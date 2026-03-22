"""File metadata extraction -- EXIF, PDF, and Office documents."""

from __future__ import annotations

import struct
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


class MetadataModule:
    """Extract metadata from images, PDFs, and Office files."""

    def extract(self, file_path: str) -> Dict[str, Any]:
        """Auto-detect file type and extract metadata.

        Args:
            file_path: Path to the target file.

        Returns:
            A dict with extracted metadata.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file type is unsupported.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        suffix = path.suffix.lower()
        if suffix in (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp"):
            return self.extract_exif(file_path)
        elif suffix == ".pdf":
            return self.extract_pdf_metadata(file_path)
        elif suffix in (".docx", ".xlsx", ".pptx"):
            return self.extract_office_metadata(file_path)
        else:
            return self._basic_metadata(path)

    def extract_exif(self, image_path: str) -> Dict[str, Any]:
        """Extract EXIF data from an image file.

        Extracts GPS coordinates, camera model, datetime, software, and other
        EXIF tags using Pillow.

        Args:
            image_path: Path to the image.

        Returns:
            A dict with EXIF fields and optional ``gps`` sub-dict.
        """
        result: Dict[str, Any] = {"file": image_path, "type": "image"}

        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS

            img = Image.open(image_path)
            result["format"] = img.format
            result["size"] = {"width": img.width, "height": img.height}
            result["mode"] = img.mode

            exif_data = img._getexif()
            if exif_data is None:
                result["exif"] = {}
                return result

            exif: Dict[str, Any] = {}
            gps_info: Dict[str, Any] = {}

            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)

                if tag == "GPSInfo":
                    for gps_tag_id, gps_value in value.items():
                        gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_info[gps_tag] = gps_value
                else:
                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="replace")
                        except Exception:
                            value = repr(value)
                    exif[str(tag)] = value

            result["exif"] = exif

            # Parse GPS coordinates
            if gps_info:
                result["gps"] = self._parse_gps(gps_info)

        except ImportError:
            result["error"] = "Pillow not installed; EXIF extraction unavailable"
        except Exception as exc:
            result["error"] = str(exc)

        return result

    def extract_pdf_metadata(self, pdf_path: str) -> Dict[str, Any]:
        """Extract metadata from a PDF file using raw byte parsing.

        Looks for the ``/Info`` dictionary in the PDF trailer to extract
        author, creator, title, and dates without external dependencies.

        Args:
            pdf_path: Path to the PDF file.

        Returns:
            A dict with available PDF metadata fields.
        """
        result: Dict[str, Any] = {"file": pdf_path, "type": "pdf"}
        path = Path(pdf_path)
        result["file_size"] = path.stat().st_size

        try:
            with open(pdf_path, "rb") as fh:
                header = fh.read(1024)
                result["pdf_version"] = header[:8].decode("ascii", errors="replace").strip()

                fh.seek(0)
                content = fh.read()

            # Extract /Info dictionary entries
            info_fields = {
                b"/Title": "title",
                b"/Author": "author",
                b"/Subject": "subject",
                b"/Creator": "creator",
                b"/Producer": "producer",
                b"/CreationDate": "creation_date",
                b"/ModDate": "modification_date",
                b"/Keywords": "keywords",
            }

            metadata: Dict[str, str] = {}
            for marker, key in info_fields.items():
                idx = content.find(marker)
                if idx != -1:
                    # Find the value in parentheses after the key
                    paren_start = content.find(b"(", idx)
                    paren_end = content.find(b")", paren_start + 1) if paren_start != -1 else -1
                    if paren_start != -1 and paren_end != -1 and (paren_start - idx) < 100:
                        val = content[paren_start + 1 : paren_end]
                        metadata[key] = val.decode("utf-8", errors="replace")

            result["metadata"] = metadata

        except Exception as exc:
            result["error"] = str(exc)

        return result

    def extract_office_metadata(self, doc_path: str) -> Dict[str, Any]:
        """Extract metadata from an Office Open XML file (.docx/.xlsx/.pptx).

        Office files are ZIP archives containing ``docProps/core.xml`` and
        ``docProps/app.xml`` with Dublin Core metadata.

        Args:
            doc_path: Path to the Office document.

        Returns:
            A dict with extracted metadata fields.
        """
        import zipfile
        import xml.etree.ElementTree as ET

        result: Dict[str, Any] = {"file": doc_path, "type": "office"}
        path = Path(doc_path)
        result["file_size"] = path.stat().st_size

        try:
            with zipfile.ZipFile(doc_path, "r") as zf:
                result["contents"] = zf.namelist()

                # Parse core.xml (Dublin Core)
                if "docProps/core.xml" in zf.namelist():
                    core_xml = zf.read("docProps/core.xml")
                    root = ET.fromstring(core_xml)
                    ns = {
                        "dc": "http://purl.org/dc/elements/1.1/",
                        "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                        "dcterms": "http://purl.org/dc/terms/",
                    }
                    fields = {
                        "dc:title": "title",
                        "dc:creator": "creator",
                        "dc:subject": "subject",
                        "dc:description": "description",
                        "cp:lastModifiedBy": "last_modified_by",
                        "cp:revision": "revision",
                        "dcterms:created": "created",
                        "dcterms:modified": "modified",
                    }
                    metadata: Dict[str, str] = {}
                    for xpath, key in fields.items():
                        prefix, tag = xpath.split(":")
                        elem = root.find(f"{{{ns[prefix]}}}{tag}")
                        if elem is not None and elem.text:
                            metadata[key] = elem.text
                    result["core_metadata"] = metadata

                # Parse app.xml
                if "docProps/app.xml" in zf.namelist():
                    app_xml = zf.read("docProps/app.xml")
                    root = ET.fromstring(app_xml)
                    app_ns = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
                    app_meta: Dict[str, str] = {}
                    for tag in ["Application", "AppVersion", "Company", "Template", "TotalTime", "Pages", "Words"]:
                        elem = root.find(f"{{{app_ns}}}{tag}")
                        if elem is not None and elem.text:
                            app_meta[tag.lower()] = elem.text
                    result["app_metadata"] = app_meta

        except zipfile.BadZipFile:
            result["error"] = "Not a valid ZIP/Office file"
        except Exception as exc:
            result["error"] = str(exc)

        return result

    @staticmethod
    def gps_to_location(lat: float, lon: float) -> str:
        """Convert GPS coordinates to a human-readable description.

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.

        Returns:
            A string like ``"48.8566 N, 2.3522 E"``.
        """
        lat_dir = "N" if lat >= 0 else "S"
        lon_dir = "E" if lon >= 0 else "W"
        return f"{abs(lat):.6f} {lat_dir}, {abs(lon):.6f} {lon_dir}"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_gps(gps_info: Dict[str, Any]) -> Dict[str, Any]:
        """Parse EXIF GPS info dict into decimal coordinates."""

        def _to_decimal(coords: Any, ref: str) -> Optional[float]:
            try:
                if hasattr(coords[0], "numerator"):
                    d = float(coords[0])
                    m = float(coords[1])
                    s = float(coords[2])
                else:
                    d, m, s = float(coords[0]), float(coords[1]), float(coords[2])
                decimal = d + m / 60 + s / 3600
                if ref in ("S", "W"):
                    decimal = -decimal
                return decimal
            except Exception:
                return None

        result: Dict[str, Any] = {"raw": {str(k): str(v) for k, v in gps_info.items()}}

        lat = _to_decimal(
            gps_info.get("GPSLatitude", []),
            gps_info.get("GPSLatitudeRef", "N"),
        )
        lon = _to_decimal(
            gps_info.get("GPSLongitude", []),
            gps_info.get("GPSLongitudeRef", "E"),
        )

        if lat is not None and lon is not None:
            result["latitude"] = lat
            result["longitude"] = lon
            result["google_maps"] = (
                f"https://www.google.com/maps?q={lat},{lon}"
            )

        if "GPSAltitude" in gps_info:
            try:
                alt = float(gps_info["GPSAltitude"])
                result["altitude_m"] = alt
            except Exception:
                pass

        return result

    @staticmethod
    def _basic_metadata(path: Path) -> Dict[str, Any]:
        stat = path.stat()
        return {
            "file": str(path),
            "type": "unknown",
            "file_size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "extension": path.suffix,
        }
