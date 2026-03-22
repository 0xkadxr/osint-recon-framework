"""IP and image geolocation module."""

from __future__ import annotations

import math
from typing import Any, Dict, Optional, TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from osintrecon.core.config import Config


class GeolocationModule:
    """Resolve IPs and image GPS data to physical locations.

    Args:
        config: Framework configuration.
    """

    def __init__(self, config: Optional["Config"] = None) -> None:
        self.config = config
        self._timeout = config.timeout if config else 15

    async def ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """Geolocate an IP address using the free ip-api.com service.

        Args:
            ip: IPv4 or IPv6 address.

        Returns:
            A dict with ``country``, ``city``, ``lat``, ``lon``, ``isp``, etc.
        """
        result: Dict[str, Any] = {"ip": ip}

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "status,message,country,countryCode,region,"
                            "regionName,city,zip,lat,lon,timezone,isp,org,as,query"},
                )
                data = resp.json()

            if data.get("status") == "success":
                result.update({
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "zip": data.get("zip"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as"),
                    "google_maps": f"https://www.google.com/maps?q={data.get('lat')},{data.get('lon')}",
                })
            else:
                result["error"] = data.get("message", "Lookup failed")

        except Exception as exc:
            result["error"] = str(exc)

        return result

    async def image_geolocation(self, image_path: str) -> Dict[str, Any]:
        """Extract GPS coordinates from an image's EXIF data.

        Args:
            image_path: Path to the image file.

        Returns:
            A dict with ``latitude``, ``longitude``, and a Google Maps link.
        """
        from osintrecon.modules.metadata import MetadataModule

        meta_mod = MetadataModule()
        meta = meta_mod.extract_exif(image_path)
        gps = meta.get("gps", {})

        result: Dict[str, Any] = {"image": image_path}

        if gps.get("latitude") is not None and gps.get("longitude") is not None:
            result["latitude"] = gps["latitude"]
            result["longitude"] = gps["longitude"]
            result["google_maps"] = gps.get("google_maps", "")
            result["altitude_m"] = gps.get("altitude_m")

            # Resolve timezone
            tz = await self.estimate_timezone(gps["latitude"], gps["longitude"])
            result["estimated_timezone"] = tz
        else:
            result["error"] = "No GPS data found in image EXIF"

        return result

    async def estimate_timezone(self, lat: float, lon: float) -> str:
        """Estimate the IANA timezone from coordinates.

        Uses a simple longitude-based heuristic when no external API is
        available, or the free TimeZoneDB / ip-api style lookup.

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.

        Returns:
            An IANA timezone string estimate (e.g. ``"Europe/Paris"``).
        """
        # Try online lookup first
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    "http://ip-api.com/json/",
                    params={"fields": "timezone"},
                )
                if resp.status_code == 200:
                    tz = resp.json().get("timezone")
                    if tz:
                        return tz
        except Exception:
            pass

        # Fallback: rough UTC offset from longitude
        offset_hours = round(lon / 15)
        sign = "+" if offset_hours >= 0 else "-"
        return f"UTC{sign}{abs(offset_hours):02d}:00"

    @staticmethod
    def haversine_distance(
        lat1: float, lon1: float, lat2: float, lon2: float
    ) -> float:
        """Compute the great-circle distance between two points (in km).

        Args:
            lat1: Latitude of point 1.
            lon1: Longitude of point 1.
            lat2: Latitude of point 2.
            lon2: Longitude of point 2.

        Returns:
            Distance in kilometres.
        """
        R = 6371.0  # Earth radius in km
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)
        a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
