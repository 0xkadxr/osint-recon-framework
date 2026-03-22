"""Wayback Machine / web archive lookup module."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from osintrecon.core.config import Config

WAYBACK_API = "https://web.archive.org"
CDX_API = "https://web.archive.org/cdx/search/cdx"


class WebArchiveModule:
    """Query the Internet Archive Wayback Machine for cached snapshots.

    Args:
        config: Framework configuration.
    """

    def __init__(self, config: Optional["Config"] = None) -> None:
        self.config = config
        self._timeout = config.timeout if config else 20

    async def check_wayback(self, url: str) -> Dict[str, Any]:
        """Check whether *url* has any Wayback Machine snapshots.

        Uses the Availability API to find the closest snapshot.

        Args:
            url: The target URL.

        Returns:
            A dict with ``available``, ``closest_snapshot``, and ``timestamp``.
        """
        result: Dict[str, Any] = {"url": url, "available": False}

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{WAYBACK_API}/wayback/available",
                    params={"url": url},
                    headers={"User-Agent": "OSINTRecon/1.0"},
                )

            if resp.status_code == 200:
                data = resp.json()
                snapshots = data.get("archived_snapshots", {})
                closest = snapshots.get("closest")
                if closest:
                    result["available"] = closest.get("available", False)
                    result["closest_snapshot"] = closest.get("url")
                    result["timestamp"] = closest.get("timestamp")
                    result["status"] = closest.get("status")
        except Exception as exc:
            result["error"] = str(exc)

        return result

    async def get_snapshots(
        self,
        url: str,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List available snapshots for *url* within a date range.

        Uses the CDX Server API.

        Args:
            url: The target URL.
            from_date: Start date in ``YYYYMMDD`` format (optional).
            to_date: End date in ``YYYYMMDD`` format (optional).
            limit: Maximum number of results.

        Returns:
            A list of dicts with ``timestamp``, ``status_code``, ``mime``,
            ``length``, and ``snapshot_url``.
        """
        params: Dict[str, Any] = {
            "url": url,
            "output": "json",
            "limit": limit,
            "fl": "timestamp,statuscode,mimetype,length,original",
        }
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date

        snapshots: List[Dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    CDX_API,
                    params=params,
                    headers={"User-Agent": "OSINTRecon/1.0"},
                )

            if resp.status_code == 200:
                rows = resp.json()
                # First row is the header
                if rows and len(rows) > 1:
                    headers_row = rows[0]
                    for row in rows[1:]:
                        entry = dict(zip(headers_row, row))
                        ts = entry.get("timestamp", "")
                        entry["snapshot_url"] = (
                            f"{WAYBACK_API}/web/{ts}/{entry.get('original', url)}"
                        )
                        snapshots.append(entry)
        except Exception as exc:
            snapshots.append({"error": str(exc)})

        return snapshots

    async def fetch_snapshot(self, url: str, timestamp: str) -> Dict[str, Any]:
        """Retrieve the content of a specific Wayback Machine snapshot.

        Args:
            url: The original URL.
            timestamp: The Wayback timestamp (``YYYYMMDDHHMMSS``).

        Returns:
            A dict with ``snapshot_url``, ``status_code``, ``content_type``,
            ``content_length``, and a truncated ``body_preview``.
        """
        snapshot_url = f"{WAYBACK_API}/web/{timestamp}/{url}"
        result: Dict[str, Any] = {"snapshot_url": snapshot_url}

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, follow_redirects=True
            ) as client:
                resp = await client.get(
                    snapshot_url,
                    headers={"User-Agent": "OSINTRecon/1.0"},
                )

            result["status_code"] = resp.status_code
            result["content_type"] = resp.headers.get("content-type", "")
            result["content_length"] = len(resp.content)
            # Only preview the first 2 KB of text content
            if "text" in result["content_type"]:
                result["body_preview"] = resp.text[:2048]
        except Exception as exc:
            result["error"] = str(exc)

        return result
