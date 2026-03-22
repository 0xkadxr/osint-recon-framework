"""Username lookup across platforms."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx


class UsernameModule:
    """Check whether a username is registered on various platforms.

    Args:
        platforms_file: Path to the JSON file listing platforms.
    """

    def __init__(self, platforms_file: Optional[str] = None) -> None:
        if platforms_file is None:
            platforms_file = str(
                Path(__file__).parent.parent / "data" / "platforms.json"
            )
        self.platforms = self._load_platforms(platforms_file)

    @staticmethod
    def _load_platforms(path: str) -> List[Dict[str, Any]]:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    async def check_platform(
        self,
        username: str,
        platform: Dict[str, Any],
        client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        """Check if *username* exists on a single platform.

        Args:
            username: The target username.
            platform: A dict with keys ``name``, ``url``, ``method``, ``expected``.
            client: An existing ``httpx.AsyncClient`` (optional).

        Returns:
            A dict with ``name``, ``url``, ``exists``, ``profile_url``, and ``status_code``.
        """
        profile_url = platform["url"].format(username)
        method = platform.get("method", "status_code")
        expected = platform.get("expected", 200)

        result: Dict[str, Any] = {
            "name": platform["name"],
            "url": profile_url,
            "exists": False,
            "profile_url": profile_url,
            "status_code": None,
        }

        own_client = client is None
        if own_client:
            client = httpx.AsyncClient(
                timeout=10,
                follow_redirects=True,
                headers={"User-Agent": "OSINTRecon/1.0"},
            )

        try:
            resp = await client.get(profile_url)
            result["status_code"] = resp.status_code

            if method == "status_code":
                result["exists"] = resp.status_code == expected
            elif method == "content":
                indicator = platform.get("indicator", "")
                result["exists"] = indicator not in resp.text
            else:
                result["exists"] = resp.status_code == expected
        except (httpx.RequestError, httpx.HTTPStatusError):
            result["exists"] = False
        finally:
            if own_client:
                await client.aclose()

        return result

    async def check_all(
        self,
        username: str,
        max_concurrent: int = 30,
    ) -> List[Dict[str, Any]]:
        """Check *username* across all loaded platforms concurrently.

        Args:
            username: The target username.
            max_concurrent: Concurrency cap (semaphore size).

        Returns:
            A list of result dicts, one per platform.
        """
        sem = asyncio.Semaphore(max_concurrent)

        async def _check(platform: Dict[str, Any], client: httpx.AsyncClient) -> Dict[str, Any]:
            async with sem:
                return await self.check_platform(username, platform, client)

        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=True,
            headers={"User-Agent": "OSINTRecon/1.0"},
        ) as client:
            tasks = [_check(p, client) for p in self.platforms]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        out: List[Dict[str, Any]] = []
        for r in results:
            if isinstance(r, dict):
                out.append(r)
        return out

    @staticmethod
    def generate_variations(username: str) -> List[str]:
        """Generate common variations of *username*.

        Useful for finding alternate accounts during CTF investigations.

        Args:
            username: The base username.

        Returns:
            A deduplicated list of username variations.
        """
        base = username.lower().strip()
        variations = {base}

        # Numeric suffixes
        for suffix in ["0", "1", "12", "123", "1337", "01", "69", "99", "00", "x", "xx"]:
            variations.add(f"{base}{suffix}")

        # Common prefixes
        for prefix in ["the", "real", "x", "im", "its", "not", "mr", "0x"]:
            variations.add(f"{prefix}{base}")
            variations.add(f"{prefix}_{base}")
            variations.add(f"{prefix}.{base}")

        # Separator swaps
        if "_" in base:
            variations.add(base.replace("_", "-"))
            variations.add(base.replace("_", "."))
            variations.add(base.replace("_", ""))
        elif "-" in base:
            variations.add(base.replace("-", "_"))
            variations.add(base.replace("-", "."))
            variations.add(base.replace("-", ""))
        elif "." in base:
            variations.add(base.replace(".", "_"))
            variations.add(base.replace(".", "-"))
            variations.add(base.replace(".", ""))
        else:
            mid = len(base) // 2
            if mid > 0:
                variations.add(f"{base[:mid]}_{base[mid:]}")
                variations.add(f"{base[:mid]}.{base[mid:]}")

        # Leet speak
        leet = base.replace("a", "4").replace("e", "3").replace("i", "1").replace("o", "0").replace("s", "5")
        if leet != base:
            variations.add(leet)

        return sorted(variations)
