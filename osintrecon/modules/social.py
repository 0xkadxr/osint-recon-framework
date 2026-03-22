"""Social media profile discovery and analysis."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from osintrecon.core.config import Config

# Platforms with publicly accessible profile pages
SOCIAL_PLATFORMS = [
    {"name": "GitHub", "url": "https://api.github.com/users/{}", "type": "api"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}/about.json", "type": "api"},
    {"name": "HackerNews", "url": "https://hacker-news.firebaseio.com/v0/user/{}.json", "type": "api"},
    {"name": "Keybase", "url": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "type": "api"},
    {"name": "GitLab", "url": "https://gitlab.com/api/v4/users?username={}", "type": "api"},
    {"name": "Medium", "url": "https://medium.com/@{}", "type": "status"},
    {"name": "Dev.to", "url": "https://dev.to/api/users/by_username?url={}", "type": "api"},
    {"name": "Gravatar", "url": "https://gravatar.com/{}", "type": "status"},
]


class SocialModule:
    """Discover and analyse social media profiles.

    Args:
        config: Framework configuration.
    """

    def __init__(self, config: Optional["Config"] = None) -> None:
        self.config = config
        self._timeout = config.timeout if config else 15

    async def discover_profiles(self, name: str) -> List[Dict[str, Any]]:
        """Search for social-media profiles matching *name*.

        Queries public APIs and profile URLs concurrently.

        Args:
            name: Username or display name.

        Returns:
            A list of dicts with ``platform``, ``url``, ``exists``, and ``data``.
        """
        sem = asyncio.Semaphore(20)
        results: List[Dict[str, Any]] = []

        async def _check(platform: Dict[str, Any], client: httpx.AsyncClient) -> Dict[str, Any]:
            async with sem:
                url = platform["url"].format(name)
                entry: Dict[str, Any] = {
                    "platform": platform["name"],
                    "url": url,
                    "exists": False,
                    "data": {},
                }
                try:
                    resp = await client.get(
                        url,
                        headers={"User-Agent": "OSINTRecon/1.0"},
                    )
                    if platform["type"] == "api" and resp.status_code == 200:
                        data = resp.json()
                        # Some APIs return empty arrays for not-found
                        if isinstance(data, list):
                            entry["exists"] = len(data) > 0
                            entry["data"] = data[0] if data else {}
                        elif isinstance(data, dict) and data:
                            entry["exists"] = True
                            entry["data"] = self._sanitize(data)
                    elif platform["type"] == "status":
                        entry["exists"] = resp.status_code == 200
                except Exception:
                    pass
                return entry

        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
        ) as client:
            tasks = [_check(p, client) for p in SOCIAL_PLATFORMS]
            raw = await asyncio.gather(*tasks, return_exceptions=True)

        for r in raw:
            if isinstance(r, dict):
                results.append(r)

        return results

    async def analyze_profile(self, platform: str, username: str) -> Dict[str, Any]:
        """Gather public data from a specific platform profile.

        Currently supports GitHub (via public API).

        Args:
            platform: Platform name (e.g. ``"GitHub"``).
            username: The username on that platform.

        Returns:
            A dict with public profile fields.
        """
        result: Dict[str, Any] = {"platform": platform, "username": username}

        if platform.lower() == "github":
            result.update(await self._github_profile(username))
        elif platform.lower() == "reddit":
            result.update(await self._reddit_profile(username))
        else:
            result["note"] = f"Detailed analysis not yet implemented for {platform}"

        return result

    async def find_connections(self, profiles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Find cross-platform connections from a list of discovered profiles.

        Heuristic: look for shared display names, bios, avatars, and URLs
        across the profiles.

        Args:
            profiles: Output of :meth:`discover_profiles`.

        Returns:
            A dict summarising potential connections.
        """
        names: Dict[str, List[str]] = {}
        urls: Dict[str, List[str]] = {}

        for p in profiles:
            if not p.get("exists"):
                continue
            data = p.get("data", {})
            platform = p["platform"]

            # Collect display names
            for key in ("name", "display_name", "login", "fullname"):
                val = data.get(key)
                if val:
                    names.setdefault(val.lower(), []).append(platform)

            # Collect linked URLs
            for key in ("blog", "html_url", "url", "website_url"):
                val = data.get(key)
                if val:
                    urls.setdefault(val, []).append(platform)

        # Connections = names or URLs appearing on 2+ platforms
        shared_names = {n: plats for n, plats in names.items() if len(plats) > 1}
        shared_urls = {u: plats for u, plats in urls.items() if len(plats) > 1}

        return {
            "shared_names": shared_names,
            "shared_urls": shared_urls,
            "profiles_found": sum(1 for p in profiles if p.get("exists")),
        }

    # ------------------------------------------------------------------
    # Platform-specific helpers
    # ------------------------------------------------------------------

    async def _github_profile(self, username: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"https://api.github.com/users/{username}",
                    headers={"User-Agent": "OSINTRecon/1.0"},
                )
                if resp.status_code == 200:
                    d = resp.json()
                    return {
                        "name": d.get("name"),
                        "bio": d.get("bio"),
                        "company": d.get("company"),
                        "location": d.get("location"),
                        "blog": d.get("blog"),
                        "public_repos": d.get("public_repos"),
                        "public_gists": d.get("public_gists"),
                        "followers": d.get("followers"),
                        "following": d.get("following"),
                        "created_at": d.get("created_at"),
                        "avatar_url": d.get("avatar_url"),
                    }
                return {"error": f"HTTP {resp.status_code}"}
        except Exception as exc:
            return {"error": str(exc)}

    async def _reddit_profile(self, username: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"https://www.reddit.com/user/{username}/about.json",
                    headers={"User-Agent": "OSINTRecon/1.0"},
                )
                if resp.status_code == 200:
                    d = resp.json().get("data", {})
                    return {
                        "name": d.get("name"),
                        "link_karma": d.get("link_karma"),
                        "comment_karma": d.get("comment_karma"),
                        "created_utc": d.get("created_utc"),
                        "has_verified_email": d.get("has_verified_email"),
                    }
                return {"error": f"HTTP {resp.status_code}"}
        except Exception as exc:
            return {"error": str(exc)}

    @staticmethod
    def _sanitize(data: Dict[str, Any], max_keys: int = 20) -> Dict[str, Any]:
        """Keep only a reasonable number of top-level keys."""
        out: Dict[str, Any] = {}
        for i, (k, v) in enumerate(data.items()):
            if i >= max_keys:
                break
            if isinstance(v, (str, int, float, bool, type(None))):
                out[k] = v
        return out
