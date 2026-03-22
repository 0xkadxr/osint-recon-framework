"""Async HTTP client with rate limiting, retries, and user-agent rotation."""

from __future__ import annotations

import asyncio
import json
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx


class RateLimiter:
    """Simple token-bucket style rate limiter.

    Args:
        requests_per_second: Maximum requests per second.
    """

    def __init__(self, requests_per_second: float = 10.0) -> None:
        self._min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self._last_request: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request slot is available."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_request = time.monotonic()


class AsyncHTTPClient:
    """Feature-rich async HTTP client built on ``httpx``.

    Features:
        - Rate limiting via token bucket.
        - User-agent rotation from a JSON file.
        - Automatic retries with exponential back-off.
        - Optional proxy support.

    Args:
        timeout: Request timeout in seconds.
        retries: Number of automatic retries on failure.
        rate_limit: Max requests per second (0 = unlimited).
        proxy: Optional proxy URL.
        user_agents_file: Path to a JSON list of user-agent strings.
        rotate_ua: Whether to rotate user agents.
    """

    def __init__(
        self,
        timeout: int = 15,
        retries: int = 2,
        rate_limit: float = 10.0,
        proxy: Optional[str] = None,
        user_agents_file: Optional[str] = None,
        rotate_ua: bool = True,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.proxy = proxy
        self.rotate_ua = rotate_ua

        self._limiter = RateLimiter(rate_limit)
        self._user_agents = self._load_user_agents(user_agents_file)
        self._client: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "AsyncHTTPClient":
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            proxy=self.proxy,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Perform a rate-limited GET request with retries.

        Args:
            url: Target URL.
            **kwargs: Extra keyword args forwarded to ``httpx.AsyncClient.get``.

        Returns:
            The ``httpx.Response``.
        """
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Perform a rate-limited POST request with retries."""
        return await self._request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        """Perform a rate-limited HEAD request with retries."""
        return await self._request("HEAD", url, **kwargs)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if self._client is None:
            raise RuntimeError(
                "Client not initialised. Use 'async with AsyncHTTPClient() as client:'"
            )

        # Inject rotating User-Agent
        headers = dict(kwargs.pop("headers", {}))
        if "User-Agent" not in headers:
            headers["User-Agent"] = self._get_ua()
        kwargs["headers"] = headers

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.retries + 2):  # 1 initial + retries
            await self._limiter.acquire()
            try:
                resp = await self._client.request(method, url, **kwargs)
                return resp
            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                last_exc = exc
                if attempt <= self.retries:
                    backoff = min(2 ** (attempt - 1), 30) + random.uniform(0, 1)
                    await asyncio.sleep(backoff)

        raise last_exc  # type: ignore[misc]

    def _get_ua(self) -> str:
        if self.rotate_ua and self._user_agents:
            return random.choice(self._user_agents)
        return "OSINTRecon/1.0"

    @staticmethod
    def _load_user_agents(path: Optional[str]) -> List[str]:
        if path is None:
            path = str(Path(__file__).parent.parent / "data" / "user_agents.json")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            return [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ]
