"""Configuration management for OSINTRecon."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class Config:
    """Framework configuration with sensible defaults for CTF usage.

    Attributes:
        timeout: HTTP request timeout in seconds.
        max_concurrent: Maximum number of concurrent async requests.
        rate_limit: Minimum delay between requests in seconds.
        retries: Number of retries for failed requests.
        proxy: Optional proxy URL (e.g. socks5://127.0.0.1:9050).
        user_agent_rotation: Enable random user-agent rotation.
        output_dir: Directory to write reports to.
        platforms_file: Path to the platforms JSON file.
        user_agents_file: Path to the user-agents JSON file.
        verbose: Enable verbose logging.
        extra: Arbitrary extra settings.
    """

    timeout: int = 15
    max_concurrent: int = 30
    rate_limit: float = 0.1
    retries: int = 2
    proxy: Optional[str] = None
    user_agent_rotation: bool = True
    output_dir: str = "./reports"
    platforms_file: Optional[str] = None
    user_agents_file: Optional[str] = None
    verbose: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        data_dir = Path(__file__).parent.parent / "data"
        if self.platforms_file is None:
            self.platforms_file = str(data_dir / "platforms.json")
        if self.user_agents_file is None:
            self.user_agents_file = str(data_dir / "user_agents.json")

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Serialize the config to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        """Load config from a JSON file."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation."""
        return {
            "timeout": self.timeout,
            "max_concurrent": self.max_concurrent,
            "rate_limit": self.rate_limit,
            "retries": self.retries,
            "proxy": self.proxy,
            "user_agent_rotation": self.user_agent_rotation,
            "output_dir": self.output_dir,
            "platforms_file": self.platforms_file,
            "user_agents_file": self.user_agents_file,
            "verbose": self.verbose,
            "extra": self.extra,
        }
