"""Main reconnaissance engine / orchestrator."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from osintrecon.core.config import Config
from osintrecon.core.report import ReportGenerator
from osintrecon.modules.username import UsernameModule
from osintrecon.modules.email import EmailModule
from osintrecon.modules.domain import DomainModule
from osintrecon.modules.metadata import MetadataModule
from osintrecon.modules.geolocation import GeolocationModule
from osintrecon.modules.social import SocialModule
from osintrecon.modules.web_archive import WebArchiveModule
from osintrecon.utils.validators import (
    is_valid_email,
    is_valid_domain,
    is_valid_ip,
    is_valid_username,
)


@dataclass
class ReconResult:
    """Structured container for reconnaissance results.

    Attributes:
        target: The original investigation target.
        target_type: One of 'username', 'domain', 'email', 'ip', 'file'.
        modules_run: Names of modules that were executed.
        findings: Mapping of module name -> result data.
        errors: Mapping of module name -> error messages.
        started_at: Unix timestamp when the investigation started.
        finished_at: Unix timestamp when the investigation finished.
        duration: Elapsed wall-clock seconds.
    """

    target: str
    target_type: str
    modules_run: List[str] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    started_at: float = 0.0
    finished_at: float = 0.0
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "target": self.target,
            "target_type": self.target_type,
            "modules_run": self.modules_run,
            "findings": self.findings,
            "errors": self.errors,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": round(self.duration, 2),
        }

    @property
    def success_count(self) -> int:
        return len(self.findings)

    @property
    def error_count(self) -> int:
        return len(self.errors)


class ReconEngine:
    """High-level orchestrator that wires modules together.

    Usage::

        engine = ReconEngine()
        result = await engine.investigate_username("johndoe")
        print(result.findings)
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self._progress_callback: Optional[Any] = None

        # Lazy-init modules
        self._username_mod: Optional[UsernameModule] = None
        self._email_mod: Optional[EmailModule] = None
        self._domain_mod: Optional[DomainModule] = None
        self._metadata_mod: Optional[MetadataModule] = None
        self._geo_mod: Optional[GeolocationModule] = None
        self._social_mod: Optional[SocialModule] = None
        self._archive_mod: Optional[WebArchiveModule] = None
        self._reporter = ReportGenerator(self.config)

    # ------------------------------------------------------------------
    # Module accessors (lazy)
    # ------------------------------------------------------------------

    @property
    def username_module(self) -> UsernameModule:
        if self._username_mod is None:
            self._username_mod = UsernameModule(self.config.platforms_file)
        return self._username_mod

    @property
    def email_module(self) -> EmailModule:
        if self._email_mod is None:
            self._email_mod = EmailModule(self.config)
        return self._email_mod

    @property
    def domain_module(self) -> DomainModule:
        if self._domain_mod is None:
            self._domain_mod = DomainModule(self.config)
        return self._domain_mod

    @property
    def metadata_module(self) -> MetadataModule:
        if self._metadata_mod is None:
            self._metadata_mod = MetadataModule()
        return self._metadata_mod

    @property
    def geolocation_module(self) -> GeolocationModule:
        if self._geo_mod is None:
            self._geo_mod = GeolocationModule(self.config)
        return self._geo_mod

    @property
    def social_module(self) -> SocialModule:
        if self._social_mod is None:
            self._social_mod = SocialModule(self.config)
        return self._social_mod

    @property
    def archive_module(self) -> WebArchiveModule:
        if self._archive_mod is None:
            self._archive_mod = WebArchiveModule(self.config)
        return self._archive_mod

    # ------------------------------------------------------------------
    # Progress
    # ------------------------------------------------------------------

    def on_progress(self, callback: Any) -> None:
        """Register a progress callback ``callback(module_name, status, detail)``."""
        self._progress_callback = callback

    def _report(self, module: str, status: str, detail: str = "") -> None:
        if self._progress_callback:
            self._progress_callback(module, status, detail)

    # ------------------------------------------------------------------
    # Investigation pipelines
    # ------------------------------------------------------------------

    async def investigate_username(self, username: str) -> ReconResult:
        """Run all username-related modules.

        Args:
            username: The username to investigate.

        Returns:
            A :class:`ReconResult` with per-module findings.
        """
        result = self._new_result(username, "username")

        # Username lookup across platforms
        self._report("username", "running", f"Checking platforms for '{username}'")
        try:
            platforms = await self.username_module.check_all(username)
            result.findings["username_platforms"] = platforms
            result.modules_run.append("username")
        except Exception as exc:
            result.errors["username"] = str(exc)

        # Variations
        self._report("username", "running", "Generating variations")
        try:
            variations = self.username_module.generate_variations(username)
            result.findings["username_variations"] = variations
        except Exception as exc:
            result.errors["username_variations"] = str(exc)

        # Social discovery
        self._report("social", "running", "Discovering social profiles")
        try:
            profiles = await self.social_module.discover_profiles(username)
            result.findings["social_profiles"] = profiles
            result.modules_run.append("social")
        except Exception as exc:
            result.errors["social"] = str(exc)

        self._finalize(result)
        return result

    async def investigate_domain(self, domain: str) -> ReconResult:
        """Run the full domain reconnaissance pipeline.

        Args:
            domain: The target domain name.

        Returns:
            A :class:`ReconResult` with DNS, WHOIS, subdomain, tech, and SSL data.
        """
        result = self._new_result(domain, "domain")

        tasks: dict[str, Any] = {
            "whois": ("whois", self.domain_module.whois_lookup(domain)),
            "dns": ("dns", self.domain_module.dns_records(domain)),
            "subdomains": ("subdomains", self.domain_module.subdomain_enum(domain)),
            "tech": ("technology", self.domain_module.technology_detection(domain)),
            "ssl": ("ssl", self.domain_module.ssl_info(domain)),
        }

        for key, (label, coro) in tasks.items():
            self._report("domain", "running", f"{label} lookup")
            try:
                result.findings[key] = await coro
                result.modules_run.append(key)
            except Exception as exc:
                result.errors[key] = str(exc)

        # Wayback snapshots
        self._report("web_archive", "running", "Checking Wayback Machine")
        try:
            url = f"https://{domain}"
            result.findings["web_archive"] = await self.archive_module.check_wayback(url)
            result.modules_run.append("web_archive")
        except Exception as exc:
            result.errors["web_archive"] = str(exc)

        self._finalize(result)
        return result

    async def investigate_email(self, email: str) -> ReconResult:
        """Run the email OSINT pipeline.

        Args:
            email: The email address to investigate.

        Returns:
            A :class:`ReconResult` with email validation, domain, breach, and related data.
        """
        result = self._new_result(email, "email")

        steps = [
            ("validate", self.email_module.validate_email(email)),
            ("domain_info", self.email_module.domain_info(email)),
            ("breaches", self.email_module.check_breaches(email)),
            ("related", self.email_module.find_related(email)),
        ]

        for key, coro in steps:
            self._report("email", "running", key)
            try:
                result.findings[key] = await coro
                result.modules_run.append(key)
            except Exception as exc:
                result.errors[key] = str(exc)

        self._finalize(result)
        return result

    async def extract_metadata(self, file_path: str) -> ReconResult:
        """Extract metadata from a file.

        Args:
            file_path: Path to the target file.

        Returns:
            A :class:`ReconResult` containing extracted metadata.
        """
        result = self._new_result(file_path, "file")

        self._report("metadata", "running", f"Extracting metadata from {file_path}")
        try:
            meta = self.metadata_module.extract(file_path)
            result.findings["metadata"] = meta
            result.modules_run.append("metadata")
        except Exception as exc:
            result.errors["metadata"] = str(exc)

        # If GPS data present, resolve geolocation
        gps = (result.findings.get("metadata") or {}).get("gps")
        if gps and gps.get("latitude") and gps.get("longitude"):
            self._report("geolocation", "running", "Resolving GPS coordinates")
            try:
                loc = await self.geolocation_module.estimate_timezone(
                    gps["latitude"], gps["longitude"]
                )
                result.findings["geolocation"] = {
                    "latitude": gps["latitude"],
                    "longitude": gps["longitude"],
                    "timezone": loc,
                }
                result.modules_run.append("geolocation")
            except Exception as exc:
                result.errors["geolocation"] = str(exc)

        self._finalize(result)
        return result

    async def run_all(self, target: str, target_type: str = "auto") -> ReconResult:
        """Run every applicable module for the given target.

        Args:
            target: The investigation target.
            target_type: One of 'username', 'domain', 'email', 'ip', 'file',
                         or 'auto' to detect automatically.

        Returns:
            A :class:`ReconResult` aggregating all module outputs.
        """
        if target_type == "auto":
            target_type = self._detect_type(target)

        dispatch = {
            "username": self.investigate_username,
            "domain": self.investigate_domain,
            "email": self.investigate_email,
            "file": self.extract_metadata,
        }

        handler = dispatch.get(target_type)
        if handler is None:
            raise ValueError(f"Unknown target type: {target_type}")

        return await handler(target)

    # ------------------------------------------------------------------
    # Report generation shortcut
    # ------------------------------------------------------------------

    async def generate_report(
        self, result: ReconResult, fmt: str = "json"
    ) -> str:
        """Generate a report from a :class:`ReconResult`.

        Args:
            result: The result to serialize.
            fmt: One of 'json', 'markdown', 'html'.

        Returns:
            The formatted report string.
        """
        return self._reporter.generate(result, fmt)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _new_result(self, target: str, target_type: str) -> ReconResult:
        return ReconResult(target=target, target_type=target_type, started_at=time.time())

    def _finalize(self, result: ReconResult) -> None:
        result.finished_at = time.time()
        result.duration = result.finished_at - result.started_at
        self._report("engine", "complete", f"Done in {result.duration:.1f}s")

    @staticmethod
    def _detect_type(target: str) -> str:
        if is_valid_email(target):
            return "email"
        if is_valid_domain(target):
            return "domain"
        if is_valid_ip(target):
            return "ip"
        if is_valid_username(target):
            return "username"
        return "username"
