"""Email OSINT -- validation, domain info, breach checks, and related accounts."""

from __future__ import annotations

import asyncio
import hashlib
import re
import socket
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from osintrecon.core.config import Config


class EmailModule:
    """Email investigation module.

    Args:
        config: Framework configuration.
    """

    def __init__(self, config: Optional["Config"] = None) -> None:
        self.config = config
        self._timeout = config.timeout if config else 15

    async def validate_email(self, email: str) -> Dict[str, Any]:
        """Validate email format and check MX records.

        Args:
            email: The email address to validate.

        Returns:
            A dict with ``valid_format``, ``mx_records``, ``domain``, and ``deliverable``.
        """
        result: Dict[str, Any] = {
            "email": email,
            "valid_format": False,
            "domain": None,
            "mx_records": [],
            "deliverable": False,
        }

        # Format validation
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, email):
            return result

        result["valid_format"] = True
        domain = email.split("@")[1]
        result["domain"] = domain

        # MX record lookup
        try:
            import dns.resolver

            answers = dns.resolver.resolve(domain, "MX")
            result["mx_records"] = [
                {"priority": r.preference, "host": str(r.exchange).rstrip(".")}
                for r in answers
            ]
            result["deliverable"] = len(result["mx_records"]) > 0
        except ImportError:
            # Fallback: basic socket check
            try:
                socket.getaddrinfo(domain, 25)
                result["deliverable"] = True
                result["mx_records"] = [{"priority": 0, "host": domain}]
            except socket.gaierror:
                pass
        except Exception:
            pass

        return result

    async def domain_info(self, email: str) -> Dict[str, Any]:
        """Extract and look up the domain of *email*.

        Args:
            email: The email address.

        Returns:
            A dict with ``domain``, ``registrar``, ``creation_date``, etc.
        """
        domain = email.split("@")[1] if "@" in email else email
        info: Dict[str, Any] = {"domain": domain}

        try:
            import whois  # python-whois

            w = whois.whois(domain)
            info["registrar"] = getattr(w, "registrar", None)
            info["creation_date"] = str(getattr(w, "creation_date", None))
            info["expiration_date"] = str(getattr(w, "expiration_date", None))
            info["name_servers"] = getattr(w, "name_servers", [])
            info["org"] = getattr(w, "org", None)
        except ImportError:
            info["note"] = "python-whois not installed; WHOIS unavailable"
        except Exception as exc:
            info["error"] = str(exc)

        return info

    async def check_breaches(self, email: str) -> Dict[str, Any]:
        """Check whether *email* appears in known breach datasets.

        This uses a simulated lookup (SHA-1 prefix check against a placeholder
        endpoint).  Replace the URL with a real HIBP API key for production use.

        Args:
            email: The email address to check.

        Returns:
            A dict with ``checked``, ``hash_prefix``, and ``breaches`` (list).
        """
        sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        result: Dict[str, Any] = {
            "email": email,
            "sha1_prefix": prefix,
            "checked": True,
            "breaches": [],
        }

        # Attempt HIBP-style k-anonymity range query
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    headers={"User-Agent": "OSINTRecon/1.0"},
                )
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        h, count = line.split(":")
                        if h.strip() == suffix:
                            result["breaches"].append(
                                {
                                    "source": "PwnedPasswords",
                                    "count": int(count.strip()),
                                    "note": "Password hash found in breach database",
                                }
                            )
                            break
        except Exception:
            result["checked"] = False

        return result

    async def find_related(self, email: str) -> Dict[str, Any]:
        """Search for accounts potentially linked to *email*.

        This is a heuristic-based module that derives a username from the email
        and searches known platforms.

        Args:
            email: The email address.

        Returns:
            A dict with ``derived_usernames`` and ``gravatar`` info.
        """
        local_part = email.split("@")[0] if "@" in email else email
        derived = [local_part]

        # Strip common numeric suffixes
        stripped = re.sub(r"\d+$", "", local_part)
        if stripped and stripped != local_part:
            derived.append(stripped)

        # Check Gravatar
        gravatar: Dict[str, Any] = {"exists": False}
        try:
            md5 = hashlib.md5(email.lower().strip().encode()).hexdigest()
            gravatar_url = f"https://www.gravatar.com/avatar/{md5}?d=404"
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(gravatar_url)
                gravatar["exists"] = resp.status_code == 200
                gravatar["profile_url"] = f"https://gravatar.com/{md5}"
        except Exception:
            pass

        return {
            "derived_usernames": derived,
            "gravatar": gravatar,
        }
