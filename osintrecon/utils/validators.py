"""Input validation helpers for emails, domains, IPs, and usernames."""

from __future__ import annotations

import ipaddress
import re


def is_valid_email(value: str) -> bool:
    """Return ``True`` if *value* looks like a valid email address.

    Uses a pragmatic regex -- not RFC 5322 complete, but sufficient for
    OSINT triage.

    Args:
        value: The string to test.
    """
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def is_valid_domain(value: str) -> bool:
    """Return ``True`` if *value* looks like a valid domain name.

    Args:
        value: The string to test.
    """
    if not value or len(value) > 253:
        return False
    # Strip trailing dot (FQDN)
    if value.endswith("."):
        value = value[:-1]
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    return bool(re.match(pattern, value))


def is_valid_ip(value: str) -> bool:
    """Return ``True`` if *value* is a valid IPv4 or IPv6 address.

    Args:
        value: The string to test.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_username(value: str) -> bool:
    """Return ``True`` if *value* is a plausible username.

    Accepts alphanumerics, underscores, hyphens, and dots (3-39 chars).

    Args:
        value: The string to test.
    """
    pattern = r"^[A-Za-z0-9._-]{3,39}$"
    return bool(re.match(pattern, value))


def is_valid_url(value: str) -> bool:
    """Return ``True`` if *value* starts with ``http://`` or ``https://``.

    Args:
        value: The string to test.
    """
    pattern = r"^https?://[^\s/$.?#].[^\s]*$"
    return bool(re.match(pattern, value))


def sanitize_input(value: str) -> str:
    """Strip dangerous characters for safe shell / log usage.

    Args:
        value: Raw user input.

    Returns:
        Sanitized string.
    """
    # Remove characters that could be used for command injection
    return re.sub(r"[;&|`$(){}]", "", value).strip()
