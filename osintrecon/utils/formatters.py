"""Output formatting utilities for CLI and reports."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence


def truncate(text: str, max_length: int = 80, suffix: str = "...") -> str:
    """Truncate *text* to *max_length* characters.

    Args:
        text: Input string.
        max_length: Maximum length including suffix.
        suffix: Appended when text is truncated.

    Returns:
        The (possibly truncated) string.
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def table(
    rows: Sequence[Dict[str, Any]],
    columns: Optional[List[str]] = None,
    max_col_width: int = 40,
) -> str:
    """Render a list of dicts as a simple ASCII table.

    Args:
        rows: Sequence of dictionaries (one per row).
        columns: Column names to display.  Defaults to all keys from the first row.
        max_col_width: Maximum width per column.

    Returns:
        A formatted table string.
    """
    if not rows:
        return "(no data)"

    if columns is None:
        columns = list(rows[0].keys())

    # Compute column widths
    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            val = str(row.get(col, ""))
            widths[col] = min(max(widths[col], len(val)), max_col_width)

    # Header
    header = " | ".join(col.ljust(widths[col]) for col in columns)
    sep = "-+-".join("-" * widths[col] for col in columns)

    lines = [header, sep]
    for row in rows:
        vals = []
        for col in columns:
            cell = truncate(str(row.get(col, "")), widths[col])
            vals.append(cell.ljust(widths[col]))
        lines.append(" | ".join(vals))

    return "\n".join(lines)


def highlight(text: str, keyword: str, color: str = "red") -> str:
    """Wrap occurrences of *keyword* in ANSI color codes.

    Args:
        text: The source string.
        keyword: Substring to highlight.
        color: One of 'red', 'green', 'yellow', 'blue', 'cyan', 'magenta'.

    Returns:
        The string with ANSI escape sequences.
    """
    codes = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
    }
    reset = "\033[0m"
    code = codes.get(color, codes["red"])
    return text.replace(keyword, f"{code}{keyword}{reset}")


def format_size(size_bytes: int) -> str:
    """Convert bytes to a human-readable size string.

    Args:
        size_bytes: File size in bytes.

    Returns:
        A string like ``"4.2 MB"``.
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0  # type: ignore[assignment]
    return f"{size_bytes:.1f} PB"


def format_findings(findings: Dict[str, Any], indent: int = 0) -> str:
    """Pretty-print a findings dict as indented key-value text.

    Args:
        findings: Nested dict of findings.
        indent: Current indentation level.

    Returns:
        A multi-line formatted string.
    """
    lines: List[str] = []
    prefix = "  " * indent
    for key, value in findings.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.append(format_findings(value, indent + 1))
        elif isinstance(value, list):
            lines.append(f"{prefix}{key}: [{len(value)} items]")
            for item in value[:10]:
                if isinstance(item, dict):
                    lines.append(format_findings(item, indent + 1))
                else:
                    lines.append(f"{prefix}  - {item}")
            if len(value) > 10:
                lines.append(f"{prefix}  ... and {len(value) - 10} more")
        else:
            lines.append(f"{prefix}{key}: {value}")
    return "\n".join(lines)
