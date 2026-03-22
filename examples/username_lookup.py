#!/usr/bin/env python3
"""Example: Username lookup across 50+ platforms.

Usage::

    python examples/username_lookup.py johndoe
"""

import asyncio
import sys

from rich.console import Console
from rich.table import Table

from osintrecon.core.engine import ReconEngine

console = Console()


async def main(username: str) -> None:
    engine = ReconEngine()

    console.print(f"\n[bold cyan]Investigating username:[/] {username}\n")

    result = await engine.investigate_username(username)

    # Display platform results
    platforms = result.findings.get("username_platforms", [])
    found = [p for p in platforms if p.get("exists")]

    table = Table(title=f"Found {len(found)}/{len(platforms)} platforms")
    table.add_column("Platform", style="cyan")
    table.add_column("URL", style="blue")
    table.add_column("Status", style="green")

    for p in found:
        table.add_row(p["name"], p["profile_url"], "Found")

    console.print(table)

    # Display variations
    variations = result.findings.get("username_variations", [])
    console.print(f"\n[bold]Username variations ({len(variations)}):[/]")
    for v in variations[:15]:
        console.print(f"  - {v}")
    if len(variations) > 15:
        console.print(f"  ... and {len(variations) - 15} more")

    console.print(f"\n[dim]Completed in {result.duration:.2f}s[/]")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "johndoe"
    asyncio.run(main(target))
