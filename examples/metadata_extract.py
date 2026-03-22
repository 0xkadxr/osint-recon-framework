#!/usr/bin/env python3
"""Example: File metadata extraction (EXIF, PDF, Office).

Usage::

    python examples/metadata_extract.py photo.jpg
    python examples/metadata_extract.py document.pdf
    python examples/metadata_extract.py report.docx
"""

import asyncio
import sys

from rich.console import Console
from rich.table import Table

from osintrecon.core.engine import ReconEngine

console = Console()


async def main(file_path: str) -> None:
    engine = ReconEngine()

    console.print(f"\n[bold cyan]Extracting metadata from:[/] {file_path}\n")

    result = await engine.extract_metadata(file_path)

    metadata = result.findings.get("metadata", {})

    # General info
    table = Table(title="File Metadata")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    for key, value in metadata.items():
        if isinstance(value, dict):
            for k, v in value.items():
                table.add_row(f"{key}.{k}", str(v))
        elif isinstance(value, list):
            table.add_row(key, f"[{len(value)} items]")
        else:
            table.add_row(key, str(value))

    console.print(table)

    # GPS / Geolocation
    geo = result.findings.get("geolocation", {})
    if geo:
        console.print(f"\n[bold green]GPS Location Found![/]")
        console.print(f"  Latitude:  {geo.get('latitude')}")
        console.print(f"  Longitude: {geo.get('longitude')}")
        console.print(f"  Timezone:  {geo.get('timezone')}")
        gps = metadata.get("gps", {})
        if gps.get("google_maps"):
            console.print(f"  Maps:      {gps['google_maps']}")

    if result.errors:
        for mod, err in result.errors.items():
            console.print(f"[red]Error ({mod}): {err}[/]")

    console.print(f"\n[dim]Completed in {result.duration:.2f}s[/]")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: python metadata_extract.py <file_path>[/]")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
