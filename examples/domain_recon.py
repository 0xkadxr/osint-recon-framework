#!/usr/bin/env python3
"""Example: Domain reconnaissance pipeline.

Usage::

    python examples/domain_recon.py example.com
"""

import asyncio
import sys

from rich.console import Console
from rich.table import Table

from osintrecon.core.engine import ReconEngine

console = Console()


async def main(domain: str) -> None:
    engine = ReconEngine()

    console.print(f"\n[bold cyan]Domain recon:[/] {domain}\n")

    result = await engine.investigate_domain(domain)

    # DNS Records
    dns = result.findings.get("dns", {})
    if dns:
        table = Table(title="DNS Records")
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="white")
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            records = dns.get(rtype, [])
            if records:
                if isinstance(records, list):
                    for r in records:
                        table.add_row(rtype, str(r))
                else:
                    table.add_row(rtype, str(records))
        console.print(table)

    # Subdomains
    subs = result.findings.get("subdomains", {})
    found = subs.get("found", [])
    if found:
        table = Table(title=f"Subdomains ({len(found)} found)")
        table.add_column("Subdomain", style="cyan")
        table.add_column("IPs", style="green")
        for s in found:
            table.add_row(s["subdomain"], ", ".join(s["ips"]))
        console.print(table)

    # Technologies
    tech = result.findings.get("tech", {})
    techs = tech.get("technologies", [])
    if techs:
        console.print(f"\n[bold]Technologies:[/] {', '.join(techs)}")

    # SSL
    ssl_data = result.findings.get("ssl", {})
    if ssl_data and not ssl_data.get("error"):
        console.print(f"\n[bold]SSL Issuer:[/] {ssl_data.get('issuer', {})}")
        console.print(f"[bold]SSL Expiry:[/] {ssl_data.get('not_after', 'N/A')}")

    console.print(f"\n[dim]Completed in {result.duration:.2f}s[/]")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    asyncio.run(main(target))
