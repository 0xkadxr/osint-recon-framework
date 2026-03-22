#!/usr/bin/env python3
"""CLI entry point for OSINTRecon.

Usage examples::

    python cli.py username johndoe
    python cli.py domain example.com --output markdown
    python cli.py email user@example.com --output html
    python cli.py metadata photo.jpg
    python cli.py full johndoe --timeout 30
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from osintrecon.core.config import Config
from osintrecon.core.engine import ReconEngine, ReconResult
from osintrecon.core.report import ReportGenerator

console = Console()

BANNER = r"""
   ____  _____ ___ _   _ _____   ____
  / __ \/ ____|_ _| \ | |_   _| |  _ \ ___  ___ ___  _ __
 | |  | \___  \| ||  \| | | |   | |_) / _ \/ __/ _ \| '_ \
 | |__| |___) | || |\  | | |   |  _ <  __/ (_| (_) | | | |
  \____/|____/___|_| \_| |_|   |_| \_\___|\___\___/|_| |_|

  Lightweight OSINT Reconnaissance Framework
"""


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="osintrecon",
        description="Lightweight OSINT reconnaissance framework for CTF competitions.",
    )
    parser.add_argument(
        "--output", "-o",
        choices=["json", "markdown", "html"],
        default="json",
        help="Report output format (default: json).",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=15,
        help="HTTP request timeout in seconds (default: 15).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=30,
        help="Max concurrent requests (default: 30).",
    )
    parser.add_argument(
        "--proxy",
        type=str,
        default=None,
        help="Proxy URL (e.g. socks5://127.0.0.1:9050).",
    )
    parser.add_argument(
        "--save", "-s",
        action="store_true",
        help="Save the report to the output directory.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Investigation commands")

    # username
    sp = subparsers.add_parser("username", help="Username lookup across platforms")
    sp.add_argument("target", help="Username to investigate")

    # domain
    sp = subparsers.add_parser("domain", help="Domain reconnaissance")
    sp.add_argument("target", help="Domain to investigate")

    # email
    sp = subparsers.add_parser("email", help="Email OSINT investigation")
    sp.add_argument("target", help="Email address to investigate")

    # metadata
    sp = subparsers.add_parser("metadata", help="File metadata extraction")
    sp.add_argument("target", help="File path to extract metadata from")

    # full
    sp = subparsers.add_parser("full", help="Full investigation (auto-detect target type)")
    sp.add_argument("target", help="Target to investigate")

    return parser


def display_result(result: ReconResult) -> None:
    """Pretty-print a ReconResult to the console using Rich."""
    # Header
    console.print()
    console.print(Panel(
        f"[bold cyan]Target:[/] {result.target}\n"
        f"[bold cyan]Type:[/] {result.target_type}\n"
        f"[bold cyan]Duration:[/] {result.duration:.2f}s\n"
        f"[bold cyan]Modules:[/] {', '.join(result.modules_run)}",
        title="[bold green]Investigation Complete[/]",
        border_style="green",
    ))

    # Findings
    for module_name, data in result.findings.items():
        title = module_name.replace("_", " ").title()

        if isinstance(data, list) and data and isinstance(data[0], dict):
            # Render as table
            tbl = Table(title=title, show_lines=True, border_style="blue")
            cols = list(data[0].keys())
            for col in cols:
                tbl.add_column(col, style="cyan", overflow="fold")
            for row in data:
                tbl.add_row(*[str(row.get(c, "")) for c in cols])
            console.print(tbl)
        elif isinstance(data, dict):
            tbl = Table(title=title, show_lines=True, border_style="blue")
            tbl.add_column("Key", style="bold cyan")
            tbl.add_column("Value", style="white", overflow="fold")
            for k, v in data.items():
                val_str = str(v)
                if len(val_str) > 200:
                    val_str = val_str[:200] + "..."
                tbl.add_row(str(k), val_str)
            console.print(tbl)
        elif isinstance(data, list):
            console.print(f"\n[bold blue]{title}[/]")
            for item in data:
                console.print(f"  - {item}")
        else:
            console.print(f"\n[bold blue]{title}:[/] {data}")

    # Errors
    if result.errors:
        console.print()
        err_table = Table(title="Errors", border_style="red")
        err_table.add_column("Module", style="bold red")
        err_table.add_column("Error", style="red")
        for mod, err in result.errors.items():
            err_table.add_row(mod, err)
        console.print(err_table)


async def run(args: argparse.Namespace) -> None:
    """Execute the selected investigation command."""
    config = Config(
        timeout=args.timeout,
        max_concurrent=args.threads,
        proxy=args.proxy,
        verbose=args.verbose,
    )
    engine = ReconEngine(config)

    dispatch = {
        "username": engine.investigate_username,
        "domain": engine.investigate_domain,
        "email": engine.investigate_email,
        "metadata": engine.extract_metadata,
        "full": lambda t: engine.run_all(t, "auto"),
    }

    handler = dispatch.get(args.command)
    if handler is None:
        console.print("[red]No command specified. Use --help for usage.[/]")
        return

    # Run with progress spinner
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Investigating {args.target}...", total=None)

        def on_progress(module: str, status: str, detail: str = "") -> None:
            progress.update(task, description=f"[cyan]{module}[/] {detail}")

        engine.on_progress(on_progress)
        result = await handler(args.target)

    display_result(result)

    # Generate and optionally save report
    report_text = engine._reporter.generate(result, args.output)

    if args.save:
        path = engine._reporter.save(result, args.output)
        console.print(f"\n[green]Report saved to:[/] {path}")
    elif args.output != "json" or args.verbose:
        console.print(f"\n[dim]--- {args.output.upper()} Report ---[/]")
        console.print(report_text)


def main() -> None:
    """CLI entry point."""
    console.print(Text(BANNER, style="bold cyan"))

    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
