"""
ReconForge — CLI Module
═══════════════════════
Beautiful terminal interface using Rich library for
professional reconnaissance output with panels, tables,
and color-coded findings.
"""

import time
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.spinner import Spinner
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.tree import Tree
from rich.text import Text
from rich.columns import Columns
from rich import box

from . import __version__

console = Console()


def print_banner():
    """Display the ReconForge banner."""
    by_line = "by godes".rjust(42)
    banner = f"""
╔══════════════════════════════════════════════════════╗
║                  ██████                              ║
║                  ██  ██                             ║
║  █████  █████  █████  █████  █████  █████  █████   ║
║  ██  ██ ██  ██ ██ ██  ██  ██ ██  ██ ██  ██ ██  ██  ║
║  █████  █████  ██ ██  █████  █████  ██  ██ ██  ██  ║
║  ██     ██     ██ ██  ██     ██     ██  ██ ██  ██  ║
║  ██     ██     ██ ██  ██     ██     █████  █████   ║
║                                              ██     ║
║                                          █████      ║
║                                                      ║
║  ██████  ██████  ███  ██ ██████  ██████  █████      ║
║  ██  ██ ██  ██ ████  ██ ██     ██     ██           ║
║  █████  █████  ██ ██ ██ █████  ██     █████        ║
║  ██  ██ ██  ██ ██ ████ ██     ██        ██         ║
║  ██  ██ ██  ██ ██  ███ ██████  █████  █████        ║
║                                                      ║
╚══════════════════════════════════════════════════════╝

    Automated Cyber Reconnaissance Framework v{__version__}
    {by_line}
"""

    console.print(banner, style="bold cyan")


def print_target_header(target: str, target_type: str):
    """Print a styled target header."""
    console.print()
    console.rule(f"[bold yellow] Target: {target}[/bold yellow]")
    console.print(f"[dim]Type: {target_type} | Started: {time.strftime('%H:%M:%S')}[/dim]")
    console.print()


def print_results(result: dict, show_all: bool = False):
    """Display reconnaissance results beautifully."""
    if not result:
        console.print("[red]No results returned.[/red]")
        return

    # Summary panel
    findings_count = len(result.get("findings", []))
    warnings_count = len(result.get("warnings", []))

    summary = Table.grid(padding=(0, 2))
    summary.add_column()
    summary.add_column()

    summary.add_row("Target", f"[bold cyan]{result.get('target', '?')}[/bold cyan]")
    summary.add_row("Type", f"[bold]{result.get('type', '?')}[/bold]")
    summary.add_row("Findings", f"[green]{findings_count}[/green] items")
    if warnings_count:
        summary.add_row("Warnings", f"[yellow]{warnings_count}[/yellow] items")

    console.print(Panel(
        summary,
        title="[bold] Reconnaissance Summary[/bold]",
        border_style="cyan",
        box=box.ROUNDED,
    ))
    console.print()

    # Findings section
    if result.get("findings"):
        findings_title = Text(" Findings", style="bold green")
        console.print(findings_title)
        console.print("─" * 50, style="dim")

        for finding in result["findings"]:
            if finding.strip():
                # Color code based on content
                if finding.startswith(""):
                    console.print(f"  [red]{finding[2:].strip()}[/red]")
                elif finding.startswith(""):
                    console.print(f"  [yellow]{finding[2:].strip()}[/yellow]")
                elif finding.startswith(""):
                    console.print(f"  [bold red]{finding[2:].strip()}[/bold red]")
                elif finding.startswith(""):
                    console.print(f"  [green]{finding[2:].strip()}[/green]")
                elif finding.startswith(""):
                    console.print(f"  [green]{finding[3:].strip()}[/green]")
                else:
                    console.print(f"  {finding}")
        console.print()

    # Warnings
    if result.get("warnings"):
        for warning in result["warnings"]:
            if warning.strip():
                console.print(f"  [yellow]  {warning}[/yellow]")
        console.print()

    # Data details (compact)
    data = result.get("data", {})
    if data and show_all:
        console.print("[bold] Detailed Data[/bold]")
        console.print("─" * 50, style="dim")

        data_table = Table(box=box.SIMPLE, padding=(0, 2))
        data_table.add_column("Key", style="cyan", no_wrap=True)
        data_table.add_column("Value", style="white")

        for key, value in data.items():
            if isinstance(value, str):
                data_table.add_row(key, value[:80])
            elif isinstance(value, (int, float, bool)):
                data_table.add_row(key, str(value))
            elif isinstance(value, list):
                items = ", ".join(str(v) for v in value[:5])
                if len(value) > 5:
                    items += f" ... ({len(value)} total)"
                data_table.add_row(key, items[:100])
            elif isinstance(value, dict):
                data_table.add_row(key, f"({len(value)} fields)")
            else:
                data_table.add_row(key, str(value)[:80])

        console.print(data_table)
        console.print()

    # OSINT Links
    lookup_links = data.get("lookup_links", [])
    if lookup_links:
        console.print("[bold] OSINT Lookup Links[/bold]")
        console.print("─" * 50, style="dim")
        for link in lookup_links:
            console.print(f"  • [link={link['url']}]{link['title']}[/link]")
            console.print(f"    [dim]{link['url']}[/dim]")
        console.print()

    # Platforms found (for username module)
    platforms = data.get("platforms_found", [])
    if platforms:
        console.print("[bold] Found On Platforms[/bold]")
        console.print("─" * 50, style="dim")
        platform_table = Table(box=box.SIMPLE, padding=(0, 2))
        platform_table.add_column("Platform", style="green")
        platform_table.add_column("URL", style="cyan")

        for p in platforms:
            platform_table.add_row(p["name"], p["url"])

        console.print(platform_table)
        console.print()


def print_timing(duration: float):
    """Print execution timing."""
    console.print(f"[dim]Completed in {duration:.1f}s[/dim]")


def print_error(message: str):
    """Print an error message."""
    console.print(f"\n[bold red] Error:[/bold red] {message}\n")


def print_welcome():
    """Print welcome message for interactive mode."""
    console.print()
    console.print("[bold yellow] ReconForge Interactive Mode[/bold yellow]")
    console.print("[dim]Type 'help' for commands, 'exit' to quit[/dim]")
    console.print()


def create_progress(text: str = "Scanning...") -> Progress:
    """Create a progress spinner."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        console=console,
    )
