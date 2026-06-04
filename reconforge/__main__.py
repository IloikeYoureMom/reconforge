#!/usr/bin/env python3
"""
ReconForge — Main Entry Point
══════════════════════════════
Automated Cyber Reconnaissance Framework.

Usage:
    python -m reconforge domain example.com
    python -m reconforge email user@example.com
    python -m reconforge username johndoe
    python -m reconforge ip 8.8.8.8
    python -m reconforge phone "+972-54-1234567"
    python -m reconforge interactive
    python -m reconforge --help
"""

import sys
import argparse
import time
from typing import Optional

from . import __version__
from .cli import (
    console,
    print_banner,
    print_target_header,
    print_results,
    print_timing,
    print_error,
    print_welcome,
    create_progress,
)
from .report import generate_report
from .modules import domain, email, username, ip_tools, phone, crt, shodan, leaks
from .modules import github_dork, wayback, dorks, dnsbrute
from .modules import urlscan, otx, builtwith


MODULES = {
    "domain": domain.recon,
    "email": email.recon,
    "username": username.recon,
    "ip": ip_tools.recon,
    "phone": phone.recon,
    "crt": crt.recon,
    "certificates": crt.recon,
    "shodan": shodan.recon,
    "leaks": leaks.recon,
    "pastebin": leaks.recon,
    "github": github_dork.recon,
    "git": github_dork.recon,
    "wayback": wayback.recon,
    "history": wayback.recon,
    "dorks": dorks.recon,
    "google": dorks.recon,
    "dnsbrute": dnsbrute.recon,
    "brute": dnsbrute.recon,
    "urlscan": urlscan.recon,
    "otx": otx.recon,
    "threat": otx.recon,
    "builtwith": builtwith.recon,
    "bt": builtwith.recon,
    "tech": builtwith.recon,
}


def run_recon(module_name: str, target: str, output: Optional[str] = None) -> dict:
    """Run a reconnaissance module and optionally generate a report."""
    handler = MODULES.get(module_name)
    if not handler:
        print_error(f"Unknown module: {module_name}")
        sys.exit(1)

    start = time.time()

    # Show progress
    progress = create_progress(f"Running {module_name} reconnaissance...")
    task = progress.add_task("", total=None)
    progress.start()

    result = handler(target)

    progress.stop()

    duration = time.time() - start

    # Display results
    print_results(result, show_all=True)
    print_timing(duration)

    # Generate HTML report if requested
    if output:
        try:
            report_path = generate_report(result, output)
            console.print(f"\n[green] Report saved:[/green] [bold]{report_path}[/bold]")
        except Exception as e:
            console.print(f"\n[red] Failed to generate report: {e}[/red]")

    return result


def interactive_mode():
    """Run ReconForge in interactive mode."""
    print_banner()
    print_welcome()

    commands = {
        "domain": "domain",
        "d": "domain",
        "email": "email",
        "e": "email",
        "username": "username",
        "u": "username",
        "ip": "ip",
        "phone": "phone",
        "p": "phone",
        "crt": "crt",
        "certificates": "crt",
        "shodan": "shodan",
        "leaks": "leaks",
        "pastebin": "leaks",
        "l": "leaks",
        "github": "github",
        "git": "github",
        "wayback": "wayback",
        "history": "wayback",
        "dorks": "dorks",
        "google": "dorks",
        "g": "dorks",
        "dnsbrute": "dnsbrute",
        "brute": "dnsbrute",
        "urlscan": "urlscan",
        "otx": "otx",
        "threat": "otx",
        "builtwith": "builtwith",
        "bt": "builtwith",
        "tech": "builtwith",
    }

    while True:
        try:
            cmd = input("reconforge> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not cmd:
            continue

        if cmd in ("exit", "quit", "q"):
            console.print("[yellow]Goodbye![/yellow]")
            break

        if cmd in ("help", "h", "?"):
            console.print("""
[bold]Available Commands:[/bold]
  [cyan]domain[/cyan] <target>     - Domain reconnaissance
  [cyan]email[/cyan] <target>      - Email reconnaissance
  [cyan]username[/cyan] <target>  - Username reconnaissance
  [cyan]ip[/cyan] <target>        - IP address reconnaissance
  [cyan]phone[/cyan] <target>     - Phone number reconnaissance
  [cyan]crt[/cyan] <domain>       - Certificate Transparency (crt.sh)
  [cyan]shodan[/cyan] <ip>        - Shodan InternetDB intelligence
  [cyan]leaks[/cyan] <target>     - Leak/paste/breach search
  [cyan]github[/cyan] <target>    - GitHub dorking (sensitive data search)
  [cyan]wayback[/cyan] <domain>   - Wayback Machine URL history
  [cyan]dorks[/cyan] <domain>     - Google dork query generator
  [cyan]dnsbrute[/cyan] <domain>  - DNS subdomain brute-force
  [cyan]urlscan[/cyan] <domain>   - urlscan.io screenshots & history
  [cyan]otx[/cyan] <target>       - AlienVault OTX threat intelligence
  [cyan]builtwith[/cyan] <domain> - BuiltWith technology profile
  [cyan]report[/cyan] <filename>  - Generate HTML report (after a scan)
  [cyan]help[/cyan]               - Show this help
  [cyan]exit[/cyan]               - Exit interactive mode

[dim]Short aliases: d, e, u, p, l, g, git, history, google, brute, threat, bt, tech[/dim]
            """)
            continue

        if cmd == "clear":
            console.clear()
            print_welcome()
            continue

        # Parse: module target [--output file.html]
        parts = cmd.split()
        module_cmd = parts[0]
        output = None

        if module_cmd not in commands:
            console.print(f"[red]Unknown command: {module_cmd}. Type 'help' for commands.[/red]")
            continue

        if len(parts) < 2:
            console.print(f"[yellow]Usage: {module_cmd} <target> [--output file.html][/yellow]")
            continue

        target = parts[1]

        if "--output" in parts:
            idx = parts.index("--output")
            if idx + 1 < len(parts):
                output = parts[idx + 1]

        module_name = commands[module_cmd]
        console.clear()
        print_banner()
        print_target_header(target, module_name.capitalize())
        run_recon(module_name, target, output)


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        prog="reconforge",
        description="ReconForge — Automated Cyber Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reconforge domain example.com
  reconforge email user@example.com --report
  reconforge username johndoe -o report.html
  reconforge ip 8.8.8.8
  reconforge phone "+972-54-1234567"
  reconforge crt example.com
  reconforge shodan 8.8.8.8
  reconforge leaks user@example.com
  reconforge github example.com
  reconforge wayback example.com
  reconforge dorks example.com
  reconforge dnsbrute example.com
  reconforge urlscan example.com
  reconforge otx example.com
  reconforge builtwith example.com
  reconforge interactive
        """,
    )

    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"ReconForge v{__version__}",
    )

    parser.add_argument(
        "mode",
        nargs="?",
        choices=["domain", "email", "username", "ip", "phone", "crt", "certificates", "shodan", "leaks", "pastebin", "github", "git", "wayback", "history", "dorks", "google", "dnsbrute", "brute", "urlscan", "otx", "threat", "builtwith", "bt", "tech", "interactive"],
        help="Reconnaissance module to run, or 'interactive' for shell mode",
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target to investigate (domain, email, username, IP, or phone)",
    )

    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output HTML report file path (default: output/report.html)",
    )

    parser.add_argument(
        "--report", "-r",
        action="store_true",
        default=False,
        help="Generate HTML report in output/ directory",
    )

    args = parser.parse_args()

    print_banner()

    if not args.mode:
        parser.print_help()
        console.print("\n[yellow] Tip:[/yellow] Run [bold]reconforge interactive[/bold] for an interactive shell!")
        return

    if args.mode == "interactive":
        interactive_mode()
        return

    if not args.target:
        print_error(f"Target required for '{args.mode}' mode")
        console.print(f"[yellow]Usage: reconforge {args.mode} <target> [options][/yellow]")
        sys.exit(1)

    # Determine output path
    output = args.output
    if args.report and not output:
        # Sanitize target for filename
        safe_target = "".join(c if c.isalnum() else "_" for c in args.target[:30])
        output = f"output/recon_report_{safe_target}.html"

    print_target_header(args.target, args.mode.capitalize())
    run_recon(args.mode, args.target, output)


if __name__ == "__main__":
    main()
