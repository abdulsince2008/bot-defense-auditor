#!/usr/bin/env python3
from __future__ import annotations
import sys
import asyncio
from pathlib import Path
import click
from rich.console import Console

from .models import Config, LEGITIMATE_BOTS, SUSPICIOUS_BOTS
from .runner import run_all_tests
from .reporter import print_results, print_config_preview, RunSummary

console = Console()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("config", type=click.Path(exists=True, path_type=Path), default="config.yaml")
@click.option("--browser", "-b", is_flag=True, help="Use Playwright browser (real TLS/JS) instead of httpx")
@click.option("--json", "-j", is_flag=True, help="Output results as JSON")
@click.option("--signature", "-s", multiple=True, help="Run only specific signatures (can repeat)")
@click.option("--dry-run", "-n", is_flag=True, help="Show config and signatures without running tests")
@click.option("--list-signatures", "-l", is_flag=True, help="List all available signatures and exit")
@click.version_option(version="1.0.0", prog_name="bot-defense-auditor")
def main(
    config: Path,
    browser: bool,
    json: bool,
    signature: tuple[str, ...],
    dry_run: bool,
    list_signatures: bool,
):
    """
    Bot Defense Auditor — Test your WAF/bot detection rules against known signatures.

    Run against your own staging site to verify legitimate crawlers aren't blocked
    and suspicious traffic is caught. Uses either fast HTTP (httpx) or real browser
    (Playwright) for TLS fingerprint testing.

    Example:
      bot-audit config.yaml
      bot-audit config.yaml --browser --signature Googlebot --signature "Headless-Chrome"
    """
    try:
        cfg = Config.from_yaml(str(config))
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Config file not found: {config}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        sys.exit(1)

    if list_signatures:
        print_signatures(cfg.signatures)
        return

    if dry_run:
        print_config_preview(str(config))
        print_signatures(cfg.signatures)
        return

    # Validate target URL
    if not cfg.target.url.startswith(("http://", "https://")):
        console.print("[red]Error:[/red] Target URL must start with http:// or https://")
        sys.exit(1)

    # Run tests (suppress status messages in JSON mode)
    if not json:
        console.print(f"[cyan]Starting audit against[/cyan] {cfg.target.full_url}")
        if browser:
            console.print("[yellow]Using Playwright browser mode (slower, real TLS fingerprints)[/yellow]")
        else:
            console.print("[green]Using httpx direct HTTP mode (fast)[/green]")

    signatures_filter = list(signature) if signature else None

    try:
        results = asyncio.run(run_all_tests(
            config_path=str(config),
            use_browser=browser,
            signatures_filter=signatures_filter,
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error during test run:[/red] {e}")
        if not json:
            console.print_exception()
        sys.exit(1)

    # Generate summary
    summary = RunSummary.from_results(
        results,
        legitimate_bots=LEGITIMATE_BOTS,
        suspicious_bots=SUSPICIOUS_BOTS,
    )

    # Output results
    print_results(results, summary, json_output=json)

    # Exit code: 1 if false positives found (legitimate bots blocked)
    if summary.false_positives:
        sys.exit(1)
    sys.exit(0)


def print_signatures(signatures: list):
    """Print all available signatures grouped by category"""
    from rich.table import Table
    from rich import box

    table = Table(title="Available Signatures", box=box.SIMPLE)
    table.add_column("Name", style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("User-Agent", width=60)

    categories = {
        "Googlebot": "✓ Legitimate Crawler",
        "Bingbot": "✓ Legitimate Crawler",
        "Googlebot-Mobile": "✓ Legitimate Crawler",
        "Chrome-Latest": "✓ Real Browser",
        "Firefox-Latest": "✓ Real Browser",
        "Safari-MacOS": "✓ Real Browser",
        "Python-Requests": "✗ Suspicious",
        "cURL": "✗ Suspicious",
        "Go-http-client": "✗ Suspicious",
        "Java-HttpClient": "✗ Suspicious",
        "Node-Fetch": "✗ Suspicious",
        "Headless-Chrome": "✗ Headless/Bot",
        "PhantomJS": "✗ Headless/Bot",
        "No-User-Agent": "✗ Malformed",
        "No-Accept-Header": "✗ Malformed",
        "Bot-Like-Headers": "✗ Suspicious",
    }

    for sig in signatures:
        cat = categories.get(sig.name, "? Unknown")
        ua = sig.user_agent[:55] + "..." if len(sig.user_agent) > 55 else sig.user_agent
        table.add_row(sig.name, cat, ua or "(empty)")

    console.print(table)


if __name__ == "__main__":
    main()