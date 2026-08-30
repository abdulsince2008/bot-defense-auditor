from __future__ import annotations
import json
from dataclasses import asdict
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .models import TestResult, Verdict, RunSummary, LEGITIMATE_BOTS, SUSPICIOUS_BOTS


console = Console()


def get_verdict_style(verdict: Verdict) -> str:
    styles = {
        Verdict.ALLOWED: "green",
        Verdict.BLOCKED: "red",
        Verdict.REDIRECTED: "yellow",
        Verdict.ERROR: "magenta",
    }
    return styles.get(verdict, "white")


def get_verdict_icon(verdict: Verdict) -> str:
    icons = {
        Verdict.ALLOWED: "✓",
        Verdict.BLOCKED: "✗",
        Verdict.REDIRECTED: "→",
        Verdict.ERROR: "⚠",
    }
    return icons.get(verdict, "?")


def format_results_table(results: list[TestResult], show_headers: bool = False) -> Table:
    table = Table(
        title="Bot Defense Audit Results",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )

    table.add_column("Signature", style="bold", width=22)
    table.add_column("Verdict", justify="center", width=10)
    table.add_column("Status", justify="center", width=8)
    table.add_column("Time (ms)", justify="right", width=10)
    table.add_column("WAF Headers", width=30)
    table.add_column("Error / Redirect", width=35)

    for r in results:
        style = get_verdict_style(r.verdict)
        icon = get_verdict_icon(r.verdict)

        waf_info = ""
        if r.waf_headers:
            waf_info = ", ".join(f"{k}: {v[:20]}" for k, v in list(r.waf_headers.items())[:2])

        extra = ""
        if r.error:
            extra = f"ERR: {r.error[:30]}"
        elif r.redirected_to:
            extra = f"→ {r.redirected_to[:30]}"

        # Mark legitimate bots that were blocked (false positive)
        name = r.signature_name
        if name in LEGITIMATE_BOTS and r.verdict == Verdict.BLOCKED:
            name = f"[bold red]⚠ {name}[/bold red]"
        elif name in SUSPICIOUS_BOTS and r.verdict == Verdict.ALLOWED:
            name = f"[bold yellow]⚠ {name}[/bold yellow]"

        table.add_row(
            name,
            f"[{style}]{icon} {r.verdict.value}[/{style}]",
            str(r.status_code) if r.status_code else "N/A",
            f"{r.elapsed_ms:.0f}",
            waf_info or "—",
            extra or "—",
        )

    return table


def format_summary(summary: RunSummary) -> Panel:
    lines = [
        f"Total Tests:  [bold]{summary.total}[/bold]",
        f"  [green]✓ Allowed:[/green]    {summary.allowed}",
        f"  [red]✗ Blocked:[/red]     {summary.blocked}",
        f"  [yellow]→ Redirected:[/yellow]  {summary.redirected}",
        f"  [magenta]⚠ Errors:[/magenta]      {summary.errors}",
        "",
    ]

    if summary.false_positives:
        lines.append("[bold red]FALSE POSITIVES (Legitimate bots blocked):[/bold red]")
        for fp in summary.false_positives:
            lines.append(f"  • {fp}")
        lines.append("")

    if summary.false_negatives:
        lines.append("[bold yellow]FALSE NEGATIVES (Suspicious bots allowed):[/bold yellow]")
        for fn in summary.false_negatives:
            lines.append(f"  • {fn}")
        lines.append("")

    if not summary.false_positives and not summary.false_negatives:
        lines.append("[green]No false positives or negatives detected.[/green]")

    return Panel("\n".join(lines), title="Summary", border_style="cyan", box=box.ROUNDED)


def print_results(results: list[TestResult], summary: RunSummary, json_output: bool = False):
    if json_output:
        output = {
            "summary": asdict(summary),
            "results": [
                {
                    "signature": r.signature_name,
                    "method": r.method.value,
                    "url": r.url,
                    "status_code": r.status_code,
                    "verdict": r.verdict.value,
                    "elapsed_ms": r.elapsed_ms,
                    "waf_headers": r.waf_headers,
                    "error": r.error,
                    "redirected_to": r.redirected_to,
                }
                for r in results
            ],
        }
        console.print_json(json.dumps(output, indent=2))
    else:
        console.print(format_results_table(results))
        console.print()
        console.print(format_summary(summary))


def print_config_preview(config_path: str):
    """Print a preview of the config being used"""
    import yaml
    with open(config_path) as f:
        data = yaml.safe_load(f)

    console.print(Panel(
        f"Target: [bold]{data['target']['url']}{data['target'].get('path', '/')}[/bold]\n"
        f"Signatures: [bold]{len(data['signatures'])}[/bold]\n"
        f"Methods: [bold]{', '.join(data.get('settings', {}).get('methods', ['GET']))}[/bold]\n"
        f"Timeout: [bold]{data.get('settings', {}).get('timeout', 10)}s[/bold]",
        title="Configuration",
        border_style="blue",
    ))