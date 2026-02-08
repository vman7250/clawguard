"""Rich-formatted output for ClawGuard scan results."""

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from clawguard.models import Finding, ScanResult, Severity

console = Console()

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "bold cyan",
    Severity.INFO: "bold green",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[red]CRITICAL[/red]",
    Severity.HIGH: "[yellow]HIGH[/yellow]",
    Severity.MEDIUM: "[cyan]MEDIUM[/cyan]",
    Severity.INFO: "[green]INFO[/green]",
}


def get_score_style(score: int) -> str:
    if score <= 30:
        return "bold red"
    elif score <= 60:
        return "bold yellow"
    elif score <= 80:
        return "bold cyan"
    return "bold green"


def get_score_label(score: int) -> str:
    if score <= 30:
        return "Critical Risk"
    elif score <= 60:
        return "High Risk"
    elif score <= 80:
        return "Moderate Risk"
    return "Low Risk"


def print_banner() -> None:
    banner = Text()
    banner.append("ClawGuard", style="bold white")
    banner.append(" v0.1.0", style="dim")
    banner.append(" - OpenClaw Security Scanner", style="white")
    console.print(Panel(banner, border_style="blue"))


def print_finding(finding: Finding) -> None:
    icon = SEVERITY_ICONS[finding.severity]
    console.print(f"\n  {icon}  {finding.title}")
    for detail in finding.details:
        console.print(f"           {detail}", style="dim")
    if finding.fix:
        console.print(f"           [italic]Fix: {finding.fix}[/italic]")


def print_report(result: ScanResult) -> None:
    print_banner()
    console.print(f"\nScanning [bold]{result.openclaw_path}[/bold] ...\n")

    if not result.findings:
        console.print("[green]No security issues found![/green]")
        console.print(f"\nScore: [bold green]100/100 (Secure)[/bold green]")
        return

    # Sort: CRITICAL first, then HIGH, MEDIUM, INFO
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.INFO: 3}
    sorted_findings = sorted(result.findings, key=lambda f: severity_order[f.severity])

    for finding in sorted_findings:
        print_finding(finding)

    # Summary
    console.print("\n" + "=" * 50)

    score = result.score
    style = get_score_style(score)
    label = get_score_label(score)
    console.print(f"\n  Score: [{style}]{score}/100 ({label})[/{style}]")

    summary_parts = []
    if result.critical_count:
        summary_parts.append(f"[red]{result.critical_count} critical[/red]")
    if result.high_count:
        summary_parts.append(f"[yellow]{result.high_count} high[/yellow]")
    if result.medium_count:
        summary_parts.append(f"[cyan]{result.medium_count} medium[/cyan]")
    if result.info_count:
        summary_parts.append(f"[green]{result.info_count} info[/green]")

    console.print(f"  Found: {', '.join(summary_parts)}")

    fixable = sum(1 for f in result.findings if f.fix and f.severity != Severity.INFO)
    if fixable:
        console.print(f"  Run [bold]clawguard fix[/bold] to auto-fix {fixable} issues")

    console.print()


def print_json(result: ScanResult) -> None:
    output = {
        "score": result.score,
        "openclaw_path": result.openclaw_path,
        "openclaw_version": result.openclaw_version,
        "node_version": result.node_version,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "info": result.info_count,
        },
        "findings": [
            {
                "severity": f.severity.value,
                "title": f.title,
                "details": f.details,
                "fix": f.fix,
                "category": f.category,
            }
            for f in result.findings
        ],
    }
    console.print_json(json.dumps(output, indent=2))
