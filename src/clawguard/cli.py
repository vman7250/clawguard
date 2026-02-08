"""ClawGuard CLI - Security scanner for OpenClaw installations."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from clawguard import __version__
from clawguard.reporter import print_banner, print_json, print_report
from clawguard.scanner import CHECK_REGISTRY, detect_openclaw_path, run_fix, run_scan

app = typer.Typer(
    name="clawguard",
    help="Security scanner for OpenClaw AI agent installations",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Path to OpenClaw directory"),
    format: str = typer.Option("rich", "--format", "-f", help="Output format: rich or json"),
    check: Optional[list[str]] = typer.Option(None, "--check", "-c", help="Run specific checks only"),
) -> None:
    """Scan your OpenClaw installation for security issues."""
    # Detect or use provided path
    openclaw_path = path or detect_openclaw_path()

    if not openclaw_path:
        console.print("[red]Could not find OpenClaw installation.[/red]")
        console.print("Checked: ~/.openclaw, ~/.clawdbot, ~/.moltbot")
        console.print("Use --path to specify the directory.")
        raise typer.Exit(1)

    if not openclaw_path.exists():
        console.print(f"[red]Path does not exist: {openclaw_path}[/red]")
        raise typer.Exit(1)

    # Validate check names
    if check:
        valid_checks = set(CHECK_REGISTRY.keys())
        for c in check:
            if c not in valid_checks:
                console.print(f"[red]Unknown check: {c}[/red]")
                console.print(f"Available: {', '.join(sorted(valid_checks))}")
                raise typer.Exit(1)

    # Run scan
    result = run_scan(openclaw_path, checks=check)

    # Output
    if format == "json":
        print_json(result)
    else:
        print_report(result)

    # Exit with non-zero if critical issues found
    if result.critical_count > 0:
        raise typer.Exit(2)


@app.command()
def fix(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Path to OpenClaw directory"),
) -> None:
    """Auto-fix common security issues in your OpenClaw installation."""
    openclaw_path = path or detect_openclaw_path()

    if not openclaw_path:
        console.print("[red]Could not find OpenClaw installation.[/red]")
        raise typer.Exit(1)

    print_banner()
    console.print(f"\nFixing security issues in [bold]{openclaw_path}[/bold] ...\n")

    actions = run_fix(openclaw_path)

    if actions:
        for action in actions:
            console.print(f"  [green]FIXED[/green]  {action}")
        console.print(f"\n[green]{len(actions)} issue(s) fixed.[/green]")
        console.print("Run [bold]clawguard scan[/bold] to verify.\n")
    else:
        console.print("[green]No auto-fixable issues found.[/green]\n")


@app.command()
def version() -> None:
    """Show ClawGuard version."""
    console.print(f"ClawGuard v{__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
