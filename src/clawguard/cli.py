"""ClawGuard command-line interface."""

import argparse
import sys
from pathlib import Path

from clawguard import __version__
from clawguard.reporter import print_banner, print_json, print_report
from clawguard.scanner import CHECK_REGISTRY, detect_openclaw_path, run_fix, run_migrate_env, run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clawguard", description="Security scanner for OpenClaw AI agent installations")
    parser.add_argument("--version", action="version", version=f"ClawGuard v{__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--path", "-p", type=Path)
    scan.add_argument("--format", "-f", default="rich", choices=["rich", "json"])
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--check", "-c", action="append")
    scan.add_argument("--verbose", "-v", action="store_true")
    scan.add_argument("--refresh-advisories", action="store_true")
    scan.add_argument("--with-openclaw-audit", action="store_true")
    fix = commands.add_parser("fix"); fix.add_argument("--path", "-p", type=Path)
    migrate = commands.add_parser("migrate-env"); migrate.add_argument("--path", "-p", type=Path); migrate.add_argument("--dry-run", action="store_true")
    commands.add_parser("version")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "version":
        print(f"ClawGuard v{__version__}"); return
    openclaw_path = args.path or detect_openclaw_path()
    if not openclaw_path or not openclaw_path.exists():
        print("Could not find OpenClaw installation. Use --path to specify it.", file=sys.stderr); raise SystemExit(1)
    if args.command == "scan":
        invalid = set(args.check or []) - set(CHECK_REGISTRY)
        if invalid:
            print(f"Unknown check: {', '.join(sorted(invalid))}", file=sys.stderr); raise SystemExit(1)
        result = run_scan(openclaw_path, args.check, args.refresh_advisories, args.with_openclaw_audit)
        print_json(result) if args.json or args.format == "json" else print_report(result, args.verbose)
        if result.critical_count:
            raise SystemExit(2)
    elif args.command == "fix":
        print_banner()
        actions = run_fix(openclaw_path)
        for action in actions:
            print(f"FIXED  {action}")
        if not actions:
            print("No auto-fixable issues found.")
    else:
        result = run_migrate_env(openclaw_path, args.dry_run)
        print(result)


if __name__ == "__main__":
    main()
