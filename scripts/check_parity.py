#!/usr/bin/env python3
"""Run both CLIs on one fixture and compare check IDs and severities."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TS_ROOT = ROOT.parent / "clawguard-npm"
FIXTURE = ROOT / "tests" / "fixtures" / "current_insecure"


def run(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> dict:
    completed = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True)
    if completed.returncode not in (0, 2):
        raise SystemExit(f"{' '.join(command)} failed:\n{completed.stderr}\n{completed.stdout}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON from {' '.join(command)}: {exc}\n{completed.stdout}") from exc


def main() -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    python_result = run(
        [sys.executable, "-m", "clawguard.cli", "scan", "--path", str(FIXTURE), "--json"],
        ROOT, environment,
    )
    ts_result = run(
        ["node", "dist/index.js", "scan", "--path", str(FIXTURE), "--json"], TS_ROOT,
    )
    python_checks = sorted((finding["id"], finding["severity"]) for finding in python_result["findings"])
    ts_checks = sorted((finding["id"], finding["severity"]) for finding in ts_result["findings"])
    if python_checks != ts_checks:
        print("Only in Python:", sorted(set(python_checks) - set(ts_checks)))
        print("Only in TypeScript:", sorted(set(ts_checks) - set(python_checks)))
        raise SystemExit(1)
    if python_result != ts_result:
        raise SystemExit("Check IDs/severities match, but the complete JSON outputs differ")
    print(f"Parity OK: {len(python_checks)} check IDs/severities and complete JSON output match")


if __name__ == "__main__":
    main()
