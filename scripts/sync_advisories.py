#!/usr/bin/env python3
"""Generate the Python and TypeScript advisory tables from GitHub data."""

from __future__ import annotations

import argparse
import json
import pprint
import re
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TS_ROOT = ROOT.parent / "clawguard-npm"
DEFAULT_INPUT = ROOT / "data" / "ghsa-advisories-full.json"
DEFAULT_CVES = ROOT / "data" / "openclaw-cves-all.json"
UPSTREAM = (
    "https://raw.githubusercontent.com/jgamblin/OpenClawCVEs/"
    "main/ghsa-advisories-full.json"
)


def normalize_version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lstrip("v")
    match = re.search(r"\d{4}\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", value)
    return match.group(0) if match else None


def version_key(value: str) -> tuple:
    match = re.fullmatch(r"(\d{4})\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", value)
    assert match
    suffix = match.group(4)
    parts = tuple((0, int(part)) if part.isdigit() else (1, part.lower()) for part in suffix.split(".")) if suffix else ()
    return (*map(int, match.group(1, 2, 3)), 1 if suffix is None else 0, parts)


def normalize_advisories(raw: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    records: list[dict[str, Any]] = []
    published_dates: list[str] = []
    for item in raw:
        patches = []
        for vulnerability in item.get("vulnerabilities") or []:
            patch = normalize_version(vulnerability.get("first_patched_version"))
            if patch:
                patches.append(patch)
            for candidate in vulnerability.get("patched_versions") or []:
                patch = normalize_version(candidate)
                if patch:
                    patches.append(patch)

        score = (item.get("cvss") or {}).get("score")
        if score is None:
            score = max(
                (
                    float(entry.get("score") or 0)
                    for entry in (item.get("cvss_severities") or {}).values()
                    if isinstance(entry, dict)
                ),
                default=0.0,
            )
        published = str(item.get("published_at") or "")[:10]
        if published:
            published_dates.append(published)
        records.append(
            {
                "ghsa": item.get("ghsa_id") or "",
                "cve": item.get("cve_id"),
                "severity": str(item.get("severity") or "unknown").upper(),
                "cvss": float(score or 0),
                "title": str(item.get("summary") or "").strip(),
                "patched_version": max(patches, key=version_key) if patches else None,
                "published": published or None,
            }
        )

    records.sort(key=lambda row: (row["severity"], -row["cvss"], row["ghsa"]))
    return records, max(published_dates, default="unknown")


def write_python(records: list[dict[str, Any]], snapshot: str, cve_count: int) -> None:
    target = ROOT / "src" / "clawguard" / "advisories.py"
    payload = pprint.pformat(records, width=100, sort_dicts=False)
    target.write_text(
        '"""Generated advisory snapshot. Do not edit by hand."""\n\n'
        f'ADVISORY_SNAPSHOT = {snapshot!r}\n'
        f"TRACKED_CVE_COUNT = {cve_count}\n"
        f"ADVISORIES = {payload}\n"
    )


def write_typescript(records: list[dict[str, Any]], snapshot: str, cve_count: int) -> None:
    target = TS_ROOT / "src" / "checks" / "advisories.ts"
    payload = json.dumps(records, indent=2, ensure_ascii=False)
    target.write_text(
        "/** Generated advisory snapshot. Do not edit by hand. */\n\n"
        f'export const ADVISORY_SNAPSHOT = {json.dumps(snapshot)};\n'
        f"export const TRACKED_CVE_COUNT = {cve_count};\n"
        f"export const ADVISORIES = {payload} as const;\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--cves", type=Path, default=DEFAULT_CVES)
    parser.add_argument("--fetch", action="store_true", help="fetch the upstream JSON first")
    args = parser.parse_args()
    if args.fetch:
        with urllib.request.urlopen(UPSTREAM, timeout=30) as response:
            raw = json.load(response)
        args.input.parent.mkdir(parents=True, exist_ok=True)
        args.input.write_text(json.dumps(raw, indent=2) + "\n")
    else:
        raw = json.loads(args.input.read_text())
    records, snapshot = normalize_advisories(raw)
    cve_count = len(json.loads(args.cves.read_text()))
    write_python(records, snapshot, cve_count)
    write_typescript(records, snapshot, cve_count)
    print(f"Generated {len(records)} advisories and {cve_count}-CVE headline (snapshot {snapshot})")


if __name__ == "__main__":
    main()
