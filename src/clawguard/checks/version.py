"""OpenClaw version drift and advisory intelligence."""

from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from clawguard.advisories import ADVISORIES, ADVISORY_SNAPSHOT
from clawguard.models import Finding, Severity

LATEST_STABLE = "2026.8.1"
LATEST_PRERELEASE = "2026.9.1-beta.1"
MIN_NODE_VERSION = (22, 22, 3)
ADVISORY_URL = "https://raw.githubusercontent.com/jgamblin/OpenClawCVEs/main/ghsa-advisories-full.json"


@dataclass(frozen=True)
class OpenClawVersion:
    core: tuple[int, int, int]
    prerelease: tuple[int | str, ...] | None = None

    def __lt__(self, other: "OpenClawVersion") -> bool:
        if self.core != other.core:
            return self.core < other.core
        if self.prerelease is None:
            return False
        if other.prerelease is None:
            return True
        for left, right in zip(self.prerelease, other.prerelease):
            if left == right:
                continue
            if isinstance(left, int) and isinstance(right, str):
                return True
            if isinstance(left, str) and isinstance(right, int):
                return False
            return left < right
        return len(self.prerelease) < len(other.prerelease)


def parse_openclaw_version(value: str) -> OpenClawVersion | None:
    match = re.search(r"(\d{4})\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", value)
    if not match:
        return None
    suffix = match.group(4)
    prerelease = None
    if suffix is not None:
        prerelease = tuple(int(part) if part.isdigit() else part.lower() for part in suffix.split("."))
    return OpenClawVersion(tuple(map(int, match.group(1, 2, 3))), prerelease)


def _run_command(cmd: list[str]) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip() if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _normalise_remote(raw: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    records: list[dict[str, Any]] = []
    dates: list[str] = []
    for item in raw:
        patches = []
        for vulnerability in item.get("vulnerabilities") or []:
            value = vulnerability.get("first_patched_version")
            if isinstance(value, str) and parse_openclaw_version(value):
                patches.append(value.lstrip("v"))
        score = (item.get("cvss") or {}).get("score")
        if score is None:
            score = max(
                (float(v.get("score") or 0) for v in (item.get("cvss_severities") or {}).values()),
                default=0.0,
            )
        published = str(item.get("published_at") or "")[:10]
        if published:
            dates.append(published)
        records.append({
            "ghsa": item.get("ghsa_id") or "", "cve": item.get("cve_id"),
            "severity": str(item.get("severity") or "unknown").upper(),
            "cvss": float(score or 0), "title": str(item.get("summary") or ""),
            "patched_version": max(patches, key=lambda value: parse_openclaw_version(value)) if patches else None,
            "published": published or None,
        })
    return records, max(dates, default=ADVISORY_SNAPSHOT)


def load_advisories(refresh: bool = False) -> tuple[list[dict[str, Any]], str, str | None]:
    if not refresh:
        return list(ADVISORIES), ADVISORY_SNAPSHOT, None
    try:
        with urllib.request.urlopen(ADVISORY_URL, timeout=15) as response:
            raw = json.load(response)
        records, snapshot = _normalise_remote(raw)
        return records, snapshot, None
    except Exception as exc:
        return list(ADVISORIES), ADVISORY_SNAPSHOT, f"Refresh failed; using vendored data: {exc}"


def advisory_findings(installed: str, advisories: list[dict[str, Any]], snapshot: str) -> list[Finding]:
    parsed = parse_openclaw_version(installed)
    if not parsed:
        return []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for advisory in advisories:
        parsed_patch = parse_openclaw_version(str(advisory.get("patched_version") or ""))
        if parsed_patch and parsed < parsed_patch:
            grouped.setdefault(str(advisory["severity"]), []).append(advisory)

    findings: list[Finding] = []
    for band in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = sorted(grouped.get(band, []), key=lambda row: (-float(row["cvss"]), row["ghsa"]))
        if not items:
            continue
        top = [str(row.get("cve") or row["ghsa"]) for row in items[:3]]
        full = [
            f"{row.get('cve') or row['ghsa']} (CVSS {float(row['cvss']):.1f}, fixed {row['patched_version']}): {row['title']}"
            for row in items
        ]
        findings.append(Finding(
            id=f"advisory.{band.lower()}", severity=Severity(band),
            title=f"{band}: {len(items)} advisories fixed after your version — {', '.join(top)}",
            details=[f"Installed: {installed}", f"Advisory snapshot: {snapshot}"],
            verbose_details=full, fix="Update OpenClaw: bunx openclaw@latest",
            category="advisories", key_path="version",
        ))
    return findings


def _installed_version(openclaw_path: Path) -> str | None:
    output = _run_command(["openclaw", "--version"])
    if output:
        match = re.search(r"\d{4}\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", output)
        return match.group(0) if match else output
    for candidate in [
        openclaw_path / "package.json",
        Path.home() / ".bun/install/global/node_modules/openclaw/package.json",
        Path("/usr/local/lib/node_modules/openclaw/package.json"),
    ]:
        try:
            version = json.loads(candidate.read_text()).get("version")
            if version:
                return str(version)
        except Exception:
            continue
    return None


def check_version(openclaw_path: Path, refresh_advisories: bool = False) -> tuple[list[Finding], str | None, str | None, str]:
    findings: list[Finding] = []
    oc_version = _installed_version(openclaw_path)
    advisories, snapshot, refresh_warning = load_advisories(refresh_advisories)
    if refresh_warning:
        findings.append(Finding(
            id="advisory.refresh", severity=Severity.INFO,
            title="Could not refresh advisory data; vendored snapshot is in use",
            details=[refresh_warning, f"Snapshot: {snapshot}"], category="advisories",
        ))
    if oc_version:
        findings.extend(advisory_findings(oc_version, advisories, snapshot))
        parsed = parse_openclaw_version(oc_version)
        stable = parse_openclaw_version(LATEST_STABLE)
        if parsed and stable and parsed < stable:
            findings.append(Finding(
                id="version.openclaw.outdated", severity=Severity.MEDIUM,
                title=f"OpenClaw {oc_version} is older than stable {LATEST_STABLE}",
                details=[f"Latest prerelease: {LATEST_PRERELEASE}"],
                fix="Update OpenClaw: bunx openclaw@latest", category="version", key_path="version",
            ))
    else:
        findings.append(Finding(
            id="version.openclaw.unknown", severity=Severity.MEDIUM,
            title="Could not determine OpenClaw version",
            details=["openclaw command not found and no package.json version was available"],
            fix="Ensure OpenClaw is installed: bunx openclaw@latest", category="version",
        ))

    node_output = _run_command(["node", "--version"])
    node_version = node_output.lstrip("v") if node_output else None
    if node_version:
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", node_version)
        parsed_node = tuple(map(int, match.groups())) if match else None
        if parsed_node and parsed_node < MIN_NODE_VERSION:
            minimum = ".".join(map(str, MIN_NODE_VERSION))
            findings.append(Finding(
                id="version.node.minimum", severity=Severity.HIGH,
                title=f"Node.js version {node_version} is below minimum ({minimum})",
                fix=f"Update Node.js to >= {minimum}", category="version", key_path="engines.node",
            ))
    return findings, oc_version, node_version, snapshot
