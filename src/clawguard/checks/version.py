"""Check OpenClaw and Node.js versions for known vulnerabilities."""

import re
import subprocess
from pathlib import Path

from clawguard.models import Finding, Severity

# Known CVEs by version
CVES = [
    {
        "id": "CVE-2026-25253",
        "fixed_in": "2026.1.29",
        "severity": Severity.CRITICAL,
        "description": "One-click RCE via malicious link (CVSS 8.8)",
    },
    {
        "id": "CVE-2026-21636",
        "fixed_in": "2026.2.0",
        "severity": Severity.HIGH,
        "description": "Permission model bypass (sandbox escape)",
    },
]

MIN_NODE_VERSION = (22, 12, 0)


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    """Parse a version string into a comparable tuple."""
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_str)
    if match:
        return tuple(int(x) for x in match.groups())
    # Handle YYYY.M.D format
    match = re.search(r'(\d{4})\.(\d+)\.(\d+)', version_str)
    if match:
        return tuple(int(x) for x in match.groups())
    return None


def _run_command(cmd: list[str]) -> str | None:
    """Run a command and return stdout, or None on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip() if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def check_version(openclaw_path: Path) -> tuple[list[Finding], str | None, str | None]:
    """Check OpenClaw and Node.js versions. Returns (findings, oc_version, node_version)."""
    findings = []
    oc_version = None
    node_version = None

    # Try to get OpenClaw version
    version_output = _run_command(["openclaw", "--version"])
    if version_output:
        oc_version = version_output
        parsed = _parse_version(version_output)
        if parsed:
            for cve in CVES:
                cve_fixed = _parse_version(cve["fixed_in"])
                if cve_fixed and parsed < cve_fixed:
                    findings.append(Finding(
                        severity=cve["severity"],
                        title=f"Vulnerable to {cve['id']}",
                        details=[
                            f"Installed: {oc_version}",
                            f"Fixed in: {cve['fixed_in']}",
                            cve["description"],
                        ],
                        fix="Update OpenClaw: bunx openclaw@latest",
                        category="version",
                    ))
        if not findings:
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"OpenClaw version {oc_version} - up to date",
                category="version",
            ))
    else:
        # Try to find version from package.json in common locations
        for pkg_path in [
            Path.home() / ".bun" / "install" / "global" / "node_modules" / "openclaw" / "package.json",
            Path("/usr/local/lib/node_modules/openclaw/package.json"),
        ]:
            if pkg_path.exists():
                try:
                    import json
                    pkg = json.loads(pkg_path.read_text())
                    oc_version = pkg.get("version", "unknown")
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title=f"OpenClaw version {oc_version} (from package.json)",
                        category="version",
                    ))
                    break
                except Exception:
                    pass

        if not oc_version:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Could not determine OpenClaw version",
                details=["openclaw command not found in PATH"],
                fix="Ensure OpenClaw is installed: bunx openclaw@latest",
                category="version",
            ))

    # Check Node.js version
    node_output = _run_command(["node", "--version"])
    if node_output:
        node_version = node_output.lstrip("v")
        parsed = _parse_version(node_version)
        if parsed and parsed < MIN_NODE_VERSION:
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Node.js version {node_version} is below minimum ({'.'.join(str(x) for x in MIN_NODE_VERSION)})",
                details=["Older Node.js versions have known security vulnerabilities"],
                fix=f"Update Node.js to >= {'.'.join(str(x) for x in MIN_NODE_VERSION)}",
                category="version",
            ))
        elif parsed:
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"Node.js version {node_version} - OK",
                category="version",
            ))

    return findings, oc_version, node_version
