"""Check gateway security configuration."""

import socket
from pathlib import Path

from clawguard.models import Finding, Severity


def _check_port_exposed(port: int) -> bool:
    """Check if a port is listening on all interfaces (0.0.0.0)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex(("0.0.0.0", port))
            return result == 0
    except (socket.error, OSError):
        return False


def check_gateway(openclaw_path: Path) -> list[Finding]:
    """Check gateway security settings."""
    findings = []
    config_file = openclaw_path / "openclaw.json"

    if not config_file.exists():
        findings.append(Finding(
            severity=Severity.INFO,
            title="No OpenClaw config file found",
            details=[f"Expected at {config_file}"],
            category="gateway",
        ))
        return findings

    try:
        import json5
        config = json5.loads(config_file.read_text(errors="ignore"))
    except Exception:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Could not parse OpenClaw config file",
            details=["openclaw.json may be malformed"],
            category="gateway",
        ))
        return findings

    gateway = config.get("gateway", {})

    # Check bind setting
    bind = gateway.get("bind", "loopback")
    if bind != "loopback":
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Gateway bound to non-loopback: {bind}",
            details=[
                f'gateway.bind = "{bind}"',
                "This exposes the gateway to network access",
            ],
            fix='Set gateway.bind to "loopback" in openclaw.json',
            category="gateway",
        ))

    # Check auth token
    token = gateway.get("auth", {}).get("token") or gateway.get("token")
    if not token:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title="No gateway authentication token configured",
            details=["Anyone with network access can control your OpenClaw agent"],
            fix="Set gateway.auth.token in openclaw.json or re-run openclaw setup",
            category="gateway",
        ))
    elif len(str(token)) < 32:
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"Gateway auth token is weak ({len(str(token))} chars)",
            details=["Minimum recommended length: 32 characters"],
            fix="Generate a strong token: openssl rand -hex 32",
            category="gateway",
        ))

    # Check port exposure
    port = gateway.get("port", 18789)
    if _check_port_exposed(port):
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"Gateway port {port} is reachable on all interfaces",
            details=[
                f"Port {port} appears to be listening on 0.0.0.0",
                "The gateway may be accessible from the network",
            ],
            fix="Bind to loopback only and use a reverse proxy if external access is needed",
            category="gateway",
        ))

    return findings
