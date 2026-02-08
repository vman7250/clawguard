"""Check sandbox and execution security settings."""

import shutil
from pathlib import Path

from clawguard.models import Finding, Severity


def check_sandbox(openclaw_path: Path) -> list[Finding]:
    """Check sandbox enforcement and exec security."""
    findings = []
    config_file = openclaw_path / "openclaw.json"

    if not config_file.exists():
        return findings

    try:
        import json5
        config = json5.loads(config_file.read_text(errors="ignore"))
    except Exception:
        return findings

    agents = config.get("agents", {})
    defaults = agents.get("defaults", {})
    sandbox = defaults.get("sandbox", {})

    # Check sandbox mode
    mode = sandbox.get("mode", "off")
    if mode == "off":
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Sandbox mode is OFF",
            details=[
                f'agents.defaults.sandbox.mode = "{mode}"',
                "The AI agent has unrestricted access to your system",
                "It can run any shell command, modify any file, and access the network",
            ],
            fix='Set agents.defaults.sandbox.mode to "all" in openclaw.json',
            category="sandbox",
        ))

    # Check Docker availability (required for sandbox)
    if mode != "off" and not shutil.which("docker"):
        findings.append(Finding(
            severity=Severity.HIGH,
            title="Docker not found (required for sandbox)",
            details=["Sandbox mode is enabled but Docker is not installed"],
            fix="Install Docker: https://docs.docker.com/get-docker/",
            category="sandbox",
        ))

    # Check Docker network setting
    docker_config = sandbox.get("docker", {})
    docker_network = docker_config.get("network")
    if mode != "off" and docker_network != "none":
        findings.append(Finding(
            severity=Severity.HIGH,
            title="Sandbox container has network access",
            details=[
                f'sandbox.docker.network = "{docker_network or "default"}"',
                "Sandboxed agent can make external network requests",
            ],
            fix='Set sandbox.docker.network to "none" in openclaw.json',
            category="sandbox",
        ))

    # Check exec host setting
    tools = config.get("tools", {})
    exec_config = tools.get("exec", {})
    exec_host = exec_config.get("host", "sandbox")
    if exec_host == "gateway":
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Tool execution runs directly on host",
            details=[
                'tools.exec.host = "gateway"',
                "Commands bypass the sandbox and execute on your machine",
            ],
            fix='Set tools.exec.host to "sandbox" in openclaw.json',
            category="sandbox",
        ))

    # Check exec security mode
    exec_security = exec_config.get("security")
    if exec_security != "allowlist":
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Exec security not in allowlist mode",
            details=[
                f'tools.exec.security = "{exec_security or "default"}"',
                "Allowlist mode restricts command chaining and redirections",
            ],
            fix='Set tools.exec.security to "allowlist" in openclaw.json',
            category="sandbox",
        ))

    # Check if Docker is available at all (informational)
    if shutil.which("docker"):
        findings.append(Finding(
            severity=Severity.INFO,
            title="Docker available for sandboxing",
            details=["Docker is installed and can be used for sandbox isolation"],
            category="sandbox",
        ))

    return findings
