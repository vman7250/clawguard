"""Main scanner orchestrator - runs all security checks."""

import json
import os
import secrets
from pathlib import Path

from rich.console import Console

from clawguard.checks.credentials import check_credentials
from clawguard.checks.gateway import check_gateway
from clawguard.checks.memory import check_memory
from clawguard.checks.permissions import check_permissions
from clawguard.checks.sandbox import check_sandbox
from clawguard.checks.skills import check_skills
from clawguard.checks.version import check_version
from clawguard.models import ScanResult

console = Console()

# Map of check names to their functions
CHECK_REGISTRY = {
    "credentials": check_credentials,
    "gateway": check_gateway,
    "sandbox": check_sandbox,
    "permissions": check_permissions,
    "skills": check_skills,
    "memory": check_memory,
}


def detect_openclaw_path() -> Path | None:
    """Auto-detect the OpenClaw installation directory."""
    candidates = [
        Path.home() / ".openclaw",
        Path.home() / ".clawdbot",  # Legacy name
        Path.home() / ".moltbot",   # Legacy name
    ]

    env_path = os.environ.get("OPENCLAW_HOME")
    if env_path:
        candidates.insert(0, Path(env_path))

    for path in candidates:
        if path.exists() and path.is_dir():
            return path

    return None


def run_scan(openclaw_path: Path, checks: list[str] | None = None) -> ScanResult:
    """Run all security checks and return aggregated results."""
    result = ScanResult(openclaw_path=str(openclaw_path))

    # Version check (always runs, returns version info)
    with console.status("[bold blue]Checking versions...[/bold blue]"):
        version_findings, oc_version, node_version = check_version(openclaw_path)
        result.findings.extend(version_findings)
        result.openclaw_version = oc_version
        result.node_version = node_version

    # Run selected or all checks
    active_checks = checks if checks else list(CHECK_REGISTRY.keys())

    for check_name in active_checks:
        if check_name not in CHECK_REGISTRY:
            continue

        check_fn = CHECK_REGISTRY[check_name]
        label = check_name.replace("_", " ").title()

        with console.status(f"[bold blue]Checking {label}...[/bold blue]"):
            try:
                findings = check_fn(openclaw_path)
                result.findings.extend(findings)
            except Exception as e:
                console.print(f"[yellow]Warning: {check_name} check failed: {e}[/yellow]")

    return result


def run_fix(openclaw_path: Path) -> list[str]:
    """Auto-fix common security issues. Returns list of actions taken."""
    actions = []

    # Fix 1: File permissions
    if openclaw_path.exists():
        current = oct(os.stat(openclaw_path).st_mode & 0o777)
        if current != "0o700":
            os.chmod(openclaw_path, 0o700)
            actions.append(f"Fixed {openclaw_path} permissions: {current} -> 0o700")

    config_file = openclaw_path / "openclaw.json"
    if config_file.exists():
        current = oct(os.stat(config_file).st_mode & 0o777)
        if current != "0o600":
            os.chmod(config_file, 0o600)
            actions.append(f"Fixed {config_file.name} permissions: {current} -> 0o600")

    creds_dir = openclaw_path / "credentials"
    if creds_dir.exists():
        for f in creds_dir.iterdir():
            if f.is_file():
                current = oct(os.stat(f).st_mode & 0o777)
                if current != "0o600":
                    os.chmod(f, 0o600)
                    actions.append(f"Fixed {f.name} permissions: {current} -> 0o600")

    # Fix 2: Enable sandbox mode in config
    if config_file.exists():
        try:
            import json5
            config = json5.loads(config_file.read_text())

            modified = False

            # Enable sandbox
            agents = config.setdefault("agents", {})
            defaults = agents.setdefault("defaults", {})
            sandbox = defaults.setdefault("sandbox", {})
            if sandbox.get("mode", "off") == "off":
                sandbox["mode"] = "all"
                sandbox["scope"] = "session"
                modified = True
                actions.append('Enabled sandbox: agents.defaults.sandbox.mode = "all"')

            # Set Docker network to none
            docker = sandbox.setdefault("docker", {})
            if docker.get("network") != "none":
                docker["network"] = "none"
                modified = True
                actions.append('Set sandbox.docker.network = "none"')

            # Ensure exec host is sandbox
            tools = config.setdefault("tools", {})
            exec_config = tools.setdefault("exec", {})
            if exec_config.get("host") == "gateway":
                exec_config["host"] = "sandbox"
                modified = True
                actions.append('Set tools.exec.host = "sandbox"')

            # Enable logging redaction
            logging_config = config.setdefault("logging", {})
            if logging_config.get("redactSensitive") in (None, "off"):
                logging_config["redactSensitive"] = "tools"
                modified = True
                actions.append('Enabled logging.redactSensitive = "tools"')

            # Generate strong gateway token if missing/weak
            gateway = config.setdefault("gateway", {})
            auth = gateway.setdefault("auth", {})
            token = auth.get("token", "")
            if not token or len(str(token)) < 32:
                new_token = secrets.token_hex(32)
                auth["token"] = new_token
                modified = True
                actions.append(f"Generated strong gateway token ({len(new_token)} chars)")

            if modified:
                config_file.write_text(json.dumps(config, indent=2))

        except Exception as e:
            actions.append(f"Could not modify config: {e}")

    # Fix 3: Delete .bak files
    bak_files = list(openclaw_path.rglob("*.bak"))
    for bak in bak_files:
        bak.unlink()
        actions.append(f"Deleted backup file: {bak.name}")

    return actions
