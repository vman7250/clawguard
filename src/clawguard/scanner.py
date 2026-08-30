"""Main scanner orchestrator - runs all security checks."""

import json
import os
import secrets
import re
import subprocess
import sys
from pathlib import Path

from clawguard.checks.agents import check_agents
from clawguard.checks.credentials import check_credentials
from clawguard.checks.hardening import check_hardening
from clawguard.checks.memory import check_memory
from clawguard.checks.permissions import check_permissions
from clawguard.checks.providers import check_providers
from clawguard.checks.skills import check_skills
from clawguard.checks.version import check_version
from clawguard.advisories import TRACKED_CVE_COUNT
from clawguard.models import ScanResult
from clawguard.patterns import API_KEY_PATTERNS, PROVIDER_ENV_MAP
from clawguard.utils import get_total_memory_gb, is_docker_available, parse_config, scan_file_for_keys

# Map of check names to their functions
CHECK_REGISTRY = {
    "credentials": check_credentials,
    "permissions": check_permissions,
    "skills": check_skills,
    "memory": check_memory,
    "agents": check_agents,
    "providers": check_providers,
    "hardening": check_hardening,
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


def _ensure_finding_ids(result: ScanResult) -> None:
    """Give legacy checks deterministic IDs while they are migrated individually."""
    seen: dict[str, int] = {}
    for finding in result.findings:
        if finding.id:
            continue
        slug = re.sub(r"[^a-z0-9]+", ".", finding.title.lower()).strip(".")
        base = f"{finding.category or 'general'}.{slug}"
        seen[base] = seen.get(base, 0) + 1
        finding.id = base if seen[base] == 1 else f"{base}.{seen[base]}"


def _run_openclaw_audit(result: ScanResult) -> None:
    try:
        completed = subprocess.run(
            ["openclaw", "security", "audit", "--json"], capture_output=True,
            text=True, timeout=30,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or f"exit {completed.returncode}")
        payload = json.loads(completed.stdout)
        if isinstance(payload, list):
            items = payload
        else:
            items = next((payload.get(key) for key in ("findings", "issues", "results") if isinstance(payload.get(key), list)), [])
        ours = {finding.key_path for finding in result.findings if finding.key_path}
        for item in items:
            if not isinstance(item, dict):
                continue
            key_path = str(item.get("key_path") or item.get("path") or item.get("check") or "")
            if key_path and key_path in ours:
                continue
            result.openclaw_audit_findings.append(item)
    except Exception as exc:
        result.openclaw_audit_findings.append({"status": "unavailable", "message": str(exc)})


def run_scan(
    openclaw_path: Path, checks: list[str] | None = None,
    refresh_advisories: bool = False, with_openclaw_audit: bool = False,
) -> ScanResult:
    """Run all security checks and return aggregated results."""
    result = ScanResult(openclaw_path=str(openclaw_path))
    result.tracked_cve_count = TRACKED_CVE_COUNT

    # Version check (always runs, returns version info)
    version_findings, oc_version, node_version, snapshot = check_version(openclaw_path, refresh_advisories)
    result.findings.extend(version_findings)
    result.openclaw_version = oc_version
    result.node_version = node_version
    result.advisory_snapshot = snapshot

    # Run selected or all checks
    active_checks = checks if checks else list(CHECK_REGISTRY.keys())

    for check_name in active_checks:
        if check_name not in CHECK_REGISTRY:
            continue

        check_fn = CHECK_REGISTRY[check_name]
        label = check_name.replace("_", " ").title()

        try:
            findings = check_fn(openclaw_path)
            result.findings.extend(findings)
        except Exception as e:
            print(f"Warning: {label} check failed: {e}", file=sys.stderr)

    _ensure_finding_ids(result)
    if with_openclaw_audit:
        _run_openclaw_audit(result)

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

    # Fix 2: Config changes (sandbox-aware)
    if config_file.exists():
        try:
            try:
                import json5
                config = json5.loads(config_file.read_text())
            except ImportError:
                config = json.loads(config_file.read_text())

            modified = False
            docker_installed = is_docker_available()

            # Sandbox changes: only apply if Docker is available
            if docker_installed:
                agents = config.setdefault("agents", {})
                defaults = agents.setdefault("defaults", {})
                sandbox = defaults.setdefault("sandbox", {})
                if sandbox.get("mode", "off") == "off":
                    sandbox["mode"] = "all"
                    sandbox["scope"] = "session"
                    modified = True
                    actions.append('Enabled sandbox: agents.defaults.sandbox.mode = "all"')

                docker = sandbox.setdefault("docker", {})
                if docker.get("network") != "none":
                    docker["network"] = "none"
                    modified = True
                    actions.append('Set sandbox.docker.network = "none"')

                tools = config.setdefault("tools", {})
                exec_config = tools.setdefault("exec", {})
                if exec_config.get("host") == "gateway":
                    exec_config["host"] = "sandbox"
                    modified = True
                    actions.append('Set tools.exec.host = "sandbox"')
            else:
                actions.append(
                    "[yellow]Sandbox changes skipped: Docker not installed. "
                    "Install Docker to enable sandbox isolation.[/yellow]"
                )

            # Always apply safe fixes regardless of Docker

            # Generate a strong token only when token auth is configured.
            gateway = config.setdefault("gateway", {})
            auth = gateway.setdefault("auth", {})
            token = auth.get("token", "")
            if auth.get("mode") == "token" and (not token or len(str(token)) < 32):
                new_token = secrets.token_hex(32)
                auth["token"] = new_token
                modified = True
                actions.append(f"Generated strong gateway token ({len(new_token)} chars)")

            control_ui = gateway.get("controlUi", {})
            if control_ui.get("dangerouslyAllowHostHeaderOriginFallback") is True:
                control_ui["dangerouslyAllowHostHeaderOriginFallback"] = False
                modified = True
                actions.append("Disabled Host-header origin fallback")

            browser = config.get("browser", {})
            ssrf = browser.get("ssrfPolicy", {})
            if ssrf.get("dangerouslyAllowPrivateNetwork") is True:
                ssrf["dangerouslyAllowPrivateNetwork"] = False
                modified = True
                actions.append("Disabled browser private-network SSRF access")

            tools = config.setdefault("tools", {})
            exec_config = tools.setdefault("exec", {})
            if exec_config.get("strictInlineEval") is not True:
                exec_config["strictInlineEval"] = True
                modified = True
                actions.append("Enabled strict inline evaluation")
            apply_patch = exec_config.get("applyPatch", {})
            if apply_patch.get("workspaceOnly") is False:
                apply_patch["workspaceOnly"] = True
                modified = True
                actions.append("Limited apply-patch to the workspace")

            pairing = gateway.get("nodes", {}).get("pairing", {})
            if pairing.get("sshVerify") is False:
                pairing["sshVerify"] = True
                modified = True
                actions.append("Enabled SSH verification for node pairing")

            sandbox_configs = [config.get("agents", {}).get("defaults", {}).get("sandbox", {})]
            entries = config.get("agents", {}).get("entries", {})
            entry_values = entries.values() if isinstance(entries, dict) else entries if isinstance(entries, list) else []
            sandbox_configs.extend(entry.get("sandbox", {}) for entry in entry_values if isinstance(entry, dict) and "sandbox" in entry)
            for sandbox_config in sandbox_configs:
                docker = sandbox_config.get("docker", {})
                if docker.get("readOnlyRoot") is False:
                    docker["readOnlyRoot"] = True
                    modified = True
                    actions.append("Made sandbox root filesystem read-only")
                for key in (
                    "dangerouslyAllowExternalBindSources",
                    "dangerouslyAllowReservedContainerTargets",
                    "dangerouslyAllowContainerNamespaceJoin",
                ):
                    if docker.get(key) is True:
                        docker[key] = False
                        modified = True
                        actions.append(f"Disabled sandbox Docker override {key}")

            acpx = config.get("plugins", {}).get("entries", {}).get("acpx", {}).get("config", {})
            if acpx.get("permissionMode") == "approve-all":
                acpx["permissionMode"] = "ask"
                modified = True
                actions.append("Set ACP-X permission mode to ask")

            if modified:
                config_file.write_text(json.dumps(config, indent=2))

            # Post-fix warnings
            ram_gb = get_total_memory_gb()
            if ram_gb > 0 and ram_gb < 2:
                actions.append(
                    f'[yellow]Warning: System has only {ram_gb:.1f}GB RAM. '
                    f'Set NODE_OPTIONS="--max-old-space-size=512" to prevent OOM kills.[/yellow]'
                )

            # Suggest migrate-env if plaintext keys found
            hits = scan_file_for_keys(config_file)
            if hits:
                actions.append(
                    f"Tip: Run [bold]clawguard migrate-env[/bold] to move {len(hits)} plaintext key(s) to .env"
                )

        except Exception as e:
            actions.append(f"Could not modify config: {e}")

    # Fix 3: Delete .bak files
    bak_files = list(openclaw_path.rglob("*.bak"))
    for bak in bak_files:
        bak.unlink()
        actions.append(f"Deleted backup file: {bak.name}")

    return actions


def run_migrate_env(
    openclaw_path: Path, dry_run: bool = False
) -> dict:
    """Migrate plaintext API keys to .env file with ${ENV_VAR} references."""
    import re

    result = {
        "migrations": [],
        "env_file_created": False,
        "configs_updated": [],
    }

    # Collect all config files to process
    config_files: list[Path] = []
    main_config = openclaw_path / "openclaw.json"
    if main_config.exists():
        config_files.append(main_config)

    # Find all agent models.json files
    agents_dir = openclaw_path / "agents"
    if agents_dir.exists():
        for models_json in agents_dir.rglob("models.json"):
            config_files.append(models_json)

    # Build a map of raw key values -> env var names
    key_to_env_var: dict[str, str] = {}

    for config_file in config_files:
        try:
            content = config_file.read_text(errors="ignore")
            for line in content.splitlines():
                # Skip lines already using env var references
                if re.search(r'\$\{[A-Z_][A-Z0-9_]*\}', line):
                    continue

                for key_name, pattern in API_KEY_PATTERNS:
                    for match in pattern.finditer(line):
                        raw_key = match.group()
                        if raw_key in key_to_env_var:
                            continue
                        env_var = _guess_env_var_name(key_name, line)
                        key_to_env_var[raw_key] = env_var
                        masked = raw_key[:8] + "..." + raw_key[-4:] if len(raw_key) > 16 else raw_key[:4] + "..."
                        result["migrations"].append({
                            "file": str(config_file.relative_to(openclaw_path)),
                            "key": masked,
                            "env_var": env_var,
                        })
        except (PermissionError, FileNotFoundError):
            pass

    if not result["migrations"]:
        return result

    if dry_run:
        return result

    # Create/append .env file
    env_file_path = openclaw_path / ".env"
    existing_env = env_file_path.read_text(errors="ignore") if env_file_path.exists() else ""
    existing_keys = set()
    for line in existing_env.splitlines():
        if "=" in line:
            existing_keys.add(line.split("=", 1)[0].strip())

    new_env_lines = []
    for raw_key, env_var in key_to_env_var.items():
        if env_var not in existing_keys:
            new_env_lines.append(f"{env_var}={raw_key}")

    if new_env_lines:
        separator = "" if existing_env.endswith("\n") or existing_env == "" else "\n"
        with open(env_file_path, "a") as f:
            f.write(separator + "\n".join(new_env_lines) + "\n")
        result["env_file_created"] = True

        try:
            os.chmod(env_file_path, 0o600)
        except OSError:
            pass

    # Replace plaintext keys in config files with ${ENV_VAR_NAME}
    for config_file in config_files:
        try:
            content = config_file.read_text(errors="ignore")
            modified = False

            for raw_key, env_var in key_to_env_var.items():
                if raw_key in content:
                    content = content.replace(raw_key, f"${{{env_var}}}")
                    modified = True

            if modified:
                config_file.write_text(content)
                result["configs_updated"].append(
                    str(config_file.relative_to(openclaw_path))
                )
        except (PermissionError, FileNotFoundError):
            pass

    return result


def _guess_env_var_name(key_name: str, context_line: str) -> str:
    """Guess the appropriate env var name for a detected key."""
    lower = key_name.lower()

    # Check PROVIDER_ENV_MAP first
    for provider, env_var in PROVIDER_ENV_MAP.items():
        if provider in lower:
            return env_var

    # Try to guess from JSON key context
    if "telegram" in context_line.lower():
        return "TELEGRAM_BOT_TOKEN"
    if "discord" in context_line.lower():
        return "DISCORD_BOT_TOKEN"
    if "slack" in context_line.lower():
        return "SLACK_BOT_TOKEN"
    if "brave" in context_line.lower() or "websearch" in context_line.lower():
        return "BRAVE_SEARCH_API_KEY"
    if "stripe" in context_line.lower():
        return "STRIPE_SECRET_KEY"

    # Fallback: generate from key name
    return re.sub(r'[^A-Z0-9_]', '', key_name.upper().replace(' ', '_').replace('/', '_'))
