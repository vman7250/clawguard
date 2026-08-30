"""Current OpenClaw 2026.8 configuration hardening checks."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from clawguard.models import Finding, Severity
from clawguard.utils import parse_config


def _finding(check_id: str, severity: Severity, title: str, key_path: str, fix: str = "", details: list[str] | None = None) -> Finding:
    return Finding(id=check_id, severity=severity, title=title, details=details or [], fix=fix, category="hardening", key_path=key_path)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sandboxes(config: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    agents = _dict(config.get("agents"))
    result = [("agents.defaults.sandbox", _dict(_dict(agents.get("defaults")).get("sandbox")))]
    entries = agents.get("entries")
    if isinstance(entries, list):
        for index, entry in enumerate(entries):
            entry = _dict(entry)
            name = str(entry.get("id") or index)
            if "sandbox" in entry:
                result.append((f"agents.entries.{name}.sandbox", _dict(entry.get("sandbox"))))
    elif isinstance(entries, dict):
        for name, entry in entries.items():
            if isinstance(entry, dict) and "sandbox" in entry:
                result.append((f"agents.entries.{name}.sandbox", _dict(entry.get("sandbox"))))
    return result


def check_hardening(openclaw_path: Path) -> list[Finding]:
    config = parse_config(openclaw_path / "openclaw.json")
    if not isinstance(config, dict):
        return []
    findings: list[Finding] = []
    gateway = _dict(config.get("gateway")); auth = _dict(gateway.get("auth")); bind = gateway.get("bind", "loopback")
    if bind != "loopback" and not auth.get("mode"):
        findings.append(_finding("gateway.bind_auth", Severity.CRITICAL, "Non-loopback gateway has no authentication mode", "gateway.auth.mode"))
    if auth.get("mode") == "token" and len(str(auth.get("token") or "")) < 32:
        findings.append(_finding("gateway.auth.token", Severity.HIGH, "Gateway token authentication is missing a strong token", "gateway.auth.token", "Generate a random token of at least 32 characters"))
    control = _dict(gateway.get("controlUi"))
    if "*" in (control.get("allowedOrigins") or []):
        findings.append(_finding("gateway.control_ui.wildcard_origin", Severity.HIGH, "Control UI allows every origin", "gateway.controlUi.allowedOrigins"))
    if control.get("dangerouslyAllowHostHeaderOriginFallback") is True:
        findings.append(_finding("gateway.control_ui.host_fallback", Severity.HIGH, "Control UI trusts the Host header as an origin", "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback", "Set to false"))
    if bind == "loopback" and gateway.get("trustedProxies"):
        findings.append(_finding("gateway.trusted_proxies.loopback", Severity.LOW, "Trusted proxies are configured for a loopback-only gateway", "gateway.trustedProxies"))
    nodes = _dict(gateway.get("nodes")); pairing = _dict(nodes.get("pairing")); browser_node = _dict(nodes.get("browser"))
    if pairing.get("autoApproveCidrs"):
        findings.append(_finding("gateway.nodes.auto_approve_cidrs", Severity.MEDIUM, "Node pairing auto-approves network ranges", "gateway.nodes.pairing.autoApproveCidrs"))
    if pairing.get("sshVerify") is False:
        findings.append(_finding("gateway.nodes.ssh_verify", Severity.HIGH, "SSH verification is disabled for node pairing", "gateway.nodes.pairing.sshVerify", "Set to true"))
    if browser_node.get("mode") == "relay" and bind != "loopback":
        findings.append(_finding("gateway.nodes.browser_relay", Severity.HIGH, "Browser relay is exposed by a non-loopback gateway", "gateway.nodes.browser.mode"))
    ssrf = _dict(_dict(config.get("browser")).get("ssrfPolicy"))
    if ssrf.get("dangerouslyAllowPrivateNetwork") is True:
        findings.append(_finding("browser.ssrf.private_network", Severity.HIGH, "Browser SSRF policy allows private-network access", "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork", "Set to false"))

    tools = _dict(config.get("tools")); execute = _dict(tools.get("exec"))
    simple = [
        (execute.get("security") == "full", "tools.exec.security_full", Severity.HIGH, "Exec tool security is full", "tools.exec.security"),
        (execute.get("ask") == "off", "tools.exec.ask_off", Severity.MEDIUM, "Exec tool approval prompts are off", "tools.exec.ask"),
        (execute.get("host") == "gateway", "tools.exec.host_gateway", Severity.HIGH, "Exec tool runs on the gateway host", "tools.exec.host"),
        (execute.get("strictInlineEval") is not True, "tools.exec.strict_inline_eval", Severity.MEDIUM, "Strict inline evaluation is not enabled", "tools.exec.strictInlineEval"),
        (_dict(execute.get("applyPatch")).get("workspaceOnly") is False, "tools.exec.patch_workspace_only", Severity.MEDIUM, "Apply-patch can write outside the workspace", "tools.exec.applyPatch.workspaceOnly"),
        (_dict(tools.get("elevated")).get("enabled") is True, "tools.elevated.enabled", Severity.HIGH, "Elevated tools are enabled", "tools.elevated.enabled"),
        (_dict(tools.get("fs")).get("workspaceOnly") is not True, "tools.fs.workspace_only", Severity.MEDIUM, "Filesystem tools are not limited to the workspace", "tools.fs.workspaceOnly"),
        (_dict(tools.get("sessions")).get("visibility") == "all", "tools.sessions.visibility_all", Severity.LOW, "All sessions are visible to tools", "tools.sessions.visibility"),
    ]
    for condition, check_id, severity, title, key in simple:
        if condition:
            fix = "Set to true" if key in {"tools.exec.strictInlineEval", "tools.exec.applyPatch.workspaceOnly"} else ""
            findings.append(_finding(check_id, severity, title, key, fix))
    deny = tools.get("deny") if isinstance(tools.get("deny"), list) else []
    missing = [group for group in ["group:automation", "group:runtime", "group:fs"] if group not in deny]
    if missing:
        findings.append(_finding("tools.deny.recommended_groups", Severity.INFO, "Recommended tool deny groups are missing", "tools.deny", details=missing))

    for prefix, sandbox in _sandboxes(config):
        suffix = prefix.removeprefix("agents.").replace(".sandbox", "").replace(".", "_")
        if sandbox.get("mode", "off") == "off":
            findings.append(_finding(f"sandbox.{suffix}.mode_off", Severity.CRITICAL, f"Sandbox mode is off at {prefix}", f"{prefix}.mode"))
        if sandbox.get("scope") == "shared":
            findings.append(_finding(f"sandbox.{suffix}.scope_shared", Severity.MEDIUM, f"Sandbox scope is shared at {prefix}", f"{prefix}.scope"))
        if sandbox.get("workspaceAccess") == "rw":
            findings.append(_finding(f"sandbox.{suffix}.workspace_rw", Severity.MEDIUM, f"Sandbox has read-write workspace access at {prefix}", f"{prefix}.workspaceAccess"))
        docker = _dict(sandbox.get("docker"))
        if sandbox.get("mode", "off") != "off" and docker.get("network") != "none":
            findings.append(_finding(f"sandbox.{suffix}.docker_network", Severity.HIGH, f"Sandbox Docker network is enabled at {prefix}", f"{prefix}.docker.network"))
        if docker.get("readOnlyRoot") is False:
            findings.append(_finding(f"sandbox.{suffix}.readonly_root", Severity.MEDIUM, f"Sandbox root filesystem is writable at {prefix}", f"{prefix}.docker.readOnlyRoot", "Set to true"))
        if docker and "ALL" not in (docker.get("capDrop") or []):
            findings.append(_finding(f"sandbox.{suffix}.cap_drop", Severity.MEDIUM, f"Sandbox does not drop all Linux capabilities at {prefix}", f"{prefix}.docker.capDrop"))
        for key, slug in [
            ("dangerouslyAllowExternalBindSources", "external_binds"),
            ("dangerouslyAllowReservedContainerTargets", "reserved_targets"),
            ("dangerouslyAllowContainerNamespaceJoin", "namespace_join"),
        ]:
            if docker.get(key) is True:
                findings.append(_finding(f"sandbox.{suffix}.{slug}", Severity.HIGH, f"Dangerous Docker override {key} is enabled at {prefix}", f"{prefix}.docker.{key}", "Set to false"))
        risky = [str(value) for value in (docker.get("binds") or []) if any(mark in str(value) for mark in ["/var/run/docker.sock", "/.ssh", "~/.ssh", "/.openclaw", "~/.openclaw", "/etc"])]
        if risky:
            findings.append(_finding(f"sandbox.{suffix}.sensitive_binds", Severity.CRITICAL, f"Sandbox mounts sensitive host paths at {prefix}", f"{prefix}.docker.binds", details=risky))

    sender_ids: set[str] = set()
    channels = _dict(config.get("channels"))
    for name, channel_value in channels.items():
        channel = _dict(channel_value)
        if channel.get("dmPolicy") == "open":
            findings.append(_finding(f"channels.{name}.dm_policy_open", Severity.HIGH, f"Channel {name} accepts open direct messages", f"channels.{name}.dmPolicy"))
        allow = channel.get("allowFrom") if isinstance(channel.get("allowFrom"), list) else []
        sender_ids.update(str(value) for value in allow)
        if "*" in allow:
            findings.append(_finding(f"channels.{name}.allow_from_wildcard", Severity.HIGH, f"Channel {name} allows every sender", f"channels.{name}.allowFrom"))
    if _dict(config.get("session")).get("dmScope") == "main" and len(sender_ids) > 1:
        findings.append(_finding("session.dm_scope_shared", Severity.MEDIUM, "Multiple DM senders share the main session context", "session.dmScope"))

    plugins = _dict(config.get("plugins"))
    if "allow" not in plugins:
        findings.append(_finding("plugins.allow_missing", Severity.MEDIUM, "Plugin allowlist is not configured", "plugins.allow"))
    if "installPolicy" not in _dict(config.get("security")):
        findings.append(_finding("security.install_policy_missing", Severity.LOW, "Extension install policy is not configured", "security.installPolicy"))
    acpx = _dict(_dict(_dict(plugins.get("entries")).get("acpx")).get("config"))
    if acpx.get("permissionMode") == "approve-all":
        findings.append(_finding("plugins.acpx.approve_all", Severity.HIGH, "ACP-X approves every permission request", "plugins.entries.acpx.config.permissionMode", 'Set to "ask"'))

    env_hits: list[str] = []
    workspace = openclaw_path / "workspace"
    if workspace.exists():
        for env_file in workspace.rglob(".env"):
            try:
                for number, line in enumerate(env_file.read_text(errors="ignore").splitlines(), 1):
                    if re.match(r"\s*(?:OPENCLAW_[A-Z0-9_]+|[A-Z0-9_]+_API_KEY)\s*=", line):
                        env_hits.append(f"{env_file.relative_to(openclaw_path)}:{number}")
            except OSError:
                continue
    if env_hits:
        findings.append(_finding("files.workspace_env_overrides", Severity.MEDIUM, "Workspace .env files define blocked OpenClaw or provider overrides", "workspace/**/.env", details=env_hits))
    return findings
