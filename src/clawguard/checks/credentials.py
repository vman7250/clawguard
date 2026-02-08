"""Scan for plaintext credentials in OpenClaw configuration files."""

import os
from pathlib import Path

from clawguard.models import Finding, Severity
from clawguard.patterns import API_KEY_PATTERNS, ENV_VAR_PATTERN


def _scan_file_for_keys(filepath: Path) -> list[tuple[str, str, int]]:
    """Scan a file for API key patterns. Returns list of (key_name, matched_value, line_num)."""
    hits = []
    try:
        content = filepath.read_text(errors="ignore")
        for line_num, line in enumerate(content.splitlines(), 1):
            # Skip lines that use env var references
            if ENV_VAR_PATTERN.search(line):
                continue
            for key_name, pattern in API_KEY_PATTERNS:
                for match in pattern.finditer(line):
                    matched = match.group()
                    # Mask the middle of the key for display
                    masked = matched[:8] + "..." + matched[-4:] if len(matched) > 16 else matched[:4] + "..."
                    hits.append((key_name, masked, line_num))
    except (PermissionError, FileNotFoundError):
        pass
    return hits


def check_credentials(openclaw_path: Path) -> list[Finding]:
    """Check for plaintext credentials across all OpenClaw config files."""
    findings = []

    # Files to scan for plaintext API keys
    config_files = [
        openclaw_path / "openclaw.json",
        openclaw_path / "credentials" / "profiles.json",
    ]

    # Add all auth-profiles.json files
    agents_dir = openclaw_path / "agents"
    if agents_dir.exists():
        for agent_dir in agents_dir.iterdir():
            auth_file = agent_dir / "agent" / "auth-profiles.json"
            if auth_file.exists():
                config_files.append(auth_file)

    # Add .env files
    for env_file in [openclaw_path / ".env", openclaw_path / "workspace" / ".env"]:
        if env_file.exists():
            config_files.append(env_file)

    # Scan config files
    all_hits = []
    for filepath in config_files:
        if filepath.exists():
            hits = _scan_file_for_keys(filepath)
            for key_name, masked, line_num in hits:
                all_hits.append(f"{filepath.relative_to(openclaw_path.parent)}:{line_num} - {key_name} ({masked})")

    if all_hits:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"{len(all_hits)} API key(s) stored in plaintext",
            details=all_hits[:10],  # Show max 10
            fix='Use environment variables: "apiKey": "${ANTHROPIC_API_KEY}" instead of raw strings',
            category="credentials",
        ))

    # Check for .bak files with credentials
    bak_files = list(openclaw_path.rglob("*.bak"))
    bak_with_keys = []
    for bak_file in bak_files:
        hits = _scan_file_for_keys(bak_file)
        if hits:
            bak_with_keys.append(str(bak_file.relative_to(openclaw_path.parent)))

    if bak_with_keys:
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"{len(bak_with_keys)} backup file(s) contain credentials",
            details=bak_with_keys,
            fix="Delete backup files: rm ~/.openclaw/*.bak",
            category="credentials",
        ))

    # Scan transcript files for leaked secrets
    transcript_hits = []
    if agents_dir.exists():
        for jsonl_file in agents_dir.rglob("*.jsonl"):
            # Only scan first 500 lines per file to keep it fast
            try:
                with open(jsonl_file, errors="ignore") as f:
                    for i, line in enumerate(f):
                        if i > 500:
                            break
                        for key_name, pattern in API_KEY_PATTERNS:
                            if pattern.search(line):
                                transcript_hits.append(
                                    f"{jsonl_file.relative_to(openclaw_path.parent)} - {key_name} found in transcript"
                                )
                                break
                    if transcript_hits:
                        break  # One finding per file is enough
            except (PermissionError, FileNotFoundError):
                pass

    if transcript_hits:
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"API keys leaked in {len(transcript_hits)} session transcript(s)",
            details=transcript_hits[:5],
            fix="Delete old transcripts and enable logging.redactSensitive in config",
            category="credentials",
        ))

    # Check logging redaction settings
    config_file = openclaw_path / "openclaw.json"
    if config_file.exists():
        try:
            import json5
            config = json5.loads(config_file.read_text(errors="ignore"))
            logging_config = config.get("logging", {})
            redact = logging_config.get("redactSensitive")
            if redact is None or redact == "off":
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Sensitive data redaction is disabled in logs",
                    details=['logging.redactSensitive is not set or set to "off"'],
                    fix='Set logging.redactSensitive to "tools" or "all" in openclaw.json',
                    category="credentials",
                ))
        except Exception:
            pass

    return findings
