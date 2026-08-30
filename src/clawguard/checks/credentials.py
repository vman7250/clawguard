"""Scan for plaintext credentials in OpenClaw configuration files."""

import os
from pathlib import Path

from clawguard.models import Finding, Severity
from clawguard.patterns import API_KEY_PATTERNS, ENV_VAR_PATTERN
from clawguard.utils import scan_file_for_keys


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

    # NOTE: .env files are NOT scanned — they are the EXPECTED secure storage
    # location for API keys. Only flag keys in JSON config files.

    # Scan config files (JSON configs only, not .env)
    all_hits = []
    for filepath in config_files:
        if filepath.exists():
            hits = scan_file_for_keys(filepath)
            for key_name, masked, line_num in hits:
                all_hits.append(f"{filepath.relative_to(openclaw_path.parent)}:{line_num} - {key_name} ({masked})")

    if all_hits:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"{len(all_hits)} API key(s) stored in plaintext config files",
            details=all_hits[:10],  # Show max 10
            fix='Move keys to .env and use env var refs: "apiKey": "${ANTHROPIC_API_KEY}"',
            category="credentials",
        ))

    # Check for .bak files with credentials
    bak_files = list(openclaw_path.rglob("*.bak"))
    bak_with_keys = []
    for bak_file in bak_files:
        hits = scan_file_for_keys(bak_file)
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
            fix="Delete old transcripts and rotate the exposed credentials",
            category="credentials",
        ))

    return findings
