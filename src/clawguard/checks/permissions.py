"""Check file permissions on sensitive OpenClaw files."""

import os
import stat
from pathlib import Path

from clawguard.models import Finding, Severity


def _get_permission_octal(filepath: Path) -> str:
    """Get file permissions as octal string."""
    return oct(os.stat(filepath).st_mode & 0o777)


def _is_world_readable(filepath: Path) -> bool:
    """Check if file is readable by others."""
    mode = os.stat(filepath).st_mode
    return bool(mode & stat.S_IROTH)


def _is_group_readable(filepath: Path) -> bool:
    """Check if file is readable by group."""
    mode = os.stat(filepath).st_mode
    return bool(mode & stat.S_IRGRP)


def check_permissions(openclaw_path: Path) -> list[Finding]:
    """Check file permissions on sensitive files and directories."""
    findings = []
    too_open = []

    # Check main directory
    if openclaw_path.exists():
        perms = _get_permission_octal(openclaw_path)
        if _is_world_readable(openclaw_path) or _is_group_readable(openclaw_path):
            too_open.append(f"{openclaw_path} is {perms} (should be 0o700)")

    # Sensitive files to check
    sensitive_files = [
        openclaw_path / "openclaw.json",
        openclaw_path / ".env",
        openclaw_path / "credentials" / "profiles.json",
    ]

    # Add auth-profiles.json files
    agents_dir = openclaw_path / "agents"
    if agents_dir.exists():
        for auth_file in agents_dir.rglob("auth-profiles.json"):
            sensitive_files.append(auth_file)

    for filepath in sensitive_files:
        if filepath.exists():
            perms = _get_permission_octal(filepath)
            if _is_world_readable(filepath) or _is_group_readable(filepath):
                rel_path = filepath.relative_to(openclaw_path.parent) if openclaw_path.parent in filepath.parents else filepath
                too_open.append(f"{rel_path} is {perms} (should be 0o600)")

    if too_open:
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"{len(too_open)} file(s) have overly permissive access",
            details=too_open[:10],
            fix="chmod 700 ~/.openclaw && chmod 600 ~/.openclaw/openclaw.json ~/.openclaw/credentials/*",
            category="permissions",
        ))

    return findings
