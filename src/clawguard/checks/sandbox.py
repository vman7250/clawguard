"""Compatibility wrapper for current tool and sandbox hardening checks."""

from pathlib import Path

from clawguard.checks.hardening import check_hardening
from clawguard.models import Finding


def check_sandbox(openclaw_path: Path) -> list[Finding]:
    return [finding for finding in check_hardening(openclaw_path) if finding.id.startswith(("tools.", "sandbox."))]
