"""Audit installed OpenClaw skills for malicious patterns and excessive permissions."""

import re
from pathlib import Path

import yaml

from clawguard.models import Finding, Severity
from clawguard.patterns import (
    C2_IP_PATTERN,
    MALICIOUS_PATTERNS,
    SUSPICIOUS_BINS,
    TYPOSQUAT_PUBLISHERS,
)


def _parse_skill_md(skill_path: Path) -> tuple[dict, str]:
    """Parse SKILL.md frontmatter and body. Returns (frontmatter_dict, body_text)."""
    content = skill_path.read_text(errors="ignore")

    # Extract YAML frontmatter between --- markers
    frontmatter = {}
    body = content
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            try:
                frontmatter = yaml.safe_load(parts[1]) or {}
            except yaml.YAMLError:
                pass
            body = parts[2]

    return frontmatter, body


def _check_skill_permissions(name: str, frontmatter: dict) -> list[Finding]:
    """Check if a skill requests excessive permissions."""
    findings = []
    dangerous_perms = []

    permissions = frontmatter.get("permissions", {})
    requires = frontmatter.get("requires", {})

    # Check for exec permission
    if permissions.get("exec"):
        dangerous_perms.append(f"exec: {permissions['exec']}")

    # Check for sensitive_data access
    if permissions.get("sensitive_data"):
        dangerous_perms.append(f"sensitive_data: {permissions['sensitive_data']}")

    # Check for broad filesystem write access
    fs_perms = permissions.get("filesystem", [])
    for perm in fs_perms:
        if isinstance(perm, str) and "write:" in perm:
            if "write:~/" in perm or "write:/" in perm or "write:.." in perm:
                dangerous_perms.append(f"filesystem: {perm}")

    # Check for suspicious required binaries
    required_bins = requires.get("bins", [])
    for bin_name in required_bins:
        if bin_name in SUSPICIOUS_BINS:
            dangerous_perms.append(f"requires binary: {bin_name}")

    # Check for requests to access sensitive env vars
    required_env = requires.get("env", [])
    sensitive_env_patterns = ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"]
    for env_var in required_env:
        if any(p in env_var.upper() for p in sensitive_env_patterns):
            dangerous_perms.append(f"requires env: {env_var}")

    if dangerous_perms:
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"Skill '{name}' requests excessive permissions",
            details=dangerous_perms,
            fix=f"Review or remove this skill: rm -rf ~/.openclaw/workspace/skills/{name}",
            category="skills",
        ))

    return findings


def _check_skill_malicious(name: str, body: str) -> list[Finding]:
    """Check skill body content for malicious patterns."""
    findings = []
    detected = []

    for pattern_name, pattern in MALICIOUS_PATTERNS:
        if pattern.search(body):
            detected.append(pattern_name)

    # Check for C2 IPs
    if C2_IP_PATTERN.search(body):
        detected.append("Known C2 IP address (ClawHavoc campaign)")

    if detected:
        severity = Severity.CRITICAL if any("C2" in d or "reverse shell" in d for d in detected) else Severity.HIGH
        findings.append(Finding(
            severity=severity,
            title=f"Skill '{name}' contains malicious patterns",
            details=detected,
            fix=f"REMOVE THIS SKILL IMMEDIATELY: rm -rf ~/.openclaw/workspace/skills/{name}",
            category="skills",
        ))

    return findings


def check_skills(openclaw_path: Path) -> list[Finding]:
    """Audit all installed skills for security issues."""
    findings = []

    # Skill directories to scan
    skill_dirs = [
        openclaw_path / "workspace" / "skills",
        openclaw_path / "skills",
    ]

    total_skills = 0
    flagged_skills = 0

    for skills_root in skill_dirs:
        if not skills_root.exists():
            continue

        for skill_dir in skills_root.iterdir():
            if not skill_dir.is_dir():
                continue

            skill_md = skill_dir / "SKILL.md"
            if not skill_md.exists():
                continue

            total_skills += 1
            name = skill_dir.name

            # Check for typosquatting publisher names
            frontmatter, body = _parse_skill_md(skill_md)
            publisher = frontmatter.get("publisher", "").lower()
            if publisher in TYPOSQUAT_PUBLISHERS:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title=f"Skill '{name}' has typosquatted publisher: {publisher}",
                    details=["This publisher name is known to be associated with malicious skills"],
                    fix=f"REMOVE IMMEDIATELY: rm -rf {skill_dir}",
                    category="skills",
                ))
                flagged_skills += 1
                continue

            # Check permissions
            perm_findings = _check_skill_permissions(name, frontmatter)
            if perm_findings:
                flagged_skills += 1
            findings.extend(perm_findings)

            # Check for malicious content
            malicious_findings = _check_skill_malicious(name, body)
            if malicious_findings:
                flagged_skills += 1
            findings.extend(malicious_findings)

    if total_skills > 0 and flagged_skills == 0:
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"{total_skills} skill(s) scanned - no issues found",
            category="skills",
        ))
    elif total_skills == 0:
        findings.append(Finding(
            severity=Severity.INFO,
            title="No skills installed",
            category="skills",
        ))

    return findings
