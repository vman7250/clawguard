"""Check for memory poisoning and sensitive data in workspace files."""

from pathlib import Path

from clawguard.models import Finding, Severity
from clawguard.patterns import API_KEY_PATTERNS, MEMORY_POISONING_PATTERNS


def check_memory(openclaw_path: Path) -> list[Finding]:
    """Check SOUL.md and MEMORY.md for poisoning and sensitive data."""
    findings = []

    workspace = openclaw_path / "workspace"
    if not workspace.exists():
        return findings

    # Files to check for memory poisoning
    identity_files = [
        workspace / "SOUL.md",
        workspace / "IDENTITY.md",
    ]

    for filepath in identity_files:
        if not filepath.exists():
            continue

        content = filepath.read_text(errors="ignore")
        detected = []

        for pattern_name, pattern in MEMORY_POISONING_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                detected.append(f"{pattern_name}: {matches[0][:80]}...")

        if detected:
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Potential memory poisoning in {filepath.name}",
                details=detected,
                fix=f"Review {filepath} for injected instructions and restore from backup",
                category="memory",
            ))

    # Check MEMORY.md and daily logs for leaked credentials
    memory_files = [workspace / "MEMORY.md"]

    memory_dir = workspace / "memory"
    if memory_dir.exists():
        memory_files.extend(memory_dir.glob("*.md"))

    leaked_in = []
    for filepath in memory_files:
        if not filepath.exists():
            continue

        content = filepath.read_text(errors="ignore")
        for key_name, pattern in API_KEY_PATTERNS:
            if pattern.search(content):
                leaked_in.append(f"{filepath.name} contains {key_name}")
                break

    if leaked_in:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"Sensitive data found in {len(leaked_in)} memory file(s)",
            details=leaked_in[:5],
            fix="Remove credentials from memory files and rotate exposed keys",
            category="memory",
        ))

    return findings
