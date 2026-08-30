"""Shared utilities used by multiple ClawGuard modules."""

import os
import shutil
from pathlib import Path

from clawguard.patterns import API_KEY_PATTERNS, ENV_VAR_PATTERN


def scan_file_for_keys(filepath: Path) -> list[tuple[str, str, int]]:
    """Scan a file for API key patterns. Returns list of (key_name, masked_value, line_num)."""
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
                    masked = matched[:8] + "..." + matched[-4:] if len(matched) > 16 else matched[:4] + "..."
                    hits.append((key_name, masked, line_num))
    except (PermissionError, FileNotFoundError):
        pass
    return hits


def parse_config(config_path: Path) -> dict | None:
    """Parse openclaw.json (with JSON5 support). Returns None on failure."""
    try:
        content = config_path.read_text(errors="ignore")
        try:
            import json5
            return json5.loads(content)
        except ImportError:
            import json
            return json.loads(content)
    except Exception:
        return None


def is_docker_available() -> bool:
    """Check if Docker is installed and available."""
    return shutil.which("docker") is not None


def get_total_memory_gb() -> float:
    """Get total system memory in GB."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    # MemTotal is in kB
                    kb = int(line.split()[1])
                    return kb / (1024 * 1024)
    except (FileNotFoundError, ValueError, IndexError):
        pass
    # Fallback using os
    try:
        import resource
        # Not reliable on all systems, use sysconf
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return (pages * page_size) / (1024 * 1024 * 1024)
    except (ValueError, OSError):
        return 0.0
