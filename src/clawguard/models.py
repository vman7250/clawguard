"""Dependency-free data models for ClawGuard scan results."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 20, Severity.HIGH: 10, Severity.MEDIUM: 5,
    Severity.LOW: 2, Severity.INFO: 0,
}


@dataclass
class Finding:
    severity: Severity
    title: str
    id: str = ""
    details: list[str] = field(default_factory=list)
    fix: str = ""
    category: str = ""
    key_path: str = ""
    verbose_details: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    openclaw_path: str = ""
    openclaw_version: str | None = None
    node_version: str | None = None
    advisory_snapshot: str = ""
    tracked_cve_count: int = 543
    openclaw_audit_findings: list[dict] = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, 100 - sum(SEVERITY_DEDUCTIONS[f.severity] for f in self.findings))

    def _count(self, severity: Severity) -> int:
        return sum(f.severity == severity for f in self.findings)

    critical_count = property(lambda self: self._count(Severity.CRITICAL))
    high_count = property(lambda self: self._count(Severity.HIGH))
    medium_count = property(lambda self: self._count(Severity.MEDIUM))
    low_count = property(lambda self: self._count(Severity.LOW))
    info_count = property(lambda self: self._count(Severity.INFO))
