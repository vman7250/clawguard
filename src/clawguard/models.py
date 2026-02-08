"""Data models for ClawGuard scan results."""

from enum import Enum
from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.INFO: 0,
}


class Finding(BaseModel):
    severity: Severity
    title: str
    details: list[str] = []
    fix: str = ""
    category: str = ""


class ScanResult(BaseModel):
    findings: list[Finding] = []
    openclaw_path: str = ""
    openclaw_version: str | None = None
    node_version: str | None = None

    @property
    def score(self) -> int:
        total = 100
        for f in self.findings:
            total -= SEVERITY_DEDUCTIONS[f.severity]
        return max(0, total)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)
