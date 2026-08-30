"""Terminal and JSON output for ClawGuard."""

import json

from clawguard.models import Finding, ScanResult, Severity


def print_banner() -> None:
    print("ClawGuard v0.3.0 - OpenClaw Security Scanner")


def print_finding(finding: Finding, verbose: bool = False) -> None:
    print(f"\n  {finding.severity.value:<8} {finding.title}")
    for detail in finding.details + (finding.verbose_details if verbose else []):
        print(f"           {detail}")
    if finding.fix:
        print(f"           Fix: {finding.fix}")


def print_report(result: ScanResult, verbose: bool = False) -> None:
    print_banner()
    print(f"\nScanning {result.openclaw_path} ...")
    print(f"Advisory snapshot: {result.advisory_snapshot} ({result.tracked_cve_count} tracked CVEs)")
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    for finding in sorted(result.findings, key=lambda item: order[item.severity]):
        print_finding(finding, verbose)
    if result.openclaw_audit_findings:
        print("\nOpenClaw vendor audit (deduplicated)")
        for finding in result.openclaw_audit_findings:
            print(f"  {json.dumps(finding, sort_keys=True)}")
    print(f"\nScore: {result.score}/100")
    print(f"Found: {result.critical_count} critical, {result.high_count} high, {result.medium_count} medium, {result.low_count} low, {result.info_count} info")


def print_json(result: ScanResult) -> None:
    output = {
        "score": result.score, "openclaw_path": result.openclaw_path,
        "openclaw_version": result.openclaw_version, "node_version": result.node_version,
        "advisory_snapshot": result.advisory_snapshot,
        "tracked_cve_count": result.tracked_cve_count,
        "summary": {"critical": result.critical_count, "high": result.high_count, "medium": result.medium_count, "info": result.info_count, "low": result.low_count},
        "findings": [
            {"id": f.id, "severity": f.severity.value, "title": f.title, "details": f.details,
             "fix": f.fix, "category": f.category, "key_path": f.key_path, "verbose_details": f.verbose_details}
            for f in result.findings
        ],
        "openclaw_audit": result.openclaw_audit_findings,
    }
    print(json.dumps(output, indent=2))
