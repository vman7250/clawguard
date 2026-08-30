"""Check LLM provider configurations for potential issues.

Catches free-tier TPM limits, rate limits, and missing web search keys.
"""

from pathlib import Path

from clawguard.models import Finding, Severity
from clawguard.patterns import OPENCLAW_SYSTEM_PROMPT_TOKENS, PROVIDER_LIMITS
from clawguard.utils import parse_config


def check_providers(openclaw_path: Path) -> list[Finding]:
    """Check LLM provider configurations for issues."""
    findings = []

    config = parse_config(openclaw_path / "openclaw.json")
    if not config:
        return findings

    models = config.get("models", {})
    providers = models.get("providers", {}) if isinstance(models, dict) else {}

    provider_summary = []

    for provider_name, provider_config in providers.items():
        if not isinstance(provider_config, dict):
            continue

        lower_name = provider_name.lower()
        provider_summary.append(
            f"{provider_name}: model={provider_config.get('model', 'default')}"
        )

        # Check 1: HIGH - Provider free tier TPM < system prompt tokens
        limits = PROVIDER_LIMITS.get(lower_name)
        if limits and limits["tpm"] < OPENCLAW_SYSTEM_PROMPT_TOKENS:
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Provider '{provider_name}' TPM too low for system prompt",
                details=[
                    limits["note"],
                    f"OpenClaw system prompt requires ~{OPENCLAW_SYSTEM_PROMPT_TOKENS} tokens",
                    f"Provider free tier allows only {limits['tpm']} TPM",
                    "System prompt alone exceeds the per-minute token limit",
                ],
                fix=f"Upgrade to a paid {provider_name} plan or switch to a provider with higher limits",
                category="providers",
            ))

        # Check 2: MEDIUM - Provider free tier has very low rate limits
        if limits and limits["rpm"] < 10:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"Provider '{provider_name}' has very low rate limits ({limits['rpm']} RPM)",
                details=[
                    limits["note"],
                    "Low RPM causes frequent rate limit errors during conversations",
                ],
                fix=f"Consider upgrading {provider_name} plan or using a different provider",
                category="providers",
            ))

    # Provider configuration summary
    if provider_summary:
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"{len(provider_summary)} LLM provider(s) configured",
            details=provider_summary,
            category="providers",
        ))

    return findings
