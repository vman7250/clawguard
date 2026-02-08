# ClawGuard

**Security scanner for OpenClaw AI agent installations.**

OpenClaw ships with insecure defaults - sandbox off, plaintext API keys, exposed gateway ports, and a skills marketplace with [341 known malicious packages](https://clawhub.dev/security). ClawGuard scans your installation, flags vulnerabilities, and auto-fixes the most common issues.

[![PyPI version](https://img.shields.io/pypi/v/clawguard.svg)](https://pypi.org/project/clawguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## Install

```bash
pip install clawguard
```

Or with pipx for isolated install:

```bash
pipx install clawguard
```

## Quick Start

```bash
# Scan your OpenClaw installation (auto-detects ~/.openclaw/)
clawguard scan

# Auto-fix common security issues
clawguard fix

# Scan a specific directory
clawguard scan --path /custom/openclaw/dir

# JSON output for CI/CD pipelines
clawguard scan --format json

# Run specific checks only
clawguard scan --check credentials --check gateway
```

## What It Checks

ClawGuard runs **25+ security checks** across 7 categories:

| Category | What it checks | Severity |
|---|---|---|
| **Credentials** | Plaintext API keys in config, `.env`, `.bak` files, session transcripts | CRITICAL |
| **Gateway** | Bind address, auth token strength, port exposure | CRITICAL |
| **Sandbox** | Sandbox mode, Docker network isolation, exec host, allowlists | CRITICAL |
| **Version** | OpenClaw version against known CVEs (CVE-2026-25253, CVE-2026-21636) | CRITICAL |
| **Skills** | Malicious patterns, C2 IPs, typosquatted publishers, excessive permissions | CRITICAL |
| **Permissions** | File/directory permission checks on sensitive configs | HIGH |
| **Memory** | SOUL.md/MEMORY.md poisoning, credential leaks in daily logs | HIGH |

### Credential Patterns Detected

Supports 17+ API key formats: Anthropic (`sk-ant-`), OpenAI (`sk-proj-`), Groq (`gsk_`), xAI (`xai-`), AWS (`AKIA`), GitHub (`ghp_`, `gho_`), GitLab (`glpat-`), Slack (`xoxb-`, `xoxp-`), Telegram bot tokens, Discord tokens, Stripe (`sk_live_`), and more.

### Malicious Skill Detection

- Base64-encoded payloads
- Remote code execution (`curl | sh`, `wget | bash`)
- Known C2 IP addresses (ClawHavoc campaign)
- Paste service references (glot.io, pastebin)
- Typosquatted publisher names
- Suspicious binary requirements (`nc`, `ncat`, `socat`)
- Excessive permission requests

## Auto-Fix

`clawguard fix` automatically remediates common issues:

- Sets correct file permissions (700 for dirs, 600 for configs)
- Enables sandbox mode
- Configures Docker network isolation
- Moves exec host to sandbox
- Enables log redaction
- Generates strong gateway auth tokens
- Removes `.bak` files containing old credentials

## CI/CD Integration

ClawGuard exits with code `2` when critical issues are found, making it easy to use in pipelines:

```yaml
# GitHub Actions example
- name: Security scan
  run: |
    pip install clawguard
    clawguard scan --format json > security-report.json
    clawguard scan  # exits 2 if critical issues found
```

## Scoring

Security score out of 100, deducted per finding:

| Severity | Deduction |
|---|---|
| CRITICAL | -20 |
| HIGH | -10 |
| MEDIUM | -5 |
| INFO | 0 |

Score ranges: **0-30** Critical Risk | **31-60** Poor | **61-80** Fair | **81-100** Good

## Development

```bash
git clone https://github.com/vishalmani/clawguard.git
cd clawguard
pip install -e .
clawguard scan --path tests/fixtures/
```

## License

MIT
