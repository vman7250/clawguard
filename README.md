# ClawGuard

**Security scanner for OpenClaw AI agent installations.**

OpenClaw ships with dangerous defaults: sandbox disabled, plaintext API keys in config files, gateway exposed to LAN, and a skills marketplace with [341 known malicious packages](https://clawhub.dev/security). CVE-2026-25253 allows 1-click remote code execution on unpatched installations.

ClawGuard scans your local OpenClaw setup, flags every vulnerability with severity ratings, and auto-fixes the most common issues. Think `npm audit` for your AI agent.

[![PyPI version](https://img.shields.io/pypi/v/clawguard.svg)](https://pypi.org/project/clawguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## Why ClawGuard?

A default OpenClaw install scores **0/100** on our security checks:

- Sandbox mode is **OFF** - agents execute commands directly on your host
- API keys are stored in **plaintext** in `~/.openclaw/openclaw.json`
- Gateway binds to **LAN** instead of loopback
- No exec allowlisting - any tool call runs unrestricted
- Skills from ClawHub run with whatever permissions they request
- Session transcripts can leak credentials into `.jsonl` logs

Most users don't know this. ClawGuard tells them exactly what's wrong and how to fix it.

## Install

```bash
pip install clawguard
```

Or with pipx (recommended for CLI tools):

```bash
pipx install clawguard
```

## Quick Start

```bash
# Scan your OpenClaw installation (auto-detects ~/.openclaw/)
clawguard scan

# Auto-fix common security issues
clawguard fix

# Verify fixes
clawguard scan
```

## Example Output

```
 ClawGuard v0.1.0 - OpenClaw Security Scanner

 Scanning /home/user/.openclaw/ ...

 CRITICAL  Plaintext API keys found in configuration
           openclaw.json: Anthropic API key (sk-ant-...) on line 14
           openclaw.json: OpenAI API key (sk-proj-...) on line 18
           credentials/profiles.json: Telegram bot token on line 7
           Fix: Use environment variables: "apiKey": "${ANTHROPIC_API_KEY}"

 CRITICAL  Sandbox mode is disabled
           agents.defaults.sandbox.mode = "off"
           Fix: Set sandbox.mode to "all" in openclaw.json

 CRITICAL  Gateway bound to LAN
           gateway.bind = "lan" (should be "loopback")
           Fix: Set gateway.bind to "loopback" in openclaw.json

 HIGH      Weak gateway auth token
           Token length: 4 characters (minimum: 32)
           Fix: openssl rand -hex 32

 HIGH      Commands execute on host, not in sandbox
           tools.exec.host = "gateway"
           Fix: Set to "sandbox" in openclaw.json

 MEDIUM    Log redaction not enabled
           Fix: Set logging.redactSensitive to "tools" in openclaw.json

 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 Score: 0/100  CRITICAL RISK

 Found: 3 critical, 2 high, 1 medium, 0 info
 Run clawguard fix to auto-fix 6 issues
```

After running `clawguard fix`:

```
 Score: 85/100  GOOD

 Found: 0 critical, 0 high, 0 medium, 3 info
```

## CLI Reference

```bash
# Full scan (auto-detects ~/.openclaw/, ~/.clawdbot/, ~/.moltbot/)
clawguard scan

# Scan a specific directory
clawguard scan --path /path/to/openclaw

# JSON output for CI/CD pipelines
clawguard scan --format json

# Run only specific check categories
clawguard scan --check credentials --check gateway --check sandbox

# Auto-fix common issues
clawguard fix
clawguard fix --path /path/to/openclaw

# Show version
clawguard version
```

### Available Check Categories

`credentials` `gateway` `sandbox` `permissions` `version` `skills` `memory`

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Scan passed, no critical issues |
| 1 | Error (path not found, invalid args) |
| 2 | Critical issues found |

## Security Checks

### 25+ checks across 7 categories:

| Category | Checks | Severity |
|---|---|---|
| **Credentials** | Plaintext API keys in config, `.env`, `.bak` files, session transcripts, log redaction settings | CRITICAL |
| **Gateway** | Bind address (loopback vs LAN), auth token strength, port exposure on 0.0.0.0 | CRITICAL |
| **Sandbox** | Sandbox mode, Docker availability, network isolation, exec host, exec allowlisting | CRITICAL |
| **Version** | OpenClaw version against CVE-2026-25253 (RCE) and CVE-2026-21636, Node.js version | CRITICAL |
| **Skills** | Malicious patterns, C2 IPs, typosquatted publishers, permission analysis, suspicious binaries | CRITICAL |
| **Permissions** | Directory (700) and file (600) permissions on sensitive configs and credentials | HIGH |
| **Memory** | SOUL.md/MEMORY.md injection detection, credential leaks in daily logs | HIGH |

### Credential Patterns

Detects 17+ key formats: `sk-ant-` (Anthropic), `sk-proj-` (OpenAI), `gsk_` (Groq), `xai-` (xAI), `AKIA` (AWS), `ghp_`/`gho_` (GitHub), `glpat-` (GitLab), `xoxb-`/`xoxp-` (Slack), Telegram bot tokens, Discord tokens, `sk_live_` (Stripe), OpenRouter, Google AI, and generic Bearer tokens.

### Malicious Skill Detection

- Remote code execution patterns (`curl | sh`, `wget | bash`)
- Base64-encoded payloads over 50 characters
- Known C2 IP addresses from the ClawHavoc campaign
- References to paste services (glot.io, pastebin.com, hastebin)
- Typosquatted ClawHub publisher names
- Suspicious binary requirements (`nc`, `ncat`, `netcat`, `nmap`, `socat`)
- Excessive permission requests (exec + sensitive_data + filesystem write)
- Password-protected archive downloads

## Auto-Fix

`clawguard fix` remediates these issues automatically:

| Issue | Fix Applied |
|---|---|
| Wrong file permissions | `chmod 700` dirs, `chmod 600` config files |
| Sandbox disabled | Sets `sandbox.mode` to `"all"` |
| No Docker network isolation | Sets `docker.network` to `"none"` |
| Exec runs on host | Sets `tools.exec.host` to `"sandbox"` |
| Log redaction off | Sets `logging.redactSensitive` to `"tools"` |
| Weak gateway token | Generates 64-character hex token |
| `.bak` files with old creds | Deletes backup files |

## CI/CD Integration

ClawGuard returns exit code `2` when critical issues are found:

```yaml
# GitHub Actions
- name: OpenClaw security scan
  run: |
    pip install clawguard
    clawguard scan --format json > security-report.json
    clawguard scan
```

```yaml
# GitLab CI
security_scan:
  script:
    - pip install clawguard
    - clawguard scan --format json --path $OPENCLAW_DIR
  allow_failure: false
```

## Scoring

Starts at 100, deducted per finding:

| Severity | Points Deducted |
|---|---|
| CRITICAL | -20 |
| HIGH | -10 |
| MEDIUM | -5 |
| INFO | 0 |

| Score Range | Rating |
|---|---|
| 81-100 | Good |
| 61-80 | Fair |
| 31-60 | Poor |
| 0-30 | Critical Risk |

## Development

```bash
git clone https://github.com/vman7250/clawguard.git
cd clawguard
pip install -e .

# Test against insecure fixture
clawguard scan --path tests/fixtures/

# Test against secure fixture
clawguard scan --path tests/fixtures/secure_config.json
```

## Contributing

Contributions welcome. Please open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Add tests for new checks in `tests/`
4. Submit a PR

## Security

If you find a security vulnerability in ClawGuard itself, please report it privately via [GitHub Security Advisories](https://github.com/vman7250/clawguard/security/advisories/new) instead of opening a public issue.

## License

[MIT](LICENSE)
