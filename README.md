# ClawGuard

Security scanner for OpenClaw installations, with advisory intelligence current through OpenClaw 2026.8.1.

OpenClaw now has 543 tracked CVEs. ClawGuard 0.3.0 vendors 113 reviewed GitHub advisories with severity, CVSS, and patched-version data, then compares them with the installed version without producing one finding per CVE. Findings are grouped into one CRITICAL, HIGH, MEDIUM, or LOW band; JSON and `--verbose` retain the complete affected list.

ClawGuard complements, rather than replaces, `openclaw security audit`: ClawGuard provides CVE/advisory intelligence, version drift, filesystem checks, and cross-tool static configuration checks. OpenClaw's command is the vendor runtime probe and can be included as a separate, deduplicated section.

## Install

```bash
pip install clawguard
```

## Use

```bash
clawguard scan
clawguard scan --path ~/.openclaw --json
clawguard scan --refresh-advisories
clawguard scan --verbose
clawguard scan --with-openclaw-audit
clawguard fix
```

`--refresh-advisories` fetches the upstream GitHub JSON and falls back gracefully to the vendored snapshot when offline. The snapshot date is included in rich and JSON scan data. OpenClaw 2026.8.1 is the latest known stable release; 2026.9.1-beta.1 is the latest known prerelease. Betas compare before their corresponding stable release and are not treated as outdated merely for being prereleases newer than stable.

## Checks

| Area | Selected checks |
|---|---|
| Advisories | 113 scored/patched GHSA records, grouped by severity; 543-CVE headline dataset |
| Gateway | Non-loopback auth, token strength, Control UI origins/fallback, proxies, node pairing and browser relay |
| Browser | Private-network SSRF override |
| Tools | Exec security/approval/host/eval, patch and filesystem workspace limits, elevated tools, session visibility, deny groups |
| Sandbox | Defaults and per-agent mode, scope, workspace access, Docker network/root/capabilities/dangerous overrides/sensitive binds |
| Channels | Open DMs, wildcard senders, shared DM context |
| Plugins | Plugin allowlist, install policy, ACP-X approve-all |
| Files | 700/600 permissions, SQLite/secrets/agent databases/credential trees, workspace `.env` overrides |
| Existing analysis | Plaintext credentials, agent/provider configuration, skills, prompt-memory injection |

The obsolete `logging.redactSensitive` check and autofix were removed because current OpenClaw always redacts sensitive values and rejects that stale key.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No critical findings |
| 1 | Invocation or path error |
| 2 | One or more critical findings |

## Development

```bash
python -m pip install -e '.[test]'
pytest -q
python scripts/sync_advisories.py
python scripts/check_parity.py
```

The advisory generator writes both `src/clawguard/advisories.py` and the TypeScript port's `src/checks/advisories.ts`, so the two packages cannot drift.

## License

[MIT](LICENSE)
