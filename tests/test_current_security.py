import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from clawguard.checks.hardening import check_hardening
from clawguard.checks.permissions import check_permissions
from clawguard.checks.version import advisory_findings, parse_openclaw_version
from clawguard.scanner import run_fix

FIXTURES = Path(__file__).parent / "fixtures"
EXPECTED_INSECURE = {
    "gateway.auth.token", "gateway.control_ui.wildcard_origin", "gateway.control_ui.host_fallback",
    "gateway.nodes.auto_approve_cidrs", "gateway.nodes.ssh_verify", "gateway.nodes.browser_relay",
    "browser.ssrf.private_network", "tools.exec.security_full", "tools.exec.ask_off", "tools.exec.host_gateway",
    "tools.exec.strict_inline_eval", "tools.exec.patch_workspace_only", "tools.elevated.enabled", "tools.fs.workspace_only",
    "tools.sessions.visibility_all", "tools.deny.recommended_groups", "sandbox.defaults.scope_shared",
    "sandbox.defaults.workspace_rw", "sandbox.defaults.docker_network", "sandbox.defaults.readonly_root",
    "sandbox.defaults.cap_drop", "sandbox.defaults.external_binds", "sandbox.defaults.reserved_targets",
    "sandbox.defaults.namespace_join", "sandbox.defaults.sensitive_binds", "sandbox.entries_worker.mode_off",
    "channels.telegram.dm_policy_open", "channels.telegram.allow_from_wildcard", "session.dm_scope_shared",
    "plugins.allow_missing", "security.install_policy_missing", "plugins.acpx.approve_all", "files.workspace_env_overrides",
}


def ids(path: Path) -> set[str]:
    return {finding.id for finding in check_hardening(path)}


class CurrentSecurityTests(unittest.TestCase):
    def test_every_combined_new_check_has_positive_and_secure_negative(self):
        self.assertLessEqual(EXPECTED_INSECURE, ids(FIXTURES / "current_insecure"))
        self.assertFalse(EXPECTED_INSECURE & ids(FIXTURES / "current_secure"))

    def test_remaining_gateway_positive_and_negative(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            for config, expected in [
                ({"gateway": {"bind": "lan"}}, "gateway.bind_auth"),
                ({"gateway": {"bind": "loopback", "trustedProxies": ["127.0.0.1"]}}, "gateway.trusted_proxies.loopback"),
            ]:
                (directory / "openclaw.json").write_text(json.dumps(config))
                self.assertIn(expected, ids(directory))
                self.assertNotIn(expected, ids(FIXTURES / "current_secure"))

    def test_prereleases_and_numeric_suffixes_sort_before_successor(self):
        for left, right in [
            ("2026.9.1-beta.1", "2026.9.1"), ("2026.7.1-2", "2026.7.1"),
            ("2026.9.1-beta.1", "2026.9.1-beta.2"),
        ]:
            self.assertLess(parse_openclaw_version(left), parse_openclaw_version(right))

    def test_advisories_are_grouped_once_per_band(self):
        records = [
            {"ghsa": "GHSA-a", "cve": "CVE-1", "severity": "HIGH", "cvss": 9.0, "title": "a", "patched_version": "2026.8.1"},
            {"ghsa": "GHSA-b", "cve": "CVE-2", "severity": "HIGH", "cvss": 8.0, "title": "b", "patched_version": "2026.8.0"},
            {"ghsa": "GHSA-c", "cve": "CVE-3", "severity": "LOW", "cvss": 2.0, "title": "c", "patched_version": "2026.8.1"},
        ]
        findings = advisory_findings("2026.7.1-2", records, "2026-08-01")
        self.assertEqual([(finding.id, finding.severity.value) for finding in findings], [("advisory.high", "HIGH"), ("advisory.low", "LOW")])
        self.assertEqual(len(findings[0].verbose_details), 2)

    def test_added_sensitive_files_use_0600(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw); directory.chmod(0o700)
            files = [directory / "state/openclaw.sqlite", directory / "secrets.json", directory / "agents/a/agent/openclaw-agent.sqlite", directory / "credentials/nested/token"]
            for file in files:
                file.parent.mkdir(parents=True, exist_ok=True); file.write_text("secret"); file.chmod(0o644)
            self.assertTrue(any(finding.severity.value == "HIGH" for finding in check_permissions(directory)))
            for file in files: file.chmod(0o600)
            self.assertFalse(check_permissions(directory))

    def test_autofix_round_trip_only_writes_current_schema_keys(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            shutil.copytree(FIXTURES / "current_insecure", directory, dirs_exist_ok=True)
            with patch("clawguard.scanner.is_docker_available", return_value=False):
                run_fix(directory)
            config = json.loads((directory / "openclaw.json").read_text())
            self.assertNotIn("redactSensitive", config.get("logging", {}))
            self.assertGreaterEqual(len(config["gateway"]["auth"]["token"]), 32)
            self.assertIs(config["gateway"]["nodes"]["pairing"]["sshVerify"], True)
            self.assertIs(config["browser"]["ssrfPolicy"]["dangerouslyAllowPrivateNetwork"], False)
            self.assertIs(config["tools"]["exec"]["strictInlineEval"], True)
            self.assertIs(config["tools"]["exec"]["applyPatch"]["workspaceOnly"], True)
            self.assertIs(config["agents"]["defaults"]["sandbox"]["docker"]["readOnlyRoot"], True)
            self.assertEqual(config["plugins"]["entries"]["acpx"]["config"]["permissionMode"], "ask")


if __name__ == "__main__":
    unittest.main()
