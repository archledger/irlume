#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""VEX generation must require a completed, unsuppressed advisory scan."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("vex", Path(__file__).with_name("generate-vex.py"))
assert SPEC is not None and SPEC.loader is not None
VEX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VEX)

ADVISORY = "RUSTSEC-2023-0071"
CONFIG = '''[graph]
targets = ["x86_64-unknown-linux-gnu"]
[advisories]
version = 2
db-path = "relative-advisory-db"
ignore = []
[licenses]
allow = ["MIT"]
'''
REVIEWED = '''ignore = [
    # no private-key operations; reference crates/x/src/
    # pcrsig.rs (the comment may contain a closing bracket ]).
    "RUSTSEC-2023-0071",
]'''


def diagnostic(advisory=ADVISORY, code="vulnerability"):
    # cargo-deny 0.20.2 src/advisories/diags.rs and src/diag/grapher.rs.
    return {"type": "diagnostic", "fields": {
        "severity": "error", "code": code, "message": "fixture finding",
        "notes": [f"ID: {advisory}", "fixture advisory description"],
    }}


def summary(errors=0):
    return {"type": "summary", "fields": {"advisories": {
        "errors": errors, "helps": 0, "notes": 0, "warnings": 0,
    }}}


def scan_result(code=0, *records):
    return subprocess.CompletedProcess([], code, "", "\n".join(map(json.dumps, records)))


class GenerationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="irlume-vex-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.deny = self.root / "deny.toml"
        self.deny.write_text(CONFIG)
        self.out = self.root / "result.json"
        self.stderr = io.StringIO()

    def generate(self, result, config=CONFIG):
        self.deny.write_text(config)

        def run(command, **kwargs):
            if isinstance(result, Exception):
                raise result
            return result(command, **kwargs) if callable(result) else result

        with patch.object(VEX, "REPO", self.root), \
                patch.object(VEX.subprocess, "run", side_effect=run), \
                patch.object(sys, "argv", ["generate-vex.py", "--version", "0.15.0",
                                          "--out", str(self.out)]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(self.stderr):
            VEX.main()
        return json.loads(self.out.read_text())

    def assert_refused(self, result, config=CONFIG):
        with self.assertRaises(SystemExit):
            self.generate(result, config)
        self.assertFalse(self.out.exists(), "a failed scan must not produce an asset")
        self.assertNotIn("clean scan", self.stderr.getvalue())
        self.assertNotIn("Advisory scan completed", self.stderr.getvalue())

    def test_failed_scan_without_ignores_never_writes_document(self):
        self.assert_refused(subprocess.CompletedProcess([], 2, "", "database unavailable"))

    def test_completed_clean_scan_writes_empty_statements(self):
        doc = self.generate(scan_result(0, summary()))
        self.assertEqual(doc["statements"], [])
        self.assertEqual(doc["product"]["version"], "0.15.0")

    def test_completed_scan_accepts_normal_cargo_deny_logs(self):
        record = {"type": "log", "fields": {"level": "INFO", "message": "checking advisories..."}}
        self.assertEqual(self.generate(scan_result(0, record, summary()))["statements"], [])

    def test_unreviewed_advisory_aborts_without_ignores(self):
        self.assert_refused(scan_result(1, diagnostic(), summary(1)))

    def test_reviewed_advisory_uses_a_real_unsuppressed_config(self):
        config = CONFIG.replace("ignore = []", REVIEWED)
        paths = []

        def scanner(command, **kwargs):
            path = Path(command[command.index("--config") + 1])
            paths.append(path)
            self.assertTrue(path.is_file(), "--config must name an existing TOML file")
            self.assertEqual(path.parent, self.root, "relative database paths must retain their base")
            actual = tomllib.loads(path.read_text())
            expected = tomllib.loads(CONFIG)
            self.assertEqual(actual, expected, "only the advisory ignore list may change")
            self.assertIn("--locked", command)
            self.assertIn("--workspace", command)
            self.assertEqual(command[command.index("--format") + 1], "json")
            return scan_result(1, diagnostic(), summary(1))

        doc = self.generate(scanner, config)
        self.assertEqual(self.deny.read_text(), config)
        self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual(doc["statements"][0]["vulnerability"]["name"], ADVISORY)
        self.assertEqual(doc["statements"][0]["justification"], "vulnerable_code_not_in_execute_path")
        self.assertIn("crates/x/src/pcrsig.rs", doc["statements"][0]["impact_statement"])

    def test_incidental_advisory_text_does_not_establish_a_live_match(self):
        self.assert_refused(scan_result(1, diagnostic(code="index-cache-load-failure"), summary(1)),
                            CONFIG.replace("ignore = []", REVIEWED))

    def test_an_additional_unreviewed_advisory_aborts(self):
        self.assert_refused(scan_result(1, diagnostic(), diagnostic("RUSTSEC-2024-0001"), summary(2)),
                            CONFIG.replace("ignore = []", REVIEWED))

    def test_incomplete_and_inconsistent_scan_results_abort(self):
        cases = [scan_result(0), scan_result(2, summary()),
                 scan_result(0, summary(1)), scan_result(1, summary()),
                 scan_result(0, diagnostic(), summary(1)),
                 scan_result(1, diagnostic()),
                 subprocess.CompletedProcess([], 0, "", "not JSON"),
                 scan_result(0, {"type": "summary", "fields": {}})]
        for result in cases:
            with self.subTest(result=result):
                self.assert_refused(result)

    def test_stale_ignore_is_refused(self):
        self.assert_refused(scan_result(0, summary()), CONFIG.replace("ignore = []", REVIEWED))

    def test_unmapped_rationale_is_refused(self):
        config = CONFIG.replace("ignore = []", REVIEWED.replace("no private-key operations", "unreviewed"))
        self.assert_refused(scan_result(1, diagnostic(), summary(1)), config)

    def test_inline_ignore_cannot_be_silently_omitted(self):
        self.assert_refused(scan_result(0, summary()),
                            CONFIG.replace("ignore = []", f'ignore = ["{ADVISORY}"]'))

    def test_missing_tool_never_writes_document(self):
        self.assert_refused(FileNotFoundError())

    def test_an_advisory_cannot_be_downgraded_to_a_clean_scan(self):
        for severity, code in (("warning", "vulnerability"), ("note", "advisory-ignored")):
            with self.subTest(severity=severity, code=code):
                record = diagnostic(code=code)
                record["fields"]["severity"] = severity
                self.assert_refused(scan_result(0, record, summary()))

    def test_failed_scan_preserves_an_existing_output(self):
        self.out.write_text("previous artifact\n")
        with self.assertRaises(SystemExit):
            self.generate(subprocess.CompletedProcess([], 2, "", "database unavailable"))
        self.assertEqual(self.out.read_text(), "previous artifact\n")

    def test_unknown_diagnostic_forms_are_refused(self):
        records = [
            {"type": "future-error", "fields": {"message": "unknown condition"}},
            {"type": "diagnostic", "fields": {"severity": "fatal", "code": "future-error"}},
            {"type": "log", "fields": {"level": "future-level", "message": "unknown condition"}},
        ]
        for record in records:
            with self.subTest(record=record):
                self.assert_refused(scan_result(0, record, summary()))


if __name__ == "__main__":
    unittest.main()
