#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Synthetic mount-generation tests; kernel execution is explicit only."""
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("generation", HERE / "measurement-generation.py")
generation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generation)
KERNEL_OUTPUT = None


class ReportTests(unittest.TestCase):
    def good(self):
        return {"case": "positive", "publisher_terminated": True, "published": "b",
                "consumer_a": "retained", "consumer_b": "retained", "handles_closed": True}

    def test_positive_requires_complete_lifetime_evidence(self):
        generation.validate_report(self.good(), "positive")
        for key, value in [("publisher_terminated", False), ("publisher_terminated", 1),
                           ("published", "a"), ("consumer_a", "ready"),
                           ("consumer_b", "missing"), ("handles_closed", False)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                generation.validate_report(dict(self.good(), **{key: value}), "positive")

    def test_wrong_case_missing_and_extra_fields_refuse(self):
        for value in [None, [], {}, dict(self.good(), case="cancel"),
                      dict(self.good(), extra=True),
                      {k: v for k, v in self.good().items() if k != "handles_closed"}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                generation.validate_report(value, "positive")

    def test_namespace_setup_is_empty_root_without_host_fallback(self):
        command = generation.namespace_command("/usr/bin/bwrap", "/private/static-fixture")
        for option in ["--unshare-all", "--as-pid-1", "--die-with-parent", "--clearenv"]:
            self.assertIn(option, command)
        self.assertNotIn("--ro-bind-try", command)
        self.assertNotIn("--unshare-user-try", command)
        self.assertNotIn("--dev", command)
        self.assertEqual(command[-2:], ["--", "/fixture"])
        self.assertEqual(command.count("--ro-bind"), 1)
        self.assertNotIn("/", [command[i + 1] for i, x in enumerate(command) if x == "--ro-bind"])

    def test_late_release_must_follow_publisher_reaping(self):
        records = [{"event": "a_ready"}, {"event": "published", "selected": "b", "b_started": True},
                   {"event": "publisher_reaped", "status": 0}, {"event": "late_release"}, self.good()]
        stdout = lambda rows: ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
        generation.validate_output(stdout(records), "positive")
        for wrong in [records[1:], records + [records[-1]],
                      [records[0], records[1], records[3], records[2], records[4]]]:
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                generation.validate_output(stdout(wrong), "positive")

    def test_missing_isolation_never_executes_a_host_fallback(self):
        with mock.patch.object(generation.bootstrap, "owned_static", return_value=(Path("/fixture"), "digest")), \
             mock.patch.object(generation.shutil, "which", return_value=None), \
             mock.patch.object(generation.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(RuntimeError, "no host fallback"):
                generation.run_fixture("/fixture")
            spawn.assert_not_called()

    def test_kernel_entrypoint_keeps_receipts_on_success_and_failure(self):
        module = sys.modules[__name__]
        for successful in (True, False):
            with self.subTest(successful=successful), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                sentinel = parent / "existing-receipt"
                sentinel.write_text("preserved")
                receipt = None

                def finish(_suite, successful=successful):
                    nonlocal receipt
                    receipt = module.KERNEL_OUTPUT / "manifest.json"
                    receipt.parent.mkdir(parents=True)
                    receipt.write_text('{"receipt": true}')
                    result = mock.Mock(testsRun=5, skipped=[], expectedFailures=[],
                                       unexpectedSuccesses=[])
                    result.wasSuccessful.return_value = successful
                    return result

                with mock.patch.object(unittest.TextTestRunner, "run", side_effect=finish), \
                     mock.patch.object(module, "KERNEL_OUTPUT", None), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(module.run_kernel(parent), 0 if successful else 1)
                self.assertTrue(receipt.is_file())
                self.assertEqual(sentinel.read_text(), "preserved")


class KernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = generation.bootstrap.Build(KERNEL_OUTPUT)
        for source in (Path(__file__).resolve(), HERE / "measurement-generation.py",
                       generation.bootstrap.ROOT / "scripts/test-measurement-generation.sh"):
            cls.build.record["sources"][str(source.relative_to(generation.bootstrap.ROOT))] = generation.bootstrap.digest(source)
        cls.build.save()
        cls.programs = {}

    def execute(self, mode, **options):
        if mode not in self.programs:
            self.programs[mode] = self.build.compile(mode, generation.bootstrap.EXAMPLES /
                                                   "measurement_generation_fixture.rs", mode=mode, **options)
        result = generation.run_fixture(self.programs[mode])
        serial = {k: v.decode("ascii", "backslashreplace") if isinstance(v, bytes) else v
                  for k, v in result.items()}
        (self.build.directory / (mode + "-result.json")).write_text(json.dumps(serial, indent=2) + "\n")
        self.assertFalse(result["timed_out"])
        self.assertTrue(result["eof"])
        self.assertFalse(generation.bootstrap._OWNED)
        return result

    def test_retains_both_generations_after_publisher_exit_and_crash(self):
        for mode in ("positive", "publisher-crash"):
            with self.subTest(mode=mode):
                result = self.execute(mode)
                self.assertEqual((result["status"], result["stderr"]), (0, b""))
                generation.validate_output(result["stdout"], mode)

    def test_partial_publication_and_cancellation_have_exact_lifetimes(self):
        for mode in ("fail-file", "fail-clone", "fail-move", "fail-after-move", "cancel"):
            with self.subTest(mode=mode):
                result = self.execute(mode)
                self.assertEqual((result["status"], result["stderr"]), (0, b""))
                generation.validate_output(result["stdout"], mode)

    def test_late_byte_control_reaches_release_before_refusal(self):
        result = self.execute("wrong-late")
        self.assertEqual(result["status"], 77)
        self.assertIn(b'"event":"publisher_reaped"', result["stdout"])
        self.assertIn(b'"event":"late_release"', result["stdout"])
        self.assertIn(b"leaf content (2)", result["stderr"])
        self.assertNotIn(b'"handles_closed":true', result["stdout"])

    def test_weakened_isolation_controls_are_detected(self):
        for mode, reason in [("nonrecursive-clone", b"sentinel open (2)"),
                             ("unfrozen-submount", b"superblock flags"),
                             ("missing-mount-readonly", b"mount attributes"),
                             ("leak-fd", b"descriptor leak (300)"),
                             ("keep-old-root", b"tree entries")]:
            with self.subTest(mode=mode):
                result = self.execute(mode)
                self.assertEqual(result["status"], 77)
                self.assertIn(reason, result["stderr"])
                self.assertNotIn(b'"handles_closed":true', result["stdout"])

    def test_inactive_builds_refuse_without_any_fixture_work(self):
        result = self.execute("ordinary-musl", evidence=False)
        self.assertEqual((result["status"], result["stdout"], result["stderr"]), (77, b"", b""))
        # An inactive GNU stub uses the existing DSO-aware empty-root tester.
        # The active generation controller still refuses dynamic executables.
        program = self.build.compile("evidence-gnu", generation.bootstrap.EXAMPLES /
                                     "measurement_generation_fixture.rs", evidence=True,
                                     target="x86_64-unknown-linux-gnu", dynamic=True)
        spec = importlib.util.spec_from_file_location("generation_isolated", HERE / "isolated-cli.py")
        isolated = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(isolated)
        receipt = self.build.directory / "gnu-stub-isolation.json"
        outcome = isolated.run(program, None, [], receipt)
        self.assertEqual((outcome.returncode, outcome.stdout, outcome.stderr), (77, b"", b""))
        self.assertEqual(json.loads(receipt.read_text())["preflight"],
                         {"empty_root": True, "host_inputs_absent": True,
                          "inherited_fds_absent": True, "no_new_privileges": True})


def run_kernel(parent=None):
    """Keep the unique build transaction and its receipts on every outcome."""
    global KERNEL_OUTPUT
    if parent is None:
        parent = Path(os.environ.get("IRLUME_GENERATION_OUTPUT",
                                     Path.home() / ".cache/irlume-measurement-generation"))
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Build requires a fresh nonexistent path beneath its transaction directory.
    KERNEL_OUTPUT = Path(tempfile.mkdtemp(prefix="acceptance-", dir=parent)) / "transaction"
    print("Generation build transaction:", KERNEL_OUTPUT, flush=True)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(KernelTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    complete = (result.testsRun == 5 and not result.skipped and not result.expectedFailures
                and not result.unexpectedSuccesses)
    return int(not (complete and result.wasSuccessful()))


if __name__ == "__main__":
    if sys.argv[1:] == ["--kernel"]:
        raise SystemExit(run_kernel())
    if sys.argv[1:]:
        raise SystemExit("usage: test-measurement-generation.py [--kernel]")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReportTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    complete = (result.testsRun == 6 and not result.skipped and not result.expectedFailures
                and not result.unexpectedSuccesses)
    raise SystemExit(not (complete and result.wasSuccessful()))
