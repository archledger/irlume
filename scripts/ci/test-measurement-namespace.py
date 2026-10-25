#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Private namespace observation tests; kernel execution is explicit."""
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("namespace_probe", HERE / "measurement-namespace.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
KERNEL_OUTPUT = None
BUILD_ONLY = False


def run_suite(suite, expected, *, receipt=None, mode="portable", stream=None):
    """Retain counts only; an interrupted or incomplete run cannot report success."""
    result = None

    def make_result(*args, **kwargs):
        nonlocal result
        result = unittest.TextTestResult(*args, **kwargs)
        return result

    def save(status, *, complete=False, success=False):
        if receipt is None:
            return
        row = {"mode": mode, "status": status, "complete": complete, "success": success,
               "expected_tests": expected, "tests_run": result.testsRun if result else 0}
        for field, attribute in (("failures", "failures"), ("errors", "errors"),
                                 ("skipped", "skipped"), ("expected_failures", "expectedFailures"),
                                 ("unexpected_successes", "unexpectedSuccesses")):
            row[field] = len(getattr(result, attribute)) if result else 0
        # Keep the started record intact if killed during a terminal write.
        temporary = receipt.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(row, indent=2) + "\n")
        temporary.replace(receipt)

    # SIGKILL and other termination without Python cleanup leave this non-success record.
    save("started")
    try:
        result = unittest.TextTestRunner(verbosity=2, stream=stream, resultclass=make_result).run(suite)
    except BaseException as error:
        save("interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "exception")
        if isinstance(error, SystemExit):
            raise SystemExit(1) from None
        raise
    complete = result.testsRun == expected and not result.shouldStop
    success = (complete and result.wasSuccessful() and not result.skipped
               and not result.expectedFailures and not result.unexpectedSuccesses)
    save("success" if success else "failed", complete=complete, success=success)
    return int(not success)


class ReportTests(unittest.TestCase):
    def result(self, **updates):
        row = {"initial": True, "namespace_id": 4, "errno": 0, "pid": 123, "uid": 1000}
        row.update(updates)
        return {"status": 0, "stdout": (json.dumps(row) + "\n").encode(),
                "stderr": b"", "eof": True, "timed_out": False}

    def test_initial_and_nonobserved_are_distinct_from_errors(self):
        self.assertIs(probe.parse_result(self.result())["initial"], True)
        self.assertIs(probe.parse_result(self.result(initial=False, namespace_id=9))["initial"], False)
        error = self.result(initial=None, namespace_id=0, errno=2)
        error["status"] = 77
        self.assertIsNone(probe.parse_result(error)["initial"])

    def test_invalid_shapes_and_nonexact_types_refuse(self):
        for updates in [{"initial": 1}, {"namespace_id": True}, {"pid": True},
                        {"uid": False}, {"errno": False}, {"initial": True, "namespace_id": 9},
                        {"initial": False, "namespace_id": 4}, {"unknown": 1}]:
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                probe.parse_result(self.result(**updates))

    def test_incomplete_execution_never_becomes_a_result(self):
        for updates in [{"timed_out": True}, {"eof": False}, {"stderr": b"failure"},
                        {"status": 1}, {"stdout": b"{}\n{}\n"}, {"stdout": b"x" * 1025}]:
            result = dict(self.result(), **updates)
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                probe.parse_result(result)

    def test_user_only_does_not_create_a_pid_or_mount_namespace(self):
        command = probe.command("/probe", "user")
        self.assertEqual(command, ["/usr/bin/unshare", "--user", "--map-root-user", "--", "/probe"])
        self.assertEqual(probe.command("/probe", "host"), ["/probe"])
        self.assertEqual(probe.command("/probe", "user-pid"),
                         ["/usr/bin/unshare", "--user", "--map-root-user", "--pid", "--fork", "--", "/probe"])
        with self.assertRaises(ValueError):
            probe.command("/probe", "unknown")


class SuiteReceiptTests(unittest.TestCase):
    def run_recorded(self, tests, expected):
        with tempfile.TemporaryDirectory(prefix="namespace-suite-") as folder:
            receipt = Path(folder) / "suite-result.json"
            status = run_suite(unittest.TestSuite(tests), expected, receipt=receipt,
                               mode="build", stream=io.StringIO())
            return status, json.loads(receipt.read_text())

    def test_success_replaces_started_record_with_exact_counts(self):
        with tempfile.TemporaryDirectory(prefix="namespace-suite-") as folder:
            receipt = Path(folder) / "suite-result.json"

            def observe_started():
                row = json.loads(receipt.read_text())
                self.assertEqual(row["status"], "started")
                self.assertFalse(row["success"])
                self.assertFalse(row["complete"])
                self.assertEqual((row["expected_tests"], row["tests_run"]), (1, 0))

            status = run_suite(unittest.TestSuite([unittest.FunctionTestCase(observe_started)]),
                               1, receipt=receipt, mode="kernel", stream=io.StringIO())
            row = json.loads(receipt.read_text())
            self.assertEqual(status, 0)
            self.assertEqual((row["mode"], row["status"]), ("kernel", "success"))
            self.assertTrue(row["complete"])
            self.assertTrue(row["success"])
            self.assertEqual((row["expected_tests"], row["tests_run"]), (1, 1))
            for name in ("failures", "errors", "skipped", "expected_failures", "unexpected_successes"):
                self.assertEqual(row[name], 0)

    def test_short_run_is_not_success(self):
        status, row = self.run_recorded([unittest.FunctionTestCase(lambda: None)], 2)
        self.assertNotEqual(status, 0)
        self.assertEqual(row["status"], "failed")
        self.assertEqual((row["expected_tests"], row["tests_run"]), (2, 1))
        self.assertFalse(row["complete"])
        self.assertFalse(row["success"])

    def test_failures_errors_and_skips_are_counted_without_details(self):
        def fail():
            raise AssertionError("private failure detail")

        def error():
            raise RuntimeError("private error detail")

        def skip():
            raise unittest.SkipTest("private skip detail")

        for test, field in ((fail, "failures"), (error, "errors"), (skip, "skipped")):
            with self.subTest(field=field):
                status, row = self.run_recorded([unittest.FunctionTestCase(test)], 1)
                self.assertNotEqual(status, 0)
                self.assertEqual(row["status"], "failed")
                self.assertEqual(row[field], 1)
                self.assertFalse(row["success"])
                self.assertNotIn("private", json.dumps(row))

    def test_expected_failure_and_unexpected_success_are_not_success(self):
        class Cases(unittest.TestCase):
            @unittest.expectedFailure
            def test_expected_failure(self):
                self.fail("private expected failure detail")

            @unittest.expectedFailure
            def test_unexpected_success(self):
                pass

        for name, field in (("test_expected_failure", "expected_failures"),
                            ("test_unexpected_success", "unexpected_successes")):
            with self.subTest(field=field):
                status, row = self.run_recorded([Cases(name)], 1)
                self.assertNotEqual(status, 0)
                self.assertEqual(row[field], 1)
                self.assertFalse(row["success"])

    def test_runner_exception_and_interruption_keep_partial_counts_and_propagate(self):
        class BrokenSuite(unittest.TestSuite):
            def run(self, result, debug=False):
                super().run(result, debug)
                raise failure("private exception detail")

        for failure, label in ((RuntimeError, "exception"), (KeyboardInterrupt, "interrupted")):
            with self.subTest(label=label), tempfile.TemporaryDirectory(prefix="namespace-suite-") as folder:
                receipt = Path(folder) / "suite-result.json"
                with self.assertRaises(failure):
                    run_suite(BrokenSuite([unittest.FunctionTestCase(lambda: None)]), 2,
                              receipt=receipt, mode="build", stream=io.StringIO())
                row = json.loads(receipt.read_text())
                self.assertEqual(row["status"], label)
                self.assertEqual((row["expected_tests"], row["tests_run"]), (2, 1))
                self.assertFalse(row["complete"])
                self.assertFalse(row["success"])
                self.assertNotIn("private", json.dumps(row))

    def test_early_system_exit_zero_is_still_an_incomplete_failure(self):
        class ExitingSuite(unittest.TestSuite):
            def run(self, result, debug=False):
                raise SystemExit(0)

        with tempfile.TemporaryDirectory(prefix="namespace-suite-") as folder:
            receipt = Path(folder) / "suite-result.json"
            with self.assertRaises(SystemExit) as caught:
                run_suite(ExitingSuite(), 1, receipt=receipt, mode="build", stream=io.StringIO())
            self.assertNotEqual(caught.exception.code, 0)
            row = json.loads(receipt.read_text())
            self.assertEqual(row["status"], "interrupted")
            self.assertEqual((row["expected_tests"], row["tests_run"]), (1, 0))
            self.assertFalse(row["complete"])
            self.assertFalse(row["success"])

    def test_always_upload_retains_namespace_json_and_logs_not_dependencies(self):
        workflow = (probe.bootstrap.ROOT / ".github/workflows/ci.yml").read_text()
        step = workflow.split("- name: Retain generation fixture receipts\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("if: always()", step)
        self.assertIn("~/.cache/irlume-namespace-probe/**/*.json\n", step)
        self.assertIn("~/.cache/irlume-namespace-probe/**/*.log\n", step)
        self.assertIn("!~/.cache/irlume-namespace-probe/**/dependencies/**\n", step)
        self.assertNotIn("~/.cache/irlume-namespace-probe/**\n", step)


class KernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = probe.bootstrap.Build(KERNEL_OUTPUT)
        if not BUILD_ONLY:
            context = {"pid": os.getpid(), "uid": os.getuid(),
                       "user_namespace": os.readlink("/proc/self/ns/user"),
                       "pid_namespace": os.readlink("/proc/self/ns/pid"),
                       "kernel_release": os.uname().release}
            cls.build.record["parent_context"] = context
            cls.build.save()
            if (context["uid"] == 0 or context["user_namespace"] != "user:[4026531837]" or
                    context["pid_namespace"] != "pid:[4026531836]"):
                raise RuntimeError("qualified non-root initial-namespace test context required")
        for source in (Path(__file__).resolve(), HERE / "measurement-namespace.py",
                       probe.bootstrap.ROOT / "scripts/test-measurement-namespace.sh"):
            cls.build.record["sources"][str(source.relative_to(probe.bootstrap.ROOT))] = probe.bootstrap.digest(source)
        cls.build.save()
        cls.program = cls.build.compile("probe", probe.bootstrap.EXAMPLES / "measurement_namespace_probe.rs",
                                        document=True)

    def variant(self, name, old, new):
        module = probe.bootstrap.EXAMPLES / "measurement_namespace_probe/probe.rs"
        original = module.read_text()
        self.assertEqual(original.count(old), 1)
        copied = self.build.directory / (name + "-module.rs")
        copied.write_text(original.replace(old, new))
        source = self.build.directory / (name + ".rs")
        entry = (probe.bootstrap.EXAMPLES / "measurement_namespace_probe.rs").read_text()
        source.write_text(entry.replace("measurement_namespace_probe/probe.rs", str(copied)))
        for path in (source, copied):
            self.build.record["sources"][str(path)] = probe.bootstrap.digest(path)
        self.build.save()
        return self.build.compile(name, source)

    def test_rust_policy_tests_execute(self):
        program = self.build.compile("unit", probe.bootstrap.EXAMPLES / "measurement_namespace_probe.rs", test=True)
        result = probe.run(program, "host")
        self.assertEqual((result["status"], result["stderr"]), (0, b""))
        self.assertIn(b"4 passed; 0 failed", result["stdout"])
        self.assertTrue(result["eof"])
        self.assertFalse(result["timed_out"])
        self.record("unit", result)

    def record(self, name, result):
        serial = {key: value.decode("ascii", "backslashreplace") if isinstance(value, bytes) else value
                  for key, value in result.items()}
        (self.build.directory / (name + "-result.json")).write_text(json.dumps(serial, indent=2) + "\n")
        self.assertFalse(probe.bootstrap._OWNED)

    def execute(self, mode, **kwargs):
        result = probe.run(self.program, mode, **kwargs)
        self.record(mode, result)
        return result, probe.parse_result(result)

    def test_host_initial_and_user_only_error_are_separate(self):
        context = json.loads((self.build.directory / "manifest.json").read_text())["parent_context"]
        self.assertEqual(context["user_namespace"], "user:[4026531837]")
        self.assertEqual(context["pid_namespace"], "pid:[4026531836]")
        self.assertEqual((context["pid"], context["uid"]), (os.getpid(), os.getuid()))
        self.assertEqual(context["kernel_release"], os.uname().release)
        result, row = self.execute("host")
        self.assertEqual((row["initial"], row["namespace_id"], row["errno"]), (True, 4, 0))
        self.assertEqual((row["pid"], row["uid"]), (result["host_pid"], os.getuid()))
        result, row = self.execute("user")
        self.assertEqual((row["initial"], row["namespace_id"], row["errno"]), (None, 0, 2))
        self.assertEqual((row["pid"], row["uid"]), (result["host_pid"], 0))

    def test_user_pid_and_fake_proc_cannot_supply_initial_witness(self):
        _, row = self.execute("user-pid")
        self.assertEqual((row["initial"], row["errno"], row["pid"], row["uid"]), (False, 0, 1, 0))
        self.assertGreater(row["namespace_id"], 8)
        with tempfile.TemporaryDirectory(prefix="namespace-fake-proc-") as folder:
            fake = Path(folder)
            (fake / "self/ns").mkdir(parents=True)
            (fake / "self/uid_map").write_text("0 0 4294967295\n")
            (fake / "self/ns/user").symlink_to("user:[4026531837]")
            _, row = self.execute("fake-proc", fake_proc=fake)
        self.assertEqual((row["initial"], row["errno"], row["pid"], row["uid"]), (False, 0, 1, 0))
        self.assertGreater(row["namespace_id"], 8)

    def test_wrong_owner_and_invalid_flags_controls_reach_the_kernel(self):
        program = self.variant("wrong-owner", "user_ns_id: u64::MAX", "user_ns_id: 3")
        result = probe.run(program, "user")
        self.record("wrong-owner", result)
        row = probe.parse_result(result)
        self.assertEqual((row["initial"], row["namespace_id"], row["errno"]), (True, 4, 0))
        self.assertEqual((row["pid"], row["uid"]), (result["host_pid"], 0))
        # This is the precise false positive that the current-owner test prevents.
        self.assertNotEqual(row["initial"], None)
        program = self.variant("invalid-flags", "1usize, 0u32", "1usize, 1u32")
        result = probe.run(program, "host")
        self.record("invalid-flags", result)
        row = probe.parse_result(result)
        self.assertEqual((result["status"], row["initial"], row["errno"]), (77, None, 22))

    def test_inactive_builds_refuse(self):
        source = probe.bootstrap.EXAMPLES / "measurement_namespace_probe.rs"
        program = self.build.compile("ordinary", source, evidence=False)
        result = probe.run(program, "host")
        self.record("ordinary", result)
        self.assertEqual((result["status"], result["stdout"], result["stderr"]), (77, b"", b""))
        program = self.build.compile("gnu", source, target="x86_64-unknown-linux-gnu", dynamic=True)
        spec = importlib.util.spec_from_file_location("namespace_isolated", HERE / "isolated-cli.py")
        isolated = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(isolated)
        receipt = self.build.directory / "gnu-stub.json"
        result = isolated.run(program, None, [], receipt)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (77, b"", b""))
        self.assertEqual(json.loads(receipt.read_text())["preflight"],
                         {"empty_root": True, "host_inputs_absent": True,
                          "inherited_fds_absent": True, "no_new_privileges": True})


if __name__ == "__main__":
    if sys.argv[1:] in (["--kernel"], ["--build"]):
        BUILD_ONLY = sys.argv[1:] == ["--build"]
        parent = Path.home() / ".cache/irlume-namespace-probe"
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        KERNEL_OUTPUT = Path(tempfile.mkdtemp(prefix="acceptance-", dir=parent)) / "transaction"
        print("Namespace build transaction:", KERNEL_OUTPUT, flush=True)
        if BUILD_ONLY:
            suite = unittest.TestSuite(KernelTests(name) for name in (
                "test_rust_policy_tests_execute", "test_inactive_builds_refuse"))
            expected = 2
        else:
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(KernelTests)
            expected = 5
    elif not sys.argv[1:]:
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                                   for case in (ReportTests, SuiteReceiptTests))
        expected = 11
    else:
        raise SystemExit("usage: test-measurement-namespace.py [--build|--kernel]")
    # The run directory already exists; Build alone creates its transaction child.
    receipt = KERNEL_OUTPUT.parent / "suite-result.json" if KERNEL_OUTPUT else None
    mode = "build" if BUILD_ONLY else "kernel" if KERNEL_OUTPUT else "portable"
    raise SystemExit(run_suite(suite, expected, receipt=receipt, mode=mode))
