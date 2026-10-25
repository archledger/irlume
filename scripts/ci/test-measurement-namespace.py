#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Private namespace observation tests; kernel execution is explicit."""
import importlib.util
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
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReportTests)
        expected = 4
    else:
        raise SystemExit("usage: test-measurement-namespace.py [--build|--kernel]")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    complete = (result.testsRun == expected and not result.skipped and not result.expectedFailures
                and not result.unexpectedSuccesses)
    raise SystemExit(not (complete and result.wasSuccessful()))
