#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Private fixture tests. --kernel explicitly builds and executes harmless fixtures."""
import importlib.util
import errno
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import sys

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("bootstrap", HERE / "measurement-fixture-bootstrap.py")
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)
KERNEL_OUTPUT = None


def require_unused_fd(fd):
    try:
        os.fstat(fd)
    except OSError as error:
        if error.errno == errno.EBADF:
            return
        raise
    raise RuntimeError("sentinel descriptor already occupied")


def elf(kind=2, segment=1):
    data = bytearray(120)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, kind, 62, 1, 0x400000, 64,
                     0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, segment, 5, 0, 0x400000, 0,
                     len(data), len(data), 4096)
    return bytes(data)


class HeaderTests(unittest.TestCase):
    def test_accepts_only_static_exec(self):
        bootstrap.static_elf(elf())
        for data in (b"#!/bin/sh\n", elf(kind=3), elf(segment=2), elf(segment=3),
                     elf()[:90], elf()[:4] + b"\x01" + elf()[5:]):
            with self.subTest(data=data[:24]), self.assertRaises(ValueError):
                bootstrap.static_elf(data)

    def test_program_table_is_bounded(self):
        data = bytearray(elf())
        struct.pack_into("<Q", data, 32, 2**64 - 1)
        with self.assertRaises(ValueError):
            bootstrap.static_elf(data)

    def test_namespace_command_has_no_host_fallback(self):
        command = bootstrap.namespace_command("/usr/bin/bwrap", Path("/private/bootstrap"))
        for option in ("--unshare-all", "--as-pid-1", "--die-with-parent", "--clearenv"):
            self.assertIn(option, command)
        self.assertNotIn("--new-session", command)
        self.assertEqual(command[-2:], ["--", "/bootstrap"])
        self.assertEqual(command.count("--ro-bind"), 1)
        self.assertNotIn("--dev", command)


class ArtifactTests(unittest.TestCase):
    def test_open_sentinel_slot_is_refused_without_closing_it(self):
        with open(os.devnull, "rb") as occupied:
            with self.assertRaisesRegex(RuntimeError, "already occupied"):
                require_unused_fd(occupied.fileno())
            os.fstat(occupied.fileno())

    def test_exact_transaction_artifacts_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / bootstrap.TARGET / "release/deps"
            directory.mkdir(parents=True)
            rows = []
            for name, version in bootstrap.VERSIONS.items():
                library = directory / f"lib{name}-fixture.rlib"
                library.touch()
                rows.append({"reason": "compiler-artifact",
                             "package_id": bootstrap.package_id(name, version),
                             "target": {"name": name, "kind": ["lib"]},
                             "profile": {"test": False}, "features": ["std"], "fresh": False,
                             "filenames": [str(library)]})
            rows.append({"reason": "build-finished", "success": True})
            self.assertEqual(set(bootstrap.select_artifacts(rows, root)), {"libc", "sha2"})
            direct = directory.parent / "liblibc.rlib"
            direct.touch()
            self.assertEqual(bootstrap.select_artifacts(
                [dict(rows[0], filenames=[str(direct)]), *rows[1:]], root)["libc"]["path"],
                str(direct))
            for invalid in (rows[:-1], rows + [rows[0]], rows[1:],
                            rows[:-1] + [{"reason": "build-finished", "success": False}]):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    bootstrap.select_artifacts(invalid, root)
            for key, value in (("package_id", bootstrap.package_id("libc", "0.2.189")),
                               ("fresh", True),
                               ("profile", {"test": True}),
                               ("target", {"name": "libc", "kind": ["bin"]}),
                               ("filenames", ["/outside/liblibc.rlib"])):
                invalid = [dict(rows[0], **{key: value}), *rows[1:]]
                with self.subTest(key=key), self.assertRaises(ValueError):
                    bootstrap.select_artifacts(invalid, root)


class KernelTests(unittest.TestCase):
    """All launches use only owned static fixtures in an empty-root namespace."""

    @classmethod
    def setUpClass(cls):
        cls.build = bootstrap.Build(KERNEL_OUTPUT)
        cls.build.negative_controls()
        cls.probe = cls.build.compile("probe", bootstrap.EXAMPLES / "measurement_entry_probe.rs", document=True)
        cls.launcher = cls.build.compile("bootstrap", bootstrap.EXAMPLES / "measurement_fixture_bootstrap.rs",
                                        pin=bootstrap.digest(cls.probe), document=True)
        cls.expected = b"fixture: constructor\nfixture: main\n"
        (cls.build.directory / "runs").mkdir()

    def variant(self, name, **options):
        return self.build.compile(name, bootstrap.EXAMPLES / "measurement_fixture_bootstrap.rs", **options)

    def tearDown(self):
        self.assertFalse(bootstrap._OWNED, "unfinished fixture process ownership")

    def execute(self, label, *, program=None, candidate=None, **options):
        candidate = candidate or self.probe
        with open(candidate, "rb") as source:
            result = bootstrap.run(program or self.launcher, source, **options)
        self.record(label, result)
        if options.get("result_fd") is None and options.get("diagnostic_fd") is None:
            self.assertTrue(result["eof"])
        else:
            self.assertFalse(result["eof"])
        self.assertEqual(result["eof_streams"], [name for name, option in
                                               (("stdout", "result_fd"), ("stderr", "diagnostic_fd"))
                                               if options.get(option) is None])
        return result

    def record(self, label, result):
        result = {key: value.decode("ascii", "backslashreplace") if isinstance(value, bytes) else value
                  for key, value in result.items()}
        (self.build.directory / "runs" / (label + ".json")).write_text(json.dumps(result, indent=2) + "\n")

    def assert_refusal(self, result, reason):
        self.assertEqual((result["status"], result["stdout"], result["stderr"]), (77, b"", reason))
        self.assertFalse(result["timed_out"])

    def test_constructor_then_main_and_empty_fixture_environment(self):
        result = self.execute("positive")
        self.assertEqual((result["status"], result["stdout"], result["stderr"]), (0, self.expected, b""))
        self.assertFalse(result["timed_out"])

    def test_environment_cwd_and_hostile_outer_environment(self):
        with mock.patch.dict(os.environ, {"LD_PRELOAD": "/missing/hostile.so", "IRLUME_FIXTURE_SHA256": "wrong",
                                         "IRLUME_BOOTSTRAP_TEST": "keep-fds", "PWD": "/wrong"}):
            result = self.execute("hostile-outer-env")
        self.assertEqual((result["status"], result["stdout"]), (0, self.expected))
        self.assert_refusal(self.execute("extra-env", extra_environment={"EXTRA": "1"}), b"argv-env\n")
        self.assert_refusal(self.execute("wrong-pwd", cwd="/proc"), b"argv-env\n")

    def test_rust_unit_harness(self):
        program = self.variant("unit-tests", test=True, document=True)
        result = self.execute("unit-tests", program=program)
        self.assertEqual(result["status"], 0)
        self.assertIn(b"10 passed; 0 failed", result["stdout"])
        self.assertIn(b"bootstrap_environment_is_exact_raw_pwd_not_authority", result["stdout"])

    def test_negative_pins_reach_each_branch(self):
        for label, pin, reason in [("pin-missing", None, b"pin-missing\n"),
                                   ("pin-malformed", "invalid", b"pin-invalid\n"),
                                   ("pin-wrong", "0" * 64, b"pin-mismatch\n")]:
            with self.subTest(label=label):
                self.assert_refusal(self.execute(label, program=self.variant(label, pin=pin)), reason)

    def test_structural_negatives_have_their_own_correct_pins(self):
        pie = self.build.compile("pie", bootstrap.EXAMPLES / "measurement_entry_probe.rs", pie=True)
        dynamic = self.build.compile("dynamic", bootstrap.EXAMPLES / "measurement_entry_probe.rs",
                                     target="x86_64-unknown-linux-gnu", dynamic=True)
        interp = bytearray(elf())
        struct.pack_into("<I", interp, 64, 3)
        cases = [("script", b"#!/bin/sh\necho forbidden\n", b"source-eof\n"),
                 ("bad-header", bytes(120), b"elf-header\n"),
                 ("truncated", self.probe.read_bytes()[:64], b"elf-table\n"),
                 ("interpreter", bytes(interp), b"elf-dynamic\n"),
                 ("static-pie", pie.read_bytes(), b"elf-profile\n"),
                 ("dynamic-elf", dynamic.read_bytes(), b"elf-profile\n")]
        for label, data, reason in cases:
            with self.subTest(label=label):
                candidate = self.build.directory / (label + ".input")
                candidate.write_bytes(data)
                program = self.variant(label + "-bootstrap", pin=bootstrap.digest(candidate))
                self.assert_refusal(self.execute(label, program=program, candidate=candidate), reason)

    def test_source_limits_and_mutation_do_not_execute_replacements(self):
        for label, size in [("empty", 0), ("oversized", bootstrap.LIMIT + 1)]:
            candidate = self.build.directory / (label + ".input")
            candidate.write_bytes(bytes(size))
            self.assert_refusal(self.execute(label, candidate=candidate), b"source-size\n")
        original = self.build.directory / "race.input"
        original.write_bytes(self.probe.read_bytes())
        replacement = self.build.directory / "replacement.input"
        replacement.write_bytes(b"#!/bin/sh\necho REPLACEMENT\n")
        with original.open("rb") as source:
            def replace(_):
                os.replace(replacement, original)
            result = bootstrap.run(self.launcher, source, cancel=replace)
        self.record("replacement", result)
        self.assertIn((result["status"], result["stdout"]), [(0, self.expected), (77, b"")])
        original.write_bytes(self.probe.read_bytes())
        with original.open("rb") as source:
            def mutate(_):
                original.write_bytes(b"mutated source")
            result = bootstrap.run(self.launcher, source, cancel=mutate)
        self.record("mutation", result)
        self.assertIn((result["status"], result["stdout"]), [(0, self.expected), (77, b"")])

    def test_high_fd_reaches_bootstrap_then_closes_and_mutation_fails(self):
        pin = bootstrap.digest(self.probe)
        clean = self.variant("sentinel", pin=pin, fault="sentinel")
        mutant = self.variant("keep-fds", pin=pin, fault="keep-fds")
        with open(os.devnull, "rb") as sentinel:
            require_unused_fd(198)
            os.dup2(sentinel.fileno(), 198, inheritable=True)
            try:
                result = self.execute("sentinel", program=clean, sync_fd=198)
                self.assertEqual((result["status"], result["stdout"], result["stderr"]),
                                 (0, self.expected, b"sentinel-received\n"))
                result = self.execute("sentinel-mutant", program=mutant, sync_fd=198)
                self.assertEqual((result["status"], result["stdout"], result["stderr"]),
                                 (77, b"", b"sentinel-received\nhigh-fd-leak\n"))
                with self.assertRaises(AssertionError):
                    self.assertEqual(result["status"], 0)
            finally:
                os.close(198)

    def test_memfd_denial_and_missing_seal_fail_closed(self):
        missing = self.variant("missing-seal", pin=bootstrap.digest(self.probe), fault="missing-seal")
        self.assert_refusal(self.execute("missing-seal", program=missing), b"seal-readback\n")
        # x86-64 seccomp: kill a wrong architecture; return EPERM for memfd_create.
        instructions = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, 0x80000000),
                        (0x20, 0, 0, 0), (0x15, 0, 1, 319), (0x06, 0, 0, 0x50000 | errno.EPERM),
                        (0x06, 0, 0, 0x7FFF0000)]
        fd = os.memfd_create("fixture-seccomp", os.MFD_CLOEXEC)
        try:
            os.write(fd, b"".join(struct.pack("<HBBI", *instruction) for instruction in instructions))
            os.lseek(fd, 0, os.SEEK_SET)
            self.assert_refusal(self.execute("memfd-denied", seccomp_fd=fd), b"memfd\n")
        finally:
            os.close(fd)

    def test_wrong_stdio_full_and_closed_pipes(self):
        with self.probe.open("rb+") as writable_source:
            result = bootstrap.run(self.launcher, writable_source)
        self.record("writable-source", result)
        self.assert_refusal(result, b"source-role\n")
        read_only, writer = os.pipe()
        try:
            self.assert_refusal(self.execute("read-only-stdout", result_fd=read_only), b"pipe-role\n")
            result = self.execute("read-only-stderr", diagnostic_fd=read_only)
            self.assertEqual((result["status"], result["stdout"]), (77, b""))
        finally:
            os.close(read_only)
            os.close(writer)
        with open(os.devnull, "rb+") as wrong:
            self.assert_refusal(self.execute("wrong-stdout", result_fd=wrong), b"pipe-role\n")
            result = self.execute("wrong-stderr", diagnostic_fd=wrong)
            self.assertEqual((result["status"], result["stdout"]), (77, b""))
        read, write = os.pipe()
        try:
            os.set_blocking(write, False)
            while True:
                try:
                    os.write(write, b"x" * 4096)
                except BlockingIOError:
                    break
            result = self.execute("full-output", result_fd=write)
            self.assertEqual(result["status"], 78)
            self.assertFalse(result["timed_out"])
            result = self.execute("alias-pipes", result_fd=write, diagnostic_fd=write)
            self.assertEqual(result["status"], 77)
            self.assertFalse(result["timed_out"])
            os.close(read)
            read = -1
            result = self.execute("closed-reader", result_fd=write)
            self.assertEqual(result["status"], 78)
        finally:
            if read >= 0: os.close(read)
            os.close(write)

    def test_closed_post_startup_stdio_never_reaches_fixture(self):
        for fd in (0, 1, 2):
            label = "closed-stdio-" + str(fd)
            program = self.variant(label, pin=bootstrap.digest(self.probe), fault=label)
            result = self.execute(label, program=program)
            self.assertEqual((result["status"], result["stdout"]), (77, b""))
            self.assertEqual(result["stderr"], b"" if fd == 2 else b"descriptor\n")

    def test_default_and_non_musl_builds_have_no_constructor(self):
        for source in ("measurement_entry_probe.rs", "measurement_fixture_bootstrap.rs"):
            for label, evidence, target in [("default", False, bootstrap.TARGET),
                                            ("gnu", True, "x86_64-unknown-linux-gnu")]:
                name = label + "-" + source.removesuffix(".rs")
                program = self.build.compile(name, bootstrap.EXAMPLES / source, evidence=evidence,
                                             target=target, pin=bootstrap.digest(self.probe), dynamic=label == "gnu")
                self.assertNotIn(b"fixture: constructor", program.read_bytes())
                if label == "gnu":
                    self.gnu_stub(name, program)
                else:
                    result = self.execute(name, program=program)
                    self.assertEqual((result["status"], result["stdout"], result["stderr"]), (77, b"", b""))

    def gnu_stub(self, name, program):
        # Disabled GNU stubs use the existing DSO-aware empty-root runner.
        # This is not a fallback or a dependency mount in the active controller.
        spec = importlib.util.spec_from_file_location("isolated_cli", HERE / "isolated-cli.py")
        isolated = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(isolated)
        tool_keys = ("IRLUME_TEST_LDDTREE", "IRLUME_TEST_ELFTOOLS_WHEEL")
        overrides = {key: os.environ[key] for key in tool_keys if key in os.environ}
        for key, value in overrides.items():
            isolated.checked_file(value)  # Verify before invoking any tool.
            self.build.record.setdefault("gnu_test_tools", {})[key] = {
                "path": value, "sha256": bootstrap.digest(value)}
        self.build.save()
        receipt = self.build.directory / "runs" / (name + "-isolation.json")
        with mock.patch.dict(os.environ, overrides):
            result = isolated.run(program, None, [], receipt)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (77, b"", b""))
        preflight = json.loads(receipt.read_text())["preflight"]
        self.assertEqual(preflight, {"empty_root": True, "host_inputs_absent": True,
                                     "inherited_fds_absent": True, "no_new_privileges": True})
        self.record(name, {"status": result.returncode, "stdout": result.stdout,
                           "stderr": result.stderr, "receipt": str(receipt),
                           "sha256": bootstrap.digest(program)})

    def test_descendant_exit_timeout_and_cancellation_reach_eof(self):
        for mode in ("descendant", "escaped", "timeout"):
            candidate = self.build.compile(mode, bootstrap.EXAMPLES / "measurement_entry_probe.rs", mode=mode)
            program = self.variant(mode + "-bootstrap", pin=bootstrap.digest(candidate))
            result = self.execute(mode, candidate=candidate, program=program, timeout=1)
            self.assertEqual(result["stdout"], self.expected + b"fixture: descendant\n")
            self.assertEqual(result["timed_out"], mode == "timeout")
            self.assertEqual(result["status"], -9 if mode == "timeout" else 0)
            if mode == "timeout":
                captured = []
                spawn = bootstrap.subprocess.Popen
                def keep_process(*args, **kwargs):
                    child = spawn(*args, **kwargs)
                    captured.append(child)
                    return child
                observed = bytearray()
                def cancel_after_descendant(channel, data):
                    if channel == "stdout":
                        observed.extend(data)
                        if b"fixture: descendant\n" in observed:
                            raise InterruptedError("fixture cancellation")
                with mock.patch.object(bootstrap.subprocess, "Popen", side_effect=keep_process):
                    with self.assertRaises(InterruptedError):
                        self.execute("cancel", candidate=candidate, program=program, on_chunk=cancel_after_descendant)
                self.assertEqual(captured[0].returncode, -9)
                self.assertTrue(captured[0].stdout.closed and captured[0].stderr.closed)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(captured[0].pid, os.WNOHANG)
                self.record("cancel", {"reaped": True, "closed": True, "descendant_observed": True})

    def test_namespace_and_collection_setup_failure_never_fall_back(self):
        result = self.execute("namespace-failure", cwd="/missing")
        self.assertNotEqual(result["status"], 0)
        self.assertEqual(result["stdout"], b"")
        captured = []
        spawn = bootstrap.subprocess.Popen
        def keep_process(*args, **kwargs):
            child = spawn(*args, **kwargs)
            captured.append(child)
            return child
        with mock.patch.object(bootstrap.subprocess, "Popen", side_effect=keep_process):
            with mock.patch.object(bootstrap.os, "set_blocking", side_effect=OSError("setup injection")):
                with self.assertRaises(OSError):
                    self.execute("collection-setup-failure")
        self.assertIsNotNone(captured[0].returncode)
        self.assertTrue(captured[0].stdout.closed and captured[0].stderr.closed)
        with self.assertRaises(ChildProcessError):
            os.waitpid(captured[0].pid, os.WNOHANG)
        self.record("setup-failure", {"reaped": True, "closed": True})

    def test_cleanup_failure_retains_owner_until_explicit_recovery(self):
        captured = []
        spawn = bootstrap.subprocess.Popen
        def keep_process(*args, **kwargs):
            child = spawn(*args, **kwargs)
            captured.append(child)
            return child
        with mock.patch.object(bootstrap.subprocess, "Popen", side_effect=keep_process):
            with mock.patch.object(bootstrap.os, "set_blocking", side_effect=OSError("setup injection")):
                with mock.patch.object(bootstrap.select, "select", side_effect=OSError("cleanup injection")):
                    with self.assertRaisesRegex(OSError, "cleanup injection"):
                        self.execute("cleanup-retained")
        child = captured[0]
        self.assertIs(bootstrap._OWNED[child.pid], child)
        self.assertIsNone(child.returncode)
        self.assertFalse(child.stdout.closed or child.stderr.closed)
        bootstrap._finish(child)
        self.assertTrue(child.stdout.closed and child.stderr.closed)
        with self.assertRaises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)
        self.record("cleanup-recovered", {"retained_then_reaped": True, "closed": True})


def load_tests(loader, _tests, _pattern):
    # Standard unittest discovery stays portable. Artifact builds and runtime
    # tests require the explicit --kernel entry point below.
    suite = unittest.TestSuite()
    for group in (HeaderTests, ArtifactTests, *([KernelTests] if KERNEL_OUTPUT is not None else [])):
        suite.addTests(loader.loadTestsFromTestCase(group))
    return suite


if __name__ == "__main__":
    kernel = "--kernel" in sys.argv
    if kernel:
        sys.argv.remove("--kernel")
        parent = Path.home() / ".cache/irlume-gpu-bootstrap-target"
        parent.mkdir(parents=True, exist_ok=True)
        import uuid
        KERNEL_OUTPUT = parent / ("acceptance-" + uuid.uuid4().hex)
        print("Fixture build transaction:", KERNEL_OUTPUT, flush=True)
    suite = load_tests(unittest.defaultTestLoader, None, None)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    complete = (result.testsRun >= (19 if kernel else 5) and not result.skipped
                and not result.expectedFailures and not result.unexpectedSuccesses)
    if not complete:
        print("fixture test-count/status guard refused incomplete coverage", file=sys.stderr)
    sys.exit(not (complete and result.wasSuccessful()))
