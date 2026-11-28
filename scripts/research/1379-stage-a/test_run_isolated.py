import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from artifact_receipt import executable_receipt, verify_executable
from run_isolated import REQUIRED_TESTS, fixture_count, sandbox_run, verify_loader


class IsolationTests(unittest.TestCase):
    def test_isolation_unavailable_fails_closed(self):
        with tempfile.TemporaryDirectory() as parent:
            marker = Path(parent) / "witness-started"
            argv = (
                "/usr/bin/python3", "-c",
                "import pathlib, sys; pathlib.Path(sys.argv[1]).touch(); "
                "print('libcamera link witness: 0.8.0')",
                str(marker),
            )
            with patch("run_isolated.BWRAP", "/usr/bin/false"):
                with self.assertRaises(subprocess.CalledProcessError) as failed:
                    sandbox_run(argv)
            self.assertNotIn("libcamera link witness: 0.8.0", failed.exception.stdout)
            self.assertFalse(marker.exists())

    def test_host_paths_and_inherited_handles_are_absent(self):
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent) / "parent-only"
            path.write_text("fixture sentinel")
            reader, writer = os.pipe()
            handle = fcntl.fcntl(reader, fcntl.F_DUPFD, 128)
            try:
                self.assertTrue(os.get_inheritable(handle))
                check = (
                    "import os, sys; from pathlib import Path;"
                    "assert not Path(sys.argv[1]).exists();"
                    "assert not Path('/proc/self/fd', sys.argv[2]).exists();"
                    "assert all(not list(Path('/dev').glob(x)) for x in "
                    "('video*','media*','v4l-subdev*','tpm*'));"
                    "assert not list(Path('/run').iterdir());"
                    "assert not list(Path('/home').iterdir());"
                    "assert 'DBUS_SESSION_BUS_ADDRESS' not in os.environ;"
                    "assert os.readlink('/proc/self/ns/net') != sys.argv[3];"
                    "print('isolated')"
                )
                reply = sandbox_run(("/usr/bin/python3", "-c", check, str(path), str(handle),
                                     os.readlink("/proc/self/ns/net")))
                self.assertEqual(reply.stdout, "isolated\n")
            finally:
                for fd in reader, writer, handle:
                    os.close(fd)

    def test_wrong_sdk_resolution_is_refused(self):
        camera = "calling init: /sdk/lib/libcamera.so.0.8"
        base = "calling init: /sdk/lib/libcamera-base.so.0.8"
        verify_loader(f"     7:\t{camera}\n     7:\t{base}\n")
        for trace in (
            camera,
            f"{camera}\n{base.replace('/sdk/', '/usr/')}\n",
            f"{camera}\n{base}\n{base.replace('/sdk/', '/usr/')}\n",
        ):
            with self.assertRaisesRegex(ValueError, "SDK loader resolution"):
                verify_loader(trace)

    def test_fixture_zero_or_incomplete_tests_fail(self):
        def result(run, passed, ignored=0, filtered=0, names=sorted(REQUIRED_TESTS)):
            rows = "".join(f"test {name} ... ok\n" for name in names)
            return (f"running {run} tests\n\n"
                    f"{rows}\n"
                    f"test result: ok. {passed} passed; 0 failed; {ignored} ignored; "
                    f"0 measured; {filtered} filtered out; finished in 0.00s\n")
        n = len(REQUIRED_TESTS)
        self.assertEqual(fixture_count(result(n, n)), n)
        for output in ("", result(0, 0), result(n, n - 1), result(n, n - 1, ignored=1),
                       result(n, n, filtered=1), result(n, n) * 2):
            with self.assertRaisesRegex(ValueError, "full fixture count"):
                fixture_count(output)

    def test_positive_stale_fixture_suite_fails(self):
        def success(names, count):
            rows = "".join(f"test {name} ... ok\n" for name in names)
            return (f"running {count} tests\n{rows}test result: ok. {count} passed; "
                    "0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n")
        only_ip3y = [n for n in REQUIRED_TESTS if n.startswith("ip3y_tests::")]
        wrong = sorted(REQUIRED_TESTS - {"journal_tests::child_exit_after_intent_keeps_attempt_closed"})
        wrong.append("journal_tests::something_else")
        for text in (success(only_ip3y, 3), success(wrong, len(REQUIRED_TESTS))):
            with self.assertRaisesRegex(ValueError, "exact Stage A fixture test set"):
                fixture_count(text)

    def test_executable_receipt_requires_the_same_bytes(self):
        with tempfile.TemporaryDirectory() as scratch:
            witness = Path(scratch) / "link-witness"
            witness.write_bytes(b"known fixture ELF bytes")
            witness.chmod(0o700)
            with self.assertRaisesRegex(ValueError, "missing executable build receipt"):
                verify_executable(witness)
            witness.with_suffix(".sha256").write_text(executable_receipt(witness))
            verify_executable(witness)
            witness.write_bytes(b"different same-named file")
            with self.assertRaisesRegex(ValueError, "build receipt mismatch"):
                verify_executable(witness)

    def test_subprocess_timeout_fails(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            sandbox_run(("/usr/bin/sleep", "2"), timeout=0.1)
