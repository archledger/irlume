import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from run_isolated import fixture_count, sandbox_run, verify_loader


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
        def result(run, passed, ignored=0, filtered=0):
            return (f"running {run} tests\n\n"
                    f"test result: ok. {passed} passed; 0 failed; {ignored} ignored; "
                    f"0 measured; {filtered} filtered out; finished in 0.00s\n")
        self.assertEqual(fixture_count(result(14, 14)), 14)
        for output in ("", result(0, 0), result(14, 13), result(14, 13, ignored=1),
                       result(14, 14, filtered=1), result(14, 14) * 2):
            with self.assertRaisesRegex(ValueError, "full fixture count"):
                fixture_count(output)

    def test_subprocess_timeout_fails(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            sandbox_run(("/usr/bin/sleep", "2"), timeout=0.1)
