#!/usr/bin/env python3
"""Exercise disposable TPM lifecycle without touching a hardware TPM."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("with-swtpm.sh").resolve()


class DisposableTpmTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="irlume-swtpm-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = dict(os.environ, TMPDIR=str(self.root), IRLUME_TCTI="device:/dev/tpmrm0")
        self.env.pop("IRLUME_SWTPM_PORT", None)

    def run_wrapper(self, command, env=None):
        return subprocess.run(["/bin/bash", str(SCRIPT), *command], env=env or self.env,
                              text=True, capture_output=True, timeout=15)

    def assert_clean(self, pid=None):
        self.assertEqual(list(self.root.iterdir()), [])
        if pid is not None:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_requires_command(self):
        result = self.run_wrapper([])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Usage:", result.stderr)
        self.assert_clean()

    def test_missing_emulator_never_runs_command(self):
        result = self.run_wrapper([sys.executable, "-c", "print('UNEXPECTED')"],
                                  dict(self.env, PATH="/nonexistent"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("swtpm", result.stderr)
        self.assertNotIn("UNEXPECTED", result.stdout)
        self.assert_clean()

    def test_success_and_failure_preserve_status_and_cleanup(self):
        for status in (0, 23):
            with self.subTest(status=status):
                probe = """import json,os,pathlib,sys
root=pathlib.Path(os.environ['TMPDIR'])
states=list(root.glob('irlume-swtpm.*'))
assert len(states)==1, states
pid=int((states[0]/'pid').read_text())
os.kill(pid,0)
print(json.dumps({'tcti':os.environ['IRLUME_TCTI'],'pid':pid}))
sys.exit(int(sys.argv[1]))
"""
                result = self.run_wrapper([sys.executable, "-c", probe, str(status)])
                self.assertEqual(result.returncode, status, result.stderr)
                observation = json.loads(result.stdout)
                self.assertRegex(observation["tcti"], r"^swtpm:host=127\.0\.0\.1,port=[0-9]+$")
                self.assert_clean(observation["pid"])

    def test_occupied_port_never_runs_command_or_stops_existing_listener(self):
        for control_port in (False, True):
            with self.subTest(control_port=control_port), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                occupied = listener.getsockname()[1]
                port = occupied - 1 if control_port else occupied
                result = self.run_wrapper([sys.executable, "-c", "print('UNEXPECTED')"],
                                          dict(self.env, IRLUME_SWTPM_PORT=str(port)))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("UNEXPECTED", result.stdout)
                # Still a functioning listener, not just a surviving descriptor.
                with socket.create_connection(("127.0.0.1", occupied), timeout=1):
                    peer, _ = listener.accept()
                    peer.close()
                self.assert_clean()

    def test_invalid_port_never_runs_command(self):
        for value in ("0", "65535", "abc", "2321,host=elsewhere"):
            with self.subTest(value=value):
                result = self.run_wrapper([sys.executable, "-c", "print('UNEXPECTED')"],
                                          dict(self.env, IRLUME_SWTPM_PORT=value))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("UNEXPECTED", result.stdout)
                self.assert_clean()


if __name__ == "__main__":
    unittest.main()
