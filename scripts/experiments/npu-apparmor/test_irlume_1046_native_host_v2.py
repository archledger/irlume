import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "native_host_v4", Path(__file__).with_name("irlume-1046-native-host-v4.py")
)
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class HostV2Tests(unittest.TestCase):
    def setUp(self):
        host.TRACE.clear()
        self.witness = {
            "scope": "machine-owned.scope",
            "invocation": "a" * 32,
            "cgroup": "/machine.slice/owned.scope",
        }

    def test_wrong_host_refuses_before_any_privileged_command(self):
        with (
            patch.object(host.os, "uname") as uname,
            patch.object(host, "run", side_effect=AssertionError("must not run")),
            self.assertRaisesRegex(RuntimeError, "approved host"),
        ):
            uname.return_value.nodename = "other"
            host.start()

    def test_changed_scope_incarnation_is_not_killed(self):
        with (
            patch.object(
                host,
                "properties",
                return_value={
                    "ActiveState": "active",
                    "InvocationID": "b" * 32,
                    "ControlGroup": self.witness["cgroup"],
                },
            ),
            patch.object(host, "run") as command,
            self.assertRaisesRegex(RuntimeError, "another scope"),
        ):
            host.stop_owned_scope(self.witness)
        command.assert_not_called()

    def test_only_verified_owned_scope_is_killed(self):
        with (
            patch.object(
                host,
                "properties",
                return_value={
                    "ActiveState": "active",
                    "InvocationID": "a" * 32,
                    "ControlGroup": self.witness["cgroup"],
                },
            ),
            patch.object(host, "run") as command,
        ):
            host.stop_owned_scope(self.witness)
        command.assert_called_once_with(
            [
                "/usr/bin/systemctl",
                "kill",
                "--kill-whom=all",
                "--signal=SIGKILL",
                "machine-owned.scope",
            ],
            root=True,
        )

    def test_ambiguous_creation_attempts_observed_teardown(self):
        record = {"creation_sent": True, "creation_acknowledged": False}
        with (
            patch.object(host, "run", return_value="123"),
            patch.object(host, "get_machine", return_value=self.witness) as observe,
            patch.object(host, "stop_owned_scope") as stop,
        ):
            self.assertEqual(host.recover_observed_scope(None, record), self.witness)
        observe.assert_called_once_with(123, require_limits=False)
        stop.assert_called_once_with(self.witness)
        self.assertFalse(record["creation_acknowledged"])

    def test_unowned_late_process_is_not_killed(self):
        record = {"creation_sent": True}
        with (
            patch.object(host, "run", return_value="123"),
            patch.object(host, "get_machine", side_effect=ValueError("wrong UUID")),
            patch.object(host, "stop_owned_scope") as stop,
        ):
            self.assertIsNone(host.recover_observed_scope(None, record))
        stop.assert_not_called()
        self.assertIn("wrong UUID", record["late_ownership_error"])

    def test_command_failure_keeps_stdout_and_stderr(self):
        value = subprocess.CompletedProcess(
            ["fake"], 1, "partial output", "specific failure"
        )
        with (
            patch.object(host.subprocess, "run", return_value=value),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            host.run(["fake"])
        self.assertEqual(host.TRACE[-1]["stdout"]["tail"], "partial output")
        self.assertEqual(host.TRACE[-1]["stderr"]["tail"], "specific failure")

    def test_command_timeout_keeps_partial_diagnostics(self):
        with (
            patch.object(
                host.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(
                    ["fake"], 1, output=b"partial", stderr=b"blocked"
                ),
            ),
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            host.run(["fake"])
        self.assertTrue(host.TRACE[-1]["timeout"])
        self.assertEqual(host.TRACE[-1]["stderr"]["tail"], "blocked")

    def test_unknown_control_group_is_rejected(self):
        with self.assertRaises(RuntimeError):
            host.cgroup_empty("/tmp/other")


if __name__ == "__main__":
    unittest.main()
