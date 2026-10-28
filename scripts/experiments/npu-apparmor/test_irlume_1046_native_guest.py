import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "native_guest", Path(__file__).with_name("irlume-1046-native-guest.py")
)
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class GuestBoundaryTests(unittest.TestCase):
    def test_control_attribution_failure_stops_before_native_execution(self):
        def denial(pid, profile="irlumed"):
            return json.dumps(
                {
                    "_TRANSPORT": "kernel",
                    "MESSAGE": f'apparmor="DENIED" profile="{profile}" pid={pid} name="/opt/irlume-aa-denied"',
                }
            )

        # The kernel PID is the process TGID (123), not the worker TID (124).
        for journal in (denial(124), denial(123) + "\n" + denial(123, "other")):

            def command(args, _journal=journal, **_kwargs):
                if args[0] == "journalctl" and "-n" in args:
                    return 0, '{"__CURSOR":"start"}'
                if args[0] == "journalctl" and "--after-cursor" in args:
                    return 0, _journal
                return 0, "expanded policy"

            output = "NATIVE_AA_DENIAL_CONTROL pid=123 tid=124\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
            with (
                self.subTest(journal=journal),
                patch("irlume_1046_native_preflight.guest_closure", return_value={}),
                patch.object(guest.shutil, "copyfile"),
                patch.object(guest, "run", side_effect=command),
                patch.object(guest, "save"),
                patch.object(guest, "lost", return_value=0),
                patch.object(guest, "execute", return_value=(0, output)) as execute,
                self.assertRaisesRegex(ValueError, "unrelated AppArmor denial"),
            ):
                guest.case_run("bin-native", [])
            execute.assert_called_once()

    def test_wrong_host_refuses_before_install(self):
        with (
            patch.object(guest.os, "geteuid", return_value=0),
            patch.object(guest.platform, "node", return_value="production"),
            patch.object(
                guest, "install", side_effect=AssertionError("must not install")
            ),
            self.assertRaisesRegex(RuntimeError, "named guest"),
        ):
            guest.main()

    def test_unprivileged_caller_refuses_before_install(self):
        with (
            patch.object(guest.os, "geteuid", return_value=1000),
            patch.object(
                guest, "install", side_effect=AssertionError("must not install")
            ),
            self.assertRaisesRegex(RuntimeError, "named guest"),
        ):
            guest.main()

    def test_capture_retains_the_real_nonzero_exit(self):
        code, text = guest.run(
            [sys.executable, "-c", 'print("evidence"); raise SystemExit(3)'],
            check=False,
        )
        self.assertEqual((code, text), (3, "evidence\n"))

    def test_output_bound_refuses_and_retains_bounded_diagnostic(self):
        with self.assertRaisesRegex(RuntimeError, "output bound"):
            guest.run([sys.executable, "-c", 'print("x" * 1000)'], maximum=64)
        self.assertEqual(len(guest.last_output), 64)

    def test_deadline_refuses_and_reaps_child(self):
        with self.assertRaises(TimeoutError):
            guest.run(
                [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.1
            )


if __name__ == "__main__":
    unittest.main()
