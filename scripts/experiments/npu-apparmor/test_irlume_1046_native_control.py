import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import irlume_1046_native_preflight as preflight

spec = importlib.util.spec_from_file_location(
    "native_control_guest", Path(__file__).with_name("irlume-1046-native-guest.py")
)
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class ControlAttributionTests(unittest.TestCase):
    def test_actual_process_id_is_used_when_worker_tid_differs(self):
        class ReachedNativeCase(Exception):
            pass

        journal = json.dumps(
            {
                "_TRANSPORT": "kernel",
                "MESSAGE": 'apparmor="DENIED" profile="irlumed" '
                'name="/opt/irlume-aa-denied" pid=1361 comm="onnx::npu_tests"',
            }
        )
        output = (
            "NATIVE_AA_DENIAL_CONTROL pid=1361 tid=1362\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            "415 filtered out; finished in 0.00s\n"
        )
        saved = {}

        def run(args, **_kwargs):
            if "--after-cursor" in args:
                return 0, journal
            if args[:2] == ["journalctl", "-n"]:
                return 0, json.dumps({"__CURSOR": "fixture"})
            return 0, ""

        with (
            patch.object(guest.shutil, "copyfile"),
            patch.object(guest, "save", side_effect=saved.__setitem__),
            patch.object(guest, "run", side_effect=run),
            patch.object(guest, "lost", return_value=0),
            patch.object(preflight, "guest_closure", return_value={}),
            patch.object(
                guest, "execute", side_effect=[(0, output), ReachedNativeCase]
            ),
            self.assertRaises(ReachedNativeCase),
        ):
            guest.case_run("bin-native", [])
        control = saved["bin-native-control.json"]
        self.assertEqual(control["pid"], 1361)
        self.assertEqual(control["tid"], 1362)
        self.assertEqual(len(control["denials"]), 1)


if __name__ == "__main__":
    unittest.main()
