import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from irlume_1046_native_protocol import power_mode_valid, scope_binding_matches

spec = importlib.util.spec_from_file_location(
    "restored_native_host", Path(__file__).with_name("irlume-1046-native-host-v4.py")
)
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class RestoredRegressionTests(unittest.TestCase):
    def test_current_valid_power_policy_can_be_preserved(self):
        self.assertTrue(power_mode_valid("on"))
        self.assertTrue(power_mode_valid("auto"))
        for value in ("", "unknown", "AUTO", None, True):
            self.assertFalse(power_mode_valid(value))

    def test_scope_binding_uses_typed_names_not_display_quoting(self):
        name = r"machine-qemu\x2d1\x2dirlume.scope"
        self.assertTrue(scope_binding_matches(name, [name]))
        self.assertFalse(
            scope_binding_matches(name, '"' + name.replace("\\", "\\\\") + '"')
        )
        self.assertFalse(scope_binding_matches(name, ["other.scope"]))

    def test_timer_admission_uses_typed_dependencies(self):
        scope = r"machine-qemu\x2d1\x2dirlume.scope"
        witness = {
            "scope": scope,
            "invocation": "a" * 32,
            "cgroup": "/machine.slice/owned.scope",
        }

        def properties(name):
            if name == scope:
                return {
                    "ActiveState": "active",
                    "InvocationID": "a" * 32,
                    "ControlGroup": witness["cgroup"],
                }
            return {"ActiveState": "active", "BindsTo": '"' + scope + '"'}

        def command(args, **_kwargs):
            if "GetUnit" in args:
                return json.dumps({"data": ["/unit/timer"]})
            if "BindsTo" in args:
                return json.dumps({"data": [scope]})
            if "NextElapseUSecMonotonic" in args:
                return json.dumps({"data": 300_000_000})
            return ""

        with (
            patch.object(host.time, "monotonic", return_value=100),
            patch.object(host, "properties", side_effect=properties),
            patch.object(host, "run", side_effect=command),
        ):
            self.assertEqual(host.arm_scope_stop(witness, 350), 300_000_000)

    def test_restored_pci_alias_is_compared_canonically(self):
        class ReachedDeviceOpen(Exception):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "sys-device"
            real.mkdir()
            driver = root / "intel_vpu"
            driver.mkdir()
            (real / "driver").symlink_to(driver)
            pci_alias = root / "pci-address"
            pci_alias.symlink_to(real)
            accel_alias = root / "accel-device"
            accel_alias.symlink_to(real)

            def mapped_path(value):
                return (
                    accel_alias
                    if value == "/sys/class/accel/accel0/device"
                    else Path(value)
                )

            with (
                patch.object(host, "NPU", pci_alias),
                patch.object(host, "Path", side_effect=mapped_path),
                patch.object(host.os, "uname") as uname,
                patch.object(host.os, "open", side_effect=ReachedDeviceOpen),
                self.assertRaises(ReachedDeviceOpen),
            ):
                uname.return_value.nodename = "UX5406S-Fedora"
                host.query_restored()


if __name__ == "__main__":
    unittest.main()
