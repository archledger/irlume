"""Configuration and persistence failures must fail before camera access."""

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

import host


def config():
    asset = {"path": "/opt/irlume-eval/file", "sha256": "a" * 64}
    return {
        "schema": 1,
        "subject_uid": 1000,
        "budget_ms": 5000,
        "watchdog_seconds": 15,
        "assets": {
            key: dict(asset)
            for key in ["binary", "detector", "recognizer", "flir", "ort"]
        },
        "cameras": {
            "rgb": "/dev/video8",
            "ir": "/dev/video10",
            "metadata": "/dev/video11",
        },
        "protected_files": ["/etc/pam.d/irlume"],
        "service": "irlumed.service",
    }


class ConfigTests(unittest.TestCase):
    def test_explicit_non_default_camera_numbers_are_preserved(self):
        self.assertEqual(
            host.validate_config(config())["cameras"]["ir"], "/dev/video10"
        )

    def test_rejects_ambiguous_or_unpinned_configuration(self):
        for key, value in [
            ("budget_ms", True),
            ("budget_ms", 99),
            ("watchdog_seconds", 4),
            ("subject_uid", 0),
            ("service", "shell; command"),
            ("extra", "private"),
        ]:
            data = config()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                host.validate_config(data)
        for edit in ["hash", "node", "duplicate", "model", "protected", "path"]:
            data = config()
            if edit == "hash":
                data["assets"]["binary"]["sha256"] = "auto"
            if edit == "node":
                data["cameras"]["ir"] = "/dev/v4l/by-id/private"
            if edit == "duplicate":
                data["cameras"]["ir"] = data["cameras"]["rgb"]
            if edit == "model":
                del data["assets"]["flir"]
            if edit == "protected":
                data["protected_files"] = []
            if edit == "path":
                data["assets"]["binary"]["path"] = "relative"
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                host.validate_config(data)

    def test_topology_requires_metadata_sibling_and_separate_rgb(self):
        nodes = {
            "rgb": {
                "index": 0,
                "interface": "/sys/devices/usb1/1-2:1.0",
                "siblings": {"video8", "video9"},
            },
            "ir": {
                "index": 0,
                "interface": "/sys/devices/usb1/1-2:1.2",
                "siblings": {"video10", "video11"},
            },
            "metadata": {
                "index": 1,
                "interface": "/sys/devices/usb1/1-2:1.2",
                "siblings": {"video10", "video11"},
            },
        }
        self.assertTrue(host.qualified_topology(nodes, config()["cameras"]))
        for role, field, value in [
            ("metadata", "index", 0),
            ("metadata", "interface", "/wrong"),
            ("rgb", "interface", "/sys/devices/usb1/1-2:1.2"),
            ("ir", "siblings", {"video10", "video11", "video12"}),
            ("ir", "interface", "/sys/devices/virtual/camera"),
        ]:
            altered = copy.deepcopy(nodes)
            altered[role][field] = value
            self.assertFalse(host.qualified_topology(altered, config()["cameras"]))

    def test_strict_json_rejects_duplicate_keys(self):
        with self.assertRaises(ValueError):
            host.strict_json('{"schema": 1, "schema": 1}')


class LedgerTests(unittest.TestCase):
    def test_started_record_survives_failure_without_final(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = host.Ledger(Path(tmp))
            attempt = ledger.reserve("a01", "genuine", "development", "a" * 64)
            self.assertEqual(
                json.loads((attempt / "started.json").read_text())["mode"], "genuine"
            )
            with self.assertRaises(ValueError):
                ledger.reserve("a02", "genuine", "development", "a" * 64)
            self.assertFalse((attempt / "final.json").exists())

    def test_exclusive_results_and_persistent_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = host.Ledger(Path(tmp))
            attempt = ledger.reserve("a01", "attack", "pilot", "a" * 64)
            ledger.finish(attempt, {"status": "stopped", "stop_required": True})
            self.assertEqual(
                json.loads((attempt / "final.json").read_text())["status"], "stopped"
            )
            with self.assertRaises((ValueError, FileExistsError)):
                ledger.finish(attempt, {"status": "ok"})
            with self.assertRaises(ValueError):
                ledger.reserve("a02", "attack", "pilot", "a" * 64)
            self.assertEqual((attempt / "final.json").stat().st_mode & 0o777, 0o600)

    def test_symlink_attempt_or_unexpected_ledger_content_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a01").symlink_to("/tmp")
            with self.assertRaises(ValueError):
                host.Ledger(Path(tmp)).reserve("a02", "genuine", "pilot", "a" * 64)

    def test_successful_attempt_allows_next_but_never_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = host.Ledger(Path(tmp))
            attempt = ledger.reserve("a01", "genuine", "pilot", "a" * 64)
            ledger.finish(attempt, {"status": "complete", "stop_required": False})
            self.assertTrue(
                ledger.reserve("a02", "genuine", "pilot", "a" * 64).exists()
            )
            with self.assertRaises((ValueError, FileExistsError)):
                ledger.reserve("a01", "genuine", "pilot", "a" * 64)


if __name__ == "__main__":
    unittest.main()


class TrustTests(unittest.TestCase):
    def test_intermediate_untrusted_symlink_is_not_hidden_by_safe_final_target(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "file").write_text("fixture")
            (base / "hop").symlink_to(base / "file")
            (base / "entry").symlink_to(base / "hop")
            original = Path.lstat

            def metadata(path, *args, **kwargs):
                info = list(original(path, *args, **kwargs))
                info[0] &= ~0o022
                info[4] = 123 if path == base / "hop" else 0
                return os.stat_result(info)

            with patch.object(Path, "lstat", metadata), self.assertRaises(ValueError):
                host.trusted_path(base / "entry")


class SecurityContextTests(unittest.TestCase):
    def test_host_without_context_provider_can_be_preserved(self):
        import errno
        from unittest.mock import patch

        process = Path("/proc/123")
        original = Path.read_text
        with tempfile.TemporaryDirectory() as tmp:
            lsm = Path(tmp) / "lsm"
            lsm.write_text("capability,landlock,lockdown,yama,bpf\n")

            def read(path, *args, **kwargs):
                if path == process / "attr/current":
                    raise OSError(errno.EINVAL, "fixture")
                return original(path, *args, **kwargs)

            with patch.object(Path, "read_text", read):
                got = host.security_state(process, lsm)
            self.assertEqual(
                got,
                {"modules": "capability,landlock,lockdown,yama,bpf", "context": None},
            )

    def test_permission_missing_or_unknown_context_support_stays_fatal(self):
        import errno
        from unittest.mock import patch

        process = Path("/proc/123")
        original = Path.read_text
        with tempfile.TemporaryDirectory() as tmp:
            lsm = Path(tmp) / "lsm"
            for modules, error in [
                ("capability,yama", errno.EACCES),
                ("capability,yama", errno.ENOENT),
                ("capability,selinux", errno.EINVAL),
                ("capability,apparmor", errno.EINVAL),
                ("capability,future_lsm", errno.EINVAL),
                ("", errno.EINVAL),
            ]:
                lsm.write_text(modules)

                def read(path, *args, failure=error, **kwargs):
                    if path == process / "attr/current":
                        raise OSError(failure, "fixture")
                    return original(path, *args, **kwargs)

                with (
                    self.subTest(modules=modules, error=error),
                    patch.object(Path, "read_text", read),
                    self.assertRaises((OSError, ValueError)),
                ):
                    host.security_state(process, lsm)

    def test_available_label_and_module_changes_remain_distinguishable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "attr").mkdir()
            ctx = root / "attr/current"
            lsm = root / "lsm"
            lsm.write_text("capability,selinux")
            ctx.write_text("system_u:system_r:fixture_t:s0\n")
            before = host.security_state(root, lsm)
            self.assertEqual(
                before,
                {
                    "modules": "capability,selinux",
                    "context": "system_u:system_r:fixture_t:s0",
                },
            )
            ctx.write_text("system_u:system_r:changed_t:s0")
            self.assertNotEqual(before, host.security_state(root, lsm))
            ctx.write_text("system_u:system_r:fixture_t:s0")
            lsm.write_text("capability,yama,selinux")
            self.assertNotEqual(before, host.security_state(root, lsm))
