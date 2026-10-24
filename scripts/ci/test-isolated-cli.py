#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Exercise namespace refusal paths without running an irlume binary."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("isolated_cli", HERE / "isolated-cli.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class IsolationTests(unittest.TestCase):
    def test_preflight_failure_retains_bounded_diagnostics(self):
        original = subprocess.run

        def refuse(command, *args, **kwargs):
            if Path(command[0]).name == "bwrap":
                return subprocess.CompletedProcess(command, 125, b"", b"synthetic denied" + b"x" * 20000)
            return original(command, *args, **kwargs)

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            runner.subprocess, "run", refuse
        ), self.assertRaisesRegex(RuntimeError, "synthetic denied") as failure:
            runner.run(Path(shutil.which("true")), None, [], Path(temporary) / "receipt.json")
        self.assertLess(len(str(failure.exception)), 4300)

    def test_sanitizer_policy_is_explicit_not_inherited(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"ASAN_OPTIONS": "UNTRUSTED-PARENT-VALUE"}
        ):
            result = runner.run(
                Path(shutil.which("env")), None, [], Path(temporary) / "receipt.json"
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn(b"ASAN_OPTIONS=detect_stack_use_after_return=1\n", result.stdout)
            self.assertNotIn(b"UNTRUSTED-PARENT-VALUE", result.stdout)

    def inject_mount(self, source, destination):
        original = subprocess.run

        def injected(command, *args, **kwargs):
            if Path(command[0]).name == "bwrap":
                command = list(command)
                command[command.index("--chdir"):command.index("--chdir")] = [
                    "--ro-bind", str(source), destination]
            return original(command, *args, **kwargs)

        return patch.object(runner.subprocess, "run", injected)

    def test_parent_stdin_cannot_reach_subject(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [sys.executable, str(HERE / "isolated-cli.py"), "--subject", shutil.which("cat"),
                 "--receipt", str(Path(temporary) / "receipt.json")],
                input=b"SYNTHETIC-STDIN-MUST-NOT-CROSS\n", capture_output=True, check=True,
                timeout=60,
            )
            self.assertEqual(result.stdout, b"")

    def test_positive_preflight_exposes_only_file_mounts(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            self.assertEqual(runner.run(Path(shutil.which("true")), None, [], path).returncode, 0)
            receipt = json.loads(path.read_text())
            self.assertTrue(all(receipt["preflight"].values()))
            for destination, entry in receipt["mounts"].items():
                # The temporary compiled probe was removed after execution.
                if destination != "/work/probe":
                    self.assertTrue(Path(entry["source"]).is_file())
                self.assertNotIn(destination, ["/", "/usr", "/lib", "/lib64", "/nix/store"])
                self.assertEqual(len(entry["sha256"]), 64)

    def test_populated_sysfs_refuses_subject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "synthetic").touch()
            with self.inject_mount(root, "/sys"), self.assertRaises(RuntimeError):
                runner.run(Path(shutil.which("true")), None, [], root / "receipt.json")

    def test_device_spelling_refuses_even_a_regular_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "video99"
            marker.touch()
            with self.inject_mount(marker, "/dev/video99"), self.assertRaises(RuntimeError):
                runner.run(Path(shutil.which("true")), None, [], root / "receipt.json")

    def test_writable_input_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"
            path.touch(mode=0o770)
            path.chmod(0o770)
            with self.assertRaises(ValueError):
                runner.checked_file(path)


if __name__ == "__main__":
    unittest.main()
