#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Offline regression checks for the hosted runner's APT mirror selection."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/prefer-ubuntu-archive.py"
MIRRORS = (
    "http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n"
    "https://archive.ubuntu.com/ubuntu/\tpriority:2\n"
    "https://security.ubuntu.com/ubuntu/\tpriority:3\n"
)


class MirrorSelectionTests(unittest.TestCase):
    def policy(self, text):
        self.assertTrue(SCRIPT.is_file(), "the mirror policy script must exist")
        spec = importlib.util.spec_from_file_location("prefer_ubuntu_archive", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.without_azure_mirror(text)

    def run_cli(self, path):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), str(path)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_removes_only_the_azure_entry(self):
        self.assertEqual(self.policy(MIRRORS), "".join(MIRRORS.splitlines(keepends=True)[1:]))

    def test_https_and_trailing_slash_variants_are_removed(self):
        text = MIRRORS.replace("http://azure", "https://azure").replace(
            "azure.archive.ubuntu.com/ubuntu/", "azure.archive.ubuntu.com/ubuntu"
        )
        self.assertEqual(self.policy(text), self.policy(MIRRORS))

    def test_comments_blank_lines_and_other_entries_are_preserved(self):
        extra = "# original image list\n\nhttps://mirror.example/ubuntu/\tpriority:4\n"
        self.assertEqual(self.policy(extra + MIRRORS), extra + self.policy(MIRRORS))

    def test_an_already_selected_archive_is_unchanged(self):
        text = "".join(MIRRORS.splitlines(keepends=True)[1:])
        self.assertEqual(self.policy(text), text)

    def test_archive_must_be_an_active_https_entry(self):
        for text in [
            "http://azure.archive.ubuntu.com/ubuntu/\n",
            "https://security.ubuntu.com/ubuntu/\n",
            "# https://archive.ubuntu.com/ubuntu/\n" + MIRRORS.splitlines()[0],
            MIRRORS.replace("https://archive.ubuntu.com", "http://archive.ubuntu.com"),
        ]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.policy(text)

    def test_similar_host_names_are_not_the_azure_entry(self):
        extra = "https://azure.archive.ubuntu.com.example/ubuntu/\tpriority:4\n"
        self.assertEqual(self.policy(MIRRORS + extra), self.policy(MIRRORS) + extra)

    def test_cli_preserves_mode_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mirrors.txt"
            path.write_text(MIRRORS)
            path.chmod(0o640)
            self.assertEqual(self.run_cli(path).returncode, 0)
            self.assertEqual(path.read_text(), self.policy(MIRRORS))
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            before = path.stat().st_mtime_ns
            self.assertEqual(self.run_cli(path).returncode, 0)
            self.assertEqual(path.stat().st_mtime_ns, before)

    def test_invalid_list_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mirrors.txt"
            text = MIRRORS.splitlines()[0] + "\n"
            path.write_text(text)
            self.assertNotEqual(self.run_cli(path).returncode, 0)
            self.assertEqual(path.read_text(), text)

    def test_links_and_missing_files_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mirrors.txt"
            target = Path(temp) / "target.txt"
            target.write_text(MIRRORS)
            path.symlink_to(target)
            self.assertNotEqual(self.run_cli(path).returncode, 0)
            self.assertEqual(target.read_text(), MIRRORS)
            missing = Path(temp) / "missing.txt"
            self.assertNotEqual(self.run_cli(missing).returncode, 0)
            self.assertFalse(missing.exists())

    def test_workflow_selects_the_mirror_before_installing_packages(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        job = workflow["jobs"]["check"]
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
        self.assertNotIn("continue-on-error", job)
        steps = job["steps"]
        policy_steps = [
            i for i, step in enumerate(steps)
            if "sudo python3 scripts/ci/prefer-ubuntu-archive.py" in step.get("run", "")
        ]
        self.assertEqual(len(policy_steps), 1, "one mandatory mirror-selection step")
        policy = policy_steps[0]
        self.assertNotIn("if", steps[policy])
        self.assertNotIn("continue-on-error", steps[policy])
        apt_steps = [i for i, step in enumerate(steps) if "apt-get" in step.get("run", "")]
        self.assertTrue(apt_steps)
        self.assertLess(policy, min(apt_steps))
        self.assertTrue(any(
            "python3 -B scripts/ci/test-prefer-ubuntu-archive.py" in step.get("run", "")
            for step in steps
        ), "the offline contract tests must run in CI")


if __name__ == "__main__":
    unittest.main()
