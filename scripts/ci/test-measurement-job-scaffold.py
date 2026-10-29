#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Predeclared systemd root layout, with no real service or mount operations."""

import copy
import hashlib
import importlib.util
import stat
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCAFFOLD = ("bin", "dev", "etc", "proc", "root", "run", "sys", "tmp", "var")
API_ROOTS = ("dev", "proc", "run", "sys", "tmp")


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preparation = load("scaffold_preparation", "test-measurement-job-prepare-runtime.py")
root_tests = load("scaffold_roots", "test-measurement-job-root.py")
tree_tests = load("scaffold_tree", "test-measurement-job-runtime-tree.py")
bus_tests = load("scaffold_bus", "test-measurement-job-rooted-bus.py")


def add_scaffold(manifest):
    existing = {row["path"] for row in manifest["members"]}
    manifest["members"].extend(
        {"path": name, "kind": "directory", "mode": 0o500}
        for name in SCAFFOLD
        if name not in existing
    )
    manifest["members"].sort(key=lambda row: row["path"])


class ScaffoldTests(unittest.TestCase):
    def test_ci_requires_scaffold_contract_without_a_skip_or_failure_override(self):
        import yaml

        workflow = yaml.safe_load(
            (HERE.parents[1] / ".github/workflows/ci.yml").read_text()
        )
        steps = workflow["jobs"]["check"]["steps"]
        selected = [
            step
            for step in steps
            if step.get("name") == "Contained-job rooted scaffold contracts"
        ]
        self.assertEqual(len(selected), 1)
        step = selected[0]
        self.assertEqual(
            step["run"].strip(),
            "python3 -B -X pycache_prefix=/dev/null scripts/ci/test-measurement-job-scaffold.py",
        )
        self.assertNotIn("if", step)
        self.assertFalse(step.get("continue-on-error", False))
        self.assertEqual(step["timeout-minutes"], 2)

    def test_preparation_declares_empty_readonly_scaffold_before_freezing(self):
        fixture = preparation.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        data, digest = fixture.run_prepare()
        manifest = preparation.prepare.closure.decode_manifest(data, digest)
        members = {row["path"]: row for row in manifest["members"]}
        for name in SCAFFOLD:
            with self.subTest(name=name):
                self.assertIn(name, members)
                self.assertEqual(
                    members[name],
                    {"path": name, "kind": "directory", "mode": 0o500},
                )
                directory = fixture.destination / name
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o500)
                self.assertFalse(directory.is_symlink())
                self.assertEqual(list(directory.iterdir()), [])

    def test_preparation_rejects_python_roots_beneath_empty_scaffold(self):
        fixture = preparation.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for name in SCAFFOLD:
            with self.subTest(name=name):
                profile = copy.deepcopy(fixture.profile)
                profile["python"]["roots"].append(name + "/hidden")
                with self.assertRaises(ValueError):
                    preparation.prepare.freeze_selection(profile, fixture.selection)
                self.assertFalse(fixture.destination.exists())

    def test_rooted_selection_accepts_exact_directory_only_scaffold(self):
        root = root_tests.root
        plan, data = root_tests.selection()
        manifest = root.runtime._json(data)
        add_scaffold(manifest)
        data = root.closure.canonical(manifest)
        plan["manifest"]["sha256"] = hashlib.sha256(data).hexdigest()
        self.assertEqual(root.check_selection(plan, data), manifest)

    def test_rooted_selection_rejects_static_payload_under_any_scaffold(self):
        root = root_tests.root
        for name in SCAFFOLD:
            with self.subTest(name=name):
                plan, data = root_tests.selection()
                manifest = root.runtime._json(data)
                add_scaffold(manifest)
                manifest["members"].append(
                    {
                        "path": name + "/hidden.py",
                        "kind": "file",
                        "mode": 0o400,
                        "size": 0,
                        "sha256": hashlib.sha256(b"").hexdigest(),
                    }
                )
                manifest["members"].sort(key=lambda row: row["path"])
                data = root.closure.canonical(manifest)
                plan["manifest"]["sha256"] = hashlib.sha256(data).hexdigest()
                with self.assertRaises(ValueError):
                    root.check_selection(plan, data)

    def test_api_mounts_cannot_become_python_import_roots(self):
        root = root_tests.root
        for name in API_ROOTS:
            with self.subTest(name=name):
                plan, data = root_tests.selection()
                manifest = root.runtime._json(data)
                add_scaffold(manifest)
                manifest["python"]["roots"] = [manifest["python"]["roots"][0], name]
                data = root.closure.canonical(manifest)
                plan["manifest"]["sha256"] = hashlib.sha256(data).hexdigest()
                with self.assertRaises(ValueError):
                    root.check_selection(plan, data)

    def test_every_scaffold_directory_is_required_before_bus_creation(self):
        fixture = bus_tests.BridgeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        root = fixture.fixture.root
        protocol = bus_tests.protocol_tests.protocol
        for name in SCAFFOLD:
            with self.subTest(name=name):
                manifest = root.runtime._json(fixture.fixture.manifest)
                add_scaffold(manifest)
                manifest["members"] = [
                    row for row in manifest["members"] if row["path"] != name
                ]
                manifest_data = root.closure.canonical(manifest)
                config = root.runtime._json(fixture.fixture.config.data)
                config["root_plan"]["manifest"]["sha256"] = hashlib.sha256(
                    manifest_data
                ).hexdigest()
                config_data = root.closure.canonical(config)
                selected = protocol.Configuration(
                    config_data, hashlib.sha256(config_data).hexdigest()
                )
                bridge = bus_tests.bridge.RootedBus(fixture.bus, fixture.support)
                with self.assertRaises(ValueError):
                    bridge.start(selected, manifest_data, 1000)
                self.assertFalse(bridge.creation_attempted)
                self.assertEqual(fixture.bus.calls, [])

    def test_host_recheck_keeps_original_empty_directory_baseline(self):
        for name in SCAFFOLD:
            for mutation in ("file", "mode", "replace", "symlink"):
                with self.subTest(name=name, mutation=mutation):
                    fixture = preparation.PreparationTests()
                    fixture.setUp()
                    try:
                        data, digest = fixture.run_prepare()
                        closure = preparation.prepare.closure
                        with closure.RuntimeSnapshot.open(
                            fixture.destination,
                            data,
                            digest,
                            deadline=time.monotonic_ns() + 5_000_000_000,
                        ) as snapshot:
                            baseline = copy.deepcopy(snapshot.observations)
                            path = fixture.destination / name
                            if mutation == "file":
                                path.chmod(0o700)
                                (path / "unlisted").write_bytes(b"unexpected")
                                path.chmod(0o500)
                            elif mutation == "mode":
                                path.chmod(0o700)
                            else:
                                fixture.destination.chmod(0o700)
                                path.chmod(0o700)
                                path.rename(fixture.base / "original-directory")
                                if mutation == "replace":
                                    path.mkdir(mode=0o500)
                                else:
                                    path.symlink_to("opt")
                                fixture.destination.chmod(0o500)
                            with self.assertRaises(ValueError):
                                snapshot.recheck(time.monotonic_ns() + 5_000_000_000)
                            self.assertEqual(snapshot.observations, baseline)
                    finally:
                        fixture.doCleanups()

    def test_mounted_view_projects_only_exact_declared_api_directories(self):
        fixture = tree_tests.RootedTreeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.path.chmod(0o700)
        for name in SCAFFOLD:
            (fixture.path / name).mkdir(mode=0o500, exist_ok=True)
        fixture.path.chmod(0o500)
        add_scaffold(fixture.manifest)
        fixture.data = tree_tests.rooted.closure.canonical(fixture.manifest)
        fixture.plan["manifest"]["sha256"] = hashlib.sha256(fixture.data).hexdigest()
        expected = copy.deepcopy(fixture.manifest)
        with fixture.open() as snapshot:
            snapshot.check()
            self.assertEqual(snapshot.manifest, expected)
            self.assertFalse(
                any(path.startswith("/proc/") for path in snapshot.file_facts())
            )

    def test_mounted_view_still_checks_non_api_scaffold_directories(self):
        for name in ("bin", "etc", "root", "var"):
            for mutation in ("missing", "mode", "file"):
                with self.subTest(name=name, mutation=mutation):
                    fixture = tree_tests.RootedTreeTests()
                    fixture.setUp()
                    try:
                        path = fixture.path / name
                        if mutation == "missing":
                            fixture.path.chmod(0o700)
                            path.rmdir()
                            fixture.path.chmod(0o500)
                        elif mutation == "mode":
                            path.chmod(0o700)
                        else:
                            path.chmod(0o700)
                            (path / "unexpected").write_bytes(b"unlisted")
                            path.chmod(0o500)
                        with self.assertRaises(ValueError), fixture.open():
                            pass
                    finally:
                        fixture.doCleanups()

    def test_scaffold_manifest_does_not_bypass_core_mount_validation(self):
        fixture = tree_tests.RootedTreeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for path in (b"/dev", b"/proc", b"/run", b"/sys", b"/tmp"):
            with self.subTest(missing_mount=path):
                core = copy.deepcopy(fixture.core)
                lines = core["mountinfo"].splitlines()
                remaining = [line for line in lines if line.split()[4] != path]
                self.assertEqual(len(remaining), len(lines) - 1)
                core["mountinfo"] = b"\n".join(remaining) + b"\n"
                with self.assertRaises(ValueError), fixture.open(core=core):
                    pass
        for mutation in ("writable_dev", "wrong_proc_type", "extra_run_entry"):
            with self.subTest(mutation=mutation):
                core = copy.deepcopy(fixture.core)
                if mutation == "writable_dev":
                    old = core["mountinfo"]
                    core["mountinfo"] = old.replace(b"/dev ro,", b"/dev rw,")
                    self.assertNotEqual(old, core["mountinfo"])
                elif mutation == "wrong_proc_type":
                    old = core["mountinfo"]
                    core["mountinfo"] = old.replace(b" - proc ", b" - ext4 ")
                    self.assertNotEqual(old, core["mountinfo"])
                else:
                    core["run_entries"] += ("/run/unexpected",)
                with self.assertRaises(ValueError), fixture.open(core=core):
                    pass


if __name__ == "__main__":
    unittest.main()
