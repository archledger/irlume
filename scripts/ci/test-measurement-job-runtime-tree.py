#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Rooted static-tree verification in ordinary temporary directories only."""

import contextlib
import copy
import hashlib
import importlib.util
import os
import tempfile
import time
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rooted = load("rooted_runtime", "measurement-job-runtime-tree.py")
fixtures = load("rooted_fixtures", "test-measurement-job-closure.py")
core_fixtures = load("rooted_core_fixtures", "test-measurement-job-root.py")


class RootedTreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "root"
        self.path.mkdir()
        self.manifest, files = fixtures.manifest()
        old = self.manifest["python"]["entry"]
        new = "opt/irlume/measurement-job-guardian-native.py"
        self.manifest["python"]["entry"] = new
        files[new] = files.pop(old)
        for row in self.manifest["members"]:
            if row["path"] == old:
                row["path"] = new
        self.manifest["members"].sort(key=lambda row: row["path"])
        for row in self.manifest["members"]:
            path = self.path / row["path"]
            if row["kind"] == "directory":
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.write_bytes(files[row["path"]])
                path.chmod(row["mode"])
        for row in reversed(self.manifest["members"]):
            if row["kind"] == "directory":
                (self.path / row["path"]).chmod(row["mode"])
        for name in ("dev", "proc", "sys", "run", "tmp"):
            (self.path / name).mkdir(mode=0o500)
        self.path.chmod(0o500)
        self.data = rooted.closure.canonical(self.manifest)
        self.plan, _ = core_fixtures.selection()
        info = self.path.stat()
        self.plan["root"].update(device=info.st_dev, inode=info.st_ino)
        self.plan["manifest"]["sha256"] = hashlib.sha256(self.data).hexdigest()
        self.core = core_fixtures.witness(self.plan)
        self.core["root"] = {"device": info.st_dev, "inode": info.st_ino}
        now = time.monotonic_ns()
        self.core.update(started_ns=now, finished_ns=now)
        self.acquired = []

    @contextlib.contextmanager
    def open(self, core=None, plan=None, deadline=None):
        real_open, real_stat = os.open, os.stat

        def open_root(path, *args, **kwargs):
            fd = real_open(self.path if path == "/" else path, *args, **kwargs)
            if path == "/":
                self.acquired.append(fd)
            return fd

        def stat_root(path, *args, **kwargs):
            return real_stat(self.path if path == "/" else path, *args, **kwargs)

        with (
            mock.patch.object(rooted.os, "open", side_effect=open_root),
            mock.patch.object(rooted.os, "stat", side_effect=stat_root),
            rooted.RootedRuntimeSnapshot.open(
                plan or self.plan,
                self.data,
                core or self.core,
                deadline=deadline
                if deadline is not None
                else self.core["started_ns"] + 5_000_000_000,
            ) as snapshot,
        ):
            yield snapshot

    def test_selected_static_members_are_hashed_and_api_directories_are_excluded(self):
        with self.open() as snapshot:
            facts = snapshot.file_facts()
            path = "/" + self.manifest["python"]["entry"]
            self.assertEqual(
                facts[path]["sha256"],
                next(
                    row["sha256"]
                    for row in self.manifest["members"]
                    if row["path"] == path[1:]
                ),
            )
            self.assertFalse(any(name.startswith("/proc/") for name in facts))
            for name, fact in facts.items():
                info = (self.path / name[1:]).stat()
                self.assertEqual(
                    (fact["device"], fact["inode"], fact["mode"], fact["size"]),
                    (info.st_dev, info.st_ino, info.st_mode, info.st_size),
                )

    def test_unknown_static_file_and_changed_file_bytes_refuse(self):
        self.path.chmod(0o700)
        (self.path / "unexpected").write_bytes(b"bad")
        self.path.chmod(0o500)
        with self.assertRaises(ValueError), self.open():
            pass
        self.path.chmod(0o700)
        (self.path / "unexpected").unlink()
        path = self.path / self.manifest["python"]["entry"]
        path.chmod(0o600)
        path.write_bytes(b"changed\n")
        path.chmod(0o400)
        self.path.chmod(0o500)
        with self.assertRaises(ValueError), self.open():
            pass

    def test_api_name_must_be_a_directory_and_must_exist(self):
        for name in ("dev", "proc", "sys", "run", "tmp"):
            for kind in ("symlink", "file", "missing"):
                path = self.path / name
                self.path.chmod(0o700)
                path.rmdir()
                if kind == "symlink":
                    path.symlink_to("opt")
                elif kind == "file":
                    path.touch(mode=0o400)
                self.path.chmod(0o500)
                with (
                    self.subTest(name=name, kind=kind),
                    self.assertRaises(ValueError),
                    self.open(),
                ):
                    pass
                self.path.chmod(0o700)
                if kind != "missing":
                    path.unlink()
                path.mkdir(mode=0o500)
                self.path.chmod(0o500)

    def test_stale_core_and_wrong_root_refuse_before_hashing(self):
        bad = copy.deepcopy(self.core)
        bad["started_ns"] -= 6_000_000_000
        bad["finished_ns"] = bad["started_ns"]
        with self.assertRaises(ValueError), self.open(core=bad):
            pass
        plan = copy.deepcopy(self.plan)
        plan["root"]["inode"] += 2**32
        with self.assertRaises(ValueError), self.open(plan=plan):
            pass

    def test_nested_api_lookalike_is_not_excluded(self):
        parent = self.path / "opt"
        parent.chmod(0o700)
        nested = parent / "proc"
        nested.mkdir(mode=0o500)
        parent.chmod(0o500)
        with self.assertRaises(ValueError), self.open():
            pass

    def test_root_replacement_and_expiry_fail_later_checks(self):
        with self.open() as snapshot:
            previous = self.path.with_name("previous-root")
            self.path.rename(previous)
            self.path.mkdir(mode=0o500)
            with self.assertRaises(ValueError):
                snapshot._root_check()
            with self.assertRaises(ValueError):
                snapshot.check()
            self.path.rmdir()
            previous.rename(self.path)
            snapshot.deadline = time.monotonic_ns() - 1
            with self.assertRaises(TimeoutError):
                snapshot.check()

    def test_acquisition_and_cleanup_errors_are_retained(self):
        real_close = os.close

        def failed_close(fd):
            real_close(fd)
            raise OSError("injected close failure")

        with (
            mock.patch.object(
                rooted.RootedRuntimeSnapshot,
                "_directory",
                side_effect=ValueError("injected directory failure"),
            ),
            mock.patch.object(rooted.os, "close", side_effect=failed_close),
            self.assertRaises(BaseExceptionGroup) as caught,
            self.open(),
        ):
            pass
        self.assertIsInstance(caught.exception.exceptions[0], ValueError)
        self.assertIsInstance(caught.exception.exceptions[1], OSError)
        self.assertTrue(self.acquired)
        with self.assertRaises(OSError):
            os.fstat(self.acquired[-1])

    def test_file_facts_cannot_return_after_deadline(self):
        with self.open() as snapshot:

            def expire():
                snapshot.deadline = time.monotonic_ns() - 1

            with (
                mock.patch.object(snapshot, "check", side_effect=expire),
                self.assertRaises(TimeoutError),
            ):
                snapshot.file_facts()

    def test_caller_deadline_cannot_extend_the_original_core_window(self):
        start = self.core["started_ns"]
        for caller, expected in (
            (start + 9_000_000_000, start + 5_000_000_000),
            (start + 1_000_000_000, start + 1_000_000_000),
        ):
            clock = [start + 10]
            with (
                mock.patch.object(
                    rooted.time,
                    "monotonic_ns",
                    side_effect=lambda clock=clock: clock[0],
                ),
                self.open(deadline=caller) as snapshot,
            ):
                self.assertEqual(snapshot.deadline, expected)
                clock[0] = expected
                with self.assertRaises(TimeoutError):
                    snapshot.check()

    def test_agreeing_false_plan_and_core_cannot_replace_live_root_identity(self):
        plan, core = copy.deepcopy(self.plan), copy.deepcopy(self.core)
        plan["root"]["inode"] += 2**32
        core["root"]["inode"] = plan["root"]["inode"]
        with (
            mock.patch.object(rooted.RootedRuntimeSnapshot, "scan") as scan,
            self.assertRaises(ValueError),
            self.open(plan=plan, core=core),
        ):
            pass
        scan.assert_not_called()
        self.assertTrue(self.acquired)
        with self.assertRaises(OSError):
            os.fstat(self.acquired[-1])

    def test_all_api_directory_types_are_checked_before_any_hashing(self):
        self.path.chmod(0o700)
        path = self.path / "tmp"
        path.rmdir()
        path.touch(mode=0o400)
        self.path.chmod(0o500)
        with (
            mock.patch.object(
                rooted.closure.elf, "inspect", wraps=rooted.closure.elf.inspect
            ) as inspect,
            self.assertRaises(ValueError),
            self.open(),
        ):
            pass
        self.assertEqual(inspect.call_count, 0)

    def test_invalid_core_namespace_is_not_replaced_by_matching_root_ids(self):
        core = copy.deepcopy(self.core)
        core["namespaces"]["net"] = self.plan["host_namespaces"]["net"]
        with self.assertRaises(ValueError), self.open(core=core):
            pass

    def test_file_facts_rechecks_snapshot_before_export(self):
        with self.open() as snapshot:
            path = self.path / self.manifest["python"]["entry"]
            path.chmod(0o600)
            path.write_bytes(b"changed after verification\n")
            path.chmod(0o400)
            with self.assertRaises(ValueError):
                snapshot.file_facts()


if __name__ == "__main__":
    unittest.main()
