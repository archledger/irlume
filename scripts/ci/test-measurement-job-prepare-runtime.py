#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Exclusive runtime preparation using synthetic files, never executing them."""

import copy
import hashlib
import importlib.util
import os
import stat
import tempfile
import time
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


prepare = load("runtime_prepare", "measurement-job-prepare-runtime.py")
fixtures = load("prepare_fixtures", "test-measurement-job-closure.py")


class PreparationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.source = self.base / "source"
        self.source.mkdir(mode=0o700)
        self.destination = self.base / "runtime"
        self.manifest, content = fixtures.manifest()
        self.profile = {
            name: value for name, value in self.manifest.items() if name != "members"
        }
        self.selection = []
        for number, row in enumerate(self.manifest["members"]):
            if row["kind"] != "file":
                continue
            path = self.source / str(number)
            path.write_bytes(content[row["path"]])
            path.chmod(0o600)
            self.selection.append(
                {key: value for key, value in row.items() if key != "kind"}
                | {"source": str(path)}
            )

    def run_prepare(self, **kwargs):
        return prepare.prepare_runtime(
            str(self.destination),
            self.profile,
            self.selection,
            deadline=time.monotonic_ns() + 5_000_000_000,
            **kwargs,
        )

    def test_exact_tree_is_copied_closed_and_manifest_verified(self):
        data, digest = self.run_prepare()
        self.assertEqual(data, prepare.closure.canonical(self.manifest))
        self.assertEqual(digest, hashlib.sha256(data).hexdigest())
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o500)
        for row in self.selection:
            result = self.destination / row["path"]
            self.assertEqual(result.read_bytes(), Path(row["source"]).read_bytes())
            self.assertEqual(stat.S_IMODE(result.stat().st_mode), row["mode"])

    def test_existing_destination_is_never_overwritten(self):
        self.destination.mkdir()
        marker = self.destination / "keep"
        marker.write_bytes(b"existing work")
        with self.assertRaises(FileExistsError):
            self.run_prepare()
        self.assertEqual(marker.read_bytes(), b"existing work")

    def test_invalid_selection_refuses_before_creating_destination(self):
        for field, value in (
            ("path", "../outside"),
            ("size", True),
            ("mode", 0o777),
            ("source", "/tmp/../outside"),
            ("sha256", "x" * 64),
        ):
            original = copy.deepcopy(self.selection)
            self.selection[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.run_prepare()
            self.assertFalse(self.destination.exists())
            self.selection[:] = original

    def test_freeze_refuses_noncanonical_source_without_reading_files(self):
        self.selection[0]["source"] = "/tmp/../outside"
        with (
            mock.patch.object(
                prepare.os,
                "open",
                side_effect=AssertionError("unexpected filesystem I/O"),
            ),
            self.assertRaises(ValueError),
        ):
            prepare.freeze_selection(self.profile, self.selection)

    def test_wrong_digest_and_source_symlink_refuse(self):
        source = Path(self.selection[0]["source"])
        original = source.read_bytes()
        source.write_bytes(b"!" * len(original))
        with self.assertRaises(ValueError):
            self.run_prepare()
        self.assertTrue(self.destination.is_dir())
        self.destination = self.base / "symlink-result"
        source.unlink()
        other = self.source / "other"
        other.write_bytes(original)
        source.symlink_to(other)
        with self.assertRaises(OSError):
            self.run_prepare()

    def test_caller_mutation_after_snapshot_cannot_redirect_copy(self):
        original = copy.deepcopy(self.selection)
        real_open = prepare.os.open
        changed = False

        def mutate(path, flags, *args, **kwargs):
            nonlocal changed
            if not changed:
                changed = True
                self.selection[0]["path"] = "outside"
                self.selection[0]["source"] = "/does/not/exist"
                self.profile["python"]["entry"] = "outside"
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(prepare.os, "open", side_effect=mutate):
            data, _ = self.run_prepare()
        self.assertEqual(
            prepare.closure.runtime._json(data)["python"]["entry"],
            "opt/irlume/entry.py",
        )
        self.assertFalse((self.destination / "outside").exists())
        self.assertTrue((self.destination / original[0]["path"]).is_file())

    def test_short_writes_are_completed_and_zero_write_refuses(self):
        real_write = prepare.os.write

        def short_write(fd, data):
            return real_write(fd, data[:127])

        with mock.patch.object(prepare.os, "write", side_effect=short_write):
            self.run_prepare()
        self.destination = self.base / "zero-result"
        before = set(os.listdir("/proc/self/fd"))
        with (
            mock.patch.object(prepare.os, "write", return_value=0),
            self.assertRaisesRegex(ValueError, "zero preparation write"),
        ):
            self.run_prepare()
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        self.assertTrue(self.destination.is_dir())

    def test_previously_copied_source_change_is_not_accepted(self):
        real_copy = prepare.copy_source
        first = Path(self.selection[0]["source"])
        calls = []

        def copy_and_change(*args):
            result = real_copy(*args)
            calls.append(args[1].path)
            if len(calls) == 2:
                first.write_bytes(b"!" * first.stat().st_size)
            return result

        with (
            mock.patch.object(prepare, "copy_source", side_effect=copy_and_change),
            self.assertRaisesRegex(ValueError, "changed after copy"),
        ):
            self.run_prepare()

    def test_source_replacement_after_copy_is_not_accepted(self):
        real_copy = prepare.copy_source
        first = Path(self.selection[0]["source"])

        def copy_and_replace(*args):
            result = real_copy(*args)
            if args[1].path == self.selection[-1]["path"]:
                data = first.read_bytes()
                first.unlink()
                first.write_bytes(data)
            return result

        with (
            mock.patch.object(prepare, "copy_source", side_effect=copy_and_replace),
            self.assertRaises(ValueError),
        ):
            self.run_prepare()

    def test_identical_future_source_replacement_is_rejected(self):
        real_copy = prepare.copy_source
        future = Path(self.selection[-1]["source"])
        replacement = future.with_name("replacement")
        original = future.read_bytes()
        before = set(os.listdir("/proc/self/fd"))

        def replace_future(*args):
            result = real_copy(*args)
            if args[1].path == self.selection[0]["path"]:
                replacement.write_bytes(original)
                replacement.chmod(0o600)
                replacement.replace(future)
            return result

        with (
            mock.patch.object(prepare, "copy_source", side_effect=replace_future),
            self.assertRaisesRegex(ValueError, "baseline"),
        ):
            self.run_prepare()
        self.assertEqual(future.read_bytes(), original)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        self.assertFalse((self.destination / self.selection[-1]["path"]).exists())

    def test_all_sources_have_baselines_before_first_copy(self):
        captured = []
        real_capture, real_copy = prepare.capture_source, prepare.copy_source

        def capture(*args):
            result = real_capture(*args)
            captured.append(args[0].source)
            return result

        def copy(*args):
            self.assertEqual(captured, [row["source"] for row in self.selection])
            return real_copy(*args)

        with (
            mock.patch.object(prepare, "capture_source", side_effect=capture),
            mock.patch.object(prepare, "copy_source", side_effect=copy),
        ):
            self.run_prepare()

    def test_failed_source_baseline_does_not_create_output_or_leak_fds(self):
        Path(self.selection[-1]["source"]).unlink()
        before = set(os.listdir("/proc/self/fd"))
        with self.assertRaises(FileNotFoundError):
            self.run_prepare()
        self.assertFalse(self.destination.exists())
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_late_verifier_close_refuses_success_without_leaking_descriptors(self):
        clock, deadline = [100], 1_000_000
        real_close = prepare.closure.RuntimeSnapshot.close

        def late_close(snapshot):
            real_close(snapshot)
            clock[0] = deadline

        before = set(os.listdir("/proc/self/fd"))
        with (
            mock.patch.object(
                prepare.time, "monotonic_ns", side_effect=lambda: clock[0]
            ),
            mock.patch.object(
                prepare.closure.RuntimeSnapshot,
                "close",
                side_effect=late_close,
                autospec=True,
            ),
            self.assertRaises(TimeoutError),
        ):
            prepare.prepare_runtime(
                str(self.destination), self.profile, self.selection, deadline=deadline
            )
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_original_failure_and_close_failure_are_retained(self):
        real_close = prepare.os.close
        writing = [False]

        def fail_write(*args):
            writing[0] = True
            return 0

        def fail_close(fd):
            real_close(fd)
            if writing[0]:
                raise OSError("injected close failure")

        before = set(os.listdir("/proc/self/fd"))
        with (
            mock.patch.object(prepare.os, "write", side_effect=fail_write),
            mock.patch.object(prepare.os, "close", side_effect=fail_close),
            self.assertRaises(BaseExceptionGroup) as caught,
        ):
            self.run_prepare()
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        leaves = []

        def collect(error):
            if isinstance(error, BaseExceptionGroup):
                for nested in error.exceptions:
                    collect(nested)
            else:
                leaves.append(error)

        collect(caught.exception)
        self.assertTrue(
            any(
                isinstance(error, ValueError) and "zero preparation write" in str(error)
                for error in leaves
            )
        )
        self.assertTrue(
            any(
                isinstance(error, OSError) and "injected close failure" in str(error)
                for error in leaves
            )
        )

    def test_bad_native_closure_is_not_blessed_by_copying(self):
        row = self.selection[0]
        row["size"] = 4
        row["sha256"] = hashlib.sha256(b"junk").hexdigest()
        Path(row["source"]).write_bytes(b"junk")
        with self.assertRaises(ValueError):
            self.run_prepare()
        self.assertTrue(self.destination.is_dir())

    def test_profile_schema_and_selection_order_are_checked_before_io(self):
        for field, value in (
            ("python", 1),
            ("platform", []),
            ("environment", {"PATH": "/bin"}),
        ):
            profile = copy.deepcopy(self.profile)
            profile[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                prepare.prepare_runtime(
                    str(self.destination),
                    profile,
                    self.selection,
                    deadline=time.monotonic_ns() + 5_000_000_000,
                )
            self.assertFalse(self.destination.exists())
        with self.assertRaises(ValueError):
            prepare.freeze_selection(self.profile, list(reversed(self.selection)))
        with self.assertRaises(ValueError):
            prepare.freeze_selection(self.profile, [self.selection[0], *self.selection])

    def test_destination_link_and_api_root_cannot_redirect_output(self):
        outside = self.base / "outside"
        outside.mkdir()
        self.destination.symlink_to(outside)
        with self.assertRaises(FileExistsError):
            self.run_prepare()
        self.assertEqual(list(outside.iterdir()), [])
        self.destination.unlink()
        self.selection[0]["path"] = "run/extra"
        with self.assertRaises(ValueError):
            self.run_prepare()
        self.assertFalse(self.destination.exists())

    def test_nonregular_and_writable_by_others_sources_refuse(self):
        path = Path(self.selection[0]["source"])
        path.chmod(0o666)
        with self.assertRaises(ValueError):
            self.run_prepare()
        self.destination = self.base / "fifo-result"
        path.unlink()
        os.mkfifo(path, 0o600)
        with self.assertRaises(ValueError):
            self.run_prepare()

    def test_source_read_truncation_and_output_mutation_refuse(self):
        with (
            mock.patch.object(prepare.os, "read", return_value=b""),
            self.assertRaisesRegex(ValueError, "short preparation source"),
        ):
            self.run_prepare()
        self.destination = self.base / "output-mutated"
        original = prepare.closure.RuntimeSnapshot.open

        def corrupt(*args, **kwargs):
            path = self.destination / self.selection[0]["path"]
            path.chmod(0o600)
            data = path.read_bytes()
            path.write_bytes(b"!" * len(data))
            path.chmod(self.selection[0]["mode"])
            return original(*args, **kwargs)

        with (
            mock.patch.object(
                prepare.closure.RuntimeSnapshot, "open", side_effect=corrupt
            ),
            self.assertRaises(ValueError),
        ):
            self.run_prepare()

    def test_long_caller_deadline_is_clamped_to_preparation_budget(self):
        clock = [100]
        original = prepare.closure.RuntimeSnapshot.close

        def late_close(snapshot):
            original(snapshot)
            clock[0] = 100 + prepare.PREPARATION_NS

        with (
            mock.patch.object(
                prepare.time, "monotonic_ns", side_effect=lambda: clock[0]
            ),
            mock.patch.object(
                prepare.closure.RuntimeSnapshot,
                "close",
                side_effect=late_close,
                autospec=True,
            ),
            self.assertRaises(TimeoutError),
        ):
            prepare.prepare_runtime(
                str(self.destination),
                self.profile,
                self.selection,
                deadline=100 + prepare.PREPARATION_NS * 2,
            )


if __name__ == "__main__":
    unittest.main()
