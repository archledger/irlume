#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""H input ownership with private files only; no service, bus or VM."""

import hashlib
import importlib.util
import os
import shutil
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


owners = load("host_inputs", "measurement-job-rooted-host-inputs.py")
fixtures = load("host_input_fixtures", "test-measurement-job-rooted-protocol.py")
root = fixtures.root_tests.root


class InputOwnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        fixture = fixtures.ProtocolTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.manifest = fixture.manifest
        self.runtime = self.path / "runtime"
        self.runtime.mkdir()
        _, contents = fixtures.root_tests.fixtures.manifest()
        contents[root.ENTRY] = contents.pop("opt/irlume/entry.py")
        contents["usr/bin/qemu-system-x86_64"] = contents["usr/bin/python3"]
        members = root.runtime._json(self.manifest)["members"]
        for member in members:
            target = self.runtime / member["path"]
            if member["kind"] == "directory":
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.write_bytes(contents[member["path"]])
                target.chmod(member["mode"])
        for member in reversed(members):
            if member["kind"] == "directory":
                (self.runtime / member["path"]).chmod(member["mode"])
        self.runtime.chmod(0o500)
        self.files = {}
        for name, data in (
            ("manifest", self.manifest),
            ("base", b"inert base"),
            ("payload", b"inert payload"),
        ):
            path = self.path / name
            path.write_bytes(data)
            path.chmod(0o400)
            self.files[name] = path
        self.spec = fixture.spec._replace(
            base=str(self.files["base"]),
            payload=str(self.files["payload"]),
            overlay=str(self.path / "attempt-run-01/overlay.qcow2"),
        )
        self.selection = owners.Selection(
            self.spec,
            str(self.runtime),
            str(self.files["manifest"]),
            hashlib.sha256(self.manifest).hexdigest(),
            hashlib.sha256(b"inert base").hexdigest(),
            hashlib.sha256(b"inert payload").hexdigest(),
        )

    def open(self, deadline=None):
        return owners.PreparedInputs.open(
            self.selection,
            root,
            deadline=deadline
            if deadline is not None
            else time.monotonic_ns() + 5_000_000_000,
        )

    def test_owned_inputs_are_real_retained_descriptors(self):
        before = set(os.listdir("/proc/self/fd"))
        owned = self.open()
        self.addCleanup(owned.close)
        self.assertEqual(owned.manifest, self.manifest)
        for name, path in self.files.items():
            self.assertEqual(os.fstat(owned.files[name].fd).st_ino, path.stat().st_ino)
        self.assertEqual(os.fstat(owned.runtime.fd).st_ino, self.runtime.stat().st_ino)
        owned.close()
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_partial_acquisition_failure_closes_earlier_inputs(self):
        self.selection = self.selection._replace(payload_sha256="0" * 64)
        before = set(os.listdir("/proc/self/fd"))
        with self.assertRaises(ValueError):
            self.open()
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_phase_recheck_rejects_changed_input_without_reopening(self):
        owned = self.open()
        self.addCleanup(owned.close)
        fd = owned.files["base"].fd
        path = self.files["base"]
        path.chmod(0o600)
        path.write_bytes(b"alter base")
        path.chmod(0o400)
        with self.assertRaises(ValueError):
            owned.recheck(time.monotonic_ns() + 5_000_000_000)
        self.assertEqual(owned.files["base"].fd, fd)

    def test_phase_checks_do_not_renew_preparation_deadline(self):
        clock = [100]
        with mock.patch.object(time, "monotonic_ns", side_effect=lambda: clock[0]):
            owned = self.open(200)
            self.addCleanup(owned.close)
            clock[0] = 201
            owned.recheck(300)
            self.assertEqual(owned.deadline, 200)
            self.assertEqual(owned.runtime.deadline, 200)
            self.assertTrue(all(item.deadline == 200 for item in owned.files.values()))

    def test_close_failure_still_closes_every_other_owner(self):
        owned = self.open()
        self.addCleanup(owned.close)
        close = owned.files["manifest"].close

        def failed_close():
            close()
            raise OSError("manifest close")

        with (
            mock.patch.object(
                owned.files["manifest"], "close", side_effect=failed_close
            ),
            self.assertRaises(BaseExceptionGroup),
        ):
            owned.close()
        self.assertIsNone(owned.runtime.fd)
        self.assertTrue(all(item.fd is None for item in owned.files.values()))

    def test_manifest_must_match_rooted_reader_permissions(self):
        self.files["manifest"].chmod(0o444)
        before = set(os.listdir("/proc/self/fd"))
        with self.assertRaisesRegex(ValueError, "manifest ownership or mode"):
            self.open()
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_final_input_checks_detect_mutation_during_runtime_hashing(self):
        owned = self.open()
        self.addCleanup(owned.close)
        recheck = owned.runtime.recheck

        def change_input(deadline):
            recheck(deadline)
            path = self.files["base"]
            path.chmod(0o600)
            path.write_bytes(b"alter base")
            path.chmod(0o400)

        with (
            mock.patch.object(owned.runtime, "recheck", side_effect=change_input),
            self.assertRaises(ValueError),
        ):
            owned.recheck(time.monotonic_ns() + 5_000_000_000)

    def test_identical_file_replacement_preserves_original_owner_but_refuses(self):
        owned = self.open()
        self.addCleanup(owned.close)
        original = owned.files["base"].fd
        replacement = self.path / "replacement"
        replacement.write_bytes(self.files["base"].read_bytes())
        replacement.chmod(0o400)
        replacement.replace(self.files["base"])
        with self.assertRaises(ValueError):
            owned.recheck(time.monotonic_ns() + 5_000_000_000)
        self.assertEqual(owned.files["base"].fd, original)

    def test_same_content_under_replaced_parent_refuses(self):
        parent = self.path / "input-parent"
        parent.mkdir(mode=0o700)
        old = self.files["base"]
        new = parent / "base"
        old.rename(new)
        self.files["base"] = new
        self.selection = self.selection._replace(
            spec=self.selection.spec._replace(base=str(new))
        )
        owned = self.open()
        self.addCleanup(owned.close)
        original = owned.files["base"].fd
        parent.rename(self.path / "old-parent")
        parent.mkdir(mode=0o700)
        new.write_bytes(b"inert base")
        new.chmod(0o400)
        with self.assertRaises(ValueError):
            owned.recheck(time.monotonic_ns() + 5_000_000_000)
        self.assertEqual(owned.files["base"].fd, original)

    def test_identical_runtime_replacement_refuses_without_new_owner(self):
        owned = self.open()
        self.addCleanup(owned.close)
        original = owned.runtime.fd
        saved = self.path / "old-runtime"
        self.runtime.rename(saved)
        shutil.copytree(saved, self.runtime)
        with self.assertRaises(ValueError):
            owned.recheck(time.monotonic_ns() + 5_000_000_000)
        self.assertEqual(owned.runtime.fd, original)

    def test_replaced_ancestor_with_identical_leaf_metadata_refuses(self):
        outer = self.path / "outer"
        inner = outer / "inner"
        inner.mkdir(parents=True, mode=0o700)
        leaf = inner / "base"
        self.files["base"].rename(leaf)
        self.files["base"] = leaf
        self.selection = self.selection._replace(
            spec=self.selection.spec._replace(base=str(leaf))
        )
        owned = self.open()
        self.addCleanup(owned.close)
        identity = root.closure.inputs.identity(leaf.stat())
        outer.rename(self.path / "old-outer")
        outer.mkdir(mode=0o700)
        (self.path / "old-outer/inner").rename(inner)
        self.assertEqual(root.closure.inputs.identity(leaf.stat()), identity)
        with self.assertRaises(ValueError):
            owned.recheck(time.monotonic_ns() + 5_000_000_000)


if __name__ == "__main__":
    unittest.main()
