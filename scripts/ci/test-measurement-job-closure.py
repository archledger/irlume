#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Synthetic finite runtime trees; never execute a member of the tree."""

import contextlib
import copy
import hashlib
import importlib.util
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "closure", HERE / "measurement-job-closure.py"
)
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)
SPEC = importlib.util.spec_from_file_location(
    "elf_fixtures", HERE / "test-measurement-job-elf.py"
)
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)


def profile():
    return {
        "scope": "contained-job-runtime-tree-v1",
        "platform": {
            "os": "linux",
            "machine": "x86_64",
            "bits": 64,
            "byte_order": "little",
        },
        "python": {
            "implementation": "cpython",
            "version": [3, 14, 8],
            "executable": "usr/bin/python3",
            "entry": "opt/irlume/entry.py",
            "roots": ["usr/lib/python3.14"],
            "flags": ["-I", "-S", "-B", "-X", "pycache_prefix=/dev/null"],
        },
        "native": {"interpreter": "lib64/ld-linux-x86-64.so.2", "library_dir": "lib64"},
        "environment": {"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        "bootstrap": "usr/bin/bootstrap",
    }


def manifest():
    value = profile()
    files = {
        "usr/bin/python3": fixtures.image(interpreter=closure.elf.INTERPRETER),
        "usr/bin/bootstrap": fixtures.image(dynamic=False, kind=2),
        "lib64/ld-linux-x86-64.so.2": fixtures.image(),
        "opt/irlume/entry.py": b"pass\n",
        "usr/lib/python3.14/__init__.py": b"",
    }
    dirs = {
        str(parent)
        for path in files
        for parent in Path(path).parents
        if str(parent) != "."
    }
    value["members"] = [{"path": d, "kind": "directory", "mode": 0o500} for d in dirs]
    value["members"] += [
        {
            "path": name,
            "kind": "file",
            "mode": 0o500 if data.startswith(b"\x7fELF") else 0o400,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for name, data in files.items()
    ]
    value["members"].sort(key=lambda row: row["path"])
    return value, files


class OtherDevice:
    def __init__(self, info, device):
        self._info, self.st_dev = info, device

    def __getattr__(self, name):
        return getattr(self._info, name)


@contextlib.contextmanager
def on_device(path, device):
    """Report one member on another device in stat and fstat, as a mount would."""
    info = os.stat(path, follow_symlinks=False)
    target = info.st_dev, info.st_ino
    real_stat, real_fstat = os.stat, os.fstat

    def moved(result):
        if (result.st_dev, result.st_ino) == target:
            return OtherDevice(result, device)
        return result

    with (
        mock.patch.object(
            os, "stat", side_effect=lambda *a, **k: moved(real_stat(*a, **k))
        ),
        mock.patch.object(
            os, "fstat", side_effect=lambda *a, **k: moved(real_fstat(*a, **k))
        ),
    ):
        yield


CROSSES = "^runtime member crosses a filesystem$"


def btrfs_subvolume(path):
    subprocess.run(
        ["btrfs", "subvolume", "create", str(path)], check=True, capture_output=True
    )


class ManifestTests(unittest.TestCase):
    def test_manifest_byte_limit_and_file_type_for_startup_references(self):
        with self.assertRaises(ValueError):
            closure.decode_manifest(b" " * (closure.MAX_MANIFEST + 1), "0" * 64)
        value, _ = manifest()
        data = closure.canonical(value)
        with (
            mock.patch.object(closure, "MAX_MANIFEST", len(data) - 1),
            self.assertRaises(ValueError),
        ):
            closure.decode_manifest(data, hashlib.sha256(data).hexdigest())
        for path in (
            value["bootstrap"],
            value["python"]["executable"],
            value["python"]["entry"],
        ):
            bad = copy.deepcopy(value)
            row = next(item for item in bad["members"] if item["path"] == path)
            row.clear()
            row.update(path=path, kind="directory", mode=0o500)
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.decode(bad)

    def decode(self, value):
        data = closure.canonical(value)
        return closure.decode_manifest(data, hashlib.sha256(data).hexdigest())

    def test_exact_manifest_allows_empty_source_and_rejects_missing_references(self):
        value, _ = manifest()
        self.assertEqual(self.decode(value), value)
        for field in ("entry", "executable"):
            bad = copy.deepcopy(value)
            bad["python"][field] = "missing/file"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.decode(bad)

    def test_unknown_fields_types_environment_and_duplicate_members_refuse(self):
        value, _ = manifest()
        for mutate in (
            lambda x: x.update(extra=1),
            lambda x: x["environment"].update(LD_PRELOAD="/evil"),
            lambda x: x["python"]["version"].__setitem__(0, True),
            lambda x: x["members"].append(x["members"][0]),
            lambda x: x["python"].update(roots=["missing"]),
        ):
            bad = copy.deepcopy(value)
            mutate(bad)
            with self.assertRaises(ValueError):
                self.decode(bad)
        raw = b'{"scope":"one","scope":"two"}'
        with self.assertRaises(ValueError):
            closure.decode_manifest(raw, hashlib.sha256(raw).hexdigest())
        with self.assertRaises(ValueError):
            closure.decode_manifest(closure.canonical(value), "0" * 64)

    def test_cache_and_loader_lookup_paths_refuse(self):
        value, _ = manifest()
        for path in (
            "etc/ld.so.preload",
            "lib64/glibc-hwcaps",
            "usr/lib/site-packages",
            "opt/irlume/cached.pyc",
            "opt/irlume/archive.zip",
        ):
            bad = copy.deepcopy(value)
            bad["members"].append({"path": path, "kind": "directory", "mode": 0o500})
            bad["members"].sort(key=lambda row: row["path"])
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.decode(bad)


class TreeTests(unittest.TestCase):
    def test_depth_limit_counts_every_member_including_files(self):
        for depth in (32, 33):
            with self.subTest(depth=depth), tempfile.TemporaryDirectory() as directory:
                files = manifest()[1]
                files["/".join(["deep"] * (depth - 1) + ["leaf.py"])] = b""
                root = self.make_tree(directory, files)
                if depth == 32:
                    closure.prepare_manifest(
                        root, profile(), deadline=time.monotonic_ns() + 2_000_000_000
                    )
                else:
                    with self.assertRaises(ValueError):
                        closure.prepare_manifest(
                            root,
                            profile(),
                            deadline=time.monotonic_ns() + 2_000_000_000,
                        )

    def test_final_root_stat_expiry_rejects_check_and_admission_without_fd_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_tree(directory)
            data, digest = closure.prepare_manifest(
                root, profile(), deadline=time.monotonic_ns() + 2_000_000_000
            )
            real_stat = os.stat
            for admission in (False, True):
                clock, calls = [0], [0]
                end = time.monotonic_ns() + 2_000_000_000
                owned = (
                    None
                    if admission
                    else closure.RuntimeSnapshot.open(root, data, digest, deadline=end)
                )
                if owned is not None:
                    owned.deadline = 100
                before = set(os.listdir("/proc/self/fd"))

                def stat(
                    path, *args, admission=admission, clock=clock, calls=calls, **kwargs
                ):
                    result = real_stat(path, *args, **kwargs)
                    if path == root.name:
                        calls[0] += 1
                        if calls[0] == (4 if admission else 2):
                            clock[0] = 101
                    return result

                try:
                    with (
                        mock.patch.object(closure.os, "stat", side_effect=stat),
                        mock.patch.object(
                            closure.inputs.time,
                            "monotonic_ns",
                            side_effect=lambda clock=clock: clock[0],
                        ),
                        self.subTest(admission=admission),
                        self.assertRaises(TimeoutError),
                    ):
                        if admission:
                            owned = closure.RuntimeSnapshot.open(
                                root, data, digest, deadline=100
                            )
                        else:
                            owned.check()
                    self.assertEqual(set(os.listdir("/proc/self/fd")), before)
                finally:
                    if owned is not None:
                        owned.close()

    def test_final_preparation_serialization_expiry_still_closes_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_tree(directory)
            clock = [0]
            original = closure.canonical

            def encode(value):
                data = original(value)
                clock[0] = 101
                return data

            before = set(os.listdir("/proc/self/fd"))
            with (
                mock.patch.object(closure, "canonical", side_effect=encode),
                mock.patch.object(
                    closure.inputs.time, "monotonic_ns", side_effect=lambda: clock[0]
                ),
                self.assertRaises(TimeoutError),
            ):
                closure.prepare_manifest(root, profile(), deadline=100)
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_membership_and_root_ancestor_replacement_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory) / "outer"
            outer.mkdir(mode=0o700)
            parent = outer / "parent"
            parent.mkdir(mode=0o700)
            root = self.make_tree(parent)
            end = time.monotonic_ns() + 2_000_000_000
            data, digest = closure.prepare_manifest(root, profile(), deadline=end)
            with closure.RuntimeSnapshot.open(
                root, data, digest, deadline=end
            ) as owned:
                original_root = closure.inputs.identity(root.stat())
                outer.rename(Path(directory) / "old-outer")
                outer.mkdir(mode=0o700)
                (Path(directory) / "old-outer/parent").rename(parent)
                self.assertEqual(closure.inputs.identity(root.stat()), original_root)
                with self.assertRaises(ValueError):
                    owned.check()
            root.chmod(0o700)
            (root / "surplus").write_bytes(b"extra")
            (root / "surplus").chmod(0o400)
            root.chmod(0o500)
            with self.assertRaises(ValueError):
                closure.RuntimeSnapshot.open(root, data, digest, deadline=end)

    def test_failed_file_read_closes_all_acquired_descriptors(self):
        def descriptors():
            result = set()
            for name in os.listdir("/proc/self/fd"):
                try:
                    os.fstat(int(name))
                except OSError:
                    continue
                result.add(int(name))
            return result

        with tempfile.TemporaryDirectory() as directory:
            root = self.make_tree(directory)
            before = descriptors()
            with (
                mock.patch.object(
                    closure.os, "read", side_effect=OSError("injected read error")
                ),
                self.assertRaises(OSError),
            ):
                closure.prepare_manifest(
                    root, profile(), deadline=time.monotonic_ns() + 2_000_000_000
                )
            self.assertEqual(descriptors(), before)

    def make_tree(self, directory, files=None, *, root="root", subvolume=None):
        """Build a tree; subvolume names a btrfs subvolume to create, "." the root."""
        root = Path(directory) / root
        if subvolume == ".":
            btrfs_subvolume(root)
            root.chmod(0o700)
        else:
            root.mkdir(mode=0o700)
            if subvolume is not None:
                (root / subvolume).parent.mkdir(parents=True, exist_ok=True)
                btrfs_subvolume(root / subvolume)
        files = manifest()[1] if files is None else files
        for name, data in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o500 if data.startswith(b"\x7fELF") else 0o400)
        for path in root.rglob("*"):
            if path.is_dir():
                path.chmod(0o500)
        root.chmod(0o500)
        return root

    def test_prepare_and_verify_exact_tree_with_empty_initializer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_tree(directory)
            end = time.monotonic_ns() + 2_000_000_000
            data, digest = closure.prepare_manifest(root, profile(), deadline=end)
            with closure.RuntimeSnapshot.open(
                root, data, digest, deadline=end
            ) as owned:
                self.assertEqual(owned.manifest["python"], profile()["python"])
                scratch = owned.manifest
                scratch["python"]["entry"] = "altered.py"
                self.assertEqual(
                    owned.manifest["python"]["entry"], profile()["python"]["entry"]
                )
                self.assertIn("usr/bin/python3", owned.graph)
                owned.check()
            self.assertIsNone(owned.fd)

    def test_content_and_new_members_invalidate_existing_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_tree(directory)
            end = time.monotonic_ns() + 2_000_000_000
            data, digest = closure.prepare_manifest(root, profile(), deadline=end)
            with closure.RuntimeSnapshot.open(
                root, data, digest, deadline=end
            ) as owned:
                source = root / "opt/irlume/entry.py"
                source.chmod(0o600)
                source.write_bytes(b"fail\n")
                source.chmod(0o400)
                with self.assertRaises(ValueError):
                    owned.check()
            with self.assertRaises(ValueError):
                closure.RuntimeSnapshot.open(root, data, digest, deadline=end)

    def test_invalid_dso_and_writable_or_linked_tree_never_publish_manifest(self):
        for fault in ("dso", "bootstrap", "writable", "symlink", "hardlink"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                files = manifest()[1]
                if fault == "dso":
                    files["usr/lib/python3.14/ext.so"] = fixtures.image(dynamic=False)
                elif fault == "bootstrap":
                    files["usr/bin/bootstrap"] = fixtures.image()
                root = self.make_tree(directory, files)
                target = root / "opt/irlume/entry.py"
                if fault == "writable":
                    target.chmod(0o600)
                elif fault in ("symlink", "hardlink"):
                    target.parent.chmod(0o700)
                    if fault == "symlink":
                        target.unlink()
                        target.symlink_to("missing")
                    else:
                        os.link(target, target.parent / "alias.py")
                    target.parent.chmod(0o500)
                with self.assertRaises(ValueError):
                    closure.prepare_manifest(
                        root, profile(), deadline=time.monotonic_ns() + 2_000_000_000
                    )

    def test_member_on_another_device_refuses_at_every_scan(self):
        # A tmpfs mounted on a directory, or an ext4 file bound into the tree.
        for member, device in (
            ("opt/irlume", os.makedev(0, 4095)),
            ("usr/bin/python3", os.makedev(259, 4095)),
        ):
            with (
                self.subTest(member=member),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = self.make_tree(directory)
                self.assertNotEqual(device, root.stat().st_dev)
                end = time.monotonic_ns() + 2_000_000_000
                data, digest = closure.prepare_manifest(root, profile(), deadline=end)
                with (
                    on_device(root / member, device),
                    self.assertRaisesRegex(ValueError, CROSSES),
                ):
                    closure.prepare_manifest(root, profile(), deadline=end)
                with (
                    on_device(root / member, device),
                    self.assertRaisesRegex(ValueError, CROSSES),
                ):
                    closure.RuntimeSnapshot.open(root, data, digest, deadline=end)
                with closure.RuntimeSnapshot.open(
                    root, data, digest, deadline=end
                ) as owned:
                    owned.check()
                    owned.recheck(end)
                    with on_device(root / member, device):
                        with self.assertRaisesRegex(ValueError, CROSSES):
                            owned.check()
                        with self.assertRaisesRegex(ValueError, CROSSES):
                            owned.recheck(end)
                    owned.check()

    def test_nested_btrfs_subvolume_refuses_and_a_subvolume_root_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            kind = subprocess.run(
                ["stat", "-f", "-c", "%T", directory],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if kind != "btrfs":
                self.skipTest(
                    f"{directory} is on {kind}, not btrfs; set TMPDIR to a btrfs "
                    "directory to run this test"
                )
            if shutil.which("btrfs") is None:
                self.skipTest("btrfs-progs (the btrfs command) is not installed")
            end = time.monotonic_ns() + 10_000_000_000
            plain = self.make_tree(directory, root="plain")
            data, digest = closure.prepare_manifest(plain, profile(), deadline=end)
            with closure.RuntimeSnapshot.open(
                plain, data, digest, deadline=end
            ) as owned:
                owned.check()
            # The same bytes with opt/ as a nested subvolume: a directory entry,
            # not a mount, whose stat device is the subvolume's own.
            nested = self.make_tree(directory, root="nested", subvolume="opt")
            self.assertNotEqual((nested / "opt").stat().st_dev, nested.stat().st_dev)
            with self.assertRaisesRegex(ValueError, CROSSES):
                closure.prepare_manifest(nested, profile(), deadline=end)
            with self.assertRaisesRegex(ValueError, CROSSES):
                closure.RuntimeSnapshot.open(nested, data, digest, deadline=end)
            # A tree that is a subvolume itself keeps every member on its device.
            own = self.make_tree(directory, root="own", subvolume=".")
            self.assertNotEqual(own.stat().st_dev, plain.stat().st_dev)
            self.assertEqual(
                closure.prepare_manifest(own, profile(), deadline=end), (data, digest)
            )
            with closure.RuntimeSnapshot.open(own, data, digest, deadline=end) as owned:
                owned.check()

    def test_tree_and_manifest_budget_limits_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_tree(directory)
            for constant, maximum in (("MAX_MEMBERS", 2), ("MAX_TOTAL", 1)):
                with (
                    mock.patch.object(closure, constant, maximum),
                    self.assertRaises(ValueError),
                ):
                    closure.prepare_manifest(
                        root, profile(), deadline=time.monotonic_ns() + 2_000_000_000
                    )


if __name__ == "__main__":
    unittest.main()
