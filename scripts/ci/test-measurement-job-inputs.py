#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Read-only admission uses temporary files; no image tools or VM are started."""

import hashlib
import importlib.util
import os
import struct
import tempfile
import time
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "inputs", HERE / "measurement-job-inputs.py"
)
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


def header(backing=None):
    data = bytearray(65536)
    struct.pack_into(
        ">IIQIIQIIQQIIQ",
        data,
        0,
        0x514649FB,
        3,
        0,
        0,
        16,
        4 * 1024 * 1024,
        0,
        1,
        65536,
        131072,
        1,
        0,
        0,
    )
    struct.pack_into(">QQQII", data, 72, 0, 0, 0, 4, 112)
    if backing is not None:
        raw = backing.encode()
        struct.pack_into(">II", data, 112, 0xE2792ACA, 3)
        data[120:123] = b"raw"
        struct.pack_into(">QI", data, 8, 512, len(raw))
        data[512 : 512 + len(raw)] = raw
    return data


class HeaderTests(unittest.TestCase):
    def test_overlay_rejects_reserved_bytes_after_backing_filename(self):
        backing = "/private/base.raw"
        for offset in (512 + len(backing.encode()), 65535):
            data = header(backing)
            data[offset] = 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.check(data, backing)

    def check(self, data, backing=None):
        return inputs.inspect_qcow2(
            bytes(data), file_size=196608, expected_backing=backing
        )

    def test_base_and_explicit_raw_backed_overlay_profiles(self):
        self.assertEqual(self.check(header())["virtual_size"], 4 * 1024 * 1024)
        name = "/private/base.raw"
        self.assertEqual(self.check(header(name), name)["backing"], name)
        for wrong in (None, "/private/other.raw", "/private/else.raw"):
            with self.assertRaises(ValueError):
                self.check(header(name), wrong)
        with self.assertRaises(ValueError):
            self.check(header(), name)

    def test_features_encryption_snapshots_and_compression_refuse(self):
        for offset, fmt, value in (
            (0, ">I", 0),
            (4, ">I", 2),
            (20, ">I", 15),
            (32, ">I", 1),
            (60, ">I", 1),
            (64, ">Q", 65536),
            (72, ">Q", 4),
            (80, ">Q", 1),
            (88, ">Q", 2),
            (96, ">I", 3),
            (100, ">I", 120),
            (104, ">B", 1),
            (105, ">B", 1),
        ):
            data = header()
            struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.check(data)

    def test_tables_virtual_size_and_truncated_cluster_refuse(self):
        for offset, fmt, value in (
            (24, ">Q", 0),
            (24, ">Q", 2**32 + 512),
            (24, ">Q", 1023),
            (36, ">I", 0),
            (40, ">Q", 1),
            (40, ">Q", 262144),
            (48, ">Q", 1),
            (56, ">I", 0),
            (56, ">I", 100),
        ):
            data = header()
            struct.pack_into(fmt, data, offset, value)
            with (
                self.subTest(offset=offset, value=value),
                self.assertRaises(ValueError),
            ):
                self.check(data)
        for size in (0, 103, 111, 65535):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.check(header()[:size])
        data = header()
        struct.pack_into(">Q", data, 40, 131072)
        with self.assertRaises(ValueError):
            self.check(data)

    def test_extensions_reject_external_duplicate_unknown_and_overrun(self):
        for kind in (0x44415441, 0x23852875, 0x0537BE77, 0x12345678):
            data = header()
            struct.pack_into(">II", data, 112, kind, 0)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.check(data)
        for length in (1, 65536, 0xFFFFFFFF):
            data = header()
            struct.pack_into(">II", data, 112, 0x6803F857, length)
            with self.subTest(length=length), self.assertRaises(ValueError):
                self.check(data)
        data = header()
        struct.pack_into(">IIII", data, 112, 0x6803F857, 0, 0x6803F857, 0)
        with self.assertRaises(ValueError):
            self.check(data)
        data = header("/private/base.raw")
        data[120:123] = b"bad"
        with self.assertRaises(ValueError):
            self.check(data, "/private/base.raw")

    def test_feature_table_is_descriptive_not_permission_for_enabled_bits(self):
        data = header()
        struct.pack_into(">II", data, 112, 0x6803F857, 48)
        data[120:122] = bytes((0, 2))
        data[122:135] = b"external data"
        self.check(data)
        struct.pack_into(">Q", data, 72, 4)
        with self.assertRaises(ValueError):
            self.check(data)


class InputTests(unittest.TestCase):
    def test_replaced_ancestor_preserves_all_leaf_metadata_but_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outer = root / "outer"
            inner = outer / "inner"
            inner.mkdir(parents=True, mode=0o700)
            path = inner / "input"
            selected = self.frozen(path)
            try:
                leaf_before = inputs.identity(path.stat())
                outer.rename(root / "old-outer")
                outer.mkdir(mode=0o700)
                (root / "old-outer/inner").rename(inner)
                self.assertEqual(inputs.identity(path.stat()), leaf_before)
                with self.assertRaises(ValueError):
                    selected.check()
            finally:
                selected.close()

    def test_acquisition_keeps_primary_and_consumed_parent_close_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"input")
            path.chmod(0o400)
            real_open, real_close = os.open, os.close
            parent_fd = None
            primary = OSError("input open failed")

            def open_fd(name, *args, **kwargs):
                nonlocal parent_fd
                if name == path.name:
                    parent_fd = kwargs["dir_fd"]
                    raise primary
                return real_open(name, *args, **kwargs)

            def close_fd(fd):
                real_close(fd)
                if fd == parent_fd:
                    raise OSError("parent close consumed")

            with (
                mock.patch.object(inputs.os, "open", side_effect=open_fd),
                mock.patch.object(inputs.os, "close", side_effect=close_fd),
                self.assertRaises(BaseExceptionGroup) as caught,
            ):
                inputs.FrozenInput.open(
                    path,
                    hashlib.sha256(b"input").hexdigest(),
                    limit=1024,
                    deadline=time.monotonic_ns() + 1_000_000_000,
                )
            self.assertIn(primary, caught.exception.exceptions)

    def test_failed_hash_does_not_leave_owned_descriptors(self):
        def open_descriptors():
            result = set()
            for name in os.listdir("/proc/self/fd"):
                try:
                    os.fstat(int(name))
                except OSError:
                    continue
                result.add(int(name))
            return result

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"input")
            path.chmod(0o400)
            before = open_descriptors()
            for _ in range(3):
                with self.assertRaises(ValueError):
                    inputs.FrozenInput.open(
                        path,
                        "0" * 64,
                        limit=1024,
                        deadline=time.monotonic_ns() + 1_000_000_000,
                    )
            self.assertEqual(open_descriptors(), before)

    def frozen(self, path, data=b"selected input"):
        path.write_bytes(data)
        path.chmod(0o400)
        return inputs.FrozenInput.open(
            path,
            hashlib.sha256(data).hexdigest(),
            limit=1024,
            deadline=time.monotonic_ns() + 1_000_000_000,
        )

    def test_retained_descriptor_matches_digest_and_is_not_inheritable(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.frozen(Path(directory) / "input") as selected:
                self.assertFalse(os.get_inheritable(selected.fd))
                self.assertEqual(selected.read_prefix(8), b"selected")
                selected.check()
                fd = selected.fd
            self.assertIsNone(selected.fd)
            with self.assertRaises(OSError):
                os.fstat(fd)
            selected.close()

    def test_writable_symlink_hardlink_fifo_and_digest_mismatch_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "input"
            path.write_bytes(b"input")
            digest = hashlib.sha256(b"input").hexdigest()

            def open_input(p=path):
                return inputs.FrozenInput.open(
                    p, digest, limit=1024, deadline=time.monotonic_ns() + 1_000_000_000
                )

            with self.assertRaises(ValueError):
                open_input()
            path.chmod(0o400)
            alias = root / "alias"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                open_input(alias)
            alias.unlink()
            os.link(path, alias)
            with self.assertRaises(ValueError):
                open_input()
            alias.unlink()
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o400)
            with self.assertRaises(ValueError):
                open_input(fifo)
            with self.assertRaises(ValueError):
                inputs.FrozenInput.open(
                    path,
                    "0" * 64,
                    limit=1024,
                    deadline=time.monotonic_ns() + 1_000_000_000,
                )

    def test_same_size_replacement_and_moved_leaf_under_new_ancestor_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            leaf = parent / "input"
            selected = self.frozen(leaf)
            try:
                parent.rename(root / "old-parent")
                parent.mkdir(mode=0o700)
                (root / "old-parent/input").rename(leaf)
                self.assertEqual(os.stat(leaf).st_ino, os.fstat(selected.fd).st_ino)
                with self.assertRaises(ValueError):
                    selected.check()
            finally:
                selected.close()
            selected = inputs.FrozenInput.open(
                leaf,
                hashlib.sha256(b"selected input").hexdigest(),
                limit=1024,
                deadline=time.monotonic_ns() + 1_000_000_000,
            )
            try:
                leaf.rename(parent / "old-input")
                leaf.write_bytes(b"selected input")
                leaf.chmod(0o400)
                with self.assertRaises(ValueError):
                    selected.check()
            finally:
                selected.close()

    def test_mutation_during_hash_and_deadline_close_acquired_handles(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"original")
            path.chmod(0o400)
            original_read = os.read
            changed = False

            def read(fd, count):
                nonlocal changed
                data = original_read(fd, count)
                if data and not changed:
                    changed = True
                    path.chmod(0o600)
                    path.write_bytes(b"replaced")
                    path.chmod(0o400)
                return data

            with (
                mock.patch.object(inputs.os, "read", side_effect=read),
                self.assertRaises(ValueError),
            ):
                inputs.FrozenInput.open(
                    path,
                    hashlib.sha256(b"original").hexdigest(),
                    limit=1024,
                    deadline=time.monotonic_ns() + 1_000_000_000,
                )
            with self.assertRaises(TimeoutError):
                inputs.FrozenInput.open(
                    path,
                    hashlib.sha256(b"replaced").hexdigest(),
                    limit=1024,
                    deadline=time.monotonic_ns() - 1,
                )

    def test_metadata_only_change_during_hash_refuses_matching_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"unchanged bytes")
            path.chmod(0o400)
            original_read = os.read

            def read(fd, count):
                data = original_read(fd, count)
                path.chmod(0o444)
                return data

            selected = None
            try:
                with (
                    mock.patch.object(inputs.os, "read", side_effect=read),
                    self.assertRaises(ValueError),
                ):
                    selected = inputs.FrozenInput.open(
                        path,
                        hashlib.sha256(b"unchanged bytes").hexdigest(),
                        limit=1024,
                        deadline=time.monotonic_ns() + 1_000_000_000,
                    )
            finally:
                if selected is not None:
                    selected.close()

    def test_close_error_consumes_slot_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = self.frozen(Path(directory) / "input")
            original_close = os.close

            def close(fd):
                original_close(fd)
                raise OSError("consumed close failure")

            with (
                mock.patch.object(inputs.os, "close", side_effect=close),
                self.assertRaises(OSError),
            ):
                selected.close()
            self.assertIsNone(selected.fd)
            selected.close()


if __name__ == "__main__":
    unittest.main()
