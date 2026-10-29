#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Closed startup artifact I/O with private temporary directories only."""

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
SPEC = importlib.util.spec_from_file_location(
    "witness_file", HERE / "measurement-job-witness-file.py"
)
files = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(files)


class WitnessFileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(self.close_directory)
        info = os.fstat(self.fd)
        self.identity = (info.st_dev, info.st_ino)
        self.data = b'{"scope":"synthetic"}'
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.deadline = time.monotonic_ns() + 5_000_000_000

    def close_directory(self):
        fd, self.fd = self.fd, None
        if fd is not None:
            os.close(fd)

    def write(self, **kwargs):
        return files.write_closed(
            self.fd, self.identity, self.data, self.digest, self.deadline, **kwargs
        )

    def read(self, metadata, **kwargs):
        return files.read_closed(
            self.fd, self.identity, metadata, self.deadline, **kwargs
        )

    def test_round_trip_closed_readonly_artifact_without_fd_leaks(self):
        before = set(os.listdir("/proc/self/fd"))
        metadata = self.write()
        self.assertEqual(self.read(metadata), self.data)
        self.assertEqual(metadata["mode"], 0o100400)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        self.assertEqual(os.fstat(self.fd).st_ino, self.identity[1])

    def test_existing_name_is_not_overwritten(self):
        path = self.directory / files.NAME
        path.write_bytes(b"previous evidence")
        with self.assertRaises(FileExistsError):
            self.write()
        self.assertEqual(path.read_bytes(), b"previous evidence")

    def test_replacement_with_identical_bytes_is_not_the_selected_file(self):
        metadata = self.write()
        replacement = self.directory / "replacement"
        replacement.write_bytes(self.data)
        replacement.chmod(0o400)
        replacement.replace(self.directory / files.NAME)
        with self.assertRaises(ValueError):
            self.read(metadata)

    def test_fifo_and_symlink_refuse_without_waiting(self):
        metadata = self.write()
        path = self.directory / files.NAME
        path.unlink()
        os.mkfifo(path, 0o400)
        with self.assertRaises(ValueError):
            self.read(metadata)
        path.unlink()
        path.symlink_to("missing")
        with self.assertRaises(OSError):
            self.read(metadata)

    def test_wrong_directory_and_wrong_digest_refuse_before_creation(self):
        with self.assertRaises(ValueError):
            files.write_closed(
                self.fd,
                (self.identity[0], self.identity[1] + 1),
                self.data,
                self.digest,
                self.deadline,
            )
        with self.assertRaises(ValueError):
            files.write_closed(
                self.fd, self.identity, self.data, "f" * 64, self.deadline
            )
        self.assertFalse((self.directory / files.NAME).exists())

    def test_short_writes_work_and_zero_writes_leave_only_failed_data(self):
        write = os.write
        with mock.patch.object(
            files.os, "write", side_effect=lambda fd, data: write(fd, data[:3])
        ):
            metadata = self.write()
        self.assertEqual(self.read(metadata), self.data)
        (self.directory / files.NAME).unlink()
        with (
            mock.patch.object(files.os, "write", return_value=0),
            self.assertRaises(OSError),
        ):
            self.write()
        self.assertTrue((self.directory / files.NAME).exists())

    def test_wrong_metadata_types_and_byte_limits_refuse(self):
        metadata = self.write()
        for field, value in (
            ("inode", True),
            ("mtime_ns", False),
            ("size", files.LIMIT + 1),
            ("sha256", "bad"),
            ("links", 2),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.read(dict(metadata, **{field: value}))
        with self.assertRaises(ValueError):
            files.write_closed(
                self.fd,
                self.identity,
                b"x" * (files.LIMIT + 1),
                self.digest,
                self.deadline,
            )

    def test_changed_permissions_and_nonprivate_directory_refuse(self):
        metadata = self.write()
        path = self.directory / files.NAME
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            self.read(metadata)
        self.directory.chmod(0o750)
        with self.assertRaises(ValueError):
            self.read(metadata)

    def test_same_identity_with_wrong_contents_fails_digest(self):
        metadata = self.write()
        path = self.directory / files.NAME
        path.chmod(0o600)
        path.write_bytes(b"!" * len(self.data))
        path.chmod(0o400)
        metadata = files.metadata(path.stat(), metadata["sha256"])
        with self.assertRaisesRegex(ValueError, "content changed"):
            self.read(metadata)

    def test_path_replacement_during_read_is_detected(self):
        metadata = self.write()
        read = os.read
        changed = [False]

        def replace(fd, count):
            data = read(fd, count)
            if not changed[0]:
                changed[0] = True
                path = self.directory / "replacement"
                path.write_bytes(self.data)
                path.chmod(0o400)
                path.replace(self.directory / files.NAME)
            return data

        with (
            mock.patch.object(files.os, "read", side_effect=replace),
            self.assertRaisesRegex(ValueError, "identity changed"),
        ):
            self.read(metadata)

    def test_sync_and_close_expiry_never_return_success(self):
        original_sync, original_close = os.fsync, os.close
        for phase in ("sync", "close"):
            clock = [100]

            def late_sync(fd, clock=clock):
                original_sync(fd)
                clock[0] = 1000

            def late_close(fd, clock=clock):
                original_close(fd)
                clock[0] = 1000

            function = late_sync if phase == "sync" else late_close
            operation = "fsync" if phase == "sync" else "close"
            before = set(os.listdir("/proc/self/fd"))
            with (
                mock.patch.object(files.os, operation, side_effect=function),
                self.subTest(phase=phase),
                self.assertRaises(TimeoutError),
            ):
                files.write_closed(
                    self.fd,
                    self.identity,
                    self.data,
                    self.digest,
                    1000,
                    clock=lambda clock=clock: clock[0],
                )
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)
            (self.directory / files.NAME).unlink()

    def test_reader_close_failure_preserves_primary_failure(self):
        metadata = self.write()
        close = os.close

        def failed_close(fd):
            close(fd)
            raise OSError("injected close")

        before = set(os.listdir("/proc/self/fd"))
        with (
            mock.patch.object(
                files.os, "read", side_effect=ValueError("injected read")
            ),
            mock.patch.object(files.os, "close", side_effect=failed_close),
            self.assertRaises(BaseExceptionGroup) as caught,
        ):
            self.read(metadata)
        self.assertIsInstance(caught.exception.exceptions[0], ValueError)
        self.assertIsInstance(caught.exception.exceptions[1], OSError)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_reader_late_close_refuses_after_releasing_file(self):
        metadata = self.write()
        clock = [100]
        close = os.close

        def late_close(fd):
            close(fd)
            clock[0] = 1000

        before = set(os.listdir("/proc/self/fd"))
        with (
            mock.patch.object(files.os, "close", side_effect=late_close),
            self.assertRaises(TimeoutError),
        ):
            files.read_closed(
                self.fd, self.identity, metadata, 1000, clock=lambda: clock[0]
            )
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_metadata_validator_rejects_invalid_scalar_and_permissions_directly(self):
        metadata = self.write()
        for field, value in (
            ("mode", 0o100600),
            ("mtime_ns", False),
            ("size", files.LIMIT + 1),
            ("sha256", "X" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                files.check_metadata(dict(metadata, **{field: value}))

    def test_directory_identity_check_is_independent(self):
        with self.assertRaises(ValueError):
            files.check_directory(self.fd, (self.identity[0], self.identity[1] + 1))
        self.directory.chmod(0o750)
        with self.assertRaises(ValueError):
            files.check_directory(self.fd, self.identity)

    def test_selected_valid_target_does_not_make_symlink_acceptable(self):
        self.write()
        path = self.directory / files.NAME
        target = self.directory / "saved"
        path.rename(target)
        metadata = files.metadata(target.stat(), self.digest)
        path.symlink_to(target.name)
        with (
            mock.patch.object(
                files.os, "read", side_effect=AssertionError("read through symlink")
            ),
            self.assertRaises(OSError),
        ):
            self.read(metadata)

    def test_oversized_write_does_not_create_partial_artifact(self):
        data = b"x" * (files.LIMIT + 1)
        with self.assertRaises(ValueError):
            files.write_closed(
                self.fd,
                self.identity,
                data,
                hashlib.sha256(data).hexdigest(),
                self.deadline,
            )
        self.assertFalse((self.directory / files.NAME).exists())

    def test_independently_opened_directory_descriptors_share_the_selected_artifact(
        self,
    ):
        reader = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            metadata = self.write()
            self.assertNotEqual(reader, self.fd)
            self.assertEqual(
                files.read_closed(reader, self.identity, metadata, self.deadline),
                self.data,
            )
            self.assertEqual(os.fstat(reader).st_ino, self.identity[1])
            self.assertEqual(os.fstat(self.fd).st_ino, self.identity[1])
        finally:
            os.close(reader)

    def test_writer_failure_and_cancellation_both_preserve_close_failure(self):
        close = os.close

        def failed_close(fd):
            close(fd)
            raise OSError("injected writer close")

        for cancelled in (False, True):
            before = set(os.listdir("/proc/self/fd"))
            options = (
                {"side_effect": KeyboardInterrupt("cancelled")}
                if cancelled
                else {"return_value": 0}
            )
            with (
                mock.patch.object(files.os, "write", **options),
                mock.patch.object(files.os, "close", side_effect=failed_close),
                self.subTest(cancelled=cancelled),
                self.assertRaises(BaseExceptionGroup) as caught,
            ):
                self.write()
            self.assertIsInstance(
                caught.exception.exceptions[0],
                KeyboardInterrupt if cancelled else OSError,
            )
            self.assertIsInstance(caught.exception.exceptions[1], OSError)
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)
            self.assertEqual(os.fstat(self.fd).st_ino, self.identity[1])
            (self.directory / files.NAME).unlink()

    def test_codec_artifact_round_trip_rejects_different_expected_binding(self):
        spec = importlib.util.spec_from_file_location(
            "artifact_codec_fixture", HERE / "test-measurement-job-startup-witness.py"
        )
        fixture_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture_module)
        fixture = fixture_module.WitnessTests(
            "test_lossless_canonical_round_trip_without_authority"
        )
        self.addCleanup(fixture.doCleanups)
        # Startup observes stdio only; artifact handles belong to the next phase.
        self.close_directory()
        try:
            fixture.setUp()
        finally:
            self.fd = os.open(
                self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
        encoded, digest = fixture.encode()
        metadata = files.write_closed(
            self.fd, self.identity, encoded, digest, self.deadline
        )
        observed = files.read_closed(self.fd, self.identity, metadata, self.deadline)
        self.assertEqual(fixture.decode(observed, digest), fixture.observation)
        fixture.binding["guardian_pid"] += 1
        with self.assertRaises(ValueError):
            fixture.decode(observed, digest)


if __name__ == "__main__":
    unittest.main()
