#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Fresh phase checks preserve original owners; no service or VM is started."""

import copy
import hashlib
import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixtures = load("phase_fixtures", "test-measurement-job-closure.py")
closure = fixtures.closure
inputs = closure.inputs
rooted = load("phase_rooted", "measurement-job-runtime-tree.py")
rooted_fixtures = load("phase_rooted_fixtures", "test-measurement-job-runtime-tree.py")


class PhaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.path = self.directory / "input.bin"
        self.path.write_bytes(b"selected-input")
        self.path.chmod(0o400)
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.tree = fixtures.TreeTests().make_tree(self.directory)
        self.manifest, self.manifest_digest = closure.prepare_manifest(
            self.tree, fixtures.profile(), deadline=time.monotonic_ns() + 5_000_000_000
        )

    def test_input_recheck_does_not_renew_the_acquisition_deadline(self):
        clock = [199]
        with (
            mock.patch.object(
                inputs.time, "monotonic_ns", side_effect=lambda: clock[0]
            ),
            inputs.FrozenInput.open(
                self.path, self.digest, limit=1024, deadline=200
            ) as owner,
        ):
            fd, offset = owner.fd, os.lseek(owner.fd, 0, os.SEEK_CUR)
            clock[0] = 201
            with self.assertRaises(TimeoutError):
                owner.check()
            owner.recheck(300)
            self.assertEqual(owner.deadline, 200)
            self.assertEqual(owner.fd, fd)
            self.assertEqual(os.lseek(owner.fd, 0, os.SEEK_CUR), offset)
            with self.assertRaises(TimeoutError):
                owner.check()

    def test_input_recheck_rejects_identical_replacement(self):
        with inputs.FrozenInput.open(
            self.path,
            self.digest,
            limit=1024,
            deadline=time.monotonic_ns() + 5_000_000_000,
        ) as owner:
            replacement = self.directory / "replacement"
            replacement.write_bytes(b"selected-input")
            replacement.chmod(0o400)
            replacement.replace(self.path)
            with self.assertRaises(ValueError):
                owner.recheck(time.monotonic_ns() + 5_000_000_000)

    def test_input_phase_reads_hash_even_if_metadata_checks_are_neutralized(self):
        with inputs.FrozenInput.open(
            self.path,
            self.digest,
            limit=1024,
            deadline=time.monotonic_ns() + 5_000_000_000,
        ) as owner:
            identity = inputs.identity(owner.info)
            self.path.chmod(0o600)
            self.path.write_bytes(b"modified-input")
            self.path.chmod(0o400)
            with (
                mock.patch.object(inputs, "identity", return_value=identity),
                self.assertRaises(ValueError),
            ):
                owner.recheck(time.monotonic_ns() + 5_000_000_000)

    def test_runtime_recheck_retains_original_baseline_and_deadline(self):
        clock = [199]
        with (
            mock.patch.object(
                inputs.time, "monotonic_ns", side_effect=lambda: clock[0]
            ),
            closure.RuntimeSnapshot.open(
                self.tree, self.manifest, self.manifest_digest, deadline=200
            ) as owner,
        ):
            baseline = copy.deepcopy(owner.observations)
            fd = owner.fd
            clock[0] = 201
            with self.assertRaises(TimeoutError):
                owner.check()
            owner.recheck(300)
            self.assertEqual(owner.deadline, 200)
            self.assertEqual(owner.observations, baseline)
            self.assertEqual(owner.fd, fd)
            with self.assertRaises(TimeoutError):
                owner.check()

    def test_runtime_phase_hashes_again_without_rebaselining(self):
        with closure.RuntimeSnapshot.open(
            self.tree,
            self.manifest,
            self.manifest_digest,
            deadline=time.monotonic_ns() + 5_000_000_000,
        ) as owner:
            path = self.tree / "opt/irlume/entry.py"
            path.chmod(0o600)
            path.write_bytes(b"fail\n")
            path.chmod(0o400)
            baseline = copy.deepcopy(owner.observations)
            with self.assertRaises(ValueError):
                owner.recheck(time.monotonic_ns() + 5_000_000_000)
            self.assertEqual(owner.observations, baseline)

    def test_rooted_startup_owner_cannot_extend_its_window(self):
        fixture = rooted_fixtures.RootedTreeTests(
            "test_selected_static_members_are_hashed_and_api_directories_are_excluded"
        )
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        with fixture.open() as owner:
            deadline, fd = owner.deadline, owner.fd
            with (
                mock.patch.object(
                    owner, "_scan", side_effect=AssertionError("rooted phase scan")
                ) as scan,
                self.assertRaisesRegex(ValueError, "prepared-tree owner"),
            ):
                owner.recheck(time.monotonic_ns() + 10_000_000_000)
            scan.assert_not_called()
            self.assertEqual(owner.deadline, deadline)
            self.assertEqual(owner.fd, fd)

    def test_runtime_phase_detects_mutation_during_linkage_validation(self):
        with closure.RuntimeSnapshot.open(
            self.tree,
            self.manifest,
            self.manifest_digest,
            deadline=time.monotonic_ns() + 5_000_000_000,
        ) as owner:
            path = self.tree / "opt/irlume/entry.py"
            original = copy.deepcopy(owner.observations)
            deadline, fd = owner.deadline, owner.fd
            verify = closure.verify_linkage

            def mutate(*args):
                result = verify(*args)
                path.chmod(0o600)
                path.write_bytes(b"fail\n")
                path.chmod(0o400)
                return result

            with (
                mock.patch.object(closure, "verify_linkage", side_effect=mutate),
                self.assertRaisesRegex(ValueError, "runtime phase"),
            ):
                owner.recheck(time.monotonic_ns() + 5_000_000_000)
            self.assertNotEqual(
                inputs.identity(path.stat()), original["opt/irlume/entry.py"]
            )
            self.assertEqual(owner.observations, original)
            self.assertEqual(owner.deadline, deadline)
            self.assertEqual(owner.fd, fd)

    def test_runtime_phase_detects_earlier_member_mutation_during_later_read(self):
        with closure.RuntimeSnapshot.open(
            self.tree,
            self.manifest,
            self.manifest_digest,
            deadline=time.monotonic_ns() + 5_000_000_000,
        ) as owner:
            earlier = self.tree / "opt/irlume/entry.py"
            later = (self.tree / "usr/bin/python3").stat()
            read, changed = os.read, []
            original = copy.deepcopy(owner.observations)

            def mutate(fd, size):
                result = read(fd, size)
                info = os.fstat(fd)
                if not changed and (info.st_dev, info.st_ino) == (
                    later.st_dev,
                    later.st_ino,
                ):
                    earlier.chmod(0o600)
                    earlier.write_bytes(b"fail\n")
                    earlier.chmod(0o400)
                    changed.append(True)
                return result

            with (
                mock.patch.object(closure.os, "read", side_effect=mutate),
                self.assertRaisesRegex(ValueError, "runtime phase"),
            ):
                owner.recheck(time.monotonic_ns() + 5_000_000_000)
            self.assertEqual(changed, [True])
            self.assertEqual(owner.observations, original)

    def test_input_phase_expiry_leaves_the_original_owner_intact(self):
        clock = [100]
        with (
            mock.patch.object(
                inputs.time, "monotonic_ns", side_effect=lambda: clock[0]
            ),
            inputs.FrozenInput.open(
                self.path, self.digest, limit=1024, deadline=200
            ) as owner,
        ):
            pread = os.pread

            def expire(fd, count, offset):
                value = pread(fd, count, offset)
                clock[0] = 300
                return value

            clock[0] = 201
            fd = owner.fd
            with (
                mock.patch.object(inputs.os, "pread", side_effect=expire),
                self.assertRaises(TimeoutError),
            ):
                owner.recheck(300)
            self.assertEqual(owner.fd, fd)
            self.assertEqual(owner.deadline, 200)

    def test_runtime_content_hash_is_independent_of_metadata_comparison(self):
        with closure.RuntimeSnapshot.open(
            self.tree,
            self.manifest,
            self.manifest_digest,
            deadline=time.monotonic_ns() + 5_000_000_000,
        ) as owner:
            path = self.tree / "opt/irlume/entry.py"
            path.chmod(0o600)
            path.write_bytes(b"fail\n")
            path.chmod(0o400)
            scan = owner._scan

            def unchanged_metadata(*args):
                members, images, _ = scan(*args)
                return members, images, owner.observations

            with (
                mock.patch.object(owner, "_scan", side_effect=unchanged_metadata),
                self.assertRaises(ValueError),
            ):
                owner.recheck(time.monotonic_ns() + 5_000_000_000)

    def test_closed_runtime_owner_cannot_be_reopened_by_phase_check(self):
        owner = closure.RuntimeSnapshot.open(
            self.tree,
            self.manifest,
            self.manifest_digest,
            deadline=time.monotonic_ns() + 5_000_000_000,
        )
        owner.close()
        before = set(os.listdir("/proc/self/fd"))
        with self.assertRaises(ValueError):
            owner.recheck(time.monotonic_ns() + 5_000_000_000)
        self.assertIsNone(owner.fd)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_runtime_phase_rejects_same_content_new_inode(self):
        with closure.RuntimeSnapshot.open(
            self.tree,
            self.manifest,
            self.manifest_digest,
            deadline=time.monotonic_ns() + 5_000_000_000,
        ) as owner:
            path = self.tree / "opt/irlume/entry.py"
            path.parent.chmod(0o700)
            replacement = path.with_name("replacement")
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o400)
            replacement.replace(path)
            path.parent.chmod(0o500)
            with self.assertRaises(ValueError):
                owner.recheck(time.monotonic_ns() + 5_000_000_000)

    def test_runtime_phase_final_expiry_does_not_change_owner(self):
        clock = [199]
        with (
            mock.patch.object(
                inputs.time, "monotonic_ns", side_effect=lambda: clock[0]
            ),
            closure.RuntimeSnapshot.open(
                self.tree, self.manifest, self.manifest_digest, deadline=200
            ) as owner,
        ):
            clock[0] = 201
            verify = closure.verify_linkage

            def expire(*args):
                result = verify(*args)
                clock[0] = 300
                return result

            with (
                mock.patch.object(closure, "verify_linkage", side_effect=expire),
                self.assertRaises(TimeoutError),
            ):
                owner.recheck(300)
            self.assertEqual(owner.deadline, 200)
            self.assertIsNotNone(owner.fd)

    def test_runtime_final_metadata_scan_uses_phase_deadline_without_rehashing(self):
        clock = [199]
        with (
            mock.patch.object(
                inputs.time, "monotonic_ns", side_effect=lambda: clock[0]
            ),
            closure.RuntimeSnapshot.open(
                self.tree,
                self.manifest,
                self.manifest_digest,
                deadline=200,
            ) as owner,
        ):
            clock[0] = 201
            scan = owner._scan
            scans, reads = [], []
            read = os.read

            def phase_scan(contents, deadline, root_check):
                scans.append((contents, deadline))
                result = scan(contents, deadline, root_check)
                if not contents:
                    clock[0] = 300
                return result

            def phase_read(fd, size):
                reads.append(scans[-1][0])
                return read(fd, size)

            with (
                mock.patch.object(owner, "_scan", side_effect=phase_scan),
                mock.patch.object(closure.os, "read", side_effect=phase_read),
                self.assertRaises(TimeoutError),
            ):
                owner.recheck(300)
            self.assertEqual(scans, [(True, 300), (False, 300)])
            self.assertTrue(reads)
            self.assertTrue(all(reads))
            self.assertEqual(owner.deadline, 200)

    def test_input_phase_rejects_short_read_without_replacing_owner(self):
        with inputs.FrozenInput.open(
            self.path,
            self.digest,
            limit=1024,
            deadline=time.monotonic_ns() + 5_000_000_000,
        ) as owner:
            fd, info = owner.fd, owner.info
            with (
                mock.patch.object(inputs.os, "pread", return_value=b""),
                self.assertRaisesRegex(ValueError, "short input phase read"),
            ):
                owner.recheck(time.monotonic_ns() + 5_000_000_000)
            self.assertEqual(owner.fd, fd)
            self.assertIs(owner.info, info)

    def test_input_phase_rejects_mutation_after_pread_returns_original_bytes(self):
        with inputs.FrozenInput.open(
            self.path,
            self.digest,
            limit=1024,
            deadline=time.monotonic_ns() + 5_000_000_000,
        ) as owner:
            fd, info, deadline = owner.fd, owner.info, owner.deadline
            offset = os.lseek(fd, 0, os.SEEK_CUR)
            pread = os.pread
            returned = []

            def mutate(fd, size, start):
                data = pread(fd, size, start)
                self.path.chmod(0o600)
                self.path.write_bytes(b"modified-input")
                self.path.chmod(0o400)
                returned.append(data)
                return data

            with (
                mock.patch.object(inputs.os, "pread", side_effect=mutate),
                self.assertRaisesRegex(ValueError, "closed or changed input"),
            ):
                owner.recheck(time.monotonic_ns() + 5_000_000_000)
            self.assertEqual(returned, [b"selected-input"])
            self.assertEqual(owner.fd, fd)
            self.assertEqual(owner.deadline, deadline)
            self.assertIs(owner.info, info)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), offset)

    def test_input_phase_honors_deadline_earlier_than_acquisition(self):
        clock = [100]
        with (
            mock.patch.object(
                inputs.time, "monotonic_ns", side_effect=lambda: clock[0]
            ),
            inputs.FrozenInput.open(
                self.path,
                self.digest,
                limit=1024,
                deadline=1000,
            ) as owner,
        ):
            fd, info = owner.fd, owner.info
            offset, pread = os.lseek(fd, 0, os.SEEK_CUR), os.pread

            def expire(fd, size, start):
                data = pread(fd, size, start)
                clock[0] = 200
                return data

            with (
                mock.patch.object(inputs.os, "pread", side_effect=expire),
                self.assertRaises(TimeoutError),
            ):
                owner.recheck(200)
            self.assertEqual(owner.deadline, 1000)
            self.assertEqual(owner.fd, fd)
            self.assertIs(owner.info, info)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), offset)

    def test_runtime_phase_honors_deadline_earlier_than_acquisition(self):
        clock = [100]
        with (
            mock.patch.object(
                inputs.time, "monotonic_ns", side_effect=lambda: clock[0]
            ),
            closure.RuntimeSnapshot.open(
                self.tree,
                self.manifest,
                self.manifest_digest,
                deadline=1000,
            ) as owner,
        ):
            fd, original = owner.fd, copy.deepcopy(owner.observations)
            verify = closure.verify_linkage

            def expire(*args):
                result = verify(*args)
                clock[0] = 200
                return result

            with (
                mock.patch.object(closure, "verify_linkage", side_effect=expire),
                self.assertRaises(TimeoutError),
            ):
                owner.recheck(200)
            self.assertEqual(owner.deadline, 1000)
            self.assertEqual(owner.fd, fd)
            self.assertEqual(owner.observations, original)


if __name__ == "__main__":
    unittest.main()
