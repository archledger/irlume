#!/usr/bin/env python3
"""Pure validation fixtures; no root commands or camera operations."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('capture_helper', Path(__file__).with_name('irlume-ci-capture.py'))
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class CaptureValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)
        (self.output / 'means.txt').write_text('00 1.0 0.0\n')
        for i in range(6):
            (self.output / f'frame{i:02}.pgm').write_bytes(b'P5\n1 1\n255\n\x01')

    def test_capture_proof_requires_one_exact_positive_outcome(self):
        write = 'irlume: capture emitter write completed'
        default = 'irlume: capture emitter device default verified'
        self.assertEqual(HELPER.capture_proof(write), 'write')
        self.assertEqual(HELPER.capture_proof(default), 'default')
        for diagnostic in ['', 'irlume: capture emitter already held the requested value',
                           'prefix ' + default, default + ' suffix',
                           write + '\n' + default, write + '\n' + write]:
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                HELPER.capture_proof(diagnostic)

    def test_only_fixed_flat_files_are_archived(self):
        self.assertEqual(len(HELPER.archive_paths(self.output)), 7)

    def test_unexpected_names_and_directories_are_rejected(self):
        for name, directory in [('extra.txt', False), ('frame06.pgm', False), ('nested', True)]:
            with self.subTest(name=name):
                path = self.output / name
                path.mkdir() if directory else path.write_text('unexpected')
                with self.assertRaises(ValueError):
                    HELPER.archive_paths(self.output)
                path.rmdir() if directory else path.unlink()

    def test_symlink_is_not_archived(self):
        path = self.output / 'frame00.pgm'
        path.unlink()
        path.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            HELPER.archive_paths(self.output)

    def test_hardlink_is_not_archived(self):
        os.link(self.output / 'frame00.pgm', self.output / 'alias')
        with self.assertRaises(ValueError):
            HELPER.archive_paths(self.output)

    def test_incomplete_capture_is_rejected(self):
        for i in range(3):
            (self.output / f'frame{i:02}.pgm').unlink()
        with self.assertRaises(ValueError):
            HELPER.archive_paths(self.output)

    def test_missing_means_is_rejected(self):
        (self.output / 'means.txt').unlink()
        with self.assertRaises(ValueError):
            HELPER.archive_paths(self.output)

    def test_oversized_capture_is_rejected(self):
        with open(self.output / 'frame00.pgm', 'wb') as stream:
            stream.truncate(HELPER.MAX_ARCHIVE_BYTES + 1)
        with self.assertRaises(ValueError):
            HELPER.archive_paths(self.output)

    def test_unprivileged_call_refused_before_binary_access(self):
        with patch.object(HELPER.os, 'geteuid', return_value=1000), \
             patch.object(HELPER, 'approved_binary') as approve:
            with self.assertRaisesRegex(ValueError, 'requires root'):
                HELPER.capture('a' * 40, '/dev/video2')
            approve.assert_not_called()

    def test_invalid_arguments_refused_before_installed_path_access(self):
        for digest, device in [('bad', '/dev/video2'), ('a' * 40, '/etc/passwd'), ('A' * 40, '/dev/video2')]:
            with self.subTest(digest=digest, device=device), \
                 patch.object(HELPER, 'trusted_metadata') as metadata:
                with self.assertRaises(ValueError):
                    HELPER.approved_binary(digest, device)
                metadata.assert_not_called()

    def test_nonroot_writable_or_symlink_metadata_is_rejected(self):
        # Metadata policy itself is tested independently of the CI user's uid.
        for mode, uid in [(stat.S_IFREG | 0o644, 1000),
                          (stat.S_IFREG | 0o664, 0),
                          (stat.S_IFLNK | 0o777, 0)]:
            info = os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))
            with self.subTest(mode=mode, uid=uid), patch.object(Path, 'lstat', return_value=info):
                with self.assertRaises(ValueError):
                    HELPER.trusted_metadata(Path('/usr/local/lib/irlume-ci/burst_dump'))


if __name__ == '__main__':
    unittest.main()
