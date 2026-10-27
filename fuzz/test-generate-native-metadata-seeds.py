#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Regression checks for source-generated ELF fuzz seeds."""

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("generate-native-metadata-seeds.py")
HASHES = {
    "needed.elf": "7459d649b46e81e0a810a039fd98c915e19e5f6728ddfd5580684b6b8f4a289e",
    "truncated.elf": "d48d637e2d4e7143e4ad098f7986d200977dbbdfad4d17b3c70a66f4f67d6d1e",
}


class SeedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="irlume-seeds-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.corpus = self.root / "corpus"

    def generate(self, expected=0):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.corpus)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_exact_original_bytes_and_non_executable_modes(self):
        self.generate()
        self.assertEqual({p.name for p in self.corpus.iterdir()}, set(HASHES))
        for name, expected in HASHES.items():
            path = self.corpus / name
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        needed = (self.corpus / "needed.elf").read_bytes()
        self.assertEqual(len(needed), 255)
        self.assertEqual((self.corpus / "truncated.elf").read_bytes(), needed[:180])

    def test_repeated_generation_keeps_existing_files(self):
        self.generate()
        before = {
            p.name: (p.stat().st_ino, p.stat().st_mtime_ns)
            for p in self.corpus.iterdir()
        }
        self.generate()
        self.assertEqual(
            {
                p.name: (p.stat().st_ino, p.stat().st_mtime_ns)
                for p in self.corpus.iterdir()
            },
            before,
        )

    def test_conflicting_seed_fails_without_overwrite(self):
        self.corpus.mkdir()
        path = self.corpus / "needed.elf"
        path.write_bytes(b"keep different existing bytes")
        self.generate(expected=1)
        self.assertEqual(path.read_bytes(), b"keep different existing bytes")

    def test_symlink_seed_is_not_followed_or_overwritten(self):
        self.corpus.mkdir()
        outside = self.root / "outside"
        outside.write_bytes(b"keep outside")
        path = self.corpus / "needed.elf"
        path.symlink_to(outside)
        self.generate(expected=1)
        self.assertTrue(path.is_symlink())
        self.assertEqual(outside.read_bytes(), b"keep outside")

    def test_matching_symlink_is_still_rejected(self):
        self.generate()
        path = self.corpus / "needed.elf"
        outside = self.root / "outside"
        path.rename(outside)
        path.symlink_to(outside)
        self.generate(expected=1)
        self.assertTrue(path.is_symlink())
        self.assertEqual(
            hashlib.sha256(outside.read_bytes()).hexdigest(), HASHES[path.name]
        )

    def test_non_regular_seed_fails_without_blocking(self):
        self.corpus.mkdir()
        path = self.corpus / "needed.elf"
        os.mkfifo(path)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.corpus)],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_leaves_other_corpus_inputs_untouched(self):
        self.corpus.mkdir()
        extra = self.corpus / "discovered-input"
        extra.write_bytes(b"retained fuzz finding")
        self.generate()
        self.assertEqual(extra.read_bytes(), b"retained fuzz finding")

    def test_missing_output_argument_fails(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)], capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 2)

    def test_ci_generates_and_tests_before_native_metadata_fuzzing(self):
        workflow = SCRIPT.parent.parent / ".github/workflows/ci.yml"
        text = workflow.read_text()
        self.assertIn("python3 test-generate-native-metadata-seeds.py", text)
        self.assertIn('python3 generate-native-metadata-seeds.py "corpus/$t"', text)
        self.assertIn('if [ "$t" = native_metadata ]; then', text)
        self.assertLess(
            text.index('python3 generate-native-metadata-seeds.py "corpus/$t"'),
            text.index('cargo fuzz run "$t"'),
        )
        self.assertNotIn('generate-native-metadata-seeds.py "corpus/$t" ||', text)


if __name__ == "__main__":
    unittest.main()
