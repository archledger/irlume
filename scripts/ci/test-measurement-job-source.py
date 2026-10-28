#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Local H/G/E imports must execute source even with a matching stale cache."""

import hashlib
import importlib.util
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = (
    "measurement-job.py",
    "measurement-job-runtime.py",
    "measurement-job-evidence.py",
    "measurement-job-boot.py",
    "measurement-job-guardian.py",
    "measurement-job-guardian-native.py",
    "measurement-job-guardian-service.py",
    "measurement-job-guardian-host.py",
)
ENTRIES = (
    "measurement-job-evidence.py",
    "measurement-job-boot.py",
    "measurement-job-guardian.py",
    "measurement-job-guardian-native.py",
    "measurement-job-guardian-host.py",
)


class SourceImportTests(unittest.TestCase):
    def test_h_g_e_ignore_timestamp_and_unchecked_hash_bytecode(self):
        for invalidation in (
            py_compile.PycInvalidationMode.TIMESTAMP,
            py_compile.PycInvalidationMode.UNCHECKED_HASH,
        ):
            with (
                self.subTest(mode=invalidation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                for name in FILES:
                    path = root / name
                    original = (HERE / name).read_bytes()
                    poison = b'raise RuntimeError("stale local bytecode executed")\n'
                    path.write_bytes(poison + b"#" * (len(original) - len(poison)))
                    stamp = path.stat().st_mtime_ns
                    py_compile.compile(
                        str(path),
                        cfile=str(
                            root
                            / "__pycache__"
                            / f"{path.stem}.{sys.implementation.cache_tag}.pyc"
                        ),
                        doraise=True,
                        invalidation_mode=invalidation,
                        optimize=0,
                    )
                    path.write_bytes(original)
                    os.utime(path, ns=(stamp, stamp))
                # Prove the child can consume the poison, not just that the
                # source-only loader happens to succeed with an unused cache.
                control = """import importlib.util,sys
s=importlib.util.spec_from_file_location('poison_control',sys.argv[1])
m=importlib.util.module_from_spec(s)
s.loader.exec_module(m)
"""
                for name in FILES:
                    result = subprocess.run(
                        [sys.executable, "-I", "-B", "-c", control, str(root / name)],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0, name)
                    self.assertIn("stale local bytecode executed", result.stderr, name)
                probe = """import pathlib,sys
p=pathlib.Path(sys.argv[1])
scope={"__name__":"source_probe","__file__":str(p)}
exec(compile(p.read_bytes(),str(p),"exec",dont_inherit=True),scope)
print("source-only import completed")
"""
                for name in ENTRIES:
                    with self.subTest(entry=name):
                        result = subprocess.run(
                            [sys.executable, "-I", "-B", "-c", probe, str(root / name)],
                            capture_output=True,
                            text=True,
                            timeout=10,
                            check=False,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(
                            result.stdout.strip(), "source-only import completed"
                        )

    def test_native_loader_records_exact_compiled_source_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in FILES:
                shutil.copy2(HERE / name, root / name)
            path = root / "measurement-job-guardian-native.py"
            spec = importlib.util.spec_from_file_location("source_probe", path)
            native = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(native)
            module = native.load("loaded_source", root / "measurement-job-runtime.py")
            self.assertEqual(
                module.__source_sha256__,
                hashlib.sha256(
                    (root / "measurement-job-runtime.py").read_bytes()
                ).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
