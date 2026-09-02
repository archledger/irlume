#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.

import pathlib
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check-openvino-matrix.py"

VALID = """
status = "experimental"
openvino = "2026.2.0-21903-52ddc073857-releases/2026/2"
level_zero_tag = "v1.28.2"
level_zero_commit = "6369d8d642e9c7625e67f38664267f171b8e42dc"
npu_userspace = "1.35.0.20260722-29947505341"
gpu_status = "disabled-unqualified"
"""


class MatrixCheckerTests(unittest.TestCase):
    def run_checker(self, matrix: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "matrix.toml"
            path.write_text(textwrap.dedent(matrix), encoding="utf-8")
            return subprocess.run(
                ["python3", str(CHECKER), "--matrix", str(path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_accepts_only_the_measured_experimental_npu_matrix(self) -> None:
        result = self.run_checker(VALID)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("experimental NPU matrix valid", result.stdout)

    def test_rejects_missing_provenance(self) -> None:
        result = self.run_checker(VALID.replace('level_zero_tag = "v1.28.2"\n', ""))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("level_zero_tag", result.stderr)

    def test_rejects_a_malformed_commit(self) -> None:
        result = self.run_checker(
            VALID.replace(
                "6369d8d642e9c7625e67f38664267f171b8e42dc",
                "not-a-commit",
            )
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("40 lowercase hexadecimal", result.stderr)

    def test_rejects_release_status_before_release_evidence_exists(self) -> None:
        result = self.run_checker(VALID.replace('status = "experimental"', 'status = "released"'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("status must be experimental", result.stderr)

    def test_rejects_enabled_gpu_without_a_separate_matrix(self) -> None:
        result = self.run_checker(
            VALID.replace('gpu_status = "disabled-unqualified"', 'gpu_status = "enabled-qualified"')
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GPU matrix", result.stderr)


if __name__ == "__main__":
    unittest.main()
