#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Oracle and probe-boundary controls; does not assert known mismatches as desired."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import run
import verify


class ConformanceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run.cv2.setNumThreads(1)
        run.cv2.ocl.setUseOpenCL(False)
        run.cv2.setUseOptimized(False)
        run.cv2.ipp.setUseIPP(False)
        run.compile_probe()

    def test_explicit_encoding_and_range_override_colorspace_defaults(self):
        self.assertEqual(run.resolve_tuple("REC709", "601", "FULL"), ("601", "FULL"))
        self.assertEqual(run.resolve_tuple("SRGB", "DEFAULT", "DEFAULT"), ("601", "LIMITED"))
        self.assertEqual(run.resolve_tuple("JPEG", "DEFAULT", "DEFAULT"), ("601", "FULL"))
        self.assertEqual(run.resolve_tuple("REC709", "DEFAULT", "DEFAULT"), ("709", "LIMITED"))

    def test_unresolved_or_unsupported_tuple_is_not_guessed(self):
        for value in [("DEFAULT", "DEFAULT", "DEFAULT"), ("REC709", "BT2020", "FULL"),
                      ("SRGB", "601", "UNKNOWN")]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                run.resolve_tuple(*value)

    def test_limited_neutral_endpoints_for_both_matrices(self):
        samples = run.np.array([[16, 128, 128], [235, 128, 128]], dtype=run.np.uint8)
        for matrix in ("601", "709"):
            run.np.testing.assert_allclose(run.reference_yuv(samples, matrix, "LIMITED"),
                                           [[0, 0, 0], [255, 255, 255]], rtol=0, atol=1e-12)

    def test_chromatic_full_range_709_and_601_primary_source_anchors(self):
        # Linux 6.10 V4L2 colorspaces-details sections 2.17.1, .2 and .10:
        # 709 Kr=.2126, Kb=.0722; 601 Kr=.299, Kb=.114; full Cb/Cr scale 256.
        # Independently evaluated decimal anchors, not reference_yuv-generated.
        # Separate Cb/Cr inputs catch coefficient, matrix, range and UV swaps.
        samples = run.np.array([[128, 192, 128], [128, 128, 192],
                                [128, 64, 192], [128, 192, 64]], dtype=run.np.uint8)
        expected709 = [[128, 116.05807760067114, 246.2945],
                       [228.3935, 98.15707760067114, 128],
                       [228.3935, 110.099, 9.7055],
                       [27.6065, 145.901, 246.2945]]
        run.np.testing.assert_allclose(run.reference_yuv(samples, "709", "FULL"),
                                       expected709, rtol=0, atol=1e-10)
        run.np.testing.assert_allclose(run.reference_yuv(samples[2:3], "601", "FULL"),
                                       [[217.3775, 104.4125, 15.035]], rtol=0, atol=1e-10)

    def test_baseline_bytes_are_hash_verified_before_extraction(self):
        name = run.SOURCES[0]
        original = run.baseline_source(name)
        with mock.patch.object(run, "command", return_value=original + b"\nchanged"):
            with self.assertRaisesRegex(ValueError, "baseline source hash mismatch"):
                run.baseline_source(name)

    def test_recorded_crop_excludes_surrounding_pixels(self):
        image = run.np.full((64, 64, 3), 255, dtype=run.np.uint8)
        image[18:37, 18:37] = 0
        for name in run.SCORERS:
            tensor, crop = run.recorded_preprocess(name)(image, [24, 24, 31, 31])
            self.assertEqual(crop.shape, (19, 19, 3))
            run.np.testing.assert_array_equal(crop, run.np.zeros_like(crop))
            run.np.testing.assert_array_equal(tensor, -run.np.ones((3, 224, 224)))

    def test_rust_probe_rejects_malformed_inputs(self):
        cases = [(["nv12", "2", "2"], b""), (["yuyv", "3", "2"], bytes(12)),
                 (["pad", "1", "1", "0", "0", "nan", "1"], bytes(3)),
                 (["pad", "1", "1", "1", "0", "0", "1"], bytes(3)),
                 (["pad", "0", "1", "0", "0", "1", "1"], b""),
                 (["camera", "2", "2"], bytes(8))]
        for args, data in cases:
            with self.subTest(args=args):
                process = subprocess.run([str(run.BUILD / "probe"), *args], input=data,
                                         capture_output=True, check=False)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(process.stdout, b"")

    def test_tools_revision_and_checkout_drift_keep_baseline_inputs(self):
        # Git transport is mocked because this test must not create commits.
        # Compilation, source extraction, scorer execution and output are real.
        real_command = run.command
        baseline = {name: real_command("git", "show", f"{run.BASE}:{name}", cwd=run.ROOT)
                    for name in run.SOURCES}
        for changed_checkout in (False, True):
            with self.subTest(changed_checkout=changed_checkout), tempfile.TemporaryDirectory(
                    dir=run.BUILD) as directory:
                root = Path(directory)
                here = root / "benchmarks/preprocessing-conformance"
                here.mkdir(parents=True)
                for name in ("run.py", "probe.rs", "test_probe.py", "verify.py", ".gitignore"):
                    (here / name).write_bytes((run.HERE / name).read_bytes())
                for name, data in baseline.items():
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"changed checkout source; must not execute" if changed_checkout else data)
                (root / "unrelated.txt").write_text("unrelated newer-main change")
                revision = "f" * 40  # Synthetic Git response, never an actual commit.

                def transport(*args, **kwargs):
                    if args == ("git", "rev-parse", "HEAD"):
                        return (revision + "\n").encode()
                    if args[:2] == ("git", "show"):
                        prefix = run.BASE + ":"
                        if not args[2].startswith(prefix):
                            raise AssertionError("probe requested an unpinned source revision")
                        return baseline[args[2][len(prefix):]]
                    return real_command(*args, **kwargs)

                with mock.patch.multiple(run, ROOT=root, HERE=here, BUILD=here / "build"), \
                        mock.patch.object(run, "command", side_effect=transport), \
                        redirect_stdout(io.StringIO()):
                    try:
                        run.main()
                    except ValueError as error:
                        self.fail(f"publishing tools or changing checkout must not reject baseline replay: {error}")
                result = json.loads((here / "results.json").read_text())
                self.assertEqual(result["baseline"], run.BASE)
                self.assertEqual(result["experiment_checkout_revision"], revision)
                self.assertEqual(result["source_sha256"], {name: run.sha(data) for name, data in baseline.items()})
                self.assertEqual(result["extracted_rust_sha256"],
                                 "ffa77e1ab564cc628ca6d10d76ac61c308764dfd8024442650744e65c9ceda68")

    def test_repeat_mismatch_replaces_stale_success_receipt(self):
        with tempfile.TemporaryDirectory(dir=run.BUILD) as directory:
            here = Path(directory)
            receipt = here / "checks.json"
            receipt.write_text('[{"repeat_stdout_identical": true, "results_sha256": "stale"}]')
            calls = 0

            def execute(args, **kwargs):
                nonlocal calls
                calls += 1
                return subprocess.CompletedProcess(args, 0, f"output-{calls}\n", "")

            with mock.patch.object(verify, "HERE", here), \
                    mock.patch.object(verify.subprocess, "run", side_effect=execute):
                with self.assertRaisesRegex(AssertionError, "outputs differ"):
                    verify.main()
            recorded = json.loads(receipt.read_text())
            self.assertIs(recorded[-1]["repeat_stdout_identical"], False)
            self.assertEqual(recorded[-1]["status"], "failed")
            self.assertEqual(len([entry for entry in recorded if "command" in entry]), calls)
            self.assertNotIn("stale", receipt.read_text())

    def test_command_failure_and_launch_error_replace_stale_receipt(self):
        for launch_error in (False, True):
            with self.subTest(launch_error=launch_error), tempfile.TemporaryDirectory(
                    dir=run.BUILD) as directory:
                here = Path(directory)
                receipt = here / "checks.json"
                receipt.write_text('[{"status": "passed", "results_sha256": "stale"}]')

                def execute(args, **kwargs):
                    # An interrupted current run must not retain old success.
                    self.assertEqual(json.loads(receipt.read_text())[-1]["status"], "running")
                    if launch_error:
                        raise FileNotFoundError("synthetic missing executable")
                    return subprocess.CompletedProcess(args, 3, "partial output", "synthetic failure")

                expected = FileNotFoundError if launch_error else RuntimeError
                with mock.patch.object(verify, "HERE", here), \
                        mock.patch.object(verify.subprocess, "run", side_effect=execute):
                    with self.assertRaises(expected):
                        verify.main()
                recorded = json.loads(receipt.read_text())
                self.assertEqual(recorded[-1]["status"], "failed")
                self.assertIn("synthetic", recorded[-1]["error"])
                self.assertEqual(recorded[0]["returncode"], None if launch_error else 3)
                self.assertNotIn("stale", receipt.read_text())


if __name__ == "__main__":
    unittest.main()
