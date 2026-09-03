#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.

import pathlib
import re
import subprocess
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER = pathlib.Path(__file__).with_name("run-openvino-hardware.sh")
WORKFLOW = ROOT / ".github/workflows/openvino-hardware.yml"
ACTIONLINT_CONFIG = ROOT / ".github/actionlint.yaml"


class WorkflowTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.text)
        cls.triggers = cls.workflow.get("on", cls.workflow.get(True))
        cls.job = cls.workflow["jobs"]["evidence"]

    def test_only_manual_and_scheduled_trusted_triggers_exist(self) -> None:
        self.assertEqual(set(self.triggers), {"workflow_dispatch", "schedule"})
        self.assertTrue(self.triggers["schedule"])

    def test_permissions_runner_timeout_and_single_non_canceling_group_are_exact(self) -> None:
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertEqual(self.workflow["concurrency"], {"group": "openvino-hardware", "cancel-in-progress": False})
        self.assertEqual(self.job["runs-on"], ["self-hosted", "lunar-lake", "npu"])
        self.assertEqual(self.job["timeout-minutes"], 45)

    def test_checkout_uses_repository_main_and_every_action_is_sha_pinned(self) -> None:
        action_steps = [step for step in self.job["steps"] if "uses" in step]
        self.assertGreaterEqual(len(action_steps), 2)
        for step in action_steps:
            self.assertRegex(step["uses"], r"^[^@]+@[0-9a-f]{40}$")
        checkout = action_steps[0]
        self.assertTrue(checkout["uses"].startswith("actions/checkout@"))
        self.assertEqual(checkout["with"], {"persist-credentials": False, "ref": "refs/heads/main"})

    def test_only_the_bounded_json_evidence_is_uploaded(self) -> None:
        upload = next(step for step in self.job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
        self.assertEqual(upload["with"]["path"], "${{ runner.temp }}/openvino-evidence.json")
        self.assertNotIn("if", upload)

    def test_workflow_invokes_runner_with_trusted_commit_and_output_only(self) -> None:
        run_step = next(step for step in self.job["steps"] if step.get("name") == "Run trusted OpenVINO hardware gate")
        self.assertEqual(
            run_step["run"].strip(),
            'bash scripts/hardware/run-openvino-hardware.sh "$(git rev-parse HEAD)" "$RUNNER_TEMP/openvino-evidence.json"',
        )

    def test_custom_runner_labels_are_declared_for_actionlint(self) -> None:
        config = yaml.safe_load(ACTIONLINT_CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(
            config,
            {
                "self-hosted-runner": {
                    "labels": ["arch", "ir-camera", "tpm", "ci", "cachyos", "n100", "lunar-lake", "npu"]
                }
            },
        )


class RunnerContractTests(unittest.TestCase):
    def test_shell_parses_and_rejects_wrong_argument_count(self) -> None:
        syntax = subprocess.run(["bash", "-n", str(RUNNER)], text=True, capture_output=True, check=False)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        no_args = subprocess.run(["bash", str(RUNNER)], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(no_args.returncode, 2)

    def test_wrong_commit_is_rejected_before_runtime_or_hardware_access(self) -> None:
        result = subprocess.run(
            ["bash", str(RUNNER), "0" * 40, "/tmp/opencode/never-published.json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact-head mismatch", result.stderr)
        self.assertFalse(pathlib.Path("/tmp/opencode/never-published.json").exists())

    def test_runner_accepts_no_caller_runtime_paths_and_uses_the_verified_matrix(self) -> None:
        text = RUNNER.read_text(encoding="utf-8")
        self.assertIn('runtime_root="/tmp/opencode/npu-spike"', text)
        self.assertIn("packaging/openvino/matrix.toml", text)
        self.assertIn("scripts/check-openvino-matrix.py", text)
        self.assertNotIn("OPENVINO_LIBS=$", text)
        self.assertNotIn("LEVEL_ZERO_LIBS=$", text)
        self.assertNotIn("NPU_LIBS=$", text)

    def test_runner_executes_all_required_hardware_and_negative_gates(self) -> None:
        text = RUNNER.read_text(encoding="utf-8")
        required = (
            "every_manifest_onnx_model_runs_deterministically_on_exact_npu",
            "available_devices_are_sanitized_and_assignment_must_be_exact",
            "openvino_cache_is_versioned_and_distinguishes_clean_warm_and_changed_runtime",
            "openvino_cache_rebuild_is_bounded_to_one_clear",
            "bench_npu_models.py",
            "bench_npu_pipeline.py",
            "validate-openvino-hardware.py",
        )
        for marker in required:
            self.assertIn(marker, text)

    def test_runner_bridges_the_versioned_wheel_c_api_for_openvino_rs(self) -> None:
        text = RUNNER.read_text(encoding="utf-8")
        self.assertIn('libopenvino_c.so.*', text)
        self.assertIn('openvino-link/libopenvino_c.so', text)
        self.assertIn('ln -s --', text)


if __name__ == "__main__":
    unittest.main()
