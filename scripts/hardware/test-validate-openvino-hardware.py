#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.

import copy
import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
VALIDATOR = pathlib.Path(__file__).with_name("validate-openvino-hardware.py")
MANIFEST = ROOT / "models/SHA256SUMS"
MATRIX = ROOT / "packaging/openvino/matrix.toml"


def inventory() -> tuple[list[str], dict[str, str]]:
    names = []
    checksums = {}
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        checksum, name = raw.split()
        if name.endswith(".onnx"):
            names.append(name)
            checksums[name] = checksum
    return names, checksums


def valid_reports() -> tuple[dict, dict]:
    names, checksums = inventory()
    models = {
        "kind": "irlume.openvino.models",
        "schema_version": 1,
        "manifest_models": names,
        "excluded_tflite": ["face_landmarks_detector.tflite"],
        "models": [
            {
                "model": name,
                "model_sha256": checksums[name],
                "shape": [1, 3, 4, 4],
                "npu_driver_version": "driver",
                "npu_compiler_version": "compiler",
                "cpu_compile_ms": 2.0,
                "cpu_execution_devices": "CPU",
                "cpu_first_infer_ms": 1.0,
                "cpu_benchmark": {"mean_ms": 1.0},
                "npu_compile_ms": 2.0,
                "npu_execution_devices": "NPU",
                "npu_first_infer_ms": 1.0,
                "npu_benchmark": {"npu_busy_delta_us": 10, "mean_ms": 1.0},
                "output_count": 1,
                "outputs": [{"max_abs": 0.1}],
                "semantic_parity": {"same_threshold_side": True},
            }
            for name in names
        ],
    }
    primary = [
        "face_detection_yunet_2023mar.onnx",
        "face_landmark.onnx",
        "glintr100.onnx",
        "liveness_vit.onnx",
        "flir.onnx",
    ]
    pipeline = {
        "kind": "irlume.openvino.pipeline",
        "schema_version": 1,
        "manifest_models": names,
        "excluded_tflite": ["face_landmarks_detector.tflite"],
        "full_device_name": "Intel(R) AI Boost",
        "device_total_mem_size": 1,
        "bypass_umd_cache": False,
        "compiled_models": [
            {
                "model": name,
                "compile_ms": 1.0,
                "execution_devices": "NPU",
                "first_infer_ms": 1.0,
                "inference_count": 5,
                "output_count": 1,
                "npu_busy_delta_us": 10,
                "npu_memory_utilization": 1,
            }
            for name in names
        ],
        "primary_pipeline": {
            "models": primary,
            "iterations": 30,
            "wall_ms": 10.0,
            "process_cpu_ms": 1.0,
            "process_cpu_core_percent": 10.0,
            "npu_busy_delta_us": 100,
            "round": {"mean_ms": 1.0},
            "stages": {name: {"mean_ms": 1.0} for name in primary},
        },
    }
    return models, pipeline


class ValidatorTests(unittest.TestCase):
    def run_validator(self, models: dict, pipeline: dict, *, matrix: pathlib.Path = MATRIX):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            models_path = root / "models.json"
            pipeline_path = root / "pipeline.json"
            models_path.write_text(json.dumps(models), encoding="utf-8")
            pipeline_path.write_text(json.dumps(pipeline), encoding="utf-8")
            return subprocess.run(
                [
                    "python3",
                    str(VALIDATOR),
                    "--models",
                    str(models_path),
                    "--pipeline",
                    str(pipeline_path),
                    "--matrix",
                    str(matrix),
                    "--commit",
                    "a" * 40,
                    "--rust-adapter-passed",
                    "--assignment-negative-passed",
                    "--cache-contracts-passed",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def assert_rejected(self, mutate) -> None:
        models, pipeline = valid_reports()
        mutate(models, pipeline)
        result = self.run_validator(models, pipeline)
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_valid_reports_emit_only_the_bounded_evidence_schema(self) -> None:
        result = self.run_validator(*valid_reports())
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(
            set(evidence),
            {"kind", "schema_version", "commit", "matrix", "gates", "models", "pipeline"},
        )
        self.assertEqual(len(evidence["models"]), 6)
        self.assertEqual(
            set(evidence["models"][0]),
            {
                "model",
                "model_sha256",
                "execution_devices",
                "first_infer_ms",
                "output_count",
                "npu_busy_delta_us",
            },
        )
        self.assertNotIn("shape", result.stdout)
        self.assertNotIn("compiler", result.stdout)

    def test_exact_inventory_assignment_inference_and_busy_time_are_required(self) -> None:
        mutations = (
            lambda models, _: models["models"].pop(),
            lambda models, _: models["models"][0].update(model="other.onnx"),
            lambda models, _: models["models"][0].update(model_sha256="0" * 64),
            lambda models, _: models.update(schema_version=True),
            lambda models, _: models["models"][0].update(npu_execution_devices="CPU"),
            lambda models, _: models["models"][0].update(npu_first_infer_ms=None),
            lambda models, _: models["models"][0].update(output_count=0),
            lambda models, _: models["models"][0]["npu_benchmark"].update(npu_busy_delta_us=0),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_pipeline_requires_all_model_residency_inference_and_positive_busy_time(self) -> None:
        mutations = (
            lambda _, pipeline: pipeline["compiled_models"].pop(),
            lambda _, pipeline: pipeline["compiled_models"][0].update(execution_devices="CPU"),
            lambda _, pipeline: pipeline["compiled_models"][0].update(inference_count=0),
            lambda _, pipeline: pipeline["compiled_models"][0].update(output_count=0),
            lambda _, pipeline: pipeline["compiled_models"][0].update(npu_busy_delta_us=0),
            lambda _, pipeline: pipeline["primary_pipeline"].update(npu_busy_delta_us=0),
            lambda _, pipeline: pipeline["primary_pipeline"]["models"].reverse(),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_tflite_is_reported_separately_and_never_as_openvino_assignment(self) -> None:
        self.assert_rejected(
            lambda models, _: models["models"].append(
                {
                    **copy.deepcopy(models["models"][0]),
                    "model": "face_landmarks_detector.tflite",
                }
            )
        )
        self.assert_rejected(lambda models, _: models.update(excluded_tflite=[]))

    def test_duplicate_members_nonstandard_numbers_and_oversized_inputs_are_rejected(self) -> None:
        models, pipeline = valid_reports()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            models_path = root / "models.json"
            pipeline_path = root / "pipeline.json"
            encoded = json.dumps(models)
            models_path.write_text(
                encoded.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1),
                encoding="utf-8",
            )
            pipeline_path.write_text(json.dumps(pipeline), encoding="utf-8")
            command = [
                "python3",
                str(VALIDATOR),
                "--models",
                str(models_path),
                "--pipeline",
                str(pipeline_path),
                "--matrix",
                str(MATRIX),
                "--commit",
                "a" * 40,
                "--rust-adapter-passed",
                "--assignment-negative-passed",
                "--cache-contracts-passed",
            ]
            duplicate = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertNotEqual(duplicate.returncode, 0)
            models_path.write_text(json.dumps(models) + " " * 1_100_000, encoding="utf-8")
            oversized = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertNotEqual(oversized.returncode, 0)


if __name__ == "__main__":
    unittest.main()
