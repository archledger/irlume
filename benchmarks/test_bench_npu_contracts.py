#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.

import importlib.util
import pathlib
import sys
import tempfile
import unittest

import numpy as np


HERE = pathlib.Path(__file__).resolve().parent
MODELS_BENCH = HERE / "bench_npu_models.py"
PIPELINE_BENCH = HERE / "bench_npu_pipeline.py"


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


models_bench = load_module("bench_npu_models", MODELS_BENCH)
pipeline_bench = load_module("bench_npu_pipeline", PIPELINE_BENCH)


MANIFEST = """\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  first.onnx
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  mesh.tflite
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  second.onnx
"""


class ManifestTests(unittest.TestCase):
    def test_only_tflite_is_excluded_from_openvino_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = pathlib.Path(directory) / "SHA256SUMS"
            manifest.write_text(MANIFEST, encoding="utf-8")
            inventory = models_bench.read_model_inventory(manifest)

        self.assertEqual(inventory.onnx, ("first.onnx", "second.onnx"))
        self.assertEqual(inventory.tflite, ("mesh.tflite",))

    def test_unknown_extensions_duplicates_and_unsafe_names_are_rejected(self) -> None:
        invalid_manifests = (
            MANIFEST + "d" * 64 + "  notes.txt\n",
            MANIFEST + "d" * 64 + "  first.onnx\n",
            "a" * 64 + "  ../first.onnx\n",
            "not-a-checksum  first.onnx\n",
        )
        for content in invalid_manifests:
            with self.subTest(content=content[-80:]):
                with tempfile.TemporaryDirectory() as directory:
                    manifest = pathlib.Path(directory) / "SHA256SUMS"
                    manifest.write_text(content, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        models_bench.read_model_inventory(manifest)


class AllModelRunTests(unittest.TestCase):
    def test_runtime_assignment_is_normalized_only_for_one_exact_device(self) -> None:
        self.assertEqual(models_bench.exact_execution_device("NPU", "NPU"), "NPU")
        self.assertEqual(models_bench.exact_execution_device(["CPU"], "CPU"), "CPU")
        for value in (["CPU", "NPU"], "AUTO", [], None):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    models_bench.exact_execution_device(value, "NPU")

    def test_existing_synthetic_semantic_parity_remains_available(self) -> None:
        parity = models_bench.semantic_parity(
            "flir.onnx",
            ["output"],
            [np.array([[1.0, 0.0]], dtype=np.float32)],
            [np.array([[0.9, 0.1]], dtype=np.float32)],
        )
        self.assertEqual(parity["probability_class_index"], 0)
        self.assertIn("probability_abs_delta", parity)

    def test_every_manifest_onnx_model_must_run_and_report_exact_npu(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest = root / "SHA256SUMS"
            manifest.write_text(MANIFEST, encoding="utf-8")
            for name in ("first.onnx", "second.onnx"):
                (root / name).write_bytes(b"model")
            calls = []

            def run(path: pathlib.Path) -> dict:
                calls.append(path.name)
                return {
                    "model": path.name,
                    "npu_execution_devices": "NPU",
                    "npu_first_infer_ms": 1.0,
                    "output_count": 1,
                    "npu_benchmark": {"npu_busy_delta_us": 1},
                }

            report = models_bench.run_manifest_models(root, manifest, run)

        self.assertEqual(calls, ["first.onnx", "second.onnx"])
        self.assertEqual([item["model"] for item in report["models"]], calls)
        self.assertEqual(report["excluded_tflite"], ["mesh.tflite"])

    def test_missing_skipped_misassigned_or_idle_models_fail(self) -> None:
        valid = {
            "model": "first.onnx",
            "npu_execution_devices": "NPU",
            "npu_first_infer_ms": 1.0,
            "output_count": 1,
            "npu_benchmark": {"npu_busy_delta_us": 1},
        }
        mutations = (
            lambda item: item.update(model="second.onnx"),
            lambda item: item.update(npu_execution_devices="CPU"),
            lambda item: item.update(npu_first_infer_ms=None),
            lambda item: item.update(output_count=0),
            lambda item: item["npu_benchmark"].update(npu_busy_delta_us=0),
        )
        for mutate in mutations:
            item = {
                **valid,
                "npu_benchmark": dict(valid["npu_benchmark"]),
            }
            mutate(item)
            with self.subTest(item=item):
                with self.assertRaises(RuntimeError):
                    models_bench.validate_model_result("first.onnx", item)

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest = root / "SHA256SUMS"
            manifest.write_text(MANIFEST, encoding="utf-8")
            (root / "first.onnx").write_bytes(b"model")
            with self.assertRaises(FileNotFoundError):
                models_bench.run_manifest_models(root, manifest, lambda _: valid)


class PipelineTests(unittest.TestCase):
    def test_all_graphs_infer_and_primary_pipeline_is_explicit(self) -> None:
        inventory = (
            "face_detection_yunet_2023mar.onnx",
            "face_landmark.onnx",
            "glintr100.onnx",
            "blaze_face_short_range.onnx",
            "liveness_vit.onnx",
            "flir.onnx",
        )
        entries = [
            {
                "model": name,
                "execution_devices": "NPU",
                "first_infer_ms": 1.0,
                "inference_count": 5,
                "output_count": 1,
                "npu_busy_delta_us": 1,
            }
            for name in inventory
        ]

        pipeline_bench.validate_compiled_models(inventory, entries)
        self.assertEqual(
            pipeline_bench.primary_pipeline(inventory),
            (
                "face_detection_yunet_2023mar.onnx",
                "face_landmark.onnx",
                "glintr100.onnx",
                "liveness_vit.onnx",
                "flir.onnx",
            ),
        )

    def test_pipeline_rejects_missing_duplicate_misassigned_or_idle_graphs(self) -> None:
        inventory = ("first.onnx", "second.onnx")
        valid = [
            {
                "model": name,
                "execution_devices": "NPU",
                "first_infer_ms": 1.0,
                "inference_count": 5,
                "output_count": 1,
                "npu_busy_delta_us": 1,
            }
            for name in inventory
        ]
        invalid = (
            valid[:1],
            [valid[0], valid[0]],
            [valid[0], {**valid[1], "execution_devices": "CPU"}],
            [valid[0], {**valid[1], "inference_count": 0}],
            [valid[0], {**valid[1], "output_count": 0}],
            [valid[0], {**valid[1], "npu_busy_delta_us": 0}],
        )
        for entries in invalid:
            with self.subTest(entries=entries):
                with self.assertRaises(RuntimeError):
                    pipeline_bench.validate_compiled_models(inventory, entries)


if __name__ == "__main__":
    unittest.main()
