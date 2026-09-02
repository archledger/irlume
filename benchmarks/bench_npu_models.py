#!/usr/bin/env python3
"""Benchmark every shipped ONNX model on OpenVINO CPU and explicit NPU."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import re
import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any


MODEL_RANGES = {
    "blaze_face_short_range.onnx": (-1.0, 1.0),
    "face_detection_yunet_2023mar.onnx": (0.0, 255.0),
    "face_landmark.onnx": (0.0, 1.0),
    "flir.onnx": (-1.0, 1.0),
    "glintr100.onnx": (-1.0, 1.0),
    "liveness_vit.onnx": (-1.0, 1.0),
}
BUSY_PATH = Path("/sys/class/accel/accel0/device/npu_busy_time_us")
CHECKSUM = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ModelInventory:
    onnx: tuple[str, ...]
    tflite: tuple[str, ...]
    checksums: dict[str, str]


def read_model_inventory(manifest: Path) -> ModelInventory:
    onnx: list[str] = []
    tflite: list[str] = []
    checksums: dict[str, str] = {}
    for line_number, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        parts = raw.split()
        if len(parts) != 2 or CHECKSUM.fullmatch(parts[0]) is None:
            raise ValueError(f"invalid checksum entry at line {line_number}")
        name = parts[1]
        if PurePath(name).name != name or name in checksums:
            raise ValueError(f"unsafe or duplicate model name at line {line_number}")
        if name.endswith(".onnx"):
            onnx.append(name)
        elif name.endswith(".tflite"):
            tflite.append(name)
        else:
            raise ValueError(f"unsupported model type at line {line_number}")
        checksums[name] = parts[0]
    if not onnx:
        raise ValueError("manifest contains no ONNX models")
    return ModelInventory(tuple(onnx), tuple(tflite), checksums)


def validate_model_result(expected_name: str, result: dict[str, Any]) -> None:
    if result.get("model") != expected_name:
        raise RuntimeError(f"benchmark skipped or reordered {expected_name}")
    if result.get("npu_execution_devices") != "NPU":
        raise RuntimeError(f"{expected_name} was not assigned exactly to NPU")
    first_infer = result.get("npu_first_infer_ms")
    if isinstance(first_infer, bool) or not isinstance(first_infer, (int, float)) or not math.isfinite(first_infer) or first_infer < 0:
        raise RuntimeError(f"{expected_name} did not report NPU inference")
    if type(result.get("output_count")) is not int or result["output_count"] <= 0:
        raise RuntimeError(f"{expected_name} produced no outputs")
    benchmark_report = result.get("npu_benchmark")
    if not isinstance(benchmark_report, dict) or type(benchmark_report.get("npu_busy_delta_us")) is not int or benchmark_report["npu_busy_delta_us"] <= 0:
        raise RuntimeError(f"{expected_name} did not move NPU busy time")


def run_manifest_models(
    models_dir: Path,
    manifest: Path,
    run_model: Callable[[Path], dict[str, Any]],
) -> dict[str, Any]:
    inventory = read_model_inventory(manifest)
    reports = []
    for name in inventory.onnx:
        path = models_dir / name
        if not path.is_file():
            raise FileNotFoundError(f"manifest model is missing: {name}")
        report = run_model(path)
        validate_model_result(name, report)
        reports.append(report)
    return {
        "kind": "irlume.openvino.models",
        "schema_version": 1,
        "manifest_models": list(inventory.onnx),
        "excluded_tflite": list(inventory.tflite),
        "models": reports,
    }


def elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1_000.0


def concrete_shape(model: Any) -> tuple[int, ...]:
    port = model.input(0)
    shape = [
        1 if dimension.is_dynamic else dimension.get_length()
        for dimension in port.partial_shape
    ]
    if port.partial_shape.is_dynamic:
        model.reshape({port: shape})
    return tuple(shape)


def make_input(np: Any, name: str, shape: tuple[int, ...]) -> Any:
    if name not in MODEL_RANGES:
        raise RuntimeError(f"no deterministic input range is defined for {name}")
    low, high = MODEL_RANGES[name]
    values = np.arange(np.prod(shape), dtype=np.float32).reshape(shape)
    values = ((values * 37.0 + 17.0) % 1021.0) / 1020.0
    return values * (high - low) + low


def infer(np: Any, compiled: Any, data: Any) -> tuple[list[Any], float]:
    start = time.perf_counter()
    result = compiled([data])
    duration = elapsed_ms(start)
    return [np.asarray(result[port]).copy() for port in compiled.outputs], duration


def npu_busy_us() -> int:
    return int(BUSY_PATH.read_text(encoding="utf-8").strip())


def exact_execution_device(value: Any, expected: str) -> str:
    if value == expected or type(value) is list and value == [expected]:
        return expected
    raise RuntimeError(f"requested {expected}, got execution devices {value!r}")


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(int(len(ordered) * fraction), len(ordered) - 1)]


def softmax(np: Any, values: Any) -> Any:
    values = values.astype(np.float64).reshape(-1)
    exponentials = np.exp(values - np.max(values))
    return exponentials / np.sum(exponentials)


def semantic_parity(
    name: str,
    output_names: list[str],
    cpu: list[Any],
    npu: list[Any],
) -> dict[str, Any]:
    import numpy as np

    by_name = {
        output_name: (cpu_output, npu_output)
        for output_name, cpu_output, npu_output in zip(output_names, cpu, npu, strict=True)
    }
    if name in ("flir.onnx", "liveness_vit.onnx"):
        class_index = 0 if name == "flir.onnx" else 1
        threshold = 0.9 if name == "flir.onnx" else 0.55
        cpu_probability = float(softmax(np, cpu[0])[class_index])
        npu_probability = float(softmax(np, npu[0])[class_index])
        return {
            "probability_class_index": class_index,
            "threshold": threshold,
            "cpu_probability": cpu_probability,
            "npu_probability": npu_probability,
            "probability_abs_delta": abs(cpu_probability - npu_probability),
            "same_threshold_side": (cpu_probability >= threshold) == (npu_probability >= threshold),
        }
    if name == "glintr100.onnx":
        cpu_vector = cpu[0].astype(np.float64).reshape(-1)
        npu_vector = npu[0].astype(np.float64).reshape(-1)
        cpu_vector /= np.linalg.norm(cpu_vector)
        npu_vector /= np.linalg.norm(npu_vector)
        return {
            "cpu_npu_cosine": float(np.dot(cpu_vector, npu_vector)),
            "normalized_max_abs_delta": float(np.max(np.abs(cpu_vector - npu_vector))),
        }
    if name == "blaze_face_short_range.onnx":
        cpu_logits, npu_logits = by_name["classificators"]
        cpu_scores = 1.0 / (1.0 + np.exp(-np.clip(cpu_logits, -100.0, 100.0)))
        npu_scores = 1.0 / (1.0 + np.exp(-np.clip(npu_logits, -100.0, 100.0)))
        return {
            "score_threshold": 0.5,
            "cpu_candidate_count": int(np.count_nonzero(cpu_scores >= 0.5)),
            "npu_candidate_count": int(np.count_nonzero(npu_scores >= 0.5)),
            "score_max_abs_delta": float(np.max(np.abs(cpu_scores - npu_scores))),
        }
    if name == "face_detection_yunet_2023mar.onnx":
        report: dict[str, Any] = {"score_threshold": 0.6, "strides": {}}
        for stride in (8, 16, 32):
            cpu_cls, npu_cls = by_name[f"cls_{stride}"]
            cpu_obj, npu_obj = by_name[f"obj_{stride}"]
            cpu_scores = np.sqrt(np.clip(cpu_cls, 0.0, 1.0) * np.clip(cpu_obj, 0.0, 1.0))
            npu_scores = np.sqrt(np.clip(npu_cls, 0.0, 1.0) * np.clip(npu_obj, 0.0, 1.0))
            report["strides"][str(stride)] = {
                "cpu_candidate_count": int(np.count_nonzero(cpu_scores >= 0.6)),
                "npu_candidate_count": int(np.count_nonzero(npu_scores >= 0.6)),
                "score_max_abs_delta": float(np.max(np.abs(cpu_scores - npu_scores))),
            }
        return report
    if name == "face_landmark.onnx":
        coordinate_delta = np.abs(cpu[0].astype(np.float64) - npu[0].astype(np.float64))
        maximum = float(np.max(coordinate_delta))
        return {
            "coordinate_max_abs_input_pixels": maximum,
            "coordinate_max_normalized_delta": maximum / 256.0,
        }
    return {}


def benchmark(compiled: Any, data: Any, warmup: int, iterations: int, measure_busy: bool) -> dict[str, Any]:
    for _ in range(warmup):
        compiled([data])
    busy_before = npu_busy_us() if measure_busy else None
    cpu_before = time.process_time()
    wall_before = time.perf_counter()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        compiled([data])
        samples.append(elapsed_ms(start))
    wall_ms = elapsed_ms(wall_before)
    cpu_ms = (time.process_time() - cpu_before) * 1_000.0
    report = {
        "iterations": iterations,
        "wall_ms": wall_ms,
        "process_cpu_ms": cpu_ms,
        "process_cpu_core_percent": cpu_ms / wall_ms * 100.0,
        "mean_ms": statistics.fmean(samples),
        "p50_ms": statistics.median(samples),
        "p95_ms": percentile(samples, 0.95),
        "min_ms": min(samples),
        "max_ms": max(samples),
    }
    if busy_before is not None:
        report["npu_busy_delta_us"] = npu_busy_us() - busy_before
    return report


def run_one_model(np: Any, core: Any, path: Path, warmup: int, iterations: int) -> dict[str, Any]:
    model = core.read_model(path)
    shape = concrete_shape(model)
    data = make_input(np, path.name, shape)
    report: dict[str, Any] = {
        "model": path.name,
        "model_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "shape": shape,
        "npu_driver_version": str(core.get_property("NPU", "NPU_DRIVER_VERSION")),
        "npu_compiler_version": str(core.get_property("NPU", "NPU_COMPILER_VERSION")),
    }
    output_count = None
    device_outputs = {}
    for device in ("CPU", "NPU"):
        start = time.perf_counter()
        compiled = core.compile_model(model, device, {"PERFORMANCE_HINT": "LATENCY"})
        report[f"{device.lower()}_compile_ms"] = elapsed_ms(start)
        assignment = exact_execution_device(
            compiled.get_property("EXECUTION_DEVICES"), device
        )
        report[f"{device.lower()}_execution_devices"] = assignment
        outputs, report[f"{device.lower()}_first_infer_ms"] = infer(np, compiled, data)
        device_outputs[device] = outputs
        if output_count is None:
            output_count = len(outputs)
        elif len(outputs) != output_count:
            raise RuntimeError(f"{path.name} output count changed across devices")
        report[f"{device.lower()}_benchmark"] = benchmark(
            compiled, data, warmup, iterations, device == "NPU"
        )
    report["output_count"] = output_count
    report["outputs"] = []
    for cpu_output, npu_output in zip(device_outputs["CPU"], device_outputs["NPU"], strict=True):
        delta = np.abs(cpu_output.astype(np.float64) - npu_output.astype(np.float64))
        scale = max(float(np.max(np.abs(cpu_output))), 1e-12)
        report["outputs"].append(
            {
                "shape": cpu_output.shape,
                "max_abs": float(np.max(delta)),
                "mean_abs": float(np.mean(delta)),
                "max_abs_over_cpu_peak": float(np.max(delta)) / scale,
            }
        )
    output_names = [output.any_name for output in model.outputs]
    report["semantic_parity"] = semantic_parity(
        path.name,
        output_names,
        device_outputs["CPU"],
        device_outputs["NPU"],
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models-dir", type=Path, default=Path("models"))
    parser.add_argument("--manifest", type=Path, default=Path("models/SHA256SUMS"))
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=30)
    args = parser.parse_args()
    if args.warmup < 0 or args.iterations <= 0:
        parser.error("warmup must be nonnegative and iterations must be positive")

    import numpy as np
    ov = importlib.import_module("openvino")

    core = ov.Core()
    report = run_manifest_models(
        args.models_dir,
        args.manifest,
        lambda path: run_one_model(np, core, path, args.warmup, args.iterations),
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
