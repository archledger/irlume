#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.

"""Validate raw OpenVINO hardware reports and emit bounded JSON evidence."""

import argparse
import json
import math
import pathlib
import re
import sys
import tomllib
from typing import NoReturn


ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "models/SHA256SUMS"
MAX_INPUT_BYTES = 1_048_576
MODEL_KEYS = {
    "model",
    "model_sha256",
    "shape",
    "npu_driver_version",
    "npu_compiler_version",
    "cpu_compile_ms",
    "cpu_execution_devices",
    "cpu_first_infer_ms",
    "cpu_benchmark",
    "npu_compile_ms",
    "npu_execution_devices",
    "npu_first_infer_ms",
    "npu_benchmark",
    "output_count",
    "outputs",
    "semantic_parity",
}
COMPILED_KEYS = {
    "model",
    "compile_ms",
    "execution_devices",
    "first_infer_ms",
    "inference_count",
    "output_count",
    "npu_busy_delta_us",
    "npu_memory_utilization",
}
PRIMARY_MODELS = [
    "face_detection_yunet_2023mar.onnx",
    "face_landmark.onnx",
    "glintr100.onnx",
    "liveness_vit.onnx",
    "flir.onnx",
]
MATRIX_KEYS = {
    "status",
    "openvino",
    "level_zero_tag",
    "level_zero_commit",
    "npu_userspace",
    "gpu_status",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member: {key!r}")
        result[key] = value
    return result


def reject_nonstandard_constant(value):
    fail(f"non-standard JSON numeric constant: {value}")


def read_json(path: pathlib.Path) -> dict:
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            fail(f"input exceeds {MAX_INPUT_BYTES} bytes: {path.name}")
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_members,
            parse_constant=reject_nonstandard_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON input {path.name}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON input must be an object: {path.name}")
    return value


def manifest_inventory() -> tuple[list[str], list[str], dict[str, str]]:
    onnx = []
    tflite = []
    checksums = {}
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        checksum, name = raw.split()
        if name.endswith(".onnx"):
            onnx.append(name)
        elif name.endswith(".tflite"):
            tflite.append(name)
        else:
            fail(f"unsupported model type in manifest: {name}")
        checksums[name] = checksum
    return onnx, tflite, checksums


def finite_nonnegative(value, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        fail(f"{label} must be a finite nonnegative number")
    return value


def positive_int(value, label: str) -> int:
    if type(value) is not int or value <= 0:
        fail(f"{label} must be a positive integer")
    return value


def validate_models(report: dict) -> list[dict]:
    onnx, tflite, checksums = manifest_inventory()
    if set(report) != {"kind", "schema_version", "manifest_models", "excluded_tflite", "models"}:
        fail("unexpected standalone report keys")
    if report["kind"] != "irlume.openvino.models" or type(report["schema_version"]) is not int or report["schema_version"] != 1:
        fail("unsupported standalone report identity")
    if report["manifest_models"] != onnx or report["excluded_tflite"] != tflite:
        fail("standalone report inventory differs from SHA256SUMS")
    models = report["models"]
    if not isinstance(models, list) or [item.get("model") for item in models if isinstance(item, dict)] != onnx:
        fail("standalone report is missing, duplicating, or reordering models")
    bounded = []
    for item in models:
        if not isinstance(item, dict) or set(item) != MODEL_KEYS:
            fail("unexpected standalone model record")
        name = item["model"]
        if item["model_sha256"] != checksums[name]:
            fail(f"{name}: model checksum differs from SHA256SUMS")
        if item["cpu_execution_devices"] != "CPU" or item["npu_execution_devices"] != "NPU":
            fail(f"{name}: execution assignment is not exact")
        first_infer = finite_nonnegative(item["npu_first_infer_ms"], f"{name}: first inference")
        output_count = positive_int(item["output_count"], f"{name}: output count")
        benchmark = item["npu_benchmark"]
        if not isinstance(benchmark, dict):
            fail(f"{name}: NPU benchmark is missing")
        busy_delta = positive_int(benchmark.get("npu_busy_delta_us"), f"{name}: NPU busy delta")
        bounded.append(
            {
                "model": name,
                "model_sha256": item["model_sha256"],
                "execution_devices": "NPU",
                "first_infer_ms": first_infer,
                "output_count": output_count,
                "npu_busy_delta_us": busy_delta,
            }
        )
    return bounded


def validate_pipeline(report: dict) -> dict:
    onnx, tflite, _ = manifest_inventory()
    expected_keys = {
        "kind",
        "schema_version",
        "manifest_models",
        "excluded_tflite",
        "full_device_name",
        "device_total_mem_size",
        "bypass_umd_cache",
        "compiled_models",
        "primary_pipeline",
    }
    if set(report) != expected_keys:
        fail("unexpected pipeline report keys")
    if report["kind"] != "irlume.openvino.pipeline" or type(report["schema_version"]) is not int or report["schema_version"] != 1:
        fail("unsupported pipeline report identity")
    if report["manifest_models"] != onnx or report["excluded_tflite"] != tflite:
        fail("pipeline report inventory differs from SHA256SUMS")
    compiled = report["compiled_models"]
    if not isinstance(compiled, list) or [item.get("model") for item in compiled if isinstance(item, dict)] != onnx:
        fail("pipeline report is missing, duplicating, or reordering models")
    for item in compiled:
        if not isinstance(item, dict) or set(item) != COMPILED_KEYS:
            fail("unexpected compiled-model record")
        name = item["model"]
        if item["execution_devices"] != "NPU":
            fail(f"{name}: pipeline assignment is not exact NPU")
        finite_nonnegative(item["first_infer_ms"], f"{name}: pipeline first inference")
        positive_int(item["inference_count"], f"{name}: pipeline inference count")
        positive_int(item["output_count"], f"{name}: pipeline output count")
        positive_int(item["npu_busy_delta_us"], f"{name}: pipeline NPU busy delta")
    primary = report["primary_pipeline"]
    if not isinstance(primary, dict) or primary.get("models") != PRIMARY_MODELS:
        fail("primary pipeline model sequence changed")
    iterations = positive_int(primary.get("iterations"), "primary pipeline iterations")
    busy_delta = positive_int(primary.get("npu_busy_delta_us"), "primary pipeline NPU busy delta")
    return {
        "all_models_resident": True,
        "all_models_inferred": True,
        "compiled_models": onnx,
        "execution_devices": ["NPU"],
        "primary_models": PRIMARY_MODELS,
        "iterations": iterations,
        "npu_busy_delta_us": busy_delta,
    }


def read_matrix(path: pathlib.Path) -> dict:
    try:
        with path.open("rb") as source:
            matrix = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"invalid matrix: {error}")
    if set(matrix) != MATRIX_KEYS:
        fail("matrix keys differ from the qualified schema")
    if matrix["status"] != "experimental" or matrix["gpu_status"] != "disabled-unqualified":
        fail("matrix does not preserve the experimental release boundary")
    return matrix


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", type=pathlib.Path, required=True)
    parser.add_argument("--pipeline", type=pathlib.Path, required=True)
    parser.add_argument("--matrix", type=pathlib.Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--rust-adapter-passed", action="store_true")
    parser.add_argument("--assignment-negative-passed", action="store_true")
    parser.add_argument("--cache-contracts-passed", action="store_true")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.commit) is None:
        fail("commit must be 40 lowercase hexadecimal characters")
    if not all((args.rust_adapter_passed, args.assignment_negative_passed, args.cache_contracts_passed)):
        fail("all Rust adapter, assignment-negative, and cache gates must pass")
    evidence = {
        "kind": "irlume.openvino.hardware",
        "schema_version": 1,
        "commit": args.commit,
        "matrix": read_matrix(args.matrix),
        "gates": {
            "rust_adapter": True,
            "assignment_mismatch_rejected": True,
            "cache_clean_warm_corrupt": True,
        },
        "models": validate_models(read_json(args.models)),
        "pipeline": validate_pipeline(read_json(args.pipeline)),
    }
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
