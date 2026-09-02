#!/usr/bin/env python3
"""Measure exact-NPU all-model coexistence and the primary model sequence."""

from __future__ import annotations

import argparse
import importlib
import json
import math
import statistics
import time
from pathlib import Path
from typing import Any

from bench_npu_models import (
    concrete_shape,
    elapsed_ms,
    exact_execution_device,
    make_input,
    npu_busy_us,
    percentile,
    read_model_inventory,
)


PRIMARY_PIPELINE = (
    "face_detection_yunet_2023mar.onnx",
    "face_landmark.onnx",
    "glintr100.onnx",
    "liveness_vit.onnx",
    "flir.onnx",
)
MEMORY_PATH = Path("/sys/class/accel/accel0/device/npu_memory_utilization")


def primary_pipeline(inventory: tuple[str, ...]) -> tuple[str, ...]:
    missing = [name for name in PRIMARY_PIPELINE if name not in inventory]
    if missing:
        raise RuntimeError(f"primary pipeline models are missing: {missing}")
    return PRIMARY_PIPELINE


def validate_compiled_models(inventory: tuple[str, ...], entries: list[dict[str, Any]]) -> None:
    if [entry.get("model") for entry in entries] != list(inventory):
        raise RuntimeError("compiled model inventory is missing, duplicated, or reordered")
    for entry in entries:
        name = entry["model"]
        if entry.get("execution_devices") != "NPU":
            raise RuntimeError(f"{name} was not assigned exactly to NPU")
        first_infer = entry.get("first_infer_ms")
        if isinstance(first_infer, bool) or not isinstance(first_infer, (int, float)) or not math.isfinite(first_infer) or first_infer < 0:
            raise RuntimeError(f"{name} did not report inference")
        if type(entry.get("inference_count")) is not int or entry["inference_count"] <= 0:
            raise RuntimeError(f"{name} did not complete inference sampling")
        if type(entry.get("output_count")) is not int or entry["output_count"] <= 0:
            raise RuntimeError(f"{name} produced no outputs")
        if type(entry.get("npu_busy_delta_us")) is not int or entry["npu_busy_delta_us"] <= 0:
            raise RuntimeError(f"{name} did not move NPU busy time")


def summary(samples: list[float]) -> dict[str, float]:
    return {
        "mean_ms": statistics.fmean(samples),
        "p50_ms": statistics.median(samples),
        "p95_ms": percentile(samples, 0.95),
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models-dir", type=Path, default=Path("models"))
    parser.add_argument("--manifest", type=Path, default=Path("models/SHA256SUMS"))
    parser.add_argument("--bypass-umd-cache", action="store_true")
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=30)
    args = parser.parse_args()
    if args.warmup < 0 or args.iterations <= 0:
        parser.error("warmup must be nonnegative and iterations must be positive")

    import numpy as np
    ov = importlib.import_module("openvino")

    inventory = read_model_inventory(args.manifest)
    pipeline = primary_pipeline(inventory.onnx)
    core = ov.Core()
    compiled = {}
    inputs = {}
    entries = []
    for name in inventory.onnx:
        path = args.models_dir / name
        if not path.is_file():
            raise FileNotFoundError(f"manifest model is missing: {name}")
        model = core.read_model(path)
        shape = concrete_shape(model)
        inputs[name] = make_input(np, name, shape)
        compile_start = time.perf_counter()
        compiled[name] = core.compile_model(
            model,
            "NPU",
            {
                "PERFORMANCE_HINT": "LATENCY",
                "NPU_BYPASS_UMD_CACHING": args.bypass_umd_cache,
            },
        )
        compile_ms = elapsed_ms(compile_start)
        assignment = exact_execution_device(
            compiled[name].get_property("EXECUTION_DEVICES"), "NPU"
        )
        busy_before = npu_busy_us()
        first_infer_ms = None
        output_count = None
        inference_count = 5
        for index in range(inference_count):
            infer_start = time.perf_counter()
            outputs = compiled[name]([inputs[name]])
            if index == 0:
                first_infer_ms = elapsed_ms(infer_start)
                output_count = len(outputs)
            elif len(outputs) != output_count:
                raise RuntimeError(f"{name} output count changed during inference sampling")
        entries.append(
            {
                "model": name,
                "compile_ms": compile_ms,
                "execution_devices": assignment,
                "first_infer_ms": first_infer_ms,
                "inference_count": inference_count,
                "output_count": output_count,
                "npu_busy_delta_us": npu_busy_us() - busy_before,
                "npu_memory_utilization": int(MEMORY_PATH.read_text(encoding="utf-8").strip()),
            }
        )
    validate_compiled_models(inventory.onnx, entries)

    for _ in range(args.warmup):
        for name in pipeline:
            compiled[name]([inputs[name]])
    samples = {name: [] for name in pipeline}
    rounds = []
    busy_before = npu_busy_us()
    cpu_before = time.process_time()
    wall_before = time.perf_counter()
    for _ in range(args.iterations):
        round_start = time.perf_counter()
        for name in pipeline:
            stage_start = time.perf_counter()
            compiled[name]([inputs[name]])
            samples[name].append(elapsed_ms(stage_start))
        rounds.append(elapsed_ms(round_start))
    wall_ms = elapsed_ms(wall_before)
    cpu_ms = (time.process_time() - cpu_before) * 1_000.0
    busy_delta = npu_busy_us() - busy_before
    if busy_delta <= 0:
        raise RuntimeError("primary pipeline did not move NPU busy time")

    report = {
        "kind": "irlume.openvino.pipeline",
        "schema_version": 1,
        "manifest_models": list(inventory.onnx),
        "excluded_tflite": list(inventory.tflite),
        "full_device_name": str(core.get_property("NPU", "FULL_DEVICE_NAME")),
        "device_total_mem_size": int(core.get_property("NPU", "NPU_DEVICE_TOTAL_MEM_SIZE")),
        "bypass_umd_cache": args.bypass_umd_cache,
        "compiled_models": entries,
        "primary_pipeline": {
            "models": list(pipeline),
            "iterations": args.iterations,
            "wall_ms": wall_ms,
            "process_cpu_ms": cpu_ms,
            "process_cpu_core_percent": cpu_ms / wall_ms * 100.0,
            "npu_busy_delta_us": busy_delta,
            "round": summary(rounds),
            "stages": {name: summary(values) for name, values in samples.items()},
        },
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
