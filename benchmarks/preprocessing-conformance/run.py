#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Synthetic differential measurement, not a production acceptance test.

Runs exact source-extracted pure Rust functions and only the preprocessing AST
from the recorded scorers. Never imports either scorer or an inference runtime.
Output/build files stay in this experiment directory. No external input images.
"""

import argparse
import ast
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import subprocess
from typing import Any

# Set before importing numerical libraries; one CPU worker throughout.
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
import cv2
import numpy as np


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = "6ee8ef5ca48f9f1ec7f9ee9b2eac876915a92820"
BUILD = HERE / "build"
SCORERS = ["vit_liveness_score.py", "vit_live_session.py"]
SOURCES = [
    "crates/irlume-camera/src/lib.rs",
    "crates/irlume-vision/src/lib.rs",
    "crates/irlume-vision/src/align.rs",
    *[f"benchmarks/pad-candidates/{name}" for name in SCORERS],
    "models/SHA256SUMS",
]
SOURCE_SHA256 = dict(zip(SOURCES, [
    "36965b9249e609eb1d95697fcd57b7019a77a4175d30044ec35d0a3b727b0ac2",
    "76b6bc04eadb26b77836a6a91482c97c539d91f5ba784255a11fbd8103688bc1",
    "7cd0bcde9bb6b0c31611598108a306a7acaffbca9ae8435907efd2ebc0253b8c",
    "9c1206f889c39d12604a7c22b98776da396aac927ec8da6f3e8d0624ad5aea0d",
    "d519bedc3ed1fe0a9850ab912ce8b441e7330119d10d08f231b80b882f848f26",
    "d0bea5ac4520313dd9afd703313e911e3e2c5c7da89bc226b13cc7eb2f959750",
], strict=True))


def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs).stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def extract(text, start, end):
    """Explicit delimiters from the pinned source; no rewritten arithmetic."""
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError("source extraction markers changed")
    return text[text.index(start):text.index(end)]


def baseline_source(name):
    """Always replay immutable Git objects, never current checkout source."""
    data = command("git", "show", f"{BASE}:{name}", cwd=ROOT)
    if sha(data) != SOURCE_SHA256[name]:
        raise ValueError(f"baseline source hash mismatch: {name}")
    return data


def baseline_sources():
    return {name: baseline_source(name) for name in SOURCES}


def compile_probe(sources=None):
    if sources is None:
        sources = baseline_sources()
    camera, vision, align = (sources[name].decode() for name in SOURCES[:3])
    pure = "// SPDX-License-Identifier: GPL-3.0-or-later\n"
    pure += "// Copyright the irlume contributors.\n"
    pure += extract(camera, "pub fn yuyv_to_rgb(", "/// Pull and discard one frame")
    pure += "\nmod align {\n"
    pure += extract(align, "pub struct RgbView<'a>", "/// A grey 8-bit frame view")
    pure += "\n}\n"
    pure += extract(vision, "    fn pad_vit_input(", "    /// Preprocessing arithmetic tests")
    BUILD.mkdir(exist_ok=True)
    (BUILD / "pure.rs").write_text(pure)
    (BUILD / "probe.rs").write_bytes((HERE / "probe.rs").read_bytes())
    command("rustc", "+1.88.0", "--edition=2021", "-Dwarnings", "-Ccodegen-units=1",
            "-Copt-level=0", str(BUILD / "probe.rs"), "-o", str(BUILD / "probe"))
    return {name: sha(data) for name, data in sources.items()}, sha(pure.encode())


def recorded_preprocess(name, sources=None):
    """Select only crop and infer's five preprocessing assignments by AST."""
    path = f"benchmarks/pad-candidates/{name}"
    data = baseline_source(path) if sources is None else sources[path]
    module = ast.parse(data.decode())
    crop_name = "crop" if name == SCORERS[0] else "crop_m96"
    crop = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == crop_name)
    infer = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "infer")
    body = infer.body[:5]
    names = [n.targets[0].id for n in body
             if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)]
    if names != ["rgb", "rgb", "x", "x", "t"]:
        raise ValueError("recorded preprocessing prefix changed")
    if any(isinstance(n, ast.Name) and n.id in {"sess", "ort", "det"}
           for stmt in [crop, *body] for n in ast.walk(stmt)):
        raise ValueError("inference object in preprocessing extraction")
    infer.body = [*body, ast.Return(value=ast.Name(id="t", ctx=ast.Load()))]
    selected = ast.fix_missing_locations(ast.Module(body=[crop, infer], type_ignores=[]))
    namespace: dict[str, Any] = {"cv2": cv2, "np": np}
    exec(compile(selected, str(path), "exec"), namespace)

    def preprocess(rgb, bbox):
        x1, y1, x2, y2 = np.asarray(bbox, dtype=np.float32)
        face = np.array([x1, y1, x2 - x1, y2 - y1], dtype=np.float32)
        bgr = np.ascontiguousarray(rgb[:, :, ::-1])
        chip = (namespace[crop_name](bgr, face, 96.0 / 112.0)
                if crop_name == "crop" else namespace[crop_name](bgr, face))
        return namespace["infer"](chip)[0], chip[:, :, ::-1]
    return preprocess


def rust(mode, image, width, height, bbox=()):
    data = command(str(BUILD / "probe"), mode, str(width), str(height),
                   *map(str, bbox), input=image.tobytes())
    return np.frombuffer(data, dtype="<f4" if mode == "pad" else np.uint8)


def difference(actual, reference):
    delta = np.abs(actual.astype(np.float64) - reference.astype(np.float64))
    return {"max_abs": float(delta.max()), "mean_abs": float(delta.mean()),
            "count_above_1e-6": int(np.count_nonzero(delta > 1e-6)),
            "elements": int(delta.size)}


def norm(rgb):
    return ((rgb.astype(np.float32) / 255.0 - 0.5) / 0.5).transpose(2, 0, 1)


def pad_experiment(sources=None):
    reference = [recorded_preprocess(name, sources) for name in SCORERS]
    yy, xx = np.indices((32, 32))
    ramp = np.stack([xx * 8, yy * 8, (xx + yy) * 4], axis=-1).astype(np.uint8)
    yy, xx = np.indices((128, 256))
    wide = np.stack([xx, yy * 2, (xx + yy) % 256], axis=-1).astype(np.uint8)
    edge = np.full((64, 64, 3), 255, dtype=np.uint8)
    edge[18:37, 18:37] = 0
    yy, xx = np.indices((384, 512))
    steps = np.stack([(xx // 16 % 2) * 255, (yy // 16 % 2) * 255,
                      ((xx + yy) // 16 % 2) * 255], axis=-1).astype(np.uint8)
    cases = [
        ("uniform_rgb_control", np.full((32, 32, 3), [255, 64, 0], dtype=np.uint8), [0, 0, 32, 32]),
        ("full_frame_ramp", ramp, [0, 0, 32, 32]),
        ("fractional_interior_ramp", wide, [100.25, 40.5, 121.75, 57.25]),
        ("integer_roi_border_isolation", edge, [24, 24, 31, 31]),
        ("left_top_clipped_ramp", wide, [-2.5, -1.25, 18.5, 15.25]),
        ("right_bottom_clipped_ramp", wide, [240, 116, 260, 134]),
        ("downsample_color_steps", steps, [0, 0, 512, 384]),
        ("one_pixel_rgb_control", np.array([[[19, 127, 233]]], dtype=np.uint8), [0, 0, 1, 1]),
    ]
    rows = []
    for name, image, bbox in cases:
        expected, chip = reference[0](image, bbox)
        other, other_chip = reference[1](image, bbox)
        np.testing.assert_array_equal(chip, other_chip)
        np.testing.assert_array_equal(expected, other)
        h, w = image.shape[:2]
        actual = rust("pad", image, w, h, bbox).reshape(3, 224, 224)
        if name.endswith("control"):
            np.testing.assert_allclose(actual, expected, rtol=0, atol=1e-6)
        float_resize = cv2.resize(chip.astype(np.float32), (224, 224), interpolation=cv2.INTER_LINEAR)
        row = {"case": name, "frame_wh": [w, h], "bbox_xyxy": bbox,
               "reference_roi_wh": [chip.shape[1], chip.shape[0]],
               "tensor_difference": difference(actual, expected),
               "pixel_equivalent_difference": difference((actual + 1) * 127.5, (expected + 1) * 127.5),
               "rgb8_vs_float_resize_only": difference(norm(float_resize), expected),
               "first_rgb_actual": ((actual[:, 0, 0] + 1) * 127.5).tolist(),
               "first_rgb_reference": ((expected[:, 0, 0] + 1) * 127.5).tolist(),
               "last_rgb_actual": ((actual[:, -1, -1] + 1) * 127.5).tolist(),
               "last_rgb_reference": ((expected[:, -1, -1] + 1) * 127.5).tolist()}
        rows.append(row)
    return rows


def resolve_tuple(colorspace, encoding, quantization):
    # Bounded subset of videodev2.h's default maps, for YUYV/NV12 only.
    if colorspace not in {"SMPTE170M", "REC709", "SRGB", "JPEG"}:
        raise ValueError("unresolved/unsupported colorspace in this probe")
    if encoding == "DEFAULT":
        encoding = "709" if colorspace == "REC709" else "601"
    if quantization == "DEFAULT":
        quantization = "FULL" if colorspace == "JPEG" else "LIMITED"
    if encoding not in {"601", "709"} or quantization not in {"FULL", "LIMITED"}:
        raise ValueError("unsupported encoding/range in this probe")
    return encoding, quantization


def reference_yuv(samples, encoding, quantization):
    # Invert the V4L2 nonlinear luma/chroma transform in float64.
    # Full-range Cb/Cr is scaled by 256 ([-128,128], clipped to [-128,127]).
    y, cb, cr = samples.astype(np.float64).T
    if quantization == "LIMITED":
        y, cb, cr = (y - 16) / 219, (cb - 128) / 224, (cr - 128) / 224
    else:
        y, cb, cr = y / 255, (cb - 128) / 256, (cr - 128) / 256
    kr, kb = {"601": (0.299, 0.114), "709": (0.2126, 0.0722)}[encoding]
    r = y + 2 * (1 - kr) * cr
    b = y + 2 * (1 - kb) * cb
    g = (y - kr * r - kb * b) / (1 - kr - kb)
    return np.clip(np.stack([r, g, b], axis=-1) * 255, 0, 255)


def color_experiment():
    samples = np.array([(i, 128, 128) for i in range(256)] + list(itertools.product(
        [0, 16, 32, 64, 128, 192, 235, 255], [16, 64, 128, 192, 240],
        [16, 64, 128, 192, 240])), dtype=np.uint8)
    y, u, v = samples.T
    packed = np.stack([y, u, y, v], axis=-1)
    yuyv = np.tile(packed, (2, 1)).reshape(2, -1, 2)
    width = 2 * len(samples)
    nv12 = np.concatenate([np.tile(np.repeat(y, 2), 2), np.stack([u, v], axis=-1).ravel()])
    actual = rust("yuyv", yuyv, width, 2).reshape(2, width, 3)
    actual_nv12 = rust("nv12", nv12, width, 2).reshape(2, width, 3)
    np.testing.assert_array_equal(actual, actual_nv12)
    decoded = actual[0, ::2]
    np.testing.assert_array_equal(decoded[:256], np.repeat(np.arange(256)[:, None], 3, axis=1))
    # Independent OpenCV YUYV conversion is a limited-range 601 cross-check,
    # not the oracle for 709 or explicit full-range tuples.
    cv = cv2.cvtColor(yuyv, cv2.COLOR_YUV2RGB_YUY2)[0, ::2]
    legal = (samples[:, 0] >= 16) & (samples[:, 0] <= 235)
    oracle601 = reference_yuv(samples, "601", "LIMITED")
    cv_error = float(np.max(np.abs(cv[legal].astype(float) - oracle601[legal])))
    if cv_error > 1.0:
        raise AssertionError(f"limited601 reference/OpenCV cross-check: {cv_error}")
    np.testing.assert_allclose(oracle601[[16, 235]], [[0, 0, 0], [255, 255, 255]], atol=1e-12)
    rows = []
    tuples = [(space, enc, quant) for space, enc in [("SMPTE170M", "601"), ("REC709", "709")]
              for quant in ["FULL", "LIMITED"]]
    tuples += [(space, "DEFAULT", "DEFAULT") for space in ["SRGB", "JPEG", "REC709"]]
    tuples += [("REC709", "601", "FULL")]
    for space, enc, quant in tuples:
        resolved = resolve_tuple(space, enc, quant)
        oracle = reference_yuv(samples, *resolved)
        delta = np.abs(decoded.astype(float) - oracle)
        anchor = np.array([[16, 128, 128], [235, 128, 128], [128, 64, 192]], dtype=np.uint8)
        ids = [int(np.flatnonzero(np.all(samples == p, axis=1))[0]) for p in anchor]
        rows.append({"tuple": [space, enc, quant], "resolved": list(resolved),
                     "samples": len(samples), "difference": difference(decoded, oracle),
                     "channels_error_over_1": int(np.count_nonzero(delta > 1.0)),
                     "anchors_yuv": anchor.tolist(), "anchors_actual": decoded[ids].tolist(),
                     "anchors_reference_float": oracle[ids].tolist()})
    return {"yuyv_nv12_equal": True, "neutral_full_range_control": True,
            "opencv_limited601_legal_y_max_error": cv_error, "cases": rows}


def main():
    cv2.setNumThreads(1)
    cv2.ocl.setUseOpenCL(False)
    cv2.setUseOptimized(False)
    cv2.ipp.setUseIPP(False)
    sources = baseline_sources()
    hashes, pure_hash = compile_probe(sources)
    result = {
        "baseline": BASE,
        "source_origin": "byte-verified git objects at baseline; not current checkout production code",
        "experiment_checkout_revision": command("git", "rev-parse", "HEAD", cwd=ROOT).decode().strip(),
        "experiment_tool_sha256": {name: sha((HERE / name).read_bytes()) for name in
                                   ["run.py", "probe.rs", "test_probe.py", "verify.py", ".gitignore"]},
        "scope": "synthetic only; no camera, model loading/inference, TPM, PAM or decision changes",
        "environment": {"python": platform.python_version(), "numpy": np.__version__,
                        "opencv": cv2.__version__, "opencv_threads": cv2.getNumThreads(),
                        "opencv_optimized": cv2.useOptimized(), "opencv_opencl": cv2.ocl.useOpenCL(),
                        "opencv_ipp": cv2.ipp.useIPP(),
                        "rustc": command("rustc", "+1.88.0", "--version").decode().strip()},
        "source_sha256": hashes, "extracted_rust_sha256": pure_hash,
        "probe_sha256": sha((HERE / "probe.rs").read_bytes()),
        "runner_sha256": sha((HERE / "run.py").read_bytes()),
        "pad": pad_experiment(sources), "colorimetry": color_experiment(),
        "interpretation": "differences are observations, not passing production parity gates",
    }
    (HERE / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-sources", action="store_true",
                        help="verify pinned Git-object bytes without compiling or running the probe")
    if parser.parse_args().check_sources:
        print(json.dumps({"baseline": BASE, "source_sha256": {
            name: sha(data) for name, data in baseline_sources().items()}}, indent=2))
    else:
        main()
