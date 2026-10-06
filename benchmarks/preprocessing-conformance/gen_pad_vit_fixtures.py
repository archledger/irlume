#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Generate independent regression fixtures for `pad_vit_input` (issue #795).

The oracle is the recorded m96 scorer crop (AST-extracted from the immutable
scorer source, never imported) followed by an RGB8 `cv2.resize(...,
INTER_LINEAR)` exactly as `infer` performs it. Frames and bboxes are generated;
no images, models or inference are involved.

Contract pinned here (see the wave-3 review, artifacts
2026-10-01-wave3-795.md):

* crop = the scorer's integer ROI: width/height reconstructed from float32
  xyxy, m96 expansion in NumPy float32, Python `int()` truncation toward
  zero, half-open slice clipped to the frame;
* resize = OpenCV's fixed-point RGB8 INTER_LINEAR path (or the exact-2x
  area-fast dispatch when the ROI is exactly 2x the output), quantized to
  bytes before `(px/255 - 0.5)/0.5` normalization.

Run from the repository root:

    python3 benchmarks/preprocessing-conformance/gen_pad_vit_fixtures.py
    python3 benchmarks/preprocessing-conformance/gen_pad_vit_fixtures.py --check

`--check` regenerates and fails if any fixture value, the generator hash, the
dispatch settings or the scorer pin would change. The receipt also records
the oracle environment (cv2, opencv-python, NumPy, Python, platform) of the
committed generation; a different environment that reproduces every value
exactly passes with a warning, and `--strict-env` makes it fail. Committed
fixtures are generated only in the recorded environment (README).
"""

import argparse
import ast
import functools
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
import cv2
import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REL = str(HERE.relative_to(ROOT))
RUST_OUT = ROOT / "crates/irlume-vision/src/pad_vit_fixtures.rs"
RECEIPT = HERE / "pad-vit-fixtures-receipt.json"
SCORER = "benchmarks/pad-candidates/vit_liveness_score.py"
SCORER_SHA256 = "9c1206f889c39d12604a7c22b98776da396aac927ec8da6f3e8d0624ad5aea0d"
OUT = 224

cv2.setNumThreads(1)
cv2.setUseOptimized(False)
cv2.ocl.setUseOpenCL(False)
cv2.ipp.setUseIPP(False)


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, cwd=ROOT).stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fnv1a64(data):
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def scorer_crop():
    """AST-extract the recorded scorer's `crop` from immutable Git objects."""
    data = command("git", "show", f"6ee8ef5ca48f9f1ec7f9ee9b2eac876915a92820:{SCORER}")
    if sha(data) != SCORER_SHA256:
        raise ValueError("scorer source hash mismatch")
    module = ast.parse(data.decode())
    crop = next(
        n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "crop"
    )
    if any(
        isinstance(n, ast.Name) and n.id in {"sess", "ort", "det"}
        for n in ast.walk(crop)
    ):
        raise ValueError("inference object in crop extraction")
    namespace: dict[str, Any] = {"cv2": cv2, "np": np}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[crop], type_ignores=[])),
                 SCORER, "exec"), namespace)
    return namespace["crop"]


CROP = scorer_crop()


def crop_bounds(rgb, bbox):
    """The scorer's integer ROI bounds, recomputed in NumPy float32.

    Mirrors run.py's width/height reconstruction and the scorer crop body;
    the self-check below proves it yields the scorer's exact slice.
    """
    x1f, y1f, x2f, y2f = np.asarray(bbox, dtype=np.float32)
    face = np.array([x1f, y1f, x2f - x1f, y2f - y1f], dtype=np.float32)
    x, y, bw, bh = face[:4]
    margin = 96.0 / 112.0
    mx, my = bw * margin, bh * margin
    x1 = max(0, int(x - mx))
    y1 = max(0, int(y - my))
    x2 = min(rgb.shape[1], int(x + bw + mx))
    y2 = min(rgb.shape[0], int(y + bh + my))
    return int(x1), int(y1), int(x2), int(y2)


def reference(rgb, bbox):
    """(crop bounds, RGB chip, RGB8 224x224 resize bytes, normalized f32 CHW)."""
    x1f, y1f, x2f, y2f = np.asarray(bbox, dtype=np.float32)
    face = np.array([x1f, y1f, x2f - x1f, y2f - y1f], dtype=np.float32)
    bgr = np.ascontiguousarray(rgb[:, :, ::-1])
    chip = CROP(bgr, face, 96.0 / 112.0)
    x1, y1, x2, y2 = crop_bounds(rgb, bbox)
    if chip.shape != (y2 - y1, x2 - x1, 3):
        raise AssertionError(f"bounds {x1,y1,x2,y2} disagree with scorer chip {chip.shape}")
    if not np.array_equal(chip[:, :, ::-1], np.ascontiguousarray(rgb[y1:y2, x1:x2])):
        raise AssertionError("bounds slice disagrees with scorer chip")
    chip_rgb = np.ascontiguousarray(chip[:, :, ::-1])
    rgb224 = cv2.resize(chip_rgb, (OUT, OUT), interpolation=cv2.INTER_LINEAR)
    tensor = ((rgb224.astype(np.float32) / 255.0 - 0.5) / 0.5).transpose(2, 0, 1)
    return (x1, y1, x2, y2), chip_rgb, rgb224, tensor


# --- deterministic frame recipes (mirrored in the Rust test module) ------------

def recipe_pixel(name, x, y):
    if name == "ramp32":
        return (x * 8) & 0xFF, (y * 8) & 0xFF, ((x + y) * 4) & 0xFF
    if name == "wide":
        return x & 0xFF, (y * 2) & 0xFF, (x + y) & 0xFF
    if name == "steps":
        return ((x // 16) % 2) * 255, ((y // 16) % 2) * 255, (((x + y) // 16) % 2) * 255
    if name == "grid48x40":
        return x & 0xFF, y & 0xFF, (x + y) & 0xFF
    if name == "white64_blackroi":
        if 18 <= x < 37 and 18 <= y < 37:
            return 0, 0, 0
        return 255, 255, 255
    if name == "pattern448":
        return (x * 73 + y * 151) & 0xFF, (x * 151 + y * 73) & 0xFF, (x ^ y) & 0xFF
    if name == "pattern224":
        return (x * 5) & 0xFF, (y * 7) & 0xFF, (x * y) & 0xFF
    if name == "pattern336":
        return (x * 11 + y * 23) & 0xFF, (x * 23 + y * 11) & 0xFF, ((x * 3) ^ (y * 5)) & 0xFF
    if name == "camera640":
        return (x * 13 + y * 7) & 0xFF, ((x * y) >> 3) & 0xFF, (x * 3 + (y ^ x)) & 0xFF
    raise ValueError(name)


RECIPES = {
    "ramp32": (32, 32),
    "wide": (256, 128),
    "steps": (512, 384),
    "grid48x40": (48, 40),
    "white64_blackroi": (64, 64),
    "pattern448": (448, 448),
    "pattern224": (224, 224),
    "pattern336": (336, 336),
    "camera640": (640, 480),
}


@functools.cache
def make_frame(name):
    w, h = RECIPES[name]
    frame = np.zeros((h, w, 3), dtype=np.uint8)
    for y in range(h):
        for x in range(w):
            frame[y, x] = recipe_pixel(name, x, y)
    frame.setflags(write=False)
    return frame


def tie_count(chip, rw, rh):
    """2x2 source-block sums equal to 2 (mod 8): exact-2x rounding-half ties
    that a round-half-even implementation would answer differently."""
    if rw != OUT * 2 or rh != OUT * 2:
        return 0
    blocks = chip.reshape(OUT, 2, OUT, 2, 3).astype(np.int64)
    return int(np.count_nonzero(blocks.sum(axis=(1, 3)) % 8 == 2))


CASES = [
    # (name, recipe, bbox, note)
    ("ramp32_rounding_counterexample", "ramp32", [0.0, 0.0, 32.0, 32.0],
     "wave-3 counterexample: output (x=4,y=0,B) must be 0, not 1"),
    ("black_roi_white_outside", "white64_blackroi", [24.0, 24.0, 31.0, 31.0],
     "integer ROI isolation: chip is exactly the black [18:37,18:37] block"),
    ("full_frame_last_row_col", "grid48x40", [0.0, 0.0, 48.0, 40.0],
     "crop extent is the full 48x40 frame, last row/column included"),
    ("fractional_interior", "wide", [100.25, 40.5, 121.75, 57.25],
     "float32 m96 expansion and truncation on fractional bounds"),
    ("negative_clipped", "wide", [-2.5, -1.25, 18.5, 15.25],
     "negative bounds truncate toward zero before the clip"),
    ("right_bottom_clipped", "wide", [240.0, 116.0, 260.0, 134.0],
     "right/bottom clip to the half-open frame edge"),
    ("one_pixel_strip", "wide", [32.0, 20.0, 32.1, 44.0],
     "one-pixel-wide ROI: passthrough extent"),
    ("identity_224", "pattern224", [0.0, 0.0, 224.0, 224.0],
     "224 ROI resized to 224 must be a byte-exact copy"),
    ("downsample_448", "pattern448", [0.0, 0.0, 448.0, 448.0],
     "exact 2x downsample dispatch (area-fast rounding)"),
    ("downscale_336", "pattern336", [0.0, 0.0, 336.0, 336.0],
     "exact 1.5x downscale (336 to 224): only 0.25/0.75 coefficients, no 11-bit rounding"),
    ("constant_rgb_channels", "steps", [8.0, 8.0, 24.0, 24.0],
     "channel order through crop+resize on constant blocks"),
    ("face_roi_300x260", "camera640", [254.0, 170.0, 364.5, 265.75],
     "interior face ROI 300x260 in a 640x480 frame (scales 1.339/1.161)"),
    ("full_frame_640x480", "camera640", [0.0, 0.0, 640.0, 480.0],
     "full 640x480 frame (scales 2.857/2.143): wider than the 585 px tie-margin bound"),
    ("clipped_roi_521x463", "camera640", [290.5, 188.5, 490.5, 388.5],
     "close face clipped right/bottom: odd ROI 521x463 (scales 2.326/2.067)"),
]

# Crop-only cases: bounds whose float32 m96 expansion truncates to a
# different integer than the same arithmetic in float64. (name, frame w/h,
# bbox, note)
CROP_CASES = [
    ("f32_margin_left_bound", (640, 480), [202.28570556640625, 120.0, 263.28570556640625, 181.0],
     "x - mx lands within float32 rounding of 150: float32 answers 150, float64 149"),
    ("f32_margin_right_bound", (640, 480), [288.5714111328125, 120.0, 348.5714111328125, 180.0],
     "x + bw + mx lands within float32 rounding of 400: float32 answers 400, float64 399"),
]

# Boxes where the scorer's NumPy slice gets a negative stop, which counts from
# the end of the axis and yields a non-empty chip. pad_vit_crop deliberately
# returns None there (the zero tensor). (name, recipe, bbox, note)
WRAP_CASES = [
    ("negative_stop_left_of_frame", "camera640", [-300.0, 100.0, -200.0, 200.0],
     "x2 = int(-114.29) = -114: the scorer slices columns 0..526"),
    ("negative_width", "camera640", [10.0, 100.0, -10.0, 200.0],
     "bw = -20: x1 = 27, x2 = -27, the scorer slices columns 27..613"),
]

PROBES = [(0, 0), (223, 0), (0, 223), (223, 223), (112, 112), (4, 0), (223, 112), (112, 223)]


def build_cases():
    out = []
    for name, recipe, bbox, note in CASES:
        rgb = make_frame(recipe)
        (x1, y1, x2, y2), chip, rgb224, tensor = reference(rgb, bbox)
        raw = np.ascontiguousarray(rgb224).tobytes()
        probes = [(x, y, [int(v) for v in rgb224[y, x]]) for x, y in PROBES]
        tprobes = []
        for plane in range(3):
            for x, y in ((0, 0), (223, 223), (112, 112)):
                tprobes.append((plane, y, x, float(tensor[plane, y, x])))
        tensor_le = np.ascontiguousarray(tensor).astype("<f4").tobytes()
        out.append({
            "name": name,
            "recipe": recipe,
            "bbox": [float(v) for v in bbox],
            "bbox_f32_bits": [int(np.float32(v).view(np.uint32)) for v in bbox],
            "crop": [x1, y1, x2, y2],
            "note": note,
            "rgb8_fnv1a64": fnv1a64(raw),
            "rgb8_bytes_sha256": sha(raw),
            "probes": probes,
            "tensor_probes": tprobes,
            "tensor_f32le_fnv1a64": fnv1a64(tensor_le),
            "tensor_f32le_sha256": sha(tensor_le),
            "exact_2x": x2 - x1 == OUT * 2 and y2 - y1 == OUT * 2,
            "tie_sums_2_mod_8": tie_count(chip, x2 - x1, y2 - y1),
        })
    return out


def crop_bounds_f64(w, h, bbox):
    """The m96 bounds in float64: the arithmetic the crop cases must reject."""
    x, y = float(np.float32(bbox[0])), float(np.float32(bbox[1]))
    bw = float(np.float32(bbox[2])) - x
    bh = float(np.float32(bbox[3])) - y
    mx, my = bw * (96.0 / 112.0), bh * (96.0 / 112.0)
    return (max(0, int(x - mx)), max(0, int(y - my)),
            min(w, int(x + bw + mx)), min(h, int(y + bh + my)))


def build_crop_cases():
    out = []
    for name, (w, h), bbox, note in CROP_CASES:
        rgb = np.zeros((h, w, 3), dtype=np.uint8)
        (x1, y1, x2, y2), _, _, _ = reference(rgb, bbox)
        if (x1, y1, x2, y2) == crop_bounds_f64(w, h, bbox):
            raise AssertionError(f"{name}: float64 gives the same bounds; must differ")
        out.append({
            "name": name,
            "frame": [w, h],
            "bbox": [float(v) for v in bbox],
            "bbox_f32_bits": [int(np.float32(v).view(np.uint32)) for v in bbox],
            "crop": [x1, y1, x2, y2],
            "crop_float64": list(crop_bounds_f64(w, h, bbox)),
            "note": note,
        })
    return out


def build_wrap_cases():
    out = []
    for name, recipe, bbox, note in WRAP_CASES:
        w, h = RECIPES[recipe]
        x1f, y1f, x2f, y2f = np.asarray(bbox, dtype=np.float32)
        face = np.array([x1f, y1f, x2f - x1f, y2f - y1f], dtype=np.float32)
        chip = CROP(np.zeros((h, w, 3), dtype=np.uint8), face, 96.0 / 112.0)
        if chip.size == 0:
            raise AssertionError(f"{name}: the scorer chip is empty; not a wrapping case")
        out.append({
            "name": name,
            "recipe": recipe,
            "bbox": [float(v) for v in bbox],
            "bbox_f32_bits": [int(np.float32(v).view(np.uint32)) for v in bbox],
            "scorer_chip_wh": [int(chip.shape[1]), int(chip.shape[0])],
            "note": note,
        })
    return out


RUST_HEADER = """\
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//
// GENERATED FILE - DO NOT EDIT.
// Generated by benchmarks/preprocessing-conformance/gen_pad_vit_fixtures.py
// (sha256 {gen_sha}). Regenerate with that script and re-review any diff.
//
// Oracle environment: cv2 {cv2} (opencv-python {opencv_python}), NumPy {numpy},
// Python {python} on {platform}; cv2 threads=1, optimized dispatch/OpenCL/IPP
// disabled.
// Contract: recorded scorer m96 integer crop (immutable scorer source at
// 6ee8ef5c) + RGB8 cv2.resize INTER_LINEAR, normalized (px/255-0.5)/0.5.
// Each FIXTURES case pins the exact crop bounds, the exact 224x224x3 RGB8
// resize output (FNV-1a-64 + probe pixels), the exact float32 CHW tensor
// (FNV-1a-64 of its little-endian bytes) and float32 tensor probe values.
// CROP_FIXTURES pin float32 m96 bounds that float64 arithmetic misses.
// SCORER_WRAP_CASES are boxes whose scorer slice wraps to a non-empty chip.

use super::pad_vit_input_tests::Recipe;
"""

RECIPE_NAMES = {
    "ramp32": "Ramp32",
    "wide": "Wide",
    "steps": "Steps",
    "grid48x40": "Grid48x40",
    "white64_blackroi": "White64BlackRoi",
    "pattern448": "Pattern448",
    "pattern224": "Pattern224",
    "pattern336": "Pattern336",
    "camera640": "Camera640",
}


def f32_literal(v):
    """Shortest decimal that parses back to the same float32."""
    return str(np.float32(v))


def oracle_environment():
    try:
        wheel = importlib.metadata.version("opencv-python")
    except importlib.metadata.PackageNotFoundError:
        wheel = "not installed"
    return {
        "cv2": cv2.__version__,
        "opencv_python": wheel,
        "numpy": np.__version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
    }


def emit_rust(cases, crop_cases, wrap_cases, gen_sha, env):
    lines = [RUST_HEADER.format(gen_sha=gen_sha, **env)]
    lines.append("pub(super) struct Fixture {\n"
                 "    pub name: &'static str,\n"
                 "    pub recipe: Recipe,\n"
                 "    pub bbox: [f32; 4],\n"
                 "    /// Half-open [x1, y1, x2, y2].\n"
                 "    pub crop: [i32; 4],\n"
                 "    /// FNV-1a-64 of the 224*224*3 RGB8 resize output.\n"
                 "    pub rgb8_fnv1a64: u64,\n"
                 "    /// FNV-1a-64 of the 3*224*224 float32 CHW tensor, little-endian.\n"
                 "    pub tensor_fnv1a64: u64,\n"
                 "    /// (x, y, [r, g, b]) probes of the RGB8 resize output.\n"
                 "    pub probes: &'static [(u16, u16, [u8; 3])],\n"
                 "    /// (plane, y, x, normalized value) probes.\n"
                 "    pub tensor_probes: &'static [(u8, u16, u16, f32)],\n"
                 "}\n")
    lines.append("pub(super) const FIXTURES: &[Fixture] = &[")
    for c in cases:
        bbox = ", ".join(f32_literal(v) for v in c["bbox"])
        crop = ", ".join(str(v) for v in c["crop"])
        probes = ", ".join(f"({x}, {y}, [{r}, {g}, {b}])"
                           for x, y, (r, g, b) in c["probes"])
        tprobes = ", ".join(f"({p}, {y}, {x}, {np.float32(v)!s}f32)"
                            for p, y, x, v in c["tensor_probes"])
        lines.append(f"    Fixture {{\n"
                     f"        name: \"{c['name']}\",\n"
                     f"        recipe: Recipe::{RECIPE_NAMES[c['recipe']]},\n"
                     f"        bbox: [{bbox}],\n"
                     f"        crop: [{crop}],\n"
                     f"        rgb8_fnv1a64: 0x{c['rgb8_fnv1a64']:016X},\n"
                     f"        tensor_fnv1a64: 0x{c['tensor_f32le_fnv1a64']:016X},\n"
                     f"        probes: &[{probes}],\n"
                     f"        tensor_probes: &[{tprobes}],\n"
                     f"    }},")
    lines.append("];\n")
    lines.append("pub(super) struct CropFixture {\n"
                 "    pub name: &'static str,\n"
                 "    /// Frame width and height.\n"
                 "    pub frame: (u32, u32),\n"
                 "    pub bbox: [f32; 4],\n"
                 "    /// Half-open [x1, y1, x2, y2] from the scorer's float32 expansion.\n"
                 "    pub crop: [i32; 4],\n"
                 "    /// The same expansion in float64, which the contract rejects.\n"
                 "    pub crop_float64: [i32; 4],\n"
                 "}\n")
    lines.append("pub(super) const CROP_FIXTURES: &[CropFixture] = &[")
    for c in crop_cases:
        w, h = c["frame"]
        lines.append(f"    CropFixture {{\n"
                     f"        name: \"{c['name']}\",\n"
                     f"        frame: ({w}, {h}),\n"
                     f"        bbox: [{', '.join(f32_literal(v) for v in c['bbox'])}],\n"
                     f"        crop: [{', '.join(str(v) for v in c['crop'])}],\n"
                     f"        crop_float64: [{', '.join(str(v) for v in c['crop_float64'])}],\n"
                     f"    }},")
    lines.append("];\n")
    lines.append("pub(super) struct WrapCase {\n"
                 "    pub name: &'static str,\n"
                 "    pub recipe: Recipe,\n"
                 "    pub bbox: [f32; 4],\n"
                 "    /// Width and height of the non-empty chip the scorer slices.\n"
                 "    pub scorer_chip_wh: [usize; 2],\n"
                 "}\n")
    lines.append("pub(super) const SCORER_WRAP_CASES: &[WrapCase] = &[")
    for c in wrap_cases:
        cw, ch = c["scorer_chip_wh"]
        lines.append(f"    WrapCase {{\n"
                     f"        name: \"{c['name']}\",\n"
                     f"        recipe: Recipe::{RECIPE_NAMES[c['recipe']]},\n"
                     f"        bbox: [{', '.join(f32_literal(v) for v in c['bbox'])}],\n"
                     f"        scorer_chip_wh: [{cw}, {ch}],\n"
                     f"    }},")
    lines.append("];")
    return "\n".join(lines) + "\n"


def self_check(cases, wrap_cases):
    for c in cases:
        if c["exact_2x"] and c["tie_sums_2_mod_8"] == 0:
            raise AssertionError(f"{c['name']}: no rounding-tie blocks; recipe must pin ties")
    for c in cases:
        if c["name"] == "ramp32_rounding_counterexample":
            px = [p for p in c["probes"] if p[0] == 4 and p[1] == 0][0]
            if px[2][2] != 0:
                raise AssertionError("counterexample (4,0,B) is not 0; oracle drift?")
        if c["name"] == "identity_224":
            rgb = make_frame(c["recipe"])
            if not np.array_equal(
                cv2.resize(rgb, (OUT, OUT), interpolation=cv2.INTER_LINEAR), rgb
            ):
                raise AssertionError("identity resize is not a byte-exact copy")
        if c["name"] == "black_roi_white_outside":
            rgb = make_frame(c["recipe"])
            _, _, rgb224, _ = reference(rgb, c["bbox"])
            if np.any(rgb224 != 0):
                raise AssertionError("black ROI chip must resize to all-zero")
    for c in wrap_cases:
        # The helper's None rule: non-positive extent or empty clipped bounds.
        x1f, y1f, x2f, y2f = np.asarray(c["bbox"], dtype=np.float32)
        w, h = RECIPES[c["recipe"]]
        x1, y1, x2, y2 = crop_bounds(np.zeros((h, w, 3), dtype=np.uint8), c["bbox"])
        if x2f - x1f > 0 and y2f - y1f > 0 and x2 > x1 and y2 > y1:
            raise AssertionError(f"{c['name']}: pad_vit_crop would not return None")


def describe(env):
    if not env:
        return "(none recorded)"
    return ", ".join(f"{k} {env[k]}" for k in sorted(env))


def check(cases, crop_cases, wrap_cases, gen_sha, receipt, strict_env):
    """Compare every fixture value exactly; report the environment apart."""
    committed = json.loads(RECEIPT.read_text()) if RECEIPT.exists() else {}
    env = receipt["oracle"]["environment"]
    recorded = committed.get("oracle", {}).get("environment")
    env_note = ""
    if recorded != env:
        env_note = (f"\nthe oracle environment ({describe(env)}) differs from the recorded "
                    f"one ({describe(recorded)}); committed fixtures are generated only in "
                    f"the recorded environment (README.md)")
    # Render with the recorded environment so only values and the generator
    # hash decide the comparison.
    expected_rust = emit_rust(cases, crop_cases, wrap_cases, gen_sha, recorded or env)
    current_rust = RUST_OUT.read_text() if RUST_OUT.exists() else ""
    if current_rust != expected_rust:
        raise SystemExit(f"{os.path.relpath(RUST_OUT, ROOT)}: fixture values or generator hash "
                         f"differ from this regeneration{env_note}")
    expected = json.loads(json.dumps(receipt))
    for snapshot in (committed, expected):
        snapshot.get("oracle", {}).pop("environment", None)
    if committed != expected:
        raise SystemExit(f"{RECEIPT.name}: fixture values, settings or generator hash differ "
                         f"from this regeneration{env_note}")
    if env_note:
        if strict_env:
            raise SystemExit(f"--strict-env:{env_note}")
        print(f"warning: every fixture value matches;{env_note}")
    print("fixtures and receipt are current")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="fail if any fixture value or the generator hash would change")
    ap.add_argument("--strict-env", action="store_true",
                    help="with --check, also fail when the oracle environment differs")
    args = ap.parse_args()

    gen_sha = sha(Path(__file__).read_bytes())
    cases = build_cases()
    crop_cases = build_crop_cases()
    wrap_cases = build_wrap_cases()
    self_check(cases, wrap_cases)

    env = oracle_environment()
    receipt = {
        "generator": f"{REL}/gen_pad_vit_fixtures.py",
        "generator_sha256": gen_sha,
        "oracle": {
            "environment": env,
            "settings": {
                "threads": 1, "use_optimized": False, "opencl": False, "ipp": False,
                "interpolation": "cv2.INTER_LINEAR (RGB8)",
            },
            "scorer_source": SCORER,
            "scorer_source_sha256": SCORER_SHA256,
            "scorer_baseline": "6ee8ef5ca48f9f1ec7f9ee9b2eac876915a92820",
        },
        "cases": cases,
        "crop_cases": crop_cases,
        "wrap_cases": wrap_cases,
    }

    if args.check:
        check(cases, crop_cases, wrap_cases, gen_sha, receipt, args.strict_env)
        return

    RUST_OUT.write_text(emit_rust(cases, crop_cases, wrap_cases, gen_sha, env))
    RECEIPT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(f"wrote {RUST_OUT.relative_to(ROOT)} and {RECEIPT.name}: "
          f"{len(cases)} cases, {len(crop_cases)} crop cases, {len(wrap_cases)} wrap cases, "
          + ", ".join(f"{c['name']} ties={c['tie_sums_2_mod_8']}" for c in cases
                      if c['exact_2x']))


if __name__ == "__main__":
    main()
