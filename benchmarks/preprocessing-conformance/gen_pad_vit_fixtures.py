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

`--check` regenerates and fails if the emitted Rust fixtures or the receipt
would change. The receipt records the oracle versions, dispatch settings and
source hashes used for the generation.
"""

import argparse
import ast
import hashlib
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
}


def make_frame(name):
    w, h = RECIPES[name]
    frame = np.zeros((h, w, 3), dtype=np.uint8)
    for y in range(h):
        for x in range(w):
            frame[y, x] = recipe_pixel(name, x, y)
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
     "non-exact-2x downscale (336 to 224): the production-typical ROI>224 regime"),
    ("constant_rgb_channels", "steps", [8.0, 8.0, 24.0, 24.0],
     "channel order through crop+resize on constant blocks"),
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
            "exact_2x": x2 - x1 == OUT * 2 and y2 - y1 == OUT * 2,
            "tie_sums_2_mod_8": tie_count(chip, x2 - x1, y2 - y1),
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
// Oracle: {cv2_ver} (cv2 {cv2_mod}), NumPy {np_ver}, Python {py_ver} on
// {platform}; cv2 threads=1, optimized dispatch/OpenCL/IPP disabled.
// Contract: recorded scorer m96 integer crop (immutable scorer source at
// 6ee8ef5c) + RGB8 cv2.resize INTER_LINEAR, normalized (px/255-0.5)/0.5.
// Each case pins the exact crop bounds and the exact 224x224x3 RGB8 resize
// output (FNV-1a-64 + probe pixels) and float32 tensor probe values.

use super::pad_vit_input_tests::Recipe;
"""


def emit_rust(cases, gen_sha):
    lines = [RUST_HEADER.format(
        gen_sha=gen_sha,
        cv2_ver=cv2.__version__,
        cv2_mod="opencv-python (runtime module version above)",
        np_ver=np.__version__,
        py_ver=platform.python_version(),
        platform=f"{platform.system()} {platform.machine()}",
    )]
    lines.append("pub(super) struct Fixture {\n"
                 "    pub name: &'static str,\n"
                 "    pub recipe: Recipe,\n"
                 "    pub bbox: [f32; 4],\n"
                 "    /// Half-open [x1, y1, x2, y2].\n"
                 "    pub crop: [i32; 4],\n"
                 "    /// FNV-1a-64 of the 224*224*3 RGB8 resize output.\n"
                 "    pub rgb8_fnv1a64: u64,\n"
                 "    /// (x, y, [r, g, b]) probes of the RGB8 resize output.\n"
                 "    pub probes: &'static [(u16, u16, [u8; 3])],\n"
                 "    /// (plane, y, x, normalized value) probes.\n"
                 "    pub tensor_probes: &'static [(u8, u16, u16, f32)],\n"
                 "}\n")
    lines.append("pub(super) const FIXTURES: &[Fixture] = &[")
    for c in cases:
        recipe = c["recipe"]
        rname = {
            "ramp32": "Ramp32",
            "wide": "Wide",
            "steps": "Steps",
            "grid48x40": "Grid48x40",
            "white64_blackroi": "White64BlackRoi",
            "pattern448": "Pattern448",
            "pattern224": "Pattern224",
            "pattern336": "Pattern336",
        }[recipe]
        bbox = ", ".join(repr(v) for v in c["bbox"])
        crop = ", ".join(str(v) for v in c["crop"])
        probes = ", ".join(f"({x}, {y}, [{r}, {g}, {b}])"
                           for x, y, (r, g, b) in c["probes"])
        tprobes = ", ".join(f"({p}, {y}, {x}, {np.float32(v)!s}f32)"
                            for p, y, x, v in c["tensor_probes"])
        lines.append(f"    Fixture {{\n"
                     f"        name: \"{c['name']}\",\n"
                     f"        recipe: Recipe::{rname},\n"
                     f"        bbox: [{bbox}],\n"
                     f"        crop: [{crop}],\n"
                     f"        rgb8_fnv1a64: 0x{c['rgb8_fnv1a64']:016X},\n"
                     f"        probes: &[{probes}],\n"
                     f"        tensor_probes: &[{tprobes}],\n"
                     f"    }},")
    lines.append("];")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="fail if the emitted files would change")
    args = ap.parse_args()

    gen_sha = sha(Path(__file__).read_bytes())
    cases = build_cases()
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

    rust = emit_rust(cases, gen_sha)
    receipt = {
        "generator": f"{REL}/gen_pad_vit_fixtures.py",
        "generator_sha256": gen_sha,
        "oracle": {
            "cv2": cv2.__version__,
            "numpy": np.__version__,
            "python": platform.python_version(),
            "platform": f"{platform.system()} {platform.machine()}",
            "settings": {
                "threads": 1, "use_optimized": False, "opencl": False, "ipp": False,
                "interpolation": "cv2.INTER_LINEAR (RGB8)",
            },
            "scorer_source": SCORER,
            "scorer_source_sha256": SCORER_SHA256,
            "scorer_baseline": "6ee8ef5ca48f9f1ec7f9ee9b2eac876915a92820",
        },
        "source_sha256": {
            "crates/irlume-vision/src/lib.rs": sha(
                (ROOT / "crates/irlume-vision/src/lib.rs").read_bytes()),
            "crates/irlume-vision/src/align.rs": sha(
                (ROOT / "crates/irlume-vision/src/align.rs").read_bytes()),
        },
        "cases": cases,
    }
    receipt_text = json.dumps(receipt, indent=2, sort_keys=True) + "\n"

    if args.check:
        current_rust = RUST_OUT.read_text() if RUST_OUT.exists() else ""
        if current_rust != rust:
            raise SystemExit(f"{RUST_OUT.relative_to(ROOT)} is stale; regenerate")
        # The receipt's source_sha256 records the generation-time source
        # state and is informational; the oracle, cases and generator hashes
        # must match a regeneration exactly.
        current_receipt = json.loads(RECEIPT.read_text()) if RECEIPT.exists() else {}
        expected = json.loads(receipt_text)
        for snapshot in (current_receipt, expected):
            snapshot.pop("source_sha256", None)
        if current_receipt != expected:
            raise SystemExit(f"{RECEIPT.name} is stale; regenerate")
        print("fixtures and receipt are current")
        return

    RUST_OUT.write_text(rust)
    RECEIPT.write_text(receipt_text)
    print(f"wrote {RUST_OUT.relative_to(ROOT)} and {RECEIPT.name}: "
          f"{len(cases)} cases, "
          + ", ".join(f"{c['name']} ties={c['tie_sums_2_mod_8']}" for c in cases
                      if c['exact_2x']))


if __name__ == "__main__":
    main()
