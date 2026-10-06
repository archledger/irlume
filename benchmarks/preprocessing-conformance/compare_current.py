#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Current-candidate pad preprocessing comparison (issue #795).

Separately identified from the #972 baseline replay: this compiles the
`pad_vit_input` region of the CURRENT working tree (never a pinned Git
object), runs it over the generated fixture cases and compares every output
element against the live recorded-scorer oracle (scorer crop + RGB8
`cv2.resize` INTER_LINEAR + normalization). Exact source hashes of every
input, the rustc version, the checkout's HEAD commit and any uncommitted
change to the measured files are recorded in the receipt, so a receipt names
the commit it covers. `--require-clean` refuses to run while any measured
file differs from HEAD; use it for the receipt archived for a PR head.
`cargo test` enforces the same per-case equality through the fixtures'
full-tensor hashes; this script is the element-wise cross-check.

The #972 `verify.py` replay measures immutable baseline 6ee8ef5c and must
never be used as this helper's regression gate; `gen_pad_vit_fixtures.py`
fixtures plus this comparison are the current-candidate evidence.

Run from the repository root:

    python3 benchmarks/preprocessing-conformance/compare_current.py [--require-clean]
"""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
import cv2
import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REL = str(HERE.relative_to(ROOT))
BUILD = HERE / "build-current"
RECEIPT = HERE / "pad-vit-current-comparison.json"

sys.path.insert(0, str(HERE))
from gen_pad_vit_fixtures import (  # noqa: E402
    CASES, OUT, make_frame, reference,
)
import run as conformance_run  # noqa: E402

cv2.setNumThreads(1)
cv2.setUseOptimized(False)
cv2.ocl.setUseOpenCL(False)
cv2.ipp.setUseIPP(False)


def sha(data):
    return hashlib.sha256(data).hexdigest()


SOURCE_PATHS = [
    "crates/irlume-camera/src/lib.rs",
    "crates/irlume-vision/src/lib.rs",
    "crates/irlume-vision/src/align.rs",
]
MEASURED_PATHS = [
    *SOURCE_PATHS,
    "crates/irlume-vision/src/pad_vit_fixtures.rs",
    f"{REL}/gen_pad_vit_fixtures.py",
    f"{REL}/compare_current.py",
    f"{REL}/run.py",
    f"{REL}/probe.rs",
]


def current_sources():
    """The measured inputs come from the working tree, hashed, never `git show`."""
    out = {}
    for name in SOURCE_PATHS:
        data = (ROOT / name).read_bytes()
        out[name] = {"sha256": sha(data)}
    return out


def checkout_state(root=ROOT):
    """HEAD and the measured paths (sources, oracle, this script) that differ from it."""
    git = ["git", "-C", str(root)]
    head = subprocess.run([*git, "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()
    status = subprocess.run([*git, "status", "--porcelain", "--", *MEASURED_PATHS], check=True,
                            capture_output=True, text=True).stdout
    return {"head": head, "modified_measured_paths": sorted(line[3:] for line in status.splitlines())}


def require_clean(state):
    """Refuse a receipt that would not describe the commit it names."""
    if state["modified_measured_paths"]:
        raise SystemExit(
            f"--require-clean: measured paths differ from HEAD {state['head']}: "
            + ", ".join(state["modified_measured_paths"]))


def rustc_version():
    out = subprocess.run(["rustc", "+1.88.0", "--version"], check=True,
                         capture_output=True, text=True, cwd=ROOT).stdout.strip()
    if not out.startswith("rustc 1.88.0 "):
        raise SystemExit(f"rustc +1.88.0 resolved to {out!r}; a rustup toolchain is required")
    return out


def compile_probe():
    camera = (ROOT / "crates/irlume-camera/src/lib.rs").read_text()
    vision = (ROOT / "crates/irlume-vision/src/lib.rs").read_text()
    align = (ROOT / "crates/irlume-vision/src/align.rs").read_text()
    pure = "// SPDX-License-Identifier: GPL-3.0-or-later\n"
    pure += "// Copyright the irlume contributors.\n"
    pure += conformance_run.extract(camera, "pub fn yuyv_to_rgb(", "/// Pull and discard one frame")
    # The current helper reads RgbView fields directly, so the view's
    # sampling helpers are intentionally unused in this probe.
    pure += "\n#[allow(dead_code)]\nmod align {\n"
    pure += conformance_run.extract(align, "pub struct RgbView<'a>", "/// A grey 8-bit frame view")
    pure += "\n}\n"
    pure += conformance_run.extract(vision, "    fn pad_vit_input(", "    /// Preprocessing arithmetic tests")
    BUILD.mkdir(exist_ok=True)
    (BUILD / "pure.rs").write_text(pure)
    (BUILD / "probe.rs").write_bytes((HERE / "probe.rs").read_bytes())
    subprocess.run(
        ["rustc", "+1.88.0", "--edition=2021", "-Dwarnings", "-Ccodegen-units=1",
         "-Copt-level=0", str(BUILD / "probe.rs"), "-o", str(BUILD / "probe")],
        check=True, capture_output=True, cwd=ROOT)
    return sha(pure.encode())


def rust_pad(image, w, h, bbox):
    out = subprocess.run(
        [str(BUILD / "probe"), "pad", str(w), str(h), *map(str, bbox)],
        input=image.tobytes(), capture_output=True, check=True, cwd=ROOT).stdout
    return np.frombuffer(out, dtype="<f4").reshape(3, OUT, OUT)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--require-clean", action="store_true",
                        help="fail unless every measured path matches HEAD")
    args = parser.parse_args()
    sources = current_sources()
    state = checkout_state()
    if args.require_clean:
        require_clean(state)
    rustc = rustc_version()
    pure_sha = compile_probe()
    cases = []
    worst = 0.0
    for name, recipe, bbox, _note in CASES:
        rgb = make_frame(recipe)
        (x1, y1, x2, y2), _chip, _rgb224, oracle = reference(rgb, bbox)
        h, w = rgb.shape[:2]
        actual = rust_pad(rgb, w, h, bbox)
        delta = np.abs(actual.astype(np.float64) - oracle.astype(np.float64))
        worst = max(worst, float(delta.max()))
        cases.append({
            "case": name,
            "crop": [x1, y1, x2, y2],
            "max_abs": float(delta.max()),
            "differing_elements": int(np.count_nonzero(delta > 1e-6)),
            "elements": int(delta.size),
        })
    receipt = {
        "probe": f"{REL}/compare_current.py",
        "pure_source_sha256": pure_sha,
        "rustc": rustc,
        "source_sha256": sources,
        "checkout": state,
        "oracle": {
            "cv2": cv2.__version__,
            "numpy": np.__version__,
            "python": platform.python_version(),
            "settings": "threads=1, optimized dispatch/OpenCL/IPP disabled",
        },
        "cases": cases,
        "worst_max_abs": worst,
    }
    RECEIPT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    modified = ", ".join(state["modified_measured_paths"]) or "none"
    print(f"compared {len(cases)} cases at HEAD {state['head']} "
          f"(modified measured paths: {modified}); worst |delta| = {worst}")
    for c in cases:
        print(f"  {c['case']}: max_abs={c['max_abs']:.3e} "
              f"differing={c['differing_elements']}/{c['elements']}")
    if any(c["differing_elements"] for c in cases):
        raise SystemExit("current candidate differs from the recorded-scorer oracle")


if __name__ == "__main__":
    main()
