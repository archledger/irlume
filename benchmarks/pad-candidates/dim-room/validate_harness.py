#!/usr/bin/env python3
"""Check this harness against the recorded 2026-08-21 LFW m96 scores.

Rescores an evenly spaced sample of the rows in
docs/research/2026-08-21-vit-lfw-scores.csv with dim_room_score.py's detector
and preprocessing and reports per-frame deltas plus the two distributions'
median and q90. Then, on the distinct faces of the grain and photon samples,
counts crops whose bounds differ between the harness (YuNet's width and
height) and the shipped arithmetic (width and height rebuilt from float32
corners). Exits non-zero unless every sampled row is rescored exactly to four
decimals, every sampled face is detected and no crop bound differs.

Usage: validate_harness.py <lfw-root> [--n N] [--models-dir DIR]
"""
import argparse
import csv
from pathlib import Path

import cv2
import numpy as np

import dim_room_score as h

RECORDED = Path(__file__).resolve().parents[3] / "docs/research/2026-08-21-vit-lfw-scores.csv"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("lfw_root", type=Path)
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--models-dir", type=Path, default=h.MODELS)
    a = ap.parse_args()
    h.require_numpy2()
    h.verify_models(a.models_dir)
    h._init(a.models_dir)
    with RECORDED.open(newline="") as fh:
        rows = [r for r in csv.DictReader(fh) if r["note"] == "ok"]
    picks = rows[:: max(1, len(rows) // a.n)][: a.n]
    paths = {p.name: p for p in a.lfw_root.rglob("*.jpg")}
    got, want = [], []
    for r in picks:
        bgr = cv2.imread(str(paths[r["frame"]]), cv2.IMREAD_COLOR)
        hh, ww = bgr.shape[:2]
        h.det.setInputSize((ww, hh))
        _, faces = h.det.detect(bgr)
        if faces is None or len(faces) == 0:
            print(f"{r['frame']}: no detection now")
            continue
        got.append(h.infer(h.crop_m96(bgr, max(faces, key=lambda x: x[2] * x[3]))))
        want.append(float(r["p_spoof_m96"]))
    got, want = np.array(got), np.array(want)
    d = np.abs(got - want)
    print(f"frames {len(d)}: |delta| median {np.median(d):.4f} p90 {np.percentile(d, 90):.4f} "
          f"max {d.max():.4f}; exact to 4 dp {(d < 5e-5).mean() * 100:.1f}%")
    print(f"recorded median {np.median(want):.3f} q90 {np.percentile(want, 90):.3f}; "
          f"rescored median {np.median(got):.3f} q90 {np.percentile(got, 90):.3f}")

    faces = {p.name: p for n in h.DEFAULT_N.values() for p in h.sample_files(a.lfw_root, n)}
    differ = missed = 0
    for name in sorted(faces):
        bgr = cv2.imread(str(faces[name]), cv2.IMREAD_COLOR)
        hh, ww = bgr.shape[:2]
        h.det.setInputSize((ww, hh))
        _, found = h.det.detect(bgr)
        if found is None or len(found) == 0:
            missed += 1
            print(f"{name}: no detection")
            continue
        f = max(found, key=lambda x: x[2] * x[3])
        if h.crop_bounds(f, ww, hh) != h.shipped_crop_bounds(f, ww, hh):
            differ += 1
            print(f"{name}: harness {h.crop_bounds(f, ww, hh)} shipped {h.shipped_crop_bounds(f, ww, hh)}")
    print(f"crop bounds differing from the shipped arithmetic: {differ} of {len(faces)} sampled faces")
    problems = []
    if len(got) != len(picks):
        problems.append(f"{len(picks) - len(got)} sampled rows not rescored")
    if d.max() >= 5e-5:
        problems.append(f"{int((d >= 5e-5).sum())} rows differ at four decimals")
    if missed or differ:
        problems.append(f"{missed} sampled faces undetected, {differ} crop bounds differ")
    if problems:
        raise SystemExit("validation failed: " + "; ".join(problems))
    print("validation passed")


if __name__ == "__main__":
    main()
