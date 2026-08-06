#!/usr/bin/env python3
"""The full-range BlazeFace parity GATE (#295 stage 2): fail-closed.

Compares irlume's decoder output (examples/blaze_full_parity.rs) against the
official mediapipe runtime's (scripts/mp-face-detector-bench.py --floor 0.6)
over the same corpus, and exits non-zero unless every bound holds. Both
inputs must cover the same frame set; a missing frame on either side is a
failure, not a smaller denominator, so a harness that silently shrank its
CSV cannot turn this into a vacuous pass (#298 review).

The bounds are regression pins from the 2026-08-05 measured run (mean IoU
0.932, min 0.782), set with a small margin, not tuned aspirations: a decoder
change that costs agreement or a few IoU points trips them.

One tolerance is explicit rather than hidden: two preprocessing paths carry
a few hundredths of score noise, so a frame whose true score sits ON the
floor can legitimately flip the binary decision between instruments (the
measured run has exactly one such frame: official 0.5774 vs rust 0.6233 at
the 0.6 floor). A disagreement is tolerated ONLY when the detecting side's
score is inside the floor band (floor + SCORE_DELTA_MEAN_MAX), the count is
capped, and every tolerated frame is printed. Anything outside the band, or
more than the cap, fails.

Usage: compare-blaze-parity.py <official.csv> <rust.csv>
"""
import csv
import statistics
import sys

KEY = ("camera", "segment", "kind", "frame")
MIN_FRAMES = 300
MEAN_IOU_MIN = 0.90
MIN_IOU_MIN = 0.75
SCORE_DELTA_MEAN_MAX = 0.05
PARITY_FLOOR = 0.6
FLOOR_BAND_MAX_FRAMES = 5


def load(path, official):
    rows = list(csv.DictReader(open(path, newline="")))
    if official:
        rows = [r for r in rows if r["model"] == "full"]
    out = {tuple(r[k] for k in KEY): r for r in rows}
    if not out:
        raise SystemExit(f"{path}: zero rows")
    if len(out) != len(rows):
        raise SystemExit(f"{path}: duplicate frame keys")
    return out


def box(row):
    return tuple(float(row[k]) for k in ("x1", "y1", "x2", "y2"))


def iou(a, b):
    ix = max(0.0, min(a[2], b[2]) - max(a[0], b[0]))
    iy = max(0.0, min(a[3], b[3]) - max(a[1], b[1]))
    inter = ix * iy
    union = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / union if union > 0 else 0.0


def main(official_path, rust_path):
    official = load(official_path, True)
    rust = load(rust_path, False)
    if set(official) != set(rust):
        only_o = sorted(set(official) - set(rust))[:5]
        only_r = sorted(set(rust) - set(official))[:5]
        raise SystemExit(
            f"frame sets differ: {len(official)} official vs {len(rust)} rust; "
            f"official-only {only_o}; rust-only {only_r}"
        )
    if len(official) < MIN_FRAMES:
        raise SystemExit(f"only {len(official)} frames; expected >= {MIN_FRAMES}")

    disagreements, floor_band = [], []
    ious, deltas = [], []
    for key, o in official.items():
        r = rust[key]
        o_det, r_det = o["score"] != "", r["score"] != ""
        if o_det != r_det:
            detecting = float(o["score"] or r["score"])
            if detecting < PARITY_FLOOR + SCORE_DELTA_MEAN_MAX:
                floor_band.append((key, o["score"], r["score"]))
            else:
                disagreements.append((key, o["score"], r["score"]))
            continue
        if o_det:
            ious.append(iou(box(o), box(r)))
            deltas.append(abs(float(o["score"]) - float(r["score"])))

    for f in floor_band:
        print("FLOOR-BAND (tolerated):", f)
    if len(floor_band) > FLOOR_BAND_MAX_FRAMES:
        raise SystemExit(
            f"{len(floor_band)} floor-band frames > cap {FLOOR_BAND_MAX_FRAMES}"
        )
    if disagreements:
        for d in disagreements[:10]:
            print("DISAGREE:", d)
        raise SystemExit(f"{len(disagreements)} detection disagreements beyond the floor band")
    if not ious:
        raise SystemExit("zero frames where both detected; nothing was compared")
    mean_iou = statistics.mean(ious)
    min_iou = min(ious)
    mean_delta = statistics.mean(deltas)
    print(
        f"frames={len(official)} both-detect={len(ious)} "
        f"mean-IoU={mean_iou:.4f} min-IoU={min_iou:.4f} mean-|score-delta|={mean_delta:.4f}"
    )
    if mean_iou < MEAN_IOU_MIN:
        raise SystemExit(f"mean IoU {mean_iou:.4f} < {MEAN_IOU_MIN}")
    if min_iou < MIN_IOU_MIN:
        raise SystemExit(f"min IoU {min_iou:.4f} < {MIN_IOU_MIN}")
    if mean_delta > SCORE_DELTA_MEAN_MAX:
        raise SystemExit(f"mean |score delta| {mean_delta:.4f} > {SCORE_DELTA_MEAN_MAX}")
    print("PARITY OK")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2])
