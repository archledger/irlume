#!/usr/bin/env python3
"""ViT liveness LFW at-scale control (genuine side), 2026-08-21.

All 13,233 LFW crops / 5,749 ids through the ViT liveness model, tight and
tight and m96 crop margins (m96 is the live-corpus operating candidate).
All-genuine corpus: the genuine mass must sit near P(spoof)=0.

Usage: vit_lfw_score.py <lfw-root> <out.csv>
"""
import csv
import sys
import time
from pathlib import Path

import cv2
import numpy as np

from vit_liveness_score import crop, detect, infer  # noqa: E402


def main():
    lfw = Path(sys.argv[1])
    out_csv = Path(sys.argv[2])
    files = sorted(lfw.rglob("*.jpg"))
    rows = []
    t0 = time.perf_counter()
    for i, fp in enumerate(files):
        bgr = cv2.imread(str(fp), cv2.IMREAD_COLOR)
        if bgr is None:
            rows.append([fp.name, "unreadable", "", ""])
            continue
        f = detect(bgr)
        if f is None:
            rows.append([fp.name, "no-detect", "", ""])
            continue
        rows.append([fp.name, "ok",
                     f"{infer(crop(bgr, f, 0.0)):.4f}",
                     f"{infer(crop(bgr, f, 96.0 / 112.0)):.4f}"])
        if (i + 1) % 2000 == 0:
            el = time.perf_counter() - t0
            print(f"{i+1}/{len(files)} ({el:.0f}s, {(i+1)/el:.1f} fps)",
                  flush=True)
    with open(out_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["frame", "note", "p_spoof_tight", "p_spoof_m96"])
        w.writerows(rows)
    for i, name in ((2, "tight"), (3, "m96")):
        vs = np.array([float(r[i]) for r in rows if r[1] == "ok"])
        nd = sum(1 for r in rows if r[1] == "no-detect")
        print(f"{name}: scored {len(vs)} no-detect {nd}")
        for q in (1, 25, 50, 75, 90, 99):
            print(f"  q{q:02d}: {np.percentile(vs, q):.4f}")
        print(f"  spoof-flagged@0.5: {(vs >= 0.5).sum()}  @0.9: {(vs >= 0.9).sum()}")


if __name__ == "__main__":
    main()
