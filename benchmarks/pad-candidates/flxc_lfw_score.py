#!/usr/bin/env python3
"""FLXC LFW at-scale mechanism control, 2026-08-21.

Scores every LFW crop (13,233 images, 5,749 identities — the same corpus the
mn3 sanity control used) through FLXC in its degenerate single-image mode,
warp route. Mechanism test: if FLXC-without-flash reads ordinary camera
imagery as out-of-distribution -> spoof, a 5,749-identity genuine population
should saturate high, confirming the 2026-08-21 live-session finding at
scale. Reports the distribution only; LFW has no attack class.

Reuses flxc_live_score.py's detect/chip_warp/infer (pinned hashes there).

Usage: flxc_lfw_score.py <lfw-root> <out.csv>   (lfw-root holds pairs.csv + train/)
"""
import csv
import sys
import time
from pathlib import Path

import cv2
import numpy as np

from flxc_live_score import chip_warp, detect, infer  # noqa: E402


def main():
    lfw = Path(sys.argv[1])
    out_csv = Path(sys.argv[2])
    files = sorted(lfw.rglob("*.jpg"))
    rows = []
    t0 = time.perf_counter()
    for i, fp in enumerate(files):
        bgr = cv2.imread(str(fp), cv2.IMREAD_COLOR)
        if bgr is None:
            rows.append([fp.name, "unreadable", ""])
            continue
        f = detect(bgr)
        if f is None:
            rows.append([fp.name, "no-detect", ""])
            continue
        rows.append([fp.name, "ok", f"{infer(chip_warp(bgr, f)):.4f}"])
        if (i + 1) % 2000 == 0:
            print(f"{i+1}/{len(files)} ({time.perf_counter()-t0:.0f}s)", flush=True)
    with open(out_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["frame", "note", "p_fake_warp"])
        w.writerows(rows)
    vs = np.array([float(r[2]) for r in rows if r[1] == "ok"])
    nd = sum(1 for r in rows if r[1] == "no-detect")
    print(f"scored {len(vs)}, no-detect {nd}")
    for q in (0.01, 0.25, 0.5, 0.75, 0.99):
        print(f"  p_fake q{int(q*100):02d}: {np.percentile(vs, q):.4f}")
    print(f"  flagged@0.5: {(vs >= 0.5).sum()}/{len(vs)}  @0.9: {(vs >= 0.9).sum()}/{len(vs)}")


if __name__ == "__main__":
    main()
