#!/usr/bin/env python3
"""Live session scorer for the 2026-08-22 ViT-PAD qualification.

Scores ~/irlume-research/2026-08-22-vit-live/<cond>/rgb/*.ppm through the
Adedev-W ViT liveness model with the m96 crop (the offline operating
candidate; tight recorded for reference), and reports BOTH frame-level
stats and the 5-frame-median presentation verdict at the 0.60 threshold
(the offline operating point; window [0.56, 0.604]).

Pinned inputs (identical to the offline evaluation):
  ViT model  sha256 c7f8a6f3054b11f9719f5e24d37ec227721608fff8b90373c6c3e7659864161c
  YuNet      sha256 8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4

Usage: vit_live_session.py [<root>] [--thr 0.60]
"""
import csv
import glob
import os
import sys
from pathlib import Path

import cv2
import numpy as np

MODEL = os.environ.get(
    "VIT_MODEL", "/home/wisbfime/Downloads/liveness_vit_with_meta.onnx")
YUNET = str(Path.home() / "irlume/models/face_detection_yunet_2023mar.onnx")

import onnxruntime as ort  # noqa: E402

sess = ort.InferenceSession(MODEL, providers=["CPUExecutionProvider"])
inp_name = sess.get_inputs()[0].name
det = cv2.FaceDetectorYN.create(YUNET, "", (320, 320), 0.5, 0.3, 5000)


def detect(bgr):
    h, w = bgr.shape[:2]
    det.setInputSize((w, h))
    n, faces = det.detect(bgr)
    if faces is None or len(faces) == 0:
        return None
    return max(faces, key=lambda f: f[2] * f[3])


def crop_m96(bgr, f):
    x, y, bw, bh = f[:4]
    m = 96.0 / 112.0
    x1 = max(0, int(x - bw * m))
    y1 = max(0, int(y - bh * m))
    x2 = min(bgr.shape[1], int(x + bw + bw * m))
    y2 = min(bgr.shape[0], int(y + bh + bh * m))
    return bgr[y1:y2, x1:x2]


def crop_tight(bgr, f):
    x, y, bw, bh = f[:4]
    return bgr[int(y):int(y + bh), int(x):int(x + bw)]


def infer(chip):
    rgb = cv2.cvtColor(chip, cv2.COLOR_BGR2RGB)
    rgb = cv2.resize(rgb, (224, 224), interpolation=cv2.INTER_LINEAR)
    x = rgb.astype(np.float32) / 255.0
    x = (x - 0.5) / 0.5
    t = x.transpose(2, 0, 1)[np.newaxis]
    logits = sess.run(None, {inp_name: t})[0][0]
    e = np.exp(logits - logits.max())
    return float((e / e.sum())[1])


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else
                Path.home() / "irlume-research/2026-08-22-vit-live")
    thr = 0.60
    if "--thr" in sys.argv:
        thr = float(sys.argv[sys.argv.index("--thr") + 1])
    rows = []
    conds = sorted(p.name for p in root.iterdir() if p.is_dir())
    for cond in conds:
        files = sorted(glob.glob(str(root / cond / "rgb" / "*.ppm")))
        if not files:
            continue
        ps96, pti = [], []
        for fp in files:
            bgr = cv2.imread(fp, cv2.IMREAD_COLOR)
            f = detect(bgr) if bgr is not None else None
            if f is None:
                rows.append([cond, os.path.basename(fp), "no-detect", "", ""])
                continue
            a, b = infer(crop_m96(bgr, f)), infer(crop_tight(bgr, f))
            ps96.append(a)
            pti.append(b)
            rows.append([cond, os.path.basename(fp), "ok", f"{b:.4f}", f"{a:.4f}"])
        if not ps96:
            print(f"{cond}: 0 scored (all no-detect)")
            continue
        v = np.array(ps96)
        # 5-frame median voting over consecutive windows
        wins = [float(np.median(v[i:i + 5])) for i in range(0, len(v) - 4)]
        flags = sum(w >= thr for w in wins)
        print(f"{cond}: n={len(v)} nodet={len(files)-len(v)} | "
              f"m96 min {v.min():.3f} med {np.median(v):.3f} max {v.max():.3f} | "
              f"frame>=thr {(v>=thr).sum()}/{len(v)} | "
              f"5med-max {max(wins):.3f} | VOTE {'SPOOF' if flags else 'REAL'} "
              f"({flags}/{len(wins)} windows)")
    out = root / "session-scores.csv"
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["cond", "frame", "note", "p_spoof_tight", "p_spoof_m96"])
        w.writerows(rows)
    print("wrote", out)


if __name__ == "__main__":
    main()
