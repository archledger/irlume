#!/usr/bin/env python3
"""ViT liveness (Adedev-W/LivenessModels-ONNX liveness_vit_with_meta.onnx)
live-corpora scorer, 2026-08-21.

Third RGB PAD candidate for the slot left open by the flrgb/flxc declines.

Pinned inputs:
  ViT model  sha256 c7f8a6f3054b11f9719f5e24d37ec227721608fff8b90373c6c3e7659864161c
  YuNet      sha256 8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4

Model facts (from the artifact + repo Example/ONNX-python.py):
  ViT-base (google/vit layout), opset 14, input pixel_values 1x3x224x224,
  output logits [1,2], metadata id2label {"0": "real", "1": "spoof"}.
  Preprocessing per the repo example: the (pre-cropped) face image is
  RESIZED (no warp, no documented bbox convention) to 224, RGB, /255,
  mean 0.5 std 0.5, CHW. Output is raw logits; softmax applied here.
  Score = P(spoof) = softmax(logits)[1].

The repo documents NO face-crop convention (the example feeds a
"face_image.jpg"), so three crop margins are scored: tight YuNet bbox,
bbox + 25% per side, and bbox + 96/112 per side (the DAMO-family
convention). Detection: irlume's shipped YuNet (standing deviation).

Usage: vit_liveness_score.py <corpus-root> <out.csv> [--lfw <lfw-root> <out2.csv>]
  corpus-root/<cond>/rgb/*.ppm for cond in genuine-desk genuine-lowlight
  attack-print.
"""
import csv
import glob
import os
import sys
import time
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

MODEL = os.environ.get("VIT_MODEL", "liveness_vit_with_meta.onnx")
YUNET = os.environ.get(
    "IRLUME_YUNET",
    str(Path.home() / "irlume/models/face_detection_yunet_2023mar.onnx"),
)

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


def crop(bgr, f, margin):
    x, y, bw, bh = f[:4]
    mx, my = bw * margin, bh * margin
    x1 = max(0, int(x - mx))
    y1 = max(0, int(y - my))
    x2 = min(bgr.shape[1], int(x + bw + mx))
    y2 = min(bgr.shape[0], int(y + bh + my))
    return bgr[y1:y2, x1:x2]


def infer(chip_bgr):
    rgb = cv2.cvtColor(chip_bgr, cv2.COLOR_BGR2RGB)
    rgb = cv2.resize(rgb, (224, 224), interpolation=cv2.INTER_LINEAR)
    x = rgb.astype(np.float32) / 255.0
    x = (x - 0.5) / 0.5
    t = x.transpose(2, 0, 1)[np.newaxis]
    logits = sess.run(None, {inp_name: t})[0][0]
    e = np.exp(logits - logits.max())
    return float((e / e.sum())[1])  # P(spoof); label 1 = spoof


MARGINS = [("tight", 0.0), ("m25", 0.25), ("m96of112", 96.0 / 112.0)]


def main():
    root = Path(sys.argv[1])
    out_csv = Path(sys.argv[2])
    rows = []
    lat = []
    for cond in ("genuine-desk", "genuine-lowlight", "attack-print"):
        for fp in sorted(glob.glob(str(root / cond / "rgb" / "*.ppm"))):
            bgr = cv2.imread(fp, cv2.IMREAD_COLOR)
            f = detect(bgr)
            if f is None:
                rows.append([cond, os.path.basename(fp), "no-detect", "", "", ""])
                continue
            t0 = time.perf_counter()
            ps = [infer(crop(bgr, f, m)) for _, m in MARGINS]
            lat.append(time.perf_counter() - t0)
            rows.append([cond, os.path.basename(fp), "ok"] +
                        [f"{p:.4f}" for p in ps])
    with open(out_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["cond", "frame", "note", "p_spoof_tight", "p_spoof_m25",
                    "p_spoof_m96"])
        w.writerows(rows)
    import statistics as st
    for cond in ("genuine-desk", "genuine-lowlight", "attack-print"):
        sel = [r for r in rows if r[0] == cond and r[2] == "ok"]
        nd = sum(1 for r in rows if r[0] == cond and r[2] == "no-detect")
        print(f"{cond}: {len(sel)} scored, {nd} no-detect")
        for i, (name, _) in enumerate(MARGINS, start=3):
            vs = [float(r[i]) for r in sel]
            if vs:
                print(f"  {name}: min {min(vs):.3f} med {st.median(vs):.3f} "
                      f"max {max(vs):.3f}")
    if lat:
        print(f"infer latency (3 variants/frame): {np.median(lat)*1000:.1f} ms"
              f" -> {np.median(lat)*1000/3:.1f} ms/infer")


if __name__ == "__main__":
    main()
