#!/usr/bin/env python3
"""FLXC (cv_manual_face-liveness_flxc) live-corpora scorer, 2026-08-21.

Scores the 2026-08-12 flrgb live session captures (genuine-desk,
genuine-lowlight, attack-print; 250 frames) through the FLXC color-flash
liveness model in its DEGENERATE single-image mode (the vendor pipeline
replicates one frame 4x to fill the 12-channel input; the model card states
this mode is "not robust" and recommends sequence+voting, and the as-designed
protocol needs 4 screen-color-flash frames, which irlume's PAM daemon cannot
capture — see the research note this belongs to).

Pinned inputs:
  flxc model.onnx  sha256 2efcdfeec34a474eaf94b425410635ae9b6b0ba7183dfdcdbd4c573daabbac2e
  YuNet detector   sha256 8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4

Preprocessing, replicated from modelscope 1.39.1 source (primary):
  - SHIPPED route (face_liveness_xc_pipeline.preprocess ->
    FaceProcessingBasePipeline.preprocess): DamoFD detect + 5 landmarks ->
    align_face() skimage SimilarityTransform to the InsightFace 96/112 base
    landmarks (+8 slide for 112x112) -> (px-127.5)*0.0078125 on the BGR chip
    -> np.concatenate([img]*4, axis=3) -> CHW. Deviation as in every prior
    candidate eval: irlume's shipped YuNet for detection/landmarks (DamoFD not
    fetched), least-squares similarity to the same reference points.
  - CARD route (README test recipe): bbox expanded 96/112 per side, clamped,
    squared by symmetric extension then 127 fill, resize 128x128, center-crop
    112 -> same normalize/replicate.

Score: the ONNX graph ends in Softmax; out[0] = P(fake) (README: higher =
spoof), taken directly with no extra softmax.

Usage: python3 flxc_live_score.py <corpus-root> <out.csv>
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

MODEL = os.environ.get("FLXC_MODEL", "model.onnx")
YUNET = os.environ.get(
    "IRLUME_YUNET",
    str(Path.home() / "irlume/models/face_detection_yunet_2023mar.onnx"),
)

# bench_faceid ARCFACE_REF == modelscope align_face base_lmk with the +8
# x-slide for 112x112 (30.2946+8=38.2946 ... 62.7299+8=70.7299).
ARCFACE_REF = np.array([
    [38.2946, 51.6963], [73.5318, 51.5014], [56.0252, 71.7366],
    [41.5493, 92.3655], [70.7299, 92.2041]], dtype=np.float32)

sess = ort.InferenceSession(MODEL, providers=["CPUExecutionProvider"])
inp_name = sess.get_inputs()[0].name
det = cv2.FaceDetectorYN.create(YUNET, "", (320, 320), 0.5, 0.3, 5000)


def detect(bgr):
    h, w = bgr.shape[:2]
    det.setInputSize((w, h))
    n, faces = det.detect(bgr)
    if faces is None or len(faces) == 0:
        return None
    f = max(faces, key=lambda f: f[2] * f[3])
    return f  # x, y, w, h, score, 5x2 landmarks in f[4:14]


def estimate_norm(lmk):
    """Least-squares similarity lmk(5x2) -> ARCFACE_REF (skimage-equivalent)."""
    src, dst = lmk.astype(np.float64), ARCFACE_REF.astype(np.float64)
    mu_s, mu_d = src.mean(0), dst.mean(0)
    sc, dc = src - mu_s, dst - mu_d
    cov = dc.T @ sc / 5
    U, S, Vt = np.linalg.svd(cov)
    d = np.sign(np.linalg.det(U) * np.linalg.det(Vt))
    R = U @ np.diag([1.0, d]) @ Vt
    var_s = (sc ** 2).sum() / 5
    scale = np.trace(np.diag(S) @ np.diag([1.0, d])) / var_s
    t = mu_d - scale * (R @ mu_s)
    return np.hstack([scale * R, t[:, None]]).astype(np.float32)


def chip_warp(bgr, f):
    """SHIPPED route: 5-lmk similarity warp to 112x112 (BGR, as the pipeline feeds)."""
    M = estimate_norm(f[4:14].reshape(5, 2))
    return cv2.warpAffine(bgr, M, (112, 112), flags=cv2.INTER_LINEAR)


def chip_pad(bgr, f, padding_size=96, pad_pixel=127):
    """CARD route: bbox + padding_size/112 expansion, 127-fill square, 128, crop."""
    x1 = int(f[0] - (f[2] + 1) * padding_size / 112)
    x2 = int(f[0] + f[2] + (f[2] + 1) * padding_size / 112)
    y1 = int(f[1] - (f[3] + 1) * padding_size / 112)
    y2 = int(f[1] + f[3] + (f[3] + 1) * padding_size / 112)
    b = [max(0, x1), max(0, y1),
         min(bgr.shape[1] - 1, x2), min(bgr.shape[0] - 1, y2)]
    ph, pw = b[3] - b[1] + 1, b[2] - b[0] + 1
    if pw > ph:
        off = (pw - ph) // 2
        b[1], b[3] = max(0, b[1] - off), min(bgr.shape[0] - 1, b[1] - off + pw - 1)
        size = pw
    else:
        off = (ph - pw) // 2
        b[0], b[2] = max(0, b[0] - off), min(bgr.shape[1] - 1, b[0] - off + ph - 1)
        size = ph
    dst = np.full((size, size, 3), pad_pixel, dtype=np.uint8)
    yo, xo = (size - (b[3] - b[1] + 1)) // 2, (size - (b[2] - b[0] + 1)) // 2
    dst[yo:yo + b[3] + 1 - b[1], xo:xo + b[2] + 1 - b[0]] = \
        bgr[b[1]:b[3] + 1, b[0]:b[2] + 1]
    img = cv2.resize(dst, (128, 128), interpolation=cv2.INTER_LINEAR)
    return img[8:120, 8:120]


def infer(chip):
    x = (chip.astype(np.float32) - 127.5) * 0.0078125
    x4 = np.concatenate([x, x, x, x], axis=2)  # HWC(12) — vendor replicate
    t = x4.transpose(2, 0, 1)[np.newaxis].astype(np.float32)
    out = sess.run(None, {inp_name: t})[0][0]
    return float(out[0])  # softmax pair already; [0] = P(fake)


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
                rows.append([cond, os.path.basename(fp), "no-detect", "", ""])
                continue
            t0 = time.perf_counter()
            pw, pp = infer(chip_warp(bgr, f)), infer(chip_pad(bgr, f))
            lat.append(time.perf_counter() - t0)
            rows.append([cond, os.path.basename(fp), "ok", f"{pw:.4f}", f"{pp:.4f}"])
    with open(out_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["cond", "frame", "note", "p_fake_warp", "p_fake_pad96"])
        w.writerows(rows)
    import statistics as st
    for cond in ("genuine-desk", "genuine-lowlight", "attack-print"):
        sel = [r for r in rows if r[0] == cond and r[2] == "ok"]
        nd = sum(1 for r in rows if r[0] == cond and r[2] == "no-detect")
        print(f"{cond}: {len(sel)} scored, {nd} no-detect")
        for i, name in ((3, "warp"), (4, "pad96")):
            vs = [float(r[i]) for r in sel]
            if vs:
                print(f"  {name}: p_fake min {min(vs):.3f} "
                      f"median {st.median(vs):.3f} max {max(vs):.3f}")
    if lat:
        print(f"infer latency (2 variants/frame): {np.median(lat)*1000:.2f} ms")


if __name__ == "__main__":
    main()
