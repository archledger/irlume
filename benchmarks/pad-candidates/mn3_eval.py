#!/usr/bin/env python3
"""Genuine-side eval of Intel OMZ anti-spoof-mn3 (Apache-2.0, CelebA-Spoof-trained).

Preprocessing per Intel's OMZ README + the author's demo:
raw detection bbox crop -> resize 128x128 -> RGB -> (x - mean)/scale with
mean [151.2405, 119.5950, 107.8395], scale [63.0105, 56.4570, 55.0035] -> CHW.
Output: probabilities, class 0 = real, class 1 = spoof. Author demo threshold 0.4.

Genuine data only: irlume-suncal RGB bursts (real camera) + local LFW (web photos).
Measures false-spoof rate on genuine faces. Attack side needs live capture.
"""
import json, sys, time
from pathlib import Path
import numpy as np
import cv2
import onnxruntime as ort

MODEL = Path(sys.argv[1])
OUT = Path(sys.argv[2])
YUNET = Path.home() / "irlume/models/face_detection_yunet_2023mar.onnx"
MEAN = np.array([151.2405, 119.5950, 107.8395], dtype=np.float32)
SCALE = np.array([63.0105, 56.4570, 55.0035], dtype=np.float32)

sess = ort.InferenceSession(str(MODEL), providers=["CPUExecutionProvider"])
inp = sess.get_inputs()[0].name


def detect(bgr):
    h, w = bgr.shape[:2]
    det = cv2.FaceDetectorYN.create(str(YUNET), "", (w, h), 0.5, 0.3, 5000)
    n, faces = det.detect(bgr)
    if faces is None or len(faces) == 0:
        return None
    f = max(faces, key=lambda f: f[2] * f[3])
    x, y, bw, bh = [int(v) for v in f[:4]]
    x, y = max(0, x), max(0, y)
    return bgr[y:y + bh, x:x + bw]


def p_spoof(face_bgr):
    img = cv2.resize(face_bgr, (128, 128)).astype(np.float32)
    rgb = img[:, :, ::-1]
    norm = (rgb - MEAN) / SCALE
    t = norm.transpose(2, 0, 1)[np.newaxis]
    out = sess.run(None, {inp: t})[0][0]
    e = np.exp(out - out.max())
    sm = e / e.sum()
    return float(sm[1])


def run_set(name, paths, limit=None):
    scores, nodet = [], 0
    for p in paths[:limit] if limit else paths:
        img = cv2.imread(str(p))
        if img is None:
            continue
        face = detect(img)
        if face is None or face.size == 0:
            nodet += 1
            continue
        scores.append(p_spoof(face))
    a = np.array(scores)
    return {
        "n_scored": len(scores), "no_detection": nodet,
        "p_spoof_median": round(float(np.median(a)), 4) if len(a) else None,
        "p_spoof_p90": round(float(np.percentile(a, 90)), 4) if len(a) else None,
        "rej@0.4": int((a >= 0.4).sum()), "rej@0.5": int((a >= 0.5).sum()),
        "rej_rate@0.4": round(float((a >= 0.4).mean()), 4) if len(a) else None,
    }


results = {}
suncal = Path.home() / "irlume-suncal"
for d in ["09b-rgb-live-sun", "16b-home-rgb-backlit"]:
    results[f"camera:{d}"] = run_set(d, sorted((suncal / d).glob("*.ppm")))

lfw = sorted((Path.home() / "datasets/lfw").rglob("*.jpg"))
t0 = time.time()
results["lfw_genuine"] = run_set("lfw", lfw)
results["lfw_genuine"]["wall_s"] = round(time.time() - t0, 1)

OUT.write_text(json.dumps(results, indent=1))
print(json.dumps(results, indent=1))
