#!/usr/bin/env python3
"""FLIR (cv_manual_face-liveness_flir) public-NIR extension scorer, 2026-08-21.

Extends the 2026-07-17 qualification (single-subject field corpus) with:
  - GENUINE at scale: CBSR active-NIR 850nm (197 ids, 3940 faces) and Tufts
    td NIR-a (110 ids, 3211 frames) — public NIR face corpora, all treated
    as genuine presentations (live faces, no spoof species present).
  - ATTACK, local bursts: irlume-suncal spoof-01..07 (paper x4, screen,
    phone, videoreplay on the NexiGo IR node, 36-frame strobe bursts; frames
    with mean luma < 10 skipped as dark strobe phase, same convention as
    flir_eval.py).

Preprocessing identical to the qualified flir_eval.py: gray->BGR replicate,
YuNet largest-face bbox, align_face_padding pad16, (x-127.5)/128, softmax
once over raw logits, P(fake)=sm[0].

Pinned inputs:
  flir model.onnx  sha256 df80cea7228b92562692e56aac965d35766c77399159798c552fb3c77b410c72
  YuNet detector   sha256 8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4

Usage: flir_public_nir_score.py <cbsr-img-dir> <tufts-nir-dir> <suncal-root> <out.json>
  cbsr-img-dir: the directory holding the 3940 *.bmp faces
  tufts-nir-dir: td-nir-a/td-nir-a (holds Set*/subject dirs of pngs)
"""
import json
import sys
import time
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

MODEL = "model.onnx"
YUNET = str(Path.home() / "irlume/models/face_detection_yunet_2023mar.onnx")

sess = ort.InferenceSession(MODEL, providers=["CPUExecutionProvider"])
inp_name = sess.get_inputs()[0].name
det = cv2.FaceDetectorYN.create(YUNET, "", (320, 320), 0.5, 0.3, 5000)


def detect(gray3):
    h, w = gray3.shape[:2]
    det.setInputSize((w, h))
    n, faces = det.detect(gray3)
    if faces is None or len(faces) == 0:
        return None
    f = max(faces, key=lambda f: f[2] * f[3])
    return [f[0], f[1], f[0] + f[2], f[1] + f[3]]


def align_face_padding(img, bbox, padding_size=16, pad_pixel=127):
    b = [int(v) for v in bbox]
    x1 = b[0] - int((b[2] - b[0] + 1) * padding_size / 112)
    x2 = b[2] + int((b[2] - b[0] + 1) * padding_size / 112)
    y1 = b[1] - int((b[3] - b[1] + 1) * padding_size / 112)
    y2 = b[3] + int((b[3] - b[1] + 1) * padding_size / 112)
    b = [max(0, x1), max(0, y1), min(img.shape[1] - 1, x2), min(img.shape[0] - 1, y2)]
    ph, pw = b[3] - b[1] + 1, b[2] - b[0] + 1
    if pw > ph:
        off = (pw - ph) // 2
        b[1] = max(0, b[1] - off)
        b[3] = min(img.shape[0] - 1, b[1] + pw - 1)
        dst_size = pw
    else:
        off = (ph - pw) // 2
        b[0] = max(0, b[0] - off)
        b[2] = min(img.shape[1] - 1, b[0] + ph - 1)
        dst_size = ph
    dst = np.full((dst_size, dst_size, 3), pad_pixel, dtype=np.uint8)
    yo = (dst_size - (b[3] - b[1] + 1)) // 2
    xo = (dst_size - (b[2] - b[0] + 1)) // 2
    dst[yo:yo + b[3] + 1 - b[1], xo:xo + b[2] + 1 - b[0]] = img[b[1]:b[3] + 1, b[0]:b[2] + 1]
    return cv2.resize(dst, (128, 128), interpolation=cv2.INTER_LINEAR)


def infer(crop128):
    img = crop128[8:120, 8:120, :].astype(np.float32)
    img = (img - 127.5) * 0.0078125
    t = img.transpose(2, 0, 1)[np.newaxis]
    logits = sess.run(None, {inp_name: t})[0]
    e = np.exp(logits[0] - logits[0].max())
    return float((e / e.sum())[0])


def stats(pfs):
    a = np.asarray(pfs)
    return {
        "n": len(a),
        "p_fake_min": round(float(a.min()), 4) if len(a) else None,
        "p_fake_median": round(float(np.median(a)), 4) if len(a) else None,
        "p_fake_p90": round(float(np.percentile(a, 90)), 4) if len(a) else None,
        "p_fake_p99": round(float(np.percentile(a, 99)), 4) if len(a) else None,
        "p_fake_max": round(float(a.max()), 4) if len(a) else None,
        "rejected_at_0.5": int((a >= 0.5).sum()),
        "rejected_at_0.9": int((a >= 0.9).sum()),
    }


def main():
    cbsr_dir, tufts_dir, suncal_root, out_json = (Path(a) for a in sys.argv[1:5])
    out = {"genuine": {}, "attack": {}}

    # CBSR genuine
    pfs, nodet = [], 0
    for fp in sorted(cbsr_dir.glob("*.bmp")):
        gray = cv2.imread(str(fp), cv2.IMREAD_GRAYSCALE)
        if gray is None:
            continue
        gray3 = cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR)
        bbox = detect(gray3)
        if bbox is None:
            nodet += 1
            continue
        pfs.append(infer(align_face_padding(gray3, bbox)))
    out["genuine"]["cbsr_nir"] = stats(pfs) | {"no_detect": nodet}
    print("cbsr_nir:", out["genuine"]["cbsr_nir"], flush=True)

    # Tufts NIR genuine
    pfs, nodet = [], 0
    for fp in sorted(tufts_dir.rglob("*.png")):
        gray = cv2.imread(str(fp), cv2.IMREAD_GRAYSCALE)
        if gray is None:
            continue
        gray3 = cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR)
        bbox = detect(gray3)
        if bbox is None:
            nodet += 1
            continue
        pfs.append(infer(align_face_padding(gray3, bbox)))
    out["genuine"]["tufts_nir"] = stats(pfs) | {"no_detect": nodet}
    print("tufts_nir:", out["genuine"]["tufts_nir"], flush=True)

    # Local IR attack bursts
    for d in sorted(p for p in suncal_root.iterdir()
                    if p.is_dir() and p.name.startswith("spoof-")):
        pfs, nodet, dark = [], 0, 0
        for fp in sorted(d.glob("*.pgm")):
            gray = cv2.imread(str(fp), cv2.IMREAD_GRAYSCALE)
            if gray is None:
                continue
            if float(gray.mean()) < 10:
                dark += 1
                continue
            gray3 = cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR)
            bbox = detect(gray3)
            if bbox is None:
                nodet += 1
                continue
            pfs.append(infer(align_face_padding(gray3, bbox)))
        out["attack"][d.name] = stats(pfs) | {"no_detect": nodet, "dark_phase": dark}
        print(d.name, out["attack"][d.name], flush=True)

    Path(out_json).write_text(json.dumps(out, indent=1))
    print("wrote", out_json)


if __name__ == "__main__":
    main()
