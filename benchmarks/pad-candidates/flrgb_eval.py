#!/usr/bin/env python3
"""Offline first-contact eval of DAMO cv_manual_face-liveness_flrgb (MIT)
against irlume's stored corpora. See RESEARCH.md in this directory.

Preprocessing replicates ModelScope's align_face_padding
(face_processing_base_pipeline.py, fetched 2026-08-07 into this dir):
expand bbox by padding_size/112 of the box dimension per side (clamped at
edges), square by symmetric extension then 127-fill, resize 128x128,
center-crop 112x112, (x-127.5)*0.0078125, CHW float32, RGB channel order
(the pipeline flips to BGR then align_face_padding flips back to RGB).
Score = P(fake) = raw output[0]; the model already emits a softmax pair,
see the double-softmax note in infer().

Two padding variants are scored per frame because the flrgb model card
documents 96/112 per side while the model's configuration.json routes it
through the flir pipeline whose code uses 16/112.

Detection uses irlume's shipped YuNet, same deviation as the 2026-07-17
flir measurement (ModelScope's own detector is DamoFD, not fetched).
"""
import csv
import os
import sys
from pathlib import Path

import numpy as np
import cv2
import onnxruntime as ort

EVAL_DIR = Path(__file__).resolve().parent
# The weights are not committed (the flrgb model is a third-party artifact and
# YuNet is a shipped model file), so both are resolved by environment override
# first and a conventional location second. The hashes that identify them are
# pinned in flrgb_live_score.py's header; a replay that reproduces the
# committed CSV proves the same pipeline ran.
MODEL = Path(os.environ.get("FLRGB_MODEL", EVAL_DIR / "model.onnx"))
if not MODEL.exists():
    MODEL = Path.home() / "irlume-research/2026-08-07-flrgb-eval/model.onnx"
YUNET = Path(
    os.environ.get("IRLUME_YUNET", Path.home() / "irlume/models/face_detection_yunet_2023mar.onnx")
)
RESEARCH = Path.home() / "irlume-research"

sess = ort.InferenceSession(str(MODEL), providers=["CPUExecutionProvider"])
inp_name = sess.get_inputs()[0].name
print("model input:", sess.get_inputs()[0].shape,
      "output:", [(o.name, o.shape) for o in sess.get_outputs()])


def detect(bgr):
    h, w = bgr.shape[:2]
    det = cv2.FaceDetectorYN.create(str(YUNET), "", (w, h), 0.5, 0.3, 5000)
    n, faces = det.detect(bgr)
    if faces is None or len(faces) == 0:
        return None
    f = max(faces, key=lambda f: f[2] * f[3])
    x, y, bw, bh = f[:4]
    return [x, y, x + bw, y + bh]


def align_face_padding(img, bbox, padding_size, pad_pixel=127):
    """Line-for-line port of FaceProcessingBasePipeline.align_face_padding
    for a single bbox. img is RGB uint8 HxWx3."""
    b = [int(v) for v in bbox]
    x1 = b[0] - int((b[2] - b[0] + 1) * padding_size * 1.0 / 112)
    x2 = b[2] + int((b[2] - b[0] + 1) * padding_size * 1.0 / 112)
    y1 = b[1] - int((b[3] - b[1] + 1) * padding_size * 1.0 / 112)
    y2 = b[3] + int((b[3] - b[1] + 1) * padding_size * 1.0 / 112)
    b = [max(0, x1), max(0, y1),
         min(img.shape[1] - 1, x2), min(img.shape[0] - 1, y2)]
    ph = b[3] - b[1] + 1
    pw = b[2] - b[0] + 1
    if pw > ph:
        off = int((pw - ph) / 2)
        b[1] = b[1] - off
        b[3] = b[1] + pw - 1
        b[1] = max(0, b[1])
        b[3] = min(img.shape[0] - 1, b[3])
        dst_size = pw
    else:
        off = int((ph - pw) / 2)
        b[0] = b[0] - off
        b[2] = b[0] + ph - 1
        b[0] = max(0, b[0])
        b[2] = min(img.shape[1] - 1, b[2])
        dst_size = ph
    dst = np.full((dst_size, dst_size, 3), pad_pixel, dtype=np.uint8)
    yo = int((dst_size - (b[3] - b[1] + 1)) / 2)
    xo = int((dst_size - (b[2] - b[0] + 1)) / 2)
    dst[yo:yo + b[3] + 1 - b[1], xo:xo + b[2] + 1 - b[0], :] = \
        img[b[1]:b[3] + 1, b[0]:b[2] + 1, :]
    return cv2.resize(dst, (128, 128), interpolation=cv2.INTER_LINEAR)


def infer(rgb, bbox, padding_size):
    img = align_face_padding(rgb, bbox, padding_size)
    if img.shape[0] != 112:
        img = img[8:120, 8:120, :]
    img = (img.astype(np.float32) - 127.5) * 0.0078125
    t = img.transpose(2, 0, 1)[np.newaxis]
    out = sess.run(None, {inp_name: t})[0][0]
    # The model's `final_actions` output is ALREADY a softmax pair summing
    # to 1.0 (verified over all corpora: row sums exactly 1.0, values
    # saturating at 0.0001/0.9999). The ModelScope FaceLivenessIrPipeline
    # applies F.softmax again, which squashes every score into
    # [0.2689, 0.7311]: the double-softmax fingerprint documented in
    # benchmarks/pad-candidates/README.md for mn3. Correct spoof score is
    # out[0] = P(fake) directly; flir differs (it emits raw logits).
    return float(out[0]), out.tolist()


def frames():
    """Yield (corpus, kind, condition, path, rgb_or_none, note)."""
    # ATTACK: vinyl print bursts, IR pgm, lit strobe phase only.
    pc = RESEARCH / "2026-08-04-print-corpus"
    for d, kind in [("burst-print-curved", "attack"),
                    ("burst-genuine", "genuine-ir-control")]:
        for fp in sorted((pc / d).glob("*.pgm")):
            g = cv2.imread(str(fp), cv2.IMREAD_GRAYSCALE)
            if g is None:
                continue
            if float(g.mean()) < 10:  # dark strobe phase, undetectable
                yield ("print-corpus", kind, d, fp, None, "dark-strobe-phase")
                continue
            rgb = cv2.cvtColor(g, cv2.COLOR_GRAY2RGB)
            yield ("print-corpus", kind, d, fp, rgb, "ir-gray-replicated")
    # GENUINE RGB: stage3 both cameras.
    s3 = RESEARCH / "2026-08-05-stage3"
    for cam in ["nexigo", "zenbook"]:
        for cond in sorted(p.name for p in (s3 / cam).iterdir() if p.is_dir()):
            for fp in sorted((s3 / cam / cond / "rgb").glob("*.ppm")):
                bgr = cv2.imread(str(fp), cv2.IMREAD_COLOR)
                if bgr is None:
                    continue
                kind = "empty-scene" if cond.startswith("empty") else "genuine"
                yield (f"stage3-{cam}", kind, cond,
                       fp, cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB), "rgb")
    # GENUINE RGB: blink corpus zenbook.
    bc = RESEARCH / "2026-08-07-blink-corpus" / "zenbook"
    for cond in sorted(p.name for p in bc.iterdir() if p.is_dir()):
        for fp in sorted((bc / cond / "rgb").glob("*.ppm")):
            bgr = cv2.imread(str(fp), cv2.IMREAD_COLOR)
            if bgr is None:
                continue
            yield ("blink-zenbook", "genuine", cond,
                   fp, cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB), "rgb")


rows = []
for corpus, kind, cond, fp, rgb, note in frames():
    if rgb is None:
        rows.append([corpus, kind, cond, str(fp), 0, note, "", "", "", ""])
        continue
    bbox = detect(cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR))
    if bbox is None:
        rows.append([corpus, kind, cond, str(fp), 0, note, "", "", "", ""])
        continue
    p96, raw96 = infer(rgb, bbox, 96)
    p16, _ = infer(rgb, bbox, 16)
    rows.append([corpus, kind, cond, str(fp), 1, note,
                 ";".join(f"{v:.0f}" for v in bbox),
                 f"{p96:.6f}", f"{p16:.6f}",
                 ";".join(f"{v:.4f}" for v in raw96)])

out = EVAL_DIR / "flrgb-scores.csv"
with out.open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["corpus", "kind", "condition", "path", "face_detected",
                "note", "bbox", "p_fake_pad96", "p_fake_pad16",
                "raw_out_pad96"])
    w.writerows(rows)
print(f"wrote {len(rows)} rows to {out}")

# Smoke synthetic sanity (NOT an APCER claim), same as flir_eval.py.
for name, img in [("flat_gray", np.full((400, 640, 3), 127, np.uint8)),
                  ("noise", np.random.default_rng(0).integers(
                      0, 255, (400, 640, 3), dtype=np.uint8))]:
    p, _ = infer(img, [220, 100, 420, 300], 96)
    print(f"smoke {name}: p_fake_pad96={p:.4f}")
