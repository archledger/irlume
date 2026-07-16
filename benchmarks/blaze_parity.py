#!/usr/bin/env python3
"""Parity check: hand-rolled BlazeFace short-range decode on the converted
ONNX vs the official MediaPipe FaceDetector, plus new-mesh ONNX vs the
official FaceLandmarker. The decode implemented here is the specification
for the Rust port; every constant matters.

BlazeFace short-range contract:
  input  128x128x3 RGB, (x - 127.5) / 127.5  -> [-1, 1], NHWC
  output regressors [1,896,16]: cx,cy,w,h + 6 keypoints (x,y), all /128
         relative to anchor center; classificators [1,896,1] -> sigmoid
  anchors: stride 8 -> 16x16 cells x 2 = 512, stride 16 -> 8x8 x 6 = 384
           centers ((c+0.5)/cells, (r+0.5)/cells), sizes 1.0
  letterbox: square-pad the frame to preserve aspect before resize.

Usage: ~/mp-venv/bin/python blaze_parity.py
"""
import json
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort
import mediapipe as mp
from mediapipe.tasks import python as mp_python
from mediapipe.tasks.python import vision

HOME = Path.home()
MP_DIR = HOME / "bench" / "models_mp"
CBSR = HOME / "datasets" / "cbsr_nir" / "NIR_face_dataset" / "NIR_face_dataset"
SUNCAL = HOME / "datasets" / "irlume-suncal"
TUFTS = HOME / "datasets" / "tufts_faces" / "td-rgb-a" / "td-rgb-a"


def gen_anchors():
    anchors = []
    for cells, per_cell in ((16, 2), (8, 6)):
        for r in range(cells):
            for c in range(cells):
                for _ in range(per_cell):
                    anchors.append(((c + 0.5) / cells, (r + 0.5) / cells))
    return np.array(anchors, np.float32)  # (896, 2)


ANCHORS = gen_anchors()


class BlazeOnnx:
    def __init__(self, path):
        self.sess = ort.InferenceSession(str(path),
                                         providers=["CPUExecutionProvider"])

    def detect(self, bgr, thr=0.5):
        """Top-1 face: returns (score, bbox xyxy px, 6 keypoints px) or None."""
        h, w = bgr.shape[:2]
        side = max(h, w)
        pad = np.zeros((side, side, 3), np.uint8)
        pad[:h, :w] = bgr
        rgb = cv2.cvtColor(cv2.resize(pad, (128, 128)), cv2.COLOR_BGR2RGB)
        x = (rgb.astype(np.float32) - 127.5) / 127.5
        reg, cls = self.sess.run(None, {"input": x[None]})
        scores = 1.0 / (1.0 + np.exp(-np.clip(cls[0, :, 0], -100, 100)))
        i = int(np.argmax(scores))
        if scores[i] < thr:
            return None
        r = reg[0, i]
        ax, ay = ANCHORS[i]
        cx, cy = ax + r[0] / 128.0, ay + r[1] / 128.0
        bw, bh = r[2] / 128.0, r[3] / 128.0
        box = np.array([cx - bw / 2, cy - bh / 2, cx + bw / 2, cy + bh / 2])
        kps = [(ax + r[4 + 2 * k] / 128.0, ay + r[5 + 2 * k] / 128.0)
               for k in range(6)]
        # un-letterbox: normalized coords are relative to the padded square
        box_px = box * side
        kps_px = [(kx * side, ky * side) for kx, ky in kps]
        return float(scores[i]), box_px, kps_px


def mp_detect(det, bgr):
    rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
    res = det.detect(mp.Image(image_format=mp.ImageFormat.SRGB, data=rgb))
    if not res.detections:
        return None
    h, w = bgr.shape[:2]
    best = max(res.detections,
               key=lambda d: d.bounding_box.width * d.bounding_box.height)
    bb = best.bounding_box
    box = np.array([bb.origin_x, bb.origin_y,
                    bb.origin_x + bb.width, bb.origin_y + bb.height],
                   np.float32)
    kps = [(k.x * w, k.y * h) for k in best.keypoints]
    return box, kps


def iou(a, b):
    x0, y0 = max(a[0], b[0]), max(a[1], b[1])
    x1, y1 = min(a[2], b[2]), min(a[3], b[3])
    inter = max(0, x1 - x0) * max(0, y1 - y0)
    ua = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / (ua + 1e-9)


def main():
    ours = BlazeOnnx(MP_DIR / "blaze_face_short_range.onnx")
    ref = vision.FaceDetector.create_from_options(vision.FaceDetectorOptions(
        base_options=mp_python.BaseOptions(
            model_asset_path=str(MP_DIR / "blaze_face_short_range.tflite")),
        min_detection_confidence=0.5))

    samples = (sorted(CBSR.glob("*.bmp"))[::400]
               + sorted((SUNCAL / "30-desk-daylight").glob("*.pgm"))[:4]
               + sorted(TUFTS.rglob("*.png"))[::800])
    ious, eyeds, agree, n = [], [], 0, 0
    for p in samples:
        img = cv2.imread(str(p))
        if img is None:
            continue
        n += 1
        a, b = ours.detect(img), mp_detect(ref, img)
        if (a is None) != (b is None):
            continue
        agree += 1
        if a is None:
            continue
        _, abox, akps = a
        bbox, bkps = b
        ious.append(iou(abox, bbox))
        eyeds.append(np.mean([np.hypot(akps[k][0] - bkps[k][0],
                                       akps[k][1] - bkps[k][1])
                              for k in range(2)]))
    print(f"[blaze parity] {agree}/{n} presence-agree, "
          f"IoU mean {np.mean(ious):.4f} min {np.min(ious):.4f}, "
          f"eye delta px mean {np.mean(eyeds):.2f} max {np.max(eyeds):.2f}")

    # New mesh ONNX vs official FaceLandmarker on face crops.
    mesh = ort.InferenceSession(str(MP_DIR / "face_landmarks_new.onnx"),
                                providers=["CPUExecutionProvider"])
    lmk = vision.FaceLandmarker.create_from_options(
        vision.FaceLandmarkerOptions(base_options=mp_python.BaseOptions(
            model_asset_path=str(MP_DIR / "face_landmarker.task")),
            num_faces=1))
    deltas = []
    for p in sorted(CBSR.glob("*.bmp"))[::800]:
        img = cv2.imread(str(p))
        if img is None:
            continue
        r = mp_detect(ref, img)
        if r is None:
            continue
        box, _ = r
        x0, y0, x1, y1 = [int(v) for v in box]
        cx, cy, s = (x0 + x1) / 2, (y0 + y1) / 2, (x1 - x0) * 1.5
        x0, y0 = int(max(0, cx - s / 2)), int(max(0, cy - s / 2))
        x1 = int(min(img.shape[1], x0 + s))
        y1 = int(min(img.shape[0], y0 + s))
        crop = img[y0:y1, x0:x1]
        rgb = cv2.cvtColor(cv2.resize(crop, (256, 256)), cv2.COLOR_BGR2RGB)
        out = mesh.run(None, {"input_12": rgb.astype(np.float32)[None] / 255.0})
        pts = out[0].reshape(-1, 3)[:478, :2] / 256.0
        pts = np.stack([pts[:, 0] * (x1 - x0) + x0,
                        pts[:, 1] * (y1 - y0) + y0], 1)
        res = lmk.detect(mp.Image(image_format=mp.ImageFormat.SRGB,
                                  data=cv2.cvtColor(img, cv2.COLOR_BGR2RGB)))
        if not res.face_landmarks:
            continue
        h, w = img.shape[:2]
        ref_pts = np.array([[q.x * w, q.y * h] for q in res.face_landmarks[0]])
        deltas.append(float(np.linalg.norm(pts - ref_pts, axis=1).mean()))
    print(f"[mesh parity] mean landmark delta px {np.mean(deltas):.2f} "
          f"(n={len(deltas)}; crop policies differ, expect a few px)")


if __name__ == "__main__":
    main()
