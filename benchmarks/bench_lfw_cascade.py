#!/usr/bin/env python3
"""LFW verification with the FULL shipped detection CASCADE in place of
YuNet-only: YuNet primary, BlazeFace short-range rescue on a YuNet miss,
FaceMesh refining the rescued box to 5 ArcFace points. Counts how many
times the rescue actually fires (expected 0 on clean LFW portraits, which
proves the cascade leaves the LFW recognizer number unchanged).

Reuses bench_faceid.run_lfw by handing it a cascade detector with the same
`largest_face_landmarks(bgr)` interface.

Usage: ~/mp-venv/bin/python bench_lfw_cascade.py
"""
import json
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

from bench_faceid import Embedder, estimate_norm, run_lfw

HOME = Path.home()
MODELS = HOME / "bench" / "models"
MP = HOME / "bench" / "models_mp"
LFW = HOME / "datasets" / "lfw"

RIGHT_EYE = [33, 133, 160, 159, 158, 144, 145, 153]
LEFT_EYE = [362, 263, 387, 386, 385, 373, 374, 380]


def blaze_anchors():
    a = []
    for cells, per in ((16, 2), (8, 6)):
        for r in range(cells):
            for c in range(cells):
                for _ in range(per):
                    a.append(((c + 0.5) / cells, (r + 0.5) / cells))
    return np.array(a, np.float32)


class CascadeDetector:
    """YuNet -> BlazeFace rescue -> FaceMesh 5pt, matching the Rust cascade."""

    def __init__(self):
        self.yunet = cv2.FaceDetectorYN.create(
            str(MODELS / "face_detection_yunet_2023mar.onnx"), "", (320, 320),
            score_threshold=0.6)
        self.blaze = ort.InferenceSession(
            str(MP / "blaze_face_short_range.onnx"),
            providers=["CPUExecutionProvider"])
        self.mesh = ort.InferenceSession(
            str(MP / "face_landmarks_new.onnx"),
            providers=["CPUExecutionProvider"])
        self.mesh_in = self.mesh.get_inputs()[0].name
        self.anchors = blaze_anchors()
        self.rescues = 0
        self.yunet_hits = 0
        self.total = 0

    def _blaze(self, bgr, thr=0.5):
        h, w = bgr.shape[:2]
        side = max(h, w)
        pad = np.zeros((side, side, 3), np.uint8)
        pad[:h, :w] = bgr
        rgb = cv2.cvtColor(cv2.resize(pad, (128, 128)), cv2.COLOR_BGR2RGB)
        x = (rgb.astype(np.float32) - 127.5) / 127.5
        reg, cls = self.blaze.run(None, {"input": x[None]})
        sc = 1.0 / (1.0 + np.exp(-np.clip(cls[0, :, 0], -100, 100)))
        i = int(np.argmax(sc))
        if sc[i] < thr:
            return None
        r = reg[0, i]
        ax, ay = self.anchors[i]
        cx, cy = ax + r[0] / 128.0, ay + r[1] / 128.0
        bw, bh = r[2] / 128.0, r[3] / 128.0
        return np.array([(cx - bw / 2) * side, (cy - bh / 2) * side,
                         (cx + bw / 2) * side, (cy + bh / 2) * side])

    def _mesh_5pt(self, bgr, box_xyxy):
        x0, y0, x1, y1 = box_xyxy
        cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
        half = 0.5 * max(x1 - x0, y1 - y0) * 1.5
        gx0, gy0, s = cx - half, cy - half, 2 * half
        H, W = bgr.shape[:2]
        side = 256
        xs = np.clip((np.arange(side) + 0.5) / side * s + gx0, 0, W - 1).astype(np.float32)
        ys = np.clip((np.arange(side) + 0.5) / side * s + gy0, 0, H - 1).astype(np.float32)
        mx, my = np.meshgrid(xs, ys)
        crop = cv2.remap(bgr, mx, my, cv2.INTER_LINEAR)
        rgb = cv2.cvtColor(crop, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
        out = self.mesh.run(None, {self.mesh_in: rgb[None]})
        pts = None
        for o in out:
            if o.size in (468 * 3, 478 * 3):
                pts = o.reshape(-1, 3)[:, :2] / side
        if pts is None:
            return None
        pts = np.stack([pts[:, 0] * s + gx0, pts[:, 1] * s + gy0], 1)
        re = pts[RIGHT_EYE].mean(0)
        le = pts[LEFT_EYE].mean(0)
        e1, e2 = sorted([tuple(re), tuple(le)])  # image-left first
        m1, m2 = sorted([tuple(pts[61]), tuple(pts[291])])
        return np.array([e1, e2, tuple(pts[1]), m1, m2], np.float32)

    def largest_face_landmarks(self, bgr):
        self.total += 1
        h, w = bgr.shape[:2]
        self.yunet.setInputSize((w, h))
        ok, faces = self.yunet.detect(bgr)
        if faces is not None and len(faces) > 0:
            self.yunet_hits += 1
            f = max(faces, key=lambda r: r[2] * r[3])
            return f[4:14].reshape(5, 2)
        # rescue
        box = self._blaze(bgr)
        if box is None:
            return None
        lm = self._mesh_5pt(bgr, box)
        if lm is not None:
            self.rescues += 1
        return lm


def main():
    prov = (["CUDAExecutionProvider", "CPUExecutionProvider"]
            if "CUDAExecutionProvider" in ort.get_available_providers()
            else ["CPUExecutionProvider"])
    det = CascadeDetector()
    models = {"auraface": Embedder(MODELS / "glintr100.onnx", 128.0, prov)}
    res = run_lfw(LFW, det, models, flip_tta=True)
    print(f"[cascade] YuNet hits {det.yunet_hits}/{det.total}, "
          f"BlazeFace rescues fired: {det.rescues}", flush=True)
    out = {"lfw_cascade": res, "yunet_hits": det.yunet_hits,
           "blaze_rescues": det.rescues, "total_images": det.total}
    Path("lfw_cascade_results.json").write_text(json.dumps(out, indent=2))
    print("wrote lfw_cascade_results.json", flush=True)


if __name__ == "__main__":
    main()
