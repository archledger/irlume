#!/usr/bin/env python3
"""Re-benchmark of the SHIPPED artifacts after the cascade + mesh swap.

What changed in irlume and what this measures:
  1. Detection cascade: YuNet primary, BlazeFace short-range ONNX rescue
     (fires only on YuNet misses). Measures yunet / blaze-onnx / cascade
     detection rates on every dataset group. The blaze decode here mirrors
     the Rust implementation exactly (same anchors, letterbox, clip).
  2. Mesh swap: the shipped face_landmark.onnx is now the 256px/478pt
     generation. Measures eye NME on CBSR (YuNet-bbox crop, the shipped
     pipeline shape) old vs new, and the EAR distribution shift on
     open-eyed burst frames (passive-blink thresholds were calibrated on
     the old mesh; a large shift would need re-validation).

Usage: ~/mp-venv/bin/python bench_cascade.py --out bench_cascade.json
"""
import argparse, json
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

HOME = Path.home()
MP_DIR = HOME / "bench" / "models_mp"
YUNET = HOME / "bench" / "models" / "face_detection_yunet_2023mar.onnx"
MESH_OLD = HOME / "ai-workspace" / "irlume" / "models" / "face_landmark.onnx"
MESH_NEW = MP_DIR / "face_landmarks_new.onnx"
BLAZE = MP_DIR / "blaze_face_short_range.onnx"
CBSR = HOME / "datasets" / "cbsr_nir"
TUFTS = HOME / "datasets" / "tufts_faces"
SUNCAL = HOME / "datasets" / "irlume-suncal"
BURST_DARK = HOME / "v5" / "captures" / "brother" / "burst-dark"

SUNCAL_GROUPS = {
    "outdoor-walking": ("27-", "28-", "29-"),
    "car-tint-sun": ("02-", "03-", "06-", "07-", "08-", "19-", "20-", "21-",
                     "22-", "23-", "24-", "25-", "26-"),
    "shade-frontal": ("01-", "04-", "12-", "13-", "14-", "15-"),
    "desk-daylight": ("30-", "31-", "32-", "33-", "34-", "35-"),
}
RIGHT_EYE = [33, 133, 160, 159, 158, 144, 145, 153]
LEFT_EYE = [362, 263, 387, 386, 385, 373, 374, 380]
EAR_LEFT = [33, 160, 158, 133, 153, 144]
EAR_RIGHT = [362, 385, 387, 263, 373, 380]


def lit_frames(d):
    mf = d / "means.txt"
    if not mf.exists():
        return []
    means = {}
    for line in mf.read_text().splitlines():
        p = line.split()
        if len(p) >= 2:
            means[p[0]] = float(p[1])
    if not means:
        return []
    mid = (max(means.values()) + min(means.values())) / 2
    return [d / f"frame{i}.pgm" for i, m in sorted(means.items()) if m >= mid]


def load_cbsr_gt():
    gt = {}
    for split in ("gallery", "probe"):
        for line in (CBSR / f"{split}-groundtruth.txt").read_text().split():
            name, lx, ly, rx, ry = line.strip().split(",")
            p1, p2 = (float(lx), float(ly)), (float(rx), float(ry))
            le, re = sorted((p1, p2))
            gt[name] = (le, re)
    return gt


def gen_anchors():
    a = []
    for cells, per in ((16, 2), (8, 6)):
        for r in range(cells):
            for c in range(cells):
                for _ in range(per):
                    a.append(((c + 0.5) / cells, (r + 0.5) / cells))
    return np.array(a, np.float32)


ANCHORS = gen_anchors()


class Yunet:
    def __init__(self):
        self.d = cv2.FaceDetectorYN.create(str(YUNET), "", (320, 320),
                                           score_threshold=0.6)

    def detect(self, bgr):
        h, w = bgr.shape[:2]
        self.d.setInputSize((w, h))
        ok, faces = self.d.detect(bgr)
        if faces is None or len(faces) == 0:
            return None
        return max(faces, key=lambda r: r[2] * r[3])


class BlazeOnnx:
    def __init__(self):
        self.sess = ort.InferenceSession(str(BLAZE),
                                         providers=["CPUExecutionProvider"])

    def detect(self, bgr, thr=0.5):
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
        return np.array([cx - bw / 2, cy - bh / 2,
                         cx + bw / 2, cy + bh / 2]) * side


class MeshOnnx:
    def __init__(self, path):
        self.sess = ort.InferenceSession(str(path),
                                         providers=["CPUExecutionProvider"])
        self.inp = self.sess.get_inputs()[0].name
        shape = self.sess.get_inputs()[0].shape
        self.side = int(shape[1]) if isinstance(shape[1], int) else 256

    def landmarks(self, bgr, bbox_xywh, margin=0.25):
        x, y, w, h = bbox_xywh[:4]
        cx, cy = x + w / 2, y + h / 2
        half = 0.5 * max(w, h) * (1 + 2 * margin)
        x0, y0 = cx - half, cy - half
        side = 2 * half
        H, W = bgr.shape[:2]
        xs = np.clip(np.arange(self.side) + 0.5, 0, None) / self.side * side + x0
        ys = np.clip(np.arange(self.side) + 0.5, 0, None) / self.side * side + y0
        mx = np.clip(xs, 0, W - 1).astype(np.float32)
        my = np.clip(ys, 0, H - 1).astype(np.float32)
        grid_x, grid_y = np.meshgrid(mx, my)
        crop = cv2.remap(bgr, grid_x, grid_y, cv2.INTER_LINEAR)
        rgb = cv2.cvtColor(crop, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
        out = self.sess.run(None, {self.inp: rgb[None]})
        raw = None
        for o in out:
            if o.size in (468 * 3, 478 * 3):
                raw = o.reshape(-1, 3)
        if raw is None:
            return None
        pts = raw[:, :2] / self.side
        return np.stack([pts[:, 0] * side + x0, pts[:, 1] * side + y0], 1)


def eye_nme_pts(pts, gt_le, gt_re):
    c1 = pts[RIGHT_EYE].mean(0)
    c2 = pts[LEFT_EYE].mean(0)
    eyes = sorted([tuple(c1), tuple(c2)])
    iod = np.hypot(gt_re[0] - gt_le[0], gt_re[1] - gt_le[1]) + 1e-9
    d = (np.hypot(eyes[0][0] - gt_le[0], eyes[0][1] - gt_le[1])
         + np.hypot(eyes[1][0] - gt_re[0], eyes[1][1] - gt_re[1])) / 2
    return float(d / iod)


def ear(pts, idx):
    d = lambda a, b: float(np.hypot(*(pts[a] - pts[b])))
    horiz = d(idx[0], idx[3])
    if horiz < 1e-6:
        return 0.0
    return (d(idx[1], idx[5]) + d(idx[2], idx[4])) / (2 * horiz)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("bench_cascade.json"))
    a = ap.parse_args()
    out = {"cascade": {}, "mesh": {}}

    yunet, blaze = Yunet(), BlazeOnnx()
    gt = load_cbsr_gt()
    groups = {
        "cbsr": [CBSR / "NIR_face_dataset" / "NIR_face_dataset" / n
                 for n in sorted(gt)],
        "tufts_nir": sorted((TUFTS / "td-nir-a").rglob("*.png")),
        "tufts_rgb": sorted((TUFTS / "td-rgb-a").rglob("*.png")),
        "dark-burst": lit_frames(BURST_DARK),
    }
    for g, pfx in SUNCAL_GROUPS.items():
        groups[g] = [f for d in sorted(SUNCAL.iterdir())
                     if d.is_dir() and d.name.startswith(pfx)
                     for f in lit_frames(d)]

    for g, files in groups.items():
        y = b = c = n = 0
        for p in files:
            img = cv2.imread(str(p))
            if img is None:
                continue
            n += 1
            yd = yunet.detect(img)
            bd = blaze.detect(img)
            y += yd is not None
            b += bd is not None
            c += (yd is not None) or (bd is not None)
        out["cascade"][g] = {"yunet": y / n, "blaze_onnx": b / n,
                             "cascade": c / n, "n": n}
        print(f"[cascade] {g}: yunet {y/n:.3f} blaze {b/n:.3f} "
              f"CASCADE {c/n:.3f} (n={n})", flush=True)

    # Mesh old vs new through the SHIPPED pipeline shape (YuNet bbox crop).
    meshes = {"old_192": MeshOnnx(MESH_OLD), "new_256": MeshOnnx(MESH_NEW)}
    names = sorted(gt)[::4]
    for tag, m in meshes.items():
        nmes = []
        ears = []
        for nm in names:
            img = cv2.imread(str(CBSR / "NIR_face_dataset" / "NIR_face_dataset" / nm))
            if img is None:
                continue
            f = yunet.detect(img)
            if f is None:
                continue
            pts = m.landmarks(img, f)
            if pts is None:
                continue
            nmes.append(eye_nme_pts(pts, *gt[nm]))
            ears.append((ear(pts, EAR_LEFT) + ear(pts, EAR_RIGHT)) / 2)
        out["mesh"][tag] = {"eye_nme": float(np.mean(nmes)),
                            "ear_mean": float(np.mean(ears)),
                            "ear_std": float(np.std(ears)), "n": len(nmes)}
        print(f"[mesh] {tag}: eye_nme {np.mean(nmes):.4f} "
              f"EAR {np.mean(ears):.3f}±{np.std(ears):.3f} (open eyes, n={len(nmes)})",
              flush=True)

    a.out.write_text(json.dumps(out, indent=2))
    print(f"wrote {a.out}", flush=True)


if __name__ == "__main__":
    main()
