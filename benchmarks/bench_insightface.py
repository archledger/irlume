#!/usr/bin/env python3
"""irlume's shipped detection/landmark stack vs InsightFace buffalo_l's.

Detectors (rate on all dataset groups; eye NME + latency on CBSR):
  yunet    - shipped primary
  cascade  - shipped: yunet + BlazeFace short-range rescue on misses
  scrfd    - InsightFace det_10g (buffalo_l detector), standard decode:
             640x640 letterbox, (x-127.5)/128, strides 8/16/32 x 2 anchors,
             distance-to-anchor bbox/kps decode, NMS 0.4.

Landmarkers (eye NME on CBSR, latency, temporal jitter on a static burst):
  mesh_new  - shipped face_landmark.onnx (256px, 478 pts), YuNet-bbox crop
  2d106det  - InsightFace dense landmarks (192px, 106 pts), same crop policy.
              Eye indices are DATA-CALIBRATED: on 50 held-out images the 8
              points nearest each ground-truth eye are selected, then frozen
              and evaluated on the remaining images (avoids hand-mapping
              the 106-point layout wrong).

Recognition was benchmarked 2026-07-13 and 2026-07-14 (LFW, Oulu, CBSR,
Tufts); this completes the stack comparison with the two stages that were
never run head-to-head.

Usage: ~/mp-venv/bin/python bench_insightface.py --out bench_if.json
"""
import argparse, json, time
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

HOME = Path.home()
YUNET = HOME / "bench" / "models" / "face_detection_yunet_2023mar.onnx"
BLAZE = HOME / "bench" / "models_mp" / "blaze_face_short_range.onnx"
MESH_NEW = HOME / "bench" / "models_mp" / "face_landmarks_new.onnx"
SCRFD = HOME / "bench" / "models_if" / "det_10g.onnx"
LMK106 = HOME / "bench" / "models_if" / "2d106det.onnx"
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


def gen_blaze_anchors():
    a = []
    for cells, per in ((16, 2), (8, 6)):
        for r in range(cells):
            for c in range(cells):
                for _ in range(per):
                    a.append(((c + 0.5) / cells, (r + 0.5) / cells))
    return np.array(a, np.float32)


BLAZE_ANCHORS = gen_blaze_anchors()


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
        f = max(faces, key=lambda r: r[2] * r[3])
        eyes = sorted([(f[4], f[5]), (f[6], f[7])])
        return f[:4], eyes


class Blaze:
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
        ax, ay = BLAZE_ANCHORS[i]
        cx, cy = ax + r[0] / 128.0, ay + r[1] / 128.0
        bw, bh = r[2] / 128.0, r[3] / 128.0
        box = np.array([(cx - bw / 2), (cy - bh / 2),
                        (cx + bw / 2), (cy + bh / 2)]) * side
        return np.array([box[0], box[1], box[2] - box[0], box[3] - box[1]],
                        np.float32), None


class Cascade:
    def __init__(self):
        self.y = Yunet()
        self.b = Blaze()

    def detect(self, bgr):
        d = self.y.detect(bgr)
        return d if d is not None else self.b.detect(bgr)


class Scrfd:
    SIZE = 640

    def __init__(self):
        self.sess = ort.InferenceSession(str(SCRFD),
                                         providers=["CPUExecutionProvider"])
        self.inp = self.sess.get_inputs()[0].name

    def detect(self, bgr, thr=0.5, nms_iou=0.4):
        h, w = bgr.shape[:2]
        scale = self.SIZE / max(h, w)
        nh, nw = int(h * scale), int(w * scale)
        img = np.zeros((self.SIZE, self.SIZE, 3), np.uint8)
        img[:nh, :nw] = cv2.resize(bgr, (nw, nh))
        x = (img.astype(np.float32) - 127.5) / 128.0
        x = x[:, :, ::-1].transpose(2, 0, 1)[None].copy()  # BGR->RGB, NCHW
        outs = self.sess.run(None, {self.inp: x})
        # outputs: per stride (8,16,32): scores (N,1), bbox (N,4), kps (N,10)
        dets = []
        for si, stride in enumerate((8, 16, 32)):
            scores = outs[si].reshape(-1)
            bbox = outs[si + 3].reshape(-1, 4) * stride
            kps = outs[si + 6].reshape(-1, 10) * stride
            fm = self.SIZE // stride
            centers = np.stack(np.meshgrid(np.arange(fm), np.arange(fm)),
                               -1).reshape(-1, 2).astype(np.float32) * stride
            centers = np.repeat(centers, 2, axis=0)  # 2 anchors per cell
            keep = scores >= thr
            if not keep.any():
                continue
            c, s, b, k = centers[keep], scores[keep], bbox[keep], kps[keep]
            boxes = np.stack([c[:, 0] - b[:, 0], c[:, 1] - b[:, 1],
                              c[:, 0] + b[:, 2], c[:, 1] + b[:, 3]], 1)
            kp = np.stack([c[:, 0:1] + k[:, 0::2], c[:, 1:2] + k[:, 1::2]],
                          2)  # (n, 5, 2)
            for i in range(len(s)):
                dets.append((float(s[i]), boxes[i], kp[i]))
        if not dets:
            return None
        dets.sort(key=lambda d: -d[0])
        kept = []
        for d in dets:
            if all(self._iou(d[1], k[1]) < nms_iou for k in kept):
                kept.append(d)
        best = max(kept, key=lambda d: (d[1][2] - d[1][0]) * (d[1][3] - d[1][1]))
        _, box, kp = best
        box, kp = box / scale, kp / scale
        eyes = sorted([tuple(kp[0]), tuple(kp[1])])
        return np.array([box[0], box[1], box[2] - box[0], box[3] - box[1]],
                        np.float32), eyes

    @staticmethod
    def _iou(a, b):
        x0, y0 = max(a[0], b[0]), max(a[1], b[1])
        x1, y1 = min(a[2], b[2]), min(a[3], b[3])
        inter = max(0.0, x1 - x0) * max(0.0, y1 - y0)
        ua = ((a[2] - a[0]) * (a[3] - a[1])
              + (b[2] - b[0]) * (b[3] - b[1]) - inter)
        return inter / (ua + 1e-9)


def eye_nme(eyes, gt_le, gt_re):
    iod = np.hypot(gt_re[0] - gt_le[0], gt_re[1] - gt_le[1]) + 1e-9
    d = (np.hypot(eyes[0][0] - gt_le[0], eyes[0][1] - gt_le[1])
         + np.hypot(eyes[1][0] - gt_re[0], eyes[1][1] - gt_re[1])) / 2
    return float(d / iod)


class MeshNew:
    name = "mesh_new_256"

    def __init__(self):
        self.sess = ort.InferenceSession(str(MESH_NEW),
                                         providers=["CPUExecutionProvider"])
        self.inp = self.sess.get_inputs()[0].name
        self.side = 256

    def landmarks(self, bgr, bbox_xywh):
        pts = self._run(bgr, bbox_xywh)
        return pts

    def eye_centers(self, pts):
        c1, c2 = pts[RIGHT_EYE].mean(0), pts[LEFT_EYE].mean(0)
        return sorted([tuple(c1), tuple(c2)])

    def _run(self, bgr, bbox, margin=0.25):
        x, y, w, h = bbox[:4]
        cx, cy = x + w / 2, y + h / 2
        half = 0.5 * max(w, h) * (1 + 2 * margin)
        x0, y0, side = cx - half, cy - half, 2 * half
        H, W = bgr.shape[:2]
        gx = np.clip((np.arange(self.side) + 0.5) / self.side * side + x0,
                     0, W - 1).astype(np.float32)
        gy = np.clip((np.arange(self.side) + 0.5) / self.side * side + y0,
                     0, H - 1).astype(np.float32)
        mgx, mgy = np.meshgrid(gx, gy)
        crop = cv2.remap(bgr, mgx, mgy, cv2.INTER_LINEAR)
        rgb = cv2.cvtColor(crop, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
        out = self.sess.run(None, {self.inp: rgb[None]})
        raw = None
        for o in out:
            if o.size in (468 * 3, 478 * 3):
                raw = o.reshape(-1, 3)
        if raw is None:
            return None
        p = raw[:, :2] / self.side
        return np.stack([p[:, 0] * side + x0, p[:, 1] * side + y0], 1)


class Lmk106:
    name = "2d106det"

    def __init__(self):
        self.sess = ort.InferenceSession(str(LMK106),
                                         providers=["CPUExecutionProvider"])
        self.inp = self.sess.get_inputs()[0].name
        self.side = 192
        self.right_idx = None  # calibrated on first 50 GT images
        self.left_idx = None

    def landmarks(self, bgr, bbox_xywh, margin=0.25):
        x, y, w, h = bbox_xywh[:4]
        cx, cy = x + w / 2, y + h / 2
        half = 0.5 * max(w, h) * (1 + 2 * margin)
        x0, y0, side = cx - half, cy - half, 2 * half
        H, W = bgr.shape[:2]
        gx = np.clip((np.arange(self.side) + 0.5) / self.side * side + x0,
                     0, W - 1).astype(np.float32)
        gy = np.clip((np.arange(self.side) + 0.5) / self.side * side + y0,
                     0, H - 1).astype(np.float32)
        mgx, mgy = np.meshgrid(gx, gy)
        crop = cv2.remap(bgr, mgx, mgy, cv2.INTER_LINEAR)
        # InsightFace landmark preprocessing: raw BGR, mean 0, std 1, NCHW.
        x_in = crop.astype(np.float32).transpose(2, 0, 1)[None]
        out = self.sess.run(None, {self.inp: x_in})[0].reshape(-1, 2)
        pts = (out + 1.0) * (self.side / 2.0) / self.side  # -> [0,1] of crop
        return np.stack([pts[:, 0] * side + x0, pts[:, 1] * side + y0], 1)

    def calibrate(self, samples):
        """Pick the 8 indices nearest each GT eye across calibration images."""
        votes_l = np.zeros(106)
        votes_r = np.zeros(106)
        for pts, (gt_le, gt_re) in samples:
            dl = np.linalg.norm(pts - np.array(gt_le), axis=1)
            dr = np.linalg.norm(pts - np.array(gt_re), axis=1)
            votes_l[np.argsort(dl)[:8]] += 1
            votes_r[np.argsort(dr)[:8]] += 1
        self.left_idx = np.argsort(-votes_l)[:8]
        self.right_idx = np.argsort(-votes_r)[:8]

    def eye_centers(self, pts):
        c1 = pts[self.left_idx].mean(0)
        c2 = pts[self.right_idx].mean(0)
        return sorted([tuple(c1), tuple(c2)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("bench_if.json"))
    a = ap.parse_args()
    out = {"detectors": {}, "landmarkers": {}}
    gt = load_cbsr_gt()
    cbsr_dir = CBSR / "NIR_face_dataset" / "NIR_face_dataset"

    groups = {
        "cbsr": [cbsr_dir / n for n in sorted(gt)],
        "tufts_nir": sorted((TUFTS / "td-nir-a").rglob("*.png")),
        "tufts_rgb": sorted((TUFTS / "td-rgb-a").rglob("*.png")),
        "dark-burst": lit_frames(BURST_DARK),
    }
    for g, pfx in SUNCAL_GROUPS.items():
        groups[g] = [f for d in sorted(SUNCAL.iterdir())
                     if d.is_dir() and d.name.startswith(pfx)
                     for f in lit_frames(d)]

    for det, name in ((Yunet(), "yunet"), (Cascade(), "cascade"),
                      (Scrfd(), "scrfd_10g")):
        r = {}
        for g, files in groups.items():
            hits, nmes, times = 0, [], []
            for p in files:
                img = cv2.imread(str(p))
                if img is None:
                    continue
                t0 = time.perf_counter()
                d = det.detect(img)
                times.append((time.perf_counter() - t0) * 1000)
                if d is not None:
                    hits += 1
                    if g == "cbsr" and d[1] is not None:
                        nmes.append(eye_nme(d[1], *gt[p.name]))
            r[g] = {"rate": hits / len(files), "n": len(files)}
            if g == "cbsr":
                r[g]["ms"] = float(np.mean(times))
                if nmes:
                    r[g]["eye_nme"] = float(np.mean(nmes))
        out["detectors"][name] = r
        print(f"[det] {name}: cbsr {r['cbsr']['rate']:.3f} "
              f"({r['cbsr'].get('eye_nme', float('nan')):.3f} nme, "
              f"{r['cbsr']['ms']:.1f}ms) "
              f"tufts {r['tufts_nir']['rate']:.3f}/{r['tufts_rgb']['rate']:.3f} "
              f"walk {r['outdoor-walking']['rate']:.3f} "
              f"shade {r['shade-frontal']['rate']:.3f}", flush=True)

    # Landmarkers, both fed the same YuNet boxes.
    yunet = Yunet()
    names = sorted(gt)
    calib_names, eval_names = names[:50], names[50::4]
    models = [MeshNew(), Lmk106()]
    # calibrate 2d106det eye indices
    calib_samples = []
    for nm in calib_names:
        img = cv2.imread(str(cbsr_dir / nm))
        f = yunet.detect(img) if img is not None else None
        if f is None:
            continue
        pts = models[1].landmarks(img, f[0])
        if pts is not None:
            calib_samples.append((pts, gt[nm]))
    models[1].calibrate(calib_samples)
    print(f"[2d106det] calibrated eye indices L={models[1].left_idx.tolist()} "
          f"R={models[1].right_idx.tolist()} on {len(calib_samples)} images",
          flush=True)

    for m in models:
        nmes, times = [], []
        for nm in eval_names:
            img = cv2.imread(str(cbsr_dir / nm))
            f = yunet.detect(img) if img is not None else None
            if f is None:
                continue
            t0 = time.perf_counter()
            pts = m.landmarks(img, f[0])
            times.append((time.perf_counter() - t0) * 1000)
            if pts is None:
                continue
            nmes.append(eye_nme(m.eye_centers(pts), *gt[nm]))
        stack = []
        for p in lit_frames(BURST_DARK):
            img = cv2.imread(str(p))
            f = yunet.detect(img) if img is not None else None
            if f is None:
                continue
            pts = m.landmarks(img, f[0])
            if pts is not None:
                stack.append(pts[:106] if m.name == "2d106det" else pts[:468])
        jitter = (float(np.stack(stack).std(0).mean())
                  if len(stack) >= 5 else None)
        out["landmarkers"][m.name] = {
            "eye_nme": float(np.mean(nmes)), "n": len(nmes),
            "ms": float(np.mean(times)), "jitter_px": jitter}
        print(f"[lmk] {m.name}: eye_nme {np.mean(nmes):.4f} "
              f"{np.mean(times):.1f}ms jitter {jitter}", flush=True)

    a.out.write_text(json.dumps(out, indent=2))
    print(f"wrote {a.out}", flush=True)


if __name__ == "__main__":
    main()
