#!/usr/bin/env python3
"""Landmark bench: the 478-point face mesh vs sparse GT landmarks.

Datasets: WFLW test split (2,500 annotation rows over 2,118 images, 98-pt),
the 300W common test subset (600 png+pts pairs, 68-pt), and AFLW2000
(2,000 jpg+mat pairs, 68-pt read from the mat's pt3d_68 x/y, which the
controller approved scipy 1.18.1 in the bench venv for; pinned in
requirements-bench.txt).

Protocol per row: YuNet at the operating point (640 square letterbox, score
threshold 0.6) proposes faces; the best detection by IoU against the GT face
box must reach MATCH_IOU or the row counts a pipeline failure. Matched and
standalone paths crop a square of CROP_SCALE x the box side, centered on the
box, edge-replicated at the frame border (the shipped Rust mesh samples its
crop square with edge clamping; the copyMakeBorder crop reproduces that
without rescaling), resize to 256, and run the mesh ([1,256,256,3] RGB in
[0,1]; output [1,1,1434] = 478 x,y,z in input space). Mapped-back points
are gated by the same plausibility rule as the runtime (every point
finite, >=half the points within the crop plus 25% slop, central 80% span
>= 2px on both axes) before scoring.

GT face box: the tight bounds of the GT landmarks. WFLW's shipped rect is a
loose region (2.1-5.4x the landmark extent wide on the first test rows), too
loose for a meaningful IoU-0.3 match or a face-scale mesh crop; the landmark
bounds are the face. 300W ships no box at all, so the landmark bounds are the
only shared convention across both sets.

GT eye-index sets are pinned by geometry (per-index mean positions over the
first 20 annotations per dataset; evidence in the task report):
  WFLW98: left eye 60-67 (outer 60, inner 64), right eye 68-75 (inner 68,
    outer 72), mouth corners 76/82, nose tip 57, chin 16.
  300W68: left eye 36-41 (outer 36, inner 39), right eye 42-47 (inner 42,
    outer 45), mouth corners 48/54, nose tip 30, chin 8.
Both verified as two tight clusters straddling the face midline, above the
mouth. Eye centers are corner means; the 68-pt scheme drops the two
inner-corner mesh anchors (133/362) that its topology cannot name.

--limit N caps rows per dataset (validation only; full runs omit it).
"""

import argparse
import json
import math
import sys
import time
from collections import OrderedDict
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

from landmark_score import (
    iou,
    mesh_eye_centers,
    mesh_plausible,
    nme,
    point_bounds,
)
from letterbox import letterbox_image, restore_boxes

OP_INPUT = 640
OP_SCORE = 0.6
YUNET_MODEL = "face_detection_yunet_2023mar.onnx"
MESH_MODEL = "face_landmark.onnx"
MESH_INPUT = 256
MESH_OUT = 478 * 3
CROP_SCALE = 1.25
MATCH_IOU = 0.3

# mesh anchor indices in correspondence order per scheme (see module
# docstring for the pinned GT evidence).
SCHEMES = {
    "wflw98": {
        "eye_corners": ((60, 64), (68, 72)),
        "anchors_mesh": [33, 133, 362, 263, 61, 291, 1, 152],
        "anchors_gt": [60, 64, 68, 72, 76, 82, 57, 16],
    },
    "pts68": {
        "eye_corners": ((36, 39), (42, 45)),
        "anchors_mesh": [33, 263, 61, 291, 1, 152],
        "anchors_gt": [36, 45, 48, 54, 30, 8],
    },
}


def yunet_detector(model_path: Path):
    return cv2.FaceDetectorYN_create(
        str(model_path), "", (OP_INPUT, OP_INPUT), score_threshold=OP_SCORE
    )


def detect_letterbox(det, img) -> list[tuple[float, list[float]]]:
    """YuNet on the 640 letterbox canvas, decoded to (score, xyxy) in
    original image coordinates (the bench_detection_wider convention)."""
    canvas, params = letterbox_image(img, OP_INPUT)
    _, faces = det.detect(canvas)
    if faces is None:
        return []
    h, w = img.shape[:2]
    raw = [
        (
            float(f[14]),
            [float(f[0]), float(f[1]), float(f[0] + f[2]), float(f[1] + f[3])],
        )
        for f in faces
    ]
    boxes = restore_boxes([b for _, b in raw], params, w, h)
    return [(s, b) for (s, _), b in zip(raw, boxes)]


class MeshRunner:
    def __init__(self, model_path: Path):
        self.sess = ort.InferenceSession(
            str(model_path), providers=["CPUExecutionProvider"]
        )
        self.input_name = self.sess.get_inputs()[0].name

    def run(self, crop_bgr):
        """RGB [0,1] NHWC into the mesh; returns 478 (x, y) pairs in input
        space (0..256), or None when no 1434-value output comes back."""
        rgb = cv2.cvtColor(crop_bgr, cv2.COLOR_BGR2RGB)
        x = rgb.astype(np.float32) / 255.0
        outs = self.sess.run(None, {self.input_name: x[None]})
        for o in outs:
            if o.size == MESH_OUT:
                return o.reshape(478, 3)[:, :2]
        return None


def crop_square(img, box, scale: float):
    """Square CROP_SCALE-x-side crop centered on `box`, edge-replicated at
    the frame border. Returns (crop, win) where win = (x, y, w, h) is the
    exact sampled window in original coordinates for mapping mesh output
    back."""
    h, w = img.shape[:2]
    x1, y1, x2, y2 = box
    cx, cy = (x1 + x2) / 2, (y1 + y2) / 2
    side = max(x2 - x1, y2 - y1) * scale
    wx0, wy0 = cx - side / 2, cy - side / 2
    xi0, yi0 = math.floor(wx0), math.floor(wy0)
    xi1, yi1 = math.ceil(wx0 + side), math.ceil(wy0 + side)
    pad_l, pad_t = max(0, -xi0), max(0, -yi0)
    pad_r, pad_b = max(0, xi1 - w), max(0, yi1 - h)
    if pad_l or pad_t or pad_r or pad_b:
        img = cv2.copyMakeBorder(
            img, pad_t, pad_b, pad_l, pad_r, cv2.BORDER_REPLICATE
        )
    win = img[yi0 + pad_t : yi1 + pad_t, xi0 + pad_l : xi1 + pad_l]
    crop = cv2.resize(win, (MESH_INPUT, MESH_INPUT))
    return crop, (float(xi0), float(yi0), float(xi1 - xi0), float(yi1 - yi0))


def map_mesh(pts2d, win) -> np.ndarray:
    """Input-space points into original image coordinates via the sampled
    window."""
    x0, y0, w, h = win
    return pts2d / MESH_INPUT * np.array([w, h]) + np.array([x0, y0])


def parse_pts(path: Path) -> np.ndarray:
    lines = path.read_text().splitlines()
    n = int([l for l in lines if l.startswith("n_points")][0].split(":")[1])
    start = lines.index("{") + 1
    return np.array([lines[start + i].split() for i in range(n)], float)


def load_wflw(root: Path):
    txt = (
        root
        / "WFLW_annotations/list_98pt_rect_attr_train_test/list_98pt_rect_attr_test.txt"
    )
    rows = []
    for line in txt.read_text().splitlines():
        f = line.split()
        pts = np.array(f[:196], float).reshape(98, 2)
        rows.append((root / "WFLW_images" / f[-1], pts))
    return rows, "wflw98"


def load_300w(root: Path):
    base = root / "300w_extracted" / "300W"
    rows = []
    for p in sorted(base.rglob("*.pts")):
        img = p.with_suffix(".png")
        if not img.exists():
            raise FileNotFoundError(f"pts without png: {p}")
        rows.append((img, parse_pts(p)))
    return rows, "pts68"


def load_aflw2000(root: Path):
    """2,000 annotation mats at the dataset root (flat glob only: the
    mirror's Code/ tree holds unrelated morphology mats under rglob).

    68-pt GT comes from pt3d_68 (3x68, x/y rows in image pixel space; zero
    NaNs across all 2,000 mats, 3 mats have landmarks at the image edge).
    The mat's roi is a loose detection region (landmark centroid outside it
    on 885 of the first-pass check), so it is ignored: the GT face box is
    the tight landmark bounds, the shared convention across all three sets.
    """
    try:
        from scipy.io import loadmat
    except ImportError as e:
        raise RuntimeError(
            "aflw2000 needs scipy (pinned in requirements-bench.txt)"
        ) from e
    rows = []
    for p in sorted(root.glob("*.mat")):
        img = p.with_suffix(".jpg")
        if not img.exists():
            raise FileNotFoundError(f"mat without jpg: {p}")
        m = loadmat(str(p))
        if "pt3d_68" not in m:
            raise KeyError(f"no pt3d_68 in {p}")
        pts = np.array(m["pt3d_68"][:2].T, float)
        rows.append((img, pts))
    return rows, "pts68"


LOADERS = {
    "wflw_test": (load_wflw, "wflw_root"),
    "300w_test": (load_300w, "w300_root"),
    "aflw2000": (load_aflw2000, "aflw_root"),
}


def gt_eye_centers(pts, scheme) -> tuple[tuple, tuple]:
    (lo, li), (ri, ro) = SCHEMES[scheme]["eye_corners"]
    left = (
        (float(pts[lo][0]) + float(pts[li][0])) / 2,
        (float(pts[lo][1]) + float(pts[li][1])) / 2,
    )
    right = (
        (float(pts[ri][0]) + float(pts[ro][0])) / 2,
        (float(pts[ri][1]) + float(pts[ro][1])) / 2,
    )
    return left, right


def score_dataset(tag, rows, scheme, det, mesh, limit):
    sch = SCHEMES[scheme]
    if limit:
        rows = rows[:limit]
    by_img: OrderedDict[Path, list] = OrderedDict()
    for path, pts in rows:
        by_img.setdefault(path, []).append(pts)

    counts = {
        "rows": len(rows),
        "mesh_ok": 0,
        "n_fail_yunet": 0,
        "n_fail_mesh": 0,
        "n_standalone_mesh_fail": 0,
        "n_zero_iod": 0,
        "n_unreadable": 0,
    }
    eye_nmes, standalone_nmes, anchor_nmes, iou_gains = [], [], [], []
    t0 = time.time()
    done = 0
    mark = {"bucket": -1}
    for path, pts_list in by_img.items():
        img = cv2.imread(str(path))
        if img is None:
            counts["n_unreadable"] += len(pts_list)
            done += len(pts_list)
            continue
        dets = detect_letterbox(det, img)
        for pts in pts_list:
            done += 1
            gt_box = point_bounds(pts)
            gt_l, gt_r = gt_eye_centers(pts, scheme)
            iod = math.hypot(gt_r[0] - gt_l[0], gt_r[1] - gt_l[1])
            if iod <= 0.0:
                counts["n_zero_iod"] += 1
                _progress(done, counts["rows"], tag, mark)
                continue
            best = None
            if dets:
                best = max(dets, key=lambda d: iou(d[1], gt_box))
            if best is None or iou(best[1], gt_box) < MATCH_IOU:
                counts["n_fail_yunet"] += 1
            else:
                det_box = best[1]
                crop, win = crop_square(img, det_box, CROP_SCALE)
                raw = mesh.run(crop)
                if raw is None or not mesh_plausible(map_mesh(raw, win), win):
                    counts["n_fail_mesh"] += 1
                else:
                    frame_pts = map_mesh(raw, win)
                    counts["mesh_ok"] += 1
                    le, re = mesh_eye_centers(frame_pts.tolist())
                    eye_nmes.append(nme((le, re), gt_l, gt_r, [], []))
                    anchors_pred = [frame_pts[i] for i in sch["anchors_mesh"]]
                    anchors_gt = [pts[i] for i in sch["anchors_gt"]]
                    anchor_nmes.append(
                        nme(None, gt_l, gt_r, anchors_pred, anchors_gt)
                    )
                    refined = point_bounds(frame_pts)
                    iou_gains.append(
                        iou(refined, gt_box) - iou(det_box, gt_box)
                    )
            crop, win = crop_square(img, gt_box, CROP_SCALE)
            raw = mesh.run(crop)
            if raw is None or not mesh_plausible(map_mesh(raw, win), win):
                counts["n_standalone_mesh_fail"] += 1
            else:
                le, re = mesh_eye_centers(map_mesh(raw, win).tolist())
                standalone_nmes.append(nme((le, re), gt_l, gt_r, [], []))
            _progress(done, counts["rows"], tag, mark)

    section = {
        "images": counts["rows"],
        "mesh_ok": counts["mesh_ok"],
        "eye_nme_mean": _mean(eye_nmes),
        "eye_nme_p90": _p90(eye_nmes),
        "eye_nme_standalone_mean": _mean(standalone_nmes),
        "anchor_nme_mean": _mean(anchor_nmes),
        "align_iou_gain_mean": _mean(iou_gains),
        "n_fail_yunet": counts["n_fail_yunet"],
        "n_fail_mesh": counts["n_fail_mesh"],
    }
    audit = {
        "rows": counts["rows"],
        "unique_images": len(by_img),
        "eye_nme_n": len(eye_nmes),
        "standalone_n": len(standalone_nmes),
        "n_standalone_mesh_fail": counts["n_standalone_mesh_fail"],
        "n_zero_iod": counts["n_zero_iod"],
        "n_unreadable": counts["n_unreadable"],
        "elapsed_s": round(time.time() - t0, 1),
    }
    return section, audit


def _mean(v):
    return float(np.mean(v)) if v else 0.0


def _p90(v):
    return float(np.percentile(v, 90)) if v else 0.0


def _progress(done, total, tag, mark):
    bucket = done // 200
    if bucket > mark["bucket"]:
        mark["bucket"] = bucket
        print(f"[{tag}] {done}/{total} rows", flush=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--wflw-root", type=Path)
    ap.add_argument("--w300-root", type=Path)
    ap.add_argument("--aflw-root", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int)
    args = ap.parse_args(argv)

    enabled = [
        (name, getattr(args, arg))
        for name, (_, arg) in LOADERS.items()
        if getattr(args, arg)
    ]
    if not enabled:
        ap.error("at least one dataset root is required")

    det = yunet_detector(args.models_dir / YUNET_MODEL)
    mesh = MeshRunner(args.models_dir / MESH_MODEL)

    per_dataset = {}
    notes = [
        (
            "pipeline: YuNet at the operating point (640 square letterbox, "
            f"score {OP_SCORE}); best detection matched to the GT face box "
            f"at IoU >= {MATCH_IOU}; matched and standalone paths crop a "
            f"{CROP_SCALE}x-side square centered on the box, edge-"
            "replicated at the frame border, resized to "
            f"{MESH_INPUT}; mesh output gated by the runtime plausibility "
            "rule before scoring."
        ),
        (
            "gt face box = tight bounds of the GT landmarks: WFLW's shipped "
            "rect is a loose region (2.1-5.4x the landmark extent wide on "
            "the first test rows), unusable for IoU-0.3 matching or "
            "face-scale crops; 300W ships no box. Eye indices pinned by "
            "geometry over the first 20 annotations per dataset (evidence "
            "in the task report): wflw98 left 60-67/right 68-75 with "
            "corners 60/64/68/72, mouth 76/82, nose tip 57, chin 16; "
            "pts68 left 36-41/right 42-47 with corners 36/39/42/45, mouth "
            "48/54, nose tip 30, chin 8; eye centers are corner means; the "
            "68-pt scheme scores 6 anchors (its topology has no separate "
            "inner-corner points for mesh 133/362), wflw98 scores 8."
        ),
    ]
    for name, root in enabled:
        loader, _ = LOADERS[name]
        rows, scheme = loader(root)
        if name == "aflw2000":
            import scipy

            notes.append(
                "aflw2000 gt: 68-pt from mat pt3d_68 x/y in image pixel "
                f"space (flat glob of 2,000 mats; the mirror's Code/ tree "
                "holds unrelated mats, excluded); roi ignored as a loose "
                "detection region, tight landmark bounds per the shared "
                f"convention; parsed with scipy {scipy.__version__}; pts68 "
                "eye/anchor constants reused, geometry re-verified over "
                "the first 20 mats (two tight clusters above the mouth)."
            )
        section, audit = score_dataset(
            name, rows, scheme, det, mesh, args.limit
        )
        per_dataset[name] = section
        notes.append(f"{name} audit: {json.dumps(audit, sort_keys=True)}")
        print(f"[{name}] {json.dumps(section)}", flush=True)

    result = {
        "runtime": {
            "ort_version": ort.__version__,
            "providers": ort.get_available_providers(),
            "cv2_version": cv2.__version__,
            "yunet_model": YUNET_MODEL,
            "mesh_model": MESH_MODEL,
            "input": OP_INPUT,
            "score_threshold": OP_SCORE,
            "crop_scale": CROP_SCALE,
            "match_iou": MATCH_IOU,
        },
        "per_dataset": per_dataset,
        "notes": notes,
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
