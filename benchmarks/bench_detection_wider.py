#!/usr/bin/env python3
"""YuNet detection benchmark on WIDER FACE.

--smoke: run the first N images of the sorted val ground truth through YuNet
at irlume operating scale and write per-image counts. Full AP evaluation is a
later phase; this smoke run exists to prove the chain (venv, CUDA, models,
dataset, OpenCV YuNet) end to end.

--ap: full WIDER FACE val AP at the operating point (640 square letterbox,
score_threshold 0.6) using the official-protocol evaluator in wider_ap.py.
Difficulty tiers use official-approximation tier cuts (h>50/h>30/h>=10),
off-tier predictions discarded: each prediction is first matched to its
best-IoU GT among all valid boxes of its image, and predictions whose
best-overlap GT is outside the tier are dropped (neither tp nor fp);
invalid-flag GT boxes stay excluded everywhere.

--sweep: stratified val sample (every k-th image of the sorted list, nearest
stride-integer approximation of a 2000-image target) across input sizes
{320, 448, 640} x score thresholds {0.3, 0.45, 0.6, 0.7}. Decoders run at
the lowest sweep threshold and rows post-filter scores, so per-input FPPI
curves support recall_at_op_fppi (recall at the 640/0.6 row's FPPI).

--cascade: recall with and without the BlazeFace short-range rescue on
YuNet misses at the operating point, on full val plus a stride-sampled
train split (nearest stride-integer approximation of 4000 images).

All non-smoke modes merge their section into the shared results JSON so
successive runs build one artifact.
"""

import argparse
import json
import math
import sys
import time
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

from letterbox import letterbox_image, restore_boxes
from wider_ap import _match, evaluate_tier, parse_val_gt, voc_ap

OP_INPUT = 640
OP_SCORE = 0.6
SWEEP_INPUTS = (320, 448, 640)
SWEEP_THRESHOLDS = (0.3, 0.45, 0.6, 0.7)
SWEEP_TARGET = 2000
CASCADE_TRAIN_TARGET = 4000
IOU_THR = 0.5
EASY_MIN_H = 50.0
MEDIUM_MIN_H = 30.0
HARD_MIN_H = 10.0
YUNET_MODEL = "face_detection_yunet_2023mar.onnx"
BLAZE_MODEL = "blaze_face_short_range.onnx"


def val_image_list(wider_root: Path) -> list[str]:
    gt = wider_root / "wider_face_split" / "wider_face_val_bbx_gt.txt"
    return gt_image_list(gt)


def gt_image_list(gt_path: Path) -> list[str]:
    out = []
    for line in gt_path.read_text().splitlines():
        if line.endswith(".jpg"):
            out.append(line.strip())
    return out


def stride_sample(items: list[str], target: int) -> tuple[list[str], int]:
    stride = max(1, math.ceil(len(items) / target))
    return items[::stride], stride


def yunet_detector(model_path: Path, size: int, score_threshold: float):
    return cv2.FaceDetectorYN_create(
        str(model_path), "", (size, size), score_threshold=score_threshold
    )


def detect_letterbox(det, img, target: int) -> list[tuple[float, list[float]]]:
    """Decode YuNet rows [x, y, w, h, 5 landmarks, score] on the letterbox
    canvas into (score, [x1, y1, x2, y2]) in original image coordinates."""
    canvas, params = letterbox_image(img, target)
    _, faces = det.detect(canvas)
    if faces is None:
        return []
    h, w = img.shape[:2]
    raw = [
        (
            float(f[14]),
            [
                float(f[0]),
                float(f[1]),
                float(f[0] + f[2]),
                float(f[1] + f[3]),
            ],
        )
        for f in faces
    ]
    boxes = restore_boxes([b for _, b in raw], params, w, h)
    return [(s, b) for (s, _), b in zip(raw, boxes)]


def _read_progress(i: int, total: int, tag: str) -> None:
    if i % 200 == 0:
        print(f"[{tag}] {i}/{total} images", flush=True)


def _load_img(wider_root: Path, split: str, rel: str):
    return cv2.imread(str(wider_root / split / "images" / rel))


def run_ap(args) -> dict:
    vals = sorted(val_image_list(args.wider_root))
    gt_all = parse_val_gt(
        args.wider_root / "wider_face_split" / "wider_face_val_bbx_gt.txt"
    )
    det = yunet_detector(args.models_dir / YUNET_MODEL, OP_INPUT, OP_SCORE)
    preds_by_image = {}
    t0 = time.time()
    for i, rel in enumerate(vals, 1):
        img = _load_img(args.wider_root, "WIDER_val", rel)
        if img is None:
            preds_by_image[rel] = []
            continue
        preds_by_image[rel] = detect_letterbox(det, img, OP_INPUT)
        _read_progress(i, len(vals), "ap")
    hard = evaluate_tier(preds_by_image, gt_all, HARD_MIN_H, strict=False)
    medium = evaluate_tier(
        preds_by_image, gt_all, MEDIUM_MIN_H, strict=True
    )
    easy = evaluate_tier(preds_by_image, gt_all, EASY_MIN_H, strict=True)
    elapsed = time.time() - t0
    section = {
        "easy": easy["ap"],
        "medium": medium["ap"],
        "hard": hard["ap"],
        "tp": hard["tp"],
        "fp": hard["fp"],
        "n_gt": hard["n_gt"],
        "images": len(vals),
    }
    notes = [
        (
            f"ap run: {len(vals)} val images in {elapsed:.1f}s at the "
            f"operating point (letterbox {OP_INPUT}, score {OP_SCORE}); "
            "official-approximation tier cuts (h>50/h>30/h>=10), off-tier "
            "predictions discarded (best-overlap valid GT outside the tier "
            "drops the prediction; zero-overlap predictions stay fp "
            "candidates); invalid-flag GT boxes excluded everywhere; "
            "tp/fp/n_gt are the hard-tier totals."
        ),
        (
            "height-band approximation run superseded by tier semantics: "
            "the earlier h>=50/h>=20/all-valid bands scored easy "
            "0.6859 / medium 0.6866 / hard 0.3964 (tp 15826, fp 2366, "
            "n_gt 39123)."
        ),
    ]
    return section, notes


def run_sweep(args) -> dict:
    vals = sorted(val_image_list(args.wider_root))
    sample, stride = stride_sample(vals, SWEEP_TARGET)
    gt_all = parse_val_gt(
        args.wider_root / "wider_face_split" / "wider_face_val_bbx_gt.txt"
    )
    gt_sample = {k: gt_all[k] for k in sample if k in gt_all}
    n_gt_sample = sum(
        1 for boxes in gt_sample.values() for b in boxes if not b["invalid"]
    )
    dets = {
        s: yunet_detector(args.models_dir / YUNET_MODEL, s, min(SWEEP_THRESHOLDS))
        for s in SWEEP_INPUTS
    }
    decoded = {s: {} for s in SWEEP_INPUTS}
    t0 = time.time()
    for i, rel in enumerate(sample, 1):
        img = _load_img(args.wider_root, "WIDER_val", rel)
        for s in SWEEP_INPUTS:
            decoded[s][rel] = (
                detect_letterbox(dets[s], img, s) if img is not None else []
            )
        _read_progress(i, len(sample), "sweep")
    flags_by_input = {}
    for s in SWEEP_INPUTS:
        pairs: list[tuple[float, int]] = []
        for rel in sample:
            preds = sorted(
                decoded[s][rel], key=lambda p: p[0], reverse=True
            )
            flags = _match(preds, gt_sample.get(rel, []), IOU_THR)
            pairs.extend(
                (preds[j][0], 1 if f else 0) for j, f in enumerate(flags)
            )
        pairs.sort(key=lambda p: p[0], reverse=True)
        flags_by_input[s] = pairs
    op_pairs = [
        p for p in flags_by_input[OP_INPUT] if p[0] >= OP_SCORE
    ]
    op_fp = sum(1 for _, tp in op_pairs if not tp)
    op_fppi = op_fp / len(sample)
    rows = []
    for s in SWEEP_INPUTS:
        pairs = flags_by_input[s]
        for thr in SWEEP_THRESHOLDS:
            filt = [p for p in pairs if p[0] >= thr]
            scores = [p[0] for p in filt]
            tps = [p[1] for p in filt]
            recall = 0.0
            cum_tp = cum_fp = 0
            for _, tp in filt:
                if tp:
                    cum_tp += 1
                else:
                    cum_fp += 1
                if n_gt_sample > 0 and cum_fp / len(sample) <= op_fppi:
                    recall = cum_tp / n_gt_sample
            rows.append(
                {
                    "input": s,
                    "score_threshold": thr,
                    "ap_hard": voc_ap(scores, tps, n_gt_sample),
                    "recall_at_op_fppi": recall,
                }
            )
    elapsed = time.time() - t0
    notes = (
        f"sweep run: {len(sample)} of {len(vals)} val images (stride "
        f"{stride}, nearest stride-integer approximation of the "
        f"{SWEEP_TARGET}-image target) in {elapsed:.1f}s; decoders run at "
        f"the lowest sweep threshold {min(SWEEP_THRESHOLDS)} and rows "
        f"post-filter scores; recall_at_op_fppi uses this sample's "
        f"operating-point FPPI {op_fppi:.4f} (640/0.6 row); ap_hard and "
        "recall use all valid val GT faces (hard band)."
    )
    return rows, notes


def _gen_anchors() -> np.ndarray:
    anchors = []
    for cells, per in ((16, 2), (8, 6)):
        for r in range(cells):
            for c in range(cells):
                for _ in range(per):
                    anchors.append(((c + 0.5) / cells, (r + 0.5) / cells))
    return np.array(anchors, np.float32)


class BlazeRescue:
    """Single-face rescue mirroring the shipped Rust decode: bottom-right
    square pad, 128x128 input, sigmoid scores over 16x16x2 + 8x8x6 = 896
    anchors, argmax anchor, box restored in original image coords and
    clipped."""

    def __init__(self, model_path: Path):
        self.sess = ort.InferenceSession(
            str(model_path), providers=["CPUExecutionProvider"]
        )
        self.input_name = self.sess.get_inputs()[0].name
        self.anchors = _gen_anchors()

    def detect(self, bgr, thr: float = 0.5) -> list[float] | None:
        h, w = bgr.shape[:2]
        side = max(h, w)
        pad = np.zeros((side, side, 3), np.uint8)
        pad[:h, :w] = bgr
        rgb = cv2.cvtColor(cv2.resize(pad, (128, 128)), cv2.COLOR_BGR2RGB)
        x = (rgb.astype(np.float32) - 127.5) / 127.5
        reg, cls = self.sess.run(None, {self.input_name: x[None]})
        scores = 1.0 / (1.0 + np.exp(-np.clip(cls[0, :, 0], -100, 100)))
        i = int(np.argmax(scores))
        if scores[i] < thr:
            return None
        r = reg[0, i]
        ax, ay = self.anchors[i]
        cx, cy = ax + r[0] / 128.0, ay + r[1] / 128.0
        bw, bh = r[2] / 128.0, r[3] / 128.0
        x1 = float(np.clip((cx - bw / 2) * side, 0.0, float(w)))
        y1 = float(np.clip((cy - bh / 2) * side, 0.0, float(h)))
        x2 = float(np.clip((cx + bw / 2) * side, 0.0, float(w)))
        y2 = float(np.clip((cy + bh / 2) * side, 0.0, float(h)))
        return [x1, y1, x2, y2]


def _matched_count(preds, gt_boxes) -> int:
    return sum(1 for f in _match(preds, gt_boxes, IOU_THR) if f)


def _cascade_counts(
    wider_root: Path, split_dir: str, items, gt_all, det, blaze
) -> dict:
    yunet_matched = cascade_matched = n_gt = 0
    yunet_empty = rescue_boxes = rescue_fired = 0
    t0 = time.time()
    for i, rel in enumerate(items, 1):
        boxes = [b for b in gt_all.get(rel, []) if not b["invalid"]]
        n_gt += len(boxes)
        img = _load_img(wider_root, split_dir, rel)
        if img is not None:
            preds = detect_letterbox(det, img, OP_INPUT)
            ym = _matched_count(preds, boxes)
            yunet_matched += ym
            if preds:
                cascade_matched += ym
            else:
                yunet_empty += 1
                rescue_fired += 1
                box = blaze.detect(img)
                if box is not None:
                    rescue_boxes += 1
                    cascade_matched += _matched_count([(1.0, box)], boxes)
        _read_progress(i, len(items), f"cascade-{split_dir}")
    return {
        "yunet_recall": yunet_matched / n_gt if n_gt else 0.0,
        "cascade_recall": cascade_matched / n_gt if n_gt else 0.0,
        "rescues": cascade_matched - yunet_matched,
        "n_gt": n_gt,
        "images": len(items),
        "yunet_empty_images": yunet_empty,
        "rescue_fired": rescue_fired,
        "rescue_boxes": rescue_boxes,
        "elapsed_s": round(time.time() - t0, 1),
    }


def run_cascade(args) -> dict:
    val_list = sorted(val_image_list(args.wider_root))
    train_list_all = sorted(
        gt_image_list(
            args.wider_root
            / "wider_face_split"
            / "wider_face_train_bbx_gt.txt"
        )
    )
    train_list, train_stride = stride_sample(
        train_list_all, CASCADE_TRAIN_TARGET
    )
    gt_val = parse_val_gt(
        args.wider_root / "wider_face_split" / "wider_face_val_bbx_gt.txt"
    )
    gt_train = parse_val_gt(
        args.wider_root / "wider_face_split" / "wider_face_train_bbx_gt.txt"
    )
    det = yunet_detector(args.models_dir / YUNET_MODEL, OP_INPUT, OP_SCORE)
    blaze = BlazeRescue(args.models_dir / BLAZE_MODEL)
    val_counts = _cascade_counts(
        args.wider_root, "WIDER_val", val_list, gt_val, det, blaze
    )
    train_counts = _cascade_counts(
        args.wider_root, "WIDER_train", train_list, gt_train, det, blaze
    )
    train_counts["stride"] = train_stride
    section = {"val": val_counts, "train_sample": train_counts}
    notes = (
        "cascade run: YuNet at the operating point, BlazeFace short-range "
        "rescue only on YuNet-empty images (rescue score 0.5, shipped "
        "anchor decode); recall is valid-GT faces matched at IoU 0.5; "
        f"train sample is {len(train_list)} of {len(train_list_all)} train "
        f"images at stride {train_stride}."
    )
    return section, notes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--wider-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--smoke", action="store_true")
    mode.add_argument("--ap", action="store_true")
    mode.add_argument("--sweep", action="store_true")
    mode.add_argument("--cascade", action="store_true")
    ap.add_argument("--n", type=int, default=32, help="smoke image count")
    args = ap.parse_args(argv)

    result: dict = {}
    if args.out.exists():
        try:
            result = json.loads(args.out.read_text())
        except json.JSONDecodeError:
            result = {}
    notes = list(result.get("notes", []))
    runtime = {
        "ort_version": ort.__version__,
        "providers": ort.get_available_providers(),
        "cv2_version": cv2.__version__,
    }

    if args.smoke or not (
        args.ap or args.sweep or args.cascade
    ):
        det = cv2.FaceDetectorYN_create(
            str(args.models_dir / "face_detection_yunet_2023mar.onnx"),
            "",
            (320, 240),
            score_threshold=0.6,
        )
        vals = val_image_list(args.wider_root)
        images = vals[: args.n] if args.smoke else vals
        per_image = []
        for rel in images:
            img = cv2.imread(str(args.wider_root / "WIDER_val" / "images" / rel))
            if img is None:
                per_image.append({"file": rel, "n_faces": -1, "max_score": 0.0})
                continue
            h, w = img.shape[:2]
            det.setInputSize((w, h))
            ret, faces = det.detect(img)
            if faces is None:
                n, mx = 0, 0.0
            else:
                n = int(faces.shape[0])
                mx = float(faces[:, 14].max())
            per_image.append({"file": rel, "n_faces": n, "max_score": round(mx, 4)})

        ok = [p for p in per_image if p["n_faces"] >= 0]
        result = {
            "runtime": runtime,
            "protocol": {
                "smoke": bool(args.smoke),
                "n": len(images),
                "source": "wider_face val, first N images of the sorted bbox ground truth",
            },
            "per_image": per_image,
            "summary": {
                "images": len(ok),
                "total_faces": sum(p["n_faces"] for p in ok),
                "images_with_zero_faces": sum(1 for p in ok if p["n_faces"] == 0),
            },
        }
        args.out.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result["summary"]))
        return 0

    result["runtime"] = runtime
    result["operating_point"] = {"input": OP_INPUT, "score_threshold": OP_SCORE}
    if args.ap:
        section, new_notes = run_ap(args)
        result["ap"] = section
    elif args.sweep:
        section, new_notes = run_sweep(args)
        result["sweep"] = section
    else:
        section, new_notes = run_cascade(args)
        result["cascade"] = section
    notes.extend(new_notes if isinstance(new_notes, list) else [new_notes])
    result["notes"] = notes
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(section))
    return 0


if __name__ == "__main__":
    sys.exit(main())
