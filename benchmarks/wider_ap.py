#!/usr/bin/env python3
"""Official-protocol WIDER FACE AP evaluator for the calibration campaign.

Parses wider_face_val_bbx_gt.txt (relative image path line, face count line,
count x "x1,y1,w,h,blur,expression,illumination,invalid,occlusion,pose" box
lines, blank separator), treats invalid=1 boxes as IGNORE regions (never
matched as true positives, never counted in n_gt), and scores predictions
with PASCAL 2010 all-point interpolated AP.
"""

from pathlib import Path
from typing import Sequence


def parse_val_gt(path: Path) -> dict[str, list[dict]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    gt: dict[str, list[dict]] = {}
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i].strip()
        if not line.endswith(".jpg"):
            i += 1
            continue
        key = line
        i += 1
        count = int(lines[i].strip())
        i += 1
        boxes: list[dict] = []
        for _ in range(count):
            cols = [c.strip() for c in lines[i].split(",")]
            if len(cols) == 1:
                cols = lines[i].split()
            x1 = float(cols[0])
            y1 = float(cols[1])
            w = float(cols[2])
            h = float(cols[3])
            boxes.append(
                {"box": (x1, y1, x1 + w, y1 + h), "invalid": cols[7] == "1"}
            )
            i += 1
        gt[key] = boxes
    return gt


def iou(a: Sequence[float], b: Sequence[float]) -> float:
    ix1 = max(a[0], b[0])
    iy1 = max(a[1], b[1])
    ix2 = min(a[2], b[2])
    iy2 = min(a[3], b[3])
    iw = max(0.0, ix2 - ix1)
    ih = max(0.0, iy2 - iy1)
    inter = iw * ih
    area_a = max(0.0, a[2] - a[0]) * max(0.0, a[3] - a[1])
    area_b = max(0.0, b[2] - b[0]) * max(0.0, b[3] - b[1])
    union = area_a + area_b - inter
    if union <= 0.0:
        return 0.0
    return inter / union


def _match(
    preds: list[tuple[float, list[float]]], gt: list[dict], iou_thr: float
) -> list[bool]:
    order = sorted(range(len(preds)), key=lambda j: preds[j][0], reverse=True)
    matched = [False] * len(gt)
    flags: list[bool] = []
    for j in order:
        box = preds[j][1]
        best_iou = 0.0
        best_k = -1
        for k, g in enumerate(gt):
            if matched[k] or g["invalid"]:
                continue
            v = iou(box, g["box"])
            if v >= iou_thr and v > best_iou:
                best_iou = v
                best_k = k
        if best_k >= 0:
            matched[best_k] = True
            flags.append(True)
        else:
            flags.append(False)
    return flags


def evaluate_image(
    preds: list[tuple[float, list[float]]],
    gt: list[dict],
    iou_thr: float = 0.5,
) -> tuple[int, int, int]:
    flags = _match(preds, gt, iou_thr)
    tp = sum(1 for f in flags if f)
    n_gt = sum(1 for g in gt if not g["invalid"])
    return tp, len(flags) - tp, n_gt


def voc_ap(scores: list[float], tps: list[int], total_gt: int) -> float:
    if total_gt <= 0:
        return 0.0
    order = sorted(range(len(scores)), key=lambda j: scores[j], reverse=True)
    flags = [tps[j] for j in order]
    tp_cum = 0
    fp_cum = 0
    rec: list[float] = []
    prec: list[float] = []
    for f in flags:
        if f:
            tp_cum += 1
        else:
            fp_cum += 1
        rec.append(tp_cum / total_gt)
        prec.append(tp_cum / (tp_cum + fp_cum))
    mrec = [0.0] + rec + [1.0]
    mpre = [0.0] + prec + [0.0]
    for j in range(len(mpre) - 1, 0, -1):
        mpre[j - 1] = max(mpre[j - 1], mpre[j])
    ap = 0.0
    for j in range(1, len(mrec)):
        if mrec[j] != mrec[j - 1]:
            ap += (mrec[j] - mrec[j - 1]) * mpre[j]
    return ap


def evaluate(preds_by_image, gt_by_image) -> dict:
    tp = fp = n_gt = 0
    scored: list[tuple[float, int]] = []
    for key in sorted(set(preds_by_image) | set(gt_by_image)):
        preds = preds_by_image.get(key, [])
        gt = gt_by_image.get(key, [])
        order = sorted(
            range(len(preds)), key=lambda j: preds[j][0], reverse=True
        )
        flags = _match(preds, gt, 0.5)
        for j, is_tp in zip(order, flags):
            scored.append((preds[j][0], 1 if is_tp else 0))
        tp += sum(1 for f in flags if f)
        fp += sum(1 for f in flags if not f)
        n_gt += sum(1 for g in gt if not g["invalid"])
    scored.sort(key=lambda pair: pair[0], reverse=True)
    scores = [s for s, _ in scored]
    tps = [t for _, t in scored]
    return {"ap": voc_ap(scores, tps, n_gt), "tp": tp, "fp": fp, "n_gt": n_gt}


def _in_tier(g: dict, min_h: float, strict: bool) -> bool:
    h = g["box"][3] - g["box"][1]
    return h > min_h if strict else h >= min_h


def _discard_off_tier(preds, gt, tier_gt) -> list:
    """Official-approximation discard: each prediction is matched to its
    best-IoU GT among ALL valid boxes of the image; predictions whose
    best-overlap GT is not in the tier are dropped from evaluation entirely
    (neither tp nor fp, matching evaluation.m proposal_list=-1). A
    prediction with zero overlap against every valid GT has no best-overlap
    GT and is kept as an fp candidate. Invalid-flag boxes never take part
    in the best-overlap scan."""
    tier_ids = {id(g) for g in tier_gt}
    surviving = []
    for pred in preds:
        best_iou = 0.0
        best = None
        for g in gt:
            if g["invalid"]:
                continue
            v = iou(pred[1], g["box"])
            if v > best_iou:
                best_iou = v
                best = g
        if best is not None and id(best) not in tier_ids:
            continue
        surviving.append(pred)
    return surviving


def evaluate_tier(preds_by_image, gt_by_image, min_h: float, strict: bool) -> dict:
    """Evaluate one difficulty tier: only GT boxes inside the height cut
    (h > min_h when strict else h >= min_h) are matchable and counted in
    n_gt; off-tier predictions are discarded before matching."""
    tp = fp = n_gt = 0
    scored: list[tuple[float, int]] = []
    for key in sorted(set(preds_by_image) | set(gt_by_image)):
        preds = preds_by_image.get(key, [])
        gt = gt_by_image.get(key, [])
        tier_gt = [
            g for g in gt if not g["invalid"] and _in_tier(g, min_h, strict)
        ]
        surviving = _discard_off_tier(preds, gt, tier_gt)
        order = sorted(
            range(len(surviving)), key=lambda j: surviving[j][0], reverse=True
        )
        flags = _match(surviving, tier_gt, 0.5)
        for j, is_tp in zip(order, flags):
            scored.append((surviving[j][0], 1 if is_tp else 0))
        tp += sum(1 for f in flags if f)
        fp += sum(1 for f in flags if not f)
        n_gt += len(tier_gt)
    scored.sort(key=lambda pair: pair[0], reverse=True)
    scores = [s for s, _ in scored]
    tps = [t for _, t in scored]
    return {"ap": voc_ap(scores, tps, n_gt), "tp": tp, "fp": fp, "n_gt": n_gt}
