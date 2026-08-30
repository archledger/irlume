#!/usr/bin/env python3
"""RGB PAD lane for the calibration campaign: CASIA-FASD, OULU-NPU,
CelebA-Spoof through the shipped ViT chain.

Chain mirrors the shipped chain's preprocessing conventions
(irlume-vision/src/lib.rs
1316-1401 PadVit / pad_vit_input; crates/irlume-auth/src/lib.rs:350
VIT_PAD_THRESHOLD = 0.55, :356 VIT_PAD_VOTE_N = 5): face box -> expand by
96/112 of w/h per side CLAMPED to the frame (no fill) -> bilinear resize
224 -> RGB, (px/255 - 0.5)/0.5, CHW -> two logits -> P(spoof) = softmax
index 1 (id2label: 0 = real, 1 = spoof). Score semantics are pad_score.py:
s = P(spoof); APCER = attack frames with s < threshold; BPCER = genuine
frames with s >= threshold.

Detection:
  CASIA-FASD, OULU-NPU: shipped YuNet at the operating point (640 square
  letterbox, score 0.6), best detection = highest score (score column 14),
  same decode as bench_detection_wider.py --ap.
  CelebA-Spoof: the mirror's Bbox column supplies the face box directly.
  Pinned convention, verified 2026-08-29 on shard test-00000 against YuNet
  at score 0.5: Bbox = [x1, y1, x2, y2] (mean IoU 0.877; the [x, y, w, h]
  reading is rejected: mean IoU 0.263 and x+w exceeds the frame width in
  every probed row).

Dataset label pins (verified 2026-08-29 on archhost):
  CelebA-Spoof (Ar4ikov/celebA_spoof parquet whale): 167 shards, 525,864
  rows. Class column carries exactly {"live": 177262, "spoof": 348602}
  (full-column scan); the 10 attack species of the original dataset are NOT
  labeled in this mirror, so per_species covers the labeled species only.
  No split column: the split comes from the shard FILENAME prefix
  (train-* / valid-* / test-*). Headline metrics use the test shards.
  CASIA-FASD: frame-extracted mirror, 123,533 frames under train/test x
  live/spoof directories; label from the directory. Frame-level scoring
  only (the video structure is not in the mirror, so no voting is
  possible). Headline metrics use the test split.
  OULU-NPU: mirror-limited test subset, 1,701 flat frames under true/
  (genuine) and false/ (attack). Filename pattern
  <subject>_<env>_<clip>_<frame>_<const>: grouping by the first three
  underscore fields yields 703 label-scoped clips (numeric clip ids are
  shared across the two classes, so clips are grouped WITHIN each label):
  343 genuine clips with EXACTLY ONE frame each, 360 attack clips with
  2-4 frames (CONTROLLER RULING: scored honestly as mirror-limited;
  subjects 1-6 of 55 only). Per-clip vote = median of the clip's
  available frame scores; genuine voting is impossible on this mirror
  (median-of-1). Frames scored at stride 1.

Resumability (CelebA-Spoof): per-shard result files under --progress-dir
(.pad_progress/): shard-<idx>-done.json when complete, shard-<idx>-
partial.json overwritten every 1000 rows, progress.jsonl appended per
1000-row boundary. A re-run skips completed shards and resumes partials
from the recorded row offset.

Usage (archhost, sequential runs merge into one results JSON):
  bench_pad_rgb.py --models-dir M --casia-root D --set casia --out R
  bench_pad_rgb.py --models-dir M --oulu-root D --set oulu --out R
  bench_pad_rgb.py --models-dir M --celeba-root D --set celeba_score --out R
  bench_pad_rgb.py --models-dir M --celeba-root D --set celeba_agg --out R
"""

import argparse
import json
import sys
import time
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

from letterbox import letterbox_image, restore_boxes
from pad_score import apcer_bpcer, median_vote, roc_auc, species_breakdown

OP_INPUT = 640
OP_SCORE = 0.6
YUNET_MODEL = "face_detection_yunet_2023mar.onnx"
VIT_MODEL = "liveness_vit.onnx"
MARGIN = 96.0 / 112.0
VIT_SIZE = 224
THRESHOLD = 0.55
VOTE_WINDOW = 5
SWEEP = (0.35, 0.45, 0.5, 0.55, 0.6, 0.7)
PROGRESS_EVERY = 1000
BATCH = 256
CLASSES = ("live", "spoof")
SPLITS = ("train", "valid", "test")


def threshold_sweep(scores_attack, scores_genuine) -> list[dict]:
    rows = []
    for thr in SWEEP:
        r = apcer_bpcer(scores_attack, scores_genuine, thr)
        rows.append({"threshold": thr, **r})
    return rows


class VitScorer:
    """The shipped ViT PAD chain: m96 crop, resize 224, RGB, /255 mean 0.5
    std 0.5, CHW, P(spoof) = softmax index 1."""

    def __init__(self, models_dir: Path):
        providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]
        available = ort.get_available_providers()
        providers = [p for p in providers if p in available] or ["CPUExecutionProvider"]
        self.sess = ort.InferenceSession(str(models_dir / VIT_MODEL), providers=providers)
        self.input_name = self.sess.get_inputs()[0].name

    def m96_crop(self, img: "np.ndarray", bbox) -> "np.ndarray":
        """Expand the box by MARGIN per side, clamp to the frame (no fill),
        crop. bbox is [x1, y1, x2, y2] in frame pixels."""
        h, w = img.shape[:2]
        bw = float(bbox[2]) - float(bbox[0])
        bh = float(bbox[3]) - float(bbox[1])
        x1 = max(0.0, float(bbox[0]) - bw * MARGIN)
        y1 = max(0.0, float(bbox[1]) - bh * MARGIN)
        x2 = min(float(w - 1), float(bbox[2]) + bw * MARGIN)
        y2 = min(float(h - 1), float(bbox[3]) + bh * MARGIN)
        xi1, yi1 = int(x1), int(y1)
        xi2, yi2 = min(w, int(x2) + 1), min(h, int(y2) + 1)
        return img[max(0, yi1):max(0, yi2), max(0, xi1):max(0, xi2)]

    def score(self, chip_bgr: "np.ndarray") -> float | None:
        if chip_bgr is None or chip_bgr.size == 0:
            return None
        rgb = cv2.cvtColor(chip_bgr, cv2.COLOR_BGR2RGB)
        rgb = cv2.resize(rgb, (VIT_SIZE, VIT_SIZE), interpolation=cv2.INTER_LINEAR)
        x = rgb.astype(np.float32) / 255.0
        x = (x - 0.5) / 0.5
        t = x.transpose(2, 0, 1)[np.newaxis]
        logits = self.sess.run(None, {self.input_name: t})[0][0]
        e = np.exp(logits - logits.max())
        return float((e / e.sum())[1])  # id2label: 0 = real, 1 = spoof


def best_face(det, img: "np.ndarray") -> list[float] | None:
    """YuNet at the 640 letterbox operating point; returns the best
    detection's [x1, y1, x2, y2] in original pixels, or None."""
    canvas, params = letterbox_image(img, OP_INPUT)
    _, faces = det.detect(canvas)
    if faces is None or len(faces) == 0:
        return None
    h, w = img.shape[:2]
    best_idx = int(np.argmax(faces[:, 14]))
    f = faces[best_idx]
    return restore_boxes(
        [[float(f[0]), float(f[1]), float(f[0] + f[2]), float(f[1] + f[3])]],
        params, w, h,
    )[0]


def eval_pairs(scores_attack: list[float], scores_genuine: list[float]) -> dict:
    out: dict = {"apcer": None, "bpcer": None, "auc": None}
    if scores_attack and scores_genuine:
        out.update(apcer_bpcer(scores_attack, scores_genuine, THRESHOLD))
        out["auc"] = roc_auc(scores_attack, scores_genuine)
        out["threshold_sweep"] = threshold_sweep(scores_attack, scores_genuine)
    return out


def merge_section(args, key: str, section: dict, notes: list[str]) -> None:
    result = {}
    if args.out.exists():
        try:
            result = json.loads(args.out.read_text())
        except json.JSONDecodeError:
            print(f"warning: {args.out} is not valid JSON, resetting", flush=True)
            result = {}
    result["runtime"] = {
        "ort_version": ort.__version__,
        "providers": ort.get_available_providers(),
        "cv2_version": cv2.__version__,
    }
    result["wired"] = {
        "vit_threshold": THRESHOLD,
        "vote_window": VOTE_WINDOW,
        "rationale": (
            "irlume-auth/src/lib.rs:339-356: 0.55 with 5-frame-median "
            "voting is the measured operating point; 0.50 and 0.60 are "
            "the documented rejected alternatives"
        ),
    }
    result[key] = section
    result["notes"] = list(result.get("notes", [])) + notes
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in section.items() if k != "per_video"}, default=str))
    print(f"merged {key} into {args.out}", flush=True)


def scan_image_dirs(root: Path) -> list[tuple[Path, str, str]]:
    """Sorted (path, split, cls) for <split>/<cls>/* image dirs."""
    exts = {".jpg", ".jpeg", ".png", ".bmp"}
    out = []
    for split in sorted(p for p in root.iterdir() if p.is_dir()):
        for cls in sorted(p for p in split.iterdir() if p.is_dir()):
            for f in sorted(cls.iterdir()):
                if f.suffix.lower() in exts:
                    out.append((f, split.name, cls.name))
    return out


def run_casia(args, det, vit) -> None:
    t0 = time.time()
    items = scan_image_dirs(args.casia_root)
    by_cond: dict[tuple[str, str], list[float]] = {}
    counts: dict[tuple[str, str], list[int]] = {}
    for i, (fp, split, cls) in enumerate(items, 1):
        img = cv2.imread(str(fp), cv2.IMREAD_COLOR)
        scored = detected = 0
        if img is not None:
            scored = 1
            box = best_face(det, img)
            if box is not None:
                s = vit.score(vit.m96_crop(img, box))
                if s is not None:
                    detected = 1
                    by_cond.setdefault((split, cls), []).append(s)
        c = counts.setdefault((split, cls), [0, 0, 0])
        c[0] += 1
        c[1] += scored
        c[2] += detected
        if i % 500 == 0:
            print(f"[casia] {i}/{len(items)} frames", flush=True)
    att = by_cond.get(("test", "spoof"), [])
    gen = by_cond.get(("test", "live"), [])
    section = {
        "images": sum(c[0] for c in counts.values()),
        "scored": sum(c[1] for c in counts.values()),
        "detected": sum(c[2] for c in counts.values()),
        **eval_pairs(att, gen),
        "per_split": {
            split: {
                "images": sum(counts.get((split, cl), [0])[0] for cl in CLASSES),
                "detected": sum(counts.get((split, cl), [0, 0, 0])[2] for cl in CLASSES),
                **eval_pairs(by_cond.get((split, "spoof"), []), by_cond.get((split, "live"), [])),
            }
            for split in ("train", "test")
        },
        "per_condition": {
            f"{split}_{cls}": {
                "images": counts[split, cls][0],
                "detected": counts[split, cls][2],
                "n_scores": len(by_cond.get((split, cls), [])),
            }
            for split in ("train", "test") for cls in CLASSES
            if (split, cls) in counts
        },
        "wall_s": round(time.time() - t0, 1),
    }
    notes = [
        (
            "casia_fasd: frame-extracted mirror (123,533 frame images under "
            "train/test x live/spoof directories; the original 550-video "
            "structure is not in this mirror), so scoring is FRAME-LEVEL "
            "with no vote; label from the directory (live = genuine, spoof "
            "= attack); headline apcer/bpcer/auc use the test split, "
            "per_split carries both; frames without a YuNet detection at "
            "the operating point are excluded from the metrics and counted "
            "in detected/images."
        ),
        (
            f"casia wall time {section['wall_s']}s at the operating point "
            f"(YuNet letterbox {OP_INPUT} score {OP_SCORE}, ViT 224 m96)."
        ),
    ]
    merge_section(args, "casia_fasd", section, notes)


def run_oulu(args, det, vit) -> None:
    t0 = time.time()
    clips: dict[str, dict[str, float]] = {}
    frames: dict[str, list[float]] = {"attack": [], "genuine": []}
    per_video = []
    n_images = n_scored = n_detected = 0
    for cls_dir, label in (("true", "genuine"), ("false", "attack")):
        files = sorted((args.oulu_root / cls_dir).glob("*.jpg"))
        by_clip: dict[str, list[float]] = {}
        for fp in files:
            n_images += 1
            img = cv2.imread(str(fp), cv2.IMREAD_COLOR)
            if img is None:
                continue
            n_scored += 1
            box = best_face(det, img)
            if box is None:
                continue
            s = vit.score(vit.m96_crop(img, box))
            if s is None:
                continue
            n_detected += 1
            clip = "_".join(fp.stem.split("_")[:3])
            by_clip.setdefault(clip, []).append(s)
            frames[label].append(s)
        for clip, ss in sorted(by_clip.items()):
            vote = float(median_vote(ss))
            clips.setdefault(label, {})[clip] = vote
            per_video.append(
                {"clip": clip, "cls": label, "n_frames": len(ss), "vote": round(vote, 6)}
            )
    vote_att = list(clips.get("attack", {}).values())
    vote_gen = list(clips.get("genuine", {}).values())
    section = {
        "clips": sum(len(v) for v in clips.values()),
        "images": n_images,
        "scored": n_scored,
        "detected": n_detected,
        "voted": eval_pairs(vote_att, vote_gen),
        "frame_level": eval_pairs(frames["attack"], frames["genuine"]),
        "per_video": per_video,
        "wall_s": round(time.time() - t0, 1),
    }
    notes = [
        (
            "oulu_npu: MIRROR-LIMITED test subset (CONTROLLER RULING: "
            "scored honestly as such): 1,701 flat frames; the genuine "
            "side (true/) is 343 clips with EXACTLY ONE frame each, so "
            "genuine voting is impossible there (median-of-1); the "
            "attack side (false/) is 360 clips with 2-4 frames (298 x 4, "
            "42 x 3, 20 x 2); subjects 1-6 of the protocol 55; the "
            "primary source is test-subset-only and the deeper fallback "
            "mirror was dead (404), so session breadth is NOT covered."
        ),
        (
            "oulu filename pattern <subject>_<env>_<clip>_<frame>_<const>: "
            "video grouping derives from the first three underscore fields"
            "; numeric clip ids are shared across the two classes (343 of "
            "360 attack ids also occur as a genuine id), so clips are "
            "grouped WITHIN each label: 703 label-scoped clips over 360 "
            "unique ids. Per-clip vote = median of the clip available "
            "frame scores; every clip has at most 5 frames, so "
            "median-of-available equals the shipped median-of-last-5 (the "
            "runtime itself abstains on fewer than 5 scores, which on "
            "this mirror means a genuine presentation would abstain "
            "rather than vote). Frames scored at stride 1."
        ),
        (
            f"oulu wall time {section['wall_s']}s at the operating point "
            f"(YuNet letterbox {OP_INPUT} score {OP_SCORE}, ViT 224 m96)."
        ),
    ]
    merge_section(args, "oulu_npu", section, notes)


def shard_split(name: str) -> str:
    for s in SPLITS:
        if name.startswith(s + "-"):
            return s
    return "unknown"


def run_celeba_score(args, vit) -> None:
    import pyarrow.parquet as pq

    shards = sorted((args.celeba_root / "data").glob("*.parquet"))
    prog = args.progress_dir
    prog.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    for idx, shard in enumerate(shards):
        done = prog / f"shard-{idx}-done.json"
        if done.exists():
            continue
        pf = pq.ParquetFile(shard)
        partial_path = prog / f"shard-{idx}-partial.json"
        offset = 0
        scores: list[list] = []
        n_no_bbox = 0
        if partial_path.exists():
            st = json.loads(partial_path.read_text())
            offset = st["rows_done"]
            scores = st["scores"]
            n_no_bbox = st["n_no_bbox"]
        rows_done = offset
        last_mark = offset // PROGRESS_EVERY
        t_shard = time.time()
        batches = pf.iter_batches(batch_size=BATCH, columns=["Filepath", "Bbox", "Class"])
        for batch in batches:
            fps = batch.column(0)
            bbs = batch.column(1)
            cls = batch.column(2).to_pylist()
            for j in range(batch.num_rows):
                rows_done += 1
                if rows_done <= offset:
                    continue
                bbox = bbs[j].as_py()
                label = 1 if cls[j] == "spoof" else 0
                s = None
                if (
                    bbox is not None
                    and len(bbox) == 4
                    and all(v is not None for v in bbox)
                    and bbox[2] > bbox[0]
                    and bbox[3] > bbox[1]
                ):
                    raw = fps[j]["bytes"].as_py()
                    img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
                    if img is not None:
                        h, w = img.shape[:2]
                        in_frame = bbox[0] < w - 1 and bbox[1] < h - 1 and bbox[2] > 0 and bbox[3] > 0
                        if in_frame:
                            s = vit.score(vit.m96_crop(img, bbox))
                if s is None:
                    n_no_bbox += 1
                else:
                    scores.append([shard_split(shard.name), label, round(s, 6)])
            if rows_done // PROGRESS_EVERY > last_mark:
                last_mark = rows_done // PROGRESS_EVERY
                partial_path.write_text(
                    json.dumps(
                        {
                            "shard": shard.name,
                            "rows_done": rows_done,
                            "n_no_bbox": n_no_bbox,
                            "scores": scores,
                        }
                    )
                )
                with (prog / "progress.jsonl").open("a") as fh:
                    fh.write(
                        json.dumps(
                            {
                                "shard_idx": idx,
                                "rows_done": rows_done,
                                "elapsed_s": round(time.time() - t0, 1),
                            }
                        )
                        + "\n"
                    )
                print(
                    f"[celeba {idx}/{len(shards)}] {rows_done}/{pf.metadata.num_rows} rows",
                    flush=True,
                )
        done.write_text(
            json.dumps(
                {
                    "shard": shard.name,
                    "rows": pf.metadata.num_rows,
                    "n_no_bbox": n_no_bbox,
                    "scores": scores,
                }
            )
        )
        partial_path.unlink(missing_ok=True)
        print(
            f"[celeba] shard {idx} done: {len(scores)} scored, {n_no_bbox} "
            f"skipped, {time.time() - t_shard:.1f}s",
            flush=True,
        )
    print(f"[celeba] all shards scored in {time.time() - t0:.1f}s", flush=True)


def run_celeba_agg(args) -> None:
    prog = args.progress_dir
    per_split_scores: dict[str, dict[int, list[float]]] = {}
    per_split_skips: dict[str, dict[str, int]] = {}
    total_rows = total_no_bbox = 0
    for done in sorted(prog.glob("shard-*-done.json")):
        st = json.loads(done.read_text())
        split = shard_split(st["shard"])
        per_split_skips.setdefault(split, {"no_bbox": 0})
        per_split_skips[split]["no_bbox"] += st["n_no_bbox"]
        total_rows += st["rows"]
        total_no_bbox += st["n_no_bbox"]
        for split_code, label, s in st["scores"]:
            d = per_split_scores.setdefault(split, {0: [], 1: []})
            d[label].append(s)
    att = per_split_scores.get("test", {}).get(1, [])
    gen = per_split_scores.get("test", {}).get(0, [])
    section = {
        "images": total_rows,
        "scored": sum(len(v) for d in per_split_scores.values() for v in d.values()),
        "detected": sum(len(v) for d in per_split_scores.values() for v in d.values()),
        **eval_pairs(att, gen),
        "per_species": species_breakdown([("spoof", s) for s in att], THRESHOLD),
        "per_split": {
            split: {
                "scored": sum(len(v) for v in d.values()),
                **eval_pairs(d.get(1, []), d.get(0, [])),
            }
            for split, d in sorted(per_split_scores.items())
        },
        "skipped_no_usable_bbox": total_no_bbox,
    }
    notes = [
        (
            "celeba_spoof: parquet whale mirror (167 shards, 525,864 rows "
            "scanned; NO split column, the split comes from the shard "
            "FILENAME prefix train-*/valid-*/test-*); Class column carries "
            "exactly live/spoof (full-column scan: 177,262 live, 348,602 "
            "spoof), so the original dataset's 10 attack species are NOT "
            "labeled in this mirror: per_species covers the labeled attack "
            "species only (one spoof row). The phone-at-distance attack "
            "gap is NOT separately labeled in CelebA-Spoof."
        ),
        (
            "celeba_spoof: Bbox convention pinned empirically on shard "
            "test-00000 (YuNet cross-check at score 0.5): Bbox = [x1, y1, "
            "x2, y2], mean IoU 0.877; the [x, y, w, h] reading is rejected "
            "(mean IoU 0.263, boxes out of frame). The provided bbox feeds "
            "the m96 crop directly; NO YuNet detection on this set, so "
            "detected counts rows scored through the provided box. Rows "
            "without a usable bbox are skipped and counted in "
            "skipped_no_usable_bbox. Headline metrics use the test shards; "
            "per_split carries train/valid too."
        ),
    ]
    merge_section(args, "celeba_spoof", section, notes)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--casia-root", type=Path)
    ap.add_argument("--oulu-root", type=Path)
    ap.add_argument("--celeba-root", type=Path)
    ap.add_argument(
        "--progress-dir", type=Path, default=Path.home() / "irlume-bench/benchmarks/.pad_progress"
    )
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--set", choices=["casia", "oulu", "celeba_score", "celeba_agg"])
    args = ap.parse_args(argv)

    det = None
    if args.set in ("casia", "oulu"):
        det = cv2.FaceDetectorYN_create(
            str(args.models_dir / YUNET_MODEL), "", (OP_INPUT, OP_INPUT), score_threshold=OP_SCORE
        )
    vit = VitScorer(args.models_dir)
    if args.set == "casia":
        run_casia(args, det, vit)
    elif args.set == "oulu":
        run_oulu(args, det, vit)
    elif args.set == "celeba_score":
        run_celeba_score(args, vit)
    else:
        run_celeba_agg(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
