#!/usr/bin/env python3
"""RGB PAD replacement-candidate lane: Intel OMZ anti-spoof-mn3 (Apache-2.0,
trained on CelebA-Spoof) on the same committed mirrors and walks as the
shipped ViT lane (bench_pad_rgb.py), so the Phase 4 candidate table compares
identical protocols. Scoring: publisher preprocessing (raw bbox crop, resize
128x128, RGB, (x - mean) / scale, CHW); output softmax is already applied
(class 1 = spoof), never re-softmaxed (the 2026-07-17 pitfall). Score
semantics match the ViT lane: higher = more spoof-like, APCER/BPCER from
pad_score at the same threshold grid plus the author-demo 0.4 line."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

from bench_pad_rgb import (
    BATCH,
    OP_INPUT,
    OP_SCORE,
    YUNET_MODEL,
    best_face,
    scan_image_dirs,
    shard_split,
)
from pad_score import apcer_bpcer, median_vote, roc_auc, species_breakdown

MN3_MODEL = "anti-spoof-mn3.onnx"
MN3_SHA256 = "c4c99af04603b62d7e44f6f4daeb33e0daeccc696008c0b1d62f6f5cebbb3262"
AUTHOR_THRESHOLD = 0.4
SWEEP = (0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.7)
THRESHOLD = AUTHOR_THRESHOLD
MEAN = np.array([151.2405, 119.5950, 107.8395], dtype=np.float32)
SCALE = np.array([63.0105, 56.4570, 55.0035], dtype=np.float32)
PROGRESS_EVERY = 2000


def candidate_input(img: "np.ndarray", box: list[float]) -> "np.ndarray":
    x1, y1, x2, y2 = [int(v) for v in box]
    x1 = max(0, min(x1, img.shape[1] - 1))
    y1 = max(0, min(y1, img.shape[0] - 1))
    x2 = max(x1 + 1, min(x2, img.shape[1]))
    y2 = max(y1 + 1, min(y2, img.shape[0]))
    crop = img[y1:y2, x1:x2]
    if crop.size == 0:
        return np.zeros((1, 3, 128, 128), dtype=np.float32)
    chip = cv2.resize(crop, (128, 128), interpolation=cv2.INTER_LINEAR)
    rgb = cv2.cvtColor(chip, cv2.COLOR_BGR2RGB).astype(np.float32)
    rgb = (rgb - MEAN) / SCALE
    return np.transpose(rgb, (2, 0, 1))[np.newaxis]


class Mn3Scorer:
    def __init__(self, models_dir: Path):
        path = models_dir / MN3_MODEL
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != MN3_SHA256:
            raise SystemExit(
                f"error: {path} sha256 {digest} does not match the recorded "
                f"{MN3_SHA256}; aborting before any measurement"
            )
        print(f"mn3 artifact sha256 verified: {digest}", flush=True)
        providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]
        available = ort.get_available_providers()
        providers = [p for p in providers if p in available] or ["CPUExecutionProvider"]
        self.sess = ort.InferenceSession(str(models_dir / MN3_MODEL), providers=providers)
        self.input_name = self.sess.get_inputs()[0].name

    def score(self, tensor: "np.ndarray") -> float | None:
        out = self.sess.run(None, {self.input_name: tensor})[0][0]
        return float(out[1])


def threshold_sweep(scores_attack: list[float], scores_genuine: list[float]) -> list[dict]:
    rows = []
    for thr in SWEEP:
        m = apcer_bpcer(scores_attack, scores_genuine, thr)
        rows.append({"threshold": thr, **m})
    return rows


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
    result["candidate"] = {
        "model": MN3_MODEL,
        "sha256": MN3_SHA256,
        "publisher": "Intel OpenVINO OMZ",
        "license": "Apache-2.0",
        "trained_on": "CelebA-Spoof",
        "author_threshold": AUTHOR_THRESHOLD,
        "preprocessing": (
            "publisher OMZ README + author demo: raw detection bbox crop, "
            "resize 128x128, RGB, (x - mean) / scale, CHW; softmax baked in, "
            "class 1 = spoof"
        ),
    }
    result[key] = section
    result["notes"] = list(result.get("notes", [])) + notes
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in section.items() if k not in ("per_split", "per_video")}, default=str))
    print(f"merged {key} into {args.out}", flush=True)


def run_casia(args, det, mn3) -> None:
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
                s = mn3.score(candidate_input(img, box))
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
                "images": sum(counts.get((split, cl), [0])[0] for cl in ("live", "spoof")),
                "detected": sum(counts.get((split, cl), [0, 0, 0])[2] for cl in ("live", "spoof")),
                **eval_pairs(by_cond.get((split, "spoof"), []), by_cond.get((split, "live"), [])),
            }
            for split in ("train", "test")
        },
        "wall_s": round(time.time() - t0, 1),
    }
    notes = [
        (
            "casia_fasd: identical walk and labels as the ViT lane "
            "(bench_pad_rgb.run_casia); differences are the scorer and the "
            "crop (publisher raw-bbox 128x128 instead of the m96 warp); "
            "headline metrics at the author-demo 0.4 line."
        ),
    ]
    merge_section(args, "casia_fasd", section, notes)


def run_oulu(args, det, mn3) -> None:
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
            s = mn3.score(candidate_input(img, box))
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
            "oulu_npu: identical walk, clip grouping, and median vote as the "
            "ViT lane (bench_pad_rgb.run_oulu); mirror-limited test subset, "
            "median-of-1 disclosure applies unchanged."
        ),
    ]
    merge_section(args, "oulu_npu", section, notes)


def run_celeba_score(args, mn3) -> None:
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
                            s = mn3.score(candidate_input(img, bbox))
                if s is None:
                    n_no_bbox += 1
                else:
                    scores.append([shard_split(shard.name), label, round(s, 6)])
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
    total_rows = total_no_bbox = 0
    for done in sorted(prog.glob("shard-*-done.json")):
        st = json.loads(done.read_text())
        split = shard_split(st["shard"])
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
            "celeba_spoof: identical parquet walk, bbox convention "
            "([x1, y1, x2, y2] pinned in the ViT lane), split-from-shard-name, "
            "and skip accounting as bench_pad_rgb.run_celeba_score; the "
            "provided bbox feeds the publisher raw-bbox crop (no YuNet on "
            "this set), so detected counts rows scored through the box."
        ),
        (
            "candidate caveat: mn3 is CelebA-Spoof-trained, so this set is "
            "its training distribution; the row quantifies home-domain "
            "strength, not generalization. The deployment-side verdict "
            "lives in docs/pad-results/2026-07-17-third-party-pad-candidates.md."
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
    ap.add_argument("--progress-dir", type=Path)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--set", choices=["casia", "oulu", "celeba_score", "celeba_agg"])
    args = ap.parse_args(argv)
    if args.set == "celeba_score":
        if not args.celeba_root or not args.progress_dir:
            raise SystemExit("error: --set celeba_score needs --celeba-root and --progress-dir")
        run_celeba_score(args, Mn3Scorer(args.models_dir))
        return 0
    if args.set == "celeba_agg":
        if not args.progress_dir:
            raise SystemExit("error: --set celeba_agg needs --progress-dir")
        run_celeba_agg(args)
        return 0
    det = cv2.FaceDetectorYN_create(
        str(args.models_dir / YUNET_MODEL),
        "",
        (OP_INPUT, OP_INPUT),
        score_threshold=OP_SCORE,
    )
    mn3 = Mn3Scorer(args.models_dir)
    if args.set == "casia":
        if not args.casia_root:
            raise SystemExit("error: --set casia needs --casia-root")
        run_casia(args, det, mn3)
    else:
        if not args.oulu_root:
            raise SystemExit("error: --set oulu needs --oulu-root")
        run_oulu(args, det, mn3)
    return 0


if __name__ == "__main__":
    sys.exit(main())
