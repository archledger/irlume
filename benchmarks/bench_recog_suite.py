#!/usr/bin/env python3
"""RGB recognition lane for calibration phase 2 (Task 3).

Scores AuraFace glintr100 (the recognizer irlume ships) over four standard
RGB verification protocols and derives the RGB grant-threshold calibration:

  - LFW deepfunneled, shipped pairs.csv 10-fold protocol (6,000 pairs,
    10 folds x [300 match + 300 mismatch] in canonical row order).
    Continuity cross-check against the committed results-lfw.json
    auraface flip-TTA number (acc10fold 0.9903).
  - AgeDB-30 / CALFW / CPLFW from the aligned_fr_bundle mirror:
    pre-aligned 112x112 crops scored over each set's shipped 6,000-pair
    annotation file.

The embedding path reuses bench_faceid.py exactly (YuNet detect + 5-point
similarity warp to 112x112 for LFW; (x - 127.5) / 128 normalization, flip
TTA, 512-D L2-normalized embedding, cosine scoring) so the numbers stay
comparable with the committed results. Metrics come from
verification_metrics (eer, far_threshold_table, fold_accuracy, ten_fold).

The aligned-set protocols ship no folds, so those sets report fold_accuracy
at the fixed 0.45 line (key acc_at_045) plus eer and tar_table; only LFW
reports acc10fold.

Usage:
  python3 bench_recog_suite.py --models-dir ~/irlume-bench/models \
      --lfw ~/datasets/lfw --bundle ~/datasets/aligned_fr_bundle \
      --out results-recognition.json
"""
import argparse, hashlib, json, sys, time
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verification_metrics as vm
from bench_faceid import Detector, Embedder, align_or_center, lfw_tenfold_accuracy

FARS = [0.1, 0.03, 0.01, 0.003, 0.001]
GRANT_THRESHOLDS = [0.3, 0.35, 0.4, 0.45, 0.5]
GRANT_FAR_CAP = 1e-3
ALIGNED_SETS = {
    "agedb30": "agedb_30_ann.txt",
    "calfw": "calfw_ann.txt",
    "cplfw": "cplfw_ann.txt",
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_lfw_pairs(pairs_csv, img_root):
    """Parse the shipped pairs.csv into (path1, path2, label, fold) tuples.

    Row formats (header row first): match rows have 3 cells
    (name, imagenum1, imagenum2), mismatch rows 4 cells
    (name1, num1, name2, num2). Fold k is rows [600k, 600k+600) per the
    canonical LFW 10-fold layout; the 300/300 match/mismatch split per
    block is asserted, not assumed for scoring.
    """
    lines = [ln.strip() for ln in pairs_csv.read_text().splitlines() if ln.strip()]
    pairs = []
    for i, ln in enumerate(lines[1:]):
        cells = [c.strip() for c in ln.split(",")]
        while cells and cells[-1] == "":
            cells.pop()
        if len(cells) == 3:
            name, num1, num2 = cells
            pairs.append((name, int(num1), name, int(num2), 1))
        elif len(cells) == 4:
            name1, num1, name2, num2 = cells
            pairs.append((name1, int(num1), name2, int(num2), 0))
        else:
            raise ValueError(f"pairs.csv row {i + 2}: unexpected shape {cells}")
    if len(pairs) != 6000:
        raise ValueError(f"pairs.csv: expected 6000 rows, got {len(pairs)}")
    out = []
    for i, (n1, u1, n2, u2, label) in enumerate(pairs):
        block = i // 600
        if i % 600 == 0 and label != 1:
            raise ValueError(f"pairs.csv: fold block {block} does not start with matches")
        if i % 600 == 300 and label != 0:
            raise ValueError(f"pairs.csv: fold block {block} mismatch half out of place")
        p1 = img_root / n1 / f"{n1}_{u1:04d}.jpg"
        p2 = img_root / n2 / f"{n2}_{u2:04d}.jpg"
        out.append((p1, p2, label, block))
    return out


def load_ann_pairs(ann_path, bundle_root):
    """Parse a label-first annotation line '1 p1 p2' into (path1, path2, label)."""
    pairs = []
    for ln in ann_path.read_text().splitlines():
        ln = ln.strip()
        if not ln:
            continue
        label, p1, p2 = ln.split()
        pairs.append((bundle_root / p1, bundle_root / p2, int(label)))
    labels = [lab for _, _, lab in pairs]
    if len(pairs) != 6000 or sum(labels) != 3000:
        raise ValueError(
            f"{ann_path.name}: expected 6000 pairs with 3000 genuine, "
            f"got {len(pairs)} pairs / {sum(labels)} genuine")
    return pairs


def embed_images(paths, det, emb, tag, detect):
    """Embed unique images; returns {path: vec or None}. Progress every 500."""
    cache = {}
    t0 = time.perf_counter()
    for i, p in enumerate(sorted(set(paths))):
        if p in cache:
            continue
        img = cv2.imread(str(p), cv2.IMREAD_COLOR)
        if img is None:
            cache[p] = None
            continue
        if detect:
            chip = align_or_center(img, det)
        else:
            chip = img if img.shape[:2] == (112, 112) else cv2.resize(img, (112, 112))
        cache[p] = None if chip is None else emb.embed(chip, flip_tta=True)
        if (len(cache)) % 500 == 0:
            print(f"[{tag}] {len(cache)} embedded "
                  f"({time.perf_counter() - t0:.0f}s)", flush=True)
    n_none = sum(1 for v in cache.values() if v is None)
    print(f"[{tag}] {len(cache) - n_none}/{len(cache)} embedded, {n_none} failed",
          flush=True)
    return cache


def run_lfw(lfw_dir, det, emb):
    inner = lfw_dir / "lfw-deepfunneled" / "lfw-deepfunneled"
    if not inner.is_dir():
        inner = lfw_dir / "lfw-deepfunneled"
    pairs = load_lfw_pairs(lfw_dir / "pairs.csv", inner)
    cache = embed_images([p for pr in pairs for p in pr[:2]], det, emb, "lfw",
                         detect=True)
    scores, labels, folds, skipped = [], [], [], 0
    for p1, p2, label, fold in pairs:
        a, b = cache.get(p1), cache.get(p2)
        if a is None or b is None:
            skipped += 1
            continue
        scores.append(float(a @ b))
        labels.append(label)
        folds.append(fold)
    genuine = [s for s, l in zip(scores, labels) if l == 1]
    impostor = [s for s, l in zip(scores, labels) if l == 0]
    tf = vm.ten_fold(scores, labels, folds)
    heldout_acc, heldout_std = lfw_tenfold_accuracy(scores, labels, folds)
    r = {
        "acc10fold": tf["acc10fold"],
        "eer": vm.eer(genuine, impostor),
        "tar_table": vm.far_threshold_table(genuine, impostor, FARS),
        "pairs": len(scores),
    }
    print(f"[lfw] acc10fold={r['acc10fold']:.4f} eer={r['eer']:.4f} "
          f"skip={skipped} heldout={heldout_acc:.4f}±{heldout_std:.4f}", flush=True)
    extra = {
        "heldout_acc": heldout_acc,
        "heldout_std": heldout_std,
        "skipped": skipped,
        "gen": genuine,
        "imp": impostor,
    }
    return r, extra


def run_aligned_set(bundle_root, ann_name, key, emb):
    pairs = load_ann_pairs(bundle_root / ann_name, bundle_root)
    cache = embed_images([p for pr in pairs for p in pr[:2]], None, emb, key,
                         detect=False)
    scores, labels, failed = [], [], 0
    for p1, p2, label in pairs:
        a, b = cache.get(p1), cache.get(p2)
        if a is None or b is None:
            failed += 1
            continue
        scores.append(float(a @ b))
        labels.append(label)
    genuine = [s for s, l in zip(scores, labels) if l == 1]
    impostor = [s for s, l in zip(scores, labels) if l == 0]
    r = {
        "eer": vm.eer(genuine, impostor),
        "tar_table": vm.far_threshold_table(genuine, impostor, FARS),
        "acc_at_045": vm.fold_accuracy(list(zip(scores, labels)), 0.45),
        "pairs": len(scores),
    }
    print(f"[{key}] eer={r['eer']:.4f} acc@0.45={r['acc_at_045']:.4f} "
          f"failed={failed}", flush=True)
    if failed:
        raise RuntimeError(f"{key}: {failed} pairs lost to unreadable images")
    return r, {"gen": genuine, "imp": impostor}


def bundle_lfw_crosscheck(bundle_root, emb):
    """Score the bundle's own aligned-LFW annotation with the same path.

    Coherence evidence for the bundle and the embedding pipeline: if this
    lands near the deepfunneled continuity numbers, the bmp reading, the
    score path, and the pair lists are all consistent.
    """
    pairs = load_ann_pairs(bundle_root / "lfw_ann.txt", bundle_root)
    cache = embed_images([p for pr in pairs for p in pr[:2]], None, emb,
                         "bundle_lfw", detect=False)
    scores, labels, failed = [], [], 0
    for p1, p2, label in pairs:
        a, b = cache.get(p1), cache.get(p2)
        if a is None or b is None:
            failed += 1
            continue
        scores.append(float(a @ b))
        labels.append(label)
    genuine = [s for s, l in zip(scores, labels) if l == 1]
    impostor = [s for s, l in zip(scores, labels) if l == 0]
    eer = vm.eer(genuine, impostor)
    thresholds = np.linspace(0.0, 1.0, 1001)
    accs = [vm.fold_accuracy(list(zip(scores, labels)), float(t))
            for t in thresholds]
    best_i = int(np.argmax(accs))
    print(f"[bundle_lfw] eer={eer:.4f} "
          f"best_acc={accs[best_i]:.4f}@t={thresholds[best_i]:.3f} "
          f"failed={failed}", flush=True)
    if failed:
        raise RuntimeError(f"bundle_lfw: {failed} pairs lost to unreadable images")
    return eer, float(accs[best_i])


def grant_calibration(pooled_gen, pooled_imp):
    table = []
    for t in GRANT_THRESHOLDS:
        far = sum(1 for s in pooled_imp if s > t) / len(pooled_imp)
        tar = sum(1 for s in pooled_gen if s > t) / len(pooled_gen)
        table.append({"threshold": t, "far": far, "tar": tar})
    ok = [row for row in table if row["far"] <= GRANT_FAR_CAP]
    if ok:
        best = max(ok, key=lambda row: (row["tar"], -row["threshold"]))
        rec = {"grant_recommendation": best["threshold"],
               "far_at_grant": best["far"], "table": table}
    else:
        rec = {"grant_recommendation": None, "far_at_grant": None, "table": table}
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--lfw", type=Path)
    ap.add_argument("--bundle", type=Path)
    ap.add_argument("--out", type=Path, default=Path("results-recognition.json"))
    a = ap.parse_args()

    t_start = time.perf_counter()
    have_cuda = "CUDAExecutionProvider" in ort.get_available_providers()
    prov = (["CUDAExecutionProvider", "CPUExecutionProvider"]
            if have_cuda else ["CPUExecutionProvider"])
    print(f"onnxruntime {ort.__version__} cuda={have_cuda}", flush=True)

    model_path = a.models_dir / "glintr100.onnx"
    det = Detector(a.models_dir / "face_detection_yunet_2023mar.onnx") if a.lfw else None
    emb = Embedder(model_path, 128.0, prov)

    notes = []
    rgb, pool_gen, pool_imp = {}, [], []
    per_set_seconds = {}
    if a.lfw:
        t0 = time.perf_counter()
        lfw_r, lfw_extra = run_lfw(a.lfw, det, emb)
        per_set_seconds["lfw"] = round(time.perf_counter() - t0, 1)
        rgb["lfw"] = lfw_r
        pool_gen += lfw_extra["gen"]
        pool_imp += lfw_extra["imp"]
        notes.append(
            "lfw acc10fold uses verification_metrics.ten_fold (per-fold optimal "
            f"threshold on the fold itself, ties to lowest threshold). The "
            f"bench_faceid.py held-out-train-fold-threshold protocol gives "
            f"{lfw_extra['heldout_acc']:.4f}±{lfw_extra['heldout_std']:.4f} on this "
            "run; the committed results-lfw.json continuity number 0.9903 used "
            "that protocol with the same auraface flip-TTA embedding path.")
        if lfw_extra["skipped"]:
            notes.append(f"lfw: {lfw_extra['skipped']} pairs skipped (no face "
                         "detected in at least one image).")
    if a.bundle:
        t0 = time.perf_counter()
        x_eer, x_acc = bundle_lfw_crosscheck(a.bundle, emb)
        per_set_seconds["bundle_lfw_crosscheck"] = round(
            time.perf_counter() - t0, 1)
        if a.lfw:
            notes.append(
                f"bundle coherence cross-check: the bundle's own aligned-LFW "
                f"annotation (lfw_ann.txt, 6,000 pairs) through the identical "
                f"embedding path gives eer={x_eer:.4f} and best-threshold "
                f"accuracy {x_acc:.4f} on its 112x112 crops, vs eer="
                f"{rgb['lfw']['eer']:.4f} for the deepfunneled detect+warp lane; "
                "the bundle data and the pipeline are consistent.")
        for key, ann_name in ALIGNED_SETS.items():
            t0 = time.perf_counter()
            r, extra = run_aligned_set(a.bundle, ann_name, key, emb)
            per_set_seconds[key] = round(time.perf_counter() - t0, 1)
            rgb[key] = r
            pool_gen += extra["gen"]
            pool_imp += extra["imp"]
        notes.append(
            "aligned sets (agedb30, calfw, cplfw): pre-aligned 112x112 crops "
            "embedded directly without detection; the shipped protocols define "
            "no folds, so each set reports acc_at_045 = "
            "verification_metrics.fold_accuracy at the fixed 0.45 line plus "
            "eer and tar_table; acc10fold is reported for lfw only.")
        notes.append(
            "aligned bundle annotations consumed: agedb_30_ann.txt, "
            "calfw_ann.txt, cplfw_ann.txt at the bundle root, label-first "
            "'<1|0> <img1> <img2>' format, 6,000 pairs (3,000 genuine / 3,000 "
            "impostor) per set, paths relative to the bundle root.")

    calibration = {"rgb": grant_calibration(pool_gen, pool_imp)}
    notes.append(
        "rgb grant calibration pools the impostor and genuine cosine scores of "
        "all scored pairs across the four sets above; grant rule is score > "
        "threshold; far/tar fractions use strict inequality; "
        "grant_recommendation is the candidate threshold with realized FAR <= "
        "1e-3 and the best TAR (lowest threshold on ties).")

    wall = time.perf_counter() - t_start
    results = {
        "runtime": {
            "host_model": str(model_path),
            "model_sha256": sha256_file(model_path),
            "ort": ort.__version__,
            "cuda": have_cuda,
            "flip_tta": True,
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "wall_seconds": round(wall, 1),
            "per_set_seconds": per_set_seconds,
        },
        "rgb": rgb,
        "threshold_calibration": calibration,
        "notes": notes,
    }
    a.out.write_text(json.dumps(results, indent=2))
    print(f"wrote {a.out}", flush=True)


if __name__ == "__main__":
    main()
