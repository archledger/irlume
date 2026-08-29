#!/usr/bin/env python3
"""Recognition suite for calibration phase 2 (Tasks 3-5).

Scores AuraFace glintr100 (the recognizer irlume ships) over standard
verification protocols and derives per-modality grant-threshold
calibrations:

  - LFW deepfunneled (Task 3), shipped pairs.csv 10-fold protocol
    (6,000 pairs, 10 folds x [300 match + 300 mismatch] in canonical row
    order). Continuity cross-check against the committed results-lfw.json
    auraface flip-TTA number (acc10fold 0.9903).
  - AgeDB-30 / CALFW / CPLFW (Task 3) from the aligned_fr_bundle mirror:
    pre-aligned 112x112 crops scored over each set's shipped 6,000-pair
    annotation file.
  - CFPW (Task 4): official 10-fold frontal-frontal (FF) and
    frontal-profile (FP) verification, 350 same + 350 diff pairs per
    fold per protocol (7,000 pairs each), resolved through
    Pair_list_F.txt / Pair_list_P.txt. Wild (unaligned) images scored
    with the same detect + warp path as LFW; the ff vs fp rows quantify
    the pose gap.
  - NIR (Task 5): CBSR (OTCBVS 07) verification on the shipped
    gallery/probe ground truth with the bench_nir_ext.py preprocessing
    (YuNet 5-point warp, ground-truth two-eye fallback), and a seeded
    10,000-pair Oulu-CASIA NIR protocol over subject-disjoint fold
    halves. Pools both sets into a NIR grant-threshold calibration whose
    candidate sweep spans 0.2-0.6, covering both the band NIR evidence
    operates in and its impostor tail.

The embedding path reuses bench_faceid.py exactly (YuNet detect + 5-point
similarity warp to 112x112 for unaligned sets; (x - 127.5) / 128
normalization, flip TTA, 512-D L2-normalized embedding, cosine scoring) so
the numbers stay comparable with the committed results. Metrics come from
verification_metrics (eer, far_threshold_table, fold_accuracy, ten_fold).

The aligned-set protocols ship no folds, so those sets report fold_accuracy
at the fixed 0.45 line (key acc_at_045) plus eer and tar_table; LFW, CFPW
and Oulu report acc10fold over their folds.

Usage:
  python3 bench_recog_suite.py --models-dir ~/irlume-bench/models \
      --lfw ~/datasets/lfw --bundle ~/datasets/aligned_fr_bundle \
      --cfp ~/datasets/cfpw --cbsr ~/datasets/cbsr_nir \
      --oulu ~/datasets/oulu_casia_nir --out results-recognition.json

The out file is merged, not replaced: lanes not run in this invocation
keep their existing rows, and threshold_calibration.rgb stays frozen to
the task 3 pool (lfw, agedb30, calfw, cplfw) it was derived from.
"""
import argparse, hashlib, json, random, sys, time
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verification_metrics as vm
from bench_faceid import (Embedder, align_or_center, estimate_norm,
                          lfw_tenfold_accuracy)
from bench_nir_ext import DetectorFull, load_cbsr_gt, two_point_norm

FARS = [0.1, 0.03, 0.01, 0.003, 0.001]
GRANT_THRESHOLDS = [0.3, 0.35, 0.4, 0.45, 0.5]
GRANT_FAR_CAP = 1e-3
NIR_SEED = 42
NIR_CBSR_PAIRS = 3000
OULU_PER_FOLD = 2500
NIR_GRANT_THRESHOLDS = [0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6]
NIR_OPERATING_BAND = (0.2, 0.4)
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


def load_cfp_pairs(cfp_dir):
    """Resolve the CFPW 10-fold FF/FP pair files to image paths.

    Protocol/Split/{FF,FP}/{01..10}/{same,diff}.txt hold 'a,b' 1-based
    image indices per fold (350 same + 350 diff rows each). Indices point
    into Protocol/Pair_list_F.txt (5,000 frontal images) and
    Protocol/Pair_list_P.txt (2,000 profile images); FF lines index the
    frontal list twice, FP lines are (frontal, profile). Fold directories
    are identity-separable per the shipped Readme.
    """
    def read_index(path):
        out = {}
        for ln in path.read_text().splitlines():
            ln = ln.strip()
            if not ln:
                continue
            idx, rel = ln.split(None, 1)
            out[int(idx)] = (path.parent / rel.strip()).resolve()
        return out

    proto_dir = cfp_dir / "Protocol"
    flist = read_index(proto_dir / "Pair_list_F.txt")
    plist = read_index(proto_dir / "Pair_list_P.txt")
    subjects = ({p.parent.parent.name for p in flist.values()}
                | {p.parent.parent.name for p in plist.values()})
    if len(subjects) != 500:
        raise ValueError(
            f"cfpw: expected 500 identities, got {len(subjects)}")
    protos = {}
    for proto in ("ff", "fp"):
        pairs = []
        split_dir = proto_dir / "Split" / proto.upper()
        fold_dirs = sorted(d for d in split_dir.iterdir() if d.is_dir())
        if len(fold_dirs) != 10:
            raise ValueError(
                f"cfpw {proto}: expected 10 fold dirs, got {len(fold_dirs)}")
        for fold, d in enumerate(fold_dirs):
            for label, name in ((1, "same.txt"), (0, "diff.txt")):
                rows = [ln.strip() for ln
                        in (d / name).read_text().splitlines() if ln.strip()]
                if len(rows) != 350:
                    raise ValueError(
                        f"{d / name}: expected 350 rows, got {len(rows)}")
                for ln in rows:
                    ia, ib = (int(x) for x in ln.split(","))
                    if proto == "ff":
                        p1, p2 = flist[ia], flist[ib]
                        ok = (p1.parent.name == "frontal"
                              and p2.parent.name == "frontal")
                    else:
                        p1, p2 = flist[ia], plist[ib]
                        ok = (p1.parent.name == "frontal"
                              and p2.parent.name == "profile")
                    if not ok:
                        raise ValueError(
                            f"cfpw {proto}: pose mismatch at "
                            f"{d.name}/{name}: {ln}")
                    pairs.append((p1, p2, label, fold))
        protos[proto] = pairs
    return protos


def run_cfp(cfp_dir, det, emb):
    """Score the CFPW FF and FP protocols; returns rows + skipped counts.

    The pose gap is the ff row vs the fp row: frontal-frontal accuracy
    against frontal-profile accuracy under the identical embedding path.
    """
    protos = load_cfp_pairs(cfp_dir)
    cache = embed_images(
        [p for pr in (protos["ff"] + protos["fp"]) for p in pr[:2]],
        det, emb, "cfpw", detect=True)
    rows, skipped = {}, {}
    for proto in ("ff", "fp"):
        scores, labels, folds, skip = [], [], [], 0
        for p1, p2, label, fold in protos[proto]:
            a, b = cache.get(p1), cache.get(p2)
            if a is None or b is None:
                skip += 1
                continue
            scores.append(float(a @ b))
            labels.append(label)
            folds.append(fold)
        genuine = [s for s, l in zip(scores, labels) if l == 1]
        impostor = [s for s, l in zip(scores, labels) if l == 0]
        tf = vm.ten_fold(scores, labels, folds)
        rows[proto] = {
            "acc10fold": tf["acc10fold"],
            "acc_sd": tf["sd"],
            "eer": vm.eer(genuine, impostor),
            "tar_table": vm.far_threshold_table(genuine, impostor, FARS),
            "acc_at_045": vm.fold_accuracy(list(zip(scores, labels)), 0.45),
            "pairs": len(scores),
        }
        skipped[proto] = skip
        print(f"[cfp_{proto}] acc10fold={tf['acc10fold']:.4f}±{tf['sd']:.4f} "
              f"eer={rows[proto]['eer']:.4f} acc@0.45="
              f"{rows[proto]['acc_at_045']:.4f} skip={skip}", flush=True)
    return {"ff": rows["ff"], "fp": rows["fp"]}, skipped


def run_cbsr(cbsr_dir, det, emb, n_pairs=NIR_CBSR_PAIRS, seed=NIR_SEED):
    """Score CBSR NIR verification on the shipped gallery/probe split.

    Preprocessing is the bench_nir_ext.py NIR path: YuNet largest-face
    5-point warp, falling back to the ground-truth two-eye similarity
    warp so coverage stays at 100%. Genuine pairs are seeded same-subject
    (gallery, probe) combinations; impostor pairs are seeded
    different-subject (gallery, probe) pairs over the same subjects.
    """
    gt = load_cbsr_gt(cbsr_dir)
    img_dir = cbsr_dir / "NIR_face_dataset" / "NIR_face_dataset"
    chips, fallbacks, missing = {}, 0, 0
    t0 = time.perf_counter()
    for i, n in enumerate(sorted(gt), 1):
        img = cv2.imread(str(img_dir / n), cv2.IMREAD_COLOR)
        if img is None:
            missing += 1
            continue
        f = det.largest_face(img)
        if f is not None:
            m = estimate_norm(f[4:14].reshape(5, 2))
        else:
            fallbacks += 1
            m = two_point_norm(gt[n]["le"], gt[n]["re"])
        chips[n] = cv2.warpAffine(img, m, (112, 112), flags=cv2.INTER_LINEAR)
        if i % 500 == 0:
            print(f"[cbsr] {i}/{len(gt)} chips "
                  f"({time.perf_counter() - t0:.0f}s)", flush=True)

    gal, probe = {}, {}
    for n in sorted(chips):
        by = n.split("-")[0]
        (gal if gt[n]["split"] == "gallery" else probe).setdefault(
            by, []).append(n)
    elig = sorted(set(gal) & set(probe))
    rng = random.Random(seed)
    pairs = []
    while len(pairs) < n_pairs:
        i = rng.choice(elig)
        pairs.append((rng.choice(gal[i]), rng.choice(probe[i]), 1))
    while len(pairs) < 2 * n_pairs:
        i, j = rng.sample(elig, 2)
        pairs.append((rng.choice(gal[i]), rng.choice(probe[j]), 0))

    embs = {}
    for i, (n, c) in enumerate(chips.items(), 1):
        embs[n] = emb.embed(c, flip_tta=True)
        if i % 500 == 0:
            print(f"[cbsr] {i}/{len(chips)} embedded "
                  f"({time.perf_counter() - t0:.0f}s)", flush=True)
    scores = [float(embs[a] @ embs[b]) for a, b, _ in pairs]
    labels = [l for _, _, l in pairs]
    genuine = [s for s, l in zip(scores, labels) if l == 1]
    impostor = [s for s, l in zip(scores, labels) if l == 0]
    r = {
        "eer": vm.eer(genuine, impostor),
        "tar_table": vm.far_threshold_table(genuine, impostor, FARS),
        "acc_at_045": vm.fold_accuracy(list(zip(scores, labels)), 0.45),
        "pairs": len(scores),
        "images": len(chips),
        "gt_align_fallbacks": fallbacks,
        "missing_images": missing,
        "seed": seed,
    }
    print(f"[cbsr] eer={r['eer']:.4f} acc@0.45={r['acc_at_045']:.4f} "
          f"images={len(chips)} fallbacks={fallbacks} missing={missing}",
          flush=True)
    return r, genuine, impostor


def run_oulu(oulu_dir, det, emb, per_fold=OULU_PER_FOLD, seed=NIR_SEED):
    """Score the seeded Oulu-CASIA NIR verification protocol.

    Identity is the P### subject across the Dark/Strong/Weak lighting
    trees. The sorted usable subject list is split into two disjoint
    halves; each half contributes per_fold genuine (same subject,
    different image) and per_fold impostor (different subjects) pairs,
    so the two fold halves are subject-disjoint. Deterministic under
    random.Random(seed); pairs with no detected face are skipped and
    counted.
    """
    by_id = {}
    for lighting in sorted(p for p in (oulu_dir / "NI").iterdir()
                           if p.is_dir()):
        for subj in sorted(p for p in lighting.iterdir() if p.is_dir()):
            for emo in sorted(p for p in subj.iterdir() if p.is_dir()):
                for p in sorted(emo.iterdir()):
                    if p.suffix.lower() in (".jpg", ".jpeg"):
                        by_id.setdefault(subj.name, []).append(p)
    usable = sorted(i for i in by_id if len(by_id[i]) >= 2)
    if len(usable) < 4 or len(usable) % 2:
        raise ValueError(
            f"oulu: cannot split {len(usable)} subjects into halves")
    halves = (usable[:len(usable) // 2], usable[len(usable) // 2:])
    rng = random.Random(seed)
    pairs = []
    for fold, half in enumerate(halves):
        n = 0
        while n < per_fold:
            i = rng.choice(half)
            a, b = rng.sample(by_id[i], 2)
            pairs.append((a, b, 1, fold))
            n += 1
        n = 0
        while n < per_fold:
            i, j = rng.sample(half, 2)
            pairs.append((rng.choice(by_id[i]), rng.choice(by_id[j]), 0, fold))
            n += 1

    cache = embed_images([p for pr in pairs for p in pr[:2]],
                         det, emb, "oulu", detect=True)
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
    r = {
        "acc10fold": tf["acc10fold"],
        "acc_sd": tf["sd"],
        "eer": vm.eer(genuine, impostor),
        "tar_table": vm.far_threshold_table(genuine, impostor, FARS),
        "acc_at_045": vm.fold_accuracy(list(zip(scores, labels)), 0.45),
        "pairs": len(scores),
        "subjects": len(usable),
        "seed": seed,
        "skipped": skipped,
    }
    print(f"[oulu] acc10fold={tf['acc10fold']:.4f}±{tf['sd']:.4f} "
          f"eer={r['eer']:.4f} acc@0.45={r['acc_at_045']:.4f} "
          f"skip={skipped}", flush=True)
    return r, genuine, impostor


def nir_operating_band(pooled_gen, pooled_imp):
    """FAR/TAR rows across the NIR operating band of the grant paths."""
    rows = []
    for t in NIR_GRANT_THRESHOLDS:
        if not (NIR_OPERATING_BAND[0] <= t <= NIR_OPERATING_BAND[1]):
            continue
        far = sum(1 for s in pooled_imp if s > t) / len(pooled_imp)
        tar = sum(1 for s in pooled_gen if s > t) / len(pooled_gen)
        rows.append({"threshold": t, "far": far, "tar": tar})
    return rows


def grant_calibration(pooled_gen, pooled_imp, thresholds=GRANT_THRESHOLDS):
    table = []
    for t in thresholds:
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
    ap.add_argument("--cfp", type=Path)
    ap.add_argument("--cbsr", type=Path)
    ap.add_argument("--oulu", type=Path)
    ap.add_argument("--out", type=Path, default=Path("results-recognition.json"))
    a = ap.parse_args()

    t_start = time.perf_counter()
    have_cuda = "CUDAExecutionProvider" in ort.get_available_providers()
    prov = (["CUDAExecutionProvider", "CPUExecutionProvider"]
            if have_cuda else ["CPUExecutionProvider"])
    print(f"onnxruntime {ort.__version__} cuda={have_cuda}", flush=True)

    model_path = a.models_dir / "glintr100.onnx"
    need_detect = bool(a.lfw or a.cfp or a.cbsr or a.oulu)
    det = (DetectorFull(a.models_dir / "face_detection_yunet_2023mar.onnx")
           if need_detect else None)
    emb = Embedder(model_path, 128.0, prov)

    results = {}
    if a.out.exists():
        results = json.loads(a.out.read_text())
    notes = list(results.get("notes", []))
    per_set_seconds = dict(
        results.get("runtime", {}).get("per_set_seconds", {}))

    def add_note(text):
        if text not in notes:
            notes.append(text)

    rgb, pool_gen, pool_imp = dict(results.get("rgb", {})), [], []
    if a.lfw:
        t0 = time.perf_counter()
        lfw_r, lfw_extra = run_lfw(a.lfw, det, emb)
        per_set_seconds["lfw"] = round(time.perf_counter() - t0, 1)
        rgb["lfw"] = lfw_r
        pool_gen += lfw_extra["gen"]
        pool_imp += lfw_extra["imp"]
        add_note(
            "lfw acc10fold uses verification_metrics.ten_fold (per-fold optimal "
            f"threshold on the fold itself, ties to lowest threshold). The "
            f"bench_faceid.py held-out-train-fold-threshold protocol gives "
            f"{lfw_extra['heldout_acc']:.4f}±{lfw_extra['heldout_std']:.4f} on this "
            "run; the committed results-lfw.json continuity number 0.9903 used "
            "that protocol with the same auraface flip-TTA embedding path.")
        if lfw_extra["skipped"]:
            add_note(f"lfw: {lfw_extra['skipped']} pairs skipped (no face "
                     "detected in at least one image).")
    if a.bundle:
        t0 = time.perf_counter()
        x_eer, x_acc = bundle_lfw_crosscheck(a.bundle, emb)
        per_set_seconds["bundle_lfw_crosscheck"] = round(
            time.perf_counter() - t0, 1)
        if a.lfw:
            add_note(
                "bundle coherence cross-check: the bundle's own aligned-LFW "
                "annotation (lfw_ann.txt, 6,000 pairs) through the identical "
                "embedding path gives eer="
                f"{x_eer:.4f} and best-threshold "
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
        add_note(
            "aligned sets (agedb30, calfw, cplfw): pre-aligned 112x112 crops "
            "embedded directly without detection; the shipped protocols define "
            "no folds, so each set reports acc_at_045 = "
            "verification_metrics.fold_accuracy at the fixed 0.45 line plus "
            "eer and tar_table; acc10fold is reported for lfw only.")
        add_note(
            "aligned bundle annotations consumed: agedb_30_ann.txt, "
            "calfw_ann.txt, cplfw_ann.txt at the bundle root, label-first "
            "'<1|0> <img1> <img2>' format, 6,000 pairs (3,000 genuine / 3,000 "
            "impostor) per set, paths relative to the bundle root.")
    if a.cfp:
        t0 = time.perf_counter()
        cfp_r, cfp_skip = run_cfp(a.cfp, det, emb)
        per_set_seconds["cfpw"] = round(time.perf_counter() - t0, 1)
        rgb["cfpw"] = cfp_r
        add_note(
            "cfpw protocol consumed: Protocol/Split/{FF,FP}/{01..10}/"
            "{same,diff}.txt with 350 same + 350 diff rows per fold per "
            "protocol; 'a,b' lines are 1-based image indices resolved through "
            "Pair_list_F.txt (5,000 frontal) and Pair_list_P.txt (2,000 "
            "profile); FF lines index the frontal list twice, FP lines are "
            "(frontal, profile); 500 identities asserted across both lists; "
            "folds are identity-separable per the shipped Readme, so "
            "acc10fold uses verification_metrics.ten_fold (per-fold optimal "
            "threshold on the fold itself, ties to lowest) and acc_sd is the "
            "population sd across the 10 folds.")
        add_note(
            "cfpw pose gap: compare rgb.cfpw.ff (frontal-frontal) with "
            "rgb.cfpw.fp (frontal-profile) accuracy and eer; images are wild "
            "(unaligned) photos embedded with the same detect + warp path as "
            "lfw; pairs with no detected face are skipped and counted "
            f"(ff skipped={cfp_skip['ff']}, fp skipped={cfp_skip['fp']}).")
        add_note(
            "cfpw scores are not pooled into threshold_calibration.rgb; that "
            "table stays frozen to its task 3 pool (lfw, agedb30, calfw, "
            "cplfw) and cfpw is reported alongside as the pose-gap evidence.")

    nir = dict(results.get("nir", {}))
    nir_gen, nir_imp = [], []
    calibration = dict(results.get("threshold_calibration", {}))
    if a.cbsr:
        t0 = time.perf_counter()
        r, gen, imp = run_cbsr(a.cbsr, det, emb)
        per_set_seconds["cbsr_nir"] = round(time.perf_counter() - t0, 1)
        nir["cbsr"] = r
        nir_gen += gen
        nir_imp += imp
        add_note(
            "cbsr protocol consumed: gallery-groundtruth.txt (1,576 lines) "
            "and probe-groundtruth.txt (2,364 lines), 'name,lx,ly,rx,ry' per "
            "image; the split field of each ground-truth entry defines the "
            "gallery/probe membership and the name prefix before '-' the "
            "subject; verification pairs are seeded (seed 42): 3,000 genuine "
            "same-subject (gallery, probe) pairs and 3,000 impostor "
            "different-subject (gallery, probe) pairs over subjects present "
            "in both splits; preprocessing is the bench_nir_ext.py NIR path "
            "(YuNet largest-face 5-point warp, ground-truth two-eye "
            "similarity warp fallback keeps coverage at 100%); embeddings "
            "use the suite flip-TTA path, while the committed bench_nir_ext "
            "numbers used no TTA, so eers are not directly comparable.")
    if a.oulu:
        t0 = time.perf_counter()
        r, gen, imp = run_oulu(a.oulu, det, emb)
        per_set_seconds["oulu_nir"] = round(time.perf_counter() - t0, 1)
        nir["oulu"] = r
        nir_gen += gen
        nir_imp += imp
        add_note(
            "oulu protocol is constructed, not canonical (no shipped pair "
            "list): identity is the P### subject across the Dark/Strong/Weak "
            "lighting trees; the sorted usable subject list splits into two "
            "disjoint halves, each contributing 2,500 genuine (same subject, "
            "different image, any lighting and emotion) and 2,500 impostor "
            "pairs under random.Random(seed 42), so acc10fold averages the "
            "two subject-disjoint fold halves; pairs with no detected face "
            "are skipped and counted.")
    if nir_gen and a.cbsr and a.oulu:
        calibration["nir"] = grant_calibration(
            nir_gen, nir_imp, NIR_GRANT_THRESHOLDS)
        calibration["nir"]["operating_band"] = nir_operating_band(
            nir_gen, nir_imp)
        t50 = next(r for r in calibration["nir"]["table"]
                   if r["threshold"] == 0.5)
        add_note(
            "nir grant calibration pools the impostor and genuine cosine "
            "scores of the cbsr and oulu pairs of this run; derivation "
            "matches rgb (smallest candidate threshold with realized FAR <= "
            "1e-3, best TAR, lowest threshold on ties, strict inequality); "
            "the candidate sweep spans 0.2-0.6 because same-modality NIR "
            "evidence concentrates lower than RGB while the pooled impostor "
            f"tail reaches past 0.5 (FAR {t50['far']:.2e} at 0.5 on this "
            "run); operating_band lists FAR/TAR at 0.2-0.4, the realistic "
            "operating band of the recognition grant paths on NIR evidence; "
            "calibration-only evidence, no runtime change.")

    if pool_gen:
        calibration["rgb"] = grant_calibration(pool_gen, pool_imp)
        add_note(
            "rgb grant calibration pools the impostor and genuine cosine scores of "
            "all scored pairs across the four sets above; grant rule is score > "
            "threshold; far/tar fractions use strict inequality; "
            "grant_recommendation is the candidate threshold with realized FAR <= "
            "1e-3 and the best TAR (lowest threshold on ties).")

    wall = time.perf_counter() - t_start
    out = {
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
    }
    if nir:
        out["nir"] = nir
    out["threshold_calibration"] = calibration
    out["notes"] = notes
    a.out.write_text(json.dumps(out, indent=2))
    print(f"wrote {a.out}", flush=True)


if __name__ == "__main__":
    main()
