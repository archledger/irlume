#!/usr/bin/env python3
"""Benchmark: irlume's shipped models vs InsightFace buffalo_l recognizer.

Models under test (all ONNX):
  - AuraFace glintr100 (irlume ships this)            512-D
  - InsightFace buffalo_l w600k_r50                   512-D
  - irlume ir_adapter v3 (applied on AuraFace IR embeddings only)

Shared pipeline for both recognizers: OpenCV FaceDetectorYN (YuNet, the
detector irlume ships) -> 5-point ArcFace similarity warp to 112x112.

Protocols:
  1. LFW 6000-pair verification (RGB): 10-fold accuracy, EER, TAR@FAR.
  2. Oulu-CASIA NIR verification (identity = P### filename prefix),
     genuine/impostor pairs, seeded: buffalo vs auraface vs auraface+adapter.
  3. Latency: single-image embed time, CPU and CUDA if available.

Usage: python3 bench_faceid.py --models-dir ~/bench/models \
         --lfw ~/datasets/lfw --oulu ~/datasets/oulu_nir_flat --out results.json
"""
import argparse, csv, json, os, random, sys, time
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

ARCFACE_REF = np.array([
    [38.2946, 51.6963], [73.5318, 51.5014], [56.0252, 71.7366],
    [41.5493, 92.3655], [70.7299, 92.2041]], dtype=np.float32)


def estimate_norm(lmk):
    """Least-squares similarity transform lmk(5x2) -> ARCFACE_REF (Umeyama)."""
    src, dst = lmk.astype(np.float64), ARCFACE_REF.astype(np.float64)
    mu_s, mu_d = src.mean(0), dst.mean(0)
    sc, dc = src - mu_s, dst - mu_d
    cov = dc.T @ sc / 5
    U, S, Vt = np.linalg.svd(cov)
    d = np.sign(np.linalg.det(U) * np.linalg.det(Vt))
    D = np.diag([1.0, d])
    R = U @ D @ Vt
    var_s = (sc ** 2).sum() / 5
    scale = np.trace(np.diag(S) @ D) / var_s
    t = mu_d - scale * (R @ mu_s)
    M = np.hstack([scale * R, t[:, None]])
    return M.astype(np.float32)


class Detector:
    def __init__(self, yunet_path):
        self.det = cv2.FaceDetectorYN.create(str(yunet_path), "", (320, 320),
                                             score_threshold=0.6)

    def largest_face_landmarks(self, bgr):
        h, w = bgr.shape[:2]
        self.det.setInputSize((w, h))
        ok, faces = self.det.detect(bgr)
        if faces is None or len(faces) == 0:
            return None
        f = max(faces, key=lambda r: r[2] * r[3])
        return f[4:14].reshape(5, 2)


class Embedder:
    def __init__(self, model_path, std, providers):
        self.sess = ort.InferenceSession(str(model_path), providers=providers)
        self.inp = self.sess.get_inputs()[0].name
        self.std = std

    def embed(self, bgr112, flip_tta=False):
        rgb = cv2.cvtColor(bgr112, cv2.COLOR_BGR2RGB).astype(np.float32)
        chips = [rgb, rgb[:, ::-1, :].copy()] if flip_tta else [rgb]
        acc = np.zeros(512, dtype=np.float32)
        for c in chips:
            x = ((c - 127.5) / self.std).transpose(2, 0, 1)[None]
            out = self.sess.run(None, {self.inp: x})[0][0]
            acc += out / (np.linalg.norm(out) + 1e-9)
        return acc / (np.linalg.norm(acc) + 1e-9)


class Adapter:
    def __init__(self, model_path, providers):
        self.sess = ort.InferenceSession(str(model_path), providers=providers)
        self.inp = self.sess.get_inputs()[0].name

    def apply(self, emb):
        x = emb.astype(np.float32)[None]
        out = self.sess.run(None, {self.inp: x})[0][0]
        return out / (np.linalg.norm(out) + 1e-9)


def align_or_center(bgr, det):
    lmk = det.largest_face_landmarks(bgr)
    if lmk is None:
        return None
    M = estimate_norm(lmk)
    return cv2.warpAffine(bgr, M, (112, 112), flags=cv2.INTER_LINEAR)


def roc_metrics(scores, labels):
    scores, labels = np.asarray(scores), np.asarray(labels)
    order = np.argsort(-scores)
    s, l = scores[order], labels[order]
    P, N = l.sum(), (1 - l).sum()
    tps, fps = np.cumsum(l), np.cumsum(1 - l)
    tpr, fpr = tps / P, fps / N
    fnr = 1 - tpr
    i = np.nanargmin(np.abs(fnr - fpr))
    eer = float((fnr[i] + fpr[i]) / 2)
    out = {"eer": eer, "auc": float(np.trapezoid(tpr, fpr))}
    for far in (1e-2, 1e-3):
        j = np.searchsorted(fpr, far, side="right") - 1
        out[f"tar@far{far:g}"] = float(tpr[j]) if j >= 0 else 0.0
    return out


def lfw_tenfold_accuracy(scores, labels, folds):
    scores, labels, folds = map(np.asarray, (scores, labels, folds))
    accs = []
    for f in sorted(set(folds.tolist())):
        tr, te = folds != f, folds == f
        ths = np.unique(scores[tr])
        best = ths[np.argmax([((scores[tr] >= t) == labels[tr]).mean() for t in ths])]
        accs.append(((scores[te] >= best) == labels[te]).mean())
    return float(np.mean(accs)), float(np.std(accs))


def run_lfw(lfw_dir, det, models, flip_tta):
    pairs = list(csv.DictReader(open(lfw_dir / "pairs.csv")))
    cache = {}  # path -> aligned chip or None
    def chip(rel):
        if rel not in cache:
            img = cv2.imread(str(lfw_dir / "train" / rel))
            cache[rel] = None if img is None else align_or_center(img, det)
        return cache[rel]

    results = {}
    for name, emb in models.items():
        ecache, scores, labels, folds, skipped = {}, [], [], [], 0
        def E(rel):
            if rel not in ecache:
                c = chip(rel)
                ecache[rel] = None if c is None else emb.embed(c, flip_tta)
            return ecache[rel]
        for p in pairs:
            a, b = E(p["image_a_path"]), E(p["image_b_path"])
            if a is None or b is None:
                skipped += 1
                continue
            scores.append(float(a @ b))
            labels.append(int(p["is_same"]))
            folds.append(int(p["fold_id"]))
        acc, std = lfw_tenfold_accuracy(scores, labels, folds)
        r = roc_metrics(scores, labels)
        r.update({"acc10fold": acc, "acc_std": std,
                  "pairs_used": len(scores), "pairs_skipped_nodet": skipped})
        results[name] = r
        print(f"[LFW]{' TTA' if flip_tta else ''} {name}: acc={acc:.4f}±{std:.4f} "
              f"EER={r['eer']:.4f} TAR@1e-3={r['tar@far0.001']:.4f} skip={skipped}",
              flush=True)
    return results


def run_oulu(oulu_dir, det, models, adapter, n_pairs=3000, seed=42):
    imgs = sorted(oulu_dir.glob("*.jpg"))
    by_id = {}
    for p in imgs:
        by_id.setdefault(p.name.split("-")[0], []).append(p)
    ids = sorted(by_id)
    rng = random.Random(seed)

    # Precompute aligned chips once.
    chips, nodet = {}, 0
    for p in imgs:
        img = cv2.imread(str(p))
        c = None if img is None else align_or_center(img, det)
        if c is None:
            nodet += 1
        else:
            chips[p.name] = c
    print(f"[Oulu] {len(chips)}/{len(imgs)} faces detected ({nodet} no-detect)",
          flush=True)

    detected = {i: [p for p in by_id[i] if p.name in chips] for i in ids}
    detected = {i: v for i, v in detected.items() if len(v) >= 2}
    ids = sorted(detected)
    genuine, impostor = [], []
    while len(genuine) < n_pairs:
        i = rng.choice(ids)
        a, b = rng.sample(detected[i], 2)
        genuine.append((a.name, b.name, 1))
    while len(impostor) < n_pairs:
        i, j = rng.sample(ids, 2)
        impostor.append((rng.choice(detected[i]).name,
                         rng.choice(detected[j]).name, 0))
    pairs = genuine + impostor

    variants = {}
    for name, emb in models.items():
        variants[name] = {n: emb.embed(c) for n, c in chips.items()}
    if adapter is not None and "auraface" in variants:
        variants["auraface+ir_adapter_v3"] = {
            n: adapter.apply(e) for n, e in variants["auraface"].items()}

    results = {}
    for name, embs in variants.items():
        scores = [float(embs[a] @ embs[b]) for a, b, _ in pairs]
        labels = [l for _, _, l in pairs]
        r = roc_metrics(scores, labels)
        r["pairs"] = len(pairs)
        results[name] = r
        print(f"[Oulu NIR] {name}: EER={r['eer']:.4f} "
              f"TAR@1e-3={r['tar@far0.001']:.4f} AUC={r['auc']:.4f}", flush=True)
    results["no_detect_images"] = nodet
    return results


def run_latency(models_dir, have_cuda):
    chip = (np.random.rand(112, 112, 3) * 255).astype(np.uint8)
    frame = (np.random.rand(480, 640, 3) * 255).astype(np.uint8)
    provs = [["CPUExecutionProvider"]]
    if have_cuda:
        provs.append(["CUDAExecutionProvider", "CPUExecutionProvider"])
    out = {}
    for pv in provs:
        tag = "cuda" if "CUDAExecutionProvider" in pv else "cpu"
        for name, fn, std in (("auraface", "glintr100.onnx", 128.0),
                              ("buffalo_w600k_r50", "w600k_r50.onnx", 127.5)):
            e = Embedder(models_dir / fn, std, pv)
            for _ in range(10):
                e.embed(chip)
            t0 = time.perf_counter()
            N = 100
            for _ in range(N):
                e.embed(chip)
            out[f"{name}_{tag}_ms"] = (time.perf_counter() - t0) / N * 1000
    det = Detector(models_dir / "face_detection_yunet_2023mar.onnx")
    for _ in range(10):
        det.largest_face_landmarks(frame)
    t0 = time.perf_counter()
    for _ in range(100):
        det.largest_face_landmarks(frame)
    out["yunet_detect_640x480_cpu_ms"] = (time.perf_counter() - t0) / 100 * 1000
    for k, v in sorted(out.items()):
        print(f"[latency] {k}: {v:.2f}", flush=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--lfw", type=Path)
    ap.add_argument("--oulu", type=Path)
    ap.add_argument("--out", type=Path, default=Path("bench_results.json"))
    ap.add_argument("--skip-latency", action="store_true")
    a = ap.parse_args()

    have_cuda = "CUDAExecutionProvider" in ort.get_available_providers()
    prov = (["CUDAExecutionProvider", "CPUExecutionProvider"]
            if have_cuda else ["CPUExecutionProvider"])
    print(f"onnxruntime {ort.__version__} cuda={have_cuda}", flush=True)

    det = Detector(a.models_dir / "face_detection_yunet_2023mar.onnx")
    models = {
        "auraface": Embedder(a.models_dir / "glintr100.onnx", 128.0, prov),
        "buffalo_w600k_r50": Embedder(a.models_dir / "w600k_r50.onnx", 127.5, prov),
    }
    adapter_path = a.models_dir / "ir_adapter.onnx"
    adapter = Adapter(adapter_path, prov) if adapter_path.exists() else None

    results = {"ort": ort.__version__, "cuda": have_cuda}
    if a.lfw:
        results["lfw"] = run_lfw(a.lfw, det, models, flip_tta=False)
        results["lfw_flip_tta"] = run_lfw(a.lfw, det, models, flip_tta=True)
    if a.oulu:
        results["oulu_nir"] = run_oulu(a.oulu, det, models, adapter)
    if not a.skip_latency:
        results["latency"] = run_latency(a.models_dir, have_cuda)
    a.out.write_text(json.dumps(results, indent=2))
    print(f"wrote {a.out}", flush=True)


if __name__ == "__main__":
    main()
