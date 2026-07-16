#!/usr/bin/env python3
"""NIR eval extension for the irlume model bench (imports bench_faceid.py).

Protocols (all seeded, eval-only datasets):
  1. CBSR NIR (OTCBVS dataset 07): 197 ids, 3940 active-NIR BMPs, eye-center
     ground truth per image, official gallery/probe split.
       a. YuNet detection on NIR: detect rate, GT-eyes-in-box rate,
          eye landmark error normalized by inter-ocular distance.
       b. Verification (genuine/impostor pairs) per recognizer variant.
       c. Rank-1 identification: gallery-averaged templates vs probe images.
     Alignment: YuNet 5pt when detected, else 2-point GT-eye similarity warp
     (keeps coverage at 100%; fallback count reported).
  2. Tufts sets A: 110 ids, paired RGB<->NIR 224x224.
       a. Per-modality YuNet detect rate.
       b. Cross-spectral verification (irlume's production shape):
          template = mean RGB embedding per id, probe = NIR image.
          Adapter applies to the NIR probe side only.
       c. NIR<->NIR and RGB<->RGB verification for reference.

Usage: python3 bench_nir_ext.py --models-dir ~/bench/models \
         --cbsr ~/datasets/cbsr_nir --tufts ~/datasets/tufts_faces \
         --out bench_nir_results.json
"""
import argparse, json, random
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

from bench_faceid import (ARCFACE_REF, Adapter, Detector, Embedder,
                          estimate_norm, roc_metrics)

EYE_REF = ARCFACE_REF[:2]  # image-left eye, image-right eye in the 112 chip


def two_point_norm(le, re):
    """Similarity transform from the two GT eye centers to the ArcFace
    reference eye positions (rotation+scale+translation from one segment)."""
    src = np.array([le, re], dtype=np.float64)
    dst = EYE_REF.astype(np.float64)
    sv, dv = src[1] - src[0], dst[1] - dst[0]
    ang = np.arctan2(dv[1], dv[0]) - np.arctan2(sv[1], sv[0])
    scale = np.linalg.norm(dv) / (np.linalg.norm(sv) + 1e-9)
    c, s = scale * np.cos(ang), scale * np.sin(ang)
    R = np.array([[c, -s], [s, c]])
    t = dst.mean(0) - R @ src.mean(0)
    return np.hstack([R, t[:, None]]).astype(np.float32)


class DetectorFull(Detector):
    def largest_face(self, bgr):
        h, w = bgr.shape[:2]
        self.det.setInputSize((w, h))
        ok, faces = self.det.detect(bgr)
        if faces is None or len(faces) == 0:
            return None
        return max(faces, key=lambda r: r[2] * r[3])


def load_cbsr_gt(cbsr_dir):
    gt = {}
    for split in ("gallery", "probe"):
        for line in (cbsr_dir / f"{split}-groundtruth.txt").read_text().split():
            name, lx, ly, rx, ry = line.strip().split(",")
            p1, p2 = (float(lx), float(ly)), (float(rx), float(ry))
            le, re = sorted((p1, p2))  # image-left eye first
            gt[name] = {"split": split, "le": le, "re": re}
    return gt


def eye_error(f, le, re):
    """Min mean eye distance over both YuNet eye-landmark orderings,
    normalized by GT inter-ocular distance."""
    e1, e2 = f[4:6], f[6:8]
    le, re = np.asarray(le), np.asarray(re)
    iod = np.linalg.norm(re - le) + 1e-9
    d = min(np.linalg.norm(e1 - le) + np.linalg.norm(e2 - re),
            np.linalg.norm(e1 - re) + np.linalg.norm(e2 - le)) / 2
    return float(d / iod)


def verification_pairs(by_id, n_pairs, seed):
    ids = sorted(i for i in by_id if len(by_id[i]) >= 2)
    all_ids = sorted(i for i in by_id if by_id[i])
    rng = random.Random(seed)
    pairs = []
    while len(pairs) < n_pairs:
        i = rng.choice(ids)
        a, b = rng.sample(by_id[i], 2)
        pairs.append((a, b, 1))
    while len(pairs) < 2 * n_pairs:
        i, j = rng.sample(all_ids, 2)
        pairs.append((rng.choice(by_id[i]), rng.choice(by_id[j]), 0))
    return pairs


def score_pairs(embs, pairs):
    scores, labels = [], []
    for a, b, l in pairs:
        if a in embs and b in embs:
            scores.append(float(embs[a] @ embs[b]))
            labels.append(l)
    r = roc_metrics(scores, labels)
    r["pairs_used"] = len(scores)
    return r


def run_cbsr(cbsr_dir, det, models, adapter, n_pairs=3000, seed=42):
    img_dir = cbsr_dir / "NIR_face_dataset" / "NIR_face_dataset"
    gt = load_cbsr_gt(cbsr_dir)
    names = sorted(gt)

    chips, det_stat = {}, {"detected": 0, "eyes_in_box": 0,
                           "gt_fallback": 0, "eye_err": []}
    for n in names:
        img = cv2.imread(str(img_dir / n))
        if img is None:
            continue
        f = det.largest_face(img)
        le, re = gt[n]["le"], gt[n]["re"]
        if f is not None:
            det_stat["detected"] += 1
            x, y, w, h = f[:4]
            if all(x <= px <= x + w and y <= py <= y + h
                   for px, py in (le, re)):
                det_stat["eyes_in_box"] += 1
            det_stat["eye_err"].append(eye_error(f, le, re))
            M = estimate_norm(f[4:14].reshape(5, 2))
        else:
            det_stat["gt_fallback"] += 1
            M = two_point_norm(le, re)
        chips[n] = cv2.warpAffine(img, M, (112, 112), flags=cv2.INTER_LINEAR)

    total = len(names)
    detection = {
        "images": total,
        "detect_rate": det_stat["detected"] / total,
        "gt_eyes_in_box_rate": det_stat["eyes_in_box"] / total,
        "gt_align_fallbacks": det_stat["gt_fallback"],
        "eye_nme_mean": float(np.mean(det_stat["eye_err"])),
        "eye_nme_p95": float(np.percentile(det_stat["eye_err"], 95)),
    }
    print(f"[CBSR det] detect={detection['detect_rate']:.4f} "
          f"eyes_in_box={detection['gt_eyes_in_box_rate']:.4f} "
          f"eye_nme={detection['eye_nme_mean']:.4f} "
          f"fallbacks={det_stat['gt_fallback']}", flush=True)

    variants = {n: {k: m.embed(c) for k, c in chips.items()}
                for n, m in models.items()}
    if adapter is not None and "auraface" in variants:
        variants["auraface+ir_adapter_v3"] = {
            k: adapter.apply(e) for k, e in variants["auraface"].items()}

    by_id = {}
    for n in names:
        by_id.setdefault(n.split("-")[0], []).append(n)
    pairs = verification_pairs(by_id, n_pairs, seed)

    gal = {}
    for n in names:
        if gt[n]["split"] == "gallery":
            gal.setdefault(n.split("-")[0], []).append(n)
    probes = [n for n in names if gt[n]["split"] == "probe"
              and n.split("-")[0] in gal]

    results = {"detection": detection}
    for vname, embs in variants.items():
        r = {"verification": score_pairs(embs, pairs)}
        tmpl_ids = sorted(gal)
        T = np.stack([np.mean([embs[n] for n in gal[i]], 0) for i in tmpl_ids])
        T /= np.linalg.norm(T, axis=1, keepdims=True) + 1e-9
        hits = sum(tmpl_ids[int(np.argmax(T @ embs[p]))] == p.split("-")[0]
                   for p in probes)
        r["rank1_ident"] = {"acc": hits / len(probes), "probes": len(probes),
                            "gallery_ids": len(tmpl_ids)}
        results[vname] = r
        v = r["verification"]
        print(f"[CBSR] {vname}: EER={v['eer']:.4f} "
              f"TAR@1e-3={v['tar@far0.001']:.4f} "
              f"rank1={r['rank1_ident']['acc']:.4f}", flush=True)
    return results


def collect_tufts(tufts_dir, modality):
    base = tufts_dir / f"td-{modality}-a" / f"td-{modality}-a"
    out = {}  # identity -> [paths]
    for setdir in sorted(base.iterdir()):
        for subj in sorted(p for p in setdir.iterdir() if p.is_dir()):
            ident = f"{setdir.name.split('Set')[-1]}/{subj.name}"
            out[ident] = sorted(subj.glob("*.png"))
    return out


def embed_tufts(paths_by_id, det, models, adapter, adapter_on):
    """Returns {variant: {key: emb}}, key = 'id|filename'. Also detect rate."""
    chips, nodet, total = {}, 0, 0
    for ident, paths in paths_by_id.items():
        for p in paths:
            total += 1
            img = cv2.imread(str(p))
            f = None if img is None else det.largest_face(img)
            if f is None:
                nodet += 1
                continue
            M = estimate_norm(f[4:14].reshape(5, 2))
            chips[f"{ident}|{p.name}"] = cv2.warpAffine(
                img, M, (112, 112), flags=cv2.INTER_LINEAR)
    variants = {n: {k: m.embed(c) for k, c in chips.items()}
                for n, m in models.items()}
    if adapter is not None and adapter_on and "auraface" in variants:
        variants["auraface+ir_adapter_v3"] = {
            k: adapter.apply(e) for k, e in variants["auraface"].items()}
    return variants, {"images": total, "detected": total - nodet,
                      "detect_rate": (total - nodet) / total}


def run_tufts(tufts_dir, det, models, adapter, n_pairs=3000, seed=42,
              imp_per_probe=10):
    rgb_ids = collect_tufts(tufts_dir, "rgb")
    nir_ids = collect_tufts(tufts_dir, "nir")

    nir_v, nir_det = embed_tufts(nir_ids, det, models, adapter, adapter_on=True)
    rgb_v, rgb_det = embed_tufts(rgb_ids, det, models, adapter, adapter_on=False)
    print(f"[Tufts det] rgb={rgb_det['detect_rate']:.4f} "
          f"nir={nir_det['detect_rate']:.4f}", flush=True)
    results = {"detection": {"rgb": rgb_det, "nir": nir_det}}

    # Same-modality verification, seeded pairs.
    for tag, variants in (("nir_nir", nir_v), ("rgb_rgb", rgb_v)):
        by_id = {}
        for k in next(iter(variants.values())):
            by_id.setdefault(k.split("|")[0], []).append(k)
        pairs = verification_pairs(by_id, n_pairs, seed)
        results[tag] = {v: score_pairs(embs, pairs)
                        for v, embs in variants.items()}
        for v, r in results[tag].items():
            print(f"[Tufts {tag}] {v}: EER={r['eer']:.4f} "
                  f"TAR@1e-3={r['tar@far0.001']:.4f}", flush=True)

    # Cross-spectral: RGB templates (raw recognizer), NIR probes (variant).
    rng = random.Random(seed)
    results["cross_spectral_rgb_enroll_nir_verify"] = {}
    for vname, nembs in nir_v.items():
        base = "buffalo_w600k_r50" if vname == "buffalo_w600k_r50" else "auraface"
        tmpl = {}
        for k, e in rgb_v[base].items():
            tmpl.setdefault(k.split("|")[0], []).append(e)
        tmpl = {i: v / (np.linalg.norm(v) + 1e-9)
                for i, v in ((i, np.mean(es, 0)) for i, es in tmpl.items())}
        ids = sorted(tmpl)
        scores, labels = [], []
        for k, e in nembs.items():
            ident = k.split("|")[0]
            if ident not in tmpl:
                continue
            scores.append(float(e @ tmpl[ident]))
            labels.append(1)
            for j in rng.sample([i for i in ids if i != ident], imp_per_probe):
                scores.append(float(e @ tmpl[j]))
                labels.append(0)
        r = roc_metrics(scores, labels)
        r.update({"genuine": int(sum(labels)),
                  "impostor": int(len(labels) - sum(labels))})
        results["cross_spectral_rgb_enroll_nir_verify"][vname] = r
        print(f"[Tufts xspec] {vname}: EER={r['eer']:.4f} "
              f"TAR@1e-3={r['tar@far0.001']:.4f} TAR@1e-2={r['tar@far0.01']:.4f}",
              flush=True)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--cbsr", type=Path)
    ap.add_argument("--tufts", type=Path)
    ap.add_argument("--out", type=Path, default=Path("bench_nir_results.json"))
    a = ap.parse_args()

    have_cuda = "CUDAExecutionProvider" in ort.get_available_providers()
    prov = (["CUDAExecutionProvider", "CPUExecutionProvider"]
            if have_cuda else ["CPUExecutionProvider"])
    print(f"onnxruntime {ort.__version__} cuda={have_cuda}", flush=True)

    det = DetectorFull(a.models_dir / "face_detection_yunet_2023mar.onnx")
    models = {
        "auraface": Embedder(a.models_dir / "glintr100.onnx", 128.0, prov),
        "buffalo_w600k_r50": Embedder(a.models_dir / "w600k_r50.onnx", 127.5, prov),
    }
    adapter_path = a.models_dir / "ir_adapter.onnx"
    adapter = Adapter(adapter_path, prov) if adapter_path.exists() else None

    results = {"ort": ort.__version__, "cuda": have_cuda}
    if a.cbsr:
        results["cbsr_nir"] = run_cbsr(a.cbsr, det, models, adapter)
    if a.tufts:
        results["tufts"] = run_tufts(a.tufts, det, models, adapter)
    a.out.write_text(json.dumps(results, indent=2))
    print(f"wrote {a.out}", flush=True)


if __name__ == "__main__":
    main()
