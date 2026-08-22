#!/usr/bin/env python3
"""SecureDark calibration + threshold sweep (ADR-0016 open measurement, offline arm).

Two DEPLOYMENT-SHAPED protocols the pairwise benchmark numbers never covered:

1. CBSR raw arm (197 ids, NIR-only): production scores best-of-N over an
   enrolled template set, not a single pair. Each id's frames split into
   enrollment (first N=11) and probes; genuine = max cosine over templates,
   impostor = every probe against every other id's set. Sweeps
   {0.55, 0.60, 0.635} flat and with the shipped scaled_threshold
   (0.015*log2(N)) for best-of-N, plus the raw mean-centroid arm.
   This measures the best-of-N FAR inflation the historical pairwise
   0.60 -> 2.7e-4 figure did not.
2. Tufts calibrated arm (paired RGB+NIR): mirrors Engine::ir_match exactly —
   fit the per-user ridge calibration (irlume-core calib.rs math,
   W = I + M.N) on k paired scans, calibrate probe AND templates, score
   best-of-N and calibrated-centroid; an impostor probe is calibrated BY THE
   VICTIM'S calibration, exactly as production. Sweeps lambda x k x
   thresholds; the no-calibration arm is the control.

Usage: securedark_sweep.py --cbsr DIR --tufts-rgb DIR --tufts-nir DIR \
         --models-dir DIR --out securedark_sweep.json
"""
import argparse, json, math
from pathlib import Path

import cv2
import numpy as np

from bench_faceid import ARCFACE_REF, Detector, Embedder, estimate_norm

N_ENROLL = 11          # production enrollment scale on the reference host.
                       # CBSR split is WITHIN-SESSION (first 11 sorted frames
                       # enroll, same-session frames probe): the genuine tail
                       # is optimistic vs cross-session probing, mirroring
                       # irlume's single-session production enrollment. Labeled
                       # so nobody reads it as a cross-session claim.
LAMBDAS = [None, 0.1, 0.5, 1.0]   # None = no calibration (control); 0.5 shipped
KS = [3, 5]            # calibration fit-pair counts (MIN_FIT_PAIRS=3 shipped)
THRESHOLDS = [0.55, 0.60, 0.635]
TEMPLATE_SCALE = 0.015  # irlume-core scaled_threshold step per log2(N)


def scaled_threshold(base, n):
    # Mirrors irlume-core scaled_threshold including its TEMPLATE_SCALE_MAX_BUMP
    # clamp (0.10): without it a large N_ENROLL would drift past production.
    return min(base + TEMPLATE_SCALE * math.log2(max(n, 1)), base + 0.10)


def normalize_rows(x):
    return x / (np.linalg.norm(x, axis=1, keepdims=True) + 1e-12)


def normalize_vec(x):
    return x / (np.linalg.norm(x) + 1e-12)


def fit_calibration(ir, rgb, lam):
    """irlume-core calib.rs: W = I + M.N, M = (A^T A + lam I)^-1 A^T, N = B-A.
    Rows L2-normalized first, exactly like calib.rs's normalize()."""
    A, B = normalize_rows(np.asarray(ir)), normalize_rows(np.asarray(rgb))
    d = A.shape[1]
    M = np.linalg.solve(A.T @ A + lam * np.eye(d), A.T)   # d x n
    N = B - A                                              # n x d
    return M, N


def apply_calibration(M, N, x):
    """calib.rs apply: y = normalize(x + (x.M).N); accepts a vector."""
    y = x + (x @ M) @ N
    return y / (np.linalg.norm(y) + 1e-12)


def far_frr(gen, imp, thr):
    gen, imp = np.asarray(gen), np.asarray(imp)
    return {"thr": round(thr, 4),
            "far": float((imp >= thr).mean()) if len(imp) else None,
            "frr": float((gen < thr).mean()) if len(gen) else None,
            "n_gen": len(gen), "n_imp": len(imp)}


def percentile_table(v):
    if v is None or len(v) == 0:
        return {}
    v = np.asarray(sorted(v))
    return {"min": float(v[0]), "p1": float(np.percentile(v, 1)),
            "p5": float(np.percentile(v, 5)), "p50": float(np.percentile(v, 50)),
            "mean": float(v.mean()), "max": float(v[-1])}


def embed_dir(det, emb, paths):
    """YuNet + 5pt ArcFace alignment + AuraFace, the shipped preprocessing."""
    out, misses = [], 0
    for p in paths:
        bgr = cv2.imread(str(p))
        if bgr is None:
            misses += 1
            continue
        lm = det.largest_face_landmarks(bgr)
        if lm is None:
            misses += 1
            continue
        M = estimate_norm(np.asarray(lm, dtype=np.float32))
        chip = cv2.warpAffine(bgr, M, (112, 112))
        out.append(emb.embed(chip))
    return out, misses


def cbsr_arm(det, emb, cbsr_dir):
    ids = {}
    for p in sorted(Path(cbsr_dir).glob("*.bmp")):
        ids.setdefault(p.name.split("-")[0], []).append(p)
    embs, miss = {}, 0
    for sid, paths in ids.items():
        e, m = embed_dir(det, emb, paths)
        miss += m
        if len(e) > N_ENROLL + 3:
            embs[sid] = normalize_rows(np.array(e))
    result = {"ids_used": len(embs), "detect_misses": miss,
              "n_enroll": N_ENROLL}
    enroll = {s: E[:N_ENROLL] for s, E in embs.items()}
    probes = {s: E[N_ENROLL:] for s, E in embs.items()}
    cents = {s: normalize_vec(T.mean(0)) for s, T in enroll.items()}
    for mode in ("best_of_n", "centroid"):
        gen, imp = [], []
        for sid, P in probes.items():
            T = enroll[sid] if mode == "best_of_n" else cents[sid][None, :]
            gen += list((P @ T.T).max(1))
            for oid in embs:
                if oid == sid:
                    continue
                O = enroll[oid] if mode == "best_of_n" else cents[oid][None, :]
                imp += list((P @ O.T).max(1))
        result[mode] = {
            "genuine": percentile_table(gen), "impostor": percentile_table(imp),
            "sweep": [
                {"flat": far_frr(gen, imp, t),
                 "scaled": far_frr(gen, imp, scaled_threshold(t, N_ENROLL))}
                for t in THRESHOLDS],
        }
    return result


def tufts_arm(det, emb, rgb_root, nir_root):
    rgb_paths, nir_paths = {}, {}
    for sub in Path(rgb_root).glob("**/TD_RGB_A_Set*"):
        for iddir in sorted(sub.iterdir()):
            if iddir.is_dir():
                rgb_paths.setdefault(iddir.name, []).extend(sorted(
                    p for p in iddir.iterdir()
                    if p.suffix.lower() in (".jpg", ".jpeg", ".png", ".bmp")))
    for sub in Path(nir_root).glob("**/TD_NIR_A_Set*"):
        for iddir in sorted(sub.iterdir()):
            if iddir.is_dir():
                nir_paths.setdefault(iddir.name, []).extend(sorted(
                    p for p in iddir.iterdir()
                    if p.suffix.lower() in (".jpg", ".jpeg", ".png", ".bmp")))
    prepared = {}
    for sid in sorted(set(rgb_paths) & set(nir_paths)):
        re_, rm = embed_dir(det, emb, rgb_paths[sid])
        ne_, nm = embed_dir(det, emb, nir_paths[sid])
        if len(re_) >= max(KS) + 1 and len(ne_) >= max(KS) + 2:
            prepared[sid] = {"rgb": normalize_rows(np.array(re_)),
                             "nir": normalize_rows(np.array(ne_))}
    result = {"ids_used": len(prepared)}
    arms = {}
    for lam in LAMBDAS:
        for k in KS:
            gen_b, imp_b, gen_c, imp_c = [], [], [], []
            # Per-id: calibrated templates + centroid under the id's own map.
            cal = {}
            for sid, D in prepared.items():
                A, B, rp = D["nir"][:k], D["rgb"][:k], D["nir"][k:]
                if lam is not None:
                    M, N = fit_calibration(A, B, lam)
                    ct = np.array([apply_calibration(M, N, t) for t in A])
                    cp = np.array([apply_calibration(M, N, p) for p in rp])
                    cal[sid] = (M, N, ct, cp, rp)
                else:
                    cal[sid] = (None, None, A, rp, rp)
            for sid, (M, N, ct, cp, rp) in cal.items():
                cen = normalize_vec(ct.mean(0))
                gen_b += list((cp @ ct.T).max(1))
                gen_c += list(cp @ cen)
                for oid, (OM, ON, oct_, ocp, orp) in cal.items():
                    if oid == sid:
                        continue
                    # Impostor probes are RAW faces scored by the VICTIM's
                    # engine: the victim's calibration applies to both the
                    # probe and the victim's templates, exactly as in
                    # ir_match_in. (A double-applied probe would inflate the
                    # impostor tail and flatter the calibration.)
                    if lam is not None:
                        op = np.array([apply_calibration(OM, ON, p) for p in rp])
                    else:
                        op = rp
                    oc2 = normalize_vec(oct_.mean(0))
                    imp_b += list((op @ oct_.T).max(1))
                    imp_c += list(op @ oc2)
            arms[f"lam={lam}_k={k}"] = {
                "best_of_n": {
                    "genuine": percentile_table(gen_b),
                    "impostor": percentile_table(imp_b),
                    "sweep": [far_frr(gen_b, imp_b, t) for t in THRESHOLDS],
                },
                "centroid": {
                    "genuine": percentile_table(gen_c),
                    "impostor": percentile_table(imp_c),
                    "sweep": [far_frr(gen_c, imp_c, t) for t in THRESHOLDS],
                },
            }
    result["arms"] = arms
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cbsr", required=True)
    ap.add_argument("--tufts-rgb", required=True)
    ap.add_argument("--tufts-nir", required=True)
    ap.add_argument("--models-dir", required=True)
    ap.add_argument("--out", default="securedark_sweep.json")
    a = ap.parse_args()

    det = Detector(str(Path(a.models_dir) / "face_detection_yunet_2023mar.onnx"))
    # std=128.0: the SHIPPED AuraFace preprocessing (px-127.5)/128.0, the
    # same value every auraface arm in this benchmark family uses.
    emb = Embedder(str(Path(a.models_dir) / "glintr100.onnx"), 128.0,
                   ["CPUExecutionProvider"])

    out = {"cbsr_raw": cbsr_arm(det, emb, a.cbsr),
           "tufts_calibrated": tufts_arm(det, emb, a.tufts_rgb, a.tufts_nir)}
    Path(a.out).write_text(json.dumps(out, indent=1))
    print("wrote", a.out)
    c = out["cbsr_raw"]
    print("CBSR ids:", c["ids_used"])
    for mode in ("best_of_n", "centroid"):
        print(f"  {mode}: gen p1={c[mode]['genuine'].get('p1'):.3f} "
              f"imp max={c[mode]['impostor'].get('max'):.3f}")
        for row in c[mode]["sweep"]:
            print("   ", row["flat"])


if __name__ == "__main__":
    main()
