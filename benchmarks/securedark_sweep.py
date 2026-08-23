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
THRESHOLDS_V2 = [0.55, 0.575, 0.60, 0.615, 0.625, 0.635, 0.65]  # dark-path grid


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


def cbsr_embeddings(det, emb, cbsr_dir, cache=None):
    """Embed the CBSR corpus once; optionally cache to a .npz so sweep
    iterations do not re-pay ~4k inference passes. Returns {sid: (n,d)
    L2-normalized matrix} for ids with more than N_ENROLL+3 usable frames."""
    cache_file = Path(cache) if cache else None
    if cache_file and cache_file.exists():
        z = np.load(cache_file, allow_pickle=True)
        return {s: z[s] for s in z.files}
    ids = {}
    for p in sorted(Path(cbsr_dir).glob("*.bmp")):
        ids.setdefault(p.name.split("-")[0], []).append(p)
    embs, miss = {}, 0
    for sid, paths in ids.items():
        e, m = embed_dir(det, emb, paths)
        miss += m
        if len(e) > N_ENROLL + 3:
            embs[sid] = normalize_rows(np.array(e))
    if cache_file:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        np.savez(cache_file, **embs)
    return embs


def cbsr_arm(embs):
    result = {"ids_used": len(embs), "detect_misses": None,
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


def cbsr_v2_arm(embs):
    """Deployment-shape operating point + multi-frame design inputs (ADR-0016
    open measurement, offline arm 2).

    Production's dark path grants on best-of-N at scaled_threshold(t,
    n_scans) OR the calibrated centroid at scaled_threshold(t, n_profiles).
    A CBSR id models ONE profile with N_ENROLL scans, so per base t:
    thr_b = t + 0.015*log2(11) ~ t+0.052, thr_c = t exactly. The separate
    per-arm sweeps above bound the OR from below only; this measures the OR.

    AND-of-2: a presentation is two CONSECUTIVE same-session probe frames
    (correlated, like a burst); it grants only if BOTH frames clear. CBSR
    cannot measure cross-session or cross-condition correlation — the live
    dark session still decides; this is the correlated-frame upper bound.

    Frame-pair cosines feed the multi-frame agreement constant design: the
    same-person-across-frames distribution that must not be guessed.
    """
    enroll = {s: E[:N_ENROLL] for s, E in embs.items()}
    probes = {s: E[N_ENROLL:] for s, E in embs.items()}
    cents = {s: normalize_vec(T.mean(0)) for s, T in enroll.items()}
    sids = sorted(embs)
    # Flat probe matrix with per-row owner, for vectorized per-victim scoring.
    rows, owner = [], []
    for sid in sids:
        for v in probes[sid]:
            rows.append(v)
            owner.append(sid)
    P = np.array(rows)
    owner = np.array(owner)
    # Per-victim arm scores for every probe frame.
    B = np.zeros((len(sids), len(rows)))
    C = np.zeros((len(sids), len(rows)))
    for vi, v in enumerate(sids):
        B[vi] = (P @ enroll[v].T).max(1)
        C[vi] = P @ cents[v]
    gen_mask = owner[None, :] == np.array(sids)[:, None]

    def frame_pass(t):
        thr_b = scaled_threshold(t, N_ENROLL)
        return (B >= thr_b) | (C >= t)          # OR arm, per frame

    def best_only_pass(t):
        return B >= scaled_threshold(t, N_ENROLL)

    def pres_rates(pass_mat):
        """AND-of-2 over consecutive same-owner frames. A presentation is an
        ATTACKER sid's consecutive probe pair scored against victim v; the
        pair grants only if BOTH frames pass v's condition."""
        idx_by_sid = {s: np.where(owner == s)[0] for s in sids}
        gen_pres = imp_pres = gen_pass = imp_pass = 0
        for vi, v in enumerate(sids):
            for s in sids:
                idx = idx_by_sid[s]
                for a, b in zip(idx[0::2], idx[1::2]):
                    both = bool(pass_mat[vi, a]) and bool(pass_mat[vi, b])
                    if s == v:
                        gen_pres += 1
                        gen_pass += both
                    else:
                        imp_pres += 1
                        imp_pass += both
        return {"far": imp_pass / imp_pres if imp_pres else None,
                "frr": 1 - gen_pass / gen_pres if gen_pres else None,
                "n_gen_pres": gen_pres, "n_imp_pres": imp_pres}

    # Single-frame OR rates per threshold (vectorized over the mask).
    rows_out = []
    for t in THRESHOLDS_V2:
        pf = frame_pass(t)
        rows_out.append({
            "thr": round(t, 4),
            "far": float(pf[~gen_mask].mean()),
            "frr": float((~pf)[gen_mask].mean()),
            "n_gen": int(gen_mask.sum()),
            "n_imp": int((~gen_mask).sum()),
        })
    or_arm = {
        "note": "grant = best_of_N >= t+0.015*log2(11) OR centroid >= t "
                "(1 profile); thresholds are the BASE t",
        "single_frame": rows_out,
        "and2": [dict(thr=round(t, 4), **pres_rates(frame_pass(t)))
                 for t in THRESHOLDS_V2],
        "and2_best_of_n_only": [
            dict(thr=round(t, 4), **pres_rates(best_only_pass(t)))
            for t in THRESHOLDS_V2],
    }

    # Frame-pair cosines: adjacent same-id frames (the same-person-across-
    # frames distribution) and a cross-id first-probe control.
    gen_pairs = []
    for s in sids:
        E = embs[s]
        gen_pairs += list(np.sum(E[:-1] * E[1:], 1))
    firsts = np.array([embs[s][N_ENROLL] for s in sids])
    imp_pairs = (firsts @ firsts.T)[np.triu_indices(len(sids), 1)]
    return {
        "or_arm": or_arm,
        "frame_pair_cosines": {
            "genuine_adjacent_frames": percentile_table(gen_pairs),
            "impostor_first_probes": percentile_table(imp_pairs),
        },
    }


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
    ap.add_argument("--cache", default=None,
                    help="npz path to cache/load CBSR embeddings")
    a = ap.parse_args()

    det = Detector(str(Path(a.models_dir) / "face_detection_yunet_2023mar.onnx"))
    # std=128.0: the SHIPPED AuraFace preprocessing (px-127.5)/128.0, the
    # same value every auraface arm in this benchmark family uses.
    emb = Embedder(str(Path(a.models_dir) / "glintr100.onnx"), 128.0,
                   ["CPUExecutionProvider"])

    embs = cbsr_embeddings(det, emb, a.cbsr, a.cache)
    out = {"cbsr_raw": cbsr_arm(embs),
           "cbsr_v2": cbsr_v2_arm(embs),
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
    v2 = out["cbsr_v2"]["or_arm"]
    print("  OR single-frame @0.60:", v2["single_frame"][2])
    print("  OR and2 @0.60:", v2["and2"][2])


if __name__ == "__main__":
    main()
