#!/usr/bin/env python3
# Live flrgb PAD scorer for the 2026-08-12 session (docs/research/
# 2026-08-12-flrgb-live-first-contact.md). Loads the definitions of
# flrgb_eval.py beside it (detect/align/infer) and scores both preprocessing
# variants. Pinned inputs, so "the pipeline used" is checkable:
#   flrgb model.onnx   sha256 e13b5543520b7770cd844266a939aedeaeab57811e26c0e57754c654f8bb7419
#   YuNet detector     sha256 8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4
#   flrgb_eval.py      sha256 2eb6e7a89b455252aca4aa2354ce2d8e499b9491512015ec7f458eae13e2a12f
# The model weights and detector are not committed (biometric-adjacent, large);
# they live in the local research store. This script plus the recorded hashes
# identify the exact pipeline that produced 2026-08-12-flrgb-live-scores.csv.
# Score the 2026-08-12 live session (genuine-desk + attack-print) through
# flrgb with BOTH preprocessing variants, reusing the 2026-08-07 harness's
# detect/align/infer functions unchanged (imported, not copied).
import sys, csv, glob, os
# Load ONLY the harness's definitions (model init + detect/align/infer):
# importing the module executes its corpus-scoring main body, five minutes
# of rework per run. Truncate the source at the first post-function
# top-level statement instead.
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "flrgb_eval.py")).read()
src = src[: src.index("\ndef frames():")]
import types  # noqa: E402
H = types.ModuleType("flrgb_defs")
H.__dict__["__file__"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flrgb_eval.py")
os.chdir(os.path.dirname(os.path.abspath(__file__)))
exec(compile(src, "flrgb_defs", "exec"), H.__dict__)

root = os.path.expanduser("~/irlume-research/2026-08-12-flrgb-live")
out = os.path.join(root, "live-scores.csv")
rows = []
for cond in ["genuine-desk", "genuine-lowlight", "attack-print"]:
    for fp in sorted(glob.glob(f"{root}/{cond}/rgb/*.ppm")):
        import cv2
        bgr = cv2.imread(fp, cv2.IMREAD_COLOR)
        bbox = H.detect(bgr)
        if bbox is None:
            rows.append([cond, os.path.basename(fp), "no-detect", "", ""])
            continue
        rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
        p96, _ = H.infer(rgb, bbox, 96)
        p16, _ = H.infer(rgb, bbox, 16)
        rows.append([cond, os.path.basename(fp), "ok", f"{p96:.4f}", f"{p16:.4f}"])
with open(out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["cond", "frame", "note", "p_fake_pad96", "p_fake_pad16"])
    w.writerows(rows)

# Summary
import statistics as st
for cond in ["genuine-desk", "genuine-lowlight", "attack-print"]:
    sel = [r for r in rows if r[0] == cond]
    ok = [r for r in sel if r[2] == "ok"]
    print(f"{cond}: {len(sel)} frames, {len(sel)-len(ok)} no-detect")
    for i, name in [(3, "pad96"), (4, "pad16")]:
        vs = [float(r[i]) for r in ok]
        if vs:
            print(f"  {name}: p_fake min {min(vs):.3f} median {st.median(vs):.3f} max {max(vs):.3f}")
