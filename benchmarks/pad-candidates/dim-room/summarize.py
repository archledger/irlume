#!/usr/bin/env python3
"""Tables for docs/research/2026-10-21-vit-dim-room-cue-evaluation.md.

Per arm: frame median and p90 of P(spoof); the paired shift (median over
images of the arm's score minus the same image's baseline score); the share of
frames at or above the deny line, which is also the refusal rate if a
presentation's five frames all scored alike; and "5-median refused", an i.i.d.
bootstrap (fixed seed) of the shipped decision, the median of VOTE_N frames
drawn with replacement from that arm reaching the deny line, which is the
refusal rate if they were independent. These are two reference cases; a real
presentation's refusal rate depends on how its frames covary and need not
fall between them.

--recorded <vit-lfw-scores.csv> also summarizes the recorded 2026-08-21 LFW
m96 scores: distribution, and the share of five-frame groups refused when a
uniform shift is added to every frame score, both for the i.i.d. bootstrap and
for each identity's images taken in fives in file order (different photos of
one person, so correlated like the frames of one presentation, though not the
same thing), with i.i.d. draws from those same frames for comparison. Before
that table, one line per deny line in LINES (cited by the ADR-0013 amendment
of 2026-10-21): the share of images at or above it, in all and in the grouped
images; the per-identity groups whose median reaches it, the identities they
come from and how many of those have every group there; and the exact i.i.d.
rate on the grouped images, the binomial probability that three or more of
five independent draws reach it.

Usage: summarize.py <scores.csv> [<scores.csv> ...] [--recorded CSV]
           [--draws N] [--seed N]
"""
import argparse
import csv
import math
from collections import defaultdict

import numpy as np

DENY_LINE = 0.55  # VIT_PAD_THRESHOLD
VOTE_N = 5  # VIT_PAD_VOTE_N
SHIFTS = [0.0, 0.02, 0.03, 0.05, 0.08, 0.10]
LINES = [0.50, 0.52, 0.55, 0.60]


def refused(p, draws, rng):
    picks = rng.choice(p, size=(draws, VOTE_N), replace=True)
    return float((np.median(picks, axis=1) >= DENY_LINE).mean())


def iid_exact(p, line):
    # The median of VOTE_N (odd) independent draws reaches the line exactly
    # when more than half of them do.
    q = float((p >= line).mean())
    return sum(math.comb(VOTE_N, k) * q ** k * (1 - q) ** (VOTE_N - k)
               for k in range(VOTE_N // 2 + 1, VOTE_N + 1))


def recorded(path, draws, seed):
    by_id = defaultdict(list)
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            if r["note"] == "ok":
                by_id[r["frame"].rsplit("_", 1)[0]].append(float(r["p_spoof_m96"]))
    p = np.array([s for v in by_id.values() for s in v])
    print(f"== {path}: {len(p)} frames, {len(by_id)} identities")
    print(f"median {np.median(p):.4f} q90 {np.percentile(p, 90):.4f} q99 {np.percentile(p, 99):.4f}; "
          f"frames >= {DENY_LINE}: {(p >= DENY_LINE).mean() * 100:.2f}%")
    chunks = [v[i:i + VOTE_N] for v in by_id.values() for i in range(0, len(v) - VOTE_N + 1, VOTE_N)]
    groups = np.array([np.median(c) for c in chunks])
    # The groups keep only identities with five or more images; i.i.d. draws
    # from the same frames separate the grouping effect from that selection.
    sub = np.array([s for c in chunks for s in c])
    ids = sum(1 for v in by_id.values() if len(v) >= VOTE_N)
    print(f"per-identity groups of {VOTE_N}: {len(groups)} from {len(sub)} frames of {ids} identities; "
          f"median >= 0.60: {int((groups >= 0.60).sum())}")
    group_ids = [k for k, v in by_id.items() for _ in range(len(v) // VOTE_N)]
    for line in LINES:
        hit = groups >= line
        per_id = defaultdict(list)
        for g, h in zip(group_ids, hit, strict=True):
            per_id[g].append(bool(h))
        n_any = sum(any(v) for v in per_id.values())
        n_all = sum(all(v) for v in per_id.values())
        print(f"deny line {line:.2f}: images >= line "
              f"{(p >= line).mean() * 100:.2f}% (all), "
              f"{(sub >= line).mean() * 100:.2f}% (grouped); per-identity groups "
              f"{int(hit.sum())}/{len(groups)} from {n_any}/{ids} identities "
              f"({n_all} with every group); 5-median i.i.d. exact "
              f"{iid_exact(sub, line) * 100:.3g}% (grouped images)")
    for shift in SHIFTS:
        hit = int(((groups + shift) >= DENY_LINE).sum())
        all_iid = refused(p + shift, draws, np.random.default_rng(seed))
        sub_iid = refused(sub + shift, draws, np.random.default_rng(seed))
        print(f"shift +{shift:.2f}: frames >= {DENY_LINE} {((p + shift) >= DENY_LINE).mean() * 100:.1f}%, "
              f"5-median refused {all_iid * 100:.1f}% (i.i.d., all frames), "
              f"{sub_iid * 100:.1f}% (i.i.d., grouped frames), "
              f"{hit / len(groups) * 100:.1f}% ({hit}/{len(groups)}) per-identity groups")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="*")
    ap.add_argument("--recorded")
    ap.add_argument("--draws", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=1155)
    a = ap.parse_args()
    if a.recorded:
        recorded(a.recorded, a.draws, a.seed)
    for path in a.csv:
        scores = defaultdict(dict)
        noise = defaultdict(list)
        lumas = defaultdict(list)
        with open(path, newline="") as fh:
            for r in csv.DictReader(fh):
                key = (r["arm"], r["param"])
                scores[key][r["frame"]] = float(r["p_spoof"])
                noise[key].append(float(r["noise_std"]))
                lumas[key].append(float(r["luma"]))
        base = next(v for k, v in scores.items() if k[0] == "base")
        print(f"== {path}")
        print("| arm | param | n | noise std | luma | frame median | p90 | paired shift | "
              "frames >= 0.55 | 5-median refused |")
        print("|---|---|---|---|---|---|---|---|---|---|")
        for key, by_frame in scores.items():
            p = np.array(list(by_frame.values()))
            shift = np.median([s - base[f] for f, s in by_frame.items()])
            rng = np.random.default_rng(a.seed)
            print(f"| {key[0]} | {key[1]} | {len(p)} | {np.median(noise[key]):.1f} | "
                  f"{np.median(lumas[key]):.1f} | {np.median(p):.3f} | {np.percentile(p, 90):.3f} | "
                  f"{shift:+.3f} | {(p >= DENY_LINE).mean() * 100:.1f}% | "
                  f"{refused(p, a.draws, rng) * 100:.1f}% |")


if __name__ == "__main__":
    main()
