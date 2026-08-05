#!/usr/bin/env python3
"""Derive committable aggregates from raw calcapture floor sessions.

The raw jsonl records carry face embeddings, which are biometric templates and
never enter the repository. This script reduces them to counts, brightness
ranges and cosine-distribution statistics, which do. Regenerating
floor-aggregates.json:

    python3 derive-floor-aggregates.py <session-dir> > floor-aggregates.json

where <session-dir> holds the floor-*.jsonl files from the capture sessions.
"""
import glob
import itertools
import json
import math
import os
import sys


def cos(a, b):
    return sum(x * y for x, y in zip(a, b)) / (
        math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(x * x for x in b))
    )


def stats(v):
    s = sorted(v)
    n = len(s)
    return {
        "n": n,
        "min": round(s[0], 4),
        "p5": round(s[int(0.05 * (n - 1))], 4),
        "mean": round(sum(s) / n, 4),
        "max": round(s[-1], 4),
    }


def main(session_dir):
    runs = {}
    sets = {}
    for fn in sorted(glob.glob(os.path.join(session_dir, "floor-*.jsonl"))):
        name = os.path.basename(fn).replace("floor-", "").replace(".jsonl", "")
        lines = open(fn).readlines()
        hdr = json.loads(lines[0])
        recs = [json.loads(line) for line in lines[1:]]
        with_rgb = [r for r in recs if r.get("rgb_emb")]
        embs = [r["rgb_emb"] for r in with_rgb]
        sets[name] = embs
        entry = {
            "model_sha256": hdr["model_sha256"],
            "host": hdr["host"],
            "samples_captured": len(recs),
            "samples_with_rgb_face": len(embs),
            "rgb_brightness_range": [
                round(min(r["rgb_brightness"] for r in with_rgb), 1),
                round(max(r["rgb_brightness"] for r in with_rgb), 1),
            ]
            if with_rgb
            else None,
        }
        if len(embs) >= 2:
            entry["pairwise_genuine"] = stats(
                [cos(a, b) for a, b in itertools.combinations(embs, 2)]
            )
        runs[name] = entry

    desk = sets.get("buffalo-desk", [])
    for probe_name in ("buffalo-lamp", "buffalo-screenglow"):
        if desk and sets.get(probe_name):
            best = sorted(max(cos(p, t) for t in desk) for p in sets[probe_name])
            runs[probe_name]["best_of_n_vs_desk"] = {
                "n": len(best),
                "min": round(best[0], 4),
                "median": round(best[len(best) // 2], 4),
                "max": round(best[-1], 4),
                "clear_055": sum(1 for b in best if b >= 0.55),
                "clear_060": sum(1 for b in best if b >= 0.60),
            }

    doc = {
        "what": "Derived aggregates of the live genuine-floor calcapture sessions. "
        "The raw jsonl records carry face embeddings (biometric templates) and are "
        "deliberately NOT committed; these aggregates carry counts, brightness ranges "
        "and cosine-distribution statistics only.",
        "instrument": "irlume calcapture (production TTA embedding path), irlume b8313f4",
        "derivation": "docs/recognition-results/data/derive-floor-aggregates.py against the raw session directory",
        "runs": runs,
    }
    json.dump(doc, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
