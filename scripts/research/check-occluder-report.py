#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Recompute every number in the occluder report and check the report states it.

Companion to `analyze-landmark-relief.py`, which cannot consume these corpora:
it asserts the relief populations and refuses a zero denominator, and a zero
chin is the central observation here.

Tables are rendered and matched as whole blocks rather than value by value. A
figure that also appears in surrounding prose defeats a substring search, which
is how an edited table cell once passed the sibling checker.

Usage:
  check-occluder-report.py <relief.jsonl> <gate.jsonl> [--check <report.md>]
"""
import json
import statistics as st
import sys
from collections import Counter

EXPECTED_RELIEF = {"control_print": 20, "occluded_chin": 20, "cotton_chin": 19}
EXPECTED_GATE = {
    "occ-control-print": 6,
    "occ-polyester-chin": 6,
    "occ-cotton-chin": 6,
    "p235-genuine": 8,
}
# Face bands carried over from the relief report, which owns their derivation.
FACE_BANDS = {"cheek/chin": (2.580, 3.532), "forehead/chin": (3.910, 6.266)}


def load(path, expected, key):
    rows = [json.loads(line) for line in open(path)]
    seen = Counter(r[key] for r in rows)
    if seen != Counter(expected):
        raise SystemExit(f"{path}: population mismatch\n  got {dict(seen)}\n  want {expected}")
    return rows


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    relief = load(argv[1], EXPECTED_RELIEF, "condition")
    gate = load(argv[2], EXPECTED_GATE, "species")
    blocks, claims = [], []

    def med(cond, k):
        return st.median([r[k] for r in relief if r["condition"] == cond])

    bare = med("control_print", "chin")
    mat = [
        ("none (bare print) ", "control_print", "—"),
        ("black polyester cloth", "occluded_chin", None),
        ("black cotton sock", "cotton_chin", None),
    ]
    tbl = ["| chin covering | chin brightness (median) | vs bare print |", "|---|---|---|"]
    for label, cond, fixed in mat:
        v = med(cond, "chin")
        rel = fixed if fixed else f"{v / bare:.2f}x{' brighter' if v > bare else ''}"
        tbl.append(f"| {label.strip()} | {v:.1f} | {rel} |")
    print("material table:")
    print("\n".join("  " + r for r in tbl))
    blocks.append(("material table", "\n".join(tbl)))

    for cond, label in (("occluded_chin", "polyester"), ("control_print", "bare print")):
        v = st.median([r["chin"] / r["forehead"] for r in relief if r["condition"] == cond])
        claims.append(f"{v:.3f}" if cond == "control_print" else f"{v:.2f}")
        print(f"  chin/forehead {label}: {v:.3f}")

    cot = [r for r in relief if r["condition"] == "cotton_chin"]
    zeros = sum(1 for r in cot if r["chin"] == 0)
    finite = sorted(r["cheek"] / r["chin"] for r in cot if r["chin"] > 0)
    print(f"\ncotton: {zeros} of {len(cot)} frames at chin=0; {len(finite)} finite ratios")
    claims.append(", ".join(f"{v:.3f}" for v in finite[:-1]) + f" and {finite[-1]:.3f}")

    gate_rows = {s: [r["ir_center_edge_ratio"] for r in gate if r["species"] == s] for s in EXPECTED_GATE}
    acc = {s: sum(1 for r in gate if r["species"] == s and r["verdict"] == "Live") for s in EXPECTED_GATE}
    gtbl = ["| presentation | centre/edge ratio | accepted |", "|---|---|---|"]
    for s, label in (("occ-control-print", "bare print"), ("occ-polyester-chin", "print + polyester"),
                     ("occ-cotton-chin", "print + cotton"),
                     ("p235-genuine", "genuine face, same day, same camera")):
        v = gate_rows[s]
        gtbl.append(f"| {label} | {min(v):.2f}-{max(v):.2f} | {acc[s]}/{len(v)} |")
    print("\ngate table:")
    print("\n".join("  " + r for r in gtbl))
    blocks.append(("gate table", "\n".join(gtbl)))
    claims.append(f"{max(gate_rows['occ-cotton-chin']):.4f}")

    btbl = ["| cue | floor gate (>= face minimum) | band gate (inside the face range) |", "|---|---|---|"]
    for name, (lo, hi) in FACE_BANDS.items():
        num = name.split("/")[0]
        floor = band = 0
        for r in cot:
            if r["chin"] == 0:
                floor += 1  # unbounded ratio clears any floor, fails any band
                continue
            v = r[num] / r["chin"]
            floor += v >= lo
            band += lo <= v <= hi
        btbl.append(f"| {name} | accepts {floor} of {len(cot)} | accepts {band} of {len(cot)} |")
    print("\nfloor vs band:")
    print("\n".join("  " + r for r in btbl))
    blocks.append(("floor/band table", "\n".join(btbl)))

    fc = max(r["forehead"] / r["chin"] for r in cot if r["chin"] > 0)
    claims.append(f"{fc:.2f}")
    print(f"\nforehead/chin cotton maximum {fc:.2f} (face minimum {FACE_BANDS['forehead/chin'][0]})")

    if "--check" in argv:
        report = open(argv[argv.index("--check") + 1]).read()
        # Prose wraps, so values are matched against a whitespace-normalised
        # copy; tables never wrap and are matched against the raw text, which
        # is what makes a single edited cell fail.
        flowed = " ".join(report.split())
        missing = [c for c in claims if c not in flowed]
        bad = [n for n, t in blocks if t not in report]
        if missing or bad:
            print("\nCHECK FAILED")
            for m in missing:
                print(f"  value absent: {m}")
            for n, t in blocks:
                if t not in report:
                    print(f"  {n} does not match the data; expected:\n{t}")
            return 1
        print(f"\nCHECK OK: {len(claims)} values and {len(blocks)} rendered blocks match the report")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
