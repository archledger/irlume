#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Recompute every number published in the landmark-relief report.

The report's tables are claims about a corpus. This regenerates them from the
committed JSONL and, with --check, asserts the report still states what the
data says, so a transposed index or an edited figure fails instead of being
believed.

Usage:
  analyze-landmark-relief.py <corpus.jsonl> [--check <report.md>]
"""
import json
import statistics as st
import sys
from collections import Counter

# The populations the report describes. Asserted before anything is computed:
# a corpus quietly missing a condition would otherwise produce narrower ranges
# that still look like a result.
EXPECTED = {
    ("2026-08-02", "face_glasses"): 54,
    ("2026-08-02", "face_no_glasses"): 108,
    ("2026-08-02", "banner_flat"): 54,
    ("2026-08-02", "banner_tilted"): 108,
    ("2026-08-02", "banner_close"): 108,
    ("2026-08-04", "face_dim"): 15,
    ("2026-08-04", "banner_curved"): 15,
}
REQUIRED = {
    "face_mean", "cheek", "forehead", "chin", "socket",
    "socket_deep", "brow", "nose", "session", "condition", "frame",
}
FACE = {"face_glasses", "face_no_glasses", "face_dim"}

RATIOS = {
    "cheek/chin": lambda r: r["cheek"] / r["chin"],
    "forehead/chin": lambda r: r["forehead"] / r["chin"],
    "nose/socket": lambda r: r["nose"] / r["socket"],
    "brow/socket_deep": lambda r: r["brow"] / r["socket_deep"],
}


def load(path):
    rows = [json.loads(line) for line in open(path)]
    for r in rows:
        missing = REQUIRED - r.keys()
        if missing:
            raise SystemExit(f"frame {r.get('frame')}: missing {sorted(missing)}")
        for k in ("chin", "socket", "socket_deep", "cheek", "forehead", "nose"):
            if r[k] <= 0:
                raise SystemExit(f"frame {r.get('frame')}: {k} is {r[k]}, cannot form a ratio")
    seen = Counter((r["session"], r["condition"]) for r in rows)
    if seen != Counter(EXPECTED):
        raise SystemExit(f"population mismatch\n  got      {dict(seen)}\n  expected {EXPECTED}")
    return rows


def rng(vals):
    return min(vals), max(vals)


def corr(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = sum((x - mx) ** 2 for x in xs) ** 0.5
    dy = sum((y - my) ** 2 for y in ys) ** 0.5
    return num / (dx * dy) if dx and dy else 0.0


def fit(xs, ys):
    """Least-squares slope and intercept, for the risk-direction bound."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    return my - b * mx, b


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    rows = load(argv[1])
    faces = [r for r in rows if r["condition"] in FACE]
    prints_ = [r for r in rows if r["condition"] not in FACE]
    claims = []

    print(f"corpus: {len(rows)} frames ({len(faces)} face, {len(prints_)} print)")
    print("\nexposure (face-region mean) by set")
    for key in [("2026-08-02", FACE), ("2026-08-04", {"face_dim"}),
                ("2026-08-02", None), ("2026-08-04", {"banner_curved"})]:
        sess, conds = key
        sel = [r for r in rows if r["session"] == sess and
               ((r["condition"] in conds) if conds else r["condition"] not in FACE)]
        lo, hi = rng([r["face_mean"] for r in sel])
        label = f"{sess} {'face' if conds and 'face' in next(iter(conds)) else 'print'}"
        print(f"  {label:20} n={len(sel):3}  {lo:.1f}-{hi:.1f}")
        claims += [f"{lo:.1f}-{hi:.1f}"]

    print("\nratios: face vs print across both sessions")
    for name, f in RATIOS.items():
        fa = [f(r) for r in faces]
        pr = [f(r) for r in prints_]
        flo, fhi = rng(fa)
        plo, phi = rng(pr)
        sep = flo - phi if flo > phi else (plo - fhi if plo > fhi else None)
        verdict = f"separated by {sep:.3f}" if sep else "OVERLAP"
        print(f"  {name:18} face {flo:.3f}-{fhi:.3f}  print {plo:.3f}-{phi:.3f}  {verdict}")
        claims += [f"{flo:.3f}-{fhi:.3f}", f"{plo:.3f}-{phi:.3f}"]
        if sep:
            claims.append(f"{sep:.3f}")

    print("\nregion medians (the mechanism, before any ratio)")
    for label, sel in (("face", faces), ("print", prints_)):
        med = {k: st.median([r[k] for r in sel]) for k in ("cheek", "forehead", "chin")}
        ratio = st.median([r["chin"] / r["cheek"] for r in sel])
        print(f"  {label:6} cheek {med['cheek']:6.1f}  forehead {med['forehead']:6.1f}  "
              f"chin {med['chin']:5.1f}  chin/cheek {ratio:.3f}")
        claims += [f"{med['cheek']:.1f}", f"{med['forehead']:.1f}", f"{med['chin']:.1f}", f"{ratio:.3f}"]

    print("\nper-condition")
    for (sess, cond), _ in sorted(EXPECTED.items()):
        sel = [r for r in rows if r["session"] == sess and r["condition"] == cond]
        cc = rng([RATIOS["cheek/chin"](r) for r in sel])
        fc = rng([RATIOS["forehead/chin"](r) for r in sel])
        print(f"  {sess} {cond:16} n={len(sel):3}  cheek/chin {cc[0]:.3f}-{cc[1]:.3f}  "
              f"forehead/chin {fc[0]:.3f}-{fc[1]:.3f}")
        claims += [f"{cc[0]:.3f}-{cc[1]:.3f}", f"{fc[0]:.3f}-{fc[1]:.3f}"]

    print("\nrisk direction: face trend extrapolated to the print ceiling")
    for name in ("cheek/chin", "forehead/chin"):
        f = RATIOS[name]
        xs = [r["face_mean"] for r in faces]
        ys = [f(r) for r in faces]
        a, b = fit(xs, ys)
        ceiling = max(f(r) for r in prints_)
        cross = (ceiling - a) / b
        print(f"  {name:14} ratio = {a:.3f} {b:+.4f}*exposure; print ceiling "
              f"{ceiling:.3f} reached at exposure {cross:.0f}")
        claims += [f"{a:.3f}", f"{b:+.4f}", f"{cross:.0f}"]

    print("\nexposure correlation within class (why the socket ratios fail)")
    for name in ("brow/socket_deep", "nose/socket"):
        f = RATIOS[name]
        dim = [r for r in rows if r["condition"] == "face_dim"]
        print(f"  {name:18} dim face r={corr([r['face_mean'] for r in dim], [f(r) for r in dim]):+.2f}  "
              f"range {rng([f(r) for r in dim])[0]:.3f}-{rng([f(r) for r in dim])[1]:.3f}")

    if "--check" in argv:
        report = open(argv[argv.index("--check") + 1]).read()
        missing = [c for c in claims if c not in report]
        if missing:
            print(f"\nCHECK FAILED: {len(missing)} computed value(s) absent from the report:")
            for m in sorted(set(missing)):
                print(f"  {m}")
            return 1
        print(f"\nCHECK OK: all {len(set(claims))} distinct computed values appear in the report")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
