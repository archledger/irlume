#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Derive the committed landmark-relief corpus from landmark CSV directories.

The raw frames are infrared images of the operator's face and are deliberately
NOT committed, the same rule the PAD corpora follow. What a reader needs to
audit a relief claim is the per-frame REGION BRIGHTNESS, which carries no
image: this writes one JSON record per detected frame, and
`analyze-landmark-relief.py` recomputes every published number from it.

Usage:
  landmark-relief-corpus.py <out.jsonl> <session> <condition> <dir> [<session> <condition> <dir> ...]

Each <dir> holds frameNN.landmarks.csv files written by `landmark_dump` or
`landmark_replay`.
"""
import csv
import glob
import json
import os
import statistics as st
import sys

# Landmark indices per region. Verified against capture geometry rather than
# taken on trust (idx 1/4 at the horizontal centre, 10 top, 152 bottom, 33/263
# left and right), because a transposed index would silently redefine what the
# published ratios mean.
REGIONS = {
    "nose": [1, 4, 5, 195, 197],
    "cheek_l": [50, 101, 118, 117, 123],
    "cheek_r": [280, 330, 347, 346, 352],
    "socket_l": [33, 133, 159, 145, 153],
    "socket_r": [263, 362, 386, 374, 380],
    "socket_deep": [159, 145, 386, 374],
    "brow": [105, 66, 107, 336, 296, 334],
    "chin": [152, 148, 377, 176, 400],
    "forehead": [10, 151, 9, 8],
}


def frame_record(path):
    """Region means for one frame, or None when the CSV carries no landmarks."""
    bright = {}
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            bright[int(row["idx"])] = float(row["brightness"])
    if not bright:
        return None
    rec = {}
    for name, idxs in REGIONS.items():
        have = [bright[i] for i in idxs if i in bright]
        if len(have) != len(idxs):
            # A partial region would average a different set of points than the
            # published tables did; refuse rather than quietly rescale.
            raise SystemExit(f"{path}: region {name} missing landmarks")
        rec[name] = round(st.mean(have), 4)
    rec["cheek"] = round((rec["cheek_l"] + rec["cheek_r"]) / 2, 4)
    rec["socket"] = round((rec["socket_l"] + rec["socket_r"]) / 2, 4)
    rec["face_mean"] = round(st.mean(bright.values()), 4)
    return rec


def main(argv):
    if len(argv) < 5 or (len(argv) - 2) % 3 != 0:
        raise SystemExit(__doc__)
    out_path = argv[1]
    rows = []
    for i in range(2, len(argv), 3):
        session, condition, directory = argv[i], argv[i + 1], argv[i + 2]
        csvs = sorted(glob.glob(os.path.join(directory, "*.landmarks.csv")))
        if not csvs:
            raise SystemExit(f"{directory}: no landmark CSVs")
        for path in csvs:
            rec = frame_record(path)
            if rec is None:
                continue
            base = os.path.basename(path)
            rec.update(
                session=session,
                condition=condition,
                frame=int(base[len("frame") : base.index(".")]),
            )
            rows.append(rec)
    with open(out_path, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    print(f"{out_path}: {len(rows)} frames")


if __name__ == "__main__":
    main(sys.argv)
