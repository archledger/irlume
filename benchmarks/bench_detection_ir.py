#!/usr/bin/env python3
"""YuNet IR-grey detection benchmark on CBSR NIR and Oulu-CASIA NIR.

No ground truth boxes are scored: the bench reports YuNet detection
rate and score distribution at the irlume operating point (640 square
letterbox, score_threshold 0.6) on near-infrared frames. The decode
matches bench_detection_wider --ap: detector rows are x,y,w,h plus 5
landmarks with the score at column 14.

CBSR NIR is walked over sorted .bmp files; the mirror nests the frames
one level under NIR_face_dataset and subjects are encoded in filename
prefixes, so the walk is flat in practice and the gallery groundtruth
file is ignored. Oulu-CASIA NIR is walked recursively under NI only and
grouped by lighting directory name; the VL/ RGB counterpart is ignored.
Each dataset is capped at 4000 frames via stride sampling over the
sorted recursive file list; the stride and counts land in the notes.
"""

import argparse
import json
import math
import sys
import time
from pathlib import Path

import cv2
import numpy as np

from letterbox import letterbox_image

OP_INPUT = 640
OP_SCORE = 0.6
FRAME_CAP = 4000
YUNET_MODEL = "face_detection_yunet_2023mar.onnx"


def collect_files(root: Path, exts: tuple[str, ...]) -> list[Path]:
    return sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in exts
    )


def stride_sample(items: list[Path], target: int) -> tuple[list[Path], int]:
    stride = max(1, math.ceil(len(items) / target))
    return items[::stride], stride


def yunet_detector(model_path: Path, size: int, score_threshold: float):
    return cv2.FaceDetectorYN_create(
        str(model_path), "", (size, size), score_threshold=score_threshold
    )


def detect_scores(det, img, target: int) -> list[float]:
    """YuNet scores on the letterbox canvas: rows are x,y,w,h plus 5
    landmarks with the score at column 14, same decode as the wider
    bench --ap mode."""
    canvas, _ = letterbox_image(img, target)
    _, faces = det.detect(canvas)
    if faces is None:
        return []
    return [float(f[14]) for f in faces]


def score_stats(scores: list[float]) -> tuple[float, float]:
    if not scores:
        return 0.0, 0.0
    arr = np.asarray(scores, dtype=np.float64)
    return float(np.percentile(arr, 50)), float(np.percentile(arr, 10))


def _read_progress(i: int, total: int, tag: str) -> None:
    if i % 500 == 0:
        print(f"[{tag}] {i}/{total} frames", flush=True)


def run_group(det, files: list[Path], tag: str) -> tuple[dict, list[float], int]:
    frames = detected = read_failures = 0
    scores: list[float] = []
    t0 = time.time()
    for i, path in enumerate(files, 1):
        img = cv2.imread(str(path))
        if img is None:
            read_failures += 1
        else:
            frames += 1
            found = detect_scores(det, img, OP_INPUT)
            if found:
                detected += 1
                scores.extend(found)
        _read_progress(i, len(files), tag)
    p50, p10 = score_stats(scores)
    section = {
        "frames": frames,
        "detected": detected,
        "rate": detected / frames if frames else 0.0,
        "score_p50": p50,
        "score_p10": p10,
    }
    print(
        f"[{tag}] {detected}/{frames} frames with a face "
        f"({section['rate']:.4f}) in {time.time() - t0:.1f}s",
        flush=True,
    )
    return section, scores, read_failures


def run_cbsr(det, root: Path) -> tuple[dict, list[str]]:
    all_files = collect_files(root, (".bmp",))
    if not all_files:
        raise SystemExit(f"error: no .bmp frames under {root}")
    sample, stride = stride_sample(all_files, FRAME_CAP)
    section, scores, failures = run_group(det, sample, "cbsr")
    notes = [
        (
            f"cbsr run: {len(sample)} of {len(all_files)} bmp frames "
            f"(stride {stride}, nearest stride-integer approximation of "
            f"the {FRAME_CAP}-frame cap) in one flat sorted walk; the "
            "gallery groundtruth file is not consulted."
        ),
    ]
    if failures:
        notes.append(f"cbsr: {failures} unreadable frames skipped.")
    return section, notes


def run_oulu(det, root: Path) -> tuple[dict, list[str]]:
    ni = root / "NI"
    if not ni.is_dir():
        raise SystemExit(f"error: missing NI/ under {root}")
    all_files = collect_files(ni, (".jpg", ".jpeg"))
    if not all_files:
        raise SystemExit(f"error: no jpg frames under {ni}")
    sample, stride = stride_sample(all_files, FRAME_CAP)
    by_lighting: dict[str, list[Path]] = {}
    for p in sample:
        by_lighting.setdefault(p.relative_to(ni).parts[0], []).append(p)
    per_lighting = []
    tot_frames = tot_detected = tot_failures = 0
    all_scores: list[float] = []
    for lighting in sorted(by_lighting):
        section, scores, failures = run_group(
            det, by_lighting[lighting], f"oulu-{lighting}"
        )
        per_lighting.append(
            {
                "lighting": lighting,
                "frames": section["frames"],
                "rate": section["rate"],
            }
        )
        tot_frames += section["frames"]
        tot_detected += section["detected"]
        tot_failures += failures
        all_scores.extend(scores)
    p50, p10 = score_stats(all_scores)
    overall = {
        "frames": tot_frames,
        "detected": tot_detected,
        "rate": tot_detected / tot_frames if tot_frames else 0.0,
        "score_p50": p50,
        "score_p10": p10,
    }
    notes = [
        (
            f"oulu run: {len(sample)} of {len(all_files)} jpg frames under "
            f"NI (stride {stride}, nearest stride-integer approximation of "
            f"the {FRAME_CAP}-frame cap) in one sorted recursive walk, "
            "grouped by lighting directory name; the VL/ RGB counterpart "
            "is not walked."
        ),
    ]
    if tot_failures:
        notes.append(f"oulu: {tot_failures} unreadable frames skipped.")
    return {"per_lighting": per_lighting, "overall": overall}, notes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--cbsr-root", type=Path, required=True)
    ap.add_argument("--oulu-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    det = yunet_detector(args.models_dir / YUNET_MODEL, OP_INPUT, OP_SCORE)
    cbsr, cbsr_notes = run_cbsr(det, args.cbsr_root)
    oulu, oulu_notes = run_oulu(det, args.oulu_root)
    result = {
        "runtime": {
            "cv2_version": cv2.__version__,
            "yunet": YUNET_MODEL,
            "input": OP_INPUT,
            "score_threshold": OP_SCORE,
        },
        "cbsr": cbsr,
        "oulu": oulu,
        "notes": cbsr_notes + oulu_notes,
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["oulu"]["overall"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
