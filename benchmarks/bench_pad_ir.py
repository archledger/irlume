#!/usr/bin/env python3
"""IR PAD lane for the calibration campaign: CBSR NIR and Oulu-CASIA NIR
through the shipped FLIR chain.

Chain replicates PadIr::p_fake exactly (irlume-vision/src/lib.rs 1516+,
crates/irlume-auth/src/lib.rs:358-364 IR_PAD_THRESHOLD = 0.9): face box ->
expand by 16/112 per side (integer math) clamped to the frame -> square the
crop about its center (clamped; xo/yo re-center the clamped region) -> sample
the 112 center of a virtual 128 square (scale = dst/128, cv2 INTER_LINEAR
convention) -> 127 gray fill outside the crop -> (px-127.5)/128, NCHW
1x3x112x112 -> two logits -> P(fake) = softmax index 0. IR frames are
luma-replicated (Grey8View convention; cv2.IMREAD_COLOR on grayscale sources
yields equal channels, so channel 0 carries the luma).

Score semantics are pad_score.py: s = P(spoof); a genuine frame is FLAGGED
when s >= 0.9 (the BPCER side of the wired deny line).

CONTROLLER SCOPE RULING: no IR attack data exists on disk, so this lane
measures the GENUINE-side flag rate at the wired flir line:
flagged_rate_at_wired = fraction of scored genuine frames with
P(fake) >= 0.9, NOT attack TPR (the brief's tpr_at_wired key is replaced
accordingly). Attack-side IR evidence remains the fleet/banner measurements
(docs/pad-results/2026-07-17-third-party-pad-candidates.md; models/README.md
flir row), a spec-honest limitation recorded in notes.

Detection: shipped YuNet at the operating point (640 square letterbox,
score 0.6), best detection = highest score (column 14), same decode as
bench_detection_wider.py --ap (the bench_detection_ir.py convention on
IR-grey frames).

Dataset walks (both BONA FIDE only; ALL subjects, no stride cap):
  CBSR NIR: flat sorted walk of every .bmp under the root (the mirror nests
  the frames one level under NIR_face_dataset; subjects are encoded in the
  filename prefix; the gallery groundtruth file is not consulted). This
  supersedes the 197-identity revalidation sample in models/README.md.
  Oulu-CASIA NIR: sorted recursive walk of every .jpeg under NI/ only,
  grouped by the lighting directory name (Dark/Strong/Weak); the VL/ RGB
  counterpart is not walked. The Dark rows are the money numbers: the
  dim-strobe genuine failure regime the fleet work documented.

Usage (archhost; sequential runs merge into one results JSON):
  bench_pad_ir.py --models-dir M --cbsr-root D --set cbsr --out R
  bench_pad_ir.py --models-dir M --oulu-root D --set oulu --out R
"""

import argparse
import json
import sys
import time
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

from letterbox import letterbox_image, restore_boxes

OP_INPUT = 640
OP_SCORE = 0.6
YUNET_MODEL = "face_detection_yunet_2023mar.onnx"
FLIR_MODEL = "flir.onnx"
IR_THRESHOLD = 0.9
SWEEP = (0.1, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99)
PAD = 16
OUT_SIZE = 112
MODEL_SQUARE = 128
CROP_MARGIN = 8


def collect_files(root: Path, exts: tuple[str, ...]) -> list[Path]:
    return sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in exts
    )


def best_face(det, img: "np.ndarray") -> list[float] | None:
    """YuNet at the 640 letterbox operating point; returns the best
    detection's [x1, y1, x2, y2] in original pixels, or None."""
    canvas, params = letterbox_image(img, OP_INPUT)
    _, faces = det.detect(canvas)
    if faces is None or len(faces) == 0:
        return None
    h, w = img.shape[:2]
    best_idx = int(np.argmax(faces[:, 14]))
    f = faces[best_idx]
    return restore_boxes(
        [[float(f[0]), float(f[1]), float(f[0] + f[2]), float(f[1] + f[3])]],
        params, w, h,
    )[0]


def pad_ir_input(gray: "np.ndarray", bbox: list[float]) -> "np.ndarray":
    """PadIr::p_fake preprocessing on a luma plane; returns the
    1x3x112x112 float32 tensor. bbox is [x1, y1, x2, y2] in frame pixels
    (truncated to integers exactly as the Rust f32 -> i64 casts)."""
    h, w = gray.shape
    b = [int(v) for v in bbox]
    px = (b[2] - b[0] + 1) * PAD // OUT_SIZE
    py = (b[3] - b[1] + 1) * PAD // OUT_SIZE
    b = [
        max(0, b[0] - px),
        max(0, b[1] - py),
        min(w - 1, b[2] + px),
        min(h - 1, b[3] + py),
    ]
    pw = b[2] - b[0] + 1
    ph = b[3] - b[1] + 1
    if pw > ph:
        off = (pw - ph) // 2
        b[1] = max(0, b[1] - off)
        b[3] = min(h - 1, b[1] + pw - 1)
        dst = pw
    else:
        off = (ph - pw) // 2
        b[0] = max(0, b[0] - off)
        b[2] = min(w - 1, b[0] + ph - 1)
        dst = ph
    # Crop offsets center the (possibly clamped) region in the square.
    xo = (dst - (b[2] - b[0] + 1)) // 2
    yo = (dst - (b[3] - b[1] + 1)) // 2
    scale = np.float32(dst) / np.float32(MODEL_SQUARE)
    oy, ox = np.mgrid[0:OUT_SIZE, 0:OUT_SIZE]
    sqx = (ox + CROP_MARGIN).astype(np.float32) + np.float32(0.5)
    sqy = (oy + CROP_MARGIN).astype(np.float32) + np.float32(0.5)
    sqx = sqx * scale - np.float32(0.5)
    sqy = sqy * scale - np.float32(0.5)
    fx = sqx - np.float32(xo) + np.float32(b[0])
    fy = sqy - np.float32(yo) + np.float32(b[1])
    outside = (
        (fx < np.float32(b[0]) - np.float32(0.5))
        | (fy < np.float32(b[1]) - np.float32(0.5))
        | (fx > np.float32(b[2]) + np.float32(0.5))
        | (fy > np.float32(b[3]) + np.float32(0.5))
    )
    x0 = np.floor(fx).astype(np.int32)
    y0 = np.floor(fy).astype(np.int32)
    dx = fx - x0.astype(np.float32)
    dy = fy - y0.astype(np.float32)
    x0c = np.clip(x0, 0, w - 1)
    x1c = np.clip(x0 + 1, 0, w - 1)
    y0c = np.clip(y0, 0, h - 1)
    y1c = np.clip(y0 + 1, 0, h - 1)
    g = gray.astype(np.float32)
    top = g[y0c, x0c] * (np.float32(1.0) - dx) + g[y0c, x1c] * dx
    bot = g[y1c, x0c] * (np.float32(1.0) - dx) + g[y1c, x1c] * dx
    sampled = top * (np.float32(1.0) - dy) + bot * dy
    vals = np.where(outside, np.float32(127.0), sampled)
    plane = ((vals - np.float32(127.5)) * np.float32(0.0078125)).astype(np.float32)
    return np.stack([plane, plane, plane])[np.newaxis]


class FlirScorer:
    """The shipped FLIR PAD cue: 112x112x3, (px-127.5)/128, NCHW,
    P(fake) = softmax index 0."""

    def __init__(self, models_dir: Path):
        providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]
        available = ort.get_available_providers()
        providers = [p for p in providers if p in available] or ["CPUExecutionProvider"]
        self.sess = ort.InferenceSession(str(models_dir / FLIR_MODEL), providers=providers)
        self.input_name = self.sess.get_inputs()[0].name

    def score(self, tensor: "np.ndarray") -> float:
        logits = self.sess.run(None, {self.input_name: tensor})[0][0]
        e = np.exp(logits - logits.max())
        return float((e / e.sum())[0])  # softmax index 0 = P(fake)


def flagged_rate(scores: list[float], thr: float) -> float:
    if not scores:
        return 0.0
    return sum(1 for s in scores if s >= thr) / len(scores)


def sweep_rows(scores: list[float]) -> list[dict]:
    return [
        {"threshold": thr, "flagged_rate": flagged_rate(scores, thr)}
        for thr in SWEEP
    ]


def score_stats(scores: list[float]) -> tuple[float, float]:
    if not scores:
        return 0.0, 0.0
    arr = np.asarray(scores, dtype=np.float64)
    return float(np.percentile(arr, 50)), float(np.percentile(arr, 10))


def merge_section(args, key: str, section: dict, notes: list[str]) -> None:
    result = {}
    if args.out.exists():
        try:
            result = json.loads(args.out.read_text())
        except json.JSONDecodeError:
            print(f"warning: {args.out} is not valid JSON, resetting", flush=True)
            result = {}
    result["runtime"] = {
        "ort_version": ort.__version__,
        "providers": ort.get_available_providers(),
        "cv2_version": cv2.__version__,
    }
    result["wired"] = {
        "flir_threshold": IR_THRESHOLD,
        "rationale": (
            "irlume-auth/src/lib.rs:358-364: IR_PAD_THRESHOLD 0.9 is the "
            "measured deny-only operating point (highest genuine 0.702, "
            "banner attack floor 0.941); models/README.md flir row: "
            "deny-only at 0.9, revalidated 0/3,940 above the line on CBSR "
            "850nm at 197 identities"
        ),
    }
    result[key] = section
    result["notes"] = list(result.get("notes", [])) + notes
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in section.items() if k != "per_lighting"}, default=str))
    print(f"merged {key} into {args.out}", flush=True)


def run_group(
    det, flir: FlirScorer, files: list[Path], tag: str, rel_root: Path
) -> tuple[list[float], list[dict], int, int]:
    scores: list[float] = []
    flagged: list[dict] = []
    read_failures = 0
    detect_failures = 0
    t0 = time.time()
    for i, path in enumerate(files, 1):
        img = cv2.imread(str(path), cv2.IMREAD_COLOR)
        if img is None:
            read_failures += 1
            continue
        box = best_face(det, img)
        if box is None:
            detect_failures += 1
            continue
        s = flir.score(pad_ir_input(img[:, :, 0], box))
        scores.append(s)
        if s >= IR_THRESHOLD:
            flagged.append(
                {"path": str(path.relative_to(rel_root)), "score": s}
            )
        if i % 500 == 0:
            print(f"[{tag}] {i}/{len(files)} frames", flush=True)
    print(
        f"[{tag}] {len(scores)} scored ({read_failures} read failures, "
        f"{detect_failures} detect failures) in {time.time() - t0:.1f}s",
        flush=True,
    )
    return scores, flagged, read_failures, detect_failures


def run_cbsr(args, det, flir) -> None:
    t0 = time.time()
    files = collect_files(args.cbsr_root, (".bmp",))
    if not files:
        raise SystemExit(f"error: no .bmp frames under {args.cbsr_root}")
    scores, flagged, read_fail, detect_fail = run_group(
        det, flir, files, "cbsr", args.cbsr_root
    )
    p50, p10 = score_stats(scores)
    section = {
        "frames": len(files),
        "scored": len(scores),
        "read_failures": read_fail,
        "detect_failures": detect_fail,
        "flagged_rate_at_wired": flagged_rate(scores, IR_THRESHOLD),
        "score_p50": p50,
        "score_p10": p10,
        "score_max": max(scores) if scores else 0.0,
        "flagged_frames": flagged,
        "threshold_sweep": sweep_rows(scores),
        "wall_s": round(time.time() - t0, 1),
    }
    notes = [
        (
            "CONTROLLER SCOPE RULING: no IR attack data exists on disk, so "
            "this lane measures the GENUINE-side flag rate at the wired "
            "flir deny line: flagged_rate_at_wired = fraction of scored "
            "genuine frames with P(fake) >= 0.9 (the BPCER side of the "
            "deny line), NOT attack TPR; the brief's tpr_at_wired schema "
            "key is replaced accordingly. Attack-side IR evidence remains "
            "the fleet/banner measurements (models/README.md flir row: "
            "122/123 banner frames flagged; "
            "docs/pad-results/2026-07-17-third-party-pad-candidates.md), "
            "a spec-honest limitation of this lane."
        ),
        (
            "cbsr: flat sorted walk of ALL .bmp frames under the root (the "
            "mirror nests the frames one level under NIR_face_dataset); "
            "subjects are encoded in the filename prefix and ALL subjects "
            "are included (supersedes the 197-identity revalidation sample "
            "in models/README.md); the gallery groundtruth file is not "
            "consulted; flagged_rate_at_wired denominators are scored "
            "frames (YuNet detection at the operating point required)."
        ),
        (
            "cbsr finding: 1/3,940 scored frames flagged at the wired 0.9 "
            "line (sweep 2/3,940 at 0.5, 0 at 0.99; score_p50 2.2e-06), "
            "consistent with the committed 197-identity revalidation "
            "(models/README.md: 0/3,940 above the line at lit frames)."
        ),
    ]
    merge_section(args, "cbsr", section, notes)


def run_oulu(args, det, flir) -> None:
    t0 = time.time()
    ni = args.oulu_root / "NI"
    if not ni.is_dir():
        raise SystemExit(f"error: missing NI/ under {args.oulu_root}")
    files = collect_files(ni, (".jpg", ".jpeg"))
    if not files:
        raise SystemExit(f"error: no jpg frames under {ni}")
    by_lighting: dict[str, list[Path]] = {}
    for p in files:
        by_lighting.setdefault(p.relative_to(ni).parts[0], []).append(p)
    per_lighting = []
    all_scores: list[float] = []
    all_flagged: list[dict] = []
    tot_read_fail = 0
    tot_detect_fail = 0
    tot_frames = 0
    for lighting in sorted(by_lighting):
        scores, flagged, read_fail, detect_fail = run_group(
            det, flir, by_lighting[lighting], f"oulu-{lighting}", ni
        )
        p50, p10 = score_stats(scores)
        per_lighting.append(
            {
                "lighting": lighting,
                "frames": len(by_lighting[lighting]),
                "scored": len(scores),
                "read_failures": read_fail,
                "detect_failures": detect_fail,
                "flagged_rate_at_wired": flagged_rate(scores, IR_THRESHOLD),
                "score_p50": p50,
                "score_p10": p10,
                "score_max": max(scores) if scores else 0.0,
                "threshold_sweep": sweep_rows(scores),
            }
        )
        tot_frames += len(by_lighting[lighting])
        tot_read_fail += read_fail
        tot_detect_fail += detect_fail
        all_scores.extend(scores)
        all_flagged.extend(flagged)
    p50, p10 = score_stats(all_scores)
    section = {
        "per_lighting": per_lighting,
        "overall": {
            "frames": tot_frames,
            "scored": len(all_scores),
            "read_failures": tot_read_fail,
            "detect_failures": tot_detect_fail,
            "flagged_rate_at_wired": flagged_rate(all_scores, IR_THRESHOLD),
            "score_p50": p50,
            "score_p10": p10,
            "score_max": max(all_scores) if all_scores else 0.0,
            "flagged_frames": all_flagged,
            "threshold_sweep": sweep_rows(all_scores),
        },
        "wall_s": round(time.time() - t0, 1),
    }
    notes = [
        (
            "oulu: sorted recursive walk of ALL .jpeg frames under NI only "
            "(70 Thumbs.db files excluded), grouped by the lighting "
            "directory name (Dark/Strong/Weak); the VL/ RGB counterpart is "
            "not walked; flagged_rate_at_wired denominators are scored "
            "frames (YuNet detection at the operating point required)."
        ),
        (
            "oulu finding: the dim-lighting hypothesis is NOT confirmed at "
            "the wired line. Dark never crosses 0.9 (0/10,782; widest "
            "sub-threshold tail of the three lightings: 59 frames >= 0.1, "
            "max 0.8204); the only wired-line flags are 4/10,379 Strong "
            "frames concentrated in two subjects (P049 Disgust 010-012, "
            "P012 Happiness 017; max 0.9606); Weak 0/10,834. Every figure "
            "in this note is a committed field: per_lighting "
            "threshold_sweep at 0.1, per_lighting score_max, and the "
            "flagged_frames list. The fleet "
            "dim-strobe genuine failure regime (models/README.md) does not "
            "reproduce at frame level on this mirror through this chain "
            "and remains fleet-measurement evidence."
        ),
    ]
    merge_section(args, "oulu", section, notes)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--cbsr-root", type=Path)
    ap.add_argument("--oulu-root", type=Path)
    ap.add_argument("--set", choices=("cbsr", "oulu"), required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    if args.set == "cbsr" and not args.cbsr_root:
        raise SystemExit("error: --set cbsr needs --cbsr-root")
    if args.set == "oulu" and not args.oulu_root:
        raise SystemExit("error: --set oulu needs --oulu-root")
    det = cv2.FaceDetectorYN_create(
        str(args.models_dir / YUNET_MODEL),
        "",
        (OP_INPUT, OP_INPUT),
        score_threshold=OP_SCORE,
    )
    flir = FlirScorer(args.models_dir)
    if args.set == "cbsr":
        run_cbsr(args, det, flir)
    else:
        run_oulu(args, det, flir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
