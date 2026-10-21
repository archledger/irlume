#!/usr/bin/env python3
"""ViT RGB PAD cue: exposure and capture-quality sensitivity on LFW, #1155.

Genuine LFW faces through the shipped cue's scorer contract (m96 crop,
INTER_LINEAR resize to 224, RGB, (px/255 - 0.5)/0.5, softmax index 1), with
one transform per arm applied to the m96 crop. Detection runs once on the
unmodified image, so the arms measure the PAD score, not the detector.

Passes:
  grain   : base; additive Gaussian grain sigma 3/6/10/15/20 (0-255 code units);
            linear scaling 0.32/0.14; JPEG quality 20. Default 200 images.
  photon  : base; Poisson shot noise in linear light plus Gaussian read noise,
            then sRGB encoding, at exposure 0.10/0.04/0.02; Gaussian blur
            sigma 1.5 px; contrast x0.5. Default 300 images.

REF_PHOTONS and READ_SIGMA are simulation parameters, not measured camera
constants. noise_std is the measured standard deviation, in 0-255 code units,
of the noisy crop minus the clean crop (0 for arms that add no noise). Each
image draws its noise from default_rng(1155 + index), so a rerun with the same
inputs writes the same rows.

Pinned inputs (verified at startup):
  liveness_vit.onnx                  c7f8a6f3054b11f9719f5e24d37ec227721608fff8b90373c6c3e7659864161c
  face_detection_yunet_2023mar.onnx  8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4

Usage: dim_room_score.py {grain,photon} <lfw-root> <out.csv>
           [--n-images N] [--workers N] [--models-dir DIR]
"""
import argparse
import csv
import hashlib
import multiprocessing as mp
from pathlib import Path

import cv2
import numpy as np

MODELS = Path(__file__).resolve().parents[3] / "models"
PINNED = {
    "liveness_vit.onnx": "c7f8a6f3054b11f9719f5e24d37ec227721608fff8b90373c6c3e7659864161c",
    "face_detection_yunet_2023mar.onnx": "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
}
M96 = 96.0 / 112.0
GRAIN_SIGMA = [3, 6, 10, 15, 20]
SCALES = [0.32, 0.14]
JPEG_Q = [20]
EXPOSURES = [0.10, 0.04, 0.02]
REF_PHOTONS = 200.0
READ_SIGMA = 2.0
BLUR_SIGMA = 1.5
CONTRAST = 0.5
DEFAULT_N = {"grain": 200, "photon": 300}


def require_numpy2():
    # NumPy 1.x promotes float32 bbox values times a Python float to float64,
    # which truncates some m96 crop bounds one pixel away from the shipped f32
    # arithmetic (benchmarks/preprocessing-conformance CROP_CASES).
    if int(np.__version__.split(".")[0]) < 2:
        raise SystemExit(f"numpy {np.__version__}: need numpy>=2.0 (benchmarks/requirements-bench.txt)")


def verify_models(models_dir):
    for name, want in PINNED.items():
        got = hashlib.sha256((models_dir / name).read_bytes()).hexdigest()
        if got != want:
            raise SystemExit(f"{name}: sha256 {got} != pinned {want}")


def _init(models_dir):
    global sess, inp, det
    import onnxruntime as ort
    so = ort.SessionOptions()
    so.intra_op_num_threads = 1
    so.inter_op_num_threads = 1
    sess = ort.InferenceSession(str(models_dir / "liveness_vit.onnx"), sess_options=so,
                                providers=["CPUExecutionProvider"])
    inp = sess.get_inputs()[0].name
    det = cv2.FaceDetectorYN.create(str(models_dir / "face_detection_yunet_2023mar.onnx"),
                                    "", (320, 320), 0.5, 0.3, 5000)


def infer(chip_bgr):
    rgb = cv2.cvtColor(chip_bgr, cv2.COLOR_BGR2RGB)
    rgb = cv2.resize(rgb, (224, 224), interpolation=cv2.INTER_LINEAR)
    t = ((rgb.astype(np.float32) / 255.0 - 0.5) / 0.5).transpose(2, 0, 1)[np.newaxis]
    logits = sess.run(None, {inp: t})[0][0]
    e = np.exp(logits - logits.max())
    return float((e / e.sum())[1])


def crop_m96(bgr, f):
    x, y, bw, bh = f[:4]
    x1 = max(0, int(x - bw * M96))
    y1 = max(0, int(y - bh * M96))
    x2 = min(bgr.shape[1], int(x + bw + bw * M96))
    y2 = min(bgr.shape[0], int(y + bh + bh * M96))
    return bgr[y1:y2, x1:x2]


def shipped_crop_bounds(f, w, h):
    """The shipped crop bounds (`pad_vit_crop` in crates/irlume-vision):
    width and height rebuilt from float32 corners, then the m96 expansion."""
    x1, y1 = np.float32(f[0]), np.float32(f[1])
    x2, y2 = x1 + np.float32(f[2]), y1 + np.float32(f[3])
    bw, bh = x2 - x1, y2 - y1
    margin = np.float32(96.0) / np.float32(112.0)
    mx, my = bw * margin, bh * margin
    return max(0, int(x1 - mx)), max(0, int(y1 - my)), min(w, int(x2 + mx)), min(h, int(y2 + my))


def crop_bounds(f, w, h):
    """The bounds crop_m96 slices: YuNet's own width and height expanded."""
    x, y, bw, bh = f[:4]
    return (max(0, int(x - bw * M96)), max(0, int(y - bh * M96)),
            min(w, int(x + bw + bw * M96)), min(h, int(y + bh + bh * M96)))


def sample_files(lfw_root, n):
    """Every (len // n)-th LFW image by file name, the first n of them."""
    # By file name, so every LFW packaging (per-identity folders or numbered
    # shards) yields the same sample.
    files = sorted(lfw_root.rglob("*.jpg"), key=lambda p: p.name)
    if not files:
        raise SystemExit(f"no *.jpg under {lfw_root}")
    return files[::max(1, len(files) // n)][:n]


def luma(chip):
    return float((chip[:, :, 2] * 0.299 + chip[:, :, 1] * 0.587 + chip[:, :, 0] * 0.114).mean())


def jpeg(chip, q):
    ok, buf = cv2.imencode(".jpg", chip, [int(cv2.IMWRITE_JPEG_QUALITY), q])
    return cv2.imdecode(buf, cv2.IMREAD_COLOR) if ok else chip


def to_linear(s):
    s = np.clip(s, 0, 1)
    return np.where(s <= 0.04045, s / 12.92, np.power((s + 0.055) / 1.055, 2.4))


def to_srgb(lin):
    lin = np.clip(lin, 0, 1)
    return np.where(lin <= 0.0031308, 12.92 * lin, 1.055 * np.power(lin, 1 / 2.4) - 0.055)


def photon_noise(chip, e, rng):
    lin = to_linear(chip.astype(np.float32) / 255.0)
    n = np.maximum(lin * e * REF_PHOTONS, 0)
    sampled = rng.poisson(n).astype(np.float32) / (e * REF_PHOTONS)
    sampled += rng.normal(0.0, READ_SIGMA / 255.0, size=lin.shape).astype(np.float32)
    return np.clip(to_srgb(sampled) * 255.0, 0, 255).astype(np.uint8)


def noise_std(noisy, clean):
    return float(np.std(noisy.astype(np.float32) - clean.astype(np.float32)))


def grain_rows(chip, rng):
    """(arm, param, luma, p_spoof, noise_std) for the grain pass."""
    rows = [("base", "0", luma(chip), infer(chip), 0.0)]
    for sigma in GRAIN_SIGMA:
        noisy = np.clip(chip.astype(np.float32) + rng.normal(0, sigma, chip.shape), 0, 255).astype(np.uint8)
        rows.append(("noise", str(sigma), luma(noisy), infer(noisy), noise_std(noisy, chip)))
    for s in SCALES:
        dim = np.clip(chip.astype(np.float32) * s, 0, 255).astype(np.uint8)
        rows.append(("exposure", str(s), luma(dim), infer(dim), 0.0))
    for q in JPEG_Q:
        coded = jpeg(chip, q)
        rows.append(("jpeg", str(q), luma(coded), infer(coded), 0.0))
    return rows


def photon_rows(chip, rng):
    rows = [("base", "1.0", luma(chip), infer(chip), 0.0)]
    for e in EXPOSURES:
        img = photon_noise(chip, e, rng)
        rows.append(("noise", str(e), luma(img), infer(img), noise_std(img, chip)))
    blurred = cv2.GaussianBlur(chip, (0, 0), BLUR_SIGMA)
    rows.append(("blur", str(BLUR_SIGMA), luma(blurred), infer(blurred), 0.0))
    flat = np.clip(128 + (chip.astype(np.float32) - 128) * CONTRAST, 0, 255).astype(np.uint8)
    rows.append(("contrast", str(CONTRAST), luma(flat), infer(flat), 0.0))
    return rows


PASSES = {"grain": grain_rows, "photon": photon_rows}


def work(item):
    pass_name, idx, path = item
    bgr = cv2.imread(str(path), cv2.IMREAD_COLOR)
    if bgr is None:
        return idx, []
    h, w = bgr.shape[:2]
    det.setInputSize((w, h))
    _, faces = det.detect(bgr)
    if faces is None or len(faces) == 0:
        return idx, []
    chip = crop_m96(bgr, max(faces, key=lambda x: x[2] * x[3]))
    if chip.size == 0:
        return idx, []
    rng = np.random.default_rng(1155 + idx)
    return idx, [(path.name, *r) for r in PASSES[pass_name](chip, rng)]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("pass_name", choices=sorted(PASSES))
    ap.add_argument("lfw_root", type=Path)
    ap.add_argument("out_csv", type=Path)
    ap.add_argument("--n-images", type=int)
    # Each worker holds its own ViT session (a 343 MB model), so the default
    # stays small; outputs do not depend on the worker count.
    ap.add_argument("--workers", type=int, default=min(4, max(1, (mp.cpu_count() or 2) - 1)))
    ap.add_argument("--models-dir", type=Path, default=MODELS)
    a = ap.parse_args()
    require_numpy2()
    verify_models(a.models_dir)
    n = a.n_images or DEFAULT_N[a.pass_name]
    sample = [(a.pass_name, i, p) for i, p in enumerate(sample_files(a.lfw_root, n))]
    print(f"{a.pass_name}: {len(sample)} images, {a.workers} workers", flush=True)
    by_idx = {}
    with mp.Pool(a.workers, initializer=_init, initargs=(a.models_dir,)) as pool:
        for k, (idx, rows) in enumerate(pool.imap_unordered(work, sample, chunksize=2), 1):
            by_idx[idx] = rows
            if k % 50 == 0:
                print(f"  {k}", flush=True)
    rows = [r for i in sorted(by_idx) for r in by_idx[i]]
    with a.out_csv.open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["frame", "arm", "param", "luma", "p_spoof", "noise_std"])
        for frame, arm, param, lu, p, s in rows:
            wr.writerow([frame, arm, param, f"{lu:.3f}", f"{p:.6f}", f"{s:.3f}"])
    print(f"wrote {len(rows)} rows to {a.out_csv}")


if __name__ == "__main__":
    main()
