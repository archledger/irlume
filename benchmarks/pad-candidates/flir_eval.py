#!/usr/bin/env python3
"""Evaluate ModelScope damo/cv_manual_face-liveness_flir (MIT) on the
irlume-suncal genuine IR field corpus.

Replicates the ModelScope FaceLivenessIrPipeline preprocessing exactly:
detect face -> pad bbox by 16/112 per side -> square with 127-gray fill ->
resize 128x128 -> center-crop 112x112 -> (x-127.5)*0.0078125 -> CHW float32.
Score reported = P(fake) = softmax(logits)[0]  (pipeline returns 1 - P(class1)).

Genuine-only corpus: this measures the false-reject side (would the model
reject a real user), per condition/ambient. Attack-side numbers need a live
spoof session and are NOT produced here.
"""
import json, sys, time
from pathlib import Path
import numpy as np
import cv2
import onnxruntime as ort

SUNCAL = Path.home() / "irlume-suncal"
MODEL = Path(sys.argv[1])
YUNET = Path.home() / "irlume/models/face_detection_yunet_2023mar.onnx"
FAKE_THRESHOLD = 0.5  # convention: p_fake >= 0.5 -> classified spoof

sess = ort.InferenceSession(str(MODEL), providers=["CPUExecutionProvider"])
inp_name = sess.get_inputs()[0].name


def detect(gray3):
    h, w = gray3.shape[:2]
    det = cv2.FaceDetectorYN.create(str(YUNET), "", (w, h), 0.5, 0.3, 5000)
    n, faces = det.detect(gray3)
    if faces is None or len(faces) == 0:
        return None
    f = max(faces, key=lambda f: f[2] * f[3])
    x, y, bw, bh = f[:4]
    return [x, y, x + bw, y + bh]


def align_face_padding(img, bbox, padding_size=16, pad_pixel=127):
    b = [int(v) for v in bbox]
    x1 = b[0] - int((b[2] - b[0] + 1) * padding_size / 112)
    x2 = b[2] + int((b[2] - b[0] + 1) * padding_size / 112)
    y1 = b[1] - int((b[3] - b[1] + 1) * padding_size / 112)
    y2 = b[3] + int((b[3] - b[1] + 1) * padding_size / 112)
    b = [max(0, x1), max(0, y1), min(img.shape[1] - 1, x2), min(img.shape[0] - 1, y2)]
    ph, pw = b[3] - b[1] + 1, b[2] - b[0] + 1
    if pw > ph:
        off = (pw - ph) // 2
        b[1] = max(0, b[1] - off)
        b[3] = min(img.shape[0] - 1, b[1] + pw - 1)
        dst_size = pw
    else:
        off = (ph - pw) // 2
        b[0] = max(0, b[0] - off)
        b[2] = min(img.shape[1] - 1, b[0] + ph - 1)
        dst_size = ph
    dst = np.full((dst_size, dst_size, 3), pad_pixel, dtype=np.uint8)
    yo = (dst_size - (b[3] - b[1] + 1)) // 2
    xo = (dst_size - (b[2] - b[0] + 1)) // 2
    dst[yo:yo + b[3] + 1 - b[1], xo:xo + b[2] + 1 - b[0]] = img[b[1]:b[3] + 1, b[0]:b[2] + 1]
    return cv2.resize(dst, (128, 128), interpolation=cv2.INTER_LINEAR)


def infer(crop128):
    img = crop128[8:120, 8:120, :].astype(np.float32)
    img = (img - 127.5) * 0.0078125
    t = img.transpose(2, 0, 1)[np.newaxis]
    logits = sess.run(None, {inp_name: t})[0]
    e = np.exp(logits[0] - logits[0].max())
    sm = e / e.sum()
    return float(sm[0])  # P(fake)


results = {}
lat = []
for d in sorted(p for p in SUNCAL.iterdir() if p.is_dir()):
    frames = sorted(d.glob("*.pgm"))
    if not frames:
        continue
    rows = []
    for fp in frames:
        gray = cv2.imread(str(fp), cv2.IMREAD_GRAYSCALE)
        if gray is None:
            continue
        mean = float(gray.mean())
        if mean < 10:  # dark strobe phase, nothing detectable
            continue
        gray3 = cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR)
        bbox = detect(gray3)
        if bbox is None:
            continue
        t0 = time.perf_counter()
        p_fake = infer(align_face_padding(gray3, bbox))
        lat.append((time.perf_counter() - t0) * 1000)
        rows.append({"frame": fp.name, "ambient": round(mean, 1), "p_fake": round(p_fake, 4)})
    if rows:
        pf = np.array([r["p_fake"] for r in rows])
        amb = np.array([r["ambient"] for r in rows])
        results[d.name] = {
            "frames_scored": len(rows),
            "ambient_median": round(float(np.median(amb)), 1),
            "p_fake_median": round(float(np.median(pf)), 4),
            "p_fake_p90": round(float(np.percentile(pf, 90)), 4),
            "p_fake_max": round(float(pf.max()), 4),
            "rejected_at_0.5": int((pf >= FAKE_THRESHOLD).sum()),
            "rows": rows,
        }

# smoke-only synthetic inputs (NOT an APCER claim): flat gray + noise
smoke = {}
for name, img in [("flat_gray", np.full((400, 640, 3), 127, np.uint8)),
                  ("noise", np.random.default_rng(0).integers(0, 255, (400, 640, 3), dtype=np.uint8))]:
    fake_bbox = [220, 100, 420, 300]
    smoke[name] = round(infer(align_face_padding(img, fake_bbox)), 4)

summary = {
    "model": str(MODEL),
    "threshold": FAKE_THRESHOLD,
    "total_frames_scored": int(sum(r["frames_scored"] for r in results.values())),
    "total_rejected": int(sum(r["rejected_at_0.5"] for r in results.values())),
    "latency_ms_median": round(float(np.median(lat)), 1) if lat else None,
    "smoke_synthetic": smoke,
}
out = {"summary": summary, "bursts": results}
outfile = Path(sys.argv[2])
outfile.write_text(json.dumps(out, indent=1))

print(f"{'burst':38s} {'n':>3s} {'amb':>5s} {'p_fake med':>10s} {'p90':>7s} {'max':>7s} {'rej@0.5':>7s}")
for name, r in results.items():
    print(f"{name:38s} {r['frames_scored']:3d} {r['ambient_median']:5.0f} "
          f"{r['p_fake_median']:10.4f} {r['p_fake_p90']:7.4f} {r['p_fake_max']:7.4f} {r['rejected_at_0.5']:7d}")
print("\nsummary:", json.dumps(summary, indent=1))
