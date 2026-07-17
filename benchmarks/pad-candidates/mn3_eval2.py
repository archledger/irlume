#!/usr/bin/env python3
"""mn3 confirmation battery: corrected scoring (model output IS probabilities;
no extra softmax) + crop-margin sensitivity sweep.

Margin m expands the detection bbox by factor m about its center before crop
(clamped to frame). m=1.0 reproduces the original tight-crop run.
"""
import json
from pathlib import Path
import numpy as np, cv2, onnxruntime as ort

SP = Path(__file__).parent
MEAN = np.array([151.2405, 119.5950, 107.8395], dtype=np.float32)
SCALE = np.array([63.0105, 56.4570, 55.0035], dtype=np.float32)
YUNET = str(Path.home() / "irlume/models/face_detection_yunet_2023mar.onnx")
MARGINS = [1.0, 1.3, 1.6, 2.0]

sess = ort.InferenceSession(str(SP / "anti-spoof-mn3.onnx"), providers=["CPUExecutionProvider"])
inp = sess.get_inputs()[0].name


def bbox_of(bgr):
    h, w = bgr.shape[:2]
    det = cv2.FaceDetectorYN.create(YUNET, "", (w, h), 0.5, 0.3, 5000)
    _, faces = det.detect(bgr)
    if faces is None or len(faces) == 0:
        return None
    f = max(faces, key=lambda f: f[2] * f[3])
    return [float(v) for v in f[:4]]


def crop(bgr, bb, m):
    x, y, w, h = bb
    cx, cy = x + w / 2, y + h / 2
    nw, nh = w * m, h * m
    x1, y1 = int(max(0, cx - nw / 2)), int(max(0, cy - nh / 2))
    x2, y2 = int(min(bgr.shape[1], cx + nw / 2)), int(min(bgr.shape[0], cy + nh / 2))
    return bgr[y1:y2, x1:x2]


def p_spoof(face):
    img = cv2.resize(face, (128, 128)).astype(np.float32)[:, :, ::-1]
    t = ((img - MEAN) / SCALE).transpose(2, 0, 1)[np.newaxis]
    return float(sess.run(None, {inp: t})[0][0][1])  # already a probability


def run(paths, margins=MARGINS):
    out = {m: [] for m in margins}
    for p in paths:
        img = cv2.imread(str(p))
        if img is None:
            continue
        bb = bbox_of(img)
        if bb is None:
            continue
        for m in margins:
            f = crop(img, bb, m)
            if f.size:
                out[m].append(p_spoof(f))
    return {m: {"n": len(v),
                "median": round(float(np.median(v)), 4) if v else None,
                "min": round(float(np.min(v)), 4) if v else None,
                "flag@0.4": int((np.array(v) >= 0.4).sum()) if v else 0}
            for m, v in out.items()}


sets = {
    "genuine-car": sorted((Path.home() / "irlume-suncal/mn3-session/genuine-car").glob("*.png")),
    "phone-replay-car": sorted((Path.home() / "irlume-suncal/mn3-session/phone-replay-car").glob("*.png")),
    "phone-replay-car-2": sorted((Path.home() / "irlume-suncal/mn3-session/phone-replay-car-2").glob("*.png")),
    "camera-sun-burst": sorted((Path.home() / "irlume-suncal/09b-rgb-live-sun").glob("*.ppm")),
    "camera-backlit-burst": sorted((Path.home() / "irlume-suncal/16b-home-rgb-backlit").glob("*.ppm")),
    "lfw-sample": sorted((Path.home() / "datasets/lfw").rglob("*.jpg"))[::27],  # ~490 spread across identities
}

results = {name: run(paths) for name, paths in sets.items()}
(SP / "mn3-eval2-results.json").write_text(json.dumps(results, indent=1))

hdr = f"{'set':22s}" + "".join(f"  m={m}:med/flag@0.4(n)" for m in MARGINS)
print(hdr)
for name, r in results.items():
    row = f"{name:22s}"
    for m in MARGINS:
        s = r[m]
        row += f"  {s['median']}/{s['flag@0.4']}({s['n']})"
    print(row)
