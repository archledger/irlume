#!/usr/bin/env python3
"""Official-runtime BlazeFace bench over the stage-3 corpus (#294 review).

Runs Google's own mediapipe Tasks FaceDetector, so no hand-rolled decode can
color the result, with BOTH the short-range and full-range tflites over every
stored frame. The short-range column doubles as a cross-check of the Rust
bench's decoder. One CSV row per (frame, model).
"""
import csv
import sys
from pathlib import Path

import numpy as np
import mediapipe as mp
from mediapipe.tasks import python as mp_python
from mediapipe.tasks.python import vision


def read_pnm(path):
    data = path.read_bytes()
    # P5/P6 header written by our capture tools: magic, w, h, maxval, one ws.
    parts = data[:64].split(None, 4)
    magic, w, h = parts[0], int(parts[1]), int(parts[2])
    # Payload offset: after the 4th whitespace-delimited token + 1 byte.
    seen = 0
    fields = 0
    for i, b in enumerate(data):
        if bytes([b]).isspace():
            if seen:
                fields += 1
                seen = 0
                if fields == 4:
                    off = i + 1
                    break
        else:
            seen += 1
    if magic == b"P6":
        arr = np.frombuffer(data[off : off + w * h * 3], np.uint8).reshape(h, w, 3)
        return arr, arr.mean()
    arr = np.frombuffer(data[off : off + w * h], np.uint8).reshape(h, w)
    rgb = np.stack([arr] * 3, axis=-1)
    return rgb, arr.mean()


def detector(model_path):
    opts = vision.FaceDetectorOptions(
        base_options=mp_python.BaseOptions(model_asset_path=model_path),
        min_detection_confidence=0.5,
    )
    return vision.FaceDetector.create_from_options(opts)


def main(short_p, full_p, roots):
    dets = {"short": detector(short_p), "full": detector(full_p)}
    w = csv.writer(sys.stdout)
    w.writerow(["camera", "segment", "kind", "frame", "model", "n", "score", "mean",
                "x1", "y1", "x2", "y2"])
    for root in roots:
        cam = Path(root).name
        for seg in sorted(p for p in Path(root).iterdir() if p.is_dir()):
            for sub, kind in [("rgb", "rgb"), ("ir", "ir")]:
                for f in sorted((seg / sub).glob("*.p?m")):
                    arr, mean = read_pnm(f)
                    img = mp.Image(image_format=mp.ImageFormat.SRGB, data=np.ascontiguousarray(arr))
                    for mname, d in dets.items():
                        r = d.detect(img)
                        n = len(r.detections)
                        # Top detection's box in pixels, for decoder parity.
                        top = max(
                            r.detections,
                            key=lambda det: max(c.score for c in det.categories),
                            default=None,
                        )
                        score = ""
                        box = ["", "", "", ""]
                        if top is not None:
                            score = f"{max(c.score for c in top.categories):.4f}"
                            bb = top.bounding_box
                            box = [f"{bb.origin_x}", f"{bb.origin_y}",
                                   f"{bb.origin_x + bb.width}", f"{bb.origin_y + bb.height}"]
                        w.writerow([cam, seg.name, kind, f"{sub}/{f.name}", mname, n,
                                    score, f"{mean:.1f}", *box])


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3:])
