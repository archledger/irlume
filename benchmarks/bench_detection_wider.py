#!/usr/bin/env python3
"""YuNet detection benchmark on WIDER FACE.

--smoke: run the first N images of the sorted val ground truth through YuNet
at irlume operating scale and write per-image counts. Full AP evaluation is a
later phase; this smoke run exists to prove the chain (venv, CUDA, models,
dataset, OpenCV YuNet) end to end.
"""

import argparse
import json
import sys
from pathlib import Path

import cv2
import onnxruntime as ort


def val_image_list(wider_root: Path) -> list[str]:
    gt = wider_root / "wider_face_split" / "wider_face_val_bbx_gt.txt"
    out = []
    for line in gt.read_text().splitlines():
        if line.endswith(".jpg"):
            out.append(line.strip())
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--wider-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--n", type=int, default=32, help="smoke image count")
    args = ap.parse_args(argv)

    det = cv2.FaceDetectorYN_create(
        str(args.models_dir / "face_detection_yunet_2023mar.onnx"),
        "",
        (320, 240),
        score_threshold=0.6,
    )
    vals = val_image_list(args.wider_root)
    images = vals[: args.n] if args.smoke else vals
    per_image = []
    for rel in images:
        img = cv2.imread(str(args.wider_root / "WIDER_val" / "images" / rel))
        if img is None:
            per_image.append({"file": rel, "n_faces": -1, "max_score": 0.0})
            continue
        h, w = img.shape[:2]
        det.setInputSize((w, h))
        ret, faces = det.detect(img)
        if faces is None:
            n, mx = 0, 0.0
        else:
            n = int(faces.shape[0])
            mx = float(faces[:, 14].max())
        per_image.append({"file": rel, "n_faces": n, "max_score": round(mx, 4)})

    ok = [p for p in per_image if p["n_faces"] >= 0]
    result = {
        "runtime": {
            "ort_version": ort.__version__,
            "providers": ort.get_available_providers(),
            "cv2_version": cv2.__version__,
        },
        "protocol": {
            "smoke": bool(args.smoke),
            "n": len(images),
            "source": "wider_face val, first N images of the sorted bbox ground truth",
        },
        "per_image": per_image,
        "summary": {
            "images": len(ok),
            "total_faces": sum(p["n_faces"] for p in ok),
            "images_with_zero_faces": sum(1 for p in ok if p["n_faces"] == 0),
        },
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
