#!/usr/bin/env python3
"""SCRFD-10G vs irlume's shipped YuNet on the stored 2026-08-05 stage-3 corpus.

DETECTION-RATE AND BOX-AGREEMENT ONLY. This measures whether each detector
returns a face box and how much the two boxes overlap. It measures NOTHING
about false grants: a detector supplies a box to alignment/recognition, and
availability says nothing about what that box lets through.

YuNet path is a line-for-line port of irlume's own invocation:
  crates/irlume-vision/src/lib.rs  Detector::detect + letterbox_bgr
  crates/irlume-vision/src/detect.rs  decode_stride/nms/letterbox_scale
so it can be validated against the committed bench CSVs.

SCRFD path follows deepinsight/insightface python-package/insightface/
model_zoo/scrfd.py (distance2bbox/distance2kps, forward, detect, nms).
"""
import argparse
import csv
import hashlib
import math
import os
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort

# Inputs are resolved by environment first so the harness is runnable from a
# clean checkout; the defaults are where this project keeps them. Neither
# model is committed (YuNet is a shipped weight file, SCRFD-10G is a
# non-commercial third-party artifact), so the hashes recorded in
# docs/pad-results/2026-08-12-scrfd-vs-yunet.md are what identify them.
CORPUS = Path(
    os.environ.get("IRLUME_STAGE3_CORPUS", Path.home() / "irlume-research/2026-08-05-stage3")
)
YUNET_PATH = os.environ.get(
    "IRLUME_YUNET", str(Path.home() / "irlume/models/face_detection_yunet_2023mar.onnx")
)
SCRFD_PATH = os.environ.get(
    "SCRFD_MODEL", str(Path.home() / "datasets/buffalo_l/det_10g.onnx")
)

# The digests this measurement is published under. Printing a hash and then
# using the file regardless is a check that authorises nothing (review round,
# #444): a different det_10g.onnx, or one replaced corpus frame, would have
# produced a plausible CSV indistinguishable from a reproduction. These are
# ENFORCED before any inference runs, and --allow-unpinned is the explicit
# way to measure something else on purpose.
EXPECTED = {
    "scrfd": "5838f7fe053675b1c7a08b633df49e7af5495cee0493c7dcf6697200b85b5b91",
    "yunet": "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
}
# Frames in the committed corpus; a short or long enumeration is a different
# corpus, whatever the paths say.
EXPECTED_FRAMES = 512


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_inputs(allow_unpinned):
    """Refuse before inference when the artifacts are not the published ones."""
    bad = []
    for name, path in (("scrfd", SCRFD_PATH), ("yunet", YUNET_PATH)):
        got = _sha256_file(path)
        if got != EXPECTED[name]:
            bad.append(f"{name}: {path}\n    expected {EXPECTED[name]}\n    got      {got}")
    if bad:
        msg = "input artifacts do not match the published measurement:\n  " + "\n  ".join(bad)
        if not allow_unpinned:
            raise SystemExit(f"{msg}\nrefusing; pass --allow-unpinned to measure anyway")
        print(f"WARNING: {msg}\ncontinuing under --allow-unpinned", file=sys.stderr)

# irlume's shipped YuNet constants (crates/irlume-vision/src/detect.rs).
YUNET_INPUT = 640
YUNET_SCORE = 0.6
YUNET_NMS = 0.3
STRIDES = (8, 16, 32)

# insightface SCRFD reference constants (scrfd.py __init__).
SCRFD_INPUT = 640
SCRFD_SCORE = 0.5
SCRFD_NMS = 0.4


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- PNM loading
def read_pnm(path):
    """Return (HxWx3 uint8 RGB, w, h). P6 is RGB; P5 grey is replicated to 3
    channels, which is exactly what irlume_camera::grey_to_rgb does before
    the frame reaches the detector."""
    data = path.read_bytes()
    # Header: magic, w, h, maxval, one whitespace byte, then the payload.
    # Mirrors detect_bench.rs read_ascii_header (no comment support; our
    # capture tools never write comments).
    text = data[:64].decode("utf-8", "replace")
    tok = text.split()
    magic, w, h, maxval = tok[0], int(tok[1]), int(tok[2]), int(tok[3])
    assert maxval == 255, f"{path}: maxval {maxval}"
    seen = fields = 0
    off = None
    for i, b in enumerate(data):
        if b in b" \t\n\r\x0b\x0c":
            if seen > 0:
                fields += 1
                seen = 0
                if fields == 4:
                    off = i + 1
                    break
        else:
            seen += 1
    assert off is not None, f"{path}: no header end"
    if magic == "P6":
        px = np.frombuffer(data, np.uint8, w * h * 3, off).reshape(h, w, 3)
    elif magic == "P5":
        g = np.frombuffer(data, np.uint8, w * h, off).reshape(h, w)
        px = np.repeat(g[:, :, None], 3, axis=2)
    else:
        raise AssertionError(f"{path}: magic {magic}")
    return px, w, h


# ------------------------------------------------------------------- geometry
def iou_xyxy(a, b):
    """Plain IoU, no +1 (irlume's detect.rs::iou)."""
    x1, y1 = max(a[0], b[0]), max(a[1], b[1])
    x2, y2 = min(a[2], b[2]), min(a[3], b[3])
    inter = max(x2 - x1, 0.0) * max(y2 - y1, 0.0)
    aa = max(a[2] - a[0], 0.0) * max(a[3] - a[1], 0.0)
    ab = max(b[2] - b[0], 0.0) * max(b[3] - b[1], 0.0)
    union = aa + ab - inter
    return inter / union if union > 0 else 0.0


# ---------------------------------------------------------------------- YuNet
class YuNet:
    """Port of irlume's Detector::detect. Letterbox scale for every frame in
    this corpus is exactly 1.0 (640 wide, <=640 tall), so the bilinear sampler
    lands on integer coordinates and reduces to a straight pixel copy: the
    port cannot differ from the Rust by resampling, only by decode."""

    def __init__(self, path):
        self.s = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        self.inp = self.s.get_inputs()[0].name
        self.names = [o.name for o in self.s.get_outputs()]

    def detect(self, rgb):
        h, w = rgb.shape[:2]
        scale = min(YUNET_INPUT / w, YUNET_INPUT / h)
        assert scale == 1.0, "port assumes the corpus's 1.0 letterbox scale"
        sw, sh = int(w * scale), int(h * scale)
        # letterbox_bgr: zero-padded square, NCHW, channel order B,G,R, raw 0-255.
        t = np.zeros((3, YUNET_INPUT, YUNET_INPUT), np.float32)
        t[:, :min(sh, YUNET_INPUT), :min(sw, YUNET_INPUT)] = (
            rgb[:YUNET_INPUT, :YUNET_INPUT, ::-1].transpose(2, 0, 1).astype(np.float32)
        )
        outs = self.s.run(None, {self.inp: t[None]})
        o = dict(zip(self.names, outs))
        dets = []
        for stride in STRIDES:
            fw = YUNET_INPUT // stride
            cls = o[f"cls_{stride}"].reshape(-1)
            obj = o[f"obj_{stride}"].reshape(-1)
            bbox = o[f"bbox_{stride}"].reshape(-1, 4)
            kps = o[f"kps_{stride}"].reshape(-1, 10)
            score = np.sqrt(np.clip(cls, 0, 1) * np.clip(obj, 0, 1))
            idx = np.where(np.isfinite(score) & (score >= YUNET_SCORE))[0]
            for i in idx:
                r, c = i // fw, i % fw
                cx = (c + bbox[i, 0]) * stride
                cy = (r + bbox[i, 1]) * stride
                bw = math.exp(bbox[i, 2]) * stride
                bh = math.exp(bbox[i, 3]) * stride
                x1, y1 = cx - bw / 2, cy - bh / 2
                dets.append((float(score[i]), [x1, y1, x1 + bw, y1 + bh]))
        # greedy NMS, irlume order: sort by score desc, drop IoU > 0.3
        dets.sort(key=lambda d: -d[0])
        keep = []
        for d in dets:
            if all(iou_xyxy(d[1], k[1]) <= YUNET_NMS for k in keep):
                keep.append(d)
        out = []
        for s, b in keep:
            bb = [v / scale for v in b]
            if all(math.isfinite(v) for v in bb) and math.isfinite(s):
                out.append((s, bb))
        return out


# ---------------------------------------------------------------------- SCRFD
def distance2bbox(points, distance):
    x1 = points[:, 0] - distance[:, 0]
    y1 = points[:, 1] - distance[:, 1]
    x2 = points[:, 0] + distance[:, 2]
    y2 = points[:, 1] + distance[:, 3]
    return np.stack([x1, y1, x2, y2], axis=-1)


def scrfd_nms(dets, thresh):
    """insightface SCRFD.nms verbatim, including the +1 areas and ovr<=thresh."""
    x1, y1, x2, y2, scores = dets[:, 0], dets[:, 1], dets[:, 2], dets[:, 3], dets[:, 4]
    areas = (x2 - x1 + 1) * (y2 - y1 + 1)
    order = scores.argsort()[::-1]
    keep = []
    while order.size > 0:
        i = order[0]
        keep.append(i)
        xx1 = np.maximum(x1[i], x1[order[1:]])
        yy1 = np.maximum(y1[i], y1[order[1:]])
        xx2 = np.minimum(x2[i], x2[order[1:]])
        yy2 = np.minimum(y2[i], y2[order[1:]])
        w = np.maximum(0.0, xx2 - xx1 + 1)
        h = np.maximum(0.0, yy2 - yy1 + 1)
        inter = w * h
        ovr = inter / (areas[i] + areas[order[1:]] - inter)
        order = order[np.where(ovr <= thresh)[0] + 1]
    return keep


class Scrfd:
    def __init__(self, path):
        self.s = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        self.inp = self.s.get_inputs()[0].name
        self.centers = {}

    def detect(self, rgb, thr=SCRFD_SCORE):
        h, w = rgb.shape[:2]
        # insightface SCRFD.detect letterbox: square model input, ratio-preserving,
        # pasted top-left. im_ratio = h/w <= 1 here, model_ratio = 1, so
        # new_width = 640, new_height = int(640*h/w), det_scale = new_height/h.
        im_ratio, model_ratio = h / w, 1.0
        if im_ratio > model_ratio:
            nh = SCRFD_INPUT
            nw = int(nh / im_ratio)
        else:
            nw = SCRFD_INPUT
            nh = int(nw * im_ratio)
        det_scale = nh / h
        assert (nw, nh) == (w, h), "corpus frames are 640-wide, expect a no-op resize"
        img = np.zeros((SCRFD_INPUT, SCRFD_INPUT, 3), np.uint8)
        img[:nh, :nw] = rgb  # no resize needed; det_scale == 1.0
        # blobFromImage(1/128, mean 127.5, swapRB=True) on a BGR image gives the
        # net RGB. We hold RGB already, so feed it straight through.
        blob = ((img.astype(np.float32) - 127.5) / 128.0).transpose(2, 0, 1)[None]
        outs = self.s.run(None, {self.inp: np.ascontiguousarray(blob)})
        fmc = 3
        dets = []
        for idx, stride in enumerate(STRIDES):
            scores = outs[idx].reshape(-1)
            bbox_preds = outs[idx + fmc].reshape(-1, 4) * stride
            hh = ww = SCRFD_INPUT // stride
            key = (hh, ww, stride)
            if key not in self.centers:
                ac = np.stack(np.mgrid[:hh, :ww][::-1], axis=-1).astype(np.float32)
                ac = (ac * stride).reshape((-1, 2))
                ac = np.stack([ac] * 2, axis=1).reshape((-1, 2))  # _num_anchors=2
                self.centers[key] = ac
            ac = self.centers[key]
            pos = np.where(scores >= thr)[0]
            if pos.size == 0:
                continue
            boxes = distance2bbox(ac, bbox_preds)[pos]
            dets.append(np.hstack([boxes, scores[pos, None]]))
        if not dets:
            return []
        pre = np.vstack(dets).astype(np.float32)
        pre[:, :4] /= det_scale
        pre = pre[pre[:, 4].argsort()[::-1], :]
        keep = scrfd_nms(pre, SCRFD_NMS)
        return [(float(pre[i, 4]), list(map(float, pre[i, :4]))) for i in keep]


# ------------------------------------------------------------------ enumerate
def frames():
    for cam in sorted(p.name for p in CORPUS.iterdir() if p.is_dir()):
        for seg in sorted(p.name for p in (CORPUS / cam).iterdir() if p.is_dir()):
            for kind, ext in (("rgb", ".ppm"), ("ir", ".pgm")):
                d = CORPUS / cam / seg / kind
                for f in sorted(d.glob(f"*{ext}")):
                    yield cam, seg, kind, f


def main():
    ap = argparse.ArgumentParser()
    # Defaults to the committed record, so a bare run reproduces what is
    # published rather than writing to a path that exists on one machine.
    ap.add_argument(
        "--out",
        default=str(
            Path(__file__).resolve().parents[2]
            / "docs/pad-results/2026-08-12-scrfd-vs-yunet-frames.csv"
        ),
    )
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument(
        "--allow-unpinned",
        action="store_true",
        help="measure artifacts other than the published ones (states so in stderr)",
    )
    args = ap.parse_args()

    verify_inputs(args.allow_unpinned)
    print(f"yunet_sha256={sha256(YUNET_PATH)}", file=sys.stderr)
    print(f"scrfd_sha256={sha256(SCRFD_PATH)}", file=sys.stderr)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)

    y, s = YuNet(YUNET_PATH), Scrfd(SCRFD_PATH)
    rows = []
    all_frames = list(frames())
    if not all_frames:
        raise SystemExit(f"no frames under {CORPUS}; set IRLUME_STAGE3_CORPUS")
    if not args.limit and len(all_frames) != EXPECTED_FRAMES:
        raise SystemExit(
            f"corpus has {len(all_frames)} frames, the published measurement used "
            f"{EXPECTED_FRAMES}; this is a different corpus"
        )
    for n, (cam, seg, kind, f) in enumerate(all_frames):
        if args.limit and n >= args.limit:
            break
        rgb, w, h = read_pnm(f)
        yd, sd = y.detect(rgb), s.detect(rgb)
        yt = max(yd, key=lambda d: d[0]) if yd else None
        st = max(sd, key=lambda d: d[0]) if sd else None
        row = {
            "camera": cam, "segment": seg, "kind": kind,
            "frame": f"{kind}/{f.name}", "w": w, "h": h,
            # Mean over all 3 channels, matching detect_bench.rs (which means
            # the RGB frame's mean, and for IR the replicated grey's mean).
            "mean": f"{float(rgb.mean()):.1f}",
            "yunet_n": len(yd), "scrfd_n": len(sd),
            "yunet_score": f"{yt[0]:.4f}" if yt else "",
            "scrfd_score": f"{st[0]:.4f}" if st else "",
            "yunet_fsize": f"{yt[1][2] - yt[1][0]:.4f}" if yt else "",
            "scrfd_fsize": f"{st[1][2] - st[1][0]:.4f}" if st else "",
            "iou": f"{iou_xyxy(yt[1], st[1]):.4f}" if (yt and st) else "",
        }
        for pre, d in (("y", yt), ("s", st)):
            for i, k in enumerate(("x1", "y1", "x2", "y2")):
                row[f"{pre}_{k}"] = f"{d[1][i]:.1f}" if d else ""
        rows.append(row)
        if n % 64 == 0:
            print(f"  {n} frames...", file=sys.stderr)

    # newline="\n": csv.writer defaults to CRLF, which makes git diff --check
    # report every committed row as trailing whitespace (review round, #444).
    with open(args.out, "w", newline="\n") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        wr.writeheader()
        wr.writerows(rows)
    print(f"wrote {len(rows)} rows -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    os.environ.setdefault("ORT_LOG_SEVERITY_LEVEL", "3")
    main()
