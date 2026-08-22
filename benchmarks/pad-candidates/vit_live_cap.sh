#!/usr/bin/env bash
# Live ViT-PAD qualification capture, 2026-08-22 session.
# Usage: cap.sh <condition> [n_keep]
# Captures n_keep+6 frames from /dev/video0 (MJPG 640x480, matching the
# 2026-08-12 corpus), drops the first 6 (auto-exposure settling — the
# 2026-07-17 FLIR banner false-accept was a settling frame), keeps n_keep.
set -euo pipefail
COND="${1:?condition}"
N="${2:-36}"
ROOT="$HOME/irlume-research/2026-08-22-vit-live/$COND/rgb"
mkdir -p "$ROOT"
TMP=$(mktemp -d)
echo "capturing $((N+6)) frames (~$(( (N+6) / 30 ))s) — HOLD THE PRESENTATION ..."
ffmpeg -hide_banner -loglevel error -y -f v4l2 -input_format mjpeg \
  -video_size 640x480 -i /dev/video0 -frames:v $((N+6)) "$TMP/f%03d.ppm"
i=0
for f in "$TMP"/f*.ppm; do
  i=$((i+1))
  [ "$i" -le 6 ] && continue
  cp "$f" "$(printf '%s/%s-%03d.ppm' "$ROOT" "$COND" "$i")"
done
rm -rf "$TMP"
echo "kept $(ls "$ROOT" | wc -l) frames in $ROOT"
