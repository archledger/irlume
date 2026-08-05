#!/bin/bash
# capture-seg.sh <repo> <out_root> <segment> [rgb_dev] [ir_dev]
# One stage-3 corpus segment: 8s positioning lead-in, 8 RGB frames, a
# 24-frame IR strobe burst. The daemon must already be stopped (the tools
# open the devices directly).
set -e
REPO=$1
ROOT=$2
SEG=$3
RGB=${4:-/dev/video0}
IR=${5:-/dev/video2}
OUT="$ROOT/$SEG"
mkdir -p "$OUT"
echo "[$SEG] get in position; capture starts in 8s"
sleep 8
echo "[$SEG] RGB frames..."
"$REPO/target/release/examples/rgb_burst_dump" "$OUT/rgb" "$RGB" 8
echo "[$SEG] IR burst..."
"$REPO/target/release/examples/burst_dump" "$OUT/ir" "$IR" 24
echo "[$SEG] done: $(ls "$OUT/rgb" | wc -l) rgb, $(ls "$OUT/ir" | grep -c pgm) ir"
