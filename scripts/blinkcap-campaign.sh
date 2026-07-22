#!/usr/bin/bash
# Deliberate-consent-gesture capture campaign helper.
#
# Records one labeled ~5s IR EarSample sequence per invocation into a dataset
# directory, using the freshly-built branch binary and the installed models.
# The daemon holds the camera, so this stops it for the capture and restarts it
# after. Run several takes per label, then replay the directory to read off the
# closure threshold.
#
#   sudo scripts/blinkcap-campaign.sh held-closure     # deliberate held closes
#   sudo scripts/blinkcap-campaign.sh natural-blink    # passive spontaneous blinks
#   sudo scripts/blinkcap-campaign.sh ae-settle        # look while the light changes
#   sudo scripts/blinkcap-campaign.sh spoof            # a photo/print on a phone
#
#   # when done, read the threshold:
#   IRLUME_DEV=1 target/release/irlume blinkcap replay ~/blink-dataset
set -euo pipefail

LABEL="${1:?usage: sudo scripts/blinkcap-campaign.sh <label> [n]}"
N="${2:-75}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/target/release/irlume"
MODELS=/usr/share/irlume/models
DATASET="${BLINKCAP_DATASET:-$HOME/blink-dataset}"
export ORT_DYLIB_PATH=/usr/share/irlume/onnxruntime/lib/libonnxruntime.so
export IRLUME_DEV=1

[ -x "$BIN" ] || { echo "build first: cargo build --release -p irlume-cli"; exit 1; }
mkdir -p "$DATASET"
# Next take number for this label.
IDX=$(( $(ls "$DATASET"/"$LABEL"-*.jsonl 2>/dev/null | wc -l) + 1 ))
OUT="$DATASET/$LABEL-$(printf '%02d' "$IDX").jsonl"

echo "== capturing '$LABEL' take $IDX -> $OUT =="
case "$LABEL" in
  held-closure)  echo "   HOLD your eyes shut for ~1 second when it says GO." ;;
  natural-blink) echo "   Just look at the camera and blink NATURALLY (do not force it)." ;;
  ae-settle)     echo "   Look at the camera; change the room light mid-capture." ;;
  spoof)         echo "   Hold a photo/print of your face over BOTH lenses; stay out of frame." ;;
esac

RESTART=0
if systemctl is-active --quiet irlumed; then
  echo "   stopping irlumed for camera access..."
  systemctl stop irlumed
  RESTART=1
fi
# Always hand the camera back, even on error.
trap '[ "$RESTART" = 1 ] && systemctl start irlumed || true' EXIT

sleep 1
"$BIN" blinkcap capture \
  --label "$LABEL" \
  --det "$MODELS/face_detection_yunet_2023mar.onnx" \
  --model "$MODELS/glintr100.onnx" \
  --mesh "$MODELS/face_landmark.onnx" \
  --ir /dev/video2 \
  --n "$N" \
  --out "$OUT"

echo "== done. Dataset now: =="
ls -1 "$DATASET"
