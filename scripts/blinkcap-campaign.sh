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
# Default the dataset into the INVOKING user's home (not root's, under sudo) so
# the captures are readable without a copy; override with BLINKCAP_DATASET.
INVOKER="${SUDO_USER:-$USER}"
INVOKER_HOME="$(getent passwd "$INVOKER" | cut -d: -f6)"
DATASET="${BLINKCAP_DATASET:-${INVOKER_HOME:-$HOME}/blink-dataset}"
export ORT_DYLIB_PATH=/usr/share/irlume/onnxruntime/lib/libonnxruntime.so
export IRLUME_DEV=1

[ -x "$BIN" ] || { echo "build first: cargo build --release -p irlume-cli"; exit 1; }
mkdir -p "$DATASET"
# Next take number for this label. `find` (not `ls <glob>`) so a not-yet-created
# label returns 0 matches instead of exit 2, which under `set -euo pipefail`
# would kill the script silently before any capture.
IDX=$(( $(find "$DATASET" -maxdepth 1 -name "$LABEL-*.jsonl" 2>/dev/null | wc -l) + 1 ))
OUT="$DATASET/$LABEL-$(printf '%02d' "$IDX").jsonl"

# Head-pose labels record pitch/yaw (--pose) for the head-nod gesture; the rest
# record EAR for the blink/closure gate.
POSE_FLAG=""
case "$LABEL" in
  nod|shake|still|look-around|reclined-nod|reclined-still) POSE_FLAG="--pose" ;;
esac

echo "== capturing '$LABEL' take $IDX -> $OUT =="
case "$LABEL" in
  held-closure)  echo "   On GO: look at the camera, then close your eyes and HOLD ~1s, then open." ;;
  natural-blink) echo "   On GO: look at the camera and blink NATURALLY (do not force it)." ;;
  squint)        echo "   On GO: SQUINT / half-close your eyes a few times (the hard negative)." ;;
  look-down)     echo "   On GO: look DOWN and around (pose-driven false-closure negative)." ;;
  ae-settle)     echo "   On GO: look at the camera; change the room light mid-capture." ;;
  spoof)         echo "   On GO: hold a photo/print of your face over BOTH lenses; stay out of frame." ;;
  nod)           echo "   On GO: NOD your head (chin down, back up) 2-3 times, deliberately." ;;
  shake)         echo "   On GO: SHAKE your head (left-right) 2-3 times." ;;
  still)         echo "   On GO: hold your head STILL and look at the camera (the negative)." ;;
  look-around)   echo "   On GO: glance around / small idle head movements (the hard negative)." ;;
  reclined-nod)  echo "   On GO (LYING DOWN): nod your head 2-3 times." ;;
  reclined-still)echo "   On GO (LYING DOWN): hold still and look at the camera (negative)." ;;
  *)             echo "   On GO: perform the '$LABEL' gesture." ;;
esac

RESTART=0
# Bring the daemon back, robustly: its startup re-opens the camera, which the
# just-finished capture may not have fully released yet, so a bare `start` can
# time out. Retry, and warn LOUDLY if it never comes back so face-login is never
# left silently down. `set -e` is disabled inside so a failed attempt still
# retries. Runs on every exit path (including capture failure).
restart_daemon() {
  [ "$RESTART" = 1 ] || return 0
  set +e
  for attempt in 1 2 3; do
    sleep 2 # let the camera fully release before the daemon grabs it
    systemctl restart irlumed
    sleep 2
    if systemctl is-active --quiet irlumed; then
      echo "[campaign] irlumed restarted (face-login is back)."
      return 0
    fi
  done
  echo "[campaign] ⚠ irlumed did NOT come back. Run:  sudo systemctl restart irlumed"
}
trap restart_daemon EXIT

if systemctl is-active --quiet irlumed; then
  echo "   stopping irlumed for camera access..."
  systemctl stop irlumed
  RESTART=1
fi

sleep 1
"$BIN" blinkcap capture \
  --label "$LABEL" \
  --det "$MODELS/face_detection_yunet_2023mar.onnx" \
  --model "$MODELS/glintr100.onnx" \
  --mesh "$MODELS/face_landmark.onnx" \
  --ir /dev/video2 \
  --n "$N" \
  $POSE_FLAG \
  --out "$OUT"

# Hand the capture (and dataset dir) back to the invoking user so it is readable
# without a manual copy/chown.
if [ -n "${SUDO_USER:-}" ]; then
  chown -R "$SUDO_USER:$(id -gn "$SUDO_USER")" "$DATASET" 2>/dev/null || true
fi

echo "== done. Dataset ($DATASET) now: =="
ls -1 "$DATASET"
