#!/usr/bin/bash
# Blink corpus capture for #316: the margin between a genuine blink and the
# 0.37 open-eye blendshape ceiling is unmeasured because the stage-3 corpus
# holds no closed-eye frames. This walks the six segments that close that gap
# on one camera pair: held closures (guaranteed closed frames even at burst
# frame rates), natural blinks (the real event), and open-eye controls
# (same-day lighting, so the comparison is not confounded by capture day),
# each with glasses on and off.
#
# Layout matches the stage-3 corpus (camera/segment/{rgb,ir}) so
# blendshapes_probe walks it unchanged in external-corpus mode.
#
#   sudo scripts/research/capture-blink-corpus.sh <out_root>/<camera> [rgb_dev] [ir_dev]
#   e.g. sudo scripts/research/capture-blink-corpus.sh ~/irlume-research/2026-08-07-blink-corpus/zenbook
#
# The daemon owns the cameras, so this stops irlumed AND its activation
# socket (a face-login attempt mid-capture would re-spawn the daemon and
# grab the device back), and restarts both on every exit path.
set -euo pipefail

ROOT="${1:?usage: sudo capture-blink-corpus.sh <out_root>/<camera> [rgb_dev] [ir_dev]}"
RGB="${2:-/dev/video0}"
IR="${3:-/dev/video2}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RGB_DUMP="$REPO/target/release/examples/rgb_burst_dump"
IR_DUMP="$REPO/target/release/examples/burst_dump"
# 24 RGB frames: a natural blink is a few frames wide, so the 8-frame stage-3
# burst can miss one entirely; three times the window makes a multi-blink
# segment carry several.
RGB_FRAMES=24
IR_FRAMES=24

[ -x "$RGB_DUMP" ] && [ -x "$IR_DUMP" ] || {
  echo "build first: cargo build --release -p irlume-camera --example rgb_burst_dump --example burst_dump"
  exit 1
}
mkdir -p "$ROOT"

RESTART=0
restart_daemon() {
  [ "$RESTART" = 1 ] || return 0
  set +e
  systemctl start irlumed.socket
  for _ in 1 2 3; do
    sleep 2 # let the camera fully release before the daemon grabs it
    systemctl restart irlumed
    sleep 2
    if systemctl is-active --quiet irlumed; then
      echo "[blink] irlumed restarted (face-login is back)."
      return 0
    fi
  done
  echo "[blink] !!! irlumed DID NOT come back; face login is DOWN: systemctl status irlumed" >&2
}
trap restart_daemon EXIT

segment() {
  local seg="$1" prompt="$2"
  local out="$ROOT/$seg"
  if [ -d "$out" ]; then
    echo "[$seg] exists, skipping (delete $out to recapture)"
    return 0
  fi
  mkdir -p "$out"
  echo
  echo "== $seg =="
  echo "   $prompt"
  read -rp "   Enter when ready (capture starts 5s later): " _
  sleep 5
  echo "[$seg] RGB ($RGB_FRAMES frames)..."
  "$RGB_DUMP" "$out/rgb" "$RGB" "$RGB_FRAMES"
  echo "[$seg] keep going: IR burst ($IR_FRAMES frames)..."
  "$IR_DUMP" "$out/ir" "$IR" "$IR_FRAMES"
  echo "[$seg] done: $(find "$out/rgb" -name '*.ppm' | wc -l) rgb, $(find "$out/ir" -name '*.pgm' | wc -l) ir"
}

echo "[blink] stopping irlumed (and its socket) for direct camera access"
systemctl stop irlumed.socket irlumed
RESTART=1

echo "GLASSES OFF for the first three segments."
segment open-frontal      "Look at the camera, eyes OPEN, hold still through both bursts."
segment held-closure      "Look at the camera, then CLOSE your eyes and HOLD them closed through both bursts."
segment natural-blink     "Look at the camera and blink NATURALLY, several times, through both bursts."

echo
echo "GLASSES ON for the last three segments."
segment open-frontal-glasses  "Glasses on. Eyes OPEN, hold still through both bursts."
segment held-closure-glasses  "Glasses on. CLOSE your eyes and HOLD through both bursts."
segment natural-blink-glasses "Glasses on. Blink NATURALLY, several times, through both bursts."

echo
echo "[blink] all segments captured under $ROOT"
