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
# grab the device back). On exit it RESTORES the prior state: a unit that
# was active comes back, a unit the operator had deliberately stopped
# stays stopped.
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

# Record what is running BEFORE touching anything, so the exit path restores
# the operator's state instead of imposing one. A dev install
# (scripts/install-host.sh) has no irlumed.socket, so its absence must not
# abort the stop of the service under set -e.
SERVICE_WAS_ACTIVE=0
SOCKET_WAS_ACTIVE=0
SOCKET_EXISTS=0
RESTORE_ARMED=0
if systemctl is-active --quiet irlumed.service; then SERVICE_WAS_ACTIVE=1; fi
if systemctl cat irlumed.socket >/dev/null 2>&1; then
  SOCKET_EXISTS=1
  if systemctl is-active --quiet irlumed.socket; then SOCKET_WAS_ACTIVE=1; fi
fi

restore_daemon_state() {
  local rc=$?
  set +e
  [ "$RESTORE_ARMED" = 1 ] || exit "$rc"
  [ "$SOCKET_WAS_ACTIVE" = 1 ] && systemctl start irlumed.socket
  if [ "$SERVICE_WAS_ACTIVE" = 1 ]; then
    # The just-finished capture may not have fully released the camera, and
    # daemon startup re-opens it, so a single start can time out. Retry, and
    # warn LOUDLY if it never comes back so face-login is never left
    # silently down.
    for _ in 1 2 3; do
      sleep 2
      systemctl start irlumed.service
      sleep 2
      if systemctl is-active --quiet irlumed.service; then
        echo "[blink] irlumed restored (face-login is back)."
        exit "$rc"
      fi
    done
    echo "[blink] !!! irlumed DID NOT come back; face login is DOWN: systemctl status irlumed" >&2
    exit 1
  fi
  exit "$rc"
}
trap restore_daemon_state EXIT

# Tolerate a missing dir: under set -e + pipefail a bare failing find inside
# the command substitution would kill the script BEFORE the refusal message
# (caught by the stub harness, 2026-08-07); a missing dir simply holds zero
# frames.
count_frames() { { find "$1" -maxdepth 1 -type f -name "$2" 2>/dev/null || true; } | wc -l; }

segment() {
  local seg="$1" prompt="$2"
  local out="$ROOT/$seg"
  local tmp rgb_count ir_count

  # A directory is only evidence when it is COMPLETE. The dump tools write
  # frames incrementally, so an interrupted run leaves a partial directory;
  # skipping on bare existence would silently accept it as a captured
  # segment and the corpus manifest built from it would pin the truncation.
  if [ -e "$out" ]; then
    rgb_count="$(count_frames "$out/rgb" '*.ppm')"
    ir_count="$(count_frames "$out/ir" '*.pgm')"
    if [ "$rgb_count" -eq "$RGB_FRAMES" ] && [ "$ir_count" -eq "$IR_FRAMES" ] \
       && [ -f "$out/ir/means.txt" ]; then
      echo "[$seg] complete, skipping (delete $out to recapture)"
      return 0
    fi
    echo "[$seg] exists but is INCOMPLETE ($rgb_count/$RGB_FRAMES rgb, $ir_count/$IR_FRAMES ir);" >&2
    echo "   delete or move $out before recapturing" >&2
    return 1
  fi

  # Capture into a temp dir beside the target and rename only a complete
  # capture into place, so an interrupt can never leave a partial directory
  # under the segment's name.
  tmp="$(mktemp -d --tmpdir="$ROOT" ".${seg}.partial.XXXXXX")"

  echo
  echo "== $seg =="
  echo "   $prompt"
  read -rp "   Enter when ready (capture starts 5s later): " _
  sleep 5
  echo "[$seg] RGB ($RGB_FRAMES frames)..."
  "$RGB_DUMP" "$tmp/rgb" "$RGB" "$RGB_FRAMES"
  echo "[$seg] keep going: IR burst ($IR_FRAMES frames)..."
  "$IR_DUMP" "$tmp/ir" "$IR" "$IR_FRAMES"

  rgb_count="$(count_frames "$tmp/rgb" '*.ppm')"
  ir_count="$(count_frames "$tmp/ir" '*.pgm')"
  if [ "$rgb_count" -ne "$RGB_FRAMES" ] || [ "$ir_count" -ne "$IR_FRAMES" ] \
     || [ ! -f "$tmp/ir/means.txt" ]; then
    echo "[$seg] INCOMPLETE capture left at $tmp ($rgb_count rgb, $ir_count ir)" >&2
    return 1
  fi
  mv -- "$tmp" "$out"
  echo "[$seg] done: $rgb_count rgb, $ir_count ir"
}

echo "[blink] stopping irlumed (and its socket) for direct camera access"
RESTORE_ARMED=1
if [ "$SOCKET_EXISTS" = 1 ]; then systemctl stop irlumed.socket; fi
systemctl stop irlumed.service

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
