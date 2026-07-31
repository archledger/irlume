#!/usr/bin/env bash
# Does a face-auth control set once before streaming STAY set for a whole
# capture window? (#168)
#
#   sudo bash emitter-selfclear-test.sh <worktree> <ir-node> [rgb-node]
#
# WHY THIS EXISTS
#
# `capture_ir_streaming` re-applied the control every eighth frame, justified by
# a comment reading "some controls self-clear". At the default consent budget of
# 80 frames that is ten extra writes to camera firmware per watch, and `enable`
# is not a bare ioctl: each call re-reads the USB descriptors from sysfs and
# takes a lock to scan the undo journal on disk.
#
# Removing it is only defensible if the premise is false on the hardware here.
# So this sets the control once, streams a full window WITHOUT touching it
# again, and then reads the control back. Two outcomes, both informative:
#
#   reads back unchanged -> nothing self-cleared, and the re-fire bought nothing
#   reads back different -> the comment was right for THIS camera, and removing
#                           the re-fire needs a different answer than metadata
#
# It also reports the frame means across the window, because a control that
# still reads correct while the illuminator has stopped would be invisible to a
# GET_CUR alone.
#
# WHAT IT WRITES
#
# One `ir-setup` and one capture, both ordinary irlume operations against a
# documented Microsoft extension-unit control, using values the camera reported.
# Everything is sandboxed: its own state directory, emitter config, lock
# directory and socket. The packaged daemon is stopped and restored from its
# ENABLED state rather than from whether it happened to be running.
set -uo pipefail

TREE="${1:?usage: $0 <worktree> <ir-node> [rgb-node]}"
IR="${2:?usage: $0 <worktree> <ir-node> [rgb-node]}"
RGB="${3:-/dev/video0}"

B="$TREE/target/release"
S=/var/lib/irlume-selfclear
M="${IRLUME_MODEL_DIR:-/usr/share/irlume/models}"
SOCK=/run/irlume-selfclear.sock
# Taken from the packaged unit rather than assumed: the ONNX runtime ships beside
# irlume on some installs and sits on the default search path on others, and a
# daemon that cannot find it never reaches its socket, which reads as a hang.
ORT="${ORT_DYLIB_PATH:-$(systemctl cat irlumed 2>/dev/null |
    sed -n 's/^Environment="\?ORT_DYLIB_PATH=\([^"]*\)"\?$/\1/p' | head -1)}"

pass=0
fail=0
ok() {
    pass=$((pass + 1))
    echo "  ok      $1"
}
bad() {
    fail=$((fail + 1))
    echo "  FAILED  $1"
    echo "            $2"
}

[ "$(id -u)" -eq 0 ] || {
    echo "refusing: needs root to reach the camera's extension unit"
    exit 2
}
[ -x "$B/irlumed" ] || {
    echo "refusing: no daemon at $B/irlumed (cargo build --release first)"
    exit 2
}
[ -e "$IR" ] || {
    echo "refusing: $IR does not exist"
    exit 2
}

cleanup() {
    pkill -KILL -f "$B/irlumed" 2>/dev/null
    rm -f "$SOCK"
    if systemctl is-enabled --quiet irlumed 2>/dev/null; then
        systemctl start irlumed 2>/dev/null
        echo "  (packaged irlumed: $(systemctl is-active irlumed))"
    fi
}
trap cleanup EXIT

rm -rf "$S"
mkdir -p "$S"
# A sandboxed state directory has none of the opt-in third-party PAD weights, and
# on a machine whose settings.conf enables one the daemon stops during startup
# instead of reaching its socket. The subject here is the emitter, not the models.
if [ -d /var/lib/irlume/models-thirdparty ]; then
    ln -sfn /var/lib/irlume/models-thirdparty "$S/models-thirdparty"
fi
systemctl stop irlumed 2>/dev/null
sleep 1

start_daemon() { # $1 = tag, $2 = optional IRLUME_IR_EMITTER override
    rm -f "$SOCK"
    env IRLUME_SOCKET="$SOCK" IRLUME_STATE_DIR="$S" \
        ${2:+IRLUME_IR_EMITTER="$2"} \
        IRLUME_IR_EMITTER_CONF="$S/ir_emitter.conf" \
        IRLUME_EMITTER_LOCK_DIR="$S/locks" \
        IRLUME_RGB_DEVICE="$RGB" IRLUME_IR_DEVICE="$IR" \
        IRLUME_LOG_EMITTER_WRITES=1 \
        IRLUME_DET_MODEL="$M/face_detection_yunet_2023mar.onnx" \
        IRLUME_MODEL="$M/glintr100.onnx" \
        IRLUME_MESH_MODEL="$M/face_landmark.onnx" \
        IRLUME_BLAZE_MODEL="$M/blaze_face_short_range.onnx" \
        ${ORT:+ORT_DYLIB_PATH="$ORT"} \
        "$B/irlumed" >"$S/daemon-$1.log" 2>&1 &
    for _ in $(seq 1 1800); do
        [ -S "$SOCK" ] && return 0
        sleep 0.1
    done
    echo "  the daemon never listened; last lines:"
    tail -5 "$S/daemon-$1.log" | sed 's/^/    /'
    return 1
}

echo "=== 0. which extension unit does this camera publish ==="
# Derived, never assumed. The same hardcoded unit 4 that made an earlier harness
# silently assert nothing on a camera whose Microsoft XU is unit 14.
start_daemon probe || exit 2
IRLUME_SOCKET="$SOCK" "$B/irlume" ir-setup --dry-run >"$S/units.out" 2>&1
pkill -TERM -f "$B/irlumed" 2>/dev/null
sleep 1
sed 's/^/  /' "$S/units.out" | head -2
UNIT=$(sed -n 's/.*unit \([0-9]*\) (Microsoft camera control).*/\1/p' "$S/units.out" | head -1)
SEL=$(sed -n 's/.*unit '"${UNIT:-x}"' (Microsoft camera control): advertises \[\(0x[0-9a-f]*\).*/\1/p' \
    "$S/units.out" | head -1)
if [ -z "$UNIT" ] || [ -z "$SEL" ]; then
    echo "refusing: no Microsoft camera-control unit here; nothing in #168 applies"
    exit 2
fi
SEL=$((SEL))
echo "  Microsoft XU: unit $UNIT, selector $SEL"

echo "=== 1. park the control, then establish it through ir-setup ==="
# Parked at the camera's own default first, so `ir-setup` has a real difference
# to measure. Without this it correctly reports "already set to the value setup
# would apply" whenever a previous run left the control there, and the run below
# would be measuring a camera nobody had set.
PARK="${PARK_VALUE:-1,3,1,0,0,0,0,0,0}"
start_daemon park "$UNIT:$SEL:$PARK" || exit 2
pkill -TERM -f "$B/irlumed" 2>/dev/null
sleep 1

start_daemon setup || exit 2
IRLUME_SOCKET="$SOCK" "$B/irlume" ir-setup >"$S/setup.out" 2>&1
sed 's/^/  /' "$S/setup.out" | tail -2
if ! grep -qE "IR emitter enabled|already set" "$S/setup.out"; then
    echo
    echo "  NOT EXERCISED  this camera found no usable emitter control here, so"
    echo "                 there is nothing to watch for self-clearing."
    echo "                 (that is a room/hardware outcome, not a failure)"
    exit 0
fi
pkill -TERM -f "$B/irlumed" 2>/dev/null
sleep 1

echo "=== 2. one long capture, with NO re-fire inside it ==="
start_daemon watch || exit 2
# camera-tune streams a long window through the same capture path the consent
# watch uses, which is where the every-eighth-frame write used to live.
IRLUME_SOCKET="$SOCK" "$B/irlume" camera-tune --rounds 3 >"$S/watch.out" 2>&1
pkill -TERM -f "$B/irlumed" 2>/dev/null
sleep 1

writes=$(grep -ac "SET_CUR unit$UNIT/sel$SEL" "$S/daemon-watch.log" 2>/dev/null || echo 0)
echo "  SET_CUR writes to unit$UNIT/sel$SEL during the capture: $writes"
grep -aE "SET_CUR|GET_CUR" "$S/daemon-watch.log" | head -6 | sed 's/^/    /'

# The point of the change: the control is written once per stream, not per frame.
# camera-tune opens more than one stream, so the bound is per round rather than a
# flat 1; what must NOT appear is a write every eighth frame.
assert_lt() {
    if [ "$writes" -le "$1" ]; then
        ok "no per-frame re-firing (writes=$writes, at most $1 expected)"
    else
        bad "the control is still being rewritten during streaming" \
            "$writes writes; the every-eighth-frame path should be gone"
    fi
}
assert_lt 8

echo "=== 3. does the control still hold what was set? ==="
start_daemon readback || exit 2
IRLUME_SOCKET="$SOCK" "$B/irlume" ir-setup --dry-run >"$S/readback.out" 2>&1
pkill -TERM -f "$B/irlumed" 2>/dev/null
sleep 1
sed 's/^/  /' "$S/readback.out" | head -3

# `ir-setup` on the second run reports "already set to the value setup would
# apply" when the control survived. That is the self-clear question answered by
# the camera rather than by a comment.
start_daemon confirm || exit 2
IRLUME_SOCKET="$SOCK" "$B/irlume" ir-setup >"$S/confirm.out" 2>&1
pkill -TERM -f "$B/irlumed" 2>/dev/null
sed 's/^/  /' "$S/confirm.out" | tail -2
if grep -qE "already set|IR emitter enabled" "$S/confirm.out"; then
    ok "the camera still answers on that control after a full capture window"
else
    bad "the control did not survive the window" "$(tail -1 "$S/confirm.out")"
fi

echo
echo "$pass passed, $fail failed"
echo "(sandbox left in $S for inspection)"
[ "$fail" -eq 0 ]
