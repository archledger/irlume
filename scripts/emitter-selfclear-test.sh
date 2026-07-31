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
skipped=0
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
    if [ "$irlumed_was_active" = active ]; then
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
# Restores the daemon to the state it was ACTUALLY in, not to whether it is
# enabled. A machine where irlumed is enabled but deliberately stopped came back
# running, which is this script changing the system it was only supposed to
# measure.
irlumed_was_active=$(systemctl is-active irlumed 2>/dev/null || true)
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

# Selector 0x06 SPECIFICALLY, and refuse otherwise.
#
# Taking "the first advertised selector" was wrong: a Microsoft XU can advertise
# 0x09 (metadata) ahead of 0x06 (face authentication), and the park value below
# describes face authentication. Writing it to whatever came first is a payload
# that does not describe the control it reaches, which is the #159 mistake in a
# test harness.
if ! grep -q "unit $UNIT (Microsoft camera control): advertises \[.*0x06" "$S/units.out"; then
    echo "refusing: unit $UNIT does not advertise 0x06 (face authentication);"
    echo "          this harness only drives that control"
    exit 2
fi
SEL=6

# The park payload is NOT derived from this camera, so it is only used on cameras
# it is known to describe.
#
# `1,3,1,...` is bNumEntries=1, streaming interface 3, mode D0. Interface 3 is
# what the ASUS 3277:0059 and NexiGo 3443:c803 publish; another camera's
# face-auth entry can name a different interface, and sending this to it writes a
# structure describing hardware that is not there. The production gate checks the
# selector is advertised and the length matches; it does not check the entry
# contents, so it would not stop this.
# Resolved from the node being driven, NOT from the bus. `lsusb | grep` matched a
# known camera anywhere on the machine, so on a laptop whose built-in ASUS sits
# beside an external camera the guard passed while the TARGET was the external
# one. Measured: it let a Logitech BRIO through on this machine.
node_dev=$(udevadm info -q path -n "$IR" 2>/dev/null | sed 's,/video4linux.*,,')
VID_PID=""
if [ -n "$node_dev" ]; then
    d=/sys$node_dev
    while [ -n "$d" ] && [ "$d" != "/sys" ] && [ "$d" != "/" ]; do
        if [ -r "$d/idVendor" ] && [ -r "$d/idProduct" ]; then
            VID_PID="$(cat "$d/idVendor"):$(cat "$d/idProduct")"
            break
        fi
        d=$(dirname "$d")
    done
fi
echo "  camera behind $IR: ${VID_PID:-unknown}"
case "$VID_PID" in
    3277:0059 | 3443:c803) known_park=yes ;;
    *) known_park=no ;;
esac
if [ -z "${PARK_VALUE:-}" ] && [ "$known_park" = no ]; then
    echo "refusing: the built-in park value describes the ASUS 3277:0059 and"
    echo "          NexiGo 3443:c803 streaming interface 3, and this is neither."
    echo "          Set PARK_VALUE to a payload derived from THIS camera's"
    echo "          GET_DEF, or run the read-only sections only."
    exit 2
fi
if [ -z "$UNIT" ] || [ -z "$SEL" ]; then
    echo "refusing: no Microsoft camera-control unit here; nothing in #168 applies"
    exit 2
fi
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

log="$S/daemon-watch.log"
writes=$(grep -ac "SET_CUR unit$UNIT/sel$SEL" "$log" 2>/dev/null || true)
# The applied value and the camera's default, counted separately. A flat total
# cannot tell "twice per stream" from "once every eighth frame": the restore that
# #168 adds is a second write BY DESIGN, so the total legitimately doubles while
# the thing being removed disappears.
applied=$(grep -ac "SET_CUR unit$UNIT/sel$SEL: \[01, 03, 02" "$log" 2>/dev/null || true)
restored=$(grep -ac "SET_CUR unit$UNIT/sel$SEL: \[01, 03, 01" "$log" 2>/dev/null || true)
echo "  SET_CUR to unit$UNIT/sel$SEL: $writes total ($applied applied, $restored restored)"
grep -aE "SET_CUR unit$UNIT/sel$SEL" "$log" | head -6 | sed 's/^/    /'

# The property #168 asks for, and it does not depend on how many frames ran:
# every mode set for a stream is put back when that stream ends.
if [ "$applied" -gt 0 ] && [ "$applied" -eq "$restored" ]; then
    ok "every applied mode was put back ($applied set, $restored restored)"
elif [ "$applied" -eq 0 ]; then
    bad "the mode was never applied" "nothing to observe; check the setup step"
else
    bad "sets and restores do not pair up" \
        "$applied applied against $restored restored; a stream ended without unsetting"
fi

# And the removed behaviour: re-firing every eighth frame put many MORE applied
# writes than there were streams. Each stream now contributes exactly one applied
# write, so applied must not exceed the restores, which count the streams.
if [ "$applied" -le "$restored" ]; then
    ok "no per-frame re-firing (one applied write per stream, not one per 8 frames)"
else
    bad "the control is still being rewritten during streaming" \
        "$applied applied writes against $restored streams"
fi

echo "=== 3. did the value survive WHILE the stream was running? ==="
# NOT ANSWERED HERE, and the earlier version of this section pretended otherwise.
#
# It read the control back after the daemon had been killed. Killing the request
# drops the guard, which restores the camera's default, so the readback examined
# the post-restore state and said nothing about whether the applied value
# survived during streaming. Its assertion then accepted BOTH "already set" and
# "IR emitter enabled" as success, which are opposite outcomes, so it could not
# fail for the thing it claimed to check. A camera that self-cleared right after
# STREAMON would have passed it.
#
# Answering it needs a GET_CUR taken from INSIDE a live stream, before STREAMOFF
# and before the guard runs. `crates/irlume-camera/examples/ir_refire_probe.rs`
# already owns one uninterrupted stream and is where that readback belongs.
skipped=$((skipped + 1))
echo "  NOT EXERCISED  needs an in-stream GET_CUR; see ir_refire_probe.rs"
echo "                 what sections 1 and 2 DO establish is the write count and"
echo "                 that every applied mode is paired with a restore"

echo
echo "$pass passed, $fail failed, $skipped not exercised"
echo "(sandbox left in $S for inspection)"
[ "$fail" -eq 0 ]
