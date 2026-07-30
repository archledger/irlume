#!/usr/bin/env bash
# Two IR cameras on one machine: does either one's setup destroy the other's
# undo data?
#
#   sudo bash emitter-journal-two-cameras-test.sh <worktree> <ir-A> <rgb-A> <ir-B> <rgb-B>
#
# WHY THIS EXISTS
#
# Records are filed per camera because a machine can have more than one, and a
# single shared file would let the second camera's setup replace the first
# camera's record — the exact loss the module exists to prevent. Until this ran,
# that was covered only by a unit test with a synthetic second identity.
#
# It could not be shown with ONE camera moved between ports, because at an
# address it cannot confirm, discovery deliberately refuses and therefore never
# creates a second record. Two DIFFERENT models are what make it reachable: each
# is plainly not the other, so setup on the second proceeds normally, and the
# question "did it tread on the first camera's record" gets a real answer.
#
# WHAT IT WRITES
#
# One `ir-setup` per camera: a documented Microsoft extension-unit control,
# values the camera itself reported. Everything else is sandboxed under its own
# state directory, emitter config and lock directory, so the installed irlume's
# files are never read or written. The packaged daemon is stopped for the
# duration and restored from its ENABLED state, not from whether it happened to
# be running.
set -uo pipefail

TREE="${1:?usage: $0 <worktree> <ir-A> <rgb-A> <ir-B> <rgb-B>}"
IR_A="${2:?}"
RGB_A="${3:?}"
IR_B="${4:?}"
RGB_B="${5:?}"

B="$TREE/target/release"
S=/var/lib/irlume-twocam
M="${IRLUME_MODEL_DIR:-/usr/share/irlume/models}"
# Taken from the packaged unit rather than assumed. Without it the daemon never
# reaches its socket and simply sits on a futex, which reads as a hung build:
# the ONNX runtime is shipped beside irlume on some installs and found on the
# default search path on others.
ORT="${ORT_DYLIB_PATH:-$(systemctl cat irlumed 2>/dev/null |
    sed -n 's/^Environment="\?ORT_DYLIB_PATH=\([^"]*\)"\?$/\1/p' | head -1)}"
STORE="$S/ir-emitter-journal"
PARK=1,3,1,0,0,0,0,0,0

pass=0
fail=0
skipped=0
ok() { pass=$((pass + 1)); echo "  ok      $1"; }
bad() {
    fail=$((fail + 1))
    echo "  FAILED  $1"
    echo "            $2"
}
assert() {
    local d="$1" x="$2"
    shift 2
    if "$@"; then ok "$d"; else bad "$d" "$x"; fi
}
assert_not() {
    local desc="$1" detail="$2"
    shift 2
    if "$@"; then bad "$desc" "$detail"; else ok "$desc"; fi
}
skip() {
    skipped=$((skipped + 1))
    echo "  NOT EXERCISED  $1"
}

[ "$(id -u)" -eq 0 ] || {
    echo "refusing: writes camera firmware, needs root"
    exit 2
}
for n in "$IR_A" "$RGB_A" "$IR_B" "$RGB_B"; do
    [ -e "$n" ] || {
        echo "refusing: $n does not exist"
        exit 2
    }
done

cleanup() {
    pkill -KILL -f "$B/irlumed" 2>/dev/null
    rm -f /run/irlume-twocam.sock
    if systemctl is-enabled --quiet irlumed 2>/dev/null; then
        systemctl start irlumed 2>/dev/null
        echo "  (packaged irlumed: $(systemctl is-active irlumed))"
    fi
}
trap cleanup EXIT

rm -rf "$S"
mkdir -p "$S"
# A sandboxed state directory does not have the opt-in third-party PAD weights,
# and on a machine where `settings.conf` enables one the daemon stops during
# startup rather than reaching its socket. Link the real ones in, read-only as
# far as this test is concerned: the point here is the emitter, not the models.
if [ -d /var/lib/irlume/models-thirdparty ]; then
    ln -sfn /var/lib/irlume/models-thirdparty "$S/models-thirdparty"
fi
systemctl stop irlumed 2>/dev/null
sleep 1

daemon_pid=""
start_daemon() { # tag, ir, rgb, override
    rm -f /run/irlume-twocam.sock
    env IRLUME_SOCKET=/run/irlume-twocam.sock IRLUME_STATE_DIR="$S" \
        IRLUME_IR_EMITTER_CONF="$S/ir_emitter.conf" \
        IRLUME_EMITTER_LOCK_DIR="$S/locks" \
        IRLUME_RGB_DEVICE="$3" IRLUME_IR_DEVICE="$2" \
        IRLUME_IR_EMITTER="$4" IRLUME_LOG_EMITTER_WRITES=1 \
        IRLUME_DET_MODEL="$M/face_detection_yunet_2023mar.onnx" \
        IRLUME_MODEL="$M/glintr100.onnx" \
        IRLUME_MESH_MODEL="$M/face_landmark.onnx" \
        IRLUME_BLAZE_MODEL="$M/blaze_face_short_range.onnx" \
        ${ORT:+ORT_DYLIB_PATH="$ORT"} \
        "$B/irlumed" >"$S/daemon-$1.log" 2>&1 &
    daemon_pid=$!
    # Generous: this daemon loads four ONNX models before it listens, which on a
    # laptop takes longer than the camera work that follows it. A short wait here
    # reads as "the build is broken" when it only means "not finished loading".
    for _ in $(seq 1 1800); do
        [ -S /run/irlume-twocam.sock ] && return 0
        kill -0 "$daemon_pid" 2>/dev/null || {
            echo "  the daemon exited during startup:"
            tail -4 "$S/daemon-$1.log" | sed 's/^/    /'
            return 1
        }
        sleep 0.1
    done
    echo "  the daemon never listened; last lines:"
    tail -4 "$S/daemon-$1.log" | sed 's/^/    /'
    return 1
}
stop_daemon() {
    [ -n "$daemon_pid" ] && kill -TERM "$daemon_pid" 2>/dev/null
    wait "$daemon_pid" 2>/dev/null
    daemon_pid=""
    # The next daemon opens the same camera. Waiting for the node to be free
    # beats racing it and reporting a busy device as a broken build.
    for _ in $(seq 1 100); do
        fuser "$IR_A" "$IR_B" >/dev/null 2>&1 || break
        sleep 0.1
    done
}
setup() { IRLUME_SOCKET=/run/irlume-twocam.sock "$B/irlume" ir-setup "$@"; }

echo "=== 0. two cameras, and they really are different ==="
ident() { # ir node -> "vid:pid devpath"
    local bus
    bus=$(v4l2-ctl -d "$1" --info 2>/dev/null | grep "Bus info" | head -1 | sed 's/.*usb-//;s/ .*//')
    for d in /sys/bus/usb/devices/*/; do
        [ -f "$d/idVendor" ] || continue
        if find "$d" -maxdepth 3 -name "$(basename "$1")" 2>/dev/null | grep -q .; then
            echo "$(cat "$d/idVendor"):$(cat "$d/idProduct") $(readlink -f "$d" | sed 's,/sys,,')"
            return
        fi
    done
    echo "unknown $bus"
}
a_id=$(ident "$IR_A")
b_id=$(ident "$IR_B")
echo "  A ($IR_A): $a_id"
echo "  B ($IR_B): $b_id"
assert "they are two different devices" "the same camera twice proves nothing" \
    test "${a_id#* }" != "${b_id#* }"

echo "=== 1. leave an UNRESOLVED record on camera A ==="
# NOT redirected to /dev/null. Hiding this step's diagnostics is how a failed
# park went unnoticed and left its daemon holding the camera, so the next start
# failed and the failure looked like it belonged there.
start_daemon parkA "$IR_A" "$RGB_A" "14:6:$PARK" || {
    echo "could not park camera A"
    exit 2
}
stop_daemon
start_daemon killA "$IR_A" "$RGB_A" off || {
    echo "daemon would not start on A"
    exit 2
}
setup >"$S/a-setup.out" 2>&1 &
client=$!
killed=no
for _ in $(seq 1 900); do
    if grep -aq "journal saved" "$S/daemon-killA.log" 2>/dev/null; then
        kill -KILL "$daemon_pid" 2>/dev/null && killed=yes
        break
    fi
    kill -0 "$client" 2>/dev/null || break
    sleep 0.05
done
wait "$client" 2>/dev/null
daemon_pid=""

if [ "$killed" != yes ]; then
    skip "camera A was never written to, so there is no record to protect"
    skip "the second camera's setup was not tested against one"
    skip "recovery of A was not tested"
    echo "  reason: $(grep -ao 'already set.*\|hardware:.*' "$S/a-setup.out" | head -1)"
    echo
    echo "$pass passed, $fail failed, $skipped not exercised"
    exit "$fail"
fi

a_record=$(find "$STORE" -name '*.json' | head -1)
assert "camera A has an unresolved record" "nothing in $STORE" test -n "$a_record"
[ -n "$a_record" ] || exit 1
a_before=$(md5sum "$a_record" | cut -d' ' -f1)
echo "  A's record: $(basename "$a_record")"

echo "=== 2. now set up camera B, with A's record sitting there ==="
start_daemon setupB "$IR_B" "$RGB_B" "4:6:$PARK" || {
    echo "could not park camera B"
    exit 2
}
stop_daemon
start_daemon runB "$IR_B" "$RGB_B" off || {
    echo "daemon would not start on B"
    exit 2
}
setup >"$S/b-setup.out" 2>&1
stop_daemon
sed 's/^/  /' "$S/b-setup.out" | tail -2

# The whole point. Before records were filed per camera, B's setup would have
# written its record over A's, and A's original bytes would be gone.
assert "A's record still exists" "camera B's setup deleted it" test -f "$a_record"
assert "A's record is byte-identical" "camera B's setup rewrote it" \
    test "$(md5sum "$a_record" 2>/dev/null | cut -d' ' -f1)" = "$a_before"
assert "B never wrote to A's extension unit" "a write crossed between cameras" \
    test "$(grep -ac 'SET_CUR unit14' "$S/daemon-runB.log")" -eq 0
assert "B's own run did write to its own unit" \
    "B never wrote anything, so nothing was tested against A's record" \
    test "$(grep -ac 'SET_CUR unit4/' "$S/daemon-runB.log")" -gt 0
# The absence of the cross-camera refusal, NOT the presence of success. Whether
# discovery finds a usable control depends on the room: this camera reported the
# image rising 114 -> 132 against a +20 threshold and correctly called the
# control unusable. That is a hardware outcome and has nothing to do with the
# other camera's record. Asserting "IR emitter enabled" made a legitimate
# NotUsable read as "B was blocked", which is a different claim entirely.
# `grep -qv` is NOT "does not contain": it succeeds as soon as ONE line fails to
# match, so a file holding the forbidden refusal plus any other line passed. This
# assertion reported ok while the very thing it forbids was in the output, and
# the 8/8 it was part of did not establish it. Absence is a POSITIVE grep,
# negated by the caller.
assert_not "B's setup was not refused because of A's record" \
    "B was blocked by another camera's pending change" \
    grep -qE "not at that address|earlier setup run left a control" "$S/b-setup.out"
if grep -q "IR emitter enabled" "$S/b-setup.out"; then
    echo "  (B found a usable control)"
else
    echo "  (B ran discovery and found no usable control: $(grep -ao 'unit [0-9]* advertises.*' "$S/b-setup.out" | head -1))"
fi

echo "=== 3. camera A recovers, untouched by any of it ==="
start_daemon recoverA "$IR_A" "$RGB_A" off || {
    echo "daemon would not start on A"
    exit 2
}
setup >"$S/a-recover.out" 2>&1
stop_daemon
grep -aE "journal|SET_CUR" "$S/daemon-recoverA.log" | head -8 | sed 's/^/  /'
assert "A's record is resolved and gone" "still pending" \
    test ! -f "$a_record"

echo
echo "$pass passed, $fail failed, $skipped not exercised"
echo "(sandbox left in $S for inspection; remove it when done)"
[ "$fail" -eq 0 ]
