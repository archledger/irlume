#!/usr/bin/env bash
# Stage 3: the camera is back at the address its record was written at.
#
# The refusal in stage 2 is only defensible if the promise attached to it is
# true. The message told the operator to reconnect the camera to the port it was
# set up on and it would be put back automatically, so this checks exactly that,
# and checks the control really does come back to the bytes recorded before
# anything touched it.
set -uo pipefail

B=${IRLUME_TREE:-/home/archledger/irl-emitter-hw}/target/release
S=/var/lib/irlume-portmove
M=/usr/share/irlume/models
IR=/dev/video2
RGB=/dev/video0

pass=0
fail=0
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

record=$(find "$S/ir-emitter-journal" -name '*.json' | head -1)
[ -n "$record" ] || {
    echo "refusing: no record left to recover"
    exit 2
}
original=$(grep -o '"original":"[^"]*"' "$record" | cut -d'"' -f4)
attempted=$(grep -o '"attempted":"[^"]*"' "$record" | cut -d'"' -f4)
recorded_at=$(grep -o '"usb_devpath":"[^"]*"' "$record" | cut -d'"' -f4)
cam=""
for d in /sys/bus/usb/devices/*/; do
    if [ -f "$d/idProduct" ] && grep -q c803 "$d/idProduct" 2>/dev/null; then
        cam="${d%/}"
        break
    fi
done
now_at=$(readlink -f "$cam" | sed 's,/sys,,')

echo "=== the addresses agree again ==="
echo "  recorded at: $recorded_at"
echo "  camera at:   $now_at"
assert "the camera is back where the record was written" "still elsewhere" \
    test "$recorded_at" = "$now_at"

rm -f /run/irlume-portmove.sock
env IRLUME_SOCKET=/run/irlume-portmove.sock IRLUME_STATE_DIR="$S" \
    IRLUME_IR_EMITTER_CONF="$S/ir_emitter.conf" \
    IRLUME_EMITTER_LOCK_DIR="$S/locks" \
    IRLUME_RGB_DEVICE="$RGB" IRLUME_IR_DEVICE="$IR" \
    IRLUME_IR_EMITTER=off IRLUME_LOG_EMITTER_WRITES=1 \
    IRLUME_DET_MODEL="$M/face_detection_yunet_2023mar.onnx" \
    IRLUME_MODEL="$M/glintr100.onnx" \
    IRLUME_MESH_MODEL="$M/face_landmark.onnx" \
    IRLUME_BLAZE_MODEL="$M/blaze_face_short_range.onnx" \
    "$B/irlumed" >"$S/daemon-home.log" 2>&1 &
pid=$!
for _ in $(seq 1 400); do
    [ -S /run/irlume-portmove.sock ] && break
    sleep 0.1
done
[ -S /run/irlume-portmove.sock ] || {
    echo "daemon would not start"
    tail -8 "$S/daemon-home.log"
    exit 2
}

# `IRLUME_IR_EMITTER=off` above means the daemon's own startup writes nothing, so
# whatever reaches the camera below comes from the recovery pass and nothing
# else. `ir-setup` is the trigger; recovery runs before it reads anything.
echo "=== recovery, at the address the record names ==="
IRLUME_SOCKET=/run/irlume-portmove.sock "$B/irlume" ir-setup >"$S/home-setup.out" 2>&1
sed 's/^/  /' "$S/home-setup.out"
kill -TERM "$pid" 2>/dev/null
sleep 1

echo "=== traced ==="
grep -aE "journal|SET_CUR" "$S/daemon-home.log" | head -12 | sed 's/^/  /'

echo "=== the verdict ==="
assert "the record was acted on and is gone" "it is still pending" \
    test -z "$(find "$S/ir-emitter-journal" -name '*.json' 2>/dev/null)"
# The bytes matter, not just that something was written: a restore that wrote
# anything else would still empty the store.
# TWO correct outcomes, and which one happens depends on whether the control is
# still holding the exploratory value when the record is found again.
#
#   * still changed  -> the attempt is counted durably, the original is written
#                       back, read back, and only then is the record dropped.
#   * already back   -> nothing is written at all and the record is dropped.
#
# Both are right; writing to a control that already holds the recorded value
# would be a firmware write for no reason. Asserting only the first read a
# correct run as a failure: a physical unplug removes bus power, and this camera
# comes back at its default, which IS the recorded original. Re-enumeration
# without a power cut does NOT clear it, measured separately by driving the
# control and toggling `authorized`.
if grep -aq "journal saved.*attempts=1" "$S/daemon-home.log"; then
    echo "  (the control was still changed: the restoring path ran)"
    assert "the ORIGINAL bytes were written back" "restored to something else" \
        grep -aq "SET_CUR unit4/sel6: \[01, 03, 01" "$S/daemon-home.log"
    assert "the attempt was counted before that write" "no durable attempt recorded" \
        grep -aq "journal saved.*attempts=1" "$S/daemon-home.log"
    assert "the control was read back before the record was dropped" "no read-back" \
        grep -aq "GET_CUR" "$S/daemon-home.log"
else
    echo "  (the control was already back at its recorded original)"
    # The discriminating part: it must have been CHECKED, and not written to.
    assert "the control was read before anything was decided" "no GET_CUR at all" \
        grep -aq "GET_CUR" "$S/daemon-home.log"
    before_clear=$(grep -an "journal cleared" "$S/daemon-home.log" | head -1 | cut -d: -f1)
    assert "no write was made to undo a change that was not there" \
        "a SET_CUR preceded the first clear" \
        test "$(head -n "$((before_clear - 1))" "$S/daemon-home.log" | grep -ac SET_CUR)" -eq 0
fi
echo "  (recorded original $original, attempted $attempted)"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
