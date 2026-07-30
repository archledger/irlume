#!/usr/bin/env bash
# Stage 2: the camera is now at a DIFFERENT device path. Its descriptors and its
# (absent) serial are unchanged, so this is byte-for-byte what a second unit of
# the same model looks like to irlume.
#
# What must happen, and what used to happen instead:
#
#   * The record from the other path must NOT be acted on. Before the fix the key
#     was the descriptor digest alone, so this record would have been loaded as
#     "mine", its bytes written to this camera, and then DELETED on a successful
#     read-back, leaving the camera that was actually changed with no undo data.
#   * It must NOT be deleted.
#   * The emitter must stay off, because the other reading of this situation is
#     that this IS that camera, still holding an exploratory value.
#   * Discovery must refuse to start, since its first act is to read a control
#     and call the answer the original.
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
    echo "refusing: no record from stage 1"
    exit 2
}
before=$(md5sum "$record" | cut -d' ' -f1)
old_path=$(grep -o '"usb_devpath":"[^"]*"' "$record" | cut -d'"' -f4)
# Found by product id, not by a hardcoded address: the whole point of this test
# is that the address changes, so pinning one is how the script stops testing
# what it claims to.
cam=""
for d in /sys/bus/usb/devices/*/; do
    if [ -f "$d/idProduct" ] && grep -q c803 "$d/idProduct" 2>/dev/null; then
        cam="${d%/}"
        break
    fi
done
[ -n "$cam" ] || {
    echo "refusing: the camera is not attached"
    exit 2
}
new_path=$(readlink -f "$cam" | sed 's,/sys,,')

echo "=== the two addresses ==="
echo "  record was written at: $old_path"
echo "  the camera is now at:  $new_path"
assert "the camera really did move" "same path; nothing was moved" \
    test "$old_path" != "$new_path"
assert "its descriptors are unchanged" "a different model would prove nothing" \
    grep -q "$(sha256sum "$cam/descriptors" | cut -d' ' -f1)" "$record"

rm -f /run/irlume-portmove.sock
env IRLUME_SOCKET=/run/irlume-portmove.sock IRLUME_STATE_DIR="$S" \
    IRLUME_IR_EMITTER_CONF="$S/ir_emitter.conf" \
    IRLUME_EMITTER_LOCK_DIR="$S/locks" \
    IRLUME_RGB_DEVICE="$RGB" IRLUME_IR_DEVICE="$IR" \
    IRLUME_LOG_EMITTER_WRITES=1 \
    IRLUME_DET_MODEL="$M/face_detection_yunet_2023mar.onnx" \
    IRLUME_MODEL="$M/glintr100.onnx" \
    IRLUME_MESH_MODEL="$M/face_landmark.onnx" \
    IRLUME_BLAZE_MODEL="$M/blaze_face_short_range.onnx" \
    "$B/irlumed" >"$S/daemon-moved.log" 2>&1 &
pid=$!
for _ in $(seq 1 400); do
    [ -S /run/irlume-portmove.sock ] && break
    sleep 0.1
done
[ -S /run/irlume-portmove.sock ] || {
    echo "daemon would not start"
    tail -8 "$S/daemon-moved.log"
    exit 2
}

echo "=== what the daemon says about the camera in front of it ==="
grep -a "irlume:" "$S/daemon-moved.log" | grep -viE "loading|loaded|listening" | head -6 | sed 's/^/  /'

echo "=== ir-setup at the new address ==="
IRLUME_SOCKET=/run/irlume-portmove.sock "$B/irlume" ir-setup >"$S/moved-setup.out" 2>&1
sed 's/^/  /' "$S/moved-setup.out"

echo "=== doctor ==="
IRLUME_SOCKET=/run/irlume-portmove.sock IRLUME_STATE_DIR="$S" "$B/irlume" doctor --json 2>/dev/null |
    grep -o '{[^{}]*"id":"emitter-undo-pending"[^{}]*}' | sed 's/^/  /'

kill -TERM "$pid" 2>/dev/null
sleep 1

echo "=== the verdict ==="
assert "the record was NOT deleted" "the other camera's undo data is gone" \
    test -f "$record"
assert "the record was not modified either" "it was rewritten" \
    test "$(md5sum "$record" | cut -d' ' -f1)" = "$before"
assert "nothing was written to this camera's emitter control" \
    "a SET_CUR reached a camera whose record could not be confirmed" \
    test "$(grep -ac 'SET_CUR' "$S/daemon-moved.log")" -eq 0
assert "discovery refused to start" "it ran against an unconfirmable control" \
    grep -qiE "not at that address|earlier setup run|unresolved" "$S/moved-setup.out"
assert "the operator is told where the original is" "no store path in the message" \
    grep -q "$S" "$S/daemon-moved.log"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
