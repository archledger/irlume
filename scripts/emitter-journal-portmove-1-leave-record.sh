#!/usr/bin/env bash
# Stage 1 of the port-move test: leave an UNRESOLVED undo record at this port.
#
# What the whole test is for: two units of one camera model publish byte-identical
# USB descriptors and, on this model, no serial at all. Filing a record by the
# descriptor digest alone therefore collided, so a capture on the second camera
# loaded the first camera's record, would have written the first camera's bytes
# into the second, and on a successful read-back would have DELETED it, leaving
# the camera that was actually changed with no undo data.
#
# One camera moved between two ports reproduces every part of that except
# simultaneity: same descriptors, same absent serial, different device path.
set -uo pipefail

# Absolute: `~` expands to /root under sudo, and the worktree is not there.
B=${IRLUME_TREE:-/home/archledger/irl-emitter-hw}/target/release
S=/var/lib/irlume-portmove
M=/usr/share/irlume/models
IR=/dev/video2
RGB=/dev/video0
PARK=1,3,1,0,0,0,0,0,0

rm -rf "$S"
mkdir -p "$S"
systemctl stop irlumed 2>/dev/null
sleep 1

start_daemon() { # $1 tag, $2 override
    rm -f /run/irlume-portmove.sock
    env IRLUME_SOCKET=/run/irlume-portmove.sock IRLUME_STATE_DIR="$S" \
        IRLUME_IR_EMITTER_CONF="$S/ir_emitter.conf" \
        IRLUME_EMITTER_LOCK_DIR="$S/locks" \
        IRLUME_RGB_DEVICE="$RGB" IRLUME_IR_DEVICE="$IR" \
        IRLUME_IR_EMITTER="$2" IRLUME_LOG_EMITTER_WRITES=1 \
        IRLUME_DET_MODEL="$M/face_detection_yunet_2023mar.onnx" \
        IRLUME_MODEL="$M/glintr100.onnx" \
        IRLUME_MESH_MODEL="$M/face_landmark.onnx" \
        IRLUME_BLAZE_MODEL="$M/blaze_face_short_range.onnx" \
        "$B/irlumed" >"$S/daemon-$1.log" 2>&1 &
    echo $! >"$S/daemon.pid"
    for _ in $(seq 1 400); do
        [ -S /run/irlume-portmove.sock ] && return 0
        sleep 0.1
    done
    return 1
}

echo "=== the camera, before anything ==="
dev=$(readlink -f /sys/bus/usb/devices/3-2.1)
echo "  devpath: ${dev#/sys}"
echo "  desc:    $(sha256sum "$dev/descriptors" | cut -d' ' -f1)"
echo "  serial:  $(cat "$dev/serial" 2>/dev/null || echo NONE)"

echo "=== park the control so discovery has something to explore ==="
start_daemon park "4:6:$PARK" || {
    echo "daemon would not start"
    exit 2
}
kill -TERM "$(cat "$S/daemon.pid")" 2>/dev/null
sleep 1

echo "=== run ir-setup and SIGKILL it once its record is on disk ==="
start_daemon victim off || {
    echo "daemon would not start"
    exit 2
}
IRLUME_SOCKET=/run/irlume-portmove.sock "$B/irlume" ir-setup >"$S/setup.out" 2>&1 &
client=$!
killed=no
for _ in $(seq 1 900); do
    if grep -aq "journal saved" "$S/daemon-victim.log" 2>/dev/null; then
        kill -KILL "$(cat "$S/daemon.pid")" 2>/dev/null && killed=yes
        break
    fi
    kill -0 "$client" 2>/dev/null || break
    sleep 0.05
done
wait "$client" 2>/dev/null

if [ "$killed" != yes ]; then
    echo "NOT EXERCISED: no record was written, so there is nothing to move away from"
    cat "$S/setup.out"
    systemctl start irlumed
    exit 3
fi

record=$(find "$S/ir-emitter-journal" -name '*.json' | head -1)
if [ -z "$record" ]; then
    echo "FAILED: the kill left no record"
    systemctl start irlumed
    exit 1
fi
echo "=== the unresolved record now sitting at this port ==="
echo "  file: $(basename "$record")"
sed 's/^/  /' "$record"
echo
echo "STAGE 1 DONE. The camera is left CHANGED, with this record describing how"
echo "to undo it. Now move the camera to hub port 2 or 4 (it is on port 1)."
# The packaged daemon stays stopped on purpose: starting it would drive the
# emitter and resolve the very record this test needs left alone.
echo "(the packaged irlumed is deliberately left stopped until the test finishes)"
