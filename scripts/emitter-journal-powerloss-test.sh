#!/usr/bin/env bash
# Does the undo record survive a real power loss?
#
# `echo b > /proc/sysrq-trigger` reboots the kernel IMMEDIATELY: no sync, no
# unmount, no userspace shutdown. Anything sitting in the page cache is gone.
# That is as close to pulling the plug as a machine can get to itself.
#
# THE CANARY. A test that only checks the record is still there afterwards can
# pass for the wrong reason: ext4 commits its journal every few seconds anyway,
# so the record might survive because the filesystem happened to flush, not
# because irlume fsynced it. So a second file is written immediately after,
# through a plain redirect with no fsync at all, and both are checked after the
# reboot. The record surviving while the canary does NOT is what makes this
# evidence about irlume rather than about ext4's timers.
#
# Run detached: this script kills the machine it is running on.
set -uo pipefail

TREE=/tmp/irl-emitter-hw
IR=/dev/video2
RGB=/dev/video0
STATE=/var/lib/irlume-powertest
OUT=/var/lib/irlume-powertest-out
MODELS=/usr/share/irlume/models
PARK=1,3,1,0,0,0,0,0,0

rm -rf "$STATE" "$OUT"
mkdir -p "$STATE" "$OUT"
# Make the setup durable BEFORE the dangerous part, so what survives afterwards
# is only ever about the window under test.
sync

start_daemon() { # $1 = tag, $2 = override
    rm -f /run/irlume-power.sock
    env IRLUME_SOCKET=/run/irlume-power.sock IRLUME_STATE_DIR="$STATE" \
        IRLUME_IR_EMITTER_CONF="$STATE/ir_emitter.conf" \
        IRLUME_EMITTER_LOCK_DIR="$STATE/locks" \
        IRLUME_RGB_DEVICE="$RGB" IRLUME_IR_DEVICE="$IR" \
        IRLUME_IR_EMITTER="$2" IRLUME_LOG_EMITTER_WRITES=1 \
        IRLUME_DET_MODEL="$MODELS/face_detection_yunet_2023mar.onnx" \
        IRLUME_MODEL="$MODELS/glintr100.onnx" \
        IRLUME_MESH_MODEL="$MODELS/face_landmark.onnx" \
        IRLUME_BLAZE_MODEL="$MODELS/blaze_face_short_range.onnx" \
        "$TREE/target/release/irlumed" >"$OUT/daemon-$1.log" 2>&1 &
    for _ in $(seq 1 400); do
        [ -S /run/irlume-power.sock ] && return 0
        sleep 0.1
    done
    return 1
}

systemctl stop irlumed
sleep 1

# Park, so discovery has a real difference to measure and therefore writes.
start_daemon park "4:6:$PARK" || {
    echo "park daemon failed" >"$OUT/ABORTED"
    sync
    systemctl start irlumed
    exit 2
}
pkill -TERM -f "target/release/irlumed"
sleep 1

start_daemon victim off || {
    echo "victim daemon failed" >"$OUT/ABORTED"
    sync
    systemctl start irlumed
    exit 2
}

# Everything written so far is deliberately made durable, so the only thing the
# reboot can prove or disprove is the record.
sync

IRLUME_SOCKET=/run/irlume-power.sock "$TREE/target/release/irlume" ir-setup \
    >"$OUT/setup.out" 2>&1 &

for _ in $(seq 1 1200); do
    if grep -aq "journal saved" "$OUT/daemon-victim.log" 2>/dev/null; then
        # The canary: same directory, same filesystem, written NOW, never
        # fsynced. If this survives too, the reboot proved nothing.
        echo "if you can read me, the page cache was flushed by something else" \
            >"$STATE/canary-not-fsynced"
        sysctl -w kernel.sysrq=128 >/dev/null
        echo b >/proc/sysrq-trigger
        # Not reached.
        exit 0
    fi
    kill -0 %2 2>/dev/null || break
    sleep 0.05
done

# Only here if no record was ever written: report and put the machine back.
echo "no journal record appeared; nothing was interrupted" >"$OUT/ABORTED"
cat "$OUT/setup.out" >>"$OUT/ABORTED" 2>/dev/null
sync
pkill -TERM -f "target/release/irlumed"
systemctl start irlumed
exit 3
