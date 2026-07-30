#!/usr/bin/env bash
# Prove, from syscalls, that the undo record is DURABLE before the camera is
# written to.
#
# An fsync leaves no trace in the filesystem afterwards, so no test can observe
# it and "the code calls it" is not evidence it reached the right object in the
# right order. This traces the daemon through one `ir-setup` and reads the
# ordering off the syscall log:
#
#   openat(<record>.tmp) -> fsync(that fd) -> rename -> fsync(<store dir>)
#   ... and only then ioctl(<camera fd>, UVCIOC_CTRL_QUERY) carrying SET_CUR
#
# UVCIOC_CTRL_QUERY is _IOWR('u', 0x21, ...) = 0xc0107521 on 64-bit, which strace
# prints unrecognised as that number.
set -uo pipefail

TREE=/tmp/irl-emitter-hw
IR=/dev/video2
RGB=/dev/video0
OUT=/tmp/emitter-strace
SOCK=/run/irlume-strace.sock
STATE=/var/lib/irlume-stracetest
MODELS=/usr/share/irlume/models
PARK=1,3,1,0,0,0,0,0,0

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  ok      $1"; }
bad() {
    fail=$((fail + 1))
    echo "  FAILED  $1"
    echo "            $2"
}

[ "$(id -u)" -eq 0 ] || {
    echo "needs root"
    exit 2
}
rm -rf "$OUT" "$STATE"
mkdir -p "$OUT" "$STATE"

was_enabled=no
systemctl is-enabled --quiet irlumed 2>/dev/null && was_enabled=yes
cleanup() {
    pkill -KILL -f "irlume-strace" 2>/dev/null
    rm -f "$SOCK"
    [ "$was_enabled" = yes ] && systemctl start irlumed 2>/dev/null
    echo "  (packaged irlumed: $(systemctl is-active irlumed))"
}
trap cleanup EXIT
systemctl stop irlumed 2>/dev/null
sleep 1

start_daemon() { # $1 = tag, $2 = override, $3 = "strace" to trace it
    rm -f "$SOCK"
    local pre=()
    # `write` is traced too, which is the trick that makes this readable: the
    # daemon's own `IRLUME_LOG_EMITTER_WRITES` lines go to stderr, so they land
    # in the SAME syscall stream, in order, and name which XU query each ioctl
    # is. Every extension-unit request uses one ioctl number, so the trace alone
    # cannot tell a GET from a SET.
    if [ "${3:-}" = strace ]; then
        # One quoted element: the comma list is strace's argument, not shell
        # array syntax.
        local syscalls="trace=openat,fsync,fdatasync,rename,unlink,unlinkat,ioctl,write"
        pre=(strace -f -y -o "$OUT/trace.log" -s 120 -e "$syscalls")
    fi
    env IRLUME_SOCKET="$SOCK" IRLUME_STATE_DIR="$STATE" \
        IRLUME_IR_EMITTER_CONF="$STATE/ir_emitter.conf" \
        IRLUME_EMITTER_LOCK_DIR="$STATE/locks" \
        IRLUME_RGB_DEVICE="$RGB" IRLUME_IR_DEVICE="$IR" \
        IRLUME_IR_EMITTER="$2" IRLUME_LOG_EMITTER_WRITES=1 \
        IRLUME_DET_MODEL="$MODELS/face_detection_yunet_2023mar.onnx" \
        IRLUME_MODEL="$MODELS/glintr100.onnx" \
        IRLUME_MESH_MODEL="$MODELS/face_landmark.onnx" \
        IRLUME_BLAZE_MODEL="$MODELS/blaze_face_short_range.onnx" \
        "${pre[@]}" "$TREE/target/release/irlumed" >"$OUT/daemon-$1.log" 2>&1 &
    for _ in $(seq 1 400); do
        [ -S "$SOCK" ] && return 0
        sleep 0.1
    done
    return 1
}

echo "=== park the control so discovery has something to explore ==="
start_daemon park "4:6:$PARK" || {
    echo "daemon would not start"
    exit 2
}
pkill -TERM -f "target/release/irlumed" 2>/dev/null
sleep 1

echo "=== trace one ir-setup ==="
start_daemon traced off strace || {
    echo "traced daemon would not start"
    tail -20 "$OUT/daemon-traced.log"
    exit 2
}
IRLUME_SOCKET="$SOCK" "$TREE/target/release/irlume" ir-setup 2>&1 | sed 's/^/    /'
pkill -TERM -f "target/release/irlumed" 2>/dev/null
sleep 2

echo "=== the ordering, from syscalls ==="
# strace -y annotates every fd with its path, so no fd bookkeeping is needed.
grep -nE 'ir-emitter-journal|UVCIOC|irlume: SET_CUR|irlume: journal' "$OUT/trace.log" |
    grep -vE 'ENOENT|resumed' >"$OUT/relevant.log"
sed -n '1,25p' "$OUT/relevant.log" | sed 's/^/    /'

# The record's own fsync, the store directory's fsync, and the first XU ioctl.
rec_fsync=$(grep -nE 'fsync\([0-9]+<.*ir-emitter-journal/.*tmp' "$OUT/relevant.log" | head -1 | cut -d: -f1)
dir_fsync=$(grep -nE 'fsync\([0-9]+<.*ir-emitter-journal>' "$OUT/relevant.log" | head -1 | cut -d: -f1)
# The first WRITE, not the first extension-unit request. The reads that precede
# it are not merely allowed before the record, they are REQUIRED: the original
# cannot be recorded until GET_CUR has answered. An earlier version of this
# script compared against the first ioctl of any kind and reported correct
# behaviour as a failure, which is the third time an assertion here has been
# wrong before the product was.
first_xu=$(grep -n 'irlume: SET_CUR' "$OUT/relevant.log" | head -1 | cut -d: -f1)

if [ -z "$first_xu" ]; then
    echo "  NOT EXERCISED  no SET_CUR was traced; nothing to order the record against"
    fail=1
else
    # `cond && ok || bad` also runs bad when ok fails, which is the SC2015 trap
    # the container suite in this directory documents. if/else, every time.
    if [ -n "$rec_fsync" ]; then
        ok "the record's own bytes are fsynced (line $rec_fsync)"
    else
        bad "the record was never fsynced" "no fsync on a journal temp file"
    fi
    if [ -n "$dir_fsync" ]; then
        ok "the store directory is fsynced (line $dir_fsync)"
    else
        bad "the store directory was never fsynced" "the rename could be lost"
    fi
    if [ -n "$rec_fsync" ] && [ "$rec_fsync" -lt "$first_xu" ]; then
        ok "the record is durable BEFORE the first SET_CUR ($rec_fsync < $first_xu)"
    else
        bad "the record is not durable before the camera is written to" \
            "record fsync at ${rec_fsync:-none}, first SET_CUR at $first_xu"
    fi
    if [ -n "$dir_fsync" ] && [ "$dir_fsync" -lt "$first_xu" ]; then
        ok "the directory entry is durable before it too ($dir_fsync < $first_xu)"
    else
        bad "the directory entry is not durable before the camera is written to" \
            "dir fsync at ${dir_fsync:-none}, first SET_CUR at $first_xu"
    fi
fi

echo
echo "$pass passed, $fail failed"
echo "full trace in $OUT/trace.log"
[ "$fail" -eq 0 ]
