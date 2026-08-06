#!/usr/bin/env bash
# Does an IRLUME_IR_EMITTER override reach the camera on EVERY stream, or only
# the first one after a daemon start? (#168)
#
#   sudo bash emitter-override-per-stream-test.sh <worktree> [requests]
#
# WHY THE SHAPE MATTERS
#
# `apply_override` memoises a successful override for the life of the PROCESS.
# So this needs one daemon and several SEPARATE requests. A single request with
# more rounds does not exercise it, and an earlier attempt that did exactly that
# produced one stream and proved nothing either way.
#
# Baseline is the commit BEFORE the memo fix, not main. On main the mode is never
# restored, so the memo's read-back still matches the payload and later streams
# report lit; the defect only exists once the per-stream restore is added. Run
# against main and the two sides look identical, which would read as "the fix was
# unnecessary".
#
# Measured on the ASUS 3277:0059, three requests:
#
#   before the fix   applied=1  restored=1   <- streams 2 and 3 ran dark
#   after            applied=7  restored=7
set -uo pipefail
TREE="${1:?tree}"; N="${2:-3}"
B="$TREE/target/release"; S=/var/lib/irlume-memoprobe; SOCK=/run/irlume-memoprobe.sock
M=/usr/share/irlume/models
ORT=$(systemctl cat irlumed 2>/dev/null | sed -n 's/^Environment="\?ORT_DYLIB_PATH=\([^"]*\)"\?$/\1/p' | head -1)
# A cleanup trap, so an interrupted run does not leave a sandboxed daemon holding
# the camera and the packaged one stopped. Without it, Ctrl-C between the stop
# and the restore left the machine with no working face login and a stray daemon
# on the device.
cleanup() {
    pkill -KILL -f "$B/irlumed" 2>/dev/null
    rm -f "$SOCK"
    [ "${irlumed_was_active:-}" = active ] && systemctl start irlumed 2>/dev/null
    return 0
}
trap cleanup EXIT INT TERM

rm -rf "$S"; mkdir -p "$S"
[ -d /var/lib/irlume/models-thirdparty ] && ln -sfn /var/lib/irlume/models-thirdparty "$S/models-thirdparty"
# Restores the daemon to the state it was ACTUALLY in, not to whether it is
# enabled. A machine where irlumed is enabled but deliberately stopped came back
# running, which is this script changing the system it was only supposed to
# measure.
irlumed_was_active=$(systemctl is-active irlumed 2>/dev/null || true)
systemctl stop irlumed 2>/dev/null; sleep 1
rm -f "$SOCK"
env IRLUME_SOCKET="$SOCK" IRLUME_STATE_DIR="$S" IRLUME_IR_EMITTER_CONF="$S/c.conf" \
    IRLUME_EMITTER_LOCK_DIR="$S/locks" IRLUME_RGB_DEVICE=/dev/video0 IRLUME_IR_DEVICE=/dev/video2 \
    IRLUME_IR_EMITTER=14:6:1,3,2,0,0,0,0,0,0 IRLUME_LOG_EMITTER_WRITES=1 \
    IRLUME_DET_MODEL="$M/face_detection_yunet_2023mar.onnx" IRLUME_MODEL="$M/glintr100.onnx" \
    IRLUME_MESH_MODEL="$M/face_landmark.onnx" IRLUME_BLAZE_MODEL="$M/blaze_face_short_range.onnx" \
    ${ORT:+ORT_DYLIB_PATH="$ORT"} "$B/irlumed" >"$S/d.log" 2>&1 &
for _ in $(seq 1 1800); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon never listened"; tail -3 "$S/d.log"; exit 2; }
# N SEPARATE requests against the one daemon: N sessions, one memo.
# Counted PER REQUEST, not in aggregate. An aggregate "more than one applied
# write" passes when an early request applies twice and a later one runs dark,
# which is the exact defect this script exists to catch.
count_applied() { grep -ac "SET_CUR unit14/sel6: \[01, 03, 02" "$S/d.log" 2>/dev/null || true; }
failed=0
dark=0
for i in $(seq 1 "$N"); do
    before=$(count_applied)
    if ! IRLUME_SOCKET="$SOCK" "$B/irlume" camera-tune --rounds 1 >"$S/tune-$i.out" 2>&1; then
        failed=$((failed + 1))
        echo "  request $i failed:"
        tail -2 "$S/tune-$i.out" | sed 's/^/    /'
        continue
    fi
    after=$(count_applied)
    if [ "$after" -le "$before" ]; then
        dark=$((dark + 1))
        echo "  request $i succeeded but applied NOTHING (still $after)"
    fi
done
pkill -TERM -f "$B/irlumed" 2>/dev/null; sleep 1
applied=$(grep -ac 'SET_CUR unit14/sel6: \[01, 03, 02' "$S/d.log" || true)
restored=$(grep -ac 'SET_CUR unit14/sel6: \[01, 03, 01' "$S/d.log" || true)
[ "$irlumed_was_active" = active ] && systemctl start irlumed 2>/dev/null
echo "requests=$N  applied=$applied  restored=$restored  failed_requests=$failed"

# Asserted, not printed. The first version of this script reported the counts and
# left a person to interpret them, which means it can never fail and would pass
# in CI against the very defect it was written for.
rc=0
fail() {
    echo "  FAILED  $1"
    rc=1
}
# A request that errored produced no stream, so its absence from the counts is
# not evidence about the memo.
[ "$failed" -eq 0 ] || fail "$failed of $N requests failed; the counts below are not comparable"
# The defect: a stream in the process that never applies the override. Asserted
# per request, because "more than one write in total" cannot tell a run where
# every request applied from one where an early request applied twice and a later
# one ran at the camera's default.
if [ "$dark" -eq 0 ]; then
    echo "  ok      every successful request applied the override ($applied writes over $N)"
else
    fail "$dark of $N successful requests applied nothing: those streams ran at the camera's default"
fi
# And every applied mode is still put back, which is the rest of #168.
if [ "$applied" -eq "$restored" ]; then
    echo "  ok      every applied mode was put back ($applied set, $restored restored)"
else
    fail "$applied applied against $restored restored: a stream ended without unsetting"
fi
exit "$rc"
