#!/usr/bin/env bash
# The per-stream leftover record (#188), against a real camera.
#
#   sudo bash scripts/emitter-stream-record-hardware-test.sh <worktree> <ir-node> [rgb-node]
#
# WHAT THIS PROVES
#
#   1. A capture's emitter write is covered: the record is on disk BEFORE the
#      SET_CUR, and resolved once the guard concludes nothing is outstanding.
#      The order is read from IRLUME_LOG_EMITTER_WRITES, where the record's
#      trace lines and the write log share one stderr stream.
#   2. A SIGKILL mid-capture leaves the record on disk, and the NEXT daemon
#      claims it and finishes the restore. Whether the control survives the
#      kill is the module's business: the ASUS 3277:0059 clears its control at
#      a clean STREAMOFF yet was measured still holding it after a SIGKILL, so
#      both branches are handled and the one taken is reported — a cleared
#      control must supersede the stale record, a surviving one must be
#      claimed.
#   3. A value planted from OUTSIDE irlume — the exact bytes irlume itself
#      would apply — is not claimed, not restored, and not recorded: same
#      bytes, no record, not irlume's.
#
# WHAT IT WRITES
#
# Emitter-control writes to this camera's Microsoft extension unit, all values
# the device itself reported: parking is its own GET_DEF via examples/xu_set,
# the capture write is irlume's ordinary derived mode, and the planted value in
# section 3 is read out of irlume's own earlier write, not typed in.
set -uo pipefail

TREE="${1:?usage: $0 <worktree> <ir-node> [rgb-node]}"
IR="${2:?usage: $0 <worktree> <ir-node> [rgb-node]}"
RGB="${3:-/dev/video0}"

B="$TREE/target/release/irlume"
D="$TREE/target/release/irlumed"
XU_SET="$TREE/target/release/examples/xu_set"
OUT=/tmp/emitter-stream-record-hw
SOCK=/run/irlume-srtest.sock
STATE=/var/lib/irlume-srtest
STORE="$STATE/ir-emitter-stream"
LOCKS="$STATE/locks"
MODELS="${IRLUME_MODEL_DIR:-/usr/share/irlume/models}"
ORT="${ORT_DYLIB_PATH:-$(systemctl cat irlumed 2>/dev/null |
    sed -n 's/^Environment="\?ORT_DYLIB_PATH=\([^"]*\)"\?$/\1/p' | head -1)}"

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
skip() {
    skipped=$((skipped + 1))
    echo "  NOT EXERCISED  $1"
}

[ "$(id -u)" -eq 0 ] || {
    echo "refusing: writes camera firmware, needs root"
    exit 2
}
[ -x "$B" ] && [ -x "$D" ] || {
    echo "refusing: no irlume/irlumed in $TREE/target/release"
    exit 2
}
[ -x "$XU_SET" ] || {
    echo "refusing: $XU_SET is missing; build it first:"
    echo "  cargo build --release -p irlume-camera --example xu_set"
    exit 2
}
[ -e "$IR" ] || {
    echo "refusing: $IR does not exist"
    exit 2
}

daemon_pid=""
cleanup() {
    [ -n "$daemon_pid" ] && kill -KILL "$daemon_pid" 2>/dev/null
    rm -f "$SOCK"
    if [ "$irlumed_was_active" = active ]; then
        systemctl start irlumed 2>/dev/null
        echo "  (packaged irlumed: $(systemctl is-active irlumed))"
    fi
}
trap cleanup EXIT

rm -rf "$OUT" "$STATE"
mkdir -p "$OUT" "$STATE" "$LOCKS"
if [ -d /var/lib/irlume/models-thirdparty ]; then
    ln -sfn /var/lib/irlume/models-thirdparty "$STATE/models-thirdparty"
fi
irlumed_was_active=$(systemctl is-active irlumed 2>/dev/null || true)
systemctl stop irlumed 2>/dev/null
sleep 1

# $1 = log tag. The capture path under test is the BUILT-IN table one, so
# IRLUME_IR_EMITTER is left unset: "off" would write nothing and an empty
# value is a refused malformed override, not an absent one.
start_daemon() {
    local tag="$1"
    rm -f "$SOCK"
    env IRLUME_SOCKET="$SOCK" \
        IRLUME_STATE_DIR="$STATE" \
        IRLUME_IR_EMITTER_CONF="$STATE/ir_emitter.conf" \
        IRLUME_EMITTER_LOCK_DIR="$LOCKS" \
        IRLUME_RGB_DEVICE="$RGB" \
        IRLUME_IR_DEVICE="$IR" \
        IRLUME_LOG_EMITTER_WRITES=1 \
        IRLUME_DET_MODEL="$MODELS/face_detection_yunet_2023mar.onnx" \
        IRLUME_MODEL="$MODELS/glintr100.onnx" \
        IRLUME_MESH_MODEL="$MODELS/face_landmark.onnx" \
        IRLUME_BLAZE_MODEL="$MODELS/blaze_face_short_range.onnx" \
        ${ORT:+ORT_DYLIB_PATH="$ORT"} \
        "$D" >"$OUT/daemon-$tag.log" 2>&1 &
    daemon_pid=$!
    for _ in $(seq 1 1800); do
        [ -S "$SOCK" ] && return 0
        kill -0 "$daemon_pid" 2>/dev/null || {
            echo "  the daemon exited during startup:"
            tail -4 "$OUT/daemon-$tag.log" | sed 's/^/    /'
            return 1
        }
        sleep 0.1
    done
    echo "  the daemon never listened; last lines:"
    tail -4 "$OUT/daemon-$tag.log" | sed 's/^/    /'
    return 1
}
stop_daemon() {
    [ -n "$daemon_pid" ] && kill -TERM "$daemon_pid" 2>/dev/null
    wait "$daemon_pid" 2>/dev/null
    daemon_pid=""
}
capture() { IRLUME_SOCKET="$SOCK" "$B" camera-tune --rounds "${1:-1}"; }
records() { find "$STORE" -name '*.json' 2>/dev/null | wc -l; }
control() { "$XU_SET" "$IR" "$UNIT" "$SEL" get 2>/dev/null; }

echo "=== 0. which control does this camera publish ==="
start_daemon probe || {
    echo "refusing: the private daemon would not start"
    exit 2
}
IRLUME_SOCKET="$SOCK" "$B" ir-setup --dry-run >"$OUT/units.txt" 2>&1
stop_daemon
sed 's/^/    /' "$OUT/units.txt"
UNIT=$(sed -n 's/.*unit \([0-9]*\) (Microsoft camera control).*/\1/p' "$OUT/units.txt" | head -1)
SEL=$(sed -n 's/.*unit '"${UNIT:-x}"' (Microsoft camera control): advertises \[\(0x[0-9a-f]*\).*/\1/p' \
    "$OUT/units.txt" | head -1)
if [ -z "$UNIT" ] || [ -z "$SEL" ]; then
    echo "refusing: no Microsoft camera-control unit on this camera"
    exit 2
fi
SEL=$((SEL))
echo "    Microsoft XU: unit $UNIT, selector $SEL"

echo "=== 1. a clean capture: record before the write, resolved after ==="
"$XU_SET" "$IR" "$UNIT" "$SEL" def >"$OUT/park1.out" 2>&1 || {
    sed 's/^/    /' "$OUT/park1.out"
    echo "refusing: could not park the control"
    exit 2
}
PARKED=$(control)
echo "    parked at: $PARKED"
start_daemon clean || exit 2
capture 1 >"$OUT/capture-clean.out" 2>&1
stop_daemon
grep -aE "stream-record|SET_CUR|leaving unit" "$OUT/daemon-clean.log" >"$OUT/clean.seq"
sed 's/^/    /' "$OUT/clean.seq"

first_set=$(grep -an "SET_CUR unit$UNIT/sel$SEL" "$OUT/clean.seq" | head -1 | cut -d: -f1)
saved=$(grep -an "stream-record saved" "$OUT/clean.seq" | head -1 | cut -d: -f1)
resolved=$(grep -an "stream-record resolved" "$OUT/clean.seq" | head -1 | cut -d: -f1)
if [ -z "$first_set" ]; then
    skip "no emitter write happened (no built-in control for this camera?), nothing to cover"
    skip "the resolve was not exercised"
else
    assert "the stream record is saved before the first SET_CUR" \
        "saved=$saved set=$first_set" \
        test -n "$saved" -a -n "$first_set" -a "$saved" -lt "$first_set"
    assert "the record is resolved by the time the daemon stops" \
        "no 'stream-record resolved' in the log" test -n "$resolved"
    assert "no record outlives the clean capture" "$(records) left in $STORE" \
        test "$(records)" -eq 0
    NOW=$(control)
    assert "the control is back at the parked value" "parked $PARKED, now $NOW" \
        test "$NOW" = "$PARKED"
fi
# What irlume applied, from its own log, for section 3's plant.
APPLIED=$(grep -a "SET_CUR unit$UNIT/sel$SEL" "$OUT/clean.seq" | head -1 |
    sed 's/.*\[//;s/\].*//;s/ //g' | tr ',' '\n' | sed 's/^/0x/' | paste -sd,)
echo "    irlume applied: ${APPLIED:-nothing}"

echo "=== 2. a SIGKILL mid-capture leaves the record, the next daemon claims it ==="
if [ -z "${APPLIED:-}" ]; then
    skip "no capture write in section 1, so there is nothing to kill or claim"
else
    "$XU_SET" "$IR" "$UNIT" "$SEL" def >/dev/null 2>&1
    start_daemon killed || exit 2
    capture 3 >"$OUT/capture-killed.out" 2>&1 &
    client=$!
    killed=no
    # The trigger is the record FILE, not the log line. The log stays true
    # forever once round 1 has run, so a grep-based kill can land between
    # rounds, after the guard has already resolved — which is exactly how the
    # first version of this section reported a false failure. The file is
    # momentary state: present exactly while a guard is armed, and a SIGKILL
    # cannot unlink it.
    for _ in $(seq 1 900); do
        if [ "$(records)" -ge 1 ]; then
            kill -KILL "$daemon_pid" 2>/dev/null && killed=yes
            break
        fi
        kill -0 "$client" 2>/dev/null || break
        sleep 0.02
    done
    wait "$client" 2>/dev/null
    daemon_pid=""
    if [ "$killed" != yes ]; then
        skip "the capture ended before a kill could land, so nothing was left behind"
        skip "the claim was not exercised"
    else
        ok "the daemon was SIGKILLed after its stream record hit the disk"
        assert "the record survived the kill" "nothing in $STORE" \
            test "$(records)" -eq 1
        LEFT=$(control)
        echo "    control after the kill: $LEFT (parked $PARKED)"
        if [ "$LEFT" = "$PARKED" ]; then
            # The module undoes its own control at stream close, so the
            # leftover the record describes is already gone. The next run must
            # supersede the record rather than claim it.
            start_daemon after || exit 2
            capture 1 >"$OUT/capture-after.out" 2>&1
            stop_daemon
            assert "the stale record is superseded, not claimed" \
                "a claim appeared in the log" \
                bash -c '! grep -aq "stream-record claimed" "$1"' _ "$OUT/daemon-after.log"
            assert "no record outlives the next clean capture" "$(records) left" \
                test "$(records)" -eq 0
            skip "the claim itself: this module clears its own control at stream \
close, so a leftover cannot survive here (use the NexiGo 3443:c803)"
        else
            start_daemon claim || exit 2
            capture 1 >"$OUT/capture-claim.out" 2>&1
            stop_daemon
            grep -aE "stream-record|SET_CUR|leaving unit" "$OUT/daemon-claim.log" \
                >"$OUT/claim.seq"
            sed 's/^/    /' "$OUT/claim.seq"
            assert "the next daemon claims the leftover" \
                "no 'stream-record claimed' in the log" \
                grep -aq "stream-record claimed.*attempt=1" "$OUT/claim.seq"
            assert "the claim is resolved" "no resolve in the log" \
                grep -aq "stream-record resolved" "$OUT/claim.seq"
            assert "no record is left" "$(records) left" test "$(records)" -eq 0
            NOW=$(control)
            assert "the control is back where the killed stream found it" \
                "parked $PARKED, now $NOW" test "$NOW" = "$PARKED"
        fi
    fi
fi

echo "=== 3. the same bytes planted from outside irlume are not claimed ==="
if [ -z "${APPLIED:-}" ]; then
    skip "no applied value is known, so nothing can be planted"
else
    "$XU_SET" "$IR" "$UNIT" "$SEL" "$APPLIED" >"$OUT/plant.out" 2>&1 || {
        sed 's/^/    /' "$OUT/plant.out"
        skip "the plant write was refused, so the outside-writer case was not staged"
    }
    if grep -aq "after:" "$OUT/plant.out"; then
        start_daemon outside || exit 2
        capture 1 >"$OUT/capture-outside.out" 2>&1
        stop_daemon
        assert "irlume writes nothing over a value it did not set" \
            "a SET_CUR appeared" \
            bash -c '! grep -aq "SET_CUR unit'"$UNIT"'/sel'"$SEL"'" "$1"' _ "$OUT/daemon-outside.log"
        assert "and records nothing" "a stream-record line appeared" \
            bash -c '! grep -aq "stream-record saved" "$1"' _ "$OUT/daemon-outside.log"
        assert "and claims nothing" "a claim appeared" \
            bash -c '! grep -aq "stream-record claimed" "$1"' _ "$OUT/daemon-outside.log"
        assert "the store stays empty" "$(records) records" test "$(records)" -eq 0
    fi
    # Unpark: put the camera's own default back so nothing is left planted.
    "$XU_SET" "$IR" "$UNIT" "$SEL" def >/dev/null 2>&1
fi

echo
echo "$pass passed, $fail failed, $skipped not exercised"
[ "$fail" -eq 0 ]
