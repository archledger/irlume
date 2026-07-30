#!/usr/bin/env bash
# Hardware validation for the IR emitter undo record (#181, PR #183).
#
#   sudo bash hw-validate-emitter-journal.sh <worktree> <ir-node> [rgb-node]
#
# WHAT THIS PROVES THAT NOTHING ELSE CAN
#
# Every ordering claim in the record is a sequence of ioctls. The record's whole
# job is to be gone by the end, so nothing is left on disk to inspect, and the
# unit suite reaches these paths only through a stand-in camera. This reads the
# order off one transcript from a real device.
#
# TWO THINGS THE FIRST VERSION OF THIS SCRIPT GOT WRONG, both of which made it
# report failures against correct behaviour:
#
#   * The daemon writes to the emitter AT STARTUP, from the built-in table,
#     before any request arrives. Finding a SET_CUR in the log and concluding
#     discovery had written is how five assertions ran against a run that never
#     wrote at all. Every section now slices the log from the moment its request
#     was made.
#   * `ir-setup` correctly reports "already set to the value setup would apply"
#     and writes nothing when the control is already there, which is precisely
#     the state the daemon's own startup write leaves it in. Discovery then has
#     nothing to explore. The control is parked at the camera's own default
#     first, so there is a real difference to measure.
#
# HOW IT IS ISOLATED
#
# A private irlumed from the worktree, on its own socket, state directory,
# emitter config and lock directory. Nothing here reads or writes the installed
# irlume's files. The packaged irlumed is stopped because it holds the camera,
# and an EXIT trap starts it again on every path out.
#
# WHAT IT WRITES
#
# `ir-setup` writes to the camera's Microsoft extension unit. That is a firmware
# write; it is the operation under test. Section 4 SIGKILLs the daemon mid-run,
# which is the state this change exists to recover from. Every value written is
# one the camera itself reported: the parking value is its own GET_DEF, sent
# through the documented override. The published descriptor is captured before
# and after and compared, because a descriptor that changes is what #159 was.
set -uo pipefail

TREE="${1:?usage: $0 <worktree> <ir-node> [rgb-node]}"
IR="${2:?usage: $0 <worktree> <ir-node> [rgb-node]}"
RGB="${3:-/dev/video0}"

B="$TREE/target/release/irlume"
D="$TREE/target/release/irlumed"
OUT=/tmp/emitter-journal-hw
SOCK=/run/irlume-hwtest.sock
STATE=/var/lib/irlume-hwtest
STORE="$STATE/ir-emitter-journal"
CONF="$STATE/ir_emitter.conf"
LOCKS="$STATE/locks"
MODELS="${IRLUME_MODEL_DIR:-/usr/share/irlume/models}"
# The camera's own default for the Microsoft face-authentication control, as both
# validated modules report it via GET_DEF. Section 1 refuses to draw conclusions
# if parking to it changed nothing.
PARK="${PARK_VALUE:-1,3,1,0,0,0,0,0,0}"

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
[ -e "$IR" ] || {
    echo "refusing: $IR does not exist"
    exit 2
}

# Whether the packaged daemon is ENABLED, not whether it happens to be running.
#
# The first version noted "is-active" at startup and restarted only if it had
# been active. A run that ended without restarting it therefore made the NEXT run
# see it stopped, decide it was meant to be stopped, and leave it that way: two
# runs in, the machine's face authentication was off and nothing said so. What
# the operator wants back is the configured state, so that is what is restored.
daemon_pid=""
cleanup() {
    [ -n "$daemon_pid" ] && kill -KILL "$daemon_pid" 2>/dev/null
    rm -f "$SOCK"
    if systemctl is-enabled --quiet irlumed 2>/dev/null; then
        systemctl start irlumed 2>/dev/null
        echo "  (packaged irlumed: $(systemctl is-active irlumed))"
    fi
}
trap cleanup EXIT

rm -rf "$OUT"
mkdir -p "$OUT" "$STATE" "$LOCKS"
systemctl stop irlumed 2>/dev/null
sleep 1

# $1 = log tag, $2 = value for IRLUME_IR_EMITTER. "off" makes the daemon write
# nothing at startup, which is what leaves a parked control alone.
start_daemon() {
    local tag="$1" override="${2:-off}"
    rm -f "$SOCK"
    IRLUME_SOCKET="$SOCK" \
        IRLUME_STATE_DIR="$STATE" \
        IRLUME_IR_EMITTER_CONF="$CONF" \
        IRLUME_EMITTER_LOCK_DIR="$LOCKS" \
        IRLUME_RGB_DEVICE="$RGB" \
        IRLUME_IR_DEVICE="$IR" \
        IRLUME_IR_EMITTER="$override" \
        IRLUME_LOG_EMITTER_WRITES=1 \
        IRLUME_DET_MODEL="$MODELS/face_detection_yunet_2023mar.onnx" \
        IRLUME_MODEL="$MODELS/glintr100.onnx" \
        IRLUME_MESH_MODEL="$MODELS/face_landmark.onnx" \
        IRLUME_BLAZE_MODEL="$MODELS/blaze_face_short_range.onnx" \
        "$D" >"$OUT/daemon-$tag.log" 2>&1 &
    daemon_pid=$!
    for _ in $(seq 1 300); do
        [ -S "$SOCK" ] && return 0
        kill -0 "$daemon_pid" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}
stop_daemon() {
    [ -n "$daemon_pid" ] && kill -TERM "$daemon_pid" 2>/dev/null
    wait "$daemon_pid" 2>/dev/null
    daemon_pid=""
}
setup() { IRLUME_SOCKET="$SOCK" "$B" ir-setup "$@"; }
mark() { wc -c <"$OUT/daemon-$1.log" 2>/dev/null || echo 0; }
since() { tail -c "+$2" "$OUT/daemon-$1.log" 2>/dev/null; }

echo "=== 0. the camera before anything ==="
start_daemon probe off || {
    echo "refusing: the private daemon would not start"
    tail -20 "$OUT/daemon-probe.log"
    exit 2
}
setup --dry-run >"$OUT/units-before.txt" 2>&1
sed 's/^/    /' "$OUT/units-before.txt"
echo "    devpath: $(udevadm info -q path -n "$IR" 2>/dev/null | sed 's,/video4linux.*,,')"
stop_daemon
if [ -n "$(find "$STORE" -name '*.json' 2>/dev/null)" ]; then
    echo "refusing: $STORE already holds a record; resolve it first"
    find "$STORE" -name '*.json' -exec cat {} \;
    exit 2
fi

echo "=== 1. park the control at the camera's own default ==="
start_daemon park "4:6:$PARK" || {
    echo "  daemon would not start"
    exit 2
}
stop_daemon
parked=$(grep -ac "SET_CUR unit4/sel6: \[01, 03, 01" "$OUT/daemon-park.log" 2>/dev/null)
assert "the control was parked at its default" \
    "no parking write traced; PARK=$PARK may not be this camera's GET_DEF" \
    test "${parked:-0}" -ge 1

echo "=== 2. discovery: record before the write, cleared after a read-back ==="
start_daemon discover off || {
    echo "  daemon would not start"
    exit 2
}
at=$(mark discover)
setup >"$OUT/run-discover.out" 2>&1
sed 's/^/    /' "$OUT/run-discover.out"
stop_daemon
since discover "$at" >"$OUT/discover.seq"
echo "    --- traced sequence for the request only ---"
grep -aE "journal|SET_CUR|GET_" "$OUT/discover.seq" | head -40 | sed 's/^/    /'

grep -aE "journal (saved|cleared|read back)|SET_CUR|GET_LEN|GET_CUR" \
    "$OUT/discover.seq" >"$OUT/discover.filtered"
first_set=$(grep -n "SET_CUR" "$OUT/discover.filtered" | head -1 | cut -d: -f1)
first_save=$(grep -n "journal saved" "$OUT/discover.filtered" | head -1 | cut -d: -f1)
first_len=$(grep -n "GET_LEN" "$OUT/discover.filtered" | head -1 | cut -d: -f1)
first_cur=$(grep -n "GET_CUR" "$OUT/discover.filtered" | head -1 | cut -d: -f1)

if [ -z "$first_set" ]; then
    skip "discovery wrote nothing, so the ordering was not exercised"
    skip "the read-back was not exercised"
    echo "    reason: $(grep -ao 'already set.*' "$OUT/run-discover.out" | head -1)"
else
    assert "the undo record is saved before the first SET_CUR" \
        "save at ${first_save:-none}, first write at $first_set" \
        test -n "$first_save" -a "${first_save:-99999}" -lt "$first_set"
    assert "GET_LEN answers before the control is read" \
        "len at ${first_len:-none}, cur at ${first_cur:-none}" \
        test -n "$first_len" -a -n "$first_cur" -a "${first_len:-99999}" -lt "${first_cur:-0}"
    # NOT a read-back here. A successful discovery deliberately leaves the
    # control at the applied value and resolves its record through `commit`,
    # which runs after `save_conf` and has nothing to read back: nothing was
    # restored. The read-back guards the RESTORE resolution, and section 5 is
    # where that is observed. Asserting it here read a correct success path as a
    # failure on the first hardware run.
    last_set=$(grep -n "SET_CUR" "$OUT/discover.filtered" | tail -1 | cut -d: -f1)
    cleared=$(grep -n "journal cleared" "$OUT/discover.filtered" | tail -1 | cut -d: -f1)
    assert "the record is cleared only after the final write" \
        "last write at ${last_set:-none}, cleared at ${cleared:-none}" \
        test -n "$cleared" -a "${last_set:-99999}" -lt "${cleared:-0}"
fi
assert "no record is left after a completed run" "still present" \
    test -z "$(find "$STORE" -name '*.json' 2>/dev/null)"

echo "=== 3. the emitter config ==="
if [ -f "$CONF" ]; then
    mode=$(stat -c %a "$CONF")
    assert "ir_emitter.conf is 0644" "$mode" test "$mode" = "644"
    echo "    conf: $(cat "$CONF")"
    assert "it records the camera and coordinates, not a payload" "old-style entry" \
        grep -qE '^[0-9a-f]{4}:[0-9a-f]{4} [0-9]+:[0-9]+$' "$CONF"
else
    skip "no ir_emitter.conf was written, so its shape was not checked"
fi

echo "=== 4. a SIGKILL mid-run leaves the record ==="
start_daemon park2 "4:6:$PARK" >/dev/null 2>&1 && stop_daemon
start_daemon killed off || {
    echo "  daemon would not start"
    exit 2
}
at=$(mark killed)
setup >"$OUT/run-killed.out" 2>&1 &
client=$!
killed=no
for _ in $(seq 1 900); do
    if since killed "$at" | grep -aq "journal saved"; then
        kill -KILL "$daemon_pid" 2>/dev/null && killed=yes
        break
    fi
    kill -0 "$client" 2>/dev/null || break
    sleep 0.05
done
wait "$client" 2>/dev/null
daemon_pid=""

if [ "$killed" != yes ]; then
    skip "no exploratory write happened, so the kill had nothing to interrupt"
    skip "the surviving record was not exercised"
    skip "the recovery write was not exercised"
else
    ok "the daemon was SIGKILLed once its undo record was on disk"
    record=$(find "$STORE" -name '*.json' 2>/dev/null | head -1)
    assert "the undo record survived the kill" "nothing in $STORE" test -n "$record"
    if [ -n "$record" ]; then
        echo "    --- the surviving record ---"
        sed 's/^/    /' "$record"
        # The kernel's own DEVPATH, leading slash and all, so it can be
        # compared by eye against `udevadm info -q path`.
        assert "it names the camera's device path as the kernel does" \
            "usb_devpath is absent or not a DEVPATH" \
            grep -q '"usb_devpath":"/devices' "$record"
        # `udevadm` names the INTERFACE directory
        # (.../3-2.1/3-2.1:1.2); the record holds the USB DEVICE directory one
        # level up (.../3-2.1), which is where `descriptors` and `idVendor`
        # live. Strip the last component, not a `:1.N` suffix: the suffix
        # appears inside the component name too, so removing it left a path
        # ending in the device id twice and the comparison failed against a
        # correct record.
        want=$(udevadm info -q path -n "$IR" 2>/dev/null |
            sed 's,/video4linux.*,,' | sed 's,/[^/]*$,,')
        assert "the recorded path is this camera's device directory" \
            "record does not contain $want" \
            grep -qF "\"usb_devpath\":\"$want\"" "$record"
        assert "it holds the original bytes" "no original" \
            grep -q '"original":"[0-9a-f]' "$record"
    fi

    echo "=== 5. the next run puts the control back ==="
    start_daemon recover off || {
        echo "  daemon would not start"
        exit 2
    }
    at=$(mark recover)
    setup >"$OUT/run-recover.out" 2>&1
    sed 's/^/    /' "$OUT/run-recover.out"
    stop_daemon
    since recover "$at" >"$OUT/recover.seq"
    grep -aE "journal|SET_CUR|GET_" "$OUT/recover.seq" | head -30 | sed 's/^/    /'
    assert "the record is resolved and gone" "still present" \
        test -z "$(find "$STORE" -name '*.json' 2>/dev/null)"
    # The sequence the whole change is about, in order, from a real device:
    # the attempt counted and made durable, then the restoring write, then the
    # read-back, and only then the record dropped.
    rec_attempt=$(grep -n "journal saved.*attempts=1" "$OUT/recover.seq" | head -1 | cut -d: -f1)
    rec_write=$(grep -n "SET_CUR" "$OUT/recover.seq" | head -1 | cut -d: -f1)
    rec_read=$(grep -n "GET_CUR" "$OUT/recover.seq" | awk -F: -v w="${rec_write:-0}" '$1 > w {print $1; exit}')
    rec_clear=$(grep -n "journal cleared" "$OUT/recover.seq" | head -1 | cut -d: -f1)
    assert "the attempt is counted before the restoring write" \
        "attempt at ${rec_attempt:-none}, write at ${rec_write:-none}" \
        test -n "$rec_attempt" -a "${rec_attempt:-99999}" -lt "${rec_write:-0}"
    assert "the control is read back after the restore" \
        "write at ${rec_write:-none}, read at ${rec_read:-none}" \
        test -n "$rec_read" -a "${rec_write:-99999}" -lt "${rec_read:-0}"
    assert "the record is dropped only after that read-back" \
        "read at ${rec_read:-none}, cleared at ${rec_clear:-none}" \
        test -n "$rec_clear" -a "${rec_read:-99999}" -lt "${rec_clear:-0}"
fi

echo "=== 6. the camera after everything ==="
start_daemon after off || {
    echo "  daemon would not start"
    exit 2
}
setup --dry-run >"$OUT/units-after.txt" 2>&1
sed 's/^/    /' "$OUT/units-after.txt"
stop_daemon
assert "the camera still publishes the same extension units" \
    "the descriptor changed, which is what #159 looked like" \
    diff -q "$OUT/units-before.txt" "$OUT/units-after.txt"

echo
echo "$pass passed, $fail failed, $skipped not exercised"
echo "transcripts in $OUT"
[ "$fail" -eq 0 ]
