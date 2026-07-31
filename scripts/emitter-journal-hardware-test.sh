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
# Two things a sandboxed daemon needs that only the packaged unit supplies.
# Without the first it never reaches its socket and sits on a futex, which reads
# as a hung build; without the second, startup stops on a warning about weights
# a sandboxed state directory does not have.
ORT="${ORT_DYLIB_PATH:-$(systemctl cat irlumed 2>/dev/null |
    sed -n 's/^Environment="\?ORT_DYLIB_PATH=\([^"]*\)"\?$/\1/p' | head -1)}"
# The camera's own default for the Microsoft face-authentication control, as both
# validated modules report it via GET_DEF. Section 1 refuses to draw conclusions
# if parking to it changed nothing.
PARK="${PARK_VALUE:-1,3,1,0,0,0,0,0,0}"
# The Microsoft unit and selector are DERIVED from the camera in section 0, not
# assumed. They were hardcoded to one module's unit 4, which meant every
# unit-specific assertion here silently checked nothing on any other camera: the
# ASUS module in the same drawer publishes its Microsoft XU as unit 14.
UNIT=""
SEL=""

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
    if [ "$irlumed_was_active" = active ]; then
        systemctl start irlumed 2>/dev/null
        echo "  (packaged irlumed: $(systemctl is-active irlumed))"
    fi
}
trap cleanup EXIT

rm -rf "$OUT"
mkdir -p "$OUT" "$STATE" "$LOCKS"
if [ -d /var/lib/irlume/models-thirdparty ]; then
    ln -sfn /var/lib/irlume/models-thirdparty "$STATE/models-thirdparty"
fi
# Restores the daemon to the state it was ACTUALLY in, not to whether it is
# enabled. A machine where irlumed is enabled but deliberately stopped came back
# running, which is this script changing the system it was only supposed to
# measure.
irlumed_was_active=$(systemctl is-active irlumed 2>/dev/null || true)
systemctl stop irlumed 2>/dev/null
sleep 1

# $1 = log tag, $2 = value for IRLUME_IR_EMITTER. "off" makes the daemon write
# nothing at startup, which is what leaves a parked control alone.
start_daemon() {
    local tag="$1" override="${2:-off}"
    rm -f "$SOCK"
    # `env`, not bare assignments: `${ORT:+VAR=val}` expands to a WORD, and a
    # word in a prefix-assignment list is taken as the command to run, not as an
    # assignment. Bash duly tried to execute it.
    env IRLUME_SOCKET="$SOCK" \
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
        ${ORT:+ORT_DYLIB_PATH="$ORT"} \
        "$D" >"$OUT/daemon-$tag.log" 2>&1 &
    daemon_pid=$!
    # Four ONNX models load before it listens, which on a laptop takes longer
    # than the camera work that follows.
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

# "unit 14 (Microsoft camera control): advertises [0x06, 0x09]"
UNIT=$(sed -n 's/.*unit \([0-9]*\) (Microsoft camera control).*/\1/p' "$OUT/units-before.txt" | head -1)

# Selector 0x06 SPECIFICALLY, and refuse otherwise.
#
# Taking "the first advertised selector" was wrong: a Microsoft XU can advertise
# 0x09 (metadata) ahead of 0x06 (face authentication), and the park value below
# describes face authentication. Writing it to whatever came first is a payload
# that does not describe the control it reaches, which is the #159 mistake in a
# test harness.
if ! grep -q "unit $UNIT (Microsoft camera control): advertises \[.*0x06" "$OUT/units-before.txt"; then
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
    echo "refusing: no Microsoft camera-control unit on this camera; nothing here applies"
    exit 2
fi
echo "    Microsoft XU: unit $UNIT, first advertised selector $SEL"
if [ -n "$(find "$STORE" -name '*.json' 2>/dev/null)" ]; then
    echo "refusing: $STORE already holds a record; resolve it first"
    find "$STORE" -name '*.json' -exec cat {} \;
    exit 2
fi

echo "=== 1. park the control at the camera's own default ==="
# Parked by applying the default in a capture and then KILLING the daemon before
# the stream ends.
#
# Starting a daemon with the override and stopping it cleanly no longer parks
# anything, and that is #168 working rather than a bug: the daemon does not
# capture at startup, so nothing is written, and if a capture does run the guard
# restores whatever was there before the park, undoing it. No capture-path route
# can leave a control changed any more, which is the whole point of the change.
#
# A kill is the one thing that still can, because the guard never runs. That is
# the same mechanism section 4 uses deliberately, and it leaves the control at
# the default exactly as this section needs.
start_daemon park "$UNIT:$SEL:$PARK" || {
    echo "  daemon would not start"
    exit 2
}
IRLUME_SOCKET="$SOCK" "$B" camera-tune --rounds 1 >"$OUT/park-tune.out" 2>&1 &
tune=$!
for _ in $(seq 1 600); do
    grep -aq "SET_CUR unit$UNIT/sel$SEL: \[01, 03, 01" "$OUT/daemon-park.log" 2>/dev/null && break
    sleep 0.05
done
# Killed the instant the park value is on the camera, so the guard cannot undo it.
pkill -KILL -f "$D" 2>/dev/null
wait "$tune" 2>/dev/null
daemon_pid=""
sleep 1
parked=$(grep -ac "SET_CUR unit$UNIT/sel$SEL: \[01, 03, 01" "$OUT/daemon-park.log" 2>/dev/null)
if [ "${parked:-0}" -ge 1 ]; then
    ok "the control was parked at its default"
else
    # No write does NOT mean the park failed: the override reads the control
    # first and writes nothing when it already holds the value, which is the
    # ordinary state on a camera nothing has driven. What actually matters is
    # whether discovery then had a difference to measure, and section 2 asserts
    # that independently by requiring a SET_CUR of its own.
    skip "the control already held the default, so no parking write was needed"
fi

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
    # The requested 0644 narrowed by the daemon's umask. The packaged unit sets
    # UMask=0027, so the real file is 0640; this harness starts the daemon from a
    # shell and inherits ITS umask, so a bare "644" assertion here would pass
    # while the shipped service produced something else. Compare against what the
    # umask in force actually implies.
    mode=$(stat -c %a "$CONF")
    expected=$(printf "%o" $((0644 & ~$(umask))))
    assert "ir_emitter.conf is $expected, the requested 0644 under umask $(umask)" \
        "got $mode" test "$mode" = "$expected"
    echo "    conf: $(cat "$CONF")"
    assert "it records the camera and coordinates, not a payload" "old-style entry" \
        grep -qE '^[0-9a-f]{4}:[0-9a-f]{4} [0-9]+:[0-9]+$' "$CONF"
else
    skip "no ir_emitter.conf was written, so its shape was not checked"
fi

echo "=== 4. a SIGKILL mid-run leaves the record ==="
start_daemon park2 "$UNIT:$SEL:$PARK" >/dev/null 2>&1 && stop_daemon
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
