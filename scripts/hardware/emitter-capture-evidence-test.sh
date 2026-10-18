#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Hardware evidence for a built-in emitter table entry (#887).
#
#   sudo bash scripts/hardware/emitter-capture-evidence-test.sh <worktree> <ir-node>
#
# ADR-0031 §4 adds a camera to the built-in table (`known_control`) only once
# four things are recorded on the hardware: the capture path's write of the
# Face Authentication D1 value, the camera reading that value back, the
# optical result of the bursts captured with it, and the restore of the value
# the write displaced. One face authentication records all four.
#
# This script never writes to the camera. It reads selector 6 with
# `xu_set get` before and after the run; the packaged irlumed makes the write
# and the restore under its own stream guard, during one face authentication
# you start from another terminal. For that run irlumed gets a runtime drop-in
# under /run with the documented override and three traces:
#
#   IRLUME_IR_EMITTER          the camera's D1 value, as the table entry would write it
#   IRLUME_LOG_EMITTER_WRITES  every extension-unit write, and every read with its bytes
#   IRLUME_DEBUG_IR_FRAMES     each burst's frame means and its D1 proof numbers
#   IRLUME_LOG=debug           each burst's clipping-ceiling judgment
#
# On exit the drop-in is removed and irlumed restarted without it.
#
# The irlumed that runs must be built from a tree that prints the read-back
# bytes and the D1 numbers; `xu_set` comes from <worktree>:
#
#   cargo build --release -p irlume-camera --example xu_set
#
# Only the cameras listed in `model_for` are accepted: today the ThinkPad
# T480's IR camera, 5986:1141. Its unit 8 also advertises selector 2, which
# this script never names.
set -uo pipefail

TREE=${1:?usage: $0 <worktree> <ir-node>}
IR=${2:?missing IR camera node}

XU_SET="$TREE/target/release/examples/xu_set"
SERVICE=irlumed.service
DROPIN_DIR=/run/systemd/system/$SERVICE.d
DROPIN=$DROPIN_DIR/zz-irlume-capture-evidence.conf
AUTH_WAIT=${IRLUME_EVIDENCE_AUTH_WAIT:-300}
RESTORE_WAIT=${IRLUME_EVIDENCE_RESTORE_WAIT:-60}

OUT=""
dropin_written=no
pid=""
pass=0
fail=0

ok() { pass=$((pass + 1)); echo "  ok      $1"; }
bad() { fail=$((fail + 1)); echo "  FAILED  $1"; echo "            $2"; }

# One camera per line: USB id, Microsoft unit, the Face Authentication value
# the camera reports by default (D0), the D1 value discovery derives from its
# GET_DEF and GET_MAX, and the trace lines the run must produce, exactly as
# irlumed prints them. A unit test pins these lines to the code that prints
# them, so a reworded trace fails the build rather than this script.
model_for() { # usb-id
    case "$1" in
        5986:1141)
            model_name="ThinkPad T480 IR camera"
            model_unit=8
            model_d0=010101000000000000
            model_d1=010102000000000000
            model_override=8:6:1,1,2,0,0,0,0,0,0
            expected_write="irlume: SET_CUR unit8/sel6: [01, 01, 02, 00, 00, 00, 00, 00, 00]"
            expected_readback="irlume: GET_CUR unit8/sel6 size=9: [01, 01, 02, 00, 00, 00, 00, 00, 00]"
            expected_restore="irlume: SET_CUR unit8/sel6: [01, 01, 01, 00, 00, 00, 00, 00, 00]"
            ;;
        *) return 1 ;;
    esac
}

remove_dropin() {
    [ "$dropin_written" = yes ] || return 0
    rm -f "$DROPIN"
    rmdir "$DROPIN_DIR" 2>/dev/null || true
    systemctl daemon-reload || return 1
    dropin_written=no
    systemctl restart "$SERVICE" || return 1
    systemctl is-active --quiet "$SERVICE"
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM HUP
    if [ "$dropin_written" = yes ]; then
        if remove_dropin; then
            echo "  (irlumed restarted without the evidence drop-in)"
        else
            echo "FAILED: could not remove $DROPIN or restart irlumed; remove it by hand," >&2
            echo "        then run: systemctl daemon-reload && systemctl restart irlumed" >&2
            status=1
        fi
    fi
    [ -n "$OUT" ] && echo "transcripts: $OUT"
    exit "$status"
}

read_cur() { # tag
    local value
    if ! value=$("$XU_SET" "$IR" "$model_unit" 6 get 2>"$OUT/get-$1.err"); then
        echo "GET_CUR failed ($1):" >&2
        sed 's/^/    /' "$OUT/get-$1.err" >&2
        return 1
    fi
    if [[ ! "$value" =~ ^([0-9a-fA-F][0-9a-fA-F])+$ ]]; then
        echo "GET_CUR returned malformed bytes ($1): $value" >&2
        return 1
    fi
    printf '%s\n' "${value,,}"
}

hex_to_payload() {
    local value=$1 result="" byte
    while [ -n "$value" ]; do
        byte=${value:0:2}
        value=${value:2}
        result="${result:+$result,}0x$byte"
    done
    printf '%s\n' "$result"
}

# The first line at or after line $2 of the run's journal that equals $1, as a
# line number, or nothing.
first_exact_after() { # line, from
    awk -v want="$1" -v from="$2" 'NR >= from && $0 == want { print NR; exit }' "$OUT/irlumed.log"
}

journal() { journalctl -q -b -o cat _PID="$pid" >"$OUT/irlumed.log" 2>/dev/null; }

[ "$(id -u)" -eq 0 ] || { echo "refusing: reading the camera and restarting irlumed require root"; exit 2; }
[ -x "$XU_SET" ] || {
    echo "refusing: $XU_SET is missing; build it with"
    echo "  cargo build --release -p irlume-camera --example xu_set"
    exit 2
}
[ -e "$IR" ] || { echo "refusing: $IR is absent"; exit 2; }
systemctl is-active --quiet "$SERVICE" || {
    echo "refusing: the packaged irlumed is not running; this run needs it, with your"
    echo "enrolled profile and the camera pairing it authenticates with"
    exit 2
}
[ ! -e "$DROPIN" ] || {
    echo "refusing: $DROPIN already exists, perhaps from an interrupted run; remove it,"
    echo "then run: systemctl daemon-reload && systemctl restart irlumed"
    exit 2
}
OUT=$(mktemp -d /tmp/irlume-capture-evidence.XXXXXX) || exit 2
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

# The USB id first, from udev, so no extension unit is named on a camera this
# script does not list.
props=$(udevadm info -q property -n "$IR" 2>/dev/null) || { echo "refusing: udev does not know $IR"; exit 2; }
vendor=$(sed -n 's/^ID_VENDOR_ID=//p' <<<"$props")
product=$(sed -n 's/^ID_MODEL_ID=//p' <<<"$props")
if ! model_for "$vendor:$product"; then
    echo "refusing: this evidence run lists only the ThinkPad T480 IR camera (5986:1141), got $vendor:$product"
    exit 2
fi

# Identity and the control's current bytes, from one open descriptor, which
# must agree with udev and publish the listed unit.
if ! snapshot=$("$XU_SET" "$IR" "$model_unit" 6 snapshot 2>"$OUT/snapshot.err"); then
    echo "refusing: could not read the camera's identity and selector 6 from $IR"
    sed 's/^/    /' "$OUT/snapshot.err"
    exit 2
fi
snapshot_extra=""
read -r identity usb_id interface snapshot_unit snapshot_selector initial snapshot_extra <<<"$snapshot"
if [[ ! "$identity" =~ ^[0-9a-f]{64}$ ]] \
    || [[ ! "$usb_id" =~ ^[0-9a-f]{4}:[0-9a-f]{4}$ ]] \
    || [[ ! "$interface" =~ ^[0-9]+$ ]] \
    || [[ ! "$snapshot_unit" =~ ^[0-9]+$ ]] \
    || [ "$snapshot_selector" != 6 ] \
    || [[ ! "$initial" =~ ^([0-9a-f][0-9a-f])+$ ]] \
    || [ -n "$snapshot_extra" ]; then
    echo "refusing: malformed camera snapshot: $snapshot"
    exit 2
fi
if [ "$usb_id" != "$vendor:$product" ]; then
    echo "refusing: the open camera reports $usb_id, udev $vendor:$product"
    exit 2
fi
if [ "$snapshot_unit" != "$model_unit" ]; then
    echo "refusing: $usb_id reported Microsoft unit $snapshot_unit, expected $model_unit"
    exit 2
fi
if [ "$initial" != "$model_d0" ]; then
    echo "refusing: selector 6 holds $initial, not this camera's default $model_d0;"
    echo "the run must start from the default so the write and the restore are both seen."
    echo "'sudo irlume doctor' reports an emitter change irlume left outstanding."
    exit 2
fi
echo "$model_name $usb_id on $IR: unit $model_unit selector 6 holds $initial (D0)"

mkdir -p "$DROPIN_DIR" || exit 2
dropin_written=yes
cat >"$DROPIN" <<EOF || exit 2
# Written by scripts/hardware/emitter-capture-evidence-test.sh for one run;
# removed when it exits.
[Service]
Environment="IRLUME_IR_EMITTER=$model_override"
Environment="IRLUME_LOG=debug"
Environment="IRLUME_LOG_EMITTER_WRITES=1"
Environment="IRLUME_DEBUG_IR_FRAMES=1"
EOF
systemctl daemon-reload || exit 2
systemctl restart "$SERVICE" || exit 2
systemctl is-active --quiet "$SERVICE" || { echo "irlumed did not start with the drop-in"; exit 2; }
pid=$(systemctl show -p MainPID --value "$SERVICE")
[[ "$pid" =~ ^[1-9][0-9]*$ ]] || { echo "irlumed has no main process"; exit 2; }
# The daemon's own environment, not the unit's text, so a later drop-in that
# overrides one of these is caught before the run rather than after it.
for wanted in "IRLUME_IR_EMITTER=$model_override" IRLUME_LOG=debug \
    IRLUME_LOG_EMITTER_WRITES=1 IRLUME_DEBUG_IR_FRAMES=1; do
    if ! tr '\0' '\n' <"/proc/$pid/environ" | grep -Fxq -- "$wanted"; then
        echo "refusing: irlumed (pid $pid) is not running with $wanted; another drop-in may override it"
        exit 2
    fi
done

echo
echo "irlumed is running with the evidence drop-in (pid $pid)."
echo "Now, in another terminal, with your face in view, run:"
echo
echo "    sudo -k; sudo true"
echo
echo "Waiting up to ${AUTH_WAIT}s for that face authentication..."
decided=""
for _ in $(seq 1 "$AUTH_WAIT"); do
    journal
    if grep -q "^irlumed: face auth '" "$OUT/irlumed.log"; then
        decided=yes
        break
    fi
    kill -0 "$pid" 2>/dev/null || { echo "irlumed exited during the run"; exit 2; }
    sleep 1
done
[ -n "$decided" ] || { echo "no face authentication reached irlumed within ${AUTH_WAIT}s"; exit 2; }
grep "^irlumed: face auth '" "$OUT/irlumed.log" | head -1 | sed 's/^/    /'

# The restore is the stream's end, which can come after the decision.
write_at=$(first_exact_after "$expected_write" 1)
restored_at=""
for _ in $(seq 1 "$RESTORE_WAIT"); do
    journal
    write_at=$(first_exact_after "$expected_write" 1)
    if [ -n "$write_at" ]; then
        restored_at=$(first_exact_after "$expected_restore" "$((write_at + 1))")
        [ -n "$restored_at" ] && break
        grep -q "^irlume: leaving unit$model_unit/sel6 " "$OUT/irlumed.log" && break
    fi
    sleep 1
done

# `xu_set` takes the camera-operation lease, which irlumed holds while it
# still has the camera open.
final=""
for attempt in 1 2 3 4 5; do
    final=$(read_cur "after-$attempt") && break
    final=""
    sleep 1
done
[ -n "$final" ] || exit 2

echo
completed_at=""
[ -n "$write_at" ] && completed_at=$(awk -v from="$write_at" \
    'NR > from && $0 == "irlume: capture emitter write completed" { print NR; exit }' \
    "$OUT/irlumed.log")
if [ -n "$write_at" ] && [ -n "$completed_at" ]; then
    ok "the capture path wrote D1 ($model_d1) to unit $model_unit selector 6"
else
    bad "the capture path wrote D1 ($model_d1) to unit $model_unit selector 6" \
        "no '$expected_write' followed by 'irlume: capture emitter write completed'"
fi

readback_at=""
[ -n "$write_at" ] && readback_at=$(first_exact_after "$expected_readback" "$((write_at + 1))")
if [ -n "$readback_at" ]; then
    ok "the camera read D1 back after the write"
else
    hint="no '$expected_readback' after the write"
    grep -Eq "^irlume: GET_CUR unit$model_unit/sel6 size=[0-9]+$" "$OUT/irlumed.log" &&
        hint="$hint; irlumed prints reads without their bytes, so it predates this harness"
    bad "the camera read D1 back after the write" "$hint"
fi

proven=0
bursts=0
ceilings=0
if [ -n "$write_at" ]; then
    bursts=$(awk -v from="$write_at" 'NR > from && /^\[ir_d1\] / { n++ } END { print n + 0 }' \
        "$OUT/irlumed.log")
    proven=$(awk -v from="$write_at" 'NR > from && /^\[ir_d1\] .*: D1 proven$/ { n++ } END { print n + 0 }' \
        "$OUT/irlumed.log")
    ceilings=$(awk -v from="$write_at" \
        'NR > from && index($0, "YUYV clipping ceiling 235 for this burst") { n++ } END { print n + 0 }' \
        "$OUT/irlumed.log")
fi
if [ "$proven" -gt 0 ] && [ "$ceilings" -gt 0 ]; then
    ok "$proven of $bursts bursts captured with D1 selected proved the alternation; $ceilings qualified for the YUYV ceiling"
elif [ "$bursts" -eq 0 ]; then
    bad "bursts captured with D1 selected prove the alternation" \
        "no [ir_d1] line after the write; irlumed predates this harness or captured no IR burst"
else
    bad "bursts captured with D1 selected prove the alternation" \
        "$proven of $bursts bursts proved D1 and $ceilings qualified for the ceiling; see $OUT/irlumed.log"
fi

if [ -n "$restored_at" ] && { [ -z "$readback_at" ] || [ "$restored_at" -gt "$readback_at" ]; }; then
    ok "the stream's end restored the displaced D0 value"
else
    bad "the stream's end restored the displaced D0 value" \
        "no '$expected_restore' after the write within ${RESTORE_WAIT}s"
fi

if [ "$final" = "$initial" ]; then
    ok "selector 6 reads $final again after the run"
else
    bad "selector 6 reads $initial again after the run" "it reads $final"
    echo "            To put it back: sudo systemctl stop irlumed, then"
    echo "            sudo $XU_SET $IR $model_unit 6 $(hex_to_payload "$initial") --expect-camera $identity"
fi

others=$(grep -E "^irlume: SET_CUR " "$OUT/irlumed.log" | grep -Fv "SET_CUR unit$model_unit/sel6: " || true)
if [ -z "$others" ]; then
    ok "irlumed wrote to no other control"
else
    bad "irlumed wrote to no other control" "$others"
fi

{
    echo "irlume capture-path emitter evidence (#887)"
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "camera: $model_name, USB $usb_id, unit $model_unit, selector 6"
    echo "kernel: $(uname -r)"
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
    echo "irlumed: ${exe:-unknown} sha256 $(sha256sum "${exe:-/dev/null}" 2>/dev/null | cut -d' ' -f1)"
    echo "tree: $(git -C "$TREE" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "GET_CUR before: $initial"
    echo "GET_CUR after:  $final"
    echo "result: $pass passed, $fail failed"
    echo
    grep -E "^irlume: (SET_CUR|GET_CUR) unit$model_unit/sel6|^irlume: stream-record |^irlume: capture emitter |^irlume: leaving unit|^\[ir_d1\] |YUYV clipping ceiling|^irlumed: face auth '" \
        "$OUT/irlumed.log"
} >"$OUT/evidence.txt"

echo
echo "$pass passed, $fail failed"
echo "evidence for #887: $OUT/evidence.txt"
[ "$fail" -eq 0 ]
