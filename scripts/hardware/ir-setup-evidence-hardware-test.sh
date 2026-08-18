#!/usr/bin/env bash
# Physical acceptance gate for #492.
#
#   sudo bash scripts/hardware/ir-setup-evidence-hardware-test.sh \
#       <worktree> <ir-node> <rgb-node> <transition|device-default|no-xu>
#
# `transition` is restricted to the ASUS 3277:0059 and NexiGo 3443:c803
# modules already validated with a device-derived Face Authentication payload.
# It parks selector 6 at this camera's own GET_DEF, then runs setup once with
# UVCM metadata enabled and once with it forcibly disabled. Success and the
# explicit Inconclusive result are both valid functional outcomes; every result
# is checked against its persistence, journal, read-back, and restoration rules.
#
# `device-default` is the read-only Logitech BRIO case: its validated Face
# Authentication D1 value is already GET_CUR == GET_DEF, so setup must report
# that state without a SET_CUR or saved config, with and without metadata.
#
# `no-xu` is the RGB-only negative gate: setup must fail without any extension-
# unit write, config, or journal.
set -uo pipefail

TREE=${1:?usage: $0 <worktree> <ir-node> <rgb-node> <transition|device-default|no-xu>}
IR=${2:?missing IR/camera node}
RGB=${3:?missing RGB node}
CLASS=${4:?missing hardware class}

CLI="$TREE/target/release/irlume"
DAEMON="$TREE/target/release/irlumed"
XU_SET="$TREE/target/release/examples/xu_set"
MODELS=${IRLUME_MODEL_DIR:-/usr/share/irlume/models}
SOCK="/run/irlume-492-$$.sock"
STATE=$(mktemp -d /var/lib/irlume-492.XXXXXX)
OUT=$(mktemp -d /tmp/irlume-492-evidence.XXXXXX)
CONF="$STATE/ir_emitter.conf"
LOCKS="$STATE/locks"
STORE="$STATE/ir-emitter-journal"
ORT=${ORT_DYLIB_PATH:-$(systemctl cat irlumed 2>/dev/null |
    sed -n 's/^Environment="\?ORT_DYLIB_PATH=\([^"]*\)"\?$/\1/p' | head -1)}

daemon_pid=""
unit=""
control_needs_restore=no
pass=0
fail=0

ok() { pass=$((pass + 1)); echo "  ok      $1"; }
bad() { fail=$((fail + 1)); echo "  FAILED  $1"; echo "            $2"; }

stop_private() {
    if [ -n "$daemon_pid" ]; then
        kill -TERM "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
        daemon_pid=""
    fi
    rm -f "$SOCK"
}

restore_default() {
    if [ "$control_needs_restore" = yes ] && [ -n "$unit" ] && [ -e "$IR" ]; then
        stop_private
        if "$XU_SET" "$IR" "$unit" 6 def >"$OUT/cleanup-restore.out" 2>&1; then
            control_needs_restore=no
        else
            echo "  WARNING: cleanup could not restore the device default" >&2
            sed 's/^/    /' "$OUT/cleanup-restore.out" >&2
        fi
    fi
}

packaged_was_active=$(systemctl is-active irlumed 2>/dev/null || true)
cleanup() {
    stop_private
    restore_default
    rm -f "$SOCK"
    case "$STATE" in
        /var/lib/irlume-492.*) rm -rf "$STATE" ;;
        *) echo "refusing to remove unexpected state path $STATE" >&2 ;;
    esac
    if [ "$packaged_was_active" = active ]; then
        systemctl start irlumed 2>/dev/null || true
        echo "  (packaged irlumed: $(systemctl is-active irlumed 2>/dev/null || true))"
    fi
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "refusing: physical camera gate requires root"; exit 2; }
[ -x "$CLI" ] && [ -x "$DAEMON" ] && [ -x "$XU_SET" ] || {
    echo "refusing: release irlume, irlumed, or xu_set is missing under $TREE/target/release"
    exit 2
}
[ -e "$IR" ] && [ -e "$RGB" ] || { echo "refusing: camera node is absent"; exit 2; }
case "$CLASS" in transition|device-default|no-xu) ;; *) echo "unknown class: $CLASS"; exit 2 ;; esac

mkdir -p "$LOCKS"
if [ -d /var/lib/irlume/models-thirdparty ]; then
    ln -s /var/lib/irlume/models-thirdparty "$STATE/models-thirdparty"
fi
systemctl stop irlumed 2>/dev/null || true

start_private() { # tag, metadata-disabled(0|1)
    local tag=$1 no_meta=$2
    local -a extra=()
    stop_private
    [ "$no_meta" = 1 ] && extra+=(IRLUME_NO_ILLUM_META=1)
    env IRLUME_SOCKET="$SOCK" \
        IRLUME_STATE_DIR="$STATE" \
        IRLUME_IR_EMITTER_CONF="$CONF" \
        IRLUME_EMITTER_LOCK_DIR="$LOCKS" \
        IRLUME_RGB_DEVICE="$RGB" \
        IRLUME_IR_DEVICE="$IR" \
        IRLUME_IR_EMITTER=off \
        IRLUME_LOG_EMITTER_WRITES=1 \
        IRLUME_DET_MODEL="$MODELS/face_detection_yunet_2023mar.onnx" \
        IRLUME_MODEL="$MODELS/glintr100.onnx" \
        IRLUME_MESH_MODEL="$MODELS/face_landmark.onnx" \
        IRLUME_BLAZE_MODEL="$MODELS/blaze_face_short_range.onnx" \
        ${ORT:+ORT_DYLIB_PATH="$ORT"} "${extra[@]}" \
        "$DAEMON" >"$OUT/daemon-$tag.log" 2>&1 &
    daemon_pid=$!
    for _ in $(seq 1 1800); do
        [ -S "$SOCK" ] && return 0
        kill -0 "$daemon_pid" 2>/dev/null || {
            tail -20 "$OUT/daemon-$tag.log"
            return 1
        }
        sleep 0.1
    done
    echo "private daemon did not open $SOCK"
    return 1
}

run_cli() { IRLUME_SOCKET="$SOCK" "$CLI" ir-setup "$@"; }
records() { find "$STORE" -name '*.json' -print 2>/dev/null; }

start_private probe 0 || exit 2
run_cli --dry-run >"$OUT/dry-run.out" 2>&1
stop_private
sed 's/^/    /' "$OUT/dry-run.out"
unit=$(sed -n 's/.*unit \([0-9]*\) (Microsoft camera control).*/\1/p' "$OUT/dry-run.out" | head -1)

run_transition_case() { # tag, metadata-disabled
    local tag=$1 no_meta=$2 rc current default
    rm -f "$CONF"
    rm -rf "$STORE"
    "$XU_SET" "$IR" "$unit" 6 def >"$OUT/$tag-park.out" 2>&1 || return 2
    control_needs_restore=yes
    default=$("$XU_SET" "$IR" "$unit" 6 get)
    start_private "$tag" "$no_meta" || return 2
    run_cli >"$OUT/$tag.out" 2>&1
    rc=$?
    stop_private
    current=$("$XU_SET" "$IR" "$unit" 6 get)
    sed 's/^/    /' "$OUT/$tag.out"

    if [ "$rc" -eq 0 ]; then
        grep -q "IR emitter enabled" "$OUT/$tag.out" && ok "$tag reports proven success" ||
            bad "$tag success is explicitly labelled" "unexpected output"
        [ -f "$CONF" ] && ok "$tag saves the proven control" ||
            bad "$tag saves the proven control" "no $CONF"
    elif [ "$rc" -eq 1 ] && grep -qi "inconclusive" "$OUT/$tag.out"; then
        ok "$tag reports the typed inconclusive outcome"
        [ ! -e "$CONF" ] && ok "$tag saves no inconclusive control" ||
            bad "$tag saves no inconclusive control" "config exists"
        [ "$current" = "$default" ] && ok "$tag exactly restores the original" ||
            bad "$tag exactly restores the original" "$current != $default"
    else
        bad "$tag returns success or typed inconclusive" "exit $rc"
    fi

    [ -z "$(records)" ] && ok "$tag leaves no undo record" ||
        bad "$tag leaves no undo record" "$(records)"
    "$XU_SET" "$IR" "$unit" 6 def >"$OUT/$tag-final-restore.out" 2>&1 || return 2
    control_needs_restore=no
    current=$("$XU_SET" "$IR" "$unit" 6 get)
    [ "$current" = "$default" ] && ok "$tag finishes at the device default" ||
        bad "$tag finishes at the device default" "$current != $default"
}

case "$CLASS" in
    transition)
        grep -q "unit $unit (Microsoft camera control): advertises \[.*0x06" "$OUT/dry-run.out" || {
            echo "refusing: target does not advertise Face Authentication selector 6"
            exit 2
        }
        devpath=$(udevadm info -q path -n "$IR" 2>/dev/null | sed 's,/video4linux.*,,' | sed 's,/[^/]*$,,')
        vid=$(cat "/sys$devpath/idVendor" 2>/dev/null || true)
        pid=$(cat "/sys$devpath/idProduct" 2>/dev/null || true)
        case "$vid:$pid" in 3277:0059|3443:c803) ;; *)
            echo "refusing: transition parking is validated only on ASUS and NexiGo, got $vid:$pid"
            exit 2
        esac
        run_transition_case metadata-present 0 || exit 2
        run_transition_case metadata-absent 1 || exit 2
        ;;
    device-default)
        [ -n "$unit" ] || { echo "refusing: no Microsoft XU"; exit 2; }
        before=$("$XU_SET" "$IR" "$unit" 6 get)
        for mode in metadata-present metadata-absent; do
            disabled=0; [ "$mode" = metadata-absent ] && disabled=1
            rm -f "$CONF"; rm -rf "$STORE"
            start_private "$mode" "$disabled" || exit 2
            run_cli >"$OUT/$mode.out" 2>&1; rc=$?
            stop_private
            sed 's/^/    /' "$OUT/$mode.out"
            [ "$rc" -eq 0 ] && grep -q "active by device default" "$OUT/$mode.out" &&
                ok "$mode recognizes device-default D1 without a write" ||
                bad "$mode recognizes device-default D1 without a write" "exit $rc"
            ! grep -q "SET_CUR unit$unit/sel6" "$OUT/daemon-$mode.log" &&
                ok "$mode sends no Face Authentication write" ||
                bad "$mode sends no Face Authentication write" "SET_CUR found"
            [ ! -e "$CONF" ] && [ -z "$(records)" ] && ok "$mode persists nothing" ||
                bad "$mode persists nothing" "config or journal exists"
            after=$("$XU_SET" "$IR" "$unit" 6 get)
            [ "$after" = "$before" ] && ok "$mode leaves the exact control unchanged" ||
                bad "$mode leaves the exact control unchanged" "$after != $before"
        done
        ;;
    no-xu)
        rm -f "$CONF"; rm -rf "$STORE"
        start_private no-xu 0 || exit 2
        run_cli >"$OUT/no-xu.out" 2>&1; rc=$?
        stop_private
        sed 's/^/    /' "$OUT/no-xu.out"
        [ "$rc" -ne 0 ] && ok "RGB-only hardware is not reported ready" ||
            bad "RGB-only hardware is not reported ready" "exit 0"
        ! grep -q "SET_CUR" "$OUT/daemon-no-xu.log" && ok "RGB-only hardware receives no XU write" ||
            bad "RGB-only hardware receives no XU write" "SET_CUR found"
        [ ! -e "$CONF" ] && [ -z "$(records)" ] && ok "RGB-only hardware persists nothing" ||
            bad "RGB-only hardware persists nothing" "config or journal exists"
        ;;
esac

echo
echo "$pass passed, $fail failed"
echo "transcripts: $OUT"
[ "$fail" -eq 0 ]
