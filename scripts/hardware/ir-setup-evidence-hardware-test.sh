#!/usr/bin/env bash
# Physical acceptance gate for #492.
#
#   sudo bash scripts/hardware/ir-setup-evidence-hardware-test.sh \
#       <worktree> <ir-node> <rgb-node> <transition|device-default|no-xu>
#
# `transition` is restricted to the ASUS 3277:0059 and NexiGo 3443:c803
# modules already validated with a device-derived Face Authentication payload.
# It durably records selector 6's exact GET_CUR, parks the selector at this
# camera's own GET_DEF, then runs setup once with
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
STATE=""
OUT=""
CONF="$STATE/ir_emitter.conf"
LOCKS="$STATE/locks"
STORE="$STATE/ir-emitter-journal"
ORT=${ORT_DYLIB_PATH:-$(systemctl cat irlumed 2>/dev/null |
    sed -n 's/^Environment="\?ORT_DYLIB_PATH=\([^"]*\)"\?$/\1/p' | head -1)}

daemon_pid=""
unit=""
control_needs_restore=no
initial_cur=""
initial_payload=""
initial_identity=""
expected_d1=""
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

read_cur() { # diagnostic tag
    local tag=$1 value
    if ! value=$("$XU_SET" "$IR" "$unit" 6 get 2>"$OUT/get-$tag.err"); then
        echo "GET_CUR failed ($tag)" >&2
        sed 's/^/    /' "$OUT/get-$tag.err" >&2
        return 1
    fi
    if [[ ! "$value" =~ ^([0-9a-fA-F][0-9a-fA-F])+$ ]]; then
        echo "GET_CUR returned malformed bytes ($tag): $value" >&2
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

restore_initial() {
    local restored
    [ "$control_needs_restore" = yes ] || return 0
    stop_private
    if [ -z "$unit" ] || [ -z "$initial_cur" ] || [ -z "$initial_payload" ] \
        || [ -z "$initial_identity" ] || [ ! -e "$IR" ]; then
        echo "cannot restore: initial control identity or camera node is unavailable" >&2
        return 1
    fi
    if ! "$XU_SET" "$IR" "$unit" 6 "$initial_payload" \
        --expect-camera "$initial_identity" >"$OUT/cleanup-restore.out" 2>&1; then
        sed 's/^/    /' "$OUT/cleanup-restore.out" >&2
        return 1
    fi
    if ! restored=$(read_cur cleanup); then
        return 1
    fi
    if [ "$restored" != "$initial_cur" ]; then
        echo "restore verification failed: $restored != $initial_cur" >&2
        return 1
    fi
    control_needs_restore=no
}

cleanup() {
    local original_status=$? cleanup_status=0
    trap - EXIT INT TERM HUP
    stop_private
    if ! restore_initial; then
        cleanup_status=1
        echo "CRITICAL: exact control restoration failed." >&2
        echo "Recovery state is preserved at $STATE; transcripts are at $OUT." >&2
        echo "The packaged daemon will NOT be restarted while the camera may be altered." >&2
    fi
    rm -f "$SOCK"
    if [ "$cleanup_status" -eq 0 ]; then
        case "$STATE" in
            /var/lib/irlume-492.*) rm -rf "$STATE" ;;
            *) echo "refusing to remove unexpected state path $STATE" >&2; cleanup_status=1 ;;
        esac
    fi
    if [ "$cleanup_status" -eq 0 ] && [ "$packaged_was_active" = active ]; then
        if systemctl start irlumed && systemctl is-active --quiet irlumed; then
            echo "  (packaged irlumed: active)"
        else
            echo "FAILED: packaged irlumed did not restart" >&2
            cleanup_status=1
        fi
    fi
    [ "$cleanup_status" -eq 0 ] || exit 1
    exit "$original_status"
}

[ "$(id -u)" -eq 0 ] || { echo "refusing: physical camera gate requires root"; exit 2; }
STATE=$(mktemp -d /var/lib/irlume-492.XXXXXX) || exit 2
OUT=$(mktemp -d /tmp/irlume-492-evidence.XXXXXX) || exit 2
CONF="$STATE/ir_emitter.conf"
LOCKS="$STATE/locks"
STORE="$STATE/ir-emitter-journal"
packaged_was_active=$(systemctl is-active irlumed 2>/dev/null || true)
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
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
if ! systemctl stop irlumed; then
    echo "refusing: failed to stop packaged irlumed"
    exit 2
fi
if systemctl is-active --quiet irlumed; then
    echo "refusing: packaged irlumed is still active"
    exit 2
fi

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
        if [ -S "$SOCK" ] \
            && IRLUME_SOCKET="$SOCK" "$CLI" ir-setup --dry-run >/dev/null 2>&1; then
            return 0
        fi
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
    local tag=$1 no_meta=$2 rc current parked_default
    rm -f "$CONF"
    rm -rf "$STORE"
    control_needs_restore=yes
    "$XU_SET" "$IR" "$unit" 6 def --expect-camera "$initial_identity" \
        >"$OUT/$tag-park.out" 2>&1 || return 2
    if ! parked_default=$(read_cur "$tag-parked"); then return 2; fi
    start_private "$tag" "$no_meta" || return 2
    run_cli >"$OUT/$tag.out" 2>&1
    rc=$?
    stop_private
    if ! current=$(read_cur "$tag-result"); then return 2; fi
    sed 's/^/    /' "$OUT/$tag.out"

    if [ "$rc" -eq 0 ]; then
        grep -q "IR emitter enabled" "$OUT/$tag.out" && ok "$tag reports proven success" ||
            bad "$tag success is explicitly labelled" "unexpected output"
        [ "$(sed -n '1p' "$CONF" 2>/dev/null)" = "$vid:$pid $unit:6" ] \
            && ok "$tag saves the proven control for this camera" ||
            bad "$tag saves the proven control for this camera" "unexpected or absent $CONF"
        [ "$current" = "$expected_d1" ] && ok "$tag leaves exactly the proven D1 value applied" ||
            bad "$tag leaves exactly the proven D1 value applied" "$current != $expected_d1"
    elif [ "$rc" -eq 1 ] && grep -qi "inconclusive" "$OUT/$tag.out"; then
        ok "$tag reports the typed inconclusive outcome"
        [ ! -e "$CONF" ] && ok "$tag saves no inconclusive control" ||
            bad "$tag saves no inconclusive control" "config exists"
        [ "$current" = "$parked_default" ] && ok "$tag exactly restores the parked value" ||
            bad "$tag exactly restores the parked value" "$current != $parked_default"
    else
        bad "$tag returns success or typed inconclusive" "exit $rc"
    fi

    [ -z "$(records)" ] && ok "$tag leaves no undo record" ||
        bad "$tag leaves no undo record" "$(records)"
}

case "$CLASS" in
    transition)
        if ! snapshot=$("$XU_SET" "$IR" "$unit" 6 snapshot 2>"$OUT/get-initial.err"); then
            echo "refusing: could not atomically capture camera identity and GET_CUR"
            sed 's/^/    /' "$OUT/get-initial.err" >&2
            exit 2
        fi
        snapshot_extra=""
        read -r initial_identity snapshot_usb_id snapshot_interface snapshot_unit \
            snapshot_selector initial_cur snapshot_extra <<<"$snapshot"
        if [[ ! "$initial_identity" =~ ^[0-9a-f]{64}$ ]] \
            || [[ ! "$snapshot_usb_id" =~ ^[0-9a-f]{4}:[0-9a-f]{4}$ ]] \
            || [[ ! "$snapshot_interface" =~ ^[0-9]+$ ]] \
            || [[ ! "$snapshot_unit" =~ ^[0-9]+$ ]] \
            || [ "$snapshot_selector" != 6 ] \
            || [[ ! "$initial_cur" =~ ^([0-9a-f][0-9a-f])+$ ]] \
            || [ -n "$snapshot_extra" ]; then
            echo "refusing: malformed camera snapshot: $snapshot"
            exit 2
        fi
        case "$snapshot_usb_id" in
            3277:0059) expected_unit=14 ;;
            3443:c803) expected_unit=4 ;;
            *)
                echo "refusing: transition parking is validated only on ASUS and NexiGo, got $snapshot_usb_id"
                exit 2
                ;;
        esac
        if [ "$snapshot_unit" != "$expected_unit" ]; then
            echo "refusing: $snapshot_usb_id reported unexpected Microsoft unit $snapshot_unit"
            exit 2
        fi
        unit=$snapshot_unit
        vid=${snapshot_usb_id%:*}
        pid=${snapshot_usb_id#*:}
        expected_d1=010302000000000000
        initial_payload=$(hex_to_payload "$initial_cur")
        recovery="$STATE/pretest-control"
        {
            printf 'device=%s\n' "$IR"
            printf 'usb_id=%s\ninterface=%s\n' "$snapshot_usb_id" "$snapshot_interface"
            printf 'unit=%s\nselector=%s\n' "$unit" "$snapshot_selector"
            printf 'initial_cur=%s\n' "$initial_cur"
            printf 'camera_identity=%s\n' "$initial_identity"
            printf 'restore_payload=%s\n' "$initial_payload"
            printf 'transcripts=%s\n' "$OUT"
        } >"$recovery"
        chmod 600 "$recovery"
        if ! sync -f "$recovery" || ! sync -f "$STATE"; then
            echo "refusing: could not durably record the pre-test control"
            exit 2
        fi
        run_transition_case metadata-present 0 || exit 2
        run_transition_case metadata-absent 1 || exit 2
        ;;
    device-default)
        [ -n "$unit" ] || { echo "refusing: no Microsoft XU"; exit 2; }
        if ! before=$(read_cur device-default-before); then exit 2; fi
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
            if ! after=$(read_cur "$mode-after"); then exit 2; fi
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
