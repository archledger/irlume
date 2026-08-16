#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 5 ] || [ "$#" -gt 6 ]; then
    echo "usage: $0 WORKTREE HOST SHA RGB_DEVICE IR_DEVICE|- [rgb-only]" >&2
    exit 2
fi

worktree=$1
host=$2
sha=$3
rgb=$4
ir=$5
mode=${6:-dual}
source_worktree=$(realpath "$worktree")
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
script_root=$(git -C "$script_dir" rev-parse --show-toplevel)
if [ "$(realpath "$script_root")" != "$source_worktree" ]; then
    echo "hardware-run: runner is not from the tested worktree" >&2
    exit 1
fi

verify_tree() {
    local root=$1
    local actual
    actual=$(git -C "$root" rev-parse HEAD)
    if [ "$actual" != "$sha" ]; then
        echo "hardware-run: exact-head mismatch: expected $sha, got $actual" >&2
        return 1
    fi
    if [ -n "$(git -C "$root" status --porcelain --untracked-files=all)" ]; then
        echo "hardware-run: source tree is dirty: $root" >&2
        return 1
    fi
}

verify_physical_uvc_node() {
    local node=$1
    local basename_node
    local device_path
    local driver
    local cursor
    local usb_found=0

    if [ ! -c "$node" ] || [ "$(realpath "$node")" != "$node" ]; then
        echo "hardware-run: not a canonical character device: $node" >&2
        return 1
    fi
    basename_node=${node##*/}
    if [[ ! "$node" =~ ^/dev/video[0-9]+$ ]]; then
        echo "hardware-run: physical evidence requires /dev/videoN: $node" >&2
        return 1
    fi
    device_path=$(readlink -f "/sys/class/video4linux/$basename_node/device")
    case "$device_path" in
        /sys/devices/virtual/* | "")
            echo "hardware-run: virtual or unresolved video node: $node" >&2
            return 1
            ;;
    esac
    driver=$(basename "$(readlink -f "/sys/class/video4linux/$basename_node/device/driver")")
    if [ "$driver" != uvcvideo ]; then
        echo "hardware-run: non-UVC video node: $node driver=$driver" >&2
        return 1
    fi
    cursor=$device_path
    while [ "$cursor" != / ]; do
        if [ -r "$cursor/idVendor" ] && [ -r "$cursor/idProduct" ]; then
            usb_found=1
            break
        fi
        cursor=${cursor%/*}
        [ -n "$cursor" ] || cursor=/
    done
    if [ "$usb_found" -ne 1 ]; then
        echo "hardware-run: video node has no physical USB ancestor: $node" >&2
        return 1
    fi
}

unit_active_state() {
    local unit=$1
    local state
    state=$(systemctl show --property=ActiveState --value "$unit") || {
        echo "hardware-run: could not read $unit ActiveState" >&2
        return 1
    }
    case "$state" in
        active | activating | deactivating | reloading | refreshing | inactive | failed)
            printf '%s\n' "$state"
            ;;
        *)
            echo "hardware-run: unexpected $unit ActiveState=$state" >&2
            return 1
            ;;
    esac
}

snapshot_unit_active() {
    local unit=$1
    local state
    state=$(unit_active_state "$unit") || return 1
    case "$state" in
        active)
            printf '1\n'
            ;;
        inactive | failed)
            printf '0\n'
            ;;
        *)
            echo "hardware-run: refusing transitional $unit ActiveState=$state" >&2
            return 1
            ;;
    esac
}

unit_is_quiescent() {
    local state
    state=$(unit_active_state "$1") || return 1
    case "$state" in
        inactive | failed)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

require_restored_state() {
    local unit=$1
    local expected_active=$2
    local state
    state=$(unit_active_state "$unit") || return 1
    if [ "$expected_active" -eq 1 ] && [ "$state" = active ]; then
        return 0
    fi
    if [ "$expected_active" -eq 0 ]; then
        case "$state" in
            inactive | failed)
                return 0
                ;;
        esac
    fi
    echo "hardware-run: could not restore $unit expected_active=$expected_active state=$state" >&2
    return 1
}

verify_tree "$source_worktree"
umask 077
runtime_dir="/run/user/$(id -u)"
if [ -L "$runtime_dir" ] || [ ! -d "$runtime_dir" ] \
    || [ "$(realpath "$runtime_dir")" != "$runtime_dir" ] \
    || [ "$(stat -c %u "$runtime_dir")" != "$(id -u)" ] \
    || [ "$(stat -c %a "$runtime_dir")" != 700 ]; then
    echo "hardware-run: trusted per-user runtime directory unavailable: $runtime_dir" >&2
    exit 1
fi
lock_dir="$runtime_dir/irlume-slice4-hardware.lock"
if ! mkdir -m 700 "$lock_dir" 2>/dev/null; then
    if [ -L "$lock_dir" ] || [ ! -d "$lock_dir" ] \
        || [ "$(realpath "$lock_dir")" != "$lock_dir" ] \
        || [ "$(stat -c %u "$lock_dir")" != "$(id -u)" ] \
        || [ "$(stat -c %a "$lock_dir")" != 700 ]; then
        echo "hardware-run: unsafe hardware lock directory: $lock_dir" >&2
        exit 1
    fi
fi
if [ "${IRLUME_SLICE4_LOCK_HELD:-}" != 1 ]; then
    exec env IRLUME_SLICE4_LOCK_HELD=1 python3 \
        "$script_dir/slice4-runner-support.py" hold-lock "$lock_dir" "$0" "$@"
fi
unset IRLUME_SLICE4_LOCK_HELD
service_was_active=$(snapshot_unit_active irlumed.service)
socket_was_active=$(snapshot_unit_active irlumed.socket)
users_file=$(mktemp)
fuser_errors=$(mktemp)
snapshot_parent=$(mktemp -d)
snapshot="$snapshot_parent/source"
build_dir=$(mktemp -d)
hardware_pid=""
evidence_tmp=""
evidence=""
evidence_published=0
units_restored=0
log=""

restore_one_unit() {
    local unit=$1
    local expected_active=$2
    local state
    state=$(unit_active_state "$unit") || return 1
    if [ "$expected_active" -eq 1 ] && [ "$state" != active ]; then
        sudo -n systemctl start "$unit" || return 1
    fi
    if [ "$expected_active" -eq 0 ] && ! unit_is_quiescent "$unit"; then
        sudo -n systemctl stop "$unit" || return 1
    fi
    require_restored_state "$unit" "$expected_active" || return 1
}

restore_units() {
    # Restore the service before its socket so an arriving client cannot race
    # socket activation ahead of the service state we observed.
    restore_one_unit irlumed.service "$service_was_active" || return 1
    restore_one_unit irlumed.socket "$socket_was_active" || return 1
    # Starting an originally-active socket may activate an originally-quiescent
    # service. Enforce the service's observed state once more before publication.
    restore_one_unit irlumed.service "$service_was_active" || return 1
    units_restored=1
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [ "$units_restored" -ne 1 ] && ! restore_units; then
        status=1
    fi
    if ! cd "$source_worktree"; then
        status=1
    fi
    if [ -e "$snapshot/.git" ]; then
        if ! git -C "$source_worktree" worktree remove --force "$snapshot"; then
            status=1
        fi
    fi
    if ! rm -f "$users_file" "$fuser_errors"; then
        status=1
    fi
    if [ -n "$evidence_tmp" ] && ! rm -f "$evidence_tmp"; then
        status=1
    fi
    if ! rm -rf "$snapshot_parent" "$build_dir"; then
        status=1
    fi
    if [ "$status" -ne 0 ] && [ "$evidence_published" -eq 1 ]; then
        if rm -f -- "$evidence"; then
            evidence_published=0
        else
            status=1
        fi
    fi
    if [ "$status" -eq 0 ] && [ "$evidence_published" -eq 1 ]; then
        printf 'hardware-run: PASS host=%s sha=%s log=%s evidence=%s\n' \
            "$host" "$sha" "$log" "$evidence"
    fi
    exit "$status"
}

on_signal() {
    local status=$1
    trap - INT TERM
    if [ -n "$hardware_pid" ] && kill -0 "$hardware_pid" 2>/dev/null; then
        kill -TERM "$hardware_pid" 2>/dev/null || true
        wait "$hardware_pid" 2>/dev/null || true
    fi
    exit "$status"
}

trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

git -C "$source_worktree" worktree add --detach "$snapshot" "$sha"
verify_tree "$snapshot"
verify_tree "$source_worktree"
worktree=$snapshot
script_dir="$snapshot/scripts/hardware"
validator="$script_dir/validate-slice4-hardware.py"
export CARGO_TARGET_DIR="$build_dir"
cd "$worktree"
cargo test -p irlume-camera --no-run --locked
verify_tree "$snapshot"
verify_tree "$source_worktree"
verify_physical_uvc_node "$rgb"
if [ "$ir" != "-" ]; then
    verify_physical_uvc_node "$ir"
fi
if ! unit_is_quiescent irlumed.socket; then
    sudo -n systemctl stop irlumed.socket
fi
if ! unit_is_quiescent irlumed.service; then
    sudo -n systemctl stop irlumed.service
fi
if ! unit_is_quiescent irlumed.socket || ! unit_is_quiescent irlumed.service; then
    echo "hardware-run: irlume units did not quiesce" >&2
    exit 1
fi

nodes=("$rgb")
if [ "$ir" != "-" ]; then
    nodes+=("$ir")
fi
set +e
# Redirections intentionally remain unprivileged; only fuser needs complete /proc access.
# shellcheck disable=SC2024
sudo -n fuser "${nodes[@]}" >"$users_file" 2>"$fuser_errors"
fuser_status=$?
set -e
if [ "$fuser_status" -eq 0 ]; then
    echo "hardware-run: camera nodes are still in use" >&2
    while IFS= read -r line; do
        printf '  %s\n' "$line" >&2
    done <"$users_file"
    exit 1
fi
if [ "$fuser_status" -ne 1 ] || [ -s "$fuser_errors" ]; then
    echo "hardware-run: camera ownership probe was inconclusive" >&2
    while IFS= read -r line; do
        printf '  %s\n' "$line" >&2
    done <"$fuser_errors"
    exit 1
fi

env_args=(
    "IRLUME_TEST_DURATION_SECONDS=60"
    "IRLUME_TEST_PHYSICAL_RGB_DEVICE=$rgb"
    "IRLUME_TEST_HOST=$host"
    "IRLUME_TEST_COMMIT=$sha"
)
if [ "$ir" = "-" ]; then
    if [ "$mode" != "rgb-only" ]; then
        echo "hardware-run: missing IR requires explicit rgb-only mode" >&2
        exit 1
    fi
    env_args+=("IRLUME_TEST_EXPECT_RGB_ONLY=1")
else
    env_args+=("IRLUME_TEST_PHYSICAL_IR_DEVICE=$ir")
fi

output_dir="$source_worktree/target"
if [ -L "$output_dir" ]; then
    echo "hardware-run: artifact directory must not be a symlink: $output_dir" >&2
    exit 1
fi
if [ ! -e "$output_dir" ]; then
    mkdir "$output_dir"
fi
output_mode=$(stat -c %a "$output_dir")
if [ ! -d "$output_dir" ] || [ "$(realpath "$output_dir")" != "$output_dir" ] \
    || [ "$(stat -c %u "$output_dir")" != "$(id -u)" ] \
    || (( (8#$output_mode & 0022) != 0 )); then
    echo "hardware-run: unsafe artifact directory: $output_dir" >&2
    exit 1
fi
run_dir=$(mktemp -d "$output_dir/slice4-${host}-${sha}.XXXXXX")
log="$run_dir/run.log"
evidence="$run_dir/evidence.json"
set +e
timeout --signal=TERM --kill-after=10s 240s \
    env -u IRLUME_TEST_ALLOW_VIRTUAL_CAMERA "${env_args[@]}" \
    ./scripts/run-tests-guarded.sh --require physical_timestamp_continuity_stress -- \
    cargo test -p irlume-camera tests::physical_timestamp_continuity_stress --locked -- \
    --ignored --exact --nocapture --test-threads=1 >"$log" 2>&1 &
hardware_pid=$!
wait "$hardware_pid"
status=$?
hardware_pid=""
set -e

verify_tree "$snapshot"
verify_tree "$source_worktree"
if [ "$status" -ne 0 ]; then
    echo "hardware-run: test failed with status $status; log=$log" >&2
    exit "$status"
fi
expected_streams=2
if [ "$mode" = "rgb-only" ]; then
    expected_streams=1
fi
evidence_tmp=$(mktemp "$run_dir/.evidence.XXXXXX")
chmod 600 "$evidence_tmp"
verify_tree "$snapshot"
verify_tree "$source_worktree"
python3 "$validator" "$log" "$host" "$sha" "$expected_streams" >"$evidence_tmp"
verify_tree "$snapshot"
verify_tree "$source_worktree"
mv -f -- "$evidence_tmp" "$evidence"
evidence_tmp=""
evidence_published=1
python3 "$script_dir/slice4-runner-support.py" durable-evidence \
    "$evidence" "$run_dir" "$output_dir" "$source_worktree"
