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

verify_tree "$source_worktree"
was_active=0
users_file=$(mktemp)
fuser_errors=$(mktemp)
snapshot_parent=$(mktemp -d)
snapshot="$snapshot_parent/source"
build_dir=$(mktemp -d)
hardware_pid=""
evidence_tmp=""

restore_service() {
    if [ "$was_active" -eq 1 ]; then
        if ! systemctl is-active --quiet irlumed.service; then
            sudo -n systemctl start irlumed.service
        fi
        systemctl is-active --quiet irlumed.service || {
            echo "hardware-run: could not restore irlumed" >&2
            return 1
        }
        was_active=0
    fi
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if ! restore_service; then
        status=1
    fi
    cd "$source_worktree" || status=1
    if [ -e "$snapshot/.git" ]; then
        if ! git -C "$source_worktree" worktree remove --force "$snapshot"; then
            status=1
        fi
    fi
    rm -f "$users_file" "$fuser_errors"
    if [ -n "$evidence_tmp" ]; then
        rm -f "$evidence_tmp"
    fi
    rm -rf "$snapshot_parent" "$build_dir"
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
if systemctl is-active --quiet irlumed.service; then
    was_active=1
    sudo -n systemctl stop irlumed.service
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
log="$output_dir/slice4-hardware-${host}-${sha}.log"
mkdir -p "$output_dir"
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
if [ "$was_active" -eq 1 ]; then
    restore_service
    systemctl is-active --quiet irlumed.service || {
        echo "hardware-run: irlumed did not restart" >&2
        exit 1
    }
fi
if [ "$status" -ne 0 ]; then
    echo "hardware-run: test failed with status $status; log=$log" >&2
    exit "$status"
fi
expected_streams=2
if [ "$mode" = "rgb-only" ]; then
    expected_streams=1
fi
evidence="$output_dir/slice4-hardware-${host}-${sha}.json"
evidence_tmp=$(mktemp "$output_dir/.slice4-evidence.XXXXXX")
chmod 600 "$evidence_tmp"
verify_tree "$snapshot"
verify_tree "$source_worktree"
python3 "$validator" "$log" "$host" "$sha" "$expected_streams" >"$evidence_tmp"
verify_tree "$snapshot"
verify_tree "$source_worktree"
mv -f -- "$evidence_tmp" "$evidence"
evidence_tmp=""
printf 'hardware-run: PASS host=%s sha=%s log=%s evidence=%s\n' \
    "$host" "$sha" "$log" "$evidence"
