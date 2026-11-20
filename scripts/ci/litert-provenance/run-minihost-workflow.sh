#!/usr/bin/env bash
# Bridge to the already-qualified private minihost build environment.
set -euo pipefail
umask 077
ulimit -c 0
export PATH=/usr/bin:/bin LC_ALL=C
t=/home/test/.local-tasks/irlume-litert-minihost-replay-20261119
tools=$(cd -- "$(dirname "$0")" && pwd)
staged=$t/staged-bounded-v2
capsule=$staged/bundle/litert-jammy-toolchain-replay.tar.gz
capsule_sha=5d08cd2d276a5800c635ddd8ede549fc8aee35f17f42c9e5e5fcaeac49604f15
base=docker.io/library/ubuntu@sha256:45e9ddc6895604674618a409ca9f73d301da8fdb75fe330e8e9a27b3b219e4ad
base_config=3b0904ac063a56dbfe1cd5496f5bc417ad9897e1e2e12768fa67be06fecf758a

fail() { printf 'Minihost workflow refused: %s\n' "$*" >&2; exit 78; }
host_guard() {
    [[ $(uname -n) == minihost && $(id -un) == test && $EUID != 0 ]] \
        || fail "only the minihost test account is permitted"
    [[ -d $t && ! -L $t && -O $t && $(stat -c %a "$t") == 700 ]] \
        || fail "private task directory is not provisioned"
}
platform_guard() {
    local runtime_link=$t/prefix/usr/lib/libcrun.so.1
    [[ -x $t/prefix/usr/bin/podman && $(readlink "$runtime_link") == libcrun.so.1.0.0 ]] \
        || fail "the qualified private OCI tools are missing"
    (cd "$t" && sha256sum --check --strict --quiet "$tools/minihost-platform.sha256")
    [[ $(realpath -e -- "$staged/storage.conf") == "$t/staged/storage.conf" &&
       $(realpath -e -- "$staged/packages") == "$t/staged/packages" ]] \
        || fail "storage or package staging no longer matches"
    printf '%s  %s\n' "$capsule_sha" "$capsule" | sha256sum --check --strict --quiet
    cmp "$t/bounded-recipes/run-owned-container.sh" <(tar -xOzf "$capsule" ./run-owned-container.sh)
    cmp -s "$t/home/.config/containers/auth.json" <(printf '{"auths":{}}\n') \
        || fail "the private registry auth file must be empty"
}
invocation_guard() {
    [[ $1 =~ ^[0-9a-f]{40}$ && $1 != 0000000000000000000000000000000000000000 &&
       $2 =~ ^[1-9][0-9]{0,19}$ && $3 =~ ^[1-9][0-9]{0,5}$ ]] \
        || fail "invalid workflow commit, run or attempt"
}
require_empty_inventory() {
    local inventory
    inventory=$("$@") || fail "inventory command failed"
    [[ -z $inventory ]] || fail "unexpected build resources are still present"
}
wait_for_scope_collection() {
    local inventory deadline=$((SECONDS + 5))
    while :; do
        inventory=$(timeout 2s "$@") || fail "scope inventory command failed"
        [[ -z $inventory ]] && return
        (( SECONDS < deadline )) || fail "owned build scope has not been collected"
        sleep 0.1
    done
}

host_guard
if [[ ${1:-} == --inside ]]; then
    shift
    [[ $# == 3 ]] || fail "expected scoped workflow invocation"
    invocation_guard "$@"
    root=$t/github-replay-$2-$3
    read -r scope < /proc/self/cgroup
    [[ $scope =~ ^0::(/user.slice/[^[:space:]]*/irlume-litert-unsigned-bounded-build-[0-9]+\.scope)$ ]] \
        || fail "controlled build scope missing"
    controls=/sys/fs/cgroup${BASH_REMATCH[1]}
    read -r quota period < "$controls/cpu.max"
    [[ $quota =~ ^[0-9]+$ && $period =~ ^[1-9][0-9]*$ ]]
    (( quota == 2 * period ))
    [[ $(<"$controls/memory.high") == 2936012800 && $(<"$controls/memory.max") == 3670016000 ]]
    for knob in memory.swap.max memory.zswap.max; do [[ $(<"$controls/$knob") == 0 ]]; done
    [[ -d $root && ! -L $root && -O $root ]]
    platform_guard
    # run-unsigned resolves Podman in the private prefix, not the runner PATH.
    export PATH="$t/prefix/usr/bin:/usr/bin:/bin"
    pod=("$t/prefix/usr/bin/podman" --events-backend=none)
    [[ $("${pod[@]}" --version) == "podman version 6.2.0" ]]
    [[ $("${pod[@]}" info --format '{{.Host.Security.Rootless}} {{.Store.GraphRoot}} {{.Store.RunRoot}} {{.Store.ImageStore.Number}}') == \
        "true $t/state/store $t/runtime/storage 1" ]]
    [[ $("${pod[@]}" image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}}' "$base") == "$base_config linux/amd64" ]]
    require_empty_inventory "${pod[@]}" ps -a --format '{{.ID}}'
    bash "$tools/run-unsigned.sh" "$staged" "$root/replay"
    require_empty_inventory "${pod[@]}" ps -a --format '{{.ID}}'
    python3 -E -B "$tools/provenance.py" stage "$root/replay" "$root/handoff" "$@"
    exit 0
fi

[[ $# == 3 ]] || fail "expected commit, run, and attempt"
invocation_guard "$@"
platform_guard
[[ $(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo) -ge 4000 ]] || fail "host memory floor not met"
[[ $(df -Pm "$t" | awk 'NR==2 {print $4}') -ge 20480 ]] || fail "host disk floor not met"
user_runtime=/run/user/$EUID
[[ -S $user_runtime/bus && -O $user_runtime ]] || fail "systemd user bus is unavailable"
user_bus=(env "XDG_RUNTIME_DIR=$user_runtime" "DBUS_SESSION_BUS_ADDRESS=unix:path=$user_runtime/bus")
lock=$t/unsigned-workflow.lock
[[ ! -L $lock ]] || fail "invalid private lock path"
exec 9>>"$lock"
flock -n 9 || fail "a workflow replay already holds the private lock"
require_empty_inventory "${user_bus[@]}" systemctl --user list-units --all --no-legend 'irlume-litert-unsigned-*.scope'
root=$t/github-replay-$2-$3
mkdir -m 0700 -- "$root"
unit=irlume-litert-unsigned-bounded-build-$BASHPID.scope
# The pinned recipe emits toolchain and build diagnostics. Keep them off the
# public Actions log, including on failure.
if "${user_bus[@]}" systemd-run --user --scope --collect --quiet --unit="$unit" \
    -p CPUQuota=200% -p MemoryAccounting=yes -p MemoryHigh=2800M -p MemoryMax=3500M \
    -p MemorySwapMax=0 -p MemoryZSwapMax=0 -p RuntimeMaxSec=3900s \
    -p TimeoutStopSec=12s -p KillMode=control-group \
    /usr/bin/env -i "HOME=$t/home" "XDG_CONFIG_HOME=$t/home/.config" \
    "XDG_RUNTIME_DIR=$t/runtime" "XDG_DATA_HOME=$t/state" "TMPDIR=$t/tmp" \
    "LD_LIBRARY_PATH=$t/prefix/usr/lib" "CONTAINERS_CONF=$t/containers.conf" \
    "CONTAINERS_STORAGE_CONF=$t/staged/storage.conf" \
    "REGISTRY_AUTH_FILE=$t/home/.config/containers/auth.json" \
    /usr/bin/bash "$tools/run-minihost-workflow.sh" --inside "$1" "$2" "$3" \
    > "$root/rebuild.log" 2>&1; then
    # A successful synchronous scope command can return before systemd
    # collects its transient unit. Check disappearance before accepting it.
    wait_for_scope_collection "${user_bus[@]}" systemctl --user list-units --all --no-legend "$unit"
else
    status=$?
    printf 'Minihost rebuild failed (exit %d); see the private build log on minihost.\n' "$status" >&2
    exit "$status"
fi
python3 -E -B "$tools/provenance.py" check-handoff "$root/handoff" "$1" "$2" "$3" \
    >> "$root/rebuild.log" 2>&1 || fail "verified handoff missing; see the private build log on minihost"
printf '%s\n' UNSIGNED_REBUILD_HANDOFF_VERIFIED
