#!/usr/bin/env bash
# Wait until a daemon with an early-bound socket can serve camera-bearing work.
#
# Usage after sourcing:
#   wait_for_camera_ready <socket> <irlume-cli> <daemon-pid> [attempts] [delay]
#
# Returns 0 when a read-only emitter dry-run reaches the loaded engine, 2 when
# the daemon exits first, and 1 when the attempt budget expires.
wait_for_camera_ready() {
    local socket="$1" cli="$2" daemon_pid="$3"
    local attempts="${4:-1800}" delay="${5:-0.1}"

    local _
    for _ in $(seq 1 "$attempts"); do
        if [ -S "$socket" ] \
            && IRLUME_SOCKET="$socket" "$cli" ir-setup --dry-run >/dev/null 2>&1; then
            return 0
        fi
        kill -0 "$daemon_pid" 2>/dev/null || return 2
        sleep "$delay"
    done
    return 1
}
