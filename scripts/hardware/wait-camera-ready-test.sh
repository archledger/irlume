#!/usr/bin/env bash
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=wait-camera-ready.sh
source "$here/wait-camera-ready.sh"

dir=$(mktemp -d)
socket="$dir/daemon.sock"
counter="$dir/calls"
server_pid=""
cleanup() {
    [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    rm -rf "$dir"
}
trap cleanup EXIT

printf '0\n' >"$counter"
cat >"$dir/fake-irlume" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
: "${IRLUME_READY_TEST_COUNTER:?}"
count=$(<"$IRLUME_READY_TEST_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" >"$IRLUME_READY_TEST_COUNTER"
if [ "${IRLUME_READY_TEST_NEVER:-0}" = 1 ]; then
    exit 1
fi
# Model loading: the early socket accepts requests, but the first two
# camera-bearing calls still receive the daemon's "starting" failure.
[ "$count" -ge 3 ]
FAKE
chmod +x "$dir/fake-irlume"

python3 - "$socket" <<'PY' &
import socket
import sys
import time

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(sys.argv[1])
server.listen(1)
time.sleep(30)
PY
server_pid=$!
for _ in $(seq 1 100); do
    [ -S "$socket" ] && break
    sleep 0.01
done
[ -S "$socket" ] || {
    printf '%s\n' 'fake daemon did not create its socket'
    exit 1
}

IRLUME_READY_TEST_COUNTER="$counter" \
    wait_for_camera_ready "$socket" "$dir/fake-irlume" "$server_pid" 10 0.01
calls=$(<"$counter")
[ "$calls" -eq 3 ] || {
    printf 'expected 3 protocol probes, got %s\n' "$calls"
    exit 1
}
printf '%s\n' 'wait-camera-ready: socket alone refused; third protocol probe accepted'

set +e
IRLUME_READY_TEST_COUNTER="$counter" IRLUME_READY_TEST_NEVER=1 \
    wait_for_camera_ready "$socket" "$dir/fake-irlume" "$server_pid" 2 0.01
status=$?
set -e
[ "$status" -eq 1 ] || {
    printf 'expected timeout status 1, got %s\n' "$status"
    exit 1
}

dead_pid=$server_pid
kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""
set +e
IRLUME_READY_TEST_COUNTER="$counter" IRLUME_READY_TEST_NEVER=1 \
    wait_for_camera_ready "$socket" "$dir/fake-irlume" "$dead_pid" 2 0.01
status=$?
set -e
[ "$status" -eq 2 ] || {
    printf 'expected daemon-exited status 2, got %s\n' "$status"
    exit 1
}
printf '%s\n' 'wait-camera-ready: timeout and daemon-exited statuses preserved'
