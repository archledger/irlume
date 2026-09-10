#!/usr/bin/env bash
# Run one command against fresh software TPM state. Never fall back to hardware.
set -euo pipefail
if [ "$#" -eq 0 ]; then
  echo 'Usage: with-swtpm.sh COMMAND [ARG ...]' >&2
  exit 2
fi
command -v swtpm >/dev/null || { echo 'with-swtpm: swtpm is required' >&2; exit 1; }
port="${IRLUME_SWTPM_PORT:-$((20000 + RANDOM))}"
if [[ ! "$port" =~ ^[0-9]{1,5}$ ]] || ((10#$port < 1 || 10#$port > 65534)); then
  echo 'with-swtpm: port must be an integer from 1 to 65534' >&2
  exit 2
fi
port=$((10#$port))
state=$(mktemp -d "${TMPDIR:-/tmp}/irlume-swtpm.XXXXXXXX")
swtpm_pid=''
cleanup() {
  local status=$?
  trap - EXIT
  if [ -n "$swtpm_pid" ]; then
    kill "$swtpm_pid" 2>/dev/null || true
    wait "$swtpm_pid" 2>/dev/null || true
  fi
  rm -rf -- "$state"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
swtpm socket --tpm2 --tpmstate "dir=$state" \
  --server "type=tcp,port=$port,bindaddr=127.0.0.1,disconnect" \
  --ctrl "type=tcp,port=$((port + 1)),bindaddr=127.0.0.1" \
  --flags not-need-init,startup-clear --pid "file=$state/pid" \
  >"$state/startup.log" 2>&1 &
swtpm_pid=$!
# swtpm writes this marker only after binding BOTH sockets. A pre-existing
# listener must never count as readiness, and its PID must never be killed.
ready=false
for _ in {1..100}; do
  if [ -f "$state/pid" ] && [ "$(cat "$state/pid")" = "$swtpm_pid" ] && kill -0 "$swtpm_pid" 2>/dev/null; then
    ready=true
    break
  fi
  kill -0 "$swtpm_pid" 2>/dev/null || break
  sleep 0.05
done
if [ "$ready" != true ]; then
  cat "$state/startup.log" >&2
  echo 'with-swtpm: emulator did not acquire its private endpoints' >&2
  exit 1
fi
IRLUME_TCTI="swtpm:host=127.0.0.1,port=$port" "$@"
# A command that never contacted its TPM must not hide emulator startup failure.
kill -0 "$swtpm_pid" 2>/dev/null
