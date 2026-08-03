#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Prove that a key irlume DERIVES opens a wallet that a real ksecretd guards,
# when handed over by the helper irlume SHIPS. Both halves have to be the real
# thing: a test that reimplemented either one could agree with itself while
# both were wrong.
#
# Needs root (the helper drops privileges), a KDE wallet daemon, and the
# libsecret CLI. It builds its own throwaway user and removes it at the end.
#
#   sudo scripts/kwallet-handoff-check.sh [stress_iterations]
#
# Exit 0 only if every control holds:
#   * the correct key opens the wallet and the canary reads back
#   * a key from the WRONG password does not
#   * a wallet daemon that cannot start is reported as a failure, not a success
#   * repeated handoffs leak neither processes nor sockets
set -u

ITER=${1:-15}
TESTUSER=irlkwchk
ROOT=$(cd "$(dirname "$0")/.." && pwd)
HELPER="$ROOT/target/debug/irlume-kwallet-init"
DERIVE="$ROOT/target/debug/examples/derive_wallet_key"
PASSWORD='handoff-check-password'
WRONG='handoff-check-WRONG'
CANARY='canary-handoff-check'
fail=0

note() { printf '%s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; fail=1; }

[ "$(id -u)" -eq 0 ] || { echo "must run as root (the helper drops privileges)"; exit 2; }
for f in "$HELPER" "$DERIVE"; do
  [ -x "$f" ] || { echo "missing $f; run: cargo build -p irlume-kwallet-init && cargo build -p irlume-core --example derive_wallet_key"; exit 2; }
done
command -v secret-tool >/dev/null || { echo "secret-tool (libsecret) is required"; exit 2; }
command -v socat >/dev/null || { echo "socat is required (it is what Plasma uses)"; exit 2; }

cleanup() {
  pkill -f -u "$TESTUSER" ksecretd 2>/dev/null
  pkill -f -u "$TESTUSER" dbus-daemon 2>/dev/null
  sleep 1
  pkill -9 -u "$TESTUSER" 2>/dev/null
  sleep 1
  userdel -r "$TESTUSER" 2>/dev/null
  rm -rf "$RT" "$WORK" 2>/dev/null
}
trap cleanup EXIT

userdel -r "$TESTUSER" 2>/dev/null
useradd -m -s /bin/bash "$TESTUSER" || { echo "could not create $TESTUSER"; exit 2; }
TUID=$(id -u "$TESTUSER")
RT=/run/user/$TUID
WORK=$(mktemp -d)
chmod 755 "$WORK"
mkdir -p "$RT"; chown "$TESTUSER:$TESTUSER" "$RT"; chmod 700 "$RT"
HOMEDIR=/home/$TESTUSER
KWL=$HOMEDIR/.local/share/kwalletd/kdewallet.kwl

ADDR=$(sudo -u "$TESTUSER" dbus-daemon --session --fork --print-address)
[ -n "$ADDR" ] || { echo "could not start a session bus"; exit 2; }
asuser() {
  sudo -u "$TESTUSER" env -i HOME="$HOMEDIR" USER="$TESTUSER" PATH=/usr/bin:/bin \
    XDG_RUNTIME_DIR="$RT" DBUS_SESSION_BUS_ADDRESS="$ADDR" "$@"
}
reap_daemon() { pkill -f -u "$TUID" ksecretd 2>/dev/null; sleep 1; }

# Start the wallet daemon with $1 as the key file, then deliver the session
# environment the way plasma-kwallet-pam.service does. A real Plasma session
# passes a display here; this harness has none, so Qt is told to go offscreen.
handoff() {
  local keyfile=$1 sock
  sock=$("$HELPER" "$TESTUSER" < "$keyfile") || return 1
  asuser sh -c "QT_QPA_PLATFORM=offscreen env | socat STDIN UNIX-CONNECT:$sock" \
    >/dev/null 2>&1
  sleep 3
  printf '%s' "$sock"
}

# --- seed: a wallet created the ordinary way, holding a known secret ---------
note "seeding a wallet for $TESTUSER"
python3 - "$HOMEDIR" "$PASSWORD" <<'PY' > "$WORK/seed.key"
import hashlib, os, sys
home, pw = sys.argv[1], sys.argv[2]
sp = os.path.join(home, ".local/share/kwalletd/kdewallet.salt")
os.makedirs(os.path.dirname(sp), exist_ok=True)
if not os.path.exists(sp):
    with open(os.open(sp, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
        f.write(os.urandom(56))
salt = open(sp, "rb").read(56)
os.sys.stdout.buffer.write(hashlib.pbkdf2_hmac("sha512", pw.encode(), salt, 50000, 56))
PY
chown -R "$TESTUSER:$TESTUSER" "$HOMEDIR/.local"
handoff "$WORK/seed.key" >/dev/null
printf '%s' "$CANARY" | asuser timeout 20 secret-tool store --label=c svc handoffcheck >/dev/null 2>&1
for _ in $(seq 12); do sleep 1; [ "$(stat -c %s "$KWL" 2>/dev/null || echo 0)" -gt 100 ] && break; done
[ "$(stat -c %s "$KWL" 2>/dev/null || echo 0)" -gt 100 ] \
  || { echo "seeding failed: the wallet never reached disk"; exit 2; }
reap_daemon

# --- 1. the key irlume derives opens it -------------------------------------
"$DERIVE" "$HOMEDIR" "$PASSWORD" > "$WORK/right.key" || { echo "derive failed"; exit 2; }
[ "$(stat -c %s "$WORK/right.key")" -eq 56 ] || bad "derived key is not 56 bytes"
handoff "$WORK/right.key" >/dev/null
got=$(asuser timeout 20 secret-tool lookup svc handoffcheck 2>/dev/null)
if [ "$got" = "$CANARY" ]; then note "PASS: the derived key opened the wallet"
else bad "the derived key did not open the wallet (read back '$got')"; fi
reap_daemon

# --- 2. a key from the wrong password does not ------------------------------
# Without this the check above could be passing for some other reason.
"$DERIVE" "$HOMEDIR" "$WRONG" > "$WORK/wrong.key"
handoff "$WORK/wrong.key" >/dev/null
got=$(asuser timeout 20 secret-tool lookup svc handoffcheck 2>/dev/null)
if [ -z "$got" ]; then note "PASS: a key from the wrong password was refused"
else bad "the WRONG key opened the wallet (read back '$got')"; fi
reap_daemon

# --- 3. a daemon that cannot start must be reported as a failure ------------
# This one guards a fail-open path rather than a feature. The caller exports
# PAM_KWALLET5_LOGIN on the strength of this program's exit status, and that
# variable makes pam_kwallet5 stand down, so reporting success when the wallet
# daemon never started would leave the wallet locked AND remove the fallback
# that would have opened it.
notexec=$WORK/not-executable
: > "$notexec"; chmod 0644 "$notexec"
if IRLUME_KSECRETD="$notexec" "$HELPER" "$TESTUSER" < "$WORK/right.key" >/dev/null 2>&1; then
  bad "the helper reported success when the wallet daemon could not be executed"
else
  note "PASS: a daemon that cannot exec is reported as a failure"
fi
reap_daemon

# --- 4. stress: repeated handoffs must not accumulate anything --------------
# One handoff working says nothing about a session that logs in and out all day.
# Each round is a fresh daemon, so leaked processes or descriptors show up as a
# trend rather than as a single failure.
note "stress: $ITER handoffs"
procs0=$(pgrep -c -u "$TUID" -f ksecretd || true)
ok=0
fdmax=0
for i in $(seq "$ITER"); do
  handoff "$WORK/right.key" >/dev/null
  got=$(asuser timeout 20 secret-tool lookup svc handoffcheck 2>/dev/null)
  [ "$got" = "$CANARY" ] && ok=$((ok + 1))
  live=$(pgrep -c -u "$TUID" -f ksecretd || true)
  # Count the WALLET DAEMON's descriptors, not this script's. The earlier
  # version measured /proc/self/fd, which belongs to the shell and never
  # touches the handoff, so it could not have caught a leak in it.
  dpid=$(pgrep -u "$TUID" -f ksecretd | head -1)
  dfd=0
  [ -n "$dpid" ] && dfd=$(ls "/proc/$dpid/fd" 2>/dev/null | wc -l)
  [ "$dfd" -gt "$fdmax" ] && fdmax=$dfd
  printf '  %2d/%s opened=%s live_daemons=%s daemon_fds=%s\n' "$i" "$ITER" \
    "$([ "$got" = "$CANARY" ] && echo yes || echo NO)" "$live" "$dfd"
  reap_daemon
  # A stale socket must not block the next login; the helper replaces it.
  [ -S "$RT/kwallet5.socket" ] || bad "round $i left no socket behind to replace"
done
procs1=$(pgrep -c -u "$TUID" -f ksecretd || true)
leftover=$(ls "$RT" 2>/dev/null | grep -c kwallet5 || true)

[ "$ok" -eq "$ITER" ] || bad "stress: only $ok/$ITER handoffs opened the wallet"
[ "$procs1" -le "$((procs0 + 1))" ] || bad "stress: wallet daemons accumulated ($procs0 -> $procs1)"
# Each round replaces the one socket; more than one means the helper is
# creating a new name per handoff and leaving the old behind.
[ "$leftover" -le 1 ] || bad "stress: $leftover handoff sockets left in $RT"
note "stress: $ok/$ITER opened, daemons $procs0 -> $procs1, peak daemon fds $fdmax, sockets left $leftover"

if [ "$fail" -eq 0 ]; then note "ALL CHECKS PASSED"; else note "CHECKS FAILED"; fi
exit "$fail"
