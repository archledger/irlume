#!/usr/bin/env bash
# Prove the GNOME keyring token handoff (#250) against a REAL
# gnome-keyring-daemon, without touching the caller's own login keyring.
#
#   scripts/gkr-token-check.sh [N]      # N = repeat count for the leak check
#
# What it establishes, in order:
#   1. a token re-key works:      CHANGE(password -> token) is accepted
#   2. the token IS the credential: CHANGE(token, token) is accepted and
#                                   CHANGE(password, password) is DENIED
#   3. it survives a daemon restart: a FRESH daemon (which starts locked) is
#                                   unlocked by irlume-gkr-unlock with the token
#                                   and NOT by the password
#   4. the keyring still works:    a canary secret stored before the re-key is
#                                   readable after it, through the Secret
#                                   Service, so "unlocked" is not just a status
#                                   bit (an earlier KDE measurement was fooled
#                                   by exactly that)
#   5. the disarm path works:      CHANGE(token -> password) puts it back
#   6. N cycles leak no daemons
#
# Everything runs as the invoking user inside a throwaway HOME and runtime dir.
# The Python side implements the control protocol independently of the Rust
# crate, so agreement between them and a real daemon is a cross-check rather
# than one implementation agreeing with itself.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
HELPER="${IRLUME_GKR_UNLOCK:-$REPO/target/release/irlume-gkr-unlock}"
CYCLES="${1:-3}"
PASSWORD="orig-pass-4417"
TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
CANARY="canary-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"

if [[ $EUID -eq 0 ]]; then
    echo "run this as an ordinary user, not root: it drives a user keyring daemon" >&2
    exit 2
fi
command -v gnome-keyring-daemon >/dev/null || { echo "SKIP: gnome-keyring-daemon not installed"; exit 0; }
[[ -x "$HELPER" ]] || { echo "missing $HELPER; cargo build --release -p irlume-gkr-unlock" >&2; exit 2; }

BASE="$(mktemp -d "${TMPDIR:-/tmp}/irlume-gkr-check-XXXXXX")"
export HOME="$BASE/home"
export XDG_RUNTIME_DIR="$BASE/run"
export XDG_DATA_HOME="$HOME/.local/share"
mkdir -p "$HOME" "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"
chmod 700 "$XDG_RUNTIME_DIR"
unset DBUS_SESSION_BUS_ADDRESS GNOME_KEYRING_CONTROL

PASS=0
FAIL=0
ok()   { echo "  ok    $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
note() { echo "  --    $*"; }

cleanup() {
    pkill -u "$(id -u)" -f "gnome-keyring-daemon.*$BASE" 2>/dev/null
    [[ -n "${DBUS_PID:-}" ]] && kill "$DBUS_PID" 2>/dev/null
    rm -rf "$BASE"
}
trap cleanup EXIT

# A private session bus: the Secret Service canary needs one, and it must not
# be the caller's own bus, where a real gnome-keyring is already the provider.
eval "$(dbus-daemon --session --print-address=1 --print-pid=1 --fork \
    | { read -r addr; read -r pid; echo "export DBUS_SESSION_BUS_ADDRESS='$addr'; DBUS_PID=$pid"; })"

# ---------------------------------------------------------------- the client
# Independent implementation of gnome-keyring's control protocol, from
# pam/gkr-pam-client.c: one credentials byte, then big-endian
# [total_len][op][(arg_len)(arg)...]; the reply is [8][result].
ctl() {  # ctl <op-number> <arg>...
    python3 - "$XDG_RUNTIME_DIR/keyring/control" "$@" <<'PY'
import socket, struct, sys
sock, op, *args = sys.argv[1], int(sys.argv[2]), *sys.argv[3:]
body = b"".join(struct.pack(">I", len(a.encode())) + a.encode() for a in args)
pkt = struct.pack(">II", 8 + len(body), op) + body
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(sock)
except OSError as e:
    print(f"connect-error:{e}"); sys.exit(3)
s.sendall(b"\0"); s.sendall(pkt)
reply = s.recv(8)
if len(reply) != 8:
    print(f"short-reply:{len(reply)}"); sys.exit(4)
ln, res = struct.unpack(">II", reply)
print({0: "OK", 1: "DENIED", 2: "FAILED", 3: "NO_DAEMON"}.get(res, f"UNKNOWN{res}"))
PY
}

start_daemon() {  # start_daemon; leaves the daemon running, control socket ready
    gnome-keyring-daemon --start --components=secrets,pkcs11 >"$BASE/env.$$" 2>/dev/null &
    for _ in $(seq 1 50); do
        [[ -S "$XDG_RUNTIME_DIR/keyring/control" ]] && return 0
        sleep 0.1
    done
    return 1
}

kill_daemon() {
    pkill -u "$(id -u)" -f "gnome-keyring-daemon" 2>/dev/null
    # Wait for the socket to actually go: a surviving daemon keeps the
    # collection unlocked in memory and would report success for a secret it
    # never accepted.
    for _ in $(seq 1 50); do
        pgrep -u "$(id -u)" -f "gnome-keyring-daemon" >/dev/null || break
        sleep 0.1
    done
    rm -f "$XDG_RUNTIME_DIR/keyring/control"
}

canary_store() {
    python3 - "$1" <<'PY' 2>/dev/null
import sys
try:
    import secretstorage
except ImportError:
    sys.exit(77)
conn = secretstorage.dbus_init()
coll = secretstorage.get_default_collection(conn)
coll.create_item("irlume-check", {"application": "irlume-check"}, sys.argv[1].encode())
PY
}

canary_read() {
    python3 - <<'PY' 2>/dev/null
import sys
try:
    import secretstorage
except ImportError:
    sys.exit(77)
conn = secretstorage.dbus_init()
coll = secretstorage.get_default_collection(conn)
for item in coll.search_items({"application": "irlume-check"}):
    print(item.get_secret().decode()); sys.exit(0)
sys.exit(1)
PY
}

echo "irlume GNOME keyring token check  (HOME=$HOME)"

# ------------------------------------------------------------------- step 1
echo "[1] create the login keyring with a password"
start_daemon || { echo "daemon did not start"; exit 1; }
r="$(ctl 1 "$PASSWORD")"   # UNLOCK on a fresh store creates the login keyring
[[ "$r" == "OK" ]] && ok "created/unlocked with the password ($r)" || bad "expected OK, got $r"

have_canary=0
if canary_store "$CANARY"; then
    have_canary=1
    ok "stored a canary secret through the Secret Service"
else
    rc=$?
    [[ $rc -eq 77 ]] && note "python3-secretstorage absent: skipping the canary (steps 4 degraded)" \
                     || note "canary store failed (rc=$rc); skipping the canary"
fi

# ------------------------------------------------------------------- step 2
echo "[2] re-key to the token, and prove which secret is now current"
r="$(ctl 2 "$PASSWORD" "$TOKEN")"
[[ "$r" == "OK" ]] && ok "CHANGE(password -> token) accepted" || bad "re-key: expected OK, got $r"

r="$(ctl 2 "$TOKEN" "$TOKEN")"
[[ "$r" == "OK" ]] && ok "CHANGE(token, token) accepted: the token IS the credential" \
                   || bad "token self-change: expected OK, got $r"

r="$(ctl 2 "$PASSWORD" "$PASSWORD")"
[[ "$r" == "DENIED" ]] && ok "CHANGE(password, password) DENIED: the password no longer opens it" \
                       || bad "the old password still works ($r); the re-key did not take"

# ------------------------------------------------------------------- step 3
echo "[3] restart the daemon, then unlock with irlume-gkr-unlock"
kill_daemon
start_daemon || { echo "daemon did not restart"; exit 1; }

if printf '%s' "wrong-token-0000" | env IRLUME_GKR_RUNTIME_DIR="$XDG_RUNTIME_DIR" IRLUME_GKR_HOME="$HOME" \
        "$HELPER" "$(id -un)" 2>"$BASE/err.wrong"; then
    bad "the helper reported success for a WRONG token"
else
    ok "helper refused a wrong token ($(tr -d '\n' <"$BASE/err.wrong" | tail -c 60))"
fi

if printf '%s' "$TOKEN" | env IRLUME_GKR_RUNTIME_DIR="$XDG_RUNTIME_DIR" IRLUME_GKR_HOME="$HOME" \
        "$HELPER" "$(id -un)" 2>"$BASE/err.right"; then
    ok "helper unlocked a freshly started daemon with the sealed token"
else
    bad "helper failed with the correct token: $(cat "$BASE/err.right")"
fi

# ------------------------------------------------------------------- step 4
echo "[4] the keyring still holds its contents"
if [[ $have_canary -eq 1 ]]; then
    got="$(canary_read)"
    if [[ "$got" == "$CANARY" ]]; then
        ok "canary read back through the Secret Service after the re-key + restart"
    else
        bad "canary readback was '$got', expected '$CANARY'"
    fi
else
    note "no canary was stored; this step proved nothing"
fi

# ------------------------------------------------------------------ step 4b
echo "[4b] the helper refuses to CREATE a keyring that does not exist"
# UNLOCK mints a login keyring keyed to whatever it is handed when none
# exists, so a blind unlock after the user deletes theirs would leave a
# keyring whose password is a random token they have never seen.
kr="$XDG_DATA_HOME/keyrings/login.keyring"
if [[ -f "$kr" ]]; then
    mv "$kr" "$kr.hidden"
    if printf '%s' "$TOKEN" | env IRLUME_GKR_RUNTIME_DIR="$XDG_RUNTIME_DIR" IRLUME_GKR_HOME="$HOME" \
            "$HELPER" "$(id -un)" 2>"$BASE/err.nokr"; then
        bad "the helper unlocked with NO login keyring present (it created one)"
    else
        grep -q 'refusing to UNLOCK' "$BASE/err.nokr" \
            && ok "refused with the reason named" \
            || bad "refused, but for another reason: $(cat "$BASE/err.nokr")"
    fi
    mv "$kr.hidden" "$kr"
else
    note "no login.keyring file on disk at $kr; step skipped"
fi

# ------------------------------------------------------------------- step 5
echo "[5] disarm: re-key back to the password"
r="$(ctl 2 "$TOKEN" "$PASSWORD")"
[[ "$r" == "OK" ]] && ok "CHANGE(token -> password) accepted" || bad "disarm: expected OK, got $r"
r="$(ctl 2 "$PASSWORD" "$PASSWORD")"
[[ "$r" == "OK" ]] && ok "the password is the credential again" || bad "after disarm: got $r"

# ------------------------------------------------------------------- step 6
echo "[6] $CYCLES unlock cycles leak no daemons"
before="$(pgrep -u "$(id -u)" -cf gnome-keyring-daemon)"
cycles_run=0
for _ in $(seq 1 "$CYCLES"); do
    kill_daemon
    start_daemon || break
    printf '%s' "$PASSWORD" | env IRLUME_GKR_RUNTIME_DIR="$XDG_RUNTIME_DIR" IRLUME_GKR_HOME="$HOME" \
        "$HELPER" "$(id -un)" >/dev/null 2>&1 || bad "cycle unlock failed"
    cycles_run=$((cycles_run+1))
done
after="$(pgrep -u "$(id -u)" -cf gnome-keyring-daemon)"
if [[ "$cycles_run" -eq "$CYCLES" ]]; then
    [[ "$after" -le "$before" ]] && ok "$cycles_run cycles, daemon count $before -> $after" \
                                 || bad "daemon count grew: $before -> $after"
else
    bad "only $cycles_run of $CYCLES cycles ran; the count means nothing"
fi

echo
echo "passed: $PASS   failed: $FAIL"
[[ $FAIL -eq 0 ]]
