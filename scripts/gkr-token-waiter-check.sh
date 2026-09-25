#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Prove that irlume-gkr-unlock delivers the GNOME keyring token only once
# gnome-keyring is initialized (#250), against a REAL gnome-keyring-daemon
# started the way pam_gnome_keyring starts it where no socket unit exists
# (`--login`, Fedora 43 and 44), without touching the caller's own keyring.
#
#   scripts/gkr-token-waiter-check.sh             # every case
#   scripts/gkr-token-waiter-check.sh CASE...     # some cases
#   scripts/gkr-token-waiter-check.sh --list      # the case names
#
# Run it with no display, as an ordinary user:
#
#   env -u DISPLAY -u WAYLAND_DISPLAY -u XAUTHORITY scripts/gkr-token-waiter-check.sh
#
# Each case gets its own throwaway HOME and runtime dir, and a private
# dbus-daemon at $XDG_RUNTIME_DIR/bus whose only activatable services are
# gnome-keyring's own two (org.gnome.keyring and org.freedesktop.secrets).
# The system bus address points at nothing. Unlock prompts go to gcr's mock
# prompter, which cancels each one after 1.5 s, like a user dismissing an
# unexpected dialog. Test secrets are fake and never printed. Everything the
# script starts is stopped at exit; nothing is selected by process name.
#
# The login keyring starts as `irlume keyring arm` leaves it: it holds a
# canary and is keyed to a random token (the stale case keeps it keyed to the
# test password). Every case that delivers checks that the Secret Service
# client got the canary with no prompt, that the collection is unlocked and
# still keyed to the token, that the helper activated no bus name, and that
# no helper process is left. The helper runs with --foreground, except in the
# first case, which runs the real PAM-mode fork: the parent must return within
# about a second while its detached waiter delivers later. That waiter logs to
# the journal, so a run leaves a few `irlume-gkr-unlock` lines there.
#
# A missing tool is a failure, not a skip: gnome-keyring-daemon, dbus-daemon,
# dbus-monitor, secret-tool, systemd-socket-activate, python3 with jeepney, a
# C compiler, pkg-config with gio-2.0, and gcr's libgcr-base-3.so.1 for the
# mock prompter.
# shellcheck disable=SC2015 # ok() always succeeds, so `A && ok || bad` is if-then-else here
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/target}"
[[ "$TARGET_DIR" == /* ]] || TARGET_DIR="$REPO/$TARGET_DIR"
HELPER="${IRLUME_GKR_UNLOCK:-$TARGET_DIR/release/irlume-gkr-unlock}"

CASES=(typed-pam-early fingerprint-order face secret-tool-client worst-client
       stale no-initializer socket-unit socket-activated fake-owner prebound
       no-login-keyring sigterm baseline)

if [[ "${1:-}" == --list ]]; then
    printf '%s\n' "${CASES[@]}"
    exit 0
fi
if [[ -v DISPLAY || -v WAYLAND_DISPLAY || -v XAUTHORITY ]]; then
    echo "refusing to run with DISPLAY, WAYLAND_DISPLAY or XAUTHORITY set: a keyring" >&2
    echo "prompt could reach your screen and ask for your real password. Run:" >&2
    echo "  env -u DISPLAY -u WAYLAND_DISPLAY -u XAUTHORITY $0 $*" >&2
    exit 2
fi
if [[ $EUID -eq 0 ]]; then
    echo "run this as an ordinary user, not root: it drives a user keyring daemon" >&2
    exit 2
fi
missing=()
for tool in gnome-keyring-daemon dbus-daemon dbus-monitor secret-tool \
            systemd-socket-activate python3 cc pkg-config; do
    command -v "$tool" >/dev/null || missing+=("$tool")
done
python3 -c 'import jeepney' 2>/dev/null || missing+=("python3 jeepney")
pkg-config --exists gio-2.0 2>/dev/null || missing+=("gio-2.0 development files")
[[ -x "$HELPER" ]] || missing+=("$HELPER (cargo build --release -p irlume-gkr-unlock)")
if ((${#missing[@]})); then
    echo "FAIL: missing: ${missing[*]}" >&2
    exit 1
fi
SELECTED=("$@")
((${#SELECTED[@]})) || SELECTED=("${CASES[@]}")
for c in "${SELECTED[@]}"; do
    [[ " ${CASES[*]} " == *" $c "* ]] || { echo "unknown case: $c" >&2; exit 2; }
done

# A unix socket path is at most 107 bytes, and the runtime dir sits under this.
TMPBASE="${TMPDIR:-/tmp}"
((${#TMPBASE} > 40)) && TMPBASE=/tmp
ROOT="$(mktemp -d "$TMPBASE/irlume-gkrw-XXXXXX")"
trap 'rm -rf "$ROOT"' EXIT

# ---------------------------------------------------------------- mock prompter
# gcr's own mock prompter, headless, on the private bus. It answers up to N
# password prompts, each after DELAY ms: cancelled, or with $MOCK_ANSWER when
# that is set. It prints its bus name, then waits.
cat >"$ROOT/mockprompter.c" <<'C'
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
const gchar *gcr_mock_prompter_start (void);
void gcr_mock_prompter_expect_password_cancel (void);
void gcr_mock_prompter_expect_password_ok (const gchar *password, const gchar *first_property_name, ...);
void gcr_mock_prompter_set_delay_msec (guint delay_msec);
void gcr_mock_prompter_stop (void);
int main (int argc, char **argv)
{
	guint delay = argc > 1 ? (guint) atoi (argv[1]) : 1500;
	int n = argc > 2 ? atoi (argv[2]) : 3;
	const gchar *answer = g_getenv ("MOCK_ANSWER");
	const gchar *name = gcr_mock_prompter_start ();
	gcr_mock_prompter_set_delay_msec (delay);
	for (int i = 0; i < n; i++) {
		if (answer)
			gcr_mock_prompter_expect_password_ok (answer, NULL);
		else
			gcr_mock_prompter_expect_password_cancel ();
	}
	printf ("%s\n", name);
	fflush (stdout);
	for (int i = 0; i < 3000; i++)
		g_usleep (100000);
	gcr_mock_prompter_stop ();
	return 0;
}
C
# shellcheck disable=SC2046 # pkg-config output is a list of flags
if ! cc -O1 -o "$ROOT/mockprompter" "$ROOT/mockprompter.c" \
        $(pkg-config --cflags --libs gio-2.0) -l:libgcr-base-3.so.1 2>"$ROOT/cc.log"; then
    echo "FAIL: could not build gcr's mock prompter (libgcr-base-3.so.1 missing?):" >&2
    cat "$ROOT/cc.log" >&2
    exit 1
fi

# ---------------------------------------------------------------- the client
# An independent client for gnome-keyring's control socket and the private
# bus. Secrets are named, never passed in argv: "@token" reads $CHECK_TOKEN,
# "@password" $CHECK_PASSWORD, "@canary" $CHECK_CANARY.
cat >"$ROOT/gk.py" <<'PY'
import ctypes, os, signal, socket, struct, subprocess, sys, time

from jeepney import (DBusAddress, HeaderFields, MatchRule, MessageType, message_bus,
                     new_error, new_method_call, new_method_return)
from jeepney.io.blocking import Proxy, open_dbus_connection

RES = {0: "OK", 1: "DENIED", 2: "FAILED", 3: "NO_DAEMON"}
OP = {"init": 0, "unlock": 1, "change": 2}
LOGIN = "/org/freedesktop/secrets/collection/login"
NO_AUTO_START = 0x2
SERVICE = DBusAddress("/org/freedesktop/secrets", bus_name="org.freedesktop.secrets",
                      interface="org.freedesktop.Secret.Service")


def secret(arg):
    if arg.startswith("@"):
        return os.environ["CHECK_" + arg[1:].upper()].encode()
    return arg.encode()


def control_path():
    return os.environ.get("CHECK_CONTROL") or os.path.join(
        os.environ["XDG_RUNTIME_DIR"], "keyring", "control")


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def ctl(op, args, stringv=None):
    body = b"".join(struct.pack(">I", len(a)) + a for a in args)
    if stringv is not None:
        body += struct.pack(">I", len(stringv))
        body += b"".join(struct.pack(">I", len(v)) + v for v in stringv)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect(control_path())
        s.sendall(b"\0")
        s.sendall(struct.pack(">II", 8 + len(body), OP[op]) + body)
        hdr = recvn(s, 8)
        if len(hdr) != 8:
            return f"SHORT-REPLY({len(hdr)})"
        ln, res = struct.unpack(">II", hdr)
        if ln > 8:
            recvn(s, ln - 8)
        return RES.get(res, f"UNKNOWN{res}")
    except OSError as e:
        return f"CONNECT-ERROR({e.strerror})"
    finally:
        s.close()


def bus():
    return open_dbus_connection(bus="SESSION")


def call(conn, addr, method, sig=None, body=(), flags=0, timeout=10):
    msg = new_method_call(addr, method, sig, body)
    msg.header.flags |= flags
    reply = conn.send_and_get_reply(msg, timeout=timeout)
    if reply.header.message_type == MessageType.error:
        raise RuntimeError(reply.header.fields.get(HeaderFields.error_name))
    return reply.body


def has_owner(conn, name):
    return Proxy(message_bus, conn).NameHasOwner(name)[0]


def locked(conn):
    props = DBusAddress(LOGIN, bus_name="org.freedesktop.secrets",
                        interface="org.freedesktop.DBus.Properties")
    return call(conn, props, "Get", "ss", ("org.freedesktop.Secret.Collection", "Locked"),
                flags=NO_AUTO_START)[0][1]


def prompt(conn, path):
    """Run a Secret Service prompt; True if it was dismissed."""
    rule = MatchRule(type="signal", interface="org.freedesktop.Secret.Prompt",
                     member="Completed", path=path)
    Proxy(message_bus, conn).AddMatch(rule)
    with conn.filter(rule) as queue:
        call(conn, DBusAddress(path, bus_name="org.freedesktop.secrets",
                               interface="org.freedesktop.Secret.Prompt"), "Prompt", "s", ("",))
        return conn.recv_until_filtered(queue, timeout=20).body[0]


def subreap(seconds, cmd):
    # Become the reaper of every descendant, so the helper's detached waiter
    # is reparented here and its exit can be seen.
    ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER
    t0 = time.monotonic()
    rc = subprocess.Popen(cmd).wait()
    print(f"parent-exit={rc} parent-ms={int((time.monotonic() - t0) * 1000)}", flush=True)
    deadline = t0 + seconds
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            print(f"descendants-gone-ms={int((time.monotonic() - t0) * 1000)}", flush=True)
            return 0
        if pid == 0:
            if time.monotonic() > deadline:
                left = [int(p) for p in os.listdir("/proc") if p.isdigit()
                        and open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()[1] == str(os.getpid())]
                for p in left:
                    os.kill(p, signal.SIGKILL)
                print(f"descendants-left={len(left)}", flush=True)
                return 1
            time.sleep(0.05)


def fake_owner(directory, seconds, count_file):
    conn = bus()
    got = Proxy(message_bus, conn).RequestName("org.gnome.keyring", 4)[0]  # DO_NOT_QUEUE
    print(f"request-name={got}", flush=True)
    calls = 0
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            msg = conn.receive(timeout=max(0.05, deadline - time.monotonic()))
        except TimeoutError:
            continue
        if msg.header.message_type != MessageType.method_call:
            continue
        if msg.header.fields.get(HeaderFields.member) == "GetControlDirectory":
            calls += 1
            conn.send(new_method_return(msg, "s", (directory,)))
        else:
            conn.send(new_error(msg, "org.freedesktop.DBus.Error.UnknownMethod"))
        with open(count_file, "w") as f:
            f.write(f"{calls}\n")
    with open(count_file, "w") as f:
        f.write(f"{calls}\n")


def fake_listener(path, seconds, count_file):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    s.listen(8)
    s.settimeout(0.1)
    total, conns = 0, 0
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            c, _ = s.accept()
        except socket.timeout:
            continue
        conns += 1
        c.settimeout(2)
        try:
            while True:
                data = c.recv(4096)
                if not data:
                    break
                total += len(data)
        except OSError:
            pass
        c.close()
        with open(count_file, "w") as f:
            f.write(f"{conns} {total}\n")
    with open(count_file, "w") as f:
        f.write(f"{conns} {total}\n")


def main():
    cmd, *a = sys.argv[1:]
    if cmd == "ctl":
        print(ctl(a[0], [secret(x) for x in a[1:]]))
    elif cmd == "init":
        env = [f"{v}={os.environ[v]}".encode() for v in ("DBUS_SESSION_BUS_ADDRESS",)
               if v in os.environ]
        print(ctl("init", [a[0].encode()], env))
    elif cmd == "peer-pid":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(control_path())
        print(struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0])
    elif cmd == "has":
        print("owned" if has_owner(bus(), a[0]) else "not-owned")
    elif cmd == "locked":
        conn = bus()
        if not has_owner(conn, "org.freedesktop.secrets"):
            print("no-secret-service")
        else:
            print("locked" if locked(conn) else "unlocked")
    elif cmd == "store-canary":
        conn = bus()
        _, session = call(conn, SERVICE, "OpenSession", "sv", ("plain", ("s", "")))
        coll = DBusAddress(LOGIN, bus_name="org.freedesktop.secrets",
                           interface="org.freedesktop.Secret.Collection")
        props = {"org.freedesktop.Secret.Item.Label": ("s", "irlume waiter check"),
                 "org.freedesktop.Secret.Item.Attributes":
                     ("a{ss}", {"application": "irlume-waiter-check"})}
        _, pr = call(conn, coll, "CreateItem", "a{sv}(oayays)b",
                     (props, (session, b"", secret("@canary"), "text/plain"), True))
        print("stored" if pr == "/" else "prompted")
    elif cmd == "fastclient":
        # The worst case: the first message is Unlock, and a prompt, if one
        # comes back, is started at once.
        conn = bus()
        _, pr = call(conn, SERVICE, "Unlock", "ao", ([LOGIN],), timeout=15)
        if pr == "/":
            print("unlocked-without-prompt")
        else:
            print(f"prompt-completed dismissed={prompt(conn, pr)}")
    elif cmd == "prompt-unlock":
        conn = bus()
        call(conn, SERVICE, "Lock", "ao", ([LOGIN],))
        _, pr = call(conn, SERVICE, "Unlock", "ao", ([LOGIN],))
        dismissed = prompt(conn, pr) if pr != "/" else "no-prompt"
        print(f"dismissed={dismissed} locked-after={locked(conn)}")
    elif cmd == "subreap":
        return subreap(float(a[0]), a[1:])
    elif cmd == "fake-owner":
        fake_owner(a[0], float(a[1]), a[2])
    elif cmd == "fake-listener":
        fake_listener(a[0], float(a[1]), a[2])
    else:
        print(f"unknown command {cmd}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
PY

# ---------------------------------------------------------------- one case
# Everything below runs inside a subshell per case, so its environment,
# processes and trap are its own.
PASSWORD="test-pass-4417"

begin_case() {  # begin_case NAME MOCK_PROMPTS [password|token]
    CASE="$1"
    DIR="$(mktemp -d "$ROOT/$CASE-XXXX")"
    mkdir -p "$DIR/home" "$DIR/run" "$DIR/svc"
    chmod 700 "$DIR/run"
    export HOME="$DIR/home" XDG_RUNTIME_DIR="$DIR/run"
    export XDG_DATA_HOME="$HOME/.local/share" XDG_CONFIG_HOME="$HOME/.config" XDG_CACHE_HOME="$HOME/.cache"
    export DBUS_SYSTEM_BUS_ADDRESS="unix:path=$DIR/no-system-bus"
    export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
    unset GNOME_KEYRING_CONTROL SSH_AUTH_SOCK DESKTOP_AUTOSTART_ID XDG_CURRENT_DESKTOP \
          XDG_SESSION_DESKTOP GNOME_KEYRING_TEST_PROMPTER MOCK_ANSWER
    export CHECK_PASSWORD="$PASSWORD"
    CHECK_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    CHECK_CANARY="canary-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
    export CHECK_TOKEN CHECK_CANARY
    PIDS=()
    FAILS=0
    trap end_case EXIT
    mkdir -p "$XDG_DATA_HOME"
    local gkd
    gkd="$(command -v gnome-keyring-daemon)"
    for name in org.gnome.keyring org.freedesktop.secrets; do
        printf '[D-BUS Service]\nName=%s\nExec=%s --start --foreground --components=secrets\n' \
            "$name" "$gkd" >"$DIR/svc/$name.service"
    done
    cat >"$DIR/bus.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <keep_umask/>
  <listen>$DBUS_SESSION_BUS_ADDRESS</listen>
  <auth>EXTERNAL</auth>
  <servicedir>$DIR/svc</servicedir>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF
    dbus-daemon --nofork --nosyslog --nopidfile --config-file="$DIR/bus.conf" 2>"$DIR/dbus.log" &
    PIDS+=("$!")
    wait_for "the private bus" 5 test -S "$XDG_RUNTIME_DIR/bus" || return 1
    dbus-monitor --address "$DBUS_SESSION_BUS_ADDRESS" >"$DIR/monitor.log" 2>&1 &
    PIDS+=("$!")
    if [[ -n "${3:-}" ]]; then
        local answer="$CHECK_PASSWORD"
        [[ "$3" == token ]] && answer="$CHECK_TOKEN"
        MOCK_ANSWER="$answer" "$ROOT/mockprompter" 1500 "$2" >"$DIR/mock.name" 2>"$DIR/mock.err" &
    else
        "$ROOT/mockprompter" 1500 "$2" >"$DIR/mock.name" 2>"$DIR/mock.err" &
    fi
    PIDS+=("$!")
    wait_for "the mock prompter" 5 test -s "$DIR/mock.name" || return 1
    GNOME_KEYRING_TEST_PROMPTER="$(head -n1 "$DIR/mock.name")"
    export GNOME_KEYRING_TEST_PROMPTER
    echo "[$CASE]"
}

end_case() {
    local status=$? p needle="XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR" left=""
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    sleep 0.2
    # Daemons the bus activated are not ours to track by pid; find them by
    # this case's runtime dir in their environment.
    for e in /proc/[0-9]*/environ; do
        p="${e#/proc/}"; p="${p%/environ}"
        [[ "$p" == "$BASHPID" ]] && continue
        if { tr '\0' '\n' <"$e"; } 2>/dev/null | grep -qxF "$needle"; then
            kill "$p" 2>/dev/null; left+=" $p"
        fi
    done
    sleep 0.2
    for p in "${PIDS[@]}" $left; do
        kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null
    done
    ((status == 0 && FAILS == 0)) || exit 1
    exit 0
}

ok()   { echo "  ok    $*"; }
bad()  { echo "  FAIL  $*"; FAILS=$((FAILS + 1)); }
note() { echo "  --    $*"; }
gk()   { python3 "$ROOT/gk.py" "$@"; }

wait_for() {  # wait_for WHAT SECONDS CMD...
    local what="$1" tenths=$(($2 * 10))
    shift 2
    for ((i = 0; i < tenths; i++)); do
        "$@" && return 0
        sleep 0.1
    done
    bad "timed out waiting for $what"
    return 1
}

control_up() { test -S "$XDG_RUNTIME_DIR/keyring/control"; }

GKR=""
start_plain() {  # an initialized daemon, like the socket unit's ExecStart
    gnome-keyring-daemon --foreground --components=pkcs11,secrets \
        --control-directory="$XDG_RUNTIME_DIR/keyring" >>"$DIR/gkr.log" 2>&1 &
    GKR=$!
    PIDS+=("$GKR")
    wait_for "the daemon's control socket" 5 control_up || return 1
    wait_for "the Secret Service" 5 name_is org.freedesktop.secrets owned
}

start_login() {  # start_login password|empty: pam_gnome_keyring's --login daemon
    local val=""
    [[ "$1" == password ]] && val="$PASSWORD"
    printf '%s' "$val" | gnome-keyring-daemon --foreground --login >>"$DIR/gkr.log" 2>&1 &
    GKR=$!
    PIDS+=("$GKR")
    wait_for "the --login daemon's control socket" 5 control_up
}

stop_daemon() {
    [[ -n "$GKR" ]] || return 0
    kill "$GKR" 2>/dev/null
    wait "$GKR" 2>/dev/null
    GKR=""
    rm -f "$XDG_RUNTIME_DIR/keyring/control"
    wait_for "the names to be released" 5 names_released
}

name_is() { [[ "$(gk has "$1")" == "$2" ]]; }
names_released() { name_is org.gnome.keyring not-owned && name_is org.freedesktop.secrets not-owned; }

seed() {  # seed token|password: a login keyring with a canary, keyed to $1
    start_plain || return 1
    local r
    r="$(gk ctl unlock @password)"
    [[ "$r" == OK ]] || { bad "creating the login keyring: $r"; return 1; }
    r="$(gk store-canary)"
    [[ "$r" == stored ]] || { bad "storing the canary: $r"; return 1; }
    if [[ "$1" == token ]]; then
        r="$(gk ctl change @password @token)"
        [[ "$r" == OK ]] || { bad "re-keying to the token: $r"; return 1; }
    fi
    stop_daemon
    reset_prompts
}

HP=""
helper_fg() {  # helper_fg TIMEOUT: --foreground, in the background of this shell
    printf '%s' "$CHECK_TOKEN" | env IRLUME_GKR_RUNTIME_DIR="$XDG_RUNTIME_DIR" IRLUME_GKR_HOME="$HOME" \
        "$HELPER" --foreground --timeout-secs "$1" "$(id -un)" \
        >"$DIR/helper.out" 2>"$DIR/helper.err" &
    HP=$!
    PIDS+=("$HP")
}

helper_done() {  # helper_done SECONDS: wait for the helper; sets HRC
    HRC=""
    if ! wait_for "the helper to exit" "$1" helper_exited; then
        kill -9 "$HP" 2>/dev/null
        return 1
    fi
    wait "$HP" 2>/dev/null
    HRC=$?
}
helper_exited() { ! kill -0 "$HP" 2>/dev/null; }

client() {  # a libsecret lookup: D-Bus-activates gnome-keyring like a session's first client
    local got
    got="$(timeout 20 secret-tool lookup application irlume-waiter-check 2>/dev/null)"
    if [[ "$got" == "$CHECK_CANARY" ]]; then echo found; else echo missing; fi
}

# Unlock prompts gnome-keyring started since the last reset_prompts.
PROMPT_BASE=0
prompt_total() { grep -a -c 'member=BeginPrompting' "$DIR/monitor.log" || true; }
reset_prompts() { PROMPT_BASE="$(prompt_total)"; }
prompts() { echo $(($(prompt_total) - PROMPT_BASE)); }

expect_exit() {  # expect_exit CODE WHAT; the helper's own lines follow as notes
    if [[ "$HRC" == "$1" ]]; then ok "helper exit $1 ($2)"; else bad "helper exit ${HRC:-none}, expected $1 ($2)"; fi
    local line
    while IFS= read -r line; do note "helper: ${line#irlume-gkr-unlock: }"; done <"$DIR/helper.err"
}

expect_log() {  # expect_log TEXT
    if grep -qF -- "$1" "$DIR/helper.err"; then ok "helper said: $1"; else bad "helper did not say '$1': $(tr '\n' ' ' <"$DIR/helper.err")"; fi
}

check_delivered() {  # the assertions shared by every case that delivers
    local r
    r="$(gk locked)"
    [[ "$r" == unlocked ]] && ok "login collection unlocked" || bad "login collection: $r"
    r="$(gk ctl change @token @token)"
    [[ "$r" == OK ]] && ok "still keyed to the token" || bad "CHANGE(token,token): $r"
    check_clean
}

check_clean() {  # no bus name activated by the helper, no helper process left
    if grep -a 'Activating service' "$DIR/dbus.log" | grep -q 'irlume-gkr-unlock'; then
        bad "the helper activated a bus name: $(grep -a 'Activating service' "$DIR/dbus.log" | grep 'irlume-gkr-unlock' | head -1)"
    else
        ok "the helper activated no bus name"
    fi
    if [[ -n "$HP" ]] && kill -0 "$HP" 2>/dev/null; then
        bad "helper $HP still running"
    else
        ok "no helper process left"
    fi
}

# ---------------------------------------------------------------- the cases

case_typed-pam-early() {
    # gdm-password's order: irlume's session line runs before
    # pam_gnome_keyring starts the daemon. The real PAM-mode fork.
    begin_case typed-pam-early 5 || return 1
    seed token || return 1
    printf '%s' "$CHECK_TOKEN" | env IRLUME_GKR_RUNTIME_DIR="$XDG_RUNTIME_DIR" IRLUME_GKR_HOME="$HOME" \
        python3 "$ROOT/gk.py" subreap 40 "$HELPER" --timeout-secs 30 "$(id -un)" \
        >"$DIR/subreap.out" 2>&1 &
    local sub=$!
    PIDS+=("$sub")
    sleep 0.3
    start_login password || return 1
    sleep 1.2
    local got
    got="$(client)"
    wait_for "the waiter to finish" 40 grep -q descendants "$DIR/subreap.out"
    local parent_exit parent_ms
    parent_exit="$(sed -nE 's/^parent-exit=([0-9-]+) .*/\1/p' "$DIR/subreap.out")"
    parent_ms="$(sed -nE 's/.*parent-ms=([0-9]+).*/\1/p' "$DIR/subreap.out")"
    [[ "$parent_exit" == 0 ]] && ok "PAM mode: the helper returned 0" || bad "PAM mode: helper exit '$parent_exit'"
    if [[ -n "$parent_ms" ]] && ((parent_ms < 1500)); then
        ok "PAM mode: the helper returned after ${parent_ms} ms, before gnome-keyring was initialized"
    else
        bad "PAM mode: the helper took '${parent_ms}' ms"
    fi
    grep -q '^descendants-gone' "$DIR/subreap.out" && ok "the detached waiter exited" \
        || bad "the waiter was left running: $(tr '\n' ' ' <"$DIR/subreap.out")"
    [[ "$got" == found ]] && ok "the client got the canary" || bad "the client got nothing"
    [[ "$(prompts)" == 0 ]] && ok "no unlock prompt" || bad "$(prompts) unlock prompt(s)"
    check_delivered
}

case_fingerprint-order() {
    # gdm-fingerprint's order: the --login daemon exists before irlume's line.
    begin_case fingerprint-order 5 || return 1
    seed token || return 1
    start_login password || return 1
    helper_fg 30
    sleep 1.2
    local got
    got="$(client)"
    helper_done 20
    expect_exit 0 delivered
    expect_log "token delivered"
    [[ "$got" == found ]] && ok "the client got the canary" || bad "the client got nothing"
    [[ "$(prompts)" == 0 ]] && ok "no unlock prompt" || bad "$(prompts) unlock prompt(s)"
    check_delivered
}

case_face() {
    # A face or fingerprint login: pam_gnome_keyring has no password to pass.
    begin_case face 5 || return 1
    seed token || return 1
    start_login empty || return 1
    helper_fg 30
    sleep 1.2
    local got
    got="$(client)"
    helper_done 20
    expect_exit 0 delivered
    [[ "$got" == found ]] && ok "the client got the canary" || bad "the client got nothing"
    [[ "$(prompts)" == 0 ]] && ok "no unlock prompt" || bad "$(prompts) unlock prompt(s)"
    check_delivered
}

case_secret-tool-client() {
    # An autostart-style `--start` initializes the daemon before any client;
    # a libsecret lookup a second later gets the secret with no prompt.
    begin_case secret-tool-client 5 || return 1
    seed token || return 1
    start_login password || return 1
    helper_fg 30
    sleep 0.5
    gnome-keyring-daemon --start --components=secrets >>"$DIR/gkr.log" 2>&1
    sleep 1
    local got
    got="$(client)"
    helper_done 20
    expect_exit 0 delivered
    [[ "$got" == found ]] && ok "secret-tool lookup returned the canary" || bad "secret-tool lookup got nothing"
    [[ "$(prompts)" == 0 ]] && ok "no unlock prompt" || bad "$(prompts) unlock prompt(s)"
    check_delivered
}

case_worst-client() {
    # Ten runs of a client whose first message is Unlock, with Prompt at once.
    begin_case worst-client 40 || return 1
    seed token || return 1
    local run results="" failed=0 got
    for run in $(seq 1 10); do
        reset_prompts
        start_login password || return 1
        helper_fg 30
        sleep 1.2
        got="$(timeout 25 python3 "$ROOT/gk.py" fastclient 2>&1)"
        helper_done 20
        local p
        p="$(prompts)"
        results+=" $run:${HRC:-?}/$p"
        if [[ "$HRC" != 0 || "$p" != 0 || "$got" == *"dismissed=True"* ]]; then
            failed=$((failed + 1))
            note "run $run: helper ${HRC:-?}, prompts $p, client '$got'"
        fi
        stop_daemon
    done
    ((failed == 0)) && ok "10 of 10 runs delivered with BeginPrompting == 0 (run:exit/prompts$results)" \
        || bad "$failed of 10 runs showed a prompt or failed (run:exit/prompts$results)"
    start_plain || return 1
    local r
    r="$(gk ctl change @token @token)"
    [[ "$r" == OK ]] && ok "still keyed to the token" || bad "CHANGE(token,token): $r"
    check_clean
}

case_stale() {
    # The keyring is keyed to the password, not the token.
    begin_case stale 5 password || return 1
    seed password || return 1
    start_login password || return 1
    helper_fg 30
    sleep 1.2
    local got
    got="$(client)"
    helper_done 20
    expect_exit 4 stale
    expect_log "not keyed to irlume's token"
    [[ "$got" == found ]] && ok "the password unlocked it at initialization" || bad "the client got nothing"
    local r
    r="$(gk ctl change @password @password)"
    [[ "$r" == OK ]] && ok "still keyed to the password" || bad "CHANGE(password,password): $r"
    # A token recorded as a failed login secret would re-key the keyring to
    # itself at the next successful prompted unlock.
    r="$(gk prompt-unlock)"
    [[ "$r" == "dismissed=False locked-after=False" ]] && ok "a prompted unlock with the password worked" \
        || bad "prompted unlock: $r"
    r="$(gk ctl change @password @password)"
    [[ "$r" == OK ]] && ok "nothing was recorded: still keyed to the password after it" \
        || bad "the keyring changed key after the prompt: CHANGE(password,password) $r"
    r="$(gk ctl change @token @token)"
    [[ "$r" == DENIED ]] && ok "the token opens nothing" || bad "CHANGE(token,token): $r"
    check_clean
}

case_no-initializer() {
    # Nothing ever initializes the --login daemon (a Plasma session).
    begin_case no-initializer 5 || return 1
    seed token || return 1
    start_login password || return 1
    helper_fg 3
    helper_done 10
    expect_exit 3 "gave up"
    expect_log "not initialized within 3 s"
    name_is org.gnome.keyring not-owned && ok "org.gnome.keyring never activated" \
        || bad "org.gnome.keyring has an owner"
    name_is org.freedesktop.secrets not-owned && ok "org.freedesktop.secrets never activated" \
        || bad "org.freedesktop.secrets has an owner"
    if grep -aq 'Activating service' "$DIR/dbus.log"; then
        bad "something was activated: $(grep -a 'Activating service' "$DIR/dbus.log" | head -1)"
    else
        ok "nothing was activated"
    fi
    check_clean
}

case_socket-unit() {
    # A socket-unit distro: the daemon is initialized from the start, and
    # pam_gnome_keyring's password was refused first.
    begin_case socket-unit 5 || return 1
    seed token || return 1
    start_plain || return 1
    local r
    r="$(gk ctl unlock @password)"
    note "pam_gnome_keyring-style UNLOCK(password): $r"
    helper_fg 30
    helper_done 5
    expect_exit 0 delivered
    local ms
    ms="$(sed -nE 's/.*token delivered ([0-9]+) ms.*/\1/p' "$DIR/helper.err")"
    [[ -n "$ms" ]] && ((ms < 1000)) && ok "delivered at once (${ms} ms)" || bad "delivery took '${ms}' ms"
    [[ "$(prompts)" == 0 ]] && ok "no unlock prompt" || bad "$(prompts) unlock prompt(s)"
    check_delivered
}

case_socket-activated() {
    # A socket-activated control socket: pam_gnome_keyring's own connection
    # starts the daemon while the helper waits. Records which of the two
    # requests gnome-keyring handled first: a password refused after the
    # token's success stays recorded, and the next prompted unlock then
    # re-keys the keyring to that password.
    begin_case socket-activated 5 token || return 1
    seed token || return 1
    mkdir -p "$XDG_RUNTIME_DIR/keyring"
    chmod 700 "$XDG_RUNTIME_DIR/keyring"
    # systemd-socket-activate passes on only the variables named with -E.
    systemd-socket-activate -l "$XDG_RUNTIME_DIR/keyring/control" \
        -E HOME -E XDG_RUNTIME_DIR -E XDG_DATA_HOME -E XDG_CONFIG_HOME -E XDG_CACHE_HOME \
        -E DBUS_SESSION_BUS_ADDRESS -E DBUS_SYSTEM_BUS_ADDRESS -E GNOME_KEYRING_TEST_PROMPTER \
        gnome-keyring-daemon --foreground --components=pkcs11,secrets \
        --control-directory="$XDG_RUNTIME_DIR/keyring" >>"$DIR/gkr.log" 2>&1 &
    GKR=$!
    PIDS+=("$GKR")
    wait_for "the activation socket" 5 control_up || return 1
    helper_fg 30
    sleep 1
    local r
    r="$(gk ctl unlock @password)"
    note "pam_gnome_keyring-style UNLOCK(password), which starts the daemon: $r"
    helper_done 20
    expect_exit 0 delivered
    [[ "$(prompts)" == 0 ]] && ok "no unlock prompt" || bad "$(prompts) unlock prompt(s)"
    check_delivered
    r="$(gk prompt-unlock)"
    if [[ "$r" != "dismissed=False locked-after=False" ]]; then
        bad "prompted unlock with the token: $r"
    elif [[ "$(gk ctl change @password @password)" == OK ]]; then
        note "order: pam_gnome_keyring's password was refused after the waiter's UNLOCK(token); it stayed recorded, and a prompted unlock re-keyed the keyring to it"
    elif [[ "$(gk ctl change @token @token)" == OK ]]; then
        note "order: pam_gnome_keyring's password was refused before the waiter's UNLOCK(token); nothing stayed recorded, and after a prompted unlock the keyring is still keyed to the token"
    else
        bad "after the prompted unlock the keyring opens with neither secret"
    fi
}

case_fake-owner() {
    # Another process claims org.gnome.keyring and even reports the right
    # control directory; the control socket's listener is the real daemon.
    begin_case fake-owner 5 || return 1
    seed token || return 1
    start_login password || return 1
    python3 "$ROOT/gk.py" fake-owner "$(realpath "$XDG_RUNTIME_DIR/keyring")" 8 "$DIR/fake.count" \
        >"$DIR/fake.out" 2>&1 &
    PIDS+=("$!")
    wait_for "the fake owner" 5 name_is org.gnome.keyring owned || return 1
    helper_fg 4
    helper_done 10
    expect_exit 3 "gave up"
    expect_log "does not match this user's control socket"
    local n
    n="$(cat "$DIR/fake.count" 2>/dev/null)"
    [[ "${n:-0}" -ge 1 ]] && ok "the helper asked the fake for its control directory" \
        || bad "the helper never asked the fake owner"
    [[ "$(grep -c 'does not match' "$DIR/helper.err")" == 1 ]] && ok "the mismatch was logged once" \
        || bad "mismatch lines: $(grep -c 'does not match' "$DIR/helper.err")"
    check_clean
}

case_prebound() {
    # Another process holds the control socket's path when the real daemon
    # is initialized; the real daemon keeps its socket under another name.
    begin_case prebound 5 || return 1
    seed token || return 1
    start_login password || return 1
    local sock="$XDG_RUNTIME_DIR/keyring/control"
    mv "$sock" "$sock.real"
    python3 "$ROOT/gk.py" fake-listener "$sock" 10 "$DIR/listener.count" >"$DIR/listener.out" 2>&1 &
    PIDS+=("$!")
    wait_for "the fake listener" 5 control_up || return 1
    helper_fg 5
    sleep 0.5
    local r
    r="$(CHECK_CONTROL="$sock.real" gk init secrets)"
    note "INITIALIZE sent to the real daemon: $r"
    helper_done 10
    expect_exit 3 "gave up"
    expect_log "does not match this user's control socket"
    local count
    count="$(cat "$DIR/listener.count" 2>/dev/null)"
    [[ "${count#* }" == 0 ]] && ok "the other listener received nothing (connections, bytes: ${count})" \
        || bad "the other listener received data (connections, bytes: ${count:-none})"
    r="$(gk locked)"
    [[ "$r" == locked ]] && ok "the real keyring stayed locked" || bad "login collection: $r"
    check_clean
}

case_no-login-keyring() {
    begin_case no-login-keyring 5 || return 1
    seed token || return 1
    rm "$XDG_DATA_HOME/keyrings/login.keyring"
    start_login password || return 1
    helper_fg 5
    helper_done 5
    expect_exit 1 refused
    expect_log "refusing to UNLOCK"
    [[ -e "$XDG_DATA_HOME/keyrings/login.keyring" ]] && bad "a login keyring was created" \
        || ok "no login keyring was created"
    check_clean
}

case_sigterm() {
    begin_case sigterm 5 || return 1
    seed token || return 1
    start_login password || return 1
    helper_fg 60
    sleep 1
    kill -TERM "$HP"
    helper_done 3
    expect_exit 3 "stopped"
    expect_log "stopped by a signal"
    check_clean
}

case_baseline() {
    # Today's Fedora 44 GNOME without the helper: the client is prompted and
    # gets nothing. This proves the harness can see a prompt at all.
    begin_case baseline 5 || return 1
    seed token || return 1
    start_login password || return 1
    sleep 1.2
    local got
    got="$(client)"
    [[ "$got" == missing ]] && ok "without the helper the client got nothing" || bad "the client got the canary"
    local p
    p="$(prompts)"
    ((p >= 1)) && ok "without the helper the client was prompted ($p)" || bad "no prompt was seen: the harness cannot see prompts"
    local r
    r="$(gk locked)"
    [[ "$r" == locked ]] && ok "the login collection stayed locked" || bad "login collection: $r"
}

# ---------------------------------------------------------------- run
echo "irlume GNOME keyring waiter check: $HELPER"
echo "gnome-keyring: $(gnome-keyring-daemon --version 2>/dev/null | tr '\n' ' ')"
passed=0
failed=()
for c in "${SELECTED[@]}"; do
    if ( "case_$c" ) </dev/null; then
        passed=$((passed + 1))
    else
        failed+=("$c")
    fi
done
echo
echo "cases passed: $passed   failed: ${#failed[@]}${failed:+ (${failed[*]})}"
((${#failed[@]} == 0))
