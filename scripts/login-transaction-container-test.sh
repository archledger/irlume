#!/usr/bin/env bash
# Exercise login apply / verify / rollback against a throwaway PAM tree.
#
#   podman run --rm -v "$PWD/scripts:/s:z" \
#     -v "$PWD/target/release/irlume:/work/irlume:z" fedora:44 \
#     bash -c 'touch /.irlume-throwaway && bash /s/login-transaction-container-test.sh'
#
# Runs as root INSIDE A CONTAINER and refuses to start without the throwaway
# marker, so it cannot run against a real stack. Not wired into CI: it needs a
# machine it may rewrite /etc/pam.d in, and the point is that it can only ever
# be somewhere disposable.
#
# A container has no camera, so `enable` wants nothing and would plan no writes.
# The disable path exercises the same machinery with real writes: plant a wired
# stack, then unwire it.
set -uo pipefail

B=/work/irlume
export IRLUME_STATE_DIR=/var/lib/irlume
SUDO_PAM=/etc/pam.d/sudo
pass=0
fail=0

ok() {
    pass=$((pass + 1))
    echo "  ok      $1"
}
bad() {
    fail=$((fail + 1))
    echo "  FAILED  $1"
    echo "            $2"
}
# `cond && ok || bad` also runs bad when ok fails, which is the SC2015 trap.
# Assert through these instead: the condition is a command, evaluated once.
assert() {
    local desc="$1" detail="$2"
    shift 2
    if "$@"; then ok "$desc"; else bad "$desc" "$detail"; fi
}
assert_not() {
    local desc="$1" detail="$2"
    shift 2
    if "$@"; then bad "$desc" "$detail"; else ok "$desc"; fi
}
# No python in the base image; pull one flat scalar with sed.
field() { sed -n "s/.*\"$1\":\"\?\([^,\"}]*\)\"\?.*/\1/p" | head -1; }
sum() { md5sum "$SUDO_PAM" | cut -d' ' -f1; }

if [ ! -f /.irlume-throwaway ]; then
    echo "refusing: no throwaway marker, so this may not be a disposable machine"
    exit 2
fi

echo "=== 0. plant a wired stack to unwire ==="
# sudo exists in the base image. Give it an irlume line plus the backup the
# disable path expects, which is the shape a real `login enable` leaves behind.
cp "$SUDO_PAM" "$SUDO_PAM.pre-irlume"
sed -i '1i auth       sufficient   pam_irlume.so' "$SUDO_PAM"
assert "planted a wired sudo stack" "no irlume line" grep -q pam_irlume "$SUDO_PAM"
planted=$(sum)

echo "=== 1. plan the disable (read-only) ==="
plan=$($B login plan --action disable --json)
pid=$(echo "$plan" | field plan_id)
writes=$(echo "$plan" | field writes)
assert "plan returned an id ($pid, $writes write(s))" "$plan" test -n "$pid"
assert "the plan includes a write" "$plan" test "$writes" != "0"
assert "plan wrote nothing" "sudo changed during a read-only plan" test "$(sum)" = "$planted"

echo "=== 2. a stale plan id is refused ==="
out=$($B login apply --action disable --plan-id 00000000000000000000000000000000 --json)
assert "stale plan id refused" "$out" test "$(echo "$out" | field code)" = "plan-stale"
assert "the refused apply wrote nothing" "sudo changed" test "$(sum)" = "$planted"

echo "=== 3. apply ==="
out=$($B login apply --action disable --plan-id "$pid" --json)
tx=$(echo "$out" | field transaction_id)
assert "apply returned transaction $tx" "$out" test -n "$tx"
assert_not "the irlume line is gone after disable" "still wired" grep -q pam_irlume "$SUDO_PAM"

echo "=== 4. verify reports as-applied ==="
out=$($B login verify --transaction-id "$tx" --json)
assert "verify: nothing drifted" "$out" test "$(echo "$out" | field drifted)" = "0"
assert "verify: rollback available" "$out" test "$(echo "$out" | field rollback_available)" = "true"

echo "=== 5. rollback dry run touches nothing ==="
mid=$(sum)
$B login rollback --transaction-id "$tx" --json >/dev/null 2>&1
assert "dry run changed nothing" "sudo changed" test "$(sum)" = "$mid"

echo "=== 6. rollback restores the planted stack byte for byte ==="
out=$($B login rollback --transaction-id "$tx" --apply --json)
assert "rollback reported applied" "$out" test "$(echo "$out" | field applied)" = "true"
assert "sudo restored byte for byte" "checksum moved" test "$(sum)" = "$planted"
assert "the irlume line is back" "not restored" grep -q pam_irlume "$SUDO_PAM"

echo "=== 7. drift blocks a rollback, and the admin's edit survives ==="
pid2=$($B login plan --action disable --json | field plan_id)
tx2=$($B login apply --action disable --plan-id "$pid2" --json | field transaction_id)
assert "second apply: transaction $tx2" "no id" test -n "$tx2"
echo "# an admin added this later" >>"$SUDO_PAM"
out=$($B login verify --transaction-id "$tx2" --json)
assert "verify sees the drift" "$out" test "$(echo "$out" | field drifted)" != "0"
assert "verify says rollback unavailable" "$out" test "$(echo "$out" | field rollback_available)" = "false"
out=$($B login rollback --transaction-id "$tx2" --apply --json)
assert "rollback refuses a drifted stack" "$out" test "$(echo "$out" | field code)" = "changed-since-apply"
assert "the admin's line survived the refusal" "lost" \
    grep -q "an admin added this later" "$SUDO_PAM"

echo "=== 8. a record is root-only ==="
perms=$(stat -c %a "$IRLUME_STATE_DIR/login-transactions/$tx.json" 2>/dev/null)
assert "record is 0600" "got $perms" test "$perms" = "600"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
