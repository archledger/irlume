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

echo "=== 8. an edit between plan and apply is refused ==="
# The defect this guards: a plan id built from outcome LABELS alone is unchanged
# when an admin rewrites a stack but leaves the anchor in place, so apply would
# overwrite a stack the consumer was never shown.
cp "$SUDO_PAM" "$SUDO_PAM.pre-irlume" 2>/dev/null
grep -q pam_irlume "$SUDO_PAM" || sed -i '1i auth       sufficient   pam_irlume.so' "$SUDO_PAM"
pid3=$($B login plan --action disable --json | field plan_id)
echo "# admin edit after the plan was shown" >>"$SUDO_PAM"
out=$($B login apply --action disable --plan-id "$pid3" --json)
assert "an edit after the plan makes it stale" "$out" test "$(echo "$out" | field code)" = "plan-stale"
assert "the admin's edit survived" "overwritten" grep -q "admin edit after the plan was shown" "$SUDO_PAM"
assert "the stack was not rewritten" "rewritten" grep -q pam_irlume "$SUDO_PAM"

echo "=== 9. a record is root-only ==="
perms=$(stat -c %a "$IRLUME_STATE_DIR/login-transactions/$tx.json" 2>/dev/null)
assert "record is 0600" "got $perms" test "$perms" = "600"

echo "=== 10. confirming a record replaces it rather than emptying it ==="
# A transaction is saved twice: Prepared before the first PAM write, Applied
# after. `save` used to truncate the record in place, so the second save emptied
# the only description of the previous PAM contents and then wrote into it; a
# failure in that window left a rewritten machine with nothing to roll back
# from. It now writes a temp beside the record and renames, so what survives on
# the real store path is checked here: every record is complete, and no temp is
# left behind for a later read to find.
store="$IRLUME_STATE_DIR/login-transactions"
strays=$(find "$store" -type f ! -name '*.json' 2>/dev/null | wc -l)
assert "no temp files left in the store" "found $strays" test "$strays" -eq 0
for r in "$store"/*.json; do
    assert "record $(basename "$r") is not empty" "zero bytes" test -s "$r"
    assert "record $(basename "$r") ends as complete JSON" "truncated" \
        grep -q '}$' "$r"
done

echo "=== 11. concurrent writers cannot interleave into one PAM file ==="
# Nothing serialised login apply, rollback, human enable/disable and reconcile.
# write_atomic also shared ONE scratch name per service, so two processes opened
# the same inode, interleaved their bodies, and whichever renamed first published
# the mixture. Run several writers at once and require the result to be one of
# the two whole outcomes, never a blend.
$B login disable --apply >/dev/null 2>&1
for _ in 1 2 3 4 5; do
    $B login enable --with-sudo --apply >/dev/null 2>&1 &
    $B login disable --apply >/dev/null 2>&1 &
done
wait
assert "no scratch files survive the race" "leftovers in /etc/pam.d" \
    test -z "$(find /etc/pam.d -name '.*irlume*tmp*' 2>/dev/null)"
# A blended file is the failure: irlume's own line appearing more than once, or a
# truncated final line, are both signatures of two bodies in one inode.
dupes=$(grep -c pam_irlume "$SUDO_PAM" 2>/dev/null || true)
assert "sudo carries irlume's line at most once" "found $dupes" test "$dupes" -le 1
assert "sudo ends with a newline" "truncated mid-line" \
    test -z "$(tail -c 1 "$SUDO_PAM")"
assert "sudo still has its own auth stack" "lost the original body" \
    grep -qE 'auth|@include' "$SUDO_PAM"
# And the lock file itself is left behind for the next run, not deleted.
assert "the PAM lock exists after the race" "missing" test -e /run/lock/irlume-pam.lock

echo "=== 12. a stopped rollback resumes instead of refusing itself ==="
# A rollback restores surfaces one at a time. Stopping partway used to be
# unrecoverable by irlume: the surfaces already restored no longer match the
# recorded after-digest, so a re-run refused the WHOLE record as drifted and the
# operator had to reconstruct the rest from JSON by hand. Simulated here by
# noting one surface as done and checking the re-run skips it rather than
# refusing.
grep -q pam_irlume "$SUDO_PAM" || sed -i '1i auth       sufficient   pam_irlume.so' "$SUDO_PAM"
pid4=$($B login plan --action disable --json | field plan_id)
tx4=$($B login apply --action disable --plan-id "$pid4" --json | field transaction_id)
assert "apply for the resume case: $tx4" "no id" test -n "$tx4"
rec4="$IRLUME_STATE_DIR/login-transactions/$tx4.json"
# The surface whose path is the one about to drift, not merely the first in the
# record: the greeters come first and picking one of those would exclude the
# wrong surface and prove nothing.
sid=$(grep -o "{\"id\":\"[^\"]*\",\"path\":\"$SUDO_PAM\"" "$rec4" |
    sed 's/.*"id":"\([^"]*\)".*/\1/')
assert "found the surface id for $SUDO_PAM" "$rec4" test -n "$sid"
prog="$IRLUME_STATE_DIR/login-transactions/$tx4.progress"

# A surface already put back no longer matches the recorded after-digest. That
# is what made a stopped rollback unfinishable: WITHOUT a progress note the
# re-run refuses the whole record as drifted.
echo "# this surface was already restored by the run that stopped" >>"$SUDO_PAM"
rm -f "$prog"
out=$($B login rollback --transaction-id "$tx4" --apply --json)
assert "without the note, the re-run refuses the whole record" "$out" \
    test "$(echo "$out" | field code)" = "changed-since-apply"

# WITH the note, that surface is skipped and the rollback completes.
printf '["%s"]' "$sid" >"$prog"
out=$($B login rollback --transaction-id "$tx4" --apply --json)
assert "with the note, the rollback resumes and completes" "$out" \
    test "$(echo "$out" | field applied)" = "true"
assert "the already-restored surface was left as it was" "it was rewritten" \
    grep -q "already restored by the run that stopped" "$SUDO_PAM"
assert "the resume note is cleared once everything is back" "left behind" test ! -e "$prog"

echo "=== 13. an unconfirmed rollback keeps what it overwrites ==="
# --accept-unconfirmed restores before-images without checking current state,
# which is how an interrupted apply is recovered and equally how a package
# update made after the crash gets reverted. Nothing used to capture that.
# A container has no camera, so `enable` plans nothing; the disable path is what
# exercises real writes here, as in the sections above.
grep -q pam_irlume "$SUDO_PAM" || sed -i '1i auth       sufficient   pam_irlume.so' "$SUDO_PAM"
pid5=$($B login plan --action disable --json | field plan_id)
tx5=$($B login apply --action disable --plan-id "$pid5" --json | field transaction_id)
rec="$IRLUME_STATE_DIR/login-transactions/$tx5.json"
assert "apply for the unconfirmed case: $tx5" "no id" test -n "$tx5"
if [ -f "$rec" ]; then
    # Exactly what an apply killed between its two record writes leaves behind.
    sed -i 's/"status":"applied"/"status":"prepared"/' "$rec"
    echo "# a security update landed after the crash" >>"$SUDO_PAM"
    out=$($B login rollback --transaction-id "$tx5" --accept-unconfirmed --apply --json)
    snap=$(echo "$out" | field snapshot)
    assert "the rollback applied" "$out" test "$(echo "$out" | field applied)" = "true"
    assert "it reports where the copies are" "$out" test -n "$snap"
    assert "the snapshot directory exists" "$snap missing" test -d "$snap"
    assert "the overwritten edit is preserved in the snapshot" "not captured" \
        grep -rq "a security update landed after the crash" "$snap"
    assert "the snapshot is root-only" "$(stat -c %a "$snap" 2>/dev/null)" \
        test "$(stat -c %a "$snap")" = "700"
else
    bad "unconfirmed rollback setup" "no record at $rec"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
