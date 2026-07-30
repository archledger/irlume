#!/usr/bin/env bash
# Exercise the IR emitter's undo record against a throwaway state directory.
#
#   podman run --rm -v "$PWD/scripts:/s:z" \
#     -v "$PWD/target/release/irlume:/work/irlume:z" fedora:44 \
#     bash -c 'touch /.irlume-throwaway && bash /s/emitter-journal-container-test.sh'
#
# WHAT A CONTAINER CAN AND CANNOT SHOW
#
# There is no camera here, so nothing below issues a single ioctl. The parts of
# the record that a container CAN prove are the parts a person can reach without
# hardware: which records `doctor` reports and how, that the store is root-only,
# that a record for another camera is not touched, and that an unreadable store
# is reported as unchecked rather than as clean.
#
# The ordering claims — the record durable before the first SET_CUR, the attempt
# counted before the restore, the record dropped only after the control reads
# back — need a camera and are proved by the hardware run against the traced
# output of IRLUME_LOG_EMITTER_WRITES. Nothing in this file demonstrates them,
# and this file does not pretend to.
set -uo pipefail

B=/work/irlume
export IRLUME_STATE_DIR=/var/lib/irlume-journal-test
STORE="$IRLUME_STATE_DIR/ir-emitter-journal"
pass=0
fail=0
skipped=0

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

if [ ! -f /.irlume-throwaway ]; then
    echo "refusing: no throwaway marker, so this may not be a disposable machine"
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "refusing: the store is root-only, so a non-root run would prove only that"
    exit 2
fi

# The one check id this file is about. Pulled out of the JSON document rather
# than the human report, because the id is the stable contract and the prose is
# explicitly not.
#
# Matched as a whole object, and the object class is `[^{}]*` on BOTH sides of
# the id. Two earlier versions of this line were each wrong for one shape: the
# serializer emits `detail` before `id` when a detail is present and `id` first
# when there is none, so an id-first pattern missed every warn and a
# leading-`{"` pattern missed every pass. Either way the empty result read as a
# failing check rather than as the pattern finding nothing, which is the whole
# reason the state is compared against an expected value rather than tested for
# non-emptiness.
check_object() {
    "$B" doctor --json 2>/dev/null |
        grep -o '{[^{}]*"id":"emitter-undo-pending"[^{}]*}' |
        head -1
}
check_state() {
    check_object | grep -o '"state":"[a-z]*"' | cut -d'"' -f4
}

plant() {
    # $1 = filename stem, $2 = usb id, $3 = unit, $4 = selector, $5 = extra json
    mkdir -p "$STORE"
    chmod 700 "$STORE"
    cat >"$STORE/$1.json" <<EOF
{"schema_version":1,"engine_version":"0.7.2","descriptor_sha256":"$1",
 "usb_id":"$2","interface_number":2,"unit":$3,"selector":$4,"len":3,
 "original":"010301","attempted":"010302","restore_attempts":0$5}
EOF
}

rm -rf "$IRLUME_STATE_DIR"
mkdir -p "$IRLUME_STATE_DIR"

echo "=== 1. an absent store is reported clean, not unknown ==="
# A store that was never created is a machine on which setup never ran. That is
# a genuine pass, and conflating it with "could not look" would either cry wolf
# on every fresh install or hide a real pending change behind a shrug.
assert_not "no store directory exists yet" "left over from a previous run" test -d "$STORE"
state=$(check_state)
assert "doctor reports pass with no store: got '${state:-<none>}'" "expected pass" \
    test "$state" = "pass"

echo "=== 2. an empty store is reported clean ==="
# Distinct from section 1: the directory exists because a record was written and
# then resolved, which is the ordinary end state after a successful setup.
mkdir -p "$STORE"
chmod 700 "$STORE"
state=$(check_state)
assert "doctor reports pass with an empty store: got '${state:-<none>}'" "expected pass" \
    test "$state" = "pass"

echo "=== 3. a planted record is reported, with its coordinates ==="
plant 1111 "3277:0059" 14 6 ""
entry=$(check_object)
assert "doctor reports warn: got '${entry:-<none>}'" "expected a warn" \
    grep -q '"state":"warn"' <<<"$entry"
# The coordinates are the whole point: an operator has to be able to match the
# record against `lsusb` and against what the camera's descriptor publishes.
assert "the report names the camera" "$entry" grep -q '3277:0059' <<<"$entry"
assert "the report names the unit" "$entry" grep -q 'unit 14' <<<"$entry"
assert "the report names the selector" "$entry" grep -q 'selector 6' <<<"$entry"
assert "the report names the original bytes" "$entry" grep -q '010301' <<<"$entry"

echo "=== 4. doctor reads the store and writes nothing to it ==="
# `doctor` runs on machines whose operator has deliberately stopped irlume
# touching the camera. It must not resolve, rewrite or tidy a record.
before=$(md5sum "$STORE/1111.json" | cut -d' ' -f1)
"$B" doctor >/dev/null 2>&1
"$B" doctor --json >/dev/null 2>&1
after=$(md5sum "$STORE/1111.json" | cut -d' ' -f1)
assert "the record is byte-identical after two doctor runs" "$before -> $after" \
    test "$before" = "$after"
assert "no stray files appeared in the store" "unexpected entries" \
    test "$(find "$STORE" -type f | wc -l)" -eq 1

echo "=== 5. every pending camera is reported, not just the first ==="
# One file per camera exists so that a second camera's setup cannot erase the
# first camera's undo data. A report that stopped at one would hide exactly the
# case the layout was chosen for.
plant 2222 "04f2:b6d9" 12 10 ""
entry=$(check_object)
assert "the first camera is still reported" "$entry" grep -q '3277:0059' <<<"$entry"
assert "the second camera is reported too" "$entry" grep -q '04f2:b6d9' <<<"$entry"
rm -f "$STORE/2222.json"

echo "=== 6. an unparseable record is reported, never skipped ==="
# Something is pending and this build cannot read it. Skipping it would report a
# machine with an outstanding firmware change as clean.
echo 'not json at all' >"$STORE/3333.json"
entry=$(check_object)
assert "a corrupt record still produces a warn: got '${entry:-<none>}'" "expected warn" \
    grep -q '"state":"warn"' <<<"$entry"
assert "the corrupt record is named" "$entry" grep -q '3333' <<<"$entry"
rm -f "$STORE/3333.json"

echo "=== 7. a file that is not a record is ignored ==="
# The store is a directory irlume owns, but a stray editor swap file or a
# package's leftover must not be read as a pending firmware change.
echo 'scratch' >"$STORE/notes.txt"
entry=$(check_object)
assert_not "a non-json file is not counted as a record" "$entry" grep -q 'notes.txt' <<<"$entry"
rm -f "$STORE/notes.txt"

echo "=== 8. a store that cannot be listed is unknown, not clean ==="
# The failure this guards against is a clean bill of health nobody checked.
#
# Exercised by putting a regular file where the store directory belongs, which
# fails with ENOTDIR for every caller including root. The permission case is the
# one that actually happens in the field, but it cannot be provoked here: root in
# a container carries CAP_DAC_OVERRIDE and reads a 000 directory happily. Section
# 9 makes that explicit instead of leaving a section that silently proved nothing.
rm -rf "$STORE"
: >"$STORE"
state=$(check_state)
rm -f "$STORE"
mkdir -p "$STORE"
chmod 700 "$STORE"
assert "doctor reports unknown when the store cannot be listed: got '${state:-<none>}'" \
    "expected unknown" test "$state" = "unknown"

echo "=== 9. the permission case, where this process can be denied ==="
# Reported as not exercised rather than passing when the process cannot be shut
# out of its own directory. A guard that never ran is not a guard that passed.
chmod 000 "$STORE"
if ls "$STORE" >/dev/null 2>&1; then
    chmod 700 "$STORE"
    skipped=$((skipped + 1))
    echo "  NOT EXERCISED  this process reads a 000 directory (CAP_DAC_OVERRIDE);"
    echo "                 the permission path is covered by the unit tests instead"
else
    state=$(check_state)
    chmod 700 "$STORE"
    assert "doctor reports unknown on a 000 store: got '${state:-<none>}'" \
        "expected unknown" test "$state" = "unknown"
fi

echo "=== 10. the store keeps its permissions ==="
assert "the store is root-only" "$(stat -c %a "$STORE")" \
    test "$(stat -c %a "$STORE")" = "700"

echo "=== 11. resolving the last record returns the report to clean ==="
# The end state after a recovery: the record is gone and doctor stops warning.
# Without this the suite would never show the warn clearing, and a check stuck
# on warn forever would look identical to a working one.
rm -f "$STORE"/*.json
state=$(check_state)
assert "doctor reports pass once the store is emptied: got '${state:-<none>}'" \
    "expected pass" test "$state" = "pass"

rm -rf "$IRLUME_STATE_DIR"

echo
echo "$pass passed, $fail failed, $skipped not exercised"
[ "$fail" -eq 0 ]
