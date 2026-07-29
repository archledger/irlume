#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Run a test command and fail if it did not actually run the tests it selected.
#
# `cargo test <names>` and `cargo test -- --ignored <prefix>` exit 0 when the
# filter matches nothing. Renaming or deleting a test therefore does not break
# the lane that selects it by name; it silently converts that lane into a no-op
# that keeps reporting success. The hardware lanes are the worst case, because
# those tests cannot run anywhere else, so nothing else would notice them
# disappearing. It also corrupts the coverage ratchet: fewer tests run, coverage
# falls, and the floor gets lowered to accommodate a lane that stopped working.
#
# Usage:
#   scripts/run-tests-guarded.sh --min N -- <command> [args...]
#   scripts/run-tests-guarded.sh --require a,b,c [--min N] -- <command> [args...]
#   scripts/run-tests-guarded.sh --self-test
#
# --min asserts that at least N tests passed. Use it for prefix filters
# (`--ignored loopback_`) and whole-package selections, where the exact set is
# expected to grow.
#
# --require asserts that each named test appears in the run as a pass. Use it
# wherever the workflow names tests explicitly: a count alone is not enough
# there, because renaming one test while adding another keeps the total intact
# and hides the loss. The contract for those lanes is the named set, not the
# size of the set.
#
# The command runs through this script rather than the assertion being a
# separate step against a log file, so the two cannot drift apart: there is no
# way to add an invocation and forget its guard, and pipefail handling lives
# here instead of depending on every caller to remember it.
#
# The expected values are hand-maintained on purpose. Deriving them from
# `cargo test -- --list` was considered and rejected: a renamed test drops out
# of the listing and out of the run by the same amount, so a derived expectation
# would move with the damage and detect nothing. Listing through `cargo llvm-cov`
# would also run instrumented binaries and add their startup to the coverage
# profile. The numbers have value only because a human wrote them down
# separately from the test names.

set -uo pipefail

# Anchored on purpose. An unanchored match would also count a summary line that
# a test printed as part of its own output.
readonly SUMMARY_RE='^test result: ok\. [0-9]+ passed;'

usage() {
  cat >&2 <<'EOF'
usage: run-tests-guarded.sh --min N -- <command> [args...]
       run-tests-guarded.sh --require a,b,c [--min N] -- <command> [args...]
       run-tests-guarded.sh --self-test
EOF
}

# Sum the `passed` counts across every test binary in a run.
#
# A single invocation can produce several summary lines: one per test target,
# plus one for doctests. Only `ok.` summaries match; a failing binary prints
# "test result: FAILED." and is deliberately excluded, though in practice a
# non-zero exit status is reported before the count is ever consulted.
count_passed() {
  grep -E "$SUMMARY_RE" | grep -oE '[0-9]+ passed' | grep -oE '^[0-9]+' \
    | awk '{s+=$1} END {print s+0}'
}

# libtest writes one line per passing test:
#   test keyring::tests::arm_and_unseal_roundtrip ... ok
#
# The workflows pass short filter names ("arm_and_unseal_roundtrip"), which
# libtest reports under their full module path, so this matches a substring of
# the reported name rather than the whole of it.
ran_as_pass() {
  local name="$1" log="$2"
  grep -qE "^test [^ ]*${name}[^ ]* \.\.\. ok$" "$log"
}

self_test() {
  local failures=0 n=0

  # Drive the real script as a subprocess with a stand-in command, so these
  # exercise the whole path (pipefail, tee, exit status, parse), not just the
  # parser in isolation.
  expect() {
    local desc="$1" want="$2"
    shift 2
    local got
    n=$((n + 1))
    "$@" >/dev/null 2>&1
    got=$?
    if [ "$got" -eq "$want" ]; then
      printf '  ok   %s\n' "$desc"
    else
      printf '  FAIL %s (want exit %s, got %s)\n' "$desc" "$want" "$got"
      failures=$((failures + 1))
    fi
  }

  # printf is the stand-in "test command"; %s keeps each fixture verbatim.
  echo "== run-tests-guarded self-test =="
  echo "-- count mode --"

  expect "exact count meets the minimum" 0 \
    "$0" --min 6 -- printf '%s' 'test result: ok. 6 passed; 0 failed; 0 ignored'

  expect "more tests than expected still passes" 0 \
    "$0" --min 6 -- printf '%s' 'test result: ok. 9 passed; 0 failed; 0 ignored'

  expect "one test short fails" 1 \
    "$0" --min 6 -- printf '%s' 'test result: ok. 5 passed; 0 failed; 0 ignored'

  # The bug this script exists for.
  expect "zero-match filter fails instead of passing green" 1 \
    "$0" --min 6 -- printf '%s' 'running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 114 filtered out'

  expect "counts sum across several test binaries" 0 \
    "$0" --min 16 -- printf '%s' 'test result: ok. 9 passed; 0 failed
test result: ok. 7 passed; 0 failed'

  expect "a doctest summary counts toward the total" 0 \
    "$0" --min 3 -- printf '%s' 'test result: ok. 2 passed; 0 failed
   Doc-tests irlume-core
test result: ok. 1 passed; 0 failed'

  expect "no summary at all fails" 1 \
    "$0" --min 1 -- printf '%s' 'error: could not compile irlume-core'

  expect "a failed run is not counted as passes" 1 \
    "$0" --min 3 -- printf '%s' 'test result: FAILED. 3 passed; 1 failed; 0 ignored'

  expect "the running-N-tests line is not counted" 1 \
    "$0" --min 4 -- printf '%s' 'running 4 tests

test result: ok. 2 passed; 0 failed; 2 ignored'

  # A test that prints a summary-shaped line must not inflate the total. This is
  # why the pattern is anchored.
  expect "a summary line printed by a test is not counted" 1 \
    "$0" --min 6 -- printf '%s' 'stdout: test result: ok. 99 passed; 0 failed
test result: ok. 1 passed; 0 failed'

  echo "-- require mode --"

  expect "every required name ran" 0 \
    "$0" --require alpha,beta -- printf '%s' 'test m::tests::alpha ... ok
test m::tests::beta ... ok

test result: ok. 2 passed; 0 failed'

  # The case a count cannot catch: one renamed away, one added, total unchanged.
  expect "a renamed test is caught even when the total is unchanged" 1 \
    "$0" --require alpha,beta -- printf '%s' 'test m::tests::alpha ... ok
test m::tests::gamma ... ok

test result: ok. 2 passed; 0 failed'

  expect "a required test that was ignored rather than run fails" 1 \
    "$0" --require alpha,beta -- printf '%s' 'test m::tests::alpha ... ok
test m::tests::beta ... ignored

test result: ok. 1 passed; 0 failed; 1 ignored'

  expect "require implies its own minimum count" 1 \
    "$0" --require alpha,beta,gamma -- printf '%s' 'test m::tests::alpha ... ok
test m::tests::beta ... ok
test m::tests::gamma ... ok

test result: ok. 2 passed; 0 failed'

  echo "-- exit status and output --"

  # A non-zero exit from the command under test must survive, and must win over
  # the count check, so a genuine test failure is never reported as a count
  # problem.
  expect "the command's own exit status is preserved" 101 \
    "$0" --min 1 -- sh -c 'echo "test result: ok. 5 passed;"; exit 101'

  expect "a failing command reports its status, not a count error" 101 \
    "$0" --min 99 -- sh -c 'echo "test result: ok. 5 passed;"; exit 101'

  local passthrough
  passthrough="$("$0" --min 1 -- printf 'test result: ok. 1 passed;\n' 2>/dev/null)"

  n=$((n + 1))
  if printf '%s' "$passthrough" | grep -qF 'test result: ok. 1 passed;'; then
    printf '  ok   %s\n' "command output is passed through to stdout"
  else
    printf '  FAIL %s\n' "command output is passed through to stdout"
    failures=$((failures + 1))
  fi

  # The confirmation line is the only evidence in a CI log that the guard ran at
  # all. Without it, a guard someone deleted looks exactly like a passing one.
  n=$((n + 1))
  if printf '%s' "$passthrough" | grep -qF 'run-tests-guarded: 1 test(s) passed'; then
    printf '  ok   %s\n' "the observed count is reported for the log"
  else
    printf '  FAIL %s\n' "the observed count is reported for the log"
    failures=$((failures + 1))
  fi

  echo "-- argument handling --"

  expect "no arguments is a usage error" 2 "$0"
  expect "a missing -- separator is a usage error" 2 "$0" --min 1 true
  expect "an empty command after -- is a usage error" 2 "$0" --min 1 --
  expect "a non-numeric minimum is a usage error" 2 "$0" --min abc -- true
  expect "neither --min nor --require is a usage error" 2 "$0" -- true
  expect "an unknown option is a usage error" 2 "$0" --nope 1 -- true

  # A harness whose output this cannot parse must say so, rather than report
  # zero tests and look like the very bug it is guarding against.
  expect "nextest is rejected rather than silently parsed as zero" 2 \
    "$0" --min 1 -- cargo nextest run
  expect "a JSON test format is rejected" 2 \
    "$0" --min 1 -- cargo test -- --format json

  echo
  if [ "$failures" -eq 0 ]; then
    echo "self-test: $n/$n passed"
    return 0
  fi
  echo "self-test: $failures of $n FAILED"
  return 1
}

if [ "${1-}" = "--self-test" ]; then
  self_test
  exit $?
fi

expected_min=""
require_csv=""

while [ $# -gt 0 ]; do
  case "$1" in
    --min)
      [ $# -ge 2 ] || { usage; exit 2; }
      expected_min="$2"
      shift 2
      ;;
    --require)
      [ $# -ge 2 ] || { usage; exit 2; }
      require_csv="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "error: unknown option '$1'" >&2
      usage
      exit 2
      ;;
  esac
done

if [ $# -eq 0 ]; then
  echo "error: no command given (did you forget the -- separator?)" >&2
  usage
  exit 2
fi

IFS=',' read -r -a required <<< "$require_csv"
# A trailing or doubled comma would otherwise become an empty name that matches
# every line.
filtered=()
for name in ${required+"${required[@]}"}; do
  [ -n "$name" ] && filtered+=("$name")
done
required=(${filtered+"${filtered[@]}"})

if [ -z "$expected_min" ] && [ ${#required[@]} -eq 0 ]; then
  echo "error: one of --min or --require is required" >&2
  usage
  exit 2
fi

# Naming the set also fixes its size; the count check then covers the case where
# a required test somehow passes twice while another vanishes.
if [ -z "$expected_min" ]; then
  expected_min="${#required[@]}"
fi

case "$expected_min" in
  '' | *[!0-9]*)
    echo "error: --min must be a non-negative integer, got '$expected_min'" >&2
    usage
    exit 2
    ;;
esac

# This parses libtest's default human-readable output. A harness or format that
# does not produce it would yield zero and fail, which looks identical to the
# silent-no-op bug being guarded against. Refuse up front instead, so the error
# names the real cause.
for arg in "$@"; do
  case "$arg" in
    nextest)
      echo "error: nextest output is not parsed by this guard; it needs its own check" >&2
      exit 2
      ;;
    --format | --format=* | json | terse)
      echo "error: this guard requires libtest's default output format" >&2
      exit 2
      ;;
  esac
done

log="$(mktemp)"
# shellcheck disable=SC2064  # $log is expanded now on purpose; it never changes.
trap "rm -f '$log'" EXIT

# Localised output would break the anchored patterns above.
export LC_ALL=C

"$@" 2>&1 | tee "$log"
statuses=("${PIPESTATUS[@]}")
command_status="${statuses[0]}"
tee_status="${statuses[1]}"

# A real failure is reported as itself. Reporting it as a count shortfall would
# send whoever reads the log hunting for a renamed test that does not exist.
if [ "$command_status" -ne 0 ]; then
  exit "$command_status"
fi

# A truncated log (full disk, closed pipe) would under-count and produce a
# confusing count failure, so it is reported as what it is.
if [ "$tee_status" -ne 0 ]; then
  echo "::error::could not capture test output (tee exited $tee_status); guard cannot verify the run" >&2
  exit 1
fi

missing=()
for name in ${required+"${required[@]}"}; do
  ran_as_pass "$name" "$log" || missing+=("$name")
done

if [ ${#missing[@]} -gt 0 ]; then
  echo "::error::these tests were selected but did not run and pass: ${missing[*]}" >&2
  echo "A filter that matches nothing still exits 0. Check for a renamed, removed" >&2
  echo "or newly-ignored test, or update the workflow if the change is intended." >&2
  exit 1
fi

ran="$(count_passed < "$log")"

if [ "$ran" -lt "$expected_min" ]; then
  echo "::error::expected at least $expected_min tests to pass, $ran did: $*" >&2
  echo "A filter that matches nothing still exits 0. Check for a renamed, removed" >&2
  echo "or newly-ignored test, or update the expected count if the change is intended." >&2
  exit 1
fi

echo "run-tests-guarded: $ran test(s) passed (expected at least $expected_min)"
