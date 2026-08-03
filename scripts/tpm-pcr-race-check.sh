#!/usr/bin/env bash
# Reproduce TPM2_RC_PCR_CHANGED against the real TPM, and prove the retry
# added for it actually rescues an unseal.
#
#   sudo scripts/tpm-pcr-race-check.sh [N]     # N unseals per phase (default 12)
#
# How the race is produced, safely: `PolicyPCR` records the TPM's GLOBAL
# pcrUpdateCounter in the policy session, so extending ANY PCR invalidates the
# session, whether or not that PCR is bound. PCR 23 is the resettable
# application PCR; irlume binds none of {16,23} on any tier, and systemd's
# pcrlock policies do not cover them either. So hammering PCR 23 bumps the
# counter without changing a single value any live seal depends on: it can
# make an unseal RACE, and cannot make one legitimately FAIL.
#
# Reboot clears PCR 23 regardless. Nothing here writes to /var/lib/irlume: the
# seal under test is created in a temp keyring dir.
set -uo pipefail

N="${1:-12}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/target/release/examples/pcr_race_probe"
DIR="$(mktemp -d "${TMPDIR:-/tmp}/irlume-pcrrace-XXXXXX")"
trap 'rm -rf "$DIR"; pkill -P $$ 2>/dev/null' EXIT

command -v tpm2_pcrextend >/dev/null || { echo "SKIP: tpm2-tools not installed (need tpm2_pcrextend)"; exit 0; }
[[ -e /dev/tpmrm0 || -n "${IRLUME_TCTI:-}" ]] || { echo "SKIP: no TPM"; exit 0; }

[[ -x "$BIN" ]] || { echo "missing $BIN; cargo build --release -p irlume-core --example pcr_race_probe" >&2; exit 2; }

# Read one counter out of a probe run, or abort.
#
# An absent `failures=` line means the probe died before it could report, and
# defaulting that to 0 prints a full-marks score for a run that never touched
# the TPM. It did exactly that once: the invoking user was not in the `tss`
# group, every unseal failed with EACCES, and this script said 12/12.
counter_or_die() {  # counter_or_die <log> <name>
    local v
    v="$(sed -n "s/.*$2=\([0-9]*\).*/\1/p" "$1" | tail -1)"
    if [[ -z "$v" ]]; then
        echo "   ABORT: the probe never reported '$2='; it did not complete. Last lines:" >&2
        tail -4 "$1" >&2
        exit 4
    fi
    printf '%s' "$v"
}

echo "== guard: nothing irlume seals may bind PCR 16 or 23"
# Read the LIVE envelopes, because those are what an extend could break. The
# directory is root-only, so a non-root run cannot see them; treating that as
# "no envelopes bind 23" would be a guard that passes precisely when it cannot
# do its job.
KEYRING_DIR=/var/lib/irlume/keyring
if [[ ! -r "$KEYRING_DIR" && -d "$KEYRING_DIR" ]]; then
    echo "   ABORT: $KEYRING_DIR is not readable by this user, so the guard cannot"
    echo "   confirm no live seal binds PCR 16/23. Re-run with sudo."
    exit 2
fi
LIVE_PCRS=""
if [[ -d "$KEYRING_DIR" ]]; then
    LIVE_PCRS="$(for f in "$KEYRING_DIR"/*.json; do
        [[ -e "$f" ]] || continue
        python3 -c "import json,sys;print(*json.load(open(sys.argv[1])).get('pcrs',[]))" "$f" \
            || { echo "   ABORT: could not parse $f" >&2; exit 2; }
    done | tr ' ' '\n' | sort -un | tr '\n' ' ')" || exit 2
fi
echo "   PCRs bound by live envelopes: ${LIVE_PCRS:-<none armed>}"
for p in $LIVE_PCRS; do
    if [[ "$p" == "16" || "$p" == "23" ]]; then
        echo "   REFUSING: a live envelope binds PCR $p; extending it would BREAK that seal"
        exit 2
    fi
done

echo "== phase 1: baseline, no interference"
IRLUME_KEYRING_DIR="$DIR/kr" "$BIN" "$N" >"$DIR/clean.log" 2>&1
CLEAN_FAIL="$(counter_or_die "$DIR/clean.log" failures)"
echo "   $((N-CLEAN_FAIL))/$N unseals succeeded with nothing extending PCRs"
if [[ "$CLEAN_FAIL" -ne 0 ]]; then
    echo "   ABORT: the baseline already fails, so phase 2 would measure nothing:"
    grep -E 'failed|ERROR' "$DIR/clean.log" | tail -3
    exit 1
fi

echo "== phase 2: extend PCR 23 continuously while unsealing"
( while :; do tpm2_pcrextend 23:sha256=$(head -c32 /dev/urandom | sha256sum | cut -d' ' -f1) >/dev/null 2>&1; done ) &
EXTENDER=$!
IRLUME_KEYRING_DIR="$DIR/kr" "$BIN" "$N" >"$DIR/race.log" 2>&1
kill "$EXTENDER" 2>/dev/null; wait "$EXTENDER" 2>/dev/null
RACE_FAIL="$(counter_or_die "$DIR/race.log" failures)"
WRONG="$(counter_or_die "$DIR/race.log" wrong_bytes)"
echo "   $((N-RACE_FAIL))/$N unseals succeeded while PCR 23 was being extended"
[[ "$WRONG" -eq 0 ]] || { echo "   FAIL: ${WRONG} unseal(s) returned the WRONG bytes"; exit 1; }

RETRIED="$(grep -c 'retrying unseal' "$DIR/race.log" 2>/dev/null)"
echo "   retries logged: ${RETRIED:-0}"

echo
echo "== verdict"
if [[ "${RETRIED:-0}" -eq 0 ]]; then
    echo "   INCONCLUSIVE: the race never fired, so the retry was never exercised."
    echo "   The window is narrow; re-run with a larger N (e.g. 60)."
    exit 3
fi
if [[ "$RACE_FAIL" -eq 0 ]]; then
    echo "   PASS: the race fired ${RETRIED} time(s) and EVERY unseal still succeeded."
    echo "   Before this fix each of those would have been a keyring password prompt."
else
    echo "   FAIL: $RACE_FAIL of $N unseals still failed despite the retry:"
    grep -E 'PCR have changed|pcr-update-counter-moved' "$DIR/race.log" | tail -3
    exit 1
fi

