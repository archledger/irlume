#!/usr/bin/env bash
# Reproduce TPM2_RC_PCR_CHANGED in a software TPM and prove the retry rescues
# it. This is the reproduction hardware cannot safely give: the only PCRs that
# are safe to extend on a live machine (16 and 23) are excluded from the PCR
# update counter, so on real silicon 655 extends of PCR 23 during live unseals
# produced zero races. In swtpm any PCR may be extended freely.
#
#   scripts/tpm-pcr-race-swtpm.sh [repo-path]
#
# The seal binds PCR 7 and the extenders hammer 10 and 12: unbound, so they
# move the global counter (invalidating the open policy session) WITHOUT
# invalidating the policy. Extending a BOUND PCR instead is a permanent and
# correct failure, not a race, and an earlier version of this script did
# exactly that and reported every unseal as failed.
#
# Measured 2026-08-03 on Fedora 44 / swtpm 0.10.1, 15 unseals per arm:
#   retry enabled  -> 15/15 succeeded, 8 races rescued, 0 wrong bytes
#   retry disabled -> 12/15 FAILED, every one an unretried race
set -u
REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
PROBE="$REPO/target/release/examples/pcr_race_probe"
[[ -x "$PROBE" ]] || { echo "build: cargo build --release -p irlume-core --example pcr_race_probe"; exit 2; }

D="$(mktemp -d)"
STATE="$D/tpm"
mkdir -p "$STATE"
cleanup() { kill $(jobs -p) 2>/dev/null; [[ -n "${SWPID:-}" ]] && kill "$SWPID" 2>/dev/null; rm -rf "$D"; }
trap cleanup EXIT

swtpm_setup --tpm2 --tpmstate "$STATE" --createek --create-ek-cert --create-platform-cert --overwrite >/dev/null 2>&1
# TCP (mssim) rather than a unix socket: only libtss2-tcti-mssim.so ships here.
# Mirror CI exactly: TCP with `disconnect`, and the swtpm TCTI (which does
# exist on Fedora as /usr/lib64/libtss2-tcti-swtpm.so; an earlier attempt used
# the unix-socket form and a truncated `ls` hid the module).
PORT=$(( 30000 + RANDOM % 20000 ))
swtpm socket --tpm2 --tpmstate dir="$STATE" \
    --server type=tcp,port=$PORT,disconnect --ctrl type=tcp,port=$((PORT+1)) \
    --flags not-need-init,startup-clear >"$D/swtpm.log" 2>&1 &
SWPID=$!
for _ in $(seq 1 60); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.2; done

export IRLUME_TCTI="swtpm:host=127.0.0.1,port=$PORT"
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$PORT"
echo "swtpm up"

ctr() { tpm2_getcap properties-variable 2>/dev/null | awk '/pcrUpdateCounter/{print $2}'; }
ext() { tpm2_pcrextend "$1:sha256=$(head -c32 /dev/urandom | sha256sum | cut -d' ' -f1)" >/dev/null 2>&1; }

echo
echo "== does an extend move the PCR update counter?"
for p in 23 16 10 12; do
    a="$(ctr)"; ext "$p"; b="$(ctr)"
    if [[ -z "$a" || -z "$b" ]]; then echo "   PCR $p: counter unreadable"; continue; fi
    if [[ "$a" == "$b" ]]; then echo "   PCR $p: counter UNCHANGED ($a) -> cannot trigger the race"
    else echo "   PCR $p: counter $a -> $b  MOVED -> can trigger the race"; fi
done

echo
echo "== seal, then unseal while extending a counter-moving PCR"
# Seal to PCR 7 ONLY, and extend 10/12. Extending a BOUND PCR changes the
# value the policy commits to, which is a permanent and correct failure, not a
# race; a first attempt at this sealed to 7,10,12 and every unseal failed for
# that reason. 10 and 12 are unbound here, so they move the global counter
# (invalidating the session) without invalidating the policy.
export IRLUME_PCRS="7"
IRLUME_KEYRING_DIR="$D/kr" "$PROBE" 1 >"$D/seed.log" 2>&1
grep -E 'sealed at|rounds=' "$D/seed.log" || { echo "seed failed:"; tail -3 "$D/seed.log"; exit 1; }

for _ in 1 2 3 4; do ( while :; do ext 10; ext 12; done ) & done
sleep 0.5
IRLUME_KEYRING_DIR="$D/kr" "$PROBE" 15 >"$D/race.log" 2>&1
kill $(jobs -p) 2>/dev/null

echo "   $(grep -E 'rounds=' "$D/race.log")"
echo "   races seen (0x128): $(grep -c 'PCR have changed' "$D/race.log")"
echo "   retries logged:     $(grep -c 'retrying unseal' "$D/race.log")"
echo "   unretried races:    $(grep -c 'unretried-race' "$D/race.log")"
grep -E 'retrying unseal|unretried-race' "$D/race.log" | head -3
