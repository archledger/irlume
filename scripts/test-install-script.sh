#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Tests the channel scripts/install.sh chooses and what it prints when an
# install fails or succeeds, without the network or root. Stand-ins first on
# PATH log what they are asked. A copy of the script reads a fixture for
# /etc/os-release, its only difference. Real gzip and grep judge a real
# gzipped index, so a check of the wrong thing still fails here. Every run
# keeps its exit status, and its stdout stays empty: install.sh's own lines go
# to stderr.
#
#   bash scripts/test-install-script.sh
#
# The copy runs under the first `sh` on PATH (dash on Ubuntu, bash on Fedora);
# put a directory holding an `sh` link to another shell first on PATH to run
# it under that shell.
#
# Checked, on Ubuntu:
#   - a PPA that lists irlume for this series is added
#   - a series the PPA has no index for (HTTP 404) never gets it added: on one
#     with no Release file either, the source fails every later `apt update`
#   - an index that does not list irlume (a Release file outlives a series'
#     packages) never gets it added either
#   - when the PPA cannot answer (offline, or bytes that are not gzip), the
#     script still tries it, as an outage should not change the channel
#   - a transient HTTP 429/500/503 is the same: a server error is not proof
#     the PPA has no such series, so the script still tries it
#   - a curl that exits on an HTTP error without reporting a code never gets
#     the PPA added either: it cannot prove the series exists, and a source
#     apt cannot use outlives this script. Defensive only: known curl
#     versions report the code on -f errors, so no_code pins the contract
# Elsewhere:
#   - Debian and an Ubuntu derivative go straight to the release .deb, without
#     asking the PPA at all
# What it prints:
#   - an install that succeeds exits 0, says the machine side is ready, and
#     names no place to report a problem; neither does a run that finds
#     irlume already installed, which changes nothing and exits 0
#   - every failure exits non-zero (a die exits 1; a failing package command
#     keeps its own status, as apt-get's 100) and ends with where to report a
#     problem, once: a die at the first check (no sudo), a die (the release
#     cannot be fetched), a package command that fails under set -e with no
#     die line of the script's own (Arch's AUR helper, apt-get installing the
#     release .deb), and a die after a die in a $(...) subshell (Fedora's
#     release-RPM fallback)
#   - a missing or bad signature, a key that cannot be imported and a
#     checksum mismatch also say not to override verification and name the
#     private route themselves, and never name the override variable
#   - a daemon that is not active after the install is named with its state,
#     or as unknown when systemctl gives none (no systemd), followed by where
#     to report; the exit status stays 0
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
script="$root/scripts/install.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sed "s#/etc/os-release#$work/os-release#g" "$script" > "$work/install.sh"
[ "$(grep -c "$work/os-release" "$work/install.sh")" -ge 2 ] \
  || { echo "test-install-script: install.sh no longer reads /etc/os-release" >&2; exit 1; }
key_fp="$(sed -n 's/^KEY_FP="\([0-9A-F]\{40\}\)"$/\1/p' "$script")"
[ -n "$key_fp" ] \
  || { echo "test-install-script: install.sh no longer pins KEY_FP" >&2; exit 1; }

mkdir "$work/bin" "$work/tmp"
for tool in sh mktemp rm uname grep gzip sed awk basename dirname cat mkdir chmod sha256sum env; do
  ln -s "$(command -v "$tool")" "$work/bin/$tool"
done

printf 'Package: irlume\n' | gzip > "$work/lists.gz"
printf 'Package: other\n' | gzip > "$work/empty.gz"
printf 'not gzip\n' > "$work/garbage"

# A release: one asset per lane and the SHA256SUMS that lists them.
mkdir "$work/release"
for asset in irlume_0.99.0_amd64.deb irlume-0.99.0-1.fc44.x86_64.rpm irlume-0.99.0-1-x86_64.pkg.tar.zst; do
  printf 'stand-in %s\n' "$asset" > "$work/release/$asset"
done
(cd "$work/release" && sha256sum irlume_* irlume-*) > "$work/SHA256SUMS"

cat > "$work/bin/curl" <<'EOF'
#!/bin/sh
# Stand-in curl: log the URL; answer the PPA index by TEST_PPA, and the
# release by TEST_RELEASE: none refuses SHA256SUMS, which ends the run at the
# release lane with no download; no_sig serves SHA256SUMS and refuses its
# signature; bad_sum serves an asset that does not match SHA256SUMS; every
# other mode serves all three.
out=""
url=""
write_out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -w) write_out="$2"; shift ;;
    http*) url="$1" ;;
  esac
  shift
done
printf 'curl %s\n' "$url" >> "$TEST_LOG"
case "$url" in
  *Packages.gz)
    code=200
    status=0
    case "$TEST_PPA" in
      absent) code=404; status=22 ;;
      server_error) code=500; status=22 ;;
      unavailable) code=503; status=22 ;;
      rate_limited) code=429; status=22 ;;
      no_code) code=""; status=22 ;;
      offline) code=000; status=6 ;;
    esac
    if [ -n "$write_out" ]; then
      [ "$write_out" = '%{http_code}' ] || exit 99
      printf '%s' "$code"
    fi
    [ "$status" = 0 ] || exit "$status"
    case "$TEST_PPA" in
      lists) cat "$TEST_DIR/lists.gz" > "$out" ;;
      empty) cat "$TEST_DIR/empty.gz" > "$out" ;;
      garbage) cat "$TEST_DIR/garbage" > "$out" ;;
    esac
    ;;
  */releases/latest/download/SHA256SUMS)
    [ "$TEST_RELEASE" != none ] || exit 22
    cat "$TEST_DIR/SHA256SUMS" > "$out"
    ;;
  */releases/latest/download/SHA256SUMS.asc)
    [ "$TEST_RELEASE" != no_sig ] || exit 22
    printf 'stand-in signature\n' > "$out"
    ;;
  */releases/latest/download/irlume*)
    asset="$TEST_DIR/release/${url##*/}"
    [ -f "$asset" ] || exit 22
    if [ "$TEST_RELEASE" = bad_sum ]; then
      printf 'changed\n' > "$out"
    else
      cat "$asset" > "$out"
    fi
    ;;
  *) exit 22 ;;
esac
EOF
# Stand-in gpg: the key always imports except under no_import, and only good
# and bad_sum (whose signature is fine) report the pinned key's VALIDSIG.
cat > "$work/bin/gpg" <<'EOF'
#!/bin/sh
printf 'gpg %s\n' "$*" >> "$TEST_LOG"
case " $* " in
  *" --import "*)
    cat > /dev/null
    [ "$TEST_RELEASE" != no_import ]
    ;;
  *" --verify "*)
    case "$TEST_RELEASE" in
      good|bad_sum) printf '[GNUPG:] VALIDSIG %s\n' "$TEST_KEY_FP" ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 99 ;;
esac
EOF
cat > "$work/bin/add-apt-repository" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$TEST_LOG"
EOF
# Stand-in apt-get: under TEST_APT=fail an install exits 100, as apt-get does
# when an install fails.
cat > "$work/bin/apt-get" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$TEST_LOG"
if [ "${1:-}" = install ] && [ "$TEST_APT" = fail ]; then exit 100; fi
EOF
# Stand-in package commands that fail: Fedora's dnf (Copr and the release
# RPM alike) and Arch's AUR helper.
for tool in dnf yay; do
  cat > "$work/bin/$tool" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$TEST_LOG"
exit 1
EOF
done
# Stand-in systemctl: is-active answers by TEST_DAEMON, as systemctl does:
# the state on stdout, and a non-zero status for any state but active. On a
# system not booted with systemd (no_systemd) it prints no state, only an
# error on stderr, and exits 1.
cat > "$work/bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$TEST_LOG"
if [ "${1:-}" = is-active ]; then
  case "$TEST_DAEMON" in
    active) echo active ;;
    failed) echo failed; exit 3 ;;
    no_systemd)
      echo "System has not been booted with systemd as init system (PID 1). Can't operate." >&2
      exit 1 ;;
    *) exit 99 ;;
  esac
fi
EOF
# A user who is not root, whoever runs the test: as root, Arch would stop
# before its AUR helper.
cat > "$work/bin/id" <<'EOF'
#!/bin/sh
[ "$*" = -u ] || exit 99
echo 1000
EOF
cat > "$work/bin/dpkg-query" <<'EOF'
#!/bin/sh
exit 1
EOF
cat > "$work/bin/sudo" <<'EOF'
#!/bin/sh
exec "$@"
EOF
chmod +x "$work"/bin/curl "$work"/bin/gpg "$work"/bin/add-apt-repository "$work"/bin/apt-get \
  "$work"/bin/dnf "$work"/bin/yay "$work"/bin/systemctl "$work"/bin/id \
  "$work"/bin/dpkg-query "$work"/bin/sudo

# Where install.sh says to report a problem, as stderr shows it without colour.
security_url='https://github.com/archledger/irlume/security/advisories/new'
chooser_url='https://github.com/archledger/irlume/issues/new/choose'
block='[irlume] Security problem (a photo, video, mask or another person got in,
[irlume] face sign-in worked without your face, or face data was exposed),
[irlume] or not sure? Never post it publicly. Report it privately:
[irlume] https://github.com/archledger/irlume/security/advisories/new
[irlume] or the e-mail address in SECURITY.md.
[irlume] Anything else: https://github.com/archledger/irlume/issues/new/choose
[irlume] Your own words are fine; paste the lines above, not the sudo prompt.'

failed=0
label=""
fail() {
  echo "FAIL: $1" >&2
  { echo "--- calls"; cat "$work/log"; echo "--- stdout"; cat "$work/stdout"
    echo "--- stderr"; cat "$work/stderr"; echo "---"; } >&2
  failed=1
}

# install <os-release text> <ppa mode> [release mode] [daemon mode] [apt mode]:
# one run of the copy. Its status lands in $rc, its streams in $work/stdout and
# $work/stderr, and $work/plain holds stderr without colour.
install() {
  printf '%s\n' "$1" > "$work/os-release"
  : > "$work/log"
  rc=0
  env -i PATH="$work/bin" HOME="$work" TMPDIR="$work/tmp" TERM=dumb TEST_LOG="$work/log" TEST_DIR="$work" \
    TEST_PPA="$2" TEST_RELEASE="${3:-none}" TEST_DAEMON="${4:-active}" TEST_APT="${5:-ok}" \
    TEST_KEY_FP="$key_fp" sh "$work/install.sh" > "$work/stdout" 2> "$work/stderr" || rc=$?
  sed 's/\x1b\[[0-9;]*m//g' "$work/stderr" > "$work/plain"
  [ ! -s "$work/stdout" ] || fail "$label: wrote to stdout; install.sh writes only to stderr"
}

want_rc() { [ "$rc" = "$1" ] || fail "$label: exit status $rc, want $1"; }
want_err() { grep -qF -- "$1" "$work/plain" || fail "$label: stderr lacks: $1"; }
want_no_err() { if grep -qF -- "$1" "$work/plain"; then fail "$label: stderr has: $1"; fi; }
# want_lines <count> <text>: the number of stderr lines that hold the text.
want_lines() {
  n="$(grep -cF -- "$2" "$work/plain" || true)"
  [ "$n" = "$1" ] || fail "$label: $n stderr lines hold $2, want $1"
}
want_called() { grep -qxF -- "$1" "$work/log" || fail "$label: never called: $1"; }

# A run that ends with where to report a problem: the whole block, once, in
# order, and each URL on exactly the given number of lines (the security URL
# is on two when a verification line names it as well).
want_block() {
  want_lines "${1:-1}" "$security_url"
  want_lines 1 "$chooser_url"
  want_lines 1 'Your own words are fine; paste the lines above, not the sudo prompt.'
  # The block follows one empty [irlume] line.
  [[ $'\n'"$(cat "$work/plain")"$'\n' == *$'\n''[irlume] '$'\n'"$block"$'\n'* ]] \
    || fail "$label: stderr lacks the where-to-report lines in order"
}
want_no_block() {
  want_no_err "$security_url"
  want_no_err "$chooser_url"
  want_no_err 'Your own words are fine'
}
want_ready() {
  want_rc 0
  want_err 'installed; the irlume daemon is active. The machine side is ready.'
  want_no_err 'not active'
  want_no_block
}
# The release lane failed before it downloaded anything, at a die.
want_no_release() {
  want_rc 1
  want_err 'could not fetch SHA256SUMS from the latest release.'
  want_no_err 'Do not override verification'
  want_no_err 'The machine side is ready.'
  want_block
}
# A verification failure: its line, then the private route, in its own lines.
want_verify_failure() {
  want_rc 1
  want_err "$1"
  want_err 'Do not override verification or install the download by hand;'
  [[ $'\n'"$(cat "$work/plain")"$'\n' == *$'\n''[irlume] report it privately:'$'\n''[irlume] '"$security_url"$'\n'* ]] \
    || fail "$label: stderr lacks the private route after the verification failure"
  want_no_err 'IRLUME_INSECURE_NO_SIG'
  want_no_err 'The machine side is ready.'
  want_block 2
}

# run <os-release text> <ppa mode> <want PPA added: yes|no> <want .deb tried: yes|no> <label>
run() {
  label="$5"
  install "$1" "$2"
  added=no; grep -q '^add-apt-repository ' "$work/log" && added=yes
  deb=no; grep -q 'SHA256SUMS' "$work/log" && deb=yes
  [ "$added" = "$3" ] || fail "$5: PPA added: got $added, want $3"
  [ "$deb" = "$4" ] || fail "$5: release .deb tried: got $deb, want $4"
  if [ "$4" = yes ]; then
    # A local .deb still needs the archive's dependency lists, so the
    # machine's existing repositories are refreshed BEFORE the .deb lane
    # starts (the harness's curl refuses SHA256SUMS, which is the first
    # thing the lane fetches, so refresh-before-fetch is what is pinned).
    up=$({ grep -n '^apt-get update$' "$work/log" || true; } | head -n1 | cut -d: -f1)
    fetch=$({ grep -n 'SHA256SUMS' "$work/log" || true; } | head -n1 | cut -d: -f1)
    if [ -z "$up" ] || [ -z "$fetch" ] || [ "$up" -ge "$fetch" ]; then
      fail "$5: release .deb path must refresh apt lists before its first fetch (update=$up fetch=$fetch)"
    fi
    want_no_release
  else
    want_ready
  fi
}

ubuntu='ID=ubuntu
ID_LIKE=debian
VERSION_CODENAME=jammy'
run "$ubuntu" lists yes no "a series the PPA serves"
grep -q 'irlume/ubuntu/dists/jammy/main/binary-amd64/Packages.gz' "$work/log" \
  || fail "the index asked for is this series' binary index"
run "$ubuntu" absent no yes "a series the PPA has no index for"
run "$ubuntu" empty no yes "a series whose index does not list irlume"
run "$ubuntu" offline yes no "the PPA cannot be reached"
run "$ubuntu" server_error yes no "the PPA temporarily returns HTTP 500"
run "$ubuntu" unavailable yes no "the PPA temporarily returns HTTP 503"
run "$ubuntu" rate_limited yes no "the PPA temporarily returns HTTP 429"
run "$ubuntu" no_code no yes "a curl that reports an HTTP error but no code"
run "$ubuntu" garbage yes no "bytes that are not an index"

debian='ID=debian
VERSION_CODENAME=bookworm'
run "$debian" lists no yes "Debian"
if grep -q 'Packages.gz' "$work/log"; then fail "Debian asked the PPA"; fi
run 'ID=linuxmint
ID_LIKE="ubuntu debian"
VERSION_CODENAME=virginia
UBUNTU_CODENAME=jammy' lists no yes "an Ubuntu derivative"
if grep -q 'Packages.gz' "$work/log"; then fail "a derivative asked the PPA"; fi

label="a user who is not root, on a machine without sudo"
mv "$work/bin/sudo" "$work/sudo"
install "$debian" lists
mv "$work/sudo" "$work/bin/sudo"
want_rc 1
want_err 'need root: install sudo, or re-run this as root.'
want_block

label="irlume already installed"
cat > "$work/bin/irlume" <<'EOF'
#!/bin/sh
[ "$*" = --version ] || exit 99
echo "irlume 0.16.0"
EOF
chmod +x "$work/bin/irlume"
install "$debian" lists
rm "$work/bin/irlume"
want_rc 0
want_err 'already installed: irlume 0.16.0 via a manual install'
want_err 'Nothing was changed.'
want_no_block

label="a daemon that is not active after the install"
install "$ubuntu" lists none failed
want_rc 0
want_called 'systemctl is-active irlumed.service'
want_err 'installed, but the irlume daemon is failed, not active.'
want_err 'systemctl status irlumed.service'
want_no_err 'The machine side is ready.'
want_block

label="a system not booted with systemd"
install "$ubuntu" lists none no_systemd
want_rc 0
want_called 'systemctl is-active irlumed.service'
want_err 'installed, but the irlume daemon is unknown, not active.'
want_no_err 'System has not been booted with systemd'
want_no_err 'The machine side is ready.'
want_block

label="Arch, where the AUR helper fails with no die line of the script's own"
install 'ID=arch' lists
want_rc 1
want_called 'yay -S --noconfirm irlume'
# No die line: the exit is set -e's, after the helper's own failure.
if grep -qF $'\033[1;31m' "$work/stderr"; then fail "$label: a die line was printed"; fi
want_block

fedora='ID=fedora
VERSION_ID=44'
label="Fedora, where Copr and the release RPM both fail"
install "$fedora" lists
want_rc 1
want_called 'dnf -y copr enable archledger/irlume'
want_err 'could not fetch SHA256SUMS from the latest release.'
want_err 'no verified release RPM for fc44; the lines above say why.'
want_no_err 'Do not override verification'
want_block

label="a release without its signature"
install "$debian" lists no_sig
want_verify_failure 'SHA256SUMS.asc not found for this release.'

label="a signature that does not verify"
install "$debian" lists bad_sig
want_verify_failure "SHA256SUMS signature did NOT verify against the pinned irlume key $key_fp; refusing to install."

label="a pinned key that cannot be imported"
install "$debian" lists no_import
want_verify_failure 'could not import the pinned irlume key; cannot verify the release signature.'

label="an asset that does not match SHA256SUMS"
install "$debian" lists bad_sum
want_verify_failure 'CHECKSUM MISMATCH on irlume_0.99.0_amd64.deb; refusing to install.'

label="Fedora's release-RPM fallback, where the signature does not verify"
install "$fedora" lists bad_sig
want_verify_failure 'SHA256SUMS signature did NOT verify'
want_err 'no verified release RPM for fc44; the lines above say why.'

label="a verified release .deb"
install "$debian" lists good
want_ready
want_err 'SHA256SUMS GPG signature verified against the pinned irlume key.'
grep -q '^apt-get install -y .*/irlume_0.99.0_amd64.deb$' "$work/log" \
  || fail "$label: the verified .deb was not installed"

label="a verified release .deb that apt-get fails to install"
install "$debian" lists good active fail
want_rc 100
grep -q '^apt-get install -y .*/irlume_0.99.0_amd64.deb$' "$work/log" \
  || fail "$label: the verified .deb was not tried"
# No die line: the exit is set -e's, with apt-get's own status.
if grep -qF $'\033[1;31m' "$work/stderr"; then fail "$label: a die line was printed"; fi
want_no_err 'The machine side is ready.'
want_block

[ "$failed" = 0 ] || exit 1
echo "test-install-script: every channel choice and message held (sh is $(readlink -f "$work/bin/sh"))"
