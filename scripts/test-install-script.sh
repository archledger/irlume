#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Tests the channel scripts/install.sh chooses, without the network or root.
# Stand-ins first on PATH log what they are asked. A copy of the script reads
# a fixture for /etc/os-release, its only difference. Real gzip and grep judge
# a real gzipped index, so a check of the wrong thing still fails here.
#
#   bash scripts/test-install-script.sh
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
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
script="$root/scripts/install.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sed "s#/etc/os-release#$work/os-release#g" "$script" > "$work/install.sh"
[ "$(grep -c "$work/os-release" "$work/install.sh")" -ge 2 ] \
  || { echo "test-install-script: install.sh no longer reads /etc/os-release" >&2; exit 1; }

mkdir "$work/bin"
for tool in sh mktemp rm uname id grep gzip sed awk basename dirname cat mkdir chmod sha256sum env; do
  ln -s "$(command -v "$tool")" "$work/bin/$tool"
done

printf 'Package: irlume\n' | gzip > "$work/lists.gz"
printf 'Package: other\n' | gzip > "$work/empty.gz"
printf 'not gzip\n' > "$work/garbage"

cat > "$work/bin/curl" <<'EOF'
#!/bin/sh
# Stand-in curl: log the URL; answer the PPA index by mode, and refuse the
# release's SHA256SUMS, which ends the run at the .deb path with no download.
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
  *) exit 22 ;;
esac
EOF
for tool in add-apt-repository apt-get systemctl; do
  cat > "$work/bin/$tool" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$TEST_LOG"
EOF
done
cat > "$work/bin/dpkg-query" <<'EOF'
#!/bin/sh
exit 1
EOF
cat > "$work/bin/sudo" <<'EOF'
#!/bin/sh
exec "$@"
EOF
chmod +x "$work"/bin/curl "$work"/bin/add-apt-repository "$work"/bin/apt-get \
  "$work"/bin/systemctl "$work"/bin/dpkg-query "$work"/bin/sudo

failed=0
fail() { echo "FAIL: $1" >&2; cat "$work/log" >&2; failed=1; }

# run <os-release text> <ppa mode> <want PPA added: yes|no> <want .deb tried: yes|no> <label>
run() {
  printf '%s\n' "$1" > "$work/os-release"
  : > "$work/log"
  env -i PATH="$work/bin" HOME="$work" TERM=dumb TEST_LOG="$work/log" TEST_DIR="$work" TEST_PPA="$2" \
    sh "$work/install.sh" > "$work/out" 2>&1 || true
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

run 'ID=debian
VERSION_CODENAME=bookworm' lists no yes "Debian"
if grep -q 'Packages.gz' "$work/log"; then fail "Debian asked the PPA"; fi
run 'ID=linuxmint
ID_LIKE="ubuntu debian"
VERSION_CODENAME=virginia
UBUNTU_CODENAME=jammy' lists no yes "an Ubuntu derivative"
if grep -q 'Packages.gz' "$work/log"; then fail "a derivative asked the PPA"; fi

[ "$failed" = 0 ] || exit 1
echo "test-install-script: every channel choice held"
