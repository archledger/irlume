#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Tests scripts/fetch-ort.sh without the network. A stand-in `curl` first on
# PATH logs each call and writes a small but valid tarball with the release's
# layout. It has to be a real tarball: with other bytes a fetcher that skipped
# the digest comparison would still fail, at `tar`, and look correct here.
#
#   bash scripts/test-fetch-ort.sh
#
# Checked:
#   - a tarball whose sha256 is not the pinned one: exit 1, nothing left behind
#   - a download that fails partway: non-zero exit, nothing left behind
#   - no argument, an empty one or two: exit 2, no download
#   - a version with no pinned digest: exit 1, no download
#   - a copy of the fetcher pinned to the stand-in's digest: exit 0, it asks
#     for the pinned release, unpacks it, and replaces a directory an earlier
#     run left instead of unpacking over it
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
fetcher="$root/scripts/fetch-ort.sh"
if [ ! -f "$fetcher" ]; then
  echo "test-fetch-ort: $fetcher not found" >&2
  exit 1
fi
ver="$(sed -n 's/^PINNED_VER=\([0-9][0-9.]*\)$/\1/p' "$fetcher")"
if [ -z "$ver" ]; then
  echo "test-fetch-ort: no PINNED_VER line in $fetcher" >&2
  exit 1
fi
name="onnxruntime-linux-x64-$ver"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The stand-in release: the path CI exports as ORT_DYLIB_PATH, and nothing else.
mkdir -p "$work/src/$name/lib"
printf 'stand-in\n' > "$work/src/$name/lib/libonnxruntime.so"
tar czf "$work/fixture.tgz" -C "$work/src" "$name"
fixture_sha="$(sha256sum "$work/fixture.tgz" | cut -d' ' -f1)"

mkdir "$work/bin"
cat > "$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
# Stand-in curl: log the arguments, write the fixture to the -o target. With
# FETCH_ORT_TEST_CUT set, write half of it and fail the way curl -f does.
printf '%s\n' "$*" >> "$FETCH_ORT_TEST_LOG"
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ -z "$out" ]; then
  echo "stand-in curl: no -o target" >&2
  exit 2
fi
if [ -n "${FETCH_ORT_TEST_CUT:-}" ]; then
  head -c "$(( $(wc -c < "$FETCH_ORT_TEST_FIXTURE") / 2 ))" "$FETCH_ORT_TEST_FIXTURE" > "$out"
  exit 22
fi
cp "$FETCH_ORT_TEST_FIXTURE" "$out"
EOF
chmod +x "$work/bin/curl"
export PATH="$work/bin:$PATH"
export FETCH_ORT_TEST_FIXTURE="$work/fixture.tgz" FETCH_ORT_TEST_LOG="$work/curl.log"

failures=0
check() {
  if [ "$2" = "$3" ]; then
    printf '  ok    %s\n' "$1"
  else
    printf '  FAIL  %s: got %s, want %s\n' "$1" "$2" "$3"
    failures=$((failures + 1))
  fi
}

# run <label> <script> [args...]: run the script in a fresh directory, as CI
# does; sets $dir, $rc and $calls (how many times curl ran).
run() {
  local label="$1"
  shift
  dir="$work/case-$label"
  mkdir -p "$dir"
  : > "$FETCH_ORT_TEST_LOG"
  rc=0
  (cd "$dir" && bash "$@") > "$work/$label.out" 2>&1 || rc=$?
  calls="$(grep -c . "$FETCH_ORT_TEST_LOG" || true)"
}
left() {
  find "$dir" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//'
}

echo "== fetch-ort.sh refuses what it cannot verify =="
run mismatch "$fetcher" "$ver"
check "wrong sha256: exit status" "$rc" 1
check "wrong sha256: downloads once" "$calls" 1
check "wrong sha256: files left" "$(left)" ""

export FETCH_ORT_TEST_CUT=1
run partial "$fetcher" "$ver"
unset FETCH_ORT_TEST_CUT
check "failed download: exit status" "$rc" 22
check "failed download: files left" "$(left)" ""

run noarg "$fetcher"
check "no argument: exit status" "$rc" 2
check "no argument: downloads" "$calls" 0
run emptyarg "$fetcher" ""
check "empty argument: exit status" "$rc" 2
check "empty argument: downloads" "$calls" 0
run twoargs "$fetcher" "$ver" "$ver"
check "two arguments: exit status" "$rc" 2
check "two arguments: downloads" "$calls" 0
run unpinned "$fetcher" "0.0.1"
check "unpinned version: exit status" "$rc" 1
check "unpinned version: downloads" "$calls" 0
check "unpinned version: files left" "$(left)" ""

echo "== a verified tarball is unpacked =="
# The same script with the stand-in's digest pinned: everything the refusals
# above did not reach (the request, the rename, the unpack) runs unchanged.
sed "s/^PINNED_SHA256=[0-9a-f]\{64\}\$/PINNED_SHA256=$fixture_sha/" "$fetcher" > "$work/fetch-ort-fixture.sh"
check "fixture copy pins the stand-in digest" \
  "$(grep -c "^PINNED_SHA256=$fixture_sha\$" "$work/fetch-ort-fixture.sh" || true)" 1
mkdir -p "$work/case-verified/$name"
printf 'left by an earlier run\n' > "$work/case-verified/$name/stale"
run verified "$work/fetch-ort-fixture.sh" "$ver"
check "verified: exit status" "$rc" 0
check "verified: downloads" "$calls" 1
check "verified: requests the pinned release" \
  "$(grep -cF "https://github.com/microsoft/onnxruntime/releases/download/v$ver/$name.tgz" "$FETCH_ORT_TEST_LOG" || true)" 1
check "verified: files left" "$(left)" "$name $name.tgz"
check "verified: tarball is the downloaded one" "$(sha256sum < "$dir/$name.tgz" | cut -d' ' -f1)" "$fixture_sha"
check "verified: library unpacked" "$([ -f "$dir/$name/lib/libonnxruntime.so" ] && echo yes || echo no)" yes
check "verified: earlier directory replaced" "$([ -e "$dir/$name/stale" ] && echo kept || echo replaced)" replaced

if [ "$failures" -ne 0 ]; then
  echo "fetch-ort.sh test: $failures check(s) FAILED"
  for f in "$work"/*.out; do
    echo "--- $(basename "$f" .out)"
    cat "$f"
  done
  exit 1
fi
echo "fetch-ort.sh test: OK"
