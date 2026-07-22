#!/usr/bin/env bash
# Build the Ubuntu PPA SOURCE package for irlume in a container, so the PPA lane
# does not depend on a dedicated Ubuntu build box. Companion to
# scripts/build-ppa-source.sh (which this runs inside ubuntu:26.04/resolute) and
# to packaging/debian/build-deb-container.sh (the same idea for the .deb).
#
# What it does, from any box with podman + a real LFS checkout:
#   1. git-archive the release tag to a CLEAN tree (no .git worktree, no LFS
#      pointer/host-path surprises), and overlay the real model weights.
#   2. Run scripts/build-ppa-source.sh inside the container with a fixed
#      SOURCE_DATE_EPOCH (the tag's commit date) for a deterministic orig.
#   3. Copy the UNSIGNED source artifacts out for host signing.
#
# The build is NOT signed here (the container never sees the GPG key) and the
# result is NOT byte-reproducible against a native Ubuntu build — gzip/cargo
# vendor differ between environments — so upload from ONE route per release.
#
# After this, on the host (where the release key lives):
#   debsign -k <fpr> <out>/irlume_<ver>-0ppa1~<series>1_source.changes   # your passphrase
#   # then upload (dput has no Fedora package, so a container works there too):
#   podman run --rm --network=host -v "<out>:/pkg:z" -w /pkg ubuntu:26.04 bash -euc '
#     apt-get update -qq && apt-get install -y -qq dput gnupg ca-certificates openssh-client
#     gpg --import /pkg/release-key.asc   # else dput sig-verify fails "No public key"
#     dput ppa:archledger/irlume irlume_<ver>-0ppa1~<series>1_source.changes'
set -euo pipefail

# resolute (26.04) is the PPA target series; digest-pinned for a reproducible
# toolchain, overridable for dev. Bump the digest deliberately (tag: ubuntu:26.04).
BASE="${BASE:-docker.io/library/ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb}"
SERIES="${SERIES:-resolute}"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${OUT:-$REPO/ppa-out}"
VERSION="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$REPO/Cargo.toml" | head -1)"
TAG="v${VERSION}"

command -v podman >/dev/null || { echo "need podman"; exit 1; }
git -C "$REPO" rev-parse "$TAG" >/dev/null 2>&1 || { echo "no git tag $TAG in $REPO"; exit 1; }

# Models must be real weights (they ride in the orig tarball), not LFS pointers.
for m in "$REPO"/models/*.onnx; do
    if [ "$(stat -c%s "$m")" -lt 1000000 ] && grep -q git-lfs "$m" 2>/dev/null; then
        echo "$m is an LFS pointer; run: git lfs pull"; exit 1
    fi
done

# Deterministic mtime for the orig tarball: the tag's commit date, same value a
# native build derives, so re-runs on the same host are byte-identical.
SDE="$(git -C "$REPO" log -1 --format=%ct "$TAG")"

WORK="$(mktemp -d)"
# Rootless podman writes into the mount as a mapped subuid; clean via unshare so
# leftovers from a prior run can't poison this one, and reclaim ownership after.
cleanup() { podman unshare rm -rf "$WORK" 2>/dev/null || rm -rf "$WORK" 2>/dev/null || true; }
trap cleanup EXIT

echo "==> exporting $TAG (git archive) + real models into a clean tree"
git -C "$REPO" archive --format=tar "$TAG" | tar -x -C "$WORK"
cp "$REPO"/models/*.onnx "$WORK/models/"

echo "==> building PPA source in $BASE (SERIES=$SERIES, SOURCE_DATE_EPOCH=$SDE)"
podman run --rm \
  -v "$WORK:/work:z" \
  -e "SOURCE_DATE_EPOCH=$SDE" -e "SERIES=$SERIES" \
  "$BASE" bash -euc '
    export DEBIAN_FRONTEND=noninteractive HOME=/work CARGO_HOME=/work/.cargo-home
    apt-get update -qq >/dev/null
    # debhelper (debhelper-compat 13) + linux-libc-dev are Build-Depends the
    # bare image lacks; without them dpkg-checkbuilddeps aborts the source build.
    apt-get install -y -qq --no-install-recommends \
      ca-certificates curl rsync git xz-utils \
      build-essential dpkg-dev debhelper devscripts fakeroot linux-libc-dev \
      cargo rustc pkg-config clang libclang-dev libtss2-dev libpam0g-dev >/dev/null
    cd /work
    export BUILDROOT=/work/ppa-build
    bash scripts/build-ppa-source.sh
  '

# Reclaim the subuid-owned artifacts to the host user, then copy them out.
podman unshare chown -R 0:0 "$WORK/ppa-build" 2>/dev/null || true
mkdir -p "$OUT"
cp "$WORK"/ppa-build/irlume_"${VERSION}"* "$OUT"/
cp "$REPO/.github/release-signing-key.asc" "$OUT/release-key.asc"

echo
echo "==> unsigned source package in $OUT/"
ls -1 "$OUT"/irlume_"${VERSION}"*
echo
echo "Next (on this host, where the release key lives):"
echo "  debsign -k <fingerprint> $OUT/irlume_${VERSION}-0ppa1~${SERIES}1_source.changes"
echo "  # then dput (see the header of this script for the container upload one-liner)"
