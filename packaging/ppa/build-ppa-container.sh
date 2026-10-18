#!/usr/bin/env bash
# Build the Ubuntu PPA SOURCE package for irlume in a container, so the PPA lane
# does not depend on a dedicated Ubuntu build box. Companion to
# scripts/build-ppa-source.sh (which this runs inside ubuntu:26.04/resolute) and
# to packaging/debian/build-deb-container.sh (the same idea for the .deb).
#
# What it does, from any box with podman (or docker) + a checkout:
#   1. git-archive the release tag to a CLEAN tree (no .git worktree, no LFS
#      pointer/host-path surprises), and overlay the real model weights.
#   2. Run scripts/build-ppa-source.sh inside the container with a fixed
#      SOURCE_DATE_EPOCH (the tag's commit date) for a deterministic orig.
#   3. Copy the UNSIGNED source artifacts out for host signing.
#
# The build is NOT signed here (the container never sees the GPG key) and the
# result is NOT byte-reproducible against a native Ubuntu build (gzip/cargo
# vendor differ between environments), so upload from ONE route per release.
#
# After this, on the host (where the release key lives):
#   debsign -k <fpr> <out>/irlume_<ver>-0ppa1~<series>1_source.changes   # your passphrase
#   # then upload (dput has no Fedora package, so a container works there too):
#   podman run --rm --network=host -v "<out>:/pkg:z" -w /pkg ubuntu:26.04 bash -euc '
#     apt-get update -qq && apt-get install -y -qq dput gnupg ca-certificates openssh-client
#     gpg --import /pkg/release-key.asc   # else dput sig-verify fails "No public key"
#     dput ppa:archledger/irlume irlume_<ver>-0ppa1~<series>1_source.changes'
#   # then confirm it actually PUBLISHED -- dput only reports that Launchpad
#   # accepted the upload, and the build and binary publication after it are
#   # both silent (0.6.1 was accepted, failed to build, and left Ubuntu users
#   # on 0.6.0 for four days):
#   python3 scripts/verify-ppa-publish.py
set -euo pipefail

# resolute (26.04) is the PPA target series; digest-pinned for a reproducible
# toolchain, overridable for dev. Bump the digest deliberately (tag: ubuntu:26.04).
BASE="${BASE:-docker.io/library/ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb}"
SERIES="${SERIES:-resolute}"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${OUT:-$REPO/ppa-out}"
VERSION="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$REPO/Cargo.toml" | head -1)"
TAG="v${VERSION}"

# podman (rootless, the original route) or docker; CONTAINER overrides.
ENGINE="${CONTAINER:-$(command -v podman || command -v docker || true)}"
[ -n "$ENGINE" ] || { echo "need podman or docker"; exit 1; }
git -C "$REPO" rev-parse "$TAG" >/dev/null 2>&1 || { echo "no git tag $TAG in $REPO"; exit 1; }

# Models are release assets (not Git LFS); fetch + verify them so the orig
# tarball carries real weights.
bash "$REPO/scripts/fetch-models.sh"

# Deterministic mtime for the orig tarball: the tag's commit date, same value a
# native build derives, so re-runs on the same host are byte-identical.
SDE="$(git -C "$REPO" log -1 --format=%ct "$TAG")"

WORK="$(mktemp -d)"
# The container's build script is this checkout's, not the tag's: a tag made
# before packaging/ppa/container-build.sh existed (v0.15.0 and older) has none,
# and the build script it runs, scripts/build-ppa-source.sh, is still the
# tag's. Outside $WORK, so it is not packed into the orig tarball.
HELPER="$(mktemp -d)"
cp "$REPO/packaging/ppa/container-build.sh" "$HELPER/"
# The build root, mounted at /out: outside $WORK, so an older tag's
# build-ppa-source.sh never copies it into itself.
BUILD="$(mktemp -d)"
# Rootless podman writes into the mount as a mapped subuid; clean via unshare so
# leftovers from a prior run can't poison this one, and reclaim ownership after.
cleanup() {
  podman unshare rm -rf "$WORK" "$BUILD" 2>/dev/null || rm -rf "$WORK" "$BUILD" 2>/dev/null || true
  rm -rf "$HELPER"
}
# Rootful docker runs the build as the real root: hand the files back at the
# end. Rootless podman's and rootless docker's root already is this user (a
# chown to this uid would map to a subuid). The runtime is asked what it is:
# podman-docker installs a `docker` command that runs podman, and docker info
# lists rootless mode among its security options.
OWNER_ENV=()
case "$("$ENGINE" --version 2>/dev/null)" in
  *[Pp]odman*) ;;
  *)
    case "$("$ENGINE" info --format '{{json .SecurityOptions}}' 2>/dev/null)" in
      *rootless*) ;;
      *) OWNER_ENV=(-e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)") ;;
    esac
    ;;
esac
trap cleanup EXIT

echo "==> exporting $TAG (git archive) + real models into a clean tree"
git -C "$REPO" archive --format=tar "$TAG" | tar -x -C "$WORK"
cp "$REPO"/models/*.onnx "$WORK/models/"

echo "==> building PPA source in $BASE (SERIES=$SERIES, SOURCE_DATE_EPOCH=$SDE)"
"$ENGINE" run --rm \
  -v "$WORK:/work:z" -v "$BUILD:/out:z" -v "$HELPER:/helper:ro,z" \
  -e "SOURCE_DATE_EPOCH=$SDE" -e "SERIES=$SERIES" -e "PPAREV=${PPAREV:-0ppa1}" \
  "${OWNER_ENV[@]}" \
  "$BASE" bash /helper/container-build.sh

# Reclaim the subuid-owned artifacts to the host user (rootless podman),
# then copy them out.
podman unshare chown -R 0:0 "$BUILD" 2>/dev/null || true
mkdir -p "$OUT"
cp "$BUILD"/irlume_"${VERSION}"* "$OUT"/
cp "$REPO/.github/release-signing-key.asc" "$OUT/release-key.asc"

echo
echo "==> unsigned source package in $OUT/"
ls -1 "$OUT"/irlume_"${VERSION}"*
echo
echo "Next (on this host, where the release key lives):"
echo "  debsign -k <fingerprint> $OUT/irlume_${VERSION}-0ppa1~${SERIES}1_source.changes"
echo "  # then dput (see the header of this script for the container upload one-liner)"
echo "  python3 $REPO/scripts/verify-ppa-publish.py ${VERSION}"
echo
echo "The upload is not the release: dput reports only that Launchpad accepted"
echo "it, and the build and binary publication after it are silent. The lane is"
echo "done when verify-ppa-publish.py exits 0."
