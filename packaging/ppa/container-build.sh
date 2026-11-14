#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Build the PPA source package inside the Ubuntu container, from the tree at
# /work (a git archive of the commit being packaged, never a checkout with
# .git). Shared by packaging/ppa/build-ppa-container.sh (a release, which
# mounts its checkout's copy at /helper, since older tags have none) and
# scripts/ppa-nightly.py (the nightly channel, ADR-0037, from the tree it
# builds): both run this script in the same digest-pinned image, so a nightly
# is built the way a release is.
#
# Environment (all passed through by the callers):
#   SERIES, PPAREV, SOURCE_DATE_EPOCH    as scripts/build-ppa-source.sh takes them
#   PPA_VERSION, PPA_CHANGELOG, PPA_NAME  a nightly's version, changelog entry
#                                        and target PPA
#   RUST_VER                             overrides the pinned Rust toolchain
#                                        (build-ppa-container.sh and
#                                        scripts/ppa-nightly.py pass it through
#                                        when it is set in their environment)
#   HOST_UID, HOST_GID                   when set (rootful docker), the files
#                                        are handed back to that owner at the end
# Mounts: /work the tree, /out the build root (empty, outside the tree).
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive HOME=/work CARGO_HOME=/work/.cargo-home
apt-get update -qq >/dev/null
# debhelper (debhelper-compat 13) + linux-libc-dev are Build-Depends the
# bare image lacks; without them dpkg-checkbuilddeps aborts the source build.
apt-get install -y -qq --no-install-recommends \
  ca-certificates curl rsync git xz-utils \
  build-essential dpkg-dev debhelper devscripts fakeroot linux-libc-dev \
  cargo rustc pkg-config clang libclang-dev libtss2-dev libpam0g-dev libudev-dev libdbus-1-dev dbus-daemon \
  cmake extra-cmake-modules qt6-base-dev qt6-declarative-dev \
  libkf6kcmutils-dev libkf6coreaddons-dev libkf6kio-dev >/dev/null
cd /work
# Pinned Rust toolchain, the same version the universal .deb lane pins
# (packaging/debian/build-deb-container.sh): the build in here must not
# depend on what the Ubuntu archive served at build time. The archive's
# cargo/rustc installed above only satisfy the source package's
# Build-Depends gate, which Launchpad's own builders re-check on their
# side. The installer is a lane input like any other: pinned by version
# and verified against its published checksum before it runs (the
# unpinned sh.rustup.rs pipe is what this replaces). --no-modify-path
# keeps rustup from writing an rc file into HOME (=/work), which the
# staging rsync below would otherwise ship inside the orig tarball; the
# toolchain itself lives under /opt, outside /work, for the same reason.
RUST_VER="${RUST_VER:-1.88.0}"   # >= ort's MSRV (edition 2024)
RUSTUP_VER=1.29.3
RUSTUP_SHA256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
export RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo
curl -fsSL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VER}/x86_64-unknown-linux-gnu/rustup-init" -o /tmp/rustup-init \
  || { echo "rustup-init download failed"; exit 1; }
echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - \
  || { echo "rustup-init failed sha256 check; refusing."; exit 1; }
chmod +x /tmp/rustup-init
/tmp/rustup-init -y --default-toolchain "$RUST_VER" --profile minimal --no-modify-path >/dev/null
export PATH="/opt/cargo/bin:$PATH"
export CARGO_HOME=/work/.cargo-home
# The build root is a mount of its own, outside the tree build-ppa-source.sh
# stages from: that script copies the tree with rsync, and a tag's copy older
# than its in-tree exclusion (v0.15.0 and before) would copy a build root
# inside /work into itself until the disk filled.
export BUILDROOT=/out
status=0
bash scripts/build-ppa-source.sh || status=$?
if [ -n "${HOST_UID:-}" ]; then
  chown -R "${HOST_UID}:${HOST_GID:-$HOST_UID}" /work /out
fi
exit "$status"
