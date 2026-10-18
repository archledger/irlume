#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Build the PPA source package inside the Ubuntu container, from the tree at
# /work (a git archive of the commit being packaged, never a checkout with
# .git). Shared by packaging/ppa/build-ppa-container.sh (a release) and
# scripts/ppa-nightly.py (the nightly channel, ADR-0037): both run this same
# script in the same digest-pinned image, so a nightly is built the way a
# release is.
#
# Environment (all passed through by the callers):
#   SERIES, PPAREV, SOURCE_DATE_EPOCH    as scripts/build-ppa-source.sh takes them
#   PPA_VERSION, PPA_CHANGELOG, PPA_NAME a nightly's version, changelog entry
#                                        and target PPA
#   HOST_UID, HOST_GID                   when set (docker), the artifacts are
#                                        handed back to that owner at the end
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
export BUILDROOT=/work/ppa-build
status=0
bash scripts/build-ppa-source.sh || status=$?
if [ -n "${HOST_UID:-}" ]; then
  chown -R "${HOST_UID}:${HOST_GID:-$HOST_UID}" /work
fi
exit "$status"
