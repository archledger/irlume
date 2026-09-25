#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Download the ONNX Runtime release tarball, check it against the sha256 pinned
# below, and only then unpack it into the current directory. CI runs it in the
# checkout; locally, run it outside, because git does not ignore the tarball:
#
#   cd "$(mktemp -d)" && bash /path/to/irlume/scripts/fetch-ort.sh 1.28.1
#   # ./onnxruntime-linux-x64-1.28.1.tgz and ./onnxruntime-linux-x64-1.28.1/
#
# A directory of that name left by an earlier run is replaced, not unpacked
# over. scripts/test-fetch-ort.sh covers this script without the network.
#
# CI loads the unpacked library into every test process through ORT_DYLIB_PATH,
# so it checks the same digest the packaging lanes check before they bundle the
# runtime (packaging/debian/build-deb.sh, scripts/build-ppa-source.sh, the
# Fedora spec and the Nix files). scripts/check-packaging-parity.sh keeps every
# copy of the version and the digest equal, so a bump changes both lines below
# and then every site that check names.
set -euo pipefail

# sha256 of onnxruntime-linux-x64-${PINNED_VER}.tgz from the upstream GitHub
# release; the release API reports the same digest for the asset.
PINNED_VER=1.28.1
PINNED_SHA256=2529aef968d0ad0603365054bc46ebefa7f0fe3bc12f28c5f729c99ddffe2a81

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 <onnxruntime version>" >&2
  exit 2
fi
ver="$1"
if [ "$ver" != "$PINNED_VER" ]; then
  echo "fetch-ort.sh: no sha256 is pinned for onnxruntime $ver (pinned: $PINNED_VER);" >&2
  echo "update PINNED_VER and PINNED_SHA256 in $0 together." >&2
  exit 1
fi

tgz="onnxruntime-linux-x64-${ver}.tgz"
part="${tgz}.part"
trap 'rm -f "$part"' EXIT

curl -fsSL --retry 3 --retry-delay 2 -o "$part" \
  "https://github.com/microsoft/onnxruntime/releases/download/v${ver}/${tgz}"
got="$(sha256sum "$part" | cut -d' ' -f1)"
if [ "$got" != "$PINNED_SHA256" ]; then
  echo "fetch-ort.sh: $tgz has sha256 $got, expected $PINNED_SHA256; not unpacking it." >&2
  exit 1
fi
mv -f "$part" "$tgz"
rm -rf "onnxruntime-linux-x64-${ver}"
tar xzf "$tgz"
echo "fetch-ort.sh: $tgz sha256 ok, unpacked to $PWD/onnxruntime-linux-x64-${ver}"
