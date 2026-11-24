#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Inner build for build-deb-container.sh; runs in a fresh Debian container.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C TZ=UTC
umask 022

# Extract the committed modes on the container filesystem, not on TMPDIR.
mkdir /build
tar --no-same-owner -xpf /tmp/irlume-source.tar -C /build
cd /build
while read -r _ model; do
    install -m 0644 -- "/src/models/$model" "models/$model"
done < models/SHA256SUMS

# The base image has the Debian archive keyring but no CA certificates.
# Bootstrap HTTPS with the read-only host CA bundle. Do not read live sources.
apt=(apt-get -o Dir::Etc::sourcelist=/build/packaging/debian/bookworm-snapshot.sources
     -o Dir::Etc::sourceparts=- -o Acquire::https::CAInfo=/tmp/irlume-ca.pem)
"${apt[@]}" -o APT::Update::Error-Mode=any update -qq
# clang/libclang-dev: bindgen (v4l2-sys-mit) needs libclang at build time.
"${apt[@]}" install -y -qq --no-install-recommends \
    curl ca-certificates build-essential pkg-config libtss2-dev libpam0g-dev \
    libudev-dev libdbus-1-dev dbus-daemon clang libclang-dev git xz-utils >/dev/null

curl -fsSL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VER}/x86_64-unknown-linux-gnu/rustup-init" -o /tmp/rustup-init
printf '%s  /tmp/rustup-init\n' "$RUSTUP_SHA256" | sha256sum --strict -c -
chmod +x /tmp/rustup-init
/tmp/rustup-init -y --default-toolchain "$RUST_VER" --profile minimal --no-modify-path >/dev/null
export PATH="$HOME/.cargo/bin:$PATH"

curl -fsSL "https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VER}/nfpm_${NFPM_VER}_amd64.deb" -o /tmp/nfpm.deb
printf '%s  /tmp/nfpm.deb\n' "$NFPM_SHA256" | sha256sum --strict -c -
"${apt[@]}" install -y -qq --no-install-recommends /tmp/nfpm.deb >/dev/null

bash packaging/debian/build-deb.sh
# The host caller must be able to read the result even when Docker owns it.
install -m 0644 -v -- irlume_*_amd64.deb /out/
