#!/usr/bin/env bash
# Build the UNIVERSAL irlume .deb: one binary that installs on Debian 12+ and
# every current Ubuntu derivative (Mint, Pop!_OS, Zorin, elementary; all
# noble/24.04-based) and every newer Ubuntu.
#
# Why a container instead of the PPA: the PPA covers only the current Ubuntu LTS,
# because Launchpad's builders use the archive's cargo and older LTSs like noble
# (24.04) ship cargo 1.75, too old to compile our ort / edition-2024 deps. So we
# build the .deb ourselves in a container of the OLDEST supported base with a
# rustup toolchain (>= ort's MSRV; a LOCAL build isn't limited to the archive's
# rust). That base is debian:12 (glibc 2.36); the binaries come out referencing
# GLIBC_2.35 symbols at most, and glibc is forward compatible, so one .deb runs
# on Debian 12+, Ubuntu 22.04+, and every derivative of those. A noble base
# (glibc 2.39) was tried first and its .deb installed but could not run on
# bookworm ("GLIBC_2.39 not found"). The bundled onnxruntime needs only glibc
# 2.27 / GLIBCXX 3.4.22, so it never binds first. If BASE ever moves, update
# the libc6 floor in nfpm.yaml; build-deb.sh asserts the two stay in sync.
#
# Requires: podman (rootless is fine) and real LFS model weights in models/.
#   bash packaging/debian/build-deb-container.sh
# Output: ./irlume_<version>_amd64.deb (copied out of the container).
set -euo pipefail
BASE="${BASE:-debian:12}"        # oldest supported base (sets the glibc floor)
RUST_VER="${RUST_VER:-1.88.0}"   # >= ort's MSRV (edition 2024)
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${OUT:-$REPO}"

command -v podman >/dev/null || { echo "need podman"; exit 1; }
# Models must be real weights, not LFS pointer stubs (bundled into the .deb).
for m in "$REPO"/models/*.onnx; do
    if [ "$(stat -c%s "$m")" -lt 1000000 ] && grep -q git-lfs "$m" 2>/dev/null; then
        echo "$m is an LFS pointer — run: git lfs pull"; exit 1
    fi
done

echo "==> building universal .deb in $BASE (rustup $RUST_VER)"
podman run --rm \
  -v "$REPO:/src:ro,z" \
  -v "$OUT:/out:z" \
  "docker.io/library/$BASE" bash -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # clang/libclang-dev: bindgen (v4l2-sys-mit) needs libclang at build time.
    apt-get install -y -qq curl ca-certificates build-essential pkg-config \
        libtss2-dev libpam0g-dev clang libclang-dev git git-lfs xz-utils >/dev/null
    curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain '"$RUST_VER"' --profile minimal >/dev/null
    . "$HOME/.cargo/env"
    NFPM_VER=$(curl -s https://api.github.com/repos/goreleaser/nfpm/releases/latest | grep -oP "\"tag_name\":\s*\"v\K[^\"]+")
    curl -sSL "https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VER}/nfpm_${NFPM_VER}_amd64.deb" -o /tmp/nfpm.deb
    apt-get install -y -qq /tmp/nfpm.deb >/dev/null
    cp -r /src /build && cd /build
    sed -i "/git lfs pull/d" packaging/debian/build-deb.sh   # models are already real in the mount
    bash packaging/debian/build-deb.sh
    cp -v *.deb /out/
  '
echo "==> universal .deb in $OUT/"
