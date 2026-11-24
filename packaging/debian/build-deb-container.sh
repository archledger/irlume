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
# Requires: podman (or docker; rootless is fine), Git and a host CA bundle.
#   bash packaging/debian/build-deb-container.sh
# Output: irlume_<version>_amd64.deb in OUT (default: checkout root).
set -euo pipefail
# Cold model downloads must have the same modes as verified cached models.
umask 022
# Digest-pinned so the glibc floor and toolchain are reproducible: the plain
# `debian:12` tag tracks every point release. Bump the digest deliberately when
# moving the base (the tag is `debian:12` as of this digest).
BASE="${BASE:-debian:12@sha256:9344f8b8992482f80cba753f323adeaf17690076c095ccff6cc9536be98185dc}"
RUST_VER="${RUST_VER:-1.88.0}"   # >= ort's MSRV (edition 2024)
# The installer is a lane input like any other: pinned by version and
# verified against its published checksum before it runs (same pin as the
# PPA container lane; keep the two in step).
RUSTUP_VER="${RUSTUP_VER:-1.29.3}"
RUSTUP_SHA256="${RUSTUP_SHA256:-b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55}"
# Pin the actual nFPM bytes rather than trusting a checksum fetched alongside
# the executable. Update the version and checksum together.
NFPM_VER="${NFPM_VER:-2.47.0}"
NFPM_SHA256="${NFPM_SHA256:-3f1cf344bd0b57373ca55636a78c08b0491f7293d609a456a9ac3b0b150fda97}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${OUT:-$REPO}"
CA_BUNDLE="${CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"

commit="$(git -C "$REPO" rev-parse --verify HEAD)"
epoch="${SOURCE_DATE_EPOCH-$(git -C "$REPO" show -s --format=%ct "$commit")}"
# The Unix timestamp also has to fit in the 12-character Debian ar field.
if [[ ! "$epoch" =~ ^[0-9]{1,12}$ ]]; then
    echo "invalid SOURCE_DATE_EPOCH: expected 1 to 12 decimal digits" >&2
    exit 1
fi
if [[ ! "$RUSTUP_SHA256" =~ ^[[:xdigit:]]{64}$ || ! "$NFPM_SHA256" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "RUSTUP_SHA256 and NFPM_SHA256 must be 64 hex digits" >&2
    exit 1
fi
if ! git -C "$REPO" diff --quiet -- || ! git -C "$REPO" diff --cached --quiet "$commit" --; then
    echo "tracked changes found; build from a clean committed checkout" >&2
    exit 1
fi
if [[ -s "$(git -C "$REPO" rev-parse --path-format=absolute --git-path info/attributes)" ]]; then
    echo "local Git attributes can change the source archive; build from a fresh clone" >&2
    exit 1
fi
CONTAINER_RUN="$(command -v podman || command -v docker)" || {
    echo "need podman (or docker)"
    exit 1
}
if [[ ! -r "$CA_BUNDLE" || ! -s "$CA_BUNDLE" ]]; then
    echo "no readable CA bundle at $CA_BUNDLE; set CA_BUNDLE to a PEM bundle" >&2
    exit 1
fi
OUT="$(cd "$OUT" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
install -m 0444 -- "$CA_BUNDLE" "$work/ca.pem"
mkdir "$work/source" "$work/out"
GIT_ATTR_NOSYSTEM=1 git -C "$REPO" -c core.attributesFile=/dev/null -c tar.umask=0022 archive --format=tar "$commit" \
    > "$work/source.tar"
tar --no-same-owner -xf "$work/source.tar" -C "$work/source"

# Seed only manifest-listed model files from the local cache.
models=()
while read -r _ model; do
    if [[ ! "$model" =~ ^[[:alnum:]_][[:alnum:]_.-]*$ ]]; then
        echo "invalid model path in models/SHA256SUMS" >&2
        exit 1
    fi
    models+=("$model")
    if [[ ! -e "$work/source/models/$model" && -f "$REPO/models/$model" ]]; then
        install -m 0644 -- "$REPO/models/$model" "$work/source/models/$model"
    fi
done < "$work/source/models/SHA256SUMS"
bash "$work/source/scripts/fetch-models.sh"
(
    cd "$work/source/models"
    sha256sum --quiet --strict -c SHA256SUMS
    # A staging filesystem's default ACL can override the umask.
    chmod 0644 -- "${models[@]}"
)

echo "==> building universal .deb in $BASE (rustup $RUST_VER)"
"$CONTAINER_RUN" run --rm --platform linux/amd64 \
  -v "$work/source:/src:ro,z" \
  -v "$work/source.tar:/tmp/irlume-source.tar:ro,z" \
  -v "$work/ca.pem:/tmp/irlume-ca.pem:ro,z" \
  -v "$work/out:/out:z" \
  -e "SOURCE_DATE_EPOCH=$epoch" \
  -e "RUST_VER=$RUST_VER" -e "RUSTUP_VER=$RUSTUP_VER" -e "RUSTUP_SHA256=$RUSTUP_SHA256" \
  -e "NFPM_VER=$NFPM_VER" -e "NFPM_SHA256=$NFPM_SHA256" \
  "docker.io/library/$BASE" bash /src/packaging/debian/container-build.sh

shopt -s nullglob
packages=("$work"/out/irlume_*_amd64.deb)
if [[ "${#packages[@]}" != 1 || ! -f "${packages[0]}" || -L "${packages[0]}" ]]; then
    echo "expected exactly one universal Debian package" >&2
    exit 1
fi
install -m 0644 -- "${packages[0]}" "$OUT/"
echo "==> universal .deb in $OUT/"
