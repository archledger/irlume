#!/usr/bin/env bash
# Build the irlume .deb: cargo build, pull LFS models, stage the bundled
# onnxruntime (>=1.24; Ubuntu's archive first gained onnxruntime in 26.04 at
# 1.23.2, below irlume's floor, and older LTSs have none), then nfpm pkg.
#   bash packaging/debian/build-deb.sh
set -euo pipefail

ORT_VER="${ORT_VER:-1.24.4}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$REPO/.deb-staging"
cd "$REPO"

command -v nfpm >/dev/null || { echo "need nfpm (https://nfpm.goreleaser.com)"; exit 1; }

# Real model weights, not LFS pointers.
git lfs pull

cargo build --release --locked

# The libc6 floor declared in nfpm.yaml must cover what the binaries really
# require. Building on a newer base silently raises the requirement (the .deb
# then installs fine and every binary dies with "GLIBC_x.y not found"), so
# fail the build instead of shipping that.
declared="$(sed -n 's/^  - libc6 (>= \(.*\))$/\1/p' "$REPO/packaging/debian/nfpm.yaml")"
[ -n "$declared" ] || { echo "nfpm.yaml no longer declares a libc6 floor"; exit 1; }
actual="$(objdump -T target/release/irlume target/release/irlumed target/release/libpam_irlume.so \
  | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -n1)"
if [ "$(printf '%s\n%s\n' "$actual" "$declared" | sort -V | tail -n1)" != "$declared" ]; then
  echo "binaries need glibc $actual but nfpm.yaml declares libc6 (>= $declared);"
  echo "either build on an older base or raise the declared floor."
  exit 1
fi
echo "glibc floor ok: binaries need $actual, package declares >= $declared"

rm -rf "$STAGE"; mkdir -p "$STAGE"
# Bundle onnxruntime.
curl -fsSL -o "$STAGE/ort.tgz" \
  "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VER}/onnxruntime-linux-x64-${ORT_VER}.tgz"
mkdir -p "$STAGE/onnxruntime"
tar -xzf "$STAGE/ort.tgz" -C "$STAGE/onnxruntime" --strip-components=1

# Unit override pointing ORT_DYLIB_PATH at the bundled lib.
cat > "$STAGE/10-ort.conf" <<EOF
[Service]
Environment="ORT_DYLIB_PATH=/opt/irlume/onnxruntime/lib/libonnxruntime.so"
EOF

cd "$REPO/packaging/debian"
# Name the artifact after the irlume version (from nfpm.yaml), NOT the bundled
# onnxruntime version; irlume_1.24.4.deb read like irlume itself was 1.24.4.
PKG_VER="$(sed -n 's/^version:[[:space:]]*v\{0,1\}\([0-9][^[:space:]]*\).*/\1/p' nfpm.yaml)"
nfpm package --packager deb --target "$REPO/irlume_${PKG_VER}_amd64.deb"
echo "built irlume_${PKG_VER}_amd64.deb in $REPO"
