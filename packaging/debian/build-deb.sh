#!/usr/bin/env bash
# Build the irlume .deb: cargo build, pull LFS models, stage the bundled
# onnxruntime (>=1.24, absent from the Debian/Ubuntu archive), then nfpm pkg.
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
nfpm package --packager deb --target "$REPO/irlume_${ORT_VER}.deb" || \
  nfpm package --packager deb --target "$REPO/"
echo "built .deb in $REPO"
