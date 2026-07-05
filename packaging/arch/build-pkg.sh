#!/usr/bin/env bash
# Build an installable irlume .pkg.tar.zst from the local checkout, for
# distribution via GitHub Releases (AUR registration is currently disabled, so
# `irlume update` on Arch installs this prebuilt package with pacman -U). Run on
# an Arch box:  bash packaging/arch/build-pkg.sh
#
# Unlike the AUR PKGBUILD (which fetches the git tag), this packages the
# already-built binaries + LFS models in place — no network source.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PKGVER="$(grep -m1 '^version' "$REPO/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
BUILD="$REPO/.arch-build"
cd "$REPO"

command -v makepkg >/dev/null || { echo "run on Arch (needs makepkg)"; exit 1; }

# Ensure real model weights (LFS). Tolerate a non-git export where they're
# already present as real files.
git lfs pull 2>/dev/null || true
[ "$(stat -c%s models/glintr100.onnx 2>/dev/null || echo 0)" -gt 1000000 ] \
  || { echo "models/glintr100.onnx missing/pointer — run 'git lfs pull' first"; exit 1; }
cargo build --release --locked 2>/dev/null || cargo build --release

rm -rf "$BUILD"; mkdir -p "$BUILD"
cp -r target/release "$BUILD/release"
cp -r models "$BUILD/models"
cp -r packaging/systemd "$BUILD/systemd"
cp LICENSE README.md packaging/arch/irlume.install "$BUILD/"

cat > "$BUILD/PKGBUILD" <<PKGB
pkgname=irlume
pkgver=${PKGVER}
pkgrel=1
pkgdesc="Windows Hello-style face login for Linux"
arch=('x86_64')
url="https://github.com/archledger/irlume"
license=('GPL-3.0-or-later')
depends=('onnxruntime' 'tpm2-tss' 'pam')
optdepends=('fprintd: fingerprint companion factor')
install=irlume.install
package() {
  install -Dm0755 "\$startdir/release/irlumed" "\$pkgdir/usr/bin/irlumed"
  install -Dm0755 "\$startdir/release/irlume"  "\$pkgdir/usr/bin/irlume"
  install -Dm0644 "\$startdir/release/libpam_irlume.so" "\$pkgdir/usr/lib/security/pam_irlume.so"
  for m in glintr100 face_detection_yunet_2023mar face_landmark ir_adapter; do
    install -Dm0644 "\$startdir/models/\$m.onnx" "\$pkgdir/usr/share/irlume/models/\$m.onnx"
  done
  install -Dm0644 "\$startdir/systemd/irlumed.service" "\$pkgdir/usr/lib/systemd/system/irlumed.service"
  install -Dm0644 "\$startdir/LICENSE" "\$pkgdir/usr/share/licenses/irlume/LICENSE"
  install -Dm0644 "\$startdir/README.md" "\$pkgdir/usr/share/doc/irlume/README.md"
}
PKGB

cd "$BUILD"
makepkg -f --nodeps   # deps are runtime; binaries already built
cp irlume-*.pkg.tar.zst "$REPO/"
echo "built $REPO/irlume-${PKGVER}-1-x86_64.pkg.tar.zst"
