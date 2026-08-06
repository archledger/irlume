#!/usr/bin/env bash
# NOT A RELEASE LANE. Arch users get irlume from the AUR.
#
# The header here used to say AUR registration was disabled and that
# `irlume update` on Arch installs this prebuilt package. Neither is true: the
# CLI's pacman arm points at the AUR, a regression test in
# crates/irlume-cli/src/commands.rs pins that, and no `.pkg.tar.zst` asset has
# been referenced since 0.1.x.
#
# It matters because the inline PKGBUILD below is not at parity with
# packaging/arch/PKGBUILD: it omits irlumed.socket, both keyring helpers
# (irlume-kwallet-init, irlume-gkr-unlock), the TFLite runtime, the machine-API
# schema, and the AppArmor profile. A package built from it installs a daemon
# with no socket activation, no wallet unlock, and no confinement.
# check-packaging-parity.sh does not look at this file, so nothing catches that.
#
# Kept for local experiments, behind an explicit opt-in so nobody publishes
# from it by accident:
#   IRLUME_ARCH_LOCAL_BUILD=1 bash packaging/arch/build-pkg.sh
set -euo pipefail

if [ "${IRLUME_ARCH_LOCAL_BUILD:-}" != "1" ]; then
    echo "packaging/arch/build-pkg.sh is not a release lane; Arch ships via the AUR." >&2
    echo "It is missing the socket unit, both keyring helpers, the TFLite runtime," >&2
    echo "the schema, and the AppArmor profile. For a local experiment only:" >&2
    echo "  IRLUME_ARCH_LOCAL_BUILD=1 bash packaging/arch/build-pkg.sh" >&2
    exit 2
fi

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PKGVER="$(grep -m1 '^version' "$REPO/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
BUILD="$REPO/.arch-build"
cd "$REPO"

command -v makepkg >/dev/null || { echo "run on Arch (needs makepkg)"; exit 1; }

# Fetch + verify the release-hosted model weights (not Git LFS).
bash scripts/fetch-models.sh
# --locked only. The fallback here silently rebuilt with a fresh resolve, which
# for the [patch.crates-io] TPM crate meant whatever its branch head was at that
# moment; that crate performs the sealing.
cargo build --release --locked

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
  for m in glintr100 face_detection_yunet_2023mar face_landmark blaze_face_short_range; do
    install -Dm0644 "\$startdir/models/\$m.onnx" "\$pkgdir/usr/share/irlume/models/\$m.onnx"
  done
  install -Dm0644 "\$startdir/systemd/irlumed.service" "\$pkgdir/usr/lib/systemd/system/irlumed.service"
  # The PAM self-heal units. This package omitted them while shipping an
  # irlume.install that runs \`systemctl enable --now irlume-reconcile.*\`, and
  # those calls end in \`|| true\`, so every install of this package silently
  # reported success while leaving the machine with no self-heal at all. Found on
  # a box installed this way: all three units \`not-found\`, zero owned by the
  # package. The AUR PKGBUILD has always shipped them; only this one did not.
  install -Dm0644 "\$startdir/systemd/irlume-reconcile.path" "\$pkgdir/usr/lib/systemd/system/irlume-reconcile.path"
  install -Dm0644 "\$startdir/systemd/irlume-reconcile.service" "\$pkgdir/usr/lib/systemd/system/irlume-reconcile.service"
  install -Dm0644 "\$startdir/systemd/irlume-reconcile.timer" "\$pkgdir/usr/lib/systemd/system/irlume-reconcile.timer"
  install -Dm0644 "\$startdir/LICENSE" "\$pkgdir/usr/share/licenses/irlume/LICENSE"
  install -Dm0644 "\$startdir/README.md" "\$pkgdir/usr/share/doc/irlume/README.md"
}
PKGB

cd "$BUILD"
makepkg -f --nodeps   # deps are runtime; binaries already built
cp irlume-*.pkg.tar.zst "$REPO/"
echo "built $REPO/irlume-${PKGVER}-1-x86_64.pkg.tar.zst"
