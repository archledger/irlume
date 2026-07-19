#!/usr/bin/env bash
# Build the Ubuntu PPA *source* package (Launchpad builds the binaries).
#
# Launchpad builders have NO network, so the orig tarball must be
# self-contained: vendored crates (cargo vendor), the bundled onnxruntime
# release libs, and the real ONNX model weights (not LFS pointers).
#
# Run on an Ubuntu/Debian box from a repo checkout with real LFS models.
#
# The PPA targets ONLY the current Ubuntu LTS (its cargo is new enough for our
# ort/edition-2024 deps). Older LTSs like noble (24.04, cargo 1.75) can't build
# irlume at all, so their derivatives (Mint, Pop!_OS, Zorin, elementary) use the
# universal .deb from the GitHub release instead; built on the oldest supported
# base + rustup in a container (see the noble-container build). Build + upload
# just the current series:
#   SERIES=resolute bash scripts/build-ppa-source.sh
#   debsign  "$HOME/ppa-build/irlume_"*"~resolute1_source.changes"   # release key
#   dput ppa:archledger/irlume "$HOME/ppa-build/irlume_"*"~resolute1_source.changes"
# (The deterministic orig below still lets a NEW LTS be added cleanly later.)
#
# Env knobs: SERIES (default resolute), PPAREV (0ppa1), ORT_VER (1.24.4),
# BUILDROOT (~/ppa-build), SKIP_BUILD_CHECK=1 to skip the offline test build.
set -euo pipefail

SERIES="${SERIES:-resolute}"
PPAREV="${PPAREV:-0ppa1}"
ORT_VER="${ORT_VER:-1.24.4}"
BUILDROOT="${BUILDROOT:-$HOME/ppa-build}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$REPO/Cargo.toml" | head -1)"
DEBVER="${VERSION}-${PPAREV}~${SERIES}1"
TREE="$BUILDROOT/irlume-$VERSION"

for tool in rsync cargo dpkg-buildpackage curl; do
    command -v "$tool" >/dev/null || { echo "need $tool"; exit 1; }
done

# Models must be real weights, not LFS pointer stubs.
for m in "$REPO"/models/*.onnx; do
    if [ "$(stat -c%s "$m")" -lt 1000000 ] && grep -q git-lfs "$m" 2>/dev/null; then
        echo "$m is an LFS pointer - run: git lfs pull"; exit 1
    fi
done

echo "==> staging source tree $TREE (irlume $DEBVER)"
mkdir -p "$BUILDROOT"
rm -rf "$TREE"
# Leading / anchors each exclude to the tree root (a bare "debian" would
# also strip packaging/ppa/debian and packaging/debian).
rsync -a --exclude .git --exclude /target --exclude /.deb-staging \
      --exclude /debian --exclude /vendor "$REPO/" "$TREE/"

echo "==> bundling onnxruntime $ORT_VER"
ORT_TGZ="$BUILDROOT/onnxruntime-linux-x64-${ORT_VER}.tgz"
[ -f "$ORT_TGZ" ] || curl -fsSL -o "$ORT_TGZ" \
    "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VER}/onnxruntime-linux-x64-${ORT_VER}.tgz"
mkdir -p "$TREE/ort-prebuilt"
tar -xzf "$ORT_TGZ" -C "$TREE/ort-prebuilt" --strip-components=1
rm -rf "$TREE/ort-prebuilt/include"   # headers unused (load-dynamic)

echo "==> vendoring crates"
cd "$TREE"
mkdir -p .cargo
cargo vendor vendor > .cargo/config.toml

if [ "${SKIP_BUILD_CHECK:-0}" != "1" ]; then
    echo "==> offline build check (catches missing vendor bits before upload)"
    CARGO_HOME="$TREE/.cargo-home-check" cargo build --release --frozen --offline
    rm -rf "$TREE/.cargo-home-check" "$TREE/target"
fi

echo "==> creating orig tarball (deterministic, same bytes for every series)"
cd "$BUILDROOT"
rm -f "irlume_${VERSION}.orig.tar.gz"
# If more than one Ubuntu series is ever uploaded for the same upstream version,
# Launchpad keeps one orig tarball per version; a second upload with a different
# checksum is rejected ("already exists with different contents"). So
# pack reproducibly: fixed mtime/owner, sorted names, gzip without a timestamp,
# so every series build yields a byte-identical orig. mtime = the release tag's
# commit date (override with SOURCE_DATE_EPOCH).
SDE="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct "v${VERSION}" 2>/dev/null || echo 1600000000)}"
tar --exclude="irlume-$VERSION/target" \
    --sort=name --mtime="@${SDE}" --owner=0 --group=0 --numeric-owner \
    --pax-option='exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime' \
    -cf - "irlume-$VERSION" | gzip -n > "irlume_${VERSION}.orig.tar.gz"

echo "==> debianizing for $SERIES"
cp -r "$TREE/packaging/ppa/debian" "$TREE/debian"
cat > "$TREE/debian/changelog" <<EOF
irlume (${DEBVER}) ${SERIES}; urgency=medium

  * PPA release of irlume ${VERSION} for ${SERIES}.
    Self-contained source: vendored crates, bundled onnxruntime ${ORT_VER},
    bundled model weights (see debian/copyright and the README model BOM).

 -- archledger <archledger236@gmail.com>  $(date -R)
EOF

echo "==> building source package"
cd "$TREE"
dpkg-buildpackage -S -us -uc

echo
echo "Artifacts in $BUILDROOT:"
ls -lh "$BUILDROOT"/irlume_"${DEBVER%%~*}"* "$BUILDROOT"/irlume_"${VERSION}".orig.tar.gz 2>/dev/null || ls -lh "$BUILDROOT"
echo
echo "Next: sign with the release key, then upload:"
echo "  debsign $BUILDROOT/irlume_${DEBVER}_source.changes"
echo "  dput ppa:archledger/irlume $BUILDROOT/irlume_${DEBVER}_source.changes"
