#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Every systemd unit must be shipped by every packaging lane, and every lane
# must agree on the version.
#
# This exists because the same bug has now shipped three times. 0.6.x installed
# irlume-reconcile.timer on Fedora but left it out of the rpm's %files, so the
# build broke. PR #98 existed solely to resync version fields that had drifted.
# And the 0.7.0 pre-release audit found the PPA lane installing the reconcile
# .path and .service but not the .timer, which is the one that catches a config
# regenerator replacing a file by rename: PPA users would have had self-heal
# that silently missed the exact failure it was built for.
#
# A unit that is added to three lanes and forgotten in the fourth is invisible
# until someone on that distro hits it. This makes it a build failure instead.
set -euo pipefail

cd "$(dirname "$0")/.."

LANES=(
  packaging/fedora/irlume.spec
  packaging/arch/PKGBUILD
  packaging/debian/nfpm.yaml
  packaging/ppa/debian/rules
)

fail=0

# Installed programs that are not the two obvious bins. A helper added to
# three lanes and forgotten in the fourth is invisible until someone on that
# distro logs in and their wallet silently stays locked, which is the same
# class of miss the units check above exists for.
echo "== helper programs in every lane =="
HELPERS=(irlume-kwallet-init)
for helper in "${HELPERS[@]}"; do
  for lane in "${LANES[@]}"; do
    if grep -q -- "$helper" "$lane"; then
      printf '  ok    %-30s %s\n' "$helper" "$lane"
    else
      printf '  MISS  %-30s %s\n' "$helper" "$lane"
      fail=1
    fi
  done
  # The Nix lane is not a package-manifest file, so it is checked separately
  # rather than left out and silently drifting.
  if grep -q -- "$helper" nix/package.nix; then
    printf '  ok    %-30s %s\n' "$helper" nix/package.nix
  else
    printf '  MISS  %-30s %s\n' "$helper" nix/package.nix
    fail=1
  fi
done
echo

echo "== systemd units in every lane =="
units=(packaging/systemd/*)
if [ "${#units[@]}" -eq 0 ]; then
  echo "  ERROR: no units found; is the layout still packaging/systemd/?"
  exit 1
fi
for unit_path in "${units[@]}"; do
  unit="$(basename "$unit_path")"
  for lane in "${LANES[@]}"; do
    if grep -q -- "$unit" "$lane"; then
      printf '  ok    %-30s %s\n' "$unit" "$lane"
    else
      printf '  MISS  %-30s %s\n' "$unit" "$lane"
      fail=1
    fi
  done
done

echo
echo "== version agreement =="
cargo_v="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -1)"
spec_v="$(sed -n 's/^Version: *\(.*\)/\1/p' packaging/fedora/irlume.spec | tr -d ' ' | head -1)"
arch_v="$(sed -n 's/^pkgver=\(.*\)/\1/p' packaging/arch/PKGBUILD | head -1)"
nfpm_v="$(sed -n 's/^version: *\(.*\)/\1/p' packaging/debian/nfpm.yaml | tr -d ' ' | head -1)"
printf '  Cargo.toml   %s\n  irlume.spec  %s\n  PKGBUILD     %s\n  nfpm.yaml    %s\n' \
  "$cargo_v" "$spec_v" "$arch_v" "$nfpm_v"
for v in "$spec_v" "$arch_v" "$nfpm_v"; do
  if [ "$v" != "$cargo_v" ]; then
    echo "  ERROR: version disagrees with Cargo.toml ($cargo_v)"
    fail=1
  fi
done
# The PPA and Nix derive their version from Cargo.toml rather than repeating it,
# which is why they are not compared here. Assert that, so a future edit that
# hardcodes one starts being checked instead of silently drifting.
for derived in packaging/ppa/build-ppa-container.sh nix/package.nix; do
  if ! grep -q "Cargo.toml" "$derived"; then
    echo "  ERROR: $derived no longer derives the version from Cargo.toml"
    fail=1
  fi
done

echo
if [ "$fail" -ne 0 ]; then
  echo "packaging parity: FAILED"
  exit 1
fi
echo "packaging parity: OK"
