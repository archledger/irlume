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
HELPERS=(irlume-kwallet-init irlume-gkr-unlock)
for helper in "${HELPERS[@]}"; do
  for lane in "${LANES[@]}"; do
    if grep -q -- "$helper" "$lane"; then
      printf '  ok    %-30s %s\n' "$helper" "$lane"
    else
      printf '  MISS  %-30s %s\n' "$helper" "$lane"
      fail=1
    fi
  done
  # The Nix lane is not a package-manifest file, so it is checked separately.
  # Checked by DESTINATION, not by the name appearing somewhere: the first
  # version of this check passed while the Nix build installed the helper to a
  # store path that the compiled-in FHS path could never find.
  if grep -Fq "libexec/irlume/$helper" nix/package.nix \
     && grep -Fq "test -x \"\$out/bin/$helper\"" nix/package.nix \
     && grep -Fq -- "--replace-fail" nix/package.nix; then
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

# Every model the shipped unit NAMES must actually be INSTALLED by every lane.
#
# The units check above greps for a filename anywhere in the manifest, which is
# not the same question. The Arch PKGBUILD downloaded face_landmarks_detector
# .tflite, listed it in source=(), staged it in prepare(), installed the TFLite
# RUNTIME, and never installed the MODEL; the filename was present twice, so a
# name grep was satisfied while `IRLUME_MESH_MODEL` pointed at a file the
# package did not ship (#360). Being absent is silent: Engine::with_mesh treats
# a missing path as a no-op and returns Ok, so the daemon starts and passive
# liveness, the closure gesture and the BlazeFace rescue just stop working.
#
# So this looks for the filename next to the lane's INSTALL DESTINATION, within
# a two-line window because two lanes wrap the install across a continuation,
# and with comments stripped first: a checker that accepts a commented-out
# install is a checker that passes the exact state it exists to catch.
echo "== models named by the unit are installed by every lane =="
unit=packaging/systemd/irlumed.service
models=$(sed -n 's/.*IRLUME_[A-Z_]*MODEL=\([^"]*\).*/\1/p' "$unit" | xargs -r -n1 basename | sort -u)
if [ -z "$models" ]; then
  echo "  ERROR: no IRLUME_*_MODEL entries found in $unit; has the unit changed shape?"
  exit 1
fi

# Where each lane writes its payload. A filename that never appears beside one
# of these is named but not shipped.
#
# An unknown lane is a hard error, not a skip. The first version returned an
# empty marker for anything unlisted, and `grep -F ''` matches every line, so
# adding a lane here without adding its destination would have made every model
# pass vacuously: a guard that reports ok while checking nothing.
# These markers are literal text to search for, not variables to expand: the
# manifests contain the strings `$pkgdir` and `$out` verbatim.
# shellcheck disable=SC2016
dest_for() {
  case "$1" in
    packaging/fedora/irlume.spec)  echo '%{buildroot}' ;;
    packaging/arch/PKGBUILD)       echo '$pkgdir' ;;
    packaging/debian/nfpm.yaml)    echo 'dst:' ;;
    packaging/ppa/debian/rules)    echo 'debian/irlume' ;;
    *)
      echo "  ERROR: no install destination known for lane $1;" >&2
      echo "  add one to dest_for() in $0 rather than leaving it unchecked." >&2
      exit 1
      ;;
  esac
}

# All four manifests use '#' comments. Stripping them is what stops a
# commented-out install from reading as a live one.
uncommented() { sed 's/[[:space:]]*#.*$//' "$1"; }

for model in $models; do
  for lane in "${LANES[@]}"; do
    dest="$(dest_for "$lane")"
    if uncommented "$lane" | grep -F -A1 -- "$model" | grep -qF -- "$dest"; then
      printf '  ok    %-34s %s\n' "$model" "$lane"
    else
      printf '  MISS  %-34s %s (named but not installed)\n' "$model" "$lane"
      fail=1
    fi
  done

  # Nix builds a models derivation and then installs from it by extension glob,
  # so ask both halves separately. Checking only the fetch would pass a model
  # that was downloaded and then never copied into the derivation output.
  ext="${model##*.}"
  # shellcheck disable=SC2016  # `$out` is literal text in the derivation
  if uncommented nix/package.nix | grep -F -- "$model" | grep -qF -- '$out' \
    && uncommented nix/package.nix | grep -qF -- "*.$ext"; then
    printf '  ok    %-34s %s\n' "$model" nix/package.nix
  else
    printf '  MISS  %-34s %s (named but not installed)\n' "$model" nix/package.nix
    fail=1
  fi
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
echo
echo "== AppArmor runtime rules in both executable-path variants =="
APPARMOR_PROFILES=(
  packaging/apparmor/usr.bin.irlumed
  packaging/apparmor/usr.local.bin.irlumed
)
APPARMOR_RUNTIME_RULES=(
  "/usr/share/irlume/tflite/libtensorflowlite_c.so mr,"
  "/var/lib/systemd/pcrlock.json r,"
  "deny capability sys_ptrace,"
  "/dev/ r,"
  "/run/lock/irlume-emitter-*.lock rwk,"
  "/var/lib/irlume/ir-emitter-stream/*.lock rwk,"
)
for profile in "${APPARMOR_PROFILES[@]}"; do
  for rule in "${APPARMOR_RUNTIME_RULES[@]}"; do
    if grep -Fqx "  $rule" "$profile"; then
      printf '  ok    %-48s %s\n' "$rule" "$profile"
    else
      printf '  MISS  %-48s %s\n' "$rule" "$profile"
      fail=1
    fi
  done
done

if [ "$fail" -ne 0 ]; then
  echo "packaging parity: FAILED"
  exit 1
fi
echo "packaging parity: OK"
