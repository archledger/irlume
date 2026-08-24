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

echo "== pamsm consumed from the maintained fork only =="
# pamsm comes from the archledger/pam_sm_rust fork at an exact commit. The
# in-tree vendored copy is gone; a source-complete build means Cargo can fetch
# that exact rev offline once vendored. A moving selector (branch =) would
# make "exact" a lie, so the rev is asserted, not just the URL.
PAMSM_URL='https://github.com/archledger/pam_sm_rust'
PAMSM_REV="$(sed -n "s|^pamsm = { git = \"$PAMSM_URL\", rev = \"\([0-9a-f]\{40\}\)\" }$|\1|p" Cargo.toml)"
if [ -n "$PAMSM_REV" ]; then
  printf '  ok    %s\n' "Cargo.toml pamsm fork pin ${PAMSM_REV:0:10}"
else
  printf '  MISS  %s\n' 'Cargo.toml pamsm exact 40-char fork rev'
  fail=1
fi
if grep -qF "git+$PAMSM_URL?rev=$PAMSM_REV#$PAMSM_REV" Cargo.lock; then
  printf '  ok    %s\n' 'Cargo.lock pamsm resolves to the same rev'
else
  printf '  MISS  %s\n' 'Cargo.lock pamsm fork rev'
  fail=1
fi
if grep -Eq 'pamsm = \{ git = "[^"]*", branch = ' Cargo.toml; then
  printf '  MISS  %s\n' 'pamsm must not use a moving branch selector'
  fail=1
fi
if [ -e third_party/pamsm-0.5.5 ]; then
  printf '  MISS  %s\n' 'third_party/pamsm-0.5.5 must be absent (fork replaces it)'
  fail=1
else
  printf '  ok    %s\n' 'third_party/pamsm-0.5.5 absent'
fi
if grep -q 'pamsm' .gitattributes; then
  printf '  MISS  %s\n' '.gitattributes still carries a pamsm exception'
  fail=1
else
  printf '  ok    %s\n' '.gitattributes has no pamsm exception'
fi
echo

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
# a missing path as a no-op and returns Ok, so the daemon starts but BlazeFace
# rescue alignment stops working.
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
echo "== every lane pins the same ONNX Runtime =="
# irlume builds `ort` with `load-dynamic`, so libonnxruntime.so is whatever the
# host supplies at runtime and the version each lane bundles IS the version its
# users run. Eight files name it and nothing made them agree (#411): a lane
# bumped on its own ships a runtime no CI job ever executed, and the embedding
# gate in irlume-vision (#407) would stay green while the numbers it pins moved
# under the shipped package.
#
# Each lane spells the pin its own way, so extraction is per file and an
# unlisted file is a hard error rather than a skip. Same reason as dest_for()
# above: a pattern that silently matches nothing yields an empty string, and two
# empty strings compare equal, which is a guard reporting ok while checking
# nothing.
ort_pin_of() {
  case "$1" in
    .github/workflows/ci.yml|.github/workflows/asan.yml|.github/workflows/install-matrix.yml)
      sed -n 's/^[[:space:]]*ver=\([0-9][0-9.]*\)[[:space:]]*$/\1/p' "$1" ;;
    flake.nix|nix/module.nix)
      # Only the `ortVersion` binding. Both files interpolate it into the
      # derivation label and the fetch URL, so reading the binding reads what is
      # actually downloaded. Matching a bare `version =` instead would read a
      # label that a bump could move while the URL kept fetching the old archive.
      sed -n 's/.*[oO]rt[Vv]ersion = "\([0-9][0-9.]*\)".*/\1/p' "$1" ;;
    packaging/fedora/irlume.spec)
      sed -n 's/^%global ort_ver \([0-9][0-9.]*\).*/\1/p' "$1" ;;
    packaging/debian/build-deb.sh|scripts/build-ppa-source.sh)
      # shellcheck disable=SC2016  # ${ORT_VER:-...} is literal text in those files
      sed -n 's/^ORT_VER="${ORT_VER:-\([0-9][0-9.]*\)}".*/\1/p' "$1" ;;
    *)
      echo "  ERROR: no ONNX Runtime pin pattern known for $1;" >&2
      echo "  add one to ort_pin_of() in $0 rather than leaving it unchecked." >&2
      exit 1
      ;;
  esac
}

ORT_PINNED_BY=(
  .github/workflows/ci.yml
  .github/workflows/asan.yml
  .github/workflows/install-matrix.yml
  flake.nix
  nix/module.nix
  packaging/fedora/irlume.spec
  packaging/debian/build-deb.sh
  scripts/build-ppa-source.sh
)

# How many times each file is expected to name it. Counting DISTINCT values is
# not enough: ci.yml fetches the runtime in three separate jobs, and deleting
# one of those steps leaves the other two agreeing, so a uniqueness check would
# report ok for a workflow that had silently stopped pinning a lane.
declare -A ORT_PIN_COUNT=(
  [.github/workflows/ci.yml]=2
  [.github/workflows/asan.yml]=1
  [.github/workflows/install-matrix.yml]=1
  [flake.nix]=1
  [nix/module.nix]=1
  [packaging/fedora/irlume.spec]=1
  [packaging/debian/build-deb.sh]=1
  [scripts/build-ppa-source.sh]=1
)

ort_ref=""
for f in "${ORT_PINNED_BY[@]}"; do
  want="${ORT_PIN_COUNT[$f]:-}"
  if [ -z "$want" ]; then
    echo "  ERROR: no expected pin count for $f; add one to ORT_PIN_COUNT in $0" >&2
    exit 1
  fi
  all="$(ort_pin_of "$f")"
  n="$(printf '%s' "$all" | grep -c . || true)"
  if [ "$n" -ne "$want" ]; then
    printf '  MISS  %-42s expected %s pin(s), found %s\n' "$f" "$want" "$n"
    fail=1
    continue
  fi
  found="$(printf '%s\n' "$all" | sort -u)"
  u="$(printf '%s' "$found" | grep -c . || true)"
  if [ "$u" -ne 1 ]; then
    printf '  MISS  %-42s names %s different versions\n' "$f" "$u"
    fail=1
    continue
  fi
  printf '  ok    %-42s %s\n' "$f" "$found"
  if [ -z "$ort_ref" ]; then
    ort_ref="$found"
  elif [ "$found" != "$ort_ref" ]; then
    printf '  ERROR %-42s pins %s, but %s pins %s\n' \
      "$f" "$found" "${ORT_PINNED_BY[0]}" "$ort_ref"
    fail=1
  fi
done

# The developer guide hands out copy-paste setup commands carrying the version,
# so a contributor who follows it after a bump installs a runtime no lane ships.
# The dated survey under docs/cross-distro/ is deliberately NOT checked: it
# records what was true on its date and is not instructions.
if [ -z "$ort_ref" ]; then
  echo "  ERROR: no ONNX Runtime version could be read from any lane"
  fail=1
else
  # EVERY place the recipe names it, not just one. The version appears in the
  # download URL, the tarball, the tar command, the exported library path, the
  # dependency table and the .deb soname example. Checking one of them passes a
  # document that downloads one version and puts a different one on
  # ORT_DYLIB_PATH, which is a working command sequence that loads the wrong
  # library.
  doc_needs=(
    "onnxruntime **$ort_ref** (\`ORT_DYLIB_PATH\`)"
    "releases/download/v$ort_ref/onnxruntime-linux-x64-$ort_ref.tgz"
    "tar xzf onnxruntime-linux-x64-$ort_ref.tgz"
    "ORT_DYLIB_PATH=\"\$PWD/onnxruntime-linux-x64-$ort_ref/lib/libonnxruntime.so\""
    "libonnxruntime.so.$ort_ref"
  )
  for need in "${doc_needs[@]}"; do
    if grep -Fq -- "$need" docs/DEVELOPMENT.md; then
      printf '  ok    %-42s %s\n' docs/DEVELOPMENT.md "$need"
    else
      printf '  MISS  %-42s %s\n' docs/DEVELOPMENT.md "$need"
      fail=1
    fi
  done
fi

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
  "/run/lock/irlume/irlume-emitter-*.lock rwk,"
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

echo
echo "== tmpfiles.d setgid lock dir shipped and applied in every lane (#542) =="
# The setgid lock directory must exist BEFORE the daemon creates its first
# lock. Every lane needs BOTH halves: the file shipped to
# /usr/lib/tmpfiles.d, and a scriptlet that applies it ahead of any daemon
# start (a fresh install has had no boot to apply it). The NixOS module has
# no package scriptlets; its equivalent is the tmpfiles rule inline.
TMPFILES_SHIP_MARKERS=(
  "packaging/fedora/irlume.spec|%{_tmpfilesdir}/irlume.conf"
  "packaging/arch/PKGBUILD|usr/lib/tmpfiles.d/irlume.conf"
  "packaging/debian/nfpm.yaml|/usr/lib/tmpfiles.d/irlume.conf"
  "packaging/ppa/debian/rules|usr/lib/tmpfiles.d/irlume.conf"
)
for marker in "${TMPFILES_SHIP_MARKERS[@]}"; do
  lane="${marker%%|*}"
  needle="${marker#*|}"
  if uncommented "$lane" | grep -F -- "$needle" >/dev/null; then
    printf '  ok    %-34s %s\n' "tmpfiles.d/irlume.conf" "$lane"
  else
    printf '  MISS  %-34s %s\n' "tmpfiles.d/irlume.conf" "$lane"
    fail=1
  fi
done
TMPFILES_APPLY_MARKERS=(
  "packaging/fedora/irlume.spec|systemd-tmpfiles --create irlume.conf"
  "packaging/arch/irlume.install|systemd-tmpfiles --create irlume.conf"
  "packaging/debian/postinstall.sh|systemd-tmpfiles --create irlume.conf"
  "packaging/ppa/debian/postinst|systemd-tmpfiles --create irlume.conf"
  "nix/module.nix|d /run/lock/irlume 2751 root video -"
)
for marker in "${TMPFILES_APPLY_MARKERS[@]}"; do
  lane="${marker%%|*}"
  needle="${marker#*|}"
  if uncommented "$lane" | grep -F -- "$needle" >/dev/null; then
    printf '  ok    %-34s %s\n' "apply before daemon start" "$lane"
  else
    printf '  MISS  %-34s %s\n' "apply before daemon start" "$lane"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "packaging parity: FAILED"
  exit 1
fi
echo "packaging parity: OK"
