#!/bin/sh
# irlume one-step installer.
#
#   curl -fsSL https://raw.githubusercontent.com/archledger/irlume/main/scripts/install.sh | sh
#
# What it does, by distro:
#   Fedora / RHEL family : enable the signed Copr repo, then dnf install irlume.
#                           If the Copr lane is unreachable (outage), falls back
#                           to the checksum+signature-verified release RPM.
#   Ubuntu (current LTS)  : add the signed PPA, then apt install irlume.
#                           PPA unavailable -> verified universal .deb.
#   Debian / Ubuntu deriv : download the universal .deb from the latest GitHub
#                           release, verify it, then install.
#   Arch                  : install from the AUR (yay/paru when present;
#                           otherwise prints the makepkg steps and stops).
#                           IRLUME_RELEASE_PKG=1 opts into the verified release
#                           .pkg.tar.zst instead (pacman -U, no-downgrade).
#
# Channel fallbacks never DOWNGRADE: a release package is installed only when
# it is strictly newer than what is installed (dnf upgrade / apt / vercmp
# semantics), so a distro lane coming back online never flip-flops with the
# release lane. Already installed and the lane is down for a security update?
#   IRLUME_UPDATE=1 sh scripts/install.sh   (below) pulls the newest verified
#   release package for your distro, or reports "already current".
#
# Integrity:
#   - The repo paths (Fedora Copr, Ubuntu PPA) are cryptographically verified by
#     dnf / apt against their signing keys.
#   - The release-asset paths verify a SHA256 checksum from the release's
#     SHA256SUMS and ABORT on any mismatch. When the release also publishes a
#     GPG signature (SHA256SUMS.asc), this script verifies it against the pinned
#     irlume signing key before trusting the checksums.
#
# Safety:
#   - The whole script is wrapped in main() and only runs once fully downloaded,
#     so a truncated download cannot execute a half-command.
#   - It installs a package only. It wires NOTHING into your login; face auth
#     changes only when you later run `irlume login enable`.
#   - It stops without changing anything if irlume is already installed.
#
# Read it before running it:
#   curl -fsSL https://raw.githubusercontent.com/archledger/irlume/main/scripts/install.sh -o install.sh
#   less install.sh && sh install.sh
set -eu

REPO="archledger/irlume"
RELEASE_BASE="https://github.com/${REPO}/releases/latest/download"
# The irlume release signing key (also signs the git tags). Pinned here, full
# key included, so a compromised release cannot swap the checksums without also
# forging a signature from this exact key. Embedding the key (instead of a
# keyserver fetch) keeps verification working offline-of-keyservers and never
# touches the user's own keyring: it is imported into a throwaway GNUPGHOME.
KEY_FP="F35053398E3C80FE20891B82C10B8492BD7F30C6"
KEY_ASC='-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEakb95BYJKwYBBAHaRw8BAQdAdjfw/0t9/UGFY1GvBHAyZAhz7IHF03DhtA2S
UYW/UbO0JGFyY2hsZWRnZXIgPGFyY2hsZWRnZXIyMzZAZ21haWwuY29tPoiZBBMW
CgBBFiEE81BTOY48gP4giRuCwQuEkr1/MMYFAmpG/eQCGwMFCQPCZwAFCwkIBwIC
IgIGFQoJCAsCBBYCAwECHgcCF4AACgkQwQuEkr1/MMbFLwD/dg3YhbBk4SFKVTeh
OVaN4hHNC2WQGSEIxmgWcw+bvokBAKprgT0zy7fyVzO3Za4V8BGaSWypCWCLA4Uv
PLCYfTcC
=PsGk
-----END PGP PUBLIC KEY BLOCK-----'

say()  { printf '\033[1;34m[irlume]\033[0m %s\n' "$1" >&2; }
warn() { printf '\033[1;33m[irlume]\033[0m %s\n' "$1" >&2; }
die()  { printf '\033[1;31m[irlume]\033[0m %s\n' "$1" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "this installer needs '$1' but it is not on PATH."; }

# Name the channel an existing irlume was installed through, for the guard
# message. $1 is the resolved binary path.
install_channel() {
  if command -v rpm >/dev/null 2>&1 && rpm -q irlume >/dev/null 2>&1; then
    echo "an RPM (dnf / Fedora Copr)"
  elif command -v dpkg >/dev/null 2>&1 && dpkg -s irlume >/dev/null 2>&1; then
    echo "a .deb (apt / PPA)"
  elif command -v pacman >/dev/null 2>&1 && pacman -Qi irlume >/dev/null 2>&1; then
    echo "a pacman package"
  else
    echo "a manual install ($1)"
  fi
}

# Fetch SHA256SUMS into $1 (a temp dir) and verify its GPG signature against the
# pinned key. Every published irlume release ships SHA256SUMS.asc, so a MISSING
# signature is treated as an attack (signature stripping), not a soft fallback:
# an attacker who can serve a modified release would otherwise just omit the
# .asc to disable enforcement. The script therefore fails closed by default and
# aborts when the signature is absent or gpg is missing. IRLUME_INSECURE_NO_SIG=1
# is the explicit, documented escape hatch for the rare case of installing on a
# box with no gpg where the user accepts HTTPS+SHA256 only.
fetch_sums() {
  d="$1"
  curl -fsSL "${RELEASE_BASE}/SHA256SUMS" -o "${d}/SHA256SUMS" \
    || die "could not fetch SHA256SUMS from the latest release."

  if [ "${IRLUME_INSECURE_NO_SIG:-}" = "1" ]; then
    warn "IRLUME_INSECURE_NO_SIG=1 set: skipping GPG signature verification (HTTPS + SHA256 only)."
    return 0
  fi

  command -v gpg >/dev/null 2>&1 \
    || die "gpg is required to verify the release signature. Install gnupg, or (not recommended) set IRLUME_INSECURE_NO_SIG=1 to trust HTTPS + SHA256 only."
  curl -fsSL "${RELEASE_BASE}/SHA256SUMS.asc" -o "${d}/SHA256SUMS.asc" 2>/dev/null \
    || die "SHA256SUMS.asc not found for this release. Every irlume release is signed; a missing signature may mean the download was tampered with. Refusing to install. (Override at your own risk with IRLUME_INSECURE_NO_SIG=1.)"

  # Throwaway keyring holding only the pinned key: nothing else can sign,
  # and the user's own keyring is never read or written.
  kh="${d}/gnupg"
  mkdir -p "$kh" && chmod 700 "$kh"
  printf '%s\n' "$KEY_ASC" | GNUPGHOME="$kh" gpg --batch --import >/dev/null 2>&1 \
    || die "could not import the pinned irlume key; cannot verify the release signature."
  if GNUPGHOME="$kh" gpg --batch --status-fd 1 --verify "${d}/SHA256SUMS.asc" "${d}/SHA256SUMS" 2>/dev/null \
       | grep -q "VALIDSIG ${KEY_FP}"; then
    say "SHA256SUMS GPG signature verified against the pinned irlume key."
  else
    die "SHA256SUMS signature did NOT verify against the pinned irlume key ${KEY_FP}; refusing to install."
  fi
}

# Download the release asset whose SHA256SUMS line contains the fixed string $1,
# verify its checksum, and echo the local path on stdout. Aborts on mismatch.
fetch_verified() {
  match="$1"
  # No EXIT trap here: this function runs in a command-substitution subshell, so
  # an EXIT trap would delete the download the moment the path is returned. The
  # caller removes the parent dir after installing.
  tmp="$(mktemp -d)"
  fetch_sums "$tmp"
  # Anchored patterns: a future .sig/.sha256 sibling must never be selected
  # as "the package", and multiple matches are an error, not first-wins.
  # Anchored, asset-name-accurate patterns (must match the actual lane names:
  # irlume_0.10.0_amd64.deb, irlume-0.10.0-1.fc44.x86_64.rpm,
  # irlume-0.10.0-1-x86_64.pkg.tar.zst). The selinux noarch RPM must NOT match.
  case "$match" in
    '_amd64.deb')          re='^[0-9a-f]{64}[[:space:]]+irlume_[^/]*_amd64\.deb$' ;;
    *'.x86_64.rpm')        re='^[0-9a-f]{64}[[:space:]]+irlume-[0-9][^/]*'"$(printf '%s' "$match" | sed 's/[.[\*^$]/\\&/g')"'$' ;;
    '_x86_64.pkg.tar.zst') re='^[0-9a-f]{64}[[:space:]]+irlume-[0-9][^/]*-x86_64\.pkg\.tar\.zst$' ;;
    *) re='^[0-9a-f]{64}[[:space:]]+[^/]*'"$(printf '%s' "$match" | sed 's/[.[\*^$]/\\&/g')"'$' ;;
  esac
  n_matches="$(grep -Ec -- "$re" "${tmp}/SHA256SUMS" || true)"
  [ "$n_matches" -eq 1 ] || die "expected exactly one release asset matching '$match' in SHA256SUMS, found ${n_matches}."
  line="$(grep -E -- "$re" "${tmp}/SHA256SUMS")"
  name="$(printf '%s' "$line" | awk '{print $NF}')"
  say "downloading ${name} ..."
  curl -fSL --progress-bar "${RELEASE_BASE}/${name}" -o "${tmp}/${name}" \
    || die "download of ${name} failed."
  say "verifying checksum ..."
  ( cd "$tmp" && printf '%s\n' "$line" | sha256sum -c - >/dev/null 2>&1 ) \
    || die "CHECKSUM MISMATCH on ${name}; refusing to install."
  printf '%s/%s\n' "$tmp" "$name"
}

# --- Channel-resilience helpers ---------------------------------------------
# The release lane is the fallback for every distro lane. Guards make the
# fallback upgrade-only: no downgrade, no flip-flop when a lane recovers.

deb_version_installed() { dpkg-query -W -f '${Version}' irlume 2>/dev/null || true; }

# $1 = candidate version, $2 = installed version ("" = fresh install).
# Exits 0 (install) when candidate is strictly newer or nothing is installed.
should_install_deb() {
  cand="$1"; have="$2"
  [ -z "$have" ] && return 0
  dpkg --compare-versions "$cand" le "$have" && return 1
  return 0
}

install_deb_release() {
  deb="$(fetch_verified '_amd64.deb')"
  cand="$(basename "$deb" | sed -n 's/^irlume_\(.*\)_amd64.deb$/\1/p')"
  [ -n "$cand" ] || die "could not parse the release .deb filename: $(basename "$deb")"
  have="$(deb_version_installed)"
  if ! should_install_deb "$cand" "$have"; then
    say "release .deb ${cand} is not newer than the installed ${have}; already current."
    rm -rf "$(dirname "$deb")"
    return 0
  fi
  $SUDO apt-get install -y "$deb"
  rm -rf "$(dirname "$deb")"
}

install_rpm_release() {
  # Match the release RPM built for this Fedora release (fc43/fc44 assets).
  ver="${VERSION_ID:-}"
  [ -n "$ver" ] || die "Fedora family without VERSION_ID; cannot pick a release RPM. Install from Copr when it is back."
  rpm_path="$(fetch_verified ".fc${ver}.x86_64.rpm")" || \
    die "no release RPM for fc${ver} in the latest release. Install from Copr when it is back."
  # `dnf install <local.rpm>` handles both fresh install and upgrade, and is
  # a no-op ("Nothing to do") when the installed version is not older: exactly
  # the upgrade-only semantics the fallback needs (`dnf upgrade` alone cannot
  # fresh-install).
  $SUDO dnf -y install "${rpm_path}"
  rm -rf "$(dirname "${rpm_path}")"
}

install_pkg_release() {
  need vercmp
  pkg="$(fetch_verified '_x86_64.pkg.tar.zst')"
  cand="$(basename "$pkg" | sed -n 's/^irlume-\(.*\)-x86_64.pkg.tar.zst$/\1/p')"
  [ -n "$cand" ] || die "could not parse the release package filename: $(basename "$pkg")"
  have="$(pacman -Qi irlume 2>/dev/null | awk '/^Version/ {print $3}')"
  if [ -n "$have" ] && [ "$(vercmp "$cand" "$have")" -ne 1 ]; then
    say "release package ${cand} is not newer than the installed ${have}; already current."
    rm -rf "$(dirname "$pkg")"
    return 0
  fi
  $SUDO pacman -U --noconfirm "$pkg"
  rm -rf "$(dirname "$pkg")"
}

# Newest verified release package for THIS distro, upgrade-only. Used by
# IRLUME_UPDATE=1 when the primary lane is unavailable (outage) and a newer
# release (e.g. a security fix) already exists on GitHub.
update_from_release() {
  [ -r /etc/os-release ] || die "cannot read /etc/os-release; unsupported system."
  # shellcheck disable=SC1091
  . /etc/os-release
  family=" ${ID:-} ${ID_LIKE:-} "
  need curl
  need sha256sum
  case "$family" in
    *" debian "*|*" ubuntu "*) install_deb_release ;;
    *" fedora "*|*" rhel "*|*" centos "*) install_rpm_release ;;
    *" arch "*|*" archlinux "*) install_pkg_release ;;
    *) die "unrecognised distro (ID=${ID:-?}); no release-lane update available." ;;
  esac
  say "release-lane update complete."
  exit 0
}

main() {
  # Privilege: run package commands as root, via sudo when not already root.
  SUDO=""
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "need root: install sudo, or re-run this as root."
    SUDO="sudo"
  fi

  # Already installed? Stop before touching anything, and say how it got there.
  if command -v irlume >/dev/null 2>&1; then
    have="$(irlume --version 2>/dev/null || echo irlume)"
    where="$(command -v irlume)"
    say "already installed: ${have} via $(install_channel "$where")."
    say "Not installing. To update an existing install, run:  irlume update"
    if [ "${IRLUME_FORCE:-}" = "1" ]; then
      say "IRLUME_FORCE=1 set; reinstalling anyway."
    elif [ "${IRLUME_UPDATE:-}" = "1" ]; then
      # Security-update escape hatch: the distro lane may be down; pull the
      # newest verified release package instead (upgrade-only, see below).
      say "IRLUME_UPDATE=1 set; updating from the verified GitHub release lane."
      update_from_release
    else
      say "Nothing was changed. Set IRLUME_FORCE=1 to reinstall regardless, or"
      say "IRLUME_UPDATE=1 to update from the release lane if the distro channel is down."
      exit 0
    fi
  fi

  need curl
  need sha256sum

  arch="$(uname -m)"
  [ "$arch" = "x86_64" ] || die "irlume ships x86-64 packages only; '$arch' is not supported yet."
  [ -r /etc/os-release ] || die "cannot read /etc/os-release; unsupported system."
  # shellcheck disable=SC1091
  . /etc/os-release
  family=" ${ID:-} ${ID_LIKE:-} "

  # Route by distro. ID is the exact distro; ID_LIKE (folded into $family) names
  # the family for derivatives. Only real Ubuntu uses the PPA (it builds per
  # Ubuntu series); derivatives (Pop!_OS, Mint, Zorin, elementary) and Debian
  # take the checksum-verified universal .deb.
  if [ "${ID:-}" = ubuntu ]; then
    if command -v add-apt-repository >/dev/null 2>&1 \
       && $SUDO add-apt-repository -y "ppa:${REPO}" 2>/dev/null \
       && $SUDO apt-get update \
       && $SUDO apt-get install -y irlume; then
      say "installed from the signed PPA."
    else
      warn "PPA path unavailable (outage or no add-apt-repository); using the checksum-verified .deb."
      # Only a HALF-CONFIGURED package can block the .deb; a working install
      # must never be purged (the guard below needs its version, and purging a
      # PAM-facing package on a network blip is exactly the churn the
      # upgrade-only promise exists to prevent).
      status="$(dpkg-query -W -f '${Status}' irlume 2>/dev/null || true)"
      case "$status" in
        "install ok installed") : ;;  # healthy: leave it; guard compares versions
        *) $SUDO apt-get purge -y irlume >/dev/null 2>&1 || true ;;
      esac
      install_deb_release
    fi
  else
    case "$family" in
      *" fedora "*|*" rhel "*|*" centos "*)
        say "Fedora family: installing from the signed Copr repo."
        if $SUDO dnf -y copr enable "${REPO}" && $SUDO dnf -y install irlume; then
          say "installed from the signed Copr repo."
        else
          warn "Copr lane unavailable (outage?); falling back to the checksum+signature-verified release RPM."
          install_rpm_release
        fi
        ;;
      *" arch "*|*" archlinux "*)
        say "Arch: irlume ships via the AUR (it builds the signed release tag)."
        if [ "${IRLUME_RELEASE_PKG:-}" = "1" ]; then
          # pacman -U is root-safe (only makepkg/AUR helpers refuse root).
          say "IRLUME_RELEASE_PKG=1 set; installing the verified release .pkg.tar.zst (pacman -U)."
          install_pkg_release
        elif [ "$(id -u)" -eq 0 ]; then
          # AUR helpers and makepkg refuse to run as root by design.
          say "AUR builds cannot run as root. As your normal user, run:"
          say "  yay -S irlume    (or: paru -S irlume)"
          say "  or, without a helper:"
          say "  git clone https://aur.archlinux.org/irlume.git && cd irlume && makepkg -si"
          say "Nothing was changed. (Set IRLUME_RELEASE_PKG=1 for the verified release package instead.)"
          exit 0
        elif command -v yay >/dev/null 2>&1; then
          yay -S --noconfirm irlume
        elif command -v paru >/dev/null 2>&1; then
          paru -S --noconfirm irlume
        else
          say "No AUR helper found. Run:"
          say "  git clone https://aur.archlinux.org/irlume.git && cd irlume && makepkg -si"
          say "Nothing was changed."
          exit 0
        fi
        ;;
      *" debian "*|*" ubuntu "*)
        say "Debian/Ubuntu-derivative: installing the checksum-verified universal .deb."
        install_deb_release
        ;;
      *)
        die "unrecognised distro (ID=${ID:-?}). See the manual instructions at https://github.com/${REPO}#install"
        ;;
    esac
  fi

  # Machine-side prep: make sure the daemon is enabled and running. The package
  # postinst does this too; this is a safety net across packaging paths.
  $SUDO systemctl enable --now irlumed.service >/dev/null 2>&1 || true

  state="$(systemctl is-active irlumed.service 2>/dev/null || echo unknown)"
  say ""
  say "installed; the irlume daemon is ${state}. The machine side is ready."
  say ""
  say "What is left is personal and interactive (it cannot be scripted): enroll"
  say "your face or fingerprint, arm your login password, set a recovery passphrase."
  say "One guided command walks through all of it:"
  say ""
  say "  irlume tui"
  say ""
  say "or step by step:"
  say "  irlume enroll                     # scan your face (IR camera) "
  say "  irlume keyring arm                # seal your login password for wallet unlock"
  say "  irlume recovery setup             # backup passphrase, so you never lock out"
  say "  sudo irlume login enable --apply  # opt-in: wire the greeter + lock screen"
  say ""
  say "the package wired nothing into your login; auth changes only at 'login enable'."
  say "check readiness any time with:  irlume doctor"
}

# Only runs once the whole script has downloaded, so a truncated pipe is a no-op.
main "$@"
