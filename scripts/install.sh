#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# irlume one-step installer.
#
#   curl -fsSL https://raw.githubusercontent.com/archledger/irlume/main/scripts/install.sh | sh
#
# What it does, by distro:
#   Fedora / RHEL family : enable the signed Copr repo, then dnf install irlume.
#                           Copr is the primary Fedora lane. The release-RPM
#                           fallback exists for a Copr outage and installs
#                           only when the release carries RPMs; the last
#                           release RPMs were v0.11.1's fc43/fc44 x86_64
#                           builds.
#   Ubuntu                : where the PPA serves this release (the current LTS),
#                           add it, then apt install irlume. Elsewhere, or when
#                           it is down, the verified universal .deb.
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
#     SHA256SUMS and ABORT on any mismatch. Every release also publishes a
#     GPG signature (SHA256SUMS.asc): this script verifies it against the pinned
#     irlume signing key before trusting the checksums, and refuses to install
#     when the signature is missing or does not verify.
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

# Where to report a problem: the six lines of WHERE_TO_REPORT in
# crates/irlume-cli/src/where_to_report.rs, whose test compares this copy and
# the package scripts' (packaging/arch/irlume.install,
# packaging/debian/postinstall.sh, packaging/ppa/debian/postinst) with it.
report_block() {
  warn ""
  warn "Security problem (a photo, video, mask or another person got in,"
  warn "face sign-in worked without your face, or face data was exposed),"
  warn "or not sure? Never post it publicly. Report it privately:"
  warn "https://github.com/archledger/irlume/security/advisories/new"
  warn "or the e-mail address in SECURITY.md."
  warn "Anything else: https://github.com/archledger/irlume/issues/new/choose"
  warn "Your own words are fine; paste the lines above, not the sudo prompt."
}

# A failed verification. It names the private route itself: it runs inside
# fetch_verified's $(...) subshell, where main()'s EXIT trap does not run.
die_verify() {
  printf '\033[1;31m[irlume]\033[0m %s\n' "$1" >&2
  printf '\033[1;31m[irlume]\033[0m %s\n' "Do not override verification or install the download by hand;" >&2
  printf '\033[1;31m[irlume]\033[0m %s\n' "report it privately:" >&2
  printf '\033[1;31m[irlume]\033[0m %s\n' "https://github.com/archledger/irlume/security/advisories/new" >&2
  exit 1
}

# main()'s EXIT trap. Every exit that is not 0 (a die, a command that fails
# under set -e, or a package command that fails, with its own status) ends
# here and says where to report a problem; an exit 0 adds nothing. A release
# package the release lane downloaded and did not install (its version did
# not parse, or the package command failed) is removed first; download_dir
# is empty while the package command runs and after the release lane has
# removed the directory itself. The exit status is kept.
on_exit() {
  rc=$?
  trap - EXIT
  if [ -n "${download_dir:-}" ]; then rm -rf "$download_dir" || true; fi
  if [ "$rc" -ne 0 ]; then report_block || true; fi
  exit "$rc"
}

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
    || die_verify "SHA256SUMS.asc not found for this release. Every irlume release is signed; a missing signature may mean the download was tampered with. Refusing to install."

  # Throwaway keyring holding only the pinned key: nothing else can sign,
  # and the user's own keyring is never read or written.
  kh="${d}/gnupg"
  mkdir -p "$kh" && chmod 700 "$kh"
  printf '%s\n' "$KEY_ASC" | GNUPGHOME="$kh" gpg --batch --import >/dev/null 2>&1 \
    || die_verify "could not import the pinned irlume key; cannot verify the release signature."
  if GNUPGHOME="$kh" gpg --batch --status-fd 1 --verify "${d}/SHA256SUMS.asc" "${d}/SHA256SUMS" 2>/dev/null \
       | grep -q "VALIDSIG ${KEY_FP}"; then
    say "SHA256SUMS GPG signature verified against the pinned irlume key."
  else
    die_verify "SHA256SUMS signature did NOT verify against the pinned irlume key ${KEY_FP}; refusing to install."
  fi
}

# fetch_verified's EXIT trap. An exit that is not 0 (a die, a die_verify, a
# command that fails under set -e, or one of the signals fetch_verified
# traps) removes the download directory with whatever was downloaded into
# it; an exit 0 keeps it for the release lane, which removes it once it is
# done with the package. The exit status is kept.
fetch_cleanup() {
  rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] && [ -n "$tmp" ]; then rm -rf "$tmp" || true; fi
  exit "$rc"
}

# Download the release asset whose SHA256SUMS line contains the fixed string $1,
# verify its checksum, and echo the local path on stdout. Aborts on mismatch.
# The body is a subshell, as is the $(...) each caller reads the path
# through, so the traps below are its own: main()'s EXIT trap is neither run
# nor replaced here.
fetch_verified() (
  match="$1"
  # The traps are set before mktemp runs. Until it answers, tmp is empty, so
  # the EXIT trap removes only a directory mktemp has named.
  tmp=""
  trap fetch_cleanup EXIT
  # A hangup, interrupt or termination signal that reaches this subshell (a
  # closed terminal or Ctrl-C sends one to the whole process group) ends it
  # through that trap too, with the status a shell reports for a command the
  # signal ended (128 plus its number).
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  # Checked here, not left to set -e, which bash ignores inside this
  # function when the caller adds `|| die`, as the release-RPM path does.
  tmp="$(mktemp -d)" || die "could not create a temporary directory for the download."
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
  # The path handed back is a file directly in $tmp, so the name must be a
  # plain file name: not empty, not . or .., and without a slash. Every
  # name scripts/verify-release-assets.py accepts in a release's SHA256SUMS
  # is one.
  case "$name" in
    ''|.|..|*/*) die "the SHA256SUMS entry for '${match}' is not a plain file name; refusing to download it." ;;
  esac
  say "downloading ${name} ..."
  curl -fSL --progress-bar "${RELEASE_BASE}/${name}" -o "${tmp}/${name}" \
    || die "download of ${name} failed."
  say "verifying checksum ..."
  ( cd "$tmp" && printf '%s\n' "$line" | sha256sum -c - >/dev/null 2>&1 ) \
    || die_verify "CHECKSUM MISMATCH on ${name}; refusing to install."
  printf '%s/%s\n' "$tmp" "$name"
)

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

# Install the verified release package with the package command "$@", as
# root, then remove its directory. download_dir is empty while the command
# runs, as bash runs on_exit as soon as a hangup or termination signal
# reaches the script, while the command may still be reading the package.
# A command that fails ends the run with its own exit status; on_exit then
# removes the package.
install_verified() {
  pkg_dir="$download_dir"
  download_dir=""
  pkg_rc=0
  $SUDO "$@" || pkg_rc=$?
  download_dir="$pkg_dir"
  [ "$pkg_rc" -eq 0 ] || exit "$pkg_rc"
  download_dir=""
  rm -rf "$pkg_dir"
}

install_deb_release() {
  # The archive's lists must be present for the .deb's dependencies
  # (libtss2-tctildr0 and friends come from the Ubuntu repositories), so
  # refresh what this machine already has configured - never the unserved
  # PPA - before anything else on this path. A failed refresh warns and
  # continues: the existing lists may already satisfy the dependencies.
  $SUDO apt-get update || warn "apt-get update failed; installing with the current package lists."
  deb="$(fetch_verified '_amd64.deb')"
  download_dir="$(dirname "$deb")"
  cand="$(basename "$deb" | sed -n 's/^irlume_\(.*\)_amd64.deb$/\1/p')"
  [ -n "$cand" ] || die "could not parse the release .deb filename: $(basename "$deb")"
  have="$(deb_version_installed)"
  if ! should_install_deb "$cand" "$have"; then
    say "release .deb ${cand} is not newer than the installed ${have}; already current."
    download_dir=""
    rm -rf "$(dirname "$deb")"
    return 0
  fi
  install_verified apt-get install -y "$deb"
}

install_rpm_release() {
  # Match a release RPM for this Fedora release, when one is published
  # (the last release RPMs were v0.11.1's fc43/fc44 x86_64 builds).
  ver="${VERSION_ID:-}"
  [ -n "$ver" ] || die "Fedora family without VERSION_ID; cannot pick a release RPM. Install from Copr when it is back."
  # A Fedora release number is digits (VERSION_ID=44), as is the N of the
  # .fcN a release RPM's name carries, so any other value names no release
  # RPM and stops here.
  case "$ver" in
    *[!0123456789]*) die "Fedora family with a VERSION_ID that is not a Fedora release number; cannot pick a release RPM. Install from Copr when it is back." ;;
  esac
  rpm_path="$(fetch_verified ".fc${ver}.x86_64.rpm")" || \
    die "no verified release RPM for fc${ver}; the lines above say why. Install from Copr when it is back."
  download_dir="$(dirname "${rpm_path}")"
  # `dnf install <local.rpm>` handles both fresh install and upgrade, and is
  # a no-op ("Nothing to do") when the installed version is not older: exactly
  # the upgrade-only semantics the fallback needs (`dnf upgrade` alone cannot
  # fresh-install).
  install_verified dnf -y install "${rpm_path}"
}

install_pkg_release() {
  need vercmp
  pkg="$(fetch_verified '_x86_64.pkg.tar.zst')"
  download_dir="$(dirname "$pkg")"
  cand="$(basename "$pkg" | sed -n 's/^irlume-\(.*\)-x86_64.pkg.tar.zst$/\1/p')"
  [ -n "$cand" ] || die "could not parse the release package filename: $(basename "$pkg")"
  have="$(pacman -Qi irlume 2>/dev/null | awk '/^Version/ {print $3}')"
  if [ -n "$have" ] && [ "$(vercmp "$cand" "$have")" -ne 1 ]; then
    say "release package ${cand} is not newer than the installed ${have}; already current."
    download_dir=""
    rm -rf "$(dirname "$pkg")"
    return 0
  fi
  install_verified pacman -U --noconfirm "$pkg"
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

# Does the PPA publish an installable irlume for Ubuntu series $1? Asked the way
# `irlume update` asks it: of the binary index, as a Release file outlives a
# series' packages. Exits 0 for yes, 1 for no, 2 when it cannot tell. curl -f
# uses 22 for any HTTP error; only a separately reported 404 proves the
# series absent. An error that reports no code at all fails safe the same
# way: a machine the PPA does not serve must not be left a source apt cannot
# use.
ppa_serves() {
  index="$(mktemp)"
  answer=2
  curl_status=0
  http_status=$(curl -fsS --max-time 15 -w '%{http_code}' -o "$index" \
      "https://ppa.launchpadcontent.net/${REPO}/ubuntu/dists/$1/main/binary-amd64/Packages.gz" 2>/dev/null) || curl_status=$?
  if [ "$curl_status" -eq 0 ]; then
    if gzip -t "$index" 2>/dev/null; then
      if gzip -dc "$index" | grep -qx 'Package: irlume'; then answer=0; else answer=1; fi
    fi
  elif [ "$curl_status" -eq 22 ]; then
    # A reported 404 is the PPA itself saying the series is absent. A reported
    # 429/500/503 is an outage: not proof of absence, so the PPA is still
    # tried (answer stays 2). No code reported at all proves nothing either
    # way: do not add the PPA on the chance the series is unserved, as that
    # leaves a source that fails every later apt-get update on this machine.
    if [ "$http_status" = 404 ] || [ -z "$http_status" ]; then
      answer=1
    fi
  fi
  rm -f "$index"
  return "$answer"
}

main() {
  # The directory on_exit removes: empty, whatever the environment holds,
  # until the release lane has downloaded and verified a package.
  download_dir=""
  # Next, so every later exit runs it. A $(...) subshell does not.
  trap on_exit EXIT

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
    # A series the PPA does not serve must not get it added: where the PPA has no
    # Release file for it, which is 22.04's case, the source would fail every
    # later `apt update` on this machine, long after this script has finished.
    ppa_answer=0
    ppa_serves "${VERSION_CODENAME:-}" || ppa_answer=$?
    if [ "$ppa_answer" -eq 1 ]; then
      say "the PPA carries only the current Ubuntu LTS, not ${VERSION_CODENAME:-this release}; using the checksum-verified .deb."
      install_deb_release
    elif command -v add-apt-repository >/dev/null 2>&1 \
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

  # is-active prints the state even when it exits non-zero.
  state="$(systemctl is-active irlumed.service 2>/dev/null)" || true
  [ -n "$state" ] || state=unknown
  say ""
  if [ "$state" = active ]; then
    say "installed; the irlume daemon is active. The machine side is ready."
  else
    warn "installed, but the irlume daemon is ${state}, not active."
    warn "The machine side is not ready. See why with:"
    warn "  systemctl status irlumed.service"
    report_block
  fi
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
