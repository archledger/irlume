#!/bin/sh
# irlume one-step installer.
#
#   curl -fsSL https://raw.githubusercontent.com/archledger/irlume/main/scripts/install.sh | sh
#
# What it does, by distro:
#   Fedora / RHEL family : enable the signed Copr repo, then dnf install irlume.
#   Ubuntu (current LTS)  : add the signed PPA, then apt install irlume.
#   Debian / Ubuntu deriv : download the universal .deb from the latest GitHub
#                           release, verify it against SHA256SUMS, then install.
#   Arch                  : download the .pkg.tar.zst from the latest release,
#                           verify it against SHA256SUMS, then pacman -U.
#
# The repo paths (Fedora, Ubuntu-LTS) are cryptographically verified by dnf/apt.
# The release-asset paths verify a SHA256 checksum and abort on any mismatch.
#
# This installs a package only. It wires NOTHING into your login: face auth
# changes only when you later run `irlume login enable`. To read this script
# before running it:
#   curl -fsSL https://raw.githubusercontent.com/archledger/irlume/main/scripts/install.sh -o install.sh
#   less install.sh && sh install.sh
set -eu

REPO="archledger/irlume"
RELEASE_BASE="https://github.com/${REPO}/releases/latest/download"

# All logging goes to stderr so command substitutions (fetch_verified) capture
# only the data on stdout, never these messages.
say()  { printf '\033[1;34m[irlume]\033[0m %s\n' "$1" >&2; }
warn() { printf '\033[1;33m[irlume]\033[0m %s\n' "$1" >&2; }
die()  { printf '\033[1;31m[irlume]\033[0m %s\n' "$1" >&2; exit 1; }

# Run a privileged command as root, via sudo when we are not already root.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "need root: install sudo, or re-run this as root."
  SUDO="sudo"
fi

need() { command -v "$1" >/dev/null 2>&1 || die "this installer needs '$1' but it is not on PATH."; }

# Already installed? Stop before touching anything, and say why. This installer
# is for a first install; upgrades go through the tool itself or the package
# manager, which know how irlume was installed and won't clobber your setup.
if command -v irlume >/dev/null 2>&1; then
  have="$(irlume --version 2>/dev/null || echo irlume)"
  where="$(command -v irlume)"
  say "already installed: ${have} (${where})."
  say "Not installing. To update an existing install, run:  irlume update"
  say "(or use your package manager: dnf/apt/pacman upgrade irlume)."
  if [ "${IRLUME_FORCE:-}" = "1" ]; then
    say "IRLUME_FORCE=1 set; reinstalling anyway."
  else
    say "Nothing was changed. Set IRLUME_FORCE=1 to reinstall regardless."
    exit 0
  fi
fi

need curl
need sha256sum

# --- platform detection ------------------------------------------------------
arch="$(uname -m)"
[ "$arch" = "x86_64" ] || die "irlume ships x86-64 packages only; '$arch' is not supported yet."

[ -r /etc/os-release ] || die "cannot read /etc/os-release; unsupported system."
# shellcheck disable=SC1091
. /etc/os-release
family="${ID:-} ${ID_LIKE:-}"

# Download the asset named on the SHA256SUMS line matching $1 (a filename
# fragment), verify its checksum, and echo the local path. Aborts on mismatch.
fetch_verified() {
  match="$1"
  sums="$(curl -fsSL "${RELEASE_BASE}/SHA256SUMS")" \
    || die "could not fetch SHA256SUMS from the latest release."
  line="$(printf '%s\n' "$sums" | grep -- "$match" | head -n1)" \
    || true
  [ -n "$line" ] || die "no release asset matching '$match' in SHA256SUMS."
  name="$(printf '%s' "$line" | awk '{print $NF}')"
  tmp="$(mktemp -d)"
  say "downloading ${name} ..."
  curl -fSL --progress-bar "${RELEASE_BASE}/${name}" -o "${tmp}/${name}" \
    || die "download of ${name} failed."
  say "verifying checksum ..."
  ( cd "$tmp" && printf '%s\n' "$line" | sha256sum -c - >/dev/null 2>&1 ) \
    || die "CHECKSUM MISMATCH on ${name}; refusing to install. Delete ${tmp} and retry."
  printf '%s/%s\n' "$tmp" "$name"
}

case " $family " in
  *" fedora "*|*" rhel "*|*" centos "*)
    say "Fedora family: installing from the signed Copr repo."
    $SUDO dnf -y copr enable "${REPO}"
    $SUDO dnf -y install irlume
    ;;
  *" ubuntu "*)
    # The PPA carries the current Ubuntu LTS. On a supported release use it
    # (signed); otherwise fall through to the universal .deb below.
    if command -v add-apt-repository >/dev/null 2>&1; then
      say "Ubuntu: adding the signed PPA."
      if $SUDO add-apt-repository -y "ppa:${REPO}" 2>/dev/null; then
        $SUDO apt-get update
        $SUDO apt-get install -y irlume
      else
        warn "PPA not available for this release; using the universal .deb."
        deb="$(fetch_verified '_amd64.deb')"
        $SUDO apt-get install -y "$deb"
      fi
    else
      deb="$(fetch_verified '_amd64.deb')"
      $SUDO apt-get install -y "$deb"
    fi
    ;;
  *" debian "*)
    say "Debian: installing the universal .deb from the latest release."
    deb="$(fetch_verified '_amd64.deb')"
    $SUDO apt-get install -y "$deb"
    ;;
  *" arch "*|*" archlinux "*)
    say "Arch: installing the package from the latest release."
    pkg="$(fetch_verified '.pkg.tar.zst')"
    $SUDO pacman -U --noconfirm "$pkg"
    ;;
  *)
    die "unrecognised distro (ID=${ID:-?}). See the manual instructions at https://github.com/${REPO}#-install"
    ;;
esac

say "installed. Next:"
printf '  irlume tui                         # enroll your face + configure, guided\n'
printf '  sudo irlume login enable --apply   # opt-in: wire the greeter + lock screen\n'
say "the package wired nothing into your login; auth changes only when you run 'login enable'."
