#!/bin/sh
# irlume one-step installer.
#
#   curl -fsSL https://raw.githubusercontent.com/archledger/irlume/main/scripts/install.sh | sh
#
# What it does, by distro:
#   Fedora / RHEL family : enable the signed Copr repo, then dnf install irlume.
#   Ubuntu (current LTS)  : add the signed PPA, then apt install irlume.
#   Debian / Ubuntu deriv : download the universal .deb from the latest GitHub
#                           release, verify it, then install.
#   Arch                  : download the .pkg.tar.zst from the latest release,
#                           verify it, then pacman -U.
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
# The irlume release signing key (also signs the git tags). Pinned here so a
# compromised release cannot swap the checksums without also forging a
# signature from this exact key.
KEY_FP="F35053398E3C80FE20891B82C10B8492BD7F30C6"

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

# Fetch SHA256SUMS into $1 (a temp dir) and, when a GPG signature is published,
# verify it against the pinned key. Aborts on a bad signature; falls back to
# HTTPS + SHA256 (with a warning) when no signature or no gpg is available.
fetch_sums() {
  d="$1"
  curl -fsSL "${RELEASE_BASE}/SHA256SUMS" -o "${d}/SHA256SUMS" \
    || die "could not fetch SHA256SUMS from the latest release."
  if command -v gpg >/dev/null 2>&1 \
     && curl -fsSL "${RELEASE_BASE}/SHA256SUMS.asc" -o "${d}/SHA256SUMS.asc" 2>/dev/null; then
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$KEY_FP" >/dev/null 2>&1 \
      || gpg --list-keys "$KEY_FP" >/dev/null 2>&1 \
      || { warn "could not fetch the irlume signing key; relying on HTTPS + SHA256 only."; return 0; }
    if gpg --batch --status-fd 1 --verify "${d}/SHA256SUMS.asc" "${d}/SHA256SUMS" 2>/dev/null \
         | grep -q "VALIDSIG ${KEY_FP}"; then
      say "SHA256SUMS GPG signature verified against the pinned irlume key."
    else
      die "SHA256SUMS signature did NOT verify against the pinned irlume key ${KEY_FP}; refusing to install."
    fi
  else
    warn "no GPG signature checked (gpg absent or unsigned release); relying on HTTPS + SHA256."
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
  line="$(grep -F -- "$match" "${tmp}/SHA256SUMS" | head -n1)" || true
  [ -n "$line" ] || die "no release asset matching '$match' in SHA256SUMS."
  name="$(printf '%s' "$line" | awk '{print $NF}')"
  say "downloading ${name} ..."
  curl -fSL --progress-bar "${RELEASE_BASE}/${name}" -o "${tmp}/${name}" \
    || die "download of ${name} failed."
  say "verifying checksum ..."
  ( cd "$tmp" && printf '%s\n' "$line" | sha256sum -c - >/dev/null 2>&1 ) \
    || die "CHECKSUM MISMATCH on ${name}; refusing to install."
  printf '%s/%s\n' "$tmp" "$name"
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
    else
      say "Nothing was changed. Set IRLUME_FORCE=1 to reinstall regardless."
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
      warn "PPA path unavailable for this release; using the checksum-verified .deb."
      # Clear any half-configured PPA package first: it would otherwise block the
      # .deb as a downgrade and leave apt wedged.
      $SUDO apt-get purge -y irlume >/dev/null 2>&1 || true
      deb="$(fetch_verified '_amd64.deb')"
      $SUDO apt-get install -y "$deb"
      rm -rf "$(dirname "$deb")"
    fi
  else
    case "$family" in
      *" fedora "*|*" rhel "*|*" centos "*)
        say "Fedora family: installing from the signed Copr repo."
        $SUDO dnf -y copr enable "${REPO}"
        $SUDO dnf -y install irlume
        ;;
      *" arch "*|*" archlinux "*)
        say "Arch: installing the package from the latest release."
        pkg="$(fetch_verified '.pkg.tar.zst')"
        $SUDO pacman -U --noconfirm "$pkg"
        rm -rf "$(dirname "$pkg")"
        ;;
      *" debian "*|*" ubuntu "*)
        say "Debian/Ubuntu-derivative: installing the checksum-verified universal .deb."
        deb="$(fetch_verified '_amd64.deb')"
        $SUDO apt-get install -y "$deb"
        rm -rf "$(dirname "$deb")"
        ;;
      *)
        die "unrecognised distro (ID=${ID:-?}). See the manual instructions at https://github.com/${REPO}#-install"
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
