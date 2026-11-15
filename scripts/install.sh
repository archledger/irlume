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
# fetch_verified's subshell, where main()'s EXIT trap does not run.
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
# not parse, or the package command failed) is removed first: download_dir
# when it is held, or pkg_dir when no package job is outstanding. A running
# or suspended job keeps the verified package to read. After ordinary cleanup
# pkg_dir is empty so a recreated directory at the old path is never removed.
# The exit status is kept.
# Capture the sole direct job in the current shell, then a completion marker.
# Query and write failures are independently unknown: neither a failed query
# nor Bash returning zero after a failed jobs write may become a no-job report.
# Parent-shell redirection is required: a command-substitution subshell cannot
# see Dash's job table.
job_capture() {
  job_path="$1"
  : > "$job_path" 2>/dev/null || return 1
  LC_ALL=C jobs -l >> "$job_path" 2>/dev/null || return 1
  printf '%s\n' 'irlume-job-state-version-1' >> "$job_path" 2>/dev/null || return 1
  [ -s "$job_path" ]
}

# A valid report is either the marker alone (no job) or one state line followed
# by the marker. Empty output is never accepted as a report. Parse both Dash's
# separated job marker and Bash's attached one; malformed layouts are unknown.
job_report_state() {
  awk -v marker='irlume-job-state-version-1' \
    'NR == 1 {
      if ($0 == marker) { no_job = 1; next }
      seen_job = 1
      if ($1 ~ /^\[[0-9]+\][+-]$/ && $2 ~ /^[0-9]+$/) state = $3
      else if ($1 ~ /^\[[0-9]+\]$/ && $2 ~ /^[+-]$/ && $3 ~ /^[0-9]+$/) state = $4
      else state = "unknown"
      next
    }
    $0 == marker { markers++; next }
    { invalid = 1 }
    END {
      if (no_job && NR == 1 && !markers && !invalid) printf ""
      else if (seen_job && NR == 2 && markers == 1 && !invalid) print state
      else print "unknown"
    }' "$1" 2>/dev/null
}

package_job_outstanding() {
  # Only the validated marker alone or Done proves no outstanding job. A failed
  # or malformed report, including an I/O failure Bash does not return, keeps
  # the package conservatively rather than deleting it under a live manager.
  job_capture "$job_report" || return 0
  job_state="$(job_report_state "$job_report")" || job_state="unknown"
  case "$job_state" in
    ''|Done*) return 1 ;;
    *) return 0 ;;
  esac
}
on_exit() {
  rc=$?
  trap - EXIT
  if [ -n "${fetch_done:-}" ]; then
    # A completion record precedes the first normal reap. Before it exists,
    # only a reported live/stopped current child can be signalled. Completed
    # or unclear states never select a numeric PID for termination.
    trap '' HUP INT TERM
    fetch_keep="${fetch_keep:--}"
    fetch_cancel_waited=0
    if [ ! -f "$fetch_done" ] && ! fetch_cancel "$fetch_done" "$fetch_job_report"; then
      fetch_keep="keep"
    else
      wait 2>/dev/null || true
      fetch_cancel_waited=1
    fi
    # Cancellation can make the worker publish after this trap began. Honor
    # the record's disposition too: keep means an inner state was unknown and
    # a download may still be active even though the publisher itself exited.
    fetch_honor_disposition "$fetch_done"
    if [ "${fetch_keep:-}" = keep ] && [ "$fetch_cancel_waited" = 1 ] && \
       [ -f "$fetch_done" ] && [ -f "${download_dir}/.command-complete" ]; then
      # Both publishing shells were waited. A raw downloader may still need
      # the directory, but no shell remains to recreate these report files.
      rm -f "$fetch_done" "$fetch_done.part" "$fetch_job_report" \
        "${download_dir}/.command-complete" "${download_dir}/.command-complete.part" \
        "${download_dir}/.command-jobs" "${download_dir}/.command-child-jobs" || true
    fi
    fetch_done=""
  fi
  if [ -n "${download_dir:-}" ] && [ "${fetch_keep:-}" != keep ]; then
    rm -f "${download_dir}/.fetch-complete" "${download_dir}/.fetch-complete.part" \
      "${download_dir}/.fetch-jobs" "${download_dir}/.command-complete" \
      "${download_dir}/.command-complete.part" "${download_dir}/.command-jobs" \
      "${download_dir}/.command-child-jobs" || true
    rm -rf "$download_dir" || true
  elif [ -n "${pkg_dir:-}" ]; then
    if [ -z "${job_report:-}" ] || ! package_job_outstanding; then
      rm -rf "$pkg_dir" || true
    fi
  fi
  if [ -n "${job_report:-}" ]; then rm -f "$job_report" || true; fi
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
  fetch_run curl -fsSL "${RELEASE_BASE}/SHA256SUMS" -o "${d}/SHA256SUMS" \
    || die "could not fetch SHA256SUMS from the latest release."

  if [ "${IRLUME_INSECURE_NO_SIG:-}" = "1" ]; then
    warn "IRLUME_INSECURE_NO_SIG=1 set: skipping GPG signature verification (HTTPS + SHA256 only)."
    return 0
  fi

  command -v gpg >/dev/null 2>&1 \
    || die "gpg is required to verify the release signature. Install gnupg, or (not recommended) set IRLUME_INSECURE_NO_SIG=1 to trust HTTPS + SHA256 only."
  fetch_run curl -fsSL "${RELEASE_BASE}/SHA256SUMS.asc" -o "${d}/SHA256SUMS.asc" 2>/dev/null \
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

# Publish status and cleanup disposition in one atomic rename. Publication is
# the last operation observable by another process. A normal parent waits
# for it before the first reaping wait. A standalone failing download removes
# its private directory only after saving the status it will actually return.
fetch_publish() {
  rc="$1"
  trap - EXIT
  printf '%s %s\n' "$rc" "${fetch_keep:--}" > "$fetch_completion.part"
  mv "$fetch_completion.part" "$fetch_completion"
  if [ "${auto_tmp:-0}" -eq 1 ]; then
    rm -f "$fetch_completion"
    if [ "$rc" -ne 0 ] && [ "${fetch_keep:-}" != keep ]; then
      rm -rf "$tmp"
    fi
  fi
  exit "$rc"
}

# Determine the current job, using a parent-shell redirection: a jobs command
# substitution cannot see dash's own job table. Each shell owns only its direct
# asynchronous job. Unknown output never authorizes a signal or removal, and
# never fakes activity. A failed report/write is unknown; a successful empty
# report means the job is gone.
fetch_job_state() {
  fetch_state=unknown
  job_capture "$1" || return 0
  state="$(job_report_state "$1")" || state=unknown
  case "$state" in
    Running|Stopped*|Suspended*) fetch_state=running ;;
    ''|Done*|Terminated*|Killed*|Interrupt*|Hangup*|Exit*) fetch_state=finished ;;
    *) fetch_state=unknown ;;
  esac
}

# Cancel one direct child only when publication is absent and its job is
# observably live or stopped. If the child exited between inspection and kill,
# it has not been reaped yet, so its PID is still owned here. wait then reaps
# that exact child before any directory cleanup.
fetch_cancel() {
  [ -n "${1:-}" ] || return 0
  [ ! -f "$1" ] || return 0
  [ -n "${!-}" ] || return 0
  fetch_job_state "$2"
  case "$fetch_state" in
    running)
      kill -s TERM "${!-}" 2>/dev/null || true
      wait "${!-}" 2>/dev/null || true
      return 0
      ;;
    finished) return 0 ;;
    unknown) return 1 ;;
  esac
}

# Wait for publication before the first normal reap. The initial state is
# finished so an already-published worker can be reaped without jobs being
# queried. A terminal jobs report may consume Dash's saved status, and a
# missing completion is therefore unknown, not success. Once read, the record
# is the status authority: wait is reap-only and cannot turn it into 127.
fetch_wait() {
  fetch_wait_rc=0
  fetch_keep=""
  fetch_state=finished
  while [ ! -f "$1" ]; do
    fetch_job_state "$2"
    case "$fetch_state" in
      running) sleep 0.1 ;;
      finished) break ;;
      unknown) fetch_keep="keep"; return 1 ;;
    esac
  done
  if [ ! -f "$1" ]; then
    fetch_keep="keep"
    return 1
  fi
  IFS=' ' read -r fetch_wait_rc fetch_keep < "$1" || {
    fetch_wait_rc=1
    fetch_keep="keep"
  }
  case "$fetch_keep" in
    keep) [ "$fetch_wait_rc" -ne 0 ] || fetch_wait_rc=1 ;;
    -) ;;
    *) fetch_keep="keep"; fetch_wait_rc=1 ;;
  esac
  wait "${!-}" 2>/dev/null || true
  return "$fetch_wait_rc"
}

# Propagate cleanup disposition without replacing the cancellation status.
# A missing record leaves the current disposition unchanged. A keep or an
# unreadable/invalid record is always conservative, at every nested parent.
fetch_honor_disposition() {
  [ -f "$1" ] || return 0
  if IFS=' ' read -r _ fetch_completion_keep < "$1"; then
    case "$fetch_completion_keep" in
      keep) fetch_keep="keep" ;;
      -) ;;
      *) fetch_keep="keep" ;;
    esac
  else
    fetch_keep="keep"
  fi
}

fetch_abort() {
  rc="$1"
  trap '' HUP INT TERM
  if ! fetch_cancel "$fetch_command_done" "${fetch_abort_report:-$fetch_command_report}"; then
    fetch_keep="keep"
  else
    wait 2>/dev/null || true
  fi
  fetch_honor_disposition "$fetch_command_done"
  exit "$rc"
}
fetch_run() {
  fetch_command_done="${tmp}/.command-complete"
  fetch_command_report="${tmp}/.command-jobs"
  fetch_command_child_report="${tmp}/.command-child-jobs"
  rm -f "$fetch_command_done" "$fetch_command_done.part" "$fetch_command_report" \
    "$fetch_command_child_report"
  (
    auto_tmp=0
    # Parent and child own different job tables. Their report writes must not
    # truncate one another and make a live job look transiently empty.
    fetch_abort_report="$fetch_command_child_report"
    fetch_completion="$fetch_command_done"
    trap 'fetch_publish "$?"' EXIT
    trap 'fetch_abort 129' HUP
    trap 'fetch_abort 130' INT
    trap 'fetch_abort 143' TERM
    # A foreground download could defer this publisher's own trap. Wait on it
    # asynchronously so cancellation reaches the child, then publish.
    env --default-signal=HUP,INT,TERM "$@" &
    command_rc=0
    wait "${!-}" || command_rc=$?
    fetch_abort "$command_rc"
  ) &
  command_rc=0
  fetch_wait "$fetch_command_done" "$fetch_command_report" || command_rc=$?
  rm -f "$fetch_command_done" "$fetch_command_done.part" "$fetch_command_report" \
    "$fetch_command_child_report"
  if [ "$command_rc" -gt 128 ]; then
    fetch_abort "$command_rc"
  fi
  return "$command_rc"
}

# fetch_verified's EXIT trap. A parent-owned directory survives publication
# and reaping; its parent decides when to delete it. In standalone mode,
# fetch_publish removes the directory after recording a failure. Unknown state
# always preserves the directory. Every marker is inside that private directory.
fetch_cleanup() {
  rc=$?
  trap - EXIT
  # A failed mktemp leaves no private directory and no legitimate completion
  # path. Never turn that empty directory into a file beside a shared tmp root.
  if [ -z "$tmp" ]; then
    exit "$rc"
  fi
  if [ -n "$tmp" ] && [ "${fetch_keep:-}" != keep ]; then
    rm -f "${tmp}/.command-complete" "${tmp}/.command-complete.part" \
      "${tmp}/.command-jobs" "${tmp}/.command-child-jobs" || true
  fi
  fetch_completion="${tmp}/.fetch-complete"
  fetch_publish "$rc"
}

# Download and verify the release asset whose SHA256SUMS line contains $1.
# $2 is the already parent-owned temporary directory; a one-argument call for
# the standalone test still creates its own. The result path is the only
# stdout line. Fetch helpers make each command wait interruptible, so killing
# this subshell also cancels its active network command before directory
# cleanup, rather than only moving Bash's deferred trap down one level. The
# body uses braces: & already supplies the worker subshell, and another pair
# of parentheses would separate its PID from the shell that owns these traps.
fetch_verified() {
  match="$1"
  tmp="${2:-}"
  auto_tmp=0
  fetch_keep=""
  fetch_command_done=""
  fetch_command_report=""
  trap fetch_cleanup EXIT
  trap 'fetch_abort 129' HUP
  trap 'fetch_abort 130' INT
  trap 'fetch_abort 143' TERM
  if [ -z "$tmp" ]; then
    auto_tmp=1
    tmp="$(mktemp -d)" || die "could not create a temporary directory for the download."
  fi
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
  fetch_run curl -fSL --progress-bar "${RELEASE_BASE}/${name}" -o "${tmp}/${name}" \
    || die "download of ${name} failed."
  say "verifying checksum ..."
  ( cd "$tmp" && printf '%s\n' "$line" | sha256sum -c - >/dev/null 2>&1 ) \
    || die_verify "CHECKSUM MISMATCH on ${name}; refusing to install."
  printf '%s/%s\n' "$tmp" "$name"
}

# Start one verified fetch in the background. download_dir is assigned before
# the worker can receive a signal, so on_exit already owns its directory.
# The worker and its current network command each have their own direct job;
# waiting for both levels stops cancellation at a foreground command wait.
# Answer reading and validation use shell builtins, not another deferred
# command substitution. download_dir remains owned on every failure path.
fetch_release() {
  fetch_keep=""
  download_dir="$(mktemp -d)" || {
    printf '\033[1;31m[irlume]\033[0m %s\n' "could not create a temporary directory for the download." >&2
    return 1
  }
  fetch_done="${download_dir}/.fetch-complete"
  fetch_job_report="${download_dir}/.fetch-jobs"
  fetch_rc=0
  fetch_verified "$1" "$download_dir" > "$download_dir/.fetch-result" &
  fetch_wait "$fetch_done" "$fetch_job_report" || fetch_rc=$?
  # An unclear state or keep record deliberately preserves directory and
  # report ownership. Otherwise publication allowed the reap-only wait.
  if [ "$fetch_state" != unknown ] && [ "$fetch_keep" != keep ]; then
    rm -f "$fetch_done" "$fetch_done.part" "$fetch_job_report"
    fetch_done=""
  fi
  [ "$fetch_rc" -eq 0 ] || return "$fetch_rc"
  result=""
  IFS= read -r result < "$download_dir/.fetch-result" || return 1
  case "$result" in
    "$download_dir"/*) result_name=${result#"$download_dir"/} ;;
    *) return 1 ;;
  esac
  case "$result_name" in
    ''|.|..|*/*) return 1 ;;
  esac
  [ -f "$result" ] || return 1
  rm -f "$download_dir/.fetch-result" || return 1
  fetch_result="$result"
  return 0
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

# Install the verified release package with the package command "$@", as
# root, then remove its directory. The package is this shell's only
# asynchronous job; exec keeps it a direct child. GNU env resets dispositions
# in that child without a wrapper, including SIGINT inherited as ignored,
# which POSIX shells cannot restore with trap. wait is
# interruptible by a trapped signal, so on_exit runs while the child may still
# read the verified file. Its job-state test preserves an outstanding child
# and removes the download before launch, after reaping, or on ordinary
# failure. No PID liveness or /proc permission check is involved.
install_verified() {
  pkg_dir="$download_dir"
  download_dir=""
  pkg_rc=0
  job_report="$pkg_dir/.package-jobs"
  # A background shell substitutes /dev/null for stdin, but only fd 0.
  # Save the caller's input and duplicate it over stdin before exec, so sudo
  # sees the original stream without needing any extra descriptor preserved.
  exec 9<&0
  (
    # Unlike trap here, env --default-signal also resets an inherited ignore.
    # exec keeps env and then the package command in this same direct child.
    exec env --default-signal=HUP,INT,TERM $SUDO "$@" <&9
  ) &
  exec 9<&-
  wait "$!" || pkg_rc=$?
  download_dir="$pkg_dir"
  [ "$pkg_rc" -eq 0 ] || exit "$pkg_rc"
  download_dir=""
  rm -rf "$pkg_dir"
  rm -f "$job_report"
  pkg_dir=""
  job_report=""
}

install_deb_release() {
  # The archive's lists must be present for the .deb's dependencies
  # (libtss2-tctildr0 and friends come from the Ubuntu repositories), so
  # refresh what this machine already has configured - never the unserved
  # PPA - before anything else on this path. A failed refresh warns and
  # continues: the existing lists may already satisfy the dependencies.
  $SUDO apt-get update || warn "apt-get update failed; installing with the current package lists."
  fetch_release '_amd64.deb'
  deb="$fetch_result"
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
  fetch_release ".fc${ver}.x86_64.rpm" || \
    die "no verified release RPM for fc${ver}; the lines above say why. Install from Copr when it is back."
  rpm_path="$fetch_result"
  # `dnf install <local.rpm>` handles both fresh install and upgrade, and is
  # a no-op ("Nothing to do") when the installed version is not older: exactly
  # the upgrade-only semantics the fallback needs (`dnf upgrade` alone cannot
  # fresh-install).
  install_verified dnf -y install "${rpm_path}"
}

install_pkg_release() {
  need vercmp
  fetch_release '_x86_64.pkg.tar.zst'
  pkg="$fetch_result"
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
  need env
  need mv
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
  pkg_dir=""
  job_report=""
  fetch_result=""
  fetch_done=""
  fetch_job_report=""
  # Next, so every later ordinary exit runs it. A $(...) subshell does not.
  trap on_exit EXIT
  # Route signals through it too. install_verified resets dispositions only
  # in its asynchronous child with GNU env, never in this parent shell.
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

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
  need env
  need mv

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
