#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Tests the channel scripts/install.sh chooses and what it prints when an
# install fails or succeeds, without the network or root. Stand-ins first on
# PATH log what they are asked. A copy of the script reads a fixture for
# /etc/os-release and adds test-only self-signals at exact handoff boundaries;
# a second copy of that one calls fetch_verified instead of main on its last
# line. Real gzip and grep judge
# a real gzipped index, so a check of the wrong thing still fails here.
# Every run keeps its exit status, and its stdout stays empty: install.sh's
# own lines go to stderr.
#
#   bash scripts/test-install-script.sh
#
# The copies run under the first `sh` on PATH (dash on Ubuntu, bash on
# Fedora); put a directory holding an `sh` link to another shell first on
# PATH to run them under that shell.
#
# Checked, on Ubuntu:
#   - a PPA that lists irlume for this series is added
#   - a series the PPA has no index for (HTTP 404) never gets it added: on one
#     with no Release file either, the source fails every later `apt update`
#   - an index that does not list irlume (a Release file outlives a series'
#     packages) never gets it added either
#   - when the PPA cannot answer (offline, or bytes that are not gzip), the
#     script still tries it, as an outage should not change the channel
#   - a transient HTTP 429/500/503 is the same: a server error is not proof
#     the PPA has no such series, so the script still tries it
#   - a curl that exits on an HTTP error without reporting a code never gets
#     the PPA added either: it cannot prove the series exists, and a source
#     apt cannot use outlives this script. Defensive only: known curl
#     versions report the code on -f errors, so no_code pins the contract
# Elsewhere:
#   - Debian and an Ubuntu derivative go straight to the release .deb, without
#     asking the PPA at all
# What it prints:
#   - an install that succeeds exits 0, says the machine side is ready, and
#     names no place to report a problem; neither does a run that finds
#     irlume already installed, which changes nothing and exits 0
#   - every failure exits non-zero (a die exits 1; a failing package command
#     keeps its own status, as apt-get's 100) and ends with where to report a
#     problem, once: a die at the first check (no sudo), a die (the release
#     cannot be fetched), a package command that fails with no die line of
#     the script's own (Arch's AUR helper, apt-get installing the release
#     .deb, dnf installing the release RPM), a signal that ends the release
#     download but not the script's shell, and a die after a die in a $(...)
#     subshell (Fedora's release-RPM fallback)
#   - a missing or bad signature, a key that cannot be imported and a
#     checksum mismatch also say not to override verification and name the
#     private route themselves, and never name the override variable
#   - a daemon that is not active after the install is named with its state,
#     or as unknown when systemctl gives none (no systemd), followed by where
#     to report; the exit status stays 0
#   - a Fedora VERSION_ID that is not a Fedora release number (9.4, 44+,
#     44|) stops the release-RPM fallback at its own die, before anything
#     is fetched
#   - a SHA256SUMS that holds a NUL byte, which grep reads as binary data
#     and prints no line of, so it gives no file name, stops the release
#     lane before the asset is fetched
# fetch_verified, called by itself from the second copy:
#   - a SHA256SUMS line its pattern selects whose name is not a plain file
#     name (one with a slash, . or ..) is refused before anything but
#     SHA256SUMS and its signature is fetched. No caller's pattern selects
#     such a name, so the test passes a match whose pattern does
# What it leaves:
#   - nothing in its temporary directory, which starts empty for every run:
#     not after a release download that is refused, breaks off or is
#     interrupted (SIGHUP, SIGINT, SIGTERM, each ending the run with 128 plus
#     its number) before a package job starts or after wait has reaped it,
#     a signature or checksum that does not verify, a release
#     .deb whose name gives no version, or a package command that fails
#     (apt-get on Debian, dnf on Fedora), and not after an install, where
#     the caller removes the directory once the package manager has read the
#     verified file
#   - a TMPDIR that does not exist stops the release lane at its own die,
#     before anything is fetched
#   - the verified .deb, when SIGTERM ends the script's shell, and not
#     apt-get, while apt-get installs it: apt-get still finds the file
#   - a directory made at the download directory's path after the install
#     removed it: the script's exit removes only a directory it still holds
#
# Every run starts with SIGHUP, SIGINT and SIGTERM at their defaults, as in a
# terminal, whatever this harness inherited (a job started with nohup, or
# with & by a shell without job control, ignores some of them, and a shell
# cannot trap a signal ignored on entry); that needs `env --default-signal`
# (GNU coreutils 8.31 or newer).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
script="$root/scripts/install.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sed "s#/etc/os-release#$work/os-release#g" "$script" > "$work/install.sh"
[ "$(grep -c "$work/os-release" "$work/install.sh")" -ge 2 ] \
  || { echo "test-install-script: install.sh no longer reads /etc/os-release" >&2; exit 1; }
# Harness-only boundary signals. pre_launch has no child; post_wait follows
# reaping and precedes ownership restoration. post_launch is present once the
# implementation has a direct asynchronous child and covers the launch/wait
# boundary before wait starts. fetch_delay signals only the captured installer
# PID while its download is active. Production has no signal-injection branch.
# Single-quoted sed templates produce literal shell expansions in the copy.
# shellcheck disable=SC2016
sed -e 's/^main() {$/main() {\n  printf "%s\\n" "$$" > "${TEST_DIR:?}\/installer-pid"/' \
    -e 's/^  pkg_rc=0$/  [ "${TEST_APT:-}" != pre_launch ] || kill -s "${TEST_SIGNAL:-TERM}" "$$"\n  pkg_rc=0/' \
    -e 's/^  \$SUDO "\$@" || pkg_rc=$?$/  $SUDO "$@" || pkg_rc=$?\n  [ "${TEST_APT:-}" != post_wait ] || kill -s "${TEST_SIGNAL:-TERM}" "$$"/' \
    -e 's/^  wait "\$!" || pkg_rc=$?$/  wait "$!" || pkg_rc=$?\n  [ "${TEST_APT:-}" != post_wait ] || kill -s "${TEST_SIGNAL:-TERM}" "$$"/' \
    -e 's/^  fetch_wait "\$fetch_done" "\$fetch_job_report" || fetch_rc=$?$/  fetch_wait "$fetch_done" "$fetch_job_report" || fetch_rc=$?\n  [ "${TEST_RELEASE:-}" != fetch_after_wait ] || kill -s "${TEST_SIGNAL:-TERM}" "$$"/' \
    -e 's/^  exec 9<&-$/  exec 9<\&-\n  [ "${TEST_APT:-}" != post_launch ] || kill -s "${TEST_SIGNAL:-TERM}" "$$"/' \
    "$work/install.sh" > "$work/install-boundaries.sh"
mv "$work/install-boundaries.sh" "$work/install.sh"
# Harness-only report failure: empty a job report by writing to /dev/full.
# shellcheck disable=SC2016
sed -e 's#^  job_capture "\$job_report" || return 0$#  job_capture "${TEST_REPORT_PATH:-$job_report}" || return 0#' \
  "$work/install.sh" > "$work/install-report-failure.sh"
mv "$work/install-report-failure.sh" "$work/install.sh"
[ "$(grep -c 'TEST_REPORT_PATH:-' "$work/install.sh")" = 1 ] \
  || { echo "test-install-script: job report substitution failed" >&2; exit 1; }
[ "$(grep -c 'TEST_APT:-.*pre_launch' "$work/install.sh")" = 1 ] \
  || { echo "test-install-script: pre-launch boundary substitution failed" >&2; exit 1; }
[ "$(grep -c 'TEST_APT:-.*post_wait' "$work/install.sh")" = 1 ] \
  || { echo "test-install-script: post-wait boundary substitution failed" >&2; exit 1; }
has_background_package=0
if grep -q '^  exec 9<&-$' "$script"; then
  has_background_package=1
  [ "$(grep -c 'TEST_APT:-.*post_launch' "$work/install.sh")" = 1 ] \
    || { echo "test-install-script: post-launch boundary substitution failed" >&2; exit 1; }
fi
has_async_fetch=1
[ "$(grep -c 'TEST_RELEASE:-.*fetch_after_wait' "$work/install.sh")" = 1 ] \
  || { echo "test-install-script: fetch post-wait substitution or wait form changed" >&2; exit 1; }
# Lifecycle probes use the production functions, never an installer run. The
# failed-query case owns a real active child; status cases use a completed
# publication record before their direct child's first reap.
# Harness-only shared-directory attacker: before the publication redirect,
# point its .part file at a known target. The production script has no such
# branch; its original redirect performs the actual vulnerable operation.
# shellcheck disable=SC2016
sed -e 's#^  printf .* > "$fetch_completion.part"$#  case "${TEST_ATTACK_PART:-}" in\n    outer) ln -s "$TEST_PROBE_DIR/protected-target" "${tmp}.fetch-complete.part" ;;\n    command) ln -s "$TEST_PROBE_DIR/protected-target" "${tmp}.command-complete.part" ;;\n  esac\n  &#' \
  "$script" > "$work/lifecycle-bindings.sh"
# Read each successful publication before the normal command cleanup. The
# expected legacy paths above are independent of the new private assignments.
# shellcheck disable=SC2016
sed -e 's#^  mv "\$fetch_completion.part" "\$fetch_completion"$#  &\n  case "${TEST_ATTACK_PART:-}" in\n    outer|command) cat "\$fetch_completion" > "\$probe_dir/\${TEST_ATTACK_PART}-record" ;;\n  esac#' \
  "$work/lifecycle-bindings.sh" > "$work/lifecycle-publication.sh"
mv "$work/lifecycle-publication.sh" "$work/lifecycle-bindings.sh"
sed 's/^fetch_wait() {$/fetch_wait_real() {/' \
  "$work/lifecycle-bindings.sh" > "$work/lifecycle-waits.sh"
mv "$work/lifecycle-waits.sh" "$work/lifecycle-bindings.sh"
sed '/^main "\$@"$/d' "$work/lifecycle-bindings.sh" > "$work/lifecycle-probes.sh"
# shellcheck disable=SC2016
[ "$(grep -cF 'ln -s "$TEST_PROBE_DIR/protected-target" "${tmp}.fetch-complete.part"' "$work/lifecycle-probes.sh")" = 1 ] \
  || { echo 'test-install-script: outer marker attack substitution failed' >&2; exit 1; }
# shellcheck disable=SC2016
[ "$(grep -cF 'ln -s "$TEST_PROBE_DIR/protected-target" "${tmp}.command-complete.part"' "$work/lifecycle-probes.sh")" = 1 ] \
  || { echo 'test-install-script: command marker attack substitution failed' >&2; exit 1; }
cat >> "$work/lifecycle-probes.sh" <<'EOF'
fetch_wait() {
  probe_dir="${TEST_PROBE_DIR:?}"
  printf '%s\n%s\n' "$1" "$2" > "$probe_dir/fetch-wait-args"
  fetch_wait_real "$@"
}
legacy_sentinels() {
  for suffix in .command-complete .command-complete.part .command-jobs \
    .command-child-jobs .fetch-complete .fetch-complete.part .fetch-jobs; do
    # The designated attack path is created at write time. All other legacy
    # paths are ordinary foreign files and must remain byte-identical.
    case "${TEST_ATTACK_PART:-}:$suffix" in
      outer:.fetch-complete.part|command:.command-complete.part) continue ;;
    esac
    printf 'outside\n' > "${1}${suffix}"
  done
}
probe_dir="${TEST_PROBE_DIR:?}"
case "$1" in
  query_failure)
    mkdir "$probe_dir/package"
    printf 'verified\n' > "$probe_dir/package/asset"
    (
      n=0
      while [ ! -e "$probe_dir/finish" ]; do
        n=$((n + 1))
        [ "$n" -lt 200 ] || exit 98
        sleep 0.05
      done
      : > "$probe_dir/child-finished"
    ) &
    jobs() { return 98; }
    pkg_dir="$probe_dir/package"
    download_dir=""
    job_report="$probe_dir/jobs"
    fetch_done=""
    fetch_keep=""
    trap on_exit EXIT
    exit 143
    ;;
  shared_tmp_markers)
    tmp="$(mktemp -d "$probe_dir/tmp.XXXXXX")"
    printf '%s\n' "$tmp" > "$probe_dir/tmp-path"
    legacy_sentinels "$tmp"
    printf 'protected-content\n' > "$probe_dir/protected-target"
    auto_tmp=0
    fetch_keep=""
    fetch_command_done=""
    fetch_command_report=""
    trap fetch_cleanup EXIT
    exit 0
    ;;
  command_markers)
    tmp="$(mktemp -d "$probe_dir/tmp.XXXXXX")"
    printf '%s\n' "$tmp" > "$probe_dir/tmp-path"
    legacy_sentinels "$tmp"
    printf 'protected-content\n' > "$probe_dir/protected-target"
    auto_tmp=0
    fetch_keep=""
    fetch_run sleep 0
    ;;
  parent_failure)
    tmp="$(mktemp -d "$probe_dir/tmp.XXXXXX")"
    printf '%s\n' "$tmp" > "$probe_dir/tmp-path"
    legacy_sentinels "$tmp"
    auto_tmp=0
    fetch_keep="${2##* }"
    trap fetch_cleanup EXIT
    exit "${2%% *}"
    ;;
  package_report)
    pkg_dir="$probe_dir/package"
    mkdir "$pkg_dir"
    printf 'verified\n' > "$pkg_dir/asset"
    cat > "$probe_dir/package-child.sh" <<'CHILD'
printf 'spawned-parent=%s arg=%s\n' "$PPID" "$1" > "$TEST_PROBE_DIR/package-child-progress"
kill -s TERM "$PPID"
n=0
while kill -0 "$PPID" 2>/dev/null && [ "$n" -lt 100 ]; do
  n=$((n + 1))
  sleep 0.1
done
printf 'asset=%s\n' "$(cat "$1" 2>/dev/null)" >> "$TEST_PROBE_DIR/package-child-progress"
[ "$(cat "$1")" != verified ] || : > "$TEST_PROBE_DIR/child-read"
CHILD
    jobs() {
      printf '%s\n' "$job_path" > "$probe_dir/job-capture-path"
      : > "$probe_dir/in-on-exit"
      return 98
    }
    download_dir="$pkg_dir"
    fetch_done=""
    fetch_keep=""
    SUDO=""
    trap on_exit EXIT
    trap 'exit 143' TERM
    install_verified sh "$probe_dir/package-child.sh" "$pkg_dir/asset"
    ;;
  main_cleanup)
    tmp="$(mktemp -d "$probe_dir/tmp.XXXXXX")"
    printf '%s\n' "$tmp" > "$probe_dir/tmp-path"
    legacy_sentinels "$tmp"
    download_dir="$tmp"
    fetch_done="${download_dir}/.fetch-complete"
    fetch_job_report="${download_dir}/.fetch-jobs"
    printf '143 -\n' > "$fetch_done"
    pkg_dir=""
    job_report=""
    trap on_exit EXIT
    exit 143
    ;;
  fetch_private_paths)
    # Observe directory creation in this probe, as a shared-directory client
    # can, and place foreign fixtures before fetch_release starts its worker.
    mktemp() {
      observed_tmp="$(command mktemp "$@")"
      printf '%s\n' "$observed_tmp" > "$probe_dir/tmp-path"
      legacy_sentinels "$observed_tmp"
      printf '%s\n' "$observed_tmp"
    }
    fetch_verified() {
      sleep 0.1
      tmp="$2"
      auto_tmp=0
      fetch_keep=""
      trap fetch_cleanup EXIT
      printf 'verified\n' > "$tmp/asset.deb"
      printf '%s/asset.deb\n' "$tmp"
    }
    fetch_release _amd64.deb
    printf '%s\n' "$download_dir" > "$probe_dir/tmp-path"
    ;;
  standalone_creation_failure)
    # Observe any publication without allowing an out-of-scope path write. A
    # missing guard calls this spy with tmp empty and a root-level path.
    fetch_publish() {
      printf 'tmp=%s completion=%s\n' "$tmp" "$fetch_completion" \
        > "$probe_dir/publication-attempt"
      exit "$1"
    }
    fetch_verified _amd64.deb
    ;;
  keep_status)
    printf '%s keep\n' "$2" > "$probe_dir/completion"
    ( exit "$2" ) &
    probe_rc=0
    fetch_wait "$probe_dir/completion" "$probe_dir/jobs" || probe_rc=$?
    [ "$probe_rc" = "$3" ] && [ "$fetch_keep" = keep ] || {
      printf 'published %s keep returned %s with %s, want %s with keep\n' \
        "$2" "$probe_rc" "${fetch_keep:-unset}" "$3" >&2
      exit 1
    }
    ;;
esac
EOF
sed 's/^main "\$@"$/fetch_verified "$@"/' "$work/install.sh" > "$work/fetch-verified.sh"
[ "$(grep -cxF 'fetch_verified "$@"' "$work/fetch-verified.sh")" = 1 ] \
  || { echo 'test-install-script: install.sh no longer has one main "$@" line' >&2; exit 1; }
key_fp="$(sed -n 's/^KEY_FP="\([0-9A-F]\{40\}\)"$/\1/p' "$script")"
[ -n "$key_fp" ] \
  || { echo "test-install-script: install.sh no longer pins KEY_FP" >&2; exit 1; }
env --default-signal=HUP,INT,TERM true \
  || { echo "test-install-script: env --default-signal is missing (GNU coreutils 8.31 or newer)" >&2; exit 1; }

mkdir "$work/bin"
for tool in sh mktemp rm mv uname grep gzip sed awk basename dirname cat mkdir chmod sha256sum env sleep ln; do
  ln -s "$(command -v "$tool")" "$work/bin/$tool"
done

printf 'Package: irlume\n' | gzip > "$work/lists.gz"
printf 'Package: other\n' | gzip > "$work/empty.gz"
printf 'not gzip\n' > "$work/garbage"

# A release: one asset per lane and the SHA256SUMS that lists them.
mkdir "$work/release"
for asset in irlume_0.99.0_amd64.deb irlume-0.99.0-1.fc44.x86_64.rpm irlume-0.99.0-1-x86_64.pkg.tar.zst; do
  printf 'stand-in %s\n' "$asset" > "$work/release/$asset"
done
(cd "$work/release" && sha256sum irlume_* irlume-*) > "$work/SHA256SUMS"
# A release whose only asset, irlume__amd64.deb, names no version: the .deb
# pattern selects it, and the version read from its name is empty. Made after
# the SHA256SUMS above, which does not list it.
printf 'stand-in irlume__amd64.deb\n' > "$work/release/irlume__amd64.deb"
(cd "$work/release" && sha256sum irlume__amd64.deb) > "$work/SHA256SUMS.no_version"

cat > "$work/bin/curl" <<'EOF'
#!/bin/sh
# Stand-in curl: log the URL; answer the PPA index by TEST_PPA, and the
# release by TEST_RELEASE: none refuses SHA256SUMS, which ends the run at the
# release lane with no download; no_sig serves SHA256SUMS and refuses its
# signature; bad_sum serves an asset that does not match SHA256SUMS;
# no_version serves the release whose .deb names no version; listed serves
# the SHA256SUMS a case wrote to $TEST_DIR/SHA256SUMS.listed; cut
# breaks the asset off after a few bytes, as curl exits 18 on a partial
# transfer; fetch_delay sends TEST_SIGNAL only to the captured installer PID
# and keeps a completed asset's download process alive for ten seconds;
# interrupt_HUP, interrupt_INT and interrupt_TERM write a few bytes
# of the asset, then send that signal to the shell running the download and
# die of it, as a closed terminal, a Ctrl-C or a kill ends a real download
# (it logs that it outlived the signal if it does not die); every other mode
# serves all three. It writes only inside the test directory.
out=""
url=""
write_out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -w) write_out="$2"; shift ;;
    http*) url="$1" ;;
  esac
  shift
done
printf 'curl %s\n' "$url" >> "$TEST_LOG"
case "$out" in
  "$TEST_DIR"/*) ;;
  *) printf 'curl refused -o %s\n' "$out" >> "$TEST_LOG"; exit 23 ;;
esac
case "$url" in
  *Packages.gz)
    code=200
    status=0
    case "$TEST_PPA" in
      absent) code=404; status=22 ;;
      server_error) code=500; status=22 ;;
      unavailable) code=503; status=22 ;;
      rate_limited) code=429; status=22 ;;
      no_code) code=""; status=22 ;;
      offline) code=000; status=6 ;;
    esac
    if [ -n "$write_out" ]; then
      [ "$write_out" = '%{http_code}' ] || exit 99
      printf '%s' "$code"
    fi
    [ "$status" = 0 ] || exit "$status"
    case "$TEST_PPA" in
      lists) cat "$TEST_DIR/lists.gz" > "$out" ;;
      empty) cat "$TEST_DIR/empty.gz" > "$out" ;;
      garbage) cat "$TEST_DIR/garbage" > "$out" ;;
    esac
    ;;
  */releases/latest/download/SHA256SUMS)
    [ "$TEST_RELEASE" != none ] || exit 22
    if [ "$TEST_RELEASE" = no_version ]; then
      cat "$TEST_DIR/SHA256SUMS.no_version" > "$out"
    elif [ "$TEST_RELEASE" = listed ]; then
      cat "$TEST_DIR/SHA256SUMS.listed" > "$out"
    else
      cat "$TEST_DIR/SHA256SUMS" > "$out"
    fi
    ;;
  */releases/latest/download/SHA256SUMS.asc)
    [ "$TEST_RELEASE" != no_sig ] || exit 22
    printf 'stand-in signature\n' > "$out"
    ;;
  */releases/latest/download/irlume*)
    asset="$TEST_DIR/release/${url##*/}"
    [ -f "$asset" ] || exit 22
    case "$TEST_RELEASE" in
      bad_sum) printf 'changed\n' > "$out" ;;
      cut) printf 'stand-in' > "$out"; exit 18 ;;
      fetch_delay)
        cat "$asset" > "$out"
        kill -s "${TEST_SIGNAL:-TERM}" "$(cat "$TEST_DIR/installer-pid")"
        exec sleep 10
        ;;
      interrupt_*)
        sig="${TEST_RELEASE#interrupt_}"
        printf 'stand-in' > "$out"
        kill -s "$sig" "$PPID"
        kill -s "$sig" "$$"
        printf 'curl outlived SIG%s\n' "$sig" >> "$TEST_LOG"
        exit 99
        ;;
      *) cat "$asset" > "$out" ;;
    esac
    ;;
  *) exit 22 ;;
esac
EOF
# Stand-in gpg: the key always imports except under no_import, and only good,
# bad_sum, no_version, listed, cut and the interrupt modes (whose signature
# is fine) report the pinned key's VALIDSIG.
cat > "$work/bin/gpg" <<'EOF'
#!/bin/sh
printf 'gpg %s\n' "$*" >> "$TEST_LOG"
case " $* " in
  *" --import "*)
    cat > /dev/null
    [ "$TEST_RELEASE" != no_import ]
    ;;
  *" --verify "*)
    case "$TEST_RELEASE" in
      good|bad_sum|no_version|listed|cut|interrupt_*|fetch_delay|fetch_after_wait) printf '[GNUPG:] VALIDSIG %s\n' "$TEST_KEY_FP" ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 99 ;;
esac
EOF
cat > "$work/bin/add-apt-repository" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$TEST_LOG"
EOF
# Stand-in apt-get: under TEST_APT=fail an install exits 100, as apt-get does
# when an install fails. Under TEST_APT=signal_shell an install first sends
# SIGTERM to the shell that started it, the run of the copy, and to nothing
# else. It and post_launch both wait up to 10 seconds for that shell to end;
# child_int sends SIGINT to itself, proving the asynchronous child did not
# inherit an ignored interrupt. Each applicable mode touches apt-done when
# finished. An install records the local .deb path in deb-path and logs
# "apt-get read the verified <name>" only when it holds the verified asset.
cat > "$work/bin/apt-get" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$TEST_LOG"
if [ "${1:-}" = install ]; then
  if [ "$TEST_APT" = signal_shell ] || [ "$TEST_APT" = report_io_failure ]; then
    kill -s TERM "$PPID"
  fi
  if [ "$TEST_APT" = child_int ]; then
    kill -s INT "$$"
    printf 'apt-get: SIGINT was ignored\n' >> "$TEST_LOG"
  fi
  if [ "$TEST_APT" = stdin_pkg ]; then
    IFS= read -r answer || exit 98
    printf 'apt-get stdin: %s\n' "$answer" >> "$TEST_LOG"
    [ "$answer" = 'keep-local-conffile' ] || exit 97
  fi
  case "$TEST_APT" in signal_shell|report_io_failure|post_launch)
    n=0
    while kill -0 "$PPID" 2>/dev/null; do
      n=$((n + 1))
      if [ "$n" -gt 100 ]; then
        printf 'apt-get: the shell outlived SIGTERM\n' >> "$TEST_LOG"
        break
      fi
      sleep 0.1
    done
    ;;
  esac
  for arg in "$@"; do
    case "$arg" in
      /*.deb)
        printf '%s\n' "$arg" > "$TEST_DIR/deb-path"
        release="$TEST_DIR/release/${arg##*/}"
        if [ -f "$arg" ] && [ -f "$release" ] && [ "$(cat "$arg")" = "$(cat "$release")" ]; then
          printf 'apt-get read the verified %s\n' "${arg##*/}" >> "$TEST_LOG"
        fi
        ;;
    esac
  done
  case "$TEST_APT" in signal_shell|report_io_failure|post_launch|child_int) : > "$TEST_DIR/apt-done" ;; esac
  [ "$TEST_APT" != fail ] || exit 100
fi
EOF
# Stand-in package commands that fail: Fedora's dnf (Copr and the release
# RPM alike) and Arch's AUR helper. An install from a local RPM first logs
# "dnf read the verified <name>" when the file still held the verified
# release asset.
for tool in dnf yay; do
  cat > "$work/bin/$tool" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$TEST_LOG"
for arg in "$@"; do
  case "$arg" in
    /*.rpm)
      release="$TEST_DIR/release/${arg##*/}"
      if [ -f "$arg" ] && [ -f "$release" ] && [ "$(cat "$arg")" = "$(cat "$release")" ]; then
        printf '%s read the verified %s\n' "$(basename "$0")" "${arg##*/}" >> "$TEST_LOG"
      fi
      ;;
  esac
done
exit 1
EOF
done
# Stand-in systemctl: is-active answers by TEST_DAEMON, as systemctl does:
# the state on stdout, and a non-zero status for any state but active. On a
# system not booted with systemd (no_systemd) it prints no state, only an
# error on stderr, and exits 1. Under remake, which is otherwise active,
# enable makes a directory, with the file not-this-run in it, at the path of
# the directory apt-get installed the .deb from, which the script removed
# after the install (it logs when that directory is still there).
cat > "$work/bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$TEST_LOG"
if [ "${1:-}" = enable ] && [ "$TEST_DAEMON" = remake ]; then
  dir="$(dirname "$(cat "$TEST_DIR/deb-path")")"
  if [ -e "$dir" ]; then
    printf 'systemctl: the download directory is still there\n' >> "$TEST_LOG"
  else
    mkdir "$dir" && : > "$dir/not-this-run"
  fi
fi
if [ "${1:-}" = is-active ]; then
  case "$TEST_DAEMON" in
    active|remake) echo active ;;
    failed) echo failed; exit 3 ;;
    no_systemd)
      echo "System has not been booted with systemd as init system (PID 1). Can't operate." >&2
      exit 1 ;;
    *) exit 99 ;;
  esac
fi
EOF
# A user who is not root, whoever runs the test: as root, Arch would stop
# before its AUR helper.
cat > "$work/bin/id" <<'EOF'
#!/bin/sh
[ "$*" = -u ] || exit 99
echo 1000
EOF
cat > "$work/bin/dpkg-query" <<'EOF'
#!/bin/sh
case "${TEST_APT:-}" in
  early_HUP|early_INT|early_TERM)
    sig=${TEST_APT#early_}
    # The command substitution owns our parent; its parent is the script's shell.
    kill -s "$sig" "$(awk '{print $4}' "/proc/$PPID/stat")"
    sleep 1
    ;;
esac
exit 1
EOF
cat > "$work/bin/sudo" <<'EOF'
#!/bin/sh
exec "$@"
EOF
chmod +x "$work"/bin/curl "$work"/bin/gpg "$work"/bin/add-apt-repository "$work"/bin/apt-get \
  "$work"/bin/dnf "$work"/bin/yay "$work"/bin/systemctl "$work"/bin/id \
  "$work"/bin/dpkg-query "$work"/bin/sudo

# Where install.sh says to report a problem, as stderr shows it without colour.
security_url='https://github.com/archledger/irlume/security/advisories/new'
chooser_url='https://github.com/archledger/irlume/issues/new/choose'
block='[irlume] Security problem (a photo, video, mask or another person got in,
[irlume] face sign-in worked without your face, or face data was exposed),
[irlume] or not sure? Never post it publicly. Report it privately:
[irlume] https://github.com/archledger/irlume/security/advisories/new
[irlume] or the e-mail address in SECURITY.md.
[irlume] Anything else: https://github.com/archledger/irlume/issues/new/choose
[irlume] Your own words are fine; paste the lines above, not the sudo prompt.'

failed=0
label=""
fail() {
  echo "FAIL: $1" >&2
  { echo "--- calls"; cat "$work/log"; echo "--- stdout"; cat "$work/stdout"
    echo "--- stderr"; cat "$work/stderr"; echo "---"; } >&2
  failed=1
}

# install <os-release text> <ppa mode> [release mode] [daemon mode] [apt mode] [TMPDIR]:
# one run of the copy, with TMPDIR set to a fresh, empty $work/tmp or to the
# sixth argument. Its status lands in $rc, its streams in $work/stdout and
# $work/stderr, $work/plain holds stderr without colour, and $leftover lists
# what the run left in $work/tmp.
install() {
  printf '%s\n' "$1" > "$work/os-release"
  : > "$work/log"
  rm -rf "$work/tmp"
  mkdir "$work/tmp"
  rc=0
  started=$SECONDS
  apt_mode=${5:-ok}
  report_path=""
  [ "$apt_mode" != report_io_failure ] || report_path=/dev/full
  set -- env --default-signal=HUP,INT,TERM -i PATH="$work/bin" HOME="$work" TMPDIR="${6:-$work/tmp}" TERM=dumb \
    TEST_LOG="$work/log" TEST_DIR="$work" \
    TEST_PPA="$2" TEST_RELEASE="${3:-none}" TEST_DAEMON="${4:-active}" TEST_APT="${5:-ok}" \
    TEST_SIGNAL="${sig:-}" TEST_REPORT_PATH="$report_path" TEST_KEY_FP="$key_fp" sh "$work/install.sh"
  if [ "$apt_mode" = stdin_pkg ]; then
    printf 'keep-local-conffile\n' | "$@" > "$work/stdout" 2> "$work/stderr" || rc=$?
  else
    "$@" > "$work/stdout" 2> "$work/stderr" || rc=$?
  fi
  elapsed=$((SECONDS - started))
  sed 's/\x1b\[[0-9;]*m//g' "$work/stderr" > "$work/plain"
  leftover="$(ls -A "$work/tmp")" || leftover="(the run removed TMPDIR itself)"
  [ ! -s "$work/stdout" ] || fail "$label: wrote to stdout; install.sh writes only to stderr"
}

# fetch_one <SHA256SUMS text> <match>: one call of fetch_verified <match> in
# the second copy, with the release served as under listed, its SHA256SUMS
# holding the text given, and TMPDIR a fresh, empty $work/tmp. Its status
# lands in $rc, its streams in $work/stdout and $work/stderr, $work/plain
# holds stderr without colour, and $leftover lists what the call left in
# $work/tmp.
fetch_one() {
  printf '%s\n' "$1" > "$work/SHA256SUMS.listed"
  : > "$work/log"
  rm -rf "$work/tmp"
  mkdir "$work/tmp"
  rc=0
  env --default-signal=HUP,INT,TERM -i PATH="$work/bin" HOME="$work" TMPDIR="$work/tmp" TERM=dumb \
    TEST_LOG="$work/log" TEST_DIR="$work" \
    TEST_PPA=lists TEST_RELEASE=listed TEST_DAEMON=active TEST_APT=ok \
    TEST_KEY_FP="$key_fp" sh "$work/fetch-verified.sh" "$2" > "$work/stdout" 2> "$work/stderr" || rc=$?
  sed 's/\x1b\[[0-9;]*m//g' "$work/stderr" > "$work/plain"
  leftover="$(ls -A "$work/tmp")" || leftover="(the run removed TMPDIR itself)"
}

want_rc() { [ "$rc" = "$1" ] || fail "$label: exit status $rc, want $1"; }
want_err() { grep -qF -- "$1" "$work/plain" || fail "$label: stderr lacks: $1"; }
want_no_err() { if grep -qF -- "$1" "$work/plain"; then fail "$label: stderr has: $1"; fi; }
# want_lines <count> <text>: the number of stderr lines that hold the text.
want_lines() {
  n="$(grep -cF -- "$2" "$work/plain" || true)"
  [ "$n" = "$1" ] || fail "$label: $n stderr lines hold $2, want $1"
}
want_called() { grep -qxF -- "$1" "$work/log" || fail "$label: never called: $1"; }
# The run left nothing in its TMPDIR: no download directory, no partial or
# whole download, no PPA index.
want_no_download() {
  [ -z "$leftover" ] || fail "$label: left in TMPDIR: $(printf '%s' "$leftover" | tr '\n' ' ')"
}

# A run that ends with where to report a problem: the whole block, once, in
# order, and each URL on exactly the given number of lines (the security URL
# is on two when a verification line names it as well).
want_block() {
  want_lines "${1:-1}" "$security_url"
  want_lines 1 "$chooser_url"
  want_lines 1 'Your own words are fine; paste the lines above, not the sudo prompt.'
  # The block follows one empty [irlume] line.
  [[ $'\n'"$(cat "$work/plain")"$'\n' == *$'\n''[irlume] '$'\n'"$block"$'\n'* ]] \
    || fail "$label: stderr lacks the where-to-report lines in order"
}
want_no_block() {
  want_no_err "$security_url"
  want_no_err "$chooser_url"
  want_no_err 'Your own words are fine'
}
want_ready() {
  want_rc 0
  want_err 'installed; the irlume daemon is active. The machine side is ready.'
  want_no_err 'not active'
  want_no_block
  want_no_download
}
# The release lane failed before it downloaded anything, at a die.
want_no_release() {
  want_rc 1
  want_err 'could not fetch SHA256SUMS from the latest release.'
  want_no_err 'Do not override verification'
  want_no_err 'The machine side is ready.'
  want_block
  want_no_download
}
# A verification failure: its line, then the private route, in its own lines.
want_verify_failure() {
  want_rc 1
  want_err "$1"
  want_err 'Do not override verification or install the download by hand;'
  [[ $'\n'"$(cat "$work/plain")"$'\n' == *$'\n''[irlume] report it privately:'$'\n''[irlume] '"$security_url"$'\n'* ]] \
    || fail "$label: stderr lacks the private route after the verification failure"
  want_no_err 'IRLUME_INSECURE_NO_SIG'
  want_no_err 'The machine side is ready.'
  want_block 2
  want_no_download
}

# run <os-release text> <ppa mode> <want PPA added: yes|no> <want .deb tried: yes|no> <label>
run() {
  label="$5"
  install "$1" "$2"
  added=no; grep -q '^add-apt-repository ' "$work/log" && added=yes
  deb=no; grep -q 'SHA256SUMS' "$work/log" && deb=yes
  [ "$added" = "$3" ] || fail "$5: PPA added: got $added, want $3"
  [ "$deb" = "$4" ] || fail "$5: release .deb tried: got $deb, want $4"
  if [ "$4" = yes ]; then
    # A local .deb still needs the archive's dependency lists, so the
    # machine's existing repositories are refreshed BEFORE the .deb lane
    # starts (the harness's curl refuses SHA256SUMS, which is the first
    # thing the lane fetches, so refresh-before-fetch is what is pinned).
    up=$({ grep -n '^apt-get update$' "$work/log" || true; } | head -n1 | cut -d: -f1)
    fetch=$({ grep -n 'SHA256SUMS' "$work/log" || true; } | head -n1 | cut -d: -f1)
    if [ -z "$up" ] || [ -z "$fetch" ] || [ "$up" -ge "$fetch" ]; then
      fail "$5: release .deb path must refresh apt lists before its first fetch (update=$up fetch=$fetch)"
    fi
    want_no_release
  else
    want_ready
  fi
}

ubuntu='ID=ubuntu
ID_LIKE=debian
VERSION_CODENAME=jammy'
run "$ubuntu" lists yes no "a series the PPA serves"
grep -q 'irlume/ubuntu/dists/jammy/main/binary-amd64/Packages.gz' "$work/log" \
  || fail "the index asked for is this series' binary index"
run "$ubuntu" absent no yes "a series the PPA has no index for"
run "$ubuntu" empty no yes "a series whose index does not list irlume"
run "$ubuntu" offline yes no "the PPA cannot be reached"
run "$ubuntu" server_error yes no "the PPA temporarily returns HTTP 500"
run "$ubuntu" unavailable yes no "the PPA temporarily returns HTTP 503"
run "$ubuntu" rate_limited yes no "the PPA temporarily returns HTTP 429"
run "$ubuntu" no_code no yes "a curl that reports an HTTP error but no code"
run "$ubuntu" garbage yes no "bytes that are not an index"

debian='ID=debian
VERSION_CODENAME=bookworm'
run "$debian" lists no yes "Debian"
if grep -q 'Packages.gz' "$work/log"; then fail "Debian asked the PPA"; fi
run 'ID=linuxmint
ID_LIKE="ubuntu debian"
VERSION_CODENAME=virginia
UBUNTU_CODENAME=jammy' lists no yes "an Ubuntu derivative"
if grep -q 'Packages.gz' "$work/log"; then fail "a derivative asked the PPA"; fi

label="a user who is not root, on a machine without sudo"
mv "$work/bin/sudo" "$work/sudo"
install "$debian" lists
mv "$work/sudo" "$work/bin/sudo"
want_rc 1
want_err 'need root: install sudo, or re-run this as root.'
want_block
want_no_download

label="irlume already installed"
cat > "$work/bin/irlume" <<'EOF'
#!/bin/sh
[ "$*" = --version ] || exit 99
echo "irlume 0.16.0"
EOF
chmod +x "$work/bin/irlume"
install "$debian" lists
rm "$work/bin/irlume"
want_rc 0
want_err 'already installed: irlume 0.16.0 via a manual install'
want_err 'Nothing was changed.'
want_no_block
want_no_download

label="a daemon that is not active after the install"
install "$ubuntu" lists none failed
want_rc 0
want_called 'systemctl is-active irlumed.service'
want_err 'installed, but the irlume daemon is failed, not active.'
want_err 'systemctl status irlumed.service'
want_no_err 'The machine side is ready.'
want_block
want_no_download

label="a system not booted with systemd"
install "$ubuntu" lists none no_systemd
want_rc 0
want_called 'systemctl is-active irlumed.service'
want_err 'installed, but the irlume daemon is unknown, not active.'
want_no_err 'System has not been booted with systemd'
want_no_err 'The machine side is ready.'
want_block
want_no_download

label="Arch, where the AUR helper fails with no die line of the script's own"
install 'ID=arch' lists
want_rc 1
want_called 'yay -S --noconfirm irlume'
# No die line: the exit is set -e's, after the helper's own failure.
if grep -qF $'\033[1;31m' "$work/stderr"; then fail "$label: a die line was printed"; fi
want_block
want_no_download

fedora='ID=fedora
VERSION_ID=44'
label="Fedora, where Copr and the release RPM both fail"
install "$fedora" lists
want_rc 1
want_called 'dnf -y copr enable archledger/irlume'
want_err 'could not fetch SHA256SUMS from the latest release.'
want_err 'no verified release RPM for fc44; the lines above say why.'
want_no_err 'Do not override verification'
want_block
want_no_download

# A VERSION_ID that is not a Fedora release number: a RHEL-family point
# release, and a number followed by a + (which os-release(5) allows from
# systemd 262 on) or a |. The release is served as under good, so only
# the check itself stops the fetch.
for version_id in '"9.4"' '"44+"' '"44|"'; do
  label="Fedora's release-RPM fallback, with VERSION_ID=$version_id"
  install "ID=fedora
VERSION_ID=$version_id" lists good
  want_rc 1
  want_called 'dnf -y copr enable archledger/irlume'
  want_err 'Fedora family with a VERSION_ID that is not a Fedora release number; cannot pick a release RPM. Install from Copr when it is back.'
  if grep -q 'SHA256SUMS' "$work/log"; then fail "$label: fetched SHA256SUMS"; fi
  want_no_err 'no verified release RPM for'
  want_block
  want_no_download
done

label="a release without its signature"
install "$debian" lists no_sig
want_verify_failure 'SHA256SUMS.asc not found for this release.'

label="a signature that does not verify"
install "$debian" lists bad_sig
want_verify_failure "SHA256SUMS signature did NOT verify against the pinned irlume key $key_fp; refusing to install."

label="a pinned key that cannot be imported"
install "$debian" lists no_import
want_verify_failure 'could not import the pinned irlume key; cannot verify the release signature.'

label="an asset that does not match SHA256SUMS"
install "$debian" lists bad_sum
want_verify_failure 'CHECKSUM MISMATCH on irlume_0.99.0_amd64.deb; refusing to install.'

label="Fedora's release-RPM fallback, where the signature does not verify"
install "$fedora" lists bad_sig
want_verify_failure 'SHA256SUMS signature did NOT verify'
want_err 'no verified release RPM for fc44; the lines above say why.'

label="a verified release .deb"
install "$debian" lists good
# want_ready also finds TMPDIR empty: the caller removed the directory, after
# apt-get had read the verified file there (the last check below).
want_ready
want_err 'SHA256SUMS GPG signature verified against the pinned irlume key.'
grep -q '^apt-get install -y .*/irlume_0.99.0_amd64.deb$' "$work/log" \
  || fail "$label: the verified .deb was not installed"
want_called 'apt-get read the verified irlume_0.99.0_amd64.deb'

label="a verified release .deb that apt-get fails to install"
install "$debian" lists good active fail
want_rc 100
grep -q '^apt-get install -y .*/irlume_0.99.0_amd64.deb$' "$work/log" \
  || fail "$label: the verified .deb was not tried"
# No die line: the run exits with apt-get's own status.
if grep -qF $'\033[1;31m' "$work/stderr"; then fail "$label: a die line was printed"; fi
want_no_err 'The machine side is ready.'
want_block
want_no_download

label="a verified release .deb whose name gives no version"
install "$debian" lists no_version
want_rc 1
want_err 'could not parse the release .deb filename: irlume__amd64.deb'
if grep -q '^apt-get install ' "$work/log"; then fail "$label: apt-get installed something"; fi
want_no_err 'The machine side is ready.'
want_block
want_no_download

# The release's SHA256SUMS with a NUL byte after its lines. grep counts the
# one .deb line but reads the file as binary data and prints no line of it,
# so the line gives no file name.
label="a SHA256SUMS that holds a NUL byte"
{ cat "$work/SHA256SUMS"; printf 'x\000y\n'; } > "$work/SHA256SUMS.listed"
printed="$(grep '_amd64\.deb$' "$work/SHA256SUMS.listed" 2>/dev/null || true)"
if [ "$(grep -c '_amd64\.deb$' "$work/SHA256SUMS.listed")" != 1 ] || [ -n "$printed" ]; then
  fail "$label: grep does not count the .deb line once and print nothing for a file that holds a NUL byte"
fi
install "$debian" lists listed
want_rc 1
want_err "the SHA256SUMS entry for '_amd64.deb' is not a plain file name; refusing to download it."
n="$(grep -c '^curl ' "$work/log" || true)"
[ "$n" = 2 ] || fail "$label: curl ran $n times, want 2 (SHA256SUMS and its signature)"
want_no_err 'downloading '
if grep -q '^apt-get install ' "$work/log"; then fail "$label: apt-get installed something"; fi
want_block
want_no_download

label="SIGTERM to the script's shell alone while apt-get installs the release .deb"
rm -f "$work/apt-done"
install "$debian" lists good active signal_shell
# apt-get outlives the shell that started it: wait up to 20 seconds for it.
n=0
while [ ! -e "$work/apt-done" ] && [ "$n" -lt 200 ]; do sleep 0.1; n=$((n + 1)); done
[ -e "$work/apt-done" ] || fail "$label: the stand-in apt-get did not finish"
if grep -q '^apt-get: the shell outlived SIGTERM$' "$work/log"; then
  fail "$label: the shell outlived SIGTERM, so the signal is ignored or blocked where this test runs"
fi
want_rc 143
# The file was still there when apt-get read it, after the shell had ended:
# the parent's signal trap runs on_exit at once, and its job-state check
# leaves a running or suspended package child's directory in place.
want_called 'apt-get read the verified irlume_0.99.0_amd64.deb'
want_no_err 'The machine side is ready.'

label="SIGTERM during package installation with an unwritable job report"
rm -f "$work/apt-done"
install "$debian" lists good active report_io_failure
n=0
while [ ! -e "$work/apt-done" ] && [ "$n" -lt 200 ]; do sleep 0.1; n=$((n + 1)); done
[ -e "$work/apt-done" ] || fail "$label: the stand-in apt-get did not finish"
want_rc 143
want_called 'apt-get read the verified irlume_0.99.0_amd64.deb'
want_no_err 'The machine side is ready.'
want_block

label="a directory made at the download directory's path after the install"
rm -f "$work/deb-path"
install "$debian" lists good remake
want_rc 0
want_err 'installed; the irlume daemon is active. The machine side is ready.'
want_called 'apt-get read the verified irlume_0.99.0_amd64.deb'
if grep -q '^systemctl: the download directory is still there$' "$work/log"; then
  fail "$label: the download directory was still there after the install"
fi
if [ -f "$work/deb-path" ]; then
  made="$(dirname "$(cat "$work/deb-path")")/not-this-run"
  [ -e "$made" ] || fail "$label: the run's exit removed $made"
else
  fail "$label: apt-get installed no local .deb"
fi

label="a verified release RPM that dnf fails to install"
install "$fedora" lists good
want_rc 1
grep -q '^dnf -y install .*/irlume-0.99.0-1.fc44.x86_64.rpm$' "$work/log" \
  || fail "$label: the verified RPM was not tried"
# The verified file reached dnf through the release-RPM caller's `|| die`.
want_called 'dnf read the verified irlume-0.99.0-1.fc44.x86_64.rpm'
# No die line: the run exits with dnf's own status.
if grep -qF $'\033[1;31m' "$work/stderr"; then fail "$label: a die line was printed"; fi
want_no_err 'The machine side is ready.'
want_block
want_no_download

label="a release download that breaks off"
install "$debian" lists cut
want_rc 1
want_err 'download of irlume_0.99.0_amd64.deb failed.'
want_no_err 'Do not override verification'
want_no_err 'The machine side is ready.'
want_block
want_no_download

for sig in HUP INT TERM; do
  case "$sig" in
    HUP) sig_rc=129 ;;
    INT) sig_rc=130 ;;
    TERM) sig_rc=143 ;;
  esac
  label="a release download interrupted by SIG$sig"
  install "$debian" lists "interrupt_$sig"
  if grep -q '^curl outlived ' "$work/log"; then
    fail "$label: the stand-in curl outlived SIG$sig, so the signal is ignored or blocked where this test runs"
  fi
  want_rc "$sig_rc"
  want_called 'curl https://github.com/archledger/irlume/releases/latest/download/irlume_0.99.0_amd64.deb'
  # The signal ended the download: no die after it, no verification.
  want_no_err 'download of irlume_0.99.0_amd64.deb failed.'
  want_no_err 'verifying checksum'
  if grep -q '^apt-get install ' "$work/log"; then fail "$label: apt-get installed something"; fi
  want_block
  want_no_download
done

label="a TMPDIR that does not exist"
install "$debian" lists good active ok "$work/missing"
want_rc 1
want_err 'could not create a temporary directory for the download.'
if grep -q 'SHA256SUMS\|^curl refused' "$work/log"; then fail "$label: fetched without a temporary directory"; fi
[ ! -e "$work/missing" ] || fail "$label: created $work/missing"
want_block

label="Fedora's release-RPM fallback, with a TMPDIR that does not exist"
install "$fedora" lists good active ok "$work/missing"
want_rc 1
want_err 'could not create a temporary directory for the download.'
want_err 'no verified release RPM for fc44; the lines above say why.'
if grep -q 'SHA256SUMS\|^curl refused' "$work/log"; then fail "$label: fetched without a temporary directory"; fi
[ ! -e "$work/missing" ] || fail "$label: created $work/missing"
want_block

# fetch_verified, called by itself, with a SHA256SUMS line its pattern
# selects whose name is not a plain file name. The checksum is the release
# RPM's, so the name is the only thing wrong with the line.
rpm_sum="$(sed -n 's/^\([0-9a-f]\{64\}\)  irlume-0\.99\.0-1\.fc44\.x86_64\.rpm$/\1/p' "$work/SHA256SUMS")"
[ -n "$rpm_sum" ] \
  || { echo "test-install-script: the release fixture lists no fc44 RPM" >&2; exit 1; }
# want_name_refused <match> <name in the SHA256SUMS line>
want_name_refused() {
  label="fetch_verified '$1', whose SHA256SUMS line names $2"
  fetch_one "$rpm_sum  $2" "$1"
  want_rc 1
  want_err "the SHA256SUMS entry for '$1' is not a plain file name; refusing to download it."
  want_called 'curl https://github.com/archledger/irlume/releases/latest/download/SHA256SUMS'
  want_called 'curl https://github.com/archledger/irlume/releases/latest/download/SHA256SUMS.asc'
  n="$(grep -c '^curl ' "$work/log" || true)"
  [ "$n" = 2 ] || fail "$label: curl ran $n times, want 2 (SHA256SUMS and its signature)"
  want_no_err 'downloading '
  [ ! -s "$work/stdout" ] || fail "$label: gave its caller a path"
  want_no_download
}
want_name_refused 'a/b' 'a/b'
want_name_refused '..' '..'
want_name_refused '.' '.'

# These signals land after fetch_verified returns and before install_verified
# clears download_dir, the top-level window the fetch subshell does not cover.
for sig in HUP INT TERM; do
  case "$sig" in
    HUP) sig_rc=129 ;;
    INT) sig_rc=130 ;;
    TERM) sig_rc=143 ;;
  esac
  label="SIG$sig after the verified .deb and before apt-get"
  install "$debian" lists good active "early_$sig"
  want_rc "$sig_rc"
  want_called 'curl https://github.com/archledger/irlume/releases/latest/download/irlume_0.99.0_amd64.deb'
  if grep -q '^apt-get install ' "$work/log"; then fail "$label: apt-get started"; fi
  want_block
  want_no_download
done

# Signals at the two sides of the package child. Before launch the parent's
# cleanup still owns the download. After wait reaps the child it owns it
# again, before download_dir is restored.
for boundary in pre_launch post_wait; do
  for sig in HUP INT TERM; do
    case "$sig" in
      HUP) sig_rc=129 ;;
      INT) sig_rc=130 ;;
      TERM) sig_rc=143 ;;
    esac
    label="SIG$sig in the $boundary package boundary"
    install "$debian" lists good active "$boundary"
    want_rc "$sig_rc"
    want_called 'curl https://github.com/archledger/irlume/releases/latest/download/irlume_0.99.0_amd64.deb'
    if [ "$boundary" = pre_launch ]; then
      if grep -q '^apt-get install ' "$work/log"; then fail "$label: apt-get started"; fi
    else
      want_called 'apt-get read the verified irlume_0.99.0_amd64.deb'
    fi
    want_no_err 'The machine side is ready.'
    want_block
    want_no_download
  done
done

if [ "$has_background_package" = 1 ]; then
  # This signal is after the child exists and before wait starts. apt-get
  # waits for the installer to end, then must still find the verified file.
  for sig in HUP INT TERM; do
    case "$sig" in
      HUP) sig_rc=129 ;;
      INT) sig_rc=130 ;;
      TERM) sig_rc=143 ;;
    esac
    label="SIG$sig after launch and before wait"
    rm -f "$work/apt-done"
    install "$debian" lists good active post_launch
    n=0
    while [ ! -e "$work/apt-done" ] && [ "$n" -lt 200 ]; do sleep 0.1; n=$((n + 1)); done
    [ -e "$work/apt-done" ] || fail "$label: the stand-in apt-get did not finish"
    want_rc "$sig_rc"
    want_called 'apt-get read the verified irlume_0.99.0_amd64.deb'
    want_no_err 'The machine side is ready.'
    want_block
  done

  # Without job control, an asynchronous child can inherit SIGINT ignored.
  # Its local reset followed by exec must make this a normal status-130 exit.
  label="SIGINT disposition in the package child"
  install "$debian" lists good active child_int
  want_rc 130
  grep -q '^apt-get install -y .*/irlume_0.99.0_amd64.deb$' "$work/log" \
    || fail "$label: apt-get did not start"
  want_no_err 'The machine side is ready.'
  want_no_err 'apt-get: SIGINT was ignored'
  want_block
  want_no_download
fi

label="a conffile response reaches the asynchronous package child"
install "$debian" lists good active stdin_pkg
want_ready
want_called 'apt-get stdin: keep-local-conffile'
want_called 'apt-get read the verified irlume_0.99.0_amd64.deb'

for sig in HUP INT TERM; do
  case "$sig" in
    HUP) sig_rc=129 ;;
    INT) sig_rc=130 ;;
    TERM) sig_rc=143 ;;
  esac
  label="SIG$sig only to the installer during an active fetch"
  install "$debian" lists fetch_delay active
  want_rc "$sig_rc"
  [ "$elapsed" -lt 5 ] || fail "$label: the active download was not cancelled promptly (${elapsed}s)"
  want_called 'curl https://github.com/archledger/irlume/releases/latest/download/irlume_0.99.0_amd64.deb'
  if grep -q '^apt-get install ' "$work/log"; then fail "$label: apt-get started"; fi
  want_block
  want_no_download

done

if [ "$has_async_fetch" = 1 ]; then
  for sig in HUP INT TERM; do
    case "$sig" in
      HUP) sig_rc=129 ;;
      INT) sig_rc=130 ;;
      TERM) sig_rc=143 ;;
    esac
    label="SIG$sig after fetch wait and before the answer is read"
    install "$debian" lists fetch_after_wait active
    want_rc "$sig_rc"
    want_called 'curl https://github.com/archledger/irlume/releases/latest/download/irlume_0.99.0_amd64.deb'
    if grep -q '^apt-get install ' "$work/log"; then fail "$label: apt-get started"; fi
    want_block
    want_no_download
  done
fi

label="a failed jobs query preserves the package of an active child"
probe_dir="$work/probe-query-failure"
mkdir "$probe_dir"
rc=0
env --default-signal=HUP,INT,TERM -i PATH="$work/bin" TEST_PROBE_DIR="$probe_dir" \
  sh "$work/lifecycle-probes.sh" query_failure > "$work/probe-stdout" 2> "$work/probe-stderr" || rc=$?
want_rc 143
[ -f "$probe_dir/package/asset" ] \
  || fail "$label: removed the verified package after a failed job query"
: > "$probe_dir/finish"
n=0
while [ ! -e "$probe_dir/child-finished" ] && [ "$n" -lt 200 ]; do sleep 0.05; n=$((n + 1)); done
[ -e "$probe_dir/child-finished" ] || fail "$label: active child did not stop"

for published in 42 143 0; do
  expected="$published"
  [ "$published" -ne 0 ] || expected=1
  label="published $published keep status and cleanup disposition"
  probe_dir="$work/probe-keep-$published"
  mkdir "$probe_dir"
  rc=0
  env --default-signal=HUP,INT,TERM -i PATH="$work/bin" TEST_PROBE_DIR="$probe_dir" \
    sh "$work/lifecycle-probes.sh" keep_status "$published" "$expected" \
    > "$work/probe-stdout" 2> "$work/probe-stderr" || rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "$label: $(cat "$work/probe-stderr")"
  fi
done

check_legacy_sentinels() {
  for suffix in .command-complete .command-complete.part .command-jobs \
    .command-child-jobs .fetch-complete .fetch-complete.part .fetch-jobs; do
    case "${2:-}:$suffix" in
      outer:.fetch-complete.part|command:.command-complete.part) continue ;;
    esac
    [ "$(cat "${1}${suffix}" 2>/dev/null)" = outside ] \
      || fail "$label: changed or removed foreign $1$suffix"
  done
}

for marker_mode in outer command; do
  label="shared-directory $marker_mode marker symlink cannot truncate another file"
  probe_dir="$work/probe-markers-$marker_mode"
  mkdir "$probe_dir"
  marker_probe=shared_tmp_markers
  [ "$marker_mode" = outer ] || marker_probe=command_markers
  rc=0
  env --default-signal=HUP,INT,TERM -i PATH="$work/bin" TEST_PROBE_DIR="$probe_dir" \
    TEST_ATTACK_PART="$marker_mode" \
    sh "$work/lifecycle-probes.sh" "$marker_probe" \
    > "$work/probe-stdout" 2> "$work/probe-stderr" || rc=$?
  want_rc 0
  [ "$(cat "$probe_dir/protected-target")" = protected-content ] \
    || fail "$label: publication followed a legacy symlink"
  [ "$(cat "$probe_dir/$marker_mode-record" 2>/dev/null)" = '0 -' ] \
    || fail "$label: missing publication record"
  private_tmp="$(cat "$probe_dir/tmp-path")"
  check_legacy_sentinels "$private_tmp" "$marker_mode"
done

label="private parent-owned fetch completion record"
for published in '42 -' '143 -' '42 keep' '143 keep'; do
  probe_dir="$work/probe-parent-${published%% *}-${published##* }"
  mkdir "$probe_dir"
  rc=0
  env --default-signal=HUP,INT,TERM -i PATH="$work/bin" TEST_PROBE_DIR="$probe_dir" \
    sh "$work/lifecycle-probes.sh" parent_failure "$published" \
    > "$work/probe-stdout" 2> "$work/probe-stderr" || rc=$?
  want_rc "${published%% *}"
  private_tmp="$(cat "$probe_dir/tmp-path")"
  [ "$(cat "$private_tmp/.fetch-complete" 2>/dev/null)" = "$published" ] \
    || fail "$label: wanted $published after publication or recording failed"
  check_legacy_sentinels "$private_tmp"
done

label="main exit removes no foreign legacy marker"
probe_dir="$work/probe-main-cleanup"
mkdir "$probe_dir"
rc=0
env --default-signal=HUP,INT,TERM -i PATH="$work/bin" TEST_PROBE_DIR="$probe_dir" \
  sh "$work/lifecycle-probes.sh" main_cleanup > "$work/probe-stdout" 2> "$work/probe-stderr" || rc=$?
want_rc 143
check_legacy_sentinels "$(cat "$probe_dir/tmp-path")"

label="fetch completion and job report stay private"
probe_dir="$work/probe-fetch-paths"
mkdir "$probe_dir"
rc=0
env --default-signal=HUP,INT,TERM -i PATH="$work/bin" TEST_PROBE_DIR="$probe_dir" \
  sh "$work/lifecycle-probes.sh" fetch_private_paths \
  > "$work/probe-stdout" 2> "$work/probe-stderr" || rc=$?
want_rc 0
private_tmp="$(cat "$probe_dir/tmp-path")"
[ "$(sed -n 1p "$probe_dir/fetch-wait-args")" = "$private_tmp/.fetch-complete" ] \
  || fail "$label: completion path changed"
[ "$(sed -n 2p "$probe_dir/fetch-wait-args")" = "$private_tmp/.fetch-jobs" ] \
  || fail "$label: job-report path changed"
check_legacy_sentinels "$private_tmp"

label="package job reports stay in the private package directory"
probe_dir="$work/probe-package-report"
mkdir "$probe_dir"
rc=0
env --default-signal=HUP,INT,TERM -i PATH="$work/bin" TEST_PROBE_DIR="$probe_dir" \
  sh "$work/lifecycle-probes.sh" package_report > "$work/probe-stdout" 2> "$work/probe-stderr" || rc=$?
want_rc 143
[ "$(cat "$probe_dir/job-capture-path" 2>/dev/null)" = "$probe_dir/package/.package-jobs" ] \
  || fail "$label: job capture used $(cat "$probe_dir/job-capture-path" 2>/dev/null)"
[ -f "$probe_dir/package/asset" ] || fail "$label: removed the asset after a failed query"
n=0
while [ ! -e "$probe_dir/child-read" ] && [ "$n" -lt 260 ]; do sleep 0.05; n=$((n + 1)); done
[ -e "$probe_dir/child-read" ] || fail "$label: active package child did not finish reading the asset; $(cat "$probe_dir/package-child-progress" 2>/dev/null)"


label="standalone temporary creation failure never publishes"
probe_dir="$work/probe-standalone-creation"
mkdir "$probe_dir"
[ ! -e "$probe_dir/missing" ] || fail "$label: missing-directory fixture exists"
rc=0
env --default-signal=HUP,INT,TERM -i PATH="$work/bin" TEST_PROBE_DIR="$probe_dir" \
  TMPDIR="$probe_dir/missing" \
  sh "$work/lifecycle-probes.sh" standalone_creation_failure \
  > "$work/probe-stdout" 2> "$work/probe-stderr" || rc=$?
want_rc 1
grep -qF 'could not create a temporary directory for the download.' "$work/probe-stderr" \
  || fail "$label: did not exercise the real one-argument creation failure"
[ ! -e "$probe_dir/publication-attempt" ] \
  || fail "$label: $(cat "$probe_dir/publication-attempt")"
[ ! -e "$probe_dir/missing" ] || fail "$label: created the intentionally missing directory"

[ "$failed" = 0 ] || exit 1
echo "test-install-script: every channel choice and message held (sh is $(readlink -f "$work/bin/sh"))"
