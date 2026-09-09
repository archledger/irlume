#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Ubuntu 24.04 permits userns creation but denies subsequent namespace
# capabilities without an application profile. Bubblewrap's loopback setup
# then fails with RTM_NEWADDR EPERM, before the isolated CLI tests can execute.
# https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions
set -euo pipefail

probe() {
  # Match the test helper's namespace setup, including namespace-root and an
  # isolated network. Success must mean a different user and network namespace.
  local userns netns
  userns=$(readlink /proc/self/ns/user)
  netns=$(readlink /proc/self/ns/net)
  # The expressions in the script are expanded by the isolated child shell.
  # shellcheck disable=SC2016
  /usr/bin/bwrap --die-with-parent --unshare-user --uid 0 --gid 0 \
    --unshare-pid --unshare-net --unshare-ipc --unshare-uts \
    --unshare-cgroup-try --ro-bind / / --tmpfs /run --dev /dev --proc /proc \
    -- /bin/sh -eu -c '
      test "$(id -u)" = 0
      test "$(readlink /proc/self/ns/user)" != "$1"
      test "$(readlink /proc/self/ns/net)" != "$2"
    ' sh "$userns" "$netns"
}

# Read-only verification is also useful on developer hosts. Profile loading is
# restricted to disposable GitHub-hosted runners; never change a local host.
if [[ $# == 1 && $1 == --check ]]; then
  probe
  exit 0
fi
if [[ $# != 0 || ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted ]]; then
  echo 'Usage: ci-bubblewrap.sh [--check]; setup requires a GitHub-hosted runner' >&2
  exit 2
fi
if probe; then
  exit 0
fi

restriction=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
if [[ ! -r $restriction || $(cat "$restriction") != 1 ]]; then
  echo 'Bubblewrap probe failed without the Ubuntu AppArmor userns restriction' >&2
  exit 1
fi
# Grant userns setup only to the installed sandbox utility. Do not disable
# AppArmor or its system-wide userns restriction, or remove --unshare-net.
sudo apparmor_parser -r <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>
profile irlume-ci-bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
}
PROFILE
probe
