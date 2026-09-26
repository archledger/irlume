#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Run the two emitter-lock tests that need a lock file owned by another uid
# (#392): root pre-creates each lock, and the tests run as the calling user.
# Needs passwordless sudo, as on CI's hosted runners. Never touches a camera.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$(id -u)" -eq 0 ]; then
  echo 'emitter-lock-tests: run as an ordinary user; the lock must belong to another uid' >&2
  exit 2
fi
# The lock name is emitter_journal::synchronization_key of the tests'
# identity(): sha256 of "descriptors:<sha256 of the descriptors>|devpath:<len>:<devpath>".
fixture=crates/irlume-camera/tests/fixtures/asus-3277-0059.descriptors
devpath=/devices/pci0000:00/0000:00:14.0/usb3/3-5
descriptors=$(sha256sum "$fixture" | cut -d' ' -f1)
key=$(printf 'descriptors:%s|devpath:%s:%s' "$descriptors" "${#devpath}" "$devpath" |
  sha256sum | cut -d' ' -f1)
lock="irlume-emitter-$key.lock"
work=$(mktemp -d "${TMPDIR:-/tmp}/irlume-emitter-lock.XXXXXXXX")
trap 'sudo rm -rf -- "$work"' EXIT
mkdir "$work/group" "$work/world"
run() {
  IRLUME_EMITTER_LOCK_DIR="$1" ./scripts/run-tests-guarded.sh --require "$2" -- \
    cargo test -p irlume-camera --lib --locked -- --ignored --exact \
    "emitter_journal::tests::$2" --test-threads=1
}
# The daemon's first run leaves root:<camera group> 0660; this user opens it
# through the group bit and cannot chmod it.
sudo install -o root -g "$(id -gn)" -m 0660 /dev/null "$work/group/$lock"
run "$work/group" lock_succeeds_on_a_preexisting_lock_this_process_cannot_chmod
# A lock any local user can open must be refused, not trusted. Its group is
# this user's, as the device's is, so the refusal is about the mode alone.
sudo install -o root -g "$(id -gn)" -m 0666 /dev/null "$work/world/$lock"
run "$work/world" lock_refuses_an_other_accessible_lock_it_cannot_fix
