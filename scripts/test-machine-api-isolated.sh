#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# The conformance checker reads fixtures outside; each CLI call is isolated.
set -euo pipefail
cd "$(dirname -- "$0")/.."
binary=${1:-${CARGO_TARGET_DIR:-target}/release/irlume}
export IRLUME_TEST_BINARY
IRLUME_TEST_BINARY=$(realpath -- "$binary")
export IRLUME_TEST_RECEIPTS
IRLUME_TEST_RECEIPTS=$(mktemp -d "${TMPDIR:-/tmp}/irlume-conformance.XXXXXXXX")
python3 scripts/machine-api-conformance.py \
  --irlume scripts/ci/isolated-cli-command.py --strict
printf 'Isolation receipts: %s\n' "$IRLUME_TEST_RECEIPTS"
