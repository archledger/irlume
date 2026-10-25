#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Synthetic mount-lifetime checks; kernel mode requires real isolated mounts.
set -euo pipefail
cd "$(dirname -- "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
if [[ $# == 0 ]]; then
    exec python3 scripts/ci/test-measurement-generation.py
fi
if [[ $# == 1 && $1 == --kernel ]]; then
    exec python3 scripts/ci/test-measurement-generation.py --kernel
fi
echo 'usage: test-measurement-generation.sh [--kernel]' >&2
exit 2
