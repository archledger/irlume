#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export PYTHONDONTWRITEBYTECODE=1
if [[ $# == 0 ]]; then
    exec python3 "$root/scripts/ci/test-measurement-namespace.py"
fi
if [[ $# == 1 && ( $1 == --build || $1 == --kernel ) ]]; then
    exec python3 "$root/scripts/ci/test-measurement-namespace.py" "$1"
fi
echo 'usage: test-measurement-namespace.sh [--build|--kernel]' >&2
exit 2
