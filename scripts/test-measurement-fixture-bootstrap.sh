#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export PYTHONDONTWRITEBYTECODE=1
if [[ ${1:-} == --kernel ]]; then
    if [[ $# != 1 ]]; then
        echo 'usage: test-measurement-fixture-bootstrap.sh [--kernel]' >&2
        exit 2
    fi
    exec env CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 \
        CARGO_PROFILE_RELEASE_DEBUG=0 python3 "$root/scripts/ci/test-measurement-fixture-bootstrap.py" --kernel
fi
if [[ $# != 0 ]]; then
    echo 'usage: test-measurement-fixture-bootstrap.sh [--kernel]' >&2
    exit 2
fi
exec python3 "$root/scripts/ci/test-measurement-fixture-bootstrap.py"
