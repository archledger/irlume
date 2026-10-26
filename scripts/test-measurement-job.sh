#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export PYTHONDONTWRITEBYTECODE=1
usage() {
    printf '%s\n' 'usage: test-measurement-job.sh [--build [fresh-output]]' \
        '       test-measurement-job.sh --kernel --execute-disposable-vm --profile FILE' \
        'Default runs portable contracts. Kernel execution is currently unavailable (exit 77).'
}
if [[ $# == 0 ]]; then
    exec python3 "$root/scripts/ci/test-measurement-job.py" --portable
fi
if [[ $1 == --build && $# == 1 ]]; then
    exec python3 "$root/scripts/ci/test-measurement-job.py" --build
fi
if [[ $1 == --build && $# == 2 && -n $2 && $2 != -* ]]; then
    exec python3 "$root/scripts/ci/test-measurement-job.py" --build "$2"
fi
if [[ $# == 4 && $1 == --kernel && $2 == --execute-disposable-vm && $3 == --profile && -n $4 && $4 != -* ]]; then
    if [[ $EUID == 0 ]]; then
        printf '%s\n' 'measurement-job: the VM controller must run unprivileged' >&2
        exit 2
    fi
    exec python3 "$root/scripts/ci/measurement-job-vm.py" --execute-disposable-vm --profile "$4"
fi
if [[ $# == 1 && $1 == --help ]]; then
    usage
    exit 0
fi
usage >&2
exit 2
