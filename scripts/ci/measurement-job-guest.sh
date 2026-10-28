#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Fixed boot-only guest entry. The installed service verifies the protected
# payload before creating one inert M; this entry cannot start native jobs.
set -eu
readonly collector=/opt/irlume/measurement-job-evidence.py
readonly boot=/opt/irlume/measurement-job-boot.py
if [ "$#" -ne 0 ]; then
    printf '%s\n' 'measurement-job: unexpected guest arguments' >&2
    exit 77
fi
if [ ! -r "$collector" ] || [ ! -r "$boot" ]; then
    printf '%s\n' 'measurement-job: qualified M/E payload absent' >&2
    exit 77
fi
# File presence grants no runtime qualification. The fixed Python entry checks
# its service parent, installed paths, input hashes and namespace/cgroup view.
exec /usr/bin/env -i /usr/bin/python3 -I -B "$boot"
