#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Fixed guest boot entry, source-prepared only. Do not execute in Task2.
# Future boot integration must start independent E and M outside J; E must
# outlive M/J and retain its own ledger. Never substitute the inactive fixture
# for M or infer boot trust from that ledger's own JSON fields.
set -eu
readonly collector=/opt/irlume/measurement-job-evidence
readonly manager=/opt/irlume/measurement_job_fixture
if [ "$#" -ne 0 ]; then
    printf '%s\n' 'measurement-job: unexpected guest arguments' >&2
    exit 77
fi
if [ ! -r "$collector" ] || [ ! -r "$manager" ]; then
    printf '%s\n' 'measurement-job: qualified M/E payload absent' >&2
    exit 77
fi
# Presence alone is not qualification. No environment flag or file marker can
# open this gate. Replace this refusal only with separately reviewed boot and
# payload integration after the privileged runtime tasks are authorized.
printf '%s\n' 'measurement-job: qualified M/E boot integration unavailable' >&2
exit 77
