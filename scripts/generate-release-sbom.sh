#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Preserve the release command while Python handles isolated generation.
set -euo pipefail
exec python3 "$(dirname "$0")/generate-release-sbom.py" "$@"
