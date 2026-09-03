#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.

import argparse
import pathlib
import re
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MATRIX = ROOT / "packaging/openvino/matrix.toml"
REQUIRED = (
    "status",
    "openvino",
    "level_zero_tag",
    "level_zero_commit",
    "npu_userspace",
    "gpu_status",
)


def validate(matrix: object) -> list[str]:
    if not isinstance(matrix, dict):
        return ["matrix root must be a TOML table"]
    errors = [f"missing required provenance: {key}" for key in REQUIRED if not matrix.get(key)]
    if matrix.get("status") != "experimental":
        errors.append("status must be experimental until release evidence exists")
    commit = matrix.get("level_zero_commit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        errors.append("level_zero_commit must be 40 lowercase hexadecimal characters")
    gpu_status = matrix.get("gpu_status")
    if gpu_status not in ("disabled-unqualified", "enabled-qualified"):
        errors.append("gpu_status must be disabled-unqualified or enabled-qualified")
    if gpu_status == "enabled-qualified" and not isinstance(matrix.get("gpu"), dict):
        errors.append("enabled-qualified requires a separate GPU matrix")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the pinned experimental OpenVINO matrix")
    parser.add_argument("--matrix", type=pathlib.Path, default=DEFAULT_MATRIX)
    args = parser.parse_args()
    try:
        with args.matrix.open("rb") as file:
            matrix = tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"OpenVINO matrix unreadable: {error}", file=sys.stderr)
        return 1
    errors = validate(matrix)
    if errors:
        for error in errors:
            print(f"OpenVINO matrix invalid: {error}", file=sys.stderr)
        return 1
    print("experimental NPU matrix valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
