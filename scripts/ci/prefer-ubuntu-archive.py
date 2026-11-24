#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Remove known slow mirrors from the hosted Ubuntu mirror list."""

import argparse
from pathlib import Path
import sys


AZURE = {
    "http://azure.archive.ubuntu.com/ubuntu",
    "https://azure.archive.ubuntu.com/ubuntu",
}
EC2 = {
    "http://us-east-2.ec2.archive.ubuntu.com/ubuntu",
    "https://us-east-2.ec2.archive.ubuntu.com/ubuntu",
}
ARCHIVE = "https://archive.ubuntu.com/ubuntu"


def without_known_slow_mirrors(text: str) -> str:
    """Preserve the image's entries and metadata except for known slow mirrors."""
    lines = text.splitlines(keepends=True)

    def uri(line: str) -> str:
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            return ""
        return fields[0]

    def is_known_slow_mirror(line: str) -> bool:
        entry = uri(line)
        return entry.rstrip("/") in AZURE or entry.removesuffix("/") in EC2

    if not any(uri(line).rstrip("/") == ARCHIVE for line in lines):
        raise ValueError("expected HTTPS Ubuntu archive fallback is absent")
    return "".join(line for line in lines if not is_known_slow_mirror(line))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mirror_list", nargs="?", type=Path,
                        default=Path("/etc/apt/apt-mirrors.txt"))
    path = parser.parse_args().mirror_list
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError("expected a regular, non-symlink mirror list")
        before = path.read_text()
        after = without_known_slow_mirrors(before)
        if after != before:
            path.write_text(after)
    except (OSError, ValueError) as error:
        print(f"CI APT mirror selection failed: {error}", file=sys.stderr)
        return 1
    print("CI APT: HTTPS Ubuntu archive retained; known Azure and us-east-2 EC2 entries are absent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
