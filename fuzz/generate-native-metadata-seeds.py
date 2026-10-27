#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Construct the two synthetic ELF parser inputs without storing binaries in Git."""

import argparse
import os
import stat
import struct
from pathlib import Path


def seeds():
    """Return a metadata-only ELF64 ET_DYN and its truncated prefix."""
    strings = b"\0libfixture.so\0"
    dynamic_at, strings_at, base = 176, 240, 0x1000
    image = bytearray(strings_at + len(strings))
    image[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into(
        "<HHIQQQIHHHHHH", image, 16, 3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0
    )
    # Read-only PT_LOAD covers the bytes; there is no executable segment.
    struct.pack_into(
        "<IIQQQQQQ", image, 64, 1, 4, 0, base, base, len(image), len(image), 4096
    )
    struct.pack_into(
        "<IIQQQQQQ", image, 120, 2, 4, dynamic_at, base + dynamic_at, 0, 64, 64, 8
    )
    for index, (tag, value) in enumerate(
        [
            (5, base + strings_at),  # DT_STRTAB
            (10, len(strings)),  # DT_STRSZ
            (1, 1),  # DT_NEEDED: libfixture.so
            (0, 0),  # DT_NULL
        ]
    ):
        struct.pack_into("<qQ", image, dynamic_at + index * 16, tag, value)
    image[strings_at:] = strings
    return {"needed.elf": bytes(image), "truncated.elf": bytes(image[:180])}


def generate(directory):
    """Add exact seeds, preserving existing corpus inputs or refusing a conflict."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in seeds().items():
        path = directory / name
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError(f"non-regular seed: {path}")
                if stream.read(len(data) + 1) != data:
                    raise ValueError(f"conflicting seed: {path}")
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="native_metadata corpus directory")
    args = parser.parse_args()
    try:
        generate(args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"seed generation failed: {error}\n")


if __name__ == "__main__":
    main()
