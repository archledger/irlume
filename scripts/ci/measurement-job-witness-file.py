#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Fixed-name closed startup artifact I/O; no READY or execution authority."""

import contextlib
import hashlib
import os
import re
import stat
import time
from builtins import BaseExceptionGroup

NAME = "startup-witness.json"
LIMIT = 1024**2
CLEANUP_ERRORS = (BaseException,)
FIELDS = (
    "device",
    "inode",
    "mode",
    "uid",
    "gid",
    "links",
    "size",
    "mtime_ns",
    "ctime_ns",
    "sha256",
)


class Deadline:
    def __init__(self, deadline, clock):
        if type(deadline) is not int or not 0 < deadline < 2**64:
            raise ValueError("witness file deadline")
        self.deadline, self.clock, self.previous = deadline, clock, 0
        self.check()

    def check(self):
        now = self.clock()
        if type(now) is not int or now < self.previous or not 0 < now < self.deadline:
            raise TimeoutError("witness file operation expired")
        self.previous = now


@contextlib.contextmanager
def owned(fd):
    try:
        yield fd
    except BaseException as error:
        try:
            os.close(fd)
        except CLEANUP_ERRORS as cleanup:
            raise BaseExceptionGroup(
                "witness file failure and close", [error, cleanup]
            ) from error
        raise
    else:
        os.close(fd)


def check_directory(fd, expected):
    if (
        type(fd) is not int
        or fd < 0
        or type(expected) is not tuple
        or len(expected) != 2
        or any(type(v) is not int or not 0 <= v < 2**64 for v in expected)
        or not expected[1]
    ):
        raise ValueError("witness directory selection")
    info = os.fstat(fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.getuid()
        or (info.st_dev, info.st_ino) != expected
    ):
        raise ValueError("witness directory identity or permissions")


def metadata(info, digest):
    return dict(
        zip(
            FIELDS,
            (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
                info.st_gid,
                info.st_nlink,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
                digest,
            ),
            strict=True,
        )
    )


def check_metadata(value):
    if type(value) is not dict or set(value) != set(FIELDS):
        raise ValueError("witness file metadata shape")
    for name in FIELDS[:-1]:
        lower, upper = (
            (-(2**63), 2**63 - 1)
            if name in ("mtime_ns", "ctime_ns")
            else (0, 2**64 - 1)
        )
        if type(value[name]) is not int or not lower <= value[name] <= upper:
            raise ValueError("witness file metadata scalar")
    if (
        value["mode"] != stat.S_IFREG | 0o400
        or value["uid"] != os.getuid()
        or value["gid"] >= 2**32
        or value["links"] != 1
        or not value["inode"]
        or not 0 < value["size"] <= LIMIT
    ):
        raise ValueError("witness file type, size or permissions")
    if (
        type(value["sha256"]) is not str
        or re.fullmatch("[0-9a-f]{64}", value["sha256"]) is None
    ):
        raise ValueError("witness file digest format")


def write_closed(
    directory, selected_directory, data, digest, deadline, *, clock=time.monotonic_ns
):
    timer = Deadline(deadline, clock)
    if (
        type(data) is not bytes
        or not 0 < len(data) <= LIMIT
        or type(digest) is not str
        or hashlib.sha256(data).hexdigest() != digest
    ):
        raise ValueError("witness bytes or digest")
    check_directory(directory, selected_directory)
    timer.check()
    with owned(
        os.open(
            NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
    ) as fd:
        offset = 0
        while offset < len(data):
            timer.check()
            written = os.write(fd, data[offset : offset + 65536])
            if written <= 0:
                raise OSError("short witness file write")
            offset += written
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        os.fsync(directory)
        timer.check()
        selected = metadata(os.fstat(fd), digest)
        check_metadata(selected)
        named = metadata(os.stat(NAME, dir_fd=directory, follow_symlinks=False), digest)
        if named != selected:
            raise ValueError("witness file replaced during write")
        check_directory(directory, selected_directory)
    timer.check()
    return selected


def read_closed(
    directory, selected_directory, expected, deadline, *, clock=time.monotonic_ns
):
    timer = Deadline(deadline, clock)
    check_metadata(expected)
    selected = dict(expected)
    check_directory(directory, selected_directory)
    timer.check()
    with owned(
        os.open(
            NAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=directory,
        )
    ) as fd:
        actual = metadata(os.fstat(fd), selected["sha256"])
        check_metadata(actual)
        if actual != selected:
            raise ValueError("witness file selection changed")
        pieces, count, digest = [], 0, hashlib.sha256()
        while True:
            timer.check()
            data = os.read(fd, min(65536, selected["size"] + 1 - count))
            if not data:
                break
            count += len(data)
            if count > selected["size"]:
                raise ValueError("witness file grew")
            digest.update(data)
            pieces.append(data)
        if count != selected["size"] or digest.hexdigest() != selected["sha256"]:
            raise ValueError("witness file content changed")
        named = metadata(
            os.stat(NAME, dir_fd=directory, follow_symlinks=False), selected["sha256"]
        )
        if metadata(os.fstat(fd), selected["sha256"]) != selected or named != selected:
            raise ValueError("witness file identity changed during read")
        check_directory(directory, selected_directory)
    result = b"".join(pieces)
    timer.check()
    return result


if __name__ == "__main__":
    raise SystemExit(77)
