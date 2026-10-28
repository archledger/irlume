#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Private read-only input admission. No conversion, recovery or VM is launched."""

import contextlib
import hashlib
import os
import re
import stat
import struct
import time
from builtins import BaseExceptionGroup
from pathlib import Path

CLEANUP_ERRORS = (BaseException,)


def before(deadline):
    if type(deadline) is not int or time.monotonic_ns() >= deadline:
        raise TimeoutError("input deadline")


def identity(info):
    return tuple(
        getattr(info, field)
        for field in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def parent_directory(path):
    """Retain no transient directory FD; bind every traversed directory identity."""
    if (
        not path.is_absolute()
        or ".." in path.parts
        or str(path) != os.path.normpath(path)
    ):
        raise ValueError("input path must be canonical and absolute")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    ancestors = []
    try:
        for part in (None, *path.parent.parts[1:]):
            if part is not None:
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=fd,
                )
                previous, fd = fd, child
                os.close(previous)
            info = os.fstat(fd)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.getuid()) or (
                info.st_mode & 0o022 and not sticky_root
            ):
                raise ValueError("unsafe input ancestor")
            ancestors.append((info.st_dev, info.st_ino))
        info = os.fstat(fd)
        if info.st_mode & 0o022 or (info.st_uid != 0 and info.st_mode & 0o077):
            raise ValueError("input parent is not private or root-controlled")
        return fd, tuple(ancestors)
    except BaseException as error:
        try:
            os.close(fd)
        except CLEANUP_ERRORS as cleanup:
            raise BaseExceptionGroup(
                "input directory and cleanup", [error, cleanup]
            ) from error
        raise


@contextlib.contextmanager
def opened_parent(path):
    fd, ancestors = parent_directory(path)
    try:
        yield fd, ancestors
    except BaseException as error:
        try:
            os.close(fd)
        except CLEANUP_ERRORS as cleanup:
            raise BaseExceptionGroup(
                "input operation and directory close", [error, cleanup]
            ) from error
        raise
    else:
        os.close(fd)


class FrozenInput:
    """Descriptor identity, not a claim that a pre-existing writer is impossible."""

    def __init__(self, path, fd, info, ancestors, digest, deadline):
        self.path, self.fd, self.info = path, fd, info
        self.ancestors, self.sha256, self.deadline = ancestors, digest, deadline

    @classmethod
    def open(cls, path, expected, *, limit, deadline):
        path = Path(path)
        if type(expected) is not str or re.fullmatch("[0-9a-f]{64}", expected) is None:
            raise ValueError("input digest")
        if type(limit) is not int or limit <= 0:
            raise ValueError("input limit")
        before(deadline)
        fd = None
        try:
            with opened_parent(path) as (parent, ancestors):
                fd = os.open(
                    path.name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=parent,
                )
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o6222
                or info.st_nlink != 1
                or not 0 < info.st_size <= limit
            ):
                raise ValueError("unsafe immutable input")
            digest, count = hashlib.sha256(), 0
            while count < info.st_size:
                before(deadline)
                data = os.read(fd, min(1024 * 1024, info.st_size - count))
                if not data:
                    raise ValueError("short immutable input")
                digest.update(data)
                count += len(data)
            before(deadline)
            if (
                identity(os.fstat(fd)) != identity(info)
                or digest.hexdigest() != expected
            ):
                raise ValueError("input changed or digest mismatch")
            result = cls(path, fd, info, ancestors, expected, deadline)
            result.check()
            return result
        except BaseException as error:
            if fd is not None:
                owned, fd = fd, None
                try:
                    os.close(owned)
                except CLEANUP_ERRORS as cleanup:
                    raise BaseExceptionGroup(
                        "input acquisition and cleanup", [error, cleanup]
                    ) from error
            raise

    def check(self):
        self._check_at(self.deadline)

    def _check_at(self, deadline):
        before(deadline)
        if self.fd is None or identity(os.fstat(self.fd)) != identity(self.info):
            raise ValueError("closed or changed input")
        with opened_parent(self.path) as (parent, ancestors):
            named = os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
            if ancestors != self.ancestors or identity(named) != identity(self.info):
                raise ValueError("input path or ancestor replaced")
        before(deadline)

    def recheck(self, deadline):
        """Rehash the retained input for one new phase, without rebasing ownership."""
        self._check_at(deadline)
        digest, offset = hashlib.sha256(), 0
        while offset < self.info.st_size:
            before(deadline)
            data = os.pread(
                self.fd, min(1024 * 1024, self.info.st_size - offset), offset
            )
            if not data:
                raise ValueError("short input phase read")
            digest.update(data)
            offset += len(data)
        if digest.hexdigest() != self.sha256:
            raise ValueError("input phase digest mismatch")
        self._check_at(deadline)

    def read_prefix(self, size):
        if type(size) is not int or not 0 <= size <= 65536:
            raise ValueError("input prefix limit")
        self.check()
        data = os.pread(self.fd, min(size, self.info.st_size), 0)
        self.check()
        if len(data) != min(size, self.info.st_size):
            raise ValueError("short input prefix")
        return data

    def close(self):
        owned, self.fd = self.fd, None
        if owned is not None:
            os.close(owned)

    def __enter__(self):
        return self

    def __exit__(self, kind, error, trace):
        try:
            self.close()
        except CLEANUP_ERRORS as cleanup:
            if error is not None:
                raise BaseExceptionGroup(
                    "input use and close", [error, cleanup]
                ) from error
            raise


def inspect_qcow2(data, *, file_size, expected_backing=None):
    """Admit only the selected v3 profile; QEMU still checks internal consistency.

    Offsets and extension tags follow QEMU v10.2.2 docs/interop/qcow2.rst.
    A raw base is identified by conversion evidence, never by this parser.
    """
    if (
        type(data) is not bytes
        or len(data) != 65536
        or type(file_size) is not int
        or file_size < len(data)
    ):
        raise ValueError("qcow2 first-cluster or file size")
    fields = struct.unpack_from(">IIQIIQIIQQIIQ", data)
    (
        magic,
        version,
        backing_offset,
        backing_size,
        cluster_bits,
        virtual_size,
        crypt,
        l1_size,
        l1_offset,
        refcount_offset,
        refcount_clusters,
        snapshots,
        snapshots_offset,
    ) = fields
    incompatible, compatible, autoclear, refcount_order, header_size = (
        struct.unpack_from(">QQQII", data, 72)
    )
    if (
        magic != 0x514649FB
        or version != 3
        or cluster_bits != 16
        or crypt
        or snapshots
        or snapshots_offset
        or incompatible
        or compatible
        or autoclear
        or refcount_order != 4
        or header_size not in (104, 112)
        or (header_size == 112 and any(data[104:112]))
    ):
        raise ValueError("unsupported qcow2 profile")
    if not 0 < virtual_size <= 4 * 1024**3 or virtual_size % 512:
        raise ValueError("qcow2 virtual size")
    # Restrict admission to tables wholly present in this local file. Deeper
    # cluster/refcount consistency belongs to the bounded QEMU parser.
    required_l1 = (virtual_size + 65536 * 8192 - 1) // (65536 * 8192)
    if (
        not required_l1 <= l1_size <= 4 * 1024**2
        or l1_offset < 65536
        or l1_offset % 65536
        or l1_offset + l1_size * 8 > file_size
        or refcount_offset < 65536
        or refcount_offset % 65536
        or not 1 <= refcount_clusters <= 512
        or refcount_offset + refcount_clusters * 65536 > file_size
    ):
        raise ValueError("qcow2 table bounds")
    l1_end = l1_offset + l1_size * 8
    refcount_end = refcount_offset + refcount_clusters * 65536
    if l1_offset < refcount_end and refcount_offset < l1_end:
        raise ValueError("overlapping qcow2 tables")
    if expected_backing is None:
        if backing_offset or backing_size:
            raise ValueError("unexpected qcow2 backing")
        extension_end = 65536
    else:
        if (
            type(expected_backing) is not str
            or not expected_backing.startswith("/")
            or "\0" in expected_backing
            or ".." in Path(expected_backing).parts
        ):
            raise ValueError("invalid selected backing path")
        raw_backing = expected_backing.encode("utf-8")
        if (
            not 1 <= backing_size <= 1023
            or backing_size != len(raw_backing)
            or backing_offset < header_size + 8
            or backing_offset + backing_size > 65536
            or data[backing_offset : backing_offset + backing_size] != raw_backing
        ):
            raise ValueError("qcow2 backing mismatch")
        extension_end = backing_offset
    position, seen, ended = header_size, set(), False
    while position + 8 <= extension_end:
        kind, size = struct.unpack_from(">II", data, position)
        position += 8
        if kind == 0:
            if size:
                raise ValueError("qcow2 end-marker length")
            ended = True
            break
        padded = (size + 7) & ~7
        if (
            kind not in (0x6803F857, 0xE2792ACA)
            or kind in seen
            or position + padded > extension_end
        ):
            raise ValueError("qcow2 extension type, duplication or bounds")
        seen.add(kind)
        payload = data[position : position + size]
        if any(data[position + size : position + padded]):
            raise ValueError("qcow2 extension padding")
        if kind == 0xE2792ACA:
            if expected_backing is None or payload != b"raw":
                raise ValueError("qcow2 backing format")
        elif size % 48:
            raise ValueError("qcow2 feature-name table size")
        position += padded
    if not ended or (expected_backing is not None and 0xE2792ACA not in seen):
        raise ValueError("qcow2 missing end marker or backing format")
    if any(data[position:extension_end]):
        raise ValueError("qcow2 reserved area not zero")
    if expected_backing is not None and any(data[backing_offset + backing_size :]):
        raise ValueError("qcow2 reserved area after backing not zero")
    return {
        "format": "qcow2",
        "virtual_size": virtual_size,
        "cluster_size": 65536,
        "backing": expected_backing,
    }


if __name__ == "__main__":
    raise SystemExit(77)
