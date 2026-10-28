#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Read-only self-proc snapshots. No service, namespace or admission operation."""

import contextlib
import fcntl
import os
import re
import stat
import time
from builtins import BaseExceptionGroup

LIMITS = {
    "mountinfo": 1024**2,
    "maps": 1024**2,
    "status": 65536,
    "uid_map": 4096,
    "gid_map": 4096,
}
NAMESPACES = ("pid", "user", "mnt", "net", "cgroup")
START_NS = 5_000_000_000
MAX_OPERATIONS = 1024
MAX_FDS = 128
# Cancellation must not bypass owned-resource cleanup or hide a close failure.
CLEANUP_ERRORS = (BaseException,)


def identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_rdev


class ProcCollector:
    """One bounded observation attempt; partial bytes survive a raised error.

    Callers retain this object on failure to preserve `partial`. Successful
    collection is not root-policy validation or proof of observation origin.
    """

    def __init__(self, deadline_ns, *, _clock=time.monotonic_ns):
        self.clock = _clock
        self.started = self.last_clock = self.clock()
        if type(deadline_ns) is not int or not 0 < deadline_ns < 2**64:
            raise ValueError("startup deadline")
        self.deadline = min(deadline_ns, self.started + START_NS)
        self.operations = 0
        self.owned = {}
        self.partial = {}
        self.used = False
        self._after()

    def _after(self):
        now = self.clock()
        if type(now) is not int or now < self.last_clock or now >= self.deadline:
            raise TimeoutError("startup observation deadline or clock regression")
        self.last_clock = now
        return now

    def _before(self):
        self._after()
        self.operations += 1
        if self.operations > MAX_OPERATIONS:
            raise ValueError("startup observation operation cap")

    def _call(self, operation, *args, **kwargs):
        self._before()
        result = operation(*args, **kwargs)
        self._after()
        return result

    @contextlib.contextmanager
    def _closing(self, close):
        try:
            yield
        except BaseException as error:
            try:
                close()
            except CLEANUP_ERRORS as cleanup:
                raise BaseExceptionGroup(
                    "startup observation and cleanup", [error, cleanup]
                ) from error
            raise
        else:
            close()
            self._after()

    def _close_fd(self, fd):
        # A failed close must not be retried: Linux may already have reused it.
        self.owned.pop(fd)
        os.close(fd)

    @contextlib.contextmanager
    def _open(self, path, *, dir_fd=None, directory=False, path_only=False):
        flags = os.O_CLOEXEC | os.O_NOFOLLOW
        flags |= os.O_PATH if path_only else os.O_RDONLY | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        self._before()
        fd = os.open(path, flags, dir_fd=dir_fd)
        self.owned[fd] = None  # Own even an open that completed after the deadline.
        with self._closing(lambda: self._close_fd(fd)):
            self._after()
            self.owned[fd] = identity(self._call(os.fstat, fd))
            if self._call(os.get_inheritable, fd):
                raise ValueError("inheritable startup observation descriptor")
            yield fd

    def _read(self, proc_fd, name, limit):
        if (
            re.fullmatch("[a-z_]+", name) is None
            or type(limit) is not int
            or not 0 < limit <= 1024**2
        ):
            raise ValueError("startup proc field")
        data = bytearray()
        with self._open(name, dir_fd=proc_fd) as fd:
            if not stat.S_ISREG(self._call(os.fstat, fd).st_mode):
                raise ValueError("startup proc field is not regular")
            while len(data) <= limit:
                self._before()
                chunk = os.read(fd, min(16384, limit + 1 - len(data)))
                data.extend(chunk)
                self.partial[name] = bytes(data)
                self._after()  # Retain returned bytes before checking a late read.
                if not chunk:
                    return bytes(data)
            raise ValueError("startup proc field byte cap")

    def _stdio(self):
        result = []
        for fd in range(3):
            info = self._call(os.fstat, fd)
            flags = self._call(fcntl.fcntl, fd, fcntl.F_GETFL)
            access = flags & os.O_ACCMODE
            if flags & os.O_PATH or access not in (
                (os.O_RDONLY, os.O_RDWR) if fd == 0 else (os.O_WRONLY, os.O_RDWR)
            ):
                raise ValueError("unusable startup standard descriptor")
            result.append((fd, identity(info), flags))
        return tuple(result)

    def _inventory(self):
        numbers, enumerators = set(), []
        stdio = {}
        with self._open(f"/proc/{os.getpid()}/fd", directory=True) as directory:
            directory_identity = self.owned[directory]
            self._before()
            iterator = os.scandir(directory)
            with self._closing(iterator.close):
                self._after()
                while True:
                    self._before()
                    try:
                        entry = next(iterator)
                    except StopIteration:
                        self._after()
                        break
                    self._after()
                    if re.fullmatch("0|[1-9][0-9]{0,9}", entry.name) is None:
                        raise ValueError("invalid startup descriptor name")
                    fd = int(entry.name)
                    if fd > 2**31 - 1 or fd in numbers or len(numbers) >= MAX_FDS:
                        raise ValueError(
                            "startup descriptor inventory cap or duplicate"
                        )
                    numbers.add(fd)
                    # Inspect while the iterator still owns its duplicate FD.
                    observed = identity(self._call(os.fstat, fd))
                    if fd in self.owned:
                        if observed != self.owned[fd]:
                            raise ValueError("startup owned descriptor replaced")
                    elif fd <= 2:
                        stdio[fd] = observed
                    elif observed == directory_identity:
                        enumerators.append(fd)
                    else:
                        raise ValueError("unexpected inherited startup descriptor")
        if len(enumerators) != 1 or set(stdio) != {0, 1, 2}:
            raise ValueError(
                "startup enumerator identity or standard descriptor inventory"
            )
        return tuple(sorted(stdio))

    def _namespaces(self, proc_fd):
        return {
            name: self._call(os.stat, "ns/" + name, dir_fd=proc_fd).st_ino
            for name in NAMESPACES
        }

    @staticmethod
    def _single_thread(data):
        values = [
            line.partition(b":")[2].strip()
            for line in data.splitlines()
            if line.startswith(b"Threads:")
        ]
        if not data.endswith(b"\n") or values != [b"1"]:
            raise ValueError("startup snapshot requires one thread")

    def collect(self):
        if self.used:
            raise ValueError("startup collector is single-use")
        self.used = True
        stdio = self._stdio()
        fds = self._inventory()
        with self._open("/", directory=True) as root_fd:
            root_info = identity(self._call(os.fstat, root_fd))
            with self._open(f"/proc/{os.getpid()}", directory=True) as proc_fd:
                namespaces = self._namespaces(proc_fd)
                status_before = self._read(proc_fd, "status", LIMITS["status"])
                self._single_thread(status_before)
                self.partial["status_before"] = status_before
                row = {
                    name: self._read(proc_fd, name, limit)
                    for name, limit in LIMITS.items()
                    if name != "status"
                }
                row["status"] = self._read(proc_fd, "status", LIMITS["status"])
                self._single_thread(row["status"])
                if namespaces != self._namespaces(proc_fd) or root_info != identity(
                    self._call(os.stat, "/")
                ):
                    raise ValueError("startup root or namespace changed")
                if self._inventory() != fds:
                    raise ValueError("startup descriptor inventory changed")
        if self._inventory() != fds or self._stdio() != stdio:
            raise ValueError("startup standard descriptors changed")
        row.update(
            root={"device": root_info[0], "inode": root_info[1]},
            namespaces=namespaces,
            fds=fds,
            stdio=stdio,
            status_before=status_before,
            started_ns=self.started,
            finished_ns=self._after(),
        )
        return row
