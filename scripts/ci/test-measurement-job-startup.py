#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Read-only self-proc observations and fault injection; never a service or VM."""

import errno
import hashlib
import importlib.util
import mmap
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "startup", HERE / "measurement-job-startup.py"
)
startup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(startup)


def deadline():
    return time.monotonic_ns() + 5_000_000_000


def kernel_threads():
    with open("/proc/self/status", "rb") as stream:
        for line in stream:
            if line.startswith(b"Threads:"):
                return int(line.partition(b":")[2])
    raise AssertionError("no Threads line")


def await_single_thread(limit_ns=2_000_000_000):
    # join() returns once the thread clears its TID, before the kernel drops
    # it from the thread group: a later self snapshot can still count two.
    end = time.monotonic_ns() + limit_ns
    while kernel_threads() != 1 and time.monotonic_ns() < end:
        time.sleep(0.001)
    return kernel_threads()


PAGE = 4096
# Linux v7.2 fs/proc/task_mmu.c:1951-1957.
SOFT_DIRTY, EXCLUSIVE, GUARD = 1 << 55, 1 << 56, 1 << 58
PM_FILE, PM_SWAP, PM_PRESENT = 1 << 61, 1 << 62, 1 << 63


def page_digest(data):
    return hashlib.sha256(data.ljust(PAGE, b"\0")).digest()


def mapping_of(path):
    """(start, end) of path's only mapping in this process."""
    # maps shows the resolved path, also when TMPDIR is a symbolic link.
    resolved = str(Path(path).resolve())
    rows = [
        line.split()[0]
        for line in Path("/proc/self/maps").read_text().splitlines()
        if line.endswith(" " + resolved)
    ]
    if len(rows) != 1:
        raise AssertionError(f"{len(rows)} mappings of {path}")
    start, end = (int(value, 16) for value in rows[0].split("-"))
    return start, end


class ProcTests(unittest.TestCase):
    def test_path_only_handle_inspects_symlink_without_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "link"
            path.symlink_to("missing-target")
            collector = startup.ProcCollector(deadline())
            with collector._open(path, path_only=True) as fd:
                self.assertTrue(startup.stat.S_ISLNK(os.fstat(fd).st_mode))
                self.assertEqual(os.readlink("", dir_fd=fd), "missing-target")
                with self.assertRaises(OSError):
                    os.read(fd, 1)
            self.assertEqual(collector.owned, {})

    def test_real_multithreaded_process_cannot_supply_startup_snapshot(self):
        stop = threading.Event()
        worker = threading.Thread(target=stop.wait)
        worker.start()
        try:
            collector = startup.ProcCollector(deadline())
            with self.assertRaises(ValueError):
                collector.collect()
            self.assertEqual(collector.owned, {})
        finally:
            stop.set()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(await_single_thread(), 1)

    def test_thread_count_is_checked_after_the_last_proc_read(self):
        collector = startup.ProcCollector(deadline())
        read = collector._read
        changed = [False]

        def changing(proc_fd, name, limit):
            data = read(proc_fd, name, limit)
            if name == "gid_map":
                changed[0] = True
            if name == "status" and changed[0]:
                return b"Threads:\t2\n"
            return data

        with (
            mock.patch.object(collector, "_read", side_effect=changing),
            self.assertRaises(ValueError),
        ):
            collector.collect()
        self.assertEqual(collector.owned, {})

    def test_real_self_proc_snapshot_is_raw_evidence_not_admission(self):
        collector = startup.ProcCollector(deadline())
        row = collector.collect()
        self.assertEqual(row["fds"], (0, 1, 2))
        self.assertEqual(
            set(row["namespaces"]), {"mnt", "pid", "user", "net", "cgroup"}
        )
        self.assertGreater(row["root"]["inode"], 0)
        for name in ("status", "mountinfo", "maps", "uid_map", "gid_map"):
            self.assertIs(type(row[name]), bytes)
            self.assertTrue(row[name].endswith(b"\n"))
        self.assertLess(row["started_ns"], row["finished_ns"])
        self.assertNotIn("accepted", row)
        self.assertEqual(collector.owned, {})
        with self.assertRaises(ValueError):
            collector.collect()

    def test_foreign_fd_is_rejected_even_when_it_is_the_same_proc_directory(self):
        for target in ("/dev/null", "/proc/self/fd"):
            fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
            try:
                collector = startup.ProcCollector(deadline())
                with self.subTest(target=target), self.assertRaises(ValueError):
                    collector.collect()
                self.assertEqual(collector.owned, {})
                os.fstat(fd)
            finally:
                os.close(fd)

    def test_expired_or_invalid_deadline_opens_nothing(self):
        for value in (True, 0, -1, 2**64, time.monotonic_ns() - 1):
            with (
                self.subTest(value=value),
                mock.patch.object(startup.os, "open") as opened,
            ):
                with self.assertRaises((ValueError, TimeoutError)):
                    startup.ProcCollector(value).collect()
                opened.assert_not_called()

    def test_bounded_read_rejects_overflow_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "status").write_bytes(b"x" * 33)
            (path / "link").symlink_to("status")
            os.mkfifo(path / "fifo")
            fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
            try:
                for name in ("status", "link", "fifo"):
                    collector = startup.ProcCollector(deadline())
                    with (
                        self.subTest(name=name),
                        self.assertRaises((ValueError, OSError)),
                    ):
                        collector._read(fd, name, 32)
                    self.assertEqual(collector.owned, {})
                self.assertEqual(len(collector.partial.get("fifo", b"")), 0)
            finally:
                os.close(fd)

    def test_late_open_is_closed_and_late_read_retains_returned_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status"
            path.write_bytes(b"returned\n")
            fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
            clock = [1]
            collector = startup.ProcCollector(100, _clock=lambda: clock[0])
            real_open, real_read = os.open, os.read
            acquired = []

            def late_open(*args, **kwargs):
                result = real_open(*args, **kwargs)
                acquired.append(result)
                clock[0] = 101
                return result

            try:
                with (
                    mock.patch.object(startup.os, "open", side_effect=late_open),
                    self.assertRaises(TimeoutError),
                ):
                    collector._read(fd, "status", 32)
                self.assertEqual(collector.owned, {})
                with self.assertRaises(OSError):
                    os.fstat(acquired[0])
                clock[0] = 1
                collector = startup.ProcCollector(100, _clock=lambda: clock[0])

                def late_read(*args):
                    data = real_read(*args)
                    clock[0] = 101
                    return data

                with (
                    mock.patch.object(startup.os, "read", side_effect=late_read),
                    self.assertRaises(TimeoutError),
                ):
                    collector._read(fd, "status", 32)
                self.assertIn("status", collector.partial)
                self.assertEqual(collector.partial["status"], b"returned\n")
                self.assertEqual(collector.owned, {})
            finally:
                os.close(fd)

    def test_missing_stdio_is_never_repaired(self):
        code = f"""import importlib.util,os,time
s=importlib.util.spec_from_file_location("startup",{str(HERE / "measurement-job-startup.py")!r})
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
os.close(0)
try:m.ProcCollector(time.monotonic_ns()+5000000000).collect()
except OSError:
    try:os.fstat(0)
    except OSError:raise SystemExit(77)
raise SystemExit(1)
"""
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-X",
                "pycache_prefix=/dev/null",
                "-c",
                code,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 77, result.stderr)

    def test_unusable_stdio_is_refused_before_any_open(self):
        collector = startup.ProcCollector(deadline())
        real_fcntl = startup.fcntl.fcntl
        for fd, flags in ((0, os.O_WRONLY), (1, os.O_RDONLY), (2, os.O_PATH)):

            def bad_mode(target, command, fd=fd, flags=flags):
                return flags if target == fd else real_fcntl(target, command)

            with (
                mock.patch.object(startup.fcntl, "fcntl", side_effect=bad_mode),
                mock.patch.object(startup.os, "open") as opened,
            ):
                with self.subTest(fd=fd), self.assertRaises(ValueError):
                    startup.ProcCollector(deadline()).collect()
                opened.assert_not_called()
        self.assertEqual(collector.owned, {})

    def test_namespace_or_standard_identity_change_refuses_snapshot(self):
        collector = startup.ProcCollector(deadline())
        original = collector._namespaces
        calls = [0]

        def different(fd):
            result = original(fd)
            calls[0] += 1
            if calls[0] == 2:
                result["mnt"] += 1
            return result

        with (
            mock.patch.object(collector, "_namespaces", side_effect=different),
            self.assertRaises(ValueError),
        ):
            collector.collect()
        self.assertEqual(collector.owned, {})
        collector = startup.ProcCollector(deadline())
        stdio = collector._stdio()
        changed = (*stdio[:2], (2, stdio[2][1], stdio[2][2] ^ os.O_APPEND))
        with (
            mock.patch.object(collector, "_stdio", side_effect=[stdio, changed]),
            self.assertRaises(ValueError),
        ):
            collector.collect()

    def test_descriptor_cap_duplicate_and_missing_enumerator_close_resources(self):
        collector = startup.ProcCollector(deadline())
        with mock.patch.object(startup, "MAX_FDS", 1), self.assertRaises(ValueError):
            collector._inventory()
        self.assertEqual(collector.owned, {})
        for names in (("0", "0"), ("bad",), ("0", "1", "2")):
            iterator = mock.MagicMock()
            iterator.__next__ = mock.Mock(
                side_effect=[
                    *(SimpleNamespace(name=name) for name in names),
                    StopIteration,
                ]
            )
            with (
                mock.patch.object(startup.os, "scandir", return_value=iterator),
                self.assertRaises(ValueError),
            ):
                collector._inventory()
            iterator.close.assert_called_once()
            self.assertEqual(collector.owned, {})

    def test_noncanonical_numeric_fd_name_is_rejected_before_conversion(self):
        real_scandir = os.scandir
        collector = startup.ProcCollector(deadline())

        class RenamedIterator:
            def __init__(self, fd):
                self.iterator = real_scandir(fd)

            def __next__(self):
                entry = next(self.iterator)
                return SimpleNamespace(name="+0") if entry.name == "0" else entry

            def close(self):
                self.iterator.close()

        with (
            mock.patch.object(startup.os, "scandir", side_effect=RenamedIterator),
            self.assertRaises(ValueError),
        ):
            collector._inventory()
        self.assertEqual(collector.owned, {})

    def test_late_scandir_acquisition_closes_iterator_and_owned_directory(self):
        now = [1]
        collector = startup.ProcCollector(100, _clock=lambda: now[0])
        real_scandir = os.scandir
        acquired = []

        def late(directory):
            iterator = real_scandir(directory)
            acquired.append((directory, iterator))
            now[0] = 100
            return iterator

        with (
            mock.patch.object(startup.os, "scandir", side_effect=late),
            self.assertRaises(TimeoutError),
        ):
            collector._inventory()
        self.assertEqual(collector.owned, {})
        self.assertEqual(len(acquired), 1)
        directory, iterator = acquired[0]
        with self.assertRaises(StopIteration):
            next(iterator)
        with self.assertRaises(OSError):
            os.fstat(directory)

    def test_listed_descriptor_vanishing_is_not_ignored(self):
        collector = startup.ProcCollector(deadline())
        real_fstat, real_scandir = os.fstat, os.scandir
        acquired = []

        def observe_iterator(directory):
            iterator = real_scandir(directory)
            acquired.append(iterator)
            return iterator

        def vanishing(fd):
            if fd == 0:
                raise OSError(errno.EBADF, "injected vanished descriptor")
            return real_fstat(fd)

        with (
            mock.patch.object(startup.os, "scandir", side_effect=observe_iterator),
            mock.patch.object(startup.os, "fstat", side_effect=vanishing),
            self.assertRaises(OSError) as caught,
        ):
            collector._inventory()
        self.assertEqual(caught.exception.errno, errno.EBADF)
        self.assertEqual(collector.owned, {})
        self.assertEqual(len(acquired), 1)
        with self.assertRaises(StopIteration):
            next(acquired[0])
        real_fstat(0)  # The failure was injected; the collector did not close stdin.

    def test_cancellation_and_cleanup_errors_are_both_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "status").write_bytes(b"data\n")
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            collector = startup.ProcCollector(deadline())
            closed = []
            real_close = os.close

            def close_then_fail(number):
                real_close(number)
                closed.append(number)
                raise OSError("injected close failure")

            try:
                with (
                    mock.patch.object(
                        startup.os, "read", side_effect=KeyboardInterrupt
                    ),
                    mock.patch.object(startup.os, "close", side_effect=close_then_fail),
                    self.assertRaises(BaseExceptionGroup) as caught,
                ):
                    collector._read(fd, "status", 100)
                self.assertIsInstance(caught.exception.exceptions[0], KeyboardInterrupt)
                self.assertIsInstance(caught.exception.exceptions[1], OSError)
                self.assertEqual(collector.owned, {})
                self.assertEqual(len(closed), 1)
                with self.assertRaises(OSError):
                    os.fstat(closed[0])
            finally:
                os.close(fd)

    def test_operation_cap_admits_exactly_its_budget(self):
        collector = startup.ProcCollector(time.monotonic_ns() + 5_000_000_000)
        collector.operations = startup.MAX_OPERATIONS - 1
        self.assertEqual(collector._call(os.getpid), os.getpid())
        self.assertEqual(collector.operations, startup.MAX_OPERATIONS)
        with self.assertRaisesRegex(ValueError, "^startup observation operation cap$"):
            collector._call(os.getpid)

    def test_deadline_ceiling_operation_budget_and_post_cleanup_check(self):
        now = [1]
        collector = startup.ProcCollector(100_000_000_000, _clock=lambda: now[0])
        self.assertEqual(collector.deadline, 1 + startup.START_NS)
        with (
            mock.patch.object(startup, "MAX_OPERATIONS", 0),
            self.assertRaises(ValueError),
        ):
            collector._inventory()
        self.assertEqual(collector.owned, {})
        collector = startup.ProcCollector(100, _clock=lambda: now[0])
        real_close = os.close

        def late_close(fd):
            real_close(fd)
            now[0] = 100

        with (
            mock.patch.object(startup.os, "close", side_effect=late_close),
            self.assertRaises(TimeoutError),
            collector._open("/", directory=True),
        ):
            pass
        self.assertEqual(collector.owned, {})

    def test_normal_bounded_read_accepts_exact_limit_and_cloexec_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "status").write_bytes(b"x" * 32)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                collector = startup.ProcCollector(deadline())
                self.assertEqual(collector._read(fd, "status", 32), b"x" * 32)
                with (
                    mock.patch.object(startup.os, "get_inheritable", return_value=True),
                    self.assertRaises(ValueError),
                ):
                    collector._read(fd, "status", 32)
                self.assertEqual(collector.owned, {})
            finally:
                os.close(fd)

    def test_io_call_checks_deadline_before_dispatch_and_after_return(self):
        now = [1]
        collector = startup.ProcCollector(100, _clock=lambda: now[0])
        now[0] = 100
        operation = mock.Mock()
        with self.assertRaises(TimeoutError):
            collector._call(operation)
        operation.assert_not_called()
        now[0] = 1
        collector = startup.ProcCollector(100, _clock=lambda: now[0])

        def late():
            now[0] = 100
            return "result"

        with self.assertRaises(TimeoutError):
            collector._call(late)

    def test_root_identity_change_is_rejected(self):
        collector = startup.ProcCollector(deadline())
        real_stat = os.stat

        def changed(path, *args, **kwargs):
            row = real_stat(path, *args, **kwargs)
            if path == "/":
                return SimpleNamespace(
                    st_dev=row.st_dev,
                    st_ino=row.st_ino + 1,
                    st_mode=row.st_mode,
                    st_rdev=row.st_rdev,
                )
            return row

        with (
            mock.patch.object(startup.os, "stat", side_effect=changed),
            self.assertRaises(ValueError),
        ):
            collector.collect()
        self.assertEqual(collector.owned, {})

    def test_owned_descriptor_replacement_is_not_hidden_as_an_enumerator(self):
        collector = startup.ProcCollector(deadline())
        real_fstat = os.fstat
        counts = {}

        def replaced(fd):
            row = real_fstat(fd)
            counts[fd] = counts.get(fd, 0) + 1
            if fd in collector.owned and counts[fd] > 1:
                return SimpleNamespace(
                    st_dev=row.st_dev,
                    st_ino=row.st_ino + 1,
                    st_mode=row.st_mode,
                    st_rdev=row.st_rdev,
                )
            return row

        with (
            mock.patch.object(startup.os, "fstat", side_effect=replaced),
            self.assertRaises(ValueError),
        ):
            collector._inventory()
        self.assertEqual(collector.owned, {})


class MappedTests(unittest.TestCase):
    """G's own mapped pages: mem first, then pagemap, digests only."""

    def private_mapping(self, data):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "member"
        path.write_bytes(data)
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            view = mmap.mmap(
                fd,
                len(data),
                flags=mmap.MAP_PRIVATE,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
        finally:
            os.close(fd)
        self.addCleanup(view.close)
        return path, view

    def collect(self, collector, regions):
        try:
            with collector._open(f"/proc/{os.getpid()}", directory=True) as proc:
                return collector._mapped(proc, regions)
        finally:
            self.assertEqual(collector.owned, {})

    def fake_proc(self, pages, *, short_pagemap=False):
        """A directory whose mem and pagemap hold pages at kernel offsets."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        base = Path(directory.name)
        with open(base / "mem", "wb") as mem, open(base / "pagemap", "wb") as table:
            for address, (data, entry) in sorted(pages.items()):
                mem.seek(address)
                mem.write(data)
                table.seek(address // PAGE * 8)
                table.write(entry.to_bytes(8, sys.byteorder))
        if short_pagemap:
            os.truncate(base / "pagemap", (base / "pagemap").stat().st_size - 1)
        fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        return base, fd

    def test_real_private_mapping_counts_written_pages_and_digests_the_rest(self):
        # Ten pages, the last partial: a two-byte bitmap with six padding bits.
        data = b"".join(bytes([65 + index]) * PAGE for index in range(9)) + b"tail"
        path, view = self.private_mapping(data)
        self.assertEqual(view[PAGE], 66)
        view[2 * PAGE + 1] = 0  # Page 2 is copied on write.
        start, end = mapping_of(path)
        self.assertEqual(end - start, 10 * PAGE)
        collector = startup.ProcCollector(deadline())
        (row,) = self.collect(collector, ((start, end),))
        self.assertEqual(set(row), {"start", "end", "anonymous", "sha256"})
        self.assertEqual((row["start"], row["end"]), (start, end))
        self.assertEqual(row["anonymous"], bytes([0b100, 0]))
        expected = b"".join(
            page_digest(data[index * PAGE : (index + 1) * PAGE])
            for index in range(10)
            if index != 2
        )
        self.assertEqual(row["sha256"], hashlib.sha256(expected).hexdigest())
        self.assertEqual(collector.partial["mapped"], (row,))

    def test_real_unreadable_page_refuses_a_short_or_failed_read(self):
        path, _ = self.private_mapping(b"x" * (3 * PAGE))
        start, end = mapping_of(path)
        os.truncate(path, PAGE)  # Pages 1 and 2 now lie past the end.
        with self.assertRaisesRegex(ValueError, "^startup mapped read short$"):
            self.collect(startup.ProcCollector(deadline()), ((start, end),))
        with self.assertRaises(OSError) as caught:
            self.collect(startup.ProcCollector(deadline()), ((start + PAGE, end),))
        self.assertEqual(caught.exception.errno, errno.EIO)

    def test_page_kinds_follow_the_kernel_file_swap_and_present_bits(self):
        entries = (
            0,  # pte_none: the next fault reads the file
            PM_PRESENT | PM_FILE,
            PM_PRESENT,  # a private copy
            PM_SWAP,  # a swapped private copy has no page, so no PM_FILE
            PM_SWAP | PM_FILE,  # a migrating file page
            PM_PRESENT | PM_FILE | SOFT_DIRTY | EXCLUSIVE,
            PM_PRESENT | EXCLUSIVE,
            SOFT_DIRTY,
            PM_SWAP | GUARD,
        )
        address = 0x40000
        pages = {
            address + index * PAGE: (bytes([index + 1]) * PAGE, entry)
            for index, entry in enumerate(entries)
        }
        _, fd = self.fake_proc(pages)
        end = address + len(entries) * PAGE
        (row,) = startup.ProcCollector(deadline())._mapped(fd, ((address, end),))
        anonymous = {2, 3, 6, 8}
        self.assertEqual(row["anonymous"], bytes([0b01001100, 0b1]))
        expected = b"".join(
            page_digest(bytes([index + 1]) * PAGE)
            for index in range(len(entries))
            if index not in anonymous
        )
        self.assertEqual(row["sha256"], hashlib.sha256(expected).hexdigest())

    def test_adjacent_regions_share_a_run_read_mem_first_in_bounded_chunks(self):
        base = 0x100000
        regions = (
            (base, base + 0x80000),
            (base + 0x80000, base + 0x180000),
            (base + 0x200000, base + 0x201000),
        )
        pages = {
            address: (bytes([address >> 12 & 0xFF]) * PAGE, PM_PRESENT | PM_FILE)
            for start, end in regions
            for address in range(start, end, PAGE)
        }
        _, fd = self.fake_proc(pages)
        reads, real = [], os.pread

        def record(descriptor, size, offset):
            name = os.readlink(f"/proc/self/fd/{descriptor}").rpartition("/")[2]
            reads.append((name, size, offset))
            return real(descriptor, size, offset)

        collector = startup.ProcCollector(deadline())
        before = collector.operations
        with mock.patch.object(startup.os, "pread", side_effect=record):
            rows = collector._mapped(fd, regions)
        self.assertEqual(
            reads,
            [
                ("mem", 1024**2, base),
                ("mem", 0x80000, base + 0x100000),
                ("pagemap", 0x180 * 8, base // PAGE * 8),
                ("mem", PAGE, base + 0x200000),
                ("pagemap", 8, (base + 0x200000) // PAGE * 8),
            ],
        )
        # Two opens of three counted operations each, and one per read.
        self.assertEqual(collector.operations - before, 6 + len(reads))
        self.assertEqual(collector.owned, {})
        self.assertEqual([(row["start"], row["end"]) for row in rows], list(regions))
        for (start, end), row in zip(regions, rows):
            count = (end - start) // PAGE
            self.assertEqual(row["anonymous"], bytes((count + 7) // 8))
            expected = b"".join(
                page_digest(pages[address][0]) for address in range(start, end, PAGE)
            )
            self.assertEqual(row["sha256"], hashlib.sha256(expected).hexdigest())

    def test_later_regions_of_a_run_read_their_own_page_kinds(self):
        # One run of two regions, private copies at different positions: each
        # region's bitmap must come from its own pagemap entries.
        first, second = (0x40000, 0x42000), (0x42000, 0x44000)
        entries = (PM_PRESENT, PM_PRESENT | PM_FILE, PM_PRESENT | PM_FILE, PM_PRESENT)
        pages = {
            first[0] + index * PAGE: (bytes([index + 1]) * PAGE, entry)
            for index, entry in enumerate(entries)
        }
        _, fd = self.fake_proc(pages)
        rows = startup.ProcCollector(deadline())._mapped(fd, (first, second))
        self.assertEqual([row["anonymous"] for row in rows], [b"\x01", b"\x02"])
        for row, kept in zip(rows, (1, 2)):
            self.assertEqual(
                row["sha256"],
                hashlib.sha256(page_digest(bytes([kept + 1]) * PAGE)).hexdigest(),
            )

    def test_pagemap_entries_past_one_read_come_from_their_own_offset(self):
        base, count = 0x100000, 600
        pages = {
            base + index * PAGE: (bytes([index % 251 + 1]) * PAGE, PM_PRESENT | PM_FILE)
            for index in range(count)
        }
        # Private copies before and after the first 512 entries (one read).
        for index in (100, 520):
            pages[base + index * PAGE] = (pages[base + index * PAGE][0], PM_PRESENT)
        _, fd = self.fake_proc(pages)
        reads, real = [], os.pread

        def record(descriptor, size, offset):
            name = os.readlink(f"/proc/self/fd/{descriptor}").rpartition("/")[2]
            reads.append((name, size, offset))
            return real(descriptor, size, offset)

        collector = startup.ProcCollector(deadline())
        with (
            mock.patch.object(startup, "CHUNK", PAGE),
            mock.patch.object(startup.os, "pread", side_effect=record),
        ):
            (row,) = collector._mapped(fd, ((base, base + count * PAGE),))
        table = base // PAGE * 8
        self.assertEqual(
            reads,
            [("mem", PAGE, base + index * PAGE) for index in range(count)]
            + [("pagemap", PAGE, table), ("pagemap", count * 8 - PAGE, table + PAGE)],
        )
        anonymous = bytearray((count + 7) // 8)
        for index in (100, 520):
            anonymous[index // 8] |= 1 << (index % 8)
        self.assertEqual(row["anonymous"], bytes(anonymous))
        expected = b"".join(
            page_digest(pages[base + index * PAGE][0])
            for index in range(count)
            if index not in (100, 520)
        )
        self.assertEqual(row["sha256"], hashlib.sha256(expected).hexdigest())

    def test_each_call_clears_the_rows_of_the_previous_one_first(self):
        _, fd = self.fake_proc({0x10000: (b"a" * PAGE, PM_PRESENT | PM_FILE)})
        collector = startup.ProcCollector(deadline())
        region = ((0x10000, 0x11000),)
        for regions, refusal in (
            ((), None),
            (((PAGE, PAGE),), "^startup mapped regions$"),
        ):
            with self.subTest(regions=regions):
                rows = collector._mapped(fd, region)
                self.assertEqual(len(rows), 1)
                self.assertEqual(collector.partial["mapped"], rows)
                if refusal is None:
                    self.assertEqual(collector._mapped(fd, regions), ())
                else:
                    with self.assertRaisesRegex(ValueError, refusal):
                        collector._mapped(fd, regions)
                self.assertEqual(collector.partial["mapped"], ())
                self.assertEqual(collector.owned, {})

    def test_short_pagemap_read_refuses_and_keeps_only_complete_rows(self):
        pages = {
            0x10000: (b"a" * PAGE, PM_PRESENT | PM_FILE),
            0x20000: (b"c" * PAGE, PM_PRESENT | PM_FILE),
            0x30000: (b"b" * PAGE, PM_PRESENT | PM_FILE),
        }
        _, fd = self.fake_proc(pages, short_pagemap=True)
        collector = startup.ProcCollector(deadline())
        regions = ((0x10000, 0x11000), (0x20000, 0x21000), (0x30000, 0x31000))
        with self.assertRaisesRegex(ValueError, "^startup mapped read short$"):
            collector._mapped(fd, regions)
        self.assertEqual(collector.owned, {})
        # The rows of every run completed before the failure, not only the last.
        self.assertEqual(
            [(row["start"], row["end"]) for row in collector.partial["mapped"]],
            list(regions[:2]),
        )

    def test_nonregular_mem_or_pagemap_refuses(self):
        for name in ("mem", "pagemap"):
            base, fd = self.fake_proc({0x10000: (b"a" * PAGE, PM_FILE)})
            (base / name).unlink()
            os.mkfifo(base / name)
            collector = startup.ProcCollector(deadline())
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(ValueError, "not regular"),
            ):
                collector._mapped(fd, ((0x10000, 0x11000),))
            self.assertEqual(collector.owned, {})

    def test_invalid_regions_refuse_before_any_open(self):
        for regions in (
            [(PAGE, 2 * PAGE)],
            ((PAGE, 2 * PAGE, 0),),
            ([PAGE, 2 * PAGE],),
            ((PAGE, PAGE),),
            ((PAGE + 1, 2 * PAGE),),
            ((PAGE, 2 * PAGE + 1),),
            ((3 * PAGE, 4 * PAGE), (PAGE, 2 * PAGE)),
            ((PAGE, 3 * PAGE), (2 * PAGE, 4 * PAGE)),
            ((False, PAGE),),
            ((PAGE, 2**63 + PAGE),),
        ):
            collector = startup.ProcCollector(deadline())
            with (
                self.subTest(regions=regions),
                # A mock descriptor would index as 1: refuse any open instead.
                mock.patch.object(
                    startup.os, "open", side_effect=AssertionError("opened")
                ) as opened,
                self.assertRaisesRegex(ValueError, "^startup mapped regions$"),
            ):
                collector._mapped(3, regions)
            opened.assert_not_called()
        with mock.patch.object(
            startup.os, "open", side_effect=AssertionError("opened")
        ) as opened:
            self.assertEqual(startup.ProcCollector(deadline())._mapped(3, ()), ())
        opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
