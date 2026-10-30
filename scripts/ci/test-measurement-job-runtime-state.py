#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Pure runtime identity and map-policy tests; no native program is executed."""

import copy
import hashlib
import importlib.util
import mmap
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import MappingProxyType

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


state = load("runtime_state", "measurement-job-runtime-state.py")
startup = load("state_startup", "measurement-job-startup.py")
fixtures = load("state_fixtures", "test-measurement-job-closure.py")
root_tests = load("state_root_tests", "test-measurement-job-root.py")
view = root_tests.root.parse_mountinfo
# The default observation's runtime: one ext4 root mount whose device stat
# and maps both report.
MOUNTS = view(b"2 1 0:1 / / ro - ext4 source rw\n")


def observation(device=(0, 1)):
    manifest, _ = fixtures.manifest()
    files = {
        "/" + row["path"]: {
            "device": os.makedev(*device),
            "inode": 100 + number,
            "mode": stat.S_IFREG | row["mode"],
            "size": row["size"],
            "sha256": row["sha256"],
        }
        for number, row in enumerate(manifest["members"])
        if row["kind"] == "file"
    }
    python = {
        "implementation": "cpython",
        "version": (3, 14, 8),
        "executable": "/usr/bin/python3",
        "flags": {
            "isolated": 1,
            "no_site": 1,
            "dont_write_bytecode": 1,
            "ignore_environment": 1,
            "safe_path": True,
        },
        "pycache_prefix": "/dev/null",
        "environment": {"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        "sys_path": tuple("/" + path for path in manifest["python"]["roots"]),
        "jit_available": False,
        "jit_enabled": False,
        "modules": (
            {
                "name": "__main__",
                "kind": "source",
                "origin": "/opt/irlume/entry.py",
                "package_paths": (),
                "cached": None,
            },
            {
                "name": "sys",
                "kind": "builtin",
                "origin": "built-in",
                "package_paths": (),
                "cached": None,
            },
            {
                "name": "os",
                "kind": "frozen",
                "origin": "frozen",
                "package_paths": (),
                "cached": None,
            },
        ),
    }
    maps = b""
    for number, path in enumerate(
        ("/usr/bin/python3", "/lib64/ld-linux-x86-64.so.2"), start=1
    ):
        maps += f"{number * 4096:016x}-{(number + 1) * 4096:016x} r-xp 00000000 {device[0]:02x}:{device[1]:02x} {files[path]['inode']} {path}\n".encode()
    maps += b"0000000000004000-0000000000005000 rw-p 00000000 00:00 0 [heap]\n"
    maps += b"0000000000006000-0000000000008000 r-xp 00000000 00:00 0 [vdso]\n"
    maps += b"ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]\n"
    return manifest, files, python, maps


PYTHON, LOADER = "/usr/bin/python3", "/lib64/ld-linux-x86-64.so.2"


def page_digests(files):
    """Synthetic digests for every page of every selected file.

    The checks compare digests only; real ones come from the runtime
    snapshot's own hashing (measurement-job-closure.py).
    """
    return MappingProxyType(
        {
            path: tuple(
                hashlib.sha256(b"%s %d" % (path.encode(), index)).digest()
                for index in range(-(-row["size"] // 4096))
            )
            for path, row in files.items()
        }
    )


def mapped_rows(maps, pages):
    """What a faithful collector reports when no page was copied."""
    rows = []
    for line in maps.decode("ascii", "replace").splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or fields[4] == "0" or not fields[1].startswith("r"):
            continue
        try:
            start, end = (int(value, 16) for value in fields[0].split("-"))
            first, count = int(fields[2], 16) // 4096, (end - start) // 4096
            digests = pages.get(fields[5], ())[first : first + count]
            rows.append(
                {
                    "start": start,
                    "end": end,
                    "anonymous": bytes(-(-count // 8)),
                    "sha256": hashlib.sha256(b"".join(digests)).hexdigest(),
                }
            )
        except ValueError:
            continue
    return tuple(rows)


FAITHFUL = object()


def check(manifest, files, python, maps, mounts, rows=FAITHFUL, pages=FAITHFUL):
    """check_runtime_state with the rows a faithful collector would report."""
    pages = page_digests(files) if pages is FAITHFUL else pages
    rows = mapped_rows(maps, pages) if rows is FAITHFUL else rows
    return state.check_runtime_state(manifest, files, python, maps, mounts, rows, pages)


def loaded():
    """python3 and the loader as ld.so maps them: code, read-only data, RELRO,
    data, a PROT_NONE gap and anonymous memory between them."""
    manifest, files, python, _ = observation()
    python3, loader = files[PYTHON]["inode"], files[LOADER]["inode"]
    maps = (
        f"0000000000010000-0000000000011000 r-xp 00000000 00:01 {python3} {PYTHON}\n"
        f"0000000000011000-0000000000012000 r--p 00001000 00:01 {python3} {PYTHON}\n"
        f"0000000000012000-0000000000013000 r--p 00002000 00:01 {python3} {PYTHON}\n"
        f"0000000000013000-0000000000014000 rw-p 00003000 00:01 {python3} {PYTHON}\n"
        "0000000000014000-0000000000016000 rw-p 00000000 00:00 0\n"
        f"0000000000020000-0000000000021000 r-xp 00000000 00:01 {loader} {LOADER}\n"
        f"0000000000021000-0000000000022000 ---p 00001000 00:01 {loader} {LOADER}\n"
        f"0000000000022000-0000000000024000 r--p 00002000 00:01 {loader} {LOADER}\n"
        "0000000000030000-0000000000031000 rw-p 00000000 00:00 0 [heap]\n"
        "0000000000040000-0000000000042000 r-xp 00000000 00:00 0 [vdso]\n"
        "ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]\n"
    ).encode()
    return manifest, files, python, maps


def btrfs_observation():
    """The laptop's runtime in G's view, as measured on its btrfs /home.

    stat reports the subvolume's device 0:52 for the runtime's python3 and
    /proc/self/maps 00:23 (0:35), the device G's root mount carries in
    R5_TRACING; both report inode 95555479.
    """
    manifest, files, python, maps = observation((0, 35))
    for row in files.values():
        row["device"] = os.makedev(0, 52)
    python3 = files["/usr/bin/python3"]
    maps = maps.replace(
        b" %d /usr/bin/python3\n" % python3["inode"], b" 95555479 /usr/bin/python3\n"
    )
    python3["inode"] = 95555479
    return manifest, files, python, maps, view(root_tests.R5_TRACING)


class RuntimeStateTests(unittest.TestCase):
    def test_package_paths_require_a_real_package_entry(self):
        manifest, files, python, maps = observation()
        python["modules"][0]["package_paths"] = ("/opt/irlume",)
        with self.assertRaises(ValueError):
            check(manifest, files, python, maps, MOUNTS)

    def test_maps_do_not_silently_normalize_control_bytes(self):
        manifest, files, python, maps = observation()
        with self.assertRaises(ValueError):
            check(manifest, files, python, maps.replace(b"\n", b"\r\n"), MOUNTS)

    def test_selected_files_cannot_alias_the_same_inode(self):
        manifest, files, _, _ = observation()
        files["/usr/bin/python3"]["inode"] = files["/lib64/ld-linux-x86-64.so.2"][
            "inode"
        ]
        with self.assertRaises(ValueError):
            state.check_files(manifest, files)

    def test_python_state_alone_matches_the_selected_runtime(self):
        manifest, files, python, _ = observation()
        self.assertEqual(state.check_python(manifest, files, python), set())

    def test_exact_state_and_kernel_code_exceptions_are_accepted_without_authority(
        self,
    ):
        self.assertIsNone(check(*observation(), MOUNTS))

    def test_python_environment_path_flags_and_jit_cannot_drift(self):
        for field, value in (
            ("implementation", "pypy"),
            ("version", (3, 14, 7)),
            ("executable", "/usr/local/bin/python3"),
            ("pycache_prefix", None),
            (
                "environment",
                {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "LD_PRELOAD": "bad"},
            ),
            ("sys_path", ("/tmp",)),
            ("jit_enabled", True),
            ("jit_available", 0),
        ):
            manifest, files, python, maps = observation()
            python[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(manifest, files, python, maps, MOUNTS)
        for name in (
            "isolated",
            "no_site",
            "dont_write_bytecode",
            "ignore_environment",
            "safe_path",
        ):
            manifest, files, python, maps = observation()
            python["flags"][name] = False
            with self.subTest(flag=name), self.assertRaises(ValueError):
                check(manifest, files, python, maps, MOUNTS)

    def test_module_origins_caches_and_loader_kinds_are_pinned(self):
        for change in (
            {"origin": "/tmp/entry.py"},
            {"kind": "zip"},
            {"cached": "/tmp/entry.pyc"},
            {"package_paths": ("/tmp",)},
        ):
            manifest, files, python, maps = observation()
            python["modules"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                check(manifest, files, python, maps, MOUNTS)
        manifest, files, python, maps = observation()
        python["modules"] = python["modules"][1:]
        with self.assertRaises(ValueError):
            check(manifest, files, python, maps, MOUNTS)

    def test_file_identity_hash_mode_and_map_identity_must_match(self):
        manifest, files, python, maps = observation()
        for field, value in (
            ("inode", True),
            ("mode", stat.S_IFLNK | 0o777),
            ("size", 0),
            ("sha256", "f" * 64),
        ):
            bad = copy.deepcopy(files)
            bad["/usr/bin/python3"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(manifest, bad, python, maps, MOUNTS)
        bad = copy.deepcopy(files)
        bad["/usr/bin/python3"]["inode"] += 1
        with self.assertRaises(ValueError):
            check(manifest, bad, python, maps, MOUNTS)

    def test_anonymous_writable_deleted_unknown_or_shared_code_refuses(self):
        manifest, files, python, maps = observation()
        for bad in (
            maps.replace(b"r-xp", b"rwxp", 1),
            maps.replace(b"r-xp", b"r-xs", 1),
            maps.replace(b"/usr/bin/python3", b"/tmp/foreign.so", 1),
            maps.replace(b"/usr/bin/python3", b"/usr/bin/python3 (deleted)", 1),
            maps.replace(b"[heap]", b"[anon:code]").replace(b"rw-p", b"r-xp"),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                check(manifest, files, python, bad, MOUNTS)

    def test_kernel_exceptions_are_exact_and_maps_are_bounded(self):
        manifest, files, python, maps = observation()
        for bad in (
            maps.replace(b"[vsyscall]", b"[kernel-code]"),
            maps.replace(b"ffffffffff600000", b"ffffffffff500000"),
            maps
            + b"ffffffffff602000-ffffffffff603000 --xp 00000000 00:00 0 [vsyscall]\n",
            maps.replace(b"[vdso]", b"[anon:vdso]"),
            maps.rstrip(b"\n"),
            b"x" * (1024**2 + 1),
        ):
            with self.subTest(bad=bad[:100]), self.assertRaises(ValueError):
                check(manifest, files, python, bad, MOUNTS)

    def test_extension_module_requires_its_own_executable_mapping(self):
        manifest, files, python, maps = observation()
        original = next(
            row
            for row in manifest["members"]
            if row["path"] == "lib64/ld-linux-x86-64.so.2"
        )
        member = {**original, "path": "usr/lib/python3.14/native.so"}
        manifest["members"].append(member)
        manifest["members"].sort(key=lambda row: row["path"])
        path = "/" + member["path"]
        files[path] = {**files["/lib64/ld-linux-x86-64.so.2"], "inode": 999}
        python["modules"] += (
            {
                "name": "native",
                "kind": "extension",
                "origin": path,
                "package_paths": (),
                "cached": None,
            },
        )
        with self.assertRaises(ValueError):
            check(manifest, files, python, maps, MOUNTS)
        mapping = f"0000000000003000-0000000000004000 r-xp 00000000 00:01 999 {path}\n".encode()
        maps = maps.replace(b"0000000000004000-", mapping + b"0000000000004000-", 1)
        self.assertIsNone(check(manifest, files, python, maps, MOUNTS))

    def test_duplicate_modules_map_overlap_and_numeric_mismatch_refuse(self):
        manifest, files, python, maps = observation()
        duplicate = copy.deepcopy(python)
        duplicate["modules"] += (dict(duplicate["modules"][0]),)
        with self.assertRaises(ValueError):
            check(manifest, files, duplicate, maps, MOUNTS)
        for bad in (
            maps.replace(b"0000000000002000-", b"0000000000001000-", 1),
            maps.replace(b"00:01", b"00:02", 1),
            maps.replace(b"r-xp 00000000", b"r-xp 00010000", 1),
        ):
            with self.subTest(bad=bad[:100]), self.assertRaises(ValueError):
                check(manifest, files, python, bad, MOUNTS)

    def test_nonmain_module_origin_and_builtin_origin_are_not_self_asserted(self):
        manifest, files, python, maps = observation()
        python["modules"] += (
            {
                "name": "helper",
                "kind": "source",
                "origin": "/tmp/helper.py",
                "package_paths": (),
                "cached": None,
            },
        )
        with self.assertRaises(ValueError):
            check(manifest, files, python, maps, MOUNTS)
        manifest, files, python, maps = observation()
        python["modules"] += (
            {
                "name": "package",
                "kind": "source",
                "origin": "/usr/lib/python3.14/__init__.py",
                "package_paths": ("/tmp",),
                "cached": None,
            },
        )
        with self.assertRaises(ValueError):
            check(manifest, files, python, maps, MOUNTS)
        manifest, files, python, maps = observation()
        python["modules"][0]["origin"] = "/usr/lib/python3.14/__init__.py"
        with self.assertRaises(ValueError):
            check(manifest, files, python, maps, MOUNTS)
        manifest, files, python, maps = observation()
        python["modules"][1]["origin"] = "frozen"
        with self.assertRaises(ValueError):
            check(manifest, files, python, maps, MOUNTS)

    def test_kernel_mapping_identity_permissions_and_presence_are_independent(self):
        manifest, files, python, maps = observation()
        vdso = next(
            line for line in maps.splitlines(keepends=True) if b"[vdso]" in line
        )
        first = maps.splitlines(keepends=True)[0]
        for bad in (
            maps.replace(vdso, vdso.replace(b"r-xp", b"r--p")),
            maps.replace(vdso, vdso.replace(b"00:00 0", b"00:01 0")),
            maps.replace(vdso, b""),
            first + maps,
        ):
            with self.subTest(bad=bad[:100]), self.assertRaises(ValueError):
                check(manifest, files, python, bad, MOUNTS)

    def test_module_count_and_total_text_have_independent_caps(self):
        manifest, files, python, maps = observation()
        python["modules"] += tuple(
            {
                "name": f"builtin_{i}",
                "kind": "builtin",
                "origin": "built-in",
                "package_paths": (),
                "cached": None,
            }
            for i in range(4096)
        )
        with self.assertRaises(ValueError):
            check(manifest, files, python, maps, MOUNTS)
        manifest, files, python, maps = observation()
        python["modules"] += tuple(
            {
                **python["modules"][0],
                "name": f"helper_{i}",
                "cached": "/dev/null/" + "a" * 4080,
            }
            for i in range(300)
        )
        with self.assertRaises(ValueError):
            check(manifest, files, python, maps, MOUNTS)

    def test_inaccessible_file_reservation_does_not_claim_readable_file_bytes(self):
        manifest, files, python, maps = observation()
        path = "/lib64/ld-linux-x86-64.so.2"
        reservation = f"0000000000003000-0000000000004000 ---p 00200000 00:01 {files[path]['inode']} {path}\n".encode()
        reserved = maps.replace(
            b"0000000000004000-", reservation + b"0000000000004000-", 1
        )
        self.assertIsNone(check(manifest, files, python, reserved, MOUNTS))
        for permissions in (b"r--p", b"r-xp", b"rw-p"):
            with self.subTest(permissions=permissions), self.assertRaises(ValueError):
                check(
                    manifest,
                    files,
                    python,
                    reserved.replace(b"---p", permissions),
                    MOUNTS,
                )
        with self.assertRaises(ValueError):
            check(
                manifest,
                files,
                python,
                reserved.replace(reservation, reservation.replace(b"00:01", b"00:02")),
                MOUNTS,
            )

    def test_btrfs_mapping_carries_the_mount_device_not_the_subvolume_device(self):
        manifest, files, python, maps, mounts = btrfs_observation()
        self.assertIn(b" 00:23 95555479 /usr/bin/python3\n", maps)
        self.assertEqual(files["/usr/bin/python3"]["device"], os.makedev(0, 52))
        self.assertEqual(mounts["/"].device, (0, 35))
        self.assertIsNone(check(manifest, files, python, maps, mounts))
        # maps never shows the subvolume's stat device for a file on it.
        stat_device = maps.replace(b" 00:23 95555479 ", b" 00:34 95555479 ")
        self.assertNotEqual(stat_device, maps)
        with self.assertRaisesRegex(ValueError, "^runtime mapped file identity$"):
            check(manifest, files, python, stat_device, mounts)

    def test_mapping_with_another_mounts_device_refuses(self):
        manifest, files, python, maps, mounts = btrfs_observation()
        others = {mount.device for mount in mounts.values()} - {mounts["/"].device}
        self.assertEqual(len(others), 9)
        for major, minor in sorted(others):
            bad = maps.replace(
                b" 00:23 95555479 ", b" %02x:%02x 95555479 " % (major, minor)
            )
            self.assertNotEqual(bad, maps)
            with (
                self.subTest(device=(major, minor)),
                self.assertRaisesRegex(ValueError, "^runtime mapped file identity$"),
            ):
                check(manifest, files, python, bad, mounts)

    def test_mapping_inode_must_be_the_pinned_inode(self):
        manifest, files, python, maps, mounts = btrfs_observation()
        loader = files["/lib64/ld-linux-x86-64.so.2"]["inode"]
        for inode in (95555480, loader):
            bad = maps.replace(b" 95555479 ", b" %d " % inode)
            self.assertNotEqual(bad, maps)
            with (
                self.subTest(inode=inode),
                self.assertRaisesRegex(ValueError, "^runtime mapped file identity$"),
            ):
                check(manifest, files, python, bad, mounts)

    def test_ext4_mapping_still_carries_the_stat_and_mount_device(self):
        mounts = view(root_tests.R5_ARCHHOST)
        self.assertEqual(mounts["/"].device, (259, 2))
        manifest, files, python, maps = observation((259, 2))
        self.assertEqual(files["/usr/bin/python3"]["device"], os.makedev(259, 2))
        self.assertIn(b" 103:02 ", maps)
        self.assertIsNone(check(manifest, files, python, maps, mounts))
        run = b" %02x:%02x " % mounts["/run"].device
        for device in (b" 103:03 ", run):
            with (
                self.subTest(device=device),
                self.assertRaisesRegex(ValueError, "^runtime mapped file identity$"),
            ):
                check(
                    manifest, files, python, maps.replace(b" 103:02 ", device), mounts
                )

    def test_the_deepest_mount_holding_the_path_decides(self):
        mounts = view(
            b"2 1 0:1 / / ro - ext4 source rw\n"
            b"3 2 0:40 / /usr ro - ext4 source rw\n"
            b"4 2 0:50 / /lib ro - ext4 source rw\n"
        )
        manifest, files, python, maps = observation()
        python3 = b" %d /usr/bin/python3\n" % files["/usr/bin/python3"]["inode"]
        inode = files["/lib64/ld-linux-x86-64.so.2"]["inode"]
        loader = b" %d /lib64/ld-linux-x86-64.so.2\n" % inode
        moved = maps.replace(b" 00:01" + python3, b" 00:28" + python3)
        self.assertNotEqual(moved, maps)
        # /usr/bin/python3 is on the /usr mount; /lib64 is not below /lib.
        self.assertIsNone(check(manifest, files, python, moved, mounts))
        for bad in (maps, moved.replace(b" 00:01" + loader, b" 00:32" + loader)):
            self.assertNotEqual(bad, moved)
            with (
                self.subTest(bad=bad[:100]),
                self.assertRaisesRegex(ValueError, "^runtime mapped file identity$"),
            ):
                check(manifest, files, python, bad, mounts)

    def test_mappings_need_a_rooted_mount_view_with_kernel_devices(self):
        manifest, files, python, maps = observation()
        mount = MOUNTS["/"]
        for mounts in (
            None,
            {},
            {"/usr": mount},
            {"/": mount._replace(device=[0, 1])},
            {"/": mount._replace(device=(0, 1, 0))},
            {"/": mount._replace(device=(0, True))},
            {"/": mount._replace(device=(0, 2**32))},
        ):
            with self.subTest(mounts=mounts), self.assertRaises(ValueError):
                check(manifest, files, python, maps, mounts)

    def test_maps_parser_lists_readable_file_mappings_in_maps_order(self):
        manifest, files, python, maps = loaded()
        executable, readable = state.file_mappings(maps, files, MOUNTS)
        self.assertEqual(executable, {PYTHON, LOADER})
        self.assertEqual(
            readable,
            (
                state.Mapping(0x10000, 0x11000, 0x0000, PYTHON, True),
                state.Mapping(0x11000, 0x12000, 0x1000, PYTHON, False),
                state.Mapping(0x12000, 0x13000, 0x2000, PYTHON, False),
                state.Mapping(0x13000, 0x14000, 0x3000, PYTHON, False),
                state.Mapping(0x20000, 0x21000, 0x0000, LOADER, True),
                state.Mapping(0x22000, 0x24000, 0x2000, LOADER, False),
            ),
        )
        self.assertIsNone(check(manifest, files, python, maps, MOUNTS))

    def test_mapped_bytes_must_equal_the_selected_page_digests(self):
        manifest, files, python, maps = loaded()
        pages = page_digests(files)
        rows = mapped_rows(maps, pages)
        self.assertIsNone(check(manifest, files, python, maps, MOUNTS, rows, pages))
        # Other bytes behind the same inode, as a btrfs snapshot copy shows.
        other = dict(pages)
        other[LOADER] = (*pages[LOADER][:3], hashlib.sha256(b"other").digest())
        with self.assertRaisesRegex(ValueError, "^runtime mapped bytes differ$"):
            check(manifest, files, python, maps, MOUNTS, rows, MappingProxyType(other))
        for value in ("0" * 64, rows[5]["sha256"].upper(), None, 0):
            bad = (*rows[:5], dict(rows[5], sha256=value))
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "^runtime mapped bytes differ$"),
            ):
                check(manifest, files, python, maps, MOUNTS, bad, pages)

    def test_private_copies_are_counted_not_compared_except_in_code(self):
        manifest, files, python, maps = loaded()
        pages = page_digests(files)
        rows = list(mapped_rows(maps, pages))
        empty = hashlib.sha256(b"").hexdigest()
        # RELRO and .data copied on write; the loader's second data page too.
        rows[2] = dict(rows[2], anonymous=b"\x01", sha256=empty)
        rows[3] = dict(rows[3], anonymous=b"\x01", sha256=empty)
        rows[5] = dict(
            rows[5],
            anonymous=b"\x02",
            sha256=hashlib.sha256(pages[LOADER][2]).hexdigest(),
        )
        self.assertIsNone(
            check(manifest, files, python, maps, MOUNTS, tuple(rows), pages)
        )
        # A copied page's own digest is not part of the hash.
        compared = dict(rows[3], sha256=hashlib.sha256(pages[PYTHON][3]).hexdigest())
        with self.assertRaisesRegex(ValueError, "^runtime mapped bytes differ$"):
            check(
                manifest,
                files,
                python,
                maps,
                MOUNTS,
                (*rows[:3], compared, *rows[4:]),
                pages,
            )
        # Code is never a private copy, even in an otherwise consistent row.
        for index in (0, 4):
            code = list(rows)
            code[index] = dict(rows[index], anonymous=b"\x01", sha256=empty)
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    ValueError, "^runtime anonymous page in executable mapping$"
                ),
            ):
                check(manifest, files, python, maps, MOUNTS, tuple(code), pages)

    def test_page_bitmap_length_and_padding_are_exact(self):
        manifest, files, python, maps = loaded()
        pages = page_digests(files)
        rows = mapped_rows(maps, pages)
        for index, value in (
            (1, b""),
            (1, b"\x00\x00"),
            (5, b""),
            (1, bytearray(1)),
            (1, "00"),
        ):
            bad = (
                *rows[:index],
                dict(rows[index], anonymous=value),
                *rows[index + 1 :],
            )
            with (
                self.subTest(index=index, value=value),
                self.assertRaisesRegex(ValueError, "^runtime mapped page bitmap$"),
            ):
                check(manifest, files, python, maps, MOUNTS, bad, pages)
        # A bit past the mapping's pages, digests unchanged.
        for index, value in ((1, b"\x02"), (1, b"\x80"), (5, b"\x04")):
            bad = (
                *rows[:index],
                dict(rows[index], anonymous=value),
                *rows[index + 1 :],
            )
            with (
                self.subTest(index=index, padding=value),
                self.assertRaisesRegex(
                    ValueError, "^runtime mapped page bitmap padding$"
                ),
            ):
                check(manifest, files, python, maps, MOUNTS, bad, pages)

    def test_bitmaps_past_eight_pages_are_read_for_every_page(self):
        # Ten pages from file page 1 of an 11-page file: two bitmap bytes,
        # six padding bits, mapping page 9 is the file's partial last page.
        path = "/lib64/libten.so.1"
        files = {path: {"size": 11 * 4096 - 100}}
        digests = tuple(
            hashlib.sha256(b"page %d" % index).digest() for index in range(11)
        )
        pages = MappingProxyType({path: digests})
        data = state.Mapping(0x10000, 0x1A000, 0x1000, path, False)
        code = data._replace(execute=True)

        def row(anonymous, observed=digests):
            return {
                "start": data.start,
                "end": data.end,
                "anonymous": anonymous,
                "sha256": hashlib.sha256(
                    b"".join(
                        observed[1 + index]
                        for index in range(10)
                        if not anonymous[index // 8] >> (index % 8) & 1
                    )
                ).hexdigest(),
            }

        for anonymous in (b"\x00\x02", b"\x20\x00"):
            with self.subTest(anonymous=anonymous):
                self.assertIsNone(
                    state.check_mapped((data,), files, (row(anonymous),), pages)
                )
        with self.assertRaisesRegex(
            ValueError, "^runtime anonymous page in executable mapping$"
        ):
            state.check_mapped((code,), files, (row(b"\x00\x02"),), pages)
        with self.assertRaisesRegex(ValueError, "^runtime mapped page bitmap padding$"):
            state.check_mapped(
                (data,), files, (dict(row(b"\x00\x00"), anonymous=b"\x00\x04"),), pages
            )
        other = (*digests[:10], hashlib.sha256(b"other").digest())
        self.assertIsNone(
            state.check_mapped((code,), files, (row(b"\x00\x00"),), pages)
        )
        with self.assertRaisesRegex(ValueError, "^runtime mapped bytes differ$"):
            state.check_mapped((code,), files, (row(b"\x00\x00", other),), pages)

    def test_one_row_per_readable_file_mapping_in_maps_order(self):
        manifest, files, python, maps = loaded()
        pages = page_digests(files)
        rows = mapped_rows(maps, pages)
        reservation = {
            "start": 0x21000,
            "end": 0x22000,
            "anonymous": b"\x00",
            "sha256": hashlib.sha256(pages[LOADER][1]).hexdigest(),
        }
        for bad in (
            rows[:-1],
            rows + rows[-1:],
            (*rows[:5], reservation, rows[5]),
            (),
            list(rows),
        ):
            with (
                self.subTest(rows=len(bad)),
                self.assertRaisesRegex(ValueError, "^runtime mapped row count$"),
            ):
                check(manifest, files, python, maps, MOUNTS, bad, pages)
        # The same bytes reported for another range, or for a resized one.
        last = rows[5]
        for change in (
            {"start": last["start"] + 0x100000, "end": last["end"] + 0x100000},
            {"end": last["end"] + 4096},
            {"start": last["start"] + 4096},
            {"start": float(last["start"])},
            {"end": float(last["end"])},
            (rows[1], rows[0]),
        ):
            bad = (
                (*rows[:5], dict(last, **change))
                if type(change) is dict
                else (*change, *rows[2:])
            )
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(ValueError, "^runtime mapped row range$"),
            ):
                check(manifest, files, python, maps, MOUNTS, bad, pages)
        for row in (dict(last, extra=1), {**last, "start": None}, list(last.items())):
            with self.subTest(row=row), self.assertRaises(ValueError):
                check(manifest, files, python, maps, MOUNTS, (*rows[:5], row), pages)

    def test_page_digests_come_from_the_selected_runtime_only(self):
        manifest, files, python, maps = loaded()
        pages = page_digests(files)
        rows = mapped_rows(maps, pages)
        digest = pages[PYTHON][0]
        for name, value in (
            ("dictionary", dict(pages)),
            ("none", None),
            ("missing", MappingProxyType({LOADER: pages[LOADER]})),
            ("short", MappingProxyType({**pages, PYTHON: pages[PYTHON][:3]})),
            ("long", MappingProxyType({**pages, PYTHON: pages[PYTHON] + (digest,)})),
            ("list", MappingProxyType({**pages, PYTHON: list(pages[PYTHON])})),
            (
                "digest size",
                MappingProxyType({**pages, PYTHON: (digest[:31], *pages[PYTHON][1:])}),
            ),
            (
                "digest type",
                MappingProxyType({**pages, PYTHON: (digest.hex(), *pages[PYTHON][1:])}),
            ),
            # Every mapped path's table is checked, not only the first one's.
            ("later short", MappingProxyType({**pages, LOADER: pages[LOADER][:1]})),
            (
                "later long",
                MappingProxyType({**pages, LOADER: pages[LOADER] + (digest,)}),
            ),
            ("later list", MappingProxyType({**pages, LOADER: list(pages[LOADER])})),
        ):
            with (
                self.subTest(pages=name),
                self.assertRaisesRegex(ValueError, "^runtime page digests$"),
            ):
                check(manifest, files, python, maps, MOUNTS, rows, value)

    def test_unreadable_file_mapping_must_be_an_inaccessible_reservation(self):
        manifest, files, python, maps = loaded()
        reservation = b" ---p 00001000 "
        self.assertEqual(maps.count(reservation), 1)
        for permissions in (b"--xp", b"-w-p", b"---s", b"-w-s"):
            bad = maps.replace(reservation, b" " + permissions + b" 00001000 ")
            with (
                self.subTest(permissions=permissions),
                self.assertRaisesRegex(ValueError, "^runtime unreadable file mapping$"),
            ):
                check(manifest, files, python, bad, MOUNTS)


TREE = "/home/u/.cache/run/root"
HOST_ENTRY = "opt/irlume/host.py"


def prefixed(tree=TREE, host_entry=False):
    """observation() as a process outside the tree sees it: a host-absolute tree.

    host_entry adds a second selected source and makes it __main__.
    """
    manifest, files, python, maps = observation()
    if host_entry:
        data = b"# host entry\n"
        manifest["members"].append(
            {
                "path": HOST_ENTRY,
                "kind": "file",
                "mode": 0o400,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
        manifest["members"].sort(key=lambda row: row["path"])
        files["/" + HOST_ENTRY] = {
            "device": os.makedev(0, 1),
            "inode": 200,
            "mode": stat.S_IFREG | 0o400,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        python["modules"][0]["origin"] = "/" + HOST_ENTRY
    files = {tree + path: row for path, row in files.items()}
    python["executable"] = tree + python["executable"]
    python["sys_path"] = tuple(tree + path for path in python["sys_path"])
    for module in python["modules"]:
        if module["kind"] in ("source", "extension"):
            module["origin"] = tree + module["origin"]
            module["package_paths"] = tuple(
                tree + path for path in module["package_paths"]
            )
    for path in (PYTHON, LOADER):
        maps = maps.replace(
            b" %s\n" % path.encode(), b" %s%s\n" % (tree.encode(), path.encode())
        )
    return manifest, files, python, maps


def check_prefixed(
    manifest, files, python, maps, rows=FAITHFUL, pages=FAITHFUL, **keywords
):
    pages = page_digests(files) if pages is FAITHFUL else pages
    rows = mapped_rows(maps, pages) if rows is FAITHFUL else rows
    return state.check_runtime_state(
        manifest, files, python, maps, MOUNTS, rows, pages, **keywords
    )


class PrefixTests(unittest.TestCase):
    """H checks itself from outside the tree: paths keep the tree's host prefix."""

    def accepted(self, check_function, *args, **keywords):
        """A refusal of a valid observation is an assertion failure."""
        try:
            return check_function(*args, **keywords)
        except ValueError as error:
            self.fail(f"refused: {error}")

    def test_defaults_leave_the_rooted_check_unchanged(self):
        manifest, files, python, maps = observation()
        self.assertIsNone(self.accepted(check, manifest, files, python, maps, MOUNTS))
        self.assertIsNone(
            self.accepted(
                check_prefixed, manifest, files, python, maps, prefix="", entry=None
            )
        )
        self.assertEqual(
            self.accepted(state.check_python, manifest, files, python, prefix=""), set()
        )
        # A prefixed observation is not a rooted one.
        with self.assertRaises(ValueError):
            check(*prefixed(), MOUNTS)

    def test_prefixed_runtime_is_accepted_with_paths_compared_verbatim(self):
        self.assertIsNone(self.accepted(check_prefixed, *prefixed(), prefix=TREE))
        manifest, files, python, maps = prefixed(host_entry=True)
        self.assertIsNone(
            self.accepted(
                check_prefixed,
                manifest,
                files,
                python,
                maps,
                prefix=TREE,
                entry=HOST_ENTRY,
            )
        )
        self.assertEqual(
            self.accepted(
                state.check_python,
                manifest,
                files,
                python,
                prefix=TREE,
                entry=HOST_ENTRY,
            ),
            set(),
        )

    def test_prefix_applies_to_executable_search_path_origins_files_and_maps(self):
        manifest, files, python, maps = prefixed()
        cases = []
        bad = copy.deepcopy(python)
        bad["executable"] = PYTHON
        cases.append(("executable", files, bad, maps))
        bad = copy.deepcopy(python)
        bad["sys_path"] = tuple(path[len(TREE) :] for path in bad["sys_path"])
        cases.append(("sys_path", files, bad, maps))
        bad = copy.deepcopy(python)
        bad["modules"][0]["origin"] = "/opt/irlume/entry.py"
        cases.append(("origin", files, bad, maps))
        bad = copy.deepcopy(python)
        bad["modules"][0]["origin"] = "/usr/lib/python3.14/entry.py"
        cases.append(("host-path origin", files, bad, maps))
        bad = copy.deepcopy(python)
        bad["modules"][0]["package_paths"] = ("/opt/irlume",)
        cases.append(("package path", files, bad, maps))
        unrooted = {path[len(TREE) :]: row for path, row in files.items()}
        cases.append(("files", unrooted, python, maps))
        cases.append(
            ("maps", files, python, maps.replace(b" " + TREE.encode(), b" ", 1))
        )
        for name, facts, state_, data in cases:
            with self.subTest(case=name), self.assertRaises(ValueError):
                check_prefixed(manifest, facts, state_, data, prefix=TREE)

    def test_entry_keyword_selects_main_and_must_be_a_selected_source(self):
        manifest, files, python, maps = prefixed(host_entry=True)
        # G's selected entry offered as H's main, and H's main without entry=.
        bad = copy.deepcopy(python)
        bad["modules"][0]["origin"] = TREE + "/opt/irlume/entry.py"
        with self.assertRaisesRegex(ValueError, "^runtime main entry$"):
            check_prefixed(manifest, files, bad, maps, prefix=TREE, entry=HOST_ENTRY)
        with self.assertRaisesRegex(ValueError, "^runtime main entry$"):
            check_prefixed(manifest, files, python, maps, prefix=TREE)
        for entry in (
            "opt/irlume/missing.py",
            "usr/bin/python3",
            "/" + HOST_ENTRY,
            "opt/irlume",
            "",
            b"opt/irlume/host.py",
        ):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                check_prefixed(manifest, files, python, maps, prefix=TREE, entry=entry)

    def test_pages_must_carry_the_prefix_and_bind_the_mapped_bytes(self):
        manifest, files, python, maps = prefixed()
        unrooted = page_digests({path[len(TREE) :]: row for path, row in files.items()})
        with self.assertRaisesRegex(ValueError, "^runtime page digests$"):
            check_prefixed(
                manifest,
                files,
                python,
                maps,
                rows=mapped_rows(maps, page_digests(files)),
                pages=unrooted,
                prefix=TREE,
            )
        rows = list(mapped_rows(maps, page_digests(files)))
        rows[0] = dict(rows[0], sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "^runtime mapped bytes differ$"):
            check_prefixed(manifest, files, python, maps, rows=tuple(rows), prefix=TREE)

    def test_prefix_is_a_canonical_directory_not_a_string_prefix(self):
        # Facts under a sibling directory, or a prefix that is only a leading
        # substring of the tree, never match.
        for facts, prefix in (
            (TREE + "x", TREE),
            (TREE, TREE[:-1]),
            (TREE, TREE + "/"),
            (TREE + "/opt", TREE),
        ):
            with (
                self.subTest(facts=facts, prefix=prefix),
                self.assertRaises(ValueError),
            ):
                check_prefixed(*prefixed(facts), prefix=prefix)
        # Consistent facts under a non-canonical prefix are refused as such.
        for prefix in (
            TREE + "/",
            "/",
            "//home/u/root",
            "/home/u/../root",
            "/home/./u/root",
            "home/u/root",
            "/home/u/root\n",
        ):
            with (
                self.subTest(prefix=prefix),
                self.assertRaisesRegex(ValueError, "^runtime path prefix$"),
            ):
                check_prefixed(*prefixed(prefix), prefix=prefix)
        for prefix in (None, b"/root", ("/root",)):
            with (
                self.subTest(prefix=prefix),
                self.assertRaisesRegex(ValueError, "^runtime path prefix$"),
            ):
                check_prefixed(*observation(), prefix=prefix)


class CollectorAgreementTests(unittest.TestCase):
    """The collector and the snapshot's digests agree on a real kernel."""

    def map_and_collect(self, path, execute, write=None):
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            view = mmap.mmap(
                fd, 0, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ | mmap.PROT_WRITE
            )
        finally:
            os.close(fd)
        try:
            if write is not None:
                view[write * 4096] ^= 1
            # maps shows the resolved path, also when TMPDIR is a symbolic link.
            resolved = str(Path(path).resolve())
            lines = [
                line
                for line in Path("/proc/self/maps").read_text().splitlines()
                if line.endswith(" " + resolved)
            ]
            self.assertEqual(len(lines), 1)
            start, end = (int(value, 16) for value in lines[0].split()[0].split("-"))
            collector = startup.ProcCollector(time.monotonic_ns() + 5_000_000_000)
            with collector._open(f"/proc/{os.getpid()}", directory=True) as proc:
                rows = collector._mapped(proc, ((start, end),))
            self.assertEqual(collector.owned, {})
        finally:
            view.close()
        return (state.Mapping(start, end, 0, PYTHON, execute),), rows

    def test_real_mapping_matches_snapshot_pages_only_for_the_hashed_bytes(self):
        files = fixtures.manifest()[1]
        files["usr/bin/python3"] += b"tail"
        with tempfile.TemporaryDirectory() as directory:
            # The tree walk refuses a symbolic link in TMPDIR (O_NOFOLLOW).
            directory = Path(directory).resolve()
            root = fixtures.TreeTests.make_tree(self, directory, files)
            end = time.monotonic_ns() + 5_000_000_000
            data, digest = fixtures.closure.prepare_manifest(
                root, fixtures.profile(), deadline=end
            )
            with fixtures.closure.RuntimeSnapshot.open(
                root, data, digest, deadline=end
            ) as owned:
                pages = owned.pages
                sizes = {
                    "/" + row["path"]: {"size": row["size"]}
                    for row in owned.manifest["members"]
                    if row["kind"] == "file"
                }
            member = root / "usr/bin/python3"
            mapping, rows = self.map_and_collect(member, True)
            self.assertIsNone(state.check_mapped(mapping, sizes, rows, pages))
            # A private copy of a data page is counted, never compared; code
            # pages may have none.
            mapping, rows = self.map_and_collect(member, False, write=4)
            self.assertEqual(rows[0]["anonymous"], b"\x10")
            self.assertIsNone(state.check_mapped(mapping, sizes, rows, pages))
            code = (mapping[0]._replace(execute=True),)
            with self.assertRaisesRegex(
                ValueError, "^runtime anonymous page in executable mapping$"
            ):
                state.check_mapped(code, sizes, rows, pages)
            # Same size, other bytes: what a snapshot copy with the member's
            # inode number would map.
            changed = bytearray(files["usr/bin/python3"])
            changed[2 * 4096] ^= 1
            copy_path = Path(directory) / "copy"
            copy_path.write_bytes(changed)
            mapping, rows = self.map_and_collect(copy_path, True)
            with self.assertRaisesRegex(ValueError, "^runtime mapped bytes differ$"):
                state.check_mapped(mapping, sizes, rows, pages)

    def snapshot_pages(self, directory, files, **tree):
        """The selected tree in directory and its snapshot's page digests."""
        root = fixtures.TreeTests.make_tree(self, directory, files, **tree)
        end = time.monotonic_ns() + 10_000_000_000
        data, digest = fixtures.closure.prepare_manifest(
            root, fixtures.profile(), deadline=end
        )
        with fixtures.closure.RuntimeSnapshot.open(
            root, data, digest, deadline=end
        ) as owned:
            return root, owned.pages

    def test_real_rows_past_eight_pages_accept_data_and_refuse_code(self):
        files = fixtures.manifest()[1]
        # Four ELF pages, six more and a partial one: an 11-page member.
        files["usr/bin/python3"] += (
            b"".join(bytes([index]) * 4096 for index in range(1, 7)) + b"tail"
        )
        size = len(files["usr/bin/python3"])
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            root, pages = self.snapshot_pages(directory, files)
            self.assertEqual(len(pages[PYTHON]), 11)
            sizes = {PYTHON: {"size": size}}
            member = root / "usr/bin/python3"
            mapping, rows = self.map_and_collect(member, False)
            self.assertEqual(rows[0]["anonymous"], b"\x00\x00")
            self.assertIsNone(state.check_mapped(mapping, sizes, rows, pages))
            mapping, rows = self.map_and_collect(member, False, write=9)
            self.assertEqual(rows[0]["anonymous"], b"\x00\x02")
            self.assertIsNone(state.check_mapped(mapping, sizes, rows, pages))
            code = (mapping[0]._replace(execute=True),)
            with self.assertRaisesRegex(
                ValueError, "^runtime anonymous page in executable mapping$"
            ):
                state.check_mapped(code, sizes, rows, pages)

    def collect_from_maps(self, path, files, mounts):
        """Map path; check its real maps line with [vdso]; collect its rows."""
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            view = mmap.mmap(fd, 0, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ)
        finally:
            os.close(fd)
        try:
            lines = sorted(
                (
                    line
                    for line in Path("/proc/self/maps").read_text().splitlines()
                    if line.endswith((" " + str(path), " [vdso]"))
                ),
                key=lambda line: int(line.partition("-")[0], 16),
            )
            self.assertEqual(len(lines), 2)
            data = ("\n".join(lines) + "\n").encode()
            executable, readable = state.file_mappings(data, files, mounts)
            self.assertEqual(executable, set())
            self.assertEqual([mapping.path for mapping in readable], [str(path)])
            collector = startup.ProcCollector(time.monotonic_ns() + 5_000_000_000)
            with collector._open(f"/proc/{os.getpid()}", directory=True) as proc:
                rows = collector._mapped(
                    proc, tuple((mapping.start, mapping.end) for mapping in readable)
                )
            self.assertEqual(collector.owned, {})
        finally:
            view.close()
        return readable, rows

    def test_real_btrfs_snapshot_copy_passes_identity_and_refuses_on_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            kind = subprocess.run(
                ["stat", "-f", "-c", "%T", str(directory)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if kind != "btrfs":
                self.skipTest(
                    f"{directory} is on {kind}, not btrfs; set TMPDIR to a btrfs "
                    "directory to run this test"
                )
            if shutil.which("btrfs") is None:
                self.skipTest("btrfs-progs (the btrfs command) is not installed")
            files = fixtures.manifest()[1]
            files["usr/bin/python3"] += (
                b"".join(bytes([index]) * 4096 for index in range(1, 7)) + b"tail"
            )
            # The selected tree is a subvolume, as a btrfs root or /home is.
            root, pages = self.snapshot_pages(directory, files, subvolume=".")
            member = root / "usr/bin/python3"
            original = member.stat()
            path = str(member)
            sizes = {path: {"inode": original.st_ino, "size": original.st_size}}
            pages = MappingProxyType({path: pages[PYTHON]})
            # maps shows the superblock device that mountinfo gives this mount.
            mounts = view(
                b"2 1 %s / / ro - btrfs source rw\n" % mountinfo_device(directory)
            )
            readable, rows = self.collect_from_maps(member, sizes, mounts)
            self.assertIsNone(state.check_mapped(readable, sizes, rows, pages))
            snapshot = directory / "snapshot"
            subprocess.run(
                ["btrfs", "subvolume", "snapshot", str(root), str(snapshot)],
                check=True,
                capture_output=True,
            )
            copy = snapshot / "usr/bin/python3"
            copy.chmod(0o700)
            with open(copy, "r+b") as stream:
                stream.seek(5 * 4096)
                stream.write(b"\xff")
            copy.chmod(0o500)
            changed = copy.stat()
            self.assertEqual(
                (changed.st_ino, changed.st_size), (original.st_ino, original.st_size)
            )
            self.assertNotEqual(changed.st_dev, original.st_dev)
            # The snapshot takes the selected tree's path. A file cannot be
            # renamed across subvolumes (EXDEV), so the subvolumes are.
            root.rename(directory / "original")
            snapshot.rename(root)
            self.assertEqual(member.stat().st_dev, changed.st_dev)
            readable, rows = self.collect_from_maps(member, sizes, mounts)
            with self.assertRaisesRegex(ValueError, "^runtime mapped bytes differ$"):
                state.check_mapped(readable, sizes, rows, pages)


def mountinfo_device(path):
    """MAJ:MIN of the mount holding path in this process's mountinfo."""
    path, found = str(path), None
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        point = fields[4]
        # The last matching row is the visible one when mounts are stacked.
        if (path == point or path.startswith(point.rstrip("/") + "/")) and (
            found is None or len(point) >= len(found[0])
        ):
            found = point, fields[2]
    if found is None:
        raise AssertionError(f"no mount holds {path}")
    return found[1].encode()


if __name__ == "__main__":
    unittest.main()
