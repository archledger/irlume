#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Pure runtime identity and map-policy tests; no native program is executed."""

import copy
import importlib.util
import os
import stat
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


state = load("runtime_state", "measurement-job-runtime-state.py")
fixtures = load("state_fixtures", "test-measurement-job-closure.py")


def observation():
    manifest, _ = fixtures.manifest()
    files = {
        "/" + row["path"]: {
            "device": os.makedev(0, 1),
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
        maps += f"{number * 4096:016x}-{(number + 1) * 4096:016x} r-xp 00000000 00:01 {files[path]['inode']} {path}\n".encode()
    maps += b"0000000000004000-0000000000005000 rw-p 00000000 00:00 0 [heap]\n"
    maps += b"0000000000006000-0000000000008000 r-xp 00000000 00:00 0 [vdso]\n"
    maps += b"ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]\n"
    return manifest, files, python, maps


class RuntimeStateTests(unittest.TestCase):
    def test_package_paths_require_a_real_package_entry(self):
        manifest, files, python, maps = observation()
        python["modules"][0]["package_paths"] = ("/opt/irlume",)
        with self.assertRaises(ValueError):
            state.check_runtime_state(manifest, files, python, maps)

    def test_maps_do_not_silently_normalize_control_bytes(self):
        manifest, files, python, maps = observation()
        with self.assertRaises(ValueError):
            state.check_runtime_state(
                manifest, files, python, maps.replace(b"\n", b"\r\n")
            )

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
        self.assertIsNone(state.check_runtime_state(*observation()))

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
                state.check_runtime_state(manifest, files, python, maps)
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
                state.check_runtime_state(manifest, files, python, maps)

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
                state.check_runtime_state(manifest, files, python, maps)
        manifest, files, python, maps = observation()
        python["modules"] = python["modules"][1:]
        with self.assertRaises(ValueError):
            state.check_runtime_state(manifest, files, python, maps)

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
                state.check_runtime_state(manifest, bad, python, maps)
        bad = copy.deepcopy(files)
        bad["/usr/bin/python3"]["inode"] += 1
        with self.assertRaises(ValueError):
            state.check_runtime_state(manifest, bad, python, maps)

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
                state.check_runtime_state(manifest, files, python, bad)

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
                state.check_runtime_state(manifest, files, python, bad)

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
            state.check_runtime_state(manifest, files, python, maps)
        mapping = f"0000000000003000-0000000000004000 r-xp 00000000 00:01 999 {path}\n".encode()
        maps = maps.replace(b"0000000000004000-", mapping + b"0000000000004000-", 1)
        self.assertIsNone(state.check_runtime_state(manifest, files, python, maps))

    def test_duplicate_modules_map_overlap_and_numeric_mismatch_refuse(self):
        manifest, files, python, maps = observation()
        duplicate = copy.deepcopy(python)
        duplicate["modules"] += (dict(duplicate["modules"][0]),)
        with self.assertRaises(ValueError):
            state.check_runtime_state(manifest, files, duplicate, maps)
        for bad in (
            maps.replace(b"0000000000002000-", b"0000000000001000-", 1),
            maps.replace(b"00:01", b"00:02", 1),
            maps.replace(b"r-xp 00000000", b"r-xp 00010000", 1),
        ):
            with self.subTest(bad=bad[:100]), self.assertRaises(ValueError):
                state.check_runtime_state(manifest, files, python, bad)

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
            state.check_runtime_state(manifest, files, python, maps)
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
            state.check_runtime_state(manifest, files, python, maps)
        manifest, files, python, maps = observation()
        python["modules"][0]["origin"] = "/usr/lib/python3.14/__init__.py"
        with self.assertRaises(ValueError):
            state.check_runtime_state(manifest, files, python, maps)
        manifest, files, python, maps = observation()
        python["modules"][1]["origin"] = "frozen"
        with self.assertRaises(ValueError):
            state.check_runtime_state(manifest, files, python, maps)

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
                state.check_runtime_state(manifest, files, python, bad)

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
            state.check_runtime_state(manifest, files, python, maps)
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
            state.check_runtime_state(manifest, files, python, maps)

    def test_inaccessible_file_reservation_does_not_claim_readable_file_bytes(self):
        manifest, files, python, maps = observation()
        path = "/lib64/ld-linux-x86-64.so.2"
        reservation = f"0000000000003000-0000000000004000 ---p 00200000 00:01 {files[path]['inode']} {path}\n".encode()
        reserved = maps.replace(
            b"0000000000004000-", reservation + b"0000000000004000-", 1
        )
        self.assertIsNone(state.check_runtime_state(manifest, files, python, reserved))
        for permissions in (b"r--p", b"r-xp", b"rw-p"):
            with self.subTest(permissions=permissions), self.assertRaises(ValueError):
                state.check_runtime_state(
                    manifest, files, python, reserved.replace(b"---p", permissions)
                )
        with self.assertRaises(ValueError):
            state.check_runtime_state(
                manifest,
                files,
                python,
                reserved.replace(reservation, reservation.replace(b"00:01", b"00:02")),
            )


if __name__ == "__main__":
    unittest.main()
