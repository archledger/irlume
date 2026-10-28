#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Private manager build contracts; fixture files and mock commands only."""

import copy
import hashlib
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "entry_build", Path(__file__).with_name("build-measurement-job-runtime.py")
)
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


def elf():
    data = bytearray(120)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 2, 62, 1)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HHH", data, 52, 64, 56, 1)
    struct.pack_into("<I", data, 64, 1)
    return data


class BuildContracts(unittest.TestCase):
    def test_failed_build_preserves_primary_and_attempts_single_close(self):
        primary = KeyboardInterrupt("stop")
        context = SimpleNamespace(
            start=mock.Mock(),
            build=mock.Mock(side_effect=primary),
            failed=mock.Mock(side_effect=OSError("receipt")),
            close=mock.Mock(side_effect=OSError("close")),
        )
        with self.assertRaises(KeyboardInterrupt) as caught:
            build.build_entry("/private/output", _context=lambda _: context)
        self.assertIs(caught.exception, primary)
        context.close.assert_called_once()
        self.assertEqual(len(primary.__notes__), 2)

    def test_successful_build_still_rejects_late_close(self):
        context = SimpleNamespace(
            start=mock.Mock(), build=mock.Mock(), close=mock.Mock(), deadline=10
        )
        with (
            mock.patch.object(build.time, "monotonic", return_value=10),
            self.assertRaises(TimeoutError),
        ):
            build.build_entry("/private/output", _context=lambda _: context)
        context.close.assert_called_once()

    def test_native_root_is_c_entry_with_closed_admission(self):
        native, pure = build.make_roots(Path("/repo"))
        self.assertTrue(native.startswith("#![no_main]"))
        self.assertIn('extern "C" fn main', native)
        self.assertIn("irlume_job_runtime_entry(argc, argv, None)", native)
        self.assertNotIn("from_protected_boot", native)
        self.assertIn("pub mod sys;", native)
        self.assertNotIn("pub mod sys;", pure)
        self.assertNotIn("fn main", pure)

    def test_link_check_rejects_dynamic_wrong_arch_and_missing_native_body(self):
        paths = [Path("/repo/kernel.rs"), Path("/repo/sys.rs")]
        symbols = (
            "0000000000400000 0000000000000500 T irlume_job_runtime_entry\n"
            "0000000000401000 0000000000000020 T main\n"
            "0000000000402000 0000000000000020 T measurement_job_runtime::sys::run\n"
            "0000000000403000 0000000000000020 T measurement_job_runtime::kernel::run_reserved\n"
        )
        deps = "output: /repo/kernel.rs /repo/sys.rs\n"
        build.check_link(bytes(elf()), symbols, deps, paths)
        for change in (2, 3):
            value = elf()
            struct.pack_into("<I", value, 64, change)
            with self.assertRaises(ValueError):
                build.check_link(bytes(value), symbols, deps, paths)
        value = elf()
        struct.pack_into("<H", value, 18, 3)
        with self.assertRaises(ValueError):
            build.check_link(bytes(value), symbols, deps, paths)
        for bad in (
            symbols.replace("T irlume_job_runtime_entry", "U irlume_job_runtime_entry"),
            symbols.replace("irlume_job_runtime_entry", "unrelated"),
            symbols.replace("measurement_job_runtime::sys::run", "unused"),
            symbols.replace("measurement_job_runtime::kernel::run_reserved", "unused"),
        ):
            with self.assertRaises(ValueError):
                build.check_link(bytes(elf()), bad, deps, paths)
        with self.assertRaises(ValueError):
            build.check_link(
                bytes(elf()),
                symbols,
                deps.replace("/repo/sys.rs", "/repo/sys.rs.extra"),
                paths,
            )

    def test_link_map_binds_each_used_startup_object(self):
        root = Path("/toolchain/lib/self-contained")
        names = ("crt1.o", "crti.o", "crtbegin.o", "crtend.o", "crtn.o")
        mapping = "\n".join("LOAD " + str(root / n) for n in names)
        build.check_startup_map(mapping, root)
        for name in names:
            for bad in (
                mapping.replace("LOAD " + str(root / name), ""),
                mapping.replace(str(root / name), "/elsewhere/" + name),
            ):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    build.check_startup_map(bad, root)

    def test_dependency_selector_requires_exact_fresh_owned_rlib(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lib = root / build.TARGET / "release" / "libsample.rlib"
            lib.parent.mkdir(parents=True)
            lib.write_bytes(b"rlib-fixture")
            row = {
                "reason": "compiler-artifact",
                "package_id": "registry+https://github.com/rust-lang/crates.io-index#sample@1.2.3",
                "target": {"name": "sample", "kind": ["lib"]},
                "profile": {"test": False},
                "fresh": False,
                "filenames": [str(lib)],
            }
            rows = [row, {"reason": "build-finished", "success": True}]
            result = build.select_dependencies(rows, root, {"sample": "1.2.3"})
            self.assertEqual(result["sample"]["path"], str(lib))
            for key, value in [
                ("fresh", True),
                ("package_id", "other@1.2.3"),
                ("filenames", [str(root / "elsewhere")]),
            ]:
                bad = copy.deepcopy(rows)
                bad[0][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    build.select_dependencies(bad, root, {"sample": "1.2.3"})
            with self.assertRaises(ValueError):
                build.select_dependencies(rows + [row], root, {"sample": "1.2.3"})
            foreign = root / "outside.rlib"
            foreign.write_bytes(b"existing-foreign-library")
            bad = copy.deepcopy(rows)
            bad[0]["filenames"] = [str(foreign)]
            with self.assertRaisesRegex(ValueError, "dependency outside output"):
                build.select_dependencies(bad, root, {"sample": "1.2.3"})

    def test_dependency_adoption_cannot_refresh_the_selected_hash(self):
        file = "/private/selected.rlib"
        original = b"selected bytes"
        artifacts = {
            "sample": {"path": file, "sha256": hashlib.sha256(original).hexdigest()}
        }
        for changed in (False, True):
            session = build.RuntimeBuild("/private/output")
            content = {file: b"replacement bytes" if changed else original}
            session.pins = build.job.FrozenPins({}, reader=content.__getitem__)
            if changed:
                with self.assertRaisesRegex(RuntimeError, "changed during adoption"):
                    session.pin_dependencies(artifacts)
            else:
                self.assertEqual(
                    session.pin_dependencies(artifacts), ["--extern", "sample=" + file]
                )

    def test_native_product_has_no_command_execution_route(self):
        session = build.RuntimeBuild("/private/output")
        session.inspection_tools = {}
        session.rustup = "/rustup"
        session.cargo = "/cargo"
        with self.assertRaises(ValueError):
            session.direct_command(["/private/output/manager"])


if __name__ == "__main__":
    unittest.main()
