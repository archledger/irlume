#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Synthetic ELF closure tests. No supplied executable is run."""

import importlib.util
import struct
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("elf", HERE / "measurement-job-elf.py")
elf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(elf)


def image(*, needed=(), soname=None, interpreter=None, dynamic=True, kind=3, extra=()):
    data = bytearray(16384)
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    count = 1 + bool(dynamic) + bool(interpreter)
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        kind,
        62,
        1,
        0x400800,
        64,
        0,
        0,
        64,
        56,
        count,
        0,
        0,
        0,
    )
    struct.pack_into(
        "<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0, len(data), len(data), 4096
    )
    position = 120
    if dynamic:
        strings = bytearray(b"\0")
        refs = []
        for tag, text in [(1, n) for n in needed] + (
            [(14, soname)] if soname is not None else []
        ):
            refs.append((tag, len(strings)))
            strings.extend(text.encode() + b"\0")
        tags = [(5, 0x402000), (10, len(strings)), *refs, *extra, (0, 0)]
        for i, pair in enumerate(tags):
            struct.pack_into("<qQ", data, 256 + i * 16, *pair)
        data[8192 : 8192 + len(strings)] = strings
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            position,
            2,
            6,
            256,
            0x400100,
            0,
            len(tags) * 16,
            len(tags) * 16,
            8,
        )
        position += 56
    if interpreter:
        value = interpreter.encode() + b"\0"
        data[768 : 768 + len(value)] = value
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            position,
            3,
            4,
            768,
            0x400300,
            0,
            len(value),
            len(value),
            1,
        )
        headers = [bytes(data[64 + i * 56 : 120 + i * 56]) for i in range(count)]
        data[64 : 64 + count * 56] = b"".join([headers[-1], *headers[:-1]])
    return bytes(data)


class ElfTests(unittest.TestCase):
    def test_null_tag_values_are_ignored_but_nonnull_tail_tags_refuse(self):
        expected = elf.inspect(image())
        self.assertEqual(elf.inspect(image(extra=((0, 0xABCDEF),))), expected)
        self.assertEqual(elf.inspect(image(extra=((0, 0), (0, 550610)))), expected)
        for tag in (1, 0x123456):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                elf.inspect(image(extra=((0, 0), (tag, 0))))

    def test_empty_load_inside_metadata_range_does_not_compete(self):
        data = bytearray(image(needed=("a.so",)))
        struct.pack_into("<Q", data, 280, 8192)
        struct.pack_into("<H", data, 56, 3)
        struct.pack_into("<IIQQQQQQ", data, 176, 1, 4, 0x3000, 0x403000, 0, 0, 0, 4096)
        try:
            parsed = elf.inspect(bytes(data))
        except ValueError as error:
            self.fail("empty load incorrectly changed metadata mapping: " + str(error))
        self.assertEqual(parsed["needed"], ("a.so",))

    def test_metadata_cannot_extend_into_its_only_load_zero_fill_tail(self):
        for file_size in (264, 8194):
            data = bytearray(image(needed=("a.so",)))
            struct.pack_into("<Q", data, 96, file_size)
            with self.subTest(file_size=file_size), self.assertRaises(ValueError):
                elf.inspect(bytes(data))

    def test_partial_or_zero_fill_load_overlap_with_metadata_refuses(self):
        for address, offset in ((0x402002, 0x3002), (0x400102, 0x3102)):
            for zero_fill in (False, True):
                data = bytearray(image(needed=("a.so",)))
                struct.pack_into("<H", data, 56, 3)
                # File-backed bytes stop at the metadata start in the tail case;
                # only the zero-filled memory portion then overlaps the metadata.
                size = 2 if zero_fill else 4
                segment_address = address - 4 if zero_fill else address
                segment_offset = offset - 4 if zero_fill else offset
                struct.pack_into(
                    "<IIQQQQQQ",
                    data,
                    176,
                    1,
                    4,
                    segment_offset,
                    segment_address,
                    0,
                    size,
                    8 if zero_fill else 4,
                    4096,
                )
                data[offset : offset + 4] = b"evil"
                with (
                    self.subTest(address=address, zero_fill=zero_fill),
                    self.assertRaises(ValueError),
                ):
                    elf.inspect(bytes(data))

    def test_dual_use_dso_interpreter_is_valid_but_must_precede_loads(self):
        data = image(
            interpreter=elf.INTERPRETER, soname="libc.so.6", extra=((0x6FFFFFFB, 1),)
        )
        parsed = elf.inspect(data)
        elf.require_dso(parsed)
        wrong_order = bytearray(data)
        wrong_order[64:120], wrong_order[120:176] = data[120:176], data[64:120]
        with self.assertRaises(ValueError):
            elf.inspect(bytes(wrong_order))

    def test_duplicate_program_metadata_and_ambiguous_string_mapping_refuse(self):
        for duplicate_type in (1, 2, 3):
            data = bytearray(image(interpreter=elf.INTERPRETER))
            data[2048:2216] = data[64:232]
            struct.pack_into("<Q", data, 32, 2048)
            struct.pack_into("<H", data, 56, 4)
            source = next(
                64 + i * 56
                for i in range(3)
                if struct.unpack_from("<I", data, 64 + i * 56)[0] == duplicate_type
            )
            data[2216:2272] = data[source : source + 56]
            with self.subTest(type=duplicate_type), self.assertRaises(ValueError):
                elf.inspect(bytes(data))

    def test_dependency_count_and_nonterminated_names_are_bounded(self):
        with self.assertRaises(ValueError):
            elf.inspect(image(needed=tuple(f"lib{i}.so" for i in range(129))))
        data = bytearray(image(needed=("lib.so",)))
        data[8193:8200] = b"x" * 7
        with self.assertRaises(ValueError):
            elf.inspect(bytes(data))

    def test_static_and_dynamic_metadata_without_execution(self):
        static = elf.inspect(image(dynamic=False, kind=2))
        self.assertFalse(static["dynamic"])
        dynamic = elf.inspect(
            image(
                needed=("libpython.so", "libc.so.6"),
                interpreter="/lib64/ld-linux-x86-64.so.2",
            )
        )
        self.assertEqual(dynamic["needed"], ("libpython.so", "libc.so.6"))
        self.assertEqual(dynamic["interpreter"], "/lib64/ld-linux-x86-64.so.2")

    def test_wrong_format_truncated_headers_and_external_paths_refuse(self):
        for value in (
            b"",
            image()[:63],
            b"\0" * 4096,
            image(needed=("/tmp/library.so",)),
            image(interpreter="/other/loader"),
            image(extra=((15, 0),)),
            image(extra=((29, 0),)),
            image(extra=((0x6FFFFEFC, 0),)),
        ):
            with self.subTest(size=len(value)), self.assertRaises(ValueError):
                elf.inspect(value)
        for offset, fmt, value in (
            (4, "B", 1),
            (5, "B", 2),
            (18, "<H", 3),
            (54, "<H", 64),
            (56, "<H", 129),
        ):
            data = bytearray(image())
            struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                elf.inspect(bytes(data))

    def test_duplicate_tags_names_missing_terminator_and_ranges_refuse(self):
        for value in (image(needed=("a.so", "a.so")), image(extra=((5, 0x402000),))):
            with self.assertRaises(ValueError):
                elf.inspect(value)
        data = bytearray(image())
        struct.pack_into("<qQ", data, 288, 1, 0)
        with self.assertRaises(ValueError):
            elf.inspect(bytes(data))
        data = bytearray(image())
        struct.pack_into("<qQ", data, 288, 0x6FFFFEF5, 0)
        with self.assertRaises(ValueError):
            elf.inspect(bytes(data))
        data = bytearray(image())
        struct.pack_into("<Q", data, 264, 0x900000)
        with self.assertRaises(ValueError):
            elf.inspect(bytes(data))

    def test_graph_uses_filenames_handles_cycles_and_rejects_missing_edges(self):
        files = {
            "usr/bin/python3": elf.inspect(
                image(needed=("a.so",), interpreter="/lib64/ld-linux-x86-64.so.2")
            ),
            "lib64/ld-linux-x86-64.so.2": elf.inspect(image()),
            "lib64/a.so": elf.inspect(image(needed=("b.so",), soname="a.so")),
            "lib64/b.so": elf.inspect(image(needed=("a.so",), soname="b.so")),
        }
        graph = elf.link_graph(files)
        self.assertIn("lib64/a.so", graph["lib64/b.so"])
        files["lib64/wrong.so"] = files.pop("lib64/a.so")
        with self.assertRaises(ValueError):
            elf.link_graph(files)

    def test_no_dynamic_metadata_or_pie_cannot_satisfy_dso_role(self):
        for candidate in (
            image(dynamic=False),
            image(kind=2),
            image(extra=((0x6FFFFFFB, 0x08000000),)),
        ):
            parsed = elf.inspect(candidate)
            with self.subTest(dynamic=parsed["dynamic"]), self.assertRaises(ValueError):
                elf.require_dso(parsed)
            files = {
                "usr/bin/python3": elf.inspect(image(needed=("a.so",))),
                "lib64/a.so": parsed,
            }
            with self.assertRaises(ValueError):
                elf.link_graph(files)

    def test_graph_caps_and_soname_filename_mismatch_refuse(self):
        shared = elf.inspect(image(needed=tuple(f"a{i}.so" for i in range(17))))
        files = {f"lib64/a{i}.so": shared for i in range(512)}
        with self.assertRaises(ValueError):
            elf.link_graph(files)
        files = {"lib64/wrong.so": elf.inspect(image(soname="actual.so"))}
        with self.assertRaises(ValueError):
            elf.link_graph(files)


if __name__ == "__main__":
    unittest.main()
