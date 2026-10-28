#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Restricted static ELF metadata inspection; never load or execute a member."""

import re
import struct
from pathlib import PurePosixPath

MAX_ELF = 256 * 1024 * 1024
INTERPRETER = "/lib64/ld-linux-x86-64.so.2"
SINGLETONS = {5, 10, 14, 0x6FFFFFFB}
FORBIDDEN = {15, 29, 0x6FFFFEFA, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF}


def basename(value):
    if (
        type(value) is not str
        or re.fullmatch(r"[A-Za-z0-9_.+-]{1,255}", value) is None
        or value in (".", "..")
    ):
        raise ValueError("invalid ELF dependency name")
    return value


def inspect(data):
    """Read only the ELF/program/dynamic metadata used by the closure policy."""
    if type(data) is not bytes or not 64 <= len(data) <= MAX_ELF:
        raise ValueError("ELF byte limit")
    if (
        data[:7] != b"\x7fELF\x02\x01\x01"
        or data[7] not in (0, 3)
        or data[8] != 0
        or any(data[9:16])
    ):
        raise ValueError("unsupported ELF identification")
    (
        kind,
        machine,
        version,
        _entry,
        phoff,
        _shoff,
        _flags,
        header_size,
        phsize,
        phnum,
        _shsize,
        _shnum,
        _shstr,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if (
        kind not in (2, 3)
        or machine != 62
        or version != 1
        or header_size != 64
        or phsize != 56
        or not 1 <= phnum <= 128
        or phoff < 64
        or phoff + phnum * phsize > len(data)
    ):
        raise ValueError("unsupported ELF/program header")
    segments = []
    for i in range(phnum):
        tag, _flags, offset, address, _physical, size, memory_size, alignment = (
            struct.unpack_from("<IIQQQQQQ", data, phoff + i * 56)
        )
        if offset + size > len(data) or address + memory_size >= 2**64:
            raise ValueError("ELF segment bounds")
        if tag == 3 and any(segment[0] == 1 for segment in segments):
            raise ValueError("ELF interpreter must precede load segments")
        if tag == 1 and (
            size > memory_size
            or (
                alignment > 1
                and (
                    alignment & (alignment - 1)
                    or offset % alignment != address % alignment
                )
            )
        ):
            raise ValueError("ELF load segment")
        segments.append((tag, offset, address, size, memory_size))
    interpreters = [s for s in segments if s[0] == 3]
    dynamics = [s for s in segments if s[0] == 2]
    if len(interpreters) > 1 or len(dynamics) > 1:
        raise ValueError("duplicate ELF program metadata")
    interpreter = None
    if interpreters:
        _, offset, _, size, _ = interpreters[0]
        if (
            not 2 <= size <= 4096
            or data[offset : offset + size] != INTERPRETER.encode() + b"\0"
        ):
            raise ValueError("unsupported ELF interpreter")
        interpreter = INTERPRETER
    result = {
        "type": kind,
        "dynamic": bool(dynamics),
        "interpreter": interpreter,
        "needed": (),
        "soname": None,
        "flags1": 0,
    }
    if not dynamics:
        if interpreter is not None:
            raise ValueError("ELF interpreter without dynamic metadata")
        return result

    def mapped(address, size):
        matches = [
            (offset, virtual, count)
            for tag, offset, virtual, count, memory_size in segments
            if tag == 1
            and memory_size > 0
            and virtual < address + size
            and address < virtual + memory_size
        ]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous ELF virtual mapping")
        offset, virtual, count = matches[0]
        if not virtual <= address or address + size > virtual + count:
            raise ValueError("ELF metadata is not entirely file-backed")
        return offset + address - virtual

    _, offset, virtual, size, _ = dynamics[0]
    if not 16 <= size <= 4096 * 16 or size % 16 or mapped(virtual, size) != offset:
        raise ValueError("ELF dynamic bounds")
    values, needed = {}, []
    terminated = False
    for position in range(offset, offset + size, 16):
        tag, value = struct.unpack_from("<qQ", data, position)
        if tag == 0:
            # GABI 8.3: DT_NULL terminates the array; its d_un is ignored.
            # Keep this profile's stronger requirement of null-only tail tags.
            if any(
                struct.unpack_from("<q", data, tail)[0] != 0
                for tail in range(position + 16, offset + size, 16)
            ):
                raise ValueError("ELF dynamic padding")
            terminated = True
            break
        if tag < 0 or tag in FORBIDDEN:
            raise ValueError("unsupported ELF dynamic tag")
        if tag == 1:
            needed.append(value)
            if len(needed) > 128:
                raise ValueError("ELF dependency count")
        elif tag in SINGLETONS:
            if tag in values:
                raise ValueError("duplicate ELF dynamic tag")
            values[tag] = value
    if (
        not terminated
        or 5 not in values
        or not 1 <= values.get(10, 0) <= 4 * 1024 * 1024
    ):
        raise ValueError("ELF dynamic strings or terminator missing")
    string_size = values[10]
    string_offset = mapped(values[5], string_size)
    strings = data[string_offset : string_offset + string_size]
    if not strings or strings[0] or strings[-1]:
        raise ValueError("ELF string-table boundary")

    def name(index):
        if not 0 <= index < len(strings):
            raise ValueError("ELF string offset")
        end = strings.find(b"\0", index, min(len(strings), index + 256))
        if end < 0:
            raise ValueError("unterminated ELF dependency")
        try:
            return basename(strings[index:end].decode("ascii"))
        except UnicodeError as error:
            raise ValueError("non-ASCII ELF dependency") from error

    names = tuple(name(index) for index in needed)
    if len(set(names)) != len(names):
        raise ValueError("duplicate ELF dependency")
    result.update(
        needed=names,
        soname=name(values[14]) if 14 in values else None,
        flags1=values.get(0x6FFFFFFB, 0),
    )
    return result


def require_dso(image):
    if image["type"] != 3 or not image["dynamic"] or image["flags1"] & 0x08000000:
        raise ValueError("ineligible ELF dependency or extension")


def link_graph(images):
    """Resolve exact filenames within a flat /lib64; no host-loader probing."""
    if type(images) is not dict or not 1 <= len(images) <= 512:
        raise ValueError("ELF closure size")
    graph, edges = {}, 0
    for path, image in sorted(images.items()):
        value = PurePosixPath(path)
        if value.is_absolute() or str(value) != path or ".." in value.parts:
            raise ValueError("ELF closure path")
        if image["soname"] is not None and image["soname"] != value.name:
            raise ValueError("ELF SONAME does not match filename")
        targets = []
        if image["interpreter"] is not None:
            targets.append(INTERPRETER[1:])
        targets.extend("lib64/" + basename(name) for name in image["needed"])
        edges += len(targets)
        if edges > 8192:
            raise ValueError("ELF edge limit")
        for target in targets:
            if target not in images:
                raise ValueError("missing ELF dependency: " + target)
            require_dso(images[target])
        graph[path] = tuple(targets)
    # Every member is a root; visited bounds cycles and diamonds without
    # requiring a topological order (libc and its loader can depend on each other).
    pending, visited = list(graph), set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        pending.extend(target for target in graph[path] if target not in visited)
    return graph


if __name__ == "__main__":
    raise SystemExit(77)
