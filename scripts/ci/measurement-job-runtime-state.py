#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Pure Python/native-map checks. Supplied facts do not prove provenance."""

import hashlib
import importlib.machinery
import importlib.util
import re
import stat
from pathlib import Path
from types import MappingProxyType
from typing import NamedTuple


class SourceLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        return self.source_to_code(self.get_data(self.path), self.path)


loader = SourceLoader(
    "state_closure", str(Path(__file__).with_name("measurement-job-closure.py"))
)
spec = importlib.util.spec_from_loader(loader.name, loader)
closure = importlib.util.module_from_spec(spec)
loader.exec_module(closure)
runtime = closure.runtime
PAGE = closure.PAGE
FLAGS = {
    "isolated": 1,
    "no_site": 1,
    "dont_write_bytecode": 1,
    "ignore_environment": 1,
    "safe_path": True,
}


def check_prefix(prefix):
    """prefix is "" for a rooted process, else the tree's canonical host path.

    Facts and maps of an unrooted process name tree files as prefix + "/" +
    member, compared verbatim: no path is rebased, so a path outside the
    tree never stands for a member. relative_path bounds its length and depth.
    """
    if prefix == "":
        return prefix
    if type(prefix) is not str or not prefix.startswith("/"):
        raise ValueError("runtime path prefix")
    try:
        closure.relative_path(prefix[1:])
    except ValueError as error:
        raise ValueError("runtime path prefix") from error
    return prefix


def check_files(manifest, files, *, prefix=""):
    members = closure.check_manifest(manifest)
    prefix = check_prefix(prefix)
    selected = {
        prefix + "/" + path: row
        for path, row in members.items()
        if row["kind"] == "file"
    }
    runtime._fields(files, selected)
    identities = set()
    for path, row in files.items():
        runtime._fields(row, ("device", "inode", "mode", "size", "sha256"))
        for name in ("device", "size"):
            runtime._integer(row[name], 0, runtime.U64_MAX)
        runtime._integer(row["inode"], 1, runtime.U64_MAX)
        runtime._integer(row["mode"], 0, 0o177777)
        identity = row["device"], row["inode"]
        if identity in identities:
            raise ValueError("aliased runtime file identities")
        identities.add(identity)
        expected = selected[path]
        if (
            row["mode"] != stat.S_IFREG | expected["mode"]
            or row["size"] != expected["size"]
            or type(row["sha256"]) is not str
            or row["sha256"] != expected["sha256"]
        ):
            raise ValueError("runtime file mode, size or digest")
    return members


def check_python(manifest, files, state, *, prefix="", entry=None):
    """entry: the selected main source when it is not the manifest's own."""
    members = check_files(manifest, files, prefix=prefix)
    if entry is None:
        entry = manifest["python"]["entry"]
    elif (
        type(entry) is not str
        or entry not in members
        or members[entry]["kind"] != "file"
        or not entry.endswith(".py")
    ):
        raise ValueError("runtime main entry")
    runtime._fields(
        state,
        (
            "implementation",
            "version",
            "executable",
            "flags",
            "pycache_prefix",
            "environment",
            "sys_path",
            "jit_available",
            "jit_enabled",
            "modules",
        ),
    )
    selected = manifest["python"]
    if (
        state["implementation"] != selected["implementation"]
        or type(state["version"]) is not tuple
        or state["version"] != tuple(selected["version"])
        or any(type(n) is not int for n in state["version"])
        or state["executable"] != prefix + "/" + selected["executable"]
    ):
        raise ValueError("runtime Python identity")
    runtime._fields(state["flags"], FLAGS)
    for name, value in FLAGS.items():
        if (
            type(state["flags"][name]) is not type(value)
            or state["flags"][name] != value
        ):
            raise ValueError("runtime Python flag")
    runtime._fields(state["environment"], manifest["environment"])
    if (
        state["environment"] != manifest["environment"]
        or state["pycache_prefix"] != "/dev/null"
        or type(state["sys_path"]) is not tuple
        or state["sys_path"] != tuple(prefix + "/" + path for path in selected["roots"])
    ):
        raise ValueError("runtime Python environment or search path")
    if (
        type(state["jit_available"]) is not bool
        or type(state["jit_enabled"]) is not bool
        or state["jit_enabled"]
    ):
        raise ValueError("runtime JIT is enabled or unknown")
    modules = state["modules"]
    if type(modules) is not tuple or not 1 <= len(modules) <= 4096:
        raise ValueError("runtime module inventory cap")
    names, extensions = set(), set()
    total = 0
    for module in modules:
        runtime._fields(module, ("name", "kind", "origin", "package_paths", "cached"))
        name, kind, origin = module["name"], module["kind"], module["origin"]
        if (
            type(name) is not str
            or not 1 <= len(name) <= 255
            or re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name
            )
            is None
            or name in names
        ):
            raise ValueError("runtime module name")
        names.add(name)
        if (
            type(kind) is not str
            or kind not in ("builtin", "frozen", "source", "extension")
            or type(origin) is not str
            or len(origin) > 4096
        ):
            raise ValueError("runtime module loader or origin")
        package, cached = module["package_paths"], module["cached"]
        if (
            type(package) is not tuple
            or len(package) > 1
            or any(type(path) is not str or len(path) > 4096 for path in package)
        ):
            raise ValueError("runtime module package path")
        if cached is not None and (
            type(cached) is not str
            or len(cached) > 4096
            or not cached.startswith("/dev/null/")
            or any(part in ("", ".", "..") for part in cached[1:].split("/"))
        ):
            raise ValueError("runtime module bytecode cache")
        total += (
            len(name)
            + len(origin)
            + sum(map(len, package))
            + (len(cached) if cached is not None else 0)
        )
        if total > 1024**2:
            raise ValueError("runtime module text cap")
        if kind in ("builtin", "frozen"):
            if (
                origin != {"builtin": "built-in", "frozen": "frozen"}[kind]
                or package
                or cached is not None
            ):
                raise ValueError("runtime builtin or frozen origin")
        else:
            if origin not in files or not origin.endswith(
                ".py" if kind == "source" else ".so"
            ):
                raise ValueError("runtime module is not a selected file")
            if package and (
                package != (str(Path(origin).parent),)
                or package[0][len(prefix) + 1 :] not in members
                or members[package[0][len(prefix) + 1 :]]["kind"] != "directory"
            ):
                raise ValueError("runtime package is not selected")
            if package and (
                Path(origin).name != "__init__.py"
                if kind == "source"
                else not Path(origin).name.startswith("__init__.")
            ):
                raise ValueError("runtime package has no package entry")
            if kind == "extension":
                extensions.add(origin)
        if name == "__main__" and (kind != "source" or origin != prefix + "/" + entry):
            raise ValueError("runtime main entry")
    if "__main__" not in names:
        raise ValueError("runtime main module missing")
    return extensions


def mount_device(mounts, path):
    """Return the device of the mount holding path.

    mounts is root.parse_mountinfo's view, which refuses stacked and hidden
    mounts, so a path walk ends on the deepest mount point that is path or
    one of its parent directories.
    """
    if type(mounts) is not dict or "/" not in mounts:
        raise ValueError("runtime mount view")
    point = path
    while point not in mounts:
        point = point.rpartition("/")[0] or "/"
    device = mounts[point].device
    if type(device) is not tuple or len(device) != 2:
        raise ValueError("runtime mount device")
    for number in device:
        runtime._integer(number, 0, runtime.U32_MAX)
    return device


class Mapping(NamedTuple):
    """A readable mapping of a selected runtime file, as maps shows it."""

    start: int
    end: int
    offset: int
    path: str
    execute: bool


def file_mappings(data, files, mounts):
    """Parse maps for collection and checking alike.

    Return the paths with an executable mapping and, in maps order, every
    readable mapping of a selected runtime file.
    """
    if (
        type(data) is not bytes
        or not 0 < len(data) <= 1024**2
        or not data.endswith(b"\n")
    ):
        raise ValueError("runtime maps byte cap or truncation")
    if any(byte not in (9, 10) and not 32 <= byte <= 126 for byte in data):
        raise ValueError("runtime maps control byte")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("runtime maps encoding") from error
    if not 1 <= len(lines) <= 8192:
        raise ValueError("runtime maps line cap")
    executable, readable, previous, vdso, vsyscall = set(), [], 0, 0, 0
    for line in lines:
        fields = line.split(None, 5)
        if len(fields) not in (5, 6):
            raise ValueError("runtime maps fields")
        addresses, permissions, offset_text, device_text, inode_text = fields[:5]
        match = re.fullmatch(r"([0-9a-fA-F]{1,16})-([0-9a-fA-F]{1,16})", addresses)
        if (
            match is None
            or re.fullmatch(r"[r-][w-][x-][ps]", permissions) is None
            or re.fullmatch(r"[0-9a-fA-F]{1,16}", offset_text) is None
            or re.fullmatch(r"[0-9]{1,20}", inode_text) is None
        ):
            raise ValueError("runtime maps numeric or permission fields")
        device = re.fullmatch(r"([0-9a-fA-F]{1,8}):([0-9a-fA-F]{1,8})", device_text)
        if device is None:
            raise ValueError("runtime maps device")
        start, end = (int(value, 16) for value in match.groups())
        offset, inode = int(offset_text, 16), int(inode_text)
        major, minor = (int(value, 16) for value in device.groups())
        if (
            start >= end
            or start < previous
            or start % 4096
            or end % 4096
            or offset % 4096
            or inode > runtime.U64_MAX
        ):
            raise ValueError("runtime maps ranges")
        previous = end
        path = fields[5] if len(fields) == 6 else ""
        if (
            len(path) > 4096
            or any(not 32 <= ord(char) <= 126 for char in path)
            or "\\" in path
            or path.endswith(" (deleted)")
        ):
            raise ValueError("runtime maps path")
        execute = permissions[2] == "x"
        if execute and (permissions[1] == "w" or permissions[3] != "p"):
            raise ValueError("runtime writable or shared executable map")
        if path in ("[vdso]", "[vsyscall]"):
            if inode or major or minor or offset:
                raise ValueError("runtime kernel map identity")
            if path == "[vdso]":
                vdso += 1
                if permissions != "r-xp" or vdso != 1:
                    raise ValueError("runtime vdso mapping")
            else:
                vsyscall += 1
                if (
                    permissions != "--xp"
                    or (start, end) != (0xFFFFFFFFFF600000, 0xFFFFFFFFFF601000)
                    or vsyscall != 1
                ):
                    raise ValueError("runtime vsyscall mapping")
            continue
        if not inode:
            if (
                major
                or minor
                or offset
                or execute
                or (path and not (path.startswith("[") and path.endswith("]")))
            ):
                raise ValueError("runtime anonymous mapping")
            continue
        if path not in files:
            raise ValueError("runtime unlisted mapped file")
        selected = files[path]
        # Linux 7.2 maps shows the mapped inode's superblock device
        # (fs/proc/task_mmu.c show_map_vma), as mountinfo does for each
        # mount (fs/proc_namespace.c show_mountinfo). stat can differ: btrfs
        # reports the subvolume's anonymous device (fs/btrfs/inode.c
        # btrfs_getattr), so the snapshot's stat device stays its own pin.
        # On btrfs an inode number is unique only per subvolume, so a file
        # in another subvolume or snapshot can carry this device and inode.
        # What binds a mapping to the runtime is its bytes: check_mapped
        # compares every page still backed by a file with the hashed file.
        if inode != selected["inode"] or (major, minor) != mount_device(mounts, path):
            raise ValueError("runtime mapped file identity")
        if permissions[0] != "r":
            # A private PROT_NONE loader reservation exposes no file bytes.
            if permissions != "---p":
                raise ValueError("runtime unreadable file mapping")
            continue
        if offset + end - start > (selected["size"] + PAGE - 1) // PAGE * PAGE:
            raise ValueError("runtime mapped file extent")
        if execute:
            executable.add(path)
        readable.append(Mapping(start, end, offset, path, execute))
    if vdso != 1:
        raise ValueError("runtime vdso absent")
    return executable, tuple(readable)


def check_mapped(readable, files, mapped, pages):
    """Bind each readable mapping's file-backed pages to the hashed file.

    mapped holds G's rows, one per readable mapping in maps order; pages
    holds the checker's own page digests of each selected ELF file, never
    values decoded from a request or a witness. A page that is anonymous
    (copied on write: RELRO, .data, .got) is counted, not compared, and
    an executable mapping may have none. The binding holds at the maps read.
    """
    if type(pages) is not MappingProxyType:
        raise ValueError("runtime page digests")
    if type(mapped) is not tuple or len(mapped) != len(readable):
        raise ValueError("runtime mapped row count")
    checked = set()
    for mapping, row in zip(readable, mapped):
        runtime._fields(row, ("start", "end", "anonymous", "sha256"))
        if (
            type(row["start"]) is not int
            or type(row["end"]) is not int
            or (row["start"], row["end"]) != (mapping.start, mapping.end)
        ):
            raise ValueError("runtime mapped row range")
        count = (mapping.end - mapping.start) // PAGE
        anonymous = row["anonymous"]
        if type(anonymous) is not bytes or len(anonymous) != (count + 7) // 8:
            raise ValueError("runtime mapped page bitmap")
        if count % 8 and anonymous[-1] >> (count % 8):
            raise ValueError("runtime mapped page bitmap padding")
        if mapping.execute and any(anonymous):
            raise ValueError("runtime anonymous page in executable mapping")
        digests = pages.get(mapping.path)
        if mapping.path not in checked:
            if (
                type(digests) is not tuple
                or len(digests) != (files[mapping.path]["size"] + PAGE - 1) // PAGE
                or any(type(item) is not bytes or len(item) != 32 for item in digests)
            ):
                raise ValueError("runtime page digests")
            checked.add(mapping.path)
        first = mapping.offset // PAGE
        expected = hashlib.sha256()
        for index in range(count):
            if not (anonymous[index // 8] >> (index % 8)) & 1:
                expected.update(digests[first + index])
        if row["sha256"] != expected.hexdigest():
            raise ValueError("runtime mapped bytes differ")


def check_maps(data, files, mounts, mapped, pages):
    executable, readable = file_mappings(data, files, mounts)
    check_mapped(readable, files, mapped, pages)
    return executable


def check_runtime_state(
    manifest, files, state, maps, mounts, mapped, pages, *, prefix="", entry=None
):
    """Check supplied observations; callers must prove collection and freshness.

    mounts is the parsed mount view of the process whose maps these are;
    mapped holds that process's rows for those maps and pages the checker's
    own page digests of the selected runtime (check_mapped). prefix and
    entry are for a process outside the tree (check_prefix, check_python);
    their defaults are the rooted guardian's view.
    """
    prefix = check_prefix(prefix)
    extensions = check_python(manifest, files, state, prefix=prefix, entry=entry)
    executable = check_maps(maps, files, mounts, mapped, pages)
    required = {
        prefix + "/" + manifest["python"]["executable"],
        prefix + "/" + manifest["native"]["interpreter"],
        *extensions,
    }
    if not required <= executable:
        raise ValueError("runtime executable mapping missing")
