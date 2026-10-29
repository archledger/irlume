#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Checked candidate core witnesses. Never an admission or provenance token."""

import importlib.machinery
import importlib.util
import os
import stat
from pathlib import Path


class SourceLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        return self.source_to_code(self.get_data(self.path), self.path)


loader = SourceLoader(
    "preflight_filesystem",
    str(Path(__file__).with_name("measurement-job-filesystem.py")),
)
spec = importlib.util.spec_from_loader(loader.name, loader)
filesystem = importlib.util.module_from_spec(spec)
loader.exec_module(filesystem)
root = filesystem.root
runtime = root.runtime
NODE_FIELDS = (
    "device",
    "inode",
    "mode",
    "uid",
    "gid",
    "links",
    "size",
    "mtime_ns",
    "ctime_ns",
    "rdev",
)


def check_bytes(value, limit):
    if type(value) is not bytes or not 0 < len(value) <= limit:
        raise ValueError("preflight byte observation")


def check_node(node):
    if node is None:
        return
    if type(node) is not dict:
        raise ValueError("preflight node type")
    mode = node.get("mode")
    runtime._integer(mode, 0, 0o177777)
    symbolic = stat.S_ISLNK(mode)
    runtime._fields(node, (*NODE_FIELDS, "target") if symbolic else NODE_FIELDS)
    for name in ("device", "links", "size", "rdev"):
        runtime._integer(node[name], 0, runtime.U64_MAX)
    runtime._integer(node["inode"], 1, runtime.U64_MAX)
    for name in ("uid", "gid"):
        runtime._integer(node[name], 0, runtime.U32_MAX)
    for name in ("mtime_ns", "ctime_ns"):
        runtime._integer(node[name], -(2**63), 2**63 - 1)
    if symbolic and (
        type(node["target"]) is not str
        or not 1 <= len(node["target"]) <= 4096
        or any(not 32 <= ord(char) <= 126 for char in node["target"])
    ):
        raise ValueError("preflight symlink target")


def check_stdio(value):
    if type(value) is not tuple or len(value) != 3:
        raise ValueError("preflight stdio shape")
    for number, row in enumerate(value):
        if type(row) is not tuple or len(row) != 3:
            raise ValueError("preflight stdio row")
        fd, identity, flags = row
        runtime._integer(fd, number, number)
        if type(identity) is not tuple or len(identity) != 4:
            raise ValueError("preflight stdio identity")
        for part in identity:
            runtime._integer(part, 0, runtime.U64_MAX)
        runtime._integer(identity[1], 1, runtime.U64_MAX)
        runtime._integer(identity[2], 0, 0o177777)
        runtime._integer(flags, 0, runtime.U32_MAX)
        if flags & os.O_PATH or flags & os.O_ACCMODE not in (
            (os.O_RDONLY, os.O_RDWR) if fd == 0 else (os.O_WRONLY, os.O_RDWR)
        ):
            raise ValueError("preflight unusable stdio")


def check_snapshot(plan, snapshot, deadline, now):
    root.check_plan(plan)
    runtime._integer(deadline, 1, runtime.U64_MAX)
    runtime._integer(now, 1, deadline - 1)
    runtime._fields(
        snapshot,
        (
            "proc",
            "nodes",
            "entries",
            "volumes",
            "status_after",
            "started_ns",
            "finished_ns",
        ),
    )
    proc = snapshot["proc"]
    runtime._fields(
        proc,
        (
            "root",
            "namespaces",
            "uid_map",
            "gid_map",
            "status",
            "fds",
            "mountinfo",
            "maps",
            "stdio",
            "status_before",
            "started_ns",
            "finished_ns",
        ),
    )
    runtime._integer(snapshot["started_ns"], 1, now)
    runtime._integer(
        now, 1, min(deadline, snapshot["started_ns"] + filesystem.startup.START_NS) - 1
    )
    runtime._integer(
        snapshot["finished_ns"],
        snapshot["started_ns"],
        min(now, snapshot["started_ns"] + 5_000_000_000),
    )
    runtime._integer(proc["started_ns"], snapshot["started_ns"], snapshot["started_ns"])
    runtime._integer(proc["finished_ns"], proc["started_ns"], snapshot["finished_ns"])
    for name, limit in filesystem.startup.LIMITS.items():
        check_bytes(proc[name], limit)
    check_bytes(proc["status_before"], 65536)
    check_bytes(snapshot["status_after"], 65536)
    check_stdio(proc["stdio"])
    paths = {"/"}
    for path in (*filesystem.target_paths(plan), *filesystem.directory_policy(plan)):
        parts = path[1:].split("/")
        paths.update(
            "/" + "/".join(parts[:count]) for count in range(1, len(parts) + 1)
        )
    nodes = snapshot["nodes"]
    runtime._fields(nodes, paths)
    for node in nodes.values():
        check_node(node)
    for path, node in nodes.items():
        if path != "/":
            parent = nodes[path.rpartition("/")[0] or "/"]
            if (
                parent is None
                and node is not None
                or parent is not None
                and not stat.S_ISDIR(parent["mode"])
            ):
                raise ValueError("preflight node parent")
    entries = snapshot["entries"]
    runtime._fields(entries, filesystem.directory_policy(plan))
    count = 0
    for path, names in entries.items():
        if (
            (nodes[path] is None) != (names is None)
            or nodes[path] is not None
            and not stat.S_ISDIR(nodes[path]["mode"])
        ):
            raise ValueError("preflight directory observation")
        if names is None:
            continue
        if (
            type(names) is not tuple
            or len(names) > 128
            or any(
                type(name) is not str
                or not 1 <= len(name) <= 255
                or any(not 32 <= ord(char) <= 126 for char in name)
                for name in names
            )
        ):
            raise ValueError("preflight entry names")
        count += len(names)
        if count > 128 or tuple(sorted(set(names))) != names:
            raise ValueError("preflight directory inventory")


def core_witness(plan, snapshot, deadline, now):
    """Return a checked core candidate, without granting provenance or admission."""
    check_snapshot(plan, snapshot, deadline, now)
    nodes, proc = snapshot["nodes"], snapshot["proc"]
    filesystem.check_roles(plan, nodes, snapshot["entries"])
    root.identity(proc["root"])
    runtime._fields(proc["namespaces"], root.NAMESPACES)
    if not filesystem.selected_identity(nodes["/"], proc["root"]):
        raise ValueError("preflight root observations disagree")
    for status in (proc["status_before"], proc["status"], snapshot["status_after"]):
        root.check_status(status, plan["uid"], plan["gid"])
    mounts = root.parse_mountinfo(proc["mountinfo"])
    volumes = snapshot["volumes"]
    runtime._fields(volumes, ("/", "/run", "/tmp"))
    flags = {
        "ro": os.ST_RDONLY,
        "nosuid": os.ST_NOSUID,
        "nodev": os.ST_NODEV,
        "noexec": os.ST_NOEXEC,
    }
    for path, volume in volumes.items():
        runtime._fields(volume, ("flags", "bytes"))
        runtime._integer(volume["flags"], 0, runtime.U64_MAX)
        runtime._integer(volume["bytes"], 1, runtime.U64_MAX)
        if path not in mounts or any(
            bool(volume["flags"] & bit) != (name in mounts[path][1])
            for name, bit in flags.items()
        ):
            raise ValueError("preflight volume and mount flags disagree")
    denied = {}
    for path in root.DENIAL_NODES:
        node = nodes[path]
        denied[path] = (
            None
            if node is None
            else {key: node[key] for key in ("device", "inode", "mode")}
        )
        if node is not None and path == "/dev/ptmx" and stat.S_ISLNK(node["mode"]):
            denied[path].update(target=node["target"], blocked_by="/dev/pts")
    link, stage = nodes["/run/host/os-release"], nodes[root.OS_RELEASE_STAGE]
    release = nodes[root.OS_RELEASE_STAGE + "/os-release"]
    os_release = (
        None
        if link is None
        else {
            "link_target": link["target"],
            "stage_mode": None if stage is None else stage["mode"],
            "file_mode": None if release is None else release["mode"],
        }
    )
    row = {
        "root": {key: nodes["/"][key] for key in ("device", "inode")},
        "namespaces": dict(proc["namespaces"]),
        "uid_map": proc["uid_map"],
        "gid_map": proc["gid_map"],
        "status": snapshot["status_after"],
        "fds": proc["fds"],
        "denied": denied,
        "dev_log": None,
        "mountinfo": proc["mountinfo"],
        "tmpfs": {
            path: {
                **{key: nodes[path][key] for key in ("device", "inode", "mode")},
                "bytes": volumes[path]["bytes"],
            }
            for path in ("/run", "/tmp")
        },
        "run_entries": tuple(
            sorted(
                path.rstrip("/") + "/" + name
                for path, names in snapshot["entries"].items()
                if path.startswith("/run") and names is not None
                for name in names
            )
        ),
        "os_release": os_release,
        "started_ns": snapshot["started_ns"],
        "finished_ns": snapshot["finished_ns"],
    }
    root.check_core(plan, row, deadline, now)
    return row
