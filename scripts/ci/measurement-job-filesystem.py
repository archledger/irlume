#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Fixed-root identity observations. No device data I/O or runtime admission."""

import contextlib
import copy
import importlib.machinery
import importlib.util
import os
import stat
from pathlib import Path


class SourceLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        return self.source_to_code(self.get_data(self.path), self.path)


def load(name, filename):
    loader = SourceLoader(name, str(Path(__file__).with_name(filename)))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


root = load("filesystem_root", "measurement-job-root.py")
startup = load("filesystem_startup", "measurement-job-startup.py")
DEVICES = {
    "null": (1, 3),
    "zero": (1, 5),
    "full": (1, 7),
    "random": (1, 8),
    "urandom": (1, 9),
    "tty": (5, 0),
}
# A private /dev links every cloned character node as /dev/char/MAJ:MIN ->
# ../NAME (systemd v255 to v259 src/core/namespace.c, clone_device_node);
# ptmx is cloned too, then made inaccessible.
CHAR_LINKS = {
    f"{major}:{minor}": name
    for name, (major, minor) in {**DEVICES, "ptmx": (5, 2)}.items()
}
DEV_LINKS = {
    "fd": "/proc/self/fd",
    "stdin": "/proc/self/fd/0",
    "stdout": "/proc/self/fd/1",
    "stderr": "/proc/self/fd/2",
    "core": "/proc/kcore",
}


def metadata(info):
    return {
        name: getattr(info, field)
        for name, field in (
            ("device", "st_dev"),
            ("inode", "st_ino"),
            ("mode", "st_mode"),
            ("uid", "st_uid"),
            ("gid", "st_gid"),
            ("links", "st_nlink"),
            ("size", "st_size"),
            ("mtime_ns", "st_mtime_ns"),
            ("ctime_ns", "st_ctime_ns"),
            ("rdev", "st_rdev"),
        )
    }


class RootTree:
    """Retain every traversed node and recheck its name in its retained parent."""

    def __init__(self, reader, fd):
        self.reader = reader
        self.stack = contextlib.ExitStack()
        self.handles = {"/": fd}
        self.nodes = {"/": metadata(reader._call(os.fstat, fd))}
        self.edges = {}
        self.entry_count = 0

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        return self.stack.__exit__(*exception)

    def node(self, path):
        if path == "/":
            return self.nodes[path]
        root.absolute_path(path)
        parent = "/"
        parts = path[1:].split("/")
        for index, name in enumerate(parts):
            current = parent.rstrip("/") + "/" + name
            if current not in self.handles:
                parent_fd = self.handles[parent]
                if parent_fd is None:
                    self.handles[current], self.nodes[current] = None, None
                else:
                    try:
                        fd = self.stack.enter_context(
                            self.reader._open(
                                name,
                                dir_fd=parent_fd,
                                directory=index < len(parts) - 1,
                                path_only=True,
                            )
                        )
                    except FileNotFoundError:
                        fd = None
                    self.edges[current] = (parent_fd, name)
                    self.handles[current] = fd
                    self.nodes[current] = (
                        None
                        if fd is None
                        else metadata(self.reader._call(os.fstat, fd))
                    )
                    if fd is not None and stat.S_ISLNK(self.nodes[current]["mode"]):
                        self.nodes[current]["target"] = self.reader._call(
                            os.readlink, "", dir_fd=fd
                        )
            node = self.nodes[current]
            if (
                index < len(parts) - 1
                and node is not None
                and not stat.S_ISDIR(node["mode"])
            ):
                raise ValueError("filesystem ancestor is not a directory")
            parent = current
        return self.nodes[path]

    def volume(self, path):
        if self.node(path) is None:
            raise ValueError("missing filesystem volume")
        row = self.reader._call(os.fstatvfs, self.handles[path])
        return {"flags": row.f_flag, "bytes": row.f_frsize * row.f_blocks}

    def entries(self, path):
        node = self.node(path)
        if node is None:
            return None
        if not stat.S_ISDIR(node["mode"]):
            raise ValueError("filesystem scan target is not a directory")
        names = set()
        with self.reader._open(".", dir_fd=self.handles[path], directory=True) as fd:
            if metadata(self.reader._call(os.fstat, fd)) != node:
                raise ValueError("filesystem scan directory changed")
            self.reader._before()
            iterator = os.scandir(fd)
            with self.reader._closing(iterator.close):
                self.reader._after()
                while True:
                    self.reader._before()
                    try:
                        entry = next(iterator)
                    except StopIteration:
                        self.reader._after()
                        break
                    self.reader._after()
                    name = entry.name
                    self.entry_count += 1
                    if (
                        self.entry_count > 128
                        or type(name) is not str
                        or not 1 <= len(name) <= 255
                        or name in names
                        or name in (".", "..")
                        or "/" in name
                        or any(not 32 <= ord(c) <= 126 for c in name)
                    ):
                        raise ValueError("filesystem directory entry cap or name")
                    names.add(name)
        return tuple(sorted(names))

    def recheck(self):
        for path, (parent, name) in self.edges.items():
            try:
                current = metadata(
                    self.reader._call(
                        os.stat, name, dir_fd=parent, follow_symlinks=False
                    )
                )
            except FileNotFoundError:
                current = None
            expected = self.nodes[path]
            if current != (
                None
                if expected is None
                else {k: v for k, v in expected.items() if k != "target"}
            ):
                raise ValueError("filesystem directory entry replaced")
            fd = self.handles[path]
            if fd is not None and metadata(self.reader._call(os.fstat, fd)) != current:
                raise ValueError("filesystem retained node changed")


def selected_identity(node, selected):
    return node is not None and (node["device"], node["inode"]) == (
        selected["device"],
        selected["inode"],
    )


def directory_policy(plan):
    uid = str(plan["uid"])
    return {
        "/dev": set(DEVICES)
        | set(DEV_LINKS)
        | {"pts", "ptmx", "shm", "mqueue", "hugepages", "char"},
        "/dev/char": set(CHAR_LINKS),
        "/run": {"irlume", "user", "host", "credentials"},
        "/run/irlume": {"attempt", "base.raw", "payload.raw", "runtime-manifest.json"},
        "/run/user": {uid},
        "/run/user/" + uid: {"bus"},
        "/run/host": {".os-release-stage", "os-release"},
        root.OS_RELEASE_STAGE: {"os-release"},
        "/tmp": set(),
    }


def check_roles(plan, bus_identity, nodes, entries):
    for path, names in entries.items():
        if names is None:
            if path not in ("/run/host", root.OS_RELEASE_STAGE, "/dev/char"):
                raise ValueError("missing filesystem structural directory")
        elif not set(names) <= directory_policy(plan)[path]:
            raise ValueError("unexpected filesystem directory entry")
    for path, node in nodes.items():
        if path == "/":
            continue
        parent, _, name = path.rpartition("/")
        if (
            parent in entries
            and entries[parent] is not None
            and ((name in entries[parent]) != (node is not None))
        ):
            raise ValueError("filesystem inventory and node disagree")
    for key, path in (
        ("attempt", root.ATTEMPT),
        ("base", "/run/irlume/base.raw"),
        ("payload", "/run/irlume/payload.raw"),
        ("manifest", "/run/irlume/runtime-manifest.json"),
    ):
        node = nodes[path]
        if not selected_identity(node, plan[key]):
            raise ValueError("selected filesystem identity mismatch")
        if key == "attempt":
            if node["mode"] != stat.S_IFDIR | 0o700 or node["uid"] != plan["uid"]:
                raise ValueError("selected attempt is not private")
        elif (
            not stat.S_ISREG(node["mode"])
            or node["mode"] & 0o222
            or node["links"] != 1
            or node["size"] <= 0
        ):
            raise ValueError("selected input is not a frozen regular file")
    bus = nodes[f"/run/user/{plan['uid']}/bus"]
    if (
        not selected_identity(bus, bus_identity)
        or not stat.S_ISSOCK(bus["mode"])
        or bus["uid"] != plan["uid"]
    ):
        raise ValueError("selected user bus identity or type")
    for name, device in DEVICES.items():
        node = nodes["/dev/" + name]
        if (
            node is None
            or not stat.S_ISCHR(node["mode"])
            or node["rdev"] != os.makedev(*device)
        ):
            raise ValueError("unexpected minimal device node")
    for number, name in CHAR_LINKS.items():
        node = nodes["/dev/char/" + number]
        if node is not None and (
            not stat.S_ISLNK(node["mode"]) or node.get("target") != "../" + name
        ):
            raise ValueError("unexpected device number link")
    for name, target in DEV_LINKS.items():
        node = nodes["/dev/" + name]
        if node is None and name == "core":
            continue
        if (
            node is None
            or not stat.S_ISLNK(node["mode"])
            or node.get("target") != target
        ):
            raise ValueError("unexpected minimal device symlink")
    for path in root.DENIAL_NODES:
        node = nodes[path]
        if node is None:
            continue
        if path == "/dev/ptmx" and stat.S_ISLNK(node["mode"]):
            pts = nodes["/dev/pts"]
            if (
                node["target"] != "pts/ptmx"
                or pts is None
                or pts["mode"] != stat.S_IFDIR
            ):
                raise ValueError("ptmx is not behind an inaccessible pts directory")
        elif node["mode"] not in (
            stat.S_IFDIR,
            stat.S_IFREG,
            stat.S_IFCHR,
            stat.S_IFBLK,
            stat.S_IFIFO,
            stat.S_IFSOCK,
        ):
            raise ValueError("filesystem denial is accessible")
        if selected_identity(
            node, plan["host_api"].get(path) or {"device": -1, "inode": -1}
        ):
            raise ValueError("filesystem denial is host-backed")
    link = nodes["/run/host/os-release"]
    stage = nodes[root.OS_RELEASE_STAGE]
    release = nodes[root.OS_RELEASE_STAGE + "/os-release"]
    if link is not None and (
        not stat.S_ISLNK(link["mode"])
        or link.get("target") != ".os-release-stage/os-release"
    ):
        raise ValueError("filesystem os-release symlink")
    if stage is not None and (
        link is None
        or release is None
        or not stat.S_ISDIR(stage["mode"])
        or not stat.S_ISREG(release["mode"])
        or release["mode"] & 0o7111
    ):
        raise ValueError("filesystem os-release staging")


def target_paths(plan):
    """The finite node selection shared by collection and witness validation."""
    return (
        "/run",
        "/tmp",
        root.ATTEMPT,
        "/run/irlume/base.raw",
        "/run/irlume/payload.raw",
        "/run/irlume/runtime-manifest.json",
        f"/run/user/{plan['uid']}/bus",
        *root.DENIAL_NODES,
        *("/dev/" + name for name in DEVICES),
        *("/dev/" + name for name in DEV_LINKS),
        *("/dev/char/" + number for number in CHAR_LINKS),
        "/run/host/os-release",
        root.OS_RELEASE_STAGE,
        root.OS_RELEASE_STAGE + "/os-release",
    )


class FilesystemCollector(startup.ProcCollector):
    """Collect fixed identities after the proc phase, without restarting its clock."""

    def collect(self, plan, bus_identity):
        root.check_plan(plan)
        root.identity(bus_identity)
        process = super().collect()
        result = self._observe_filesystem(plan, bus_identity, process)
        self._final_selection = copy.deepcopy((plan, bus_identity, process))
        self._final_observed = False
        return result

    def reobserve(self):
        """One final view under the original selection, clock and operation budget."""
        if not hasattr(self, "_final_selection") or self._final_observed:
            raise ValueError("filesystem final observation is unavailable")
        self._final_observed = True
        self._after()
        plan, bus_identity, process = copy.deepcopy(self._final_selection)
        return self._observe_filesystem(plan, bus_identity, process)

    def _observe_filesystem(self, plan, bus_identity, process):
        self.filesystem_partial = {"nodes": {}, "entries": {}}
        with (
            self._open("/", directory=True, path_only=True) as root_fd,
            RootTree(self, root_fd) as tree,
        ):
            if not selected_identity(
                tree.nodes["/"], plan["root"]
            ) or not selected_identity(tree.nodes["/"], process["root"]):
                raise ValueError("filesystem root does not match process and selection")
            self.filesystem_partial["nodes"] = tree.nodes
            for path in target_paths(plan):
                tree.node(path)
            entries = self.filesystem_partial["entries"]
            for path in directory_policy(plan):
                entries[path] = tree.entries(path)
            volumes = {path: tree.volume(path) for path in ("/", "/run", "/tmp")}
            check_roles(plan, bus_identity, tree.nodes, entries)
            tree.recheck()
            if (
                metadata(self._call(os.stat, "/", follow_symlinks=False))
                != tree.nodes["/"]
            ):
                raise ValueError("filesystem root changed")
            with self._open(f"/proc/{os.getpid()}", directory=True) as proc_fd:
                if (
                    self._namespaces(proc_fd) != process["namespaces"]
                    or self._read(proc_fd, "mountinfo", startup.LIMITS["mountinfo"])
                    != process["mountinfo"]
                ):
                    raise ValueError("filesystem namespace or mounts changed")
                status = self._read(proc_fd, "status", startup.LIMITS["status"])
                self._single_thread(status)
        if self._inventory() != process["fds"] or self._stdio() != process["stdio"]:
            raise ValueError("filesystem standard descriptors changed")
        return {
            "proc": process,
            "nodes": tree.nodes,
            "entries": entries,
            "volumes": volumes,
            "status_after": status,
            "started_ns": self.started,
            "finished_ns": self._after(),
        }
