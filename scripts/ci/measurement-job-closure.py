#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Finite runtime-tree metadata. This module does not launch a prepared runtime."""

import contextlib
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import stat
from builtins import BaseExceptionGroup
from pathlib import Path, PurePosixPath
from types import MappingProxyType

MAX_MANIFEST = 2 * 1024 * 1024
MAX_MEMBERS = 8192
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
FLAGS = ["-I", "-S", "-B", "-X", "pycache_prefix=/dev/null"]
PLATFORM = {"os": "linux", "machine": "x86_64", "bits": 64, "byte_order": "little"}
ENVIRONMENT = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
CLEANUP_ERRORS = (BaseException,)


class SourceLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        return self.source_to_code(self.get_data(self.path), self.path)


def load(name, filename):
    loader = SourceLoader(name, str(Path(__file__).with_name(filename)))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


elf = load("closure_elf", "measurement-job-elf.py")
runtime = load("closure_json", "measurement-job-runtime.py")
inputs = load("closure_inputs", "measurement-job-inputs.py")


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def relative_path(value):
    if (
        type(value) is not str
        or not 1 <= len(value) <= 1024
        or any(not 32 <= ord(char) <= 126 for char in value)
        or value.startswith("/")
        or value.endswith("/")
        or len(value.split("/")) > 32
        or any(
            not part or part in (".", "..") or len(part) > 255
            for part in value.split("/")
        )
    ):
        raise ValueError("runtime member path")
    path = PurePosixPath(value)
    if (
        any(
            part in ("__pycache__", "site-packages", "glibc-hwcaps")
            for part in path.parts
        )
        or value.lower().endswith((".pyc", ".zip", ".pth"))
        or value in ("etc/ld.so.cache", "etc/ld.so.preload", "etc/ld.so.conf")
        or value.startswith("etc/ld.so.conf.d/")
        or value == "etc/ld.so.conf.d"
        or (path.parts[0] == "lib64" and len(path.parts) > 2)
    ):
        raise ValueError("unsupported runtime lookup path")
    return value


def check_manifest(value):
    runtime._fields(
        value,
        (
            "scope",
            "platform",
            "python",
            "native",
            "environment",
            "bootstrap",
            "members",
        ),
    )
    if (
        value["scope"] != "contained-job-runtime-tree-v1"
        or value["platform"] != PLATFORM
        or value["environment"] != ENVIRONMENT
    ):
        raise ValueError("runtime platform, scope or environment")
    python = value["python"]
    runtime._fields(
        python, ("implementation", "version", "executable", "entry", "roots", "flags")
    )
    if python["implementation"] != "cpython" or python["flags"] != FLAGS:
        raise ValueError("runtime Python policy")
    if type(python["version"]) is not list or len(python["version"]) != 3:
        raise ValueError("runtime Python version")
    for number in python["version"]:
        runtime._integer(number, 0, 65535)
    if type(python["roots"]) is not list or not 1 <= len(python["roots"]) <= 4:
        raise ValueError("runtime Python roots")
    roots = [relative_path(path) for path in python["roots"]]
    if len(set(roots)) != len(roots):
        raise ValueError("duplicate Python root")
    if value["native"] != {
        "interpreter": "lib64/ld-linux-x86-64.so.2",
        "library_dir": "lib64",
    }:
        raise ValueError("runtime native lookup policy")
    members = value["members"]
    if type(members) is not list or not 1 <= len(members) <= MAX_MEMBERS:
        raise ValueError("runtime member count")
    by_path, total, previous = {}, 0, ""
    for row in members:
        if type(row) is not dict or row.get("kind") not in ("file", "directory"):
            raise ValueError("runtime member kind")
        runtime._fields(
            row,
            ("path", "kind", "mode", "size", "sha256")
            if row["kind"] == "file"
            else ("path", "kind", "mode"),
        )
        path = relative_path(row["path"])
        if path <= previous:
            raise ValueError("runtime members unsorted or duplicate")
        previous = path
        if type(row["mode"]) is not int or row["mode"] not in (
            (0o400, 0o500) if row["kind"] == "file" else (0o500,)
        ):
            raise ValueError("runtime member mode")
        if row["kind"] == "file":
            runtime._integer(row["size"], 0, MAX_FILE)
            total += row["size"]
            if (
                total > MAX_TOTAL
                or type(row["sha256"]) is not str
                or len(row["sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in row["sha256"])
            ):
                raise ValueError("runtime size or digest")
        by_path[path] = row
    for path in by_path:
        parent = str(PurePosixPath(path).parent)
        if parent != "." and (
            parent not in by_path or by_path[parent]["kind"] != "directory"
        ):
            raise ValueError("runtime parent not listed")
    for path in [*roots, "lib64"]:
        if path not in by_path or by_path[path]["kind"] != "directory":
            raise ValueError("runtime search directory missing")
    for path in (
        python["entry"],
        python["executable"],
        value["bootstrap"],
        value["native"]["interpreter"],
    ):
        relative_path(path)
        if path not in by_path or by_path[path]["kind"] != "file":
            raise ValueError("runtime entry missing")
    if not python["entry"].endswith(".py"):
        raise ValueError("runtime entry must be source")
    for path in (
        python["executable"],
        value["bootstrap"],
        value["native"]["interpreter"],
    ):
        if by_path[path]["mode"] != 0o500 or not by_path[path]["size"]:
            raise ValueError("runtime executable mode or size")
    return by_path


def decode_manifest(data, expected):
    if type(data) is not bytes or not 0 < len(data) <= MAX_MANIFEST:
        raise ValueError("runtime manifest byte cap")
    if (
        type(expected) is not str
        or len(expected) != 64
        or any(c not in "0123456789abcdef" for c in expected)
    ):
        raise ValueError("runtime manifest digest")
    value = runtime._json(data)
    check_manifest(value)
    encoded = canonical(value)
    if encoded != data or hashlib.sha256(encoded).hexdigest() != expected:
        raise ValueError("runtime manifest encoding or digest mismatch")
    return value


def verify_linkage(manifest, images):
    members = check_manifest(manifest)
    if set(images) - set(members):
        raise ValueError("unlisted ELF member")
    for path in (
        manifest["bootstrap"],
        manifest["python"]["executable"],
        manifest["native"]["interpreter"],
    ):
        if path not in images:
            raise ValueError("runtime executable is not ELF")
    bootstrap = images[manifest["bootstrap"]]
    if (
        bootstrap["type"] != 2
        or bootstrap["dynamic"]
        or bootstrap["interpreter"] is not None
    ):
        raise ValueError("runtime bootstrap must be static")
    elf.require_dso(images[manifest["native"]["interpreter"]])
    for path, image in images.items():
        parent = str(PurePosixPath(path).parent)
        if parent in (
            "lib",
            "lib32",
            "usr/lib",
            "usr/lib64",
            "usr/local/lib",
            "usr/local/lib64",
        ):
            raise ValueError("alternate native lookup candidate")
        if path.startswith("lib64/"):
            elf.require_dso(image)
    for path, row in members.items():
        if (
            row["kind"] == "file"
            and path.endswith(".so")
            and any(path.startswith(root + "/") for root in manifest["python"]["roots"])
        ):
            if path not in images:
                raise ValueError("Python extension is not ELF")
            elf.require_dso(images[path])
    return elf.link_graph(images)


@contextlib.contextmanager
def owned_fd(fd):
    try:
        yield fd
    except BaseException as error:
        try:
            os.close(fd)
        except CLEANUP_ERRORS as cleanup:
            raise BaseExceptionGroup(
                "runtime operation and descriptor close", [error, cleanup]
            ) from error
        raise
    else:
        os.close(fd)


class RuntimeSnapshot:
    """A retained, checked snapshot, not protection against an existing writer."""

    _api_roots = frozenset()

    def __init__(self, root, deadline):
        self.root, self.deadline = Path(root), deadline
        self.fd = None
        self.observations = None
        self._manifest_data = None
        inputs.before(deadline)
        try:
            with inputs.opened_parent(self.root) as (parent, ancestors):
                self.ancestors = ancestors
                self.fd = os.open(
                    self.root.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent,
                )
            self.root_info = os.fstat(self.fd)
            self._directory(self.root_info)
            inputs.before(deadline)
        except BaseException as error:
            try:
                self.close()
            except CLEANUP_ERRORS as cleanup:
                raise BaseExceptionGroup(
                    "runtime root acquisition and cleanup", [error, cleanup]
                ) from error
            raise

    @staticmethod
    def _directory(info):
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o500
            or info.st_uid not in (0, os.getuid())
        ):
            raise ValueError("runtime directory ownership or mode")

    def _root_check(self):
        self._root_check_at(self.deadline)

    def _root_check_at(self, deadline):
        inputs.before(deadline)
        if self.fd is None or inputs.identity(os.fstat(self.fd)) != inputs.identity(
            self.root_info
        ):
            raise ValueError("runtime root changed or closed")
        with inputs.opened_parent(self.root) as (parent, ancestors):
            current = os.stat(self.root.name, dir_fd=parent, follow_symlinks=False)
            if ancestors != self.ancestors or inputs.identity(
                current
            ) != inputs.identity(self.root_info):
                raise ValueError("runtime root ancestry replaced")
        inputs.before(deadline)

    def scan(self, *, contents):
        return self._scan(contents, self.deadline, self._root_check)

    def _scan(self, contents, deadline, root_check):
        root_check()
        members, images, observations = [], {}, {}
        count = total = 0

        def visit(directory, prefix, depth):
            nonlocal count, total
            inputs.before(deadline)
            if depth > 32:
                raise ValueError("runtime tree depth")
            directory_info = os.fstat(directory)
            self._directory(directory_info)
            observations[prefix] = inputs.identity(directory_info)
            # Use a fresh directory description for each walk; enumeration must
            # not inherit an earlier scandir offset from the retained root FD.
            with (
                owned_fd(
                    os.open(
                        ".",
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                        dir_fd=directory,
                    )
                ) as listing,
                os.scandir(listing) as iterator,
            ):
                names = []
                for entry in iterator:
                    inputs.before(deadline)
                    count += 1
                    if count > MAX_MEMBERS:
                        raise ValueError("runtime member count")
                    names.append(entry.name)
            if not prefix:
                root_names = frozenset(names)
                if not self._api_roots <= root_names:
                    raise ValueError("runtime API root missing")
                for name in sorted(self._api_roots):
                    inputs.before(deadline)
                    if not stat.S_ISDIR(
                        os.stat(name, dir_fd=directory, follow_symlinks=False).st_mode
                    ):
                        raise ValueError("runtime API root is not a directory")
                    inputs.before(deadline)
            for name in sorted(names):
                inputs.before(deadline)
                if not prefix and name in self._api_roots:
                    continue
                path = relative_path(prefix + "/" + name if prefix else name)
                before = os.stat(name, dir_fd=directory, follow_symlinks=False)
                mode = stat.S_IMODE(before.st_mode)
                if stat.S_ISDIR(before.st_mode):
                    with owned_fd(
                        os.open(
                            name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory,
                        )
                    ) as child:
                        if inputs.identity(os.fstat(child)) != inputs.identity(before):
                            raise ValueError("runtime directory replaced during walk")
                        members.append(
                            {"path": path, "kind": "directory", "mode": mode}
                        )
                        visit(child, path, depth + 1)
                    continue
                if (
                    not stat.S_ISREG(before.st_mode)
                    or mode not in (0o400, 0o500)
                    or before.st_uid not in (0, os.getuid())
                    or before.st_nlink != 1
                    or not 0 <= before.st_size <= MAX_FILE
                ):
                    raise ValueError("unsafe runtime member")
                total += before.st_size
                if total > MAX_TOTAL:
                    raise ValueError("runtime total byte limit")
                with owned_fd(
                    os.open(
                        name,
                        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory,
                    )
                ) as file:
                    if inputs.identity(os.fstat(file)) != inputs.identity(before):
                        raise ValueError("runtime member replaced during open")
                    digest = None
                    if contents:
                        sha, remaining = hashlib.sha256(), before.st_size
                        while remaining:
                            inputs.before(deadline)
                            data = os.read(file, min(1024 * 1024, remaining))
                            if not data:
                                raise ValueError("short runtime member")
                            sha.update(data)
                            remaining -= len(data)
                        digest = sha.hexdigest()
                        if os.pread(file, 4, 0) == b"\x7fELF":
                            inputs.before(deadline)
                            data = os.pread(file, before.st_size, 0)
                            if len(data) != before.st_size:
                                raise ValueError("short runtime ELF")
                            images[path] = elf.inspect(data)
                    if inputs.identity(os.fstat(file)) != inputs.identity(before):
                        raise ValueError("runtime member changed during observation")
                observations[path] = inputs.identity(before)
                members.append(
                    {
                        "path": path,
                        "kind": "file",
                        "mode": mode,
                        "size": before.st_size,
                        "sha256": digest,
                    }
                )
            if inputs.identity(os.fstat(directory)) != inputs.identity(directory_info):
                raise ValueError("runtime directory changed during walk")
            inputs.before(deadline)

        visit(self.fd, "", 0)
        members.sort(key=lambda row: row["path"])
        root_check()
        return members, images, observations

    @classmethod
    def open(cls, root, data, expected, *, deadline):
        manifest = decode_manifest(data, expected)
        snapshot = cls(root, deadline)
        try:
            members, images, snapshot.observations = snapshot.scan(contents=True)
            if members != manifest["members"]:
                raise ValueError("runtime tree does not match selected manifest")
            snapshot.graph = MappingProxyType(verify_linkage(manifest, images))
            snapshot._manifest_data = data
            snapshot.check()
            inputs.before(deadline)
            return snapshot
        except BaseException as error:
            try:
                snapshot.close()
            except CLEANUP_ERRORS as cleanup:
                raise BaseExceptionGroup(
                    "runtime verification and cleanup", [error, cleanup]
                ) from error
            raise

    def check(self):
        _, _, current = self.scan(contents=False)
        if self.observations is None or current != self.observations:
            raise ValueError("runtime membership or metadata changed")
        inputs.before(self.deadline)

    def recheck(self, deadline):
        """Rehash a prepared tree for a new phase, keeping all original identities."""
        if (
            type(self) is not RuntimeSnapshot
            or self.observations is None
            or self._manifest_data is None
        ):
            raise ValueError("runtime phase recheck requires a prepared-tree owner")

        def root_check():
            self._root_check_at(deadline)

        members, images, observations = self._scan(True, deadline, root_check)
        manifest = self.manifest
        if observations != self.observations or members != manifest["members"]:
            raise ValueError("runtime phase content or identity changed")
        verify_linkage(manifest, images)
        # A member hashed early can change during a later read or linkage check.
        _, _, current = self._scan(False, deadline, root_check)
        if current != self.observations:
            raise ValueError("runtime phase membership or metadata changed")
        inputs.before(deadline)

    @property
    def manifest(self):
        if self._manifest_data is None:
            raise ValueError("runtime snapshot has no selected manifest")
        return runtime._json(self._manifest_data)

    def close(self):
        fd, self.fd = self.fd, None
        if fd is not None:
            os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, kind, error, trace):
        try:
            self.close()
        except CLEANUP_ERRORS as cleanup:
            if error is not None:
                raise BaseExceptionGroup(
                    "runtime use and cleanup", [error, cleanup]
                ) from error
            raise


def prepare_manifest(root, profile, *, deadline):
    """Trusted preparation only. Runtime admission must use an expected manifest."""
    runtime._fields(
        profile, ("scope", "platform", "python", "native", "environment", "bootstrap")
    )
    with RuntimeSnapshot(root, deadline) as snapshot:
        members, images, snapshot.observations = snapshot.scan(contents=True)
        value = dict(profile, members=members)
        check_manifest(value)
        verify_linkage(value, images)
        snapshot.check()
        data = canonical(value)
        if len(data) > MAX_MANIFEST:
            raise ValueError("runtime manifest byte cap")
    digest = hashlib.sha256(data).hexdigest()
    inputs.before(deadline)
    return data, digest


if __name__ == "__main__":
    raise SystemExit(77)
