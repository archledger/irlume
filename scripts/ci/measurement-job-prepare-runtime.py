#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Copy explicitly pinned local inputs into a new runtime, without executing it."""

import contextlib
import hashlib
import importlib.machinery
import importlib.util
import os
import stat
import time
from pathlib import Path, PurePosixPath
from typing import NamedTuple


class SourceLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        return self.source_to_code(self.get_data(self.path), self.path)


loader = SourceLoader(
    "prepare_closure", str(Path(__file__).with_name("measurement-job-closure.py"))
)
spec = importlib.util.spec_from_loader(loader.name, loader)
closure = importlib.util.module_from_spec(spec)
loader.exec_module(closure)
inputs = closure.inputs
PREPARATION_NS = 120_000_000_000
API_ROOTS = frozenset(("dev", "proc", "sys", "run", "tmp"))


class SourceFile(NamedTuple):
    source: str
    path: str
    mode: int
    size: int
    sha256: str


class Selection(NamedTuple):
    files: tuple
    directories: tuple
    manifest: bytes
    digest: str


def absolute_path(value):
    if (
        type(value) is not str
        or not 1 < len(value) <= 4096
        or any(not 32 <= ord(char) <= 126 for char in value)
    ):
        raise ValueError("preparation absolute path")
    path = Path(value)
    if (
        not path.is_absolute()
        or str(path) != value
        or ".." in path.parts
        or value.startswith("//")
    ):
        raise ValueError("preparation noncanonical path")
    return path


def profile_copy(value, budget, depth=0):
    budget[0] += 1
    if budget[0] > 512 or depth > 8:
        raise ValueError("preparation profile cap")
    if (
        type(value) is str
        and len(value) <= 4096
        or type(value) is int
        and 0 <= value <= 2**64 - 1
    ):
        return value
    if type(value) is list and len(value) <= 512:
        return [profile_copy(item, budget, depth + 1) for item in value]
    if (
        type(value) is dict
        and len(value) <= 512
        and all(type(key) is str and len(key) <= 255 for key in value)
    ):
        return {
            key: profile_copy(item, budget, depth + 1) for key, item in value.items()
        }
    raise ValueError("preparation profile value")


def freeze_selection(profile, records):
    """Validate and detach every selection value before filesystem operations."""
    profile = profile_copy(profile, [0])
    closure.runtime._fields(
        profile, ("scope", "platform", "python", "native", "environment", "bootstrap")
    )
    closure.runtime._fields(
        profile["python"],
        ("implementation", "version", "executable", "entry", "roots", "flags"),
    )
    if (
        type(profile["python"]["roots"]) is not list
        or not 1 <= len(profile["python"]["roots"]) <= 4
    ):
        raise ValueError("preparation Python roots")
    if type(records) is not list or not 1 <= len(records) <= closure.MAX_MEMBERS:
        raise ValueError("preparation selection count")
    files, directories, members = [], set(), []
    previous = ""
    for record in records:
        closure.runtime._fields(record, ("source", "path", "mode", "size", "sha256"))
        source = str(absolute_path(record["source"]))
        path = closure.relative_path(record["path"])
        if path <= previous or path.split("/")[0] in API_ROOTS:
            raise ValueError("preparation destination order or API root")
        previous = path
        if type(record["mode"]) is not int or record["mode"] not in (0o400, 0o500):
            raise ValueError("preparation file mode")
        closure.runtime._integer(record["size"], 0, closure.MAX_FILE)
        digest = record["sha256"]
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError("preparation source digest")
        files.append(SourceFile(source, path, record["mode"], record["size"], digest))
        members.append(
            {
                "path": path,
                "kind": "file",
                "mode": record["mode"],
                "size": record["size"],
                "sha256": digest,
            }
        )
        directories.update(
            str(parent) for parent in PurePosixPath(path).parents if str(parent) != "."
        )
    for path in profile["python"]["roots"]:
        closure.relative_path(path)
        if path.split("/")[0] in API_ROOTS:
            raise ValueError("preparation Python API root")
        directories.add(path)
        directories.update(
            str(parent) for parent in PurePosixPath(path).parents if str(parent) != "."
        )
    members.extend(
        {"path": path, "kind": "directory", "mode": 0o500} for path in directories
    )
    manifest = dict(profile, members=sorted(members, key=lambda row: row["path"]))
    closure.check_manifest(manifest)
    data = closure.canonical(manifest)
    if len(data) > closure.MAX_MANIFEST:
        raise ValueError("preparation manifest byte cap")
    return Selection(
        tuple(files),
        tuple(sorted(directories, key=lambda name: (name.count("/"), name))),
        data,
        hashlib.sha256(data).hexdigest(),
    )


@contextlib.contextmanager
def directory_at(root, parts):
    with contextlib.ExitStack() as stack:
        directory = root
        for part in parts:
            directory = stack.enter_context(
                closure.owned_fd(
                    os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory,
                    )
                )
            )
        yield directory


def source_info(fd, row):
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid not in (0, os.getuid())
        or info.st_mode & 0o6022
        or info.st_size != row.size
    ):
        raise ValueError("unsafe preparation source")
    return inputs.identity(info)


@contextlib.contextmanager
def source_view(row, deadline):
    inputs.before(deadline)
    with (
        inputs.opened_parent(Path(row.source)) as (parent, ancestors),
        closure.owned_fd(
            os.open(
                Path(row.source).name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=parent,
            )
        ) as source,
    ):
        identity = source_info(source, row)
        if (
            inputs.identity(
                os.stat(Path(row.source).name, dir_fd=parent, follow_symlinks=False)
            )
            != identity
        ):
            raise ValueError("preparation source replaced before copy")
        yield source, identity, ancestors
        if (
            source_info(source, row) != identity
            or inputs.identity(
                os.stat(Path(row.source).name, dir_fd=parent, follow_symlinks=False)
            )
            != identity
        ):
            raise ValueError("preparation source path changed")
    inputs.before(deadline)


def capture_source(row, deadline):
    with source_view(row, deadline) as (_, identity, ancestors):
        result = identity, ancestors
    return result


def copy_source(root, row, deadline, expected):
    with source_view(row, deadline) as (source, identity, ancestors):
        if (identity, ancestors) != expected:
            raise ValueError("preparation source baseline changed")
        parts = PurePosixPath(row.path).parts
        with (
            directory_at(root, parts[:-1]) as directory,
            closure.owned_fd(
                os.open(
                    parts[-1],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=directory,
                )
            ) as output,
        ):
            digest, remaining = hashlib.sha256(), row.size
            while remaining:
                inputs.before(deadline)
                data = os.read(source, min(1024 * 1024, remaining))
                if not data:
                    raise ValueError("short preparation source")
                digest.update(data)
                remaining -= len(data)
                offset = 0
                while offset < len(data):
                    inputs.before(deadline)
                    count = os.write(output, data[offset:])
                    if count <= 0:
                        raise ValueError("zero preparation write")
                    offset += count
            if source_info(source, row) != identity or digest.hexdigest() != row.sha256:
                raise ValueError("preparation source changed or digest mismatch")
            os.fchmod(output, row.mode)
            os.fsync(output)
            inputs.before(deadline)
    inputs.before(deadline)


def check_sources(files, observations, deadline):
    for row, (identity, ancestors) in zip(files, observations, strict=True):
        inputs.before(deadline)
        with inputs.opened_parent(Path(row.source)) as (parent, current):
            if (
                current != ancestors
                or inputs.identity(
                    os.stat(Path(row.source).name, dir_fd=parent, follow_symlinks=False)
                )
                != identity
            ):
                raise ValueError("preparation source changed after copy")
        inputs.before(deadline)


def prepare_runtime(destination, profile, records, *, deadline):
    """Return verified manifest bytes and digest; retain partial trees on failure."""
    inputs.before(deadline)
    deadline = min(deadline, time.monotonic_ns() + PREPARATION_NS)
    path = absolute_path(destination)
    selection = freeze_selection(profile, records)
    inputs.before(deadline)
    observations = tuple(capture_source(row, deadline) for row in selection.files)
    check_sources(selection.files, observations, deadline)
    with inputs.opened_parent(path) as (parent, ancestors):
        os.mkdir(path.name, 0o700, dir_fd=parent)
        with closure.owned_fd(
            os.open(
                path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
        ) as root:
            root_identity = (os.fstat(root).st_dev, os.fstat(root).st_ino)
            for name in selection.directories:
                inputs.before(deadline)
                parts = PurePosixPath(name).parts
                with directory_at(root, parts[:-1]) as directory:
                    os.mkdir(parts[-1], 0o700, dir_fd=directory)
            for row, baseline in zip(selection.files, observations, strict=True):
                inputs.before(deadline)
                copy_source(root, row, deadline, baseline)
            check_sources(selection.files, observations, deadline)
            for name in reversed(selection.directories):
                inputs.before(deadline)
                with directory_at(root, PurePosixPath(name).parts) as directory:
                    os.fchmod(directory, 0o500)
                    os.fsync(directory)
            os.fchmod(root, 0o500)
            os.fsync(root)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != root_identity:
                raise ValueError("preparation root replaced")
            inputs.before(deadline)
        os.fsync(parent)
    inputs.before(deadline)
    with closure.RuntimeSnapshot.open(
        path, selection.manifest, selection.digest, deadline=deadline
    ):
        check_sources(selection.files, observations, deadline)
    with inputs.opened_parent(path) as (parent, current):
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if current != ancestors or (named.st_dev, named.st_ino) != root_identity:
            raise ValueError("preparation ancestry changed")
    inputs.before(deadline)
    return selection.manifest, selection.digest


if __name__ == "__main__":
    raise SystemExit(77)
