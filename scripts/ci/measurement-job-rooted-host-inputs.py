#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Retained input owners for H's inert startup check, never VM admission."""

import hashlib
import os
import stat
import types
from builtins import BaseExceptionGroup
from typing import NamedTuple

CLEANUP_FAILURES = (BaseException,)


class Selection(NamedTuple):
    spec: object
    runtime: str
    manifest: str
    manifest_sha256: str
    base_sha256: str
    payload_sha256: str


class PreparedInputs:
    """Own every acquired descriptor until closed; preserve preparation baselines."""

    def __init__(self, selection, root, deadline):
        self.selection, self.root, self.deadline = selection, root, deadline
        self.files = {}
        self.runtime = None
        self.manifest = None
        self.closed = False

    @classmethod
    def open(cls, selection, root, *, deadline):
        if type(selection) is not Selection or type(root) is not types.ModuleType:
            raise ValueError("host input selection or dependencies")
        root.guardian.validate_spec(selection.spec)
        if selection.spec.mode != "boot-only" or selection.spec.cases != (
            "supervisor-only",
        ):
            raise ValueError("host input selection must be startup-only")
        paths = (
            selection.runtime,
            selection.manifest,
            selection.spec.base,
            selection.spec.payload,
        )
        for index, path in enumerate(paths):
            root.absolute_path(path)
            if any(
                root.nested(path, other) or root.nested(other, path)
                for other in paths[index + 1 :]
            ):
                raise ValueError("overlapping host input paths")
        owner = cls(selection, root, deadline)
        inputs = root.closure.inputs
        try:
            for name, path, digest, limit in (
                (
                    "manifest",
                    selection.manifest,
                    selection.manifest_sha256,
                    root.closure.MAX_MANIFEST,
                ),
                ("base", selection.spec.base, selection.base_sha256, 1024**2),
                ("payload", selection.spec.payload, selection.payload_sha256, 1024**2),
            ):
                owner.files[name] = inputs.FrozenInput.open(
                    path, digest, limit=limit, deadline=deadline
                )
            manifest = owner.files["manifest"]
            if manifest.info.st_mode != stat.S_IFREG | 0o400 or (
                manifest.info.st_uid,
                manifest.info.st_gid,
            ) != (os.getuid(), os.getgid()):
                raise ValueError("host manifest ownership or mode")
            data = bytearray()
            while len(data) < manifest.info.st_size:
                inputs.before(deadline)
                part = os.pread(
                    manifest.fd,
                    min(65536, manifest.info.st_size - len(data)),
                    len(data),
                )
                if not part:
                    raise ValueError("short host manifest read")
                data.extend(part)
            if hashlib.sha256(data).hexdigest() != selection.manifest_sha256:
                raise ValueError("host manifest read digest")
            manifest.check()
            owner.manifest = bytes(data)
            owner.runtime = root.closure.RuntimeSnapshot.open(
                selection.runtime,
                owner.manifest,
                selection.manifest_sha256,
                deadline=deadline,
            )
            owner.recheck(deadline)
            return owner
        except BaseException as error:
            try:
                owner.close()
            except CLEANUP_FAILURES as cleanup:
                raise BaseExceptionGroup(
                    "host input acquisition and cleanup", [error, cleanup]
                ) from error
            raise

    def recheck(self, deadline):
        if (
            self.closed
            or self.runtime is None
            or set(self.files) != {"manifest", "base", "payload"}
        ):
            raise ValueError("host input ownership incomplete or closed")
        for owner in self.files.values():
            owner.recheck(deadline)
        self.runtime.recheck(deadline)
        # Runtime hashing can outlast an earlier file read; verify its identity again.
        for owner in self.files.values():
            owner._check_at(deadline)

    def identities(self):
        if self.closed or self.runtime is None:
            raise ValueError("host input ownership closed")
        result = {}
        for name, owner in self.files.items():
            result[name] = {
                "path": str(owner.path),
                "device": owner.info.st_dev,
                "inode": owner.info.st_ino,
            }
        info = self.runtime.root_info
        result["root"] = {
            "path": str(self.runtime.root),
            "device": info.st_dev,
            "inode": info.st_ino,
        }
        result["manifest"]["sha256"] = self.selection.manifest_sha256
        return result

    def close(self):
        self.closed = True
        errors = []
        for owner in (self.runtime, *reversed(tuple(self.files.values()))):
            if owner is not None:
                try:
                    owner.close()
                except CLEANUP_FAILURES as error:
                    errors.append(error)
        if errors:
            raise BaseExceptionGroup("host input descriptor cleanup", errors)


if __name__ == "__main__":
    raise SystemExit(77)
