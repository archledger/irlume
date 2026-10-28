#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Hash the selected mounted runtime. This produces no execution authority."""

import importlib.machinery
import importlib.util
import os
import time
from builtins import BaseExceptionGroup
from pathlib import Path
from types import MappingProxyType


class SourceLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        return self.source_to_code(self.get_data(self.path), self.path)


loader = SourceLoader(
    "mounted_root", str(Path(__file__).with_name("measurement-job-root.py"))
)
spec = importlib.util.spec_from_loader(loader.name, loader)
root = importlib.util.module_from_spec(spec)
loader.exec_module(root)
closure = root.closure
CLEANUP_ERRORS = (BaseException,)


class RootedRuntimeSnapshot(closure.RuntimeSnapshot):
    """A fixed-root snapshot; API mount validation belongs to the core witness."""

    _api_roots = frozenset(("dev", "proc", "sys", "run", "tmp"))

    def __init__(self, plan, core, deadline):
        root.check_plan(plan)
        root.check_core(plan, core, deadline, time.monotonic_ns())
        self.root = Path("/")
        self.deadline = min(deadline, core["started_ns"] + root.guardian.STOP_NS)
        self.fd = None
        self.observations = None
        self._manifest_data = None
        try:
            closure.inputs.before(self.deadline)
            self.fd = os.open(
                "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            self.root_info = os.fstat(self.fd)
            self._directory(self.root_info)
            actual = self.root_info.st_dev, self.root_info.st_ino
            if actual != (plan["root"]["device"], plan["root"]["inode"]) or actual != (
                core["root"]["device"],
                core["root"]["inode"],
            ):
                raise ValueError("mounted runtime root identity")
            closure.inputs.before(self.deadline)
        except BaseException as error:
            try:
                self.close()
            except CLEANUP_ERRORS as cleanup:
                raise BaseExceptionGroup(
                    "mounted runtime acquisition and cleanup", [error, cleanup]
                ) from error
            raise

    def _root_check(self):
        closure.inputs.before(self.deadline)
        if (
            self.fd is None
            or closure.inputs.identity(os.fstat(self.fd))
            != closure.inputs.identity(self.root_info)
            or closure.inputs.identity(os.stat("/", follow_symlinks=False))
            != closure.inputs.identity(self.root_info)
        ):
            raise ValueError("mounted runtime root changed or closed")
        closure.inputs.before(self.deadline)

    @classmethod
    def open(cls, plan, data, core, *, deadline):
        manifest = root.check_selection(plan, data)
        snapshot = cls(plan, core, deadline)
        try:
            members, images, snapshot.observations = snapshot.scan(contents=True)
            if members != manifest["members"]:
                raise ValueError("mounted runtime manifest mismatch")
            snapshot.graph = MappingProxyType(closure.verify_linkage(manifest, images))
            snapshot._manifest_data = data
            snapshot.check()
            closure.inputs.before(snapshot.deadline)
            return snapshot
        except BaseException as error:
            try:
                snapshot.close()
            except CLEANUP_ERRORS as cleanup:
                raise BaseExceptionGroup(
                    "mounted runtime verification and cleanup", [error, cleanup]
                ) from error
            raise

    def file_facts(self):
        self.check()
        result = {
            "/" + member["path"]: {
                "device": self.observations[member["path"]][0],
                "inode": self.observations[member["path"]][1],
                "mode": self.observations[member["path"]][2],
                "size": self.observations[member["path"]][6],
                "sha256": member["sha256"],
            }
            for member in self.manifest["members"]
            if member["kind"] == "file"
        }
        closure.inputs.before(self.deadline)
        return result
