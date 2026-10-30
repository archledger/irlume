#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Compose fixed startup checks. No native admission or child creation."""

import copy
import importlib.machinery
import os
import re
import sys
import types
from typing import NamedTuple


class ModuleSnapshot(NamedTuple):
    table: dict
    bindings: tuple
    locals: tuple
    loaders: tuple
    edges: tuple


def _binding(name, module):
    if (
        type(name) is not str
        or not 1 <= len(name) <= 255
        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name)
        is None
        or type(module) is not types.ModuleType
    ):
        raise ValueError("invalid startup module binding")
    attrs = module.__dict__
    spec = attrs.get("__spec__")
    if spec is not None and type(spec) is not importlib.machinery.ModuleSpec:
        raise ValueError("invalid startup module spec")
    loader = attrs.get("__loader__")
    spec_loader = None if spec is None else spec.__dict__.get("loader")
    return name, module, spec, loader, spec_loader


def module_snapshot(roots, table, check_time):
    """Retain identities, not just descriptive module metadata."""
    if (
        type(roots) is not tuple
        or not 1 <= len(roots) <= 16
        or any(type(root) is not types.ModuleType for root in roots)
    ):
        raise ValueError("invalid startup module roots")
    if type(table) is not dict or len(table) > 4096:
        raise ValueError("startup module table cap")
    check_time()
    bindings = []
    for name, module in tuple(table.items()):
        check_time()
        bindings.append(_binding(name, module))
    bindings.sort(key=lambda row: row[0])
    global_ids = {id(row[1]) for row in bindings}
    root_ids = {id(root) for root in roots}
    queue, queued, seen = list(roots), set(root_ids), set()
    local, loaders, loader_ids, edges = [], [], set(), []
    while queue:
        check_time()
        module = queue.pop(0)
        if id(module) in seen:
            continue
        seen.add(id(module))
        attrs = module.__dict__
        if len(attrs) > 4096 or any(
            type(name) is not str or len(name) > 255 for name in attrs
        ):
            raise ValueError("startup module attribute cap")
        if id(module) not in global_ids:
            if len(local) >= 128:
                raise ValueError("startup local module cap")
            name = f"irlume_local_{len(local):03}"
            if name in table:
                raise ValueError("startup local module name collision")
            local.append(_binding(name, module))
        kind = attrs.get("SourceLoader")
        if kind is not None:
            if type(kind) is not type or not issubclass(
                kind, importlib.machinery.SourceFileLoader
            ):
                raise ValueError("unreviewed startup source loader class")
            if id(kind) not in loader_ids:
                loader_ids.add(id(kind))
                loaders.append(kind)
                if len(loaders) > 16:
                    raise ValueError("startup source loader class cap")
        for name in sorted(attrs):
            check_time()
            value = attrs[name]
            if type(value) is types.ModuleType:
                edges.append((module, name, value))
                if len(edges) > 4096:
                    raise ValueError("startup module edge cap")
            if (
                type(value) is not types.ModuleType
                or id(value) in queued
                or id(value) in global_ids
                and id(value) not in root_ids
            ):
                continue
            queued.add(id(value))
            if len(queued) > 128 + len(roots):
                raise ValueError("startup module graph cap")
            queue.append(value)
    check_time()
    return ModuleSnapshot(
        table, tuple(bindings), tuple(local), tuple(loaders), tuple(edges)
    )


def same_modules(before, after):
    if (
        type(before) is not ModuleSnapshot
        or type(after) is not ModuleSnapshot
        or before.table is not after.table
    ):
        return False
    for left, right in (
        (before.bindings, after.bindings),
        (before.locals, after.locals),
    ):
        if len(left) != len(right):
            return False
        for a, b in zip(left, right):
            if a[0] != b[0] or any(x is not y for x, y in zip(a[1:], b[1:])):
                return False
    if len(before.edges) != len(after.edges) or any(
        a[0] is not b[0] or a[1] != b[1] or a[2] is not b[2]
        for a, b in zip(before.edges, after.edges)
    ):
        return False
    return len(before.loaders) == len(after.loaders) and all(
        a is b for a, b in zip(before.loaders, after.loaders)
    )


class Dependencies(NamedTuple):
    preflight: types.ModuleType
    runtime_tree: types.ModuleType
    runtime_state: types.ModuleType
    python_state: types.ModuleType


class Startup(NamedTuple):
    """One startup observation and the page digests of the tree it checked."""

    observation: dict
    pages: object


def collect_startup(
    plan,
    manifest_data,
    dependencies,
    module_roots,
    deadline,
    *,
    _module_table=None,
):
    """Compose one startup observation. Returned data is not execution authority.

    Dependencies and module roots are trusted Python objects from the pinned
    entry, never values decoded from a request. All temporary FDs close before
    the final inventory. A later layer owns bounded persistence and READY.
    """
    if type(dependencies) is not Dependencies or any(
        type(module) is not types.ModuleType for module in dependencies
    ):
        raise ValueError("invalid startup dependency modules")
    if type(module_roots) is not tuple or not 1 <= len(module_roots) <= 12:
        raise ValueError("invalid startup module roots")
    dependencies.preflight.root.check_plan(plan)
    if type(manifest_data) is not bytes:
        raise ValueError("invalid startup manifest bytes")
    plan = copy.deepcopy(plan)
    table = (lambda: sys.modules) if _module_table is None else _module_table
    reader = dependencies.preflight.filesystem.FilesystemCollector(deadline)
    roots = (*module_roots, *dependencies)

    def capture():
        return module_snapshot(roots, table(), reader._after)

    def python_state(snapshot):
        return dependencies.python_state.collect_python_state(
            reader.deadline,
            local_modules=tuple((row[0], row[1]) for row in snapshot.locals),
            source_loader_types=snapshot.loaders,
        )

    def fresh_process(core, files, mounts):
        with reader._open(f"/proc/{os.getpid()}", directory=True) as fd:
            maps = reader._read(
                fd, "maps", dependencies.preflight.filesystem.startup.LIMITS["maps"]
            )
            # The checker's own parser picks the mappings whose pages to read.
            _, readable = dependencies.runtime_state.file_mappings(maps, files, mounts)
            mapped = reader._mapped(
                fd, tuple((mapping.start, mapping.end) for mapping in readable)
            )
            status = reader._read(
                fd, "status", dependencies.preflight.filesystem.startup.LIMITS["status"]
            )
            dependencies.preflight.root.check_status(status, plan["uid"], plan["gid"])
            if reader._namespaces(fd) != core["namespaces"]:
                raise ValueError("startup namespaces changed")
        return maps, mapped, status

    initial = reader.collect(plan)
    first_core = dependencies.preflight.core_witness(
        plan, initial, reader.deadline, reader._after()
    )
    # The mount table the core witness checked; reobserve refuses any change.
    mounts = dependencies.preflight.root.parse_mountinfo(first_core["mountinfo"])
    with dependencies.runtime_tree.RootedRuntimeSnapshot.open(
        plan, manifest_data, first_core, deadline=reader.deadline
    ) as tree:
        files, manifest, pages = tree.file_facts(), tree.manifest, tree.pages
        first_modules = capture()
        first_python = python_state(first_modules)
        if not same_modules(first_modules, capture()):
            raise ValueError("startup module identities changed")
        first_maps, first_mapped, _ = fresh_process(first_core, files, mounts)
        dependencies.runtime_state.check_runtime_state(
            manifest, files, first_python, first_maps, mounts, first_mapped, pages
        )
        last_modules = capture()
        if not same_modules(first_modules, last_modules):
            raise ValueError("startup module identities changed")
        last_python = python_state(last_modules)
        if not same_modules(first_modules, capture()) or first_python != last_python:
            raise ValueError("startup Python state changed")
        maps, mapped, _ = fresh_process(first_core, files, mounts)
        dependencies.runtime_state.check_runtime_state(
            manifest, files, last_python, maps, mounts, mapped, pages
        )
        tree.check()
    # The root snapshot FD must be closed before reobserving the complete table.
    final = reader.reobserve()
    final_core = dependencies.preflight.core_witness(
        plan, final, reader.deadline, reader._after()
    )
    if not same_modules(first_modules, capture()):
        raise ValueError("startup module identities changed")
    status = final["status_after"]
    dependencies.preflight.root.check_status(status, plan["uid"], plan["gid"])
    info = reader._call(os.stat, "/", follow_symlinks=False)
    if (info.st_dev, info.st_ino) != (
        final_core["root"]["device"],
        final_core["root"]["inode"],
    ):
        raise ValueError("startup root changed")
    if (
        reader._inventory() != initial["proc"]["fds"]
        or reader._stdio() != initial["proc"]["stdio"]
    ):
        raise ValueError("startup descriptors changed")
    observation = {
        "initial_filesystem": initial,
        "filesystem": final,
        "core": final_core,
        "runtime_manifest_sha256": plan["manifest"]["sha256"],
        "files": files,
        "python": last_python,
        "maps": maps,
        "mapped": mapped,
        "status": status,
        "started_ns": reader.started,
        "finished_ns": reader._after(),
    }
    return Startup(observation, pages)
