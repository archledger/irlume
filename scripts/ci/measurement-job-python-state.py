#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Explicit live interpreter observation; importing performs no collection."""

import importlib.machinery
import os
import re
import sys
import time
import types

ENVIRONMENT = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
FLAG_NAMES = (
    "isolated",
    "no_site",
    "dont_write_bytecode",
    "ignore_environment",
    "safe_path",
)
FLAGS_TYPE = type(sys.flags)
VERSION_TYPE = type(sys.version_info)


def describe_module(name, module, source_loader_types=()):
    if (
        type(name) is not str
        or len(name) > 255
        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name)
        is None
        or type(module) is not types.ModuleType
    ):
        raise ValueError("unsupported Python module entry")
    attrs = module.__dict__
    spec = attrs.get("__spec__")
    if spec is None:
        if name != "__main__":
            raise ValueError("missing Python module spec")
        loader, origin, package = attrs.get("__loader__"), attrs.get("__file__"), None
        loader_name = "__main__"
    else:
        if type(spec) is not importlib.machinery.ModuleSpec:
            raise ValueError("unsupported Python module spec")
        fields = spec.__dict__
        if fields.get("_initializing", False) is not False:
            raise ValueError("Python import still initializing")
        loader, origin, package = (
            fields.get("loader"),
            fields.get("origin"),
            fields.get("submodule_search_locations"),
        )
        loader_name = fields.get("name")
        if attrs.get("__loader__") is not loader:
            raise ValueError("Python loader instance disagreement")
    if loader is importlib.machinery.BuiltinImporter:
        kind = "builtin"
    elif loader is importlib.machinery.FrozenImporter:
        kind = "frozen"
    elif any(
        type(loader) is allowed
        for allowed in (importlib.machinery.SourceFileLoader, *source_loader_types)
    ):
        kind = "source"
    elif type(loader) is importlib.machinery.ExtensionFileLoader:
        kind = "extension"
    else:
        raise ValueError("unsupported Python loader")
    if type(origin) is not str or not 0 < len(origin) <= 4096:
        raise ValueError("invalid Python origin")
    if kind in ("source", "extension"):
        fields = object.__getattribute__(loader, "__dict__")
        if (
            any(
                type(value) is not str
                for value in (
                    fields.get("name"),
                    fields.get("path"),
                    loader_name,
                    attrs.get("__file__"),
                )
            )
            or fields["name"] != loader_name
            or fields["path"] != origin
            or attrs["__file__"] != origin
        ):
            raise ValueError("Python loader name or path disagreement")
    if package is None:
        paths = ()
        if "__path__" in attrs:
            raise ValueError("unexpected Python package path")
    else:
        for value in (package, attrs.get("__path__")):
            if (
                (type(value) is not tuple and type(value) is not list)
                or len(value) > 1
                or any(type(path) is not str or len(path) > 4096 for path in value)
            ):
                raise ValueError("invalid Python package path")
        paths = tuple(package)
        if tuple(attrs["__path__"]) != paths:
            raise ValueError("Python package path disagreement")
    cached = attrs.get("__cached__")
    if cached is not None and (type(cached) is not str or len(cached) > 4096):
        raise ValueError("invalid Python cache path")
    return {
        "name": name,
        "kind": kind,
        "origin": origin,
        "package_paths": paths,
        "cached": cached,
    }


def collect_python_state(
    deadline,
    *,
    local_modules=(),
    source_loader_types=(),
    _sys=sys,
    _environ=os.environ,
    _clock=time.monotonic_ns,
):
    """Collect bounded data only. The caller supplies the original startup deadline."""
    if type(deadline) is not int or not 0 < deadline < 2**64:
        raise ValueError("Python observation deadline")
    last = [0]

    def check_time():
        now = _clock()
        if type(now) is not int or now < last[0] or now >= deadline:
            raise TimeoutError("Python observation expired")
        last[0] = now

    check_time()
    if type(_sys) is not types.ModuleType:
        raise ValueError("unsupported interpreter state object")
    attrs = _sys.__dict__
    if len(_environ) != 2 or set(_environ) != set(ENVIRONMENT):
        raise ValueError("unexpected Python environment")
    environment = {}
    for key, value in ENVIRONMENT.items():
        if type(_environ[key]) is not str or _environ[key] != value:
            raise ValueError("unexpected Python environment")
        environment[key] = value
    if (
        type(source_loader_types) is not tuple
        or len(source_loader_types) > 16
        or any(
            type(kind) is not type
            or not issubclass(kind, importlib.machinery.SourceFileLoader)
            for kind in source_loader_types
        )
    ):
        raise ValueError("invalid Python loader registry")
    if type(local_modules) is not tuple or len(local_modules) > 128:
        raise ValueError("invalid local Python module registry")
    table = attrs.get("modules")
    if type(table) is not dict or len(table) + len(local_modules) > 4096:
        raise ValueError("Python module inventory cap")
    bindings = tuple(table.items())
    jit = attrs.get("_jit")
    if type(jit) is not types.ModuleType:
        raise ValueError("unobservable Python JIT state")
    jit_values = []
    for name in ("is_available", "is_enabled"):
        query = jit.__dict__.get(name)
        if (
            type(query) is not types.BuiltinFunctionType
            and type(query) is not types.FunctionType
        ):
            raise ValueError("unobservable Python JIT query")
        check_time()
        value = query()
        check_time()
        if type(value) is not bool:
            raise ValueError("invalid Python JIT result")
        jit_values.append(value)
    records, names, total = [], set(), 0
    for pair in (*bindings, *local_modules):
        check_time()
        if (
            type(pair) is not tuple
            or len(pair) != 2
            or type(pair[0]) is not str
            or pair[0] in names
        ):
            raise ValueError("duplicate or invalid Python module binding")
        name, module = pair
        row = describe_module(name, module, source_loader_types)
        total += (
            len(name)
            + len(row["origin"])
            + sum(map(len, row["package_paths"]))
            + (len(row["cached"]) if row["cached"] is not None else 0)
        )
        if total > 1024**2:
            raise ValueError("Python module observation text cap")
        names.add(name)
        records.append(row)
    if (
        attrs.get("modules") is not table
        or len(table) != len(bindings)
        or any(table.get(name) is not module for name, module in bindings)
    ):
        raise ValueError("Python module table changed")
    paths = attrs.get("path")
    if (
        (type(paths) is not list and type(paths) is not tuple)
        or not 1 <= len(paths) <= 4
        or any(type(path) is not str or not 1 <= len(path) <= 4096 for path in paths)
    ):
        raise ValueError("unsupported or unbounded Python search path")
    version, flags, implementation = (
        attrs.get("version_info"),
        attrs.get("flags"),
        attrs.get("implementation"),
    )
    if (
        (type(version) is not VERSION_TYPE and type(version) is not tuple)
        or not 3 <= len(version) <= 5
        or any(type(value) is not int for value in version[:3])
    ):
        raise ValueError("unsupported interpreter version object")
    if type(flags) is FLAGS_TYPE:
        flag_values = {name: getattr(flags, name) for name in FLAG_NAMES}
    elif type(flags) is types.SimpleNamespace and all(
        name in flags.__dict__ for name in FLAG_NAMES
    ):
        flag_values = {name: flags.__dict__[name] for name in FLAG_NAMES}
    else:
        raise ValueError("unsupported interpreter flags object")
    if (
        type(implementation) is not types.SimpleNamespace
        or type(implementation.__dict__.get("name")) is not str
    ):
        raise ValueError("unsupported interpreter implementation object")
    executable, cache_prefix = attrs.get("executable"), attrs.get("pycache_prefix")
    if (
        len(implementation.__dict__["name"]) > 64
        or type(executable) is not str
        or not 0 < len(executable) <= 4096
        or cache_prefix is not None
        and (type(cache_prefix) is not str or len(cache_prefix) > 4096)
    ):
        raise ValueError("unbounded interpreter metadata")
    if any(
        type(value) is not (bool if name == "safe_path" else int)
        for name, value in flag_values.items()
    ):
        raise ValueError("invalid interpreter flag types")
    result = {
        "implementation": implementation.__dict__["name"],
        "version": tuple(version[:3]),
        "executable": executable,
        "flags": flag_values,
        "pycache_prefix": cache_prefix,
        "environment": environment,
        "sys_path": tuple(paths),
        "jit_available": jit_values[0],
        "jit_enabled": jit_values[1],
        "modules": tuple(sorted(records, key=lambda row: row["name"])),
    }
    check_time()
    return result
