#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""H's startup self-check from its selected runtime tree; no admission or bus.

The launcher's --host role execs the tree's own loader with the tree's
interpreter and this entry, in the host namespaces. The entry loads the
module graph HostOwner uses, proves its own process against the selected
manifest (Python state, descriptors, every file mapping by identity and page
bytes) and writes a canonical witness to fd 1. It never coordinates; the
witness is evidence, not authority.
"""

import errno
import hashlib
import importlib
import importlib.machinery
import importlib.util
import os
import re
import stat
import sys
import time
import types
import zipimport
from builtins import BaseExceptionGroup
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import NamedTuple

ENTRY = "opt/irlume/measurement-job-host.py"
LAUNCHER = "opt/irlume/launcher"
LOADER = "lib64/ld-linux-x86-64.so.2"
PYTHON = "/usr/bin/python3"
# CPython v3.14.8 Modules/getpath.py: prefix is search_up from the
# executable's directory to the stdlib landmark, and exec_prefix the same
# directory when it holds lib-dynload, so all four are <T>/usr.
PREFIX = str(PurePosixPath(PYTHON).parents[1])
FLAGS = ("-I", "-S", "-B", "-X", "pycache_prefix=/dev/null")
ENVIRONMENT = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
REQUEST_SCOPE = "contained-job-host-request-v1"
SCOPE = "contained-job-host-startup-witness-v1"
REQUEST_LIMIT = 65536
WITNESS_LIMIT = 1024**2
# Entry to witness. The two observation passes keep ProcCollector's own 5 s
# window (measurement-job-startup.py START_NS).
HOST_NS = 60_000_000_000
# Refused if present. --inhibit-cache --library-path <T>/lib64 is not a
# boundary: glibc-hwcaps subdirectories, the host's default directories for a
# name <T>/lib64 lacks, LD_* variables and this file stay reachable. The
# maps, snapshot, environment and exe checks keep every mapping a member.
PRELOAD = "/etc/ld.so.preload"
JEEPNEY = "0.9.0"
JEEPNEY_ENTRY = "opt/irlume/vendor/jeepney/__init__.py"
# rooted-native.py load_runtime's modules: HostOwner's runtime.
RUNTIME = (
    "preflight",
    "runtime-tree",
    "runtime-state",
    "python-state",
    "startup-check",
    "startup-witness",
    "witness-file",
    "rooted-protocol",
    "rooted-handshake",
)
# Loaded with a recorded source digest: HostOwner's graph and its bus bridge.
SOURCES = (
    "measurement-job-guardian-native.py",
    "measurement-job-guardian.py",
    "measurement-job-guardian-service.py",
    "measurement-job-rooted-native.py",
    *("measurement-job-" + name + ".py" for name in RUNTIME),
    "measurement-job-rooted-host-inputs.py",
    "measurement-job-rooted-host.py",
    "measurement-job-rooted-bus.py",
)
FIELDS = (
    "pid",
    "uid",
    "gid",
    "orig_argv",
    "argv",
    "file",
    "prefixes",
    "initial_path",
    "environment",
    "exe",
    "preload",
    "descriptors",
    "stdio",
    "request_data",
    "hooks",
    "jeepney",
    "sources",
    "mountinfo",
    "namespaces",
    "status",
    "files",
    "python",
    "maps",
    "mapped",
    "started_ns",
    "finished_ns",
)
WIRE = (
    "scope",
    "runtime",
    "request_sha256",
    "manifest_sha256",
    "observation",
    "accepted",
    "native_authorized",
    "full_contract_proven",
)
CLEANUP_FAILURES = (BaseException,)


class Dependencies(NamedTuple):
    state: types.ModuleType
    root: types.ModuleType
    witness: types.ModuleType


def canonical_path(value):
    return (
        type(value) is str
        and value.startswith("/")
        and len(value) <= 4096
        and all(32 <= ord(char) <= 126 for char in value)
        and all(part not in ("", ".", "..") for part in value[1:].split("/"))
    )


def tree_root(executable):
    """The tree whose interpreter runs: sys.executable without /usr/bin/python3."""
    if type(executable) is not str or not executable.endswith(PYTHON):
        raise ValueError("host runtime root")
    tree = executable[: -len(PYTHON)]
    if not canonical_path(tree):
        raise ValueError("host runtime root")
    return tree


def check_environment(environment):
    if type(environment) is not dict or environment != ENVIRONMENT:
        raise ValueError("host environment")


def check_arguments(tree, argv, file, orig_argv):
    """The launcher's exact interpreter flags and entry; nothing else on argv."""
    entry = tree + "/" + ENTRY
    if (
        type(argv) is not tuple
        or len(argv) != 4
        or any(type(value) is not str for value in argv)
        or argv[0] != entry
        or argv[1] != "--request"
        or file != entry
    ):
        raise ValueError("host entry arguments")
    if type(orig_argv) is not tuple or orig_argv != (tree + PYTHON, *FLAGS, *argv):
        raise ValueError("host interpreter arguments")


def check_prefixes(tree, prefixes):
    """prefix, exec_prefix and both base prefixes, each exactly <T>/usr."""
    if (
        type(prefixes) is not tuple
        or any(type(path) is not str for path in prefixes)
        or prefixes != (tree + PREFIX,) * 4
    ):
        raise ValueError("host interpreter prefix")


def check_initial_path(tree, manifest, paths):
    """CPython's initial search path, exactly: the absent stdlib zip, then the
    stdlib and lib-dynload, which the selected manifest lists first.

    getpath.py ("UPDATE pythonpath") appends base_prefix/<platlibdir>/
    pythonXY.zip, stdlib_dir and platstdlib_dir when no PYTHONPATH, home or
    ._pth applies.
    """
    python = manifest["python"]
    roots = python["roots"]
    major, minor = python["version"][:2]
    expected = (
        f"{tree}/{PurePosixPath(roots[0]).parent}/python{major}{minor}.zip",
        *(tree + "/" + path for path in roots[:2]),
    )
    if (
        len(roots) < 2
        or type(paths) is not tuple
        or any(type(path) is not str for path in paths)
        or paths != expected
    ):
        raise ValueError("host initial search path")


def check_executable(exe, path, identity):
    """/proc/self/exe is the tree's loader: H was not started by another ld.so."""
    if type(exe) is not dict or exe != {
        "path": path,
        "device": identity[0],
        "inode": identity[1],
    }:
        raise ValueError("host process executable")


def check_preload(present):
    if present is not False:
        raise ValueError("host loader preload file")


def check_descriptors(descriptors, stdio):
    if (
        type(descriptors) is not dict
        or descriptors != {"initial": (0, 1, 2), "final": (0, 1, 2)}
        or type(stdio) is not dict
        or set(stdio) != {"initial", "final"}
        or type(stdio["initial"]) is not tuple
        or stdio["initial"] != stdio["final"]
    ):
        raise ValueError("host descriptors")


def check_status(root, data, pid, uid, gid):
    """One thread of this unprivileged process holding no capability.

    The inheritable set is recorded, not checked: a login session may set it
    (pam_cap), and it grants nothing without file capabilities on an exec.
    """
    rows = {}
    for line in root.lines(data, 65536, 1024):
        key, separator, value = line.partition(":")
        if not separator or not key or key in rows:
            raise ValueError("host process status")
        rows[key] = value.split()
    expected = {
        "Pid": [str(pid)],
        "Uid": [str(uid)] * 4,
        "Gid": [str(gid)] * 4,
        "Threads": ["1"],
    }
    expected.update(
        {key: ["0000000000000000"] for key in ("CapPrm", "CapEff", "CapAmb")}
    )
    if (
        type(uid) is not int
        or uid <= 0
        or any(rows.get(key) != value for key, value in expected.items())
    ):
        raise ValueError("host process status")


def decode_request(data, digest, tree, root):
    """The launcher-pinned request: exact, canonical and naming this tree."""
    if type(data) is not bytes or not 0 < len(data) <= REQUEST_LIMIT:
        raise ValueError("host request size")
    if (
        type(digest) is not str
        or re.fullmatch("[0-9a-f]{64}", digest) is None
        or hashlib.sha256(data).hexdigest() != digest
    ):
        raise ValueError("host request digest")
    value = root.runtime._json(data)
    root.runtime._fields(
        value, ("scope", "mode", "runtime", "manifest", "manifest_sha256")
    )
    if value["scope"] != REQUEST_SCOPE or value["mode"] != "self-check":
        raise ValueError("host request scope or mode")
    if value["runtime"] != tree:
        raise ValueError("host request runtime")
    if (
        type(value["manifest_sha256"]) is not str
        or re.fullmatch("[0-9a-f]{64}", value["manifest_sha256"]) is None
    ):
        raise ValueError("host request manifest")
    try:
        root.absolute_path(value["manifest"])
    except ValueError as error:
        raise ValueError("host request manifest") from error
    if root.closure.canonical(value) != data:
        raise ValueError("host request encoding")
    return value


def read_private(inputs, path, limit, deadline):
    """Read one caller-owned 0400 single-link file without following a link."""
    path = Path(path)
    fd = None
    try:
        with inputs.opened_parent(path) as (parent, _):
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=parent,
            )
        info = os.fstat(fd)
        if (
            info.st_mode != stat.S_IFREG | 0o400
            or (info.st_uid, info.st_gid) != (os.getuid(), os.getgid())
            or info.st_nlink != 1
            or not 0 < info.st_size <= limit
        ):
            raise ValueError("host input mode, owner or size")
        data = bytearray()
        while len(data) <= info.st_size:
            inputs.before(deadline)
            part = os.read(fd, min(65536, info.st_size + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        if len(data) != info.st_size or inputs.identity(
            os.fstat(fd)
        ) != inputs.identity(info):
            raise ValueError("host input changed")
    except BaseException as error:
        if fd is not None:
            try:
                os.close(fd)
            except CLEANUP_FAILURES as cleanup:
                raise BaseExceptionGroup(
                    "host input read and close", [error, cleanup]
                ) from error
        raise
    os.close(fd)
    return bytes(data)


def mount_chain(root, data, tree):
    """The mounts a walk from / to tree crosses; nothing is mounted at or below it.

    root.parse_mountinfo refuses any stacked or hidden mount in the whole
    table, as host tables have (an autofs point under a network share). H
    needs only its tree's chain: one row per point, each mounted on the
    previous, so mount_device (runtime-state) finds the tree's mount. The
    tree is an ordinary directory on an ancestor's mount: one staged as its
    own mount (bind, tmpfs, a separately mounted subvolume) refuses.
    """
    chain = {}
    for path, mount in root.mount_rows(data):
        if path == tree:
            raise ValueError("host mount at the runtime root")
        if path.startswith(tree + "/"):
            raise ValueError("host mount inside the runtime")
        if path == "/" or tree.startswith(path + "/"):
            if path in chain:
                raise ValueError("host stacked mount on the runtime path")
            chain[path] = mount
    if "/" not in chain:
        raise ValueError("host mount chain root")
    ordered, previous = {}, None
    for path in sorted(chain, key=len):
        if previous is not None and chain[path].parent != previous.number:
            raise ValueError("host mount chain is not one path walk")
        ordered[path] = previous = chain[path]
    return ordered


def file_facts(snapshot, tree):
    """runtime-tree.py file_facts for a tree at a host path."""
    snapshot.check()
    observed = snapshot.observations
    return {
        tree + "/" + member["path"]: {
            "device": observed[member["path"]][0],
            "inode": observed[member["path"]][1],
            "mode": observed[member["path"]][2],
            "size": observed[member["path"]][6],
            "sha256": member["sha256"],
        }
        for member in snapshot.manifest["members"]
        if member["kind"] == "file"
    }


def page_digests(snapshot, tree):
    """The snapshot's own ELF page digests, keyed by host path."""
    return MappingProxyType(
        {tree + path: digests for path, digests in snapshot.pages.items()}
    )


def import_hooks():
    machinery = importlib.machinery
    finder = machinery.FileFinder.__dict__["path_hook"].__func__.__code__
    hooks = sys.path_hooks
    return {
        "excepthook": sys.excepthook is sys.__excepthook__,
        "meta_path": type(sys.meta_path) is list
        and len(sys.meta_path) == 3
        and all(
            found is default
            for found, default in zip(
                sys.meta_path,
                (
                    machinery.BuiltinImporter,
                    machinery.FrozenImporter,
                    machinery.PathFinder,
                ),
            )
        ),
        "path_hooks": type(hooks) is list
        and len(hooks) == 2
        and hooks[0] is zipimport.zipimporter
        and type(hooks[1]) is types.FunctionType
        and any(code is hooks[1].__code__ for code in finder.co_consts),
    }


def source_digests(modules):
    """(origin, sha256) of every module a source loader recorded."""
    rows = set()
    for row in (*modules.bindings, *modules.locals):
        attrs = row[1].__dict__
        if "__source_sha256__" in attrs:
            origin, digest = attrs.get("__file__"), attrs["__source_sha256__"]
            if type(origin) is not str or type(digest) is not str:
                raise ValueError("host source digest")
            rows.add((origin, digest))
    return tuple(sorted(rows))


def check_sources(tree, files, sources):
    seen = set()
    if type(sources) is not tuple:
        raise ValueError("host source digest")
    for row in sources:
        if (
            type(row) is not tuple
            or len(row) != 2
            or type(row[0]) is not str
            or row[0] in seen
            or row[0] not in files
            or row[1] != files[row[0]]["sha256"]
        ):
            raise ValueError("host source digest")
        seen.add(row[0])
    if not {tree + "/opt/irlume/" + name for name in SOURCES} <= seen:
        raise ValueError("host sources missing")


def validate(observation, tree, manifest_data, manifest_sha256, pages, dependencies):
    """Check one observation against the checker's own manifest and pages.

    Collection, freshness and the live rechecks between passes belong to
    run(); this repeats every check a recorded observation allows. pages are
    the checker's own page digests, never decoded values. Returns the
    manifest; nothing here is execution authority.
    """
    state, root = dependencies.state, dependencies.root
    runtime = root.runtime
    runtime._fields(observation, FIELDS)
    check_environment(observation["environment"])
    argv = observation["argv"]
    check_arguments(tree, argv, observation["file"], observation["orig_argv"])
    check_prefixes(tree, observation["prefixes"])
    manifest = root.closure.decode_manifest(manifest_data, manifest_sha256)
    check_initial_path(tree, manifest, observation["initial_path"])
    files = observation["files"]
    state.check_files(manifest, files, prefix=tree)
    loader = tree + "/" + manifest["native"]["interpreter"]
    check_executable(
        observation["exe"], loader, (files[loader]["device"], files[loader]["inode"])
    )
    check_preload(observation["preload"])
    check_descriptors(observation["descriptors"], observation["stdio"])
    check_status(
        root,
        observation["status"],
        observation["pid"],
        observation["uid"],
        observation["gid"],
    )
    request = decode_request(observation["request_data"], argv[3], tree, root)
    if request["manifest_sha256"] != manifest_sha256:
        raise ValueError("host request manifest digest")
    if manifest["bootstrap"] != LAUNCHER:
        raise ValueError("host runtime bootstrap")
    state.check_runtime_state(
        manifest,
        files,
        observation["python"],
        observation["maps"],
        mount_chain(root, observation["mountinfo"], tree),
        observation["mapped"],
        pages,
        prefix=tree,
        entry=ENTRY,
    )
    check_sources(tree, files, observation["sources"])
    if observation["jeepney"] != {
        "version": JEEPNEY,
        "origin": tree + "/" + JEEPNEY_ENTRY,
    }:
        raise ValueError("host jeepney")
    hooks = observation["hooks"]
    if type(hooks) is not dict or set(hooks) != {
        "excepthook",
        "meta_path",
        "path_hooks",
    }:
        raise ValueError("host import hooks")
    if any(value is not True for value in hooks.values()):
        raise ValueError("host import hooks")
    runtime._fields(observation["namespaces"], root.NAMESPACES)
    for value in observation["namespaces"].values():
        runtime._integer(value, 1, runtime.U64_MAX)
    runtime._integer(observation["started_ns"], 1, runtime.U64_MAX)
    runtime._integer(
        observation["finished_ns"], observation["started_ns"], runtime.U64_MAX
    )
    return manifest


def encode(observation, tree, manifest_sha256, dependencies, deadline):
    witness = dependencies.witness
    timer = witness.Clock(deadline, time.monotonic_ns)
    wire = {
        "scope": SCOPE,
        "runtime": tree,
        "request_sha256": observation["argv"][3],
        "manifest_sha256": manifest_sha256,
        "observation": witness.transform(observation, witness.Budget(timer)),
        "accepted": False,
        "native_authorized": False,
        "full_contract_proven": False,
    }
    data = dependencies.root.closure.canonical(wire)
    if len(data) > WITNESS_LIMIT:
        raise ValueError("host witness size")
    return data


def decode(data, dependencies, deadline):
    """Decode one witness for a checker; validate() then checks the observation."""
    root, witness = dependencies.root, dependencies.witness
    if type(data) is not bytes or not 0 < len(data) <= WITNESS_LIMIT:
        raise ValueError("host witness size")
    wire = root.runtime._json(data)
    root.runtime._fields(wire, WIRE)
    if wire["scope"] != SCOPE or any(
        wire[name] is not False
        for name in ("accepted", "native_authorized", "full_contract_proven")
    ):
        raise ValueError("host witness scope or authority")
    if root.closure.canonical(wire) != data:
        raise ValueError("host witness encoding")
    timer = witness.Clock(deadline, time.monotonic_ns)
    observation = witness.transform(
        wire["observation"], witness.Budget(timer), decode=True
    )
    return dict(wire, observation=observation)


def process_executable():
    path = os.readlink("/proc/self/exe")
    info = os.stat("/proc/self/exe")
    if os.readlink("/proc/self/exe") != path:
        raise ValueError("host process executable")
    return {"path": path, "device": info.st_dev, "inode": info.st_ino}


def preload_present(path=PRELOAD):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def load_native(tree):
    """guardian-native from source with the digest of the bytes it compiled.

    A standard SourceFileLoader whose get_code compiles one read of the
    source, so no cache is consulted and this entry adds no loader class:
    startup-check.py module_snapshot caps the graph at 16 SourceLoader
    classes, and G's graph, which H's contains, already has 16.
    """
    path = tree + "/opt/irlume/measurement-job-guardian-native.py"
    loader = importlib.machinery.SourceFileLoader("host_guardian_native", path)
    source = loader.get_data(path)
    loader.get_code = lambda fullname: loader.source_to_code(source, path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    native = importlib.util.module_from_spec(spec)
    loader.exec_module(native)
    native.__source_sha256__ = hashlib.sha256(source).hexdigest()
    return native


def inventory(collector):
    """Descriptors 0-2 only; the enumerator is excluded by identity."""
    try:
        return collector._inventory()
    except ValueError as error:
        raise ValueError("host descriptors") from error


def run(initial):
    started = time.monotonic_ns()
    deadline = started + HOST_NS
    os.chdir("/")
    tree = tree_root(initial["executable"])
    if os.path.realpath(tree) != tree:
        raise ValueError("host runtime root")
    # Before any input is read or any module of the graph is loaded.
    check_environment(initial["environment"])
    argv = initial["argv"]
    check_arguments(tree, argv, initial["file"], initial["orig_argv"])
    # The executable first: the prefixes come from whichever libpython the
    # process loaded, so another loader's refusal would depend on the host.
    loader = os.lstat(tree + "/" + LOADER)
    exe = process_executable()
    check_executable(exe, tree + "/" + LOADER, (loader.st_dev, loader.st_ino))
    check_prefixes(tree, initial["prefixes"])
    preload = preload_present()
    check_preload(preload)

    # HostOwner's module graph from the tree as an embedder builds it
    # (rooted-host.py:1557-1559), with its bus bridge (rooted-host.py:240),
    # so this witness covers what H2 runs.
    native = load_native(tree)
    rooted = native.load(
        "host_rooted_native", native.HERE / "measurement-job-rooted-native.py"
    )
    runtime = rooted.load_runtime(native, rooted)
    host_inputs = native.load(
        "host_rooted_host_inputs", native.HERE / "measurement-job-rooted-host-inputs.py"
    )
    owner = native.load(
        "host_rooted_host", native.HERE / "measurement-job-rooted-host.py"
    )
    bridge = owner.load_bus_bridge(runtime)
    root, state = runtime.preflight.root, runtime.state
    startup = runtime.preflight.filesystem.startup
    dependencies = Dependencies(state, root, runtime.witness)
    closure = root.closure

    request_data = read_private(closure.inputs, argv[2], REQUEST_LIMIT, deadline)
    request = decode_request(request_data, argv[3], tree, root)
    manifest_data = read_private(
        closure.inputs, request["manifest"], closure.MAX_MANIFEST, deadline
    )
    manifest = closure.decode_manifest(manifest_data, request["manifest_sha256"])
    if manifest["bootstrap"] != LAUNCHER:
        raise ValueError("host runtime bootstrap")
    check_initial_path(tree, manifest, initial["path"])
    sys.path = [tree + "/" + path for path in manifest["python"]["roots"]]
    jeepney = importlib.import_module("jeepney")
    importlib.import_module("jeepney.io.blocking")

    roots = (sys.modules["__main__"], *runtime.roots, host_inputs, owner, bridge)
    early = startup.ProcCollector(deadline)
    descriptors = {"initial": inventory(early)}
    stdio = {"initial": early._stdio()}
    with closure.RuntimeSnapshot.open(
        tree, manifest_data, request["manifest_sha256"], deadline=deadline
    ) as snapshot:
        files = file_facts(snapshot, tree)
        pages = page_digests(snapshot, tree)
        reader = startup.ProcCollector(deadline)

        def capture():
            return runtime.startup.module_snapshot(roots, sys.modules, reader._after)

        def python(modules):
            return runtime.python.collect_python_state(
                reader.deadline,
                local_modules=tuple((row[0], row[1]) for row in modules.locals),
                source_loader_types=modules.loaders,
            )

        def process():
            with reader._open(f"/proc/{os.getpid()}", directory=True) as fd:
                mountinfo = reader._read(fd, "mountinfo", startup.LIMITS["mountinfo"])
                mounts = mount_chain(root, mountinfo, tree)
                maps = reader._read(fd, "maps", startup.LIMITS["maps"])
                _, readable = state.file_mappings(maps, files, mounts)
                mapped = reader._mapped(
                    fd, tuple((mapping.start, mapping.end) for mapping in readable)
                )
                status = reader._read(fd, "status", startup.LIMITS["status"])
                check_status(root, status, os.getpid(), os.getuid(), os.getgid())
                namespaces = reader._namespaces(fd)
            return mountinfo, mounts, maps, mapped, status, namespaces

        def check_pass(python_state, facts):
            state.check_runtime_state(
                manifest,
                files,
                python_state,
                facts[2],
                facts[1],
                facts[3],
                pages,
                prefix=tree,
                entry=ENTRY,
            )

        same = runtime.startup.same_modules
        first_modules = capture()
        first_python = python(first_modules)
        if not same(first_modules, capture()):
            raise ValueError("host module identities changed")
        first = process()
        check_pass(first_python, first)
        last_modules = capture()
        if not same(first_modules, last_modules):
            raise ValueError("host module identities changed")
        last_python = python(last_modules)
        if not same(first_modules, capture()) or first_python != last_python:
            raise ValueError("host Python state changed")
        last = process()
        check_pass(last_python, last)
        if last[1] != first[1] or last[5] != first[5]:
            raise ValueError("host mount chain or namespaces changed")
        sources = source_digests(last_modules)
        hooks = import_hooks()
        snapshot.check()
    descriptors["final"] = inventory(reader)
    stdio["final"] = reader._stdio()
    observation = {
        "pid": os.getpid(),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "orig_argv": initial["orig_argv"],
        "argv": argv,
        "file": initial["file"],
        "prefixes": initial["prefixes"],
        "initial_path": initial["path"],
        "environment": initial["environment"],
        "exe": exe,
        "preload": preload,
        "descriptors": descriptors,
        "stdio": stdio,
        "request_data": request_data,
        "hooks": hooks,
        "jeepney": {"version": jeepney.__version__, "origin": jeepney.__file__},
        "sources": sources,
        "mountinfo": last[0],
        "namespaces": last[5],
        "status": last[4],
        "files": files,
        "python": last_python,
        "maps": last[2],
        "mapped": last[3],
        "started_ns": started,
        "finished_ns": time.monotonic_ns(),
    }
    validate(
        observation,
        tree,
        manifest_data,
        request["manifest_sha256"],
        pages,
        dependencies,
    )
    return encode(observation, tree, request["manifest_sha256"], dependencies, deadline)


def reason(error):
    """A fixed refusal reason: messages of the checks, never paths or values."""
    if isinstance(error, BaseExceptionGroup) and error.exceptions:
        return reason(error.exceptions[0])
    if isinstance(error, (ValueError, TimeoutError)) and str(error):
        text = str(error)
    elif isinstance(error, OSError):
        text = "OSError " + errno.errorcode.get(error.errno, "unknown")
    else:
        text = type(error).__name__
    return "".join(char if 32 <= ord(char) <= 126 else "?" for char in text[:256])


def main():
    # Before any code below could change them.
    initial = {
        "path": tuple(sys.path),
        "environment": dict(os.environ),
        "orig_argv": tuple(sys.orig_argv),
        "argv": tuple(sys.argv),
        "file": globals().get("__file__"),
        "executable": sys.executable,
        "prefixes": (
            sys.prefix,
            sys.exec_prefix,
            sys.base_prefix,
            sys.base_exec_prefix,
        ),
    }
    try:
        data = memoryview(run(initial))
        while data:
            data = data[os.write(1, data) :]
    except CLEANUP_FAILURES as error:
        try:
            os.write(2, ("measurement-job-host: " + reason(error) + "\n").encode())
        except OSError:
            pass
        return 77
    return 0


if __name__ == "__main__":
    os._exit(main())
