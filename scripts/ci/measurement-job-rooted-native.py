#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Concrete startup-only G bootstrap. No child or virtual machine is created."""

import contextlib
import errno
import hashlib
import importlib
import os
import select
import socket
import stat
import sys
import time
import types
from pathlib import Path
from typing import NamedTuple

CLEANUP_FAILURES = (BaseException,)


class Runtime(NamedTuple):
    native: types.ModuleType
    roots: tuple
    preflight: types.ModuleType
    tree: types.ModuleType
    state: types.ModuleType
    python: types.ModuleType
    startup: types.ModuleType
    witness: types.ModuleType
    artifact: types.ModuleType
    protocol: types.ModuleType
    handshake: types.ModuleType
    bus_bridge: types.ModuleType


def load_runtime(native, entry):
    if type(native) is not types.ModuleType or type(entry) is not types.ModuleType:
        raise ValueError("rooted bootstrap module roots")
    names = (
        "preflight",
        "runtime-tree",
        "runtime-state",
        "python-state",
        "startup-check",
        "startup-witness",
        "witness-file",
        "rooted-protocol",
        "rooted-handshake",
        "rooted-bus",
    )
    modules = tuple(
        native.load(
            "rooted_" + name.replace("-", "_"),
            native.HERE / ("measurement-job-" + name + ".py"),
        )
        for name in names
    )
    return Runtime(native, (native, entry, *modules), *modules)


def prime_bus_imports():
    package = importlib.import_module("jeepney")
    importlib.import_module("jeepney.io.blocking")
    if type(package.__version__) is not str or package.__version__ != "0.9.0":
        raise ValueError("unselected Jeepney version")


def read_manifest(plan, root, deadline):
    """Read only the fixed bind, after proving the expected runtime root."""
    root.check_plan(plan)
    inputs = root.closure.inputs
    inputs.before(deadline)
    with contextlib.ExitStack() as stack:
        directory = stack.enter_context(
            root.closure.owned_fd(
                os.open(
                    "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                )
            )
        )
        root_fd = directory
        root_info = os.fstat(root_fd)
        root_identity = inputs.identity(root_info)
        if (
            (root_info.st_dev, root_info.st_ino)
            != (plan["root"]["device"], plan["root"]["inode"])
            or stat.S_IMODE(root_info.st_mode) != 0o500
            or root_info.st_uid not in (0, plan["uid"])
        ):
            raise ValueError("rooted bootstrap root identity or mode")
        ancestors = []
        for name in ("run", "irlume"):
            inputs.before(deadline)
            child = stack.enter_context(
                root.closure.owned_fd(
                    os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory,
                    )
                )
            )
            info = os.fstat(child)
            identity = inputs.identity(info)
            if (
                info.st_uid not in (0, plan["uid"])
                or info.st_mode & 0o022
                or inputs.identity(
                    os.stat(name, dir_fd=directory, follow_symlinks=False)
                )
                != identity
            ):
                raise ValueError("rooted bootstrap unsafe parent")
            ancestors.append((directory, name, child, identity))
            directory = child
        fd = stack.enter_context(
            root.closure.owned_fd(
                os.open(
                    "runtime-manifest.json",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=directory,
                )
            )
        )
        info = os.fstat(fd)
        identity = inputs.identity(info)
        if (
            (info.st_dev, info.st_ino)
            != (plan["manifest"]["device"], plan["manifest"]["inode"])
            or info.st_mode != stat.S_IFREG | 0o400
            or info.st_uid != plan["uid"]
            or info.st_gid != plan["gid"]
            or info.st_nlink != 1
            or not 0 < info.st_size <= root.closure.MAX_MANIFEST
        ):
            raise ValueError("rooted bootstrap manifest identity or type")
        data = bytearray()
        while len(data) < info.st_size:
            inputs.before(deadline)
            chunk = os.read(fd, min(65536, info.st_size - len(data)))
            if not chunk:
                raise ValueError("rooted bootstrap short manifest")
            data.extend(chunk)
        if (
            os.read(fd, 1)
            or hashlib.sha256(data).hexdigest() != plan["manifest"]["sha256"]
        ):
            raise ValueError("rooted bootstrap manifest digest or size")
        if (
            inputs.identity(os.fstat(fd)) != identity
            or inputs.identity(
                os.stat(
                    "runtime-manifest.json", dir_fd=directory, follow_symlinks=False
                )
            )
            != identity
        ):
            raise ValueError("rooted bootstrap manifest changed")
        for parent, name, child, before in ancestors:
            if (
                inputs.identity(os.fstat(child)) != before
                or inputs.identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                != before
            ):
                raise ValueError("rooted bootstrap parent changed")
        if (
            inputs.identity(os.fstat(root_fd)) != root_identity
            or inputs.identity(os.stat("/", follow_symlinks=False)) != root_identity
        ):
            raise ValueError("rooted bootstrap root changed")
        inputs.before(deadline)
        result = bytes(data)
    inputs.before(deadline)
    return result


class GuardianEffects:
    """Concrete inert G effects; the controller owns the returned attempt FD."""

    def __init__(self, config, manifest, runtime):
        if type(runtime) is not Runtime:
            raise ValueError("rooted native runtime")
        self.runtime = runtime
        self.root = runtime.preflight.root
        self.protocol_deps = runtime.protocol.Dependencies(self.root, runtime.artifact)
        if type(config) is not runtime.protocol.Configuration:
            raise ValueError("rooted native configuration")
        self.value = runtime.protocol.decode_config(
            config.data, config.sha256, manifest, self.protocol_deps
        )
        self.config, self.manifest = config, manifest
        self.spec = runtime.protocol.validate_config(
            self.value, manifest, self.protocol_deps
        )
        self.attempt_fd = self.channel = self.connecting = None
        self.service_observation = None

    def now(self):
        return time.monotonic_ns()

    def before(self, deadline):
        return self.runtime.native.before(self.limit(deadline))

    def limit(self, deadline):
        self.root.runtime._integer(deadline, 1, self.root.runtime.U64_MAX)
        return min(deadline, self.value["startup_deadline_ns"])

    def same_inputs(self, config, manifest=None):
        if (
            type(config) is not self.runtime.protocol.Configuration
            or config != self.config
            or manifest is not None
            and manifest != self.manifest
        ):
            raise ValueError("rooted native input changed")

    def collect(self, config, manifest, deadline):
        self.same_inputs(config, manifest)
        self.before(deadline)
        if (
            self.attempt_fd is not None
            or self.channel is not None
            or self.connecting is not None
        ):
            raise ValueError("rooted collection after handle acquisition")
        runtime = self.runtime
        dependencies = runtime.startup.Dependencies(
            runtime.preflight, runtime.tree, runtime.state, runtime.python
        )
        return runtime.startup.collect_startup(
            self.value["root_plan"],
            self.value["bus_identity"],
            manifest,
            dependencies,
            runtime.roots,
            min(deadline, self.value["startup_deadline_ns"]),
        )

    def read_cgroup(self, deadline):
        self.before(deadline)
        with self.root.closure.owned_fd(
            os.open(
                f"/proc/{os.getpid()}/cgroup",
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        ) as fd:
            data = os.read(fd, 4097)
        self.before(deadline)
        if len(data) > 4096:
            raise ValueError("rooted cgroup byte cap")
        return data

    def preflight(self, config, manifest, deadline):
        self.same_inputs(config, manifest)
        deadline = self.limit(deadline)
        self.before(deadline)
        if (
            os.getuid() != self.value["client"]["uid"]
            or os.getgid() != self.value["client"]["gid"]
            or os.geteuid() != os.getuid()
        ):
            raise ValueError("rooted guardian user identity")
        runtime, errors = self.runtime, []
        bus = runtime.native.service.SystemdBus(os.getuid(), deadline=deadline)
        bridge = None
        try:
            bridge = runtime.bus_bridge.RootedBus(
                bus,
                runtime.bus_bridge.Dependencies(
                    runtime.protocol, self.protocol_deps, runtime.native.service
                ),
            )
            observed = bridge.observe(config, manifest, deadline)
        except CLEANUP_FAILURES as error:
            errors.append(error)
        self.service_observation = None if bridge is None else bridge.partial
        try:
            bus.close()
        except CLEANUP_FAILURES as error:
            errors.append(error)
        runtime.native.raise_errors("rooted service preflight and close", errors)
        self.before(deadline)
        base = observed["service"]
        keys = (
            (set(self.root.guardian.service_properties(self.spec)) - {"AddRef"})
            | set(runtime.native.service.UNIT_TYPES)
            | {"MainPID", "ControlGroup", "ExecMainStartTimestampMonotonic"}
        )
        identity = self.root.guardian.check_service(
            {key: base[key] for key in keys},
            self.spec,
            os.getpid(),
            os.getuid(),
            self.now(),
        )
        argv = self.root.entry_argv(self.value["root_plan"], config.sha256)
        if base["ExecStart"] != ((argv[0], argv, False),):
            raise ValueError("rooted static executable binding")
        if self.read_cgroup(deadline) != ("0::" + identity.cgroup + "\n").encode(
            "ascii"
        ) or os.sched_getaffinity(0) != set(self.spec.cpus):
            raise ValueError("rooted guardian placement")
        client = self.value["client"]
        self.root.runtime._integer(
            runtime.native.process_start(client["pid"]),
            client["starttime"],
            client["starttime"],
        )
        starttime = runtime.native.process_start(os.getpid())
        self.root.runtime._integer(starttime, 1, self.root.runtime.U64_MAX)
        self.before(deadline)
        return identity, starttime

    def open_attempt(self, config, deadline):
        self.same_inputs(config)
        self.before(deadline)
        if self.attempt_fd is not None:
            raise ValueError("rooted attempt already acquired")
        self.attempt_fd = self.runtime.native.private_directory(Path(self.root.ATTEMPT))
        return self.attempt_fd

    def connect(self, config, deadline):
        self.same_inputs(config)
        deadline = self.limit(deadline)
        self.before(deadline)
        if self.channel is not None or self.connecting is not None:
            raise ValueError("rooted control already acquired")
        plan = self.value["root_plan"]["attempt"]
        self.runtime.artifact.check_directory(
            self.attempt_fd, (plan["device"], plan["inode"])
        )
        info = os.stat("control.sock", dir_fd=self.attempt_fd, follow_symlinks=False)
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != self.value["client"]["uid"]
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("rooted control socket identity")
        self.connecting = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC,
        )
        for _ in range(self.root.guardian.IO_LIMIT):
            delay = self.before(deadline)
            result = self.connecting.connect_ex(self.root.ATTEMPT + "/control.sock")
            if result in (0, errno.EISCONN):
                break
            if result not in (errno.EAGAIN, errno.EINPROGRESS, errno.EALREADY):
                raise OSError(result, "rooted control connect")
            select.select([], [self.connecting], [], delay)
        else:
            raise ValueError("rooted control connection cap")
        client = self.value["client"]
        connected, self.connecting = self.connecting, None
        # PeerChannel consumes the socket, including on constructor failure.
        self.channel = self.root.guardian.PeerChannel(
            connected, (client["pid"], client["uid"], client["gid"])
        )
        self.channel.check(deadline)
        observed_start = self.runtime.native.process_start(client["pid"])
        self.channel.check(deadline)
        self.root.runtime._integer(
            observed_start, client["starttime"], client["starttime"]
        )
        if self.root.closure.inputs.identity(
            os.stat("control.sock", dir_fd=self.attempt_fd, follow_symlinks=False)
        ) != self.root.closure.inputs.identity(info):
            raise ValueError("rooted control socket replaced")
        self.before(deadline)

    def receive(self, deadline):
        return self.channel.receive(self.limit(deadline))

    def send(self, data, deadline):
        self.channel.send(data, self.limit(deadline))

    def require_idle(self, deadline):
        self.channel.require_idle(self.limit(deadline))

    def close_control(self):
        errors = []
        for name in ("channel", "connecting"):
            resource = getattr(self, name)
            setattr(self, name, None)
            if resource is not None:
                try:
                    resource.close()
                except CLEANUP_FAILURES as error:
                    errors.append(error)
        self.runtime.native.raise_errors("rooted control close", errors)


def run_service(data, digest, native, entry):
    runtime = load_runtime(native, entry)
    root = runtime.preflight.root
    protocol_deps = runtime.protocol.Dependencies(root, runtime.artifact)
    value = runtime.protocol.decode_header(data, digest, protocol_deps)
    root.runtime._integer(
        time.monotonic_ns(), value["origin_ns"], value["startup_deadline_ns"] - 1
    )
    manifest = read_manifest(value["root_plan"], root, value["startup_deadline_ns"])
    config = runtime.protocol.Configuration(data, digest)
    runtime.protocol.decode_config(data, digest, manifest, protocol_deps)
    selected = root.check_selection(value["root_plan"], manifest)
    sys.path = ["/" + path for path in selected["python"]["roots"]]
    prime_bus_imports()
    effects = GuardianEffects(config, manifest, runtime)
    witness_deps = runtime.witness.Dependencies(runtime.preflight, runtime.state)
    support = runtime.handshake.Dependencies(
        runtime.protocol, protocol_deps, runtime.witness, witness_deps, runtime.artifact
    )
    runtime.handshake.Guardian(config, manifest, support, effects).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(77)
