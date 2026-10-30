#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Concrete startup-only H ownership. No child or virtual machine is created."""

import hashlib
import importlib
import json
import os
import re
import select
import socket
import stat
import time
import types
from pathlib import Path
from typing import NamedTuple


class Dependencies(NamedTuple):
    runtime: object
    inputs: types.ModuleType
    terminal_check: object


PREPARE_NS = 60_000_000_000
# The host entry's startup request and witness (measurement-job-host.py
# REQUEST_SCOPE, SCOPE and WITNESS_LIMIT). H runs only with its own process's
# witness for exactly its selection, and binds the witness into the attempt.
HOST_REQUEST_SCOPE = "contained-job-host-request-v1"
HOST_WITNESS_SCOPE = "contained-job-host-startup-witness-v1"
# measurement-job-host.py REQUEST_FIELDS["resolve-failed-startup"].
RESOLVER_REQUEST_FIELDS = frozenset(
    ("scope", "mode", "runtime", "manifest", "manifest_sha256", "run_id", "commit")
)
HOST_WITNESS_LIMIT = 1024**2
INTENT_SCOPE = "contained-job-rooted-host-intent-v2"
INTENT_FIELDS = frozenset(
    (
        "scope",
        "config_sha256",
        "run_id",
        "unit",
        "path",
        "client",
        "host_witness_sha256",
    )
)
RECEIPTS = (
    "guardian-config",
    "host-intent",
    "host-started",
    "host-finished",
    "host-witness",
)
UNRESOLVED = {}
CLEANUP_FAILURES = (BaseException,)
# Abort keeps this part of its window (STOP_NS after the startup deadline) to
# persist the failure record; it must stay well below the guardian's STOP_NS.
FAILURE_RECORD_NS = 1_000_000_000
JOB_PATH = r"/org/freedesktop/systemd1/job/[1-9][0-9]{0,19}"
FAILURE_OBSERVATION = (
    "Id",
    "InvocationID",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlGroup",
    "ExecMainStartTimestampMonotonic",
)


def admission_path(root, gate):
    """Name-checked identity of the admission directory, its ancestors and lock."""
    with root.closure.inputs.opened_parent(gate.root) as (parent, ancestors):
        named = os.stat(gate.root.name, dir_fd=parent, follow_symlinks=False)
        actual = os.fstat(gate.root_fd)
        if (
            (named.st_dev, named.st_ino) != (actual.st_dev, actual.st_ino)
            or not stat.S_ISDIR(actual.st_mode)
            or stat.S_IMODE(actual.st_mode) != 0o700
            or actual.st_uid != os.getuid()
        ):
            raise ValueError("rooted admission path changed")
    lock = os.fstat(gate.lock_fd)
    named = os.stat("admission.lock", dir_fd=gate.root_fd, follow_symlinks=False)
    if (
        (named.st_dev, named.st_ino) != (lock.st_dev, lock.st_ino)
        or not stat.S_ISREG(lock.st_mode)
        or stat.S_IMODE(lock.st_mode) != 0o600
        or lock.st_uid != os.getuid()
        or lock.st_nlink != 1
    ):
        raise ValueError("rooted admission lock changed")
    return ancestors, (actual.st_dev, actual.st_ino), (lock.st_dev, lock.st_ino)


def boot_id():
    with open("/proc/sys/kernel/random/boot_id", "rb") as file:
        value = file.read(64)
    if re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n", value) is None:
        raise ValueError("host boot identity")
    return value[:-1].decode("ascii")


def observe_host(runtime, deadline):
    """Observe fixed host coordinates without connecting to a bus or service."""
    filesystem = runtime.preflight.filesystem
    reader = filesystem.startup.ProcCollector(deadline)
    root = runtime.preflight.root
    with (
        reader._open("/", directory=True) as fd,
        filesystem.RootTree(reader, fd) as tree,
        reader._open(f"/proc/{os.getpid()}", directory=True) as proc,
    ):
        namespaces = reader._namespaces(proc)
        api = {}
        for path in (*root.DENIED, "/run", "/tmp"):
            node = tree.node(path)
            api[path] = (
                None
                if node is None
                else {key: node[key] for key in ("device", "inode")}
            )
        bus = tree.node(f"/run/user/{os.getuid()}/bus")
        if bus is None or not stat.S_ISSOCK(bus["mode"]) or bus["uid"] != os.getuid():
            raise ValueError("host user bus identity")
        if reader._namespaces(proc) != namespaces:
            raise ValueError("host namespaces changed during observation")
        tree.recheck()
        result = {
            "host_namespaces": namespaces,
            "host_api": api,
            "bus": {key: bus[key] for key in ("device", "inode")},
        }
    reader._after()
    return result


def load_bus_bridge(runtime):
    """H's typed manager calls. G's runtime never loads this module."""
    return runtime.native.load(
        "rooted_host_bus", runtime.native.HERE / "measurement-job-rooted-bus.py"
    )


def preload_jeepney():
    """Jeepney as SystemdBus imports it when it connects (guardian-service.py:82-86)."""
    jeepney = importlib.import_module("jeepney")
    importlib.import_module("jeepney.io.blocking")
    if jeepney.__version__ != "0.9.0":
        raise ValueError("unreviewed Jeepney version")


class HostWitness(NamedTuple):
    """The entry's canonical startup witness and its process recheck.

    check(deadline) refuses when this process's module table or file
    mappings differ from the witness's last pass.
    """

    data: bytes
    check: object


def host_request(selection):
    """The startup-only request that names exactly this selection."""
    spec = selection.spec
    return {
        "scope": HOST_REQUEST_SCOPE,
        "mode": "startup-only",
        "runtime": selection.runtime,
        "manifest": selection.manifest,
        "manifest_sha256": selection.manifest_sha256,
        "specification": dict(
            spec._asdict(), cases=list(spec.cases), cpus=list(spec.cpus)
        ),
        "base_sha256": selection.base_sha256,
        "payload_sha256": selection.payload_sha256,
    }


def witness_wire(witness, root):
    """The canonical, non-authoritative wire of this process's witness."""
    if (
        type(witness) is not HostWitness
        or type(witness.data) is not bytes
        or not 0 < len(witness.data) <= HOST_WITNESS_LIMIT
        or type(witness.check) is not types.FunctionType
    ):
        raise ValueError("rooted host witness")
    try:
        wire = root.runtime._json(witness.data)
    except ValueError as error:
        raise ValueError("rooted host witness binding") from error
    if type(wire) is not dict or root.closure.canonical(wire) != witness.data:
        raise ValueError("rooted host witness binding")
    observation = wire.get("observation")
    if (
        wire.get("scope") != HOST_WITNESS_SCOPE
        or any(
            wire.get(name) is not False
            for name in ("accepted", "native_authorized", "full_contract_proven")
        )
        or type(observation) is not dict
        or type(observation.get("pid")) is not int
        or observation["pid"] != os.getpid()
    ):
        raise ValueError("rooted host witness binding")
    return wire


def check_witness(witness, selection, root):
    """This process's witness for this selection; returns its digest.

    Only the binding is checked here: the entry validated the observation
    against its manifest before H was built, and a checker can repeat that
    from host-witness.json.
    """
    wire = witness_wire(witness, root)
    request = root.closure.canonical(host_request(selection))
    if (
        wire.get("runtime") != selection.runtime
        or wire.get("manifest_sha256") != selection.manifest_sha256
        or wire.get("request_sha256") != hashlib.sha256(request).hexdigest()
        or wire["observation"].get("request_data") != {"$bytes": request.hex()}
    ):
        raise ValueError("rooted host witness binding")
    return hashlib.sha256(witness.data).hexdigest()


def check_resolver_witness(witness, run_id, commit, root):
    """This process's witness for resolving exactly this run; returns its digest.

    The request differs from any host_request, so a resolver witness cannot
    start HostOwner and a startup witness cannot resolve.
    """
    wire = witness_wire(witness, root)
    try:
        request = bytes.fromhex(wire["observation"]["request_data"]["$bytes"])
        value = root.runtime._json(request)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("rooted host witness binding") from error
    if (
        type(value) is not dict
        or root.closure.canonical(value) != request
        or set(value) != RESOLVER_REQUEST_FIELDS
        or value.get("scope") != HOST_REQUEST_SCOPE
        or value.get("mode") != "resolve-failed-startup"
        or value.get("run_id") != run_id
        or value.get("commit") is not commit
        or wire.get("runtime") != value.get("runtime")
        or wire.get("manifest_sha256") != value.get("manifest_sha256")
        or wire.get("request_sha256") != hashlib.sha256(request).hexdigest()
    ):
        raise ValueError("rooted host witness binding")
    return hashlib.sha256(witness.data).hexdigest()


class LeaseBus:
    """Adapt one canonical rooted configuration to the retained UnitLease."""

    def __init__(self, config, manifest, support, bus, bridge):
        runtime = support.runtime
        self.root = runtime.preflight.root
        deps = runtime.protocol.Dependencies(self.root, runtime.artifact)
        value = runtime.protocol.decode_config(
            config.data, config.sha256, manifest, deps
        )
        self.spec = runtime.protocol.validate_config(value, manifest, deps)
        self.config, self.manifest, self.bus = config, manifest, bus
        self.name = self.root.guardian.unit_name(self.spec)
        self.properties = self.root.guardian.service_properties(self.spec)
        self.argv = self.root.entry_argv(value["root_plan"], config.sha256)
        self.bridge = bridge.RootedBus(
            bus, bridge.Dependencies(runtime.protocol, deps, runtime.native.service)
        )
        self.last_root = self.last_cgroup_id = None
        self.cleanup_binding = None

    def check_name(self, name):
        if type(name) is not str or name != self.name:
            raise ValueError("rooted lease unit mismatch")

    def start(self, name, properties, argv, deadline):
        self.check_name(name)
        if (
            self.cleanup_binding is not None
            or type(properties) is not dict
            or properties.keys() != self.properties.keys()
            or any(
                type(properties[key]) is not type(value) or properties[key] != value
                for key, value in self.properties.items()
            )
            or type(argv) is not tuple
            or argv != self.argv
        ):
            raise ValueError("rooted lease creation mismatch")
        return self.bridge.start(self.config, self.manifest, deadline)

    def observe(self, name, deadline):
        self.check_name(name)
        if self.cleanup_binding is not None:
            row = self.bus.observe(name, deadline)
            if any(
                row.get(key) != value for key, value in self.cleanup_binding.items()
            ):
                raise ValueError("rooted cleanup lost invocation")
            return row
        observed = self.bridge.observe(self.config, self.manifest, deadline)
        self.last_root = observed["root"]
        self.last_cgroup_id = observed["cgroup_id"]
        return observed["service"]

    def enter_cleanup(self, bound):
        if self.cleanup_binding is not None or type(bound) is not dict:
            raise ValueError("rooted cleanup binding")
        self.check_name(bound.get("Id"))
        if (
            type(bound.get("InvocationID")) is not str
            or re.fullmatch("[0-9a-f]{32}", bound["InvocationID"]) is None
            or bound["InvocationID"] == "0" * 32
        ):
            raise ValueError("rooted cleanup invocation")
        self.cleanup_binding = {key: bound[key] for key in ("Id", "InvocationID")}

    def pin_cleanup(self, deadline):
        # Only for a created unit whose startup observation never completed.
        if self.cleanup_binding is not None:
            raise ValueError("rooted cleanup binding")
        row = self.bus.observe(self.name, deadline)
        if row.get("Transient") is not True or row.get("ExecStart") != (
            (self.argv[0], self.argv, False),
        ):
            raise ValueError("rooted cleanup unit mismatch")
        self.enter_cleanup(row)
        return dict(self.cleanup_binding)

    def stop(self, name, deadline):
        self.check_name(name)
        if self.cleanup_binding is None:
            raise ValueError("rooted stop is cleanup-only")
        return self.bus.stop(name, deadline)

    def processes(self, name, deadline):
        self.check_name(name)
        return self.bus.processes(name, deadline)

    def close(self):
        self.bus.close()


def verify_service_terminal(proof, identity, started_ns, now):
    """G's unit ended cleanly and in time, with no process left.

    The controller's terminal_check. Moved from guardian-host.py, whose R4
    coordinator keeps its own copy, so HostOwner's graph needs neither that
    file nor measurement-job.py, tomllib, shutil and their compression modules.
    """
    if type(proof) is not dict or set(proof) != {"unit", "processes"}:
        raise ValueError("invalid fields")
    row = proof["unit"]
    if (
        type(row) is not dict
        or type(proof["processes"]) is not tuple
        or proof["processes"]
    ):
        raise ValueError("guardian service domain not terminal")
    expected = {
        "Id": identity.unit,
        "InvocationID": identity.invocation_id,
        "MainPID": 0,
        "ActiveState": "inactive",
        "SubState": "dead",
        "Result": "success",
        "ExecMainCode": 1,
        "ExecMainStatus": 0,
    }
    for key, value in expected.items():
        if type(row.get(key)) is not type(value) or row[key] != value:
            raise ValueError("guardian service termination mismatch")
    start, end = (
        row.get("ExecMainStartTimestampMonotonic"),
        row.get("ExecMainExitTimestampMonotonic"),
    )
    if (
        type(start) is not int
        or type(end) is not int
        or start * 1000 != started_ns
        or not started_ns <= end * 1000 <= now
        or end * 1000 >= identity.deadline_ns
    ):
        raise ValueError("guardian service terminal timestamps")


class HostOwner:
    """Retain admission, inputs and exact service ownership until gate commit."""

    def __init__(
        self,
        selection,
        support,
        *,
        witness=None,
        bus_bridge=None,
        gate_factory=None,
        bus_factory=None,
        host_observer=None,
    ):
        if (
            type(support) is not Dependencies
            or type(support.inputs) is not types.ModuleType
            or type(support.terminal_check) is not types.FunctionType
        ):
            raise ValueError("rooted host dependencies")
        if type(selection) is not support.inputs.Selection:
            raise ValueError("rooted host selection")
        if bus_bridge is not None and type(bus_bridge) is not types.ModuleType:
            raise ValueError("rooted host dependencies")
        self.selection, self.support = selection, support
        self.runtime = support.runtime
        self.root = self.runtime.preflight.root
        self.spec = selection.spec
        self.root.guardian.validate_spec(self.spec)
        self.witness_sha256 = check_witness(witness, selection, self.root)
        self.witness = witness
        self.gate_factory = (
            gate_factory or self.runtime.native.service.AdmissionGate.for_current_user
        )
        self.bus_factory = bus_factory or self.runtime.native.service.SystemdBus
        # Loaded before admission, so no code is read inside the startup
        # window: the bus bridge (the embedder's, which its witness covers)
        # and Jeepney, which SystemdBus imports only when it connects
        # (guardian-service.py:82-86). The witness's process check refuses an
        # import or a new file mapping after the witness's last pass, so an
        # embedder imports both before that pass.
        self.bus_bridge = bus_bridge or load_bus_bridge(self.runtime)
        preload_jeepney()
        self.host_observer = host_observer or (
            lambda deadline: observe_host(self.runtime, deadline)
        )
        self.gate = self.inputs = self.directory = self.bus = self.adapter = (
            self.lease
        ) = None
        self.listener = self.channel = None
        self.config = self.value = self.identity = self.starttime = None
        self.service_cgroup_id = self.completed = self.boot_id = None
        self.used = self.claim_attempted = self.aborted = self.committed = False
        self.commit_state = "not-attempted"
        self.output_bytes = 0
        self.phases = {}
        self.previous = 0

    def now(self):
        return time.monotonic_ns()

    def before(self, deadline):
        now = self.now()
        self.root.runtime._integer(now, self.previous, self.root.runtime.U64_MAX)
        self.root.runtime._integer(deadline, 1, self.root.runtime.U64_MAX)
        if now >= deadline:
            raise TimeoutError("rooted host operation deadline")
        self.previous = now
        return min((deadline - now) / 1_000_000_000, 0.01)

    def check_gate(self, deadline):
        self.before(deadline)
        ancestors, gate, lock = admission_path(self.root, self.gate)
        if ancestors != self.gate_ancestors or gate != self.gate_identity:
            raise ValueError("rooted admission path changed")
        if lock != self.lock_identity:
            raise ValueError("rooted admission lock changed")
        self.before(deadline)

    def check_attempt(self, deadline):
        self.check_gate(deadline)
        self.runtime.artifact.check_directory(self.directory, self.directory_identity)
        named = os.stat(self.path.name, dir_fd=self.gate.root_fd, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != self.directory_identity:
            raise ValueError("rooted attempt path changed")
        self.before(deadline)

    def acquire(self, deadline):
        if self.gate is not None:
            raise ValueError("rooted host already acquired")
        self.before(deadline)
        self.witness.check(deadline)
        self.before(deadline)
        self.gate = self.gate_factory(deadline)
        self.gate_ancestors, self.gate_identity, self.lock_identity = admission_path(
            self.root, self.gate
        )
        self.check_gate(deadline)
        try:
            os.stat("active.json", dir_fd=self.gate.root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("prior rooted ownership unresolved")
        self.inputs = self.support.inputs.PreparedInputs.open(
            self.selection, self.root, deadline=deadline
        )
        self.path = self.gate.root / ("attempt-" + self.spec.run_id)
        os.mkdir(self.path.name, 0o700, dir_fd=self.gate.root_fd)
        self.directory = os.open(
            self.path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=self.gate.root_fd,
        )
        info = os.fstat(self.directory)
        self.directory_identity = info.st_dev, info.st_ino
        self.check_attempt(deadline)
        os.fsync(self.gate.root_fd)
        self.boot_id = boot_id()
        self.coordinates = self.host_observer(deadline)
        plan = dict(
            self.inputs.identities(),
            scope="contained-job-root-plan-v1",
            run_id=self.spec.run_id,
            uid=os.getuid(),
            gid=os.getgid(),
            attempt={
                "path": str(self.path),
                "device": info.st_dev,
                "inode": info.st_ino,
            },
            host_namespaces=self.coordinates["host_namespaces"],
            host_api=self.coordinates["host_api"],
        )
        manifest = self.inputs.runtime.manifest
        bootstrap = manifest["bootstrap"]
        plan["launcher"] = {
            "path": "/" + bootstrap,
            "sha256": next(
                member["sha256"]
                for member in manifest["members"]
                if member["path"] == bootstrap
            ),
        }
        client = {
            "pid": os.getpid(),
            "uid": os.getuid(),
            "gid": os.getgid(),
            "starttime": self.runtime.native.process_start(os.getpid()),
        }
        self.before(deadline)
        origin = self.now()
        self.config = self.runtime.protocol.make_config(
            self.spec,
            plan,
            client,
            origin,
            self.inputs.manifest,
            self.runtime.protocol.Dependencies(self.root, self.runtime.artifact),
        )
        self.value = self.runtime.protocol.decode_config(
            self.config.data,
            self.config.sha256,
            self.inputs.manifest,
            self.runtime.protocol.Dependencies(self.root, self.runtime.artifact),
        )
        self.before(deadline)

    def write(self, name, data, deadline):
        if (
            name not in RECEIPTS
            or type(data) is not bytes
            or (name == "host-witness" and data is not self.witness.data)
        ):
            raise ValueError("rooted host receipt selection")
        self.check_attempt(deadline)
        # The witness has its own cap (HOST_WITNESS_LIMIT), outside the budget.
        if name != "host-witness":
            if self.output_bytes + len(data) > self.root.guardian.HOST_RECEIPT_BUDGET:
                raise ValueError("rooted host receipt budget")
            self.output_bytes += len(data)
        with self.runtime.artifact.owned(
            os.open(
                name + ".json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=self.directory,
            )
        ) as fd:
            offset = 0
            while offset < len(data):
                self.before(deadline)
                count = os.write(fd, data[offset : offset + 65536])
                if count <= 0:
                    raise OSError("short rooted host receipt")
                offset += count
            os.fchmod(fd, 0o400)
            os.fsync(fd)
            os.fsync(self.directory)
            self.check_attempt(deadline)
        self.before(deadline)

    def prepare(self, config, manifest, deadline):
        if (
            config != self.config
            or manifest != self.inputs.manifest
            or self.claim_attempted
        ):
            raise ValueError("rooted host preparation binding")
        self.write("host-witness", self.witness.data, deadline)
        self.write("guardian-config", config.data, deadline)
        endpoint = str(self.path / "control.sock")
        if len(os.fsencode(endpoint)) >= 108:
            raise ValueError("rooted control endpoint too long")
        self.listener = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC,
        )
        self.listener.bind(endpoint)
        os.chmod(endpoint, 0o600)
        self.listener.listen(1)
        intent = self.root.closure.canonical(
            {
                "scope": INTENT_SCOPE,
                "config_sha256": config.sha256,
                "run_id": self.spec.run_id,
                "unit": self.root.guardian.unit_name(self.spec),
                "path": str(self.path),
                "client": self.value["client"],
                "host_witness_sha256": self.witness_sha256,
            }
        )
        self.write("host-intent", intent, deadline)
        # Claim includes hex encoding; reserve room for it and failure diagnostics.
        if (
            self.output_bytes + 2 * len(intent) + 512
            > self.root.guardian.HOST_RECEIPT_BUDGET - 48 * 1024
        ):
            raise ValueError("rooted host diagnostic reserve")
        self.check_attempt(deadline)
        # A change during admission or input preparation (an NSS module for
        # getpwuid, guardian-service.py:661) refuses before the blocker
        # exists, so abort closes the gate.
        self.witness.check(deadline)
        self.claim_attempted = True
        self.gate.claim(self.spec.run_id, intent, deadline)
        self.output_bytes += len(self.gate.record)
        self.before(deadline)

    def phase_recheck(self, name, deadline):
        if name in self.phases:
            raise ValueError("rooted host phase already checked")
        start = self.now()
        self.before(deadline)
        self.inputs.recheck(deadline)
        self.check_attempt(deadline)
        if self.host_observer(deadline) != self.coordinates:
            raise ValueError("rooted host coordinates changed")
        self.witness.check(deadline)
        self.before(deadline)
        self.phases[name] = {
            "started_ns": start,
            "finished_ns": self.now(),
            "deadline_ns": deadline,
        }

    def active_identity(self, row):
        argv = self.root.entry_argv(self.value["root_plan"], self.config.sha256)
        if row["ExecStart"] != ((argv[0], argv, False),):
            raise ValueError("rooted host guardian executable mismatch")
        keys = (
            (set(self.root.guardian.service_properties(self.spec)) - {"AddRef"})
            | set(self.runtime.native.service.UNIT_TYPES)
            | {"MainPID", "ControlGroup", "ExecMainStartTimestampMonotonic"}
        )
        return self.root.guardian.check_service(
            {key: row[key] for key in keys},
            self.spec,
            row["MainPID"],
            os.getuid(),
            self.now(),
        )

    def start(self, config, deadline):
        if (
            config != self.config
            or not self.claim_attempted
            or self.gate.record is None
            or self.bus is not None
            or self.aborted
        ):
            raise ValueError("rooted service lacks exclusive durable intent")
        deadline = min(deadline, self.value["startup_deadline_ns"])
        self.phase_recheck("prestart", deadline)
        # Descriptor passing lets check_peer resolve the peer's pidfd.
        self.bus = self.bus_factory(os.getuid(), deadline=deadline, fds=True)
        self.adapter = LeaseBus(
            config, self.inputs.manifest, self.support, self.bus, self.bus_bridge
        )
        self.lease = self.runtime.native.service.UnitLease(
            self.adapter.name, self.adapter, now=self.now
        )
        self.lease.create(self.adapter.properties, self.adapter.argv, deadline)
        for _ in range(self.root.guardian.IO_LIMIT):
            delay = self.before(deadline)
            row = self.lease.observe(deadline)
            if row["ActiveState"] == "active" and row["SubState"] == "running":
                self.identity = self.active_identity(row)
                # From the same Service reply as the row: G binds by it.
                self.service_cgroup_id = self.adapter.last_cgroup_id
                self.lease.bind(row)
                self.write(
                    "host-started",
                    self.root.closure.canonical(
                        {
                            "service": self.identity._asdict(),
                            "cgroup_id": self.service_cgroup_id,
                            "creation_reply": self.lease.creation_reply,
                        }
                    ),
                    deadline,
                )
                return self.identity
            if row["ActiveState"] not in ("activating", "active"):
                raise ValueError("rooted guardian failed during startup")
            time.sleep(delay)
        raise ValueError("rooted guardian startup event cap")

    def process_start(self, identity, deadline):
        if identity != self.identity:
            raise ValueError("rooted process identity mismatch")
        self.before(deadline)
        start = self.runtime.native.process_start(identity.pid)
        self.root.runtime._integer(start, 1, self.root.runtime.U64_MAX)
        self.before(deadline)
        self.starttime = start
        return start

    def cgroup_id(self, identity, deadline):
        """The manager's ControlGroupId recorded with the bound identity."""
        if self.identity is None or identity != self.identity:
            raise ValueError("rooted cgroup identity mismatch")
        self.before(deadline)
        self.root.runtime._integer(self.service_cgroup_id, 1, self.root.runtime.U64_MAX)
        return self.service_cgroup_id

    def check_peer(self, deadline):
        self.channel.check(deadline)
        start = self.runtime.native.process_start(self.identity.pid)
        # The manager names the unit and invocation holding the connected
        # peer's pidfd (SO_PEERPIDFD), independent of PID numbers.
        invocation = self.adapter.bridge.process_invocation(
            self.config, self.inputs.manifest, self.channel.peer_fd, deadline
        )
        self.channel.check(deadline)
        if type(start) is not int or start != self.starttime:
            raise ValueError("rooted connected guardian starttime changed")
        if invocation != self.identity.invocation_id:
            raise ValueError("rooted connected guardian invocation")

    def connect(self, identity, deadline):
        if (
            identity != self.identity
            or self.channel is not None
            or self.starttime is None
            or self.aborted
        ):
            raise ValueError("rooted host connection state")
        for _ in range(self.root.guardian.IO_LIMIT):
            delay = self.before(deadline)
            try:
                connected, _ = self.listener.accept()
            except BlockingIOError:
                select.select([self.listener], [], [], delay)
                continue
            # PeerChannel takes ownership even when its constructor fails.
            self.channel = self.root.guardian.PeerChannel(
                connected, (identity.pid, os.getuid(), os.getgid())
            )
            self.check_peer(deadline)
            listener, self.listener = self.listener, None
            listener.close()
            self.recheck(identity, self.starttime, deadline)
            return
        raise ValueError("rooted host connection event cap")

    def recheck(self, identity, starttime, deadline):
        if (
            self.aborted
            or identity != self.identity
            or type(starttime) is not int
            or starttime != self.starttime
        ):
            raise ValueError("rooted host recheck identity")
        self.check_attempt(deadline)
        # A lazy import or dlopen in the window refuses before COMMIT.
        self.witness.check(deadline)
        row = self.lease.observe(deadline)
        if (
            self.active_identity(row) != identity
            or self.adapter.last_cgroup_id != self.service_cgroup_id
        ):
            raise ValueError("rooted guardian changed before commit")
        self.check_peer(deadline)

    def send(self, data, deadline):
        self.before(deadline)
        committing = self.root.guardian.decode(data)["kind"] == "commit"
        self.channel.send(data, deadline, allow_exit_after_send=committing)
        if committing:
            self.committed = True

    def receive(self, deadline):
        self.before(deadline)
        return self.channel.receive(deadline, allow_exit=self.committed)

    def expect_eof(self, deadline):
        self.channel.expect_eof(deadline)

    def attempt_fd(self, deadline):
        self.check_attempt(deadline)
        return self.directory

    def close_control(self):
        errors = []
        for name in ("channel", "listener"):
            value = getattr(self, name)
            setattr(self, name, None)
            if value is not None:
                try:
                    value.close()
                except CLEANUP_FAILURES as error:
                    errors.append(error)
        self.runtime.native.raise_errors("rooted host control cleanup", errors)

    def close_directory(self):
        fd, self.directory = self.directory, None
        if fd is not None:
            os.close(fd)

    def wait_terminal(self, identity, deadline):
        if identity != self.identity:
            raise ValueError("rooted terminal identity")
        for _ in range(self.root.guardian.IO_LIMIT):
            delay = self.before(deadline)
            row = self.lease.observe(deadline)
            self.lease.same_invocation(row)
            if row["ActiveState"] == "inactive" and row["SubState"] == "dead":
                row = self.lease.verify_terminal(
                    deadline, self.value["startup_deadline_ns"]
                )
                return {"unit": row, "processes": self.lease.last_processes}
            if row["ActiveState"] == "failed":
                raise ValueError("rooted guardian failed after DONE")
            time.sleep(delay)
        raise ValueError("rooted terminal event cap")

    def finish(self, data, deadline):
        if self.completed is not None or self.lease is None or not self.lease.terminal:
            raise ValueError("rooted completion lacks terminal proof")
        self.write("host-finished", data, deadline)
        self.completed = data

    def active_state(self):
        if self.gate is None or self.gate.root_fd is None:
            return "uncertain"
        try:
            os.stat("active.json", dir_fd=self.gate.root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return "absent"
        except (OSError, TypeError):
            return "uncertain"
        return "present"

    def complete(self, record):
        if (
            self.aborted
            or self.completed is None
            or self.completed != self.root.closure.canonical(record)
            or self.lease is None
            or not self.lease.terminal
        ):
            raise ValueError("rooted completion record mismatch")
        deadline = self.value["startup_deadline_ns"] + self.root.guardian.STOP_NS
        self.phase_recheck("postservice", deadline)
        errors = []
        for close in (
            self.close_control,
            self.close_directory,
            lambda: self.lease.release(deadline),
            self.inputs.close,
        ):
            try:
                close()
            except CLEANUP_FAILURES as error:
                errors.append(error)
        self.runtime.native.raise_errors("rooted completion cleanup", errors)
        proof = self.root.closure.canonical(
            {
                "scope": "contained-job-rooted-host-completion-v2",
                "startup": record,
                "host_witness_sha256": self.witness_sha256,
                "phase_checks": self.phases,
                "non_gate_handles_closed": True,
            }
        )
        if self.output_bytes + len(proof) > self.root.guardian.HOST_RECEIPT_BUDGET:
            raise ValueError("rooted completion receipt budget")
        self.output_bytes += len(proof)
        self.check_gate(deadline)
        self.commit_state = "uncertain"
        try:
            self.gate.complete(proof, deadline)
        except BaseException:
            self.commit_state = self.active_state()
            raise
        self.commit_state = "absent"
        self.gate.close()
        self.before(deadline)

    def abort(self, config, identity, reason, deadline):
        if self.aborted:
            return
        self.aborted = True
        errors = []
        try:
            self.close_control()
        except CLEANUP_FAILURES as error:
            errors.append(error)
        lease = self.lease
        row = None if lease is None else lease.last_observation
        observed = (
            {key: row.get(key) for key in FAILURE_OBSERVATION}
            if type(row) is dict
            else None
        )
        reply = None if lease is None else lease.creation_reply
        if reply is None and self.adapter is not None:
            # The bridge keeps a reply that arrived after its deadline.
            late = self.adapter.bridge.start_reply
            if type(late) is str and re.fullmatch(JOB_PATH, late) is not None:
                reply = late
        invocation = source = stop_error = None
        # A created service is stopped even when it was refused before binding.
        if lease is not None and lease.created and not lease.terminal:
            end = deadline - FAILURE_RECORD_NS
            try:
                try:
                    owned = lease.cleanup_identity()
                except ValueError:
                    # Refused inside its first observation: pin the current
                    # invocation of the unit this lease created, then observe it.
                    owned = self.adapter.pin_cleanup(end)
                    # Recorded even when the observation below refuses the stop.
                    invocation, source = owned["InvocationID"], "cleanup"
                    lease.observe(end)
                else:
                    invocation = owned["InvocationID"]
                    source = "bound" if lease.bound is not None else "observation"
                    self.adapter.enter_cleanup(owned)
                lease.stop(end)
            except CLEANUP_FAILURES as error:
                errors.append(error)
                stop_error = type(error).__name__
        elif lease is not None and lease.bound is not None:
            invocation, source = lease.bound["InvocationID"], "bound"
        if self.gate is not None and self.claim_attempted:
            if self.commit_state != "absent":
                self.commit_state = self.active_state()
            try:
                self.check_gate(deadline)
                # created: this lease validated a creation reply in time; a late
                # reply can still appear in creation_reply. invocation_source is
                # bound, observation (startup row), cleanup (pinned at abort) or
                # null; observed is the last startup row before any stop.
                failure = self.root.closure.canonical(
                    {
                        "scope": "contained-job-rooted-host-failure-v2",
                        "run_id": self.spec.run_id,
                        "reason": reason,
                        "admission_state": self.commit_state,
                        "boot_id": self.boot_id,
                        "creation_attempted": lease is not None
                        and lease.creation_attempted,
                        "created": lease is not None and lease.created,
                        "creation_reply": reply,
                        "invocation_id": invocation,
                        "invocation_source": source,
                        "observed": observed,
                        "stop_attempted": lease is not None and lease.stop_attempted,
                        "stop_reply": (
                            lease.stop_reply
                            if lease is not None and type(lease.stop_reply) is str
                            else None
                        ),
                        "stop_error": stop_error,
                        "cleanup_errors": [type(error).__name__ for error in errors],
                        "native_authorized": False,
                        "full_contract_proven": False,
                    }
                )
                if (
                    self.output_bytes + len(failure)
                    > self.root.guardian.HOST_RECEIPT_BUDGET
                ):
                    raise ValueError("rooted failure receipt budget")
                self.output_bytes += len(failure)
                self.gate.write(
                    "failed-" + self.spec.run_id + ".json", failure, deadline
                )
            except CLEANUP_FAILURES as error:
                errors.append(error)
        retain_inputs = (
            self.lease is not None
            and self.lease.creation_attempted
            and not self.lease.terminal
        )
        if not retain_inputs:
            for close in (
                self.close_directory,
                self.inputs.close if self.inputs is not None else lambda: None,
            ):
                try:
                    close()
                except CLEANUP_FAILURES as error:
                    errors.append(error)
        # Never drop AddRef for an uncertain creation or nonterminal invocation.
        if self.bus is not None and (
            self.lease is None or not self.lease.creation_attempted
        ):
            try:
                self.bus.close()
            except CLEANUP_FAILURES as error:
                errors.append(error)
        elif (
            self.lease is not None
            and self.lease.terminal
            and not self.lease.close_attempted
        ):
            try:
                self.lease.release(deadline)
            except CLEANUP_FAILURES as error:
                errors.append(error)
        if self.claim_attempted or self.bus is not None:
            UNRESOLVED[self.spec.run_id] = self
        elif self.gate is not None:
            try:
                self.gate.close()
            except CLEANUP_FAILURES as error:
                errors.append(error)
                UNRESOLVED[self.spec.run_id] = self
        self.runtime.native.raise_errors("rooted host abort", errors)

    def run(self):
        if self.used or UNRESOLVED:
            raise ValueError("rooted host one-shot or unresolved prior ownership")
        self.used = True
        errors = []
        preparation_end = self.now() + PREPARE_NS
        try:
            self.acquire(preparation_end)
            witness_deps = self.runtime.witness.Dependencies(
                self.runtime.preflight, self.runtime.state
            )
            support = self.runtime.handshake.Dependencies(
                self.runtime.protocol,
                self.runtime.protocol.Dependencies(self.root, self.runtime.artifact),
                self.runtime.witness,
                witness_deps,
                self.runtime.artifact,
            )
            # H checks G's mapped rows with its own runtime's page digests.
            controller = self.runtime.handshake.Host(
                self.config,
                self.inputs.manifest,
                support,
                self,
                self.support.terminal_check,
                pages=self.inputs.runtime.pages,
            )
            record = controller.run()
            self.complete(record)
            return record
        except CLEANUP_FAILURES as error:
            errors.append(error)
        if not self.aborted:
            cleanup_end = (
                self.now() + self.root.guardian.STOP_NS
                if self.value is None
                else self.value["startup_deadline_ns"] + self.root.guardian.STOP_NS
            )
            try:
                self.abort(
                    self.config, self.identity, type(errors[0]).__name__, cleanup_end
                )
            except CLEANUP_FAILURES as error:
                errors.append(error)
        self.runtime.native.raise_errors("rooted host failure and cleanup", errors)


RESOLVE_NS = 30_000_000_000
RESOLUTION_SCOPE = "contained-job-rooted-failed-attempt-resolution-v2"
PROC_LIMIT = 65536
FD_LIMIT = 1 << 20
HEX32 = "[0-9a-f]{32}"
UNIT_PATH = r"/org/freedesktop/systemd1/unit/[A-Za-z0-9_]{1,255}"
PROPERTIES = "org.freedesktop.DBus.Properties"
# Files H or G can leave in an attempt directory, with their required type.
ATTEMPT_ENTRIES = {
    "control.sock": stat.S_ISSOCK,
    "guardian-config.json": stat.S_ISREG,
    "host-finished.json": stat.S_ISREG,
    "host-intent.json": stat.S_ISREG,
    "host-started.json": stat.S_ISREG,
    "host-witness.json": stat.S_ISREG,
    "startup-witness.json": stat.S_ISREG,
}
FAILURE_V1 = frozenset(
    (
        "scope",
        "run_id",
        "reason",
        "admission_state",
        "creation_attempted",
        "cleanup_errors",
        "native_authorized",
        "full_contract_proven",
    )
)
FAILURE_V2 = FAILURE_V1 | {
    "boot_id",
    "created",
    "creation_reply",
    "invocation_id",
    "invocation_source",
    "observed",
    "stop_attempted",
    "stop_reply",
    "stop_error",
}
# H's receipt of the invocation it bound (HostOwner.start). A killed H writes
# no failure record, so this is what it leaves.
STARTED_FIELDS = frozenset(("service", "cgroup_id", "creation_reply"))
# The manager's errors for a name it does not know, as SystemdBus raises them
# (guardian-service.py:196-200). Any other error refuses.
NO_UNIT = "user-bus error: org.freedesktop.systemd1.NoSuchUnit"
NO_INVOCATION = "user-bus error: org.freedesktop.systemd1.NoUnitForInvocationID"
SERVICE_FIELDS = (
    "Id",
    "InvocationID",
    "Transient",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "MainPID",
    "ExecMainPID",
    "ControlGroup",
    "ExecMainStartTimestampMonotonic",
    "ExecMainExitTimestampMonotonic",
    "ActiveEnterTimestampMonotonic",
    "ExecStart",
)


class Resolution(NamedTuple):
    record: bytes
    sha256: str
    committed: bool
    admission_state: str


class ReadOnlyBus:
    """The manager reads a resolver needs; no method can start or stop a unit."""

    METHODS = ("GetUnit", "GetAll", "GetUnitProcesses", "GetUnitByInvocationID")

    def __init__(self, bus):
        self._bus = bus

    def call(self, path, interface, method, signature, args, deadline):
        if method not in self.METHODS:
            raise ValueError("resolver bus method")
        return self._bus.call(path, interface, method, signature, args, deadline)

    def normal(self, variant, kind):
        return self._bus.normal(variant, kind)

    def close(self):
        self._bus.close()


def read_owned(directory, name, limit, mode=None):
    fd = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
        dir_fd=directory,
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
            or info.st_nlink != 1
            or not 0 < info.st_size <= limit
        ):
            raise ValueError("resolver input file: " + name)
        data = bytearray()
        while len(data) < info.st_size:
            part = os.read(fd, info.st_size - len(data))
            if not part:
                break
            data.extend(part)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            len(data) != info.st_size
            or os.read(fd, 1)
            or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise ValueError("resolver input file changed: " + name)
    finally:
        os.close(fd)
    return bytes(data), info


def observe_failed_unit(bus, transport, unit, deadline):
    path = bus.call(
        transport.MANAGER_PATH, transport.MANAGER, "GetUnit", "s", (unit,), deadline
    )
    if type(path) is not str or re.fullmatch(UNIT_PATH, path) is None:
        raise ValueError("resolver unit path")
    raw, row = {}, {}
    for name, kinds in (
        ("Unit", transport.UNIT_TYPES),
        ("Service", transport.PROPERTY_TYPES),
    ):
        values = bus.call(
            path,
            PROPERTIES,
            "GetAll",
            "s",
            (transport.BUS_NAME + "." + name,),
            deadline,
        )
        if type(values) is not dict or len(values) > 4096:
            raise ValueError("resolver property dictionary")
        raw[name] = values
        for key, kind in kinds.items():
            if key not in values:
                raise ValueError("missing D-Bus property: " + key)
            row[key] = bus.normal(values[key], kind)
    row["InvocationID"] = bytes(row["InvocationID"]).hex()
    row["ExecMainPID"] = bus.normal(raw["Service"].get("ExecMainPID"), "u")
    job, refs = raw["Unit"].get("Job"), raw["Unit"].get("Refs")
    if (
        type(job) is not tuple
        or len(job) != 2
        or job[0] != "(uo)"
        or type(job[1]) not in (tuple, list)
        or list(job[1]) != [0, "/"]
    ):
        raise ValueError("resolver unit has a queued job")
    if (
        type(refs) is not tuple
        or len(refs) != 2
        or refs[0] != "as"
        or type(refs[1]) not in (tuple, list)
        or len(refs[1]) != 0
    ):
        raise ValueError("resolver unit is still referenced")
    processes = bus.call(
        transport.MANAGER_PATH,
        transport.MANAGER,
        "GetUnitProcesses",
        "s",
        (unit,),
        deadline,
    )
    if type(processes) is not list or processes:
        raise ValueError("resolver unit still has processes")
    return row


def check_failed_unit(row, unit, invocation, argv, value, main_pid, tick):
    expected = {
        "Id": unit,
        "Transient": True,
        "InvocationID": invocation,
        "ActiveState": "failed",
        "SubState": "failed",
        "MainPID": 0,
        "ControlGroup": "",
        "Restart": "no",
        "ExecStartPre": (),
        "ExecStartPost": (),
        "ExecStop": (),
        "ExecStopPost": (),
        "ExecStart": ((argv[0], argv, False),),
    }
    for key, want in expected.items():
        if type(row[key]) is not type(want) or row[key] != want:
            raise ValueError("resolver unit state: " + key)
    start = row["ExecMainStartTimestampMonotonic"]
    end = row["ExecMainExitTimestampMonotonic"]
    # tick: the guardian's START_TICK_NS, the floor of a PrivatePIDs= start.
    if not value["origin_ns"] - tick <= start * 1000 <= value["startup_deadline_ns"]:
        raise ValueError("resolver unit start window")
    if not end >= start > 0:
        raise ValueError("resolver unit exit order")
    if row["ExecMainPID"] <= 1 or main_pid not in (None, row["ExecMainPID"]):
        raise ValueError("resolver unit main process")


def observe_unit_again(bus, transport, unit, deadline):
    """observe_failed_unit for a unit the manager answered for a moment ago.

    NoSuchUnit now means it changed. As a ValueError the refusal keeps that
    reason; reason() in measurement-job-host.py names a RuntimeError by class.
    """
    try:
        return observe_failed_unit(bus, transport, unit, deadline)
    except RuntimeError as error:
        if str(error) != NO_UNIT:
            raise
        raise ValueError("resolver unit changed during resolution") from error


def bind_invocation(bus, transport, unit, invocation, deadline):
    path = bus.call(
        transport.MANAGER_PATH,
        transport.MANAGER,
        "GetUnitByInvocationID",
        "ay",
        (bytes.fromhex(invocation),),
        deadline,
    )
    if type(path) is not str or re.fullmatch(UNIT_PATH, path) is None:
        raise ValueError("resolver invocation path")
    values = bus.call(
        path, PROPERTIES, "GetAll", "s", (transport.BUS_NAME + ".Unit",), deadline
    )
    if (
        type(values) is not dict
        or bus.normal(values.get("Id"), "s") != unit
        or bytes(bus.normal(values.get("InvocationID"), "ay")).hex() != invocation
    ):
        raise ValueError("resolver invocation binding")
    return path


def started_invocation(data, root, unit):
    """Invocation and main PID from H's host-started.json for this unit."""
    try:
        value = root.runtime._json(data)
    except ValueError as error:
        raise ValueError("resolver host start receipt") from error
    service = value.get("service") if type(value) is dict else None
    if (
        type(value) is not dict
        or root.closure.canonical(value) != data
        or set(value) != STARTED_FIELDS
        or type(value["creation_reply"]) is not str
        or re.fullmatch(JOB_PATH, value["creation_reply"]) is None
        or type(value["cgroup_id"]) is not int
        or value["cgroup_id"] <= 0
        or type(service) is not dict
        or set(service) != set(root.guardian.ServiceIdentity._fields)
        or service["unit"] != unit
        or type(service["invocation_id"]) is not str
        or re.fullmatch(HEX32, service["invocation_id"]) is None
        or service["invocation_id"] == "0" * 32
        or type(service["pid"]) is not int
        or service["pid"] <= 1
    ):
        raise ValueError("resolver host start receipt")
    return service["invocation_id"], service["pid"]


def unit_absent(bus, transport, unit, invocation, deadline):
    """The manager knows neither the unit nor the invocation a receipt names.

    False when the unit answers. True only on the manager's exact errors; any
    other error propagates and refuses. A running or failed unit stays loaded,
    so this means a unit that never started or ended without failing and lost
    its reference; the caller's window guard covers one still being created.
    """
    try:
        bus.call(
            transport.MANAGER_PATH, transport.MANAGER, "GetUnit", "s", (unit,), deadline
        )
    except RuntimeError as error:
        if str(error) != NO_UNIT:
            raise
    else:
        return False
    if invocation is None:
        return True
    try:
        bus.call(
            transport.MANAGER_PATH,
            transport.MANAGER,
            "GetUnitByInvocationID",
            "ay",
            (bytes.fromhex(invocation),),
            deadline,
        )
    except RuntimeError as error:
        if str(error) != NO_INVOCATION:
            raise
        return True
    raise ValueError("resolver invocation without its unit")


def unit_cgroups(unit, uid, base="/sys/fs/cgroup"):
    """Directories named after the unit below the user manager, depth-limited."""
    root = Path(base) / f"user.slice/user-{uid}.slice/user@{uid}.service"
    if not stat.S_ISDIR(os.stat(root, follow_symlinks=False).st_mode):
        raise ValueError("resolver user manager cgroup")
    found, seen, frontier = [], 0, [(root, 0)]
    while frontier:
        path, depth = frontier.pop()
        try:
            entries = list(os.scandir(path))
        except FileNotFoundError:
            continue
        for entry in entries:
            seen += 1
            if seen > PROC_LIMIT:
                raise ValueError("resolver cgroup scan cap")
            if not entry.is_dir(follow_symlinks=False):
                continue
            if entry.name == unit:
                found.append(str(Path(entry.path).relative_to(root)))
            elif depth < 3:
                frontier.append((Path(entry.path), depth + 1))
    return sorted(found)


def own_namespaces(names):
    return {name: os.stat(f"/proc/self/ns/{name}").st_ino for name in names}


def scan_processes(targets, unit, before_tick, *, proc="/proc", pids=None):
    """Find any process that may belong to the attempt; fails closed.

    A same-user process whose files cannot be inspected is accepted only when
    its /proc start tick is earlier than before_tick, the attempt owner's own
    start tick on the same clock: the guardian and every descendant started
    later. A process whose real or effective uid differs (a setuid helper) is
    foreign: under NoNewPrivileges no guardian descendant can become one.
    """
    uid, own = os.getuid(), os.getpid()
    if pids is None:
        pids = [int(name) for name in os.listdir(proc) if name.isdigit()]
    if len(pids) > PROC_LIMIT:
        raise ValueError("resolver process scan cap")
    summary = {"processes": 0, "same_uid": 0, "unreadable_before_owner": 0}
    matches, descriptors = [], 0
    for pid in sorted(pids):
        if pid == own:
            continue
        base = f"{proc}/{pid}"
        try:
            with open(base + "/stat", "rb") as file:
                row = file.read(4097)
            with open(base + "/status", "rb") as file:
                status = file.read(65536)
            with open(base + "/cgroup", "rb") as file:
                cgroup = file.read(65536)
        except (FileNotFoundError, ProcessLookupError):
            continue
        summary["processes"] += 1
        fields = row.rpartition(b") ")[2].split()
        uids = [
            line.split()[1:3] for line in status.splitlines() if line[:4] == b"Uid:"
        ]
        if len(row) > 4096 or len(fields) < 20 or len(uids) != 1:
            raise ValueError("resolver process identity")
        if any(
            unit.encode() in line.split(b":", 2)[-1].split(b"/")
            for line in cgroup.splitlines()
        ):
            matches.append({"pid": pid, "via": ["cgroup"]})
            continue
        if uids[0] != [str(uid).encode()] * 2:
            continue
        summary["same_uid"] += 1
        hits = set()
        try:
            for name in ("exe", "cwd", "root"):
                try:
                    info = os.stat(f"{base}/{name}")
                except FileNotFoundError:
                    continue
                if (info.st_dev, info.st_ino) in targets:
                    hits.add(name)
            try:
                entries = os.listdir(base + "/fd")
            except FileNotFoundError:
                entries = []
            descriptors += len(entries)
            if descriptors > FD_LIMIT:
                raise ValueError("resolver descriptor scan cap")
            for entry in entries:
                try:
                    info = os.stat(f"{base}/fd/{entry}")
                except FileNotFoundError:
                    continue
                if (info.st_dev, info.st_ino) in targets:
                    hits.add("fd")
        except PermissionError:
            if hits:
                matches.append({"pid": pid, "via": sorted(hits) + ["unreadable"]})
            elif int(fields[19]) >= before_tick:
                matches.append({"pid": pid, "via": ["unreadable-after-owner"]})
            else:
                summary["unreadable_before_owner"] += 1
            continue
        if hits:
            matches.append({"pid": pid, "via": sorted(hits)})
    summary["matches"] = matches
    return summary


def resolve_failed_startup(
    run_id,
    runtime,
    *,
    witness=None,
    invocation_id=None,
    commit=False,
    gate_factory=None,
    bus_factory=None,
    process_start=None,
    process_scan=None,
    cgroup_scan=None,
    namespaces=None,
    now=time.monotonic_ns,
):
    """Clear the admission blocker of a startup attempt whose H has exited.

    witness is this process's witness for exactly this run and commit flag;
    None (the default) refuses. Everything is read-only until the final writes
    of the witness and the non-accepting resolved-<run>.json and the blocker
    unlink; with commit=False nothing is written. A v1 failure record needs the
    caller's invocation evidence, which the manager must bind.

    With no failure record H was lost: a SIGKILL never reaches abort. Then its
    host-started.json or the manager's row binds a failed unit, or the manager
    knows none and G's startup window has passed.
    """
    transport = runtime.native.service
    deadline = now() + RESOLVE_NS
    uid = os.getuid()
    if UNRESOLVED or uid == 0 or os.geteuid() != uid:
        raise ValueError("resolver needs an unprivileged, unowned process")
    if (
        type(run_id) is not str
        or re.fullmatch("[a-z0-9][a-z0-9-]{0,63}", run_id) is None
    ):
        raise ValueError("resolver run ID")
    if invocation_id is not None and (
        type(invocation_id) is not str
        or re.fullmatch(HEX32, invocation_id) is None
        or invocation_id == "0" * 32
    ):
        raise ValueError("resolver invocation ID")
    witness_sha256 = check_resolver_witness(
        witness, run_id, commit, runtime.preflight.root
    )
    witness.check(deadline)
    gate = (gate_factory or transport.AdmissionGate.for_current_user)(deadline)
    owned, errors, result = {"bus": None}, [], None
    try:
        result = _resolve(
            run_id,
            runtime,
            gate,
            owned,
            witness,
            witness_sha256,
            invocation_id,
            commit,
            deadline,
            bus_factory or transport.SystemdBus,
            process_start or runtime.native.process_start,
            process_scan or scan_processes,
            cgroup_scan or unit_cgroups,
            namespaces or own_namespaces,
            now,
        )
    except CLEANUP_FAILURES as error:
        errors.append(error)
    for close in (owned["bus"], gate):
        if close is not None:
            try:
                close.close()
            except CLEANUP_FAILURES as error:
                errors.append(error)
    runtime.native.raise_errors("rooted failed-attempt resolution", errors)
    return result


def _resolve(
    run_id,
    runtime,
    gate,
    owned,
    witness,
    witness_sha256,
    invocation_id,
    commit,
    deadline,
    bus_factory,
    process_start,
    process_scan,
    cgroup_scan,
    namespaces,
    now,
):
    root = runtime.preflight.root
    transport = runtime.native.service
    uid = os.getuid()

    def check():
        if now() >= deadline:
            raise TimeoutError("resolver deadline")

    gate_path = admission_path(root, gate)
    try:
        blocker, blocker_identity = gate.read_blocker(deadline)
    except FileNotFoundError as error:
        raise ValueError("resolver found no blocker") from error
    try:
        claim = json.loads(blocker)
        intent = bytes.fromhex(claim["intent_hex"])
        exact = gate.encode_claim(claim["run_id"], intent) == blocker
    except (TypeError, ValueError, KeyError) as error:
        raise ValueError("resolver blocker format") from error
    if not exact or claim["run_id"] != run_id:
        raise ValueError("resolver blocker format")
    for prefix in ("terminal-", "resolved-"):
        try:
            os.stat(
                prefix + run_id + ".json", dir_fd=gate.root_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            continue
        raise FileExistsError("resolver outcome already recorded")

    failure_name = "failed-" + run_id + ".json"
    # A failure record always wins. Only a missing one means a lost owner; a
    # symlink (ELOOP) or a bad record refuses.
    try:
        failure_data, failure_info = read_owned(
            gate.root_fd, failure_name, 65536, 0o600
        )
    except FileNotFoundError:
        failure_data = failure_info = None
    lost = failure_data is None
    invocation = source = main_pid = None
    if lost:
        if invocation_id is not None:
            raise ValueError("resolver lost owner with caller evidence")
    else:
        failure = root.runtime._json(failure_data)
        keys = {
            "contained-job-rooted-host-failure-v1": FAILURE_V1,
            "contained-job-rooted-host-failure-v2": FAILURE_V2,
        }.get(failure.get("scope") if type(failure) is dict else None)
        if (
            keys is None
            or root.closure.canonical(failure) != failure_data
            or set(failure) != keys
            or failure["run_id"] != run_id
            or failure["admission_state"] != "present"
            or failure["creation_attempted"] is not True
            or failure["native_authorized"] is not False
            or failure["full_contract_proven"] is not False
        ):
            raise ValueError("resolver failure record shape")
        if keys is FAILURE_V2:
            # A record with uncertain creation (created false) is never resolved
            # here. This covers records only: a missing record is a lost owner.
            if (
                invocation_id is not None
                or failure["created"] is not True
                or type(failure["invocation_id"]) is not str
                or re.fullmatch(HEX32, failure["invocation_id"]) is None
                or failure["invocation_id"] == "0" * 32
                or failure["boot_id"] != boot_id()
            ):
                raise ValueError("resolver v2 failure record")
            invocation, source = failure["invocation_id"], "failure-record"
            observed = failure["observed"]
            # MainPID 0 means no main process at that moment, not a pid claim.
            if type(observed) is dict and type(observed.get("MainPID")) is int:
                main_pid = observed["MainPID"] if observed["MainPID"] > 1 else None
        elif invocation_id is None:
            raise ValueError(
                "resolver needs caller invocation evidence for a v1 record"
            )
        else:
            invocation, source = invocation_id, "caller-evidence"

    attempt_name = "attempt-" + run_id
    attempt_path = str(gate.root / attempt_name)
    targets = {
        gate_path[1]: "admission-directory",
        gate_path[2]: "admission.lock",
        blocker_identity: "active.json",
    }
    if not lost:
        targets[(failure_info.st_dev, failure_info.st_ino)] = failure_name
    entries = []
    started_data = None
    directory = os.open(
        attempt_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=gate.root_fd,
    )
    try:
        attempt = os.fstat(directory)
        if attempt.st_uid != uid or stat.S_IMODE(attempt.st_mode) != 0o700:
            raise ValueError("resolver attempt directory")
        targets[(attempt.st_dev, attempt.st_ino)] = attempt_name
        for name in sorted(os.listdir(directory)):
            check()
            kind = ATTEMPT_ENTRIES.get(name)
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (
                kind is None
                or not kind(info.st_mode)
                or info.st_uid != uid
                or info.st_mode & 0o077
                or info.st_nlink != 1
            ):
                raise ValueError("resolver attempt entry: " + name)
            digest = None
            if stat.S_ISREG(info.st_mode):
                data, _ = read_owned(directory, name, 1 << 20)
                digest = hashlib.sha256(data).hexdigest()
            kind = "file" if digest is not None else "socket"
            entries.append([name, kind, info.st_size, digest])
            targets[(info.st_dev, info.st_ino)] = attempt_name + "/" + name
        intent_data, _ = read_owned(directory, "host-intent.json", 65536, 0o400)
        config_data, _ = read_owned(
            directory, "guardian-config.json", runtime.protocol.CONFIG_LIMIT, 0o400
        )
        try:
            witness_data, _ = read_owned(
                directory, "host-witness.json", HOST_WITNESS_LIMIT, 0o400
            )
        except FileNotFoundError as error:
            raise ValueError("resolver host witness") from error
        if lost:
            try:
                started_data, _ = read_owned(
                    directory, "host-started.json", 65536, 0o400
                )
            except FileNotFoundError:
                pass
    finally:
        os.close(directory)

    # v2 intents only: an attempt left unresolved with a v1 intent is
    # resolved by the resolver of the commit that wrote it.
    plan_intent = root.runtime._json(intent_data)
    if (
        intent_data != intent
        or root.closure.canonical(plan_intent) != intent
        or type(plan_intent) is not dict
        or set(plan_intent) != INTENT_FIELDS
        or plan_intent["scope"] != INTENT_SCOPE
        or plan_intent["run_id"] != run_id
        or plan_intent["path"] != attempt_path
    ):
        raise ValueError("resolver intent binding")
    if plan_intent["host_witness_sha256"] != hashlib.sha256(witness_data).hexdigest():
        raise ValueError("resolver host witness")
    value = runtime.protocol.decode_header(
        config_data,
        plan_intent["config_sha256"],
        runtime.protocol.Dependencies(root, runtime.artifact),
    )
    plan = value["root_plan"]
    selection = value["host_spec"]
    spec = root.guardian.Specification(
        **dict(
            selection, cpus=tuple(selection["cpus"]), cases=tuple(selection["cases"])
        )
    )
    unit = root.guardian.unit_name(spec)
    if (
        plan["attempt"]
        != {"path": attempt_path, "device": attempt.st_dev, "inode": attempt.st_ino}
        or value["client"] != plan_intent["client"]
        or unit != plan_intent["unit"]
        or spec.run_id != run_id
    ):
        raise ValueError("resolver configuration binding")
    if started_data is not None:
        invocation, main_pid = started_invocation(started_data, root, unit)
        source = "host-started"
    argv = root.entry_argv(plan, plan_intent["config_sha256"])
    # /proc and pid checks prove nothing from another namespace than H's.
    if namespaces(tuple(plan["host_namespaces"])) != plan["host_namespaces"]:
        raise ValueError("resolver must run in the attempt owner's namespaces")
    targets[(plan["root"]["device"], plan["root"]["inode"])] = "native-root"
    try:
        launcher = os.stat(
            plan["root"]["path"] + plan["launcher"]["path"], follow_symlinks=False
        )
    except FileNotFoundError:
        pass
    else:
        targets[(launcher.st_dev, launcher.st_ino)] = "launcher"

    client = value["client"]
    try:
        start = process_start(client["pid"])
    except (FileNotFoundError, ProcessLookupError):
        client_state = "absent"
    else:
        if type(start) is not int or start == client["starttime"]:
            raise ValueError("resolver attempt owner is alive")
        client_state = "reused"
    check()

    owned["bus"] = bus = ReadOnlyBus(bus_factory(uid, deadline=deadline))
    absent = lost and unit_absent(bus, transport, unit, invocation, deadline)
    row = manager_path = None
    if absent:
        # Past G's own deadline a late-created G refuses before any write
        # (rooted-native.py:465-467), and a bound unit cannot be mid-startup.
        if now() < value["startup_deadline_ns"] + root.guardian.STOP_NS:
            raise ValueError("resolver startup window still open")
    else:
        observe = observe_unit_again if lost else observe_failed_unit
        row = observe(bus, transport, unit, deadline)
        if invocation is None:
            # H died before its receipt. ExecStart, compared below, carries the
            # config digest (measurement-job-root.py:297-305).
            invocation, source = row["InvocationID"], "manager"
            if re.fullmatch(HEX32, invocation) is None or invocation == "0" * 32:
                raise ValueError("resolver manager invocation")
        check_failed_unit(
            row, unit, invocation, argv, value, main_pid, root.guardian.START_TICK_NS
        )
        manager_path = bind_invocation(bus, transport, unit, invocation, deadline)
    if cgroup_scan(unit, uid):
        raise ValueError("resolver unit cgroup remains")
    check()
    scan = process_scan(targets, unit, client["starttime"])
    if scan["matches"]:
        raise ValueError("resolver found attempt processes")
    check()

    if absent:
        if not unit_absent(bus, transport, unit, invocation, deadline):
            raise ValueError("resolver unit changed during resolution")
    elif observe_unit_again(bus, transport, unit, deadline) != row:
        raise ValueError("resolver unit changed during resolution")
    # G does not check H while it binds, encodes and writes its witness
    # (rooted-handshake.py:176-205), so a lost owner allows a late file.
    directory = os.open(
        attempt_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=gate.root_fd,
    )
    try:
        current = os.fstat(directory)
        names = sorted(os.listdir(directory))
    finally:
        os.close(directory)
    if names != [entry[0] for entry in entries] or (
        current.st_dev,
        current.st_ino,
    ) != (attempt.st_dev, attempt.st_ino):
        raise ValueError("resolver attempt entries changed")
    if admission_path(root, gate) != gate_path:
        raise ValueError("resolver admission path changed")
    again, identity = gate.read_blocker(deadline, len(blocker))
    if again != blocker or identity != blocker_identity:
        raise ValueError("resolver blocker changed")
    check()
    witness_name = f"resolver-witness-{run_id}-{witness_sha256[:16]}.json"
    record = root.closure.canonical(
        {
            "scope": RESOLUTION_SCOPE,
            "run_id": run_id,
            "outcome": "lost-owner-resolved" if lost else "failed-attempt-resolved",
            "unit_state": "absent" if absent else "failed",
            "accepted": False,
            "startup_complete": False,
            "native_authorized": False,
            "full_contract_proven": False,
            "blocker": {
                "sha256": hashlib.sha256(blocker).hexdigest(),
                "size": len(blocker),
                "device": blocker_identity[0],
                "inode": blocker_identity[1],
                "hex": blocker.hex(),
            },
            "intent_sha256": claim["intent_sha256"],
            "config_sha256": plan_intent["config_sha256"],
            "attempt": {
                "path": attempt_path,
                "device": attempt.st_dev,
                "inode": attempt.st_ino,
                "entries": entries,
            },
            "failure_record": None
            if lost
            else {
                "name": failure_name,
                "sha256": hashlib.sha256(failure_data).hexdigest(),
                "scope": failure["scope"],
                "reason": failure["reason"],
            },
            "invocation": {
                "id": invocation,
                "source": source,
                "manager_path": manager_path,
            },
            "client": {
                "pid": client["pid"],
                "starttime": client["starttime"],
                "state": client_state,
            },
            "service": None if absent else {key: row[key] for key in SERVICE_FIELDS},
            "service_processes": [],
            "cgroups": [],
            "host_scan": scan,
            "observed_monotonic_ns": now(),
            "boot_id": boot_id(),
            "resolver_witness": {
                "name": witness_name,
                "sha256": witness_sha256,
                "size": len(witness.data),
            },
        }
    )
    digest = hashlib.sha256(record).hexdigest()
    # An NSS module from the gate factory (guardian-service.py:661) or anything
    # else loaded while resolving refuses here, so a dry run predicts the commit.
    witness.check(deadline)
    if not commit:
        return Resolution(record, digest, False, "present")
    # Unique per process and read by no code: a dead resolver's copy blocks no retry.
    gate.write(witness_name, witness.data, deadline)
    gate.resolve_failed(blocker, blocker_identity, record, deadline)
    try:
        os.stat("active.json", dir_fd=gate.root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return Resolution(record, digest, True, "absent")
    raise ValueError("resolver blocker still present after commit")


def run_startup(selection, support, **factories):
    """Explicit trusted embedding API only; it can never start a virtual machine.

    factories carry the witness (required) and, for tests, the gate, bus and
    observer; measurement-job-host.py's startup-only mode is the embedder.
    """
    return HostOwner(selection, support, **factories).run()


if __name__ == "__main__":
    raise SystemExit(77)
