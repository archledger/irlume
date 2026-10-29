#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Concrete startup-only H ownership. No child or virtual machine is created."""

import os
import re
import select
import socket
import stat
import time
import types
from typing import NamedTuple


class Dependencies(NamedTuple):
    runtime: object
    inputs: types.ModuleType
    terminal_check: object


PREPARE_NS = 60_000_000_000
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


class LeaseBus:
    """Adapt one canonical rooted configuration to the retained UnitLease."""

    def __init__(self, config, manifest, support, bus):
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
        self.bridge = runtime.bus_bridge.RootedBus(
            bus,
            runtime.bus_bridge.Dependencies(
                runtime.protocol, deps, runtime.native.service
            ),
        )
        self.last_root = None
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


class HostOwner:
    """Retain admission, inputs and exact service ownership until gate commit."""

    def __init__(
        self,
        selection,
        support,
        *,
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
        self.selection, self.support = selection, support
        self.runtime = support.runtime
        self.root = self.runtime.preflight.root
        self.spec = selection.spec
        self.root.guardian.validate_spec(self.spec)
        self.gate_factory = (
            gate_factory or self.runtime.native.service.AdmissionGate.for_current_user
        )
        self.bus_factory = bus_factory or self.runtime.native.service.SystemdBus
        self.host_observer = host_observer or (
            lambda deadline: observe_host(self.runtime, deadline)
        )
        self.gate = self.inputs = self.directory = self.bus = self.adapter = (
            self.lease
        ) = None
        self.listener = self.channel = None
        self.config = self.value = self.identity = self.starttime = None
        self.completed = self.boot_id = None
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
        inputs = self.root.closure.inputs
        with inputs.opened_parent(self.gate.root) as (parent, ancestors):
            named = os.stat(self.gate.root.name, dir_fd=parent, follow_symlinks=False)
            actual = os.fstat(self.gate.root_fd)
            if (
                ancestors != self.gate_ancestors
                or (named.st_dev, named.st_ino) != self.gate_identity
                or (actual.st_dev, actual.st_ino) != self.gate_identity
                or not stat.S_ISDIR(actual.st_mode)
                or stat.S_IMODE(actual.st_mode) != 0o700
                or actual.st_uid != os.getuid()
            ):
                raise ValueError("rooted admission path changed")
        lock = os.fstat(self.gate.lock_fd)
        named = os.stat(
            "admission.lock", dir_fd=self.gate.root_fd, follow_symlinks=False
        )
        if (
            (lock.st_dev, lock.st_ino) != self.lock_identity
            or (named.st_dev, named.st_ino) != self.lock_identity
            or not stat.S_ISREG(lock.st_mode)
            or stat.S_IMODE(lock.st_mode) != 0o600
            or lock.st_uid != os.getuid()
            or lock.st_nlink != 1
        ):
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
        self.gate = self.gate_factory(deadline)
        info = os.fstat(self.gate.root_fd)
        self.gate_identity = info.st_dev, info.st_ino
        lock = os.fstat(self.gate.lock_fd)
        self.lock_identity = lock.st_dev, lock.st_ino
        with self.root.closure.inputs.opened_parent(self.gate.root) as (_, ancestors):
            self.gate_ancestors = ancestors
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
            self.coordinates["bus"],
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
            name
            not in ("guardian-config", "host-intent", "host-started", "host-finished")
            or type(data) is not bytes
        ):
            raise ValueError("rooted host receipt selection")
        self.check_attempt(deadline)
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
                "scope": "contained-job-rooted-host-intent-v1",
                "config_sha256": config.sha256,
                "run_id": self.spec.run_id,
                "unit": self.root.guardian.unit_name(self.spec),
                "path": str(self.path),
                "client": self.value["client"],
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
        self.bus = self.bus_factory(os.getuid(), deadline=deadline)
        self.adapter = LeaseBus(config, self.inputs.manifest, self.support, self.bus)
        self.lease = self.runtime.native.service.UnitLease(
            self.adapter.name, self.adapter, now=self.now
        )
        self.lease.create(self.adapter.properties, self.adapter.argv, deadline)
        for _ in range(self.root.guardian.IO_LIMIT):
            delay = self.before(deadline)
            row = self.lease.observe(deadline)
            if row["ActiveState"] == "active" and row["SubState"] == "running":
                self.identity = self.active_identity(row)
                self.lease.bind(row)
                self.write(
                    "host-started",
                    self.root.closure.canonical(
                        {
                            "service": self.identity._asdict(),
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

    def check_peer(self, deadline):
        self.channel.check(deadline)
        start = self.runtime.native.process_start(self.identity.pid)
        self.channel.check(deadline)
        if type(start) is not int or start != self.starttime:
            raise ValueError("rooted connected guardian starttime changed")

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
        row = self.lease.observe(deadline)
        if self.active_identity(row) != identity:
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
                "scope": "contained-job-rooted-host-completion-v1",
                "startup": record,
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
            controller = self.runtime.handshake.Host(
                self.config,
                self.inputs.manifest,
                support,
                self,
                self.support.terminal_check,
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


def run_startup(selection, support, **factories):
    """Explicit trusted embedding API only; it can never start a virtual machine."""
    return HostOwner(selection, support, **factories).run()


if __name__ == "__main__":
    raise SystemExit(77)
