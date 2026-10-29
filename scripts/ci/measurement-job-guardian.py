#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Private guardian protocol. Ordinary invocation never launches a process."""

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import select
import socket
import struct
import time
from builtins import BaseExceptionGroup
from pathlib import Path
from typing import NamedTuple


class SourceLoader(importlib.machinery.SourceFileLoader):
    """Bootstrap from source without trusting this entry's adjacent caches."""

    def get_code(self, fullname):
        self.source = self.get_data(self.path)
        return self.source_to_code(self.source, self.path)


LOADER = SourceLoader(
    "guardian_evidence", str(Path(__file__).with_name("measurement-job-evidence.py"))
)
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
evidence = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(evidence)
evidence.__source_sha256__ = hashlib.sha256(LOADER.source).hexdigest()
runtime = evidence.runtime
CONTROL_LIMIT = 16 * 1024
KINDS = {"launch", "ready", "commit", "cancel", "done"}
HOST_NS = 300_000_000_000
STOP_NS = 5_000_000_000
# With PrivatePIDs=yes systemd resets ExecMainStartTimestamp from the main
# process's /proc stat starttime (v259.10 and v262.1 service.c,
# service_set_main_pidref), which counts whole USER_HZ ticks (Linux
# fs/proc/array.c; 100 Hz on x86-64). Its boottime-to-monotonic mapping
# (time-util.c, dual_timestamp_from_boottime) adds the gap between two clock
# reads; a host suspend between the fork and that mapping moves it earlier,
# which still refuses. H's resolver and G's service binding share it.
START_TICK_NS = 10_000_000
IO_LIMIT = 65536
# Linux UAPI asm-generic/socket.h; Python 3.14 does not export this constant.
# SO_PEERPIDFD binds the socket's stored peer, without a PID lookup/reuse race.
SO_PEERPIDFD = 77
STREAM_LIMIT = 8 * 1024 * 1024
HOST_RECEIPT_BUDGET = 64 * 1024
# Bytes for CPUs 0-4095, the range validate_spec accepts.
CPU_MASK_LIMIT = 512
# Cleanup must continue through cancellation; every captured error is re-raised.
CLEANUP_FAILURES = (BaseException,)


class Specification(NamedTuple):
    run_id: str
    boot_input_sha256: str
    build_sha256: str
    input_manifest_sha256: str
    mode: str
    cases: tuple[str, ...]
    first_epoch: int
    qemu: str
    base: str
    payload: str
    overlay: str
    cpus: tuple[int, int]


def validate_spec(spec):
    """Validate immutable selection, not input provenance or execution authority."""
    if type(spec) is not Specification:
        raise ValueError("guardian specification type")
    runtime._identifier(spec.run_id)
    for digest in (
        spec.boot_input_sha256,
        spec.build_sha256,
        spec.input_manifest_sha256,
    ):
        if type(digest) is not str or re.fullmatch("[0-9a-f]{64}", digest) is None:
            raise ValueError("guardian digest")
    if spec.mode not in ("boot-only", "runtime-candidate"):
        raise ValueError("guardian mode")
    if type(spec.cases) is not tuple or not 1 <= len(spec.cases) <= 6:
        raise ValueError("guardian cases")
    if any(type(case) is not str or case not in runtime.CASES for case in spec.cases):
        raise ValueError("guardian case name")
    if len(set(spec.cases)) != len(spec.cases):
        raise ValueError("duplicate guardian case")
    if spec.mode == "boot-only" and spec.cases != ("supervisor-only",):
        raise ValueError("boot-only selection")
    if any(runtime.expected_outcome(case) == "incomplete" for case in spec.cases[:-1]):
        raise ValueError("quarantine must terminate the batch")
    runtime._integer(spec.first_epoch, 1, runtime.U64_MAX - len(spec.cases) + 1)
    paths = (spec.qemu, spec.base, spec.payload, spec.overlay)
    for path in paths:
        if type(path) is not str or not path or len(path) > 4096 or "\0" in path:
            raise ValueError("guardian path")
        value = Path(path)
        if not value.is_absolute() or ".." in value.parts or str(value) != path:
            raise ValueError("guardian absolute path")
    if len(set(paths)) != len(paths):
        raise ValueError("guardian path alias")
    if type(spec.cpus) is not tuple or len(spec.cpus) != 2:
        raise ValueError("guardian CPU selection")
    for cpu in spec.cpus:
        runtime._integer(cpu, 0, 4095)
    if spec.cpus[0] == spec.cpus[1]:
        raise ValueError("guardian duplicate CPU")


def launch_request(spec):
    validate_spec(spec)
    # JSON arrays have their wire type from construction onward.
    payload = dict(spec._asdict(), cases=list(spec.cases), cpus=list(spec.cpus))
    return {"kind": "launch", "payload": payload}


class ServiceIdentity(NamedTuple):
    unit: str
    invocation_id: str
    pid: int
    cgroup: str
    deadline_ns: int


def unified_cgroup(data):
    """The cgroup v2 path in /proc/<pid>/cgroup text.

    Legacy v1 hierarchies mounted beside the unified one (for example a VPN's
    net_cls for split tunnelling) add their own lines; they do not place the
    process. Exactly one unified line is required.
    """
    if type(data) is not str or not 0 < len(data) <= 4096 or not data.endswith("\n"):
        raise ValueError("cgroup membership format")
    unified = []
    for line in data[:-1].split("\n"):
        if re.fullmatch(r"0::(/[\x21-\x7e]*)", line):
            unified.append(line[3:])
        elif (
            re.fullmatch(r"[1-9][0-9]{0,5}:[a-z0-9_,=.-]+:/[\x21-\x7e]*", line) is None
        ):
            raise ValueError("cgroup membership format")
    if len(unified) != 1:
        raise ValueError("cgroup membership format")
    return unified[0]


def unit_name(spec):
    validate_spec(spec)
    return "irlume-job-guardian-" + spec.run_id + ".service"


def service_properties(spec):
    """Typed D-Bus property values; AddRef holds metadata, not the running unit."""
    validate_spec(spec)
    mask = bytearray(max(spec.cpus) // 8 + 1)
    for cpu in spec.cpus:
        mask[cpu // 8] |= 1 << (cpu % 8)
    return {
        "AddRef": True,
        "Type": "exec",
        "ExitType": "main",
        "Restart": "no",
        "NotifyAccess": "none",
        "RemainAfterExit": False,
        "RuntimeMaxUSec": HOST_NS // 1000,
        "RuntimeRandomizedExtraUSec": 0,
        "TimeoutStartUSec": STOP_NS // 1000,
        "TimeoutStopUSec": STOP_NS // 1000,
        "KillMode": "control-group",
        "KillSignal": 9,
        "FinalKillSignal": 9,
        "SendSIGKILL": True,
        "NoNewPrivileges": True,
        "CPUQuotaPerSecUSec": 2_000_000,
        "CPUAffinity": tuple(mask),
        "MemoryMax": 3 * 1024**3,
        "MemorySwapMax": 0,
        "TasksMax": 64,
        "ExecStartPre": (),
        "ExecStartPost": (),
        "ExecStop": (),
        "ExecStopPost": (),
    }


def check_service(row, spec, pid, uid, now_ns):
    """Check normalized typed readback against G's independently observed identity."""
    properties = service_properties(spec)
    del properties["AddRef"]  # Creation-only reference, not a readable property.
    fields = (
        "Id",
        "InvocationID",
        "MainPID",
        "ControlGroup",
        "ExecMainStartTimestampMonotonic",
        "ActiveEnterTimestampMonotonic",
        "ActiveState",
        "SubState",
        "Transient",
    )
    runtime._fields(row, (*properties, *fields))
    runtime._integer(pid, 2, 2**31 - 1)
    runtime._integer(uid, 1, 2**32 - 2)
    runtime._integer(now_ns)
    for name, expected in properties.items():
        if name != "CPUAffinity" and (
            type(row[name]) is not type(expected) or row[name] != expected
        ):
            raise ValueError("effective service property: " + name)
    # systemd reads CPUAffinity back as its whole CPU_ALLOC_SIZE buffer (a
    # multiple of eight bytes on x86-64): the requested bits, then zero bytes.
    mask, observed = properties["CPUAffinity"], row["CPUAffinity"]
    if (
        type(observed) is not tuple
        or len(observed) > CPU_MASK_LIMIT
        or any(type(byte) is not int or not 0 <= byte <= 255 for byte in observed)
        or observed[: len(mask)] != mask
        or any(observed[len(mask) :])
    ):
        raise ValueError("effective service property: CPUAffinity")
    runtime._integer(row["MainPID"], pid, pid)
    name = unit_name(spec)
    group = row["ControlGroup"]
    if (
        row["Id"] != name
        or row["Transient"] is not True
        or row["ActiveState"] != "active"
        or row["SubState"] != "running"
        or type(row["InvocationID"]) is not str
        or re.fullmatch("[0-9a-f]{32}", row["InvocationID"]) is None
        or row["InvocationID"] == "0" * 32
        or type(group) is not str
        or len(group) > 4096
        or not group.startswith(f"/user.slice/user-{uid}.slice/user@{uid}.service/")
        or not group.endswith("/" + name)
        or ".." in Path(group).parts
        or str(Path(group)) != group
    ):
        raise ValueError("effective service identity")
    started = row["ExecMainStartTimestampMonotonic"]
    active = row["ActiveEnterTimestampMonotonic"]
    runtime._integer(started, 1, (runtime.U64_MAX - HOST_NS) // 1000)
    runtime._integer(active, started, now_ns // 1000)
    deadline = started * 1000 + HOST_NS
    if now_ns >= deadline:
        raise ValueError("effective service expired")
    return ServiceIdentity(name, row["InvocationID"], pid, group, deadline)


def decode(data):
    if type(data) is not bytes or not 4 < len(data) <= CONTROL_LIMIT + 4:
        raise ValueError("guardian frame size")
    if int.from_bytes(data[:4], "big") != len(data) - 4:
        raise ValueError("guardian frame length")
    row = runtime._json(data[4:])
    runtime._fields(row, ("kind", "payload"))
    if (
        type(row["kind"]) is not str
        or row["kind"] not in KINDS
        or type(row["payload"]) is not dict
    ):
        raise ValueError("guardian message")
    return row


def encode(row):
    data = evidence.canonical(row)
    framed = len(data).to_bytes(4, "big") + data
    decode(framed)
    return framed


def qemu_argv(spec):
    """Fixed device graph; actual input provenance belongs to the R5 boundary."""
    validate_spec(spec)
    disk = {
        "driver": "qcow2",
        "node-name": "job-disk",
        "file": {"driver": "file", "filename": spec.overlay},
        "backing": {
            "driver": "raw",
            "read-only": True,
            "file": {"driver": "file", "filename": spec.base},
        },
    }
    payload = {
        "driver": "raw",
        "node-name": "job-payload",
        "read-only": True,
        "file": {"driver": "file", "filename": spec.payload, "read-only": True},
    }
    return (
        spec.qemu,
        "-no-user-config",
        "-nodefaults",
        "-accel",
        "kvm",
        "-smp",
        "2",
        "-m",
        "2048",
        "-display",
        "none",
        "-monitor",
        "none",
        "-nic",
        "none",
        "-no-reboot",
        "-chardev",
        "stdio,id=job-status,mux=off,signal=off",
        "-device",
        "virtio-serial-pci,id=job-serial,max_ports=2",
        "-device",
        "virtserialport,nr=1,chardev=job-status,name=irlume-job-status",
        "-blockdev",
        json.dumps(disk, separators=(",", ":")),
        "-device",
        "virtio-blk-pci,drive=job-disk",
        "-blockdev",
        json.dumps(payload, separators=(",", ":")),
        "-device",
        "virtio-blk-pci,drive=job-payload",
    )


def check_terminal(data, spec):
    """Check the R3 post-close frame; recovered-ledger matching remains mandatory."""
    validate_spec(spec)
    if type(data) is not bytes or not 4 < len(data) <= CONTROL_LIMIT + 4:
        raise ValueError("guest terminal frame size")
    if int.from_bytes(data[:4], "big") != len(data) - 4:
        raise ValueError("guest terminal frame length")
    row = runtime._json(data[4:])
    runtime._fields(
        row,
        (
            "scope",
            "mode",
            "identity",
            "batch_sha256",
            "ledger_bytes",
            "ledger_sha256",
            "outcome",
            "native_authorized",
            "full_contract_proven",
        ),
    )
    runtime._fields(row["identity"], runtime.Identity._fields)
    identity = runtime.Identity(**row["identity"])
    runtime._identity(identity)
    selected = (
        spec.run_id,
        spec.boot_input_sha256,
        spec.build_sha256,
        spec.input_manifest_sha256,
    )
    received = (
        identity.run_id,
        identity.boot_input_sha256,
        identity.build_sha256,
        identity.input_manifest_sha256,
    )
    if (
        selected != received
        or row["scope"] != "contained-job-terminal-v1"
        or row["mode"] != spec.mode
    ):
        raise ValueError("guest terminal selection")
    runtime._integer(row["ledger_bytes"], 1, evidence.LEDGER_LIMIT)
    if (
        type(row["ledger_sha256"]) is not str
        or re.fullmatch("[0-9a-f]{64}", row["ledger_sha256"]) is None
    ):
        raise ValueError("guest ledger digest")
    batch = {
        "identity": identity._asdict(),
        "cases": spec.cases,
        "first_epoch": spec.first_epoch,
        "mode": spec.mode,
    }
    if row["batch_sha256"] != hashlib.sha256(evidence.canonical(batch)).hexdigest():
        raise ValueError("guest terminal batch")
    outcome = (
        "expected-abort"
        if runtime.expected_outcome(spec.cases[-1]) == "incomplete"
        else "complete"
    )
    if (
        row["outcome"] != outcome
        or row["native_authorized"] is not False
        or row["full_contract_proven"] is not False
    ):
        raise ValueError("guest terminal outcome")
    return row


class Guardian:
    """One G transaction. Effects own child/FD slots before fallible operations."""

    def __init__(self, effects, spec, origin):
        validate_spec(spec)
        runtime._integer(origin, 0, runtime.U64_MAX - HOST_NS - STOP_NS)
        self.os, self.spec, self.origin = effects, spec, origin
        self.end, self.start_end = origin + HOST_NS, origin + STOP_NS
        self.previous = origin
        self.identity = None
        self.pid = self.wait = self.exitcode = self.guest = None
        self.spawn_attempted = self.control_close_attempted = False
        self.raw = {"stdout": bytearray(), "stderr": bytearray()}
        self.counts = dict.fromkeys(self.raw, 0)
        self.eof = set()
        self.transaction = hashlib.sha256(encode(launch_request(spec))).hexdigest()

    def check(self, deadline):
        now = self.os.now()
        runtime._integer(now)
        if now < self.previous or now >= deadline:
            raise TimeoutError("guardian deadline or clock regression")
        self.previous = now
        return now

    def call(self, deadline, function, *args):
        self.check(deadline)
        result = function(*args)
        self.check(deadline)
        return result

    def snapshot(self):
        return {
            "scope": "contained-job-guardian-v1",
            "run_id": self.spec.run_id,
            "transaction_sha256": self.transaction,
            "service": None if self.identity is None else self.identity._asdict(),
            "host_origin_ns": self.origin,
            "host_deadline_ns": self.end,
            "spawn_attempted": self.spawn_attempted,
            "pid": self.pid,
            "terminal_wait": self.wait,
            "observed_exitcode": self.exitcode,
            "stdout_hex": self.raw["stdout"].hex(),
            "stderr_hex": self.raw["stderr"].hex(),
            "stream_bytes": dict(self.counts),
            "eof": sorted(self.eof),
            "guest_terminal": self.guest,
            "transport_complete": False,
            "accepted": False,
            "native_authorized": False,
            "full_contract_proven": False,
        }

    def message(self, kind, payload):
        return encode({"kind": kind, "payload": payload})

    def close_control(self):
        if not self.control_close_attempted:
            self.control_close_attempted = True
            self.os.close_control()

    def read_event(self, deadline):
        self.check(deadline)
        event = self.os.event(deadline)
        if type(event) is tuple and len(event) == 2:
            channel, data = event
            if type(channel) is str and channel in self.raw:
                if type(data) is bytes:
                    self.counts[channel] += len(data)
                    limit = CONTROL_LIMIT + 4 if channel == "stdout" else STREAM_LIMIT
                    self.raw[channel].extend(
                        data[: max(0, limit - len(self.raw[channel]))]
                    )
                elif data is None:
                    self.eof.add(channel)
            elif channel == "exit" and type(data) is int and self.exitcode is None:
                self.exitcode = data
        self.check(deadline)
        if (
            sum(self.counts.values()) > STREAM_LIMIT
            or self.counts["stdout"] > CONTROL_LIMIT + 4
        ):
            raise ValueError("guardian stream cap")
        return event

    def run(self):
        try:
            return self.execute()
        except CLEANUP_FAILURES as primary:
            self.abort(primary)

    def execute(self):
        self.identity = self.call(
            self.start_end, self.os.preflight, self.spec, self.start_end
        )
        if type(
            self.identity
        ) is not ServiceIdentity or self.identity.unit != unit_name(self.spec):
            raise ValueError("guardian preflight identity")
        runtime._integer(self.identity.deadline_ns, self.origin + 1)
        self.end = min(self.end, self.identity.deadline_ns)
        self.start_end = min(self.start_end, self.end)
        self.identity = self.identity._replace(deadline_ns=self.end)
        self.call(
            self.start_end, self.os.record, "started", self.snapshot(), self.start_end
        )
        incoming = self.call(self.start_end, self.os.receive, self.start_end)
        if evidence.canonical(decode(incoming)) != evidence.canonical(
            launch_request(self.spec)
        ):
            raise ValueError("guardian launch transaction mismatch")
        ready = {
            "transaction_sha256": self.transaction,
            "service": self.identity._asdict(),
        }
        self.call(
            self.start_end, self.os.send, self.message("ready", ready), self.start_end
        )
        incoming = self.call(self.start_end, self.os.receive, self.start_end)
        wanted = self.message("commit", {"transaction_sha256": self.transaction})
        if encode(decode(incoming)) != wanted:
            raise ValueError("guardian commit mismatch")
        self.call(self.start_end, self.os.require_idle, self.start_end)
        self.call(self.end, self.os.record, "spawn-intent", self.snapshot(), self.end)
        self.check(self.end)
        self.spawn_attempted = True
        self.pid = self.os.spawn(self.spec, self.end)
        self.check(self.end)
        runtime._integer(self.pid, 2, 2**31 - 1)
        self.call(self.end, self.os.record, "spawned", self.snapshot(), self.end)
        failure = None
        for _ in range(IO_LIMIT):
            self.call(self.end, self.os.require_idle, self.end)
            prior_eof, prior_exit = set(self.eof), self.exitcode
            event = self.read_event(self.end)
            if event is None:
                continue
            if type(event) is not tuple or len(event) != 2:
                raise ValueError("guardian event")
            channel, data = event
            if channel == "exit":
                if type(data) is not int or prior_exit is not None:
                    raise ValueError("guardian exit event")
                if data != 0:
                    failure = ValueError("QEMU nonzero exit or signal")
            elif type(channel) is str and channel in self.raw:
                if channel in prior_eof or (
                    data is not None and (type(data) is not bytes or not data)
                ):
                    raise ValueError("guardian stream event")
                if (
                    sum(self.counts.values()) > STREAM_LIMIT
                    or self.counts["stdout"] > CONTROL_LIMIT + 4
                ):
                    raise ValueError("guardian stream cap")
            else:
                raise ValueError("guardian unknown event")
            if self.exitcode is not None and self.eof == set(self.raw):
                break
        else:
            raise ValueError("guardian event cap")
        self.check(self.end)
        self.wait = self.os.reap(self.end)
        self.check(self.end)
        if failure is not None:
            raise failure
        if self.wait != {"pid": self.pid, "exitcode": 0, "status": 0} or any(
            type(value) is not int for value in self.wait.values()
        ):
            raise ValueError("guardian terminal wait mismatch")
        self.guest = check_terminal(bytes(self.raw["stdout"]), self.spec)
        self.call(self.end, self.os.close_child)
        self.call(self.end, self.os.require_idle, self.end)
        row = dict(self.snapshot(), state="ready-to-finalize")
        count, digest = self.call(self.end, self.os.finalize, row, self.end)
        runtime._integer(count, 1, evidence.LEDGER_LIMIT)
        if type(digest) is not str or re.fullmatch("[0-9a-f]{64}", digest) is None:
            raise ValueError("guardian receipt digest")
        self.call(self.end, self.os.require_idle, self.end)
        done = {
            "transaction_sha256": self.transaction,
            "invocation_id": self.identity.invocation_id,
            "receipt_bytes": count,
            "receipt_sha256": digest,
        }
        self.call(self.end, self.os.send, self.message("done", done), self.end)
        self.call(self.end, self.os.require_idle, self.end)
        self.call(self.end, self.close_control)
        return dict(row, state="transport-complete", transport_complete=True)

    def abort(self, primary):
        errors = [primary]
        try:
            now = self.os.now()
            runtime._integer(now)
            if now < self.previous:
                raise ValueError("abort clock regression")
        except CLEANUP_FAILURES as error:
            errors.append(error)
            now = self.previous
        stop_end = min(now + STOP_NS, self.origin + HOST_NS + STOP_NS)
        try:
            owner = self.os.owner_state()
            if owner["attempted"] and not owner["reaped"]:
                try:
                    self.os.stop(stop_end)
                except CLEANUP_FAILURES as error:
                    errors.append(error)
                try:
                    self.wait = self.os.reap(stop_end)
                    self.check(stop_end)
                except CLEANUP_FAILURES as error:
                    errors.append(error)
        except CLEANUP_FAILURES as error:
            errors.append(error)
        try:
            if self.os.owner_state()["reaped"]:
                for _ in range(IO_LIMIT):
                    if self.eof == set(self.raw):
                        break
                    self.read_event(stop_end)
                else:
                    raise ValueError("guardian failure-drain event cap")
        except CLEANUP_FAILURES as error:
            errors.append(error)
        for close in (self.os.close_child, self.close_control):
            try:
                close()
            except CLEANUP_FAILURES as error:
                errors.append(error)
        try:
            owner = self.os.owner_state()
            row = dict(
                self.snapshot(),
                state="failed",
                owner=owner,
                leftover=bool(owner["attempted"] and not owner["reaped"]),
                drain_complete=self.eof == set(self.raw),
                truncated_streams={
                    name: len(self.raw[name]) != self.counts[name] for name in self.raw
                },
                errors=[
                    {"type": type(e).__name__, "message": str(e)[:256]} for e in errors
                ],
            )
            self.os.failed(row, stop_end)
        except CLEANUP_FAILURES as error:
            errors.append(error)
        if len(errors) == 1:
            raise primary
        raise BaseExceptionGroup("guardian failure and cleanup", errors) from primary


def run_guardian(effects, spec, origin):
    return Guardian(effects, spec, origin).run()


class PeerChannel:
    """Consume one connected AF_UNIX socket and retain its exact peer pidfd."""

    def __init__(self, connected, expected_peer, *, now=time.monotonic_ns):
        self.socket, self.peer_fd, self.now = connected, None, now
        self.received = bytearray()
        self.read_total = self.sent_total = 0
        self.truncated = False
        self.last_peek = None
        self.receive_eof = False
        self.previous = None
        try:
            host = os.uname()
            if host.sysname != "Linux" or host.machine != "x86_64":
                raise ValueError("unsupported guardian peer platform")
            if (
                connected.family != socket.AF_UNIX
                or connected.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                != socket.SOCK_STREAM
            ):
                raise ValueError("guardian requires a Unix stream")
            if (
                type(expected_peer) is not tuple
                or len(expected_peer) != 3
                or any(type(x) is not int for x in expected_peer)
            ):
                raise ValueError("invalid expected peer")
            peer = struct.unpack(
                "3i", connected.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if peer != expected_peer:
                raise ValueError("unexpected guardian peer")
            self.peer_fd = connected.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD)
            os.set_inheritable(self.peer_fd, False)
            connected.set_inheritable(False)
            connected.setblocking(False)
            if select.select([self.peer_fd], [], [], 0)[0]:
                raise ValueError("guardian peer already terminated")
        except BaseException as error:
            try:
                self.close()
            except CLEANUP_FAILURES as cleanup:
                raise BaseExceptionGroup(
                    "peer setup and cleanup", [error, cleanup]
                ) from error
            raise

    def check(self, deadline, *, alive=True):
        now = self.now()
        if type(now) is not int or type(deadline) is not int or now < 0:
            raise ValueError("peer clock")
        if now >= deadline or (self.previous is not None and now < self.previous):
            raise TimeoutError("peer deadline")
        self.previous = now
        if alive and select.select([self.peer_fd], [], [], 0)[0]:
            raise ValueError("guardian peer terminated")
        return min(0.01, (deadline - now) / 1_000_000_000)

    def receive(self, deadline, *, allow_exit=False):
        self.received = bytearray()
        self.truncated = False
        self.receive_eof = False
        for _ in range(IO_LIMIT):
            wait = self.check(deadline, alive=not allow_exit)
            try:
                data = self.socket.recv(4096)
            except BlockingIOError:
                select.select([self.socket], [], [], wait)
                continue
            self.read_total += len(data)
            self.receive_eof = not data
            room = CONTROL_LIMIT + 4 - len(self.received)
            self.received.extend(data[:room])
            self.truncated |= len(data) > room
            self.check(deadline, alive=not allow_exit)
            if not data:
                raise ValueError("peer EOF before complete frame")
            if self.truncated or self.read_total > 4 * (CONTROL_LIMIT + 4):
                raise ValueError("peer byte cap")
            if len(self.received) >= 4:
                size = int.from_bytes(self.received[:4], "big")
                if not 0 < size <= CONTROL_LIMIT or len(self.received) > size + 4:
                    raise ValueError("peer frame length or surplus")
                if len(self.received) == size + 4:
                    return bytes(self.received)
        raise ValueError("peer receive event cap")

    def send(self, data, deadline, *, allow_exit_after_send=False):
        if (
            type(allow_exit_after_send) is not bool
            or type(data) is not bytes
            or not 4 < len(data) <= CONTROL_LIMIT + 4
            or int.from_bytes(data[:4], "big") != len(data) - 4
        ):
            raise ValueError("invalid outgoing peer frame")
        offset = 0
        for _ in range(IO_LIMIT):
            wait = self.check(
                deadline, alive=not (allow_exit_after_send and offset == len(data))
            )
            if offset == len(data):
                return
            try:
                count = self.socket.send(data[offset:])
            except BlockingIOError:
                select.select([], [self.socket], [], wait)
                continue
            self.sent_total += count
            offset += count
            self.check(
                deadline, alive=not (allow_exit_after_send and offset == len(data))
            )
            if count <= 0 or self.sent_total > 4 * (CONTROL_LIMIT + 4):
                raise ValueError("peer write or byte cap")
        raise ValueError("peer send event cap")

    def require_idle(self, deadline, *, cancel_frame=None):
        self.check(deadline)
        try:
            self.last_peek = self.socket.recv(CONTROL_LIMIT + 5, socket.MSG_PEEK)
        except BlockingIOError:
            self.check(deadline)
            return
        self.check(deadline)
        if not self.last_peek:
            raise ValueError("peer write-side EOF")
        if len(self.last_peek) < 4:
            raise ValueError("peer partial control frame")
        size = int.from_bytes(self.last_peek[:4], "big")
        if not 0 < size <= CONTROL_LIMIT:
            raise ValueError("peer invalid control frame")
        if len(self.last_peek) < size + 4:
            raise ValueError("peer partial control frame")
        if len(self.last_peek) != size + 4:
            raise ValueError("peer surplus control bytes")
        try:
            message = decode(self.last_peek)
        except ValueError as error:
            raise ValueError("peer invalid control frame") from error
        if cancel_frame is not None and evidence.canonical(
            message
        ) == evidence.canonical(decode(cancel_frame)):
            raise ValueError("peer cancelled")
        raise ValueError("peer unexpected control message")

    def expect_eof(self, deadline):
        for _ in range(IO_LIMIT):
            wait = self.check(deadline, alive=False)
            try:
                self.last_peek = self.socket.recv(1)
            except BlockingIOError:
                select.select([self.socket], [], [], wait)
                continue
            self.check(deadline, alive=False)
            if self.last_peek:
                raise ValueError("surplus after final peer frame")
            return
        raise ValueError("peer EOF event cap")

    def close(self):
        errors = []
        connected, self.socket = self.socket, None
        peer_fd, self.peer_fd = self.peer_fd, None
        for resource, close in ((connected, lambda x: x.close()), (peer_fd, os.close)):
            if resource is not None:
                try:
                    close(resource)
                except CLEANUP_FAILURES as error:
                    errors.append(error)
        if errors:
            raise BaseExceptionGroup("peer channel cleanup", errors)

    def diagnostics(self):
        """Bounded last-frame/peek evidence; remains available after disposal."""
        return {
            "received_hex": self.received.hex(),
            "receive_eof": self.receive_eof,
            "received_total": self.read_total,
            "sent_total": self.sent_total,
            "receive_truncated": self.truncated,
            "last_peek_hex": None if self.last_peek is None else self.last_peek.hex(),
            "peek_limit_reached": self.last_peek is not None
            and len(self.last_peek) == CONTROL_LIMIT + 5,
        }


if __name__ == "__main__":
    raise SystemExit(77)
