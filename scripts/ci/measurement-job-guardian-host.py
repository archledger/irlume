#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Private H coordinator. R5 must verify/freeze inputs before the runtime call."""

import hashlib
import importlib.machinery
import importlib.util
import os
import re
import select
import socket
import time
from builtins import BaseExceptionGroup
from pathlib import Path

HERE = Path(__file__).resolve().parent


class SourceLoader(importlib.machinery.SourceFileLoader):
    """Bootstrap from source without trusting this entry's adjacent caches."""

    def get_code(self, fullname):
        self.source = self.get_data(self.path)
        return self.source_to_code(self.source, self.path)


LOADER = SourceLoader(
    "host_guardian_native", str(HERE / "measurement-job-guardian-native.py")
)
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
native = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(native)
native.__source_sha256__ = hashlib.sha256(LOADER.source).hexdigest()
g = native.guardian
CLEANUP_FAILURES = (BaseException,)
job = native.load("guardian_host_output", HERE / "measurement-job.py")
HOST_RECEIPT_LIMIT = g.HOST_RECEIPT_BUDGET
UNRESOLVED = {}


def verify_receipt(data, spec, identity, origin):
    if type(data) is not bytes or not 0 < len(data) <= g.evidence.LEDGER_LIMIT:
        raise ValueError("guardian receipt size")
    row = g.runtime._json(data)
    g.runtime._fields(
        row,
        (
            "scope",
            "run_id",
            "transaction_sha256",
            "service",
            "host_origin_ns",
            "host_deadline_ns",
            "spawn_attempted",
            "pid",
            "terminal_wait",
            "observed_exitcode",
            "stdout_hex",
            "stderr_hex",
            "stream_bytes",
            "eof",
            "guest_terminal",
            "transport_complete",
            "accepted",
            "native_authorized",
            "full_contract_proven",
            "state",
        ),
    )
    transaction = hashlib.sha256(g.encode(g.launch_request(spec))).hexdigest()
    if (
        row["scope"] != "contained-job-guardian-v1"
        or row["state"] != "ready-to-finalize"
        or row["run_id"] != spec.run_id
        or row["transaction_sha256"] != transaction
    ):
        raise ValueError("guardian receipt identity")
    if g.evidence.canonical(row["service"]) != g.evidence.canonical(identity._asdict()):
        raise ValueError("guardian receipt service")
    g.runtime._integer(row["host_origin_ns"], origin, origin)
    g.runtime._integer(
        row["host_deadline_ns"], identity.deadline_ns, identity.deadline_ns
    )
    for key in (
        "transport_complete",
        "accepted",
        "native_authorized",
        "full_contract_proven",
    ):
        if row[key] is not False:
            raise ValueError("guardian receipt authority or premature completion")
    if row["spawn_attempted"] is not True or row["eof"] != ["stderr", "stdout"]:
        raise ValueError("guardian receipt lifecycle")
    g.runtime._integer(row["pid"], 2, 2**31 - 1)
    g.runtime._integer(row["observed_exitcode"], 0, 0)
    g.runtime._fields(row["terminal_wait"], ("pid", "exitcode", "status"))
    for key, value in (("pid", row["pid"]), ("exitcode", 0), ("status", 0)):
        g.runtime._integer(row["terminal_wait"][key], value, value)
    g.runtime._fields(row["stream_bytes"], ("stdout", "stderr"))
    streams = {}
    for name in ("stdout", "stderr"):
        text = row[name + "_hex"]
        limit = g.CONTROL_LIMIT + 4 if name == "stdout" else g.STREAM_LIMIT
        if (
            type(text) is not str
            or len(text) > limit * 2
            or re.fullmatch("(?:[0-9a-f]{2})*", text) is None
        ):
            raise ValueError("guardian receipt stream encoding")
        streams[name] = bytes.fromhex(text)
        g.runtime._integer(
            row["stream_bytes"][name], len(streams[name]), len(streams[name])
        )
    if sum(map(len, streams.values())) > g.STREAM_LIMIT:
        raise ValueError("guardian receipt stream cap")
    terminal = g.check_terminal(streams["stdout"], spec)
    if g.evidence.canonical(terminal) != g.evidence.canonical(row["guest_terminal"]):
        raise ValueError("guardian receipt terminal mismatch")
    return row


def verify_service_terminal(proof, identity, started_ns, now):
    g.runtime._fields(proof, ("unit", "processes"))
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


class HostController:
    def __init__(self, spec, effects):
        g.validate_spec(spec)
        self.spec, self.io = spec, effects
        self.origin = effects.now()
        g.runtime._integer(self.origin, 0, g.runtime.U64_MAX - g.HOST_NS - g.STOP_NS)
        self.previous = self.origin
        self.start_end, self.end = self.origin + g.STOP_NS, self.origin + g.HOST_NS
        self.identity = self.done = self.receipt = self.terminal = None
        self.transaction = hashlib.sha256(g.encode(g.launch_request(spec))).hexdigest()

    def check(self, deadline):
        now = self.io.now()
        g.runtime._integer(now)
        if now < self.previous or now >= deadline:
            raise TimeoutError("host guardian deadline")
        self.previous = now
        return now

    def call(self, deadline, function, *args, **kwargs):
        self.check(deadline)
        value = function(*args, **kwargs)
        self.check(deadline)
        return value

    def snapshot(self):
        return {
            "scope": "contained-job-host-v1",
            "run_id": self.spec.run_id,
            "transaction_sha256": self.transaction,
            "origin_ns": self.origin,
            "deadline_ns": self.end,
            "service": None if self.identity is None else self.identity._asdict(),
            "done": self.done,
            "terminal": self.terminal,
            "transport_complete": False,
            "accepted": False,
            "native_authorized": False,
            "full_contract_proven": False,
        }

    def run(self):
        try:
            return self.execute()
        except CLEANUP_FAILURES as error:
            errors = [error]
            try:
                now = self.io.now()
                g.runtime._integer(now)
                now = max(now, self.previous)
            except CLEANUP_FAILURES as clock:
                errors.append(clock)
                now = self.previous
            stop_end = min(now + g.STOP_NS, self.origin + g.HOST_NS + g.STOP_NS)
            try:
                self.io.abort(
                    dict(
                        self.snapshot(),
                        state="failed",
                        error=type(error).__name__,
                        message=str(error)[:256],
                    ),
                    stop_end,
                )
            except CLEANUP_FAILURES as cleanup:
                errors.append(cleanup)
            if len(errors) > 1:
                raise BaseExceptionGroup(
                    "host guardian failure and cleanup", errors
                ) from error
            raise

    def execute(self):
        self.call(
            self.start_end, self.io.prepare, self.spec, self.origin, self.start_end
        )
        self.identity = self.call(
            self.start_end, self.io.start_service, self.spec, self.start_end
        )
        if type(
            self.identity
        ) is not g.ServiceIdentity or self.identity.unit != g.unit_name(self.spec):
            raise ValueError("host service identity")
        started_ns = self.identity.deadline_ns - g.HOST_NS
        self.end = min(self.end, self.identity.deadline_ns)
        self.identity = self.identity._replace(deadline_ns=self.end)
        self.call(self.start_end, self.io.connect, self.identity, self.start_end)
        self.call(
            self.start_end,
            self.io.send,
            g.encode(g.launch_request(self.spec)),
            self.start_end,
        )
        ready = g.decode(self.call(self.start_end, self.io.receive, self.start_end))
        expected = {
            "kind": "ready",
            "payload": {
                "transaction_sha256": self.transaction,
                "service": self.identity._asdict(),
            },
        }
        if g.evidence.canonical(ready) != g.evidence.canonical(expected):
            raise ValueError("host READY mismatch")
        self.call(
            self.start_end,
            self.io.send,
            g.encode(
                {"kind": "commit", "payload": {"transaction_sha256": self.transaction}}
            ),
            self.start_end,
        )
        done = g.decode(self.call(self.end, self.io.receive, self.end, allow_exit=True))
        if done["kind"] != "done":
            raise ValueError("host expected DONE")
        candidate = done["payload"]
        g.runtime._fields(
            candidate,
            ("transaction_sha256", "invocation_id", "receipt_bytes", "receipt_sha256"),
        )
        if (
            candidate["transaction_sha256"] != self.transaction
            or candidate["invocation_id"] != self.identity.invocation_id
        ):
            raise ValueError("host DONE identity")
        g.runtime._integer(candidate["receipt_bytes"], 1, g.evidence.LEDGER_LIMIT)
        if (
            type(candidate["receipt_sha256"]) is not str
            or re.fullmatch("[0-9a-f]{64}", candidate["receipt_sha256"]) is None
        ):
            raise ValueError("host DONE digest")
        self.done = candidate
        self.call(self.end, self.io.expect_eof, self.end)
        data = self.call(self.end, self.io.read_receipt, self.end)
        if (
            len(data) != self.done["receipt_bytes"]
            or hashlib.sha256(data).hexdigest() != self.done["receipt_sha256"]
        ):
            raise ValueError("host closed receipt mismatch")
        self.receipt = verify_receipt(data, self.spec, self.identity, self.origin)
        self.terminal = self.call(self.end, self.io.wait_terminal, self.end)
        verify_service_terminal(
            self.terminal, self.identity, started_ns, self.check(self.end)
        )
        row = dict(
            self.snapshot(),
            state="ready-to-finalize",
            guest_outcome=self.receipt["guest_terminal"]["outcome"],
        )
        self.call(self.end, self.io.finish, row, self.end)
        self.call(self.end, self.io.release, self.end)
        return dict(row, state="transport-complete", transport_complete=True)


class HostEffects:
    """Concrete H effects, used only after R5 verifies and freezes its inputs."""

    def __init__(self, spec, *, _gate_factory=None, _bus_factory=None):
        self.spec = spec
        self.gate_factory = (
            _gate_factory or native.service.AdmissionGate.for_current_user
        )
        self.bus_factory = _bus_factory or native.service.SystemdBus
        self.gate = self.lease = self.listener = self.channel = None
        self.root = self.directory = self.directory_identity = self.writer = None
        self.config = self.argv = self.identity = None
        self.output_bytes = 0
        self.last_receipt = None
        self.control_diagnostic = None
        self.terminal_evidence = None

    def now(self):
        return time.monotonic_ns()

    def write(self, label, data, deadline):
        native.before(deadline)
        if self.writer is None or self.output_bytes + len(data) > HOST_RECEIPT_LIMIT:
            raise ValueError("host receipt state or byte cap")
        self.output_bytes += len(data)
        self.writer.save_blob(label, data)
        native.before(deadline)

    def prepare(self, spec, origin, deadline):
        if self.gate is not None:
            raise ValueError("host attempt already prepared")
        self.gate = self.gate_factory(deadline)
        try:
            os.stat("active.json", dir_fd=self.gate.root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("prior guardian ownership unresolved")
        name = "attempt-" + spec.run_id
        os.mkdir(name, 0o700, dir_fd=self.gate.root_fd)
        self.root = self.gate.root / name
        self.directory = native.private_directory(self.root)
        info = os.fstat(self.directory)
        self.directory_identity = info.st_dev, info.st_ino
        self.writer = job.OwnedOutput(self.directory)
        os.fsync(self.gate.root_fd)
        self.config = native.make_config(spec, origin)
        config_data = g.evidence.canonical(self.config)
        self.write("guardian-config", config_data, deadline)
        digest = hashlib.sha256(config_data).hexdigest()
        self.argv = native.entry_argv(self.root, digest)
        endpoint = str(self.root / "control.sock")
        if len(os.fsencode(endpoint)) >= 108:
            raise ValueError("guardian Unix endpoint path too long")
        self.listener = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC,
        )
        self.listener.bind(endpoint)
        os.chmod(endpoint, 0o600)
        self.listener.listen(1)
        intent = g.evidence.canonical(
            {
                "scope": "contained-job-host-intent-v1",
                "run_id": spec.run_id,
                "unit": g.unit_name(spec),
                "directory": str(self.root),
                "config_sha256": digest,
                "client_pid": os.getpid(),
                "client_starttime": self.config["client_starttime"],
                "origin_ns": origin,
                "transaction_sha256": hashlib.sha256(
                    g.encode(g.launch_request(spec))
                ).hexdigest(),
            }
        )
        self.write("host-intent", intent, deadline)
        # Keep room for a full bounded last control frame, peek and failure
        # metadata. Reject oversized setup before a service can be created.
        if self.output_bytes + 2 * len(intent) + 512 > HOST_RECEIPT_LIMIT - 48 * 1024:
            raise ValueError("host control diagnostic reserve")
        self.gate.claim(spec.run_id, intent, deadline)
        self.output_bytes += len(self.gate.record)
        if self.output_bytes > HOST_RECEIPT_LIMIT:
            raise ValueError("host intent byte cap")
        native.before(deadline)

    def active_identity(self, row, spec):
        keys = set(g.service_properties(spec)) - {"AddRef"}
        keys |= set(native.service.UNIT_TYPES) | {
            "MainPID",
            "ControlGroup",
            "ExecMainStartTimestampMonotonic",
        }
        if row["ExecStart"] != ((self.argv[0], self.argv, False),):
            raise ValueError("host guardian executable mismatch")
        return g.check_service(
            {key: row[key] for key in keys},
            spec,
            row["MainPID"],
            os.getuid(),
            self.now(),
        )

    def start_service(self, spec, deadline):
        if self.gate is None or self.gate.record is None or self.lease is not None:
            raise ValueError("host service lacks exclusive durable intent")
        self.lease = native.service.UnitLease(
            g.unit_name(spec), self.bus_factory(os.getuid(), deadline=deadline)
        )
        self.lease.create(g.service_properties(spec), self.argv, deadline)
        for _ in range(g.IO_LIMIT):
            delay = native.before(deadline)
            row = self.lease.observe(deadline)
            if row["ActiveState"] == "active" and row["SubState"] == "running":
                self.identity = self.active_identity(row, spec)
                self.lease.bind(row)
                return self.identity
            if row["ActiveState"] not in ("activating", "active"):
                raise ValueError("guardian service failed during startup")
            time.sleep(delay)
        raise ValueError("host startup event cap")

    def connect(self, identity, deadline):
        for _ in range(g.IO_LIMIT):
            delay = native.before(deadline)
            try:
                connected, _ = self.listener.accept()
            except BlockingIOError:
                select.select([self.listener], [], [], delay)
                continue
            self.channel = g.PeerChannel(
                connected, (identity.pid, os.getuid(), os.getgid())
            )
            listener, self.listener = self.listener, None
            listener.close()
            row = self.lease.observe(deadline)
            current = self.active_identity(row, self.spec)._replace(
                deadline_ns=identity.deadline_ns
            )
            if current != identity:
                raise ValueError("guardian service changed during connection")
            self.identity = identity
            return
        raise ValueError("host connect event cap")

    def send(self, data, deadline):
        self.channel.send(data, deadline)

    def receive(self, deadline, *, allow_exit=False):
        return self.channel.receive(deadline, allow_exit=allow_exit)

    def expect_eof(self, deadline):
        self.channel.expect_eof(deadline)

    def read_receipt(self, deadline):
        native.before(deadline)
        self.last_receipt = native.protected_read(
            self.root / "guardian-finished.json", g.evidence.LEDGER_LIMIT
        )
        native.before(deadline)
        return self.last_receipt

    def wait_terminal(self, deadline):
        for _ in range(g.IO_LIMIT):
            delay = native.before(deadline)
            row = self.lease.observe(deadline)
            self.lease.same_invocation(row)
            if row["ActiveState"] == "inactive" and row["SubState"] == "dead":
                row = self.lease.verify_terminal(deadline, self.identity.deadline_ns)
                return {"unit": row, "processes": self.lease.last_processes}
            if row["ActiveState"] == "failed":
                raise ValueError("guardian service failed after DONE")
            time.sleep(delay)
        raise ValueError("host terminal event cap")

    def finish(self, row, deadline):
        if self.lease is None or not self.lease.terminal or self.last_receipt is None:
            raise ValueError("host terminal proof incomplete")
        data = g.evidence.canonical(row)
        self.write("host-finished", data, deadline)
        if self.output_bytes + len(data) > HOST_RECEIPT_LIMIT:
            raise ValueError("host gate proof byte cap")
        self.output_bytes += len(data)
        self.close_directory()
        self.terminal_evidence = data

    def close_directory(self):
        if self.directory is not None:
            fd, self.directory = self.directory, None
            self.writer = None
            os.close(fd)

    def close_channels(self):
        errors = []
        for name in ("channel", "listener"):
            value = getattr(self, name)
            setattr(self, name, None)
            if value is not None:
                if name == "channel":
                    try:
                        self.control_diagnostic = value.diagnostics()
                    except CLEANUP_FAILURES as error:
                        errors.append(error)
                try:
                    value.close()
                except CLEANUP_FAILURES as error:
                    errors.append(error)
        native.raise_errors("host channel close", errors)

    def release(self, deadline):
        if self.terminal_evidence is None:
            raise ValueError("host terminal evidence not closed")
        errors = []
        for method in (self.close_channels, lambda: self.lease.release(deadline)):
            try:
                method()
            except CLEANUP_FAILURES as error:
                errors.append(error)
        native.raise_errors("host reference release", errors)
        self.gate.complete(self.terminal_evidence, deadline)
        self.gate.close()

    def abort(self, row, deadline):
        errors = []
        try:
            self.close_channels()
        except CLEANUP_FAILURES as error:
            errors.append(error)
        if (
            self.lease is not None
            and self.lease.bound is not None
            and not self.lease.terminal
        ):
            try:
                self.lease.stop(deadline)
            except CLEANUP_FAILURES as error:
                errors.append(error)
        if self.directory is None and self.directory_identity is not None:
            try:
                self.directory = native.private_directory(self.root)
                info = os.fstat(self.directory)
                if (info.st_dev, info.st_ino) != self.directory_identity:
                    raise ValueError("host output directory replaced")
                self.writer = job.OwnedOutput(self.directory)
            except CLEANUP_FAILURES as error:
                errors.append(error)
        if self.directory is not None and self.writer is not None:
            try:
                detail = dict(
                    row,
                    ownership_unresolved=True,
                    cleanup_errors=[type(e).__name__ for e in errors],
                    control=self.control_diagnostic,
                )
                if self.lease is not None:
                    detail.update(
                        creation_reply=self.lease.creation_reply,
                        service_observation=self.lease.last_observation,
                    )
                self.write("host-failed", g.evidence.canonical(detail), deadline)
            except CLEANUP_FAILURES as error:
                errors.append(error)
        for method in (
            self.close_directory,
            self.gate.close if self.gate is not None else lambda: None,
        ):
            try:
                method()
            except CLEANUP_FAILURES as error:
                errors.append(error)
        if self.lease is not None or (
            self.gate is not None and self.gate.record is not None
        ):
            UNRESOLVED[self.spec.run_id] = self
        native.raise_errors("host abort cleanup", errors)


def run_prepared(spec, *, effects=None):
    """Caller must already hold R5's verified frozen inputs; not a CLI route."""
    return HostController(
        spec, effects if effects is not None else HostEffects(spec)
    ).run()


if __name__ == "__main__":
    raise SystemExit(77)
