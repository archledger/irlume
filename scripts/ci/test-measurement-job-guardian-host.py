#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""H coordination tests: no service creation and no QEMU execution."""

import hashlib
import importlib.util
import json
import os
import socket
import tempfile
import time
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
# sun_path holds 108 bytes, so directories that will hold a bound AF_UNIX
# socket use this short base instead of TMPDIR, which may be long.
SOCKET_BASE = "/tmp"
SPEC = importlib.util.spec_from_file_location(
    "host", HERE / "measurement-job-guardian-host.py"
)
host = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host)


def specification():
    return host.g.Specification(
        "run-01",
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "boot-only",
        ("supervisor-only",),
        41,
        "/usr/bin/qemu-system-x86_64",
        "/private/base",
        "/private/payload",
        "/private/overlay",
        (0, 1),
    )


class Effects:
    def __init__(self, spec):
        self.spec = spec
        self.time = self.origin = 1_000_000
        self.calls = []
        self.late = None
        self.changed_exit = False
        self.identity = host.g.ServiceIdentity(
            host.g.unit_name(spec),
            "d" * 32,
            4200,
            "/owned",
            self.origin + host.g.HOST_NS,
        )
        self.digest = hashlib.sha256(
            host.g.encode(host.g.launch_request(spec))
        ).hexdigest()
        identity = {
            "run_id": spec.run_id,
            "boot_input_sha256": spec.boot_input_sha256,
            "build_sha256": spec.build_sha256,
            "input_manifest_sha256": spec.input_manifest_sha256,
            "guest_boot_id": "00000000-0000-0000-0000-000000000001",
        }
        batch = {
            "identity": identity,
            "cases": spec.cases,
            "first_epoch": spec.first_epoch,
            "mode": spec.mode,
        }
        terminal = {
            "scope": "contained-job-terminal-v1",
            "mode": spec.mode,
            "identity": identity,
            "batch_sha256": hashlib.sha256(
                host.g.evidence.canonical(batch)
            ).hexdigest(),
            "ledger_bytes": 1234,
            "ledger_sha256": "e" * 64,
            "outcome": "complete",
            "native_authorized": False,
            "full_contract_proven": False,
        }
        raw = host.g.evidence.canonical(terminal)
        stdout = len(raw).to_bytes(4, "big") + raw
        self.receipt = {
            "scope": "contained-job-guardian-v1",
            "run_id": spec.run_id,
            "transaction_sha256": self.digest,
            "service": self.identity._asdict(),
            "host_origin_ns": self.origin,
            "host_deadline_ns": self.identity.deadline_ns,
            "spawn_attempted": True,
            "pid": 4300,
            "terminal_wait": {"pid": 4300, "status": 0, "exitcode": 0},
            "observed_exitcode": 0,
            "stdout_hex": stdout.hex(),
            "stderr_hex": "",
            "stream_bytes": {"stdout": len(stdout), "stderr": 0},
            "eof": ["stderr", "stdout"],
            "guest_terminal": terminal,
            "transport_complete": False,
            "accepted": False,
            "native_authorized": False,
            "full_contract_proven": False,
            "state": "ready-to-finalize",
        }
        self.messages = 0

    def now(self):
        return self.time

    def step(self, name):
        self.calls.append(name)
        if self.late == name:
            self.time += host.g.HOST_NS

    def prepare(self, spec, origin, deadline):
        self.step("prepare")

    def start_service(self, spec, deadline):
        self.step("start")
        return self.identity

    def connect(self, identity, deadline):
        self.step("connect")

    def send(self, data, deadline):
        self.step("send-" + host.g.decode(data)["kind"])

    def receive(self, deadline, *, allow_exit=False):
        self.messages += 1
        if self.messages == 1:
            return host.g.encode(
                {
                    "kind": "ready",
                    "payload": {
                        "transaction_sha256": self.digest,
                        "service": self.identity._asdict(),
                    },
                }
            )
        data = host.g.evidence.canonical(self.receipt)
        return host.g.encode(
            {
                "kind": "done",
                "payload": {
                    "transaction_sha256": self.digest,
                    "invocation_id": self.identity.invocation_id,
                    "receipt_bytes": len(data),
                    "receipt_sha256": hashlib.sha256(data).hexdigest(),
                },
            }
        )

    def expect_eof(self, deadline):
        self.step("eof")

    def read_receipt(self, deadline):
        self.step("read-receipt")
        return host.g.evidence.canonical(self.receipt)

    def wait_terminal(self, deadline):
        self.step("terminal")
        self.time = 3_000_000
        return {
            "unit": {
                "Id": self.identity.unit,
                "InvocationID": self.identity.invocation_id,
                "MainPID": 0,
                "ActiveState": "inactive",
                "SubState": "dead",
                "Result": "success",
                "ExecMainCode": 2 if self.changed_exit else 1,
                "ExecMainStatus": 9 if self.changed_exit else 0,
                "ExecMainStartTimestampMonotonic": 1000,
                "ExecMainExitTimestampMonotonic": 2000,
            },
            "processes": (),
        }

    def finish(self, record, deadline):
        self.step("finish")

    def release(self, deadline):
        self.step("release")

    def abort(self, record, deadline):
        self.step("abort")


class CreationBus:
    def __init__(self, **effective):
        self.effective, self.stops = effective, []

    def start(self, name, properties, argv, deadline):
        self.created = (name, properties, argv, deadline)
        now = time.monotonic_ns() // 1000
        self.row = {
            **{k: v for k, v in properties.items() if k != "AddRef"},
            "Id": name,
            "InvocationID": "a" * 32,
            "MainPID": 4200,
            "ControlGroup": f"/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service/app.slice/"
            + name,
            "ExecMainStartTimestampMonotonic": now,
            "ActiveEnterTimestampMonotonic": now,
            "ActiveState": "active",
            "SubState": "running",
            "Transient": True,
            "ExecStart": ((argv[0], argv, False),),
            **self.effective,
        }
        return "/org/freedesktop/systemd1/job/42"

    def observe(self, name, deadline):
        return dict(self.row)

    def stop(self, name, deadline):
        self.stops.append(name)  # This is a fake bus: no unit was created.


class HostTests(unittest.TestCase):
    def test_success_clears_gate_only_after_closed_receipt_and_terminal_unit(self):
        spec = specification()
        effects = Effects(spec)
        row = host.run_prepared(spec, effects=effects)
        self.assertTrue(row["transport_complete"])
        self.assertFalse(row["accepted"])
        self.assertLess(effects.calls.index("terminal"), effects.calls.index("finish"))
        self.assertEqual(effects.calls[-1], "release")

    def test_done_then_guardian_death_cannot_clear_gate(self):
        spec = specification()
        effects = Effects(spec)
        effects.changed_exit = True
        with self.assertRaises(ValueError):
            host.run_prepared(spec, effects=effects)
        self.assertNotIn("finish", effects.calls)
        self.assertIn("abort", effects.calls)

    def test_rehashed_bad_guardian_wait_still_rejects(self):
        spec = specification()
        effects = Effects(spec)
        effects.receipt["terminal_wait"]["exitcode"] = 1
        with self.assertRaises(ValueError):
            host.run_prepared(spec, effects=effects)
        self.assertNotIn("finish", effects.calls)

    def test_late_receipt_does_not_receive_another_budget(self):
        spec = specification()
        effects = Effects(spec)
        effects.late = "read-receipt"
        with self.assertRaises(TimeoutError):
            host.run_prepared(spec, effects=effects)
        self.assertNotIn("finish", effects.calls)


class NativeHostTests(unittest.TestCase):
    def test_post_finish_expiry_or_channel_close_failure_keeps_blocker(self):
        spec = specification()
        for fault in ("expiry", "channel"):
            with (
                self.subTest(fault=fault),
                tempfile.TemporaryDirectory(dir=SOCKET_BASE) as directory,
            ):
                end = time.monotonic_ns() + 2_000_000_000
                effects = host.HostEffects(
                    spec,
                    _gate_factory=lambda deadline: host.native.service.AdmissionGate(
                        Path(directory), deadline
                    ),
                )
                try:
                    effects.prepare(spec, time.monotonic_ns(), end)
                    effects.lease = SimpleNamespace(
                        terminal=True, release=host.native.before
                    )
                    effects.last_receipt = b"verified"
                    effects.finish({"state": "ready-to-finalize"}, end)
                    if fault == "channel":

                        def failed_close():
                            raise OSError("channel close failed")

                        effects.channel = SimpleNamespace(
                            diagnostics=dict, close=failed_close
                        )
                        deadline = end
                    else:
                        deadline = time.monotonic_ns() - 1
                    with self.assertRaises(OSError):
                        effects.release(deadline)
                    self.assertTrue((Path(directory) / "active.json").exists())
                finally:
                    effects.close_channels()
                    effects.close_directory()
                    if effects.gate is not None:
                        effects.gate.close()

    def test_large_nonascii_invalid_done_preserves_raw_failure_evidence(self):
        spec = specification()
        body = json.dumps(
            {"kind": "done", "payload": {"padding": "é" * 8000}}, ensure_ascii=False
        ).encode()
        bad = len(body).to_bytes(4, "big") + body
        self.assertLessEqual(len(bad), host.g.CONTROL_LIMIT + 4)

        class Transcript(host.HostEffects):
            def start_service(self, selected, deadline):
                self.identity = host.g.ServiceIdentity(
                    host.g.unit_name(selected),
                    "d" * 32,
                    4200,
                    "/owned",
                    self.config["origin_ns"] + host.g.HOST_NS,
                )
                return self.identity

            def connect(self, identity, deadline):
                left, self.peer = socket.socketpair()
                self.channel = host.g.PeerChannel(
                    left, (os.getpid(), os.getuid(), os.getgid())
                )

            def send(self, data, deadline):
                kind = host.g.decode(data)["kind"]
                if kind == "launch":
                    digest = hashlib.sha256(
                        host.g.encode(host.g.launch_request(spec))
                    ).hexdigest()
                    reply = host.g.encode(
                        {
                            "kind": "ready",
                            "payload": {
                                "transaction_sha256": digest,
                                "service": self.identity._asdict(),
                            },
                        }
                    )
                else:
                    reply = bad
                self.peer.sendall(reply)

        with tempfile.TemporaryDirectory(dir=SOCKET_BASE) as directory:
            effects = Transcript(
                spec,
                _gate_factory=lambda deadline: host.native.service.AdmissionGate(
                    Path(directory), deadline
                ),
            )
            try:
                with self.assertRaises((ValueError, BaseExceptionGroup)) as caught:
                    host.run_prepared(spec, effects=effects)
                failure_file = effects.root / "host-failed.json"
                self.assertTrue(failure_file.exists())
                self.assertIsInstance(caught.exception, ValueError)
                row = json.loads(failure_file.read_bytes())
                self.assertIsNone(row["done"])
                self.assertEqual(row["control"]["received_hex"], bad.hex())
            finally:
                if hasattr(effects, "peer"):
                    effects.peer.close()
                effects.close_channels()
                effects.close_directory()
                if effects.gate is not None:
                    effects.gate.close()
                host.UNRESOLVED.clear()

    def test_release_failure_is_journaled_after_output_directory_closed(self):
        spec = specification()
        with tempfile.TemporaryDirectory(dir=SOCKET_BASE) as directory:
            effects = host.HostEffects(
                spec,
                _gate_factory=lambda deadline: host.native.service.AdmissionGate(
                    Path(directory), deadline
                ),
            )
            end = time.monotonic_ns() + 2_000_000_000
            right = None
            try:
                effects.prepare(spec, time.monotonic_ns(), end)
                left, right = socket.socketpair()
                effects.channel = host.g.PeerChannel(
                    left, (os.getpid(), os.getuid(), os.getgid())
                )
                effects.channel.last_peek = b"retained-control"

                def failed_release(deadline):
                    raise OSError("reference close failed")

                effects.lease = SimpleNamespace(
                    terminal=True,
                    created=True,
                    bound=None,
                    release=failed_release,
                    creation_reply="job",
                    last_observation={},
                )
                effects.last_receipt = b"verified"
                effects.finish({"state": "ready-to-finalize"}, end)
                self.assertIsNone(effects.directory)
                with self.assertRaises(OSError):
                    effects.release(end)
                effects.abort(
                    {
                        "state": "failed",
                        "error": "OSError",
                        "message": "reference close failed",
                    },
                    end,
                )
                failure_file = effects.root / "host-failed.json"
                self.assertTrue(failure_file.exists())
                row = json.loads(failure_file.read_bytes())
                self.assertEqual(row["message"], "reference close failed")
                self.assertEqual(
                    row["control"]["last_peek_hex"], b"retained-control".hex()
                )
                self.assertTrue((Path(directory) / "active.json").exists())
            finally:
                if right is not None:
                    right.close()
                effects.close_channels()
                effects.close_directory()
                if effects.gate is not None:
                    effects.gate.close()
                host.UNRESOLVED.clear()

    def test_failed_host_persists_partial_or_surplus_control_before_disposal(self):
        spec = specification()
        for partial in (True, False):
            with tempfile.TemporaryDirectory(dir=SOCKET_BASE) as directory:
                end = time.monotonic_ns() + 2_000_000_000
                effects = host.HostEffects(
                    spec,
                    _gate_factory=lambda deadline: host.native.service.AdmissionGate(
                        Path(directory), deadline
                    ),
                )
                left, right = socket.socketpair()
                try:
                    effects.prepare(spec, time.monotonic_ns(), end)
                    effects.channel = host.g.PeerChannel(
                        left, (os.getpid(), os.getuid(), os.getgid())
                    )
                    raw = b"\0\0" if partial else b"x"
                    right.sendall(raw)
                    if partial:
                        with self.assertRaises(TimeoutError):
                            effects.channel.receive(time.monotonic_ns() + 10_000_000)
                    else:
                        with self.assertRaises(ValueError):
                            effects.channel.expect_eof(end)
                    effects.abort({"state": "failed"}, end)
                    record = json.loads(
                        (effects.root / "host-failed.json").read_bytes()
                    )
                    diagnostic = record.get("control", {})
                    key = "received_hex" if partial else "last_peek_hex"
                    self.assertEqual(diagnostic.get(key), raw.hex())
                finally:
                    right.close()
                    left.close()
                    effects.close_channels()
                    effects.close_directory()
                    if effects.gate is not None:
                        effects.gate.close()
                host.UNRESOLVED.clear()

    def test_reference_close_failure_keeps_admission_blocker(self):
        class Lease:
            terminal = True

            def release(self, deadline):
                raise OSError("reference close failed")

        spec = specification()
        with tempfile.TemporaryDirectory(dir=SOCKET_BASE) as directory:
            end = time.monotonic_ns() + 2_000_000_000
            effects = host.HostEffects(
                spec,
                _gate_factory=lambda deadline: host.native.service.AdmissionGate(
                    Path(directory), deadline
                ),
            )
            try:
                effects.prepare(spec, time.monotonic_ns(), end)
                effects.lease = Lease()
                effects.last_receipt = b"already-verified"
                effects.finish({"state": "ready-to-finalize"}, end)
                self.assertTrue((Path(directory) / "active.json").exists())
                with self.assertRaises(OSError):
                    effects.release(end)
                self.assertTrue((Path(directory) / "active.json").exists())
            finally:
                effects.close_channels()
                effects.close_directory()
                if effects.gate is not None:
                    effects.gate.close()

    def test_preparation_claims_shared_gate_before_service_creation(self):
        spec = specification()
        with tempfile.TemporaryDirectory(dir=SOCKET_BASE) as directory:
            gate_root = Path(directory)
            factory = lambda deadline: host.native.service.AdmissionGate(
                gate_root, deadline
            )
            effects = host.HostEffects(spec, _gate_factory=factory)
            end = time.monotonic_ns() + 3_000_000_000
            try:
                effects.prepare(spec, time.monotonic_ns(), end)
                self.assertTrue((gate_root / "active.json").exists())
                self.assertIsNone(effects.lease)
                self.assertEqual(
                    (effects.root / "guardian-config.json").stat().st_mode & 0o777,
                    0o600,
                )
            finally:
                effects.abort({"state": "test-abort"}, end)
            second = host.HostEffects(
                spec._replace(run_id="run-02"), _gate_factory=factory
            )
            try:
                with self.assertRaises(FileExistsError):
                    second.prepare(second.spec, time.monotonic_ns(), end)
            finally:
                second.abort({"state": "test-abort"}, end)
            host.UNRESOLVED.clear()  # Test-only objects; no real service exists.

    def test_concrete_creation_uses_addref_and_binds_exact_snapshot(self):
        spec = specification()

        with tempfile.TemporaryDirectory(dir=SOCKET_BASE) as directory:
            bus = CreationBus()
            effects = host.HostEffects(
                spec,
                _gate_factory=lambda deadline: host.native.service.AdmissionGate(
                    Path(directory), deadline
                ),
                _bus_factory=lambda uid, deadline: bus,
            )
            end = time.monotonic_ns() + 3_000_000_000
            try:
                effects.prepare(spec, time.monotonic_ns(), end)
                identity = effects.start_service(spec, end)
                self.assertEqual(identity.invocation_id, "a" * 32)
                self.assertIs(bus.created[1]["AddRef"], True)
                self.assertIn("--service", bus.created[2])
                self.assertIsNotNone(effects.lease.bound)
            finally:
                effects.abort({"state": "test-abort"}, end)
            self.assertEqual(bus.stops, [host.g.unit_name(spec)])
            host.UNRESOLVED.clear()

    def test_abort_stops_created_service_refused_before_binding(self):
        spec = specification()
        # A third CPU in the effective mask refuses the service before binding.
        bus = CreationBus(CPUAffinity=(7,))
        with tempfile.TemporaryDirectory(dir=SOCKET_BASE) as directory:
            effects = host.HostEffects(
                spec,
                _gate_factory=lambda deadline: host.native.service.AdmissionGate(
                    Path(directory), deadline
                ),
                _bus_factory=lambda uid, deadline: bus,
            )
            end = time.monotonic_ns() + 3_000_000_000
            try:
                effects.prepare(spec, time.monotonic_ns(), end)
                with self.assertRaisesRegex(ValueError, "CPUAffinity"):
                    effects.start_service(spec, end)
                self.assertTrue(effects.lease.created)
                self.assertIsNone(effects.lease.bound)
            finally:
                effects.abort({"state": "test-abort"}, end)
            self.assertEqual(bus.stops, [host.g.unit_name(spec)])
            self.assertTrue(effects.lease.stop_attempted)
            self.assertTrue((Path(directory) / "active.json").exists())
            self.assertIs(host.UNRESOLVED[spec.run_id], effects)
            host.UNRESOLVED.clear()


if __name__ == "__main__":
    unittest.main()
