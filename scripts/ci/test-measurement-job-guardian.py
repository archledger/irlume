#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Private guardian contracts; service and VM execution are never test effects."""

import contextlib
import hashlib
import importlib.util
import json
import os
import socket
import time
import unittest
from builtins import BaseExceptionGroup
from collections import deque
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "guardian", HERE / "measurement-job-guardian.py"
)
guardian = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guardian)


def specification(**changes):
    values = {
        "run_id": "run-01",
        "boot_input_sha256": "a" * 64,
        "build_sha256": "b" * 64,
        "input_manifest_sha256": "c" * 64,
        "mode": "boot-only",
        "cases": ("supervisor-only",),
        "first_epoch": 41,
        "qemu": "/usr/bin/qemu-system-x86_64",
        "base": "/private/base.raw",
        "payload": "/private/payload.raw",
        "overlay": "/private/run/overlay.qcow2",
        "cpus": (0, 1),
    }
    values.update(changes)
    return guardian.Specification(**values)


def service_snapshot(spec):
    name = guardian.unit_name(spec)
    return {
        **{k: v for k, v in guardian.service_properties(spec).items() if k != "AddRef"},
        "Id": name,
        "InvocationID": "d" * 32,
        "MainPID": 4200,
        "ControlGroup": "/user.slice/user-1000.slice/user@1000.service/app.slice/"
        + name,
        "ExecMainStartTimestampMonotonic": 10,
        "ActiveEnterTimestampMonotonic": 11,
        "ActiveState": "active",
        "SubState": "running",
        "Transient": True,
    }


def terminal(spec, **changes):
    identity = {
        "run_id": spec.run_id,
        "boot_input_sha256": spec.boot_input_sha256,
        "guest_boot_id": "00000000-0000-0000-0000-000000000001",
        "build_sha256": spec.build_sha256,
        "input_manifest_sha256": spec.input_manifest_sha256,
    }
    batch = {
        "identity": identity,
        "cases": spec.cases,
        "first_epoch": spec.first_epoch,
        "mode": spec.mode,
    }
    row = {
        "scope": "contained-job-terminal-v1",
        "mode": spec.mode,
        "identity": identity,
        "batch_sha256": hashlib.sha256(guardian.evidence.canonical(batch)).hexdigest(),
        "ledger_bytes": 1234,
        "ledger_sha256": "e" * 64,
        "outcome": "complete",
        "native_authorized": False,
        "full_contract_proven": False,
    }
    row.update(changes)
    data = guardian.evidence.canonical(row)
    return len(data).to_bytes(4, "big") + data


class LaunchTests(unittest.TestCase):
    def test_qemu_has_only_bounded_owned_streams_and_fixed_devices(self):
        spec = specification()
        argv = guardian.qemu_argv(spec)
        self.assertNotIn("-serial", argv)
        self.assertIn("stdio,id=job-status,mux=off,signal=off", argv)
        self.assertIn(
            "virtserialport,nr=1,chardev=job-status,name=irlume-job-status", argv
        )
        self.assertEqual(argv[argv.index("-nic") + 1], "none")
        self.assertEqual(argv[argv.index("-accel") + 1], "kvm")
        self.assertEqual(argv[argv.index("-m") + 1], "2048")
        disks = [
            json.loads(argv[i + 1]) for i, v in enumerate(argv) if v == "-blockdev"
        ]
        self.assertEqual(disks[0]["backing"]["driver"], "raw")
        self.assertIs(disks[0]["backing"]["read-only"], True)
        self.assertIs(disks[1]["read-only"], True)

    def test_terminal_binds_selected_batch_without_claiming_certification(self):
        spec = specification()
        row = guardian.check_terminal(terminal(spec), spec)
        self.assertEqual(row["outcome"], "complete")
        self.assertFalse(row["native_authorized"])
        for change in (
            {"batch_sha256": "f" * 64},
            {"mode": "runtime-candidate"},
            {"outcome": "expected-abort"},
            {"ledger_bytes": True},
            {"ledger_bytes": 0},
            {"ledger_sha256": "bad"},
            {"native_authorized": True},
            {"full_contract_proven": 0},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                guardian.check_terminal(terminal(spec, **change), spec)

    def test_only_selected_quarantine_can_end_expected_abort(self):
        spec = specification(mode="runtime-candidate", cases=("bounds-withheld-wait",))
        self.assertEqual(
            guardian.check_terminal(terminal(spec, outcome="expected-abort"), spec)[
                "outcome"
            ],
            "expected-abort",
        )
        with self.assertRaises(ValueError):
            guardian.check_terminal(terminal(spec), spec)


class ChannelTests(unittest.TestCase):
    @contextlib.contextmanager
    def exiting_peer(self, *, partial=False, expired=False):
        left, right = socket.socketpair()
        clock = [time.monotonic_ns()]
        deadline = clock[0] + 1_000_000_000
        dead = [False]

        class Wire:
            def __getattr__(self, name):
                return getattr(left, name)

            def send(self, data):
                count = left.send(data[:1] if partial else data)
                dead[0] = True
                if expired:
                    clock[0] = deadline
                return count

        channel = None
        try:
            channel = guardian.PeerChannel(
                Wire(), (os.getpid(), os.getuid(), os.getgid()), now=lambda: clock[0]
            )
            select = guardian.select.select

            def readiness(read, write, error, timeout):
                if read == [channel.peer_fd]:
                    return ([channel.peer_fd] if dead[0] else [], [], [])
                return select(read, write, error, timeout)

            with mock.patch.object(guardian.select, "select", side_effect=readiness):
                yield channel, right, dead, deadline
        finally:
            if channel is not None:
                channel.close()
            else:
                left.close()
            right.close()

    def test_final_send_allows_exit_but_still_requires_done_and_eof(self):
        frame = guardian.encode({"kind": "commit", "payload": {}})
        done = guardian.encode({"kind": "done", "payload": {}})
        with self.exiting_peer() as (channel, right, _, deadline):
            try:
                channel.send(frame, deadline, allow_exit_after_send=True)
            except ValueError as error:
                self.fail(f"final send rejected a post-write exit: {error}")
            self.assertEqual(right.recv(len(frame)), frame)
            right.sendall(done)
            right.close()
            self.assertEqual(channel.receive(deadline, allow_exit=True), done)
            channel.expect_eof(deadline)

    def test_ordinary_send_still_rejects_peer_exit(self):
        with (
            self.exiting_peer() as (channel, _, _, deadline),
            self.assertRaisesRegex(ValueError, "peer terminated"),
        ):
            channel.send(guardian.encode({"kind": "ready", "payload": {}}), deadline)

    def test_final_send_rejects_exit_during_partial_write(self):
        with (
            self.exiting_peer(partial=True) as (channel, _, _, deadline),
            self.assertRaisesRegex(ValueError, "peer terminated"),
        ):
            channel.send(
                guardian.encode({"kind": "commit", "payload": {}}),
                deadline,
                allow_exit_after_send=True,
            )

    def test_final_send_rejects_exit_before_any_write(self):
        with self.exiting_peer() as (channel, _, dead, deadline):
            dead[0] = True
            with self.assertRaisesRegex(ValueError, "peer terminated"):
                channel.send(
                    guardian.encode({"kind": "commit", "payload": {}}),
                    deadline,
                    allow_exit_after_send=True,
                )
            self.assertEqual(channel.sent_total, 0)

    def test_final_send_still_rejects_deadline_after_last_write(self):
        with (
            self.exiting_peer(expired=True) as (channel, _, _, deadline),
            self.assertRaises(TimeoutError),
        ):
            channel.send(
                guardian.encode({"kind": "commit", "payload": {}}),
                deadline,
                allow_exit_after_send=True,
            )

    def test_peer_pidfd_constant_is_restricted_to_the_qualified_platform(self):
        left, right = socket.socketpair()
        channel = None
        try:
            foreign = os.uname_result(
                ("Linux", "host", "release", "version", "aarch64")
            )
            with (
                mock.patch.object(guardian.os, "uname", return_value=foreign),
                self.assertRaises(ValueError),
            ):
                channel = guardian.PeerChannel(
                    left, (os.getpid(), os.getuid(), os.getgid())
                )
        finally:
            if channel is not None:
                channel.close()
            else:
                left.close()
            right.close()

    def test_exact_peer_channel_roundtrip_and_eof(self):
        left, right = socket.socketpair()
        channel = None
        try:
            channel = guardian.PeerChannel(
                left, (os.getpid(), os.getuid(), os.getgid())
            )
            raw = guardian.encode({"kind": "commit", "payload": {"digest": "a" * 64}})
            right.sendall(raw)
            self.assertEqual(channel.receive(time.monotonic_ns() + 1_000_000_000), raw)
            channel.send(raw, time.monotonic_ns() + 1_000_000_000)
            self.assertEqual(right.recv(len(raw)), raw)
            right.close()
            channel.expect_eof(time.monotonic_ns() + 1_000_000_000)
        finally:
            if channel is not None:
                channel.close()
            else:
                left.close()
            right.close()

    def test_wrong_peer_is_rejected_and_owned_socket_closed(self):
        left, right = socket.socketpair()
        try:
            with self.assertRaises(ValueError):
                guardian.PeerChannel(left, (os.getpid() + 1, os.getuid(), os.getgid()))
            self.assertEqual(left.fileno(), -1)
        finally:
            left.close()
            right.close()

    def test_partial_frame_timeout_and_surplus_keep_received_bytes(self):
        for raw in (b"\0\0", b"\0\0\0\2{}surplus"):
            left, right = socket.socketpair()
            channel = None
            try:
                channel = guardian.PeerChannel(
                    left, (os.getpid(), os.getuid(), os.getgid())
                )
                right.sendall(raw)
                with (
                    self.subTest(raw=raw),
                    self.assertRaises((TimeoutError, ValueError)),
                ):
                    channel.receive(time.monotonic_ns() + 10_000_000)
                self.assertEqual(bytes(channel.received), raw)
            finally:
                if channel is not None:
                    channel.close()
                else:
                    left.close()
                right.close()

    def test_running_channel_rejects_input_or_eof(self):
        for payload in (b"cancel", None):
            left, right = socket.socketpair()
            channel = None
            try:
                channel = guardian.PeerChannel(
                    left, (os.getpid(), os.getuid(), os.getgid())
                )
                channel.require_idle(time.monotonic_ns() + 1_000_000_000)
                if payload is None:
                    right.close()
                else:
                    right.sendall(payload)
                with self.assertRaises(ValueError):
                    channel.require_idle(time.monotonic_ns() + 1_000_000_000)
            finally:
                if channel is not None:
                    channel.close()
                else:
                    left.close()
                right.close()


class Effects:
    def __init__(self, spec):
        self.time = 100
        self.calls = []
        self.fault = None
        self.late = None
        self.sent = []
        self.failure = None
        self.closed_record = None
        self.owner = {"attempted": False, "pid": None, "reaped": False}
        digest = hashlib.sha256(
            guardian.encode(guardian.launch_request(spec))
        ).hexdigest()
        self.messages = deque(
            [
                guardian.encode(guardian.launch_request(spec)),
                guardian.encode(
                    {"kind": "commit", "payload": {"transaction_sha256": digest}}
                ),
            ]
        )
        self.events = deque(
            [
                ("stdout", terminal(spec)),
                ("stdout", None),
                ("stderr", None),
                ("exit", 0),
            ]
        )

    def step(self, name):
        self.calls.append(name)
        if self.late == name:
            self.time += guardian.HOST_NS
        if self.fault == name:
            raise OSError(name)

    def now(self):
        return self.time

    def preflight(self, spec, deadline):
        self.step("preflight")
        return guardian.ServiceIdentity(
            guardian.unit_name(spec), "d" * 32, 4200, "/owned", 100 + guardian.HOST_NS
        )

    def record(self, kind, row, deadline):
        self.step("record-" + kind)

    def receive(self, deadline):
        self.step("receive")
        return self.messages.popleft()

    def send(self, data, deadline):
        row = guardian.decode(data)
        self.step("send-" + row["kind"])
        self.sent.append(row)

    def require_idle(self, deadline):
        self.step("idle-running" if self.owner["attempted"] else "idle")

    def spawn(self, spec, deadline):
        self.owner["attempted"] = True
        self.step("spawn")
        self.owner["pid"] = 4300
        return 4300

    def event(self, deadline):
        self.step("event")
        if self.events:
            return self.events.popleft()
        self.time = deadline
        return None

    def owner_state(self):
        return dict(self.owner)

    def stop(self, deadline):
        self.step("stop")

    def reap(self, deadline):
        self.step("reap")
        self.owner["reaped"] = True
        return {"pid": self.owner["pid"], "exitcode": 0, "status": 0}

    def close_child(self):
        self.step("close-child")

    def finalize(self, row, deadline):
        self.step("finalize")
        self.closed_record = dict(row)
        data = guardian.evidence.canonical(row)
        return len(data), hashlib.sha256(data).hexdigest()

    def failed(self, row, deadline):
        self.step("failed")
        self.failure = dict(row)

    def close_control(self):
        self.step("close-control")


class GuardianTests(unittest.TestCase):
    def test_input_or_write_eof_during_done_send_is_still_rejected(self):
        spec = specification()
        for reason in ("pending input", "write-side EOF"):
            effects = Effects(spec)
            original_send = effects.send
            state = {"after_done": False}

            def send(data, deadline, original_send=original_send, state=state):
                original_send(data, deadline)
                if guardian.decode(data)["kind"] == "done":
                    state["after_done"] = True

            def idle(deadline, reason=reason, state=state):
                if state["after_done"]:
                    raise ValueError(reason)

            effects.send = send
            effects.require_idle = idle
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                guardian.run_guardian(effects, spec, 100)
            self.assertTrue(state["after_done"])
            self.assertIsNotNone(effects.failure)

    def test_nonzero_observation_is_not_repaired_by_later_zero_wait(self):
        spec = specification()
        for status in (7, -9):
            effects = Effects(spec)
            effects.events[-1] = ("exit", status)
            # Fault injection: a later apparently clean wait must not erase the
            # earlier observed nonzero/signal result.
            with self.subTest(status=status), self.assertRaises(ValueError):
                guardian.run_guardian(effects, spec, 100)
            self.assertEqual(effects.failure["observed_exitcode"], status)
            self.assertFalse(any(row["kind"] == "done" for row in effects.sent))

    def test_success_requires_handshake_wait_closed_receipt_and_done(self):
        spec = specification()
        effects = Effects(spec)
        result = guardian.run_guardian(effects, spec, 100)
        self.assertTrue(result["transport_complete"])
        self.assertFalse(result["accepted"])
        for before, after in (
            ("send-ready", "spawn"),
            ("spawn", "reap"),
            ("reap", "finalize"),
            ("finalize", "send-done"),
            ("send-done", "close-control"),
        ):
            self.assertLess(effects.calls.index(before), effects.calls.index(after))
        self.assertEqual(
            effects.sent[-1]["payload"]["receipt_sha256"],
            hashlib.sha256(
                guardian.evidence.canonical(effects.closed_record)
            ).hexdigest(),
        )

    def test_bad_commit_never_spawns(self):
        spec = specification()
        effects = Effects(spec)
        effects.messages[-1] = guardian.encode(
            {"kind": "commit", "payload": {"transaction_sha256": "0" * 64}}
        )
        with self.assertRaises(ValueError):
            guardian.run_guardian(effects, spec, 100)
        self.assertFalse(effects.owner["attempted"])
        self.assertIsNotNone(effects.failure)

    def test_peer_loss_stops_and_reaps_exact_owner(self):
        spec = specification()
        effects = Effects(spec)
        effects.fault = "idle-running"
        with self.assertRaises(OSError):
            guardian.run_guardian(effects, spec, 100)
        self.assertIn("stop", effects.calls)
        self.assertTrue(effects.owner["reaped"])
        self.assertEqual(bytes.fromhex(effects.failure["stdout_hex"]), terminal(spec))
        self.assertFalse(any(row["kind"] == "done" for row in effects.sent))

    def test_late_read_retains_bytes_but_never_completes(self):
        spec = specification()
        effects = Effects(spec)
        effects.late = "event"
        with self.assertRaises((TimeoutError, BaseExceptionGroup)):
            guardian.run_guardian(effects, spec, 100)
        self.assertEqual(bytes.fromhex(effects.failure["stdout_hex"]), terminal(spec))
        self.assertFalse(any(row["kind"] == "done" for row in effects.sent))

    def test_failed_reap_retains_unresolved_domain(self):
        spec = specification()
        effects = Effects(spec)
        effects.fault = "reap"
        with self.assertRaises(BaseExceptionGroup):
            guardian.run_guardian(effects, spec, 100)
        self.assertFalse(effects.owner["reaped"])
        self.assertTrue(effects.failure["leftover"])

    def test_finalization_failure_cannot_be_repaired_by_done(self):
        spec = specification()
        effects = Effects(spec)
        effects.fault = "finalize"
        with self.assertRaises(OSError):
            guardian.run_guardian(effects, spec, 100)
        self.assertFalse(any(row["kind"] == "done" for row in effects.sent))

    def test_control_close_failure_after_done_still_fails(self):
        spec = specification()
        effects = Effects(spec)
        effects.fault = "close-control"
        with self.assertRaises(OSError):
            guardian.run_guardian(effects, spec, 100)
        self.assertTrue(any(row["kind"] == "done" for row in effects.sent))
        self.assertEqual(effects.calls.count("close-control"), 1)
        self.assertEqual(effects.failure["state"], "failed")


class ServiceTests(unittest.TestCase):
    def test_service_profile_preserves_loss_cleanup_and_pins_metadata(self):
        spec = specification()
        properties = guardian.service_properties(spec)
        self.assertIs(properties["AddRef"], True)
        self.assertIs(properties["RemainAfterExit"], False)
        self.assertEqual(properties["KillSignal"], 9)
        self.assertEqual(properties["KillMode"], "control-group")
        identity = guardian.check_service(
            service_snapshot(spec), spec, 4200, 1000, 100_000
        )
        self.assertEqual(identity.deadline_ns, 10_000 + 300_000_000_000)
        self.assertEqual(identity.invocation_id, "d" * 32)

    def test_wrong_effective_service_identity_or_limit_refuses(self):
        spec = specification()
        for key, value in (
            ("MainPID", 4201),
            ("InvocationID", ""),
            ("Transient", False),
            ("RemainAfterExit", True),
            ("Restart", "always"),
            ("RuntimeMaxUSec", 301_000_000),
            ("NotifyAccess", "all"),
            ("KillMode", "process"),
            ("SendSIGKILL", False),
            ("CPUQuotaPerSecUSec", 3_000_000),
            ("CPUAffinity", (1, 2)),
            ("MemoryMax", 2**64 - 1),
            ("ExecMainStartTimestampMonotonic", 0),
            ("ExecMainStartTimestampMonotonic", True),
            ("ControlGroup", "/another/" + guardian.unit_name(spec)),
        ):
            row = service_snapshot(spec)
            row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guardian.check_service(row, spec, 4200, 1000, 100_000)

    def test_zero_padded_cpu_mask_readback_is_the_same_selection(self):
        # systemd reads CPUAffinity back as its whole CPU_ALLOC_SIZE buffer.
        for cpus, readback in (
            ((0, 1), (3, 0, 0, 0, 0, 0, 0, 0)),
            ((9, 10), (0, 6, 0, 0, 0, 0, 0, 0)),
            ((63, 64), (0,) * 7 + (0x80, 1) + (0,) * 7),
            ((0, 1), (3,) + (0,) * 511),
            ((7, 4095), (0x80,) + (0,) * 510 + (0x80,)),
        ):
            spec = specification(cpus=cpus)
            row = service_snapshot(spec)
            row["CPUAffinity"] = readback
            with self.subTest(cpus=cpus, size=len(readback)):
                identity = guardian.check_service(row, spec, 4200, 1000, 100_000)
                self.assertEqual(identity.invocation_id, "d" * 32)
                self.assertEqual(row["CPUAffinity"], readback)

    def test_cpu_mask_refuses_other_cpus_malformed_or_oversized_readback(self):
        spec = specification()
        self.assertEqual(guardian.service_properties(spec)["CPUAffinity"], (3,))
        for value in (
            (),
            (0,),
            (0,) * 8,
            (1,),
            (2,),
            (7,),
            (0, 3),
            (3, 1),
            (3, 0, 0, 0, 0, 0, 0, 0x80),
            (3,) + (0,) * 510 + (1,),
            (3,) + (0,) * 512,
            (3, False),
            (3.0,),
            ("\x03",),
            (3, -1),
            (3, 256),
            (259,),
            [3, 0, 0, 0, 0, 0, 0, 0],
            b"\x03\0\0\0\0\0\0\0",
            None,
        ):
            row = service_snapshot(spec)
            row["CPUAffinity"] = value
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "CPUAffinity"),
            ):
                guardian.check_service(row, spec, 4200, 1000, 100_000)

    def test_multi_byte_cpu_mask_refuses_any_other_bit_or_truncation(self):
        spec = specification(cpus=(9, 10))
        self.assertEqual(guardian.service_properties(spec)["CPUAffinity"], (0, 6))
        for value in (
            (0,),
            (0, 2, 0, 0, 0, 0, 0, 0),
            (0, 4, 0, 0, 0, 0, 0, 0),
            (0, 22, 0, 0, 0, 0, 0, 0),
            (1, 6, 0, 0, 0, 0, 0, 0),
            (0, 6, 1, 0, 0, 0, 0, 0),
            (6, 0, 0, 0, 0, 0, 0, 0),
        ):
            row = service_snapshot(spec)
            row["CPUAffinity"] = value
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "CPUAffinity"),
            ):
                guardian.check_service(row, spec, 4200, 1000, 100_000)

    def test_service_deadline_is_not_restarted_at_observation(self):
        spec = specification()
        row = service_snapshot(spec)
        for now in (9999, 10_000 + 300_000_000_000):
            with self.subTest(now=now), self.assertRaises(ValueError):
                guardian.check_service(row, spec, 4200, 1000, now)


class WireTests(unittest.TestCase):
    def test_duplicate_selection_is_rejected_before_terminal_admission(self):
        spec = specification(
            mode="runtime-candidate", cases=("supervisor-only", "supervisor-only")
        )
        with self.assertRaises(ValueError):
            guardian.validate_spec(spec)
        with self.assertRaises(ValueError):
            guardian.check_terminal(terminal(spec), spec)

    def test_specification_is_immutable_and_request_has_no_executable_overrides(self):
        spec = specification()
        guardian.validate_spec(spec)
        request = guardian.launch_request(spec)
        self.assertEqual(request["kind"], "launch")
        self.assertEqual(request["payload"]["mode"], "boot-only")
        for forbidden in ("argv", "environment", "deadline", "qualified"):
            self.assertNotIn(forbidden, request["payload"])
        with self.assertRaises(AttributeError):
            spec.run_id = "other"

    def test_invalid_selection_or_quarantine_order_refuses(self):
        for change in (
            {"run_id": "../run"},
            {"build_sha256": "bad"},
            {"first_epoch": True},
            {"first_epoch": 0},
            {"mode": "runtime"},
            {"cpus": (0, 0)},
            {"cpus": [0, 1]},
            {"base": "relative"},
            {
                "cases": ("bounds-withheld-wait", "supervisor-only"),
                "mode": "runtime-candidate",
            },
            {"cases": ("unknown",)},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                guardian.validate_spec(specification(**change))

    def test_wire_is_bounded_exact_and_rejects_duplicate_or_noninteger_fields(self):
        request = guardian.launch_request(specification())
        frame = guardian.encode(request)
        self.assertEqual(guardian.decode(frame), request)
        for raw in (frame[:-1], frame + b"x", b"\0\0\0\0", b"\xff" * 4):
            with self.subTest(raw=raw[:8]), self.assertRaises(ValueError):
                guardian.decode(raw)
        for body in (
            b'{"kind":"launch","kind":"cancel","payload":{}}',
            b'{"kind":"launch","payload":{"epoch":1.0}}',
        ):
            with self.assertRaises(ValueError):
                guardian.decode(len(body).to_bytes(4, "big") + body)


if __name__ == "__main__":
    unittest.main()
