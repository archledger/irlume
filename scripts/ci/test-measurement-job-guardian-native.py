#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Concrete guardian primitives with only explicitly owned inert children."""

import hashlib
import importlib.util
import io
import json
import os
import socket
import stat
import sys
import tempfile
import time
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
# sun_path holds 108 bytes, so directories that will hold a bound AF_UNIX
# socket use this short base instead of TMPDIR, which may be long.
SOCKET_BASE = "/tmp"
SPEC = importlib.util.spec_from_file_location(
    "native", HERE / "measurement-job-guardian-native.py"
)
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


def specification():
    return native.guardian.Specification(
        "run-01",
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "boot-only",
        ("supervisor-only",),
        41,
        "/usr/bin/qemu-system-x86_64",
        "/private/base.raw",
        "/private/payload.raw",
        "/private/run/overlay.qcow2",
        (0, 1),
    )


class NativeEffectsTests(unittest.TestCase):
    def test_actual_preflight_refuses_before_child_or_control_connection(self):
        spec = specification()
        cases = (
            ("property", "effective service property"),
            ("argv", "executable binding"),
            ("membership", "effective placement"),
            ("membership-v1-only", "effective placement"),
            ("affinity", "effective placement"),
            ("client", "client identity"),
            ("endpoint", "control endpoint"),
        )
        for fault, reason in cases:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                origin = time.monotonic_ns()
                config = native.make_config(spec, origin)
                effects = native.GuardianEffects(root, config, spec)
                group = (
                    f"/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service/app.slice/"
                    + native.guardian.unit_name(spec)
                )
                argv = native.entry_argv(
                    root,
                    hashlib.sha256(
                        native.guardian.evidence.canonical(config)
                    ).hexdigest(),
                )
                row = {
                    k: v
                    for k, v in native.guardian.service_properties(spec).items()
                    if k != "AddRef"
                }
                row.update(
                    Id=native.guardian.unit_name(spec),
                    InvocationID="d" * 32,
                    MainPID=os.getpid(),
                    ControlGroup=group,
                    ExecStart=((argv[0], argv, False),),
                    ExecMainStartTimestampMonotonic=origin // 1000,
                    ActiveEnterTimestampMonotonic=origin // 1000,
                    ActiveState="active",
                    SubState="running",
                    Transient=True,
                )
                if fault == "property":
                    row["RuntimeMaxUSec"] += 1
                if fault == "argv":
                    row["ExecStart"] = ()
                (root / "control.sock").write_bytes(b"not a socket")
                (root / "control.sock").chmod(0o600)
                bus = mock.Mock()
                bus.observe.return_value = row
                real_open = open

                def opened(
                    path, *args, fault=fault, group=group, real_open=real_open, **kwargs
                ):
                    if path == "/proc/self/cgroup":
                        return io.StringIO(
                            {
                                "membership": "0::/wrong\n",
                                "membership-v1-only": "1:net_cls:/\n",
                            }.get(fault, "1:net_cls:/\n0::" + group + "\n")
                        )
                    return real_open(path, *args, **kwargs)

                try:
                    with (
                        mock.patch.object(
                            native.service, "SystemdBus", return_value=bus
                        ),
                        mock.patch("builtins.open", side_effect=opened),
                        mock.patch.object(
                            native.os,
                            "sched_getaffinity",
                            return_value={2, 3}
                            if fault == "affinity"
                            else set(spec.cpus),
                        ),
                        mock.patch.object(
                            native,
                            "process_start",
                            return_value=config["client_starttime"]
                            + (fault == "client"),
                        ),
                        mock.patch.object(
                            native.socket,
                            "socket",
                            side_effect=AssertionError("unexpected connection"),
                        ),
                        self.assertRaisesRegex(ValueError, reason),
                    ):
                        effects.preflight(spec, origin + 2_000_000_000)
                    self.assertFalse(effects.child.attempted)
                    self.assertIsNone(effects.channel)
                    bus.close.assert_called_once()
                finally:
                    effects.close_directory()

    def test_guardian_failure_retains_post_commit_control_peek(self):
        spec = specification()
        for kind, reason in (
            ("partial", "partial control"),
            ("invalid", "invalid control"),
            ("cancel", "peer cancelled"),
            ("eof", "write-side EOF"),
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                effects = native.GuardianEffects(
                    Path(directory), native.make_config(spec, time.monotonic_ns()), spec
                )
                left, right = socket.socketpair()
                try:
                    effects.channel = native.guardian.PeerChannel(
                        left, (os.getpid(), os.getuid(), os.getgid())
                    )
                    end = time.monotonic_ns() + 1_000_000_000
                    commit = native.guardian.encode(
                        {"kind": "commit", "payload": {"transaction_sha256": "a" * 64}}
                    )
                    right.sendall(commit)
                    self.assertEqual(effects.channel.receive(end), commit)
                    payload = {
                        "partial": b"\0\0",
                        "invalid": b"\0\0\0\2[]",
                        "cancel": effects.cancel_frame,
                        "eof": b"",
                    }[kind]
                    if kind == "eof":
                        right.shutdown(socket.SHUT_WR)
                    else:
                        right.sendall(payload)
                    with self.assertRaisesRegex(ValueError, reason) as caught:
                        effects.require_idle(end)
                    effects.close_control()
                    effects.failed(
                        {"state": "failed", "reason": str(caught.exception)}, end
                    )
                    row = json.loads(
                        (Path(directory) / "guardian-failed.json").read_bytes()
                    )
                    self.assertEqual(row["control"]["received_hex"], commit.hex())
                    self.assertEqual(row["control"]["last_peek_hex"], payload.hex())
                    self.assertIn(reason, row["reason"])
                finally:
                    right.close()
                    left.close()
                    effects.close_control()
                    effects.close_directory()

    def test_code_pin_mismatch_refuses_before_constructing_effects(self):
        class ConstructionForbidden(Exception):
            pass

        with tempfile.TemporaryDirectory() as directory:
            config = native.make_config(specification(), time.monotonic_ns())
            config["code_pins"]["measurement-job-guardian.py"] = "0" * 64
            data = native.guardian.evidence.canonical(config)
            path = Path(directory) / "guardian-config.json"
            path.write_bytes(data)
            path.chmod(0o600)
            with mock.patch.object(
                native, "GuardianEffects", side_effect=ConstructionForbidden
            ) as construct:
                try:
                    result = native.run_service(
                        [
                            str(HERE / "measurement-job-guardian-native.py"),
                            "--service",
                            str(path),
                            hashlib.sha256(data).hexdigest(),
                        ]
                    )
                except ConstructionForbidden:
                    self.fail("changed code reached effect construction")
                self.assertEqual(result, 77)
                construct.assert_not_called()

    def test_protected_file_rejects_nonprivate_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"bounded-public-data")
            for mode in (0o644, 0o660):
                path.chmod(mode)
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    native.protected_read(path, 1024)

    def test_guardian_loop_uses_real_inert_child_and_closed_receipt(self):
        spec = specification()
        origin = time.monotonic_ns()
        config = native.make_config(spec, origin)
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
        terminal = {
            "scope": "contained-job-terminal-v1",
            "mode": spec.mode,
            "identity": identity,
            "batch_sha256": hashlib.sha256(
                native.guardian.evidence.canonical(batch)
            ).hexdigest(),
            "ledger_bytes": 1234,
            "ledger_sha256": "e" * 64,
            "outcome": "complete",
            "native_authorized": False,
            "full_contract_proven": False,
        }
        raw = native.guardian.evidence.canonical(terminal)
        frame = len(raw).to_bytes(4, "big") + raw
        digest = hashlib.sha256(
            native.guardian.encode(native.guardian.launch_request(spec))
        ).hexdigest()

        class Channel:
            def __init__(self):
                self.messages = [
                    native.guardian.encode(native.guardian.launch_request(spec)),
                    native.guardian.encode(
                        {"kind": "commit", "payload": {"transaction_sha256": digest}}
                    ),
                ]
                self.received = bytearray()
                self.sent_total = 0
                self.sent = []
                self.closed = False

            def receive(self, deadline):
                return self.messages.pop(0)

            def send(self, data, deadline):
                self.sent.append(data)
                self.sent_total += len(data)

            def require_idle(self, deadline, *, cancel_frame=None):
                pass  # No service/peer is qualified by this fixture.

            def close(self):
                self.closed = True

        class InertEffects(native.GuardianEffects):
            def preflight(self, selected, deadline):
                self.channel = Channel()
                return native.guardian.ServiceIdentity(
                    native.guardian.unit_name(spec),
                    "d" * 32,
                    os.getpid(),
                    "/synthetic",
                    origin + native.guardian.HOST_NS,
                )

            def spawn(self, selected, deadline):
                return self.child.spawn(
                    (
                        sys.executable,
                        "-I",
                        "-c",
                        "import os,sys;os.write(1,bytes.fromhex(sys.argv[1]))",
                        frame.hex(),
                    ),
                    deadline,
                )

        with tempfile.TemporaryDirectory() as directory:
            effects = InertEffects(Path(directory), config, spec)
            try:
                result = native.guardian.run_guardian(effects, spec, origin)
                self.assertTrue(result["transport_complete"])
                self.assertTrue(effects.child.reaped)
                self.assertTrue(effects.channel.closed)
                self.assertIsNone(effects.directory)
                receipt = (Path(directory) / "guardian-finished.json").read_bytes()
                done = native.guardian.decode(effects.channel.sent[-1])["payload"]
                self.assertEqual(
                    done["receipt_sha256"], hashlib.sha256(receipt).hexdigest()
                )
                host = native.load(
                    "guardian_wire_host", HERE / "measurement-job-guardian-host.py"
                )
                host_spec = host.g.Specification(**spec._asdict())
                host_identity = host.g.ServiceIdentity(**result["service"])
                self.assertEqual(
                    host.verify_receipt(receipt, host_spec, host_identity, origin)[
                        "terminal_wait"
                    ]["exitcode"],
                    0,
                )
            finally:
                if effects.child.process is not None and not effects.child.reaped:
                    end = time.monotonic_ns() + 2_000_000_000
                    effects.child.stop(end)
                    effects.child.reap(end)
                effects.child.close()
                effects.close_control()
                effects.close_directory()

    def test_protected_file_close_failure_still_closes_owned_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "config"
            path.write_bytes(b"safe")
            path.chmod(0o600)
            root_id = root.stat().st_ino
            closed = []
            real_close = os.close

            def close(fd):
                info = os.fstat(fd)
                closed.append(info.st_ino)
                real_close(fd)
                if stat.S_ISREG(info.st_mode):
                    raise OSError("injected consumed file close failure")

            try:
                with (
                    mock.patch.object(native.os, "close", side_effect=close),
                    self.assertRaises((OSError, BaseExceptionGroup)),
                ):
                    native.protected_read(path, 16)
                self.assertIn(root_id, closed)
            finally:
                # Contain the pre-fix RED leak as well as a failing test setup.
                for name in os.listdir("/proc/self/fd"):
                    try:
                        info = os.fstat(int(name))
                    except OSError:
                        continue
                    if info.st_ino == root_id and stat.S_ISDIR(info.st_mode):
                        real_close(int(name))

    def test_config_roundtrip_rejects_extra_or_wrong_scalar_fields(self):
        spec = specification()
        config = native.make_config(spec, time.monotonic_ns())
        decoded = json.loads(native.guardian.evidence.canonical(config))
        self.assertEqual(native.check_config(decoded), spec)
        for key, value in (("origin_ns", True), ("client_pid", 0), ("extra", "value")):
            bad = dict(decoded, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                native.check_config(bad)

    def test_receipt_finalization_returns_only_after_descriptor_close(self):
        spec = specification()
        with tempfile.TemporaryDirectory() as directory:
            config = native.make_config(spec, time.monotonic_ns())
            effects = native.GuardianEffects(Path(directory), config, spec)
            try:
                end = time.monotonic_ns() + 1_000_000_000
                effects.record("started", {"state": "started"}, end)
                size, digest = effects.finalize({"state": "ready-to-finalize"}, end)
                data = (Path(directory) / "guardian-finished.json").read_bytes()
                self.assertEqual(
                    (size, digest), (len(data), hashlib.sha256(data).hexdigest())
                )
                self.assertIsNone(effects.directory)
                with self.assertRaises(ValueError):
                    effects.finalize({}, end)
            finally:
                effects.close_directory()


class ChildTests(unittest.TestCase):
    def test_peer_pidfd_tracks_exact_other_process_through_exit(self):
        owner = native.ChildOwner()
        channel = None
        with (
            tempfile.TemporaryDirectory(dir=SOCKET_BASE) as directory,
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener,
        ):
            endpoint = str(Path(directory) / "peer.sock")
            listener.bind(endpoint)
            listener.listen(1)
            listener.settimeout(2)
            try:
                end = time.monotonic_ns() + 3_000_000_000
                script = "import socket,sys;s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(sys.argv[1]);s.sendall(b'\\0\\0\\0\\2{}');s.recv(1)"
                pid = owner.spawn((sys.executable, "-I", "-c", script, endpoint), end)
                connected, _ = listener.accept()
                channel = native.guardian.PeerChannel(
                    connected, (pid, os.getuid(), os.getgid())
                )
                self.assertEqual(channel.receive(end), b"\0\0\0\2{}")
                channel.socket.send(b"x")
                owner.reap(end)
                with self.assertRaises(ValueError):
                    channel.check(end)
                channel.expect_eof(end)
            finally:
                if channel is not None:
                    channel.close()
                self.cleanup(owner)

    def test_successful_wait_is_retained_if_status_decoding_fails(self):
        owner = native.ChildOwner()
        try:
            end = time.monotonic_ns() + 2_000_000_000
            owner.spawn((sys.executable, "-I", "-c", "pass"), end)
            with (
                mock.patch.object(
                    native.os,
                    "waitstatus_to_exitcode",
                    side_effect=ValueError("injected decoding failure"),
                ),
                self.assertRaises(ValueError),
            ):
                owner.reap(end)
            self.assertTrue(owner.reaped)
            self.assertEqual(owner.wait["pid"], owner.process.pid)
            with self.assertRaises(ChildProcessError):
                os.waitpid(owner.process.pid, os.WNOHANG)
        finally:
            if owner.process is not None:
                try:
                    waited, _ = os.waitpid(owner.process.pid, os.WNOHANG)
                    if waited == owner.process.pid:
                        owner.reaped = True
                        owner.process.returncode = 0
                except ChildProcessError:
                    owner.reaped = True
                    owner.process.returncode = 0
            self.cleanup(owner)

    def cleanup(self, owner):
        if owner.process is not None and not owner.reaped:
            deadline = time.monotonic_ns() + 2_000_000_000
            owner.stop(deadline)
            owner.reap(deadline)
        owner.close()

    def test_owned_inert_child_drains_and_reaps_before_fd_disposal(self):
        owner = native.ChildOwner()
        try:
            end = time.monotonic_ns() + 2_000_000_000
            pid = owner.spawn(
                (
                    sys.executable,
                    "-I",
                    "-c",
                    "import os;os.write(1,b'out');os.write(2,b'err')",
                ),
                end,
            )
            data = {"stdout": b"", "stderr": b""}
            while owner.eof != set(data) or not owner.exit_sent:
                event = owner.event(end)
                if event is not None and event[0] in data and event[1] is not None:
                    data[event[0]] += event[1]
            wait = owner.reap(end)
            self.assertEqual(wait, {"pid": pid, "exitcode": 0, "status": 0})
            self.assertEqual(data, {"stdout": b"out", "stderr": b"err"})
            self.assertTrue(owner.reaped)
            owner.close()
            self.assertIsNone(owner.pidfd)
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)
        finally:
            self.cleanup(owner)

    def test_pidfd_failure_preserves_exact_child_for_cleanup(self):
        owner = native.ChildOwner()
        try:
            with (
                mock.patch.object(
                    native.os, "pidfd_open", side_effect=OSError(24, "test exhaustion")
                ),
                self.assertRaises(OSError),
            ):
                owner.spawn(
                    (sys.executable, "-I", "-c", "import time;time.sleep(30)"),
                    time.monotonic_ns() + 2_000_000_000,
                )
            self.assertIsNotNone(owner.process)
            self.assertTrue(owner.attempted)
            self.assertFalse(owner.reaped)
            self.cleanup(owner)
            self.assertTrue(owner.reaped)
        finally:
            self.cleanup(owner)

    def test_reap_deadline_retains_owner_until_later_exact_cleanup(self):
        owner = native.ChildOwner()
        try:
            owner.spawn(
                (sys.executable, "-I", "-c", "import time;time.sleep(30)"),
                time.monotonic_ns() + 2_000_000_000,
            )
            with self.assertRaises(TimeoutError):
                owner.reap(time.monotonic_ns() + 10_000_000)
            self.assertFalse(owner.reaped)
            self.assertIsNotNone(owner.pidfd)
        finally:
            self.cleanup(owner)

    def test_constructor_error_is_uncertain_not_proven_no_child(self):
        owner = native.ChildOwner()
        with (
            mock.patch.object(
                native.subprocess, "Popen", side_effect=OSError("constructor failed")
            ),
            self.assertRaises(OSError),
        ):
            owner.spawn(
                (sys.executable, "-I", "-c", "pass"),
                time.monotonic_ns() + 1_000_000_000,
            )
        self.assertTrue(owner.state()["spawn_uncertain"])
        with (
            mock.patch.object(native.os, "kill") as kill,
            self.assertRaises(ValueError),
        ):
            owner.stop(time.monotonic_ns() + 1_000_000_000)
        kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
