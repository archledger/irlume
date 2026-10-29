#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Service ownership tests use a fake bus; never create a systemd unit."""

import importlib.util
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event, Thread
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "service", HERE / "measurement-job-guardian-service.py"
)
service = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(service)


class TransportTests(unittest.TestCase):
    def transport(self, invalid=False):
        import jeepney

        spec = importlib.util.spec_from_file_location(
            "bus_guardian", HERE / "measurement-job-guardian.py"
        )
        guardian = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guardian)
        selection = guardian.Specification(
            "test",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            "boot-only",
            ("supervisor-only",),
            1,
            "/qemu",
            "/base",
            "/payload",
            "/overlay",
            (0, 1),
        )
        properties = guardian.service_properties(selection)
        defaults = {
            "s": "",
            "t": 0,
            "u": 0,
            "i": 0,
            "b": False,
            "ay": b"",
            "commands": [],
        }

        class FakeSocket:
            def __init__(self):
                self.pending = bytearray()
                self.calls = []
                self.closed = False

            def set_inheritable(self, value):
                if value:
                    raise AssertionError("bus socket inherited")

            def settimeout(self, value):
                if not 0 < value <= 5:
                    raise AssertionError("unbounded bus I/O")

            def sendall(self, data):
                parser = jeepney.Parser()
                parser.add_data(data)
                request = parser.get_next_message()
                method = request.header.fields[jeepney.HeaderFields.member]
                self.calls.append(request)
                if method == "Hello":
                    signature, body = "s", (":test.1",)
                elif method == "GetAll":
                    kinds = (
                        service.UNIT_TYPES
                        if request.body[0].endswith(".Unit")
                        else service.PROPERTY_TYPES
                    )
                    values = {}
                    for key, kind in kinds.items():
                        value = properties.get(key, defaults[kind])
                        if kind == "ay":
                            value = bytes(value)
                        elif kind == "commands":
                            value = []
                        values[key] = (
                            "a(sasbttttuii)" if kind == "commands" else kind,
                            value,
                        )
                    if "Id" in values:
                        values["Id"] = ("s", "irlume-job-guardian-test.service")
                        values["InvocationID"] = ("ay", b"a" * 16)
                    if invalid and "RuntimeMaxUSec" in values:
                        values["RuntimeMaxUSec"] = ("u", 300_000_000)
                    signature, body = "a{sv}", (values,)
                elif method == "GetUnitProcesses":
                    signature, body = "a(sus)", ([],)
                else:
                    path = (
                        "/org/freedesktop/systemd1/unit/test"
                        if method == "GetUnit"
                        else "/org/freedesktop/systemd1/job/42"
                    )
                    signature, body = "o", (path,)
                reply = jeepney.new_method_return(request, signature, body)
                self.pending.extend(reply.serialise(serial=len(self.calls)))

            def recv(self, size):
                part = bytes(self.pending[:size])
                del self.pending[:size]
                return part

            def close(self):
                self.closed = True

        sock = FakeSocket()
        bus = service.SystemdBus(
            os.getuid(),
            deadline=time.monotonic_ns() + 1_000_000_000,
            _socket_factory=lambda *args, **kwargs: sock,
        )
        return bus, sock, properties, jeepney

    def test_complete_property_vector_roundtrips_through_typed_wire(self):
        bus, sock, properties, protocol = self.transport()
        try:
            end = time.monotonic_ns() + 1_000_000_000
            argv = ("/usr/bin/python3", "-I", "/private/guardian.py")
            self.assertEqual(
                bus.start("irlume-job-guardian-test.service", properties, argv, end),
                "/org/freedesktop/systemd1/job/42",
            )
            start = next(
                r
                for r in sock.calls
                if r.header.fields[protocol.HeaderFields.member] == "StartTransientUnit"
            )
            self.assertEqual(start.body[1], "fail")
            sent = dict(start.body[2])
            self.assertEqual(sent["AddRef"], ("b", True))
            self.assertEqual(sent["CPUAffinity"], ("ay", b"\x03"))
            self.assertEqual(sent["ExecStart"][0], "a(sasb)")
            self.assertEqual(sent["ExecStart"][1][0][1], list(argv))
            observed = bus.observe("irlume-job-guardian-test.service", end)
            for key, value in properties.items():
                if key != "AddRef":
                    self.assertEqual(observed[key], value, key)
            self.assertEqual(bus.processes("irlume-job-guardian-test.service", end), ())
        finally:
            bus.close()
        self.assertTrue(sock.closed)

    def test_bad_typed_response_keeps_prior_property_observations(self):
        bus, _, _, _ = self.transport(invalid=True)
        try:
            with self.assertRaises(ValueError):
                bus.observe(
                    "irlume-job-guardian-test.service",
                    time.monotonic_ns() + 1_000_000_000,
                )
            self.assertEqual(bus.last_partial["Id"], "irlume-job-guardian-test.service")
            self.assertNotIn("RuntimeMaxUSec", bus.last_partial)
        finally:
            bus.close()

    def test_authentication_and_hello_stalls_share_startup_deadline(self):
        def descriptors():
            result = set()
            for name in os.listdir("/proc/self/fd"):
                try:
                    os.fstat(int(name))
                except OSError:
                    continue
                result.add(int(name))
            return result

        for authenticate in (False, True):
            before = descriptors()
            with (
                self.subTest(authenticate=authenticate),
                tempfile.TemporaryDirectory() as directory,
            ):
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(str(Path(directory) / "bus"))
                listener.listen(1)
                listener.settimeout(1)
                release, began = Event(), Event()

                def server(listener, release, began, authenticate):
                    try:
                        connected, _ = listener.accept()
                    except OSError:
                        return
                    with connected:
                        connected.settimeout(1)
                        if authenticate:
                            try:
                                data = b""
                                while b"\r\n" not in data:
                                    part = connected.recv(1024)
                                    if not part:
                                        return
                                    data += part
                                connected.sendall(b"OK " + b"a" * 32 + b"\r\n")
                                data = b""
                                while b"BEGIN\r\n" not in data:
                                    part = connected.recv(1024)
                                    if not part:
                                        return
                                    data += part
                                began.set()
                            except OSError:
                                return
                        release.wait(1)

                thread = Thread(
                    target=server, args=(listener, release, began, authenticate)
                )
                thread.start()
                started = time.monotonic()
                try:
                    failure = None
                    try:
                        service.SystemdBus(
                            os.getuid(),
                            deadline=time.monotonic_ns() + 200_000_000,
                            _address=str(Path(directory) / "bus"),
                        )
                    except OSError as error:
                        failure = error
                    self.assertIsInstance(failure, TimeoutError)
                    self.assertLess(time.monotonic() - started, 1)
                    if authenticate:
                        self.assertTrue(began.is_set(), "fixture did not reach Hello")
                finally:
                    release.set()
                    listener.close()
                    thread.join(2)
                    self.assertFalse(thread.is_alive())
            self.assertEqual(descriptors(), before)


class GateTests(unittest.TestCase):
    def test_fifo_replacement_refuses_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            script = """import importlib.util,os,sys,time
from pathlib import Path
s=importlib.util.spec_from_file_location('gate',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
root=Path(sys.argv[2]);end=time.monotonic_ns()+1000000000
g=m.AdmissionGate(root,end);g.claim('fifo',b'intent',end)
(root/'active.json').unlink();os.mkfifo(root/'active.json',0o600)
try:
    g.complete(b'proof',end)
except ValueError:
    g.close();sys.exit(0)
sys.exit(2)
"""
            try:
                result = subprocess.run(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-c",
                        script,
                        str(HERE / "measurement-job-guardian-service.py"),
                        directory,
                    ],
                    capture_output=True,
                    timeout=2,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                self.fail("FIFO validation blocked before file type inspection")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_same_size_replaced_active_intent_is_never_cleared(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            end = time.monotonic_ns() + 2_000_000_000
            gate = service.AdmissionGate(root, end)
            try:
                gate.claim("one", b"intent", end)
                before = (root / "active.json").read_bytes()
                changed = before.replace(b'"run_id": "one"', b'"run_id": "two"')
                self.assertNotEqual(before, changed)
                self.assertEqual(len(before), len(changed))
                (root / "active.json").write_bytes(changed)
                with self.assertRaises(ValueError):
                    gate.complete(b"proof", end)
                self.assertEqual((root / "active.json").read_bytes(), changed)
            finally:
                gate.close()

    def test_shared_gate_excludes_concurrent_and_unresolved_different_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            end = time.monotonic_ns() + 2_000_000_000
            first = service.AdmissionGate(root, end)
            try:
                first.claim("one", b"first-intent", end)
                record = (root / "active.json").read_bytes()
                with self.assertRaises(BlockingIOError):
                    service.AdmissionGate(root, end)
            finally:
                first.close()
            second = service.AdmissionGate(root, end)
            try:
                with self.assertRaises(FileExistsError):
                    second.claim("different-run", b"new-intent", end)
                self.assertEqual((root / "active.json").read_bytes(), record)
            finally:
                second.close()

    def test_process_death_releases_lock_but_leaves_durable_blocker(self):
        with tempfile.TemporaryDirectory() as directory:
            script = """import importlib.util,os,sys,time
from pathlib import Path
s=importlib.util.spec_from_file_location('gate',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
end=time.monotonic_ns()+1000000000
g=m.AdmissionGate(Path(sys.argv[2]),end);g.claim('dead-h',b'intent',end)
os._exit(0)
"""
            result = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-c",
                    script,
                    str(HERE / "measurement-job-guardian-service.py"),
                    directory,
                ],
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            end = time.monotonic_ns() + 1_000_000_000
            gate = service.AdmissionGate(Path(directory), end)
            try:
                with self.assertRaises(FileExistsError):
                    gate.claim("next-run", b"next", end)
            finally:
                gate.close()

    def test_completion_retains_proof_before_clearing_only_own_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            end = time.monotonic_ns() + 2_000_000_000
            gate = service.AdmissionGate(root, end)
            try:
                gate.claim("one", b"intent", end)
                gate.complete(b"closed-terminal-evidence", end)
                self.assertFalse((root / "active.json").exists())
                self.assertEqual(
                    (root / "terminal-one.json").read_bytes(),
                    b"closed-terminal-evidence",
                )
            finally:
                gate.close()
            gate = service.AdmissionGate(root, end)
            try:
                gate.claim("two", b"intent-two", end)
                (root / "active.json").write_bytes(b"changed-by-another-writer")
                with self.assertRaises(ValueError):
                    gate.complete(b"proof-two", end)
                self.assertEqual(
                    (root / "active.json").read_bytes(), b"changed-by-another-writer"
                )
            finally:
                gate.close()

    def retained_claim(self, root, run_id="one", intent=b"intent"):
        end = time.monotonic_ns() + 2_000_000_000
        gate = service.AdmissionGate(root, end)
        gate.claim(run_id, intent, end)
        gate.close()
        return (root / "active.json").read_bytes(), end

    def assert_unresolved(self, root, record):
        self.assertEqual((root / "active.json").read_bytes(), record)
        self.assertEqual(
            sorted(p.name for p in root.iterdir() if p.name != "admission.lock"),
            ["active.json"],
        )

    def test_failed_claim_resolves_only_to_non_accepting_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record, end = self.retained_claim(root)
            gate = service.AdmissionGate(root, end)
            try:
                data, identity = gate.read_blocker(end)
                self.assertEqual(data, record)
                gate.resolve_failed(data, identity, b"resolution", end)
                self.assertIsNone(gate.record)
            finally:
                gate.close()
            self.assertFalse((root / "active.json").exists())
            self.assertEqual((root / "resolved-one.json").read_bytes(), b"resolution")
            self.assertEqual((root / "resolved-one.json").stat().st_mode & 0o777, 0o600)
            self.assertFalse(list(root.glob("terminal-*")))
            gate = service.AdmissionGate(root, end)
            try:
                gate.claim("two", b"next", end)
            finally:
                gate.close()

    def test_resolution_refuses_any_other_blocker_bytes(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            tempfile.TemporaryDirectory() as elsewhere,
        ):
            root = Path(directory)
            record, end = self.retained_claim(root)
            value = json.loads(record)
            other, _ = self.retained_claim(Path(elsewhere), "two")
            bad = {
                "reordered": (
                    json.dumps(dict(reversed(value.items()))) + "\n"
                ).encode(),
                "compact": (
                    json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode(),
                "extra-key": (
                    json.dumps(dict(value, extra=1), sort_keys=True) + "\n"
                ).encode(),
                "wrong-sha": record.replace(value["intent_sha256"].encode(), b"0" * 64),
                "no-newline": record[:-1],
                "other-run": other,
                "not-json": b"blocker",
                "not-bytes": record.decode(),
            }
            gate = service.AdmissionGate(root, end)
            try:
                _, identity = gate.read_blocker(end)
                for label, blocker in bad.items():
                    with self.subTest(label), self.assertRaises(ValueError):
                        gate.resolve_failed(blocker, identity, b"resolution", end)
                    self.assert_unresolved(root, record)
            finally:
                gate.close()

    def test_resolution_refuses_a_replaced_linked_or_special_blocker(self):
        for change in ("copy", "link", "fifo", "symlink"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                record, end = self.retained_claim(root)
                gate = service.AdmissionGate(root, end)
                try:
                    _, identity = gate.read_blocker(end)
                    active = root / "active.json"
                    if change == "copy":
                        # Keep the old inode alive so the copy cannot reuse it.
                        active.rename(root / "kept")
                        active.write_bytes(record)
                        active.chmod(0o600)
                    elif change == "link":
                        os.link(active, root / "second")
                    else:
                        (root / "kept").write_bytes(record)
                        active.unlink()
                        if change == "fifo":
                            os.mkfifo(active, 0o600)
                        else:
                            active.symlink_to("kept")
                    with self.subTest(change), self.assertRaises((ValueError, OSError)):
                        gate.resolve_failed(record, identity, b"resolution", end)
                    self.assertFalse(list(root.glob("resolved-*")))
                    self.assertTrue(active.exists() or active.is_symlink())
                finally:
                    gate.close()

    def test_resolution_clears_only_a_claim_this_gate_could_have_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record, end = self.retained_claim(root)
            value = json.loads(record)
            forged = (json.dumps(dict(value, extra=1), sort_keys=True) + "\n").encode()
            (root / "active.json").write_bytes(forged)
            gate = service.AdmissionGate(root, end)
            try:
                data, identity = gate.read_blocker(end)
                self.assertEqual(data, forged)
                with self.assertRaisesRegex(ValueError, "blocker format"):
                    gate.resolve_failed(data, identity, b"resolution", end)
            finally:
                gate.close()
            self.assert_unresolved(root, forged)

    def test_blocker_swapped_after_the_evidence_write_is_never_unlinked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record, end = self.retained_claim(root)
            gate = service.AdmissionGate(root, end)
            write = gate.write

            def write_then_swap(name, data, deadline):
                write(name, data, deadline)
                (root / "active.json").rename(root / "kept")
                (root / "active.json").write_bytes(record)
                (root / "active.json").chmod(0o600)

            try:
                _, identity = gate.read_blocker(end)
                with (
                    mock.patch.object(gate, "write", side_effect=write_then_swap),
                    self.assertRaisesRegex(ValueError, "ownership"),
                ):
                    gate.resolve_failed(record, identity, b"resolution", end)
            finally:
                gate.close()
            self.assertEqual((root / "active.json").read_bytes(), record)
            self.assertTrue((root / "resolved-one.json").is_file())

    def test_resolution_needs_an_idle_open_gate_and_no_prior_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record, end = self.retained_claim(root)
            gate = service.AdmissionGate(root, end)
            _, identity = gate.read_blocker(end)
            gate.record = b"claimed"
            with self.assertRaises(ValueError):
                gate.resolve_failed(record, identity, b"resolution", end)
            gate.record = None
            gate.close()
            with self.assertRaises(ValueError):
                gate.resolve_failed(record, identity, b"resolution", end)
            for name in ("terminal-one.json", "resolved-one.json"):
                (root / name).write_bytes(b"earlier")
                gate = service.AdmissionGate(root, end)
                try:
                    with self.subTest(name), self.assertRaises(FileExistsError):
                        gate.resolve_failed(record, identity, b"resolution", end)
                finally:
                    gate.close()
                self.assertEqual((root / "active.json").read_bytes(), record)
                self.assertEqual((root / name).read_bytes(), b"earlier")
                (root / name).unlink()

    def test_failed_evidence_write_keeps_the_blocker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            end = time.monotonic_ns() + 2_000_000_000
            gate = service.AdmissionGate(root, end)
            try:
                gate.claim("one", b"intent", end)
                record = (root / "active.json").read_bytes()
                with (
                    mock.patch.object(gate, "write", side_effect=OSError("full")),
                    self.assertRaises(OSError),
                ):
                    gate.complete(b"proof", end)
                self.assertEqual((root / "active.json").read_bytes(), record)
            finally:
                gate.close()
            gate = service.AdmissionGate(root, end)
            try:
                _, identity = gate.read_blocker(end)
                with (
                    mock.patch.object(gate, "write", side_effect=OSError("full")),
                    self.assertRaises(OSError),
                ):
                    gate.resolve_failed(record, identity, b"resolution", end)
                self.assertEqual((root / "active.json").read_bytes(), record)
            finally:
                gate.close()

    def test_symlink_gate_and_foreign_mode_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(OSError):
                service.AdmissionGate(link, time.monotonic_ns() + 1_000_000_000)
            os.chmod(real, 0o777)
            with self.assertRaises(ValueError):
                service.AdmissionGate(real, time.monotonic_ns() + 1_000_000_000)


class Bus:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.row = {
            "Id": "irlume-job-guardian-test.service",
            "InvocationID": "a" * 32,
            "MainPID": 42,
            "ControlGroup": "/own/cgroup",
            "ExecMainStartTimestampMonotonic": 10,
        }

    def start(self, name, properties, argv, deadline):
        self.calls.append(("start", name, dict(properties), tuple(argv), deadline))
        if self.failure:
            raise self.failure
        return "/org/freedesktop/systemd1/job/42"

    def observe(self, name, deadline):
        self.calls.append(("observe", name, deadline))
        return dict(self.row)

    def processes(self, name, deadline):
        self.calls.append(("processes", name, deadline))
        return ()

    def stop(self, name, deadline):
        self.calls.append(("stop", name, deadline))
        return "/org/freedesktop/systemd1/job/43"

    def close(self):
        self.calls.append(("close",))


class LeaseTests(unittest.TestCase):
    def test_unreferenced_creation_is_refused_before_bus_effect(self):
        for properties in ({}, {"AddRef": False}):
            bus, lease = self.lease()
            with self.subTest(properties=properties), self.assertRaises(ValueError):
                lease.create(properties, ("/fixed/entry",), 100)
            self.assertFalse(lease.creation_attempted)
            self.assertEqual(bus.calls, [])

    def test_terminal_time_cannot_precede_the_bound_invocation(self):
        bus, lease = self.lease()
        lease.create({"AddRef": True}, ("/fixed/entry",), 100)
        lease.bind(lease.observe(100))
        bus.row.update(
            MainPID=0,
            ActiveState="inactive",
            SubState="dead",
            Result="success",
            ExecMainCode=1,
            ExecMainStatus=0,
            ExecMainExitTimestampMonotonic=5,
        )
        with self.assertRaises(ValueError):
            lease.verify_terminal(100, 100_000)
        self.assertFalse(lease.terminal)

    def test_nonempty_domain_or_missing_unit_never_releases_reference(self):
        for missing in (False, True):
            bus, lease = self.lease()
            lease.create({"AddRef": True}, ("/fixed/entry",), 100)
            lease.bind(lease.observe(100))
            bus.row.update(
                MainPID=0,
                ActiveState="inactive",
                SubState="dead",
                Result="success",
                ExecMainCode=1,
                ExecMainStatus=0,
                ExecMainExitTimestampMonotonic=20,
            )
            if missing:

                def absent(*_):
                    raise OSError("unit disappeared")

                bus.observe = absent
            else:
                bus.processes = lambda *_: (("/own/cgroup", 55, "still-owned"),)
            with (
                self.subTest(missing=missing),
                self.assertRaises((ValueError, OSError)),
            ):
                lease.verify_terminal(100, 100_000)
            with self.assertRaises(ValueError):
                lease.release(100)
            self.assertNotIn(("close",), bus.calls)

    def lease(self):
        bus = Bus()
        return bus, service.UnitLease(bus.row["Id"], bus, lambda: 10)

    def test_failed_creation_is_uncertain_and_cannot_retry_or_stop_by_name(self):
        bus, lease = self.lease()
        bus.failure = TimeoutError("reply lost after creation")
        with self.assertRaises(TimeoutError):
            lease.create({"AddRef": True}, ("/fixed/entry",), 100)
        self.assertTrue(lease.creation_attempted)
        self.assertTrue(lease.unresolved)
        with self.assertRaises(ValueError):
            lease.create({"AddRef": True}, ("/fixed/entry",), 200)
        with self.assertRaises(ValueError):
            lease.stop(100)
        self.assertEqual([c[0] for c in bus.calls], ["start"])

    def test_identity_is_bound_before_an_exact_owned_stop(self):
        bus, lease = self.lease()
        lease.create({"AddRef": True}, ("/fixed/entry",), 100)
        row = lease.observe(100)
        lease.bind(row)
        lease.stop(100)
        self.assertEqual(bus.calls[-1], ("stop", bus.row["Id"], 100))
        bus.row["InvocationID"] = "b" * 32
        with self.assertRaises(ValueError):
            lease.stop(100)
        self.assertEqual(len([c for c in bus.calls if c[0] == "stop"]), 1)

    def test_observed_unbound_invocation_is_stopped_only_while_unchanged(self):
        for change in (
            {},
            {"InvocationID": "b" * 32},
            {"Id": "irlume-job-guardian-x.service"},
        ):
            bus, lease = self.lease()
            lease.create({"AddRef": True}, ("/fixed/entry",), 100)
            lease.observe(100)
            self.assertEqual(
                lease.cleanup_identity(),
                {"Id": bus.row["Id"], "InvocationID": "a" * 32},
            )
            bus.row.update(change)
            with self.subTest(change=change):
                if change:
                    with self.assertRaisesRegex(ValueError, "lost service invocation"):
                        lease.stop(100)
                    self.assertNotIn("stop", [call[0] for call in bus.calls])
                    self.assertFalse(lease.stop_attempted)
                    self.assertFalse(lease.unresolved)
                    continue
                lease.stop(100)
                self.assertIsNone(lease.bound)
                self.assertEqual(bus.calls[-1], ("stop", bus.row["Id"], 100))
                self.assertTrue(lease.stop_attempted)
                self.assertTrue(lease.unresolved)
                self.assertEqual(lease.stop_reply, "/org/freedesktop/systemd1/job/43")

    def test_unobserved_or_anonymous_invocation_cannot_be_stopped(self):
        changes = {
            "unobserved": None,
            "zero": lambda row: row.update(InvocationID="0" * 32),
            "missing": lambda row: row.pop("InvocationID"),
            "upper": lambda row: row.update(InvocationID="A" * 32),
            "short": lambda row: row.update(InvocationID="a" * 31),
            "bytes": lambda row: row.update(InvocationID=b"\xaa" * 16),
            "other-unit": lambda row: row.update(Id="irlume-job-guardian-x.service"),
        }
        for label, change in changes.items():
            bus, lease = self.lease()
            lease.create({"AddRef": True}, ("/fixed/entry",), 100)
            if change is not None:
                change(bus.row)
                lease.observe(100)
            calls = list(bus.calls)
            with self.subTest(label), self.assertRaisesRegex(ValueError, "established"):
                lease.stop(100)
            self.assertEqual(bus.calls, calls)
            self.assertFalse(lease.stop_attempted)
            self.assertFalse(lease.unresolved)
        bus, lease = self.lease()
        bus.failure = TimeoutError("reply lost after creation")
        with self.assertRaises(TimeoutError):
            lease.create({"AddRef": True}, ("/fixed/entry",), 100)
        bus.failure = None
        lease.observe(100)
        with self.assertRaisesRegex(ValueError, "established"):
            lease.stop(100)
        self.assertNotIn("stop", [call[0] for call in bus.calls])
        self.assertFalse(lease.stop_attempted)

    def test_bound_invocation_outranks_a_later_changed_observation(self):
        bus, lease = self.lease()
        lease.create({"AddRef": True}, ("/fixed/entry",), 100)
        lease.bind(lease.observe(100))
        bus.row["InvocationID"] = "b" * 32
        lease.observe(100)
        self.assertEqual(lease.cleanup_identity()["InvocationID"], "a" * 32)
        with self.assertRaisesRegex(ValueError, "lost service invocation"):
            lease.stop(100)
        self.assertNotIn("stop", [call[0] for call in bus.calls])
        self.assertFalse(lease.stop_attempted)

    def test_stop_request_failure_or_late_reply_stays_unresolved(self):
        bus, lease = self.lease()
        lease.create({"AddRef": True}, ("/fixed/entry",), 100)
        lease.observe(100)
        bus.stop = mock.Mock(side_effect=TimeoutError("stop reply lost"))
        with self.assertRaises(TimeoutError):
            lease.stop(100)
        bus.stop.assert_called_once_with(bus.row["Id"], 100)
        self.assertTrue(lease.stop_attempted)
        self.assertIsNone(lease.stop_reply)
        self.assertTrue(lease.unresolved)
        bus, lease = self.lease()
        lease.create({"AddRef": True}, ("/fixed/entry",), 100)
        lease.observe(100)
        lease.now = iter((10, 10, 100)).__next__
        with self.assertRaises(TimeoutError):
            lease.stop(100)
        self.assertEqual(lease.stop_reply, "/org/freedesktop/systemd1/job/43")
        self.assertTrue(lease.unresolved)

    def test_returned_creation_and_observations_survive_post_call_expiry(self):
        _, lease = self.lease()
        times = iter((10, 100))
        lease.now = lambda: next(times)
        with self.assertRaises(TimeoutError):
            lease.create({"AddRef": True}, ("/fixed/entry",), 100)
        self.assertEqual(lease.creation_reply, "/org/freedesktop/systemd1/job/42")
        self.assertTrue(lease.unresolved)

    def test_reference_release_requires_bound_terminal_identity_and_empty_domain(self):
        bus, lease = self.lease()
        lease.create({"AddRef": True}, ("/fixed/entry",), 100)
        lease.bind(lease.observe(100))
        with self.assertRaises(ValueError):
            lease.release(100)
        self.assertNotIn(("close",), bus.calls)
        bus.row.update(
            MainPID=0,
            ActiveState="inactive",
            SubState="dead",
            Result="success",
            ExecMainCode=1,
            ExecMainStatus=0,
            ExecMainExitTimestampMonotonic=20,
        )
        lease.verify_terminal(100, 100_000)
        lease.release(100)
        self.assertEqual(bus.calls[-1], ("close",))
        with self.assertRaisesRegex(ValueError, "released"):
            lease.stop(100)
        self.assertEqual(bus.calls[-1], ("close",))


if __name__ == "__main__":
    unittest.main()
