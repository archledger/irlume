#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Concrete H tests with fake manager/peer endpoints; no service or VM."""

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host = load("rooted_host", "measurement-job-rooted-host.py")
native = load("h_native", "measurement-job-guardian-native.py")
rooted_native = load("h_rooted_native", "measurement-job-rooted-native.py")
inputs_module = load("h_inputs", "measurement-job-rooted-host-inputs.py")
legacy_host = load("h_terminal", "measurement-job-guardian-host.py")
fixtures = load("h_fixtures", "test-measurement-job-rooted-bus.py")
input_fixtures = load("h_input_fixtures", "test-measurement-job-rooted-host-inputs.py")
channel_fixtures = load("h_channel_fixtures", "test-measurement-job-guardian.py")


class LeaseBusTests(unittest.TestCase):
    def setUp(self):
        self.runtime = rooted_native.load_runtime(native, rooted_native)
        self.support = host.Dependencies(
            self.runtime, inputs_module, legacy_host.verify_service_terminal
        )
        fixture = fixtures.protocol_tests.ProtocolTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.config = self.runtime.protocol.Configuration(
            fixture.config.data, fixture.config.sha256
        )
        self.bus = fixtures.FakeBus(fixture)
        self.bus.close = mock.Mock()
        self.bridge = host.load_bus_bridge(self.runtime)
        self.adapter = host.LeaseBus(
            self.config, fixture.manifest, self.support, self.bus, self.bridge
        )

    def test_exact_creation_delegates_to_typed_bridge(self):
        self.assertEqual(
            self.adapter.start(
                self.adapter.name, self.adapter.properties, self.adapter.argv, 1000
            ),
            self.bus.job,
        )
        self.assertTrue(self.adapter.bridge.creation_attempted)

    def test_changed_creation_coordinates_refuse_before_bus(self):
        for field in ("name", "properties", "argv"):
            name, properties, argv = (
                self.adapter.name,
                dict(self.adapter.properties),
                self.adapter.argv,
            )
            if field == "name":
                name += "x"
            elif field == "properties":
                properties["AddRef"] = False
            else:
                argv = (*argv[:-1], "0" * 64)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.adapter.start(name, properties, argv, 5_001_000_000)
        self.assertEqual(self.bus.calls, [])

    def test_observation_keeps_root_evidence(self):
        self.assertIsNone(self.adapter.last_cgroup_id)
        row = self.adapter.observe(self.adapter.name, 5_001_000_000)
        self.assertEqual(row["Id"], self.adapter.name)
        self.assertIn("RootDirectory", self.adapter.last_root)
        # The cgroup ID comes from the same Service reply as the row.
        self.assertEqual(self.adapter.last_cgroup_id, 286458)
        self.assertNotIn("ControlGroupId", row)
        self.bus.service["ControlGroupId"] = ("t", 286459)
        self.bus.unit_reads = 0
        self.adapter.observe(self.adapter.name, 5_001_000_000)
        self.assertEqual(self.adapter.last_cgroup_id, 286459)

    def test_cleanup_observation_stays_bound_to_original_invocation(self):
        bound = {"Id": self.adapter.name, "InvocationID": "d" * 32}
        self.adapter.enter_cleanup(bound)
        replacement = dict(bound, InvocationID="e" * 32)
        self.bus.observe = mock.Mock(return_value=replacement)
        with self.assertRaises(ValueError):
            self.adapter.observe(self.adapter.name, 10_000_000_000)

    def test_cleanup_pin_takes_one_exact_raw_observation(self):
        row = {"Id": self.adapter.name, "InvocationID": "d" * 32}
        unit = dict(
            row,
            Transient=True,
            ExecStart=((self.adapter.argv[0], self.adapter.argv, False),),
        )
        self.bus.observe = mock.Mock(return_value=dict(unit, ActiveState="active"))
        self.assertEqual(self.adapter.pin_cleanup(10_000_000_000), row)
        self.bus.observe.assert_called_once_with(self.adapter.name, 10_000_000_000)
        with self.assertRaisesRegex(ValueError, "rooted cleanup binding"):
            self.adapter.pin_cleanup(10_000_000_000)
        self.bus.observe.assert_called_once()
        for wrong in (
            {"Id": self.adapter.name + "x"},
            {"InvocationID": "0" * 32},
            {"Transient": False},
            {"ExecStart": (("/usr/bin/other", ("/usr/bin/other",), False),)},
        ):
            adapter = host.LeaseBus(
                self.config, self.fixture.manifest, self.support, self.bus, self.bridge
            )
            self.bus.observe = mock.Mock(return_value=dict(unit, **wrong))
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                adapter.pin_cleanup(10_000_000_000)
            self.assertIsNone(adapter.cleanup_binding)


def stat_is_file(info):
    return (info.st_mode & 0o170000) == 0o100000


class ProcessScanTests(unittest.TestCase):
    UNIT = "irlume-job-guardian-run-01.service"

    def child(self, *args, **kwargs):
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            **kwargs,
        )
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        self.assertEqual(process.stdout.readline(), b"ready\n")
        return process

    def test_real_processes_holding_or_inside_attempt_paths_match(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "host-intent.json"
            path.write_bytes(b"intent")
            info, folder = path.stat(), Path(directory).stat()
            targets = {
                (info.st_dev, info.st_ino): "file",
                (folder.st_dev, folder.st_ino): "dir",
            }
            holder = self.child(
                "import sys; f = open(sys.argv[1]); print('ready', flush=True); sys.stdin.read()",
                str(path),
                cwd="/",
            )
            inside = self.child(
                "import sys; print('ready', flush=True); sys.stdin.read()",
                cwd=directory,
            )
            idle = self.child(
                "import sys; print('ready', flush=True); sys.stdin.read()", cwd="/"
            )
            scan = host.scan_processes(
                targets,
                self.UNIT,
                0,
                pids=[holder.pid, inside.pid, idle.pid, os.getpid()],
            )
            self.assertEqual(
                scan["matches"],
                sorted(
                    [
                        {"pid": holder.pid, "via": ["fd"]},
                        {"pid": inside.pid, "via": ["cwd"]},
                    ],
                    key=lambda row: row["pid"],
                ),
            )
            self.assertEqual((scan["processes"], scan["same_uid"]), (3, 3))

    def fake_process(
        self,
        proc,
        pid,
        *,
        uids,
        start,
        cgroup="0::/user.slice/x.scope",
        locked=False,
        links=None,
    ):
        base = proc / str(pid)
        (base / "fd").mkdir(parents=True)
        fields = ["S"] + ["0"] * 18 + [str(start)] + ["0"] * 5
        (base / "stat").write_text(f"{pid} (fake) " + " ".join(fields) + "\n")
        real, effective = uids
        (base / "status").write_text(
            f"Name:\tfake\nUid:\t{real}\t{effective}\t{effective}\t{effective}\n"
        )
        (base / "cgroup").write_text(cgroup + "\n")
        for name, target in (links or {}).items():
            (base / name).symlink_to(target)
        if locked:
            (base / "fd").chmod(0)

    def test_cgroup_members_partial_hits_and_unreadable_later_processes_match(self):
        uid = os.getuid()
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            target = Path(directory) / "attempt"
            target.mkdir()
            (target / "launcher").write_bytes(b"x")
            folder, member = target.stat(), (target / "launcher").stat()
            targets = {
                (folder.st_dev, folder.st_ino): "attempt",
                (member.st_dev, member.st_ino): "launcher",
            }
            same, other = (uid, uid), (uid + 1, uid + 1)
            unit = f"0::/app.slice/{self.UNIT}"
            self.fake_process(proc, 11, uids=other, start=5, cgroup=unit)
            self.fake_process(proc, 12, uids=same, start=499, locked=True)
            self.fake_process(proc, 13, uids=same, start=500, locked=True)
            self.fake_process(proc, 14, uids=other, start=900, locked=True)
            self.fake_process(proc, 15, uids=(uid, 0), start=900, locked=True)
            self.fake_process(
                proc, 16, uids=same, start=10, locked=True, links={"cwd": target}
            )
            self.fake_process(proc, 17, uids=same, start=900, links={"root": target})
            self.fake_process(
                proc, 18, uids=same, start=900, links={"exe": target / "launcher"}
            )
            self.fake_process(proc, 19, uids=same, start=900)
            try:
                scan = host.scan_processes(targets, self.UNIT, 500, proc=str(proc))
            finally:
                for pid in (12, 13, 14, 15, 16):
                    (proc / str(pid) / "fd").chmod(0o700)
        self.assertEqual(
            scan["matches"],
            [
                {"pid": 11, "via": ["cgroup"]},
                {"pid": 13, "via": ["unreadable-after-owner"]},
                {"pid": 16, "via": ["cwd", "unreadable"]},
                {"pid": 17, "via": ["root"]},
                {"pid": 18, "via": ["exe"]},
            ],
        )
        self.assertEqual(scan["unreadable_before_owner"], 1)
        self.assertEqual((scan["processes"], scan["same_uid"]), (9, 6))

    def test_unit_cgroups_finds_only_unit_directories_below_the_user_manager(self):
        uid = os.getuid()
        unit = self.UNIT
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with self.assertRaises(FileNotFoundError):
                host.unit_cgroups(unit, uid, base=str(base))
            manager = base / f"user.slice/user-{uid}.slice/user@{uid}.service"
            (manager / "app.slice" / unit).mkdir(parents=True)
            (manager / "a/b/c" / unit).mkdir(parents=True)
            (manager / "a/b/c/d" / unit).mkdir(parents=True)
            (manager / "app.slice" / (unit + ".x")).mkdir()
            (manager / "session.slice").mkdir()
            (manager / "session.slice" / unit).write_text("not a directory")
            self.assertEqual(
                host.unit_cgroups(unit, uid, base=str(base)),
                [f"a/b/c/{unit}", f"app.slice/{unit}"],
            )
            self.assertEqual(
                host.unit_cgroups("other.service", uid, base=str(base)), []
            )


class BootIdentityTests(unittest.TestCase):
    def test_boot_identity_is_one_lowercase_uuid_line(self):
        good = b"0123abcd-4567-89ef-0123-456789abcdef"
        with mock.patch.object(
            host, "open", mock.mock_open(read_data=good + b"\n"), create=True
        ):
            self.assertEqual(host.boot_id(), good.decode())
        for data in (b"", good, good.upper() + b"\n", good + b"\n\n", b"x" + good):
            with (
                self.subTest(data=data),
                mock.patch.object(
                    host, "open", mock.mock_open(read_data=data), create=True
                ),
                self.assertRaisesRegex(ValueError, "host boot identity"),
            ):
                host.boot_id()


class FactoryTests(unittest.TestCase):
    def setUp(self):
        input_fixtures.InputOwnerTests.setUp(self)
        self.runtime = rooted_native.load_runtime(native, rooted_native)
        self.root = self.runtime.preflight.root
        self.support = host.Dependencies(
            self.runtime, inputs_module, legacy_host.verify_service_terminal
        )
        self.gate_path = self.path / "gate"
        self.gate_path.mkdir(mode=0o700)
        spec = self.root.guardian.Specification(**self.spec._asdict())._replace(
            overlay=str(self.gate_path / "attempt-run-01/overlay.qcow2")
        )
        self.selection = inputs_module.Selection(spec, *self.selection[1:])
        fixture = fixtures.protocol_tests.ProtocolTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.coordinates = {
            "host_namespaces": fixture.plan["host_namespaces"],
            "host_api": fixture.plan["host_api"],
            # H's own bus node, a stability coordinate only it observes.
            "bus": {"device": 1, "inode": 900},
        }
        self.owner = host.HostOwner(
            self.selection,
            self.support,
            gate_factory=lambda deadline: native.service.AdmissionGate(
                self.gate_path, deadline
            ),
            bus_factory=mock.Mock(side_effect=AssertionError("unexpected bus")),
            host_observer=lambda deadline: self.coordinates,
        )
        self.addCleanup(self.close_owned)

    def tearDown(self):
        if host.UNRESOLVED.get(self.spec.run_id) is self.owner:
            host.UNRESOLVED.pop(self.spec.run_id)

    def close_owned(self):
        for resource in (self.owner.channel, self.owner.listener, self.owner.inputs):
            if resource is not None:
                resource.close()
        if self.owner.directory is not None:
            os.close(self.owner.directory)
            self.owner.directory = None
        if self.owner.gate is not None:
            self.owner.gate.close()

    def acquire(self):
        self.owner.acquire(time.monotonic_ns() + 5_000_000_000)

    def test_factory_holds_admission_before_any_input_acquisition(self):
        opening = inputs_module.PreparedInputs.open

        def check_locked(*args, **kwargs):
            with self.assertRaises(BlockingIOError):
                native.service.AdmissionGate(self.gate_path, kwargs["deadline"])
            return opening(*args, **kwargs)

        with mock.patch.object(
            inputs_module.PreparedInputs, "open", side_effect=check_locked
        ):
            self.acquire()
        value = self.owner.value
        for key, selected in self.owner.inputs.identities().items():
            self.assertEqual(value["root_plan"][key], selected)
        self.assertEqual(value["client"]["pid"], os.getpid())
        self.assertEqual(
            value["client"]["starttime"], native.process_start(os.getpid())
        )

    def test_existing_admission_refuses_before_reading_inputs(self):
        (self.gate_path / "active.json").write_bytes(b"prior ownership")
        with (
            mock.patch.object(
                inputs_module.PreparedInputs,
                "open",
                side_effect=AssertionError("input read"),
            ),
            self.assertRaises(FileExistsError),
        ):
            self.acquire()

    def test_preparation_closes_readonly_config_and_intent_before_service(self):
        self.acquire()
        self.owner.prepare(
            self.owner.config,
            self.owner.inputs.manifest,
            self.owner.value["startup_deadline_ns"],
        )
        config = self.owner.path / "guardian-config.json"
        self.assertEqual(config.read_bytes(), self.owner.config.data)
        self.assertEqual(config.stat().st_mode & 0o777, 0o400)
        self.assertIsNotNone(self.owner.gate.record)
        self.assertTrue((self.gate_path / "active.json").is_file())
        self.assertTrue((self.owner.path / "host-intent.json").is_file())
        self.owner.bus_factory.assert_not_called()

    def make_bus(self, install=True):
        fixture = types.SimpleNamespace(
            spec=self.owner.spec, root=self.root, plan=self.owner.value["root_plan"]
        )
        bus = fixtures.FakeBus(fixture)
        now = time.monotonic_ns() // 1000
        bus.service["MainPID"] = ("u", os.getpid() + 100)
        bus.service["ExecMainStartTimestampMonotonic"] = ("t", now - 100)
        bus.unit["ActiveEnterTimestampMonotonic"] = ("t", now - 50)
        bus.after = dict(bus.unit)
        argv = self.root.entry_argv(
            self.owner.value["root_plan"], self.owner.config.sha256
        )
        bus.service["ExecStart"] = (
            "a(sasbttttuii)",
            [[argv[0], list(argv), False, 0, 0, 0, 0, 0, 0, 0]],
        )
        bus.close = mock.Mock()
        bus.processes = mock.Mock(return_value=())
        if install:
            self.owner.bus_factory = mock.Mock(return_value=bus)
        return bus

    def test_prestart_input_change_prevents_any_manager_connection(self):
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        self.files["base"].chmod(0o600)
        self.files["base"].write_bytes(b"bad inputs")
        self.files["base"].chmod(0o400)
        with self.assertRaises(ValueError):
            self.owner.start(self.owner.config, deadline)
        self.owner.bus_factory.assert_not_called()

    def test_start_binds_service_with_manager_padded_cpu_mask(self):
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        bus = self.make_bus()
        kind, requested = bus.service["CPUAffinity"]
        self.assertEqual((kind, len(requested)), ("ay", 1))
        # systemd returns its whole 8-byte CPU_ALLOC_SIZE buffer for this mask.
        bus.service["CPUAffinity"] = (kind, requested + bytes(7))
        identity = self.owner.start(self.owner.config, deadline)
        self.assertEqual(identity.invocation_id, "d" * 32)
        self.assertEqual(self.owner.lease.bound["InvocationID"], "d" * 32)

    def test_start_records_the_cgroup_id_of_the_bound_row(self):
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        bus = self.make_bus()
        observe = self.owner.bus_bridge.RootedBus.observe
        seen = []

        def activating_first(bridge, *args):
            # The first row is still activating and has another ID; only the
            # row that produced the identity names the recorded one.
            result = observe(bridge, *args)
            seen.append(result["cgroup_id"])
            bus.unit_reads = 0
            if len(seen) == 1:
                bus.service["ControlGroupId"] = ("t", 286458)
                return dict(
                    result,
                    cgroup_id=1,
                    service=dict(result["service"], ActiveState="activating"),
                )
            return result

        bus.service["ControlGroupId"] = ("t", 1)
        with (
            mock.patch.object(
                self.owner.bus_bridge.RootedBus, "observe", activating_first
            ),
            mock.patch.object(host.time, "sleep"),
        ):
            identity = self.owner.start(self.owner.config, deadline)
        self.assertEqual(seen, [1, 286458])
        record = json.loads((self.owner.path / "host-started.json").read_bytes())
        self.assertEqual(
            record,
            {
                "service": identity._asdict(),
                "cgroup_id": 286458,
                "creation_reply": self.owner.lease.creation_reply,
            },
        )
        self.assertEqual(self.owner.cgroup_id(identity, deadline), 286458)
        for other in (
            identity._replace(pid=identity.pid + 1),
            identity._replace(invocation_id="e" * 32),
            identity._asdict(),
            None,
        ):
            with (
                self.subTest(other=other),
                self.assertRaisesRegex(ValueError, "rooted cgroup identity mismatch"),
            ):
                self.owner.cgroup_id(other, deadline)
        # Not after the configuration deadline.
        with self.assertRaises(TimeoutError):
            self.owner.cgroup_id(identity, self.owner.now())

    def test_start_without_a_cgroup_id_binds_nothing(self):
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        bus = self.make_bus()
        del bus.service["ControlGroupId"]
        with self.assertRaisesRegex(
            ValueError, "missing rooted bus property: ControlGroupId"
        ):
            self.owner.start(self.owner.config, deadline)
        self.assertIsNone(self.owner.identity)
        self.assertIsNone(self.owner.lease.bound)
        self.assertFalse((self.owner.path / "host-started.json").exists())
        with self.assertRaisesRegex(ValueError, "rooted cgroup identity mismatch"):
            self.owner.cgroup_id(None, deadline)

    def test_peer_liveness_brackets_connected_guardian_starttime(self):
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        self.make_bus()
        identity = self.owner.start(self.owner.config, deadline)
        with mock.patch.object(native, "process_start", return_value=100):
            self.owner.process_start(identity, deadline)
        self.owner.listener.close()
        self.owner.listener = mock.Mock()
        self.owner.listener.accept.return_value = (mock.Mock(), None)
        channel, order = mock.Mock(), []
        channel.check.side_effect = lambda end: order.append("alive")
        channel.peer_fd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, channel.peer_fd)

        def changed_start(pid):
            order.append("starttime")
            return 101

        with (
            mock.patch.object(self.root.guardian, "PeerChannel", return_value=channel),
            mock.patch.object(native, "process_start", side_effect=changed_start),
            self.assertRaises(ValueError),
        ):
            self.owner.connect(identity, deadline)
        self.assertEqual(order, ["alive", "starttime", "alive"])
        channel.send.assert_not_called()

    def connectable_owner(self):
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        bus = self.make_bus()
        identity = self.owner.start(self.owner.config, deadline)
        with mock.patch.object(native, "process_start", return_value=100):
            self.owner.process_start(identity, deadline)
        self.owner.listener.close()
        channel = mock.Mock()
        # A real pidfd: the fake manager resolves it by the PID it names.
        channel.peer_fd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, channel.peer_fd)
        return bus, identity, channel, deadline

    def test_connect_binds_peer_pidfd_invocation(self):
        bus, identity, channel, deadline = self.connectable_owner()
        # H opened its manager connection with descriptor passing.
        self.owner.bus_factory.assert_called_once_with(
            os.getuid(), deadline=deadline, fds=True
        )
        other = "irlume-job-guardian-other.service"
        cases = (
            ("invocation", "pidfd_invocation", bytes.fromhex("e" * 32), "invocation"),
            ("unit", "pidfd_unit", other, "process unit"),
        )

        def peer_calls():
            return [call[4] for call in bus.calls if call[2] == "GetUnitByPIDFD"]

        with (
            mock.patch.object(self.root.guardian, "PeerChannel", return_value=channel),
            mock.patch.object(native, "process_start", return_value=100),
        ):
            for label, field, value, message in cases:
                self.owner.channel = None
                self.owner.listener = mock.Mock()
                self.owner.listener.accept.return_value = (mock.Mock(), None)
                setattr(bus, field, value)
                with (
                    self.subTest(at="connect", case=label),
                    self.assertRaisesRegex(ValueError, message),
                ):
                    self.owner.connect(identity, deadline)
                setattr(bus, field, None)
                self.assertEqual(peer_calls()[-1], (channel.peer_fd,))
            self.owner.channel = None
            self.owner.listener = mock.Mock()
            self.owner.listener.accept.return_value = (mock.Mock(), None)
            count = len(peer_calls())
            self.owner.connect(identity, deadline)
            # Once after accept and once more in the recheck connect ends with.
            self.assertEqual(peer_calls()[count:], [(channel.peer_fd,)] * 2)
            self.assertEqual(
                self.owner.adapter.bridge.partial["pidfd_unit"][1:],
                (identity.unit, identity.invocation_id),
            )
            for label, field, value, message in cases:
                setattr(bus, field, value)
                with (
                    self.subTest(at="recheck", case=label),
                    self.assertRaisesRegex(ValueError, message),
                ):
                    self.owner.recheck(identity, 100, deadline)
                setattr(bus, field, None)
            self.owner.recheck(identity, 100, deadline)
        channel.send.assert_not_called()

    def foreign_exec_starts(self):
        """Wire ExecStart readbacks of a unit not running this config's entry."""
        plan, digest = self.owner.value["root_plan"], self.owner.config.sha256
        argv = list(self.root.entry_argv(plan, digest))
        self.assertEqual(argv[-1], digest)
        other = [*argv[:-1], "0" * 64]
        self.assertNotEqual(other, argv)

        def row(path, args, ignore=False):
            return ("a(sasbttttuii)", [[path, args, ignore, 0, 0, 0, 0, 0, 0, 0]])

        return {
            "executable": row("/usr/bin/other", ["/usr/bin/other"]),
            "config": row(argv[0], other),
            "argv0": row(argv[0], ["other", *argv[1:]]),
            "ignore-failure": row(argv[0], argv, True),
            "none": ("a(sasbttttuii)", []),
        }

    def test_start_refuses_a_foreign_guardian_executable(self):
        # Only H binds the unit's ExecStart to this config's entry argv.
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        bus = self.make_bus()
        bus.service["ExecStart"] = self.foreign_exec_starts()["executable"]
        with self.assertRaisesRegex(
            ValueError, "rooted host guardian executable mismatch"
        ):
            self.owner.start(self.owner.config, deadline)
        self.assertTrue(self.owner.lease.created)
        self.assertIsNone(self.owner.lease.bound)
        self.assertIsNone(self.owner.identity)
        self.assertFalse((self.owner.path / "host-started.json").exists())

    def test_recheck_refuses_a_foreign_guardian_executable(self):
        bus, identity, channel, deadline = self.connectable_owner()
        exact = bus.service["ExecStart"]

        def peer_calls():
            return [call for call in bus.calls if call[2] == "GetUnitByPIDFD"]

        with (
            mock.patch.object(self.root.guardian, "PeerChannel", return_value=channel),
            mock.patch.object(native, "process_start", return_value=100),
        ):
            self.owner.listener = mock.Mock()
            self.owner.listener.accept.return_value = (mock.Mock(), None)
            self.owner.connect(identity, deadline)
            for label, value in self.foreign_exec_starts().items():
                bus.service["ExecStart"] = value
                count = len(peer_calls())
                with self.subTest(case=label):
                    with self.assertRaisesRegex(
                        ValueError, "rooted host guardian executable mismatch"
                    ):
                        self.owner.recheck(identity, 100, deadline)
                    # The unit is refused before the peer is consulted.
                    self.assertEqual(len(peer_calls()), count)
            bus.service["ExecStart"] = exact
            self.owner.recheck(identity, 100, deadline)
        channel.send.assert_not_called()

    def test_recheck_refuses_a_changed_cgroup_id(self):
        bus, identity, channel, deadline = self.connectable_owner()
        with (
            mock.patch.object(self.root.guardian, "PeerChannel", return_value=channel),
            mock.patch.object(native, "process_start", return_value=100),
        ):
            self.owner.listener = mock.Mock()
            self.owner.listener.accept.return_value = (mock.Mock(), None)
            self.owner.connect(identity, deadline)
            # A new cgroup directory for the same invocation, or none.
            for value in (("t", 286459), ("t", 286457), ("t", 0)):
                bus.service["ControlGroupId"] = value
                with (
                    self.subTest(value=value),
                    self.assertRaisesRegex(
                        ValueError,
                        "rooted guardian changed before commit"
                        if value[1]
                        else "rooted service cgroup ID",
                    ),
                ):
                    self.owner.recheck(identity, 100, deadline)
                # LAUNCH still gets the ID bound with the identity.
                self.assertEqual(self.owner.cgroup_id(identity, deadline), 286458)
            bus.service["ControlGroupId"] = ("t", 286458)
            self.owner.recheck(identity, 100, deadline)
            self.assertEqual(self.owner.cgroup_id(identity, deadline), 286458)
        channel.send.assert_not_called()

    def test_commit_allows_peer_exit_after_final_write(self):
        frame = self.root.guardian.encode({"kind": "commit", "payload": {}})
        with channel_fixtures.ChannelTests().exiting_peer() as (
            channel,
            right,
            _,
            deadline,
        ):
            self.owner.channel = channel
            try:
                self.owner.send(frame, deadline)
            except ValueError as error:
                self.fail(f"fully delivered COMMIT rejected peer exit: {error}")
            self.assertEqual(right.recv(len(frame)), frame)
            self.assertTrue(self.owner.committed)

    def test_exit_after_send_is_selected_only_for_commit(self):
        self.owner.channel = mock.Mock()
        deadline = time.monotonic_ns() + 1_000_000_000
        for kind, allowed in (("launch", False), ("commit", True)):
            frame = self.root.guardian.encode({"kind": kind, "payload": {}})
            self.owner.send(frame, deadline)
            self.owner.channel.send.assert_called_with(
                frame, deadline, allow_exit_after_send=allowed
            )

    def terminal_owner(self):
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        bus = self.make_bus()
        identity = self.owner.start(self.owner.config, deadline)
        self.owner.lease.terminal = True
        self.owner.lease.unresolved = False
        record = {
            "scope": "contained-job-rooted-startup-result-v1",
            "role": "H",
            "config_sha256": self.owner.config.sha256,
            "startup_sha256": "a" * 64,
            "service": identity._asdict(),
            "outcome": "startup-only-complete",
            "accepted": False,
            "native_authorized": False,
            "full_contract_proven": False,
        }
        self.owner.finish(self.root.closure.canonical(record), deadline)
        return bus, record

    def test_all_non_gate_owners_close_before_admission_commit(self):
        bus, record = self.terminal_owner()
        complete = self.owner.gate.complete

        def checked_complete(data, deadline):
            self.assertTrue(
                all(value.fd is None for value in self.owner.inputs.files.values())
            )
            self.assertIsNone(self.owner.inputs.runtime.fd)
            self.assertIsNone(self.owner.directory)
            self.assertIsNone(self.owner.listener)
            self.assertIsNone(self.owner.channel)
            bus.close.assert_called_once()
            return complete(data, deadline)

        with mock.patch.object(
            self.owner.gate, "complete", side_effect=checked_complete
        ):
            self.owner.complete(record)
        self.assertFalse((self.gate_path / "active.json").exists())
        self.assertEqual(self.owner.commit_state, "absent")

    def test_input_close_failure_keeps_admission_blocker(self):
        _, record = self.terminal_owner()
        close = self.owner.inputs.files["base"].close

        def failed_close():
            close()
            raise OSError("input close failed")

        with (
            mock.patch.object(
                self.owner.inputs.files["base"], "close", side_effect=failed_close
            ),
            mock.patch.object(
                self.owner.gate,
                "complete",
                side_effect=AssertionError("premature commit"),
            ),
            self.assertRaises(BaseExceptionGroup),
        ):
            self.owner.complete(record)
        self.assertTrue((self.gate_path / "active.json").exists())
        self.assertIsNotNone(self.owner.gate.lock_fd)

    def test_gate_failure_after_unlink_records_absence_not_retained_blocker(self):
        _, record = self.terminal_owner()
        fsync, calls = os.fsync, []
        gate_fd = self.owner.gate.root_fd

        def failed_after_unlink(fd):
            fsync(fd)
            if fd == gate_fd:
                calls.append(fd)
                if len(calls) == 2:
                    raise OSError("post-unlink fsync failed")

        with (
            mock.patch.object(
                native.service.os, "fsync", side_effect=failed_after_unlink
            ),
            self.assertRaises(OSError),
        ):
            self.owner.complete(record)
        self.assertFalse((self.gate_path / "active.json").exists())
        self.assertEqual(self.owner.commit_state, "absent")

    def test_gate_and_lock_permission_changes_refuse(self):
        self.acquire()
        for path, original, changed in (
            (self.gate_path, 0o700, 0o755),
            (self.gate_path / "admission.lock", 0o600, 0o644),
        ):
            path.chmod(changed)
            try:
                with self.subTest(path=path.name), self.assertRaises(ValueError):
                    self.owner.check_gate(self.owner.value["startup_deadline_ns"])
            finally:
                path.chmod(original)

    def test_post_commit_gate_close_failure_keeps_known_absent_state(self):
        _, record = self.terminal_owner()
        close = self.owner.gate.close

        def fail_after_close():
            close()
            raise OSError("gate close failed")

        with (
            mock.patch.object(self.owner.gate, "close", side_effect=fail_after_close),
            self.assertRaises(OSError),
        ):
            self.owner.complete(record)
        with self.assertRaises((OSError, TypeError, BaseExceptionGroup)):
            self.owner.abort(
                self.owner.config,
                self.owner.identity,
                "OSError",
                self.owner.value["startup_deadline_ns"] + self.root.guardian.STOP_NS,
            )
        self.assertEqual(self.owner.commit_state, "absent")

    def test_closed_gate_cannot_fall_back_to_current_directory(self):
        self.acquire()
        self.owner.gate.close()
        with mock.patch.object(
            host.os, "stat", side_effect=AssertionError("lost dir_fd")
        ):
            self.assertEqual(self.owner.active_state(), "uncertain")

    def test_uncertain_creation_keeps_bus_and_admission_through_abort(self):
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        bus = self.make_bus()
        held = [value.fd for value in self.owner.inputs.files.values()] + [
            self.owner.inputs.runtime.fd,
            self.owner.directory,
        ]
        identities = [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in held]
        bus.late = "StartTransientUnit"
        with self.assertRaises(TimeoutError):
            self.owner.start(self.owner.config, deadline)
        self.owner.abort(
            self.owner.config,
            None,
            "TimeoutError",
            deadline + self.root.guardian.STOP_NS,
        )
        self.assertTrue(self.owner.lease.unresolved)
        self.assertEqual(self.owner.adapter.bridge.start_reply, bus.job)
        self.assertIs(host.UNRESOLVED[self.spec.run_id], self.owner)
        self.assertTrue((self.gate_path / "active.json").is_file())
        self.assertIsNotNone(self.owner.gate.lock_fd)
        bus.close.assert_not_called()
        retained = [value.fd for value in self.owner.inputs.files.values()] + [
            self.owner.inputs.runtime.fd,
            self.owner.directory,
        ]
        self.assertEqual(retained, held)
        self.assertEqual(
            [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in retained], identities
        )
        self.owner.inputs.recheck(deadline + self.root.guardian.STOP_NS)
        self.assertNotIn("StopUnit", [call[2] for call in bus.calls])
        record = self.failure_record()
        self.assertEqual(
            {key: record[key] for key in self.STOP_FIELDS},
            {
                "creation_attempted": True,
                "created": False,
                "creation_reply": bus.job,
                "invocation_id": None,
                "invocation_source": None,
                "observed": None,
                "stop_attempted": False,
                "stop_reply": None,
                "stop_error": None,
                "cleanup_errors": [],
            },
        )

    STOP_FIELDS = (
        "creation_attempted",
        "created",
        "creation_reply",
        "invocation_id",
        "invocation_source",
        "observed",
        "stop_attempted",
        "stop_reply",
        "stop_error",
        "cleanup_errors",
    )

    def failure_record(self):
        data = (self.gate_path / f"failed-{self.spec.run_id}.json").read_bytes()
        record = json.loads(data)
        self.assertEqual(self.root.closure.canonical(record), data)
        self.assertEqual(record["scope"], "contained-job-rooted-host-failure-v2")
        self.assertEqual(record["run_id"], self.spec.run_id)
        self.assertEqual(record["admission_state"], "present")
        self.assertEqual(
            record["boot_id"],
            Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        )
        self.assertIs(record["native_authorized"], False)
        self.assertIs(record["full_contract_proven"], False)
        return record

    def refused_service(self):
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        bus = self.make_bus()
        # A third CPU in the effective mask refuses the service before binding.
        bus.service["CPUAffinity"] = ("ay", [7])
        bus.stop = mock.Mock(return_value="/org/freedesktop/systemd1/job/77")
        with self.assertRaisesRegex(ValueError, "CPUAffinity"):
            self.owner.start(self.owner.config, deadline)
        self.assertTrue(self.owner.lease.created)
        self.assertIsNone(self.owner.lease.bound)
        return bus, deadline + self.root.guardian.STOP_NS

    def assert_blocker_and_reference_retained(self, bus):
        self.assertTrue((self.gate_path / "active.json").is_file())
        self.assertIsNotNone(self.owner.gate.lock_fd)
        self.assertIs(host.UNRESOLVED[self.spec.run_id], self.owner)
        bus.close.assert_not_called()

    def test_abort_stops_created_service_refused_before_binding(self):
        bus, end = self.refused_service()
        self.owner.abort(self.owner.config, None, "ValueError", end)
        bus.stop.assert_called_once_with(
            self.owner.adapter.name, end - host.FAILURE_RECORD_NS
        )
        record = self.failure_record()
        self.assertEqual(
            {key: record[key] for key in self.STOP_FIELDS},
            {
                "creation_attempted": True,
                "created": True,
                "creation_reply": bus.job,
                "invocation_id": "d" * 32,
                "invocation_source": "observation",
                "observed": {
                    "Id": self.owner.adapter.name,
                    "InvocationID": "d" * 32,
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": bus.service["MainPID"][1],
                    "ControlGroup": bus.service["ControlGroup"][1],
                    "ExecMainStartTimestampMonotonic": bus.service[
                        "ExecMainStartTimestampMonotonic"
                    ][1],
                },
                "stop_attempted": True,
                "stop_reply": "/org/freedesktop/systemd1/job/77",
                "stop_error": None,
                "cleanup_errors": [],
            },
        )
        self.assertIsNone(self.owner.lease.bound)
        self.assert_blocker_and_reference_retained(bus)

    def test_abort_never_stops_a_changed_invocation_refused_before_binding(self):
        bus, end = self.refused_service()
        bus.unit["InvocationID"] = bus.variant("ay", tuple(bytes.fromhex("e" * 32)))
        bus.after = dict(bus.unit)
        with self.assertRaisesRegex(ValueError, "lost invocation"):
            self.owner.abort(self.owner.config, None, "ValueError", end)
        bus.stop.assert_not_called()
        record = self.failure_record()
        self.assertEqual(record["invocation_id"], "d" * 32)
        self.assertEqual(record["invocation_source"], "observation")
        self.assertEqual(record["observed"]["InvocationID"], "d" * 32)
        self.assertIs(record["stop_attempted"], False)
        self.assertIsNone(record["stop_reply"])
        self.assertEqual(record["stop_error"], "ValueError")
        self.assertEqual(record["cleanup_errors"], ["ValueError"])
        self.assert_blocker_and_reference_retained(bus)

    def test_abort_after_terminal_proof_records_invocation_without_stop(self):
        bus, _ = self.terminal_owner()
        bus.stop = mock.Mock(side_effect=AssertionError("terminal stop"))
        self.owner.abort(
            self.owner.config,
            self.owner.identity,
            "OSError",
            self.owner.value["startup_deadline_ns"] + self.root.guardian.STOP_NS,
        )
        bus.stop.assert_not_called()
        record = self.failure_record()
        self.assertEqual(record["invocation_id"], "d" * 32)
        self.assertEqual(record["invocation_source"], "bound")
        self.assertIs(record["stop_attempted"], False)
        self.assertIsNone(record["stop_error"])
        self.assertEqual(record["cleanup_errors"], [])

    def test_abort_never_redirects_a_bound_invocation_to_a_later_one(self):
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        bus = self.make_bus()
        bus.stop = mock.Mock(side_effect=AssertionError("redirected stop"))
        self.owner.start(self.owner.config, deadline)
        bus.unit["InvocationID"] = bus.variant("ay", tuple(bytes.fromhex("e" * 32)))
        bus.after = dict(bus.unit)
        self.owner.lease.observe(deadline)
        end = deadline + self.root.guardian.STOP_NS
        with self.assertRaisesRegex(ValueError, "lost invocation"):
            self.owner.abort(self.owner.config, self.owner.identity, "ValueError", end)
        bus.stop.assert_not_called()
        record = self.failure_record()
        self.assertEqual(record["invocation_id"], "d" * 32)
        self.assertEqual(record["invocation_source"], "bound")
        self.assertEqual(record["observed"]["InvocationID"], "e" * 32)
        self.assertIs(record["stop_attempted"], False)
        self.assertEqual(record["stop_error"], "ValueError")
        self.assert_blocker_and_reference_retained(bus)

    def unobserved_service(self, trigger):
        self.acquire()
        deadline = self.owner.value["startup_deadline_ns"]
        self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
        bus = self.make_bus()
        if trigger == "changed":
            # The first observation straddles activating -> active.
            bus.unit.update(
                ActiveState=bus.variant("s", "activating"),
                SubState=bus.variant("s", "start"),
            )
            error = (ValueError, "changed during observation")
        else:
            bus.late = "GetUnit"
            error = (TimeoutError, "")
        bus.stop = mock.Mock(return_value="/org/freedesktop/systemd1/job/77")
        with self.assertRaisesRegex(*error):
            self.owner.start(self.owner.config, deadline)
        self.assertTrue(self.owner.lease.created)
        self.assertIsNone(self.owner.lease.last_observation)
        return bus, deadline + self.root.guardian.STOP_NS

    def assert_unobserved_service_stopped(self, trigger):
        bus, end = self.unobserved_service(trigger)
        self.owner.abort(self.owner.config, None, "ValueError", end)
        bus.stop.assert_called_once_with(
            self.owner.adapter.name, end - host.FAILURE_RECORD_NS
        )
        self.assertEqual(
            self.owner.adapter.cleanup_binding,
            {"Id": self.owner.adapter.name, "InvocationID": "d" * 32},
        )
        record = self.failure_record()
        self.assertEqual(
            {key: record[key] for key in self.STOP_FIELDS},
            {
                "creation_attempted": True,
                "created": True,
                "creation_reply": bus.job,
                "invocation_id": "d" * 32,
                "invocation_source": "cleanup",
                "observed": None,
                "stop_attempted": True,
                "stop_reply": "/org/freedesktop/systemd1/job/77",
                "stop_error": None,
                "cleanup_errors": [],
            },
        )
        self.assert_blocker_and_reference_retained(bus)

    def test_abort_stops_created_service_refused_inside_first_observation(self):
        self.assert_unobserved_service_stopped("changed")

    def test_abort_stops_created_service_whose_first_observation_timed_out(self):
        self.assert_unobserved_service_stopped("late")

    def stalled_cleanup_observation(self, stall_at):
        bus, end = self.unobserved_service("late")
        clock, deadlines, observe = [time.monotonic_ns()], [], bus.observe

        def raw(name, deadline):
            deadlines.append(deadline)
            if len(deadlines) == stall_at:
                clock[0] = deadline
                raise TimeoutError("manager stalled")
            return observe(name, deadline)

        bus.observe = raw
        with (
            mock.patch.object(self.owner, "now", side_effect=lambda: clock[0]),
            self.assertRaises(TimeoutError),
        ):
            self.owner.abort(self.owner.config, None, "TimeoutError", end)
        self.assertEqual(deadlines, [end - host.FAILURE_RECORD_NS] * stall_at)
        bus.stop.assert_not_called()
        record = self.failure_record()
        self.assertIs(record["stop_attempted"], False)
        self.assertEqual(record["stop_error"], "TimeoutError")
        self.assertEqual(record["cleanup_errors"], ["TimeoutError"])
        self.assert_blocker_and_reference_retained(bus)
        return record

    def test_stalled_cleanup_pin_leaves_time_for_the_failure_record(self):
        record = self.stalled_cleanup_observation(1)
        self.assertIsNone(self.owner.adapter.cleanup_binding)
        self.assertIsNone(record["invocation_id"])
        self.assertIsNone(record["invocation_source"])

    def test_stalled_observation_after_the_pin_keeps_the_pinned_invocation(self):
        record = self.stalled_cleanup_observation(2)
        self.assertEqual(self.owner.adapter.cleanup_binding["InvocationID"], "d" * 32)
        self.assertEqual(record["invocation_id"], "d" * 32)
        self.assertEqual(record["invocation_source"], "cleanup")

    def test_invocation_changed_after_the_pin_is_recorded_but_never_stopped(self):
        bus, end = self.unobserved_service("late")
        observe, rows = bus.observe, []

        def raw(name, deadline):
            rows.append(observe(name, deadline))
            if len(rows) > 1:
                return dict(rows[-1], InvocationID="e" * 32)
            return rows[-1]

        bus.observe = raw
        with self.assertRaisesRegex(ValueError, "rooted cleanup lost invocation"):
            self.owner.abort(self.owner.config, None, "TimeoutError", end)
        bus.stop.assert_not_called()
        record = self.failure_record()
        self.assertEqual(record["invocation_id"], "d" * 32)
        self.assertEqual(record["invocation_source"], "cleanup")
        self.assertIs(record["stop_attempted"], False)
        self.assertEqual(record["stop_error"], "ValueError")
        self.assert_blocker_and_reference_retained(bus)

    def test_cleanup_pin_refuses_an_anonymous_invocation(self):
        bus, end = self.unobserved_service("changed")
        bus.after["InvocationID"] = bus.variant("ay", tuple(bytes(16)))
        with self.assertRaisesRegex(ValueError, "rooted cleanup invocation"):
            self.owner.abort(self.owner.config, None, "ValueError", end)
        bus.stop.assert_not_called()
        self.assertIsNone(self.owner.adapter.cleanup_binding)
        record = self.failure_record()
        self.assertIsNone(record["invocation_id"])
        self.assertIsNone(record["invocation_source"])
        self.assertIs(record["stop_attempted"], False)
        self.assertEqual(record["stop_error"], "ValueError")
        self.assert_blocker_and_reference_retained(bus)

    def test_stalled_stop_leaves_time_for_the_failure_record(self):
        bus, end = self.refused_service()
        clock = [time.monotonic_ns()]

        def stalled(name, deadline):
            clock[0] = deadline
            raise TimeoutError("stop reply lost")

        bus.stop = mock.Mock(side_effect=stalled)
        with (
            mock.patch.object(self.owner, "now", side_effect=lambda: clock[0]),
            self.assertRaises(TimeoutError),
        ):
            self.owner.abort(self.owner.config, None, "ValueError", end)
        self.assertEqual(clock[0], end - host.FAILURE_RECORD_NS)
        record = self.failure_record()
        self.assertIs(record["stop_attempted"], True)
        self.assertIsNone(record["stop_reply"])
        self.assertEqual(record["stop_error"], "TimeoutError")
        self.assertEqual(record["cleanup_errors"], ["TimeoutError"])
        self.assert_blocker_and_reference_retained(bus)

    FOREIGN = "/org/freedesktop/systemd1/unit/foreign_2eservice"

    def retained_failure(self):
        """A refused attempt left as a dead H leaves it, with its unit now failed."""
        bus, end = self.refused_service()
        self.owner.abort(self.owner.config, None, "ValueError", end)
        observed = self.failure_record()["observed"]
        self.close_owned()
        self.owner.inputs = self.owner.gate = None
        host.UNRESOLVED.pop(self.spec.run_id)
        start = bus.service["ExecMainStartTimestampMonotonic"][1]
        bus.unit.update(
            ActiveState=("s", "failed"),
            SubState=("s", "failed"),
            Job=("(uo)", (0, "/")),
            Refs=("as", []),
        )
        bus.after = dict(bus.unit)
        bus.service.update(
            MainPID=("u", 0),
            ControlGroup=("s", ""),
            ExecMainExitTimestampMonotonic=("t", start + 50),
            Result=("s", "signal"),
            ExecMainCode=("i", 2),
            ExecMainStatus=("i", 9),
            ExecMainPID=("u", observed["MainPID"]),
        )
        bus.leftover, bus.by_invocation, bus.get_unit = [], self.FOREIGN, None
        self.scanned, self.cgroups = [], []
        call = bus.call

        def manager(path, interface, method, signature, args, deadline):
            if method in ("GetUnitProcesses", "GetUnitByInvocationID"):
                bus.calls.append((path, interface, method, signature, args, deadline))
                answer = (
                    bus.leftover if method == "GetUnitProcesses" else bus.by_invocation
                )
                if isinstance(answer, BaseException):
                    raise answer
                return copy.deepcopy(answer)
            if method == "GetUnit" and bus.get_unit is not None:
                raise bus.get_unit
            if method == "GetAll" and path == self.FOREIGN:
                bus.calls.append((path, interface, method, signature, args, deadline))
                return copy.deepcopy(
                    bus.foreign if hasattr(bus, "foreign") else bus.after
                )
            return call(path, interface, method, signature, args, deadline)

        bus.call = manager
        return bus, len(bus.calls)

    def resolve(self, bus, **options):
        defaults = {
            "gate_factory": lambda deadline: native.service.AdmissionGate(
                self.gate_path, deadline
            ),
            "bus_factory": lambda uid, deadline: bus,
            "process_start": mock.Mock(side_effect=FileNotFoundError("exited")),
            "process_scan": lambda targets, unit, before: (
                self.scanned.append((dict(targets), unit, before))
                or {
                    "processes": 1,
                    "same_uid": 1,
                    "unreadable_before_owner": 0,
                    "matches": [],
                }
            ),
            "cgroup_scan": lambda unit, uid: self.cgroups.append((unit, uid)) or [],
            "namespaces": lambda names: dict(
                self.owner.value["root_plan"]["host_namespaces"]
            ),
        }
        defaults.update(options)
        return host.resolve_failed_startup(self.spec.run_id, self.runtime, **defaults)

    def gate_state(self):
        rows = {}
        for path in sorted(self.gate_path.rglob("*")):
            info = path.lstat()
            data = path.read_bytes() if stat_is_file(info) else b""
            rows[str(path.relative_to(self.gate_path))] = (
                info.st_ino,
                info.st_mode,
                hashlib.sha256(data).hexdigest(),
            )
        return rows

    def assert_refused(self, bus, pattern, errors=(ValueError,), **options):
        before = self.gate_state()
        with self.assertRaisesRegex(errors, pattern):
            self.resolve(bus, commit=True, **options)
        self.assertEqual(self.gate_state(), before)

    def test_resolver_clears_a_proven_failed_attempt_with_non_accepting_evidence(self):
        bus, mark = self.retained_failure()
        blocker = (self.gate_path / "active.json").read_bytes()
        before = self.gate_state()
        dry = self.resolve(bus)
        self.assertEqual((dry.committed, dry.admission_state), (False, "present"))
        self.assertEqual(self.gate_state(), before)
        result = self.resolve(bus, commit=True)
        self.assertEqual((result.committed, result.admission_state), (True, "absent"))
        after = self.gate_state()
        name = f"resolved-{self.spec.run_id}.json"
        self.assertEqual(set(before) - set(after), {"active.json"})
        self.assertEqual(set(after) - set(before), {name})
        self.assertTrue(all(after[key] == before[key] for key in after if key != name))
        self.assertFalse(list(self.gate_path.glob("terminal-*")))
        path = self.gate_path / name
        self.assertEqual(path.read_bytes(), result.record)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(hashlib.sha256(result.record).hexdigest(), result.sha256)
        record = json.loads(result.record)
        self.assertEqual(self.root.closure.canonical(record), result.record)
        self.assertEqual(hashlib.sha256(dry.record).hexdigest(), dry.sha256)
        first = json.loads(dry.record)
        first.pop("observed_monotonic_ns")
        self.assertEqual(
            first, {k: v for k, v in record.items() if k != "observed_monotonic_ns"}
        )
        run = self.spec.run_id
        attempt = self.gate_path / f"attempt-{run}"
        failure = self.gate_path / f"failed-{run}.json"
        intent = (attempt / "host-intent.json").read_bytes()
        identity = before["active.json"][0]
        self.assertEqual(
            record["blocker"],
            {
                "sha256": hashlib.sha256(blocker).hexdigest(),
                "size": len(blocker),
                "device": self.gate_path.stat().st_dev,
                "inode": identity,
                "hex": blocker.hex(),
            },
        )
        self.assertEqual(
            record["failure_record"]["sha256"],
            hashlib.sha256(failure.read_bytes()).hexdigest(),
        )
        self.assertEqual(record["intent_sha256"], hashlib.sha256(intent).hexdigest())
        self.assertEqual(record["config_sha256"], self.owner.config.sha256)
        self.assertEqual(
            (record["attempt"]["device"], record["attempt"]["inode"]),
            (attempt.stat().st_dev, attempt.stat().st_ino),
        )
        unit = self.owner.adapter.name
        self.assertEqual(self.cgroups, [(unit, os.getuid())] * 2)
        plan = self.owner.value["root_plan"]

        def key(path):
            info = path.lstat()
            return info.st_dev, info.st_ino

        expected = {
            key(self.gate_path): "admission-directory",
            key(self.gate_path / "admission.lock"): "admission.lock",
            (self.gate_path.stat().st_dev, identity): "active.json",
            key(failure): failure.name,
            key(attempt): attempt.name,
            (plan["root"]["device"], plan["root"]["inode"]): "native-root",
            key(Path(plan["root"]["path"] + plan["launcher"]["path"])): "launcher",
        }
        for name in ("control.sock", "guardian-config.json", "host-intent.json"):
            expected[key(attempt / name)] = f"{attempt.name}/{name}"
        self.assertEqual(
            self.scanned,
            [(expected, unit, self.owner.value["client"]["starttime"])] * 2,
        )
        self.assertEqual(
            {key: record[key] for key in ("scope", "run_id", "outcome")},
            {
                "scope": "contained-job-rooted-failed-attempt-resolution-v1",
                "run_id": self.spec.run_id,
                "outcome": "failed-attempt-resolved",
            },
        )
        for flag in (
            "accepted",
            "startup_complete",
            "native_authorized",
            "full_contract_proven",
        ):
            self.assertIs(record[flag], False)
        self.assertEqual(record["blocker"]["hex"], blocker.hex())
        self.assertEqual(record["invocation"]["id"], "d" * 32)
        self.assertEqual(record["invocation"]["source"], "failure-record")
        self.assertEqual(record["invocation"]["manager_path"], self.FOREIGN)
        self.assertEqual(record["client"]["state"], "absent")
        self.assertEqual(
            (record["service"]["ActiveState"], record["service"]["Result"]),
            ("failed", "signal"),
        )
        self.assertEqual(
            [entry[0] for entry in record["attempt"]["entries"]],
            ["control.sock", "guardian-config.json", "host-intent.json"],
        )
        self.assertEqual(
            record["failure_record"]["scope"], "contained-job-rooted-host-failure-v2"
        )
        methods = {call[2] for call in bus.calls[mark:]}
        self.assertLessEqual(methods, set(host.ReadOnlyBus.METHODS))
        self.assertIn("GetUnitByInvocationID", methods)
        end = time.monotonic_ns() + 2_000_000_000
        gate = native.service.AdmissionGate(self.gate_path, end)
        try:
            gate.claim("run-02", b"next", end)
        finally:
            gate.close()

    def test_resolver_refuses_any_unit_not_proven_failed_and_released(self):
        bus, _ = self.retained_failure()
        value = self.owner.value
        tick = self.root.guardian.START_TICK_NS
        other = bus.variant("ay", tuple(bytes.fromhex("e" * 32)))
        cases = {
            "active": {
                "unit": {"ActiveState": ("s", "active"), "SubState": ("s", "running")}
            },
            "inactive": {
                "unit": {"ActiveState": ("s", "inactive"), "SubState": ("s", "dead")}
            },
            "other-invocation": {"unit": {"InvocationID": other}},
            "not-transient": {"unit": {"Transient": ("b", False)}},
            "other-id": {"unit": {"Id": ("s", "irlume-job-guardian-other.service")}},
            "queued-job": {
                "unit": {"Job": ("(uo)", (7, "/org/freedesktop/systemd1/job/7"))}
            },
            "referenced": {"unit": {"Refs": ("as", [":1.42"])}},
            "main-pid": {"service": {"MainPID": ("u", 77)}},
            "cgroup": {"service": {"ControlGroup": ("s", "/app.slice/x.service")}},
            "restart": {"service": {"Restart": ("s", "on-failure")}},
            "exec-start": {
                "service": {
                    "ExecStart": (
                        "a(sasbttttuii)",
                        [["/x", ["/x"], False, 0, 0, 0, 0, 0, 0, 0]],
                    )
                }
            },
            "early-start": {
                "pattern": "start window",
                "service": {
                    "ExecMainStartTimestampMonotonic": (
                        "t",
                        (value["origin_ns"] - tick) // 1000 - 1,
                    )
                },
            },
            "late-start": {
                "pattern": "start window",
                "service": {
                    "ExecMainStartTimestampMonotonic": (
                        "t",
                        value["startup_deadline_ns"] // 1000 + 1,
                    ),
                    "ExecMainExitTimestampMonotonic": (
                        "t",
                        value["startup_deadline_ns"] // 1000 + 2,
                    ),
                },
            },
            "no-exit": {
                "pattern": "exit order",
                "service": {"ExecMainExitTimestampMonotonic": ("t", 0)},
            },
            "exec-main-pid": {"service": {"ExecMainPID": ("u", 77)}},
            "processes": {"leftover": [["/app.slice/x", 77, "/x"]]},
            "foreign-binding": {"foreign": dict(bus.after, Id=("s", "other.service"))},
            "no-binding": {"by_invocation": RuntimeError("NoSuchUnit")},
            "no-unit": {"get_unit": RuntimeError("NoSuchUnit")},
        }
        saved = copy.deepcopy((bus.unit, bus.service))
        for label, change in cases.items():
            bus.unit.update(change.get("unit", {}))
            bus.after = dict(bus.unit)
            bus.service.update(change.get("service", {}))
            for key in ("leftover", "by_invocation", "get_unit", "foreign"):
                if key in change:
                    setattr(bus, key, change[key])
            with self.subTest(label):
                self.assert_refused(
                    bus, change.get("pattern", ""), (ValueError, RuntimeError)
                )
            bus.unit, bus.service = copy.deepcopy(saved)
            bus.after = dict(bus.unit)
            bus.leftover, bus.by_invocation, bus.get_unit = [], self.FOREIGN, None
            if hasattr(bus, "foreign"):
                del bus.foreign
        del bus.service["ExecMainPID"]
        self.assert_refused(bus, "variant")
        bus.service = copy.deepcopy(saved[1])
        self.assertTrue(self.resolve(bus).sha256)

    def test_resolver_start_window_allows_one_proc_clock_tick(self):
        # PrivatePIDs= start timestamps are whole 10 ms ticks, never later.
        # G's binding window uses the same constant, so H keeps no copy.
        tick = self.root.guardian.START_TICK_NS
        self.assertEqual(tick, 10_000_000)
        self.assertFalse(hasattr(host, "START_TICK_NS"))
        bus, _ = self.retained_failure()
        value = self.owner.value
        edge = -(-(value["origin_ns"] - tick) // 1000)
        self.assertGreaterEqual(edge * 1000, value["origin_ns"] - tick)
        self.assertLess((edge - 1) * 1000, value["origin_ns"] - tick)
        saved = copy.deepcopy(bus.service)
        bus.service["ExecMainStartTimestampMonotonic"] = ("t", edge - 1)
        self.assert_refused(bus, "start window")
        bus.service = copy.deepcopy(saved)
        bus.service["ExecMainStartTimestampMonotonic"] = ("t", edge)
        self.assertTrue(self.resolve(bus, commit=True).committed)

    def test_resolver_refuses_changed_or_inconsistent_attempt_files(self):
        bus, _ = self.retained_failure()
        run = self.spec.run_id
        gate, attempt = self.gate_path, self.gate_path / f"attempt-{run}"
        failure = gate / f"failed-{run}.json"
        original = failure.read_bytes()

        def rewrite(path, data, mode):
            path.chmod(0o600)
            path.write_bytes(data)
            path.chmod(mode)

        def record(**changes):
            value = dict(json.loads(original), **changes)
            return lambda: rewrite(failure, self.root.closure.canonical(value), 0o600)

        def edit(path, mode):
            data = path.read_bytes()
            return lambda: rewrite(path, data + b" ", mode), lambda: rewrite(
                path, data, mode
            )

        def swap_attempt():
            os.rename(attempt, gate / "kept")
            attempt.mkdir(0o700)
            for item in (gate / "kept").iterdir():
                if item.is_file():
                    (attempt / item.name).write_bytes(item.read_bytes())
                    (attempt / item.name).chmod(0o400)

        def unswap_attempt():
            for item in attempt.iterdir():
                item.unlink()
            attempt.rmdir()
            os.rename(gate / "kept", attempt)

        restore_failure = lambda: rewrite(failure, original, 0o600)
        cases = {
            "intent": edit(attempt / "host-intent.json", 0o400),
            "config": edit(attempt / "guardian-config.json", 0o400),
            "intent-mode": (
                lambda: (attempt / "host-intent.json").chmod(0o600),
                lambda: (attempt / "host-intent.json").chmod(0o400),
            ),
            "unknown-entry": (
                lambda: (
                    (attempt / "extra").write_bytes(b"x"),
                    (attempt / "extra").chmod(0o600),
                ),
                lambda: (attempt / "extra").unlink(),
            ),
            "replaced-attempt": (swap_attempt, unswap_attempt),
            "failure-flag": (record(native_authorized=True), restore_failure),
            "failure-uncertain": (record(created=False), restore_failure),
            "failure-extra-key": (record(extra=1), restore_failure),
            "failure-hardlink": (
                lambda: os.link(failure, gate / "failure-link"),
                lambda: (gate / "failure-link").unlink(),
            ),
            "failure-state": (record(admission_state="absent"), restore_failure),
            "failure-run": (record(run_id="other"), restore_failure),
            "failure-not-canonical": (
                lambda: rewrite(failure, original + b"\n", 0o600),
                restore_failure,
            ),
            "failure-other-boot": (
                record(boot_id="0" * 8 + "-0000-0000-0000-" + "0" * 12),
                restore_failure,
            ),
            "failure-missing": (
                lambda: os.rename(failure, gate / "kept-failure"),
                lambda: os.rename(gate / "kept-failure", failure),
            ),
            "failure-symlink": (
                lambda: (
                    os.rename(failure, gate / "kept-failure"),
                    failure.symlink_to("kept-failure"),
                ),
                lambda: (failure.unlink(), os.rename(gate / "kept-failure", failure)),
            ),
            "terminal-exists": (
                lambda: (gate / f"terminal-{run}.json").write_bytes(b"x"),
                lambda: (gate / f"terminal-{run}.json").unlink(),
            ),
            "resolved-exists": (
                lambda: (gate / f"resolved-{run}.json").write_bytes(b"x"),
                lambda: (gate / f"resolved-{run}.json").unlink(),
            ),
        }
        for label, (apply, undo) in cases.items():
            apply()
            with self.subTest(label):
                self.assert_refused(bus, "", (ValueError, OSError))
                before = self.gate_state()
                with self.assertRaises((ValueError, OSError)):
                    self.resolve(bus)
                self.assertEqual(self.gate_state(), before)
            undo()
        self.assertTrue(self.resolve(bus).sha256)

    def test_resolver_accepts_v2_records_whose_rows_saw_no_main_process(self):
        bus, _ = self.retained_failure()
        failure = self.gate_path / f"failed-{self.spec.run_id}.json"
        value = json.loads(failure.read_bytes())
        for source, observed in (
            ("observation", dict(value["observed"], MainPID=0)),
            ("cleanup", None),
        ):
            failure.write_bytes(
                self.root.closure.canonical(
                    dict(value, observed=observed, invocation_source=source)
                )
            )
            with self.subTest(source):
                self.assertTrue(self.resolve(bus).sha256)
        failure.write_bytes(
            self.root.closure.canonical(
                dict(value, observed=dict(value["observed"], MainPID=77))
            )
        )
        self.assert_refused(bus, "main process")

    def test_resolver_runs_only_in_the_attempt_owners_namespaces(self):
        bus, _ = self.retained_failure()
        plan = self.owner.value["root_plan"]["host_namespaces"]
        self.assert_refused(
            bus,
            "namespaces",
            namespaces=lambda names: dict(plan, pid=plan["pid"] + 1),
        )
        self.assertEqual(
            host.own_namespaces(("pid",)),
            {"pid": os.stat("/proc/self/ns/pid").st_ino},
        )

    def test_resolver_refuses_while_any_ownership_is_unresolved(self):
        bus, _ = self.retained_failure()
        host.UNRESOLVED["other-run"] = object()
        try:
            self.assert_refused(bus, "unowned")
        finally:
            host.UNRESOLVED.pop("other-run")
        self.assertTrue(self.resolve(bus).sha256)

    def test_read_only_bus_refuses_every_state_changing_method(self):
        bus = mock.Mock()
        reader = host.ReadOnlyBus(bus)
        for method in ("StartUnit", "StopUnit", "KillUnit", "ResetFailedUnit", "Unref"):
            with self.subTest(method), self.assertRaisesRegex(ValueError, "bus method"):
                reader.call("/org/freedesktop/systemd1", "x", method, "s", ("u",), 1)
        bus.call.assert_not_called()
        reader.call("/p", "i", "GetUnit", "s", ("u",), 1)
        bus.call.assert_called_once_with("/p", "i", "GetUnit", "s", ("u",), 1)

    def test_resolver_refuses_a_held_lock_or_a_live_attempt_owner(self):
        bus, _ = self.retained_failure()
        end = time.monotonic_ns() + 2_000_000_000
        holder = native.service.AdmissionGate(self.gate_path, end)
        try:
            self.assert_refused(bus, "", (BlockingIOError,))
        finally:
            holder.close()
        self.assert_refused(bus, "owner is alive", process_start=None)
        self.assert_refused(
            bus,
            "process start",
            process_start=mock.Mock(side_effect=ValueError("process start identity")),
        )
        starttime = self.owner.value["client"]["starttime"]
        reused = self.resolve(bus, process_start=lambda pid: starttime + 1)
        self.assertEqual(json.loads(reused.record)["client"]["state"], "reused")

    def test_resolver_refuses_remaining_cgroups_processes_or_a_late_change(self):
        bus, _ = self.retained_failure()
        self.assert_refused(
            bus, "cgroup", cgroup_scan=lambda unit, uid: ["app.slice/" + unit]
        )
        self.assert_refused(
            bus,
            "attempt processes",
            process_scan=lambda targets, unit, before: {
                "matches": [{"pid": 7, "via": ["fd"]}]
            },
        )

        def changing(targets, unit, before):
            bus.service["MainPID"] = ("u", 99)
            return {"matches": []}

        self.assert_refused(bus, "changed during resolution", process_scan=changing)

    def test_resolver_binds_v1_records_only_to_manager_confirmed_caller_evidence(self):
        bus, _ = self.retained_failure()
        failure = self.gate_path / f"failed-{self.spec.run_id}.json"
        value = json.loads(failure.read_bytes())
        v1 = {key: value[key] for key in host.FAILURE_V1}
        self.assert_refused(bus, "v2 failure record", invocation_id="d" * 32)
        failure.write_bytes(
            self.root.closure.canonical(
                dict(v1, scope="contained-job-rooted-host-failure-v1")
            )
        )
        self.assert_refused(bus, "caller invocation evidence")
        self.assert_refused(bus, "InvocationID", invocation_id="e" * 32)
        self.assert_refused(bus, "invocation ID", invocation_id="0" * 32)
        result = self.resolve(bus, invocation_id="d" * 32)
        self.assertEqual(
            json.loads(result.record)["invocation"]["source"], "caller-evidence"
        )

    def test_resolver_keeps_the_blocker_when_persistence_fails(self):
        bus, _ = self.retained_failure()
        name = f"resolved-{self.spec.run_id}.json"
        with mock.patch.object(
            native.service.AdmissionGate, "write", side_effect=OSError("full")
        ):
            self.assert_refused(bus, "", (OSError,))
        with (
            mock.patch.object(native.service.os, "unlink", side_effect=OSError("busy")),
            self.assertRaises(OSError),
        ):
            self.resolve(bus, commit=True)
        self.assertTrue((self.gate_path / "active.json").is_file())
        self.assertTrue((self.gate_path / name).is_file())
        with self.assertRaises(FileExistsError):
            self.resolve(bus, commit=True)

    def test_resolver_deadline_keeps_the_blocker_at_every_check(self):
        bus, _ = self.retained_failure()
        calls = []

        def counting():
            calls.append(None)
            return time.monotonic_ns()

        self.resolve(bus, now=counting)
        before = self.gate_state()
        for jump in range(2, len(calls)):
            seen = []

            def late(jump=jump, seen=seen):
                seen.append(None)
                extra = host.RESOLVE_NS if len(seen) >= jump else 0
                return time.monotonic_ns() + extra

            with self.subTest(jump=jump), self.assertRaises(TimeoutError):
                self.resolve(bus, commit=True, now=late)
            self.assertEqual(self.gate_state(), before)

    def test_successful_gate_close_crossing_completion_deadline_refuses(self):
        _, record = self.terminal_owner()
        clock = [time.monotonic_ns()]
        deadline = self.owner.value["startup_deadline_ns"] + self.root.guardian.STOP_NS
        close = self.owner.gate.close

        def late_close():
            close()
            clock[0] = deadline

        with (
            mock.patch.object(self.owner.gate, "close", side_effect=late_close),
            mock.patch.object(self.owner, "now", side_effect=lambda: clock[0]),
            self.assertRaises(TimeoutError),
        ):
            self.owner.complete(record)
        self.assertEqual(self.owner.commit_state, "absent")
        self.assertFalse((self.gate_path / "active.json").exists())
        self.assertIsNone(self.owner.gate.lock_fd)

    def test_run_uses_real_host_controller_with_closed_artifact_and_stub_decoder(self):
        messages, buses, options = [], [], []
        real_listener = host.socket.socket(host.socket.AF_UNIX, host.socket.SOCK_STREAM)
        self.addCleanup(real_listener.close)
        channel, listener = mock.Mock(), mock.Mock(wraps=real_listener)
        listener.accept.return_value = (mock.Mock(), None)
        channel.peer_fd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, channel.peer_fd)

        def bus_factory(*args, **kwargs):
            options.append(kwargs["fds"])
            bus = self.make_bus(install=False)
            buses.append(bus)
            return bus

        self.owner.bus_factory = bus_factory

        def make_channel(connected, peer):
            self.assertEqual(peer, (self.owner.identity.pid, os.getuid(), os.getgid()))
            data = b"{}"
            reference = self.runtime.artifact.write_closed(
                self.owner.directory,
                self.owner.directory_identity,
                data,
                hashlib.sha256(data).hexdigest(),
                self.owner.value["startup_deadline_ns"],
            )
            deps = self.runtime.protocol.Dependencies(self.root, self.runtime.artifact)
            messages.extend(
                [
                    self.runtime.protocol.ready(
                        self.owner.config,
                        self.owner.identity,
                        reference,
                        self.owner.inputs.manifest,
                        deps,
                    ),
                    self.runtime.protocol.done(
                        self.owner.config,
                        self.owner.identity,
                        reference,
                        self.owner.inputs.manifest,
                        deps,
                    ),
                ]
            )
            return channel

        channel.receive.side_effect = lambda *args, **kwargs: messages.pop(0)

        def terminal(*args):
            bus = buses[0]
            bus.service.update(
                MainPID=("u", 0),
                ExecMainCode=("i", 1),
                ExecMainStatus=("i", 0),
                ExecMainExitTimestampMonotonic=("t", time.monotonic_ns() // 1000),
            )
            bus.unit.update(ActiveState=("s", "inactive"), SubState=("s", "dead"))
            bus.after = dict(bus.unit)

        channel.expect_eof.side_effect = terminal

        def decode(data, *args, **kwargs):
            self.assertEqual(data, b"{}")
            return {"started_ns": self.owner.value["origin_ns"]}

        with (
            mock.patch.object(host.socket, "socket", return_value=listener),
            mock.patch.object(
                self.root.guardian, "PeerChannel", side_effect=make_channel
            ),
            mock.patch.object(native, "process_start", return_value=100),
            mock.patch.object(
                self.runtime.witness, "decode", side_effect=decode
            ) as decoder,
            mock.patch.object(
                native, "ChildOwner", side_effect=AssertionError("legacy child path")
            ),
        ):
            result = self.owner.run()
        self.assertEqual(result["outcome"], "startup-only-complete")
        self.assertIs(result["native_authorized"], False)
        self.assertIs(result["full_contract_proven"], False)
        decoder.assert_called_once()
        # H re-verifies G's rows with its own runtime's page digests.
        pages = decoder.call_args.kwargs["pages"]
        self.assertIs(pages, self.owner.inputs.runtime.pages)
        self.assertIs(type(pages), types.MappingProxyType)
        self.assertIn("/usr/bin/python3", pages)
        self.assertEqual(options, [True])
        # Connect, its recheck and the recheck before COMMIT bind the peer.
        self.assertEqual(
            [call[4] for call in buses[0].calls if call[2] == "GetUnitByPIDFD"],
            [(channel.peer_fd,)] * 3,
        )
        self.assertFalse((self.gate_path / "active.json").exists())
        self.assertTrue((self.gate_path / "terminal-run-01.json").is_file())
        self.assertEqual(set(self.owner.phases), {"prestart", "postservice"})
        self.assertTrue(
            all(value.fd is None for value in self.owner.inputs.files.values())
        )

    def test_run_preparation_failure_closes_partial_owners(self):
        self.owner.selection = self.selection._replace(payload_sha256="0" * 64)
        before = set(os.listdir("/proc/self/fd"))
        with self.assertRaises(ValueError):
            self.owner.run()
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        self.owner.bus_factory.assert_not_called()

    def test_run_creation_uncertainty_blocks_a_subsequent_attempt(self):
        buses = []

        def factory(*args, **kwargs):
            bus = self.make_bus(install=False)
            bus.late = "StartTransientUnit"
            buses.append(bus)
            return bus

        self.owner.bus_factory = factory
        with self.assertRaises(TimeoutError):
            self.owner.run()
        self.assertIs(host.UNRESOLVED[self.spec.run_id], self.owner)
        self.assertTrue((self.gate_path / "active.json").exists())
        self.assertIsNotNone(self.owner.gate.lock_fd)
        buses[0].close.assert_not_called()
        another = host.HostOwner(
            self.selection,
            self.support,
            gate_factory=mock.Mock(side_effect=AssertionError("must not reacquire")),
        )
        with self.assertRaises(ValueError):
            another.run()

    def assert_finalize_close_failure(self, target):
        _, record = self.terminal_owner()
        close = getattr(self.owner, target)

        def fail_after_close():
            close()
            raise OSError(target)

        with (
            mock.patch.object(self.owner, target, side_effect=fail_after_close),
            mock.patch.object(
                self.owner.gate,
                "complete",
                side_effect=AssertionError("premature commit"),
            ),
            self.assertRaises(OSError),
        ):
            self.owner.complete(record)
        self.assertTrue((self.gate_path / "active.json").is_file())
        self.assertIsNotNone(self.owner.gate.lock_fd)
        self.assertIsNone(self.owner.inputs.runtime.fd)

    def test_control_close_failure_blocks_commit(self):
        self.assert_finalize_close_failure("close_control")

    def test_directory_close_failure_blocks_commit(self):
        self.assert_finalize_close_failure("close_directory")

    def test_reference_release_failure_blocks_commit(self):
        bus, record = self.terminal_owner()
        bus.close.side_effect = OSError("reference release")
        with (
            mock.patch.object(
                self.owner.gate,
                "complete",
                side_effect=AssertionError("premature commit"),
            ),
            self.assertRaises(OSError),
        ):
            self.owner.complete(record)
        self.assertTrue((self.gate_path / "active.json").is_file())
        self.assertTrue(self.owner.lease.unresolved)
        self.assertIsNone(self.owner.inputs.runtime.fd)

    def test_completion_close_expiry_blocks_commit(self):
        _, record = self.terminal_owner()
        close = self.owner.inputs.close
        deadline = self.owner.value["startup_deadline_ns"] + self.root.guardian.STOP_NS
        clock = [time.monotonic_ns()]

        def expire_after_close():
            close()
            clock[0] = deadline

        with (
            mock.patch.object(
                self.owner.inputs, "close", side_effect=expire_after_close
            ),
            mock.patch.object(self.owner, "now", side_effect=lambda: clock[0]),
            mock.patch.object(
                self.owner.gate, "complete", side_effect=AssertionError("late commit")
            ),
            self.assertRaises(TimeoutError),
        ):
            self.owner.complete(record)
        self.assertTrue((self.gate_path / "active.json").is_file())

    def test_postservice_mutation_blocks_commit(self):
        _, record = self.terminal_owner()
        self.files["payload"].chmod(0o600)
        self.files["payload"].write_bytes(b"changed bytes")
        self.files["payload"].chmod(0o400)
        with (
            mock.patch.object(
                self.owner.gate,
                "complete",
                side_effect=AssertionError("changed-input commit"),
            ),
            self.assertRaises(ValueError),
        ):
            self.owner.complete(record)
        self.assertTrue((self.gate_path / "active.json").is_file())

    def test_near_limit_preparation_keeps_fresh_startup_and_completion_phases(self):
        clock = [1_000_000_000]
        preparation_end = clock[0] + host.PREPARE_NS
        calls = []

        def observe(deadline):
            calls.append(deadline)
            if len(calls) == 1:
                clock[0] = preparation_end - 1
            return self.coordinates

        self.owner.host_observer = observe
        with mock.patch.object(time, "monotonic_ns", side_effect=lambda: clock[0]):
            self.owner.acquire(preparation_end)
            self.assertEqual(self.owner.value["origin_ns"], preparation_end - 1)
            deadline = self.owner.value["startup_deadline_ns"]
            self.owner.prepare(self.owner.config, self.owner.inputs.manifest, deadline)
            clock[0] = preparation_end + 1
            self.make_bus()
            identity = self.owner.start(self.owner.config, deadline)
            self.owner.lease.terminal = True
            record = {
                "scope": "contained-job-rooted-startup-result-v1",
                "role": "H",
                "config_sha256": self.owner.config.sha256,
                "startup_sha256": "a" * 64,
                "service": identity._asdict(),
                "outcome": "startup-only-complete",
                "accepted": False,
                "native_authorized": False,
                "full_contract_proven": False,
            }
            self.owner.finish(self.root.closure.canonical(record), deadline)
            clock[0] = deadline - 1
            self.owner.complete(record)
        self.assertEqual(
            calls, [preparation_end, deadline, deadline + self.root.guardian.STOP_NS]
        )
        self.assertGreater(self.owner.phases["prestart"]["started_ns"], preparation_end)
        self.assertEqual(self.owner.inputs.deadline, preparation_end)
        self.assertEqual(self.owner.inputs.runtime.deadline, preparation_end)

    def test_partial_receipt_writes_are_completed_before_close(self):
        self.acquire()
        write = os.write
        with mock.patch.object(
            host.os, "write", side_effect=lambda fd, data: write(fd, data[:1])
        ):
            self.owner.write(
                "host-started",
                b"complete bytes",
                self.owner.value["startup_deadline_ns"],
            )
        self.assertEqual(
            (self.owner.path / "host-started.json").read_bytes(), b"complete bytes"
        )
        self.assertEqual(self.owner.output_bytes, len(b"complete bytes"))

    def test_receipt_write_and_close_failures_are_preserved(self):
        self.acquire()
        opening, closing, target = os.open, os.close, []

        def open_receipt(path, *args, **kwargs):
            fd = opening(path, *args, **kwargs)
            if path == "host-started.json":
                target.append(fd)
            return fd

        def close_receipt(fd):
            closing(fd)
            if fd in target:
                target.remove(fd)
                raise OSError("receipt close failure")

        before = set(os.listdir("/proc/self/fd"))
        with (
            mock.patch.object(host.os, "open", side_effect=open_receipt),
            mock.patch.object(host.os, "close", side_effect=close_receipt),
            mock.patch.object(
                host.os, "write", side_effect=ValueError("receipt write failure")
            ),
            self.assertRaises(BaseExceptionGroup) as caught,
        ):
            self.owner.write(
                "host-started", b"content", self.owner.value["startup_deadline_ns"]
            )
        self.assertEqual(
            [str(error) for error in caught.exception.exceptions],
            ["receipt write failure", "receipt close failure"],
        )
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_receipt_sync_failure_keeps_gate_and_closes_receipt(self):
        self.acquire()
        before = set(os.listdir("/proc/self/fd"))
        with (
            mock.patch.object(
                host.os, "fsync", side_effect=OSError("receipt sync failure")
            ),
            self.assertRaises(OSError),
        ):
            self.owner.write(
                "host-started", b"content", self.owner.value["startup_deadline_ns"]
            )
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        self.assertIsNotNone(self.owner.gate.lock_fd)

    def test_receipt_budget_accepts_boundary_but_refuses_another_byte(self):
        self.acquire()
        budget = self.root.guardian.HOST_RECEIPT_BUDGET
        self.owner.write(
            "host-started", b"x" * budget, self.owner.value["startup_deadline_ns"]
        )
        with self.assertRaisesRegex(ValueError, "receipt budget"):
            self.owner.write(
                "host-finished", b"x", self.owner.value["startup_deadline_ns"]
            )
        self.assertFalse((self.owner.path / "host-finished.json").exists())

    def test_hex_expanded_intent_and_diagnostic_reserve_precede_claim(self):
        self.acquire()
        self.owner.output_bytes = self.root.guardian.HOST_RECEIPT_BUDGET - 48 * 1024
        with (
            mock.patch.object(
                self.owner.gate,
                "claim",
                side_effect=AssertionError("claim before budget check"),
            ),
            self.assertRaisesRegex(ValueError, "diagnostic reserve"),
        ):
            self.owner.prepare(
                self.owner.config,
                self.owner.inputs.manifest,
                self.owner.value["startup_deadline_ns"],
            )
        self.assertIsNone(self.owner.gate.record)
        self.assertFalse((self.gate_path / "active.json").exists())

    def test_hex_expansion_alone_crosses_setup_allowance(self):
        self.acquire()
        intent = self.root.closure.canonical(
            {
                "scope": "contained-job-rooted-host-intent-v1",
                "config_sha256": self.owner.config.sha256,
                "run_id": self.owner.spec.run_id,
                "unit": self.root.guardian.unit_name(self.owner.spec),
                "path": str(self.owner.path),
                "client": self.owner.value["client"],
            }
        )
        allowance = self.root.guardian.HOST_RECEIPT_BUDGET - 48 * 1024
        self.owner.output_bytes = (
            allowance - len(self.owner.config.data) - 2 * len(intent) - 512
        )
        self.assertGreater(self.owner.output_bytes, 0)
        with (
            mock.patch.object(
                self.owner.gate,
                "claim",
                side_effect=AssertionError("omitted hex expansion"),
            ),
            self.assertRaisesRegex(ValueError, "diagnostic reserve"),
        ):
            self.owner.prepare(
                self.owner.config,
                self.owner.inputs.manifest,
                self.owner.value["startup_deadline_ns"],
            )
        self.assertLessEqual(self.owner.output_bytes + 512, allowance)
        self.assertGreater(self.owner.output_bytes + 2 * len(intent) + 512, allowance)
        self.assertFalse(self.owner.claim_attempted)


if __name__ == "__main__":
    unittest.main()
