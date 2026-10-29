#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Concrete H tests with fake manager/peer endpoints; no service or VM."""

import hashlib
import importlib.util
import json
import os
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
        self.adapter = host.LeaseBus(
            self.config, fixture.manifest, self.support, self.bus
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
        row = self.adapter.observe(self.adapter.name, 5_001_000_000)
        self.assertEqual(row["Id"], self.adapter.name)
        self.assertIn("RootDirectory", self.adapter.last_root)

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
                self.config, self.fixture.manifest, self.support, self.bus
            )
            self.bus.observe = mock.Mock(return_value=dict(unit, **wrong))
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                adapter.pin_cleanup(10_000_000_000)
            self.assertIsNone(adapter.cleanup_binding)


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
            "bus": fixture.bus,
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
        messages, buses = [], []
        real_listener = host.socket.socket(host.socket.AF_UNIX, host.socket.SOCK_STREAM)
        self.addCleanup(real_listener.close)
        channel, listener = mock.Mock(), mock.Mock(wraps=real_listener)
        listener.accept.return_value = (mock.Mock(), None)

        def bus_factory(*args, **kwargs):
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
