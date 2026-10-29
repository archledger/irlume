#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Typed bus bridge tests. Fake calls never contact a manager or create a unit."""

import copy
import importlib.util
import os
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bridge = load("rooted_bus", "measurement-job-rooted-bus.py")
protocol_tests = load("bus_protocol_tests", "test-measurement-job-rooted-protocol.py")
transport = load("bus_transport", "measurement-job-guardian-service.py")


class FakeBus(transport.SystemdBus):
    def __init__(self, fixture):
        self.calls, self.time = [], 100
        self.late = None
        # Descriptor passing as negotiated by SystemdBus(fds=True).
        self.fds = True
        self.pidfd_pid = os.getpid()
        self.pidfd_unit = self.pidfd_invocation = None
        self.unit_reads = 0
        self.job = "/org/freedesktop/systemd1/job/123"
        self.path = "/org/freedesktop/systemd1/unit/test_2eservice"
        tests = protocol_tests.root_tests.guardian_tests
        snapshot = tests.service_snapshot(
            tests.guardian.Specification(**fixture.spec._asdict())
        )
        snapshot.update(
            ExecMainExitTimestampMonotonic=0,
            ExecMainCode=0,
            ExecMainStatus=0,
            Result="success",
            ExecStart=(("/launcher", ("/launcher",), False),),
        )
        self.unit = {
            name: self.variant(
                kind,
                tuple(bytes.fromhex(snapshot[name]))
                if name == "InvocationID"
                else snapshot[name],
            )
            for name, kind in transport.UNIT_TYPES.items()
        }
        self.service = {}
        for name, kind in transport.PROPERTY_TYPES.items():
            value = snapshot[name]
            if kind == "commands":
                value = [
                    [row[0], list(row[1]), row[2], 0, 0, 0, 0, 0, 0, 0] for row in value
                ]
                self.service[name] = ("a(sasbttttuii)", value)
            else:
                self.service[name] = self.variant(kind, value)
        self.service.update(dict(fixture.root.wire_properties(fixture.plan)))
        self.service.update(
            PrivateUsers=("b", True), ProtectControlGroupsEx=("s", "yes")
        )
        self.after = copy.deepcopy(self.unit)

    def remaining(self, deadline):
        if self.time >= deadline:
            raise TimeoutError("fake deadline")
        return 1

    def call(self, path, interface, method, signature, args, deadline, **options):
        self.calls.append((path, interface, method, signature, args, deadline))
        if self.late == method:
            self.time = deadline
        if method == "StartTransientUnit":
            return self.job
        if method == "GetUnitByPIDFD":
            if options != {"expected": "osay", "values": 3} or signature != "h":
                raise AssertionError("unexpected GetUnitByPIDFD shape")
            # Resolve the descriptor as the manager does: by the PID it names.
            with open(f"/proc/self/fdinfo/{args[0]}") as info:
                rows = [line.split()[1:] for line in info if line.startswith("Pid:")]
            if rows != [[str(self.pidfd_pid)]]:
                raise RuntimeError("user-bus error: NoUnitForPID")
            unit = self.pidfd_unit or self.unit["Id"][1]
            invocation = self.pidfd_invocation or bytes(self.unit["InvocationID"][1])
            return self.path, unit, invocation
        if method == "GetUnit":
            return self.path
        if method == "GetAll" and args[0].endswith(".Unit"):
            self.unit_reads += 1
            return copy.deepcopy(self.unit if self.unit_reads == 1 else self.after)
        if method == "GetAll":
            return copy.deepcopy(self.service)
        raise AssertionError("unexpected fake method")


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = protocol_tests.ProtocolTests(
            "test_canonical_config_preserves_host_coordinates_and_is_detached"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.bus = FakeBus(self.fixture)
        self.support = bridge.Dependencies(
            protocol_tests.protocol, self.fixture.deps, transport
        )
        self.bridge = bridge.RootedBus(self.bus, self.support)

    def test_start_derives_only_fixed_rooted_properties_and_static_argv(self):
        reply = self.bridge.start(self.fixture.config, self.fixture.manifest, 1000)
        self.assertEqual(reply, self.bus.job)
        call = self.bus.calls[-1]
        self.assertEqual(call[2:4], ("StartTransientUnit", "ssa(sv)a(sa(sv))"))
        name, mode, entries, aux = call[4]
        self.assertEqual(name, self.fixture.service.unit)
        self.assertEqual(mode, "fail")
        self.assertEqual(aux, [])
        props = dict(entries)
        self.assertEqual(props["AddRef"], ("b", True))
        self.assertEqual(
            props["RootDirectory"], ("s", self.fixture.plan["root"]["path"])
        )
        self.assertEqual(props["DeviceAllow"], ("a(ss)", []))
        argv = self.fixture.root.entry_argv(
            self.fixture.plan, self.fixture.config.sha256
        )
        self.assertEqual(
            props["ExecStart"], ("a(sasb)", [(argv[0], list(argv), False)])
        )
        plan = self.fixture.plan
        command = [
            plan["launcher"]["path"],
            "--guardian",
            "/run/irlume/attempt/guardian-config.json",
            self.fixture.config.sha256,
        ]
        expected = [
            ("AddRef", ("b", True)),
            ("Type", ("s", "exec")),
            ("ExitType", ("s", "main")),
            ("Restart", ("s", "no")),
            ("NotifyAccess", ("s", "none")),
            ("RemainAfterExit", ("b", False)),
            ("RuntimeMaxUSec", ("t", 300_000_000)),
            ("RuntimeRandomizedExtraUSec", ("t", 0)),
            ("TimeoutStartUSec", ("t", 5_000_000)),
            ("TimeoutStopUSec", ("t", 5_000_000)),
            ("KillMode", ("s", "control-group")),
            ("KillSignal", ("i", 9)),
            ("FinalKillSignal", ("i", 9)),
            ("SendSIGKILL", ("b", True)),
            ("NoNewPrivileges", ("b", True)),
            ("CPUQuotaPerSecUSec", ("t", 2_000_000)),
            ("CPUAffinity", ("ay", b"\x03")),
            ("MemoryMax", ("t", 3 * 1024**3)),
            ("MemorySwapMax", ("t", 0)),
            ("TasksMax", ("t", 64)),
            ("ExecStartPre", ("a(sasb)", [])),
            ("ExecStartPost", ("a(sasb)", [])),
            ("ExecStop", ("a(sasb)", [])),
            ("ExecStopPost", ("a(sasb)", [])),
            ("MountFlags", ("t", 262144)),
            ("RootDirectory", ("s", plan["root"]["path"])),
            ("PrivateUsersEx", ("s", "self")),
            ("PrivateMounts", ("b", True)),
            ("PrivateNetwork", ("b", True)),
            ("PrivateDevices", ("b", True)),
            ("PrivatePIDs", ("s", "yes")),
            ("ProcSubset", ("s", "pid")),
            ("ProtectProc", ("s", "invisible")),
            ("MountAPIVFS", ("b", True)),
            ("BindLogSockets", ("b", False)),
            ("ProtectSystem", ("s", "strict")),
            ("ProtectHome", ("s", "read-only")),
            ("ProtectKernelTunables", ("b", True)),
            ("ProtectKernelLogs", ("b", True)),
            ("KeyringMode", ("s", "private")),
            ("ProtectControlGroups", ("b", True)),
            ("RestrictNamespaces", ("t", 0)),
            ("CapabilityBoundingSet", ("t", 0)),
            ("AmbientCapabilities", ("t", 0)),
            ("DevicePolicy", ("s", "closed")),
            ("DeviceAllow", ("a(ss)", [])),
            (
                "BindPaths",
                (
                    "a(ssbt)",
                    [(plan["attempt"]["path"], "/run/irlume/attempt", False, 0)],
                ),
            ),
            (
                "BindReadOnlyPaths",
                (
                    "a(ssbt)",
                    [
                        (plan["base"]["path"], "/run/irlume/base.raw", False, 0),
                        (plan["payload"]["path"], "/run/irlume/payload.raw", False, 0),
                        (
                            plan["manifest"]["path"],
                            "/run/irlume/runtime-manifest.json",
                            False,
                            0,
                        ),
                    ],
                ),
            ),
            (
                "TemporaryFileSystem",
                (
                    "a(ss)",
                    [
                        ("/tmp", "rw,nosuid,nodev,noexec,size=16M,mode=1777"),
                        ("/run", "rw,nosuid,nodev,noexec,size=16M,mode=0755"),
                    ],
                ),
            ),
            (
                "InaccessiblePaths",
                (
                    "as",
                    [
                        "-+/dev/pts",
                        "-+/dev/ptmx",
                        "-+/dev/shm",
                        "-+/dev/mqueue",
                        "-+/dev/hugepages",
                        "-+/sys/fs/selinux",
                        "-+/run/credentials",
                        "-+/sys/firmware/efi/efivars",
                        "-+/sys/fs/bpf",
                        "-+/sys/fs/fuse/connections",
                        "-+/sys/fs/pstore",
                        "-+/sys/fs/smackfs",
                        "-+/sys/kernel/config",
                        "-+/sys/kernel/debug",
                        "-+/sys/kernel/security",
                        "-+/sys/kernel/tracing",
                    ],
                ),
            ),
            ("ExecStart", ("a(sasb)", [(command[0], command, False)])),
            ("WorkingDirectory", ("s", "/")),
            ("StandardInput", ("s", "null")),
            ("StandardOutput", ("s", "null")),
            ("StandardError", ("s", "null")),
        ]
        self.assertEqual(
            call,
            (
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "StartTransientUnit",
                "ssa(sv)a(sa(sv))",
                ("irlume-job-guardian-run-01.service", "fail", expected, []),
                1000,
            ),
        )
        with self.assertRaises(ValueError):
            self.bridge.start(self.fixture.config, self.fixture.manifest, 1000)

    def test_observe_reads_derived_root_properties_and_stable_unit_twice(self):
        result = self.bridge.observe(self.fixture.config, self.fixture.manifest, 1000)
        self.fixture.root.check_properties(result["root"], self.fixture.plan)
        self.assertEqual(result["service"]["InvocationID"], "d" * 32)
        self.assertEqual(result["root"]["PrivateUsers"], ("b", True))
        self.assertEqual(self.bus.unit_reads, 2)
        self.assertEqual(
            self.bus.calls,
            [
                (
                    "/org/freedesktop/systemd1",
                    "org.freedesktop.systemd1.Manager",
                    "GetUnit",
                    "s",
                    ("irlume-job-guardian-run-01.service",),
                    1000,
                ),
                (
                    self.bus.path,
                    "org.freedesktop.DBus.Properties",
                    "GetAll",
                    "s",
                    ("org.freedesktop.systemd1.Unit",),
                    1000,
                ),
                (
                    self.bus.path,
                    "org.freedesktop.DBus.Properties",
                    "GetAll",
                    "s",
                    ("org.freedesktop.systemd1.Service",),
                    1000,
                ),
                (
                    self.bus.path,
                    "org.freedesktop.DBus.Properties",
                    "GetAll",
                    "s",
                    ("org.freedesktop.systemd1.Unit",),
                    1000,
                ),
            ],
        )

    def test_invocation_change_preserves_both_partial_views_and_refuses(self):
        self.bus.after["InvocationID"] = ("ay", list(bytes.fromhex("f" * 32)))
        with self.assertRaises(ValueError):
            self.bridge.observe(self.fixture.config, self.fixture.manifest, 1000)
        self.assertNotEqual(
            self.bridge.partial["unit_before"]["InvocationID"],
            self.bridge.partial["unit_after"]["InvocationID"],
        )

    def test_missing_derived_property_and_wrong_signature_refuse(self):
        del self.bus.service["PrivateUsers"]
        with self.assertRaises(ValueError):
            self.bridge.observe(self.fixture.config, self.fixture.manifest, 1000)
        self.bus.service["PrivateUsers"] = ("s", "yes")
        with self.assertRaises(ValueError):
            self.bridge.observe(self.fixture.config, self.fixture.manifest, 1000)

    def test_observe_refuses_pid_kernel_view_and_namespace_profile_drift(self):
        saved = copy.deepcopy(self.bus.service)
        for name, value, message in (
            ("PrivatePIDs", ("s", "no"), "effective root property: PrivatePIDs"),
            ("ProcSubset", ("s", "all"), "effective root property: ProcSubset"),
            ("ProtectProc", ("s", "default"), "effective root property: ProtectProc"),
            ("ProcSubset", None, "missing rooted bus property: ProcSubset"),
            ("ProtectHome", ("s", "no"), "effective root property: ProtectHome"),
            (
                "RestrictNamespaces",
                ("t", 2**64 - 1),
                "effective root property: RestrictNamespaces",
            ),
            (
                "ProtectKernelLogs",
                None,
                "missing rooted bus property: ProtectKernelLogs",
            ),
            ("KeyringMode", ("s", "inherit"), "effective root property: KeyringMode"),
            ("KeyringMode", None, "missing rooted bus property: KeyringMode"),
        ):
            self.bus.service = copy.deepcopy(saved)
            if value is None:
                del self.bus.service[name]
            else:
                self.bus.service[name] = value
            with (
                self.subTest(name=name, value=value),
                self.assertRaisesRegex(ValueError, message),
            ):
                self.bridge.observe(self.fixture.config, self.fixture.manifest, 1000)

    def test_process_invocation_names_only_the_configured_unit(self):
        fd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, fd)
        invocation = self.bridge.process_invocation(
            self.fixture.config, self.fixture.manifest, fd, 1000
        )
        self.assertEqual(invocation, "d" * 32)
        call = self.bus.calls[-1]
        self.assertEqual(call[2:5], ("GetUnitByPIDFD", "h", (fd,)))
        self.assertEqual(
            self.bridge.partial["pidfd_unit"],
            (self.bus.path, self.fixture.service.unit, "d" * 32),
        )
        self.bus.pidfd_unit = "irlume-job-guardian-other.service"
        with self.assertRaisesRegex(ValueError, "rooted service process unit"):
            self.bridge.process_invocation(
                self.fixture.config, self.fixture.manifest, fd, 1000
            )
        self.assertEqual(
            self.bridge.partial["pidfd_unit"][1], "irlume-job-guardian-other.service"
        )
        self.bus.pidfd_unit, self.bus.pidfd_pid = None, os.getpid() + 1
        with self.assertRaisesRegex(RuntimeError, "NoUnitForPID"):
            self.bridge.process_invocation(
                self.fixture.config, self.fixture.manifest, fd, 1000
            )
        self.bus.pidfd_pid, self.bus.fds = os.getpid(), False
        calls = len(self.bus.calls)
        with self.assertRaisesRegex(ValueError, "descriptor passing"):
            self.bridge.process_invocation(
                self.fixture.config, self.fixture.manifest, fd, 1000
            )
        self.assertEqual(len(self.bus.calls), calls)
        self.bus.fds, self.bus.late = True, "GetUnitByPIDFD"
        with self.assertRaises(TimeoutError):
            self.bridge.process_invocation(
                self.fixture.config, self.fixture.manifest, fd, 1000
            )

    def test_late_start_retains_reply_and_creation_uncertainty(self):
        self.bus.late = "StartTransientUnit"
        with self.assertRaises(TimeoutError):
            self.bridge.start(self.fixture.config, self.fixture.manifest, 1000)
        self.assertEqual(self.bridge.start_reply, self.bus.job)
        self.assertTrue(self.bridge.creation_attempted)

    def test_later_caller_deadline_cannot_extend_configuration_window(self):
        value = protocol_tests.protocol.decode_config(
            self.fixture.config.data,
            self.fixture.config.sha256,
            self.fixture.manifest,
            self.fixture.deps,
        )
        deadline = value["startup_deadline_ns"]
        self.bus.time = deadline
        for name in ("start", "observe"):
            with self.subTest(name=name), self.assertRaises(TimeoutError):
                getattr(self.bridge, name)(
                    self.fixture.config, self.fixture.manifest, deadline + 5_000_000_000
                )
        self.assertEqual(len(self.bus.calls), 0)

    def test_bad_creation_reply_is_retained_and_cannot_be_retried(self):
        self.bus.job = "not-a-job-path"
        with self.assertRaises(ValueError):
            self.bridge.start(self.fixture.config, self.fixture.manifest, 1000)
        self.assertEqual(self.bridge.start_reply, "not-a-job-path")
        self.assertTrue(self.bridge.creation_attempted)
        with self.assertRaises(ValueError):
            self.bridge.start(self.fixture.config, self.fixture.manifest, 1000)
        self.assertEqual(len(self.bus.calls), 1)

    def test_unit_path_root_flags_and_dictionary_bounds_refuse(self):
        self.bus.path = "/foreign/unit"
        with self.assertRaises(ValueError):
            self.bridge.observe(self.fixture.config, self.fixture.manifest, 1000)
        self.bus.path = "/org/freedesktop/systemd1/unit/test_2eservice"
        self.bus.service["BindLogSockets"] = ("b", True)
        with self.assertRaises(ValueError):
            self.bridge.observe(self.fixture.config, self.fixture.manifest, 1000)
        self.bus.unit = {str(i): ("s", "x") for i in range(4097)}
        self.bus.unit_reads = 0
        with self.assertRaisesRegex(ValueError, "property dictionary"):
            self.bridge.observe(self.fixture.config, self.fixture.manifest, 1000)

    def test_late_read_preserves_its_partial_view(self):
        self.bus.late = "GetAll"
        with self.assertRaises(TimeoutError):
            self.bridge.observe(self.fixture.config, self.fixture.manifest, 1000)
        self.assertIn("unit_before", self.bridge.partial)
        self.assertNotIn("service", self.bridge.partial)

    def test_creation_failure_cannot_be_retried_as_if_no_request_was_sent(self):
        def uncertain(*args, **kwargs):
            raise ConnectionError("reply lost")

        self.bus.call = uncertain
        with self.assertRaises(ConnectionError):
            self.bridge.start(self.fixture.config, self.fixture.manifest, 1000)
        self.assertTrue(self.bridge.creation_attempted)
        with self.assertRaises(ValueError):
            self.bridge.start(self.fixture.config, self.fixture.manifest, 1000)

    def test_normalized_root_arrays_do_not_alias_bus_reply_lists(self):
        result = self.bridge.observe(self.fixture.config, self.fixture.manifest, 1000)
        before = copy.deepcopy(result["root"]["BindPaths"])
        self.bus.service["BindPaths"][1][0] = ("/changed", "/changed", False, 0)
        self.assertEqual(result["root"]["BindPaths"], before)

    def test_duplicate_creation_property_is_rejected_before_request(self):
        original = self.fixture.root.wire_properties

        def duplicate(plan):
            return original(plan) + [("Type", ("s", "exec"))]

        with (
            mock.patch.object(
                self.fixture.root, "wire_properties", side_effect=duplicate
            ),
            self.assertRaises(ValueError),
        ):
            self.bridge.start(self.fixture.config, self.fixture.manifest, 1000)
        self.assertEqual(len(self.bus.calls), 0)
        self.assertFalse(self.bridge.creation_attempted)


if __name__ == "__main__":
    unittest.main()
