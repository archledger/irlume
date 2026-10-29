#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Concrete rooted-G bootstrap tests without a service, VM or real user bus."""

import contextlib
import copy
import hashlib
import importlib.util
import os
import socket
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


rooted = load("rooted_native", "measurement-job-rooted-native.py")
native = load("rooted_native_entry", "measurement-job-guardian-native.py")
fixtures = load("rooted_native_fixture", "test-measurement-job-rooted-protocol.py")
bus_fixtures = load("rooted_native_bus_fixture", "test-measurement-job-rooted-bus.py")


class DispatchTests(unittest.TestCase):
    def test_rooted_mode_dispatches_without_legacy_effects(self):
        data = b'{"scope":"contained-job-rooted-startup-config-v1"}'
        digest = hashlib.sha256(data).hexdigest()
        target = types.ModuleType("rooted_target")
        target.run_service = mock.Mock(return_value=0)
        with (
            mock.patch.object(native, "protected_read", return_value=data),
            mock.patch.object(native, "load", return_value=target),
            mock.patch.object(
                native, "GuardianEffects", side_effect=AssertionError("legacy effects")
            ),
        ):
            result = native.run_service(
                [
                    "entry",
                    "--service",
                    "/run/irlume/attempt/guardian-config.json",
                    digest,
                ],
                _module=native,
            )
        self.assertEqual(result, 0)
        target.run_service.assert_called_once_with(data, digest, native, target)

    def test_rooted_dispatch_requires_fixed_path_and_actual_entry_module(self):
        data = b'{"scope":"contained-job-rooted-startup-config-v1"}'
        digest = hashlib.sha256(data).hexdigest()
        with (
            mock.patch.object(native, "protected_read", return_value=data),
            mock.patch.object(
                native, "load", side_effect=AssertionError("unexpected load")
            ),
        ):
            self.assertEqual(
                native.run_service(
                    ["entry", "--service", "/private/guardian-config.json", digest],
                    _module=native,
                ),
                77,
            )
            self.assertEqual(
                native.run_service(
                    [
                        "entry",
                        "--service",
                        "/run/irlume/attempt/guardian-config.json",
                        digest,
                    ]
                ),
                77,
            )

    def test_rooted_failure_does_not_fall_back_to_legacy(self):
        data = b'{"scope":"contained-job-rooted-startup-config-v1"}'
        digest = hashlib.sha256(data).hexdigest()
        target = types.ModuleType("failed_rooted_target")
        target.run_service = mock.Mock(side_effect=ValueError("rooted failure"))
        with (
            mock.patch.object(native, "protected_read", return_value=data),
            mock.patch.object(native, "load", return_value=target),
            mock.patch.object(
                native, "GuardianEffects", side_effect=AssertionError("legacy fallback")
            ),
            self.assertRaisesRegex(ValueError, "rooted failure"),
        ):
            native.run_service(
                [
                    "entry",
                    "--service",
                    "/run/irlume/attempt/guardian-config.json",
                    digest,
                ],
                _module=native,
            )


class ManifestReaderTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.ProtocolTests(
            "test_canonical_config_preserves_host_coordinates_and_is_detached"
        )
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.plan, self.data, self.root = fixture.plan, fixture.manifest, fixture.root
        directory = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)
        (self.path / "run/irlume").mkdir(parents=True)
        self.file = self.path / "run/irlume/runtime-manifest.json"
        self.file.write_bytes(self.data)
        self.file.chmod(0o400)
        self.path.chmod(0o500)
        info = self.path.stat()
        self.plan["root"].update(device=info.st_dev, inode=info.st_ino)
        info = self.file.stat()
        self.plan["manifest"].update(device=info.st_dev, inode=info.st_ino)

    def read(self, deadline=None):
        opening, stating = os.open, os.stat

        def open_root(path, *args, **kwargs):
            return opening(self.path if path == "/" else path, *args, **kwargs)

        def stat_root(path, *args, **kwargs):
            return stating(self.path if path == "/" else path, *args, **kwargs)

        with (
            mock.patch.object(rooted.os, "open", side_effect=open_root),
            mock.patch.object(rooted.os, "stat", side_effect=stat_root),
        ):
            return rooted.read_manifest(
                self.plan, self.root, deadline or time.monotonic_ns() + 5_000_000_000
            )

    def test_exact_manifest_is_read_with_no_retained_descriptors(self):
        before = set(os.listdir("/proc/self/fd"))
        self.assertEqual(self.read(), self.data)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_wrong_root_refuses_before_file_reads(self):
        self.plan["root"]["inode"] += 1
        with (
            mock.patch.object(
                rooted.os,
                "read",
                side_effect=AssertionError("read before root validation"),
            ),
            self.assertRaises(ValueError),
        ):
            self.read()

    def test_file_identity_content_and_symlink_changes_refuse(self):
        self.plan["manifest"]["inode"] += 1
        with self.assertRaises(ValueError):
            self.read()
        self.plan["manifest"]["inode"] -= 1
        self.file.chmod(0o600)
        self.file.write_bytes(b"x" * len(self.data))
        self.file.chmod(0o400)
        with self.assertRaises(ValueError):
            self.read()
        self.file.unlink()
        self.file.symlink_to("/outside")
        with self.assertRaises(OSError):
            self.read()

    def test_expired_deadline_refuses_and_does_not_leak(self):
        before = set(os.listdir("/proc/self/fd"))
        with self.assertRaises(TimeoutError):
            self.read(time.monotonic_ns() - 1)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_short_reads_are_handled_and_parent_symlinks_refuse(self):
        reading = os.read
        with mock.patch.object(
            rooted.os, "read", side_effect=lambda fd, count: reading(fd, min(count, 7))
        ):
            self.assertEqual(self.read(), self.data)
        parent = self.file.parent
        moved = parent.with_name("saved")
        parent.rename(moved)
        parent.symlink_to(moved.name)
        with self.assertRaises(OSError):
            self.read()

    def test_live_root_replacement_is_rejected(self):
        reading = os.read
        replaced = [False]
        saved = self.path.with_name(self.path.name + "-saved")

        def replace_root(fd, count):
            result = reading(fd, count)
            if not replaced[0]:
                replaced[0] = True
                self.path.rename(saved)
                self.path.mkdir(mode=0o500)
            return result

        try:
            with (
                mock.patch.object(rooted.os, "read", side_effect=replace_root),
                self.assertRaises(ValueError),
            ):
                self.read()
        finally:
            if replaced[0]:
                self.path.rmdir()
                saved.rename(self.path)

    def test_group_writable_manifest_parent_is_rejected(self):
        self.file.parent.chmod(0o777)
        with self.assertRaises(ValueError):
            self.read()

    def test_late_manifest_close_refuses_after_closing_every_descriptor(self):
        clock = [100]
        acquired = []
        owned = self.root.closure.owned_fd

        @contextlib.contextmanager
        def late_close(fd):
            acquired.append(fd)
            with owned(fd):
                yield fd
            clock[0] = 1000

        before = set(os.listdir("/proc/self/fd"))
        with (
            mock.patch.object(self.root.closure, "owned_fd", side_effect=late_close),
            mock.patch.object(
                self.root.closure.inputs.time,
                "monotonic_ns",
                side_effect=lambda: clock[0],
            ),
            self.assertRaises(TimeoutError),
        ):
            self.read(1000)
        self.assertEqual(len(acquired), 4)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_manifest_read_and_close_failures_are_both_preserved(self):
        original_close = os.close

        def fail_close(fd):
            original_close(fd)
            raise OSError("injected close")

        before = set(os.listdir("/proc/self/fd"))
        with (
            mock.patch.object(
                rooted.os, "read", side_effect=ValueError("injected read")
            ),
            mock.patch.object(rooted.os, "close", side_effect=fail_close),
            self.assertRaises(BaseExceptionGroup) as caught,
        ):
            self.read()
        leaves = []

        def flatten(error):
            if isinstance(error, BaseExceptionGroup):
                for part in error.exceptions:
                    flatten(part)
            else:
                leaves.append(error)

        flatten(caught.exception)
        self.assertTrue(
            any(
                isinstance(error, ValueError) and str(error) == "injected read"
                for error in leaves
            )
        )
        self.assertEqual(sum(isinstance(error, OSError) for error in leaves), 4)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)


class EffectsTests(unittest.TestCase):
    def setUp(self):
        self.runtime = rooted.load_runtime(native, rooted)
        fixture = fixtures.ProtocolTests(
            "test_canonical_config_preserves_host_coordinates_and_is_detached"
        )
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        directory = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)
        info = self.path.stat()
        fixture.plan["attempt"].update(
            path=str(self.path), device=info.st_dev, inode=info.st_ino
        )
        root = self.runtime.preflight.root
        self.pdeps = self.runtime.protocol.Dependencies(root, self.runtime.artifact)
        spec = root.guardian.Specification(**fixture.spec._asdict())._replace(
            overlay=str(self.path / "overlay.qcow2")
        )
        self.config = self.runtime.protocol.make_config(
            spec,
            fixture.plan,
            fixture.client,
            fixture.bus,
            time.monotonic_ns(),
            fixture.manifest,
            self.pdeps,
        )
        self.manifest, self.fixture = fixture.manifest, fixture
        self.effects = rooted.GuardianEffects(self.config, self.manifest, self.runtime)
        self.addCleanup(self.effects.close_control)
        self.deadline = self.effects.value["startup_deadline_ns"]

    def open_attempt(self):
        with mock.patch.object(
            native,
            "private_directory",
            side_effect=lambda path: os.open(
                self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            ),
        ):
            fd = self.effects.open_attempt(self.config, self.deadline)
        self.addCleanup(os.close, fd)
        return fd

    def test_constructor_and_collect_do_not_open_output_or_bus(self):
        with (
            mock.patch.object(
                native.service,
                "SystemdBus",
                side_effect=AssertionError("bus before collection"),
            ),
            mock.patch.object(
                native,
                "private_directory",
                side_effect=AssertionError("output before collection"),
            ),
            mock.patch.object(
                self.runtime.startup, "collect_startup", return_value={"test": True}
            ) as collect,
        ):
            effects = rooted.GuardianEffects(self.config, self.manifest, self.runtime)
            self.assertEqual(
                effects.collect(self.config, self.manifest, self.deadline),
                {"test": True},
            )
        self.assertEqual(collect.call_args.args[-1], self.deadline)
        self.assertIsNone(effects.attempt_fd)

    def make_bus(self):
        bus = bus_fixtures.FakeBus(self.fixture)
        root = self.runtime.preflight.root
        argv = root.entry_argv(self.fixture.plan, self.config.sha256)
        bus.service["ExecStart"] = (
            "a(sasbttttuii)",
            [[argv[0], list(argv), False, 0, 0, 0, 0, 0, 0, 0]],
        )
        bus.service["MainPID"] = ("u", os.getpid())
        now = time.monotonic_ns() // 1000
        bus.service["ExecMainStartTimestampMonotonic"] = ("t", now - 100)
        bus.unit["ActiveEnterTimestampMonotonic"] = ("t", now - 50)
        bus.after = copy.deepcopy(bus.unit)
        bus.close = mock.Mock()
        group = bus.service["ControlGroup"][1]
        return bus, group

    def test_preflight_closes_bus_and_checks_exact_exec_and_placement(self):
        bus, group = self.make_bus()
        # A legacy net_cls hierarchy (VPN split tunnelling) beside the unified one.
        with (
            mock.patch.object(native.service, "SystemdBus", return_value=bus),
            mock.patch.object(
                self.effects,
                "read_cgroup",
                return_value=("1:net_cls:/\n0::" + group + "\n").encode(),
            ),
            mock.patch.object(
                rooted.os, "sched_getaffinity", return_value=set(self.effects.spec.cpus)
            ),
            mock.patch.object(
                native,
                "process_start",
                side_effect=lambda pid: (
                    self.fixture.client["starttime"]
                    if pid == self.fixture.client["pid"]
                    else 123
                ),
            ),
        ):
            identity, start = self.effects.preflight(
                self.config, self.manifest, self.deadline
            )
        self.assertEqual(identity.pid, os.getpid())
        self.assertEqual(start, 123)
        bus.close.assert_called_once()
        self.assertIsNone(self.effects.attempt_fd)

    def test_preflight_refuses_argv_placement_and_client_changes_after_bus_close(self):
        cases = (
            "argv",
            "cgroup",
            "v1-only",
            "two-unified",
            "parent",
            "affinity",
            "client",
        )
        for case in cases:
            bus, group = self.make_bus()
            if case == "argv":
                bus.service["ExecStart"] = (
                    "a(sasbttttuii)",
                    [["/wrong", ["/wrong"], False, 0, 0, 0, 0, 0, 0, 0]],
                )
            cgroup = {
                "cgroup": b"wrong\n",
                "v1-only": b"1:net_cls:/\n",
                "two-unified": ("0::" + group + "\n0::/other\n").encode(),
                "parent": ("0::" + group.rsplit("/", 1)[0] + "\n").encode(),
            }.get(case, ("1:net_cls:/\n0::" + group + "\n").encode())
            affinity = set() if case == "affinity" else set(self.effects.spec.cpus)

            def start(pid, case=case):
                return (
                    self.fixture.client["starttime"] + (case == "client")
                    if pid == self.fixture.client["pid"]
                    else 123
                )

            with (
                mock.patch.object(native.service, "SystemdBus", return_value=bus),
                mock.patch.object(self.effects, "read_cgroup", return_value=cgroup),
                mock.patch.object(
                    rooted.os, "sched_getaffinity", return_value=affinity
                ),
                mock.patch.object(native, "process_start", side_effect=start),
                self.subTest(case=case),
                self.assertRaises(ValueError),
            ):
                self.effects.preflight(self.config, self.manifest, self.deadline)
            bus.close.assert_called_once()

    def test_bus_is_closed_if_bridge_construction_fails(self):
        bus = mock.Mock()
        with (
            mock.patch.object(native.service, "SystemdBus", return_value=bus),
            mock.patch.object(
                self.runtime.bus_bridge,
                "RootedBus",
                side_effect=ValueError("bridge failed"),
            ),
            self.assertRaises(ValueError),
        ):
            self.effects.preflight(self.config, self.manifest, self.deadline)
        bus.close.assert_called_once()

    def test_bus_observation_and_close_failures_are_both_preserved(self):
        bus = mock.Mock()
        bus.close.side_effect = OSError("close failed")
        bridge = mock.Mock()
        bridge.observe.side_effect = ValueError("observation failed")
        with (
            mock.patch.object(native.service, "SystemdBus", return_value=bus),
            mock.patch.object(
                self.runtime.bus_bridge, "RootedBus", return_value=bridge
            ),
            self.assertRaises(BaseExceptionGroup) as caught,
        ):
            self.effects.preflight(self.config, self.manifest, self.deadline)
        self.assertIsInstance(caught.exception.exceptions[0], ValueError)
        self.assertIsInstance(caught.exception.exceptions[1], OSError)
        bus.close.assert_called_once()
        self.assertIsNone(self.effects.attempt_fd)

    def test_suboperations_cannot_extend_the_configuration_deadline(self):
        later = self.deadline + 5_000_000_000
        with (
            mock.patch.object(
                native.service,
                "SystemdBus",
                side_effect=RuntimeError("stop before connect"),
            ) as factory,
            self.assertRaises(RuntimeError),
        ):
            self.effects.preflight(self.config, self.manifest, later)
        self.assertEqual(factory.call_args.kwargs["deadline"], self.deadline)
        channel = mock.Mock()
        self.effects.channel = channel
        self.effects.receive(later)
        self.effects.send(b"data", later)
        self.effects.require_idle(later)
        channel.receive.assert_called_once_with(self.deadline)
        channel.send.assert_called_once_with(b"data", self.deadline)
        channel.require_idle.assert_called_once_with(self.deadline)

    def test_same_pid_with_different_starttime_refuses_after_channel_creation(self):
        fd = self.open_attempt()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(self.path / "control.sock"))
        (self.path / "control.sock").chmod(0o600)
        wire = mock.Mock()
        wire.connect_ex.return_value = 0
        channel = mock.Mock()
        checks = []
        channel.check.side_effect = lambda deadline: checks.append("alive")

        def changed_start(pid):
            checks.append("starttime")
            return self.fixture.client["starttime"] + 1

        with (
            mock.patch.object(rooted.socket, "socket", return_value=wire),
            mock.patch.object(
                self.runtime.preflight.root.guardian,
                "PeerChannel",
                return_value=channel,
            ) as construct,
            mock.patch.object(
                native,
                "process_start",
                side_effect=changed_start,
            ),
            self.assertRaises(ValueError),
        ):
            self.effects.connect(self.config, self.deadline)
        self.assertEqual(channel.check.call_count, 2)
        self.assertEqual(checks, ["alive", "starttime", "alive"])
        construct.assert_called_once_with(
            wire,
            (
                self.fixture.client["pid"],
                self.fixture.client["uid"],
                self.fixture.client["gid"],
            ),
        )
        channel.receive.assert_not_called()
        channel.send.assert_not_called()
        self.effects.close_control()
        channel.close.assert_called_once()
        self.assertGreater(os.fstat(fd).st_ino, 0)

    def test_real_bootstrap_selects_roots_and_calls_only_inert_controller(self):
        original_path = list(rooted.sys.path)
        expected = [
            "/" + path
            for path in self.runtime.preflight.root.closure.runtime._json(
                self.manifest
            )["python"]["roots"]
        ]

        def primed():
            self.assertEqual(rooted.sys.path, expected)

        inert = mock.Mock()
        with (
            mock.patch.object(rooted, "load_runtime", return_value=self.runtime),
            mock.patch.object(rooted, "read_manifest", return_value=self.manifest),
            mock.patch.object(rooted, "prime_bus_imports", side_effect=primed) as prime,
            mock.patch.object(rooted, "GuardianEffects", return_value=mock.Mock()),
            mock.patch.object(self.runtime.handshake, "Guardian", return_value=inert),
            mock.patch.object(rooted.sys, "path", original_path),
        ):
            self.assertEqual(
                rooted.run_service(
                    self.config.data, self.config.sha256, native, rooted
                ),
                0,
            )
        inert.run.assert_called_once_with()
        prime.assert_called_once_with()

    def test_bad_header_is_rejected_before_reading_the_manifest(self):
        value = self.runtime.protocol.decode_header(
            self.config.data, self.config.sha256, self.pdeps
        )
        value["mode"] = "execute"
        data = self.runtime.preflight.root.closure.canonical(value)
        with (
            mock.patch.object(rooted, "load_runtime", return_value=self.runtime),
            mock.patch.object(
                rooted,
                "read_manifest",
                side_effect=AssertionError("read before validation"),
            ),
            self.assertRaises(ValueError),
        ):
            rooted.run_service(data, hashlib.sha256(data).hexdigest(), native, rooted)

    def test_peer_constructor_failure_consumes_socket_only_once(self):
        self.open_attempt()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(self.path / "control.sock"))
        (self.path / "control.sock").chmod(0o600)
        wire = mock.Mock()
        wire.connect_ex.return_value = 0

        def failed(connected, peer):
            connected.close()
            raise ValueError("bad peer")

        with (
            mock.patch.object(rooted.socket, "socket", return_value=wire),
            mock.patch.object(
                self.runtime.preflight.root.guardian, "PeerChannel", side_effect=failed
            ),
            self.assertRaises(ValueError),
        ):
            self.effects.connect(self.config, self.deadline)
        self.effects.close_control()
        wire.close.assert_called_once()

    def test_peer_death_after_matching_starttime_prevents_exchange(self):
        fd = self.open_attempt()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(self.path / "control.sock"))
        (self.path / "control.sock").chmod(0o600)
        wire, channel = mock.Mock(), mock.Mock()
        wire.connect_ex.return_value = 0
        sequence = []

        def alive(deadline):
            sequence.append("alive")
            if len(sequence) == 3:
                raise ConnectionError("peer exited")

        def same_start(pid):
            sequence.append("starttime")
            return self.fixture.client["starttime"]

        channel.check.side_effect = alive
        with (
            mock.patch.object(rooted.socket, "socket", return_value=wire),
            mock.patch.object(
                self.runtime.preflight.root.guardian,
                "PeerChannel",
                return_value=channel,
            ),
            mock.patch.object(native, "process_start", side_effect=same_start),
            self.assertRaises(ConnectionError),
        ):
            self.effects.connect(self.config, self.deadline)
        self.assertEqual(sequence, ["alive", "starttime", "alive"])
        channel.receive.assert_not_called()
        channel.send.assert_not_called()
        self.effects.close_control()
        self.assertGreater(os.fstat(fd).st_ino, 0)


if __name__ == "__main__":
    unittest.main()
