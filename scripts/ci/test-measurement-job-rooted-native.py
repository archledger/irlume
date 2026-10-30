#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Concrete rooted-G bootstrap tests without a service, VM or real user bus."""

import contextlib
import hashlib
import importlib.util
import os
import socket
import sys
import tempfile
import time
import types
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
# sun_path holds 108 bytes, so directories that will hold a bound AF_UNIX
# socket use this short base instead of TMPDIR, which may be long.
SOCKET_BASE = "/tmp"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rooted = load("rooted_native", "measurement-job-rooted-native.py")
native = load("rooted_native_entry", "measurement-job-guardian-native.py")
fixtures = load("rooted_native_fixture", "test-measurement-job-rooted-protocol.py")


class DispatchTests(unittest.TestCase):
    def test_rooted_mode_dispatches_without_legacy_effects(self):
        data = b'{"scope":"contained-job-rooted-startup-config-v2"}'
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
        data = b'{"scope":"contained-job-rooted-startup-config-v2"}'
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
        data = b'{"scope":"contained-job-rooted-startup-config-v2"}'
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

    def test_v1_rooted_scope_is_not_dispatched(self):
        data = b'{"scope":"contained-job-rooted-startup-config-v1"}'
        digest = hashlib.sha256(data).hexdigest()
        with (
            mock.patch.object(native, "protected_read", return_value=data),
            mock.patch.object(
                native, "load", side_effect=AssertionError("v1 rooted dispatch")
            ),
            mock.patch.object(
                native, "GuardianEffects", side_effect=AssertionError("legacy effects")
            ),
            self.assertRaisesRegex(ValueError, "invalid fields"),
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
        directory = tempfile.TemporaryDirectory()
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
        directory = tempfile.TemporaryDirectory(dir=SOCKET_BASE)
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
            time.monotonic_ns(),
            fixture.manifest,
            self.pdeps,
        )
        self.manifest, self.fixture = fixture.manifest, fixture
        self.effects = rooted.GuardianEffects(self.config, self.manifest, self.runtime)
        self.addCleanup(self.effects.close_control)
        self.deadline = self.effects.value["startup_deadline_ns"]
        uid, unit = fixture.plan["uid"], root.guardian.unit_name(spec)
        self.group = (
            f"/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/" + unit
        )
        # H's LAUNCH identity: the manager's MainPID and its start plus HOST_NS.
        self.identity = root.guardian.ServiceIdentity(
            unit,
            "d" * 32,
            4242,
            self.group,
            self.effects.value["origin_ns"] + root.guardian.HOST_NS,
        )
        # G's own cgroup directory, the root of its cgroup namespace, whose
        # inode number is the unit's ControlGroupId.
        self.cgroup_root = self.cgroup_directory()
        info = os.stat(self.cgroup_root)
        self.cgroup_view = (info.st_dev, info.st_ino)
        self.cgroup_id = info.st_ino

    def cgroup_directory(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return directory.name

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
        collected = self.runtime.startup.Startup(
            {"test": True}, types.MappingProxyType({})
        )
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
                self.runtime.startup, "collect_startup", return_value=collected
            ) as collect,
        ):
            effects = rooted.GuardianEffects(self.config, self.manifest, self.runtime)
            self.assertIs(
                effects.collect(self.config, self.manifest, self.deadline),
                collected,
            )
        self.assertEqual(collect.call_args.args[-1], self.deadline)
        self.assertIsNone(effects.attempt_fd)

    def test_collect_returns_only_an_observation_with_its_tree_pages(self):
        effects = rooted.GuardianEffects(self.config, self.manifest, self.runtime)
        for value in ({"test": True}, ({"test": True}, types.MappingProxyType({}))):
            with (
                self.subTest(value=type(value).__name__),
                mock.patch.object(
                    self.runtime.startup, "collect_startup", return_value=value
                ),
                self.assertRaisesRegex(ValueError, "^rooted startup collection$"),
            ):
                effects.collect(self.config, self.manifest, self.deadline)

    def local(
        self,
        *,
        cgroup=None,
        affinity=None,
        pid=1,
        ppid=0,
        deadline=None,
        cgroup_root=None,
    ):
        """Run preflight as the PID namespace init; host PIDs are never read."""
        if cgroup is None:
            cgroup = b"1:net_cls:/\n0::/\n"
        if affinity is None:
            affinity = set(self.effects.spec.cpus)
        self.started = []

        def start(target):
            self.started.append(target)
            if target != pid:
                raise AssertionError("G read another process start")
            return 123

        self.read = mock.Mock(return_value=cgroup)
        with (
            mock.patch.object(
                native.service, "SystemdBus", side_effect=AssertionError("bus in G")
            ),
            mock.patch.object(
                rooted.os, "pidfd_open", side_effect=AssertionError("pidfd in G")
            ),
            mock.patch.object(self.effects, "read_cgroup", self.read),
            mock.patch.object(rooted, "CGROUP_ROOT", cgroup_root or self.cgroup_root),
            mock.patch.object(rooted.os, "sched_getaffinity", return_value=affinity),
            mock.patch.object(rooted.os, "getpid", return_value=pid),
            mock.patch.object(rooted.os, "getppid", return_value=ppid),
            mock.patch.object(native, "process_start", side_effect=start),
        ):
            return self.effects.preflight(
                self.config, self.manifest, deadline or self.deadline
            )

    def members(self, base, data=b"1\n", *, link=False):
        """G's cgroup directory listing the given members."""
        unit = Path(base)
        for name in ("cgroup.procs", "real.procs"):
            (unit / name).unlink(missing_ok=True)
        if link:
            (unit / "real.procs").write_bytes(data)
            (unit / "cgroup.procs").symlink_to("real.procs")
        else:
            (unit / "cgroup.procs").write_bytes(data)

    def bind(
        self,
        identity=None,
        *,
        cgroup_id=None,
        cgroup=None,
        cgroup_root=None,
        procs=b"1\n",
        link=False,
        now=None,
        deadline=None,
        config=None,
    ):
        """Run bind_service with H's LAUNCH identity against G's cgroup."""
        if cgroup is None:
            cgroup = b"0::/\n"
        base = cgroup_root or self.cgroup_root
        self.members(base, procs, link=link)
        self.read = mock.Mock(return_value=cgroup)
        with (
            mock.patch.object(
                native.service, "SystemdBus", side_effect=AssertionError("bus in G")
            ),
            mock.patch.object(rooted, "CGROUP_ROOT", base),
            mock.patch.object(self.effects, "read_cgroup", self.read),
            mock.patch.object(
                self.effects, "now", return_value=now or self.effects.now()
            ),
        ):
            return self.effects.bind_service(
                config or self.config,
                self.manifest,
                self.identity if identity is None else identity,
                self.cgroup_id if cgroup_id is None else cgroup_id,
                deadline or self.deadline,
            )

    def test_rooted_guardian_never_opens_a_bus(self):
        before = set(os.listdir("/proc/self/fd"))
        with (
            mock.patch.dict(sys.modules),
            mock.patch.object(
                rooted.socket, "socket", side_effect=AssertionError("socket")
            ),
        ):
            for name in [name for name in sys.modules if name.startswith("jeepney")]:
                del sys.modules[name]
            view = self.local()
            self.assertEqual(self.bind(), 123)
            self.assertFalse(any(name.startswith("jeepney") for name in sys.modules))
        self.assertEqual(view, rooted.LocalView(self.cgroup_view, 123))
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        self.assertFalse(hasattr(self.effects, "service_observation"))

    def test_runtime_has_no_bus_bridge(self):
        self.assertNotIn("bus_bridge", rooted.Runtime._fields)
        self.assertFalse(hasattr(rooted, "prime_bus_imports"))
        loading = native.load
        loaded = []

        def record(name, path):
            loaded.append(Path(path).name)
            return loading(name, path)

        with mock.patch.object(native, "load", side_effect=record):
            runtime = rooted.load_runtime(native, rooted)
        self.assertEqual(len(loaded), len(rooted.Runtime._fields) - 2)
        self.assertNotIn("measurement-job-rooted-bus.py", loaded)
        self.assertFalse(
            any(hasattr(module, "RootedBus") for module in runtime.roots[2:])
        )

    def test_preflight_is_local_and_returns_its_placement(self):
        before = set(os.listdir("/proc/self/fd"))
        view = self.local()
        self.assertIs(type(view), rooted.LocalView)
        self.assertEqual(view, (self.cgroup_view, 123))
        self.assertIs(self.effects.local, view)
        self.assertEqual(self.started, [1])
        self.read.assert_called_once_with(self.deadline)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        self.assertIsNone(self.effects.attempt_fd)

    def test_preflight_requires_the_pid_namespace_init(self):
        for pid, ppid in ((2, 0), (1, 7), (os.getpid(), os.getppid())):
            with (
                self.subTest(pid=pid, ppid=ppid),
                self.assertRaisesRegex(ValueError, "PID namespace init"),
            ):
                self.local(pid=pid, ppid=ppid)
            self.assertEqual(self.started, [])
            self.read.assert_not_called()
            self.assertIsNone(self.effects.local)

    def test_preflight_refuses_malformed_placement(self):
        cases = {
            "malformed": b"wrong\n",
            "v1-only": b"1:net_cls:/\n",
            "two-unified": b"0::/\n0::/other\n",
            "affinity": None,
        }
        for case, cgroup in cases.items():
            affinity = set() if case == "affinity" else None
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.local(cgroup=cgroup, affinity=affinity)
            self.assertIsNone(self.effects.local)

    def test_preflight_requires_its_own_cgroup_namespace_root(self):
        # The host path: no cgroup namespace, or a fallback to the host's.
        # /../x: moved out of the namespace root. /x: below it.
        for label, cgroup in (
            ("host path", ("0::" + self.group + "\n").encode()),
            ("host path beside v1", ("1:net_cls:/\n0::" + self.group + "\n").encode()),
            ("outside", b"0::/../x\n"),
            ("parent", b"0::/..\n"),
            ("below", b"0::/x\n"),
        ):
            with (
                self.subTest(case=label),
                self.assertRaisesRegex(
                    ValueError, "^rooted guardian cgroup namespace$"
                ),
            ):
                self.local(cgroup=cgroup)
            self.assertIsNone(self.effects.local)
        link = Path(self.cgroup_directory()) / "link"
        link.symlink_to(self.cgroup_root)
        regular = Path(self.cgroup_directory()) / "file"
        regular.write_bytes(b"")
        for label, path, message in (
            # O_DIRECTORY with O_NOFOLLOW: Linux refuses a final symlink
            # with ENOTDIR before ELOOP.
            ("symlink", link, "Not a directory"),
            ("not a directory", regular, "Not a directory"),
            ("missing", Path(self.cgroup_root) / "missing", "No such file"),
        ):
            with (
                self.subTest(case=label),
                self.assertRaisesRegex(OSError, message),
            ):
                self.local(cgroup_root=str(path))
            self.assertIsNone(self.effects.local)

    def test_preflight_never_reads_the_client_process(self):
        # G's proc lists only its own namespace; the client is H's to check.
        client = self.fixture.client
        self.assertNotEqual(client["pid"], 1)
        self.local()
        self.assertNotIn(client["pid"], self.started)

    def test_bind_service_returns_local_start_for_the_launch_identity(self):
        self.local()
        self.assertEqual(self.bind(), 123)
        # The cgroup is read again at binding, under the configuration deadline.
        self.read.assert_called_once_with(self.deadline)

    def test_bind_service_refuses_identity_g_cannot_confirm(self):
        guardian = self.runtime.preflight.root.guardian
        origin = self.effects.value["origin_ns"]
        now = origin + 1_000_000
        # The earliest deadline: a start one proc clock tick before the origin.
        earliest = origin + guardian.HOST_NS - guardian.START_TICK_NS
        # Another directory at G's cgroup path, and an ID that names it.
        other = self.cgroup_directory()
        other_id = os.stat(other).st_ino
        self.assertNotEqual(other_id, self.cgroup_id)
        cases = (
            ("other cgroup ID", {"cgroup_id": other_id}, "^rooted guardian cgroup ID$"),
            ("next cgroup ID", {"cgroup_id": self.cgroup_id + 1}, "cgroup ID"),
            ("cgroup ID type", {"cgroup_id": True}, "cgroup ID"),
            ("cgroup ID text", {"cgroup_id": str(self.cgroup_id)}, "cgroup ID"),
            # Equal as a number, not an integer.
            ("cgroup ID float", {"cgroup_id": float(self.cgroup_id)}, "cgroup ID"),
            (
                "replaced cgroup",
                {"cgroup_root": other},
                "^rooted guardian cgroup binding$",
            ),
            (
                "replaced cgroup with its ID",
                {"cgroup_root": other, "cgroup_id": other_id},
                "^rooted guardian cgroup ID$",
            ),
            (
                "migrated",
                {"cgroup": b"0::/../sibling\n"},
                "^rooted guardian cgroup namespace$",
            ),
            (
                "host path",
                {"cgroup": ("0::" + self.group + "\n").encode()},
                "^rooted guardian cgroup namespace$",
            ),
            (
                "early",
                {"identity": self.identity._replace(deadline_ns=earliest - 1)},
                "start window",
            ),
            (
                "late",
                {
                    "identity": self.identity._replace(
                        deadline_ns=now + guardian.HOST_NS + 1
                    ),
                    "now": now,
                },
                "start window",
            ),
            ("outside member", {"procs": b"1\n0\n"}, "cgroup members"),
            ("no member", {"procs": b""}, "cgroup members"),
            ("other member", {"procs": b"0\n"}, "cgroup members"),
            ("second member", {"procs": b"1\n2\n"}, "cgroup members"),
            ("linked members", {"link": True}, "Too many levels"),
            ("identity type", {"identity": self.identity._asdict()}, "identity"),
        )
        self.local()
        for case, options, message in cases:
            with (
                self.subTest(case=case),
                self.assertRaisesRegex((ValueError, OSError), message),
            ):
                self.bind(**options)
        changed = self.runtime.protocol.Configuration(self.config.data, "f" * 64)
        with self.assertRaisesRegex(ValueError, "input changed"):
            self.bind(config=changed)

    def test_bind_service_reads_members_through_the_checked_directory(self):
        # The path names another directory once G has opened and checked its
        # own: the members still come from the checked one.
        self.local()
        base = Path(self.cgroup_root)
        moved = Path(self.cgroup_directory()) / "moved"
        opening = os.open

        def swap(path, flags, *args, **kwargs):
            fd = opening(path, flags, *args, **kwargs)
            if path == str(base) and flags & os.O_DIRECTORY and not moved.exists():
                base.rename(moved)
                base.mkdir()
                (base / "cgroup.procs").write_bytes(b"1\n")
            return fd

        with (
            mock.patch.object(rooted.os, "open", side_effect=swap),
            self.assertRaisesRegex(ValueError, "^rooted guardian cgroup members$"),
        ):
            self.bind(procs=b"1\n2\n")
        self.assertTrue(moved.exists())
        self.assertEqual((base / "cgroup.procs").read_bytes(), b"1\n")

    def test_bind_service_refuses_the_same_inode_on_another_device(self):
        # G's inode number on another filesystem is not G's cgroup.
        self.local()
        statting = os.fstat

        def elsewhere(fd):
            info = statting(fd)
            fields = list(info[:10])
            fields[2] = info.st_dev + 1
            return os.stat_result(fields)

        with (
            mock.patch.object(rooted.os, "fstat", side_effect=elsewhere),
            self.assertRaisesRegex(ValueError, "^rooted guardian cgroup binding$"),
        ):
            self.bind()

    def test_bind_service_window_edges_are_inclusive(self):
        guardian = self.runtime.preflight.root.guardian
        origin = self.effects.value["origin_ns"]
        now = origin + 2_000_000
        self.local()
        for deadline_ns in (
            origin + guardian.HOST_NS - guardian.START_TICK_NS,
            now + guardian.HOST_NS,
        ):
            with self.subTest(deadline_ns=deadline_ns):
                identity = self.identity._replace(deadline_ns=deadline_ns)
                self.assertEqual(self.bind(identity, now=now), 123)

    def test_bind_service_requires_the_local_view(self):
        with self.assertRaisesRegex(ValueError, "before preflight"):
            self.bind()
        self.read.assert_not_called()

    def test_suboperations_cannot_extend_the_configuration_deadline(self):
        later = self.deadline + 5_000_000_000
        self.local(deadline=later)
        self.read.assert_called_once_with(self.deadline)
        self.bind(deadline=later)
        self.read.assert_called_once_with(self.deadline)
        channel = mock.Mock()
        self.effects.channel = channel
        self.effects.receive(later)
        self.effects.send(b"data", later)
        self.effects.require_idle(later)
        channel.receive.assert_called_once_with(self.deadline)
        channel.send.assert_called_once_with(b"data", self.deadline)
        channel.require_idle.assert_called_once_with(self.deadline)

    def control_socket(self):
        fd = self.open_attempt()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(self.path / "control.sock"))
        (self.path / "control.sock").chmod(0o600)
        wire = mock.Mock()
        wire.connect_ex.return_value = 0
        return fd, wire

    def test_host_peer_is_expected_outside_the_pid_namespace(self):
        fd, wire = self.control_socket()
        channel = mock.Mock()
        sequence = []
        channel.check.side_effect = lambda deadline: sequence.append("alive")
        stating = os.stat

        def stat_socket(*args, **kwargs):
            sequence.append("socket")
            return stating(*args, **kwargs)

        with (
            mock.patch.object(rooted.socket, "socket", return_value=wire),
            mock.patch.object(
                self.runtime.preflight.root.guardian,
                "PeerChannel",
                return_value=channel,
            ) as construct,
            mock.patch.object(rooted.os, "stat", side_effect=stat_socket),
            mock.patch.object(
                native,
                "process_start",
                side_effect=AssertionError("G read a host process"),
            ),
        ):
            self.effects.connect(self.config, self.deadline)
        # SO_PEERCRED gives PID 0 for any peer outside G's namespace.
        construct.assert_called_once_with(
            wire, (0, self.fixture.client["uid"], self.fixture.client["gid"])
        )
        self.assertEqual(sequence, ["socket", "alive", "socket", "alive"])
        channel.receive.assert_not_called()
        self.effects.close_control()
        channel.close.assert_called_once()
        self.assertGreater(os.fstat(fd).st_ino, 0)

    def test_control_socket_replaced_during_connect_prevents_exchange(self):
        fd, wire = self.control_socket()
        channel = mock.Mock()
        stating, seen = os.stat, []
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(replacement.close)

        def replace_after_connect(*args, **kwargs):
            seen.append(args)
            if len(seen) == 2:
                (self.path / "control.sock").unlink()
                replacement.bind(str(self.path / "control.sock"))
                (self.path / "control.sock").chmod(0o600)
            return stating(*args, **kwargs)

        with (
            mock.patch.object(rooted.socket, "socket", return_value=wire),
            mock.patch.object(
                self.runtime.preflight.root.guardian,
                "PeerChannel",
                return_value=channel,
            ),
            mock.patch.object(rooted.os, "stat", side_effect=replace_after_connect),
            self.assertRaisesRegex(ValueError, "rooted control socket replaced"),
        ):
            self.effects.connect(self.config, self.deadline)
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

        def effects(*args):
            self.assertEqual(rooted.sys.path, expected)
            return mock.Mock()

        inert = mock.Mock()
        with (
            mock.patch.dict(rooted.sys.modules),
            mock.patch.object(rooted, "load_runtime", return_value=self.runtime),
            mock.patch.object(rooted, "read_manifest", return_value=self.manifest),
            mock.patch.object(rooted, "GuardianEffects", side_effect=effects) as made,
            mock.patch.object(self.runtime.handshake, "Guardian", return_value=inert),
            mock.patch.object(rooted.sys, "path", original_path),
        ):
            for name in [n for n in rooted.sys.modules if n.startswith("jeepney")]:
                del rooted.sys.modules[name]
            self.assertEqual(
                rooted.run_service(
                    self.config.data, self.config.sha256, native, rooted
                ),
                0,
            )
            # G imports no bus library before or during its run.
            self.assertFalse(any(n.startswith("jeepney") for n in rooted.sys.modules))
        inert.run.assert_called_once_with()
        made.assert_called_once()

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

    def test_peer_death_after_socket_recheck_prevents_exchange(self):
        fd, wire = self.control_socket()
        channel = mock.Mock()
        sequence = []

        def alive(deadline):
            sequence.append("alive")
            if len(sequence) == 2:
                raise ConnectionError("peer exited")

        channel.check.side_effect = alive
        with (
            mock.patch.object(rooted.socket, "socket", return_value=wire),
            mock.patch.object(
                self.runtime.preflight.root.guardian,
                "PeerChannel",
                return_value=channel,
            ),
            self.assertRaises(ConnectionError),
        ):
            self.effects.connect(self.config, self.deadline)
        self.assertEqual(sequence, ["alive", "alive"])
        channel.receive.assert_not_called()
        channel.send.assert_not_called()
        self.effects.close_control()
        self.assertGreater(os.fstat(fd).st_ino, 0)


if __name__ == "__main__":
    unittest.main()
