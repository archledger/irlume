#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Boot-only payload and guest topology contracts; never boot a VM."""

import importlib.util
import json
import os
import signal
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("boot", HERE / "measurement-job-boot.py")
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)


class PayloadTests(unittest.TestCase):
    def parameters(self):
        return {
            "run_id": "run-01",
            "base_sha256": "a" * 64,
            "python_sha256": "b" * 64,
            "first_epoch": 41,
        }

    def test_fixed_payload_has_only_boot_sources_and_fixed_commands(self):
        cloud, config = boot.make_payload(HERE, **self.parameters())
        self.assertTrue(cloud.startswith(b"#cloud-config\n"))
        row = json.loads(cloud.split(b"\n", 1)[1])
        paths = {entry["path"] for entry in row["write_files"]}
        self.assertEqual(
            paths,
            set(boot.INSTALLED.values())
            | {boot.CONFIG, "/etc/systemd/system/irlume-job-run-01.service"},
        )
        self.assertEqual(config["mode"], "boot-only")
        self.assertEqual(
            row["runcmd"][-1], ["systemctl", "start", "irlume-job-run-01.service"]
        )
        self.assertNotIn("measurement_job_fixture", paths)
        self.assertNotIn("sys::run", cloud.decode())
        self.assertIn(
            config["input_manifest_sha256"],
            json.loads(boot.metadata(config))["instance-id"],
        )

    def test_payload_refuses_unbounded_or_command_like_input(self):
        for key, value in [
            ("run_id", "run;poweroff"),
            ("run_id", "../run"),
            ("base_sha256", "bad"),
            ("python_sha256", "0" * 63),
            ("first_epoch", True),
            ("first_epoch", 0),
        ]:
            args = self.parameters()
            args[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                boot.make_payload(HERE, **args)

    def test_service_has_exact_delegation_and_outer_deadline(self):
        cloud, _ = boot.make_payload(HERE, **self.parameters())
        row = json.loads(cloud.split(b"\n", 1)[1])
        unit = next(
            f["content"] for f in row["write_files"] if f["path"].endswith(".service")
        )
        for line in [
            "Type=exec",
            "Delegate=cpu memory pids",
            "DelegateSubgroup=evidence",
            "RuntimeMaxSec=150s",
            "RuntimeRandomizedExtraSec=0",
            "Restart=no",
            "NotifyAccess=none",
            "KillMode=control-group",
            "TimeoutStopSec=5s",
        ]:
            self.assertIn(line + "\n", unit)
        self.assertNotIn("ExecStop", unit)

    def test_source_entry_and_wrapper_arguments_refuse(self):
        p = subprocess.run(
            ["/usr/bin/python3", "-I", "-B", str(HERE / "measurement-job-boot.py")],
            capture_output=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(p.returncode, 77)
        p = subprocess.run(
            ["/bin/sh", str(HERE / "measurement-job-guest.sh"), "unexpected"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(p.returncode, 77)


class PreflightTests(unittest.TestCase):
    def test_mount_requires_one_unshifted_cgroup2_mount(self):
        good = "33 22 0:30 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
        boot.check_mount(good)
        for bad in (
            good + good,
            good.replace("cgroup2", "tmpfs"),
            good.replace(" / /sys", " /shifted /sys"),
            "",
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                boot.check_mount(bad)

    def test_process_status_requires_root_single_thread_and_default_signals(self):
        good = "Pid:\t42\nPPid:\t1\nUid:\t0 0 0 0\nGid:\t0 0 0 0\nThreads:\t1\nTracerPid:\t0\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\n"
        boot.check_status(good, 42, 1, default_signals=True)
        for bad in (
            good + "Threads: 1\n",
            good.replace("Threads:\t1", "Threads:\t2"),
            good.replace("0 0 0 0", "1 1 1 1"),
            good.replace("SigIgn:\t0", "SigIgn:\t1"),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                boot.check_status(bad, 42, 1, default_signals=True)

    def test_config_is_self_consistent_and_exact(self):
        _, config = boot.make_payload(
            HERE,
            run_id="run-01",
            base_sha256="a" * 64,
            python_sha256="b" * 64,
            first_epoch=41,
        )
        boot.check_config(config)
        for key, value in (
            ("mode", "runtime"),
            ("first_epoch", False),
            ("extra", 1),
            ("input_manifest_sha256", "f" * 64),
        ):
            bad = dict(config)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                boot.check_config(bad)

    def test_fd_roles_require_distinct_exact_nonblocking_objects(self):
        with tempfile.TemporaryDirectory() as path:
            inp = os.open("/dev/null", os.O_RDONLY)
            jobs = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            pipes = [os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC) for _ in range(3)]
            control = socket.socketpair()
            control[0].setblocking(False)
            try:
                mapping = {
                    0: inp,
                    1: pipes[0][1],
                    2: pipes[1][1],
                    3: jobs,
                    4: control[0].fileno(),
                }
                facts = {role: boot.fd_fact(fd) for role, fd in mapping.items()}
                expected_ids = {role: fact[0] for role, fact in facts.items()}
                boot.check_fds(facts, expected_ids, parked=False)
                for slot in (1, 2, 3, 4):
                    bad = dict(facts)
                    bad[slot] = facts[0]
                    with self.subTest(slot=slot), self.assertRaises(ValueError):
                        boot.check_fds(bad, expected_ids, parked=False)
                for slot in (1, 2):
                    bad = dict(facts)
                    bad[slot] = boot.fd_fact(pipes[2][1])
                    with (
                        self.subTest(same_kind_slot=slot),
                        self.assertRaisesRegex(ValueError, "descriptor identity"),
                    ):
                        boot.check_fds(bad, expected_ids, parked=False)
                os.set_blocking(pipes[0][1], True)
                facts[1] = boot.fd_fact(pipes[0][1])
                with self.assertRaises(ValueError):
                    boot.check_fds(facts, expected_ids, parked=False)
            finally:
                os.close(inp)
                os.close(jobs)
                for pair in pipes:
                    for fd in pair:
                        os.close(fd)
                for sock in control:
                    sock.close()


class ParkedChildTests(unittest.TestCase):
    def test_pidfd_setup_failure_retains_cleanup_ownership(self):
        children = []
        real_fork = os.fork

        def descriptors():
            opened = set()
            for name in os.listdir("/proc/self/fd"):
                fd = int(name)
                try:
                    os.fstat(fd)
                except OSError as error:
                    if error.errno != 9:
                        raise
                else:
                    opened.add(fd)
            return opened

        before = descriptors()

        def fork():
            pid = real_fork()
            if pid:
                children.append(pid)
            return pid

        try:
            with (
                mock.patch.object(os, "fork", side_effect=fork),
                mock.patch.object(
                    os, "pidfd_open", side_effect=OSError(24, "test pidfd exhaustion")
                ),
                self.assertRaises(OSError),
            ):
                self.test_real_descriptor_handoff_waits_for_parent_gate()
            self.assertEqual(len(children), 1)
            with self.assertRaises(ChildProcessError):
                os.waitpid(children[0], os.WNOHANG)
            self.assertEqual(descriptors(), before)
        finally:
            # Also contain the deliberately broken fixture during the RED run.
            for pid in children:
                try:
                    waited, _ = os.waitpid(pid, os.WNOHANG)
                    if waited == 0:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            for fd in descriptors() - before:
                try:
                    os.close(fd)
                except OSError as error:
                    if error.errno != 9:
                        raise

    def test_real_descriptor_handoff_waits_for_parent_gate(self):
        with tempfile.TemporaryDirectory() as path:
            jobs = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            null = os.open("/dev/null", os.O_RDONLY)
            pipes = [os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC) for _ in range(2)]
            control = socket.socketpair()
            gate = socket.socketpair()
            for sock in (*control, *gate):
                sock.setblocking(False)
            sources = {
                0: null,
                1: pipes[0][1],
                2: pipes[1][1],
                3: jobs,
                4: control[1].fileno(),
                5: gate[1].fileno(),
            }
            identities = {n: boot.fd_fact(fd)[0] for n, fd in sources.items()}
            end = boot.evidence.boottime() + 3_000_000_000
            pid = os.fork()
            if pid == 0:
                try:
                    boot.child_descriptors(sources, end)
                    boot.check_fds(boot.proc_fds(os.getpid()), identities, parked=False)
                    os.write(1, b"released")
                    os._exit(0)
                finally:
                    os._exit(99)
            pidfd = None
            reaped = False
            try:
                pidfd = os.pidfd_open(pid)
                self.assertEqual(
                    boot.transfer(gate[0].fileno(), 1, end, reading=True), b"P"
                )
                boot.check_fds(boot.proc_fds(pid), identities, parked=True)
                with self.assertRaises(BlockingIOError):
                    os.read(pipes[0][0], 16)
                boot.transfer(gate[0].fileno(), b"G", end)
                self.assertEqual(
                    boot.transfer(pipes[0][0], 8, end, reading=True), b"released"
                )
                waited, status = os.waitpid(pid, 0)
                reaped = True
                self.assertEqual((waited, os.waitstatus_to_exitcode(status)), (pid, 0))
            finally:
                if not reaped:
                    if pidfd is None:
                        # No other waiter can reuse this unreaped direct-child PID.
                        os.kill(pid, signal.SIGKILL)
                    else:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    os.waitpid(pid, 0)
                if pidfd is not None:
                    os.close(pidfd)
                os.close(jobs)
                os.close(null)
                for pair in pipes:
                    for fd in pair:
                        os.close(fd)
                for sock in (*control, *gate):
                    sock.close()


class GuestTopologyTests(unittest.TestCase):
    def model(self, changed=None):
        guest = boot.Guest({})
        controls = {
            "cgroup.type": "domain\n",
            "cgroup.procs": "",
            "evidence/cgroup.procs": "42\n",
            "cgroup.controllers": "cpu memory pids io\n",
            "cgroup.subtree_control": "cpu memory pids\n",
            "jobs/cgroup.subtree_control": "cpu memory pids\n",
            "jobs/cgroup.type": "domain\n",
            "jobs/cgroup.procs": "",
        }
        if changed:
            controls.update(changed)
        writes = []

        def control(name, value=None):
            if value is not None:
                writes.append((name, value))
                return None
            return controls[name]

        guest.control = control
        ns = tuple([("ns", 0)] * 10)
        status = b"Pid:\t42\nPPid:\t1\nUid:\t0 0 0 0\nGid:\t0 0 0 0\nThreads:\t1\nTracerPid:\t0\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000001000\nSigCgt:\t0000000000000000\n"

        def read(path, *_):
            if path == "/proc/self/status":
                return status
            if path == "/proc/self/mountinfo":
                return b"33 22 0:30 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
            if path.endswith("/children"):
                return b""
            if path.endswith("/name"):
                return b"irlume-job-status\n"
            raise AssertionError(path)

        fake_os = SimpleNamespace(**vars(os))
        fake_os.getpid = lambda: 42
        fake_os.open = mock.Mock(side_effect=range(100, 106))
        fake_os.mkdir = mock.Mock()
        fake_os.fstat = lambda fd: SimpleNamespace(
            st_uid=0, st_mode=(0o020000 if fd == 105 else 0o040700)
        )
        want = boot.runtime.Expected(
            boot.runtime.Identity(
                "run-01",
                "a" * 64,
                "0" * 8
                + "-"
                + "0" * 4
                + "-"
                + "0" * 4
                + "-"
                + "0" * 4
                + "-"
                + "0" * 12,
                "b" * 64,
                "c" * 64,
            ),
            41,
            ("supervisor-only",),
        )
        with (
            mock.patch.object(boot, "os", fake_os),
            mock.patch.object(boot, "read_file", side_effect=read),
            mock.patch.object(boot, "file_id", return_value=(1, 2)),
            mock.patch.object(boot, "namespaces", return_value=ns),
            mock.patch.object(
                boot,
                "membership",
                return_value="/system.slice/irlume-job-run-01.service/evidence",
            ),
            mock.patch.object(boot.Path, "resolve", return_value=Path("/dev/vport0p1")),
            mock.patch.object(boot.signal, "signal"),
        ):
            guest.preflight(want, True)
        return writes, fake_os

    def test_only_own_empty_subtree_is_created_and_read_back(self):
        writes, fake_os = self.model()
        self.assertEqual(
            writes,
            [
                ("cgroup.subtree_control", b"+cpu +memory +pids"),
                ("jobs/cgroup.subtree_control", b"+cpu +memory +pids"),
            ],
        )
        self.assertEqual(
            fake_os.mkdir.call_args_list[:2],
            [
                mock.call("managers", 0o700, dir_fd=100),
                mock.call("jobs", 0o700, dir_fd=100),
            ],
        )

    def test_missing_controllers_occupied_root_or_bad_readback_refuses(self):
        for key, value in [
            ("cgroup.type", "threaded\n"),
            ("cgroup.procs", "42\n"),
            ("evidence/cgroup.procs", "42 43\n"),
            ("cgroup.controllers", "memory pids\n"),
            ("jobs/cgroup.subtree_control", "cpu memory\n"),
            ("jobs/cgroup.type", "threaded\n"),
            ("jobs/cgroup.procs", "77\n"),
        ]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.model({key: value})


if __name__ == "__main__":
    unittest.main()
