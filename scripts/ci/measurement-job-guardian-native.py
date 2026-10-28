#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Concrete guardian ownership primitives; ordinary invocation is unavailable."""

import errno
import hashlib
import importlib.machinery
import importlib.util
import os
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import time
import types
from builtins import BaseExceptionGroup
from pathlib import Path

CLEANUP_FAILURES = (BaseException,)
HERE = Path(__file__).resolve().parent


class SourceLoader(importlib.machinery.SourceFileLoader):
    """Bootstrap from source without trusting this entry's adjacent caches."""

    def get_code(self, fullname):
        self.source = self.get_data(self.path)
        return self.source_to_code(self.source, self.path)


def load(name, path):
    loader = SourceLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    module.__source_sha256__ = hashlib.sha256(loader.source).hexdigest()
    return module


guardian = load("native_guardian", HERE / "measurement-job-guardian.py")
service = load("native_service", HERE / "measurement-job-guardian-service.py")
CODE = (
    "measurement-job-guardian.py",
    "measurement-job-guardian-native.py",
    "measurement-job-guardian-service.py",
    "measurement-job-guardian-host.py",
    "measurement-job.py",
    "measurement-job-evidence.py",
    "measurement-job-runtime.py",
)


def code_pins():
    rows = {
        name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in CODE
    }
    rows["python"] = hashlib.sha256(Path("/usr/bin/python3").read_bytes()).hexdigest()
    return rows


def process_start(pid):
    with open(f"/proc/{pid}/stat", "rb") as file:
        row = file.read(4097)
    head, separator, tail = row.rpartition(b") ")
    if (
        len(row) > 4096
        or not separator
        or not head.startswith(str(pid).encode() + b" (")
        or len(tail.split()) < 20
    ):
        raise ValueError("process start identity")
    return int(tail.split()[19])


def make_config(spec, origin):
    guardian.validate_spec(spec)
    config = {
        "scope": "contained-job-guardian-config-v1",
        "spec": guardian.launch_request(spec)["payload"],
        "origin_ns": origin,
        "client_pid": os.getpid(),
        "client_uid": os.getuid(),
        "client_gid": os.getgid(),
        "client_starttime": process_start(os.getpid()),
        "code_pins": code_pins(),
    }
    check_config(config)
    return config


def check_config(config):
    r = guardian.runtime
    r._fields(
        config,
        (
            "scope",
            "spec",
            "origin_ns",
            "client_pid",
            "client_uid",
            "client_gid",
            "client_starttime",
            "code_pins",
        ),
    )
    if config["scope"] != "contained-job-guardian-config-v1":
        raise ValueError("guardian config scope")
    r._integer(config["origin_ns"], 0, r.U64_MAX - guardian.HOST_NS - guardian.STOP_NS)
    r._integer(config["client_pid"], 2, 2**31 - 1)
    r._integer(config["client_uid"], 1, 2**32 - 2)
    r._integer(config["client_gid"], 0, 2**32 - 2)
    r._integer(config["client_starttime"], 1)
    r._fields(config["code_pins"], (*CODE, "python"))
    if any(
        type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None
        for value in config["code_pins"].values()
    ):
        raise ValueError("guardian code pin")
    values = config["spec"]
    r._fields(values, guardian.Specification._fields)
    if type(values["cases"]) is not list or type(values["cpus"]) is not list:
        raise ValueError("guardian config arrays")
    spec = guardian.Specification(
        **dict(values, cases=tuple(values["cases"]), cpus=tuple(values["cpus"]))
    )
    guardian.validate_spec(spec)
    return spec


def entry_argv(root, digest):
    return (
        "/usr/bin/python3",
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        "--service",
        str(root / "guardian-config.json"),
        digest,
    )


def raise_errors(label, errors):
    if len(errors) == 1:
        raise errors[0]
    if errors:
        raise BaseExceptionGroup(label, errors)


def private_directory(path):
    fd = service.open_directory(path)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("guardian directory must be owner-only")
        return fd
    except CLEANUP_FAILURES as error:
        errors = [error]
        try:
            os.close(fd)
        except CLEANUP_FAILURES as cleanup:
            errors.append(cleanup)
        raise_errors("directory acquisition", errors)


def protected_read(path, limit):
    parent = private_directory(path.parent)
    fd = None
    result = None
    errors = []
    try:
        fd = os.open(
            path.name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        start = os.fstat(fd)
        if (
            not stat.S_ISREG(start.st_mode)
            or start.st_uid != os.getuid()
            or start.st_mode & 0o077
            or not 0 < start.st_size <= limit
        ):
            raise ValueError("guardian protected file")
        data = bytearray()
        while len(data) <= limit:
            part = os.read(fd, min(4096, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        end = os.fstat(fd)
        keys = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if len(data) != start.st_size or any(
            getattr(start, key) != getattr(end, key) for key in keys
        ):
            raise ValueError("guardian protected file changed")
        result = bytes(data)
    except CLEANUP_FAILURES as error:
        errors.append(error)
    for owned in (fd, parent):
        if owned is not None:
            try:
                os.close(owned)
            except CLEANUP_FAILURES as error:
                errors.append(error)
    raise_errors("protected read and cleanup", errors)
    return result


def before(deadline):
    now = time.monotonic_ns()
    if type(deadline) is not int or now >= deadline:
        raise TimeoutError("guardian child deadline")
    return min(0.01, (deadline - now) / 1_000_000_000)


class ChildOwner:
    """One direct child. Keep this owner until reaped or the service aborts.

    No other actor may wait for this child. The service domain remains the
    external owner if Popen fails after possibly creating a process, or G dies.
    A failed constructor is never evidence that no process was created.
    """

    def __init__(self):
        self.attempted = False
        self.process = None
        self.pidfd = None
        self.reaped = False
        self.kill_attempted = False
        self.exit_sent = False
        self.eof = set()
        self.observations = []
        self.observation_count = 0
        self.wait = None
        self.last_read = None

    def spawn(self, argv, deadline, *, cwd="/"):
        if self.attempted:
            raise ValueError("guardian child slot already used")
        if (
            type(argv) is not tuple
            or not argv
            or not all(type(arg) is str and "\0" not in arg for arg in argv)
            or not argv[0].startswith("/")
        ):
            raise ValueError("guardian child argv")
        before(deadline)
        self.attempted = True
        # The slot predates Popen. On constructor uncertainty, the caller retains
        # its unit/domain intent and aborts; it must not invent a child PID.
        self.process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            close_fds=True,
            restore_signals=True,
            cwd=cwd,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.pidfd = os.pidfd_open(self.process.pid)
        os.set_inheritable(self.pidfd, False)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            os.set_blocking(stream.fileno(), False)
        before(deadline)
        return self.process.pid

    def observe(self):
        if self.reaped:
            return self.wait["exitcode"]
        if self.process is None:
            if self.attempted:
                raise ValueError("unresolved child construction")
            return None
        kind, value = (
            (os.P_PIDFD, self.pidfd)
            if self.pidfd is not None
            else (os.P_PID, self.process.pid)
        )
        result = os.waitid(kind, value, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if result is None:
            return None
        self.observation_count += 1
        if len(self.observations) < 16:
            self.observations.append(
                {
                    "pid": result.si_pid,
                    "code": result.si_code,
                    "status": result.si_status,
                }
            )
        if result.si_pid != self.process.pid or result.si_code not in (
            os.CLD_EXITED,
            os.CLD_KILLED,
            os.CLD_DUMPED,
        ):
            raise ValueError("unexpected direct-child wait")
        return (
            result.si_status if result.si_code == os.CLD_EXITED else -result.si_status
        )

    def event(self, deadline):
        wait = before(deadline)
        if not self.exit_sent:
            status = self.observe()
            if status is not None:
                self.exit_sent = True
                return "exit", status
        streams = {
            getattr(self.process, name).fileno(): name
            for name in ("stdout", "stderr")
            if getattr(self.process, name) is not None and name not in self.eof
        }
        ready = select.select(list(streams), [], [], wait)[0]
        if not ready:
            return None
        fd = ready[0]
        try:
            data = os.read(fd, 4096)
        except BlockingIOError:
            return None
        name = streams[fd]
        self.last_read = (name, data)
        if not data:
            self.eof.add(name)
            return name, None
        return name, data

    def stop(self, deadline):
        if self.reaped:
            return
        before(deadline)
        status = self.observe()
        if status is not None:
            return
        if self.process is None:
            raise ValueError("cannot signal an unknown child")
        if self.kill_attempted:
            return
        self.kill_attempted = True
        if self.pidfd is not None:
            signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
        else:
            # A failed pidfd acquisition still leaves this exact, unreaped
            # direct child. observe used WNOWAIT; no other waiter is allowed.
            os.kill(self.process.pid, signal.SIGKILL)
        before(deadline)

    def reap(self, deadline):
        before(deadline)
        if self.reaped:
            return self.wait
        for _ in range(65536):
            delay = before(deadline)
            status = self.observe()
            if status is not None:
                pid, raw = os.waitpid(self.process.pid, os.WNOHANG)
                self.wait = {
                    "pid": pid,
                    "status": raw,
                    "exitcode": None,
                }
                self.reaped = pid == self.process.pid
                if self.reaped:
                    self.process.returncode = status
                self.wait["exitcode"] = os.waitstatus_to_exitcode(raw)
                before(deadline)
                if not self.reaped or self.wait["exitcode"] != status:
                    raise ValueError("child terminal wait mismatch")
                return self.wait
            time.sleep(delay)
        raise ValueError("child reap event cap")

    def state(self):
        return {
            "attempted": self.attempted,
            "pid": None if self.process is None else self.process.pid,
            "spawn_uncertain": self.attempted and self.process is None,
            "reaped": self.reaped,
            "kill_attempted": self.kill_attempted,
            "wait": self.wait,
            "wait_observations": list(self.observations),
            "wait_observations_truncated": self.observation_count
            > len(self.observations),
            "eof": sorted(self.eof),
        }

    def close(self):
        errors = []
        if self.process is not None:
            for name in ("stdin", "stdout", "stderr"):
                stream = getattr(self.process, name)
                setattr(self.process, name, None)
                if stream is not None:
                    try:
                        stream.close()
                    except CLEANUP_FAILURES as error:
                        errors.append(error)
        if self.reaped and self.pidfd is not None:
            fd, self.pidfd = self.pidfd, None
            try:
                os.close(fd)
            except CLEANUP_FAILURES as error:
                errors.append(error)
        if errors:
            raise BaseExceptionGroup("child descriptor disposal", errors)


class GuardianEffects:
    """Concrete G effects; the caller supplies the protected H configuration."""

    def __init__(self, root, config, spec):
        self.root, self.config, self.spec = root, config, spec
        self.directory = private_directory(root)
        info = os.fstat(self.directory)
        self.directory_identity = info.st_dev, info.st_ino
        self.persisted_bytes = 0
        self.child = ChildOwner()
        self.channel = None
        self.service_snapshot = None
        self.finished_digest = None
        transaction = hashlib.sha256(
            guardian.encode(guardian.launch_request(spec))
        ).hexdigest()
        self.cancel_frame = guardian.encode(
            {"kind": "cancel", "payload": {"transaction_sha256": transaction}}
        )

    def now(self):
        return time.monotonic_ns()

    def preflight(self, spec, deadline):
        if self.config["client_uid"] != os.getuid() or os.geteuid() != os.getuid():
            raise ValueError("guardian UID")
        before(deadline)
        bus = service.SystemdBus(os.getuid(), deadline=deadline)
        errors = []
        try:
            self.service_snapshot = bus.observe(guardian.unit_name(spec), deadline)
        except CLEANUP_FAILURES as error:
            errors.append(error)
        try:
            bus.close()
        except CLEANUP_FAILURES as error:
            errors.append(error)
        raise_errors("guardian service observation", errors)
        row = self.service_snapshot
        keys = set(guardian.service_properties(spec)) - {"AddRef"}
        keys |= set(service.UNIT_TYPES) | {
            "MainPID",
            "ControlGroup",
            "ExecMainStartTimestampMonotonic",
        }
        identity = guardian.check_service(
            {key: row[key] for key in keys}, spec, os.getpid(), os.getuid(), self.now()
        )
        expected_argv = entry_argv(
            self.root,
            hashlib.sha256(guardian.evidence.canonical(self.config)).hexdigest(),
        )
        if row["ExecStart"] != ((expected_argv[0], expected_argv, False),):
            raise ValueError("guardian executable binding")
        with open("/proc/self/cgroup", encoding="ascii") as file:
            membership = file.read(4097)
        if membership != "0::" + identity.cgroup + "\n" or os.sched_getaffinity(
            0
        ) != set(spec.cpus):
            raise ValueError("guardian effective placement")
        if process_start(self.config["client_pid"]) != self.config["client_starttime"]:
            raise ValueError("guardian client identity")
        info = os.stat("control.sock", dir_fd=self.directory, follow_symlinks=False)
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("guardian control endpoint")
        connected = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC,
        )
        try:
            for _ in range(guardian.IO_LIMIT):
                delay = before(deadline)
                error = connected.connect_ex(str(self.root / "control.sock"))
                if error in (0, errno.EISCONN):
                    break
                if error not in (errno.EAGAIN, errno.EINPROGRESS, errno.EALREADY):
                    raise OSError(error, "guardian connect")
                select.select([], [connected], [], delay)
            else:
                raise ValueError("guardian connection event cap")
            self.channel = guardian.PeerChannel(
                connected,
                (
                    self.config["client_pid"],
                    self.config["client_uid"],
                    self.config["client_gid"],
                ),
            )
        except BaseException:
            connected.close()
            raise
        before(deadline)
        return identity

    def receive(self, deadline):
        return self.channel.receive(deadline)

    def send(self, data, deadline):
        self.channel.send(data, deadline)

    def require_idle(self, deadline):
        self.channel.require_idle(deadline, cancel_frame=self.cancel_frame)

    def spawn(self, spec, deadline):
        return self.child.spawn(guardian.qemu_argv(spec), deadline)

    def event(self, deadline):
        return self.child.event(deadline)

    def owner_state(self):
        return self.child.state()

    def stop(self, deadline):
        self.child.stop(deadline)

    def reap(self, deadline):
        return self.child.reap(deadline)

    def close_child(self):
        self.child.close()

    def record(self, kind, row, deadline):
        if (
            kind not in ("started", "spawn-intent", "spawned", "finished", "failed")
            or self.directory is None
        ):
            raise ValueError("guardian receipt state")
        data = guardian.evidence.canonical(row) + b"\n"
        if (
            self.persisted_bytes + len(data)
            > guardian.evidence.LEDGER_LIMIT - guardian.HOST_RECEIPT_BUDGET
        ):
            raise ValueError("guardian receipt byte cap")
        before(deadline)
        fd = os.open(
            "guardian-" + kind + ".json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self.directory,
        )
        self.persisted_bytes += len(data)
        errors = []
        try:
            offset = 0
            while offset < len(data):
                before(deadline)
                count = os.write(fd, data[offset:])
                if count <= 0:
                    raise OSError("short guardian receipt write")
                offset += count
            os.fsync(fd)
        except CLEANUP_FAILURES as error:
            errors.append(error)
        try:
            os.close(fd)
        except CLEANUP_FAILURES as error:
            errors.append(error)
        try:
            before(deadline)
            os.fsync(self.directory)
            before(deadline)
        except CLEANUP_FAILURES as error:
            errors.append(error)
        if errors:
            raise BaseExceptionGroup("guardian receipt failure", errors)
        return len(data), hashlib.sha256(data).hexdigest()

    def finalize(self, row, deadline):
        result = self.record("finished", row, deadline)
        self.finished_digest = result[1]
        self.close_directory()
        before(deadline)
        return result

    def failed(self, row, deadline):
        if self.directory is None:
            self.directory = private_directory(self.root)
            info = os.fstat(self.directory)
            if (info.st_dev, info.st_ino) != self.directory_identity:
                raise ValueError("guardian receipt directory replaced")
        if self.finished_digest is not None:
            row = {
                key: value
                for key, value in row.items()
                if key not in ("stdout_hex", "stderr_hex")
            }
            row["prior_finished_sha256"] = self.finished_digest
        if self.channel is not None:
            row = dict(row, control=self.channel.diagnostics())
        self.record("failed", row, deadline)
        self.close_directory()

    def close_control(self):
        if self.channel is not None:
            self.channel.close()

    def close_directory(self):
        if self.directory is not None:
            fd, self.directory = self.directory, None
            os.close(fd)


def run_service(argv, *, _module=None):
    if (
        len(argv) != 4
        or argv[1] != "--service"
        or re.fullmatch("[0-9a-f]{64}", argv[3]) is None
    ):
        return 77
    path = Path(argv[2])
    if path.name != "guardian-config.json" or not path.is_absolute():
        return 77
    data = protected_read(path, 65536)
    if hashlib.sha256(data).hexdigest() != argv[3]:
        return 77
    config = guardian.runtime._json(data)
    if (
        type(config) is dict
        and config.get("scope") == "contained-job-rooted-startup-config-v1"
    ):
        if (
            argv[2] != "/run/irlume/attempt/guardian-config.json"
            or type(_module) is not types.ModuleType
            or _module.__dict__.get("run_service") is not run_service
        ):
            return 77
        rooted = load("rooted_native", HERE / "measurement-job-rooted-native.py")
        return rooted.run_service(data, argv[3], _module, rooted)
    spec = check_config(config)
    if config["code_pins"] != code_pins():
        return 77
    effects = GuardianEffects(path.parent, config, spec)
    try:
        guardian.run_guardian(effects, spec, config["origin_ns"])
    finally:
        effects.close_directory()
    return 0


if __name__ == "__main__":
    try:
        STATUS = run_service(sys.argv, _module=sys.modules[__name__])
    except CLEANUP_FAILURES:
        STATUS = 77
    os._exit(STATUS)
