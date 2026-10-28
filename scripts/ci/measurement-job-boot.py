#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Fixed boot-only E/M integration; no native manager or provider is imported."""

import base64
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import os
import re
import select
import signal
import socket
import stat
import struct
import sys
from pathlib import Path


class SourceLoader(importlib.machinery.SourceFileLoader):
    """Bootstrap from source without trusting this entry's adjacent caches."""

    def get_code(self, fullname):
        self.source = self.get_data(self.path)
        return self.source_to_code(self.source, self.path)


LOADER = SourceLoader(
    "boot_evidence", str(Path(__file__).with_name("measurement-job-evidence.py"))
)
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
evidence = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(evidence)
evidence.__source_sha256__ = hashlib.sha256(LOADER.source).hexdigest()
runtime = evidence.runtime

CONFIG = "/opt/irlume/measurement-job-boot.json"
INSTALLED = {
    name: "/opt/irlume/" + name
    for name in (
        "measurement-job-evidence.py",
        "measurement-job-runtime.py",
        "measurement-job-boot.py",
        "measurement-job-guest.sh",
    )
}
STATE = "/var/lib/irlume-job-evidence"
STATUS_PORT = "/dev/virtio-ports/irlume-job-status"


def make_payload(source_directory, *, run_id, base_sha256, python_sha256, first_epoch):
    """Render fixed NoCloud user-data; produce bytes only, never execute it.

    base_sha256 identifies the separately pinned base, not these self-containing
    payload bytes. input_manifest_sha256 covers this selection and source hashes;
    the enclosing payload's digest belongs to the later host input transaction.
    """
    runtime._identifier(run_id)
    runtime._integer(first_epoch, 1)
    for value in (base_sha256, python_sha256):
        if (
            type(value) is not str
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
        ):
            raise ValueError("invalid input digest")
    sources = {}
    files = []
    for name, target in INSTALLED.items():
        data = (source_directory / name).read_bytes()
        if not 0 < len(data) <= 128 * 1024:
            raise ValueError("source size")
        sources[name] = hashlib.sha256(data).hexdigest()
        files.append(
            {
                "path": target,
                "owner": "root:root",
                "permissions": "0500",
                "encoding": "b64",
                "content": base64.b64encode(data).decode("ascii"),
            }
        )
    unit = (source_directory / "measurement-job-guest.service.in").read_text()
    sources["measurement-job-guest.service.in"] = hashlib.sha256(
        unit.encode()
    ).hexdigest()
    config = {
        "scope": "contained-job-boot-input-v1",
        "mode": "boot-only",
        "run_id": run_id,
        "base_sha256": base_sha256,
        "python_sha256": python_sha256,
        "first_epoch": first_epoch,
        "sources": sources,
    }
    config["input_manifest_sha256"] = hashlib.sha256(
        evidence.canonical(config)
    ).hexdigest()
    unit_name = f"irlume-job-{run_id}.service"
    files.extend(
        [
            {
                "path": CONFIG,
                "owner": "root:root",
                "permissions": "0400",
                "content": evidence.canonical(config).decode("ascii") + "\n",
            },
            {
                "path": "/etc/systemd/system/" + unit_name,
                "owner": "root:root",
                "permissions": "0400",
                "content": unit,
            },
        ]
    )
    user_data = {
        "write_files": files,
        "runcmd": [
            ["systemctl", "mask", "serial-getty@ttyS0.service"],
            ["systemctl", "daemon-reload"],
            ["systemctl", "start", unit_name],
        ],
    }
    return b"#cloud-config\n" + evidence.canonical(user_data) + b"\n", config


def metadata(config):
    check_config(config)
    return (
        evidence.canonical(
            {
                "instance-id": "irlume-job-"
                + config["run_id"]
                + "-"
                + config["input_manifest_sha256"]
            }
        )
        + b"\n"
    )


def check_config(config):
    runtime._fields(
        config,
        (
            "scope",
            "mode",
            "run_id",
            "base_sha256",
            "python_sha256",
            "first_epoch",
            "sources",
            "input_manifest_sha256",
        ),
    )
    if (
        config["scope"] != "contained-job-boot-input-v1"
        or config["mode"] != "boot-only"
    ):
        raise ValueError("boot input scope")
    runtime._identifier(config["run_id"])
    runtime._integer(config["first_epoch"], 1)
    runtime._fields(config["sources"], (*INSTALLED, "measurement-job-guest.service.in"))
    for value in (
        *config["sources"].values(),
        config["base_sha256"],
        config["python_sha256"],
        config["input_manifest_sha256"],
    ):
        if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
            raise ValueError("boot input digest")
    selected = {
        key: value for key, value in config.items() if key != "input_manifest_sha256"
    }
    if (
        hashlib.sha256(evidence.canonical(selected)).hexdigest()
        != config["input_manifest_sha256"]
    ):
        raise ValueError("boot input manifest changed")


def check_mount(text):
    matches = []
    for line in text.splitlines():
        left, separator, right = line.partition(" - ")
        fields = left.split()
        if len(fields) >= 6 and fields[4] == "/sys/fs/cgroup":
            matches.append(
                separator and fields[3] == "/" and right.split()[:1] == ["cgroup2"]
            )
    if matches != [True]:
        raise ValueError("unshifted cgroup2 mount required")


def check_status(text, pid, parent, *, default_signals):
    values = {}
    names = {
        "Pid",
        "PPid",
        "Uid",
        "Gid",
        "Threads",
        "TracerPid",
        "SigBlk",
        "SigIgn",
        "SigCgt",
    }
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        if separator and name in names:
            if name in values:
                raise ValueError("duplicate status field")
            values[name] = value.split()
    if set(values) != names:
        raise ValueError("missing status field")
    for name, expected in (
        ("Pid", [str(pid)]),
        ("PPid", [str(parent)]),
        ("Threads", ["1"]),
        ("TracerPid", ["0"]),
        ("Uid", ["0"] * 4),
        ("Gid", ["0"] * 4),
    ):
        if values[name] != expected:
            raise ValueError("unexpected process posture")
    if default_signals and any(
        values[n] != ["0000000000000000"] for n in ("SigBlk", "SigIgn", "SigCgt")
    ):
        raise ValueError("nondefault signal state")


def read_file(path, limit=65536):
    with open(path, "rb") as file:
        data = file.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file cap")
    return data


def trusted_file(path, limit=128 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or not 0 < info.st_size <= limit
        ):
            raise ValueError("untrusted boot file")
        data = bytearray()
        while len(data) <= limit:
            part = os.read(fd, min(4096, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        after = os.fstat(fd)
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            any(getattr(info, k) != getattr(after, k) for k in fields)
            or len(data) != info.st_size
        ):
            raise ValueError("boot file changed")
        return bytes(data)
    finally:
        os.close(fd)


NS_NAMES = (
    "user",
    "mnt",
    "pid",
    "net",
    "ipc",
    "uts",
    "cgroup",
    "time",
    "pid_for_children",
    "time_for_children",
)


def file_id(path):
    value = os.stat(path)
    return (value.st_dev, value.st_ino)


def namespaces(pid):
    return tuple(file_id(f"/proc/{pid}/ns/{name}") for name in NS_NAMES)


def membership(pid):
    value = read_file(f"/proc/{pid}/cgroup", 4096).decode("ascii")
    if (
        not value.startswith("0::/")
        or not value.endswith("\n")
        or value.count("\n") != 1
    ):
        raise ValueError("unexpected cgroup membership")
    return value[3:-1]


def fd_fact(fd):
    value = os.fstat(fd)
    return (
        (value.st_dev, value.st_ino),
        value.st_mode,
        value.st_rdev,
        fcntl.fcntl(fd, fcntl.F_GETFL),
    )


def proc_fds(pid):
    facts = {}
    for name in os.listdir(f"/proc/{pid}/fd"):
        try:
            value = os.stat(f"/proc/{pid}/fd/{name}")
        except FileNotFoundError:
            # Self enumeration may include its own now-closed directory fd.
            if str(pid) == str(os.getpid()):
                continue
            raise
        info = read_file(f"/proc/{pid}/fdinfo/{name}", 4096).decode("ascii")
        flags = [
            line.split()[1] for line in info.splitlines() if line.startswith("flags:\t")
        ]
        if len(flags) != 1:
            raise ValueError("descriptor flags")
        facts[int(name)] = (
            (value.st_dev, value.st_ino),
            value.st_mode,
            value.st_rdev,
            int(flags[0], 8),
        )
    return facts


def check_fds(facts, identities, *, parked):
    wanted = set(range(6 if parked else 5))
    if set(facts) != wanted or not wanted <= set(identities):
        raise ValueError("descriptor inventory")
    if len({fact[0] for fact in facts.values()}) != len(facts):
        raise ValueError("descriptor alias")
    for n, (identity, mode, device, flags) in facts.items():
        if identity != identities[n] or flags & os.O_PATH:
            raise ValueError("descriptor identity")
        access = flags & os.O_ACCMODE
        if n == 0:
            valid = (
                stat.S_ISCHR(mode)
                and os.major(device) == 1
                and os.minor(device) == 3
                and access == os.O_RDONLY
            )
        elif n in (1, 2):
            valid = (
                stat.S_ISFIFO(mode)
                and access == os.O_WRONLY
                and bool(flags & os.O_NONBLOCK)
            )
        elif n == 3:
            valid = stat.S_ISDIR(mode) and access == os.O_RDONLY
        else:
            valid = (
                stat.S_ISSOCK(mode)
                and access == os.O_RDWR
                and bool(flags & os.O_NONBLOCK)
            )
        if not valid:
            raise ValueError("descriptor role")


def transfer(fd, value, deadline, *, reading=False):
    """One exact bounded transfer on a nonblocking owned channel."""
    if reading:
        if type(value) is not int or not 0 < value <= runtime.MAX_FRAME + 4:
            raise ValueError("read limit")
        output = bytearray()
    else:
        if type(value) is not bytes or not 0 < len(value) <= runtime.MAX_FRAME + 4:
            raise ValueError("write limit")
        offset = 0
    for _ in range(evidence.EVENT_LIMIT):
        if evidence.boottime() >= deadline:
            raise TimeoutError("transfer deadline")
        try:
            if reading:
                part = os.read(fd, value - len(output))
                if not part:
                    raise ValueError("channel EOF")
                output.extend(part)
                done = len(output) == value
            else:
                count = os.write(fd, value[offset:])
                if count <= 0:
                    raise ValueError("short write")
                offset += count
                done = offset == len(value)
            if done:
                if evidence.boottime() >= deadline:
                    raise TimeoutError("late transfer")
                return bytes(output) if reading else None
        except (BlockingIOError, InterruptedError):
            remaining = max(0, deadline - evidence.boottime()) / 1_000_000_000
            select.select(
                [fd] if reading else [],
                [] if reading else [fd],
                [],
                min(0.01, remaining),
            )
    raise ValueError("transfer operation cap")


def child_descriptors(sources, deadline):
    """In an already-forked inert child, install exact roles and wait for E."""
    if set(sources) != set(range(6)):
        raise ValueError("child descriptor sources")
    copies = {
        n: fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 64) for n, fd in sources.items()
    }
    for n, fd in copies.items():
        os.dup2(fd, n, inheritable=True)
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd > 5:
            try:
                os.close(fd)
            except OSError as error:
                if error.errno != 9:  # The directory enumerator already closed itself.
                    raise
    for number in signal.valid_signals() - {signal.SIGKILL, signal.SIGSTOP}:
        signal.signal(number, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_SETMASK, [])
    transfer(5, b"P", deadline)
    if transfer(5, 1, deadline, reading=True) != b"G":
        raise ValueError("child gate")
    os.close(5)


def inert_main(want, sequence, origin, deadline, identities, reference_ns, parent):
    """Only checks the boot handoff and reports it. Creates no job or descendants."""
    pid = os.getpid()
    check_status(
        read_file("/proc/self/status").decode(), pid, parent, default_signals=True
    )
    if namespaces(pid) != reference_ns or namespaces(1) != reference_ns:
        raise ValueError("child namespaces")
    if (
        membership(pid)
        != f"/system.slice/irlume-job-{want.identity.run_id}.service/managers"
    ):
        raise ValueError("child placement")
    if read_file(f"/proc/self/task/{pid}/children", 4096).strip():
        raise ValueError("child descendants")
    channel = socket.socket(fileno=4)
    try:
        peer = struct.unpack(
            "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if (
            channel.family != socket.AF_UNIX
            or channel.type != socket.SOCK_STREAM
            or peer != (parent, 0, 0)
        ):
            raise ValueError("child control peer")
    finally:
        channel.detach()
    parentfd = os.pidfd_open(parent)
    try:
        if select.select([parentfd], [], [], 0)[0] or os.getppid() != parent:
            raise ValueError("parent lost")
    finally:
        os.close(parentfd)
    check_fds(proc_fds(pid), identities, parked=False)
    startup_end = min(deadline, origin + 5_000_000_000)
    packet = transfer(4, 236, startup_end, reading=True)
    if packet != evidence.request_packet(want, sequence, origin, parent, identities[3]):
        raise ValueError("child request")
    try:
        os.read(4, 1)
    except BlockingIOError:
        pass
    else:
        raise ValueError("child request surplus or EOF")
    # Exercise the distinct report pipe only after disposing the E control fd.
    os.close(4)
    os.close(3)
    record = evidence.canonical(
        {
            "scope": "contained-job-boot-v1",
            "identity": want.identity._asdict(),
            "sequence": sequence,
            "epoch": want.first_epoch + sequence,
            "pid": pid,
            "checked": True,
            "native_authorized": False,
            "full_contract_proven": False,
        }
    )
    transfer(1, len(record).to_bytes(4, "big") + record, deadline)
    os.close(1)
    os.close(2)
    if evidence.boottime() >= deadline:
        raise TimeoutError("late inert exit")
    os._exit(0)


class Guest:
    """Concrete boot-only effects. Live entry is fixed to the installed service.

    A failure leaves the started child with this object and rejects the run.
    The guest unit/G owns abort termination; E never certifies native cleanup.
    """

    def __init__(self, config):
        self.config = config
        self.active = None
        self.partial = None
        self.root = self.jobs = self.ledger = self.directory = self.state = (
            self.port
        ) = None

    def now(self):
        return evidence.boottime()

    def control(self, name, value=None):
        flags = os.O_RDONLY if value is None else os.O_WRONLY
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.root)
        try:
            if value is None:
                data = os.read(fd, 4097)
                if len(data) > 4096:
                    raise ValueError("cgroup control cap")
                return data.decode("ascii")
            if os.write(fd, value) != len(value):
                raise ValueError("short cgroup write")
        finally:
            os.close(fd)

    def preflight(self, want, boot_only):
        if not boot_only or want.cases != ("supervisor-only",):
            raise ValueError("this payload is boot-only")
        pid = os.getpid()
        check_status(
            read_file("/proc/self/status").decode(), pid, 1, default_signals=False
        )
        if read_file(f"/proc/self/task/{pid}/children", 4096).strip():
            raise ValueError("E already has children")
        self.reference_ns = namespaces(pid)
        if (
            self.reference_ns != namespaces(1)
            or self.reference_ns[2] != self.reference_ns[8]
            or self.reference_ns[7] != self.reference_ns[9]
        ):
            raise ValueError("E initial namespace view")
        if file_id("/") != file_id("/proc/1/root") or file_id(".") != file_id("/"):
            raise ValueError("E root view")
        check_mount(read_file("/proc/self/mountinfo").decode())
        self.unit = f"/system.slice/irlume-job-{want.identity.run_id}.service"
        if membership(pid) != self.unit + "/evidence":
            raise ValueError("E service placement")
        self.root = os.open(
            "/sys/fs/cgroup" + self.unit,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        if (
            self.control("cgroup.type") != "domain\n"
            or self.control("cgroup.procs").strip()
        ):
            raise ValueError("service root is not an empty domain")
        if self.control("evidence/cgroup.procs").split() != [str(pid)]:
            raise ValueError("E not exclusive")
        if not {"cpu", "memory", "pids"} <= set(
            self.control("cgroup.controllers").split()
        ):
            raise ValueError("missing delegated controllers")
        for name in ("managers", "jobs"):
            os.mkdir(name, 0o700, dir_fd=self.root)
        self.control("cgroup.subtree_control", b"+cpu +memory +pids")
        self.control("jobs/cgroup.subtree_control", b"+cpu +memory +pids")
        if set(self.control("jobs/cgroup.subtree_control").split()) != {
            "cpu",
            "memory",
            "pids",
        }:
            raise ValueError("jobs controller readback")
        if (
            self.control("jobs/cgroup.type") != "domain\n"
            or self.control("jobs/cgroup.procs").strip()
        ):
            raise ValueError("jobs not empty domain")
        self.jobs = os.open(
            "jobs",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=self.root,
        )
        self.state = os.open(
            STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        if os.fstat(self.state).st_uid != 0 or os.fstat(self.state).st_mode & 0o077:
            raise ValueError("state directory protection")
        os.mkdir(want.identity.run_id, 0o700, dir_fd=self.state)
        self.directory = os.open(
            want.identity.run_id,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=self.state,
        )
        self.ledger = os.open(
            "ledger.jsonl",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self.directory,
        )
        target = Path(STATUS_PORT).resolve(strict=True)
        if re.fullmatch(
            r"vport[0-9]+p[0-9]+", target.name
        ) is None or target.parent != Path("/dev"):
            raise ValueError("status device path")
        if (
            read_file("/sys/class/virtio-ports/" + target.name + "/name", 256).strip()
            != b"irlume-job-status"
        ):
            raise ValueError("status device identity")
        self.port = os.open(
            target, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        if not stat.S_ISCHR(os.fstat(self.port).st_mode):
            raise ValueError("status device type")
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)

    def start(self, want, sequence, origin, deadline, boot_only):
        if not boot_only or self.active is not None or self.partial is not None:
            raise ValueError("inert manager already owned or wrong mode")
        null = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        report = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        diagnostic = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        channels = [
            socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_STREAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK,
            )
            for _ in range(2)
        ]
        control, gate = [tuple(s.detach() for s in pair) for pair in channels]
        sources = {
            0: null,
            1: report[1],
            2: diagnostic[1],
            3: self.jobs,
            4: control[1],
            5: gate[1],
        }
        identities = {n: fd_fact(fd)[0] for n, fd in sources.items()}
        parent = os.getpid()
        pid = os.fork()
        if pid == 0:
            try:
                child_descriptors(sources, min(deadline, origin + 5_000_000_000))
                inert_main(
                    want,
                    sequence,
                    origin,
                    deadline,
                    identities,
                    self.reference_ns,
                    parent,
                )
            finally:
                os._exit(77)
        self.partial = pid  # Retained before pidfd acquisition or any close can fail.
        self.active = evidence.ChildStreams(
            pid, os.pidfd_open(pid), report[0], diagnostic[0], control[0]
        )
        self.partial = None
        self.gate = gate[0]
        for fd in (null, report[1], diagnostic[1], control[1], gate[1]):
            os.close(fd)
        startup_end = min(deadline, origin + 5_000_000_000)
        if transfer(self.gate, 1, startup_end, reading=True) != b"P":
            raise ValueError("parked manager handshake")
        check_status(
            read_file(f"/proc/{pid}/status").decode(), pid, parent, default_signals=True
        )
        if namespaces(pid) != self.reference_ns or not self.active.alive():
            raise ValueError("parked manager view/lifetime")
        self.control("managers/cgroup.procs", str(pid).encode("ascii"))
        if membership(pid) != self.unit + "/managers" or self.control(
            "managers/cgroup.procs"
        ).split() != [str(pid)]:
            raise ValueError("manager placement readback")
        check_fds(proc_fds(pid), identities, parked=True)
        transfer(
            control[0],
            evidence.request_packet(want, sequence, origin, parent, identities[3]),
            startup_end,
        )
        transfer(self.gate, b"G", startup_end)
        fd, self.gate = self.gate, None
        os.close(fd)
        return self.active

    def event(self, child, deadline):
        return child.event(deadline)

    def alive(self, child):
        return child.alive()

    def quiescent(self, child):
        return child.quiescent()

    def close_case(self, child, quarantined):
        child.close(quarantined)
        if not quarantined:
            self.active = None

    def append(self, data):
        offset = 0
        while offset < len(data):
            count = os.write(self.ledger, data[offset:])
            if count <= 0:
                raise ValueError("short ledger write")
            offset += count

    def sync_ledger(self):
        os.fsync(self.ledger)

    def sync_directory(self):
        os.fsync(self.directory)
        os.fsync(self.state)

    def close_ledger(self):
        fd, self.ledger = self.ledger, None
        os.close(fd)

    def close_directory(self):
        for name in ("directory", "state"):
            fd = getattr(self, name)
            setattr(self, name, None)
            os.close(fd)

    def terminal(self, data, deadline):
        transfer(self.port, data, deadline)

    def close_port(self):
        fd, self.port = self.port, None
        os.close(fd)

    def poweroff(self, deadline):
        if self.now() >= deadline:
            raise TimeoutError("poweroff deadline")
        # Replace E with one fixed no-block request; the existing guest service
        # deadline remains the independent bound, including a stalled helper.
        os.execve("/usr/bin/systemctl", ["systemctl", "--no-block", "poweroff"], {})


def main():
    # An ordinary source-tree invocation cannot reach guest writes or poweroff.
    if (
        len(sys.argv) != 1
        or not sys.flags.isolated
        or os.geteuid() != 0
        or os.getppid() != 1
        or Path(__file__).resolve() != Path(INSTALLED["measurement-job-boot.py"])
    ):
        return 77
    config = runtime._json(trusted_file(CONFIG, 8192))
    check_config(config)
    for name, expected in config["sources"].items():
        target = INSTALLED.get(
            name, "/etc/systemd/system/irlume-job-" + config["run_id"] + ".service"
        )
        if hashlib.sha256(trusted_file(target)).hexdigest() != expected:
            raise ValueError("installed boot source mismatch")
    interpreter = os.readlink("/proc/self/exe")
    if (
        hashlib.sha256(trusted_file(interpreter, 64 * 1024 * 1024)).hexdigest()
        != config["python_sha256"]
    ):
        raise ValueError("interpreter mismatch")
    boot_id = read_file("/proc/sys/kernel/random/boot_id", 64).decode("ascii").strip()
    identity = runtime.Identity(
        config["run_id"],
        config["base_sha256"],
        boot_id,
        config["sources"]["measurement-job-boot.py"],
        config["input_manifest_sha256"],
    )
    want = runtime.Expected(identity, config["first_epoch"], ("supervisor-only",))
    evidence.collect(Guest(config), want, boot_only=True)
    return 77  # A real successful poweroff request replaced this process.


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TimeoutError):
        print(
            "measurement-job: qualified M/E boot-only preconditions unavailable",
            file=sys.stderr,
        )
        raise SystemExit(77)
