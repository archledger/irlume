#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""One referenced transient service; importing this module touches no bus."""

import fcntl
import hashlib
import json
import os
import pwd
import re
import stat
import time
from builtins import BaseExceptionGroup
from pathlib import Path

CLEANUP_FAILURES = (BaseException,)

BUS_NAME = "org.freedesktop.systemd1"
MANAGER_PATH = "/org/freedesktop/systemd1"
MANAGER = BUS_NAME + ".Manager"
PROPERTY_TYPES = {
    "Type": "s",
    "ExitType": "s",
    "Restart": "s",
    "NotifyAccess": "s",
    "RemainAfterExit": "b",
    "RuntimeMaxUSec": "t",
    "RuntimeRandomizedExtraUSec": "t",
    "TimeoutStartUSec": "t",
    "TimeoutStopUSec": "t",
    "KillMode": "s",
    "KillSignal": "i",
    "FinalKillSignal": "i",
    "SendSIGKILL": "b",
    "NoNewPrivileges": "b",
    "CPUQuotaPerSecUSec": "t",
    "CPUAffinity": "ay",
    "MemoryMax": "t",
    "MemorySwapMax": "t",
    "TasksMax": "t",
    "ExecStartPre": "commands",
    "ExecStartPost": "commands",
    "ExecStop": "commands",
    "ExecStopPost": "commands",
    "MainPID": "u",
    "ControlGroup": "s",
    "ExecMainStartTimestampMonotonic": "t",
    "ExecMainExitTimestampMonotonic": "t",
    "ExecMainCode": "i",
    "ExecMainStatus": "i",
    "Result": "s",
    "ExecStart": "commands",
}
UNIT_TYPES = {
    "Id": "s",
    "InvocationID": "ay",
    "ActiveState": "s",
    "SubState": "s",
    "Transient": "b",
    "ActiveEnterTimestampMonotonic": "t",
}


class SystemdBus:
    """Private broker connection. Only explicit methods create or stop a unit."""

    def __init__(self, uid, *, deadline, _address=None, _socket_factory=None):
        if (
            type(uid) is not int
            or uid <= 0
            or uid != os.getuid()
            or os.geteuid() != uid
        ):
            raise ValueError("guardian requires the caller's unprivileged user bus")
        import jeepney
        from jeepney.io.blocking import prep_socket

        if jeepney.__version__ != "0.9.0":
            raise ValueError("unreviewed Jeepney version")
        self.protocol = jeepney
        self.socket = None
        self.closed = False
        self.last_partial = {}
        self.serial = 0
        self.parser = jeepney.Parser()
        try:
            # prep_socket bounds connect and authentication and closes its
            # partial socket on failure. Hello is deliberately not delegated to
            # DBusConnection.__init__, whose default reply wait is unbounded.
            self.socket = (_socket_factory or prep_socket)(
                _address or f"/run/user/{uid}/bus",
                enable_fds=False,
                timeout=self.remaining(deadline),
            )
            self.socket.set_inheritable(False)
            self.unique_name = self.call(
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "Hello",
                "",
                (),
                deadline,
                destination="org.freedesktop.DBus",
                expected="s",
            )
            if (
                type(self.unique_name) is not str
                or re.fullmatch(r":[A-Za-z0-9_.-]+", self.unique_name) is None
            ):
                raise ValueError("invalid user-bus unique name")
            self.remaining(deadline)
        except BaseException as error:
            try:
                self.close()
            except CLEANUP_FAILURES as cleanup:
                raise BaseExceptionGroup(
                    "user-bus establishment and cleanup", [error, cleanup]
                ) from error
            raise

    def remaining(self, deadline):
        remaining = deadline - time.monotonic_ns()
        if self.closed or remaining <= 0:
            raise TimeoutError("user-bus deadline or closed connection")
        return min(5, remaining / 1_000_000_000)

    def call(
        self,
        path,
        interface,
        method,
        signature,
        args,
        deadline,
        *,
        destination=BUS_NAME,
        expected=None,
    ):
        protocol = self.protocol
        expected = expected or {"GetAll": "a{sv}", "GetUnitProcesses": "a(sus)"}.get(
            method, "o"
        )
        message = protocol.new_method_call(
            protocol.DBusAddress(path, bus_name=destination, interface=interface),
            method,
            signature,
            tuple(args),
        )
        self.serial += 1
        data = message.serialise(serial=self.serial)
        if len(data) > 1024 * 1024:
            raise ValueError("user-bus request cap")
        self.socket.settimeout(self.remaining(deadline))
        self.socket.sendall(data)
        received = 0
        for _ in range(4096):
            reply = self.parser.get_next_message()
            if reply is None:
                wanted = self.parser.bytes_desired()
                if not 0 < wanted <= 1024 * 1024:
                    raise ValueError("user-bus message cap")
                self.socket.settimeout(self.remaining(deadline))
                chunk = self.socket.recv(min(4096, wanted))
                if not chunk:
                    raise ConnectionError("user bus disconnected")
                received += len(chunk)
                if received > 1024 * 1024:
                    raise ValueError("user-bus reply cap")
                self.parser.add_data(chunk)
                continue
            fields = reply.header.fields
            if fields.get(protocol.HeaderFields.reply_serial) != self.serial:
                self.remaining(deadline)
                continue
            if reply.header.message_type == protocol.MessageType.error:
                raise RuntimeError(
                    "user-bus error: "
                    + str(fields.get(protocol.HeaderFields.error_name, "unknown"))[:256]
                )
            if (
                reply.header.message_type != protocol.MessageType.method_return
                or fields.get(protocol.HeaderFields.signature, "") != expected
                or len(reply.body) != 1
            ):
                raise ValueError("user-bus reply signature")
            # The owner stores this result before its post-call deadline check.
            return reply.body[0]
        raise ValueError("user-bus event cap")

    def variant(self, kind, value):
        scalar = {"s": str, "t": int, "u": int, "i": int, "b": bool}
        if kind in scalar:
            if type(value) is not scalar[kind]:
                raise ValueError("transient property scalar type")
            return kind, value
        if kind == "ay":
            return kind, bytes(value)
        if kind == "commands":
            return "a(sasb)", [
                (path, list(argv), ignore) for path, argv, ignore in value
            ]
        raise ValueError("unsupported transient property type")

    def start(self, name, properties, argv, deadline):
        if (
            properties.get("AddRef") is not True
            or not argv
            or not all(type(x) is str and "\0" not in x for x in argv)
        ):
            raise ValueError("unreferenced service or invalid command")
        if not argv[0].startswith("/"):
            raise ValueError("service executable must be absolute")
        kinds = {**PROPERTY_TYPES, "AddRef": "b"}
        # Runtime observations and ExecStart cannot be caller-supplied overrides.
        forbidden = {
            "MainPID",
            "ControlGroup",
            "ExecMainStartTimestampMonotonic",
            "ExecMainExitTimestampMonotonic",
            "ExecMainCode",
            "ExecMainStatus",
            "Result",
            "ExecStart",
        }
        if set(properties) - set(kinds) or set(properties) & forbidden:
            raise ValueError("unexpected transient property")
        entries = [
            (key, self.variant(kinds[key], value)) for key, value in properties.items()
        ]
        entries += [("ExecStart", self.variant("commands", ((argv[0], argv, False),)))]
        for key, value in (
            ("WorkingDirectory", "/"),
            ("StandardInput", "null"),
            ("StandardOutput", "null"),
            ("StandardError", "null"),
        ):
            entries.append((key, self.variant("s", value)))
        reply = self.call(
            MANAGER_PATH,
            MANAGER,
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            (name, "fail", entries, []),
            deadline,
        )
        return str(reply)

    def normal(self, variant, kind):
        expected_signature = "a(sasbttttuii)" if kind == "commands" else kind
        if (
            type(variant) is not tuple
            or len(variant) != 2
            or variant[0] != expected_signature
        ):
            raise ValueError("unexpected D-Bus variant signature")
        value = variant[1]
        scalar = {"s": str, "t": int, "u": int, "i": int, "b": bool}
        if kind in scalar:
            if type(value) is not scalar[kind]:
                raise ValueError("unexpected D-Bus scalar type")
            return value
        if kind == "ay":
            if type(value) not in (bytes, list, tuple):
                raise ValueError("unexpected D-Bus byte array")
            if len(value) > 512 or any(
                type(byte) is not int or not 0 <= byte <= 255 for byte in value
            ):
                raise ValueError("D-Bus byte array cap")
            return tuple(value)
        if kind == "commands":
            if type(value) is not list or len(value) > 1:
                raise ValueError("unexpected D-Bus command array")
            rows = []
            for row in value:
                if len(row) != 10 or len(row[1]) > 16:
                    raise ValueError("D-Bus command shape")
                rows.append(
                    (
                        self.normal(("s", row[0]), "s"),
                        tuple(self.normal(("s", arg), "s") for arg in row[1]),
                        self.normal(("b", row[2]), "b"),
                    )
                )
            return tuple(rows)
        raise ValueError("unsupported observed property")

    def observe(self, name, deadline):
        self.last_partial = {}
        path = self.call(MANAGER_PATH, MANAGER, "GetUnit", "s", (name,), deadline)
        if type(path) is not str or not path.startswith(
            "/org/freedesktop/systemd1/unit/"
        ):
            raise ValueError("D-Bus unit path")
        for interface, kinds in (
            (BUS_NAME + ".Unit", UNIT_TYPES),
            (BUS_NAME + ".Service", PROPERTY_TYPES),
        ):
            row = self.call(
                str(path),
                "org.freedesktop.DBus.Properties",
                "GetAll",
                "s",
                (interface,),
                deadline,
            )
            if type(row) is not dict:
                raise ValueError("D-Bus property dictionary")
            for key, kind in kinds.items():
                if key not in row:
                    raise ValueError("missing D-Bus property: " + key)
                self.last_partial[key] = self.normal(row[key], kind)
        self.last_partial["InvocationID"] = bytes(
            self.last_partial["InvocationID"]
        ).hex()
        return dict(self.last_partial)

    def processes(self, name, deadline):
        rows = self.call(
            MANAGER_PATH, MANAGER, "GetUnitProcesses", "s", (name,), deadline
        )
        if type(rows) is not list or len(rows) > 64:
            raise ValueError("invalid or overflowing service process inventory")
        if any(len(row) != 3 for row in rows):
            raise ValueError("invalid service process row")
        return tuple(
            (
                self.normal(("s", row[0]), "s"),
                self.normal(("u", row[1]), "u"),
                self.normal(("s", row[2]), "s"),
            )
            for row in rows
        )

    def stop(self, name, deadline):
        return self.call(
            MANAGER_PATH, MANAGER, "StopUnit", "ss", (name, "fail"), deadline
        )

    def close(self):
        if self.closed:
            raise ValueError("bus connection already consumed")
        self.closed = True
        if self.socket is not None:
            owned, self.socket = self.socket, None
            owned.close()


class UnitLease:
    """The caller persists ownership intent before create and every result after.

    A timed-out creation can still have created a service. Such a lease remains
    unresolved and cannot be retried or treated as a missing unit. The private
    bus connection owns AddRef until verified terminal evidence is persisted.
    """

    def __init__(self, name, bus, now=time.monotonic_ns):
        if (
            type(name) is not str
            or re.fullmatch(
                r"irlume-job-guardian-[a-z0-9][a-z0-9-]{0,63}\.service", name
            )
            is None
        ):
            raise ValueError("guardian unit name")
        self.name, self.bus, self.now = name, bus, now
        self.creation_attempted = False
        self.creation_reply = None
        self.created = False
        self.unresolved = False
        self.bound = None
        self.last_observation = None
        self.last_processes = None
        self.terminal = False
        self.close_attempted = False
        self.previous = None

    def check(self, deadline):
        now = self.now()
        if type(now) is not int or type(deadline) is not int or now < 0:
            raise ValueError("service clock")
        if (self.previous is not None and now < self.previous) or now >= deadline:
            raise TimeoutError("service operation deadline")
        self.previous = now

    def create(self, properties, argv, deadline):
        if self.creation_attempted or properties.get("AddRef") is not True:
            raise ValueError("unreferenced or repeated service creation")
        self.check(deadline)
        self.creation_attempted = True
        self.unresolved = True
        # Persist the reply before checking time: a late reply is still evidence
        # that a side-effecting request returned, never proof of no service.
        self.creation_reply = self.bus.start(self.name, properties, argv, deadline)
        self.check(deadline)
        if (
            type(self.creation_reply) is not str
            or re.fullmatch(
                r"/org/freedesktop/systemd1/job/[0-9]+", self.creation_reply
            )
            is None
        ):
            raise ValueError("invalid service creation reply")
        self.created = True
        self.unresolved = False

    def observe(self, deadline):
        if not self.creation_attempted or self.close_attempted:
            raise ValueError("service not observable through this lease")
        self.check(deadline)
        self.last_observation = self.bus.observe(self.name, deadline)
        self.check(deadline)
        return self.last_observation

    def bind(self, row):
        if (
            not self.created
            or self.unresolved
            or self.bound is not None
            or row is not self.last_observation
        ):
            raise ValueError("service binding lacks creation or observation")
        if (
            type(row) is not dict
            or row.get("Id") != self.name
            or type(row.get("InvocationID")) is not str
            or re.fullmatch("[0-9a-f]{32}", row["InvocationID"]) is None
            or row["InvocationID"] == "0" * 32
            or type(row.get("MainPID")) is not int
            or row["MainPID"] <= 1
            or type(row.get("ControlGroup")) is not str
            or not row["ControlGroup"].startswith("/")
            or type(row.get("ExecMainStartTimestampMonotonic")) is not int
            or row["ExecMainStartTimestampMonotonic"] <= 0
        ):
            raise ValueError("invalid service binding")
        self.bound = {
            k: row[k]
            for k in (
                "Id",
                "InvocationID",
                "MainPID",
                "ControlGroup",
                "ExecMainStartTimestampMonotonic",
            )
        }

    def same_invocation(self, row):
        if (
            self.bound is None
            or type(row) is not dict
            or any(row.get(k) != self.bound[k] for k in ("Id", "InvocationID"))
        ):
            raise ValueError("lost service invocation")
        if row.get("ControlGroup") not in (self.bound["ControlGroup"], ""):
            raise ValueError("changed service cgroup")

    def stop(self, deadline):
        if self.bound is None or not self.created or self.close_attempted:
            raise ValueError("cannot stop unbound service")
        row = self.observe(deadline)
        self.same_invocation(row)
        self.unresolved = True
        self.bus.stop(self.name, deadline)
        self.check(deadline)

    def verify_terminal(self, deadline, acceptance_deadline):
        row = self.observe(deadline)
        self.same_invocation(row)
        for key, expected in {
            "MainPID": 0,
            "ActiveState": "inactive",
            "SubState": "dead",
            "Result": "success",
            "ExecMainCode": 1,
            "ExecMainStatus": 0,
        }.items():
            if type(row.get(key)) is not type(expected) or row[key] != expected:
                raise ValueError("service not successfully terminal")
        exited = row.get("ExecMainExitTimestampMonotonic")
        if (
            type(acceptance_deadline) is not int
            or type(exited) is not int
            or exited < self.bound["ExecMainStartTimestampMonotonic"]
            or exited * 1000 >= acceptance_deadline
        ):
            raise ValueError("service terminal deadline")
        self.last_processes = self.bus.processes(self.name, deadline)
        self.check(deadline)
        if self.last_processes != () or type(self.last_processes) is not tuple:
            raise ValueError("service domain not empty")
        self.terminal = True
        self.unresolved = False
        return row

    def release(self, deadline):
        if not self.terminal or self.unresolved or self.close_attempted:
            raise ValueError("cannot release unresolved service reference")
        self.check(deadline)
        self.close_attempted = True
        try:
            self.bus.close()
            self.check(deadline)
        except BaseException:
            self.unresolved = True
            raise


def open_directory(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute directory required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            new = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=fd,
            )
            old, fd = fd, new
            os.close(old)
        return fd
    except BaseException:
        os.close(fd)
        raise


class AdmissionGate:
    """One persistent blocker across all run IDs. Runtime uses for_current_user.

    complete receives H's already-verified, closed terminal evidence, never a
    wire flag. The H coordinator is responsible for its semantic verification.
    A failed/unresolved attempt only closes the lock; its blocker stays on disk.
    """

    def __init__(self, root, deadline):
        self.root = Path(root)
        self.root_fd = self.lock_fd = None
        self.record = None
        self.run_id = None
        self.check(deadline)
        try:
            self.root_fd = open_directory(root)
            info = os.fstat(self.root_fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("admission directory must be owner-only")
            self.lock_fd = os.open(
                "admission.lock",
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=self.root_fd,
            )
            info = os.fstat(self.lock_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
            ):
                raise ValueError("admission lock ownership")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            named = os.stat(
                "admission.lock", dir_fd=self.root_fd, follow_symlinks=False
            )
            if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("admission lock replaced")
            self.check(deadline)
        except BaseException as error:
            try:
                self.close()
            except CLEANUP_FAILURES as cleanup:
                raise BaseExceptionGroup(
                    "admission setup and cleanup", [error, cleanup]
                ) from error
            raise

    @classmethod
    def for_current_user(cls, deadline):
        uid = os.getuid()
        if uid == 0 or os.geteuid() != uid:
            raise ValueError("unprivileged admission only")
        home = Path(pwd.getpwuid(uid).pw_dir)
        fd = open_directory(home)
        try:
            for part in (".local", "state", "irlume-job-runner"):
                info = os.fstat(fd)
                if info.st_uid != uid or info.st_mode & 0o022:
                    raise ValueError("unsafe admission ancestor")
                cls.check(deadline)
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
                new = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=fd,
                )
                old, fd = fd, new
                os.close(old)
        finally:
            os.close(fd)
        return cls(home / ".local/state/irlume-job-runner", deadline)

    @staticmethod
    def check(deadline):
        if type(deadline) is not int or time.monotonic_ns() >= deadline:
            raise TimeoutError("admission deadline")

    def write(self, name, data, deadline):
        self.check(deadline)
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self.root_fd,
        )
        errors = []
        try:
            offset = 0
            while offset < len(data):
                self.check(deadline)
                count = os.write(fd, data[offset:])
                if count <= 0:
                    raise OSError("short admission write")
                offset += count
            os.fsync(fd)
            self.check(deadline)
        except CLEANUP_FAILURES as error:
            errors.append(error)
        try:
            os.close(fd)
        except CLEANUP_FAILURES as error:
            errors.append(error)
        try:
            self.check(deadline)
            os.fsync(self.root_fd)
            self.check(deadline)
        except CLEANUP_FAILURES as error:
            errors.append(error)
        if errors:
            raise BaseExceptionGroup("admission persistence", errors)

    def claim(self, run_id, intent, deadline):
        if self.record is not None or self.lock_fd is None:
            raise ValueError("admission already used or closed")
        if (
            type(run_id) is not str
            or re.fullmatch("[a-z0-9][a-z0-9-]{0,63}", run_id) is None
        ):
            raise ValueError("admission run ID")
        if type(intent) is not bytes or not 0 < len(intent) <= 65536:
            raise ValueError("admission intent cap")
        record = (
            json.dumps(
                {
                    "run_id": run_id,
                    "intent_sha256": hashlib.sha256(intent).hexdigest(),
                    "intent_hex": intent.hex(),
                },
                sort_keys=True,
            )
            + "\n"
        ).encode()
        self.write("active.json", record, deadline)
        self.record, self.run_id = record, run_id

    def complete(self, terminal_evidence, deadline):
        if self.record is None or self.lock_fd is None:
            raise ValueError("no owned admission intent")
        if (
            type(terminal_evidence) is not bytes
            or not 0 < len(terminal_evidence) <= 32 * 1024**2
        ):
            raise ValueError("terminal evidence cap")
        self.write("terminal-" + self.run_id + ".json", terminal_evidence, deadline)
        fd = os.open(
            "active.json",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=self.root_fd,
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
                or info.st_size != len(self.record)
            ):
                raise ValueError("active intent changed")
            data = bytearray()
            while len(data) < len(self.record):
                self.check(deadline)
                part = os.read(fd, len(self.record) - len(data))
                if not part:
                    break
                data.extend(part)
            named = os.stat("active.json", dir_fd=self.root_fd, follow_symlinks=False)
            if bytes(data) != self.record or (named.st_dev, named.st_ino) != (
                info.st_dev,
                info.st_ino,
            ):
                raise ValueError("active intent ownership mismatch")
        finally:
            os.close(fd)
        self.check(deadline)
        os.unlink("active.json", dir_fd=self.root_fd)
        # Only reached after durable terminal proof. A late sync failure may
        # leave the old blocker after reboot; it cannot resurrect the domain.
        os.fsync(self.root_fd)
        self.check(deadline)
        self.record = None

    def close(self):
        errors = []
        for name in ("lock_fd", "root_fd"):
            fd = getattr(self, name)
            setattr(self, name, None)
            if fd is not None:
                try:
                    os.close(fd)
                except CLEANUP_FAILURES as error:
                    errors.append(error)
        if errors:
            raise BaseExceptionGroup("admission descriptor cleanup", errors)


if __name__ == "__main__":
    raise SystemExit(77)
