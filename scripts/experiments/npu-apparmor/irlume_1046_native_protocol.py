"""Bounded native-client framing and immutable machine-witness checks."""

import os
import re
import selectors
import subprocess
import time
import uuid


class RetainedClient:
    """One pipe-driven virsh connection; the caller supplies native lifetime protection."""

    def __init__(self, argv, deadline):
        require_live(deadline)
        self.deadline = deadline
        self.process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.buffer = bytearray()
        self.trace = []
        self.closed = False
        self.last_ack = False

    def command(self, command, timeout=30):
        require_live(self.deadline)
        self.last_ack = False
        if self.closed or self.process.poll() is not None:
            raise RuntimeError("creator connection is closed")
        if (
            not command
            or len(command) > 2048
            or any(c in command for c in ("\n", "\r", "\0", ";"))
        ):
            raise ValueError("not one fixed virsh command")
        marker = ("ACK_" + uuid.uuid4().hex).encode()
        sent = (command + "\necho ").encode() + marker + b"\n"
        start = time.monotonic()
        deadline = min(self.deadline, start + timeout)
        try:
            self.process.stdin.write(sent)
            self.process.stdin.flush()
            while True:
                found = split_reply(bytes(self.buffer), marker)
                if found is not None:
                    reply, rest = found
                    self.buffer = bytearray(rest)
                    self.last_ack = True
                    text = reply.decode(errors="replace")
                    if "error:" in text.lower():
                        raise RuntimeError(text)
                    self.trace.append(
                        {
                            "command": command,
                            "output": text,
                            "elapsed": time.monotonic() - start,
                        }
                    )
                    return text
                require_live(deadline)
                for key, _ in self.selector.select(0.1):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        raise RuntimeError(
                            "creator exited without command acknowledgement"
                        )
                    self.buffer.extend(chunk)
                    if len(self.buffer) > 65536:
                        raise RuntimeError("creator output bound exceeded")
        except (OSError, ValueError, RuntimeError):
            self.trace.append(
                {
                    "command": command,
                    "partial_output": bytes(self.buffer[-8192:]).decode(
                        errors="replace"
                    ),
                    "elapsed": time.monotonic() - start,
                    "complete": False,
                }
            )
            raise

    def close_input(self):
        self.closed = True
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            finally:
                self.process.stdin = None

    def dispose(self):
        self.selector.close()
        self.process.stdout.close()


def property_unit(name):
    if (
        not isinstance(name, str)
        or not name.startswith("machine-")
        or not name.endswith(".scope")
    ):
        raise ValueError("not a machine scope")
    if any(char.isspace() or char in "'\"" for char in name):
        raise ValueError("invalid scope spelling")
    # systemd-run's unit-list property parser removes one escaping layer.
    return name.replace("\\", "\\\\")


def machine_witness(identifier, pid, machine, unit, process):
    if (
        str(uuid.UUID(bytes=bytes(machine["Id"]))) != identifier
        or machine["Leader"] != pid
    ):
        raise ValueError("machine UUID/leader differs")
    scope = machine["Unit"]
    property_unit(scope)
    if unit.get("ActiveState") != "active" or not re.fullmatch(
        "[0-9a-f]{32}", unit.get("InvocationID", "")
    ):
        raise ValueError("machine scope is not active")
    group = unit.get("ControlGroup", "")
    if not group.startswith("/machine.slice/") or ".." in group.split("/"):
        raise ValueError("unexpected machine control group")
    if not (process["cgroup"] == group or process["cgroup"].startswith(group + "/")):
        raise ValueError("QEMU is not a member of the machine scope")
    argv = process["argv"]
    if (
        "-uuid" not in argv
        or argv.index("-uuid") + 1 >= len(argv)
        or argv[argv.index("-uuid") + 1] != identifier
    ):
        raise ValueError("QEMU arguments identify another VM")
    if process["uid"] != 107 or process["exe"] != "/usr/bin/qemu-system-x86_64":
        raise ValueError("unexpected QEMU process owner/executable")
    return {
        "uuid": identifier,
        "pid": pid,
        "scope": scope,
        "invocation": unit["InvocationID"],
        "cgroup": group,
    }


def require_live(deadline, minimum=0, *, now=None):
    if now is None:
        now = time.monotonic()
    if deadline - now <= minimum:
        raise TimeoutError("native launch lease expired or too short")


def split_reply(buffer, marker):
    needle = b"\n" + marker
    at = buffer.find(needle)
    if at < 0:
        return None
    # The echoed command is prefixed by "virsh # echo", so it is not an ACK.
    return buffer[:at], buffer[at + len(needle) :]


def diagnostic(args, code, stdout, stderr, elapsed, *, timeout=False):
    def bounded(value):
        if isinstance(value, bytes):
            value = value.decode(errors="replace")
        return {"tail": (value or "")[-4096:], "truncated": len(value or "") > 4096}

    return {
        "argv": list(args),
        "exit": code,
        "stdout": bounded(stdout),
        "stderr": bounded(stderr),
        "elapsed_seconds": elapsed,
        "timeout": timeout,
    }


def same_domain_states(before, after):
    return all(after.get(identifier) == state for identifier, state in before.items())


def same_scope(expected, current):
    return (
        current.get("InvocationID") == expected["invocation"]
        and current.get("ControlGroup") == expected["cgroup"]
    )


def release_allowed(observations):
    return all(
        observations.get(key) is True
        for key in (
            "creator_terminated",
            "birth_fenced",
            "guest_absent",
            "scope_empty",
            "hardware_restored",
        )
    )


def power_mode_valid(value):
    return isinstance(value, str) and value in ("on", "auto")


def scope_binding_matches(scope, dependencies):
    return isinstance(dependencies, list) and dependencies == [scope]
