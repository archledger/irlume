#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Guest E's private bounded collector. Importing this module starts nothing."""

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import selectors
import signal
import time
from pathlib import Path


class SourceLoader(importlib.machinery.SourceFileLoader):
    """Bootstrap from source without trusting this entry's adjacent caches."""

    def get_code(self, fullname):
        self.source = self.get_data(self.path)
        return self.source_to_code(self.source, self.path)


LOADER = SourceLoader(
    "collector_runtime", str(Path(__file__).with_name("measurement-job-runtime.py"))
)
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
runtime = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(runtime)
runtime.__source_sha256__ = hashlib.sha256(LOADER.source).hexdigest()
CASE_NS = runtime.LIMITS["case_total_ns"]
GUEST_NS = 150_000_000_000
LEDGER_LIMIT = 32 * 1024 * 1024
EVENT_LIMIT = 8192
WAIT_LIMIT = 16
CHANNELS = {"report", "diagnostic", "control"}


class CaseReceipt:
    """Bounded observations, retained before decoding or checking elapsed time."""

    def __init__(self):
        self.report = bytearray()
        self.channel_bytes = dict.fromkeys(sorted(CHANNELS), 0)
        self.eof = set()
        self.waits = []
        self.wait_count = 0
        self.diagnostic = hashlib.sha256()
        self.diagnostic_bytes = 0
        self.confirmed = False

    def capture(self, event):
        if type(event) is not tuple or len(event) != 2:
            return
        channel, data = event
        if type(channel) is not str:
            return
        if channel in CHANNELS:
            if data is None:
                self.eof.add(channel)
            elif type(data) is bytes:
                self.channel_bytes[channel] += len(data)
                if channel == "report":
                    self.report.extend(
                        data[: max(0, runtime.MAX_FRAME + 4 - len(self.report))]
                    )
                elif channel == "diagnostic":
                    kept = data[
                        : max(
                            0,
                            runtime.LIMITS["case_output_bytes"] - self.diagnostic_bytes,
                        )
                    ]
                    self.diagnostic.update(kept)
                    self.diagnostic_bytes += len(kept)
        elif channel in ("exit", "stopped", "continued") and type(data) is int:
            self.wait_count += 1
            if len(self.waits) < WAIT_LIMIT:
                self.waits.append({"event": channel, "status": data})

    def fields(self):
        size = int.from_bytes(self.report[:4], "big") if len(self.report) >= 4 else 0
        return {
            "report_hex": self.report.hex(),
            "report_truncated": len(self.report) != self.channel_bytes["report"],
            "frame_complete": 1 <= size <= runtime.MAX_FRAME
            and size + 4 == self.channel_bytes["report"],
            "channel_bytes": self.channel_bytes,
            "output_bytes": sum(self.channel_bytes.values()),
            "eof": sorted(self.eof),
            "diagnostic_sha256": self.diagnostic.hexdigest(),
            "diagnostic_bytes_hashed": self.diagnostic_bytes,
            "wait_observations": self.waits,
            "wait_observations_truncated": self.wait_count > len(self.waits),
            "quarantine_confirmed": self.confirmed,
        }


def child_receipt(child):
    observations = getattr(child, "wait_observations", [])
    return {
        "terminal_wait": getattr(child, "terminal_wait", None),
        "reaped": getattr(child, "reaped", False),
        "child_wait_observations": observations,
        "child_wait_observations_truncated": getattr(child, "wait_count", 0)
        > len(observations),
    }


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def request_packet(want, sequence, origin, parent_pid, jobs):
    """Encode only the fixed R2b protocol; these bytes confer no boot authority."""
    runtime._expected(want)
    runtime._integer(sequence, 0, len(want.cases) - 1)
    runtime._integer(origin, 0, runtime.U64_MAX - CASE_NS)
    runtime._integer(parent_pid, 2, 2**31 - 1)
    if type(jobs) is not tuple or len(jobs) != 2:
        raise ValueError("jobs identity")
    runtime._integer(jobs[0])
    runtime._integer(jobs[1], 1)
    packet = bytearray(236)
    run = want.identity.run_id.encode("ascii")
    packet[:8] = b"IRLMJOB1"
    packet[8] = len(run)
    packet[9 : 9 + len(run)] = run
    packet[73] = runtime.CASES.index(want.cases[sequence])
    packet[74] = sequence
    for offset, value in (
        (80, want.first_epoch + sequence),
        (88, origin),
        (96, origin + CASE_NS),
        (108, jobs[0]),
        (116, jobs[1]),
    ):
        packet[offset : offset + 8] = value.to_bytes(8, "little")
    packet[104:108] = parent_pid.to_bytes(4, "little")
    for offset, digest in (
        (124, want.identity.boot_input_sha256),
        (156, want.identity.build_sha256),
        (188, want.identity.input_manifest_sha256),
    ):
        packet[offset : offset + 32] = bytes.fromhex(digest)
    packet[220:236] = bytes.fromhex(want.identity.guest_boot_id.replace("-", ""))
    return bytes(packet)


class FrameReader:
    """One bounded frame, including an explicit EOF check by the owner."""

    def __init__(self):
        self.data = bytearray()
        self.size = None

    def feed(self, data):
        if type(data) is not bytes or not data:
            raise ValueError("empty or invalid frame chunk")
        if len(self.data) + len(data) > runtime.MAX_FRAME + 4:
            raise ValueError("frame cap")
        self.data.extend(data)
        if len(self.data) >= 4:
            self.size = int.from_bytes(self.data[:4], "big")
            if (
                not 1 <= self.size <= runtime.MAX_FRAME
                or len(self.data) > self.size + 4
            ):
                raise ValueError("frame length or surplus")

    def finish(self):
        if self.size is None or len(self.data) != self.size + 4:
            raise ValueError("incomplete frame")
        return bytes(self.data)


class Collector:
    """One E lifetime. Effects retain every started child even when a call fails.

    start creates a parked child, verifies placement/descriptors/namespaces and
    releases its fixed gate before returning. event drains bounded chunks and
    yields (report/diagnostic/control, bytes-or-None), lifecycle events, or None.
    After M's successful self-stop, boundary events mark each still-open stream
    drained to EAGAIN. The protected profile forbids foreign stop/continue signals
    to M and other writers; an external intervention invalidates the outer run.
    close_case consumes collector transports, never quarantined M or its jobs.
    No failure handler here claims native cleanup or replaces M's ownership.
    """

    def __init__(self, effects, want, boot_only):
        runtime._expected(want)
        if type(boot_only) is not bool:
            raise ValueError("boot mode type")
        if boot_only and want.cases != ("supervisor-only",):
            raise ValueError("boot-only selection")
        if any(runtime.expected_outcome(c) == "incomplete" for c in want.cases[:-1]):
            raise ValueError("quarantine must be last")
        self.os, self.want, self.boot_only = effects, want, boot_only
        self.origin = self.os.now()
        runtime._integer(self.origin, 0, runtime.U64_MAX - GUEST_NS)
        self.end = self.origin + GUEST_NS
        self.previous = self.origin
        self.bytes = 0
        self.digest = hashlib.sha256()
        self.hold = None
        self.mode = "boot-only" if boot_only else "runtime-candidate"
        self.batch = hashlib.sha256(
            canonical(
                {
                    "identity": want.identity._asdict(),
                    "cases": want.cases,
                    "first_epoch": want.first_epoch,
                    "mode": self.mode,
                }
            )
        ).hexdigest()

    def clock(self, end):
        now = self.os.now()
        runtime._integer(now)
        if now < self.previous or now >= min(end, self.end):
            raise TimeoutError("collector deadline or clock regression")
        self.previous = now
        return now

    def call(self, end, method, *args):
        self.clock(end)
        value = method(*args)
        self.clock(end)
        return value

    def record(self, event, end, **fields):
        data = (
            canonical(
                {
                    "scope": "contained-job-evidence-v1",
                    "mode": self.mode,
                    "event": event,
                    "native_authorized": False,
                    "full_contract_proven": False,
                    **fields,
                }
            )
            + b"\n"
        )
        if self.bytes + len(data) > LEDGER_LIMIT:
            raise ValueError("ledger cap")
        self.call(end, self.os.append, data)
        self.bytes += len(data)
        self.digest.update(data)

    def decode(self, frame, sequence, child):
        if not self.boot_only:
            result = runtime.decode_report(frame, self.want, sequence)
            if not result.matches_expected:
                raise ValueError("unexpected native report")
            return result.outcome == "incomplete"
        row = runtime._json(frame[4:])
        runtime._fields(
            row,
            (
                "scope",
                "identity",
                "sequence",
                "epoch",
                "pid",
                "checked",
                "native_authorized",
                "full_contract_proven",
            ),
        )
        if row != {
            "scope": "contained-job-boot-v1",
            "identity": self.want.identity._asdict(),
            "sequence": sequence,
            "epoch": self.want.first_epoch + sequence,
            "pid": child.pid,
            "checked": True,
            "native_authorized": False,
            "full_contract_proven": False,
        }:
            raise ValueError("boot-only report")
        # Python bool equals int; enforce these fields independently of equality.
        for key in ("sequence", "epoch", "pid"):
            runtime._integer(row[key])
        for key in ("checked", "native_authorized", "full_contract_proven"):
            runtime._boolean(row[key])
        return False

    def check_hold(self):
        if (
            self.hold is not None
            and self.call(self.end, self.os.quiescent, self.hold) is not True
        ):
            raise ValueError("lost quarantine stop during finalization")

    def case(self, sequence):
        origin = self.clock(self.end)
        end = min(origin + CASE_NS, self.end)
        self.record(
            "reserved",
            end,
            sequence=sequence,
            epoch=self.want.first_epoch + sequence,
            origin=origin,
            deadline=origin + CASE_NS,
        )
        child = self.call(
            end,
            self.os.start,
            self.want,
            sequence,
            origin,
            origin + CASE_NS,
            self.boot_only,
        )
        runtime._integer(child.pid, 2, 2**31 - 1)
        self.record("started", end, sequence=sequence, pid=child.pid)
        reader, receipt = FrameReader(), CaseReceipt()
        eof, boundary, exitcode = set(), set(), None
        quarantine, stopped, first_error = None, False, None
        try:
            for _ in range(EVENT_LIMIT):
                self.clock(end)
                event = self.os.event(child, end)
                receipt.capture(event)
                self.clock(end)  # Keep even the bytes consumed by a late read.
                if (
                    sum(receipt.channel_bytes.values())
                    > runtime.LIMITS["case_output_bytes"]
                ):
                    raise ValueError("case byte cap")
                if event is None:
                    continue
                try:
                    if type(event) is not tuple or len(event) != 2:
                        raise ValueError("collector event")
                    channel, data = event
                    if channel == "exit":
                        if type(data) is not int or exitcode is not None:
                            raise ValueError("manager exit")
                        exitcode = data
                        if data != 0 or stopped:
                            raise ValueError("manager exit")
                    elif channel == "stopped":
                        if (
                            type(data) is not int
                            or data != signal.SIGSTOP
                            or stopped
                            or exitcode is not None
                        ):
                            raise ValueError("unexpected manager stop")
                        stopped = True
                    elif channel == "boundary":
                        if (
                            not stopped
                            or type(data) is not str
                            or data not in CHANNELS
                            or data in boundary
                        ):
                            raise ValueError("invalid stopped-stream boundary")
                        boundary.add(data)
                    elif type(channel) is str and channel in CHANNELS:
                        if channel in eof or channel in boundary:
                            raise ValueError("event after stream boundary")
                        if data is None:
                            eof.add(channel)
                            if channel == "report":
                                quarantine = self.decode(
                                    reader.finish(), sequence, child
                                )
                        else:
                            if type(data) is not bytes or not data:
                                raise ValueError("collector chunk")
                            if channel == "report":
                                reader.feed(data)
                            elif channel == "control":
                                raise ValueError("unexpected native control bytes")
                    else:
                        raise ValueError("unknown collector channel")
                except ValueError as error:
                    if first_error is None:
                        first_error = error
                if stopped and boundary | eof == CHANNELS:
                    if (
                        quarantine is not True
                        or "report" not in eof
                        or exitcode is not None
                    ):
                        raise ValueError("unexpected quarantine boundary")
                    if self.call(end, self.os.quiescent, child) is not True:
                        raise ValueError("lost quarantine manager")
                    receipt.confirmed = first_error is None
                    break
                if exitcode is not None and eof == CHANNELS:
                    if quarantine is not False:
                        raise ValueError("manager outcome mismatch")
                    break
            else:
                raise ValueError("event budget")
            if first_error is not None:
                raise first_error
            if quarantine:
                self.hold = child
            self.call(end, self.os.close_case, child, quarantine)
            self.record(
                "case-finished",
                end,
                sequence=sequence,
                pid=child.pid,
                **receipt.fields(),
                exitcode=exitcode,
                **child_receipt(child),
                custody="not-created-boot-only"
                if self.boot_only
                else "retained-by-M"
                if quarantine
                else "reported-clean",
                observed_at=self.clock(end),
            )
            return quarantine
        except (OSError, ValueError) as error:
            primary = first_error if first_error is not None else error
            try:
                # Diagnostic preservation uses only the remaining outer budget.
                # It never extends case acceptance or produces a terminal frame.
                self.record(
                    "case-failed",
                    self.end,
                    sequence=sequence,
                    pid=child.pid,
                    **receipt.fields(),
                    exitcode=exitcode,
                    boundary=sorted(boundary),
                    **child_receipt(child),
                    failure=type(primary).__name__,
                    reason=str(primary)[:256],
                    unobserved_remainder=(eof | boundary != CHANNELS),
                )
                self.call(self.end, self.os.sync_ledger)
            except (OSError, ValueError) as preservation_error:
                primary.add_note(
                    "failure receipt incomplete: " + type(preservation_error).__name__
                )
            raise primary

    def run(self):
        self.call(self.end, self.os.preflight, self.want, self.boot_only)
        self.record(
            "started",
            self.end,
            identity=self.want.identity._asdict(),
            batch_sha256=self.batch,
            cases=self.want.cases,
            first_epoch=self.want.first_epoch,
            guest_origin=self.origin,
            guest_deadline=self.end,
        )
        quarantine = False
        for sequence in range(len(self.want.cases)):
            quarantine = self.case(sequence)
            if quarantine:
                break
        outcome = "expected-abort" if quarantine else "complete"
        self.record(
            "ready-to-finalize", self.end, batch_sha256=self.batch, outcome=outcome
        )
        for method in (
            self.os.sync_ledger,
            self.os.sync_directory,
            self.os.close_ledger,
            self.os.close_directory,
        ):
            self.call(self.end, method)
            self.check_hold()
        terminal = {
            "scope": "contained-job-terminal-v1",
            "mode": self.mode,
            "identity": self.want.identity._asdict(),
            "batch_sha256": self.batch,
            "ledger_bytes": self.bytes,
            "ledger_sha256": self.digest.hexdigest(),
            "outcome": outcome,
            "native_authorized": False,
            "full_contract_proven": False,
        }
        payload = canonical(terminal)
        self.call(
            self.end,
            self.os.terminal,
            len(payload).to_bytes(4, "big") + payload,
            self.end,
        )
        self.check_hold()
        self.call(self.end, self.os.close_port)
        self.check_hold()
        self.call(self.end, self.os.poweroff, self.end)
        return terminal


def collect(effects, want, *, boot_only=False):
    return Collector(effects, want, boot_only).run()


def boottime():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class ChildStreams:
    """Own an unreaped direct child and its three nonblocking read transports.

    The creator transfers a freshly obtained pidfd while retaining sole wait
    authority; PID reuse is impossible while that direct child is unreaped.
    Construct/store this owner before fallible placement or gate-release work.
    An error leaves remaining descriptors and the child with this owner.
    """

    def __init__(self, pid, pidfd, report, diagnostic, control):
        self.pid, self.pidfd = pid, pidfd
        self.fds = {"report": report, "diagnostic": diagnostic, "control": control}
        self.eof = set()
        self.exitcode = None
        self.reaped = False
        self.stopped = False
        self.continued = False
        self.boundary = set()
        self.terminal_wait = None
        self.wait_observations = []
        self.wait_count = 0

    def _wait(self, flags):
        result = os.waitid(os.P_PIDFD, self.pidfd, flags)
        if result is not None:
            self.wait_count += 1
            if len(self.wait_observations) < WAIT_LIMIT:
                self.wait_observations.append(
                    {
                        "pid": result.si_pid,
                        "uid": result.si_uid,
                        "code": result.si_code,
                        "status": result.si_status,
                        "signal": result.si_signo,
                        "flags": flags,
                    }
                )
        return result

    def alive(self):
        if self.reaped or self.pidfd is None:
            return False
        result = self._wait(os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if result is None:
            return True
        if result.si_pid != self.pid or result.si_code not in (
            os.CLD_EXITED,
            os.CLD_KILLED,
            os.CLD_DUMPED,
        ):
            raise ValueError("foreign child wait")
        return False

    def quiescent(self):
        """Corroborate the protected self-stop; never infer signal provenance."""
        if not self.stopped or self.continued or not self.alive():
            return False
        continued = self._wait(os.WCONTINUED | os.WNOHANG | os.WNOWAIT)
        if continued is not None:
            self.continued = True
            return False
        with open(f"/proc/{self.pid}/stat", "rb") as file:
            row = file.read(4097)
        head, separator, tail = row.rpartition(b") ")
        return (
            len(row) <= 4096
            and separator == b") "
            and head.startswith(str(self.pid).encode() + b" (")
            and tail.split()[:1] == [b"T"]
        )

    def event(self, deadline):
        if self.exitcode is None:
            result = self._wait(
                os.WEXITED | os.WSTOPPED | os.WCONTINUED | os.WNOHANG | os.WNOWAIT,
            )
            if result is not None:
                if result.si_pid != self.pid or result.si_code not in (
                    os.CLD_EXITED,
                    os.CLD_KILLED,
                    os.CLD_DUMPED,
                    os.CLD_STOPPED,
                    os.CLD_CONTINUED,
                ):
                    raise ValueError("foreign child wait")
                if result.si_code in (os.CLD_STOPPED, os.CLD_CONTINUED):
                    flag = (
                        os.WSTOPPED
                        if result.si_code == os.CLD_STOPPED
                        else os.WCONTINUED
                    )
                    consumed = self._wait(flag | os.WNOHANG)
                    if consumed != result:
                        raise ValueError("child state changed during observation")
                    if result.si_code == os.CLD_CONTINUED:
                        self.continued = True
                        return ("continued", result.si_status)
                    if self.stopped:
                        raise ValueError("repeated manager stop")
                    self.stopped = result.si_status == signal.SIGSTOP
                    return ("stopped", result.si_status)
                self.exitcode = (
                    result.si_status
                    if result.si_code == os.CLD_EXITED
                    else -result.si_status
                )
                return ("exit", self.exitcode)
        remaining = deadline - boottime()
        if remaining <= 0:
            raise TimeoutError("child deadline")
        if self.stopped:
            if not self.quiescent():
                raise ValueError("lost quarantine stop")
            for name, fd in self.fds.items():
                if name in self.eof or name in self.boundary:
                    continue
                try:
                    data = os.read(fd, 4096)
                except BlockingIOError:
                    self.boundary.add(name)
                    return ("boundary", name)
                if not data:
                    self.eof.add(name)
                    return (name, None)
                return (name, data)
            return None
        with selectors.DefaultSelector() as selector:
            for name, fd in self.fds.items():
                if name not in self.eof:
                    selector.register(fd, selectors.EVENT_READ, name)
            ready = selector.select(min(0.01, remaining / 1_000_000_000))
        if not ready:
            return None
        key = ready[0][0]
        try:
            data = os.read(key.fd, 4096)
        except BlockingIOError:
            return None
        if not data:
            self.eof.add(key.data)
            return (key.data, None)
        return (key.data, data)

    def close(self, quarantined):
        if quarantined:
            if (
                not self.quiescent()
                or "report" not in self.eof
                or self.eof | self.boundary != CHANNELS
            ):
                raise ValueError("quarantine boundary incomplete")
        elif self.exitcode != 0 or self.eof != {"report", "diagnostic", "control"}:
            raise ValueError("child completion incomplete")
        while self.fds:
            _, fd = self.fds.popitem()
            os.close(fd)  # Consumed once even on failure; never retry its number.
        if quarantined and not self.quiescent():
            raise ValueError("quarantine child lost during close")
        if not quarantined:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            self.terminal_wait = {"pid": pid, "status": status}
            self.reaped = pid == self.pid
            if (
                pid != self.pid
                or not os.WIFEXITED(status)
                or os.WEXITSTATUS(status) != 0
            ):
                raise ValueError("child terminal mismatch")
            fd, self.pidfd = self.pidfd, None
            os.close(fd)
