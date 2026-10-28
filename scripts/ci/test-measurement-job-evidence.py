#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Collector contracts with synthetic reports and explicitly owned inert children."""

import importlib.util
import json
import os
import signal
import unittest
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
evidence = load("evidence", HERE / "measurement-job-evidence.py")
vectors = load("vectors", HERE / "test-measurement-job-runtime.py")


class WireTests(unittest.TestCase):
    def test_request_matches_static_manager_layout(self):
        want = evidence.runtime.Expected(
            evidence.runtime.Identity(*vectors.identity()), 41, ("supervisor-only",)
        )
        packet = evidence.request_packet(want, 0, 100, 4242, (3, 123))
        self.assertEqual(len(packet), 236)
        self.assertEqual(packet[:15], b"IRLMJOB1\x06run-01")
        self.assertEqual(packet[73:80], bytes(7))
        self.assertEqual(int.from_bytes(packet[80:88], "little"), 41)
        self.assertEqual(int.from_bytes(packet[88:96], "little"), 100)
        self.assertEqual(int.from_bytes(packet[96:104], "little"), 20_000_000_100)
        self.assertEqual(int.from_bytes(packet[104:108], "little"), 4242)
        self.assertEqual(int.from_bytes(packet[116:124], "little"), 123)
        self.assertEqual(packet[124:156], bytes.fromhex("a" * 64))

    def test_request_rejects_bad_origin_pid_identity_and_sequence(self):
        want = evidence.runtime.Expected(
            evidence.runtime.Identity(*vectors.identity()), 41, ("supervisor-only",)
        )
        for sequence, origin, pid, jobs in [
            (1, 100, 4242, (3, 123)),
            (0, True, 4242, (3, 123)),
            (0, 2**64 - 1, 4242, (3, 123)),
            (0, 100, 1, (3, 123)),
            (0, 100, 4242, (3, 0)),
        ]:
            with (
                self.subTest(sequence=sequence, origin=origin, pid=pid, jobs=jobs),
                self.assertRaises(ValueError),
            ):
                evidence.request_packet(want, sequence, origin, pid, jobs)

    def test_incremental_frame_requires_exact_eof_and_rejects_surplus(self):
        raw = vectors.frame(vectors.packet())
        reader = evidence.FrameReader()
        for part in (raw[:2], raw[2:5], raw[5:]):
            reader.feed(part)
        self.assertEqual(reader.finish(), raw)
        for bad in (raw[:-1], raw + b"x", (16385).to_bytes(4, "big"), b"\0\0\0\0"):
            with self.subTest(bad=bad[:8]), self.assertRaises(ValueError):
                reader = evidence.FrameReader()
                reader.feed(bad)
                reader.finish()


def expected(cases=("supervisor-only",)):
    return evidence.runtime.Expected(
        evidence.runtime.Identity(*vectors.identity()), 41, cases
    )


class Fake:
    def __init__(self, cases=("supervisor-only",)):
        self.time = 100
        self.calls = []
        self.records = bytearray()
        self.sent = b""
        self.fault = None
        self.overrun = None
        self.children = []
        self.lose_after = None
        self.fail_at = None
        self.final_overrun = False
        self.streams = []
        for sequence, case in enumerate(cases):
            data = vectors.frame(vectors.packet(case, sequence, 41 + sequence))
            events = [
                ("report", data[:7]),
                ("diagnostic", b"fixture"),
                ("report", data[7:]),
                ("report", None),
            ]
            if evidence.runtime.expected_outcome(case) != "incomplete":
                events += [("control", None), ("diagnostic", None), ("exit", 0)]
            else:
                events += [
                    ("stopped", int(signal.SIGSTOP)),
                    ("boundary", "diagnostic"),
                    ("boundary", "control"),
                ]
            self.streams.append(deque(events))

    def step(self, name):
        self.calls.append(name)
        if self.overrun == name:
            self.time += evidence.GUEST_NS if self.final_overrun else evidence.CASE_NS
        if self.fault == name or self.fail_at == (name, self.calls.count(name)):
            raise OSError(name)

    def now(self):
        return self.time

    def preflight(self, want, boot_only):
        self.step("preflight")

    def append(self, data):
        self.step("append")
        self.records.extend(data)

    def start(self, want, sequence, origin, deadline, boot_only):
        self.step("start")
        child = SimpleNamespace(pid=4000 + sequence, sequence=sequence)
        self.children.append(child)
        return child

    def event(self, child, deadline):
        self.step("event")
        if self.streams[child.sequence]:
            return self.streams[child.sequence].popleft()
        self.time = deadline
        return None

    def alive(self, child):
        self.step("alive")
        return self.lose_after not in self.calls

    def quiescent(self, child):
        self.step("quiescent")
        return self.alive(child)

    def close_case(self, child, quarantined):
        self.step("close-case")

    def sync_ledger(self):
        self.step("sync-ledger")

    def sync_directory(self):
        self.step("sync-directory")

    def close_ledger(self):
        self.step("close-ledger")

    def close_directory(self):
        self.step("close-directory")

    def terminal(self, data, deadline):
        self.step("terminal")
        self.sent = data

    def close_port(self):
        self.step("close-port")

    def poweroff(self, deadline):
        self.step("poweroff")


class CollectorTests(unittest.TestCase):
    def failure_receipt(self, effects):
        rows = [json.loads(line) for line in effects.records.splitlines()]
        failed = [row for row in rows if row["event"] == "case-failed"]
        self.assertEqual(len(failed), 1)
        self.assertNotIn("terminal", effects.calls)
        self.assertNotIn("poweroff", effects.calls)
        return failed[0]

    def test_unconfirmed_quarantine_cannot_finalize(self):
        cases = ("bounds-withheld-wait",)
        effects = Fake(cases)
        effects.streams[0] = deque(
            e for e in effects.streams[0] if e[0] not in ("stopped", "boundary")
        )
        with self.assertRaises((ValueError, TimeoutError)):
            evidence.collect(effects, expected(cases))
        receipt = self.failure_receipt(effects)
        self.assertFalse(receipt["quarantine_confirmed"])

    def test_failed_case_retains_exact_report_and_terminal_observation(self):
        effects = Fake()
        raw = vectors.frame(vectors.packet())
        effects.streams[0] = deque(
            [
                ("exit", 7),
                ("report", raw),
                ("report", None),
                ("diagnostic", b"late diagnostic"),
                ("diagnostic", None),
                ("control", None),
            ]
        )
        with self.assertRaisesRegex(ValueError, "manager exit"):
            evidence.collect(effects, expected())
        receipt = self.failure_receipt(effects)
        self.assertEqual(bytes.fromhex(receipt["report_hex"]), raw)
        self.assertEqual(receipt["exitcode"], 7)
        self.assertEqual(receipt["eof"], ["control", "diagnostic", "report"])
        self.assertEqual(receipt["channel_bytes"]["diagnostic"], 15)
        self.assertTrue(receipt["frame_complete"])

    def test_rejected_report_and_close_error_preserve_received_bytes(self):
        for stage in ("decode", "close-case"):
            effects = Fake()
            raw = vectors.frame(vectors.packet(epoch=40 if stage == "decode" else 41))
            effects.streams[0] = deque(
                [
                    ("report", raw),
                    ("report", None),
                    ("diagnostic", None),
                    ("control", None),
                    ("exit", 0),
                ]
            )
            effects.fault = stage if stage == "close-case" else None
            with self.subTest(stage=stage), self.assertRaises((ValueError, OSError)):
                evidence.collect(effects, expected())
            receipt = self.failure_receipt(effects)
            self.assertEqual(bytes.fromhex(receipt["report_hex"]), raw)
            self.assertTrue(receipt["frame_complete"])

    def test_deadline_failure_retains_last_received_chunk(self):
        effects = Fake()
        raw = vectors.frame(vectors.packet())

        def late_event(child, deadline):
            effects.time = deadline
            return ("report", raw)

        effects.event = late_event
        with self.assertRaises(TimeoutError):
            evidence.collect(effects, expected())
        receipt = self.failure_receipt(effects)
        self.assertEqual(bytes.fromhex(receipt["report_hex"]), raw)
        self.assertEqual(receipt["output_bytes"], len(raw))
        self.assertNotIn("report", receipt["eof"])

    def test_quarantine_control_after_report_eof_still_refuses(self):
        cases = ("bounds-withheld-wait",)
        effects = Fake(cases)
        effects.streams[0].insert(4, ("control", b"late violation"))
        with self.assertRaises((ValueError, TimeoutError)):
            evidence.collect(effects, expected(cases))
        receipt = self.failure_receipt(effects)
        self.assertEqual(receipt["channel_bytes"]["control"], 14)

    def test_oversized_frame_preserves_bounded_raw_prefix(self):
        effects = Fake()
        raw = (evidence.runtime.MAX_FRAME + 1).to_bytes(4, "big") + b"x" * (
            evidence.runtime.MAX_FRAME + 1
        )
        effects.streams[0] = deque(
            [
                ("report", raw),
                ("report", None),
                ("control", None),
                ("diagnostic", None),
                ("exit", 0),
            ]
        )
        with self.assertRaises(ValueError):
            evidence.collect(effects, expected())
        receipt = self.failure_receipt(effects)
        self.assertEqual(
            bytes.fromhex(receipt["report_hex"]), raw[: evidence.runtime.MAX_FRAME + 4]
        )
        self.assertTrue(receipt["report_truncated"])
        self.assertFalse(receipt["frame_complete"])

    def test_quarantine_counts_diagnostics_after_report_eof(self):
        cases = ("bounds-withheld-wait",)
        effects = Fake(cases)
        effects.streams[0].insert(5, ("diagnostic", b"after eof"))
        evidence.collect(effects, expected(cases))
        receipt = next(
            json.loads(line)
            for line in effects.records.splitlines()
            if json.loads(line)["event"] == "case-finished"
        )
        self.assertEqual(receipt["channel_bytes"]["diagnostic"], 16)
        self.assertTrue(receipt["quarantine_confirmed"])

    def test_quarantine_requires_all_stopped_stream_boundaries(self):
        cases = ("bounds-withheld-wait",)
        for channel in ("diagnostic", "control"):
            effects = Fake(cases)
            effects.streams[0].remove(("boundary", channel))
            with self.subTest(channel=channel), self.assertRaises(TimeoutError):
                evidence.collect(effects, expected(cases))
            self.assertFalse(self.failure_receipt(effects)["quarantine_confirmed"])

    def test_quarantine_late_flood_and_read_error_retain_report(self):
        cases = ("bounds-withheld-wait",)
        raw = vectors.frame(vectors.packet(cases[0]))
        for failure in ("flood", "read-error"):
            effects = Fake(cases)
            if failure == "flood":
                effects.streams[0].insert(
                    4,
                    ("diagnostic", b"x" * evidence.runtime.LIMITS["case_output_bytes"]),
                )
            else:
                effects.fail_at = ("event", 5)
            with (
                self.subTest(failure=failure),
                self.assertRaises((ValueError, OSError)),
            ):
                evidence.collect(effects, expected(cases))
            receipt = self.failure_receipt(effects)
            self.assertEqual(bytes.fromhex(receipt["report_hex"]), raw)
            self.assertFalse(receipt["quarantine_confirmed"])

    def test_continue_or_wrong_stop_never_confirms_quarantine(self):
        cases = ("bounds-withheld-wait",)
        for event in (
            ("stopped", int(signal.SIGTSTP)),
            ("continued", int(signal.SIGCONT)),
        ):
            effects = Fake(cases)
            effects.streams[0].insert(4, event)
            with self.subTest(event=event), self.assertRaises(ValueError):
                evidence.collect(effects, expected(cases))
            self.failure_receipt(effects)

    def test_complete_closes_ledger_before_terminal_and_poweroff(self):
        os = Fake()
        result = evidence.collect(os, expected())
        self.assertEqual(result["outcome"], "complete")
        self.assertEqual(
            os.calls[-7:],
            [
                "sync-ledger",
                "sync-directory",
                "close-ledger",
                "close-directory",
                "terminal",
                "close-port",
                "poweroff",
            ],
        )
        terminal = json.loads(os.sent[4:])
        self.assertEqual(terminal["ledger_bytes"], len(os.records))
        self.assertEqual(
            terminal["ledger_sha256"], evidence.hashlib.sha256(os.records).hexdigest()
        )
        self.assertFalse(terminal["native_authorized"])
        self.assertFalse(terminal["full_contract_proven"])
        self.assertEqual(
            json.loads(os.records.splitlines()[-1])["event"], "ready-to-finalize"
        )

    def test_quarantine_must_be_last_and_keeps_live_child(self):
        cases = ("supervisor-only", "bounds-withheld-wait")
        os = Fake(cases)
        result = evidence.collect(os, expected(cases))
        self.assertEqual(result["outcome"], "expected-abort")
        self.assertEqual(len(os.children), 2)
        self.assertIn("alive", os.calls)
        with self.assertRaises(ValueError):
            evidence.collect(Fake(), expected(tuple(reversed(cases))))

    def test_every_finalization_failure_stops_later_boundaries(self):
        stages = [
            "sync-ledger",
            "sync-directory",
            "close-ledger",
            "close-directory",
            "terminal",
            "close-port",
            "poweroff",
        ]
        for index, stage in enumerate(stages):
            os = Fake()
            os.fault = stage
            with self.subTest(stage=stage), self.assertRaises(OSError):
                evidence.collect(os, expected())
            for later in stages[index + 1 :]:
                self.assertNotIn(later, os.calls)

    def test_start_event_and_close_overrun_never_finalize(self):
        for stage in ("start", "event", "close-case"):
            os = Fake()
            os.overrun = stage
            with self.subTest(stage=stage), self.assertRaises(TimeoutError):
                evidence.collect(os, expected())
            self.assertNotIn("terminal", os.calls)
            self.assertEqual(len(os.children), 1)

    def test_nonzero_exit_and_surplus_data_refuse(self):
        for event in (("exit", 1), ("report", b"surplus"), ("control", b"unexpected")):
            os = Fake()
            os.streams[0].insert(3, event)
            with self.subTest(event=event), self.assertRaises(ValueError):
                evidence.collect(os, expected())
            self.assertNotIn("terminal", os.calls)

    def test_quarantine_loss_during_finalization_blocks_terminal(self):
        cases = ("bounds-withheld-wait",)
        os = Fake(cases)
        os.lose_after = "sync-ledger"
        with self.assertRaisesRegex(ValueError, "quarantine"):
            evidence.collect(os, expected(cases))
        self.assertNotIn("terminal", os.calls)

    def test_each_ledger_write_failure_blocks_terminal_and_poweroff(self):
        for occurrence in range(1, 6):
            effects = Fake()
            effects.fail_at = ("append", occurrence)
            with self.subTest(write=occurrence), self.assertRaises(OSError):
                evidence.collect(effects, expected())
            self.assertNotIn("terminal", effects.calls)
            self.assertNotIn("poweroff", effects.calls)

    def test_finalization_overruns_do_not_gain_a_new_deadline(self):
        for stage in (
            "sync-ledger",
            "sync-directory",
            "close-ledger",
            "close-directory",
            "terminal",
            "close-port",
            "poweroff",
        ):
            effects = Fake()
            effects.overrun = stage
            effects.final_overrun = True
            with self.subTest(stage=stage), self.assertRaises(TimeoutError):
                evidence.collect(effects, expected())
            if stage != "poweroff":
                self.assertNotIn("poweroff", effects.calls)

    def test_missing_eof_or_wait_cannot_be_complete(self):
        for missing in ("report", "diagnostic", "control", "exit"):
            effects = Fake()
            effects.streams[0] = deque(
                (kind, data)
                for kind, data in effects.streams[0]
                if not (kind == missing and (data is None or kind == "exit"))
            )
            with self.subTest(missing=missing), self.assertRaises(TimeoutError):
                evidence.collect(effects, expected())
            self.assertNotIn("terminal", effects.calls)

    def test_stale_epoch_or_model_record_refuses(self):
        for row in (vectors.packet(epoch=40), {"scope": "model-only"}):
            effects = Fake()
            effects.streams[0] = deque(
                [("report", vectors.frame(row)), ("report", None)]
            )
            with self.assertRaises(ValueError):
                evidence.collect(effects, expected())
            self.assertNotIn("terminal", effects.calls)

    def test_diagnostic_flood_and_nonadvancing_events_are_bounded(self):
        for pending in (False, True):
            effects = Fake()
            effects.event = lambda child, end, pending=pending: (
                None if pending else ("diagnostic", b"x" * 4096)
            )
            with self.subTest(pending=pending), self.assertRaises(ValueError):
                evidence.collect(effects, expected())
            self.assertNotIn("terminal", effects.calls)

    def test_preflight_failure_starts_no_child(self):
        effects = Fake()
        effects.fault = "preflight"
        with self.assertRaises(OSError):
            evidence.collect(effects, expected())
        self.assertEqual(effects.children, [])

    def test_boot_report_cannot_be_relabelled_runtime_or_claim_cleanup(self):
        effects = Fake()
        row = {
            "scope": "contained-job-boot-v1",
            "identity": expected().identity._asdict(),
            "sequence": 0,
            "epoch": 41,
            "pid": 4000,
            "checked": True,
            "native_authorized": False,
            "full_contract_proven": False,
        }
        effects.streams[0] = deque(
            [
                ("report", vectors.frame(row)),
                ("report", None),
                ("diagnostic", None),
                ("control", None),
                ("exit", 0),
            ]
        )
        result = evidence.collect(effects, expected(), boot_only=True)
        self.assertEqual(result["mode"], "boot-only")
        record = next(
            json.loads(line)
            for line in effects.records.splitlines()
            if json.loads(line)["event"] == "case-finished"
        )
        self.assertEqual(record["custody"], "not-created-boot-only")
        with self.assertRaises(ValueError):
            evidence.runtime.decode_report(vectors.frame(row), expected(), 0)


@contextmanager
def inert_child(hold=False, status=0, stopped=False, payload=b"inert-report"):
    pipes = [os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK) for _ in range(3)]
    pid = os.fork()
    if pid == 0:
        try:
            for read, _ in pipes:
                os.close(read)
            if os.write(pipes[0][1], payload) != len(payload):
                os._exit(98)
            os.close(pipes[0][1])
            os.write(pipes[1][1], b"inert-diagnostic")
            if stopped:
                os.kill(os.getpid(), signal.SIGSTOP)
            if hold:
                while True:
                    signal.pause()
            os._exit(status)
        finally:
            os._exit(99)
    pidfd, child = None, None
    owned = {fd for pair in pipes for fd in pair}
    try:
        pidfd = os.pidfd_open(pid)
        for _, write in pipes:
            owned.remove(write)
            os.close(write)
        child = evidence.ChildStreams(pid, pidfd, *(read for read, _ in pipes))
        owned.clear()  # ChildStreams now owns the read descriptors.
        yield child
    finally:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
            if waited == 0:
                # This unreaped direct child cannot have had its PID reused,
                # including when obtaining its pidfd was the failed operation.
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        for fd in child.fds.values() if child is not None else owned:
            os.close(fd)
        remaining_pidfd = child.pidfd if child is not None else pidfd
        if remaining_pidfd is not None:
            os.close(remaining_pidfd)


class ChildTests(unittest.TestCase):
    def test_wait_receipts_bound_repeated_observations_and_mark_truncation(self):
        with inert_child(status=7) as child:
            deadline = evidence.boottime() + 3_000_000_000
            while child.exitcode is None:
                child.event(deadline)
            for _ in range(32):
                self.assertFalse(child.alive())
            receipt = evidence.child_receipt(child)
            self.assertEqual(len(receipt["child_wait_observations"]), 16)
            self.assertTrue(receipt["child_wait_observations_truncated"])
            self.assertTrue(
                all(
                    row["pid"] == child.pid
                    for row in receipt["child_wait_observations"]
                )
            )
        receipt = evidence.CaseReceipt()
        for _ in range(32):
            receipt.capture(("exit", 7))
        self.assertEqual(len(receipt.fields()["wait_observations"]), 16)
        self.assertTrue(receipt.fields()["wait_observations_truncated"])

    def test_final_quiescence_probe_preserves_death_and_continuation(self):
        cases = ("bounds-withheld-wait",)
        raw = vectors.frame(vectors.packet(cases[0]))
        for signum, code, wait_flag in (
            (signal.SIGKILL, os.CLD_KILLED, os.WEXITED),
            (signal.SIGCONT, os.CLD_CONTINUED, os.WCONTINUED),
        ):
            with (
                self.subTest(signum=signum),
                inert_child(hold=True, stopped=True, payload=raw) as child,
            ):
                effects = Fake(cases)
                effects.now = evidence.boottime
                effects.start = lambda *args: child
                effects.event = lambda child, deadline: child.event(deadline)

                def final_probe(child, signum=signum, wait_flag=wait_flag):
                    os.kill(child.pid, signum)
                    os.waitid(os.P_PIDFD, child.pidfd, wait_flag | os.WNOWAIT)
                    return child.quiescent()

                effects.quiescent = final_probe
                with self.assertRaisesRegex(ValueError, "quarantine"):
                    evidence.collect(effects, expected(cases))
                row = next(
                    json.loads(line)
                    for line in effects.records.splitlines()
                    if json.loads(line)["event"] == "case-failed"
                )
                self.assertEqual(bytes.fromhex(row["report_hex"]), raw)
                waits = row.get("child_wait_observations", [])
                self.assertTrue(
                    any(
                        w["pid"] == child.pid
                        and w["code"] == code
                        and w["status"] == signum
                        for w in waits
                    ),
                    waits,
                )
                self.assertFalse(child.reaped)
                self.assertIsNotNone(child.pidfd)
                self.assertFalse(effects.sent)

    def test_collector_retains_real_nonzero_child_report(self):
        raw = vectors.frame(vectors.packet())
        with inert_child(status=7, payload=raw) as child:
            effects = Fake()
            effects.now = evidence.boottime
            effects.start = lambda *args: child
            effects.event = lambda child, deadline: child.event(deadline)
            with self.assertRaisesRegex(ValueError, "manager exit"):
                evidence.collect(effects, expected())
            row = next(
                json.loads(line)
                for line in effects.records.splitlines()
                if json.loads(line)["event"] == "case-failed"
            )
            self.assertEqual(bytes.fromhex(row["report_hex"]), raw)
            self.assertEqual(row["exitcode"], 7)
            self.assertEqual(
                row["channel_bytes"]["diagnostic"], len(b"inert-diagnostic")
            )
            self.assertFalse(row["reaped"])
            self.assertFalse(effects.sent)

    def test_collector_accepts_only_stopped_drained_quarantine(self):
        cases = ("bounds-withheld-wait",)
        raw = vectors.frame(vectors.packet(cases[0]))
        with inert_child(hold=True, stopped=True, payload=raw) as child:
            effects = Fake(cases)
            effects.now = evidence.boottime
            effects.start = lambda *args: child
            effects.event = lambda child, deadline: child.event(deadline)
            effects.quiescent = lambda child: child.quiescent()
            effects.close_case = lambda child, quarantined: child.close(quarantined)
            result = evidence.collect(effects, expected(cases))
            self.assertEqual(result["outcome"], "expected-abort")
            self.assertTrue(child.quiescent())
            self.assertFalse(child.reaped)
            self.assertIsNotNone(child.pidfd)

    def test_stopped_child_drains_all_streams_and_retains_custody(self):
        with inert_child(hold=True, stopped=True) as child:
            deadline = evidence.boottime() + 3_000_000_000
            received = {name: b"" for name in evidence.CHANNELS}
            stopped = False
            boundaries = set()
            while boundaries | child.eof != evidence.CHANNELS:
                event = child.event(deadline)
                if event is None:
                    continue
                channel, data = event
                if channel == "stopped":
                    self.assertEqual(data, signal.SIGSTOP)
                    stopped = True
                elif channel == "boundary":
                    self.assertTrue(stopped)
                    boundaries.add(data)
                elif channel in received and data is not None:
                    received[channel] += data
            self.assertTrue(stopped)
            self.assertEqual(received["diagnostic"], b"inert-diagnostic")
            self.assertEqual(received["report"], b"inert-report")
            self.assertTrue(child.quiescent())
            child.close(True)
            self.assertTrue(child.quiescent())
            self.assertFalse(child.reaped)
            self.assertIsNotNone(child.pidfd)
            os.kill(child.pid, signal.SIGCONT)
            # SIGCONT makes continuation observable before the next user instruction.
            self.assertFalse(child.quiescent())

    def test_pidfd_setup_failure_reaps_owned_child_and_closes_descriptors(self):
        children = []
        real_fork = os.fork
        before = set(os.listdir("/proc/self/fd"))

        def fork():
            pid = real_fork()
            if pid:
                children.append(pid)
            return pid

        try:
            with (
                mock.patch.object(os, "fork", side_effect=fork),
                mock.patch.object(
                    os, "pidfd_open", side_effect=OSError(24, "fixture fd exhaustion")
                ),
                self.assertRaises(OSError),
                inert_child(hold=True),
            ):
                self.fail("setup failure yielded a child")
            self.assertEqual(len(children), 1)
            with self.assertRaises(ChildProcessError):
                os.waitpid(children[0], os.WNOHANG)
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        finally:
            # Also clean the deliberately broken pre-fix implementation during RED.
            for pid in children:
                try:
                    result, _ = os.waitpid(pid, os.WNOHANG)
                    if result == 0:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                except ChildProcessError:
                    pass

    def test_real_inert_child_is_drained_and_reaped_exactly(self):
        with inert_child() as child:
            deadline = evidence.boottime() + 3_000_000_000
            received = {"report": b"", "diagnostic": b"", "control": b""}
            while child.exitcode is None or len(child.eof) != 3:
                event = child.event(deadline)
                if event is not None and event[0] != "exit" and event[1] is not None:
                    received[event[0]] += event[1]
            self.assertEqual(received["report"], b"inert-report")
            self.assertEqual(received["diagnostic"], b"inert-diagnostic")
            self.assertFalse(child.alive())
            child.close(False)
            self.assertTrue(child.reaped)
            self.assertIsNone(child.pidfd)
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)

    def test_real_inert_hold_cannot_close_without_confirmation(self):
        with inert_child(hold=True) as child:
            deadline = evidence.boottime() + 3_000_000_000
            while "report" not in child.eof:
                child.event(deadline)
            with self.assertRaises(ValueError):
                child.close(True)
            self.assertTrue(child.alive())
            self.assertFalse(child.reaped)
            self.assertIsNotNone(child.pidfd)
            self.assertTrue(child.fds)

    def test_real_nonzero_child_cannot_be_clean_completion(self):
        with inert_child(status=7) as child:
            deadline = evidence.boottime() + 3_000_000_000
            while child.exitcode is None:
                child.event(deadline)
            self.assertEqual(child.exitcode, 7)
            with self.assertRaises(ValueError):
                child.close(False)


if __name__ == "__main__":
    unittest.main()
