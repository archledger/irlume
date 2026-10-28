#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Private report contracts, using public synthetic bytes only."""

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "job_runtime", Path(__file__).with_name("measurement-job-runtime.py")
)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)

CASES = (
    "supervisor-only",
    "loss-before-birth",
    "loss-before-delivery",
    "loss-before-registration",
    "loss-before-placement",
    "loss-before-readback",
    "loss-after-readback",
    "double-fork",
    "zombie",
    "bounds-complete",
    "bounds-supervisor-stall",
    "bounds-worker-stall",
    "bounds-extension-flood",
    "bounds-output-flood",
    "bounds-replay",
    "bounds-late-read",
    "bounds-pre-cutover-loss",
    "bounds-withheld-wait",
    "bounds-withheld-population",
    "bounds-withheld-consumer",
    "bounds-withheld-sentinel",
)


def identity():
    return runtime.Identity(
        "run-01",
        "a" * 64,
        "01234567-89ab-cdef-0123-456789abcdef",
        "b" * 64,
        "c" * 64,
    )


def expected(cases=("supervisor-only",), first_epoch=41):
    return runtime.Expected(identity(), first_epoch, cases)


def failure(operation="fixture-withheld-wait", errno=0):
    return {"operation": operation, "errno": errno}


def terminal(pid=101, code=2, status=9):
    return {"pid": pid, "code": code, "status": status}


def report(case="supervisor-only", epoch=41):
    row = {
        "bounds": None,
        "case": case,
        "reached": None,
        "injected": False,
        "registered": False,
        "placed": False,
        "placement_verified": False,
        "worker_pid": None,
        "descendant_pid": None,
        "worker_reaped": False,
        "descendant_reaped": False,
        "oom_observations": 0,
        "oom_kills": [0, 0, 0],
        "epoch": epoch,
        "outcome": "complete",
        "reserved": True,
        "leases_held": [False, False],
        "custody_retained": False,
        "releases": 1,
        "first": None,
        "errors": [None] * 16,
        "errors_truncated": False,
        "kill": True,
        "empty": True,
        "direct_reaped": True,
        "drained": True,
        "consumers": 0,
        "adopted": 0,
        "terminal": [terminal()] + [None] * 32,
        "operations": 30,
        "native_authorized": False,
        "full_contract_proven": False,
    }
    if case.startswith("bounds-"):
        row.update(
            registered=True,
            placed=True,
            placement_verified=True,
            worker_pid=102,
            worker_reaped=True,
            adopted=1,
            oom_observations=3,
            terminal=[terminal(), terminal(102, 1, 0)] + [None] * 31,
        )
        row["bounds"] = {
            "output": {"bytes": 9, "exhausted": False},
            "work_cap": 10_000_000_000,
            "caps": [5_000_000_000, 10_000_000_000, 15_000_000_000, 20_000_000_000],
            "active": True,
            "candidate_received": True,
            "result_frame": [2, *epoch.to_bytes(8, "little")],
            "result_return": 9_000_000_000,
            "result_postcheck_pending": False,
            "replay_epoch": None,
            "result_valid": True,
            "worker_terminal": True,
            "cutover": True,
            "loss_observed": False,
            "stopped_oom_checked": True,
            "sentinel_created": True,
            "sentinel_pre": True,
            "sentinel_post": True,
            "sentinel_stopped": True,
            "sentinel_failed": False,
            "consumer_withheld": False,
        }
    if case == "bounds-withheld-wait":
        row.update(
            outcome="incomplete",
            releases=0,
            leases_held=[True, True],
            custody_retained=True,
            first=failure(),
            errors=[failure()] + [None] * 15,
            worker_reaped=False,
            drained=False,
            consumers=1,
            adopted=0,
            terminal=[terminal()] + [None] * 32,
        )
    if case in CASES[1:9]:
        cut = case[5:] if case.startswith("loss-") else "before-placement"
        born = cut != "before-birth"
        row.update(
            outcome="aborted_clean",
            reached=cut,
            injected=True,
            first=failure("supervisor-loss-injected"),
            errors=[failure("supervisor-loss-injected")] + [None] * 15,
            oom_observations=3,
            worker_pid=102 if born else None,
            worker_reaped=born,
            adopted=int(born),
            registered=cut in ("before-placement", "before-readback", "after-readback"),
            placed=cut in ("before-readback", "after-readback"),
            placement_verified=cut == "after-readback",
        )
        if born:
            row["terminal"][1] = terminal(102)
        if case == "double-fork":
            row.update(descendant_pid=103, descendant_reaped=True, adopted=2)
            row["terminal"][2] = terminal(103)
    if case in CASES[10:17]:
        state = row["bounds"]
        row["outcome"] = "aborted_clean"
        state["cutover"] = False
        state["result_valid"] = case == "bounds-pre-cutover-loss"
        state["worker_terminal"] = case == "bounds-pre-cutover-loss"
        if case != "bounds-pre-cutover-loss":
            state.update(
                candidate_received=False,
                result_frame=None,
                result_return=None,
                stopped_oom_checked=False,
                sentinel_stopped=False,
            )
        operation = {
            "bounds-supervisor-stall": "expired",
            "bounds-worker-stall": "expired",
            "bounds-extension-flood": "bounds-result-record",
            "bounds-output-flood": "output-cap",
            "bounds-replay": "bounds-result-epoch",
            "bounds-late-read": "expired",
            "bounds-pre-cutover-loss": "bounds-supervisor-loss",
        }[case]
        row.update(first=failure(operation), errors=[failure(operation)] + [None] * 15)
        if case == "bounds-replay":
            state.update(
                replay_epoch=epoch + 1,
                result_frame=[2, *(epoch + 1).to_bytes(8, "little")],
            )
        if case == "bounds-extension-flood":
            state["result_frame"] = [12, *epoch.to_bytes(8, "little")]
        if case == "bounds-late-read":
            state["candidate_received"] = True
            state["result_frame"] = [2, *epoch.to_bytes(8, "little")]
            state["result_return"] = state["work_cap"]
        if case == "bounds-pre-cutover-loss":
            state["loss_observed"] = True
    if case in CASES[18:]:
        state = row["bounds"]
        row.update(
            outcome="incomplete",
            releases=0,
            leases_held=[True, True],
            custody_retained=True,
        )
        operation = {
            "bounds-withheld-population": "fixture-withheld-population",
            "bounds-withheld-consumer": "expired",
            "bounds-withheld-sentinel": "fixture-withheld-sentinel",
        }[case]
        row.update(first=failure(operation), errors=[failure(operation)] + [None] * 15)
        if case == "bounds-withheld-population":
            row["empty"] = False
        if case == "bounds-withheld-consumer":
            row["consumers"] = 1
            state["consumer_withheld"] = True
        if case == "bounds-withheld-sentinel":
            state["sentinel_post"] = False
            state["sentinel_stopped"] = False
    return row


def packet(case="supervisor-only", sequence=0, epoch=41):
    return {
        "scope": "contained-job-report-v1",
        "mode": "runtime-candidate",
        "identity": identity()._asdict(),
        "sequence": sequence,
        "limits": {
            "case_total_ns": 20_000_000_000,
            "phase_ns": 5_000_000_000,
            "case_output_bytes": 1_048_576,
            "max_operations": 8192,
            "batch_cases": 6,
        },
        "completion": "quarantined" if case in CASES[17:] else "clean",
        "report": report(case, epoch),
    }


def frame(row):
    payload = json.dumps(row, separators=(",", ":")).encode()
    return len(payload).to_bytes(4, "big") + payload


class FrameTests(unittest.TestCase):
    def test_worker_roles_remain_distinct_even_when_wait_is_withheld(self):
        case = "bounds-withheld-wait"
        for key, value in [
            ("worker_pid", None),
            ("worker_pid", 101),
            ("descendant_pid", 103),
        ]:
            row = packet(case)
            row["report"][key] = value
            with self.subTest(key=key, value=value):
                self.assertFalse(
                    runtime.decode_report(
                        frame(row), expected((case,)), 0
                    ).matches_expected
                )
        case = "loss-before-registration"
        row = packet(case)
        row["report"].update(
            worker_pid=None,
            worker_reaped=False,
            descendant_pid=102,
            descendant_reaped=True,
        )
        self.assertFalse(
            runtime.decode_report(frame(row), expected((case,)), 0).matches_expected
        )

    def test_injected_supervisor_loss_requires_the_observed_sigkill_status(self):
        for case in (*CASES[1:9], "bounds-pre-cutover-loss"):
            for code, status in [(1, 0), (2, 15), (3, 9)]:
                row = packet(case)
                row["report"]["terminal"][0] = terminal(101, code, status)
                with self.subTest(case=case, code=code, status=status):
                    self.assertFalse(
                        runtime.decode_report(
                            frame(row), expected((case,)), 0
                        ).matches_expected
                    )

    def test_failure_result_evidence_matches_the_reached_producer_stage(self):
        for case in CASES[10:15]:
            for key, value in [
                ("candidate_received", True),
                ("result_return", 9_000_000_000),
                ("worker_terminal", True),
            ]:
                row = packet(case)
                row["report"]["bounds"][key] = value
                with self.subTest(case=case, key=key):
                    self.assertFalse(
                        runtime.decode_report(
                            frame(row), expected((case,)), 0
                        ).matches_expected
                    )
        for case in ("bounds-supervisor-stall", "bounds-worker-stall"):
            row = packet(case)
            row["report"]["bounds"]["result_frame"] = [
                2,
                *(41).to_bytes(8, "little"),
            ]
            self.assertFalse(
                runtime.decode_report(frame(row), expected((case,)), 0).matches_expected
            )

    def test_early_flood_rejection_allows_absent_but_not_valid_result_frames(self):
        for case in ("bounds-extension-flood", "bounds-output-flood"):
            for operation in ("channel-surplus", "output-cap"):
                row = packet(case)
                row["report"]["first"] = failure(operation)
                row["report"]["errors"] = [failure(operation)] + [None] * 15
                row["report"]["bounds"]["result_frame"] = None
                with self.subTest(case=case, operation=operation):
                    self.assertTrue(
                        runtime.decode_report(
                            frame(row), expected((case,)), 0
                        ).matches_expected
                    )
                    row["report"]["bounds"]["result_frame"] = [
                        2,
                        *(41).to_bytes(8, "little"),
                    ]
                    self.assertFalse(
                        runtime.decode_report(
                            frame(row), expected((case,)), 0
                        ).matches_expected
                    )

    def test_each_required_field_is_individually_required(self):
        original = packet("bounds-withheld-wait")
        paths = [
            (),
            ("identity",),
            ("limits",),
            ("report",),
            ("report", "bounds"),
            ("report", "bounds", "output"),
            ("report", "first"),
            ("report", "errors", 0),
            ("report", "terminal", 0),
        ]
        for path in paths:
            parent = original
            for key in path:
                parent = parent[key]
            for key in parent:
                altered = copy.deepcopy(original)
                obj = altered
                for part in path:
                    obj = obj[part]
                del obj[key]
                with self.subTest(path=path, key=key), self.assertRaises(ValueError):
                    runtime.decode_report(
                        frame(altered), expected(("bounds-withheld-wait",)), 0
                    )

    def test_each_injected_failure_requires_its_zero_errno(self):
        for case in CASES[1:]:
            if case == "bounds-complete":
                continue
            row = packet(case)
            row["report"]["first"]["errno"] = 5
            row["report"]["errors"][0]["errno"] = 5
            with self.subTest(case=case):
                self.assertFalse(
                    runtime.decode_report(
                        frame(row), expected((case,)), 0
                    ).matches_expected
                )

    def test_nested_primitive_types_and_ranges(self):
        changes = [
            (("bounds", "active"), 1),
            (("bounds", "output", "exhausted"), 0),
            (("bounds", "output", "bytes"), -1),
            (("bounds", "work_cap"), True),
            (("bounds", "caps"), [0, 1, 2]),
            (("bounds", "result_frame"), [0] * 8),
            (("bounds", "result_frame"), [256] * 9),
            (("bounds", "replay_epoch"), 0),
            (("bounds", "result_return"), 2**64),
            (("first", "errno"), -1),
            (("first", "operation"), "bad\n"),
            (("terminal", 0, "code"), 4),
            (("terminal", 0, "status"), 0),
            (("terminal", 0, "pid"), True),
        ]
        for path, value in changes:
            row = packet("bounds-withheld-wait")
            obj = row["report"]
            for key in path[:-1]:
                obj = obj[key]
            obj[path[-1]] = value
            with self.subTest(path=path, value=value), self.assertRaises(ValueError):
                runtime.decode_report(
                    frame(row), expected(("bounds-withheld-wait",)), 0
                )

    def test_all_twenty_one_native_case_descriptions_match(self):
        for case in CASES:
            with self.subTest(case=case):
                result = runtime.decode_report(
                    frame(packet(case)), expected((case,)), 0
                )
                self.assertTrue(result.matches_expected)
                self.assertFalse(result.accepted)

    def test_clean_report_is_candidate_only(self):
        raw = frame(packet())
        result = runtime.decode_report(raw, expected(), 0)
        self.assertEqual(
            (result.case, result.epoch, result.sequence), ("supervisor-only", 41, 0)
        )
        self.assertEqual(result.frame, raw)
        self.assertTrue(result.matches_expected)
        self.assertFalse(
            result.accepted or result.native_authorized or result.full_contract_proven
        )

    def test_all_identity_components_and_sequence_are_bound(self):
        for key in identity()._fields:
            row = packet()
            row["identity"][key] = "other" if key == "run_id" else "d" * 64
            with self.subTest(key=key), self.assertRaises(ValueError):
                runtime.decode_report(frame(row), expected(), 0)
        for path, value in [("epoch", 42), ("case", "bounds-complete")]:
            row = packet()
            row["report"][path] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                runtime.decode_report(frame(row), expected(), 0)
        row = packet(sequence=1)
        with self.assertRaises(ValueError):
            runtime.decode_report(frame(row), expected(), 0)

    def test_framing_rejects_short_extra_oversized_and_nonbytes(self):
        raw = frame(packet())
        for bad in [
            b"",
            b"\0" * 4,
            raw[:-1],
            raw + b"\n",
            b"\xff" * 4,
            (16_385).to_bytes(4, "big") + b" " * 16_385,
            bytearray(raw),
            "not bytes",
        ]:
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                runtime.decode_report(bad, expected(), 0)

    def test_json_duplicates_floats_constants_and_bad_utf8_refuse(self):
        text = json.dumps(packet(), separators=(",", ":"))
        variants = [
            text[:-1] + ',"scope":"contained-job-report-v1"}',
            text.replace('"epoch":41', '"epoch":41,"epoch":41'),
            text.replace('"epoch":41', '"epoch":41.0'),
            text.replace('"epoch":41', '"epoch":4.1e1'),
            text.replace('"epoch":41', '"epoch":NaN'),
            text.replace('"epoch":41', '"epoch":' + "9" * 200),
        ]
        for text in variants:
            raw = text.encode()
            with self.subTest(text=text[:100]), self.assertRaises(ValueError):
                runtime.decode_report(len(raw).to_bytes(4, "big") + raw, expected(), 0)
        with self.assertRaises(ValueError):
            runtime.decode_report(b"\0\0\0\1\xff", expected(), 0)

    def test_every_object_has_exact_fields(self):
        original = packet("bounds-complete")
        paths = [
            (),
            ("identity",),
            ("limits",),
            ("report",),
            ("report", "bounds"),
            ("report", "bounds", "output"),
            ("report", "terminal", 0),
        ]
        for path in paths:
            for add in (True, False):
                row = copy.deepcopy(original)
                obj = row
                for key in path:
                    obj = obj[key]
                if add:
                    obj["invented"] = False
                else:
                    del obj[next(iter(obj))]
                with self.subTest(path=path, add=add), self.assertRaises(ValueError):
                    runtime.decode_report(frame(row), expected(("bounds-complete",)), 0)

    def test_integer_boolean_and_fixed_array_domains(self):
        original = packet()
        for key, bad in [
            ("epoch", True),
            ("epoch", 0),
            ("epoch", 2**64),
            ("consumers", -1),
            ("consumers", 2**32),
            ("operations", False),
            ("adopted", 33),
            ("kill", 1),
            ("leases_held", [False]),
            ("oom_kills", [0, 0]),
            ("errors", [None] * 15),
            ("terminal", [None] * 34),
            ("worker_pid", 0),
            ("worker_pid", 2**31),
        ]:
            row = copy.deepcopy(original)
            row["report"][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                runtime.decode_report(frame(row), expected(), 0)

    def test_false_cleanup_claims_do_not_match(self):
        for key, value in [
            ("kill", False),
            ("empty", False),
            ("direct_reaped", False),
            ("drained", False),
            ("consumers", 1),
            ("releases", 0),
            ("leases_held", [True, True]),
            ("custody_retained", True),
            ("reserved", False),
            ("errors_truncated", True),
        ]:
            row = packet()
            row["report"][key] = value
            with self.subTest(key=key):
                self.assertFalse(
                    runtime.decode_report(frame(row), expected(), 0).matches_expected
                )

    def test_no_job_created_preserves_missing_cleanup(self):
        row = packet()
        row["report"].update(
            outcome="no_job_created",
            kill=False,
            empty=False,
            direct_reaped=False,
            drained=False,
            terminal=[None] * 33,
            operations=0,
            first=failure("clock", 5),
            errors=[failure("clock", 5)] + [None] * 15,
        )
        result = runtime.decode_report(frame(row), expected(), 0)
        self.assertEqual(result.outcome, "no_job_created")
        self.assertEqual(result.cleanup, "not-created")
        self.assertFalse(result.matches_expected or result.accepted)
        self.assertFalse(json.loads(result.frame[4:])["report"]["empty"])

    def test_expected_quarantine_keeps_ownership(self):
        case = "bounds-withheld-wait"
        row = packet(case)
        result = runtime.decode_report(frame(row), expected((case,)), 0)
        self.assertTrue(result.matches_expected)
        self.assertEqual(result.cleanup, "incomplete")
        self.assertFalse(result.accepted)
        for key, value in [
            ("releases", 1),
            ("custody_retained", False),
            ("leases_held", [False, False]),
            ("drained", True),
        ]:
            altered = copy.deepcopy(row)
            altered["report"][key] = value
            with self.subTest(key=key):
                self.assertFalse(
                    runtime.decode_report(
                        frame(altered), expected((case,)), 0
                    ).matches_expected
                )

    def test_bounds_result_and_terminal_evidence_are_not_optional(self):
        case = "bounds-complete"
        row = packet(case)
        self.assertTrue(
            runtime.decode_report(frame(row), expected((case,)), 0).matches_expected
        )
        for key, value in [
            ("cutover", False),
            ("result_valid", False),
            ("worker_terminal", False),
            ("sentinel_post", False),
            ("sentinel_pre", False),
            ("sentinel_failed", True),
        ]:
            altered = copy.deepcopy(row)
            altered["report"]["bounds"][key] = value
            with self.subTest(key=key):
                self.assertFalse(
                    runtime.decode_report(
                        frame(altered), expected((case,)), 0
                    ).matches_expected
                )
        for entries in [
            [None] * 33,
            [terminal(), terminal()] + [None] * 31,
            [terminal(), terminal(999, 1, 0)] + [None] * 31,
        ]:
            altered = copy.deepcopy(row)
            altered["report"]["terminal"] = entries
            self.assertFalse(
                runtime.decode_report(
                    frame(altered), expected((case,)), 0
                ).matches_expected
            )

    def test_complete_result_needs_its_frame_and_timed_return(self):
        case = "bounds-complete"
        for key, value in [
            ("candidate_received", False),
            ("result_frame", None),
            ("result_return", None),
            ("result_frame", [2, 42, 0, 0, 0, 0, 0, 0, 0]),
            ("result_return", 10_000_000_000),
            ("result_postcheck_pending", True),
        ]:
            row = packet(case)
            row["report"]["bounds"][key] = value
            with self.subTest(key=key, value=value):
                self.assertFalse(
                    runtime.decode_report(
                        frame(row), expected((case,)), 0
                    ).matches_expected
                )

    def test_unknown_adopted_wait_cannot_replace_worker_identity(self):
        case = "loss-before-registration"
        row = packet(case)
        row["report"].update(worker_pid=None, worker_reaped=False)
        self.assertFalse(
            runtime.decode_report(frame(row), expected((case,)), 0).matches_expected
        )

    def test_loss_cut_matches_placement_progress(self):
        for case, key in [
            ("loss-before-registration", "registered"),
            ("loss-before-readback", "placed"),
            ("loss-after-readback", "placement_verified"),
        ]:
            row = packet(case)
            row["report"][key] = not row["report"][key]
            with self.subTest(case=case, key=key):
                self.assertFalse(
                    runtime.decode_report(
                        frame(row), expected((case,)), 0
                    ).matches_expected
                )

    def test_no_job_cannot_claim_that_a_child_was_reaped(self):
        row = packet()
        row["report"]["outcome"] = "no_job_created"
        with self.assertRaises(ValueError):
            runtime.decode_report(frame(row), expected(), 0)

    def test_model_and_runtime_records_are_mutually_rejected(self):
        row = packet()
        row["mode"] = "model"
        with self.assertRaises(ValueError):
            runtime.decode_report(frame(row), expected(), 0)
        spec = importlib.util.spec_from_file_location(
            "old_job_tests", Path(__file__).with_name("test-measurement-job.py")
        )
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        with self.assertRaises(ValueError):
            runtime.decode_report(frame(old.evidence()), expected(), 0)
        with self.assertRaises(ValueError):
            old.job.validate_evidence(json.dumps(packet()).encode(), old.expected())

    def test_claimed_authority_or_changed_limits_refuse(self):
        for key in ("native_authorized", "full_contract_proven"):
            row = packet()
            row["report"][key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                runtime.decode_report(frame(row), expected(), 0)
        for key in packet()["limits"]:
            for bad in (True, packet()["limits"][key] + 1):
                row = packet()
                row["limits"][key] = bad
                with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                    runtime.decode_report(frame(row), expected(), 0)


class BatchTests(unittest.TestCase):
    def test_duplicate_selection_refuses_a_complete_otherwise_valid_batch(self):
        cases = ("supervisor-only", "supervisor-only")
        raw = tuple(frame(packet(case, i, 41 + i)) for i, case in enumerate(cases))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            runtime.decode_batch(raw, expected(cases))

    def test_exact_three_case_selection_is_not_full_fixture_coverage(self):
        cases = ("supervisor-only", "bounds-complete", "bounds-withheld-wait")
        raws = tuple(frame(packet(case, i, 41 + i)) for i, case in enumerate(cases))
        result = runtime.decode_batch(raws, expected(cases))
        self.assertTrue(result.matches_expected)
        self.assertEqual(result.cases, cases)
        self.assertFalse(result.full_inventory or result.accepted)

    def test_missing_duplicate_reordered_or_stale_frames_refuse(self):
        cases = ("supervisor-only", "bounds-complete")
        raws = tuple(frame(packet(case, i, 41 + i)) for i, case in enumerate(cases))
        for bad in (
            raws[:1],
            raws + raws[:1],
            (raws[0], raws[0]),
            tuple(reversed(raws)),
        ):
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                runtime.decode_batch(bad, expected(cases))

    def test_expected_input_cannot_shrink_or_overflow_inventory(self):
        for cases, epoch in [
            ((), 41),
            (("supervisor-only",) * 2, 41),
            (CASES[:7], 41),
            (("unknown",), 41),
            (("supervisor-only",), 0),
            (("supervisor-only",), True),
            (CASES[:2], 2**64 - 1),
        ]:
            with self.subTest(cases=cases, epoch=epoch), self.assertRaises(ValueError):
                runtime.decode_batch((), expected(cases, epoch))


class CasePolicyTests(unittest.TestCase):
    def test_exact_native_inventory(self):
        self.assertEqual(runtime.CASES, CASES)

    def test_outcomes_are_fixed_by_case_not_report(self):
        for index, name in enumerate(CASES):
            expected = (
                "complete"
                if index in (0, 9)
                else "incomplete"
                if index >= 17
                else "aborted_clean"
            )
            with self.subTest(name=name):
                self.assertEqual(runtime.expected_outcome(name), expected)

    def test_unknown_or_nonexact_case_refuses(self):
        for name in (
            "",
            "normal",
            "bounds_complete",
            "bounds-complete ",
            "Bounds-Complete",
            None,
            0,
            True,
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                runtime.expected_outcome(name)


class RustInteropTests(unittest.TestCase):
    """Run explicitly with --rust-frames FILE from the named Rust corpus test."""

    output = b""

    def frames(self):
        rows = {}
        for line in self.output.decode("ascii").splitlines():
            if line.startswith("R1_FRAME "):
                _, case, encoded = line.split()
                self.assertNotIn(case, rows)
                rows[case] = bytes.fromhex(encoded)
        self.assertEqual(tuple(rows), CASES)
        return rows

    def test_all_rust_emitted_fields_match_independent_python_vectors(self):
        for case, data in self.frames().items():
            with self.subTest(case=case):
                self.assertEqual(json.loads(data[4:]), packet(case))
                observed = runtime.decode_report(data, expected((case,)), 0)
                self.assertTrue(observed.matches_expected)
                self.assertFalse(
                    observed.accepted
                    or observed.native_authorized
                    or observed.full_contract_proven
                )

    def test_mutated_rust_frames_cannot_change_binding_or_drop_reaping(self):
        for case, data in self.frames().items():
            with self.subTest(case=case):
                row = json.loads(data[4:])
                row["report"]["epoch"] += 1
                with self.assertRaises(ValueError):
                    runtime.decode_report(frame(row), expected((case,)), 0)
                row = json.loads(data[4:])
                row["report"]["direct_reaped"] = False
                self.assertFalse(
                    runtime.decode_report(
                        frame(row), expected((case,)), 0
                    ).matches_expected
                )


if __name__ == "__main__":
    if sys.argv[1:2] == ["--rust-frames"]:
        if len(sys.argv) != 3:
            raise SystemExit(
                "usage: test-measurement-job-runtime.py --rust-frames FILE"
            )
        with Path(sys.argv[2]).open("rb") as source:
            RustInteropTests.output = source.read(2 * 1024 * 1024 + 1)
        if len(RustInteropTests.output) > 2 * 1024 * 1024:
            raise SystemExit("oversized Rust corpus output")
        unittest.main(argv=sys.argv[:1], defaultTest="RustInteropTests")
    else:
        unittest.main(defaultTest=("CasePolicyTests", "FrameTests", "BatchTests"))
