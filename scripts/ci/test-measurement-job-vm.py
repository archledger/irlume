#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Model the controller only. No processes, VM tools or recovery are executed."""

import importlib.util
import json
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("job_vm", HERE / "measurement-job-vm.py")
vm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vm)
SPEC = importlib.util.spec_from_file_location(
    "job_cases", HERE / "test-measurement-job.py"
)
cases = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cases)
# The input factories must use the same private module instance as the controller.
cases.job = vm.job


class Output:
    def __init__(self):
        self.rows = {}
        self.blobs = {}
        self.closed = False

    def save(self, label, row):
        if label in self.rows:
            raise AssertionError("receipt overwritten")
        self.rows[label] = dict(row)

    def save_blob(self, label, data):
        if label in self.blobs:
            raise AssertionError("evidence overwritten")
        self.blobs[label] = data

    def close(self):
        self.closed = True


class Process:
    def __init__(self, waits=(0,), kill_error=None):
        self.waits = list(waits)
        self.timeouts = []
        self.kills = 0
        self.kill_error = kill_error

    def wait(self, timeout):
        self.timeouts.append(timeout)
        value = self.waits.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    def kill(self):
        self.kills += 1
        if self.kill_error:
            raise self.kill_error


class Model:
    """In-memory model, not a QEMU backend or runtime qualification."""

    model_only = True

    def __init__(self, process=None):
        self.process = process or Process()
        self.calls = []
        self.data = json.dumps(cases.evidence()).encode()
        self.size = 1

    def prepare(self, argv, **bounds):
        self.calls.append(("prepare", argv, bounds))
        return {"status": 0, "output_bytes": 0, "overlay_bytes": 1}

    def spawn(self, argv, **bounds):
        self.calls.append(("spawn", argv, bounds))
        return self.process

    def serial_size(self):
        return self.size

    def recover(self, overlay, **bounds):
        self.calls.append(("recover", overlay, bounds))
        return self.data


def host():
    return {
        "uid": 1000,
        "euid": 1000,
        "gid": 1000,
        "egid": 1000,
        "kvm": True,
        "tools": True,
        "scratch_free": vm.job.LIMITS["scratch_bytes"],
    }


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.output = Output()
        self.model = Model()
        self.host = host()
        self.patches = [
            mock.patch.object(vm.job.OwnedOutput, "create", return_value=self.output),
            mock.patch.object(vm, "observe_host", side_effect=lambda *_: self.host),
            mock.patch.object(vm.time, "monotonic", return_value=0),
            mock.patch.object(
                vm.job,
                "observe_input",
                side_effect=lambda path, **_: next(
                    digest
                    for _, expected_path, digest in cases.expected().inputs
                    if path == expected_path
                ),
            ),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def tearDown(self):
        # Leftover ownership is inspected explicitly by its test, not leaked to others.
        vm._OWNED.clear()

    def run_model(self, **options):
        return vm.run(
            json.dumps(cases.profile()).encode(),
            cases.expected(),
            "/private/run",
            _model=self.model,
            **options,
        )

    def assert_failed(self, row, reason):
        self.assertEqual(row["reason"], reason)
        self.assertFalse(row["accepted"])
        self.assertFalse(row["model_matched"])
        self.assertIn("started", self.output.rows)
        self.assertIn("finished", self.output.rows)
        self.assertFalse(self.output.rows["started"]["accepted"])

    def assert_expected_context(self, row, want):
        expected = {
            "run_id": want.run_id,
            "boot_id": want.boot_id,
            "epoch": want.epoch,
            "cases": [list(case) for case in want.cases],
            "inputs": {
                role: {"path": path, "sha256": digest}
                for role, path, digest in want.inputs
            },
            "limits": dict(vm.job.LIMITS),
        }
        for key, value in expected.items():
            self.assertIn(key, row)
            self.assertEqual(row[key], value)

    def test_no_real_runtime_can_be_enabled_by_profile_or_tool_availability(self):
        row = vm.run(
            json.dumps(cases.profile()).encode(), cases.expected(), "/private/run"
        )
        self.assert_failed(row, "runtime-unavailable")
        self.assertFalse(row["qemu_started"])
        self.assertEqual(self.model.calls, [])

    def test_model_success_is_explicitly_partial_and_readonly(self):
        row = self.run_model()
        self.assertEqual(row["status"], "model-complete")
        self.assertTrue(row["model_matched"])
        self.assertFalse(row["accepted"])
        self.assertFalse(row["native_authorized"])
        self.assertFalse(row["full_contract_proven"])
        self.assertTrue(row["qemu_reaped"])
        self.assertFalse(row["leftover"])
        self.assertEqual(
            [call[0] for call in self.model.calls], ["prepare", "spawn", "recover"]
        )
        self.assertEqual(
            self.model.calls[-1][2],
            {"read_only": True, "timeout": 60, "limit": vm.job.EVIDENCE_LIMIT},
        )
        self.assertEqual(self.output.blobs["recovered"], self.model.data)
        self.assertTrue(self.output.closed)
        self.assertEqual(vm._OWNED, {})

    def test_root_setid_missing_kvm_tools_or_scratch_never_spawns(self):
        for updates in [
            {"uid": 0, "euid": 0},
            {"euid": 2},
            {"egid": 2},
            {"kvm": False},
            {"tools": False},
            {"scratch_free": 0},
            {"uid": True},
        ]:
            with self.subTest(updates=updates):
                self.output.rows.clear()
                self.model.calls.clear()
                self.host = dict(host(), **updates)
                self.assert_failed(self.run_model(), "host-preflight")
                self.assertEqual(self.model.calls, [])

    def test_missing_or_changed_observations_never_spawn(self):
        for effect in [lambda *a, **k: "f" * 64, OSError("missing")]:
            with (
                self.subTest(effect=effect),
                mock.patch.object(vm.job, "observe_input", side_effect=effect),
            ):
                self.output.rows.clear()
                self.assert_failed(self.run_model(), "input-preflight")
                self.assertEqual(self.model.calls, [])

    def test_unsafe_output_never_gets_failure_write(self):
        with (
            mock.patch.object(
                vm.job.OwnedOutput, "create", side_effect=ValueError("unsafe")
            ),
            self.assertRaises(ValueError),
        ):
            self.run_model()
        self.assertEqual(self.output.rows, {})
        self.assertEqual(self.model.calls, [])

    def test_profile_refusal_has_started_and_failure_receipts(self):
        row = vm.run(
            b'{"qualified":true}', cases.expected(), "/private/run", _model=self.model
        )
        self.assert_failed(row, "profile-preflight")
        self.assertEqual(self.model.calls, [])

    def test_missing_host_loss_handling_is_not_a_success_flag(self):
        value = cases.profile()
        value["host_loss"] = {"owner": "owner", "mechanism": "none"}
        row = vm.run(
            json.dumps(value).encode(),
            cases.expected(),
            "/private/run",
            _model=self.model,
        )
        self.assert_failed(row, "profile-preflight")
        self.assertEqual(self.model.calls, [])

    def test_prepare_failure_keeps_its_receipt_without_launch(self):
        self.model.prepare = mock.Mock(side_effect=TimeoutError)
        self.assert_failed(self.run_model(), "prepare")
        self.assertFalse(self.output.rows["finished"]["qemu_started"])

    def test_spawn_failure_does_not_claim_reaping(self):
        self.model.spawn = mock.Mock(side_effect=OSError)
        row = self.run_model()
        self.assert_failed(row, "spawn")
        self.assertFalse(row["qemu_started"])
        self.assertFalse(row["qemu_reaped"])

    def test_early_nonzero_or_signal_exit_never_accepts_recovered_success(self):
        for status in [77, 1, -15]:
            with self.subTest(status=status):
                self.output.rows.clear()
                self.output.blobs.clear()
                self.model.process = Process((status,))
                row = self.run_model()
                self.assert_failed(row, "qemu-exit")
                self.assertTrue(row["qemu_reaped"])
                self.assertEqual(self.model.process.kills, 0)
                self.assertIn("recovered", self.output.blobs)

    def test_timeout_kills_only_owned_handle_and_reaps_with_finite_budget(self):
        self.model.process = Process((TimeoutError(), -9))
        row = self.run_model()
        self.assert_failed(row, "wait")
        self.assertEqual(self.model.process.kills, 1)
        self.assertEqual(self.model.process.timeouts, [300, 5])
        self.assertTrue(row["qemu_reaped"])
        self.assertFalse(row["leftover"])

    def test_failed_reaping_retains_exact_handle_and_skips_recovery(self):
        self.model.process = Process((TimeoutError(), TimeoutError()))
        row = self.run_model()
        self.assert_failed(row, "wait")
        self.assertEqual(row["cleanup"], "incomplete")
        self.assertTrue(row["leftover"])
        self.assertFalse(row["qemu_reaped"])
        self.assertIs(vm._OWNED[id(self.model.process)], self.model.process)
        self.assertNotIn("recover", [call[0] for call in self.model.calls])

    def test_kill_failure_does_not_skip_bounded_wait_or_erase_primary_failure(self):
        self.model.process = Process((TimeoutError(), -9), OSError("kill failed"))
        row = self.run_model()
        self.assert_failed(row, "wait")
        self.assertTrue(row["stop_error"])
        self.assertTrue(row["qemu_reaped"])
        self.assertEqual(len(self.model.process.timeouts), 2)

    def test_cancellation_is_recorded_and_owned_process_is_reaped(self):
        self.model.process = Process((KeyboardInterrupt(), -9))
        with self.assertRaises(KeyboardInterrupt):
            self.run_model()
        row = self.output.rows["finished"]
        self.assert_failed(row, "interrupted")
        self.assertTrue(row["qemu_reaped"])

    def test_invalid_or_missing_recovery_is_retained_but_never_accepted(self):
        for data in [b"", b"{}", self.model.data + self.model.data]:
            with self.subTest(data=data[:50]):
                self.output.rows.clear()
                self.output.blobs.clear()
                self.model.process = Process()
                self.model.data = data
                row = self.run_model()
                self.assert_failed(row, "evidence")
                self.assertIn("recovered", self.output.blobs)

    def test_oversized_serial_or_recovery_never_validates(self):
        self.model.size = vm.job.LIMITS["serial_bytes"] + 1
        self.assert_failed(self.run_model(), "serial-limit")
        self.output.rows.clear()
        self.model.size = 0
        self.model.process = Process()
        self.model.data = b"x" * (vm.job.EVIDENCE_LIMIT + 1)
        self.assert_failed(self.run_model(), "recovery")

    def test_late_zero_exit_is_not_timely_success(self):
        now = [0]

        def late_wait(**_):
            now[0] = 301
            return 0

        self.model.process.wait = late_wait
        with mock.patch.object(vm.time, "monotonic", side_effect=lambda: now[0]):
            row = self.run_model()
        self.assert_failed(row, "wait")

    def test_late_prepare_and_recovery_cannot_extend_deadlines(self):
        for operation, duration, reason in [
            ("prepare", 61, "prepare"),
            ("recover", 61, "recovery"),
        ]:
            with self.subTest(operation=operation):
                self.output.rows.clear()
                self.output.blobs.clear()
                self.model = Model()
                now = [0]
                original = getattr(self.model, operation)

                def delayed(
                    *args, original=original, now=now, duration=duration, **kwargs
                ):
                    result = original(*args, **kwargs)
                    now[0] += duration
                    return result

                setattr(self.model, operation, delayed)
                with mock.patch.object(
                    vm.time, "monotonic", side_effect=lambda now=now: now[0]
                ):
                    self.assert_failed(self.run_model(), reason)

    def test_changed_validator_after_launch_refuses_even_complete_evidence(self):
        def change_after_wait(**_):
            self.postflight = mock.patch.object(
                vm.job, "observe_input", return_value="f" * 64
            )
            self.postflight.start()
            self.addCleanup(self.postflight.stop)
            return 0

        self.model.process.wait = change_after_wait
        self.assert_failed(self.run_model(), "input-postflight")
        self.assertIn("recovered", self.output.blobs)

    def test_prepare_and_reap_results_require_exact_bounded_scalars(self):
        for prepared in [
            {"status": True, "output_bytes": 0, "overlay_bytes": 1},
            {"status": 0, "output_bytes": 65537, "overlay_bytes": 1},
            {"status": 0, "output_bytes": 0, "overlay_bytes": 0},
        ]:
            with self.subTest(prepared=prepared):
                self.output.rows.clear()
                self.model.prepare = mock.Mock(return_value=prepared)
                self.assert_failed(self.run_model(), "prepare")
        self.output.rows.clear()
        self.model = Model(Process((True, -9)))
        self.assert_failed(self.run_model(), "wait")
        self.assertEqual(self.model.process.kills, 1)

    def test_interrupted_recovery_retains_non_success_receipt(self):
        self.model.recover = mock.Mock(side_effect=KeyboardInterrupt)
        with self.assertRaises(KeyboardInterrupt):
            self.run_model()
        self.assert_failed(self.output.rows["finished"], "recovery")

    def test_unrelated_handle_is_not_touched_during_cleanup(self):
        unrelated = Process((0,))
        vm._OWNED[id(unrelated)] = unrelated
        self.model.process = Process((TimeoutError(), -9))
        self.run_model()
        self.assertEqual(unrelated.kills, 0)
        self.assertEqual(unrelated.timeouts, [])
        self.assertIs(vm._OWNED[id(unrelated)], unrelated)

    def test_unexpected_model_exception_reaps_and_records_before_propagating(self):
        self.model.process.wait = mock.Mock(
            side_effect=[AssertionError("model fault"), -9]
        )
        with self.assertRaises(AssertionError):
            self.run_model()
        self.assert_failed(self.output.rows["finished"], "wait")
        self.assertTrue(self.output.rows["finished"]["qemu_reaped"])

    def test_observation_recheck_precedes_spawn(self):
        count = 0

        def changed(path, **_):
            nonlocal count
            count += 1
            if count > len(vm.job.ROLES):
                return "f" * 64
            return next(d for _, p, d in cases.expected().inputs if p == path)

        with mock.patch.object(vm.job, "observe_input", side_effect=changed):
            self.assert_failed(self.run_model(), "input-preflight")
        self.assertNotIn("spawn", [call[0] for call in self.model.calls])

    def test_model_marker_is_not_read_from_json(self):
        self.model.model_only = False
        self.assert_failed(self.run_model(), "runtime-unavailable")
        self.assertEqual(self.model.calls, [])

    def test_unexpected_kill_still_waits_finalizes_and_preserves_primary_cause(self):
        primary = TimeoutError("wait expired")
        failure = AssertionError("kill fault")
        self.model.process = Process((primary, -9), failure)
        with self.assertRaises(AssertionError) as caught:
            self.run_model()
        self.assertIs(caught.exception, failure)
        self.assertIs(caught.exception.__cause__, primary)
        self.assertEqual(self.model.process.timeouts, [300, 5])
        row = self.output.rows["finished"]
        self.assert_failed(row, "wait")
        self.assertTrue(row["qemu_reaped"])
        self.assertTrue(row["stop_error"])
        self.assertEqual(
            [item["stage"] for item in row["failures"]], ["wait", "stop-kill"]
        )
        self.assertTrue(self.output.closed)
        self.assertNotIn(id(self.model.process), vm._OWNED)

    def test_unexpected_recovery_still_finalizes_before_reraise(self):
        failure = AssertionError("recovery fault")
        self.model.recover = mock.Mock(side_effect=failure)
        with self.assertRaises(AssertionError) as caught:
            self.run_model()
        self.assertIs(caught.exception, failure)
        self.assertIn("finished", self.output.rows)
        self.assert_failed(self.output.rows["finished"], "recovery")
        self.assertTrue(self.output.closed)

    def test_recovery_uses_only_positive_budget_remaining_after_inspection(self):
        for elapsed in (17, 59.5, 60, 61):
            with self.subTest(elapsed=elapsed):
                self.output = Output()
                # The patched factory captures self.output at setUp, so retain its instance.
                vm.job.OwnedOutput.create.return_value = self.output
                self.model = Model()
                now = [0]

                def inspect(elapsed=elapsed, now=now):
                    now[0] = elapsed
                    return 1

                self.model.serial_size = inspect
                with mock.patch.object(
                    vm.time, "monotonic", side_effect=lambda now=now: now[0]
                ):
                    row = self.run_model()
                recovered = [call for call in self.model.calls if call[0] == "recover"]
                if elapsed >= 60:
                    self.assert_failed(row, "recovery")
                    self.assertEqual(recovered, [])
                else:
                    self.assertTrue(row["model_matched"])
                    self.assertEqual(recovered[0][2]["timeout"], 60 - elapsed)
                self.assertTrue(self.output.closed)

    def test_late_stop_wait_keeps_reap_fact_but_records_deadline_failure(self):
        for elapsed in (4, 5, 6):
            with self.subTest(elapsed=elapsed):
                self.output.rows.clear()
                self.output.blobs.clear()
                self.model = Model()
                now = [0]
                waits = []

                def wait(*, timeout, elapsed=elapsed, now=now, waits=waits):
                    waits.append(timeout)
                    if len(waits) == 1:
                        raise TimeoutError("initial wait expired")
                    now[0] = elapsed
                    return -9

                self.model.process.wait = wait
                with mock.patch.object(
                    vm.time, "monotonic", side_effect=lambda now=now: now[0]
                ):
                    row = self.run_model()
                self.assert_failed(row, "wait")
                self.assertEqual(waits, [300, 5])
                self.assertTrue(row["qemu_reaped"])
                self.assertEqual(row["stop_error"], elapsed >= 5)
                self.assertFalse(row["leftover"])
                self.assertNotIn(id(self.model.process), vm._OWNED)

    def test_unexpected_stop_wait_retains_ownership_and_finalizes(self):
        primary = TimeoutError("initial wait expired")
        failure = AssertionError("stop wait fault")
        self.model.process = Process((primary, failure))
        with self.assertRaises(AssertionError) as caught:
            self.run_model()
        self.assertIs(caught.exception, failure)
        self.assertIs(caught.exception.__cause__, primary)
        row = self.output.rows["finished"]
        self.assert_failed(row, "wait")
        self.assertTrue(row["stop_error"])
        self.assertTrue(row["leftover"])
        self.assertFalse(row["qemu_reaped"])
        self.assertIs(vm._OWNED[id(self.model.process)], self.model.process)
        self.assertNotIn("recover", [call[0] for call in self.model.calls])
        self.assertTrue(self.output.closed)

    def test_cancellation_and_secondary_unexpected_failure_are_preserved(self):
        cancellation = KeyboardInterrupt("cancel")
        failure = AssertionError("kill fault")
        self.model.process = Process((cancellation, -9), failure)
        with self.assertRaises(BaseExceptionGroup) as caught:
            self.run_model()
        self.assertEqual(caught.exception.exceptions, (cancellation, failure))
        row = self.output.rows["finished"]
        self.assert_failed(row, "interrupted")
        self.assertTrue(row["qemu_reaped"])
        self.assertTrue(row["stop_error"])
        self.assertTrue(self.output.closed)

    def test_secondary_recovery_failure_does_not_replace_initial_failure(self):
        primary = TimeoutError("initial wait expired")
        failure = AssertionError("recovery fault")
        self.model.process = Process((primary, -9), OSError("kill failed"))
        self.model.recover = mock.Mock(side_effect=failure)
        with self.assertRaises(AssertionError) as caught:
            self.run_model()
        self.assertIs(caught.exception, failure)
        self.assertIs(caught.exception.__cause__, primary)
        row = self.output.rows["finished"]
        self.assert_failed(row, "wait")
        self.assertEqual(
            [item["stage"] for item in row["failures"]],
            ["wait", "stop-kill", "recovery"],
        )
        self.assertTrue(self.output.closed)

    def test_finished_receipt_failure_preserves_pending_error_and_closes(self):
        primary = AssertionError("initial wait fault")
        receipt_failure = OSError("finished receipt failed")
        self.model.process = Process((primary, -9))
        save = self.output.save
        attempted = []

        def fail_finished(label, row):
            if label == "finished":
                attempted.append(dict(row))
                raise receipt_failure
            save(label, row)

        self.output.save = fail_finished
        with self.assertRaises(BaseExceptionGroup) as caught:
            self.run_model()
        self.assertEqual(caught.exception.exceptions, (primary, receipt_failure))
        self.assertEqual(attempted[0]["reason"], "wait")
        self.assertFalse(attempted[0]["model_matched"])
        self.assertIn("started", self.output.rows)
        self.assertNotIn("finished", self.output.rows)
        self.assertTrue(self.output.closed)
        self.assertNotIn(id(self.model.process), vm._OWNED)

    def test_operational_finished_receipt_error_is_not_returned_as_success(self):
        failure = OSError("finished receipt failed")
        save = self.output.save

        def fail_finished(label, row):
            if label == "finished":
                raise failure
            save(label, row)

        self.output.save = fail_finished
        with self.assertRaises(OSError) as caught:
            self.run_model()
        self.assertIs(caught.exception, failure)
        self.assertIn("started", self.output.rows)
        self.assertNotIn("finished", self.output.rows)
        self.assertTrue(self.output.closed)

    def test_unexpected_receipt_and_close_errors_both_propagate(self):
        receipt_failure = AssertionError("finished receipt fault")
        close_failure = AssertionError("close fault")
        save = self.output.save

        def fail_finished(label, row):
            if label == "finished":
                raise receipt_failure
            save(label, row)

        def fail_close():
            self.output.closed = True
            raise close_failure

        self.output.save = fail_finished
        self.output.close = fail_close
        with self.assertRaises(BaseExceptionGroup) as caught:
            self.run_model()
        self.assertEqual(caught.exception.exceptions, (receipt_failure, close_failure))
        self.assertTrue(self.output.closed)

    def test_kill_spending_entire_stop_budget_never_starts_wait_or_recovery(self):
        now = [0]

        def kill():
            now[0] = 5

        self.model.process = Process((TimeoutError("initial wait expired"),))
        self.model.process.kill = kill
        with mock.patch.object(vm.time, "monotonic", side_effect=lambda: now[0]):
            row = self.run_model()
        self.assert_failed(row, "wait")
        self.assertEqual(self.model.process.timeouts, [300])
        self.assertTrue(row["stop_error"])
        self.assertTrue(row["leftover"])
        self.assertIs(vm._OWNED[id(self.model.process)], self.model.process)
        self.assertNotIn("recover", [call[0] for call in self.model.calls])

    def test_expected_context_survives_prepare_recovery_and_reap_failures(self):
        for phase, reason in (
            ("prepare", "prepare"),
            ("recovery", "recovery"),
            ("reap", "wait"),
        ):
            with self.subTest(phase=phase):
                self.output.rows.clear()
                self.output.blobs.clear()
                self.model = Model()
                if phase == "prepare":
                    self.model.prepare = mock.Mock(
                        side_effect=OSError("prepare failed")
                    )
                elif phase == "recovery":
                    self.model.recover = mock.Mock(
                        side_effect=OSError("recovery failed")
                    )
                else:
                    self.model.process = Process((TimeoutError(), TimeoutError()))
                row = self.run_model()
                self.assert_failed(row, reason)
                for label in ("started", "finished"):
                    self.assert_expected_context(
                        self.output.rows[label], cases.expected()
                    )
                self.assertEqual(self.output.rows["started"]["status"], "started")

    def test_profile_edits_cannot_change_retained_trusted_context(self):
        want = cases.expected()
        profile = cases.profile()
        profile.update(
            run_id="untrusted",
            boot_id="untrusted",
            epoch=1,
            cases=[["untrusted", "unsupported"]],
        )
        profile["inputs"]["payload"]["sha256"] = "f" * 64
        profile["limits"]["host_seconds"] = 1
        row = vm.run(
            json.dumps(profile).encode(), want, "/private/run", _model=self.model
        )
        self.assert_failed(row, "profile-preflight")
        for label in ("started", "finished"):
            self.assert_expected_context(self.output.rows[label], want)
            self.assertNotIn("untrusted", json.dumps(self.output.rows[label]))
        self.assertEqual(self.model.calls, [])

    def test_different_case_and_payload_expectations_remain_distinguishable(self):
        first = cases.expected()
        second = first._replace(
            run_id="run-02",
            boot_id="boot-02",
            epoch=42,
            cases=(("other", "aborted_clean"),),
            inputs=tuple(
                (role, path, "f" * 64 if role == "payload" else digest)
                for role, path, digest in first.inputs
            ),
        )
        snapshots = []
        for want in (first, second):
            self.output.rows.clear()
            vm.run(b"{}", want, "/private/run", _model=self.model)
            self.assert_expected_context(self.output.rows["started"], want)
            self.assert_expected_context(self.output.rows["finished"], want)
            snapshots.append(self.output.rows["started"])
        self.assertNotEqual(snapshots[0]["cases"], snapshots[1]["cases"])
        self.assertNotEqual(
            snapshots[0]["inputs"]["payload"], snapshots[1]["inputs"]["payload"]
        )
        self.assertEqual(self.model.calls, [])

    def test_invalid_or_empty_expected_data_is_refused_before_any_output(self):
        for want in (
            None,
            cases.expected()._replace(cases=()),
            cases.expected()._replace(inputs=()),
            cases.expected()._replace(epoch=True),
            cases.expected()._replace(run_id=""),
            cases.expected()._replace(run_id="unsafe/\nraw"),
        ):
            with (
                self.subTest(want=want),
                mock.patch.object(vm.job.OwnedOutput, "create") as create,
            ):
                with self.assertRaises(ValueError):
                    vm.run(b"{}", want, "/private/run", _model=self.model)
                create.assert_not_called()
                self.assertEqual(self.output.rows, {})
                self.assertEqual(self.model.calls, [])


class CommandTests(unittest.TestCase):
    def test_import_never_starts_build_process_or_output_transaction(self):
        spec = importlib.util.spec_from_file_location(
            "import_check", HERE / "measurement-job-vm.py"
        )
        module = importlib.util.module_from_spec(spec)
        with (
            mock.patch(
                "subprocess.Popen", side_effect=AssertionError("process at import")
            ),
            mock.patch.object(
                vm.os, "mkdir", side_effect=AssertionError("mkdir at import")
            ),
            mock.patch.object(
                vm.os, "open", side_effect=AssertionError("open at import")
            ),
        ):
            spec.loader.exec_module(module)
        self.assertEqual(module._OWNED, {})

    def test_fixed_argv_no_network_monitor_shares_or_device_passthrough(self):
        prepare, launch = vm.commands(cases.expected(), "/private/run")
        self.assertEqual(
            prepare,
            [
                "/private/qemu_img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "raw",
                "-b",
                "/private/base",
                "/private/run/overlay.qcow2",
            ],
        )
        self.assertIsInstance(launch, list)
        for option, value in [
            ("-accel", "kvm"),
            ("-nic", "none"),
            ("-monitor", "none"),
            ("-display", "none"),
            ("-smp", "2"),
            ("-m", "2048"),
        ]:
            self.assertEqual(launch[launch.index(option) + 1], value)
        self.assertNotIn("-virtfs", launch)
        self.assertNotIn("-chardev", launch)
        self.assertNotIn("-snapshot", launch)
        self.assertIn("-nodefaults", launch)
        blocks = [
            json.loads(launch[index + 1])
            for index, arg in enumerate(launch)
            if arg == "-blockdev"
        ]
        self.assertEqual(len(blocks), 2)
        self.assertTrue(blocks[1]["read-only"])
        self.assertEqual(blocks[1]["file"]["filename"], "/private/payload")

    def test_guest_entry_has_no_activation_switch_or_old_executor(self):
        source = (HERE / "measurement-job-guest.sh").read_text()
        self.assertIn("exit 77", source)
        self.assertIn("qualified M/E", source)
        for token in ["bwrap", "measurement_anchor", "eval ", "sudo ", "qemu"]:
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
