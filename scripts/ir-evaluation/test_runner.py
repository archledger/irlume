"""Real ledger and trace supervision; host/camera boundaries are substituted."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import runner
from test_host import config


def result(category="candidate_match"):
    return {
        "returncode": 0,
        "output_valid": True,
        "readers_completed": True,
        "watchdog_fired": False,
        "early_tracer_exit": False,
        "trace_error": False,
        "trace_overflow": False,
        "output_overflow": False,
        "cancellation_sent": False,
        "report": {
            "schema": 1,
            "operation": "ir_only_evaluation",
            "authentication_granted": False,
            "category": category,
            "elapsed_ms": 23,
            "capture_ms": 10,
            "detection_ms": 3,
            "pad_ms": 5,
            "identity_ms": 5,
        },
        "video_events": [
            {
                "device": "/dev/video10",
                "operation": "open",
                "result": 7,
                "fd": 7,
                "timestamp": 1.0,
            },
            {
                "device": "/dev/video10",
                "operation": "close",
                "result": 0,
                "fd": 7,
                "timestamp": 1.2,
            },
        ],
        "wall_elapsed_ms": 45,
    }


class RunnerTests(unittest.TestCase):
    def execute(self, mode="genuine", outcomes=None, snapshots=None, ready=True):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        folder = Path(self.tmp.name)
        preflight = result("ready")
        preflight["video_events"] = []
        with (
            contextlib.redirect_stdout(io.StringIO()),
            patch(
                "runner.pwd.getpwuid", return_value=SimpleNamespace(pw_name="fixture")
            ),
            patch("runner.host.snapshot", side_effect=snapshots or [{"x": 1}] * 5),
            patch(
                "runner.harness.run_traced",
                side_effect=outcomes or [preflight, result()],
            ),
            patch("runner.attend", return_value=ready),
        ):
            runner.execute(config(), folder, "a01", mode, "pilot", "/fixed/binary")
        return json.loads((folder / "a01/final.json").read_text())

    def test_attack_candidate_stops_and_preserves_categorical_evidence(self):
        got = self.execute(mode="attack")
        self.assertEqual(got["status"], "stopped")
        self.assertTrue(got["stop_required"])
        self.assertEqual(got["evaluation"]["report"]["category"], "candidate_match")

    def test_no_face_remains_no_face_not_pad_success(self):
        preflight = result("ready")
        preflight["video_events"] = []
        got = self.execute(mode="attack", outcomes=[preflight, result("no_face")])
        self.assertEqual(got["status"], "complete")
        self.assertEqual(got["evaluation"]["report"]["category"], "no_face")

    def test_private_exception_is_reduced_to_failure_and_ledger_retained(self):
        got = self.execute(outcomes=[RuntimeError("/private/name score=0.79")])
        self.assertEqual(got["failure"], "execution_failed")
        self.assertTrue(got["stop_required"])
        self.assertNotIn("private", json.dumps(got))

    def test_keyboard_interrupt_records_attempt_and_checks_preservation(self):
        got = self.execute(outcomes=[KeyboardInterrupt()])
        self.assertEqual(got["failure"], "interrupted")
        self.assertTrue(got["preservation_verified"])
        self.assertTrue(got["stop_required"])

    def test_unready_terminal_never_reaches_evaluation(self):
        got = self.execute(ready=False)
        self.assertIsNone(got["evaluation"])
        self.assertEqual(got["failure"], "readiness_declined")

    def test_changed_protected_state_cannot_pass(self):
        got = self.execute(snapshots=[{"x": 1}, {"x": 1}, {"x": 1}, {"x": 1}, {"x": 2}])
        self.assertEqual(got["status"], "stopped")
        self.assertFalse(got["preservation_verified"])

    def test_only_expected_device_opens_allowed(self):
        preflight = result("ready")
        preflight["video_events"] = []
        bad = result()
        bad["video_events"][0]["device"] = "/dev/video8"
        got = self.execute(outcomes=[preflight, bad])
        self.assertTrue(got["stop_required"])

    def test_operator_cue_requires_a_terminal_and_explicit_readiness(self):
        stream = io.StringIO("READY\n")
        with (
            patch("sys.stdin", stream),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertFalse(runner.attend("genuine"))
        self.assertNotIn("START", output.getvalue())


if __name__ == "__main__":
    unittest.main()
