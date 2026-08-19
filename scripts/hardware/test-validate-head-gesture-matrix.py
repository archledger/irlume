#!/usr/bin/env python3
"""Offline fixture tests for the privacy-bounded head-gesture matrix tools."""

import copy
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
VALIDATOR = HERE / "validate-head-gesture-matrix.py"
RUNNER = HERE / "run-head-gesture-matrix.sh"
HOSTS = ("current", "archhost", "minihost", "thinkpad")
GESTURES = ("nod", "shake", "still", "look-around", "look-down-and-hold")
OID = "a" * 40
BINARY_SHA256 = "b" * 64


def camera_digest(host):
    return hashlib.sha256(host.encode()).hexdigest()


def evidence(frames=75):
    return {
        "frames": frames,
        "face_frames": frames,
        "pitch_range": 0.25 if frames else 0,
        "yaw_range": 18.0 if frames else 0,
        "pitch_crossings": 2 if frames else 0,
        "yaw_crossings": 0,
        "mean_step": 0.03 if frames else 0,
    }


def capability(host, present=True):
    return {
        "schema_version": 1,
        "record_type": "capability",
        "frozen_commit_oid": OID,
        "release_binary_sha256": BINARY_SHA256,
        "host_label": host,
        "camera_identity_digest": (camera_digest(host) if present else None),
        "service": "capability",
        "purpose": "capability",
        "requested_policy": "not-applicable",
        "resolved_policy": "not-applicable",
        "trial_id": None,
        "expected_gesture": "none",
        "typed_outcome": "capability-present" if present else "capability-not-present",
        "detector_evidence": evidence(0),
        "timestamp": "2026-08-19T12:00:00Z",
    }


def trial(host, gesture, attempt):
    outcomes = {"nod": "approved", "shake": "declined"}
    return {
        "schema_version": 1,
        "record_type": "trial",
        "frozen_commit_oid": OID,
        "release_binary_sha256": BINARY_SHA256,
        "host_label": host,
        "camera_identity_digest": camera_digest(host),
        "service": "gesturecap",
        "purpose": "detector",
        "requested_policy": "not-applicable",
        "resolved_policy": "not-applicable",
        "trial_id": f"{host}:{gesture}:{attempt}",
        "expected_gesture": gesture,
        "typed_outcome": outcomes.get(gesture, "no-gesture"),
        "detector_evidence": evidence(),
        "timestamp": f"2026-08-19T12:{attempt:02d}:00Z",
    }


def valid_records():
    records = []
    for host in HOSTS:
        records.append(capability(host))
        for gesture in GESTURES:
            records.extend(trial(host, gesture, attempt) for attempt in range(1, 6))
    return records


class ValidatorTests(unittest.TestCase):
    def run_raw(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "evidence.jsonl"
            path.write_text(raw, encoding="utf-8")
            return subprocess.run(
                ["python3", str(VALIDATOR), str(path)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def run_records(self, records):
        return self.run_raw("".join(json.dumps(record) + "\n" for record in records))

    def assert_rejected(self, mutate):
        records = valid_records()
        mutate(records)
        result = self.run_records(records)
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_complete_matrix_passes(self):
        result = self.run_records(valid_records())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_capability_not_present_is_not_a_pass_or_trial(self):
        records = valid_records()
        records = [record for record in records if record["host_label"] != "thinkpad"]
        records.append(capability("thinkpad", present=False))
        result = self.run_records(records)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("capability-not-present=1", result.stdout)

        records.append(trial("thinkpad", "nod", 1))
        self.assertNotEqual(self.run_records(records).returncode, 0)

    def test_exact_schema_types_and_json_are_enforced(self):
        self.assert_rejected(lambda records: records[1].pop("service"))
        self.assert_rejected(lambda records: records[1].__setitem__("extra", False))
        self.assert_rejected(lambda records: records[1].__setitem__("schema_version", True))
        self.assert_rejected(lambda records: records[1].__setitem__("trial_id", 7))
        encoded = json.dumps(valid_records()[0])
        duplicate = encoded.replace('"host_label": "current"', '"host_label": "archhost", "host_label": "current"')
        self.assertNotEqual(self.run_raw(duplicate + "\n").returncode, 0)
        self.assertNotEqual(self.run_raw('{"broken":\n').returncode, 0)
        self.assertNotEqual(self.run_raw(encoded.replace("0.25", "NaN") + "\n").returncode, 0)

    def test_identity_and_matrix_completeness_are_enforced(self):
        self.assert_rejected(lambda records: records.__setitem__(1, {**records[1], "frozen_commit_oid": "c" * 40}))
        self.assert_rejected(lambda records: records.__setitem__(1, {**records[1], "release_binary_sha256": "d" * 64}))
        self.assert_rejected(lambda records: records.__setitem__(1, {**records[1], "camera_identity_digest": "e" * 64}))
        self.assert_rejected(lambda records: records.pop(0))
        self.assert_rejected(lambda records: records.__setitem__(0, {**records[0], "host_label": "unknown-host"}))
        self.assert_rejected(lambda records: records.pop(5))
        self.assert_rejected(lambda records: records.append(copy.deepcopy(records[1])))

    def test_outcomes_and_detector_bounds_are_enforced(self):
        self.assert_rejected(lambda records: records[1].__setitem__("typed_outcome", "granted"))
        self.assert_rejected(lambda records: records[6].__setitem__("typed_outcome", "approved"))
        self.assert_rejected(lambda records: records[1]["detector_evidence"].__setitem__("pitch_range", float("inf")))
        self.assert_rejected(lambda records: records[1]["detector_evidence"].__setitem__("yaw_range", -1))
        self.assert_rejected(lambda records: records[1]["detector_evidence"].__setitem__("face_frames", 76))
        self.assert_rejected(lambda records: records[1].__setitem__("timestamp", "yesterday"))

    def test_privacy_sensitive_names_values_and_prose_are_rejected(self):
        sensitive = [
            ("raw_frame_path", "/tmp/frame.raw"),
            ("camera_path", "/dev/video2"),
            ("serial", "ABC123"),
            ("username", "person"),
            ("embedding", [0.1]),
            ("template", "bytes"),
            ("image", "pixels"),
        ]
        for key, value in sensitive:
            with self.subTest(key=key):
                self.assert_rejected(lambda records, key=key, value=value: records[1].__setitem__(key, value))
        self.assert_rejected(lambda records: records[1].__setitem__("service", "please run sudo now"))

    def test_file_line_and_record_count_are_bounded(self):
        self.assertNotEqual(self.run_raw(" " * 5000 + "\n").returncode, 0)
        too_many = [capability(host) for host in HOSTS]
        too_many.extend(copy.deepcopy(valid_records()[1]) for _ in range(600))
        for index, record in enumerate(too_many[4:]):
            record["trial_id"] = f"current:nod:{index}"
        self.assertNotEqual(self.run_records(too_many).returncode, 0)
        self.assertNotEqual(self.run_raw("x" * (2 * 1024 * 1024 + 1)).returncode, 0)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.binary = self.root / "irlume"
        self.binary.write_bytes(b"reviewed release binary\n")
        self.binary.chmod(0o755)
        self.oid = "c" * 40
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.log = self.root / "calls.log"
        self.log.write_text("", encoding="utf-8")
        self.output = self.root / "evidence.jsonl"
        self.policy_state = self.root / "policy.state"
        self.policy_state.write_text("required\n", encoding="utf-8")
        self.make_fake("git", """#!/bin/sh
case "$*" in
  *"rev-parse HEAD"*) printf '%s\\n' "$FAKE_OID" ;;
  *"status --porcelain"*) printf '%s' "${FAKE_DIRTY-}" ;;
  *) exit 2 ;;
esac
""")
        self.make_fake("status", """#!/bin/sh
printf '%s\\n' status >>"$FAKE_LOG"
printf '{"ok":true,"data":{"daemon":"running","camera":{"rgb":%s,"ir":true}}}\\n' "${FAKE_RGB-true}"
""")
        self.make_fake("doctor", """#!/bin/sh
printf '%s\\n' doctor >>"$FAKE_LOG"
printf '%s\\n' '{"ok":true,"data":{"checks":[{"id":"camera-nodes","state":"pass"},{"id":"models","state":"pass"},{"id":"stage-detection-model","state":"pass"},{"id":"stage-recognition-model","state":"pass"}]}}'
""")
        self.make_fake("attempt", """#!/bin/sh
printf 'attempt' >>"$FAKE_LOG"
printf ' %s' "$@" >>"$FAKE_LOG"
printf '\\n' >>"$FAKE_LOG"
[ "${FAKE_ATTEMPT_FAIL-0}" -eq 0 ] || exit "$FAKE_ATTEMPT_FAIL"
printf '%s\\n' '{"camera_identity_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","typed_outcome":"approved","detector_evidence":{"frames":75,"face_frames":75,"pitch_range":0.25,"yaw_range":18.0,"pitch_crossings":2,"yaw_crossings":0,"mean_step":0.03}}'
""")
        self.make_fake("policy", """#!/bin/sh
if [ "$3" = status ]; then
  printf 'get %s\\n' "$2" >>"$FAKE_LOG"
  cat "$FAKE_POLICY_STATE"
else
  printf 'set %s %s\\n' "$2" "$3" >>"$FAKE_LOG"
  [ "${FAKE_POLICY_IGNORE-0}" -eq 1 ] || printf '%s\\n' "$3" >"$FAKE_POLICY_STATE"
  [ "${FAKE_POLICY_SET_FAIL-}" != "$3" ] || exit 8
fi
""")

    def tearDown(self):
        self.temporary.cleanup()

    def make_fake(self, name, source):
        path = self.root / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    def run_runner(self, trial="gesturecap:nod:not-applicable", stdin="ready\n", extra_env=None, extra_args=None):
        env = os.environ.copy()
        env.update({
            "PATH": f"{self.root}:{env['PATH']}",
            "FAKE_LOG": str(self.log),
            "FAKE_OID": self.oid,
            "FAKE_POLICY_STATE": str(self.policy_state),
            "TMPDIR": str(self.root),
            "IRLUME_HEAD_GESTURE_ROOT": str(self.root),
            "IRLUME_HEAD_GESTURE_BINARY": str(self.binary),
            "IRLUME_HEAD_GESTURE_STATUS_CMD": str(self.root / "status"),
            "IRLUME_HEAD_GESTURE_DOCTOR_CMD": str(self.root / "doctor"),
            "IRLUME_HEAD_GESTURE_ATTEMPT_CMD": str(self.root / "attempt"),
            "IRLUME_HEAD_GESTURE_POLICY_CMD": str(self.root / "policy"),
        })
        if extra_env:
            env.update(extra_env)
        args = [
            "bash", str(RUNNER),
            "--host-label", "current",
            "--expected-oid", self.oid,
            "--expected-binary-sha256", self.digest,
            "--output", str(self.output),
            "--trial", trial,
        ]
        if extra_args:
            args.extend(extra_args)
        return subprocess.run(args, input=stdin, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)

    def test_runner_waits_for_literal_ready_then_publishes_0600(self):
        refused = self.run_runner(stdin="Ready\n")
        self.assertNotEqual(refused.returncode, 0)
        self.assertNotIn("attempt", self.log.read_text(encoding="utf-8"))
        self.assertFalse(self.output.exists())

        self.log.write_text("", encoding="utf-8")
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("status\ndoctor\nattempt --service gesturecap", self.log.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        records = [json.loads(line) for line in self.output.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([record["record_type"] for record in records], ["capability", "trial"])
        self.assertNotIn("/dev/video", self.output.read_text(encoding="utf-8"))
        self.assertEqual(list(self.root.glob("irlume-head-gesture.*")), [])

    def test_runner_refuses_unknown_arguments_identity_and_dirty_checkout(self):
        self.assertNotEqual(self.run_runner(trial="unknown:nod:required").returncode, 0)
        self.assertNotEqual(self.run_runner(extra_args=["--mystery"]).returncode, 0)
        self.assertNotEqual(self.run_runner(extra_env={"FAKE_OID": "e" * 40}).returncode, 0)
        self.assertNotEqual(self.run_runner(extra_env={"FAKE_DIRTY": " M file\n"}).returncode, 0)
        self.assertNotEqual(self.run_runner(extra_env={"IRLUME_HEAD_GESTURE_BINARY": str(self.root / "attempt")}).returncode, 0)

    def test_runner_records_capability_not_present_without_attempt(self):
        result = self.run_runner(extra_env={"FAKE_RGB": "false"}, stdin="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("attempt", self.log.read_text(encoding="utf-8"))
        records = [json.loads(line) for line in self.output.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["typed_outcome"], "capability-not-present")

    def test_runner_restores_temporary_policy_when_attempt_fails(self):
        result = self.run_runner(trial="sudo:nod:off", extra_env={"FAKE_ATTEMPT_FAIL": "9"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.log.read_text(encoding="utf-8").splitlines(), [
            "status",
            "doctor",
            "get sudo",
            "set sudo off",
            "get sudo",
            "attempt --service sudo --purpose authentication --expected-gesture nod --timeout-seconds 20",
            "set sudo required",
        ])
        self.assertFalse(self.output.exists())

    def test_runner_refuses_to_record_an_unresolved_policy_write(self):
        result = self.run_runner(trial="sudo:nod:off", extra_env={"FAKE_POLICY_IGNORE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.log.read_text(encoding="utf-8").splitlines(), [
            "status",
            "doctor",
            "get sudo",
            "set sudo off",
            "get sudo",
            "set sudo required",
        ])
        self.assertFalse(self.output.exists())

    def test_runner_attempts_restore_when_policy_set_reports_failure(self):
        result = self.run_runner(trial="sudo:nod:off", extra_env={"FAKE_POLICY_SET_FAIL": "off"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.log.read_text(encoding="utf-8").splitlines(), [
            "status",
            "doctor",
            "get sudo",
            "set sudo off",
            "set sudo required",
        ])
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
