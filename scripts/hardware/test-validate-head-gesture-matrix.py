#!/usr/bin/env python3
"""Offline fixture tests for the privacy-bounded head-gesture matrix tools."""

import copy
import calendar
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
VALIDATOR = HERE / "validate-head-gesture-matrix.py"
RUNNER = HERE / "run-head-gesture-matrix.sh"
HOSTS = ("current", "archhost", "minihost", "thinkpad")
GESTURES = ("nod", "shake", "still", "look-around", "look-down-and-hold")
OID = "a" * 40
BINARY_SHA256 = "b" * 64
ADAPTER_SHA256 = "c" * 64


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
        "attempt_adapter_sha256": ADAPTER_SHA256 if present else None,
        "host_label": host,
        "camera_identity_digest": (camera_digest(host) if present else None),
        "service": "capability",
        "purpose": "capability",
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
        "attempt_adapter_sha256": ADAPTER_SHA256,
        "host_label": host,
        "camera_identity_digest": camera_digest(host),
        "service": "gesturecap",
        "purpose": "detector",
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
    def run_raw(self, raw, *extra):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "evidence.jsonl"
            path.write_text(raw, encoding="utf-8")
            return subprocess.run(
                ["python3", str(VALIDATOR), *extra, str(path)],
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
        self.assertEqual(json.loads(result.stdout)["qualified"], True)

    def test_capability_not_present_is_not_a_pass_or_trial(self):
        records = valid_records()
        records = [record for record in records if record["host_label"] != "thinkpad"]
        records.append(capability("thinkpad", present=False))
        result = self.run_records(records)
        self.assertEqual(result.returncode, 3, result.stderr)
        verdict = json.loads(result.stdout)
        self.assertEqual(verdict["schema_valid"], True)
        self.assertEqual(verdict["qualified"], False)
        self.assertEqual(self.run_raw("".join(json.dumps(record) + "\n" for record in records), "--schema-only").returncode, 0)

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
        records = valid_records()
        records[1]["camera_identity_digest"] = "e" * 64
        raw = "".join(json.dumps(record) + "\n" for record in records)
        self.assertNotEqual(self.run_raw(raw, "--schema-only").returncode, 0)

    def test_outcomes_and_detector_bounds_are_enforced(self):
        self.assert_rejected(lambda records: records[1].__setitem__("typed_outcome", "granted"))
        self.assert_rejected(lambda records: records[1]["detector_evidence"].__setitem__("pitch_range", float("inf")))
        self.assert_rejected(lambda records: records[1]["detector_evidence"].__setitem__("yaw_range", -1))
        self.assert_rejected(lambda records: records[1]["detector_evidence"].__setitem__("face_frames", 76))
        self.assert_rejected(lambda records: records[1].__setitem__("timestamp", "yesterday"))

    def test_misclassification_and_attempt_failure_are_schema_valid_but_unqualified(self):
        for outcome in ["approved", "attempt-failed", "attempt-timeout"]:
            records = valid_records()
            records[6]["typed_outcome"] = outcome
            raw = "".join(json.dumps(record) + "\n" for record in records)
            with self.subTest(outcome=outcome):
                self.assertEqual(self.run_raw(raw, "--schema-only").returncode, 0)
                result = self.run_raw(raw)
                self.assertEqual(result.returncode, 3)
                self.assertEqual(json.loads(result.stdout)["qualified"], False)

    def test_exact_service_purpose_policy_gesture_cells_are_enforced(self):
        allowed = [
            ("sudo", "authentication", "required", "shake", "declined"),
            ("sudo", "authentication", "off", "none", "no-gesture"),
            ("kde", "authentication", "off", "none", "no-gesture"),
            ("kde", "authentication", "required", "nod", "approved"),
            ("credential_release", "credential-release", "off", "none", "no-gesture"),
            ("credential_release", "credential-release", "required", "nod", "approved"),
        ]
        records = valid_records()
        for index, (service, purpose, policy, gesture, outcome) in enumerate(allowed):
            policy_record = copy.deepcopy(records[1])
            policy_record.update({
                "service": service,
                "purpose": purpose,
                "resolved_policy": policy,
                "expected_gesture": gesture,
                "typed_outcome": outcome,
                "trial_id": f"current:policy:{index}",
            })
            records.append(policy_record)
        self.assertEqual(self.run_records(records).returncode, 0)
        for key, value in [
            ("purpose", "detector"),
            ("resolved_policy", "not-applicable"),
            ("expected_gesture", "look-around"),
        ]:
            broken = copy.deepcopy(records)
            broken[-1][key] = value
            with self.subTest(key=key):
                self.assertNotEqual(self.run_records(broken).returncode, 0)

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
    CAMERA_DIGEST = "d" * 64

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir(mode=0o700)
        self.log = self.root / "calls.log"
        self.log.write_text("", encoding="utf-8")
        self.attempt_args = self.root / "attempt.args"
        self.evidence_root = self.root / "external-evidence"
        self.evidence_root.mkdir(mode=0o700)
        self.oid = "c" * 40
        self.make_fake("git", """#!/bin/sh
case "$*" in
  *"rev-parse HEAD"*) printf '%s\\n' "$FAKE_OID" ;;
  *"status --porcelain"*) printf '%s' "${FAKE_DIRTY-}" ;;
  *) exit 2 ;;
esac
""")
        self.status = self.make_fake("status", """#!/bin/sh
printf '%s\\n' status >>"$FAKE_LOG"
case "${FAKE_STATUS_MODE-good}" in
  good) printf '%s\\n' '{"ok":true,"data":{"daemon":"running","camera":{"rgb":true,"ir":true}}}' ;;
  absent) printf '%s\\n' '{"ok":true,"data":{"daemon":"running","camera":{"rgb":false,"ir":false}}}' ;;
  starting) printf '%s\\n' '{"ok":true,"data":{"daemon":"starting","camera":{"rgb":true,"ir":true}}}' ;;
  malformed) printf '%s\\n' '{broken' ;;
esac
""")
        self.doctor = self.make_fake("doctor", """#!/bin/sh
printf '%s\\n' doctor >>"$FAKE_LOG"
case "${FAKE_DOCTOR_MODE-good}" in
  good) printf '%s\\n' '{"ok":true,"data":{"checks":[{"id":"camera-nodes","state":"pass"},{"id":"models","state":"pass"},{"id":"stage-detection-model","state":"pass"},{"id":"stage-recognition-model","state":"pass"}]}}' ;;
  unknown) printf '%s\\n' '{"ok":true,"data":{"checks":[{"id":"camera-nodes","state":"unknown"}]}}' ;;
  failed) printf '%s\\n' '{"ok":false,"error":{"code":"operation-failed"}}' ;;
esac
""")
        self.binary = self.make_fake("repo/irlume", """#!/bin/sh
case "$1" in
  status)
    printf '%s\\n' candidate-status >>"$FAKE_LOG"
    printf '%s\\n' '{"ok":true,"data":{"daemon":"running","camera":{"rgb":true,"ir":true}}}'
    ;;
  doctor)
    printf '%s\\n' candidate-doctor >>"$FAKE_LOG"
    printf '%s\\n' '{"ok":true,"data":{"checks":[{"id":"camera-nodes","state":"pass"},{"id":"models","state":"pass"},{"id":"stage-detection-model","state":"pass"},{"id":"stage-recognition-model","state":"pass"}]}}'
    ;;
  credential-release-challenge)
    [ "$3" = status ] || exit 99
    printf 'policy-observe %s\\n' "$2" >>"$FAKE_LOG"
    case "$2" in
      kde|gdm-password|sddm|plasmalogin) printf '[credential-release-challenge] %s: off (default)\\n' "$2" ;;
      credential_release) printf '[credential-release-challenge] %s: %s (explicit)\\n' "$2" "${FAKE_CREDENTIAL_POLICY-REQUIRED}" ;;
      *) printf '[credential-release-challenge] %s: REQUIRED (default)\\n' "$2" ;;
    esac
    ;;
  *) exit 2 ;;
esac
""")
        self.adapter = self.make_fake("attempt-adapter", """#!/bin/sh
if [ "$1" = --preflight ]; then
  printf '%s\\n' preflight >>"$FAKE_LOG"
  printf '{"camera_identity_digest":"%s"}\\n' "${FAKE_CAMERA_DIGEST}"
  if [ -n "${FAKE_ADAPTER_REPLACEMENT-}" ]; then
    mv "$FAKE_ADAPTER_REPLACEMENT" "$FAKE_ADAPTER_PATH"
  fi
  exit 0
fi
printf '%s\\n' attempt >>"$FAKE_LOG"
printf '%s\\n' "$@" >"$FAKE_ATTEMPT_ARGS"
expected=
while [ "$#" -gt 0 ]; do
  if [ "$1" = --expected-gesture ]; then expected=$2; shift 2; else shift; fi
done
zero='{"frames":0,"face_frames":0,"pitch_range":0,"yaw_range":0,"pitch_crossings":0,"yaw_crossings":0,"mean_step":0}'
normal='{"frames":75,"face_frames":75,"pitch_range":0.25,"yaw_range":18.0,"pitch_crossings":2,"yaw_crossings":0,"mean_step":0.03}'
case "${FAKE_ADAPTER_MODE-good}" in
  good)
    case "$expected" in nod) outcome=approved ;; shake) outcome=declined ;; *) outcome=no-gesture ;; esac
    printf '{"typed_outcome":"%s","detector_evidence":%s}\\n' "$outcome" "$normal"
    ;;
  misclassified) printf '{"typed_outcome":"approved","detector_evidence":%s}\\n' "$normal" ;;
  fail-json) printf '{"typed_outcome":"attempt-failed","detector_evidence":%s}\\n' "$zero"; exit 9 ;;
  invalid) printf 'arbitrary prose\\n'; exit 7 ;;
  unknown-outcome) printf '{"typed_outcome":"surprise","detector_evidence":%s}\\n' "$normal" ;;
  bad-evidence) printf '%s\\n' '{"typed_outcome":"approved","detector_evidence":{"frames":999,"face_frames":999,"pitch_range":0,"yaw_range":0,"pitch_crossings":0,"yaw_crossings":0,"mean_step":0}}' ;;
  success-hang) printf '{"typed_outcome":"approved","detector_evidence":%s}\\n' "$normal"; sleep 60 & child=$!; printf '%s\\n' "$child" >"$FAKE_CONTAINED_PID"; wait "$child" ;;
  success-nonzero) printf '{"typed_outcome":"approved","detector_evidence":%s}\\n' "$normal"; exit 9 ;;
  escape)
    setsid sh -c 'setsid sh -c '\''sleep 60 & child=$!; printf "%s\\n" "$child" >"$FAKE_ESCAPE_PID"; wait "$child"'\'' &' &
    deadline=50
    while [ ! -s "$FAKE_ESCAPE_PID" ] && [ "$deadline" -gt 0 ]; do sleep 0.02; deadline=$((deadline - 1)); done
    printf '{"typed_outcome":"approved","detector_evidence":%s}\\n' "$normal"
    ;;
  oversize) head -c 5000 /dev/zero ;;
  oversize-stderr) head -c 5000 /dev/zero >&2 ;;
  hang-child) sleep 60 & child=$!; printf '%s\\n' "$child" >"$FAKE_CHILD_PID"; wait "$child" ;;
esac
""")
        self.containment = self.make_fake("containment", """#!/bin/sh
operation=$1
shift
case "$operation" in
  check)
    printf '%s\\n' containment-check >>"$FAKE_LOG"
    [ "${FAKE_CONTAINMENT_CHECK_FAIL-0}" -eq 0 ]
    ;;
  run)
    unit=$1
    shift
    printf 'containment-run %s\\n' "$unit" >>"$FAKE_LOG"
    exec "$@"
    ;;
  term|kill)
    unit=$1
    printf 'containment-%s %s\\n' "$operation" "$unit" >>"$FAKE_LOG"
    signal=TERM
    [ "$operation" = kill ] && signal=KILL
    for pid_file in "${FAKE_ESCAPE_PID-}" "${FAKE_CHILD_PID-}" "${FAKE_CONTAINED_PID-}"; do
      if [ -n "$pid_file" ] && [ -s "$pid_file" ]; then
        kill -"$signal" "$(cat "$pid_file")" 2>/dev/null || true
      fi
    done
    ;;
  verify-empty)
    unit=$1
    printf 'containment-verify %s\\n' "$unit" >>"$FAKE_LOG"
    for pid_file in "${FAKE_ESCAPE_PID-}" "${FAKE_CHILD_PID-}" "${FAKE_CONTAINED_PID-}"; do
      if [ -n "$pid_file" ] && [ -s "$pid_file" ]; then
        pid=$(cat "$pid_file")
        tries=100
        while kill -0 "$pid" 2>/dev/null && [ "$tries" -gt 0 ]; do sleep 0.02; tries=$((tries - 1)); done
        ! kill -0 "$pid" 2>/dev/null || exit 1
      fi
    done
    ;;
esac
""")
        self.binary_digest = self.sha256(self.binary)
        self.adapter_digest = self.sha256(self.adapter)

    def tearDown(self):
        self.temporary.cleanup()

    def make_fake(self, name, source):
        path = self.root / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)
        return path

    @staticmethod
    def sha256(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def invocation(
        self,
        trial="gesturecap:nod",
        evidence_root=None,
        extra_env=None,
        extra_args=None,
        test_mode=True,
        expected_binary_sha256=None,
        expected_adapter_sha256=None,
    ):
        env = os.environ.copy()
        env.update({
            "PATH": f"{self.root}:{env['PATH']}",
            "FAKE_LOG": str(self.log),
            "FAKE_OID": self.oid,
            "FAKE_CAMERA_DIGEST": self.CAMERA_DIGEST,
            "FAKE_ATTEMPT_ARGS": str(self.attempt_args),
            "FAKE_ADAPTER_PATH": str(self.adapter),
            "FAKE_CONTAINED_PID": str(self.root / "contained.pid"),
            "TMPDIR": str(self.root),
            "IRLUME_HEAD_GESTURE_ROOT": str(self.repo),
            "IRLUME_HEAD_GESTURE_BINARY": str(self.binary),
            "IRLUME_HEAD_GESTURE_ATTEMPT_CMD": str(self.adapter),
        })
        if test_mode:
            env.update({
                "IRLUME_HEAD_GESTURE_TEST_MODE": "1",
                "IRLUME_HEAD_GESTURE_STATUS_CMD": str(self.status),
                "IRLUME_HEAD_GESTURE_DOCTOR_CMD": str(self.doctor),
                "IRLUME_HEAD_GESTURE_CONTAINMENT_CMD": str(self.containment),
            })
        if extra_env:
            for key, value in extra_env.items():
                if value is None:
                    env.pop(key, None)
                else:
                    env[key] = value
        args = [
            "bash", str(RUNNER),
            "--host-label", "current",
            "--expected-oid", self.oid,
            "--expected-binary-sha256", expected_binary_sha256 or self.binary_digest,
            "--expected-adapter-sha256", expected_adapter_sha256 or self.adapter_digest,
            "--expected-camera-identity-digest", self.CAMERA_DIGEST,
            "--evidence-root", str(evidence_root or self.evidence_root),
            "--trial", trial,
        ]
        if extra_args:
            args.extend(extra_args)
        return args, env

    def run_runner(self, **kwargs):
        stdin = kwargs.pop("stdin", "ready\n")
        args, env = self.invocation(**kwargs)
        return subprocess.run(args, input=stdin, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)

    def records(self, root=None):
        return [json.loads(path.read_text(encoding="utf-8")) for path in sorted((root or self.evidence_root).glob("*.json"))]

    def test_preflight_precedes_literal_ready_and_attempt_timestamp_follows_it(self):
        refused = self.run_runner(stdin="Ready\n")
        self.assertNotEqual(refused.returncode, 0)
        refused_calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertLess(refused_calls.index("containment-check"), refused_calls.index("status"))
        self.assertLess(refused_calls.index("status"), refused_calls.index("doctor"))
        self.assertLess(refused_calls.index("doctor"), refused_calls.index("preflight"))
        self.assertNotIn("attempt", refused_calls)
        self.assertEqual(self.records(), [])

        self.log.write_text("", encoding="utf-8")
        args, env = self.invocation()
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        time.sleep(1.1)
        ready_at = time.time()
        stdout, stderr = process.communicate("ready\n", timeout=10)
        self.assertEqual(process.returncode, 0, stderr)
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertLess(calls.index("status"), calls.index("doctor"))
        self.assertLess(calls.index("doctor"), calls.index("preflight"))
        self.assertLess(calls.index("preflight"), calls.index("attempt"))
        captured_args = self.attempt_args.read_text(encoding="utf-8").splitlines()
        self.assertIn("--expected-camera-identity-digest", captured_args)
        self.assertIn(self.CAMERA_DIGEST, captured_args)
        trial_record = next(record for record in self.records() if record["record_type"] == "trial")
        observed = calendar.timegm(time.strptime(trial_record["timestamp"], "%Y-%m-%dT%H:%M:%SZ"))
        self.assertGreaterEqual(observed, ready_at - 1)
        self.assertNotIn("/dev/video", "".join(path.read_text(encoding="utf-8") for path in self.evidence_root.glob("*.json")))

    def test_repeated_unknown_and_unfrozen_inputs_are_refused_before_preflight(self):
        cases = [
            {"trial": "unknown:nod"},
            {"extra_args": ["--trial", "gesturecap:nod"]},
            {"extra_args": ["--mystery", "x"]},
            {"extra_env": {"FAKE_OID": "e" * 40}},
            {"extra_env": {"FAKE_DIRTY": " M file\n"}},
            {"extra_args": ["--expected-adapter-sha256", "e" * 64]},
            {"expected_binary_sha256": "e" * 64},
            {"expected_adapter_sha256": "e" * 64},
        ]
        for kwargs in cases:
            self.log.write_text("", encoding="utf-8")
            with self.subTest(kwargs=kwargs):
                self.assertNotEqual(self.run_runner(**kwargs).returncode, 0)
                self.assertNotIn("preflight", self.log.read_text(encoding="utf-8"))
        link = self.root / "adapter-link"
        link.symlink_to(self.adapter)
        self.assertNotEqual(self.run_runner(extra_env={"IRLUME_HEAD_GESTURE_ATTEMPT_CMD": str(link)}).returncode, 0)

    def test_status_doctor_test_gate_and_camera_preflight_fail_closed(self):
        for variable, value in [
            ("FAKE_STATUS_MODE", "starting"),
            ("FAKE_STATUS_MODE", "malformed"),
            ("FAKE_DOCTOR_MODE", "unknown"),
            ("FAKE_DOCTOR_MODE", "failed"),
        ]:
            self.log.write_text("", encoding="utf-8")
            with self.subTest(variable=variable, value=value):
                self.assertNotEqual(self.run_runner(extra_env={variable: value}).returncode, 0)
                self.assertNotIn("attempt", self.log.read_text(encoding="utf-8"))
        self.assertNotEqual(self.run_runner(extra_env={"FAKE_CAMERA_DIGEST": "e" * 64}).returncode, 0)

        production = self.run_runner(test_mode=False, extra_env={
            "IRLUME_HEAD_GESTURE_STATUS_CMD": str(self.status),
            "IRLUME_HEAD_GESTURE_DOCTOR_CMD": str(self.doctor),
        })
        self.assertNotEqual(production.returncode, 0)
        self.log.write_text("", encoding="utf-8")
        candidate = self.run_runner(extra_env={
            "IRLUME_HEAD_GESTURE_STATUS_CMD": None,
            "IRLUME_HEAD_GESTURE_DOCTOR_CMD": None,
        })
        self.assertEqual(candidate.returncode, 0, candidate.stderr)
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertLess(calls.index("candidate-status"), calls.index("candidate-doctor"))
        self.assertLess(calls.index("candidate-doctor"), calls.index("preflight"))
        self.assertLess(calls.index("preflight"), calls.index("attempt"))

    def test_verified_adapter_inode_is_bound_across_preflight_and_attempt(self):
        replacement = self.make_fake("replacement-adapter", """#!/bin/sh
printf '%s\\n' replaced-adapter >>"$FAKE_LOG"
exit 99
""")
        result = self.run_runner(extra_env={"FAKE_ADAPTER_REPLACEMENT": str(replacement)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("attempt", self.log.read_text(encoding="utf-8").splitlines())
        self.assertNotIn("replaced-adapter", self.log.read_text(encoding="utf-8").splitlines())

    def test_policy_is_observed_only_through_verified_candidate(self):
        result = self.run_runner(trial="sudo:shake")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.log.read_text(encoding="utf-8")
        self.assertIn("policy-observe sudo", calls)
        trial_record = next(record for record in self.records() if record["record_type"] == "trial")
        self.assertEqual((trial_record["purpose"], trial_record["resolved_policy"]), ("authentication", "required"))

    def test_observed_misclassification_and_attempt_failures_are_persisted(self):
        result = self.run_runner(trial="gesturecap:shake", extra_env={"FAKE_ADAPTER_MODE": "misclassified"})
        self.assertEqual(result.returncode, 0, result.stderr)
        trial_record = next(record for record in self.records() if record["record_type"] == "trial")
        self.assertEqual(trial_record["typed_outcome"], "approved")
        qualified = subprocess.run(["python3", str(VALIDATOR), str(self.evidence_root)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(qualified.returncode, 3)

        second_root = self.root / "second-evidence"
        second_root.mkdir(mode=0o700)
        result = self.run_runner(evidence_root=second_root, extra_env={"FAKE_ADAPTER_MODE": "fail-json"})
        self.assertNotEqual(result.returncode, 0)
        trial_record = next(record for record in self.records(second_root) if record["record_type"] == "trial")
        self.assertEqual(trial_record["typed_outcome"], "attempt-failed")

    def test_timeout_and_nonzero_override_success_shaped_adapter_json(self):
        cases = [("success-hang", "attempt-timeout"), ("success-nonzero", "attempt-failed")]
        for mode, expected_outcome in cases:
            root = self.root / f"status-authority-{mode}"
            root.mkdir(mode=0o700)
            env = {"FAKE_ADAPTER_MODE": mode}
            if mode == "success-hang":
                env["IRLUME_HEAD_GESTURE_TEST_TIMEOUT_SECONDS"] = "1"
            result = self.run_runner(evidence_root=root, extra_env=env)
            with self.subTest(mode=mode):
                self.assertNotEqual(result.returncode, 0)
                trial_record = next(record for record in self.records(root) if record["record_type"] == "trial")
                self.assertEqual(trial_record["typed_outcome"], expected_outcome)

    def test_containment_authority_is_required_and_kills_setsid_double_fork(self):
        refused = self.run_runner(extra_env={"FAKE_CONTAINMENT_CHECK_FAIL": "1"})
        self.assertNotEqual(refused.returncode, 0)
        self.assertNotIn("preflight", self.log.read_text(encoding="utf-8"))

        self.log.write_text("", encoding="utf-8")
        escaped_pid = self.root / "escaped.pid"
        result = self.run_runner(extra_env={"FAKE_ADAPTER_MODE": "escape", "FAKE_ESCAPE_PID": str(escaped_pid)})
        child = int(escaped_pid.read_text(encoding="utf-8"))
        try:
            self.assertEqual(result.returncode, 0, result.stderr)
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
            calls = self.log.read_text(encoding="utf-8")
            self.assertIn("containment-kill", calls)
            self.assertIn("containment-verify", calls)
        finally:
            try:
                os.kill(child, 9)
            except ProcessLookupError:
                pass

    def test_timeout_oversize_and_invalid_adapter_output_are_bounded_and_persisted(self):
        child_pid = self.root / "child.pid"
        result = self.run_runner(extra_env={
            "FAKE_ADAPTER_MODE": "hang-child",
            "FAKE_CHILD_PID": str(child_pid),
            "IRLUME_HEAD_GESTURE_TEST_TIMEOUT_SECONDS": "1",
        })
        self.assertNotEqual(result.returncode, 0)
        trial_record = next(record for record in self.records() if record["record_type"] == "trial")
        self.assertEqual(trial_record["typed_outcome"], "attempt-timeout")
        child = int(child_pid.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)

        for mode in ["oversize", "oversize-stderr", "invalid", "unknown-outcome", "bad-evidence"]:
            root = self.root / f"evidence-{mode}"
            root.mkdir(mode=0o700)
            result = self.run_runner(evidence_root=root, extra_env={"FAKE_ADAPTER_MODE": mode})
            self.assertNotEqual(result.returncode, 0)
            trial_record = next(record for record in self.records(root) if record["record_type"] == "trial")
            self.assertEqual(trial_record["typed_outcome"], "attempt-failed")
            self.assertEqual(list(self.root.glob("irlume-head-gesture.*")), [])

    def test_capability_absence_is_published_but_never_qualified(self):
        result = self.run_runner(stdin="", extra_env={"FAKE_STATUS_MODE": "absent"})
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertNotIn("preflight", self.log.read_text(encoding="utf-8"))
        self.assertEqual([record["typed_outcome"] for record in self.records()], ["capability-not-present"])
        schema = subprocess.run(
            ["python3", str(VALIDATOR), "--schema-only", str(self.evidence_root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        qualified = subprocess.run(
            ["python3", str(VALIDATOR), str(self.evidence_root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(schema.returncode, 0)
        self.assertEqual(qualified.returncode, 3)

    def test_publication_rejects_unsafe_roots_existing_targets_and_precommit_failure(self):
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o755)
        self.assertNotEqual(self.run_runner(evidence_root=unsafe).returncode, 0)
        real = self.root / "real-evidence"
        real.mkdir(mode=0o700)
        link = self.root / "evidence-link"
        link.symlink_to(real, target_is_directory=True)
        self.assertNotEqual(self.run_runner(evidence_root=link).returncode, 0)
        inside = self.repo / "evidence"
        inside.mkdir(mode=0o700)
        self.assertNotEqual(self.run_runner(evidence_root=inside).returncode, 0)
        self.assertFalse((inside / ".head-gesture.lock").exists())

        (self.evidence_root / "trial-deadbeef.json").write_text("occupied", encoding="utf-8")
        self.assertNotEqual(self.run_runner(extra_env={"IRLUME_HEAD_GESTURE_TEST_TOKEN": "deadbeef"}).returncode, 0)
        (self.evidence_root / "trial-deadbeef.json").unlink()
        (self.evidence_root / "trial-deadbeef.json").symlink_to(self.root / "outside")
        self.assertNotEqual(self.run_runner(extra_env={"IRLUME_HEAD_GESTURE_TEST_TOKEN": "deadbeef"}).returncode, 0)
        (self.evidence_root / "trial-deadbeef.json").unlink()
        result = self.run_runner(extra_env={"IRLUME_HEAD_GESTURE_TEST_FAIL_BEFORE_PUBLISH": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.records(), [])

    def test_directory_symlink_swap_before_commit_is_rejected(self):
        pause = self.root / "publish-pause"
        args, env = self.invocation(extra_env={"IRLUME_HEAD_GESTURE_TEST_PAUSE_BEFORE_PUBLISH": str(pause)})
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        process.stdin.write("ready\n")
        process.stdin.flush()
        deadline = time.monotonic() + 5
        while not pause.with_suffix(".ready").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(pause.with_suffix(".ready").exists(), "publisher did not reach the commit boundary")
        moved = self.root / "moved-evidence"
        self.evidence_root.rename(moved)
        replacement = self.root / "replacement-evidence"
        replacement.mkdir(mode=0o700)
        self.evidence_root.symlink_to(replacement, target_is_directory=True)
        pause.with_suffix(".continue").write_text("go", encoding="utf-8")
        _, stderr = process.communicate(timeout=10)
        self.assertNotEqual(process.returncode, 0, stderr)
        self.assertEqual(list(moved.glob("*.json")), [])
        self.assertEqual(list(replacement.glob("*.json")), [])

    def test_ancestor_swap_between_component_binding_steps_is_rejected(self):
        container = self.root / "evidence-container"
        container.mkdir(mode=0o700)
        authorized = container / "authorized"
        authorized.mkdir(mode=0o700)
        pause = self.root / "open-pause"
        args, env = self.invocation(
            evidence_root=authorized,
            extra_env={"IRLUME_HEAD_GESTURE_TEST_PAUSE_BEFORE_DIRECTORY_OPEN": str(pause)},
        )
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        deadline = time.monotonic() + 3
        while not pause.with_suffix(".ready").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        if not pause.with_suffix(".ready").exists():
            process.terminate()
            process.communicate(timeout=5)
        self.assertTrue(pause.with_suffix(".ready").exists(), "directory traversal did not expose the tested bind boundary")
        moved = self.root / "moved-container"
        container.rename(moved)
        replacement = self.root / "replacement-container"
        replacement.mkdir(mode=0o700)
        (replacement / "authorized").mkdir(mode=0o700)
        container.symlink_to(replacement, target_is_directory=True)
        pause.with_suffix(".continue").write_text("go", encoding="utf-8")
        _, stderr = process.communicate("ready\n", timeout=10)
        self.assertNotEqual(process.returncode, 0, stderr)
        self.assertEqual(list((moved / "authorized").glob("*.json")), [])
        self.assertEqual(list((replacement / "authorized").glob("*.json")), [])

    def test_concurrent_writers_publish_without_loss(self):
        invocations = [self.invocation() for _ in range(2)]
        processes = [subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env) for args, env in invocations]
        results = [process.communicate("ready\n", timeout=10) for process in processes]
        for process, (_, stderr) in zip(processes, results):
            self.assertEqual(process.returncode, 0, stderr)
        records = self.records()
        self.assertEqual(sum(record["record_type"] == "trial" for record in records), 2)
        self.assertEqual(sum(record["record_type"] == "capability" for record in records), 2)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in self.evidence_root.glob("*.json")))


if __name__ == "__main__":
    unittest.main()
