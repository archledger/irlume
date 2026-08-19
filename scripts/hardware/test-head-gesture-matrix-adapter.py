#!/usr/bin/env python3
"""Offline contract tests for the head-gesture matrix adapter."""

import hashlib
import os
import pathlib
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ADAPTER = HERE / "head-gesture-matrix-adapter.sh"


class AdapterTests(unittest.TestCase):
    DIGEST = hashlib.sha256(b"camera").hexdigest()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="irlume-gesture-adapter-")
        self.root = pathlib.Path(self.temporary.name)
        self.log = self.root / "candidate.args"
        self.candidate = self.root / "irlume"
        self.candidate.write_text(
            """#!/bin/sh
printf '%s\\n' "$@" >"$FAKE_CANDIDATE_ARGS"
case "$1:$2" in
  gesturecap:identity) printf '{"camera_identity_digest":"%s"}\\n' "$FAKE_CAMERA_DIGEST" ;;
  gesturecap:attempt) printf '%s\\n' '{"typed_outcome":"approved","detector_evidence":{"frames":75,"face_frames":75,"pitch_range":0.25,"yaw_range":0.2,"pitch_crossings":2,"yaw_crossings":0,"mean_step":0.03}}' ;;
  *) exit 9 ;;
esac
""",
            encoding="utf-8",
        )
        self.candidate.chmod(0o755)
        self.candidate_fd = os.open(self.candidate, os.O_RDONLY | os.O_CLOEXEC)
        self.candidate_bound = f"/proc/{os.getpid()}/fd/{self.candidate_fd}"
        (self.root / "models").mkdir()

    def tearDown(self):
        os.close(self.candidate_fd)
        self.temporary.cleanup()

    def run_adapter(self, args, **extra_env):
        env = os.environ.copy()
        env.update(
            {
                "FAKE_CANDIDATE_ARGS": str(self.log),
                "FAKE_CAMERA_DIGEST": self.DIGEST,
                "IRLUME_HEAD_GESTURE_ROOT": str(self.root),
                **extra_env,
            }
        )
        return subprocess.run(
            [str(ADAPTER), *args, "--candidate-binary", self.candidate_bound],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            pass_fds=(self.candidate_fd,),
        )

    def test_preflight_forwards_only_the_bound_identity_check(self):
        result = self.run_adapter(
            ["--preflight", "--expected-camera-identity-digest", self.DIGEST]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            f'{{"camera_identity_digest":"{self.DIGEST}"}}\n',
        )
        self.assertEqual(
            self.log.read_text(encoding="utf-8").splitlines(),
            ["gesturecap", "identity", "--expected-camera-identity-digest", self.DIGEST],
        )

    def test_attempt_forwards_the_frozen_detector_contract(self):
        result = self.run_adapter(
            [
                "--service",
                "gesturecap",
                "--purpose",
                "detector",
                "--expected-gesture",
                "nod",
                "--expected-camera-identity-digest",
                self.DIGEST,
                "--timeout-seconds",
                "20",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = result.stdout.strip()
        self.assertIn('"typed_outcome":"approved"', document)
        arguments = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(arguments[:2], ["gesturecap", "attempt"])
        self.assertEqual(arguments[arguments.index("--n") + 1], "75")
        self.assertEqual(arguments[arguments.index("--expected-gesture") + 1], "nod")
        self.assertEqual(
            arguments[arguments.index("--expected-camera-identity-digest") + 1],
            self.DIGEST,
        )

    def test_service_trials_and_contract_drift_fail_before_candidate_execution(self):
        cases = [
            [
                "--service",
                "sudo",
                "--purpose",
                "authentication",
                "--expected-gesture",
                "nod",
                "--expected-camera-identity-digest",
                self.DIGEST,
                "--timeout-seconds",
                "20",
            ],
            [
                "--service",
                "gesturecap",
                "--purpose",
                "detector",
                "--expected-gesture",
                "blink",
                "--expected-camera-identity-digest",
                self.DIGEST,
                "--timeout-seconds",
                "20",
            ],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.log.unlink(missing_ok=True)
                result = self.run_adapter(args)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
