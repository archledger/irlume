#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Pin the hosted coverage lane's shape and execute its guards on fixtures.

The previous hosted coverage job (removed 2026-08-10, #409) degraded silently:
its --fail-under-lines flag was dropped in a refactor and it ran zero tests
while staying green. This contract fails the `units` job when
.github/workflows/coverage.yml loses any of the properties that make such a
silent degradation impossible again. Fixtures only: no tool install, no
Rust build, no hardware.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/coverage.yml'

# The instrumented lanes the job must run: the workspace lane, ci.yml's five
# TPM-gated swtpm lanes, its four loopback-camera lanes and the PAM FFI lane.
# A lane deleted from the workflow must fail here, not vanish quietly.
EXPECTED_INSTRUMENTED_LANES = 11


def workflow_text():
    text = WORKFLOW.read_text()
    # Join shell continuations so one lane spanning several lines is checked
    # as the single command the guard actually sees.
    return text.replace('\\\n', ' ')


def instrumented_lanes(joined):
    return [line.strip() for line in joined.splitlines()
            if 'llvm-cov --no-report' in line]


class HostedCoverageContractTests(unittest.TestCase):
    def test_clean_precedes_every_instrumented_run(self):
        # `--no-report` keeps earlier build artifacts and the report reads
        # every instrumented binary under the target directory, so a stale
        # binary double-counts its changed files (#906). The clean must run
        # after setup and before the first measurement.
        joined = workflow_text()
        self.assertEqual(joined.count('llvm-cov clean'), 1)
        setup = joined.index('bash scripts/ci/setup-coverage-tools.sh rustup')
        clean = joined.index('"$IRLUME_COVERAGE_BIN" llvm-cov clean --workspace')
        first_run = joined.index('llvm-cov --no-report')
        self.assertLess(setup, clean)
        self.assertLess(clean, first_run)

    def test_every_instrumented_run_is_guarded(self):
        # `cargo test` (and cargo llvm-cov) exit 0 when a filter matches
        # nothing, so an unguarded lane can silently become a no-op. Every
        # instrumented invocation must go through run-tests-guarded.sh with a
        # --min floor or a --require name set, with the guard ahead of the
        # invocation on the same command line.
        lanes = instrumented_lanes(workflow_text())
        self.assertGreaterEqual(len(lanes), 1)
        self.assertEqual(len(lanes), EXPECTED_INSTRUMENTED_LANES)
        for lane in lanes:
            with self.subTest(lane=lane[:70]):
                self.assertIn('./scripts/run-tests-guarded.sh', lane)
                self.assertLess(lane.index('./scripts/run-tests-guarded.sh'),
                                lane.index('"$IRLUME_COVERAGE_BIN" llvm-cov'))
                self.assertTrue('--min ' in lane or '--require ' in lane,
                                'lane has neither a --min floor nor --require names')

    def test_lane_steps_cannot_be_silently_disabled(self):
        # A text contract over lane lines cannot see step-level switches: a
        # lane step carrying `if: false` or `continue-on-error: true` would
        # still satisfy every guard assertion while running zero tests, which
        # is the 2026-08 failure mode wearing a different flag. Lane steps
        # and the clean step must carry neither switch.
        steps = []
        for line in WORKFLOW.read_text().splitlines():
            trimmed = line.strip()
            if trimmed.startswith('- name:') or trimmed.startswith('- uses:'):
                steps.append([])
            if steps:
                steps[-1].append(trimmed)
        lane_steps = [step for step in steps
                      if any('llvm-cov --no-report' in line
                             or 'llvm-cov clean' in line for line in step)]
        self.assertGreaterEqual(len(lane_steps), 2,
                                'expected the clean step and lane steps')
        for step in lane_steps:
            with self.subTest(step=step[0]):
                for line in step:
                    self.assertFalse(
                        line.startswith('if:')
                        or line.startswith('continue-on-error:'),
                        f'{step[0]} carries a disabling switch: {line}')

    def test_report_exists_after_every_run_and_enforces_a_floor(self):
        # The report step is the measurement: without it the job runs tests
        # and enforces nothing (the 2026-08 failure mode). It must run after
        # every instrumented lane and carry a --fail-under-lines floor of at
        # least 1, so the flag cannot be dropped silently again.
        joined = workflow_text()
        report = [line.strip() for line in joined.splitlines()
                  if 'llvm-cov report' in line]
        self.assertEqual(len(report), 1)
        self.assertIn('--summary-only', report[0])
        match = re.search(r'--fail-under-lines ([0-9]+)', report[0])
        self.assertIsNotNone(match, report[0])
        self.assertGreaterEqual(int(match.group(1)), 1)
        self.assertLess(joined.rindex('llvm-cov --no-report'),
                        joined.index('llvm-cov report'))

    def test_export_and_artifact_upload_exist(self):
        # The lcov trace and the summary are the calibration evidence for the
        # floor; they must upload even when the floor fails, and the upload
        # must use the pinned artifact action with modest retention.
        joined = workflow_text()
        self.assertIn('llvm-cov export --format lcov --output-path coverage/lcov.info',
                      joined)
        self.assertLess(joined.index('llvm-cov export'), joined.index('llvm-cov report'))
        self.assertRegex(joined, r'uses: actions/upload-artifact@[0-9a-f]{40}')
        self.assertRegex(joined, r'if: always\(\)')
        self.assertRegex(joined, r'retention-days: [0-9]+')

    def test_setup_uses_the_rustup_toolchain_path_and_pinned_binary(self):
        joined = workflow_text()
        self.assertIn('bash scripts/ci/setup-coverage-tools.sh rustup', joined)
        self.assertIn('components: llvm-tools-preview', joined)
        # The pinned binary from setup, never a bare cargo subcommand that an
        # inherited stale tool could satisfy.
        self.assertNotIn('-- cargo llvm-cov', joined)
        self.assertEqual(joined.count('"$IRLUME_COVERAGE_BIN" llvm-cov clean'),
                         1)
        self.assertIn('persist-credentials: false', joined)

    def test_pam_lane_requires_the_pam_tools(self):
        # Mirrors the pamwrap test that checks ci.yml's and
        # hardware-suite.yml's PAM steps: without IRLUME_REQUIRE_PAM_TOOLS a
        # runner that lost pamtester or pam_wrapper skips every pamwrap test
        # and the lane still passes.
        env_line = 'IRLUME_REQUIRE_PAM_TOOLS: "1"'
        steps = []
        for line in WORKFLOW.read_text().splitlines():
            trimmed = line.strip()
            if trimmed.startswith('- name:') or trimmed.startswith('- uses:'):
                steps.append([])
            if steps:
                steps[-1].append(trimmed)
        pam_steps = [step for step in steps
                     if any('-p irlume-pam ' in line and '--include-ignored' in line
                            for line in step)]
        self.assertTrue(pam_steps, 'no step runs the irlume-pam lane')
        for step in pam_steps:
            self.assertIn(env_line, step, step[0])


class WorkspaceLaneGuardTests(unittest.TestCase):
    """Execute the workflow's real workspace lane against a fixture tool."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hosted coverage contract ')
        self.addCleanup(self.tmp.cleanup)
        self.bin = Path(self.tmp.name) / 'coverage fixture'
        self.bin.write_text(r'''#!/usr/bin/env python3
import os,sys
args=sys.argv[1:]
assert args[0]=='llvm-cov' and '--no-report' in args
assert '--workspace' in args and '--locked' in args
print(f'test result: ok. {os.environ["FIXTURE_PASSED"]} passed; 0 failed; 0 ignored')
sys.exit(int(os.environ['FIXTURE_EXIT']))
''')
        self.bin.chmod(0o755)

    def lane(self):
        joined = workflow_text()
        lanes = [line.strip() for line in joined.splitlines()
                 if '--no-report --workspace' in line]
        assert len(lanes) == 1
        return lanes[0]

    def run_lane(self, passed, exit_code=0):
        return subprocess.run(['bash', '-e', '-c', self.lane()], cwd=ROOT,
                              env=dict(os.environ, IRLUME_COVERAGE_BIN=str(self.bin),
                                       FIXTURE_PASSED=str(passed),
                                       FIXTURE_EXIT=str(exit_code)),
                              capture_output=True, text=True, timeout=10)

    def test_lane_passes_at_its_floor(self):
        result = self.run_lane(2720)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_lane_below_its_floor_fails(self):
        self.assertNotEqual(self.run_lane(2719).returncode, 0)

    def test_lane_with_zero_tests_fails(self):
        # The zero-match filter the guard exists for.
        self.assertNotEqual(self.run_lane(0).returncode, 0)

    def test_failed_command_cannot_pass_from_success_output(self):
        self.assertEqual(self.run_lane(2720, exit_code=23).returncode, 23)


if __name__ == '__main__':
    unittest.main()
