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
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/coverage.yml'

# The instrumented lanes the job must run: the workspace lane, ci.yml's five
# TPM-gated swtpm lanes, its four loopback-camera lanes and the PAM FFI lane.
# A lane deleted from the workflow must fail here, not vanish quietly.
EXPECTED_INSTRUMENTED_LANES = 11

# Independently pin the existing daemon swtpm suite, not the contents of
# either workflow or libtest's current --list output. Losing a name in both
# workflows at once must still fail this contract.
DAEMON_SWTPM_TESTS = (
    'tpm_a_checked_arm_never_replaces_a_token_with_another_kind',
    'tpm_a_checked_arm_never_seals_over_an_unreadable_envelope',
    'tpm_a_checked_new_password_rewraps_the_token',
    'tpm_a_checked_token_arm_never_mints_over_an_unreadable_envelope',
    'tpm_a_first_arm_on_an_oo7_home_seals_the_login_password',
    'tpm_an_arm_on_an_oo7_home_keeps_an_armed_token',
    'tpm_endorsement_report_keeps_its_deadline_and_notes_progress',
    'tpm_owner_reseal_leaves_the_token_envelope_unchanged',
    'tpm_readiness_report_carries_the_lockout_state',
    'tpm_refused_eyes_open_off_keeps_the_enrollment_and_key_unmoved',
    'tpm_reseal_with_a_wrong_login_password_leaves_the_envelope_unchanged',
    'tpm_seal_and_unseal_keyring_release_the_secret_to_root_only',
    'tpm_split_whole_broken_credential_envelope_refuses_release_and_keeps_charge',
    'tpm_split_whole_centroid_identity_releases_once_at_each_skew',
    'tpm_split_whole_reset_preserves_template_key_and_next_authenticate_routes',
    'tpm_split_whole_unseal_releases_once_at_each_skew_and_resets_only_after_delivery',
    'tpm_split_whole_unwritten_credential_keeps_the_charge_after_one_real_release',
    'tpm_unverified_owner_seal_leaves_the_token_envelope_unchanged',
    'tpm_unverified_reseal_rewraps_the_token_under_the_new_password',
    'tpm_unverified_root_seal_leaves_the_token_envelope_unchanged',
)


def workflow_text(workflow=WORKFLOW):
    text = workflow.read_text()
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
        # and the clean step must carry neither switch, and the job itself
        # must be unconditional: this workflow has one job whose top-level
        # keys sit at four spaces of indentation, so a job-level `if:` is
        # any exactly-four-space `if:` line, which the parser below the
        # step markers would never collect.
        joined = workflow_text()
        self.assertNotRegex(joined, r'(?m)^    if:')
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
        # least the calibrated minimum, so the flag cannot be dropped or
        # quietly lowered back to a placeholder again. The first hosted run
        # measured 88.17% (2026-11-14); the floor was set to 87. A floor
        # moves only with the change that moves the measurement, and this
        # minimum moves with it.
        joined = workflow_text()
        report = [line.strip() for line in joined.splitlines()
                  if '--summary-only' in line
                  and 'llvm-cov report' in line]
        self.assertEqual(len(report), 1)
        self.assertIn('--summary-only', report[0])
        match = re.search(r'--fail-under-lines ([0-9]+)', report[0])
        self.assertIsNotNone(match, report[0])
        self.assertGreaterEqual(int(match.group(1)), 87)
        self.assertLess(joined.rindex('llvm-cov --no-report'),
                        joined.index('llvm-cov report'))

    def test_export_and_artifact_upload_exist(self):
        # The lcov trace and the summary are the calibration evidence for the
        # floor; they must upload even when the floor fails, and the upload
        # must use the pinned artifact action with modest retention. The
        # pinned cargo-llvm-cov 0.9.1 has no export subcommand: the trace is
        # a report-format flag, so the exact invocation is pinned to keep a
        # future syntax drift from silently skipping the export. The
        # always-conditions are asserted on the exact steps that need them,
        # not somewhere in the file: a stray `if: always()` elsewhere must
        # not cover a step losing its own.
        joined = workflow_text()
        self.assertIn(
            'llvm-cov report --lcov --output-path coverage/lcov.info',
            joined)
        self.assertLess(joined.rindex('llvm-cov --no-report'),
                        joined.index('llvm-cov report --lcov'))
        self.assertLess(joined.index('llvm-cov report --lcov'),
                        joined.index('llvm-cov report --summary-only'))
        self.assertRegex(joined, r'uses: actions/upload-artifact@[0-9a-f]{40}')
        self.assertRegex(joined, r'retention-days: [0-9]+')
        steps = []
        for line in WORKFLOW.read_text().splitlines():
            trimmed = line.strip()
            if trimmed.startswith('- name:') or trimmed.startswith('- uses:'):
                steps.append([])
            if steps:
                steps[-1].append(trimmed)
        # !cancelled(), not always(): the summary and the trace are the
        # calibration evidence after a lane failure, but a run cancelled by a
        # newer push should not pay for a full report and an upload. The
        # condition is asserted on the exact steps that need it, not
        # somewhere in the file: a stray `if:` elsewhere must not cover a
        # step losing its own.
        for name_fragment in ('Report and enforce the line-coverage floor',
                              'Upload coverage artifacts'):
            matching = [step for step in steps
                        if step and name_fragment in step[0]]
            self.assertEqual(len(matching), 1, name_fragment)
            self.assertIn("if: ${{ !cancelled() }}", matching[0],
                          name_fragment)

    def test_floor_step_enforcement_reaches_the_job(self):
        # The floor is only a floor if its failure fails the job. The report
        # step pipes into tee, so without pipefail a nonzero
        # --fail-under-lines exit is swallowed by the pipe's last command and
        # the job goes green with the floor "enforced". The step must carry
        # set -euo pipefail (or drop the pipe), and nothing may add
        # continue-on-error to it: both are edits this contract exists to
        # refuse (#325/#409's silent-degradation mode).
        steps = []
        for line in WORKFLOW.read_text().splitlines():
            trimmed = line.strip()
            if trimmed.startswith('- name:') or trimmed.startswith('- uses:'):
                steps.append([])
            if steps:
                steps[-1].append(trimmed)
        matching = [step for step in steps
                    if step and 'Report and enforce' in step[0]]
        self.assertEqual(len(matching), 1)
        self.assertIn('set -euo pipefail', matching[0])
        self.assertFalse(
            any('continue-on-error' in line for line in matching[0]),
            matching[0])

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


class DaemonSwtpmGuardTests(unittest.TestCase):
    def guard_args(self, workflow, command):
        lines = [line.strip() for line in workflow_text(workflow).splitlines()
                 if '-p irlume-daemon ' in line and '--ignored tpm_' in line]
        self.assertEqual(len(lines), 1, workflow.name)
        args = shlex.split(lines[0])
        self.assertEqual(args[0], './scripts/run-tests-guarded.sh')
        separator = args.index('--')
        self.assertEqual(
            args[separator + 1:],
            command + ['-p', 'irlume-daemon', '--locked', '--',
                       '--ignored', 'tpm_', '--test-threads=1'],
        )
        return args[1:separator]

    def test_both_daemon_lanes_guard_every_named_result(self):
        def run_guard(args, names):
            # These are libtest's normal result lines. This test runs only
            # the guard, never Cargo or any software or physical TPM.
            transcript = ''.join(f'test tests::{name} ... ok\n' for name in names)
            transcript += f'test result: ok. {len(names)} passed; 0 failed; 0 ignored;\n'
            return subprocess.run(
                ['bash', './scripts/run-tests-guarded.sh', *args, '--', 'printf', '%s',
                 transcript],
                cwd=ROOT, capture_output=True, text=True, timeout=10,
            )

        for workflow, command in (
            (WORKFLOW.with_name('ci.yml'), ['cargo', 'test']),
            (WORKFLOW, ['$IRLUME_COVERAGE_BIN', 'llvm-cov', '--no-report']),
        ):
            args = self.guard_args(workflow, command)
            result = run_guard(args, DAEMON_SWTPM_TESTS)
            self.assertEqual(result.returncode, 0, result.stderr)
            for missing in DAEMON_SWTPM_TESTS:
                with self.subTest(workflow=workflow.name, missing=missing):
                    # A different passing case keeps the count unchanged.
                    names = tuple('tpm_unrelated_passing_fixture' if name == missing else name
                                  for name in DAEMON_SWTPM_TESTS)
                    result = run_guard(args, names)
                    self.assertEqual(result.returncode, 1, result.stdout)
                    self.assertIn(f'did not run and pass: {missing}', result.stderr)


if __name__ == '__main__':
    unittest.main()
