#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Execute the real nightly camera shell with fixtures; never access hardware."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = 'a' * 40


def camera_step():
    lines = (ROOT / '.github/workflows/hardware-suite.yml').read_text().splitlines()
    start = lines.index('      - name: IR camera strobe-burst capture')
    assert lines[start + 1] == '        run: |'
    body = []
    for line in lines[start + 2:]:
        if line.strip() and not line.startswith('          '):
            break
        body.append(line[10:])
    assert body
    return '\n'.join(body)


class NightlyCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='irlume-nightly-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.target = self.root / 'target with spaces'
        (self.target / 'debug/examples').mkdir(parents=True)
        (self.root / 'scripts').mkdir()
        shutil.copy(ROOT / 'scripts/ir-node-from-doctor.sh', self.root / 'scripts')
        self.write(self.bin / 'cargo', '#!/bin/bash\nexit 0\n')
        self.write(self.bin / 'git', '#!/bin/bash\nprintf \"%s\\n\" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n')
        self.write(self.bin / 'sudo', '''#!/bin/bash
set -eu
[ "$1" = -n ] || exit 90
shift
if [ "${DENY_SUDO:-0}" = 1 ]; then
  echo 'sudo: fixture requires a password' >&2
  exit 1
fi
export FIXTURE_PRIVILEGED=1
exec "$@"
''')
        self.write(self.bin / 'sleep', '''#!/bin/bash
printf '%s\\n' "$@" >> "$SLEEPS"
''')
        self.write(self.target / 'debug/irlume', '''#!/bin/bash
if [ "${NO_NODES:-0}" = 1 ]; then
  printf '%s\\n' '[doctor] camera nodes (classified by pixel format):' '  (no /dev/video* nodes on this machine)'
elif [ "${TWO_IR:-0}" = 1 ]; then
  printf '%s\\n' '[doctor] camera nodes (classified by pixel format):' '  /dev/video6: Ir (uvcvideo, USB)' '  /dev/video2: Ir (uvcvideo, USB)'
else
  printf '%s\\n' '[doctor] camera nodes (classified by pixel format):' '  /dev/video2: Ir (uvcvideo, USB)'
fi
''')
        self.write(self.target / 'debug/examples/burst_dump', '''#!/bin/bash
set -eu
printf '%s\\n' "${FIXTURE_PRIVILEGED:-0}" >> "$CALLS"
[ "$2" = /dev/video2 ] && [ "$3" = 6 ] || exit 91
[ "${IRLUME_LOG_EMITTER_WRITES:-0}" = 1 ] || exit 92
if [ "${FIRST_WINDOW_REFUSED:-0}" = 1 ]; then
  echo 'irlume: burst first window refused: requested=1/30 accepted=1/30 floor=15/1 tolerance_percent=97 window_count=30 window_span_us=2104076 delivered=7500000/526019 max_inter_frame_gap_us=95945 meets_floor=false' >&2
fi
if [ "${RECHECK_REFUSED:-0}" = 1 ]; then
  echo 'irlume: burst rate refused: role=ir window_count=30 window_span_us=2090000 sequence_gap=0 cumulative_drops=0' >&2
  exit 3
fi
# Written at the first frame after the recheck, before any later window.
if [ "${FIRST_WINDOW_REFUSED:-0}" = 1 ]; then
  echo 'irlume: burst rate accepted after one startup recheck: requested=1/30 accepted=1/30 floor=15/1 tolerance_percent=97 window_count=30 window_span_us=2028086 delivered=15000000/1014043 max_inter_frame_gap_us=71998 meets_floor=true' >&2
fi
if [ "${LATER_REFUSED:-0}" = 1 ]; then
  echo 'irlume: burst rate refused: role=ir window_count=30 window_span_us=2100212 sequence_gap=0 cumulative_drops=0' >&2
  exit 3
fi
if [ "${REFUSE_RATE_ONCE:-0}" = 1 ] && [ ! -e "$RATE_REFUSED" ]; then
  : > "$RATE_REFUSED"
  echo 'irlume: burst rate refused: role=ir window_count=30 window_span_us=2088113 sequence_gap=0 cumulative_drops=0' >&2
  exit 3
fi
if [ "${FAIL_CAPTURE:-0}" = 1 ]; then
  echo 'fixture: capture failed' >&2
  exit 23
fi
mkdir -p "$1"
for ((i=0; i<${FRAMES:-6}; i++)); do
  touch "$1/frame$i.pgm"
  printf '%s %s\\n' "$i" "$((i * ${SPREAD:-10}))" >> "$1/means.txt"
done
if [ "${FIXTURE_PRIVILEGED:-0}" != 1 ]; then
  # The actual failure: successful raw capture, but no managed emitter write.
  echo 'irlume: could not check interrupted emitter setup: lock: Permission denied' >&2
elif [ "${NO_MARKER:-0}" != 1 ]; then
  case "${PROOF:-write}" in
    write) echo 'irlume: capture emitter write completed' >&2 ;;
    default) echo 'irlume: capture emitter device default verified' >&2 ;;
    held) echo 'irlume: capture emitter already held the requested value' >&2 ;;
    both) printf '%s\\n' 'irlume: capture emitter write completed' 'irlume: capture emitter device default verified' >&2 ;;
    partial) echo 'prefix irlume: capture emitter device default verified' >&2 ;;
  esac
fi
''')
        self.env = dict(os.environ, PATH=f'{self.bin}:/usr/bin:/bin',
                        CARGO_TARGET_DIR=str(self.target), TMPDIR=str(self.root),
                        CALLS=str(self.root / 'calls'), SLEEPS=str(self.root / 'sleeps'),
                        RATE_REFUSED=str(self.root / 'rate-refused'))
        for key in ['FIXTURE_PRIVILEGED', 'DENY_SUDO', 'FAIL_CAPTURE', 'FRAMES',
                    'SPREAD', 'NO_MARKER', 'PROOF', 'HELPER_EXIT', 'REJECT_BUILD', 'TWO_IR',
                    'NO_NODES', 'REFUSE_RATE_ONCE', 'FIRST_WINDOW_REFUSED', 'RECHECK_REFUSED',
                    'LATER_REFUSED']:
            self.env.pop(key, None)

    def write(self, path, source):
        path.write_text(textwrap.dedent(source))
        path.chmod(0o755)

    def run_step(self, **env):
        body = (camera_step()
                .replace('/usr/local/libexec/irlume-ci-capture', str(self.root / 'capture-helper'))
                .replace('/usr/local/lib/irlume-ci/capture.json', str(self.root / 'capture.json')))
        return subprocess.run(['/bin/bash', '-e', '-c', body],
                              cwd=self.root, env=dict(self.env, **env),
                              capture_output=True, text=True, timeout=10)

    def approve(self, tree=TREE, device='/dev/video2', age_days=0, text=None):
        """Write the fixture approval, dated `age_days` back."""
        path = self.root / 'capture.json'
        path.write_text(text if text is not None else json.dumps(
            {'schema': 1, 'source_tree': tree, 'sha256': 'b' * 64, 'device': device}))
        stamp = time.time() - age_days * 86400
        os.utime(path, (stamp, stamp))

    def install_helper(self, **approval):
        self.approve(**approval)
        self.write(self.root / 'capture-helper', '''#!/bin/bash
set -eu
[ "${FIXTURE_PRIVILEGED:-0}" = 1 ] || exit 93
export IRLUME_LOG_EMITTER_WRITES=1
[ "$1" = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ] || exit 94
if [ "${REJECT_BUILD:-0}" = 1 ]; then
  echo 'fixture: build is not approved' >&2
  exit 1
fi
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"$CARGO_TARGET_DIR/debug/examples/burst_dump" "$out" "$2" 6 >/dev/null || exit 1
tar -C "$out" -cf - .
exit "${HELPER_EXIT:-0}"
''')

    def assert_first_rate_refusal_fails(self):
        # The fake capture would succeed on a second call. The first refusal
        # must stay visible to the workflow's failure-only forensics.
        result = self.run_step(REFUSE_RATE_ONCE='1')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('privileged IR burst failed', result.stdout, result.stdout + result.stderr)
        self.assertEqual((self.root / 'calls').read_text(), '1\n')
        self.assertFalse((self.root / 'sleeps').exists())
        self.assertIn('irlume: burst rate refused: role=ir', result.stdout)
        self.assertIn('window_span_us=2088113', result.stdout)
        self.assertNotIn('captured 6 frames', result.stdout)

    def test_direct_rate_refusal_remains_a_failure(self):
        self.assert_first_rate_refusal_fails()

    def test_helper_rate_refusal_remains_a_failure(self):
        self.install_helper()
        self.assert_first_rate_refusal_fails()

    def assert_rechecked_capture_passes(self):
        # The first rate window missed; the one startup recheck passed. The
        # step stays green and says so, with both windows in the log.
        result = self.run_step(FIRST_WINDOW_REFUSED='1')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / 'calls').read_text(), '1\n')
        self.assertFalse((self.root / 'sleeps').exists())
        self.assertIn('irlume: burst first window refused: requested=1/30', result.stdout)
        self.assertIn('irlume: burst rate accepted after one startup recheck:', result.stdout)
        self.assertIn(
            '::warning::IR burst: the first rate window of the session was below the floor', result.stdout)
        self.assertIn('captured 6 frames', result.stdout)

    def assert_refused_recheck_fails(self):
        # The window after the recheck missed too: both windows stay visible
        # and the step fails on its first capture.
        result = self.run_step(FIRST_WINDOW_REFUSED='1', RECHECK_REFUSED='1')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('privileged IR burst failed', result.stdout)
        self.assertEqual((self.root / 'calls').read_text(), '1\n')
        self.assertFalse((self.root / 'sleeps').exists())
        self.assertIn('irlume: burst first window refused:', result.stdout)
        self.assertIn('irlume: burst rate refused: role=ir window_count=30 window_span_us=2090000', result.stdout)
        self.assertNotIn('captured 6 frames', result.stdout)

    def test_direct_first_window_refusal_with_a_passing_recheck_passes(self):
        self.assert_rechecked_capture_passes()

    def test_helper_first_window_refusal_with_a_passing_recheck_passes(self):
        self.install_helper()
        self.assert_rechecked_capture_passes()

    def test_direct_refused_recheck_window_fails_with_both_windows(self):
        self.assert_refused_recheck_fails()

    def test_helper_refused_recheck_window_fails_with_both_windows(self):
        self.install_helper()
        self.assert_refused_recheck_fails()

    def assert_later_refusal_after_acceptance_fails(self):
        # The recheck window passed and a later window missed: the step fails
        # on its first capture, and the log keeps all three lines in order.
        result = self.run_step(FIRST_WINDOW_REFUSED='1', LATER_REFUSED='1')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('privileged IR burst failed', result.stdout)
        self.assertEqual((self.root / 'calls').read_text(), '1\n')
        self.assertFalse((self.root / 'sleeps').exists())
        positions = [result.stdout.index(line) for line in [
            'irlume: burst first window refused:',
            'irlume: burst rate accepted after one startup recheck:',
            'irlume: burst rate refused: role=ir window_count=30 window_span_us=2100212']]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn('captured 6 frames', result.stdout)

    def test_direct_later_refusal_after_acceptance_fails_with_all_three_lines(self):
        self.assert_later_refusal_after_acceptance_fails()

    def test_helper_later_refusal_after_acceptance_fails_with_all_three_lines(self):
        self.install_helper()
        self.assert_later_refusal_after_acceptance_fails()

    def test_a_capture_without_a_recheck_prints_no_warning(self):
        for helper in [False, True]:
            if helper:
                self.install_helper()
            with self.subTest(helper=helper):
                result = self.run_step()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn('burst first window refused', result.stdout)
                self.assertNotIn('burst rate accepted after one startup recheck', result.stdout)
                self.assertNotIn('::warning::IR burst:', result.stdout)

    def test_installed_helper_preserves_all_capture_gates(self):
        self.install_helper()
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / 'calls').read_text(), '1\n')
        self.assertIn('captured 6 frames', result.stdout)
        self.assertIn('mean spread: 50.0', result.stdout)
        for env in [dict(NO_MARKER='1'), dict(FRAMES='3'), dict(SPREAD='0')]:
            with self.subTest(env=env):
                result = self.run_step(**env)
                self.assertNotEqual(result.returncode, 0)

    def test_helper_failure_cannot_hide_behind_successful_archive_extraction(self):
        self.install_helper()
        result = self.run_step(HELPER_EXIT='23')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('privileged IR burst failed', result.stdout)

    def test_unapproved_helper_build_never_captures(self):
        self.install_helper()
        result = self.run_step(REJECT_BUILD='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'calls').exists())
        self.assertIn('build is not approved', result.stdout + result.stderr)

    def test_helper_captures_the_approved_device_not_the_first_ir_node(self):
        self.install_helper()
        result = self.run_step(TWO_IR='1')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('IR node: /dev/video2', result.stdout)
        self.assertEqual((self.root / 'calls').read_text(), '1\n')

    def test_approved_device_doctor_does_not_call_ir_never_captures(self):
        self.install_helper(device='/dev/video3')
        result = self.run_step()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'calls').exists())
        self.assertIn('names /dev/video3, which doctor does not classify as an IR node', result.stdout)

    def test_approval_for_another_tree_warns_and_skips_within_grace(self):
        for age, shown in [(0, 0), (7 - 1 / 24, 6)]:
            with self.subTest(age=age):
                self.install_helper(tree='c' * 40, age_days=age)
                result = self.run_step()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.root / 'calls').exists())
                self.assertIn('::warning::IR capture not run', result.stdout)
                self.assertIn(f'written {shown} day(s) ago', result.stdout)

    def test_approval_for_another_tree_fails_from_seven_days(self):
        for age in [7, 8]:
            with self.subTest(age=age):
                self.install_helper(tree='c' * 40, age_days=age)
                result = self.run_step()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'calls').exists())
                self.assertIn(f'::error::IR capture not run for {age} days', result.stdout)

    def test_absent_camera_skip_cannot_outlast_the_deadline(self):
        self.install_helper(tree='c' * 40, age_days=1)
        result = self.run_step(NO_NODES='1')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('camera stage skipped', result.stdout)
        self.assertIn('::warning::IR capture not run', result.stdout)
        self.install_helper(tree='c' * 40, age_days=8)
        result = self.run_step(NO_NODES='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('::error::IR capture not run for 8 days', result.stdout)

    def test_stale_tree_still_validates_the_approved_device(self):
        self.install_helper(tree='c' * 40, device='/dev/video3')
        result = self.run_step(TWO_IR='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'calls').exists())
        self.assertIn('names /dev/video3, which doctor does not classify as an IR node', result.stdout)

    def test_another_tree_still_fails_on_a_doctor_regression(self):
        self.install_helper(tree='c' * 40)
        self.write(self.target / 'debug/irlume', """#!/bin/bash
printf '%s\\n' '[doctor] camera nodes (classified by pixel format):' '  /dev/video0: Rgb (uvcvideo, USB)'
""")
        result = self.run_step()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('none as Ir', result.stdout)

    def test_unreadable_or_incomplete_approval_never_captures(self):
        for text in ['{', '{"schema": 1, "source_tree": "%s"}' % TREE,
                     '{"schema": 1, "source_tree": "short", "device": "/dev/video2"}']:
            with self.subTest(text=text):
                self.install_helper(text=text)
                result = self.run_step()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'calls').exists())
                self.assertIn('cannot read the capture approval', result.stdout)

    def test_verified_default_keeps_frame_and_spread_gates(self):
        for helper in [False, True]:
            if helper:
                self.install_helper()
            with self.subTest(helper=helper):
                result = self.run_step(PROOF='default')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('device default verified', result.stdout)
                for env in [dict(FRAMES='3'), dict(SPREAD='0')]:
                    result = self.run_step(PROOF='default', **env)
                    self.assertNotEqual(result.returncode, 0)

    def test_held_partial_or_ambiguous_proof_is_rejected(self):
        for proof in ['held', 'both', 'partial']:
            with self.subTest(proof=proof):
                self.assertNotEqual(self.run_step(PROOF=proof).returncode, 0)

    def test_privileged_hardware_job_is_restricted_to_main(self):
        workflow = (ROOT / '.github/workflows/hardware-suite.yml').read_text()
        hardware = workflow.split('  hardware:\n', 1)[1].split('    steps:', 1)[0]
        self.assertIn("    if: github.ref == 'refs/heads/main'\n", hardware)

    def test_privileged_capture_succeeds_without_unprivileged_probe(self):
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / 'calls').read_text(), '1\n')
        self.assertIn('captured 6 frames', result.stdout)
        self.assertIn('mean spread: 50.0', result.stdout)

    def test_sudo_denied_never_captures(self):
        result = self.run_step(DENY_SUDO='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'calls').exists())
        self.assertIn('requires a password', result.stdout + result.stderr)

    def test_capture_failure_preserves_diagnostic(self):
        result = self.run_step(FAIL_CAPTURE='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fixture: capture failed', result.stdout + result.stderr)

    def test_successful_capture_without_write_marker_fails(self):
        result = self.run_step(NO_MARKER='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('did not complete the emitter write', result.stdout)

    def test_insufficient_frames_fail(self):
        result = self.run_step(FRAMES='3')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('captured 3 frames', result.stdout)

    def test_flat_burst_fails(self):
        result = self.run_step(SPREAD='0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('mean spread: 0.0', result.stdout)


if __name__ == '__main__':
    unittest.main()
