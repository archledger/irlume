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
        self.write(self.target / 'debug/irlume', '''#!/bin/bash
if [ "${TWO_IR:-0}" = 1 ]; then
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
                        CALLS=str(self.root / 'calls'))
        for key in ['FIXTURE_PRIVILEGED', 'DENY_SUDO', 'FAIL_CAPTURE', 'FRAMES',
                    'SPREAD', 'NO_MARKER', 'PROOF', 'HELPER_EXIT', 'REJECT_BUILD', 'TWO_IR']:
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
"$CARGO_TARGET_DIR/debug/examples/burst_dump" "$out" "$2" 6 >/dev/null
tar -C "$out" -cf - .
exit "${HELPER_EXIT:-0}"
''')

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
        for age in [0, 7]:
            with self.subTest(age=age):
                self.install_helper(tree='c' * 40, age_days=age)
                result = self.run_step()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.root / 'calls').exists())
                self.assertIn('::warning::IR capture not run', result.stdout)
                self.assertIn(f'written {age} day(s) ago', result.stdout)

    def test_approval_for_another_tree_fails_after_grace(self):
        self.install_helper(tree='c' * 40, age_days=8)
        result = self.run_step()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'calls').exists())
        self.assertIn('::error::IR capture not run for 8 days', result.stdout)

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
