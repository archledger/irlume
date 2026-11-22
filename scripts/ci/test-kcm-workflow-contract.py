#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Check the container KCM smoke step without starting CMake or KDE."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


WORKFLOW = Path(__file__).resolve().parents[2] / '.github/workflows/kcm.yml'
STEP = 'Runtime QML instantiation check (offscreen kcmshell6)'


class KcmSmokeContractTests(unittest.TestCase):
    def test_step_reports_the_smoke_process_result(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        job = workflow['jobs']['build']
        self.assertIn('container', job)
        matching = [step for step in job['steps'] if step.get('name') == STEP]
        self.assertEqual(len(matching), 1, STEP)
        step = matching[0]
        # A container run defaults to sh, not the hosted runner's bash.
        for scope in (workflow, job):
            self.assertNotIn('shell', scope.get('defaults', {}).get('run', {}))
        self.assertNotIn('shell', step)
        self.assertNotIn('if', step)
        self.assertNotIn('continue-on-error', step)

        # Run the workflow's real shell body. The only CMake and KCM commands
        # on its PATH are stand-ins; no installation or graphical session.
        with tempfile.TemporaryDirectory(prefix='kcm-smoke-') as directory:
            root = Path(directory)
            for name in ('cat', 'env', 'grep', 'mktemp', 'tee', 'timeout'):
                tool = shutil.which(name, path=os.defpath)
                self.assertIsNotNone(tool, name)
                (root / name).symlink_to(tool)
            for name, body in {
                'cmake': '[ "$*" = "--install kcm-build" ]\n',
                'kcmshell6': (
                    '[ "$*" = kcm_irlume ] || exit 96\n'
                    '[ "$QT_QPA_PLATFORM" = offscreen ] || exit 97\n'
                    '[ "$QT_FORCE_STDERR_LOGGING" = 1 ] || exit 98\n'
                    ': > smoke-ran\n'
                    'printf "%s\\n" "$FIXTURE_DIAGNOSTIC" >&2\n'
                    'exit "$FIXTURE_STATUS"\n'
                ),
            }.items():
                path = root / name
                path.write_text('#!/bin/sh\n' + body)
                path.chmod(0o700)

            for status, diagnostic, expected in (
                (0, 'clean exit', 0),
                (124, 'event-loop timeout', 0),
                (1, 'ordinary failure', 1),
                (134, 'abort status', 134),
                (139, 'crash status', 139),
                (124, 'Unable to assign [undefined]', 1),
                (124, 'Could not find KCM with given Id', 1),
            ):
                with self.subTest(status=status, diagnostic=diagnostic):
                    marker = root / 'smoke-ran'
                    marker.unlink(missing_ok=True)
                    result = subprocess.run(
                        ['/bin/sh', '-e', '-c', step['run']],
                        cwd=root, capture_output=True, text=True, timeout=5,
                        env={
                            'PATH': str(root), 'TMPDIR': str(root),
                            'FIXTURE_STATUS': str(status), 'FIXTURE_DIAGNOSTIC': diagnostic,
                        },
                    )
                    self.assertTrue(marker.is_file(), result.stderr)
                    self.assertIn(diagnostic, result.stdout)
                    self.assertEqual(result.returncode, expected, result.stderr)


if __name__ == '__main__':
    unittest.main()
