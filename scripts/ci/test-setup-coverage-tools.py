#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Exercise coverage bootstrap without downloading tools or accessing hardware."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/ci/setup-coverage-tools.sh'


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='coverage setup ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env_file = self.root / 'github env'
        self.env_file.touch()
        self.calls = self.root / 'calls'
        self.env = dict(os.environ, PATH=f'{self.bin}:/usr/bin:/bin',
                        RUNNER_TEMP=str(self.root), GITHUB_ENV=str(self.env_file),
                        CALLS=str(self.calls))
        for key in ['INSTALL_FAIL', 'COV_MAJOR', 'PROFDATA_MAJOR', 'BAD_VERSION',
                    'MISSING_LLVM', 'RUST_BAD']:
            self.env.pop(key, None)
        self.write('rustc', '#!/bin/bash\n[ "${RUST_BAD:-0}" = 0 ] || exit 3\necho "LLVM version: 22.1.2"\n')
        for tool, key in [('llvm-cov', 'COV_MAJOR'), ('llvm-profdata', 'PROFDATA_MAJOR')]:
            self.write(tool, f'#!/bin/bash\n[ "${{MISSING_LLVM:-0}}" = 0 ] || exit 4\necho "LLVM version ${{{key}:-22}}.1.2"\n')
        self.write('cargo', r'''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps(sys.argv[1:])+'\n')
if os.environ.get('INSTALL_FAIL')=='1':sys.exit(23)
a=sys.argv[1:];assert a[0:2]==['install','cargo-llvm-cov'];assert '--locked' in a
assert a[a.index('--version')+1]=='0.9.1'
p=Path(a[a.index('--root')+1])/'bin';p.mkdir()
(p/'cargo-llvm-cov').write_text('#!/bin/bash\n[ "$1" = llvm-cov ] && [ "$2" = --version ] || exit 90\necho "cargo-llvm-cov ${BAD_VERSION:-0.9.1}"\n')
(p/'cargo-llvm-cov').chmod(0o755)
''')

    def write(self, name, body):
        p = self.bin / name
        p.write_text(body)
        p.chmod(0o755)

    def run_setup(self, **env):
        return subprocess.run(['/bin/bash', str(SCRIPT)], env=dict(self.env, **env),
                              capture_output=True, text=True, timeout=10)

    def test_fresh_runner_installs_pinned_tool_and_exports_exact_paths(self):
        p = self.run_setup()
        self.assertEqual(p.returncode, 0, p.stderr)
        env = dict(x.split('=', 1) for x in self.env_file.read_text().splitlines())
        self.assertEqual(env['LLVM_COV'], str(self.bin / 'llvm-cov'))
        self.assertEqual(env['LLVM_PROFDATA'], str(self.bin / 'llvm-profdata'))
        self.assertTrue(Path(env['IRLUME_COVERAGE_BIN']).is_file())
        self.assertTrue(Path(env['IRLUME_COVERAGE_BIN']).is_relative_to(self.root))
        self.assertEqual(len(self.calls.read_text().splitlines()), 1)

    def test_inherited_tool_cannot_replace_job_local_pin(self):
        self.write('cargo-llvm-cov', '#!/bin/bash\nexit 99\n')
        self.assertEqual(self.run_setup().returncode, 0)
        self.assertNotIn(str(self.bin / 'cargo-llvm-cov'), self.env_file.read_text())

    def test_mismatched_llvm_fails_before_install(self):
        for key in ['COV_MAJOR', 'PROFDATA_MAJOR']:
            with self.subTest(key=key):
                p = self.run_setup(**{key: '21'})
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('LLVM', p.stderr)
                self.assertFalse(self.calls.exists())
                self.assertEqual(self.env_file.read_text(), '')

    def test_missing_llvm_and_invalid_rust_fail_before_install(self):
        for key in ['MISSING_LLVM', 'RUST_BAD']:
            with self.subTest(key=key):
                self.assertNotEqual(self.run_setup(**{key: '1'}).returncode, 0)
                self.assertFalse(self.calls.exists())

    def test_install_failure_does_not_publish_environment(self):
        p = self.run_setup(INSTALL_FAIL='1')
        self.assertEqual(p.returncode, 23)
        self.assertEqual(self.env_file.read_text(), '')

    def test_wrong_installed_version_fails(self):
        self.assertNotEqual(self.run_setup(BAD_VERSION='0.1.0').returncode, 0)
        self.assertEqual(self.env_file.read_text(), '')

    def test_workflow_uses_pinned_program_after_setup(self):
        workflow = (ROOT / '.github/workflows/hardware-suite.yml').read_text()
        coverage = workflow.split('\n  coverage:', 1)[1]
        self.assertLess(coverage.index('bash scripts/ci/setup-coverage-tools.sh'),
                        coverage.index('ffmpeg -loglevel'))
        self.assertNotIn('-- cargo llvm-cov', coverage)
        self.assertEqual(coverage.count('"$IRLUME_COVERAGE_BIN" llvm-cov'), 9)
        self.assertIn('--fail-under-lines 75', coverage)


if __name__ == '__main__':
    unittest.main()
