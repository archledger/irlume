#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Run the actual CI kernel bootstrap with fake commands, never host privileges."""
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
KERNEL = '7.0.0-1017-azure'
PIN = '0f9ee86760b7f2bea174b7e3e7a1d38845da0ab4'
# Each stub's shebang is written as sys.executable when the file is created:
# an absolute interpreter needs no PATH lookup, so the fake-only PATH below is
# safe on any host and no stub can resolve a real system command by accident.
STUB = r'''
import json, os, sys
from pathlib import Path
command = Path(sys.argv[0]).name
args = sys.argv[1:]
if command == 'sudo':
    assert args and args[0] in ('apt-get', 'modprobe', 'insmod', 'udevadm', 'chmod')
    command, args = args[0], args[1:]
with open(os.environ['CALLS'], 'a') as output:
    output.write(json.dumps([command, *args]) + '\n')
path = Path(os.environ['STATE'])
state = json.loads(path.read_text())
kernel = state['kernel']
if command == 'uname':
    assert args == ['-r']
    print(kernel)
elif command == 'nproc':
    print('2')
elif command == 'apt-get':
    assert args[:3] == ['install', '-y', '--no-install-recommends']
    if state['apt_failure']:
        sys.exit(23)
    for package in args[3:]:
        if package == 'linux-modules-extra-' + kernel:
            if not state['extra_available']:
                print('E: Unable to locate package ' + package, file=sys.stderr)
                sys.exit(100)
            state['module_present'] |= state['extra_supplies_video']
        elif package == 'linux-modules-' + kernel:
            if not state['core_available']:
                sys.exit(100)
            state['module_present'] |= state['core_supplies_video']
        else:
            assert package in ('linux-headers-' + kernel, 'ffmpeg'), package
elif command == 'modprobe':
    assert args == ['videodev']
    if not state['module_present'] or state['load_failure']:
        print('videodev is not loadable', file=sys.stderr)
        sys.exit(1)
    state['loaded'] = True
elif command == 'make':
    if state['make_failure']:
        sys.exit(24)
elif command == 'insmod':
    assert state['loaded'], 'loopback must not be loaded before videodev'
    if state['insmod_failure']:
        sys.exit(25)
elif command not in ('git', 'udevadm', 'chmod'):
    raise AssertionError('unmocked command: ' + command)
path.write_text(json.dumps(state))
'''


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='v4l-bootstrap-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for command in ('sudo', 'git', 'make', 'uname', 'nproc'):
            path = self.bin / command
            path.write_text(f'#!{sys.executable}\n{STUB.lstrip(chr(10))}')
            path.chmod(0o755)
        workflow = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
        self.job = workflow['jobs']['check']
        self.steps = self.job['steps']
        self.step = next(step for step in self.steps
                         if step.get('name') == 'Start virtual cameras (v4l2loopback + ffmpeg feeders)')
        parts = self.step['run'].split('\nnohup ffmpeg ', 1)
        self.assertEqual(len(parts), 2, 'keep the complete bootstrap before feeders')
        self.bootstrap = parts[0]
        for number in (8, 9, 10):
            self.bootstrap = self.bootstrap.replace(
                f'/dev/video{number}', shlex.quote(str(self.root / f'video{number}')))
        # PATH contains fakes only. Refuse absolute executables under any
        # standard system binary or library location that could evade it;
        # /dev, /tmp and module names above appear only as arguments.
        self.assertIsNone(
            re.search(r'/(?:usr/(?:local/)?)?(?:s?bin|lib(?:32|64)?|libexec)/', self.bootstrap))
        self.state_path = self.root / 'state.json'
        self.calls_path = self.root / 'calls.jsonl'

    def run_bootstrap(self, **changes):
        state = dict(kernel=KERNEL, module_present=True, loaded=False,
                     core_available=True, core_supplies_video=True,
                     extra_available=False, extra_supplies_video=True,
                     load_failure=False, apt_failure=False,
                     make_failure=False, insmod_failure=False)
        state.update(changes)
        self.state_path.write_text(json.dumps(state))
        return subprocess.run(
            ['/bin/bash', '-e', '-c', self.bootstrap],
            env={'PATH': str(self.bin), 'HOME': str(self.root),
                 'STATE': str(self.state_path), 'CALLS': str(self.calls_path)},
            capture_output=True, text=True, timeout=10)

    def calls(self):
        if not self.calls_path.exists():
            return []
        return [json.loads(line) for line in self.calls_path.read_text().splitlines()]

    def packages(self):
        return [package for command, *args in self.calls() if command == 'apt-get'
                for package in args[3:]]

    def assert_no_build(self):
        self.assertFalse(any(call[0] in ('git', 'make', 'insmod') for call in self.calls()))

    def test_loadable_module_needs_no_extra_package(self):
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('linux-modules-extra-' + KERNEL, self.packages())
        self.assertIn(['git', '-C', '/tmp/v4l2loopback', 'checkout', PIN], self.calls())
        self.assertIn(['insmod', '/tmp/v4l2loopback/v4l2loopback.ko',
                       'devices=3', 'video_nr=8,9,10', 'exclusive_caps=0'], self.calls())

    def test_current_kernel_core_package_can_supply_video_without_extra(self):
        result = self.run_bootstrap(module_present=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('linux-modules-' + KERNEL, self.packages())
        self.assertNotIn('linux-modules-extra-' + KERNEL, self.packages())

    def test_older_extra_package_layout_still_loads_the_module(self):
        result = self.run_bootstrap(module_present=False, core_supplies_video=False,
                                    extra_available=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('linux-modules-extra-' + KERNEL, self.packages())
        self.assertTrue(json.loads(self.state_path.read_text())['loaded'])

    def test_unavailable_packages_fail_before_build(self):
        result = self.run_bootstrap(module_present=False, core_supplies_video=False)
        self.assertEqual(result.returncode, 100, result.stderr)
        self.assert_no_build()

    def test_missing_core_package_fails_before_build(self):
        result = self.run_bootstrap(module_present=False, core_available=False)
        self.assertEqual(result.returncode, 100, result.stderr)
        self.assert_no_build()

    def test_load_failure_is_terminal_even_with_available_packages(self):
        result = self.run_bootstrap(load_failure=True, extra_available=True)
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_build()

    def test_dependency_install_failure_is_not_hidden(self):
        result = self.run_bootstrap(apt_failure=True)
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_no_build()

    def test_compiler_failure_stops_before_insmod(self):
        result = self.run_bootstrap(make_failure=True, extra_available=True)
        self.assertEqual(result.returncode, 24, result.stderr)
        self.assertFalse(any(call[0] == 'insmod' for call in self.calls()))

    def test_insmod_failure_is_not_hidden(self):
        result = self.run_bootstrap(insmod_failure=True, extra_available=True)
        self.assertEqual(result.returncode, 25, result.stderr)

    def test_existing_devices_preserve_the_provisioned_path(self):
        (self.root / 'video8').touch()
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_workflow_keeps_readiness_and_camera_test_gates(self):
        # Job-level escapes would skip the whole gate, not just one step.
        self.assertNotIn('continue-on-error', self.job)
        self.assertNotIn('if', self.job)
        self.assertNotIn('continue-on-error', self.step)
        self.assertNotIn('if', self.step)
        body = self.step['run']
        self.assertIn('timeout -k 1 5 ffmpeg', body)
        self.assertIn('if ! wait_for_frame "$d" 30; then', body)
        self.assertIn('sudo udevadm settle', body)
        camera = next(step for step in self.steps
                      if step.get('name') == 'test (camera + capture paths, against v4l2loopback)')
        self.assertNotIn('if', camera)
        self.assertNotIn('continue-on-error', camera)
        for floor in (19, 6, 5, 1):
            self.assertIn(f'run-tests-guarded.sh --min {floor} --', camera['run'])

    def test_workflow_runs_bootstrap_regressions_before_camera_setup(self):
        regressions = next((step for step in self.steps
                            if 'python3 -B scripts/ci/test-v4l2-bootstrap.py' in step.get('run', '')),
                           None)
        self.assertIsNotNone(regressions, 'run the hermetic regression suite in CI')
        self.assertLess(self.steps.index(regressions), self.steps.index(self.step))


if __name__ == '__main__':
    unittest.main()
