#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Execute the nightly CLI coverage guard against synthetic test results."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = [
    'loopback_capture_runs_detection_and_reports_no_face',
    'loopback_liveness_probe_gates_a_faceless_feed_as_not_live',
    'loopback_calcapture_writes_header_and_faceless_samples',
    'loopback_padcapture_ir_only_records_faceless_attack_presentations',
    'loopback_genuine_declines_stats_without_two_face_frames',
    'loopback_suncal_analyzes_a_faceless_burst_dataset',
]


def capture_guard():
    workflow = (ROOT / '.github/workflows/hardware-suite.yml').read_text()
    joined = workflow.replace('\\\n', ' ')
    commands = [line.strip() for line in joined.splitlines()
                if '--test cli_capture ' in line]
    assert len(commands) == 1
    return commands[0]


class CaptureContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='nightly coverage contract ')
        self.addCleanup(self.tmp.cleanup)
        self.bin = Path(self.tmp.name) / 'coverage fixture'
        self.bin.write_text(r'''#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:]
assert args[0]=='llvm-cov' and args[args.index('--test')+1]=='cli_capture'
assert '--ignored' in args and 'loopback_' in args and '--test-threads=1' in args
names=json.loads(os.environ['FIXTURE_NAMES'])
for name in names:print('test '+name+' ... ok')
print(f'test result: ok. {len(names)} passed; 0 failed; 0 ignored')
sys.exit(int(os.environ['FIXTURE_EXIT']))
''')
        self.bin.chmod(0o755)

    def run_guard(self, names, exit_code=0):
        return subprocess.run(['bash', '-e', '-c', capture_guard()], cwd=ROOT,
                              env=dict(os.environ, IRLUME_COVERAGE_BIN=str(self.bin),
                                       FIXTURE_NAMES=json.dumps(names),
                                       FIXTURE_EXIT=str(exit_code)),
                              capture_output=True, text=True, timeout=10)

    def test_all_supported_scenarios_pass(self):
        result = self.run_guard(REQUIRED)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_missing_scenario_fails_even_with_seven_passing_tests(self):
        for missing in REQUIRED:
            with self.subTest(missing=missing):
                names = [n for n in REQUIRED if n != missing]
                names += ['loopback_unrelated_one', 'loopback_unrelated_two']
                result = self.run_guard(names)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(missing, result.stderr)

    def test_zero_selection_fails(self):
        self.assertNotEqual(self.run_guard([]).returncode, 0)

    def test_failed_command_cannot_pass_from_success_output(self):
        self.assertEqual(self.run_guard(REQUIRED, exit_code=23).returncode, 23)


if __name__ == '__main__':
    unittest.main()
