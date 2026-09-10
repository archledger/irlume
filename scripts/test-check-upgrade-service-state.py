#!/usr/bin/env python3
"""Offline behavior tests for the passive upgrade service-state checker."""
import copy
import contextlib
import io
import json
import tempfile
from unittest import mock
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    'state_check', Path(__file__).with_name('check-upgrade-service-state.py'))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def state(case, pid=101):
    enabled = 'masked' if case == 'masked-stopped' else case.split('-')[0]
    active = case.endswith('-running')
    return {unit: {'UnitFileState': enabled, 'LoadState': 'masked' if enabled == 'masked' else 'loaded',
                   'ActiveState': 'active' if active else 'inactive',
                   'SubState': ('running' if unit.endswith('service') else 'listening') if active else 'dead',
                   **({'MainPID': str(pid if active else 0)} if unit.endswith('service') else {})}
            for unit in CHECK.UNITS}


class StateChecks(unittest.TestCase):
    def test_all_declared_states_survive_upgrade(self):
        for case in CHECK.CASES:
            with self.subTest(case=case):
                CHECK.check_transition(state(case, 101), state(case, 202), case)

    def test_deliberately_stopped_socket_must_not_be_started(self):
        before = state('enabled-stopped'); after = copy.deepcopy(before)
        after['irlumed.socket'].update(ActiveState='active', SubState='listening')
        with self.assertRaisesRegex(CHECK.upgrade.Failure, 'socket-activity-changed'):
            CHECK.check_transition(before, after, 'enabled-stopped')

    def test_disabled_running_is_not_stopped(self):
        with self.assertRaises(CHECK.upgrade.Failure):
            CHECK.check_transition(state('disabled-running'), state('disabled-stopped'), 'disabled-running')

    def test_disabled_units_must_not_be_reenabled(self):
        for unit in CHECK.UNITS:
            after = state('disabled-stopped'); after[unit]['UnitFileState'] = 'enabled'
            with self.subTest(unit=unit), self.assertRaises(CHECK.upgrade.Failure):
                CHECK.check_transition(state('disabled-stopped'), after, 'disabled-stopped')

    def test_masks_must_not_be_removed(self):
        for unit in CHECK.UNITS:
            after = state('masked-stopped'); after[unit]['LoadState'] = 'loaded'
            with self.subTest(unit=unit), self.assertRaises(CHECK.upgrade.Failure):
                CHECK.check_transition(state('masked-stopped'), after, 'masked-stopped')

    def test_running_daemon_must_get_new_process(self):
        with self.assertRaisesRegex(CHECK.upgrade.Failure, 'daemon-not-restarted'):
            CHECK.check_transition(state('disabled-running'), state('disabled-running'), 'disabled-running')

    def test_invalid_baseline_is_rejected(self):
        with self.assertRaises(CHECK.upgrade.Failure):
            CHECK.check_transition(state('enabled-stopped'), state('disabled-stopped'), 'disabled-stopped')

    def test_failed_or_transitional_state_is_rejected(self):
        for active in ('failed', 'activating', 'deactivating'):
            after = state('disabled-stopped'); after['irlumed.service']['ActiveState'] = active
            with self.subTest(active=active), self.assertRaises(CHECK.upgrade.Failure):
                CHECK.check_transition(state('disabled-stopped'), after, 'disabled-stopped')

    def test_inactive_service_must_have_no_process(self):
        after = state('disabled-stopped'); after['irlumed.service']['MainPID'] = '44'
        with self.assertRaises(CHECK.upgrade.Failure):
            CHECK.check_transition(state('disabled-stopped'), after, 'disabled-stopped')

    def test_missing_properties_fail_closed(self):
        after = state('disabled-stopped'); del after['irlumed.service']['UnitFileState']
        with self.assertRaises(CHECK.upgrade.Failure):
            CHECK.check_transition(state('disabled-stopped'), after, 'disabled-stopped')

    def test_observation_is_passive(self):
        class Runner:
            def __init__(self): self.calls = []
            def command(self, argv):
                self.calls.append(argv)
                return '\n'.join(k+'='+v for k,v in state('enabled-stopped')[argv[2]].items())
        runner = Runner()
        self.assertEqual(CHECK.observe(runner), state('enabled-stopped'))
        self.assertEqual([call[:3] for call in runner.calls],
                         [['systemctl','show',unit] for unit in CHECK.UNITS])


class CliChecks(unittest.TestCase):
    def run_cli(self, directory, case='enabled-stopped', before=None, observed=None):
        output = Path(directory) / 'after.json'
        args = ['--case', case, '--output', str(output)]
        if before is not None:
            baseline = Path(directory) / 'before.json'
            baseline.write_text(json.dumps(before))
            args.extend(['--before', str(baseline)])
        with mock.patch.object(CHECK.upgrade, 'admit_guest'), \
                mock.patch.object(CHECK, 'observe', return_value=observed or state(case)), \
                contextlib.redirect_stdout(io.StringIO()):
            status = CHECK.main(args)
        return status, output

    def test_real_host_refused_before_any_output_write(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'receipt.json'
            with mock.patch.object(CHECK.upgrade, 'admit_guest',
                                   side_effect=CHECK.upgrade.Failure('qemu-kvm-required')), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(CHECK.main(['--case', 'enabled-stopped', '--output', str(output)]), 1)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_baseline_and_after_receipts_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            before = {'schema': 1, 'case': 'enabled-stopped', 'passed': True,
                      'units': state('enabled-stopped')}
            status, output = self.run_cli(directory, before=before)
            self.assertEqual(status, 0)
            self.assertTrue(json.loads(output.read_text())['passed'])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_failed_receipt_keeps_observed_state(self):
        with tempfile.TemporaryDirectory() as directory:
            changed = state('enabled-stopped')
            changed['irlumed.socket'].update(ActiveState='active', SubState='listening')
            status, output = self.run_cli(directory, observed=changed)
            self.assertEqual(status, 1)
            receipt = json.loads(output.read_text())
            self.assertFalse(receipt['passed'])
            self.assertEqual(receipt['units'], changed)

    def test_failed_baseline_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            status, output = self.run_cli(directory, before={'schema': 1, 'passed': False})
            self.assertEqual(status, 1)
            self.assertFalse(output.exists())

    def test_malformed_baseline_substate_reports_fixed_error_without_output(self):
        for case in ('enabled-stopped', 'disabled-running'):
            for unit in CHECK.UNITS:
                for substate in ([], {}, None, 0, True, 1.5):
                    with self.subTest(case=case, unit=unit, substate=substate), \
                            tempfile.TemporaryDirectory() as directory:
                        baseline = Path(directory) / 'before.json'
                        before = {'schema': 1, 'case': case, 'passed': True,
                                  'units': state(case)}
                        before['units'][unit]['SubState'] = substate
                        baseline.write_text(json.dumps(before))
                        output = Path(directory) / 'after.json'
                        stdout = io.StringIO()
                        with mock.patch.object(CHECK.upgrade, 'admit_guest'), \
                                mock.patch.object(CHECK, 'observe', side_effect=AssertionError(
                                    'invalid baseline must be rejected before observation')), \
                                contextlib.redirect_stdout(stdout):
                            status = CHECK.main(['--case', case, '--before', str(baseline),
                                                 '--output', str(output)])
                        self.assertEqual(status, 1)
                        self.assertEqual(json.loads(stdout.getvalue()),
                                         {'passed': False, 'error': 'invalid-unit-properties'})
                        self.assertEqual(list(Path(directory).iterdir()), [baseline])

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'after.json'
            output.write_text('original')
            status, _ = self.run_cli(directory)
            self.assertEqual(status, 1)
            self.assertEqual(output.read_text(), 'original')


if __name__ == '__main__':
    unittest.main()
