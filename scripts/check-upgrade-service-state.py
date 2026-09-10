#!/usr/bin/env python3
"""Passively check daemon/socket state around a disposable-guest package upgrade.

Run before the transaction with --case and --output, then after it with the
same --case, --before pointing at that receipt, and a new --output. This checker
never starts units or connects to the product socket. The operator sets the
intended state and runs the package transaction separately. Raw command output
stays in the receipt's private .log sibling; export JSON only.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location(
    'package_upgrade', Path(__file__).with_name('test-package-upgrade.py'))
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)
UNITS = ('irlumed.service', 'irlumed.socket')
CASES = ('disabled-running', 'disabled-stopped', 'enabled-stopped', 'masked-stopped')
PROPERTIES = ('LoadState', 'UnitFileState', 'ActiveState', 'SubState', 'MainPID')


def observe(runner):
    result = {}
    for unit in UNITS:
        argv = ['systemctl', 'show', unit]
        for name in PROPERTIES:
            argv.extend(('-p', name))
        fields = {}
        for line in runner.command(argv).splitlines():
            name, sep, value = line.partition('=')
            upgrade.require(sep and name in PROPERTIES and name not in fields,
                            'invalid-unit-properties')
            fields[name] = value
        result[unit] = fields
    return result


def check_state(units, case):
    upgrade.require(case in CASES and isinstance(units, dict), 'invalid-state-case')
    enabled = 'masked' if case == 'masked-stopped' else case.split('-')[0]
    active = case.endswith('-running')
    for unit in UNITS:
        row = units.get(unit, {})
        upgrade.require(isinstance(row, dict), 'invalid-unit-properties')
        short = 'daemon' if unit.endswith('.service') else 'socket'
        upgrade.require(row.get('UnitFileState') == enabled, short + '-enablement-changed')
        upgrade.require(row.get('LoadState') == ('masked' if enabled == 'masked' else 'loaded'),
                        short + '-load-state-changed')
        upgrade.require(row.get('ActiveState') == ('active' if active else 'inactive'),
                        short + '-activity-changed')
        substate = row.get('SubState')
        upgrade.require(isinstance(substate, str), 'invalid-unit-properties')
        allowed = {'running'} if short == 'daemon' else {'running', 'listening'}
        upgrade.require(substate in (allowed if active else {'dead'}),
                        short + '-substate-changed')
        if short == 'daemon':
            value = row.get('MainPID', '')
            upgrade.require(isinstance(value, str) and value.isascii() and value.isdigit(),
                            'invalid-daemon-pid')
            upgrade.require((int(value) > 0) if active else (int(value) == 0), 'daemon-pid-state')


def check_transition(before, after, case):
    check_state(before, case)
    check_state(after, case)
    if case.endswith('-running'):
        upgrade.require(before['irlumed.service']['MainPID'] != after['irlumed.service']['MainPID'],
                        'daemon-not-restarted')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--before', help='Successful pre-transaction JSON receipt')
    parser.add_argument('--output', required=True, help='New JSON receipt in an existing directory')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        upgrade.admit_guest()
        before = None
        if args.before:
            path = Path(args.before)
            upgrade.no_symlinks(path)
            before = json.loads(path.read_text())
            upgrade.require(isinstance(before, dict) and before.get('schema') == 1
                            and before.get('case') == args.case and before.get('passed') is True,
                            'invalid-baseline-receipt')
            check_state(before.get('units'), args.case)
        output = Path(args.output)
        log_path = output.with_name(output.name + '.log')
        for path in (output, log_path):
            upgrade.no_symlinks(path)
            upgrade.require(path.parent.is_dir() and not path.exists(), 'new-output-required')
    except (upgrade.Failure, OSError, ValueError) as error:
        print(json.dumps({'passed': False, 'error': str(error) if isinstance(error, upgrade.Failure)
                          else 'preflight-read-failed'}))
        return 1
    result = {'schema': 1, 'case': args.case, 'passed': False}
    with output.open('x') as receipt, log_path.open('xb') as log:
        try:
            result['units'] = observe(upgrade.Runner(log))
            check_state(result['units'], args.case)
            if before is not None:
                check_transition(before['units'], result['units'], args.case)
            result['passed'] = True
        except (upgrade.Failure, OSError) as error:
            result['error'] = str(error) if isinstance(error, upgrade.Failure) else 'observation-failed'
        json.dump(result, receipt, indent=2)
        receipt.write('\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
