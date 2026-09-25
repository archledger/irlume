#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Run the CI health alert against fixtures: a fake `gh`, no network.

The end-to-end cases execute the `run:` step of .github/workflows/ci-alert.yml
exactly as written, with its env, against the repository's real workflow files.
"""
from datetime import datetime, timedelta
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/ci-alert.yml'
REPO = 'archledger/irlume'
RUNS = f'https://github.com/{REPO}/actions/runs/'
SELF_REF = f'{REPO}/.github/workflows/ci-alert.yml@refs/heads/main'
# The check ran at this time on 2026-09-24, the tenth day audit.yml was red.
NOW = '2026-09-24T14:11:24Z'


SPEC = importlib.util.spec_from_file_location('ci_alert', Path(__file__).with_name('ci-alert.py'))
ALERT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ALERT)


def iso(when):
    return when.strftime('%Y-%m-%dT%H:%M:%SZ')


def at(text):
    return datetime.fromisoformat(text.replace('Z', '+00:00'))


def unquote(value):
    value = re.sub(r'\s+#.*$', '', value.strip())
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        return value[1:-1]
    return value


def env_block(lines, start, indent):
    """KEY: value pairs indented deeper than `indent`, from lines[start:]."""
    found = {}
    for line in lines[start:]:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if len(line) - len(line.lstrip()) <= indent:
            break
        match = re.match(r'\s*([A-Z_][A-Z0-9_]*):\s*(.*)$', line)
        if match:
            found[match.group(1)] = unquote(match.group(2))
    return found


def depth(line):
    return len(line) - len(line.lstrip(' '))


def content(line):
    return bool(line.strip()) and not line.lstrip().startswith('#')


def alert_step(text=None):
    """The workflow's single `run:` step: its script and its env.

    The env merges the workflow, job and step `env:` mappings in that order,
    as Actions does.
    """
    lines = (WORKFLOW.read_text() if text is None else text).splitlines()
    runs = [i for i, line in enumerate(lines) if re.match(r'\s*(- )?run:', line)]
    assert len(runs) == 1, 'ci-alert.yml should have exactly one run step'
    run = runs[0]
    indent = len(lines[run]) - len(lines[run].lstrip(' -'))
    value = lines[run].split('run:', 1)[1].strip()
    if value in ('|', '|-'):
        body = []
        for line in lines[run + 1:]:
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            body.append(line)
        cut = min(len(line) - len(line.lstrip()) for line in body if line.strip())
        script = '\n'.join(line[cut:] for line in body) + '\n'
    else:
        script = unquote(value) + '\n'
    # The mappings that contain the run: key, innermost first, each with the
    # indent of its own keys: the step, steps, the job, jobs, the document.
    chain, level = [], depth(lines[run])
    for i in range(run - 1, -1, -1):
        if content(lines[i]) and depth(lines[i]) < level:
            chain.append((i, level))
            level = depth(lines[i])
    chain.append((-1, 0))
    env = {}
    for start, level in reversed(chain):
        end = next((j for j in range(start + 1, len(lines)) if start >= 0 and content(lines[j])
                    and depth(lines[j]) <= depth(lines[start])), len(lines))
        for i in range(start + 1, end):
            if lines[i].strip() == 'env:' and depth(lines[i]) == level:
                env.update(env_block(lines, i + 1, level))
    return script, env


FAKE_GH = r'''
import json, os, subprocess, sys

STATE, LOG = os.environ['FAKE_GH_STATE'], os.environ['FAKE_GH_LOG']
state = json.load(open(STATE))
args = sys.argv[1:]
words, flags, i = [], {}, 0
while i < len(args):
    if args[i] in ('--paginate', '--all'):
        flags[args[i][2:]] = True
        i += 1
    elif args[i].startswith('--'):
        flags[args[i][2:]] = args[i + 1]
        i += 2
    else:
        words.append(args[i])
        i += 1


def log(entry):
    with open(LOG, 'a') as handle:
        handle.write(json.dumps(entry) + '\n')


def save():
    json.dump(state, open(STATE, 'w'))


def emit(data):
    text = json.dumps(data)
    if 'jq' in flags:
        text = subprocess.run(['jq', '-rc', flags['jq']], input=text, text=True,
                              check=True, capture_output=True).stdout
        sys.stdout.write(text)
    else:
        print(text)


def pick(item):
    return {k: item.get(k) for k in flags['json'].split(',')}


def issue(number):
    return next(x for x in state['issues'] if x['number'] == int(number))


STATUSES = {'queued', 'in_progress', 'completed', 'requested', 'waiting', 'pending'}
if words[:2] == ['run', 'list']:
    assert flags['repo'] == 'archledger/irlume'
    listed = {w['path'].rsplit('/', 1)[-1]: w for w in state['workflows']}
    if listed.get(flags['workflow'], {}).get('state', 'active') != 'active' and 'all' not in flags:
        sys.exit(f"could not find any workflows named {flags['workflow']}")
    runs = [r for r in state['runs'].get(flags['workflow'], [])
            if r.get('headBranch', 'main') == flags.get('branch', r.get('headBranch', 'main'))]
    status = flags.get('status')
    if status in STATUSES:
        runs = [r for r in runs if r['status'] == status]
    elif status:
        runs = [r for r in runs if r.get('conclusion') == status]
    runs.sort(key=lambda r: r['createdAt'], reverse=True)
    emit([pick(r) for r in runs[:int(flags.get('limit', 20))]])
elif words[:2] == ['issue', 'list']:
    found = [x for x in state['issues'] if flags['label'] in x['labels']
             and x['state'] == flags.get('state', 'open').upper()]
    emit([pick(x) for x in found[:int(flags.get('limit', 30))]])
elif words[:2] == ['issue', 'view']:
    emit(pick(issue(words[2])))
elif words[:2] == ['issue', 'create']:
    number = max([x['number'] for x in state['issues']] + [900]) + 1
    state['issues'].append({'number': number, 'title': flags['title'], 'body': flags['body'],
                            'labels': [flags['label']], 'state': 'OPEN', 'comments': []})
    save()
    log({'op': 'create', 'number': number, 'title': flags['title'], 'body': flags['body']})
    print(f'https://github.com/archledger/irlume/issues/{number}')
elif words[:2] == ['issue', 'comment']:
    issue(words[2])['comments'].append({'body': flags['body']})
    save()
    log({'op': 'comment', 'number': int(words[2]), 'body': flags['body']})
elif words[:2] == ['issue', 'close']:
    item = issue(words[2])
    item['state'] = 'CLOSED'
    save()
    log({'op': 'close', 'number': int(words[2]), 'body': flags.get('comment', ''),
         'reason': flags.get('reason')})
elif words[:2] == ['label', 'create']:
    log({'op': 'label', 'name': words[2]})
elif words[:1] == ['api'] and words[1] == f"repos/{state['repo']}/actions/workflows":
    emit({'total_count': len(state['workflows']), 'workflows': state['workflows']})
else:
    sys.exit('fake gh: unsupported call: ' + ' '.join(args))
'''


def run(number, conclusion='success', created=None, status='completed', event='schedule'):
    return {'databaseId': number, 'status': status, 'event': event,
            'conclusion': conclusion if status == 'completed' else None,
            'createdAt': created, 'url': f'{RUNS}{number}'}


def audit_incident():
    """audit.yml on main as it was: green to 09-14, red every day 09-15 to 09-24."""
    return [
        run(34685953488, 'success', '2026-09-12T09:28:45Z'),
        run(34751801271, 'success', '2026-09-13T10:25:12Z'),
        run(34835144834, 'success', '2026-09-14T10:50:15Z'),
        run(34956905679, 'failure', '2026-09-15T10:14:41Z'),
        run(35083303139, 'failure', '2026-09-16T10:07:57Z'),
        run(35209174202, 'failure', '2026-09-17T10:11:31Z'),
        run(35332126223, 'failure', '2026-09-18T09:56:21Z'),
        run(35435257266, 'failure', '2026-09-19T09:38:36Z'),
        run(35503582080, 'failure', '2026-09-20T09:54:20Z'),
        run(35591208246, 'failure', '2026-09-21T10:54:20Z'),
        run(35714381159, 'failure', '2026-09-22T10:08:57Z'),
        run(35847270299, 'failure', '2026-09-23T10:10:40Z'),
        run(35986337791, 'failure', '2026-09-24T10:17:18Z'),
    ]


def healthy_state(now=NOW):
    """Every workflow file in the repository last succeeded on main 6 h ago."""
    created = iso(at(now) - timedelta(hours=6))
    runs, workflows = {}, []
    for number, path in enumerate(sorted((ROOT / '.github/workflows').glob('*.y*ml'))):
        runs[path.name] = [run(40000000000 + number, 'success', created)]
        workflows.append({'path': f'.github/workflows/{path.name}', 'state': 'active',
                          'created_at': '2026-07-20T08:41:16.000-04:00'})
    return {'repo': REPO, 'runs': runs, 'issues': [], 'workflows': workflows}


class StepTests(unittest.TestCase):
    """Execute the workflow step with a fake gh on PATH."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ci alert ')
        self.addCleanup(self.tmp.cleanup)
        tmp = Path(self.tmp.name)
        (tmp / 'bin').mkdir()
        gh = tmp / 'bin/gh'
        gh.write_text(f'#!{sys.executable}\n' + FAKE_GH)
        gh.chmod(0o755)
        self.bin, self.state_file, self.log_file = tmp / 'bin', tmp / 'state.json', tmp / 'log'

    def run_step(self, state, mode='check', now=NOW, argv=None):
        """Run the step, or `argv` in its place, with the step's env."""
        self.state_file.write_text(json.dumps(state))
        self.log_file.write_text('')
        script, env = alert_step()
        expressions = {'${{ github.token }}': 'fixture-token',
                       '${{ github.repository }}': REPO,
                       "${{ inputs.mode || 'check' }}": mode}
        for key, value in env.items():
            if '${{' in value:
                self.assertIn(value, expressions, f'no fixture value for {key}')
                env[key] = expressions[value]
        env.update(PATH=f'{self.bin}:{os.environ["PATH"]}', HOME=self.tmp.name,
                   FAKE_GH_STATE=str(self.state_file), FAKE_GH_LOG=str(self.log_file),
                   GITHUB_WORKFLOW_REF=SELF_REF, CI_ALERT_NOW=now, LANG='C.UTF-8')
        command = argv or ['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script]
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True,
                                timeout=60)
        self.output = result.stdout + result.stderr
        self.log = [json.loads(line) for line in self.log_file.read_text().splitlines()]
        return result

    def ops(self, op):
        return [entry for entry in self.log if entry['op'] == op]

    def check(self, state, **kwargs):
        result = self.run_step(state, **kwargs)
        self.assertEqual(result.returncode, 0, self.output)
        return result

    def test_audit_failing_since_09_15_opens_an_issue_naming_it(self):
        state = healthy_state()
        state['runs']['audit.yml'] = audit_incident()
        self.check(state)
        created = self.ops('create')
        self.assertEqual([c['title'] for c in created],
                         ['CI health: audit.yml failing or stale'], self.output)
        body = created[0]['body']
        self.assertIn(f'{RUNS}35986337791', body)
        self.assertIn('concluded failure', body)
        self.assertIn(f'{RUNS}34835144834', body)
        self.assertIn('last succeeded 2026-09-14T10:50:15Z', body)
        self.assertEqual(self.ops('comment') + self.ops('close'), [], self.output)

    def test_healthy_repository_changes_nothing(self):
        self.check(healthy_state())
        self.assertEqual(self.log, [], self.output)
        self.assertIn('alert=0', self.output)

    def test_every_scheduled_workflow_is_judged_except_the_alert_itself(self):
        self.check(healthy_state())
        for name in ALERT.scheduled_workflows(ROOT / '.github/workflows', exclude='ci-alert.yml'):
            self.assertIn(f'{name} healthy', self.output)
        self.assertNotIn('ci-alert.yml healthy', self.output)
        self.assertNotIn('ci.yml healthy', self.output)

    def test_each_failing_workflow_gets_its_own_issue(self):
        state = healthy_state()
        state['runs']['audit.yml'] = audit_incident()
        state['runs']['hardware-suite.yml'] = [run(1, 'success', '2026-09-23T00:10:00Z'),
                                               run(2, 'failure', '2026-09-24T00:15:46Z')]
        state['issues'].append({'number': 950, 'title': 'CI health: audit.yml failing or stale',
                                'labels': ['ci-alert'], 'state': 'OPEN', 'body': '',
                                'comments': [{'body': 'Automated check 2026-09-23T14:13:24Z:'}]})
        self.check(state)
        self.assertEqual([c['title'] for c in self.ops('create')],
                         ['CI health: hardware-suite.yml failing or stale'])
        self.assertEqual([c['number'] for c in self.ops('comment')], [950])
        self.assertNotIn('audit.yml', self.ops('create')[0]['body'])

    def test_an_open_issue_gets_at_most_one_comment_a_day(self):
        state = healthy_state()
        state['runs']['audit.yml'] = audit_incident()
        state['issues'].append({'number': 950, 'title': 'CI health: audit.yml failing or stale',
                                'labels': ['ci-alert'], 'state': 'OPEN', 'body': '',
                                'comments': [{'body': 'Automated check 2026-09-24T09:00:00Z:'}]})
        self.check(state)
        self.assertEqual(self.log, [], self.output)

    def test_recovery_closes_the_workflow_issue(self):
        # The fixed audit.yml ran green by hand before the next daily check.
        later = '2026-09-25T09:15:00Z'
        state = healthy_state(later)
        state['runs']['audit.yml'] = audit_incident() + [
            run(36081858019, 'success', '2026-09-25T01:24:18Z', event='workflow_dispatch')]
        state['issues'].append({'number': 950, 'title': 'CI health: audit.yml failing or stale',
                                'labels': ['ci-alert'], 'state': 'OPEN', 'body': '',
                                'comments': []})
        self.check(state, now=later)
        self.assertEqual([c['number'] for c in self.ops('close')], [950])
        self.assertIn(f'No longer alerting as of {later}', self.ops('close')[0]['body'])
        self.assertIn('last success 2026-09-25T01:24:18Z', self.ops('close')[0]['body'])
        self.assertEqual(self.ops('create'), [])

    def test_the_shared_issue_is_closed_in_favor_of_per_workflow_issues(self):
        state = healthy_state()
        state['runs']['audit.yml'] = audit_incident()
        state['issues'].append({'number': 792, 'title': 'CI health: watched workflow failing or stale',
                                'labels': ['ci-alert'], 'state': 'OPEN', 'body': '', 'comments': []})
        state['issues'].append({'number': 800, 'title': 'Unrelated tracking issue',
                                'labels': ['ci-alert'], 'state': 'OPEN', 'body': '', 'comments': []})
        self.check(state)
        self.assertEqual([c['number'] for c in self.ops('close')], [792])
        self.assertIn('CI health: audit.yml failing or stale', self.ops('close')[0]['body'])
        self.assertEqual(len(self.ops('create')), 1)

    def test_a_runner_that_stays_offline_alerts_on_the_stale_success(self):
        # One concurrency group: the run waiting behind a queued one is
        # cancelled and replaced every night, so the newest run is always young.
        state = healthy_state()
        state['runs']['hardware-suite.yml'] = [
            run(1, 'success', '2026-09-21T00:10:00Z'),
            run(2, None, '2026-09-22T00:12:00Z', status='queued'),
            run(3, 'cancelled', '2026-09-23T00:11:00Z'),
            run(4, None, '2026-09-24T00:15:00Z', status='pending'),
        ]
        self.check(state)
        created = self.ops('create')
        self.assertEqual([c['title'] for c in created],
                         ['CI health: hardware-suite.yml failing or stale'], self.output)
        self.assertIn('last succeeded 2026-09-21T00:10:00Z', created[0]['body'])
        self.assertIn('over the 48 h limit', created[0]['body'])

    def test_a_superseded_run_is_not_a_failure(self):
        state = healthy_state()
        state['runs']['asan.yml'] += [run(9, 'cancelled', '2026-09-24T13:00:00Z', event='push'),
                                      run(10, None, '2026-09-24T13:05:00Z', 'in_progress', 'push')]
        self.check(state)
        self.assertEqual(self.log, [], self.output)

    def test_a_cancelled_run_that_nothing_replaced_alerts(self):
        # A job over its timeout-minutes, or cancelled by hand: no newer run
        # will give the verdict this one did not.
        state = healthy_state()
        state['runs']['install-matrix.yml'].append(run(11, 'cancelled', '2026-09-24T13:00:00Z'))
        self.check(state)
        created = self.ops('create')
        self.assertEqual([c['title'] for c in created],
                         ['CI health: install-matrix.yml failing or stale'], self.output)
        self.assertIn('run 11 (schedule) concluded cancelled', created[0]['body'])

    def test_pull_request_runs_from_a_branch_named_main_are_not_main_runs(self):
        # gh run list --branch main matches the head branch, so a pull request
        # from a fork's main branch is listed with the runs on main.
        state = healthy_state()
        state['runs']['codeql.yml'].append(
            run(12, 'failure', '2026-09-24T13:00:00Z', event='pull_request'))
        self.check(state)
        self.assertEqual(self.log, [], self.output)
        state['runs']['codeql.yml'] = [
            run(13, 'success', '2026-09-12T00:20:00Z'),
            run(14, 'success', '2026-09-24T13:00:00Z', event='pull_request')]
        self.check(state)
        created = self.ops('create')
        self.assertEqual([c['title'] for c in created],
                         ['CI health: codeql.yml failing or stale'], self.output)
        self.assertIn('last succeeded 2026-09-12T00:20:00Z', created[0]['body'])
        self.assertIn('over the 8 d limit', created[0]['body'])

    def test_many_pull_request_runs_cannot_hide_the_runs_on_main(self):
        # gh applies --limit before the pull request runs are dropped, so a
        # burst of them from a fork's main branch must not fill the page.
        state = healthy_state()
        state['runs']['codeql.yml'] += [
            run(2000 + n, 'success', f'2026-09-24T{10 + n // 60:02d}:{n % 60:02d}:00Z',
                event='pull_request')
            for n in range(40)]
        self.check(state)
        self.assertEqual(self.log, [], self.output)

    def test_finding_no_scheduled_workflow_is_an_error_that_changes_no_issue(self):
        state = healthy_state()
        state['issues'].append({'number': 950, 'title': 'CI health: audit.yml failing or stale',
                                'labels': ['ci-alert'], 'state': 'OPEN', 'body': '',
                                'comments': []})
        tmp = Path(self.tmp.name)
        (tmp / 'empty').mkdir()
        (tmp / 'unscheduled').mkdir()
        for name in ['ci.yml', 'dco.yml', 'ci-alert.yml']:
            (tmp / 'unscheduled' / name).write_text(
                (ROOT / '.github/workflows' / name).read_text())
        script = str(ROOT / 'scripts/ci/ci-alert.py')
        for directory in ['missing', 'empty', 'unscheduled']:
            for mode in ['check', 'dry']:
                with self.subTest(directory=directory, mode=mode):
                    result = self.run_step(state, argv=[
                        sys.executable, script, '--repo', REPO, '--mode', mode,
                        '--workflows', str(tmp / directory)])
                    self.assertEqual(result.returncode, 2, self.output)
                    self.assertIn('no scheduled workflow found', self.output)
                    self.assertNotIn('alert=', self.output)
                    self.assertEqual(self.log, [], self.output)

    def test_a_duplicate_issue_is_closed_in_favor_of_the_oldest(self):
        state = healthy_state()
        state['runs']['audit.yml'] = audit_incident()
        for number in (951, 950):
            state['issues'].append({'number': number,
                                    'title': 'CI health: audit.yml failing or stale',
                                    'labels': ['ci-alert'], 'state': 'OPEN', 'body': '',
                                    'comments': []})
        self.check(state)
        self.assertEqual([c['number'] for c in self.ops('comment')], [950], self.output)
        self.assertEqual([(c['number'], c['reason']) for c in self.ops('close')],
                         [(951, 'not planned')], self.output)
        self.assertIn('duplicate of #950', self.ops('close')[0]['body'])
        self.assertEqual(self.ops('create'), [])

    def test_a_monthly_workflow_is_stale_after_32_days(self):
        state = healthy_state()
        state['runs']['update-flake-lock.yml'] = [run(7, 'success', '2026-08-24T06:30:00Z')]
        self.check(state)
        self.assertEqual(self.log, [], self.output)
        state['runs']['update-flake-lock.yml'] = [run(7, 'success', '2026-08-23T06:30:00Z')]
        self.check(state)
        self.assertEqual([c['title'] for c in self.ops('create')],
                         ['CI health: update-flake-lock.yml failing or stale'])
        self.assertIn('over the 32 d limit', self.ops('create')[0]['body'])

    def test_no_successful_run_alerts_unless_the_workflow_is_new(self):
        state = healthy_state()
        state['runs']['install-matrix.yml'] = []
        self.check(state)
        self.assertEqual([c['title'] for c in self.ops('create')],
                         ['CI health: install-matrix.yml failing or stale'])
        self.assertIn('no successful run on main', self.ops('create')[0]['body'])
        for workflow in state['workflows']:
            if workflow['path'].endswith('/install-matrix.yml'):
                workflow['created_at'] = '2026-09-20T12:00:00.000-04:00'
        self.check(state)
        self.assertEqual(self.log, [], self.output)

    def test_disabled_workflows(self):
        state = healthy_state()
        state['runs']['codeql.yml'] = [run(8, 'success', '2026-07-01T00:00:00Z')]
        for workflow in state['workflows']:
            if workflow['path'].endswith('/codeql.yml'):
                workflow['state'] = 'disabled_manually'
        self.check(state)
        self.assertEqual(self.log, [], self.output)
        self.assertIn('codeql.yml is disabled manually', self.output)
        for workflow in state['workflows']:
            if workflow['path'].endswith('/codeql.yml'):
                workflow['state'] = 'disabled_inactivity'
        self.check(state)
        self.assertEqual([c['title'] for c in self.ops('create')],
                         ['CI health: codeql.yml failing or stale'])
        self.assertIn('disabled_inactivity', self.ops('create')[0]['body'])

    def test_dry_mode_changes_nothing_and_exits_1_on_alert(self):
        state = healthy_state()
        state['runs']['audit.yml'] = audit_incident()
        result = self.run_step(state, mode='dry')
        self.assertEqual(result.returncode, 1, self.output)
        self.assertEqual(self.log, [])
        self.assertIn('audit.yml run 35986337791', self.output)
        self.assertEqual(self.run_step(healthy_state(), mode='dry').returncode, 0, self.output)


class ScheduleTests(unittest.TestCase):
    """Schedules are read from the workflow files, and each sets its own limit."""

    def test_stale_limit_is_the_longest_gap_plus_a_day(self):
        cases = {
            ('0 22 * * *',): timedelta(hours=48),
            ('45 6 * * 1',): timedelta(days=8),
            ('15 6 1 * *',): timedelta(days=32),
            ('*/15 * * * *',): timedelta(days=1, minutes=15),
            ('0 0 * * 1-5',): timedelta(days=4),
            ('0 6 * * 1', '0 6 * * 4'): timedelta(days=5),
            ('0 0 1 * 1',): timedelta(days=8),
            ('0 0 * * 0',): timedelta(days=8),
            ('0 0 * * 7',): timedelta(days=8),
            ('0 0 1,15 * *',): timedelta(days=18),
        }
        for crons, limit in cases.items():
            with self.subTest(crons=crons):
                self.assertEqual(ALERT.stale_after(crons), limit)

    def test_bad_cron_is_rejected(self):
        for cron in ['0 22 * *', '60 * * * *', '0 0 * JAN *', '0 0 30 2 *', '* * * * * *', '1-0 * * * *']:
            with self.subTest(cron=cron), self.assertRaises(ValueError):
                ALERT.stale_after([cron])

    def test_reads_block_style_schedules_only(self):
        read = ALERT.schedule_crons
        self.assertEqual(read('on:\n  push:\n  schedule:\n    - cron: "0 1 * * *" # x\n'
                              "    - cron: '5 1 * * *'\n# note\n  workflow_dispatch:\njobs: {}\n"),
                         ['0 1 * * *', '5 1 * * *'])
        self.assertEqual(read('"on": [push, pull_request]\n'), [])
        self.assertEqual(read('on:\n  push:\n    branches: [main]\njobs: {}\n'), [])
        for text in ['on: {schedule: [{cron: "0 1 * * *"}]}\n',
                     'on:\n  schedule: [{cron: "0 1 * * *"}]\n',
                     'on:\n  schedule:\n    - cron: "0 1 * * *"\n      timezone: x\n',
                     'on:\n  schedule:\n',
                     'on:\n  "schedule": [{cron: "0 1 * * *"}]\n',
                     'on:\n  schedule:\n    - cron: "0 1 * * *"\n  schedule:\n    - cron: "0 2 * * *"\n',
                     'name: x\n',
                     'on:\n  push:\non:\n  push:\n']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                read(text)

    def test_every_repository_workflow_is_read_the_way_yaml_reads_it(self):
        workflows = sorted((ROOT / '.github/workflows').glob('*.y*ml'))
        self.assertGreater(len(workflows), 5)
        for path in workflows:
            text = path.read_text()
            with self.subTest(path=path.name):
                crons = ALERT.schedule_crons(text)
                self.assertEqual(len(crons), len(re.findall(r'^\s*- cron:', text, re.M)))
                if crons:
                    ALERT.stale_after(crons)
        try:
            import yaml
        except ImportError:
            # ci.yml installs PyYAML before this runs, so in CI the exact
            # comparison cannot drop out unnoticed.
            if os.environ.get('GITHUB_ACTIONS') == 'true':
                self.fail('PyYAML is missing on the CI runner')
            print('PyYAML missing: exact comparison skipped', file=sys.stderr)
            return
        for path in workflows:
            data = yaml.safe_load(path.read_text())
            on = data.get(True, data.get('on'))
            schedule = on.get('schedule', []) if isinstance(on, dict) else []
            with self.subTest(path=path.name):
                self.assertEqual(ALERT.schedule_crons(path.read_text()),
                                 [entry['cron'] for entry in schedule])

    def test_the_step_env_merges_workflow_job_and_step_env(self):
        _, env = alert_step(
            'env:\n  A: workflow\n  B: workflow\n  C: workflow\n'
            'jobs:\n'
            '  other:\n    env:\n      A: other-job\n'
            '    steps:\n      - uses: x/y@0\n        env:\n          A: other-step\n'
            '  check:\n    env:\n      B: job\n      C: job\n'
            '    steps:\n'
            '      - uses: x/y@0\n        env:\n          C: sibling-step\n'
            '      - name: the step\n        env:\n          C: "step" # quoted\n'
            '        run: |\n          echo "$A $B $C"\n'
            '    timeout-minutes: 5\n')
        self.assertEqual(env, {'A': 'workflow', 'B': 'job', 'C': 'step'})

    def test_watched_set_includes_the_nightly_lanes(self):
        watched = ALERT.scheduled_workflows(ROOT / '.github/workflows', exclude='ci-alert.yml')
        for name in ['audit.yml', 'hardware-suite.yml', 'install-matrix.yml', 'update-flake-lock.yml']:
            self.assertIn(name, watched)
        self.assertNotIn('ci-alert.yml', watched)
        self.assertNotIn('ci.yml', watched)
        self.assertEqual(watched['audit.yml'], timedelta(hours=48))


if __name__ == '__main__':
    unittest.main()
