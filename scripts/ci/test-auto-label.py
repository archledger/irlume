#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Run the auto-labeler against fixtures: a fake `gh`, no network.

The step cases execute the `run:` step of .github/workflows/auto-label.yml
(events) and auto-label-sweep.yml (sweep, backfill) as written, with the env
each trigger gives it, against the repository's real .github/labels.toml.
Titles and paths below are real issues and pull requests.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[2]
EVENTS = ROOT / '.github/workflows/auto-label.yml'
SWEEP = ROOT / '.github/workflows/auto-label-sweep.yml'
TEMPLATE = ROOT / '.github/ISSUE_TEMPLATE/bug-report.yml'
REPO = 'archledger/irlume'

SPEC = importlib.util.spec_from_file_location('auto_label', Path(__file__).with_name('auto-label.py'))
LABEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LABEL)
RULES = LABEL.load_rules()

try:
    import yaml
except ImportError:
    # ci.yml installs PyYAML before this runs, so in CI the step and shape
    # cases cannot drop out unnoticed; locally they skip.
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        sys.exit('PyYAML is missing on the CI runner')
    yaml = None

# Serves list endpoints one page at a time, as GitHub does, so a caller that
# stops early or skips paging misses data.
FAKE_GH = r"""#!/usr/bin/env python3
import json, os, sys, urllib.parse
state_path = os.environ['FAKE_GH_STATE']
state = json.load(open(state_path))
args = sys.argv[1:]
stdin = sys.stdin.read() if '--input' in args else None
with open(os.environ['FAKE_GH_LOG'], 'a') as log:
    log.write(json.dumps({'args': args, 'stdin': stdin}) + '\n')
def save():
    json.dump(state, open(state_path, 'w'))
fail = state.get('fail')
if fail and fail['match'] in ' '.join(args) and fail['times'] > 0:
    fail['times'] -= 1
    save()
    sys.stderr.write(fail['stderr'])
    sys.exit(1)
def out(values):
    for value in values:
        print(json.dumps(value))
if args[:2] == ['label', 'list']:
    out(state['labels'])
elif args[:2] == ['label', 'create']:
    if args[2] in state.get('created_elsewhere', []):
        sys.stderr.write(f'label with name "{args[2]}" already exists; use `--force` to update its color and description\n')
        sys.exit(1)
    state['labels'].append(args[2])
    save()
elif args[:2] == ['api', 'rate_limit']:
    print(state['reset'])
elif args[0] == 'api' and '-X' in args:
    number = args[args.index('-X') + 2].split('/')[-2]
    state['added'].setdefault(number, []).extend(json.loads(stdin)['labels'])
    save()
elif args[0] == 'api' and '?' not in args[1]:
    out([state['current'][args[1].split('/')[-1]]])
elif args[0] == 'api':
    path, _, query = args[1].partition('?')
    q = urllib.parse.parse_qs(query)
    page, per = int(q['page'][0]), int(q['per_page'][0])
    number = path.split('/')[-2]
    if path.endswith('/files'):
        entries = [f if isinstance(f, dict) else {'filename': f} for f in state['files'][number]]
    elif path.endswith('/events'):
        entries = [{'event': 'labeled', 'label': {'name': 'bug'}}, {'event': 'closed'}]
        entries += [{'event': 'unlabeled', 'label': {'name': n}} for n in state['removed'].get(number, [])]
    elif path.endswith('/issues'):
        entries = state['open_items'] if q.get('state') == ['open'] else state['items']
    else:
        sys.exit(f'fake gh: unexpected api path {path}')
    out(entries[(page - 1) * per:page * per])
else:
    sys.exit(f'fake gh: unexpected call {args}')
"""


def issue(number, title, body='', labels=()):
    return {'number': number, 'title': title, 'body': body,
            'labels': [{'name': n} for n in labels]}


def pull(number, title, labels=(), fork=False):
    base = {'full_name': REPO}
    head = {'full_name': 'someone/irlume' if fork else REPO}
    return {'number': number, 'title': title, 'labels': [{'name': n} for n in labels],
            'head': {'repo': head}, 'base': {'repo': base}, 'pull_request': {}}


def every_label():
    return list(RULES)


class Rules(unittest.TestCase):
    def test_the_rules_file_is_valid(self):
        self.assertGreater(len(RULES), 30)
        self.assertEqual(LABEL.main(['--mode', 'check']), 0)

    def test_labels_other_automation_relies_on_are_defined(self):
        # ci-alert.yml, Dependabot's defaults and the issue templates.
        for name in ('ci-alert', 'dependencies', 'rust', 'github_actions', 'bug', 'hardware'):
            self.assertIn(name, RULES)

    def test_a_broken_rules_file_is_refused(self):
        cases = {
            'color': '[labels.x]\ncolor = "red"\ndescription = "d"\n',
            'unknown key': '[labels.x]\ncolor = "aaaaaa"\ndescription = "d"\nglob = ["a"]\n',
            'regex': '[labels.x]\ncolor = "aaaaaa"\ndescription = "d"\nissue_title = "("\n',
            'case': '[labels.x]\ncolor = "aaaaaa"\ndescription = "d"\n[labels.X]\ncolor = "aaaaaa"\ndescription = "d"\n',
            'description': '[labels.x]\ncolor = "aaaaaa"\ndescription = "' + 'd' * 101 + '"\n',
            'token': '[labels.x]\ncolor = "aaaaaa"\ndescription = "d"\ntitle_tokens = ["Fix"]\n',
        }
        for what, text in cases.items():
            with self.subTest(what), tempfile.NamedTemporaryFile('w', suffix='.toml') as f:
                f.write(text)
                f.flush()
                with self.assertRaises(LABEL.RulesError):
                    LABEL.load_rules(f.name)
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(LABEL.main(['--mode', 'check', '--rules', f.name]), 2)

    @unittest.skipIf(yaml is None, 'PyYAML not installed')
    def test_the_bug_report_area_options_are_the_rules_area_options(self):
        form = yaml.safe_load(TEMPLATE.read_text())
        [area] = [f for f in form['body'] if f.get('id') == 'area']
        self.assertEqual(area['attributes']['label'], LABEL.AREA_HEADING)
        options = set(area['attributes']['options']) - {'Not sure'}
        mapped = {o for rule in RULES.values() for o in rule['issue_area']}
        self.assertEqual(options, mapped)
        # Containment matching needs no option inside another.
        self.assertFalse([(a, b) for a in options for b in options if a != b and a in b])


class Matching(unittest.TestCase):
    def test_title_tokens(self):
        cases = {
            'fix(tpm): compute the literal PCR seal': {'fix', 'tpm'},
            'feat(doctor, tpm)!: report firmware': {'feat', 'doctor', 'tpm'},
            'docs+packaging: describe irlume as itself': {'docs', 'packaging'},
            'core, daemon: follow-ups from the #918 and #919 reviews': {'core', 'daemon'},
            'doctor/detect: recognize the MIPI/ISP camera class': {'doctor', 'detect'},
            'TUI: surface the measured model choices': {'tui'},
            'Camera arbitration: no wall-clock deadline': set(),
            '[hw] ThinkPad T480 Bison IR 5986:1141: YUYV-only node': set(),
            'A model number is not a camera identity (#341)': set(),
        }
        for title, tokens in cases.items():
            self.assertEqual(LABEL.title_tokens(title), tokens, title)

    def test_pull_requests_by_title_and_paths(self):
        cases = [
            ('feat(camera): judge YUYV IR bursts for a ceiling and active-IR evidence (ADR-0031 §4)',
             ['crates/irlume-camera/src/ir.rs', 'crates/irlume-cli/src/main.rs',
              'docs/adr/0031-ir.md', 'CHANGELOG.md', '.github/workflows/ci.yml'],
             {'enhancement', 'camera', 'cli', 'design'}),
            ('docs(adr): ADR-0023 per-camera-model profile layer', ['docs/adr/0023.md', 'README.md'],
             {'documentation', 'design'}),
            ('Lock both lockfiles', ['Cargo.lock', 'fuzz/Cargo.lock'], {'dependencies'}),
            ('Stabilize a flaky test', ['crates/irlume-cli/tests/machine_api.rs', 'scripts/test-x.py'],
             {'tests', 'cli'}),
            ('Coverage floor', ['.github/workflows/ci.yml', 'scripts/ci/ci-alert.py'], {'github_actions'}),
            ('deps: bump rustls to 0.23.46', ['Cargo.lock'], {'dependencies'}),
            ('fix(kcm): centered layout', ['kcm/src/main.qml', '.github/workflows/kcm.yml'],
             {'bug', 'desktop'}),
            ('Renamed', ['crates/irlume-fingerprint/src/lib.rs'], {'fingerprint'}),
            ('no prefix, nothing matched', ['.gitlab-ci.yml'], set()),
        ]
        for title, files, labels in cases:
            self.assertEqual(LABEL.labels_for_pull_request(RULES, title, files), labels, title)

    def test_issues_by_title(self):
        cases = {
            '[hw] Chicony 04f2:b74f: an unsaturated bright window leaves a genuine face dark':
                {'hardware'},
            'Logitech BRIO: ERROR-marked first image buffer retires the capture ring':
                {'camera'},
            'CI health: asan.yml failing or stale': {'github_actions'},
            'irlume-kwallet-init: the PAM module waits on the helper without a bound':
                {'keyring', 'pam'},
            'Credential-release nod gate: no signal for when to nod': set(),
            'slsa-provenance can never attest a release\'s assets': {'release'},
            'Dark IR-only login appears unreachable': {'camera'},
            'feat: spec-driven emitter discovery': {'enhancement', 'camera'},
        }
        for title, labels in cases.items():
            self.assertEqual(LABEL.labels_for_issue(RULES, title, ''), labels, title)

    def test_issues_by_area_and_never_by_pasted_body(self):
        body = textwrap.dedent('''\
            ### irlume version and install channel

            0.15.0, Copr

            ### Area

            Login, lock screen, sudo or polkit (PAM), TPM or Secure Boot

            ### What happened, and what you expected

            doctor: camera ok, tpm ok, fingerprint missing, keyring ok
            ''')
        self.assertEqual(LABEL.labels_for_issue(RULES, '[bug] face no longer unlocks', body),
                         {'pam', 'tpm'})
        unanswered = body.replace('Login, lock screen, sudo or polkit (PAM), TPM or Secure Boot',
                                  '_No response_')
        self.assertEqual(LABEL.labels_for_issue(RULES, '[bug] face no longer unlocks', unanswered),
                         set())


class FakeGh(unittest.TestCase):
    """Calls through a fake `gh` on PATH."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='auto label ')
        self.addCleanup(self.tmp.cleanup)
        tmp = Path(self.tmp.name)
        (tmp / 'bin').mkdir()
        gh = tmp / 'bin/gh'
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        self.state_path, self.log_path = tmp / 'state.json', tmp / 'log.jsonl'
        self.event_path = tmp / 'event.json'
        self.env = {'PATH': f'{tmp / "bin"}:{os.environ["PATH"]}', 'FAKE_GH_STATE': str(self.state_path),
                    'FAKE_GH_LOG': str(self.log_path), 'GH_TOKEN': 'fixture', 'HOME': str(tmp),
                    'AUTO_LABEL_PACE': '0'}
        self.state = {'labels': every_label(), 'files': {}, 'removed': {}, 'items': [],
                      'open_items': [], 'current': {}, 'added': {}}

    def calls(self):
        if not self.log_path.exists():
            return []
        return [json.loads(line)['args'] for line in self.log_path.read_text().splitlines()]

    def listings(self):
        return [c[1] for c in self.calls() if c[0] == 'api' and '/issues?' in c[1]]

    def writes(self):
        return [c for c in self.calls() if '-X' in c or c[:2] == ['label', 'create']]

    def added(self):
        return json.loads(self.state_path.read_text())['added']


@unittest.skipIf(yaml is None, 'PyYAML not installed')
class Step(FakeGh):
    """The workflows' run steps as written, with each trigger's env."""

    def step(self, mode, event=None, payload=None, dry_run='false', start='0', actor='archledger'):
        self.state_path.write_text(json.dumps(self.state))
        path, job = (EVENTS, 'label') if mode == 'event' else (SWEEP, 'sweep')
        workflow = yaml.safe_load(path.read_text())
        [run] = [s['run'] for s in workflow['jobs'][job]['steps'] if 'run' in s]
        env = dict(self.env, REPO=REPO, MODE=mode, DRY_RUN=dry_run, FROM=start, GITHUB_ACTOR=actor)
        if event:
            item = payload.get('issue') or payload.get('pull_request')
            self.state['current'].setdefault(str(item['number']), item)
            self.state_path.write_text(json.dumps(self.state))
            self.event_path.write_text(json.dumps(payload))
            env.update(GITHUB_EVENT_NAME=event, GITHUB_EVENT_PATH=str(self.event_path))
        done = subprocess.run(['bash', '-c', run], cwd=ROOT, env=env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.output = done.stdout
        return done.returncode

    def test_an_opened_issue_gets_its_labels(self):
        payload = {'action': 'opened', 'issue': issue(1076, 'pamwire: an enable that finds no anchor')}
        self.assertEqual(self.step('event', 'issues', payload), 0, self.output)
        self.assertEqual(self.added(), {'1076': ['pam']})

    def test_a_same_repository_pull_request_is_labeled_by_its_files(self):
        self.state['files']['1072'] = ['crates/irlume-cli/src/main.rs', 'crates/irlume-common/src/secureboot.rs']
        payload = {'action': 'opened', 'pull_request': pull(1072, 'feat(doctor): report TPM firmware')}
        self.assertEqual(self.step('event', 'pull_request', payload), 0, self.output)
        self.assertEqual(self.added(), {'1072': ['cli', 'enhancement', 'tpm']})

    def test_every_page_of_a_long_list_is_read(self):
        # Only the 150th of 150 changed files names an area, and the issue's
        # removal sits after a page of other events.
        self.state['files']['1073'] = [f'docs/plans/{n}.md' for n in range(149)] + [
            {'filename': 'crates/irlume-fingerprint/src/lib.rs', 'previous_filename': 'old.rs'}]
        payload = {'action': 'opened', 'pull_request': pull(1073, 'feat: move a file')}
        self.assertEqual(self.step('event', 'pull_request', payload), 0, self.output)
        self.assertEqual(self.added(), {'1073': ['enhancement', 'fingerprint']})
        pages = [c[1] for c in self.calls() if '/pulls/1073/files' in c[1]]
        self.assertEqual([p.split('page=')[-1] for p in pages], ['1', '2'])

    def test_an_event_run_judges_the_item_as_it_is_now(self):
        # Queued behind an edit: the payload still has the old title.
        payload = {'action': 'edited', 'issue': issue(1079, 'Camera hangs at the lock screen')}
        self.state['current']['1079'] = issue(1079, 'KWallet stays locked after face login')
        self.assertEqual(self.step('event', 'issues', payload), 0, self.output)
        self.assertEqual(self.added(), {'1079': ['keyring']})

    def test_fork_and_dependabot_pull_requests_are_left_to_the_sweep_without_a_call(self):
        fork = {'action': 'opened', 'pull_request': pull(1080, 'fix(camera): x', fork=True)}
        self.assertEqual(self.step('event', 'pull_request', fork), 0, self.output)
        self.assertIn('hourly sweep', self.output)
        bot = {'action': 'opened', 'pull_request': pull(1081, 'deps: bump x')}
        self.assertEqual(self.step('event', 'pull_request', bot, actor='dependabot[bot]'), 0, self.output)
        self.assertEqual(self.calls(), [])

    def test_a_removed_label_is_not_added_back_and_a_present_one_not_again(self):
        self.state['removed']['1033'] = ['performance']
        payload = {'action': 'edited',
                   'issue': issue(1033, 'Held concurrent pair: slow stream recovery', labels=['camera'])}
        self.assertEqual(self.step('event', 'issues', payload), 0, self.output)
        self.assertEqual(self.added(), {})
        self.assertIn('not re-adding removed performance', self.output)

    def test_nothing_to_add_reads_no_history_and_writes_nothing(self):
        payload = {'action': 'edited', 'issue': issue(1069, 'Per-frame evidence for IR cameras',
                                                       labels=['camera'])}
        self.assertEqual(self.step('event', 'issues', payload), 0, self.output)
        # One read of the item as it is now; no history, no write.
        self.assertEqual([c for c in self.calls() if c[0] == 'api'],
                         [['api', f'repos/{REPO}/issues/1069', '--jq', 'tojson']])

    def test_missing_labels_are_created_before_use(self):
        self.state['labels'] = [n for n in every_label() if n not in ('keyring', 'daemon')]
        payload = {'action': 'opened', 'issue': issue(1077, 'irlumed: KWallet handoff stalls')}
        self.assertEqual(self.step('event', 'issues', payload), 0, self.output)
        created = [c[2] for c in self.calls() if c[:2] == ['label', 'create']]
        self.assertEqual(sorted(created), ['daemon', 'keyring'])
        create = [c for c in self.calls() if c[:3] == ['label', 'create', 'keyring']][0]
        self.assertEqual(create[create.index('--color') + 1], RULES['keyring']['color'])
        self.assertEqual(self.added(), {'1077': ['daemon', 'keyring']})

    def test_a_label_another_run_created_first_counts_as_present(self):
        self.state['labels'] = [n for n in every_label() if n != 'keyring']
        self.state['created_elsewhere'] = ['keyring']
        payload = {'action': 'opened', 'issue': issue(1078, 'KWallet handoff stalls')}
        self.assertEqual(self.step('event', 'issues', payload), 0, self.output)
        self.assertEqual(self.added(), {'1078': ['keyring']})
        self.assertNotIn('label keyring: created', self.output)

    def test_a_dry_run_writes_nothing(self):
        self.state['labels'] = every_label()[1:]
        self.state['items'] = [issue(1, 'CI health: audit.yml failing or stale')]
        self.assertEqual(self.step('sweep', dry_run='true'), 0, self.output)
        self.assertEqual(self.writes(), [])
        self.assertIn('would add github_actions', self.output)
        self.assertIn('would create', self.output)

    def test_a_sweep_covers_every_open_item_and_recently_updated_ones(self):
        # 1070 closed in the window; 1050 is open but idle for days (a fork's
        # pull request whose sweeps were missed); 1069 is both.
        recent = [issue(1069, 'Per-frame active-IR evidence for IR cameras'), pull(1070, 'deps: rustls 0.23.46')]
        self.state['items'] = recent
        self.state['open_items'] = [pull(1050, 'fix(pam): x'), recent[0]]
        self.state['files']['1070'] = ['Cargo.lock', 'fuzz/Cargo.lock']
        self.state['files']['1050'] = ['crates/irlume-pam/src/lib.rs']
        self.assertEqual(self.step('sweep'), 0, self.output)
        self.assertEqual(self.added(), {'1050': ['bug', 'pam'], '1069': ['camera'], '1070': ['dependencies']})
        self.assertEqual(sorted('since=' in l for l in self.listings()), [False, True])
        self.assertIn('state=open', [l for l in self.listings() if 'since=' not in l][0])

    def test_a_backfill_resumes_from_a_number(self):
        self.state['items'] = [issue(n, 'CI health: audit.yml failing or stale') for n in (5, 6, 7)]
        self.assertEqual(self.step('backfill', start='6'), 0, self.output)
        self.assertEqual(sorted(self.added()), ['6', '7'])
        [listing] = self.listings()
        self.assertNotIn('since=', listing)
        self.assertIn('state=all', listing)


class Pacing(FakeGh):
    def gh(self, **kw):
        self.state_path.write_text(json.dumps(self.state))
        os.environ.update(self.env)
        self.slept = []
        return LABEL.Gh(REPO, sleep=self.slept.append, clock=lambda: 1000, **kw)

    def setUp(self):
        super().setUp()
        self.saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(self.saved)))

    def test_a_secondary_rate_limit_is_waited_out(self):
        self.state['fail'] = {'match': 'label list', 'times': 2,
                              'stderr': 'HTTP 403: You have exceeded a secondary rate limit'}
        gh = self.gh(pace=4.0)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(LABEL.ensure_labels(gh, RULES), [])
        self.assertEqual(self.slept, [4.0, 60, 4.0, 120, 4.0])

    def test_a_spent_primary_allowance_waits_for_its_reset(self):
        self.state['fail'] = {'match': 'label list', 'times': 1,
                              'stderr': 'HTTP 403: API rate limit exceeded for installation ID 1'}
        self.state['reset'] = 1030
        with redirect_stdout(io.StringIO()):
            LABEL.ensure_labels(self.gh(), RULES)
        self.assertEqual(self.slept, [35])

    def test_a_primary_allowance_still_spent_after_two_resets_fails(self):
        self.state['fail'] = {'match': 'label list', 'times': 3,
                              'stderr': 'HTTP 429: API rate limit exceeded for installation ID 1'}
        self.state['reset'] = 1000
        with redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
            LABEL.ensure_labels(self.gh(), RULES)
        self.assertEqual(self.slept, [5, 5])

    def test_a_file_list_cut_at_githubs_cap_applies_no_every_file_rule(self):
        # All listed files are docs, but GitHub stopped listing: the rest
        # may be code, so documentation is not claimed.
        self.state['files']['760'] = [f'docs/{n}.md' for n in range(150)]
        self.state['files']['761'] = [f'docs/{n}.md' for n in range(149)]
        saved, LABEL.FILES_CAP = LABEL.FILES_CAP, 150
        self.addCleanup(setattr, LABEL, 'FILES_CAP', saved)
        out = io.StringIO()
        with redirect_stdout(out):
            gh = self.gh()
            self.assertEqual(LABEL.label_item(gh, RULES, pull(760, 'feat: seeds')), ['enhancement'])
            self.assertEqual(LABEL.label_item(gh, RULES, pull(761, 'feat: seeds')),
                             ['documentation', 'enhancement'])
        self.assertIn('#760 pull request: GitHub lists only its first 150 files', out.getvalue())

    def test_other_errors_are_not_retried(self):
        self.state['fail'] = {'match': 'label list', 'times': 1, 'stderr': 'HTTP 404: Not Found'}
        with self.assertRaises(RuntimeError):
            LABEL.ensure_labels(self.gh(), RULES)
        self.assertEqual(len(self.calls()), 1)

    def test_each_page_is_its_own_paced_request(self):
        self.state['items'] = [issue(n, 'x') for n in range(1, 251)]
        gh = self.gh(pace=4.0)
        self.assertEqual(len(LABEL.list_items(gh)), 250)
        self.assertEqual((gh.calls, self.slept), (3, [4.0, 4.0, 4.0]))

    def test_a_backfill_stops_at_its_write_budget_and_names_the_resume_point(self):
        items = [issue(n, 'CI health: audit.yml failing or stale') for n in (5, 6, 7)]
        out = io.StringIO()
        with redirect_stdout(out):
            LABEL.run_items(self.gh(), RULES, items, max_writes=2)
        self.assertEqual(sorted(self.added()), ['5', '6'])
        self.assertIn('resume with --from 7', out.getvalue())

    def test_a_failed_write_is_not_counted_and_is_the_resume_point(self):
        self.state['fail'] = {'match': 'issues/5/labels', 'times': 1, 'stderr': 'HTTP 502: Bad Gateway'}
        items = [issue(n, 'CI health: audit.yml failing or stale') for n in (5, 6, 7)]
        gh, out = self.gh(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(LABEL.run_items(gh, RULES, items, max_writes=1), 1)
        self.assertEqual((gh.writes, sorted(self.added())), (1, ['6']))
        self.assertIn('resume with --from 5', out.getvalue())
        self.assertIn('failures=1 (#5)', out.getvalue())


@unittest.skipIf(yaml is None, 'PyYAML not installed')
class WorkflowShape(unittest.TestCase):
    def load(self, path):
        return path.read_text(), yaml.safe_load(path.read_text())

    def test_no_trigger_runs_a_forks_event_with_write_access(self):
        for path, triggers in ((EVENTS, {'issues', 'pull_request'}),
                               (SWEEP, {'schedule', 'workflow_dispatch'})):
            text, workflow = self.load(path)
            self.assertEqual(set(workflow[True]), triggers, path.name)
            self.assertNotIn('pull_request_target', yaml.safe_dump(workflow[True]))

    def test_the_event_labeler_runs_the_default_branch_code(self):
        _, workflow = self.load(EVENTS)
        [checkout] = [s for s in workflow['jobs']['label']['steps']
                      if s.get('uses', '').startswith('actions/checkout@')]
        self.assertEqual(checkout['with']['ref'], '${{ github.event.repository.default_branch }}')

    def test_only_the_sweep_is_scheduled_so_ci_alert_judges_it_alone(self):
        self.assertNotIn('schedule', self.load(EVENTS)[1][True])
        self.assertIn('schedule', self.load(SWEEP)[1][True])

    def test_least_privilege_and_no_expression_in_run(self):
        for path, job in ((EVENTS, 'label'), (SWEEP, 'sweep')):
            _, workflow = self.load(path)
            self.assertEqual(workflow['permissions'], {})
            job = workflow['jobs'][job]
            self.assertEqual(job['permissions'], {'contents': 'read', 'issues': 'write', 'pull-requests': 'write'})
            [checkout] = [s for s in job['steps'] if s.get('uses', '').startswith('actions/checkout@')]
            self.assertIs(checkout['with']['persist-credentials'], False)
            for step in job['steps']:
                self.assertNotIn('${{', step.get('run', ''))


if __name__ == '__main__':
    unittest.main(verbosity=2)
