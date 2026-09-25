#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Judge every scheduled workflow on main and keep one issue per failing one.

Run by .github/workflows/ci-alert.yml. The watched set is every workflow file
under .github/workflows with an `on.schedule` trigger, except the workflow
running this check. Each is judged on two things:

- the latest completed run on main, any event but a pull request, passing
  over skipped runs and cancelled runs that a newer run replaced (a run waiting
  in a concurrency group is cancelled when a newer one queues): any conclusion
  other than success alerts, so a cancelled run that nothing replaced (a job
  over its timeout-minutes, or one cancelled by hand) alerts too;
- the age of the latest successful run on main: older than the schedule's
  longest gap between firings plus one day alerts. This is what catches a
  runner that stays offline, whose newest run is always a young queued one.

In check mode each alerting workflow gets an open issue titled
"CI health: <file> failing or stale" (label ci-alert), commented at most once a
day, and closed when the workflow stops alerting. In dry mode the verdicts
are printed and the exit status is 1 if any workflow alerts. Finding no
scheduled workflow at all is an error (exit 2) that changes no issue.

Needs `gh` with GH_TOKEN. CI_ALERT_NOW (an ISO 8601 time) replaces the clock,
for the self-test: python3 scripts/ci/test-ci-alert.py (fixtures, no network).
"""
import argparse
from datetime import date, datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys

TITLE = 'CI health: {} failing or stale'
TITLE_PREFIX = 'CI health: '
FIELDS_JSON = 'databaseId,status,conclusion,createdAt,event,url'
GRACE = timedelta(days=1)
FIELDS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
# Eight years from a leap year: every month length and weekday alignment.
WINDOW = (date(2024, 1, 1), date(2032, 1, 1))


def parse_time(text):
    return datetime.fromisoformat(text.replace('Z', '+00:00')).astimezone(timezone.utc)


def stamp(when):
    return when.strftime('%Y-%m-%dT%H:%M:%SZ')


def span(delta):
    hours = int(delta.total_seconds() // 3600)
    if hours < 72:
        return f'{hours} h'
    return f'{hours // 24} d' + (f' {hours % 24} h' if hours % 24 else '')


def strip_comment(text):
    return re.sub(r'(^|\s)#.*$', '', text).strip()


def schedule_crons(text):
    """The cron strings of a workflow's top-level `on.schedule`, [] if none.

    Reads the block style every workflow here uses and raises ValueError on
    anything else that mentions a schedule, so no schedule is missed quietly.
    """
    lines = text.splitlines()
    heads = [i for i, line in enumerate(lines)
             if re.match(r'''(on|"on"|'on')\s*:(\s|$)''', line)]
    if len(heads) != 1:
        raise ValueError(f'expected one top-level on: key, found {len(heads)}')
    inline = strip_comment(lines[heads[0]].split(':', 1)[1])
    if inline:
        if 'schedule' in inline:
            raise ValueError('a flow-style schedule is not supported; use block style')
        return []
    block = []
    for line in lines[heads[0] + 1:]:
        if line.strip() and not line.lstrip().startswith('#') and not line[0].isspace():
            break
        if line.strip() and not line.lstrip().startswith('#'):
            block.append(line)
    if not block:
        return []
    indent = len(block[0]) - len(block[0].lstrip())
    starts = [i for i, line in enumerate(block) if len(line) - len(line.lstrip()) == indent
              and line.split(':', 1)[0].strip().strip('"\'') == 'schedule']
    if not starts:
        return []
    if len(starts) > 1:
        raise ValueError('on.schedule appears twice')
    if strip_comment(block[starts[0]].split(':', 1)[1]):
        raise ValueError('a flow-style schedule is not supported; use block style')
    crons = []
    for line in block[starts[0] + 1:]:
        if len(line) - len(line.lstrip()) <= indent:
            break
        match = re.fullmatch(r'''\s*-\s+cron:\s*("[^"]*"|'[^']*'|[^"'#\s][^#]*?)\s*(#.*)?''', line)
        if not match:
            raise ValueError(f'unexpected line in on.schedule: {line.strip()}')
        crons.append(match.group(1).strip('"\''))
    if not crons:
        raise ValueError('on.schedule has no cron entries')
    return crons


def cron_field(text, low, high):
    values = set()
    for part in text.split(','):
        match = re.fullmatch(r'(\*|\d+(?:-\d+)?)(?:/(\d+))?', part)
        if not match:
            raise ValueError(f'unsupported cron field {text!r}')
        base, step = match.group(1), int(match.group(2) or 1)
        if base == '*':
            first, last = low, high
        elif '-' in base:
            first, last = (int(n) for n in base.split('-'))
        else:
            first = int(base)
            last = high if match.group(2) else first
        if not low <= first <= last <= high or step < 1:
            raise ValueError(f'cron field {text!r} is out of range')
        values.update(range(first, last + 1, step))
    return values


def cron_matcher(expr):
    """(day predicate, sorted minutes of the day) for a five-field cron."""
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError(f'cron {expr!r} does not have five fields')
    minutes, hours, days, months, weekdays = (
        cron_field(part, low, high) for part, (low, high) in zip(parts, FIELDS))
    weekdays = {d % 7 for d in weekdays}
    either = not parts[2].startswith('*') and not parts[4].startswith('*')

    def fires_on(day):
        if day.month not in months:
            return False
        dom, dow = day.day in days, day.isoweekday() % 7 in weekdays
        return (dom or dow) if either else (dom and dow)

    return fires_on, sorted(h * 60 + m for h in hours for m in minutes)


def stale_after(crons):
    """The longest gap between firings of the union of `crons`, plus GRACE."""
    matchers = [cron_matcher(expr) for expr in crons]
    widest, previous, day = timedelta(0), None, WINDOW[0]
    while day < WINDOW[1]:
        times = sorted({t for fires_on, ts in matchers if fires_on(day) for t in ts})
        if times:
            start = datetime(day.year, day.month, day.day)
            firings = [start + timedelta(minutes=t) for t in times]
            if previous is not None:
                widest = max(widest, firings[0] - previous)
            for earlier, later in zip(firings, firings[1:]):
                widest = max(widest, later - earlier)
            previous = firings[-1]
        day += timedelta(days=1)
    if widest == timedelta(0):
        raise ValueError(f'schedule {list(crons)} fires fewer than twice in eight years')
    return widest + GRACE


def scheduled_workflows(directory, exclude=None):
    """{file name: stale limit, or the ValueError that stopped reading it}."""
    watched = {}
    for path in sorted(Path(directory).glob('*.y*ml')):
        if path.name == exclude or path.suffix not in ('.yml', '.yaml'):
            continue
        try:
            crons = schedule_crons(path.read_text())
            if crons:
                watched[path.name] = stale_after(crons)
        except ValueError as error:
            watched[path.name] = error
    return watched


def deciding_run(runs):
    """The run that gives the verdict, from runs on main newest first.

    The newest completed run, passing over skipped runs and cancelled runs
    that a newer run replaced. A cancelled run with nothing newer counts: no
    later run will give a verdict in its place.
    """
    for index, run in enumerate(runs):
        if run.get('status') != 'completed':
            continue
        conclusion = run.get('conclusion')
        if conclusion == 'skipped' or (conclusion == 'cancelled' and index > 0):
            continue
        return run
    return None


def judge(name, limit, runs, success, workflow, now):
    """(alert, lines) for one workflow.

    runs: its runs on main in any status, newest first; success: its newest
    successful run on main or None; workflow: its entry from the Actions API
    (state, created_at) or None.
    """
    state = (workflow or {}).get('state', 'active')
    if state == 'disabled_manually':
        return False, [f'{name} is disabled manually; not judged']
    alert, lines = False, []
    if state != 'active':
        alert = True
        lines.append(f'{name} is {state}: its schedule does not run')
    if isinstance(limit, ValueError):
        alert = True
        lines.append(f'{name}: cannot read its schedule: {limit}')
        limit = None
    latest = deciding_run(runs)
    if latest is not None and latest.get('conclusion') != 'success':
        alert = True
        lines.append(f"{name} run {latest['databaseId']} ({latest.get('event', '?')}) concluded "
                     f"{latest.get('conclusion')}, created {latest['createdAt']}: {latest['url']}")
    if success is None:
        registered = (workflow or {}).get('created_at')
        if registered and limit is not None and now - parse_time(registered) < limit:
            lines.append(f'{name} has no successful run on main yet; added {registered}')
        else:
            alert = True
            lines.append(f'{name} has no successful run on main')
    elif limit is not None and now - parse_time(success['createdAt']) > limit:
        alert = True
        lines.append(f"{name} last succeeded {success['createdAt']}, "
                     f"{span(now - parse_time(success['createdAt']))} ago, over the "
                     f"{span(limit)} limit: {success['url']}")
    if not lines:
        lines.append(f"{name} healthy: last success {success['createdAt']}: {success['url']}")
    return alert, lines


class GitHub:
    def __init__(self, repo):
        self.repo = repo

    def __call__(self, *args):
        return subprocess.run(['gh', *args], check=True, stdout=subprocess.PIPE, text=True).stdout

    def json(self, *args):
        return json.loads(self(*args, '--repo', self.repo))

    def runs(self, name, status=None, limit=20):
        """Runs of workflow file `name` on main, newest first.

        `--branch main` matches the head branch, which a pull request from a
        fork's own main branch shares, so pull request runs are dropped here.
        """
        found = self.json('run', 'list', '--workflow', name, '--branch', 'main',
                          *(('--status', status) if status else ()),
                          '--limit', str(limit), '--json', FIELDS_JSON)
        return [r for r in found if not str(r.get('event', '')).startswith('pull_request')]

    def workflows(self):
        out = self('api', '--paginate', f'repos/{self.repo}/actions/workflows',
                   '--jq', '.workflows[] | {path, state, created_at}')
        return {Path(w['path']).name: w
                for w in map(json.loads, out.splitlines()) if w['path'].startswith('.github/')}


def last_note(gh, number):
    issue = gh.json('issue', 'view', str(number), '--json', 'body,comments')
    return issue['comments'][-1]['body'] if issue['comments'] else issue['body']


def maintain_issues(gh, label, verdicts, now):
    """Open, comment or close one issue per watched workflow."""
    header = f'Automated check {stamp(now)}:'
    open_issues, duplicates = {}, []
    for issue in sorted(gh.json('issue', 'list', '--label', label, '--state', 'open',
                                '--limit', '100', '--json', 'number,title'),
                        key=lambda i: i['number']):
        if issue['title'] in open_issues:
            duplicates.append((issue['number'], open_issues[issue['title']], issue['title']))
        else:
            open_issues[issue['title']] = issue['number']
    labelled, tracked = False, []
    for name, alert, lines in verdicts:
        title, body = TITLE.format(name), '\n'.join(lines)
        number = open_issues.pop(title, None)
        if alert and number is None:
            if not labelled:
                subprocess.run(['gh', 'label', 'create', label, '--repo', gh.repo, '--color', 'b60205',
                                '--description', 'open while a scheduled workflow is failing or stale'],
                               capture_output=True, check=False)
                labelled = True
            url = gh('issue', 'create', '--repo', gh.repo, '--label', label, '--title', title,
                     '--body', f'{header}\n\n{body}\n\nThe CI health alert workflow (ci-alert.yml) '
                     'opens, comments and closes this issue; a human should still diagnose and fix.')
            tracked.append(f'- {title}: {url.strip()}')
            print(f'opened issue: {title}')
        elif alert:
            if f'Automated check {now:%Y-%m-%d}' not in last_note(gh, number):
                gh('issue', 'comment', str(number), '--repo', gh.repo, '--body', f'{header}\n\n{body}')
            tracked.append(f'- {title}: #{number}')
            print(f'updated issue #{number}: {title}')
        elif number is not None:
            gh('issue', 'close', str(number), '--repo', gh.repo, '--reason', 'completed',
               '--comment', f'No longer alerting as of {stamp(now)}:\n\n{body}')
            print(f'closed issue #{number}: {title}')
    for title, number in open_issues.items():
        if title.startswith(TITLE_PREFIX):
            # The shared issue of the two-workflow check, or a workflow that
            # lost its schedule or its file.
            status = '\n'.join(tracked) or 'None: every scheduled workflow is healthy.'
            gh('issue', 'close', str(number), '--repo', gh.repo, '--reason', 'completed',
               '--comment', f'{header} no scheduled workflow matches this issue. CI health is '
               f'tracked in one issue per scheduled workflow. Open now:\n\n{status}')
            print(f'closed issue #{number}: {title}')
    for number, kept, title in duplicates:
        if title.startswith(TITLE_PREFIX):
            gh('issue', 'close', str(number), '--repo', gh.repo, '--reason', 'not planned',
               '--comment', f'{header} duplicate of #{kept}, which tracks this workflow.')
            print(f'closed issue #{number}: duplicate of #{kept}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--repo', required=True)
    parser.add_argument('--label', default='ci-alert')
    parser.add_argument('--mode', choices=('check', 'dry'), required=True)
    parser.add_argument('--workflows', default='.github/workflows')
    args = parser.parse_args(argv)
    now = parse_time(os.environ['CI_ALERT_NOW']) if os.environ.get('CI_ALERT_NOW') \
        else datetime.now(timezone.utc)
    # owner/repo/.github/workflows/<file>@<ref>, set by Actions.
    own = Path(os.environ.get('GITHUB_WORKFLOW_REF', '').split('@', 1)[0]).name or None

    watched = scheduled_workflows(args.workflows, exclude=own)
    if not watched:
        # A wrong path or a sparse checkout must not read as "all healthy"
        # and close the open issues.
        print(f'error: no scheduled workflow found in {args.workflows}; '
              'no verdict and no issue change', file=sys.stderr)
        return 2

    gh = GitHub(args.repo)
    registered = gh.workflows()
    verdicts = []
    for name, limit in watched.items():
        workflow = registered.get(name)
        if (workflow or {}).get('state') == 'disabled_manually':
            runs, success = [], None
        else:
            runs = gh.runs(name)
            success = next(iter(gh.runs(name, 'success')), None)
        alert, lines = judge(name, limit, runs, success, workflow, now)
        verdicts.append((name, alert, lines))
        print('\n'.join(lines))
    alert = int(any(a for _, a, _ in verdicts))
    print(f'alert={alert}')
    if args.mode == 'dry':
        print('dry mode: no issue changes')
        return alert
    maintain_issues(gh, args.label, verdicts, now)
    return 0


if __name__ == '__main__':
    sys.exit(main())
