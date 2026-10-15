#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Add labels to issues and pull requests by the rules in .github/labels.toml.

Run by .github/workflows/auto-label.yml (events) and auto-label-sweep.yml
(hourly sweep, manual sweep or backfill). A pull request is labeled by the
files it changes and by its conventional title prefix, `type(scope, ...):`;
an issue by its title and the bug report's Area field. Every label the file
defines and the repository lacks is created first, with the file's color and
description; nothing is renamed, recolored or deleted.

Labels are only added. A label already present is left alone, and a label
that was removed from the issue or pull request at any time is not added back,
so a maintainer's correction stands.

Modes:

- event: the issue or pull request of the triggering event, from
  GITHUB_EVENT_NAME and GITHUB_EVENT_PATH, read afresh so that a run queued
  behind an edit judges the current title, body and labels. A pull request
  from a fork, or one Dependabot triggered, runs with a read-only token and is
  left to the sweep.
- sweep: every open issue and pull request, and every one updated in the last
  --hours hours, so a sweep that runs late still reaches what it missed.
- backfill: every issue and pull request, oldest first; --from resumes at a
  number and --max-writes stops after that many label writes, naming the
  resume point (the first item that failed, if one did).
- check: validate the rules file only; no network.

--dry-run true prints what would be added and changes nothing. --pace waits
that many seconds before each API request; lists are fetched one page of 100
at a time, each page its own paced request. Backfill defaults to 5 s, 720
requests an hour, which leaves the other workflows part of the token's 1,000
an hour (the allowance is per repository) and, since each write follows at
least one read, stays under the 500 content-creating requests an hour GitHub
allows. A secondary rate limit is waited out with growing delays, an
exhausted primary allowance until its reset. A label that a concurrent run
created first counts as present. GitHub lists at most 3,000 files of a pull
request; past that, only the labels any listed file earns are added.

Needs `gh` with GH_TOKEN, except in check mode. AUTO_LABEL_PACE (seconds)
replaces the default pace, for the self-test: python3 scripts/ci/test-auto-label.py
(fixtures and a fake `gh`, no network).
"""
import argparse
from datetime import datetime, timedelta, timezone
import fnmatch
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / '.github/labels.toml'
KEYS = {'color', 'description', 'paths', 'only_paths', 'title_tokens', 'issue_title', 'issue_area'}
# Bots whose pull_request events carry a read-only token, like a fork's.
READ_ONLY_ACTORS = {'dependabot[bot]'}
AREA_HEADING = 'Area'
RETRY_WAITS = (60, 120, 240, 480)
PAGE = 100
# What the pull request files endpoint lists at most (GitHub REST docs).
FILES_CAP = 3000
PRIMARY_LIMIT = re.compile(r'API rate limit exceeded', re.I)
SECONDARY_LIMIT = re.compile(r'secondary rate limit|HTTP 429', re.I)


class RulesError(ValueError):
    pass


def load_rules(path=RULES):
    """The labels of `path`, by name, each with its compiled rules."""
    try:
        data = tomllib.loads(Path(path).read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RulesError(f'{path}: {error}') from error
    labels = data.get('labels')
    if not isinstance(labels, dict) or not labels or set(data) != {'labels'}:
        raise RulesError(f'{path}: expected only a [labels.<name>] table per label')
    rules, seen = {}, {}
    for name, spec in labels.items():
        where = f'{path}: label {name!r}'
        if name.lower() in seen:
            raise RulesError(f'{where} repeats {seen[name.lower()]!r} (label names ignore case)')
        seen[name.lower()] = name
        if not isinstance(spec, dict) or set(spec) - KEYS:
            raise RulesError(f'{where}: unknown keys {sorted(set(spec) - KEYS)}')
        if not re.fullmatch(r'[0-9a-f]{6}', str(spec.get('color', ''))):
            raise RulesError(f'{where}: color must be six lowercase hex digits')
        description = spec.get('description', '')
        if not isinstance(description, str) or not description or len(description) > 100:
            raise RulesError(f'{where}: description must be 1 to 100 characters (GitHub limit)')
        rule = {'color': spec['color'], 'description': description}
        for key in ('paths', 'only_paths', 'title_tokens', 'issue_area'):
            values = spec.get(key, [])
            if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
                raise RulesError(f'{where}: {key} must be a list of non-empty strings')
            rule[key] = values
        if any(t != t.lower() or not re.fullmatch(r'[a-z0-9][a-z0-9.-]*', t) for t in rule['title_tokens']):
            raise RulesError(f'{where}: title_tokens must be lowercase words')
        pattern = spec.get('issue_title')
        try:
            rule['issue_title'] = re.compile(pattern, re.IGNORECASE) if pattern else None
        except (re.error, TypeError) as error:
            raise RulesError(f'{where}: issue_title: {error}') from error
        rules[name] = rule
    return rules


def title_tokens(title):
    """The lowercase words of a conventional prefix.

    `fix(tpm, cli)!: x` gives fix, tpm and cli; `docs+packaging: x` and
    `core, daemon: x` give both words. A prose title with a colon, such as
    `Camera arbitration: x`, gives none: words before the colon must be joined
    by `+`, `,`, `&` or `/`.
    """
    match = re.match(r'\s*([A-Za-z][\w-]*(?:\s*[+,&/]\s*[A-Za-z][\w-]*)*)(?:\(([^)]*)\))?!?:\s',
                     title or '')
    if not match:
        return set()
    words = re.split(r'[\s,/+&]+', match.group(1)) + re.split(r'[\s,/+&]+', match.group(2) or '')
    return {w.lower() for w in words if w}


def area_answer(body):
    """The text under the issue form's `### Area` heading, '' if absent or unanswered."""
    match = re.search(rf'^###\s+{AREA_HEADING}\s*$\n(.*?)(?=^###\s|\Z)', body or '', re.M | re.S)
    answer = match.group(1).strip() if match else ''
    return '' if answer == '_No response_' else answer


def matches(path, patterns):
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def labels_for_pull_request(rules, title, files, complete=True):
    """Labels a pull request earns. With an incomplete file list no every-file rule applies."""
    tokens = title_tokens(title)
    wanted = set()
    for name, rule in rules.items():
        if tokens & set(rule['title_tokens']):
            wanted.add(name)
        elif any(matches(f, rule['paths']) for f in files):
            wanted.add(name)
        elif (complete and files and rule['only_paths']
              and all(matches(f, rule['only_paths']) for f in files)):
            wanted.add(name)
    return wanted


def labels_for_issue(rules, title, body):
    tokens = title_tokens(title)
    area = area_answer(body)
    wanted = set()
    for name, rule in rules.items():
        if tokens & set(rule['title_tokens']):
            wanted.add(name)
        elif rule['issue_title'] and rule['issue_title'].search(title or ''):
            wanted.add(name)
        elif area and any(option in area for option in rule['issue_area']):
            wanted.add(name)
    return wanted


class Gh:
    """`gh` with pacing and secondary-rate-limit retries; writes are skipped in a dry run."""

    def __init__(self, repo, dry_run=False, pace=0.0, sleep=time.sleep, clock=time.time):
        self.repo, self.dry_run, self.pace, self.sleep, self.clock = repo, dry_run, pace, sleep, clock
        self.calls = self.writes = 0

    def run(self, args, stdin=None):
        secondary, primary = iter(RETRY_WAITS), 0
        while True:
            if self.pace:
                self.sleep(self.pace)
            self.calls += 1
            done = subprocess.run(['gh', *args], input=stdin, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if done.returncode == 0:
                return done.stdout
            wait = None
            if PRIMARY_LIMIT.search(done.stderr):
                # The allowance is spent: only its reset brings requests back.
                if primary < 2:
                    primary += 1
                    wait = self.until_reset()
            elif SECONDARY_LIMIT.search(done.stderr):
                wait = next(secondary, None)
            if wait is None:
                raise RuntimeError(f'gh {" ".join(args[:3])}: {done.stderr.strip()}')
            print(f'rate limited; waiting {wait} s', flush=True)
            self.sleep(wait)

    def until_reset(self):
        """Seconds until the primary allowance resets, plus a margin; GET /rate_limit costs none."""
        done = subprocess.run(['gh', 'api', 'rate_limit', '--jq', '.resources.core.reset'],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            reset = int(done.stdout.strip())
        except ValueError:
            return 3600
        return min(max(reset - int(self.clock()), 0) + 5, 3700)

    def lines(self, args):
        return [json.loads(line) for line in self.run(args).splitlines() if line.strip()]

    def pages(self, path):
        """Every element of a list endpoint, one paced request per page of PAGE."""
        items, page = [], 1
        while True:
            sep = '&' if '?' in path else '?'
            batch = self.lines(['api', f'{path}{sep}per_page={PAGE}&page={page}', '--jq', '.[] | tojson'])
            items += batch
            if len(batch) < PAGE:
                return items
            page += 1

    def write(self, args, stdin=None):
        """Run a write; counted once it succeeded (or would have, in a dry run)."""
        out = '' if self.dry_run else self.run(args, stdin)
        self.writes += 1
        return out


def ensure_labels(gh, rules):
    """Create each defined label the repository lacks. Returns the names created."""
    have = {n.lower() for n in gh.lines(['label', 'list', '--repo', gh.repo, '--limit', '1000',
                                         '--json', 'name', '--jq', '.[].name | tojson'])}
    created = []
    for name, rule in rules.items():
        if name.lower() not in have:
            try:
                gh.write(['label', 'create', name, '--repo', gh.repo,
                          '--color', rule['color'], '--description', rule['description']])
            except RuntimeError as error:
                # A run for another item created it first; theirs stands.
                if 'already exists' not in str(error):
                    raise
                continue
            created.append(name)
    return created


def changed_files(gh, number):
    """Each changed path of a pull request and the old path of a renamed file, and
    whether that is all of them: GitHub lists at most FILES_CAP files."""
    files, entries = [], gh.pages(f'repos/{gh.repo}/pulls/{number}/files')
    for entry in entries:
        files.append(entry['filename'])
        if entry.get('previous_filename'):
            files.append(entry['previous_filename'])
    return files, len(entries) < FILES_CAP


def removed_labels(gh, number):
    return {event['label']['name'].lower() for event in gh.pages(f'repos/{gh.repo}/issues/{number}/events')
            if event.get('event') == 'unlabeled' and event.get('label')}


def label_item(gh, rules, item):
    """Add the labels `item` (an issue or pull request object) should have. Returns those added."""
    number = item['number']
    is_pr = 'pull_request' in item or 'head' in item
    if is_pr:
        files, complete = changed_files(gh, number)
        if not complete:
            print(f'#{number} pull request: GitHub lists only its first {FILES_CAP} files; '
                  'every-file rules are not applied')
        wanted = labels_for_pull_request(rules, item.get('title'), files, complete)
    else:
        wanted = labels_for_issue(rules, item.get('title'), item.get('body'))
    present = {label['name'].lower() for label in item.get('labels', [])}
    add = sorted(n for n in wanted if n.lower() not in present)
    kind = 'pull request' if is_pr else 'issue'
    if add:
        removed = removed_labels(gh, number)
        kept = [n for n in add if n.lower() in removed]
        add = [n for n in add if n.lower() not in removed]
        if kept:
            print(f'#{number} {kind}: not re-adding removed {", ".join(kept)}')
    if add:
        gh.write(['api', '-X', 'POST', f'repos/{gh.repo}/issues/{number}/labels', '--input', '-'],
                 json.dumps({'labels': add}))
        print(f'#{number} {kind}: {"would add" if gh.dry_run else "added"} {", ".join(add)}', flush=True)
    return add


def from_event(name, payload, actor):
    """The issue or pull request an event names, or (None, reason) when it is left to the sweep."""
    if name == 'issues':
        return payload['issue'], None
    if name == 'pull_request':
        pr = payload['pull_request']
        if pr['head']['repo'] is None or pr['head']['repo']['full_name'] != pr['base']['repo']['full_name']:
            return None, 'a pull request from a fork gets a read-only token; the hourly sweep labels it'
        if actor in READ_ONLY_ACTORS:
            return None, f'{actor} runs get a read-only token; the hourly sweep labels this pull request'
        return pr, None
    raise ValueError(f'unsupported event {name!r}')


def list_items(gh, state='all', since=None):
    """Issues and pull requests, oldest first."""
    query = f'state={state}&sort=created&direction=asc'
    if since:
        query += f'&since={since.strftime("%Y-%m-%dT%H:%M:%SZ")}'
    return gh.pages(f'repos/{gh.repo}/issues?{query}')


def sweep_items(gh, since):
    """Every open item and every item updated since `since`, oldest first."""
    items = {i['number']: i for i in list_items(gh, state='open')}
    for item in list_items(gh, since=since):
        items.setdefault(item['number'], item)
    return [items[n] for n in sorted(items)]


def run_items(gh, rules, items, max_writes=None):
    tally, failed = {}, []
    for item in items:
        if max_writes is not None and gh.writes >= max_writes:
            print(f'stopped after {gh.writes} writes; resume with --from {min(failed + [item["number"]])}')
            break
        try:
            for name in label_item(gh, rules, item):
                tally[name] = tally.get(name, 0) + 1
        except RuntimeError as error:
            failed.append(item['number'])
            print(f'#{item["number"]}: {error}', file=sys.stderr)
    summary = ', '.join(f'{n} {c}' for n, c in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0])))
    print(f'items={len(items)} writes={gh.writes} calls={gh.calls} failures={len(failed)}'
          + (f' (#{", #".join(map(str, failed))})' if failed else '')
          + (f' added: {summary}' if summary else ''))
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--mode', required=True, choices=['event', 'sweep', 'backfill', 'check'])
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--rules', default=str(RULES))
    parser.add_argument('--dry-run', default='false', choices=['true', 'false'])
    parser.add_argument('--hours', type=float, default=3.0)
    parser.add_argument('--pace', type=float, default=None)
    parser.add_argument('--from', dest='start', type=int, default=0)
    parser.add_argument('--max-writes', type=int, default=None)
    args = parser.parse_args(argv)
    try:
        rules = load_rules(args.rules)
    except RulesError as error:
        print(error, file=sys.stderr)
        return 2
    if args.mode == 'check':
        print(f'{len(rules)} labels, rules valid')
        return 0
    if not args.repo:
        print('--repo or GITHUB_REPOSITORY is required', file=sys.stderr)
        return 2
    item = None
    if args.mode == 'event':
        # Before any call: a read-only run must not try to create labels.
        name = os.environ.get('GITHUB_EVENT_NAME', '')
        payload = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        item, reason = from_event(name, payload, os.environ.get('GITHUB_ACTOR', ''))
        if item is None:
            print(reason)
            return 0
    pace = args.pace
    if pace is None:
        pace = float(os.environ.get('AUTO_LABEL_PACE') or (5.0 if args.mode == 'backfill' else 0.0))
    gh = Gh(args.repo, dry_run=args.dry_run == 'true', pace=pace)
    try:
        created = ensure_labels(gh, rules)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    for name in created:
        print(f'label {name}: {"would create" if gh.dry_run else "created"}')
    if item is not None:
        # The payload is the item as it was when the event fired; a run queued
        # behind a later edit must judge what the item says now.
        try:
            [item] = gh.lines(['api', f'repos/{gh.repo}/issues/{item["number"]}', '--jq', 'tojson'])
        except RuntimeError as error:
            print(error, file=sys.stderr)
            return 1
        return run_items(gh, rules, [item])
    if args.mode == 'sweep':
        since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
        return run_items(gh, rules, sweep_items(gh, since))
    items = [i for i in list_items(gh) if i['number'] >= args.start]
    return run_items(gh, rules, items, args.max_writes)


if __name__ == '__main__':
    sys.exit(main())
