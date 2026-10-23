#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Check the measurement-build boundary without opening a native runtime."""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
LIBRARY_EDGES = {
    'irlume-common': (),
    'irlume-camera': ('irlume-common',),
    'irlume-vision': ('irlume-common',),
    'irlume-liveness': ('irlume-common', 'irlume-vision'),
    'irlume-core': ('irlume-common', 'irlume-vision'),
    'irlume-auth': ('irlume-camera', 'irlume-common', 'irlume-core', 'irlume-liveness', 'irlume-vision'),
    'irlume-fingerprint': ('irlume-common',),
}
ROOT_EDGES = {
    'irlume-cli': ('irlume-auth', 'irlume-camera', 'irlume-common', 'irlume-core', 'irlume-fingerprint', 'irlume-liveness', 'irlume-pam-view', 'irlume-vision'),
    'irlume-daemon': ('irlume-auth', 'irlume-common', 'irlume-core', 'irlume-liveness'),
    'irlume-gkr-unlock': ('irlume-common',),
    'irlume-kwallet-init': ('irlume-common',),
    'irlume-password-verify': (),
    'irlume-pam': ('irlume-common',),
    'irlume-pam-view': (),
}
ROOT_TARGETS = {
    'irlume-cli': ('irlume', 'bin'),
    'irlume-daemon': ('irlumed', 'bin'),
    'irlume-gkr-unlock': ('irlume-gkr-unlock', 'bin'),
    'irlume-kwallet-init': ('irlume-kwallet-init', 'bin'),
    'irlume-password-verify': ('irlume-password-verify', 'bin'),
    'irlume-pam': ('pam_irlume', 'cdylib'),
    'irlume-pam-view': ('pam_irlume_view', 'cdylib'),
}
EDGES = {**LIBRARY_EDGES, **ROOT_EDGES}
BEGIN = '// BEGIN HARDWARE EVIDENCE BOUNDARY'
END = '// END HARDWARE EVIDENCE BOUNDARY'


def metadata(root):
    result = subprocess.run(
        ['cargo', 'metadata', '--locked', '--offline', '--no-deps', '--format-version', '1'],
        cwd=root, check=True, capture_output=True, text=True, timeout=60,
    )
    return json.loads(result.stdout)


def check_graph(data):
    packages = {p['name']: p for p in data['packages']}
    if set(packages) != set(EDGES):
        raise ValueError('workspace package inventory changed; classify its build boundary')
    for name, p in packages.items():
        edges = {d['name'] for d in p['dependencies'] if d['kind'] is None and d['name'] in packages}
        if edges != set(EDGES[name]):
            raise ValueError(f'{name}: normal internal dependency edges changed')
    roots = {(p['name'], t['name'], kind) for p in packages.values()
             for t in p['targets'] for kind in t['kind'] if kind in {'bin', 'cdylib'}}
    expected = {(p, target, kind) for p, (target, kind) in ROOT_TARGETS.items()}
    if roots != expected:
        raise ValueError('shipped root inventory changed; classify its build boundary')
    return packages


def check_sources(root, data):
    packages = check_graph(data)
    lint = tomllib.loads((root / 'Cargo.toml').read_text()).get('workspace', {}).get('lints', {}).get('rust', {}).get('unexpected_cfgs', {})
    if lint.get('level') not in {'warn', 'deny', 'forbid'} or 'cfg(irlume_hw_evidence)' not in lint.get('check-cfg', []):
        raise ValueError('the evidence cfg must be registered without weakening cfg checks')
    for name, p in packages.items():
        manifest = Path(p['manifest_path'])
        if tomllib.loads(manifest.read_text()).get('lints', {}).get('workspace') is not True:
            raise ValueError(f'{name}: workspace lint inheritance is missing')
        target_name, kind = ROOT_TARGETS[name] if name in ROOT_TARGETS else (name.replace('-', '_'), 'lib')
        targets = [t for t in p['targets'] if t['name'] == target_name and kind in t['kind']]
        if len(targets) != 1:
            raise ValueError(f'{name}: expected exactly one classified target')
        source_path = Path(targets[0]['src_path'])
        source_path.resolve().relative_to(root.resolve())
        source = source_path.read_text()
        block = active_boundary(source)
        dependencies = {d.replace('-', '_') for d in EDGES[name] if d in LIBRARY_EDGES}
        check_block(block, name, dependencies, name in ROOT_TARGETS)
        if name in {'irlume-cli', 'irlume-daemon'}:
            check_main(source)
    print(f'evidence-build: source contract passes for {len(packages)} packages and {len(ROOT_TARGETS)} shipped roots')


@dataclass(frozen=True)
class RustToken:
    kind: str
    text: str
    depth: int
    start: int
    end: int


def rust_tokens(source):
    """Lex enough Rust to reject comment/literal and nested-item decoys."""
    raw = re.compile(r'(?:br|cr|r)(#{0,255})"')
    quoted = re.compile(r'(?:b|c)?"')
    character = re.compile(r"(?:b)?'(?:[^'\\\n]|\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|[^\n]))'")
    identifier = re.compile(r'(?:r#)?[A-Za-z_][A-Za-z_0-9]*')
    i, delimiters = 0, []
    pairs = {')': '(', ']': '[', '}': '{'}
    while i < len(source):
        if source[i].isspace():
            i += 1
            continue
        start, kind = i, 'code'
        if source.startswith('//', i):
            end = source.find('\n', i)
            i = len(source) if end < 0 else end
            kind = 'line-comment'
        elif source.startswith('/*', i):
            nesting, i = 1, i + 2
            while nesting and i < len(source):
                if source.startswith('/*', i):
                    nesting, i = nesting + 1, i + 2
                elif source.startswith('*/', i):
                    nesting, i = nesting - 1, i + 2
                else:
                    i += 1
            if nesting:
                raise ValueError('unterminated Rust block comment')
            kind = 'block-comment'
        elif match := raw.match(source, i):
            closing = '"' + match[1]
            end = source.find(closing, match.end())
            if end < 0:
                raise ValueError('unterminated Rust raw string')
            i, kind = end + len(closing), 'literal'
        elif match := quoted.match(source, i):
            i = match.end()
            while i < len(source) and source[i] != '"':
                i += 2 if source[i] == '\\' else 1
            if i >= len(source):
                raise ValueError('unterminated Rust string')
            i, kind = i + 1, 'literal'
        elif match := character.match(source, i):
            i, kind = match.end(), 'literal'
        elif match := identifier.match(source, i):
            i = match.end()
        else:
            if source[i] in pairs:
                if not delimiters or delimiters.pop() != pairs[source[i]]:
                    raise ValueError('unbalanced Rust delimiters')
            i += 1
        yield RustToken(kind, source[start:i], len(delimiters), start, i)
        if kind == 'code' and source[start:i] in {'(', '[', '{'}:
            delimiters.append(source[start:i])
    if delimiters:
        raise ValueError('unbalanced Rust delimiters')


def compact(source):
    return ''.join(t.text for t in rust_tokens(source) if not t.kind.endswith('comment')).replace(',);', ');')


def active_boundary(source):
    tokens = list(rust_tokens(source))
    begin = [t for t in tokens if t.kind == 'line-comment' and t.depth == 0 and t.text.rstrip() == BEGIN]
    end = [t for t in tokens if t.kind == 'line-comment' and t.depth == 0 and t.text.rstrip() == END]
    if len(begin) != 1 or len(end) != 1 or begin[0].end >= end[0].start:
        raise ValueError('missing, repeated or inactive evidence-boundary block')
    preceding = [t for t in tokens if t.end <= begin[0].start and not t.kind.endswith('comment')]
    if preceding and preceding[-1].text not in {';', '}'}:
        raise ValueError('an outside attribute or unfinished item precedes the boundary')
    return source[begin[0].end:end[0].start]


def marker_inputs(expression):
    terms = re.sub(r'\s+', '', expression).split('||')
    if not terms or terms.pop(0) != 'cfg!(irlume_hw_evidence)':
        raise ValueError('marker must begin with its own evidence cfg')
    sources = []
    for term in terms:
        match = re.fullmatch(r'(irlume_[a-z_]+)::HARDWARE_EVIDENCE_BUILD', term)
        if not match:
            raise ValueError(f'unsupported marker term: {term}')
        sources.append(match[1])
    if len(set(sources)) != len(sources):
        raise ValueError('duplicate marker dependency')
    return set(sources)


def expected_block(package, dependencies, shipped):
    parts = []
    named = not shipped or package in {'irlume-cli', 'irlume-daemon'}
    if shipped:
        parts.extend([
            '#[cfg(irlume_hw_evidence)]',
            f'compile_error!("irlume evidence build refused: {package}/direct");',
        ])
    if dependencies or not shipped:
        terms = ['cfg!(irlume_hw_evidence)']
        terms.extend(f'{name}::HARDWARE_EVIDENCE_BUILD' for name in sorted(dependencies))
        expression = ' || '.join(terms)
        visibility = '' if shipped else 'pub '
        if named:
            parts.append(f'{visibility}const HARDWARE_EVIDENCE_BUILD: bool = {expression};')
    if dependencies:
        if not shipped:
            parts.append('#[cfg(not(irlume_hw_evidence))]')
        condition = '!HARDWARE_EVIDENCE_BUILD' if named else f'!({expression})'
        parts.append(f'const _: () = assert!({condition}, "irlume evidence build refused: {package}/dependency");')
    return '\n'.join(parts)


def check_block(source, package, dependencies, shipped):
    normal = compact(source)
    named = not shipped or package in {'irlume-cli', 'irlume-daemon'}
    pattern = r'constHARDWARE_EVIDENCE_BUILD:bool=([^;]+);' if named else r'assert!\(!\((.+)\),'
    found = re.findall(pattern, normal)
    if dependencies or not shipped:
        if len(found) != 1 or marker_inputs(found[0]) != dependencies:
            raise ValueError(f'{package}: marker dependency set differs')
    if normal != compact(expected_block(package, dependencies, shipped)):
        raise ValueError(f'{package}: guard differs from the reviewed form')


def check_main(source):
    tokens = [t for t in rust_tokens(source) if not t.kind.endswith('comment')]
    mains = [i for i, t in enumerate(tokens[:-1]) if t.kind == 'code' and t.depth == 0
             and t.text == 'fn' and tokens[i + 1].text == 'main']
    if len(mains) != 1:
        raise ValueError('expected exactly one active top-level main')
    opening = next((i for i in range(mains[0], len(tokens)) if tokens[i].text == '{' and tokens[i].depth == 0), None)
    if opening is None:
        raise ValueError('main body not found')
    expected = [t.text for t in rust_tokens('irlume_common::build_mode::refuse_evidence_startup(HARDWARE_EVIDENCE_BUILD);')]
    actual = [t.text for t in tokens[opening + 1:opening + 1 + len(expected)]]
    if actual != expected:
        raise ValueError('startup refusal must be the first executable main statement')


@dataclass(frozen=True)
class CompilerCase:
    name: str
    packages: tuple[str, ...]
    marked: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    global_cfg: bool = False


def reachable(package):
    found = set()
    pending = list(EDGES[package])
    while pending:
        current = pending.pop()
        if current not in found:
            found.add(current)
            pending.extend(EDGES[current])
    return found


def compiler_cases():
    cases = [CompilerCase('normal', tuple(EDGES)), CompilerCase(
        'global', tuple(EDGES), diagnostics=tuple(f'{p}/direct' for p in ROOT_TARGETS), global_cfg=True)]
    for package in ROOT_TARGETS:
        cases.append(CompilerCase(f'root-only-{package}', (package,), (package,), (f'{package}/direct',)))
    consumers = {
        'irlume-common': 'irlume-gkr-unlock', 'irlume-camera': 'irlume-cli',
        'irlume-vision': 'irlume-cli', 'irlume-liveness': 'irlume-daemon',
        'irlume-core': 'irlume-daemon', 'irlume-auth': 'irlume-daemon',
        'irlume-fingerprint': 'irlume-cli',
    }
    for library, root in consumers.items():
        diagnostics = tuple(f'{p}/dependency' for p in sorted(reachable(root) | {root})
                            if library in reachable(p))
        cases.append(CompilerCase(f'reverse-{library}', (root,), (library,), diagnostics))
    for root, dependencies in ROOT_EDGES.items():
        if any(d in LIBRARY_EDGES for d in dependencies):
            cases.append(CompilerCase(f'root-dependencies-{root}', (root,), tuple(LIBRARY_EDGES), (f'{root}/dependency',)))
    for library, dependencies in LIBRARY_EDGES.items():
        if dependencies:
            marked = tuple(p for p in LIBRARY_EDGES if p != library)
            cases.append(CompilerCase(f'library-dependencies-{library}', (library,), marked, (f'{library}/dependency',)))
    cases.append(CompilerCase('auth-liveness-edge', ('irlume-auth',), ('irlume-liveness',), ('irlume-auth/dependency',)))
    cases.append(CompilerCase('marked-libraries', tuple(LIBRARY_EDGES), tuple(LIBRARY_EDGES)))
    if len(cases) > 32:
        raise ValueError('compiler matrix exceeds its reviewed process budget')
    return cases


WRAPPER = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

config = json.loads(Path(__file__).with_suffix('.json').read_text())
compiler, *args = sys.argv[1:]
probe = any(a == '--print' or a.startswith('--print=') for a in args)
crate = args[args.index('--crate-name') + 1] if '--crate-name' in args and not probe else None
if crate is not None and crate not in config['known']:
    raise SystemExit('unclassified workspace compiler unit: ' + crate)
if crate in config['inject']:
    args.extend(['--cfg', 'irlume_hw_evidence'])
marked = '--cfg=irlume_hw_evidence' in args or any(
    a == '--cfg' and i + 1 < len(args) and args[i + 1] == 'irlume_hw_evidence'
    for i, a in enumerate(args))
if crate is not None:
    row = json.dumps(dict(crate=crate, marked=marked, args=args)) + '\n'
    data = row.encode()
    fd = os.open(config['receipts'], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise SystemExit('incomplete compiler receipt')
    finally:
        os.close(fd)
os.execvp(compiler, [compiler, *args])
'''


def compiler_name(package):
    return ROOT_TARGETS[package][0].replace('-', '_') if package in ROOT_TARGETS else package.replace('-', '_')


def make_wrapper(directory, case):
    wrapper = directory / 'rustc-wrapper.py'
    receipts = directory / 'compiler.jsonl'
    config = dict(known=[compiler_name(p) for p in EDGES],
                  inject=[] if case.global_cfg else [compiler_name(p) for p in case.marked],
                  receipts=str(receipts.resolve()))
    wrapper.write_text(WRAPPER)
    wrapper.with_suffix('.json').write_text(json.dumps(config))
    wrapper.chmod(0o700)
    return wrapper, receipts


def check_receipts(case, rows, output, status):
    if not rows:
        raise ValueError(f'{case.name}: no workspace compiler invocation recorded')
    names = {compiler_name(p): p for p in EDGES}
    observed = set()
    for row in rows:
        if row['crate'] not in names:
            raise ValueError(f'{case.name}: unclassified compiler invocation')
        package = names[row['crate']]
        observed.add(package)
        if row['marked'] != (case.global_cfg or package in case.marked):
            raise ValueError(f'{case.name}: wrong cfg marking for {package}')
    if case.diagnostics:
        matches = [d for d in case.diagnostics if f'irlume evidence build refused: {d}' in output]
        if status != 101 or not matches:
            raise ValueError(f'{case.name}: missing intended compiler refusal')
        if not any(d.split('/')[0] in observed for d in matches):
            raise ValueError(f'{case.name}: refusing crate was not compiled')
        selected = set(case.packages)
        selected.update(*(reachable(p) for p in case.packages))
        if not (set(case.marked) & selected) <= observed:
            raise ValueError(f'{case.name}: the marked dependency was not compiled')
    elif status != 0 or not set(case.packages) <= observed:
        raise ValueError(f'{case.name}: positive build did not compile every selected target')


def wait_compiler(command, root, env, log, timeout):
    """Own and clean up one compiler process group, including on cancellation."""
    cancelled = [None]
    signals = (signal.SIGINT, signal.SIGTERM)
    previous = {sig: signal.getsignal(sig) for sig in signals}
    process = None

    def remember_signal(signum, _frame):
        cancelled[0] = signum

    try:
        for sig in signals:
            signal.signal(sig, remember_signal)
        if cancelled[0] is not None:
            raise SystemExit(128 + cancelled[0])
        process = subprocess.Popen(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + timeout
        while True:
            if cancelled[0] is not None:
                raise SystemExit(128 + cancelled[0])
            # Observe without reaping: the leader's PID continues to identify
            # this owned group until its descendants have been stopped.
            status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('compiler deadline exceeded')
            time.sleep(min(remaining, 0.05))
    finally:
        try:
            if process is not None:
                # Also clean up after a normal leader exit. It may have left a
                # descendant, and cancellation may race with that exit.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    status = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise ValueError(f'compiler process {process.pid} could not be reaped within five seconds') from None
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    if cancelled[0] is not None:
        raise SystemExit(128 + cancelled[0])
    return status


def run_compiler_matrix(root, cargo, output_dir, selected=None):
    cases = compiler_cases()
    if selected is not None:
        cases = [case for case in cases if case.name == selected]
        if len(cases) != 1:
            raise ValueError('unknown compiler case: ' + selected)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    summaries = []
    for case in cases:
        directory = output_dir / case.name
        directory.mkdir(mode=0o700)
        wrapper, receipts = make_wrapper(directory, case)
        env = os.environ.copy()
        for name in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC']:
            env.pop(name, None)
        env.update(RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER=str(wrapper.resolve()),
                   CARGO_ENCODED_RUSTFLAGS='--cfg\x1firlume_hw_evidence' if case.global_cfg else '',
                   CARGO_BUILD_JOBS='4', CARGO_TERM_COLOR='never')
        command = [*cargo, 'check', '--locked', '--offline']
        for package in case.packages:
            command.extend(['-p', package])
        if all(p in LIBRARY_EDGES for p in case.packages):
            command.append('--lib')
        elif len(case.packages) == 1:
            target, kind = ROOT_TARGETS[case.packages[0]]
            command.extend(['--bin', target] if kind == 'bin' else ['--lib'])
        (directory / 'command.json').write_text(json.dumps(command) + '\n')
        started = time.monotonic()
        with (directory / 'build.log').open('w') as log:
            status = wait_compiler(command, root, env, log, 600)
        output = (directory / 'build.log').read_text()
        rows = [json.loads(line) for line in receipts.read_text().splitlines()] if receipts.exists() else []
        (directory / 'result.json').write_text(json.dumps(dict(returncode=status)) + '\n')
        check_receipts(case, rows, output, status)
        summary = dict(case=case.name, status='pass', compiler_calls=len(rows), seconds=round(time.monotonic() - started, 3))
        summaries.append(summary)
        print(json.dumps(summary), flush=True)
    (output_dir / 'summary.json').write_text(json.dumps(summaries, indent=2) + '\n')
    print(f'evidence-build: {len(summaries)} compiler cases passed; receipts in {output_dir}', flush=True)


class ContractTests(unittest.TestCase):
    def test_cancellation_reaps_the_owned_compiler_group(self):
        for sig in [signal.SIGINT, signal.SIGTERM]:
            self.cancellation_case(sig, leader_exits=False)

    def test_cancellation_after_group_leader_exit_stops_descendants(self):
        self.cancellation_case(signal.SIGTERM, leader_exits=True)

    def cancellation_case(self, sig, leader_exits):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            record = directory / 'owned-pids.json'
            child = (
                'import json,os,pathlib,subprocess,sys,time; '
                f'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)",{str(record)!r}]); '
                f'path=pathlib.Path({str(record)!r}); temporary=path.with_suffix(".tmp"); '
                'temporary.write_text(json.dumps([os.getpid(),p.pid])); temporary.replace(path); '
                + ('sys.exit(0)' if leader_exits else 'time.sleep(60)')
            )
            after_exit = ''
            if leader_exits:
                after_exit = (
                    'original_wait=subprocess.Popen.wait\n'
                    'def cancelled_wait(self,*args,**kwargs):\n'
                    '    result=original_wait(self,*args,**kwargs)\n'
                    f'    os.kill(os.getpid(),{sig})\n'
                    '    return result\n'
                    'subprocess.Popen.wait=cancelled_wait\n'
                )
            driver = directory / 'driver.py'
            driver.write_text(
                'import os,runpy,subprocess,sys\nfrom pathlib import Path\n'
                f'm=runpy.run_path({str(Path(__file__).resolve())!r})\n' + after_exit +
                f'with open({str(directory / "compiler.log")!r}, "w") as log:\n'
                f'    m["wait_compiler"]([sys.executable,"-c",{child!r}],Path.cwd(),os.environ.copy(),log,30)\n'
            )
            process = subprocess.Popen([sys.executable, str(driver)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            pids = []
            try:
                deadline = time.monotonic() + 5
                while not record.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(record.exists(), 'compiler driver did not start')
                pids = json.loads(record.read_text())
                if not leader_exits:
                    process.send_signal(sig)
                process.communicate(timeout=8)
                self.assertEqual(process.returncode, 128 + sig)
                deadline = time.monotonic() + 5
                while self.running_pids(pids) and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(self.running_pids(pids), 'owned compiler descendants remained alive')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
                for pid in pids:
                    try:
                        command = Path(f'/proc/{pid}/cmdline').read_bytes()
                        if str(record).encode() in command and os.getpgid(pid) == pids[0]:
                            os.killpg(pids[0], signal.SIGKILL)
                            break
                    except ProcessLookupError:
                        pass
                    except FileNotFoundError:
                        pass

    @staticmethod
    def running_pids(pids):
        running = []
        for pid in pids:
            try:
                text = Path(f'/proc/{pid}/stat').read_text()
                if not text:
                    continue
                state = text.rsplit(')', 1)[1].split()[0]
                if state != 'Z':
                    running.append(pid)
            except (FileNotFoundError, ProcessLookupError):
                pass
        return running

    def test_compiler_deadline_is_bounded(self):
        with tempfile.TemporaryFile(mode='w') as log:
            with self.assertRaisesRegex(ValueError, 'deadline exceeded'):
                wait_compiler([sys.executable, '-c', 'import time; time.sleep(60)'], ROOT, os.environ.copy(), log, 0.1)

    def test_compiler_receipts_reject_unrelated_failures_and_wrong_marking(self):
        case = next(c for c in compiler_cases() if c.name == 'root-only-irlume-cli')
        rows = [dict(crate='irlume', marked=True)]
        message = 'irlume evidence build refused: irlume-cli/direct'
        check_receipts(case, rows, message, 101)
        for wrong_rows, wrong_message, status in [
            ([], message, 101), (rows, 'unrelated error', 101),
            ([dict(crate='irlume', marked=False)], message, 101),
            (rows, message, 0),
        ]:
            with self.assertRaises(ValueError):
                check_receipts(case, wrong_rows, wrong_message, status)

    def test_wrapper_records_and_marks_only_the_selected_compiler_unit(self):
        with tempfile.TemporaryDirectory() as temporary:
            wrapper, receipts = make_wrapper(Path(temporary), CompilerCase('sample', ('irlume-auth',), ('irlume-auth',)))
            for name, marked in [('irlume_auth', True), ('irlume_common', False)]:
                result = subprocess.run(
                    [sys.executable, str(wrapper), sys.executable, '-c',
                     'import json,sys; print(json.dumps(sys.argv[1:]))', '--crate-name', name],
                    check=True, capture_output=True, text=True, timeout=10,
                )
                forwarded = json.loads(result.stdout)
                self.assertEqual('irlume_hw_evidence' in forwarded, marked)
            rows = [json.loads(line) for line in receipts.read_text().splitlines()]
            self.assertEqual([(r['crate'], r['marked']) for r in rows], [('irlume_auth', True), ('irlume_common', False)])

    def test_compiler_cases_cover_roots_libraries_and_the_unmasked_edge(self):
        cases = compiler_cases()
        self.assertEqual(len(cases), 29)
        self.assertEqual(len({case.name for case in cases}), len(cases))
        self.assertEqual({case.packages[0] for case in cases if case.name.startswith('root-only-')}, set(ROOT_TARGETS))
        edge = next(case for case in cases if case.name == 'auth-liveness-edge')
        self.assertEqual(edge.marked, ('irlume-liveness',))
        self.assertEqual(edge.diagnostics, ('irlume-auth/dependency',))

    def test_existing_root_cannot_gain_an_unchecked_dependency(self):
        packages = []
        for name, edges in EDGES.items():
            target, kind = ROOT_TARGETS[name] if name in ROOT_TARGETS else (name.replace('-', '_'), 'lib')
            packages.append(dict(name=name, dependencies=[dict(name=d, kind=None) for d in edges],
                                 targets=[dict(name=target, kind=[kind])]))
        data = {'packages': packages}
        check_graph(data)
        helper = next(p for p in packages if p['name'] == 'irlume-gkr-unlock')
        helper['dependencies'].append(dict(name='irlume-vision', kind=None))
        with self.assertRaisesRegex(ValueError, 'dependency edges changed'):
            check_graph(data)

    def test_marker_inputs_are_exact_and_cannot_omit_one_dependency(self):
        expression = 'cfg!(irlume_hw_evidence) || irlume_common::HARDWARE_EVIDENCE_BUILD || irlume_vision::HARDWARE_EVIDENCE_BUILD'
        self.assertEqual(marker_inputs(expression), {"irlume_common", "irlume_vision"})
        for invalid in [
            expression.replace(' || ', ' && ', 1),
            expression.replace('cfg!(irlume_hw_evidence)', 'false'),
            expression + ' || irlume_common::HARDWARE_EVIDENCE_BUILD',
            expression + ' || true',
        ]:
            with self.assertRaises(ValueError):
                marker_inputs(invalid)

    def test_block_rejects_dependency_loss_and_changed_guard_operand(self):
        block = expected_block('irlume-auth', {'irlume_common', 'irlume_liveness'}, False)
        check_block(block, 'irlume-auth', {'irlume_common', 'irlume_liveness'}, False)
        for invalid in [
            block.replace(' || irlume_liveness::HARDWARE_EVIDENCE_BUILD', ''),
            block.replace('!HARDWARE_EVIDENCE_BUILD', 'true'),
            block.replace('#[cfg(not(irlume_hw_evidence))]', '#[cfg(debug_assertions)]'),
        ]:
            with self.assertRaises(ValueError):
                check_block(invalid, 'irlume-auth', {'irlume_common', 'irlume_liveness'}, False)

    def test_shipped_block_requires_both_direct_and_dependency_refusal(self):
        block = expected_block('irlume-cli', {'irlume_auth'}, True)
        check_block(block, 'irlume-cli', {'irlume_auth'}, True)
        for invalid in [
            block.replace('compile_error!', 'println!'),
            block.replace('assert!(!HARDWARE_EVIDENCE_BUILD', 'assert!(true'),
        ]:
            with self.assertRaises(ValueError):
                check_block(invalid, 'irlume-cli', {'irlume_auth'}, True)

    def test_compile_only_root_assertions_keep_exact_dependency_inputs(self):
        block = expected_block('irlume-pam', {'irlume_common'}, True)
        self.assertNotIn('const HARDWARE_EVIDENCE_BUILD', block)
        check_block(block, 'irlume-pam', {'irlume_common'}, True)
        with self.assertRaises(ValueError):
            check_block(block.replace(' || irlume_common::HARDWARE_EVIDENCE_BUILD', ''), 'irlume-pam', {'irlume_common'}, True)

    def test_main_wiring_must_be_first_and_use_the_aggregate(self):
        call = 'irlume_common::build_mode::refuse_evidence_startup(HARDWARE_EVIDENCE_BUILD);'
        check_main('fn main() { // comment\n' + call + '\n work(); }')
        check_main('fn main() -> std::process::ExitCode {\n' + call + '\n work(); }')
        for body in ['work(); ' + call, call.replace('HARDWARE_EVIDENCE_BUILD', 'false')]:
            with self.assertRaises(ValueError):
                check_main('fn main() { ' + body + ' }')

    def test_inactive_or_nested_main_cannot_supply_the_startup_guard(self):
        call = 'irlume_common::build_mode::refuse_evidence_startup(HARDWARE_EVIDENCE_BUILD);'
        decoys = [
            '/* nested /* comment */ fn main() { ' + call + ' } */',
            'const TEXT: &str = r##"fn main() { ' + call + ' }"##;',
            'const TEXT: &str = "fn main() { ' + call + ' }";',
            'mod nested { fn main() { ' + call + ' } }',
            'macro_rules! ignore { ($($t:tt)*) => {}; } ignore!(fn main() { ' + call + ' });',
            'macro_rules! ignore { ($($t:tt)*) => {}; } ignore![fn main() { ' + call + ' }];',
        ]
        for decoy in decoys:
            with self.assertRaises(ValueError):
                check_main(decoy + '\nfn main() { work(); }')
            check_main(decoy + '\nfn main() { ' + call + ' work(); }')
        with self.assertRaises(ValueError):
            check_main('fn main() { fn nested() { ' + call + ' } work(); }')

    def test_boundary_markers_must_be_active_top_level_line_comments(self):
        block = BEGIN + '\n' + expected_block('irlume-pam-view', set(), True) + '\n' + END
        for decoy in ['/* ' + block + ' */', 'const S: &str = r#"' + block + '"#;', 'mod nested {\n' + block + '\n}',
                      'ignore!(\n' + block + '\n);', 'ignore![\n' + block + '\n];']:
            with self.assertRaises(ValueError):
                active_boundary(decoy)
            self.assertEqual(compact(active_boundary(decoy + '\n' + block)), compact(expected_block('irlume-pam-view', set(), True)))

    def test_boundary_cannot_be_hidden_by_an_outside_attribute(self):
        block = BEGIN + '\n' + expected_block('irlume-pam-view', set(), True) + '\n' + END
        with self.assertRaises(ValueError):
            active_boundary('#[cfg(any())]\n' + block)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--source-check', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--case')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--toolchain')
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[sys.argv[0]])
    elif args.source_check or args.check:
        try:
            check_sources(ROOT, metadata(ROOT))
            if args.check:
                cargo = ['cargo', '+' + args.toolchain] if args.toolchain else ['cargo']
                output = args.output or Path(tempfile.gettempdir()) / f'irlume-evidence-build-{time.time_ns()}'
                run_compiler_matrix(ROOT, cargo, output, args.case)
        except ValueError as error:
            raise SystemExit(f'evidence-build: {error}') from error
    else:
        parser.error('choose --self-test, --source-check or --check')
