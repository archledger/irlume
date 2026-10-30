#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Compile the CPU-reference boundary, including unified dependency features."""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import runpy
import shutil
import sys
import tempfile
import time
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = {'cuda': 'CUDA', 'openvino': 'OpenVINO', 'coreml': 'CoreML', 'tensorrt': 'TensorRT'}
REFUSAL = 'irlume evidence reference refused: '


@dataclass(frozen=True)
class Case:
    name: str
    features: tuple = ()
    evidence: bool = True
    no_defaults: bool = False
    unified: bool = False
    diagnostic: str = ''


def cases():
    result = [
        Case('normal', evidence=False),
        Case('evidence'),
        Case('evidence-npu', ('npu',)),
        Case('normal-minimal', evidence=False, no_defaults=True),
        Case('evidence-minimal', no_defaults=True, diagnostic=REFUSAL + 'requires onnx'),
    ]
    for feature, symbol in PROVIDERS.items():
        result.extend([
            Case('direct-' + feature, ('ort/' + feature,), diagnostic=f'`{symbol}` is ambiguous'),
            Case('direct-minimal-' + feature, ('ort/' + feature,), no_defaults=True,
                 diagnostic=REFUSAL + 'requires onnx'),
            Case('unified-' + feature, (feature,), unified=True, diagnostic=f'`{symbol}` is ambiguous'),
        ])
    return result


def prepare_unifier(directory, feature):
    """A second normal dependency enables ort without vision's own feature."""
    fixture = directory / 'unifier'
    fixture.mkdir()
    (fixture / 'src').mkdir()
    (fixture / 'src/lib.rs').write_text('// Compiler fixture: no runtime entry.\n')
    ort = dict(tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['dependencies']['ort'])
    ort['features'] = [*ort['features'], feature]
    dependency = ', '.join(f'{key} = {json.dumps(value)}' for key, value in ort.items())
    (fixture / 'Cargo.toml').write_text(
        '[package]\nname = "irlume-reference-unifier"\nversion = "0.0.0"\nedition = "2021"\n'
        '[workspace]\n[dependencies]\n'
        f'irlume-vision = {{ path = {json.dumps(str(ROOT / "crates/irlume-vision"))} }}\n'
        f'ort = {{ {dependency} }}\n'
    )
    shutil.copy2(ROOT / 'Cargo.lock', fixture / 'Cargo.lock')
    return fixture


def run_matrix(cargo, output, selected):
    selected_cases = [case for case in cases() if selected is None or case.name == selected]
    if not selected_cases:
        raise ValueError('unknown compiler case: ' + selected)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Reuse the tested timeout/cancellation cleanup, including orphaned children.
    wait = runpy.run_path(str(ROOT / 'scripts/test-evidence-build-boundary.py'))['wait_compiler']
    summaries = []
    for case in selected_cases:
        directory = output / case.name
        directory.mkdir(mode=0o700)
        env = os.environ.copy()
        for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC']:
            env.pop(key, None)
        env.update(CARGO_ENCODED_RUSTFLAGS='--cfg\x1firlume_hw_evidence' if case.evidence else '',
                   CARGO_BUILD_JOBS='4', CARGO_TERM_COLOR='never')
        env.setdefault('CARGO_TARGET_DIR', str((output / 'target').resolve()))
        command = [*cargo, 'check', '--locked', '--offline', '--lib']
        if case.unified:
            fixture = prepare_unifier(directory, case.features[0])
            # Add only the fixture to a copy of the workspace lock, never the live lock.
            metadata_command = [*cargo, 'metadata', '--offline', '--format-version', '1',
                                '--manifest-path', str(fixture / 'Cargo.toml')]
            with (directory / 'metadata.log').open('w') as log:
                status = wait(metadata_command, ROOT, env, log, 120)
            if status:
                raise ValueError(f'{case.name}: fixture metadata failed')
            metadata = json.loads((directory / 'metadata.log').read_text().splitlines()[-1])
            names = {package['id']: package['name'] for package in metadata['packages']}
            features = {names[node['id']]: node['features'] for node in metadata['resolve']['nodes']}
            if case.features[0] not in features['ort'] or case.features[0] in features['irlume-vision']:
                raise ValueError(f'{case.name}: fixture did not independently unify ort features')
            command.extend(['--manifest-path', str(fixture / 'Cargo.toml')])
        else:
            command.extend(['-p', 'irlume-vision'])
            if case.features:
                command.extend(['--features', ','.join(case.features)])
            if case.no_defaults:
                command.append('--no-default-features')
        (directory / 'command.json').write_text(json.dumps(dict(command=command,
            encoded_rustflags=env['CARGO_ENCODED_RUSTFLAGS'])) + '\n')
        started = time.monotonic()
        with (directory / 'build.log').open('w') as log:
            status = wait(command, ROOT, env, log, 600)
        text = (directory / 'build.log').read_text()
        expected = 101 if case.diagnostic else 0
        if status != expected or (case.diagnostic and case.diagnostic not in text):
            raise ValueError(f'{case.name}: expected exit {expected} and diagnostic '
                             f'{case.diagnostic!r}, got {status}; see {directory / "build.log"}')
        summary = dict(case=case.name, status='pass', exit=status,
                       seconds=round(time.monotonic() - started, 3))
        (directory / 'result.json').write_text(json.dumps(summary) + '\n')
        summaries.append(summary)
        print(json.dumps(summary), flush=True)
    (output / 'summary.json').write_text(json.dumps(summaries, indent=2) + '\n')
    print(f'reference-isolation: {len(summaries)} compiler cases passed; receipts in {output}', flush=True)


class MatrixTests(unittest.TestCase):
    def test_every_provider_has_all_activation_routes(self):
        indexed = {case.name: case for case in cases()}
        self.assertEqual(len(indexed), 17)
        for feature, symbol in PROVIDERS.items():
            for route in ['direct-', 'direct-minimal-', 'unified-']:
                case = indexed[route + feature]
                self.assertTrue(case.evidence)
                self.assertTrue(case.diagnostic)
            self.assertTrue(indexed['unified-' + feature].unified)
            self.assertIn(symbol, indexed['direct-' + feature].diagnostic)
            self.assertTrue(indexed['direct-minimal-' + feature].no_defaults)

    def test_vision_has_no_provider_features_of_its_own(self):
        manifest = tomllib.loads((ROOT / 'crates/irlume-vision/Cargo.toml').read_text())
        self.assertFalse(set(PROVIDERS) & set(manifest['features']))

    def test_positive_controls_and_missing_reference(self):
        indexed = {case.name: case for case in cases()}
        for name in ['normal', 'evidence', 'evidence-npu', 'normal-minimal']:
            self.assertFalse(indexed[name].diagnostic)
        self.assertFalse(indexed['normal'].evidence)
        self.assertFalse(indexed['normal-minimal'].evidence)
        self.assertTrue(indexed['normal-minimal'].no_defaults)
        self.assertEqual(indexed['evidence-npu'].features, ('npu',))
        self.assertTrue(indexed['evidence-minimal'].no_defaults)
        self.assertIn('requires onnx', indexed['evidence-minimal'].diagnostic)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--case')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--toolchain')
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[sys.argv[0]])
    elif args.check:
        try:
            cargo = ['cargo', '+' + args.toolchain] if args.toolchain else ['cargo']
            output = args.output or Path(tempfile.gettempdir()) / f'irlume-reference-isolation-{time.time_ns()}'
            run_matrix(cargo, output.resolve(), args.case)
        except ValueError as error:
            raise SystemExit(f'reference-isolation: {error}') from error
    else:
        parser.error('choose --self-test or --check')
