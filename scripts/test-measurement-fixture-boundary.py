#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Keep private fixture examples out of shipped targets and install sources."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
NAMES = ("measurement_fixture_bootstrap", "measurement_entry_probe", "measurement_generation_fixture",
          "measurement_namespace_probe", "measurement_job_fixture")


def check(metadata, sources):
    """Refuse changed target roles or explicit references from shipping inputs.

    This source/metadata guard is not an audit of arbitrary installer semantics.
    Runtime refusal and the existing shipped-root inventory remain separate gates.
    """
    found = []
    for package in metadata["packages"]:
        for target in package["targets"]:
            path = Path(target["src_path"]).resolve()
            if target["name"] not in NAMES and path.stem not in NAMES:
                continue
            expected = ROOT / "crates/irlume-common/examples" / (target["name"] + ".rs")
            if (package["name"] != "irlume-common" or target["name"] not in NAMES
                    or target["kind"] != ["example"] or path != expected):
                raise ValueError("private fixture target role or location changed")
            found.append(target["name"])
    if sorted(found) != sorted(NAMES):
        raise ValueError("expected exactly five private fixture examples")
    for path, text in sources.items():
        if any(name in text for name in NAMES):
            raise ValueError(f"private fixture referenced by shipping source: {path}")
        if not path.endswith(".rs") and any(token in text for token in
                                             ("/examples/*", "/examples/.", "--examples")):
            raise ValueError(f"example artifact selection in shipping source: {path}")


def check_repository():
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version=1"],
        cwd=ROOT, text=True))
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "packaging", "nix", "flake.nix", "scripts/install.sh",
         "scripts/install-*.sh", "scripts/build-*.sh", "crates/*/src/*.rs"], cwd=ROOT).split(b"\0")
    sources = {}
    for raw in paths:
        if not raw:
            continue
        path = raw.decode()
        if path.endswith(".md"):
            continue
        try:
            sources[path] = (ROOT / path).read_text()
        except UnicodeDecodeError:
            continue
    check(metadata, sources)
    print(f"fixture-boundary: five private examples, {len(sources)} shipping/source inputs checked")


class BoundaryTests(unittest.TestCase):
    def fixture(self):
        return {"packages": [{"name": "irlume-common", "targets": [
            {"name": name, "kind": ["example"],
             "src_path": str(ROOT / "crates/irlume-common/examples" / (name + ".rs"))}
            for name in NAMES]}]}

    def test_private_examples_are_accepted(self):
        self.assertEqual(NAMES, (
            "measurement_fixture_bootstrap", "measurement_entry_probe",
            "measurement_generation_fixture", "measurement_namespace_probe",
            "measurement_job_fixture"))
        check(self.fixture(), {"packaging/example.spec": "install irlume /usr/bin",
                               "scripts/install-host.sh": "cargo build --example tflite_runtime_probe\n"
                               'PROBE="$ROOT/target/release/examples/tflite_runtime_probe"'})

    def test_binary_reclassification_refuses(self):
        for index, name in enumerate(NAMES):
            for kind in (["bin"], ["lib"], ["test"], ["example", "bin"]):
                data = self.fixture()
                data["packages"][0]["targets"][index]["kind"] = kind
                with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                    check(data, {})

    def test_missing_duplicate_or_moved_example_refuses(self):
        base = self.fixture()
        for index, name in enumerate(NAMES):
            cases = [copy.deepcopy(base) for _ in range(3)]
            cases[0]["packages"][0]["targets"].pop(index)
            cases[1]["packages"][0]["targets"].append(copy.deepcopy(base["packages"][0]["targets"][index]))
            cases[2]["packages"][0]["targets"][index]["src_path"] = str(ROOT / "crates/irlume-common/src/main.rs")
            for variant, data in enumerate(cases):
                with self.subTest(name=name, variant=variant), self.assertRaises(ValueError):
                    check(data, {})

    def test_foreign_package_or_renamed_target_refuses(self):
        for index, name in enumerate(NAMES):
            for field, value in [("package", "irlume-cli"), ("target", "hidden_alias")]:
                data = self.fixture()
                if field == "package":
                    data["packages"][0]["name"] = value
                else:
                    data["packages"][0]["targets"][index]["name"] = value
                with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                    check(data, {})

    def test_install_references_or_example_wildcards_refuse(self):
        for text in [*(f"install {name} /usr/bin/" for name in NAMES),
                     "cp target/release/examples/* $out/bin/", "cargo build --examples",
                     "cp target/release/examples/. $out/bin/"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                check(self.fixture(), {"packaging/install.sh": text})

    def test_production_source_reference_refuses(self):
        for name in NAMES:
            for text in [f"mod {name};", f'#[path = "../examples/{name}.rs"] mod private;']:
                with self.subTest(name=name, text=text), self.assertRaises(ValueError):
                    check(self.fixture(), {"crates/irlume-common/src/lib.rs": text})


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(BoundaryTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        sys.exit(not (result.wasSuccessful() and result.testsRun == 6))
    if sys.argv[1:] == ["--check"]:
        check_repository()
        raise SystemExit(0)
    raise SystemExit("usage: test-measurement-fixture-boundary.py --self-test | --check")
