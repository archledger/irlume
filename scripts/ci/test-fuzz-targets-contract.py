#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""The CI fuzz step runs every fuzz target the tree declares.

The `fuzz` job in ci.yml names its targets by hand in a shell loop. A target
left out of that loop is never built in CI and its checked-in seeds are never
replayed. Four lists must name the same targets: that loop, the `[[bin]]`
entries of fuzz/Cargo.toml, the files in fuzz/fuzz_targets and the
directories in fuzz/seeds. Files only: no build, no network.
"""

from pathlib import Path
import re
import tomllib
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github/workflows/ci.yml"
FUZZ = ROOT / "fuzz"
THIS = "python3 -B scripts/ci/test-fuzz-targets-contract.py"


def loop_targets(run):
    """The names in the one `for t in ...; do` line of a fuzz step's script."""
    loops = re.findall(r"^[ \t]*for t in ([^;\n]+); do$", run, flags=re.M)
    if len(loops) != 1:
        raise AssertionError(f"expected one `for t in ...; do` line, found {len(loops)}")
    return loops[0].split()


def differences(lists):
    """One line per name that some list has and another lacks."""
    everything = set().union(*lists.values())
    return [
        f"{name}: missing from {where}"
        for name in sorted(everything)
        for where, names in lists.items()
        if name not in names
    ]


def fuzz_step():
    ci = yaml.safe_load(CI.read_text())
    steps = [
        step for step in ci["jobs"]["fuzz"]["steps"]
        if "cargo fuzz run" in str(step.get("run", ""))
    ]
    assert len(steps) == 1, "one step of the fuzz job runs the targets"
    return ci, steps[0]


class FuzzTargetContractTests(unittest.TestCase):
    def test_the_fuzz_step_runs_every_declared_target(self):
        ci, step = fuzz_step()
        job = ci["jobs"]["fuzz"]
        # A skipped job satisfies a required check, and a crash must fail the
        # step: no condition, no tolerated failure, the default `bash -e`.
        for scope in (job, step):
            self.assertNotIn("if", scope)
            self.assertNotIn("continue-on-error", scope)
        self.assertNotIn("shell", step)
        self.assertNotIn("defaults", job)
        self.assertNotIn("defaults", ci)
        self.assertEqual(step.get("working-directory"), "fuzz")
        lines = [line.strip() for line in step["run"].splitlines()]
        self.assertIn('cargo fuzz run "$t" -- -max_total_time=45 -rss_limit_mb=4096', lines)
        self.assertIn('cp -n "seeds/$t"/* "corpus/$t"/ 2>/dev/null || true', lines)
        loop = loop_targets(step["run"])
        self.assertEqual(len(loop), len(set(loop)), "a target is listed twice")

        bins = tomllib.loads((FUZZ / "Cargo.toml").read_text())["bin"]
        for entry in bins:
            self.assertEqual(entry["path"], f"fuzz_targets/{entry['name']}.rs")
        lists = {
            "the ci.yml fuzz loop": loop,
            "fuzz/Cargo.toml [[bin]]": [entry["name"] for entry in bins],
            # Hidden files are skipped, as the step's `seeds/$t/*` skips them.
            "fuzz/fuzz_targets": [
                p.stem for p in (FUZZ / "fuzz_targets").glob("*.rs")
                if not p.name.startswith(".")
            ],
            "fuzz/seeds": [
                p.name for p in (FUZZ / "seeds").iterdir()
                if p.is_dir() and any(
                    f.is_file() and not f.name.startswith(".") for f in p.iterdir()
                )
            ],
        }
        self.assertGreater(len(loop), 0, "the comparison must not become vacuous")
        self.assertEqual(differences(lists), [])

    def test_a_target_missing_from_one_list_is_reported(self):
        self.assertEqual(differences({"loop": ["a"], "bins": ["a", "b"], "seeds": ["b", "a"]}),
                         ["b: missing from loop"])
        self.assertEqual(differences({"loop": ["a", "b"], "bins": ["b", "a"]}), [])

    def test_the_loop_reader_takes_exactly_one_loop(self):
        self.assertEqual(loop_targets("cargo fetch --locked\n  for t in a b_c; do\n  done\n"),
                         ["a", "b_c"])
        with self.assertRaises(AssertionError):
            loop_targets("cargo fuzz run a\n")
        with self.assertRaises(AssertionError):
            loop_targets("for t in a; do\ndone\nfor t in b; do\ndone\n")

    def test_this_contract_runs_in_ci(self):
        ci, _ = fuzz_step()
        self.assertTrue(any(
            THIS in str(step.get("run", "")) and "if" not in step
            and "continue-on-error" not in step
            for step in ci["jobs"]["check"]["steps"]
        ), "the fuzz target contract must run in the check job")


if __name__ == "__main__":
    unittest.main()
