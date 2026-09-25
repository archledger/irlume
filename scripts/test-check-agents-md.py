#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Regressions for check-agents-md.py over a throwaway repository."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

SPEC = importlib.util.spec_from_file_location(
    "check_agents_md", Path(__file__).with_name("check-agents-md.py")
)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

ROOT_DOC = """\
# AGENTS.md

See [CONTRIBUTING.md](CONTRIBUTING.md) and [the PAM guide](crates/irlume-pam/AGENTS.md#rules).
Start at `crates/irlume-pam/src/lib.rs` and `src/lib.rs`; seeds go in
`fuzz/seeds/<target>/`, ADRs in `docs/adr/NNNN-*.md`, never `/etc/pam.d`.
Lanes: `ci.yml`. Build: `cargo check --features irlume-pam/extra`.
Tests: `crates/irlume-pam/tests/*.rs`.

## Gate commands

```sh
cargo fmt --all --check
cargo test --locked -p irlume-pam
```

## Next
"""

CI = """\
jobs:
  check:
    steps:
      - run: cargo fmt --all --check
      - run: cargo test --locked -p irlume-pam
"""


class CheckAgentsMdTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write("CONTRIBUTING.md", "# Contributing\n")
        self.write(".github/workflows/ci.yml", CI)
        self.write("crates/irlume-pam/src/lib.rs", "")
        self.write("crates/irlume-pam/tests/pamwrap.rs", "")
        self.write("crates/irlume-pam/AGENTS.md", "# PAM\n\nSee `tests/pamwrap.rs`.\n")
        self.write("AGENTS.md", ROOT_DOC)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(text), encoding="utf-8")

    def problems(self):
        return checker.check(self.root)[1]

    def test_a_true_tree_passes(self):
        count, problems = checker.check(self.root)
        self.assertEqual(problems, [])
        self.assertEqual(count, 2)

    def test_a_moved_file_is_named(self):
        (self.root / "crates/irlume-pam/src/lib.rs").rename(self.root / "crates/irlume-pam/src/main.rs")
        found = self.problems()
        self.assertTrue(any("crates/irlume-pam/src/lib.rs" in p for p in found), found)
        self.assertTrue(any("src/lib.rs names nothing" in p for p in found), found)

    def test_a_crate_relative_path_in_a_nested_file_is_checked(self):
        (self.root / "crates/irlume-pam/tests/pamwrap.rs").unlink()
        found = self.problems()
        self.assertTrue(any(p.startswith("crates/irlume-pam/AGENTS.md:3: path tests/pamwrap.rs") for p in found), found)
        self.assertTrue(any("crates/irlume-pam/tests/*.rs" in p for p in found), found)

    def test_a_broken_link_is_named_and_an_anchor_is_ignored(self):
        (self.root / "CONTRIBUTING.md").unlink()
        found = self.problems()
        self.assertEqual(found, ["AGENTS.md:3: link target CONTRIBUTING.md does not exist"])

    def test_a_gate_command_ci_no_longer_runs_is_named(self):
        self.write(".github/workflows/ci.yml", CI.replace("--locked -p irlume-pam", "--locked --workspace"))
        found = self.problems()
        self.assertEqual(found, ["AGENTS.md:13: gate command is not in .github/workflows/ci.yml: cargo test --locked -p irlume-pam"])

    def test_a_missing_gate_block_is_an_error(self):
        self.write("AGENTS.md", ROOT_DOC.replace("## Gate commands", "## Commands"))
        self.assertEqual(self.problems(), ['AGENTS.md: no command block under "## Gate commands"'])

    def test_a_renamed_workflow_is_named(self):
        (self.root / ".github/workflows/ci.yml").rename(self.root / ".github/workflows/build.yml")
        found = self.problems()
        self.assertIn("AGENTS.md:6: workflow ci.yml is not in .github/workflows/", found)
        self.assertIn("AGENTS.md: .github/workflows/ci.yml is missing, so the gate commands cannot be checked", found)

    def test_placeholders_absolute_paths_and_features_are_not_paths(self):
        bases = checker.bases_for(self.root, self.root / "AGENTS.md")
        for token in ("fuzz/seeds/<target>/", "docs/adr/NNNN-*.md", "/etc/pam.d",
                      "target/release/irlume", "irlume-pam/extra"):
            self.assertFalse(checker.is_path(bases, token), token)

    def test_paths_inside_code_fences_are_not_checked(self):
        self.write("AGENTS.md", ROOT_DOC + "\n```sh\ncat `docs/gone.md`\n```\n")
        self.assertEqual(self.problems(), [])

    def test_the_root_file_is_required(self):
        (self.root / "AGENTS.md").unlink()
        self.assertEqual(self.problems(), ["AGENTS.md: the root file is missing"])

    def test_the_real_tree_passes(self):
        repo = Path(__file__).resolve().parent.parent
        count, problems = checker.check(repo)
        self.assertEqual(problems, [])
        self.assertGreaterEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
