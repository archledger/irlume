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
Start at `crates/irlume-pam/src/lib.rs` and `kcm/`; seeds go in
`fuzz/seeds/<target>/`, ADRs in `docs/adr/NNNN-*.md`, never `/etc/pam.d`.
Lanes: `ci.yml`. Build: `cargo check --features irlume-pam/extra`.
Tests: `crates/irlume-pam/tests/*.rs`. Every `.rs` file; `Cargo.toml`.

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
      - name: test
        run: |
          # the PAM crate
          cargo test --locked -p irlume-pam
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
        self.write("crates/irlume-daemon/src/main.rs", "")
        self.write("crates/irlume-daemon/AGENTS.md", "# Daemon\n\nStart at `src/main.rs`.\n")
        self.write("crates/irlume-cli/src/main.rs", "")
        self.write("kcm/CMakeLists.txt", "")
        self.write("Cargo.toml", "")
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
        self.assertEqual(count, 3)

    def test_a_moved_file_is_named(self):
        (self.root / "crates/irlume-pam/src/lib.rs").rename(self.root / "crates/irlume-pam/src/main.rs")
        self.assertEqual(self.problems(), ["AGENTS.md:4: path crates/irlume-pam/src/lib.rs names nothing in the tree"])

    def test_a_crate_relative_path_resolves_only_in_its_own_crate(self):
        (self.root / "crates/irlume-daemon/src/main.rs").unlink()
        self.assertEqual(self.problems(), ["crates/irlume-daemon/AGENTS.md:3: path src/main.rs names nothing in the tree"])

    def test_the_root_file_cites_full_paths(self):
        self.write("AGENTS.md", ROOT_DOC.replace("`kcm/`", "`src/lib.rs`"))
        self.assertEqual(self.problems(), ["AGENTS.md:4: path src/lib.rs names nothing in the tree"])

    def test_a_removed_root_file_cited_by_bare_name_is_named(self):
        (self.root / "Cargo.toml").unlink()
        self.assertEqual(self.problems(), ["AGENTS.md:7: path Cargo.toml names nothing in the tree"])

    def test_an_empty_gate_block_is_an_error(self):
        self.write("AGENTS.md", ROOT_DOC.replace("cargo fmt --all --check\ncargo test --locked -p irlume-pam\n", "# none\n"))
        self.assertEqual(self.problems(), ['AGENTS.md: no command block under "## Gate commands"'])

    def test_a_removed_top_level_directory_is_named(self):
        (self.root / "kcm/CMakeLists.txt").unlink()
        (self.root / "kcm").rmdir()
        self.assertEqual(self.problems(), ["AGENTS.md:4: path kcm/ names nothing in the tree"])

    def test_a_crate_relative_path_in_a_nested_file_is_checked(self):
        (self.root / "crates/irlume-pam/tests/pamwrap.rs").unlink()
        self.assertEqual(self.problems(), [
            "AGENTS.md:7: path crates/irlume-pam/tests/*.rs names nothing in the tree",
            "crates/irlume-pam/AGENTS.md:3: path tests/pamwrap.rs names nothing in the tree",
        ])

    def test_a_broken_link_is_named_and_an_anchor_is_ignored(self):
        (self.root / "CONTRIBUTING.md").unlink()
        found = self.problems()
        self.assertEqual(found, ["AGENTS.md:3: link target CONTRIBUTING.md does not exist"])

    def test_a_gate_command_ci_no_longer_runs_is_named(self):
        self.write(".github/workflows/ci.yml", CI.replace("--locked -p irlume-pam", "--locked --workspace"))
        self.assertEqual(self.problems(), [self.MISSING_TEST])

    MISSING_TEST = ("AGENTS.md:13: gate command is not a run line of the check job in "
                    ".github/workflows/ci.yml: cargo test --locked -p irlume-pam")

    def test_a_gate_command_only_another_job_runs_is_named(self):
        moved = CI.replace(
            "      - name: test\n        run: |\n          # the PAM crate\n          cargo test --locked -p irlume-pam\n",
            "")
        self.write(".github/workflows/ci.yml",
                   moved + "  stable:\n    steps:\n      - run: cargo test --locked -p irlume-pam\n")
        self.assertEqual(self.problems(), [self.MISSING_TEST])

    def test_a_workflow_without_the_check_job_is_an_error(self):
        self.write(".github/workflows/ci.yml", CI.replace("  check:", "  build:"))
        self.assertEqual(self.problems(), [
            "AGENTS.md: .github/workflows/ci.yml has no `check` job, so the gate commands cannot be checked"])

    def test_job_block_ends_at_the_next_job(self):
        workflow = "on: push\njobs:\n  check:\n    steps:\n      - run: a\n  other:\n    steps:\n      - run: b\n"
        self.assertEqual(checker.job_block(workflow, "check"), "  check:\n    steps:\n      - run: a")
        self.assertIsNone(checker.job_block(workflow, "missing"))

    def test_a_gate_command_left_only_in_a_comment_is_named(self):
        self.write(".github/workflows/ci.yml",
                   CI.replace("  cargo test --locked -p irlume-pam", "  # cargo test --locked -p irlume-pam"))
        self.assertEqual(self.problems(), [self.MISSING_TEST])

    def test_a_longer_ci_command_does_not_stand_in_for_a_gate_command(self):
        self.write(".github/workflows/ci.yml", CI.replace("-p irlume-pam", "-p irlume-pam -- --ignored"))
        self.assertEqual(self.problems(), [self.MISSING_TEST])

    def test_run_commands_reads_inline_and_block_steps(self):
        workflow = textwrap.dedent("""\
            jobs:
              check:
                defaults:
                  run:
                    shell: bash
                env:
                  run: job-env
                steps:
                  - run: 'cargo fmt --all --check'
                  - name: block
                    run: |
                      set -e
                      # not a command
                      cargo build

                  - name: next
                    env:
                      run: step-env
                    with:
                      args:
                        - run: nested-list
                    run: cargo doc
                after: not-a-step
              other:
                steps:
                - run: unindented list
            """)
        self.assertEqual(
            checker.run_commands(workflow),
            {"cargo fmt --all --check", "set -e", "cargo build", "cargo doc", "unindented list"},
        )

    def test_a_gate_command_kept_only_under_env_is_named(self):
        self.write(".github/workflows/ci.yml", CI.replace(
            "        run: |\n          # the PAM crate\n          cargo test --locked -p irlume-pam\n",
            "        env:\n          run: cargo test --locked -p irlume-pam\n        run: echo moved\n"))
        self.assertEqual(self.problems(), [self.MISSING_TEST])

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
        # Alone in its span, a path-shaped token is a path even when its first
        # segment is gone; inside a command, a feature is not.
        self.assertTrue(checker.is_path(bases, "gone/dir", whole_span=True))
        self.assertFalse(checker.is_path(bases, "gone/dir"))

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
