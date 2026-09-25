#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Regressions for check-agents-md.py over a throwaway repository."""
import importlib.util
import os
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

try:
    import yaml  # noqa: F401
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

needs_yaml = unittest.skipUnless(HAVE_YAML, "needs PyYAML (python3-yaml)")


def setUpModule():
    # The fixture repositories must not see the host's git setup: a global
    # excludes file or an inherited GIT_DIR (inside a hook) would change what
    # git lists.
    os.environ["GIT_CONFIG_GLOBAL"] = os.devnull
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
    for name in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_COMMON_DIR"):
        os.environ.pop(name, None)


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

TEST_STEP = "        run: |\n          # the PAM crate\n          cargo test --locked -p irlume-pam\n"

MISSING_TEST = ("AGENTS.md:13: gate command is not a run line of the check job in "
                ".github/workflows/ci.yml: cargo test --locked -p irlume-pam")


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
        target.write_text(text, encoding="utf-8")

    def problems(self):
        return checker.check(self.root)[1]

    def root_doc(self, extra):
        """The root file with `extra` added before the gate section."""
        self.write("AGENTS.md", ROOT_DOC.replace("## Gate commands", extra + "\n## Gate commands"))

    # Paths

    @needs_yaml
    def test_a_true_tree_passes(self):
        count, problems = checker.check(self.root)
        self.assertEqual(problems, [])
        self.assertEqual(count, 3)

    @needs_yaml
    def test_a_moved_file_is_named(self):
        (self.root / "crates/irlume-pam/src/lib.rs").rename(self.root / "crates/irlume-pam/src/main.rs")
        self.assertEqual(self.problems(),
                         ["AGENTS.md:4: path crates/irlume-pam/src/lib.rs names nothing in the tree"])

    @needs_yaml
    def test_a_crate_relative_path_resolves_only_in_its_own_crate(self):
        (self.root / "crates/irlume-daemon/src/main.rs").unlink()
        self.assertEqual(self.problems(),
                         ["crates/irlume-daemon/AGENTS.md:3: path src/main.rs names nothing in the tree"])

    @needs_yaml
    def test_the_root_file_cites_full_paths(self):
        self.write("AGENTS.md", ROOT_DOC.replace("`kcm/`", "`src/lib.rs`"))
        self.assertEqual(self.problems(), ["AGENTS.md:4: path src/lib.rs names nothing in the tree"])

    @needs_yaml
    def test_a_removed_top_level_directory_is_named(self):
        (self.root / "kcm/CMakeLists.txt").unlink()
        (self.root / "kcm").rmdir()
        self.assertEqual(self.problems(), ["AGENTS.md:4: path kcm/ names nothing in the tree"])

    @needs_yaml
    def test_a_removed_root_file_cited_by_bare_name_is_named(self):
        (self.root / "Cargo.toml").unlink()
        self.assertEqual(self.problems(), ["AGENTS.md:7: path Cargo.toml names nothing in the tree"])

    @needs_yaml
    def test_a_crate_relative_path_in_a_nested_file_is_checked(self):
        (self.root / "crates/irlume-pam/tests/pamwrap.rs").unlink()
        self.assertEqual(self.problems(), [
            "AGENTS.md:7: path crates/irlume-pam/tests/*.rs names nothing in the tree",
            "crates/irlume-pam/AGENTS.md:3: path tests/pamwrap.rs names nothing in the tree",
        ])

    @needs_yaml
    def test_a_code_span_wrapped_across_lines_is_read_whole(self):
        self.root_doc("Run `bash\nscripts/gone.sh` and read docs/guide or `Cargo.toml`.\n")
        self.assertEqual(self.problems(), ["AGENTS.md:9: path scripts/gone.sh names nothing in the tree"])

    @needs_yaml
    def test_prose_and_commands_are_not_paths(self):
        self.root_doc("Push to `origin/main` of `archledger/irlume`; `RGB/IR` cameras;\n"
                      "`irlume-auth/ir-only-evaluation`; `journalctl -u irlumed.service`;\n"
                      "`https://example.com/x.md`; `/etc/irlume/settings.conf`.\n")
        self.assertEqual(self.problems(), [])

    @needs_yaml
    def test_a_line_suffix_a_flag_and_an_env_prefix_are_stripped(self):
        self.root_doc("See `crates/gone/x.rs:42`, `cargo x --manifest-path=fuzz/Cargo.toml`\n"
                      "and `CONFIG=docs/gone.toml make`.\n")
        self.assertEqual(self.problems(), [
            "AGENTS.md:9: path crates/gone/x.rs names nothing in the tree",
            "AGENTS.md:9: path fuzz/Cargo.toml names nothing in the tree",
            "AGENTS.md:10: path docs/gone.toml names nothing in the tree",
        ])

    @needs_yaml
    def test_build_output_and_ignored_files_never_satisfy_a_citation(self):
        self.write(".gitignore", "/target\n/models/*.json\n")
        self.write("target/release/irlume", "")
        self.write("models/fetched.json", "")
        self.root_doc("Run `target/release/irlume`; weights in `models/fetched.json`.\n")
        self.assertEqual(self.problems(), ["AGENTS.md:9: path models/fetched.json names nothing in the tree"])

    @needs_yaml
    def test_an_ignored_agents_file_is_not_scanned(self):
        self.write(".gitignore", "/.claude/\n")
        self.write(".claude/x/AGENTS.md", "See `gone/file.rs`.\n")
        self.assertEqual(self.problems(), [])

    @needs_yaml
    def test_a_bare_yaml_name_resolves_in_github_or_the_crate(self):
        self.write(".github/dependabot.yml", "")
        self.write("crates/irlume-pam/tests/cases.yaml", "")
        self.root_doc("See `dependabot.yml` and `ci.yml`.\n")
        self.write("crates/irlume-pam/AGENTS.md", "# PAM\n\nSee `tests/pamwrap.rs` and `cases.yaml`.\n")
        self.assertEqual(self.problems(),
                         ["crates/irlume-pam/AGENTS.md:3: path cases.yaml names nothing in the tree"])
        self.write("crates/irlume-pam/AGENTS.md", "# PAM\n\nSee `tests/pamwrap.rs` and `tests/cases.yaml`.\n")
        self.assertEqual(self.problems(), [])

    @needs_yaml
    def test_a_renamed_workflow_is_named(self):
        (self.root / ".github/workflows/ci.yml").rename(self.root / ".github/workflows/build.yml")
        found = self.problems()
        self.assertIn("AGENTS.md:6: path ci.yml names nothing in the tree", found)
        self.assertIn("AGENTS.md: .github/workflows/ci.yml is missing, so the gate commands cannot be checked",
                      found)

    def test_placeholders_absolute_paths_and_features_are_not_paths(self):
        tree = checker.Tree(self.root)
        bases = checker.bases_for("")
        for token in ("fuzz/seeds/<target>/", "docs/adr/NNNN-*.md", "/etc/pam.d",
                      "target/release/irlume", "irlume-pam/extra", "origin/main"):
            self.assertFalse(checker.is_path(tree, bases, token, lone=True), token)
        self.assertTrue(checker.is_path(tree, bases, "gone/dir/", lone=True))
        self.assertTrue(checker.is_path(tree, bases, "Cargo.toml", lone=True))
        self.assertFalse(checker.is_path(tree, bases, "irlumed.service", lone=False))

    # Fences

    @needs_yaml
    def test_paths_inside_code_fences_are_not_checked(self):
        self.write("AGENTS.md", ROOT_DOC + "\n```sh\ncat `docs/gone.md`\n```\n\n~~~\n`docs/gone2.md`\n~~~\n")
        self.assertEqual(self.problems(), [])

    @needs_yaml
    def test_an_unclosed_fence_is_an_error(self):
        self.write("crates/irlume-pam/AGENTS.md", "# PAM\n\n```sh\nmake\n\n`src/gone.rs`\n")
        self.assertEqual(self.problems(), ["crates/irlume-pam/AGENTS.md:3: code fence is never closed"])

    # Links

    @needs_yaml
    def test_a_broken_link_is_named_and_an_anchor_is_ignored(self):
        (self.root / "CONTRIBUTING.md").unlink()
        self.assertEqual(self.problems(), ["AGENTS.md:3: link target CONTRIBUTING.md does not exist"])

    @needs_yaml
    def test_every_link_form_is_checked(self):
        self.root_doc(
            '[a](docs/t.md "Title") [b][r] [the\nwrapped](docs/w.md) ![img](docs/i.png)\n'
            '[c](<docs/sp ace.md>) [d](/docs/root.md) <a href="docs/h.md">e</a>\n'
            "[r]: docs/ref.md\n")
        self.assertEqual(self.problems(), [
            "AGENTS.md:9: link target docs/t.md does not exist",
            "AGENTS.md:9: link target docs/w.md does not exist",
            "AGENTS.md:10: link target docs/i.png does not exist",
            "AGENTS.md:11: link target docs/sp ace.md does not exist",
            "AGENTS.md:11: link target /docs/root.md does not exist",
            "AGENTS.md:11: link target docs/h.md does not exist",
            "AGENTS.md:12: link target docs/ref.md does not exist",
        ])

    @needs_yaml
    def test_urls_code_and_comments_hold_no_links_and_escapes_are_named(self):
        self.root_doc("[u](https://example.com/gone) [m](mailto:x@example.com) `[c](docs/gone.md)`\n"
                      "<!-- [h](docs/gone.md) --> [e](../outside.md) [q](CONTRIBUTING.md?plain=1)\n"
                      "[pct](CONTRIBUTING%2Emd)\n")
        self.assertEqual(self.problems(), ["AGENTS.md:10: link target ../outside.md leaves the repository"])

    # Gate commands

    @needs_yaml
    def test_a_gate_command_ci_no_longer_runs_is_named(self):
        self.write(".github/workflows/ci.yml", CI.replace("--locked -p irlume-pam", "--locked --workspace"))
        self.assertEqual(self.problems(), [MISSING_TEST])

    @needs_yaml
    def test_a_gate_command_left_only_in_a_comment_is_named(self):
        self.write(".github/workflows/ci.yml",
                   CI.replace("  cargo test --locked -p irlume-pam", "  # cargo test --locked -p irlume-pam"))
        self.assertEqual(self.problems(), [MISSING_TEST])

    @needs_yaml
    def test_a_longer_ci_command_does_not_stand_in_for_a_gate_command(self):
        self.write(".github/workflows/ci.yml", CI.replace("-p irlume-pam", "-p irlume-pam -- --ignored"))
        self.assertEqual(self.problems(), [MISSING_TEST])

    @needs_yaml
    def test_a_gate_command_only_another_job_runs_is_named(self):
        moved = CI.replace("      - name: test\n" + TEST_STEP, "")
        self.write(".github/workflows/ci.yml",
                   moved + "  stable:\n    steps:\n      - run: cargo test --locked -p irlume-pam\n")
        self.assertEqual(self.problems(), [MISSING_TEST])

    @needs_yaml
    def test_a_gate_command_under_env_or_in_a_step_that_cannot_fail_the_job_is_named(self):
        for step in ("        env:\n          run: cargo test --locked -p irlume-pam\n        run: echo x\n",
                     "        if: false\n        run: cargo test --locked -p irlume-pam\n",
                     "        if: github.event_name == 'push'\n        run: cargo test --locked -p irlume-pam\n",
                     "        continue-on-error: true\n        run: cargo test --locked -p irlume-pam\n",
                     "        working-directory: fuzz\n        run: cargo test --locked -p irlume-pam\n"):
            with self.subTest(step=step):
                self.write(".github/workflows/ci.yml", CI.replace(TEST_STEP, step))
                self.assertEqual(self.problems(), [MISSING_TEST])

    @needs_yaml
    def test_folded_continued_and_anchored_runs_match(self):
        self.write(".github/workflows/ci.yml", textwrap.dedent("""\
            jobs:  # the gate
              check:
                steps:
                  - {name: fmt, run: &fmt "cargo fmt --all --check"}
                  - name: test
                    run: >-
                      cargo test --locked
                      -p irlume-pam
            """))
        self.assertEqual(self.problems(), [])
        self.write(".github/workflows/ci.yml", CI.replace(
            "          cargo test --locked -p irlume-pam\n",
            "          cargo test --locked \\\n            -p irlume-pam\n"))
        self.assertEqual(self.problems(), [])

    @needs_yaml
    def test_a_workflow_without_the_check_job_is_an_error(self):
        self.write(".github/workflows/ci.yml", CI.replace("  check:", "  build:"))
        self.assertEqual(self.problems(), [
            "AGENTS.md: .github/workflows/ci.yml has no `check` job, so the gate commands cannot be checked"])

    @needs_yaml
    def test_a_missing_or_empty_gate_block_is_an_error(self):
        error = ['AGENTS.md: no command block under "## Gate commands"']
        self.write("AGENTS.md", ROOT_DOC.replace("## Gate commands", "## Commands"))
        self.assertEqual(self.problems(), error)
        self.write("AGENTS.md", ROOT_DOC.replace(
            "cargo fmt --all --check\ncargo test --locked -p irlume-pam\n", "# none\n"))
        self.assertEqual(self.problems(), error)

    @needs_yaml
    def test_a_heading_like_comment_inside_the_gate_block_does_not_end_it(self):
        self.write("AGENTS.md", ROOT_DOC.replace(
            "cargo test --locked -p irlume-pam\n",
            "## lint\ncargo test --locked -p irlume-pam\ncargo clippy --gone\n"))
        self.assertEqual(self.problems(), [
            "AGENTS.md:15: gate command is not a run line of the check job in "
            ".github/workflows/ci.yml: cargo clippy --gone"])

    def test_logical_lines_join_continuations_and_skip_heredocs(self):
        script = "set -e\n# note\ncargo test \\\n  -p x\ncat <<'EOF'\ncargo fake\nEOF\ndone\n"
        self.assertEqual(checker.logical_lines(script), {"set -e", "cargo test -p x", "cat <<'EOF'", "done"})

    @needs_yaml
    def test_question_mark_and_bracket_globs_must_match(self):
        self.root_doc("Tests: `crates/irlume-pam/tests/pamwra?.rs` and `crates/irlume-pam/tests/[p]amwrap.rs`.\n")
        self.assertEqual(self.problems(), [])
        (self.root / "crates/irlume-pam/tests/pamwrap.rs").unlink()
        found = self.problems()
        self.assertIn("AGENTS.md:9: path crates/irlume-pam/tests/pamwra?.rs names nothing in the tree", found)
        self.assertIn("AGENTS.md:9: path crates/irlume-pam/tests/[p]amwrap.rs names nothing in the tree", found)

    @needs_yaml
    def test_a_line_range_is_stripped_before_the_path_is_checked(self):
        self.root_doc("See `crates/gone/x.rs:40-55` and `crates/irlume-pam/src/lib.rs:1-2`.\n")
        self.assertEqual(self.problems(), ["AGENTS.md:9: path crates/gone/x.rs names nothing in the tree"])

    @needs_yaml
    def test_single_quoted_href_and_undefined_references_are_checked(self):
        self.root_doc("<a href='docs/gone.md'>x</a> [guide][missing] [ok][] [lit][ok]\n\n[ok]: CONTRIBUTING.md\n")
        self.assertEqual(self.problems(), [
            "AGENTS.md:9: reference link [missing] has no definition",
            "AGENTS.md:9: link target docs/gone.md does not exist",
        ])

    @needs_yaml
    def test_a_continued_gate_line_matches_the_joined_command(self):
        self.write("AGENTS.md", ROOT_DOC.replace(
            "cargo test --locked -p irlume-pam\n", "cargo test --locked \\\n  -p irlume-pam\n"))
        self.assertEqual(self.problems(), [])

    @needs_yaml
    def test_a_gate_command_inside_a_shell_block_is_named(self):
        for body in ("          if false; then\n            cargo test --locked -p irlume-pam\n          fi\n",
                     "          run_tests() {\n            cargo test --locked -p irlume-pam\n          }\n",
                     "          for x in; do\n            cargo test --locked -p irlume-pam\n          done\n"):
            with self.subTest(body=body):
                self.write(".github/workflows/ci.yml", CI.replace(
                    "          # the PAM crate\n          cargo test --locked -p irlume-pam\n", body))
                self.assertEqual(self.problems(), [MISSING_TEST])

    @needs_yaml
    def test_step_conditions_and_defaults_follow_github_semantics(self):
        self.write(".github/workflows/ci.yml", CI.replace(TEST_STEP, "        if: true\n" + TEST_STEP))
        self.assertEqual(self.problems(), [])
        self.write(".github/workflows/ci.yml",
                   CI.replace(TEST_STEP, "        continue-on-error: ${{ matrix.experimental }}\n" + TEST_STEP))
        self.assertEqual(self.problems(), [MISSING_TEST])
        self.write(".github/workflows/ci.yml", "defaults:\n  run:\n    working-directory: fuzz\n" + CI)
        found = self.problems()
        self.assertEqual(len(found), 2, found)
        self.assertIn(MISSING_TEST, found)

    @needs_yaml
    def test_a_glob_star_stays_inside_one_directory(self):
        (self.root / "crates/irlume-pam/tests/pamwrap.rs").unlink()
        self.write("crates/irlume-pam/tests/unit/deep.rs", "")
        found = self.problems()
        self.assertIn("AGENTS.md:7: path crates/irlume-pam/tests/*.rs names nothing in the tree", found)
        self.assertTrue(checker.glob_match("a/b/c/d.rs", "a/**/d.rs"))
        self.assertTrue(checker.glob_match("a/d.rs", "a/**/d.rs"))
        self.assertFalse(checker.glob_match("a/b/d.rs", "a/*.rs"))

    @needs_yaml
    def test_a_gate_command_after_a_short_circuit_operator_is_named(self):
        for joint in ("false &&", "true ||", "echo x |"):
            with self.subTest(joint=joint):
                self.write(".github/workflows/ci.yml", CI.replace(
                    "          cargo test --locked -p irlume-pam\n",
                    f"          {joint}\n          cargo test --locked -p irlume-pam\n          true\n"))
                self.assertEqual(self.problems(), [MISSING_TEST])

    @needs_yaml
    def test_masked_failures_needs_and_a_dangling_gate_line_are_named(self):
        self.write(".github/workflows/ci.yml", CI.replace(
            "          cargo test --locked -p irlume-pam\n",
            "          set +e\n          cargo test --locked -p irlume-pam\n          true\n"))
        self.assertEqual(self.problems(), [MISSING_TEST])
        self.write(".github/workflows/ci.yml", CI.replace("  check:\n", "  check:\n    needs: setup\n"))
        self.assertEqual(self.problems(), ["AGENTS.md: .github/workflows/ci.yml runs the `check` job only "
                                           "after its `needs` jobs succeed, so the gate commands cannot be checked"])
        self.write(".github/workflows/ci.yml", CI)
        self.write("AGENTS.md", ROOT_DOC.replace("cargo test --locked -p irlume-pam\n",
                                                 "cargo test --locked -p irlume-pam \\\n"))
        self.assertEqual(self.problems(), ["AGENTS.md:13: gate command ends in a dangling \\ continuation"])

    @needs_yaml
    def test_unquoted_href_and_tracked_symlinks(self):
        (self.root / "docs").mkdir()
        (self.root / "docs/link").symlink_to("gone-target")
        self.root_doc("<a href = docs/gone.md>x</a> <a href=docs/link>y</a> `docs/link`\n")
        self.assertEqual(self.problems(), ["AGENTS.md:9: link target docs/gone.md does not exist"])

    # Robustness

    @needs_yaml
    def test_a_tracked_root_file_deleted_from_the_work_tree_is_missing(self):
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        (self.root / "AGENTS.md").unlink()
        self.assertEqual(self.problems(), ["AGENTS.md: the root file is missing"])

    @needs_yaml
    def test_an_unreadable_file_and_a_non_ascii_path_are_reported_not_raised(self):
        (self.root / "crates/irlume-pam/AGENTS.md").write_bytes(b"# PAM\n\xff\xfe bad\n")
        self.write("docs/café/AGENTS.md", "See `docs/gone.md`.\n")
        found = self.problems()
        self.assertTrue(any(p.startswith("crates/irlume-pam/AGENTS.md: cannot be read") for p in found), found)
        self.assertIn("docs/café/AGENTS.md:1: path docs/gone.md names nothing in the tree", found)

    def test_outside_a_git_checkout_the_problem_is_reported(self):
        with tempfile.TemporaryDirectory() as plain:
            count, found = checker.check(plain)
        self.assertEqual(count, 0)
        self.assertTrue(found[0].startswith("git cannot list the tree"), found)

    @needs_yaml
    def test_the_root_file_is_required(self):
        (self.root / "AGENTS.md").unlink()
        self.assertEqual(self.problems(), ["AGENTS.md: the root file is missing"])

    @needs_yaml
    def test_the_real_tree_passes(self):
        repo = Path(__file__).resolve().parent.parent
        count, problems = checker.check(repo)
        self.assertEqual(problems, [])
        self.assertGreaterEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
