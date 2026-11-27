#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Offline checks for the code-to-docs gate."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("sync-docs.py")
ROOT = SCRIPT.resolve().parents[2]


def load():
    spec = importlib.util.spec_from_file_location("sync_docs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Regeneration(unittest.TestCase):
    def test_checked_in_outputs_equal_clean_regeneration(self):
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--check"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_parser_flag_edits_cannot_hide_behind_unchanged_help(self):
        parse = 'fn run(args: &[String]) { flag(args, "--old"); }\n'
        sysdoc = load()
        self.assertNotEqual(sysdoc.cli_signature({"main.rs": parse}),
                            sysdoc.cli_signature({"main.rs": parse.replace("--old", "--new")}))
        self.assertEqual(sysdoc.cli_signature({"main.rs": parse}),
                         sysdoc.cli_signature({"main.rs": "// comment\n" + parse}))

    def test_marker_changes_preserve_hand_written_text(self):
        sysdoc = load()
        start, end = sysdoc.CLI_MARKERS
        original = f"before\n{start}\nold\n{end}\nafter\n"
        self.assertEqual(sysdoc.replace_region(original, sysdoc.CLI_MARKERS, "new\n"),
                         f"before\n{start}\nnew\n{end}\nafter\n")
        with self.assertRaises(ValueError):
            sysdoc.replace_region(original + start, sysdoc.CLI_MARKERS, "new\n")

    def test_schema_edits_change_the_reference(self):
        sysdoc = load()
        api = {"title": "API", "properties": {}, "$defs": {
            "doctorData": {"properties": {"checks": {"type": "array"}}},
            "doctorCheck": {"properties": {"id": {"type": "string"}}},
        }}
        nightly = {"title": "Nightly", "properties": {}}
        old = sysdoc.schema_reference(api, nightly)
        api["$defs"]["doctorCheck"]["properties"]["state"] = {"enum": ["info", "unknown"]}
        new = sysdoc.schema_reference(api, nightly)
        self.assertIn('`"info"`, `"unknown"`', new)
        self.assertNotEqual(old, new)

    def test_authored_reference_must_name_new_parser_spellings(self):
        sysdoc = load()
        sources = {
            "commands.rs": 'pub fn update(args: &[String]) { args.iter().any(|a| a == "--new"); }',
            "trace.rs": 'pub fn run(args: &[String]) {\n    match args.get(1) {\n'
                        '        Some("inspect") => run_analyze(args),\n    }\n}\n',
        }
        self.assertEqual(sysdoc.cli_doc_problems(
            sources, "`irlume update --old`\n`irlume ir-setup --new`\n`irlume trace analyze`\n"),
            ["irlume trace inspect", "irlume update --new"])
        self.assertEqual(sysdoc.cli_doc_problems(sources, "`irlume update --new`\n`irlume trace inspect`\n"),
                         [])


class Environment(unittest.TestCase):
    def test_documented_environment_names_require_non_comment_code(self):
        sysdoc = load()
        code = ('std::env::var("IRLUME_CURRENT");\n// "IRLUME_GONE"\n'
                'eprintln!("IRLUME_GONE");\n'
                '#[cfg(test)]\nmod tests { fn setup() { std::env::var("IRLUME_GONE"); } }\n')
        self.assertEqual(sysdoc.environment_names("reader.rs", code), {"IRLUME_CURRENT"})
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            doc = root / "docs/user/setup.md"
            doc = doc.parent / "nested" / doc.name
            doc.parent.mkdir(parents=True)
            doc.write_text("Set `IRLUME_CURRENT` or `IRLUME_GONE`.\n", encoding="utf-8")
            archive = root / "docs/architecture/adr/0001.md"
            archive.parent.mkdir(parents=True)
            archive.write_text("Historical `IRLUME_RETIRED`.\n", encoding="utf-8")
            (root / "README.md").write_text("Set `IRLUME_GONE`.\n", encoding="utf-8")
            self.assertEqual(sysdoc.unknown_environment(root, {"IRLUME_CURRENT"}),
                             ["README.md:1: IRLUME_GONE", "docs/user/nested/setup.md:1: IRLUME_GONE"])

    def test_collector_requires_a_read_not_a_diagnostic_or_test_assignment(self):
        sysdoc = load()
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            subprocess.run(["git", "init", "-q", work], check=True)
            source = root / "crates/test/src/main.rs"
            source.parent.mkdir(parents=True)
            read = 'std::env::var_os(CURRENT);'
            source.write_text(
                'const CURRENT: &str = "IRLUME_CURRENT";\n'
                f'fn read() {{ {read} eprintln!("IRLUME_CURRENT"); }}\n'
                '#[cfg(test)]\nmod tests { fn setup() { std::env::set_var("IRLUME_CURRENT", "1"); } }\n',
                encoding="utf-8",
            )
            shell = root / "scripts/run.sh"
            shell.parent.mkdir()
            shell.write_text('true # ${IRLUME_CURRENT:-1}\n', encoding="utf-8")
            source.with_name("tests.rs").write_text(
                'fn fixture() { std::env::var("IRLUME_CURRENT"); }\n', encoding="utf-8")
            subprocess.run(["git", "-C", work, "add", "--", "crates", "scripts"], check=True)
            self.assertIn("IRLUME_CURRENT", sysdoc.known_environment(root))
            source.write_text(source.read_text(encoding="utf-8").replace(read, ""), encoding="utf-8")
            self.assertNotIn("IRLUME_CURRENT", sysdoc.known_environment(root))


class PullRequestPolicy(unittest.TestCase):
    def test_each_changed_surface_needs_matching_docs(self):
        rule = load().missing_pr_docs
        changes = [("M", "kcm/src/controller.cpp"), ("M", "crates/irlume-cli/src/main.rs"),
                   ("M", "docs/reference/COMMANDS.md")]
        self.assertEqual(rule(changes), ["KCM"])
        self.assertEqual(rule(changes + [("M", "docs/user/KCM.md-unrelated.md")]), ["KCM"])
        self.assertEqual(rule(changes + [("M", "docs/user/KCM.md")]), [])

    def test_deletions_and_dated_research_do_not_satisfy_the_gate(self):
        rule = load().missing_pr_docs
        changes = [("D", "packaging/debian/nfpm.yaml"), ("D", "docs/user/PLATFORMS.md"),
                   ("M", "docs/research/old.md")]
        self.assertEqual(rule(changes), ["packaging"])
        self.assertEqual(rule(changes + [("M", "CHANGELOG.md")]), [])
        self.assertEqual(rule(changes, labels={"docs-not-needed"}), [])

    def test_credits_are_not_cli_or_schema_docs_and_packaging_readme_counts(self):
        rule = load().missing_pr_docs
        changes = [("M", "crates/irlume-cli/src/main.rs"), ("M", "schemas/machine-api-v1.schema.json"),
                   ("M", "docs/reference/CREDITS.md")]
        self.assertEqual(rule(changes), ["CLI", "schemas"])
        self.assertEqual(rule([("M", "packaging/README.md")]), [])

    def test_git_diff_uses_the_pr_merge_parent_not_branch_history(self):
        sysdoc = load()
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)

            def git(*args):
                return subprocess.check_output(["git", "-C", work, *args], text=True).strip()

            git("init", "-q", "-b", "main")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            git("config", "commit.gpgsign", "false")
            git("commit", "--allow-empty", "-m", "common")
            git("branch", "topic")
            path = root / "README.md"
            path.write_text("base-only\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-m", "base only")
            base = git("rev-parse", "HEAD")
            git("checkout", "-q", "topic")
            path = root / "kcm/filename with spaces.cpp"
            path.parent.mkdir()
            path.write_text("topic-only\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-m", "topic only")
            head = git("rev-parse", "HEAD")
            git("checkout", "-q", "main")
            git("merge", "--no-ff", "--no-edit", "topic")
            self.assertEqual(sysdoc.pr_changes(root, base, head),
                             [("A", "kcm/filename with spaces.cpp")])
            with self.assertRaises(ValueError):
                sysdoc.pr_changes(root, head, base)
            with tempfile.TemporaryDirectory() as checkout:
                subprocess.run(["git", "clone", "-q", "--depth", "2", root.as_uri(), checkout], check=True)
                event = root / "event.json"
                event.write_text(json.dumps({"pull_request": {
                    "base": {"sha": base}, "head": {"sha": head}, "labels": [{"name": "docs-not-needed"}],
                }}), encoding="utf-8")
                self.assertEqual(sysdoc.pr_policy(Path(checkout), event), 0)
                with self.assertRaises(ValueError):
                    sysdoc.pr_changes(Path(checkout), base, "0" * 40)
                subprocess.run(["git", "-C", checkout, "checkout", "-q", "--detach", head], check=True)
                with self.assertRaises(ValueError):
                    sysdoc.pr_policy(Path(checkout), event)


if __name__ == "__main__":
    unittest.main()
