#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Keep the AGENTS.md files true to the tree they describe.

Every AGENTS.md cites paths, links and commands that go stale when the code
moves. This fails when:

* a relative Markdown link does not resolve from the file that holds it;
* a path in backticks names nothing in the tree (a glob must match at least
  one file);
* a line of the root file's "Gate commands" block is not, verbatim, a
  whole command line of a step's `run:` in .github/workflows/ci.yml (a
  comment, a longer command or a `run` key under `env:` does not count),
  or the block is gone or empty;
* a bare workflow file name (`ci.yml`) is not in .github/workflows/.

A path is looked up from the repository root and, for a nested AGENTS.md,
from its own directory and that directory's `src/`, so `src/main.rs` in the
daemon's file must be the daemon's. The root file cites full paths.
Placeholders (`<target>`, `NNNN`), absolute paths (`/etc/pam.d`) and build
output under `target/` are not checked. A code span that is one path-shaped
token is always a path, so a removed top-level directory (`kcm/`) is named.
Inside a longer span, a command, a token is a path when it ends in `/` or a
file extension or its first segment exists, so a cargo feature such as
`irlume-auth/ir-only-evaluation` is not one. A bare name with a file
extension (`Cargo.toml`) is a path too, so files outside the tree, such as
`/etc/irlume/settings.conf`, are cited by absolute path.

Runs in CI on every push and PR (ci.yml, "AGENTS.md references").
"""
import argparse
import glob
from pathlib import Path
import re
import subprocess
import sys

WORKFLOWS = Path(".github/workflows")
CI = WORKFLOWS / "ci.yml"
GATE_HEADING = "## Gate commands"

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
CODE_SPAN = re.compile(r"`([^`\n]+)`")
PATH_TOKEN = re.compile(r"^[\w.@+*-]+(?:/[\w.@+*-]*)+$")
BARE_NAME = re.compile(r"^[\w@+-][\w.@+-]*$")
STEP_ITEM = re.compile(r"^(\s*)-(\s+)(\S.*)$")
YAML_KEY = re.compile(r"^([\w-]+):\s*(.*)$")
EXTENSION = re.compile(r"\.(?:rs|md|py|sh|toml|ya?ml|json|nix|lock|conf|service|tflite)$")
WORKFLOW_NAME = re.compile(r"^[\w-]+\.ya?ml$")
PLACEHOLDER = re.compile(r"[<>]|NNNN")


def agents_files(root):
    """Every AGENTS.md git sees, tracked or new, never ignored checkouts."""
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard",
         "--", ":(glob)**/AGENTS.md"],
        cwd=root, check=True, capture_output=True, text=True,
    ).stdout
    return sorted({root / line for line in out.splitlines() if line})


def outside_fences(text):
    """(line number, line) pairs outside ``` fences."""
    fenced = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            yield number, line


def bases_for(root, doc):
    if doc.parent == root:
        return [root]
    return [root, doc.parent, doc.parent / "src"]


def resolves(bases, token):
    token = token.rstrip("/")
    for base in bases:
        if "*" in token:
            if glob.glob(str(base / token)):
                return True
        elif (base / token).exists():
            return True
    return False


def is_path(bases, token, whole_span=False):
    if PLACEHOLDER.search(token) or token.startswith(("/", "target/", "./target/")):
        return False
    if "/" not in token:
        return bool(BARE_NAME.match(token) and EXTENSION.search(token))
    if not PATH_TOKEN.match(token.removeprefix("./")):
        return False
    if whole_span or token.endswith("/") or EXTENSION.search(token):
        return True
    first = token.removeprefix("./").split("/", 1)[0]
    return any((base / first).exists() for base in bases)


def check_links(root, doc, text):
    problems = []
    for number, line in outside_fences(text):
        for target in LINK.findall(line):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                continue
            path = target.split("#", 1)[0]
            if path and not (doc.parent / path).exists():
                problems.append(f"{doc.relative_to(root)}:{number}: link target {target} does not exist")
    return problems


def check_paths(root, doc, text):
    problems = []
    bases = bases_for(root, doc)
    for number, line in outside_fences(text):
        for span in CODE_SPAN.findall(line):
            tokens = span.split()
            for token in tokens:
                token = token.strip("'\"(),;")
                if WORKFLOW_NAME.match(token):
                    if not (root / WORKFLOWS / token).exists():
                        problems.append(f"{doc.relative_to(root)}:{number}: workflow {token} is not in {WORKFLOWS}/")
                    continue
                if is_path(bases, token, len(tokens) == 1) and not resolves(
                    bases, token.removeprefix("./")
                ):
                    problems.append(f"{doc.relative_to(root)}:{number}: path {token} names nothing in the tree")
    return problems


def gate_commands(text):
    """The lines of the first ``` block under the Gate commands heading."""
    lines = text.splitlines()
    try:
        start = lines.index(GATE_HEADING)
    except ValueError:
        return None
    commands, fenced = [], False
    for number, line in enumerate(lines[start + 1:], start + 2):
        if line.startswith("## "):
            break
        if line.startswith("```"):
            if fenced:
                return commands or None
            fenced = True
            continue
        if fenced and line.strip() and not line.lstrip().startswith("#"):
            commands.append((number, line.strip()))
    return commands or None


def run_commands(workflow):
    """Every command line of the workflow's step `run:` keys, comments dropped.

    Only a step's own `run` key counts: on the step's `- ` line or at its key
    column inside a `steps:` list. A `run` under `env:`, `with:` or a job's
    `defaults:` is data, not a command. A block scalar (`run: |`) runs the
    lines indented deeper than its key; an inline `run:` runs its value.
    """
    commands = set()
    lines = workflow.splitlines()
    steps_column = None  # column of the `steps:` key being read
    key_column = None  # column of the current step's keys
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        column = len(line) - len(line.lstrip())
        if steps_column is not None and (
            column < steps_column or (column == steps_column and not text.startswith("-"))
        ):
            steps_column = key_column = None
        if steps_column is None:
            if re.match(r"^steps:\s*$", text):
                steps_column = column
            continue
        item = STEP_ITEM.match(line)
        if item and (key_column is None or len(item.group(1)) < key_column):
            key_column = len(item.group(1)) + 1 + len(item.group(2))
            entry = item.group(3)
        elif column == key_column:
            entry = text
        else:
            continue
        key = YAML_KEY.match(entry)
        if not key or key.group(1) != "run":
            continue
        value = key.group(2).strip()
        if value[:1] in ("|", ">"):
            while index < len(lines) and (
                not lines[index].strip()
                or len(lines[index]) - len(lines[index].lstrip()) > key_column
            ):
                commands.add(lines[index].strip())
                index += 1
        elif value:
            if len(value) > 1 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            commands.add(value)
    return {command for command in commands if command and not command.startswith("#")}


def check_gate(root, text):
    doc = "AGENTS.md"
    commands = gate_commands(text)
    if commands is None:
        return [f"{doc}: no command block under \"{GATE_HEADING}\""]
    if not (root / CI).is_file():
        return [f"{doc}: {CI} is missing, so the gate commands cannot be checked"]
    ran = run_commands((root / CI).read_text(encoding="utf-8"))
    return [
        f"{doc}:{number}: gate command is not a {CI} run line: {command}"
        for number, command in commands
        if command not in ran
    ]


def check(root):
    root = Path(root).resolve()
    docs = agents_files(root)
    if root / "AGENTS.md" not in docs:
        return 0, ["AGENTS.md: the root file is missing"]
    problems = []
    for doc in docs:
        text = doc.read_text(encoding="utf-8")
        problems += check_links(root, doc, text)
        problems += check_paths(root, doc, text)
        if doc == root / "AGENTS.md":
            problems += check_gate(root, text)
    return len(docs), problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--root", default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args(argv)
    count, problems = check(args.root)
    for problem in problems:
        print(problem)
    if problems:
        print(f"AGENTS.md check: {len(problems)} stale reference(s). Update the AGENTS.md "
              "line, or the code it describes, in the same PR.")
        return 1
    print(f"AGENTS.md check: {count} files, every link, path and gate command resolves.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
