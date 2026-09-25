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
  command in .github/workflows/ci.yml;
* a bare workflow file name (`ci.yml`) is not in .github/workflows/.

A path is looked up from the repository root, from the AGENTS.md file's own
directory, and from every crate and crate `src/` directory, because the files
cite crate-relative paths such as `src/lib.rs` beside the crate they name.
Placeholders (`<target>`, `NNNN`), absolute paths (`/etc/pam.d`) and build
output under `target/` are not checked. A token is treated as a path when its
first segment exists in one of those places or it ends in a file extension,
so a cargo feature such as `irlume-auth/ir-only-evaluation` is not a path.

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
    bases = [root, doc.parent]
    for crate in sorted((root / "crates").glob("*/")):
        bases.extend([crate, crate / "src"])
    return bases


def resolves(bases, token):
    token = token.rstrip("/")
    for base in bases:
        if "*" in token:
            if glob.glob(str(base / token)):
                return True
        elif (base / token).exists():
            return True
    return False


def is_path(bases, token):
    if PLACEHOLDER.search(token) or token.startswith(("/", "target/", "./target/")):
        return False
    if not PATH_TOKEN.match(token.removeprefix("./")):
        return False
    first = token.removeprefix("./").split("/", 1)[0]
    if any((base / first).exists() for base in bases):
        return True
    return bool(EXTENSION.search(token.rstrip("/")))


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
            for token in span.split():
                token = token.strip("'\"(),;")
                if WORKFLOW_NAME.match(token):
                    if not (root / WORKFLOWS / token).exists():
                        problems.append(f"{doc.relative_to(root)}:{number}: workflow {token} is not in {WORKFLOWS}/")
                    continue
                if is_path(bases, token) and not resolves(bases, token.removeprefix("./")):
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
                return commands
            fenced = True
            continue
        if fenced and line.strip() and not line.lstrip().startswith("#"):
            commands.append((number, line.strip()))
    return commands or None


def check_gate(root, text):
    doc = "AGENTS.md"
    commands = gate_commands(text)
    if commands is None:
        return [f"{doc}: no command block under \"{GATE_HEADING}\""]
    if not (root / CI).is_file():
        return [f"{doc}: {CI} is missing, so the gate commands cannot be checked"]
    ci = (root / CI).read_text(encoding="utf-8")
    return [
        f"{doc}:{number}: gate command is not in {CI}: {command}"
        for number, command in commands
        if command not in ci
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
