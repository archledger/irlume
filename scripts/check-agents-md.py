#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Keep the AGENTS.md files true to the tree they describe.

Every AGENTS.md cites paths, links and commands that go stale when the code
moves. This fails when:

* a relative link (inline, with or without a title, `<...>` target,
  reference definition, image or `<a href>`) does not resolve from the file
  that holds it, or leaves the repository; a leading `/` is the repo root;
  a full or collapsed reference link (`[text][label]`, `[label][]`) has no
  definition;
* a path in a code span names nothing in the tree (a glob must match at
  least one file);
* a line of the root file's "Gate commands" block is not, after joining
  `\\` continuations on both sides, a whole top-level command line of an
  enforced step's `run:` in the required `check` job of
  .github/workflows/ci.yml (a step or job that is conditional, may fail, or
  runs in another directory does not count, nor does a line inside a shell
  `if`, `case`, loop or function body), or the block is gone or empty;
* a code fence is never closed.

"The tree" is what git lists: tracked files and new files that are not
ignored, so build output, fetched models and other checkouts never satisfy
a citation. A path is looked up from the repository root and, for a nested
AGENTS.md, from its own directory and that directory's `src/`, so
`src/main.rs` in the daemon's file must be the daemon's; the root file
cites full paths. A bare name (`Cargo.toml`) is looked up the same way, and
a bare `.yml` name also in `.github/` and `.github/workflows/`.

Code spans may wrap across lines. A token in a span is a path when it has a
`/` and ends in `/` or a known file extension, or its first segment exists;
a bare name counts only when it is the whole span and has a known
extension. So `kcm/` and `Cargo.toml` are checked, while `origin/main`, a
cargo feature such as `irlume-auth/ir-only-evaluation` and a unit name
inside a command are not. A `:line`, `#anchor`, `--flag=` or `VAR=` around a
path is stripped first. Placeholders (`<target>`, `NNNN`), absolute paths
(`/etc/pam.d`, which name the host, not the tree) and `target/` are not
checked. Files outside the tree are cited by absolute path. Only the root
file's gate block is compared with CI; the per-area table, lanes, rules and
versions need a reread.

Reading ci.yml needs PyYAML (`python3-yaml`). Runs in CI on every pull
request and every push to main (ci.yml, "AGENTS.md references").
"""
import argparse
import fnmatch
import posixpath
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

CI = ".github/workflows/ci.yml"
GATE_HEADING = "## Gate commands"
GATE_JOB = "check"
EXTENSIONS = (
    "rs md py sh toml yml yaml json nix lock conf service timer path socket tflite "
    "txt cpp h hpp qml cmake policy te fc spec xml desktop rules"
).split()
EXTENSION = re.compile(r"\.(?:" + "|".join(EXTENSIONS) + r")$")
BARE_NAME = re.compile(r"^[\w@+-][\w.@+-]*$")
PATH_TOKEN = re.compile(r"^[\w.@+*?\[\]-]+(?:/[\w.@+*?\[\]-]*)+$")
PLACEHOLDER = re.compile(r"[<>{}$]|NNNN|://")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
CODE_SPAN = re.compile(r"(?<!`)(`+)(?!`)((?:(?!\n[ \t]*\n).)+?)(?<!`)\1(?!`)", re.S)
LINK = re.compile(
    r"\[(?:[^\[\]]|\[[^\[\]]*\])*\]"
    r"\(\s*(<[^>\n]*>|(?:[^()\s]|\([^()\s]*\))+)"
    r"(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?\s*\)",
    re.S,
)
REFERENCE = re.compile(r"^ {0,3}\[[^\]]+\]:\s*(<[^>\n]*>|\S+)", re.M)
HREF = re.compile(r"<a\s[^>]*?href=(?:\"([^\"]+)\"|'([^']+)')", re.I)
FULL_REFERENCE = re.compile(r"\[((?:[^\[\]]|\[[^\[\]]*\])+)\]\[([^\[\]]*)\]")
DEFINITION = re.compile(r"^ {0,3}\[([^\]]+)\]:", re.M)
COMMENT = re.compile(r"<!--.*?-->", re.S)
ENFORCED_IF = {"success()", "always()", "${{ success() }}", "${{ always() }}", "true"}
SHELL_OPEN = re.compile(r"^(?:if|case|for|while|until|select)\b|^(?:function\s+)?[\w-]+\s*\(\)\s*\{?$|^function\s+[\w-]+")
SHELL_CLOSE = re.compile(r"^(?:fi|esac|done|\})\s*(?:[;&|#].*)?$")


class Tree:
    """The files and directories git lists for the checkout."""

    def __init__(self, root):
        out = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root, check=True, capture_output=True,
        ).stdout.decode("utf-8", "surrogateescape")
        self.files = set()
        for name in filter(None, out.split("\0")):
            try:
                present = (root / name).is_file()
            except OSError:
                present = False
            if present:
                self.files.add(name)
        self.dirs = {""}
        for name in self.files:
            parent = posixpath.dirname(name)
            while parent not in self.dirs:
                self.dirs.add(parent)
                parent = posixpath.dirname(parent)

    def has(self, path):
        path = path.rstrip("/")
        if any(ch in path for ch in "*?["):
            return any(fnmatch.fnmatchcase(name, path) for name in self.files)
        return path in self.files or path in self.dirs


def joined(base, path):
    """`path` from repo-relative `base`, or None when it leaves the repo."""
    full = posixpath.normpath(posixpath.join(base, path))
    if full == ".":
        return ""
    if full == ".." or full.startswith("../"):
        return None
    return full


def prose_of(text):
    """The text with fenced blocks and HTML comments blanked (line count kept),
    and the line of a fence left open, if any."""
    text = COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    out, fence, opened = [], None, 0
    for number, line in enumerate(text.split("\n"), 1):
        match = FENCE.match(line)
        if fence is None:
            if match:
                fence, opened = match.group(1), number
                out.append("")
            else:
                out.append(line)
            continue
        if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence) \
                and not match.group(2).strip():
            fence = None
        out.append("")
    return "\n".join(out), (opened if fence is not None else None)


def line_at(text, offset):
    return text.count("\n", 0, offset) + 1


def bases_for(doc_dir):
    return [""] if doc_dir == "" else ["", doc_dir, posixpath.join(doc_dir, "src")]


def clean_token(token):
    token = token.strip("'\"(),;")
    token = re.sub(r"^--?[\w-]+=", "", token)
    token = re.sub(r"^[A-Z_][A-Z0-9_]*=", "", token)
    token = re.sub(r"#.*$", "", token)
    token = re.sub(r"(?::\d+(?:-\d+)?)+$", "", token)
    return token.removeprefix("./")


def is_path(tree, bases, token, lone):
    if not token or PLACEHOLDER.search(token) or token.startswith(("/", "target/")):
        return False
    if "/" not in token:
        return lone and bool(BARE_NAME.match(token) and EXTENSION.search(token))
    if not PATH_TOKEN.match(token):
        return False
    if token.endswith("/") or EXTENSION.search(token):
        return True
    first = token.split("/", 1)[0]
    return any(tree.has(joined(base, first) or "..") for base in bases)


def resolves(tree, bases, token):
    candidates = list(bases)
    if "/" not in token and re.search(r"\.ya?ml$", token):
        candidates += [".github", ".github/workflows"]
    for base in candidates:
        full = joined(base, token)
        if full is not None and tree.has(full):
            return True
    return False


def check_doc(tree, root, name):
    try:
        text = (root / name).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as error:
        return [f"{name}: cannot be read ({error})"]
    problems = []
    doc_dir = posixpath.dirname(name)
    prose, open_fence = prose_of(text)
    if open_fence is not None:
        problems.append(f"{name}:{open_fence}: code fence is never closed")

    bases = bases_for(doc_dir)
    for match in CODE_SPAN.finditer(prose):
        tokens = match.group(2).split()
        for raw in tokens:
            token = clean_token(raw)
            if is_path(tree, bases, token, len(tokens) == 1) and not resolves(tree, bases, token):
                problems.append(
                    f"{name}:{line_at(prose, match.start())}: path {token} names nothing in the tree"
                )

    no_code = CODE_SPAN.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), prose)
    targets = [(m.start(), m.group(1)) for m in LINK.finditer(no_code)]
    targets += [(m.start(), m.group(1)) for m in REFERENCE.finditer(no_code)]
    targets += [(m.start(), m.group(1) or m.group(2)) for m in HREF.finditer(no_code)]
    defined = {" ".join(d.lower().split()) for d in DEFINITION.findall(no_code)}
    for m in FULL_REFERENCE.finditer(no_code):
        label = " ".join((m.group(2) or m.group(1)).lower().split())
        if label not in defined:
            problems.append(f"{name}:{line_at(no_code, m.start())}: reference link [{label}] has no definition")
    for offset, target in sorted(targets):
        target = target.strip("<>")
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target) or target.startswith("#"):
            continue
        path = unquote(re.split(r"[?#]", target, maxsplit=1)[0])
        if not path:
            continue
        full = joined("", path.lstrip("/")) if path.startswith("/") else joined(doc_dir, path)
        where = f"{name}:{line_at(no_code, offset)}"
        if full is None:
            problems.append(f"{where}: link target {target} leaves the repository")
        elif not tree.has(full):
            problems.append(f"{where}: link target {target} does not exist")
    return problems


def gate_commands(text):
    """The lines of the first code block under the Gate commands heading."""
    lines = text.split("\n")
    try:
        start = lines.index(GATE_HEADING)
    except ValueError:
        return None
    commands, fence, pending = [], None, None
    for number, line in enumerate(lines[start + 1:], start + 2):
        match = FENCE.match(line)
        if fence is None:
            if line.startswith("## "):
                break
            if match:
                fence = match.group(1)
            continue
        if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence):
            break
        if line.strip() and not line.lstrip().startswith("#"):
            if pending is not None:
                start_line, parts = pending
                parts.append(line.strip())
            else:
                start_line, parts = number, [line.strip()]
            if parts[-1].endswith("\\"):
                parts[-1] = parts[-1][:-1]
                pending = (start_line, parts)
                continue
            pending = None
            commands.append((start_line, " ".join(" ".join(parts).split())))
    return commands or None


def logical_lines(script):
    """The top-level command lines of a `run:` script: `\\` continuations
    joined, comments and heredoc bodies dropped, whitespace collapsed. Lines
    inside a shell `if`, `case`, loop or function body are left out: the
    shell may never run them."""
    lines, buffer, heredoc, depth = set(), [], None, 0
    for raw in str(script).split("\n"):
        if heredoc is not None:
            if raw.strip() == heredoc:
                heredoc = None
            continue
        text = raw.strip()
        if not buffer and (not text or text.startswith("#")):
            continue
        if text.endswith("\\"):
            buffer.append(text[:-1])
            continue
        buffer.append(text)
        command = " ".join(" ".join(buffer).split())
        buffer = []
        if SHELL_CLOSE.match(command) and depth:
            depth -= 1
        elif SHELL_OPEN.match(command) and not re.search(r"\b(?:fi|esac|done)\s*$|\}\s*$", command):
            depth += 1
        elif depth == 0:
            lines.add(command)
        tag = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", command)
        if tag:
            heredoc = tag.group(1)
    if buffer:
        lines.add(" ".join(" ".join(buffer).split()))
    return lines


def enforced(node):
    condition = node.get("if")
    if condition is not None and condition is not True \
            and str(condition).strip() not in ENFORCED_IF:
        return False
    tolerate = node.get("continue-on-error")
    return tolerate is None or tolerate is False or str(tolerate).strip() == "false"


def run_commands(workflow_text):
    """(the command lines the `check` job's enforced steps run, error)."""
    try:
        import yaml
    except ImportError:
        return None, "cannot be read without PyYAML (python3-yaml)"
    try:
        data = yaml.safe_load(workflow_text)
    except yaml.YAMLError as error:
        return None, f"cannot be parsed ({error})"
    jobs = data.get("jobs") if isinstance(data, dict) else None
    job = jobs.get(GATE_JOB) if isinstance(jobs, dict) else None
    if not isinstance(job, dict):
        return None, f"has no `{GATE_JOB}` job"
    if not enforced(job):
        return None, f"runs the `{GATE_JOB}` job only conditionally"
    def default_dir(node):
        defaults = node.get("defaults") if isinstance(node.get("defaults"), dict) else {}
        run = defaults.get("run") if isinstance(defaults.get("run"), dict) else {}
        return run.get("working-directory")
    job_dir = default_dir(job) or default_dir(data)
    commands = set()
    for step in job.get("steps") or []:
        if not isinstance(step, dict) or "run" not in step or not enforced(step):
            continue
        if step.get("working-directory", job_dir) not in (None, ".", "./"):
            continue
        commands |= logical_lines(step["run"])
    return commands, None


def check_gate(root, text):
    doc = "AGENTS.md"
    commands = gate_commands(text)
    if commands is None:
        return [f"{doc}: no command block under \"{GATE_HEADING}\""]
    try:
        workflow = (root / CI).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return [f"{doc}: {CI} is missing, so the gate commands cannot be checked"]
    ran, error = run_commands(workflow)
    if error:
        return [f"{doc}: {CI} {error}, so the gate commands cannot be checked"]
    return [
        f"{doc}:{number}: gate command is not a run line of the {GATE_JOB} job in {CI}: {command}"
        for number, command in commands
        if command not in ran
    ]


def check(root):
    root = Path(root).resolve()
    try:
        tree = Tree(root)
    except (OSError, subprocess.CalledProcessError) as error:
        return 0, [f"git cannot list the tree at {root} ({error})"]
    docs = sorted(name for name in tree.files if posixpath.basename(name) == "AGENTS.md")
    if "AGENTS.md" not in docs:
        return len(docs), ["AGENTS.md: the root file is missing"]
    problems = []
    for name in docs:
        problems += check_doc(tree, root, name)
    try:
        root_text = (root / "AGENTS.md").read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        root_text = ""
    problems += check_gate(root, root_text)
    return len(docs), problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
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
