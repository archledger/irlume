#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Refresh or check the code-backed documentation; no hardware or network."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
CLI = Path("crates/irlume-cli/src")
COMMANDS = Path("docs/reference/COMMANDS.md")
API = Path("docs/reference/MACHINE-API.md")
SCHEMAS = Path("docs/reference/SCHEMAS.md")
CLI_MARKERS = ("<!-- cli-help:start -->", "<!-- cli-help:end -->")
HISTORICAL_DOCS = (
    "docs/architecture/adr/", "docs/cross-distro/", "docs/pad-results/",
    "docs/plans/", "docs/recognition-results/", "docs/research/",
    "docs/superpowers/", "docs/validation/",
)
ENV = re.compile(r"\bIRLUME_[A-Z][A-Z0-9_]*\b")
RETIRED_GESTURE_NAMES = {
    "IRLUME_CREDENTIAL_RELEASE_CHALLENGE", "IRLUME_POLKIT_GESTURE",
    "IRLUME_CONSENT_GESTURE", "IRLUME_CONSENT_MAX_FRAMES", "IRLUME_DUMP_POSE_SERIES",
    "IRLUME_NOD_PITCH_MIN", "IRLUME_SHAKE_",
}
ENV_SOURCE_DIRS = ("crates", "scripts", "packaging", "kcm", "nix", ".github/workflows", "flake.nix")
CODE_SUFFIXES = {".rs", ".py", ".sh", ".nix", ".c", ".cpp", ".h", ".hpp", ".qml",
                 ".service", ".socket", ".conf", ".spec", ".install", ".yml", ".yaml"}
CODE_FILENAMES = {"PKGBUILD", "postinst", "rules"}
RUST_TOKEN = re.compile(
    r'(?P<line>//[^\n]*)|(?P<block>/\*)|'
    r'(?P<raw>(?:b|c)?r(?P<hashes>\#*)".*?"(?P=hashes))|'
    r'''(?P<char>'(?:\\.|[^'\\\n])')|(?P<string>"(?:\\.|[^"\\])*")''',
    re.DOTALL,
)
OPTION = re.compile(r'"(--[a-zA-Z0-9][\w-]*(?:=[\w-]*)?|-[a-zA-Z])"')
DOC_OPTION = re.compile(r"(?<![\w-])(-{1,2}[a-zA-Z0-9][\w-]*)")
OPTION_INPUTS = tuple(re.compile(pattern, re.M) for pattern in (
    r'\bflag(?:_present)?\s*\(\s*[^,\n]+,\s*"(-{1,2}[a-zA-Z0-9][\w-]*)(?:=[\w-]*)?"',
    r'\b(?:a|arg|args\[[^]]+\]|token|flag|value|option)\s*(?:==|!=)\s*"(-{1,2}[a-zA-Z0-9][\w-]*)(?:=[\w-]*)?"',
    r'\b(?:strip_prefix|starts_with)\("(-{1,2}[a-zA-Z0-9][\w-]*)(?:=[\w-]*)?"',
    r'^[ \t]*(?:Some\(\s*)?"(-{1,2}[a-zA-Z0-9][\w-]*)(?:=[\w-]*)?"[^;\n]{0,80}=>',
))
TOP_FUNCTION = re.compile(r"^(?:pub(?:\([^)]+\))? )?(?:const )?fn (\w+)", re.M)
DISPATCH = re.compile(r'^[ \t]*((?:\(Some|Some)\("[-\w]+"[^\n]*)', re.MULTILINE)
TRACE_SUBCOMMAND = re.compile(r'^[ \t]*Some\("([a-z][a-z0-9-]*)"\).*=> run_', re.M)
TEST_MODULE = re.compile(r"^#\[cfg\(test\)\]\s*(?:#\[[^\n]+\]\s*)*mod \w+\s*\{", re.M)
HEX_OID = re.compile(r"[0-9a-f]{40}")
RUST_ENV_READ = re.compile(
    r'\b(?:var|var_os|option_env!|env!|[a-z_]*(?:env_[a-z_]+|[a-z_]+_env))\s*\(\s*'
    r'(?:"(IRLUME_[A-Z0-9_]+)"|([A-Z][A-Z0-9_]+)\b)'
)
RUST_ENV_CONST = re.compile(
    r'''\bconst ([A-Z][A-Z0-9_]+)\s*:\s*&(?:'static\s+)?str\s*=\s*"(IRLUME_[A-Z0-9_]+)"'''
)
SCRIPT_ENV_USE = tuple(re.compile(pattern) for pattern in (
    r"\$\{?(IRLUME_[A-Z0-9_]+)\b",
    r"\b(IRLUME_[A-Z0-9_]+)\s*[=:]",
    r'''\b(?:environ(?:\.get)?|getenv)\s*[\[(]\s*['"](IRLUME_[A-Z0-9_]+)['"]''',
))

# These handlers are not covered by the public synopsis. Their names are
# pinned here so a newly added public parser does not inherit the exception.
DEV_MAIN_FUNCTIONS = {
    "calcapture", "capture", "engine", "enrolldev", "eval", "farbench", "genuine",
    "irbench", "liveness_probe", "normprobe", "selftest_align", "verify",
}
PRIVATE_OPTIONS = {
    # Preview is explicitly refused, not part of the accepted argument list.
    ("machine.rs", "valid_auth_test_args", "--preview"),
    ("main.rs", "set_cameras_request", "--expected-camera"),
    ("pamwire/lightdm_view.rs", "run", "--permit-module"),
    ("pamwire/lightdm_view.rs", "run", "--session-module"),
}
SCOPED_HANDLERS = {
    ("bitwarden.rs", "run"): "bitwarden",
    ("commands.rs", "update"): "update",
    ("fingerprint.rs", "enable"): "fingerprint",
    ("fingerprint.rs", "reset"): "fingerprint reset",
    ("logs.rs", "build_view_argv"): "logs",
    ("logs.rs", "failure_hint"): "logs",
    ("machine.rs", "login_rollback"): "login rollback",
    ("machine.rs", "support_report"): "support-report",
    ("machine.rs", "valid_auth_test_args"): "auth test",
    ("machine.rs", "valid_login_apply_args"): "login apply",
    ("machine.rs", "valid_login_plan_args"): "login plan",
    ("machine.rs", "valid_profiles_list_args"): "profiles list",
    ("machine.rs", "valid_status_args"): "status",
    ("machine.rs", "valid_transaction_args"): "login rollback",
    ("main.rs", "camera_tune"): "camera-tune",
    ("main.rs", "doctor_wants_check"): "doctor",
    ("main.rs", "enroll"): "enroll",
    ("main.rs", "enrollment_camera_choice_flag"): "enroll",
    ("main.rs", "enrollment_split_camera_choice_flag"): "enroll",
    ("main.rs", "ir_setup"): "ir-setup",
    ("main.rs", "profiles"): "profiles",
    ("main.rs", "scans_flag"): "enroll",
    ("retry.rs", "valid_arguments"): "retry",
    ("sensor_policy.rs", "run"): "auth sensor preflight",
    ("split.rs", "split_request"): "split",
    ("support_report.rs", "parse_human_args"): "support-report",
    ("trace.rs", "parse_analyze_args"): "trace analyze",
    ("trace.rs", "parse_explain_args"): "trace explain",
    ("trace.rs", "parse_record_args"): "trace",
    ("trace.rs", "run"): "trace",
    ("tui/launch.rs", "parse_launch"): "tui",
    ("uninstall.rs", "run"): "uninstall",
}


def stable_digest(data):
    encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def rust_without_comments(text, *, mask_literals=False):
    parts = []
    cursor = 0
    while token := RUST_TOKEN.search(text, cursor):
        parts.append(text[cursor:token.start()])
        cursor = token.end()
        if token.lastgroup == "block":
            depth = 1
            while depth:
                delimiter = re.search(r"/\*|\*/", text[cursor:])
                if delimiter is None:
                    raise ValueError("unterminated Rust block comment")
                depth += 1 if delimiter[0] == "/*" else -1
                cursor += delimiter.end()
        segment = text[token.start():cursor]
        if mask_literals or token.lastgroup in {"block", "line"}:
            segment = re.sub(r"[^\n]", " ", segment)
        parts.append(segment)
    parts.append(text[cursor:])
    return "".join(parts)


def rust_production(text):
    structure = rust_without_comments(text, mask_literals=True)
    for test in reversed(list(TEST_MODULE.finditer(structure))):
        depth = 1
        for brace in re.finditer(r"[{}]", structure[test.end():]):
            depth += 1 if brace[0] == "{" else -1
            if depth == 0:
                end = test.end() + brace.end()
                text = text[:test.start()] + text[end:]
                break
        else:
            raise ValueError("unterminated Rust test module")
    return rust_without_comments(text)


def cli_signature(sources):
    """A conservative inventory: track parsed literals even outside terminal help."""
    inventory = {}
    for name, source in sorted(sources.items()):
        code = rust_production(source)
        options = []
        function = "<module>"
        for line in code.splitlines():
            # Function names distinguish an option moving between handlers.
            if match := TOP_FUNCTION.match(line):
                function = match[1]
            for token in RUST_TOKEN.finditer(line):
                if token.lastgroup == "string" and (match := OPTION.fullmatch(token[0])):
                    options.append((function, match[1]))
        if options:
            inventory[name] = options
        if dispatch := DISPATCH.findall(code):
            inventory[f"{name}: dispatch"] = [s.strip() for s in dispatch]
    return stable_digest(inventory)


def cli_doc_problems(sources, authored):
    """Require visible documentation for option reads and explicit trace verbs."""
    documented = set(DOC_OPTION.findall(authored))
    by_command = {}
    for command in set(SCOPED_HANDLERS.values()):
        start = rf"{re.escape(command)}(?=[\s`])"
        invocations = re.findall(rf"`(?:sudo )?irlume {start}([^`\n]*)`", authored)
        invocations += re.findall(rf"(?m)^[ \t]*(?:sudo )?irlume {start}([^\n]*)", authored)
        synopsis = re.findall(rf"(?m)^  {start}([^\n]*(?:\n {{4,}}[^\n]*)*)", authored)
        by_command[command] = set(DOC_OPTION.findall("\n".join(invocations + synopsis)))
    missing = set()
    for name, source in sources.items():
        code = rust_production(source)
        functions = list(TOP_FUNCTION.finditer(code))
        for pattern in OPTION_INPUTS:
            for match in pattern.finditer(code):
                spelling = match[1]
                function = next((fn[1] for fn in reversed(functions)
                                 if fn.start() < match.start()), "")
                if (name, function, spelling) in PRIVATE_OPTIONS:
                    continue
                scope = SCOPED_HANDLERS.get((name, function))
                if scope:
                    if spelling not in by_command[scope]:
                        missing.add(f"irlume {scope} {spelling}")
                    continue
                if spelling in documented:
                    continue
                if ((name == "main.rs" and function in DEV_MAIN_FUNCTIONS)
                        or (name == "pad.rs" and function in {"padcapture", "padreport"})):
                    continue
                missing.add(spelling)
        if name == "trace.rs":
            for verb in TRACE_SUBCOMMAND.findall(code):
                if not re.search(rf"\btrace\s+(?:\[{re.escape(verb)}\]|{re.escape(verb)}\b)", authored):
                    missing.add(f"irlume trace {verb}")
    return sorted(missing)


def replace_region(original, markers, body):
    start, end = markers
    if original.count(start) != 1 or original.count(end) != 1:
        raise ValueError(f"expected exactly one of each marker: {start}, {end}")
    before, remainder = original.split(start + "\n", 1)
    _, after = remainder.split(end, 1)
    return f"{before}{start}\n{body}{end}{after}"


def read(path):
    return path.read_text(encoding="utf-8")


def property_table(record):
    yield "| Field | Unconditionally required | Schema |"
    yield "|---|---|---|"
    for name, field in sorted(record["properties"].items()):
        if "enum" in field:
            shape = ", ".join(f"`{json.dumps(value)}`" for value in field["enum"])
        elif "const" in field:
            shape = f"`{json.dumps(field['const'])}`"
        else:
            shape = f"`{field.get('type', field.get('$ref', 'see schema'))}`"
            if field.get("items", {}).get("$ref"):
                shape += f" of `{field['items']['$ref']}`"
        required = "yes" if name in record.get("required", ()) else "no"
        yield f"| `{name}` | {required} | {shape} |"


def schema_reference(api, nightly):
    lines = [
        "# JSON Schema reference",
        "",
        "<!-- Generated by scripts/ci/sync-docs.py. Edit the schemas, then regenerate. -->",
        "",
        "See [Machine API](MACHINE-API.md) for compatibility rules, examples, and",
        "the current doctor check ID registry.",
        "",
        "## Machine API envelope",
        "",
        "[machine-api-v1.schema.json](../../schemas/machine-api-v1.schema.json)",
        f"<!-- canonical JSON sha256: {stable_digest(api)} -->",
        "",
        *property_table(api),
    ]
    for rule in api.get("allOf", ()):
        if rule.get("if", {}).get("properties") != {"ok": {"const": True}}:
            continue
        lines.extend(["", "| Envelope state | Required | Forbidden |", "|---|---|---|"])
        for key, condition in (("then", "`ok: true`"), ("else", "`ok: false`")):
            branch = rule[key]
            required = ", ".join(f"`{name}`" for name in branch.get("required", ())) or "none"
            forbidden = ", ".join(f"`{name}`" for name in branch.get("not", {}).get("required", ())) or "none"
            lines.append(f"| {condition} | {required} | {forbidden} |")
    lines.extend(["", "### Command-specific success payloads", "",
                  "| Response command | Schema definition for `data` |", "|---|---|"])
    for rule in api.get("allOf", ()):
        condition = rule.get("if", {}).get("properties", {})
        command = condition.get("command", {}).get("const")
        payload = rule.get("then", {}).get("properties", {}).get("data", {}).get("$ref")
        if command and payload:
            lines.append(f"| `{command}` | `{payload}` |")
    for key, title in (("doctorData", "Doctor payload"), ("doctorCheck", "Doctor check")):
        lines.extend(["", f"## {title}", "", *property_table(api["$defs"][key])])
    lines.extend([
        "",
        "## Nightly candidate record",
        "",
        "[nightly-candidate-v1.schema.json](../../schemas/nightly-candidate-v1.schema.json)",
        f"<!-- canonical JSON sha256: {stable_digest(nightly)} -->",
        "",
        *property_table(nightly),
        "",
    ])
    return "\n".join(lines)


def environment_names(filename, text):
    if filename.endswith(".rs"):
        return {name for name, _ in RUST_ENV_READ.findall(rust_production(text)) if name}
    text = re.sub(r"(?m)(?:^|[ \t]+)(?:#|//).*$", "", text)
    return {name for pattern in SCRIPT_ENV_USE for name in pattern.findall(text)}


def rust_test_source(path):
    return any(part in {"tests", "testenv"} or part.startswith("test_") or part.endswith("_tests")
               for part in path.with_suffix("").parts)


def known_environment(root):
    result = subprocess.check_output(["git", "ls-files", "-z", "--", *ENV_SOURCE_DIRS], cwd=root)
    names = set()
    consts = {}
    reads = set()
    for filename in filter(None, result.decode("utf-8", errors="surrogateescape").split("\0")):
        if filename in ("scripts/ci/sync-docs.py", "scripts/ci/test-sync-docs.py"):
            continue
        path = root / filename
        if path.suffix in CODE_SUFFIXES or path.name in CODE_FILENAMES:
            if path.suffix == ".rs":
                if rust_test_source(Path(filename)):
                    continue
                code = rust_production(read(path))
                for name, spelling in RUST_ENV_CONST.findall(code):
                    consts.setdefault(name, set()).add(spelling)
                for spelling, name in RUST_ENV_READ.findall(code):
                    if spelling:
                        names.add(spelling)
                    if name:
                        reads.add(name)
            else:
                names.update(environment_names(filename, read(path)))
    for name in reads:
        names.update(consts.get(name, ()))
    return names


def unknown_environment(root, known):
    """Check current guides; dated records and ADRs describe historical code."""
    problems = []
    paths = [p for p in (root / "README.md", root / "schemas/README.md", root / "packaging/README.md")
             if p.is_file()]
    paths.extend(sorted((root / "docs").rglob("*.md")))
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if relative.startswith(HISTORICAL_DOCS):
            continue
        allowed = known
        if relative == "docs/architecture/HEAD-GESTURE-REMOVAL.md":
            allowed = known | RETIRED_GESTURE_NAMES
        text = re.sub(r"<!--[\s\S]*?-->", lambda m: "\n" * m[0].count("\n"), read(path))
        for number, line in enumerate(text.splitlines(), 1):
            for name in sorted(set(ENV.findall(line)) - allowed):
                problems.append(f"{relative}:{number}: {name}")
    return problems


def updates(root):
    commands = root / COMMANDS
    source = root / CLI
    help_text = read(source / "cli-help.txt").rstrip("\n")
    parser_files = {p.relative_to(source).as_posix(): read(p) for p in source.rglob("*.rs")
                    if not p.name.endswith("_tests.rs")}
    original = read(commands)
    authored = replace_region(original, CLI_MARKERS, "")
    authored += "\n" + help_text + "\n" + read(root / API) + "\n" + read(root / "docs/reference/TUI.md")
    if missing := cli_doc_problems(parser_files, authored):
        raise ValueError("CLI parser spellings missing from help or reference: " + ", ".join(missing))
    body = (
        f"<!-- parser option inventory sha256: {cli_signature(parser_files)} -->\n\n"
        "```text\n" + help_text + "\n```\n\n"
    )
    machine = json.loads(read(root / "schemas/machine-api-v1.schema.json"))
    nightly = json.loads(read(root / "schemas/nightly-candidate-v1.schema.json"))
    return {
        commands: replace_region(original, CLI_MARKERS, body),
        root / SCHEMAS: schema_reference(machine, nightly),
        # Temporary copy: the AUR's published recipe still reads this path.
        root / "docs/MACHINE-API.md": read(root / API),
        root / "docs/INTEGRATION.md": read(root / "docs/reference/INTEGRATION.md"),
    }


def sync(root, check):
    stale = []
    for path, content in updates(root).items():
        if not path.is_file() or path.read_bytes() != content.encode("utf-8"):
            relative = path.relative_to(root)
            if check:
                stale.append(str(relative))
            else:
                path.write_bytes(content.encode("utf-8"))
                print(f"refreshed {relative}")
    generator = [sys.executable, "-B", str(root / "scripts/generate-hardware-matrix.py")]
    if check:
        generator.append("--check")
    hardware = subprocess.run(generator, cwd=root, check=False)
    if stale:
        print("Stale docs: " + ", ".join(stale), file=sys.stderr)
        print("Run python3 -B scripts/ci/sync-docs.py and review the diff.", file=sys.stderr)
    undocumented = unknown_environment(root, known_environment(root))
    for problem in undocumented:
        print(f"Environment variable not found in code: {problem}", file=sys.stderr)
    return int(bool(stale or hardware.returncode or undocumented))


def missing_pr_docs(changes, labels=()):
    if "docs-not-needed" in labels:
        return []
    changed = {path for _, path in changes}
    updated_docs = {path for status, path in changes if status != "D" and path.endswith(".md")}
    if "CHANGELOG.md" in updated_docs:
        return []
    scopes = [
        ("CLI", ("crates/irlume-cli/src/", "crates/irlume-cli/tests/", "crates/irlume-cli/Cargo.toml"),
         ("docs/reference/COMMANDS.md", "docs/reference/TUI.md", "docs/reference/MACHINE-API.md",
          "docs/reference/INTEGRATION.md", "docs/user/SETUP.md", "docs/user/DISABLE.md",
          "docs/user/DEBUGGING.md", "docs/user/DESKTOP-AUTH.md")),
        ("schemas", ("schemas/",), ("docs/reference/SCHEMAS.md", "docs/reference/MACHINE-API.md",
                                   "docs/reference/INTEGRATION.md", "schemas/README.md")),
        ("KCM", ("kcm/",), ("docs/user/KCM.md", "docs/reference/TUI.md")),
        ("packaging", ("packaging/", "nix/", ".packit.yaml", "flake.nix", "flake.lock"),
         ("packaging/README.md", "docs/user/SETUP.md", "docs/user/PLATFORMS.md", "docs/user/NIXOS.md",
          "docs/user/DISABLE.md", "docs/user/KCM.md", "docs/security/REPRODUCIBILITY.md",
          "docs/architecture/RELEASING.md", "docs/architecture/UPGRADE-VALIDATION.md")),
    ]

    def matches(path, patterns):
        return any(path.startswith(p) if p.endswith("/") else path == p for p in patterns)

    return [
        name for name, sources, docs in scopes
        if any(matches(path, sources) for path in changed)
        and not any(matches(path, docs) for path in updated_docs)
    ]


def pr_changes(root, base, head):
    if not (HEX_OID.fullmatch(base) and HEX_OID.fullmatch(head)):
        raise ValueError("expected GitHub's full base and head commit IDs")
    parents = subprocess.check_output(["git", "rev-list", "--parents", "-1", "HEAD"],
                                      cwd=root, text=True).split()
    if parents[1:] != [base, head]:
        raise ValueError("checkout is not the pull request merge commit for this event")
    diff = subprocess.check_output(
        ["git", "diff", "--name-status", "--no-renames", "-z", base, parents[0], "--"], cwd=root,
    )
    fields = diff.decode("utf-8", errors="surrogateescape").split("\0")
    return list(zip(fields[:-1:2], fields[1:-1:2], strict=True))


def pr_policy(root, event_file):
    pr = json.loads(read(event_file))["pull_request"]
    changes = pr_changes(root, pr["base"]["sha"], pr["head"]["sha"])
    missing = missing_pr_docs(changes, {label["name"] for label in pr["labels"]})
    if not missing:
        print("PR documentation policy: OK")
        return 0
    print("Missing corresponding docs or CHANGELOG.md for: " + ", ".join(missing), file=sys.stderr)
    print("If no documentation applies, a maintainer can add docs-not-needed.", file=sys.stderr)
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="check without writing")
    mode.add_argument("--pr-event", type=Path, help="check the documentation policy for a PR merge checkout")
    args = parser.parse_args()
    try:
        return pr_policy(ROOT, args.pr_event) if args.pr_event else sync(ROOT, args.check)
    except (KeyError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"sync-docs: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
