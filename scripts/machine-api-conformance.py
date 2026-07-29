#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Check that an irlume build answers contract 1 the way docs/MACHINE-API.md says.

Written for consumers, not for this repository: it needs Python 3 and an irlume
binary, no Rust toolchain and no irlume source tree. A desktop integration can
run it in its own CI against whichever irlume versions it claims to support, and
a packager can run it after a build to confirm the packaging did not break the
machine surface.

It checks three things a consumer depends on and cannot see from a single call:

  * the envelope rules (one JSON document on stdout, nothing on stderr, exit
    codes, `data` and `error` never both present);
  * every advertised capability actually answers, so a capability is never a
    promise the build cannot keep;
  * contract negotiation refuses what it does not implement, before acting.

Schema validation needs the `jsonschema` package (Fedora `python3-jsonschema`,
Debian/Ubuntu `python3-jsonschema`, Arch `python-jsonschema`, or `pip install
jsonschema`). Without it the structural checks still run and the skipped ones
are reported rather than passed over quietly.

Only read-only commands are run. Nothing here enrolls, wires PAM, or writes.
"""

import argparse
import copy
import json
import os
import subprocess
import sys

# Capability name -> the argv that capability promises will work.
CAPABILITY_COMMANDS = {
    "version-json": ["version", "--json"],
    "status-json": ["status", "--json"],
    "doctor-json": ["doctor", "--json"],
    "profiles-list-json": ["profiles", "list", "--json"],
    "login-status-json": ["login", "status", "--json"],
    "login-plan-json": ["login", "plan", "--action", "enable", "--json"],
}

# Streaming capabilities operate the camera, so invoking them here would need
# hardware, a face, and tens of seconds. They are still checked, on the paths
# that are deterministic without a capture: the command must exist, negotiate a
# contract, and refuse a bad invocation with a single document rather than a
# stream. Listing them separately is the point. An unlisted capability lands in
# the "this script does not know that capability" skip, which reads as a pass
# and would let a streaming capability ship with nothing verifying it at all.
#
# Capability name -> (argv that must be refused, expected error code).
STREAMING_CAPABILITY_REFUSALS = {
    "auth-test-events": [
        (["auth", "test"], "usage-error"),
        (["auth", "test", "--events=jsonl", "--contract", "9"], "unsupported-contract"),
        # Preview is a separate capability. Accepting the flag and dropping it
        # would tell a consumer that frames were withheld by policy.
        (["auth", "test", "--events=jsonl", "--preview=ir-jpeg"], "usage-error"),
    ],
}

# Commands whose output must never contain these, per the security and privacy
# section of docs/MACHINE-API.md. Camera device nodes and PAM file paths are the
# two that a well-meaning addition would most plausibly reintroduce.
FORBIDDEN_SUBSTRINGS = ["/dev/video", "/etc/pam.d", "/usr/lib/pam.d"]

CONTRACT = 1


class Results:
    def __init__(self):
        self.passed = 0
        self.failed = []
        self.skipped = []

    def ok(self, what):
        self.passed += 1
        print(f"  ok      {what}")

    def fail(self, what, detail):
        self.failed.append((what, detail))
        print(f"  FAILED  {what}\n            {detail}")

    def skip(self, what, why):
        self.skipped.append((what, why))
        print(f"  skipped {what} ({why})")


def run(binary, argv, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [binary] + argv,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    return proc


def parse_document(results, what, proc):
    """Envelope rules that hold for every machine document. Returns the document
    or None, so a caller can stop rather than report the same break twice."""
    if proc.stderr != "":
        results.fail(what, f"stderr must be empty in machine mode, got: {proc.stderr!r}")
        return None
    if proc.stdout.count("\n") != 1 or not proc.stdout.endswith("\n"):
        results.fail(what, "stdout must be exactly one line holding one JSON document")
        return None
    try:
        document = json.loads(proc.stdout)
    except json.JSONDecodeError as error:
        results.fail(what, f"stdout is not valid JSON: {error}")
        return None
    if document.get("contract_version") != CONTRACT:
        results.fail(what, f"contract_version must be {CONTRACT}, got {document.get('contract_version')!r}")
        return None
    if not isinstance(document.get("ok"), bool):
        results.fail(what, "ok must be a boolean")
        return None
    if document["ok"] and "error" in document:
        results.fail(what, "a successful document must not carry an error")
        return None
    if not document["ok"] and "data" in document:
        results.fail(what, "a failed document must not carry data")
        return None
    if not document["ok"] and "error" not in document:
        results.fail(what, "a failed document must carry an error")
        return None
    return document


def strict_schema(schema):
    """The same schema with every described object closed.

    The published schema deliberately allows unknown properties: fields may be
    added within a contract version, so a consumer that rejects them breaks on an
    engine update the contract permits. This variant is for the engine's own CI,
    where a property nobody documented is worth seeing before it ships.
    """
    # Never close a subschema reached through `if`, `then`, `else` or `not`.
    # Those describe a condition or a fragment, not a whole object: closing the
    # `if` in {"if": {"properties": {"ok": {"const": true}}}} would make the
    # condition false for every real document, and closing a `then` that names
    # one property would reject the rest of the envelope. Shapes worth closing
    # all live in $defs and are reached directly.
    conditional_keys = {"if", "then", "else", "not"}

    def close(node, closable):
        if isinstance(node, dict):
            if closable and "properties" in node and "additionalProperties" not in node:
                node["additionalProperties"] = False
            for key, value in node.items():
                close(value, closable and key not in conditional_keys)
        elif isinstance(node, list):
            for item in node:
                close(item, closable)

    closed = copy.deepcopy(schema)
    close(closed, True)
    return closed


def load_validator(schema_path, strict):
    """Returns (validate_fn, note). validate_fn is None when validation cannot run."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        return None, (
            "install python3-jsonschema (Fedora/Debian/Ubuntu), python-jsonschema "
            "(Arch), or `pip install jsonschema`"
        )
    try:
        with open(schema_path, encoding="utf-8") as handle:
            schema = json.load(handle)
    except OSError as error:
        return None, f"cannot read {schema_path}: {error}"
    if strict:
        schema = strict_schema(schema)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    # A stream line is not the single-document envelope, so it is validated
    # against $defs/event instead of the root.
    event_validator = Draft202012Validator(
        {"$ref": "#/$defs/event", "$defs": schema.get("$defs", {})}
    )

    def validate(document, event=False):
        chosen = event_validator if event else validator
        return [
            f"{'/'.join(str(p) for p in error.absolute_path) or '<root>'}: {error.message}"
            for error in sorted(chosen.iter_errors(document), key=lambda e: list(e.absolute_path))
        ]

    return validate, None


def check_streaming_capability(results, binary, validate, capability, refusals):
    """Verify a streaming capability on the paths that need no camera.

    A refusal must arrive as ONE document with the documented error code, not as
    an event stream: the stream has not started, and a consumer that mis-invoked
    the command should get the same shape every other refusal uses. Exit status
    must be 2, matching the contract's usage-error rule.
    """
    for argv, expected in refusals:
        what = f"capability {capability} refuses: irlume {' '.join(argv)}"
        proc = run(binary, argv)
        document = parse_document(results, what, proc)
        if document is None:
            continue
        if document.get("ok") is not False:
            results.fail(what, "a refusal must set ok=false")
            continue
        code = document.get("error", {}).get("code")
        if code != expected:
            results.fail(what, f"expected error code {expected!r}, got {code!r}")
            continue
        if proc.returncode != 2:
            results.fail(what, f"a refusal must exit 2, got {proc.returncode}")
            continue
        # One document, not a stream. More than one line here would mean the
        # command began streaming before it validated its arguments.
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        if len(lines) != 1:
            results.fail(what, f"a refusal must be one document, got {len(lines)} lines")
            continue
        if validate is not None:
            # validate returns a LIST of messages; empty means valid.
            errors = validate(document)
            if errors:
                results.fail(what, "schema: " + "; ".join(errors[:5]))
                continue
        results.ok(what)


def check_engine(results, binary, validate, validate_note):
    print(f"\nengine: {binary}")
    proc = run(binary, ["version", "--json"])
    document = parse_document(results, "version --json envelope", proc)
    if document is None:
        results.fail("engine", "version --json did not produce a usable document; stopping")
        return
    results.ok("version --json envelope")
    if proc.returncode != 0:
        results.fail("version --json exit code", f"expected 0, got {proc.returncode}")
    else:
        results.ok("version --json exit code")

    data = document.get("data", {})
    capabilities = data.get("capabilities", [])
    # An engine that advertises nothing gives the per-capability loop below
    # nothing to iterate, so every capability check silently does not happen and
    # the run still ends green. Contract 1 requires version-json at minimum, so
    # an empty list is a broken engine rather than a modest one.
    if not capabilities:
        results.fail(
            "advertised capabilities",
            "the engine advertises no capabilities, so no capability was checked",
        )
    versions = data.get("contract_versions", {})
    if versions.get("min", 0) <= CONTRACT <= versions.get("max", 0):
        results.ok(f"engine speaks contract {CONTRACT} (range {versions.get('min')}-{versions.get('max')})")
    else:
        results.fail(
            "contract range",
            f"this script checks contract {CONTRACT}, engine advertises {versions}",
        )
        return

    # Every advertised capability must answer. A capability that does not is
    # worse than a missing one: consumers enable behaviour on seeing the name.
    for capability in capabilities:
        refusals = STREAMING_CAPABILITY_REFUSALS.get(capability)
        if refusals is not None:
            check_streaming_capability(results, binary, validate, capability, refusals)
            continue
        argv = CAPABILITY_COMMANDS.get(capability)
        if argv is None:
            results.skip(
                f"capability {capability}",
                "this script does not know that capability; it is newer than the script",
            )
            continue
        what = f"capability {capability} -> irlume {' '.join(argv)}"
        proc = run(binary, argv)
        document = parse_document(results, what, proc)
        if document is None:
            continue
        if document["ok"] and proc.returncode != 0:
            results.fail(what, f"ok document with nonzero exit {proc.returncode}")
            continue
        if not document["ok"] and proc.returncode == 0:
            results.fail(what, "error document with exit 0")
            continue
        leaked = [s for s in FORBIDDEN_SUBSTRINGS if s in proc.stdout]
        if leaked:
            results.fail(what, f"output contains paths the contract does not publish: {leaked}")
            continue
        if validate is not None:
            errors = validate(document)
            if errors:
                results.fail(what, "schema: " + "; ".join(errors[:5]))
                continue
        results.ok(what)

    for capability, argv in CAPABILITY_COMMANDS.items():
        if capability not in capabilities:
            results.skip(f"capability {capability}", "not advertised by this build")

    if validate is None:
        results.skip("schema validation", validate_note)

    # Negotiation refuses before acting. An engine that ignores --contract would
    # let a consumer act on semantics it does not implement.
    negotiation = [
        (["status", "--contract", "999", "--json"], "unsupported-contract"),
        (["status", "--contract", "not-a-number", "--json"], "usage-error"),
        (["status", "--contract", "--json"], "usage-error"),
        (["version", "--json", "--no-such-flag"], "usage-error"),
        # The flag BEFORE the subcommand, on the two commands that have one.
        # Every case above puts it last, which is why this script could not see
        # that `profiles --contract 9 list --json` and `login --contract 9 status
        # --json` used to fall through to the human handler and answer a machine
        # caller with prose on stderr. The contract states no ordering rule, so
        # neither may this.
        (["profiles", "--contract", "999", "list", "--json"], "unsupported-contract"),
        (["login", "--contract", "999", "status", "--json"], "unsupported-contract"),
    ]
    for argv, expected in negotiation:
        what = f"refusal: irlume {' '.join(argv)} -> {expected}"
        proc = run(binary, argv)
        document = parse_document(results, what, proc)
        if document is None:
            continue
        code = document.get("error", {}).get("code")
        if code != expected:
            results.fail(what, f"expected error code {expected!r}, got {code!r}")
        elif proc.returncode != 2:
            results.fail(what, f"expected exit 2, got {proc.returncode}")
        else:
            results.ok(what)


def check_fixtures(results, fixtures_dir, validate, validate_note):
    print(f"\nfixtures: {fixtures_dir}")
    try:
        names = sorted(n for n in os.listdir(fixtures_dir) if n.endswith(".json"))
    except OSError as error:
        results.fail("fixtures", f"cannot read {fixtures_dir}: {error}")
        return
    if not names:
        results.fail("fixtures", f"no .json files in {fixtures_dir}")
        return
    for name in names:
        path = os.path.join(fixtures_dir, name)
        what = f"fixture {name}"
        try:
            with open(path, encoding="utf-8") as handle:
                raw = handle.read()
            document = json.loads(raw)
        except (OSError, json.JSONDecodeError) as error:
            results.fail(what, str(error))
            continue
        # Fixtures are captures, so they must look like what the engine writes:
        # one line, no trailing blank.
        if raw.count("\n") != 1 or not raw.endswith("\n"):
            results.fail(what, "a fixture must be one line, as written by the engine")
            continue
        if validate is None:
            results.skip(what, validate_note)
            continue
        errors = validate(document)
        if errors:
            results.fail(what, "schema: " + "; ".join(errors[:5]))
        else:
            results.ok(what)

    check_stream_fixtures(results, fixtures_dir, validate, validate_note)


def check_stream_fixtures(results, fixtures_dir, validate, validate_note):
    """Validate NDJSON stream captures, line by line, plus the stream rules.

    Kept separate from the single-document fixtures because the loader above
    matches only *.json. A stream capture dropped into the same directory would
    otherwise be listed by nobody and checked by nothing, which reads exactly
    like a directory that happens to hold no streams.
    """
    try:
        names = sorted(n for n in os.listdir(fixtures_dir) if n.endswith(".ndjson"))
    except OSError as error:
        results.fail("stream fixtures", f"cannot read {fixtures_dir}: {error}")
        return
    for name in names:
        what = f"stream fixture {name}"
        try:
            with open(os.path.join(fixtures_dir, name), encoding="utf-8") as handle:
                lines = [json.loads(line) for line in handle if line.strip()]
        except (OSError, json.JSONDecodeError) as error:
            results.fail(what, str(error))
            continue
        if not lines:
            results.fail(what, "a stream fixture must contain at least one event")
            continue
        # The three promises a consumer relies on, checked on a real capture.
        sequences = [line.get("sequence") for line in lines]
        if sequences != list(range(len(lines))):
            results.fail(what, f"sequence must start at 0 and be gapless, got {sequences}")
            continue
        terminals = [bool(line.get("terminal")) for line in lines]
        if terminals.count(True) != 1 or not terminals[-1]:
            results.fail(what, "exactly one event must be terminal, and it must be last")
            continue
        ids = {line.get("operation_id") for line in lines}
        # Present and non-empty on EVERY line, not merely equal: a set of one
        # None has length one, so an equality check alone accepts a fixture
        # where no line carries an operation_id at all.
        if None in ids or "" in ids:
            results.fail(what, "every line must carry a non-empty operation_id")
            continue
        if len(ids) != 1:
            results.fail(what, "every line must carry the same operation_id")
            continue
        if validate is None:
            results.skip(what, validate_note)
            continue
        bad = []
        for index, line in enumerate(lines):
            errors = validate(line, event=True)
            if errors:
                bad.append(f"line {index}: {errors[0]}")
        if bad:
            results.fail(what, "schema: " + "; ".join(bad[:5]))
        else:
            results.ok(what)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    parser = argparse.ArgumentParser(
        description="Check an irlume build against the contract 1 machine API."
    )
    parser.add_argument(
        "--irlume",
        default="irlume",
        help="the irlume binary to check (default: irlume on PATH)",
    )
    parser.add_argument(
        "--schema",
        default=os.path.join(root, "schemas", "machine-api-v1.schema.json"),
        help="the contract 1 schema (default: the one beside this script; installed builds carry it in /usr/share/irlume/schemas)",
    )
    parser.add_argument(
        "--fixtures",
        default=os.path.join(root, "schemas", "fixtures", "v1"),
        help="directory of captured documents to validate as well",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="also fail on properties the schema does not describe (for the engine's own CI; a consumer must accept added fields)",
    )
    parser.add_argument(
        "--no-engine",
        action="store_true",
        help="check the fixtures only, without running a binary",
    )
    parser.add_argument(
        "--no-fixtures",
        action="store_true",
        help="check the engine only",
    )
    args = parser.parse_args()

    validate, validate_note = load_validator(args.schema, args.strict)
    if validate is None and args.strict:
        # A run that could not validate must not look like a run that validated.
        # Permissive mode degrades to the structural checks and says so, which
        # suits someone trying the script out; --strict is what a pipeline runs,
        # and there a missing validator is a broken pipeline, not a green one.
        print(f"cannot validate, and --strict will not pass without it: {validate_note}", file=sys.stderr)
        return 2
    results = Results()

    if not args.no_engine:
        check_engine(results, args.irlume, validate, validate_note)
    if not args.no_fixtures:
        check_fixtures(results, args.fixtures, validate, validate_note)

    print(
        f"\n{results.passed} passed, {len(results.failed)} failed, "
        f"{len(results.skipped)} skipped"
    )
    if results.skipped:
        print("skipped checks are not passes:")
        for what, why in results.skipped:
            print(f"  {what}: {why}")
    if results.failed:
        print("failures:")
        for what, detail in results.failed:
            print(f"  {what}: {detail}")
        return 1
    # A run that checked nothing is not a pass. `--no-engine --no-fixtures`
    # disables both halves and used to print "0 passed, 0 failed" and exit 0,
    # which is the exact shape this script exists to catch elsewhere: a green
    # result from a check that never ran. An empty capability list produces the
    # same thing by a different route, since the per-capability loop simply has
    # nothing to iterate.
    if results.passed == 0 and not results.skipped:
        print(
            "nothing was attempted, so nothing passed: this is a failure, not a clean run.\n"
            "  --no-engine and --no-fixtures cannot both be given.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FileNotFoundError as error:
        print(f"cannot run: {error}", file=sys.stderr)
        sys.exit(2)
