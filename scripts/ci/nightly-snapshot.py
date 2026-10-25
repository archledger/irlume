#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Read-only daily source selection. A candidate is not a published release."""

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import jsonschema
import nightly_snapshot_github as github

REPOSITORY = "archledger/irlume"
REF = "refs/heads/main"
ACTIONS_APP = 15368
CHECKS = {
    "fmt · clippy · build · test": "ci.yml",
    "test (stable)": "ci.yml",
    "fuzz (untrusted-input parsers)": "ci.yml",
    "cargo-deny (advisories · licenses · duplicate versions)": "ci.yml",
    "systemd units (verify + exposure ratchet)": "ci.yml",
    "nix flake check": "ci.yml",
    "DCO (exactly one trailer)": "dco.yml",
    "actionlint (workflow correctness)": "workflow-audit.yml",
    "zizmor (workflow security)": "workflow-audit.yml",
}
REQUIRED = tuple(list(CHECKS)[:7])
# Source declarations, not a resolved native-library or build dependency closure.
# The full Git tree also binds source files outside this diagnostic inventory.
INPUTS = (
    ".github/workflows/ci.yml",
    ".github/workflows/dco.yml",
    ".github/workflows/workflow-audit.yml",
    "Cargo.lock",
    "Cargo.toml",
    "flake.lock",
    "fuzz/Cargo.lock",
    "fuzz/Cargo.toml",
    "models/SHA256SUMS",
    "nix/package.nix",
    "packaging/arch/PKGBUILD",
    "packaging/debian/nfpm.yaml",
    "packaging/fedora/irlume.spec",
    "packaging/ppa/container-build.sh",
    "scripts/build-tflite-runtime.sh",
    "scripts/fetch-models.sh",
    "scripts/fetch-ort.sh",
)
LIMIT = 1024 * 1024
POLICY = {
    "version": 1,
    "repository": REPOSITORY,
    "ref": REF,
    "app_id": ACTIONS_APP,
    "checks": CHECKS,
    "required": REQUIRED,
    "inputs": INPUTS,
}


def canonical(value):
    """Stable JSON bytes for local identity comparisons, not a signature."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


POLICY_DIGEST = hashlib.sha256(canonical(POLICY)).hexdigest()


def load_json(data):
    """Reject ambiguous or unbounded JSON before schema/semantic validation."""
    if len(data) > LIMIT:
        raise ValueError("json-too-large")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate-json-key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("non-finite-json-number")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("invalid-json") from error


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("invalid-object-fields")


def identifier(value, length=40):
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise ValueError("invalid-digest")


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", value
    ):
        raise ValueError("invalid-utc-timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_source(value):
    if value["repository"] != REPOSITORY or value["ref"] != REF:
        raise ValueError("wrong-source")
    identifier(value["commit"])
    identifier(value["tree"])
    slot = value["slot"]
    if not isinstance(slot, str) or not re.fullmatch(r"\d{4}-\d\d-\d\d", slot):
        raise ValueError("invalid-slot")
    if date.fromisoformat(slot) != timestamp(value["observed_at"]).date():
        raise ValueError("slot-observation-date-mismatch")
    inputs = value["inputs"]
    if not isinstance(inputs, list) or len(inputs) != len(INPUTS):
        raise ValueError("incomplete-input-inventory")
    paths = []
    for item in inputs:
        keys(item, ("path", "blob", "sha256"))
        identifier(item["blob"])
        identifier(item["sha256"], 64)
        paths.append(item["path"])
    if paths != list(INPUTS):
        raise ValueError("wrong-input-inventory")


def check_reason(value):
    checks = value["checks"]
    if not isinstance(checks, list):
        raise TypeError("invalid-check-list")
    # Validate all entries before returning a qualification hold. Otherwise
    # malformed input could be hidden behind an earlier unsuccessful check.
    for check in checks:
        keys(
            check,
            (
                "name",
                "workflow",
                "commit",
                "app_id",
                "workflow_id",
                "run_id",
                "attempt",
                "job_id",
                "status",
                "conclusion",
                "completed_at",
            ),
        )
        for key in ("name", "workflow", "status"):
            if not isinstance(check[key], str):
                raise TypeError("invalid-check-string")
        if check["conclusion"] is not None and not isinstance(check["conclusion"], str):
            raise ValueError("invalid-check-conclusion")
        identifier(check["commit"])
        for key in ("app_id", "workflow_id", "run_id", "attempt", "job_id"):
            if type(check[key]) is not int or check[key] <= 0:
                raise ValueError("invalid-check-identifier")
        if check["completed_at"] is not None or (
            check["status"] == "completed" and check["conclusion"] == "success"
        ):
            timestamp(check["completed_at"])
    if len(checks) != len(CHECKS):
        return "incomplete-checks"
    names = []
    workflow_ids = {}
    job_ids = set()
    for check in checks:
        name = check["name"]
        if CHECKS.get(name) != check["workflow"]:
            return "wrong-check-identity"
        if check["commit"] != value["commit"] or check["app_id"] != ACTIONS_APP:
            return "wrong-check-identity"
        run = (check["workflow_id"], check["run_id"], check["attempt"])
        workflow = check["workflow"]
        if workflow in workflow_ids and workflow_ids[workflow] != run:
            return "mixed-workflow-attempts"
        workflow_ids[workflow] = run
        if check["job_id"] in job_ids:
            return "duplicate-job"
        job_ids.add(check["job_id"])
        names.append(name)
        if check["status"] != "completed" or check["conclusion"] != "success":
            return "checks-not-successful"
        if timestamp(check["completed_at"]) > timestamp(value["observed_at"]):
            return "future-check"
    if set(names) != set(CHECKS) or len(set(names)) != len(names):
        return "incomplete-checks"
    return None


def validate_candidate(value):
    """Validate structure and cross-field invariants of a candidate record."""
    schema = load_json(
        (
            Path(__file__).resolve().parents[2]
            / "schemas/nightly-candidate-v1.schema.json"
        ).read_bytes()
    )
    try:
        jsonschema.Draft202012Validator(schema).validate(value)
    except jsonschema.ValidationError as error:
        raise ValueError("invalid-candidate-schema") from error
    validate_source(value)
    if value["policy_sha256"] != POLICY_DIGEST or value["candidate_id"] != candidate_id(
        value
    ):
        raise ValueError("candidate-identity-mismatch")
    if check_reason(value):
        raise ValueError("candidate-checks-invalid")


def candidate_id(value):
    return f"nightly-{value['slot'].replace('-', '')}-g{value['commit'][:12]}"


def identity(value):
    return (
        value["commit"],
        value["tree"],
        canonical(value["inputs"]),
        value["policy_sha256"],
        value["evidence_origin"],
    )


def decide(value, previous=None, *, origin="fixture"):
    """Pure selection. Fixture input never acquires live evidence provenance."""
    keys(
        value,
        (
            "repository",
            "ref",
            "commit",
            "tree",
            "main_after",
            "slot",
            "observed_at",
            "required_checks",
            "inputs",
            "checks",
        ),
    )
    validate_source(value)
    identifier(value["main_after"])
    required = value["required_checks"]
    if not isinstance(required, list) or any(
        not isinstance(name, str) for name in required
    ):
        raise ValueError("invalid-required-check-list")
    reason = check_reason(value)
    if origin not in ("fixture", "github-api"):
        raise ValueError("invalid-evidence-origin")
    if previous is not None:
        validate_candidate(previous)
        if previous["evidence_origin"] != origin:
            raise ValueError("previous-evidence-origin-mismatch")

    def hold(reason):
        return {"outcome": "hold", "reason": reason}

    if value["main_after"] != value["commit"]:
        return hold("main-moved")
    if required != sorted(REQUIRED):
        return hold("required-policy-drift")
    if reason:
        return hold(reason)
    candidate = {
        key: value[key]
        for key in (
            "repository",
            "ref",
            "commit",
            "tree",
            "slot",
            "observed_at",
            "inputs",
            "checks",
        )
    }
    candidate.update(
        schema_version=1,
        kind="nightly-candidate",
        candidate_id=candidate_id(value),
        policy_version=POLICY["version"],
        policy_sha256=POLICY_DIGEST,
        evidence_origin=origin,
        input_scope="source-declarations-not-build-closure",
    )
    validate_candidate(candidate)
    if previous:
        if previous["slot"] > candidate["slot"]:
            return hold("slot-regression")
        if identity(previous) == identity(candidate):
            return {
                "outcome": "unchanged",
                "reason": "same-source-inputs-policy",
                "previous_candidate_id": previous["candidate_id"],
            }
        if previous["slot"] == candidate["slot"]:
            return hold("slot-conflict")
    return {
        "outcome": "selected",
        "reason": "source-checks-passed",
        "candidate": candidate,
    }


def read_descriptor(fd):
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise ValueError("input-not-regular")
    with os.fdopen(fd, "rb", closefd=False) as stream:
        return load_json(stream.read(LIMIT + 1))


def read_local(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        return read_descriptor(fd)
    finally:
        os.close(fd)


def write_candidate(path, candidate):
    """Publish a complete local file without replacing an existing inode."""
    validate_candidate(candidate)
    path = Path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = ".nightly-" + secrets.token_hex(16)
    created = False
    try:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("output-directory-not-private")
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        created = True
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(candidate) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(
                temporary,
                path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing_fd = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
            )
            try:
                info = os.fstat(existing_fd)
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise ValueError("unsafe-existing-output")
                existing = read_descriptor(existing_fd)
            finally:
                os.close(existing_fd)
            validate_candidate(existing)
            if existing["slot"] != candidate["slot"] or identity(existing) != identity(
                candidate
            ):
                raise ValueError("output-conflict")
            return existing
        os.fsync(directory)
        return candidate
    finally:
        if created:
            os.unlink(temporary, dir_fd=directory)
        os.close(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--fixture",
        type=Path,
        help="untrusted offline observation, never live evidence",
    )
    mode.add_argument(
        "--collect", action="store_true", help="GET-only collection from GitHub"
    )
    parser.add_argument(
        "--slot", help="UTC date for live collection; defaults to today"
    )
    parser.add_argument(
        "--previous", type=Path, help="previous complete candidate record"
    )
    parser.add_argument(
        "--output", type=Path, help="new immutable candidate file; no writes on hold"
    )
    args = parser.parse_args(argv)
    try:
        previous = read_local(args.previous) if args.previous else None
        origin = "github-api" if args.collect else "fixture"
        if previous is not None:
            validate_candidate(previous)
            if previous["evidence_origin"] != origin:
                raise ValueError("previous-evidence-origin-mismatch")
        if args.collect:
            now = datetime.now(timezone.utc)
            slot = args.slot or now.date().isoformat()
            if date.fromisoformat(slot) != now.date():
                raise ValueError("live-slot-must-be-today")
            value = github.collect(
                github.Github(load_json),
                POLICY,
                slot,
                now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            value["observed_at"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        else:
            if args.slot:
                raise ValueError("fixture-slot-is-in-observation")
            value = read_local(args.fixture)
        result = decide(value, previous, origin=origin)
        if args.output and result["outcome"] == "selected":
            result["candidate"] = write_candidate(args.output, result["candidate"])
    except github.Hold as error:
        result = {"outcome": "hold", "reason": str(error)}
    except (ValueError, TypeError, KeyError, AttributeError, OSError, OverflowError):
        print(
            json.dumps(
                {"outcome": "hold", "reason": "invalid-input-or-unavailable-evidence"}
            )
        )
        print(
            "nightly-snapshot: input, evidence, or output validation failed",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
