#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Capture the machine-API fixtures in schemas/fixtures/ from a real engine.

The fixtures exist so a consumer can develop against documents irlume actually
wrote rather than documents someone imagined. That only holds if they are
re-captured from a real run when the surface changes, which is what this script
is for; run it before cutting a release, and commit what changes.

Every document here comes from a read-only command. Nothing enrolls, wires PAM,
or writes to the system.

Two fields are not verbatim, and both are deliberate:

  * profile and scan display names are replaced with neutral placeholders,
    because they are user text and the maintainer capturing a fixture should not
    have to publish their own;
  * `engine_version` is left exactly as the engine wrote it, so a stale fixture
    set is visible rather than hidden.

Usage:  scripts/capture-machine-fixtures.py [--irlume PATH] [--out DIR]
"""

import argparse
import json
import os
import subprocess
import sys

UNREACHABLE_SOCKET = "/nonexistent/irlume-fixture-capture.sock"


def run(binary, argv, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run([binary] + argv, capture_output=True, text=True, env=env, timeout=180)
    if proc.stderr:
        print(f"warning: {' '.join(argv)} wrote to stderr: {proc.stderr.strip()}", file=sys.stderr)
    return proc.stdout


def redact_profiles(raw):
    """Replace user-chosen display names with placeholders, keeping the counts,
    the ordering and every other field as captured."""
    document = json.loads(raw)
    profiles = document.get("data", {}).get("profiles", [])
    for profile_index, profile in enumerate(profiles, start=1):
        profile["display_name"] = f"Face Profile {profile_index}"
        for scan_index, scan in enumerate(profile.get("scans", []), start=1):
            scan["display_name"] = f"Face Scan {scan_index}"
    # separators match serde_json's compact form, so a fixture stays
    # byte-comparable with engine output apart from the redacted names.
    return json.dumps(document, separators=(",", ":"), sort_keys=False) + "\n"


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--irlume", default="irlume", help="the binary to capture from")
    parser.add_argument("--out", default=os.path.join(root, "schemas", "fixtures", "v1"))
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    unreachable = {"IRLUME_SOCKET": UNREACHABLE_SOCKET}
    captures = [
        ("version.json", ["version", "--json"], None, None),
        ("status-daemon-running.json", ["status", "--json"], None, None),
        ("status-daemon-unreachable.json", ["status", "--json"], unreachable, None),
        ("doctor.json", ["doctor", "--json"], None, None),
        ("login-status.json", ["login", "status", "--json"], None, None),
        ("profiles-list.json", ["profiles", "list", "--json"], None, redact_profiles),
        (
            "error-daemon-unavailable.json",
            ["profiles", "list", "--json"],
            unreachable,
            None,
        ),
        ("error-unsupported-contract.json", ["status", "--contract", "999", "--json"], None, None),
        ("error-usage-error.json", ["version", "--json", "--no-such-flag"], None, None),
    ]

    for name, argv, env_extra, transform in captures:
        raw = run(args.irlume, argv, env_extra)
        if transform is not None:
            raw = transform(raw)
        path = os.path.join(args.out, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(raw)
        document = json.loads(raw)
        state = "ok" if document.get("ok") else document.get("error", {}).get("code")
        print(f"{name}: {document.get('command')} ({state})")

    print(
        "\nCaptured. Read the diff before committing: a fixture is a claim about "
        "what this engine writes."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
