#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Generate an OpenVEX document for an irlume release.

The statements come from the cargo-deny advisory configuration: every advisory
listed in deny.toml's [advisories].ignore carries, in its comment, the reason
the project is NOT affected. This script parses that file, cross-checks that
each ignored advisory actually applies to the current dependency graph via
`cargo deny check advisories` diagnostics, and emits an OpenVEX statement per
advisory with the documented justification. A rationale whose wording does not
map to a known OpenVEX justification FAILS generation: an unreviewed
suppression must never silently become a signed security claim.

Output is signed together with the release assets (SHA256SUMS); the document
itself carries the project's identity, the release version, and the tool that
produced it.

Usage:
  scripts/generate-vex.py --version 0.13.0 [--out FILE.vex.json]

Requires: cargo-deny on PATH, deny.toml in the repository root.
"""
import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Map deny.toml comment phrasing to OpenVEX justification ids (J401
# vocabulary). A suppression whose comment matches NONE of these aborts
# generation: extend this table with an explicit, reviewed mapping instead of
# defaulting the claim.
JUSTIFICATIONS = {
    "no private-key operations": "vulnerable_code_not_in_execute_path",
    "not in execute path": "vulnerable_code_not_in_execute_path",
    "build-dependency": "vulnerable_code_not_in_execute_path",
    "build dependency": "vulnerable_code_not_in_execute_path",
    "never links into any shipped binary": "vulnerable_code_not_in_execute_path",
    "vulnerable code is not reached": "vulnerable_code_not_in_execute_path",
}


def parse_ignore_with_comments(deny_path):
    """Return [(advisory_id, comment_text)] from the [advisories] ignore list.

    Wrapped comment lines are joined WITHOUT introducing a space after a
    slash, so a source path split across lines (``crates/x/src/`` +
    ``pcrsig.rs``) reconstitutes to the real path ``crates/x/src/pcrsig.rs``.
    """
    text = deny_path.read_text(encoding="utf-8")
    section = re.search(r"\[advisories\](.*?)(\n\[|\Z)", text, re.S)
    if section is None:
        return []
    body = section.group(1)
    entries = []
    pending = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            pending.append(stripped.lstrip("# ").rstrip())
        elif stripped.startswith('"'):
            match = re.match(r'"([^"]+)"', stripped)
            if match:
                joined = ""
                for piece in pending:
                    if joined.endswith("/"):
                        joined += piece
                    elif joined:
                        joined += " " + piece
                    else:
                        joined = piece
                entries.append((match.group(1), joined))
            pending = []
        elif not stripped:
            continue
        else:
            pending = []
    return entries


def check_advisories_apply(ids):
    """Verify every ignored advisory matches the CURRENT dependency graph.

    cargo-deny hides ignored advisories from its normal diagnostics, so this
    re-runs the advisory check with the ignore list emptied via --config: any
    ignored-but-live advisory then FAILS the check and names itself. An ignore
    entry whose advisory does not appear that way is stale (or the vulnerable
    crate was removed), and a signed not_affected statement must describe the
    live tree - so stale entries abort generation.
    """
    try:
        proc = subprocess.run(
            ["cargo", "deny", "--workspace", "--config",
             "advisories.ignore=[]", "check", "advisories"],
            capture_output=True, text=True, check=False,
            cwd=REPO,
        )
    except FileNotFoundError:
        sys.exit("generate-vex: cargo-deny not on PATH; cannot validate the ignore list")
    combined = proc.stdout + proc.stderr
    live = {}
    for advisory_id in ids:
        live[advisory_id] = advisory_id in combined
    return live


def build_vex(version, entries, live):
    now = datetime.datetime.now(datetime.timezone.utc)
    doc_id = (
        f"https://github.com/archledger/irlume/vex/{version}/"
        f"{now.strftime('%Y%m%dT%H%M%SZ')}"
    )
    statements = []
    for advisory_id, comment in entries:
        justification = None
        for needle, vex_id in JUSTIFICATIONS.items():
            if needle.lower() in comment.lower():
                justification = vex_id
                break
        if justification is None:
            sys.exit(
                f"generate-vex: deny.toml advisory {advisory_id} has a rationale that maps "
                "to no OpenVEX justification:\n  " + comment
                + "\nExtend JUSTIFICATIONS with an explicit reviewed mapping "
                "(or reword the deny.toml comment) instead of defaulting the claim."
            )
        if not live.get(advisory_id):
            sys.exit(
                f"generate-vex: advisory {advisory_id} is ignored in deny.toml but does "
                "not match any crate in the current dependency graph (stale ignore, or the "
                "vulnerable crate was removed). Remove the ignore entry or re-verify; a "
                "signed not_affected statement must describe the live tree."
            )
        statements.append({
            "vulnerability": {"name": advisory_id},
            "products": [
                f"pkg:generic/irlume@{version}",
                f"pkg:generic/irlume-{version}-1-x86_64",
                f"pkg:deb/irlume@{version}",
            ],
            "status": "not_affected",
            "justification": justification,
            "impact_statement": comment,
        })
    doc = {
        "@context": "https://openvex.dev/ns",
        "@id": doc_id,
        "author": "Wisbendji Fimerlus <archledger236@gmail.com>",
        "timestamp": now.isoformat(),
        "version": 1,
        "tooling": (
            "scripts/generate-vex.py over cargo-deny advisories; "
            "source of truth: deny.toml [advisories].ignore; each statement "
            "cross-checked against the live dependency graph"
        ),
        "product": {
            "name": "irlume",
            "version": version,
            "download_url": f"https://github.com/archledger/irlume/releases/tag/v{version}",
        },
        "statements": statements,
    }
    return doc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="release version, e.g. 0.13.0")
    parser.add_argument("--out", default=None, help="output path (default irlume-<v>-vex.json)")
    args = parser.parse_args()

    deny = REPO / "deny.toml"
    entries = parse_ignore_with_comments(deny)
    if not entries:
        print("deny.toml lists no ignored advisories; emitting an empty-statement "
              "document that records the clean scan.", file=sys.stderr)
    live = check_advisories_apply([a for a, _ in entries])
    doc = build_vex(args.version, entries, live)
    out = Path(args.out) if args.out else REPO / f"irlume-{args.version}-vex.json"
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(doc['statements'])} statement(s))")


if __name__ == "__main__":
    main()
