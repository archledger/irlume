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

Requires: Python 3.11+, cargo-deny on PATH, deny.toml in the repository root.
"""
import argparse
import datetime
import json
import re
import subprocess
import sys
import tempfile
import tomllib
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


def advisory_config(deny_path):
    """Locate the documented string-array ignore format in valid TOML."""
    text = deny_path.read_text(encoding="utf-8")
    try:
        config = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        sys.exit(f"generate-vex: invalid deny.toml: {error}")
    advisories = config.get("advisories", {})
    if not isinstance(advisories, dict):
        sys.exit("generate-vex: advisories must be a TOML table")
    ignored = advisories.get("ignore", [])
    if not isinstance(ignored, list) or any(not isinstance(item, str) for item in ignored):
        sys.exit("generate-vex: advisory ignores require strings with rationale comments")
    section = re.search(r"(?ms)^\[advisories\][ \t]*(?:#[^\n]*)?\n(.*?)(?=^\[|\Z)", text)
    match = None
    if section:
        # Comments may themselves contain brackets. Unsupported representations
        # fail closed; the TOML comparison below also protects all other settings.
        match = re.search(
            r'(?m)^[ \t]*ignore[ \t]*=[ \t]*\[((?:\s|#[^\n]*(?:\n|\Z)|"(?:[^"\\\n]|\\.)*"|,)*)\]',
            section.group(1),
        )
    if ignored and match is None:
        sys.exit("generate-vex: cannot locate the advisory ignore array")
    span = (section.start(1) + match.start(), section.start(1) + match.end()) if match and section else None
    return text, config, ignored, span, match.group(1) if match else ""


def parse_ignore_with_comments(deny_path):
    """Return [(advisory_id, comment_text)] from the [advisories] ignore list.

    Wrapped comment lines are joined WITHOUT introducing a space after a
    slash, so a source path split across lines (``crates/x/src/`` +
    ``pcrsig.rs``) reconstitutes to the real path ``crates/x/src/pcrsig.rs``.
    """
    _, _, ignored, _, body = advisory_config(deny_path)
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
    if [item[0] for item in entries] != ignored or len(set(ignored)) != len(ignored):
        sys.exit("generate-vex: each ignored advisory needs its own line and rationale comment")
    return entries


def check_advisories_apply(ids):
    """Verify every ignored advisory matches the CURRENT dependency graph.

    cargo-deny hides ignored advisories from its normal diagnostics, so this
    re-runs the advisory check with an actual config file whose ignore list is empty: any
    ignored-but-live advisory then FAILS the check and names itself. An ignore
    entry whose advisory does not appear that way is stale (or the vulnerable
    crate was removed), and a signed not_affected statement must describe the
    live tree - so stale entries abort generation.
    """
    text, config, ignored, span, _ = advisory_config(REPO / "deny.toml")
    if ids != ignored:
        sys.exit("generate-vex: advisory configuration changed during generation")
    scan_text = text
    if span:
        scan_text = text[:span[0]] + "ignore = []" + text[span[1]:]
        config["advisories"]["ignore"] = []
    if tomllib.loads(scan_text) != config:
        sys.exit("generate-vex: refusing to change settings beyond the advisory ignore list")
    try:
        # Keep the config beside deny.toml so relative paths retain their base.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=REPO,
                                         prefix=".vex-", suffix=".toml") as scan_config:
            scan_config.write(scan_text)
            scan_config.flush()
            proc = subprocess.run(
                ["cargo", "deny", "--workspace", "--locked", "--format", "json",
                 "--config", scan_config.name, "check", "advisories"],
                capture_output=True, text=True, check=False, cwd=REPO,
            )
    except FileNotFoundError:
        sys.exit("generate-vex: cargo-deny not on PATH; cannot validate the ignore list")
    live = set()
    errors = 0
    summaries = []
    try:
        for line in (proc.stdout + "\n" + proc.stderr).splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            fields = record["fields"]
            if record["type"] == "summary":
                summaries.append(fields["advisories"]["errors"])
            elif record["type"] == "diagnostic":
                if fields["severity"] not in {"error", "bug", "warning", "note", "help"}:
                    sys.exit("generate-vex: unsupported cargo-deny diagnostic severity")
                if fields.get("code") in {"index-failure", "index-cache-load-failure"}:
                    sys.exit("generate-vex: advisory registry scan was incomplete")
                advisory_codes = {"vulnerability", "notice", "unmaintained", "unsound"}
                if (fields.get("code") == "advisory-ignored"
                        or fields.get("code") in advisory_codes and fields["severity"] != "error"):
                    sys.exit("generate-vex: advisory evidence was unexpectedly suppressed")
                if fields["severity"] in {"error", "bug"}:
                    matches = [note[4:] for note in fields.get("notes", []) if note.startswith("ID: ")]
                    if (fields.get("code") not in advisory_codes
                            or len(matches) != 1 or matches[0] not in ids):
                        sys.exit("generate-vex: scan contains an unreviewed advisory or another error")
                    errors += 1
                    live.add(matches[0])
            elif record["type"] == "log":
                if fields.get("level", "").lower() not in {"warn", "info", "debug", "trace"}:
                    sys.exit("generate-vex: cargo-deny reported an error or unsupported log level")
            else:
                sys.exit("generate-vex: unsupported cargo-deny diagnostic record")
    except (ValueError, KeyError, TypeError, AttributeError):
        sys.exit("generate-vex: malformed cargo-deny JSON; cannot validate advisories")
    if (len(summaries) != 1 or type(summaries[0]) is not int or summaries[0] != errors
            or proc.returncode != (1 if errors else 0)):
        sys.exit("generate-vex: cargo-deny scan failed or did not report a complete advisory summary")
    return {advisory_id: advisory_id in live for advisory_id in ids}


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
    live = check_advisories_apply([a for a, _ in entries])
    doc = build_vex(args.version, entries, live)
    if not entries:
        print("Advisory scan completed with no ignored advisories; emitting an "
              "empty-statement document.", file=sys.stderr)
    out = Path(args.out) if args.out else REPO / f"irlume-{args.version}-vex.json"
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(doc['statements'])} statement(s))")


if __name__ == "__main__":
    main()
