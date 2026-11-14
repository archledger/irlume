#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Refresh the tracked per-crate CycloneDX SBOMs under crates/.

cargo-cyclonedx writes machine-specific identities: path+file bom-refs naming
the checkout and local download_url purl qualifiers. release_sbom's
normalize_sbom rewrites them to purl identities, so the committed documents
describe the tree, not the machine that generated them (#1346).

Release SBOM assets are a different flow (scripts/generate-release-sbom.py,
run from a tag checkout into a caller-chosen directory) and stay untouched.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tomllib

from release_sbom import normalize_sbom

PATTERN = "crates/*/irlume-*.cdx.json"
PINNED_TOOLS = {"cargo-cyclonedx 0.5.9", "cargo-cyclonedx-cyclonedx 0.5.9"}


def tracked_documents(repo):
    listed = subprocess.check_output(["git", "ls-files", "--", PATTERN],
                                     cwd=repo, text=True).splitlines()
    if not listed:
        raise ValueError(f"no tracked SBOM documents match {PATTERN}")
    return listed


def refresh(repo):
    repo = Path(repo)
    manifest = repo / "Cargo.toml"
    version = tomllib.loads(manifest.read_text())["workspace"]["package"]["version"]
    tool_version = subprocess.check_output(["cargo", "cyclonedx", "--version"],
                                           text=True).strip()
    if tool_version not in PINNED_TOOLS:
        raise ValueError(f"need cargo-cyclonedx 0.5.9, found {tool_version}")
    tracked = tracked_documents(repo)
    lock = repo / "Cargo.lock"
    before = lock.read_bytes()
    existing = set(repo.glob(PATTERN))
    # A lockfile the manifest disagrees with is refused before any file is
    # touched, the way the release flow refuses it (generate-release-sbom.py):
    # without this, a drift run would leave raw, unnormalized documents and a
    # changed lockfile behind after it fails.
    subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1",
                    "--manifest-path", str(manifest)], cwd=repo,
                   stdout=subprocess.DEVNULL, check=True)
    subprocess.run(["cargo", "cyclonedx", "--manifest-path", str(manifest),
                    "--format", "json", "--spec-version", "1.3"], cwd=repo, check=True)
    if lock.read_bytes() != before:
        raise ValueError("SBOM generation changed Cargo.lock")
    for relative in tracked:
        path = repo / relative
        document = normalize_sbom(json.loads(path.read_text()))
        component = document.get("metadata", {}).get("component", {})
        if component.get("name") != path.parent.name or component.get("version") != version:
            raise ValueError(f"unexpected SBOM component identity in {relative}")
        path.write_text(json.dumps(document, indent=2) + "\n")
        print(f"refreshed {relative} ({len(document.get('components', []))} components)")
    # cargo-cyclonedx writes a document for every workspace member; members
    # whose document this run created and whose SBOM is not tracked are
    # clutter, so remove them again.
    for path in sorted(set(repo.glob(PATTERN)) - existing):
        if path.relative_to(repo).as_posix() not in tracked:
            path.unlink()
            print(f"removed untracked {path.relative_to(repo).as_posix()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    try:
        refresh(Path(__file__).resolve().parent.parent)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"tracked SBOM refresh failed: {error}\n")


if __name__ == "__main__":
    main()
