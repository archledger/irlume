#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Generate six Rust release SBOMs from a committed, isolated source snapshot."""
import argparse
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

from release_sbom import normalize_sbom

ROOT = Path(__file__).resolve().parent.parent
CRATES = ("cli", "daemon", "pam", "kwallet-init", "gkr-unlock", "password-verify")


def extract_source(tree, stage):
    # Git source snapshots need regular files and directories only. Copy their
    # bytes rather than relying on tar extraction filters absent in Python 3.11.2.
    for member in tree:
        relative = PurePosixPath(member.name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("source archive contains an unsafe path")
        destination = stage.joinpath(*relative.parts)
        if member.isdir():
            destination.mkdir(parents=True, exist_ok=True)
        elif member.isfile():
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tree.extractfile(member) as source, destination.open("xb") as output:
                shutil.copyfileobj(source, output)
            destination.chmod(member.mode & 0o777)
        else:
            raise ValueError("source archive must contain only regular files and directories")


def generate(repo, revision, version, output):
    output = output.resolve()
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"], cwd=repo, text=True).strip()
    with tempfile.TemporaryDirectory(prefix="irlume-sbom-source-") as temporary:
        stage = Path(temporary)
        with tempfile.TemporaryFile() as archive:
            subprocess.run(["git", "archive", "--format=tar", commit], cwd=repo,
                           stdout=archive, check=True)
            archive.seek(0)
            with tarfile.open(fileobj=archive) as tree:
                extract_source(tree, stage)
        manifest = stage / "Cargo.toml"
        source_version = tomllib.loads(manifest.read_text())["workspace"]["package"]["version"]
        if source_version != version:
            raise ValueError(f"source version {source_version} does not match requested {version}")
        tool_version = subprocess.check_output(["cargo", "cyclonedx", "--version"], text=True).strip()
        if tool_version not in {"cargo-cyclonedx 0.5.9", "cargo-cyclonedx-cyclonedx 0.5.9"}:
            raise ValueError(f"need cargo-cyclonedx 0.5.9, found {tool_version}")
        lock = (stage / "Cargo.lock").read_bytes()
        subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1",
                        "--manifest-path", str(manifest)], cwd=stage,
                       stdout=subprocess.DEVNULL, check=True)
        subprocess.run(["cargo", "cyclonedx", "--manifest-path", str(manifest),
                        "--format", "json", "--spec-version", "1.3"], cwd=stage, check=True)
        if (stage / "Cargo.lock").read_bytes() != lock:
            raise ValueError("SBOM generation changed the release lockfile")
        documents = {}
        for short in CRATES:
            crate = f"irlume-{short}"
            doc = normalize_sbom(json.loads((stage / "crates" / crate / f"{crate}.cdx.json").read_text()))
            component = doc.get("metadata", {}).get("component", {})
            if component.get("name") != crate or component.get("version") != version:
                raise ValueError(f"unexpected SBOM component identity for {crate}")
            documents[f"irlume-{version}-sbom-{short}.cdx.json"] = doc
        output.mkdir(parents=True, exist_ok=True)
        for name, doc in documents.items():
            (output / name).write_text(json.dumps(doc, indent=2) + "\n")
            print(f"wrote {output / name} ({len(doc.get('components', []))} components)")
        print(f"source commit: {commit}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("output", nargs="?", type=Path, default=Path("."))
    parser.add_argument("--revision", default="HEAD", help="committed source revision (default: HEAD)")
    args = parser.parse_args()
    try:
        generate(ROOT, args.revision, args.version, args.output)
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f"SBOM generation failed: {error}\n")


if __name__ == "__main__":
    main()
