#!/usr/bin/env python3
"""Verify a complete downloaded release; optionally emit SLSA subjects.

Requires GnuPG, dpkg-deb, tar/zstd, and rpm if an RPM is present. Packages are
inspected, never installed or executed. Missing assets always fail, including
manual finalization. Python 3.11+; no third-party Python dependencies.
"""
import argparse
import base64
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
FINGERPRINT = "F35053398E3C80FE20891B82C10B8492BD7F30C6"
LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)")


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing regular file: {path.name}")


def command(args, failure):
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError(failure)
    return result.stdout


def package_format(name):
    if name.startswith("irlume_") and name.endswith(".deb"):
        return "deb"
    if name.startswith("irlume-") and name.endswith(".pkg.tar.zst"):
        return "arch"
    if name.startswith("irlume-selinux-") and name.endswith(".rpm"):
        return "rpm"
    raise ValueError(f"unsupported package: {name}")


def verify(directory, key, fingerprint, required):
    directory = directory.resolve(strict=True)
    manifest = directory / "SHA256SUMS"
    signature = directory / "SHA256SUMS.asc"
    regular(manifest)
    regular(signature)
    with tempfile.TemporaryDirectory(prefix="irlume-release-key-") as home:
        gpg = ["gpg", "--homedir", home, "--batch"]
        command(gpg + ["--import", str(key.resolve(strict=True))], "release key import failed")
        status = command(gpg + ["--status-fd", "1", "--verify", str(signature), str(manifest)],
                         "signature verification failed")
        valid = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
        if not any(fingerprint in (fields[2], fields[-1]) for fields in valid):
            raise ValueError("signature verification failed: unexpected signer")

    packages = {}
    formats = set()
    for line in manifest.read_text(encoding="ascii").splitlines():
        match = LINE.fullmatch(line)
        if match is None:
            raise ValueError("invalid manifest line: require SHA256 and a plain package filename")
        digest, name = match.groups()
        if name in packages:
            raise ValueError(f"duplicate manifest entry: {name}")
        formats.add(package_format(name))
        path = directory / name
        regular(path)
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != digest:
            raise ValueError(f"checksum mismatch: {name}")
        packages[name] = digest
    if not set(required) <= formats:
        raise ValueError("required package formats missing: " + ", ".join(sorted(set(required) - formats)))

    for path in directory.iterdir():
        regular(path)
        if path.name in {"SHA256SUMS", "SHA256SUMS.asc"} or path.name.endswith(".intoto.jsonl"):
            continue
        if path.name not in packages:
            raise ValueError(f"unsigned asset: {path.name}")

    for name in sorted(packages):
        path = str(directory / name)
        failure = f"package structure check failed: {name}"
        kind = package_format(name)
        if kind == "deb":
            command(["dpkg-deb", "--info", path], failure)
            command(["dpkg-deb", "--contents", path], failure)
        elif kind == "arch":
            entries = command(["tar", "--zstd", "--list", "--file", path], failure).splitlines()
            if not any(entry in {".PKGINFO", "./.PKGINFO"} for entry in entries):
                raise ValueError(failure + " (missing .PKGINFO)")
        else:
            command(["rpm", "-qip", path], failure)
            command(["rpm", "-qlp", path], failure)
    return packages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--key", type=Path, default=ROOT / ".github/release-signing-key.asc")
    parser.add_argument("--fingerprint", default=FINGERPRINT)
    parser.add_argument("--require", action="append", choices=["deb", "arch", "rpm"],
                        help="required format (repeatable); default: deb and arch; historical releases may use --require deb")
    parser.add_argument("--subjects", action="store_true", help="emit base64 SHA256 subjects after full verification")
    args = parser.parse_args()
    try:
        packages = verify(args.directory, args.key, args.fingerprint, args.require or ["deb", "arch"])
    except (ValueError, OSError, UnicodeError) as error:
        print(f"release verification failed: {error}", file=sys.stderr)
        return 1
    if args.subjects:
        subjects = "".join(f"{digest}  {name}\n" for name, digest in sorted(packages.items()))
        print(base64.b64encode(subjects.encode("ascii")).decode("ascii"))
    else:
        print(f"Verified signature, checksums, coverage and structure of {len(packages)} packages.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
