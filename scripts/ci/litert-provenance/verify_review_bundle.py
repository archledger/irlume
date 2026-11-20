"""Check a stable private snapshot against an independently obtained manifest hash."""

from argparse import ArgumentParser
from hashlib import file_digest, sha256
import os
from pathlib import Path
import re


MANIFEST = "REVIEW-SHA256SUMS"
SHA = r"[0-9a-f]{64}"
PART = r"[A-Za-z0-9][A-Za-z0-9._+-]*"
ENTRY = re.compile(fr"({SHA})  ({PART}(?:/{PART})*)")


def verify(root: Path, manifest_pin: str) -> dict[str, str]:
    """Verify integrity only, never a signature or an authorization to release."""
    manifest = root / MANIFEST
    if root.is_symlink() or not root.is_dir() or manifest.is_symlink() or not manifest.is_file():
        raise ValueError("non-regular bundle or manifest")
    content = manifest.read_bytes()
    if sha256(content).hexdigest() != manifest_pin:
        raise ValueError("manifest pin mismatch")
    entries = {}
    for line in content.decode("ascii").splitlines():
        match = ENTRY.fullmatch(line)
        if not match:
            raise ValueError("invalid manifest entry")
        digest, relative = match.groups()
        if relative in entries or relative == MANIFEST:
            raise ValueError(f"duplicate or reserved entry: {relative}")
        entries[relative] = digest
    if not entries:
        raise ValueError("empty manifest")

    def raise_walk_error(error):
        raise error

    actual = set()
    for directory, directories, files in os.walk(root, onerror=raise_walk_error):
        for name in directories:
            if (Path(directory) / name).is_symlink():
                raise ValueError(f"non-regular directory: {name}")
        for name in files:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"non-regular file: {name}")
            actual.add(path.relative_to(root).as_posix())
    if actual != (set(entries) | {MANIFEST}):
        raise ValueError("bundle file set differs from manifest")
    for relative, digest in entries.items():
        with (root / relative).open("rb") as data:
            if file_digest(data, "sha256").hexdigest() != digest:
                raise ValueError(f"checksum mismatch: {relative}")
    return entries


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("manifest_pin")
    options = parser.parse_args()
    try:
        entries = verify(options.bundle, options.manifest_pin)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Review integrity check refused: {error}\n")
    print(f"PRIVATE_INTEGRITY_ONLY files={len(entries)}; not authenticated for release")


if __name__ == "__main__":
    main()
