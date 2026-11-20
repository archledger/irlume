"""Prepare and check the unsigned minihost-only handoff."""

from argparse import ArgumentParser
from hashlib import file_digest
import json
import os
from pathlib import Path
import re
import shutil
import stat


REPO = "archledger/irlume"
REPO_ID = "1286828818"
OWNER_ID = "276915572"
WORKFLOW = ".github/workflows/litert-runtime-provenance.yml"
ELF = "libtensorflowlite_c.so"
PREDICATE_FILE = "build-predicate.json"
PREDICATE_TYPE = f"https://github.com/{REPO}/attestations/litert-minihost-offline-build/v1"
RUNTIME_SHA256 = "8fbdab61b184bd36979c2159dac0ea9569652e37962ca0b0985c72ddda92e034"
ELF_BYTES = 9040968
MATERIALS = {
    "reviewedManifestSha256": "5b6ce00784916b5faad8e0b230c967f2af347755a3e9a6821b50206c418ea4f8",
    "sourceArchiveSha256": "35a7ba1ec4357a665d5478a09c3d5ca8f341a2435d990b61ec043d509e4d8842",
    "frozenFileManifestSha256": "a6678ff1cb5eb6f6e70b61c49b699aae8c5bf5d97d9cfcaa0a38c90dbaf0b21f",
    "frozenSymlinkManifestSha256": "de1f0fc6ddc909c203f062a83e5f0833025051372c762fbf67b34092d19ff3f4",
    "toolchainArchiveSha256": "5d08cd2d276a5800c635ddd8ede549fc8aee35f17f42c9e5e5fcaeac49604f15",
    "ubuntuBaseManifestSha256": "45e9ddc6895604674618a409ca9f73d301da8fdb75fe330e8e9a27b3b219e4ad",
    "ubuntuBaseConfigSha256": "3b0904ac063a56dbfe1cd5496f5bc417ad9897e1e2e12768fa67be06fecf758a",
    "debChecksumsSha256": "4937a187fa0dc147d4cb756a829e5064ebb88c7f8e65ee970bccce62d6af8a9b",
    "exactDebLockSha256": "488e68ff401a4a2c8add77a8ca508ab0803109fb7c9b250d517c19eb80b1bd43",
    "installedPackagesSha256": "9a8c3727fe36d115b36054e1e509835c6f76ad3fde9bf03fe33130feb298fdd7",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_text(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def digest_id(value, size):
    return exact_text(value, f"[0-9a-f]{{{size}}}") and value != "0" * size


def parse_json(raw):
    def unique(pairs):
        result = dict(pairs)
        require(len(pairs) == len(result), "duplicate JSON key")
        return result

    return json.loads(raw, object_pairs_hook=unique)


def local_file(path, limit):
    meta = path.lstat()
    require(stat.S_ISREG(meta.st_mode) and 0 < meta.st_size <= limit, "invalid local evidence file")
    return path.resolve(strict=True)


def digest(path, limit=64 * 1024 * 1024):
    with local_file(path, limit).open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def json_file(path):
    return parse_json(local_file(path, 1 << 20).read_bytes())


def verify_elf(path):
    require(path.name == ELF and local_file(path, ELF_BYTES).stat().st_size == ELF_BYTES
            and digest(path, ELF_BYTES) == RUNTIME_SHA256, "unexpected runtime subject bytes")


def expected_predicate(source_sha, run, attempt):
    require(digest_id(source_sha, 40) and exact_text(run, "[1-9][0-9]{0,19}")
            and exact_text(attempt, "[1-9][0-9]{0,5}"), "invalid build invocation")
    return {
        "format": "irlume-litert-minihost-offline-build-v1",
        "invocation": {"sourceSha": source_sha, "runId": run, "runAttempt": attempt},
        "platform": {"target": "linux/amd64", "isolation": "rootless-podman", "buildNetwork": "none"},
        "materials": dict(MATERIALS),
        "outputCheck": "byte-identical-to-qualified-runtime",
    }


def stage(rebuild, handoff, source_sha, run, attempt):
    predicate = expected_predicate(source_sha, run, attempt)
    elf = rebuild / "replay/run/build-runtime" / ELF
    verify_elf(elf)
    receipt_pins = {key: MATERIALS[key] for key in (
        "sourceArchiveSha256", "toolchainArchiveSha256", "reviewedManifestSha256",
    )}
    require(json_file(rebuild / "unsigned-build-receipt.json") == {
        "format": "irlume-litert-unsigned-rebuild-receipt-v1",
        "attestationStatus": "unsigned-private-draft",
        "subject": {"name": ELF, "sha256": RUNTIME_SHA256},
        "materials": receipt_pins, "buildNetwork": "none", "result": "byte-identical",
    }, "unexpected unsigned replay receipt")
    verified = {
        "frozenFileManifestSha256": rebuild / "replay/verified-source.sha256",
        "frozenSymlinkManifestSha256": rebuild / "recipe/locks/FROZEN-SYMLINKS.txt",
        "debChecksumsSha256": rebuild / "recipe/locks/DEBS.sha256",
        "exactDebLockSha256": rebuild / "recipe/locks/EXACT-DEBS.tsv",
        "installedPackagesSha256": rebuild / "recipe/locks/expected.txt",
    }
    require(all(digest(path) == MATERIALS[key] for key, path in verified.items()),
            "actual replay locks do not match the reviewed material pins")
    handoff.mkdir(mode=0o700)
    with elf.open("rb") as source, (handoff / ELF).open("xb") as target:
        shutil.copyfileobj(source, target)
    with (handoff / PREDICATE_FILE).open("x", encoding="utf-8") as stream:
        json.dump(predicate, stream, sort_keys=True, indent=2)
        stream.write("\n")
    check_handoff(handoff, source_sha, run, attempt)


def check_handoff(handoff, source_sha, run, attempt):
    require(not handoff.is_symlink() and set(path.name for path in handoff.iterdir()) ==
            {ELF, PREDICATE_FILE}, "unexpected workflow handoff entries")
    verify_elf(handoff / ELF)
    require(json_file(handoff / PREDICATE_FILE) == expected_predicate(source_sha, run, attempt),
            "wrong build invocation or input pins")


def main():
    os.umask(0o077)
    parser = ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("stage")
    prepare.add_argument("rebuild", type=Path)
    handoff = commands.add_parser("check-handoff")
    for sub in (prepare, handoff):
        sub.add_argument("handoff", type=Path)
        sub.add_argument("source_sha")
        sub.add_argument("run")
        sub.add_argument("attempt")
    commands.add_parser("verify-attestation", help="always refused until minihost trust is approved")
    args = parser.parse_args()
    try:
        if args.command == "stage":
            stage(args.rebuild, args.handoff, args.source_sha, args.run, args.attempt)
            print("UNSIGNED_REBUILD_HANDOFF_VERIFIED")
        elif args.command == "check-handoff":
            check_handoff(args.handoff, args.source_sha, args.run, args.attempt)
            print("UNSIGNED_REBUILD_HANDOFF_VERIFIED")
        else:
            raise ValueError("signed minihost acceptance held: signed verification is not enabled in this unsigned draft")
    except (OSError, ValueError) as error:
        parser.exit(1, f"Provenance policy refused: {error}\n")


if __name__ == "__main__":
    main()
