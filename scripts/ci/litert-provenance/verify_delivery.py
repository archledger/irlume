"""Check exactly the private standalone delivery draft, never authenticate a release."""

from argparse import ArgumentParser
from hashlib import sha256
import json
import os
from pathlib import Path
import tarfile

from verify_review_bundle import verify


ELF = "libtensorflowlite_c.so"
SOURCE = "runtime-rebuild-inputs-fixture-trim-private.tar.zst"
EIGEN = "eigen-ea13a98decd497a8c5588fb5de71b57bcf10d864-as-built.tar.gz"
NOTICES = "runtime-notices.tar.gz"
SPDX = "litert-interpreter.spdx.json"
BUILD = "litert-interpreter.build-record.json"
DELIVERY = "litert-runtime-delivery.json"
TOOLCHAIN = "litert-jammy-toolchain-replay.tar.gz"
PINS = {
    ELF: "8fbdab61b184bd36979c2159dac0ea9569652e37962ca0b0985c72ddda92e034",
    SOURCE: "35a7ba1ec4357a665d5478a09c3d5ca8f341a2435d990b61ec043d509e4d8842",
    EIGEN: "93d28f79918e9387a08013de74afc6ad1b374319102c27ce0cd443b7287b5db2",
    NOTICES: "ad95f96c44351bad1fd559ee3fe356a865db6b48ab1d4fa2a5868e97382328db",
    SPDX: "575862fc5cca86bc47093ea7774cc5523fa03bdcd7afaae320f10612de62d006",
}
ASSETS = PINS.keys() | {BUILD, DELIVERY, TOOLCHAIN}
LOCK_PINS = {
    "DEBS.sha256": "4937a187fa0dc147d4cb756a829e5064ebb88c7f8e65ee970bccce62d6af8a9b",
    "EXACT-DEBS.tsv": "488e68ff401a4a2c8add77a8ca508ab0803109fb7c9b250d517c19eb80b1bd43",
    "expected.txt": "9a8c3727fe36d115b36054e1e509835c6f76ad3fde9bf03fe33130feb298fdd7",
    "OMITTED-FIXTURES.sha256": "9c4e5f24107e77411109e7dd8aa5d4a7bdaeaef14119c516eee64fe8b7087fc4",
}


def check_bindings(entries, delivery, record, spdx, locks):
    def asset(name):
        return {"name": name, "sha256": entries[name]}

    try:
        if (delivery["format"] != "irlume-runtime-delivery-draft-v2"
                or delivery["releaseStatus"] != "hold"
                or delivery["assets"] != {n: h for n, h in entries.items() if n != DELIVERY}):
            raise ValueError("delivery index binding mismatch")
        if delivery["toolchainLocks"] != locks:
            raise ValueError("toolchain locks binding mismatch")
        subject = record["subject"]
        src = record["sourceDelivery"]
        eigen = record["sourceAvailability"]
        if (record["attestationStatus"] != "unsigned-private-draft"
                or subject["name"] != ELF or subject["sha256"] != entries[ELF]
                or src["runtimeSource"] != asset(SOURCE)
                or src["toolchainRecipe"] != asset(TOOLCHAIN)
                or eigen["preparedEigenArchive"] != EIGEN or eigen["sha256"] != entries[EIGEN]):
            raise ValueError("build record binding mismatch")
        packages = [p for p in spdx["packages"] if p["SPDXID"] == "SPDXRef-LiteRT-Interpreter-ELF"]
        if (spdx["spdxVersion"] != "SPDX-2.3" or len(packages) != 1
                or packages[0]["packageFileName"] != ELF
                or packages[0]["checksums"] != [{"algorithm": "SHA256", "checksumValue": entries[ELF]}]):
            raise ValueError("SBOM subject binding mismatch")
    except (KeyError, TypeError) as error:
        raise ValueError("invalid companion metadata structure") from error


def exact_locks(archive: Path):
    found = {}
    with tarfile.open(archive, mode="r:gz") as bundle:
        for member in bundle:
            prefix, _, name = member.name.rpartition("/")
            if prefix != "./locks" or name not in LOCK_PINS:
                continue
            if name in found or not member.isfile() or not 0 < member.size < 65536:
                raise ValueError("invalid toolchain lock member")
            with bundle.extractfile(member) as stream:
                found[name] = sha256(stream.read()).hexdigest()
    if found != LOCK_PINS:
        raise ValueError("pinned toolchain locks mismatch")
    return found


def read_json(path):
    def pairs_unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("duplicate JSON key")
        return result

    return json.loads(path.read_bytes(), object_pairs_hook=pairs_unique)


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="Stable caller-owned directory")
    parser.add_argument("--trusted-review-manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        root = args.bundle
        state = root.stat()
        if root.is_symlink() or state.st_uid != os.geteuid() or state.st_mode & 0o022:
            raise ValueError("use a stable caller-owned directory not writable by others")
        entries = verify(root, args.trusted_review_manifest_sha256)
        if entries.keys() != ASSETS or any(entries[name] != digest for name, digest in PINS.items()):
            raise ValueError("unexpected delivery asset set or candidate pin")
        check_bindings(entries, read_json(root / DELIVERY), read_json(root / BUILD),
                       read_json(root / SPDX), exact_locks(root / TOOLCHAIN))
    except (ValueError, OSError, tarfile.TarError) as error:
        parser.exit(1, f"Private standalone delivery refused: {error}\n")
    print(f"STANDALONE_DELIVERY_PRIVATE_ONLY assets={len(entries)}; not signed or releasable")


if __name__ == "__main__":
    main()
