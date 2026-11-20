"""Exercise delivery acceptance with small fixtures, not release inputs."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from hashlib import sha256
from io import BytesIO, StringIO
import json
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import verify_delivery as delivery
from verify_review_bundle import MANIFEST


def digest(data):
    return sha256(data).hexdigest()


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in (delivery.ELF, delivery.SOURCE, delivery.EIGEN, delivery.NOTICES):
            (self.root / name).write_bytes(f"fixture for {name}\n".encode())
        self.locks = {name: f"fixture lock {name}\n".encode() for name in delivery.LOCK_PINS}
        self.lock_hashes = {name: digest(data) for name, data in self.locks.items()}
        self.write_capsule(list(self.locks.items()))
        entries = self.entries()
        self.record = {
            "attestationStatus": "unsigned-private-draft",
            "subject": {"name": delivery.ELF, "sha256": entries[delivery.ELF]},
            "sourceDelivery": {
                "runtimeSource": {"name": delivery.SOURCE, "sha256": entries[delivery.SOURCE]},
                "toolchainRecipe": {"name": delivery.TOOLCHAIN, "sha256": entries[delivery.TOOLCHAIN]},
            },
            "sourceAvailability": {
                "preparedEigenArchive": delivery.EIGEN, "sha256": entries[delivery.EIGEN],
            },
        }
        self.sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [{
                "SPDXID": "SPDXRef-LiteRT-Interpreter-ELF",
                "packageFileName": delivery.ELF,
                "checksums": [{"algorithm": "SHA256", "checksumValue": entries[delivery.ELF]}],
            }],
        }
        self.write_json(delivery.BUILD, self.record)
        self.write_json(delivery.SPDX, self.sbom)
        entries = self.entries()
        self.index = {"format": "irlume-runtime-delivery-draft-v2", "releaseStatus": "hold",
                      "assets": entries, "toolchainLocks": self.lock_hashes}
        self.write_json(delivery.DELIVERY, self.index)
        # Substitute only independent digest expectations. Parsing, inventory,
        # metadata binding and lock checks are the production implementations.
        pins = patch.multiple(delivery, PINS={name: entries[name] for name in delivery.PINS},
                              LOCK_PINS=self.lock_hashes)
        pins.start()
        self.addCleanup(pins.stop)

    def write_capsule(self, members):
        with tarfile.open(self.root / delivery.TOOLCHAIN, mode="w:gz") as archive:
            for name, data in members:
                member = tarfile.TarInfo(f"./locks/{name}")
                member.size = len(data)
                archive.addfile(member, BytesIO(data))

    def write_json(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def entries(self):
        return {path.name: digest(path.read_bytes())
                for path in sorted(self.root.iterdir()) if path.name != MANIFEST}

    def manifest(self):
        manifest = "".join(f"{h}  {name}\n" for name, h in self.entries().items()).encode()
        (self.root / MANIFEST).write_bytes(manifest)
        return digest(manifest)

    def invoke(self, manifest_pin, refusal=None):
        args = ["verify_delivery.py", str(self.root), "--trusted-review-manifest-sha256", manifest_pin]
        with patch("sys.argv", args), redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
            if refusal is None:
                delivery.main()
                self.assertIn("STANDALONE_DELIVERY_PRIVATE_ONLY assets=8", out.getvalue())
            else:
                with self.assertRaises(SystemExit) as stopped:
                    delivery.main()
                self.assertEqual(stopped.exception.code, 1)
                self.assertIn(refusal, err.getvalue())
                self.assertEqual(out.getvalue(), "")

    def test_accepts_complete_bound_private_delivery(self):
        self.invoke(self.manifest())

    def test_rejects_unlisted_file_in_reviewed_snapshot(self):
        pin = self.manifest()
        (self.root / "unexpected.txt").write_text("not in the reviewed manifest\n")
        self.invoke(pin, "bundle file set differs from manifest")

    def test_rejects_extra_asset_even_with_matching_manifest(self):
        (self.root / "unexpected.txt").write_text("newly listed, but not an allowed asset\n")
        self.invoke(self.manifest(), "unexpected delivery asset set or candidate pin")

    def test_rejects_file_changed_after_manifest_is_pinned(self):
        pin = self.manifest()
        (self.root / delivery.NOTICES).write_bytes(b"changed fixture notices\n")
        self.invoke(pin, f"checksum mismatch: {delivery.NOTICES}")

    def test_rejects_changed_candidate_even_with_matching_manifest(self):
        (self.root / delivery.ELF).write_bytes(b"different fixture runtime\n")
        self.invoke(self.manifest(), "unexpected delivery asset set or candidate pin")

    def test_rejects_duplicate_json_key_in_reviewed_delivery_index(self):
        index = json.dumps(self.index)
        self.assertTrue(index.startswith("{"))
        (self.root / delivery.DELIVERY).write_text('{"releaseStatus": "hold", ' + index[1:])
        self.invoke(self.manifest(), "duplicate JSON key")

    def test_rejects_changed_toolchain_lock_in_reviewed_capsule(self):
        mutated = self.locks | {"expected.txt": b"changed package lock\n"}
        self.write_capsule(list(mutated.items()))
        self.invoke(self.manifest(), "pinned toolchain locks mismatch")

    def test_rejects_duplicate_toolchain_lock_member(self):
        self.write_capsule([*self.locks.items(), ("expected.txt", self.locks["expected.txt"])])
        self.invoke(self.manifest(), "invalid toolchain lock member")

    def test_rejects_mismatched_metadata_bindings(self):
        cases = (
            (0, "releaseStatus", "other", "delivery index binding mismatch"),
            (0, "toolchainLocks", {}, "toolchain locks binding mismatch"),
            (1, "subject", {"name": delivery.ELF, "sha256": "0" * 64}, "build record binding mismatch"),
            (2, "packages", [], "SBOM subject binding mismatch"),
        )
        entries = self.entries()
        for position, field, value, refusal in cases:
            with self.subTest(field=field):
                docs = deepcopy([self.index, self.record, self.sbom])
                docs[position][field] = value
                with self.assertRaisesRegex(ValueError, refusal):
                    delivery.check_bindings(entries, *docs, self.lock_hashes)


if __name__ == "__main__":
    unittest.main()
