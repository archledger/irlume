"""Exercise staging and rechecking an unsigned handoff with non-ELF fixtures."""
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import provenance


SHA, RUN, ATTEMPT = "a" * 40, "847", "2"
SUBJECT = b"fixture runtime contents\n"


class HandoffTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.rebuild, self.handoff = root / "rebuild", root / "handoff"
        self.elf = self.rebuild / "replay/run/build-runtime" / provenance.ELF
        self.elf.parent.mkdir(parents=True)
        self.elf.write_bytes(SUBJECT)
        digest = sha256(SUBJECT).hexdigest()
        materials = {key: sha256(key.encode()).hexdigest() for key in provenance.MATERIALS}
        locks = {
            "frozenFileManifestSha256": "replay/verified-source.sha256",
            "frozenSymlinkManifestSha256": "recipe/locks/FROZEN-SYMLINKS.txt",
            "debChecksumsSha256": "recipe/locks/DEBS.sha256",
            "exactDebLockSha256": "recipe/locks/EXACT-DEBS.tsv",
            "installedPackagesSha256": "recipe/locks/expected.txt",
        }
        for key, relative in locks.items():
            path = self.rebuild / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            data = f"fixture for {relative}\n".encode()
            path.write_bytes(data)
            materials[key] = sha256(data).hexdigest()
        self.receipt = self.rebuild / "unsigned-build-receipt.json"
        self.receipt.write_text(json.dumps({
            "format": "irlume-litert-unsigned-rebuild-receipt-v1",
            "attestationStatus": "unsigned-private-draft",
            "subject": {"name": provenance.ELF, "sha256": digest},
            "materials": {key: materials[key] for key in (
                "sourceArchiveSha256", "toolchainArchiveSha256", "reviewedManifestSha256",
            )},
            "buildNetwork": "none", "result": "byte-identical",
        }))
        pins = patch.multiple(provenance, ELF_BYTES=len(SUBJECT), RUNTIME_SHA256=digest,
                              MATERIALS=materials)
        pins.start()
        self.addCleanup(pins.stop)

    def stage(self):
        provenance.stage(self.rebuild, self.handoff, SHA, RUN, ATTEMPT)

    def test_stage_verifies_and_copies_only_unsigned_handoff(self):
        self.stage()
        self.assertEqual({p.name for p in self.handoff.iterdir()},
                         {provenance.ELF, provenance.PREDICATE_FILE})
        self.assertEqual((self.handoff / provenance.ELF).read_bytes(), SUBJECT)
        predicate = json.loads((self.handoff / provenance.PREDICATE_FILE).read_text())
        self.assertEqual(predicate["invocation"], {"sourceSha": SHA, "runId": RUN, "runAttempt": ATTEMPT})
        self.assertEqual(predicate["platform"]["buildNetwork"], "none")
        provenance.check_handoff(self.handoff, SHA, RUN, ATTEMPT)

    def test_stage_refuses_changed_lock_without_creating_handoff(self):
        (self.rebuild / "recipe/locks/EXACT-DEBS.tsv").write_text("different expected packages\n")
        with self.assertRaisesRegex(ValueError, "actual replay locks do not match"):
            self.stage()
        self.assertFalse(self.handoff.exists())

    def test_stage_refuses_same_length_runtime_mutation(self):
        self.elf.write_bytes(b"X" + SUBJECT[1:])
        with self.assertRaisesRegex(ValueError, "unexpected runtime subject bytes"):
            self.stage()
        self.assertFalse(self.handoff.exists())

    def test_stage_refuses_duplicate_receipt_keys(self):
        raw = self.receipt.read_text()
        self.assertTrue(raw.startswith("{"))
        self.receipt.write_text('{"result": "byte-identical", ' + raw[1:])
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.stage()
        self.assertFalse(self.handoff.exists())

    def test_handoff_rejects_different_attempt(self):
        self.stage()
        with self.assertRaisesRegex(ValueError, "wrong build invocation or input pins"):
            provenance.check_handoff(self.handoff, SHA, RUN, "3")

    def test_handoff_rejects_extra_file(self):
        self.stage()
        (self.handoff / "unreviewed.txt").write_text("fixture\n")
        with self.assertRaisesRegex(ValueError, "unexpected workflow handoff entries"):
            provenance.check_handoff(self.handoff, SHA, RUN, ATTEMPT)


if __name__ == "__main__":
    unittest.main()
