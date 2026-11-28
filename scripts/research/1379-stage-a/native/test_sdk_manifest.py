import hashlib
from pathlib import Path
import tempfile
import unittest

from sdk_manifest import verify_sdk


class SdkReceiptTests(unittest.TestCase):
    def setUp(self):
        self.scratch = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.sdk = self.scratch / "sdk"
        records = (
            "lib/libcamera.so.0.8.0",
            "lib/libcamera-base.so.0.8.0",
            "lib/libcamera/ipa/ipa_ipu3.so",
            "lib/pkgconfig/libcamera.pc",
            "lib/pkgconfig/libcamera-base.pc",
            "include/libcamera/libcamera/camera.h",
        )
        for rel in records:
            dest = self.sdk / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(rel)
        for name in ("libcamera", "libcamera-base"):
            (self.sdk / f"lib/{name}.so").symlink_to(f"{name}.so.0.8.0")
        self.manifest = self.scratch / "sdk.sha256"
        self.manifest.write_text(
            "".join(f"{hashlib.sha256(rel.encode()).hexdigest()}  {rel}\n" for rel in records)
        )

    def test_resolves_the_recorded_elfs(self):
        self.assertEqual(verify_sdk(self.sdk, self.manifest), (
            self.sdk / "lib/libcamera.so.0.8.0",
            self.sdk / "lib/libcamera-base.so.0.8.0",
        ))

    def test_changed_library_same_name_refuses(self):
        (self.sdk / "lib/libcamera.so.0.8.0").write_text("another build")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            verify_sdk(self.sdk, self.manifest)

    def test_symlink_cannot_resolve_outside_sdk(self):
        elf = self.sdk / "lib/libcamera.so"
        elf.unlink()
        outside = self.scratch / "outside"
        outside.write_text("outside")
        elf.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "outside SDK"):
            verify_sdk(self.sdk, self.manifest)

    def test_unlisted_public_header_refuses(self):
        (self.sdk / "include/libcamera/libcamera/extra.h").write_text("not recorded")
        with self.assertRaisesRegex(ValueError, "unlisted SDK header"):
            verify_sdk(self.sdk, self.manifest)

    def test_receipt_cannot_claim_parent_files(self):
        with self.manifest.open("a") as out:
            out.write(f"{'0' * 64}  ../outside\n")
        with self.assertRaisesRegex(ValueError, "invalid SDK receipt path"):
            verify_sdk(self.sdk, self.manifest)
