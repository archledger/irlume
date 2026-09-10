#!/usr/bin/env python3
"""Release gate regressions using actual signatures and disposable packages."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("verify-release-assets.py")


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="irlume-release-tests-")
        cls.root = Path(cls.scratch.name)
        cls.home = cls.root / "keys"
        cls.home.mkdir(mode=0o700)
        cls.gpg = ["gpg", "--homedir", str(cls.home), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        subprocess.run(cls.gpg + ["--quick-generate-key", "Irlume disposable fixture", "ed25519", "sign", "0"], check=True, capture_output=True)
        listing = subprocess.check_output(cls.gpg + ["--with-colons", "--list-keys"], text=True)
        cls.fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        cls.key = cls.root / "public.asc"
        cls.key.write_bytes(subprocess.check_output(cls.gpg + ["--armor", "--export", cls.fingerprint]))
        deb = cls.root / "deb"
        (deb / "DEBIAN").mkdir(parents=True)
        (deb / "DEBIAN/control").write_text("Package: irlume\nVersion: 99.0.0\nArchitecture: amd64\nMaintainer: Fixture <fixture@example.invalid>\nDescription: Disposable release regression fixture\n")
        cls.deb = cls.root / "fixture.deb"
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(deb), str(cls.deb)], check=True, capture_output=True)
        arch = cls.root / "arch"
        arch.mkdir()
        (arch / ".PKGINFO").write_text("pkgname = irlume\npkgver = 99.0.0-1\narch = x86_64\n")
        cls.arch = cls.root / "fixture.pkg.tar.zst"
        subprocess.run(["tar", "--zstd", "-cf", str(cls.arch), "-C", str(arch), ".PKGINFO"], check=True, capture_output=True)

        spec = cls.root / "fixture.spec"
        spec.write_text("""Name: irlume-selinux
Version: 99.0.0
Release: 1
Summary: Disposable release regression fixture
License: MIT
BuildArch: noarch
%description
Disposable fixture; never installed.
%install
mkdir -p %{buildroot}/usr/share/irlume-fixture
printf fixture > %{buildroot}/usr/share/irlume-fixture/policy
%files
/usr/share/irlume-fixture/policy
""")
        subprocess.run(["rpmbuild", "--define", "_topdir " + str(cls.root / "rpmbuild"),
                        "-bb", str(spec)], check=True, capture_output=True)
        cls.rpm = next((cls.root / "rpmbuild/RPMS/noarch").glob("*.rpm"))

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["gpgconf", "--homedir", str(cls.home), "--kill", "gpg-agent"], check=True)
        cls.scratch.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.root, prefix="assets-")
        self.addCleanup(self.temp.cleanup)
        self.assets = Path(self.temp.name)
        self.deb_name = "irlume_99.0.0_amd64.deb"
        self.arch_name = "irlume-99.0.0-1-x86_64.pkg.tar.zst"
        (self.assets / self.deb_name).write_bytes(self.deb.read_bytes())
        (self.assets / self.arch_name).write_bytes(self.arch.read_bytes())
        self.sign()

    def sign(self, manifest=None):
        if manifest is None:
            manifest = "".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n"
                               for p in sorted(self.assets.iterdir()) if p.suffix in {".deb", ".zst", ".rpm"})
        (self.assets / "SHA256SUMS").write_text(manifest)
        subprocess.run(self.gpg + ["--yes", "--armor", "--detach-sign", str(self.assets / "SHA256SUMS")], check=True, capture_output=True)

    def verify(self, *extra):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.assets), "--key", str(self.key),
                               "--fingerprint", self.fingerprint, *extra], capture_output=True, text=True)

    def refuses(self, expected):
        got = self.verify()
        self.assertNotEqual(got.returncode, 0)
        self.assertIn(expected, got.stderr)
        self.assertEqual(got.stdout, "")

    def test_complete_release_passes(self):
        got = self.verify()
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn("2 packages", got.stdout)

    def test_subjects_cover_both_exact_package_digests(self):
        got = self.verify("--subjects")
        self.assertEqual(got.returncode, 0, got.stderr)
        rows = base64.b64decode(got.stdout.strip(), validate=True).decode().splitlines()
        expected = [hashlib.sha256((self.assets / n).read_bytes()).hexdigest() + "  " + n
                    for n in sorted([self.deb_name, self.arch_name])]
        self.assertEqual(rows, expected)

    def assert_subjects(self, names):
        got = self.verify("--subjects")
        self.assertEqual(got.returncode, 0, got.stderr)
        expected = [hashlib.sha256((self.assets / n).read_bytes()).hexdigest() + "  " + n
                    for n in sorted(names)]
        self.assertEqual(base64.b64decode(got.stdout.strip(), validate=True).decode().splitlines(), expected)

    def test_optional_rpm_is_verified_and_attested(self):
        name = "irlume-selinux-99.0.0-1.noarch.rpm"
        (self.assets / name).write_bytes(self.rpm.read_bytes())
        self.sign()
        self.assert_subjects([self.deb_name, self.arch_name, name])

    def test_multiple_packages_of_one_format_are_attested(self):
        name = "irlume_99.0.0_arm64.deb"
        (self.assets / name).write_bytes(self.deb.read_bytes())
        self.sign()
        self.assert_subjects([self.deb_name, self.arch_name, name])

    def test_corrupt_but_signed_rpm_fails_structure_check(self):
        (self.assets / "irlume-selinux-99.0.0-1.noarch.rpm").write_bytes(b"not an rpm")
        self.sign()
        self.refuses("package structure check failed")

    def test_missing_manifest_fails(self):
        (self.assets / "SHA256SUMS").unlink()
        self.refuses("missing regular file: SHA256SUMS")

    def test_missing_signature_fails(self):
        (self.assets / "SHA256SUMS.asc").unlink()
        self.refuses("missing regular file: SHA256SUMS.asc")

    def test_empty_assets_fail(self):
        for p in self.assets.iterdir():
            p.unlink()
        self.refuses("missing regular file")

    def test_missing_signed_package_fails(self):
        (self.assets / self.arch_name).unlink()
        self.refuses("missing regular file: " + self.arch_name)

    def test_invalid_signature_fails(self):
        (self.assets / "SHA256SUMS.asc").write_text("invalid signature")
        self.refuses("signature verification failed")

    def test_wrong_signer_fails(self):
        got = self.verify("--fingerprint", "0" * 40)
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("signature verification failed", got.stderr)

    def test_altered_signed_manifest_fails(self):
        with (self.assets / "SHA256SUMS").open("a") as f:
            f.write("tampered\n")
        self.refuses("signature verification failed")

    def test_checksum_mismatch_fails(self):
        (self.assets / self.deb_name).write_bytes(b"corrupt")
        self.refuses("checksum mismatch")

    def test_extra_unsigned_asset_fails(self):
        (self.assets / "extra.txt").write_text("unsigned")
        self.refuses("unsigned asset: extra.txt")

    def test_existing_provenance_is_not_a_package_subject(self):
        (self.assets / "multiple.intoto.jsonl").write_text(json.dumps({"fixture": True}) + "\n")
        self.test_subjects_cover_both_exact_package_digests()

    def test_duplicate_manifest_entry_fails(self):
        manifest = (self.assets / "SHA256SUMS").read_text()
        self.sign(manifest + manifest.splitlines()[0] + "\n")
        self.refuses("duplicate manifest entry")

    def test_path_traversal_manifest_fails(self):
        self.sign("0" * 64 + "  ../outside.deb\n")
        self.refuses("invalid manifest line")

    def test_symlink_package_fails(self):
        p = self.assets / self.deb_name
        p.unlink()
        p.symlink_to(self.deb)
        self.refuses("missing regular file")

    def test_signed_nonpackage_manifest_fails(self):
        self.sign("0" * 64 + "  random.txt\n")
        self.refuses("unsupported package")

    def test_empty_signed_manifest_fails(self):
        self.sign("")
        self.refuses("required package formats")

    def test_arch_cannot_silently_disappear_from_manifest(self):
        (self.assets / self.arch_name).unlink()
        self.sign()
        self.refuses("required package formats")

    def test_corrupt_but_signed_deb_fails_structure_check(self):
        (self.assets / self.deb_name).write_bytes(b"not a deb")
        self.sign()
        self.refuses("package structure check failed")

    def test_corrupt_but_signed_arch_fails_structure_check(self):
        (self.assets / self.arch_name).write_bytes(b"not an archive")
        self.sign()
        self.refuses("package structure check failed")


if __name__ == "__main__":
    unittest.main()
