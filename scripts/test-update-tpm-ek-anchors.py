#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""The TPM EK anchor refresh keeps exactly one vendor DER certificate per file,
checks root self-signatures and never drops a certificate a URL stops serving.

No network: certificates are made with the openssl command line tool and the
script's download is replaced by a lookup.
"""
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "anchors", Path(__file__).with_name("update-tpm-ek-anchors.py")
)
assert SPEC is not None and SPEC.loader is not None
ANCHORS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANCHORS)


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


class Pki:
    """A root and intermediates made with openssl in a temporary directory."""

    def __init__(self, tmp):
        self.tmp = Path(tmp)

    def key(self, name):
        path = self.tmp / f"{name}.key"
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(path))
        return path

    def root(self, cn, key=None):
        key = key or self.key(cn)
        return openssl(
            "req", "-x509", "-new", "-key", str(key), "-subj", f"/CN={cn}", "-days", "3650",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign", "-outform", "DER",
        ), key

    def intermediate(self, cn, issuer_der, issuer_key):
        key = self.key(cn)
        csr = openssl("req", "-new", "-key", str(key), "-subj", f"/CN={cn}")
        issuer = self.tmp / "issuer.pem"
        issuer.write_bytes(openssl("x509", "-inform", "DER", data=issuer_der))
        ext = self.tmp / "ext.cnf"
        ext.write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n")
        return openssl(
            "x509", "-req", "-CA", str(issuer), "-CAkey", str(issuer_key), "-CAcreateserial",
            "-days", "3650", "-extfile", str(ext), "-outform", "DER", data=csr,
        )


class ToDer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root, _ = Pki(self.tmp.name).root("Test Root")

    def tearDown(self):
        self.tmp.cleanup()

    def test_one_der_certificate_is_kept_byte_for_byte(self):
        self.assertEqual(ANCHORS.to_der(self.root), self.root)

    def test_trailing_or_missing_bytes_are_refused(self):
        for data in (self.root + b"\x00", self.root + self.root, self.root[:-1], b""):
            with self.assertRaises(ValueError):
                ANCHORS.to_der(data)

    def test_pem_is_decoded_without_re_encoding(self):
        body = base64.encodebytes(self.root)
        pem = b"-----BEGIN CERTIFICATE-----\n" + body + b"-----END CERTIFICATE-----\n"
        self.assertEqual(ANCHORS.to_der(pem), self.root)
        with self.assertRaises(ValueError):
            ANCHORS.to_der(pem + pem)
        with self.assertRaises(ValueError):
            ANCHORS.to_der(pem + b"trailing text")


class SelfSignature(unittest.TestCase):
    def test_a_root_whose_self_signature_is_broken_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = Pki(tmp).root("Test Root")
            self.assertTrue(ANCHORS.signed_by(root, root))
            broken = bytearray(root)
            broken[-5] ^= 0x01
            self.assertFalse(ANCHORS.signed_by(bytes(broken), bytes(broken)))


class Refresh(unittest.TestCase):
    """A refresh against a temporary anchors directory."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        self.pki = Pki(tmp)
        self.anchors = tmp / "tpm-ek-anchors"
        self.anchors.mkdir()
        self.manifest = self.anchors / "manifest.json"
        self.shipped = tmp / "shipped.rs"
        self.root, self.root_key = self.pki.root("Test Root")
        self.served = {
            "https://pki.example/root.crt": self.root,
            "https://pki.example/ca.crt": self.pki.intermediate("Test CA", self.root, self.root_key),
        }
        self.write_manifest([
            {"vendor": "amd", "url": "https://pki.example/root.crt"},
            {"vendor": "amd", "url": "https://pki.example/ca.crt"},
        ])
        paths = {"ANCHORS": str(self.anchors), "MANIFEST": str(self.manifest), "SHIPPED_RS": str(self.shipped)}
        self.patches = [patch.object(ANCHORS, name, value) for name, value in paths.items()]
        self.patches.append(patch.object(ANCHORS, "download", lambda url: self.served[url]))
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def write_manifest(self, certificates):
        self.manifest.write_text(json.dumps({"format": 1, "certificates": certificates}))

    def refresh(self, today="2026-10-17"):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            ANCHORS.refresh(ANCHORS.load_manifest(), today)
        return out.getvalue()

    def entries(self):
        return json.loads(self.manifest.read_text())["certificates"]

    def test_a_refresh_writes_files_manifest_and_list_that_check_out(self):
        self.refresh()
        entries = self.entries()
        self.assertEqual([e["role"] for e in entries], ["root", "intermediate"])
        for entry in entries:
            self.assertEqual((self.anchors / entry["file"]).read_bytes(), self.served[entry["url"]])
            self.assertEqual(entry["retrieved"], "2026-10-17")
            self.assertNotIn("retained", entry)
        self.assertIn('include_bytes!("../../tpm-ek-anchors/amd/', self.shipped.read_text())
        with contextlib.redirect_stdout(io.StringIO()):
            ANCHORS.check(ANCHORS.load_manifest())

    def test_a_certificate_its_url_stops_serving_is_retained(self):
        self.refresh()
        old = self.entries()[1]
        # The vendor re-keys the CA and serves the successor at the same URL.
        self.served["https://pki.example/ca.crt"] = self.pki.intermediate("Test CA", self.root, self.root_key)
        out = self.refresh(today="2026-11-01")
        self.assertIn("stays, retained", out)
        entries = self.entries()
        self.assertEqual(len(entries), 3)
        kept = [e for e in entries if e["sha256"] == old["sha256"]]
        self.assertEqual(len(kept), 1)
        self.assertTrue(kept[0]["retained"])
        self.assertEqual(kept[0]["retrieved"], old["retrieved"])
        self.assertTrue((self.anchors / old["file"]).exists())
        new = [e for e in entries if e["url"] == old["url"] and not e.get("retained")]
        self.assertEqual([e["retrieved"] for e in new], ["2026-11-01"])
        with contextlib.redirect_stdout(io.StringIO()):
            ANCHORS.check(ANCHORS.load_manifest())
        # A later refresh keeps it without downloading it again.
        self.refresh(today="2026-12-01")
        self.assertEqual(len(self.entries()), 3)

    def test_an_intermediate_that_does_not_chain_to_a_listed_root_is_refused(self):
        other, other_key = self.pki.root("Other Root")
        self.served["https://pki.example/ca.crt"] = self.pki.intermediate("Test CA", other, other_key)
        with self.assertRaises(SystemExit):
            self.refresh()
        self.assertEqual(os.listdir(self.anchors), ["manifest.json"])

    def test_an_issuer_named_with_other_case_and_spacing_is_found(self):
        # The CA was issued under "test  root"; the listed root, with the
        # same key, is named "Test Root".
        lower, _ = self.pki.root("test  root", key=self.root_key)
        self.served["https://pki.example/ca.crt"] = self.pki.intermediate("Test CA", lower, self.root_key)
        self.refresh()
        self.assertEqual([e["role"] for e in self.entries()], ["root", "intermediate"])
        with contextlib.redirect_stdout(io.StringIO()):
            ANCHORS.check(ANCHORS.load_manifest())

    def test_a_root_with_a_broken_self_signature_is_refused(self):
        broken = bytearray(self.root)
        broken[-5] ^= 0x01
        self.served["https://pki.example/root.crt"] = bytes(broken)
        with self.assertRaises(SystemExit):
            self.refresh()


if __name__ == "__main__":
    unittest.main()
