#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Refresh or check the TPM vendor CA certificates irlume ships (ADR-0036 s5).

irlume's `tpm-endorsement` doctor check verifies a TPM's endorsement key
certificate against vendor root and intermediate CA certificates that irlume
curates from the vendors' own PKI pages. They live in
crates/irlume-core/tpm-ek-anchors/, one DER file per CA, listed in
manifest.json with the URL each was downloaded from. irlumed embeds them at
build time through crates/irlume-core/src/ek_cert/shipped.rs, which this
script generates.

  update-tpm-ek-anchors.py                   re-download every listed URL,
                                             verify, rewrite the directory,
                                             the manifest and shipped.rs
  update-tpm-ek-anchors.py --add VENDOR URL  add a certificate, then refresh
  update-tpm-ek-anchors.py --check           offline: every file matches the
                                             manifest, every intermediate
                                             chains to a listed root, and
                                             shipped.rs is current

A refresh writes nothing unless every download succeeds, every URL is HTTPS,
every file is exactly one DER certificate, every root is self-signed and
every intermediate's signature chains to a listed root. A certificate that
its URL no longer serves is kept, marked "retained": TPMs it certified stay
in use, so only removing its manifest entry by hand retires it. Review the
diff like any other pull request: a changed root is a change of whom irlume
trusts.

Requires Python 3.9+ and the openssl command line tool.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANCHORS = os.path.join(ROOT, "crates", "irlume-core", "tpm-ek-anchors")
MANIFEST = os.path.join(ANCHORS, "manifest.json")
SHIPPED_RS = os.path.join(ROOT, "crates", "irlume-core", "src", "ek_cert", "shipped.rs")
# Directory per vendor; the manifest's `vendor` field names one of these.
VENDORS = ("amd", "infineon", "intel", "nuvoton", "stmicro")
MAX_CERT_BYTES = 64 * 1024
USER_AGENT = "irlume-update-tpm-ek-anchors (+https://github.com/archledger/irlume)"


def fail(message):
    sys.exit(f"update-tpm-ek-anchors: {message}")


def openssl(args, data):
    proc = subprocess.run(["openssl", *args], input=data, capture_output=True)
    if proc.returncode != 0:
        raise ValueError(proc.stderr.decode("utf-8", "replace").strip() or "openssl failed")
    return proc.stdout


PEM_CERTIFICATE = re.compile(
    rb"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*)-----END CERTIFICATE-----"
)


def der_length(data):
    """Length of the DER SEQUENCE that starts `data`, or None."""
    if len(data) < 2 or data[0] != 0x30:
        return None
    if data[1] < 0x80:
        return 2 + data[1]
    count = data[1] & 0x7F
    if count == 0 or count > 4 or len(data) < 2 + count or data[2] == 0:
        return None
    length = int.from_bytes(data[2 : 2 + count], "big")
    # DER uses the long form only for lengths the short form cannot hold.
    if length < 0x80:
        return None
    return 2 + count + length


def to_der(data):
    """The vendor's own bytes of exactly one certificate, given as DER or PEM.

    PEM is decoded here rather than by openssl, which would re-encode: the
    shipped bytes must be the ones the issuer signed.
    """
    text = data.strip()
    if text.startswith(b"-----BEGIN"):
        blocks = PEM_CERTIFICATE.findall(text)
        if len(blocks) != 1 or PEM_CERTIFICATE.sub(b"", text).strip():
            raise ValueError("not exactly one PEM certificate")
        data = base64.b64decode(b"".join(blocks[0].split()), validate=True)
    if der_length(data) != len(data):
        raise ValueError("not exactly one DER certificate (trailing or missing bytes)")
    openssl(["x509", "-inform", "DER", "-noout"], data)
    return data


def iso_date(openssl_date):
    # "Jan  1 05:00:00 2017 GMT"
    parsed = datetime.datetime.strptime(" ".join(openssl_date.split()), "%b %d %H:%M:%S %Y %Z")
    return parsed.strftime("%Y-%m-%d")


def describe(der):
    text = openssl(
        [
            "x509", "-inform", "DER", "-noout", "-nameopt", "RFC2253",
            "-subject", "-issuer", "-startdate", "-enddate",
        ],
        der,
    ).decode("utf-8", "replace")
    fields = {}
    for line in text.splitlines():
        key, _, value = line.partition("=")
        fields[key.strip()] = value.strip()
    return {
        "subject": fields["subject"],
        "issuer": fields["issuer"],
        "not_before": iso_date(fields["notBefore"]),
        "not_after": iso_date(fields["notAfter"]),
    }


def name_hashes(der):
    """OpenSSL's hashes of the subject and issuer in canonical form.

    X509_NAME_hash folds case, insignificant spaces and the string type
    before hashing, the comparison RFC 5280 7.1 asks for and irlume's own
    verifier makes: vendors do not always repeat a CA's name with the same
    encoding. A matching hash only nominates an issuer; its signature must
    still verify.
    """
    subject, issuer = openssl(
        ["x509", "-inform", "DER", "-noout", "-subject_hash", "-issuer_hash"], der
    ).decode().split()
    return subject, issuer


def role_of(der):
    """A root is self-signed: self-issued and verified by its own key. A
    self-issued certificate another key signed (a same-name key rollover
    linking a new key to the old one) is an intermediate."""
    subject, issuer = name_hashes(der)
    return "root" if subject == issuer and self_signed(der) else "intermediate"


def self_signed(der):
    """True when the certificate is its own issuer and its own key verifies it.

    Without -partial_chain OpenSSL accepts the certificate only as a
    self-signed anchor, and -check_ss_sig then checks that signature; a
    certificate that names itself but another key signed fails.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "cert.pem")
        with open(path, "wb") as f:
            f.write(openssl(["x509", "-inform", "DER"], der))
        proc = subprocess.run(
            [
                "openssl", "verify", "-auth_level", "0", "-no_check_time",
                "-check_ss_sig", "-CAfile", path, path,
            ],
            capture_output=True,
        )
        return proc.returncode == 0


def signed_by(child_der, parent_der):
    """True when parent's key verifies child's signature (no time or trust checks).

    A root parent's own self-signature is checked too (-check_ss_sig); use
    self_signed to ask whether a certificate is a root.
    """
    with tempfile.TemporaryDirectory() as tmp:
        child = os.path.join(tmp, "child.pem")
        parent = os.path.join(tmp, "parent.pem")
        with open(child, "wb") as f:
            f.write(openssl(["x509", "-inform", "DER"], child_der))
        with open(parent, "wb") as f:
            f.write(openssl(["x509", "-inform", "DER"], parent_der))
        # -partial_chain trusts the given parent as the anchor; -auth_level 0
        # keeps OpenSSL from refusing SHA-1 here, which irlume itself reads as
        # unverifiable rather than as a broken chain; -no_check_time because
        # validity is reported, not enforced (ADR-0036 s2.3).
        proc = subprocess.run(
            [
                "openssl", "verify", "-auth_level", "0", "-no_check_time",
                "-partial_chain", "-check_ss_sig", "-CAfile", parent, child,
            ],
            capture_output=True,
        )
        return proc.returncode == 0


class HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect hop that is not HTTPS, not only the last one: a
    plaintext hop could be answered with a redirect to any host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.HTTPError(newurl, code, f"redirect to a non-HTTPS URL: {newurl}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(HttpsOnlyRedirects)


def download(url):
    if not url.startswith("https://"):
        fail(f"{url}: only HTTPS sources are accepted")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with OPENER.open(request, timeout=60) as response:
            if not response.geturl().startswith("https://"):
                fail(f"{url}: redirected to a non-HTTPS URL")
            data = response.read(MAX_CERT_BYTES + 1)
    except OSError as err:
        fail(f"{url}: {err}; to keep a certificate its vendor no longer serves, mark its entry \"retained\"")
    if len(data) > MAX_CERT_BYTES:
        fail(f"{url}: larger than {MAX_CERT_BYTES} bytes")
    try:
        return to_der(data)
    except ValueError as err:
        fail(f"{url}: not a certificate: {err}")


def file_name(entry):
    """Stable, readable file name: the CA's name plus a SHA-256 prefix."""
    subject = entry["subject"]
    cn = re.search(r"(?:^|[,+])CN=((?:\\.|[^,+])*)", subject)
    ou = re.search(r"(?:^|[,+])OU=((?:\\.|[^,+])*)", subject)
    name = cn.group(1) if cn else subject
    # Intel names every CA "www.intel.com" and puts the CA in the OU.
    if ou and (not cn or re.fullmatch(r"[\w-]+(\.[\w-]+)+", name)):
        name = ou.group(1)
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60].strip("-")
    return f"{entry['vendor']}/{slug}-{entry['sha256'][:8]}.der"


def load_manifest():
    with open(MANIFEST, encoding="utf-8") as f:
        manifest = json.load(f)
    if manifest.get("format") != 1:
        fail("manifest.json: unknown format")
    for entry in manifest["certificates"]:
        if entry.get("vendor") not in VENDORS:
            fail(f"manifest.json: unknown vendor {entry.get('vendor')!r}")
    return manifest


def verify_set(entries, ders):
    """Fail unless roots are self-signed and every intermediate chains to a root."""
    hashes = {entry["sha256"]: name_hashes(ders[entry["sha256"]]) for entry in entries}
    by_subject = {}
    for entry in entries:
        by_subject.setdefault(hashes[entry["sha256"]][0], []).append(entry)
    for entry in entries:
        der = ders[entry["sha256"]]
        if entry["role"] == "root":
            if not self_signed(der):
                fail(f"{entry['url']}: root is not self-signed")
            continue
        # Walk issuer links to a root, trying every listed CA with the
        # issuer's name (re-keyed CAs share a name).
        seen = set()
        frontier = [entry]
        reached = False
        while frontier and not reached:
            child = frontier.pop()
            if child["sha256"] in seen:
                continue
            seen.add(child["sha256"])
            for parent in by_subject.get(hashes[child["sha256"]][1], []):
                if parent["sha256"] == child["sha256"]:
                    continue
                if not signed_by(ders[child["sha256"]], ders[parent["sha256"]]):
                    continue
                if parent["role"] == "root":
                    reached = True
                    break
                frontier.append(parent)
        if not reached:
            fail(f"{entry['url']}: {entry['subject']} does not chain to a listed root")


def rust_list(entries):
    lines = [
        "// SPDX-License-Identifier: GPL-3.0-or-later",
        "// Copyright the irlume contributors.",
        "",
        "//! The TPM vendor CA certificates irlume ships (ADR-0036 section 5).",
        "//!",
        "//! Generated by `scripts/update-tpm-ek-anchors.py` from",
        "//! `crates/irlume-core/tpm-ek-anchors/manifest.json`; do not edit by hand.",
        "",
        "use super::AnchorRole::{Intermediate, Root};",
        "use super::ShippedAnchor;",
        "",
        "pub(super) const SHIPPED: &[ShippedAnchor] = &[",
    ]
    for entry in entries:
        role = "Root" if entry["role"] == "root" else "Intermediate"
        lines += [
            "    ShippedAnchor {",
            f"        role: {role},",
            f'        der: include_bytes!("../../tpm-ek-anchors/{entry["file"]}"),',
            "    },",
        ]
    lines += ["];", ""]
    return "\n".join(lines)


def sort_key(entry):
    return (entry["vendor"], entry["role"] != "root", entry["subject"], entry["sha256"])


def listed_files():
    found = set()
    for vendor in VENDORS:
        directory = os.path.join(ANCHORS, vendor)
        if not os.path.isdir(directory):
            continue
        for name in os.listdir(directory):
            found.add(f"{vendor}/{name}")
    return found


MANIFEST_KEYS = (
    "vendor", "role", "subject", "issuer", "not_before", "not_after",
    "sha256", "file", "url", "retrieved",
)


def read_shipped(entry):
    """The bytes of a certificate already in the directory, checked."""
    with open(os.path.join(ANCHORS, entry["file"]), "rb") as f:
        der = f.read()
    if hashlib.sha256(der).hexdigest() != entry["sha256"]:
        fail(f"{entry['file']}: SHA-256 differs from the manifest")
    return der


def entry_for(vendor, url, der, retrieved):
    entry = {"vendor": vendor, "url": url, **describe(der), "sha256": hashlib.sha256(der).hexdigest()}
    entry["role"] = role_of(der)
    entry["file"] = file_name(entry)
    entry["retrieved"] = retrieved
    return entry


def refresh(manifest, today):
    old_entries = manifest["certificates"]
    known = {entry["sha256"]: entry for entry in old_entries if entry.get("sha256")}
    live_urls = []
    for entry in old_entries:
        if not entry.get("retained") and entry["url"] not in live_urls:
            live_urls.append(entry["url"])
    vendors = {entry["url"]: entry["vendor"] for entry in old_entries}

    certificates = {}
    for url in live_urls:
        der = download(url)
        sha = hashlib.sha256(der).hexdigest()
        if sha in certificates:
            fail(f"{url}: the same certificate is already listed under another URL")
        previous = known.get(sha)
        # The date these exact bytes were first downloaded.
        retrieved = previous["retrieved"] if previous and previous.get("retrieved") else today
        certificates[sha] = (entry_for(vendors[url], url, der, retrieved), der)
        for old in old_entries:
            if old["url"] == url and old.get("sha256") not in (None, sha) and not old.get("retained"):
                print(f"changed: {url} now serves another certificate; {old['file']} stays, retained")
    # A certificate irlume has shipped stays, also when its URL now serves
    # another: TPMs it certified are still in use.
    for old in old_entries:
        sha = old.get("sha256")
        if sha and sha not in certificates:
            der = read_shipped(old)
            entry = entry_for(old["vendor"], old["url"], der, old["retrieved"])
            entry["retained"] = True
            certificates[sha] = (entry, der)

    entries = sorted((entry for entry, _ in certificates.values()), key=sort_key)
    ders = {sha: der for sha, (_, der) in certificates.items()}
    verify_set(entries, ders)

    for name in listed_files():
        os.remove(os.path.join(ANCHORS, name))
    for entry in entries:
        path = os.path.join(ANCHORS, entry["file"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(ders[entry["sha256"]])
    manifest["certificates"] = [manifest_entry(entry) for entry in entries]
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    with open(SHIPPED_RS, "w", encoding="utf-8") as f:
        f.write(rust_list(entries))
    roots = sum(entry["role"] == "root" for entry in entries)
    retained = sum(bool(entry.get("retained")) for entry in entries)
    print(f"{len(entries)} certificates ({roots} roots, {retained} retained) written")


def manifest_entry(entry):
    out = {key: entry[key] for key in MANIFEST_KEYS}
    if entry.get("retained"):
        out["retained"] = True
    return out


def check(manifest):
    entries = manifest["certificates"]
    ders = {}
    for entry in entries:
        if not entry["url"].startswith("https://"):
            fail(f"{entry['file']}: source is not HTTPS")
        if entry["file"] != file_name(entry):
            fail(f"{entry['file']}: expected the name {file_name(entry)}")
        der = read_shipped(entry)
        try:
            to_der(der)
        except ValueError as err:
            fail(f"{entry['file']}: {err}")
        if describe(der) != {key: entry[key] for key in ("subject", "issuer", "not_before", "not_after")}:
            fail(f"{entry['file']}: subject, issuer or validity differs from the manifest")
        role = role_of(der)
        if entry["role"] != role:
            fail(f"{entry['file']}: role should be {role}")
        ders[entry["sha256"]] = der
    if len(ders) != len(entries):
        fail("manifest.json lists a certificate twice")
    live = [entry["url"] for entry in entries if not entry.get("retained")]
    if len(live) != len(set(live)):
        fail("manifest.json lists a URL twice without marking the older certificate retained")
    if entries != [manifest_entry(entry) for entry in entries]:
        fail("manifest.json has fields a refresh does not write")
    extra = listed_files() - {entry["file"] for entry in entries}
    if extra:
        fail(f"files not in manifest.json: {', '.join(sorted(extra))}")
    if entries != sorted(entries, key=sort_key):
        fail("manifest.json is not in the order a refresh writes")
    verify_set(entries, ders)
    with open(SHIPPED_RS, encoding="utf-8") as f:
        if f.read() != rust_list(entries):
            fail("crates/irlume-core/src/ek_cert/shipped.rs is stale: run a refresh")
    print(f"{len(entries)} certificates check out")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="verify offline, change nothing")
    parser.add_argument("--add", nargs=2, action="append", metavar=("VENDOR", "URL"), default=[])
    args = parser.parse_args()
    manifest = load_manifest()
    if args.check:
        if args.add:
            fail("--check and --add do not combine")
        check(manifest)
        return
    known = {entry["url"] for entry in manifest["certificates"]}
    for vendor, url in args.add:
        if vendor not in VENDORS:
            fail(f"unknown vendor {vendor!r}; one of {', '.join(VENDORS)}")
        if url not in known:
            manifest["certificates"].append({"vendor": vendor, "url": url})
            known.add(url)
    refresh(manifest, datetime.date.today().isoformat())


if __name__ == "__main__":
    main()
