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
every root is self-signed and every intermediate's signature chains to a
listed root. Review the diff like any other pull request: a changed root is
a change of whom irlume trusts.

Requires Python 3.9+ and the openssl command line tool.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
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


def to_der(data):
    """DER bytes of one certificate given as DER or PEM."""
    if data.lstrip().startswith(b"-----BEGIN"):
        return openssl(["x509", "-outform", "DER"], data)
    # Round-trip through openssl to prove it is one certificate, then keep
    # the vendor's own bytes: re-encoding could change what was signed.
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


def signed_by(child_der, parent_der):
    """True when parent's key verifies child's signature (no time or trust checks)."""
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
                "-partial_chain", "-CAfile", parent, child,
            ],
            capture_output=True,
        )
        return proc.returncode == 0


def download(url):
    if not url.startswith("https://"):
        fail(f"{url}: only HTTPS sources are accepted")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        if not response.geturl().startswith("https://"):
            fail(f"{url}: redirected to a non-HTTPS URL")
        data = response.read(MAX_CERT_BYTES + 1)
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
    by_subject = {}
    for entry in entries:
        by_subject.setdefault(entry["subject"], []).append(entry)
    for entry in entries:
        der = ders[entry["sha256"]]
        if entry["role"] == "root":
            if not signed_by(der, der):
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
            for parent in by_subject.get(child["issuer"], []):
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


def refresh(manifest, today):
    previous = {entry["url"]: entry for entry in manifest["certificates"]}
    entries = []
    ders = {}
    for url, old in previous.items():
        der = download(url)
        sha = hashlib.sha256(der).hexdigest()
        if sha in ders:
            fail(f"{url}: the same certificate is already listed under another URL")
        ders[sha] = der
        entry = {"vendor": old["vendor"], "url": url, **describe(der), "sha256": sha}
        entry["role"] = "root" if entry["subject"] == entry["issuer"] else "intermediate"
        entry["file"] = file_name(entry)
        # The date these exact bytes were first downloaded.
        entry["retrieved"] = old["retrieved"] if old.get("sha256") == sha and old.get("retrieved") else today
        if old.get("sha256") and old["sha256"] != sha:
            print(f"changed: {url}")
        entries.append(entry)
    entries.sort(key=sort_key)
    verify_set(entries, ders)

    for name in listed_files():
        os.remove(os.path.join(ANCHORS, name))
    for entry in entries:
        path = os.path.join(ANCHORS, entry["file"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(ders[entry["sha256"]])
    manifest["certificates"] = [
        {key: entry[key] for key in (
            "vendor", "role", "subject", "issuer", "not_before", "not_after",
            "sha256", "file", "url", "retrieved",
        )}
        for entry in entries
    ]
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    with open(SHIPPED_RS, "w", encoding="utf-8") as f:
        f.write(rust_list(entries))
    roots = sum(entry["role"] == "root" for entry in entries)
    print(f"{len(entries)} certificates ({roots} roots) written")


def check(manifest):
    entries = manifest["certificates"]
    ders = {}
    for entry in entries:
        if not entry["url"].startswith("https://"):
            fail(f"{entry['file']}: source is not HTTPS")
        if entry["file"] != file_name(entry):
            fail(f"{entry['file']}: expected the name {file_name(entry)}")
        with open(os.path.join(ANCHORS, entry["file"]), "rb") as f:
            der = f.read()
        if hashlib.sha256(der).hexdigest() != entry["sha256"]:
            fail(f"{entry['file']}: SHA-256 differs from the manifest")
        if describe(der) != {key: entry[key] for key in ("subject", "issuer", "not_before", "not_after")}:
            fail(f"{entry['file']}: subject, issuer or validity differs from the manifest")
        role = "root" if entry["subject"] == entry["issuer"] else "intermediate"
        if entry["role"] != role:
            fail(f"{entry['file']}: role should be {role}")
        ders[entry["sha256"]] = der
    if len(ders) != len(entries):
        fail("manifest.json lists a certificate twice")
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
