# TPM vendor CA certificates

The root and intermediate CA certificates irlume trusts when it checks a TPM's
endorsement key (EK) certificate: the `tpm-endorsement` doctor check of
[ADR-0036](../../../docs/adr/0036-tpm-endorsement-evidence-offline.md). irlumed
embeds them at build time through `src/ek_cert/shipped.rs`; nothing here is
read at run time, and irlume never fetches a certificate.

- One DER file per CA, in a directory per vendor: `amd/`, `infineon/`,
  `intel/`, `nuvoton/`, `stmicro/` (STMicroelectronics, whose TPM roots
  GlobalSign issues).
- `manifest.json` lists each with its role, subject, issuer, validity,
  SHA-256, the vendor URL it was downloaded from and the date those exact
  bytes were first downloaded.
- A **root** is self-signed and is a trust anchor, by its name and key. An
  **intermediate** is not trusted by being listed: it only helps find a path,
  and its own signature must chain to a root, as the TPM's NV chain indices'
  certificates must.

## Sources

Every file comes over HTTPS from the vendor's own PKI site, unmodified:
`pki.infineon.com` (from Infineon's "OPTIGA TPM & OPTIGA Trust certificates"
page), `secure.globalsign.com` and `sw-center.st.com`, the URLs in Nuvoton's
"TPM EK Certificate Chain" document (`www.nuvoton.com/security/NTC-TPM-EK-Cert/`),
`upgrades.intel.com` and `tsci.intel.com`, and `ftpm.amd.com`. The vendors
state no licence for these public CA certificates; the irlume maintainer
accepted redistributing them as published on 2026-10-17 (ADR-0036 Status).

Left out on purpose:
- CAs whose issuer has no vendor source: AMD's Pluton chains (AMD Root CA R4,
  the Microsoft Pluton roots and their factory intermediates).
- Infineon's OPTIGA Trust M CAs (a secure element, not a TPM) and Intel's
  ICL-N EPID pre-production intermediate.
- TPM 1.2 era chains (VeriSign and IFX roots), signed with SHA-1, which
  irlume reads as unverifiable anyway.

A chain through a CA that is not here reads `unknown` (issuer not in irlume's
list), never `warn`.

## Refreshing

```sh
python3 scripts/update-tpm-ek-anchors.py           # re-download, verify, rewrite
python3 scripts/update-tpm-ek-anchors.py --add infineon https://pki.infineon.com/...
python3 scripts/update-tpm-ek-anchors.py --check   # offline consistency check
```

A refresh writes nothing unless every source is HTTPS and downloads, every
file is exactly one DER certificate, every root's self-signature verifies
and every intermediate's signature chains to a listed root. Review it like
code: a changed or new root changes whom irlume trusts, so compare a new
root's SHA-256 with a second, independent copy before merging. One refresh
before each release is the target.

A certificate is never dropped by a refresh: when its URL starts serving
another certificate (a re-keyed CA, say), the old one stays, marked
`"retained": true`, since the TPMs it certified are still in use, and later
refreshes keep it without downloading it. To keep a certificate whose URL is
gone, mark its entry retained by hand; to retire one, remove its entry.

CI runs `scripts/test-update-tpm-ek-anchors.py` and `--check`, and
`cargo test -p irlume-core ek_cert` checks the same set with irlume's own
verifier: every file parses and matches the manifest, the directory holds
nothing else, and every intermediate chains to a root.
