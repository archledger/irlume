# ADR-0036: Genuine-TPM evidence in doctor, offline

## Status

Proposed 2026-10-17. Adds a doctor check that says whether the TPM irlume
seals to is a genuine one from a known manufacturer, from the TPM's
endorsement key (EK) certificate. The maintainer decided on 2026-10-17 that:
- the check works offline only and never contacts a vendor;
- its trust anchors are vendor root and intermediate CA certificates that
  irlume curates from the vendors' own PKI pages, each pinned by SHA-256,
  refreshed by a script and reviewed in pull requests;
- a chain irlume cannot complete reads as unknown, never as "not genuine";
- the vendors' unstated redistribution terms for public CA certificates are
  accepted.

Item 7 of the 2026-10-14 TPM survey. Depends on ADR-0034 (irlume's storage
key) and ADR-0008 (share-safe support reports).

## Context

### Why

irlume seals the template key and keyring secrets to the TPM (ADR-0025,
ADR-0034). Nothing checks today that the TPM irlumed talks to is a real one:
a software TPM left configured (`IRLUME_TCTI` pointing at swtpm after a test),
a device swapped on the bus, or a misconfigured transport would seal to
something that is not a hardware TPM, and doctor would not say so. Windows
uses the EK certificate for exactly this: "Solutions can use the certificate
with the TPM containing the endorsement key to confirm a scenario really
involves a TPM from a specific TPM manufacturer (instead of malware acting
like a TPM)" (Microsoft Learn, "How Windows uses the TPM").

### Where the certificate is, when there is one

From the TCG EK Credential Profile 2.7 (2026-03-16), the PC Client Platform
TPM Profile 1.05 r14 and the TPM 2.0 Library v185:

- A certificate is optional: "the TPM might not be provisioned with all the
  credentials because of NV space restrictions; the credentials could be
  stored off the TPM" (Credential Profile 2.2), and the PTP "does not require
  pre-provisioned certificates" (4.5.2).
- When stored, it is in an NV index: the legacy low range (0x01C00002 for
  RSA 2048, 0x01C0000A for ECC P-256, with templates at 0x01C00004 and
  0x01C0000C) or the high range from 0x01C00012, where each even index holds
  a certificate and the next odd index may hold its template. An optional
  chain may sit at 0x01C00100 to 0x01C001FF, but "The Root CA certificate
  MUST NOT be contained in NV". An index may carry bytes after the DER
  certificate, and some TPMs prefix it with a `0x10 0x01 0x00` length header
  (go-attestation `ParseEKCertificate`).
- The certificate matches the EK when the EK's public key, recreated from its
  template, equals the certificate's (Credential Profile 2.2.2.8).
- "The root certificate should not be retrieved from a URL in the AIA
  extension as this is a possible attack vector. Instead, the root
  certificate should be provisioned in a trusted root store out of band or
  from a trusted source" (3.2).

### What the TPMs irlume meets carry

- **Discrete TPMs** (Infineon, STMicroelectronics, Nuvoton) normally store a
  certificate, issued by a per-product or per-firmware intermediate CA under a
  long-lived vendor root (2030 to 2099). Intermediates are not in the TPM and
  keep appearing: Microsoft's TrustedTpm.cab lists about 150 for Infineon
  alone, and added six on 2026-04-15.
- **Intel PTT** before Tiger Lake usually has no certificate in NV; Intel
  serves it from `ekop.intel.com` keyed by a hash of the EK. From Tiger Lake
  (CSME 15) Intel's On-Die CA issues the PTT EK certificate "without a need to
  connect to the Intel server over the internet" (Intel CSME Security White
  Paper 1.5, 5.3).
- **AMD fTPM** usually has none in NV; AMD serves it from `ftpm.amd.com`.
  Its two `AMDTPM` roots are not in Microsoft's bundle.
- **swtpm** can create an EK certificate signed by a local CA
  (`swtpm_setup --create-ek-cert`, `swtpm_localca`), so a certificate being
  present proves nothing; only a chain to a known vendor root does.

### What other tools do

No Linux tool verifies the chain completely: tpm2-tools and go-attestation
retrieve certificates only, systemd v262 checks that the EK matches its
certificate but carries no roots, and keylime checks one issuer level against
a store last changed in 2023. Microsoft's TrustedTpm.cab is the broadest
anchor list (122 dated updates since 2017) but states no licence.

### Linking the storage key to that TPM

TPM2_MakeCredential needs no TPM secret and can run in software; the TPM
returns its secret through TPM2_ActivateCredential only "if the public area
is a valid object on the same TPM as the EK" (Part 1, 21.2). A key with
`fixedTPM` cannot be placed into another TPM: TPM2_LoadExternal requires
`fixedTPM` CLEAR when a private area is given, and TPM2_Import refuses it
(Part 3, 12.3 and 13.3). So a software MakeCredential to the certified EK,
bound to the Name of irlume's storage key, followed by an ActivateCredential
the TPM completes, shows that a TPM holding that EK also holds that key.

### What the check cannot claim

A verdict computed on the machine is only as trustworthy as the program that
computes it and its trust store: RFC 9334 (7.1) assumes "the Verifier has not
been compromised", and Microsoft notes that "someone can easily spoof a
software KSP as a TPM KSP with local administrator credentials" ("TPM Key
Attestation"). The check catches a misconfiguration, a swapped or emulated
device, or a non-root tampering; it does not protect against a live root
process, which docs/SECURITY_AT_REST.md already names as the trust boundary.

### Privacy

"Because an Endorsement Key is unique to a TPM and usually has a long
lifetime, it could be used to identify a user or a platform" (Credential
Profile 2.3). Fetching a certificate from Intel or AMD sends a hash of the EK,
a permanent device identifier, to the vendor with the client's address.

## Decision

### 1. A `tpm-endorsement` doctor check

doctor gains a public check, `tpm-endorsement`, in the same doctor code the
TUI's diagnostics and `irlume doctor --json` run (CLI and TUI parity). The CLI
never opens the TPM: irlumed answers a new root-only request (section 4).

| State | When |
|---|---|
| `pass` | A stored EK certificate matches the TPM's EK, is an EK certificate by the Credential Profile (section 2.3), its chain verifies to a pinned vendor root, and irlume's storage key is in the same TPM. The detail names the manufacturer, model and firmware version (the certificate's subject alternative name, as `tpm-firmware` already reports them from the TPM's properties) and the root CA. |
| `info` | No EK certificate is stored (common on Intel PTT before Tiger Lake and on AMD fTPM). doctor says irlume does not fetch one. |
| `warn` | A stored certificate does not match the TPM's EK; on a chain that reaches a pinned root, a signature, a CA constraint or the leaf's EK profile (section 2.3) fails; or the same-TPM test fails with the result section 2.4 names, so irlume's storage key is not in the TPM the certificate names. Each points at a swapped device, an emulator or a wrong `IRLUME_TCTI`. |
| `unknown` | The chain cannot be completed: its issuer is not in irlume's list (a newer intermediate, or a manufacturer irlume does not know), or it is signed with an algorithm irlume does not accept, such as SHA-1; neither means the TPM is not genuine. Also: irlumed is not running, older than the request, or the caller is not root; the endorsement hierarchy is disabled or its authorization is set (section 3); the same-TPM test hit an operational error (section 2.4); or the TPM could not be read in the time allowed. |

A TPM may store several EK certificates (the low-range RSA and ECC ones, say).
irlume judges only certificates for storage EKs it can run the same-TPM test
with: RSA and ECC NIST P-256, P-384 and P-521 storage EKs, whose template has
`restricted` and `decrypt` SET and `sign` CLEAR, since "If keyHandle is not a
Storage Key, then the TPM shall return TPM_RC_TYPE" (Part 3, 12.5). The
certificates the Credential Profile assigns to other EKs are skipped and
named when populated: signing EKs, firmware-limited EKs, ML-KEM storage EKs
and the SM2 one (section 2.1); they do not change the result. Each judged
storage EK certificate is judged on its own by the rows above, and the check reports the worst
evidence first, so a bad certificate is never hidden by a good one and a
genuine TPM is not refused over an optional certificate irlume cannot read:
`warn` when any certificate is in a `warn` case; otherwise `pass` when any
passes; otherwise `unknown` when any cannot be judged; otherwise `info`. The
detail names each certificate's result by its index and algorithm.

The check never reports `fail`: it judges evidence, and irlume works on a TPM
it cannot vouch for.

### 2. What irlumed reads and checks

1. The certificate handles the Credential Profile assigns, and no other index
   in its 0x01C00000 to 0x01C07FFF range (which also holds templates, nonces,
   PolicyAuthorizeNV data such as 0x01C07F02 and other reserved
   allocations). Judged: the low-range RSA 2048 and ECC P-256 certificates at
   0x01C00002 and 0x01C0000A, and the high-range storage EK certificates H-1
   to H-4, H-6 and H-7 at 0x01C00012, 0x01C00014, 0x01C00016, 0x01C00018,
   0x01C0001C and 0x01C0001E. Skipped and named when populated: H-5 (SM2 at
   0x01C0001A) and every other certificate the profile assigns from
   0x01C00032 to 0x01C0007A, that is the signing EK certificates (H-8 to
   H-17 and H-22 to H-25, and the ML-DSA ones at 0x01C00070 to 0x01C0007A),
   the firmware-limited storage ones (0x01C00040 to 0x01C00046) and the
   ML-KEM storage ones (0x01C00060 to 0x01C0006A), none of which irlume can
   run the same-TPM test with. Each judged certificate index
   is read as DER with trailing bytes tolerated, and when it starts with the PC Client wrapper
   (`0x10 0x01 0x00` then a two-byte big-endian length), exactly the
   `length` bytes after those five, as go-attestation's `ParseEKCertificate`
   reads them; the templates and, in the low range,
   the nonces that go with them (below); and the chain indices 0x01C00100 to
   0x01C001FF, whose contents are joined in index order and split into every
   complete DER certificate, since one index may hold several certificates
   and one certificate may continue into the next index (Credential Profile
   2.2.2.5.2). Nothing else in NV is read.
2. The EK for each certificate: the persistent EK at 0x81010001 when its
   public key matches (TCG provisioning guidance; systemd v262 persists one
   there), otherwise one derived transiently. In the high range its template
   is the next odd index when populated, else the default for that index. In
   the low range the template is 0x01C00004 (RSA) or 0x01C0000C (ECC) when
   populated, else the default L-1 or L-2, and the nonce at 0x01C00003 or
   0x01C0000B, when populated, goes into the template's unique field as the
   Credential Profile's EK creation procedure describes. The certificate is
   used only when its public key equals the EK's. The firmware-limited EKs
   skipped in section 2.1 are created under `TPM_RH_FW_ENDORSEMENT`, which
   irlume does not use; the ML-KEM and SM2 ones would need a key exchange
   none of irlume's crates provides (section 6).
3. The chain, in software: the EK certificate, then intermediates from the
   NV chain indices and from irlume's list (section 5), up to a pinned root.
   The leaf must be an EK certificate by the Credential Profile (3.2): a
   critical Basic Constraints with `CA:FALSE`, the critical Key Usage the
   profile sets for the EK's algorithm, a subject alternative name (critical
   when the subject is empty) carrying all three attributes the profile
   requires there (3.2.9): the TPM manufacturer, whose value equals
   `TPM_PT_MANUFACTURER`, the model and the firmware version, and, when an
   Extended Key Usage is present, `tcg-kp-EKCertificate` (2.23.133.8.1) in
   it. Each signature verifies, and each CA has `CA:TRUE` with its path
   length and `keyCertSign`; a CA that carries an Extended Key Usage must
   include `tcg-kp-EKCertificate` or `anyExtendedKeyUsage` in it, since an
   issuing CA's Extended Key Usage limits what it may issue (Credential
   Profile 3.2.16, RFC 5280 4.2.1.12). Every critical extension on the path must be one the
   verifier processes, as RFC 5280 (4.2) requires; a path with any other
   critical extension, such as name or policy constraints it does not
   implement, cannot be judged and reads `unknown`. Validity periods are reported, not enforced: EK and
   intermediate certificates of genuine TPMs expire while the TPM stays in
   use (a typical PC Client validity is 5 to 10 years, Credential Profile
   2.2.3, and one Infineon intermediate expired on 2025-10-20), so a `pass`
   names an end date that has passed. Revocation is not checked: CRLs and
   OCSP need the network.
4. The same-TPM test: a software TPM2_MakeCredential to the EK's public key
   (RSA-OAEP or ECDH with that key, computed by irlumed, not by the TPM's own
   `TPM2_MakeCredential`, which would show the secret to the very TPM under
   test)
   with the Name of the storage key new seals go under (ADR-0034's recorded
   DA-exempt key, or the original key before it persists), then
   TPM2_ActivateCredential with that key as `activateHandle` and the EK as
   `keyHandle`, under the EK's policy (PolicySecret on the endorsement
   hierarchy for the low-range templates, the high-range PolicyB otherwise).
   It passes when the TPM returns the secret. It fails, the `warn` of section
   1, only when the TPM refuses the credential itself: `TPM_RC_INTEGRITY`
   (the credential is not bound to that key's Name) or a seed the EK cannot
   decrypt (`TPM_RC_VALUE` on the secret). Any other error is `unknown`:
   `TPM_RC_LOCKOUT` and authorization failures, resource exhaustion
   (`TPM_RC_OBJECT_MEMORY`, `TPM_RC_SESSION_MEMORY`), `TPM_RC_RETRY` and
   transport errors. While only the original storage key exists, which is
   not exempt from dictionary-attack protection (ADR-0034), the test is not
   run during a lockout and reads `unknown`.

irlumed keeps nothing between requests. Each one reads the endorsement
hierarchy's state (section 3) and the certificate and chain indices again,
verifies the chain again in software, matches the EK and runs the same-TPM
test again, since `TPM2_HierarchyControl`, `TPM2_HierarchyChangeAuth`,
`TPM2_ChangeEPS` and NV writes can change any of these answers within a boot.
A request costs the NV reads, at most one EK derivation and one
ActivateCredential per storage EK certificate, and the software checks.

### 3. The endorsement hierarchy

The test needs the endorsement hierarchy's authorization, which is empty on
almost every Linux machine. irlumed reads `endorsementAuthSet` from
`TPM_PT_PERMANENT` and `ehEnable` from `TPM_PT_STARTUP_CLEAR` first. When the
authorization is set or the hierarchy is disabled, it tries nothing and the
check is `unknown` with that reason: irlume never guesses an authorization.

### 4. A request of its own

The answer travels in a new root-only request, `TpmEndorsement`, with its own
client budget of 60 seconds, not in `TpmReadiness`: deriving an EK can take
more than 10 seconds on a slow firmware TPM, and `TpmReadiness` already stays
within its 30-second budget only by deriving at most once (#1105). The budget
binds irlumed too, not only the client: the handler takes the request's
deadline, checks it before each TPM command, and stops with `unknown` ("ran
out of time") once it has passed, so an abandoned request releases the TPM
within one command after its deadline. It judges at most four storage EK
certificates, the low-range RSA and ECC ones first. Any beyond those are named
as not judged, and their presence keeps the result from `pass`: it reads
`unknown` unless a judged certificate is in a `warn` case, so the worst-first
rule of section 1 never hides a certificate it did not look at. The request
is additive on the wire, gets explicit posture table arms, and an older
irlumed's refusal reads as "irlumed predates the endorsement check"
(`unknown`).

### 5. The trust anchors

- irlume ships the vendor CA certificates it trusts in
  `crates/irlume-core/tpm-ek-anchors/`: one DER file per root or intermediate
  CA, grouped by vendor, with a manifest that lists for each its subject, its
  role (root or intermediate), its validity, its SHA-256, the vendor URL it
  was downloaded from and the date. irlumed embeds them at build time; nothing
  is read from disk at run time.
- Sources are the vendors' own pages: Infineon (`pki.infineon.com`),
  STMicroelectronics and GlobalSign (`secure.globalsign.com`,
  `sw-center.st.com`), Nuvoton (`www.nuvoton.com/security/NTC-TPM-EK-Cert/`),
  Intel (`upgrades.intel.com` for the legacy PTT root, `tsci.intel.com` for the
  On-Die CA) and AMD (`ftpm.amd.com/pki/aia/`). Other manufacturers are added
  when a primary source for them is found.
- `scripts/update-tpm-ek-anchors.py` downloads the listed URLs, checks that
  every intermediate chains to a listed root and that each file's SHA-256 is
  what the manifest records, and rewrites the directory and manifest. A
  refresh is a reviewed pull request; one before each release is the target.
  A stale list makes a new intermediate read `unknown` (issuer not in
  irlume's list), never `warn`.
- A root or intermediate that expires stays listed, since the TPMs it
  certified stay in use (section 2.3).

### 6. The verification code

All of it is RustCrypto, on the `der` and `spki` crates irlume-core already
depends on: `x509-cert` parses; `rsa` verifies RSA PKCS#1 v1.5 and PSS
signatures with SHA-256, SHA-384 and SHA-512 and performs the RSA-OAEP
encryption of section 2.4; `p256`, `p384` and `p521` verify ECDSA (P-521 for
Nuvoton's 2023 root) and perform the ECDH of section 2.4. A chain signed
with SHA-1, or with an algorithm outside this list, cannot be verified and
reads `unknown` with the algorithm named, unless another path to a pinned
root verifies.

`rsa` has an unpatched advisory, RUSTSEC-2023-0071 (the Marvin attack): a
timing side channel in operations with the RSA private key. irlume holds no
RSA private key here and calls only public-key verification and encryption,
so the vulnerable code is never reached. `deny.toml` therefore takes a
justified ignore for it, with that rationale and a tracking issue, as
AGENTS.md's dependency rule allows; `ring` is not used because it offers no
RSA encryption.

### 7. Privacy

- Nothing leaves the machine: no vendor fetch, no AIA, CRL or OCSP request,
  ever.
- doctor's text, `--json` and support reports (ADR-0008) never carry the EK
  public key, its hash, the certificate serial or a fingerprint of the EK
  certificate. They carry the manufacturer, model and firmware version, the
  names of the CAs in the chain, and the result.
- Every string taken from a certificate (the manufacturer, model and
  firmware version in its subject alternative name, a CA's name) is
  untrusted: irlumed bounds it, and doctor prints it as visible ASCII on one
  line, as `firmware_text` already does for firmware-written text in the
  `pcr7-binding` check, before it reaches the terminal, `--json` or a support
  report.

### 8. When to revisit

Revisit if TCG or Microsoft publishes a signed, licensed anchor set usable on
Linux (it would replace section 5's curation), if the maintainer wants an
opt-in vendor fetch for firmware TPMs (declined on 2026-10-17), or if irlume
gains a remote verifier, which would make the evidence stronger than a local
check.

## Consequences

- doctor reports, on most discrete TPMs and recent Intel PTT, which
  manufacturer's TPM irlume seals to, and flags an emulator or a swapped
  device that claims a certificate it cannot back.
- On Intel PTT before Tiger Lake and on AMD fTPM the check usually reads
  `info` (no certificate stored), since irlume does not fetch one.
- irlume carries and refreshes a few hundred vendor CA certificates (about
  half a megabyte), and gains `x509-cert`, `rsa`, `p256`, `p384` and `p521`
  as normal dependencies of irlume-core, with a justified ignore of
  RUSTSEC-2023-0071 (section 6).
- The wire gains one root-only request.

## Phasing

- **Phase 1:** the anchors directory, its manifest and update script, and the
  software chain verifier (sections 5 and 6), unit-tested on generated test
  chains and on the shipped anchors' own consistency.
- **Phase 2:** irlumed's `TpmEndorsement` request (sections 2 to 4), with
  swtpm tests.
- **Phase 3:** the `tpm-endorsement` doctor check, its MACHINE-API row, the
  TUI readout through the shared doctor code, and the documentation.

## Amendment 2026-10-17: Phase 1 verifier details

Phase 1 (`crates/irlume-core/src/ek_cert.rs`, the anchors in
`crates/irlume-core/tpm-ek-anchors/`) settles points sections 2.3, 5 and 6
left open:

- **Names.** An issuer is found by comparing names as RFC 5280 7.1 does:
  each RDN's attributes in any order, and directory strings as text after
  case folding and insignificant space handling (RFC 4518, without its
  Unicode normalization). ST's ECC Intermediate CA 02 names its issuer in
  UTF8String where that issuer's own subject is PrintableString; an exact
  comparison missed the link. A matching name only nominates an issuer: its
  key must still verify the signature.
- **When a failing signature is evidence.** A signature that does not verify
  reads `warn` only between certificates irlume vouches for (the EK
  certificate, the listed CAs and the roots), and only when the child's
  authority key identifier equals the issuer's subject key identifier, so the
  certificate names the very key that failed. Without both identifiers, a
  same-named CA with another key (a re-keyed CA irlume does not list) is not
  the issuer, and the path reads `unknown`; so does a failing signature of or
  by a certificate from the chain indices, which any process that can define
  NV indices may write. A first search uses irlume's own certificates
  alone, and only a second adds those, so they cannot use up the search's
  bounds ahead of a listed path.
- **The EK certificate's Extended Key Usage**, when present, must also be
  non-critical, as the profile requires (3.2.16); a critical one is refused.
- **Profile checks are about purpose, not encoding.** Section 2.3's checks,
  and the EKU's criticality, decide whether a certificate is an EK
  certificate for this TPM; a failure is `warn`, which points at a swapped
  device or an emulator. Deviations the vendor's signature still covers and
  that do not change what the certificate certifies are accepted: a TPM
  attribute in PrintableString or IA5String rather than UTF8String, a missing
  or critical authority key identifier (which then only stops tying a failing
  signature to a key), rsaEncryption parameters absent rather than NULL.
  Parameters other than NULL make the key unreadable, so `unknown`.
- **Roots** are trust anchors by name and key: their own extensions are not
  processed (RFC 5280 6.1.1), and a root's self-signature is never relied on.
  A CA that is not self-signed is an intermediate, also when its vendor calls
  it a root (ST's `STM TPM EK Root CA` under GlobalSign's root).
- **Algorithms.** RSA moduli of 2048 to 4096 bits; ECDSA on P-521 needs at
  least SHA-384, since a shorter hash cannot fill half the order. The EK
  certificate's own key may be named rsaEncryption or id-RSAES-OAEP (older EK
  certificates use the latter).
- **Extensions.** Basic Constraints, Key Usage, Extended Key Usage, Subject
  Alternative Name, the key identifiers and Certificate Policies are
  processed, the last with the initial policy set anyPolicy and no explicit
  policy; name constraints, policy constraints, policy mappings and
  inhibitAnyPolicy read `unknown` even when not critical. A processed
  extension that does not parse, or any extension that appears twice, reads
  `unknown`.
- **Bounds**, since the chain indices are untrusted: at most 64 certificates
  from them, 6 CAs between the EK certificate and a root, 32 complete paths
  and 2048 candidate issuers tried per EK certificate.
- **The anchors**: 279 certificates (31 roots), all over HTTPS from the
  vendors' sites, with Infineon's OPTIGA Trust M CAs (not a TPM), Intel's
  pre-production ICL-N intermediate, the TPM 1.2 era SHA-1 chains and AMD's
  Pluton chains left out; the last have no vendor source for AMD Root CA R4
  or the factory intermediates. A refresh never drops a certificate: one
  whose URL starts serving another stays, marked retained, as section 5
  keeps expired ones; only removing its manifest entry retires it.
- **Crates**: `rsa` is pinned at `=0.10.0-rc.19`, the release candidate on
  the der 0.8 and digest 0.11 generation irlume already uses; 0.9 would
  duplicate the previous generation. The RUSTSEC-2023-0071 ignore is tracked
  in #1112.

## Acceptance tests

- The verifier accepts a generated chain (root, intermediate, EK certificate)
  with RSA and ECDSA signatures, also when a certificate in it has expired
  (the end date reported), and refuses one with a broken signature, a CA
  without `CA:TRUE` or `keyCertSign`, or a path length exceeded; a SHA-1
  signature and a chain that ends at a root not in the list read as
  unverifiable (`unknown`), not as failed.
- A leaf that is not an EK certificate is refused even when its key matches
  and its chain verifies: `CA:TRUE`, a missing or non-critical Basic
  Constraints, the wrong Key Usage, no TPM manufacturer attribute or one that
  differs from `TPM_PT_MANUFACTURER`, no model or no firmware version
  attribute, or an Extended Key Usage without `tcg-kp-EKCertificate`.
- A path through an issuing CA whose Extended Key Usage leaves out both
  `tcg-kp-EKCertificate` and `anyExtendedKeyUsage` is refused.
- The chain reader joins the chain indices in order and finds every
  certificate when one index holds two and when one certificate continues
  into the next index.
- A low-range certificate whose EK uses the template at 0x01C00004 with the
  nonce at 0x01C00003 matches its EK; derived from the default template alone
  it would not.
- A path with a critical extension the verifier does not process reads
  `unknown`.
- Several certificates: one that passes beside one signed with SHA-1 reads
  `pass`, naming the other as unverifiable; one that passes beside one that
  does not match its EK reads `warn`; one that cannot be judged beside none
  that passes reads `unknown`.
- Every shipped intermediate chains to a shipped root, and every file's
  SHA-256 matches the manifest.
- The NV reader reads a certificate with trailing bytes, and one in the PC
  Client wrapper with trailing bytes after the declared length, as exactly
  the certificate; it refuses a wrapper whose length runs past the index, and
  a certificate whose public key differs from the EK's. It never takes an
  index in the chain range for an EK certificate.
- Only the assigned certificate handles are read: data at 0x01C07F02 or
  another non-certificate index in the range is never taken for a
  certificate, and a TPM with only such indices reads `info`. A
  firmware-limited, signing, ML-KEM or SM2 EK certificate is skipped and
  named, and does not change the result.
- A request whose deadline passes stops before its next TPM command and
  reads `unknown`. With five storage EK certificates, the fifth is named as
  not judged and the result is not `pass`.
- A certificate whose subject alternative name or CA name carries control
  characters or terminal sequences reaches doctor's output as visible ASCII
  on one bounded line.
- On swtpm, for an RSA EK (`swtpm_setup --create-ek-cert`, RSA by default)
  and an ECC one (with `--ecc`) alike: the check reads `unknown` (issuer not
  in irlume's list) with the shipped anchors; with the test CA added as an
  anchor in the test only, it reads `pass` and the same-TPM test succeeds
  against irlume's storage key, through RSA-OAEP and through ECDH; a
  credential bound to another key's Name fails with `TPM_RC_INTEGRITY`
  (`warn`) on both; with the endorsement authorization set, nothing is tried and the
  check reads `unknown`; after the authorization is cleared in the same boot,
  the next request runs the test.
- No doctor text, `--json` field or support report contains the EK public
  key, its hash, the certificate serial or its fingerprint.
- irlume makes no network request in any of these paths.
