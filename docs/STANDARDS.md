# Standards that apply to irlume, and where it stands

Facial-recognition security has a small set of standards that matter for a
device-login system: how anti-spoofing is tested (ISO/IEC 30107-3), how error
rates are measured and reported honestly (ISO/IEC 19795-1), how stored
templates are protected (ISO/IEC 24745), and two published consumer bars
(Microsoft's Windows Hello biometric requirements and Android's biometric
classes). This page maps each onto irlume: what the standard demands, what
irlume has measured, and what irlume does not claim.

**irlume holds no certification.** Every number on this page comes from a
committed artifact in this repository (a dated result document or a raw
benchmark file) and has a reproduction path, most of them collected in
[VERIFY.md](VERIFY.md). Where a sample is too small to support a strong claim,
the confidence interval says so. Anything that cannot be checked that way is
not on this page.

| Standard / bar | What it covers | irlume today |
|---|---|---|
| [ISO/IEC 30107-3](#isoiec-30107-3-presentation-attack-detection) | spoof testing and reporting | methodology adopted, self-tested; one attack class published as unsolved |
| [ISO/IEC 19795-1](#isoiec-19795-1-measuring-and-reporting-accuracy) | accuracy measurement and reporting | benchmark protocols with committed raw results |
| [ISO/IEC 24745](#isoiec-24745-template-protection) | biometric template protection | encryption and TPM key custody, live-audited |
| [Windows Hello requirements](#the-windows-hello-bar) | consumer face-login bar (FAR, TAR) | not demonstrated at the required confidence; measured points published |
| [Android biometric classes](#the-android-biometric-class-bar) | device-unlock bar (SAR, FAR, FRR) | vocabulary used in spoof reporting; no certification program covers Linux PCs |

## ISO/IEC 30107-3: presentation attack detection

The standard defines how liveness ("is this a real face or a photo/screen/mask")
gets tested: attack instruments grouped into species, two error rates (APCER,
the fraction of attacks accepted; BPCER, the fraction of genuine users
rejected), and non-responses reported separately. Commercial labs (iBeta is the
NIST-accredited one) certify against it in tiers by attacker budget: Level 1
caps artifact cost at $30 (prints, screen replays), Level 2 at $300 (3D masks).

irlume adopted the methodology rather than the certificate:

- [PAD_SELFTEST.md](PAD_SELFTEST.md) is the protocol: six 2D attack species
  (the Level 1 family), APCER/BPCER/non-response per species, worst-case
  headline, and a Clopper-Pearson exact confidence interval on every rate. The
  capture and report tools ship in the repo (`irlume padcapture` /
  `irlume padreport`, metrics unit-tested in `crates/irlume-core/src/pad.rs`),
  so anyone with the hardware can run the same protocol.
- Results are published dated and tied to the gate commit, including the ones
  that hurt. The [2026-06-30 run](pad-results/2026-06-30-ir-liveness-selftest.md)
  rejected every phone-screen, laptop-screen, and matte-print attack (APCER 0%
  at n=20 per species, so the honest statement is "APCER at or below 16.8% with
  95% confidence") and then found that a life-size glossy vinyl print defeats
  the gate: 69 of 70 presentations accepted, APCER 98.6% [92.3%, 100%]. The
  result document proves threshold tuning cannot fix it (the banner's depth
  ratio range overlaps and exceeds the genuine range) instead of shipping a
  cosmetic threshold bump.
- The follow-up passive blink gate closed that breach in validation
  ([2026-07-01](pad-results/2026-07-01-passive-ear-liveness.md), 0 of 10 banner
  attacks accepted) but collapsed in field conditions
  ([same day, daemon path](pad-results/2026-07-01-passive-ear-realworld-nonresponse.md):
  11 of 11 genuine sudo attempts got no blink verdict), so it ships **off by
  default** (`require_challenge`, [ADR-0002](adr/0002-challenge-response-liveness.md)).

What that adds up to, stated plainly: in the default configuration the
credential-releasing gate is single-frame IR physics. It stopped every emissive
screen and matte print tested; a large IR-reflective flat print of the enrolled
user defeats it, and that is an accepted, documented residual risk
([ADR-0001](adr/0001-liveness-pad-strategy.md), and the README's honest
limitations). Level 2 instruments (3D masks) have never been tested and no
resistance is claimed. Scene-level IR flooding (open sky, sun) fails closed with
an explanatory message rather than degrading the cues silently
(`IR_AMBIENT_FLOOD` in `crates/irlume-liveness/src/lib.rs`).

**Not claimed:** any lab accreditation, iBeta conformance letter, or FIDO
certificate. The home protocol runs about 20 presentations per species against
iBeta's 150; the confidence intervals carry that difference.

**Verify:** run the protocol in [PAD_SELFTEST.md §6](PAD_SELFTEST.md#6-how-to-run)
against your own instruments; an accepted attack prints a breach warning at
capture time.

## ISO/IEC 19795-1: measuring and reporting accuracy

This is the methodology standard behind every credible FAR/FRR table: defined
protocols, disclosed datasets and sample sizes, and no claim beyond what the
data supports. irlume's implementation of that idea is the
[benchmarks/](../benchmarks/) directory: every accuracy figure in the README
and release notes is produced by a script there, on public datasets, and the
raw result files are committed (`results-*.json`) so the numbers can be read
without re-running anything.

The measured points (from [results-lfw.json](../benchmarks/results-lfw.json),
LFW 6000-pair verification, shipped AuraFace recognizer):

- EER 1.4%; 10-fold accuracy 98.7% (±0.5%); TAR 97.6% at FAR 0.1%.
- All-pairs FAR at the 0.50 measurement threshold across 87M LFW impostor
  pairs: 2.3×10⁻³ ([FAIRNESS.md](FAIRNESS.md), with the reproduce command).

Demographic differentials, the subject of NIST FRVT Part 3, are published
rather than averaged away: [FAIRNESS.md](FAIRNESS.md) reports within-group FAR
from 1.05×10⁻⁴ (White) to 1.04×10⁻³ (East Asian) at the 0.50 measurement
threshold, a roughly 10× spread, and the policy that handles it: one threshold
for everyone rather than per-group thresholds. The shipped RGB threshold
(0.55) is stricter than the 0.50 measurement point but short of the ≈0.69 that
would bound every group at 1×10⁻⁴; the password fallback absorbs the
false-reject cost, and FAR is never relaxed for a harder-to-match face.

**Not claimed:** any specific production FAR. The shipped threshold (0.55) is
stricter than the 0.50 measurement point, so the tables bound it from the loose
side; the exact operating-point FAR has not been measured at scale.

**Verify:** [benchmarks/README.md](../benchmarks/README.md) documents every
protocol; the `irlume irbench` commands in FAIRNESS.md reproduce the FAR tables.

## ISO/IEC 24745: template protection

The standard names three properties for stored biometric references:
confidentiality, renewability, and irreversibility. The irlume implementation
and its live audit are in [SECURITY_AT_REST.md](SECURITY_AT_REST.md) (tested
2026-07-02 on two TPM machines):

- **Confidentiality.** Templates are AES-256-GCM encrypted under a random key
  sealed by the TPM (PCR-bound, three-tier policy), files are `0600 root:root`,
  and the daemon releases profile data only to the owning user or root
  (`SO_PEERCRED`). The audit's disk-theft test found only ciphertext: no
  plaintext floats, no field names, no image data.
- **Renewability.** Profiles and individual scans can be deleted and
  re-enrolled at any time. The honest limit: templates are embeddings from a
  fixed public model, not a revocable transform, so this is re-enrollment, not
  cancellable biometrics in the strict 24745 sense.
- **Irreversibility.** No image is ever stored, only L2-normalized 512-D
  embeddings. Academic template inversion can produce a blurry look-alike from
  an embedding, not the original photo, and a reconstructed image still has to
  pass IR liveness to be used against irlume itself.

**Not claimed:** enclave isolation. The daemon is a root process that holds
decrypted embeddings in memory while matching; root on the live machine is the
trust boundary. SECURITY_AT_REST.md states where that is weaker than Windows
Hello's VBS enclave.

**Verify:** [VERIFY.md](VERIFY.md) §1 checks the at-rest claims in about two
minutes on your own enrollment.

## The Windows Hello bar

Microsoft's published hardware requirement for Hello face login is FAR below
0.001% (1 in 100,000) with TAR above 95%, on near-infrared cameras
([Windows Hello biometric requirements](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-biometric-requirements)).
Since irlume describes itself as Windows Hello-style, this is the comparison a
skeptical reader should demand, so here it is without rounding in irlume's
favor:

- Microsoft's own appendix computes what it takes to *verify* a 1-in-100,000
  FAR claim at 96% confidence: about 2.5 million unique impostor comparisons,
  roughly 2,237 distinct subjects. No single-maintainer project has that; any
  hobby-scale system claiming the Hello FAR bar is bluffing, and irlume does
  not claim it.
- What irlume can state from committed data: TAR 97.6% at FAR 0.1% on LFW
  (a FAR point 100× looser than the Hello bar), and within-group FAR between
  1.05×10⁻⁴ and 1.04×10⁻³ at the 0.50 measurement threshold on FairFace. The
  shipped threshold is stricter (0.55), and a sub-threshold match falls back to
  the password rather than retrying looser.
- The hardware model matches Hello's (near-IR camera, IR liveness gating the
  RGB match), and the at-rest storage comparison is written out in
  [SECURITY_AT_REST.md](SECURITY_AT_REST.md#how-this-compares-to-windows-hello).

## The Android biometric class bar

Android's CDD grades device biometrics into classes; Class 3 ("strong")
requires spoof acceptance rate (SAR) of 7% or less, FAR of 1 in 50,000 or
less, and FRR under 10%
([Measuring biometric unlock security](https://source.android.com/docs/security/features/biometric/measure)).
There is no analogous certification program for Linux PCs, so irlume borrows
only the useful part: SAR is per-attack-instrument spoof acceptance, the same
shape as per-species APCER, and irlume's spoof results read directly in those
terms. From the published self-tests under the default configuration: SAR 0%
(n=20 each, CI upper bound 16.8%) for phone-screen, laptop-screen, and
matte-print instruments; SAR 98.6% for the life-size vinyl-print instrument
that remains the documented open breach.

## Standards that do not apply to irlume

NIST FRTE (formerly FRVT) evaluates recognition algorithms; that is upstream's
scope (irlume ships AuraFace unmodified), and FRVT Part 3 is why FAIRNESS.md
exists. The iBeta conformance letter and FIDO's Biometric Component
Certification are the formal lab routes for exactly irlume's feature set; both
are accredited-lab engagements priced for vendors, and neither is claimed or
scheduled. ICAO 9303, ANSI/NIST-ITL, and the ISO 19794/39794 families govern
biometric data exchange for identity documents; irlume never exchanges
biometric data with anything, so they impose nothing. IEEE 2945-2023 describes
face-recognition system architecture but has no public conformance regime to
test against.

## If you distrust any number on this page

Good. Start at [VERIFY.md](VERIFY.md), which orders the reproductions from a
two-minute storage check to a full benchmark rerun. Every table above names the
file the number came from; if you find a mismatch between a document and its
artifact, that is a bug: open an
[issue](https://github.com/archledger/irlume/issues).
