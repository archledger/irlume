# ADR-0022: Seal maintainer qualification campaigns before release signing

**Status:** Accepted
**Date:** 2026-09-02
**Amends:** [ADR-0021](0021-release-qualified-camera-profile-evidence.md)
**Design:** [Maintainer Qualification Campaign](../superpowers/specs/2026-09-02-camera-profile-maintainer-qualification-campaign-design.md)

## Context

ADR-0021 requires a signed aggregate release qualification artifact, but an
artifact signature alone cannot prove that labels were frozen before capture,
the cohort and attack matrix were complete, statistical rules were not changed
after seeing results, or a second person reviewed the evidence. A single
end-to-end tool would combine biometric access, evaluation, review, and release
authority. Procedural scripts would leave the same facts unverifiable.

## Decision

Use a sealed, one-way campaign workflow. A versioned campaign policy constrains
a signed campaign protocol. The protocol constrains a frozen private campaign
bundle. A deterministic evaluator produces a private transcript and an
aggregate-only public result. A distinct reviewer signs an attestation binding
every predecessor digest and the exact public result. A canonical reviewed
aggregate envelope binds that public result to the attestation. Its digest is
the campaign-result digest compiled into the existing release artifact. A
compiler with no vault access may then emit canonical unsigned artifact bytes.
Release signing and publication remain separate explicit gates.

Each campaign qualifies one exact hardware class and one baseline/candidate
profile pair. The framework is reusable across campaigns, but a campaign never
generalizes its evidence to nearby hardware or profiles. Profile acceptance is
a paired non-inferiority claim against the exact baseline, not a new population
certification of Irlume's biometric models.

Participant withdrawal before publication invalidates a referencing campaign.
After publication, withdrawal deletes retained biometric assets and prevents
future use, while the identity-free reviewed aggregate remains valid only until
its fixed artifact expiry. Private assets are retained no longer than that
validity period and never longer than one year from collection.

## Alternatives Considered

### One End-To-End Tool

Rejected because one process could collect biometric data, choose analysis,
declare a pass, and prepare authority output without an independently
verifiable boundary.

### Manual Governance Plus Measurement Scripts

Rejected because procedures alone cannot prove immutable labels, complete
denominators, reviewer independence, or that compiled artifact bytes came from
the reviewed result.

### Absolute Population Recertification Per Profile

Rejected because profile qualification asks whether an exact candidate
preserves an already approved operating point. Repeating a population-scale
model certification for every transport profile is a different and much larger
program.

## Consequences

- Campaign collection, evaluation, review, compilation, signing, local
  commissioning, and production selection remain separate authorities.
- A failed campaign cannot be repaired by editing labels, margins, denominators,
  or results under the same campaign identifier.
- The release artifact and repository contain only identity-free aggregates and
  digests. Raw assets and biometric intermediates remain in the encrypted
  maintainer vault.
- A second reviewer is mandatory before release-artifact compilation.
- Real recruitment, biometric capture, hardware execution, release signing,
  publication, commissioning, and production integration each require a later
  explicit gate.
