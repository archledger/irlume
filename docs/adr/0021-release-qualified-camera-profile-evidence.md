# ADR-0021: Use release-qualified camera profile evidence

**Status:** Accepted
**Date:** 2026-09-01
**Amends:** [ADR-0020](0020-layered-camera-profile-and-evidence-engine.md)
**Design:** [Camera Profile Release Qualification](../superpowers/specs/2026-09-01-camera-profile-release-qualification-design.md)

## Context

ADR-0020 requires detector, recognition, liveness, PAD, and latency gates before
an optimized camera profile can become selection authority. The first corpus
design proposed an owner-local pilot to exercise those gates without granting
authority.

Face ID and Windows Hello separate user enrollment from vendor validation.
Microsoft's published Windows Hello requirements show why: population FAR
confidence requires millions of comparisons and thousands of unique biometric
samples. One owner's local A/B captures cannot establish population security.

An owner-local corpus would impose consent, retention, signing, deletion,
encrypted storage, and biometric lifecycle obligations on the user while still
remaining non-authorizing.

## Decision

Use two independent evidence classes for optimized camera profile selection:

- Maintainers produce a bounded signed aggregate release qualification artifact
  from an approved biometric campaign. The corpus and biometric intermediates do
  not ship.
- The target machine produces fresh local commissioning evidence using only
  non-biometric transport, signal, timing, conditioning, restoration, camera,
  and connection facts.

Selection requires both evidence classes to match the exact camera scope,
baseline profile, candidate profile, tuples, schedule, catalog, preprocessing,
model, producer, and policy contracts.

Normal enrollment remains separate and cannot create qualification evidence.
Qualification and commissioning cannot read enrollment or authenticate.

Remove the unshipped owner-pilot protocol, local capture manifests, consent
ledger, vault, and legacy-import design. Do not retain compatibility code for an
unreleased schema.

## Alternatives Considered

### Keep An Optional Owner Pilot

Rejected because it adds a second biometric evidence lifecycle without
supporting population FAR, TAR, cross-identity, or presentation-attack claims.

### Use Only Local Transport Qualification

Rejected because transport evidence cannot establish model or PAD behavior. An
optimized profile with no release qualification must remain unauthorized.

### Use Production Enrollment

Rejected because it crosses the enrollment trust boundary, exposes personal
production state to qualification tooling, and still lacks population evidence.

## Consequences

- Users do not manage a qualification corpus.
- Maintainers own biometric campaign governance and release evidence.
- Raw corpus assets and biometric intermediates do not ship.
- Unsupported cameras retain conservative behavior until a matching release
  artifact exists.
- Local commissioning remains useful across physical devices without claiming
  model security.
- Commissioning uses a non-human scene and persists no frames or biometric
  derivatives.
- Artifact or commissioning drift invalidates optimized selection.
- The ASUS RGB15/IR15 candidate remains unauthorized until matching release and
  local evidence pass.
