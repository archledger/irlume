# Camera Profile Release Qualification: Design

Status: software-only authority design implemented and independently approved;
campaign and production integration remain separate
Date: 2026-09-01
Agent: opencode
Scope: Task 7 release qualification authority, local non-biometric commissioning,
and profile-selection evidence. No corpus collection, biometric access, hardware
run, qualification write, or production change is authorized by this document.

Supersedes:

- `docs/superpowers/specs/2026-09-01-camera-profile-evaluation-corpus-design.md`
- `docs/superpowers/plans/2026-09-01-camera-profile-evaluation-corpus-software.md`

Amends:

- `docs/superpowers/specs/2026-09-01-layered-camera-profile-engine-design.md`
- `docs/superpowers/plans/2026-09-01-layered-camera-profile-engine.md`
- `docs/adr/0020-layered-camera-profile-and-evidence-engine.md`

Decision record:

- `docs/adr/0021-release-qualified-camera-profile-evidence.md`

Campaign design:

- `docs/superpowers/specs/2026-09-02-camera-profile-maintainer-qualification-campaign-design.md`

## Goal

Qualify camera profile changes without making end users create, retain, or
govern a local face corpus.

Maintainers evaluate biometric behavior before release. Irlume distributes only
a signed aggregate qualification artifact. A target machine independently
commissions its camera transport without collecting faces. Profile selection
requires both evidence classes and fails closed to the conservative profile or
an already-qualified sequential fallback.

## Why The Design Changed

Apple Face ID and Windows Hello do not ask users to curate qualification data.
Their enrollment flows create device-local matching references, while vendors
validate security and availability before release.

Apple publishes a random-person false-match claim below one in one million and
describes depth-based anti-spoofing. Microsoft requires Windows Hello facial
recognition FAR below 0.001 percent and TAR above 95 percent. Microsoft also
documents that establishing 0.001 percent FAR at 96 percent confidence requires
2.5 million comparisons and about 2,237 unique biometric samples.

Sources:

- https://support.apple.com/en-us/102381
- https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-biometric-requirements

One owner's A/B captures can expose a local availability regression, but they
cannot establish population FAR, TAR, cross-identity behavior, or presentation-
attack resistance. Requiring that owner to maintain a corpus would add privacy,
consent, retention, signing, and deletion machinery without producing the
evidence needed for profile authority.

The unshipped owner-pilot protocol is therefore retired rather than maintained
as a second evidence system.

## Binding Constraints

- End users never create or manage a camera profile evaluation corpus.
- Normal enrollment remains the only user-facing biometric collection flow.
- Production enrollment is never read by release qualification or local
  commissioning.
- Release qualification and enrollment are separate trust domains.
- Local commissioning uses no faces, templates, embeddings, identities, model
  scores, or authentication decisions.
- Security and model-quality gates remain hard gates. Payload and latency rank
  only candidates that pass them.
- A local transport pass cannot replace missing release qualification.
- A release qualification pass cannot replace failed local commissioning.
- Missing, stale, unsigned, mismatched, or incomplete evidence creates no
  profile-selection authority.
- Password fallback and the current conservative capture path remain available.
- No design or software-only test authorizes a hardware run or production write.

## Vocabulary

**Release qualification campaign**:
A maintainer-controlled evaluation of one baseline and one or more candidate
profiles against approved biometric regression and presentation-attack
protocols. It may combine public model-regression datasets with private,
profile-bound lab captures.

**Release qualification artifact**:
The bounded, canonical, signed, aggregate-only result distributed with Irlume.
It contains no corpus assets, identities, templates, embeddings, or model
scores.

**Local commissioning**:
On-device, non-biometric measurement of an exact camera pair, requested and
accepted tuples, schedule, delivered rate, continuity, signal sanity, latency,
conditioning application, and restoration.

**Enrollment**:
The existing user flow that creates production authentication references. It
does not qualify camera profiles.

**Profile-selection authority**:
The combination of a valid release qualification artifact and fresh matching
local commissioning evidence for one exact candidate profile.

## Authority Layers

### Release Qualification

Maintainers qualify supported camera/profile combinations before release. The
campaign must test the same canonical evidence and typed model-input contracts
used by Irlume.

Public datasets may exercise profile-independent model regression. They cannot
substitute for private lab captures produced through the exact baseline and
candidate camera profiles being compared.

Applicable gates include:

- detection;
- recognition, including genuine and cross-identity comparisons;
- liveness;
- RGB PAD;
- IR PAD;
- end-to-end latency;
- exact preprocessing and model-contract parity.

The campaign policy defines cohort composition, presentation attacks, expected
outcomes, thresholds, sample-size method, confidence requirements, and
invalidation rules. Those governance details belong to maintainer campaign
documentation, not the installed product or user setup.

Raw private campaign assets stay in maintainer-controlled encrypted storage.
Public research data remains subject to its license. Neither asset class ships
with the qualification artifact.

### Local Commissioning

Local commissioning checks the physical machine without collecting a face. It
measures:

- exact requested and driver-accepted RGB and IR tuples;
- capture schedule and endpoint roles;
- delivered frame rate and continuity;
- concurrent establishment or sequential operation;
- bounded RGB and IR signal sanity without face inference;
- camera context and connection topology;
- conditioning application and exact restoration;
- p50 and p95 capture-path latency;
- runtime degradation compatibility.

Commissioning binds evidence to the exact physical pair and current connection
context. It cannot set detection, recognition, liveness, or PAD gates.

The commissioning procedure requires a non-human scene, such as a diffuse test
target. Frames remain process-local, are dropped after bounded signal and timing
statistics are computed, and never produce a persisted image, crop, template,
embedding, model score, or authentication decision.

### Enrollment And Authentication

Enrollment and authentication keep their existing responsibilities. They do
not read release corpus assets, campaign records, or commissioning internals.

Enrollment output cannot become qualification evidence. Qualification tooling
cannot read or update enrollment, authenticate a request, release a credential,
or construct an authentication grant.

## Signed Release Qualification Artifact

The canonical artifact is a bounded versioned document. Schema 1 contains:

- schema version;
- qualification policy version;
- producer version;
- campaign protocol digest;
- campaign result digest;
- bounded campaign identifier;
- qualification timestamp and optional expiry;
- hardware-scope match-policy version;
- camera vendor and product identifiers;
- role and interface-layout digest;
- driver family and connection-class constraints when policy-relevant;
- exact baseline profile ID and requested and accepted RGB and IR tuples;
- exact candidate profile ID;
- exact candidate requested and accepted RGB and IR tuples;
- exact capture schedule;
- conditioning catalog and selected-policy digests;
- preprocessing and model-contract digests;
- aggregate detection, recognition, liveness, RGB PAD, IR PAD, and latency
  dispositions;
- detached-signature metadata.

The artifact does not contain:

- names, usernames, participant tokens, or enrollment identifiers;
- raw or derived corpus paths;
- images, crops, tensors, templates, or embeddings;
- per-person or per-case model scores;
- consent receipts or private campaign metadata;
- device serial numbers.

The canonical compact bytes receive a detached signature from an allowlisted
maintainer key. Verification requires the full signer fingerprint. A short key
ID, trust status, filename, package ownership, or successful JSON parse is not
enough.

Signature metadata inside the signed document identifies the algorithm and full
signer fingerprint. Signature bytes remain in the detached signature file.

## Version Evolution

Schema 1 is closed: unknown fields and unknown enum values fail validation.
Artifact fields should remain additive in the source model where practical, but
an emitted wire field that an older parser cannot validate requires a schema
version increment. Shape changes, canonicalization changes, and changed field
meaning also require a schema version increment.

A policy version increment covers meaningful changes to required gates,
thresholds, cohort rules, statistical confidence, hardware matching, freshness,
or invalidation while the wire shape remains unchanged. Producer version records
which implementation emitted the artifact but never substitutes for schema or
policy compatibility.

Older consumers reject unsupported schema and policy versions and keep the
conservative profile. They never ignore an unknown authority field to preserve
forward compatibility.

## Hardware Scope

Release qualification applies to a declared hardware class, not one user's
serial-numbered device. The match policy identifies the camera model and every
hardware or software fact that can affect the qualified pipeline.

Local commissioning proves that the target pair:

- belongs to the artifact's declared hardware scope;
- exposes the exact requested tuples;
- accepts the exact qualified tuples;
- uses the qualified schedule;
- satisfies all local non-biometric gates;
- matches the bound catalog, preprocessing, model, producer, and policy
  versions.

If firmware, endpoint layout, driver behavior, connection context, or another
policy-bound fact changes, the evidence no longer matches. The profile is not
silently generalized to a nearby camera model or tuple.

Unsupported and user-supplied cameras may continue through existing
conservative capture qualification. They cannot receive an optimized profile
without a matching release artifact.

## Selection Flow

Selection is ordered and fail closed:

1. Load the allowlisted maintainer public key from the trusted package path.
2. Read the bounded artifact and detached signature.
3. Verify the signature and exact full fingerprint.
4. Parse and validate the canonical artifact.
5. Match schema, policy, producer, campaign, model, preprocessing, and catalog
   versions.
6. Match the declared hardware scope.
7. Load fresh local commissioning evidence for the exact physical pair.
8. Match the baseline and candidate profiles, requested and accepted tuples,
   schedule, context, and local gates.
9. Require every applicable release gate and local gate to pass.
10. Rank only fully qualified candidates by the existing balanced payload and
    latency policy.
11. Persist profile selection only through the separate revision-CAS store.

Any failure retains the existing conservative selection or an already-qualified
sequential fallback. Selection never retries with enrollment data, an unsigned
artifact, a nearby profile, or partial gate coverage.

## Invalidation

The artifact becomes ineligible when any bound fact changes, including:

- artifact schema or policy support;
- signature or signer;
- campaign protocol or result digest;
- hardware-scope match policy;
- camera model or interface layout;
- baseline or candidate profile;
- baseline or candidate requested or accepted stream tuple;
- capture schedule;
- conditioning catalog or selected policy;
- preprocessing contract;
- model contract;
- producer version;
- explicit expiry.

Local commissioning becomes ineligible when its physical pair, connection
context, accepted tuple, schedule, catalog, or freshness policy changes.

An artifact revocation mechanism may be added later as a separately designed
signed release input. Schema 1 does not invent online revocation or network
dependency.

## Failure And Diagnostics

Safe diagnostics report categorical failures only:

- `artifact_missing`;
- `artifact_too_large`;
- `artifact_schema_unsupported`;
- `signature_missing`;
- `signature_invalid`;
- `signer_untrusted`;
- `artifact_expired`;
- `hardware_scope_mismatch`;
- `baseline_profile_mismatch`;
- `profile_tuple_mismatch`;
- `camera_context_mismatch`;
- `model_digest_changed`;
- `preprocessing_digest_changed`;
- `conditioning_digest_changed`;
- `commissioning_missing`;
- `commissioning_stale`;
- `release_gate_failed`;
- `local_gate_failed`.

Diagnostics never include third-party error strings, corpus details, model
scores, identities, serial numbers, or absolute paths.

A qualification failure does not corrupt enrollment, disable password fallback,
or turn a candidate profile into a partial authority record.

## Verification

### Synthetic Contract Tests

- canonical artifact round trip and deterministic digest;
- document, identifier, list, and string bounds;
- unknown-field and unsupported-version rejection;
- invalid, missing, short-ID, and wrong-fingerprint signatures;
- modified artifact and signature rejection;
- exact requested and accepted tuple reconstruction;
- exact baseline and candidate binding;
- hardware-scope mismatch;
- model, preprocessing, catalog, policy, and producer drift;
- expiry boundaries;
- aggregate-only serialization and safe error projection;
- no enrollment or authentication authority in artifact APIs.

### Selection Tests

- release pass plus local pass permits candidate ranking;
- either evidence class missing or failed prevents candidate ranking;
- stale local commissioning prevents selection;
- optimized unsupported-camera profiles remain unavailable;
- conservative selection and sequential fallback remain intact;
- revision-CAS publication rejects stale writers;
- deserialization revalidates every nested authority fact.

### Campaign Gates

Maintainer-only campaign verification covers the approved biometric protocols,
population method, presentation attacks, final model decisions, and end-to-end
latency. Passing software unit tests does not satisfy campaign gates.

### Hardware Gates

Hardware tests measure only commissioning and artifact-to-device matching. They
remain ignored until separately authorized. No hardware test reads enrollment or
collects qualification faces from the end user.

## Migration From The Unshipped Owner Pilot

The owner-pilot contracts have no released consumer or persisted data. Remove
them directly rather than adding deprecation adapters.

The implementation plan must:

1. discard the uncommitted Task 3 capture-manifest work;
2. remove `ProfileEvaluationProtocolManifest` and its owner-pilot enums and
   tests from the unshipped Task 2 surface;
3. keep shared `QualificationScene` in the profile domain;
4. retain the useful offline qualification, deterministic selection, and secure
   revision-CAS store core from Task 1;
5. replace `evaluation_manifest_digest` authority with a release-qualification
   artifact digest and validated artifact reference;
6. add the signed artifact parser and verifier using synthetic fixtures;
7. separate release-gate evidence from local commissioning evidence in types;
8. prove neither side can construct the other's evidence;
9. keep every profile-selection writer disconnected until the full combined
   authority path is reviewed.

The superseded design and plan remain in Git history and carry explicit
supersession notices. No compatibility code is required for unshipped schema 1.

## Alternatives Rejected

### Release Qualification Plus Owner-Local Pilot

Rejected because the owner pilot adds consent, retention, signing, deletion,
and biometric-storage machinery without supporting population security claims.
Its local availability signal does not justify a second product evidence lane.

### Owner-Local Corpus As Profile Authority

Rejected because one participant cannot establish FAR, TAR, cross-identity
behavior, presentation-attack resistance, or machine-wide security.

### No Biometric Qualification Anywhere

Rejected because transport stability alone cannot show that a changed profile
preserves detection, recognition, liveness, or PAD behavior. Under this option,
new optimized profiles could never become production authority.

### Production Enrollment As Evaluation Data

Rejected because it couples qualification to personal production state, grants
diagnostic code access to enrollment authority, and still does not produce
population evidence.

### Runtime Confidence-Based Profile Selection

Rejected because attacker-influenced model outputs could steer capture policy
and move the security operating point during authentication.

## Delivery Phases And Gates

1. Remove the unshipped owner-pilot surface and restore a clean branch.
2. Define bounded signed release-artifact contracts with synthetic tests.
3. Split release evidence from local commissioning evidence in the authority
   core.
4. Add fail-closed combined selection tests without a production writer.
5. Design and approve the maintainer campaign protocol, corpus governance, and
   statistical policy separately.
6. Produce a synthetic signed artifact fixture and package-path verification.
7. Obtain explicit approval before any real campaign data, hardware run, or
   artifact publication.
8. Review aggregate campaign and commissioning evidence.
9. Wire a selection writer only after a separate production review.

Each biometric-data operation, hardware action, signer change, artifact
publication, qualification write, and production change remains an independent
user gate.

## Success Criteria

- No end-user workflow creates or retains a qualification corpus.
- Enrollment remains independent from qualification and commissioning.
- Release artifacts are bounded, canonical, signed, aggregate-only, and exact-
  scope.
- Local commissioning is non-biometric and cannot construct release gates.
- Release evidence cannot construct local hardware evidence.
- Selection requires both evidence classes for the exact profile and context.
- Missing or mismatched evidence retains conservative behavior.
- Unsupported cameras cannot receive unqualified optimized profiles.
- The owner-pilot protocol, consent ledger, local vault, legacy import, and
  capture-manifest lanes are removed from the active design.
- Synthetic tests cover contracts and authority boundaries.
- Real campaign, hardware, writer, and production actions remain separately
  gated.
