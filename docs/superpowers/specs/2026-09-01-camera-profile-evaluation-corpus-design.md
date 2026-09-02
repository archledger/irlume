# Camera Profile Evaluation Corpus: Design

Status: superseded by `2026-09-01-camera-profile-release-qualification-design.md`
Date: 2026-09-01
Agent: opencode
Scope: Task 7 corpus protocol, private capture evidence, consent governance,
offline evaluation, and no-write reporting. No biometric collection, corpus
copy, hardware run, qualification write, or production selection is authorized
by this document.

This owner-local design is retained for history only. Do not implement it.

## Goal

Build a reproducible and privacy-bounded evaluation corpus system for comparing
an exact candidate camera profile with the current production profile through
detector, recognition, liveness, RGB PAD, IR PAD, scene, transport, restoration,
and latency gates.

The first implementation is an owner-only pilot. It validates the corpus
contract, collection protocol, evaluator, and reporting boundary, but cannot
authorize a machine-wide camera profile. A later authorizing corpus requires a
separately approved multi-participant and presentation-attack design.

This design refines the corpus portion of Task 7 in:

- `docs/superpowers/plans/2026-09-01-layered-camera-profile-engine.md`
- `docs/superpowers/specs/2026-09-01-layered-camera-profile-engine-design.md`
- `docs/adr/0020-layered-camera-profile-and-evidence-engine.md`

## Why Models Are Not Enough

The model files prove that Irlume can load a particular implementation. They do
not prove that a changed camera format, geometry, interval, conditioning policy,
capture schedule, preprocessing contract, or lighting context preserves the
expected decisions.

The corpus provides fixed inputs, protocol-derived expected outcomes, and exact
provenance. Qualification then answers whether a candidate profile preserves the
required model and security behavior instead of merely producing model output.

## Binding Constraints

- Security and model quality remain hard gates before USB demand or latency may
  rank a candidate.
- Public research data cannot provide consent authority for a local profile.
- One enrolled person's recognition score cannot authorize a machine-wide
  profile.
- Production enrollment is never read, modified, or used as the corpus
  reference source.
- Expected outcomes are frozen before candidate evaluation and are never
  inferred from candidate model output.
- Raw frames, crops, identities, templates, embeddings, and scores never cross
  the aggregate diagnostic callback into camera qualification.
- The example probe and owner pilot are no-write evidence producers.
- No corpus lane can write `ProfileSelectionRecord` or alter production
  behavior.
- Every persistent input is bounded, versioned, content-addressed, and validated
  after deserialization.
- Password fallback remains independent and unchanged.

## Vocabulary

**Protocol manifest**:
The signed, profile-independent declaration of cases, participant tokens,
reference/probe relationships, scenes, presentation kinds, and expected
outcomes. It contains no image assets or real identities.

**Capture manifest**:
A content-addressed record of assets captured for one exact profile and one
signed protocol. It binds each asset to the exact profile, camera context,
conditioning catalog, producer, and case.

**Consent ledger**:
The separately encrypted mapping from random participant tokens to consent
receipts, allowed uses, expiry, and withdrawal state.

**Public regression lane**:
Non-authorizing model-regression evidence consumed from the approved model
calibration campaign.

**Private local lane**:
Provenance-complete captures produced on the exact target camera profiles. In
schema 1 this lane is owner-pilot only.

**Legacy pilot shard**:
Selected owner assets imported for evaluator and importer development despite
missing the provenance required for profile authority.

## Evidence Lanes And Authority

### Public Regression Lane

Reuse the versioned protocols, provenance, and result artifacts from
`docs/superpowers/specs/2026-08-30-model-calibration-campaign-design.md`.

Research-license public datasets may reveal detector, recognition, liveness, or
PAD regressions. Their raw assets are not copied into the private local corpus.
Camera qualification consumes only the approved campaign protocol digest,
result digest, model-contract digest, and aggregate gate status.

This lane is always non-authorizing. It cannot compensate for a failed or
missing local gate.

### Private Local Lane

The private lane binds captures to exact baseline and candidate profiles. Its
schema-1 purpose is fixed to `owner_pilot`. The purpose is not a caller-selected
string and cannot be changed to an authorizing value.

The owner pilot may:

- validate import, signing, consent, capture, replay, and reporting;
- compare the current production and candidate profiles for the owner;
- expose scene-specific regressions and operational failures;
- produce evidence for a later corpus and policy review.

The owner pilot may not:

- create or replace profile-selection authority;
- claim population representativeness;
- satisfy a future multi-participant or attack-coverage requirement;
- alter enrollment or authenticate a request.

### Future Authorizing Corpus

An authorizing local corpus is a conceptual future stage, not a schema-1 value.
It requires a new accepted policy and schema version defining at least:

- cohort composition and a justified sample-size method;
- explicit participant consent and withdrawal handling;
- cross-identity no-match probes;
- separately consented presentation attacks;
- statistical acceptance and confidence rules;
- invalidation of any derived authority after consent withdrawal.

Until that follow-up is approved and implemented, selection writes remain
structurally blocked even when every pilot and public regression check passes.

## Artifact Model

The current uncommitted `ProfileEvaluationManifest` combines expected outcomes
with captured assets. Replace that shape before it becomes a persisted contract.
Schema 1 uses separate protocol and capture documents.

### Protocol Manifest

`ProfileEvaluationProtocolManifest` contains:

- schema version;
- protocol ID;
- fixed `owner_pilot` purpose;
- acceptance-policy version;
- bounded reference-set declarations;
- bounded ordered cases;
- expected model outcomes;
- creation metadata that carries no real identity;
- canonical SHA-256 digest.

Each reference-set declaration contains a stable reference-set ID and a random
participant token. It declares relationships only. Reference assets belong in
the capture manifest.

Each case contains:

- stable case ID;
- one of `lit`, `backlit`, `low_light`, or `dark_ir`;
- one of `genuine_live` or `no_face` in schema 1;
- optional random participant token;
- optional reference-set ID;
- fixed expected detection, recognition, liveness, RGB PAD, and IR PAD
  outcomes.

Protocol IDs, case IDs, reference-set IDs, and participant tokens are bounded,
portable identifiers. They contain no names, usernames, email addresses, device
paths, serials, or enrollment identifiers.

The canonical compact JSON bytes are signed with a detached GPG signature. The
runner verifies both the signature and an allowlisted signer fingerprint before
collection or evaluation. Pretty JSON is a derived view and is not the signed
authority.

### Expected Outcomes

Expected outcomes use closed enums:

| Stage | Values |
|---|---|
| Detection | `present`, `absent` |
| Recognition | `match`, `no_match`, `not_applicable` |
| Liveness | `live`, `spoof`, `not_applicable` |
| RGB PAD | `genuine`, `spoof`, `not_applicable` |
| IR PAD | `genuine`, `spoof`, `not_applicable` |

Cross-field validation is fail-closed:

- `no_face` requires detection `absent` and every downstream stage
  `not_applicable`.
- `genuine_live` requires detection `present`, recognition `match`, liveness
  `live`, and every policy-applicable PAD role `genuine`.
- Recognition `match` or `no_match` requires a reference-set relationship.
- A participant token is required for genuine cases and prohibited for no-face
  cases.
- Schema 1 rejects presentation kinds other than `genuine_live` and `no_face`.

This corrects the current inability to represent a detector-negative case
without falsely claiming that recognition or liveness ran.

### Capture Manifest

`ProfileEvaluationCaptureManifest` contains:

- schema version and capture ID;
- signed protocol digest;
- exact closed pair-transport profile ID and requested/accepted tuples;
- capture schedule;
- camera-pair and connection-context digest;
- conditioning-catalog and selected-policy digests;
- model-contract and preprocessing digests;
- producer and policy versions;
- capture start/end facts;
- bounded reference asset sets;
- bounded ordered case captures;
- per-asset relative path, role, media shape, sequence position, and SHA-256;
- canonical manifest digest.

After collection and asset verification, the canonical capture-manifest bytes
also receive a detached GPG signature from an allowlisted operator. Baseline and
candidate manifests are signed independently. Evaluation rejects an unsigned or
modified capture manifest.

Each case capture represents one complete attempt. A bounded asset sequence may
contain the lossless RGB and IR frames required by the existing canonical RGB
median and IR burst pipelines. Asset paths stay relative to the mounted vault
root.

Baseline and candidate capture manifests must bind the same signed protocol and
contain the same ordered case IDs. Their profile and capture provenance must be
independent; a candidate manifest cannot copy baseline provenance.

### Corpus Index And Sharding

One manifest remains bounded to 128 cases, 32 assets per role per case, and 256
KiB of serialized metadata. A future corpus that exceeds a bound uses a signed
`ProfileEvaluationCorpusIndex` containing an ordered list of shard digests.
Readers never silently concatenate arbitrary manifests or raise an unbounded
limit.

### Consent Ledger

The consent ledger lives separately in the encrypted offline vault and contains:

- monotonic revision and previous-revision digest;
- random participant token;
- real participant identity;
- consent receipt digest and storage location;
- permitted purposes and presentation types;
- collection date;
- expiry date, no later than one year after consent;
- withdrawal state and effective date;
- asset and manifest references needed for deletion and invalidation.

Each bounded canonical ledger revision receives a detached GPG signature. The
runner accepts only an explicitly supplied ledger head and verifies its signer
and revision chain before checking consent. Missing, modified, or disconnected
revisions fail closed. This makes pilot changes tamper-evident; a future
authorizing design must additionally define a rollback-resistant latest-revision
anchor before consent state can support durable authority.

The replay manifests bind participant tokens but never copy ledger PII. Before
collection and before every evaluation, the runner checks that each token is
active, unexpired, and permitted for the declared purpose and presentation.

A protocol signature does not override a later expiry or withdrawal. Current
ledger state always fails closed.

## Owner Pilot Capture Protocol

### Coverage

The pilot covers four required scenes:

- lit;
- backlit;
- low light;
- dark IR.

It covers only the presentations currently approved by the owner:

- genuine live;
- no face.

Each scene, presentation, and profile combination requires six complete
attempts. Each attempt is a distinct case capture, giving 48 case captures per
profile before reference assets:

`4 scenes * 2 presentations * 6 attempts = 48`

The six-attempt bound matches the established bounded hardware-probe round
count. It is a pilot engineering criterion, not a population confidence claim.

### Scene Authority

The operator establishes the physical scene before capture. The completed
evidence window must independently classify into the intended fixed scene using
the existing non-model `SceneStatistics` and conditioning catalog boundaries.

If the observed class differs from the protocol case, the capture is discarded
and repeated. The case is never relabeled after model output.

### Baseline And Candidate Ordering

Baseline and candidate attempts are interleaved in a deterministic balanced
order recorded in the capture session. They are not collected as separate long
blocks. This limits time-of-day, lighting, pose, and participant-fatigue drift.

Every switch must complete exact stream negotiation, conditioning application,
evidence capture, and conditioning restoration. A restoration or context failure
aborts the session rather than advancing to the next case.

### Recognition References

The protocol designates separate owner reference captures. Evaluation builds
test-only templates from those reference assets in memory. Candidate probes use
the same logical reference set as baseline probes.

These templates:

- are not production enrollment;
- are never written to the enrollment store or corpus;
- carry no grant authority;
- do not cross the diagnostic callback;
- are destroyed after the run.

### Collection Command

Collection is initiated only by an explicit offline daemon-owned command. The
command requires:

- explicit RGB and IR devices;
- explicit baseline and candidate profile IDs;
- signed protocol path;
- mounted vault root;
- explicit operator confirmation;
- no-write qualification mode.

The command cannot write profile-selection state, authenticate, enroll, update a
template, or fall back to production enrollment.

Design approval does not authorize running this command or touching hardware.

## Legacy Owner Pilot Import

`/home/wisbfime/irlume-suncal` contains useful owner capture scenarios,
including varied lighting, distance, no-face, and presentation material, with
some paired RGB/IR bursts. Its observed metadata predates the Task 7 authority
contract and does not establish all exact requested/accepted profile,
conditioning, camera-context, model-contract, and per-asset manifest facts.

Use only a user-reviewed subset of owner assets to exercise importer and runner
behavior. Imported manifests carry an immutable `legacy_pilot` classification
and can never satisfy profile provenance or selection gates.

The import flow is:

1. Inventory metadata without displaying or modifying image content.
2. Exclude every apparent non-owner asset unless separate consent is documented.
3. Present the proposed owner-only subset for explicit review.
4. Copy approved assets into vault staging.
5. Compute and verify per-asset SHA-256 digests.
6. Create a non-authorizing legacy capture manifest.
7. Leave every source file untouched.
8. Consider source deletion only in a separate explicit destructive review.

No missing provenance is inferred from filenames, timestamps, old model scores,
or current machine state.

## Evaluation Flow

Evaluation is ordered and fail-closed:

1. Mount the frozen corpus read-only.
2. Verify the detached protocol and capture-manifest signatures and allowlisted
   signer fingerprints.
3. Parse and validate the bounded protocol and capture manifests.
4. Check current consent eligibility and expiry for every participant token.
5. Verify every asset digest before decoding any asset.
6. Require exact baseline/candidate protocol and case parity.
7. Require exact profile, context, conditioning, producer, preprocessing, and
   model-contract provenance.
8. Build ephemeral reference templates from designated reference assets.
9. Run assets through the same canonical evidence and typed model-input
   contracts used by Irlume.
10. Reduce each result immediately to expected-outcome booleans.
11. Destroy temporary templates and biometric model intermediates.
12. Evaluate the public regression result independently by its approved protocol
    and result digests when those campaign artifacts exist. Their absence marks
    the composite pilot incomplete but does not discard a valid local report.
13. Emit a bounded identity-free no-write report.

There is no fallback to legacy assets, unsigned labels, production enrollment,
stale consent, a different profile, or a partially matching case set.

## Pilot Acceptance Policy

The pilot uses asymmetric acceptance because security-direction failures and
genuine-user availability failures have different consequences. The policy is
still non-authorizing.

### Security Direction

Zero wrong-direction outcomes are tolerated in the fixed suite.

For schema 1, every no-face attempt must remain detection-absent. A false
detection fails the no-face gate for that candidate and scene.

Future schemas must apply the same zero-tolerance rule to cross-identity false
matches and presentation attacks classified as genuine or live.

### Genuine Availability

For each required scene and each applicable detector, recognition, liveness,
RGB PAD, and IR PAD gate:

- the candidate must produce at least five correct outcomes out of six; and
- the candidate correct count must be greater than or equal to the production
  baseline count for the same scene and gate.

Counts are predeclared, reported exactly, and never converted into a population
accuracy claim. Passing this pilot rule does not create profile authority.

### Independent Hard Gates

Exact negotiation/readback, transport, delivered rate, continuity, camera
context, conditioning application/restoration, scene applicability, p50/p95
latency, and model/catalog digest gates remain independently required.

A public regression pass cannot compensate for a failed local or hardware gate.

## Reporting Boundary

The no-write report may contain:

- protocol, capture, public-result, model-contract, and catalog digests;
- bounded profile and policy IDs;
- scene and presentation categories;
- case denominators and aggregate correct counts;
- gate status and failure reason;
- p50/p95 timing summaries;
- exact provenance-validation status.

The report must not contain:

- real or pseudonymous participant identity;
- consent receipt contents;
- raw or absolute asset paths;
- device serials in share-safe output;
- frames, crops, tensors, templates, embeddings, or model scores;
- enrollment handles or authentication decisions.

The existing aggregate-only `DiagnosticAuthAssessmentCallback` remains the
boundary into camera qualification. It receives no biometric values and has no
store handle.

## Vault And Privacy Lifecycle

### Storage

The private corpus resides only on encrypted offline or removable storage. It
is outside:

- the source repository;
- production daemon state;
- production enrollment state;
- general benchmark data roots;
- unencrypted backups;
- share-safe support artifacts.

Collection writes into a staging area with owner-only permissions and a
restrictive umask. After asset and manifest verification, the corpus is frozen
and evaluation mounts it read-only.

The qualifier performs no network access during private corpus evaluation. It
disables core dumps where supported and does not persist model intermediates.

### Distribution

After an asset is admitted to the private corpus, its raw or derived biometric
content never leaves the encrypted vault. Pre-existing legacy source files stay
outside the corpus and remain untouched pending a separate deletion review.
Only identity-free aggregate results and cryptographic digests may enter the
repository or reports.

### Expiry And Withdrawal

Raw local captures expire no later than one year after consent. A participant
may choose an earlier expiry.

On every vault mount, expired or withdrawn tokens become immediately
ineligible. Purging is an explicit reviewed operation because offline storage
cannot guarantee automatic deletion while unmounted.

Withdrawal invalidates every protocol, capture manifest, result, and future
authority that references the participant. A new protocol excluding that token
must be signed before another run. Schema 1 creates no authority, so withdrawal
invalidates pilot evidence only.

### Filesystem Safety

Asset readers reject:

- absolute paths;
- parent traversal and nonportable components;
- control characters and oversized path fields;
- symlinks;
- non-regular files;
- files outside the canonical mounted vault root;
- oversized assets;
- duplicate paths;
- SHA-256 mismatch.

Validation occurs before decoding and before allocating model inputs.

## Failure Handling

Any of the following makes the run incomplete and non-authorizing:

- unsupported or malformed schema;
- invalid or untrusted signature;
- stale, expired, missing, or withdrawn consent;
- protocol/capture/public-result digest mismatch;
- missing, duplicate, extra, modified, or unsafe assets;
- baseline/candidate case mismatch;
- requested/accepted profile drift;
- camera context, catalog, conditioning, preprocessing, or model-contract drift;
- scene classification mismatch;
- incomplete reference set;
- impossible expected-outcome combination;
- decode, preprocessing, inference, restoration, or timing failure;
- missing applicable PAD evidence;
- an inconclusive capture or context change.

Failure produces a bounded reason and no authority. It does not mutate labels,
skip the case, weaken a denominator, or retry with production enrollment.

## Verification

All software tests use synthetic, non-biometric fixtures.

### Protocol And Signature Tests

- valid canonical protocol, capture manifests, and detached signatures;
- untrusted signer, modified bytes, missing signature, and malformed signature;
- unsupported schema and unknown fields;
- bounded IDs, cases, references, shards, and serialized size;
- deterministic canonical digest;
- duplicate IDs and invalid participant/reference relationships;
- detection-absent downstream N/A enforcement;
- schema-1 rejection of unsupported presentation kinds or authority purposes.

### Consent Tests

- active consent permits only its declared pilot purpose and presentation;
- unsigned, modified, disconnected, or non-monotonic ledger revisions fail;
- expired, withdrawn, missing, or mismatched consent fails before asset access;
- one-year maximum retention is enforced;
- withdrawal invalidates every referencing manifest and result;
- no PII enters protocol, capture, result, or diagnostic fixtures.

### Capture And Filesystem Tests

- exact protocol, profile, context, catalog, producer, and model digest binding;
- baseline/candidate ordered case parity;
- reference and probe asset completeness;
- path traversal, symlink, non-regular file, root escape, duplicate, size, and
  digest rejection;
- interrupted staging never appears as a frozen corpus;
- legacy imports remain permanently non-authorizing.

### Evaluation And Acceptance Tests

- ephemeral reference creation and cleanup;
- no production enrollment or grant handle reaches the evaluator;
- no identity, path, image, template, embedding, or score reaches result DTOs;
- zero-tolerance no-face boundary;
- genuine `5/6` floor boundary;
- candidate equal-to-baseline and candidate-below-baseline boundaries;
- missing or inconclusive evidence fails closed;
- public regression evidence remains separate and non-authorizing;
- identity-free deterministic report projection.

### Hardware Gates

Hardware tests remain declared ignored until separately authorized. A later
owner-pilot run must preserve and restore daemon, camera controls, emitter
state, qualification stores, installed binaries, and production selection.

## Alternatives Rejected

### One Mixed Public And Local Corpus

Rejected because one aggregate result could obscure consent provenance and let
non-authorizing research data appear to satisfy local profile authority.

### Live Recapture Without Retained Assets

Rejected because it prevents reproducible replay after model, preprocessing, or
policy changes and weakens auditability. The encrypted offline vault provides a
bounded retention compromise.

### Production Enrollment As Recognition Reference

Rejected because it couples qualification to personal production state, cannot
represent a population, and would give a diagnostic evaluator access to
enrollment authority.

### Model-Generated Ground Truth

Rejected because it makes the implementation under test define its own expected
outcomes and cannot detect inherited model errors.

### Self-Declared Authorizing Purpose

Rejected because a manifest flag cannot prove cohort composition, consent,
attack coverage, or statistical adequacy. A future authorizing corpus requires a
new accepted policy and schema.

## Delivery Phases And User Gates

1. Revise the uncommitted schema into signed protocol and capture contracts.
2. Implement synthetic-fixture validation, consent eligibility, filesystem
   safety, and no-write aggregation tests.
3. Implement the offline evaluator and identity-free report with no hardware.
4. Present a metadata-only proposed owner subset from `irlume-suncal`.
5. Obtain explicit approval before creating or mounting a vault or copying any
   biometric asset.
6. Import the approved owner subset as a legacy pilot shard without deleting
   sources.
7. Obtain explicit approval before any fresh camera capture.
8. Capture the fresh owner baseline/candidate pilot and produce a no-write
   report.
9. Review evidence. Do not begin Task 8 or enable selection.
10. If an authorizing corpus is still desired, design and approve the separate
    cohort, presentation, consent, and statistical policy first.

Each data copy, hardware action, destructive deletion, qualification write, and
production change remains an independent explicit user gate.

## Success Criteria

- The protocol and capture contracts are separate, bounded, signed or
  content-addressed as appropriate, and fail closed.
- Expected outcomes are protocol-derived and frozen before evaluation.
- No-face semantics cannot falsely claim downstream inference.
- Recognition uses ephemeral test-only references, never production enrollment.
- Public regression and private local evidence remain separate.
- Owner legacy data remains non-authorizing and source files remain untouched.
- Consent expiry and withdrawal invalidate affected evidence.
- The owner pilot covers six attempts for genuine and no-face cases in lit,
  backlit, low-light, and dark-IR scenes for baseline and candidate profiles.
- The pilot applies zero security-direction tolerance and the predeclared
  availability comparison without claiming population accuracy.
- Reports are reproducible from digests and contain no biometric or identity
  material.
- All runnable synthetic software tests pass; hardware tests remain ignored
  until authorized.
- No profile-selection record, production behavior, enrollment, service,
  hardware, or source biometric data changes merely because this design or its
  software implementation exists.
