# Camera Profile Maintainer Qualification Campaign: Design

Status: approved design; artifact-authority correction approved;
Delivery Phases 2 and 3 planned in
`docs/superpowers/plans/2026-09-02-camera-profile-maintainer-qualification-contracts.md`
Date: 2026-09-02
Agent: opencode
Scope: generic maintainer campaign contracts, governance, paired statistical
policy, review authority, and aggregate artifact production. This document does
not authorize recruitment, biometric access, vault creation, hardware capture,
release signing, artifact publication, packaging, local commissioning, profile
selection writes, or production changes.

Amends:

- `docs/superpowers/specs/2026-09-01-camera-profile-release-qualification-design.md`
- `docs/adr/0021-release-qualified-camera-profile-evidence.md`

Decision record:

- `docs/adr/0022-sealed-maintainer-qualification-campaign.md`

## Goal

Define a reusable maintainer-controlled campaign framework that can determine
whether one exact candidate camera profile is non-inferior to one exact baseline
profile without shipping or exposing campaign biometrics.

One campaign evaluates one hardware class and one baseline/candidate pair. It
freezes labels, cohort composition, attacks, ordering, operating points,
statistical margins, software, models, and exclusions before authorizing
capture. A deterministic evaluator produces an identity-free aggregate. A
distinct reviewer verifies the sealed evidence before an isolated compiler may
prepare the existing schema-1 release qualification artifact.

The framework supports many independent campaigns. Evidence from one campaign
never generalizes to a nearby camera, profile, tuple, schedule, conditioning
policy, preprocessing contract, model contract, or software revision.

## Evidence Basis And Claim Boundary

This design uses established biometric testing concepts without claiming
certification:

- FIDO Biometrics Requirements 4.0 fixes biometric operating points during
  testing, reports IAPAR per PAI species, separates bona fide and attack
  performance, defines test-crew composition, and requires privacy-protecting
  reports.
- ISO/IEC 19795 and ISO/IEC 30107 terminology, as summarized by FIDO, separates
  mated, non-mated, bona fide, and presentation-attack trials.
- NIST IR 8280 demonstrates that face-recognition error behavior must be
  examined across demographic groups rather than only as one pooled rate.
- Microsoft's Windows Hello requirements illustrate why absolute low-FAR
  population claims require millions of comparisons and thousands of unique
  samples.
- Matched-pair non-inferiority literature treats a predeclared confidence bound
  on the paired response-rate difference as the relevant decision, rather than
  comparing two unrelated point estimates.

The campaign claim is narrower than certification. It states that changing one
exact camera profile did not produce a disallowed paired regression under the
approved protocol. It does not establish a new absolute FAR, TAR, PAD
certification, demographic fairness certification, or protection against attack
classes outside the protocol.

Primary references:

- https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.0-fd-20240522.html
- https://doi.org/10.6028/NIST.IR.8280
- https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-biometric-requirements
- https://doi.org/10.1002/sim.1012
- https://doi.org/10.1080/10543406.2024.2390888

## Binding Constraints

- End users never create, manage, or contribute a release qualification corpus.
- Production enrollment is never read, copied, modified, or used as a campaign
  reference source.
- Campaign tooling cannot authenticate, release a credential, enroll a user,
  write profile selection, or mint verified release evidence.
- Security and model-quality outcomes are hard gates. Payload and latency may
  rank only profiles that pass every gate.
- Labels, expected outcomes, cohort strata, attack species, operating points,
  margins, sample size, stopping rules, exclusions, and software are frozen
  before authorizing capture.
- Baseline and candidate inputs are paired within the same participant or PAI,
  scene, expected outcome, and bounded collection block.
- Candidate results never define ground truth or alter the protocol.
- No stage may construct the authority output of a later stage.
- A passing evaluator result without independent review creates no artifact.
- A reviewed aggregate without explicit release signing and publication creates
  no installed authority.
- Raw private assets and biometric intermediates never enter source control,
  packages, support output, or the release qualification artifact.
- Missing, malformed, stale, incomplete, mismatched, or withdrawn evidence fails
  closed.
- Software-only success does not authorize recruitment, biometrics, hardware,
  signing, publication, commissioning, or production integration.

## Vocabulary

**Campaign policy**:
The versioned maintainer rules that fix cohort, attack, statistical, retention,
review, and invalidation requirements. An operator cannot weaken policy through
a campaign protocol.

**Campaign protocol**:
A signed campaign-specific declaration applying one campaign policy to one
exact hardware scope and baseline/candidate profile pair before capture. The
hardware scope includes the release artifact's exact identity-free endpoint
contracts, not only class and descriptor digests.

**Private campaign bundle**:
The frozen, encrypted, content-addressed biometric assets, manifests, consent
eligibility snapshot, and audit records for one campaign.

**Private case transcript**:
The deterministic vault-local record of per-case validation and model outcomes.
It may contain campaign-scoped participant tokens and bounded internal values
needed for independent review.

**Public aggregate result**:
The identity-free canonical projection containing only denominators, aggregate
counts, confidence bounds, latency summaries, dispositions, and predecessor
digests.

**Review attestation**:
A distinct reviewer's signed decision binding the frozen inputs, evaluator,
private transcript, public aggregate, policy checks, and approval outcome.

**Reviewed aggregate**:
A canonical envelope binding one passing public aggregate result to its valid
matching independent review attestation. Its digest is the release artifact's
campaign result digest. The opaque reviewed authority also retains the exact
validated protocol used during assembly so later compilation cannot infer or
accept replacement target contracts.

**Publication boundary**:
The point at which a reviewed aggregate becomes an immutable released fact.
Later participant withdrawal removes retained assets and future use, not the
already published identity-free fact.

## Architecture And Authority

The workflow is one-way:

```text
campaign policy
  -> signed campaign protocol
  -> collection eligibility snapshot
  -> frozen private campaign bundle
  -> evaluation eligibility snapshot
  -> deterministic private transcript and public aggregate
  -> publication eligibility snapshot
  -> independent review attestation
  -> reviewed aggregate envelope
  -> canonical unsigned release artifact
  -> detached release signature and publication
```

### Authority Matrix

| Stage | May read | May emit | Must not do |
|---|---|---|---|
| Policy authoring | Approved standards and repository contracts | Campaign policy | Read biometrics or declare a campaign pass |
| Protocol authoring | Policy and exact target contracts | Signed campaign protocol | Capture, evaluate, or change policy |
| Collection | Protocol, eligibility snapshot, hardware | Staging assets and capture manifests | Evaluate, review, compile, sign, enroll, or authenticate |
| Freeze | Staging bundle | Frozen private bundle | Repair missing evidence or alter labels |
| Evaluation | Frozen bundle and exact software | Private transcript and public aggregate | Change inputs, review itself, or create artifact authority |
| Review | Frozen bundle, both results, policy, software | Signed pass/fail attestation | Edit inputs, results, labels, margins, or denominators |
| Aggregate assembly | Validated protocol, passing public aggregate, and attestation | Opaque reviewed authority and canonical envelope | Change any reviewed input or declare release authority |
| Artifact compilation | Opaque reviewed authority and intended release signer fingerprint | Canonical unsigned artifact bytes | Accept caller-supplied target contracts or access vault, biometrics, release key, or selection store |
| Release signing | Exact compiler bytes and publication approval | Detached signature | Recompute or repair campaign results |
| Product verification | Packaged artifact, signature, allowlisted public key | Opaque verified release evidence | Access campaign data or infer missing authority |

The campaign operator and reviewer must have distinct full signing
fingerprints. The release key is a role-specific allowlisted key that never
enters the biometric vault. A reviewer may reject a campaign but cannot waive a
gate or edit a result.

## Versioned Documents

Every document uses a closed schema, compact canonical JSON, bounded fields,
unknown-field rejection, and a deterministic SHA-256 digest. Each metadata
document is limited to 256 KiB. Larger case sets use ordered signed indexes and
bounded shards rather than raised parser limits.

All signatures are detached OpenPGP signatures verified against exact full
fingerprints assigned to protocol-author, operator, reviewer, or release roles.
Trust-database status and short key IDs are not authority.

### Campaign Policy

The policy contains:

- schema and policy versions;
- policy identifier and canonical digest;
- target-population and permitted hardware-class rules;
- required demographic and operational stratification axes;
- required bona fide, no-face, non-mated, and 2D PAI classes;
- fixed expected-outcome vocabulary;
- paired collection and order-balancing rules;
- security hard-gate definitions;
- matched-pair non-inferiority method and margins;
- confidence, power, sample-size, and stopping rules;
- latency method and budget relationship;
- missingness and bounded-repeat rules;
- protocol, bundle, result, review, and artifact expiry rules;
- one-year absolute private-asset retention ceiling;
- publication-boundary withdrawal semantics;
- role separation and signer policy;
- safe public projection version;
- minimum public stratum cell size;
- invalidation rules.

Policy values are not caller options. A changed method, margin, attack minimum,
stratum rule, or lifecycle rule requires a new policy version.

### Campaign Protocol

The signed protocol contains:

- schema version, campaign ID, policy ID, and policy digest;
- planned creation, collection, evaluation, review, and expiry bounds;
- exact source revision and evaluator build identity;
- exact identity-free hardware scope and match-policy version, including RGB
  and IR descriptor digests, VID, PID, interface number, driver, backend, and
  link speed;
- exact baseline and candidate profile contracts, including requested and
  accepted RGB and IR tuples and schedules;
- exact conditioning catalog and selected-policy digests;
- exact preprocessing, model, producer, and threshold-contract digests;
- fixed biometric operating points;
- target-population definition;
- predeclared demographic and operational strata with required counts;
- mated, non-mated, no-face, scene, and PAI case matrices;
- PAI production methods and instrument identifiers that reveal no identity;
- campaign-scoped reference and probe relationships;
- deterministic balanced ordering seed;
- pilot-estimated discordance inputs and locked authorizing sample sizes;
- exact confidence, power, margins, stopping rule, and attempt caps inherited
  from policy;
- allowed pre-outcome equipment invalidations;
- expected outcomes frozen independently of candidate output;
- full protocol-author signer fingerprint.

One protocol binds one hardware class and one baseline/candidate pair. Another
pair requires another campaign ID and protocol even when policy is unchanged.

### Consent Eligibility Snapshots

Private eligibility snapshots are produced from a separate encrypted consent
registry before collection, evaluation, and publication review. They share one
closed schema with a fixed `collection`, `evaluation`, or `publication` phase.
Each contains only campaign-scoped participant tokens and eligibility facts
needed by the campaign:

- exact protocol digest and purpose;
- allowed bona fide and presentation classes;
- collection and retention windows;
- aggregate-publication acknowledgement;
- publication-boundary withdrawal acknowledgement;
- active, expired, or withdrawn status;
- registry revision and predecessor digest;
- operator signature.

Real identities and consent documents remain in the separate registry and are
not copied into protocols, manifests, transcripts, aggregates, or artifacts.
The collection snapshot is part of the frozen bundle. The evaluation snapshot
binds the exact token set and collection-snapshot digest into the private
transcript. The publication snapshot binds the same token set and both prior
snapshot digests into the review attestation. A missing token, disconnected
registry revision, expiry, or withdrawal at any phase fails closed.

### Capture Manifests And Bundle Index

The bundle contains an ordered signed index and bounded capture shards. One
capture shard contains no more than 128 paired cases, no more than 32 assets per
role per case, and no asset larger than the policy maximum or the framework
ceiling of 64 MiB.

Each case binds:

- protocol, participant or PAI token, case, stratum, scene, and expected outcome;
- exact baseline or candidate profile and balanced order position;
- camera and connection context;
- requested and accepted tuples and capture schedule;
- conditioning application and restoration proof;
- preprocessing, model, producer, policy, and software digests;
- bounded relative asset paths, media shapes, sequence positions, and SHA-256;
- capture start and end facts;
- pre-outcome invalidation and bounded-repeat history.

Baseline and candidate cases must have exact logical parity and independent
capture provenance. Missing, duplicate, extra, relabeled, or mismatched cases
prevent freeze.

### Private Case Transcript

The transcript records enough vault-local information for deterministic review:

- every input and predecessor digest;
- every case validation outcome;
- expected and actual categorical stage outcomes;
- bounded model values needed to recompute category decisions;
- latency observations;
- missingness and attempt history;
- stratum and PAI membership by campaign token;
- exact reducer inputs and output digest.

The transcript cannot contain real identity, consent-document content,
production enrollment handles, authentication grants, or release-key material.

### Public Aggregate Result

The public result contains only:

- schema, campaign, policy, protocol, bundle, evaluator, and transcript digests;
- exact hardware, profile, conditioning, preprocessing, model, and producer
  contract digests;
- aggregate and predeclared stratum denominators;
- mated, non-mated, no-face, and per-PAI categorical counts;
- paired 2 by 2 tables for each binary non-inferiority gate;
- confidence bounds, margins, and pass/fail dispositions;
- latency p50 and p95 summaries and paired upper bound;
- provenance, completeness, security, availability, and latency dispositions;
- collection and evaluation time bounds;
- explicit 3D-mask and active-IR exclusions;
- evaluator signer fingerprint.

It contains no participant or PAI token, identity, consent content, path, serial
number, frame, crop, tensor, template, embedding, per-case value, or model score.

### Review Attestation

The review attestation binds:

- policy, protocol, collection, evaluation, and publication eligibility
  snapshot, bundle, evaluator, transcript, and public-result digests;
- exact source revision and independently reproduced result digest;
- consent, cohort, case, attack, ordering, provenance, completeness,
  statistical, projection, and expiry checks;
- passing or rejected decision with fixed safe categories;
- operator and reviewer full fingerprints;
- review timestamp and reviewer signature.

The attestation is valid only when the reviewer fingerprint differs from the
operator fingerprint and every check passes. A rejection cannot be converted to
a pass without a new campaign ID.

### Reviewed Aggregate Envelope

After a passing review, a pure assembler creates a closed canonical envelope
containing:

- schema version and campaign ID;
- policy and protocol digests;
- public aggregate result digest;
- passing review attestation digest;
- public aggregate and reviewer signer fingerprints;
- review timestamp copied exactly from the signed attestation.

The assembler verifies both canonical inputs and the review signature before
emitting the envelope. It has no vault, biometric, release-key, package, or
selection-store access. The SHA-256 of the canonical envelope is the exact
`campaign_result_sha256` written into the schema-1 release qualification
artifact. This binds independent review without changing the implemented
artifact wire schema.

### Deletion Record

A signed deletion record contains only affected campaign and asset digests,
reason category, completion timestamp, reviewer fingerprint, and completion
status. It never lists identities or recoverable paths. Deletion failure remains
an unresolved governance incident and blocks future use of the affected vault.

## Corpus And Consent Governance

### Cohort Structure

Recruitment is multi-participant and maintainer-controlled. Policy requires
predeclared demographic axes for age, gender, and skin tone plus operational
axes that materially affect camera evidence, including eyewear, facial hair or
occlusion where applicable, and required lighting or pose conditions.

The target population, category instrument, category values, intersections to
be tested, and minimum count per stratum are fixed in policy and protocol before
recruitment closes. Categories are self-described or collected through the
approved instrument. They are not inferred by Irlume models. A short stratum
makes the campaign incomplete and is never pooled away after results are known.

Demographic fields exist only in the private registry, eligibility snapshot,
and private transcript. The public result identifies bounded stratum IDs and
denominators defined by policy, not participant attributes or tokens. Policy
fixes a minimum public cell size before recruitment. A short cell makes the
campaign incomplete; it is not suppressed, merged, or relabeled after results
are known.

### Presentation Attacks

Policy version 1 covers the product's currently claimed 2D scope:

- no-face presentations;
- non-mated live cross-identity presentations;
- printed-face PAI species;
- display and replay PAI species at the supported login distance;
- protocol-defined cutout or partial-face variants where applicable to the
  existing threat claim.

PAI production method, source diversity, display or print properties, distance,
lighting, and attempts are frozen before capture. Attack operators have separate
consent for each presentation class. The operating point remains fixed.

Three-dimensional masks and active-IR attacks are outside policy version 1.
Every public result and artifact review records these exclusions. Their absence
cannot be described as a pass or certification.

### Consent And Withdrawal

Consent states:

- exact `camera_profile_release_qualification` purpose;
- allowed bona fide and presentation classes;
- collection and retention windows;
- private replay and independent review;
- identity-free aggregate publication;
- publication-boundary withdrawal behavior;
- deletion and future-use consequences.

Withdrawal before artifact publication invalidates every referencing snapshot,
bundle, transcript, aggregate, and attestation. Signing is blocked.

Withdrawal after publication triggers reviewed deletion of retained assets and
prevents future campaign use. It does not retract the already published
identity-free aggregate or artifact, which remains eligible only until its fixed
expiry. Consent must explain this boundary before collection.

### Retention And Storage

The private snapshot is retained only through the artifact validity and audit
window and never beyond one year from collection. An earlier participant
withdrawal after publication shortens asset retention for that participant.

The vault is:

- encrypted and maintainer-controlled;
- outside the repository, production daemon state, enrollment state, benchmark
  roots, unencrypted backups, and support output;
- owner-restricted while writable staging exists;
- frozen and mounted read-only for evaluation and review;
- offline during private evaluation;
- configured to avoid core dumps and persistent model intermediates;
- accessed only through bounded relative paths with no symlink traversal.

Minimal consent and deletion audit records may remain where required, but they
must not reconstruct biometric content.

### Public Regression Lane

Public research datasets remain a separate profile-independent lane. Their
license, source, mirror identity, and content digests are recorded. Existing
model-calibration results may be bound by protocol and result digest.

Public regression evidence may strengthen confidence in the fixed model
operating point. It cannot replace exact profile-bound private captures, repair
a failed campaign gate, or authorize a hardware class by itself.

## Collection Protocol

Baseline and candidate cases are collected in deterministic balanced crossover
order. Long baseline and candidate blocks are prohibited. The protocol limits
time between paired cases and records scene, context, conditioning,
negotiation, capture, and restoration evidence for each side.

The collector:

1. verifies policy, protocol, signer, collection eligibility snapshot, and
   target scope;
2. verifies exact camera endpoints and connection context;
3. applies the protocol's next balanced profile and conditioning policy;
4. verifies requested and accepted tuples before capture;
5. captures one complete bounded evidence window;
6. verifies exact conditioning restoration;
7. records content digests and provenance into staging;
8. advances only when the paired-case rules permit it.

A failure to acquire, model-relevant capture failure, timeout, missing PAD
evidence, or restoration uncertainty is an incorrect outcome, not an exclusion.
Only a predeclared equipment or provenance invalidation detected before model
evaluation may be repeated. The protocol fixes a repeat cap. Every invalidation
and attempt remains in the private audit record. Exceeding the cap makes the
campaign incomplete.

Collection has no network, enrollment, authentication, selection-store,
artifact-compilation, review, or release-signing capability.

## Deterministic Evaluation

Evaluation is ordered and fail closed:

1. mount the frozen bundle read-only;
2. verify exact signatures, roles, schemas, bounds, and predecessor digests;
3. obtain and verify the evaluation-phase eligibility snapshot;
4. verify every relative path, descriptor, type, size, and asset digest before
   decoding;
5. require exact baseline/candidate case, stratum, scene, and ordering parity;
6. require exact hardware, profile, conditioning, preprocessing, model,
   producer, policy, threshold, and software provenance;
7. construct campaign-only recognition references in memory;
8. run the same canonical evidence and typed model-input contracts as Irlume;
9. reduce each case to frozen expected-versus-actual categorical outcomes;
10. destroy temporary templates and model intermediates;
11. compute the private transcript and public aggregate deterministically;
12. sign both result digests with the evaluator role key.

There is no fallback to production enrollment, legacy assets, unsigned labels,
another profile, nearby hardware, stale consent, partial cases, or changed
thresholds.

## Statistical Acceptance Policy

### Unit Of Analysis

The unit is a paired case under baseline and candidate profiles for the same
participant or PAI, scene, expected outcome, logical reference relationship,
and bounded collection block.

Before the authorizing protocol is signed, a non-authorizing pilot with
different participants and instruments estimates discordant-pair rates. The
authorizing sample size is then locked. Pilot observations never enter the
authorizing denominator.

### Security Direction

Zero candidate accepts are tolerated for:

- non-mated identity trials;
- no-face trials;
- required print PAI species;
- required display or replay PAI species;
- every other policy-required security-direction case.

Any candidate accept fails the campaign. Any case accepted by both baseline and
candidate also blocks publication and triggers security review. A known
baseline failure cannot normalize candidate authority.

IAPAR is reported per PAI species and pooled at the fixed production operating
point. The result includes exact one-sided 95 percent Clopper-Pearson upper
bounds and full denominators. These values describe the campaign and do not
claim FIDO or ISO certification.

### Bona Fide Non-Inferiority

Detection, recognition, liveness, RGB PAD, and IR PAD are co-primary paired
binary gates. Policy version 1 uses the MOVER-Wilson matched-pair risk-difference
method, identified as `paired_mover_wilson_v1`.

For every gate:

- the one-sided 95 percent lower confidence bound for
  `candidate_success_rate - baseline_success_rate` must exceed `-0.02` overall;
- the corresponding bound must exceed `-0.05` in every predeclared demographic
  and operational stratum;
- the exact paired 2 by 2 table and denominator are retained in the public
  aggregate;
- all overall and stratum tests must pass.

The implementation must pin the formula, numerical precision, boundary
behavior, and reference vectors under the method version. Changing any of them
requires a new policy method version.

### Power And Sample Size

Each authorizing overall and stratum test requires at least 80 percent planned
power at one-sided alpha `0.05`, using the non-authorizing pilot's predeclared
discordant-pair estimates and the applicable 2 or 5 percentage-point margin.

The sample-size calculator and inputs are part of the signed protocol. Capture
cannot stop early for apparent success. A stratum that cannot meet its locked
sample size makes the campaign incomplete.

Every component is required to pass, so the final decision is an
intersection-union decision. A strong result in one gate or stratum cannot
compensate for another failure.

### Latency

Candidate end-to-end p95 latency must remain within the existing fixed budget.
Using 10,000 deterministic participant-cluster bootstrap resamples seeded from
the signed protocol, the one-sided 95 percent upper bound for the paired
candidate-minus-baseline latency increase must not exceed 5 percent of that
budget.

The bootstrap unit is the participant or PAI cluster, not an individual frame.
The resampling algorithm, seed derivation, quantile convention, precision, and
reference vectors are fixed by policy method version.

### Missingness And Exclusions

Model rejection, failure to acquire, timeout, missing required PAD evidence,
and incomplete model-relevant capture count as incorrect. They cannot disappear
from a denominator.

Only a protocol-listed equipment or provenance invalidation detected before
model evaluation may use the bounded repeat rule. The private transcript keeps
the original invalidation and repeat. No outcome-known exclusion, relabeling,
threshold change, optional stopping, or denominator reduction is allowed.

## Independent Review

The reviewer obtains read-only access to the frozen bundle and exact evaluator
build. Review requires:

- distinct operator and reviewer full fingerprints;
- valid policy and protocol signatures;
- complete eligible cohort and every locked stratum;
- exact case, attack, order, and denominator completeness;
- a current publication-phase eligibility snapshot connected to the collection
  and evaluation snapshots;
- exact provenance and asset digest verification;
- deterministic reproduction of private and public result digests;
- independent recomputation of statistical tables and bounds;
- confirmation that every hard gate and intersection component passed;
- confirmation that the public projection contains no prohibited content;
- confirmation that expiry and retention remain valid;
- a signed pass or rejection attestation.

The reviewer cannot edit evidence or waive a gate. A failed review requires a
new campaign ID after the cause is corrected.

## Artifact Compilation And Publication

The artifact compiler runs outside the vault and accepts only:

- opaque reviewed authority retaining the canonical envelope, exact validated
  protocol, passing public aggregate, and valid matching independent review
  attestation;
- the intended allowlisted release signer fingerprint.

No target field is supplied separately by the compiler caller. The compiler
recomputes the canonical protocol hardware and profile digests and requires
them to equal the passing public result before projecting:

- campaign ID, protocol digest, and reviewed aggregate envelope digest;
- exact hardware scope;
- exact baseline and candidate profile contracts;
- conditioning catalog and selected-policy digests;
- preprocessing and model-contract digests;
- policy and producer versions;
- passing aggregate gate dispositions;
- qualification time copied exactly from the signed review timestamp;
- expiry no later than both protocol expiry and one year after collection;
- release signature metadata.

The protocol hardware scope is a strict superset of the schema-1 artifact
hardware scope: it additionally binds the campaign hardware class while its
identity-free RGB and IR endpoint contracts project exactly into the artifact.
The compiler never copies a serial, device path, or mutable local-discovery
label. Protocol expiry and collection end come from the retained validated
protocol and matching public result, so a caller cannot extend validity.

It emits canonical unsigned bytes only. It cannot access the private bundle,
consent registry, biometric data, release private key, package root, local
commissioning store, or profile-selection store.

Release signing and publication require another explicit gate. Signing covers
the exact compiler bytes with the allowlisted release key. Packaging,
commissioning, artifact installation, and production profile selection remain
separate later plans.

## Failure Handling And Safe Diagnostics

Fixed public campaign categories are:

- `policy_unsupported`;
- `protocol_invalid`;
- `consent_ineligible`;
- `cohort_incomplete`;
- `bundle_unsafe`;
- `capture_incomplete`;
- `provenance_mismatch`;
- `evaluator_drift`;
- `security_gate_failed`;
- `noninferiority_failed`;
- `latency_failed`;
- `review_missing`;
- `review_rejected`;
- `artifact_compile_failed`.

Public output may identify a gate, denominator, aggregate count, margin, and
confidence bound. It never includes tokens, identities, paths, serials,
third-party error text, per-case values, model scores, or asset details.

Unknown schema, field, enum, signer, role, policy, method, or analysis version
fails. A crash leaves staging data only. Restart verifies all immutable
predecessors rather than trusting partial progress.

A failed result cannot be repaired by changing labels, margins, exclusions,
denominators, or outputs under the same campaign ID. A method change requires a
new policy version; a campaign-specific correction requires a new protocol and
campaign ID.

## Verification

All software-only tests use synthetic, non-biometric fixtures.

### Contract Tests

- canonical-byte round trips and deterministic digests;
- closed schemas, enums, bounds, identifiers, lists, shards, and total sizes;
- unknown-field and unsupported-version rejection;
- invalid, missing, duplicate, wrong-role, short-ID, and wrong-fingerprint
  signatures;
- predecessor digest mismatch and reordered-index rejection;
- disconnected collection, evaluation, or publication eligibility snapshots;
- reviewed aggregate envelope, public-result, and review-attestation mismatch;
- invalid campaign, hardware, profile, model, preprocessing, conditioning,
  policy, operating-point, and expiry bindings.

### Statistical Tests

- hand-computed and published matched-pair non-inferiority fixtures;
- exhaustive small-sample paired 2 by 2 tables;
- exact Clopper-Pearson boundary fixtures;
- power and sample-size boundary fixtures;
- deterministic cluster-bootstrap reference vectors;
- exact 2 percent overall, 5 percent stratum, and 5 percent latency-margin
  boundaries;
- minimum public stratum cell-size boundaries;
- security zero-tolerance and shared baseline/candidate failure cases;
- intersection decisions where each component fails independently;
- monotonicity: removing, corrupting, or failing evidence cannot improve a
  verdict.

### Consent And Lifecycle Tests

- purpose and presentation-scope enforcement;
- active, expired, missing, and pre-publication withdrawn consent;
- post-publication withdrawal and asset deletion;
- artifact-life and one-year retention ceilings;
- signed deletion success, interruption, and unresolved failure;
- no real identity or consent content enters non-registry fixtures.

### Filesystem And Determinism Tests

- traversal, absolute path, symlink, non-regular file, root escape, duplicate,
  size, and digest rejection;
- interrupted staging never appears frozen;
- frozen bundles reject mutation;
- read-only replay produces byte-identical private and public results;
- changed software, models, policy, thresholds, or contracts produce drift,
  never silent recomputation.

### Projection And Authority Tests

- no token, identity, path, image, crop, tensor, template, embedding, per-case
  value, score, or unsafe text reaches public results or artifacts;
- collection cannot evaluate, review, compile, or sign;
- evaluation cannot review itself or compile authority;
- review cannot alter evidence or waive gates;
- compilation cannot access the vault or release key;
- campaign tooling cannot access enrollment, authentication grants, local
  commissioning writers, or `ProfileSelectionStore::save`;
- synthetic end-to-end pass and every fixed failure category;
- operator/reviewer fingerprint collision and artifact tampering rejection;
- detached release-signature verification through the existing production
  boundary.

Real biometric and hardware tests remain declared and ignored until separately
authorized. Synthetic success creates no release, local, or production
authority.

## Delivery Phases And Gates

1. Commit this design, glossary additions, and ADR-0022.
2. Implement closed policy, protocol, eligibility-snapshot, bundle-index,
   result, review-attestation, reviewed-envelope, and deletion-record contracts
   with synthetic fixtures.
3. Implement and independently verify the paired reducer, power calculator,
   public projection, and unsigned schema-1 artifact compiler.
4. Implement synthetic vault, filesystem, and deterministic evaluator
   boundaries without real assets, enrollment, hardware, or network.
5. Complete an independent software-only authority review and keep every writer
   disconnected.
6. Design and approve one exact real campaign protocol under the generic
   framework.
7. Obtain separate approval before recruitment, consent execution, or private
   vault creation.
8. Obtain separate approval before each biometric collection and hardware
   campaign.
9. Independently review the frozen campaign and aggregate result.
10. Obtain separate approval before release signing or publication.
11. Design local commissioning and production integration only after a
   published artifact passes its own review.

No phase inherits authorization for the next phase.

## Alternatives Rejected

### One End-To-End Campaign Tool

Rejected because one process could collect biometrics, choose analysis, declare
a pass, and prepare authority output without an independently verifiable
boundary.

### Manual Governance Plus Measurement Scripts

Rejected because procedures alone cannot prove immutable labels, complete
denominators, reviewer independence, or that artifact bytes came from the
reviewed result.

### Absolute Population Recertification Per Profile

Rejected because the profile question is whether an exact candidate preserves
an approved operating point. Repeating population-scale model certification for
every transport profile is a separate program.

### Aggregate-Only Cohort Evaluation

Rejected because a pooled pass can hide a demographic or operational stratum
regression caused by changed camera evidence.

### Optional Independent Review

Rejected because reproducibility by the same operator does not establish that
cohort, consent, analysis, and public projection were independently checked.

### Immediate Revocation After Post-Publication Withdrawal

Rejected for schema 1 because no signed revocation channel exists. The approved
publication boundary deletes retained data and blocks future use while fixed
artifact expiry bounds already released authority.

### Delete All Assets At Publication

Rejected because exact replay and post-release audit would become impossible.
Retention remains bounded by withdrawal, artifact life, and an absolute
one-year ceiling.

## Success Criteria

- Every campaign document is bounded, canonical, versioned,
  content-addressed, and closed to unknown input.
- One campaign binds one exact hardware scope and one baseline/candidate pair.
- Labels, strata, attacks, margins, sample size, order, exclusions, software,
  models, and operating points are frozen before authorizing capture.
- Security failures cannot be averaged away.
- Every overall and predeclared stratum non-inferiority gate passes.
- Consent withdrawal and retention obey the publication boundary and one-year
  maximum.
- Collection, evaluation, review, compilation, signing, commissioning, and
  production selection remain separate authorities.
- The public result and release artifact are aggregate-only and privacy-safe.
- The compiler cannot access biometrics, and campaign tooling cannot access
  enrollment, authentication grants, or production selection writers.
- Synthetic tests cover every contract, statistical boundary, fixed failure
  category, lifecycle transition, and authority separation.
- Real-data, hardware, signing, packaging, commissioning, and production actions
  remain separately gated.
