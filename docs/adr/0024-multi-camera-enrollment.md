# ADR-0024: Multi-camera enrollment under enrolled-camera-set binding

## Status

Accepted (implementation reality recorded 2026-09-18). Originally proposed
2026-09-10, revised 2026-09-16 following design review. Historical source-review
baseline: `d4bc0f1` (the parent of `bcc26a5`), as identified in the preceding
review. The Windows observation below is maintainer-reported.

Implementation status: Phase 1 (secondary store foundation) merged in #732 and
Phase 2 (secondary authentication wiring, `enroll --add-camera`,
`profiles remove-camera`) shipped in v0.13.0. **Known deviation from s1.2:** the
secondary store is currently persisted as root-only plaintext JSON (see the
note in section 1.2); either the confidentiality clause is implemented or the
deviation is formally accepted, but the shipped state is as described there.
Numbered after ADR-0023; independent of ADR-0022's acceptance.

## Context

At the reviewed baseline, an enrollment's recorded camera binding contains
one role-labelled pair, `CameraBinding { rgb, ir }`. `FaceScan` has no camera
origin; scan selection filters by recognizer embedding space rather than
camera. `pitch_neutral` and the personalized IR ratio floor
(`ir_center_edge_ratio_floor`, 75% of the minimum eligible ratio across
profiles) are not partitioned by camera. Legacy records can lack a usable
binding; their migration requires an explicit provenance rule.

The reviewed enrollment readers do not reject unknown fields. Adding
secondary scans to their existing arrays would let an old reader score
those scans without understanding their camera tags. An old writer could
subsequently discard the tags. Additive parsing compatibility therefore
cannot establish camera isolation.

On the tested Windows configuration (2026-09-15 ThinkPad session), enrollment
performed using one camera permitted authentication using another. This is
a workflow observation, not evidence of Windows' internal template
representation, policy generality, or spoof resistance. It motivates one
account using laptop and desk cameras without replacing its enrollment.

## Decision

### 1. Storage: keep the legacy-visible enrollment primary-only

The existing enrollment file remains the primary camera group's complete
store: primary scans, binding, and primary-derived state. Secondary bindings,
scans, calibration, and derived state live in a separate, versioned store
outside the enrollment discovery namespace used by supported legacy
readers. The new implementation composes validated views; it never writes
secondary templates into legacy-visible arrays or calibration slots.

The exact storage location and all supported legacy discovery paths must
be verified in Phase 1. A different filename alone is not proof that an
older reader, enumerator, or exporter will never open the store.

#### 1.1 Secondary activation depends on the primary snapshot

Physical separation prevents template mixing; it does not establish that
secondary authorization remains valid after the primary enrollment changes.

The secondary store records its owner, immutable group/profile references,
state generation, and a protected binding to the exact primary-store
snapshot against which it was authorized. For the initial implementation,
that binding includes a cryptographic digest of the actual primary-file
bytes. It is not just a username, profile display name, timestamp, or camera
model. The primary and secondary stores are read under the account's shared
state lock and validated together.

A missing, unreadable, replaced, or digest-mismatched primary store makes
secondary groups inactive. Their data is preserved for diagnosis and
explicit recovery; it is not automatically rebound, reattributed, or
reauthorized. Even a semantically equivalent legacy rewrite may invalidate
the digest. That conservative availability cost is accepted.

A new-code mutation may preserve secondary authorization across an expected
primary change only through the authorized transaction contract in §4. It
must preserve or explicitly update profile associations and publish a new
snapshot binding. Merely observing changed primary bytes never authorizes
this update.

A deliberately retired primary group uses the explicit empty-anchor
representation described in §4. It is not inferred from an unexpectedly
missing file.

#### 1.2 Protection, parsing, and failure behavior

The secondary store receives at least the primary store's applicable
confidentiality, integrity, ownership, and permission protections. It uses
the existing account template-key lifecycle, not a separate authentication
credential. An encrypted enrollment cannot become plaintext because a key
is unavailable. Owner, store type, format version, snapshot binding, and
authorization-bearing records are validated as part of the protected state.

> **Deviation note (2026-09-18, still open):** the shipped implementation
> satisfies the integrity, ownership, parsing, and failure clauses above, but
> NOT the confidentiality clause: `save_secondary` persists plain
> `serde_json` bytes under `cameras/<user>.json` (0640 root:root inside the
> 0700 state dir) with no sealing layer, and the commit journal carries the
> same bytes. Primary-store embeddings remain AES-256-GCM under the
> TPM-sealed key. Closing this gap (encrypting the secondary store under the
> account template key) or formally accepting the deviation is a pending
> maintainer decision; the ADR text above remains the requirement.

Unsupported versions or invalid supported-version records reject the
secondary store as a whole. Unknown fields, duplicate identifiers,
unresolvable references, invalid dimensions, and exceeded resource limits
are not partially accepted. Such a store is never treated as an empty file
that a subsequent add operation may silently overwrite.

An absent or rejected secondary store cannot authorize a secondary group.
The independently valid primary enrollment may remain usable under its
existing requirements. Failure does not silently redirect an attempt already
pinned to a secondary group. Diagnostics distinguish absent, incompatible,
corrupt, and stale-secondary-state conditions without exposing templates.

#### 1.3 Downgrade guarantees and limitations

Supported old readers see only primary-camera templates and derived state.
Old writers cannot rewrite secondary data, but their primary changes can
invalidate secondary activation. On re-upgrade, preserving secondary bytes
is not equivalent to preserving their authorization.

Compatibility is claimed only for binaries and operations exercised in the
acceptance matrix. Legacy tools do not implement complete multi-camera
account deletion, profile deletion, replacement, backup, or recovery. Those
operations must use the new lifecycle implementation, or an explicitly
documented migration/reset procedure covering both stores.

Concurrent use of a legacy mutation operation is supported only when that
operation participates in the same account-state locking and publication
protocol. Locks such as `flock` are advisory: a legacy writer with
sufficient permissions can perform I/O without honoring them, so a new
daemon holding its lock does not by itself establish coordination with an
older writer. Legacy operations that do not meet this requirement are
unsupported while the new daemon is authenticating the account and require
a documented maintenance procedure with authentication stopped. The
compatibility matrix distinguishes concurrent-operation support from
offline downgrade read/write compatibility; an offline round-trip test
does not prove concurrent safety. The account-state lock object must also
remain stable across enrollment replacement and deletion (an `flock` lock
belongs to the open file description): publication must not replace or
recreate its synchronization object. Phase 1 verifies the actual legacy
entry points' locking behavior, not just the new implementation's.

A primary digest detects a different snapshot, not every historical write.
Restoring byte-identical old snapshots is not detectable from that digest
alone. This ADR does not promise irreversible revocation against external
backup rollback or trusted-host state restoration. Supported restore flows
must explicitly authorize restoration and validate both stores; they must
not silently merge residual secondary state into a restored primary.

### 2. Camera groups: authorize the complete role-labelled pair

A group has an immutable identifier and the exact
`{ rgb identity, ir identity }` pair, using the existing `device_identity`
representation with explicit roles. Scans reference that group, not a bare
single-device identity, display name, or mutable list position. Profile
associations likewise cannot be recovered by matching a reused display name.

Authentication through a pair requires that complete pair. Enrolling
`(RGB-A, IR-A)` and `(RGB-B, IR-B)` never authorizes `(RGB-A, IR-B)`.
Shared endpoints do not merge groups or their calibration domains. Missing
identities are not wildcards; an ambiguous group resolution refuses the
attempt rather than selecting a group by its biometric score.

Legacy primary scans are attributed only through an unambiguous recorded
binding and an immutable legacy-group reference. Reordering, removing, or
explicitly promoting groups never changes retained scans' origin. A legacy
enrollment without usable binding retains its data without invented
provenance and requires attended migration or fresh capture before it can
participate in multi-camera authentication.

New secondary records with missing or unresolvable group references are
invalid. The legacy primary layout may omit per-scan references because its
entire store has one validated camera scope; that exception does not extend
to new secondary records.

This ADR creates no new single-role fallback. Any already-supported
role-restricted authentication path needs an explicit, tested secondary-group
resolution rule preserving its existing requirements. Until that rule is
implemented, secondary-group authentication on that path remains disabled;
this does not redefine the existing primary path.

### 3. Camera-scoped views feed scoring and calibration

A validated camera-scoped enrollment view enforces group and pipeline
compatibility before exposing candidates. It provides profile-scoped views
where the existing algorithm requires them. Matching, calibration, and
derived-state consumers use these views rather than optional caller-side
filters. Diagnostic accessors that expose unfiltered data are not available
as authentication inputs.

| Derived state or operation | Required scope |
|---|---|
| RGB and IR template selection | Active group plus existing recognizer, IR-space, and dimension checks |
| Calibration fitting and retrieval | Profile, group, recognizer/pipeline, and scan revision; the legacy mirror stays primary-only |
| Personalized IR ratio floor | Only the active group's policy-applicable scans; existing profile-aggregation semantics remain explicit |
| Pitch neutral | Per profile and group; legacy aggregation cannot include secondary data or supply a new group's calibration |
| Centroids and template aggregates | Constructed after group and embedding-space filtering |
| Threshold-scaling counts | The candidates each scoring arm actually evaluates, retaining that arm's existing count semantics |
| Readiness and limits | Per profile, group, and compatible pipeline, with explicit account-wide resource bounds |

Scans and cached derived state carry compatible revisions. Adding or removing
scans invalidates or replaces affected calibration and aggregates; cached
state from another group, model, or scan revision is never a fallback.
The calibrated IR and personalized ratio-floor consumers are in scope, not
just embedding selectors.

A new group starts with existing fresh-enrollment defaults. It borrows no
primary calibration, pitch neutral, or personalized signal floor.
`DEFAULT_ENROLL_SCANS` (10 accepted quality-gated scans at the reviewed
baseline) is the add-camera target. `IMPROVE_SCANS` remains for improving an
established group, not bootstrapping a new one.

The capture target, `MIN_FIT_PAIRS`, and authentication-readiness predicates
are distinct. Ten scans do not by themselves establish usable IR evidence
or readiness for every authentication mode. The implementation defines and
tests readiness for each supported mode using compatible data from the
relevant profile/group only. Lack of calibration follows the existing
mode's policy; it neither borrows another group's fit nor invents a new
threshold policy.

Existing per-comparison template limits retain their meaning. Group counts,
profile references, total templates, serialized sizes, and calibration sizes
also have explicit account-wide bounds fixed and tested in Phase 1.

### 4. Adding, removing, and restoring groups are credential operations

Adding a group requires fresh authorization to modify the target account's
biometric enrollment, independent of the proposed camera. The daemon scopes
that authorization to the account, profile, exact group, and operation.
The new camera never authorizes its own addition. Attended capture and
quality checks supplement authorization; they do not replace it.

The CLI and TUI invoke the same daemon-enforced policy. Whether authorization
is presented through an elevated invocation or an interactive prompt is not
the security boundary. Machine-wide `set-cameras` configuration remains
separate from account-specific enrollment authorization.

#### 4.1 Publication and concurrent mutation

Capture uses a defined enrollment revision and transaction-scoped camera
selection. Before publication, the daemon revalidates authorization,
identity, source revision, profile association, and readiness. Cancellation,
hotplug, insufficient evidence, or a conflicting mutation does not partially
activate a group or overwrite newer state.

Adding or removing a secondary group normally replaces only the secondary
store. Its scans, binding, derived state, and activation record are published
together. A mutation affecting both stores requires an explicit
cross-store commit and crash-recovery protocol. Two individually atomic
file writes are not, by themselves, one atomic enrollment transaction.

Phase 1 must specify that protocol using the account's shared lock,
snapshot/generation checks, and durable publication. Readers may expose a
coherent committed state or refuse affected secondary groups; they may not
combine mismatched generations. A crash may cost secondary availability,
but cannot activate a binding against the wrong primary or silently restore
revoked authorization. Recovery preserves uncertain state for explicit
resolution rather than guessing. Success is reported only after the
required durable commit; ambiguous publication is reported as such.

Interrupted capture does not change the operator's default pair. Making a
newly enrolled pair the default is an explicit subsequent operation.

#### 4.2 Removal, replacement, and revocation

Removing a secondary group deletes its active binding, scans, and derived
state together. Removing an account-level face profile removes that
profile's data and authorization across groups, not only in the primary
file. Replacement and account reset likewise cover both stores and the
applicable shared credential state.

Removing the primary never silently promotes another group or reattributes
its scans. To retain secondary authentication, the new implementation must
publish an intentionally empty, legacy-readable primary anchor plus the
corresponding secondary snapshot binding. Actual supported legacy readers
must be proven unable to grant from that empty anchor. Unexpected primary
absence is not this state. This operation is unavailable until its
cross-store and legacy-reader tests pass.

Promotion is a separate explicitly authorized operation, not a list reorder.
It must produce a legacy-visible store containing only the promoted group's
own scans and derived state while preserving immutable group references.
It is not exposed unless its migration and interruption semantics are
tested; it is not required to implement secondary addition and removal.

Authentication validates its pinned enrollment generation at the final
grant-decision boundary, serialized with revocation. For secondary
authentication, that final validation covers BOTH the secondary
authorization generation AND its binding to the currently published
primary snapshot. Checking the secondary generation alone is
insufficient: a supported legacy writer may change the primary without
updating any secondary state, and an open file descriptor retained from
the attempt's start does not establish the currently published snapshot
(replacing a pathname with `rename(2)` leaves existing descriptors
unaffected). The final check must therefore establish the current
authoritative primary snapshot; a changed, missing, unreadable, or
otherwise invalid primary invalidates the attempt before a grant
decision - including for an attempt already in progress. Once removal
commits, no subsequent grant decision may use the removed group or stale
cached state. Removal cancels or invalidates in-flight use; it does not
claim to undo a grant already issued or terminate an existing login
session.

#### 4.3 Backup, recovery, and keys

Managed backup and recovery cover both stores and their snapshot relationship.
A primary-only backup is identified as incomplete for multi-camera recovery.
Restoring it leaves residual secondary data inactive rather than attaching
that data automatically. Restoring secondary authorization requires the
account's credential-management authorization and an explicitly validated
restore transaction.

Template-key rotation, recovery, account replacement, and deletion must not
leave a secondary store active under stale ownership or key context. Key
failure never creates a replacement key or a plaintext downgrade as an
implicit repair. The retained-state and error behavior is tested alongside
normal enrollment publication.

### 5. Pair selection and attempt lifecycle

An explicitly configured enrolled pair takes precedence when available and
eligible for the requested authentication mode. Otherwise, an explicitly
enabled automatic-selection policy chooses a complete eligible pair in a
stable documented order: active legacy primary first, then a canonical order
of enrolled pair identities. An explicit preference is not silently
subordinated to the number of scans.

Selection and enrollment scope are pinned before capture and retained through
the camera-operation lease and final decision. Hotplug, device re-resolution,
or configuration changes cannot redirect the attempt or substitute another
group's evidence.

There is no automatic movement to another pair after a mismatch or PAD
refusal, and no pooling of evidence across pairs. All paths share the
account-level attempt budget, retry state, and deadline. Availability
fallback before an attempt is not permission to try every camera until one
accepts. A new attempt follows the same shared limits.

### 6. Claims, precisely

Exact membership checking is preserved under the existing identity
representation (`vid:pid[:serial]`) and trusted-host assumptions. This ADR
introduces no cryptographic hardware attestation. Without a serial, that
identity alone cannot distinguish same-model physical units; this is an
existing representation limit, not a new guarantee.

More authorized cameras mean more authorized capture paths. No claim is made
that aggregate biometric error rates or spoof resistance are unchanged.
Downgrade claims concern the tested primary-only reader behavior and the
explicit mutation limitations in §1, not universal lifecycle compatibility
with every historical binary.

The separate-enrollments alternative is rejected for UX and state-management
reasons: one account credential and shared retry state. It is not rejected
on the claim that multiple secrets would be unavoidable.

### 7. Thresholds: existing formulas, not new policy

Computing existing threshold formulas from camera-filtered candidate counts
is part of Phase 1. Each count retains the meaning assigned by its scoring
arm. No group borrows another group's candidates to satisfy readiness or
alter its counts.

Camera-specific biometric or PAD threshold policy is out of scope. It
requires a separate decision and security evaluation covering genuine
users, impostors, presentation attacks, and relevant capture conditions.
ADR-0023 capture evidence can describe those conditions; it does not
authorize threshold changes, enroll hardware, or substitute local
qualification or live runtime evidence.

## Phasing

- **Phase 1: core invariants, no new user-facing activation.** Implement the
  storage boundary and activation binding; the cross-store lifecycle and
  recovery contract; group records; scoped views and derived state;
  daemon authorization and mutation primitives; selection pinning; and
  revocation/grant coordination. Pass the applicable acceptance tests below.
  Authorization and atomicity are not deferred merely because the UI is.
- **Phase 2: integrated flows and release gates.** Expose
  `irlume enroll --add-camera`, supported removal operations, and CLI/TUI
  parity through the tested primitives. `status`, `doctor`, and `profiles`
  distinguish enrolled, connected, selected, ready, stale, and incompatible
  groups, with per-group counts and calibration state. Complete end-to-end
  authorization, lifecycle, downgrade, and hardware integration tests before
  enabling secondary-camera authentication in a release.
- **Phase 3: none.** Per-camera biometric threshold policy remains outside
  this ADR.

## Acceptance tests

The software invariants are Phase 1 gates. Phase 2 reruns them through the
actual user-facing flows and adds hardware integration; unit-test success
alone does not authorize shipment.

| Boundary | Required result |
|---|---|
| Actual supported legacy readers and writers | Secondary data never enters legacy matching, calibration, or discovery; primary round trips cannot erase secondary provenance |
| Legacy primary mutation | Changed, deleted, replaced, or incompatible primary state cannot leave secondary groups implicitly authorized; equivalent rewrites may conservatively mark them stale. A primary rewrite DURING secondary authentication, with the secondary generation unchanged, prevents a subsequent grant from that attempt |
| Version, protection, and activation binding | Missing keys, wrong owner/context, unsupported versions, invalid references, corrupt records, or snapshot mismatch never activate secondary data or trigger destructive automatic repair |
| Exact pair membership | Enrolling pairs A and B never authorizes a hybrid; shared endpoints never merge calibration groups |
| Camera and pipeline isolation | Foreign-group data cannot influence scores, centroids, calibration, ratio floors, pitch, readiness, or threshold counts |
| Legacy migration and primary retirement | No invented provenance; no reattribution on reorder/removal; the intentional empty primary anchor cannot grant on supported old readers |
| Per-profile/group readiness and limits | Incomplete groups borrow no evidence; count semantics and all storage/calibration bounds hold |
| Authorization and identity | Unauthorized, wrong-account, wrong-profile, expired, interrupted, or device-changed additions cannot activate a group |
| Cross-store publication and recovery | Fault injection at publication, synchronization, and restart boundaries yields coherent committed state or refusal, never mixed-generation authorization |
| Profile deletion, replacement, and restore | Account/profile lifecycle operations cover secondary authorization; primary-only restore does not silently reactivate residual groups |
| Selection and attempt lifecycle | Explicit preference is honored; selection is pinned before capture; hotplug/configuration changes cannot redirect an attempt |
| Removal and shared budgets | No post-revocation grant decision uses a stale group; switching cameras does not reset limits or deadlines |

Hardware integration verifies laptop-plus-desk operation, both pairs
connected, disconnect/reconnect, interrupted enrollment, and each supported
RGB/IR authentication mode. Modes lacking a tested secondary-group resolver
remain disabled for secondary authentication.

## Consequences

- **Positive:** laptop-plus-desk operation with one account credential and
  retry state; camera-specific calibration; exact-pair authorization;
  genuinely primary-only views for supported legacy readers.
- **Costs:** a protected second store, conservative primary-snapshot
  invalidation, explicit cross-store recovery and lifecycle handling, and
  scoped access across scoring/calibration consumers. Existing atomic-write
  helpers are building blocks, not proof of multi-file atomicity.
- **Risks and mitigations:** mixing is blocked by scoped views; stale
  secondary authority by snapshot binding and explicit lifecycle rules;
  sparse groups by capture/readiness requirements; unbounded state by
  resource limits; downgrade confusion by tested compatibility and visible
  stale-state diagnostics. External snapshot rollback remains subject to
  the stated trusted-host and recovery limitations.
- **Alternatives:** sensor-agnostic reuse is not selected because this design
  deliberately keeps explicit pair authorization and camera-scoped evidence;
  separate user-facing enrollments are rejected for UX/state management;
  additive secondary fields in legacy arrays are rejected because reviewed
  old readers would ignore their isolation metadata. A new format rejected
  by old readers remains the simpler fallback if the two-store lifecycle
  contract cannot meet its tests; it must not be replaced by an unsafe
  compatibility shortcut.
