# ADR-0028: IR-only authentication honours enrolled secondary IR cameras

## Status

Accepted 2026-09-22; Phase 1 merged (#808) and Phase 2 completed on
archhost 2026-09-23 (`artifacts/irlume/2026-09-23-adr28-phase2/RESULTS.md`
on the shared ledger); the gate of §7 is removed by the change that cites
that evidence. Amends ADR-0024 (multi-camera enrollment) §5 for the
experimental IR-only sensor policy; changes nothing in ADR-0016's IR
evidence rules or in the dual-sensor path. Motivated by the sensor-policy ×
camera matrix measured on archhost on 2026-09-22
(`artifacts/irlume/2026-09-22-archhost-rollout-c8f5b21d/RESULTS.md` on the
shared ledger).

## Context

An account's enrollment consists of the legacy-visible primary store (the
primary camera pair's scans, binding and calibration) and, since ADR-0024, a
separate secondary store holding further authorized camera groups, each a
complete role-labelled pair with its own scans and its own IR calibrations,
activated only while the store's primary-snapshot digest matches the primary
file (§1.1). The dual-sensor path resolves the live pair against the primary
binding first and then against the active secondary groups, and scores each
attempt against that group's camera-scoped view (§3, §5).

The experimental IR-only policy does not. `enrollment_readiness` in
`ir_assessment.rs` compares the configured IR target's identity with
`enrollment.camera_binding.ir` of the primary store alone; any other identity
yields `IrOnlyReadiness::BindingMismatch`, and the request is refused before
a camera is opened ("IR camera differs from enrollment; re-enroll on this
camera or use your password"). `irlume auth sensor preflight` reports the
same.

Measured on archhost (enrollment primary on the Logitech BRIO, NexiGo N930W
authorized as a secondary group):

| camera | dual | ir-only |
|---|---|---|
| BRIO (primary) | granted 8.75 s | granted **1.39 s** |
| NexiGo (secondary) | granted 7.38 s | **refused 143 ms**, `BindingMismatch` |

So the one path that reaches a ~1.4 s unlock on the primary is unavailable
on every other camera, although the same account has authorized the other
pair and the dual path already trusts it. A user who chose IR-only for its
speed and sits at a secondary camera gets the password every time. What the
NexiGo would measure on this path is NOT yet known: the matrix holds no
successful NexiGo IR-only attempt, only the refusal; Phase 2 measures it.

"Re-enroll on this camera" is not an answer: ADR-0024 rejected separate
enrollments per camera (§6) and made adding a camera a credential operation
that produces a secondary group precisely so one account credential covers
all its cameras.

## Decision

1. IR-only target resolution consults the same authorization the dual path
   does, with the same exact-pair rule. The configured pair (explicit
   configuration only, as today: IR-only never discovers or opens a camera
   during preflight, the contract established for issue #701) carries both
   identities. Resolution matches the configured RGB and IR identities
   first against the primary binding, then against an ACTIVE secondary
   store by STRICT equality of both sides: the group's `pair.rgb` and
   `pair.ir` must each be `Some` and equal to the configured identity.
   `GroupPair::matches` is not used here: it treats a missing side as
   unchecked, so a valid one-sided group `(None, IR-X)` would match any
   pair on IR-X. Exactly one strict match resolves; zero, or more than one
   (store validation does not forbid duplicate pairs), is refused as
   `BindingMismatch`, never resolved by store order. A configured pair that
   carries only an IR identity, or an IR identity shared by several groups
   whose RGB sides differ (ADR-0024 permits shared endpoints without
   merging groups), does not resolve either. The primary keeps precedence;
   no automatic movement to another group after a refusal (§5 unchanged).

2. A secondary match scores against that group's camera-scoped view: its
   own IR scans and its own `ir_calibs` for the live recognizer (§3), through
   the existing IR-only pipeline (detect, align, embed, adapt, identify) and
   the existing IR PAD gate. Account-level enrollment policy is checked
   against the REAL primary enrollment for every scope before any scoped
   view is built: `CameraGroupView::matching_enrollment` bridges a group
   with `..Enrollment::default()`, which clears account-level fields such
   as `require_eyes_open`, so running `legacy_eye_policy` on the bridged
   view would let a secondary attempt proceed where the same account's
   primary attempt is `IncompatibleEnrollment`. The readiness sequence is
   therefore: primary load, account policy on it, scope resolution, scoped
   view; a legacy-policy fixture pins this. No pooling: the primary's scans are not added to
   a secondary attempt and a secondary group's scans are never mixed into
   the primary's. The IR-only thresholds and the experimental-attempt
   evidence rules (ADR-0016) apply unchanged; a group whose view yields zero
   compatible IR templates is `IncompatibleEnrollment`, exactly as the
   primary would be.

3. Readiness codes: `BindingMismatch` now means the configured pair
   resolves to neither the primary binding nor an active secondary group
   (including the ambiguous and IR-only-identity cases above). Two causes
   that today collapse into it become distinct and camera-free:
   - the pair matches a secondary group but the store is inactive (the
     primary changed since authorization, §1.1): a new
     `SecondaryInactive` readiness, refused with "this camera's authorization
     is inactive since the primary enrollment changed; remove your added
     cameras and add back the ones you use, or use your password". The
     store carries ONE `primary_snapshot_sha256`, and `publish_camera_group`
     rewrites it for the whole store, so adding one camera into an
     inactive store would silently reactivate every other stale group,
     which ADR-0024 forbids (no automatic rebind). Phase 1 therefore adds a
     writer guard: adding a group into an inactive store is refused while
     any other stale group remains ("remove the other added cameras
     first"), so recovery is remove every retained group, then add back
     each wanted one under its own authorization. A rebind transaction is
     out of scope here;
   - the pair matches an authorized group whose IR view is empty:
     `IncompatibleEnrollment`, as above.
   Wire compatibility: `IrOnlyReadiness` has no `#[serde(other)]`
   fallback, so an older client would reject a whole `FaceSensorStatus`
   carrying an unknown readiness value. The existing `ir_readiness` field
   therefore keeps its current vocabulary: `SecondaryInactive` and
   `SecondaryUnvalidated` are sent there as `BindingMismatch`, which is
   what an older daemon would have said. The precise cause travels in a new
   optional field, `ir_readiness_detail`, absent on older daemons and
   ignored by older clients; new clients prefer it when present. The enum
   also gains a `#[serde(other)]` `Unknown` fallback so this class of
   incompatibility cannot recur. An old-client/new-daemon test decodes a
   new daemon's payload for each new value with a frozen copy of the
   pre-change types.

   Scope reporting: `CameraGroupId` is derived from the device identity
   (`derive_group_id` sanitizes `vid:pid[:serial]`), so it is not opaque
   and must not be printed. The wire gains an optional `ir_scope` of
   `primary` or `secondary`, with `ir_scope_index` (the group's 1-based
   position in the store) as the only handle: an ordinal, never an
   identity. `irlume auth sensor preflight` prints these. Making stored
   group ids genuinely opaque is an ADR-0024 follow-up, not this ADR. The
   refusal reasons keep the closed vocabulary and expose no identities.

4. Revocation at the grant boundary, for BOTH scopes. The IR-only path
   decides through `assessed_outcome` and does not pass the dual path's
   `authenticate_qualified_assessment`; that function also skips its
   boundary logic for primary attempts, so there is no existing primary
   boundary check for this path to inherit and a primary reset during an
   IR-only capture could grant from the stale in-memory enrollment.
   Immediately before every IR-only grant: the primary scope re-reads the
   primary file and requires its digest to equal the one pinned at load;
   the secondary scope additionally re-reads the secondary store and
   requires activation against the current primary and the pinned group's
   presence with the same strict pair. Any change refuses. The secondary
   check is the dual path's `grant_boundary_now_with` step, with the
   ADR-0025 request key.

5. The request key. `load_ir_enrollment` today discards the key its load
   returns, and preflight uses the read-only loader. Phase 1 adopts the key
   into the request-scoped `RequestTemplateKey` on the authentication path
   exactly as the dual path does (ADR-0025 §3), and reads the secondary store
   and the grant boundary through it, so an authentication request still
   unseals once. Preflight is not an authentication request: it adopts the
   key from its own read-only load for the duration of the call, so a
   preflight also unseals once, as it does today. The cost added by this ADR
   is file reads, not a TPM operation: a primary-scoped attempt adds one
   (the boundary re-read of the primary); a secondary-scoped attempt adds at
   least three (the secondary store at resolution, then both stores at the
   boundary), and the primary bytes pinned at load are retained so that
   count does not grow. Phase 2 measures the route as specified here.

6. Everything else stays: the account-level attempt budget, retry state and
   deadline are shared across scopes; the camera lease, the per-attempt
   pinning of scope before capture, and the rule that hotplug or
   configuration changes cannot redirect an attempt (§5) apply to the
   secondary scope as they do to the primary. The IR-only policy remains an
   owner opt-in marked experimental; this ADR widens which cameras it
   accepts, not what it claims.

7. Activation waits for hardware. ADR-0024's release gate requires hardware
   integration before a secondary-camera authentication route is enabled.
   Phase 1 lands with the secondary scope refusing as `SecondaryUnvalidated`
   ("IR-only on additional cameras is not yet validated on this build")
   unless the validation hook `IRLUME_IR_ONLY_SECONDARY=1` is set in the
   daemon's environment; the flip that removes the gate is its own change,
   made only after the Phase 2 evidence is recorded on the shared ledger and
   referenced from that change. Done: the gate and the hook are removed;
   the `SecondaryUnvalidated` readiness remains on the wire only so a Phase
   1 daemon's status still decodes.

## Consequences

- On a secondary IR camera, IR-only goes from a 143 ms policy refusal to the
  same attempt it makes on the primary. The expectation is an unlock of the
  order of the BRIO's 1.4 s; the NexiGo's actual figure is a Phase 2
  measurement, not a claim of this ADR.
- More authorized cameras mean more authorized IR-only capture paths, the
  same statement ADR-0024 §6 makes for the dual path. The secondary group's
  IR scans and calibration were captured and authorized as a credential
  operation; this ADR does not add an authorization surface, it stops
  ignoring one. Same-model units without a serial remain indistinguishable
  (ADR-0024 §6), for IR-only as for dual.
- The IR-only pipeline runs without the RGB PAD vote by design (ADR-0016);
  extending it to secondary cameras does not change that trade-off, and the
  experimental label stays.
- With the key threaded as in item 5, an authentication request still
  unseals once and gains one file read on the primary scope and at least
  three on a secondary scope; preflight is unchanged at one unseal. Without
  item 5 the route would pay a second unseal, which is why item 5 is a
  Phase 1 requirement and not an optimisation.

## Phasing

- Phase 1: strict-pair resolution against active secondary groups, account
  policy on the real primary, the scoped IR view, request-key adoption on
  both flows, the grant-boundary revalidation for both scopes, the
  readiness causes with the compatible wire mapping and `ir_scope` /
  `ir_scope_index` reporting, the inactive-store writer guard, unit tests,
  all behind the `SecondaryUnvalidated` gate.
- Phase 2: hardware confirmation on archhost (NexiGo secondary, BRIO
  primary) with the gate lifted through the validation hook, in both
  directions; the refusal causes exercised by deliberately invalidating the
  store (change the primary, observe `SecondaryInactive`; remove and add the
  camera, observe readiness); the boundary revalidation exercised by
  removing the group during a capture. Then the gate-removal change.
  Outcome (2026-09-23): NexiGo secondary granted IR-only 4/4, 5.04 s cold
  and 4.82–4.87 s warm (the camera's IR capture is ~4.5 s of it; resolution
  and scoring add under 250 ms); BRIO primary unchanged at 1.37 s warm;
  `SecondaryInactive` on a one-byte primary change; boundary refusal with
  the store removed 1.8 s into a capture; `SecondaryUnvalidated` with the
  hook off. The remove-and-add case was skipped by decision (it re-enrolls
  the group's scans for no measurement; the writer guard's positive path is
  unit-covered).

## Acceptance tests

- Resolution (pure): primary match → primary scope; strict secondary match
  in an active store → that group's scope; two groups sharing the IR
  identity with different RGB sides and a configured pair naming one of
  them → that one; the same two groups with a configured pair carrying
  only the IR identity → `BindingMismatch`; a one-sided group
  `(None, IR-X)` beside `(RGB-B, IR-X)` with configured `(RGB-B, IR-X)` →
  the two-sided one, and with configured `(RGB-A, IR-X)` → `BindingMismatch`
  (the one-sided group never wildcards); two groups with identical pairs →
  `BindingMismatch`; secondary match in an inactive store →
  `SecondaryInactive`; no match → `BindingMismatch`; matched group with an
  empty IR view → `IncompatibleEnrollment`; (Phase 1 only) gate set and no
  validation hook → `SecondaryUnvalidated`.
- Account policy: a legacy enrollment with `require_eyes_open` set is
  `IncompatibleEnrollment` on the secondary scope exactly as on the
  primary, checked on the real primary before the scoped view exists.
- Scope pinning: an attempt resolved to a group scores only that group's
  scans; a fixture with a primary scan that would match and a group scan
  that would not must refuse when the configured pair is the group's.
- Grant boundary: with a matching scoped assessment in hand, removing the
  group, replacing the secondary store, or changing the primary file
  before the grant step refuses; unchanged stores grant. On the primary
  scope, resetting or removing the primary enrollment during capture
  refuses.
- Writer guard: adding a camera into an inactive store that still holds
  another stale group is refused; after removing the others, adding works
  and activates only the added group's store snapshot.
- Wire: a new daemon's `FaceSensorStatus` for each new readiness value
  decodes with a frozen copy of the pre-change types (`ir_readiness` reads
  `binding_mismatch`, extra fields ignored); a new client reads the detail
  and the scope.
- Request key: the IR-only authentication path performs exactly one unseal
  with a secondary scope (counted through `RequestTemplateKey::unseals`),
  and preflight exactly one.
- Preflight names the scope and never opens a device (the existing #701
  guard test extended to the secondary branch); older clients ignore the
  new field.
- Hardware (Phase 2): on archhost, `ir-only` grants on the NexiGo with the
  BRIO-primary enrollment and its time is recorded; the BRIO figure is
  unchanged.
