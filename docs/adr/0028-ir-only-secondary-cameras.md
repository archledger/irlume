# ADR-0028: IR-only authentication honours enrolled secondary IR cameras

## Status

Proposed 2026-09-22. Amends ADR-0024 (multi-camera enrollment) §5 for the
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
   store through the existing `group_for_pair` exact match on the complete
   pair. A configured pair that carries only an IR identity, or an IR
   identity shared by several groups whose RGB sides differ (ADR-0024
   permits shared endpoints without merging groups), does not resolve: it
   is refused as `BindingMismatch`, never resolved by store order. The
   primary keeps precedence; no automatic movement to another group after
   a refusal (§5 unchanged).

2. A secondary match scores against that group's camera-scoped view: its
   own IR scans and its own `ir_calibs` for the live recognizer (§3), through
   the existing IR-only pipeline (detect, align, embed, adapt, identify) and
   the existing IR PAD gate. No pooling: the primary's scans are not added to
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
     is inactive since the primary enrollment changed; remove the camera and
     add it again, or use your password". Remove-then-add is the recovery
     because the retained inactive group makes `add` refuse the same pair as
     already enrolled; a credential-authorized rebind operation is out of
     scope here;
   - the pair matches an authorized group whose IR view is empty:
     `IncompatibleEnrollment`, as above.
   Reporting: the preferences/status wire gains an optional
   `ir_scope` field beside `ir_readiness`, either `primary` or the group's
   opaque `CameraGroupId` (an id, never a device identity), absent on older
   daemons and ignored by older clients. `irlume auth sensor preflight`
   prints it. The refusal reasons keep the closed vocabulary and expose no
   identities.

4. Revocation at the grant boundary. The IR-only path decides through
   `assessed_outcome` and does not pass the dual path's
   `authenticate_qualified_assessment`, so pinning a scoped view at capture
   time would not by itself inherit ADR-0024's guarantee. Immediately before
   every IR-only grant, both stores are re-read and re-validated: the
   primary's bytes against the pinned digest, the secondary store's
   activation against the current primary, and the pinned group's presence
   and pair; any change refuses. For the primary scope the existing primary
   boundary check applies. This is the same `grant_boundary_now_with` step
   the dual path runs, with the ADR-0025 request key.

5. The request key. `load_ir_enrollment` today discards the key its load
   returns, and preflight uses the read-only loader. Phase 1 adopts the key
   into the request-scoped `RequestTemplateKey` on the authentication path
   exactly as the dual path does (ADR-0025 §3), and reads the secondary store
   and the grant boundary through it, so an authentication request still
   unseals once. Preflight is not an authentication request: it adopts the
   key from its own read-only load for the duration of the call, so a
   preflight also unseals once, as it does today. The cost added by this ADR
   is two file reads, not a TPM operation.

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
   referenced from that change.

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
  unseals once and gains two file reads; preflight is unchanged at one
  unseal. Without item 5 the route would pay a second unseal, which is why
  item 5 is a Phase 1 requirement and not an optimisation.

## Phasing

- Phase 1: exact-pair resolution against active secondary groups, the
  scoped IR view, request-key adoption on both flows, the grant-boundary
  revalidation, the readiness causes and `ir_scope` reporting, unit tests,
  all behind the `SecondaryUnvalidated` gate.
- Phase 2: hardware confirmation on archhost (NexiGo secondary, BRIO
  primary) with the gate lifted through the validation hook, in both
  directions; the refusal causes exercised by deliberately invalidating the
  store (change the primary, observe `SecondaryInactive`; remove and add the
  camera, observe readiness); the boundary revalidation exercised by
  removing the group during a capture. Then the gate-removal change.

## Acceptance tests

- Resolution (pure): primary match → primary scope; exact secondary match
  in an active store → that group's scope; two groups sharing the IR
  identity with different RGB sides and a configured pair naming one of
  them → that one; the same two groups with a configured pair carrying
  only the IR identity → `BindingMismatch`; secondary match in an inactive
  store → `SecondaryInactive`; no match → `BindingMismatch`; matched group
  with an empty IR view → `IncompatibleEnrollment`; gate set and no
  validation hook → `SecondaryUnvalidated`.
- Scope pinning: an attempt resolved to a group scores only that group's
  scans; a fixture with a primary scan that would match and a group scan
  that would not must refuse when the configured pair is the group's.
- Grant boundary: with a matching scoped assessment in hand, removing the
  group, replacing the secondary store, or changing the primary file
  before the grant step refuses; unchanged stores grant.
- Request key: the IR-only authentication path performs exactly one unseal
  with a secondary scope (counted through `RequestTemplateKey::unseals`),
  and preflight exactly one.
- Preflight names the scope and never opens a device (the existing #701
  guard test extended to the secondary branch); older clients ignore the
  new field.
- Hardware (Phase 2): on archhost, `ir-only` grants on the NexiGo with the
  BRIO-primary enrollment and its time is recorded; the BRIO figure is
  unchanged.
