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

So the one path that reaches a ~1.4 s unlock is unavailable on every camera
except the primary, although the same account has authorized the other pair
and the dual path already trusts it. A user who chose IR-only for its speed
and sits at a secondary camera gets the password every time.

"Re-enroll on this camera" is not an answer: ADR-0024 rejected separate
enrollments per camera (§6) and made adding a camera a credential operation
that produces a secondary group precisely so one account credential covers
all its cameras.

## Decision

1. IR-only target resolution consults the same authorization the dual path
   does. Given the configured IR target (explicit configuration only, as
   today: IR-only never discovers or opens a camera during preflight, the
   contract established for issue #701), the identity is matched first
   against the primary binding, then against the `pair.ir` identity of each
   group in an ACTIVE secondary store. The first match selects the
   enrollment scope; the primary keeps precedence; no automatic movement to
   another group after a refusal (§5 unchanged).

2. A secondary match scores against that group's camera-scoped view: its
   own IR scans and its own `ir_calibs` for the live recognizer (§3), through
   the existing IR-only pipeline (detect, align, embed, adapt, identify) and
   the existing IR PAD gate. No pooling: the primary's scans are not added to
   a secondary attempt and a secondary group's scans are never mixed into
   the primary's. The IR-only thresholds and the experimental-attempt
   evidence rules (ADR-0016) apply unchanged; a group whose view yields zero
   compatible IR templates is `IncompatibleEnrollment`, exactly as the
   primary would be.

3. Readiness codes: `BindingMismatch` now means the configured IR target
   matches neither the primary binding nor any active secondary group. Two
   causes that today collapse into it become distinct and camera-free:
   - the target matches a secondary group but the store is inactive (the
     primary changed since authorization, §1.1): a new
     `SecondaryInactive` readiness, refused with "this camera's authorization
     is inactive since the primary enrollment changed; re-add the camera or
     use your password";
   - the target matches an authorized group whose IR view is empty:
     `IncompatibleEnrollment`, as above.
   `irlume auth sensor preflight` reports the selected scope (primary or the
   group id) and these causes; the refusal reasons keep the closed
   vocabulary and expose no identities.

4. Everything else stays: the account-level attempt budget, retry state and
   deadline are shared across scopes; the camera lease, the per-attempt
   pinning of scope before capture, and the rule that hotplug or
   configuration changes cannot redirect an attempt (§5) apply to the
   secondary scope as they do to the primary. The IR-only policy remains an
   owner opt-in marked experimental; this ADR widens which cameras it
   accepts, not what it claims.

## Consequences

- On a secondary IR camera, IR-only goes from a 143 ms policy refusal to the
  same attempt it makes on the primary; on archhost that is a ~1.4 s unlock
  on the NexiGo instead of the password.
- More authorized cameras mean more authorized IR-only capture paths, the
  same statement ADR-0024 §6 makes for the dual path. The secondary group's
  IR scans and calibration were captured and authorized as a credential
  operation; this ADR does not add an authorization surface, it stops
  ignoring one. Same-model units without a serial remain indistinguishable
  (ADR-0024 §6), for IR-only as for dual.
- The IR-only pipeline runs without the RGB PAD vote by design (ADR-0016);
  extending it to secondary cameras does not change that trade-off, and the
  experimental label stays.
- One more unseal-free read: the secondary store is decrypted with the
  request key ADR-0025 already holds, so preflight and attempt cost do not
  grow beyond the file read.

## Phasing

- Phase 1: resolution against active secondary groups, the scoped view for
  IR-only, the two new readiness causes, preflight reporting, unit tests.
- Phase 2: hardware confirmation on archhost (NexiGo secondary, BRIO
  primary) in both directions, and the refusal causes exercised by
  deliberately invalidating the store (change the primary, observe
  `SecondaryInactive`, re-add the camera, observe readiness).

## Acceptance tests

- `enrollment_readiness` (pure): primary match → ready; secondary match in
  an active store → ready with that group's scope; secondary match in an
  inactive store → `SecondaryInactive`; no match → `BindingMismatch`;
  matched group with an empty IR view → `IncompatibleEnrollment`.
- Scope pinning: an attempt resolved to a group scores only that group's
  scans; a fixture with a primary scan that would match and a group scan
  that would not must refuse when the live IR camera is the group's.
- Preflight names the scope and never opens a device (the existing #701
  guard test extended to the secondary branch).
- Hardware: on archhost, `ir-only` grants on the NexiGo with the
  BRIO-primary enrollment, and the BRIO figure is unchanged.
