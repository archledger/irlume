# ADR-0024: Multi-camera enrollment under enrolled-camera-set binding

## Status

Proposed. Design grounded in source verification at main bcc26a5's parent
(2026-09-16) and the measured Windows Hello reference (a user enrolled on
one camera authenticates on another; 2026-09-15 ThinkPad session).
Implementation is phased; nothing ships until Phase 1's invariants are
tested. Numbered after ADR-0023; independent of ADR-0022's acceptance.

## Context

An enrollment is bound to ONE physical camera pair: `CameraBinding { rgb,
ir }` captures the pair's device identities at enroll time, and every
authentication verifies the live cameras match exactly, refusing otherwise
(anti-swap: a swapped or virtual camera never scores against the
enrollment). `FaceScan` records no camera origin; matching selects scans by
recognizer embedding space, not by camera; `pitch_neutral` (the frontal
framing calibration) is the median across ALL of a user's scans.

Windows Hello takes the opposite position: templates are sensor-agnostic,
and the sensor is chosen at authentication time (measured: enrollment on a
BRIO authorized unlocks with a NexiGo N930W preferred). For irlume that
free cross-sensor reuse is unavailable BY DESIGN, and copying it would
weaken the anti-swap control and mix calibration across cameras with
different geometry and IR response.

The workflow gap is real all the same: a user with a laptop (built-in
camera) and a desk (external camera) must choose one camera for face auth
or re-enroll to move between them.

## Decision

### 1. Bind an enrollment to a SET of camera pairs

`CameraBinding` grows an additive `additional` list (serde-defaulted); the
existing `rgb`/`ir` fields remain the FIRST entry, so a downgrade binary
reads today's shape exactly. Authentication refuses unless the live pair
matches ANY bound entry exactly. Anti-swap is unchanged in strength: an
unknown camera is refused just as today; the set only grows through the
attended flow below.

Downgrade behavior (stated, accepted): an older binary verifies only the
first (legacy) pair, so secondary cameras simply fail closed on old
binaries. No secondary-camera authentication is possible without the new
code.

### 2. Scans record their capturing camera

`FaceScan` grows `#[serde(default)] camera: Option<String>` (the
`device_identity` string). New scans record it; `None` means legacy or
unattributed and is treated as belonging to the first bound pair.

### 3. Matching and calibration are per camera group

- RGB and IR candidate scans are filtered to the ACTIVE camera's group
  before scoring: a probe captured on one camera is never scored against
  another camera's scans (the deliberate difference from Windows).
- The per-camera scan count must independently clear the existing
  minimum-pairs floor before that camera may authenticate (fail-closed per
  camera: a newly added camera with too few scans refuses, it never
  dilutes the primary's threshold either).
- `pitch_neutral` is computed per (profile, camera) from that group's
  scans; the merged median remains only for `None`-camera legacy scans.
- IR calibration (ADR-0004, per recognizer) is fitted from the active
  camera group's scans for that camera's authentication; per-scan
  `ir_center_edge_ratio`/`ir_brightness` already carry camera-specific
  signal and are unaffected.

### 4. Adding a camera is an attended enrollment flow on that camera

`irlume enroll --add-camera` (after `set-cameras` names the new pair):
captures IMPROVE_SCANS (5) quality-gated scans ON the new pair, appends
them tagged with that camera, and extends the binding set. The same
consent and supervision as any enrollment capture; a camera can never
silently join the set. Removing a camera (`irlume profiles` surface)
drops its scans and binding entry.

### 5. Surfaces

`status`/`doctor`/`profiles` list enrolled cameras with per-camera scan
counts and calibration state. The daemon's camera inventory already
distinguishes cameras; the auth path picks the pair in the bound set that
is currently connected when more than one is (deterministic order:
legacy first, then sorted identity).

## Phasing

- Phase 1 (invariants, no UX): storage types with additive serde defaults;
  binding-set verification; per-camera scan filtering; per-camera
  pitch/calibration; per-camera floor. All unit-tested against downgrade
  shapes (an old-binary write must still load; a new-binary write with
  `additional` must load on the legacy code path).
- Phase 2: `enroll --add-camera` flow + removal + status surfaces.
- Phase 3 (only if measured to matter): per-camera threshold tuning from
  the ADR-0023 evidence base.

## Consequences

- Positive: the laptop-plus-desk workflow without re-enrollment; each
  camera's calibration stays honest; anti-swap strength unchanged;
  downgrade fails closed on secondary cameras.
- Costs: enrollment storage grows a per-scan field and a binding list;
  matching gains a group filter; the add-camera flow is new UX surface.
- Risks and mitigations: mixing groups would recreate the Windows
  cross-sensor hazard - prevented by construction (filter before scoring);
  sparse secondary sets weakening security - prevented by the per-camera
  floor; threshold drift from split scan pools - mitigated by per-camera
  counts feeding the existing threshold formula (Phase 3 only if measured).
- Alternatives considered: Windows-style sensor-agnostic templates
  (rejected: weakens anti-swap and mixes calibration); N enrollments
  selectable by camera (rejected: multiplies secrets, no single retry
  state, and the UX already failed the user in practice); auto-enrolling
  any newly seen camera (rejected: violates attended-consent).

## Open questions for review

- IMPROVE_SCANS (5) as the add-camera scan count, or the full
  DEFAULT_ENROLL_SCANS (10) for parity of per-camera floors?
- Whether the daemon should prefer a connected camera whose group has MORE
  scans when several bound cameras are simultaneously connected, or keep
  deterministic legacy-first ordering and let the pair selection follow
  the operator's `set-cameras`.
- Whether `enroll --add-camera` should require sudo parity with
  `set-cameras` (binding the machine's auth surface) or user-level consent
  like scan improvement.
