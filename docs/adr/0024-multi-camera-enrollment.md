# ADR-0024: Multi-camera enrollment under enrolled-camera-set binding

## Status

Proposed. Revised after an external design review (second revision basis:
source verification at d4bc0f1's parent, 2026-09-16, plus the measured
Windows observation below). Implementation phased; Phase 1 gates include
the acceptance-test table at the end. Numbered after ADR-0023; independent
of ADR-0022's acceptance.

## Context

An enrollment is bound to ONE physical camera pair: `CameraBinding { rgb,
ir }` captures the pair's device identities at enroll time, and every
authentication verifies the live cameras match exactly (anti-swap).
`FaceScan` records no camera origin; scan selection filters by recognizer
embedding space, not camera; `pitch_neutral` and the personalized IR
ratio floor (`ir_center_edge_ratio_floor`, the 75%-of-minimum over ALL
scans of ALL profiles) are pooled across everything today. The enrollment
serialization applies no `deny_unknown_fields`, so unknown fields are
silently ignored by older readers - which is exactly why naive additive
fields cannot carry camera isolation (see the storage decision).

On the tested Windows configuration (2026-09-15 ThinkPad session),
enrollment performed using one camera permitted authentication using
another. That is recorded as a workflow observation - what it says about
Windows' internal template representation, policy generality, or spoof
resistance is not established. What it motivates here is the workflow:
one account, a laptop camera and a desk camera, no re-enrollment dance.

## Decision

### 1. Storage: secondary cameras live where pre-multi-camera binaries
never read

Additive fields inside today's enrollment file are REJECTED as the
compatibility mechanism: an old binary verifies only the legacy pair (so
secondary cameras cannot open), but its matching selects scans by
embedding space and would score a primary-camera probe against secondary
cameras' scans, and an old writer's round trip silently drops per-scan
camera tags and reattributes those scans to the primary. Both holes are
properties of the shipped readers, not of the new code.

Instead: the existing enrollment file remains the PRIMARY camera group's
complete store - primary scans, primary binding, primary-derived state -
exactly as today, so old binaries read a genuinely single-camera
enrollment. Multi-camera data (secondary groups: their bindings, scans,
calibration, derived state) lives in a separate store the old code never
opens. The new implementation composes the two views. Contract:

- Legacy single-camera enrollments remain readable by the new
  implementation (imported as the primary group with an immutable
  legacy-group reference).
- Pre-multi-camera readers see only primary-camera data and state;
  secondary-camera authentication on them fails closed with password
  fallback intact.
- Old-writer round trips can only ever touch primary data; secondary data
  is untouched by construction.
- The multi-camera store carries its own format version; the new reader
  refuses unsupported versions rather than partially loading.

### 2. Camera groups: the authorization unit is the complete role-labelled
pair

A group is a stable record of the exact `{ rgb identity, ir identity }`
pair, each side the `device_identity` string with its role. Scans
reference their group by an immutable group reference that resolves to
that complete pair - never a bare single-device string (two authorized
pairs sharing one RGB node must keep separate IR calibration domains,
and vice versa). Authentication requires the live pair to match a group's
COMPLETE pair: enrolling (RGB-A, IR-A) and (RGB-B, IR-B) never authorizes
the hybrid (RGB-A, IR-B).

Legacy scans without provenance are attributed only through an immutable
legacy-group reference established at import; reordering, promoting, or
removing groups never reattributes retained scans. A legacy enrollment
with no usable binding preserves its scans without invented provenance
and requires attended migration or fresh capture before multi-camera
authentication. For new records, a missing or unresolvable group
reference is invalid data, not "use the primary".

### 3. A camera-scoped enrollment view feeds scoring and calibration

Rather than hoping every caller remembers an optional filter, the
implementation exposes a validated view of the enrollment scoped to
(profile, camera group, compatible pipeline), consumed by matching and
calibration. Required scopes:

| Derived state or operation | Scope |
|---|---|
| RGB and IR template selection | active group + existing recognizer/IR-space/dimension checks |
| Calibration fitting and retrieval | profile, group, recognizer/pipeline, scan revision (the per-recognizer calibration map extends its key with the group; the legacy mirror slot stays primary-only) |
| Personalized IR ratio floor | only the active group's applicable scans (today it pools every scan of every profile) |
| Pitch neutral | per (profile, group); legacy pooled behavior only for unattributed legacy scans |
| Centroids and template aggregates | built after group and embedding-space filtering |
| Threshold-scaling counts | the candidates the scoring arm actually evaluates |
| Readiness and limits | per (profile, group, pipeline); bounded overall storage |

A new group bootstraps with the existing fresh-enrollment defaults (no
borrowed primary calibration). Eligibility predicates are stated
explicitly: the capture target (DEFAULT_ENROLL_SCANS quality-gated
scans), the calibration-fit minimum (MIN_FIT_PAIRS), and authentication
readiness (compatible-template availability) are distinct - a group with
ten scans but too few compatible IR pairs is not a fully ready group.

### 4. Adding a camera is a credential-management operation

Adding a group requires fresh authorization to modify the target
account's biometric enrollment, independent of the proposed camera (the
new camera never authorizes its own addition), enforced by the daemon and
scoped to target account, profile, exact group, and operation. Attended
capture and quality checks are additional requirements, not substitutes.
The boundary is described in policy terms (equivalent to modifying
biometric credentials); whether the CLI uses an elevated invocation or
the TUI a graphical prompt is an implementation detail that must satisfy
the same daemon-enforced policy. Machine-wide camera configuration
(set-cameras) and account enrollment authorization stay distinct.

Publication is atomic: new scans, binding, calibration, and readiness
become active together, via the existing publication and locking
facilities, with a revision check - capture runs against a defined
enrollment revision, and a conflicting mutation during the attended
capture never silently overwrites newer state. Removal removes the
group's binding, scans, and derived state together without reassigning
anything; it invalidates in-flight use so no stale cached group can
issue a new grant. Pair selection during the flow is transaction-scoped
(the operator's default pair selection is not silently changed by an
interrupted flow); making a new pair the default is an explicit
subsequent choice.

### 5. Pair selection and attempt lifecycle

An explicitly configured enrolled pair takes precedence when available
and eligible; otherwise an explicit automatic-selection policy chooses a
complete eligible enrolled pair in a stable documented order
(legacy-group first). The pair is pinned before scoring: no silent
movement to another camera after a mismatch or PAD refusal, no combining
evidence across pairs in one attempt, and all camera paths share the
existing account-level attempt budget, retry state, and deadline
(availability fallback is not "try every camera until one accepts").

### 6. Claims, precisely

Exact matching against explicitly enrolled camera-group identities is
preserved, under the existing device-identity representation
(vid:pid[:serial]) and trusted-host assumptions: this ADR introduces no
cryptographic hardware attestation, and where a serial is absent the
identity cannot distinguish same-model units - a pre-existing property
restated here, not a regression. More authorized cameras mean more
authorized capture paths; no claim is made that aggregate biometric error
rates are unchanged. The rejected separate-enrollments alternative is
rejected for UX and state-management reasons (one credential and retry
state per account), not because N secrets are unavoidable.

### 7. Thresholds: formulas yes, policy no

Computing the EXISTING threshold formulas from camera-filtered candidate
counts is part of Phase 1 (each count keeps the meaning its scoring arm
already assigns it). Introducing camera-specific biometric or PAD
threshold POLICY is out of scope: it would require a separate decision
and security evaluation (genuine users, impostors, presentation attacks,
capture conditions). ADR-0023 capture evidence may describe experimental
conditions; it does not authorize threshold changes.

## Phasing

- Phase 1: the storage boundary (primary store + multi-camera store with
  version refusal), group records, camera-scoped view, per-group
  derived state, and the acceptance tests below - no UX.
- Phase 2: the add/remove flows, authorization, atomic publication, and
  status surfaces.
- Phase 3: none. (Formerly "per-camera thresholds": removed per §7.)

## Acceptance tests (Phase 1 gates)

| Boundary | Required result |
|---|---|
| Actual legacy reader and writer | Secondary templates and derived state never affect primary-camera authentication on old binaries; downgrade/re-upgrade cannot erase provenance or reattribute scans |
| Exact pair membership | Enrolling pairs A and B never authorizes a hybrid of their endpoints |
| Camera and pipeline isolation | Foreign-group scans cannot influence scores, centroids, calibration, ratio floors, or threshold counts |
| Legacy migration and primary removal | Reordering or removing the primary never changes retained scans' origin; ambiguous provenance is not invented |
| Per-profile/group readiness | Incomplete or incompatible secondary groups cannot borrow another group's scans to satisfy eligibility |
| Authorization and atomicity | Unauthorized, cancelled, interrupted, or conflicting additions never partially expand the binding set |
| Selection and attempt lifecycle | Explicit preference honored; selection pinned; hotplug or configuration changes cannot silently redirect an attempt |
| Removal and shared budgets | Removed groups cannot grant through stale state; camera switching does not reset retry limits or deadlines |

Hardware integration then verifies the laptop-plus-desk workflow: both
cameras connected, disconnect/reconnect, enrollment cancellation, and
the applicable RGB/IR authentication modes.

## Consequences

- Positive: the laptop-plus-desk workflow with one credential and retry
  state; honest per-camera calibration; exact-pair authorization;
  fail-closed interaction with every pre-multi-camera binary.
- Costs: a second enrollment store and a synchronization contract; the
  camera-scoped view touches every scoring and calibration consumer;
  the add/remove flows are new authorization-bearing surface.
- Risks and mitigations: group mixing (prevented by the validated view);
  sparse secondary sets weakening security (per-group floors and the
  ten-scan target); storage growth (bounded overall limits); downgrade
  confusion (the storage boundary makes old-binary behavior provably
  primary-only).
- Alternatives considered: Windows-style sensor-agnostic templates
  (rejected: crosses the exact-pair authorization line this design
  keeps); N user-facing enrollments (rejected for UX and state
  management); additive in-file fields (rejected: verified to leak
  secondary templates into old readers' matching).
