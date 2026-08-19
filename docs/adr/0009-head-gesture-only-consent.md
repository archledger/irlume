# ADR-0009: Head-gesture-only consent

**Status:** Accepted
**Date:** 2026-08-19

## Context

irlume had three user-performed eye mechanisms: a natural-blink challenge, an
eyes-open policy, and calibrated held-eye closure as an approving consent
gesture. None met the reliability bar for authentication:

- the natural-blink gate produced no verdict in 11 of 11 genuine daemon-path
  attempts after closing the vinyl-print breach in a small validation set;
- the eyes-open evaluator admitted only 1 of 72 genuine detected frames in its
  committed corpus, while a live session also granted with the eyes closed
  behind glasses;
- one subject's median open eye-aspect ratio shifted from 0.109 to 0.166 between
  lighting conditions, and glasses moved the held-closure median from 0.048 to
  0.090.

These measurements are preserved in [ADR-0002](0002-challenge-response-liveness.md),
the dated [PAD results](../pad-results/), and the
[removal-impact research](../research/2026-08-18-head-gesture-only-removal-impact.md).
The approved implementation contract is the
[head-gesture-only retirement design](../superpowers/specs/2026-08-19-head-gesture-only-retirement-design.md).

## Decision

When a service policy requires deliberate consent, repeated or continuous head
nodding is the only approving action. A deliberate head shake declines the face
attempt. The gesture proves intent; it is not liveness or presentation-attack
detection.

Service policy does not change. Elevation and polkit services require the head
gesture by default. Lock-screen and cold-login gesture gates remain off by
default and may be enabled per service. TPM-sealed keyring credential release
also remains off by default and may be enabled separately for a cold keyring.
Existing per-service overrides remain.

Automatic passive PAD stays independent and mandatory. RGB/IR co-location,
frontality, exposure checks, IR reflectance and falloff, passive corneal-glint
evidence, camera binding, and optional deny-only PAD keep their existing roles.
FaceMesh, its TFLite runtime, and BlazeFace remain dense-landmark and
rescue-alignment infrastructure; head consent uses the primary detector's five
landmarks.

This retirement is fail closed for one minor release:

- absent or legacy `consent_gesture=nod` configuration selects head-only
  consent;
- legacy `consent_gesture=closure`, `IRLUME_CONSENT_GESTURE=closure`, malformed
  values, and stored `require_eyes_open=true` block the face path with migration
  instructions rather than being reinterpreted;
- `SetRequireEyesOpen`, `CaptureEarMedian`, and `SetClosureCalibration` remain
  wire-compatible tombstones. Only `SetRequireEyesOpen { on: false }` may change
  state, to clear the legacy blocker; calibration tombstones do not capture or
  write;
- machine API contract 1 keeps `require_eyes_open` and `require_challenge` and
  emits both as `false`.

The tombstones and legacy blocker may be removed after that release window.
Contract 2 may then omit the frozen fields. Historical enrollment eye data is
ignored for authorization and removed by the next ordinary atomic enrollment
save; package installation and daemon startup do not bulk-rewrite enrollments.

Nod and shake thresholds are not retuned by this decision. Their existing
hardware-calibrated defaults and overrides remain.

## Consequences

- No supported setup, enrollment, recovery, or authorization path asks for an
  eye action or calibration.
- An early nod still proceeds through capture, matching, PAD, camera binding,
  rate limiting, and biopolicy. It cannot grant by itself.
- On polkit, a shake retains the existing `PAM_ABORT` behavior. Other PAM
  services deny the face attempt and preserve password or fingerprint fallback.
- A rollback before an enrollment is rewritten can expose its old stored eye
  state to an old binary. After the next save, old binaries read the missing
  fields at their false/empty defaults.
- Removing the mesh model or TFLite runtime is outside this decision because it
  would remove BlazeFace rescue alignment.
