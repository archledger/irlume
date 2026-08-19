# Head-gesture-only retirement design

Date: 2026-08-19

Status: approved design, awaiting implementation plan

Research basis: [Head-gesture-only removal impact](../../research/2026-08-18-head-gesture-only-removal-impact.md)

## Decision

irlume will retire every user-performed eye challenge and keep one deliberate
consent mechanism:

- repeated or continuous head nodding approves a gesture-gated face request;
- a deliberate head shake declines the face request;
- no supported path asks the user to blink, close their eyes, keep their eyes
  open, hold an eye pose, or calibrate an eye measurement;
- automatic presentation-attack detection and passive liveness remain mandatory
  and independent of the consent gesture.

This is a staged, fail-closed retirement. Eye actions stop authorizing in the
first release, while small compatibility tombstones remain for one minor release
so existing configuration, enrollment state, daemon clients, and machine API
consumers receive safe and actionable behavior.

## Motivation

The eye mechanisms do not meet the reliability bar for an authentication
product:

- deliberate closure depends on a per-user EAR calibration;
- lighting and eyewear move the measured open/closed ranges enough to reject a
  genuine user;
- the legacy eyes-open gate already refuses new enables after measured genuine
  failures;
- the natural-blink challenge has already been retired from authorization but
  left substantial dead detector and research code behind.

Head pose is measured from the primary detector's five landmarks. It requires no
per-user calibration and is already hardware-calibrated before release. Removing
the eye branches also stops the consent watch from running FaceMesh and building
EAR samples on every frame when only a nod is needed.

## Goals

1. Make nod the only approving gesture and shake the only declining gesture.
2. Preserve the existing per-service policy defaults and user overrides.
3. Remove every eye detector from authorization and every normal eye setup
   surface.
4. Preserve passive PAD, cross-spectrum checks, corneal-glint evidence, and
   FaceMesh rescue alignment.
5. Migrate legacy restrictive choices without silently widening them.
6. Preserve mixed-version daemon compatibility and machine API contract 1.
7. Retain one head-only developer tool for pre-release hardware calibration and
   regression capture.
8. Leave the repository with no active or misleading eye-feature code, help,
   packaging description, or current documentation.

## Non-goals

- Do not retune nod or shake thresholds in this change.
- Do not change which services require a gesture by default.
- Do not make nod or shake part of presentation-attack detection. They prove
  user intent, not that the presentation is live.
- Do not remove FaceMesh, the TFLite runtime, or the mesh model; rescue alignment
  still uses them.
- Do not rewrite historical changelogs, ADR evidence, or dated research as if
  the removed experiments never existed.
- Do not publish machine API contract 2 in the first retirement release.
- Do not broaden a head-shake into `PAM_ABORT` for every PAM service. Only the
  existing polkit path aborts the stack; other services deny the face attempt
  and preserve password or fingerprint fallback.

## Target authentication policy

The service-policy decision remains separate from gesture classification.

| Authentication surface | Default | User control | Required action |
|---|---:|---|---|
| `sudo`, `sudo-i`, `su`, `su-l`, `runuser`, `runuser-l`, `doas` | Head gesture on | May disable per service after a risk warning and explicit confirmation | Keep nodding to approve; shake to decline the face attempt |
| `polkit-1` / `polkit` app consent | Head gesture on | May disable after a risk warning and explicit confirmation | Keep nodding to approve; shake maps to the existing polkit `PAM_ABORT` path |
| Lock screen | Head gesture off | May opt in through the per-service policy | If enabled, nod approves and shake declines the face attempt |
| Cold login after reboot or logout | Face-login gesture off | May opt in for the relevant service | Face matching itself does not require a gesture by default |
| TPM-sealed keyring credential release | Head gesture off | May opt in through `service_gesture.credential_release` or the existing global fallback | One nod confirms release only when the keyring is cold; a warm/unlocked keyring performs no release and asks for no gesture |

Disabling a gesture on an elevation or app-consent service must keep the current
warning: a face match alone would approve that privileged action, and a printed
face presented to the camera could therefore reach the remaining passive PAD
boundary. The user must confirm before the setting changes. Enabling a gesture
needs no confirmation because it only adds an intent step.

## Head-consent state machine

### Typed result

Replace the current boolean result plus `gesture_cancelled` side state with one
typed result used at every boundary:

```rust
enum HeadConsentVerdict {
    Approve,
    Decline,
    NoGesture,
}
```

The exact name may follow repository conventions, but the three states must not
collapse into a boolean.

### Ordering and terminality

For every rolling and completed take:

1. Classify shake-shaped yaw before nod-shaped pitch.
2. Return `Decline` immediately for a deliberate shake.
3. Return `Approve` for a nod only when no shake verdict applies.
4. Return `NoGesture` for stillness, ordinary look-around motion, insufficient
   frames, or an exhausted window.

`Decline` and `Approve` are terminal. A completed-take fallback must never
re-evaluate a terminal result. The completed-take boundary must classify both
nod and shake so a shake completed in the final one-to-five frames is reported
as a deliberate decline rather than a generic timeout.

### Capture and authorization flow

- Run the early head-consent watch only when the resolved service policy requires
  it.
- Derive pose from the primary detector's five landmarks; do not run FaceMesh or
  compute EAR in the head watch.
- Preserve per-frame cancellation/preemption checks and the existing bounded
  total watch budget.
- An early nod records consent but never bypasses capture, face matching, PAD,
  camera binding, rate limiting, or biopolicy.
- An early shake ends the face request before matching.
- A post-match nod grants only the already-live, already-matched outcome.
- A post-match shake converts the outcome to the typed gesture-decline result.
- Clear all request-scoped gesture state before the next authentication.

## Passive security boundary that remains

The retirement must leave these protections unchanged:

- RGB/IR face presence and co-location;
- frontality and usable exposure checks;
- camera identity binding;
- IR reflectance and center/edge falloff;
- dark IR-only decision policy;
- RGB-only deterrent cues;
- passive `ir_eye_glint` measurement and trace evidence;
- optional deny-only third-party PAD;
- camera lease, provenance, cancellation, and bounded retry behavior;
- password and fingerprint fallback.

The separate `both_eyes_open` policy evaluator is removed. The supporting
corneal-glint signal is retained because it is automatic evidence and does not
ask the user to perform or calibrate an eye action.

FaceMesh remains loaded for BlazeFace rescue alignment. Its health, packaged
model, native runtime, and fallback behavior must be described as landmark and
rescue infrastructure rather than closure or passive-blink infrastructure.

## Legacy configuration migration

`service_gesture.*`, `polkit_gesture`, `credential_release_challenge`, and their
current environment overrides remain. They answer whether a head-consent gate
exists.

`consent_gesture` and `IRLUME_CONSENT_GESTURE` become transitional legacy input:

| Legacy value | First retirement release |
|---|---|
| absent | Head-only gate operates normally |
| `nod` | Head-only gate operates normally; diagnostics may say the key is now redundant |
| `closure` | No gesture is accepted for a required gate; face authentication falls back to password with an actionable instruction to remove the key or set `nod` |
| malformed or any other value | Continue to fail closed with an actionable configuration error |

No code may reinterpret `closure` as nod. That would silently widen an explicit
operator-selected policy.

After one documented minor-release compatibility window, remove this legacy
decoder and the accepted-method setting entirely. Nod is then fixed behavior,
not a configurable mode.

Remove all closure- and blink-only threshold variables in the first release:

- `IRLUME_CONSENT_CLOSURE_FRAMES`;
- `IRLUME_CONSENT_CLOSURE_MAX`;
- `IRLUME_BLINK_MOTION_MAX`;
- `IRLUME_BLINK_CONTRAST_DROP`;
- `IRLUME_BLINK_CONTRAST_MOTION_FLOOR`.

Keep the nod, shake, watch-budget, and pose-dump variables. Their validation and
hardware-calibrated defaults do not change.

## Legacy enrollment migration

### First retirement release

Keep reading `require_eyes_open` and `closure_calibration` only for migration.
Neither value may run an eye evaluator or authorize an eye action.
Represent them as deserialization-only legacy state (or an equivalent custom
migration view): new serialization must omit both fields even while the first
release can still inspect an old file. This is what makes the next ordinary,
atomic enrollment save perform the lazy cleanup.

For `require_eyes_open=true`:

- treat it as a legacy policy blocker;
- deny the face path with an actionable message;
- preserve password and fingerprint fallback;
- retain only the existing OFF operation so the user can explicitly clear the
  old restrictive policy;
- continue refusing ON.

For `closure_calibration`:

- ignore it for authorization;
- do not expose normal capture, replacement, status, or calibration UI;
- remove it lazily on the next ordinary enrollment save;
- do not bulk-decrypt and rewrite every enrollment during package installation
  or daemon startup.

The store is JSON, including the decrypted inner payload of encrypted
enrollments. Removed named fields are ignored by a new reader, while old readers
already default missing `require_eyes_open` and `closure_calibration` to
`false`/`None`. Add explicit plaintext and encrypted round-trip tests rather
than relying on this property implicitly.

Release notes must state that a rollback before an enrollment rewrite can expose
the old stored eye state again. After a new save, the retired values are gone;
an old binary reads their defaults.

### Following release

After the compatibility window, remove the storage fields and legacy blocker.
Contract-1 compatibility output remains a machine adapter concern and must not
keep the enrollment feature alive.

## Daemon IPC and mixed-version compatibility

Keep these request variants for one minor release as nonfunctional tombstones:

- `SetRequireEyesOpen`;
- `CaptureEarMedian`;
- `SetClosureCalibration`.

Behavior:

- `SetRequireEyesOpen { on: false }` clears the legacy blocker idempotently;
- `SetRequireEyesOpen { on: true }` returns a precise retired-feature error;
- both calibration requests return a precise retired-feature error;
- calibration tombstones never open a camera and never write enrollment data;
- retain the existing authorization posture for every tombstone so removal does
  not create an unauthenticated oracle.

Keep `Response::Enrollment.require_eyes_open` and emit `false`. Old clients
require the field and cannot deserialize a reply that omits it. Keep or omit
`closure_calibrated` according to old-client tests; it already defaults on
deserialization, but emitting `false` during the same compatibility window is
the least surprising behavior as long as no current UI recommends calibration.

Package upgrades must restart a running daemon so the old authorization engine
cannot survive while the new CLI claims head-only behavior. Mixed-version tests
remain necessary because package restart hooks are best-effort and intentionally
do not start a daemon the operator stopped.

## Machine API contract

Contract 1 remains the default and only published contract in the first
retirement release. `profiles list --json` must continue to emit:

```json
{
  "require_eyes_open": false,
  "require_challenge": false
}
```

Both fields remain required by the contract-1 schema. Their values are frozen
compatibility tombstones and must not be derived from enrollment state.

Contract 2, in the following release, may omit the retired fields. Contract 1
must continue returning its documented shape for as long as the product claims
to support it.

## CLI, TUI, doctor, and PAM

### Remove

- public `calibrate-closure` dispatch, help, measurement mode, overwrite flow,
  and tests;
- normal `profiles eyes-open` UI except the temporary OFF migration command;
- TUI eyes-open settings row and calibration action;
- closure-calibrated status, doctor guidance, and dashboard state;
- closure-mode PAM wording and suppression of shake instructions;
- active help or documentation that offers blink or closure as supported.

### Retain and clarify

- per-service enable/disable controls;
- the separate cold keyring-release opt-in;
- warning and confirmation before disabling high-privilege gates;
- unconditional prompt wording: keep nodding to approve; shake to decline;
- `AuthResult.declined_by_gesture` and machine `refusal: "declined"`;
- polkit's `abort=die` PAM control;
- password/fingerprint fallback for non-polkit declines and every ordinary
  failure.

The UI should use “head gesture” when describing the physical action and
“consent” or “intent” when describing its security purpose. It must not call nod
or shake liveness or anti-spoof protection.

## Developer tooling

Replace the mixed-purpose `blinkcap` with one head-only tool, tentatively named
`gesturecap`:

- capture pose samples for nod, shake, stillness, look-around, look-down, and
  reclining cases;
- replay a file or directory through the shipped head classifier;
- preserve strict bounded JSONL validation and atomic capture publication;
- keep clear “developer/research only” gating;
- remove EAR capture, blink replay, closure profiles, selector manifests, and
  closure threshold evaluation.

Consolidate or retire the overlapping `gesture_calibrate` example so there is
one authoritative evaluator and threshold implementation. Rename the classifier
from `detect_nod` to `detect_head_gesture` because it returns both nod and shake.
No compatibility wrapper is required unless a repository consumer is found by
the final audit.

Remove or archive active eye executables and scripts, including the passive-EAR
deployment script and closure capture campaigns. Preserve dated result files,
hashes, ADRs, research reports, and changelog entries as historical evidence.

## Documentation and packaging

Update every current-contract source:

- CLI command reference and setup guide;
- app integration and PAM instructions;
- architecture, threat model, limitations, debugging, and third-party model
  policy;
- model README, credits, package descriptions, daemon degradation messages, and
  TUI health text;
- machine API documentation and contract-1 fixture;
- scripts index and active research-tool instructions.

Historical material remains, with a short supersession banner where a dated ADR
or research document could otherwise be mistaken for current instructions.
Package changelog history is not rewritten.

No dependency is removed solely because eye consent is gone. Packaging parity
must continue to install the FaceMesh model and runtime needed by rescue
alignment.

## Test strategy

Implementation is test-first and incremental.

### Head classifier and watch

- nod approves at ordinary and reclining posture;
- stillness, look-down-and-hold, slow drift, look-around, and too-few frames do
  not approve;
- normal, wide, vigorous, and trailing-frame shakes decline;
- a shake with vertical motion never becomes an approving nod;
- pre-match and post-match nods approve once;
- pre-match, post-match, and completed-take shakes produce typed decline;
- terminal results never run completed-take fallback;
- cancellation/preemption never returns a gesture verdict;
- state is cleared between requests;
- missing FaceMesh has no effect on head classification;
- missing IR, camera errors, and timeouts fall back without weakening policy.

### Policy and migration

- elevation and polkit defaults remain on;
- greeter/lock and credential release retain their existing defaults;
- every per-service override still wins;
- disabling a high-privilege service warns and confirms;
- absent/`nod` legacy accepted-method config enables head-only;
- `closure` and malformed legacy values fail closed;
- old plaintext and encrypted enrollments load without losing templates;
- legacy eyes-open true blocks until explicitly cleared;
- new saves omit retired eye data and remain readable by a local legacy type.

### IPC and public contracts

- old eye request JSON parses during the tombstone release;
- calibration tombstones never capture or mutate;
- eyes-open OFF is idempotent and ON is refused;
- old client/new daemon and new client/old daemon profile listing both work;
- contract-1 fixtures validate with both retired booleans false;
- version-skew health reporting detects a stale daemon after package replacement.

### PAM, PAD, model, and packaging regression

- polkit nod success and shake `PAM_ABORT` remain;
- non-polkit shake denies face and preserves password fallback;
- no gesture, timeout, no match, and caught spoof preserve existing PAM behavior;
- full IR, dark IR-only, RGB-only, and third-party PAD decisions remain;
- passive `ir_eye_glint` remains in cues and trace output;
- FaceMesh plus BlazeFace rescue still yields refined alignment landmarks;
- every packaging lane still ships and configures the mesh/runtime;
- package upgrade tests prove a running daemon is restarted.

## Verification and audit gate

Before completion:

1. Run formatting, strict clippy, rustdoc, full workspace tests, machine API
   conformance, packaging parity, shell/static checks, and PAM wrapper tests.
2. Exercise explicit old/new daemon-client combinations.
3. Run the four-device hardware matrix on the current host, archhost, minihost,
   and thinkpad:
   - nod approval;
   - shake cancellation;
   - stillness and look-around negatives;
   - high-privilege defaults and per-service disable behavior;
   - cold keyring-release opt-in;
   - greeter/lock default-off behavior;
   - passive PAD and camera regressions.
4. Perform an independent change-focused security/correctness review.
5. Perform a repository-wide audit for:
   - active eye-feature references;
   - stale product or security claims;
   - dead EAR/blink/closure code;
   - contract and packaging drift;
   - unrelated high-confidence defects.

Unrelated audit findings are reported separately and do not silently expand this
change.

## Delivery sequence

1. Land migration, mixed-version, and contract tests.
2. Introduce the typed head-consent verdict and completed-take shake coverage.
3. Make the production watch pose-only.
4. Remove closure and eyes-open from every grant decision while retaining passive
   PAD and rescue alignment.
5. Add legacy configuration/state blockers and IPC tombstones.
6. Remove normal eye CLI/TUI/PAM/doctor/status surfaces.
7. Consolidate `gesturecap` and remove active eye research tools.
8. Delete unused EAR/blink/closure library code and threshold variables.
9. Update current documentation, packaging text, and supersession notices.
10. Run the full verification and hardware matrix.
11. Complete independent change review and repository-wide audit.

Each logical slice is tested and committed independently. The repository must
remain buildable and password/fingerprint fallback must remain available after
every slice.

## Acceptance criteria

The first retirement release is complete when all of the following are true:

- no eye action can authorize any request;
- no normal UI asks for eye setup or calibration;
- a required consent gate accepts nod, reports shake as decline, and accepts
  nothing else;
- legacy closure-only configuration and legacy eyes-open true fail closed with
  actionable migration instructions;
- service defaults and override confirmations are unchanged;
- passive PAD, `ir_eye_glint`, FaceMesh rescue, password fallback, and
  fingerprint fallback pass regression tests;
- old/new daemon-client combinations work through the documented compatibility
  window;
- machine API contract 1 emits both retired booleans as false;
- head-only developer capture/replay remains available;
- active documentation describes only head consent and automatic passive PAD;
- repository scans find eye/blink/closure terms only in compatibility code,
  explicit retirement notices, or historical evidence;
- the complete software and four-device hardware gates pass;
- independent review has no unresolved critical or required finding;
- the repository-wide audit is delivered with unrelated findings separated from
  this change.

## Rejected alternatives

### Immediate one-shot deletion

Rejected because it silently widens explicit closure-only configuration, breaks
old clients and contract-1 consumers, and can leave a stale daemon enforcing the
old policy during upgrade.

### Automatic policy rewrite

Rejected because a package hook or daemon startup would mutate root-owned policy
and encrypted user state without an explicit user decision. Partial failure and
rollback behavior would be harder to reason about than the temporary fail-closed
blocker.

### Hide only the CLI/TUI

Rejected because authorization, storage, IPC, and detector branches would remain
reachable or misleading, leaving the codebase with the same security ambiguity.

### Remove FaceMesh and the TFLite runtime

Rejected because rescue alignment still depends on them. Eye-consent retirement
does not justify a detection-availability regression.
