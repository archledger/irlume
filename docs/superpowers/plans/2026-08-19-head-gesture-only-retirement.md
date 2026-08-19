# Head-Gesture-Only Retirement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Retire every user-performed eye challenge while preserving nod approval, shake decline, existing per-service policy, passive PAD, mixed-version compatibility, and contract-1 output.

**Architecture:** Replace the combined pose/EAR consent watch with a pose-only state machine returning a typed approve/decline/no-gesture verdict. Remove eye behavior from authorization immediately, but retain one-release fail-closed configuration, enrollment, and daemon-wire tombstones; keep contract-1 fields frozen false and preserve all automatic PAD and FaceMesh rescue paths.

**Tech Stack:** Rust 1.88 workspace, Serde/serde_json, Unix-domain daemon IPC, Linux-PAM, Ratatui, shell/Python packaging and conformance harnesses.

**Spec:** `docs/superpowers/specs/2026-08-19-head-gesture-only-retirement-design.md`

## Global Constraints

- Repeated/continuous nodding is the only approving gesture; a deliberate shake is the only declining gesture.
- Do not change nod or shake thresholds in this change.
- Shake denies every face request, but only polkit maps it to `PAM_ABORT`; other PAM services retain password/fingerprint fallback.
- Elevation and polkit defaults stay on; lock/greeter and credential-release defaults stay off; existing per-service overrides keep precedence.
- `consent_gesture=closure` and malformed legacy values fail closed until explicitly removed or changed to `nod`.
- Legacy `require_eyes_open=true` blocks face authentication until cleared through the temporary OFF-only migration command; its evaluator never runs.
- Keep `service_gesture.*`, `polkit_gesture`, `credential_release_challenge`, and their existing environment overrides.
- Keep passive cross-spectrum PAD, `ir_eye_glint`, third-party deny-only PAD, camera binding/provenance, and FaceMesh/BlazeFace rescue alignment.
- Keep daemon eye-request tombstones for one minor release; they cannot capture or store eye data.
- Machine API contract 1 continues emitting `require_eyes_open:false` and `require_challenge:false`.
- Persisted eye fields deserialize for migration but are omitted on the next atomic enrollment save; no bulk encrypted-state rewrite.
- Current docs describe only head consent and automatic PAD. Dated research, ADR evidence, hashes, and changelogs remain historical.
- No new dependency is allowed.
- Every task ends with focused tests, `git diff --check`, and one signed atomic commit.

## File and Responsibility Map

- `crates/irlume-liveness/src/lib.rs`: canonical head classifier, thresholds, and evidence; all EAR/blink/closure algorithms leave this production library.
- `crates/irlume-auth/src/lib.rs`: request-scoped head-consent state machine, policy blocker, face/PAD ordering, and typed decline outcome.
- `crates/irlume-common/src/config.rs`: transitional legacy accepted-method decoder plus enduring per-service gate policy.
- `crates/irlume-common/src/lib.rs`: one-release daemon IPC tombstones and response compatibility fields.
- `crates/irlume-core/src/storage.rs`: deserialization-only legacy eye state and lazy cleanup on serialization.
- `crates/irlume-daemon/src/main.rs`, `crates/irlume-daemon/src/arbiter.rs`: tombstone authorization/classification, no-op retirement responses, and frozen summary values.
- `crates/irlume-pam/src/lib.rs`: unconditional nod/shake instructions and unchanged service-specific PAM results.
- `crates/irlume-cli/src/main.rs`, `commands.rs`, `machine.rs`: public cleanup, migration command, doctor/status, and contract-1 adapters.
- `crates/irlume-cli/src/tui.rs`: remove eye actions/state while preserving service and keyring head-gate controls.
- `crates/irlume-cli/src/gesturecap.rs`: head-only developer capture/replay, extracted from `blinkcap.rs`.
- `crates/irlume-vision/src/lib.rs`: retain general FaceMesh landmarks/rescue, remove EAR-only helpers after callers are gone.
- `crates/irlume-camera/src/lib.rs`: retain temporal IR sequence capture for head diagnostics; remove eye-specific contract text.
- `schemas/`, `docs/`, `models/`, `packaging/`, `nix/`, `scripts/`: public contract, current documentation, upgrade behavior, and historical supersession.

---

### Task 1: Characterize enrollment and wire compatibility before cutover

**Files:**
- Modify: `crates/irlume-core/src/storage.rs:174-195, 225-235, 469-500, 1010-1100`
- Modify: `crates/irlume-common/src/lib.rs:1250-1310, 1403-1451`

**Interfaces:**
- Consumes: existing `Enrollment`, daemon `Request`/`Response`, and Serde JSON behavior.
- Produces: test-only old/future reader fixtures that Tasks 5-6 reuse during the production cutover.

- [ ] **Step 1: Add plaintext reader-direction characterization tests**

Use local old/future types to pin both reader directions without changing production serialization yet:

```rust
#[test]
fn named_eye_fields_are_compatible_in_both_reader_directions() {
    #[derive(serde::Deserialize)]
    struct FutureEnrollment {
        user: String,
        profiles: Vec<FaceProfile>,
    }
    #[derive(serde::Deserialize)]
    struct LegacyEnrollment {
        user: String,
        profiles: Vec<FaceProfile>,
        #[serde(default)]
        require_eyes_open: bool,
        #[serde(default)]
        closure_calibration: Option<(f32, f32)>,
    }

    let old = r#"{"user":"u","profiles":[],"require_eyes_open":true,
        "closure_calibration":[0.24,0.05]}"#;
    let future: FutureEnrollment = serde_json::from_str(old).expect("unknown fields ignored");
    assert_eq!(future.user, "u");
    assert!(future.profiles.is_empty());

    let new = r#"{"user":"u","profiles":[]}"#;
    let legacy: LegacyEnrollment = serde_json::from_str(new).expect("missing fields default");
    assert_eq!(legacy.user, "u");
    assert!(legacy.profiles.is_empty());
    assert!(!legacy.require_eyes_open);
    assert_eq!(legacy.closure_calibration, None);
}
```

- [ ] **Step 2: Add encrypted-inner-payload characterization**

Use `crypto::generate_key`, `crypto::encrypt`, and `crypto::decrypt` to prove that the same local future reader accepts the decrypted old JSON. This test must not change the envelope version or production writer.

- [ ] **Step 3: Add old/new daemon response characterizations**

Serialize the current `Response::Enrollment` and deserialize it into a local old response type whose `require_eyes_open` field has no default. Also deserialize an old reply into the current type. This records why Task 6 must keep the field.

- [ ] **Step 4: Run characterization tests**

Run:

```bash
cargo test -p irlume-core named_eye_fields_are_compatible --locked
cargo test -p irlume-common enrollment_response --locked
```

Expected: PASS. These are compatibility characterizations; production behavior changes only after authorization and IPC are retired.

- [ ] **Step 5: Commit**

```bash
git add crates/irlume-core/src/storage.rs crates/irlume-common/src/lib.rs
git commit -m "test(compat): pin eye retirement boundaries"
```

---

### Task 2: Introduce a typed head-consent verdict

**Files:**
- Modify: `crates/irlume-liveness/src/lib.rs:986-1438, 2562-2627, 3489-4008`
- Modify: `crates/irlume-auth/src/lib.rs:458-509, 7417-7446, 11055-11150`

**Interfaces:**
- Produces: `detect_head_gesture(&[PoseSample]) -> HeadGesture` and private `HeadConsentVerdict::{Approve, Decline, NoGesture}`.
- Consumed by: Task 3 production watch and Task 9 `gesturecap`.

- [ ] **Step 1: Add RED boundary tests for completed nod and shake**

Define auth-layer tests around a new pure function:

```rust
fn still_poses() -> Vec<irlume_liveness::PoseSample> {
    (0..20)
        .map(|idx| irlume_liveness::PoseSample {
            idx,
            pitch_frac: Some(0.5),
            yaw_signed: Some(0.0),
            bri: 60.0,
        })
        .collect()
}

fn wide_shake_poses(len: usize) -> Vec<irlume_liveness::PoseSample> {
    let third = len / 3;
    (0..len)
        .map(|idx| irlume_liveness::PoseSample {
            idx,
            pitch_frac: Some(0.5),
            yaw_signed: Some(if idx < third {
                -0.9
            } else if idx < 2 * third {
                0.0
            } else {
                0.9
            }),
            bri: 60.0,
        })
        .collect()
}

#[test]
fn completed_take_reports_nod_and_shake_as_distinct_terminal_verdicts() {
    assert_eq!(head_consent_from_poses(&boundary_poses()), HeadConsentVerdict::Approve);
    assert_eq!(head_consent_from_poses(&wide_shake_poses(20)), HeadConsentVerdict::Decline);
    assert_eq!(head_consent_from_poses(&still_poses()), HeadConsentVerdict::NoGesture);
}

#[test]
fn stream_verdict_is_terminal_before_completed_take() {
    assert_eq!(
        resolve_head_consent(Some(HeadConsentVerdict::Decline), || panic!("must not run")),
        HeadConsentVerdict::Decline
    );
    assert_eq!(
        resolve_head_consent(Some(HeadConsentVerdict::Approve), || panic!("must not run")),
        HeadConsentVerdict::Approve
    );
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo test -p irlume-auth completed_take_reports_nod_and_shake --locked
```

Expected: FAIL because the typed verdict helpers are absent.

- [ ] **Step 3: Rename the public classifier without changing thresholds**

Implement:

```rust
pub fn detect_head_gesture(samples: &[PoseSample]) -> HeadGesture {
    detect_head_gesture_with_evidence(samples).0
}

pub fn detect_head_gesture_with_evidence(
    samples: &[PoseSample],
) -> (HeadGesture, NodEvidence) {
    // Move the existing detect_nod_with_evidence body unchanged.
}
```

Keep temporary hidden wrappers named `detect_nod` and `detect_nod_with_evidence` delegating to the new functions so the branch stays buildable until Task 9 removes eye tooling and updates all callers.

- [ ] **Step 4: Implement the auth-layer typed mapping**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadConsentVerdict {
    Approve,
    Decline,
    NoGesture,
}

fn head_consent_from_poses(poses: &[irlume_liveness::PoseSample]) -> HeadConsentVerdict {
    match irlume_liveness::detect_head_gesture(poses) {
        irlume_liveness::HeadGesture::Nod => HeadConsentVerdict::Approve,
        irlume_liveness::HeadGesture::Shake => HeadConsentVerdict::Decline,
        irlume_liveness::HeadGesture::None | irlume_liveness::HeadGesture::NoFace => {
            HeadConsentVerdict::NoGesture
        }
    }
}

fn resolve_head_consent(
    stream: Option<HeadConsentVerdict>,
    completed: impl FnOnce() -> HeadConsentVerdict,
) -> HeadConsentVerdict {
    stream.unwrap_or_else(completed)
}
```

- [ ] **Step 5: Preserve shake-first classifier coverage**

Run the existing nod/shake evidence suite and ensure the classifier still evaluates shake before nod:

```bash
cargo test -p irlume-liveness nod_evidence_tests --locked
cargo test -p irlume-auth stream_verdict_is_terminal --locked
```

Expected: PASS without threshold or fixture changes.

- [ ] **Step 6: Commit**

```bash
git add crates/irlume-liveness/src/lib.rs crates/irlume-auth/src/lib.rs
git commit -m "refactor(auth): type head consent verdicts"
```

---

### Task 3: Make the production consent watch pose-only

**Files:**
- Modify: `crates/irlume-auth/src/lib.rs:96-106, 4147-4568, 4678-4722, 7417-7490, 10430-10650, 11055-11150`
- Test: `crates/irlume-auth/tests/no_probe_on_the_auth_path.rs`

**Interfaces:**
- Consumes: `HeadConsentVerdict` and `detect_head_gesture` from Task 2.
- Produces: `head_consent_watch(max_frames) -> Result<HeadConsentVerdict>` with no enrollment, FaceMesh, EAR, or calibration input.

- [ ] **Step 1: Add RED tests for a pose-only watch contract**

Add pure/helper-level tests proving that only pose input is needed and that trailing-frame shake is typed:

```rust
#[test]
fn completed_head_take_classifies_every_trailing_boundary() {
    for tail in 1..=5 {
        let poses = wide_shake_poses(18 + tail);
        assert_eq!(head_consent_from_poses(&poses), HeadConsentVerdict::Decline);
    }
}

#[test]
fn head_consent_api_is_pose_only() {
    let classify: fn(&[irlume_liveness::PoseSample]) -> HeadConsentVerdict =
        head_consent_from_poses;
    assert_eq!(classify(&boundary_poses()), HeadConsentVerdict::Approve);
}
```

- [ ] **Step 2: Verify RED for trailing shake coverage**

```bash
cargo test -p irlume-auth completed_head_take_classifies_every_trailing_boundary --locked
```

Expected: FAIL until the completed-take path uses the typed head classifier.

- [ ] **Step 3: Replace combined frame conversion with pose-only conversion**

Replace `frame_to_consent_samples` with:

```rust
fn frame_to_head_pose(
    &mut self,
    frame: &irlume_camera::Frame,
    idx: usize,
) -> irlume_common::Result<irlume_liveness::PoseSample> {
    // Reuse the detector, brightness, pitch_frac, and yaw_signed logic from
    // the existing pose half. Do not consult self.mesh.
}
```

The rolling watch stores only `Vec<PoseSample>` and checks `head_consent_from_poses` every sixth usable window.

- [ ] **Step 4: Return typed terminal results from streaming and completion**

Use `ControlFlow::Break(HeadConsentVerdict::Approve)` for nod and `Decline` for shake. After the stream:

```rust
let verdict = resolve_head_consent(stream_verdict, || head_consent_from_poses(&poses));
```

Delete the boolean `gesture_cancelled` side channel. Replace `gesture_seen_before_match: bool` with `head_consent_before_match: HeadConsentVerdict`, initialize it to `NoGesture`, assign the early-watch result, and restore `NoGesture` on every return path.

- [ ] **Step 5: Simplify the grant gate**

`early_consent_watch` and the post-match gate no longer accept `Enrollment`. Map:

```rust
HeadConsentVerdict::Approve => Ok(outcome),
HeadConsentVerdict::Decline => Ok(Outcome::gesture_declined(live, score)),
HeadConsentVerdict::NoGesture => Ok(deny("keep nodding your head to approve")),
```

Do not change PAD/matching order or camera-operation lease ownership.

- [ ] **Step 6: Run focused authorization tests**

```bash
cargo test -p irlume-auth consent --locked
cargo test -p irlume-auth gesture_decline --locked
cargo test -p irlume-auth --test no_probe_on_the_auth_path --locked
```

Expected: PASS; no test depends on closure for a grant.

- [ ] **Step 7: Commit**

```bash
git add crates/irlume-auth/src/lib.rs crates/irlume-auth/tests/no_probe_on_the_auth_path.rs
git commit -m "refactor(auth): make consent watch head-only"
```

---

### Task 4: Fail closed on legacy accepted-method configuration

**Files:**
- Modify: `crates/irlume-common/src/config.rs:514-632, 730-790, 1344-1386`
- Modify: `crates/irlume-auth/src/lib.rs:514-530, 4447-4568, 10313-10650`

**Interfaces:**
- Produces: `HeadConsentPolicy::{Ready, LegacyClosure, Misconfigured}` and `head_consent_policy()`.
- Consumed by: auth, PAM, CLI doctor/status, and TUI diagnostics.

- [ ] **Step 1: Replace the mode-matrix test with migration-policy tests**

```rust
#[test]
fn legacy_gesture_config_never_silently_widens_to_nod() {
    assert_eq!(parse_head_consent_policy(None), HeadConsentPolicy::Ready);
    assert_eq!(parse_head_consent_policy(Some("nod")), HeadConsentPolicy::Ready);
    assert_eq!(parse_head_consent_policy(Some("closure")), HeadConsentPolicy::LegacyClosure);
    assert_eq!(parse_head_consent_policy(Some("clousure")), HeadConsentPolicy::Misconfigured);
}

#[test]
fn legacy_closure_instruction_is_actionable_and_names_no_eye_action() {
    let message = HeadConsentPolicy::LegacyClosure.instruction("approve");
    assert!(message.contains("remove consent_gesture") || message.contains("set it to nod"));
    assert!(!message.contains("close your eyes"));
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo test -p irlume-common legacy_gesture_config --locked
```

Expected: FAIL because `Either` and `Closure` are still supported modes.

- [ ] **Step 3: Implement the transitional parser**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadConsentPolicy {
    Ready,
    LegacyClosure,
    Misconfigured,
}

impl HeadConsentPolicy {
    pub fn instruction(self, what: &str) -> String {
        match self {
            Self::Ready => format!("keep nodding your head to {what}"),
            Self::LegacyClosure => format!(
                "cannot {what}: eye closure is retired; remove consent_gesture or set it to nod"
            ),
            Self::Misconfigured => format!(
                "cannot {what}: consent_gesture is invalid; remove it or set it to nod"
            ),
        }
    }
}

fn parse_head_consent_policy(value: Option<&str>) -> HeadConsentPolicy {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        None | Some("nod") => HeadConsentPolicy::Ready,
        Some("closure") => HeadConsentPolicy::LegacyClosure,
        Some(_) => HeadConsentPolicy::Misconfigured,
    }
}
```

`head_consent_policy()` applies the existing environment-over-settings precedence, then calls `parse_head_consent_policy`. Absent or normalized `nod` returns `Ready`; normalized `closure` returns `LegacyClosure`; all other present values return `Misconfigured`. Both blocked variants produce a bounded diagnostic naming the source and the explicit remedy.

- [ ] **Step 4: Gate required head-consent requests before camera work**

When `purpose.demands_gesture(service)` is true, refuse `LegacyClosure` and `Misconfigured` with `OutcomeKind::OtherDeny` before opening the consent watch. A surface whose policy does not require a gesture remains unaffected.

- [ ] **Step 5: Run config/auth tests**

```bash
cargo test -p irlume-common config:: --locked
cargo test -p irlume-auth legacy --locked
cargo test -p irlume-auth demands_gesture --locked
```

Expected: absent/nod work; closure/malformed fall back to password and never call a detector.

- [ ] **Step 6: Commit**

```bash
git add crates/irlume-common/src/config.rs crates/irlume-auth/src/lib.rs
git commit -m "fix(auth): block retired closure policy"
```

---

### Task 5: Replace legacy eyes-open enforcement with an OFF-only blocker

**Files:**
- Modify: `crates/irlume-auth/src/lib.rs:174-182, 3968-4007, 4968-5020, 6973-7070, 9390-9588`
- Modify: `crates/irlume-daemon/src/main.rs:3260-3300, 4210-4258`
- Test: `crates/irlume-daemon/src/main.rs` unit module

**Interfaces:**
- Consumes: the existing deserialized `Enrollment.require_eyes_open` field characterized in Task 1.
- Produces: no eye-state evaluator; legacy true is a pre-camera policy refusal.

- [ ] **Step 1: Add RED auth and daemon migration tests**

```rust
#[test]
fn legacy_eyes_open_true_blocks_without_running_an_eye_detector() {
    let enrollment: Enrollment = serde_json::from_str(
        r#"{"user":"u","profiles":[],"require_eyes_open":true}"#,
    )
    .unwrap();
    let outcome = legacy_eye_policy(&enrollment).expect_err("must block");
    assert!(outcome.contains("profiles eyes-open off"));
}

#[test]
fn eyes_open_off_is_idempotent_and_on_is_retired() {
    // Dispatch OFF twice and assert success both times; dispatch ON and assert
    // a retired-feature error without changing the stored enrollment.
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo test -p irlume-auth legacy_eyes_open_true_blocks --locked
cargo test -p irlume-daemon eyes_open_off_is_idempotent --locked
```

Expected: FAIL because the old evaluator still runs after assessment.

- [ ] **Step 3: Move the legacy blocker before camera capture**

Add the pure decision used by the RED test:

```rust
fn legacy_eye_policy(enrollment: &Enrollment) -> Result<(), &'static str> {
    if enrollment.require_eyes_open {
        Err(
            "legacy require-eyes-open is retired; run `irlume profiles eyes-open off`; \
             use your password or fingerprint until it is cleared",
        )
    } else {
        Ok(())
    }
}
```

Call it after enrollment load and before the camera operation. Convert the error to an `OutcomeKind::OtherDeny` policy refusal without opening a camera.

- [ ] **Step 4: Remove the evaluator and assessment field**

Delete `Assessment.eyes_open`, `eyes_open_from_capture`, `both_eyes_open`, their dedicated thresholds, the assessment computation, and all evaluator tests. Do not delete `eye_glint`, `eye_glint_of`, `Signals.ir_eye_glint`, or their passive liveness tests.

- [ ] **Step 5: Implement OFF-only daemon mutation**

`SetRequireEyesOpen { on: false }` assigns `enrollment.require_eyes_open = false`, saves atomically, invalidates/publishes the summary, and returns success. `on:true` returns the retired-feature error before invalidation or mutation.

- [ ] **Step 6: Run focused regressions**

```bash
cargo test -p irlume-auth eyes_open --locked
cargo test -p irlume-auth glint --locked
cargo test -p irlume-daemon require_eyes_open --locked
```

Expected: only migration/blocker tests remain under eyes-open names; glint tests pass unchanged.

- [ ] **Step 7: Commit**

```bash
git add crates/irlume-auth/src/lib.rs crates/irlume-daemon/src/main.rs
git commit -m "refactor(auth): retire eyes-open enforcement"
```

---

### Task 6: Add daemon IPC tombstones and freeze contract-1 fields

**Files:**
- Modify: `crates/irlume-core/src/storage.rs:174-195, 1010-1100`
- Modify: `crates/irlume-common/src/lib.rs:398-516, 763-951, 1250-1310, 1403-1451`
- Modify: `crates/irlume-daemon/src/main.rs:2333-2451, 2595-2658, 2900-2910, 3176-3217, 4234-4256, 5750-5770, 6000-6015, 6500-6630, 8404-8565`
- Modify: `crates/irlume-daemon/src/arbiter.rs:81-138`
- Modify: `crates/irlume-cli/src/machine.rs:2040-2075, 2246-2303, 3230-3240`
- Modify: `schemas/fixtures/v1/profiles-list.json`
- Test: `schemas/machine-api-v1.schema.json` remains structurally unchanged.

**Interfaces:**
- Keeps old request names parseable for one release.
- Produces frozen `Response::Enrollment` and contract-1 values.

- [ ] **Step 1: Add old-client/new-daemon wire tests**

```rust
#[test]
fn retired_eye_requests_still_parse_as_tombstones() {
    for wire in [
        r#"{"SetRequireEyesOpen":{"user":"u","on":false}}"#,
        r#"{"CaptureEarMedian":{"user":"u"}}"#,
        r#"{"SetClosureCalibration":{"user":"u","ear_open":0.2,"ear_closed":0.1}}"#,
    ] {
        serde_json::from_str::<Request>(wire).expect("old request remains parseable");
    }
}

#[test]
fn old_enrollment_response_shape_decodes_new_frozen_reply() {
    #[derive(serde::Deserialize)]
    enum OldResponse {
        Enrollment {
            profiles: Vec<ProfileSummary>,
            require_eyes_open: bool,
            #[serde(default)]
            closure_calibrated: bool,
            #[serde(default)]
            ir_ratio_calibrated: bool,
        },
    }
    let wire = serde_json::to_string(&Response::Enrollment {
        profiles: Vec::new(),
        require_eyes_open: false,
        closure_calibrated: false,
        ir_ratio_calibrated: false,
    })
    .unwrap();
    let OldResponse::Enrollment { require_eyes_open, .. } =
        serde_json::from_str(&wire).expect("old client decodes new reply");
    assert!(!require_eyes_open);
}
```

- [ ] **Step 2: Add daemon no-side-effect tests**

Assert `CaptureEarMedian` and `SetClosureCalibration` return an error containing `retired`, do not enqueue a camera-class operation, and do not alter the enrollment summary. Keep their old privilege posture.

- [ ] **Step 3: Verify RED**

```bash
cargo test -p irlume-common retired_eye_requests --locked
cargo test -p irlume-daemon retired_eye --locked
```

Expected: calibration requests still run their old camera/storage behavior.

- [ ] **Step 4: Convert calibration arms to tombstones**

Keep enum variants and exhaustive match arms, but return a precise `Response::Error` without accessing `Engine`, camera, or storage. Keep their existing root/root-or-target request posture, classify both calibration tombstones as `Class::Plain`, and classify their diagnostic outcome as status/completed work. Tests must prove the privilege gate runs before the tombstone reply and no camera-class queue entry is created.

- [ ] **Step 5: Make legacy enrollment fields load-only**

Now that closure authorization is gone and calibration requests are tombstones, add `skip_serializing` without renaming the existing fields:

```rust
#[serde(default, skip_serializing)]
pub require_eyes_open: bool,
#[serde(default, skip_serializing)]
pub closure_calibration: Option<(f32, f32)>,
```

The fields remain readable for the first-release blocker and OFF cleanup, but the next atomic save omits them. Adapt Task 1's plaintext/encrypted characterizations into production assertions against `serialize_enrollment` and `deserialize_enrollment`.

- [ ] **Step 6: Freeze profile summaries**

Every daemon `Response::Enrollment` emits `require_eyes_open:false` and `closure_calibrated:false`. Remove real-value summary computation. In `profiles_data`, ignore daemon eye values and always emit:

```rust
"require_eyes_open": false,
"require_challenge": false,
```

Update the v1 fixture; do not remove either required schema property.

- [ ] **Step 7: Run storage, wire, and machine-contract tests**

```bash
cargo test -p irlume-common --locked
cargo test -p irlume-core retired_eye --locked
cargo test -p irlume-daemon retired_eye --locked
cargo test -p irlume-cli machine --locked
cargo build -p irlume-cli --release --locked
python3 scripts/machine-api-conformance.py --irlume target/release/irlume --strict
```

Expected: all pass; contract 1 keeps both false booleans.

- [ ] **Step 8: Commit**

```bash
git add crates/irlume-core/src/storage.rs crates/irlume-common/src/lib.rs crates/irlume-daemon/src/main.rs \
  crates/irlume-daemon/src/arbiter.rs crates/irlume-cli/src/machine.rs \
  schemas/fixtures/v1/profiles-list.json
git commit -m "fix(protocol): tombstone retired eye requests"
```

---

### Task 7: Remove eye surfaces from CLI, doctor, and PAM

**Files:**
- Modify: `crates/irlume-cli/src/main.rs:17-24, 123-230, 384-515, 650-1085, 3637-3815, 4770-4880, 5280-5695`
- Modify: `crates/irlume-cli/src/commands.rs:680-725, 1450-1720, 2140-2205`
- Modify: `crates/irlume-cli/src/pamwire.rs:1393-1407`
- Modify: `crates/irlume-pam/src/lib.rs:273-360`
- Modify: `crates/irlume-pam/tests/pamwrap.rs:428-563, 567-650`
- Modify: `crates/irlume-cli/tests/cli.rs`, `cli_dispatch.rs`

**Interfaces:**
- Consumes: `HeadConsentPolicy` and frozen daemon summary.
- Produces: head-only human help/diagnostics and unchanged PAM result semantics.

- [ ] **Step 1: Add RED CLI/PAM assertions**

```rust
#[test]
fn help_exposes_no_eye_challenge_or_calibration() {
    let sandbox = Sandbox::new("head-only-help");
    let (code, help, stderr) = run(&mut sandbox.cmd(&["--help"]));
    assert_eq!(code, 0, "{stderr}");
    for retired in ["calibrate-closure", "eyes-open on", "eye-closure gesture"] {
        assert!(!help.contains(retired), "retired surface remains: {retired}");
    }
    assert!(help.contains("keep nodding to approve"));
    assert!(help.contains("shake your head to decline"));
}
```

Update PAM wrapper coverage so the default and legacy `nod` paths always name nod plus shake, while legacy closure configuration prints only the actionable blocker. Keep assertions that polkit shake aborts and non-polkit shake falls through.

- [ ] **Step 2: Verify RED**

```bash
cargo test -p irlume-cli help_exposes_no_eye --locked
cargo test -p irlume-pam --test pamwrap --locked -- --include-ignored --test-threads=1
```

Expected: CLI test fails on existing help; PAM test may require the installed `pam_wrapper` harness.

- [ ] **Step 3: Delete normal eye CLI flows**

Remove `calibrate_closure`, measurement helpers, dispatch, help, doctor readiness, status suffixes, and calibration advice. Keep `profiles eyes-open off` only as an explicitly labeled one-release migration command; reject `on` before contacting the daemon.

- [ ] **Step 4: Make policy status head-only**

Per-service status and disable confirmation remain. Replace “consent gesture” where it describes the physical action with “head gesture.” Legacy closure/malformed configuration gets one actionable fail-closed diagnostic.

- [ ] **Step 5: Simplify PAM instructions without changing outcomes**

For a ready policy, always render:

```text
irlume: keep nodding your head to approve; shake your head to decline
```

For blocked legacy config, render the migration message and let the daemon deny. Preserve `PAM_SUCCESS`, polkit-only `PAM_ABORT`, and all other `PAM_IGNORE` paths.

- [ ] **Step 6: Run CLI and PAM tests**

```bash
cargo test -p irlume-cli --locked
cargo test -p irlume-pam --locked
git diff --check
```

Expected: all runnable tests pass; ignored PAM wrapper tests are exercised again in Task 12.

- [ ] **Step 7: Commit**

```bash
git add crates/irlume-cli/src/main.rs crates/irlume-cli/src/commands.rs \
  crates/irlume-cli/src/pamwire.rs crates/irlume-cli/tests \
  crates/irlume-pam/src/lib.rs crates/irlume-pam/tests/pamwrap.rs
git commit -m "refactor(cli): expose head-only consent"
```

---

### Task 8: Remove eye state and actions from the TUI

**Files:**
- Modify: `crates/irlume-cli/src/tui.rs:141-151, 276-278, 1560-1575, 2780-2940, 3640-3818, 4932-5075, 6410-6460, 6525-6555, 6780-6795, 8300-8460, 12860-13020`

**Interfaces:**
- Consumes: per-service/head policy state from common and frozen profile summary.
- Produces: no eye rows/actions; service and keyring head-gate controls remain.

- [ ] **Step 1: Add RED render/action tests**

```rust
#[test]
fn tui_contains_only_head_gesture_controls() {
    let mut app = test_app();
    app.screen = SC_SETTINGS;
    let text = draw_text(&app);
    assert!(text.contains("Keep nodding to approve; shake your head to decline."));
    for retired in ["Require eyes open", "Calibrate gesture", "eye-closure"] {
        assert!(!text.contains(retired), "retired TUI text remains: {retired}");
    }
}
```

Add a key-routing test proving the old PAM `[c]` calibration action and settings eyes-open action no longer dispatch anything, while the per-service toggle still raises confirmation on disable.

- [ ] **Step 2: Verify RED**

```bash
cargo test -p irlume-cli tui_contains_only_head_gesture_controls --locked
```

Expected: FAIL on existing eye rows and calibration footer action.

- [ ] **Step 3: Remove eye state, suspend variants, rows, and bindings**

Delete `CalibrateClosure`, associated worker/sudo dispatch, PAM-tab `[c]`, settings eyes-open rendering/toggle, dashboard eye state, closure-mode calibration row, and obsolete tests. Reclaim layout rows rather than leaving blank separators.

- [ ] **Step 4: Preserve service and keyring controls**

Keep `SETTINGS_GESTURE_SERVICES`, current tri-state root visibility, disable confirmation, and the separate credential-release toggle. Update labels to “Per-service head gesture” and “Head gesture before keyring release.”

- [ ] **Step 5: Run TUI tests**

```bash
cargo test -p irlume-cli tui::tests --locked
```

Expected: every screen/key/size test passes; no retired action is advertised.

- [ ] **Step 6: Commit**

```bash
git add crates/irlume-cli/src/tui.rs
git commit -m "refactor(tui): remove eye challenge setup"
```

---

### Task 9: Replace `blinkcap` with head-only `gesturecap`

**Files:**
- Create: `crates/irlume-cli/src/gesturecap.rs`
- Delete: `crates/irlume-cli/src/blinkcap.rs`
- Modify: `crates/irlume-cli/src/main.rs:17-24, 71-91, 123-157`
- Modify: `crates/irlume-cli/tests/cli.rs:2020-2570`
- Delete: `crates/irlume-auth/examples/gesture_calibrate.rs`
- Delete: `scripts/research/blinkcap-campaign.sh`
- Delete: `scripts/research/capture-blink-corpus.sh`
- Delete: `scripts/deploy-passive-ear.sh`
- Modify: `scripts/README.md`

**Interfaces:**
- Consumes: `capture_pose_samples`, `detect_head_gesture`, and evidence API.
- Produces: developer-only `gesturecap capture` and `gesturecap replay` with bounded pose JSONL.

- [ ] **Step 1: Rename pose fixtures and add RED command tests**

```rust
#[test]
fn gesturecap_replays_pose_only_recordings() {
    let sandbox = Sandbox::new("gesturecap-replay");
    let file = sandbox.path("work/nod.jsonl");
    write_pose_recording(
        &file,
        "nod",
        &[
            0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50,
            0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 0.60, 0.40,
        ],
    );
    let mut command = sandbox.cmd(&["gesturecap", "replay", file.to_str().unwrap()]);
    command.env("IRLUME_DEV", "1");
    let (code, stdout, stderr) = run(&mut command);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("Nod"), "{stdout}");
}

#[test]
fn retired_blinkcap_is_not_dispatchable() {
    let sandbox = Sandbox::new("blinkcap-retired");
    let (code, _, stderr) = run(&mut sandbox.cmd(&["blinkcap", "replay", "anything"]));
    assert_eq!(code, 2, "{stderr}");
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo test -p irlume-cli gesturecap --locked
```

Expected: FAIL because `gesturecap` is not registered.

- [ ] **Step 3: Extract only pose capture/replay**

Move `RecordedPose`, atomic capture installation, strict header/frame/index validation, directory walking, capture countdown, pose collection, and head evidence reporting into `gesturecap.rs`. The file accepts only `posecap:true` recordings and never imports `EarSample`, `BlinkResult`, closure profiles, FaceMesh, or closure environment variables.

- [ ] **Step 4: Register and gate the new tool**

Add `gesturecap` to `DEV_CMDS` and dispatch. Remove `blinkcap`. Keep the existing `IRLUME_DEV=1` refusal behavior.

- [ ] **Step 5: Consolidate the example and scripts**

Delete the overlapping `gesture_calibrate` example; `gesturecap capture/replay` becomes the one authoritative head-corpus evaluator and must print the same pitch/yaw ranges, crossing counts, mean step, and verdict. Delete active eye capture/deployment scripts and remove them from `scripts/README.md`. Preserve dated research outputs and hashes.

- [ ] **Step 6: Run tool tests and authority guard**

```bash
cargo test -p irlume-cli --test cli gesturecap --locked
cargo test -p irlume-cli --test camera_authority --locked
```

Expected: pose capture/replay remains developer-gated and uses the same camera authority rules.

- [ ] **Step 7: Commit**

```bash
git add crates/irlume-cli/src crates/irlume-cli/tests/cli.rs \
  crates/irlume-auth/examples scripts
git commit -m "refactor(dev): replace blinkcap with gesturecap"
```

---

### Task 10: Delete dead EAR, blink, closure, and eye-open implementation

**Files:**
- Modify: `crates/irlume-liveness/src/lib.rs:842-983, 1438-2108, 2323-2550, 3000-3475`
- Modify: `crates/irlume-auth/src/lib.rs:71-79, 4012-4201, 4252-4273, eye-only tests/examples`
- Modify: `crates/irlume-vision/src/lib.rs:651-870, 962-983, 1617-1620, 1980-2005`
- Modify: `crates/irlume-camera/src/lib.rs:5802-5819, related tests/comments`
- Delete: `crates/irlume-auth/examples/blendshapes_probe.rs`
- Modify: `crates/irlume-auth/examples/landmark_failure_probe.rs`, `mp_latency_bench.rs`
- Modify: `benchmarks/bench_cascade.py`, `benchmarks/pad-candidates/flrgb_eval.py` only where they claim current eye behavior.

**Interfaces:**
- Consumes: compiler-confirmed absence of active eye callers after Tasks 3-9.
- Produces: production libraries with head/PAD/rescue code only.

- [ ] **Step 1: Establish the removal scan before deletion**

```bash
rg -n 'EarSample|BlinkResult|detect_blink|detect_deliberate_closure|ClosureCalibration|closure_profile|capture_ear_samples|both_eyes_open|eye_ear|mesh_min_ear' crates
```

Classify every hit as implementation/test/tool/history. No production caller may remain before deleting its definition.

- [ ] **Step 2: Delete liveness eye algorithms and knobs**

Remove `EarSample`, natural-blink scan/events/result, closure profile selection, `ClosureCalibration`, calibration median, deliberate-closure detector, five eye-only environment knobs, their tests, and the temporary `detect_nod`/`detect_nod_with_evidence` wrappers from Task 2 after every caller uses the head-named API. Keep `Signals.ir_eye_glint`, PAD cues/verdicts, `PoseSample`, `HeadGesture`, head thresholds/evidence, and their tests.

- [ ] **Step 3: Delete auth and vision eye helpers**

Remove production-dead `run_passive_liveness`, EAR capture/conversion, `eye_glint_contrast`, `eye_ear`, `mesh_min_ear`, EAR landmark constants, and eye-only tests/re-exports. Tasks 3 and 9 remove every consumer before this deletion. Keep `FaceMesh::landmarks`, mesh validity/plausibility, BlazeFace rescue, `eye_glint`, and passive trace tests.

- [ ] **Step 4: Update generic temporal-capture contracts**

Keep `capture_ir_sequence` because `gesturecap` uses it. Rewrite its docs and shortfall logs to say “temporal head-pose evidence,” not blink or closure.

- [ ] **Step 5: Trim research examples without erasing dated evidence**

Delete `blendshapes_probe.rs`. Remove EAR-only cases from `landmark_failure_probe.rs`. Remove the blendshape stage and arguments from `mp_latency_bench.rs` while keeping shipped detector/mesh/Blaze runtime measurements. Remove EAR-distribution output from `bench_cascade.py` while keeping cascade and rescue-mesh measurements. Keep `flrgb_eval.py`'s dated blink-corpus directory as an immutable genuine-frame data source, but remove any comment that presents blink as current product behavior. Historical CSV/JSON/results and research Markdown stay unchanged except supersession banners added in Task 11.

- [ ] **Step 6: Prove no active implementation remains**

```bash
rg -n 'EarSample|BlinkResult|detect_blink|detect_deliberate_closure|ClosureCalibration|capture_ear_samples|both_eyes_open|eye_ear|mesh_min_ear' crates
cargo test -p irlume-liveness -p irlume-vision -p irlume-auth --locked
cargo clippy -p irlume-liveness -p irlume-vision -p irlume-auth --all-targets -- -D warnings
```

Expected: `rg` returns no active symbols; tests and clippy pass.

- [ ] **Step 7: Commit**

```bash
git add crates benchmarks
git commit -m "refactor(liveness): delete retired eye detectors"
```

---

### Task 11: Update current documentation, packaging, and historical disposition

**Files:**
- Create: `docs/adr/0009-head-gesture-only-consent.md`
- Modify: `docs/APP-INTEGRATION.md`, `ARCHITECTURE.md`, `COMMANDS.md`, `CREDITS.md`, `DEBUGGING.md`, `LIMITATIONS.md`, `MACHINE-API.md`, `SETUP.md`, `STANDARDS.md`, `THIRD-PARTY-MODELS.md`, `THREAT_MODEL.md`
- Modify: `docs/adr/0001-liveness-pad-strategy.md`, `docs/adr/0002-challenge-response-liveness.md`
- Modify: `models/README.md`
- Modify: `packaging/arch/PKGBUILD`, current section of `packaging/fedora/irlume.spec`, `nix/module.nix`, current package descriptions/comments
- Modify: daemon/TUI/common comments and degradation messages identified by the research report.
- Preserve: `CHANGELOG.md`, dated `docs/pad-results/**`, and dated `docs/research/**` content except concise supersession headers.

**Interfaces:**
- Produces: one coherent current product contract; historical evidence remains attributable.

- [ ] **Step 1: Record the architectural decision**

Create ADR-0009 with status Accepted, the reliability evidence, the head-only/service-policy decision, the passive-PAD boundary, fail-closed migration, one-release tombstone window, contract-1 frozen fields, and the explicit non-decision to retune thresholds. Link the approved design and removal-impact research.

- [ ] **Step 2: Add a release-facing changelog entry**

At the top unreleased section, state:

```markdown
- Eye-based user challenges are retired. Gesture-gated requests now use only
  repeated head nodding to approve and a head shake to decline. Existing
  per-service defaults are unchanged; passive PAD remains mandatory.
- Legacy `consent_gesture=closure` and `require_eyes_open=true` fail closed with
  migration instructions for one release. Contract-1 eye fields remain present
  and frozen at `false`.
```

Do not alter historical release entries.

- [ ] **Step 3: Rewrite current user and architecture documents**

Remove calibration/eye instructions and explain nod as intent, shake as decline, service defaults, cold keyring opt-in, and automatic PAD as a separate boundary. Document the temporary migration blockers and tombstones.

- [ ] **Step 4: Correct model and package descriptions**

Describe FaceMesh/TFLite as dense landmark and BlazeFace rescue-alignment infrastructure. Keep every package dependency and installed model/runtime. Remove claims that current consent or passive blink requires the mesh.

- [ ] **Step 5: Mark historical research as superseded**

Add a short header to ADR-0001/0002 and issue-173 research notes pointing to the head-only ADR/spec. Do not rewrite measurements, dates, results, or hashes.

- [ ] **Step 6: Run the repository terminology audit**

```bash
rg -n -i 'closure|blink|eyes-open|require_eyes_open|EAR|ConsentGesture|CaptureEarMedian|SetClosureCalibration' \
  --glob '!CHANGELOG.md' --glob '!docs/pad-results/**' --glob '!docs/research/**' .
```

Review every remaining line. Allowed hits are compatibility tombstones, explicit retirement/migration text, or unrelated programming-language “closure” usage. No current instruction may offer an eye action.

- [ ] **Step 7: Run documentation and packaging checks**

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
./scripts/check-packaging-parity.sh
git diff --check
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add CHANGELOG.md docs models packaging nix crates scripts/README.md
git commit -m "docs: publish head-only consent policy"
```

---

### Task 12: Run full software, mixed-version, PAM, and packaging verification

**Files:**
- Modify only if a verification failure proves a defect in the planned change.
- Create: `docs/research/2026-08-19-head-gesture-only-software-verification.md`

**Interfaces:**
- Consumes: Tasks 1-11 at one frozen commit.
- Produces: exact-head verification evidence and any necessary focused fix commits.

- [ ] **Step 1: Run formatting, lint, docs, build, and guarded tests**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo build --release --locked
./scripts/run-tests-guarded.sh --min 650 -- cargo test --workspace --locked
git diff --check
```

Expected: all commands pass.

- [ ] **Step 2: Run machine and packaging gates**

```bash
python3 scripts/machine-api-conformance.py --irlume target/release/irlume --strict
./scripts/check-packaging-parity.sh
python3 scripts/hardware/test-run-slice4-hardware.py
python3 scripts/hardware/test-validate-slice4-hardware.py
bash -n scripts/hardware/run-slice4-hardware.sh
```

Expected: contract 1 and packaging parity pass.

- [ ] **Step 3: Run PAM wrapper integration**

```bash
./scripts/run-tests-guarded.sh --min 16 -- \
  cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1
```

Expected: polkit shake abort and non-polkit fallback tests pass. If host dependencies are absent, run the identical CI container/lane and record that environment explicitly.

- [ ] **Step 4: Exercise mixed-version wire fixtures**

Build `origin/main` client/daemon binaries in a detached temporary worktree and run the focused socket harness in both directions:

```bash
git worktree add --detach /tmp/irlume-head-only-origin-main origin/main
CARGO_TARGET_DIR=/tmp/irlume-old-target \
  cargo build --manifest-path /tmp/irlume-head-only-origin-main/Cargo.toml \
  --release --locked -p irlume-cli -p irlume-daemon
cargo test -p irlume-common old_client --locked
cargo test -p irlume-daemon mixed_version --locked
git worktree remove /tmp/irlume-head-only-origin-main
```

The test harness must launch each daemon against a temporary socket/state/config root and pair it with the opposite client version. Do not manually swap binaries into `/usr/bin`. If the explicit temporary worktree path already exists, stop and choose a new validated `/tmp/irlume-head-only-origin-main-N` path rather than deleting it.

- [ ] **Step 5: Record exact outputs and commit only fixes**

Write the verification report with commit OID, command, result, ignored-test reason, and environment. If a fix was required, add a focused regression test, rerun the affected gate plus the full guarded suite, and commit the fix separately before updating the frozen OID.

- [ ] **Step 6: Commit the verification report**

```bash
git add docs/research/2026-08-19-head-gesture-only-software-verification.md
git commit -m "docs: record head-only software verification"
```

---

### Task 13: Run hardware matrix, independent review, and repository audit

**Files:**
- Create: `scripts/hardware/run-head-gesture-matrix.sh`
- Create: `scripts/hardware/validate-head-gesture-matrix.py`
- Create: `scripts/hardware/test-validate-head-gesture-matrix.py`
- Create: `docs/research/2026-08-19-head-gesture-only-hardware-evidence.jsonl`
- Create: `docs/research/2026-08-19-head-gesture-only-hardware-matrix.md`
- Create: `docs/research/2026-08-19-head-gesture-only-codebase-audit.md`
- Modify implementation only for reviewed, in-scope defects with regression tests.

**Interfaces:**
- Consumes: exact final implementation OID and release binary.
- Produces: four-host evidence, review verdict, and separated repository-audit findings.

- [ ] **Step 1: Write the hardware-evidence validator tests**

Create fixture-driven tests requiring one record per host/trial with: frozen OID, host label, camera identity digest, service/purpose, requested policy, expected gesture, typed outcome, detector evidence bounds, and timestamp. The validator must reject missing hosts, mixed OIDs, duplicate trial IDs, raw frame paths, embeddings, usernames, and fewer than five attempts per required cell.

Run:

```bash
python3 scripts/hardware/test-validate-head-gesture-matrix.py
```

Expected: FAIL until the validator exists, then PASS after the smallest schema/validator implementation.

- [ ] **Step 2: Implement the interactive runner**

`run-head-gesture-matrix.sh` must:

```text
1. verify the repository OID and release-binary digest;
2. verify the daemon and camera are ready without writing extension units;
3. print the exact pose/service trial and wait for an explicit "ready";
4. run one bounded gesture/auth attempt;
5. record only categorical outcome and bounded pose evidence;
6. restore every temporary service-policy override on EXIT;
7. publish the evidence atomically only after all requested trials finish.
```

The script accepts `--host-label`, `--expected-oid`, `--output`, and one `--trial` value; it never starts a capture before the user confirms readiness.

- [ ] **Step 3: Freeze and distribute the candidate**

Record `git rev-parse HEAD`, build the release binary, verify its digest, and deploy that exact OID to the current host, `archhost`, `minihost`, and `thinkpad` using the repository's existing non-destructive host workflow. Do not run speculative camera extension-unit writes.

- [ ] **Step 4: Run head-gesture trials on each capable host**

For each host/camera pair, record at least:

```text
nod approval: 5 attempts
shake decline: 5 attempts
still negative: 5 attempts
look-around negative: 5 attempts
look-down-and-hold negative: 5 attempts
```

Ask the user before every live capture sequence. Record detector evidence and outcome, never biometric frames or embeddings in the repository.

- [ ] **Step 5: Verify service policy on hardware**

On applicable hosts, verify elevation and polkit default on; lock/greeter default off; high-privilege disable warning/confirmation; cold keyring-release opt-in asks once; warm keyring asks zero times; shake cancels the face attempt and preserves the intended PAM fallback per service.

- [ ] **Step 6: Run passive PAD and camera regressions**

Run the existing safe hardware suites for full IR, dark IR-only, RGB-only, capture/recovery, and passive PAD. Confirm `ir_eye_glint` remains traceable and FaceMesh rescue remains available. Do not infer optical emitter activity from a host control write or LED alone.

- [ ] **Step 7: Validate and summarize the matrix**

```bash
python3 scripts/hardware/validate-head-gesture-matrix.py \
  docs/research/2026-08-19-head-gesture-only-hardware-evidence.jsonl
```

Expected: one OID; all four hosts represented or an explicit capability-not-present record; five attempts in each required cell; zero nod grants in shake/still/look-around/look-down cells; every deliberate shake typed as decline.

- [ ] **Step 8: Perform independent change review**

Review `origin/main...HEAD` for correctness, security, spec adherence, compatibility, dead code, and test quality. Every critical/required finding receives a regression test and focused fix; rerun full software and affected hardware gates after any change.

- [ ] **Step 9: Perform the repository-wide audit**

Audit active source, interfaces, docs, packaging, schemas, scripts, and tests for remaining eye-feature code, stale claims, dead flexibility, public-contract drift, and unrelated high-confidence defects. Put unrelated findings in the audit report with severity and recommended follow-up; do not mix them into this branch.

- [ ] **Step 10: Re-freeze exact-head evidence**

After the last fix/review commit, rerun the complete software gates and every hardware trial invalidated by that change. The report must name one final OID whose tests, review, and hardware evidence all agree.

- [ ] **Step 11: Commit harness and reports**

```bash
git add scripts/hardware/run-head-gesture-matrix.sh \
  scripts/hardware/validate-head-gesture-matrix.py \
  scripts/hardware/test-validate-head-gesture-matrix.py \
  docs/research/2026-08-19-head-gesture-only-hardware-evidence.jsonl \
  docs/research/2026-08-19-head-gesture-only-hardware-matrix.md \
  docs/research/2026-08-19-head-gesture-only-codebase-audit.md
git commit -m "docs: record head-only hardware and audit evidence"
```

---

## Final Completion Gate

- [ ] No eye action authorizes any request.
- [ ] Nod approval and shake decline pass pure, integration, and four-host tests.
- [ ] Service defaults, override precedence, warnings, and confirmation are unchanged.
- [ ] Legacy closure configuration and legacy eyes-open true fail closed with actionable migration.
- [ ] Daemon tombstones cannot capture or store eye data.
- [ ] Contract 1 emits both retired fields as false and validates strictly.
- [ ] Passive PAD, `ir_eye_glint`, FaceMesh rescue, password fallback, and fingerprint fallback pass.
- [ ] Current CLI/TUI/PAM/docs contain no supported eye challenge or calibration.
- [ ] Active source contains no EAR/blink/closure implementation outside explicit compatibility code.
- [ ] Historical evidence remains intact and marked superseded where needed.
- [ ] Full software, PAM, packaging, mixed-version, and hardware gates pass at one final OID.
- [ ] Independent review has no unresolved critical or required findings.
- [ ] Repository-wide audit findings are delivered separately from the implementation scope.
