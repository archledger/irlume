# Persistent IR Saturation Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Diagnose fail-closed authentication denials caused by a localized IR-bright source that remains saturated while the camera emitter is off.

**Architecture:** The camera records whole-frame clipping for the selected metadata-lit frame, its adjacent metadata-dark partner, and the exact pixel overlap clipped in both. Auth passes the overlap into liveness, where it selects a more accurate reason only when the existing dark or flat cue already denies; auth and PAM expose one stable, action-oriented situation without changing any verdict, score, grant threshold, retry class, or enrollment behavior.

**Tech Stack:** Rust 1.88 workspace, V4L2/UVC illumination metadata, existing `irlume-camera`, `irlume-liveness`, `irlume-auth`, and `irlume-pam` unit tests.

**Spec:** `/home/wisbfime/archledger-gp/project-irlume.md` (approved issue #636 bounded design)

## Global Constraints

- Preserve every grant threshold, liveness verdict, score, and fail-closed path.
- Use paired evidence only when the selected frame is metadata-lit, an adjacent partner is metadata-dark, and the negotiated format supplies a clipping ceiling.
- Keep missing metadata, missing ceiling, malformed frame geometry, and missing ambient partners as `None`, never zero.
- Keep single-frame enrollment preflight unchanged.
- The new evidence is a reason and situation selector only.
- Do not recommend `ir-setup` for persistent ambient saturation.
- Do not commit unless the user explicitly requests a commit.

---

### Task 1: Capture Paired Whole-Frame Saturation

**Files:**
- Modify: `crates/irlume-camera/src/lib.rs:307-393,5362-5597`
- Test: `crates/irlume-camera/src/lib.rs` test module

**Interfaces:**
- Consumes: decoded burst frames, `ir_metadata::Illumination`, selected gate index, and `white_level: Option<u8>`.
- Produces: `IrCaptureStats::{lit_saturated_frac, ambient_saturated_frac, persistent_saturated_frac}: Option<f32>`.

- [ ] **Step 1: Write failing camera evidence tests**

Add tests that construct metadata-lit/dark synthetic frames matching the field measurements:

```rust
// ThinkPad: 17.25% lit, 17.02% ambient, with the ambient-clipped pixels
// overlapping the lit-clipped window.
assert_eq!(evidence.lit_saturated_frac, Some(0.1725));
assert_eq!(evidence.ambient_saturated_frac, Some(0.1702));
assert_eq!(evidence.persistent_saturated_frac, Some(0.1702));

// BRIO: emitter-created clipping disappears in the dark partner.
assert_eq!(evidence.lit_saturated_frac, Some(0.1403));
assert_eq!(evidence.ambient_saturated_frac, Some(0.0031));
assert_eq!(evidence.persistent_saturated_frac, Some(0.0031));
```

Also assert all evidence is `None` without a ceiling or selected lit metadata, and ambient/persistent evidence is `None` without an adjacent metadata-dark partner.

- [ ] **Step 2: Verify RED**

Run: `cargo test -p irlume-camera persistent_saturation -- --nocapture`

Expected: compilation failure because the paired-evidence function and `IrCaptureStats` fields do not exist.

- [ ] **Step 3: Implement exact paired evidence**

Add one private capture helper returning a small private evidence value. It must:

```rust
let lit_saturated_frac = ir_probe::saturated_fraction(lit, white) as f32;
let ambient_saturated_frac = ir_probe::saturated_fraction(ambient, white) as f32;
let persistent_saturated_frac = lit
    .iter()
    .zip(ambient)
    .filter(|(lit, ambient)| **lit >= white && **ambient >= white)
    .count() as f32
    / lit.len() as f32;
```

Require equal, non-empty frame lengths before computing overlap. Select the ambient index with `ir_metadata::ambient_partner`, but accept it only when the selected frame is explicitly `Lit` and the partner is explicitly `Dark`. Populate the three public stats fields and document that they are whole-frame diagnostics, not grant gates.

- [ ] **Step 4: Verify GREEN**

Run: `cargo test -p irlume-camera persistent_saturation -- --nocapture`

Expected: PASS for ThinkPad, BRIO, and unavailable-evidence cases.

- [ ] **Step 5: Review checkpoint**

Inspect `git diff -- crates/irlume-camera/src/lib.rs` and confirm capture selection, subtraction, returned pixels, and enrollment preflight are unchanged. Do not commit.

### Task 2: Select Accurate Liveness Reasons

**Files:**
- Modify: `crates/irlume-liveness/src/lib.rs:30-170,449-469,575-711`
- Test: `crates/irlume-liveness/src/lib.rs` test module

**Interfaces:**
- Consumes: `Signals::ir_persistent_saturated_frac: Option<f32>`.
- Produces: `Signals::persistent_ir_source_overwhelms() -> bool` and reason text for already-denied dark/flat captures.

- [ ] **Step 1: Write failing liveness tests**

Extend `live_signals()` with `ir_persistent_saturated_frac: None`. Add table-driven tests using `0.1702` for ThinkPad and `0.0031` for BRIO. For both `evaluate` and `evaluate_ir_only`, assert:

```rust
assert_eq!(verdict, Verdict::Spoof);
assert!(reason.contains("IR-bright source"));
assert!(reason.contains("reposition"));
assert!(reason.contains("password"));
assert!(!reason.contains("ir-setup"));
```

Exercise both existing denial cues independently: `ir_face_brightness < IR_FACE_MIN_BRIGHTNESS` and `ir_center_edge_ratio < MIN_CENTER_EDGE_RATIO`. Assert BRIO, `None`, and exactly the diagnostic boundary retain their old reasons and verdicts; a value immediately above the boundary rewords only the reason.

- [ ] **Step 2: Verify RED**

Run: `cargo test -p irlume-liveness persistent_ir_source -- --nocapture`

Expected: compilation failure because the new signal and selector do not exist.

- [ ] **Step 3: Implement the reason selector**

Add `IR_PERSISTENT_SATURATED_FRAC_MIN: f32 = 0.10` as a diagnostic threshold, not a grant threshold. Implement:

```rust
pub fn persistent_ir_source_overwhelms(&self) -> bool {
    self.ir_persistent_saturated_frac
        .is_some_and(|fraction| fraction > IR_PERSISTENT_SATURATED_FRAC_MIN)
        && (self.ir_face_brightness < IR_FACE_MIN_BRIGHTNESS
            || self.ir_center_edge_ratio < MIN_CENTER_EDGE_RATIO)
}
```

In each existing dark and flat branch, prefer the persistent-source reason before the broader ambient-mean and glint selectors. Keep the current `Verdict::Spoof` return values and leave `exposure_refusal` unchanged.

- [ ] **Step 4: Verify GREEN**

Run: `cargo test -p irlume-liveness persistent_ir_source -- --nocapture`

Expected: PASS on both credential-releasing evaluators and both cue branches, with unchanged verdicts.

- [ ] **Step 5: Review checkpoint**

Inspect `git diff -- crates/irlume-liveness/src/lib.rs` and confirm only reason selection changed. Do not commit.

### Task 3: Thread Evidence and Classify the Authentication Situation

**Files:**
- Modify: `crates/irlume-auth/src/lib.rs:324-445,3559-3580,4338-4377`
- Modify: `crates/irlume-cli/src/pad.rs:141-168`
- Modify: `crates/irlume-cli/src/main.rs:2379-2416`
- Test: `crates/irlume-auth/src/lib.rs` test modules

**Interfaces:**
- Consumes: `IrCaptureStats::persistent_saturated_frac` and `Signals::persistent_ir_source_overwhelms()`.
- Produces: stable `AttemptSituation::IrSource` label `"IR source"` and unchanged `OutcomeKind` values.

- [ ] **Step 1: Write failing auth tests**

Add tests proving a failed assessment with ThinkPad persistent clipping and an existing dark/flat denial maps to `AttemptSituation::IrSource`, while BRIO clipping, unavailable evidence, and an otherwise healthy face do not. Pin `attempt_situation_label(AttemptSituation::IrSource) == "IR source"`, preserve all existing precedence tests, and assert `liveness_deny_kind` returns the same kind before and after rewording.

- [ ] **Step 2: Verify RED**

Run: `cargo test -p irlume-auth ir_source -- --nocapture`

Expected: compilation failure because the signal plumbing and situation variant do not exist.

- [ ] **Step 3: Thread and classify evidence**

Populate `Signals::ir_persistent_saturated_frac` from `ir_stats.persistent_saturated_frac` in auth, `padcapture`, and the developer gate probe. Set it to `None` on RGB-only paths. Add one `AttemptFacts` boolean populated by `a.signals.persistent_ir_source_overwhelms()` and classify it after framing/orientation conditions but before generic darkness, score, and spoof labels. Do not inspect reason strings and do not change outcome classification or retryability.

- [ ] **Step 4: Verify GREEN**

Run: `cargo test -p irlume-auth ir_source -- --nocapture`

Expected: PASS with the stable journal situation and unchanged deny kinds.

- [ ] **Step 5: Review checkpoint**

Inspect diffs for auth and CLI callers. Confirm every IR `Signals` producer carries the evidence, every RGB-only producer uses `None`, and no enrollment preflight changed. Do not commit.

### Task 4: Add Actionable PAM Wording

**Files:**
- Modify: `crates/irlume-pam/src/lib.rs:837-853,1376-1433`
- Test: `crates/irlume-pam/src/lib.rs` test module

**Interfaces:**
- Consumes: daemon situation label `"IR source"`.
- Produces: one number-free prompt line recommending repositioning or password fallback.

- [ ] **Step 1: Write the failing PAM test**

Assert:

```rust
assert_eq!(
    situation_prompt("IR source"),
    Some("an IR-bright source is overwhelming the camera; reposition or use your password")
);
```

Include the label in the no-digits prompt test and keep attack-shaped situations silent.

- [ ] **Step 2: Verify RED**

Run: `cargo test -p irlume-pam IR_source -- --nocapture`

Expected: FAIL because `situation_prompt("IR source")` returns `None`.

- [ ] **Step 3: Add the prompt mapping**

Add only the `"IR source"` match arm. Do not include percentages, thresholds, source guesses, or `ir-setup`.

- [ ] **Step 4: Verify GREEN**

Run: `cargo test -p irlume-pam situation -- --nocapture`

Expected: PASS for usability mapping, silence policy, and number-free wording.

- [ ] **Step 5: Review checkpoint**

Inspect `git diff -- crates/irlume-pam/src/lib.rs` and confirm fallback behavior is unchanged. Do not commit.

### Task 5: Regression, Mutation, and Workspace Verification

**Files:**
- Verify all modified files.
- Update: `/home/wisbfime/archledger-gp/project-irlume.md`
- Update: `/home/wisbfime/archledger-gp/index.md`

**Interfaces:**
- Consumes: all preceding task outputs.
- Produces: verified issue #636 implementation and exact resumption state.

- [ ] **Step 1: Validate the production algorithm against issue #636 raw frames**

Download the six full-resolution PNGs linked by `https://github.com/archledger/irlume/issues/636` into `/tmp/opencode/irlume-636-frames`, verify they are 8-bit grayscale at the reported 640x360 ThinkPad and 340x340 BRIO dimensions, and record SHA-256 hashes. Convert temporary raw GREY8 payloads with ImageMagick and add a temporary camera unit test that feeds each adjacent pair through `paired_saturation_evidence` at the production GREY8 ceiling `255`.

Assert the observed values within `0.00001`: window-in lit `0.16778`, dark `0.16521`, exact overlap `0.16487`; window-out lit `0.00718`, dark `0.00072`, exact overlap `0.00067`; BRIO lit, dark, and overlap `0.0` at the actual ceiling. The issue's BRIO `14.03%`/`0.31%` figures used `>=250`, so zero at `255` is expected and is stronger separation, not a contradiction. Run the temporary test, then remove the temporary source test and generated raw payloads; retain only the downloaded public PNG evidence outside the worktree.

- [ ] **Step 2: Run focused regression suites**

Run: `cargo test -p irlume-camera -p irlume-liveness -p irlume-auth -p irlume-pam`

Expected: all non-hardware tests pass; only explicitly environment-gated hardware/PAM-wrapper tests may remain ignored.

- [ ] **Step 3: Run mutation probes**

Temporarily invert each of these independently, run the named focused test, and restore the line immediately: require `>=` instead of `>` at the diagnostic boundary; drop the metadata-dark requirement; replace exact overlap with lit-only clipping; remove auth situation precedence; remove the PAM mapping. Each probe must make its focused test fail.

- [ ] **Step 4: Run workspace quality gates**

Run:

```text
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Expected: all commands exit zero, except documented environment-gated tests remain ignored rather than failed.

- [ ] **Step 5: Run the sandboxed fleet control**

Build the branch daemon and CLI, snapshot the installed daemon/socket state plus hashes of production enrollment and emitter configuration, and run the branch daemon under `/tmp/opencode/irlume-636-hw/{state,config,irlumed.sock}` with copied capture qualification and encrypted enrollment inputs. Exercise one ordinary live identify attempt on the available ASUS fleet pair, confirm the new IR-source situation does not appear without persistent paired clipping, and retain the branch daemon's numeric diagnostic lines. Restore the installed daemon and socket, verify the original selected pair and byte-identical production hashes, and record exact rollback evidence. Never print or persist frame data, embeddings, credentials, decrypted enrollment material, or emitter payloads.

- [ ] **Step 6: Inspect final scope**

Run `git status --short` and `git diff --check`, then inspect the complete diff. Confirm no model symlink, captured frame, biometric data, threshold change, enrollment behavior, or unrelated file is tracked.

- [ ] **Step 7: Refresh project handoff**

Update the mutable current state, append an `agent: opencode` checkpoint using `/home/wisbfime/archledger-gp/session-summary-template.md`, and refresh the irlume row in `/home/wisbfime/archledger-gp/index.md`. Record exact commands and outcomes without secrets or biometric data. Do not commit unless explicitly requested.
