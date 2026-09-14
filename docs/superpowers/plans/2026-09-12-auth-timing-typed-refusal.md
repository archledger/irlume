# Typed liveness refusals + complete authentication timing boundaries — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use inline `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Do not commit or push without explicit user authorization; leave reviewable changes in the worktree.

**Goal:** Replace the two text-prefix liveness refusal classifications with typed causes produced at their origin, and add the missing end-to-end authentication timing boundaries (daemon ingress/queue, enrollment load, engine call, credential unseal) with a repeatable daemon-level harness, preserving all outward behavior.

**Architecture:** Part A adds a `DenyCause` value to `irlume_liveness::Cues`, set exactly where the gate produces each refusal, and rewrites `irlume_auth::liveness_deny_kind` to branch on `(Verdict, DenyCause)`; `Assessment` carries the cause alongside `verdict`/`reason`. Part B extends the existing privileged `TraceStage`/`StageTiming` diagnostics with the missing boundaries behind trace schema v3 and adds one `daemon_timing` example that merges the trace into a labeled boundary table with explicit gaps.

**Tech Stack:** Rust 2021 edition, MSRV 1.88, cargo workspace (`irlume-liveness`, `irlume-auth`, `irlume-common`, `irlume-daemon`), serde, existing `DiagnosticSink` plumbing.

**Spec:** `artifacts/irlume/2026-09-11-tui-desktop-experience/NEXT-RECOMMENDATION.md` (shared ledger, not in-repo) and `docs/research/benchmark-harness.md` (in-repo contract for benchmark examples).

## Global Constraints

- rust-version 1.88, edition 2021; every task ends green under `cargo fmt --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test --locked --workspace`, and `cargo doc --locked --workspace --no-deps --document-private-items` warnings denied (repo standard gates; IR-featured variants where the touched code is feature-gated).
- Outward reason strings, `presence_retryable` outcomes, retry/account-strike semantics, deadlines, and wire `TraceRefusalReason` values must not change. The `legacy_prefix_retryable` oracle test (`crates/irlume-auth/src/lib.rs:8757`) must keep passing unchanged.
- Diagnostic-trace compatibility: legacy schema-1 subscribers must never receive new `TraceStage` variants (unknown enum variants fail serde deserialization in old parsers). New variants ship behind a schema bump to 3 with `supports_schema` exclusions for schemas 1 and 2.
- Domain language per `CONTEXT.md`: "capture schedule" (never "camera mode"), "capture qualification", "runtime degradation", "support report", "diagnostic trace".
- No test opens cameras, TPM, or enrollment state. Attended hardware measurement is a separate user-authorized session, not part of this plan's verification.
- No em dashes in source comments or commit messages (repo convention).
- Sign commits with the repo release key only after explicit user authorization.

---

### Task A1: `DenyCause` typed at the origin in irlume-liveness

**Files:**
- Modify: `crates/irlume-liveness/src/lib.rs:343` (`Cues` struct), `:567-573` (`evaluate` no-IR Spoof arm), `:719-721` (`evaluate_ir_only` no-face arm), `:853-897` (`exposure_refusal`)
- Test: `crates/irlume-liveness/src/lib.rs` test module

**Interfaces:**
- Produces: `pub enum DenyCause { Other, NoIrFace, ExposureUnmeasurable }` (exported from `irlume_liveness`), `pub deny_cause: DenyCause` field on `Cues`, defaulting to `DenyCause::Other`.

- [ ] **Step 1: Write the failing tests** (compile-fail is the red state) in the liveness test module:

```rust
/// The typed cause is produced at the refusal origin, not re-derived from
/// wording downstream: each arm below pins the cause for one producer.
#[test]
fn deny_causes_are_typed_at_their_origin() {
    let gate = LivenessGate::new();
    let mut s = live_signals();
    // RGB present, IR absent: the retryable cross-spectrum transient.
    s.ir_face = None;
    let (_, cues, _) = gate.evaluate(&s);
    assert_eq!(cues.deny_cause, DenyCause::NoIrFace);
    // Dark evaluator's own no-face arm carries the same cause; its verdict
    // stays Uncertain and classification stays with the verdict there.
    let (_, cues, _) = gate.evaluate_ir_only(&s);
    assert_eq!(cues.deny_cause, DenyCause::NoIrFace);
    // Unmeasurable exposure, both evaluators (shared exposure_refusal).
    let mut un = live_signals();
    un.ir_ceiling_known = false;
    let (_, cues, _) = gate.evaluate(&un);
    assert_eq!(cues.deny_cause, DenyCause::ExposureUnmeasurable);
    let (_, cues, _) = gate.evaluate_ir_only(&un);
    assert_eq!(cues.deny_cause, DenyCause::ExposureUnmeasurable);
    // Every other refusal, and every Live result, stays Other.
    let mut flat = live_signals();
    flat.ir_center_edge_ratio = 0.1;
    let (verdict, cues, _) = gate.evaluate(&flat);
    assert_eq!(verdict, Verdict::Spoof);
    assert_eq!(cues.deny_cause, DenyCause::Other);
    let (_, cues, _) = gate.evaluate(&live_signals());
    assert_eq!(cues.deny_cause, DenyCause::Other);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --locked -p irlume-liveness deny_causes_are_typed_at_their_origin`
Expected: compile error (`no field deny_cause`, `DenyCause` not found).

- [ ] **Step 3: Implement** — add above `Cues`:

```rust
/// Typed origin of a non-Live gate decision, produced where the refusal is
/// produced, so downstream routing (retry eligibility, runtime availability)
/// branches on a value instead of pinning reason prefixes. `Other` covers
/// every refusal without special routing and every Live result, where the
/// field carries no information.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DenyCause {
    #[default]
    Other,
    /// RGB saw a face the IR stream did not: the retryable settling
    /// transient and the persistent screen/print signature at once.
    NoIrFace,
    /// The negotiated IR format defines no sensor ceiling, so exposure
    /// cannot be checked (#358); a property of the camera, not the frame.
    ExposureUnmeasurable,
}
```

Add to `Cues` (after `ir_exposure_measured`):

```rust
    /// Typed origin of this decision; see [`DenyCause`]. `Other` unless the
    /// evaluator named a cause where it produced its refusal.
    pub deny_cause: DenyCause,
```

Set it at the three origins: in `evaluate`'s no-IR Spoof arm (`cues.deny_cause = DenyCause::NoIrFace;` before the return), in `evaluate_ir_only`'s no-face arm (same), and in `exposure_refusal`'s unmeasurable arm (`cues.deny_cause = DenyCause::ExposureUnmeasurable;`). The blown-frame arm and every other refusal keep the `Other` default deliberately (they are retryable Uncertainties or ordinary Spoofs).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --locked -p irlume-liveness`
Expected: all pass. Then `cargo clippy --locked -p irlume-liveness --all-targets -- -D warnings` and `cargo fmt --check -p irlume-liveness`.

### Task A2: irlume-auth classifies on the typed cause

**Files:**
- Modify: `crates/irlume-auth/src/lib.rs:150-192` (`Assessment`), `:1085-1112` (`liveness_deny_kind`), `:5051-5106` (gate result + overrides), `:5161` (Assessment construction), `:6065-6069`, `:6089-6093`, `:6318-6339` (classification sites), `:8962` test, `:8837` test, `:8990-8996` test
- Modify: `crates/irlume-auth/src/grouped_auth.rs:113-118`, `:133-138`
- Modify: `crates/irlume-auth/src/engine_tests/pair_identity_tests.rs:663-664`

**Interfaces:**
- Consumes: `irlume_liveness::DenyCause`, `Cues::deny_cause` (Task A1).
- Produces: `Assessment { pub deny_cause: DenyCause, .. }`; `fn liveness_deny_kind(verdict: Verdict, cause: DenyCause) -> OutcomeKind` (private, unchanged visibility).

- [ ] **Step 1: Write the failing parity test** in the auth test module. The old prefix classifier is kept in the test as the oracle:

```rust
/// The prefix rules this refactor removes, kept here as the parity oracle:
/// for every (verdict, cause, reason) triple the producers can emit, the
/// typed classifier must agree with the prefix classifier it replaced.
    fn legacy_prefix_kind(verdict: Verdict, reason: &str) -> OutcomeKind {
        match verdict {
            Verdict::Uncertain if reason.starts_with(EXPOSURE_UNMEASURABLE_PREFIX) => {
                OutcomeKind::RuntimeUnavailable
            }
            Verdict::Uncertain => OutcomeKind::Uncertain,
            Verdict::Spoof if reason.starts_with("no face in IR") => OutcomeKind::SpoofNoIrFace,
            Verdict::Spoof => OutcomeKind::Spoof,
            Verdict::Live => OutcomeKind::OtherDeny,
        }
    }

    #[test]
    fn typed_cause_classification_matches_the_prefix_contract() {
        use irlume_liveness::DenyCause;
        let cases = [
            (Verdict::Uncertain, DenyCause::ExposureUnmeasurable, "IR exposure unmeasurable: this camera's IR format defines no sensor ceiling"),
            (Verdict::Uncertain, DenyCause::Other, "IR frame blown out (90% of the face at the sensor ceiling); move back or dim the light"),
            (Verdict::Uncertain, DenyCause::Other, "not facing the camera (yaw 0.50, pitch 0.10); look directly at it"),
            (Verdict::Uncertain, DenyCause::NoIrFace, "no face in IR"),
            (Verdict::Spoof, DenyCause::NoIrFace, "no face in IR: a real face reflects 850nm; a screen/print does not"),
            (Verdict::Spoof, DenyCause::Other, "IR too flat (center/edge 0.90); looks 2D, not a 3D face"),
            (Verdict::Spoof, DenyCause::Other, "IR PAD cue flags a spoof; use your password"),
            (Verdict::Live, DenyCause::Other, "live: face in RGB+IR, co-located, frontal, IR-reflective, 3D"),
        ];
        for (verdict, cause, reason) in cases {
            assert_eq!(
                liveness_deny_kind(verdict, cause),
                legacy_prefix_kind(verdict, reason),
                "typed drift: {verdict:?} + {cause:?} ({reason})"
            );
        }
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --locked -p irlume-auth typed_cause_classification`
Expected: compile error (field/signature mismatch).

- [ ] **Step 3: Implement.** Change `liveness_deny_kind` to match on `(verdict, cause)` exactly as the parity test's expectations, updating its doc comment (the pin is now the typed cause; wording pins remain in tests). Add `pub deny_cause: irlume_liveness::DenyCause` to `Assessment`. At the `assess_full` gate-result site, capture `cues.deny_cause` from `self.gate.evaluate(&signals)`; the `stale_pair_reason` override forces `DenyCause::Other`, and the PAD-downgrade override in the same function resets the captured cause to `DenyCause::Other` when it replaces the verdict/reason. Store the final value in the `Assessment` built at `:5161`. Update the five classification sites (`6067`, `6091`, `6335`, `grouped_auth.rs:115`, `:136`) to pass the cause (`a.deny_cause` for stored assessments, `cues.deny_cause` for fresh evaluations). Update the direct-call tests (`grace_retries_only_presence_failures`, `an_unmeasurable_exposure_is_not_retryable`, the `liveness Spoof: no face in IR` case near `:8993`, and the `pair_identity_tests.rs` fixture) to pass typed causes while keeping their reason-string assertions as wording pins. `EXPOSURE_UNMEASURABLE_PREFIX` moves into the test module (routing no longer reads it).

- [ ] **Step 4: Full gate**

Run: `cargo test --locked -p irlume-auth && cargo test --locked -p irlume-liveness && cargo clippy --locked -p irlume-auth -p irlume-liveness --all-targets -- -D warnings && cargo fmt --check`
Expected: all pass, including the untouched `legacy_prefix_retryable` oracle and `no_deny_site_classifies_a_liveness_verdict_by_hand` source scan.

- [ ] **Step 5: Workspace gate**

Run: `cargo test --locked --workspace && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo doc --locked --workspace --no-deps --document-private-items 2>&1 | tail -1`
Expected: all pass, zero doc warnings.

---

### Task B1: Trace schema v3 with the new stage vocabulary

**Files:**
- Modify: `crates/irlume-common/src/diagnostics.rs:16-20` (version constants), `:694-706` (`TraceStage`), `:853-866` (`supports_schema`)

**Interfaces:**
- Produces: `TraceStage::{EnrollmentLoad, IngressParse, QueueWait, EngineAuthenticate, CredentialUnseal}`; `CURRENT_TRACE_SCHEMA_VERSION = 3`; `V2_TRACE_SCHEMA_VERSION = 2` named tier.

- [ ] **Step 1: Write the failing test** (in diagnostics.rs tests or a new adjacent test): for each new stage, `supports_schema(1, stage)` and `supports_schema(2, stage)` are false while `supports_schema(3, stage)` is true; every pre-existing stage stays true at 2 and false-or-true at 1 exactly as today (IdentityInference/StreamOwnerRelease false at 1, others true).
- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement** the variants, bump `CURRENT_TRACE_SCHEMA_VERSION` to 3, add the named v2 tier, and extend `supports_schema` so schemas 1 and 2 exclude the five new stages (schema 1 keeps its existing exclusions). `TRACE_SCHEMA_VERSION` follows `CURRENT`.
- [ ] **Step 4:** `cargo test --locked -p irlume-common && cargo clippy --locked -p irlume-common --all-targets -- -D warnings`.

### Task B2: Engine enrollment-load boundary

**Files:**
- Modify: `crates/irlume-auth/src/lib.rs:5448-5610` (loader span)

- [ ] **Step 1: Write the failing test:** a `DiagnosticSink` collector around an authenticate call that ends in a setup refusal (not-enrolled path) still observes `StageTiming { stage: EnrollmentLoad }` exactly once, with nonzero elapsed. Use an existing test harness that exercises `authenticate_for_with_diagnostics` against missing enrollment.
- [ ] **Step 2: Verify it fails** (no such event today).
- [ ] **Step 3: Implement:** wrap the loader span (`load_started` at `:5448` through resolution including the NotEnrolled/Fallback early returns) in `TraceStageTimer::new(diagnostics, TraceStage::EnrollmentLoad)` so unwinding and early returns are measured; remove the now-duplicated `dlog!` elapsed or keep the dlog for its async/synchronous annotation while the trace carries the number.
- [ ] **Step 4:** `cargo test --locked -p irlume-auth && cargo clippy --locked -p irlume-auth --all-targets -- -D warnings && cargo fmt --check`.

### Task B3: Daemon ingress, queue, engine-call and unseal boundaries

**Files:**
- Modify: `crates/irlume-daemon/src/main.rs:1576` (`Queued`), serve_peer queue-submission site, worker `arbiter.take()` site (`:943`), Authenticate arm (`:4953`), `UnsealPassword`/`UnsealKeyring` arms (`:4461`)
- Test: `crates/irlume-daemon/src/main.rs` test module

**Interfaces:**
- Consumes: `TraceStage::{IngressParse, QueueWait, EngineAuthenticate, CredentialUnseal}` (Task B1), `OperationScope: DiagnosticSink`.

- [ ] **Step 1: Write failing tests** using the existing `serve`/`serve_peer` test scaffolding (it builds a real arbiter and socketpair): an Authenticate request produces `QueueWait` then `EngineAuthenticate` StageTiming events on its operation scope in that order; an Unseal request produces `CredentialUnseal`; `IngressParse` precedes `QueueWait`.
- [ ] **Step 2: Verify failure.**
- [ ] **Step 3: Implement:** record `read_request` start before the read in `serve_peer` and emit `IngressParse` through the operation scope once created (the boundary is measured pre-scope and reported inside the operation; document this in the field docs). Add `enqueued_at: std::time::Instant` to `Queued`, set at submit; the worker emits `QueueWait` as `enqueued_at.elapsed()` immediately after `arbiter.take()` returns the job. In the Authenticate arm, emit `EngineAuthenticate` with the existing `t` measurement. In the Unseal arms, emit `CredentialUnseal` the same way. Bound all values with the existing `u64::try_from(...).unwrap_or(u64::MAX)` convention.
- [ ] **Step 4:** `cargo test --locked -p irlume-daemon && cargo clippy --locked -p irlume-daemon --all-targets -- -D warnings && cargo fmt --check`.

### Task B4: `daemon_timing` harness example

**Files:**
- Create: `crates/irlume-daemon/examples/daemon_timing.rs`
- Test: unit tests inside the example (offline merge/table logic only)

**Interfaces:**
- Consumes: the real daemon socket (`/run/irlume/…`, resolved the same way `irlume-cli` resolves it), `Request::Authenticate`, `Request::TraceSubscribe` (schema 3), `TraceValidator`/`ParsedTrace`.

- [ ] **Step 1: Write failing unit tests** for the pure boundary-table builder: given synthetic `TraceRecord`s with StageTiming events plus wall-clock request/reply instants, the builder labels every boundary, refuses to sum stages, and prints the explicit gaps (socket write after worker reply, PAM stack time, desktop unlock) as `unmeasured` lines. Test: gaps always present, stages never summed, cancel trials labeled.
- [ ] **Step 2: Verify failure.**
- [ ] **Step 3: Implement** the example: options `--service`, `--purpose`, `--trials N`, `--cancel-after MS`, `--user`; per trial it opens the daemon socket, optionally subscribes a diagnostic trace on a second connection, sends one Authenticate, measures request-to-reply, and prints the merged boundary table plus categorical outcome (granted/refused/cancelled). Refused outcomes are labeled, not pooled with grants. No camera/TPM access beyond what the daemon itself does for the request. `--help` performs no request.
- [ ] **Step 4:** `cargo test --locked -p irlume-daemon --example daemon_timing && cargo clippy --locked -p irlume-daemon --example daemon_timing -- -D warnings`.

### Task B5: Document the boundary contract

**Files:**
- Modify: `docs/research/benchmark-harness.md`

- [ ] **Step 1:** Add a `daemon_timing` section stating exactly what each boundary covers (ingress parse, queue wait, engine call with its nested engine stages, credential unseal), the explicit unmeasured gaps (worker reply to socket write, PAM stack, desktop-unlock completion), the cold/warm and route-labeling protocol (route evidence comes from the trace's stream-contract and capture-schedule events, never from the service name), and the desktop-unlock completion-signal finding: investigate whether a trustworthy signal exists (greeter/kscreenlocker journal events); if none is established, the gap stays explicit and this section says so.
- [ ] **Step 2:** `grep` the docs for consistency with `CONTEXT.md` vocabulary; run `cargo doc` gate once more.

---

## Self-Review

1. **Spec coverage:** typed causes at origin (A1/A2) with parity tests preserving messages/retry eligibility/accounting/deadlines; missing timing boundaries incl. queue/template loading (B1-B3); repeatable harness not overlapping existing tools (B4); desktop-unlock signal validated or gap retained (B5); no-face/cancel/loaded-system behavior (harness cancel mode + docs protocol; loaded-system documented as session protocol). Optimization choice deliberately deferred until measurements exist, per spec.
2. **Placeholders:** none; each step names files, anchors, and code.
3. **Type consistency:** `DenyCause` names/shapes match between A1 and A2; stage names match between B1, B2, B3, B4.
