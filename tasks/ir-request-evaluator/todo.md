# IR request evaluator tasks

## 1. Read-only account view
- [x] Add non-creating, nonblocking account-lock acquisition and reuse the locked primary parser.
- [x] Read primary/secondary state without recovery; refuse pending or changing protected state.
- [x] Test missing/busy locks, journals, late changes, successful reads and preservation.
- Verify: `cargo +1.88.0 test --locked -p irlume-core --lib read_only` plus affected core tests and Clippy.
- Files: core `template_key.rs`, `storage.rs`, `lib.rs`, new read-only module/tests. Scope: medium.
- Result: signed `a40ae87f`; 524 core tests pass, 67 existing hardware tests unrun.
  Independent review's FIFO-open and UID-hold findings reproduced, fixed and rechecked.

## 2. Typed request report and scoped observation
- [x] Add feature-gated phase/result/count/timing types and strict JSON projection.
- [x] Install observation only through an unwind-safe Engine scope; reject nested evaluation.
- [x] Test final-result invariants, privacy, overflow and context restoration.
- Verify: feature-enabled auth report/context tests and default-feature build.
- Result: final feature auth suite 599 passed, 3 existing ignored; examples 27 passed.
  Default build and both Clippy lanes pass. Scope and output regressions pass.
- Depends: 1 for integration. Files: auth `lib.rs`, new evaluator module/tests. Scope: medium.

## 3. Reuse the production Engine request
- [x] Route evaluator reads and final scope checks through the read-only view.
- [x] Use the real verification entry, retry loop, PAD/identity rule and current window.
- [x] Test primary/secondary equivalence, retries, terminal identity, late cancellation and revocation.
- Verify: auth request tests, all auth tests and both Clippy lanes; deliberate negative mutations.
- Result: full-entry primary/secondary fixture passes. Finalization cancellation
  and expiry regressions fail with the old ordering and pass with the fix.
- Depends: 1, 2. Files: auth `ir_assessment.rs`, evaluator module and focused tests. Scope: medium.

## 4. Non-granting developer executable
- [x] Add explicit preflight/evaluate parser, service restrictions and required model validation.
- [x] Preserve root/no-debug/dumpability/cancellation protections; emit only bounded report JSON.
- [x] Test invalid input, unarmed/refusal behavior, no credential/publication entry and feature exclusion.
- Verify: example tests and release build with `ir-only-evaluation`.
- Result: release example builds; two real malformed-argument subprocess checks
  pass, including non-UTF-8 input. Explicit default-feature build refuses the target.
- Depends: 3. Files: auth Cargo manifest, example and tests. Scope: small.

## 5. Additive request-mode supervision
- [x] Add strict request-report validation and exact supported topology checks.
- [x] Bind one request to one durable attempt, actual exit, cleanup and preservation evidence.
- [x] Retain old-mode compatibility; test malformed, stale, unknown and incomplete results.
- Verify: `python3 -m unittest discover -s scripts/ir-evaluation -p 'test_*.py'`, Ruff and subprocess fixtures.
- Depends: 4. Files: existing Python harness/runner/host tests, split into smaller changes if needed. Scope: medium per change.
- Result: 65 offline Python tests pass, including real traced subprocess failures
  and native supervisor dump protection. Five copied-source mutations are caught.

## 6. Documentation and final verification
- [x] Document command, report semantics, read-only differences and pilot prerequisites.
- [x] Run required workspace/feature checks, selected software-TPM coverage and source-preservation checks.
- [x] Review, sign local commits and archive exact sources/results; report unrun hardware honestly.
- Depends: 1-5. Verify: root AGENTS.md command set, relevant Python tests and final diff review.
- Result: guarded workspace run reports 5,473 passed. Format, lint, docs, default
  release build, feature release build and AGENTS checks pass. Three selected TPM
  tests pass against software TPMs. All independent review findings are resolved.
- Archive: code, release example, test receipts and review records are uploaded
  and checksum-verified. The documentation closeout uses a separate bundle addendum.

No task marks empirical qualification, a live camera trial, or a stable policy label complete.
