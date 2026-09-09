# IR-only evaluation implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development for the bounded implementation, then independent review. Preserve all pre-existing work and do not commit or install.

**Goal:** A runnable developer diagnostic that captures only IR and evaluates existing IR PAD and compatible enrolled IR identity without authenticating or releasing credentials.

**Architecture:** A non-default `ir-only-evaluation` Cargo feature exposes a diagnostic module on Engine and a required-feature example. No daemon/PAM/protocol/settings integration. An external attended harness records metadata and verifies camera release and no RGB device use.

**Tech Stack:** Existing Rust workspace, Rust 1.88 floor, existing camera/liveness/vision/core components; Python standard library for the external harness.

**Spec:** /home/wisbfime/archledger-gp/artifacts/irlume/2026-09-08-ir-only-design/assessment.md (diagnostic slice accepted by user September 8).

## Global constraints

- No changes to production authentication acceptance, camera mode configuration, enrolled data or installed binaries.
- No `Outcome::grant`, authenticate method, PAM client or credential-release call in the diagnostic execution path.
- Open only the configured bound IR device; no camera discovery/probing or RGB scene substitution.
- IR PAD mandatory; absent/invalid/failed evidence and incompatible enrollment cannot produce candidate_match.
- Reuse existing IR liveness and IR matching contracts, including best-template and centroid acceptance; label candidate_match as experimental evidence only.
- No saved raw camera images, identity embeddings, templates, names or secrets in output/artifacts. Only bounded categories and timings.
- Cooperatively check cancellation and a bounded deadline before capture, between inference stages and before reporting; release camera before inference when one-shot capture returns. Do not claim a hard wall-clock bound on blocked kernel/inference calls.
- Hardware trial needs an attended start cue; dim-light trials excluded. Keep consented desktop and legacy greeter behavior.

## Task 1: feature-gated diagnostic and runnable example

Files: crates/irlume-auth/Cargo.toml, crates/irlume-auth/src/lib.rs (module declaration only), new crates/irlume-auth/src/ir_only_evaluation.rs, new crates/irlume-auth/examples/ir_only_evaluation.rs, new docs/research/2026-09-08-ir-only-evaluation.md.

- [ ] Write behavior tests first for diagnostic policy. Missing/failed/nonfinite/out-of-range PAD, no face, failed liveness, incompatible templates, mismatch and late cancellation/expiry cannot return candidate_match. A good synthetic compatible IR candidate can return candidate_match only as a diagnostic category.
- [ ] Run `cargo test -p irlume-auth --features ir-only-evaluation ir_only_evaluation --lib`, record red evidence for missing behavior before implementation.
- [ ] Implement the separate feature-gated Engine operation with caller-supplied Enrollment and CaptureControl, a single configured IR endpoint, and categorical result/timing output. Use existing camera lease Diagnostics and ordinary pinned/emitter capture. Reuse detector/alignment/embed/adapter/ir_match and evaluate_ir_only, without calling assess_full or authenticating. Cover injected capture boundary in tests to demonstrate selected endpoint and no RGB call; production boundary remains real capture code.
- [ ] Add the required-feature example: explicit evaluation invocation, root-only execution, argument/budget validation before loading/capture; load configured pair without probing and supplied existing models/enrollment. Load templates through existing protected storage only; never serialize them. Report fixed categories on errors without raw reason/model values. Help/preflight must not open cameras. Successful process execution never means authentication success.
- [ ] Run feature-specific tests, auth library tests, example help/invalid input tests, fmt, Clippy all targets with feature, Rust 1.88 check and rustdoc. Record exact counts and ignored hardware limits.
- [ ] Document developer invocation, categories, no-grant semantics, enrollment/model compatibility, hardware consent/cancellation, limitations and proposed next trial matrix.
- [ ] Review complete diff independently; correct material findings and rerun affected gates. No commit/install/publication.

## Task 2: external evaluation harness and attended trial

Files under /home/wisbfime/archledger-gp/artifacts/irlume/2026-09-08-ir-only-evaluation only: metadata-only preflight, attended harness, tests, report and manifest.

- [ ] Snapshot source hashes, installed overlay/protected state, selected camera binding and model metadata without camera opening or biometric file contents.
- [ ] Build the exact diagnostic example and verify its library API is absent in normal feature configuration.
- [ ] Write and test a bounded harness that launches the non-granting example, records only allowed output categories/timing, observes video-node descriptor use and process cleanup, and never records image/model inference payloads. Use system tracing where available for no-RGB-open evidence rather than claiming sampling proves absence.
- [ ] Request readiness only when executable and hardware checks are ready; give start cue. One ordinary-light genuine-user trial first, then no-face/cancellation trials based on readiness. Ask what attack props/second consenting participant are available before claiming those evaluations.
- [ ] Record observed result and camera release limits; compare against dual-camera only with same-condition measured trials. Missing attack coverage stays explicit, no optional login support enabled.
- [ ] Verify source changes and unchanged installed state; refresh shared handoff/index with exact resumption and rollback.

## Completed execution and approved recorded-data extension

The user supplied seven explicit prior NexiGo IR attack folders during execution. Added a separate required-feature ir_recorded_pad example to process all252PGMframes with the current primary detector and FLIR, retaining aggregate counts only. This is regression data already evaluated in August, not held-out validation. No dataset downloaded. Four parser/accounting tests and three actual failure-invocation checks pass; independent review accepted the strict exit0/exact36/accounting gate. Failed-run counts are discarded entirely, including caught panics.

Task1 completed:17newIRpolicy/orchestration tests +3CLI tests; defaultauth176pass/3ignored,featureauth193pass/3ignored. Readonlyloading correction adds5coretests,core136pass/26existinghardwareignored. No opportunistic template-key upgrades or persistent SRK creation in diagnostic loading. Core/header/source and harness independently reviewed.

Task2 completed for first evaluation pass: camera-free preflight ready withzero videoopens; attended genuine candidate_match, empty no_face, cancellation cancelled, banner pad_refused. Allfourtrials noRGBopens,IRimage+companionmetadata only, release+installed7/66 preservation checks pass. Root13harness tests pass. Frame-level recordedreplay252noface/0failed/0PADevaluated. Alloutputsare non-granting; nooptional loginmode enabled.

Final gates: Clippy/MSRV1.88/rustdoc/fmt/diff and optimizedexamples pass. Normal-feature positive Engine import compiles; diagnostic import refuses E0432. Report/evidence in /home/wisbfime/archledger-gp/artifacts/irlume/2026-09-08-ir-only-evaluation. No commit/install/publication. Broader held-out sensor-matched genuine/attack evaluation remains before optional authentication support.
