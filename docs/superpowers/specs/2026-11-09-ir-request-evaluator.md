# Spec: non-granting IR verification-request evaluator

Status: **Approved by the owner, 2026-11-09.** The owner also authorized
autonomous planning, implementation and offline validation within this scope.
No new camera campaign, threshold change or policy promotion is authorized here.

Source baseline: `bbb2d84f644e3f2d50686cbeb8d2f3d7b37acf8e`.
Related requirements: [IR-only qualification](../../IR_ONLY_QUALIFICATION.md),
[threat model](../../THREAT_MODEL.md), and the November 9 qualification audit
in shared project evidence.

## Objective and scope

Give maintainers one attributable measurement of the **production engine's
IR-only verification request**, including its internal assessment retries and
final decision checks, without granting operating-system access.

Version 1 covers an explicitly configured ordinary IR target, primary or
authorized secondary enrollment, and recognized login/lock service contexts.
It uses the existing IR inference, PAD, identity union, count scaling, account
policy, camera binding, deadlines and revocation predicates.

This is an engine-level evaluator. It does not measure daemon socket/peer/seat
authorization, queueing, polkit, persistent retry-accounting writes, PAM
conversation, graphical unlock or credential delivery. Those retain separate
integration tests. The output and documentation must state this boundary;
neither a would-grant result nor a successful tool exit proves a login worked.

Automatic camera selection, split pairs and privileged/credential-release
service contexts remain outside version 1. Unsupported input refuses before
capture instead of falling back to another target or timing profile.

The feature remains developer-only behind the existing non-default
`ir-only-evaluation` Cargo feature. Dual authentication stays the default;
the IR-only experimental designation and runtime thresholds do not change.

## Verified source facts

- `ir_assessment.rs::authenticate_ir_in_window` resolves a configured target,
  loads enrollment, pins primary/secondary scope and enters the IR request.
- `authenticate_ir_resolution` uses `authentication_attempt_loop_with`.
  `authenticate_ir_target_attempt` invokes the shared assessment stages,
  final scope checks and cancellation/deadline checks.
- `presence_retryable` does not retry a below-threshold identity decision.
- `identity_arms::dark_verdict` evaluates best-template and centroid predicates;
  branch precedence is not a substitute for observing both predicates.
- `storage::load_snapshot_read_only` and the read-only scope resolver already
  exist. An encrypted read can unseal the existing template key; it does not
  create enrollment, repair an envelope or provision a persistent TPM key.
- Production secondary grant-boundary checking can call `resolve_commit`.
  Calling that helper unchanged would violate the evaluator's read-only
  storage contract. The pure boundary predicate can be shared, but its input
  acquisition must not perform recovery.

## Input contract

Proposed standalone example: `ir_request_evaluation`.

```text
ir_request_evaluation (--preflight|--evaluate) USER DETECTOR RECOGNIZER FLIR
  --service SERVICE [--adapter PATH] [--cancel-on-stdin]
```

- `USER` is one existing local account, used privately and never serialized.
- Model paths are explicit, absolute, existing files. A required missing or
  invalid model is a refusal; no model is downloaded or silently omitted.
- `SERVICE` must classify through the existing registry as a supported greeter
  or screen-unlock service. Version 1 evaluates `Verify`, not credential release.
- The request window is the existing production-resolved window for that
  context. There is no independent larger diagnostic-budget override in v1.
  Its start point must match production, including request-time enrollment
  loading and admission; model initialization is reported separately. A prior
  preflight must not supply a stale snapshot or pre-unsealed key to evaluation.
- Target selection is the existing explicit ordinary configuration. Preflight
  verifies the exact supported target/model/enrollment prerequisites without
  opening a camera, enabling the emitter, or discovering an alternative target.
- Evaluation requires the reviewed supervisor's fresh participant readiness.
  A standalone flag or an old readiness file is not evidence of that readiness.
- With cancellation input enabled, a byte, EOF or read failure requests
  cancellation. It is checked at production-safe boundaries.

Malformed, duplicate, unknown, overlong or incompatible arguments refuse before
model/biometric processing. Preflight and evaluation results remain distinct.

## Read-only and decision-equivalence contract

The evaluator must share the production request loop and decision predicates.
It must not copy and maintain a simplified scoring or retry implementation.
Eligible clean-state synthetic cases must give the same engine decision under
the same prepared inputs, clock and assessment results.

Storage acquisition is intentionally stricter than normal production:

- Read existing primary/secondary state through read-only loaders and retain
  the request-scoped key and source binding through the final check.
- Require consistent read-only state at admission and final revocation checks.
  A preflight-only journal existence check is insufficient to cover races.
- Refuse pending, ambiguous or repair-dependent state. Do not recover journals,
  upgrade envelopes, create protected account state/lock files, enroll faces,
  reset retry history,
  seal credentials, or provision persistent TPM objects.
- Reuse the same pure primary/secondary revocation predicates. A changed
  account, primary, group or pair cannot produce a would-grant result.
- Mark repair-dependent refusals explicitly in the measurement category.
  They are a documented evaluator/production difference and remain failures
  in campaign accounting; they are not proof that production would deny.

No generic no-op admission callback may stand in for an applicable engine
policy check. External daemon/PAM authorization is outside the measured scope,
not simulated as having passed. An implementation that cannot preserve these
boundaries must return for design review rather than silently narrow checks.

## Output contract

Use a new, closed schema namespace (`operation: "ir_request_evaluation"`,
`schema: 1`); keep existing one-shot schemas 1 through 4 unchanged.

The public report contains only:

- `authentication_granted: false`, invariant for every result;
- `phase` of `preflight` or `evaluation`;
- a tagged result: preflight-only `ready`; evaluation-only `would_grant` with
  `identity_acceptance` of `best_template`,
  `centroid` or `both`; `refused` with a bounded categorical cause; or
  `incomplete` with a bounded measurement-failure cause;
- primary/secondary scope or null when unresolved;
- resolved window and elapsed duration, unsigned and explicitly bounded;
- fixed-size counters for entered assessments and relevant stages;
- nullable stage timing aggregates with documented overlap/measurement bounds.

Example shape, not a measured result:

```json
{"schema":1,"operation":"ir_request_evaluation","phase":"evaluation","authentication_granted":false,
 "result":{"kind":"would_grant","identity_acceptance":"both"},
 "scope":"primary","window_ms":15000,"elapsed_ms":2400,
 "initialization_ms":500,
 "counts":{"assessments":2,"captures":2,"detections":2,"pad":1,"identity":1},
 "timings_ms":{"load":100,"capture":2100,"detection":20,"pad":5,"identity":120}}
```

The final JSON contract must reject unknown/duplicate fields, invalid variants,
nonfinite or negative numbers and contradictory result/acceptance fields. No
acceptance label survives cancellation, expiry or a failed final boundary.
`ready` is valid only for preflight with zero camera/assessment counters; it is
never a successful evaluation result.
One invocation has one terminal report, limited to 16 KiB. Counter or evidence
overflow makes the measurement incomplete rather than changing production
decision policy or silently discarding observations.

The outer receipt binds the reviewed source/executable/model/runtime identities,
anonymous scheduled attempt, actual process exit, supervision, cleanup and
preservation results. A report alone cannot certify its own successful delivery
or process exit. Partial output, panic, timeout, nonzero exit or unresolved
cleanup cannot become a successful would-grant observation.

Do not export scores, thresholds, names, paths, serials, raw exceptions,
identities, images, templates, embeddings, landmarks or enrollment fingerprints.
Configuration/model version identities needed by the campaign are recorded
through the reviewed outer manifest rather than copied from arbitrary output.

## Privacy and lifetime requirements

The storage read-only contract permits the existing transient camera lease,
emitter journaling/restoration and the supervisor's anonymous evidence ledger.
Those effects must stay scoped to their existing ownership and cleanup rules;
they do not permit mutation of protected account state.

Retain the existing root-owned artifact and no-debug/no-virtual-camera checks.
Disable core dumping and process dumpability before reading biometrics; suppress
dependency stderr before model loading. Hardware supervision must verify that
biometric memory cannot be paged to persistent swap. These are prerequisites,
not assertions that the tool is a sandbox for untrusted models.

All camera/metadata owners and the request key must be released on completion,
refusal, cancellation and panic paths. Cooperative deadlines may be exceeded by
an in-flight kernel/model call, but a late would-grant is forbidden. The outer
watchdog and unresolved-cleanup rules remain separate from the engine deadline.
Descriptor close must not be reported as optical emitter-off proof.

## Project structure and style

Proposed implementation locations:

- `crates/irlume-auth/src/ir_request_evaluation.rs`: feature-gated report and
  evaluator entry, with private typed projection rather than serializing `Outcome`.
- Existing `ir_assessment.rs`, `identity_arms.rs` and request helpers: only the
  minimal shared seams needed for equivalence and read-only acquisition.
- `crates/irlume-auth/examples/ir_request_evaluation.rs`: bounded private-input
  parser and output boundary, registered with required features in Cargo.toml.
- `scripts/ir-evaluation/`: additive request-report validation/supervision;
  existing one-shot contracts and tests remain supported.
- Focused Rust unit/integration tests and Python harness tests beside those files.

Use Rust edition 2021/MSRV 1.88, current enums/errors and existing dependencies.
No blanket lint suppression or new dependency is justified by this spec.
Represent mutually exclusive output states with an enum, for example:

```rust,ignore
enum EvaluationResult {
    Ready,
    WouldGrant { identity_acceptance: IdentityAcceptance },
    Refused { cause: RefusalCause },
    Incomplete { cause: MeasurementFailure },
}
```

These names are proposed types, not existing APIs. A successful internal
`Outcome` is projected into this measurement type; its reason/name/score never
cross the boundary.

## Testing strategy and success criteria

Tests use fake time and injected capture/storage boundaries with the real
decision logic; no camera or physical TPM is opened by offline tests.

1. Prove request equivalence on clean eligible inputs: one successful assessment;
   presence failures then a candidate; terminal below-threshold identity;
   mandatory PAD failure; and a retry that no longer fits the original window.
2. Prove primary and secondary binding, account policy and final revocation,
   including changes between readiness and the last decision.
3. Demonstrate zero protected-state recovery/write/provisioning calls with pending journals,
   missing locks, invalid state or read failures. Cover read-only race boundaries.
4. Cancel before capture, after capture, after PAD and after identity. Expiry
   and cancellation must remove candidate/acceptance evidence and release owners.
5. Cover best-only, centroid-only, both and neither under existing count/adapter
   rules. Below-threshold identity remains terminal; no added identity retry.
6. Verify exact counters, one terminal record, bounded schema, old-schema
   compatibility and rejection of forged success/unknown/private output fields.
7. Show that no public diagnostic return or executable output can invoke PAM,
   publish enrollment or deliver a credential. Report/exit/cleanup failures are
   retained as failed or incomplete attempts.
8. Preserve default production behavior and feature exclusion. Existing full
   workspace checks and relevant software-TPM tests must pass before publication.

Relevant commands, to be run after implementation (not results):

```sh
cargo +1.88.0 fmt --all --check
cargo +1.88.0 test --locked -p irlume-auth --lib
cargo +1.88.0 test --locked -p irlume-auth --features ir-only-evaluation --lib --examples
cargo +1.88.0 clippy --locked --all-targets -- -D warnings
cargo +1.88.0 clippy --locked -p irlume-auth -p irlume-camera --features irlume-auth/ir-only-evaluation --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo +1.88.0 doc --workspace --no-deps --locked
./scripts/run-tests-guarded.sh --min 2720 -- cargo +1.88.0 test --workspace --locked
python3 -m unittest discover -s scripts/ir-evaluation -p 'test_*.py'
cargo +1.88.0 build --release --locked -p irlume-auth --features ir-only-evaluation --example ir_request_evaluation
```

Use separate target directories for comparisons. Any software-TPM case uses the
existing `with-swtpm.sh`/explicit test selection, never an all-ignored sweep or a
fallback to the physical TPM. The root AGENTS.md supplies the remaining gates.

## Boundaries and approval

- Always: preserve current authentication policy, reuse the production decision
  logic, keep records private/bounded, retain failures and verify cleanup.
- Ask before: a camera pilot, new participant enrollment, an expanded service or
  target scope, storage/security-policy changes, publication or installation.
- Never: grant from a diagnostic, silently repair protected state, relax a test
  or threshold, reuse old readiness, or describe this evaluator as qualification.

The version-1 scope and read-only refusal semantics above are approved.
Quantitative qualification targets, recruitment and hardware campaign approval
remain separate. Implementation follows the task-specific plan and test gates;
approval is not completed test evidence.
