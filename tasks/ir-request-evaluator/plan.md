# IR verification-request evaluator implementation plan

Approved scope: [spec](../../docs/superpowers/specs/2026-11-09-ir-request-evaluator.md).
Base: `bbb2d84f644e3f2d50686cbeb8d2f3d7b37acf8e`. The owner authorized autonomous
execution of routine planning, implementation and offline validation. Existing
nightly-snapshot plans remain preserved; this task uses [todo.md](todo.md).

## Decisions

1. Add a core read-only account view using the existing account lock without
   creating it. Refuse pending primary replacement or secondary intent before
   and after the read. Check the read snapshot again to detect changes from
   legacy writers that do not hold the account lock. Never call recovery.
2. Reuse primary parsing/key handling by extracting the already-locked body of
   the existing loader, keeping production call order unchanged. Read-only
   diagnostics borrow the request key; no extra unseal or owned key copy.
3. Keep a private, feature-gated evaluation context on a scoped Engine borrow.
   Restore it on return/panic. The evaluator calls the normal verification
   entry; only protected-state acquisition/final reads select read-only mode.
   Default builds have no evaluator path or public diagnostic endpoint.
4. Observe stages and both identity predicates through private typed hooks.
   Project only the final settled result after deadline/revocation checks;
   never serialize `Outcome` or its score/reason/name.
5. Use a separate request-report schema and additive supervisor mode. Preserve
   one-shot diagnostic schemas and their stricter existing topology behavior.
   Request-mode topology must be independently checked for the declared exact
   configured IR target; no blanket relaxation of the legacy harness.

## Dependency order

Read-only state view -> scoped request/report context -> real Engine route ->
developer executable -> strict supervisor integration -> full verification.
The report model and filesystem test fixtures can be developed independently,
but integration and validation of shared Engine changes are sequential.

## Verification checkpoints

- After read-only state work: core tests prove no file/key/journal changes,
  absent/busy lock refusal, pending/late intent refusal, and race rejection.
- After Engine integration: injected capture/time tests compare real request
  results and count retries, identity decisions, cancellation and revocation.
- After executable/supervisor integration: unarmed subprocess tests, strict
  schema tests, old-mode compatibility, mutation checks, all required local
  Rust/Python checks, docs and release builds.
- Hardware remains unrun until a separately prepared, freshly attended pilot.

## Risks

| Risk | Control |
| --- | --- |
| Secondary final reads call recovery | Dedicated read-only view and explicit no-recovery tests; share pure predicates only |
| Lock reentry deadlocks | Already-locked loader boundary, no lock-taking callbacks; fail closed on a busy diagnostic lock |
| Evaluation state leaks into authentication | RAII scope, nested-call refusal, unwind/repeated-request tests and feature exclusion |
| Observation changes decisions | Typed side-channel observation only; identical production tests and explicit equivalence cases |
| Stale success survives final cancellation | Build report after the normal entry returns and final checks settle |
| Wrapper passes the wrong topology or stale result | Exact mode/schema/source binding and negative integration cases |

The detailed checklist records completion only from observed test/build results.
