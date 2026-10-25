# Nightly snapshot foundation implementation

Specification: [daily nightly snapshot](../docs/superpowers/specs/2026-10-25-nightly-snapshot.md).
Owner approved the specification and its read-only boundary. This plan covers
only that foundation, not release publication or installation.

## Build order

1. Candidate contract and decision logic.
2. Read-only GitHub collection against that contract.
3. Local output, command-line interface and documentation.

Tasks and verification are recorded in [todo.md](todo.md).

## Design constraints

- Use Python 3 and existing repository tools. No new package dependency.
- Separate the pure decision function from network I/O and local output.
- Fix the repository and workflow identities; names alone are insufficient.
- Bind every source observation to the selected full commit. Recheck main
  after collection and hold if it moved during collection.
- Capture the union of classic and ruleset required checks. A mismatch with
  the reviewed policy is a hold, never an automatic policy change.
- Inspect the newest applicable run and its current attempt; require every
  expected job to complete successfully. Missing/ambiguous data holds.
- Enumerate the existing lockfiles and model/runtime declaration files.
  Record source-file digests without claiming a complete resolved build
  closure. The Git tree identifies the rest of the source.
- Fixture inputs prove parser/decision behavior only. They cannot authorize
  signing, publication, installation or channel promotion.
- Leave existing schedules, publishers, installers and package versions alone.

## Verification boundary

Tests use synthetic API responses and private temporary directories. A
separately invoked live smoke may read public repository metadata only;
it must never dispatch a workflow or inspect credentials in its output.
Do not start PR monitoring or run physical hardware tests.

## Known operational limit

The current workflow audit has path filters. Most application-only commits
therefore have no exact-commit audit run. The approved policy must report a
hold for those commits. A later scheduled publisher must arrange those checks
or obtain a reviewed policy change; this foundation must not relax the gate.

## Completion

All named positive/negative tests, schema validation, Python compilation,
Ruff and diff checks pass. Record limitations and mutation results. Stop
before publishing a PR, enabling a schedule or creating a release.

## Approved follow-up: CI readiness

The owner approved this follow-up after the local foundation passed its checks:

1. Run the focused offline tests in the existing required, hosted CI check,
   after its existing Python dependencies and before model downloads.
2. Remove path filtering from the hosted workflow audit's push trigger so
   every main commit can acquire the same two exact-SHA audit checks. Keep
   existing weekly/manual triggers, job names, permissions and runners.
3. Lock those workflow contracts with tests. Run one local, manually invoked
   end-to-end collection against live GitHub metadata. Then inject failed,
   incomplete and unavailable evidence to prove preservation of that live
   candidate; label injections separately from live observations.

Do not push a branch merely to run these checks: existing push automation
includes hardware work, excluded from this task. Do not add a selector timer,
publisher, installer or new credential. Hosted execution of the new CI step
requires separately authorized integration; a local live collector run does
not prove that the new step has run on GitHub.
