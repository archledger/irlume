# Nightly snapshot foundation tasks

## 1. Candidate contract

- [x] Add a versioned candidate schema and pure validation/decision logic.
- [x] Require correct repository/ref/commit/tree, source input digests,
  policy identity and all nine qualified checks.
- [x] Cover selected, unchanged and hold outcomes, malformed/duplicate JSON,
  wrong identities, missing/duplicate/substituted checks and stale attempts.
- Verify: focused Python unittest suite, schema examples and negative mutations.
- Files: `scripts/ci/nightly-snapshot.py`,
  `scripts/ci/test-nightly-snapshot.py`, `schemas/nightly-candidate-v1.schema.json`.

## 2. Read-only evidence collector

- [x] Fetch only expected GitHub repository endpoints, with bounded time,
  response size and pagination; never interpolate credentials into commands.
- [x] Resolve main once, retrieve its immutable source inputs and check
  evidence, compare required-check policy, and detect a mid-collection move.
- [x] Test API failures, incomplete pages, wrong workflows, reruns and drift
  without making real network calls.
- Verify: mocked-boundary tests plus inspection that no mutation endpoint exists.
- Files: collector module if needed, decision module and focused test file.
- Depends on task 1.

## 3. Local command and output

- [x] Add the documented CLI, bounded JSON decisions and private local
  output; preserve existing output on interruption or a conflicting slot.
- [x] Test retries, previous candidates, write failures and command exit codes.
- [x] Finalize usage/source-inventory documentation and run the complete
  focused verification set. No schedule or publisher is added.
- Verify: subprocess CLI tests, Python compile, Ruff, schema checks and
  `git diff --check`; record self-review and mutation evidence.
- Files: existing new modules/tests and the approved specification.
- Depends on task 2.

## Final checkpoint

- [x] Every focused test passes; no test or gate was weakened.
- [x] Candidate output is explicitly separate from a published release.
- [x] Existing nightly/stable/package/installer behavior is unchanged.
- [x] Evidence and exact resumption state are saved before reporting completion.

## Foundation verification result

On 2026-10-25, the final implementation passed 39 focused tests, eight isolated
mutation checks, Ruff check/format, Python compilation and schema validation.
Existing machine API (5), PPA nightly (35) and nightly coverage contract (5)
tests passed; the PPA tests emitted existing unclosed-lock ResourceWarnings.
AGENTS checks and Rust formatting passed. No tracked file changed.

Independent static review found one ordering-dependent malformed-input exit
code; a failing regression reproduced it, and validation now precedes hold
decisions. The follow-up review found no new actionable issue.

A bounded live collector smoke returned `hold: workflow-not-successful` after
six GET requests. It did not exercise complete live job/source collection or
select a candidate. Full Rust builds/workspace/hardware tests were not run;
the isolated machine API test had no local release binary. No schedule, CI
wiring, publisher or installer was changed. Tests remain manually invoked.

## CI-readiness follow-up

- [x] Invoke the offline suite in the required hosted check before models.
- [x] Make every branch push eligible for exact-commit workflow audits;
  preserve audit names, permissions, runners and weekly/manual triggers.
- [x] Add workflow contracts and previous-record hold regression coverage.
- [x] Complete a manual local live-GitHub collection and label injected
  failed/missing/unavailable evidence separately.
- [x] Verify formatting, schema/compilation, action pins, actionlint,
  offline zizmor and twelve isolated mutations.
- [x] Complete independent static review and archive final state.

The final local suite passes 43 tests. The live collector selected
`339cb8b75a3adb4807031ef4eb25dc70ad0770b4` using all nine checks after 45 GETs
in 11.113 seconds. Three injected failure cases preserved that candidate's
bytes. Those cases are fault-injection evidence, not real failing CI runs.

Changes are still local and uncommitted. The new CI invocation has not run
on GitHub. Nothing was pushed or dispatched; no publisher, selector timer,
installer, host authentication or physical hardware was changed. Zizmor used
the cached 1.28.0 image offline; its existing 37 suppressions were unchanged.
Independent static review found no actionable defects in this CI delta.
It did not execute tests or authorize publication.
