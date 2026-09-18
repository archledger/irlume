# Code review requirements

Every change to `main` arrives as a pull request and is reviewed before merge.

## What is reviewed

1. **Correctness**: the diff is read against its stated intent; a regression
   test accompanies every confirmed defect fix.
2. **Security**: trust boundaries (daemon socket authorization, PAM surfaces,
   TPM/keyring state, file modes) are checked at the touched code; new
   dependencies require an audit note.
3. **Tests**: the full workspace suite, clippy `-D warnings`, `rustfmt`, and
   the relevant hardware lanes must pass on the final head before merge.
   Pending Packit builds are recorded honestly, never claimed as passed.
4. **Docs**: behavior changes update `CHANGELOG.md`; interface changes update
   `docs/MACHINE-API.md` and the schema.

## How review is conducted

- Proposed modifications are prepared on feature branches by the project's
  automation and reviewed by the owner, who is a different party from the
  author, before every merge. Branch protection on `main` requires one
  approving review and dismisses stale reviews after new pushes.
- Required status checks must pass on the final head; branches are updated
  and re-run when `main` moves under them.

## What is required to be acceptable

A change is acceptable when it matches the agreed intent, adds or updates
tests for changed behavior, keeps the password fallback always available,
fails closed on hardware and state errors, and does not weaken any existing
guarantee (votes, budgets, modes, authorization posture) without an ADR.
