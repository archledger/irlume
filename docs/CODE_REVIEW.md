# Code review requirements

Every change to `main` arrives as a pull request and is reviewed before merge.

## What is reviewed

1. **Correctness**: the diff is read against its stated intent; a regression
   test accompanies every confirmed defect fix.
2. **Security**: trust boundaries (daemon socket authorization, PAM surfaces,
   TPM/keyring state, file modes) are checked at the touched code; new
   dependencies require an audit note.
3. **Tests**: the full workspace suite, clippy `-D warnings`, `rustfmt`, the
   warnings-denied documentation build
   (`RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked`),
   and the relevant hardware lanes must pass on the final head before merge.
   Pending Packit builds are recorded honestly, never claimed as passed.
4. **Docs**: behavior changes update `CHANGELOG.md`; interface changes update
   `docs/MACHINE-API.md` and the schema. A change that makes a line of an
   `AGENTS.md` wrong (a command, path, CI lane, toolchain version or rule it
   cites) fixes that line in the same PR; CI's `scripts/check-agents-md.py`
   catches cited paths git no longer lists, broken links, and gate commands
   the `check` job in `ci.yml` no longer runs.

## How review is conducted

This is a solo-maintainer project. Proposed modifications - whether from the
project's automation or from human contributors, whom `CONTRIBUTING.md`
welcomes - are gated by the owner before every merge. The primary reviewer
is the validation itself: the required checks on the final head, the
hardware lanes (real TPM, real cameras, PAM) and the exhaustive audits
(security, keyring/recovery, uninstall) that preceded releases. Branch
protection on `main` enforces those checks for every merge.

## What is required to be acceptable

A change is acceptable when it matches the agreed intent, adds or updates
tests for changed behavior, keeps the password fallback always available,
fails closed on hardware and state errors, and does not weaken any existing
guarantee (votes, budgets, modes, authorization posture) without an ADR.
