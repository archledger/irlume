# ADR-0012: Maintain a GitHub-only pamsm fork

**Status:** Accepted
**Date:** 2026-08-20
**Implementation:** Complete. Fork repository
<https://github.com/archledger/pam_sm_rust>, branch `irlume-patches` at
`ac9f644240e95c49246cb6b55adce2f2aea12a77` (signed annotated tag
`irlume-0.5.5-patch.1`, GPG `F35053398E3C80FE20891B82C10B8492BD7F30C6`;
the governance PR #1 squash-merged as the GitHub-signed, DCO-carrying commit
`ac9f644240e95c49246cb6b55adce2f2aea12a77`). irlume consumes exactly that
rev: PR #505, merged as `aef04e6653cd91c5af843bf6c155a38e0729b629` (tree
`c8d39511fee27957fb02cf6a9708853363123044`); the vendored
`third_party/pamsm-0.5.5` copy is deleted and forbidden to return by
`scripts/check-packaging-parity.sh`. Evidence:
[`docs/research/2026-08-20-maintained-pamsm-fork-verification.md`](../research/2026-08-20-maintained-pamsm-fork-verification.md)

## Context

Irlume implements a Linux-PAM service module through `pamsm 0.5.5`. That
release was published and tagged on 2024-06-28, and the upstream repository has
had no commits since. The much older date shown for the project's latest GitHub
Release belongs to release object 0.3.0, not to the crates.io 0.5.5 package.
The distinction does not change the maintenance conclusion: irlume cannot rely
on timely upstream security or compatibility work.

PR #502 needed two binding changes for its single-field privileged
authentication contract:

- clear `PAM_AUTHTOK` with `pam_set_item(PAM_AUTHTOK, NULL)` before face work;
- display informational text without borrowing a conversation response.

The temporary in-tree patch also removed two invalid-pointer dereferences found
by GitHub CodeQL. Reviewing the remaining binding exposed further ownership
work that should not remain anonymous dependency debt: exported PAM callbacks
need complete pointer validation and panic containment, the cross-thread handle
escape is unnecessary for irlume, and module-data secret buffers need explicit
zeroization.

The binding is small enough for downstream ownership, and irlume already uses
the same exact-revision fork model for `rust-tss-esapi`. A maintained GitHub
fork preserves upstream history while giving irlume an auditable place for CI,
security policy, issues, and future Linux-PAM improvements.

## Decision

Fork `https://github.com/rcatolino/pam_sm_rust` to the public repository:

```text
https://github.com/archledger/pam_sm_rust
```

Use GitHub as the only distribution channel. Do not publish a crates.io package
and do not rename the Cargo package or Rust crate. Irlume will select the fork
through Cargo's patch mechanism with the Git URL above and the full 40-character
OID of the verified hardening checkpoint. That OID does not exist until the
hardening commits are created; the migration records it directly and never
substitutes a branch or tag.

The fork has two long-lived branches:

- `master` mirrors the original upstream and receives no irlume-only changes;
- `irlume-patches` is the protected default branch and maintained release line,
  initially based on upstream tag `0.5.5`.

The dependency is a permanent irlume-owned security boundary, not a temporary
patch expected to disappear when upstream publishes again. A future maintained
upstream or alternative binding may replace it only after an explicit design,
API audit, complete PAM tests, and installed acceptance testing.

The first pinned fork revision must include the existing token-clearing and
response-free informational APIs plus the complete initial hardening defined in
the related design. Irlume must not release with a partially initialized fork.

## Alternatives considered

### Keep the source under `third_party/`

This is reproducible and currently tested, but it provides no independent CI,
branch protection, issue history, security policy, or reusable audit trail.
It also makes a permanent fork look like a one-off source patch. Rejected.

### Publish a renamed crates.io successor

This would improve registry discovery but creates a second package identity,
release channel, ownership surface, and consumer compatibility promise that
irlume does not need. The user explicitly chose GitHub-only distribution.
Rejected.

### Migrate immediately to another Rust PAM binding

`pam-bindings 0.3.0` is actively maintained and has useful FFI hardening, but
it does not expose every Linux-PAM operation irlume currently needs. Migration
would still require an irlume-owned adapter and would change a larger part of
the already live-tested authentication boundary. Keep it as a future
alternative, not the initial ownership strategy.

### Hand-write the complete PAM ABI in irlume

Irlume uses only part of PAM, but entrypoint generation, error values, items,
module data, cleanup callbacks, and conversations are a coherent reusable
boundary. Embedding all of that in the product would couple application logic
to unsafe ABI details. Rejected.

## Consequences

- Irlume owns security response, compatibility, tests, and maintenance for the
  forked boundary.
- Every irlume build resolves the same reviewed Git commit; branch movement
  cannot change a locked build.
- Distribution remains offline-capable through `cargo vendor --locked` and the
  existing source-completeness checks.
- The in-tree `third_party/pamsm-0.5.5` copy and its path-specific packaging
  rules are removed only after the Git revision passes all migration gates.
- Fork checkpoints use signed annotated Git tags for provenance; tags and
  branches are never dependency selectors.
- Upstream copyright, license, history, and attribution remain intact.
- Public issues and contributions may improve the fork, but irlume's verified
  Linux-PAM requirements determine support scope and release timing.

The detailed contract is in the
[GitHub-maintained pamsm fork design](../superpowers/specs/2026-08-20-github-maintained-pamsm-fork-design.md).
