# GitHub-maintained pamsm fork design

Date: 2026-08-20

Status: implemented; irlume pins fork rev
`ac9f644240e95c49246cb6b55adce2f2aea12a77` (tag `irlume-0.5.5-patch.1`,
merged in PR #505 as `aef04e6653cd91c5af843bf6c155a38e0729b629`);
verification at
[`../../research/2026-08-20-maintained-pamsm-fork-verification.md`](../../research/2026-08-20-maintained-pamsm-fork-verification.md);
implementation plan at
`../plans/2026-08-20-github-maintained-pamsm-fork.md`

Related decisions and evidence:

- [ADR-0011: Use one hidden field for privileged face intent or password](../../adr/0011-single-field-privileged-auth-input.md)
- [ADR-0012: Maintain a GitHub-only pamsm fork](../../adr/0012-maintain-pamsm-github-fork.md)
- [Single-field privileged authentication verification](../../research/2026-08-19-single-field-privileged-auth-input-verification.md)
- Upstream repository: <https://github.com/rcatolino/pam_sm_rust>
- Upstream base: tag `0.5.5`, commit
  `a51131ebaa252a9c77727f65d962d33d8a632e87`
- Upstream crates.io checksum:
  `aad7ddca63c73e80eb4ace88e130c9b513da6ec1284becd9fc1fc385a9a72a64`

## Purpose

Create and maintain a public, GitHub-only fork of `pamsm` as an explicit
irlume security dependency. The fork must preserve the product behavior
verified in PR #502 while replacing the temporary in-tree patch with a
protected, independently tested, exact-revision source.

The fork is not a general PAM rewrite and is not a registry publication
project. It exists so irlume can review, harden, and evolve the small Rust
service-module boundary on its own schedule without silently trusting a dormant
upstream.

## Binding decisions

The following decisions are fixed:

1. The public repository is `archledger/pam_sm_rust` and remains a GitHub fork
   of `rcatolino/pam_sm_rust`, preserving network history and attribution.
2. Distribution is GitHub-only. No crates.io package, alternate registry,
   GitHub binary Release, or renamed Cargo package is created.
3. The Cargo package and Rust crate remain named `pamsm`.
4. Irlume pins a full 40-character Git commit OID. It never selects a moving
   branch, tag, short OID, or GitHub archive URL.
5. `master` is an upstream mirror. `irlume-patches` is the protected default
   branch and the only branch from which irlume pins revisions.
6. The fork is permanent downstream ownership. Upstream inactivity is not
   treated as a temporary outage.
7. The first migration is release-blocking for irlume. It must finish before
   the next irlume release, but remains separate from already merged PR #502.

## Repository creation and provenance

Before creating anything, verify that `archledger/pam_sm_rust` does not already
exist and that the authenticated GitHub account is `archledger`. Create the
repository with GitHub's fork operation rather than importing a source archive.
Do not retry creation blindly: read the repository state after any uncertain
response.

The new fork must retain upstream commits and tag `0.5.5`. Record the base
commit and crates.io checksum above in the fork README and a dedicated
`IRLUME-MAINTENANCE.md` file. The maintenance file distinguishes:

- upstream files retained unchanged;
- downstream hardening commits;
- APIs removed or changed;
- the exact irlume PR and fork commit that introduced each downstream change;
- the process for evaluating later upstream work.

Create `irlume-patches` directly from upstream tag `0.5.5`. Never squash or
rewrite upstream history. Downstream commits are signed, contain one DCO
trailer, and remain individually reviewable. Force pushes are prohibited after
the branch is published.

After the first verified hardening checkpoint, create a signed annotated tag:

```text
irlume-0.5.5-patch.1
```

The tag is provenance for humans. Cargo continues to pin its exact commit.
Later checkpoints increment only the patch suffix. No semantic-version or
registry-release promise is implied.

## Repository governance

The fork is public and accepts issues and pull requests. Its documented support
scope is deliberately narrow:

- Linux-PAM service modules;
- the current irlume MSRV, initially Rust 1.88;
- Linux distributions exercised by irlume packaging and PAM integration tests;
- APIs needed by irlume or justified by a concrete external PAM-module use.

The repository must contain:

- a README identifying the original project and the irlume maintenance scope;
- the original GPL-3.0 license and copyright notices without weakening or
  relicensing them;
- `SECURITY.md` with private vulnerability-reporting instructions;
- `CONTRIBUTING.md` describing tests, DCO, signed commits, unsafe-code rules,
  and compatibility expectations;
- `CODEOWNERS` naming the irlume maintainer for the complete crate;
- Dependabot or an equivalent Cargo dependency monitor;
- branch protection on `irlume-patches` with administrators included.

Required branch checks are formatting, strict Clippy, MSRV build/test,
pam_wrapper integration, ASan/LeakSanitizer, CodeQL Rust analysis, dependency
policy, workflow-security linting, and exactly-one-trailer DCO validation. No
maintainer may merge by bypassing required checks. The solo-maintainer branch
does not require an impossible self-approval; required checks, resolved
conversations, signed commits, and DCO validation are the merge gate.

Normalize only the deprecated Cargo metadata spelling from `GPL-3.0` to
`GPL-3.0-only`. This describes the preserved upstream license accurately; it
does not relicense the code or add an “or later” grant.

## API ownership boundary

Keep the crate small. It owns:

- the opaque PAM handle wrapper;
- PAM flags and return codes used by service modules;
- checked `pam_sm_*` entrypoint generation;
- safe wrappers over the Linux-PAM item, token, environment, message, module
  data, and logging calls needed by supported consumers;
- secret-aware PAM module-data storage;
- conversion of FFI return codes to explicit Rust results.

It does not own:

- authentication policy;
- face, camera, gesture, or keyring logic;
- PAM client/application orchestration;
- a generic cross-platform PAM abstraction;
- async execution or cross-thread sharing of a PAM handle;
- fallback password validation;
- a replacement for Linux-PAM's token or conversation lifecycle.

Irlume continues to own all product policy. The fork supplies only the smallest
safe ABI and lifecycle boundary.

## Initial hardening checkpoint

The first `irlume-patches` checkpoint must include every item in this section.
Deferring a known item to “later” is not acceptable because the fork is being
created specifically to own this boundary.

### Existing PR #502 delta

Port the already verified downstream changes without semantic drift:

- `clear_authtok` calls `pam_set_item(PAM_AUTHTOK, NULL)`;
- `info` calls `pam_prompt(PAM_TEXT_INFO, NULL, "%s", message)`;
- the generic borrowed-response `conv` method is absent;
- embedded nulls in Rust messages fail closed before FFI;
- the informational format string is constant, never user-controlled.

The imported implementation must first be compared byte-for-byte with merged
irlume's `third_party/pamsm-0.5.5` delta. Subsequent hardening receives separate
commits and tests.

### Entrypoint validation

Every exported `pam_sm_*` function receives the C ABI shape directly and
validates it before constructing Rust references or slices:

- null `pamh` returns `PAM_ABORT`;
- negative `argc` returns `PAM_ABORT`;
- `argc > 0` with null `argv` returns `PAM_ABORT`;
- `argc` greater than 256 returns `PAM_ABORT` before allocation;
- a null element in the `argv` array returns `PAM_ABORT`;
- invalid UTF-8 in a module argument returns `PAM_SERVICE_ERR`, preserving the
  existing string-based public callback contract;
- the exported flags parameter remains raw `c_int`; conversion uses a bitflag
  representation that retains unknown bits, so no invalid Rust enum value or
  undefined behavior can be constructed;
- a panic in argument conversion, the service hook, or result cleanup is caught
  before it crosses the C boundary and becomes `PAM_ABORT`.

The macro must not accept the transparent `Pam` wrapper by value as its exported
ABI parameter. It accepts the raw PAM handle pointer, checks it, then creates a
non-owning opaque wrapper for the duration of the callback.

All six entrypoints—authenticate, set credentials, account management, open
session, close session, and change token—use the same checked dispatcher. No
callback has a weaker validation path.

### Handle confinement

PAM handles are process- and transaction-scoped and are not generally safe for
concurrent use. Remove `PamSendRef`, its `unsafe impl Send`, and public APIs that
encourage moving or sharing a handle across threads. The opaque `Pam` wrapper is
explicitly `!Send` and `!Sync`.

The fork may provide synchronous borrowed access only. Any future asynchronous
request must be designed around copying non-secret values away from PAM, not
around sending the handle.

### Secret lifecycle

PAM authentication tokens remain borrowed from Linux-PAM. The fork never logs,
formats, or implements `Debug` for token contents.

Replace the current `send_bytes` storage, which owns a plain `Vec<u8>`, with an
opaque `PamSecretBytes` value whose allocation is zeroized before release. Its
public API permits:

- construction from owned bytes;
- length and emptiness checks;
- explicitly named borrowed exposure for the shortest possible scope;
- cloning only into another zeroizing secret value;
- no `Display`, plaintext `Debug`, implicit string conversion, or ordinary
  `Vec<u8>` return.

`send_secret` stores a boxed `PamSecretBytes` through `pam_set_data`.
`get_secret` returns a borrow tied to the PAM transaction. The cleanup callback
catches panics, zeroizes and frees the secret exactly once, handles replacement
and transaction end, and tolerates a defensive null pointer without
dereferencing it.

The old `send_bytes` and `retrieve_bytes` APIs are removed rather than left as
non-zeroizing alternatives. Irlume's reseal and keyring handoff call sites
migrate to the secret API in the same product migration.

### FFI declarations and unsafe discipline

Match declarations against the Linux-PAM headers shipped on the oldest and
newest supported distribution lanes. Enable crate-level denial of
`improper_ctypes`, `improper_ctypes_definitions`, and unsafe operations inside
unsafe functions. Every unsafe expression has a local safety explanation.

Keep FFI declarations private unless a public raw API has an independently
reviewed consumer. Safe wrappers must check returned status before reading an
output pointer and must treat success with an unexpected null output as a
fail-closed PAM error.

No wrapper may infer pointer validity solely from a success status when the API
contract permits null. No borrowed value may outlive the callback or PAM
transaction that owns it.

## Error semantics

The fork preserves exact PAM return values where Linux-PAM supplies one.
Wrapper-local failures map as follows:

| Failure | Result |
|---|---|
| Invalid exported handle/argument pointer or panic | `PAM_ABORT` |
| Invalid UTF-8 module argument | `PAM_SERVICE_ERR` |
| Embedded null in a Rust-to-C string | `PAM_SERVICE_ERR` |
| Conversation unavailable/fails | Underlying PAM error |
| PAM reports success with missing required output | `PAM_SYSTEM_ERR` |
| Module-data type/key mismatch | Existing PAM error or `PAM_SYSTEM_ERR` |

The crate must not silently translate a security-boundary failure to success or
`PAM_IGNORE`. Product modules remain free to choose `PAM_IGNORE` after receiving
an explicit safe wrapper error.

## Test strategy

### Pure boundary tests

Test the shared entrypoint dispatcher directly for null handles, negative and
oversized counts, null arrays, null elements, invalid UTF-8, unknown flags,
normal arguments, and panicking hooks. Each exported macro route must be proven
to use that dispatcher.

Test result conversion for every PAM code represented by the crate, including
unknown integer values. Test all string wrappers for embedded nulls and
success-with-null outputs through injectable internal FFI seams or a purpose
built test library; do not dereference fabricated pointers merely to satisfy a
unit test.

Test `PamSecretBytes` for redacted formatting, zeroization on normal drop,
replacement cleanup, transaction cleanup, panic containment, and exactly-once
freeing. A sabotage test must temporarily replace zeroization with an ordinary
drop and demonstrate that the zeroization assertion fails.

### Real PAM integration

Build a small test service module from the fork and run it through pam_wrapper
and pamtester. Cover all six exported entrypoints, module arguments, item
get/set, user lookup, token get/set/clear, response-free informational text,
environment mutation, module-data replacement, and cleanup.

Fixed dummy tokens only are permitted in CI. Captured stdout, stderr, debug
formatting, and test artifacts must contain no dummy token. Run integration
tests serially when PAM process-global state requires it.

### Sanitizers and static analysis

Run the full fork suite with AddressSanitizer and LeakSanitizer on nightly Rust.
Suppress only a deliberate leak with a named allocation stack and written
rationale; otherwise sanitizer output is a failure. Run CodeQL Rust analysis on
every pull request and branch push. The two pointer patterns removed in PR #502
must have explicit absence or regression tests so they cannot reappear under a
different helper name.

### Compatibility

Compile and test at Rust 1.88 and current stable. Verify the generated `cdylib`
exports exactly the six expected `pam_sm_*` symbols and no accidental secret or
test symbol. Run Linux-PAM integration on Ubuntu in GitHub Actions and in the
Fedora lane used by irlume before the first pin.

## Fork CI and branch protection

Use SHA-pinned GitHub Actions with `persist-credentials: false` and least
privilege permissions. Required checks on `irlume-patches` are:

1. `fmt · clippy · build · test`;
2. `pam_wrapper integration`;
3. `AddressSanitizer (test suite)`;
4. `CodeQL / Analyze (rust)`;
5. `cargo-deny (advisories · licenses · sources)`;
6. `actionlint (workflow correctness)`;
7. `zizmor (workflow security)`;
8. `DCO (exactly one trailer)`.

Administrators are subject to protection. Require pull requests, linear
history, resolved review threads, signed commits, and one DCO trailer per
commit. Set the approving-review count to zero because GitHub does not permit a
pull-request author to approve their own change and this repository initially
has one maintainer. Disable force pushes and branch deletion. Do not grant
workflows write permissions or preserve checkout credentials unless a
separately reviewed release workflow requires them; this fork has no
publication workflow.

Dependabot may open Cargo and Actions updates. Each update passes the complete
required set. Automatic merging is disabled at the authentication boundary.

## Irlume dependency migration

Migration happens in a new irlume branch from current `main`, after the fork's
hardening checkpoint is green and tagged.

Change the root patch from the local path to the fork URL and the full
40-character OID produced by the verified hardening checkpoint. The OID is an
implementation output and therefore cannot be named before the fork commits
exist; the migration must insert the literal OID and must not use
`irlume-patches`, a tag, or an abbreviated hash. Keep the member dependency
declaration compatible with the unchanged package name.

Then:

1. update `Cargo.lock` and verify the pamsm source names the exact Git OID;
2. adapt `irlume-pam` only where the fork intentionally changes hardening APIs,
   particularly secret module data;
3. remove `third_party/pamsm-0.5.5` and its path-specific `.gitattributes` rule;
4. replace packaging parity's local-file assertions with exact Git-source,
   locked-resolution, clean-archive, and offline-vendor assertions;
5. update ADR-0011, ADR-0012, setup/development guidance, and the verification
   report with the fork OID and tag;
6. scan the tree for the old path, response-returning `conv`, `PamSendRef`, plain
   secret byte storage, and moving branch selectors.

The migration must not change the daemon wire protocol, service classification,
keyboard-confirmation state machine, passive PAD, face matching, or installed
PAM stack.

## Irlume verification and installed acceptance

The migration candidate must pass:

- formatting, all-target strict Clippy, rustdoc warnings, and release build;
- guarded full workspace tests;
- all 38 current pam_wrapper tests plus new fork-specific secret and ABI cases;
- the exact ASan/LeakSanitizer workspace workflow;
- CodeQL with no new alerts;
- cargo-deny and packaging parity;
- clean `git archive`, `cargo vendor --locked`, and locked offline resolution;
- machine conformance and unchanged-wire comparison;
- the physical camera gate only if product code outside the PAM boundary changes.

Build the exact release PAM artifact and install it transactionally on the
Fedora KDE laptop with a new byte-for-byte rollback snapshot. Repeat the five
accepted cases from ADR-0011:

1. `yes` displays the exact message and grants through face;
2. one correct password authenticates once with no camera;
3. wrong password then correct password remains camera-free;
4. empty Enter then cancel remains unauthorized and camera-free;
5. camera-busy face failure falls back to one fresh password prompt and never
   tests `yes` as a Unix password.

Correlate each case with PAM audit and daemon logs without observing or
recording credentials. Restore the previous module automatically on any failed
install or health check.

## Rollback

Fork hardening is additive Git history. A bad fork commit is reverted with a
new signed commit; do not rewrite the protected branch.

Before irlume migration, the current in-tree patched source remains the product
fallback. During migration, preserve the previous Cargo files and installed PAM
bytes in the normal rollback snapshot. Reverting the irlume migration commit
must restore the local path dependency and compile without requiring the fork.

Do not delete the source branch or installed rollback snapshot until the forked
candidate has passed CI, landed in irlume main, and completed installed KDE
acceptance. GitHub repository deletion, transfer, visibility changes, and
crates.io publication are outside this design and require new explicit user
authorization.

## Ongoing maintenance

Before each irlume release:

- review new upstream pamsm commits and open security reports;
- review fork dependency and Actions updates;
- rerun the fork's required checks at the pinned OID;
- verify irlume's lockfile still names that OID;
- confirm the maintenance and security documents remain accurate.

An upstream update is imported to `master` first. Moving `irlume-patches` to a
new upstream base requires a dedicated pull request, source diff, API review,
PAM integration suite, and irlume migration. Never merge upstream changes
directly into the protected patch branch without separating upstream and
downstream deltas.

Public enhancements are accepted only with a concrete service-module use case,
documented safety contract, tests, and no weakening of irlume's fail-closed
defaults. Compatibility is governed by documented API review and exact Git
pins, not by an unpublished semantic-version promise.

## Acceptance criteria

The project is complete only when:

- `archledger/pam_sm_rust` exists as a public GitHub fork with preserved
  upstream history and license;
- `irlume-patches` is the protected default branch and all required checks are
  enforced for administrators;
- the complete initial hardening checkpoint is implemented and green;
- the checkpoint has a signed annotated tag and immutable full OID;
- irlume pins that OID and contains no in-tree pamsm copy or moving selector;
- source archives and offline vendor builds remain complete;
- all software, sanitizer, CodeQL, PAM integration, packaging, and installed KDE
  acceptance gates pass;
- the exact fork and irlume OIDs, test totals, known limitations, and rollback
  are recorded in shared memory and repository verification evidence;
- no crates.io package or release has been created.
