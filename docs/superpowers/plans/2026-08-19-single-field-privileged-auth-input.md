# Single-Field Privileged Authentication Input Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Execute inline; the user explicitly requested no subagents.

**Goal:** Make the existing hidden privileged PAM field accept either explicit `yes` face intent or the user's ordinary password once, while empty/error paths remain camera-free.

**Architecture:** Collect the field through Linux-PAM's `pam_get_authtok` so PAM owns the password lifecycle and downstream modules reuse the cached token. Carry a pinned local `pamsm 0.5.5` patch exposing safe `PAM_AUTHTOK` clearing; clear empty/`yes` tokens before fallback or camera, and leave non-empty non-`yes` tokens untouched for `pam_unix`/SSSD. Keep the daemon protocol and attestation enforcement unchanged.

**Tech Stack:** Rust 1.88 workspace, Linux-PAM 1.7.x API, `pamsm 0.5.5`, pam_wrapper/pamtester/pam_exec, Cargo local patches, Fedora 44 KDE Plasma 6.7.4.

**Spec:** `docs/superpowers/specs/2026-08-19-single-field-privileged-auth-input-design.md`

## Global Constraints

- The visible informational message is exactly `Type yes to use face authentication`.
- Input stays echo-off and uses the client's normal localized password prompt.
- Only a freshly entered accepted `yes` spelling can create `IntentAttestation::PamConversation`.
- A pre-cached token is password state, never fresh face intent.
- Non-empty non-`yes` input remains in `PAM_AUTHTOK`; irlume never validates, serializes, or logs it.
- Empty input and `yes` are cleared before fallback/camera; clear failure aborts before daemon contact.
- Login, lock, unseal, keyring, optional gestures, passive PAD, daemon policy, wire schema, and PAM control stanzas do not change.
- Preserve upstream `pamsm 0.5.5` source, GPL-3.0 license, version, crates.io checksum `aad7ddca63c73e80eb4ace88e130c9b513da6ec1284becd9fc1fc385a9a72a64`, and patch provenance.
- Never place a real password in source, command arguments, logs, reports, shared memory, or test output.
- Update `/home/wisbfime/Agent Shared Memory/project-irlume.md` and its index row after every material task/commit and before context compaction.
- Every commit is GPG-signed and contains exactly one `Signed-off-by: archledger <archledger236@gmail.com>` trailer.

## File map

- `third_party/pamsm-0.5.5/`: exact attributed upstream crate plus the narrow `clear_authtok` addition.
- `third_party/pamsm-0.5.5/IRLUME-PATCH.md`: source checksum, upstream URL/license, local delta, and removal condition.
- `Cargo.toml`, `Cargo.lock`: select the reproducible local pamsm patch without changing the declared `irlume-pam` dependency range.
- `crates/irlume-pam/src/lib.rs`: three-way token classifier, exact info message, secure token acquisition/clearing, and PAM result mapping.
- `crates/irlume-pam/tests/pamwrap.rs`: real PAM-stack proof for one-field password reuse, empty fallback, face-failure fallback, cached-token precedence, and no-secret output.
- `docs/SETUP.md`: current sudo/polkit instructions for one field accepting `yes` or password.
- `docs/adr/0011-single-field-privileged-auth-input.md`, `docs/superpowers/specs/2026-08-19-single-field-privileged-auth-input-design.md`: implementation status and exact product OID after code freezes.
- `docs/research/2026-08-19-single-field-privileged-auth-input-verification.md`: offline and installed KDE evidence, artifact hashes, rollback, and known limitations.

---

### Task 1: Add the reproducible safe token-clear dependency seam

**Files:**

- Create: `third_party/pamsm-0.5.5/Cargo.toml`
- Create: `third_party/pamsm-0.5.5/Cargo.toml.orig`
- Create: `third_party/pamsm-0.5.5/License`
- Create: `third_party/pamsm-0.5.5/readme.md`
- Create: `third_party/pamsm-0.5.5/src/lib.rs`
- Create: `third_party/pamsm-0.5.5/src/libpam.rs`
- Create: `third_party/pamsm-0.5.5/src/pam.rs`
- Create: `third_party/pamsm-0.5.5/src/pam_types.rs`
- Create: `third_party/pamsm-0.5.5/IRLUME-PATCH.md`
- Modify: `Cargo.toml:102-133`
- Modify: `Cargo.lock` (`pamsm` package source/checksum)
- Test: `crates/irlume-pam/src/lib.rs:1016-1085`

**Interfaces:**

- Consumes: upstream `pamsm 0.5.5` `PamLibExt`, private `set_item`, and `PamItemType::AUTHTOK`.
- Produces: `fn PamLibExt::clear_authtok(&self) -> PamResult<()>`, implemented as `pam_set_item(PAM_AUTHTOK, NULL)` without exposing `Pam`'s raw handle.

- [ ] **Step 1: Add a compile-contract test that requires the missing API**

Add this test beside the existing classifier tests in `crates/irlume-pam/src/lib.rs`:

```rust
#[test]
fn pamsm_exposes_safe_auth_token_clearing() {
    fn require_api(pam: &Pam) -> pamsm::PamResult<()> {
        pam.clear_authtok()
    }
    let _: fn(&Pam) -> pamsm::PamResult<()> = require_api;
}
```

- [ ] **Step 2: Run the compile contract and capture RED**

Run:

```bash
cargo test -p irlume-pam --lib --no-run --locked
```

Expected: compile failure `E0599`, no method named `clear_authtok` for `&pamsm::Pam`.

- [ ] **Step 3: Copy the exact cached crate source and record provenance**

Copy the contents of the installed Cargo registry directory for `pamsm-0.5.5` into `third_party/pamsm-0.5.5/` without editing upstream files during the copy. Add `IRLUME-PATCH.md` containing:

```markdown
# irlume patch to pamsm 0.5.5

- Upstream: https://github.com/rcatolino/pam_sm_rust
- Crate: pamsm 0.5.5
- crates.io checksum: aad7ddca63c73e80eb4ace88e130c9b513da6ec1284becd9fc1fc385a9a72a64
- License: GPL-3.0 (preserved in License)
- Local delta: expose `PamLibExt::clear_authtok`, implemented with
  `pam_set_item(PAM_AUTHTOK, NULL)`.
- Reason: a privileged PAM module must remove the reserved `yes` token before
  camera work so downstream password fallback receives a fresh prompt.
- Removal: replace this directory when an audited upstream release provides
  equivalent token clearing and all PAM/KDE acceptance tests pass.
```

Verify copied source identity before editing by comparing every upstream file other than Cargo registry metadata and `IRLUME-PATCH.md` with the registry copy using `diff -ru`.

- [ ] **Step 4: Add only the clear method to the local pamsm API**

In the local `src/libpam.rs`, add to `PamLibExt`:

```rust
/// Remove the cached authentication token from this PAM transaction.
fn clear_authtok(&self) -> PamResult<()>;
```

Add to `impl PamLibExt for Pam` beside `set_authtok`:

```rust
fn clear_authtok(&self) -> PamResult<()> {
    unsafe { set_item(self.0, PamItemType::AUTHTOK, ptr::null()) }
}
```

Do not change `Pam`, expose a raw handle, or modify `conv` in this task.

- [ ] **Step 5: Select the local patch and refresh the lockfile**

Extend the existing root patch table:

```toml
[patch.crates-io]
pamsm = { path = "third_party/pamsm-0.5.5" }
tss-esapi = { git = "https://github.com/archledger/rust-tss-esapi", rev = "7567f6048d2bcb42779e80c0dad90e7eacf6185c" }
```

Run:

```bash
cargo update -p pamsm --precise 0.5.5
cargo metadata --locked --format-version 1 --no-deps
```

Expected: the resolved pamsm package has the local path and version `0.5.5`; no new package appears.

- [ ] **Step 6: Run GREEN dependency gates**

Run:

```bash
cargo test -p irlume-pam --lib --no-run --locked
cargo check --workspace --all-targets --locked
cargo deny check licenses sources
git diff --check
```

Expected: all pass; `deny.toml` continues accepting the preserved GPL-3.0 pamsm license and the path source creates no unknown registry/git source.

- [ ] **Step 7: Review and commit the dependency seam**

Inspect `git diff -- Cargo.toml Cargo.lock third_party/pamsm-0.5.5 crates/irlume-pam/src/lib.rs`. Confirm the copied crate differs from upstream only by the public method, implementation, and provenance document.

```bash
git add Cargo.toml Cargo.lock third_party/pamsm-0.5.5 crates/irlume-pam/src/lib.rs
git commit -S -s -m "fix(pam): expose safe auth token clearing"
git verify-commit HEAD
```

Expected: good signature, one DCO trailer, clean worktree.

---

### Task 2: Implement the one-field token state machine

**Files:**

- Modify: `crates/irlume-pam/src/lib.rs:35-78`
- Modify: `crates/irlume-pam/src/lib.rs:273-331`
- Test: `crates/irlume-pam/src/lib.rs:1048-1090`

**Interfaces:**

- Consumes: `PamLibExt::{conv,get_authtok,get_cached_authtok,clear_authtok}` and the existing privileged `ServiceKind` table.
- Produces:
  - `const FACE_INTENT_INFO: &str = "Type yes to use face authentication";`
  - `enum IntentInput { Confirmed, Empty, Password }`
  - `enum IntentConfirmation { Confirmed, Fallback, Abort }`
  - `fn classify_intent_input(Option<&[u8]>) -> IntentInput`
  - `fn resolve_intent_input(IntentInput, impl FnOnce() -> pamsm::PamResult<()>) -> IntentConfirmation`
  - private `fn confirm_face_intent_with(...) -> IntentConfirmation` closure seam for deterministic conversation-error tests

- [ ] **Step 1: Replace the old parser test with three-way RED expectations**

Write tests that use `matches!` rather than formatting the result:

```rust
#[test]
fn intent_input_separates_confirmation_empty_and_password() {
    for accepted in [b"yes".as_slice(), b" YES ", b"\tyEs\r\n"] {
        assert!(matches!(
            classify_intent_input(Some(accepted)),
            IntentInput::Confirmed
        ));
    }
    assert!(matches!(classify_intent_input(None), IntentInput::Empty));
    assert!(matches!(classify_intent_input(Some(b"")), IntentInput::Empty));
    for password in [
        b"no".as_slice(),
        b"correct horse battery staple",
        &[0xff, 0xfe],
        b"yes             x",
    ] {
        assert!(matches!(
            classify_intent_input(Some(password)),
            IntentInput::Password
        ));
    }
}

#[test]
fn empty_and_yes_require_successful_token_clearing() {
    for input in [IntentInput::Empty, IntentInput::Confirmed] {
        assert!(matches!(
            resolve_intent_input(input, || Err(PamError::SYSTEM_ERR)),
            IntentConfirmation::Abort
        ));
    }
    assert!(matches!(
        resolve_intent_input(IntentInput::Password, || panic!("must not clear password")),
        IntentConfirmation::Fallback
    ));
}

#[test]
fn conversation_errors_never_confirm_or_clear() {
    let token = CString::new("yes").unwrap();
    let kind = ServiceKind::Elevation;
    assert!(matches!(
        confirm_face_intent_with(
            kind,
            || Err(PamError::CONV_ERR),
            || Ok(Some(token.as_c_str())),
            || panic!("must not clear after info error"),
        ),
        IntentConfirmation::Fallback
    ));
    assert!(matches!(
        confirm_face_intent_with(
            kind,
            || Ok(()),
            || Err(PamError::CONV_ERR),
            || panic!("must not clear after token error"),
        ),
        IntentConfirmation::Fallback
    ));
}
```

- [ ] **Step 2: Run the focused tests and capture RED**

Run:

```bash
cargo test -p irlume-pam intent_input --locked -- --nocapture
```

Expected: compile failure because `IntentInput`, `classify_intent_input`, and `resolve_intent_input` do not exist.

- [ ] **Step 3: Implement the pure classifier and clear-result mapping**

Import `CStr` beside the existing `CString`, then replace the old prompt/parser definitions with:

```rust
const FACE_INTENT_INFO: &str = "Type yes to use face authentication";

#[derive(Clone, Copy, PartialEq, Eq)]
enum IntentInput {
    Confirmed,
    Empty,
    Password,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IntentConfirmation {
    Confirmed,
    Fallback,
    Abort,
}

fn classify_intent_input(response: Option<&[u8]>) -> IntentInput {
    let Some(response) = response else {
        return IntentInput::Empty;
    };
    if response.is_empty() {
        return IntentInput::Empty;
    }
    if response.len() <= 16 && response.is_ascii() {
        if std::str::from_utf8(response)
            .is_ok_and(|text| text.trim().eq_ignore_ascii_case("yes"))
        {
            return IntentInput::Confirmed;
        }
    }
    IntentInput::Password
}

fn resolve_intent_input(
    input: IntentInput,
    clear: impl FnOnce() -> pamsm::PamResult<()>,
) -> IntentConfirmation {
    match input {
        IntentInput::Password => IntentConfirmation::Fallback,
        IntentInput::Empty => match clear() {
            Ok(()) => IntentConfirmation::Fallback,
            Err(_) => IntentConfirmation::Abort,
        },
        IntentInput::Confirmed => match clear() {
            Ok(()) => IntentConfirmation::Confirmed,
            Err(_) => IntentConfirmation::Abort,
        },
    }
}

fn confirm_face_intent_with<'a>(
    service: ServiceKind,
    show_info: impl FnOnce() -> pamsm::PamResult<()>,
    get_token: impl FnOnce() -> pamsm::PamResult<Option<&'a CStr>>,
    clear: impl FnOnce() -> pamsm::PamResult<()>,
) -> IntentConfirmation {
    if !service.requires_face_intent_confirmation() || show_info().is_err() {
        return IntentConfirmation::Fallback;
    }
    let Ok(Some(token)) = get_token() else {
        return IntentConfirmation::Fallback;
    };
    resolve_intent_input(classify_intent_input(Some(token.to_bytes())), clear)
}
```

Do not derive `Debug` or implement display on these types.

- [ ] **Step 4: Replace the custom secret conversation with PAM token acquisition**

Implement `confirm_face_intent` as:

```rust
fn confirm_face_intent(pamh: &Pam, service: ServiceKind) -> IntentConfirmation {
    confirm_face_intent_with(
        service,
        || {
            pamh.conv(Some(FACE_INTENT_INFO), pamsm::PamMsgStyle::TEXT_INFO)
                .map(|_| ())
        },
        || pamh.get_authtok(None),
        || pamh.clear_authtok(),
    )
}
```

Retain the existing non-empty cached-token check before service classification. Extend the caller match:

```rust
match confirm_face_intent(&pamh, kind) {
    IntentConfirmation::Confirmed => Some(IntentAttestation::PamConversation),
    IntentConfirmation::Fallback => return PamError::IGNORE,
    IntentConfirmation::Abort => return PamError::ABORT,
}
```

Update comments to say the privileged one-shot prompt now obtains the ordinary PAM token; do not alter the active greeter `unseal` behavior.

- [ ] **Step 5: Run GREEN focused and crate tests**

Run:

```bash
cargo test -p irlume-pam --lib --locked
cargo clippy -p irlume-pam --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

Expected: all unit tests pass; no secret-bearing value is formatted or logged.

- [ ] **Step 6: Prove protocol and daemon scope stayed untouched**

Run:

```bash
git diff 392d15132322e2bde29559a23540ce9fbeb25f43 -- crates/irlume-common crates/irlume-daemon
```

Expected: empty output.

- [ ] **Step 7: Commit the state machine**

```bash
git add crates/irlume-pam/src/lib.rs
git commit -S -s -m "fix(pam): reuse privileged input as password"
git verify-commit HEAD
```

Expected: good signature, one DCO trailer, clean worktree.

---

### Task 3: Prove the real PAM stack uses one field safely

**Files:**

- Modify: `crates/irlume-pam/tests/pamwrap.rs:48-61`
- Modify: `crates/irlume-pam/tests/pamwrap.rs:437-609`
- Modify: `crates/irlume-pam/tests/pamwrap.rs:1116-1156`

**Interfaces:**

- Consumes: `FACE_INTENT_INFO`, pam_wrapper's `pam_set_items.so`, system `pam_exec.so expose_authtok`, fake daemon request log, and one-line pamtester stdin.
- Produces: integration evidence that the same cached token reaches a downstream password verifier, while `yes` is absent before fallback and no password path contacts irlumed.

- [ ] **Step 1: Rewrite the discarded-password test to demand one-entry authentication**

Replace `pamwrap_confirmation_response_is_hidden_and_never_becomes_authtok` with a test that writes an owner-executable `check-token.sh` containing:

```sh
#!/bin/sh
IFS= read -r value || :
[ "$value" = 'fixed-test-password' ]
```

Use this PAM stack:

```rust
&[
    h.auth_line("sufficient", ""),
    format!(
        "auth required pam_exec.so expose_authtok {}",
        check_token.display()
    ),
]
```

Feed only `"fixed-test-password\n"`. Assert authentication succeeds, the exact info line occurs once, neither the dummy token nor any alternate dummy appears in output, and the fake daemon log is empty.

- [ ] **Step 2: Run the rewritten test and capture RED against the old behavior**

Run outside the socket-restricted sandbox if the first run returns `EPERM`:

```bash
cargo test -p irlume-pam --test pamwrap pamwrap_password_input_is_reused_once --locked -- --include-ignored --exact --nocapture
```

Expected before Task 2 implementation: FAIL because `pam_exec` receives no cached token and prompts for a second value after pamtester stdin has reached EOF.

- [ ] **Step 3: Add empty, wrong-password, and face-denial cases**

Add these exact cases using fixed dummy values only:

- `"\nfixed-test-password\n"`: empty intent token is cleared; `pam_exec` prompts once and succeeds; daemon log remains empty.
- `"wrong-fixed-token\n"`: required `pam_exec` rejects; daemon log remains empty. A separate fresh `h.run` with `"fixed-test-password\n"` succeeds with one line.
- fake daemon returns an ordinary face denial; `"yes\nfixed-test-password\n"` makes exactly one attested daemon request, then `pam_exec` receives the fresh password and succeeds. Output contains neither dummy value.
- leading `pam_set_items.so` provides a cached password; irlume emits no info line and no daemon request, and downstream `pam_exec` validates the cached value.
- EOF/cancellation and a dead daemon retain camera-free fallback behavior.

Update `pamwrap_privileged_yes_prompts_once_and_attests_every_service` to assert `FACE_INTENT_INFO` exactly once. Remove assertions for the retired long custom prompt.

Remove the harness's `matrix` and `get_items` fields, discovery, and existence assertions after the rewritten tests no longer use them. Keep `set_items` for cached-token precedence.

- [ ] **Step 4: Run focused integrations GREEN**

Run:

```bash
cargo test -p irlume-pam --test pamwrap pamwrap_password_input_is_reused_once --locked -- --include-ignored --exact --nocapture
cargo test -p irlume-pam --test pamwrap pamwrap_empty_input_clears_before_password_fallback --locked -- --include-ignored --exact --nocapture
cargo test -p irlume-pam --test pamwrap pamwrap_face_denial_clears_yes_before_password_fallback --locked -- --include-ignored --exact --nocapture
cargo test -p irlume-pam --test pamwrap pamwrap_cached_password_skips_face_offer --locked -- --include-ignored --exact --nocapture
```

Expected: each passes with exact request counts and no dummy secret in output.

- [ ] **Step 5: Run the complete real-PAM lane**

Run outside the sandbox when necessary:

```bash
./scripts/run-tests-guarded.sh --min 25 -- cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1
```

Set the minimum to the final observed library-plus-integration count if it exceeds 25; never lower it to accommodate a missing test. Expected: zero failures and no secret text in captured output.

- [ ] **Step 6: Commit the integration proof**

```bash
git add crates/irlume-pam/tests/pamwrap.rs
git commit -S -s -m "test(pam): prove one-field password fallback"
git verify-commit HEAD
```

Expected: good signature, one DCO trailer, clean worktree.

---

### Task 4: Update current guidance and prove packaging carries the local patch

**Files:**

- Modify: `docs/SETUP.md:296-333`
- Modify: `docs/adr/0011-single-field-privileged-auth-input.md`
- Modify: `docs/superpowers/specs/2026-08-19-single-field-privileged-auth-input-design.md`
- Test: `scripts/check-packaging-parity.sh`
- Test: `scripts/build-ppa-source.sh` staging/vendor behavior

**Interfaces:**

- Consumes: the product code OID after Task 3 and the tracked `third_party/pamsm-0.5.5` path.
- Produces: current user guidance, implementation-status links, and source/package evidence that offline builders receive the patched dependency.

- [ ] **Step 1: Update sudo and polkit setup copy**

Replace the two-stage wording with the exact contract:

```markdown
PAM shows `Type yes to use face authentication` above the normal hidden field.
Type `yes` for one face attempt, or type the ordinary password once for the
password/fingerprint path. Empty Enter never starts the camera and falls through
to the password provider. This confirmation is mandatory and has no disable
setting.
```

Keep the existing optional-head-gesture and passive-PAD language.

- [ ] **Step 2: Mark the design implemented by the exact code OID**

Capture `git rev-parse HEAD` after Task 3 and put that full OID in the ADR/design implementation status. Do not call the later documentation/report commit the product candidate.

- [ ] **Step 3: Add source-presence assertions to packaging parity**

Extend `scripts/check-packaging-parity.sh` with checks that these tracked paths exist and are regular files:

```text
third_party/pamsm-0.5.5/Cargo.toml
third_party/pamsm-0.5.5/License
third_party/pamsm-0.5.5/IRLUME-PATCH.md
third_party/pamsm-0.5.5/src/libpam.rs
```

Also assert root `Cargo.toml` contains the exact local `pamsm` patch path. A missing source or patch entry must set `fail=1`.

- [ ] **Step 4: Verify a clean source archive and offline Cargo vendor staging**

Create a temporary directory with `mktemp -d`, export `HEAD` using `git archive`, and verify the four paths above exist in the extracted tree. In that extracted tree run:

```bash
cargo vendor --locked vendor
cargo metadata --locked --offline --format-version 1 --no-deps
```

Expected: both pass; the path dependency remains present outside the generated `vendor/` registry directory. Remove the exact temporary directory afterward.

- [ ] **Step 5: Run documentation/packaging gates**

Run:

```bash
./scripts/check-packaging-parity.sh
cargo deny check advisories bans licenses sources
git diff --check
rg -n "Face authentication: type yes and press Enter|discarded.*password|password.*discard" README.md docs crates/irlume-pam
```

Expected: parity and cargo-deny pass. Any matches are either explicitly labeled historical evidence or are corrected before commit.

- [ ] **Step 6: Commit current guidance and packaging assertions**

```bash
git add docs/SETUP.md docs/adr/0011-single-field-privileged-auth-input.md docs/superpowers/specs/2026-08-19-single-field-privileged-auth-input-design.md scripts/check-packaging-parity.sh
git commit -S -s -m "docs: publish single-field privileged authentication"
git verify-commit HEAD
```

Expected: good signature, one DCO trailer, clean worktree.

---

### Task 5: Freeze and verify the exact software candidate

**Files:**

- Create after verification: `docs/research/2026-08-19-single-field-privileged-auth-input-verification.md` (initial offline section only; append live evidence in Task 6 before committing it)
- Verify: entire workspace and release artifacts

**Interfaces:**

- Consumes: clean Task 4 HEAD.
- Produces: immutable product candidate OID/tree, release hashes, test totals, and a rollback-ready install set.

- [ ] **Step 1: Run complete offline gates against a clean worktree**

Run sequentially:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
./scripts/run-tests-guarded.sh --min 650 -- cargo test -q --workspace --locked
./scripts/run-tests-guarded.sh --min 25 -- cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1
cargo deny check advisories bans licenses sources
./scripts/check-packaging-parity.sh
bash -n scripts/hardware/run-slice4-hardware.sh
python3 scripts/hardware/test-validate-slice4-hardware.py
python3 scripts/hardware/test-run-slice4-hardware.py
git diff --check
```

If a sandbox-only Unix-socket/system-bus `EPERM` occurs, rerun the identical failing command outside the sandbox and record both results. Do not change code to accommodate the sandbox.

- [ ] **Step 2: Build release artifacts and run strict machine conformance**

Run:

```bash
cargo build --release --locked
python3 scripts/machine-api-conformance.py --strict --irlume target/release/irlume
```

Expected: build and conformance pass; only explicit unknown-hardware capability skips are permitted.

- [ ] **Step 3: Prove the wire/daemon candidate is unchanged**

Run:

```bash
git diff 392d15132322e2bde29559a23540ce9fbeb25f43 -- crates/irlume-common crates/irlume-daemon
```

Expected: empty. Cite the prior two-direction mixed-version evidence because the serialized request and daemon gate are byte-for-byte unchanged; do not claim a new protocol test occurred.

- [ ] **Step 4: Freeze identity and artifact hashes**

Require `git status --porcelain` to be empty, then record:

```bash
git rev-parse HEAD
git rev-parse HEAD^{tree}
sha256sum target/release/irlume target/release/irlumed target/release/libpam_irlume.so
```

Write the offline portion of the verification report with exact commands, totals, ignored-test reasons, candidate OID/tree, hashes, and the distinction between new tests and reused unchanged-wire evidence. Do not commit yet: Task 6 adds installed evidence while the product OID stays frozen.

---

### Task 6: Install transactionally, validate KDE, and publish the final report

**Files:**

- Create: `/home/wisbfime/irlume-system-backups/<timestamp>-single-field-<candidate-short-oid>/` (outside Git; mode 0700)
- Modify installed: `/usr/lib64/security/pam_irlume.so` only, unless release hashes prove another active artifact changed and the active-path inventory requires it
- Modify: `docs/research/2026-08-19-single-field-privileged-auth-input-verification.md`
- Modify: `/home/wisbfime/Agent Shared Memory/project-irlume.md` and `index.md`

**Interfaces:**

- Consumes: exact Task 5 product OID/hash, the already wired `/etc/pam.d/polkit-1`, active KDE polkit agent, and prior rollback snapshot.
- Produces: installed exact PAM module, five live KDE outcomes, final signed report commit, and a mechanical rollback handoff.

- [ ] **Step 1: Reconfirm installed scope and create a new exact rollback snapshot**

Before writing, capture:

```bash
rpm -q irlume
sha256sum /usr/lib64/security/pam_irlume.so
sed -n '1,80p' /etc/pam.d/polkit-1
systemctl cat irlumed.service
systemctl is-active irlumed.socket irlumed.service
```

Copy the current PAM module, polkit stack, wiring marker, and service overrides into the new 0700 backup directory. Preserve the earlier `/home/wisbfime/irlume-system-backups/2026-08-19-kde-intent-392d151` snapshot unchanged.

- [ ] **Step 2: Install the hash-pinned PAM module atomically**

Create a reviewed rollback-on-error script in the new backup directory. It must verify candidate and backup hashes, stage the candidate beside `/usr/lib64/security/pam_irlume.so`, rename atomically, run `restorecon -F`, verify the installed hash, and restore the prior module on any error. Run `bash -n` and `shellcheck` before executing it with sudo.

No PAM stack rewrite is needed. No daemon restart is needed because the wire and daemon are unchanged and polkit loads the PAM module in a fresh helper process; still verify both irlume units remain active and `irlume status --json` remains healthy.

- [ ] **Step 3: Validate exact message and confirmed face path**

Run `pkcheck --revoke-temp`, then `pkexec /usr/bin/true`. The user verifies that Plasma displays exactly `Type yes to use face authentication` above the normal hidden field, types `yes`, and faces the camera. Require exit 0, one new daemon face request, and PAM audit success through `pam_irlume`.

- [ ] **Step 4: Validate one-entry real-password path**

Revoke temporary grants and repeat. The user enters the real password once and never shares it with the agent. Require exit 0, PAM audit success through `pam_unix`, and zero irlumed entries in the exact test window. The user explicitly confirms one field submission.

- [ ] **Step 5: Validate wrong-password retry and empty/cancel safety**

For each case revoke temporary grants first:

- Enter a random wrong password once. Require password failure, zero daemon entries, and no camera. On the fresh retry, enter the real password once and require success.
- Press empty Enter, then Cancel on the next prompt. Require `pkexec` unauthorized/non-zero and zero daemon entries.

Do not log or record either real or random password text.

- [ ] **Step 6: Validate face-denial password fallback**

Revoke temporary grants, type `yes`, and deliberately make the face unavailable without changing camera hardware or policy (move out of frame). Require one failed face request followed by a fresh normal password field. Enter the real password once; require final success through `pam_unix`. Verify `yes` was not recorded as a Unix-password failure.

- [ ] **Step 7: Roll back on any acceptance failure**

If any message, field-count, factor, camera-ordering, service-health, or secret-handling check fails, restore the prior PAM module from the new backup, run `restorecon -F`, and re-run password-only `pkexec /usr/bin/true` plus `irlume status --json`. Record the failed candidate honestly and stop before report completion.

- [ ] **Step 8: Finish and commit the verification report**

Append exact live timestamps, command exit codes, PAM grantors, daemon request counts, user-observed field counts/message, installed hash, backup path, and rollback status. State that no password value was observed or recorded.

```bash
git add docs/research/2026-08-19-single-field-privileged-auth-input-verification.md
git commit -S -s -m "docs: verify single-field privileged authentication"
git verify-commit HEAD
git status --short --branch
```

Expected: good signature, one DCO trailer, clean worktree. Record both the frozen product OID and later report OID in shared memory, update mutable installed/rollback state, append the final checkpoint, and update the index row.

---

## Completion criteria

- One KDE hidden field accepts either `yes` or the real password once.
- Empty Enter, wrong password, cancellation, cached-token, and error paths are camera-free.
- `yes` is cleared before daemon contact; face failure presents a fresh password path without testing `yes` as a Unix password.
- The exact informational line renders above KDE's field.
- PAM wrapper proves the same behavior without real credentials and emits no dummy secret.
- The daemon/common diff from `392d151` is empty; prior wire compatibility remains applicable and is labeled reused evidence.
- The local pamsm patch is minimal, attributed, licensed, locked, cargo-deny clean, and present in clean/offline packaging sources.
- Full offline gates and live KDE acceptance pass at one frozen product OID.
- Installed bytes have an exact rollback snapshot, and shared memory names product/report OIDs, hashes, results, lessons, blocker status, and next action.
