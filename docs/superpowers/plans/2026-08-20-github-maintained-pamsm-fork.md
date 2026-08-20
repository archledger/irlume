# GitHub-Maintained pamsm Fork Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` and execute inline. The user explicitly asked
> not to dispatch subagents. Track every step with its checkbox and stop at the
> external-state review gates named below.

**Goal:** Create, harden, and protect a public GitHub-only pamsm fork, then
migrate irlume to one immutable verified fork commit before its next release.

**Architecture:** Preserve upstream pamsm 0.5.5 history in
`archledger/pam_sm_rust`, keep `master` as an upstream mirror, and maintain a
protected `irlume-patches` line. Harden the fork's C ABI, handle confinement,
secret lifecycle, and Linux-PAM wrappers independently before pinning irlume to
the resulting full Git OID and removing the temporary in-tree copy.

**Tech Stack:** Rust 1.88, Linux-PAM, pam_wrapper, pamtester, zeroize,
AddressSanitizer/LeakSanitizer, CodeQL, cargo-deny, actionlint, zizmor, GitHub
branch protection, Cargo Git patches and offline vendoring.

**Spec:**
`docs/superpowers/specs/2026-08-20-github-maintained-pamsm-fork-design.md`

## Global Constraints

- The public repository is `https://github.com/archledger/pam_sm_rust` and must
  be created with GitHub's fork operation from `rcatolino/pam_sm_rust`.
- GitHub is the only distribution channel. Never create a crates.io package,
  alternate registry entry, or GitHub binary release.
- Keep the Cargo package and Rust crate name `pamsm`.
- Preserve upstream tag `0.5.5`, commit
  `a51131ebaa252a9c77727f65d962d33d8a632e87`, history, copyright, and
  GPL-3.0-only terms.
- `master` is an upstream mirror. `irlume-patches` is the protected default
  branch. Never force-push or delete either branch.
- Irlume may select only a literal full 40-character commit OID from
  `irlume-patches`; branches, tags, short hashes, and archive URLs are forbidden
  dependency selectors.
- Rust 1.88 is the initial MSRV. Required checks also run current stable and
  nightly only where ASan requires it.
- Every fork and irlume commit is signed and contains exactly one
  `Signed-off-by` trailer.
- Use test-first RED/GREEN cycles for every code change. Record the exact
  failing command and expected failure before implementation.
- No real password, biometric sample, camera capture, PAM stack change, or
  installed module is used before the explicit installed-acceptance task.
- Keep `/home/wisbfime/Agent Shared Memory/project-irlume.md` current after
  every remote repository, code, test, pin, install, or rollback change.

## File and module map

### Fork repository: `archledger/pam_sm_rust`

- `src/lib.rs` — public exports and crate documentation only.
- `src/pam.rs` — `Pam`, `PamFlags`, `PamError`, and `PamServiceModule`.
- `src/entrypoint.rs` — one checked dispatcher used by every `pam_sm_*` export.
- `src/libpam.rs` — safe Linux-PAM wrappers and FFI result conversion.
- `src/module_data.rs` — typed module data and secret-specific storage/cleanup.
- `src/pam_types.rs` — private C-compatible types, item numbers, message styles,
  and logging levels.
- `tests/entrypoints.rs` — exported-entrypoint ABI validation and panic tests.
- `tests/pamwrap.rs` — real Linux-PAM integration through pam_wrapper/pamtester.
- `tests/symbols.sh` — exact `cdylib` exported-symbol check.
- `IRLUME-MAINTENANCE.md` — upstream base, checksum, downstream changes, and
  update policy.
- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `.github/CODEOWNERS` — public
  ownership and contribution contract.
- `.github/workflows/ci.yml` — MSRV/stable build, unit, pam_wrapper, symbols,
  strict Clippy, formatting, rustdoc, and cargo-deny.
- `.github/workflows/asan.yml` — full ASan/LeakSanitizer suite.
- `.github/workflows/codeql.yml` — Rust CodeQL.
- `.github/workflows/workflow-audit.yml` — actionlint and zizmor.
- `deny.toml` — advisories, license, and source policy.

### Irlume repository

- `Cargo.toml`, `Cargo.lock` — replace the local pamsm path with the fork URL and
  verified full OID.
- `.gitattributes` — remove the deleted vendored-license exception.
- `crates/irlume-pam/src/lib.rs` — migrate only module-secret call sites and API
  imports changed by hardening.
- `crates/irlume-pam/tests/pamwrap.rs` — preserve all 25 real integrations and
  add zeroizing module-data behavior where observable.
- `scripts/check-packaging-parity.sh` — replace local-file assertions with exact
  Git-source, lockfile, archive, and offline-vendor assertions.
- `third_party/pamsm-0.5.5/` — delete only after the Git pin passes the full PAM
  lane.
- `docs/adr/0011-single-field-privileged-auth-input.md`,
  `docs/adr/0012-maintain-pamsm-github-fork.md`, and related design/research
  files — record actual fork/tag/OIDs and verification.

---

### Task 0: Land the approved architecture on irlume main

**Files:**
- Existing branch: `design/maintain-pamsm-fork`
- Existing commits: signed ADR/spec commit and this implementation-plan commit
- External modify: one irlume documentation pull request

**Interfaces:**
- Produces: merged ADR-0012, written design, and implementation plan on irlume
  main before any fork repository exists.

- [ ] **Step 1: Verify the design branch**

Run the guarded workspace baseline, formatting, diff check, local-link checks,
signature verification, DCO trailer count, and clean status. Expected: 1,765 or
more tests, zero failures, and only the two documentation commits ahead of
`origin/main`.

- [ ] **Step 2: Push and open one draft documentation PR**

After explicit push authorization:

```bash
git push -u origin design/maintain-pamsm-fork
gh pr create --base main --head design/maintain-pamsm-fork --draft --title 'Document the maintained pamsm fork' --body-file /tmp/irlume-pamsm-design-pr.md
```

The body names the GitHub-only/no-registry decision, required initial
hardening, 1,765-test baseline, and the fact that no fork exists yet. Verify the
created PR read-only; never retry blindly.

- [ ] **Step 3: Wait for checks and merge only with exact-head authorization**

Address findings without widening scope. After explicit merge authorization,
verify the exact head, zero non-success checks, and clean merge state; then use
the repository's squash convention with a DCO trailer. Fetch and verify the
GitHub-signed main commit. Preserve the design branch/worktree until readback
passes.

### Task 1: Create the public fork and immutable branch topology

**Files:**
- External create: `https://github.com/archledger/pam_sm_rust`
- External create: branch `irlume-patches`
- Local clone: `/home/wisbfime/pam_sm_rust`

**Interfaces:**
- Consumes: authenticated `archledger` GitHub session; upstream tag `0.5.5`.
- Produces: public fork with `master` at upstream and `irlume-patches` at exact
  commit `a51131ebaa252a9c77727f65d962d33d8a632e87`.

- [ ] **Step 1: Verify identity and absence without writing**

Run:

```bash
gh auth status
gh api repos/rcatolino/pam_sm_rust --jq '{full_name,default_branch,fork,pushed_at}'
gh api repos/archledger/pam_sm_rust
```

Expected: authenticated account is `archledger`; upstream is public with
default `master`; the final command returns HTTP 404. If the fork already
exists, stop and inventory its refs/settings rather than creating another.

- [ ] **Step 2: Create the GitHub fork once**

Run:

```bash
gh repo fork rcatolino/pam_sm_rust --clone=false
gh api repos/archledger/pam_sm_rust --jq '{full_name,fork,parent:.parent.full_name,default_branch,visibility}'
```

Expected: `fork=true`, parent `rcatolino/pam_sm_rust`, public visibility. If the
creation response is uncertain, perform only the readback; never retry blindly.

- [ ] **Step 3: Clone and verify upstream provenance**

Run:

```bash
git clone git@github.com:archledger/pam_sm_rust.git /home/wisbfime/pam_sm_rust
git -C /home/wisbfime/pam_sm_rust remote add upstream https://github.com/rcatolino/pam_sm_rust.git
git -C /home/wisbfime/pam_sm_rust fetch --tags upstream master
git -C /home/wisbfime/pam_sm_rust rev-parse 0.5.5 master upstream/master
```

Expected: tag `0.5.5` resolves to
`a51131ebaa252a9c77727f65d962d33d8a632e87`; `master` and
`upstream/master` match. Stop on any mismatch.

- [ ] **Step 4: Create and publish the maintained branch**

Run:

```bash
git -C /home/wisbfime/pam_sm_rust switch -c irlume-patches 0.5.5
git -C /home/wisbfime/pam_sm_rust push -u origin irlume-patches
gh api -X PATCH repos/archledger/pam_sm_rust -f default_branch=irlume-patches
gh api repos/archledger/pam_sm_rust --jq '{default_branch,visibility}'
```

Expected: public repository, default branch `irlume-patches`. Do not change
`master`.

- [ ] **Step 5: Create the bootstrap feature branch**

Run:

```bash
git -C /home/wisbfime/pam_sm_rust switch -c hardening/initial-boundary
git -C /home/wisbfime/pam_sm_rust status --short --branch
```

Expected: clean feature branch based on the upstream 0.5.5 commit.

### Task 2: Establish provenance and import the already verified PR #502 delta

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/libpam.rs`
- Create: `IRLUME-MAINTENANCE.md`
- Modify: `README.md`
- Test: `src/libpam.rs` unit tests

**Interfaces:**
- Consumes: upstream pamsm 0.5.5; merged irlume methods
  `PamLibExt::clear_authtok` and `PamLibExt::info`.
- Produces: the exact response-free API used by PR #502 and explicit fork
  provenance.

- [ ] **Step 1: Add compile contracts before implementation**

Append under `#[cfg(test)]` in `src/libpam.rs`:

```rust
#[test]
fn irlume_boundary_exposes_clear_and_response_free_info() {
    fn require_clear(pam: &Pam) -> PamResult<()> {
        pam.clear_authtok()
    }
    fn require_info(pam: &Pam) -> PamResult<()> {
        pam.info("Type yes to use face authentication")
    }
    let _: fn(&Pam) -> PamResult<()> = require_clear;
    let _: fn(&Pam) -> PamResult<()> = require_info;
}
```

- [ ] **Step 2: Run RED**

Run:

```bash
cargo test --features libpam --lib --no-run
```

Expected: `E0599` for missing `clear_authtok` and `info`.

- [ ] **Step 3: Port the minimal verified API**

Add these trait signatures and implementations in `src/libpam.rs`:

```rust
fn clear_authtok(&self) -> PamResult<()>;
fn info(&self, message: &str) -> PamResult<()>;

fn clear_authtok(&self) -> PamResult<()> {
    // PAM_AUTHTOK with a null item pointer removes the transaction token.
    unsafe { set_item(self.0, PamItemType::AUTHTOK, std::ptr::null()) }
}

fn info(&self, message: &str) -> PamResult<()> {
    let message = CString::new(message)?;
    let format = b"%s\0".as_ptr().cast::<c_char>();
    unsafe {
        PamError::new(pam_prompt(
            self.0,
            PamMsgStyle::TEXT_INFO as c_int,
            std::ptr::null_mut(),
            format,
            message.as_ptr(),
        ))
        .to_result(())
    }
}
```

Declare the private variadic `pam_prompt` FFI with a null response parameter.
Delete the public generic `conv` method and its `PamConv`, `PamMessage`, and
`PamResponse` imports from `libpam.rs`; do not delete private C types still used
elsewhere until the absence scan proves they are dead.

- [ ] **Step 4: Record provenance and maintenance scope**

Create `IRLUME-MAINTENANCE.md` with the exact upstream URL, tag, commit,
crates.io checksum from the spec, GitHub-only/no-registry rule, branch topology,
downstream change ledger, and update procedure. Update `README.md` to identify
the fork and link this file. Change Cargo metadata only from `GPL-3.0` to
`GPL-3.0-only` and set the homepage/repository to the fork; retain the original
license file and authors.

- [ ] **Step 5: Run GREEN and verify the delta**

Run:

```bash
cargo fmt --all -- --check
cargo test --features libpam --lib
cargo clippy --all-targets --all-features -- -D warnings
if rg -n 'fn conv|conv_pointer|resp_ptr|PamResponse' src/libpam.rs; then exit 1; fi
git diff --check
```

Expected: tests and lint pass; absence scan returns no response-returning
conversation implementation.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml README.md IRLUME-MAINTENANCE.md src/libpam.rs
git commit -S -s -m "feat: own irlume PAM token boundary"
git verify-commit HEAD
```

### Task 3: Harden every exported PAM entrypoint

**Files:**
- Create: `src/entrypoint.rs`
- Modify: `src/lib.rs`
- Modify: `src/pam.rs`
- Create: `tests/entrypoints.rs`

**Interfaces:**
- Produces:
  `unsafe fn invoke_hook(pamh: *mut c_void, flags: c_int, argc: c_int,
  argv: *const *const c_char, hook: impl FnOnce(Pam, PamFlags, Vec<String>) ->
  PamError) -> c_int`.
- Every generated `pam_sm_*` symbol delegates to this function.

- [ ] **Step 1: Write RED tests for invalid ABI inputs and panic containment**

Create `src/entrypoint.rs`, declare it from `src/lib.rs`, and add a unit-test
module that calls the wished-for `invoke_hook` function before defining it. Use
a shared assertion helper with these cases:

```rust
assert_eq!(call(std::ptr::null_mut(), 0, 0, std::ptr::null()), PAM_ABORT);
assert_eq!(call(valid_handle(), 0, -1, std::ptr::null()), PAM_ABORT);
assert_eq!(call(valid_handle(), 0, 1, std::ptr::null()), PAM_ABORT);
assert_eq!(call_with_null_argv_element(), PAM_ABORT);
assert_eq!(call_with_argc(257), PAM_ABORT);
assert_eq!(call_with_invalid_utf8(), PAM_SERVICE_ERR);
assert_eq!(call_with_panicking_hook(), PAM_ABORT);
assert_eq!(call_with_args(&[c"mode=auth", c"debug"]), PAM_SUCCESS);
```

The valid handle is never dereferenced by the test hook; construct it as a
non-null opaque pointer and keep the hook limited to argument assertions.

- [ ] **Step 2: Run RED**

Run:

```bash
cargo test --test entrypoints -- --nocapture
```

Expected: `E0425` because `entrypoint::invoke_hook` does not exist. No old
exported function receives a deliberately invalid pointer during RED.

- [ ] **Step 3: Implement the shared checked dispatcher**

Create `src/entrypoint.rs` with constant `MAX_MODULE_ARGS: usize = 256` and this
ordering:

```rust
pub(crate) unsafe fn invoke_hook<F>(
    pamh: *mut c_void,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
    hook: F,
) -> c_int
where
    F: FnOnce(Pam, PamFlags, Vec<String>) -> PamError,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Some(handle) = std::ptr::NonNull::new(pamh) else {
            return PamError::ABORT as c_int;
        };
        let Ok(count) = usize::try_from(argc) else {
            return PamError::ABORT as c_int;
        };
        if count > MAX_MODULE_ARGS || (count > 0 && argv.is_null()) {
            return PamError::ABORT as c_int;
        }
        let raw_args = if count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(argv, count) }
        };
        let mut args = Vec::with_capacity(count);
        for raw in raw_args {
            if raw.is_null() {
                return PamError::ABORT as c_int;
            }
            let Ok(arg) = unsafe { CStr::from_ptr(*raw) }.to_str() else {
                return PamError::SERVICE_ERR as c_int;
            };
            args.push(arg.to_owned());
        }
        hook(Pam::from_non_null(handle), PamFlags::from_bits_truncate(flags), args)
            as c_int
    }))
    .unwrap_or(PamError::ABORT as c_int)
}
```

Keep `Pam::from_non_null` crate-private. Add a local safety comment to every
unsafe expression. Change the macro's exported parameters to raw C types and
delegate every symbol to this dispatcher. Do not duplicate parsing in the
macro. Then add `tests/entrypoints.rs`: define a minimal `PamServiceModule`,
invoke `pam_module!`, and call all six generated `pam_sm_*` symbols through
their raw C signatures to prove every route uses the checked dispatcher.

- [ ] **Step 4: Run GREEN and symbol smoke test**

Run:

```bash
cargo test --test entrypoints -- --nocapture
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: all invalid inputs fail closed and the normal hook receives both
arguments.

- [ ] **Step 5: Commit**

```bash
git add src/entrypoint.rs src/lib.rs src/pam.rs tests/entrypoints.rs
git commit -S -s -m "fix: validate PAM entrypoint pointers"
git verify-commit HEAD
```

### Task 4: Confine PAM handles and retain unknown flag bits

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/lib.rs`
- Modify: `src/pam.rs`
- Modify: `tests/entrypoints.rs`

**Interfaces:**
- `Pam` remains an opaque callback-scoped handle and is `!Send + !Sync`.
- `PamFlags::from_bits_retain(c_int) -> PamFlags` preserves unknown bits.

- [ ] **Step 1: Add API-absence and flag regressions**

Add a test that reads `src/pam.rs` and `src/lib.rs` and asserts neither contains
`PamSendRef`, `as_send_ref`, nor an `unsafe impl Send`. Add an entrypoint test
with flag value `0x4000_0000` and assert the hook observes that bit through
`flags.bits()`. Add a `compile_fail` doctest on `Pam` showing a callback cannot
move the handle into `std::thread::spawn`.

- [ ] **Step 2: Run RED**

Run:

```bash
cargo test no_cross_thread_handle_api_is_exported -- --exact
cargo test --test entrypoints unknown_flag_bits_are_retained -- --exact
```

Expected: the API-absence test fails on `PamSendRef`; the flag test fails because
Task 3 deliberately truncates unknown bits.

- [ ] **Step 3: Remove cross-thread support and modernize bitflags**

Upgrade `bitflags` to major version 2. Delete `PamSendRef`, its conversions,
`unsafe impl Send`, `Pam::as_send_ref`, and its public re-export. Define the
flags with `bitflags!` and use `from_bits_retain` only at the checked entrypoint.
Make `Pam` contain `PhantomData<*const ()>` or an equivalent private marker so
auto traits remain `!Send + !Sync` without a manual unsafe negative claim.

- [ ] **Step 4: Run GREEN and absence scan**

```bash
cargo test --doc --all-features
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
if rg -n 'PamSendRef|as_send_ref|unsafe impl.*Send|from_bits_unchecked' src tests; then exit 1; fi
```

Expected: tests pass; absence scan returns no matches.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/pam.rs tests/entrypoints.rs
git commit -S -s -m "refactor: confine PAM handles to callbacks"
git verify-commit HEAD
```

### Task 5: Replace plain module bytes with zeroizing secrets

**Files:**
- Modify: `Cargo.toml`
- Create: `src/module_data.rs`
- Modify: `src/lib.rs`
- Modify: `src/libpam.rs`
- Test: `src/module_data.rs`

**Interfaces:**
- Produces `PamSecretBytes::new(Vec<u8>)`, `is_empty`, `len`, and
  `expose(&self) -> &[u8]`.
- Produces `PamLibExt::send_secret(&self, key: &str, value: PamSecretBytes) ->
  PamResult<()>` and `unsafe PamLibExt::get_secret<'a>(&'a self, key: &str) ->
  PamResult<&'a PamSecretBytes>`.
- Removes `send_bytes`, `retrieve_bytes`, and `PamCleanupCb`.

- [ ] **Step 1: Write RED tests for secret behavior**

In `src/module_data.rs` under `#[cfg(test)]`, assert:

```rust
let secret = PamSecretBytes::new(b"fixed-ci-dummy".to_vec());
assert_eq!(secret.expose(), b"fixed-ci-dummy");
assert_eq!(format!("{secret:?}"), "PamSecretBytes([redacted; 14 bytes])");
assert!(!secret.is_empty());

let mut bytes = b"fixed-ci-dummy".to_vec();
pamsm::module_data::wipe(&mut bytes);
assert!(bytes.iter().all(|byte| *byte == 0));
```

Add a cleanup harness that boxes `PamSecretBytes`, passes its raw pointer to the
internal cleanup seam, and observes a separate atomic drop counter. Assert one
drop on normal cleanup, one on replacement, no dereference for null, and
normal return without unwinding when a test cleanup observer panics.

- [ ] **Step 2: Run RED**

```bash
cargo test module_data::tests -- --nocapture
```

Expected: compile failure because `PamSecretBytes`, `wipe`, and cleanup seam do
not exist.

- [ ] **Step 3: Implement the secret type and storage**

Add `zeroize = "1"`. Implement:

```rust
pub struct PamSecretBytes(Vec<u8>);

impl PamSecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self { Self(bytes) }
    pub fn expose(&self) -> &[u8] { &self.0 }
    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

impl Drop for PamSecretBytes {
    fn drop(&mut self) { wipe(&mut self.0); }
}

pub(crate) fn wipe(bytes: &mut [u8]) {
    use zeroize::Zeroize;
    bytes.zeroize();
}
```

Implement redacted `Debug`; do not implement `Display`, `Deref`, `AsRef`, or
ordinary `Clone`. `send_secret` transfers one boxed value to `pam_set_data` and
reclaims it on failure. `get_secret` checks the status and null output before
creating a borrow. Cleanup wraps `Box::from_raw` and drop inside
`catch_unwind`, catches panic-payload drop, and never dereferences null.

- [ ] **Step 4: Verify RED sabotage then GREEN**

Temporarily change `wipe` to an empty body and run:

```bash
cargo test module_data::tests::secret_memory_is_wiped -- --exact
```

Expected: FAIL because bytes remain nonzero. Restore `zeroize`, rerun the exact
test, then run:

```bash
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
if rg -n 'send_bytes|retrieve_bytes|PamByteData|PamCleanupCb' src tests; then exit 1; fi
```

Expected: all tests pass; absence scan has no matches.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/libpam.rs src/module_data.rs
git commit -S -s -m "fix: zeroize PAM module secrets"
git verify-commit HEAD
```

### Task 6: Audit FFI declarations and fail-closed output pointers

**Files:**
- Modify: `src/libpam.rs`
- Modify: `src/pam_types.rs`
- Test: `src/libpam.rs`

**Interfaces:**
- All FFI remains private; public methods return `PamResult`.
- Successful calls with a missing required output map to
  `PamError::SYSTEM_ERR`.

- [ ] **Step 1: Write table-driven RED tests**

Create an internal test `PamApi` function table covering `pam_get_user`,
`pam_get_item`, `pam_get_authtok`, `pam_set_item`, `pam_putenv`, and
`pam_prompt`. Inject success-with-null and explicit error statuses. Assert that
no output pointer is read after error and success-with-null returns
`SYSTEM_ERR` where output is required.

Use one private struct with the production signatures:

```rust
struct PamApi {
    get_item: unsafe extern "C" fn(PamHandle, c_int, *mut *const c_void) -> c_int,
    get_user: unsafe extern "C" fn(PamHandle, *mut *const c_char, *const c_char) -> c_int,
    get_authtok: unsafe extern "C" fn(PamHandle, c_int, *mut *const c_char, *const c_char) -> c_int,
    set_item: unsafe extern "C" fn(PamHandle, c_int, *const c_void) -> c_int,
    putenv: unsafe extern "C" fn(PamHandle, *const c_char) -> c_int,
}
```

Keep the variadic response-free `pam_prompt` behind a separate private helper
because a variadic function cannot use the same stable Rust function-pointer
seam.

- [ ] **Step 2: Run RED**

```bash
cargo test libpam::tests::ffi_contract -- --nocapture
```

Expected: compile failure because the injectable internal API seam is absent,
or a success-with-null case incorrectly returns `None`.

- [ ] **Step 3: Implement one private API table and checked wrappers**

Move raw declarations into one private module. Production uses constant
function pointers to Linux-PAM; tests inject stubs. Every wrapper follows this
order: build checked C inputs, call FFI, inspect status, validate output pointer,
then create the shortest possible borrow. Add crate attributes:

```rust
#![deny(improper_ctypes)]
#![deny(improper_ctypes_definitions)]
#![deny(unsafe_op_in_unsafe_fn)]
```

Use `GPL-3.0-only` in Cargo metadata. Do not expose the API table publicly.

- [ ] **Step 4: Compare declarations with installed headers and run GREEN**

Run bindgen only as a comparison artifact, not generated source:

```bash
bindgen /usr/include/security/pam_appl.h --allowlist-function 'pam_(get|set|put|prompt|syslog).*' --allowlist-type 'pam_handle_t' -- -I/usr/include > /tmp/pamsm-pam-bindings.rs
rg -n 'pam_get_user|pam_get_item|pam_get_authtok|pam_set_item|pam_set_data|pam_get_data|pam_putenv|pam_prompt|pam_syslog' /tmp/pamsm-pam-bindings.rs src/libpam.rs
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: signature shapes agree; all tests pass. Delete the temporary bindgen
artifact after review.

- [ ] **Step 5: Commit**

```bash
git add src/libpam.rs src/pam_types.rs
git commit -S -s -m "fix: validate Linux-PAM FFI outputs"
git verify-commit HEAD
```

### Task 7: Add real PAM integration and exported-symbol coverage

**Files:**
- Create: `tests/pamwrap.rs`
- Create: `tests/fixtures/test_module.rs`
- Create: `tests/symbols.sh`
- Modify: `Cargo.toml`

**Interfaces:**
- Produces a test-only `cdylib` using all six entrypoints and the hardened
  wrappers.

- [ ] **Step 1: Write failing pam_wrapper and symbol tests**

The test module must implement authenticate, setcred, account, open/close
session, and chauthtok. Use fixed dummy token `fixed-ci-dummy`, info message
`pamsm test info`, environment `PAMSM_TEST=ready`, and module-data key
`pamsm.test.secret`. Tests assert token clear/set, user/service/rhost reads,
environment round-trip, secret replacement/retrieval, and cleanup.

`tests/symbols.sh` must run `nm -D --defined-only` and compare the sorted
`pam_sm_*` list exactly with:

```text
pam_sm_acct_mgmt
pam_sm_authenticate
pam_sm_chauthtok
pam_sm_close_session
pam_sm_open_session
pam_sm_setcred
```

- [ ] **Step 2: Run RED**

```bash
cargo test --test pamwrap -- --include-ignored --test-threads=1
bash tests/symbols.sh
```

Expected: tests fail because the fixture module/harness and exact symbol audit
are not yet wired.

- [ ] **Step 3: Implement the harness using system pam_wrapper**

Follow irlume's existing `crates/irlume-pam/tests/pamwrap.rs` discovery and
private temporary-directory pattern. Generate a service file per case, set
`PAM_WRAPPER`, `PAM_WRAPPER_SERVICE_DIR`, and module path only inside the child,
and cap stdout/stderr. Never put a token in command arguments, logs, panic
messages, or retained artifacts.

- [ ] **Step 4: Run GREEN and secret scan**

```bash
cargo test --test pamwrap -- --include-ignored --test-threads=1
bash tests/symbols.sh
test -d target/pamsm-test-logs
if rg -n 'fixed-ci-dummy' target/pamsm-test-logs; then exit 1; fi
```

Expected: integrations and symbols pass; the harness publishes only bounded
text logs under `target/pamsm-test-logs`, and the scan finds no captured token.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml tests/pamwrap.rs tests/fixtures/test_module.rs tests/symbols.sh
git commit -S -s -m "test: exercise the real PAM module ABI"
git verify-commit HEAD
```

### Task 8: Add governance, CI, sanitizers, and workflow security

**Files:**
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Create: `.github/CODEOWNERS`
- Create: `.github/dependabot.yml`
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/asan.yml`
- Create: `.github/workflows/codeql.yml`
- Create: `.github/workflows/workflow-audit.yml`
- Create: `.github/actionlint.yaml`
- Create: `deny.toml`
- Create: `tests/workflow_contract.sh`

**Interfaces:**
- Produces the eight exact required check names listed in the spec.

- [ ] **Step 1: Write static workflow contracts before workflow files**

Create `tests/workflow_contract.sh` that fails unless actions are full SHA pins,
checkout disables persisted credentials, permissions are read-only by default,
MSRV is exactly 1.88, all eight required check names exist, ASan uses an
explicit target and symbolizer, and no workflow contains crates.io publish,
GitHub release creation, `cargo publish`, or write-all permissions.

- [ ] **Step 2: Run RED**

```bash
bash tests/workflow_contract.sh
```

Expected: FAIL because workflows and governance files are absent.

- [ ] **Step 3: Add the minimal pinned workflows and policies**

Adapt irlume's pinned Actions/check patterns but keep only this crate's needs.
CI installs `libpam0g-dev`, `pamtester`, `libpam-wrapper`, and build tools; runs
fmt, strict all-target/all-feature Clippy, rustdoc `-D warnings`, MSRV/stable
tests, serial pam_wrapper, symbols, and cargo-deny. ASan runs the same unit and
pam_wrapper tests with nightly `-Zsanitizer=address`. CodeQL builds the crate
and uploads Rust analysis. Workflow audit downloads checksum-pinned actionlint
and runs zizmor with no advanced-security write token. The DCO job checks out
full history, enumerates every commit in the pull-request base-to-head range,
and fails unless each message contains exactly one line matching
`^Signed-off-by: [^<]+ <[^>]+>$`; its job name is exactly
`DCO (exactly one trailer)`.

- [ ] **Step 4: Run GREEN locally**

```bash
shellcheck tests/workflow_contract.sh tests/symbols.sh
bash tests/workflow_contract.sh
actionlint -color
zizmor .github/workflows
cargo deny check advisories bans licenses sources
```

Expected: all checks pass with the deprecated upstream-license warning removed
by the accurate `GPL-3.0-only` metadata.

- [ ] **Step 5: Commit**

```bash
git add SECURITY.md CONTRIBUTING.md deny.toml tests/workflow_contract.sh .github
git commit -S -s -m "ci: protect the maintained PAM boundary"
git verify-commit HEAD
```

### Task 9: Publish, protect, review, merge, and tag the fork checkpoint

**Files:**
- External modify: fork feature branch, pull request, branch protection, signed
  tag `irlume-0.5.5-patch.1`.

**Interfaces:**
- Produces the full 40-character fork checkpoint OID consumed by Task 10.

- [ ] **Step 1: Run the complete fork verification locally**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps
cargo test --all-features
cargo test --test pamwrap -- --include-ignored --test-threads=1
bash tests/symbols.sh
cargo deny check advisories bans licenses sources
bash tests/workflow_contract.sh
git diff --check
```

Run the exact ASan workflow command outside ptrace/sandbox restrictions and
record its test total. Expected: zero failures and a clean worktree.

- [ ] **Step 2: Push the feature branch and open one draft PR**

```bash
git push -u origin hardening/initial-boundary
gh pr create --repo archledger/pam_sm_rust --base irlume-patches --head hardening/initial-boundary --draft --title 'Harden the irlume-maintained PAM boundary' --body-file /tmp/pamsm-pr-body.md
```

Create the body as a reviewed owner-only temporary file containing scope,
RED/GREEN evidence, unsafe inventory, tests, licensing, and no-registry rule.
Verify the PR read-only after creation; never retry blindly.

- [ ] **Step 3: Configure branch protection after check contexts exist**

Use `gh api -X PUT repos/archledger/pam_sm_rust/branches/irlume-patches/protection`
with `strict=true`, the eight exact required check contexts, enforced admins,
zero required approvals, conversation resolution, linear history, required
commit signatures, no force push, and no deletion. Enable signatures separately
with:

```bash
gh api -X POST repos/archledger/pam_sm_rust/branches/irlume-patches/protection/required_signatures
```

Read back every protection field and the required-signatures endpoint before
continuing.

- [ ] **Step 4: Wait for every check and address findings test-first**

```bash
gh pr checks hardening/initial-boundary --repo archledger/pam_sm_rust --watch --interval 10
```

Resolve review threads only after posting exact fix evidence and only with
explicit authorization. No admin bypass.

- [ ] **Step 5: Merge with exact-head guard and tag**

After explicit merge authorization, capture the PR head, verify zero non-success
checks, mark ready, and use a rebase merge so individually reviewed downstream
commits remain on the linear patch branch. Fetch `irlume-patches`, verify every
rebased commit's GitHub signature and DCO trailer, then:

```bash
fork_checkpoint_oid=$(git rev-parse origin/irlume-patches)
test "${#fork_checkpoint_oid}" -eq 40
git tag -s -a irlume-0.5.5-patch.1 -m 'Irlume-maintained pamsm 0.5.5 patch checkpoint 1' "$fork_checkpoint_oid"
git push origin irlume-0.5.5-patch.1
git verify-tag irlume-0.5.5-patch.1
```

Record the literal full merged OID. That value is the only dependency selector
allowed in Task 10.

### Task 10: Migrate irlume to the exact fork revision

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/irlume-pam/src/lib.rs`
- Modify: `crates/irlume-pam/tests/pamwrap.rs`

**Interfaces:**
- Consumes: verified fork OID from Task 9.
- Produces: irlume PAM code compiled against the fork and zeroizing secret API.

- [ ] **Step 1: Write RED compile/integration contracts**

Replace the old compile test with one requiring `send_secret`, `get_secret`,
`clear_authtok`, and `info`. Update reseal/keyring unit seams to require
`PamSecretBytes`, and add a pam_wrapper case that replaces a dummy secret then
completes the transaction without printing either value.

- [ ] **Step 2: Run RED against the current local path dependency**

```bash
cargo test -p irlume-pam --lib --no-run --locked
```

Expected: `E0432`/`E0599` for `PamSecretBytes`, `send_secret`, or `get_secret`.

- [ ] **Step 3: Pin the actual fork OID and migrate call sites**

Edit `[patch.crates-io]` to use
`https://github.com/archledger/pam_sm_rust` and paste the literal 40-character
OID recorded in Task 9 as `rev`. Run locked update for `pamsm`. Replace:

```rust
pamh.send_bytes(KEY, bytes.to_vec(), None)
pamh.retrieve_bytes(KEY)
```

with:

```rust
pamh.send_secret(KEY, PamSecretBytes::new(bytes.to_vec()))
match unsafe { pamh.get_secret(KEY) } {
    Ok(secret) if !secret.is_empty() => SecretBytes::new(secret.expose().to_vec()),
    _ => return,
}
```

Keep borrows inside the smallest match arm. Do not convert returned secrets to
ordinary owned vectors unless an existing irlume `SecretBytes` immediately
owns and zeroizes the copy.

- [ ] **Step 4: Run GREEN PAM gates**

```bash
cargo test -p irlume-pam --lib --locked
./scripts/run-tests-guarded.sh --min 25 -- cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1
cargo clippy -p irlume-pam --all-targets --locked -- -D warnings
```

Expected: library tests and all pam_wrapper integrations pass; no dummy secret
appears in output.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/irlume-pam/src/lib.rs crates/irlume-pam/tests/pamwrap.rs
git commit -S -s -m "refactor(pam): pin the maintained binding fork"
git verify-commit HEAD
```

### Task 11: Remove vendored source and preserve offline packaging

**Files:**
- Delete: `third_party/pamsm-0.5.5/`
- Modify: `.gitattributes`
- Modify: `scripts/check-packaging-parity.sh`
- Modify: `docs/DEVELOPMENT.md`

**Interfaces:**
- Produces: source-complete exact-Git dependency validation and no in-tree fork.

- [ ] **Step 1: Write RED packaging assertions**

Change packaging parity's expected contract to require:

```text
Cargo.toml contains the exact archledger/pam_sm_rust Git URL and 40-char rev
Cargo.lock pamsm source contains git+https URL with the same rev
third_party/pamsm-0.5.5 is absent
.gitattributes has no pamsm license exception
```

Run before deleting the directory.

- [ ] **Step 2: Verify RED**

```bash
./scripts/check-packaging-parity.sh
```

Expected: FAIL because vendored source and old path assertions still exist.

- [ ] **Step 3: Delete only the retired source and update parity**

Remove `third_party/pamsm-0.5.5` and its single `.gitattributes` rule. Implement
the new exact URL/OID/lockfile checks without hard-coding an OID different from
Task 9. Update development docs with GitHub-only maintenance and offline vendor
commands.

- [ ] **Step 4: Prove clean archive and offline resolution**

Create an owner-only temporary archive from `HEAD`, extract it, run
`cargo vendor --locked vendor`, then run locked metadata/build with network
disabled and the generated vendor config. Add a negative copy whose Cargo patch
uses `branch = "irlume-patches"`; packaging parity must fail specifically on
the moving selector. Remove both temporary trees after evidence is recorded.

- [ ] **Step 5: Run GREEN and absence scans**

```bash
./scripts/check-packaging-parity.sh
if rg -n 'third_party/pamsm|pamsm = \{ path|PamSendRef|send_bytes|retrieve_bytes|fn conv' Cargo.toml Cargo.lock .gitattributes crates scripts docs --glob '!docs/superpowers/plans/**'; then exit 1; fi
git diff --check
```

Expected: parity passes; scans return no live stale dependency/API references.

- [ ] **Step 6: Commit**

```bash
git add .gitattributes scripts/check-packaging-parity.sh docs/DEVELOPMENT.md
git add -u third_party/pamsm-0.5.5
git commit -S -s -m "build: retire the in-tree pamsm copy"
git verify-commit HEAD
```

### Task 12: Update decisions and produce exact verification evidence

**Files:**
- Modify: `docs/adr/0011-single-field-privileged-auth-input.md`
- Modify: `docs/adr/0012-maintain-pamsm-github-fork.md`
- Modify: `docs/superpowers/specs/2026-08-20-github-maintained-pamsm-fork-design.md`
- Create: `docs/research/2026-08-20-maintained-pamsm-fork-verification.md`

**Interfaces:**
- Consumes: exact fork OID/tag and irlume migration commit.
- Produces: durable source, test, installed, and rollback evidence.

- [ ] **Step 1: Record exact identities, never labels alone**

Update ADR/spec implementation fields with the literal fork repo, full fork
OID, signed tag, full irlume commit, source checksum/tree, and the removal of the
in-tree copy. The report must distinguish fork-local tests, irlume software
tests, GitHub checks, and installed KDE observations.

- [ ] **Step 2: Run the frozen software candidate gates**

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked
./scripts/run-tests-guarded.sh --min 650 -- cargo test -q --workspace --locked
./scripts/run-tests-guarded.sh --min 25 -- cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1
cargo deny check advisories bans licenses sources
./scripts/check-packaging-parity.sh
cargo build --workspace --release --locked
git diff --check
```

Run the exact full ASan/LeakSanitizer workflow command outside sandbox ptrace
restrictions. Expected: zero failures; record actual totals.

- [ ] **Step 3: Verify API/wire scope and fork source identity**

Prove `crates/irlume-common` and daemon protocol are unchanged from merge
`308f26fe271d80ec55b91fbf3369bcb12504a3ac`. Verify Cargo metadata/tree and the
lockfile resolve pamsm to exactly the fork OID. Verify every new commit and the
fork tag signature plus one DCO trailer per commit.

- [ ] **Step 4: Commit the software report**

```bash
git add docs/adr/0011-single-field-privileged-auth-input.md docs/adr/0012-maintain-pamsm-github-fork.md docs/superpowers/specs/2026-08-20-github-maintained-pamsm-fork-design.md docs/research/2026-08-20-maintained-pamsm-fork-verification.md
git commit -S -s -m "docs: verify the maintained PAM binding"
git verify-commit HEAD
```

### Task 13: Install the exact PAM artifact and repeat KDE acceptance

**Files:**
- External modify: `/usr/lib64/security/pam_irlume.so`
- External create: new 0700 rollback snapshot under
  `/home/wisbfime/irlume-system-backups/`
- Modify after evidence: fork verification report from Task 12

**Interfaces:**
- Produces: installed evidence that the fork migration preserved the five-case
  contract.

- [ ] **Step 1: Freeze and hash the candidate**

Require a clean irlume worktree, record HEAD/tree, rebuild release PAM, and hash
the artifact. Inventory installed PAM, `/etc/pam.d/polkit-1`, wiring marker,
service overrides, unit states, health, and enrollment count. Stop on unexpected
drift.

- [ ] **Step 2: Create and verify rollback before installation**

Create a 0700 timestamped directory, copy the installed PAM and relevant
configuration byte-for-byte, record SHA-256/mode/owner/SELinux context, and
write a reviewed rollback-on-error installer. Run `bash -n` and shellcheck.

- [ ] **Step 3: Install only the exact PAM module transactionally**

Stage beside the target, verify candidate hash, atomically rename, restore
SELinux context, and recheck installed hash, stack hash, units, and daemon
health. Automatic rollback runs on any failure. Do not rewrite PAM stacks or
restart the unchanged daemon.

- [ ] **Step 4: Run five fresh-grant KDE cases with the user**

Revoke temporary polkit grants before each harmless `pkexec /usr/bin/true`
case: `yes` face, one correct password, wrong then correct password, empty then
cancel, and camera-busy face then one password. Collect human-visible field
count/message separately from PAM audit and daemon/camera evidence. Never
observe or record credentials.

- [ ] **Step 5: Finalize report, commit, and stop before publication**

Append exact installed hashes, timestamps, factor grantors, daemon request
counts, user confirmations, and rollback path. Rerun final fmt/diff/link checks,
commit signed+DCO, and update shared memory. Do not push, open an irlume PR,
resolve reviews, or merge without explicit authorization for each action.

## Execution finish gate

Before claiming completion, verify all acceptance criteria from the spec line by
line. The fork repository must be public and protected, the signed tag and exact
OID must exist, irlume must contain no vendored copy or moving selector, all
software/ASan/CodeQL/PAM/packaging checks must pass, the installed KDE cases
must pass, and no crates.io package or GitHub binary release may exist.
