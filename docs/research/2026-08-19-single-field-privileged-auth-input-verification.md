# Single-field privileged authentication verification

Date: 2026-08-19

Status: exact software candidate and installed KDE acceptance pass

Design: [Single-field privileged authentication input](../superpowers/specs/2026-08-19-single-field-privileged-auth-input-design.md)

Implementation plan: [Single-field privileged authentication input implementation plan](../superpowers/plans/2026-08-19-single-field-privileged-auth-input.md)

## Frozen product candidate

- Commit: `efddb9fedd17f431a06b83f128b7d3db7556c54a`
- Tree: `c2c28577fb65d2f96c043bdf4f6359b2b14611ad`
- Runtime/test implementation commit: `9fdfcb09d16fefbbe89815c7d2c7ad98c3a8ef01`
- Release `irlume` SHA-256: `667fbe67576ac0261cae3c9e1d2e50d24525ee2057ac022fde5688031ab46468`
- Release `irlumed` SHA-256: `3cf000985592c37afe3a40d67907b3a3f09d7bb84678539d71af5e6e5baca2b2`
- Release `pam_irlume` SHA-256: `4a1833c19c3d222a903b3dda68b14be104c7b3ba9642167965a6a31c063bc805`

The worktree was clean at freeze. CLI and daemon hashes are identical to
candidate `392d151`; only the PAM artifact changed. All four implementation
commits (`7cb866af`, `0454e779`, `9fdfcb09`, `efddb9fe`) have valid EDDSA
signatures and one DCO trailer.

## Test-first evidence

### Safe pamsm clearing seam

The compile contract failed first with `E0599` because `PamLibExt` had no
`clear_authtok`. The local pamsm patch then made the same contract pass. The
crates.io archive SHA-256 matched the locked checksum
`aad7ddca63c73e80eb4ace88e130c9b513da6ec1284becd9fc1fc385a9a72a64`.
All packaged upstream files are byte-identical except the attributed
`src/libpam.rs` delta; Cargo's local `.cargo-ok` extraction marker is omitted.

### PAM state machine

The three-way classifier and injected error tests failed before the new types
and functions existed. After implementation, 13/13 PAM library tests passed,
including confirmation/password/empty classification, info/token conversation
errors, clear failures, and the public clear API contract.

### Real PAM stack

The new one-entry integration was copied into a disposable worktree at parent
`7cb866af`. Against the old product code it displayed the old long intent
prompt, issued a second `Password:` prompt, reached EOF, and failed the required
`pam_exec.so expose_authtok` verifier. The temporary worktree was removed.

Against current code, five focused cases and the complete PAM lane passed:

- one non-`yes` input reused by the downstream password verifier;
- empty input cleared before a fresh password prompt;
- face denial cleared `yes` before password fallback;
- pre-cached password skipped the face offer and camera;
- wrong password remained camera-free and a fresh one-entry retry succeeded.

The guarded lane result was 38 passed: 13 library tests plus all 25 real
pam_wrapper integrations. Fixed dummy tokens were echo-off and absent from
captured output. No real credential was used.

## Full software gates

All of these commands returned zero against frozen candidate `efddb9fe`:

```text
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
cargo build --release --locked
git diff --check
```

Results:

- guarded workspace: 1,764 passed, above the 650 floor;
- dedicated PAM lane: 38 passed;
- slice-4 validator: 16 passed;
- slice-4 runner: 10 passed;
- packaging parity: passed, including local-patch source completeness;
- cargo-deny: advisories, bans, licenses, and sources passed.

Cargo-deny retained existing non-failing warnings for duplicate versions, the
yanked transitive `spin 0.9.8`, and pamsm's deprecated upstream SPDX spelling
`GPL-3.0`. This change did not update unrelated transitive dependencies or
rewrite upstream license metadata.

## Machine contract

The sandboxed strict run reported 35 pass, one failure, and two skips because
udev and the system bus returned `EPERM`, and those diagnostics reached machine
stderr. The identical host run passed 36 checks with zero failures. Both runs
reported two explicit non-pass skips because the conformance script does not
yet know the newer `camera-diagnostics` and `support-report-json` capabilities.

No machine or daemon protocol changed.

## Wire and mixed-version scope

This command produced no diff:

```text
git diff 392d15132322e2bde29559a23540ce9fbeb25f43 -- crates/irlume-common crates/irlume-daemon
```

Therefore the serialized `IntentAttestation::PamConversation`, root-peer
daemon gate, and both mixed-reader directions are byte-for-byte the already
verified `392d151` implementation. The prior mixed-version evidence is reused;
no new mixed-binary run is claimed here. The changed PAM module sends the same
attestation only after obtaining and clearing `yes` through Linux-PAM.

## Packaging-source evidence

A clean `git archive` contained the local pamsm manifest, license, provenance,
and patched source. In the extracted tree, `cargo vendor --locked vendor` and
locked offline metadata resolution passed. A separate disposable negative tree
with only `IRLUME-PATCH.md` removed made packaging parity fail on exactly that
missing file. Both temporary trees were removed.

## Installed KDE acceptance

The user authorized a PAM-only install on Fedora 44 KDE Plasma 6.7.4. Before
the write, the installed PAM hash was `7afbed93…`; `/etc/pam.d/polkit-1` hashed
to `976de951…`, the wiring marker retained sudo/polkit/lock, both irlume units
were active, and daemon health reported one profile with 11 scans, encrypted
templates, and an armed keyring.

A reviewed rollback-on-error script verified every source and backup hash,
staged the PAM module beside its target, renamed atomically, restored SELinux,
and rechecked stack and health. It installed only:

```text
/usr/lib64/security/pam_irlume.so
```

The installed hash is the frozen `4a1833c1…` artifact and its label is
`system_u:object_r:lib_t:s0`. The polkit stack hash stayed `976de951…`; no CLI,
daemon, unit, enrollment, camera configuration, or service policy changed.
No daemon restart was needed because the wire/daemon were unchanged and each
polkit attempt loads PAM in a fresh helper.

The new byte-for-byte rollback snapshot is:

```text
/home/wisbfime/irlume-system-backups/2026-08-19-single-field-efddb9fe
```

It preserves the prior PAM module, polkit stack, wiring marker, service
overrides, and the reviewed install/restore script. The original pre-rollout
snapshot at `/home/wisbfime/irlume-system-backups/2026-08-19-kde-intent-392d151`
also remains intact.

Temporary polkit grants were revoked before every authoritative case. Every
command was the harmless `pkexec /usr/bin/true`; no password value was observed,
logged, or recorded.

### 1. Exact message and confirmed face

At 23:44 EDT the user confirmed Plasma displayed exactly
`Type yes to use face authentication` above the password field, entered `yes`,
and faced the camera. The command exited 0. The daemon received one request,
granted live IR-only authentication at score 0.805, and audit named
`pam_irlume` as the authentication grantor.

### 2. One-entry password

At 23:49 EDT the user entered the real password once in the first field and
confirmed no second field was required. The command exited 0; audit named
`pam_usertype,pam_localuser,pam_unix`; the irlumed journal had no entries in the
test window. Kamoso could remain open because this path never requested the
camera.

### 3. Wrong-password retry

At 23:49–23:50 EDT the user entered one random wrong password, then the real
password once on the retry, and confirmed exactly two submissions total. Audit
recorded one PAM authentication failure followed by one `pam_unix` success.
The command exited 0 and irlumed had no entries in the entire window.

### 4. Empty Enter and cancel

At 23:50–23:51 EDT the user pressed empty Enter, then cancelled the retry.
`pkexec` exited 127/not authorized. Audit recorded the empty password failure;
irlumed had no entries.

### 5. Face failure to fresh password

At 23:51–23:52 EDT Kamoso deliberately held the camera. The user entered `yes`,
waited for the camera-busy face failure, then entered the real password once and
confirmed exactly two submissions total. The daemon recorded the camera-busy
face attempt. Audit then recorded direct `pam_unix` success with no intervening
Unix-password failure for `yes`; the command exited 0.

After all five cases, installed PAM and polkit hashes remained exact, both
irlume units were active, and health still reported the original enrollment,
encrypted templates, armed keyring, and recovery state. The candidate remains
installed; rollback was not needed.

## Conclusion

Candidate `efddb9fe` meets the approved single-field contract on real KDE:
`yes` deliberately selects face, a correct password works once in the same
field, wrong and empty input are camera-free, and a failed face attempt does
not test `yes` as the Unix password. Passive PAD and optional default-off head
gesture policy remain unchanged.
