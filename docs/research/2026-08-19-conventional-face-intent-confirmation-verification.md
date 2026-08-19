# Conventional face-intent confirmation verification

Date: 2026-08-19

Status: software candidate passes; installed-PAM rollout remains on hold

Design: [Conventional face-intent confirmation](../superpowers/specs/2026-08-19-conventional-face-intent-confirmation-design.md)

Implementation plan: [Conventional face-intent confirmation implementation plan](../superpowers/plans/2026-08-19-conventional-face-intent-confirmation.md)

## Frozen candidate

- Commit: `392d15132322e2bde29559a23540ce9fbeb25f43`
- Tree: `6c4b172fdb153a3e8e10a7a3d7d296ea5bb947d5`
- Release `irlumed` SHA-256: `3cf000985592c37afe3a40d67907b3a3f09d7bb84678539d71af5e6e5baca2b2`
- Release `pam_irlume` SHA-256: `7afbed93888dfdf5459704711f0d3657a018483d77648c562f2e5e3395ae12db`
- Release `irlume` SHA-256: `667fbe67576ac0261cae3c9e1d2e50d24525ee2057ac022fde5688031ab46468`

The worktree was clean at freeze. Local ignored detector/recognizer symlinks
pointed to the parent repository's existing model assets; they were environment
setup, not candidate content.

## Software gates

All commands below ran against the frozen candidate and returned zero:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo build --release --locked
./scripts/run-tests-guarded.sh --min 650 -- cargo test -q --workspace --locked
git diff --check
```

The guarded workspace result was 1,761 passed, above the 650 floor. Explicitly
ignored tests retained their stated external requirements: real/swtpm TPM,
v4l2loopback or real camera nodes, packaged model/runtime benchmark lanes,
hardware emitter locks, and the separately run PAM wrapper suite.

The dedicated PAM lane ran outside the socket-restricted sandbox, using only
pam_wrapper service files and fake Unix-socket daemons:

```text
./scripts/run-tests-guarded.sh --min 21 -- \
  cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1
```

Result: 31 passed—10 library tests plus all 21 pam_wrapper integrations. The
suite covers bounded ASCII `yes`, empty/wrong/EOF fallback with no daemon
request, hidden input, no `PAM_AUTHTOK` reuse, cached-password precedence,
every shared elevation/app-consent spelling, privileged `wait`/`unseal`
refusal, nonprivileged login/lock/keyring scoping, one-shot attestation, optional
gesture ordering, and polkit shake semantics.

Additional gates:

- Machine API strict conformance: 36 passed, 0 failed, 2 explicit
  unknown-capability skips (`camera-diagnostics`, `support-report-json`).
- Packaging parity: passed across Fedora, Arch, Debian/nfpm, Ubuntu/PPA, and
  Nix declarations.
- Slice-4 runner harness: 10 passed.
- Slice-4 validator harness: 16 passed.
- `bash -n scripts/hardware/run-slice4-hardware.sh`: passed.

Machine contract 1 did not gain a confirmation/attestation field.

## Mixed versions

The older side was a detached `origin/main` build:

- Old commit: `f94ca363d3638712ad9d707a273f6236415e2a62`
- Old `irlumed` SHA-256: `c97dcff977ed16a3f959a5a73784909e5b3df40b7dc72fb7a98cc7e0f90091cc`
- Old `pam_irlume` SHA-256: `eb6dae4d0d27ad14e5215cd6178cf36fd6ae591d8dbad44dfb33d1d8b6b9fee7`

Both daemons ran only with temporary socket/state/config/keyring roots.

### Candidate PAM to old daemon

The candidate PAM displayed exactly one hidden confirmation and sent the
additive `PamConversation` field. The old daemon ignored the unknown field,
parsed the request, and returned its ordinary typed unenrolled denial rather
than `bad request`. pam_wrapper then reached password fallback successfully.

Observed old-daemon response, with the local test account redacted:

```json
{"AuthResult":{"granted":false,"score":0.0,"live":false,"reason":"'<local-test-user>' is not enrolled","refused_by_policy":false,"declined_by_gesture":false}}
```

### Old PAM to candidate daemon

The old PAM emitted an `Authenticate` request with no attestation. The candidate
daemon refused it before camera/worker work, and the old module mapped the
response to `PAM_IGNORE`; pam_wrapper's fallback completed successfully.

Observed candidate response:

```json
{"AuthResult":{"granted":false,"score":0.0,"live":false,"reason":"privileged face authentication requires PAM conversation confirmation","refused_by_policy":true,"declined_by_gesture":false}}
```

### Candidate PAM to candidate daemon

The 21-test pam_wrapper lane proves `yes` emits exactly one attested request and
Enter/wrong/cancelled input emits none. Daemon socket tests prove missing,
non-root, absent-service, and nonprivileged assertions never queue; a root
assertion for a shared privileged service alone crosses the worker boundary.

All temporary mixed-version worktrees, targets, PAM service directories,
sockets, and state roots were removed after verification. No `/usr/bin` binary
was replaced.

## Tooling and documentation

- The live gesture-matrix runner, validator, adapter, and their tests are gone.
- `gesturecap identity` and `gesturecap attempt` are retired before camera work.
- `gesturecap capture` and `gesturecap replay` retain bounded pose-only tests.
- Current CLI, TUI, doctor, Bitwarden guidance, architecture, threat model,
  setup, FAQ, limits, standards, debugging, commands, and machine-API docs call
  keyboard confirmation mandatory and head gesture optional/experimental.
- Dated research, prior ADRs/plans, and package changelogs remain historical.

## Security review

- The response parser accepts only an original input of at most 16 ASCII bytes
  equal to `yes` after trimming and case folding.
- `PAM_PROMPT_ECHO_OFF` is used. Response bytes are not copied into
  `PAM_AUTHTOK`, request data, logs, or diagnostics.
- Privileged confirmation is checked in PAM before daemon contact and again in
  the daemon before startup routing, arbiter queueing, or camera work.
- The typed assertion is accepted only from a root peer for a recognized
  elevation/app-consent service. It is not cryptographic proof against root or
  a compromised PAM conversation provider.
- Optional head gesture defaults off, cannot replace keyboard confirmation,
  and remains separate from passive PAD.
- No new dependency was added.

## Rollout hold

pam_wrapper verifies the real PAM module and exact sudo, sudo-i, su, su-l,
runuser, runuser-l, doas, polkit-1, and polkit service names. It verifies the
prompt bytes and text-client behavior. The repository has no isolated KDE or
GNOME authentication-agent renderer, and those desktop agents cannot be pointed
at a temporary PAM stack without an isolated VM/container or an installed PAM
edit.

Therefore KDE/GNOME visual rendering, cancellation, and dialog composition are
not claimed as passed. This is a rollout hold, not a product-code failure and
not permission to test against the host stack.

No installed PAM file, system daemon, real credential, camera capture, service
policy, or host authentication attempt changed during this verification. A
separate user decision is required before provisioning a disposable graphical
test environment or modifying any installed PAM stack.
