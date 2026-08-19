# Conventional Face-Intent Confirmation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Execution mode:** Inline execution only. The user explicitly requested no
sub-agents for this work.

**Goal:** Require a hidden literal `yes` through the PAM conversation before any privileged face-authentication attempt, while making head gestures optional, default-off, and additional-only.

**Architecture:** Put privileged-service classification in the existing shared PAM-service table, carry one additive typed attestation on `Request::Authenticate`, collect it in `pam_irlume`, and reject missing or untrusted attestations in the daemon's existing pre-queue gate. Reuse the current per-service gesture keys only as explicit opt-ins, keep login/keyring/PAD behavior separate, and delete the live gesture-matrix surface that no longer qualifies a security boundary.

**Tech Stack:** Rust 1.88 workspace, `pamsm 0.5.5`, Serde/serde_json, Unix-domain daemon IPC with `SO_PEERCRED`, Linux-PAM/pam_wrapper, Ratatui, shell/Python packaging checks.

**Spec:** `docs/superpowers/specs/2026-08-19-conventional-face-intent-confirmation-design.md`

## Global Constraints

- The exact PAM prompt is `Face authentication: type yes and press Enter (input hidden), or press Enter for password:`.
- The prompt uses `PAM_PROMPT_ECHO_OFF`; its response is never copied into `PAM_AUTHTOK`, PAM transaction data, logs, daemon diagnostics, or error text.
- Only ASCII `yes`, after ASCII-whitespace trimming and ASCII case folding, and with an original length of at most 16 bytes, confirms.
- Every `Elevation` and `AppConsent` service in the shared normalized table requires confirmation; login, greeter, lock, credential release, remote, and unknown services do not gain this prompt.
- A high-privilege transaction carrying `wait` or the structurally wrong `unseal` mode falls back without a camera request; one confirmation never authorizes retries or credential release.
- The daemon accepts `PamConversation` only for a recognized privileged service and only from a root peer, before worker queueing or camera acquisition.
- Head gesture defaults off everywhere. Existing `service_gesture.*=1`, `polkit_gesture=1`, `IRLUME_POLKIT_GESTURE=1`, and credential-release opt-ins remain explicit additional gates.
- A privileged head gesture can run only after conventional confirmation and can never replace it. Shake keeps the existing typed decline behavior.
- Login, lock, cold keyring release, password-first behavior, fingerprint fallback, passive PAD, camera provenance, face matching, rate limits, and biopolicy remain otherwise unchanged.
- `Request::Authenticate` changes additively; old readers ignore the new field and new readers default it to absent. Machine API contract 1 does not change.
- No new dependency, global input listener, desktop plugin, or installed PAM-stack edit is allowed.
- Matrix-only tools are deleted; `gesturecap capture` and `gesturecap replay` remain.
- Every implementation task uses RED → GREEN, ends with focused verification and `git diff --check`, and lands as one signed+DCO atomic commit.

## File and Responsibility Map

- `crates/irlume-common/src/pam_service.rs`: canonical privileged-service predicate shared by PAM and daemon.
- `crates/irlume-common/src/config.rs`: explicit-only head-gesture policy and legacy opt-in precedence.
- `crates/irlume-common/src/lib.rs`: additive `IntentAttestation` wire type and compatibility tests.
- `crates/irlume-auth/src/lib.rs`: consume the shared explicit gesture policy without an implicit privileged default.
- `crates/irlume-pam/src/lib.rs`: pure response parser, hidden PAM prompt, password-first ordering, and attested request.
- `crates/irlume-pam/tests/pamwrap.rs`: real PAM-conversation behavior and no-camera fallback assertions.
- `crates/irlume-daemon/src/main.rs`: root-attestation pre-camera gate, diagnostics, and socket-level tests.
- `crates/irlume-daemon/src/arbiter.rs`: mechanical request-constructor update only; auth classification remains unchanged.
- `crates/irlume-cli/src/commands.rs`, `crates/irlume-cli/src/tui.rs`: fixed confirmation state plus experimental additional-gesture controls.
- `crates/irlume-cli/src/gesturecap.rs`, `crates/irlume-cli/tests/cli.rs`: retain only capture/replay.
- `scripts/hardware/`: delete the head-gesture matrix runner, validator, adapter, and their tests.
- `docs/COMMANDS.md`, `docs/SETUP.md`, `docs/APP-INTEGRATION.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/LIMITATIONS.md`, `docs/FAQ.md`, `docs/STANDARDS.md`, `docs/DEBUGGING.md`, `docs/MACHINE-API.md`, `scripts/README.md`: current user and operator contract.
- Historical ADRs, research, plans, reports, hashes, and external evidence: preserved as historical records.

---

### Task 1: Make privileged intent and gesture defaults one shared policy

**Files:**
- Modify: `crates/irlume-common/src/pam_service.rs:100-165`
- Modify: `crates/irlume-common/src/config.rs:380-505, 694-750, 1080-1135`
- Modify: `crates/irlume-auth/src/lib.rs:449-620, 9860-10145`

**Interfaces:**
- Produces: `ServiceKind::requires_face_intent_confirmation(self) -> bool`.
- Produces: `service_gesture_required(service: &str) -> bool` with absent values always false.
- Consumed by: Tasks 3-5.

- [ ] **Step 1: Add the shared privileged-service RED test**

Add to `pam_service.rs`:

```rust
#[test]
fn only_privileged_services_require_face_intent_confirmation() {
    for (name, kind) in SERVICES {
        assert_eq!(
            kind.requires_face_intent_confirmation(),
            matches!(kind, ServiceKind::Elevation | ServiceKind::AppConsent),
            "{name}"
        );
    }
}
```

- [ ] **Step 2: Add explicit-only gesture RED tests**

Replace the default-on assertions in `config.rs` with a temporary-config test that proves:

```rust
for service in ["sudo", "sudo-i", "su", "su-l", "runuser", "runuser-l", "doas", "polkit-1", "kde"] {
    assert!(!service_gesture_required(service), "{service} must default off");
}
std::fs::write(config_path("settings.conf"), "service_gesture.sudo=1\n").unwrap();
assert!(service_gesture_required("sudo"));
std::fs::write(config_path("settings.conf"), "polkit_gesture=1\n").unwrap();
assert!(service_gesture_required("polkit-1"));
```

Also cover `IRLUME_POLKIT_GESTURE=1`, explicit `service_gesture.*=0`, malformed
`polkit_gesture` values staying off, and the visible tri-state reader.

- [ ] **Step 3: Run the focused tests and record RED**

```bash
cargo test -p irlume-common only_privileged_services_require_face_intent_confirmation --locked
cargo test -p irlume-common explicit_service_gestures_are_opt_in --locked
```

Expected: FAIL because the predicate is absent and current elevation/polkit defaults are on.

- [ ] **Step 4: Implement the smallest shared policy**

Add:

```rust
impl ServiceKind {
    #[must_use]
    pub fn requires_face_intent_confirmation(self) -> bool {
        matches!(self, Self::Elevation | Self::AppConsent)
    }
}
```

Keep `service_gesture_default` for source compatibility but make it return
false. Change `polkit_gesture_enabled` to use the existing `truthy` parser so
only `1`/`true`/`yes`/`on` opt in; absent or malformed environment/file values
return false. Apply the same parser in the visible reader. Preserve precedence:
`service_gesture.<service>` first, then the explicit polkit switch for
`AppConsent`, then false.

- [ ] **Step 5: Make the auth engine consume that one gesture answer**

Remove `forced_consent_for` and `consent_gesture_enabled`. Classify `AppConsent` from `pam_service::classify`, independent of whether its optional gesture is enabled, and reduce the first two `demands_gesture` arms to:

```rust
Self::Verify | Self::AppConsent => {
    service.is_some_and(irlume_common::config::service_gesture_required)
}
```

Leave `CredentialRelease { temporal_challenge }` precedence unchanged.

- [ ] **Step 6: Update auth policy tests and verify GREEN**

Pin `sudo`, `su-l`, `doas`, and `polkit-1` default-off; explicit per-service on; legacy polkit env/file opt-in; login/lock off; credential-release opt-in unchanged.

```bash
cargo test -p irlume-common pam_service --locked
cargo test -p irlume-common service_gesture --locked
cargo test -p irlume-auth demands_gesture --locked
git diff --check
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/irlume-common/src/pam_service.rs crates/irlume-common/src/config.rs crates/irlume-auth/src/lib.rs
git commit -S -s -m "fix(policy): make head gestures explicit opt-ins"
```

---

### Task 2: Add the compatible PAM-conversation attestation

**Files:**
- Modify: `crates/irlume-common/src/lib.rs:395-420, 1310-1375, 1700-1740`
- Modify mechanically: `crates/irlume-cli/src/machine.rs`
- Modify mechanically: `crates/irlume-daemon/src/arbiter.rs`
- Modify mechanically: `crates/irlume-daemon/src/main.rs`
- Modify mechanically: `crates/irlume-pam/src/lib.rs`
- Modify mechanically: `crates/irlume-pam/tests/pamwrap.rs`

**Interfaces:**
- Produces: `IntentAttestation::PamConversation`.
- Produces: `Request::Authenticate { user, service, intent_confirmation }` where the new field is `Option<IntentAttestation>`.
- Consumed by: Tasks 3-4.

- [ ] **Step 1: Add both wire-direction RED tests**

Extend `request_wire_compat_defaults_for_older_callers` and add an old-reader fixture:

```rust
let old: Request = serde_json::from_str(
    r#"{"Authenticate":{"user":"alice","service":"sudo"}}"#,
).unwrap();
assert!(matches!(
    old,
    Request::Authenticate { intent_confirmation: None, .. }
));

let new = Request::Authenticate {
    user: "alice".into(),
    service: Some("sudo".into()),
    intent_confirmation: Some(IntentAttestation::PamConversation),
};
let wire = serde_json::to_string(&new).unwrap();
let round_trip: Request = serde_json::from_str(&wire).unwrap();
assert!(matches!(
    round_trip,
    Request::Authenticate {
        user,
        service: Some(service),
        intent_confirmation: Some(IntentAttestation::PamConversation),
    } if user == "alice" && service == "sudo"
));
```

Use a local `OldRequest::Authenticate(OldAuthenticate)` containing only `user` and `service` to prove Serde ignores the additive field.

- [ ] **Step 2: Run the compatibility test and record RED**

```bash
cargo test -p irlume-common authenticate_intent_attestation_is_compatible_in_both_directions --locked
```

Expected: FAIL because the enum and field do not exist.

- [ ] **Step 3: Add the typed field**

Implement beside `Request`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentAttestation {
    PamConversation,
}
```

and extend only `Authenticate`:

```rust
Authenticate {
    user: String,
    #[serde(default)]
    service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intent_confirmation: Option<IntentAttestation>,
},
```

- [ ] **Step 4: Perform the mechanical constructor migration**

Add `intent_confirmation: None` to ordinary constructors. Change destructuring that does not inspect the field to use `..`; do not add fallback inference from service names.

```bash
rg -n "Request::Authenticate|Authenticate \{" crates -g '*.rs'
cargo check --workspace --all-targets --locked
```

Expected: the first command accounts for every constructor; the check passes.

- [ ] **Step 5: Verify compatibility GREEN**

```bash
cargo test -p irlume-common request_wire_compat --locked
cargo test -p irlume-common authenticate_intent_attestation --locked
cargo check --workspace --all-targets --locked
git diff --check
```

Expected: PASS. Serialized unprivileged requests remain byte-for-byte field-compatible because `None` is omitted.

- [ ] **Step 6: Commit**

```bash
git add crates/irlume-common/src/lib.rs crates/irlume-cli/src/machine.rs \
  crates/irlume-daemon/src/arbiter.rs crates/irlume-daemon/src/main.rs \
  crates/irlume-pam/src/lib.rs crates/irlume-pam/tests/pamwrap.rs
git commit -S -s -m "feat(protocol): carry PAM intent attestation"
```

---

### Task 3: Collect conventional confirmation in PAM before camera work

**Files:**
- Modify: `crates/irlume-pam/src/lib.rs:30-55, 140-405, 730-780, 1000-1140`
- Modify: `crates/irlume-pam/tests/pamwrap.rs:130-190, 360-760, 830-880`

**Interfaces:**
- Consumes: `ServiceKind::requires_face_intent_confirmation` and `IntentAttestation`.
- Produces privately: `classify_intent_response(Option<&[u8]>) -> IntentConfirmation`.
- Produces privately: `confirm_face_intent(&Pam, ServiceKind) -> IntentConfirmation`.
- Produces: exactly one attested `Authenticate` request after `yes`.

- [ ] **Step 1: Add pure parser RED tests**

Add table-driven tests:

```rust
for accepted in [b"yes".as_slice(), b" YES ", b"\tyEs\r\n"] {
    assert_eq!(
        classify_intent_response(Some(accepted)),
        IntentConfirmation::Confirmed
    );
}
let rejected: [Option<&[u8]>; 7] = [
    None,
    Some(b""),
    Some(b"no"),
    Some(b"password"),
    Some(b"yes\0"),
    Some(&[0xff]),
    Some(b"yes             x"),
];
for rejected in rejected {
    assert_eq!(
        classify_intent_response(rejected),
        IntentConfirmation::Fallback
    );
}
```

- [ ] **Step 2: Run parser test and record RED**

```bash
cargo test -p irlume-pam classify_intent_response --locked
```

Expected: FAIL because the classifier is absent.

- [ ] **Step 3: Implement the pure parser and hidden prompt wrapper**

Add only:

```rust
use irlume_common::pam_service::ServiceKind;
use irlume_common::IntentAttestation;

const FACE_INTENT_PROMPT: &str =
    "Face authentication: type yes and press Enter (input hidden), or press Enter for password:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntentConfirmation { Confirmed, Fallback }

fn classify_intent_response(response: Option<&[u8]>) -> IntentConfirmation {
    let Some(response) = response else { return IntentConfirmation::Fallback };
    if response.len() > 16 || !response.is_ascii() {
        return IntentConfirmation::Fallback;
    }
    match std::str::from_utf8(response) {
        Ok(text) if text.trim().eq_ignore_ascii_case("yes") => IntentConfirmation::Confirmed,
        _ => IntentConfirmation::Fallback,
    }
}

fn confirm_face_intent(pamh: &Pam, service: ServiceKind) -> IntentConfirmation {
    if !service.requires_face_intent_confirmation() {
        return IntentConfirmation::Fallback;
    }
    match pamh.conv(Some(FACE_INTENT_PROMPT), pamsm::PamMsgStyle::PROMPT_ECHO_OFF) {
        Ok(Some(response)) => classify_intent_response(Some(response.to_bytes())),
        _ => IntentConfirmation::Fallback,
    }
}
```

The service check makes the prompt fail closed if a future caller invokes it on
a login/lock path. Do not add a prompt abstraction or dependency.

- [ ] **Step 4: Add PAM-flow RED integration cases**

In `pamwrap.rs`, use the real module and fake daemon to prove:

1. `sudo`, `sudo-i`, `su`, `su-l`, `runuser`, `runuser-l`, `doas`, `polkit-1`, and `polkit` prompt once; `yes\n` sends one request with `PamConversation`.
2. Enter, `no`, junk, and a pamtester run whose stdin is closed (the conversation-error path) send no request and fall through to `pam_permit.so`.
3. `kde`, `sddm`, unseal/keyring/reseal, and remote paths do not receive the new confirmation prompt.
4. A non-empty cached `PAM_AUTHTOK` returns before the prompt and daemon.
5. A privileged `wait` or privileged `unseal` line sends no request.
6. Feeding `not-the-real-password\nreal-password\n` through an echo-off confirmation followed by pam_wrapper's `pam_matrix.so` never prints the first value and authenticates with the second value. Extend `Harness` with the sibling path `pam_wrapper/pam_matrix.so`, write `tester:real-password:sudo` to a temporary passdb, and use this stack:

```rust
h.write_service(
    "sudo",
    &[
        h.auth_line("sufficient", ""),
        format!(
            "auth required {} passdb={} verbose",
            h.matrix.display(),
            passdb.display()
        ),
    ],
);
```

If the confirmation response leaks into `PAM_AUTHTOK`, `pam_matrix` consumes
`not-the-real-password` and the test fails instead of asking for the fresh
password.

For fallback stacks, use the existing pattern:

```rust
h.write_service(
    "sudo",
    &[
        h.auth_line("sufficient", ""),
        "auth required pam_permit.so".into(),
    ],
);
```

- [ ] **Step 5: Wire confirmation after password-first and before gesture/camera work**

Resolve `service` once after the cached/typed-password early return. If its kind requires confirmation:

```rust
if wait || unseal {
    return PamError::IGNORE;
}
let intent_confirmation = match confirm_face_intent(&pamh, kind) {
    IntentConfirmation::Confirmed => Some(IntentAttestation::PamConversation),
    IntentConfirmation::Fallback => return PamError::IGNORE,
};
```

Pass that value to `try_verify`. For all other services pass `None`. Remove the default polkit gesture instruction; after a successful `yes`, show the existing nod/shake `TEXT_INFO` only when `service_gesture_required(service)` is explicitly true. Keep the credential-release opt-in instruction unchanged.

- [ ] **Step 6: Change `try_verify` to send the attestation**

Use the exact signature:

```rust
fn try_verify(
    pamh: &Pam,
    user: &str,
    intent_confirmation: Option<IntentAttestation>,
) -> PamError
```

and populate the new request field. Do not expose a CLI flag or module argument that fabricates confirmation.

- [ ] **Step 7: Verify PAM GREEN**

```bash
cargo test -p irlume-pam --lib --locked
./scripts/run-tests-guarded.sh --min 16 -- \
  cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1
git diff --check
```

Expected: parser, real hidden prompt, no-request fallback, password-first, and existing keyring/gesture-decline tests pass.

- [ ] **Step 8: Commit**

```bash
git add crates/irlume-pam/src/lib.rs crates/irlume-pam/tests/pamwrap.rs
git commit -S -s -m "feat(pam): confirm privileged face intent"
```

---

### Task 4: Enforce attestation at the daemon pre-camera boundary

**Files:**
- Modify: `crates/irlume-daemon/src/main.rs:2040-2125, 2750-2820, 3405-3425, 5900-6025, 6380-6570, 7860-8135`

**Interfaces:**
- Consumes: `Request::Authenticate.intent_confirmation`, `IntentAttestation`, and the shared service predicate.
- Produces: a typed `Response::AuthResult` policy refusal before queue/camera.

- [ ] **Step 1: Add pure pre-gate RED cases**

Add `privileged_auth_requires_root_pam_attestation` covering this table:

```text
root + sudo + PamConversation       -> proceed
root + polkit-1 + PamConversation   -> proceed
root + sudo + absent                -> policy refusal
non-root + sudo + PamConversation   -> policy refusal
root + service None + attestation   -> policy refusal
root + kde + attestation            -> policy refusal
root + kde + absent                 -> proceed unchanged
```

The refusal must be:

```rust
Response::AuthResult {
    granted: false,
    score: 0.0,
    live: false,
    reason: "privileged face authentication requires PAM conversation confirmation".into(),
    declined_by_gesture: false,
    refused_by_policy: true,
}
```

- [ ] **Step 2: Add a real socket/closed-arbiter RED test**

Using `with_serve_as_peer_and_diagnostics`, send missing and non-root attestations to a ready daemon with a closed arbiter. Assert the exact typed response, `arbiter.take().is_none()`, and one failed `OperationClass::Authentication` terminal event per refusal. Send a root-attested sudo request to an open worker boundary and prove it is the only case queued.

- [ ] **Step 3: Run focused daemon tests and record RED**

```bash
cargo test -p irlume-daemon privileged_auth_requires_root_pam_attestation --locked
cargo test -p irlume-daemon intent_refusal_is_recorded_without_queue_or_camera --locked
```

Expected: FAIL because `pregate` does not inspect the attestation.

- [ ] **Step 4: Add one pre-gate helper and call it from `pregate`**

Implement a private helper that matches only `Request::Authenticate`. Rules:

- recognized `Elevation`/`AppConsent`: require root plus `Some(PamConversation)`;
- non-privileged, absent, or unknown service: accept only `None` and preserve existing policy paths;
- any attestation on a non-privileged/absent service is malformed and refused;
- never log prompt bytes or response bytes.

Call it in `pregate` after username validation and before posture privilege handling. Because startup dispatch, ready socket dispatch, and worker dispatch all call `pregate`, do not duplicate the check in the camera arm.

- [ ] **Step 5: Verify daemon GREEN and ordering**

```bash
cargo test -p irlume-daemon privileged_auth_requires_root_pam_attestation --locked
cargo test -p irlume-daemon intent_refusal_is_recorded_without_queue_or_camera --locked
cargo test -p irlume-daemon pregate --locked
cargo test -p irlume-daemon authenticate_ --locked
git diff --check
```

Expected: missing/forged attestations never queue; root-attested privileged requests reach the existing auth dispatch; screen unlock remains unchanged.

- [ ] **Step 6: Commit**

```bash
git add crates/irlume-daemon/src/main.rs
git commit -S -s -m "fix(daemon): gate privileged face auth on PAM intent"
```

---

### Task 5: Present fixed confirmation and optional gesture honestly

**Files:**
- Modify: `crates/irlume-cli/src/commands.rs:1500-1755, 2170-2205`
- Modify: `crates/irlume-cli/tests/cli_dispatch.rs:310-450`
- Modify: `crates/irlume-cli/src/tui.rs:3600-3760, 4860-4960, 8190-8320, 12700-12750`

**Interfaces:**
- Consumes: explicit-only `service_gesture_required_visible`.
- Produces user copy: `Face confirmation: keyboard required` and `Additional head gesture: off | on (experimental)`.

- [ ] **Step 1: Write CLI/TUI RED expectations**

Update tests so a clean configuration shows sudo and polkit gesture `off (default)` plus fixed keyboard confirmation. Pin:

```text
Face confirmation: keyboard required
Additional head gesture: off (default)
```

Enabling a service gesture must say it is experimental and may reject valid attempts. Disabling must proceed without a security warning or yes/no confirmation because it cannot remove conventional confirmation.

- [ ] **Step 2: Run focused UI tests and record RED**

```bash
cargo test -p irlume-cli --test cli_dispatch credential_release_challenge --locked
cargo test -p irlume-cli settings_per_service_gesture --locked
```

Expected: FAIL on old default-on and “face match alone” copy.

- [ ] **Step 3: Simplify the CLI toggle**

Delete `confirm_high_privilege_disable` and the `--yes` bypass branch used only for that confirmation. Keep root authorization and unknown-service diagnostics. Print the fixed confirmation line for recognized privileged services, then render the gesture as explicit/default and additional/experimental.

On `on`, print one warning that the classifier is not population-qualified and may reject a valid attempt. On `off`, print a neutral success message; never say a face match alone approves privilege.

- [ ] **Step 4: Simplify the TUI toggle**

Change the section heading to:

```text
Face confirmation: keyboard required
Additional head gesture (experimental)   ([↑/↓] pick  [c] toggle)
```

Both toggle directions set `Suspend::ServiceGesture` directly. Enabling logs the experimental false-reject warning; disabling is neutral. Keep root-only tri-state handling and the separate credential-release toggle.

Update sudo/polkit setup hints to say the PAM keyboard confirmation is mandatory and a gesture is optional only when explicitly enabled.

- [ ] **Step 5: Verify GREEN and contract stability**

```bash
cargo test -p irlume-cli --test cli_dispatch credential_release_challenge --locked
cargo test -p irlume-cli settings_per_service_gesture --locked
cargo test -p irlume-cli tui_contains_only_head_gesture_controls --locked
cargo test -p irlume-cli --test machine_api --locked
git diff --check
```

Expected: PASS; machine API contract 1 output is unchanged.

- [ ] **Step 6: Commit**

```bash
git add crates/irlume-cli/src/commands.rs crates/irlume-cli/src/tui.rs crates/irlume-cli/tests/cli_dispatch.rs
git commit -S -s -m "fix(cli): present gesture as optional confirmation"
```

---

### Task 6: Delete the obsolete live gesture matrix surface

**Files:**
- Delete: `scripts/hardware/run-head-gesture-matrix.sh`
- Delete: `scripts/hardware/validate-head-gesture-matrix.py`
- Delete: `scripts/hardware/test-validate-head-gesture-matrix.py`
- Delete: `scripts/hardware/head-gesture-matrix-adapter.sh`
- Delete: `scripts/hardware/test-head-gesture-matrix-adapter.py`
- Modify: `crates/irlume-cli/src/gesturecap.rs:1-270, 690-790`
- Modify: `crates/irlume-cli/tests/cli.rs:300-325, 2140-2410`
- Modify: `scripts/README.md:55-70`

**Interfaces:**
- Preserves: `IRLUME_DEV=1 irlume gesturecap capture ...`.
- Preserves: `IRLUME_DEV=1 irlume gesturecap replay <file-or-dir>`.
- Removes: `gesturecap identity`, `gesturecap attempt`, and matrix publication/qualification.

- [ ] **Step 1: Add retired-subcommand RED tests**

Change CLI help to require only `<capture|replay>`. Add tests that `identity` and `attempt` exit 2, print the two-command usage, and do not inspect a camera. Keep every strict replay/input-bound test.

- [ ] **Step 2: Run the focused CLI test and record RED**

```bash
cargo test -p irlume-cli --test cli gesturecap_hardware_subcommands_are_retired --locked
```

Expected: FAIL because both subcommands still dispatch.

- [ ] **Step 3: Remove matrix-only Rust code**

Delete `camera_node_sysfs_path`, camera-pair digest/identity helpers, `valid_digest`, `identity`, `attempt`, and their dedicated digest/rolling-window adapter tests. Retain capture/replay, bounded JSONL parsing, atomic 0600 capture installation, and replay's production-window evidence.

- [ ] **Step 4: Delete the five matrix files and current references**

Use `git rm` on the exact five paths. Remove their rows from `scripts/README.md` and remove only current help/CI/package references. Do not edit dated research, old plans, old reports, ADR-0009, commit history, or external evidence.

- [ ] **Step 5: Prove the retained research tool and absence contract**

```bash
cargo test -p irlume-cli gesturecap --locked
cargo test -p irlume-cli --test cli gesturecap --locked
python3 -m py_compile scripts/*.py scripts/hardware/*.py
bash -n scripts/*.sh scripts/hardware/*.sh
rg -n "head-gesture-matrix|gesturecap (identity|attempt)" \
  crates scripts .github packaging nix docs/COMMANDS.md docs/DEBUGGING.md
git diff --check
```

Expected: tests and syntax pass; the final `rg` returns no current reference. Historical directories are intentionally outside the scan.

- [ ] **Step 6: Commit**

```bash
git add crates/irlume-cli/src/gesturecap.rs crates/irlume-cli/tests/cli.rs scripts
git commit -S -s -m "refactor(dev): retire live gesture matrix"
```

---

### Task 7: Publish the current confirmation contract

**Files:**
- Modify: `docs/COMMANDS.md`
- Modify: `docs/SETUP.md`
- Modify: `docs/APP-INTEGRATION.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/THREAT_MODEL.md`
- Modify: `docs/LIMITATIONS.md`
- Modify: `docs/FAQ.md`
- Modify: `docs/STANDARDS.md`
- Modify: `docs/DEBUGGING.md`
- Modify: `docs/MACHINE-API.md`

**Interfaces:**
- Consumes: implemented PAM prompt, daemon enforcement, explicit gesture policy, and retained capture/replay tool.
- Produces: one current operator story; historical records remain unchanged.

- [ ] **Step 1: Write the exact user flow in current docs**

For privileged face auth document:

```text
1. irlume asks for hidden literal `yes` through PAM.
2. Enter or any other response chooses password/fingerprint without opening the camera.
3. `yes` authorizes one face attempt.
4. An explicitly enabled experimental head gesture is an additional gate.
5. Shake declines a gesture-gated attempt; it never bypasses keyboard confirmation.
```

Document no extra irlume prompt for login/greeter/lock/keyring release and preserve the existing optional gesture policy for those surfaces.

- [ ] **Step 2: Correct settings, threat, and limitation text**

State that all `service_gesture.*` and polkit gesture defaults are off, `=1` is an experimental additional opt-in, and disabling it does not weaken the mandatory keyboard gate. Document the attestation residual: root or a compromised PAM conversation provider can assert it; it is not cryptographic proof of physical input.

Keep passive PAD distinct from intent. Do not describe head gesture as population-qualified or as anti-spoofing.

- [ ] **Step 3: Keep machine contract 1 explicit**

In `docs/MACHINE-API.md`, state that fixed confirmation policy is rendered from the shared service table and introduces no contract-1 field. Preserve existing JSON examples and retired eye fields exactly.

- [ ] **Step 4: Audit only current terminology**

```bash
rg -n -i "elevation and polkit require|gesture.*default on|face match alone.*approve|disable.*gesture.*risk|gesturecap (identity|attempt)|head-gesture-matrix" \
  README.md docs/COMMANDS.md docs/SETUP.md docs/APP-INTEGRATION.md \
  docs/ARCHITECTURE.md docs/THREAT_MODEL.md docs/LIMITATIONS.md docs/FAQ.md \
  docs/STANDARDS.md docs/DEBUGGING.md docs/MACHINE-API.md scripts/README.md \
  crates packaging nix .github
```

Expected: no stale current claim. Findings in dated research/ADRs/plans are historical and remain.

- [ ] **Step 5: Verify links and diff, then commit**

```bash
git diff --check
cargo doc --workspace --no-deps --locked
git add docs/COMMANDS.md docs/SETUP.md docs/APP-INTEGRATION.md \
  docs/ARCHITECTURE.md docs/THREAT_MODEL.md docs/LIMITATIONS.md docs/FAQ.md \
  docs/STANDARDS.md docs/DEBUGGING.md docs/MACHINE-API.md
git commit -S -s -m "docs: publish privileged face confirmation flow"
```

---

### Task 8: Freeze software evidence and stop before installed PAM changes

**Files:**
- Create: `docs/research/2026-08-19-conventional-face-intent-confirmation-verification.md`
- Modify implementation only when a failing gate proves an in-scope defect; every fix starts with a focused regression test and lands separately.

**Interfaces:**
- Consumes: Tasks 1-7 at one exact commit OID.
- Produces: release-candidate evidence and a separate installed-PAM approval checkpoint.

- [ ] **Step 1: Run formatting, compile, lint, docs, release, and full tests**

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo build --release --locked
./scripts/run-tests-guarded.sh --min 650 -- cargo test --workspace --locked
git diff --check
```

Expected: all pass.

- [ ] **Step 2: Run PAM, machine, and packaging gates**

```bash
./scripts/run-tests-guarded.sh --min 16 -- \
  cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1
python3 scripts/machine-api-conformance.py --irlume target/release/irlume --strict
./scripts/check-packaging-parity.sh
python3 scripts/hardware/test-run-slice4-hardware.py
python3 scripts/hardware/test-validate-slice4-hardware.py
bash -n scripts/hardware/run-slice4-hardware.sh
```

Expected: hidden prompt/fallback and contract 1 pass; passive camera/PAD tooling remains intact.

- [ ] **Step 3: Run mixed-version reader and behavior checks**

Create a detached, validated temporary worktree for `origin/main`; never replace `/usr/bin` binaries.

```bash
git worktree add --detach /tmp/irlume-intent-origin-main origin/main
CARGO_TARGET_DIR=/tmp/irlume-intent-old-target \
  cargo build --manifest-path /tmp/irlume-intent-origin-main/Cargo.toml \
  --release --locked -p irlume-pam -p irlume-daemon -p irlume-cli
cargo test -p irlume-common authenticate_intent_attestation --locked
cargo test -p irlume-daemon privileged_auth_requires_root_pam_attestation --locked
```

Using pam_wrapper service directories and temporary socket/state/config roots, verify:

- candidate PAM → old daemon: the hidden prompt occurs, old Serde ignores the field, and the legacy daemon may impose its old gesture policy; no parse failure occurs;
- old PAM → candidate daemon: its privileged request lacks the field and is refused before camera, then password fallback runs;
- candidate PAM → candidate daemon: `yes` permits exactly one request and Enter permits none.

Remove the temporary worktree and target only after validating their exact paths. Do not install either PAM module.

- [ ] **Step 4: Validate isolated client rendering without editing installed stacks**

With pam_wrapper-owned service files, exercise exact sudo/su/doas stacks plus polkit-shaped KDE/GNOME/text conversations. Record prompt visibility, hidden input, Enter fallback, one-shot `yes`, cancellation, unsupported conversation fallback, and optional gesture composition. Stop on duplicate prompts, invisible prompt, camera-before-confirmation, cached-response reuse, or fallback failure.

- [ ] **Step 5: Record the frozen evidence**

Write the verification report with:

- exact commit and tree OIDs;
- every command and result;
- test counts and explicit environment skips;
- mixed-version binary hashes and directions;
- confirmation that no installed PAM file, system daemon, real credential, or host service policy changed;
- remaining trust boundary and optional-gesture limitations.

- [ ] **Step 6: Commit the report**

```bash
git add docs/research/2026-08-19-conventional-face-intent-confirmation-verification.md
git commit -S -s -m "docs: verify privileged face confirmation"
git verify-commit HEAD
git status --short
```

Expected: signature good, one DCO trailer, clean worktree.

- [ ] **Step 7: Stop and request separate user approval**

Report the isolated results and candidate OID. Do not edit `/etc/pam.d`, install `pam_irlume.so`, restart host authentication services, or run a real privileged face attempt until the user explicitly approves that separate rollout step.

---

## Final Completion Gate

- [ ] Every shared `Elevation` and `AppConsent` spelling requires hidden literal `yes` before a face request.
- [ ] Enter, wrong input, oversized/non-ASCII input, cancellation, missing conversation, and errors choose fallback with no daemon/camera request.
- [ ] The confirmation response is neither echoed nor reused as `PAM_AUTHTOK` and never appears in logs or diagnostics.
- [ ] Cached passwords still win before confirmation or camera work.
- [ ] Privileged `wait`/miswired `unseal` cannot turn one confirmation into retries or credential release.
- [ ] Missing, forged, non-root, absent-service, and non-privileged attestations are refused before the arbiter and camera.
- [ ] Old/new request readers work in both directions; old PAM → new daemon fails closed; new PAM → old daemon parses.
- [ ] Head gesture is default-off everywhere and can be only an explicit additional gate after privileged keyboard confirmation.
- [ ] Login, lock, keyring release, password/fingerprint fallback, passive PAD, face matching, rate limits, and machine contract 1 remain intact.
- [ ] CLI/TUI/docs call keyboard confirmation mandatory and gesture optional/experimental; no stale “face match alone approves privilege” warning remains.
- [ ] Matrix runner/validator/adapter and `gesturecap identity/attempt` are absent; capture/replay remains fully tested.
- [ ] Full workspace, strict Clippy, rustdoc, release, PAM wrapper, machine, packaging, syntax, and mixed-version gates pass at one exact OID.
- [ ] No installed PAM stack or live host authentication policy changed without a new explicit user approval.

## Self-Review Record

- Spec coverage: decision, service table, hidden prompt, parser bounds, password-first ordering, daemon trust seam, mixed versions, gesture migration, UI copy, tooling cleanup, documentation, verification, and rollout approval each map to Tasks 1-8.
- Minimality: reuses the existing service table, PAM conversation, request enum, `pregate`, gesture keys, diagnostics, and pam_wrapper harness; adds no dependency or public bypass.
- Type consistency: Tasks 2-4 use the exact `IntentAttestation::PamConversation` and `Option<IntentAttestation>` names; Task 1's service predicate is the sole privileged classification used by PAM and daemon.
- Intentional non-work: no classifier retune, no population qualification claim, no machine-contract bump, no desktop plugin, no global key listener, no bulk config rewrite, and no installed PAM mutation.
