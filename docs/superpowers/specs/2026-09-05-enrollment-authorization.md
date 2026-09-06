# Enrollment authorization follow-up

Date: 2026-09-05. Agent: codex. Status: approved by user in conversation. Implementation uses this specification.

## Finding

At commit `8bf99653b83292b0a00107836a607c92cc0fe7c9`, an account-owned process can request adding or replacing trusted faces without fresh authorization. Existing live capture, liveness and account-ownership checks still apply. This is a source-confirmed authorization gap relative to the proposed fresh-verification requirement, not a demonstrated face-match bypass or account takeover.

Source checkout: `/home/wisbfime/archledger-gp/irlume/.worktrees/perf-onnx-idle-pools`, branch `perf/onnx-idle-pools`, clean when inspected.

| Operation | Current behavior | Proposed scope |
|---|---|---|
| `Enroll`, including reset and named profiles | Root or target UID; captures new trusted templates | Require OS authorization for non-root peer |
| `AddScan`, including another recognizer | Same ownership gate; captures additional trusted templates | Same requirement, every request |
| Delete/rename/forget operations | Ownership-gated mutations | Preserve current behavior; not a complete account-settings hardening project |
| `RecoveryRestore` | Uses recovery passphrase to restore existing template key | Separate recovery contract; does not capture a new trusted face |
| Position guidance and ordinary authentication | Existing capture/authentication contracts | Preserve current behavior |

Anchors in `crates/irlume-daemon/src/main.rs`: peer credentials and `authorized_for` around 1310-1332; connection scheduling at 2605-2710; exhaustive posture table at 2893; worker authorization and cache invalidation at 4099-4131; `Enroll` at 4438; `AddScan` at 4564; recovery restore at 4868. Wire requests are in `crates/irlume-common/src/lib.rs`, not a separate `ipc.rs`. CLI and guided TUI both construct enrollment requests; TUI sends subsequent captures through `AddScan`.

The separate, validated transactional-replacement patch is still uncommitted in `fix-enrollment-replacement`. It is not included in PR657. Its preservation guarantee must be retained when integrating authorization; the published baseline still deletes existing enrollment early on reset.

## Approaches

1. **Recommended: daemon checks polkit for each trust-adding request.** Reuses the desktop or registered terminal authentication agent. Small private authorization boundary, no new credential store or client-issued reusable token. Requires packaging and confinement integration.
2. **Dedicated PAM password verification.** Can define an independent-factor policy, but needs a new trusted conversation path, distribution-specific PAM configuration, cancellation and secret handling. Reusing the keyring password helper is unsuitable: its unverifiable-password behavior permits continuation and its `crypt` call relies on serialized worker execution.
3. **Root-only enrollment through an elevation helper.** Smaller daemon rule, but removes ordinary non-administrator self-service and does not itself establish fresh authentication when elevation is cached.

## Proposed behavior

Retain the root-or-target UID check. Cross-account non-root requests are denied before prompting. Root retains existing administrative authority, explicitly without claiming fresh human verification. Non-root owners must receive a successful, per-request polkit decision before enrollment work is queued.

Ship a dedicated action with `auth_self`, without the retained `_keep` form, for active, inactive and other sessions. This preserves self-service, including a registered terminal agent, while the daemon independently prevents cross-account changes. No agent or authority means refusal with actionable guidance. Administrative polkit overrides remain OS policy and can permit authorization without a prompt; therefore the guarantee is fresh OS authorization under the shipped policy, not unconditional proof of a newly typed password. Existing polkit PAM configuration may authenticate using Irlume, fingerprint or another configured method.

Use one private adapter around the polkit D-Bus authority interface, including explicit cancellation. Prefer this over a `pkcheck` subprocess because cancellation and typed results are first-class in the API. Implementation uses dbus 0.9.12 and the distribution-maintained system libdbus; the bundled libdbus 1.14.4 was rejected during dependency inspection. Do not add a general authorization framework.

Bind the decision to the daemon-owned request and kernel-derived peer identity. No client-supplied UID, approval boolean or transferable authorization token. Validate process identity against exit, credential changes and PID reuse; do not use bare PID. A private, single-use authorization value travels with the immutable request into the worker, where missing, expired or mismatched authorization is refused before cache invalidation or any enrollment mutation. Recheck the account mapping when consuming it. Root authorization is an explicit separate case.

Authorization runs on the connection side before camera-worker admission, outside camera and template-key locks. This is necessary because polkit's PAM helper can call Irlume authentication. An enrollment request holding that worker while awaiting polkit could prevent its own approval. Pending approvals must be bounded per UID and globally, and disconnected clients cancel outstanding authorization. Reuse existing connection limits, refusal accounting and cancellation primitives where they fit.

Proposed independent budgets: at most 60 seconds for approval, at most 15 seconds from approval to worker admission, and the existing 300-second worker reply budget afterward. Update enrollment-specific CLI/TUI reply waits to cover these stages, without extending ordinary login or status-poll waits. The CLI currently uses a 120-second reply timeout. Each TUI `AddScan` requests its own approval; a whole-wizard grant is deliberately outside this first change.

Denial, cancellation, missing authority/agent, stale approval and client disconnect must not mutate enrollment or invalidate its summary. Approval can itself invoke existing face authentication and open the camera; the promise is that enrollment capture and mutation begin only after approval. Framing guidance retains its existing independent behavior.

Keep the current wire request/reply shapes where possible, using existing error responses for old clients. Old clients still face the daemon gate but may time out earlier. A new client talking to an old daemon cannot promise the new protection; documentation and installed-version checks must distinguish that upgrade case.

## Integration and verification required after approval

- Compose with the transactional-replacement patch in an isolated checkout, preserving its old-profile/key/recovery guarantees.
- Extend the exhaustive request-posture classification so both `Enroll` and `AddScan` require authorization. Exercise the actual connection-to-worker path, not only a helper imitation.
- Test root, owner and stranger; initial, append and reset enrollment; second recognizer; direct socket requests; cancellation, missing agent, timeout, stale identity, queue expiry, duplicate requests and prompt limits. Assert refused requests never reach mutation or cache invalidation.
- Exercise polkit reentry into authentication without an enrollment-held camera or key lock. Verify repeated requests are challenged under the shipped non-retained policy.
- Install the action through Arch, Fedora, both Debian packaging routes, Nix and source install/uninstall paths. Validate confined operation under AppArmor and SELinux. Existing AppArmor rules do not explicitly grant the proposed process-stat/system-bus path, so runtime access must be checked, not assumed. Preserve the systemd sandbox.
- Check old/new client-daemon combinations and TUI cancellation/prompt wording. Run real formatter, Clippy, compiler, relevant tests and packaging checks. Any model or live-camera verification belongs on archhost, with separate coordination for user participation.

The user approved this proposal. It is not yet a tested security implementation. Version 127 was observed locally with `pkcheck --version`; no authentication prompt was invoked. Supported-distribution polkit/binding versions and runtime confinement compatibility remain implementation-planning checks.

## Primary references

[Polkit overview](https://polkit.pages.freedesktop.org/polkit/polkit.8.html) documents action policies, authentication agents and retained authorizations. Its warning about `auth_self` on multiuser systems is why the independent root-or-target check must remain; no application-supplied JavaScript authorization rules are proposed.

[Authority D-Bus interface](https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html) specifies subject identity, authorization results and cancellation. [pkcheck manual](https://polkit.pages.freedesktop.org/polkit/pkcheck.1.html) explicitly requires PID, process start time and UID for its process form, with the UID obtained from OS peer credentials for a custom socket daemon.

These references support the proposed platform interface. They do not establish Windows Hello equivalence, password-only assurance or compatibility on every supported distribution.

## Review and execution record

Inline design review corrected three easy mistakes: covering `Enroll` alone misses `AddScan`; approval inside the camera worker permits circular waiting; OS authorization does not prove an independent password factor. No source code, installed services, PAM/polkit policy, cameras, enrollment, models, power settings or Windows state changed. No benchmark or product test was run for this design-only task.

Some read-only searches initially used a nonexistent source path or omitted the checkout working directory. Corrected reads established the actual paths; failed reads are not evidence of absent functionality. Future source commands must specify the checkout explicitly.

PR657 remains open/draft at the same commit. At 19:29 EDT, 8 of 11 reported checks succeeded; main CI and the two Fedora package jobs were still running, with no failure observed. Continue checking that exact head before any publication-status claim.

The user approved this design and implementation is underway. See the adjacent implementation plan and the canonical task report for current validation and limitations. Do not silently substitute password-only verification or a cached wizard-wide grant.
