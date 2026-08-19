# Head-gesture-only removal impact

Date: 2026-08-18

Repository baseline: local branch HEAD `39c4e44eaba19e2431e640734875f86356718008` (upstream merge baseline [`f94ca363d3638712ad9d707a273f6236415e2a62`](https://github.com/archledger/irlume/commit/f94ca363d3638712ad9d707a273f6236415e2a62), [PR #501](https://github.com/archledger/irlume/pull/501), plus the local developer-only selector-diagnostics commit).

## Executive finding

Making irlume head-gesture-only is a cross-contract retirement, not a detector swap. The shipped approving contract is currently **nod or calibrated held eye closure by default**, with `consent_gesture=nod` and `consent_gesture=closure` narrowing the choice; the shared parser returns `Either` when the key is absent (`crates/irlume-common/src/config.rs:514-632`). The production authorization path converts the enrollment's stored EAR pair to a `ClosureCalibration`, collects pose and EAR in both the pre-match and post-match watches, and grants on either a nod or a qualifying closure (`crates/irlume-auth/src/lib.rs:4229-4272`, `4281-4376`, `4488-4568`). Therefore closure is active, not leftover research code.

The safe target contract is:

- when a service policy requires deliberate consent, repeated/continuous head nodding approves;
- a deliberate head shake declines the daemon authentication attempt; on polkit it continues to map to `PAM_ABORT`, while on login/lock/elevation it remains a soft PAM failure that preserves password fallback unless the product owner explicitly changes that separate PAM semantic (`crates/irlume-pam/src/lib.rs:273-360`, `744-782`);
- no authorization, enrollment, setup, status, or recovery path asks the user to blink, close or open their eyes, hold an eye pose, or calibrate an eye measurement;
- passive automatic PAD remains in front of matching and remains independent of the consent gesture: RGB/IR co-location, frontality, exposure validity, IR reflectance, center/edge depth, optional deny-only third-party PAD, RGB-only deterrent cues, and the passive corneal-glint measurement (`crates/irlume-liveness/src/lib.rs:4-11`, `502-696`; `crates/irlume-auth/src/lib.rs:3831-3939`).

The smallest safe implementation is not to replace `Either` with `Nod` and delete every old symbol in one release. Existing `consent_gesture=closure` explicitly excluded nod; silently interpreting it as nod widens an operator-selected authorization policy. Existing enrollments may still carry `require_eyes_open=true`; silently ignoring that also weakens an explicit per-user policy even though new enables are already refused as broken (`crates/irlume-daemon/src/main.rs:3270-3291`). Use a staged, fail-closed migration: make nod/shake the only runtime detectors, preserve old wire variants and required contract-1 fields as tombstones, make legacy `closure` configuration an actionable refusal until explicitly migrated, and keep the legacy eyes-open OFF operation long enough to clear old state.

One head-only correctness issue should be fixed as part of the refactor. The current consent result is a boolean plus `gesture_cancelled` side state. In-loop shake detection is terminal, but the completed-take fallback only asks whether the whole take is a nod or closure; a shake completed in the final one-to-five frames can be safely not granted, but is not reported as an explicit decline (`crates/irlume-auth/src/lib.rs:477-509`, `4325-4376`). A typed `Approve | Decline | NoGesture` result should flow from both the streaming cadence and the completed-take boundary.

## Scope and terminology

Four eye-related mechanisms exist and must not be conflated:

| Mechanism | Current status | Retirement disposition |
|---|---|---|
| Natural-blink `require_challenge` | Already retired from production. `run_passive_liveness` is marked production-dead, while the contract-1 machine field remains frozen at false (`crates/irlume-auth/src/lib.rs:4012-4042`; `crates/irlume-cli/src/machine.rs:2293-2303`). | Do not revive. Dead detector/research tooling may be removed or archived, but dated evidence remains. |
| Deliberate held-eye closure | Production-live approving gesture, stored per user and accepted by the rolling consent watch (`crates/irlume-core/src/storage.rs:186-194`; `crates/irlume-auth/src/lib.rs:4252-4272`, `4350-4355`). | Remove from authorization, storage, setup, IPC, and current docs. |
| `require_eyes_open` | Stored and enforced for legacy `true`, but new enables are refused because genuine open eyes were rejected (`crates/irlume-auth/src/lib.rs:5014-5019`; `crates/irlume-daemon/src/main.rs:3270-3291`). | Retire with an explicit legacy-state policy; remove its evaluator after legacy state can no longer reach it. |
| Passive corneal-glint cue | Automatically measured from the IR frame; supporting/logged, never decisive by itself (`crates/irlume-auth/src/lib.rs:3831-3889`; `crates/irlume-liveness/src/lib.rs:470-479`, `587-595`). | Keep. It asks nothing of the user and belongs to PAD observability, not consent. |

“Gesture required” is a separate service-policy decision and remains useful. Elevation services default on, polkit/app consent defaults on while its global switch is enabled, and credential release defaults off but can be opted in or overridden per service (`crates/irlume-common/src/config.rs:351-429`, `469-511`; `crates/irlume-auth/src/lib.rs:576-612`). Head-only changes **which gesture satisfies** a required gate, not which services require the gate.

## Current active contract and runtime reachability

### Service and purpose selection

`AuthenticationPurpose::demands_gesture` is the authorization choke point: elevation-class `Verify` uses the per-service value or the elevation default, `AppConsent` defaults on, and credential release uses `service_gesture.credential_release` over its default-off global flag (`crates/irlume-auth/src/lib.rs:531-612`). Authentication acquires one camera-operation lease, runs one early consent watch before capture/matching, terminates immediately on a pre-match shake, and later applies the remaining watch budget immediately before grant (`crates/irlume-auth/src/lib.rs:4678-4722`, `4447-4474`).

The user-visible service surfaces are not identical. The TUI exposes toggles for sudo, su, doas and polkit plus a separate credential-release toggle; greeter and lock-screen services are not direct entries in that picker (`crates/irlume-cli/src/tui.rs:141-151`, `4932-4979`, `5030-5072`). This policy UI remains, with nod/shake wording only.

### Relevant history and why it matters

The repository history contains three separate eye-feature lines:

1. [`6fe99dfa40ab46aa4c1a0164c4842ce64fbbfa30`](https://github.com/archledger/irlume/commit/6fe99dfa40ab46aa4c1a0164c4842ce64fbbfa30) (2026-06-28) introduced the per-user `require_eyes_open` field, IR-glint evaluator, daemon request and profiles UI.
2. [`8a44482c48048d5a613c5d9c2e94071838eab358`](https://github.com/archledger/irlume/commit/8a44482c48048d5a613c5d9c2e94071838eab358) (2026-07-01) introduced the separate opt-in `require_challenge` blink gate; [`a8d839d67dfca08dad0f44feedab7f6feb426d72`](https://github.com/archledger/irlume/commit/a8d839d67dfca08dad0f44feedab7f6feb426d72) changed it to passive natural-blink EAR detection.
3. The consent-gesture series around [`9437934241398ec28040e18d55294742d4ab498a`](https://github.com/archledger/irlume/commit/9437934241398ec28040e18d55294742d4ab498a) and release [`76874ecf1411aa7aa815d1868b8d84f3a0aa1129`](https://github.com/archledger/irlume/commit/76874ecf1411aa7aa815d1868b8d84f3a0aa1129) (2026-07-22/23) added nod plus deliberate held closure, the stored `closure_calibration`, and its IPC/CLI setup. [`795e5478ac4e400be11eeb7dcfe95e2ae3d48a34`](https://github.com/archledger/irlume/commit/795e5478ac4e400be11eeb7dcfe95e2ae3d48a34), [`03321771bcf6f4f15dd1da8dee001cf20e0ec759`](https://github.com/archledger/irlume/commit/03321771bcf6f4f15dd1da8dee001cf20e0ec759), and [`91842092d077b843f53ad1ead286e1e41c6eeef9`](https://github.com/archledger/irlume/commit/91842092d077b843f53ad1ead286e1e41c6eeef9) subsequently added multi-round calibration, measure-only capture, and the light/eyewear warning.

The later retirements were partial. [`92c7b8b892fc59995e9644ce8d5a2a4641bd0c2d`](https://github.com/archledger/irlume/commit/92c7b8b892fc59995e9644ce8d5a2a4641bd0c2d) refused new eyes-open enables after the committed corpus admitted only 1 of 72 genuine detected frames, but deliberately kept OFF for legacy users. [`ae352ff4d8138d7d9a2dff3ff569f04ddfa970a5`](https://github.com/archledger/irlume/commit/ae352ff4d8138d7d9a2dff3ff569f04ddfa970a5) stopped enforcing the natural-blink gate and added shake; [`c458e3cdad7ea9beef83637970e5940d52920da4`](https://github.com/archledger/irlume/commit/c458e3cdad7ea9beef83637970e5940d52920da4) then removed `require_challenge` end to end. Neither removed deliberate closure or the stored/enforced eyes-open flag. [`37c254cbad79c5e367d633e520eb01210065986c`](https://github.com/archledger/irlume/commit/37c254cbad79c5e367d633e520eb01210065986c) shipped the present per-service nod/shake policy and polkit abort semantics.

The current issue-173 series ([`b96cdaa`](https://github.com/archledger/irlume/commit/b96cdaa859294e500574185c4f83a188f33e6de2)..[`f94ca363`](https://github.com/archledger/irlume/commit/f94ca363d3638712ad9d707a273f6236415e2a62), plus local `39c4e44eaba19e2431e640734875f86356718008`) is research, pure selector logic, and developer-only shadow reporting. It never writes enrollment or changes an authorization verdict (`crates/irlume-cli/src/blinkcap.rs:4-39`; `docs/research/2026-08-18-issue-173-closure-calibration-profiles.md:1-35`). Its code may be removed, while its note and commit history should remain as the evidence that closure-profile selection was intentionally abandoned rather than silently lost.

### Gesture detection

The head signal is derived from the primary detector's five landmarks and does not require FaceMesh (`crates/irlume-auth/src/lib.rs:4110-4144`; `crates/irlume-liveness/src/lib.rs:986-1003`). `detect_nod_with_evidence` classifies shake-shaped yaw before nod-shaped pitch so motion in the overlapping yaw band can never approve; it requires enough face frames, then returns `Shake`, `Nod`, `None`, or `NoFace` (`crates/irlume-liveness/src/lib.rs:1212-1368`). The current prompt says “keep nodding” because continuous nodding was the hardware-validated usable behavior even though the algorithm's minimum crossing count is one (`crates/irlume-common/src/config.rs:541-578`; `crates/irlume-liveness/src/lib.rs:1019-1075`).

The combined watch currently computes an EAR sample on every frame whenever FaceMesh is loaded, even if the configured mode is nod-only (`crates/irlume-auth/src/lib.rs:4147-4201`). Every sixth pose it checks nod/shake when nod is permitted, then checks deliberate closure if a calibration exists (`crates/irlume-auth/src/lib.rs:4287-4357`). Head-only should make this path pose-only: no `EarSample` allocation, no FaceMesh run, no closure calibration input, and no `BlinkResult` in the grant path.

### Face match and automatic liveness still follow consent

An early nod never bypasses face or PAD. The watch only records consent; capture, liveness, and matching still run under the same authentication before `challenge_if_required` returns the successful outcome (`crates/irlume-auth/src/lib.rs:4691-4722`, `4965-5012`). The hard IR gate requires an RGB face, an IR face, cross-spectrum alignment, frontality, measurable exposure, IR reflectance, and center/edge falloff before returning `Live`; glint is recorded as supporting evidence (`crates/irlume-liveness/src/lib.rs:502-595`). The optional third-party PAD can only downgrade an existing result to `Spoof` (`crates/irlume-auth/src/lib.rs:3895-3932`). These protections must not be deleted or described as supplied by nod/shake.

## Exhaustive removal and compatibility inventory

### 1. Authentication and liveness code

| Location | Current responsibility | Required change |
|---|---|---|
| `crates/irlume-auth/src/lib.rs:71-79` | `Engine.mesh` is documented as blink/closure plus rescue alignment. | Keep the field for rescue alignment; rewrite the contract. |
| `crates/irlume-auth/src/lib.rs:477-509` | Completed take accepts nod or closure and reduces the result to bool. | Replace with a typed head verdict; evaluate both nod and shake at the boundary. |
| `crates/irlume-auth/src/lib.rs:718-735` | Maps `ConsentGesture` to `(allow_nod, allow_closure)`. | Remove from the runtime path; only a transitional legacy-config decoder may remain. |
| `crates/irlume-auth/src/lib.rs:4012-4079` | Production-dead natural-blink runner and EAR capture. | Remove if no developer research consumer remains; it is not an active PAD protection. |
| `crates/irlume-auth/src/lib.rs:4110-4201` | Separate pose capture plus combined pose/EAR frame conversion. | Retain pose capture; replace combined conversion with pose-only consent sampling. |
| `crates/irlume-auth/src/lib.rs:4229-4272` | Early watch derives closure calibration from the enrollment. | Remove enrollment input and calibration construction. |
| `crates/irlume-auth/src/lib.rs:4281-4444` | Rolling combined nod/shake/closure watch. | Make it head-only and return a typed verdict. Preserve per-frame cancellation and evidence logging. |
| `crates/irlume-auth/src/lib.rs:4488-4568` | Grant gate documents and messages `Nod`, `Closure`, `Either`, `Misconfigured`. | Collapse supported behavior to nod approval/shake decline. Keep a separate fail-closed legacy-config refusal during migration. |
| `crates/irlume-auth/src/lib.rs:4968-5019`, `6973-7070` | Computes and enforces the `require_eyes_open` heuristic. | Remove `Assessment.eyes_open`, `eyes_open_from_capture`, `both_eyes_open`, helper constants, and their tests after legacy true-state handling is settled. |
| `crates/irlume-liveness/src/lib.rs:842-983`, `1438-1828` | EAR sample type and natural-blink detector. | Not production reachable. Delete if the eye research tools retire; otherwise isolate under a clearly research-only module/feature and do not call it protection. |
| `crates/irlume-liveness/src/lib.rs:1832-2108` | Closure-profile shadow types, `ClosureCalibration`, deliberate-closure detector, calibration median, and closure env overrides. | Remove from the production library when the corresponding developer selector is retired; at minimum remove every auth caller and the two closure env knobs. |
| `crates/irlume-liveness/src/lib.rs:986-1438` | Pose sample, nod/shake classifier, thresholds and evidence. | Keep. Prefer renaming the public classifier to `detect_head_gesture`; a compatibility wrapper is optional. |

Tests that should remain and grow are the head-gesture negatives and terminality tests: deliberate nod, stillness, look-around, look-down drift, too-few frames, shake-with-vertical-motion never becoming nod, still drift not becoming shake, wide/vigorous shake decline, and look-around outside the shake band (`crates/irlume-liveness/src/lib.rs:2577-2627`, `3517-3655`). Tests devoted to closure profiles, held closure, natural blink and eyes-open enforcement become deletion tests or move with any deliberately retained research-only module (`crates/irlume-liveness/src/lib.rs:3051-3473`; `crates/irlume-auth/src/lib.rs:9390-9588`, `10803-10810`, `11121-11146`).

### 2. Configuration and environment

Current accepted-method selection is `consent_gesture=nod|closure`, `IRLUME_CONSENT_GESTURE`, or absent=`Either`; malformed values enable neither (`crates/irlume-common/src/config.rs:582-632`). The closure-specific runtime knobs are `IRLUME_CONSENT_CLOSURE_FRAMES` and `IRLUME_CONSENT_CLOSURE_MAX` (`crates/irlume-liveness/src/lib.rs:2059-2108`). The natural-blink-only knobs are `IRLUME_BLINK_MOTION_MAX`, `IRLUME_BLINK_CONTRAST_DROP`, and `IRLUME_BLINK_CONTRAST_MOTION_FLOOR` (`crates/irlume-liveness/src/lib.rs:1572-1606`).

Disposition:

- keep `service_gesture.*`, `polkit_gesture` / `IRLUME_POLKIT_GESTURE`, and `credential_release_challenge` / `IRLUME_CREDENTIAL_RELEASE_CHALLENGE`; they decide whether a consent gate exists, not its accepted physical action (`crates/irlume-common/src/config.rs:351-429`, `469-511`);
- keep `IRLUME_CONSENT_MAX_FRAMES`, `IRLUME_NOD_PITCH_MIN`, all `IRLUME_SHAKE_*` thresholds, and `IRLUME_DUMP_POSE_SERIES`; they govern or diagnose the head watch (`crates/irlume-auth/src/lib.rs:4204-4214`, `4397-4408`; `crates/irlume-liveness/src/lib.rs:1403-1438`);
- retire the two closure and three blink threshold variables when their last developer-only caller is removed; remove them from validation-table tests and `docs/DEBUGGING.md` (`crates/irlume-liveness/src/lib.rs:2323-2382`; `docs/DEBUGGING.md:212-227`);
- keep `IRLUME_MESH_MODEL`; it remains required for BlazeFace rescue alignment even after no consent path consumes EAR (`crates/irlume-auth/src/lib.rs:2807-2845`; `packaging/systemd/irlumed.service:19-23`).

For `consent_gesture`, the compatibility decoder should have three outcomes during the transition:

| Input | Transitional result |
|---|---|
| absent or `nod` | head-only gate enabled |
| `closure` | no gesture accepted; actionable message says the removed policy must be changed explicitly to `nod` or the key removed |
| any other value | no gesture accepted, as today |

Do not map `closure` to nod silently. The current code's own safety rationale says `Nod` and `Closure` are incomparable policies and an unreadable value must not fall back to a wider set (`crates/irlume-common/src/config.rs:529-537`, `586-624`). After one deprecation cycle and migration telemetry/support, the accepted-method key and enum can disappear entirely because nod is no longer a choice.

### 3. Enrollment storage and serialization

The active store is JSON, not RON. `irlume-core` depends on `serde_json`, the workspace has no RON dependency, and both plaintext enrollment and the decrypted inner payload of an encrypted enrollment use `serde_json` (`Cargo.toml:65-66`; `crates/irlume-core/Cargo.toml:7-12`; `crates/irlume-core/src/storage.rs:533-595`). “RON compatibility” is therefore a negative finding: no enrollment RON reader, writer, fixture, or migration exists in this tree.

`Enrollment` carries both `require_eyes_open: bool` and `closure_calibration: Option<(f32,f32)>`, each with `#[serde(default)]` (`crates/irlume-core/src/storage.rs:174-195`). Old files missing the fields load with false/None, and new code that removes the Rust fields can ignore those unknown JSON members because these types do not use `deny_unknown_fields`; this is Serde's documented default, while `#[serde(default)]` supplies a value for a missing field ([Serde container attributes](https://serde.rs/container-attrs.html#deny_unknown_fields), [Serde field attributes](https://serde.rs/field-attrs.html#default)). The repository tests the same forward-unknown-field rule on its wire types and uses it in upgrade design (`crates/irlume-common/src/lib.rs:457-465`, `1429-1451`). The encrypted envelope version is informational and the loader detects encryption from `enc`, decrypts, then deserializes the same inner JSON, so removing fields does not require an envelope-version bump (`crates/irlume-core/src/storage.rs:514-531`, `559-594`).

RON's own documented limitations do not alter this result because no RON value crosses irlume's storage or socket boundaries ([RON documentation](https://docs.rs/ron/latest/ron/index.html#limitations)). If a future format did serialize these enums through Serde, removing a named enum variant would still be incompatible with input that names it: Serde exposes unknown variants as deserialization errors ([Serde `unknown_variant`](https://docs.rs/serde/latest/serde/de/trait.Error.html#method.unknown_variant)). Do not infer enum-variant safety from the compatible removal of named struct fields.

Compatibility consequences:

- old file -> new binary: removed members are ignored;
- new save -> old binary: missing members default to false/None because the old struct already annotated them with `#[serde(default)]` (`crates/irlume-core/src/storage.rs:179-194`);
- rollback after a new save therefore loses closure calibration and clears require-eyes-open, but preserves face templates and camera binding; this loss is intentional retirement and must be release-noted;
- lazy rewrite on the next unrelated enrollment mutation removes deprecated eye data naturally; an eager privacy cleanup requires loading/decrypting and durably rewriting every enrollment, which is much riskier and not necessary for authorization safety (`crates/irlume-core/src/storage.rs:608-645`).

Add explicit plaintext and encrypted bidirectional tests rather than relying only on general Serde behavior: deserialize old JSON with both fields into the new type; serialize the new type and deserialize into a local legacy type with defaults; repeat through `serialize_enrollment`/`deserialize_enrollment` with a generated key. Existing storage tests already provide the pure encrypted/plaintext seams (`crates/irlume-core/src/storage.rs:1054-1097`).

Legacy `require_eyes_open=true` needs a product decision before deleting its field. Recommended: a transitional release continues reading it only as a **legacy policy blocker**, denies face grant with an actionable “run `profiles eyes-open off`” message, and retains the OFF request. It must not run the broken eye detector and it must not silently grant. After the user clears it, later saves erase the field. Password/fingerprint fallback remains available through PAM (`crates/irlume-pam/src/lib.rs:354-360`).

### 4. Daemon IPC and mixed versions

The newline-JSON daemon protocol uses externally tagged `Request` and `Response` enums (`crates/irlume-common/src/lib.rs:398-400`, `763-765`). Eye-specific messages are:

- `Request::SetRequireEyesOpen`, `CaptureEarMedian`, `SetClosureCalibration` (`crates/irlume-common/src/lib.rs:503-516`);
- `Response::Enrollment.require_eyes_open`, `closure_calibrated`, and `Response::EarMedian` (`crates/irlume-common/src/lib.rs:833-849`, `948-951`);
- daemon posture, arbiter classification, diagnostics classification, dispatch arms, enrollment-summary fields and tests (`crates/irlume-daemon/src/main.rs:2333-2451`, `2595-2658`, `3176-3217`, `4227-4256`; `crates/irlume-daemon/src/arbiter.rs:81-138`).

Keep one-release request tombstones. An old CLI can run during or after package replacement and still send these variants. Removing an enum variant makes deserialization fail before dispatch, producing only “bad request”; retaining it allows a precise and permission-preserving response. Suggested behavior:

- `SetRequireEyesOpen { on:false }`: idempotent success and clear legacy state while that field is still read;
- `SetRequireEyesOpen { on:true }`: explicit retired/unsupported error;
- `CaptureEarMedian` and `SetClosureCalibration`: explicit retired/unsupported error, never fire the camera or write state;
- keep their existing privilege classification during the tombstone period so retirement does not accidentally expose a new unauthenticated oracle (`crates/irlume-daemon/src/main.rs:2338-2451`).

`Response::Enrollment.require_eyes_open` is more subtle than storage. It has **no** `#[serde(default)]`, so an old client cannot decode a new daemon reply that omits it; `closure_calibrated` does have a default and may be omitted safely for current clients (`crates/irlume-common/src/lib.rs:833-848`). Keep the internal response member and always emit false until the supported mixed-version window has passed. The repository explicitly treats old daemon/new client and new daemon/old client as normal during package upgrades (`crates/irlume-common/src/lib.rs:1403-1451`).

This is a demonstrated failure class, not a theoretical one: the 0.10.0 upgrade notes say a running 0.9.0 TUI could not parse the new daemon's `Enrollment` reply after `require_challenge` was removed without a default (`CHANGELOG.md:428-433`). Removing a request enum variant likewise becomes the generic `ReadOutcome::Bad` before authorization/dispatch because `read_request` directly deserializes `Request` (`crates/irlume-daemon/src/main.rs:2238-2265`).

The machine API has an independent public-version constraint. Contract 1 requires `require_eyes_open` and `require_challenge` in `profiles.list` (`schemas/machine-api-v1.schema.json:479-548`). Keep both and emit false; remove them only in contract 2. This exactly follows the repaired `require_challenge=false` precedent (`crates/irlume-cli/src/machine.rs:2293-2303`; `docs/MACHINE-API.md:335-346`). Update the fixture but keep both fields false (`schemas/fixtures/v1/profiles-list.json:1`).

Packaging already attempts to restart a running daemon on Debian/Ubuntu and Arch upgrades, and Fedora delegates restart-on-upgrade to its systemd macros, but the shell calls are best-effort and a stopped daemon is intentionally not started; source-level mixed-version handling is still required (`packaging/debian/postinstall.sh:19-25`, `57-61`; `packaging/arch/irlume.install:32-42`; `packaging/fedora/irlume.spec:181-186`). The CLI/TUI should continue comparing the health-reported daemon version with their own version rather than assuming package replacement restarted it (`crates/irlume-common/src/lib.rs:899-913`). Add lane tests for Debian/nfpm/PPA, Fedora, Arch and NixOS activation so every supported upgrade actually replaces the authorization engine before it claims head-only.

### 5. CLI, TUI, doctor, PAM and machine API

Remove or change these active user surfaces:

- normal CLI dispatch, help, `profiles eyes-open`, `calibrate-closure`, measure-only mode, overwrite confirmation, threshold feedback, and associated tests (`crates/irlume-cli/src/main.rs:17-18`, `226`, `384-515`, `720-1085`; `crates/irlume-cli/src/commands.rs:2142-2154`);
- `status` enrollment suffix, doctor closure-calibration query and closure-mode branches (`crates/irlume-cli/src/commands.rs:701-721`; `crates/irlume-cli/src/main.rs:4800-4876`);
- PAM-wiring completion text that advertises calibration (`crates/irlume-cli/src/pamwire.rs:1393-1407`);
- TUI `CalibrateClosure` suspend/action, PAM-tab `[c]`, closure-mode row, Settings eyes-open section/toggle, dashboard eyes-open status, and their tests (`crates/irlume-cli/src/tui.rs:276-278`, `3646-3703`, `5003-5028`, `6415-6457`, `6525-6539`);
- machine `profiles_data` input/output plumbing for the real enrollment value, while continuing to emit contract-1 `require_eyes_open:false` and `require_challenge:false` (`crates/irlume-cli/src/machine.rs:2040-2075`, `2246-2303`);
- PAM mode-dependent approval text. The new text is unconditional head semantics: keep nodding to approve; shake to decline. Remove closure-only suppression of the shake clause (`crates/irlume-pam/src/lib.rs:273-323`, `345-350`);
- PAM tests for closure-mode messaging; retain and strengthen tests for polkit shake abort versus non-polkit/password fallback (`crates/irlume-pam/tests/pamwrap.rs:486-563`, `567-650`).

Keep `Response::AuthResult.declined_by_gesture`, machine `refusal:"declined"`, and their compatibility defaults. They are the typed head-shake contract and are independent of closure (`crates/irlume-common/src/lib.rs:784-792`; `crates/irlume-cli/src/machine.rs:1957-1985`; `docs/MACHINE-API.md:459-477`).

The PAM control must also remain. The polkit line expands `sufficient` with `abort=die`, so only the module's deliberate polkit shake result terminates the stack while success grants and ordinary failures continue to password (`crates/irlume-cli/src/pamwire/stanzas.rs:85-116`). Upstream Linux-PAM defines `sufficient` as `[success=done new_authtok_reqd=done default=ignore]`, `ignore` as contributing nothing, and `die` as immediately terminating the stack ([Linux-PAM configuration syntax](https://github.com/linux-pam/linux-pam/blob/master/doc/man/pam.conf-syntax.xml)). Simplifying this stanza during eye-feature removal would weaken shake decline, not remove closure.

### 6. Developer tools, scripts and examples

`blinkcap` is gated by `IRLUME_DEV=1`, but it is executable code rather than a dated record. It supports both EAR/closure selection and pose replay under a blink-named command (`crates/irlume-cli/src/main.rs:71-91`, `123-157`; `crates/irlume-cli/src/blinkcap.rs:1-39`). The current issue-173 selector is shadow-only and never writes enrollment or changes authorization, but leaving an active closure selector after product retirement invites it back into the grant path.

Recommended disposition:

- extract the pose capture/replay pieces into a clearly named head-only `gesturecap`/`posecap`, or rely on `crates/irlume-auth/examples/gesture_calibrate.rs`; keep pose-corpus tests (`crates/irlume-cli/tests/cli.rs:2502-2570`);
- remove the closure-profile selector, EAR capture/replay, selector tests and the active `blinkcap-campaign.sh` entrypoint (`crates/irlume-cli/tests/cli.rs:2035-2500`; `scripts/research/blinkcap-campaign.sh:1-93`);
- retire or archive `scripts/deploy-passive-ear.sh`, whose stated purpose is deploying the already-retired passive-EAR build (`scripts/deploy-passive-ear.sh:1-42`; `scripts/README.md:44-45`);
- decide whether `meshprobe` remains as a pure mesh/rescue diagnostic. Its passive-blink verdict mode and loopback test are not head-only (`crates/irlume-cli/src/main.rs:2806-2955`; `crates/irlume-cli/tests/cli_capture.rs:251-305`), but a landmark-validity probe remains useful because FaceMesh still refines rescue boxes;
- keep `landmark_failure_probe` portions that test general landmark geometry and rescue safety; remove or mark historical the EAR-only portions (`crates/irlume-auth/examples/landmark_failure_probe.rs:1-28`);
- archive `blendshapes_probe` and the raw blink-corpus capture script if reproducibility policy requires executable instruments, otherwise retain only their dated results and hashes (`crates/irlume-auth/examples/blendshapes_probe.rs:1-24`; `scripts/research/capture-blink-corpus.sh:1-14`).

The generic camera sequence API may remain because pose diagnostics use it, but its comments must stop promising eye-closure calibration (`crates/irlume-camera/src/lib.rs:5802-5819`). If no EAR consumer remains, remove `mesh_min_ear`, `eye_ear`, EAR landmark constants, and public re-exports from `irlume-vision`; retain the general `FaceMesh::landmarks` API used by rescue alignment (`crates/irlume-vision/src/lib.rs:845-864`, `962-983`, `1617-1620`; `crates/irlume-auth/src/lib.rs:2807-2841`).

### 7. Models, dependencies and packaging

No dependency can be removed merely because closure is retired. FaceMesh and the TFLite runtime remain in the shipped graph because BlazeFace rescue boxes are deliberately not aligned from BlazeFace's coarse keypoints; FaceMesh refines them to five alignment points (`crates/irlume-auth/src/lib.rs:2807-2841`). FHS packages install the TFLite mesh/runtime and Nix currently uses the ONNX mesh conversion (`packaging/fedora/irlume.spec:116-142`; `packaging/arch/PKGBUILD:67-92`; `nix/package.nix:43-61`; `nix/module.nix:284-297`). `irlume-liveness` also remains because it owns both PAD and head-gesture classification (`Cargo.toml:57-63`; `crates/irlume-liveness/src/lib.rs:4-11`, `986-1438`).

Update current packaging/model descriptions that say the mesh supplies passive liveness or closure, but preserve historical package changelog entries. Direct current-description sites include `models/README.md:18-31`, `79`; `packaging/arch/PKGBUILD:67-74`; `nix/module.nix:288-293`; daemon startup/degradation messages (`crates/irlume-daemon/src/main.rs:552-580`, `611-625`); and TUI model health (`crates/irlume-cli/src/tui.rs:1548-1573`). The systemd `IRLUME_MESH_MODEL` line and model/runtime files remain (`packaging/systemd/irlumed.service:19-23`).

Secondary source contracts and tests also need deliberate cleanup rather than being left semantically stale:

| Location | Action |
|---|---|
| `crates/irlume-common/src/lib.rs:899-913` | Change `Health.mesh` documentation from passive-blink model to landmark/rescue model; retain the field for mixed versions and health reporting. |
| `crates/irlume-common/src/thirdparty.rs:110-138` | Keep the landmark stage closed, but replace the eye-cue rationale with the stronger surviving risk: bad dense landmarks feed grant-capable rescue alignment. |
| `crates/irlume-core/src/biopolicy.rs:34-52` | Replace the stale “forced passive-liveness blink gate” AppConsent comment with deliberate head consent. |
| `crates/irlume-camera/src/lib.rs:5802-5819` | Keep the generic sequence capture if head diagnostics use it; remove EAR/closure/blink claims. |
| `crates/irlume-vision/src/lib.rs:651-870`, `962-983`, `1617-1620` | Keep FaceMesh landmarks for rescue; remove EAR helpers/re-exports only if all eye research consumers retire. |
| `crates/irlume-cli/src/commands.rs:1580-1591`, `1709-1717` | Remove “expected nod or closure” diagnostics and make required-gesture status head-only while preserving service enable/disable. |
| `crates/irlume-cli/tests/cli.rs:1560-1610`, `2035-2570`; `crates/irlume-cli/tests/cli_dispatch.rs:230-270`; `crates/irlume-cli/tests/cli_capture.rs:251-305` | Replace eyes-open/closure fixtures and selectors, retain pose replay and unrelated profile/status coverage. |
| `crates/irlume-daemon/src/main.rs:5750-5770`, `8404-8565`; `crates/irlume-daemon/src/arbiter.rs:81-138` | Update exhaustive request fixtures/classifiers for tombstones, then remove them only after the compatibility window. |
| `crates/irlume-common/src/config.rs:730-790`, `1344-1386`; `crates/irlume-auth/src/lib.rs:7417-7490`, `10582-10646` | Replace mode-matrix tests with absent/nod/legacy-closure fail-closed tests, then delete the transitional parser tests in the later release. |
| `crates/irlume-core/src/storage.rs:1010-1097`; `crates/irlume-common/src/lib.rs:1250-1310`, `1403-1451` | Add the explicit field-removal and old/new response probes described above; retain general compatibility tests. |

### 8. Current documentation versus historical evidence

Update current promises in:

- `docs/APP-INTEGRATION.md:22-82`, `160-179`;
- `docs/ARCHITECTURE.md:87-124`;
- `docs/COMMANDS.md:39-40`, `83-100`;
- `docs/DEBUGGING.md:212-227`;
- `docs/LIMITATIONS.md:22-31`;
- `docs/MACHINE-API.md:222-236`, `335-346` (while documenting the frozen false v1 field);
- `docs/SETUP.md:325-327`, `482-502`, `514`;
- `docs/THIRD-PARTY-MODELS.md:209-222`;
- the live-contract portions of `docs/THREAT_MODEL.md:163-212`, `280-344`;
- `docs/CREDITS.md:6-11` (the mesh still supplies rescue alignment, no longer closure);
- `models/README.md:18-31`, `59-79`; and
- `scripts/README.md:44-45`, `65-78`.

Keep dated research and history intact, with only a short supersession banner or cross-link if needed:

- `CHANGELOG.md` and packaging changelogs are release history, not current promises;
- `docs/adr/0002-challenge-response-liveness.md` is already marked superseded and should preserve the failed blink experiment; update only its top disposition, which still says infrastructure stays for require-eyes-open (`docs/adr/0002-challenge-response-liveness.md:3-15`);
- `docs/adr/0001-liveness-pad-strategy.md` and all `docs/pad-results/2026-06-30-*`, `2026-07-01-*`, `2026-08-05-*`, `2026-08-07-*` measurements remain evidence explaining why eye gates were retired. ADR-0001's 2026-06-30 follow-up direction still names eyes-open/blink scaffolding, so add a supersession note without rewriting the dated proposal (`docs/adr/0001-liveness-pad-strategy.md:70-95`);
- the issue-173 research notes and PR #501 shadow-selector history remain as evidence that the path was studied and then superseded, not as product instructions.

The precedent is commit [`c458e3cdad7ea9beef83637970e5940d52920da4`](https://github.com/archledger/irlume/commit/c458e3cdad7ea9beef83637970e5940d52920da4): it retired `require_challenge` end to end but explicitly left dated PAD results as history. Commit [`33aa696fa45067d01dda0c6c4638717ddf2028ef`](https://github.com/archledger/irlume/commit/33aa696fa45067d01dda0c6c4638717ddf2028ef) subsequently restored the required machine-contract key as a frozen false compatibility field. Apply both lessons here.

## Things that must remain

1. **The service-policy gate.** Per-service enable/disable and credential-release opt-in remain; head-only is not face-only (`crates/irlume-common/src/config.rs:376-511`).
2. **Nod approval and shake-first discrimination.** Shake-shaped yaw must remain terminal before the nod branch; a bobbing “no” may never grant (`crates/irlume-liveness/src/lib.rs:1282-1321`).
3. **Explicit decline propagation.** `OutcomeKind::GestureDeclined`, wire `declined_by_gesture`, polkit `PAM_ABORT`, and machine `refusal:"declined"` remain (`crates/irlume-auth/src/lib.rs:202-229`; `crates/irlume-common/src/lib.rs:784-792`; `crates/irlume-pam/src/lib.rs:744-782`).
4. **Password/fingerprint fallback.** Timeouts, no gesture, no face, and non-polkit declines remain non-locking PAM failures (`crates/irlume-pam/src/lib.rs:354-360`, `744-782`).
5. **Camera lease, cancellation and bounded watch.** The watch remains inside one authentication's camera-operation lease and checks stop state per frame (`crates/irlume-auth/src/lib.rs:4294-4313`, `4691-4722`).
6. **Automatic PAD and frontality.** Consent proves intent, not presentation resistance; the hard liveness gates remain (`crates/irlume-liveness/src/lib.rs:502-696`; `docs/FAQ.md:128-140`).
7. **Passive `ir_eye_glint`.** It remains a supporting automatic measurement; remove only the separate `both_eyes_open` policy evaluator (`crates/irlume-auth/src/lib.rs:3831-3889`, `6973-7070`).
8. **FaceMesh, its verified model and TFLite runtime.** Rescue alignment still consumes them (`crates/irlume-auth/src/lib.rs:2807-2841`; `packaging/systemd/irlumed.service:19-23`).
9. **Contract-1 compatibility fields.** Emit `require_eyes_open:false` and `require_challenge:false` until contract 2 (`schemas/machine-api-v1.schema.json:479-548`).
10. **Historical evidence.** Dated PAD/gesture measurements, ADR history and release notes explain security decisions and should not be rewritten as though the experiments never occurred.

## Migration strategy options

### Option A: one-shot deletion

Delete config modes, storage fields, IPC variants and UI in one release; treat every install as nod-only immediately.

Advantages: smallest final code and no prolonged compatibility layer.

Risks: silently widens `consent_gesture=closure`; old clients get protocol errors; old contract-1 consumers reject profiles JSON; legacy `require_eyes_open=true` is silently weakened; a stale old daemon can continue accepting closure while the new CLI claims head-only. This option is not recommended.

### Option B: staged fail-closed retirement (recommended)

Release N:

- remove EAR/closure/eyes-open from all grant decisions;
- absent/`nod` means head-only, but explicit `closure` or malformed selection makes required gesture gates fail closed with actionable diagnostics;
- retain request and response tombstones; accept only the eyes-open OFF cleanup operation;
- retain storage reads for legacy-state detection, but do not run the eye evaluator;
- freeze machine-contract fields false;
- remove normal eye setup UI and current documentation;
- emit one bounded, non-biometric diagnostic when legacy config/state blocks a face grant.

Release N+1 (after a documented support window):

- remove legacy request variants and internal response fields if no supported client needs them;
- remove storage fields and legacy blocker once upgrades have had a chance to clear them;
- publish machine contract 2 without the frozen fields;
- remove the transitional `consent_gesture` parser and its diagnostic.

This preserves the operator's old restrictive choice until they explicitly choose nod, while ensuring no eye action can grant.

### Option C: automatic rewrite

On upgrade or daemon start, rewrite `consent_gesture=closure` to `nod`, clear `require_eyes_open`, and strip calibration.

Advantages: users immediately get the target experience.

Risks: a package script or daemon startup mutates root-owned authorization policy and encrypted user state; failure can leave a partially migrated fleet; a rollback cannot restore the previous policy/calibration; a best-effort package script can lie about success. This is appropriate only with explicit owner approval and a transactional migration design, not as an incidental cleanup.

## Failure modes and required mitigations

| Failure | Consequence | Mitigation/test |
|---|---|---|
| `closure` silently maps to nod | Authorization policy widens. | Legacy config must fail closed until explicit migration. |
| Absent key remains interpreted as old `Either` in one caller | Closure can remain live through a missed branch. | Remove `ConsentGesture` from auth/PAM call sites; repository-wide no-caller assertion. |
| Completed-take shake is not typed | User's final-frame decline becomes a timeout/fallback rather than a deliberate decline. | Typed whole-take verdict and boundary tests for 1-5 trailing frames. |
| Shake check occurs after nod | A bobbing shake can approve in the yaw-overlap band. | Preserve classifier ordering and existing mutation-sensitive negative test (`crates/irlume-liveness/src/lib.rs:1282-1321`, `3517-3538`). |
| Closure detector remains in completed-take helper | A head turn's eye geometry can overturn or grant. | No `EarSample`, `ClosureCalibration`, or `BlinkResult` in the consent module. |
| Old CLI sends removed request | Opaque “bad request”, or a direct eye capture continues. | Tombstone variants that never capture/write and return explicit errors. |
| New daemon omits `Response::Enrollment.require_eyes_open` | Old CLI cannot deserialize profile listing. | Internal false tombstone; field lacks Serde default (`crates/irlume-common/src/lib.rs:833-841`). |
| Contract-1 removes required fields | Existing JSON-schema consumers reject output. | Freeze both false until contract 2 (`schemas/machine-api-v1.schema.json:479-548`). |
| Legacy `require_eyes_open=true` is ignored | Explicit per-user policy silently weakens. | Transitional blocker plus OFF cleanup, or an explicitly approved migration. |
| New CLI talks to stale old daemon | Closure remains accepted despite new UI/docs. | Package restart plus health-version mismatch warning; head-only acceptance must be verified at daemon version, not inferred from CLI version. |
| FaceMesh/model/runtime removed | BlazeFace rescue silently stops, harming detection availability. | Keep model/runtime and rescue-path integration tests. |
| `ir_eye_glint` removed with eyes-open code | Passive liveness observability regresses. | Separate unit tests and liveness trace assertions for the surviving cue. |
| Gesture called “liveness” in docs | Users/operators overestimate nod against prints. | Current docs must say consent/intent; PAD remains separate. |
| Developer closure tools remain presented as supported | Removed feature gets tuned or reintroduced accidentally. | Rename/extract pose tooling; archive eye tools and label research notes historical. |
| Stored calibration persists forever | Deprecated biometric-adjacent data remains unnecessarily. | Lazy removal on next save plus optional explicit cleanup command/report; avoid risky bulk rewrite by default. |
| PAM semantics unintentionally change | Shake could close sudo/login stacks or stop closing polkit. | Retain service-scoped integration tests through real pam_wrapper (`crates/irlume-pam/tests/pamwrap.rs:567-650`). |

## Test matrix

### Pure head classifier

- nod: repeated/continuous nod approves at ordinary and reclining pose;
- still face, single look-down-and-hold, slow pitch drift, look-around, too few frames: no approval;
- normal, wide and vigorous shakes: decline;
- shake plus vertical bob: decline or no gesture, never approval;
- threshold environment values: valid overrides take effect; NaN, infinity, zero/out-of-range and malformed values fall back loudly;
- strobe cadence and missing-frame indices do not inflate motion evidence (`crates/irlume-liveness/src/lib.rs:1212-1281`).

### Consent-watch state machine

- pre-match nod, post-match nod, and nod completed in each trailing position approve once;
- pre-match shake and post-match shake decline immediately;
- shake completed in each trailing position reports decline, never timeout or nod;
- cancellation/preemption stops streaming and never returns a gesture verdict;
- one request's approve/decline state is cleared before the next request;
- no gesture consumes only the configured total budget and falls back;
- no FaceMesh installed has no effect on nod/shake;
- no IR camera, camera busy and capture errors fail to password rather than weakening the gate.

### Policy and configuration

- elevation defaults on, polkit defaults on, ordinary greeter/lock defaults follow their existing policy, credential release defaults off;
- every per-service override still wins;
- absent and `nod` select head-only;
- legacy `closure` and malformed values fail closed and identify the exact key/source;
- no active path reads `closure_calibration`, `require_eyes_open`, closure thresholds or blink thresholds after the transition.

### Storage and migration

- old plaintext and encrypted enrollments with false/true eyes-open and valid/invalid closure tuples load without losing profiles;
- legacy true state takes the chosen blocker/migration path;
- new saves omit eye fields and deserialize in a local legacy type with false/None defaults;
- encrypted envelope and template-key binding stay unchanged;
- interrupted/failed save leaves the original enrollment intact, using the existing atomic-save tests.

### IPC and mixed versions

- old request JSON for all three eye variants still parses during the tombstone release;
- capture/set calibration never touches camera/storage and returns the retired error;
- eyes-open OFF is idempotent, ON is refused;
- old-client-shaped `Response::Enrollment` decodes from the new daemon because `require_eyes_open:false` remains;
- new clients decode old daemon replies with extra eye fields;
- unknown removed variants after the compatibility window produce a protocol error without daemon crash;
- new CLI/stale daemon and old CLI/new daemon are exercised explicitly.

### CLI/TUI/machine/PAM

- help and dispatch contain no normal eye/blink/calibration command;
- TUI has no eyes-open or calibration action and always names nod approval plus shake decline;
- doctor/status contain no closure readiness or calibration advice and report legacy blockers if applicable;
- contract-1 profiles fixture validates with both retired booleans false; contract 2 omits them;
- polkit prompt names nod and shake; polkit shake maps to `PAM_ABORT`; timeout/no-match maps to `PAM_IGNORE` and password fallback;
- sudo/login/lock shake remains the explicitly chosen soft-failure behavior;
- credential-release prompt is shown only when that gate is required.

### PAD/model regression

- full IR, dark IR-only, RGB-only convenience and third-party PAD tests remain unchanged;
- `ir_eye_glint` still appears in liveness cues/trace and remains supporting-only;
- FaceMesh plus BlazeFace rescue still produces refined alignment landmarks;
- daemon starts in degraded mode if mesh load fails, but docs now say rescue alignment is unavailable rather than implying a closure gate;
- packaging parity continues to ship mesh and TFLite runtime in every supported lane.

### Documentation and repository audit

- a case-insensitive repository scan for `closure`, `blink`, `eyes-open`, `EAR`, `ConsentGesture`, and retired IPC names is reviewed line by line;
- active docs/help contain only historical links or explicit retirement/migration language;
- dated research, ADR evidence and changelog claims remain intact;
- no source comment claims nod/shake is anti-spoof protection.

## Recommended implementation sequence

1. Record the product decision in a short ADR/addendum: head-only consent, service policies unchanged, exact legacy `closure` and legacy eyes-open behavior, and PAM meaning of decline.
2. Add mixed-version and storage migration tests first, including the contract-1 false tombstones and old-client `Response::Enrollment` shape.
3. Introduce a typed `HeadConsentVerdict` and refactor the current watch to pose-only while closure is still available behind a test-only comparison. Prove nod/shake and completed-take terminality.
4. Remove closure and eyes-open from grant decisions. Keep passive PAD/glint and FaceMesh rescue intact.
5. Add the transitional legacy config/state blocker and daemon request/response tombstones. Ensure tombstones cannot capture or mutate except eyes-open OFF cleanup.
6. Remove normal CLI/TUI calibration and eyes-open actions, closure doctor/status logic, closure PAM branches, and machine real-value plumbing. Keep v1 false fields.
7. Extract/rename pose developer tooling, then retire/archive EAR/closure tools, examples and scripts according to the reproducibility decision.
8. Remove unused closure/blink/EAR library code and environment knobs; run compiler-driven exhaustive-match cleanup through daemon posture, arbiter and diagnostics tables.
9. Update current docs, model/package descriptions and upgrade notes. Preserve dated evidence and changelogs with a supersession banner only.
10. Run the full workspace, ignored PAM wrapper tests, machine-API conformance, packaging parity, and real-camera head gesture matrix. Test new/old client-daemon pairs before release.
11. In a later contract/deprecation release, remove tombstone IPC members, storage legacy fields/blocker and contract-1-only fields only after the supported upgrade window closes.

## Open questions requiring owner decisions

1. Does “head shake cancels/declines” preserve today's scope—daemon attempt always denied, only polkit returns `PAM_ABORT`—or should shake abort every PAM stack? The latter is a separate and potentially lockout-affecting behavior change.
2. How should existing `consent_gesture=closure` be migrated: fail closed until manual edit (recommended), an explicit migration command, or an authorized automatic rewrite?
3. How should existing `require_eyes_open=true` be handled: transitional blocker plus OFF command (recommended), explicitly announced automatic clear, or immediate face-policy relaxation?
4. What mixed-version support window is promised? This determines how long request/response tombstones remain.
5. Is machine API contract 2 in scope for the same release, or should contract 1 alone continue with frozen false fields?
6. Must raw closure calibration be eagerly erased for privacy, or is lazy deletion on the next enrollment save sufficient?
7. Should research executables remain buildable behind a feature, move to an archive, or be removed while dated outputs/hashes remain?
8. Should `blinkcap --pose` become a supported `gesturecap` developer command, or is the existing `gesture_calibrate` example sufficient?
9. Should the public liveness classifier be renamed from `detect_nod` to `detect_head_gesture` now that it returns both nod and shake?
10. Does “repeated nod” mean the current continuous-nodding instruction with a one-crossing algorithm, or a new requirement for multiple complete nod cycles? Changing `NOD_MIN_CROSSINGS` is a detector policy change requiring fresh hardware evidence (`crates/irlume-liveness/src/lib.rs:1052-1075`).

## Verification performed for this report

- `cargo test --workspace --locked` passes at the inspected baseline (root audit, 2026-08-18).
- Focused probes passed locally: `cargo test -p irlume-core an_enrollment_written_before_keying --locked`, `cargo test -p irlume-common request_wire_compat_defaults_for_older_callers --locked`, and `cargo test -p irlume-common auth_result_without_declined_by_gesture_reads_false --locked`. Their source assertions are at `crates/irlume-core/src/storage.rs:926-940` and `crates/irlume-common/src/lib.rs:1652-1689`, `1280-1308`.
- The current storage loader, wire enums, machine schema/fixture, package restart scripts, all active gesture call sites, and relevant history from eyes-open introduction (`6fe99df`), polkit consent (`e1bd076`), passive blink (`8a44482`), deliberate nod/closure release (`76874ec`), eyes-open refusal (`92c7b8b`), blink retirement (`c458e3c`), head-shake addition (`ae352ff`), per-service gesture release (`37c254c`), contract repair (`33aa696`), and issue-173 shadow selector (`87be3e5`..`f94ca363`, local `39c4e44`) were inspected.
