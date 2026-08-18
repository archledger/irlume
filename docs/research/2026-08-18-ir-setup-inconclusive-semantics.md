# `ir-setup`: semantics when D1 is accepted but functional proof is inconclusive

Date: 2026-08-18

Issue: [#492](https://github.com/archledger/irlume/issues/492)

## Decision

When the camera advertises Microsoft Face Authentication D1, accepts a
standards-derived D1 `SET_CUR`, returns that exact value from `GET_CUR`, and is
then restored to its exact original value, but neither per-frame metadata nor
the optical experiment establishes that D1 took functional effect, the result
must be **inconclusive**.

It is not `unsupported`: the camera advertised D1 and accepted the D1 state. It
is not `unusable`: the observation did not establish a negative result. It is
not success: `ir-setup` has not established a configuration safe to persist and
reuse. The camera's compatibility state remains **unproven**.

The human CLI should:

- say which protocol facts succeeded;
- say that exact restoration was verified and no configuration was saved;
- say why the functional evidence was insufficient;
- explicitly say that this is not evidence that the control is unsupported or
  unusable;
- give a scene-specific retry instruction; and
- return nonzero status **1**.

Status 0 would tell shells and service automation that setup accomplished its
goal when it did not. Status 1 keeps the ordinary success predicate honest and
preserves irlume's current `0 = established`, `1 = not established`, `2 = bad
invocation` convention. The structured daemon/machine result—not a new process
status—is where `inconclusive` must remain distinct from an operational error.

## Scope and pinned artifacts

This is source and contract research, not a hardware run. The repository
behavior audited here is GitHub `main` at
[`715fd170983c9500e5fa25ff6374663909bcccb1`](https://github.com/archledger/irlume/commit/715fd170983c9500e5fa25ff6374663909bcccb1),
queried on 2026-08-18. Relevant Git blob IDs are:

| Artifact | Git blob |
|---|---|
| `crates/irlume-camera/src/ir_emitter.rs` | `9236123e03fad370265584b8226d410fc0fdc819` |
| `crates/irlume-camera/src/lib.rs` | `a5015a5d70c09858e5df31672a3ac066f253a86c` |
| `crates/irlume-camera/src/ir_metadata.rs` | `c08907cadd7412bfe4064dda48033eb8b36b7e29` |
| `crates/irlume-cli/src/main.rs` | `711525eb5df1af13f02b80c26d8cf4b69542a09b` |

Issue #492 had no comments when inspected. Its hardware measurements are
treated as project evidence reported by the issue, not as measurements repeated
for this note.

Primary external sources were restricted to Microsoft's camera contracts and
bring-up documentation, Linux kernel documentation and upstream source, POSIX,
and the GNU project's own CLI manual. The Microsoft UVC extension page was last
updated 2024-05-22; the face-auth DDI page was last updated 2023-02-27; the
public Hello bring-up guide was last updated 2021-12-15. Linux source links are
to upstream `master` as observed on the date above.

## Terminology verdict

| Term | Authority | What it establishes | What it does not establish |
|---|---|---|---|
| Face Authentication D1 | Microsoft-defined control mode | Alternative-frame illumination is the selected mode for a named IR streaming interface | That Linux received usable metadata, that photons reached the scene, or that irlume can authenticate |
| Successful `SET_CUR` | UVC control transaction | The request completed without an ioctl/device error | That the requested state became current or affected frames |
| Exact D1 `GET_CUR` readback | Microsoft control contract | The camera reports D1 as the current selected mode | Optical output, metadata delivery to Linux, or useful reflected signal |
| `MetadataId_FrameIllumination` | Microsoft standard-format frame metadata | The camera reports whether active illumination was on for that captured frame | Measured irradiance, reflected signal strength, emitter health, or scene suitability |
| `UVCM` | Linux V4L2 metadata format | Userspace can receive the complete Microsoft-style UVC payload metadata rather than only the standard UVC header | That every Microsoft camera embeds illumination metadata, that every kernel exposes it, or that every queued record arrives |
| Optical proof | irlume policy/experiment | Pixel observations changed in a repeatable way correlated with control state | Microsoft/USB conformance by itself |
| Inconclusive | irlume operation result | The safe experiment ended without enough evidence for success or a definitive negative | Permanent device incompatibility |

The important correction is grammatical as much as technical: **the operation
is inconclusive; the control is not thereby unusable**.

## The standards and OS layers are different contracts

The relevant path is:

```text
Microsoft FaceAuth XU capability and mode selection
        -> USB control transfer (SET_CUR / GET_CUR)
        -> camera firmware and IR streaming interface
        -> optional embedded Microsoft frame metadata
        -> Linux uvcvideo UVCM metadata node
        -> irlume timestamp/sequence correlation
        -> contract-level or optical proof policy
```

Windows has another possible path: a vendor Device MFT can attach the required
illumination metadata in the Windows capture stack. Linux cannot observe a
Windows Device MFT. Microsoft explicitly describes both a Device MFT and
firmware-carried metadata as ways to provide the illumination attribute in the
[UVC extensions](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5#22210-ir-torch-control).
Consequently, lack of an embedded record visible through Linux is not, by
itself, proof that a Windows Hello camera violates its Windows integration
contract.

This layer boundary rules out two tempting but incorrect conclusions:

1. A successful control write cannot be promoted to optical success.
2. Missing Linux metadata cannot be promoted to control failure.

## What Microsoft's D1 contract actually proves

### Capability and state

Microsoft assigns Face Authentication selector `0x06` to the Microsoft camera
control extension unit. For each IR streaming interface, `GET_MAX` identifies
whether D1 or D2 is supported; `GET_DEF`, `GET_CUR`, and `SET_CUR` select exactly
one of D0, D1, or D2. The control must not be implemented by a camera that is
not capable of face authentication. These are normative device declarations,
not scene measurements. See [Microsoft UVC Extensions, Face Authentication
Control](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5#2226-face-authentication-control).

Therefore, after irlume has validated the descriptor, the payload shape, D1
support, interface identities, and then obtained exact D1 readback, it may
truthfully report:

> The camera advertised D1 and reports D1 selected.

It may not replace that sentence with:

> The IR emitter works.

The first is device-reported control state. The second is a claim about
functional or physical effect that needs additional evidence.

### Expected streaming behavior

Microsoft's face-authentication DDI defines alternative-frame illumination as
a mode in which the IR strobe is expected to alternate off and on for captured
frames, with the mode represented on each sample. The alternative mode and the
background-subtraction mode are mutually exclusive. See
[`KSPROPERTY_CAMERACONTROL_EXTENDED_FACEAUTH_MODE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/ksproperty-cameracontrol-extended-faceauth-mode).

The public Windows Hello bring-up procedure follows that contract. It selects
the FaceAuth IR stream, sets the supported face-auth property, starts streaming,
and for alternative illumination checks illuminated/unilluminated frame-pair
metadata at the required delivered rate. It then stops streaming and unsets the
control. The procedure does **not** prescribe a fixed increase in mean image
brightness. See [Windows Hello Camera Driver Bring Up
Guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/windows-hello-camera-driver-bring-up-guide#hlk-tests-for-kscategory_sensor_camera-to-assist-driver-testing).

This does not prove that Microsoft's private certification contains no optical
tests. It proves only what the public guide contracts: the published bring-up
gate is mode, stream, rate, timestamp, and per-frame metadata oriented. There
is no primary-source basis for treating irlume's `+20` mean threshold as a
Microsoft requirement.

### What illumination metadata says

Microsoft defines a 16-byte `MetadataId_FrameIllumination` item. Bit 0 is set
when a frame was captured with illumination on and clear otherwise. The
corresponding Media Foundation attribute likewise says whether active IR
illumination was on for the frame. See the [standard-format metadata
definition](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5#222344-metadataid_frameillumination)
and
[`MF_CAPTURE_METADATA_FRAME_ILLUMINATION`](https://learn.microsoft.com/en-us/windows/win32/medfound/mf-capture-metadata-frame-illumination).

That is strong contract evidence when correlated with the correct video frame:
it can establish that the camera reports the expected D1 off/on pattern. It is
not a photodiode reading. A firmware defect could report `ON` while an LED is
failed, blocked, or too weak at the subject. Irlume's own runtime diagnosis
already preserves this distinction: its `LitButDark` arm says metadata reports
state, not optical output.

For user-facing wording, the honest proof labels are therefore:

- `contract-proven` for a control-correlated D1 metadata pattern;
- `optically-proven` for a sufficiently strong pixel-domain experiment; and
- `unproven` when neither is conclusive.

Do not call metadata-only evidence `optically proven`.

## What Linux can and cannot observe

### The usable path

The Linux metadata interface exposes non-image data on metadata capture nodes.
A supporting node reports `V4L2_CAP_META_CAPTURE`, and the buffer layout is
bound to a negotiated metadata format. See the [V4L2 Metadata
Interface](https://docs.kernel.org/userspace-api/media/v4l/dev-meta.html).

Ordinary `V4L2_META_FMT_UVC` (`UVCH`) retains only the standard 2--12-byte UVC
payload header. `V4L2_META_FMT_UVC_MSXU_1_5` (`UVCM`) uses the same V4L2 block
layout but retains all payload metadata, which is what makes the appended
Microsoft illumination item observable. See the kernel documentation for
[`UVCH`](https://docs.kernel.org/userspace-api/media/v4l/metafmt-uvc.html) and
[`UVCM`](https://docs.kernel.org/userspace-api/media/v4l/metafmt-uvc-msxu-1-5.html).

Current upstream `uvcvideo` looks for the Microsoft XU GUID, queries Microsoft
metadata selector 9, enables metadata when possible, and advertises `UVCM` only
when that detection succeeds. It still advertises `UVCH`. See
[`uvc_metadata.c`](https://github.com/torvalds/linux/blob/master/drivers/media/usb/uvc/uvc_metadata.c#L197-L266).

The repository already has an implementation of the userspace half. At the
pinned revision,
[`ir_metadata.rs`](https://github.com/archledger/irlume/blob/715fd170983c9500e5fa25ff6374663909bcccb1/crates/irlume-camera/src/ir_metadata.rs)
finds the paired metadata node, negotiates `UVCM`, parses
`MetadataId_FrameIllumination`, and correlates metadata to image timestamps.
The ordinary authentication capture path uses it. `ir-setup` does not: its
measurement closure still returns only the maximum decoded mean of eight
frames.

### Absence is not a negative result

There are several independent reasons for no usable illumination record:

- the distribution kernel predates `UVCM` support;
- the camera exposes no metadata node;
- the Microsoft metadata control is absent, disabled, or unavailable to the
  current kernel;
- the Windows integration supplies the attribute through a Device MFT rather
  than the USB payload;
- the camera embeds metadata but the userspace queue loses or cannot correlate
  a record; or
- the camera emits other Microsoft metadata but not the illumination item.

The kernel's `UVCH` documentation also permits dropping UVC header records for
buffer-space, usefulness, or rate-limiting reasons. A proof algorithm must use
sequence/timestamp correlation and tolerate a bounded number of missing
records; it must not treat one missing buffer as an `OFF` frame or as a device
failure.

Linux 6.17 documentation contains `UVCM`; older deployed kernels cannot be
assumed to do so. The portability rule is therefore:

> Metadata present and correlated can be positive evidence. Metadata absent,
> uncorrelated, or unavailable is an evidence gap.

## Current irlume behavior and the classification bug

At `715fd170`, setup computes the brightest decoded mean from a short burst. It
requires `after >= before + 20`, restores, and then requires the brightness to
fall by 20. The reversible transition is a useful causal structure, but the
fixed effect-size threshold is scene dependent. See
[`ir_emitter.rs` lines 3893--3923](https://github.com/archledger/irlume/blob/715fd170983c9500e5fa25ff6374663909bcccb1/crates/irlume-camera/src/ir_emitter.rs#L3893-L3923).

If the first delta is smaller than 20, setup returns `Attempt::NotUsable`. The
outer discovery loop folds that into `DiscoveryError::NoUsableControl`, whose
text says the unit advertises no usable emitter control. See
[`DiscoveryError`](https://github.com/archledger/irlume/blob/715fd170983c9500e5fa25ff6374663909bcccb1/crates/irlume-camera/src/ir_emitter.rs#L2469-L2533).
The daemon turns the error into `Response::Error`; `report_ok_response` prints
it to stderr and returns `ExitCode::FAILURE` (1). See
[`setup_ir_emitter`](https://github.com/archledger/irlume/blob/715fd170983c9500e5fa25ff6374663909bcccb1/crates/irlume-camera/src/lib.rs#L7429-L7561)
and the [CLI response mapping](https://github.com/archledger/irlume/blob/715fd170983c9500e5fa25ff6374663909bcccb1/crates/irlume-cli/src/main.rs#L608-L638).

The exit status is already safe. The classification and message are not. The
code turns `did not cross this scene-dependent threshold` into `the control is
not usable`, losing the stronger protocol facts it had just established.

### Four-device evidence and what it does—and does not—calibrate

The project's physical matrix contains four materially different cases:

| Device | Relevant evidence | Semantic consequence |
|---|---|---|
| ASUS 3277:0059 RGB/IR | Issue #492 reports correct derived D1 write and exact restoration, but setup measured only `48 -> 52` (`+4`). The configured production path then wrote/read D1 and delivered 120 frames with a much wider observed range. The repository's metadata reader also records this model as supplying per-frame illumination records. | The `+20` miss is inconclusive, not unusable. Metadata should be attempted before optical fallback. |
| NexiGo 3443:c803 RGB/IR | Issue #492 reports correct D1 write/restore with `2 -> 9` (`+7`); the production path wrote/read D1 and delivered 120 frames. The mostly empty/distant scene remained dim. The metadata reader records this model as supplying illumination records. | A weak/empty scene can hide a working transition; lowering the threshold blindly would trade false negatives for false positives. |
| Logitech BRIO 046d:085e RGB/IR | A 21-burst campaign measured a stable paired lit-minus-ambient differential around 36 after two warm-up bursts, with uncontrolled ambient light and one underpowered post-idle arm. See [the pinned BRIO cadence note](https://github.com/archledger/irlume/blob/715fd170983c9500e5fa25ff6374663909bcccb1/docs/research/2026-08-12-brio-emitter-cadence.md). | Alternating within-burst structure is more informative than one absolute before/after mean. The study is not a universal threshold calibration. |
| ThinkPad RGB-only camera | The #491/#496 hardware matrix found no Microsoft XU and no IR member on this device. See [PR #496](https://github.com/archledger/irlume/pull/496). | This is `Unsupported` from capability evidence; no optical experiment should run. |

The first two are direct counterexamples to `small delta => unusable`. The
BRIO run shows that warm-up and paired phase structure matter. The ThinkPad
shows why unsupported must remain a separate, pre-write result.

This is not enough data to choose a new universal numeric cutoff. It spans
only three IR implementations, scenes were not standardized, and the ASUS and
NexiGo issue measurements intentionally demonstrate poor optical targets.

## Evidence model: keep five axes separate

A single success/error boolean cannot express this operation safely. Preserve
these facts independently:

1. **Capability provenance**: Microsoft XU and selector advertised; D1 listed
   for the correct IR interface; payload structurally derived from current
   device answers.
2. **Control transaction**: original captured; D1 write completed; exact D1
   `GET_CUR` readback matched.
3. **Functional observation**: metadata pattern, optical correlation, negative
   evidence, or insufficient evidence.
4. **Restoration**: exact original read back, not merely a successful restore
   ioctl.
5. **Publication**: configuration durably saved, intentionally unnecessary, or
   not saved.

The scenario in this note is:

```text
capability = advertised_d1
transaction = accepted_and_read_back
functional_observation = insufficient
restoration = exact_original_confirmed
publication = not_saved
```

The only honest disposition is `Inconclusive`.

## Recommended typed contract

The names below are illustrative Rust, not an implementation requirement. The
important property is that the axes survive across the daemon protocol rather
than being formatted into one string too early.

```rust
enum IrSetupDisposition {
    Ready {
        control: EmitterControlRef,
        proof: D1Proof,
        publication: Publication,
    },
    Inconclusive {
        control: EmitterControlRef,
        protocol: ProtocolAcceptance,
        evidence_gap: EvidenceGap,
        restoration: Restoration,
        retry: RetryGuidance,
    },
    Unsupported {
        reason: UnsupportedReason,
    },
    Unusable {
        control: EmitterControlRef,
        reason: ConclusiveNegative,
        restoration: Restoration,
    },
    Failed {
        stage: SetupStage,
        error: SetupFailure,
        restoration: Restoration,
    },
}

enum D1Proof {
    DeviceDeclaredActiveDefault,
    MetadataAlternation {
        correlated: usize,
        lit: usize,
        dark: usize,
        missing: usize,
    },
    OpticalControlCorrelation {
        transitions: usize,
        effect_summary: RobustEffectSummary,
    },
}

enum EvidenceGap {
    MetadataUnavailableAndOpticalEffectTooWeak,
    MetadataInsufficient { correlated: usize, missing: usize },
    SceneUnsuitable(SceneReason),
    ExposureOrWarmupUnsettled,
    ConflictingMetadataAndPixels,
}

enum Restoration {
    NotNeeded,
    ExactOriginalConfirmed,
    PendingRecovery,
    Failed,
}

enum Publication {
    SavedDurably,
    NotNeededDeviceDefault,
}
```

`Ready` is the only ordinary configuration success. The existing
`ActiveByDeviceDefault` result fits `Ready` with
`DeviceDeclaredActiveDefault` and `NotNeededDeviceDefault`; this note does not
reopen the deliberate #490 policy for a device whose validated active value is
already its own default.

`Inconclusive` is allowed only when exact restoration is confirmed and no
configuration was published. If restoration cannot be verified, the result is
`Failed`, the durable recovery record remains authoritative, and retry guidance
must concern recovery—not scene positioning.

### Classification rules

| Observation | Disposition | Persist? | Exit |
|---|---|---:|---:|
| No Microsoft XU, selector absent, D1 not advertised, or only D2 is offered | `Unsupported` | no | 1 |
| D1 advertised; write/readback/restoration succeeded; metadata and optical evidence insufficient | `Inconclusive` | no | 1 |
| D1 advertised, but a properly powered experiment obtains affirmative, repeatable contradictory evidence under established prerequisites | `Unusable` | no | 1 |
| D1 proof obtained; final applied value read back; config committed | `Ready` | yes | 0 |
| Validated active device default, unchanged | `Ready` | unnecessary | 0 |
| Busy, privacy refusal, journal failure, query failure, stream failure, or unconfirmed restore | `Failed` | no | 1 |
| Invalid CLI invocation | usage error | no | 2 |

`Unusable` should be rare. A query transport failure is not conclusive proof of
permanent unusability; it belongs under `Failed`. Missing metadata is not
conclusive. A weak scene is not conclusive. Reserve `Unusable` for a defined,
repeatable contradiction after the test has first established that its
prerequisites and observation channel are adequate.

## CLI exit status and automation semantics

POSIX's process model uses zero to conventionally report successful
termination and warns applications not to return zero when they terminate
unsuccessfully. See POSIX
[`_Exit`/`_exit`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/_exit.html).
An inconclusive `ir-setup` has not achieved the requested postcondition: there
is no established reusable control and no saved configuration. Returning 0
would make all of these common patterns wrong:

```sh
sudo irlume ir-setup && sudo irlume login enable
if sudo irlume ir-setup; then enable_face_login; fi
set -e
sudo irlume ir-setup
```

Nonzero does not have to assert a permanent error. GNU `grep`, for example,
uses 1 for the valid negative outcome “no selected lines” and 2 for an actual
error. See the [GNU grep exit-status
contract](https://www.gnu.org/s/grep/manual/html_node/Exit-Status.html). The
material analogy is predicate semantics: status 0 means the requested predicate
was established; status 1 means it was not.

For irlume now:

- **0**: setup established `Ready`.
- **1**: setup did not establish `Ready`, including `Inconclusive`,
  `Unsupported`, `Unusable`, and `Failed`.
- **2**: malformed invocation.

Do not add an undocumented status 3 merely to encode `Inconclusive`. Existing
shell callers need only the success predicate, and a second nonzero number does
not carry the restoration, evidence, or retry facts automation actually needs.
Expose those through a typed daemon response and, if/when a stable machine CLI
is added, a versioned object such as:

```json
{
  "outcome": "inconclusive",
  "ready": false,
  "retryable": true,
  "protocol": "d1-accepted-readback",
  "restoration": "exact-original-confirmed",
  "configuration_saved": false,
  "evidence_gap": "metadata-unavailable-optical-effect-too-weak"
}
```

Automation must branch on `outcome`, not parse localized prose. A generic
shell sees nonzero and safely stops. An interactive installer can recognize
`inconclusive`, show positioning instructions, and offer one user-directed
retry. A headless service should not busy-loop: the missing prerequisite is
often a human/scene change, and repeating the same firmware transaction against
the same empty view adds risk without adding information.

## Operator message

The message must lead with the disposition and then state the safe facts. A
calibrated example is:

```text
[ir-setup] inconclusive: this camera advertised Microsoft Face Authentication
D1, accepted the device-derived D1 value, and read it back exactly. irlume then
restored the exact original value and verified the restoration. The available
frame metadata and image changes did not prove D1 illumination, so no emitter
configuration was saved. This does not show that the control is unsupported or
unusable. Put a nearby subject in the IR camera's view, keep the scene still,
make sure the privacy shutter is open, and retry `sudo irlume ir-setup`.
```

When known, replace the generic evidence sentence with a specific one:

- `Linux exposed no UVCM illumination metadata, and the optical change was too
  weak to classify.`
- `Only 2 of 16 video frames had correlated metadata; that is not enough to
  verify the D1 pattern.`
- `The scene was saturated/flat before the write, so brightness could not
  measure an additional reflection.`
- `Exposure was still changing across the reversal, so the observed delta
  could not be assigned to the control.`

The retry instruction intentionally gives no universal distance or brightness
number. None of the primary sources specifies one, and the local devices have
already shown wide scene-dependent means. Distance and optical thresholds must
come from a controlled empirical calibration, not from the Microsoft mode
number.

Ideally, scene guidance appears **before** the first optical measurement as
well as after an inconclusive result. Requiring an undocumented target and then
blaming the control when it is absent is the compatibility defect in #492.

## Calibrated limits for the optical fallback

The metadata-first path should not become metadata-only policy. When correlated
UVCM illumination records are unavailable, an optical fallback remains useful,
but it must answer a narrower question and preserve an inconclusive arm.

The following are engineering deductions from the contracts and the four-device
evidence, not requirements stated by Microsoft:

1. **Preflight the observation channel.** Refuse to classify a flat,
   near-black, saturated, empty/distant, or still-settling scene as a negative
   control result. Prompt for a nearby subject and a still scene first.
2. **Discard warm-up and in-flight frames.** The BRIO's first two bursts differed
   from its later stable paired differential. The current setup already drains
   frames after transitions; retain that invariant and calibrate the count per
   delivered-frame behavior rather than wall-clock sleep alone.
3. **Use repeated reversible transitions.** One `off -> D1 -> restore` triplet
   rejects some ambient drift but is still vulnerable to exposure movement.
   Multiple balanced transitions allow a median paired effect and a sign/
   consistency check.
4. **Prefer within-burst D1 periodicity.** D1 is an alternating-frame mode. A
   stable alternating component correlated with the selected mode is more
   specific than comparing only the maximum of two bursts.
5. **Use robust effects, not one absolute mean delta.** Record paired effect,
   dispersion, transition count, classified/missing metadata counts, exposure
   stability when available, and scene dynamic range. Do not silently lower
   `+20` to fit the ASUS and NexiGo examples.
6. **Require positive evidence for success, adequate prerequisites for a
   negative.** If the effect is below the success bound and the test lacks power
   to reject scene/exposure explanations, return `Inconclusive`. Only a
   separately calibrated negative test may return `Unusable`.
7. **Calibrate and validate out of sample.** Use all three IR cameras across
   controlled distances, targets, ambient levels, exposure states, and warm-up
   conditions; keep one session/device condition out of threshold selection.
   The RGB-only ThinkPad remains the no-write `Unsupported` control.

This policy preserves the existing safety invariants: journal before write,
re-read before forward write, stop on the first failed query/dequeue, exact
readback after every write, restore even when privacy changes, and publish only
after proof. Statistical sophistication must not weaken any of them.

## Known gaps and unresolved tensions

- **Metadata is device testimony.** Microsoft defines what it means, but it
  does not independently measure emitted or reflected power. Runtime dark-frame
  policy must continue to distinguish `metadata-lit` from `optically useful`.
- **Windows and Linux observability differ.** A Windows Device MFT can supply
  metadata Linux never sees. The public contracts do not provide a portable way
  for Linux to execute that transform.
- **Kernel version and queue behavior matter.** `UVCM` is recent relative to
  supported distributions, and metadata capture is a separate queue. Missing
  records need correlation and bounded-loss policy.
- **The public Hello guide is not the complete private HLK implementation.** It
  supports a metadata-oriented bring-up model and does not support the `+20`
  rule; it cannot prove that no unpublished optical certification exists.
- **No universal optical threshold is sourced.** The present device/scene data
  refutes the current classification but is insufficient to choose replacement
  constants.
- **`ActiveByDeviceDefault` has different assurance.** It is a deliberate
  device-declared ready state from #490, not metadata or optical proof. The
  typed result must retain that proof provenance rather than merging every
  status-0 path into “optically verified.”

## Implementation acceptance implied by the research

This note does not implement #492, but an implementation conforming to the
decision should demonstrate:

- a typed `Inconclusive` path retains D1 support, exact D1 readback, evidence
  gap, exact restoration, and `configuration_saved = false`;
- the path cannot render `unsupported`, `unusable`, `enabled`, or `saved`;
- human CLI output is on stderr and returns 1;
- structured consumers can distinguish inconclusive from unsupported,
  conclusive negative, and operational failure without parsing text;
- status 0 is impossible until the ready-state postcondition is established;
- metadata-present fixtures verify correlated D1 lit/dark behavior, tolerate a
  bounded missing first/occasional record, and reject mismatched stream
  provenance;
- metadata-absent fixtures fall back to optical evidence without treating
  absence as dark or unsupported;
- exposure/ambient drift and unsuitable-scene fixtures return inconclusive, not
  success or unusable;
- restore failure overrides inconclusive and retains the recovery journal;
- the physical matrix covers ASUS and NexiGo metadata and weak-scene cases,
  BRIO alternating behavior and warm-up, and the ThinkPad no-XU unsupported
  case.

## Final answer to the narrow question

For the exact scenario posed:

- **Device classification:** `D1 advertised and control-accepted; functional
  compatibility unproven`.
- **Operation outcome:** `Inconclusive`, retryable after an operator changes the
  scene; exact restoration verified; nothing saved.
- **Operator message:** report the successful D1 derivation/write/readback and
  exact restore, name the evidence gap, explicitly deny the inference
  “unusable,” and instruct the operator to put a nearby subject in view and
  retry.
- **CLI exit:** **1**, not 0. Keep 2 for invocation errors. Preserve the richer
  distinction in a typed daemon/machine response.

That contract is simultaneously honest about Microsoft's standard, Linux's
limited observation channel, the successful safety transaction, and the fact
that `ir-setup` did not actually establish a reusable configuration.
