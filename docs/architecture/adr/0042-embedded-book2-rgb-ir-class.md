# ADR-0042: Select a native RGB+IR class for Surface Book 2

## Status

Proposed 2026-11-28 for [#1379](https://github.com/archledger/irlume/issues/1379). This is the class decision (G0) requested by [proposed ADR-0041](0041-admission-first-embedded-ir.md#1-decide-the-admitted-pair-class-before-defining-backend-interfaces), not approval of that whole proposal. Depends on existing [capture qualification](0007-context-bound-capture-qualification.md), [schedule-aware posture](0014-schedule-aware-pairing-budget.md), [PAD](0019-fail-closed-pad-availability.md), [camera-scoped enrollment](0024-multi-camera-enrollment.md), and [one unseal per request](0025-one-unseal-per-request.md). No existing ADR or admission policy is amended by this proposal.

Acceptance chooses a class and its evidence and enrollment contract. It does not authorize backend implementation, device access, enrollment, authentication, credential release, or publication. The separate [supervised lab design](../../superpowers/specs/2026-11-28-embedded-book2-lab-boundary-design.md) is also proposed.

## Context

The original reporter describes front OV5693 RGB and OV7251 IR on different ports of one IPU3 CIO2 receiver, with ImgU on another media graph. One front RGB frame succeeded with local libcamera v0.8.0; the earlier IR preview used a bridge. The [current reply](https://github.com/archledger/irlume/issues/1379#issuecomment-7229600363) names the 13.5-inch `Surface_Book_1832`, Core i5-7300U, UEFI reported as `394.779.768`, `7.3.5-arch1-1-surface`, the locally rebuilt OV7251 DKMS backport, and libcamera 0.8.0. These are reporter observations, not a fresh topology, exact loaded image or a safe capture pair. Willingness to test is not consent to a particular run.

The private Stage A witness linked pinned Linux and libcamera interfaces and exercised synthetic buffers and receipts. It never started a manager or opened a camera. The known source evidence is insufficient for stock shared-desktop use: [libcamera IPU3 discovery](https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/pipeline/ipu3/ipu3.cpp#L848-L898) resets links before acquire, while [CIO2](https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/pci/intel/ipu3/ipu3-cio2.c#L482-L556) exposes shared queue and DMA behavior. A native visible or IR image is not enrollment, simultaneous capture, proof of identity or evidence that either route shut down.

## Decision

### 1. Select one closed, default-off candidate

Select a distinct **native embedded RGB+IR pair**, starting with the 13.5-inch `Surface_Book_1832` i5-7300U variant and the exact reviewed board, slot and loaded stack. The class is separate from `ConnectedPair`, `SplitPair`, ordinary USB and all IR-only classes. Do not extend support by DMI match, camera name, expected PCI topology, IPU3 version, one successful sample, or a user setting. The rear camera, 15-inch sibling, other CPU variants, loopback and software stand-ins are not in this choice.

Before G3q, G1 must review the exact candidate board and physical role locations, expected graphs and endpoint identity contract, kernel and modules, OV7251 revision/config and libcamera pipeline/IPA, allowed formats and operations, and independently bounded lab safety. G1 sets the conditions under which the exact instrumented stack may be considered for the trial, not hardware observations about how it actually behaved. G3q then measures the negotiated streams, capture-space/decoder/orientation behavior, optical state, timing and stop outcomes. A later local G2 review must bind that evidence and the observed endpoints to the exact slot and loaded stack; it is not automatic and cannot be offered as a prerequisite measured before G3q. An update, rebind or replacement that changes the reviewed predicate invalidates readiness. Use path names and observed bus addresses only to correlate evidence, not as stable identity or authority. This ADR selects no `cameras.d` entry, ABI, on-disk discriminator spelling or allowlist.

### 2. Keep the capture posture sequential and evidence complete

Use actual processed front RGB and native CIO2 multi-planar `ip3y` IR, separated under one reviewed supervised owner. Qualify the exact phase relationship, freshness, timestamps, capture-space and formats rather than importing ordinary USB timing limits. A small reported skew cannot establish concurrence. No concurrent mode and no IR-only fallback for stale, unavailable, conflicting or missing RGB. Only IR-identity-verified arms can be considered on a sequential schedule. Require produced compatible RGB and IR PAD for any grant under ADR-0019; a failed or absent required input is refusal, not a spoof classification or a reason to grant based on another class.

Require separately measured G7 input-domain and G8 PAD/recognition evidence before product enrollment or product matching. A separately authorized G3q non-granting evaluation can compare isolated test references under its own protocol to obtain that evidence; it cannot create a product enrollment or return any authentication outcome. Do not choose timing, optical ceiling, OFF latency, exposure or PAD acceptance limits from the topology, prior USB work, a model score or the Stage A numbers. No accepted measurement means no activation.

### 3. Separate local qualification, first enrollment and use

G3q is a separately authorized, single-use test or recovery operation and is non-granting. Passing it does not authorize enrollment, match output, account access, or a secret. Account enrollment needs fresh, explicit G3a authority for the exact account, local slot and operation. Authorized first enrollment requires no existing identity. Capture real processed RGB for the required RGB anchor and bound native IR for calibration, under the qualified contract and both modalities' applicable PAD. Never copy another RGB anchor or treat IR as the RGB identity. Authentication (G3b) instead requires a unique current and compatible G9 enrollment.

Use a protected versioned store separate from stable readers and a class discriminator inside the binding value that tested older readers refuse. Bind account, explicit profile, current slot authorization instance, capture and model/calibration contracts, and revocation/record lineage. Do not publish a partial enrollment or change existing store meaning. Confirm phase, ownership, teardown and final release, revalidate authority, persist operation disposition, then atomically publish enrollment or deliver a separately authorized outcome. A failure never adapts an enrollment. This does not change the ordinary UVC outcome timing in [ADR-0027](0027-decision-before-stream-teardown.md).

### 4. Keep desktop and secret decisions out of G0

The first future reference remains KDE/SDDM/KWallet. Non-root local `kde` ScreenUnlock with no secret, and cold local `sddm` sign-in that opens the same existing encrypted KWallet, are distinct targets. Proposed ADR-0041's `cosmic-greeter` predicate is not a `kde` decision. The warm worker/session proof and G10 expansion require separate review. Cold sign-in additionally needs the exact `sddm` G10/G11 and [ADR-0003](0003-fingerprint-keyring-unlock.md) same-transaction continuation for `KdeWalletKey`. Do not treat a successful face factor, a saved PAM value, another login service, or a launched wallet helper as permission or proof. Typed-password fallback and ordinary camera/fingerprint routes stay unchanged.

## Consequences

The feature is not activated by a detected device, a locally compiled backend, a lab pass, or one account setting. A read-and-refuse diagnosis may explain lack of qualification without exposing a camera capability. The cost is per-unit evidence, review and a separate enrollment/activation path. That cost is necessary to retain real RGB, existing password behavior, late teardown discipline and a separate secret boundary.

If a reviewed split cannot establish an owner before discovery, downstream normal/partial-stop results, independent optical OFF or suitable timing, keep it disabled and consider a coordinated upstream pipeline. A single pipeline does not waive those proofs. An integrated IR-only class and a pure viewing bridge do not replace native RGB-backed enrollment.

## Phasing

1. Maintainer reviews and accepts or rejects G0 separately. No code or live action follows from this document alone.
2. Review the exact supervised backend, trusted lab image and observation design before any real adapter work. Any later test on a device needs separately approved scope, operator, evidence handling and recovery.
3. Require a reviewed G1 contract for the exact instrumented lab stack and separately approved G3q transport/optics. Independently bound any emission and persist a unique pre-arm record before every possible arming. Treat this as evidence for a future, separately approved qualification, not an implicit G2. Later require qualified G7/G8, then authorized G9, G10 and G11 as separate gates. Do not request a contributor test until there is a reviewed runnable candidate for the specifically authorized stage.

## Acceptance tests

These are contract tests to plan and review, not results.

- A visible `1832`, correct CPU, maliciously renamed node, generic IPU3 hint, camera profile, stale holder or correct path number with wrong evidence cannot admit the class. On opt-out, unreadable scope or mismatch, ordinary operations behave as before and the embedded path opens nothing.
- Reject route substitution or reuse across RGB/IR roles, slot replacement, stale generation, build/profile change and unqualified timing. No RGB-only, IR-only or concurrent grant on this class, even at a short gap. No grant when either required PAD input is unavailable.
- An authorized first enrollment with proper qualification may publish atomically without a pre-existing identity; authentication without compatible G9 refuses. Test old readers, supported downgrade and re-upgrade, prior account revocation, failed final publication, and no mutation of ordinary records.
- No abort, missing optical result, unqualified release, stale reservation or unresolved hold permits an outcome or a retry. Exact class admission and warm unlock cannot release a secret; a future cold release needs its own accepted continuation proof.
