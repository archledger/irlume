# ADR-0038: Remove GPU inference

## Status

Accepted 2026-10-30, on the maintainer's decision. Implementation follows in
separate pull requests.

Withdraws ADR-0033, except its section 7 as narrowed below. Amends ADR-0022
sections 3 and 15, which return to "no GPU". Closes #1053, #1162, #1163 and
#1164 as not planned.

## Context

ADR-0022 section 15 kept the GPU out of scope, to be revisited "only with
evidence that CPU-only users face unacceptable latency". ADR-0033 reopened it
without that evidence. It recorded that the accelerator is "much faster, not
that CPU users today face a failed budget: authentication is capture-bound and
no user-facing latency target is violated."

The upkeep turned out large for that gain. The GPU path maps 37 libraries, and
numerics-set updates arrive about monthly, each needing a new certification
campaign of over an hour on the decision hardware (ADR-0033 amendment of
2026-10-22, #1164). Its results also differ from the CPU function, by cosine
0.999524 to 0.999687 in the #1053 runs, so a certification could not be skipped.
No GPU entry was ever certified and no GPU loading profile was ever admitted, so
no authentication has run on a GPU.

The platform vendors' documentation points the same way. Apple runs Face ID on
the Secure Neural Engine
([Apple Platform Security](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)).
Windows Hello with Enhanced Sign-in Security isolates the face algorithm with
virtualization-based security
([Microsoft](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-enhanced-sign-in-security)).
Android requires recognition inside a secure isolated environment
([AOSP](https://source.android.com/docs/security/features/biometric)). None of
these pages names a GPU. That is an absence in those pages, not proof that no
product uses one.

## Decision

### 1. CPU and NPU only

The recognizer runs on the CPU, which stays authoritative, or on the NPU under
ADR-0022 once a certification passes. GPU placement, identity, certification,
loading admission, launch checks, evidence lanes and ranking are removed.

### 2. What stays from ADR-0033

Every CPU session keeps its exact CPU execution provider and its cutoff of
environment-selected providers (section 7). Those protect the CPU reference with
or without a GPU. The ONNX Runtime provider features `cuda`, `openvino`, `coreml`
and `tensorrt` are removed: they could only reach a test escape, and removing them
leaves that protection in place.

Section 4's ELF metadata and declared fixture graph, and the measurement-only
build boundary, are not decided here. They have no GPU consumer left. ADR-0022's
text that names the GPU for them stays dated, and whether the NPU uses them or
they are removed is decided separately.

Everything else in ADR-0033 and its amendments stays on file as a record, and no
longer binds.

### 3. Settings

`recognizer_device` takes `auto`, `cpu` and `npu`. A stored `gpu` takes the existing
invalid-value path: a journal warning and `auto`, with the issue reported in the
selection provenance. Authentication never fails because of it. The `gpu` key in
`settings.conf` and `IRLUME_GPU` are no longer read, so a line left behind does
nothing.

### 4. Machine API

The selection word `gpu`, the fields `accelerator`, `gpu_platform`,
`gpu_runtime_available` and `gpu_qualified`, and the doctor ids `gpu-platform`,
`gpu-runtime` and `gpu-qualification` are removed from contract 1, with no new
contract. `docs/MACHINE-API.md` allows removal only under a new contract. This is
a stated exception: none of these is in a tagged release (`git tag --contains`
finds none, and v0.15.0's schema has no `gpu` word), and the nightly channel
promises nothing beyond `main` (ADR-0037). The three doctor ids are never reused.

### 5. Service rules

The GPU rules leave the AppArmor profiles, the systemd unit, the Nix module and
`scripts/install-host.sh`: render nodes, the render-node and firmware walks,
OpenCL registrations, compute-runtime libraries, the `irlumed-gpu` local include
and the GPU launch environment. Rules the NPU path also uses stay, including
Level Zero and oneTBB.

### 6. Before NPU admission opens

NPU discovery calls `Core::available_devices()` only to check that `NPU` is listed
(`crates/irlume-vision/src/npu.rs`). OpenVINO's `CoreImpl::get_available_devices`
asks every registered device, which creates its plugin, so on a host with the GPU
plugin installed NPU discovery may map the GPU stack into the process and into the
hashed NPU inventory. This is read from OpenVINO 2026.2.1's source and not measured.
Production is unaffected while NPU admission is closed, since the refusal comes
first. Discovery queries only the NPU before admission opens, with a hardware run
on the decision laptop.

### 7. Revisiting

Section 15 of ADR-0022 sets the test again: evidence that CPU-only users face
unacceptable latency. A full login on CPU has not been timed end to end, only single
inferences (108.7 to 258.5 ms on the fleet's CPUs). If that timing shows a failed
target, the NPU is the first answer.

## Consequences

- About 13,000 Rust lines leave, most of them tests, with no crate dependency
  change expected. No template, digest or decision fingerprint moves, because the
  GPU tables and identity were separate from the NPU's.
- Only the CPU runs authentication today, as before: the NPU's `CERTIFIED` table is
  empty too.
- The contained-job runner built for the GPU campaign is not merged (#1231, closed).
  Its branch `test/1164-job-runtime-evidence` stays as the record.
- The research records in `docs/research/` stay as historical evidence, with a
  short supersession banner. `2026-10-22-certification-extent.md` gets none, because
  its extent rule still applies to NPU certification.
- CI test floors do not change. The workspace run stays above its floor of 2,720,
  and the NPU lane keeps its floor of nine by requiring three other named tests.

## Acceptance tests

- `recognizer_device=gpu` and `IRLUME_RECOGNIZER_DEVICE=gpu` give a warning, `auto`
  and provenance `invalid_value`. The daemon starts, and no GPU code runs.
- `gpu=off`, `gpu=on` and `IRLUME_GPU=...` left behind have no effect on the `npu`
  switch or on placement.
- The schema rejects `selection: "gpu"`, and the conformance suite passes in strict
  mode.
- The doctor registry test passes with the three ids gone, and existing fixtures
  validate unedited.
- `execution_providers_stay_escape_gated_and_strict`, rewritten for the single CPU
  pin, still proves the environment cutoff and the pin.
- The NPU test lanes keep their strength.

## Amendment 2026-10-30: the measurement tooling is removed

Section 2 left the ELF metadata, the declared fixture graph and the measurement-only
build boundary undecided. On the maintainer's decision they are removed: the
`irlume_hw_evidence` build and its guards in every crate, `measurement_profile`,
`native_generation`, `native_metadata`, the measurement fixtures, their fuzz targets
and the contained-job scripts. They were built for the GPU campaign, and no shipped
program used them. ADR-0022's amendment of 2026-10-22 "measurement-only evidence builds"
stays as the record, and no longer binds.

If the NPU is certified later, its measurement path is decided then and sized to what
it needs. The corpus extent rule in ADR-0022 still applies to that certification.
