# ADR-0039: Remove NPU inference

## Status

Accepted 2026-10-31, on the maintainer's decision. Implementation follows in a
separate pull request.

Withdraws ADR-0022. Amends ADR-0038 sections 1, 3 and 7. ADR-0033 section 7, as
narrowed by ADR-0038 section 2, stays in force. Closes #1244 as not planned.

## Context

ADR-0022 made the NPU optional, per model and certified. It never admitted a loading
profile or certified a model, so no authentication has run on an NPU, and no tagged
release carries the code.

The last candidate failed. On OpenVINO 2026.2.1, the exhaustive CBSR raw-IR run of
2026-10-09 (3,940 images, 74,860 genuine and 15,444,800 impostor comparisons) gave 30,
5 and 2 new impostor accepts that the CPU denied, at thresholds 0.55, 0.60 and 0.635,
with a maximum score drift of 0.00047. These are offline comparisons, not account
grants. ADR-0022 expected this kind of result: "At this extent f32 rounding alone may
break the no-new-grant rule. Such a failure is the answer, not a reason to relax the
rule." The route that had the CPU recompute every probe was slower than the CPU alone
(medians +4.12% to +8.54%), and used 383 to 536 MiB more memory.

The gain is small for a login:

- **Speed.** One recognizer call takes 118 to 183 ms on the CPU session and about
  6.8 ms on the NPU ([measurements](../research/2026-10-08-npu-measurements.md)). A
  paired RGB and IR recognition took 402 ms on the CPU on the same laptop, so the saving
  is at most about 380 ms, against a recorded lit-room median of 3,592 ms (n=3,
  2026-09-12). This is an estimate. The larger cost, the ViT PAD cue, stays on the CPU
  under ADR-0022 section 3.
- **Energy.** Published results show large savings on sustained heavy work and a CPU
  win on tiny calls on the same chips
  ([KATANA](https://arxiv.org/abs/2606.14992): 97.9% less energy on batched work, and
  0.40 mJ on the CPU against 2.61 mJ on the NPU for a single small call). No published
  figure covers a short burst like a login, and irlume never measured its own. Applying
  those power figures to 402 ms gives roughly 7 J per login, about one second of the
  UX5406 idling at 5.66 W
  ([Notebookcheck](https://www.notebookcheck.net/Asus-Zenbook-S-14-UX5406-laptop-review-Excellent-everyday-laptop-with-Intel-Lunar-Lake.892978.0.html)).
- **Reach.** The only qualified profile is one Lunar Lake identity on Fedora 44, and it
  needs a runtime newer than Fedora's own packages. Any stack update can invalidate an
  entry, so the certification upkeep that ended the GPU (ADR-0038) would return.

Authentication runs on a user action and opens the camera only briefly. Nothing in
irlume runs continuously, which is where an NPU saves the most, and always-on presence
detection is not wanted. Windows Hello's published requirements name no NPU and no
processor for face sign-in
([Microsoft](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-enhanced-sign-in-security)),
and it dates from Windows 10. Apple does use a neural engine for Face ID, through a
secure mode built into its hardware
([Apple](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)).
Linux on these chips offers no documented equivalent that this decision could find.

## Decision

### 1. CPU only

The recognizer and every other model run on the CPU. NPU placement, identity,
certification, loading admission, provider selection, probes, the `CERTIFIED` table and
the `npu` cargo feature are removed, with the `openvino` and `openvino-sys`
dependencies. Performance work goes to the CPU path.

### 2. What stays

Every CPU session keeps its exact CPU execution provider and its cutoff of
environment-selected providers (ADR-0033 section 7). Those protect authentication with
or without an accelerator, because the runtime crate can otherwise arm its own device
selection.

The identity arms stay, as the pure functions authentication calls, with their tests
and the characterization golden. The decision fingerprint, its witnesses and the
threshold enumeration leave production and stay as test-only code, with their pinned
digests. They were built to bind a certification entry to the decision code it was
measured through, and they also pin the CPU's grant decisions at their boundaries, which
is what performance work on the CPU path needs.

### 3. Settings

`recognizer_device`, `npu` and `npu_library` in `settings.conf`, and
`IRLUME_RECOGNIZER_DEVICE`, `IRLUME_NPU` and `IRLUME_NPU_LIBRARY`, are no longer read. A
line left behind does nothing, and authentication never fails because of one.

### 4. Stored enrollments

`embed_producer` on a scan is removed: only NPU admission read it. A scan that carries
the field, written by a nightly build, still loads and matches, and the field is
dropped the next time the enrollment is written. No embedding, template or threshold
changes.

### 5. Machine API

The Health and `status --json` object `recognizer`, its selection provenance and the
doctor ids `recognizer-device`, `recognizer-selection`, `npu-platform`, `npu-runtime` and
`npu-qualification` are removed from contract 1, with no new contract. As in ADR-0038
section 4, this is a stated exception to `docs/MACHINE-API.md`: none of these is in a
tagged release (`git grep` finds none at v0.15.0), and the nightly channel promises
nothing beyond `main` (ADR-0037). The five doctor ids are never reused.

### 6. Service rules

The NPU rules leave both AppArmor profiles, the systemd unit and the Nix module: the
`/var/cache/irlume/npu` cache and `CacheDirectory`, accelerator device and class paths,
the firmware version read, OpenVINO, Level Zero and oneTBB rules, and the `irlumed-npu`
local include. A rule stays only if something else on the CPU path needs it. An empty
`/var/cache/irlume/npu` left on a machine is harmless.

### 7. The intel-npu-stack project

`intel-npu-stack` is an independent, application-neutral project. This decision does not
change it. irlume stops referring to it as a reference installation.

### 8. Revisiting

A return needs a new ADR, and one of two things: evidence that CPU users face a failed
latency target, measured on full logins, or a new feature that runs continuously and that
the maintainer wants. Either way it must also answer the no-new-grant result above. This
replaces the revisit rule of ADR-0038 section 7, which named the NPU as the first answer.

## Consequences

- About 5,800 lines of NPU vision code and tests leave, with the wiring through the auth
  crate, daemon, CLI, schema, packaging and CI. Only the CPU runs authentication today,
  so no login changes.
- The CI lane for the optional NPU feature goes. The workspace test floor does not change.
- ADR-0022, the measurement record and the other research records stay on file as
  history, with a short supersession note. They no longer bind. The certification corpus
  extent rule falls with ADR-0022.
- #1244 closes, because no NPU discovery remains.

## Acceptance tests

- `recognizer_device=npu`, `npu=on` and `npu_library=/x` in `settings.conf`, and their
  environment variables, change nothing: the daemon starts and authenticates on the CPU
  with no warning about them.
- An enrollment whose scans carry `embed_producer` loads and matches the same, and writing
  it back omits the field.
- `status --json` validates against the schema with no `recognizer` object, and the
  conformance suite passes in strict mode. The doctor registry test passes with the five
  ids gone.
- The execution-provider test still proves the environment cutoff and the CPU pin.
- The characterization golden and the pinned decision and arm-grid digests are unchanged.
- No crate in `Cargo.lock` remains from OpenVINO, and no source file outside the ADRs,
  research records and CHANGELOG describes the NPU as present. The retired ids in
  `docs/MACHINE-API.md` and the list of forbidden libraries in `scripts/ci/isolated-cli.py`
  stay.
