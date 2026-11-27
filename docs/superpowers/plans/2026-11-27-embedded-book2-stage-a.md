# Embedded Book 2 Stage A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a private linked libcamera/Linux interface witness and a fixture-only RGB/IR handover proof that can be run without cameras, a desktop session or credentials.

**Architecture:** A C11 declaration witness and a C++20 link witness use verified public headers and a private libcamera build. A standalone, test-only Rust crate exercises payload bounds, typed synthetic receipts, both capture orders and restart refusal. A fail-closed runner verifies the exact linked libraries and runs only those witnesses and fixture tests inside an isolated process.

**Tech Stack:** Linux x86-64 upstream v7.3.5, GCC C11/C++20, libcamera v0.8.0 with IPU3 handler/IPA, Meson/Ninja, Rust 1.88.0 with no crate dependencies, Python 3, bubblewrap.

**Spec:** [Approved Book 2 design, Stage A](../specs/2026-11-27-embedded-book2-experimental-design.md#1-bound-the-first-engineering-slice), local design commit `fd58802b1acee45a5df11698acd2818eb5160d96`.

## Global Constraints

- This plan implements Stage A only. Do not add a real camera adapter, issue a V4L2 ioctl, open a camera, construct or start `CameraManager`, load an IPA at runtime, configure an emitter, or instrument the kernel.
- Keep all new files under `scripts/research/1379-stage-a/`. Do not touch the root Cargo workspace/lock, product crates, CI, packages, models, PAM, wallet, TPM, settings, schemas, installed services or other worktrees. No install target or public command. No push or reporter contact.
- Pins: Linux stable [`988117cc1bb17338c586a4e21ade88b5397eac33`](https://github.com/gregkh/linux/tree/988117cc1bb17338c586a4e21ade88b5397eac33); libcamera [`df8e348d64b4932a0676256ed24f0da3ee9438bc`](https://github.com/libcamera-org/libcamera/tree/df8e348d64b4932a0676256ed24f0da3ee9438bc). These are source references, not reported downstream ABI or hardware. If a pin needs to change, re-evaluate the plan before switching.
- Keep sources and build outputs in task-private scratch. Verify the upstream source trees against exact commits; record tool and library versions, input hashes, Meson introspection and witness dependency resolution. Check pinned upstream docs, sources and distro changes at each relevant task. No system install; if approved private prerequisites cannot be verified, report a blocked native witness, not a skipped pass.
- Stage A has only synthetic evidence and synthetic non-face bytes. No real-derived fixture data, frames, biometric templates, keys, or production trust/qualification type. No live proof, grant, or rollback-resistance claim.
- Run each task’s RED and GREEN checks and keep their receipts. Sign each commit locally with `git commit -S -s` (one owner DCO); stage only named files. Keep the production diff empty.

## Review Focus

- A system `libcamera.pc` or unrelated same-version library must not satisfy pin provenance (Task 1 `private_pc_never_falls_back`, Task 5 `wrong_sdk_resolution_is_refused`).
- Signature checks alone or a discarded address witness must not count as a linked interface (Task 1 `missing_link_symbols_fail`).
- A larger allocation is valid, but a claimed extent crossing the plane length or mapping cannot become a slice (Task 2 `extent_is_checked_before_slicing`).
- The first IR stop/optical result must not clear the second IR phase despite matching apparent status (Task 3 `prior_ir_receipt_cannot_clear_later_phase`).
- A process exiting before the terminal observation must leave the fixture attempt unusable after reopen, even with fresh synthetic identifiers (Task 4 `child_exit_after_intent_keeps_attempt_closed`).

## File Map and Commands

| Path below `scripts/research/1379-stage-a/` | Responsibility |
| --- | --- |
| `native/linux_uapi.c`, `native/libcamera_link.cpp` | Static type/layout assertions and real retained ELF references. C++ `main()` reads only the library version string. |
| `native/check.sh` | Check exact private input locations, compile positive and negative cases, retain final link binary. Never run it here. |
| `fixture/Cargo.toml`, `fixture/Cargo.lock`, `fixture/src/lib.rs` | `irlume-book2-stage-a`, separate `[workspace]`, Edition 2021, `rust-version = "1.88"`, `publish = false`, no dependencies or non-test API. |
| `fixture/src/ip3y.rs`, `fixture/src/ip3y_tests.rs` | Exact synthetic IR contract and in-bounds sample access. |
| `fixture/src/handover.rs`, `fixture/src/handover_tests.rs` | Synthetic fixed orders, receipts and ordered side-effect ledger. |
| `fixture/src/journal.rs`, `fixture/src/journal_tests.rs` | Single-use scratch attempt marker and child interruption check. |
| `run_isolated.py`, `test_run_isolated.py`, `README.md` | Run and prove no-device containment, exact SDK recipe and limitations. |

Commands below assume worktree root, `S=scripts/research/1379-stage-a`, and a fresh, absolute scratch directory `SCRATCH` under `/tmp/opencode`. Set `CARGO_TARGET_DIR="$SCRATCH/rust-target"` before Rust commands. Test selectors must run a nonzero number of tests, with no skip/ignore fallback. Use `#![cfg(test)]` and `#![forbid(unsafe_code)]` in the fixture crate; apply the repository’s Rust file headers and Clippy conventions.

**Fixture execution for Tasks 2–4:** Build with `cargo +1.88.0 test --locked --offline --manifest-path "$S/fixture/Cargo.toml" --no-run --message-format=json`. Extract the sole executable for this fixture package with `profile.test == true` and a non-null `executable` from `compiler-artifact` output. Until Task 5 adds the reusable runner, use the following command via a `subprocess.run` argument list with `stdin=DEVNULL`, `close_fds=True` and a finite timeout. Verify `/lib` and `/lib64` on the Arch host point into `/usr/lib` first; require both named user/network namespaces with no fallback. Append `ip3y`, `handover`, or `journal` to select a lane, or no filter for the full suite. Before the first run, use the same mount map with `/usr/bin/sh` to verify no real media/TPM device nodes, host home, or host `/run` sockets. Do not invoke the test executable on the host.

```sh
bwrap --unshare-all --new-session --die-with-parent --clearenv \
  --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib /lib64 \
  --dev /dev --proc /proc --tmpfs /tmp --dir /run --dir /home \
  --dir /etc --dir /sys --dir /tmp/fixture-home --chdir /tmp \
  --setenv HOME /tmp/fixture-home --setenv PATH /usr/bin \
  --ro-bind "$FIXTURE_TEST_BIN" /fixture-test -- /fixture-test
```

### Task 1: Prove the pinned native interface can link

**Files:** `native/linux_uapi.c`, `native/libcamera_link.cpp`, `native/check.sh`, `README.md` under `$S`.

**Interfaces:** `bash "$S/native/check.sh" "$UAPI" "$SDK" "$SDK_MANIFEST" "$SCRATCH/native"` expects exported `UAPI/include`, `SDK/lib/pkgconfig/libcamera.pc`, a reviewed build receipt `SDK_MANIFEST`, and an empty output directory. The receipt uses `sha256sum` text format with paths relative to `$SDK`; it covers the two library ELFs, IPA, `.pc` files and installed public headers. Resolved paths must stay under `$SDK`. Produces `libcamera-link` and logs in the output, with no execution of the witness. Every incompatible SDK or test-negative failure is a nonzero result.

- [ ] **Preflight build inputs.** Verify git `HEAD` and clean source trees at both public pins. Run `make -C "$LINUX" ARCH=x86 O="$SCRATCH/kbuild" INSTALL_HDR_PATH="$UAPI" headers_install` on the pinned Linux tree; do not substitute host Linux UAPI. For libcamera verify the [build requirements](https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/README.rst) and [options](https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/meson_options.txt). On Archhost Meson, `jinja2`, and `ply` were absent from the active environment during planning. Reuse a verified private tool environment or build one from exact hash-verified, compatible packages in scratch, recording versions/hashes before use. Do not install system tools or bootstrap from unchecked scripts.
- [ ] **Build and stage the SDK.** Start from cleared libcamera/pkg-config override variables. Run `meson setup "$SCRATCH/lc-build" "$LIBCAMERA" --prefix "$SDK" --libdir lib --wrap-mode=nodownload -Dpipelines=ipu3 -Dipas=ipu3 -Dtest=false -Dcam=disabled -Dqcam=disabled -Dgstreamer=disabled -Ddocumentation=disabled -Dpycamera=disabled -Dlc-compliance=disabled -Dv4l2=disabled -Dtracing=disabled`, then `meson compile -C "$SCRATCH/lc-build"` and `meson install -C "$SCRATCH/lc-build"` without privilege. Verify the absolute prefix beforehand. Retain Meson build options/targets and derive `SDK_MANIFEST` from this verified build only, not from an arbitrary installed SDK; require exactly the requested IPU3 pipeline option, `ipa_ipu3.so`, generated headers, and private `libcamera.pc` version `0.8.0`. Record whether the build signed the IPA; do not claim runtime loading or retain build keys. Confirm upstream [IPA target definition](https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/ipa/ipu3/meson.build).
- [ ] **Write native assertions and RED cases.** Compile with strict warnings. Cover C queue `MPLANE=9` versus legacy `1`, `ip3y=0x79337069`, MMAP `1`, field `NONE=1`, error flag `0x40`, `pix_mp`, `m.planes`, `u32` plane lengths/offsets and ioctl struct sizes (`G_FMT`, `REQBUFS`, `QUERYBUF`, `QBUF`, `DQBUF`, `STREAMOFF`, `MEDIA_IOC_G_TOPOLOGY`). Check C++ types for manager start `int`, stop `void`, camera acquire/release/stop `int`, camera start with `const ControlList *`, configure, `queueRequest(Request *)`, allocator `free(Stream *)` and frame metadata/plane extents, against the [pinned public headers](https://github.com/libcamera-org/libcamera/tree/df8e348d64b4932a0676256ed24f0da3ee9438bc/include/libcamera). RED: wrong single-planar queue and false `int` manager stop fail with their named assertions.

  ```c
  _Static_assert(REQUIRED_QUEUE == 9, "native IR requires the multiplanar queue");
  _Static_assert(V4L2_PIX_FMT_IPU3_Y10 == 0x79337069U, "expected ip3y FourCC");
  ```

  C++ control: `static_assert(std::is_same_v<decltype(&libcamera::CameraManager::stop), ManagerStop>, "manager stop is void");` with `ManagerStop` switched to `int (libcamera::CameraManager::*)()` only in the failing build.

- [ ] **Verify link-specific RED before runner success.** `missing_link_symbols_fail`: a compile-only object accepts the headers but an executable link with the libcamera libraries omitted must fail for referenced libcamera symbols. `private_pc_never_falls_back`: a missing private `.pc` must fail even when `PKG_CONFIG_PATH` points to a deliberately conflicting same-version fixture. No wrong-failure masking: verify the diagnostic is from the expected assertion/missing symbols/refusal.
- [ ] **Implement `check.sh` and witness retention.** Verify the SDK receipt and listed path containment before compilation. Use private `$SDK/lib/pkgconfig` as `PKG_CONFIG_LIBDIR` (clear `PKG_CONFIG_PATH`/`PKG_CONFIG_SYSROOT_DIR`); independently check resolved prefix, include and library dirs. Compile actual `CameraManager::{start,stop}`, `Camera::{acquire,release,start,stop,configure,queueRequest}` and `FrameBufferAllocator::free` address references into an object, without constructing or calling receivers. Use retained volatile-address storage read by `main()` without invocation; check named undefined references with `nm -uC` rather than trusting the source. `main()` checks `CameraManager::version()` for the pinned `0.8.0` base version and emits `libcamera link witness: 0.8.0`; the pinned accessor reads the library's version string. Use no alternate code path, no LTO or linker dead skipping of those references. Link against exact private shared library files, demand resolved symbols, and retain `readelf -d` output for the executable and SDK libraries.
- [ ] **Run and commit the verified compile/link step.** Run `bash -n "$S/native/check.sh"` and `shellcheck "$S/native/check.sh"`, then the interface command with real inputs. Require two positive compiles, actual executable link, separate intended negative outcomes and the required dynamic references. Record "not executed" here; Task 5 owns runtime verification. Commit `test(research): add pinned Book 2 interface witnesses`.

### Task 2: Check the exact synthetic IR payload before decoding

**Files:** `fixture/{Cargo.toml,Cargo.lock,src/lib.rs,src/ip3y.rs,src/ip3y_tests.rs}` under `$S`. Verify the archived prior frame/validator evidence if using it; no build depends on mounted research artifacts.

**Interfaces:** `struct Layout { queue: u32, fourcc: u32, planes: u8, field: u32, width: u32, height: u32, stride: u32, size_image: u32 }`; `struct Plane { flags: u32, length: usize, offset: usize, bytes_used: usize }`; `fn validate<'a>(layout: Layout, plane: Plane, mapped: &'a [u8]) -> Result<Ip3y<'a>, IrError>`; `Ip3y::sample(&self, row: usize, column: usize) -> Option<u16>`. `Ip3y` borrows only the validated payload. `IrError::{Format, Completion, Extent}` are fixture outcomes, not trust evidence.

- [ ] **Write failing tests.** `reference_layout_decodes_without_padding`: `640×480`, stride `832`, size `399_360`, one plane, type `9`, field `1`, FourCC `0x79337069`; first bytes `[0x01,0x08,0x00,0xe0,0xff]` decode to `[1,2,512,1023]`; fill the first sample of row 1 with `7`, column `639` of row 0 with `15`, and seeds in padding slots. Additional allocation and a nonzero offset are allowed with unchanged payload length. `exact_layout_and_error_flag_refuse`: variant format/queue/planes/field/geometry/stride/size rejects `Format`, ERROR with valid metadata rejects `Completion`. `extent_is_checked_before_slicing`: offset after bytes used, length greater than mapping, used beyond advertised plane, short/extra payload and extreme indices each refuse without panic; ensure offset `usize::MAX` does not overflow.

  ```rust
  assert_eq!((0..4).map(|i| image.sample(0, i)).collect::<Vec<_>>(),
             vec![Some(1), Some(2), Some(512), Some(1023)]);
  assert_eq!((image.sample(1, 0), image.sample(0, 639)), (Some(7), Some(15)));
  assert_eq!((image.sample(0, 640), image.sample(480, 0)), (None, None));
  assert!(matches!(validate(layout, bad_extent, &bytes), Err(IrError::Extent)));
  ```

- [ ] **Run RED against a safe stub.** Build the test executable and run the isolated `ip3y` lane as above; require named positive case fails with stub refusal rather than an unrelated Cargo failure.
- [ ] **Implement the borrowed validator and accessor.** Check `offset <= bytes_used <= length <= mapped.len()`, exact payload `bytes_used - offset == 399_360`, then slice. Decode each row separately as 25 samples/32 bytes, little-endian ten-bit windows, 832 bytes per row. The [driver stride/format](https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/pci/intel/ipu3/ipu3-cio2.c#L101-L108) and [packing](https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/Documentation/userspace-api/media/v4l/pixfmt-yuv-luma.rst#L205-L208) define this exact witness, not frame completeness. Use the borrowed value in a fixture test only; no dynamic negotiation or allocation from untrusted dimensions.
- [ ] **Run GREEN and commit.** Re-run the targeted tests, package fmt and Clippy with `-D warnings` (common checks in Task 5); verify empty dependencies. Commit `test(research): validate the synthetic IPU3 payload`.

### Task 3: Verify both fixed capture orders with synthetic observations

**Files:** `fixture/src/{lib.rs,handover.rs,handover_tests.rs}` under `$S`.

**Interfaces:** `Scope { boot: u64, stack: u64, graph: u64, attempt: u64, reservation: u64 }`; `PhaseKey { scope: Scope, ordinal: u8, route: Route, queue_generation: u64, stop_generation: u64 }`; `Order::{RgbIrRgb, IrRgbIr}` and `Route::{Rgb, Ir}`. `Observation::{Confirmed, Failed, Unknown}`; `WorkerResult::{Completed, Refused, TimedOut}`. `fn run_fixture(scope: Scope, order: Order, script: &Script, record_intent: impl FnOnce() -> bool, emit: impl FnMut(Event)) -> Outcome`, with `Outcome::{Complete, Refused, Held}`. A `Script` has three ordered fixture phases, owner checks at entry/exit for each phase, separate pre-discovery owner and optical-baseline observations, and separate terminal graph-state and release observations. Each observation carries its exact `Scope` or `PhaseKey`, a typed evidence kind and the synthetic status. Derive expected phases from the order independently of receipts, with ordinals and both synthetic generations set to `1, 2, 3` within this single attempt. Keep the worker result separate from the observer's facts. `Event::{IntentRecorded, BeginPhase(PhaseKey), RestoreGraph, Release}` records attempted transitions, not production audit evidence.

- [ ] **Write event-order tests.** `both_orders_one_reservation`: checked entry precedes `IntentRecorded`; `BeginPhase` shows ordinals `1..=3` and both exact schedules; only one final `RestoreGraph, Release` occurs. `no_owner_means_no_intent_or_phase`: initial owner unknown/foreign or baseline absent produces refusal with no events or intent callback. `unconfirmed_intent_refuses_before_effect`: callback false returns `Held` with no `BeginPhase`. `prior_ir_receipt_cannot_clear_later_phase`: inject stop/optical receipt from ordinal 1 into ordinal 3 with same reservation; expect `Held` without restore/release. `cleanup_is_not_worker_success`: independently vary software drain, RGB manager retirement/ImgU stop, CIO2 receiver/DMA halt, sensor stop, phase graph readback, IR optical OFF and continuing ownership as unknown/failed/foreign; no next phase or terminal release. `timeout_distinguishes_known_cleanup`: timeout or partial start with positive independently observed cleanup/restoration/release is `Refused`, never next phase; missing rollback evidence is `Held`. `lost_final_observation_is_not_complete`: final restoration or release receipt missing, stale or unknown means `Held`, even with three valid prior phases.

  ```rust
  assert_eq!(result, Outcome::Complete);
  assert_eq!(events, [Event::IntentRecorded, Event::BeginPhase(first),
                     Event::BeginPhase(second), Event::BeginPhase(third),
                     Event::RestoreGraph, Event::Release]);
  ```

  For the stale second-IR proof, assert `Outcome::Held` and the same event sequence without its last two events.

- [ ] **Run RED.** Build the test executable and run the isolated `handover` lane; require both positive orders fail against refusal stub and negative tests actually run.
- [ ] **Implement bounded transitions.** Use exact scope and route keys; accept only a matching positive observation for each applicable stage. RGB requires manager retirement, software drain and ImgU stop, IR requires independently observed OFF; both require receiver/DMA/sensor teardown and exact handover state. For a refused or partial start, an observer can prove a particular stage was never reached only with a separately keyed positive no-effect observation for that stage; missing observation is never equivalent. After a clean failed phase restore/release once and return refusal, never start another phase. Require final restoration and release proof for complete/clean refusal. No retry, scan, hook into Irlume, bytes from cameras, real optical inference or non-test public API.
- [ ] **Run GREEN and commit.** Repeat targeted and full fixture tests and record correlated event logs for both schedules and the stale/unknown paths. Commit `test(research): model Book 2 handover refusals`.

### Task 4: Prove fixture interruption is not permission to start again

**Files:** `fixture/src/{lib.rs,journal.rs,journal_tests.rs}` under `$S`. Reuse `run_fixture`'s intent hook; do not create a real recovery or hold-clearing tool.

**Interfaces:** `fn record_intent(case_dir: &Path) -> io::Result<()>` creates a `0600` marker named `attempt.hold` using `create_new` in a fixture-owned `0700` directory, writes only a fixed synthetic version string, syncs the marker and directory before success. Any existing marker or error refuses; fixture case dirs are single-use even after successful results. This models durable unresolved intent and refusal, not an installed hold store.

- [ ] **Write tests.** `marker_present_before_begin_phase`: assert the marker is readable and exact at the first phase event, not just after return. `child_exit_after_intent_keeps_attempt_closed`: run the current test executable as a fixture-only subprocess, require a flushed `intent synced` notice and deliberate exit `73` before any release; reopen same case in another process and attempt with a fresh scope, expect zero `BeginPhase` events. `occupied_or_unwritable_marker_never_starts`: precreate a marker and compare its bytes after refusal; provoke a reliable error with a regular file where the case directory is required, not a permission test that may pass as root. Use a bounded test timeout and no ignored or zero-match helper invocation.
- [ ] **Run RED.** Build the test executable and run the isolated `journal` lane; require named tests and a missing-intent false success or missing-marker failure before implementing.
- [ ] **Implement `record_intent`.** Use safe stdlib operations, fixture-only path under an exclusively created disposable temp directory, `DirBuilderExt::mode(0o700)` and `OpenOptionsExt::mode(0o600)`, fixed bytes `b"stage-a-fixture-v1\n"`. The phase-event closure checks `assert_eq!(fs::read(case_dir.join("attempt.hold")).unwrap(), b"stage-a-fixture-v1\n")`. Fail on marker conflicts. A fixture never clears the marker or guesses the prior disposition. Propagate write/sync failure as false to the intent hook. Document process death/reopen coverage and no power-loss, rollback or general filesystem custody claim.
- [ ] **Run GREEN and commit.** Run targeted and full fixture tests, with child real exit and reopen observed, both schedules still green and no skipped test. Commit `test(research): cover interrupted fixture attempts`.

### Task 5: Run the proof from a clean no-device environment

**Files:** `$S/{run_isolated.py,test_run_isolated.py,README.md}`.

**Interfaces:** `python3 "$S/run_isolated.py" "$SDK" "$SDK_MANIFEST" "$SCRATCH/native/libcamera-link" "$FIXTURE_TEST_BIN"`; paths are canonical absolute, no privilege. The script checks the manifest from Task 1 and runs only these verified inputs with cleared environment and inherited non-stdio descriptors closed. `FIXTURE_TEST_BIN` is the single test artifact reported by `cargo +1.88.0 test --locked --offline --manifest-path "$S/fixture/Cargo.toml" --no-run --message-format=json` for this package (`profile.test`, `executable` present).

- [ ] **Write runner RED tests.** `isolation_unavailable_fails_closed`: force sandbox launcher failure, assert nonzero and witness not run. `host_paths_and_inherited_handles_are_absent`: put sentinel path and pipe in parent temp, child preflight cannot see either; verify no host `/dev/video*`, `/dev/media*`, `/dev/v4l-subdev*`, TPM, `/run` sockets, host home or system bus. `wrong_sdk_resolution_is_refused`: same-version alternate directory or missing private shared object cannot satisfy designated library resolution. `fixture_zero_tests_or_subprocess_timeout_fails`: return zero without a nonzero libtest count or exceed wall bound, expect failure and no success receipt. Never perform these probes on hardware.

  ```python
  self.assertNotEqual(result.returncode, 0)
  self.assertNotIn("libcamera link witness: 0.8.0", result.stdout)
  self.assertFalse(witness_marker.exists())
  ```

  Apply all three assertions when isolation fails; for a failed fixture after a successful link, require runner failure without any overall success receipt, not absence of the earlier link line.

- [ ] **Run RED with `python3 -m unittest discover -s "$S" -p 'test_run_isolated.py'`.** Verify that omission of isolation/path or count gates fails the named tests.
- [ ] **Implement the runner.** Check the recorded SDK artifact hashes and relative paths; pairing an alternate same-version library with the original build receipt must fail. Use `subprocess` argument vectors, `close_fds=True`, null stdin and bounded timeouts; no shell or host fallback. Run `bwrap --unshare-all --new-session --die-with-parent --clearenv` with read-only host `/usr` for verified tools/loader, the verified Arch `/lib*` aliases, only the verified SDK/test artifacts mounted read-only, new proc/minimal dev/temp and empty home/run/etc/sys, no host seat, sockets or credentials. Set the child working directory inside the new scratch environment. Make absence of devices, host mounts and network access observable in a sandbox preflight; refuse missing namespace support. Set immediate binding (`LD_BIND_NOW=1`) and a private lib search path; use loader diagnostics to verify both libcamera and libcamera-base resolve to mounted SDK objects, not merely the expected SONAME or version. Do not use `LD_PRELOAD`, a system lookup fallback or `cam -l`. Require the exact witness line and a nonzero full fixture count with zero failed/ignored/filtered tests; an early exit or child timeout is failure.
- [ ] **Run final local gates.** Rebuild native witnesses from the recorded inputs. Run Python runner tests, then the isolation command twice in fresh scratch instances with matching semantic outcomes. Verify `cargo +1.88.0 fmt --manifest-path "$S/fixture/Cargo.toml" --all --check`, `cargo +1.88.0 clippy --manifest-path "$S/fixture/Cargo.toml" --all-targets --locked --offline -- -D warnings`, `RUSTDOCFLAGS="-D warnings" cargo +1.88.0 doc --manifest-path "$S/fixture/Cargo.toml" --locked --offline --no-deps`, and offline non-test release build. Confirm no binary targets and no dependencies from fixture metadata, and unchanged root workspace members/lock and production paths. Run applicable repository gates from `AGENTS.md` in their documented safe environments; never sweep ignored tests or use real hardware as a substitute. Report unavailable gates separately.
- [ ] **Document and commit the final proof.** Record exact build inputs, receipts, drop/timeout checks, isolation and app/runtime limits. README gives repeatable scratch instructions and explicitly distinguishes a private link witness, MPLANE payload math and synthetic receipt verification from any loaded hardware/IPA, graph exclusion, optical OFF or authorization. Commit `test(research): verify the no-device Book 2 proof`; run independent review of the exact resulting branch before presenting results. Stop. Any real backend, product work, publication or device test needs its own decision.
