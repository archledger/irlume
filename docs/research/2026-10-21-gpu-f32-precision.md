# GPU inference precision: f16 against f32 under the ADR-0022 gates

Measurement record for the ADR-0033 amendment of 2026-10-21. Everything
here is measurement only: loading admission stays closed, `CERTIFIED`
stays empty and CPU authentication stays authoritative. No biometric data
is recorded; the corpora are private copies on the measurement hosts.
Archives live on the shared project store under `artifacts/irlume/`, each
with a `SHA256SUMS` manifest; the digests quoted below are the first eight
hex characters of the full values in those manifests.

## Setup

- Model: glintr100 (`glintr100.onnx`, pinned by the embedded artifact
  manifest), input NCHW 3x112x112 f32 through the production
  `preprocess_arcface`, fixed operating point 0.55.
- Runtime: OpenVINO 2026.2.1 C API (`libopenvino_c.so.2621`), GPU plugin
  on one explicit device (`GPU.0`), batch 1, `PERFORMANCE_HINT=LATENCY`,
  the inference precision named explicitly. ONNX Runtime 1.28.1 serves the
  CPU reference.
- Gates: ADR-0022 section 7.4 (verdict budget: no new grant, false-accept
  not above the CPU's, false-reject not above the CPU's by more than 0.2
  points) and 7.5 (the maximum absolute drift read as a threshold shift on
  the CPU scores moves the false-reject rate by at most 0.2 points and the
  false-accept rate by at most 10%).
- Corpora on both hosts: 400 genuine and 400 impostor canonical LFW pairs
  and 2,597 within-group FairFace impostor pairs (371 in each of seven
  groups); the UX5406S additionally measured recorded genuine IR and RGB
  frames and presentation attacks (the real-frames lane).
- Hosts: UX5406S (Lunar Lake, Arc 140V `8086:64a0`, `xe`, the decision
  hardware) and ThinkPad X13 Yoga Gen 4 (Iris Xe `8086:a7a1`, `i915`, a second
  measured identity). Each host's identity binds the plugin build, the
  render node, the GuC/HuC firmware, the compile configuration and every
  mapped native library, so a precision change is a new identity.

## f16 (the plugin default)

| Host, identity, date | Arm | n | 7.4 | 7.5 | Measured |
|---|---|---|---|---|---|
| UX5406S `f8591769`, 2026-10-12 | recorded genuine IR | 1,474 | PASS | FAIL | lower threshold shift moves 5/1,474 verdicts (0.339 points); upper shift 2/1,474 within budget |
| UX5406S `f8591769`, 2026-10-12 | recorded genuine RGB | 339 | FAIL | FAIL | one additional rejection (0.295 points), also on the upper shift |
| UX5406S `f8591769`, 2026-10-12 | 11 other arms | | PASS | PASS | recorded attacks and impostors, LFW, FairFace: no new grant |
| ThinkPad `6aa45541`, 2026-10-13 | genuine LFW | 400 | PASS | FAIL | maximum absolute drift 0.00108; one pair in 400 flips on each shift direction (0.25 points) |
| ThinkPad `6aa45541`, 2026-10-13 | impostor LFW and 7 FairFace groups | 2,997 | PASS | PASS | zero verdict differences, no new grant; maximum FairFace drift 0.00162 |

The UX5406S rows are the measured-budget receipt of
[the identity record](2026-10-11-gpu-identity.md). The ThinkPad rows come
from `artifacts/irlume/2026-10-13-retained-reliability/thinkpad-corpora-drift/`
(75.7 minutes, 3,397 comparisons, zero CPU/GPU verdict differences). By the
ADR-0022 section 7.5 figure (a drift of 0.00038 moves LFW's false-reject
rate by about 0.09 points), 0.00108 is about 0.26 points, so the f16
default fails that gate independently of the sample size.

Reliability and cache evidence collected on the ThinkPad f16 identity
(1,000 retained calls including 300 after a proven runtime suspend and 300
after a proven system suspend; cache matrix of one seed, 20 cache-bypassed
compiles and 20 verified imports, 41 of 41 processes; audit verdict
APPROVE-with-notes on 2026-10-19) established the harness, not the
identity: it does not transfer to an f32 identity.

## f32

ThinkPad X13 Yoga Gen 4, 2026-10-19. A measurement build of origin/main (`f97a9796`
for the probe, `07023313` for the campaign) with the compile
configuration's precision changed to `f32`, installed beside the untouched
f16 binaries under a root-owned prefix with a process-local ICD. Identity
`f592e9bc` (probe, kernel 7.2.9) and `d689e37d` (campaign, after the
kernel moved to 7.2.11 and the binary was rebuilt; the field responsible
for the change was not isolated because the runs did not archive their
field-level identity dumps).

| Arm | n | CPU accepts | GPU accepts | Verdict diffs | Max abs drift | Outcome |
|---|---|---|---|---|---|---|
| genuine LFW | 400 | 292 | 292 | 0 | 6.5565e-7 | PASS 7.4 and 7.5 |
| impostor LFW | 400 | 0 | 0 | 0 | 3.5763e-7 | PASS |
| FairFace Black | 371 | 0 | 0 | 0 | 3.5763e-7 | PASS |
| FairFace East Asian | 371 | 0 | 0 | 0 | 4.0233e-7 | PASS |
| FairFace Indian | 371 | 0 | 0 | 0 | 3.2783e-7 | PASS |
| FairFace Latino Hispanic | 371 | 1 | 1 | 0 | 3.2783e-7 | PASS (the single accept is a CPU baseline false accept the GPU repeats, not a new grant) |
| FairFace Middle Eastern | 371 | 0 | 0 | 0 | 3.1292e-7 | PASS |
| FairFace Southeast Asian | 371 | 0 | 0 | 0 | 3.8743e-7 | PASS |
| FairFace White | 371 | 0 | 0 | 0 | 3.7253e-7 | PASS |

Every shifted-threshold recount moved nothing. The drift values were
bit-identical between the probe identity and the campaign identity, so f32
GPU outputs reproduced across builds. The corpora lane's wall time matched
the f16 run within two minutes (77m33s against 75m42s); single-request
latency was not measured in these runs.

Campaign arms on `d689e37d`
(`artifacts/irlume/2026-10-19-f32-campaign/`, audit APPROVE-with-notes):

- Retained process, three runs of 1,000 calls (400 before any event, 300
  runtime-event calls, 300 system-event calls): 1,000 of 1,000 bit-exact
  in every run with the six boundary checks and the setup fingerprint
  unchanged. The third run proved a system suspend (sleep bounds grew
  15.999 s to 30.999 s around a 15 s `rtcwake`). No run observed a runtime
  suspend of the render node: the harness reported the runtime subset
  inconclusive (`RELIABILITY_COVERAGE_READY=false`), because the desktop
  session kept `renderD128` open and the device stayed active on kernel
  7.2.11. The ADR-0022 section 7.6 runtime subset is therefore still open
  for this identity.
- Power-management lifetime diagnostic: 5 of 5 stages, 301 samples each.
- Cache matrix: one seed in miss mode, 20 bypassed cold compiles, 20
  verified imports, 41 of 41 processes, 492 reference calls, no endurance
  calls. The f32 compiled blob is 263,474,861 bytes against 133,509,421 for
  f16.

Probe record: `artifacts/irlume/2026-10-19-f32-probe/`.

### Runtime-suspend witness, 2026-10-21

The identity `d689e37d` was re-seeded on 2026-10-21 (same digest after
the host's package updates of 2026-10-19) and the retained control ran
twice more from the same prefix, this time with the panel blanked through
the compositor (`kscreen-doctor --dpms off`) so the render node could
runtime-suspend under the `i915` 10 s autosuspend delay:

| Run | Reference waits | Runtime witness | System suspend | Counted calls |
|---|---|---|---|---|
| unattended | runtime 120 s, system 0 s | observed (counter growth 9 to 11 ms) | disabled by the reference | 1,000 of 1,000 bit-exact; 300 after the runtime event |
| combined | runtime 120 s, system 120 s | observed (9 to 11 ms) | proven: `rtcwake -m mem -s 15` 20 s after `RELIABILITY_READY`, s2idle entry 05:19:29Z, exit 05:19:45Z, sleep bounds 810.46 s to 825.41 s | 1,000 of 1,000 bit-exact; 300 after each event; `RELIABILITY_COVERAGE_READY=true` |

Every boundary (setup, before and after each event, final) kept the CPU
canary, the mapped inventory and the device binding unchanged. With the
2026-10-19 campaign this completes the ADR-0022 section 7.6 and 7.7
items for `d689e37d`. Archive:
`artifacts/irlume/2026-10-21-1053-f32-witness/thinkpad/` (controller
logs, render-node samples, unit journals, kernel suspend lines, the
reference files and the worker and controller scripts, with `SHA256SUMS`).

### UX5406S (the decision hardware), 2026-10-21

The f32 configuration ran on the UX5406S from a measurement build of
origin/main `5728309b` with this change (37 mapped libraries, identity
`ec747155`, kernel 7.2.11, the intel-npu-stack 2026.2.1 packages,
intel-compute-runtime 26.35.39758.11, process pinned to CPUs 0 to 3).
The identity lane, the compile-parity and retirement-trigger lane and the
cache control in bypass mode passed first; the real-frames and
recognition-corpora lanes then measured 13 arms in 3,291 s:

| Arm | n | CPU accepts | GPU accepts | CPU accept, GPU reject | CPU reject, GPU accept | Max abs drift | Lower shift delta | Upper shift delta | 7.4 | 7.5 lower / upper | Outcome |
|---|---|---|---|---|---|---|---|---|---|---|---|
| recorded genuine IR | 1474 | 992 | 992 | 0 | 0 | 7.45e-07 | 0/1474 | 0/1474 | PASS | PASS / PASS | PASS |
| recorded IR attacks | 138 | 0 | 0 | 0 | 0 | 5.96e-07 | 0/138 | 0/138 | PASS | PASS / PASS | PASS |
| recorded genuine RGB | 339 | 27 | 27 | 0 | 0 | 4.47e-07 | 0/339 | 0/339 | PASS | PASS / PASS | PASS |
| recorded RGB attacks | 209 | 13 | 13 | 0 | 0 | 5.36e-07 | 0/209 | 0/209 | PASS | PASS / PASS | PASS |
| FairFace impostor Black | 371 | 0 | 0 | 0 | 0 | 2.68e-07 | 0/371 | 0/371 | PASS | PASS / PASS | PASS |
| FairFace impostor East_Asian | 371 | 0 | 0 | 0 | 0 | 3.58e-07 | 0/371 | 0/371 | PASS | PASS / PASS | PASS |
| FairFace impostor Indian | 371 | 0 | 0 | 0 | 0 | 3.28e-07 | 0/371 | 0/371 | PASS | PASS / PASS | PASS |
| FairFace impostor Latino_Hispanic | 371 | 1 | 1 | 0 | 0 | 2.53e-07 | 0/371 | 0/371 | PASS | PASS / PASS | PASS |
| FairFace impostor Middle_Eastern | 371 | 0 | 0 | 0 | 0 | 2.53e-07 | 0/371 | 0/371 | PASS | PASS / PASS | PASS |
| FairFace impostor Southeast_Asian | 371 | 0 | 0 | 0 | 0 | 2.98e-07 | 0/371 | 0/371 | PASS | PASS / PASS | PASS |
| FairFace impostor White | 371 | 0 | 0 | 0 | 0 | 2.24e-07 | 0/371 | 0/371 | PASS | PASS / PASS | PASS |
| genuine LFW | 400 | 292 | 292 | 0 | 0 | 4.77e-07 | 0/400 | 0/400 | PASS | PASS / PASS | PASS |
| impostor LFW | 400 | 0 | 0 | 0 | 0 | 1.64e-07 | 0/400 | 0/400 | PASS | PASS / PASS | PASS |

All 13 arms pass both gates: maximum absolute drift 7.45e-7 (recorded
genuine IR), zero verdict differences in 5,557 comparisons, no new grant,
and no movement under either threshold shift. The two arms that failed at
f16 on this host (recorded genuine IR lower shift 5/1,474 and recorded
genuine RGB +1/339) pass with no movement. The single FairFace Latino
Hispanic accept is the same CPU baseline false accept the ThinkPad runs
record. The cache matrix of one seed, 20 bypassed compiles and 20
imports passed the same day (41 of 41 processes); the suspend and
power-management arms follow below. Archive:
`artifacts/irlume/2026-10-21-1053-f32-witness/ux5406s-f32-campaign/`
(lane logs, the measured-budget table, host facts, `SHA256SUMS`).

### UX5406S suspend and power-management arms, 2026-10-21

Run later the same day from a build of origin/main `5b275141` (the f32
configuration on main; identity `ec747155` unchanged), as root under
`systemd-run`, pinned to CPUs 0 to 3, with the panel blanked from the
owner's Plasma session (`kscreen-doctor --dpms off`) so the render node
could idle under the `xe` 1 s autosuspend delay:

| Lane | Result |
|---|---|
| Power-management lifetime diagnostic (60 s stages, 301 samples each) | 5 of 5 stages; `a_cpu_only` 206 of 301 samples suspended; `b_platform_only`, `c_retained_request`, `d_request_dropped` and `e_platform_dropped_libraries_retained` 0 of 301, panel dark throughout |
| Retained control, attended (runtime 120 s, system 120 s) | 1,000 of 1,000 bit-exact calls (400 before the runtime window, 300 after it, 300 after the resume); every boundary unchanged; runtime witness inconclusive (`missing event`, below); system suspend proven: `rtcwake -m mem -s 15` 20 s after `RELIABILITY_READY`, s2idle entry 13:38:55Z, exit 13:39:11Z, clock growth 10.94 s; `RELIABILITY_COVERAGE_READY=false` only because of the runtime arm; normal unit exit |
| Suspend-resume recheck, same suspend | `bounded clock growth proved suspend; post-resume bits and mapped inventory unchanged` |

The kernel froze user space in 0.004 s, suspended devices in 0.663 s and
resumed them in 0.249 s; `/sys/power/suspend_stats` went from 0 to 1
success with `last_hw_sleep` 8,969,440 µs, and the `pmc_core` SLP_S0
residency grew by the same amount (substate S0i2.1), so the platform
reached S0ix for about 9 s of the 16 s cycle. Neither process saw an
OpenVINO error and the kernel log has no xe engine reset. A first attempt
had failed in the kernel freezer, unrelated to the GPU: a language-server
process indexing the home directory was mid-`stat` on a FUSE mount and
stayed uninterruptible for the 20 s freeze timeout. FUSE mounts can block
s2idle on this host; the retry waited for the FUSE queues to drain first.

The runtime witness cannot be reached on this host with the model
retained, by driver design. With the panel dark the Arc 140V suspends
about 1 s after its last activity while no process has touched the
compute runtime; as soon as a process enumerates the OpenCL platform the
device stays `active` until that process exits, through context creation,
context release and the OpenVINO platform drop with the libraries still
mapped. A bare OpenCL probe reproduces it without OpenVINO (no OpenCL: 40
of 50 samples suspended; after `clGetPlatformIDs` and `clGetDeviceIDs`
alone, after a context is created and after it is released: 50 of 50
active), and the GPU suspended again within seconds of the lane processes
exiting (35 of 45 samples). The sources: kernel v7.2
`drivers/gpu/drm/xe/xe_vm.c` takes `xe_pm_runtime_get_noresume()` for
every VM created with `XE_VM_FLAG_LR_MODE` and releases it only when the
VM is destroyed (lines 1684 to 1686 and 1998 to 1999 at v7.2; 1679 to
1688 and 1995 to 1996 at v7.2.11), and intel/compute-runtime
26.35.39758.11 `shared/source/os_interface/linux/xe/ioctl_helper_xe.cpp`
(`getFlagsForVmCreate`) always sets `DRM_XE_VM_CREATE_FLAG_LR_MODE`,
creating the VM at device discovery (`NEOReadDebugKeys=1 PrintXeLogs=1
clinfo -l` logs `gemVmCreate f=0x2` on this host). The i915 ThinkPad has
no such hold, which is why its runtime witness passed with the model
retained. Two consequences: the ADR-0022 section 7.6 runtime subset needs
a decision for xe identities (accept the system-suspend proof plus the
documented hold, or define a witness that releases the compute-runtime
process, which then tests a fresh platform and compile after D3hot), and
a production daemon that keeps the GPU plugin loaded keeps an xe GPU in
D0 for its lifetime (the device is a Root Complex Integrated Endpoint, so
runtime suspend means D3hot and D3cold is never available). Both were
decided on 2026-10-22 in the ADR-0033 amendment of that date: the GPU
session stays in irlumed, and a hold witness meets the runtime arm on xe. The only
earlier lifetime diagnostic archived on the share (ThinkPad, 2026-10-13,
identity `45a24201`) recorded 0 of 301 suspended samples in every stage
including `a_cpu_only`, so it ran with the panel on; this is the first
lifetime diagnostic with a real idle observation.
Archive: `artifacts/irlume/2026-10-21-1053-ux5406s-pm/` (report, lane
logs, stage JSONs, kernel log, receipts, source copies, research notes,
`SHA256SUMS`).

## Observation: an efficiency-core-only CPU affinity aborts the GPU compile

Independent of the precision. On the UX5406S (Core Ultra 7 258V: CPUs 0
to 3 are the performance cores of `/sys/devices/cpu_core`, 4 to 7 the
efficiency cores of `/sys/devices/cpu_atom`), the compile lane aborts
with the libstdc++ assertion `__n < this->size()` (Fedora's hardened
build of OpenVINO 2026.2.1, `stl_vector.h:1253`) whenever the process
affinity mask holds two or more efficiency cores and no performance core.
Measured with the same binary, prefix and model:

| Affinity mask | f32 build | f16 build (origin/main) |
|---|---|---|
| CPUs 0,1,2,3 | pass | pass |
| CPUs 4,5,6,7 | abort (8 of 8 runs) | abort |
| CPUs 4,5 | abort | not run |
| CPUs 0,4 | pass | not run |
| CPU 6 | pass | not run |
| no mask (0 to 7) | pass | not run |

The backtrace under `gdb` places the assertion in
`ov::threading::IStreamsExecutor::Config::update_executor_config()`,
called from the GPU plugin's `make_task_executor_config` while
`ov::Core::compile_model` builds the program. In the 2026.2.1 source
(`src/inference/src/dev/threading/istreams_executor.cpp`, unchanged in
2026.4.1), the streams table is filled only from the `MAIN_CORE_PROC`,
`EFFICIENT_CORE_PROC` and `HYPER_THREADING_PROC` columns of the
affinity-filtered processor table; the Lunar Lake efficiency cores are
classified as `LP_EFFICIENT_CORE_PROC`, so an efficiency-core-only mask
leaves the table empty and the function then reads
`_streams_info_table[0]`. A single allowed CPU takes the one-stream path
that pushes an `ALL_PROC` row first, which is why one efficiency core
passes. Every earlier campaign pinned to CPUs 0 to 3, so this never
surfaced before. Consequences for ADR-0033 phase 5: the launch profile
must not confine the daemon to efficiency cores only, and the GPU lanes
keep the performance-core pin. The crash reproduces with the GPU plugin's
default host-task priority; it is reported upstream as a plugin defect
rather than worked around in the compile configuration. Evidence:
`artifacts/irlume/2026-10-21-1053-f32-witness/ux5406s-affinity-crash/`.

## Reading

- The f16 default is outside the ADR-0022 section 7.5 budget on both
  identities and outside 7.4 on the UX5406S recorded genuine RGB arm. No
  sample-size argument rescues it: one flip at n=400 is already 0.25
  points, and the drift-to-points conversion gives about 0.26 points.
- f32 is inside both gates by about three orders of magnitude on the
  ThinkPad with zero verdict differences. The precision hint governs
  regardless of the execution mode: the 2026.2.1 GPU plugin derives a
  precision from `EXECUTION_MODE_HINT` only when no `inference_precision`
  was set (`apply_execution_hints`, `execution_config.cpp`), and its option
  table defaults the precision to `f16`.
- Costs: about twice the compiled-blob size; no measurable wall-time cost
  on the corpora lane. Single-request latency under f32 remains to be
  measured on the decision hardware.
- Still open after this record: on the decision hardware, the ADR-0022
  section 7.6 runtime-suspend subset (unreachable with the model retained
  on xe, see above; met by the hold witness of the ADR-0033 amendment of
  2026-10-22), plus the
  ADR-0022 section 7.3 items no GPU run has measured yet (IR recognition
  corpora, paired fusion, calibration and profile selection, enrollments
  up to 90 scans, the decision fingerprint over every arm). The ThinkPad
  runtime-suspend witness, the f32 real-frames arms, the UX5406S cache
  matrix, power-management diagnostic and system-suspend proof are closed
  above.
