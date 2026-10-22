# Intra-op pools for the ViT PAD cue and the recognizer

Date: 2026-10-22 · Baseline: `main` e2980253 · Issue: #1173 · No threshold,
vote or model changed. Archives live on the shared project store under
`artifacts/irlume/2026-10-22-latency-r1r2/`, each directory with a
`SHA256SUMS` manifest.

## Question

Every ONNX session runs with two intra-op threads (`ORT_INTRA_THREADS`,
#508). The ViT RGB PAD cue (`PadVit`) and the recognizer (`Embedder`) are the
heavy part of a grant: on the BRIO grouped route the five per-sample liveness
stages, which hold the ViT runs, took 0.86 to 0.89 s and identity inference
0.34 to 0.35 s (#856; 0.89 to 0.92 s and 0.34 to 0.35 s in this note's main
grants). The cap came from four core-sized
pools contending with capture and consent-watch threads; the consent watch no
longer exists. How large should their pools be, and how should their threads
be placed?

## Method

`heavy_pool_bench` (research only, not in the tree) loads the production
`PadVit` and `Embedder` from the shipped weights and, after a 2 s idle, times
one grouped evaluation's worth of their work: five `p_spoof` calls on
640x480 frames, then `embed_tta` and `embed` (three recognizer runs). Six
trials per process; each process reports its upper median (the fourth of
six). Inputs are synthetic and deterministic. Each process also runs the same
calls once untimed and prints an FNV-1a digest of every output bit. The bench
is built from WIP a12ee08e with a research-only override that sets the pool;
for these hosts the override's thread counts and masks name the same CPUs as
the shipped `heavy_pool` (which writes the 5700G's set as the interval `1-8`).
Variants run in a fixed order within each round:

- `2 threads`: today's pool.
- `unpinned`: one thread per physical core, no affinity.
- `cores - 2`: two fewer, no affinity (on the N100, four threads: the same
  configuration as `unpinned`, pooled with it).
- `per-core pinned`: one thread per core, each extra thread pinned to its
  own core's CPUs, the first core left to the caller (the shape of ONNX
  Runtime's default).
- `ORT default`: `intra_op_num_threads = 0`.
- `one CPU per core`: one thread per core, every extra thread allowed only
  the first CPU of each core (the chosen rule where cores have siblings).

| host | runtime | notes |
|---|---|---|
| Ryzen 7 5700G, 8C/16T | ONNX Runtime 1.28.1 (the irlumed library) | a browser renderer at about 16% CPU throughout |
| i5-1335U, 2P (SMT) + 8E | 1.28.1 | load not recorded |
| N100, 4C | 1.29.0 | shares the host with a self-hosted CI runner; load not recorded per round |
| Core Ultra 7 258V, 4P + 4LPE, no SMT | 1.28.1 | a desktop in use; load not recorded |

The 258V's two-thread and first unpinned figures come from an earlier run of
the same binary and options, three rounds alternating two and eight threads
(`ux5406s-258v-baseline.txt`); every other figure comes from the sweep
scripts in the archive.

## Results

Median and range of the per-process medians in ms, rounded with halves up,
and the number of processes:

| host | 2 threads | unpinned | cores - 2 | per-core pinned | ORT default | one CPU per core |
|---|---|---|---|---|---|---|
| 5700G | 1228 (1205-1232), 3 | 713 (695-740), 6 | 637 (620-657), 8 | 601 (551-691), 6 | 567 (523-687), 11 | 561 (535-682), 8 |
| i5-1335U | 1090 (1089-1094), 3 | 597 (586-615), 6 | 676 (660-690), 3 | 704 (700-715), 6 | 691 (639-712), 6 | 613 (596-615), 3 |
| N100 | 3077 (3074-3083), 3 | 2026 (1943-2576), 6 | = unpinned | 2005 (1957-2885), 3 | 2199 (1947-3529), 3 | = unpinned |
| 258V | 1733 (1720-1813), 3 | 847 (833-971), 6 | | 853 (817-866), 3 | 823 (791-828), 3 | 850 (849-885), 3 |

The columns pool sweeps that ran minutes apart, and the same configuration
moved between them (5700G `per-core pinned` 551 to 589 in one sweep, 612 to
691 in the next), so differences between columns under about 100 ms on the
5700G and the N100 do not read. The comparisons below pair variants within
the same round of the same sweep, against `unpinned`, in ms:

| host | cores - 2 | per-core pinned | ORT default | one CPU per core |
|---|---|---|---|---|
| 5700G | -120, -91, -50 | -189, -137, -129, -4, -84, -60 | -204, -102, -120, -171, -154, -197 | -144, -142, -39 |
| i5-1335U | +74, +98, +78 | +115, +110, +102, +110, +102, +100 | +53, +111, +49, +116, +69, +94 | +1, +2, 0 |
| 258V | | +20, -154, +25 | -5, -148, -50 | +16, -86, +10 |

On the N100 one round each of `ORT default`, `cores - 2` (four unpinned
threads, the unpinned configuration) and `per-core pinned` ran 626 to 1488 ms
above the same round's unpinned run, so its placements cannot be ranked. Every
run on every host, including ONNX Runtime 1.29.0 on the N100, printed the
same digest, `db639ec93f9cf549`: the outputs were bit-identical at every
pool, placement, runtime and microarchitecture tried.

## Placement

1. On the 5700G every confined placement beat `unpinned` in every paired
   round, and eight unpinned threads were slower than six. That fits
   unpinned threads stacking on SMT siblings; thread placement itself was
   not recorded.
2. On the i5-1335U, pinning each thread to its own core cost 100 to 115 ms
   in every paired round as `per-core pinned` and 49 to 116 ms as ONNX
   Runtime's default, while the one-CPU-per-core mask matched `unpinned`. The
   258V did not show the penalty, and the cause was not isolated. ONNX Runtime's
   documentation advises leaving affinity to the OS
   ([threading](https://onnxruntime.ai/docs/performance/tune-performance/threading.html)),
   and on Windows clients its own default does not pin, citing P-core/E-core
   scheduling
   ([`thread_utils.cc`](https://github.com/microsoft/onnxruntime/blob/rel-1.28.0/onnxruntime/core/util/thread_utils.cc)).
3. On both hosts where the rule applies the mask (cores with siblings), it
   was no worse than the best placement measured there; on the 5700G it
   cannot be told apart from ONNX Runtime's default (each faster in four of
   eight paired rounds). On the 258V, where the rule runs unpinned, ONNX
   Runtime's default was faster than unpinned in all three paired rounds, by
   5, 148 and 50 ms.

The default is still not used, because it ignores the process's CPU mask. It
takes the core list from cpuinfo, every core of the machine, and pins one
thread to each
([`posix/env.cc`](https://github.com/microsoft/onnxruntime/blob/rel-1.28.0/onnxruntime/core/platform/posix/env.cc)).
Run under `taskset -c 0-3` on the 5700G, the mask systemd's `CPUAffinity=`
also sets, the bench's two sessions pinned their 14 pool threads to the core
pairs `1,9` to `7,15` with no message: every one of them may run outside the
four CPUs the process was given, and the eight on `4,12` to `7,15` only
outside them. Under a cpuset the same calls fail for every core outside it
([sched_setaffinity(2)](https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html),
EINVAL), and those threads run on the cpuset's CPUs as well, a pool sized
for the whole machine. The affinity string's ids count from 1, and there is one
entry per thread beyond the caller's
([config keys](https://github.com/microsoft/onnxruntime/blob/rel-1.28.0/include/onnxruntime/core/session/onnxruntime_session_options_config_keys.h));
each entry is one `first-last` interval or a comma list, never both
(`ReadThreadAffinityConfig` in
[`thread_utils.cc`](https://github.com/microsoft/onnxruntime/blob/rel-1.28.0/onnxruntime/core/util/thread_utils.cc)).

## Decision

`heavy_pool` (`crates/irlume-vision/src/lib.rs`), read from the building
thread's `sched_getaffinity` mask and each allowed CPU's `core_cpus_list`
every time a heavy session is built:

- one thread per allowed physical core, bounded by `available_parallelism`
  (a cgroup quota), never fewer than two and never more than sixteen, the
  largest pool the bit-identity gate compares;
- where some core holds two or more allowed CPUs, every thread beyond the
  caller's may use only the first allowed CPU of each core
  (`session.intra_op_thread_affinities`; the caller's thread keeps its own
  mask, as in the measured variant); otherwise no affinity;
- an affinity longer than 4096 bytes, the config value limit up to ONNX
  Runtime 1.24.2 (8192 from 1.24.3; `config_options.h`), is left out: with
  interleaved sibling numbering that is past 82 cores;
- a CPU whose topology cannot be read is skipped (the mask names active
  CPUs only; its `/proc` fallback past 1024 CPUs can name offline ones), and
  a topology that cannot be read at all keeps two threads;
- a pool that fails to build (an affinity the runtime refuses, threads a
  task limit will not start) loads at the two-thread pool with a warning, so
  the pool never takes face authentication down; a failure the small pool
  shares returns its first error without one.

The small models keep two threads.
`model_tests::heavy_models_answer_bit_identically_at_every_pool` holds both
models bit-identical on every CI runner at every pool production can pick
(2 to 16), at the runner's own pool, and with an explicit affinity in both
notations, built without the fallback, and it compares the recognizer's CPU
reference digest, the producer enrollment records for its templates
(ADR-0022 §2), so for those pools the producer does not change with the
pool. The bench digests cover the measured pools on four AVX2 hosts (none
with AVX-512) for fixed synthetic inputs.

The pool reads its mask with `sched_getaffinity`, which needs no file and no
AppArmor rule; Rust's `available_parallelism` reads the unit's `cpu.max`,
which the shipped profile denied, so a `CPUQuota=` went unseen. The profiles
now grant it. In an Ubuntu 24.04 VM (AppArmor 4.0.1, enforce, a unit with
`CPUQuota=200%`), a probe making exactly the pool's reads as
`/usr/bin/irlumed` logged two `cpu.max` denials and saw 8 CPUs under the old
profile, and none and 2 CPUs under the new one; the previous revision's
`/proc/thread-self/status` read was denied under both. Archive: `apparmor/`.

## Effect on a grant

On the BRIO (archhost), attended `irlume auth test` grants ran with the
installed daemon replaced per block through a runtime drop-in. In the
second run (`attended2/irlume-r1r2-stages-2.json`; builds of `main`
95f78c14 and of this change at 0ddb863a, whose runtime code is this
revision's; three warm and two cold grants each), this change took the
warm grouped evaluation from 1385 to 746 ms, identity inference from 342 to
166 ms and the engine span less the capture from 1490 to 857 ms (cold
evaluation 1422 to 739 ms). The first run (`irlume-r1r2-stages.json`;
`main` e2980253 and revision 3242dcfe, whose pool on this host is the same
eight threads on the same CPUs; four warm and two cold grants each, all
granted) measured 1379 to 699, 348 to 143 and 1488 to 805 ms. In the
second run one of six trials on each build was refused, as a password
fallback: on `main` a no-match, on this change a not-live from the IR
brightness cue on the first sample, which reads the IR frame only; that
cue ran close to its floor on every build in that run.

## Capture while the models run

The heavy models can run while a camera streams: held-session pair
assessments keep both streams on through inference (`self_heal_may_recapture`
in `crates/irlume-auth/src/lib.rs`), and with #1174 the grouped route scores
its RGB half during the IR phase. On the
258V (eight cores, no SMT, IR at 15 fps), the general sequential-IR path ran
15 captures without and 15 with a continuous eight-thread ViT and recognizer
load in a separate process. That load is more sustained than any production
overlap but is not the same burst at IR session start, and the host was not
otherwise idle (load average 2.4 to 5.0 at block starts; a language server
used about 80% of one core in both conditions). All 30 captures succeeded
with no rate-fill failure. The first round of each process was cold in both
conditions (setup 2198 to 2231 ms without the load, 2175 to 2194 with it;
rate fill 1999 to 2000 ms). In rounds 2 to 5, setup measured 922 to 952 ms
without the load and 897 to 932 ms with it, and rate fill 731 to 732 and 730
to 733 ms. Bursts followed the IR brightness plateau (201 to 268 ms, and 474
and 605 ms when the plateau needed seven to nine frames) except for an
unexplained 2.2 s burst mode in 5 of 15 rounds without the load and 7 of 15
with it, clustered (all of one block in each condition, plus two single
rounds under load); with three blocks per condition, an effect of load on
that mode cannot be excluded. Archive: `ir-under-load/`.

## Limits

- No host with more than ten cores was measured; the cap keeps larger hosts
  at sixteen threads, the largest pool the gate compares.
- No cgroup CPU quota on hardware, no cpuset and no NUMA host was measured;
  the quota read is checked in the VM above, the mask logic is unit-tested.
- The pinning penalty on the i5-1335U was not explained, the variant order
  was fixed, and power state was not recorded.
- No camera host with four cores (the N100 has none attached) ran the
  capture check.

Archive: `pool-sweep/` (per-host sweep logs, the bench and sweep scripts, the
research-only override patch, `pool_table.py` behind both tables),
`ortdefault-mask/`, `apparmor/`, `ir-under-load/`, and for the attended
grants `irlume-r1r2-stages.json` and `attended2/` (stage timings and
categorical outcomes; no score, frame or measurement).
