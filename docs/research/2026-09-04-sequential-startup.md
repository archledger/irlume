# Sequential camera startup

The RGB rate fill now reuses valid timing evidence gathered during auto-exposure
warm-up. The pixels are still discarded. With no RGB startup exclusion, resetting
that evidence required seven redundant dequeues before the same full rate window
could be checked.

Sequential IR now measures its full 30-interval window before spending the existing
ten-dequeue startup exclusion budget. A healthy stream proceeds earlier. A slow
stream slides the window forward by at most ten additional dequeues, then the
normal delivery gate accepts or returns its typed rate failure. The initial fill
still has its 64-attempt bound; per-dequeue timeouts propagate immediately.

The explicit sequential IR API is used by authentication's sequential path and
fallback, and qualification's sequential control. Ordinary IR one-shot APIs, held
sessions and concurrent paired rate fill retain their existing startup behavior.
No shorter evidence window, lower rate floor, concurrency override, new setting,
model change or dependency is introduced. Recovery epochs, corrupt payload handling,
privacy/emitter checks and downstream matching/liveness gates remain in place.

## Measurements, 2026-09-04

Release builds on base `8d86e55e3c930153c1ab842b480ab0452c6c83d1`, comparing before
both startup changes with the combined candidate. Hardware validation used the same
capture/authentication implementation in an audit checkout; that checkout's separate
unused-classifier removal and diagnostic wording changes are excluded from this PR.
Baseline source recompilation and distinct executable hashes were verified before
measurement. No images, embeddings, credentials or match/liveness scores were saved.

| Device and scope | Before | Candidate | Reduction |
|---|---:|---:|---:|
| ASUS, full Engine authentication mean | 7.960 s | 6.835 s | 14.1% |
| BRIO, RGB+IR capture median | 5.857 s | 5.032 s | 14.1% |
| NexiGo N930W, RGB+IR capture median | 8.476 s | 7.496 s | 11.6% |

ASUS genuine-user order was before/after/after/before: two samples per build, all
four granted. Engine timing includes enrollment loading, capture and inference;
model initialization is excluded because the daemon keeps models resident. Each
remote camera repeated that order twice: four samples per build, all eight captures
passed. Remote timing starts after lease acquisition and includes camera open,
setup, capture and teardown; it excludes authentication and PAM. NexiGo had more
open/teardown variation: candidate samples ranged from 7.378 to 8.052 s.

ASUS out-of-view trials both refused after two capture attempts. Those single
samples were not isolated from build-phase load and are not a latency benchmark.
A real candidate PAM module plus private candidate daemon granted in 6.843 s.
A subsequent runtime-only candidate daemon activation also passed the actual KDE
Wayland lock-screen test using the installed PAM stack and stored sequential mode:
the user confirmed face-only unlock, followed by a separate out-of-view refusal
while still locked and a successful password fallback. Installed binaries, PAM,
settings and enrollment files were unchanged after restoration.

These small functional samples do not establish false-accept rates, spoof
resistance, all lighting/startup conditions, cold-boot keyring behavior or other
desktops. Thirteen synthetic regression cases cover warm-up reuse, full-window
requirements, legacy IR exclusion, slow/bursty startup, late shortfalls, corrupt or
invalid input, timeout propagation and recovery without stale rate evidence.
