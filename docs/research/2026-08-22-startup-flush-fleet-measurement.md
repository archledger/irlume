# Startup flush and sequential capture-path latency — fleet measurement

Date: 2026-08-22
Agent: opencode
Worktree: `perf/capture-latency` (base `1354b723`)
Status: flush change implemented and measured; skew decision proposed, not taken

## The problem

Every authentication on a sequential-schedule host (both dual-camera fleet
hosts today: ASUS qualification-v2 `sequential_required`, minihost
`sequential_required`) paid, per stream, a rate-evidence fill of 30 discarded
startup frames plus a 30-delta measurement window: ~61 dequeues ≈ 4.4 s at the
delivered 13.7-15 fps. Measured on the ASUS auth path (`auth_timing`, real
root-owned state, no face present, daemon stopped):

```
TOTAL authenticate_for: 10.38s
  RgbCapture: 5136 ms   (capture burst itself: 267 ms)
  IrCapture:  4966 ms   (capture burst itself: 600 ms)
  assess: rgb/ir capture skew 4380ms (limit 3000ms) -> RGB discarded
```

Two distinct costs: the fill itself (~8.8 s of the 10.1 s capture stage), and
the structural consequence — the second stream's fill sits BETWEEN the two
capture bursts, so the inter-window gap (4.38 s) always exceeds
`MAX_CROSS_SPECTRUM_SKEW` (3 s) and the RGB evidence is discarded on every
sequential auth.

## Method

New probe `irlume_camera::startup_probe` (module) + `startup_transient.rs`
(example): streams N raw validated dequeues through the same `SafeStream`
boundary the production gate wraps, with NO tracked gating, recording per
attempt: index, validity, driver sequence, driver timestamp, dequeue offset.
The example then simulates the production fill for flush sizes 0..=30
("discard K dequeue attempts, then seed a 30-delta window of successful
dequeue timestamps; does it meet the spectrum floor at 98%?").

Three runs per node, deterministic results (identical to the frame in most
cells). Daemon units stopped during all runs.

## Evidence

| host | node | role | seq gaps (96-110 frames) | flush-0 window | flush-3 | flush-10 | flush-15 | flush-30 |
|---|---|---|---|---|---|---|---|---|
| ASUS UX5406S | /dev/video2 | IR | 0 | 15.000 fps PASS | pass | pass | pass | pass |
| ASUS UX5406S | /dev/video0 | RGB | 0 | 14.91 fps PASS (floor 7.5) | pass | pass | pass | pass |
| minihost (NexiGo N930W) | /dev/video2 | IR | 0 | **14.018 FAIL** | 14.676-14.705 MIXED | 14.76-14.79 PASS | 14.763 PASS | 14.763-14.792 PASS |
| minihost (NexiGo N930W) | /dev/video0 | RGB | 0 | 29.64 fps PASS | pass | pass | pass | pass |
| archhost (Logitech Brio) | /dev/video0 | RGB | 0 | 14.88-15.92 PASS | pass | pass | pass | pass |

Fine sweep on the NexiGo IR (the only node whose startup transient is real):
windows seeded at dequeues 0/1/2 measure 14.018/14.678/14.677 (FAIL), dequeue
3 is the tail (14.676-14.705, mixed across runs), dequeue 4+ is settled
(≥14.734). The transient is ≤4 frames.

Findings:

1. **Single-stream startup has zero sequence gaps on every measured node.**
   The 32-gap startup transient that motivated the original 30-frame flush
   (RATE_STARTUP_FLUSH rationale) was measured under dual-load starvation
   during slice-8 development (hermes 2026-08-19, the concurrent-mode bug),
   not single-stream STREAMON. The flush's sequence-continuity rationale does
   not apply to what the sequential path actually does.
2. **The flush is load-bearing only on the NexiGo IR, only for ~4 frames.**
3. **No RGB node needs any flush** (2x-4x floor margin from dequeue 0).
4. Pre-existing, unrelated: the NexiGo IR's STEADY-STATE window measures
   14.73-14.79 fps against the 14.7 floor — ~0.4% margin. This is true today
   at flush 30 as well. Any drift tips that host into fail-closed capture
   errors. Follow-up deserving its own look (floor tolerance vs the NexiGo's
   negotiated interval).

## Change made

`rate_gate::startup_flush(role)`: IR 10 dequeues (2.5x the measured 4-frame
tail), RGB 0 — replacing the unconditional 30 for both roles, at both flush
sites (`TrackedStream::fill_rate_evidence`, concurrent
`drain_until_both_ready`). A camera whose transient exceeds its role's flush
still fails CLOSED (window misses floor -> capture error -> password
fallback), loudly.

### Measured effect (ASUS auth path, same conditions as the baseline)

```
TOTAL authenticate_for: 7.04s   (was 10.38s, -32%)
  RgbCapture: 3127 ms   (was 5136)
  IrCapture:  3632 ms   (was 4966)
  assess: rgb/ir capture skew 3050ms (was 4380ms; limit 3000ms)
```

## The skew question (proposed, not changed)

Post-change, the sequential inter-burst gap is 3050 ms — 50 ms over the 3 s
pairing limit. The gap is now almost entirely the second stream's rate
evidence (10 flush + 30 window dequeues ≈ 2.67 s) plus open/negotiate
(~0.3 s). Options, all needing an owner decision because they change which
spoof cues run on which hosts:

1. **Schedule-aware skew budget.** `MAX_CROSS_SPECTRUM_SKEW` (3 s) was
   calibrated for CONCURRENT retry/self-heal stacking ("3 s of GAP means
   something went wrong rather than slow"). Sequential's NORMAL gap is
   machinery-sized by construction. A sequential-aware bound (e.g. the
   qualification-measured machinery bound for the exact pair, or a constant
   ~6 s) would let sequential pairs be judged. Security note: accepting the
   pair ADDS RGB evidence (co-location, RGB pose, ViT PAD) on top of the
   independently gated IR path — the system already grants via IrOnly when
   the pair is stale, so rejecting the pair today removes evidence rather
   than adding safety. The limit change is a loosening in name only, but it
   IS a spoof-cue constant and deserves an ADR.
2. **Pre-arm the second stream during the first capture** (open + REQBUFS,
   no STREAMON; the concurrent path already arms both before streaming, so
   the arming precedent exists on this hardware). Saves the ~0.3 s
   open/negotiate from the gap: ~2.75 s < 3 s, pairing passes with thin
   margin. Needs measurement on both dual hosts; dual-incapable cameras
   must tolerate arm-without-stream (untested on the NexiGo).
3. **Window 30 -> 25** (slice-8's measured minimum): saves 0.33 s but zero
   margin against the measured minimum, and thins the NexiGo's already thin
   steady-state margin. Not recommended.

**Interaction with PR #516 (ViT RGB PAD):** on BOTH dual fleet hosts
(sequential schedule), the cross-spectrum pairing is skew-discarded in
production auth, so the ViT cue wired in #516 is unreachable there today
(it runs only via `assess_probe`, and on the RGB-only hosts via the
RGB-only tier). Whichever skew option is chosen un-blocks (or permanently
retires) the ViT on dual hosts; that decision should be made explicitly.

## Fleet validation status for this change

- Probe evidence (this document): ASUS RGB+IR, NexiGo RGB+IR, Brio RGB —
  3 runs each, all in the table above.
- Physical continuity stress (production TrackedStream path): PENDING in
  this session — sequential stress on ASUS + minihost; archhost has no IR
  node (probe + auth-path evidence only).
- thinkpad (Chicony, RGB-only): OFFLINE, validation pending user return.
  The four-host camera-change rule blocks merge until then.

## Follow-ups recorded

- NexiGo steady-state rate margin (14.73-14.79 vs 14.7 floor) — pre-existing.
- Grace-window retries re-pay the full per-capture opens (~6.8 s post-change
  per attempt on ASUS): an attempt that starts with less remaining time than
  the previous attempt took will overrun the deadline mid-capture, holding
  the camera past the window for a guaranteed-useless result. A
  remaining-time-vs-last-attempt-cost bound in `authentication_attempt_loop`
  is a small honest fix; not in this change.
- The 3 s skew decision (options above) gates the value of everything else
  on sequential hosts.
