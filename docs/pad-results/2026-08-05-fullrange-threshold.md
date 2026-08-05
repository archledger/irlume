# Full-range BlazeFace operating threshold, measured through irlume, 2026-08-05

Stage 3 of #295: the measurement that sets the `fullrange` catalog entry's
threshold and decides whether the detection stage opens. The #294 bench
measured this model through Google's runtime; this measures it through
irlume's own decoder and preprocessing, which is what will actually run,
and against a population #294 never captured: the empty scene.

- **Instrument:** `examples/blaze_full_parity --floor 0.01` (the floor is
  dropped so the sub-threshold distribution is visible; at the default 0.6
  every negative reads as a clean non-detection and the margin is
  invisible). Raw per-frame scores:
  `2026-08-05-fullrange-threshold-scores.csv`, 512 rows.
- **Corpus:** the 2026-08-05 stage-3 corpus extended the same evening with
  the conditions it lacked. Genuine, both cameras: frontal, close (~30cm),
  far (~1m), pose sweep, glasses, plus **dim** (Zenbook, lights out) and
  **dusk** (archhost, lights out with residual outdoor light). Negative,
  both cameras: **empty scenes** with the subject out of frame, captured
  in each lighting state (empty-dim, empty-dusk, empty-lit). 384 genuine
  frames, 128 empty.
- **Artifact:** the pinned `blaze_face_full_range.tflite` (sha256
  `3698b18f…2b181b`) on the bundled TFLite runtime.

## The populations

| population | frames | max score | notes |
|---|---:|---:|---|
| empty scene (all) | 128 | **0.5293** | top scores are near-black IR frames (frame mean 4 to 32): the model reading sensor noise |
| empty scene, 95th pct | 128 | 0.4059 | |
| genuine, exposure-usable | 291 | 0.9642 | frames with mean between 8 and 235 |
| genuine, degenerate exposure | 93 | 0.8507 | near-black or near-saturated strobe phases, excluded from the false-reject side as an exposure question, not a threshold one |

## Threshold selection

| threshold | genuine misses | empty admits |
|---|---:|---:|
| 0.45 | 60 / 291 | 3 / 128 |
| 0.50 | 60 / 291 | 1 / 128 |
| **0.53** | 61 / 291 | **0 / 128** |
| **0.55** | 61 / 291 | **0 / 128** |
| 0.60 | 61 / 291 | 0 / 128 |
| 0.65 | 65 / 291 | 0 / 128 |

**0.55 is enabled.** The empty-scene population decides it: 0.5, the shipped
short-range rescue's own operating point, admits a false detection on a
near-black IR frame. Everything from 0.53 up admits none. The genuine side
is FLAT across that whole range (60 to 61 misses at every candidate from
0.45 to 0.6), because those misses are frames scoring about 0.10, which is a
non-detection at any threshold rather than a threshold effect. So the choice
costs nothing genuine, and 0.55 sits in the middle of the flat region with
0.02 of margin over the highest empty-scene score.

## Findings

1. **An empty room is not a zero.** The model returns a box for every frame;
   on near-black IR it reached 0.5293, above the shipped rescue's threshold.
   A detection threshold for this model cannot be inherited from the
   short-range one, which is what makes this measurement load-bearing rather
   than a formality.
2. **A false detection here is not an authentication event.** The rescue slot
   feeds a coarse box into the FaceMesh refine, alignment, recognition, and
   the liveness gates; an empty-room box cannot match a template, and the
   #293 geometry gates already refuse implausible boxes. The threshold trades
   wasted pipeline work against missed rescues, not access.
3. **True-dark detection is uneven per frame, and the corpus says so.** In
   the Zenbook dim segment the emitter strobe produced frames the model
   scored 0.85 and frames it scored 0.10, alternating within one burst.
   Because an authentication attempt captures many frames and the rescue only
   needs to fire once, this is a per-frame observation, not a per-attempt
   failure rate; no per-attempt dark rescue rate is measured here.
4. **The genuine floor for frames that do detect stays well clear.** Lit-frame
   ranges by segment run 0.526 (nexigo sweep, pose extreme) to 0.964, with
   every other segment's minimum at 0.60 or above.

## What this does not establish

- One subject, two cameras, one session per condition. Nothing here is a
  population false-accept rate, and none is claimed: the negative population
  is empty rooms, not other people's faces, because the question for a
  detector is "does it invent a face", not "whose face is it".
- No per-attempt rates, only per-frame. The daemon's own behaviour under the
  wired entry was validated separately (a live enable/disable run on this
  hardware); throughput, latency, and dark-rescue attempt rates are
  unmeasured.
- The degenerate-exposure frames were excluded from the false-reject side by
  a mean-brightness rule (8 to 235), stated here so the exclusion is
  auditable; including them raises the miss count to 153 of 384 and does not
  move the threshold, since those frames score about 0.10 at every candidate.
