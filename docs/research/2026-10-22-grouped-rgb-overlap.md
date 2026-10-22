# The RGB half of grouped samples during the IR phase

Date: 2026-10-22 · Issue: #1174 · Stacked on #1173 (the heavy-model pools) ·
No threshold, vote, model or capture change. Archives live on the shared
project store under `artifacts/irlume/2026-10-22-latency-r1r2/`, each
directory with a `SHA256SUMS` manifest.

## Question

On the grouped sequential route, `authenticate_grouped_once` captures five
RGB samples, releases RGB, captures five IR samples, releases IR, and only
then evaluates every sample. On the BRIO the evaluation after both releases
took 1.37 to 1.42 s, of which the five per-sample liveness stages, which
hold the five ViT RGB PAD runs, took 0.86 to 0.89 s (#856). A sample's RGB
face detection and ViT score depend on its RGB frame alone. Can they run
while the IR session captures, without changing the decision?

## Change

`irlume_camera::capture_sequential_batch_overlapped` runs a caller's closure
over the released RGB samples on a scoped thread while the IR session
captures on the calling thread. The RGB session is dropped before the
thread starts; when the IR phase ends, with its samples or not, the closure
is asked to stop and hands back what it finished; the thread joins before
pair validation on every path; a panicking worker resumes its panic after
the IR session is released. The grouped route's closure
(`grouped_auth::RgbHalfModels`) runs YuNet and the ViT for each frame in
order, with side-effect-free reads of the request's cancellation and window.

The evaluation consumes each result where it used to make the same calls:
`adopt_rgb_detection` repeats the direct detection's checks, error and log
lines and runs the rescue detector itself when YuNet found nothing, and
`rgb_pad_answer` uses a precomputed ViT answer only for the frame it was
computed for (its capture window) and the bit-identical face box, recomputing
otherwise. Everything else, including every `check_request_active`, the vote
ring, the refusals and identity for the final admissible sample, runs where
it ran before. The worker scores the top RGB face of each sample it
reaches, also ones a later verdict does not consume; only a Live frame
consumes a score.

The decision's inputs are those of the serial order, so only its timing
differs, near the authentication deadline and in either direction. The
evaluation is shorter, so an attempt the serial order would have expired can
reach its grant or refusal. When the IR phase ends the batch waits for the
worker's call in flight, which can be one the serial order never makes (a
ViT run for a frame no Live verdict consumes), so an attempt the serial order
would have decided can expire instead, which strikes: one it would have
refused without a retry strike (an uncertain or IR-faceless sample) or
granted (the final sample on the dark IR-only route after such samples).
Either way it is a password-fallback denial or a grant on complete evidence.

## Verification

- Camera crate: the worker reads the released samples while IR captures,
  the stop stays down during the IR phase and rises when a healthy or failed
  IR phase ends, a worker panic resumes after the IR session is released, and
  an unwinding IR phase joins the worker (`sequential_batch_tests.rs`).
- Auth crate: the worker's order, stop points and detector-error handling,
  each half's capture window taken from its own camera frame, the
  bit-for-bit box rule, where a precomputed ViT answer is consumed
  (`vit_pad_evidence`), the adopted detection against the direct one (error,
  cancellation and deadline points included), the route's wiring of each
  half to its own sample, and a real ViT session scored from a scoped thread
  against the same call on the evaluating thread
  (`engine_tests/grouped_tests.rs`, `engine_tests/split_capture_tests.rs`).
- Hardware, the BRIO on archhost (Ryzen 7 5700G), attended, a research-only
  build (`research_patch_v2.py`, not committed). Wherever the evaluation
  adopted the worker's detection it also ran the detector on the same frame
  and compared every box, score and landmark bit. Wherever it used a
  precomputed ViT answer it recomputed the answer serially and compared the
  bits. Nine assessments in eight operations covered the default pool, the
  two-thread pools of `main`, a worker stopped after its second detection, a
  head turned away and a person leaving the view. All 39 adopted detections
  and all 27 precomputed ViT answers equalled their serial counterparts. In
  the stopped runs the second sample's half carried a detection without a
  ViT answer, and the evaluation computed that answer and the three
  remaining samples itself, as designed. The person leaving the view left
  one face in the first RGB half and none after. The evaluation refused that
  sample (an RGB face without an IR face), found no face in the rest,
  retried once on new frames that held no face, and denied. The turned head
  was granted: its head-yaw measure stayed inside the frontal limit, so that
  trial tested no new refusal. The first attended run's cross-check, at the
  default pool, matched all ten ViT answers of its two grants.

## Measured effect

Attended BRIO grants on archhost, `irlume auth test` from the seat with
`irlume trace` recording, the installed daemon replaced per block through a
runtime drop-in by a build of `main` 95f78c14, of #1173 alone (0ddb863a), of
#1173 with this change (d51012f6), or of this change on `main`'s two-thread
heavy pools (the research build with `IRLUME_RESEARCH_HEAVY_THREADS=2`).
Blocks of three ran in the order main, #1173, both, two-thread, then the
cross-check blocks and the refusal prompts, then two-thread, both, #1173,
main. The first grant of each block follows a daemon start, so it also pays
the cold delivered-rate evidence (R4 in the 2026-10-21 latency report,
`artifacts/irlume/2026-10-21-latency-research/REPORT.md`); the rest are
warm. Of the 24 timing trials 21 granted; the three refusals are below.
Medians and ranges of the granted operations, in ms:

| stage | main | #1173 | #1173 + this | this, two-thread pools |
|---|---|---|---|---|
| warm grants | 3 | 3 | 3 | 4 |
| engine span | 6994 (6829-7142) | 6409 (6150-6445) | 6129 (5728-6150) | 6023 (5908-6320) |
| sequential capture | 5504 (5343-5647) | 5527 (5293-5662) | 5735 (5347-5788) | 5481 (5364-5774) |
| IR session start | 857 (850-858) | 851 (851-859) | 850 (850-858) | 854 (850-858) |
| IR start + samples | 1967 (1823-2102) | 1960 (1760-2104) | 2168 (1827-2228) | 1967 (1826-2227) |
| evaluation after the IR release | 1385 (1382-1391) | 746 (680-778) | 275 (260-291) | 439 (437-441) |
| identity inference | 342 (340-345) | 166 (142-182) | 174 (160-190) | 341 (336-344) |
| engine span minus capture | 1490 (1485-1495) | 857 (782-882) | 381 (362-394) | 543 (541-546) |
| cold engine span (n=2) | 9248 (9200-9296) | 8627 (8610-8644) | 8055 (7998-8113) | 8317 (8263-8371) |
| cold evaluation after the IR release | 1422 | 739 | 255 | 450 |

The evaluation after the IR release is the `grouped_evaluation` stage, and
the capture is the sum of the six sequential stages. The engine span varies
with the capture, mainly with how long the IR samples take to arrive, so
the span minus the capture is the cleaner comparison. On top of #1173 this
change takes 476 ms off a warm grant there (857 to 381 ms), and on
`main`'s two-thread pools 947 ms (1490 to 543 ms). The first attended run
(`irlume-r1r2-stages.json`, 20 of 20 granted, builds of `main` e2980253,
an earlier #1173 revision with the same pool on this host, and both)
measured 1488, 805 and 378 ms.

Where the worker runs, from the traces. With the pools of #1173 its last
record ended 342 to 395 ms before the IR session start ended (cold 1034 to
1044 ms), so it never overlapped an IR sample. On `main`'s two-thread pools
its last ViT run ended 84 to 102 ms after the IR session start, during the
first IR sample, in all four warm grants (cold 531 to 539 ms before). In
every operation of both runs, the cross-check builds included, the worker
had finished at least 876 ms before the IR release, so the batch never
waited for it. The IR phase is not measurably longer: over both runs the
warm IR start and samples took 1964 (1760-2226) ms in 14 grants without the
overlap and 1967 (1755-2285) ms in 11 with it, the IR session start 845 to
872 and 837 to 860 ms.

In the traces of this change the worker's five `detection` and five
`liveness` records lie in the IR phase; `finalization` holds the
evaluation's five IR detections, its five `liveness` records, identity and
`grouped_evaluation`, where on `main` it held ten detections. `irlume trace
analyze` reads all 32 traces of the run; the residual outside any stage
measured 19 to 22 ms.

Identity inference rose by 8 and 26 ms with this change on the pools of
#1173 (174 against 166 ms warm here, 169 against 143 in the first run), not
on two-thread pools (341 against 342). In the warm timing grants of both
runs the recognizer now starts 1.4 to 2.0 s after the worker's last ViT run
on the pools of #1173 and 1.0 to 1.5 s on the two-thread pools, instead of
right after the evaluation's. An unattended bench on archhost with the
production pools and synthetic input (`idle_embed_bench.rs`; three
processes, ten rounds
each, load average 4.0 at the start just after the build and 0.9 at the
end) timed three recognizer runs at 134 to 147 ms (process medians) right
after five ViT runs, 164 to 175 ms after the same runs and a 1.5 s pause,
and 166 to 180 ms after 2 s idle without them. So the rise matches the
recognizer starting after a pause; why a pause costs the eight-thread pool
about 30 ms was not isolated.

Capture while a heavy model runs was also measured with a continuous
eight-thread ViT and recognizer load on a host without SMT (the UX5406S, IR
at 15 fps); that load is more sustained than this overlap and not its burst
at IR session start (docs/research/2026-10-22-heavy-model-pools.md, #1173).

### Refusals in the timing trials

Three of the 24 look-at-the-camera trials were refused, each a password
fallback. On `main` one was a no-match after five live samples. On #1173
alone and with this change one each was not-live: the IR brightness cue
refused the first sample, and that cue reads the IR frame only. In this run
the IR brightness of every trial on every build sat much closer to that
cue's floor than in the first run (morning light at the seat, the ambient
share of the IR frame several times higher), and in 19 of the 29 trials
that scored more than one sample the first was the darkest. Neither refusal
depends on the RGB half: one is on a build without the overlap, and the
cue reads the IR face box and frame, which the RGB half does not feed.

## Limits

- One RGB+IR camera host ran the grouped route (the BRIO on an SMT part); no
  four-core camera host was available. The two-thread pools stand in for a
  slower CPU, and there the overlap reached only the first IR sample.
- 32 attended operations in this run (the 24 timing trials and eight
  cross-check operations) and 20 in the first, by one person in one room;
  the refusal coverage is one person leaving the view, and no presentation
  attack was tried.
- No hardware run put the deadline inside the worker's call in flight; the
  unit tests cover the cancellation and deadline points.
- The measured builds predate the final revision. Since them this change
  moved its ViT site into `vit_pad_evidence` without changing its behaviour
  and moved and reworded one debug line; #1173's runtime code is unchanged.
- The managed concurrent route, the split route and the RGB-only grouped
  route are unchanged.

Archive: `attended2/` (this run: `irlume-r1r2-stages-2.json` with the stage
timings and categorical outcome of every operation, outcomes, the
cross-check lines, `irlume trace analyze` output, the seat, build, export
and table scripts, the research patch, the bench and its results; no score,
frame or measurement) and `irlume-r1r2-stages.json` (the first run).
