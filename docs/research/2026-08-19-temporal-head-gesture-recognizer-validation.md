# Temporal head-gesture recognizer validation

Date: 2026-08-19

Status: complete; recommends a participant-disjoint velocity-direction pilot
before any production recognizer design

## Question

Is the proposed deterministic position-phase state machine—five alternating
position phases, two-sample dwell, and a 48-frame span—the right production
replacement for irlume's range/crossing head-gesture classifier?

## Short answer

No, not as proposed.

The position-phase design produced no terminal verdict on the available
negative pose corpus, but detected only 2 of 41 historical nod recordings when
using the proposed two-sample dwell. Removing dwell improved that to only 12 of
41. Implementing that design would likely replace false terminal verdicts with
severe genuine-user rejection.

A different deterministic model based on **directions of head velocity** is
promising in the local corpus: one five-direction configuration produced zero
terminal verdicts on all 62 pose-capable negative recordings, correctly
classified all four repeated one-minute nod/shake recordings, and classified
39 of 41 historical nod recordings. This agrees with primary literature, which
models direction or angular velocity over time rather than absolute
position-relative lobes.

That result is not sufficient for a global release. All pose-capable local
recordings are from one participant and one primary camera, only two raw shake
recordings exist, parameters were selected and evaluated on the same corpus,
and the raw trajectories behind the latest live false verdicts were intentionally
not retained. The correct conclusion is **promising research direction, not
validated production policy**.

## Security and accessibility requirements

NIST defines authentication intent as an explicit response to each
authentication request. It also says passive face capture does not necessarily
show intent and gives tapping a software or physical button as an explicit
mechanism. See [NIST SP 800-63B-4, section 3.2.8](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=959882).

NIST does not evaluate or endorse head gesture as that mechanism. Applying its
intent requirement to irlume is a security-design inference, not a claim that
the guideline approves this gesture design.

The gesture therefore has to discriminate deliberate prompted action from
ordinary motion. Merely recognizing something that resembles a conversational
nod is insufficient for a high-privilege intent gate.

W3C's motion-actuation guidance explicitly covers face gestures observed by a
camera. It calls for a conventional alternative and the ability to disable
motion input because some users cannot perform precise movement and others may
trigger it accidentally due to tremor or motor impairment. See
[WCAG 2.2 Understanding SC 2.5.4](https://www.w3.org/WAI/WCAG22/Understanding/motion-actuation.html)
and [Technique G213](https://www.w3.org/WAI/WCAG22/Techniques/general/G213).

WCAG governs web content, not Linux PAM. It is used here as authoritative human
factors guidance for camera-observed motion input, not as a claim of irlume
conformance.

irlume's password/fingerprint fallback and per-service gesture disablement are
therefore load-bearing accessibility controls. Requiring more repeated movement
cannot be treated as a free security improvement.

## What primary recognition research says

### Temporal direction matters

Kapoor and Picard represented consecutive head-movement directions as five
symbols—up, down, left, right, and none—and used separate three-state HMMs for
nod and shake. Their system was tested on natural data from ten users and
reported 78.46% overall recognition accuracy. They also noted that sequence
window length affects whether slow gestures are detected. See
[A Real-Time Head Nod and Shake Detector](https://www.microsoft.com/en-us/research/publication/real-time-head-nod-shake-detector/).

Morency et al. used 3-D head angular velocity, resampling, and windowed FFT
features for an SVM, and compared that with HMMs. Their training data included
natural gestures, commanded gestures, and three minutes of explicit negative
head movement. On nine held-out interactions, the vision-only detector reached
75% nod and 84% shake true-positive rates at a 5% false-positive rate. Adding
dialog context improved the reported operating point, but did not make the
visual signal intrinsically unambiguous. See
[Contextual Recognition of Head Gestures](https://people.csail.mit.edu/lmorency/Papers/icmi05-lp-final.pdf).

A 2021 continuous-stream HMM study used direction/motion states, velocity,
duration, sliding windows, and subject-wise validation. On a 78-gesture
validation set it reported 88.51% precision, 98.72% recall, 93.34% F1, ten false
positives, and one false negative. It also observed duplicate detections from
overlapping online windows. See
[HMM-based Detection of Head Nods to Evaluate Conversational Engagement](https://eurasip.org/Proceedings/Eusipco/Eusipco2021/pdfs/0001301.pdf).

These results support temporal velocity/direction modeling, negative-motion
data, and subject-disjoint evaluation. They do not support expecting zero error
from a small universal threshold rule.

### Prompt context helps but does not solve accidental activation

The Headbang interaction technique used a touch-and-hold action to arm a short
back-and-forth head gesture. Across 12 participants it reported 95.22% task
success and 1.39-second average completion, but the authors explicitly listed
accidental activation as unresolved future work. The study evaluated prompted
target execution, not high-privilege false intent. See
[Headbang: Using Head Gestures to Trigger Discrete Actions on Mobile Devices](https://doi.org/10.1145/3379503.3403538).

This supports a clearly armed prompt and immediate feedback, but it is not
evidence that a hands-free gesture alone is a sufficiently reliable security
confirmation.

### Trained sequence models require a real corpus

Recent on-device work uses HMMs, cascaded HMMs, DTW, KNN-DTW, LSTM, or GRU over
pose/IMU sequences. Examples include
[Real-time on-device nod and shake recognition](https://arxiv.org/abs/1806.04776),
[Real-Time Head Gesture Recognition on Head-Mounted Displays](https://arxiv.org/abs/1707.06691),
and [HeadText](https://arxiv.org/abs/2205.09978).

Those methods are alternatives only after representative, participant-disjoint
training and evaluation data exists. irlume does not currently have that data,
and adopting a trained model now would add opacity, model provenance, and
packaging work without establishing generalization.

The cited systems also use different sensors and tasks—pupil tracking, 3-D head
trackers, HMD IMUs, phone depth cameras, and conversational labeling. Their
reported numbers cannot be transferred directly to irlume's five-landmark IR
pose signal. Their value is methodological: temporal direction/velocity,
explicit negative motion, context, and participant-disjoint evaluation.

## Local evidence audited

### Pose-capable recordings

The usable raw pose corpus contains:

| Label | Recordings | Role |
|---|---:|---|
| seated nod | 21 | historical positive |
| reclined nod | 20 | historical positive |
| look-around | 20 | negative |
| still | 21 | negative |
| reclined still | 21 | negative |
| one-minute seated nod | 1 | repeated positive |
| one-minute reclined nod | 1 | repeated positive |
| one-minute seated shake | 1 | repeated positive |
| one-minute reclined shake | 1 | repeated positive |

The eye-era look-down, blink, closure, squint, AE-settle, and spoof files do not
contain pose trajectories. They cannot validate a head recognizer and were
excluded from the negative denominator. The usable negative count is therefore
62, not 149.

The live hardware matrix contributes bounded aggregate evidence but no raw
trajectory. It documents real false verdicts, but cannot be replayed through a
new temporal recognizer.

### Existing production classifier

Replaying the 20 raw look-around recordings through `e48d221` produced 18
`None`, one `NoFace`, and one false `Nod` at frame 24. The fresh five-attempt
look-around campaign under the same OID produced four `no-gesture` outcomes and
one false `declined` outcome. This is why `e48d221` remains NO-SHIP.

## Throwaway evaluator

A disposable standard-library Python evaluator was created at
`/tmp/irlume-temporal-evaluator.py` and was not added to the repository. Its
final SHA-256 is
`3154798b5448e26800a86f08dca764b1eb264b738e7da8eb794401a00097447d`
for the evaluated script; it is explicitly not a production artifact or an
independent oracle.

It mirrors:

- conservative bright-strobe parity selection;
- paired finite pitch/yaw observations;
- raw-index continuity;
- rolling six-frame evaluation and completed-take fallback;
- existing absolute pitch/yaw gates and axis-dominance checks.

It compared three deterministic families:

1. position relative to a median;
2. thresholded per-frame velocity directions;
3. hysteretic turning-point swings.

The evaluator intentionally did not test HMM, DTW, or learned models because
there is no participant-disjoint training corpus.

Three synthetic sanity assertions require the selected velocity model to label
an ideal vertical sequence as nod, an ideal horizontal sequence as shake, and a
still sequence as none. These catch gross evaluator breakage; they are not an
independent validation of its implementation.

## Offline results

The unconstrained numerical winner was a three-phase hysteretic swing model
with 40/41 historical nods, but three phases encode one complete cycle
(`A-B-A`). It violates the explicitly approved two-cycle intent policy and is
not a candidate. The table compares the requested five-phase/two-cycle forms.

| Prototype | Negative terminal verdicts | Repeated positives | Historical nods | Finding |
|---|---:|---:|---:|---|
| proposed position phases, dwell 2, five phases, span 48 | 0/62 | 4/4 | 2/41 | unacceptable recall |
| position phases, no dwell, five phases, span 48 | 0/62 | 4/4 | 12/41 | unacceptable recall |
| hysteretic swings, five phases, span 48, low swing threshold | 0/62 | 4/4 | 31/41 | better, still weak |
| velocity directions, five phases, span 48, pitch 0.004/frame, yaw 0.04/frame | 0/62 | 4/4 | 38/41 | promising |
| velocity directions, five phases, span 48, pitch 0.002/frame, yaw 0.03/frame | 0/62 | 4/4 | 39/41 | best two-cycle local recall |
| velocity directions with causal median-3 smoothing | 0/62 | 4/4 | 26-28/41 | smoothing harmed recall |
| velocity directions with two-observation neutral arming | 0/62 | 2/4 | 18/41 | old recordings do not support this flow |

For the velocity family, pitch thresholds from 0.002 to 0.004 per raw frame and
yaw thresholds from 0.03 to 0.05 produced a local zero-negative-error plateau
while preserving all four repeated positives. Lowering yaw velocity to 0.02
produced one false look-around shake; lowering it to 0.01 produced three. This
shows a measurable local margin, but also that the shake decision remains
sensitive to a hardware- and participant-dependent velocity threshold.

The 48-, 60-, and 75-frame spans tied on the best local counts. A 48-frame span
is therefore the smallest supported candidate, not a proven universal timing
limit.

## Why these numbers still do not validate release policy

1. **One participant:** no participant-held-out result exists.
2. **One primary camera:** pose and velocity scale may shift across detector,
   focal length, position, and frame cadence.
3. **Only two raw shakes:** shake recall and dominance have almost no coverage.
4. **Selection bias:** configurations were chosen using the same corpus on
   which results are reported.
5. **Missing hard negatives:** talking, coughing, posture changes, tremor,
   wheelchair motion, motor impairments, and natural prompted behavior are not
   represented.
6. **No raw live failures:** the newest false verdict trajectories cannot test a
   replacement directly.
7. **No identical-motion solution:** a casual movement that is kinematically
   identical to the prompted gesture is not distinguishable from intent by pose
   alone.

Zero errors in 62 same-participant negatives is useful falsification evidence,
not a security false-actuation estimate.

No primary source establishes an acceptable false-actuation target for a head
gesture used as a high-privilege authentication-intent control. The product must
set that risk target explicitly before a pilot can claim success. A pilot of ten
participants is a minimum opportunity to falsify the design and compare with
prior study scale; it is not, by itself, proof of a sufficiently low security
error rate.

## Adversarial assessment of the first design

The first design assumed that absolute position lobes plus dwell would remove
noise while preserving deliberate cycles. The corpus directly disproves the
preservation claim: only 2/41 historical nods survive. It also selected exact
span, dwell, and dominance values before participant-disjoint evidence existed.

The first design should not proceed to production implementation.

## Review status

The user directed this work to remain single-agent. The adversarial review was
therefore a degraded fresh-prompt self-review rather than an independent agent
review. It found and corrected:

- eye-era files without pose being counted as recognizer negatives;
- missing prototype sanity assertions;
- an incorrect publication DOI;
- overstatement of NIST endorsement and WCAG applicability;
- transfer of results across incompatible sensors and tasks;
- treating ten participants as proof rather than a minimum falsification pilot;
- omission of the unresolved product false-actuation target.

The user explicitly skipped the offered cross-model review. The recommendation
therefore rests on primary sources, local corpus falsification, parameter
sensitivity, and this disclosed single-model limitation.

## Final recommendation

### If head gesture remains the high-privilege intent mechanism

Run a research-only pilot for a **velocity-direction** recognizer before writing
production code:

1. Capture pose-only data—never images or embeddings—from at least ten
   participants, matching the scale of primary studies (9-15 participants).
2. Include at least three camera/host configurations, seated and reclined
   posture, glasses where applicable, and natural hard negatives.
3. Explicitly capture repeated nod, repeated shake, still, casual look-around,
   look-down-and-hold, talking, coughing, posture adjustment, and interrupted
   gestures.
4. Split participants, not recordings: tune on one participant set and evaluate
   once on untouched participants.
5. Freeze preprocessing and thresholds before held-out evaluation.
6. Report false approval, false decline, genuine completion, no-face, and
   latency separately. Do not collapse them into overall accuracy.
7. Require zero approvals and declines on held-out negative trials, then state
   the statistical limit honestly; zero observed errors does not prove zero
   risk.
8. Test accessibility fallback and per-service motion disablement explicitly.

The research candidate should start from five velocity-direction phases within
48 raw frames, with pitch velocity in the observed 0.002-0.004 plateau and yaw
velocity in the 0.03-0.05 plateau. These are experiment ranges, not production
constants.

### If that data collection is not acceptable

Do not make camera-observed head motion the default high-privilege intent
mechanism. Use an explicit conventional action such as a keypress or prompt
button, as recommended by NIST's authentication-intent examples, and retain
head gestures only as an optional convenience mechanism with password or
fingerprint fallback.

This alternative has a lower research burden and a clearer accessibility story.
It also changes the original product decision, so it requires explicit product
approval rather than being inferred from this report.

## Conclusion

The research prevented the intended failure mode: implementing and qualifying a
plausible but wrong design. The proposed position-phase state machine is not the
right approach. Velocity-direction temporal recognition is the strongest local
candidate and is consistent with primary literature, but irlume's present corpus
cannot establish that it generalizes safely enough for default high-privilege
authorization.

The next decision is product-level, not a threshold choice:

- fund a participant-disjoint pose-only pilot for the velocity recognizer; or
- use conventional explicit confirmation by default and keep motion optional.
