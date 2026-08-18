# Issue #173: closure-calibration profiles without widening consent

Date: 2026-08-18

Issue: [#173 — Closure calibration is one snapshot per user, but glasses change
the eye it measured](https://github.com/archledger/irlume/issues/173)

## Decision

Support more than one closure calibration, but **never accept a gesture against
every stored calibration**. The production target should be a fail-closed,
two-stage state machine:

1. While closure acceptance is disarmed, collect a clean, frontal, stable
   open-eye prefix.
2. Select exactly one calibration whose enrolled open range uniquely contains
   that prefix and whose enrolled closed range does not overlap it.
3. Lock that calibration for the entire authorization attempt, discard the
   selection prefix from the gesture samples, and only then arm the existing
   bounded close-and-reopen detector.
4. If the prefix is missing, out of range, consistent with a closed state, or
   consistent with more than one profile, do not select a nearest fallback.
   Closure remains unavailable; `Either` mode can still accept a nod and
   `Closure` mode falls back to the password.

This is a safety-engineering conclusion, not an algorithm already validated by
the literature. The primary literature establishes condition and subject
variation, gaze/squint confounding, and the danger of contaminated or
unsupervised adaptation. It does **not** establish automatic selection among
multiple stored closure calibrations. The current project evidence is one
subject on one camera. Therefore the smallest safe first implementation is an
evidence-only slice: record the would-be selector inputs and verdicts without
changing authorization, then collect a held-out matrix of genuine closures,
downward gaze, squint, ambiguity, glasses, and lighting conditions. Storage and
the production selector should follow only after the selector rule and margins
are fixed from that evidence.

## Scope and pinned artifacts

This note audits GitHub `main` at
[`f1e20e9e5270a4791737fa618bf24f4aa921463d`](https://github.com/archledger/irlume/commit/f1e20e9e5270a4791737fa618bf24f4aa921463d).
It changes no code and repeats no hardware measurement.

| Artifact | Git blob |
|---|---|
| `crates/irlume-core/src/storage.rs` | `b51f28225bbacc430a1497a6543bcfd5a8e15163` |
| `crates/irlume-common/src/lib.rs` | `e46dc06d9281020091b2f963d5f172d46f761d38` |
| `crates/irlume-liveness/src/lib.rs` | `dced31b7699024041aabc4c05bf2fe6271cb6bfe` |
| `crates/irlume-auth/src/lib.rs` | `f14596d582b28045e255ba4b091d7b15711e9289` |
| `crates/irlume-cli/src/main.rs` | `711525eb5df1af13f02b80c26d8cf4b69542a09b` |

Repository measurements are treated as project evidence reported by the issue
or checked-in measurement notes, not as independently reproduced results.
External sources are original papers, author/institution repositories, and
official platform or serialization documentation.

## What the current system actually does

The on-disk `Enrollment` has one
[`Option<(f32, f32)>`](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-core/src/storage.rs#L176-L195),
representing the median open and closed EAR. `calibrate-closure` captures three
open/closed rounds by default, takes each median, verifies a minimum `0.05` gap,
and reports how many of the enrollment readings would pass the resulting
thresholds. It then sends the single
[`SetClosureCalibration`](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-common/src/lib.rs#L505-L516)
request, whose daemon handler replaces the tuple.

At authentication, a usable tuple becomes one runtime `ClosureCalibration`.
The detector classifies a closure below

```text
closed + 0.30 * (open - closed)
```

for 11–25 face frames, then requires a reopen above

```text
closed + 0.60 * (open - closed)
```

within four frames. These are an enrolled absolute threshold and a bounded
temporal shape, not a per-attempt relative baseline; see the
[`ClosureCalibration` and detector contract](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-liveness/src/lib.rs#L1832-L1980).

The same authorization may watch twice: an early pre-match watch exists so a
gesture made when the PAM prompt appears is not missed, and a post-match watch
uses the remaining budget. The current watch begins evaluating the accumulated
EAR sequence every six frames as soon as frames arrive; it has no profile
selection phase. The relevant flow is
[`early_consent_watch`](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-auth/src/lib.rs#L4216-L4249)
and
[`consent_watch`](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-auth/src/lib.rs#L4281-L4358).
Any selector must therefore work before an early gesture, and its lock must
survive the transition from the early watch through matching to the post-match
watch. Selecting afresh in each watch would let one authorization be tested
under two thresholds.

## Evidence that drives the design

### The effect is condition-dependent, not a uniform offset

Issue #173 reports five captures in each state from one subject on the ASUS FHD
IR module:

| State | Observed range | Median |
|---|---:|---:|
| glasses off, open | 0.2460–0.2541 | 0.2527 |
| glasses off, closed | 0.0162–0.0267 | 0.0178 |
| glasses on, open | 0.2598–0.2885 | 0.2710 |
| glasses on, closed | 0.1065–0.1303 | 0.1128 |

The open median moved by 0.0183, while the closed median moved by 0.0950
(6.3×). A bare-eyed calibration yields a closed threshold of 0.0883 and
registered 0/5 glasses-on closures. A glasses-on calibration yields 0.1603 and
registered all captured closures in both states. Those figures come directly
from the issue's
[`2026-08-04 measurement comment`](https://github.com/archledger/irlume/issues/173#issuecomment-5175356292).

That apparent one-profile workaround has a safety cost already documented in
the shipped CLI. An excluded “open” run while the operator looked down at the
terminal read 0.07–0.16. The glasses-on threshold classifies that entire band as
closed; a roughly one-second glance down followed by looking back at the camera
can have the same below-threshold-run-plus-reopen shape as the consent gesture.
The exact concern and arithmetic are preserved in
[`closure_calibration_intro`](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-cli/src/main.rs#L720-L770).

Independent primary evidence supports treating this as a real confound rather
than an odd local trace. Frigerio et al.'s controlled 24-participant IR sensor
study reported false blink detections during 46.5% of downward gaze changes,
versus 6.3% lateral and 10.4% upward, and reported disruption from substantial
squinting ([JAMA Facial Plastic Surgery, DOI
10.1001/jamafacial.2014.1](https://pubmed.ncbi.nlm.nih.gov/24699708/)). Its
wearable beam sensor is not EAR, so the percentages cannot be transferred to
irlume; what transfers is the demonstrated ambiguity between eyelid closure,
downward gaze, and squint in an IR eye signal. BlinkLinMulT also treats head
pose, lighting, reflection, appearance, and temporal features as jointly
relevant and reports condition-stratified performance differences
([Fodor et al. 2023](https://doi.org/10.3390/jimaging9100196)).

### Multiple enrollment conditions are reasonable; their decision rule matters

Microsoft's official Windows Hello documentation describes enrollment as a set
of representations and specifically recommends additional enrollment for
occasional glasses and high ambient near-IR environments. It also performs a
head-orientation check before its decision
([Windows Hello face authentication](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-face-authentication)).
That supports representing condition diversity; it does not specify how an EAR
consent gesture should choose a calibration.

Personalized thresholds have empirical support. A 2026 study reports fixed
EAR/MAR thresholds failing to generalize across facial structure, illumination,
and driving conditions, with a 2–3 percentage-point accuracy improvement from
driver-specific calibration
([Ersoy et al., arXiv:2604.22479](https://arxiv.org/abs/2604.22479)). The
original EAR work likewise notes that a low EAR can be an intentional closure,
expression, or landmark error rather than a blink and finds temporal modeling
more reliable than a fixed threshold
([Soukupová 2016 thesis](https://cmp.felk.cvut.cz/ftp/articles/cech/Soukupova-TR-2016-05.pdf),
building on the original
[CVWW paper](https://vision.fe.uni-lj.si/cvww2016/proceedings/papers/05.pdf)).
These sources justify subject/condition calibration and temporal checks, but
none validates a multi-profile selector for a credential-release gesture.

### A mutable baseline is not the same as a clean prefix

The current source deliberately rejects a running median: once a deliberate
closure occupies most of the window, it pulls the “open” median toward the
closed value and can make itself disappear. This follows directly from the
11–25-frame held-closure contract and is stated in the
[`ClosureCalibration` documentation](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-liveness/src/lib.rs#L1832-L1856).

Related primary evidence points in the same direction. Mathôt et al. show that
blink/data-loss samples in a pupil baseline can materially distort baseline
correction and recommend rejecting contaminated baseline trials
([Behavior Research Methods 2018](https://pubmed.ncbi.nlm.nih.gov/29330763/)).
That is pupil size rather than EAR, so applying it here is an arithmetic and
safety inference, not a direct replication. Soukupová's adaptive HMM learned a
half-open squint as the new open state and then made symmetric errors when the
squint ended; adaptation can normalize the adversarial state it is supposed to
distinguish. At the stored-template level, Lovisotto et al. demonstrate that
unsupervised biometric updates can be poisoned and distinguish them from
supervised updates with independent identity assurance
([EuroS&P 2020](https://conferences.computer.org/eurosp/pdfs/EuroSP2020-2psedXWK6U4prXdo7t91Gm/508700a184/508700a184.pdf)).

Consequently:

- a pre-gesture prefix that is validated once and frozen is defensible;
- a statistic that continues moving after the gesture can start is not; and
- normal authentication must never modify stored calibration profiles.

## Threat model and invariants

This gesture authorizes polkit actions and release of a reusable keyring secret
after a face match. Availability failures fall back to another gesture or the
password; false acceptance weakens an explicit-consent boundary. The design
must therefore prefer a visible refusal over extrapolation.

The relevant adversarial or confused inputs are:

- a real matched user looking down at a keyboard or prompt without intending
  consent;
- a held or timed squint followed by reopening;
- a user beginning the capture already closed, before any clean open prefix;
- a lighting/glasses condition outside every enrolled profile;
- a prefix equally compatible with two profiles;
- transient landmark errors or exposure settling; and
- a presentation attack that produces a closure-like EAR trace. Profile
  selection is not PAD and must not be credited as one.

The non-negotiable invariants are:

1. At most one closure profile can contribute to one authorization decision.
2. No closure sample can contribute to profile selection or baseline update.
3. The detector remains disarmed until selection is complete.
4. Selection never chooses the nearest profile outside an enrolled acceptance
   region and never breaks a tie.
5. A locked profile cannot change across early watch, face matching, retries,
   or post-match watch.
6. A shake decline stays terminal and cannot be reinterpreted by closure logic.
7. Missing, invalid, ambiguous, or out-of-range evidence cannot enable closure.
8. Authentication never writes profile state.

## Comparison of the five candidate designs

| Design | Availability | False-accept effect | Verdict |
|---|---|---|---|
| Accept against any stored calibration | Highest | The effective accepted set is the union of every profile; a permissive condition can authorize a trace rejected by the correct condition | Reject |
| Named/manual active profile | Predictable when the user switches correctly | No union, but stale/wrong selection can retain a permissive threshold and is easy to forget at a PAM prompt | Useful management/fallback, not the automatic default |
| Select from pre-gesture open frames, then lock | Can cover conditions without user interaction | Safe only with bounded, unique selection and a clean prefix; forced-nearest is unsafe | Recommended target |
| Within-burst adaptive baseline | Smooth when the starting state is clean | Closure/squint can pollute or become the baseline; behavior changes during the decision | Reject for production consent |
| Ambiguous/out-of-range fail closed | More password/nod fallbacks | Does not widen the accepted set | Mandatory policy around every design |

### 1. Accepting against any calibration

Running `detect_deliberate_closure(samples, cal)` for every profile and OR-ing
the results is compact but wrong. In #173's measured pair, the glasses profile's
0.1603 closed threshold admits the full 0.07–0.16 downward-looking band that the
bare profile mostly rejects. Adding that profile would broaden consent even
when the live user is bare-eyed.

This is the same direction as the general biometric OR rule: it reduces false
rejects while increasing false accepts. Daugman's primary analysis gives the
independent-test formula and explains the operating-point tradeoff
([University of Cambridge Technical Report 482](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-482.html)).
Closure profiles are correlated, so its numerical formula must not be applied
to them; set inclusion is sufficient here—the union cannot have fewer false
accepts than either member.

### 2. Named/manual active profiles

Names such as `desk-glasses` and `night-no-glasses` help users understand and
replace data. An explicit active profile also guarantees one threshold rather
than a union. However, a user cannot reasonably switch persistent state every
time a polkit prompt appears. Selecting a stale glasses profile while bare-eyed
retains the exact downward-gaze exposure above. Manual selection is therefore
appropriate for diagnostics, an operator-controlled fallback, or a first data
collection tool—not sufficient as the unattended runtime policy. A live
out-of-range guard is still required.

Names must remain labels, not a glasses classifier. The underlying variation is
continuous across lens reflections, light, gaze, distance, and landmark error;
the machine decision must use measured enrollment ranges, not the string.

### 3. Pre-gesture selection and lock

This is the only candidate that represents multiple conditions without unioning
their closure thresholds or trusting a persistent manual switch. “Nearest” must
mean **the only eligible profile**, not the least-distant profile among all
profiles.

The selector needs repeated enrollment observations, not just two medians. For
each profile it needs at least an enrolled open acceptance region and a closed
exclusion region derived from explicitly prompted, quality-gated rounds. At
runtime it should:

1. Start in `Selecting`, with closure detection disabled.
2. Gather a stable prefix after rejecting non-finite landmarks, bad framing,
   out-of-policy head pose, and exposure/transient failures.
3. Refuse selection if the prefix is compatible with any enrolled closed
   region. This prevents one condition's closed eye from serving as another
   condition's “open” baseline.
4. Find profiles whose open region contains the complete observed prefix under
   a prevalidated margin.
5. Lock only if exactly one remains and it has required clearance from the next
   candidate. Zero or multiple candidates produce `Unavailable`, never a
   nearest fallback.
6. Clear the selection samples, enter `Armed(locked_profile)`, and begin the
   existing bounded close-and-reopen detector at frame zero.
7. Carry the lock across both consent watches. If later quality/context leaves
   the validated envelope, make closure unavailable; do not switch profiles.

The required prefix length, stability statistic, pose envelope, and margins are
not established by current evidence and must come from the evidence-only slice.
Hard-coding them from five captures would turn measurement noise into policy.
The instruction also needs to become sequential—“look at the camera, then close
your eyes”—because a user who starts closed cannot provide a selectable open
prefix and must safely miss rather than be guessed through.

### 4. Within-burst adaptive baselines

A rolling median over the whole watch is directly incompatible with a gesture
whose closed portion deliberately lasts 11–25 frames. Updating only on samples
classified as open is circular when the mutable baseline is what classifies
them, and Soukupová's squint adaptation demonstrates the failure shape. Using a
maximum or upper quantile may resist closure pollution but becomes sensitive to
landmark spikes and has no project validation.

If “adaptive” is narrowed to a clean prefix that is frozen before any gesture
sample, it is no longer this option; it is option 3. No stored profile should be
updated from successful authentication samples.

### 5. Ambiguity and out-of-range handling

This is not a separate convenience feature. It is the condition that makes
option 3 safe:

- no face/eyes or insufficient valid prefix → unavailable;
- prefix begins in a closed-like region → unavailable;
- no open region contains the prefix → unavailable;
- two open regions contain it or clearance is insufficient → unavailable;
- quality/pose changes after lock → unavailable, without reselection; and
- exactly one eligible profile → lock it once.

The fallback already exists. In `Either`, the nod is independent of closure
calibration. In `Closure`, the password is the safe result. The UI and journal
should distinguish “profile ambiguous/out of range” from “gesture not seen”
without logging raw EAR values or user-chosen condition names by default.

## Backward-compatible storage and IPC migration

### On-disk representation

The current encrypted payload is ordinary JSON serialized from `Enrollment`;
old plaintext and encrypted forms converge through the same deserializer
([storage serialization](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-core/src/storage.rs#L528-L595)).
The least disruptive new shape is additive:

```rust
struct ClosureCalibrationProfile {
    name: String,
    ear_open: f32,
    ear_closed: f32,
    open_observed_min: f32,
    open_observed_max: f32,
    closed_observed_min: f32,
    closed_observed_max: f32,
    // Any later selector context is additive and defaults absent.
}

struct Enrollment {
    // Existing field retained exactly for old data and downgrade behavior.
    closure_calibration: Option<(f32, f32)>,
    #[serde(default)]
    closure_calibrations: Vec<ClosureCalibrationProfile>,
}
```

The exact persisted statistics may change after the evidence slice; the
important properties are that selection bounds come from repeated raw rounds,
not reconstructed from the two medians, and every numeric field is finite,
ordered, and validated on load and write.

Effective behavior should be explicit:

- empty vector + legacy tuple: use the exact legacy single-profile behavior;
- empty vector + no tuple: closure unavailable;
- nonempty vector: use the new selector and **do not also OR the legacy tuple**;
- legacy tuples have no observed range, so they cannot silently become
  auto-selectable multi-profile entries; enrolling the first multi-profile set
  must explain that the legacy calibration needs a fresh repeated capture.

Serde's official contract says `#[serde(default)]` fills a missing field and,
unless `deny_unknown_fields` is used, JSON ignores fields unknown to an older
struct ([field attributes](https://serde.rs/field-attrs.html),
[container attributes](https://serde.rs/container-attrs.html)). That gives
new-reader/old-file compatibility and lets an older binary read the retained
legacy tuple. It does **not** provide lossless downgrade round-tripping: an old
daemon that loads and re-saves the enrollment will discard the unknown vector.
That risk must be documented and tested with an old-shape fixture. It cannot be
fixed by bumping the current envelope's `version`, because the source explicitly
treats that number as informational and detects the envelope by `enc`.

Do not mirror the “most permissive” new profile into the legacy tuple. A
downgrade would then inherit the widest threshold without the new selector. The
legacy tuple should remain the pre-migration calibration until the user
explicitly replaces legacy mode. A separate sidecar could avoid unknown-field
loss on downgrade, but it would duplicate encryption, atomicity, deletion, and
template-key lifecycle; that is not the smallest safe design.

### Wire contract

Keep `SetClosureCalibration` with its current replace-one semantics for old
clients. Add distinct privileged requests for profile add/replace/delete rather
than optional fields that an old daemon would ignore and misinterpret as a
legacy overwrite. Add a default-false capability field to the existing
`Response::Health` and require a new client to check it before sending a profile
request. A new client meeting an old daemon can then ask the user to restart the
daemon after upgrade instead of turning the old daemon's generic `bad request`
response into ambiguous UX. If a request nevertheless reaches an old daemon,
deserialization fails before dispatch and no enrollment state changes.

Extend the existing `Response::Enrollment` with a defaulted list of closure
profile summaries. Old clients ignore the field; new clients meeting an old
daemon see an empty list plus the existing `closure_calibrated` boolean and can
identify legacy mode. Do not add a new response variant unless the client first
opts in: the repository's own wire comments note that an unknown response
variant fails deserialization while unknown fields can be ignored
([upgrade contract](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-common/src/lib.rs#L451-L467)).

A new daemon receiving the old `SetClosureCalibration` while profiles exist
must not leave the profile vector silently active, because the old CLI would
report a successful replacement that authentication ignores. Treat the old
request as an explicit return to legacy single-profile mode and clear the new
vector, using the old CLI's existing destructive replacement confirmation.

## Measurable acceptance criteria

### Evidence gate before authorization changes

Collect separate enrollment and held-out authorization sessions, not validation
on the samples that created each profile. The matrix must include:

- glasses on/off;
- at least the materially different lighting sessions already observed;
- frontal open, genuine close-and-reopen, downward gaze-and-return at several
  durations, timed squint-and-release, natural blink, and initially closed;
- ambiguous open states near profile boundaries and wholly out-of-range states;
- normal stream start/exposure settling; and
- each available project camera whose IR/landmark behavior differs.

For every attempt, record without raw images: candidate count, selected/ambiguous/
out-of-range result, quality/pose rejection category, lock frame, whether any
profile would have accepted under OR, and the final shadow detector verdict.
Raw EAR traces are biometric measurements and should remain in the same
restricted research handling as existing corpora, not ordinary journals.

Report these denominators separately:

1. unique-selection rate for each genuine condition;
2. genuine close-and-reopen acceptance after unique selection;
3. ambiguity and out-of-range fallback rates;
4. false closure accepts for downward gaze, squint, natural blink, and initially
   closed;
5. how often OR-any would accept when locked selection refuses; and
6. selection changes that would have occurred if the lock were absent.

The safety gate is zero observed grants on the adversarial/confused corpus,
including the exact 0.07–0.16 downward-gaze band, plus deterministic unit tests
for every invariant. Zero events in a small corpus is not proof of a production
false-accept rate; the report must give the denominator and must not claim a FAR
the sample size cannot support. A production threshold should not be chosen
until the project states the acceptable false-consent bound and gathers enough
trials to measure it.

### Deterministic code criteria for the later production slice

- Legacy JSON with only `closure_calibration` loads and behaves byte-for-value
  like the current detector.
- New JSON round-trips under both plaintext and encrypted enrollment paths.
- Missing/defaulted new fields never enable closure.
- Invalid, non-finite, inverted, or duplicate-name profiles are rejected on
  write and fail closed on load. Overlapping but otherwise valid measurements
  may be retained for diagnostics/manual management, but are never
  auto-selectable while the required clearance is absent.
- OR-any sabotage: a trace accepted only by the wrong/permissive profile is
  refused by the locked selector.
- Selection-prefix sabotage: prefix frames can never contribute to the
  11–25-frame closure run.
- Closed-first, downward-gaze, timed-squint, ambiguous, and out-of-range traces
  never lock or grant.
- Once locked, a later closer profile cannot replace the first one; the same
  lock is used across early and post-match watches.
- Shake decline remains terminal.
- Normal authentication performs no enrollment write.
- `Either` continues accepting a valid nod when closure selection fails;
  `Closure` returns a password fallback.
- Old request/new daemon and new request/old daemon behavior is covered, and an
  old-shape deserialize/reserialize fixture demonstrates the documented
  downgrade-loss risk rather than hiding it.

## Smallest safe first implementation slice

Do **not** begin with the storage vector or production OR/selector behavior.
Begin with a shadow selector probe that cannot affect `Outcome`:

1. Extend the existing measurement tooling to capture repeated labelled open
   and closed ranges for named conditions while retaining the current stored
   tuple.
2. Add a pure candidate-classification function over explicit profile fixtures
   and a pre-gesture prefix. Its output is only `Unique(id)`, `Ambiguous`, or
   `OutOfRange`; it must have no nearest fallback.
3. Run that function in offline tooling or shadow diagnostics against the matrix
   above. Do not call it from the grant path yet.
4. Use the held-out results to fix the prefix length, stability/pose filters,
   range construction, and separation margin.
5. Only then add profile storage/IPC and wire the proven selector into the
   consent state machine, with exact-head hardware replay and adversarial tests.

This slice is deliberately small: it answers the remaining design questions
without widening a credential-release gate or committing an on-disk schema to
statistics that five samples cannot justify.

## Missing evidence and open decisions

- The #173 ranges are one subject, one camera, one day, five captures per state.
  They establish a real failure, not population bounds.
- No primary paper found here validates automatic selection among multiple
  stored EAR closure profiles for consent or liveness.
- The open-glasses ranges in #173 are separated by only 0.0057 at their closest
  observed points. It is unknown whether that separation survives another day,
  head position, lens reflection, or another subject.
- The repository has evidence that lighting can shift open EAR from 0.109 to
  0.166 and that the paired sessions cannot share one usable calibration, but
  there is not yet a labelled multi-condition selector corpus.
- Head pose is available, but downward **eye gaze** can change lid opening while
  the head remains frontal. Pose gating reduces risk; it cannot be assumed to
  solve it.
- The UX cost of an open-prefix phase has not been measured. Because the early
  watch exists specifically to honor a gesture made immediately at the PAM
  prompt, the prompt and arming timing must be tested together.
- A profile-count cap, selection margin, and production false-consent target
  need evidence or a stated policy; they should not be invented in the schema.

## Primary sources

### Project sources

- [Issue #173 body and measurement discussion](https://github.com/archledger/irlume/issues/173)
- [Enrollment storage at the pinned commit](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-core/src/storage.rs)
- [Daemon wire types at the pinned commit](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-common/src/lib.rs)
- [Closure detector at the pinned commit](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-liveness/src/lib.rs)
- [Consent watch at the pinned commit](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-auth/src/lib.rs)
- [Calibration CLI at the pinned commit](https://github.com/archledger/irlume/blob/f1e20e9e5270a4791737fa618bf24f4aa921463d/crates/irlume-cli/src/main.rs)
- [Checked-in blink corpus, one subject/camera](../pad-results/2026-08-07-blink-corpus.md)

### External primary sources and official documentation

- Soukupová, T. and Čech, J., [*Real-Time Eye Blink Detection using Facial
  Landmarks*](https://vision.fe.uni-lj.si/cvww2016/proceedings/papers/05.pdf),
  CVWW 2016; extended primary analysis in
  [Soukupová's thesis](https://cmp.felk.cvut.cz/ftp/articles/cech/Soukupova-TR-2016-05.pdf).
- Dewi et al., [*Adjusting eye aspect ratio for strong eye blink detection based
  on facial landmarks*](https://pmc.ncbi.nlm.nih.gov/articles/PMC9044337/),
  PeerJ Computer Science 2022, DOI 10.7717/peerj-cs.943.
- Frigerio et al., [*Infrared-based blink-detecting glasses for facial pacing:
  toward a bionic blink*](https://pubmed.ncbi.nlm.nih.gov/24699708/), JAMA
  Facial Plastic Surgery 2014, DOI 10.1001/jamafacial.2014.1.
- Fodor, Fenech, and Lőrincz,
  [*BlinkLinMulT: Transformer-Based Eye Blink Detection*](https://doi.org/10.3390/jimaging9100196),
  Journal of Imaging 2023.
- Ersoy et al., [*Improving Driver Drowsiness Detection via Personalized EAR/MAR
  Thresholds and CNN-Based Classification*](https://arxiv.org/abs/2604.22479),
  arXiv:2604.22479, 2026.
- Mathôt et al., [*Safe and sensible preprocessing and baseline correction of
  pupil-size data*](https://pubmed.ncbi.nlm.nih.gov/29330763/), Behavior
  Research Methods 2018, DOI 10.3758/s13428-017-1007-2.
- Lovisotto, Eberz, and Martinovic,
  [*Biometric Backdoors: A Poisoning Attack Against Unsupervised Template
  Updating*](https://conferences.computer.org/eurosp/pdfs/EuroSP2020-2psedXWK6U4prXdo7t91Gm/508700a184/508700a184.pdf),
  IEEE EuroS&P 2020, DOI 10.1109/EuroSP48549.2020.00020.
- Daugman, J., [*Biometric decision landscapes*](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-482.html),
  University of Cambridge Computer Laboratory Technical Report 482, 2000.
- Microsoft, [*Windows Hello face authentication*](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-face-authentication).
- Serde, [field attributes](https://serde.rs/field-attrs.html) and
  [container attributes](https://serde.rs/container-attrs.html).
