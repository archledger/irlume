# Optional IR-only qualification protocol

Status: contributor evaluation protocol, not a qualification result. Dual-camera
RGB+IR authentication remains the default. Irlume provides an explicit
machine-owner IR-only policy whose production route has separate integration and
granting-policy coverage. Sequential/concurrent remains a separate dual-camera
scheduling choice. This document neither enables the policy nor certifies it.

## What this evaluates

Use the [non-granting diagnostic](research/2026-09-08-ir-only-evaluation.md) to
exercise live IR capture, provenance and illumination handling, detection,
liveness, mandatory FLIR PAD, compatible enrollment and the complete existing IR
identity decision. `candidate_match` is an experimental decision, never login
permission. No authentication, PAM grant or credential release belongs in this
phase. Its absence of RGB scene/cross-spectrum evidence is part of the policy
being evaluated, not evidence that those checks are unnecessary.

The older [PAD self-test](PAD_SELFTEST.md) measures a component; `padcapture`,
`padreport`, or recorded-frame PAD replay cannot substitute for this full-path
study. Do not use their raw-signal logging for this protocol. No claim of Windows
Hello parity, superiority, ISO conformity, FIDO approval or lab certification
follows from completing an engineering campaign.

## 1. Freeze a campaign before observing evaluation results

Copy the [campaign and report template](research/ir-only-campaign-template.md).
Declare the campaign **development**, **pilot**, or **qualification**. A pilot is
useful for finding faults but cannot become qualification by relabeling it after
seeing results. A qualification campaign needs a recorded maintainer review of:

- The exact commit plus local patch hash, executable/model/adapter hashes,
  recognizer space, profile/template-count strata, matching/PAD/gate thresholds,
  capture budget and external watchdog. Record kernel/driver and sensor models,
  capture backend, illumination/metadata behavior and topology, without serials.
- The intended deployment scope: sensor/configuration combinations, ordinary
  lighting/pose/distance range, enrollment procedure and intended population.
  Dim-light testing is excluded from this campaign; make no dim-light claim.
- Separate development and evaluation partitions, the sampling unit, planned
  trial counts per sensor and attack species, ordering, treatment of missing
  data and statistical analysis. Fix the schedule before seeing outcomes.
- Numerical acceptance targets and confidence requirements for impostor candidate
  decisions, attack candidate decisions, genuine failed attempts and capture
  failures. Define acceptable data coverage and what evidence each claim needs.

There are **no adopted numerical full-path release targets in this protocol**.
The legacy component targets do not automatically become full-path targets.
An unfilled or unapproved target/sampling plan means **not qualified**; do not
invent a target after collecting data. Choosing release risk tolerance is a
recorded product/security decision, distinct from selecting a model threshold.
Any successful attack or zero-effort impostor candidate is an immediate stop for
investigation, independent of aggregate targets. Do not retune against evaluation
results and then report the same partition as held out.

## 2. Independence and coverage

Split by people, attack instruments and collection sessions, not by frames. New
frames from a previously used person/banner remain development/regression
material for those dimensions. Evaluation participants may enroll using the
frozen enrollment procedure, but their evaluation sessions must be separate and
must not influence global tuning. Reusing a device model is expected when testing
that model; claim cross-device generalization only with separate device evidence.

Include consenting enrolled participants and consenting non-enrolled participants
presenting their own faces against a different enrolled target (zero effort).
Keep local participant/instrument linkage private; publish aggregate coverage,
not names, account identifiers or face-derived records. Do not infer demographic
attributes from images. Any demographic study needs explicit participant consent
and an appropriate independent privacy plan; otherwise limit the population claim.

| Required stratum | Evidence to collect |
|---|---|
| Genuine users | Ordinary position and declared pose/distance variation; distinct enrollment and evaluation sessions; all failures retained |
| Zero-effort impostors | Live non-target faces against enrolled targets; separately sampled from attack artifacts |
| Printed artifacts | Target-identity matte, glossy, vinyl, and bent/cutout variants; independently sourced instruments |
| Display replay | Target-identity still and video presentations on declared phone/tablet/laptop devices |
| Higher-capability attacks | Masks, active IR artifacts and sensor injection assessed separately; unavailable coverage remains an explicit gap |
| Sensor/configuration | Every claimed camera/driver/model/adapter configuration; no automatic transfer from ASUS to NexiGo or another topology |
| Identity decision | Best-template and calibrated-centroid arms, profile/template counts and adapter/no-adapter configurations actually claimed |
| Lifecycle/failure | Empty view, cancellation, expiry, contention, disconnect and incompatible enrollment; separate controlled cases, not accuracy samples |

Check that an artifact depicts its intended enrolled target and is presented
within the declared procedure; otherwise its rejection cannot qualify targeted
attack resistance. Record artifact coverage without saving its image. Do not
claim paper or screens can never produce a detectable IR face.

Diagnostic schema 4 exposes which existing identity predicates passed as the
bounded `identity_acceptance` label: `best_template`, `centroid`, or `both` for a
final `candidate_match`, and null for every other category. Synthetic tests verify
the arm logic, but they cannot establish empirical arm coverage. Instrumentation
makes that coverage measurable; only predeclared, completed trials can supply it.
Never infer arm coverage from older `candidate_match` records, disable an arm to
pass evaluation, or count a component-only match as the union policy result.

Independent public IR datasets can extend component testing, subject to verified
modality, preprocessing, provenance, license and published splits. They cannot
supply live provenance, emitter lifecycle or local full-policy evidence. FLIR
training-data overlap is unknown; state this limitation even for locally held-out
data. Do not substitute an unverified Kaggle mirror for publisher access terms.

## 3. Run without granting access or retaining biometrics

1. Use a test account/device under the operator's control with a working password
   fallback. New participant enrollment is a separate consented operation; do not
   alter the owner's enrollment or weaken an existing service configuration.
2. Follow the diagnostic's real build/preflight instructions. Record the source
   and executable identity. Never paste the maintainer's `/dev/videoN` choices onto
   another host. Independently verify IR image/metadata topology, device binding,
   required models and protected-state preservation. The current contributor
   example needs a vetted IR image+metadata interface distinct from RGB; other
   topologies require harness adaptation and review. The production route uses the
   shared configured target and may accept an exact topology that explicitly has
   no metadata companion; that does not broaden this harness campaign.
3. Run camera-free preflight. Only after fresh readiness and an explicit start cue
   run one evaluation for the scheduled presentation. Release the participant from
   positioning after each group. No unattended scans or reused readiness.
4. Supervise with a reviewed watchdog and an allowlist for the diagnostic's exact
   schema/categories. Trace only video-device open/close metadata; discard other
   paths and raw stderr. Reject unknown fields/categories and any grant indication.
   For schema 4, require a bounded non-null identity acceptance label only for a
   final candidate and require null for interruption, refusal and error categories.
   Use the [contributor harness](../scripts/ir-evaluation/README.md) with an
   explicit private host configuration. Its Linux/systemd topology and tracing
   checks are conservative; each new host still needs review and attended lifecycle
   validation. Passing the harness is not a qualification verdict.
5. Retain one categorical outcome per started attempt, nullable stage timings and
   release evidence. Include malformed output, process failure and watchdog cleanup
   as harness failures in the attempt ledger. They never count as PAD successes.
   Cancelled planned controls are separate from accuracy trials; an unplanned
   cancellation in an accuracy trial remains in its failed-attempt count.
6. Verify expected IR-only opens, all successful closes, idle state and protected
   files after each attempt. Stop on any grant, attack/impostor candidate, unexpected
   device access, cleanup or preservation failure. Keep the evidence; do not replace
   the attempt, change thresholds, reset counters or continue until reviewed.

No new images, frames, embeddings, templates, landmarks, similarity/PAD scores,
raw errors, account names or private paths may enter campaign artifacts, shared
memory or issue attachments. Do not turn on debug capture. Timing/aggregate
outcomes and public code/model hashes suffice. Descriptor close is not optical
emitter-off measurement; an optical claim requires its own measurement method.

## 4. Account for every attempt

Let `N` be all started accuracy attempts of a given ground-truth class and
sensor/species stratum. Let `C` be its `candidate_match` count. All diagnostic
categories plus harness-failure counts must sum to `N`.

| Measure | Definition and limit |
|---|---|
| Genuine failed-attempt fraction | `(N - C) / N`; includes no-face, PAD/liveness/identity refusal, capture/model/enrollment errors, unplanned cancellation, deadline and harness failure |
| Attack candidate fraction | `C / N` per species and configuration; diagnostic full-policy proxy, not certified IAPAR and not actual login grants |
| Zero-effort impostor candidate fraction | `C / N` separately; full-policy proxy, not an isolated comparator FMR |
| Capture/infrastructure outcomes | Each camera/lease/model/enrollment/harness error and timeout count separately, against all started attempts |
| Decision detail | Separate `no_face`, `liveness_refused`, `pad_refused`, `identity_mismatch`, cancellation and other categories; never relabel no-face or hardware failure as PAD refusal |
| Stage coverage | Count which timed stages were reached; stages not reached are missing evidence, not passed tests |

Also report candidate fractions among assessment outcomes, using exactly
`candidate_match`, `identity_mismatch`, `no_face`, `liveness_refused` and
`pad_refused` for that conditional denominator. List its count explicitly; this
does not imply every inference stage ran. All other categories remain outside
this conditional denominator and inside the all-started denominator. Missing capture/infrastructure evidence
must not make an attack result appear stronger: qualification also needs the
predeclared adequacy gate, a sufficiently broad attack set and genuine controls.
A run of unusable frames may produce zero candidates while qualifying nothing.

Component APCER/BPCER or comparator FMR/FNMR requires a separate protocol and
appropriate denominators. This diagnostic's staged, short-circuit output is not a
complete PAD confusion matrix. In particular, `liveness_refused` combines multiple
reasons and cannot automatically become BPCER. Report raw counts per stratum,
worst supported stratum and uncertainty; never average away a weak species/device.
If `N = 0`, the result is unavailable, not zero errors.

## 5. Statistical claims

State whether confidence bounds are one-sided or two-sided, their confidence
level and the independent sampling unit. Use an analysis justified by the sampling
design. Repeated frames, attempts from the same person/instrument, and all pairwise
comparisons among a small cohort are not automatically independent trials. Report
those clusters and seek statistical review before a population claim. Ordinary
bootstrap resampling of an all-zero error sample cannot prove a tiny error rate.

For **independent Bernoulli trials only**, zero errors in `n` trials has one-sided
95% exact upper bound `1 - 0.05^(1/n)`. These are planning examples, not release
targets or valid bounds for our correlated banner trials:

| Zero-error independent trials | One-sided 95% upper bound |
|---:|---:|
| 6 | 39.304% |
| 20 | 13.911% |
| 59 | 4.951% |
| 299 | 0.997% |
| 29,956 | 0.00999994% |

For nonzero errors use the declared exact-binomial or other justified method;
account for clustering and multiple simultaneous stratum claims. Do not repeatedly
peek and extend the campaign until an ordinary fixed-sample interval passes.
[NIST's exact-binomial reference](https://www.itl.nist.gov/div898/software/dataplot/refman2/auxillar/exacbino.htm)
explains one-sided versus two-sided limits. The older self-test's 0/20 example uses
a two-sided 95% interval, so its upper limit is different.

As external context, NIST SP800-63B-4 states FMR at most 1/10,000, recommends FNMR
below 5%, and recommends deployment IAPAR below 7% in its biometric authentication
requirements. It also requires biometrics to be part of MFA with a physical
authenticator. These are not interchangeable metrics or automatic Irlume desktop
release criteria. Do not claim NIST compliance from this experiment.
[Current NIST biometric requirements](https://pages.nist.gov/800-63-4/sp800-63b.html#biometrics).

## 6. Qualification decision and product integration

A report may conclude **not qualified**, **inconclusive**, or **evidence meets the
predeclared campaign targets for the stated scope**. Missing targets, inadequate
independence/coverage, unresolved stop conditions or unverified arm coverage cannot
be called a pass. State untested scope explicitly, including masks/injection where
absent. The report is reviewed independently of the implementer before acceptance.

Even accepted diagnostic evidence does not turn `candidate_match` into authority.
The experimental product route has separate integration and isolated
granting-policy tests covering the explicit root opt-in and dual default, supported
target/model/enrollment binding, mandatory IR PAD, consent, password fallback,
cancellation and late-result rejection, durable retry/recovery accounting, and
credential release. Production derives its own ordinary authentication outcome; it
does not grant from the diagnostic category. Camera-free preflight establishes
prerequisites only. The existing product windows remain 15 seconds for login/lock
and 5 seconds for short privileged services; a measured fixed-startup Minihost
empty-view capture of about 5.5 seconds exceeded that short window before identity.
The target-bound IR route now uses the existing adaptive startup strategy: it
measures the full 30-interval rate window first and uses up to ten additional
dequeues if that window is too slow. The rate floor, continuity, metadata binding
and all downstream authentication checks remain in place. This replaces the
original integration's fixed startup; the historical Minihost measurement above
describes that earlier behavior. It does not extend a window or revive
stock-desktop hands-free scanning. This integration coverage permits explicit
experimental opt-in; it does not qualify a device, participant group, or population.

## Current evidence, September 8, 2026

The maintained local reports record: 252 earlier paper/screen/video frames with no
face detections; a separate 396-frame regression with 119/123 detected banner
frames PAD-refused and four below threshold; twelve live attempts with six banner
PAD refusals and genuine four candidates/one identity mismatch/one capture failure;
then two targeted genuine candidates after diagnostic-only error refinement.
These are observations on an existing person/artifact and a limited hardware set,
not independent qualification. The earlier capture and identity failures remain in
the campaign record; successful repeats do not erase them or establish population
performance. The experimental product option is not a qualification result.
