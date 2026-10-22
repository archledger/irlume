# ADR-0013: Ship both PAD models default-on (ViT RGB + FLIR IR)

**Status:** Accepted
**Date:** 2026-08-22
**Amended by:** [ADR-0019](0019-fail-closed-pad-availability.md), which makes
required PAD availability fail closed while keeping the daemon available
**Implementation:** Complete with this PR. `liveness_vit.onnx` (Adedev-W
LivenessModels-ONNX, MIT, sha256 `c7f8a6f3…`) and `flir.onnx` (Alibaba DAMO
ModelScope `cv_manual_face-liveness_flir`, MIT, sha256 `df80cea7…`) are
shipped as release assets, installed by every distribution lane, verified
against `models/SHA256SUMS` at startup, and consulted DENY-ONLY at their
measured operating points. Kill switches: `IRLUME_PAD_VIT=0` /
`pad_vit=0` and `IRLUME_PAD_IR=0` / `pad_ir=0`.

## Context

ADR-0001 set the bar for SHIPPED weights: licenses on the weights and
warrantable training data. That bar exists because a shipped model is
trusted by default and its failures are silent. The opt-in third-party lane
(`irlume models enable`, `irlume_common::thirdparty`) was created for
measured models that fail that bar — FLIR was its first (and until now only)
qualified entry, which meant the single measured defence against the
life-size print attack (the 2026-06-30 breach species, 98.6% APCER against
the physics gate) required an enablement step almost nobody would run.

The 2026-08-21/-22 PAD evaluation campaign changed the evidence base:

- Seven software cues were measured against a labeled 480-frame deployment
  corpus (`docs/research/2026-08-22-screen-attack-pad-survey.md` part 2):
  the shipped moiré cue, 1D/2D banding, MiniFASNet, instrument-rectangle
  detection, POS rPPG, and landmark micro-motion. **None separates a phone
  at login distance from a genuine face** on this camera class, and every
  failure now has a measured physics reason.
- The Adedev-W ViT classifier is the one measured exception for the
  **print/banner species**: 100% detection across every presentation in two
  independent sessions, 0 false-fire frames in 180 genuine frames including
  dim and close regimes and glasses. Its phone coverage is honestly
  incomplete (see Consequences).
- The industry survey confirms no shipping system does passive RGB-only
  screen defense; IR is the answer for screens (which is irlume's
  architecture), and the print species is the RGB gap that remains.

The user decision (2026-08-22): both models ship DEFAULT-ON. This ADR
records why that is sound and what it costs.

## Decision

1. **Both models ship in every package** as release assets on `models-v1`,
   installed to `/usr/share/irlume/models/`, pinned in
   `models/SHA256SUMS`, verified at startup, fetched by
   `scripts/fetch-models.sh` for dev/CI trees. Verification follows the
   shipped-model house policy, not the opt-in lane's: `IRLUME_MODELS_STRICT=1`
   refuses a present-but-tampered cue; in the default non-strict mode a
   mismatched file warns and the cue still loads from the path (the same
   warn-first policy det/mesh/blaze follow — tampering a deny-only cue is
   capability-equivalent to its kill switch, which root can set anyway).

2. **DENY-ONLY wiring, unchanged from the opt-in lane's contract.** Each cue
   can downgrade a Live verdict to Spoof and NOTHING else. A false fire
   costs the password; an absent or wrong cue can never cause a grant. This
   asymmetry is the entire safety argument for default-on.

3. **ADR-0001 is amended, not overridden, for deny-only cues:** a PAD cue
   whose worst case is a password fallback may ship default-on with MIT
   weights and UNDOCUMENTED training data, provided (a) it is measured on
   deployment hardware against the published attack species with the
   measurement committed, (b) the provenance gap is disclosed in
   `models/README.md` and the startup line, and (c) a kill switch exists.
   Grant-capable models (recognition, detection) keep the full ADR-0001
   bar unchanged. The bar for shipped models is now tiered by blast radius,
   which is the property ADR-0001 was protecting all along.

4. **Operating points are the measured ones, pinned by tests:**
   - ViT: m96 crop, **0.55** with a 5-frame-median vote per authentication.
     0.60 was the single-camera (Zenbook) qualification number; fleet
     validation measured the NexiGo banner at presentation-medians 0.55–0.60,
     which 0.60 misses entirely. At 0.55: every login-distance banner
     presentation on both cameras measured 0.594–0.656 (caught), every
     genuine presentation on both cameras (desk/dim/close/glasses) measured
     0.27–0.465 (margin 0.085), and 0 of 531 sampled LFW all-genuine
     presentations fire (0.50 would fire 7.3% — rejected). The vote is part
     of the measurement (it is what holds the genuine side at zero).
     (Amended 2026-10-21, below: no committed record shows which LFW
     images, grouped how, produced the figures at 0.55 and 0.50; on the
     committed scores, 4 of 1,072 per-identity groups of five LFW images,
     every group of one identity, reach 0.55, and 131 reach 0.50.)
     (Amended 2026-10-22, below: 0.594 and 0.656 are the Zenbook
     qualification's banner medians, close and at login distance; the
     NexiGo banner was recorded only as one score per assessment call, so
     no NexiGo presentation median is on record.)
   - FLIR: 0.9 on lit-phase IR frames, the 2026-07-27 re-measured window
     (genuine max 0.702, attack floor 0.941).

5. **Kill switches** are first-class: env (`IRLUME_PAD_VIT` /
   `IRLUME_PAD_IR`) and settings.conf (`pad_vit` / `pad_ir`). A
   kill-switched cue skips startup verification entirely and its absence is
   named in the startup log. ADR-0019 changes their runtime consequence from
   an uncovered face path to password-only face authentication.

## Consequences

- **Accepted, disclosed: the ViT does NOT stop a phone at login distance.**
  The 2026-08-22 live session measured that species at P(spoof) 0.455 —
  inside the genuine band — twice, bistably (docs/research/
  2026-08-22-vit-live-qualification.md). The startup line states this. The
  phone species remains IR's job (screens present no face at 850 nm); a
  phone attack against a dual-camera host never reaches RGB matching with a
  Live verdict. On RGB-only convenience hosts the phone gap remains open —
  unchanged from before this ADR, because no measured cue closes it, and
  that tier never releases credentials.
- **Accepted: +345 MB payload** (343 MB ViT + 2 MB FLIR) across all
  distribution lanes and CI model fetches.
- **Accepted: latency.** The ViT scores only frames the gate verdicted Live
  (no cost on denying frames): 59 ms on a 5700G, 268 ms on the N100 fleet
  floor. First grants on the weakest host pay up to ~1.3 s of extra scoring
  until the 5-vote window fills; measured on the fleet before release.
- **The narrow window (0.04) is a standing risk:** a new camera or print
  landing inside [0.56, 0.604] produces false denials. The kill switch and
  the `pad-vit: p_spoof` journal line exist so an operator can diagnose and
  switch face authentication to password-only in one step. Re-qualification is required (and this ADR's
  Implementation status must change) if either threshold moves.
- **The opt-in catalog keeps both entries' provenance records** and remains
  the path for future PAD candidates; `flir` stays listed so existing
  `settings.conf` selections keep working (the daemon treats an explicit
  opt-in selection of a shipped cue as redundant, not an error).
- Four-host fleet validation gates the merge per the camera-change rule.

## Evidence

- Offline + at-scale: `docs/research/2026-08-21-vit-liveness-pad-evaluation.md`
- Live qualification (the phone finding): `docs/research/2026-08-22-vit-live-qualification.md`
- FLIR qualification + threshold addendum:
  `docs/pad-results/2026-07-17-third-party-pad-candidates.md`
- FLIR at 197 identities: `docs/research/2026-08-21-flir-public-nir-revalidation.md`
- The seven-cue survey: `docs/research/2026-08-22-screen-attack-pad-survey.md`

## Amendment 2026-10-21: the LFW figures behind 0.55

Section 4 and the `VIT_PAD_THRESHOLD` comment cite 0 of 531 sampled LFW
all-genuine presentations firing at 0.55 and 7.3% firing at 0.50, and the
vote test's comment added 1.3% at 0.52. All three first appear in the
2026-08-22 threshold change of #516, and the two percentages give no count
(#1166). The 531 comes from [the 2026-08-21
evaluation](../research/2026-08-21-vit-liveness-pad-evaluation.md) (#515),
which reports a "5-frame-median presentation simulation" on LFW with 0 of
531 at or above 0.60, as #516 first did and as the `VIT_PAD_VOTE_N` and
`vit_pad_votes_deny` comments still did. The per-frame scores behind that
evaluation are committed; which images formed the 531 groups, how they
were drawn and the code that drew them are not. None of these figures can
be rerun, so they no longer support this decision.

The reproducible figures come from the committed per-frame scores
([`2026-08-21-vit-lfw-scores.csv`](../research/2026-08-21-vit-lfw-scores.csv),
13,233 m96 scores of 5,749 identities), printed by `python3 summarize.py
--recorded ../../../docs/research/2026-08-21-vit-lfw-scores.csv` run in
`benchmarks/pad-candidates/dim-room/`. LFW holds still photographs, not
camera presentations, so two reference cases stand in for the five-score
median: each identity's images taken in fives in file order (1,072 groups
from the 423 identities with five or more images, different photos of one
person), and five scores drawn independently from those same 5,360
images, computed exactly (the median of five reaches the line when three
or more scores do). A camera presentation's frames covary in ways neither
case captures, so its refusal rate need not fall between them.

| Deny line | All images | Grouped images | Per-identity groups | Identities with such a group | Five independent draws, exact (3 significant figures) |
|---|---|---|---|---|---|
| 0.50 | 16.69% | 18.68% | 131 of 1,072 | 83 of 423 | 4.83% |
| 0.52 | 7.36% | 7.69% | 24 of 1,072 | 19 of 423 | 0.403% |
| 0.55 | 1.86% | 1.74% | 4 of 1,072 | 1 of 423 | 0.00509% |
| 0.60 | 0.29% | 0.15% | 0 of 1,072 | 0 of 423 | 0.00000332% |

The decision is unchanged: 0.55 with the five-score median, pinned by the
same tests. At 0.55 the four groups are every group of one identity.
Section 4 says the vote holds the genuine side at zero. On these
reference cases it does not: 4 of the 1,072 group medians (0.37%) reach
0.55, against 1.74% of the images in those groups.

## Amendment 2026-10-22: the banner figures behind 0.55

Section 4, the `VIT_PAD_THRESHOLD` comment, the two vote tests and the
models/README.md ViT row say every login-distance banner presentation on
both cameras measured 0.594 to 0.656. Section 4, the threshold comment and
the first vote test also say the NexiGo banner measured presentation
medians of 0.55 to 0.60 (#1169). The records give these figures:

| Camera | Record | Banner presentation | Statistic | P(spoof) |
|---|---|---|---|---|
| Zenbook | [2026-08-22 qualification](../research/2026-08-22-vit-live-qualification.md), A1 | flat, login distance | median of 48 frame scores | 0.656 |
| Zenbook | 2026-08-22 qualification, A2 | close | median of 48 frame scores | 0.594 |
| Zenbook | #516 fleet run | distance not recorded | one score per call | 0.653 to 0.742 |
| NexiGo | #516 fleet run | login distance | one score per call | 0.576 to 0.607 |
| NexiGo | #516 fleet run | close | one score per call | 0.516 to 0.603 |

So 0.594 to 0.656 spans the qualification's two banner presentations on
one camera, and 0.594 is the close one. #516 ran its fleet validation
through `assess_probe`, which calls `Engine::assess` once per probe
iteration (six by default). Each call scores the ViT once, on the
per-pixel median of a five-frame RGB burst. At every #516 commit the only
ViT value the code logs is that score (`pad-vit: p_spoof`, or
`pad-vit(rgb-only): p_spoof` on the RGB-only tier the run used); the
vote's deny line carries the threshold, not the median, and the probe
prints only the verdict and its reason. From 715dc399 on, each call also
clears the vote ring first, so the vote cannot fill inside the probe.
Every #516 figure is therefore one score per call, and no five-score
median was recorded on either camera in that run. The NexiGo
"presentation-medians 0.55-0.60" rest on those scores.

The committed qualification scores
([`2026-08-22-vit-live-session-scores.csv`](../research/2026-08-22-vit-live-session-scores.csv),
`p_spoof_m96`) reproduce both medians, and every five-frame window of
both banner presentations has a median at or above 0.55: 44 of 44 each,
lowest window medians 0.582 (close) and 0.583 (login distance). On the
NexiGo the lowest login-distance score was 0.576, 0.026 above the line,
and close-range scores went as low as 0.516, below it; no five-score
median of either presentation was recorded. The genuine side of section
4 mixes the same two statistics: 0.368 to 0.465 are the qualification's
desk, glasses, dim and close medians, 0.27 to 0.428 the #516 per-call
scores on four hosts, and the 0.085 margin is taken from the 0.465
median. None of the qualification's 143 genuine five-frame windows
reaches 0.55 (highest window median 0.502).

The decision is unchanged: 0.55 with the five-score median. The vote
tests keep 0.594 as their banner pin, now named as the Zenbook
banner-close median. It is the lowest banner presentation median on
record and the same statistic as the genuine pin (0.465, the Zenbook
dim-marginal median). The NexiGo figures are per-call scores and cannot
stand in for a presentation median; a NexiGo banner pin needs that
camera's presentation medians, recorded with their scores.

The 2026-08-21 evaluation also reports "Identity-median ≥ 0.60:
7/2,280". On its committed per-frame scores (13,233 images of 5,749
identities), 26 identity medians reach 0.60, every one of an identity
with a single image, and none of the 1,680 identities with two or more
images; no count of identities by number of images gives 2,280. The
dated evaluation keeps the figure with a pointer here; this decision
does not rest on it.
