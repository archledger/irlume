# Landmark-anchored IR relief: what separates a face from a print, and what only looks like it does

Measurement for [#25](https://github.com/archledger/irlume/issues/25). One camera
(ASUS FHD built-in IR pin, GREY8 640x400), one subject, two sessions, six print
presentations across four geometries. **No gate code follows from this yet**;
the closing section says what would have to be measured first.

Every table below is regenerated from the committed corpus beside this file:

```sh
python3 scripts/analyze-landmark-relief.py \
  docs/pad-results/2026-08-04-landmark-relief.jsonl \
  --check docs/pad-results/2026-08-04-landmark-relief.md
```

The corpus is one record per detected frame carrying the region brightness
means, not images: the raw infrared frames are of the operator's face and are
kept out of the repository like every other PAD capture. `--check` exits
nonzero if any count, range, median, coefficient or separation in this document
stops matching the data.

## Corpus

462 frames carrying a detected FaceMesh, across two sessions whose exposure
bands differ, which is the point:

| set | n | face-region mean | conditions |
|---|---|---|---|
| face, 2026-08-02 | 162 | 105.1-120.2 | glasses, no glasses (two sittings) |
| face, 2026-08-04 | 15 | 40.5-78.5 | room lit, subject dimmer than the print |
| vinyl banner, 2026-08-02 | 270 | 55.4-85.0 | flat, tilted (x2), held closer (x2) |
| vinyl banner, 2026-08-04 | 15 | 55.4-75.3 | hand-curved toward the camera |

The 2026-08-02 session could not bring the two classes into one exposure band and
recorded that as the blocker: vinyl reflects 850nm far more weakly than skin, so
the face sat 20 units above the print's ceiling and every ratio measured there
was confounded with brightness. The 2026-08-04 session resolves it by accident
rather than by design. A lit room raised ambient, auto-exposure pulled the face
down to 40.5-78.5, and the face now overlaps the print band almost entirely. The
comparison below is therefore no longer "bright face against dim print".

Frames were sampled with `landmark_replay`, which reads stored PGMs and applies
the same 3x3 patch mean as the live `landmark_dump`. Instrument check before
use: replaying the 2026-08-02 frames reproduced that session's CSVs
byte-identically, 18 of 18, with the same detection count.

## Two candidates survive matched exposure; two do not

| ratio | face (177 frames) | print (285 frames) | verdict |
|---|---|---|---|
| cheek / chin | 2.580-3.532 | 1.295-1.610 | separated by 0.971 |
| forehead / chin | 3.910-6.266 | 1.286-1.785 | separated by 2.126 |
| nose / socket | 0.545-2.217 | 1.494-1.862 | overlaps |
| brow / socket_deep | 0.478-2.063 | 1.192-1.507 | overlaps |

The two failures matter more than the successes, because they were the
2026-08-02 session's leading candidates. `brow/socket_deep` scored +0.626 there
and its extrapolation into the print's exposure band suggested the face would
stay 0.179 above the print. The dim-face data settles it in the opposite
direction: a real face at exposure 40-78 reads 0.478-0.952, well **below** the
print's 1.192-1.507, not above. The extrapolation was not merely imprecise, it
had the sign wrong, and any gate built on it would have rejected genuine faces in
ordinary room light. Both failed ratios use an eye-socket region, whose response
collapses with exposure (r = +0.95 and +0.74 against face-region mean on the dim
face); that is the confound the previous session suspected and could not test.

The stated hypothesis in the issue, `nose > cheek > socket`, remains false: it
held in 0 of 54 face frames on 2026-08-02 and nothing here revives it.

## Why chin ratios survive

The mechanism is visible in the regions before any ratio is taken (medians):

| class | cheek | forehead | chin | chin/cheek |
|---|---|---|---|---|
| face | 122.8 | 193.5 | 38.2 | 0.302 |
| print | 77.8 | 83.0 | 50.8 | 0.655 |

These medians are consistent with a geometric-shadow hypothesis: this subject's
chin returned a third of the cheek's response, where this printed portrait's
returned two thirds, which is what a surface angled away from a near-coaxial
emitter and shadowed by the jaw would do against a coplanar sheet.

Matching the exposure ranges removes the earlier between-class brightness
separation, and that is all it removes. It does not isolate geometry from this
subject's skin, facial hair, or pigmentation, from the source photograph's own
lighting and tones, from the banner's ink and coating, or from head pitch. The
experiment establishes a candidate ratio worth testing, not that the ratio
measures relief; the darkened-chin attack below is the same point stated as an
attack, and multiple subjects and print materials are what would separate these
explanations.

The attacker's degrees of freedom against the global centre/edge ratio do not
transfer. Per condition:

| condition | n | cheek/chin | forehead/chin |
|---|---|---|---|
| face, glasses | 54 | 2.580-3.287 | 3.910-4.342 |
| face, no glasses (x2) | 108 | 3.235-3.532 | 4.996-5.403 |
| face, dim room | 15 | 3.065-3.259 | 4.716-6.266 |
| banner flat | 54 | 1.503-1.604 | 1.625-1.785 |
| banner tilted (x2) | 108 | 1.408-1.610 | 1.370-1.653 |
| banner held closer (x2) | 108 | 1.302-1.610 | 1.298-1.736 |
| banner hand-curved | 15 | 1.295-1.432 | 1.286-1.412 |

Tilting is what defeats the global ratio (it reached 1.51 against a genuine
1.44-1.54 on 2026-08-02). Here tilting moves the print by 0.2 and never
approaches the face. Curving, which raised the print's global ratio from
1.04-1.12 to 1.15-1.20 the same morning, leaves this one at 1.295-1.432.

## The exposure trend, extrapolated in the risk direction

Both surviving ratios fall as the face brightens, so the failure direction is a
very bright face. Fitting the face data and extending it to the print's ceiling:

- `cheek/chin` = 3.480 `-0.0030`*exposure, reaching the print's 1.610 at
  exposure **627**
- `forehead/chin` = 6.466 `-0.0146`*exposure, reaching 1.785 at exposure
  **320**

Both crossings sit beyond 255, the 8-bit sensor ceiling, so neither is reachable
by brightness alone on this hardware. This is an extrapolation from faces
measured to 120 and is offered as a bound, not as evidence about saturated
frames; saturation clips regions unevenly and is measured separately (#221).

## The printed-shadow attack remains untested

The cue reads brightness at the chin and cannot tell an emitter shadow from a
printed one, so darkening the chin region of the source image should raise the
ratio without changing the print's geometry.

What the banner does show is how little contrast its current portrait retains
at 850nm across the sampled regions. Each value is camera brightness divided by
the forehead brightness in the same frame (medians):

| region | real face | vinyl print |
|---|---|---|
| nose | 0.858 | 1.137 |
| cheek | 0.645 | 0.974 |
| brow (eyebrow) | 0.728 | 0.961 |
| socket | 0.454 | 0.711 |
| socket_deep | 0.424 | 0.721 |
| chin | 0.192 | 0.625 |

A real eyebrow reads 0.728 of forehead; the printed eyebrow, strongly dark to
the eye, reads 0.961. Across these regions the face spans 0.192 to 1.000 and
the print 0.625 to 1.137.

The arithmetic of the attack, holding the measured cheek brightness fixed:

| quantity | value |
|---|---|
| print cheek median | 77.8 |
| print chin median | 50.8 |
| print cheek/chin | 1.532 |
| lowest captured face cheek/chin | 2.580 |
| required print chin | 30.2 |
| required chin / print forehead | 0.363 |

**This does not rule the attack out, and an earlier revision of this page said
it did.** The required 0.363 sits below every region sampled here, but these
are six landmark regions of one portrait, not a tone scale: they differ at once
in source-image tone, surface orientation, emitter incidence, coating response
and viewing angle. The lowest of them is not the darkest tone the ink can
print. Nor is camera brightness over a printed forehead a reflectance
measurement; reflectance is defined against a reference under stated
illumination and observation geometry, and no such reference is in frame, so no
absorption figure can be derived from these numbers either.

What would settle it: a controlled tone scale printed on the same medium, or
simply the attack itself, a second print whose chin is filled with the darkest
printable tone. Neither exists here. A physical occluder, dark cloth or an
infrared-absorbing patch over the chin of an existing print, produces the same
signal without printing anything and needs no new instrument at all.

## What would have to be true before a gate

- **A deliberately darkened or infrared-absorbing chin**, produced by printing
  a second attack image or by physical occlusion, captured and refused. The
  banner carries no controlled tone scale, so nothing here establishes the
  minimum response its ink and medium can reach.
- **More than one subject.** Facial relief is the quantity being measured, and
  jaw shape, beard, and chin prominence vary. One subject cannot establish a
  floor.
- **Head pitch.** Every face frame here is frontal within the existing gate's
  bounds; looking up or down changes chin illumination directly, and no sample
  varies it deliberately.
- **The envelopes #25 requires**: dim IR-emitter-only, and direct-sun
  saturation. Neither is in this corpus.
- **Chin visibility as a precondition.** The region has to be in frame and
  unoccluded; a beard, a scarf, or a cropped bbox changes what is sampled, and
  the sampler clamps at frame borders rather than reporting absence.

Raw frames and landmark CSVs for both sessions are kept, so each of these starts
from data rather than from scratch.
