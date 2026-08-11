# Landmark-anchored IR relief: what separates a face from a print, and what only looks like it does

Measurement for [#25](https://github.com/archledger/irlume/issues/25). One camera
(ASUS FHD built-in IR pin, GREY8 640x400), one subject, two sessions, six print
presentations across four geometries. **No gate code follows from this yet**;
the closing section says what would have to be measured first.

Every table below is regenerated from the committed corpus beside this file:

```sh
python3 scripts/research/analyze-landmark-relief.py \
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
- **More than one subject, and at least one clean-shaven.** The sole subject
  here has a full beard covering the chin and jaw, established by rendering the
  frames (see [the ambient report](2026-08-04-ambient.md)), so every chin
  reading above is beard rather than skin. Real hair absorbs 850nm and printed
  hair does not, the same effect this corpus measures at the eyebrow (0.728
  against 0.961), so the cue may be separating real hair from printed hair
  rather than relief from flatness. Those explanations differ exactly where it
  matters: on a face without facial hair.
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

## 2026-08-10: Emitter-only and head-pitch envelopes

Three new measurements on the same camera (ASUS FHD built-in IR pin, GREY8
640x400), one subject, four captures. The question was whether the chin ratio
holds across the envelopes #25 requires: emitter-only dark room, and head pitch
variation.

### Emitter-only dark room

The emitter is the only light source. A lit room with emitter was also captured
for comparison.

| Envelope | n | cheek/chin | forehead/chin | chin median |
|---|---|---|---|---|
| Room-lit + emitter | 54 | 0.66-1.34 (0.72) | 0.90-2.02 (1.09) | 97.7 |
| Dark + emitter | 4 lit | 1.76-2.19 (1.81) | 1.83-2.51 (2.11) | 121.0 |
| Ambient (report above) | 177 | 2.58-3.53 | 3.91-6.27 | 38.2 |

Under room-lit + emitter, the chin is brighter than the cheek (ratio 0.72). The
co-axial emitter illuminates the chin directly, and ambient light fills the jaw
shadow. Under dark + emitter, the chin is shadowed but still 3x brighter than
under ambient (121 vs 38), because the emitter is the only source and the chin
is closer to it. The ratio (1.81) sits between the ambient face range (2.58-3.53)
and the print range (1.30-1.61).

**The emitter-only envelope is not separated from the print.** The chin ratio
only works under ambient light, where the chin is shadowed by the jaw and the
emitter is not the dominant source.

### Head pitch

Captured straight, looking up, and looking down. All lit by the emitter in a lit
room. Two runs were taken to check consistency.

**Run 1:**

| Angle | n | cheek/chin | forehead/chin | chin |
|---|---|---|---|---|
| Straight | 6 | 2.47-3.16 (2.72) | 3.99-5.09 (4.44) | 37.0 |
| Up | 18 | 2.49-3.04 (2.81) | 3.82-4.85 (4.35) | 42.9 |
| Down | 18 | 1.60-2.90 (2.19) | 2.43-4.29 (3.34) | 60.2 |

**Run 2:**

| Angle | n | cheek/chin | forehead/chin | chin |
|---|---|---|---|---|
| Straight | 18 | 2.35-2.99 (2.92) | 3.63-4.86 (4.73) | 39.0 |
| Up | 18 | 1.74-2.37 (1.98) | 2.06-2.75 (2.48) | 38.7 |
| Down | 18 | 2.04-2.73 (2.41) | 3.12-4.01 (3.65) | 55.4 |

The two runs disagree on which angle is the problem: run 1 has down as the
failure (min 1.60), run 2 has up as the failure (min 1.74). The chin brightens
under down-angle (55-60 vs 37-39 straight) because the chin angles toward the
camera. The cheek darkens under up-angle because the forehead angles toward the
camera and the cheek away.

**Combined pitch-varied (54 frames):** cheek/chin 1.74-2.99 (median 2.38). The
report's face range was 2.58-3.53 with a 0.97 gap above print. Head pitch
shrinks the gap from 0.97 to **0.13** (face min 1.74 vs print max 1.61).

### Glint extent + chin ratio as a distance-robust pair

The two cues were predicted to have opposite distance sensitivity: the chin
ratio weakens at close range, the bright pupil (retinal retroreflection)
strengthens at range because the emitter-to-lens angle shrinks.

The existing stage3 close/far/sweep frames (2026-08-05, same camera) were
replayed through `landmark_replay` and the glint extent (pixel count above a
dynamic threshold in a 15px radius around each iris center) was measured.

| Distance | Frame mean | Left bright px | Right bright px | L/R ratio |
|---|---|---|---|---|
| Close | 83 | 498 | 456 | 1.09 (symmetric) |
| Far | 59 | 0 | 0 | — (no signal) |
| Sweep | 84 | 276 | 20 | 13.78 (asymmetric) |

At far range, the 1/r² IR falloff dominates: the frame is too dim for any pixel
to clear the threshold. At close range, both eyes show bright regions. The bright
pupil effect is strongest at close range, not far. The angular effect from the
physics paper (Nguyen et al., PMC4721713) is real but the 1/r² falloff overwhelms
it at the distances these cameras operate at.

**The two cues do not have opposite distance sensitivity.** They both degrade
at range. The chin ratio weakens at close range (down-angle chin brightens), and
the glint extent also weakens at range (1/r² falloff). They track in the same
direction.

### Verdict

The chin ratio separates face from print under ambient frontal light, but fails
under emitter-only illumination and head pitch. The glint extent does not
complement it as a distance-robust pair. The original hypothesis from the issue
(nose > cheek > socket) is false in 0 of 54 face frames. The landmark-anchored
approach is a partial improvement over the global centre/edge ratio — it resists
tilting and curving where the global ratio does not — but it is not a standalone
gate, and the emitter-only envelope remains unseparated.

The remaining open path: a deliberately darkened chin attack (to test whether
the ratio can be defeated by printing or occluding the chin), and multiple
subjects including a clean-shaven face (to test whether the cue separates real
hair from printed hair rather than relief from flatness).
