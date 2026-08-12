# Third-party models irlume has measured

This page lists the externally-trained models irlume can run in its two open
pipeline stages: liveness (PAD) cues that can deny a presentation the built-in
gate accepted, and a recognizer that replaces the shipped one for RGB matching
at a measured threshold. **Everything here was
measured on real hardware by this project before it was listed.** Nothing is
listed because a publisher claims it works, and a model irlume has not measured
is not supported, whatever its benchmarks say elsewhere.

Two things follow from that, and they are the reason this page exists:

- irlume knows exactly **which** model is loaded. Every entry carries the sha256
  of the artifact that was measured, and irlume refuses weights that do not
  match it. A threshold measured on one set of weights means nothing applied to
  another, so a near-miss is a refusal rather than a warning.
- irlume does not have to be the one who **fetches** it. Some models carry
  licences that make obtaining them the user's decision. Those are still
  measured, still pinned, still supported; you supply the file.

## Pipeline stages open one at a time

Every catalog entry names the pipeline stage it plugs into, and only an open
stage can be installed or wired. Two stages are open:

- **Liveness (PAD)**, opened first because its wiring is deny-only: a bad
  model there can cost retries or the password, never grant.
- **Recognition**, opened 2026-08-05 under the split-source threshold
  protocol of [ADR-0006](adr/0006-third-party-model-stage-policy.md), first
  recorded on issue #276: the false-accept side measured on public
  datasets replayed through irlume's own pipeline, the false-reject side on
  this project's cameras, the threshold set from where those populations were
  observed. A third-party recognizer runs RGB matching only: IR matching,
  fusion, and dark login are disabled because no entry carries IR-side
  measurements, and templates enrolled under a different recognizer never
  match (each is tagged with the digest of the weights that produced it), so
  enabling one means re-enrolling. If the daemon cannot honour an enabled
  recognizer selection (missing file, failed pin), it refuses to start and
  logins fall back to the password; it never silently substitutes another
  recognizer.

Detection and landmarks are named but closed: bad landmarks feed confident
wrong numbers into the liveness cues rather than erroring. `irlume models`
refuses to install an entry for a closed stage, and the daemon refuses to
wire one.

`irlume doctor` shows what every stage is running today, and
`irlume models list --json` is the machine-readable version
([MACHINE-API.md](MACHINE-API.md)).

## How to read an entry

Run `irlume models` for the live version of this table. Each entry states:

| field | what it means |
|---|---|
| `license` | the publisher's licence for the weights, as published |
| `provenance` | whether the training data and pipeline are documented, and so whether the model could ever meet [ADR-0001](adr/0001-liveness-pad-strategy.md) |
| `stage` | which pipeline stage the model plugs into, and whether that stage is open |
| `threshold` | the decision point irlume **measured**, never the publisher's default |
| `measured` | the one-line result, pointing at the full document in `pad-results/` |
| `obtain` | whether irlume fetches it, or you supply the file |

The threshold is the part that matters most and the part a page like this
usually gets wrong. A deny-only cue firing in a score band where neither genuine
faces nor attacks were observed is guessing, and it guesses against the user:
every false fire costs a real login. So irlume sets each threshold from where
the two populations were actually seen to sit on its own hardware.

## The models

The case for the PAD entries is that irlume's built-in liveness gate does not
stop a printed photograph of an enrolled face. That is measured, not
suspected: the gate returned `Live` for all 24 presentations of a vinyl print
in issue #235, and again for an enhanced version of the same attack, so a
trained cue is currently the only thing that refuses it. See
[the PAD results](pad-results/) for every number behind that.

### `flir`: irlume fetches it

An infrared anti-spoof cue from Alibaba DAMO, published on ModelScope under MIT.

- **Measured:** 122 of 123 attack frames flagged across two cameras
  (2026-07-17); re-measured at the shipped threshold on 2026-07-27, 6 of 6
  presentations flagged at p_fake 0.941 to 1.000; on 2026-08-04 it refused the
  same print enhanced with an infrared-absorbing patch, at 0.998 to 0.999, in
  the same runs where the built-in gate returned `Live`.
- **Threshold:** 0.9. Highest genuine score observed 0.702, lowest attack score
  0.941. The publisher's model card states no threshold at all.
- **Genuine-side failures are mapped, not absent:** dim strobe frames and direct
  sun, and a blown frame drops the score into an abstain band (#237).
- **Provenance:** the publisher documents neither the training data nor a
  reproducible pipeline, so it fails ADR-0001 criteria 2 and 3. irlume does not
  ship or warrant it.

```sh
sudo irlume models enable flir
```

`irlume setup` also offers this one, with the licence and provenance on screen.

### Bring-your-own entries

A bring-your-own model is one whose licence makes obtaining the file your
decision, not irlume's. It is measured and pinned exactly like a fetched one;
irlume verifies your file against the published sha256 before enabling it, and
a non-matching file is refused: that file is not the artifact the threshold was
measured on.

### `buffalo`: you supply the file (recognition stage)

The InsightFace `buffalo_l` recognizer (`w600k_r50.onnx`, WebFace600K-trained),
measured 2026-08-05 under the split-source threshold protocol
([full record](recognition-results/2026-08-05-buffalo-l.md)).

- **Measured:** LFW EER 3.9% against the shipped recognizer's 4.2% on the
  identical pipeline. At the enabled 0.55 threshold the demographic FAR
  spread is 3.9x against the shipped model's 6.1x, with the two worst groups
  at parity, and the worst-served group shifts to Middle Eastern, which
  reads slightly worse than under the shipped model. Live genuine floors
  0.685 to 0.793 across two cameras, anchored by shipped-model control runs.
- **Threshold:** 0.55. Worst demographic group's FAR there matches the shipped
  stack's worst group at its own operating point. 0.60 was rejected: its
  cross-lighting margin measured zero.
- **What enabling it does:** replaces the recognizer for RGB matching. IR
  matching, fusion, and dark login are disabled (unmeasured for this model),
  and templates enrolled under the shipped recognizer will not match;
  re-enroll after enabling, and again after disabling.
- **Provenance:** WebFace600K is scraped web imagery without subject consent,
  and the licence is non-commercial research only. Both fail ADR-0001 for
  shipping, which is why this entry is bring-your-own.

```sh
# extract w600k_r50.onnx from the publisher's official buffalo_l.zip
# (github.com/deepinsight/insightface, release v0.7), then:
sudo irlume models add buffalo /path/to/w600k_r50.onnx
```

### full-range BlazeFace: measured, not yet enableable (detection stage)

Google's MediaPipe full-range BlazeFace is measured and its runtime support
is shipped, but it is **not a catalog entry yet** and the detection stage
remains closed, so it cannot be enabled.

- **Measured:** 100% detection on every segment of the two-camera stage-3
  corpus through Google's own runtime, including all far-IR frames the
  shipped short-range rescue misses at 0%; irlume's decoder holds 0.9354
  mean IoU parity against that runtime
  ([bench](pad-results/2026-08-05-stage3-live-detection-bench.md)). Its
  operating point measured through irlume's pipeline is 0.55
  ([threshold record](pad-results/2026-08-05-fullrange-threshold.md)).
- **Why it is not enableable:** the slot it would occupy, the detection
  rescue, feeds the grant path: a box it supplies where YuNet found nothing
  is aligned, matched, and can authenticate. The measurement covers genuine
  frames and empty rooms, not prints, screens, or other faces on the frames
  where the rescue actually fires. Until that evidence exists, opening the
  stage would rest on the wrong corpus.
- **Provenance:** the model card (read 2026-08-05) licenses the weights
  Apache-2.0 and states consented first-party training data, in-scope to
  5 meters.

Whether a given licence permits **your** use of a model is your determination.
irlume prints the licence before enabling anything and distributes no weights.

## What is deliberately not here

- **Models irlume has not measured.** Publishing "this probably works" is how a
  page like this becomes a recommendation engine for untested weights.
- **Any model as a default.** The PAD entries are deny-only: they can refuse a
  presentation the built-in gate accepted, never approve one it rejected. That
  is what makes them safe to add, and it is also why a broken one degrades
  quietly rather than loudly, so `irlume doctor` reports which model is active
  and whether its weights still match their pin. The recognition entry grants,
  and its case for staying opt-in is different: enabling it replaces the
  matcher on the grant path and turns off IR matching, fusion, and dark login,
  so it runs only at a threshold irlume measured, never at a number the
  publisher shipped.

## Adding a model to this page

The bar is a measurement, not an opinion. `irlume padcapture` and `irlume
padreport` are the tools; [`PAD_SELFTEST.md`](PAD_SELFTEST.md) describes the
protocol. A candidate needs genuine and attack presentations on real hardware,
enough of both to see where the populations sit, and a written result in
`pad-results/` before a threshold is chosen from it.

Every measurement in this repository so far comes from one subject on one or two
cameras, which is stated in each document and is the standing limitation on all
of it.
