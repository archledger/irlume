# Third-party liveness models irlume has measured

irlume's built-in liveness gate does not stop a printed photograph of an
enrolled face. That is measured, not suspected: the gate returned `Live` for all
24 presentations of a vinyl print in issue #235, and again for an enhanced
version of the same attack, so a trained cue is currently the only thing that
refuses it. See [the PAD results](pad-results/) for every number behind that.

This page lists the models irlume can use for that job. **Everything here was
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

## How to read an entry

Run `irlume models` for the live version of this table. Each entry states:

| field | what it means |
|---|---|
| `license` | the publisher's licence for the weights, as published |
| `provenance` | whether the training data and pipeline are documented, and so whether the model could ever meet [ADR-0001](adr/0001-liveness-pad-strategy.md) |
| `threshold` | the decision point irlume **measured**, never the publisher's default |
| `measured` | the one-line result, pointing at the full document in `pad-results/` |
| `obtain` | whether irlume fetches it, or you supply the file |

The threshold is the part that matters most and the part a page like this
usually gets wrong. A deny-only cue firing in a score band where neither genuine
faces nor attacks were observed is guessing, and it guesses against the user:
every false fire costs a real login. So irlume sets each threshold from where
the two populations were actually seen to sit on its own hardware.

## The models

### `flir` — irlume fetches it

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

None yet. When a model whose licence prevents irlume from fetching it has been
measured, it appears here with its pin, its threshold and its `pad-results`
document, and is installed with:

```sh
sudo irlume models add <name> /path/to/weights.onnx
```

irlume verifies your file against the published sha256 before enabling it. If it
does not match, it is refused: that file is not the artifact the threshold was
measured on.

Whether a given licence permits **your** use of a model is your determination.
irlume prints the licence before enabling anything and distributes no weights.

## What is deliberately not here

- **Models irlume has not measured.** Publishing "this probably works" is how a
  page like this becomes a recommendation engine for untested weights.
- **Any model as a default.** These cues are deny-only: they can refuse a
  presentation the built-in gate accepted, never approve one it rejected. That
  is what makes them safe to add, and it is also why a broken one degrades
  quietly rather than loudly, so `irlume doctor` reports which model is active
  and whether its weights still match their pin.

## Adding a model to this page

The bar is a measurement, not an opinion. `irlume padcapture` and `irlume
padreport` are the tools; [`PAD_SELFTEST.md`](PAD_SELFTEST.md) describes the
protocol. A candidate needs genuine and attack presentations on real hardware,
enough of both to see where the populations sit, and a written result in
`pad-results/` before a threshold is chosen from it.

Every measurement in this repository so far comes from one subject on one or two
cameras, which is stated in each document and is the standing limitation on all
of it.
