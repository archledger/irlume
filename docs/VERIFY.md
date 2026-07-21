# Verify irlume's claims yourself

irlume makes measurable claims: anti-spoof numbers, encrypted storage, error
rates. None of them ask for your trust: each maps to something you can run on
your own machine and check against the docs. This page collects the
reproductions, easiest first.

If a claim in the README or docs has no reproduction path here and you think it
should, open an [issue](https://github.com/archledger/irlume/issues) or a
[discussion](https://github.com/archledger/irlume/discussions).

---

## 1. Your face is stored encrypted, never as an image · ~2 min

**Claim:** templates are 512-D embeddings (never images), AES-256-GCM encrypted
under a TPM-sealed key, root-only at rest.

After enrolling a face, look at the stored profile:

```sh
sudo head -c 200 /var/lib/irlume/*.json
sudo stat -c '%a %U:%G' /var/lib/irlume/*.json
```

You will see `{"version":2,"enc":"<base64 ciphertext>"...}` and mode `600
root:root`. The biometric data is an encrypted blob, not readable embeddings,
and no image is ever written.

On a machine **without** a TPM the daemon stores the same embeddings root-only
but unencrypted. The TUI says so on the Keyring tab, and the cross-machine
disk-theft test (copy the files to a second machine with its own TPM: they do
not decrypt) is written up in [`SECURITY_AT_REST.md`](SECURITY_AT_REST.md).

## 2. The per-camera anti-spoof numbers are real readings · ~2 min

**Claim:** the moiré values in
[`cross-distro/2026-07-01-arch-ubuntu-survey.md`](cross-distro/2026-07-01-arch-ubuntu-survey.md)
(≈9–13 on one camera, ≈18–27 on another) are real readings from the code.

Turn on the daemon's diagnostic tracing:

```sh
sudo irlume logs debug on
```

If your camera is an **IR (Windows Hello)** one, also force the RGB path the
moiré cue lives on (it drops to the RGB / convenience tier for the test):

```sh
sudo systemctl edit irlumed     # add:  [Service]  Environment=IRLUME_FORCE_NO_IR=1
sudo systemctl restart irlumed
```

Run a check with a lit face:

```sh
irlume identify
irlume logs | grep moire
```

You will see your own camera's score, e.g. `rgb-only cues: ... moire 10 ...`.
Different camera modules read different values; that per-camera spread is the
whole reason the threshold is tunable per camera. Put things back when done:

```sh
sudo systemctl revert irlumed && sudo systemctl restart irlumed
```

## 3. It builds and passes its tests · ~5 min

**Claim:** the workspace is real, tested Rust.

```sh
git clone https://github.com/archledger/irlume
cd irlume && git lfs pull
cargo test --workspace
```

Around 150 tests pass; the fifteen or so that need camera or TPM hardware are
marked `ignored`.

## 4. The liveness gate is self-tested against ISO/IEC 30107-3 · deeper (needs your own spoofs)

**Claim:** the presentation-attack self-test methodology and results in
[`PAD_SELFTEST.md`](PAD_SELFTEST.md).

The tooling is dev-gated (`IRLUME_DEV=1`) and opens the camera directly. A live
bona-fide capture works with no extra configuration:

```sh
IRLUME_DEV=1 irlume padcapture --species live --kind bonafide \
  --det /usr/share/irlume/models/face_detection_yunet_2023mar.onnx \
  --out pad.jsonl --n 5
```

To measure attack resistance you make the spoofs yourself (a matte print, a
glossy print, a phone or tablet replay) and capture each as its own species:

```sh
IRLUME_DEV=1 irlume padcapture --species phone_replay --kind attack \
  --det /usr/share/irlume/models/face_detection_yunet_2023mar.onnx --out pad.jsonl
IRLUME_DEV=1 irlume padreport --in pad.jsonl --md report.md
```

The report gives per-species APCER / BPCER with exact-binomial confidence
intervals; a 0% point estimate on a small sample does not prove 0% (read the
upper CI bound). This is the same tooling that caught the
life-size glossy-vinyl breach documented in the
[threat model](THREAT_MODEL.md), including the failures, not just the wins.

## 5. The demographic FAR numbers · deeper (needs a face dataset)

**Claim:** the real-face False Accept Rate in [`FAIRNESS.md`](FAIRNESS.md).

Download LFW (Labeled Faces in the Wild), for example the
[Kaggle `jessicali9530/lfw-dataset`](https://www.kaggle.com/datasets/jessicali9530/lfw-dataset),
the source used here. Any copy with the standard `Person_Name_NNNN.jpg`
filenames works; the figure is stable to the variant. Then run the impostor
benchmark against the bundled recognizer:

```sh
IRLUME_DEV=1 irlume irbench --lfw --impostor-only --dir <lfw-image-dir> \
  --det /usr/share/irlume/models/face_detection_yunet_2023mar.onnx \
  --model /usr/share/irlume/models/glintr100.onnx
```

On the full set (13,233 images, ~87M impostor pairs) you get FAR ≈ **2.3×10⁻³
at threshold 0.50**, the same figure `FAIRNESS.md` reports and reasons about
(it is higher than the curated-dataset per-group numbers because LFW is
unconstrained real-world imagery). Embedding all 13k images takes roughly an
hour on a CPU; `--max-images N` bounds it for a quick look, at the cost of a
noisier estimate. `FAIRNESS.md` has the full protocol and the per-group
FairFace table.

## 6. The model-accuracy numbers · benchmarks/

**Claim:** the recognition, detection-cascade, and landmark figures in the
README, [`models/README.md`](../models/README.md), the CHANGELOG, and the release
notes (LFW 99.03%, the IR-adapter overfit that justified its removal, the
cascade's 76.9% → 98.5% outdoor rescue, the 478-point mesh's 28% eye-NME gain).

The scripts that produced every one of these live in
[`../benchmarks/`](../benchmarks/), and the raw result files are committed beside
them (`results-*.json` / `.log`); read them directly, or reproduce from scratch
on the public datasets (LFW, CBSR NIR, Oulu-CASIA NIR, Tufts Face). Datasets,
exact protocols, the runtime, and the honest caveats (small outdoor sample;
InsightFace's non-commercial recognizer beats the permissive one irlume ships)
are all in [`../benchmarks/README.md`](../benchmarks/README.md).

## 7. The release you downloaded is the one that was published · ~2 min

**Claim:** the `.deb` and SELinux `.rpm` on a GitHub release are the exact bytes
the maintainer published, signed two independent ways.

First, the GPG-signed checksum manifest (the release key is
`F350 5339 8E3C 80FE 2089 1B82 C10B 8492 BD7F 30C6`, committed at
[`.github/release-signing-key.asc`](../.github/release-signing-key.asc)):

```bash
gpg --import .github/release-signing-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --strict SHA256SUMS
```

Second, the SLSA provenance attached to the release
(`multiple.intoto.jsonl`, Sigstore/Fulcio keyless-signed and logged in Rekor),
which you check with [slsa-verifier](https://github.com/slsa-framework/slsa-verifier):

```bash
slsa-verifier verify-artifact irlume_*.deb \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/archledger/irlume
```

The `.github/workflows/verify-release.yml` job runs the GPG + checksum + coverage
checks on every release automatically; the provenance is generated by
`.github/workflows/slsa-provenance.yml`.

---

**A note on effort.** Some of these reproductions are easy (1–3, 6, 7) and some take
real effort (4–5). The point is that every claim *can* be checked, against code
and data that are in this repo.
