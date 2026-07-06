# Demographic fairness — measured FAR variance and policy

irlume publishes its demographic error rates rather than hiding them. Face
recognition has well-documented demographic differentials (NIST FRVT Part 3);
irlume is not exempt, and an auth system that pretends otherwise is more
dangerous than one that measures and bounds the gap. This document states the
measured variance, the recognizer trade-off we accepted, and the policy that
keeps the residual gap from becoming a security hole.

## Measured demographic FAR (recognizer: AuraFace)

False Accept Rate is **demographic-differential**: impostors who share a
demographic group are harder to separate, so within-group FAR is the honest
operational number (a mixed-population FAR understates real risk). Measured on
FairFace (validation split, ~1,100–1,900 faces/group, YuNet → AuraFace, all-pairs
impostor; same pipeline as production; 0.50 is the measurement threshold used
throughout this document):

| Group | FAR @ threshold 0.50 |
|---|---|
| White | 1.05×10⁻⁴ |
| Indian | 1.68×10⁻⁴ |
| Latino/Hispanic | 2.52×10⁻⁴ |
| Black | 4.37×10⁻⁴ |
| Middle Eastern | 4.50×10⁻⁴ |
| Southeast Asian | 7.46×10⁻⁴ |
| **East Asian** | **1.04×10⁻³** |

**Spread ≈ 10×.** At the 0.50 measurement threshold, only the
best-served group meets NIST FMR ≤ 1×10⁻⁴; the others exceed it within-group.
A single fixed threshold that holds FAR ≤ 1×10⁻⁴ for **every** group requires
≈ **0.69** (bound by the worst groups). A cross-check on real faces (LFW,
13,233 images, 87M impostor pairs, same YuNet→AuraFace pipeline) measured the
all-pairs RGB FAR at 0.50 at **2.3×10⁻³** (reproduce it with the command in the
Appendix). That is *higher* than the FairFace per-group figures above, not
lower: LFW is unconstrained web imagery — varied pose and lighting, with some
near-duplicate identities — that aligns less cleanly than FairFace's curated
crops, so real-world faces are the harder test. The shipped RGB threshold is
stricter than the 0.50 measurement point (0.55, with template-count scaling up
to +0.10; the IR path uses 0.55 native / 0.40 adapted, and calibrated RGB+IR
fusion grants at probability ≥ 0.50), and the mandatory password fallback
bounds the residual either way.

## The recognizer trade-off (why we keep AuraFace)

A stronger recognizer narrows the gap. **buffalo_l** (InsightFace, Glint360K) on
the identical protocol cut the spread to ≈ 4.5× and halved the worst-group FAR —
it is both fairer and more accurate. **We do not use it.** buffalo_l is trained
on MS-Celeb-1M / Glint360K (web-scraped, non-consensual, research-/non-commercial
license). Bundling it would break irlume's clean Bill of Materials and the GPL's
promise of downstream commercial freedom (see `docs/ARCHITECTURE.md` and the
model-licensing notes). We accept a fairness/accuracy cost to stay legally clean.

The gap is therefore **partly recognizer quality** (a better-trained model helps)
and **partly intrinsic** to recognizers trained on demographically-skewed data.

## Mitigation: clean synthetic debiasing (benchmark)

Training a debiasing adapter on **DigiFace-1M** (synthetic, 3D-rendered,
demographically diverse, no scraped real people) and applying it to AuraFace's
embeddings reduces the disparity **~30%** on real faces:

- per-group FAR disparity (max/min, at matched pooled FAR): **4.5× → 3.0×**
- coefficient of variation across groups: **0.52 → 0.36**
- result is scale-invariant (not an artifact of the adapter compressing the
  cosine range) — both absolute spread and CV drop by the same ~30%.

This proves fairness *can* be moved with **commercially-clean synthetic data**
rather than tainted scraped datasets. **It is a benchmark, not a shipped default**,
and a deploy-safety test on real faces shows why. Measured on LFW (real,
identity-labeled — the genuine pairs FairFace lacks), the same adapter **degrades
overall recognition**:

| | Raw AuraFace | DigiFace-adapted |
|---|---|---|
| EER | 4.17% | 5.12% (+23%) |
| FRR @ matched FAR (1e-3) | 4.65% | **10.62%** (2.3×) |

The adapter balances demographics but compresses genuine similarity on real faces
(mean 0.584 → 0.447) — the synthetic→real **domain gap** (AuraFace embeds
DigiFace's synthetic faces at EER 8.7%). Deploying it would more than double the
false-reject rate, so it is **not** in the auth path. A deployable clean debiasing
adapter needs either synthetic data with a smaller domain gap to real faces (a
generator AuraFace embeds well) or real consented diverse data — plus a
commercial license (DigiFace is non-commercial). The ~30% result stands as proof
the lever exists; this particular adapter is not the one to ship.

## Policy: a single conservative threshold + uniform fallback

irlume does **not** classify a user's demographic group at authentication time to
pick a threshold. Runtime demographic classification is privacy-invasive,
unreliable, and self-defeating for a fairness goal — and it is unnecessary. The
right direction is a **single fixed threshold chosen conservatively against the
worst-performing group's curve** — the shipped 0.55 (vs the 0.50 measurement
point) moves that way, though fully bounding every group at 1×10⁻⁴ would need
≈0.69 and a real FRR cost; the residual gap is bounded by the mandatory
password fallback, never by relaxing FAR. Users in better-served
groups pay a slightly higher False Reject Rate than strictly necessary; that cost
is absorbed **uniformly** by the mandatory non-biometric fallback.

Because the biometric is **one MFA factor with a mandatory fallback** (see
`docs/THREAT_MODEL.md`), residual demographic variance manifests as a *convenience*
cost (an occasional password/PIN prompt), never as a security hole:

1. The PAM module captures and scores the frame.
2. On a sub-threshold (or low-confidence) match it returns control to the stack
   rather than hard-failing — the existing greeter/sudo/lockscreen fallback to
   `pam_unix` (password) engages seamlessly.
3. The user authenticates with the secondary factor; FAR is never relaxed to
   accommodate a harder-to-match face.

This is the "MFA as equalizer" principle: tune the threshold for the worst case,
let the fallback absorb the FRR, and never trade away the false-accept bound.

## Roadmap to closing the gap (cleanly)

- Commercially-licensed synthetic generation (own pipeline or permissive set) to
  ship a debiasing adapter, and to validate its real-face FRR before it enters
  the primary path.
- Own consented, demographically-diverse data collection — the only route to a
  *shippable + clean + fair* recognizer; public balanced sets (BUPT-Balancedface)
  are MS-Celeb-derived and fail the clean-BOM test.
- The melanin-independent NIR liveness gate (>1.2 µm skin remission) is
  fair-by-physics and partially offsets demographic effects on the *liveness*
  decision, though not on recognition FAR.

## Reproducing these numbers

```
# per-group FAR (one directory of distinct-identity faces per group)
# (irbench is dev-gated: export IRLUME_DEV=1)
IRLUME_DEV=1 irlume irbench --dir <group_faces> --det <yunet> --model <glintr100> --impostor-only
# real-face FAR + FRR (identity in filename, LFW convention)
irlume irbench --dir <lfw/images> --det <yunet> --model <glintr100> --lfw
```

Datasets: FairFace (CC-BY-4.0, demographic labels), LFW (real, identity labels),
SFHQ (synthetic, FAR), CBSR/Oulu (NIR), DigiFace-1M (synthetic, non-commercial,
debiasing). All evaluation-only; none are bundled.
