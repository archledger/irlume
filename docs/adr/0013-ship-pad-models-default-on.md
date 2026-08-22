# ADR-0013: Ship both PAD models default-on (ViT RGB + FLIR IR)

**Status:** Accepted
**Date:** 2026-08-22
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
   `scripts/fetch-models.sh` for dev/CI trees.

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
   - ViT: m96 crop, threshold 0.60, 5-frame-median vote per
     authentication. The vote is part of the measurement (LFW: 0.29%
     frame-level tail → 0/531 presentation false-fires under 5-median).
   - FLIR: 0.9 on lit-phase IR frames, the 2026-07-27 re-measured window
     (genuine max 0.702, attack floor 0.941).

5. **Kill switches** are first-class: env (`IRLUME_PAD_VIT` /
   `IRLUME_PAD_IR`) and settings.conf (`pad_vit` / `pad_ir`). A
   kill-switched cue skips startup verification entirely and its absence is
   named in the startup log.

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
  disable in one step. Re-qualification is required (and this ADR's
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
