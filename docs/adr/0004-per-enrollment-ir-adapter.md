# ADR-0004: Retire the shipped IR adapter; adapt per enrollment on-device

**Status:** Accepted. Direction set 2026-07-15; the removal ships in the
release after the space-tagging groundwork (`e6c23f5`), the per-enrollment
calibration is future work validated in principle but not yet built.
**Date:** 2026-07-15

## Context

`ir_adapter.onnx` (a 512→512 residual MLP applied to IR embeddings on both
the template and probe side) has two problems, one legal, one structural.

**Legal.** Both shipped versions (v1 and v3) were trained on AuraFace
embeddings of the CBSR NIR (OTCBVS dataset 07) and Oulu-CASIA NIR academic
datasets, whose grants cover education and research use only. By the same
standard this project applies to third-party weights (ADR-0002's Silent-Face
analysis), the adapter's weights carry that restriction, which conflicts
with the commercial freedom GPLv3 promises downstream. The
[models/README.md](../../models/README.md) provenance claim was corrected on
2026-07-14 (`03d1a51`); this ADR records the remediation decision.

**Structural.** A global adapter is trained once and runs on every install,
so it must improve recognition for faces and cameras it has never seen. A
2026-07-15 experiment measured how hard that is. An adapter of the same
architecture ("v5") was trained on 1,137 license-clean self-captured
embedding pairs (2 identities, 12 lighting/distance/eyewear conditions, one
consumer Hello camera) and evaluated two ways:

| Evaluation | raw AuraFace | v5 |
|---|---|---|
| Held-out lighting conditions, trained identities | 3.41% EER | 0.61% EER |
| CBSR NIR, 197 unseen identities | 0.77% EER | 1.00% EER |
| Tufts NIR-NIR, 110 unseen identities | 1.43% EER | 1.53% EER |
| Tufts cross-spectral (RGB enroll, NIR verify) | 0.90% EER | 0.97% EER |

The same weights that cut error by 5x for the people in the training set
made every stranger slightly worse off. The shipped v3 shows the same
pattern on the datasets it never saw (Tufts NIR-NIR 1.43% → 1.53%). Small-
cohort adapters personalize; they do not generalize. Growing the cohort
enough to change that would need a consented multi-hundred-person capture
program, which is out of reach and, per the measurements below, unnecessary.

Two more measurements close the case for removal:

1. With IR templates enrolled (which irlume stores by default), matching raw
   IR probes against raw IR templates scores within 0.07 EER points of the
   adapter path on data the adapter never trained on (Tufts: 0.69% raw
   templates vs 0.62% adapted). The global adapter's honest value to a
   stranger is at most that margin.
2. The per-condition win above (3.41% → 0.61%) shows where the adapter idea
   actually pays: adapted to the specific person and camera it serves.

## Decision

1. **Stop shipping `ir_adapter.onnx`.** The engine already runs without it
   (raw IR embeddings, `IR_MATCH_THRESHOLD`). Embedding-space tagging
   (`e6c23f5`) makes the transition fail loud: templates recorded under the
   adapter no longer match a raw pipeline, and the dark path answers
   "re-enroll to refresh dark unlock" instead of scoring garbage.
2. **Replace global adaptation with per-enrollment calibration, on-device.**
   At enroll (or first logins), fit a small correction from the user's own
   scans, in the spirit of the per-user IR liveness floors that already
   exist. Candidate forms, cheapest first:
   - a closed-form linear map (least-squares / orthogonal Procrustes) from
     the user's IR embeddings toward their RGB anchor: no ML runtime, a few
     hundred floats of state, solvable in Rust;
   - the residual-MLP form of this experiment, if the linear map measurably
     underperforms it (requires an on-device training story).
   Any fitted correction is per-user state derived from consented local
   data: nothing ships, nothing is redistributed, no license surface exists.
3. **FAR guard.** A correction fitted only on genuine data can drag
   impostors closer along with the owner. Before any per-enrollment
   calibration is enabled by default, it must show non-inflated FAR against
   an impostor set (the project's self-captured cross-identity data and the
   public benchmarks used above), and it must never relax the operating
   threshold on its own.

## Consequences

- The model BOM becomes fully clean: YuNet (MIT), AuraFace (Apache-2.0),
  MediaPipe FaceMesh (Apache-2.0), algorithmic liveness, no adapter.
- Existing enrollments keep working until the removal release; then dark
  unlock asks for one re-enroll (bright-path RGB matching is unaffected).
- Strangers to the old training set lose nothing measurable; the ~0.07-point
  margin returns, better, once per-enrollment calibration lands.
- The 2026-07-15 self-captured dataset (1,137 pairs and growing) becomes the
  validation bed for the calibration feature and for any future revisit of a
  global adapter, should a large consented cohort ever exist.
