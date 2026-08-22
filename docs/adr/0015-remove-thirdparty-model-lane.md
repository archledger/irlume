# ADR-0015: Remove the third-party / bring-your-own model lane

**Status:** Accepted
**Date:** 2026-08-22
**Implementation:** With this PR.

## Context

Issue #4 opened an opt-in lane for externally-trained models: a measured,
sha-pinned catalog (`irlume_common::thirdparty`) with per-stage settings keys,
a CLI (`irlume models list/enable/disable/add`) carrying license/provenance
consent, and engine wiring for third-party PAD cues, a replacement RGB
recognizer (`buffalo`, InsightFace w600k_r50), and a replacement rescue
detector. The lane existed because ADR-0001's shipped-stack bar (warrantable
training data) ruled those weights out of the default install while their
measurements showed real value (the FLIR print-defence cue) or parity-level
quality (buffalo at 0.55).

Since then the product's direction settled, and the lane's premises changed:

- **The FLIR cue ships.** ADR-0013 moved both measured PAD cues (ViT RGB +
  FLIR IR) into models-v1, default-on and startup-verified. The lane's
  strongest use case became the default.
- **A replacement recognizer was always a poor trade.** It replaces exactly
  one thing (AuraFace) while disabling IR matching, fusion, dark login, and
  the calibrated centroid (all unmeasured for the external model), forces
  re-enrollment (templates are per-space, #288), and forfeits the Secure
  tier's tested thresholds. InsightFace's licensing (WebFace600K is
  web-scraped without subject consent; the zoo is non-commercial research
  only) additionally rules it out of any shipped posture permanently.
- **The value proposition is a validated stack, not a framework.** Irlume is
  a secure biometric authentication system with a controlled security
  profile: few components, deep validation, known behavior, reproducibility.
  Interchangeable recognizer slots are the opposite shape.

## Decision

The lane is removed entirely:

- `irlume_common::thirdparty` (catalog, stages, settings keys, weight-state
  machinery) is deleted. `sha256_hex` was already a common-root utility.
- The engine keeps only the shipped model builders (YuNet/BlazeFace rescue/
  FaceMesh/AuraFace + adapter/ViT PAD/FLIR PAD). The third-party PAD cue
  slot, `with_thirdparty_recognizer`, `with_full_range_rescue`, and the
  `ir_matching` kill-switch that existed solely for the external-recognizer
  policy are gone. The deny-only helper survives as `pad_downgrades`.
- The daemon resolves the shipped stack only. Legacy `settings.conf` keys
  (`third_party_pad` / `third_party_recognizer` / `third_party_detector`)
  and the env override are ignored with a startup NOTICE (an enrollment
  made under an external recognizer is quarantined by its embedding-space
  tag; re-enrollment restores face auth, password fallback applies until
  then — fail-closed, never lockout).
- The CLI `models` command answers a removal notice (exit 2).
  `profiles forget-model` still accepts `shipped` and literal
  `embed:<64-hex>` spaces so legacy external-space scans can be cleaned.
- The TUI loses its third-party Settings section and toggle; Health drops
  the three `third_party_*` fields.
- The machine API keeps contract 1: `models.list --json` still reports the
  four stages with `open` present and `false` everywhere (now simply true —
  no stage accepts third-party models) and no `third_party` objects, exactly
  the shape the schema defines for closed stages.
- `setup` no longer offers a model step: the shipped cues are default-on.

Internal architecture abstractions (the PadVit/PadIr/embedder seams in
irlume-vision) stay — they are engineering structure, not a public ecosystem.
If a future, license-clean external model is ever measured to beat the
shipped stack decisively, the path is a NEW shipped model replacing the old
one in models-v1 with re-validation and a space migration, not a slot.

## Consequences

- The maintainable surface shrinks by one subsystem (catalog + consent flow +
  wiring + their tests and docs) and one authentication-policy hazard (a
  grant-capable component outside the validated set).
- `docs/THIRD-PARTY-MODELS.md` is removed; the measurements remain in
  `docs/pad-results/` and `docs/recognition-results/` as the historical
  evidence base.
- Buffers: a buffalo-era enrollment keeps functioning as password-fallback
  (its scans cannot match under AuraFace; the quarantine is by design, #288).
- Future evaluation work (e.g. better IR recognizers) continues to be
  welcome as RESEARCH that could replace a shipped model, per the FRIR
  precedent — it just cannot ship as a user-selectable slot.
