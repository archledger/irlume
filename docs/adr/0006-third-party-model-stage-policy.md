# ADR-0006: Which pipeline stages accept third-party models, and on what evidence

**Status:** Accepted
**Date:** 2026-08-12

## Context

The shipped model stack is chosen for a commercially clean bill of
materials, and that constraint is irlume's, not its users'. #275 built the
mechanism for exactly one stage (a catalog entry measured and pinned,
installed with `models add`, verified against the sha256 irlume measured),
and issue #276 asked the question this ADR answers: the stages are not
equally safe to open, so which may accept a third-party model, and what
evidence does each require? The stage-by-stage work merged across #277,
#278, #279, #280, #293, #294 and #295; the normative pieces lived on the
issue thread, and a policy whose canonical text sits in an issue is one
close away from being unfindable. This ADR is that text's home.

## Decision

- **The pin is the whole safety property.** Every stage that opens keeps
  the catalog discipline: an entry names its stage, its license, its
  provenance, its measured threshold and its sha256, and the daemon runs
  exactly the pinned artifact or refuses to start. There will never be a
  directory where an ONNX file is dropped and silently used.
- **Liveness (PAD): open.** Its wiring is deny-only: a hostile, broken or
  mismatched model can refuse a presentation the built-in gate accepted,
  never approve one it rejected. Every false denial falls back to the
  password. No other stage has this property, which is why it opened first.
- **Recognition: open, only under the split-source threshold protocol.**
  The stage is grant-capable and a swapped embedder fails silently, so an
  entry earns its threshold; a publisher default is never adopted. The
  protocol's four clauses, none substitutable:
  1. The artifact is pinned against the publisher's official distribution.
  2. The false-accept side is measured offline at population scale through
     irlume's own pipeline, never taken from publisher numbers: at minimum
     the full LFW protocol, all seven FairFace groups individually, and one
     synthetic set named down to the part and selection rule.
  3. The false-reject side is measured on this project's cameras as a live
     genuine floor, confirmed per user at enrollment. A floor that does not
     clear the threshold means re-enroll or decline the model, never lower
     the threshold.
  4. The candidate's worst FairFace group FAR must not exceed the shipped
     stack's worst group at its own operating point, and any residual above
     1e-4 is published in the `FAIRNESS.md` style.
  A third-party recognizer runs RGB matching only (no IR matching, fusion
  or dark login without IR-side measurements), and templates are tagged
  with the digest of the weights that produced them, so switching
  recognizers means re-enrolling, never comparing across embedding spaces.
  The first entry (`buffalo`, threshold 0.55) was measured under this
  protocol on 2026-08-05; the record is in `docs/recognition-results/`.
- **Detection: closed until an end-to-end corpus exists.** The rescue slot
  is grant-capable: when the primary detector returns nothing, a rescue
  detection is aligned, embedded and matched, and can reach a grant. The
  candidate (full-range BlazeFace) is implemented, parity-tested and
  operating-point-measured, and stays unenableable because the corpus that
  would justify it does not exist yet: YuNet-miss frames carrying prints of
  the enrolled face, screens, other faces and genuine users, followed
  through to the authentication outcome. Availability and hallucination
  corpora measure the wrong thing for a grant-capable slot.
- **Landmarks: closed, nothing to open for.** The measured mesh is the
  shipped artifact byte for byte, and the one alternative bundle fails the
  clean-BOM bar. The #293 geometry gates (pathological boxes and NaN
  landmarks abstain with named reasons) protect the cues that consume
  landmarks regardless of where a mesh comes from.

## Consequences: accepted residual risk

An opted-in third-party model remains an unaudited artifact: the catalog
pin proves identity, the measured threshold bounds the operating point, and
provenance gaps are disclosed per entry rather than resolved. The
recognition protocol's FAR side rests on public datasets; a live impostor
distribution is unmeasurable with one enrolled subject, so the threshold
rule is comparative against the shipped stack, not absolute.

## Revisit when

- The detection corpus described above exists: its result decides both the
  stage and whether any catalog entry may carry the rescue model.
- A PAD candidate answers its decisive question live: the current RGB
  candidate's attack behaviour is unanswerable offline (stored attack
  bursts are IR-only), and its preprocessing fork must be settled by
  measurement before any entry ships.
- A recognition entry wants IR-side matching: that reopens the disabled
  fusion paths and needs IR-side measurements this protocol does not yet
  define.
