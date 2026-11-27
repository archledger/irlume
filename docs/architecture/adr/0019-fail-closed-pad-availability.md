# ADR-0019: Fail closed when required PAD evidence is unavailable

**Status:** Accepted
**Date:** 2026-08-31
**Amends:** [ADR-0013](0013-ship-pad-models-default-on.md)
**Implementation:** `irlume-auth` PAD evidence policy, daemon PAD health fields

## Context

ADR-0013 made the shipped RGB and IR PAD classifiers default-on and deny-only.
The score rule was fail safe: a confident attack score could only tighten a
Live verdict. Model availability was not. A missing or disabled model, or an
inference error, collapsed to the same `None` used for a modality that did not
apply. Authentication then continued and could grant from the algorithmic gate
alone, despite the threat model declaring PAD mandatory and documenting a
98.6% glossy-print bypass of that gate.

Killing the daemon when PAD cannot load is also the wrong failure mode. It
would remove password fallback, status, diagnostics, and management operations
at the moment they are needed. Authentication availability and daemon
availability therefore need separate policies.

## Decision

The daemon starts when a PAD model is missing, disabled, or fails to load. Core
detection and recognition model failures remain fatal. The daemon reports each
PAD model as `loaded`, `disabled`, `missing`, or `load-failed` through additive,
backward-compatible health fields.

Strict checksum verification still rejects altered PAD weights, but rejects the
cue rather than the daemon: the corresponding status is `load-failed` and face
authentication falls back to password. Strict failures in core models remain
startup-fatal.

Every face grant requires produced evidence from every PAD model applicable to
that grant:

| Face grant path | Required PAD evidence |
|---|---|
| RGB-only convenience | ViT RGB |
| RGB+IR secure | ViT RGB and FLIR IR |
| Dark IR-only | FLIR IR |

Authentication carries private evidence states that distinguish not
applicable, model unavailable, inference failed, and score produced. An
unavailable model or failed inference on a required modality produces an
immediate nonretryable policy denial that directs the user to password
fallback. It is not labeled as a spoof because no attack was established.

Clarified 2026-11-17: the
[retry-precedence amendment](#amendment-2026-11-17-execution-failures-before-retries)
below specifies the order when another refusal also applies.

A produced score keeps ADR-0013's measured behavior and thresholds. Confident
attack scores remain spoof denials; valid scores permit the existing identity
and liveness gates to decide. A model not applicable to the selected grant path
is not required.

The existing PAD kill switches remain supported for diagnosis, but their
meaning changes: they put affected face grants into password-only mode. They no
longer restore the algorithmic-gate-only grant path.

## Consequences

- A partial model install or runtime loader failure does not take down the
  daemon, password fallback, health, or repair tooling.
- A PAD outage cannot silently widen the face-authentication policy.
- Health consumers can distinguish an older daemon, which reports no PAD
  fields, from each current failure state without receiving internal loader
  error text.
- Operators diagnosing false PAD fires can still disable a cue, but face
  authentication remains unavailable until the cue is restored.
- ADR-0013's operating points, model provenance decision, and measured attack
  coverage remain unchanged.

## Amendment 2026-11-17: execution failures before retries

If an assessment reaches final admission and the selected outcome is
presence-retryable, a recorded execution failure of PAD required by that
route prevents another grace retry. The result is `RuntimeUnavailable`
with password guidance.

Existing authority, capture, cancellation, deadline and eager identity
failures remain prior, as do already-terminal ordinary diagnostics. This
includes an unmeasurable-exposure refusal, a nonretryable gate spoof and an
incompatible dark enrollment where the template check is reached. The
presence-retryable RGB-yes/IR-no spoof (`SpoofNoIrFace`), including a rescued
IR face below the liveness gate's confidence cutoff, is replaced like
`Uncertain`. Its situation becomes `unavailable`, and its wire cause
changes from `LivenessRefused` to `Other`, reporting an operational failure.
In a lit scene, ordinary admission selects a retryable scene refusal before
reaching the template check; a recorded required IR failure replaces that retry even
if the later template would be incompatible. No check is moved earlier.
Grouped admission keeps its existing terminal diagnostic order, which need
not select the same reason as ordinary admission.

Only recorded `Unavailable` and `InferenceFailed` qualify. Existing
producers normalize native nonfinite answers into `InferenceFailed`;
the retry selector does not reinterpret raw scores. `Pending`,
`NotApplicable` and finite PAD scores are not execution failures.
NoFace/inapplicable samples keep their presence handling, but no candidate
grant is exempt from full required-evidence checks. Dark capture does not
acquire an RGB PAD requirement, nor RGB-only convenience an IR requirement.

RGB execution failures are recorded only while the frame is still Live
when RGB PAD is reached. A produced score can remain recorded if its vote
later downgrades the frame to Spoof. Mixed non-Live gate failures therefore
arise from recorded IR execution; grouped precomputation does not change
this rule. This is not a new missing-model preflight before a face exists.
Eligible managed collection requires loaded PAD cues; a managed execution
error is `InferenceFailed`, not a missing session.

The existing accounting applies: `RuntimeUnavailable` adds a short-cooldown
strike, while the reserved request keeps one durable charge. There is no
charge per internal capture, strike exemption or reset. The general
classifier used in tests keeps the same strike classification.
This changes retry termination and its diagnostic/accounting consequence,
not grant eligibility, model defaults, operating points or identity policy.
