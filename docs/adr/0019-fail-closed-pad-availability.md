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
