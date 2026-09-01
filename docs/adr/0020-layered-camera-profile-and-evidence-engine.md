# ADR-0020: Layer camera profiles, conditioning, and model evidence

**Status:** Accepted
**Date:** 2026-09-01
**Amends:** [ADR-0007](0007-context-bound-capture-qualification.md)
**Design:** [Layered Camera Profile And Evidence Engine](../superpowers/specs/2026-09-01-layered-camera-profile-engine-design.md)

## Context

Irlume already converts V4L2 payloads into owned RGB8 and GREY8 frames, reduces
bounded RGB and IR bursts, validates frame provenance, and applies
model-specific preprocessing. It does not feed borrowed camera buffers directly
to models.

The capture path still requests one fixed geometry per role and accepts the
driver's default interval. Hardware experiments found one lower-demand ASUS
tuple that is transport-promising, while lower BRIO demand did not rescue
concurrent capture and NexiGo exposes no lower-demand decoded tuple. Transport
evidence alone does not establish detector, recognition, liveness, PAD, or
latency suitability.

Camera controls and post-capture preprocessing also solve different problems.
Only format, geometry, interval, and compression negotiated before streaming
can reduce USB demand. Control selection and canonical preprocessing can improve
signal quality and model stability, but can also change calibrated security
behavior if adjusted without qualification.

## Decision

Use a layered qualified policy engine.

- A qualification-time transport-profile engine selects only exact
  device-advertised and fully qualified RGB/IR tuples.
- Security and quality are hard gates. Balanced USB demand and p95 latency rank
  only profiles that pass every gate.
- The qualified transport profile remains fixed for its exact camera and
  connection context.
- A runtime conditioning controller may choose among pre-qualified standard
  camera-control and preprocessing policies between authentication attempts.
- One immutable attempt capture plan freezes transport, conditioning,
  preprocessing, calibration, and model contracts for each evidence window.
- Capture converts device-specific payloads into owned canonical evidence.
  Model gateways accept only typed canonical inputs with matching contracts.
- Runtime degradation may select an already-qualified sequential schedule for a
  later attempt, but cannot invent or switch transport profiles.
- Required PAD evidence remains fail closed under ADR-0019.

## Alternatives Considered

### Unified Optimizer

A single optimizer over transport, controls, preprocessing, and models was
rejected because its qualification state is combinatorial and difficult to
reproduce, invalidate, or audit.

### Learned Adaptive Tuner

A controller driven by model confidence was rejected because input controlled
by an attacker could influence capture policy, changing the model distribution
and security operating point during authentication.

### Vendor-Specific Overrides

Fixed presets keyed only by camera model were rejected because they ignore
firmware, endpoint incarnation, USB topology, driver behavior, and
model/preprocessing versions.

## Consequences

- Models receive stable input contracts independent of camera-native formats.
- USB-demand selection and image conditioning remain independently testable.
- Runtime adaptation is broader than a fixed camera preset but remains bounded
  and reproducible.
- Qualification must cover every accepted profile and conditioning policy
  through detector, recognition, liveness, PAD, and latency gates.
- The ASUS RGB15/IR15 profile remains unauthorized until those gates pass.
- BRIO and NexiGo retain qualified sequential capture unless new complete
  evidence authorizes a different result.
