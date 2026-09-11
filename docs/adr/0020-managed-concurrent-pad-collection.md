# ADR-0020: Service concurrent camera queues while collecting PAD evidence

**Status:** Proposed; implementation and hardware validation in progress
**Date:** 2026-09-11
**Related:** [ADR-0013](0013-ship-pad-models-default-on.md),
[ADR-0014](0014-schedule-aware-pairing-budget.md),
[ADR-0019](0019-fail-closed-pad-availability.md)

## Context

RGB PAD requires five fresh scores before its median can support admission.
Ordinary concurrent authentication opens new streams and establishes their
delivery rate for each retry. In the September 11 ASUS experiment, individual
rate establishment intervals were about 3.13 seconds. Neither tested ordinary
concurrent revision completed the required evidence within its request budget.
Deferring unnecessary identity work alone did not establish a login speedup.

Holding streaming sessions across inference avoids repeated startup work only
if their queues continue to be consumed. Idle queues can overflow and invalidate
delivery evidence. Alternating blocking reads can also throttle the faster
camera behind its slower companion. Sequential grouped authentication has a
different capture schedule and admission policy, so its evaluator cannot simply
be applied to concurrent frames.

## Decision

Keep transport servicing in `irlume-camera` and the bounded evidence collection
policy in `irlume-auth`. A paired processing operation borrows both held stream
owners, services each independently on a scoped thread, and runs inference on
the calling thread. Its transport result contains the processing result; model
errors do not become camera-degradation events. Every servicing worker joins
before a result can escape, including after failure or unwinding.

An eligible concurrent login operation opens one pair and establishes its full
existing rate window. It captures and processes at most five fresh pairs. The
collector continues only for Live evidence with an eligible RGB face whose PAD
state is pending. Every sample is qualified once. Any other result ends that
collection under ordinary outcome precedence. Only the final admissible sample
is used for identity; the collector does not try later samples for a better
identity score.

Eligibility requires the live runtime pair contract, enabled IR and both PAD
models, non-demoted concurrent authority, and the existing login/lock operation
and grace-window scope. Stored measured concurrent qualification permits
automatic selection. The existing explicit concurrent override can exercise
this path under the same runtime validation without changing stored
qualification. Grouped sequential, IR-only, RGB-only, enrollment and support
operations retain their separate capture paths.

Identity deferral is confined to this managed collector. Ordinary RGB+IR
attempts, including sequential fallback and operations outside the eligibility
scope, retain eager identity materialization before PAD qualification. They
keep their existing identity-error precedence and retry-cost behavior. The
earlier experiment that deferred ordinary attempts is not part of this scope.

Every analyzed pair must satisfy the existing runtime contract and concurrent
pairing rules. Successive acquisition windows must advance without overlap or
replay; intervening validated discarded frames need not become PAD samples.
Evidence cannot cross recovery, fallback or requests. Any transport failure,
including a failure during the final dequeue after successful processing,
invalidates the prepared result and clears the collection's votes.

Streaming owners are released before final admission. The original request
deadline applies throughout. The retry estimator measures the complete
collection, including inference and cleanup, and retains the existing
sequential fallback cost floor. The rate window, PAD operating points,
concurrent skew limit and identity thresholds do not change.

## Consequences

- Startup validation may be paid once for several PAD samples, but successful
  authentication and refusal latency must be measured before claiming a gain.
- Independent servicing adds two temporary scoped workers during processing.
  It avoids detached workers and retained queues between requests.
- A processing callback can mutate pending evidence before a tail failure is
  known. Authentication must discard that state as well as the returned value;
  dropping the value alone is insufficient.
- Cancellation remains cooperative at driver and inference boundaries. Joining
  workers guarantees ownership cleanup, not forced termination of a blocking
  model call or a hard cancellation-latency bound.
- Deterministic transport, provenance, policy and cleanup tests complement
  attended hardware comparisons. They do not establish camera stability or
  additional spoof resistance on their own.
