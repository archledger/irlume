# ADR-0027: Deliver the decision before releasing the concurrent pair

## Status

Accepted 2026-09-22 (proposed and implemented the same day). Amends ADR-0020 (managed concurrent PAD collection),
whose rule "streaming owners are released before final admission" this
decision replaces for the final release of a request. Motivated by the
`stream_owner_release` measurements in issue #797 and the release-order
experiment recorded in `artifacts/irlume/2026-09-22-pair-release-order/`
on the shared ledger.

## Context

On the concurrent capture path the engine arms an RGB and an IR streaming
session as a pair, establishes the delivered rate, collects the PAD samples,
decides, and then drops both sessions (`with_owned_pair`) before it returns.
The daemon's worker builds the reply from the returned outcome and hands it
to the connection thread, which performs the last admission checks and
writes it. The client therefore waits for the camera teardown after the
decision exists.

On the NexiGo N930W that teardown costs 1.0–1.2 s per grant
(`stream_owner_release` in every schema 4 trace of 2026-09-22: 1046, 1157,
1208, 1218 ms), about 15% of a 7.3 s warm grant. The `release_probe`
example (#804) attributes it: the camera performs one ~0.8 s blocking
operation per session cycle, and it lands on whichever V4L2 call the
sequence hits at that moment. Stopping RGB first, which is what the tuple
drop does, makes it land inside the release every time (810–977 ms in the
probe). Stopping IR first avoids it at release in most rounds but moves it
to the next stream start; a daemon build with that order (2c414fea, eight
attended attempts) released cheaply only half the time, missed the rate
probe in 2 of 7 warm attempts (a 5.0 s full fill instead of 2.2 s, against
1 in 10 before) and raised the warm mean from 7.3 s to 8.4 s. It was rolled
back. The order of the two stops moves the cost; it does not remove it.

The one attempt on that build where nothing landed on the critical path
granted in 6.58 s. That is the figure available if the stall is paid where
it is deterministic, at an RGB-first release, and the user is no longer
waiting when it is paid.

What the teardown does, and does not do: `STREAMOFF` and buffer release on
both nodes, the IR metadata queue teardown, the IR emitter restore
(`StreamMode` drop), and the RGB control restore. None of it produces or
validates evidence. The trailing drain that ADR-0020 protects ("a failure
during the final dequeue after successful processing invalidates the
prepared result") happens inside `capture_pair_with`, before the decision,
and is untouched by this ADR. The grant-boundary store re-read
(ADR-0024/0025) and the engine's window check are decision inputs and stay
before delivery.

## Decision

1. On the concurrent path, when the assessment inside `with_owned_pair`
   produces a final outcome (a grant, or a refusal that the pending-PAD
   retry loop will not retry), the engine invokes a delivery hook with that
   outcome BEFORE the two streaming owners are dropped. Every engine-side
   admission check that gates the outcome (identity threshold, PAD votes,
   grant boundary, the request window) has already run when the hook is
   called; the hook cannot change the outcome.

2. The daemon's worker uses the hook to do what it does today after the
   engine returns: build the `WorkerReply` (retry-throttle bookkeeping,
   credential preparation for the unseal paths, completion binding) and send
   it to the connection thread. The connection thread's last-instant checks
   before the first byte (window remaining, shared-unlock binding, peer
   liveness, retry delivery accounting) run exactly as today. When the
   engine returns, the worker sees the reply was already sent and sends
   nothing more. A hook that fails (channel closed, client gone) is logged;
   the engine still releases the pair and returns.

3. The release order stays RGB first, then IR: the stall is paid at a known
   point, off the client's clock. IR-first is rejected by the measurement
   above and must not be reintroduced without a new one.

4. The pair is still released before the worker takes its next job, so
   evidence cannot cross requests and the next request's camera open never
   overlaps a live pair (the lease is held until the drop). A back-to-back
   second request pays the teardown in `queue_wait` instead of the first
   request paying it before its reply; the total is unchanged, the
   user-visible latency of the first is not.

5. The hook is not invoked when the outcome is not final for the request:
   a `rgb_pad_pending` refusal that the retry loop will re-arm for, a
   concurrent capture failure that falls back to the sequential path, or an
   outcome that requires a further capture (intent confirmation, ADR-0010).
   Those paths release and re-arm as today. The sequential, one-shot and
   RGB-only paths hold no pair across the decision and are unchanged.

6. Tracing: `stream_owner_release` keeps measuring both destructors in one
   interval; it now appears after the reply has been handed over, and the
   operation's terminal `finished` record is still emitted after it, so a
   subscriber sees the whole request. The retry estimator of ADR-0020
   (which sizes the in-request retry loop) keeps including the inter-round
   teardown; only the final teardown leaves the client's critical path.

## Consequences

- Expected: NexiGo warm grant ~7.3 s to ~6.3 s; the reply follows the
  identity decision by the daemon's own bookkeeping only. Sequential-path
  cameras (BRIO, the laptop's built-in) see no change.
- The camera stays open for about a second after a grant or a refusal on
  the concurrent path: the RGB capture LED and the IR emitter turn off that
  much later than today. The emitter restore is still guaranteed by the
  same drop; nothing is left streaming. This is a visible change and is
  named in the CHANGELOG.
- A grant is delivered while the pair is still held by the engine's stack.
  No frame is dequeued after the decision, no evidence is consumed, and no
  other consumer can obtain the pair (it is owned, not shared), so the
  decision's inputs are exactly those of today.
- A teardown error after delivery cannot retract the reply. Today such an
  error is logged and does not change the outcome either (`with_owned_pair`
  drops without inspecting results), so no admission path weakens.
- Hook plumbing crosses the engine boundary: the engine gains a delivery
  callback parameter on the authentication entry points; the daemon passes
  its reply sender. Tests that call the engine directly pass a no-op.

## Acceptance tests

- Unit: with recording sinks, the hook is invoked with the final outcome
  after the last engine-side check and before either destructor runs (order
  recorded), for a grant and for a final refusal; not invoked for a
  retried `rgb_pad_pending` round or a concurrent-to-sequential fallback.
- Unit: a hook that returns an error does not change the outcome and both
  destructors still run.
- Daemon: the worker sends exactly one `WorkerReply` per request when the
  hook fires, and the connection thread's admission checks still run before
  the first byte (existing shared-greeter and completion tests extended).
- Trace: `stream_owner_release` precedes the terminal record and follows
  the reply hand-over (schema 4, no new stage).
- Hardware: one attended NexiGo series on archhost after the candidate
  install, expecting elapsed ≈ identity decision + daemon bookkeeping
  (~6.3 s warm) with `stream_owner_release` still ~1.0 s in the trace, and
  no change on the BRIO.
