# ADR-0021: Bounded reuse of delivered-rate evidence across capture sessions

## Status

Proposed (implementation PR cites this ADR).

## Context

A sequential capture pair cannot stream RGB and IR at once, so every
authentication attempt pays, per stream and serially: open, negotiate, the
role startup flush, and a 30-delta delivered-rate observation window whose
frames are all discarded (~2.1-2.7 s per stream at the ~15 fps fleet floor).
Measured on the BRIO sequential pair, full authentication is ~10.7 s of which
only ~1.9 s is the IR evidence burst; the rate windows paid twice, serially,
are the dominant contributor (~4-6 s).

`rate_gate`'s own contract states what the window is: TRANSPORT-HEALTH
evidence (a degraded USB link, a starved stream, a demoted schedule), not
the anti-injection control; camera identity is pinned by `verify_pinned` at
open, and an injected stream can deliver any rate it likes, floor included.
Independent of any reuse, the per-frame path already judges `meets_floor`
on EVERY dequeued frame after the fill, sliding the 30-delta ring through
the whole burst, with a typed BelowFloor refusal on failure.

Prior measurement (the slice-8 design) found five- and ten-delta windows
INVALID as sole admission evidence. This ADR does not propose judging from
five deltas alone.

## Decision

A capture session may skip the 30-delta fill and admit on a continuity
probe when ALL of the following hold:

1. The same node and stream role, in this same process, previously
   completed a full 30-delta window that met its floor.
2. That completion is no older than 5 minutes (staleness bound).
3. No invalidating event occurred for that key since: a stream recovery
   epoch, a dequeue I/O error, or a failed probe all remove the entry.
4. The role startup flush still runs (the probe measures THIS session).
5. A probe of exactly 5 positive deltas, judged by the same exact integer
   `meets_floor` arithmetic used everywhere else, clears the same floor
   with the same tolerance. On probe failure the session falls back to the
   full 30-delta fill and the cached entry is invalidated.

After a probe admission, every subsequent dequeued frame continues to be
judged per-frame by the sliding ring exactly as before; the ring simply
starts at 5 entries and grows during the burst. Reported evidence carries
the honest window count (5, then growing), and no downstream consumer
gates on the count (the auth path reads sequence-gap evidence only).

The reuse can be disabled with `IRLUME_RATE_AMORTIZATION=0` as the rollback
valve.

## Security and correctness argument

- The gate being amortized is transport health, not identity or
  anti-injection (identity stays per-open via `verify_pinned`).
- Freshness becomes bounded-staleness: the probe confirms the current
  session delivers above floor for its first ~5 deltas, and the per-frame
  sliding judgment covers the rest of the burst. A degradation that begins
  after the probe produces a typed BelowFloor refusal on the next judged
  frame, the same enforcement a burst always had.
- Five deltas alone were measured insufficient as SOLE evidence; here they
  are a continuity confirmation of a prior full window, and the sole
  evidence path (no cache hit) is unchanged at 30.
- A stream that cannot clear the probe re-pays the full fill, so the change
  cannot turn a failing stream into a passing one; it can only shorten the
  machinery of streams that are currently delivering at floor.

## Consequences

- On the second and later sequential attempts per process, per-stream
  machinery drops from ~2.7 s to ~0.4-1.0 s (flush plus probe), cutting
  full sequential authentication by roughly 4-5 s.
- The first attempt per process is unchanged (full fills populate the
  cache).
- The cache is process-local memory keyed by node path and role; a
  replugged or re-pinned camera is caught by `verify_pinned` at open, and
  error-path invalidation removes stale entries aggressively.
