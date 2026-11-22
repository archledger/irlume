# ADR-0021: Bounded reuse of delivered-rate evidence across capture sessions

## Status

Accepted; implemented in #717 and shipped in v0.13.0
(`crates/irlume-camera/src/rate_amortization.rs`). Amendment after ship: a
probe miss now escalates to a 15-delta window before the full 30-delta fill,
and amortization was extended to the concurrent pair fill; see
`CONTINUITY_PROBE_ESCALATED_DELTAS`.

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
2. That completion is no older than the staleness bound: 5 minutes
   originally, 24 hours since the 2026-09-22 amendment below.
3. No invalidating event occurred for that key since: a stream recovery
   epoch, a dequeue I/O error, or a failed probe all remove the entry.
4. The role startup flush still runs (the probe measures THIS session).
5. A probe of exactly 5 positive deltas, judged by the same exact integer
   `meets_floor` arithmetic used everywhere else, clears the same floor
   with the same tolerance. On probe failure the session escalates to a
   15-delta window (shipped amendment) and then falls back to the full
   30-delta fill, and the cached entry is invalidated.

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

## Amendment 2026-09-22: staleness bound raised to 24 hours

Measured on the NexiGo N930W pair on archhost with the schema 4 trace
stages: back-to-back attempts admit on the probe and spend about 2.2 s in
rate establishment (the IR stream's start-up), while an attempt 9 minutes
after the previous one found the cache expired and spent 3.8 s re-paying
the full 30-delta fill. Unlocks after more than five minutes away are the
common case, so the 5-minute bound made the amortization miss most real
unlocks.

The security argument above does not depend on the bound's value: a
session is admitted by its own probe (5 deltas, escalating to 15) through
the same floor arithmetic, every later frame is judged by the sliding ring,
a failed probe re-pays the full fill and invalidates the entry, and camera
identity is re-pinned at every open. The bound only states how long ago the
stream's full shape was last observed in this process. It is now 24 hours,
a working day of unlocks; the entry is still removed by every invalidating
event and by a daemon restart, and `IRLUME_RATE_AMORTIZATION=0` still
disables reuse.

## Amendment 2026-10-05: parked buffers before paired admission

Native capture may park at most two ERROR-marked startup buffers before delivering
a sound frame, provided the original ring retains capacity. Those buffers stay
unviewed and unrequeued until teardown. The paired startup fill may consume only
this exact operation-specific pending return before any observation, prior health
admission or recovery epoch. Companion cancellation, deadline, endpoint, privacy
and producer checks run between every attempt. A Parked return counts neither as
a sound startup flush nor as delivered-rate evidence.

Handling a Parked return prevents this stream's continuity-probe admission. Once
both preparation workers have finished and joined, any handled Parked revokes
both streams' cached completions, prior readiness and windows. One additional
bounded fill on the same serviced streams owes a fresh sound seed and full
30-delta window on both sides after the last Parked. A second pending phase is
not admitted. A failed Parked preparation or fresh phase also revokes both sides
before returning its original refusal. The same role floors and subsequent
sliding judgments remain in force. Other Interrupted returns, uncertain queue or
start failures, third startup errors, post-sound corruption, exhausted rings and
authority refusals remain terminal; no hidden restart or device replacement occurs.

This corrects the paired startup policy's propagation of a pending return that
adaptive single-stream warm-up already handles. It does not establish why a device
reported ERROR, qualify concurrent split capture or enable split authentication
(#995; ADR-0032).

## Amendment 2026-10-09: held-side faults invalidate their rate evidence explicitly

The held-pair failover change (#1033) ends in-place stream recovery on the
held concurrent pair path. The recovery epoch was the only invalidation that
path performed: it revoked the faulted role's amortization entry as a side
effect of renegotiating the broken stream. The failover now revokes that
entry explicitly instead. Every capture fault the capture call itself
returns (the `denoised`/`capture_with_stats` callbacks), other than
Preempted or DeadlineExpired, calls `invalidate_rate_evidence` on the
faulted role's session before the pair fails over (both on the
`assess_full_with_finish` held pair and on the managed collector's pair),
revoking exactly the cache entry the recovery epoch revoked, keyed by that
session's own amortization key. The below-floor refusal case named in #1033
is covered by that explicit call when it surfaces from the capture call. A
fault the pair folds in after the callback returned successfully (a
drain-phase continuity, rate or privacy failure) does not reach the explicit
call; that gap existed before #1033 as well (those paths never recovered
either) and the fallback's probe re-measures this session, so it stays
recorded here rather than closed by this change. Both
held sessions are then discarded; the mandatory sequential fallback's fresh
one-shot session for the faulted role re-pays the full 30-delta fill, while
the healthy role's cached entry stays valid and its fallback session may
still admit on the probe, as before.

One-shot capture paths are unchanged. Their pre-existing invalidation gaps
remain out of scope here: a fill-time hard fault returned from
`next_discarded` and a fill-time `observe_success` failure (also
`next_discarded`) do not invalidate the amortization entry. Neither was
introduced by this change.

## Amendment 2026-11-22: completions outlive the daemon, keyed on USB identity

Measured on the HP EliteBook 830 G8 of #1399: a concurrent attempt spends
8.417 s of a 15.08 s lock-screen window in rate establishment, and 9.3 s
pass before the first face sample. A cold session pays the 30-delta window
per stream, and its wall time scales with the inverse of the delivered
rate (30 deltas are 4.02 s on that machine's RGB stream at 7.456 fps).
Every daemon start, whether boot, package upgrade or watchdog restart,
began with an empty cache, so the first attempt after each of them was
cold, and the trace could not say so.

1. A full window's completion is kept on disk as well as in memory: one
   small file per stream identity under `state_dir()/rate-evidence/`,
   holding the record schema and the completion's unix time in
   milliseconds. Nothing else is stored: no secret, no biometric data,
   no device path and no serial.

2. The identity is a SHA-256 digest of the stream's USB endpoint as
   `CameraEndpoint` collects it from the open descriptor (vendor and
   product id, serial where present, interface, bus and port,
   configuration-bound descriptor digest, controller and link speed),
   of its negotiated stream contract and of the rate policy its window
   is judged by (role floor, tolerance, window width, startup flush).
   A renumbered video node keeps its identity. A camera moved to another
   port, a link-speed change, a new descriptor, stream or policy gives
   another, for which no record exists (ADR-0023, section 5). A camera
   that publishes no serial is known by its port, as it is by the
   emitter journal and the qualifications: an identical unit later
   plugged into the same port inherits the record, and item 5 is all
   that costs.

3. At session start the record is consulted once, exactly as the
   in-memory cache is consulted after it. A completion within the
   staleness bound becomes the cache entry for this session's key, with
   the age the record states, and the cache then behaves as before:
   decision item 5's probe (5 deltas, escalating to 15) on the current
   session is THE evidence that admits it, every later frame is judged
   by the sliding ring, and a full window that completes records its
   completion in memory and on disk. The bound stays at 24 hours and now
   spans restarts. A restored entry never replaces what this process
   already observed itself.

4. Every invalidating event of decision item 3 (stream recovery, a
   dequeue I/O error, a failed probe, a parked startup buffer, a
   held-side fault) removes the memory entry and the record with it:
   an invalidated stream re-proves itself with a full window, which is
   the conservative direction.
   `IRLUME_RATE_AMORTIZATION=0` restores nothing, records nothing and
   removes nothing.

5. The record only decides whether the probe is tried. It is never rate
   evidence. A forged, stale or corrupt record can cause a probe attempt
   and nothing else; a stream below its floor fails that probe, pays the
   full window and is refused exactly as before.

The security and correctness argument above does not change. The probe
and the sliding ring are the admitting evidence on every path; the
record only removes the need for a full window before a probe may be
tried, and a failed probe still revokes what it contradicted. On top of
that:

- The record is not trusted input. The daemon writes it 0600, at file
  creation, by atomic replace into a 0700 directory. A read accepts
  only a regular file owned by the effective user with no access for
  group or other, opened without following links, within a small size
  bound, in the known schema, with a completion neither in the future
  nor past the staleness bound. Each refusal is the same as an absent
  record, as are a missing, unreadable or unwritable state directory.
  Only root can write it, inside the stated trust boundary.
- The per-frame sliding floor judgment, the exact-integer `meets_floor`
  arithmetic and the watchdog bound are untouched. The only new work on
  the capture path is one bounded file read at session start, and one
  small atomic write when a full window completes.
- The directory holds at most 32 records; when a new one would exceed
  that, a file that is no sound record goes first and then the oldest
  completions. A record past the bound or in the future is removed when
  it is read.

Consequences:

- The first attempt after a daemon start tries the probe when the same
  stream completed a full window in the previous 24 hours. On #1399-class
  hardware the per-stream machinery of that attempt drops from the full
  window (about 4 s on its RGB stream) to the probe.
- A probe that now misses where a cold fill would have been paid costs
  up to 15 deltas before the full window: on that RGB stream about 2 s.
  The trace's `rate_evidence` record (schema 6) reports that outcome as
  `probe_missed`, and its `persisted` field says when the decision
  rested on a completion from before this daemon start.
- A test or tool that opens a real USB camera as root without
  `IRLUME_STATE_DIR` set keeps its records under the production state
  directory, as the emitter journal already does.
