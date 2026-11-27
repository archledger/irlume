# ADR-0005: One face is one profile; the enroll protocol reports the merge

**Status:** Accepted and DONE. The engine already enforced the identity model;
this ADR records it and fixes the two things sitting on top of it that
contradicted it (issue #15): the TUI's non-merge-aware split protocol, which
crashed, and the copy that told users to make a second profile for glasses.
Implemented 2026-07-18 (`Response::Enrolled`, the merge-aware `enroll_worker`
plus a confirm modal, and the copy corrections).

**Date:** 2026-07-18

## Context

A profile is one identity. `MAX_PROFILES = 3` people, each holding up to
`MAX_SCANS_PER_PROFILE = 30` scans of that one person (glasses, lighting, angle,
beard). A face can never own two profiles: `Engine::enroll_profile`
(`crates/irlume-auth/src/lib.rs`) probes the capture, and if it matches an
existing profile above `RGB_MATCH_THRESHOLD` it merges the scans into that
profile and returns `EnrollOutcome::Merged`; `add_scan` carries the same
`colliding_profile` guard. So enrollment auto-routes: a matching face strengthens
its existing profile, a novel face creates a new one (or is refused at 3).

Two things on top of that model disagreed with it.

The TUI drives enrollment as separate daemon calls for per-scan framing: scan 1
is `Request::Enroll` (create), scans 2..N are `Request::AddScan` (append). Both
`New` and `Merged` collapsed to `Response::Ok(String)` in the daemon, so
`enroll_worker` could not tell them apart. For an already-enrolled face, scan 1
merged into the existing profile, the worker read it as an ordinary success, and
scan 2's `AddScan` targeted a profile that was never created, failing with
`no face profile '<name>'`. Net: one orphaned scan on the old profile and a
confusing error (issue #15).

The Profiles-tab tip, the README FAQ, and the SETUP guide told users to enroll a
second profile named `glasses`, which the identity model forbids.

## Decision

Carry the resolved profile in the protocol, and make the TUI honor the merge
instead of fighting it.

- `Response::Enrolled { profile, created, added, total, added_scans }` replaces
  the stringly `Ok` for enroll results. `created` distinguishes a new profile
  from a merge; `added_scans` names the scans this call appended so a caller can
  undo a merge precisely. `EnrollOutcome::Merged` gained the same
  `added_scans`.
- `enroll_worker` reads scan 1's `Enrolled`. On a merge it stops and hands off
  to the UI, which shows a confirm: "this face is already enrolled as X; add
  these scans to it?". On yes it captures the rest via `AddScan` against the
  resolved profile (capped at the 30-scan budget); on no it deletes the one
  merged scan so the profile is left exactly as it was. The CLI enroll paths
  print the same friendly result.
- The copy now matches the model everywhere: variants of one person are extra
  scans added with Improve Recognition (`[a]`), not a second profile (Profiles
  tip, merge modal, README, SETUP, the `MAX_PROFILES` comment).

The confirm is explicit rather than silent because the user asked for a new
profile and gets told they already have one; a modal makes that visible and
reversible instead of surprising.

## Consequences

| Enroll scenario | Result |
| --- | --- |
| New person, a slot free | New profile created |
| New person, already 3 profiles | Refused: "at the max of 3 profiles" |
| Already-enrolled face, TUI new-profile | Confirm modal; yes adds scans to the matched profile, no leaves it unchanged. No crash, no orphan |
| Same person, glasses that still match | Merge, strengthening recognition |
| Same person, look drifts below threshold | A new profile, the one seam below |

The identity check is threshold-based on the face embedding, so "new person"
means "matches no existing profile above `RGB_MATCH_THRESHOLD`". The one place
the model can misfire is the same person whose look drifts so far it drops below
threshold (heavy disguise, drastic lighting): it reads as a stranger and eats a
profile slot. This is inherent to any threshold identity check and is not a
policy change here. Making that auto-created profile visible and offering a
"merge into" action to fold it back is left as a follow-up (issue to file), not
part of this fix.

Nothing here touches the identity policy or auth security; it is protocol, UI,
and copy.
