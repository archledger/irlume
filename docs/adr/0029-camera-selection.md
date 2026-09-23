# ADR-0029: Camera selection follows the enrollment; cameras are shown by name

## Status

Proposed 2026-09-23. Implements the automatic-selection policy that ADR-0024
§5 reserved and changes its default; amends nothing in ADR-0024's authorization
model, in ADR-0028's IR-only resolution, or in ADR-0007's rule that identity
is the USB descriptor, never a name. Motivated by the "System → Cameras" page
as it stands on 2026-09-22 and by the reference desk (a Logitech BRIO as the
enrolled primary, a NexiGo N930W as an added camera, a built-in pair nobody
enrolled).

## Context

The Cameras page lists a pair as `video0+video2 · built-in · [3277:0059]`. The
node numbers are the one thing about a camera the user has no reason to know,
and they are not even stable across reboots; the `vid:pid` is meaningful to a
maintainer with the hardware table open and to nobody else. The page mixes
this list with the IR-emitter, tuning and unit-listing tools, which act on a
camera but are not about choosing one.

Choosing is manual. `set-cameras` writes `/etc/irlume/cameras.conf` with the
pair's nodes and identities; at daemon start `select_pair` prefers the
`IRLUME_RGB_DEVICE`/`IRLUME_IR_DEVICE` override, then the saved pair
re-anchored by identity (`resolve_saved_pair`, so a renumbered node is found
again), then a rank over the discovered pairs (`IRLUME_CAMERA_PIN` allowlist,
built-in first). Nothing re-selects while the daemon runs: docking a laptop
that was enrolled on its lid camera and a desk camera means opening the TUI
and picking again, in both directions.

Meanwhile the account already knows its cameras. The primary enrollment
carries the pair it was captured on (`camera_binding`, ADR-0024 §1) and the
secondary store carries every added camera's pair by identity (§2). The dual
path resolves the live pair against exactly these (`resolve_attempt_enrollment`)
and ADR-0028 made the IR-only path do the same (`resolve_ir_only_scope_at`).
What is missing is the step before that: choosing which connected pair to
open for this account, instead of assuming the pinned one. ADR-0024 §5 wrote
it down — "an explicitly enabled automatic-selection policy chooses a complete
eligible pair in a stable documented order: active legacy primary first, then
a canonical order of enrolled pair identities" — and it was never built, so it
has no setting, no order in code and no UI.

Two constraints shape the design. The bindings live inside the enrollment,
which on a TPM host is sealed: the daemon cannot rank pairs "for whoever will
log in next" without unsealing every account's key, so selection cannot be a
daemon-wide background decision. And a human-readable camera name is
available for free (`/sys/class/video4linux/videoN/name`, already read by the
IR target code, and the USB `product` string) but is explicitly not trusted
for identification (ADR-0007; `uvc_descriptor.rs` distrusts the `card` string):
a name may be shown, never matched on.

## Decision

1. **Selection is per request, from the requesting account's enrollment.**
   When an authentication request for `user` arrives and the selection mode is
   `automatic`, the pair to open is chosen after the enrollment load (the key
   is then held once, ADR-0025) and before capture, in this order over the
   pairs currently connected:
   1. the pair matching the primary binding (`GroupPair::matches`, the dual
      path's rule; the primary keeps precedence exactly as in ADR-0024 §5);
   2. the account's active secondary groups in store order, by strict
      both-side equality of identities (ADR-0028 §1's rule; a one-sided group
      never wildcards);
   3. none connected → the request refuses to the password with the existing
      binding-mismatch vocabulary, and the camera-free status names the cause
      (`no enrolled camera is connected`). An unenrolled pair is never opened
      for authentication: it cannot grant and opening it only produces a
      confusing refusal.
   The chosen pair is pinned for the attempt through the camera-operation
   lease and the decision, as ADR-0024 §5 requires; hotplug during an attempt
   changes nothing. The engine's standing pair (what diagnostics, prefetch and
   the passive inventory report) follows the last selection.

2. **`pinned` keeps today's behaviour.** `camera_selection = pinned` means the
   pair in `cameras.conf` is the only pair authentication opens; if it is not
   connected the request refuses to the password and the status says so. The
   TUI calls this "Always use: <camera>". Enrollment and `--add-camera`
   capture keep using the explicitly chosen pair in either mode — a
   credential operation never has its camera chosen for it.

3. **Default.** Fresh installs (no `cameras.conf`) run `automatic`. An existing
   `cameras.conf` without a `mode` line is read as `pinned`, so no upgraded
   host changes camera on its own; switching to automatic is an owner action
   in the TUI or `irlume set-cameras --automatic`. This replaces ADR-0024 §5's
   "explicitly enabled" wording for new installs only.

4. **Configuration.** `cameras.conf` gains `mode=automatic|pinned` (absent =
   pinned, item 3) and keeps `rgb`, `ir`, `rgb_id`, `ir_id` as the pinned pair
   (present in automatic mode too, as the last explicit choice and the
   enrollment-time pair). The writer adds one comment line per side with the
   product name (`# rgb: Logitech BRIO`) for the person reading the file;
   comments carry no authority and the reader ignores them. The setting is
   root-written through the daemon like the pin today (`SetCameras` /
   `SetCamerasIfCurrent` gain the mode; the TUI's confirm-before-write and
   connection-change invalidation apply unchanged). `forbid_external_cameras`
   filters the candidate set in both modes.

5. **Names and roles on the wire, display only.** `CameraPairInfo` gains
   optional `name` (sysfs node name, then USB `product`, then absent),
   `serial_present`, and `role` for the requesting account: `primary`,
   `secondary { index }` (the group's 1-based store position, as ADR-0028
   reports it — never the group id) or `unenrolled`. `ListCameras` stays
   camera-class (it opens nodes to classify, #187); the role lookup is
   camera-free and reuses the ADR-0028 readiness resolution. A new
   camera-free `CameraSelectionStatus { user }` reports the mode, the pair
   automatic would choose now (or why none), and the pinned pair's
   connection state; the TUI's `●` marker and the KCM read this, never guess
   from the list. All new fields are `serde(default)`; older clients ignore
   them and older daemons omit them.

6. **The Cameras page.** Lists cameras by name with the role, built-in/external,
   and a one-line status (ready · privacy shutter · not connected · last use);
   the selection mode sits above the list ("Let irlume choose" / "Always use:
   <camera>"); Enter opens a details panel with the identity (with an explicit
   note when there is no serial, since same-model units are then
   indistinguishable, ADR-0024 §6), the nodes, connection, enrollment facts,
   qualification state, last use and the ADR-0023 profile; the IR-emitter,
   tune and list-units actions act on the highlighted camera. `add as camera`
   and `remove` move here from the Faces page (the Faces page keeps showing
   groups; the actions are the same commands). The `capture history` line
   distinguishes "not fetched yet" from a daemon that does not answer.

7. **Not changed.** Identity is `vid:pid[:serial]` from the descriptor; a
   name is never compared. No automatic movement to another pair after a
   refusal, no pooling, no auto-rebind of an inactive store (ADR-0024 §5, §6;
   ADR-0028 §3). Selection never opens a device that is not going to be used
   for the attempt.

## Consequences

- A person with an enrolled desk camera and an enrolled lid camera stops
  visiting the Cameras page: the account's own authorization decides, in the
  order it was written down in 2026-09-19's ADR.
- One more read on the automatic path when the primary pair is not
  connected: the secondary store, under the key the request already holds
  (ADR-0025). The primary-connected case costs a pair-identity comparison.
  Capture qualification (ADR-0023, keyed by runtime context) is per pair, so
  a pair used for the first time on this host runs the conservative schedule
  until measured, as it does after a manual switch today.
- Upgraded hosts keep their pin until the owner switches; the page tells
  them the alternative exists.
- The name comes from the device and is shown as given; a camera that
  reports nothing useful ("USB Camera") is shown as that plus its
  built-in/external tag, and two same-model units without serials are shown
  twice with a warning rather than merged.

## Phasing

- A (display, additive): `name`, `serial_present`, `role` on `CameraPairInfo`;
  `CameraSelectionStatus` reporting the pinned pair's state; the Cameras page
  redesign with the details panel; the "not fetched yet" wording; docs.
  No behaviour change to selection.
- B (automatic mode): `mode` in `cameras.conf` and the requests; per-request
  selection in the engine with the order of item 1; `CameraSelectionStatus`
  reporting the would-be choice; the mode control in the TUI; `set-cameras
  --automatic`; the default of item 3.
- C: add/remove actions on the Cameras page; KCM parity with the same wire
  fields.

## Acceptance tests

- Selection order (pure): primary connected → primary; primary absent, one
  active group connected → that group; two groups connected → store order;
  group in an inactive store → skipped; nothing enrolled connected → refusal
  naming the cause; an unenrolled pair present alone → never chosen.
- Pinning: a pair chosen for an attempt stays the attempt's pair when the
  inventory changes mid-attempt; the next request re-selects.
- `pinned` mode: the pinned pair absent → refusal, the status says "not
  connected", no other pair is opened.
- Default: no `cameras.conf` → automatic; a `cameras.conf` without `mode` →
  pinned; `mode=automatic` survives a `set-cameras` of a new explicit pair
  only when passed again (an explicit pick without the flag is a pin).
- Wire: a frozen copy of today's `CameraPairInfo` decodes a new daemon's
  listing; `role` and `name` absent from an old daemon leave the TUI showing
  the identity row it shows today.
- Names: a node whose sysfs name is empty falls back to the USB product,
  then to the identity; the name is never used by any matching path (a test
  changes the name and asserts selection and the boundary are unaffected).
- Hardware: on the reference desk, automatic mode chooses the BRIO with both
  connected and the NexiGo with the BRIO unplugged, in the dual and IR-only
  policies, each attended attempt recorded on the shared ledger.
