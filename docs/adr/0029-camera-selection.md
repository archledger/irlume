# ADR-0029: Camera selection follows the enrollment; cameras are shown by name

## Status

Proposed 2026-09-23, revised the same day after two design reviews.
Implements the automatic-selection policy that ADR-0024 §5 reserved and
changes its default; supersedes ADR-0028 §1's "explicitly configured pair"
rule for automatic mode only (item 5); amends nothing in ADR-0024's
authorization model or in ADR-0007's rule that identity is the USB
descriptor, never a name. Motivated by the "System → Cameras" page
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

1. **Selection is per request, from the requesting account's enrollment,
   before any device is opened.** The order of an authentication request
   in `automatic` mode is: enumerate the connected candidates **camera-
   free** from the daemon's passive inventory — the lifecycle supervisor
   classifies each node's role (RGB / IR) when the device appears, on the
   camera worker, and the request reads that cached classification plus
   the sysfs identity, so a candidate is a pair only when both role nodes
   of one identity are present (an identity with its RGB node alone is not
   a connected pair); load the enrollment (the key is then held once,
   ADR-0025); select; take the camera lease; **re-check both selected
   identities under the lease immediately before opening** (a device that
   left and another that took its node in between refuses with "camera
   changed", as the IR target revalidation already does); then open. This
   reorders the dual path's current lease-then-join sequence; a test
   asserts no open before selection and a refusal on a swapped node.
   Candidates are ranked among the account's enrolled pairs only:
   1. the primary binding when **both** its sides are bound and both match
      a connected pair (`vid:pid[:serial]` on each side). A legacy binding
      with one side unbound is not a complete pair (ADR-0024 §2): automatic
      mode refuses it with a status that names the cause ("primary camera
      binding incomplete; pin the camera or re-enroll"); pinned mode keeps
      today's behaviour for such records;
   2. otherwise the account's active secondary groups whose pair matches a
      connected pair by strict both-side equality (ADR-0028 §1), in the
      canonical order of ADR-0024 §5 — sorted by the pair identity
      (`rgb`, then `ir`), never by store position, so removing and re-adding
      a group cannot change which of two connected cameras is chosen;
   3. two or more groups with the same exact pair are **ambiguous**: they
      are skipped and the status reports the ambiguity, exactly as the
      IR-only resolver refuses them (ADR-0028); store order never decides;
   4. **eligibility for the requested mode** is part of selection, not a
      fallback: a candidate is eligible when its camera-scoped view can
      serve the mode — for IR-only, when it holds compatible IR templates
      for the live recognizer (the camera-free readiness check ADR-0028
      already runs). The primary keeps precedence among eligible
      candidates; an ineligible primary beside an eligible group selects
      the group. This is the pre-capture choice ADR-0024 §5 describes,
      distinct from the forbidden movement after a biometric or PAD
      refusal;
   5. nothing eligible connected → the request refuses to the password with
      the existing vocabulary and the camera-free status names the cause
      (`no enrolled camera is connected`, `primary camera binding
      incomplete`, `ambiguous secondary groups`). An unenrolled pair is
      never opened for authentication.
   The chosen pair is pinned for the attempt through the lease and the
   decision (ADR-0024 §5); hotplug during an attempt changes nothing. The
   engine's standing pair follows the last selection. **Background capture
   requalification** (which opens cameras and fires the emitter) runs only
   for the pinned pair or for a pair selected for an account, and
   re-checks that authority immediately before it takes the camera: a
   group removed or made inactive in the meantime cancels the probe. In
   automatic mode before any selection nothing is probed.
   **Account-less capture** — root's cross-account `Identify`, a
   diagnostic that searches every enrollment — has no account to select
   from: it uses the environment or pinned pair when one exists, else the
   enrollment-candidate rule of item 3, and reports which camera it used;
   it grants nothing, so no authorization is implied by the choice.

2. **`pinned` keeps today's behaviour.** `mode=pinned` in `cameras.conf`
   means the pair saved there is the only pair authentication opens; if it
   is not connected the request refuses to the password and the status
   says so. The TUI calls this "Always use: <camera>". The
   `IRLUME_RGB_DEVICE` + `IRLUME_IR_DEVICE` environment pair remains an
   overriding pin in **both** modes, as today; the status reports the
   source (`environment`, `pinned`, `automatic`).

3. **Enrollment and the first pair.** A credential operation (`enroll`,
   `--add-camera`) never has its camera chosen by the account's
   authorization — there is none yet, or the point is to add a new one. It
   captures on an explicitly chosen pair carried **in the operation**:
   new request variants `EnrollOn { pair, .. }` and `AddCameraGroupOn {
   pair, .. }` name the RGB and IR nodes, which the daemon resolves to
   identities and re-checks under the lease as in item 1; the pair is
   scoped to that capture and never touches `cameras.conf`, so an
   automatic-mode account adds a camera without pinning the machine. An
   older daemon rejects the unknown variant, so a mixed-version client
   fails visibly rather than capturing on a different camera. The
   authorization is the operation's own (ADR-0024 §4). A bare `enroll` on
   a host with no pinned pair uses the documented **enrollment candidate**
   rule — the existing discovery ranking (allowlist, built-in
   first) — and prints which camera it is about to use before capturing,
   so first enrollment on a fresh install works without a settings step;
   the enrolled pair becomes the primary binding. A test covers the fresh
   install path.

4. **Default and upgrade.** A fresh install (no `cameras.conf`, or one that
   parses and holds no complete non-blank `rgb`/`ir` pair — the file may
   hold only legacy `capture_mode.*` keys, docs/SETUP.md) runs
   `automatic`. A `cameras.conf` holding a complete saved pair and no
   `mode` line is read as `pinned`, so no upgraded host with a chosen pair
   changes camera on its own; switching is an owner action. A file that
   exists but cannot be read or parsed is a third state, `unreadable`:
   selection refuses to the password and the status names the cause; it
   is never treated as fresh, so an I/O or permission error cannot move a
   pinned host to another camera. This replaces ADR-0024 §5's
   "explicitly enabled" wording for new installs only.

5. **IR-only.** This ADR supersedes ADR-0028 §1's "explicitly configured
   pair" rule for automatic mode: the IR-only target is the pair item 1
   selects, resolved from the account's binding or group identity to the
   connected nodes through sysfs, still without opening a device. The
   preflight (`FaceSensorStatus`) and the authentication path use the same
   resolution, so the preflight names the same camera the attempt would
   open. Pinned mode and the environment pair keep ADR-0028 §1 as written.

6. **Configuration and the wire.** `cameras.conf` gains
   `mode=automatic|pinned` (absent = item 4) and keeps `rgb`, `ir`,
   `rgb_id`, `ir_id` as the pinned pair. Mode, pair and comments are
   written as **one locked atomic publication** (the existing
   `write_camera_pin` lock and single rename, extended), so no reader can
   observe a mode with a pair it was never requested with, and a crash
   leaves either the old or the new file. The writer adds one comment
   line per side with the product name for the person reading the file,
   with control characters, CR and LF removed and the text bounded, so a
   device-supplied name can never become a key line; comments carry no
   authority. The mode is changed through a **new** request,
   `SetCameraSelection { mode }`, which an older daemon does not know and
   therefore answers with an error rather than a silent success; the
   client confirms the resulting mode through `CameraSelectionStatus`
   before reporting success. `forbid_external_cameras` filters candidates
   in both modes.

7. **Names, identities and roles on the wire, display only.**
   `CameraPairInfo` gains optional `name` (sysfs node name, then USB
   `product`, control characters removed), `identity` (the full binding
   identity `vid:pid[:serial]`, so the client can tell two serial-bearing
   units apart; `id` keeps its `vid:pid` meaning; the raw value is what
   matching compares, and every rendering of it blanks control characters
   and bounds its length, since a serial is device-supplied text too),
   `serial_present`, and `usb_port_chain: Vec<u8>` — the device's position
   in the USB topology, the same share-safe field the support snapshot's
   `SanitizedCameraContext` carries, which tells two connected units of one
   model apart while they stay plugged in and identifies nothing once
   unplugged (ADR-0030 uses it for attempt history). The **role** is not a daemon
   field: it is derived by the client from the account-scoped enrollment
   reply — `ListProfiles { user }` gains the primary binding
   (`primary_camera`) beside the groups it already carries — so a
   `sudo irlume tui` session labels cameras for the target account, not
   for the root peer. A camera-free `CameraSelectionStatus { user }`
   reports the mode and its source, the pair automatic would choose now
   (or the cause), and the pinned pair's connection state. New fields are
   `serde(default)`.

8. **The Cameras page.** As ADR-0030 §2 and phase A: names, roles,
   status, selection mode above the list, details on Enter (or in the
   wide-terminal column), per-camera actions.

9. **Not changed.** Identity is `vid:pid[:serial]` from the descriptor; a
   name is never compared. No movement to another pair after a refusal,
   no pooling, no auto-rebind of an inactive store (ADR-0024 §5, §6;
   ADR-0028 §3). Selection never opens a device that is not going to be
   used for the attempt.

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

- A (display, additive): `name`, `identity`, `serial_present` on
  `CameraPairInfo`; `primary_camera` on the enrollment reply; the Cameras
  page redesign with the details panel; the "not fetched yet" wording;
  docs. No behaviour change to selection.
- B (automatic mode): `mode` in `cameras.conf` with the atomic writer and
  the `unreadable` state; candidate discovery from the passive inventory
  and the reordered request (select, lease, re-check identities, open);
  `EnrollOn` / `AddCameraGroupOn`; the account-less identify rule;
  selection with the order, canonical sort, ambiguity and eligibility of
  item 1; the IR-only target resolution of item 5; the enrollment candidate
  rule of item 3; background requalification gated on a selected pair;
  `SetCameraSelection` and `CameraSelectionStatus`; the mode control in the
  TUI; `set-cameras --automatic`; the defaults of item 4.
- C: add/remove actions on the Cameras page; KCM parity with the same wire
  fields.

## Acceptance tests

- Selection order (pure): complete primary connected and eligible →
  primary; one-sided legacy binding → refusal naming it; primary absent or
  ineligible for the mode, one eligible group connected → that group; two
  eligible groups connected → the lower pair identity, unchanged after the
  store is rewritten in another order; two groups with the same pair →
  ambiguous, skipped and reported; group in an inactive store → skipped;
  nothing eligible connected → refusal naming the cause; an unenrolled
  pair present alone → never chosen.
- Ordering: with automatic mode the camera lease and the open happen after
  selection; a test with a spy backend asserts no node is opened before the
  selection ran, and none at all when nothing is selected.
- Enrollment candidate: a fresh install with no `cameras.conf` enrolls on
  the ranked candidate and prints it; the enrolled pair becomes the
  primary binding.
- Pinning: a pair chosen for an attempt stays the attempt's pair when the
  inventory changes mid-attempt; the next request re-selects.
- `pinned` mode: the pinned pair absent → refusal, the status says "not
  connected", no other pair is opened; the environment pair overrides in
  both modes and the status names `environment` as the source; an
  unreadable or malformed `cameras.conf` refuses with `unreadable` and is
  never read as fresh.
- Candidates: an identity whose IR node is absent from the passive
  inventory is not a candidate even though its RGB node is; a swapped node
  between selection and open refuses with "camera changed".
- Enrollment on an explicit pair: `EnrollOn` / `AddCameraGroupOn` capture
  on the named pair without writing `cameras.conf`; an older daemon
  rejects the variant. Root `Identify` in automatic mode with no pinned
  pair uses the candidate rule and reports the camera.
- Probing: a requalification scheduled for a group that is removed before
  it runs never opens the camera.
- Default: no `cameras.conf`, or one without a complete `rgb`/`ir` pair →
  automatic; a `cameras.conf` with a complete pair and no `mode` → pinned;
  `set-cameras <rgb> <ir>` pins; `SetCameraSelection { automatic }` to an
  older daemon fails visibly, never as a silent success.
- The comment lines: a product string with CR, LF or control characters
  never produces a key line the reader would consume; mode, pair and
  comments land in one rename.
- Wire: a frozen copy of today's `CameraPairInfo` decodes a new daemon's
  listing; `name`, `identity` and `primary_camera` absent from an old daemon
  leave the TUI showing the node row and no role.
- Names: a node whose sysfs name is empty falls back to the USB product,
  then to the identity; the name is never used by any matching path (a test
  changes the name and asserts selection and the boundary are unaffected).
- Hardware: on the reference desk, automatic mode chooses the BRIO with both
  connected and the NexiGo with the BRIO unplugged, in the dual and IR-only
  policies, each attended attempt recorded on the shared ledger.
