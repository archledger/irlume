# ADR-0030: TUI interaction model

## Status

Proposed 2026-09-23, revised the same day after two design reviews (the
reviewers' points are folded into §1.1, §1.3, §1.4, §2, §4, §5 and §6).
Depends on ADR-0029, which merges first. From a page-by-page review of the nine `irlume` TUI
screens on the reference laptop (screenshots on the shared ledger's
project handoff, 2026-09-23) and a written pass through the tool from a
first-hour user's seat and a maintainer's seat. Builds on ADR-0029 (camera
names, roles and selection; its phase A redesigns the Cameras page) and
changes nothing in what the daemon decides: every rule here is about how the
TUI asks, shows and names. Where a rule needs a new daemon fact it says so;
each such fact is share-safe and non-biometric.

## Context

The TUI is complete and correct, and it reads like a map rather than a
route. Concretely, on 2026-09-23:

- Every page sits in the top third of a 40-row terminal. Actions are laid
  out one per row with a blank line between them, so five actions take ten
  rows, and the facts a person opens the page for — the last unlock, the
  camera in use, what is wrong — have no home. Diagnostics leaves a
  half-screen gap between its check list and the box that repeats the
  selected row.
- Key letters change meaning per page: `r` is re-arm, re-check, readiness
  or inspect candidates; `s` is set passphrase, support report, set up
  emitter or show status; `p` is pcrlock refresh, app prompts, list units
  or restore confirmation. Enter opened a row on Overview, switched the
  camera pin on Cameras (until ADR-0029 A) and did nothing on Preferences.
- Overview's status rows say `yes` where the fact is known (`wired: login,
  lock, sudo`; `armed · Tier 2`; `set`). Faces lists sixteen scans flat and
  in file order. Login & Apps spends eight rows on display managers that
  are not installed and wraps its action descriptions mid-sentence.
  Diagnostics truncates without an ellipsis. Test Recognition is a page for
  one key that Overview already exposes. Preferences names settings by
  mechanism ("Biopolicy operation-class gate").
- Two freshness indicators compete ("observations ≤18s old" at the top,
  "[F4] Daemon worker ready" at the bottom); "advanced ·" in the header has
  no hint that `v` toggles it; "capture history unknown (daemon not
  answering)" was drawn before the poll had run (fixed in ADR-0029 A).
- What a first-hour user asks after a refused or slow unlock — *why?* — is
  answered nowhere in the TUI. What a maintainer asks — which camera, how
  long, cold or warm — is answered only by the trace tooling.

Things the TUI already does well and which this ADR keeps: the sidebar
with three groups, the bottom key bar, the confirm-before-side-effect
dialogs, the passive live inventory, `NO_COLOR` support, the Activity log
line and `F4` details, and the rule that nothing the TUI renders opens a
device.

## Decision

### 1. Interaction rules, every page

1. **Enter opens, never mutates.** On a list row, a section or a panel,
   Enter opens it; it never runs a side effect from a list, and a second
   click on a selected row is the same as Enter. The one place Enter (or
   Space) activates is an action chip explicitly focused with `F6`: there it
   does exactly what the chip's letter does, including the chip's
   confirmation, because the person chose the action, not the row. Every
   side effect keeps its own letter and, when it writes or runs as root,
   the existing confirmation dialog.
2. **Esc closes the innermost thing** (help, overlay, details panel,
   dialog); with nothing open it goes to Overview. Never quits.
3. **Stable keys.** Global: `1`–`9` jump to sections by a fixed table —
   `1` Overview, `2` Faces, `3` Password Wallet, `4` Recovery, `5` Login &
   Apps, `6` Diagnostics, `7` Cameras, `8` Preferences, `9` Fingerprint —
   not by sidebar position, so a digit means the same thing whether or
   not the advanced view is on or the hardware hides a page (a hidden
   section's digit shows it when the machine has it, else does nothing
   and says so); `Tab`/`Shift-Tab` cycle the visible ones; `j`/`k` move like `↓`/`↑`; `g`/`G` first
   and last row; `/` filters the current list (Diagnostics, scans, login
   surfaces, activity history); `r` refreshes the page's observations;
   `i` runs Test Recognition wherever recognition is the subject; `?`
   opens context help for the current page; `q` quits; `v` toggles the
   advanced view. A page may not reuse a global letter with another
   meaning. Page letters are verbs that read in the bottom bar (`w` wire,
   `x` un-wire, `u` use this camera, `f` fix, `e` enroll, `a` add scans,
   `c` add camera, `n` rename, `d` delete).
4. **One action row.** Actions sit on one or two lines under the page's
   facts: the key dim, the verb plain, an optional grey hint. Keys are
   advertised in exactly two places, which agree: the action rows (every
   page action) and the bottom bar (the page's primary actions, `F2` for
   the full list). Prose never embeds a key — a recommendation such as
   "wire the lock screen" is itself an action row, not a sentence with
   `(w)` in it.
5. **Status vocabulary.** Five glyphs, one meaning each, on every page:
   `●` ready/on, `○` off/not selected, `◐` unobserved or pending, `✕` not
   connected/absent, `⚠` needs attention. Colour reinforces, never carries
   (`NO_COLOR` keeps the glyphs).
6. **Facts, not "yes".** A status row states the fact the person would
   open the page for; a row that cannot state it says why and the
   remediation is an action row beneath it (`refresh`, `run as root`),
   never a key inside the sentence (§1.4).
7. **Truncate with an ellipsis; expand on Enter.** No silently cut line.
8. **Wide terminals get a details column.** At ≥120 columns, list pages
   (Cameras, Faces, Diagnostics, Login & Apps) show the selected row's
   details in a right-hand column; narrower terminals keep the Enter
   panel. Same content, one code path.
9. **One freshness indicator.** The page header keeps "observations ≤Ns
   old · F4 details"; the bottom line keeps the Activity log only. The
   header's `F4` is the one exemption from §1.4: it is not prose but the
   freshness chip's own action, the same key the bottom bar lists, and
   no other key may appear in a header.
10. **Identifiers live in details or Diagnostics.** Node paths, NV handles,
    context hashes and vid:pid never appear on a Setup page's first line.

### 2. Pages

- **Overview** leads with the account's last face attempt (§5): the
  stored `kind` and surface name it — for an `authenticate` record, the
  surface's own word ("last login", "last unlock", "last admin prompt",
  "last app sign-in", or "last authentication" when the surface is
  `other`); "last recognition test" for an `identify` one — then when,
  which camera by
  name, the outcome class and, for a refusal, the cause in plain words
  from the closed vocabulary of §5 (`no face seen — were you in frame?`,
  `camera shutter closed`), and the elapsed time. The record keeps the
  latest of each kind, so a recognition test never displaces the last
  real authentication: the line shows the most recent attempt labelled by
  its kind, and when the latest is a test and an authentication exists
  the line adds "last authentication: <outcome>, <when>". When no attempt
  is retained the line says so. Below it the status rows of §1.6 and the one recommended
  next step as an action row ("wire the lock screen"), which becomes
  "Test Recognition" once everything is wired.
- **Faces** groups a profile's scans by the camera they were captured on
  (primary / added camera #N, ADR-0029 roles), collapsed by default with a
  count and, for scans that carry one, a capture date range. `FaceScan`
  gains an optional `captured_at` (unix seconds) written for new scans,
  and the enrollment reply carries it beside each scan name (an optional
  per-scan `captured_at` on `ProfileSummary` and a per-group first/last
  pair on `CameraGroupProfileSummary`, `serde(default)`); older scans and
  older daemons show "date not recorded". The count line states only what
  is known: the number of scans against the **capture target**
  (`16 scans · capture target met`), and separately the recognizer
  compatibility the reply already reports (`IR ready on this recognizer`,
  or the shortfall); it never presents the count as recognition readiness,
  and makes no claim about glasses, lighting or other conditions, which
  the store does not record — the tips about adding scans in other
  conditions stay. It
  owns `e` add a person, `a` improve recognition, `c` add a camera, `n`
  rename, `d` delete, `i` test recognition. Test Recognition stops being a
  page. `i` runs the identification diagnostic through a **user-scoped**
  request, `IdentifyFor { user }` (1:N against that account's enrollment
  only; no grant), so what the TUI shows for the selected account is what
  it tests and the attempt record it updates is that account's; root's
  account-less `Identify` stays a CLI diagnostic and is not what the page
  runs. `IdentifyFor { user }` sits in the posture table as
  root-or-target, exactly like `LastAttempts { user }` and
  `FaceSensorStatus { user }`: the daemon checks the peer against the
  named account before it loads any enrollment or opens a camera, so no
  local user can run recognition against another account, learn its
  result or touch its attempt record. Identification attempts are
  retained in the account's record marked `identify`, so the beginner
  route's "try it" updates the last-attempt line without replacing the
  last authentication (Overview, above).
- **Login & Apps** lists the surfaces present on this machine with what
  each does, and folds the absent display managers into one grey
  sentence. Actions on one row.
- **Diagnostics** keeps the check list; the selected row expands in place
  (or in the details column); the "diagnosis" box goes.
- **Cameras** as ADR-0029 A/B/C: names, roles, selection mode, details.
- **Preferences** names each setting by the decision, with its state and
  its one action on the same row: *IR-only mode*, *Hands-free at admin
  prompts*, *Camera selection* (ADR-0029 B), *Strict service gate*. The
  read-only threshold note stays as one grey line.
- **Password Wallet / Recovery** keep their content; actions move to one
  row; the NV handle moves into `F4`.

### 3. Beginner route

- The existing first-run front door becomes a three-step route with
  "next" on every step: enroll → wire login + lock → try it, ending on
  Overview with the last-attempt line showing the try. Each step's page
  shows only that step's action until it is done. The route is chosen
  from the detected capabilities the sidebar already uses
  (`compute_visible`): with no usable camera it is the fingerprint route
  (enroll a finger → wire → try it) when a reader exists, and otherwise
  the front door says what is missing and offers Login & Apps for the
  password path; a face step is never offered on a machine that cannot
  complete it, and a machine with both offers face first with
  fingerprint as the alternative on the same step.
- Every "unavailable / unknown / needs root" line ends in the action that
  resolves it (§1.6).
- Confirmation dialogs say what changes for the person and how to undo it
  ("Face unlock will use the Logitech BRIO from now on. To change it,
  choose another camera on the Cameras page."), keeping the file path as
  the second sentence; the dialog's own choices are its action row
  (§1.4), and no key is named in the sentence.
- Plain names: "password wallet" (already), "admin prompts" for
  sudo/polkit on first mention, recognizer and model names only in
  Diagnostics.

### 4. Maintainer tools

- **Raw facts** behind `F4`: for an ordinary account, exactly the share-
  safe facts ADR-0008 already permits (vid/pid, USB topology as role
  labels and port chain, descriptor and qualification tokens, serial
  present/absent, TPM tier and PCR policy) plus the retained
  `elapsed_ms`/`capture_ms` of the attempt record. The raw serial and the
  `/dev` node paths are gated by the **daemon**, not by the TUI: they
  travel only in a root-only `CameraDetails` request (the same posture as
  the trace subscription), and the any-peer `ListCameras` row carries
  `vid:pid`, `serial_present`, the port chain, the descriptor token and an
  opaque **pair handle** (`handle`: a daemon-minted token for this pair in
  this connection generation, share-safe, meaningless off the machine),
  not the serial or the node paths — an amendment to ADR-0029 A's
  `identity` field, which becomes root-only likewise. The boundary is
  the daemon's, so it covers every any-peer carrier of node paths, not
  only `ListCameras`: `Health`'s `rgb_dev`/`ir_dev` are redacted to
  `None` for a non-root peer in the same change, and `LiveStatus`'s
  `CameraCandidate` keeps its validated shape (its decoder rejects an
  empty path list, so an empty vector is not a redaction) but carries
  `endpoint_paths` as **opaque endpoint tokens** for a non-root peer —
  the same bounded literal form (`/dev/`-prefixed names of the same
  count, minted from the pair handle, never real node names) — with a
  `redacted: true` marker (`serde(default)`), so an older client decodes
  the snapshot unchanged and a newer one knows not to treat the tokens
  as paths; the TUI's Cameras page reads the active pair by handle
  (`Health` gains `active_handle`) rather than by node string; root keeps
  the full snapshot. The transition is additive
  so the mixed-version window of a package upgrade degrades rather than
  breaks: `CameraPairInfo` keeps `rgb`/`ir` as fields that an upgraded
  daemon fills with `""` for a non-root peer (an older TUI still decodes
  the row and shows the name and role, with no node column), and gains
  `handle` with `serde(default)` (a newer TUI receiving no handle from an
  older daemon shows the row but disables the handle-bearing actions
  with "daemon older than this tool"). The same rule as ADR-0029 A's
  optional fields: additive, defaulted, and the client states which side
  is older. Two consequences for ordinary accounts, which never see
  nodes or serials:
  - ADR-0029 §3's `EnrollOn` / `AddCameraGroupOn` take the pair
    **handle**, not node names; the daemon resolves the handle to the
    nodes and identities server-side and re-checks them under the lease as
    §1 of that ADR requires. A handle from an older connection generation
    is refused ("camera changed; pick it again").
  - Roles are correlated **by the daemon, account-scoped**: the
    user-scoped enrollment reply's `primary_camera` and each camera group
    gain `connected_handle: Option<handle>` — the handle of the connected
    pair whose identity matches that binding, or `None` — so the client
    labels rows by handle and never needs the serial; two same-model units
    with different serials get the right labels because the daemon holds
    both identities. In the same change the enrollment reply stops
    carrying binding identities to ordinary peers: `primary_camera`'s
    sides and `CameraGroupSummary.rgb`/`ir` are reduced to `vid:pid` for
    a non-root peer (the same redaction `ListCameras` applies; the fields
    stay present so older clients decode), and the full identities travel
    only to root — so no any-peer reply names a serial. Until this lands,
    ADR-0029 A's client-side match on `vid:pid` is the interim and is
    documented as such. Stage timings beyond those two durations exist
  only while a root trace subscriber is active and are not retained; the
  pane says "stage timings are recorded by a trace" and its action row
  offers *record a trace* (root) rather than promising them. Text is
  selectable and the pane's action row offers *copy* when a clipboard is
  reachable (OSC 52 with the terminal's consent; otherwise the pane
  prints a path). The pane's keys live in its action row and the bottom
  bar, as §1.4 requires.
- **Support bundle** from Diagnostics prints the file path it wrote and
  offers `y` to copy it.
- **Per-camera timing history**: the last five attempts per camera for
  the account, elapsed and the capture stage's duration (`capture_ms`,
  §5), from the account's retained attempt records. Shown in the camera's
  details; two connected units of the same model are told apart by the
  USB port chain the record and the listing both carry.
- **Simulate selection** (after ADR-0029 B): "if the BRIO were unplugged →
  NexiGo (added camera #1)", a pure function of the roles and the
  connected set; never opens a device.
- **Undo within the session** (`z`) for reversible changes the TUI itself
  made: rename, camera pin, policy toggles. Each such action records the
  value it wrote and its inverse; `z` confirms and sends the inverse with
  an **expected-current-value precondition** carried in a **separate
  compare-and-set variant** (`RenameProfileExpecting { expected, .. }`,
  so an older client's plain `RenameProfile` keeps decoding; for the pin
  a new
  `SetCamerasExpecting { expected_pair, expected_mode, .. }` that writes
  pair and mode in ADR-0029's one atomic publication only when the file
  still holds the expected ones — `SetCameraSelection` changes the mode
  alone and `SetCamerasIfCurrent` guards the live device generation, not
  the file; the policy writers likewise), which the daemon checks under
  its own lock and refuses if the value is no longer the one this session
  wrote; the refusal names the change. No separate read-then-act. Every
  undo entry records the account it belongs to (the pin and the policy
  toggles are per machine and record none); switching accounts (§6)
  drops the account-bound entries at once, so `z` can never send Alice's
  inverse while the page says Bob, and an entry is only ever offered
  while its account is the selected one.
- **Command echo**: every action that runs a CLI command logs the exact
  command to the Activity line (most do; this makes it a rule), and
  `irlume tui --print-commands` prints them to stderr as well.

### 5. Daemon facts this needs (non-biometric, account-scoped)

- The daemon's share-safe event ring (`SupportSnapshot`) is the wrong
  carrier for authentication history: it is readable by any local peer on
  the mode-0666 socket, is process-local, is erased on restart and is
  bounded to 30 minutes. Nothing about attempts is added to it.
- Instead the daemon keeps, per account, a small **attempt record**
  file under its state directory (root-only, like the retry journal):
  the latest attempt of each kind and the last five per camera, bounded
  as a whole — at most eight camera buckets per account, the least
  recently used bucket evicted when a ninth camera appears, and a bucket
  whose newest attempt is older than 90 days pruned on the next write —
  so the file stays small however many cameras come and go; each attempt
  carries the time, the
  surface (login / lock / elevation / app / other, from the service
  class **as the daemon already resolved it**: the operation class from
  `biopolicy::classify` with the session state, so a greeter that serves
  both login and lock is recorded as what it was, not reclassified from
  the service name), the kind (`authenticate` or `identify`), the camera
  as vid/pid plus the USB port chain **and** the share-safe
  `descriptor_token` (the digest `SanitizedCameraContext` already carries:
  durable across unplugging, identical only for units that share a
  descriptor byte for byte) — the record is a history of what was attached
  where, so the TUI maps it to a current camera only when **both** the
  port chain and the token match a connected camera, and otherwise shows
  the model name (vid/pid) with "no longer connected" (or "different
  port" when only the token matches) rather than attributing the attempt
  to a replacement unit or to the same unit moved elsewhere; never the
  binding identity, so no serial. The
  camera fields are **optional**, absent for an attempt refused before any
  camera was selected (startup, retry throttling, method or policy
  checks), as is `capture_ms` — the outcome class, the cause, `elapsed_ms` and
  `capture_ms`. The cause is structured at every place a result is
  decided: on the engine's `Outcome` (`OutcomeCause`, set where the
  outcome is built, next to `OutcomeKind`) for attempts that reached a
  decision; on the engine's error boundary for attempts that reached the
  engine but ended in an error (`irlume_common::Error` gains a `cause()`
  classification — privacy shutter, camera unavailable, cancelled, timed
  out, other — so the daemon maps an `Err` without reading its text; the
  privacy boundary, which today reaches the engine as
  `Error::Hardware(String)` prose, gets its own typed variant
  `Error::PrivacyShutter` raised where the camera layer detects the
  refusal, so `privacy shutter` is a cause the classifier can assign and
  the Overview line can name); on
  `IdentifyOutcome`, which gains the same `OutcomeCause` beside its
  `reason`; and as a daemon-level `EarlyRefusal` enum for the paths that
  answer before the engine (`method not available`, `policy`,
  `configuration`, `retry throttled`, `daemon starting`), each recorded
  as its own cause. The vocabulary: `no face`, `liveness refused`,
  `below threshold`, `privacy shutter`, `camera unavailable`, `not
  enrolled on this camera`, `setup unavailable`, `cancelled`, `timed
  out`, `method not available`, `policy`, `configuration`, `retry
  throttled`, `daemon starting`, `other`. The daemon records what it
  decided and never infers a cause from reason prose. No score,
  threshold, embedding or reason prose is stored; the TUI phrases the
  cause, and for a record with no camera says "before a camera was
  chosen".
- A new user-scoped request `LastAttempts { user }` returns that record;
  the posture table admits the account itself and root, as it does for
  `FaceSensorStatus { user }`. The camera listing of ADR-0029 A gains the
  same USB port chain so the TUI can map a record to a listed camera.
- Nothing else: roles come from ADR-0029 A, selection from ADR-0029 B.

### 6. Machine and account

- Every page's header says whose settings it shows and whether the page is
  per account (Faces, Wallet, Recovery, Preferences' account rows) or per
  machine (Cameras' pin, Login & Apps, Diagnostics). Root sees an account
  switcher (`Ctrl-U`) where per-account pages are shown. Switching
  accounts **clears** the installed per-account rows and selections at
  once and disables the account-bound actions (rename, delete, add scans,
  add/remove camera, wallet, recovery) until the new account's generation
  has loaded, so no action can be built against the old account's rows;
  every per-account load carries the account and a generation, and a
  result that lands after the account changed is dropped, never installed
  into the new account's page.
- Docking: an inventory change refreshes the Cameras page and the
  Diagnostics camera row without a keypress (the live snapshot already
  arrives; the rows re-render from it), and because the connection
  generation changed it also re-issues the handle-bearing loads: the
  `ListCameras` listing (new handles) and the account's enrollment reply
  (new `connected_handle` correlations), clears the Cameras selection and
  any pending camera action built on an old handle, and generation-checks
  the results so a listing from before the change is dropped. Until both
  land the camera actions are disabled with "cameras changed; reloading".
- First launch after an upgrade shows one line from the changelog's
  Unreleased/latest section that affects the TUI, once.
- User-facing strings move to one table per page so they can be reviewed
  and, later, translated; no behaviour change.
- Accessibility: `NO_COLOR` stays; a `--high-contrast` flag maps the theme
  to bold/underline instead of hue; reading order of every page is
  top-to-bottom, left-to-right, with the status glyph first.

### 7. Outside the TUI, recorded here so it is not lost

- The lock screen should show the one-line reason when face fails
  ("camera shutter closed", "no face seen"); that is the PAM/KDE surface,
  a separate change with its own ADR if pursued.

## Consequences

- Beginners get a route and an answer to "why not"; maintainers get the
  figures they now collect by hand. The daemon's contract grows by one
  root-only per-account attempt record and one user-scoped request (§5);
  no existing event changes, and the any-peer support snapshot carries
  nothing new.
- Muscle memory forms because letters stop changing meaning; the cost is a
  one-time relearn for the few pages whose letters move (Cameras' Enter,
  Wallet's `p`).
- Fewer pages (Test Recognition folds into Faces), and less empty screen.
- Nothing changes in what grants: no rule here reads or shows biometric
  data, and the daemon's posture table still decides who may read what.

## Phasing

- C1 — interaction rules: §1.1–1.5, 1.7–1.9 (Enter rule, Esc rule, stable
  keys, one action row, status vocabulary, ellipsis/expand, details column,
  one freshness indicator) and the `?` context help. TUI only.
- C2 — pages and the last-attempt line: `OutcomeCause` on the engine's
  outcome, §5's attempt record and request in the daemon, `captured_at`
  on new scans and on the enrollment reply,
  Overview, Faces (grouped scans, Test Recognition folded), Login & Apps,
  Diagnostics, Preferences by decision, Wallet/Recovery action rows, §1.6
  and §1.10 sweeps.
- C3 — maintainer tools: raw facts + copy, support bundle path, timing
  history, undo, command echo and `--print-commands`; simulate selection
  once ADR-0029 B has landed.
- C4 — route and machine/account: the first-run route, confirmation
  wording, account switcher and per-account/per-machine markers, docking
  refresh, upgrade note, string tables, high contrast.

## Acceptance tests

- Key table: a test walks every page and asserts no page letter collides
  with a global letter, Enter on a row never sets
  `confirm`/`suspend`/`input` (an F6-focused chip is the documented
  exception), Esc closes an open panel before navigating, and each digit
  reaches its fixed section whatever the sidebar shows.
- Vocabulary: every status span uses one of the five glyphs; a
  `NO_COLOR` render still distinguishes the five states.
- Layout: at 120×40 a list page renders the selected row's details in the
  right column; at 80×30 it renders them only after Enter.
- Overview: with an attempt record carrying a refusal cause, the first
  line names the surface, the camera by name and the plain-words cause;
  no score or threshold text can appear (a forbidden-word scan as in the
  attended trial tooling); a record for another account is never shown;
  after an `identify` attempt the line is labelled a recognition test and
  the last `authenticate` record is still reported beside it; a sudo
  attempt is labelled "last admin prompt", never a login.
- Route: on a fingerprint-only machine the first-run route offers no
  face step; on a machine with neither it offers Login & Apps.
- Faces: scans group by camera role; the count line states the minimum
  and nothing about conditions; scans without `captured_at` read "date
  not recorded".
- Login & Apps: an absent display manager never occupies a row.
- Undo: rename then `z` restores the name through the same request path
  with the expected-value precondition; `z` with nothing to undo says so;
  a request whose precondition no longer holds is refused by the daemon
  and the refusal names the change; an entry recorded for one account is
  gone after the switcher selects another.
- Wire boundary: as a non-root peer, `Health`, `LiveStatus`,
  `ListCameras` and `ListProfiles` carry no real `/dev` path and no
  serial, and a redacted `LiveStatus` still decodes with the current
  `CameraCandidate` validator; `IdentifyFor` for
  another account is refused before any enrollment load; a
  `ListCameras` row without `handle` (older daemon) renders with the
  handle-bearing actions disabled.
- Docking: an inventory change re-issues the listing and enrollment
  loads, drops a listing from the previous generation and clears the
  selection.
- Attempt record: a refusal before camera selection is recorded without a
  camera and rendered as "before a camera was chosen"; a lock-screen
  attempt through a dual-purpose greeter is recorded as lock, not login;
  an identification is recorded as `identify`; a shutter refusal during
  capture is recorded as `privacy shutter`, never `other`; a record
  whose token matches a connected camera on a different port chain
  renders "different port", not the connected camera's name; a ninth
  camera evicts the least recently used bucket and the file never holds
  more than eight.
- Command echo: every `Suspend::*` variant logs a line beginning with the
  command it runs.
