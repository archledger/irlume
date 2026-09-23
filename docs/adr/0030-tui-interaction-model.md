# ADR-0030: TUI interaction model

## Status

Proposed 2026-09-23, from a page-by-page review of the nine `irlume` TUI
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

1. **Enter opens, never mutates.** Enter opens a row, a details panel or a
   sub-list. Every side effect has its own letter and, when it writes or
   runs as root, the existing confirmation dialog.
2. **Esc closes the innermost thing** (help, overlay, details panel,
   dialog); with nothing open it goes to Overview. Never quits.
3. **Stable keys.** Global: `1`–`9` jump to the sidebar sections in order;
   `Tab`/`Shift-Tab` cycle them; `j`/`k` move like `↓`/`↑`; `g`/`G` first
   and last row; `/` filters the current list (Diagnostics, scans, login
   surfaces, activity history); `r` refreshes the page's observations;
   `i` runs Test Recognition wherever recognition is the subject; `?`
   opens context help for the current page; `q` quits; `v` toggles the
   advanced view. A page may not reuse a global letter with another
   meaning. Page letters are verbs that read in the bottom bar (`w` wire,
   `x` un-wire, `u` use this camera, `f` fix, `e` enroll, `a` add scans,
   `c` add camera, `n` rename, `d` delete).
4. **One action row.** Actions sit on one or two lines under the page's
   facts: the key dim, the verb plain, an optional grey hint. The in-page
   `[r] …` columns go away; the bottom bar is the one place keys are
   advertised, with `F2` still opening the full list.
5. **Status vocabulary.** Five glyphs, one meaning each, on every page:
   `●` ready/on, `○` off/not selected, `◐` unobserved or pending, `✕` not
   connected/absent, `⚠` needs attention. Colour reinforces, never carries
   (`NO_COLOR` keeps the glyphs).
6. **Facts, not "yes".** A status row states the fact the person would
   open the page for; a row that cannot state it says what to do
   (`unknown — press r`, `needs root — sudo irlume doctor`).
7. **Truncate with an ellipsis; expand on Enter.** No silently cut line.
8. **Wide terminals get a details column.** At ≥120 columns, list pages
   (Cameras, Faces, Diagnostics, Login & Apps) show the selected row's
   details in a right-hand column; narrower terminals keep the Enter
   panel. Same content, one code path.
9. **One freshness indicator.** The page header keeps "observations ≤Ns
   old · F4 details"; the bottom line keeps the Activity log only.
10. **Identifiers live in details or Diagnostics.** Node paths, NV handles,
    context hashes and vid:pid never appear on a Setup page's first line.

### 2. Pages

- **Overview** leads with the last authentication on this machine: when,
  which surface (login / lock / sudo / app), which camera by name, the
  outcome class and, for a refusal, the non-biometric reason in plain words
  (`no face seen — were you in frame?`, `IR camera shutter is closed`),
  and the elapsed time. Below it the status rows of §1.6 and the one
  recommended next step ("You're one step away: wire the lock screen
  (w)"), which becomes "Test Recognition (i)" once everything is wired.
- **Faces** groups a profile's scans by the camera they were captured on
  (primary / added camera #N, ADR-0029 roles), collapsed by default with a
  count and date range, and says whether the count is enough
  (`16 scans · enough for glasses and low light ✓`). It owns `e` add a
  person, `a` improve recognition, `c` add a camera, `n` rename, `d`
  delete, `i` test recognition. Test Recognition stops being a page.
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
  shows only that step's action until it is done.
- Every "unavailable / unknown / needs root" line ends in the action that
  resolves it (§1.6).
- Confirmation dialogs say what changes for the person and how to undo it
  ("Face unlock will use the Logitech BRIO from now on; press u on another
  camera to change"), keeping the file path as the second sentence.
- Plain names: "password wallet" (already), "admin prompts" for
  sudo/polkit on first mention, recognizer and model names only in
  Diagnostics.

### 4. Maintainer tools

- **Raw facts** behind `F4`: identities with serials, nodes, qualification
  context, TPM tier and PCR policy, the last trace's stage timings; text
  is selectable and `y` copies the pane to the clipboard when a clipboard
  is reachable (OSC 52 with the terminal's consent; otherwise the pane
  prints a path).
- **Support bundle** from Diagnostics prints the file path it wrote and
  offers `y` to copy it.
- **Per-camera timing history**: the last five attempts per camera, cold
  or warm, elapsed and the capture stage's share, from the daemon's
  share-safe events (§5). Shown in the camera's details.
- **Simulate selection** (after ADR-0029 B): "if the BRIO were unplugged →
  NexiGo (added camera #1)", a pure function of the roles and the
  connected set; never opens a device.
- **Undo within the session** (`z`) for reversible changes the TUI itself
  made: rename, camera pin, policy toggles. Each such action records its
  inverse command; `z` confirms and runs it.
- **Command echo**: every action that runs a CLI command logs the exact
  command to the Activity line (most do; this makes it a rule), and
  `irlume tui --print-commands` prints them to stderr as well.

### 5. Daemon facts this needs (share-safe, non-biometric)

- The last-attempt line and the timing history read the share-safe event
  stream the daemon already keeps for `SupportSnapshot`. `OperationFinished`
  gains optional `elapsed_ms`, `surface` (login / lock / elevation / app /
  other, from the service class) and `camera` (the pair's `vid`/`pid` and
  `descriptor_token`, the same share-safe reference `SanitizedCameraContext`
  already carries — never the binding identity, since share-safe records
  hold no serial and a test enforces that; the TUI maps vid/pid to the
  listed camera's name, and two same-model units share a name anyway), and
  a refusal gains its `OutcomeKind` class name. No score, threshold,
  embedding or reason prose crosses the socket; the TUI phrases the class. A `since_ms` read of the snapshot
  already exists and is user-scoped by the posture table.
- Nothing else: roles come from ADR-0029 A, selection from ADR-0029 B.

### 6. Machine and account

- Every page's header says whose settings it shows and whether the page is
  per account (Faces, Wallet, Recovery, Preferences' account rows) or per
  machine (Cameras' pin, Login & Apps, Diagnostics). Root sees an account
  switcher (`Ctrl-U`) where per-account pages are shown.
- Docking: an inventory change refreshes the Cameras page and the
  Diagnostics camera row without a keypress (the live snapshot already
  arrives; the rows re-render from it).
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
  figures they now collect by hand. The daemon's contract grows by three
  optional fields on an event it already emits.
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
- C2 — pages and the last-attempt line: §5's event fields in the daemon,
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
  with a global letter, Enter never sets `confirm`/`suspend`/`input`, and
  Esc closes an open panel before navigating.
- Vocabulary: every status span uses one of the five glyphs; a
  `NO_COLOR` render still distinguishes the five states.
- Layout: at 120×40 a list page renders the selected row's details in the
  right column; at 80×30 it renders them only after Enter.
- Overview: with an `OperationFinished` carrying a refusal class, the first
  line names the surface, the camera by name and the plain-words reason;
  no score or threshold text can appear (a forbidden-word scan as in the
  attended trial tooling).
- Faces: scans group by camera role; the count line says "enough" only
  above the documented floor.
- Login & Apps: an absent display manager never occupies a row.
- Undo: rename then `z` restores the name through the same request path;
  `z` with nothing to undo says so.
- Command echo: every `Suspend::*` variant logs a line beginning with the
  command it runs.
