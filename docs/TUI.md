# TUI and CLI workflows

Open **Irlume** from your desktop's application menu, or run `irlume tui` as your
account. The menu entry asks your desktop to open its terminal application;
it does not run the whole interface as root. A terminal-capable desktop launcher
and an installed terminal are required. `--user ACCOUNT` selects the same account as
the CLI; managing another account still requires the existing administrator
permissions. Read the account name in the header before making changes.

The minimum window size is **80 columns × 24 rows**. Below either dimension,
only a resize message is shown with the current and required size. Enlarge the
terminal to restore the current page or dialog; hidden controls cannot activate.
Live observations continue refreshing. Esc can request cancellation of an active
enrollment, and `q` exits (a general daemon task can keep running).

Tab/Shift-Tab and Left/Right switch sections. **F3 opens Sections**, including
on a supported narrow terminal where the sidebar is hidden. **F6 switches page/action
focus**: use Up/Down to select a control and Enter or Space to activate it. The
focused action scrolls into view and uses the same confirmation as its mouse
button or shortcut. PageUp/PageDown reads the page while actions have focus;
otherwise it scrolls Activity. `?` shows this screen's shortcuts. `v` reveals technical
sections. **F2 opens More actions**
from any idle screen. Type a task or CLI command to filter the list, use Up/Down
to select, and Enter to open it. Esc closes the list or cancels a field.

Mouse users can click the sidebar, status rows and action buttons, including
in-page Wallet, Recovery, Login, Fingerprint, Cameras, Diagnostics, Identify,
Preferences and completion actions. Each action has a separated row; its label
and wrapped explanation activate the same keyboard command. Blank space and
ordinary explanatory text do not activate commands. In More
actions, click a row to select it and read its description, then click **Open**.
Dialogs have separate **Continue**, **Confirm**, **Cancel** or **Close** buttons;
clicking outside a dialog does nothing. Typed confirmations still require the
exact requested text.

The mouse wheel moves through the list under the pointer (Faces, Cameras,
Diagnostics or More actions). Over Activity it scrolls the activity history.
The wheel also scrolls longer information/action panels, including Wallet,
Recovery and Login. Long dialogs scroll within their own body while the buttons
remain visible.
Use Up/Down to scroll long non-text dialogs without activating their buttons.
Press `M` to release mouse capture for the terminal's text selection and copy
controls; press it again to resume mouse navigation.

More actions supplies guided fields for less frequent tasks and shows the
account, effects, and literal command arguments before asking you to run it.
Blank optional fields use the CLI default; required fields cannot be blank.
It executes the same running CLI build, then returns to the TUI after you
press Enter. Commands needing administrator access use sudo; password and
recovery prompts stay in the command's private terminal input. Fields in the
menu are never shell commands. Paths beginning with `-` can use a `./` prefix.

If a command fails or is interrupted, some changes may already have been
applied. Review its terminal output and the refreshed status before retrying.
An unsuccessful daemon-start command does not automatically resume enrollment.

## Activity and device transparency

**A** expands or collapses recent Activity. **Shift+L** opens full-height
**Session history**; you can also click its History control. This view shows
elapsed session timestamps, text status labels, and the retained message details.
Use Up/Down, the wheel, PageUp/PageDown, Home and End to read history. End follows
new messages; Esc or Shift+L closes history without running a page action.

The compact strip shows one summary per message so a long older explanation
cannot hide the newest result. Open history to read wrapped details. While you
read older entries, arriving messages do not pull you to the bottom. History is
bounded to 200 messages and 32 KiB of text; individual messages are bounded to
4096 bytes. Omission/truncation is displayed, and history is kept only in this
process's memory.

Session history describes this TUI's actions and observations. Live daemon
status separately shows the current worker operation, queued work, and automatic
background camera qualification, including requests from another Irlume client.
Press **F4** to open **Current observations**, with operation details and the age
of each source. It continues refreshing while dialogs or
an enrollment are open. The observer reads copied metadata; it does not capture
frames or inspect the TPM. These observations are not a complete operating-system
audit or proof of camera/IR-emitter shutdown. Explicit setup and test actions
can use the camera or TPM and change configuration. F2 provides
existing system/login history, diagnostics and explicit trace tools when more
detail is needed; camera diagnostics explicitly discloses that it captures.

Status fields carry observation freshness. A failed or expired check becomes
unavailable; it does not mean OFF, an empty profile list, or an idle daemon.
Each source is checked separately, so a successful camera refresh cannot make
an older wallet result current. Live status is polled about once a second; other
sources refresh at bounded intervals and after relevant changes. This is observed
state, so a change can take time to reach the display. One-shot recognition and qualification results
remain past observations until you explicitly run another test. An older daemon
without live-status support is shown as unavailable for that source.

The Cameras page automatically follows connected devices. New UVC candidates
appear from the daemon's passive connection monitor, and disconnected choices
are removed. When the page is open and idle, a changed inventory triggers a
camera-role inspection; that inspection can open device nodes to identify RGB
and infrared endpoints. It does not repeatedly run capture qualification.
Inspection failure is shown separately from an empty device list. Selection
follows device identity, and a connection change invalidates an open camera
switch confirmation rather than silently choosing a replacement.

During enrollment, click **Cancel enrollment** or press Esc to request cancellation.
For a general daemon task, the **quit** control exits the TUI and explicitly says
the task keeps running. Other page controls stay inactive during these operations.

An action's start describes a request, not confirmed success. Cancellation is
reported as requested until an outcome is known. A worker that ends without a
result no longer leaves the interface permanently busy: Activity explains the
unknown outcome or stale observation. Refresh status before retrying a mutation.

## Appearance and accessibility

Sections use blank rows and clear headings to separate related settings. Labels,
values and controls have visible spacing; long explanations wrap inside scrollable
panels. Supported narrow layouts (at least 80×24) keep navigation and dialog controls accessible.

State badges combine text and symbols: green **ON**, neutral **OFF**, and amber
**UNKNOWN**. Red is reserved for errors and adverse states; switching an optional
setting off is not inherently an error. Selection and keyboard focus remain
visible independently of color. The palette follows the terminal's colors
without assuming that truecolor means a dark background.

Set `NO_COLOR=1` to disable color, or `IRLUME_REDUCE_MOTION=1` to use static
activity marks. Keyboard shortcuts remain available with mouse capture released.

## Preferences

Preferences shows **ON**, **OFF**, or **UNKNOWN** for experimental IR-only,
hands-free privileged face authentication, and the biopolicy gate. State is
read from the daemon in the background, so a normal user can inspect root-only
settings without running the entire TUI as root. A disconnected or older daemon
is explicitly labeled; any available local observation is not a confirmed
daemon state. Environment overrides are identified and block misleading toggles.

Click an action or use its key:

- **i** switches IR-only on or restores dual-camera authentication. Enabling
  experimental IR-only requires the displayed warning to be accepted.
- **r** checks IR-only prerequisites for the account shown in the header,
  without opening a camera. Enabled policy and readiness are separate facts.
- **p** switches hands-free privileged authentication on or restores required
  confirmation. Enabling hands-free explains its scope and asks first.
- **b** switches the biopolicy operation-class gate on or off.

Administrator approval is requested by the action itself. State refreshes after
it returns, including after a failed command. An unknown observation never
chooses a toggle direction. Login/app wiring and fingerprint enable/disable
controls remain in their dedicated sections.

F2 includes sensor status, readiness, privileged confirmation status, face retry
status, password-verified retry reset, and a separately labeled administrator
retry reset. Password Wallet's Reseal uses the same seal-type handling as the CLI.
Forget uses the safe password-rekey flow for token or unknown seals; it refuses
an unsuccessful inspection. Force-forget remains a separate, explicitly warned
action. No command needs to be typed for these workflows.

## Diagnostics

Select a check with the mouse or arrow keys to read its full, wrapped diagnosis.
The details panel adapts to terminal height and scrolls with the mouse wheel;
changing the selection returns to the start of the explanation. Passed,
warning, failed and unknown checks are counted separately. Pending system
checks are labeled, and an unavailable automatic fix does not imply a pass.

**Fix Selected Issue** (`f`) starts the appropriate existing workflow. A daemon
that is loading models or denying this account access is not offered a restart
from the Cameras row. Access-denied inspection opens the read-only SELinux
status action. Fingerprint-only wiring repair preserves the selected method.
Wallet connection and PCR resealing open Password Wallet's guided flows.
Missing template keys offer Recovery Restore when a recovery backup is present;
without a backup, the diagnosis explains the need to re-enroll. The CLI's
status, recovery status and Doctor use the same recovery distinction, and
Doctor reports a missing template key as a failed check.

Physical actions such as opening a privacy shutter or changing firmware settings
remain instructions. Recheck, Full Diagnostics, logs, support reports and explicit
camera tests remain available. The default support report does not capture
camera data; an IR test or camera probe still requires an explicit action.

## Several people on one account

A profile represents one person. An account supports up to **three people**;
any enrolled person can authenticate as that account. Scans represent that
person's appearances or conditions, such as glasses or different lighting.
Use **Improve Recognition** (`a`) on that person's profile to add scans.
The current limit is 30 scans per profile for each recognizer.

**Enroll Face** (`e`) also handles a face that is already enrolled:

1. Enter a name to use if this is a new person, or leave it blank for an
   automatic name. A supplied name must be unused.
2. Follow the framing guide and initial countdown, then approve the system
   authorization prompt once for the whole capture operation. Enrollment collects
   10 scans; Improve Recognition collects 5, subject to the profile's available room.
3. Watch the continuous scan progress. Quality, liveness and identity checks still
   apply to each capture; only the initial framing guide and countdown are repeated
   when starting a new operation.
4. If the capture matches an existing profile, the TUI names it and asks
   whether to improve recognition instead of creating another profile. Yes keeps
   the pending probe and captures the remaining scans. Cancel discards the pending
   scans. Nothing is saved while this confirmation is open. A target discovered
   only after later captures also requires confirmation before saving.
5. If the face does not match an existing profile, enrollment creates a new
   profile, provided a person slot is available. At three profiles, an existing
   person can still take the improvement route; a fourth person is refused.

The framing guide keeps the RGB camera open through its initial checks and
countdown. It loads the account's calibration once and requests a new report
for each check. Framing ends after one minute if you have not completed the
guide; start again when ready. Cancelling releases the camera, and login
requests can interrupt the guide. After interruption, start a new operation.

The camera is released before the system authorization prompt. The authorized
capture operation then uses one connection and has a bounded duration. A merge
prompt expires after 60 seconds. Cancellation or interruption before the final
save discards the pending batch. A connection lost after the save can hide the
success reply; refresh the profile list before starting again.

During an upgrade, an older daemon may reject the new guided request. The TUI
then warns and uses its older per-scan flow. That flow repeats approval/countdown
and saves the first matching scan before confirmation; Cancel attempts to remove
it, and abrupt termination can leave it saved. Update and restart the daemon to
use the bounded guided flow.

If only the framing-session request is unsupported, the TUI uses individual
framing checks, with the same cues and countdown. Update and restart the daemon
to use the continuous framing session. A failure after a session starts stops
the operation; it does not silently switch to the older flow.

Use F2 for custom scan counts or **Replace face enrollment**. Replacement
replaces all profiles for the account after successful capture, so it is a
different task from improving one person's recognition. The review screen
explains the scope before it runs.

The daemon rejects added scans that match a different enrolled profile.
This is a check against known profiles, not a guarantee that every unrecognized
person will be classified correctly. Only the intended person should be in
view during an enrollment or improvement session.

Selection follows a profile and scan by name when the list refreshes. If that
item disappears or is renamed elsewhere, selection clears until you choose a
row again. Mouse selection follows the visible rows even in long, scrolled
scan lists. Rename and Delete confirmations name their exact target.

## CLI and TUI parity

| CLI task | TUI route |
|---|---|
| `setup`, `status`, `detect` | Overview, guided setup and Diagnostics |
| `doctor`, `diag` | Diagnostics: Full Diagnostics and TPM Diagnostics |
| `deps`, `version` | F2: runtime dependencies and version |
| `enroll` | Faces: Enroll Face (`e`); matching faces offer improvement |
| `enroll --scans`, `enroll --reset` | F2: chosen scan count or Replace face enrollment |
| `profiles list` | Faces; F2 lists full recognizer tags |
| `profiles add-scan` | Faces: Improve Recognition (`a`); F2 accepts a chosen scan count |
| `profiles rename`, `profiles delete` | Faces: select profile/scan, then Rename/Delete; F2 also works without camera navigation |
| `profiles forget-model`, `profiles eyes-open off` | F2: remove recognizer scans or clear the legacy blocker |
| `identify` | Overview / Test Recognition |
| `auth consent status/required/hands-free` | Preferences (`p`); F2 status |
| `auth sensor status/dual/ir-only` | Preferences (`i`); F2 status |
| `auth sensor preflight [--user U]` | Preferences (`r`); F2 readiness for the selected account |
| `retry status/reset`, administrator `retry reset` | F2: status, password-verified reset or administrator reset |
| `auth test` | F2: Test authentication for this account; JSON `granted` is the verdict |
| `keyring arm/status/forget`, `reseal` | Password Wallet |
| `keyring forget --force` | F2: Forget wallet secret without rekeying; review the consequence carefully |
| `recovery status/setup/restore/forget` | Recovery; F2 also works with the camera disconnected |
| `fingerprint status/add/verify/reset/enable/disable` | Fingerprint |
| `fingerprint enable --fingerprint-only` | F2: Enable fingerprint-only login |
| `login status/enable/disable` | Login & Apps |
| `login enable --with-sudo/--with-polkit` | Login & Apps; F2 can apply both together |
| `login reconcile` | Diagnostics repair or F2: Reconcile login wiring |
| login preview and `login plan/apply/verify/rollback` | F2: preview, prepared transaction, verification and rollback |
| `bitwarden status/setup` | Login & Apps: app unlock |
| `biopolicy` | Preferences |
| `logs`, `logs --since`, `logs -f` | Diagnostics: Show Logs; F2: history window or live follow |
| `logs debug on/off` | Diagnostics: Toggle Debug Logs (`t`) |
| `trace record` | Diagnostics: Record Trace (`T`); F2 accepts duration/output |
| `trace explain` | F2: Explain a recorded trace |
| `support-report` | Diagnostics: Create Support Report (`s`); F2 accepts output/history |
| `support-report --probe` | F2: report with camera probe, with explicit review |
| `camera census`, `camera diagnostics --json`, `camera-mode` | F2: all devices, diagnostics or full qualification; Cameras shows the active summary |
| `set-cameras`, `ir-setup`, `ir-setup --dry-run` | Cameras: select pair, Set Up Emitter, List Units |
| `camera-tune` | Cameras: Tune Capture; F2 accepts a chosen round count |
| `selftest liveness` | Diagnostics: Test Infrared Camera |
| `selinux status/load` | Diagnostics repair; F2 shows full SELinux status |
| `update`, `update --check` | Overview: Update; F2: Check for updates |
| `uninstall`, `uninstall --keep-data` | Overview: Uninstall; F2: uninstall while retaining enrollment data |

JSON contract negotiation and event framing are automation formats, rather
than separate end-user tasks. Where an operation is machine-only, More actions
displays that output in the terminal. Developer tools gated by `IRLUME_DEV=1`
remain CLI-only: they include direct camera access and raw research outputs
and are outside the normal operator interface.

The standalone authentication test does not exercise PAM or polkit. A
successful command exit also does not imply its diagnostic verdict passed;
read the reported verdict. A face failure followed by a successful password
is password approval, even when the overall system operation succeeds.

### IR compatibility in Faces

Each profile shows IR compatibility for the recognizer currently loaded by
the daemon. Missing, unknown and incompatible IR scans are listed separately.
Use **[a] Improve Recognition** on that profile with an IR camera to add fresh
IR coverage; existing scans remain. The CLI shows the same explanation in
`irlume profiles list`, with a command targeting the selected account/profile.

A paused-calibration message means unknown IR scans still prevent use of that
profile's stored calibration. Compatible IR scans can still match without it;
adding scans alone does not remove the restriction while unknown scans remain.
Older daemons show “not reported”, not an empty or broken IR enrollment. These
counts describe templates and do not certify camera or authentication readiness.
