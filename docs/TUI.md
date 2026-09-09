# TUI and CLI workflows

Run `irlume tui` as your account. `--user ACCOUNT` selects the same account as
the CLI; managing another account still requires the existing administrator
permissions. Read the account name in the header before making changes.

Tab and arrow keys navigate, Enter activates the selected item, and `?` shows
this screen's shortcuts. `v` reveals technical sections. **F2 opens More actions**
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
