# Turning irlume off

Three levels of off, in order of how much they remove: stop face on some
surfaces, stop face everywhere, or remove irlume entirely. The password is
always the floor underneath every one of these: PAM face lines are
`sufficient` or `[success=1 default=ignore]`, so unwiring them can only take
the shortcut away, never the login. Nothing on this page can lock you out.

## See what is wired first

```sh
irlume login status
```

A dry run prints exactly what a change would touch without writing anything:

```sh
sudo irlume login disable        # no --apply: plan only
```

The surfaces irlume can wire, and what puts each in scope:

| Surface | PAM service | Scope |
|---|---|---|
| Login greeter (GNOME, SDDM, LightDM, Plasma, COSMIC, greetd, ly) | `gdm-password`, `sddm`, `lightdm`, `plasmalogin`, `cosmic-greeter`, `greetd`, `ly` | default |
| Lock screen (KDE) | `kde` | default |
| Fingerprint keyring handoff (GDM) | `gdm-fingerprint` | default, where present |
| Terminal privilege (`sudo`) | `sudo` | opt-in `--with-sudo` |
| App consent prompts (pkexec, Bitwarden) | `polkit-1` | opt-in `--with-polkit` |

Real `/etc/pam.d` files are backed up to `*.pre-irlume` before editing;
vendor-owned files (plasmalogin, kde, polkit-1 on Fedora) get an `/etc`
override materialized from the vendor copy. Both revert cleanly.

## Stop face everywhere

```sh
sudo irlume login disable --apply
```

This unwires every greeter and the lock screen, and removes the `sudo` and
`polkit-1` lines whether or not you opted in originally. It also:

- restores the original stacks (moves the `.pre-irlume` backup back, or
  deletes the `/etc` override so the vendor file shows through again),
- removes the SELinux module on Fedora (`semodule -r irlume`, checked: a
  failure is reported, not papered over),
- clears the self-heal marker, so the reconcile unit stops re-wiring after
  distro PAM updates.

Enrollment data and the daemon stay in place; re-enabling later is one
command and no re-enrollment.

## Keep some surfaces

Turn everything off, then re-add only what you want:

```sh
sudo irlume login enable --apply                 # greeter + lock screen only
sudo irlume login enable --with-sudo --apply     # add face-sudo back
sudo irlume login enable --with-polkit --apply   # add app prompts back
```

On RGB-only cameras (no IR pair), face already satisfies the lock screen
only; greeter and `sudo` keep the password regardless of wiring.

## Stand face down without touching PAM

To leave the wiring intact but have the daemon refuse face so another factor
drives:

```sh
sudo irlume fingerprint enable --fingerprint-only
```

This records method `fingerprint`, and irlume's face recognition stands down.
The command refuses unless an active `pam_fprintd.so` line is reachable from
a tracked surface, so face never goes quiet while every prompt is actually
password-only. To put face back:

```sh
sudo irlume fingerprint disable
```

## Canceling a scan that already started

- **Type instead of confirming face.** With privileged confirmation enabled,
  where irlume asks, typing picks the
  password path before the camera powers up: probing greeters (SDDM,
  plasmalogin style, COSMIC's on-demand mode) treat any typed characters as
  "password", and privileged prompts (`sudo`, polkit) treat anything other
  than the literal `yes` as "password". GNOME wires its greeter face-first
  (the camera checks once your account is selected), so there the way out is
  canceling or escaping the dialog; a typed password still wins afterwards.
- **Desktop cancellation depends on the frontend.** Stock KDE installations do
  not automatically provide a parallel face lane that stops on typing. The
  development frontend integration is not enabled by this package; see
  [desktop authentication boundaries](DESKTOP-AUTH.md).
- **Close or cancel whatever asked.** Escape, a dialog's Cancel button, or
  Ctrl+C can end the request when the frontend closes its PAM worker or socket.
  Merely returning a cancellation error from a synchronous PAM conversation
  does not interrupt a daemon request already in progress. The daemon checks
  disconnects cooperatively; physical camera release also depends on the active
  capture operation. There is no universal quarter-second stop guarantee.
- **In `irlume tui`:** Esc cancels guided enrollment immediately; q or Esc
  backs out of a stalled identify or self-test instead of trapping you.
- **If you just wait:** every scan window is bounded. The login/lock screen
  keeps looking for about 15 seconds (~10 attempts), `sudo` and `su` give up
  after about 5 seconds, then the password takes over. `IRLUME_GRACE_MS`
  overrides this if you want shorter.

Face verification and face-gated credential release share a durable limit of
50 consecutive unsuccessful requests per account. Each request reserves one
charge before engine work; its internal presence retries, grouped capture and
fallbacks share that reservation. At 50, face stands down until independently
verified password recovery or an explicit administrator reset. Ordinary password
login remains available. A successfully admitted and completely written face
grant resets the count, so successful everyday unlocks do not exhaust it.

Cancellation, errors, interrupted requests and completed no-face/setup outcomes
retain their cumulative charge. No cumulative neutral refund is made. Separately,
the short throttle defaults to five strikes followed by a 30-second camera rest.
No-face and uncertain-evidence outcomes do not consume short strikes; hard spoof
and below-threshold rejections do. An abandoned reservation conservatively adds
one short strike when it is next observed.
Missing or empty enrollment, scans belonging only to a different recognition
model, a retired eyes-open setting, and invalid or retired consent settings end
the request without adding or clearing strikes. Fixing those
settings does not erase earlier face rejections or cancel an active cooldown.
Camera-binding refusals, PAD failures and grouped
capture timeouts retain their existing strike behavior.

A cooldown expiry clears only the short throttle, never the cumulative budget.
Both survive daemon restarts; profiles, modes and PAM services for one Linux
account share them. Ordinary password login does not send a reset event; use
`irlume retry reset` when face is blocked.

### Persistent retry records

The daemon stores version-2 records in `/var/lib/irlume/retry/<uid>.json`.
The directory is root-owned mode 0700; files are root-owned mode 0600. A record
contains the account UID/name, short strikes, cumulative count, pending request
flag, and an optional monotonic
clock deadline, boot identifier and original cooldown duration. It contains no
biometric data or credentials. The retry location is fixed; enrollment path
overrides do not redirect it. The explicit `irlume retry reset` command can reset
these records after independently verifying the account password, as described
below; ordinary password login does not notify the counter.

A daemon restart in the same boot keeps the original deadline. Civil-clock
changes do not affect it. After reboot, partial failures remain and a recorded
cooldown starts again for its original duration; this can extend the wait.
`IRLUME_RATE_LIMIT` accepts 1–5; `IRLUME_RATE_COOLDOWN_SECS` accepts 30–86400.
Invalid values, including zero, use safe defaults (5 and 30 respectively) with a
fixed diagnostic. These settings cannot disable or increase the cumulative limit.

The first reservation starts an explicitly prospective epoch for a missing or
strictly valid version-1 record, preserving its short strikes/cooldown. Earlier
cycles cannot be reconstructed and are not counted or presented as known.
Status does not migrate records; it distinguishes unknown legacy history from a
known zero count. Existing malformed, oversized,
unreadable, wrongly owned or unsafe records refuse the face path with a password
fallback message. UID/name mismatches also refuse: a reused UID or renamed
account must be reconciled by an administrator. No engine work starts until its
reservation is durably committed. The daemon holds the account lock through
response delivery and clears a successful request only after final admission and
successful write/flush. A crash after delivery but before reset can conservatively
retain a charge. A failed reset after delivery cannot retract the grant; the next
operation re-reads and synchronizes authoritative disk state. Admission checks
the original window immediately before the first byte and bounds the write
timeout to remaining time where possible; partially written bytes cannot be
retracted if cancellation or expiry arrives during the write.

For repair, use password authentication and inspect `journalctl -u irlumed`.
Stop `irlumed.socket` and `irlumed.service` while correcting the affected
record's ownership, permissions,
account binding or malformed content; preserve the count and deadline whenever
they can be established. Inspect the exact UID with `id -u <account>` and do not
follow symlinks or change other users' records. Removing the affected record is
an explicit root reset of its history; do so only if the administrator intends
that reset, then start the socket and daemon. Corrected state is re-read automatically.
Version-1-only daemons refuse version-2 records; older daemons without persistent
retry support do not enforce this limit. Do not delete records or restore older,
smaller counts as part of a binary rollback.

Write-ahead charges survive crashes and reboot, but cannot resist root deletion
or disk rollback. Fifty bounds requested composite authentication decisions, not
individual frames/comparisons or a qualified false-accept probability. The
independent reset-password budget below also reserves before verification.

### Password-verified retry reset

```sh
irlume retry status
irlume retry reset
sudo irlume retry reset --user <account>   # explicit administrator override
```

`status` inspects face and reset-password counters without requesting a camera
or password. `reset` probes daemon support and the recovery gate before asking
for the current login password without terminal echo. Non-root requests are
limited to the caller's own account. Successful independent password verification
clears the face retry record and the reset-password budget; it does not change
the login password, enrollment, template key, or consent settings. A root reset
is an explicit administrative action and does not ask for the account password.
Malformed or unsafe records still require the repair procedure above.

A reset commits the face state first, then clears the reset-password budget.
Interruption or a storage failure between these writes can clear face history
while retaining a conservative password-check charge. If the command cannot
confirm the reset, run `irlume retry status` before trying again.

This path requires an updated daemon and the packaged root-only password verifier
with its fixed `irlume-retry-reset` PAM service. The initial backend is local
Linux passwords through `pam_unix`; LDAP, SSSD and systemd-homed accounts are not
qualified. Self-service reset is unavailable under enforcing AppArmor in this
release. Keep normal password login available and ask an administrator when
status reports reset unavailable. An older daemon is refused before prompting;
updating the client alone does not add recovery support.

Reset-password guessing has its own persistent record at
`/var/lib/irlume/retry/<uid>.reset.json`, with the same private ownership and
permissions as face records. After five failed checks, each further check needs
a 30-second wait; the wait never erases failures. At 50 failed checks, an
administrator must reset the budget. A verification attempt is charged durably
before the helper runs, so interruption or unknown completion also consumes an
attempt. This budget survives daemon restarts; reboot can restart its recorded
cooldown. None of these limits block ordinary password login or introduce a
cumulative ceiling for face authentication.

`irlume recovery restore` is separate: it uses the recovery passphrase to restore
the template key and never clears retry counters. A desktop/polkit approval or
an already open keyring also does not satisfy password verification for retry
reset. Keep both face and reset-password records when rolling back binaries;
older daemons do not offer this reset path or enforce the reset-password budget.

## Remove everything

```sh
sudo irlume uninstall            # add --keep-data to preserve enrollment
```

The teardown runs in the only safe order: un-wire PAM first (so no line can
reference a module that is about to vanish), stop and disable the daemon,
disarm every user's TPM keyring seal, then wipe templates, sealed secrets,
third-party models, and config (unless `--keep-data`). After it finishes,
remove the package through your manager, which also stops the daemon and
reconcile units:

```sh
sudo dnf remove irlume     # Fedora / Copr
sudo pacman -R irlume      # Arch / AUR
sudo apt remove irlume     # Ubuntu / PPA
```

## Verify

After any change here, confirm with `irlume login status` (nothing should
list as wired), then lock and unlock the screen once with your password.
`irlume doctor` re-checks the PAM stacks and SELinux state if anything reads
odd. See [SETUP.md](SETUP.md) for the wiring walkthrough this page reverses,
and [DEBUGGING.md](DEBUGGING.md) if a login misbehaves after a change.
