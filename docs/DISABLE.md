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

- **Type instead of confirming face.** Where irlume asks, typing picks the
  password path before the camera powers up: probing greeters (SDDM,
  plasmalogin style, COSMIC's on-demand mode) treat any typed characters as
  "password", and privileged prompts (`sudo`, polkit) treat anything other
  than the literal `yes` as "password". GNOME wires its greeter face-first
  (the camera checks once your account is selected), so there the way out is
  canceling or escaping the dialog; a typed password still wins afterwards.
- **Press a key at the KDE lock screen.** KDE runs face as a parallel
  biometric device there and cancels it natively the moment you type.
- **Close or cancel whatever asked.** Escape on a greeter dialog, cancel on
  a polkit prompt, Ctrl+C at a terminal `sudo`: when the asking process hangs
  up its connection, the daemon notices within about a quarter second and
  stops the capture cooperatively. The camera does not keep scanning for a
  departed client.
- **In `irlume tui`:** Esc cancels guided enrollment immediately; q or Esc
  backs out of a stalled identify or self-test instead of trapping you.
- **If you just wait:** every scan window is bounded. The login/lock screen
  keeps looking for about 15 seconds (~10 attempts), `sudo` and `su` give up
  after about 5 seconds, then the password takes over. `IRLUME_GRACE_MS`
  overrides this if you want shorter.

There is no failed-scan lockout class: any miss falls to the password. After
repeated failures the camera itself rests while the password keeps working
(5 strikes by default, then a 30-second camera cooldown; `IRLUME_RATE_LIMIT`
and `IRLUME_RATE_COOLDOWN_SECS` adjust both).

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
