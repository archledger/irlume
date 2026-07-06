# Setting up irlume

You've installed irlume (see the [README](../README.md#-install) for `dnf` /
`apt` / `pacman`). This guide takes you from there to a working face login.

The package **starts the `irlumed` daemon for you** — nothing else is running or
wired yet, and nothing touches your login until you ask. Two ways to set up:

- **[Guided (TUI)](#guided-setup-tui)** — one screen walks you through it.
- **[Manual (CLI)](#manual-setup-cli)** — the individual commands, scriptable.

Both do the same thing. The password is always the fallback; no step can lock
you out.

---

## Guided setup (TUI)

```sh
irlume tui
```

The TUI opens on a six-step wizard — **Welcome → Profiles → Keyring → Recovery →
Login wiring → Done**. `Tab` moves forward, `⇧Tab` back, `[v]` reveals the
advanced tabs (Cameras, Identify, Settings), and each screen shows its own keys
in the footer.

1. **Welcome** — press `[e]` to enroll right away, or `Tab` to walk the steps.
2. **Profiles** — `[e]` enrolls a face. Look at the camera; it guides your
   framing and captures three scans automatically. Wear glasses sometimes?
   Enroll a second profile for that look.
3. **Keyring** *(IR camera + TPM)* — arm TPM keyring unlock so a face login
   opens your wallet with no prompt. You'll enter your login password once; it
   is sealed in the TPM, never stored in plaintext.
4. **Recovery** — set a recovery passphrase so you can restore your templates
   after a TPM clear or firmware update without re-enrolling.
5. **Login wiring** — press `[w]` to wire the **greeter and lock screen**
   (runs `sudo irlume login enable --apply`). Face-`sudo` is opt-in and *not*
   included by `[w]` — see [face-sudo](#face-sudo-optional) below.
6. **Done** — a dashboard of everything's state. If anything failed, the
   **Repair** tab appears with one-key fixes.

That's it. Skip to [Verify](#verify) to confirm, or read on for the manual
equivalents.

---

## Manual setup (CLI)

Default user is `$USER`; add `--user NAME` to any command to target another.

### 1. Confirm the daemon is up

```sh
irlume status
```

On a fresh install it shows what still needs doing:

```
irlume status for 'you'
  daemon        : running ✅
  auth method   : Auto
  enrollment    : none ⚠ (run `irlume enroll`)
  keyring unlock: not armed (run `irlume keyring arm`)
  templates     : plaintext ⚠ (run `irlume recovery setup`)
  recovery pass : not set ⚠
  cameras       : rgb=/dev/video0 ir=/dev/video2
```

`irlume doctor` gives the deeper platform/TPM/Secure-Boot/camera/model report;
`irlume detect` is a script-friendly probe (exit 0 = ready, 10 = partial,
20 = absent).

### 2. Enroll your face

```sh
irlume enroll
```

Look at the camera. It captures three scans and saves a profile:

```
[enroll] 'you' — capturing a new face profile; stay in frame, look at the camera…
[enroll] enrolled 'Face Profile 1' with 3 scans
```

Options: `--name "Glasses"` names the profile, `--scans K` sets the scan count,
`--reset` wipes existing profiles first. Enroll a second named profile for a
different look (glasses on/off). On a machine with a TPM, the templates are now
**encrypted at rest** automatically.

Confirm the match:

```sh
irlume identify
# [identify] you (profile 'Face Profile 1', score 0.906) ✅
irlume profiles list
```

### 3. Wire the login screen

```sh
sudo irlume login enable --apply
```

This wires the **greeter and lock screen** for your login manager (GDM, SDDM,
Plasma). Without `--apply` it's a dry run that prints the plan and writes
nothing.

```
  login manager: plasmalogin   ·   method: auto   ·   IR/Secure tier
  plan → face login: on   face lock: on   fingerprint keyring: —
  ✓ /etc/pam.d/plasmalogin — materialized override from /usr/lib/pam.d/plasmalogin
  ✓ /etc/pam.d/kde-fingerprint — wired (backup /etc/pam.d/kde-fingerprint.pre-irlume)
[login] done. Password remains the fallback everywhere.
```

### 4. (Optional) Keyring unlock

So a face login opens GNOME Keyring / KWallet with no separate prompt:

```sh
irlume keyring arm
```

It prompts once for your **login password**, which it seals in the TPM (never
stored in plaintext). Re-run it after you change your login password.

### 5. (Optional) Recovery passphrase

A backstop that restores your templates after a TPM clear, firmware/dbx update,
or disk move — without re-enrolling:

```sh
irlume recovery setup
```

It prompts for a passphrase separate from your login password. Store it
somewhere safe (like a disk-encryption recovery key).

---

## face-sudo (optional)

`login enable` and the TUI's `[w]` deliberately wire only the greeter and lock
screen. Granting **root by face** is a trade-off worth choosing on purpose, so
`sudo` is separate:

```sh
sudo irlume login enable --with-sudo --apply
```

The password still works for `sudo` too — face is `sufficient`, not required.
Test it in a fresh terminal with `sudo -k` (clear the cached credential) then
`sudo true`.

## Fingerprint companion (optional)

On a laptop with a fingerprint reader, add it as a second factor:

```sh
irlume fingerprint status
irlume fingerprint add           # enroll a finger via fprintd
sudo irlume fingerprint enable   # make fingerprint the method (face stands down)
```

## IR emitter (rarely needed)

Enrollment auto-enables the 850 nm emitter if the IR frames come back dark, so
there's normally nothing to do. Only if IR stays dark after enrolling:

```sh
sudo irlume ir-setup
```

(IR cameras only; on an RGB webcam it exits without touching anything.)

---

## Verify

```sh
irlume status
```

A fully set-up secure-tier machine reads:

```
  daemon        : running ✅
  enrollment    : 1 profile(s), 3 scan(s) ✅
  keyring unlock: armed ✅
  templates     : encrypted at rest ✅
  recovery pass : set ✅
  cameras       : rgb=/dev/video0 ir=/dev/video2
```

Then lock your screen (or open a fresh `sudo` if you wired it) and look at the
camera. Want to check the anti-spoofing and other claims for yourself? See
[VERIFY.md](VERIFY.md).

## Undo everything

```sh
sudo irlume login disable --apply
```

Removes every PAM change (greeter, lock, and `sudo`) and restores the originals.
Your password login is never touched. To remove just face-`sudo` while keeping
the greeter, re-run `login enable --apply` *without* `--with-sudo`.
