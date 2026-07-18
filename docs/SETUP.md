# Setting up irlume

You've installed irlume (see the [README](../README.md#-install) for `dnf` /
`apt` / `pacman`). This guide takes you from there to a working face login.

The package **starts the `irlumed` daemon for you**; nothing else is running or
wired yet, and nothing touches your login until you ask. Two ways to set up:

- **[Guided (TUI)](#guided-setup-tui)**: one screen walks you through it.
- **[Manual (CLI)](#manual-setup-cli)**: the individual commands, scriptable.

Both do the same thing. The password is always the fallback; no step can lock
you out.

---

## Guided setup (TUI)

```sh
irlume tui
```

The TUI opens on a six-step wizard: **Welcome → Profiles → Keyring → Recovery →
Login wiring → Done**. `Tab` moves forward, `⇧Tab` back, `[v]` reveals the
advanced tabs (Cameras, Identify, Settings), and each screen shows its own keys
in the footer.

1. **Welcome**: press `[e]` to enroll right away, or `Tab` to walk the steps.
2. **Profiles**: `[e]` enrolls a face. Look at the camera; it guides your
   framing and captures three scans automatically. Wear glasses sometimes? Add
   a scan with Improve Recognition (`[a]`) while wearing them, on the same
   profile; a face can only own one profile.
3. **Keyring** *(recommended; IR camera + TPM)*: arm TPM keyring unlock so a
   face login opens your wallet with no prompt. You'll enter your login password
   once; it is sealed in the TPM, never stored in plaintext. Skip it and your
   wallet just prompts separately after login.
4. **Recovery** *(recommended)*: set a recovery passphrase. It restores your
   templates after a TPM clear or firmware update without re-enrolling; without
   it, such a change forces a full re-enroll.
5. **Login wiring**: press `[w]` to wire the **greeter and lock screen**
   (runs `sudo irlume login enable --apply`). Face-`sudo` is opt-in and *not*
   included by `[w]`; see [face-sudo](#face-sudo-optional) below.
6. **Done**: a dashboard of everything's state. If anything failed, the
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
  biopolicy     : off (default)
  cameras       : rgb=/dev/video0 ir=/dev/video2
  fingerprint   : none
```

`irlume doctor` gives the deeper platform/TPM/Secure-Boot/camera/model report;
`irlume detect` is a script-friendly probe (exit 0 = ready, 10 = partial,
20 = absent).

### 2. Enroll your face

```sh
irlume enroll
```

Look at the camera. It captures three scans and saves a profile:

<!-- mirrors the enroll output in crates/irlume-cli/src/main.rs; keep in sync -->
```
[enroll] 'you': capturing a new face profile; stay in frame, look at the camera…
[enroll] enrolled 'Face Profile 1' with 3 scans
```

Options: `--name "Alex"` names the profile, `--scans K` sets the scan count,
`--reset` wipes existing profiles first. Name a separate profile for a
*different person* you trust (up to three); for your own glasses/lighting
variants, add scans to your own profile instead. On a machine with a TPM, the
templates are now
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
Plasma, LightDM, greetd, COSMIC). Without `--apply` it's a dry run that prints
the plan and writes nothing.

<!-- mirrors the `login enable` plan output in crates/irlume-cli/src/pamwire.rs; keep in sync -->
```
  login manager: plasmalogin   ·   method: auto   ·   IR/Secure tier
  plan → face login: on   face lock: on   fingerprint keyring: off
  face trigger: on-demand; leave the password empty and press Enter to use your face
  ✓ /etc/pam.d/plasmalogin: materialized override from /usr/lib/pam.d/plasmalogin
  ✓ /etc/pam.d/kde-fingerprint: wired (backup /etc/pam.d/kde-fingerprint.pre-irlume)
[login] done. Password remains the fallback everywhere.
```

**How you log in:** face is **on-demand**. At the greeter (and lock screen),
leave the password field **empty and press Enter**; the camera fires only then,
never on its own. Typing a password never starts the camera, and the password
always works. The one exception is older GNOME greeters (Shell < 46), whose
greeter can't relay the empty-field probe; there the camera verifies as soon
as your account is selected (face-first). `irlume login status` shows which
mode each wired service uses.

### 4. Keyring unlock: recommended (IR camera + TPM)

This is what makes a face login open your GNOME Keyring / KWallet with no
separate prompt, the Windows-Hello-style experience. Skip it and face login
still works, but your wallet stays locked and prompts you for its password after
every login, which is half the point.

```sh
irlume keyring arm
```

It prompts for your **login password** (typed twice, to catch a typo), which it
seals in the TPM; the password is never stored in plaintext. Re-run it after you change your
login password. On a fingerprint machine a fingerprint login unseals the wallet
the same way (see [ADR-0003](adr/0003-fingerprint-keyring-unlock.md)).

### 5. Recovery passphrase: recommended

Set this. It's your backstop: without it, a TPM clear or a routine
firmware/dbx/Secure-Boot update can invalidate the TPM-sealed key and force you
to **re-enroll from scratch**. With it, you restore in seconds. That's why
`irlume status` flags `recovery pass: not set ⚠` until you do.

```sh
irlume recovery setup
```

It prompts for a passphrase separate from your login password. Store it
somewhere safe (like a disk-encryption recovery key).

---

## face-sudo (optional)

`login enable` and the TUI's `[w]` deliberately wire only the greeter and lock
screen. Granting **root by face** is its own decision, so `sudo` is
separate:

```sh
sudo irlume login enable --with-sudo --apply
```

The password still works for `sudo` too; face is `sufficient`, not required.
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

## Optional third-party liveness models

irlume's anti-spoof gate is algorithmic by default. `irlume models` lists
externally-trained models irlume can fetch onto your machine as an extra,
deny-only liveness cue: one that can reject a presentation but can never
approve one the built-in gate rejected. These models carry a real license on
their weights but fail the shipped-stack provenance bar (ADR-0001), so irlume
does not ship or mirror them; enabling downloads them once from the publisher,
pinned by checksum, after you confirm the license and provenance on screen.
Each catalog entry was measured on real hardware first
([docs/pad-results/](pad-results/)).

```sh
irlume models                     # what exists, what it measured, what's enabled
sudo irlume models enable flir    # fetch + verify + enable (typed confirmation)
sudo irlume models disable        # delete the weights, back to the shipped stack
```

`irlume doctor` names the enabled model; the daemon refuses weights whose
checksum stops matching and falls back to the built-in gate alone.

---

## Configuration reference

Nothing here is required for a normal install; the TUI and the setup flow
write these files for you. They exist so a headless or scripted setup can do
the same thing, and so you know what state irlume keeps where.

### Files

All are root-owned `key=value` files (`#` comments allowed). Secrets never
live in them; sealed envelopes are stored separately (see
[SECURITY_AT_REST.md](SECURITY_AT_REST.md)).

| File | Holds | Written by |
|---|---|---|
| `/etc/irlume/settings.conf` | `enforce_biopolicy=1` opts into operation-class gating; `third_party_pad=<name>` names an enabled opt-in model | TUI Settings; `sudo irlume models enable/disable` |
| `/etc/irlume/cameras.conf` | `rgb=` / `ir=` device nodes of the active camera pair | TUI camera picker, or `sudo irlume set-cameras <rgb> <ir>` |
| `/etc/irlume/method` | one line: the active auth method | `irlume fingerprint enable/disable` |
| `/var/lib/irlume/ir_emitter.conf` | the UVC extension-unit control that lights the emitter (optional second line: a brightness-boost control) | `irlume ir-setup` / enrollment auto-setup |

Camera selection precedence: the `IRLUME_RGB_DEVICE`+`IRLUME_IR_DEVICE` env
pair (both set), then `cameras.conf`, then auto-detection, then the compiled
defaults (`/dev/video0`+`/dev/video2`).

### Daemon environment variables

Set these on the service, not in a shell (`sudo systemctl edit irlumed`, then
`Environment=` lines in the drop-in).

| Variable | Effect | Default |
|---|---|---|
| `IRLUME_MODELS_STRICT` | refuse to start when a model file is missing or fails the checksum manifest, instead of warning | warn and continue |
| `IRLUME_ENFORCE_BIOPOLICY` | same switch as `enforce_biopolicy` in `settings.conf`; the env var wins | off |
| `IRLUME_DET_MODEL` / `IRLUME_MODEL` / `IRLUME_MESH_MODEL` / `IRLUME_BLAZE_MODEL` | paths to the detector / recognizer / FaceMesh / BlazeFace weights | `/etc/irlume/*.onnx` |
| `IRLUME_IR_ADAPTER` | path to an optional IR-adapter model (none ships; see ADR-0004) | `/etc/irlume/ir_adapter.onnx` |
| `IRLUME_RGB_DEVICE` / `IRLUME_IR_DEVICE` | camera-pair override; both must be set | auto |
| `IRLUME_IR_EMITTER` | emitter control override: `off`, or `unit:selector:b,b,..` (decimal or `0x` hex bytes); bypasses `ir_emitter.conf` | conf, else known-module table |
| `IRLUME_IR_EMITTER_CONF` | alternate path for `ir_emitter.conf` | `/var/lib/irlume/ir_emitter.conf` |
| `IRLUME_RGB_MOIRE_MAX` | per-camera ceiling for the screen-replay moiré cue | 28 |
| `IRLUME_IR_AMBIENT_SUBTRACT` | `1` enables experimental lit-minus-ambient IR subtraction; changes the IR frames the matcher sees, so re-enroll after toggling (see [ARCHITECTURE.md](ARCHITECTURE.md)) | off |
| `IRLUME_TCTI` | TPM transport | `device:/dev/tpmrm0` |
| `IRLUME_PCRS` | comma-separated PCR list the sealed password binds to | `7` |
| `IRLUME_SRK_HANDLE` | persistent SRK handle (hex), if the default collides with another TPM user | `0x81010002` |
| `IRLUME_METHOD_CONF` | alternate path for the method file | `/etc/irlume/method` |

Liveness-cue tuning knobs (blink thresholds, IR capture debug) are in
[DEBUGGING.md](DEBUGGING.md); development sandbox overrides (state/config/socket
paths) are in [DEVELOPMENT.md](DEVELOPMENT.md).

---

## Verify

```sh
irlume status
```

A fully set-up secure-tier machine reads:

```
irlume status for 'you'
  daemon        : running ✅
  auth method   : Auto
  enrollment    : 1 profile(s), 3 scan(s) ✅
                  - Face Profile 1 (3 scan(s))
  keyring unlock: armed ✅
  templates     : encrypted at rest ✅
  recovery pass : set ✅
  biopolicy     : off (default)
  cameras       : rgb=/dev/video0 ir=/dev/video2
  fingerprint   : none
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
