# Setting up irlume

You've installed irlume (see the [README](../README.md#install) for `dnf` /
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

The TUI opens as a settings app with stable, grouped navigation and an
**Overview** that shows live status plus the next recommended action. Use the
sidebar or click a status row to jump directly to a section; `Tab`/`⇧Tab` and
`←`/`→` move between sections without a mouse. `[v]` reveals technical tools
(Cameras and Test Recognition), `[A]` expands recent activity, and `[?]` shows
every action for the current section. Footer actions, selectable rows, and the
sidebar can all be clicked.

1. **Overview**: follow the recommended action, or open any status row.
2. **Faces**: `[e]` enrolls a face. Look at the camera; it guides your
   framing and captures ten scans automatically. Wear glasses sometimes? Add
   a scan with Improve Recognition (`[a]`) while wearing them, on the same
   profile; a face can only own one profile.
3. **Password Wallet** *(recommended; IR camera + TPM)*: connect TPM-backed
   wallet unlock so a
   face login opens your wallet with no prompt. You'll enter your login password
   once; it is sealed in the TPM, never stored in plaintext. Skip it and your
   wallet just prompts separately after login.
4. **Recovery** *(recommended)*: set a recovery passphrase. It restores your
   templates after a TPM clear or firmware update without re-enrolling; without
   it, such a change forces a full re-enroll.
5. **Login & Apps**: press `[w]` to connect irlume to the **greeter and lock screen**
   (runs `sudo irlume login enable --apply`). Face-`sudo` is opt-in and *not*
   included by `[w]`; see [face-sudo](#face-sudo-optional) below.
6. **Diagnostics**: review warnings or failures and apply focused fixes. Its
   navigation item remains available, with an issue count when attention is
   needed.

Set `IRLUME_REDUCE_MOTION=1` before launching to replace indeterminate spinners
with static activity marks. Determinate enrollment progress remains visible.

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

Look at the camera. It captures ten scans and saves a profile:

<!-- mirrors the enroll output in crates/irlume-cli/src/main.rs; keep in sync -->
```
[enroll] 'you': capturing a new face profile; stay in frame, look at the camera…
[enroll] enrolled 'Face Profile 1' with 10 scans
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

It prompts for your **login password** (typed twice, to catch a typo) and
verifies it is actually your login password before sealing it in the TPM, so a
mistyped password can't be sealed and leave the wallet failing to unlock; the
password is never stored in plaintext. Re-run it after you change your login
password. On a fingerprint machine a fingerprint login unseals the wallet the
same way (see [ADR-0003](adr/0003-fingerprint-keyring-unlock.md)).

#### KDE Plasma: what has to be in place for KWallet

On Plasma the chain is: `plasmalogin` runs irlume's `unseal` line, which sets the
released password as `PAM_AUTHTOK`; `pam_kwallet5.so`'s **auth** line reads that
token and stashes the derived key; its **session** line starts the wallet daemon
(`ksecretd` on Plasma 6, `kwalletd6`/`kwalletd5` before it) and hands the key
over. Both halves are required: kwallet-pam stashes with `pam_set_data` during
auth and only acts on it in `pam_sm_open_session`. irlume owns only the first
step, so two things must be true of the rest:

- **kwallet-pam is installed**: the module is `pam_kwallet5.so`, still that name
  under Plasma 6 (upstream's CMake sets `library_name "pam_kwallet5"` on the KF6
  branch). Fedora additionally lists a legacy `pam_kwallet.so`.
- **Its auth line sits BELOW irlume's**, with a session line for the *same*
  module. Above ours it runs before the token exists, and kwallet-pam then
  prompts for the password itself, which is exactly the "it asked me anyway"
  symptom.

`auto_start` on those lines is a *gnome-keyring* option; kwallet-pam parses only
`kdehome=`, `kwalletd=`, `socketPath=` and `force_run`, and ignores the rest. Its
session half also stands down outside a graphical session unless `force_run` is
given, which is why the greeter is the right place for this and a TTY login is
not.

`irlume login status` (and `login enable --apply`) checks both halves, paired per
module, and warns, so a wallet that still prompts after a face login names its
own cause instead of looking like a face-login failure:

```
  ⚠ /etc/pam.d/plasmalogin: face login releases your login password, but no keyring module
     reads it afterwards, so KWallet/the login keyring will still prompt.
```

Fedora, Arch and Debian all ship a `plasmalogin` with both halves present, so the
check stays quiet there. **openSUSE's upstream file carries no keyring module at
all**, so face login on stock openSUSE releases a password nothing reads; the
warning above is the expected output until `pam_kwallet5.so` is added to that
stack. Adding it needs both lines, for example:

```
-auth    optional    pam_kwallet5.so
-session optional    pam_kwallet5.so
```

placed after the `auth substack common-auth` line and in the session phase
respectively. (openSUSE's greeter is otherwise wired correctly: irlume anchors
its face line on that `common-auth` substack, leaving `pam_nologin.so` ahead of
it.)

One more requirement is outside PAM: your **wallet password must equal your login
password**, since that is the password `keyring arm` seals. A wallet created with
a different password cannot be opened on this path; change it under *System
Settings → KDE Wallet*, or remove and recreate the wallet.

**Fingerprint on KDE.** Plasma's login greeter runs ONE PAM stack for user
authentication: plasma-login-manager's PAM backend selects only `plasmalogin`
(plus `plasmalogin-greeter` for the greeter user and `plasmalogin-autologin`);
it has no separate fingerprint service, unlike kscreenlocker, which drives the
*lock screen* through the `kde` / `kde-fingerprint` / `kde-smartcard` triple.
So a fingerprint login at the KDE greeter happens when your distro's shared
stack carries `pam_fprintd.so` (that is what `irlume fingerprint enable` wires,
via authselect on Fedora or pam-auth-update on Debian), inside the same
`plasmalogin` transaction. A fingerprint provides no password, so irlume's
`keyring` line, wired into the greeter whenever a reader is present, releases
the TPM-sealed secret at the post-auth landing, and `pam_kwallet5.so`
below it opens the wallet: a cold-boot fingerprint login unlocks KWallet with
no prompt, same as face. The lock screen needs none of this: a warm unlock
meets a wallet the login already opened.

#### GNOME: what has to be in place for the login keyring

Same shape, different module. `gdm-password` runs irlume's `unseal` line, which
sets `PAM_AUTHTOK`; `pam_gnome_keyring.so`'s **auth** line reads it and stashes it
under `gkr_system_authtok`; its **session** line unlocks the keyring and starts
the daemon. Both halves are required, for the same reason as KWallet:
`pam_sm_authenticate` only stashes, and `pam_sm_open_session` is what acts.

Two differences from KDE are worth knowing:

- **`auto_start` is real here.** gnome-keyring parses it (`ARG_AUTO_START`) and
  needs it on the session line to start the daemon, the opposite of kwallet,
  which ignores the option entirely. Upstream GDM already ships
  `session optional pam_gnome_keyring.so auto_start`.
- **Failure is silent.** With no `PAM_AUTHTOK`, gnome-keyring's auth phase logs
  "no password is available for user" and returns success without prompting.
  kwallet prompts; gnome-keyring does not. So a mis-ordered line costs you
  nothing visible at the login screen; the keyring simply stays locked, and you
  only find out when an application asks for a secret. That is exactly the case
  `irlume login status` now names.
- **`only_if=` can switch it off per service.** A line such as
  `-auth optional pam_gnome_keyring.so only_if=gdm,gdm-password` does nothing at
  all on any other service; on `gdm-fingerprint`, for instance, it returns
  success without reading the token. irlume evaluates that list per service, so
  a line gated off for the stack being checked is not counted as unlocking
  anything. `pam_kwallet5.so` has no such option.

GDM's upstream `gdm-password.pam` ships both halves on every OS variant it
provides (Red Hat, Arch, LFS, Exherbo), so the check stays quiet on a stock
GNOME system.

**Fingerprint on GNOME.** GDM's `gdm-fingerprint.pam` names neither
`pam_fprintd.so` (it delegates to `auth substack fingerprint-auth`) nor any
keyring module. So the [ADR-0003](adr/0003-fingerprint-keyring-unlock.md)
fingerprint keyring unlock needs both an anchor that recognizes the substack and
a consumer to read the released password. `login enable` supplies both:

```
auth        substack      fingerprint-auth
auth       optional       pam_irlume.so keyring          ← releases the sealed secret
-auth      optional       pam_gnome_keyring.so           ← reads and stashes it
...
-session   optional       pam_gnome_keyring.so auto_start  ← unlocks, starts the daemon
```

The two `pam_gnome_keyring.so` lines are added **only** when the stack has no
keyring module of its own, and are tagged so `login disable` removes exactly
those and never a line your distro shipped. The leading `-` is PAM's "do not
complain if the module is missing", so a machine without gnome-keyring installed
is unaffected.

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
`sudo true`. PAM shows `Type yes to use face authentication` above the normal
hidden field. Type `yes` for one face attempt, or type the ordinary password
once for the password/fingerprint path. Empty Enter never starts the camera and
falls through to the password provider.

This confirmation is on by default and stays that way unless the machine's
owner turns it off. `privileged_face_consent=0` in `/etc/irlume/settings.conf`
(or `IRLUME_PRIVILEGED_FACE_CONSENT=0`) is the owner's waiver of that keyword:
the scan starts when the privileged PAM prompt appears, with no per-attempt
word. Do it only if you accept what follows: every
`sudo` opens the camera, including one typed by someone else at your machine
and one run from a script. Passive PAD still applies, and the password still
works.

## App prompts via polkit (optional)

Desktop apps ask polkit to verify you; Bitwarden's biometric unlock and
`pkexec` are polkit prompts. Opt in with:

```sh
sudo irlume login enable --with-polkit --apply
```

The daemon treats polkit as verify-only (it never releases the TPM-sealed
credential to it). PAM shows `Type yes to use face authentication` above the
normal hidden field, unless `privileged_face_consent=0` waives it as described
above. Type `yes` for one face attempt, or type the ordinary
password once for the password/fingerprint path. Empty Enter and cancellation
never open the camera. An experimental head gesture can be explicitly added as
a second gate, but defaults off and never replaces keyboard confirmation.
Automatic passive PAD remains mandatory and separate.
Full walkthrough, Bitwarden setup, and the security stance:
[APP-INTEGRATION.md](APP-INTEGRATION.md).

## Fingerprint companion (optional)

On a laptop with a fingerprint reader, add it as a second factor:

```sh
irlume fingerprint status
irlume fingerprint add           # enroll a finger via fprintd
sudo irlume fingerprint enable   # unlock with face OR fingerprint (keeps face on)
# add --fingerprint-only to replace face with fingerprint instead
```

## IR emitter (rarely needed)

Most Hello cameras need nothing here: irlume applies the control for modules it
has been validated against, and re-applies it on every capture.

If IR frames stay dark and you believe your camera has an emitter irlume is not
driving:

```sh
sudo irlume ir-setup --dry-run   # lists the camera's extension units, writes nothing
sudo irlume ir-setup
```

`ir-setup` writes to your camera. It only ever addresses Microsoft's documented
camera-control extension unit, and only selectors that unit advertises in its USB
descriptor. The value it writes comes from the camera: for the IR Torch control it is that
control's own default, and for the Face Authentication control it is built from
the modes the camera says each of its interfaces supports, because the default
there is "ordinary capture" and would not light anything. If the control does not
help, the value read from it beforehand is written back to undo the change.

A change is only accepted if the picture brightens when the control is set and
dims again when it is put back, so a passing cloud or someone moving is not
mistaken for a working illuminator. Setup stops as soon as the camera fails to
answer a request or to deliver a frame; it does not retry and does not move on
to another control.

What `ir-setup` finds is recorded as which control worked, never as a payload,
so later captures rebuild the value from the camera rather than replaying bytes
from a file.

Before 0.7.1 it did something quite different: it wrote invented payloads to
every extension unit and selector until the picture brightened, and it ran
automatically at daemon start and during enrollment. That permanently destroyed a
reporter's camera ([#159]). It is now only ever run when you ask for it.

To see exactly what irlume sends to the camera, set `IRLUME_LOG_EMITTER_WRITES=1`
and it prints each emitter write before making it, interleaved with the undo
record's own events so the order is visible.

Setup writes that undo record before it touches the control and removes it only
once the control reads back holding its original value again, so a crash, a kill
or a power loss part-way through leaves the original bytes on disk. The next
capture on that camera puts them back; `irlume doctor` reports anything still
outstanding, which is how you find it on a machine running
`IRLUME_IR_EMITTER=off`.

If your camera's vendor documents a control that irlume cannot discover, set it
yourself:

```sh
IRLUME_IR_EMITTER=unit:selector:b,b,b
```

These bytes go to your camera's firmware. Use a value the vendor documents; do
not try numbers to see what happens, which is what destroyed the camera in
[#159].

A value that is set but is not `unit:selector:bytes` drives nothing and says so.
It does not fall back to the camera's own control: setting the variable is
consent to the control named in it, so a typo refuses rather than writing
something you did not ask for. Unset it to go back to the built-in behaviour.

The unit may be a vendor's rather than Microsoft's, since this exists for
cameras with no Microsoft unit at all. Before writing anything, irlume checks
the camera's USB descriptor publishes that unit and advertises that selector,
that `GET_INFO` says the control accepts a write, that the payload is the length
`GET_LEN` states, and that `GET_CUR` answers. If any of those fails it refuses
and prints which one. The value is applied at most once per camera per run of
the process: before 0.7.2 it was re-sent every eighth frame of every capture,
with none of these checks ([#179]).

[#159]: https://github.com/archledger/irlume/issues/159
[#179]: https://github.com/archledger/irlume/issues/179

## Anti-spoofing (PAD) models: shipped default-on

The shipped PAD pair refuses a life-size print.
The algorithmic gate alone does not stop one. Measured twice on the same
hardware, on 2026-06-30 and again on 2026-08-02, an angled vinyl print of the
enrolled user's face produces the same centre-to-edge infrared falloff a real
face does, so no threshold separates them and the gate accepts the print. The
measured defence is the SHIPPED PAD pair (ADR-0013): the FLIR IR cue denied
that print at `p_fake` 0.999 and above, and the ViT RGB cue catches the
print/banner species at login distance. Both ship default-on and verified
against `models/SHA256SUMS` at daemon startup; kill switches if a cue misfires
on your hardware: `IRLUME_PAD_IR=0` (service env `pad_ir=0`) and
`IRLUME_PAD_VIT=0` (`pad_vit=0`), then `sudo systemctl restart irlumed`.
These switches are password-only controls: the daemon, diagnostics, and
password fallback remain available, but no face grant that requires the
disabled cue is permitted. A missing model or inference failure has the same
fail-closed authentication result. Model availability is reported by the daemon
health check; a runtime inference failure is reported on the failed attempt.

Third-party / bring-your-own model support was removed (ADR-0015): irlume
ships and supports exactly the models-v1 set it was validated with, and there
is no external recognizer path. The historical measurements behind that
decision live in [docs/pad-results/](pad-results/) and
[docs/recognition-results/](recognition-results/).

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
| `/etc/irlume/settings.conf` | `execution_device=auto\|cpu\|npu` selects one backend for the complete ONNX engine at the next daemon start (`auto` is the default; explicit `npu` never falls back). `credential_release_challenge=1` opts IN to a head gesture before the login-keyring credential is released (default off); every `service_gesture.<service>` also defaults off, with `=1` adding an experimental gesture after mandatory privileged keyboard confirmation; the legacy `polkit_gesture=1` switch remains an explicit polkit opt-in. `privileged_face_consent=0` is the machine owner's waiver of the literal `yes` on privileged services, so the scan starts when the privileged PAM prompt appears, with no per-attempt word (default on: the confirmation is required, and an unreadable settings file keeps it). `enforce_biopolicy=1` opts into operation-class gating; `forbid_external_cameras=1` restricts face authentication to cameras the kernel reports as `removable: fixed` (internal only; `removable: unknown` fails closed to the password, mirroring Windows ShouldForbidExternalCameras post-CVE-2021-34466); the legacy `third_party_pad` / `third_party_recognizer` keys are ignored with a startup notice (the third-party lane was removed, ADR-0015). During the migration window, `consent_gesture=closure` or malformed values block only a gesture-gated request until removed or changed to `nod` | TUI Settings; `sudo irlume inference-device auto\|cpu\|npu`; `sudo irlume credential-release-challenge [<service>] on\|off` |
| `/etc/irlume/cameras.conf` | `rgb=` / `ir=` device nodes of the active camera pair | TUI camera picker, or `sudo irlume set-cameras <rgb> <ir>` |
| `/etc/irlume/method` | one line: the active auth method (`auto`, `face`, `fingerprint`, or `both` = face OR fingerprint) | `irlume fingerprint enable/disable` |
| `/var/lib/irlume/ir_emitter.conf` | the UVC extension-unit control that lights the emitter | `irlume ir-setup` |
| `/var/lib/irlume/ir-emitter-journal/` | one record per camera, holding the bytes a control held before `ir-setup` changed it. Written before the change and removed once the control reads back as restored, so a crash, a kill or a power loss mid-setup leaves something that can undo it. Root-only | `irlume ir-setup`, cleared by it or by the next capture |

During the one-release migration window, a stored legacy eyes-open policy also
fails closed. Clear it with `irlume profiles eyes-open off`; no current setup
path enables it.

Camera selection precedence: the `IRLUME_RGB_DEVICE`+`IRLUME_IR_DEVICE` env
pair (both set), then `cameras.conf`, then auto-detection, then the compiled
defaults (`/dev/video0`+`/dev/video2`).

### Daemon environment variables

Set these on the service, not in a shell (`sudo systemctl edit irlumed`, then
`Environment=` lines in the drop-in).

| Variable | Effect | Default |
|---|---|---|
| `IRLUME_MODELS_STRICT` | refuse to start when a core model file is missing or fails the checksum manifest; a rejected PAD model keeps the daemon available but makes affected face paths password-only | warn and continue |
| `IRLUME_EXECUTION_DEVICE` | overrides `execution_device` with exactly `auto`, `cpu`, or `npu`. Released builds resolve `auto` to ONNX Runtime CPU; accelerator candidates exist only in explicitly experimental builds. Inspect policy and the daemon-proven result with `irlume inference-device status` | `auto` |
| `IRLUME_PRIVILEGED_FACE_CONSENT` | same switch as `privileged_face_consent` in `settings.conf`; the env var wins. `0` waives the literal `yes` on privileged services | on |
| `IRLUME_ENFORCE_BIOPOLICY` | same switch as `enforce_biopolicy` in `settings.conf`; the env var wins | off |
| `IRLUME_FORBID_EXTERNAL_CAMERAS` | same switch as `forbid_external_cameras` in `settings.conf`; the env var wins | off |
| `IRLUME_CREDENTIAL_RELEASE_CHALLENGE` | same switch as `credential_release_challenge` in `settings.conf`. Precedence: `service_gesture.credential_release` has highest priority; when that key is absent, this variable overrides the `settings.conf` key. Set `1` to add a gesture before the keyring password is released | off |
| `IRLUME_POLKIT_GESTURE` | legacy explicit opt-in for an additional experimental polkit head gesture; `service_gesture.polkit-1` takes precedence. It cannot disable or replace mandatory PAM keyboard confirmation | off |
| `IRLUME_CONSENT_GESTURE` | one-release migration input that overrides `consent_gesture` in `settings.conf`. Unset or `nod` permits an explicitly enabled head gesture; legacy `closure` and malformed values fail that gesture-gated request closed. Unset the variable or set it to `nod` to migrate | unset |
| `IRLUME_DET_MODEL` / `IRLUME_MODEL` / `IRLUME_MESH_MODEL` / `IRLUME_BLAZE_MODEL` | paths to the detector / recognizer / FaceMesh / BlazeFace weights | `/etc/irlume/*.onnx` |
| `IRLUME_IR_ADAPTER` | path to an optional IR-adapter model (none ships; see ADR-0004) | `/etc/irlume/ir_adapter.onnx` |
| `IRLUME_RGB_DEVICE` / `IRLUME_IR_DEVICE` | camera-pair override; both must be set | auto |
| `IRLUME_IR_EMITTER` | emitter control override: `off`, or `unit:selector:b,b,..` (decimal or `0x` hex bytes); writes to camera firmware, checked against the descriptor first, applied once per camera per process; bypasses `ir_emitter.conf` | conf, else known-module table |
| `IRLUME_IR_EMITTER_CONF` | alternate path for `ir_emitter.conf` | `/var/lib/irlume/ir_emitter.conf` |
| `IRLUME_RGB_MOIRE_MAX` | per-camera ceiling for the screen-replay moiré cue | 28 |
| `IRLUME_IR_AMBIENT_SUBTRACT` | `1` enables experimental lit-minus-ambient IR subtraction; changes the IR frames the matcher sees, so re-enroll after toggling (see [ARCHITECTURE.md](ARCHITECTURE.md)) | off |
| `IRLUME_TCTI` | TPM transport | `device:/dev/tpmrm0` |
| `IRLUME_PCRS` | comma-separated PCR list the sealed secret binds to | `7` |
| `IRLUME_SRK_HANDLE` | persistent SRK handle (hex), if the default collides with another TPM user | `0x81010002` |
| `IRLUME_METHOD_CONF` | alternate path for the method file | `/etc/irlume/method` |

Liveness-cue tuning knobs and IR capture debug settings are in
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
  enrollment    : 1 profile(s), 10 scan(s) ✅
                  - Face Profile 1 (10 scan(s))
  keyring unlock: armed ✅
  templates     : encrypted at rest ✅
  recovery pass : set ✅
  biopolicy     : off (default)
  cameras       : rgb=/dev/video0 ir=/dev/video2
  fingerprint   : none
```

Then lock your screen and look at the camera. For a wired fresh `sudo`, type
`yes` at irlume's hidden confirmation before looking at the camera. Want to
check the anti-spoofing and other claims for yourself? See
[VERIFY.md](VERIFY.md).

## Undo everything

```sh
sudo irlume login disable --apply
```

Removes every PAM change (greeter, lock, and `sudo`) and restores the originals.
Your password login is never touched. To remove just face-`sudo` while keeping
the greeter, re-run `login enable --apply` *without* `--with-sudo`. For every
off-switch in one place (per-surface tiers, standing face down without touching
PAM, canceling a running scan, full uninstall), read [DISABLE.md](DISABLE.md).
