# App integration: face-approve polkit prompts (Bitwarden, pkexec)

irlume can satisfy polkit authentication prompts, which is how desktop apps on
Linux ask the OS to verify you. Bitwarden's "unlock with biometrics" is a
polkit prompt; so are `pkexec`, GNOME Software's install dialog, and systemd
unit operations from your desktop. Wire it once and every polkit prompt in
your session accepts your face, with your password as the unchanged fallback.

## How it works

An app never talks to irlume, the camera, or your face templates. The chain
is the same middleman model Windows Hello uses, built from standard Linux
pieces:

1. The app asks polkit for authorization
   (`org.freedesktop.PolicyKit1.Authority.CheckAuthorization`). Bitwarden does
   exactly this with its `com.bitwarden.Bitwarden.unlock` action.
2. Your desktop's polkit agent (KDE or GNOME) opens its dialog, which names
   the app and the action being approved, and starts a PAM conversation on the
   `polkit-1` service.
3. `pam_irlume` in that stack asks `irlumed` to verify your face. For a polkit
   prompt the daemon also requires a deliberate consent gesture: **close your
   eyes for about a second, then open them** (see the security section). It
   then answers yes or no; the app learns only the verdict.

Both the KDE and GNOME agents start the PAM conversation the moment the dialog
appears, so the camera fires immediately. The dialog shows "irlume: close your
eyes for about a second, then open, to approve"; perform the gesture and it
approves, no typing or clicking.

## Enabling

Two steps: wire polkit, then calibrate the consent gesture.

```console
sudo irlume login enable --with-polkit --apply   # wire pam_irlume into polkit-1
sudo irlume calibrate-closure                     # teach it your open/closed eye shape
```

The first adds one verify-only line to the `polkit-1` PAM stack (Fedora gets an
`/etc/pam.d/polkit-1` override of the vendor file; Debian and Arch get an
edit-in-place with a `.pre-irlume` backup). `sudo irlume login disable --apply`
removes it along with everything else, flag or no flag.

`calibrate-closure` captures your eyes-open and eyes-closed EAR in two quick
prompts and stores them in your enrollment. The gesture is verified against
these per-user values, so without it a polkit prompt falls back to the
password. `irlume doctor` flags a wired-but-uncalibrated setup.

Check the state any time:

```console
irlume login status     # shows a "polkit app prompts" row
irlume doctor           # flags Bitwarden-installed-but-polkit-unwired
```

## Bitwarden specifics

Bitwarden's desktop app needs its polkit action registered on the host. The
non-sandboxed packages install it themselves ("set up biometric unlock" in
Settings); the flatpak and snap cannot write to `/usr/share/polkit-1/actions`,
so Bitwarden displays the one-time manual step in its settings. After that:

- Unlock the vault once with your master password (Bitwarden holds the vault
  key in protected memory; biometrics never replace the first unlock).
- "Unlock with system authentication" then pops the polkit dialog, which your
  face satisfies.
- Browser-extension biometric unlock rides the same desktop app via native
  messaging; enable "biometric unlock in browser" in the desktop settings.

There is no Bitwarden-specific code in irlume. Any app using polkit this way
works the same day it ships.

## Security stance

- **Verify-only, always.** The daemon refuses to release the TPM-sealed login
  password to a polkit service unconditionally: not tier-dependent, not
  config-dependent. A polkit prompt gets a yes/no and nothing else, so a
  misconfigured or malicious stack cannot use a polkit dialog to extract a
  credential.
- **Deliberate gesture required.** polkit agents run the PAM conversation with
  no user action, so a bare face match would approve a prompt the user never
  acknowledged. For polkit-class services the daemon requires the deliberate
  eye-closure gesture (close ~1s, then open) even for users who did not opt into
  any per-enrollment liveness, and fails closed if it cannot run (no IR camera,
  no FaceMesh model, or no stored calibration). Disable the forced gesture with `polkit_gesture=0` in
  `settings.conf` if you accept that trade.
- **IR tier only.** RGB-only (convenience) devices never satisfy polkit
  prompts; a printed photo in front of a webcam must not approve app actions.
- **What this does not protect against.** Any process in your active session
  can pop a polkit prompt at any time; the dialog itself is your notice of
  what is being approved. Read it. This matches the Windows Hello model, where
  the consent is your attention to the prompt on screen. The password prompt
  remains for anything you decline or the camera cannot verify.

## Troubleshooting

- Prompt appears but the camera never fires: check `irlume login status` for
  the polkit row, then `sudo ausearch -m avc -ts recent | grep irlume` on
  SELinux systems; the shipped policy (1.1.0) grants the polkit helper domain
  access to the daemon socket.
- Face matches but the prompt stays: it wants the consent gesture. Close your
  eyes for about a second, then open them. If it never accepts, check the
  calibration with `irlume doctor` and re-run `sudo irlume calibrate-closure`.
  `irlume logs` shows the deny reason.
- Bitwarden says biometrics are unavailable: its polkit action file is
  missing (`irlume doctor` reports this) or the desktop app needs the
  Secret Service (GNOME Keyring / KWallet) running.
