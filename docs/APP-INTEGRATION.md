# App integration: face-approve polkit prompts (Bitwarden, pkexec)

irlume can satisfy polkit authentication prompts, which is how desktop apps on
Linux ask the OS to verify you. Bitwarden's "unlock with biometrics" is a
polkit prompt; so are `pkexec`, GNOME Software's install dialog, and systemd
unit operations from your desktop. Wire it once and every polkit prompt in
your session can offer face verification after explicit confirmation, with
your password as the unchanged fallback.

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
3. `pam_irlume` asks for hidden literal `yes`. Enter, cancellation, or any other
   response selects password/fingerprint without opening the camera. `yes`
   authorizes exactly one face attempt.
4. `irlumed` verifies the face and automatic passive PAD. The app learns only
   the final verdict.

Both the KDE and GNOME agents start the PAM conversation the moment the dialog
appears, but irlume does not open the camera until it receives the hidden `yes`.
This conventional response is mandatory and cannot be disabled.

## Enabling

One wiring step; keyboard confirmation needs no calibration.

```console
sudo irlume login enable --with-polkit --apply   # wire pam_irlume into polkit-1
```

This adds one verify-only line to the `polkit-1` PAM stack (Fedora gets an
`/etc/pam.d/polkit-1` override of the vendor file; Debian and Arch get an
edit-in-place with a `.pre-irlume` backup). `sudo irlume login disable --apply`
removes it along with everything else, flag or no flag.

Privileged intent is fixed: type hidden literal `yes` for one face attempt.
Automatic PAD remains mandatory before a face grant. Head gestures have been
removed; old settings no longer add a challenge. Stored legacy eyes-open policy
still blocks authentication until `irlume profiles eyes-open off` clears it.

Check the state any time:

```console
irlume login status     # shows a "polkit app prompts" row
irlume doctor           # flags Bitwarden-installed-but-polkit-unwired
```

## Bitwarden specifics

Bitwarden's "Unlock with system authentication" is a polkit prompt for the
action `com.bitwarden.Bitwarden.unlock` (`auth_self`), so it runs the `polkit-1`
PAM stack that irlume wires. First wire irlume for polkit if you have not:

```console
sudo irlume login enable --with-polkit --apply
```

Then let irlume install Bitwarden's polkit action (it detects how Bitwarden
was installed and does the right thing per flavor):

```console
irlume bitwarden status              # what is installed, what is missing
sudo irlume bitwarden setup --apply  # dry-run first by omitting --apply
```

What it does per install flavor:

- **Flatpak**: installs the action file on the host. The flatpak bundles no
  policy file and its sandbox cannot write `/usr/share/polkit-1/actions`, so
  a host-side install is always required; this is the main case.
- **Snap**: nothing. snapd installs the action itself when the snap's polkit
  plug connects (auto-connected from the store since Bitwarden 2025.3). If
  the action is missing there, the fix is `sudo snap connect bitwarden:polkit`.
- **.deb / .rpm / Arch**: installs the same file the app would self-install
  on first toggle, sparing the pkexec prompt (the app's own setup also breaks
  on hosts without SELinux tooling; irlume's does not).
- **ostree / immutable (Silverblue, Kinoite)**: explains instead of writing.
  `/usr` is read-only and polkit reads actions from exactly one directory,
  so the supported route is layering a small rpm that owns the file
  (`rpm-ostree install --apply-live`), then restarting polkit.

The policy content ships inside irlume (byte-identical to
`apps/desktop/resources/com.bitwarden.desktop.policy` in bitwarden/clients),
so nothing is downloaded at install time. An already-present action file with
different content is left alone: Bitwarden's own setup may have written a
newer one. After installing, the command asks polkit itself (`pkaction`)
whether the action registered, which catches label problems a plain file
check misses.

Then in Bitwarden: **File > Settings > Security > Unlock with system
authentication**. `irlume doctor` confirms the action is registered.

- Unlock the vault once with your master password (Bitwarden holds the vault
  key in protected memory; biometrics never replace the first unlock).
- "Unlock with system authentication" then pops the polkit dialog. Type `yes`
  at irlume's hidden confirmation, then complete face verification. Verified on
  the 2026.6.1 flatpak. Flatpak builds before
  Bitwarden 2026.5 failed here with polkit's "Unix process subject does not
  have uid set"; if you hit that, update the flatpak or use the `.deb`/`.rpm`.
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
- **Conventional confirmation required.** polkit agents can begin PAM without a
  user action, so `pam_irlume` requires hidden literal `yes` before contacting
  the daemon. Production `pam_irlume` sends a typed `PamConversation` assertion;
  the daemon accepts it only from a root peer and for a recognized privileged
  service. Missing, non-root, or irrelevant assertions are refused before
  camera work. Root can forge it, so it is not cryptographic proof against root
  or a compromised PAM conversation provider.
- **IR tier only.** RGB-only (convenience) devices never satisfy polkit
  prompts; a printed photo in front of a webcam must not approve app actions.
- **What this does not protect against.** Any process in your active session
  can pop a polkit prompt at any time; read the dialog before typing `yes`.
  Root or a compromised desktop authentication agent remains inside the trust
  boundary. The password prompt remains for anything you decline or the camera
  cannot verify.

## Troubleshooting

- Prompt appears but the camera never fires: check `irlume login status` for
  the polkit row, then `sudo ausearch -m avc -ts recent | grep irlume` on
  SELinux systems; the shipped policy (1.1.0) grants the polkit helper domain
  access to the daemon socket.
- Confirmation appears but the camera stays off: type literal `yes`; Enter or
  any other response intentionally chooses the password/fingerprint path.
- Bitwarden says biometrics are unavailable: its polkit action file is
  missing (`irlume doctor` reports this) or the desktop app needs the
  Secret Service (GNOME Keyring / KWallet) running. `irlume doctor` also
  reports whether a Secret Service provider is up and the login keyring is
  unlocked; run it as yourself (not under sudo), since it inspects your
  session bus.
- Face login stops working after a system update: a distro tool (authselect,
  pam-auth-update) can rewrite a greeter's PAM file and drop irlume's lines.
  The `irlume-reconcile.path` unit watches those files and re-applies the
  wiring automatically once `login enable` has been run; `irlume doctor`
  flags it if anything slips through.
