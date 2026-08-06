# Frequently asked questions

Moved out of the README so the front page stays short. For what irlume does
not do, read [Limits](LIMITATIONS.md) first;
several answers below depend on it.

<details>
<summary><b>Is this "Windows Hello for Linux"?</b></summary>

Yes, that's the bar. irlume brings Windows Hello-style face login to Linux:
face-unlock the login screen, lock screen, `sudo`, and your keyring/wallet,
using the same IR (Windows Hello) camera your laptop already has. And it aims
past Hello where Hello is weak: real anti-spoof liveness, encrypted
TPM-sealed templates, and a fully open stack.
</details>

<details>
<summary><b>How is irlume different from Howdy?</b></summary>

[Howdy](https://github.com/boltgolt/howdy) is the best-known face unlock for
Linux, and it's honest about being a *convenience*: its README says a
well-printed photo of you could be enough to fool it. irlume is built as an
*authenticator*: an IR liveness gate (self-tested against ISO/IEC 30107-3),
AES-256-GCM-encrypted templates under a TPM-sealed key, camera pinning, and
TPM keyring unlock at login, with tiers, so RGB-only face match is
deliberately limited to screen unlock. That gate has a documented hole of its
own, though: read [Limits](LIMITATIONS.md) before
treating it as a security boundary.
</details>

<details>
<summary><b>Do I need an IR camera?</b></summary>

No. An IR (Windows Hello) camera gets the full **Secure** tier: greeter
login, `sudo`, keyring unlock, works in the dark. A **regular RGB webcam**
gets the Convenience tier: face unlock for the lock screen only. A
**fingerprint reader** works as a companion factor on either. All
auto-detected.
</details>

<details>
<summary><b>Is this AI-generated?</b></summary>

AI-assisted, human-directed, and disclosed throughout the git history: the
large majority of commits carry `Co-Authored-By` trailers naming the AI
assistant (Anthropic's Claude, also visible under this repo's contributors). A human maintainer sets
direction, reviews the changes, and validates every release with clean-slate
installs on real hardware (Fedora, Arch, Ubuntu; IR camera, TPM, fingerprint)
before anything ships. Judge the project by its verifiable artifacts: the
threat model, measured error rates, spoof-test results, and the code itself
are all in the repo, reproducible regardless of what tools wrote them.
</details>

<details>
<summary><b>Can I verify these claims myself?</b></summary>

That's the point of [`docs/VERIFY.md`](VERIFY.md). Each claim maps to a
command you can run: see your own camera's anti-spoof score, confirm the stored
template is encrypted ciphertext (not an image), run the presentation-attack
self-test against your own spoofs, reproduce the real-face FAR on LFW, and build
and run the test suite. Some checks take two minutes, some take real effort, but
every one is runnable.
</details>

<details>
<summary><b>Glasses, beards, outdoors: when should I re-enroll?</b></summary>

One enrollment usually lasts. A profile is one identity, and a face can only
own one profile, so different looks of the same person are extra **scans** on
that profile, not a second profile. **Wear glasses sometimes?** Add a scan with
Improve Recognition (TUI Profiles → `[a]`, or `irlume profiles add-scan`) while
wearing them. **Major appearance change** (shaved beard, new heavy frames)? Same
thing, add a scan rather than starting over. **Recognition flaky in bright
sunlight?** Strong ambient IR can wash out the emitter's illumination; add a
scan captured in that environment.
Profiles are per-user and deletable any time.
</details>

<details>
<summary><b>Does it work on Ubuntu / Fedora / Arch, GNOME / KDE, Wayland?</b></summary>

It does. irlume authenticates through PAM, and tailors the greeter wiring to the
login manager it detects. Validated live on real machines: **Fedora KDE**
end-to-end on IR hardware (Plasma Login Manager greeter, lock screen, `sudo`,
TPM keyring unlock; Wayland), **Ubuntu GNOME** on an RGB+fingerprint laptop
(lock-screen face unlock, fingerprint, correct password-only refusals for
login/sudo), and the full login-manager matrix: **GDM** (on-demand on GNOME ≥ 46;
face-first before that), **SDDM**, **LightDM** (gtk and slick greeters, X11),
**greetd** (tuigreet), and **COSMIC's greeter**. **Arch** is validated for packaging,
install, and the full CLI/daemon stack (that testbed has no camera). Reports
from other hardware are very welcome.
</details>

<details>
<summary><b>I changed my login password and now my keyring/wallet won't open</b></summary>

This is general Linux behaviour, not specific to irlume. Changing your login
password (`passwd` or a settings dialog) updates `/etc/shadow`, but it does not
re-encrypt your KWallet / GNOME keyring. The wallet keeps the key derived from
your old password until you change the wallet's password separately, so it no
longer matches the new login password.

irlume seals whatever password you armed and hands it to the wallet, so it
passes along the old one and cannot fix this by itself. To bring all three back
in sync after a password change:

1. **Login password** is already updated by `passwd`.
2. **Wallet password**: change it to the new one in KWallet Manager →
   "Change Password" (KDE), or Seahorse → the "Login" keyring →
   "Change Password" (GNOME).
3. **irlume's sealed copy**: run `irlume keyring arm` to re-seal the new password.

Rule of thumb: whenever the wallet password changes, re-run `irlume keyring arm`
so irlume's seal keeps matching it. Your typed password opens everything in the
meantime, so nothing locks you out.
</details>

<details>
<summary><b>How fast is a face login, and why is the blink challenge slower?</b></summary>

A normal face login takes about **2.5 seconds** on an integrated IR camera
(measured on an ASUS Zenbook, CPU inference). Most of that is opening the
camera and letting auto-exposure settle, not the neural networks. The RGB and
IR captures run in parallel, which cuts the capture stage by about a third;
[docs/DEBUGGING.md](DEBUGGING.md) shows how to time every stage on your
own hardware.

The **opt-in blink challenge** (`irlume profiles challenge on`) is a deterrent
against a glossy print or vinyl that mimics the infrared relief pattern: it
watches for a
natural blink, which a static image cannot do. Detecting a blink is inherently
temporal, so it captures a roughly 5-second infrared sequence, and the login
takes about **10 seconds** (measured across six runs, glasses on and off). That
is the trade: the challenge closes a spoof gap the default single-frame gate
cannot, at about four times the latency.

It is off by default. Turn it on with `irlume profiles challenge on` if you
want the extra deterrent, or leave it off for the ~2.5-second login. The
default IR-structure gate rejected the tested screens, video replays, and
matte-paper photos, but a glossy vinyl print of the enrolled face passed it;
see [Limits](LIMITATIONS.md).
</details>
