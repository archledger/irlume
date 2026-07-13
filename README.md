<div align="center">

<img src="docs/assets/banner.svg" alt="irlume: face authentication for Linux" width="640">

<br>

**Face-unlock for Linux login, `sudo`, and the lock screen. Works in the dark,
resists photo & screen spoofs, and never stores your face as an image.**

Works with the camera you have: an **IR (Windows Hello) camera** unlocks the full
secure tier, a **regular webcam** gives convenient screen unlock, and a
**fingerprint reader** slots in as a companion factor.

Built to match or beat Windows Hello, on a fully open, commercially clean stack.

<br>

[![License: GPL v3](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux-1f2328)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-dea584)
![Packaged](https://img.shields.io/badge/packaged-Fedora%20·%20Arch%20·%20Debian%2FUbuntu-2ea44f)
[![Version](https://img.shields.io/github/v/release/archledger/irlume?label=version&color=c0304f)](https://github.com/archledger/irlume/releases)
[![AI-assisted](https://img.shields.io/badge/AI--assisted-human--directed-7c5cbf)](#-faq)

[Install](#-install) · [How it works](#-how-it-works) · [Security](#-your-face-never-leaves-as-an-image) · [Limits](#-honest-limitations) · [FAQ](#-faq) · [Docs](docs/)

<br>

<img src="docs/assets/irlume-demo.gif" alt="irlume demo: one-line install, guided face enrollment in the TUI, wiring the greeter and lock screen, and opt-in face-sudo" width="720">

<sub>From a one-line install to a wired face login: guided face enrollment in the TUI, greeter and lock-screen wiring, and opt-in face-<code>sudo</code>.</sub>

</div>

---

## ✨ What you get

|  |  |
|---|---|
| 🌑 **Works in the dark** | Active **infrared** recognition (Windows-Hello cameras); no ambient light needed. |
| 🔒 **Unlocks everything** | Login greeter, lock screen, and `sudo` (opt-in via `login enable --with-sudo`), with the password always as fallback (**no lockout, ever**). |
| 🙋 **On-demand, by consent** | The camera fires only when you ask: leave the password field **empty and press Enter**. Typing a password never starts a scan. Wiring is tailored per login manager (GDM · SDDM · Plasma Login · LightDM · greetd · COSMIC). |
| 🗝️ **Opens your keyring** | On IR hardware a face match **TPM-unseals your login password** so the wallet unlocks at login, like Hello. |
| 👁️ **Real liveness** | Algorithmic IR anti-spoof gate + **opt-in passive blink** detection (no prompt, no action). |
| 🧬 **No face images stored** | Stores **512-D embeddings, never images**; on TPM hardware they're **AES-256-GCM encrypted** under a **TPM-sealed** key (without a TPM: root-only files, and the TUI says so). |
| 🎚️ **Adapts to your hardware** | IR camera → **Secure** tier · RGB-only → **Convenience** (screen-unlock) tier · fingerprint reader → companion factor. All auto-detected. |
| 🩺 **Self-healing** | A live TUI (`irlume tui`) detects & one-key-fixes daemon/PAM/reader/config faults. |
| 📦 **Self-contained** | One package per distro, all models bundled. `git clone` and go. |

## 🆚 Comparison: Windows Hello, Howdy, visage

How irlume stacks up against Windows Hello and the Linux face-unlock projects you've
probably met ([Howdy](https://github.com/boltgolt/howdy), [visage](https://github.com/sovren-software/visage)):

| | Windows Hello | Howdy | `visage` | **irlume** |
|---|:---:|:---:|:---:|:---:|
| **Liveness / anti-spoof** | IR only *(bypassable: [CVE-2021-34466](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34466))* | ❌ none; its own README warns a *"well-printed photo of you could be enough"* | ⚠️ passive (landmark-stability; blocks photos, not video) | ✅ algorithmic IR gate **+** opt-in passive blink; self-tested vs [ISO/IEC 30107-3](docs/PAD_SELFTEST.md) |
| **Camera-injection defense** | device-trust *(newer HW)* | ❌ none | ❌ none | ✅ device pinning **+** cross-spectrum RGB↔IR |
| **Template protection** | TPM-bound enclave | ⚠️ unencrypted encodings on disk | AES-256-GCM, key in a 0600 disk file *(not TPM-sealed)* | ✅ AES-256-GCM, **TPM-sealed key** *(survives disk theft)* |
| **Opens your keyring/wallet** | ✅ | ❌ *(keyring stays locked)* | ❌ | ✅ **TPM-unseals** it at login |
| **Stores your face as…** | template | encoding | embedding | **embedding only, never an image** |
| **Model licensing** | proprietary | MIT code · dlib weights | ⚠️ non-commercial weights | ✅ **permissive, bundleable** |
| **Runs on** | Windows | Linux | Linux | **Linux: Fedora · Arch · Debian/Ubuntu** |

## 📦 Install

> **v0.1.5.** Works end-to-end on real hardware across all three families. Not
> yet certified (no iBeta lab pass); see [Honest limitations](#-honest-limitations).

**You need:** x86-64 Linux with systemd & PAM; the distros below are
packaged and tested. A **TPM 2.0** is strongly recommended (encrypted templates,
keyring unlock) but not required. Any camera works; it just sets your tier:
**IR camera** → secure login · **RGB webcam** → screen unlock · **fingerprint** → companion.

### One-step install

```sh
curl -fsSL https://raw.githubusercontent.com/archledger/irlume/main/scripts/install.sh | sh
```

Detects your distro and installs from the **signed Copr repo** (Fedora) or
**PPA** (Ubuntu LTS), or a **checksum-verified** release package (Arch, Debian,
Ubuntu derivatives). It installs a package only and wires nothing into your
login, and it stops without changing anything if irlume is already installed
(use `irlume update` to upgrade). Prefer to read it before running it?

```sh
curl -fsSL https://raw.githubusercontent.com/archledger/irlume/main/scripts/install.sh -o install.sh
less install.sh && sh install.sh
```

Or install manually with your package manager:

<table>
<tr><th>Fedora</th><th>Ubuntu</th><th>Arch</th><th>Debian</th></tr>
<tr valign="top">
<td>

```sh
# Copr
sudo dnf copr enable \
  archledger/irlume
sudo dnf install irlume
```

</td>
<td>

```sh
# PPA
sudo add-apt-repository \
  ppa:archledger/irlume
sudo apt install irlume
```

</td>
<td>

```sh
# prebuilt from Releases
sudo pacman -U \
  ./irlume-*.pkg.tar.zst
```

</td>
<td>

```sh
# .deb from Releases
sudo apt install \
  ./irlume_*.deb
```

</td>
</tr>
</table>

Fedora and current-LTS Ubuntu update with the system (`dnf upgrade` /
`apt upgrade`). The [PPA](https://launchpad.net/~archledger/+archive/ubuntu/irlume)
carries the **current Ubuntu LTS only**; on an older LTS or a derivative (Mint,
Pop!_OS, Zorin, elementary) use the universal Debian `.deb` from
[Releases](https://github.com/archledger/irlume/releases). `irlume update`
handles every case: it detects how irlume was installed and updates the same way.

Then, once:

```sh
irlume tui                         # enroll your face + configure, guided
sudo irlume login enable --apply   # opt-in: wire the greeter + lock screen
```

`login enable` (and the TUI's `[w]`) wires the **greeter and lock screen** for
your login manager. From then on face is **on-demand**: at the greeter or lock
screen, leave the password empty and press Enter. The camera fires only then.
Face-`sudo` is a separate opt-in; add it with
`sudo irlume login enable --with-sudo --apply`, since granting root by face is a
trade-off worth choosing deliberately (the password always still works).

**Full step-by-step** (both the guided TUI and the individual CLI commands, with
keyring unlock, recovery, and fingerprint): [`docs/SETUP.md`](docs/SETUP.md).
**Something not working, or want to audit every decision?**
[`docs/DEBUGGING.md`](docs/DEBUGGING.md): `irlume logs` puts every
face-auth journal line in one view, and `sudo irlume logs debug on` traces
every pipeline stage (scores, liveness cues, thresholds, timings; numbers
only, never frames or embeddings).

No IR-emitter step needed: enrollment probes the IR camera and, if its frames
come back black, auto-discovers and enables the 850 nm emitter itself. Only if
IR stays dark after enrolling, run `sudo irlume ir-setup` manually. It applies
to IR cameras only (on an RGB-only webcam it exits with "not an IR capture
node" without touching anything).

**Safe to try.** Installing the package wires **nothing** into your login.
Auth only changes when you run `login enable`, and without `--apply` it's a
dry run that prints the full per-file wiring plan without writing anything. Your password always keeps
working, and one command undoes everything: `sudo irlume login disable --apply`.

`irlume update` checks for a new release the way your distro expects. Prefer to
build from source? See [`packaging/`](packaging/) and [`scripts/install-host.sh`](scripts/install-host.sh).

## 🧠 How it works

Privilege separation first. The thin **`pam_irlume.so`** module and **`irlume`**
CLI are *untrusted* clients of the privileged **`irlumed`** daemon, the only thing
that ever touches the camera, IR emitter, models, templates, or TPM. They speak
over a Unix socket authenticated with `SO_PEERCRED`.

```
    ┌───────────────┐   ┌───────────────┐        ╔═══════════════════════════╗
    │ pam_irlume.so │   │  irlume  (CLI │        ║  irlumed   (privileged)   ║
    │  greeter/sudo │   │   + live TUI) │        ║                           ║
    └──────┬────────┘   └───────┬───────┘        ║  camera + IR emitter      ║
           │  SO_PEERCRED       │   Unix socket  ║  YuNet → AuraFace (ONNX)  ║
           └────────────────────┴───────────────▶║  IR liveness · matcher    ║
                                                 ║  TPM seal · templates     ║
                                                 ╚═══════════════════════════╝
```

**Model bill-of-materials.** Every weight is permissive or first-party, all
GPLv3-compatible, so the whole thing is bundleable:

| Stage | Model | License |
|---|---|:---:|
| Detection | **YuNet** | MIT |
| Recognition | **AuraFace** *(512-D ArcFace)* | Apache-2.0 |
| IR liveness gate | self-built, algorithmic *(no weights)* | n/a |
| Passive blink liveness | **MediaPipe FaceMesh** → eye-aspect-ratio *(opt-in)* | Apache-2.0 |
| IR domain adapter | self-trained *(author's own IR captures)* | GPL-3.0 |

More depth: [Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Cross-distro notes](docs/cross-distro/).

## 🔐 Your face never leaves as an image

irlume stores **only 512-D embeddings** (a one-way projection; you can't rebuild
a photo from it), **AES-256-GCM encrypted**, under a key the **TPM seals to your
boot state**. We [audited this live](docs/SECURITY_AT_REST.md):

- 🧑‍💻 A normal user account → `cat`ting the files gives **Permission denied** *(root-only, 0600)*.
- 💽 **Disk-theft test:** copied the encrypted templates **and** the sealed key to a
  *second machine with its own TPM* → **`tpm: integrity check failed`**. The stolen
  data is undecryptable off the original box.

The delta vs Hello: Hello isolates templates in a VBS/TPM enclave the kernel
never sees; irlume's daemon is a root process holding decrypted embeddings in RAM
during a match, so **root on the live machine is the trust boundary** (as with
most Linux secrets). Full write-up: [`docs/SECURITY_AT_REST.md`](docs/SECURITY_AT_REST.md).

Every claim here maps to something you can run on your own machine:
[`docs/VERIFY.md`](docs/VERIFY.md).

## ⚖️ Honest limitations

The current gaps:

- **Passive blink liveness is a deterrent, not a guarantee.** It closes casual and
  typical print/screen attacks, but a *determined life-size glossy print* still
  slips through occasionally, and it **doesn't cover glasses-wearers** (IR lens
  reflections hide the eyelid). Every miss falls **safely to the password**. Beating
  a determined glossy print is the passive-cue ceiling; it needs a trained PAD
  model or true depth hardware. See [ADR-0002](docs/adr/0002-challenge-response-liveness.md)
  and the [PAD self-test results](docs/pad-results/).
- **RGB-only laptops get the Convenience tier:** face unlocks the *screen only*,
  never `sudo`, login, or the keyring (those keep the password). By design.
- **Not lab-certified.** We self-test against ISO/IEC 30107-3; there's no paid iBeta
  pass. Demographic FMR tuning ([FAIRNESS.md](docs/FAIRNESS.md)) is ongoing.

## ❓ FAQ

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
deliberately limited to screen unlock. See the [comparison](#-comparison-windows-hello-howdy-visage).
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

That's the point of [`docs/VERIFY.md`](docs/VERIFY.md). Each claim maps to a
command you can run: see your own camera's anti-spoof score, confirm the stored
template is encrypted ciphertext (not an image), run the presentation-attack
self-test against your own spoofs, reproduce the real-face FAR on LFW, and build
and run the test suite. Some checks take two minutes, some take real effort, but
every one is runnable.
</details>

<details>
<summary><b>Glasses, beards, outdoors: when should I re-enroll?</b></summary>

One enrollment usually lasts. Add to it when reality changes, the same way
Windows Hello recommends: **wear glasses sometimes?** Enroll a second profile
named `glasses` (TUI Profiles → `[e]`) so both looks match. **Major appearance
change** (shaved beard, new heavy frames)? Add a scan (`[a]`) rather than
starting over. **Recognition flaky in bright sunlight?** Strong ambient IR can
wash out the emitter's illumination; add a scan captured in that environment.
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
camera and letting auto-exposure settle, not the neural networks. The greeter
and lock screen pre-warm the camera on the unlock signal, so a real unlock
feels quicker than a cold `irlume identify`.

The **opt-in blink challenge** (`irlume profiles challenge on`) is a deterrent
against a glossy print or vinyl that mimics infrared depth: it watches for a
natural blink, which a static image cannot do. Detecting a blink is inherently
temporal, so it captures a roughly 5-second infrared sequence, and the login
takes about **10 seconds** (measured across six runs, glasses on and off). That
is the trade: the challenge closes a spoof gap the default single-frame gate
cannot, at about four times the latency.

It is off by default. Turn it on with `irlume profiles challenge on` if you
want the extra deterrent, or leave it off for the ~2.5-second login; the
default IR-structure gate already rejects photos, screens, and video replays.
</details>

## 🛠️ Status

**v0.1.5: working, validated on real hardware** across Fedora (full IR Secure tier,
end-to-end), Ubuntu/Pop!_OS (RGB Convenience tier + fingerprint), and Arch (packaging +
CLI/daemon on a camera-less testbed). Packaged for all three families (see [Install](#-install)).

0.1.5 adds **Tier-2 TPM sealing via systemd-pcrlock**: on a pcrlock-provisioned machine a
firmware or Secure Boot update needs one `systemd-pcrlock make-policy` run instead of
re-arming the keyring, and the sealed password keeps releasing. Sealing picks the best
policy the machine supports (signed PCR, then pcrlock, then a literal PCR-7 seal) and
round-trip-verifies it before trusting it, so a policy that cannot unseal on the current
boot never holds the secret.

**Presentation attacks tested and denied** on a NexiGo HelloCam N930W: a printed photo
(including in direct sunlight), a laptop screen, a phone screen at full brightness, and a
video replay with real head motion. Each is rejected at the infrared face-detection stage,
because print and screens do not reproduce a face at 850nm. A physical 3D mask is not yet
tested; see [contributing](#-contributing--license) if you can run that.

**Contributor-ready:** a reproducible Nix dev shell and [developer guide](docs/DEVELOPMENT.md),
with CI running fmt / clippy / build / test on every push and PR. Interfaces may still shift
before 1.0.

## 🙏 Credits

irlume relies on models and code from other projects. The bundled models:

- **[YuNet](https://github.com/opencv/opencv_zoo)** (OpenCV Zoo, MIT) detects faces in both the RGB and IR streams.
- **[AuraFace](https://huggingface.co/fal/AuraFace-v1)** by fal (Apache-2.0) is the 512-D ArcFace recognizer; irlume ships only its `glintr100.onnx`.
- **[MediaPipe FaceMesh](https://ai.google.dev/edge/mediapipe/solutions/vision/face_landmarker)** (Google, Apache-2.0) supplies the eye landmarks for the opt-in blink liveness.

The TPM and camera code builds on:

- **[rust-tss-esapi](https://github.com/parallaxsecond/rust-tss-esapi)** (the Parsec project, Apache-2.0) wraps the TPM 2.0 ESAPI. irlume builds from a small patch branch that adds the `PolicyAuthorizeNV` wrapper (upstream [PR #486](https://github.com/parallaxsecond/rust-tss-esapi/pull/486)) plus the [PR #530](https://github.com/parallaxsecond/rust-tss-esapi/pull/530) session-leak fix, pinned to an exact commit.
- **[systemd](https://github.com/systemd/systemd)** (LGPL-2.1-or-later): the Tier-2 pcrlock seal and unseal in `crates/irlume-core/src/tpm.rs` follows the scheme in systemd's `src/shared/tpm2-util.c` and `src/pcrlock/pcrlock.c`.
- **[linux-enable-ir-emitter](https://github.com/EmixamPP/linux-enable-ir-emitter)** documented the UVC Extension-Unit writes that fire the 850nm emitter on integrated Hello cameras.
- **[ort](https://github.com/pykeio/ort)** binds Microsoft's ONNX Runtime, which irlume loads at runtime for every model above.

Prior art that shaped the design: **Windows Hello** for the infrared, dual-sensor credential model, and [Howdy](https://github.com/boltgolt/howdy) and [visage](https://github.com/sovren-software/visage) as the existing Linux face-unlock projects (see the [comparison](#-comparison-windows-hello-howdy-visage)). irlume is the from-scratch successor to the author's earlier linhello.

## 🤝 Contributing & license

**GPL-3.0-or-later**, fully open, copyleft: modifications stay free, nobody can
lock this down. Contributions welcome under the [DCO](CONTRIBUTING.md); **no CLA,
no commercial relicensing**. Security reports: see [SECURITY.md](SECURITY.md).

**Questions, setup help, hardware reports** →
[GitHub Discussions](https://github.com/archledger/irlume/discussions). Reports
from laptops with IR cameras (working *or* not) are the most valuable
contribution right now. Bugs → [Issues](https://github.com/archledger/irlume/issues).

> [!NOTE]
> **AI disclosure: assisted, human-directed.** irlume is built by a human
> maintainer working with an AI assistant (Anthropic's Claude), disclosed
> throughout the git history via `Co-Authored-By` trailers; see the log or the
> [contributors](https://github.com/archledger/irlume/graphs/contributors) page.
> Direction, review, and releases are human-driven; every release is validated
> with clean-slate installs on real hardware, and the security claims rest on
> reproducible evaluations in this repo, not on who typed the code.

<div align="center"><sub>Built with Rust · <a href="LICENSE">GPL-3.0-or-later</a> · your face stays yours</sub></div>
