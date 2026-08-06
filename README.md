<div align="center">

<img src="docs/assets/banner.svg" alt="irlume: face authentication for Linux" width="640">

<br>

**Your face unlocks Linux: login, `sudo`, the lock screen, and app prompts like
Bitwarden. Works in the dark. Your face is stored as a 512-D embedding, never as
an image, encrypted under a TPM-sealed key.**

An **IR (Windows Hello) camera** gives the full secure tier; a **regular webcam**
gives screen unlock; a **fingerprint reader** works alongside as a second factor.
The password is always the fallback, and there is no lockout.

<br>

[![License: GPL v3](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux-1f2328)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-dea584)
![Packaged](https://img.shields.io/badge/packaged-Fedora%20·%20Arch%20·%20Debian%2FUbuntu%20·%20NixOS-2ea44f)
[![Version](https://img.shields.io/github/v/release/archledger/irlume?label=version&color=c0304f)](https://github.com/archledger/irlume/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/archledger/irlume/badge)](https://scorecard.dev/viewer/?uri=github.com/archledger/irlume)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13671/badge)](https://www.bestpractices.dev/projects/13671)
[![AI-assisted](https://img.shields.io/badge/AI--assisted-human--directed-7c5cbf)](docs/FAQ.md)

[Install](#install) · [Limits](#honest-limitations) · [Docs](docs/) · [FAQ](docs/FAQ.md)

<br>

<img src="docs/assets/irlume-demo.gif" alt="irlume demo: install, guided face enrollment in the TUI, wiring the greeter and lock screen, and opt-in face-sudo" width="720">

</div>

---

> [!IMPORTANT]
> **A printed photograph of an enrolled face passes the built-in liveness gate.**
> Not occasionally: a life-size glossy print was accepted in 69 of 70 measured
> presentations, and the cue that should reject it cannot be tuned to.
> `irlume setup` offers a trained cue that does refuse it. Read
> [Honest limitations](#honest-limitations) before wiring this into anything
> that matters.

## What you get

- **Works in the dark.** Active infrared recognition on Windows Hello cameras; no
  ambient light needed.
- **Unlocks login, lock screen, `sudo`, and app prompts.** `sudo` and polkit are
  opt-in. The password always works, and there is no lockout.
- **Fires only when you ask.** Leave the password field empty and press Enter.
  Typing a password never starts a scan.
- **Opens your keyring.** On IR hardware a face match TPM-unseals the secret that
  opens your wallet: the KWallet key on KDE, or a token that re-keys the login
  keyring on GNOME. Your login password is not what is sealed.
- **No face images.** 512-D embeddings only, AES-256-GCM encrypted under a
  TPM-sealed key. Without a TPM they are root-only files, and the TUI says so.
- **Adapts to your hardware.** IR camera gives the secure tier, RGB-only gives
  screen unlock, a fingerprint reader coexists. All auto-detected.
- **Repairs itself.** `irlume tui` finds and one-key-fixes daemon, PAM, and camera
  faults, and a systemd watcher re-applies the PAM wiring when a distro update
  strips it.

[How it works](docs/ARCHITECTURE.md) · [What is stored, and how](docs/SECURITY_AT_REST.md)

## Install

**You need** x86-64 Linux with systemd and PAM. A TPM 2.0 is strongly recommended
(encrypted templates, keyring unlock) but not required. Any camera works; it sets
your tier.

```sh
curl -fsSL https://raw.githubusercontent.com/archledger/irlume/main/scripts/install.sh | sh
```

It picks the right source for your distro, installs a package only, and wires
nothing into your login. Read it first if you prefer:

```sh
curl -fsSL https://raw.githubusercontent.com/archledger/irlume/main/scripts/install.sh -o install.sh
less install.sh && sh install.sh
```

Or by hand:

```sh
# Fedora
sudo dnf copr enable archledger/irlume && sudo dnf install irlume

# Ubuntu (current release)
sudo add-apt-repository ppa:archledger/irlume && sudo apt install irlume

# Arch
yay -S irlume

# Debian 12+, older Ubuntu, and derivatives
sudo apt install ./irlume_*.deb    # from Releases
```

Then:

```sh
irlume doctor    # what your hardware supports
irlume tui       # guided enrollment and wiring
```

Every lane's package is also attached to each [release](https://github.com/archledger/irlume/releases),
signed, so you can install or roll back when a repository is unavailable.

On NixOS use `nixosModules.irlume` from this flake instead ([docs/NIXOS.md](docs/NIXOS.md)).
Full setup, including which lane suits which distro version, is in
[docs/SETUP.md](docs/SETUP.md).

## Honest limitations

- **A glossy printed photo defeats the built-in gate.** The
  [2026-06-30 self-test](docs/pad-results/2026-06-30-ir-liveness-selftest.md)
  accepted a life-size vinyl print in 69 of 70 presentations. The cue is a
  brightness ratio on a 2D infrared sensor, and a print held at an angle produces
  the same falloff a face does, so no threshold accepts the user and rejects the
  print. `irlume setup` offers a trained deny-only cue (`flir`) that refused the
  same print at p_fake 0.941 to 1.000, including when it was enhanced with an
  infrared-absorbing patch. irlume does not ship or warrant those weights,
  because their publisher documents neither the training data nor a way to
  reproduce the model ([ADR-0001](docs/adr/0001-liveness-pad-strategy.md)).
  Every miss falls safely to the password.
- **Bright infrared behind you rejects a genuine face.** The gate infers shape
  from how the emitter's light falls, and open sky or a hot lamp floods it. In a
  430-sample field session it was reliable below ambient ~120 on the 0-255 IR
  scale and rejected 129 of 129 genuine samples above ~170. The rejection names
  the condition and the fix.
- **Passive blink liveness misses glasses-wearers**, because IR lens reflections
  hide the eyelid.
- **RGB-only laptops get screen unlock only**, never `sudo`, login, or the
  keyring. By design.
- **Not lab-certified.** Self-tested against ISO/IEC 30107-3, with no iBeta pass.
  Demographic tuning ([FAIRNESS.md](docs/FAIRNESS.md)) is ongoing.
- **Root on the live machine is the trust boundary.** The daemon holds decrypted
  embeddings in RAM during a match, unlike Hello's VBS enclave. Disk theft is
  covered: templates copied to another machine fail to decrypt
  ([tested](docs/SECURITY_AT_REST.md)).

Every claim here maps to something you can run yourself: [docs/VERIFY.md](docs/VERIFY.md).

## Documentation

| I want to… | Go to |
|---|---|
| **Install and set up**, guided or by hand | [`docs/SETUP.md`](docs/SETUP.md) |
| Look up **every command and flag** | [`docs/COMMANDS.md`](docs/COMMANDS.md) |
| Read the **FAQ** | [`docs/FAQ.md`](docs/FAQ.md) |
| Understand the **architecture** | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| **Write software that drives irlume** | [`docs/INTEGRATION.md`](docs/INTEGRATION.md) · [`docs/MACHINE-API.md`](docs/MACHINE-API.md) |
| Choose a **third-party model** irlume has measured | [`docs/THIRD-PARTY-MODELS.md`](docs/THIRD-PARTY-MODELS.md) |
| Read the **threat model** and standards mapping | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) · [`docs/STANDARDS.md`](docs/STANDARDS.md) |
| **Verify the claims** on my own machine | [`docs/VERIFY.md`](docs/VERIFY.md) |
| **Debug** a login or trace every stage | [`docs/DEBUGGING.md`](docs/DEBUGGING.md) |
| **Contribute** and set up a dev shell | [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) |
| Run it on **NixOS** | [`docs/NIXOS.md`](docs/NIXOS.md) |
| See **what changed** in each release | [`CHANGELOG.md`](CHANGELOG.md) |

## Status

**v0.9.0, working on real hardware.** Fedora runs the full IR secure tier end to
end including face-approved Bitwarden prompts; Ubuntu runs the RGB convenience
tier with a fingerprint; Arch is validated on an IR camera and a USB webcam.
Packaged for Fedora, Arch, Debian/Ubuntu and NixOS. Interfaces may still shift
before 1.0.

Presentation attacks tested on a NexiGo N930W: laptop screen, phone screen at
full brightness, a video replay with head motion, and a matte-paper photo were
rejected at the infrared stage. A life-size glossy vinyl print was not; see
[Honest limitations](#honest-limitations). A physical 3D mask is untested, and
[contributions are welcome](CONTRIBUTING.md).

Per-release detail is in [`CHANGELOG.md`](CHANGELOG.md).

## Credits

The bundled models:

- **[YuNet](https://github.com/opencv/opencv_zoo)** (OpenCV Zoo, MIT) detects faces in both streams.
- **[AuraFace](https://huggingface.co/fal/AuraFace-v1)** by fal (Apache-2.0) is the 512-D ArcFace recognizer; irlume ships only its `glintr100.onnx`.
- **[MediaPipe FaceLandmarker](https://ai.google.dev/edge/mediapipe/solutions/vision/face_landmarker)** and **[BlazeFace short-range](https://ai.google.dev/edge/mediapipe/solutions/vision/face_detector)** (Google, Apache-2.0) supply the dense landmarks behind blink liveness, and the detection-rescue stage for saturated frames.

The TPM and camera code builds on:

- **[rust-tss-esapi](https://github.com/parallaxsecond/rust-tss-esapi)** (Parsec, Apache-2.0) wraps TPM 2.0 ESAPI; irlume builds from a small patch branch pinned to an exact commit.
- **[systemd](https://github.com/systemd/systemd)** (LGPL-2.1-or-later): the Tier-2 pcrlock seal follows the scheme in its `tpm2-util.c` and `pcrlock.c`.
- **[linux-enable-ir-emitter](https://github.com/EmixamPP/linux-enable-ir-emitter)** first showed the 850nm emitter can be driven from userspace over UVC Extension Units. irlume no longer uses its search technique, which destroyed a camera here ([#159](https://github.com/archledger/irlume/issues/159)).
- **[ort](https://github.com/pykeio/ort)** binds ONNX Runtime, which irlume loads at runtime.
- **[TensorFlow Lite](https://github.com/tensorflow/tensorflow)** (Apache-2.0) is bundled as a C runtime; its statically linked components are named in the notices beside it.

Prior art: **Windows Hello** for the infrared dual-sensor credential model, and
[Howdy](https://github.com/boltgolt/howdy) and [visage](https://github.com/sovren-software/visage)
as the existing Linux face-unlock projects. irlume is the from-scratch successor
to the author's earlier linhello.

*Windows and Windows Hello are trademarks of Microsoft Corporation. irlume is an
independent project, not affiliated with or endorsed by Microsoft; the marks are
used only to describe compatibility and prior art.*

## Contributing & license

**GPL-3.0-or-later.** Contributions welcome under the [DCO](CONTRIBUTING.md); no
CLA, no commercial relicensing. Security reports: [SECURITY.md](SECURITY.md).

Questions, setup help, and hardware reports go to
[Discussions](https://github.com/archledger/irlume/discussions); reports from
laptops with IR cameras, working or not, are the most useful contribution right
now. Bugs go to [Issues](https://github.com/archledger/irlume/issues).

> [!NOTE]
> **AI disclosure: assisted, human-directed.** irlume is built by a human
> maintainer working with an AI assistant (Anthropic's Claude), disclosed in the
> git history via `Co-Authored-By` trailers. Direction, review, and releases are
> human-driven; every release is validated with clean-slate installs on real
> hardware, and the security claims rest on reproducible evaluations in this
> repo.

<div align="center"><sub>Built with Rust · <a href="LICENSE">GPL-3.0-or-later</a> · your face stays yours</sub></div>
