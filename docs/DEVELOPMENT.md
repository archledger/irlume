# Developing irlume

This guide gets you from a fresh clone to a working build. There are two paths:

- **[Nix](#option-a--nix-recommended)** — one command, identical on every
  distro, nothing installed globally. Recommended.
- **[Manual, per distro](#option-b--manual-per-distro)** — install the build
  dependencies yourself with `dnf` / `apt` / `pacman`.

For *what* you're building (the daemon/PAM/CLI split and the model pipeline),
read [`ARCHITECTURE.md`](ARCHITECTURE.md). For the contribution rules (DCO,
biometric-data and model-license policy, PAD self-tests), read
[`../CONTRIBUTING.md`](../CONTRIBUTING.md).

## Get the source (with model weights)

The ONNX models live in **Git LFS**, so a plain clone gives you pointer stubs,
not real weights. You need the weights to *run* irlume or run tests that load a
model (you can compile without them).

```sh
git clone https://github.com/archledger/irlume.git
cd irlume
git lfs install
git lfs pull            # fetch the real models/*.onnx
```

## Option A — Nix (recommended)

### 1. Install Nix (once)

The [Determinate Systems installer](https://determinate.systems/) turns on
flakes by default and is cleanly uninstallable:

```sh
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

Open a new shell afterwards so `nix` is on your PATH.

### 2. Enter the dev shell and build

```sh
nix develop            # drops you into a shell with the whole toolchain
cargo build --release
```

The first `nix develop` writes a `flake.lock` pinning every input to an exact
commit — **commit that file** so everyone (and CI) gets identical tooling.

### What the flake pins for you

Everything irlume's messy build needs, so you don't hunt distro packages:

| Pinned by the flake | Why |
| --- | --- |
| Rust (MSRV from `Cargo.toml`) | edition/toolchain floor via the `ort` binding |
| `pkg-config` + `tpm2-tss` | the `tss-esapi` crate finds the TPM libs |
| `clang` + `libclang` (`LIBCLANG_PATH`) | `v4l2-sys-mit`'s bindgen needs it |
| kernel headers (`BINDGEN_EXTRA_CLANG_ARGS`) | bindgen parses `<linux/videodev2.h>` |
| `linux-pam` | the `pamsm` crate links `libpam` |
| onnxruntime **1.24.4** (`ORT_DYLIB_PATH`) | irlume needs the `api-24` ABI; nixpkgs' is older |

To bump the toolchain or nixpkgs later: edit the version string in `flake.nix`
or run `nix flake update`, then commit the changed `flake.lock`.

### Optional: auto-activation with direnv

If you use [direnv](https://direnv.net/) with
[nix-direnv](https://github.com/nix-community/nix-direnv), drop an `.envrc`
containing `use flake` in the repo root and the shell loads automatically when
you `cd` in.

## Option B — Manual, per distro

Install the build dependencies, then use `cargo` as usual.

**Fedora**

```sh
sudo dnf install cargo rust clang-devel pkgconf-pkg-config gcc \
    pam-devel tpm2-tss-devel kernel-headers git-lfs
```

**Ubuntu / Debian** — the archive's `rustc` is usually too old (the `ort`
binding needs Rust ≥ 1.88), so install the toolchain with
[rustup](https://rustup.rs/):

```sh
sudo apt install build-essential pkg-config clang libclang-dev \
    libpam0g-dev libtss2-dev git-lfs
rustup toolchain install 1.88.0   # or newer stable
```

**Arch**

```sh
sudo pacman -S --needed base-devel rust clang tpm2-tss pam onnxruntime-cpu git-lfs
```

### ONNX runtime (non-Nix)

irlume needs onnxruntime **≥ 1.24** (the `api-24` ABI) and loads it dynamically
at runtime. Arch's `onnxruntime-cpu` package is new enough. On Fedora/Ubuntu the
distro build is older, so fetch the upstream release and point `ORT_DYLIB_PATH`
at it:

```sh
curl -fsSLO https://github.com/microsoft/onnxruntime/releases/download/v1.24.4/onnxruntime-linux-x64-1.24.4.tgz
tar xzf onnxruntime-linux-x64-1.24.4.tgz
export ORT_DYLIB_PATH="$PWD/onnxruntime-linux-x64-1.24.4/lib/libonnxruntime.so"
```

## Build, lint, test, run

```sh
cargo build --release
cargo clippy                    # required before a PR
cargo fmt                       # required before a PR
cargo test
cargo run -p irlume-cli -- doctor   # platform / TPM / camera / model check
```

Developer-only benchmark and capture subcommands are gated behind `IRLUME_DEV=1`
(e.g. `IRLUME_DEV=1 cargo run -p irlume-cli -- selftest align --model models/glintr100.onnx`).

## What the dev shell can't do: real-hardware testing

The build shell compiles and runs the code, but the security-critical paths —
**an IR camera, TPM sealing, PAM wiring, greeter/lock integration, SELinux** —
can only be exercised on a physical machine. For enrolling, wiring a greeter,
and end-to-end login/lock/sudo testing on real hardware, follow
[`SETUP.md`](SETUP.md). To build the distro packages (RPM/`.deb`/Arch), see the
recipes under [`../packaging/`](../packaging/). Liveness/PAD changes must ship
with an ISO/IEC 30107-3 self-test — see [`PAD_SELFTEST.md`](PAD_SELFTEST.md).

## Project layout

Crate roles (details and the privilege-separation diagram are in
[`ARCHITECTURE.md`](ARCHITECTURE.md)):

| Crate | Role |
| --- | --- |
| `irlume-common` | shared types / IPC request-response protocol |
| `irlume-camera` | V4L2 capture + IR emitter control |
| `irlume-vision` | detection / recognition (ONNX via `ort`) |
| `irlume-liveness` | anti-spoof / presentation-attack detection |
| `irlume-core` | matching, encrypted template storage, TPM-bound secret release (`tss-esapi`) |
| `irlume-auth` | shared authentication orchestration (the security-critical decision flow) |
| `irlume-fingerprint` | optional fprintd companion factor |
| `irlume-daemon` | privileged `irlumed` — the only thing that touches hardware |
| `irlume-pam` | `pam_irlume.so` — the untrusted PAM client |
| `irlume-cli` | the `irlume` command + guided TUI |

## Before you open a PR

Sign your commits (DCO — see [`../CONTRIBUTING.md`](../CONTRIBUTING.md)):

```sh
git commit -s -m "your message"
```

and make sure `cargo fmt`, `cargo clippy`, and `cargo test` are clean.
