# irlume on NixOS

irlume ships a flake with two things a NixOS user needs: a source build of the
daemon and CLI (`packages.default`), and `nixosModules.irlume`, which runs the
daemon, opens the camera, and splices face auth into the PAM stacks you name.

The PAM control flags in the module were derived on a NixOS VM against the
greeter and lock-screen stacks when the module was added, with a sealed login
password. That matrix has not been re-run since, so it is unverified; the end
of this file lists what it covered. On NixOS irlume supports the login password
kind of keyring unlock only (see "Keyring unlock").

## Requirements

- A NixOS system with flakes enabled.
- An IR-capable camera (an RGB node plus an IR node, e.g. a Windows Hello webcam).
- A TPM 2.0 device if you want the daemon to seal the login password (the
  keyring-unlock path). Face-only auth works without a TPM.

## Add the flake

```nix
# flake.nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.irlume.url = "github:archledger/irlume";
  inputs.irlume.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { self, nixpkgs, irlume }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        irlume.nixosModules.irlume
        ./configuration.nix
      ];
    };
  };
}
```

## Configure

The smallest working config: enable the daemon, then name the PAM services you
want face auth on. A graphical login greeter and its matching lock screen is the
common pair.

```nix
# configuration.nix (Plasma / SDDM example)
services.irlume = {
  enable = true;
  rgbDevice = "/dev/video0";   # your RGB node
  irDevice  = "/dev/video2";   # your IR node
  pam.services = {
    sddm = { };   # graphical login  -> face unlocks the wallet on login
    kde  = { };   # Plasma lock screen -> face unlocks it
  };
};
```

Enroll after the first boot:

```
sudo irlume enroll --user $USER
irlume doctor          # camera, models, daemon, TPM state
```

To bind the login password into the TPM so a face login also unlocks the wallet
(see "Keyring unlock" for which accounts can):

```
sudo irlume keyring arm
```

## Options

| Option | Default | What it does |
| --- | --- | --- |
| `services.irlume.enable` | `false` | Runs `irlumed` and installs the CLI. |
| `services.irlume.package` | source build | The irlume package (override to pin your own). |
| `services.irlume.rgbDevice` | `/dev/video0` | V4L2 node for the RGB camera. |
| `services.irlume.irDevice` | `/dev/video2` | V4L2 node for the IR camera. |
| `services.irlume.sequentialCapture` | `false` | Capture RGB then IR instead of both at once. Set this only inside a VM (see below). |
| `services.irlume.pam.services.<name>` | `{}` | Adds face auth to PAM service `<name>`; picks the control flag from the name. |
| `services.irlume.kcm.enable` | `false` | Installs the Plasma System Settings module (read-only status and launch actions; see [KCM.md](KCM.md)). Requires a Plasma 6 session; off by default pending a NixOS loading verification (nixpkgs#296999). |
| `services.irlume.kcm.package` | source build | The irlume-kcm package (override to pin your own). |
| `services.irlume.pam.services.<name>.profile` | auto | `"login"` or `"lock"`; override when a service name is not recognised. |

### How a service gets its control flag
Name a PAM service under `pam.services` and the module classifies it:

- Login greeters (`sddm`, `gdm-password`, `greetd`, `ly`, `login`) get
  `[success=1 default=ignore]`. This records the face success but skips
  exactly one rule, so `pam_kwallet` or `pam_gnome_keyring` still runs and
  unseals the wallet, and `pam_unix` grants on the token the daemon
  unsealed. Plain `sufficient` would short-circuit past the keyring and
  leave you with a locked wallet after login.
- Lock screens (`kde`, `swaylock`, `hyprlock`, `gtklock`, `waylock`) get
  `sufficient`. The wallet is already open in the live session, so there
  is no keyring handoff; and `pam_unix` on a verify-only unlock cannot
  grant, so a `success=1` jump would fall through to `pam_deny`.
  `sufficient` grants outright.

A name the module does not recognise defaults to the login profile. Set
`profile` yourself for anything unusual:

```nix
services.irlume.pam.services.my-custom-locker.profile = "lock";
```

### Where the face line goes

The module renders the jump form FHS distros get from
`irlume login enable`: the face line's success skips exactly one rule, so
its placement is derived from the rendered stack and every layout where
that jump cannot be proven safe is rejected at evaluation time with a
message naming the conflicting rule. Current nixpkgs renders SDDM's
authentication as `substack login` rather than a flat module chain, and
for such a service the face line goes immediately before the password
substack (several substacks are disambiguated by the known password stack
names, so an earlier policy substack still runs above the face line) with
a `pam_permit.so` landing immediately after it: an empty Enter runs the
face scan first, a face success jumps over the whole substack (whose
`pam_unix` would fail on that same empty password) and lands on the
permit, and the login grants; the required-by-default substack keeps a
failed password attempt fatal, so the permit cannot authenticate a
failure. On a flat chain the face line sits immediately before the
password-prompting `pam_unix` and no landing is rendered: the jump skips
that prompt, and the keyring module plus the `try_first_pass` `pam_unix`
still see the released token. Lock screens stay a single `sufficient`
line.

Evaluation refuses, instead of rendering a broken stack: substacks
without exactly one known password stack among them (a lone unrecognized
substack may be a policy stack, not a password carrier), an order slot
another rule occupies or shares, a numeric jump on an existing rule whose
destination the new rules would change (any `word = N` action in a
bracketed control, including landing exactly on it), a required gate
(such as `pam_nologin` or `pam_faillock`) inside the substack the jump
would skip or behind a nested `include`/`substack` delegation of it, an
extended control or a delegation that cannot be resolved (by file path,
cyclic, or to an unknown service), and a password stack with no required
rule at all, where a failed password would leave no fatal failure behind.

A flat chain with only one `pam_unix` (no keyring or second-unix trigger
in its stack) cannot complete a greeter face grant: the jump would skip
the only rule that grants. A face attempt there still verifies and falls
back to the password.

## PAM changes go through the module

The system configuration generates `/etc/pam.d`, and the next rebuild replaces
any edit, so on NixOS `irlume login enable` and `irlume login disable` exit with
an error that points here, with or without `--apply`, and `irlume login
reconcile` reports nothing to do. The TUI runs the same commands and shows the
same message. Add or remove a service under `services.irlume.pam.services` and
rebuild. `irlume login status` still reports the stacks, and where it or
`irlume doctor` finds no login screen wired, it names that option, not `irlume
login enable`.

## Password-verified retry recovery

The matching Nix package and module stage the password verifier at
`/run/irlume-recovery/irlume-password-verify` before starting the daemon.
The directory is root-owned `0700`; the regular helper file is `0755` and
comes from the selected package. Stopping the service removes that runtime
directory, and the next start stages the selected generation's helper.
If a pinned or custom package omits the verifier, the daemon still starts,
but self-service retry recovery is unavailable. Startup removes any stale
runtime verifier rather than using one from a different package.

The dedicated `/etc/pam.d/irlume-retry-reset` service is copied as a
root-owned `0644` file. These paths satisfy the daemon's existing ancestry
checks without exceptions for `/nix/store`, whose normal `1775` mode has a
group-write bit even when the store is mounted read-only. The verifier's
trust checks and the daemon's privilege restrictions remain in force.

The disposable-VM regression exercises local-password reset, wrong-password
refusal, unsafe-mode rejection, runtime-helper cleanup/recreation and a
package override that omits the verifier:

```sh
nix build .#checks.x86_64-linux.irlume-retry-recovery --no-link
```

## Keyring unlock

On NixOS irlume seals only the login password, the kind the module's PAM rules
were written for.

On other distributions irlume seals a KDE wallet key for an account with a KDE
wallet, and re-keys a GNOME login keyring to a random token. Both need PAM
rules the module does not add yet, a session-phase `pam_irlume.so reseal` rule
among them. So on NixOS `irlume keyring arm`, `irlume reseal`, the keyring step
of `irlume setup` and the TUI's Password Wallet refuse, and seal nothing, for
an account that has or would get either kind:

- an account with a KDE wallet and no GNOME login keyring (a wallet key);
- an account with a GNOME login keyring and no KDE wallet (a token).

An account with neither wallet, or with both, gets the login password, and an
account whose login password is already armed keeps it when it re-arms or
reseals. `irlume keyring forget` removes a wallet key or token armed earlier; a
token is re-keyed back to your password first. As on every distribution, irlume
does not arm over a sealed secret irlumed cannot read; on NixOS `keyring arm`,
`reseal` and the setup step say so before asking for the password. Without an
arm, irlume leaves the wallet to the rest of the PAM stack.

## greetd on a wlroots compositor (Sway, Hyprland)

Two extra points apply when the greeter is greetd and the session is a wlroots
compositor using gnome-keyring.

First, greetd and ly are text-mode; PAM does not see them as a graphical
session, so `pam_kwallet` skips itself. The module sets `kwallet.forceRun = true`
for these greeters automatically when they opt in, so KWallet still unseals.

Second, greetd does not export the keyring's control socket into the session, so
a second, locked gnome-keyring spawns and applications prompt for a keyring
password at launch. The module exposes a wrapper that starts one keyring and
pushes its environment into the session. Wrap your compositor command with it:

```nix
services.greetd.settings.default_session.command =
  "${pkgs.greetd.tuigreet}/bin/tuigreet --time --remember "
  + "--cmd '${config.services.irlume.keyringSessionWrapper} Hyprland'";
```

The wrapper starts `gnome-keyring-daemon` with the `secrets`, `ssh`, and
`pkcs11` components, then runs `dbus-update-activation-environment` so systemd
user services and dbus activation see `GNOME_KEYRING_CONTROL`. After that a
browser launches without a keyring prompt.

GNOME with GDM does not need the wrapper: GDM starts the keyring and exports its
environment on its own.

## Testing in a VM

On real hardware the module opens both camera streams at once when a measured
verdict allows it; an unmeasured pair captures one stream at a time. USB
passthrough into a QEMU/KVM guest cannot sustain concurrent RGB and IR
isochronous transfers, so set `sequentialCapture = true` in a VM, which pins
the order whatever the measurement stored. Leave it off on bare metal, where
concurrent capture is faster.

For the graphical console, use QXL (`-vga qxl`) or virtio without 3D
acceleration. virtio-vga-gl (`accel3d`) needs a local GL display and crashes a
headless SPICE host.

## Model weights and building from a remote flake

The six ONNX model files plus the TFLite mesh are
fetched by the flake from the `models-v1` GitHub
release as hash-pinned `fetchurl` inputs, and the package installs them into
`$out/share/irlume/models/`. Because they are fixed-output fetches keyed by
sha256 (not Git LFS), `nix build github:archledger/irlume` gets the real weights
with no smudge-filter caveat and no LFS bandwidth cost. The daemon still refuses
to start on a truncated model when `IRLUME_MODELS_STRICT=1` is set.

## Native .tflite models need `IRLUME_TFLITE_LIB`

The FHS packages (Fedora, Arch, Debian, PPA) bundle the TFLite C runtime,
`libtensorflowlite_c.so`, at `/usr/share/irlume/tflite/`, the first path the
daemon's resolver probes. The Nix package does not bundle it yet, so to run
native `.tflite` models set `IRLUME_TFLITE_LIB` to the library's path in the
daemon's environment (`systemd.services.irlumed.environment`). Without it,
`.tflite` support reports "runtime not installed" and everything else keeps
working; a missing runtime is never a startup failure.

## What was tested (unverified)

The rows below were exercised on a NixOS VM when the module was added (#5, July
2026): log in or unlock with a face, then confirm the keyring state. "keyring"
means a browser launched afterward without a keyring-unlock prompt. Every row
used a sealed login password, before irlume could seal a KDE wallet key or a
GNOME keyring token (#253, #256). The matrix has not been re-run since against
the current module, irlume or nixpkgs, so no row is a current result, and only
the login password kind is supported (see "Keyring unlock").

Live host checks on 2026-09-29 (NixOS 26.05, SDDM 0.21, Plasma 6.6, BRIO
RGB+IR, irlume 0.15.0 from merged main) verified enrollment, camera
qualification, the `kde` lock-screen face unlock, liveness rejections and the
password fallback on every surface. SDDM greeter face login on that nixpkgs
failed before this module rendered the substack-aware placement: the daemon
matched the face (0.93) and unsealed the sealed password, but the old rule
order could not complete the grant. The rendered layouts are asserted at
eval time in the flake's `irlume-module` check; a live greeter re-test with
the corrected placement is still pending.

| Surface | Service | Control | Keyring backend | Result |
| --- | --- | --- | --- | --- |
| Graphical login | `sddm` | `[success=1 default=ignore]` | KWallet | face login, wallet unlocked |
| Graphical login | `gdm-password` | `[success=1 default=ignore]` | gnome-keyring | face login, keyring unlocked |
| Text login | `greetd` | `[success=1 default=ignore]` + `kwallet.forceRun` | KWallet / gnome-keyring | face login, keyring unlocked (with wrapper on wlroots) |
| Text login | `ly` | `[success=1 default=ignore]` + `kwallet.forceRun` | KWallet | face login, wallet unlocked |
| Lock screen | `kde` | `sufficient` | already open | face unlock |
| Lock screen | `swaylock` | `sufficient` | already open | face unlock |
| Lock screen | `hyprlock` | `sufficient` | already open | face unlock |
