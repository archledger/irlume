# irlume on NixOS

irlume ships a flake with two things a NixOS user needs: a source build of the
daemon and CLI (`packages.default`), and `nixosModules.irlume`, which runs the
daemon, opens the camera, and splices face auth into the PAM stacks you name.

The PAM control flags in the module are not defaults picked by feel. Each was
derived on a NixOS VM against the real greeter and lock-screen stacks, then
checked by logging in with a face and confirming the keyring unlocked without a
prompt. The matrix at the end of this file lists what was tested.

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

To bind the login password into the TPM so a face login also unlocks the wallet:

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
| `services.irlume.pam.services.<name>.profile` | auto | `"login"` or `"lock"`; override when a service name is not recognised. |

### How a service gets its control flag

Name a PAM service under `pam.services` and the module classifies it:

- Login greeters (`sddm`, `gdm-password`, `greetd`, `ly`, `login`) get
  `[success=1 default=ignore]`. This records the face success but skips exactly
  one rule, so `pam_kwallet` or `pam_gnome_keyring` still runs and unseals the
  wallet, and `pam_unix` grants on the token the daemon unsealed. Plain
  `sufficient` would short-circuit past the keyring and leave you with a locked
  wallet after login.
- Lock screens (`kde`, `swaylock`, `hyprlock`, `gtklock`, `waylock`) get
  `sufficient`. The wallet is already open in the live session, so there is no
  keyring handoff; and `pam_unix` on a verify-only unlock cannot grant, so a
  `success=1` jump would fall through to `pam_deny`. `sufficient` grants outright.

A name the module does not recognise defaults to the login profile. Set
`profile` yourself for anything unusual:

```nix
services.irlume.pam.services.my-custom-locker.profile = "lock";
```

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

The module runs on real hardware with both camera streams open at once. USB
passthrough into a QEMU/KVM guest cannot sustain concurrent RGB and IR
isochronous transfers, so set `sequentialCapture = true` in a VM. Leave it off
on bare metal, where concurrent capture is faster.

For the graphical console, use QXL (`-vga qxl`) or virtio without 3D
acceleration. virtio-vga-gl (`accel3d`) needs a local GL display and crashes a
headless SPICE host.

## Model weights and building from a remote flake

The four ONNX model files ship in the repository through Git LFS, and the
package installs them from the source tree into
`$out/share/irlume/models/`. Building from a local checkout works as long as the
LFS objects are present (`git lfs pull`), which they are after a normal clone
with git-lfs installed.

Fetching the flake straight from GitHub is the one case to watch: nix reads the
git tree without running the LFS smudge filter, so a `nix build github:archledger/irlume`
can land LFS pointer files instead of the real weights. Build from a checkout
that has run `git lfs pull`, or add the model files to your own flake inputs, if
you hit that. The daemon refuses to start on a truncated model when
`IRLUME_MODELS_STRICT=1` is set, so a pointer file fails loudly rather than
silently.

## What was validated

Every row below was exercised on a NixOS VM: log in or unlock with a face, then
confirm the keyring state. "keyring" means a browser launched afterward without
a keyring-unlock prompt.

| Surface | Service | Control | Keyring backend | Result |
| --- | --- | --- | --- | --- |
| Graphical login | `sddm` | `[success=1 default=ignore]` | KWallet | face login, wallet unlocked |
| Graphical login | `gdm-password` | `[success=1 default=ignore]` | gnome-keyring | face login, keyring unlocked |
| Text login | `greetd` | `[success=1 default=ignore]` + `kwallet.forceRun` | KWallet / gnome-keyring | face login, keyring unlocked (with wrapper on wlroots) |
| Text login | `ly` | `[success=1 default=ignore]` + `kwallet.forceRun` | KWallet | face login, wallet unlocked |
| Lock screen | `kde` | `sufficient` | already open | face unlock |
| Lock screen | `swaylock` | `sufficient` | already open | face unlock |
| Lock screen | `hyprlock` | `sufficient` | already open | face unlock |
