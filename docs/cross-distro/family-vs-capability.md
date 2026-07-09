# Family-awareness vs capability-detection (2026-07-02)

irlume adapts to the host two different ways. Choosing the right one per
concern is what keeps it correct across distros AND across machines within a
distro. The rule:

> **Detect the distro family when the difference is set by the distro's
> conventions. Detect the live capability when the difference is set by the
> machine's hardware or boot configuration.** Family is a proxy; when a real
> runtime signal exists, prefer it; a family guess can be wrong within a family.

## Family-determined (use `distro_family()`)

These genuinely differ by distro convention and are stable for all installs of
that family. irlume already branches on `platform::distro_family()` here:

| Concern | Fedora | Debian/Ubuntu | Arch |
|---|---|---|---|
| Fingerprint PAM tooling | `authselect enable-feature` | `pam-auth-update` | manual stanza |
| Greeter PAM stack style | jump (`success=N`) | `@include` branch | plain |
| Default LSM policy shipped | SELinux module | AppArmor profile | (none) |
| PAM module dir (packaging) | `/usr/lib64/security` | `/usr/lib/x86_64-linux-gnu/security` | `/usr/lib/security` |
| onnxruntime sourcing (packaging) | bundled in the RPM | bundled in the .deb | system pkg |
| Package format | rpm/Copr | .deb (GitHub Releases) | prebuilt .pkg.tar.zst (AUR pending) |

## Capability-determined (use runtime detection, NOT family)

These vary **per machine**, often *within* one family, so a family rule is
wrong. irlume detects the live condition instead:

| Concern | How detected | Why not family |
|---|---|---|
| Camera tier (Secure/Convenience/none) | probe RGB+IR nodes | any distro, any camera combo |
| TPM present | `/dev/tpmrm0` | desktop vs VM vs old board |
| Secure Boot on/off | EFI var | firmware setting |
| **Signed-PCR seal usable** | **seal→unseal round-trip** | **boot loader (UKI vs GRUB), not distro** |
| Fingerprint reader | fprintd + reader probe | hardware |

### Signed-PCR policy follows boot config, not family

Measured live across all three boxes (`/run/systemd/tpm2-pcr-*`):

| Box | Family | Signed-PCR artifacts present? |
|---|---|---|
| Zenbook | Fedora | **no** → literal PCR-7 |
| ThinkPad | Ubuntu | **no** → literal PCR-7 |
| archhost | Arch | **yes** (but GRUB boot ⇒ don't match the live PCRs) |

The *only* box with signed artifacts is the Arch one, the opposite of the
"Fedora/UKI has them" intuition. A family rule would misfire in every
direction. So irlume seals via the signed path only if the sealed envelope
**actually round-trips** (`tpm::seal` test-unseals before trusting it), else
falls back to literal PCR-7. This is correct on every machine regardless of
family or boot loader (fix committed `e1e7cf1`; caught the archhost enrollment
failure live).

## What to add (packaging phase)

Family-awareness is the right tool for the packaging layer still ahead:
per-family PAM module install dir, onnxruntime dependency, and post-install
PAM wiring. A small `irlume doctor` line printing the detected family + the
choices it implies would make the adaptation transparent (candidate).

Capability-detection stays the tool for everything the daemon does at runtime;
it already is, and the TPM round-trip is the model to follow for any future
"does this actually work here?" decision.
