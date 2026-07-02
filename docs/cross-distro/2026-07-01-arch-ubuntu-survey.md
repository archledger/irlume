# Cross-distro survey — Arch + Ubuntu first install, 2026-07-01

First run of irlume outside Fedora. Live testing over ssh on real hardware:

| | **Fedora 44** (Zenbook S14) | **Arch** (archhost, desktop) | **Ubuntu 26.04 LTS** (ThinkPad X13 Yoga G4) |
|---|---|---|---|
| Camera | RGB + IR (Secure tier) | none | RGB-only Chicony (Convenience tier) + Synaptics fingerprint |
| Build | reference | **clean, 1m30s, 17/17 suites** | **clean, 2m05s, 17/17 suites** |
| onnxruntime | 1.24.4 (own Copr) | 1.24.4 system (`/usr/lib`, w/ CUDA EPs) | repo had only 1.22 → installed official MS 1.24.4 tarball to `/opt/onnxruntime-1.24.4` (`api-24` pin needs ≥1.24) |
| Toolchain deps | — | pam headers, tss2, clang all present | ditto (`libpam0g-dev`-equivalent, tss2 present) |
| LSM | SELinux (module shipped) | none by default | **AppArmor on** (daemon unconfined — profile TODO) |
| PAM manager | authselect | plain `/etc/pam.d` (+ `/usr/lib/pam.d` overrides) | `pam-auth-update` + `@include common-auth` |
| Greeter detected | plasmalogin | sddm + plasmalogin | gdm-password |
| Daemon install | reference | `scripts/install-host.sh` → active first try | ditto |
| `login enable` dry-run | shipped | ✓ correct plan incl. `/usr/lib/pam.d` materialization | ✓ correct plan (gdm-password + backup) |
| `identify` smoke | full stack | clean refusal (no camera) | RGB capture ran, clean "no face" |
| Fingerprint | n/a | n/a | reader + 2 enrolled fingers detected via fprintd |

**Headline: zero code changes needed to build and run on either distro.**
The portability costs were environmental only: onnxruntime version sourcing
(Ubuntu) and packaging-layer gaps (AppArmor profile, unit file distribution).

## Install points (what a package must provide per distro)

1. Binaries `irlumed`/`irlume` + `pam_irlume.so` (PAM dir differs:
   Fedora `/usr/lib64/security`, Arch `/usr/lib/security`,
   Ubuntu `/usr/lib/x86_64-linux-gnu/security`).
2. `irlumed.service` (currently hand-written per host — move a template into
   `packaging/systemd/`; `scripts/install-host.sh` generates it today).
3. Models: 265 MB — too big for most package payloads; needs a first-run
   `irlume models fetch` (checksummed) or a separate -data package.
4. onnxruntime ≥1.24: Fedora = own Copr pkg; Arch = system package already
   current; Ubuntu = **no usable archive version** → bundle, vendor a fetch
   step, or document the MS tarball (what this survey did).
5. LSM policy: SELinux module (Fedora, exists) / AppArmor profile (Ubuntu,
   **TODO**) / none (Arch).
6. Config `/etc/irlume/`, state dirs, socket — same everywhere (systemd).

## Configure points

- `irlume login enable --apply` already handles all three PAM layouts
  (verified by dry-run on each). sudo wiring separate.
- Enrollment/TUI identical across distros (socket + daemon).
- Per-tier behavior held on real foreign hardware: Convenience
  recommendation on RGB-only ThinkPad, password-only on camera-less Arch.

## Test points (regression list for any release)

build+tests → daemon start (models/ORT load) → `identify` smoke →
`login enable` dry-run → TUI screen-set per capability tier → (hardware
permitting) enroll + verify + lockscreen.

## TUI/UX findings from this survey (F1–F14)

1. **F1** `cameras rgb=... ir=...` startup log prints the hardcoded fallback
   pair even when the nodes don't exist (both hosts) — log selected AND
   validated capability tier instead.
2. **F2 (bug)** Welcome `[e]` jumps to Profiles + opens the enroll modal on a
   camera-less box — bypasses the screen-visibility capability filter.
3. **F3 (bug)** Repair "Models: missing" checks a CWD-relative `models/` path;
   daemon had them loaded. Repair should ask the daemon (it knows its env).
4. **F4** Repair "✗ Cameras need both RGB and IR" — should be tier-aware
   (RGB-only ⇒ "Convenience tier available"; none ⇒ informational).
5. **F5** Repair diagnosis says "N fail" and "→ no action needed" together.
6. **F6** "Recovery backstop ✓ plaintext (no TPM…)" wording contradicts the
   platform line "TPM ✓" (state vs hardware conflated).
7. **F7** Login wiring shows "SELinux module: unknown" on Arch (no SELinux)
   and Ubuntu (AppArmor) — detect the LSM and show the relevant row.
8. **F8** Done screen says "All set." regardless of state.
9. **F9** ✓ PAM service presence detection correct on all three distros.
10. **F10** `login enable` doesn't warn when no camera exists (wiring face
    auth on a box that can't do face auth).
11. **F11** Cameras screen: "no RGB+IR pair found" and "active /dev/video0 +
    /dev/video2" shown together (phantom fallback, same root as F1).
12. **F12** Cameras screen can't show/select an RGB-only camera even though
    the Convenience tier supports it.
13. **F13 (bug)** Repair "✗ ONNX Runtime not found" while the daemon runs
    with ORT loaded from its unit env (static path probe; same class as F3).
14. **F14** Nonexistent camera node error reads "no physical device in sysfs
    (virtual camera?)" — should say "no camera found" when the node is absent.

Positive: adaptive screen sets correct on both (5 vs 10), recommendation
lines accurate, fingerprint integration worked untouched on Ubuntu,
`/usr/lib/pam.d` materialization already encoded, wrap-around nav clean.

## Distribution strategy (draft — verify specifics at implementation)

- **Fedora**: RPM in Copr built from GitHub via Packit on signed tags —
  same proven pipeline as linhello. `irlume update` → dnf/Copr.
- **Arch**: AUR `PKGBUILD` (build from the release tag; `-bin` variant
  optional later). Self-updating binaries fight pacman's model — let the
  AUR helper own updates; `irlume update` on Arch = "check + print the AUR
  command".
- **Ubuntu/Debian**: no PPA needed initially — host a signed apt repo (e.g.
  GitHub Pages/Releases) or ship a .deb from GitHub Releases with
  `irlume update` handling check+download+apt-install. Must solve
  onnxruntime ≥1.24 (bundle in the .deb or a -ort companion package).
- Models: distribute via `irlume models fetch` (checksummed download) in all
  three, keeping packages small.
