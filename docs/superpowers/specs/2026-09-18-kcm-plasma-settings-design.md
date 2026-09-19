# KCM: a Plasma System Settings module for irlume

Status: the agreed dashboard and TUI launch-action scope shipped in v0.14.0.
Tracks issue #762. Agent: opencode. Date: 2026-09-18. Revision 2 incorporates the
adversarial review pass (target naming, flock-based guard, contract-correct
Cameras page, pkexec path pinning, dependency and packaging corrections).
Research baseline: `artifacts/irlume/2026-09-18-kcm-research/RESEARCH.md`
(shared ledger artifacts; the KF6/KCM facts are from develop.kde.org's KCM
tutorial and KF6 porting guide, fetched 2026-09-18).

## Implementation status (2026-09-19)

- Phase 0 shipped in PR #763: TUI page deep links and the single-instance guard.
- Phase 1 shipped in PR #764, with hands-on and API corrections in #765 and #766.
  Fedora, Arch, and Ubuntu 26.04 PPA packages shipped in v0.14.0; #767 added PPA
  and Nix packaging, and #771 corrected the Arch split-package function.
- The Phase 2 hands-on polish is delivered. English-only UI remains the chosen
  default, matching the rest of the application.
- The original issue's broader proposal was narrowed by this reviewed design:
  capture, enrollment, wallet, recovery, and login mutations use the existing TUI.
  Native privileged controls in optional Phase 3 are not an outstanding delivery
  requirement. A concrete usage need and a separate ADR would reopen that work.
- NixOS exposes `services.irlume.kcm.enable`, default off. Runtime loading still
  needs a NixOS host; this documented limitation was accepted for v0.14.0.
- Validation includes the user-accepted Fedora walkthrough, installed Arch KCM
  loadtest against the real daemon, hosted Fedora/Arch loadtests, and clean
  Ubuntu 26.04 package installation and QML loading. See [KCM.md](../../KCM.md)
  for the supported interaction model.

The design below records the reviewed architecture and optional future scope.

## Objective

Give irlume a native desktop settings presence by shipping a KDE
Configuration Module (KCM) that appears inside Plasma's System Settings. The
KCM is a read-only dashboard over the existing machine API plus launch
actions that hand interactive work to the TUI. The GUI holds no policy logic;
every value shown comes from `irlume --json` output, every change happens in
the TUI (Phase 1-2) or through a pkexec'd CLI call (Phase 3, trivial toggles
only).

Why KDE first and only: Plasma is the only major desktop with a supported
third-party System Settings module story, and it is irlume's deepest
validated desktop (lock screen wiring, kwallet integration, kscreenlocker).
GNOME has no stable third-party equivalent; a GNOME panel is out of scope.

## Non-goals

- No policy, matching, or authorization logic in the GUI layer. Ever.
- No KAuth helper: it would be a new D-Bus-activated root process. KF6
  removed the old KCM auth API anyway. Privilege stays where it is today:
  the daemon wire, pkexec, and the two shipped polkit actions.
- The KCM never edits PAM or any file directly. No exceptions.
- The TUI remains the full-featured interactive surface; the KCM does not
  replicate its flows.
- No native enrollment camera UI. Enrollment happens in the TUI.

## Architecture

### Component: `kcm_irlume`

New top-level `kcm/` directory in the repo (sibling of `crates/`; not a
cargo member). Build: CMake >= 3.16 + ECM, C++20, Qt6 >= 6.5
(Core, Quick, Gui, Qml), KF6 >= 6.0 (Config, CoreAddons, KCMUtils, I18n,
KIO for the desktop-entry launch).

One C++ source pair, ~tens of lines, doing nothing but satisfying the plugin
contract and providing the process bridge:

- `IrlumeKcm : KQuickConfigModule`, registered with
  `K_PLUGIN_CLASS_WITH_JSON` against `kcm_irlume.json`.
- A small `IrlumeProcess` helper (QProcess wrapper): runs
  `irlume <args> --json --contract 1`, captures stdout/stderr, surfaces
  exit code and completion. No parsing beyond JSON document boundaries. The
  irlume binary is resolved once at startup (prefer the packaged absolute
  path, e.g. `/usr/bin/irlume`, falling back to
  `QStandardPaths::findExecutable`); a fixed path is used for all execs.
- Metadata `kcm_irlume.json`: Name "irlume", Description "Face
  authentication", Icon `io.github.archledger.Irlume`, FormFactors
  `["desktop"]`, `X-KDE-System-Settings-Parent-Category` (decision below),
  `X-KDE-Keywords` = face, login, authentication, biometric, camera, IR.

Everything visible is QML (`ui/`), built and bundled by
`kcmutils_add_qml_kcm(kcm_irlume)` which also installs into the
`plasma/kcms/systemsettings` namespace and generates the .desktop entry.
The CMake target name IS the plugin name: `kcm_irlume.so`,
`kcm_irlume.json` (the desktop-file generator requires the JSON basename to
match the target), and `kcmshell6 kcm_irlume` for standalone testing.
Root components: `SimpleKCM` + Kirigami form layouts (Kirigami is an
explicit runtime dependency on every lane; kcmutils' QML sits on it).

### Differences from the research phase plan

The research pass sketched a larger Phase 1; three surfaces are deliberately
out of this design: `auth test` (it captures; the KCM is read-only),
`models list` (operator-facing detail, available via the TUI), and retry
state (no machine capability exists for it; adding one would be a contract
change with its own review). The research's "Phase 2 writes" is Phase 3
here, after the launch-action model landed in between.

### Pages (Phase 1)

1. **Overview** - `irlume status --json`: daemon, enrollment, keyring,
   templates, recovery, sensor-policy rows rendered as a Kirigami form;
   launch buttons open the corresponding TUI screens.
2. **Diagnostics** - `irlume doctor --json`: checks grouped pass/warn/fail
   with remediation text verbatim from the document; conditionally-present
   ids (camera-groups, pam-faillock) rendered only when present. The
   pam-regeneration-guard state comes from this document (it is a doctor
   check id, not a login-status field).
3. **Cameras** - `irlume camera census --json`: the classification table.
   Read-only capability per the contract (it performs read-only node opens
   and sysfs walks, no streaming, no daemon). The CONFIGURED pair is not
   shown: contract 1 deliberately publishes camera capability without
   identity, so "active pair" is out of scope unless a census-side
   configured-pair flag is added as its own contract proposal later.
4. **Login wiring** - `irlume login status --json`: wired surfaces, login
   manager, selinux module state.

Capability gating: on open, run `irlume version --json` once, assert the
echoed `contract_version` equals the requested one, gate pages on the
`capabilities` array (the exact negotiation INTEGRATION.md documents for
external consumers). Unknown capabilities are ignored, unknown pages are
hidden, never broken.

### Data flow rules

- One exec per view render. No polling loops, no timers. A manual refresh
  action per page. Typed refusals (`daemon-unavailable` etc.) render as
  state, never as an error dialog.
- Per-command UI timeouts: status uses the contract's 2-second deadline;
  doctor (checksums model weights) and census get explicit larger budgets
  with a progress indicator; each page names its budget.
- Machine error codes map to inline messages with their documented
  meanings; codes carrying `retryable: true` get a retry button.
- No value is ever rendered from anything other than a machine document.

## Launch actions: the core interaction model

Interactive and privileged work happens in the TUI, launched from the KCM:

- The KCM launches the **existing** desktop entry
  (`io.github.archledger.Irlume.desktop`, `Terminal=true`,
  `Exec=irlume tui`) via `KIO::ApplicationLauncherJob` on the resolved
  KService (KIO Gui is an explicit build + runtime dependency for this).
  Zero terminal-detection logic in C++; the shipped launcher already works
  on every lane.
- **Deep links**: where a button targets a specific screen, the KCM first
  tries `xdg-terminal-exec irlume tui --page <page>`; if that binary is
  absent it falls back to the desktop entry (no deep link). Konsole's
  xdg-terminal-exec support is a Phase 1 validation item on Plasma 6.
- Buttons and their targets (Phase 1): Enroll face / add scans ->
  `faces`; Camera pair selection -> `cameras`; Arm wallet -> `wallet`;
  Recovery passphrase -> `recovery`; Full diagnostics -> `diagnostics`.

## Rust-side prerequisites (Phase 0, shippable alone)

Two TUI features the launch model builds on, both in `irlume-cli`:

1. **`irlume tui --page <name>`** - start on a named page
   (`faces|cameras|wallet|recovery|diagnostics`), validated against the
   page registry, rejected with usage on unknown names. Help text updated;
   COMMANDS.md/TUI.md rows added.
2. **Single-instance guard with handoff** - so repeated KCM clicks cannot
   pile up terminals. The lock is a kernel-held `flock` on
   `$XDG_RUNTIME_DIR/irlume/tui.lock` (0600; directory 0700), the same
   pid-reuse-proof pattern the CLI already uses for machine-API session
   guards (`SessionGuard`, released by the kernel when the holder dies -
   no pid-file liveness heuristics, no /proc comm matching, no stale-lock
   takeover race):
   - On start, a new instance tries to take the flock. If it succeeds, no
     other TUI holds it: proceed (also bind the abstract Unix socket
     `\0irlume-tui-<uid>` as the handoff listener).
   - If the flock is held, the new instance connects to that socket and
     sends `goto:<page>` (or `focus:` when no page given), prints one line
     ("irlume is already running; switching it to <page>"), and exits 0.
   - If the flock is held but the connect FAILS (holder predates the
     socket, or is mid-startup), the new instance retries briefly, then
     proceeds WITHOUT the lock rather than refusing to start (guard is UX,
     never a lockout; the older instance keeps its page).
   - The listener accepts only same-uid peers, enforced with
     `SO_PEERCRED` on accept and a check of the received credentials.
     Abstract-namespace sockets carry no permission bits; the uid check is
     the enforcement, not the namespace.
   - The running instance polls the socket in its existing event-loop tick
     (the loop already polls input at a short interval) and navigates; a
     `goto` naming an unknown page is ignored (logged).
   - `--new` skips the guard entirely (no flock, no listener; documented
     escape hatch for parallel sessions and debugging).
   - No `$XDG_RUNTIME_DIR` (bare SSH): guard disabled, current behavior.
   - The channel is navigate-only: it can change the visible page,
     nothing else - no captures, no privileged actions, no settings writes.
     Phase 0 ships with tests pinning that the socket accepts only
     `goto:`/`focus:` messages and only same-uid peers. This is a new
     same-user, no-privilege IPC surface; per CONTRIBUTING's ADR rule it
     stops short of a security-posture change, but if review disagrees it
     becomes an ADR before merge.
3. Tests: page-name validation; flock exclusivity (second instance
   handoffs, exits 0); connect-failure fallback (holder without listener
   proceeds); same-uid enforcement (peer credentials check); navigate-only
   message rejection; `--new` bypass; missing-runtime-dir path.

Honest limit, documented in TUI.md: the TUI cannot raise or focus the other
terminal's window; the running instance navigates but the user brings its
window forward. Multiple TUIs today are not dangerous (the daemon serializes
clients, stress-tested), so this guard ships as UX correctness, and it also
fixes double-launching from the application menu.

## Privilege model

- **Phase 1**: reads (unprivileged) + TUI launches (unprivileged; the TUI
  performs its own authorization through the existing polkit actions
  `org.irlume.enroll` / `org.irlume.recovery-manage` and its guided flows).
- **Phase 3 (optional, only if Phase 1 feedback wants it)**: trivial
  toggles executed as `pkexec /usr/bin/irlume <subcommand>` (sensor policy
  dual/ir-only, biopolicy, consent mode) with preview-and-confirm. Two hard
  preconditions, both because pkexec resolves a relative program name
  through the caller's PATH: always exec the ABSOLUTE packaged path, and
  prefer a dedicated polkit action with
  `org.freedesktop.policykit.exec.path` pinned to it. pkexec uses the
  session's polkit-kde agent; no helper binaries of ours. Phase 3 requires
  its own ADR (privileged GUI mutations are a design-level security-posture
  change under CONTRIBUTING's ADR rule). Login wiring changes remain TUI
  territory (its plan/apply/verify/rollback flow) unless that ADR says
  otherwise.
- Known operational fact carried in: root-under-pkexec ignores
  `IRLUME_SOCKET` (secure_getenv), so pkexec'd calls target the system
  daemon at `/run/irlume.sock` - which is the intent.

## Packaging

- **rpm (Fedora/Copr)**: `irlume-kcm` subpackage (precedent:
  `irlume-selinux`), Requires irlume + kf6 KCMUtils/Config/CoreAddons/I18n/
  KIO and qt6-qtdeclarative + kf6-kirigami.
- **Arch**: split package or PKGBUILD section; deps: extra-cmake-modules
  at build; kf6 kcmutils, kf6-kio, kf6-kirigami at runtime.
- **PPA (Ubuntu 26.04)**: `irlume-kcm` binary package; Kubuntu 26.04 has
  Plasma 6.6 / Qt 6.10.2 / KF 6.24 (verified), Build-Depends on the KF6
  stack (kcmutils, kio, kirigami, extra-cmake-modules).
- **Universal deb (debian:12 build base)**: Debian 12 has no KF6 and its
  Qt 6.4 is below the 6.5 floor (Plasma 6/KF6 arrived in Debian 13). The
  KCM therefore does NOT ride the universal deb; Debian-family users get
  it from the PPA lane on Ubuntu, and a separate trixie-based KCM .deb is
  a possible later addition with its own container (no such container
  exists today; the CI lane gains a fedora:44 + arch KCM build first, and
  the deb-family KCM stays PPA-only until that container exists).
- **Nix**: package `irlume-kcm` built against `kdePackages`; module option
   `services.irlume.kcm.enable` (default off initially). Known caveat
  nixpkgs#296999 (KCMs built outside the plasma-desktop set had environment
  issues) - in-module verification is a Phase 1 gate on NixOS.
- **Parity + SBOM**: check-packaging-parity.sh gains a KCM section that
  encodes the PPA-only (not universal-deb) reality for the Debian family;
  generate-release-sbom.sh gains its first non-cargo CycloneDX entry for
  `kcm_irlume.so`; VEX unaffected.

## CI

- A `kcm` build lane: new containers for fedora:44 and archlinux build the
  CMake target (the existing packaging containers are debian:12-based and
  cannot build KF6); the Nix flake builds it in the existing nix lane.
- Smoke tests: `kcmshell6 --list` contains kcm_irlume in the Fedora/Arch
  matrices; QML syntax check via `qmllint` where available. A full
  interactive kcmshell6 load needs a session and stays a manual validation
  step on KDE hardware (archhost / laptop), recorded in the validation doc.

## Security review checklist

- SECURITY.md: new row - `kcm_irlume` plugin, tier Low (unprivileged view
  layer; renders machine documents; spawns only `irlume` CLI and the TUI
  desktop entry).
- AppArmor/selinux profiles unchanged: the KCM runs inside systemsettings,
  not an irlume binary; the pkexec/polkit boundary is unchanged.
- No secrets anywhere in the KCM: no tokens, no key material, no camera
  frames; the census and diagnostics documents are the designed
  privacy-bounded surfaces.
- The process bridge execs a resolved absolute path (packaged
  `/usr/bin/irlume` preferred); no shell interpolation of user input into
  command lines - arguments are fixed literals plus enum-validated page
  names.

## Phasing and acceptance gates

- **Phase 0** (Rust only): `--page` + single-instance guard + tests + docs.
  Gate: workspace tests, clippy, doc gates; live double-launch check on KDE
  hardware. Shippable alone, no KCM dependency.
- **Phase 1** (read-only KCM + launch actions): component, pages, packaging
  on Fedora + Arch first (validation hardware), then PPA + Nix, deb last.
  Gates: container builds per lane; parity script; live System Settings
  walkthrough on archhost/laptop (pages render real documents, deep links
  land, guard prevents terminal pileup); SECURITY.md/docs updated.
- **Phase 2**: docs + polish from real usage; i18n decision (default:
  English-only, matching the rest of irlume today).
- **Phase 3 (optional)**: native trivial toggles via pkexec with its own
  mini-design addendum if pursued.

## Open decisions (defaults chosen, flagged for review)

1. System Settings category: default `personalization` (face auth is a
   per-user credential experience); alternative `system-administration`.
   Cheap to change (metadata field).
2. Repo layout: top-level `kcm/` (default) vs `packaging/kcm/`.
3. `xdg-terminal-exec` deep links with plain-desktop-entry fallback
   (default) vs desktop entries only (no deep links) if validation fails.
4. Whether Phase 3 ever happens (default: decide after Phase 1 usage).

## Test matrix sketch

- Unit (Rust): page validation, flock exclusivity and handoff,
  connect-failure fallback, same-uid peer enforcement, navigate-only
  message rejection, `--new`, no runtime dir.
- Container: CMake build on fedora:44 and archlinux; PPA source build
  includes irlume-kcm; nix build includes the kcm package. The universal
  deb stays KCM-free (documented).
- Live KDE: System Settings shows the module under the chosen category;
  each page renders against a real daemon; every launch button lands the
  TUI on the right page; second click navigates the existing TUI instead of
  opening a terminal; kcmshell6 kcm_irlume standalone works; daemon-down
  state renders as data; NixOS module verification per the caveat above.
