// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume bitwarden`: set up Bitwarden's biometric-unlock polkit action so
//! its prompt can be face-approved (docs/APP-INTEGRATION.md).
//!
//! Bitwarden's "unlock with system authentication" is a polkit
//! CheckAuthorization on `com.bitwarden.Bitwarden.unlock`, which only exists
//! once its action file sits in `/usr/share/polkit-1/actions/`. Who puts it
//! there depends on the install flavor (verified against bitwarden/clients
//! `os-biometrics-linux.service.ts` and the shipped artifacts, 2026-07):
//!
//! - **Flatpak**: never. The Flathub package repacks the release tarball,
//!   which contains no .policy, and the sandbox cannot write /usr. Manual
//!   host install is always required; that is the gap this command fills.
//! - **Snap**: snapd itself. The snap ships the policy under `meta/polkit/`
//!   and snapd's polkit interface installs it host-side on plug connect as
//!   `snap.bitwarden.interface.polkit.*.policy`. Nothing for us to do.
//! - **Native (.deb/.rpm/Arch/AUR)**: the app self-installs via a pkexec
//!   one-liner when the user first enables the setting. That flow chains an
//!   unconditional `chcon` with `&&`, so it fails on hosts without SELinux
//!   tooling; pre-installing here also spares the pkexec prompt.
//! - **ostree/immutable**: /usr is read-only and polkitd compiles in exactly
//!   one actions directory (no /etc or XDG fallback), so there is nothing an
//!   installer can honestly do; we explain the rpm-layering workaround.
//!
//! The policy content is EMBEDDED (resources/com.bitwarden.Bitwarden.policy,
//! byte-identical to bitwarden/clients `apps/desktop/resources/`): the
//! upstream-documented flow wgets it from their main branch at install time,
//! and a root-installed file should not depend on a moving branch or the
//! network. If a file is already present with different content we leave it
//! alone; Bitwarden's own self-install may have written a newer version.
//!
//! polkitd watches the actions directory (GFileMonitor), so a newly written
//! file is live immediately; no service restart.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Byte-identical copy of bitwarden/clients apps/desktop/resources/
/// com.bitwarden.desktop.policy (the app installs it under the
/// com.bitwarden.Bitwarden.policy name; we mirror that). GPL-3.0 like the
/// clients repo. sha256 e0e0be0c…; matches the copy live-validated on real
/// hardware 2026-07-22.
const POLICY: &str = include_str!("../resources/com.bitwarden.Bitwarden.policy");

/// Where polkitd's single compiled-in actions directory lives on every
/// mainstream distro build (PACKAGE_DATA_DIR /polkit-1/actions).
const ACTIONS_DIR: &str = "/usr/share/polkit-1/actions";

/// The filename Bitwarden's own self-install writes (NOT the repo resource
/// name); doctor and the app's needsSetup probe both key on this action.
const POLICY_FILE: &str = "com.bitwarden.Bitwarden.policy";

/// What snapd's polkit interface names the host-side copy it installs from
/// the snap's meta/polkit/ (`snap.<name>.interface.<basename>.policy`).
const SNAPD_POLICY_FILE: &str = "snap.bitwarden.interface.polkit.com.bitwarden.desktop.policy";

// ---- CLI entry ---------------------------------------------------------------

pub fn run(action: Option<&str>, args: &[String]) -> ExitCode {
    let apply = args.iter().any(|a| a == "--apply");
    match action {
        None | Some("status") => status(),
        Some("setup") => setup(apply),
        _ => {
            eprintln!("usage: irlume bitwarden <status|setup> [--apply]");
            eprintln!("  (setup without --apply prints what it WOULD change: a dry run)");
            ExitCode::from(2)
        }
    }
}

// ---- detection ---------------------------------------------------------------

/// How Bitwarden got onto this system. Multiple can coexist (a flatpak next
/// to a .deb); detection returns all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flavor {
    /// Flathub com.bitwarden.desktop, system-wide or per-user install.
    Flatpak,
    /// Snap Store bitwarden (snapd owns the polkit action host-side).
    Snap,
    /// .deb/.rpm/Arch extra/AUR bitwarden-bin (all land in /opt/Bitwarden or
    /// /usr/lib/bitwarden).
    Native,
}

/// Detect installed Bitwarden flavors by their deployment directories,
/// rooted at `root` so tests can build a fake filesystem ("/" in production).
fn detect_flavors(root: &Path, user_home: Option<&Path>) -> Vec<Flavor> {
    let mut found = Vec::new();
    let system_flatpak = root.join("var/lib/flatpak/app/com.bitwarden.desktop");
    let user_flatpak = user_home.map(|h| h.join(".local/share/flatpak/app/com.bitwarden.desktop"));
    if system_flatpak.is_dir() || user_flatpak.is_some_and(|p| p.is_dir()) {
        found.push(Flavor::Flatpak);
    }
    // Classic /snap plus Fedora's /var/lib/snapd/snap mount point.
    if root.join("snap/bitwarden").is_dir() || root.join("var/lib/snapd/snap/bitwarden").is_dir() {
        found.push(Flavor::Snap);
    }
    // /opt/Bitwarden: electron-builder .deb/.rpm and the AUR repack of the
    // .deb. /usr/lib/bitwarden: Arch's from-source extra/bitwarden package.
    if root.join("opt/Bitwarden").is_dir() || root.join("usr/lib/bitwarden").is_dir() {
        found.push(Flavor::Native);
    }
    found
}

/// Whether any Bitwarden install is present at all (doctor's gate for the
/// "installed but no polkit action" advisory).
pub(crate) fn app_detected() -> bool {
    !detect_flavors(Path::new("/"), detection_home().as_deref()).is_empty()
}

/// Condensed state for the TUI's app-unlock row. `None` when Bitwarden is not
/// installed at all, so the row disappears entirely for everyone else (the
/// feature stays invisible until it is relevant: opt-in by presence).
pub(crate) enum TuiState {
    /// Action file present (ours, Bitwarden's own, or snapd's). Ready.
    Ready,
    /// Snap install whose snapd-managed action is missing; irlume must not
    /// write it, the fix is `snap connect bitwarden:polkit`.
    SnapMissing,
    /// Action file absent and `irlume bitwarden setup --apply` would fix it.
    NeedsSetup,
}

pub(crate) fn tui_state() -> Option<TuiState> {
    let flavors = detect_flavors(Path::new("/"), detection_home().as_deref());
    if flavors.is_empty() {
        return None;
    }
    let actions = Path::new(ACTIONS_DIR);
    match read_policy_state(actions) {
        // A differing file is Bitwarden's own (possibly newer) install; from
        // the user's seat that is just as ready as ours.
        PolicyState::Installed | PolicyState::Differs => Some(TuiState::Ready),
        PolicyState::Absent if actions.join(SNAPD_POLICY_FILE).exists() => Some(TuiState::Ready),
        PolicyState::Absent if flavors == [Flavor::Snap] => Some(TuiState::SnapMissing),
        PolicyState::Absent => Some(TuiState::NeedsSetup),
    }
}

/// The invoking user's home for per-user flatpak detection: under sudo the
/// real user's, not root's.
fn detection_home() -> Option<PathBuf> {
    if crate::is_root() {
        if let Ok(u) = std::env::var("SUDO_USER") {
            if !u.is_empty() {
                return Some(PathBuf::from(format!("/home/{u}")));
            }
        }
    }
    std::env::var_os("HOME").map(PathBuf::from)
}

// ---- policy-file state -------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum PolicyState {
    /// No action file on the host.
    Absent,
    /// Present and byte-identical to the copy we ship.
    Installed,
    /// Present with other content: Bitwarden's own (possibly newer) install,
    /// or a hand-edited file. Not ours to overwrite.
    Differs,
}

fn classify_policy(existing: Option<&str>) -> PolicyState {
    match existing {
        None => PolicyState::Absent,
        Some(s) if s == POLICY => PolicyState::Installed,
        Some(_) => PolicyState::Differs,
    }
}

fn read_policy_state(actions_dir: &Path) -> PolicyState {
    let existing = std::fs::read_to_string(actions_dir.join(POLICY_FILE)).ok();
    classify_policy(existing.as_deref())
}

/// Whether this boot is an ostree/immutable system (Silverblue, Kinoite…),
/// where /usr is read-only and no writable actions directory exists.
fn ostree_booted() -> bool {
    Path::new("/run/ostree-booted").exists()
}

// ---- status ------------------------------------------------------------------

fn status() -> ExitCode {
    let flavors = detect_flavors(Path::new("/"), detection_home().as_deref());
    if flavors.is_empty() {
        println!("[bitwarden] app: not detected (flatpak/snap/native paths all absent)");
    }
    for f in &flavors {
        let label = match f {
            Flavor::Flatpak => "flatpak (com.bitwarden.desktop)",
            Flavor::Snap => "snap (polkit action managed by snapd)",
            Flavor::Native => "native package (/opt/Bitwarden or /usr/lib/bitwarden)",
        };
        println!("[bitwarden] app: {label} ✓");
    }
    let actions = Path::new(ACTIONS_DIR);
    match read_policy_state(actions) {
        PolicyState::Installed => {
            println!("[bitwarden] polkit action: installed ✓ (matches the copy irlume ships)")
        }
        PolicyState::Differs => println!(
            "[bitwarden] polkit action: installed ✓ (content differs from the copy irlume \
             ships; Bitwarden's own setup may have written a newer one; leaving it alone)"
        ),
        PolicyState::Absent if flavors.contains(&Flavor::Snap) => {
            if actions.join(SNAPD_POLICY_FILE).exists() {
                println!("[bitwarden] polkit action: installed by snapd ✓");
            } else {
                println!(
                    "[bitwarden] polkit action: MISSING and snapd has not installed its copy; \
                     try: sudo snap connect bitwarden:polkit"
                );
            }
        }
        PolicyState::Absent => println!(
            "[bitwarden] polkit action: not installed (biometric unlock will not work); \
             run: sudo irlume bitwarden setup --apply"
        ),
    }
    match crate::pamwire::polkit_wired() {
        Some(true) => println!("[bitwarden] polkit face auth: wired ✓"),
        Some(false) => println!(
            "[bitwarden] polkit face auth: not wired; the prompt will ask for the password. \
             Enable: sudo irlume login enable --with-polkit --apply"
        ),
        None => {}
    }
    ExitCode::SUCCESS
}

// ---- setup -------------------------------------------------------------------

fn setup(apply: bool) -> ExitCode {
    let flavors = detect_flavors(Path::new("/"), detection_home().as_deref());
    if flavors.is_empty() {
        println!(
            "[bitwarden] app not detected; installing the polkit action anyway is harmless \
             (it is inert until Bitwarden uses it), continuing."
        );
    }

    // Snap-only: snapd owns the host-side action; installing our copy too
    // would leave two files declaring overlapping intent. Report and stop.
    if flavors == [Flavor::Snap] {
        return if Path::new(ACTIONS_DIR).join(SNAPD_POLICY_FILE).exists() {
            println!("[bitwarden] snap install: snapd already installed the polkit action ✓");
            print_app_steps();
            ExitCode::SUCCESS
        } else {
            println!(
                "[bitwarden] snap install, but snapd's action file is missing. irlume does \
                 not write it (snapd owns that file); try: sudo snap connect bitwarden:polkit"
            );
            ExitCode::FAILURE
        };
    }

    match read_policy_state(Path::new(ACTIONS_DIR)) {
        PolicyState::Installed => {
            println!("[bitwarden] polkit action already installed ✓ (nothing to change)");
            print_app_steps();
            return ExitCode::SUCCESS;
        }
        PolicyState::Differs => {
            println!(
                "[bitwarden] a polkit action file is already present with different content; \
                 leaving it alone (Bitwarden's own setup may have written a newer version). \
                 Nothing to change."
            );
            print_app_steps();
            return ExitCode::SUCCESS;
        }
        PolicyState::Absent => {}
    }

    // ostree: /usr is read-only and polkitd reads actions ONLY from
    // /usr/share/polkit-1/actions (compiled in; no /etc fallback). Writing
    // would just fail with EROFS; explain the supported route instead.
    if ostree_booted() {
        println!(
            "[bitwarden] this is an ostree/immutable system: /usr is read-only and polkit \
             has no other actions directory. Install the policy by layering a small rpm \
             that owns {ACTIONS_DIR}/{POLICY_FILE} (rpm-ostree install --apply-live), \
             then restart polkit. See docs/APP-INTEGRATION.md."
        );
        return ExitCode::FAILURE;
    }

    if !apply {
        println!("[bitwarden] DRY RUN: showing what `--apply` would change (nothing is written):");
        println!("  write {ACTIONS_DIR}/{POLICY_FILE} (root:root 0644, content shipped in irlume)");
        println!("  restore its SELinux label (Fedora-family; no-op elsewhere)");
        println!("[bitwarden] re-run with --apply (as root) to perform these changes.");
        return ExitCode::SUCCESS;
    }
    if !crate::is_root() {
        eprintln!(
            "[bitwarden] applying changes needs root; run: sudo irlume bitwarden setup --apply"
        );
        return ExitCode::FAILURE;
    }

    let target = Path::new(ACTIONS_DIR).join(POLICY_FILE);
    if let Err(e) = std::fs::write(&target, POLICY) {
        eprintln!("[bitwarden] writing {} failed: {e}", target.display());
        return ExitCode::FAILURE;
    }
    // polkitd runs unprivileged (User=polkitd) and silently skips files it
    // cannot read, so 0644 is a requirement, set explicitly rather than
    // trusting the caller's umask.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644));
    // SELinux: a file CREATED in this directory inherits the default usr_t
    // label already; restorecon covers the remaining edge (a pre-staged file
    // moved into place keeps its old label, which makes polkitd skip it).
    // Failure or absence (non-SELinux hosts) is fine, unlike Bitwarden's own
    // setup whose hard-chained `chcon` breaks there (clients#16671).
    let _ = std::process::Command::new("restorecon")
        .arg(&target)
        .status();
    println!(
        "[bitwarden] polkit action installed ✓ ({}). polkit picks it up immediately \
         (no restart needed).",
        target.display()
    );
    // Confirm from polkitd's side, not the filesystem's: pkaction resolves
    // the action only if the daemon parsed and registered the file. Catches
    // the file-present-but-unreadable/mislabeled class of failure.
    match std::process::Command::new("pkaction")
        .args(["--action-id", "com.bitwarden.Bitwarden.unlock"])
        .output()
    {
        Ok(out) if out.status.success() => {
            println!("[bitwarden] polkit registered the action ✓ (pkaction sees it)")
        }
        Ok(_) => println!(
            "[bitwarden] ⚠ polkit has not registered the action yet. Remedies: \
             sudo systemctl restart polkit; on SELinux hosts check the label \
             (restorecon -v {})",
            target.display()
        ),
        Err(_) => {} // pkaction not installed; skip the verification quietly
    }

    if crate::pamwire::polkit_wired() != Some(true) {
        println!(
            "[bitwarden] polkit face auth is not wired yet; without it the prompt asks for \
             your password. Enable: sudo irlume login enable --with-polkit --apply"
        );
    }
    print_app_steps();
    ExitCode::SUCCESS
}

/// The two steps that live inside Bitwarden's own UI and cannot be automated.
fn print_app_steps() {
    println!("[bitwarden] finish inside the app:");
    println!("  1. File > Settings > Security > \"Unlock with system authentication\"");
    println!("  2. unlock the vault once with your master password (biometrics never replace");
    println!("     the first unlock; Bitwarden keeps the vault key in memory)");
    println!("  then the unlock prompt is a polkit dialog your consent gesture satisfies.");
}

#[cfg(test)]
mod tests {
    use super::{classify_policy, detect_flavors, Flavor, PolicyState, POLICY};
    use std::path::Path;

    #[test]
    fn embedded_policy_declares_the_expected_action() {
        // The action id is the contract with Bitwarden's CheckAuthorization
        // call and with doctor's detection; a drifted resource file must fail.
        assert!(POLICY.contains(r#"<action id="com.bitwarden.Bitwarden.unlock">"#));
        assert!(POLICY.contains("<allow_active>auth_self</allow_active>"));
        assert!(POLICY.contains("<allow_any>no</allow_any>"));
    }

    #[test]
    fn policy_state_classification() {
        assert_eq!(classify_policy(None), PolicyState::Absent);
        assert_eq!(classify_policy(Some(POLICY)), PolicyState::Installed);
        assert_eq!(
            classify_policy(Some("<policyconfig/>")),
            PolicyState::Differs
        );
    }

    #[test]
    fn flavor_detection_from_a_fake_root() {
        let base = std::env::temp_dir().join(format!("irlume-bw-test-{}", std::process::id()));
        let home = base.join("home/user");
        std::fs::create_dir_all(base.join("opt/Bitwarden")).unwrap();
        std::fs::create_dir_all(base.join("var/lib/snapd/snap/bitwarden")).unwrap();
        std::fs::create_dir_all(home.join(".local/share/flatpak/app/com.bitwarden.desktop"))
            .unwrap();

        let all = detect_flavors(&base, Some(&home));
        assert_eq!(all, vec![Flavor::Flatpak, Flavor::Snap, Flavor::Native]);

        // Per-user flatpak alone is enough; an unrelated home is not.
        let none = detect_flavors(Path::new("/nonexistent-bw-root"), Some(Path::new("/tmp")));
        assert!(none.is_empty());

        std::fs::remove_dir_all(&base).unwrap();
    }
}
