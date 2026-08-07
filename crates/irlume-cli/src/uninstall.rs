// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume uninstall`: the safe teardown a package `remove` cannot do.
//!
//! Removing the distro package deletes the binary and `pam_irlume.so`, but the
//! package manager does not know about the pam.d edits that reference them. A
//! `pam_irlume.so` line left behind after the module is gone makes PAM fail to
//! load it, which can lock you out of login and sudo. So the irlume-specific
//! teardown has to run FIRST, and in this order:
//!
//!   1. un-wire PAM from every stack (greeters, sudo, lock screen)
//!   2. stop and disable the daemon
//!   3. disarm every enrolled user's TPM keyring seal
//!   4. wipe enrolled templates, sealed secrets, third-party models, and config
//!
//! Only then does it remove irlume itself: the package through its manager (so
//! the package database stays consistent), or the hand-placed files for a
//! source install. It deletes the binary running this command last of all,
//! which is fine on Linux (the inode survives until the process exits). The
//! same teardown-then-remove backs the TUI's uninstall entry, which puts its
//! own double-confirmation in front of it and exits once it returns.

use crate::commands::{install_origin, InstallOrigin};
use crate::is_root;
use crate::pamwire;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// What the teardown actually did, so the CLI and the TUI can report it the
/// same way.
pub struct TeardownReport {
    pub pam_unwired: bool,
    pub service_stopped: bool,
    pub users_cleared: usize,
    pub data_wiped: bool,
}

pub fn run(args: &[String]) -> ExitCode {
    let assume_yes = args.iter().any(|a| a == "--yes" || a == "-y");
    let keep_data = args.iter().any(|a| a == "--keep-data");

    if !is_root() {
        eprintln!("[uninstall] needs root: sudo irlume uninstall");
        return ExitCode::FAILURE;
    }

    // A GNOME keyring token arm (#250) means the user's login keyring is keyed
    // to a secret that exists ONLY in the sealed envelope. Deleting it here
    // would make that keyring permanently unreachable, and the re-key back to
    // the password cannot happen from this root process (the keyring control
    // socket authenticates the session's uid). Refuse until each such user has
    // disarmed from their own session; this is a data-loss guard, so there is
    // deliberately no flag to bypass it (`irlume keyring forget --force` per
    // user is the explicit, per-user override).
    // Enumerate ENVELOPES, not enrolled users: `keyring arm` needs no
    // enrollment, so a user can hold a sealed token and never appear in
    // `storage::list_users()`. And an envelope this cannot READ is not an
    // envelope that holds no token; the enumerator errors rather than skipping,
    // because guessing here erases the only copy of the secret a login keyring
    // is encrypted under.
    let sealed = match irlume_core::keyring::list_sealed_kinds() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[uninstall] refusing: could not read the sealed-envelope store ({e}). \
                 One of these may hold a GNOME keyring token, and deleting it would \
                 leave that keyring encrypted under a secret nothing can reproduce. \
                 Fix the store (or move it aside deliberately) and re-run."
            );
            return ExitCode::FAILURE;
        }
    };
    let token_users: Vec<&str> = sealed
        .iter()
        .filter(|(_, kind)| *kind == irlume_core::envelope::SecretKind::GnomeKeyringToken)
        .map(|(u, _)| u.as_str())
        .collect();
    if !token_users.is_empty() {
        eprintln!(
            "[uninstall] refusing: the login keyring of {} is keyed to an irlume-held \
             token, and uninstalling now would lock it permanently.",
            token_users.join(", ")
        );
        eprintln!(
            "[uninstall] Have each of these users run `irlume keyring forget` in their \
             own session first (it re-keys the keyring back to their password), then \
             re-run the uninstall."
        );
        return ExitCode::FAILURE;
    }

    println!("irlume uninstall will:");
    println!("  1. remove irlume from every PAM stack (greeters, sudo, lock screen)");
    println!("  2. stop and disable the irlumed service");
    if keep_data {
        println!("  3. keep your enrolled faces and sealed secrets (--keep-data)");
    } else {
        println!("  3. disarm the keyring seal, then delete every enrolled face,");
        println!("     sealed secret, third-party model, and config file");
    }
    println!("  4. remove irlume itself (the package, or the installed files)");
    println!();

    if !assume_yes {
        if !stdin_is_tty() {
            eprintln!(
                "[uninstall] refusing to run unconfirmed without a terminal; pass --yes to proceed"
            );
            return ExitCode::FAILURE;
        }
        // Double confirmation: a typed word, then a final y/N. Uninstall deletes
        // sealed secrets that cannot be recovered, so make it deliberate.
        print!("Type 'uninstall' to continue: ");
        let _ = std::io::stdout().flush();
        let mut typed = String::new();
        if std::io::stdin().read_line(&mut typed).is_err() || typed.trim() != "uninstall" {
            println!("[uninstall] cancelled; nothing was changed.");
            return ExitCode::FAILURE;
        }
        print!("Really remove irlume from this machine? [y/N] ");
        let _ = std::io::stdout().flush();
        let mut yn = String::new();
        if std::io::stdin().read_line(&mut yn).is_err() || !matches!(yn.trim(), "y" | "Y" | "yes") {
            println!("[uninstall] cancelled; nothing was changed.");
            return ExitCode::FAILURE;
        }
    }

    let report = perform_teardown(keep_data);

    println!();
    println!(
        "[uninstall] PAM un-wired: {}",
        if report.pam_unwired {
            "yes (no stack references irlume)"
        } else {
            "WARNING: some stack may still reference irlume; check `irlume login status`"
        }
    );
    println!(
        "[uninstall] service stopped and disabled: {}",
        yn(report.service_stopped)
    );
    println!(
        "[uninstall] users disarmed: {}{}",
        report.users_cleared,
        if report.data_wiped {
            " (enrollments, seals, models, and config deleted)"
        } else {
            " (data kept)"
        }
    );

    // Now actually remove irlume: the package via its manager, or the
    // hand-placed files for a source install. Done last, because it deletes the
    // binary running this very command (fine on Linux: the inode survives until
    // this process exits).
    println!();
    let origin = install_origin();
    let removed = remove_irlume(&origin);
    // Clean the leftovers a package `remove` doesn't (drop-in, empty dirs, repo)
    // regardless of whether the package removal itself succeeded.
    clean_residuals(&origin);
    // Snapshot tooling keeps copies of everything the wipe just deleted: on the
    // #335 audit box, snapper's pacman hooks had snapshotted the templates, the
    // sealed keyring blob, and the recovery envelope, so "no data left behind"
    // was not the whole truth. Detection is evidence-only (no snapshot tool is
    // ever run) and irrelevant when --keep-data skipped the wipe.
    let snapshots = if report.data_wiped {
        detect_snapshot_tools()
    } else {
        SnapshotEvidence::default()
    };
    match removed {
        Ok(what) => {
            println!("[uninstall] {what}");
            println!("[uninstall] {}", closing_line(&snapshots));
        }
        Err(e) => {
            println!("[uninstall] could not finish removal automatically: {e}");
            println!("[uninstall] the teardown above is done; remove the package by hand:");
            println!("  {}", removal_hint(&origin));
        }
    }
    ExitCode::SUCCESS
}

/// Remove irlume itself. Package installs go through the package manager (so the
/// package database stays consistent); a source install has its hand-placed
/// files deleted directly. `--yes`/confirmation already happened in `run`.
fn remove_irlume(origin: &InstallOrigin) -> Result<String, String> {
    match origin {
        InstallOrigin::Copr | InstallOrigin::LocalRpm(_) => {
            run_pkg("dnf", &["remove", "-y", "irlume"])
        }
        // purge, not remove, so any packaged conffiles go too (nothing left).
        InstallOrigin::Ppa | InstallOrigin::LocalDeb => {
            run_pkg("apt-get", &["purge", "-y", "irlume"])
        }
        InstallOrigin::ArchPkg => run_pkg("pacman", &["-R", "--noconfirm", "irlume"]),
        InstallOrigin::Source => remove_source_files(),
    }
}

/// Run a package-manager removal; map a non-zero exit to a readable error.
fn run_pkg(bin: &str, args: &[&str]) -> Result<String, String> {
    println!("[uninstall] removing the package: {bin} {}", args.join(" "));
    match Command::new(bin).args(args).status() {
        Ok(s) if s.success() => Ok(format!("removed the {bin} package")),
        Ok(s) => Err(format!("{bin} exited with {s}")),
        Err(e) => Err(format!("could not run {bin} ({e})")),
    }
}

/// Delete the files a source install placed: the two binaries (this one and its
/// sibling irlumed), the PAM module, the systemd unit + drop-ins, and the model
/// tree. The state/config dirs are already gone from the teardown. Best-effort;
/// reports the count removed.
fn remove_source_files() -> Result<String, String> {
    let mut targets: Vec<PathBuf> = Vec::new();

    // The running binary and irlumed next to it.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            targets.push(dir.join("irlumed"));
        }
        targets.push(exe);
    }
    // The PAM module, wherever the loader keeps modules on this distro.
    for d in [
        "/usr/lib/security",
        "/usr/lib64/security",
        "/lib/security",
        "/lib/x86_64-linux-gnu/security",
    ] {
        targets.push(PathBuf::from(d).join("pam_irlume.so"));
    }
    // The systemd unit and any drop-ins.
    targets.push(PathBuf::from("/etc/systemd/system/irlumed.service"));
    let _ = std::fs::remove_dir_all("/etc/systemd/system/irlumed.service.d");
    // The model tree (the two common source-install prefixes).
    for d in ["/usr/share/irlume", "/usr/local/share/irlume"] {
        let _ = std::fs::remove_dir_all(d);
    }

    let removed = targets
        .iter()
        .filter(|p| p.exists() && std::fs::remove_file(p).is_ok())
        .count();
    let _ = systemctl(&["daemon-reload"]);
    if removed == 0 {
        return Err("found no source-installed files to remove (already gone?)".into());
    }
    Ok(format!("removed {removed} source-installed file(s)"))
}

/// Remove irlume artifacts a package `remove` leaves behind, so "uninstall"
/// leaves nothing: the admin-created `logs debug on` systemd drop-in (not
/// package-owned), empty share dirs a package manager can leave, and the
/// install channel (repo) the installer added. Runs for every install method.
fn clean_residuals(origin: &InstallOrigin) {
    // `irlume logs debug on` drops this in; it survives a package remove.
    let _ = std::fs::remove_dir_all("/etc/systemd/system/irlumed.service.d");
    let _ = systemctl(&["daemon-reload"]);
    // Empty model/onnxruntime dirs a package remove can leave behind.
    for d in ["/usr/share/irlume", "/usr/local/share/irlume"] {
        let _ = std::fs::remove_dir_all(d);
    }
    // The install channel the installer added, so nothing on the box still
    // points at irlume. (A source install and an AUR/pacman install add no
    // repo; the Fedora Copr repo and the Ubuntu PPA do.)
    match origin {
        InstallOrigin::Copr => remove_repo_files("/etc/yum.repos.d"),
        InstallOrigin::Ppa => {
            // The PPA leaves both a sources file and a signing key.
            remove_repo_files("/etc/apt/sources.list.d");
            for d in [
                "/etc/apt/trusted.gpg.d",
                "/etc/apt/keyrings",
                "/usr/share/keyrings",
            ] {
                remove_repo_files(d);
            }
        }
        _ => {}
    }
}

/// Delete files under `dir` whose name mentions irlume: the Copr `.repo` or the
/// PPA `.list` the installer added.
fn remove_repo_files(dir: &str) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if e.file_name()
                .to_string_lossy()
                .to_lowercase()
                .contains("irlume")
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Where systemd records each timer's last-trigger stamp.
const TIMER_STAMP_DIR: &str = "/var/lib/systemd/timers";

/// Delete systemd's `stamp-*` files for irlume's timer units under `dir`. The
/// stamps are systemd's own bookkeeping, so no package owns them and disabling
/// the timer leaves them behind (#335). Best-effort like the other residual
/// cleaners: a missing directory or file is simply nothing to do.
fn remove_timer_stamps(dir: &str) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("stamp-irlume") && name.ends_with(".timer") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// The filesystem facts that say a snapshot tool retains copies of the wiped
/// data (#335). Gathered from cheap existence checks only; the tools' own
/// commands are never run, because detection must not be able to mutate
/// snapshot state or fail the uninstall.
#[derive(Default)]
struct SnapshotEvidence {
    snapper: bool,
    timeshift: bool,
}

fn detect_snapshot_tools() -> SnapshotEvidence {
    SnapshotEvidence {
        snapper: snapper_evidence(),
        timeshift: timeshift_evidence(),
    }
}

/// snapper is retaining data when its binary exists AND /etc/snapper/configs
/// holds at least one config, or when a package-manager hook re-snapshots every
/// transaction: snap-pac's pacman hooks (the mechanism that snapshotted the
/// #335 audit box) or openSUSE's zypp commit plugin.
fn snapper_evidence() -> bool {
    let bin = [
        "/usr/bin/snapper",
        "/usr/sbin/snapper",
        "/usr/local/bin/snapper",
    ]
    .iter()
    .any(|p| Path::new(p).exists());
    if bin && dir_has_entries("/etc/snapper/configs") {
        return true;
    }
    for d in ["/usr/share/libalpm/hooks", "/etc/pacman.d/hooks"] {
        if dir_has_entry_named(d, "snap-pac") || dir_has_entry_named(d, "snapper") {
            return true;
        }
    }
    dir_has_entry_named("/usr/lib/zypp/plugins/commit", "snapper")
}

/// Timeshift needs less corroboration than snapper: its binary or /etc/timeshift
/// only exist when someone installed it, and it exists only to take snapshots.
fn timeshift_evidence() -> bool {
    [
        "/usr/bin/timeshift",
        "/usr/sbin/timeshift",
        "/usr/local/bin/timeshift",
        "/etc/timeshift",
    ]
    .iter()
    .any(|p| Path::new(p).exists())
}

/// True when `dir` exists and holds at least one entry. An unreadable directory
/// counts as no evidence, never as an error: detection must not fail the
/// uninstall (#335).
fn dir_has_entries(dir: &str) -> bool {
    std::fs::read_dir(dir)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

/// True when `dir` holds an entry whose name contains `needle`, compared in
/// lowercase. Same tolerance as `dir_has_entries`.
fn dir_has_entry_named(dir: &str, needle: &str) -> bool {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if e.file_name()
                .to_string_lossy()
                .to_lowercase()
                .contains(needle)
            {
                return true;
            }
        }
    }
    false
}

/// The closing line of a successful uninstall. Without snapshot evidence it is
/// the exact line the module has always printed. With evidence it stays honest
/// (#335): the wipe cannot reach inside filesystem snapshots, so the line names
/// the tool holding them and the command that lists them, and drops the "no
/// data left behind" claim it can no longer make. Pure over the gathered
/// evidence so both arms are unit tested.
fn closing_line(snapshots: &SnapshotEvidence) -> String {
    let mut tools: Vec<&str> = Vec::new();
    let mut list_cmds: Vec<&str> = Vec::new();
    if snapshots.snapper {
        tools.push("snapper");
        list_cmds.push("`snapper list`");
    }
    if snapshots.timeshift {
        tools.push("Timeshift");
        list_cmds.push("`timeshift --list`");
    }
    if tools.is_empty() {
        return "irlume is removed, with no repo, drop-in, or data left behind.".into();
    }
    format!(
        "irlume is removed, with no repo or drop-in left behind, but {} filesystem \
         snapshots may still contain the wiped templates and sealed secrets (list \
         them with {}).",
        tools.join(" and "),
        list_cmds.join(" and ")
    )
}

/// Run the four teardown steps in the lockout-safe order. Public so the TUI
/// calls the identical sequence behind its own confirmation.
pub fn perform_teardown(keep_data: bool) -> TeardownReport {
    // 1. PAM FIRST. Un-wire every greeter, the lock screen, sudo, and polkit
    //    (disable puts the opt-in stacks in scope regardless of flags) so no
    //    stack references pam_irlume.so once the module is removed.
    let _ = pamwire::run(
        Some("disable"),
        &["--apply".to_string(), "--with-sudo".to_string()],
    );
    let pam_unwired = !pamwire::login_wired();

    // 2. Stop and disable the daemon, and the self-heal units with it. Leaving
    //    those enabled means a uninstalled irlume still wakes up on a PAM change
    //    or on the timer; they self-gate on the marker so they would no-op, but
    //    an uninstall should not leave units armed. Their failure is not counted
    //    against the daemon's: a box that never enabled login never had them.
    let stop = systemctl(&["stop", "irlumed.service"]);
    let disable = systemctl(&["disable", "irlumed.service"]);
    for unit in [
        "irlume-reconcile.path",
        "irlume-reconcile.timer",
        "irlume-reconcile.service",
    ] {
        let _ = systemctl(&["disable", "--now", unit]);
    }
    // systemd keeps a monotonic stamp per timer under /var/lib/systemd/timers
    // and deletes it neither on disable nor on package remove: the #335 audit
    // found stamp-irlume-reconcile.timer still there after the uninstall AND a
    // reboot. Removed here, right after the unit that owned it.
    remove_timer_stamps(TIMER_STAMP_DIR);
    let service_stopped = stop && disable;

    // 3. Disarm each enrolled user's keyring seal (idempotent), and 4. wipe the
    //    per-user enrollment + sealed secrets unless data is being kept.
    let users = irlume_core::storage::list_users();
    for user in &users {
        let _ = irlume_core::keyring::forget_password(user);
        if !keep_data {
            let _ = irlume_core::storage::delete(user);
        }
    }

    // 4 (cont). Remove the state and config trees: third-party models, any
    //    remaining sealed envelopes, cameras.conf/settings.conf. Guarded so
    //    --keep-data leaves them for a later reinstall.
    if !keep_data {
        // Through `state_dir()`, not the bare constant: the user enumeration
        // above already honors IRLUME_STATE_DIR, so deleting the literal path
        // here meant a SANDBOXED teardown reached into live /var/lib/irlume and
        // took the enrollments, template keys, recovery envelopes and keyring
        // seals with it. That is not hypothetical; the same split resolution in
        // template_key.rs destroyed a real machine's keys on 2026-08-05.
        //
        // A failure is reported rather than swallowed: this used to discard the
        // result, so a partial teardown still announced success and left secrets
        // on disk under a directory the user believes is gone.
        for dir in [
            irlume_common::state_dir(),
            irlume_common::config::CONFIG_ROOT.into(),
        ] {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!(
                        "[uninstall] could not remove {}: {e} (files may remain)",
                        dir.display()
                    );
                }
            }
        }
    }

    TeardownReport {
        pam_unwired,
        service_stopped,
        users_cleared: users.len(),
        data_wiped: !keep_data,
    }
}

/// The package-removal command for how irlume was installed. Pure so it is unit
/// tested; the teardown above is what actually touches the system.
pub fn removal_hint(origin: &InstallOrigin) -> String {
    match origin {
        InstallOrigin::Copr | InstallOrigin::LocalRpm(_) => "sudo dnf remove irlume".into(),
        InstallOrigin::Ppa | InstallOrigin::LocalDeb => "sudo apt remove irlume".into(),
        InstallOrigin::ArchPkg => "sudo pacman -Rns irlume".into(),
        InstallOrigin::Source => {
            "source install: remove the binaries you placed (e.g. /usr/local/bin/irlume, \
             /usr/local/bin/irlumed) and the systemd unit"
                .into()
        }
    }
}

fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no (may not have been running)"
    }
}

fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_hint_maps_each_origin_to_its_package_manager() {
        assert_eq!(removal_hint(&InstallOrigin::Copr), "sudo dnf remove irlume");
        assert_eq!(
            removal_hint(&InstallOrigin::LocalRpm(String::new())),
            "sudo dnf remove irlume"
        );
        assert_eq!(removal_hint(&InstallOrigin::Ppa), "sudo apt remove irlume");
        assert_eq!(
            removal_hint(&InstallOrigin::LocalDeb),
            "sudo apt remove irlume"
        );
        assert_eq!(
            removal_hint(&InstallOrigin::ArchPkg),
            "sudo pacman -Rns irlume"
        );
        assert!(removal_hint(&InstallOrigin::Source).contains("source install"));
    }

    // The repo-residual cleaner backs both the Copr and the PPA teardown; it
    // must take everything the installers drop (repo file, sources file,
    // signing keys, any capitalisation) and nothing else in the directory.
    #[test]
    fn remove_repo_files_deletes_only_irlume_named_entries() {
        let dir = std::env::temp_dir().join(format!("irlume-repo-clean-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ours = [
            "_copr:copr.fedorainfracloud.org:archledger:irlume.repo",
            "archledger-ubuntu-irlume-resolute.sources",
            "IRLUME-2026.gpg",
        ];
        let theirs = ["fedora.repo", "docker.list", "archledger-other.gpg"];
        for f in ours.iter().chain(theirs.iter()) {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        remove_repo_files(dir.to_str().unwrap());
        for f in ours {
            assert!(!dir.join(f).exists(), "{f} should have been removed");
        }
        for f in theirs {
            assert!(dir.join(f).exists(), "{f} must be left alone");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_repo_files_tolerates_a_missing_directory() {
        remove_repo_files("/nonexistent/irlume-repo-dir");
    }

    // remove_repo_files also backs the PPA teardown, which sweeps several key
    // dirs; a nested subdir must be ignored (it only deletes files it names).
    #[test]
    fn remove_repo_files_ignores_subdirectories() {
        let dir = std::env::temp_dir().join(format!("irlume-repo-sub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("irlume-subdir")).unwrap();
        std::fs::write(dir.join("irlume.list"), b"x").unwrap();
        remove_repo_files(dir.to_str().unwrap());
        assert!(!dir.join("irlume.list").exists(), "file should be removed");
        assert!(
            dir.join("irlume-subdir").is_dir(),
            "a same-named subdir must be left in place"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn yn_reports_yes_or_the_maybe_not_running_note() {
        assert_eq!(yn(true), "yes");
        assert_eq!(yn(false), "no (may not have been running)");
    }

    // The stamp cleaner (#335) runs against systemd's timer-stamp directory,
    // where irlume's stamps sit next to every other timer's; it must take only
    // the irlume ones. Exercised on an owned temp dir through the same `dir`
    // parameter the teardown passes TIMER_STAMP_DIR.
    #[test]
    fn remove_timer_stamps_deletes_only_irlume_stamp_files() {
        let dir = std::env::temp_dir().join(format!("irlume-timer-stamps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ours = ["stamp-irlume-reconcile.timer"];
        let theirs = [
            "stamp-fstrim.timer",
            "stamp-logrotate.timer",
            // Not a stamp: the shape matters, not just the irlume name.
            "irlume-reconcile.timer",
        ];
        for f in ours.iter().chain(theirs.iter()) {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        remove_timer_stamps(dir.to_str().unwrap());
        for f in ours {
            assert!(!dir.join(f).exists(), "{f} should have been removed");
        }
        for f in theirs {
            assert!(dir.join(f).exists(), "{f} must be left alone");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_timer_stamps_tolerates_a_missing_directory() {
        remove_timer_stamps("/nonexistent/irlume-timer-stamp-dir");
    }

    // The closing line is the uninstall's last word, and #335 measured it being
    // wrong on a snapshotting box. Without evidence it must be the historical
    // line, byte for byte; with evidence it must name the tool, keep the
    // templates-and-secrets warning, and give the listing command.
    #[test]
    fn closing_line_without_snapshot_evidence_is_the_historical_line() {
        assert_eq!(
            closing_line(&SnapshotEvidence::default()),
            "irlume is removed, with no repo, drop-in, or data left behind."
        );
    }

    #[test]
    fn closing_line_names_each_detected_snapshot_tool_and_its_list_command() {
        let snapper = closing_line(&SnapshotEvidence {
            snapper: true,
            timeshift: false,
        });
        assert!(
            snapper.contains("snapper filesystem snapshots"),
            "{snapper}"
        );
        assert!(
            snapper.contains("wiped templates and sealed secrets"),
            "{snapper}"
        );
        assert!(snapper.contains("`snapper list`"), "{snapper}");
        assert!(
            !snapper.contains("no repo, drop-in, or data left behind"),
            "the all-gone claim must not survive snapshot evidence: {snapper}"
        );

        let timeshift = closing_line(&SnapshotEvidence {
            snapper: false,
            timeshift: true,
        });
        assert!(
            timeshift.contains("Timeshift filesystem snapshots"),
            "{timeshift}"
        );
        assert!(timeshift.contains("`timeshift --list`"), "{timeshift}");

        let both = closing_line(&SnapshotEvidence {
            snapper: true,
            timeshift: true,
        });
        assert!(both.contains("snapper and Timeshift"), "{both}");
        assert!(
            both.contains("`snapper list` and `timeshift --list`"),
            "{both}"
        );
    }

    // The evidence helpers back detection; both must read "cannot look" as "no
    // evidence" rather than an error, because detection may never fail the
    // uninstall (#335).
    #[test]
    fn dir_evidence_helpers_report_contents_and_tolerate_absence() {
        let dir = std::env::temp_dir().join(format!("irlume-snap-evidence-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!dir_has_entries(dir.to_str().unwrap()), "empty dir");
        std::fs::write(dir.join("05-snap-pac-pre.hook"), b"x").unwrap();
        assert!(dir_has_entries(dir.to_str().unwrap()));
        assert!(dir_has_entry_named(dir.to_str().unwrap(), "snap-pac"));
        assert!(!dir_has_entry_named(dir.to_str().unwrap(), "snapper"));
        assert!(!dir_has_entries("/nonexistent/irlume-evidence-dir"));
        assert!(!dir_has_entry_named(
            "/nonexistent/irlume-evidence-dir",
            "snapper"
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // run_pkg maps a package manager's exit into a readable Result: success →
    // Ok, non-zero → Err naming the tool, spawn failure → Err. Exercised with
    // the harmless `true`/`false` shells and a bin that does not exist (never a
    // real package manager, which would touch the system).
    #[test]
    fn run_pkg_maps_exit_status_to_a_result() {
        assert_eq!(
            run_pkg("true", &["remove", "irlume"]).unwrap(),
            "removed the true package"
        );
        let nonzero = run_pkg("false", &[]).unwrap_err();
        assert!(nonzero.contains("false exited with"), "{nonzero}");
        let missing = run_pkg("irlume-no-such-pkg-manager-xyz", &[]).unwrap_err();
        assert!(missing.contains("could not run"), "{missing}");
    }
}
