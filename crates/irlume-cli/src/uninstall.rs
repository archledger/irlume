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
use std::path::PathBuf;
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

    println!("irlume uninstall will:");
    println!("  1. remove irlume from every PAM stack (greeters, sudo, lock screen)");
    println!("  2. stop and disable the irlumed service");
    if keep_data {
        println!("  3. keep your enrolled faces and sealed secrets (--keep-data)");
    } else {
        println!("  3. disarm the keyring seal, then delete every enrolled face,");
        println!("     sealed password, third-party model, and config file");
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
    match removed {
        Ok(what) => {
            println!("[uninstall] {what}");
            println!("[uninstall] irlume is removed, with no repo, drop-in, or data left behind.");
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

    // 2. Stop and disable the daemon.
    let stop = systemctl(&["stop", "irlumed.service"]);
    let disable = systemctl(&["disable", "irlumed.service"]);
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
        let _ = std::fs::remove_dir_all(irlume_common::STATE_DIR);
        let _ = std::fs::remove_dir_all(irlume_common::config::CONFIG_ROOT);
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
