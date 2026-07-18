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
//! Only then is removing the package safe. This command does not run the
//! package manager itself; it prints the exact command for how irlume was
//! installed. The same teardown backs the TUI's uninstall entry, which puts its
//! own double-confirmation in front of it.

use crate::commands::{install_origin, InstallOrigin};
use crate::pamwire;
use std::io::Write;
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
    println!("It does not remove the package; it prints that command at the end.");
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

    println!();
    println!("Teardown done. To remove the package itself:");
    println!("  {}", removal_hint(&install_origin()));
    ExitCode::SUCCESS
}

/// Run the four teardown steps in the lockout-safe order. Public so the TUI
/// calls the identical sequence behind its own confirmation.
pub fn perform_teardown(keep_data: bool) -> TeardownReport {
    // 1. PAM FIRST. Un-wire every greeter, the lock screen, and sudo so no
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

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
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
}
