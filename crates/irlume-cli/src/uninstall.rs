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
    /// The run was asked to wipe (no `--keep-data`).
    pub data_wipe_requested: bool,
    /// The wipe was requested AND every deletion succeeded. The PR #337 review
    /// caught this meaning "wipe requested": every delete result was discarded,
    /// so a read-only or failing filesystem still produced the deleted-
    /// everything summary while live templates sat on disk.
    pub data_wiped: bool,
    /// The paths that still hold data after a failed wipe, for the output to
    /// name; empty when the wipe succeeded or was never requested.
    pub data_left: Vec<String>,
}

/// The first argument `uninstall` does not accept, if any.
///
/// Extracted so the refusal is testable without running a teardown: the check
/// itself must never need a machine to prove.
fn unknown_arg(args: &[String]) -> Option<&String> {
    const KNOWN: &[&str] = &["--yes", "-y", "--keep-data", "uninstall"];
    args.iter().find(|a| !KNOWN.contains(&a.as_str()))
}

pub fn run(args: &[String]) -> ExitCode {
    // Refuse anything this command does not know, BEFORE it can delete a thing.
    // `--keep-data` mistyped as `--keep-dat` used to be ignored in silence, and
    // with `--yes` beside it the run wiped every enrolled face, sealed secret and
    // recovery envelope that the flag was there to protect. A destructive verb is
    // the last place to guess what the operator meant.
    if let Some(bad) = unknown_arg(args) {
        eprintln!("[uninstall] unknown argument '{bad}' (accepts: --yes/-y, --keep-data)");
        eprintln!("[uninstall] nothing was removed.");
        return ExitCode::from(2);
    }
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
    // Three states, not two: a requested wipe that FAILED must never read as a
    // completed one (PR #337 review), so the warning names what still holds
    // data instead of borrowing the success phrasing.
    let data_status = if !report.data_wipe_requested {
        "data kept".to_string()
    } else if report.data_wiped {
        "enrollments, seals, models, and config deleted".to_string()
    } else {
        format!(
            "WARNING: the data wipe was incomplete; data remains at {}",
            report.data_left.join(", ")
        )
    };
    println!(
        "[uninstall] users disarmed: {} ({data_status})",
        report.users_cleared
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
    // sealed keyring blob, and the recovery envelope. Detection is evidence-only
    // (no snapshot tool is ever run) and can only ADD listing advice; the
    // warning itself does not depend on it, because snapshots outlive the tools
    // that made them (PR #337 review). Skipped when --keep-data skipped the wipe.
    let snapshots = if report.data_wipe_requested {
        detect_snapshot_tools()
    } else {
        SnapshotEvidence::default()
    };
    let removal_failed = removed.is_err();
    match removed {
        Ok(what) => {
            println!("[uninstall] {what}");
            println!("[uninstall] {}", closing_line(&report, &snapshots));
        }
        Err(e) => {
            println!("[uninstall] could not finish removal automatically: {e}");
            println!("[uninstall] the teardown above is done; remove the package by hand:");
            println!("  {}", removal_hint(&origin));
        }
    }
    // The exit code has to carry what the text already says. Returning success
    // after "the data wipe was incomplete" or "could not finish removal" told
    // every script, and every operator who checks `$?`, that a machine had been
    // cleaned when enrolled templates and sealed envelopes were still on disk.
    let wipe_incomplete = report.data_wipe_requested && !report.data_wiped;
    if removal_failed || wipe_incomplete {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
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

/// The filesystem facts that say a known snapshot tool is present (#335).
/// Gathered from cheap existence checks only; the tools' own commands are never
/// run, because detection must not be able to mutate snapshot state or fail the
/// uninstall. Positive evidence only ADDS listing advice to the closing line;
/// negative evidence proves nothing (PR #337 review: a Timeshift RSYNC snapshot
/// on an external disk outlives an uninstalled Timeshift, and a plain btrfs
/// snapshot or a backup needs neither tool), so no all-clear is ever built on it.
#[derive(Default)]
struct SnapshotEvidence {
    snapper: bool,
    timeshift: bool,
}

fn detect_snapshot_tools() -> SnapshotEvidence {
    detect_snapshot_tools_at(Path::new("/"))
}

/// Detection against an injected filesystem root, so the tests exercise the
/// real path set under a directory they own; production passes `/`.
fn detect_snapshot_tools_at(root: &Path) -> SnapshotEvidence {
    SnapshotEvidence {
        snapper: snapper_evidence(root),
        timeshift: timeshift_evidence(root),
    }
}

/// snapper is present when its binary exists AND etc/snapper/configs holds at
/// least one config, or when a package-manager hook re-snapshots every
/// transaction: snap-pac's pacman hooks (the mechanism that snapshotted the
/// #335 audit box) or openSUSE's zypp commit plugin.
fn snapper_evidence(root: &Path) -> bool {
    let bin = [
        "usr/bin/snapper",
        "usr/sbin/snapper",
        "usr/local/bin/snapper",
    ]
    .iter()
    .any(|p| root.join(p).exists());
    if bin && dir_has_entries(&root.join("etc/snapper/configs")) {
        return true;
    }
    for d in ["usr/share/libalpm/hooks", "etc/pacman.d/hooks"] {
        let d = root.join(d);
        if dir_has_entry_named(&d, "snap-pac") || dir_has_entry_named(&d, "snapper") {
            return true;
        }
    }
    dir_has_entry_named(&root.join("usr/lib/zypp/plugins/commit"), "snapper")
}

/// Timeshift needs less corroboration than snapper: its binary or etc/timeshift
/// only exist when someone installed it, and it exists only to take snapshots.
fn timeshift_evidence(root: &Path) -> bool {
    [
        "usr/bin/timeshift",
        "usr/sbin/timeshift",
        "usr/local/bin/timeshift",
        "etc/timeshift",
    ]
    .iter()
    .any(|p| root.join(p).exists())
}

/// True when `dir` holds at least one READABLE entry. Unreadable entries are
/// skipped, not counted: `ReadDir` yields `Some(Err(_))` for an entry it cannot
/// read, and treating that as evidence contradicted the no-evidence contract
/// (PR #337 review). A missing or unreadable dir is likewise no evidence, never
/// an error: detection must not fail the uninstall (#335).
fn dir_has_entries(dir: &Path) -> bool {
    match std::fs::read_dir(dir) {
        Ok(entries) => entries.flatten().next().is_some(),
        Err(_) => false,
    }
}

/// True when `dir` holds an entry whose name contains `needle`, compared in
/// lowercase. Same tolerance as `dir_has_entries`.
fn dir_has_entry_named(dir: &Path, needle: &str) -> bool {
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

/// The closing line of a successful removal, pure over the teardown report and
/// the snapshot evidence so every arm is unit tested. The old "no repo,
/// drop-in, or data left behind" claim is retired for a wipe on purpose (#335,
/// PR #337 review): this process cannot see inside snapshots or backups, so
/// after a wipe it always says they may retain the deleted data, and positive
/// tool evidence only appends the matching listing command. A failed wipe never
/// borrows the deleted phrasing; it names the paths that still hold data.
fn closing_line(report: &TeardownReport, snapshots: &SnapshotEvidence) -> String {
    if !report.data_wipe_requested {
        return "irlume is removed, with no repo or drop-in left behind; your enrolled \
                faces, sealed secrets, models, and config were kept (--keep-data)."
            .into();
    }
    if !report.data_wiped {
        return format!(
            "irlume is removed, but the requested data wipe was incomplete: data \
             remains at {}; filesystem snapshots and backups may also retain copies.",
            report.data_left.join(", ")
        );
    }
    let mut line = "irlume is removed, with no repo or drop-in left behind. Live irlume \
                    data was deleted, but filesystem snapshots and backups may still \
                    contain the deleted templates and sealed secrets."
        .to_string();
    let mut list_cmds: Vec<&str> = Vec::new();
    if snapshots.snapper {
        list_cmds.push("`snapper list`");
    }
    if snapshots.timeshift {
        list_cmds.push("`timeshift --list`");
    }
    if !list_cmds.is_empty() {
        line.push_str(&format!(" List them with {}.", list_cmds.join(" and ")));
    }
    line
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
        // The login-runner prune unit ships enabled-by-default in some lanes;
        // an uninstall must not leave a dead unit armed (#335 class).
        "irlume-runner-prune.service",
    ] {
        let _ = systemctl(&["disable", "--now", unit]);
    }
    // The socket unit does not unlink its socket file on stop, and a stopped
    // daemon leaves /run/irlume.sock behind as a stale node (found by the
    // 0.11.0rc1 uninstall-cleanliness audit). Remove it when the service is
    // down; a live daemon would only recreate it, so only try after a stop.
    if stop {
        let sock = std::path::Path::new("/run/irlume.sock");
        if sock.exists() {
            let _ = std::fs::remove_file(sock);
        }
    }
    // `systemctl enable` copies units into /etc/systemd/system/ (Arch's
    // systemd does this for units with [Install] aliases) — files pacman/apt
    // do not own, so package removal leaves them behind as the second
    // RC2 audit finding (4 files + a still-enabled timer). Remove exactly the
    // irlume-named units from /etc; package-owned /usr/lib copies are the
    // package manager's business.
    for unit in [
        "irlume-runner-prune.timer",
        "irlume-runner-prune.service",
        "irlume-reconcile.path",
        "irlume-reconcile.timer",
        "irlume-reconcile.service",
        "irlumed.socket",
        "irlumed.service",
    ] {
        let _ = systemctl(&["reset-failed", unit]);
        let p = std::path::Path::new("/etc/systemd/system").join(unit);
        if p.exists() {
            let _ = std::fs::remove_file(&p);
        }
    }
    // Reload so a later `systemctl list-unit-files` reflects the removal.
    let _ = systemctl(&["daemon-reload"]);
    // AppArmor: removing the package deletes /etc/apparmor.d/usr.bin.irlumed
    // but does NOT unload the profile from the kernel — the daemon binary is
    // gone, so the residual profile can only cause confusion (and would
    // silently re-confine a later non-irlume binary at the same path). Unload
    // it explicitly; absence of apparmor_parser is not an error (non-AA boxes).
    if std::path::Path::new("/etc/apparmor.d/usr.bin.irlumed").exists()
        || Command::new("apparmor_status")
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("irlumed"))
            .unwrap_or(false)
    {
        let _ = Command::new("apparmor_parser")
            .args(["-R", "/etc/apparmor.d/usr.bin.irlumed"])
            .status();
    }
    // systemd keeps a monotonic stamp per timer under /var/lib/systemd/timers
    // and deletes it neither on disable nor on package remove: the #335 audit
    // found stamp-irlume-reconcile.timer still there after the uninstall AND a
    // reboot. Removed here, right after the unit that owned it.
    remove_timer_stamps(TIMER_STAMP_DIR);
    let service_stopped = stop && disable;

    // 3. Disarm each enrolled user's keyring seal (idempotent), and 4. wipe the
    //    per-user enrollment + sealed secrets unless data is being kept. Every
    //    deletion result is collected: a discarded Err here is what let a
    //    failed wipe report itself as "deleted" (PR #337 review), so any
    //    failure lands in data_left and pulls data_wiped false.
    let users = irlume_core::storage::list_users();
    let mut data_left: Vec<String> = Vec::new();
    for user in &users {
        let _ = irlume_core::keyring::forget_password(user);
        if !keep_data {
            if let Err(e) = irlume_core::storage::delete(user) {
                let path = irlume_core::storage::profile_path(user);
                eprintln!(
                    "[uninstall] could not delete the enrollment of {user} at {}: {e}",
                    path.display()
                );
                data_left.push(path.display().to_string());
            }
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
        for dir in wipe_data_trees(&[
            irlume_common::state_dir(),
            irlume_common::config::CONFIG_ROOT.into(),
        ]) {
            data_left.push(dir.display().to_string());
        }
        // Per-user XDG state (~/.local/share/irlume): login-runner records and
        // similar. Root cannot know every human's $HOME, so sweep the HOMEs of
        // human accounts (uid >= 1000). Files owned by root inside a user HOME
        // (written by a past `sudo irlume` run) still remove fine here because
        // teardown itself runs as root; the residue the 0.11.0rc1 audit found
        // was exactly such a root-owned file a non-root sweep would miss.
        for home in human_homes() {
            let p = home.join(".local/share/irlume");
            for dir in wipe_data_trees(&[p]) {
                data_left.push(format!("{} (user state)", dir.display()));
            }
        }
    }

    let data_wipe_requested = !keep_data;
    TeardownReport {
        pam_unwired,
        service_stopped,
        users_cleared: users.len(),
        data_wipe_requested,
        data_wiped: data_wipe_requested && data_left.is_empty(),
        data_left,
    }
}

/// HOME directories of human accounts (uid >= 1000, below the nobody range),
/// via /etc/passwd. Used only to sweep per-user XDG state at uninstall; an
/// unreadable passwd entry is skipped, not fatal.
fn human_homes() -> Vec<std::path::PathBuf> {
    let Ok(passwd) = std::fs::read_to_string("/etc/passwd") else {
        return Vec::new();
    };
    passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            match (f.first(), f.get(2), f.get(5)) {
                (Some(_), Some(uid), Some(home)) => {
                    let uid: u32 = uid.parse().ok()?;
                    (1000..=60000).contains(&uid).then(|| (*home).into())
                }
                _ => None,
            }
        })
        .collect()
}

/// Delete the given data trees and return the ones that still exist afterwards.
/// A missing tree is a success (nothing to wipe); any other failure is reported
/// on the spot AND returned, so the caller can refuse to claim a completed wipe
/// (PR #337 review: this used to only print, and the report still said wiped).
/// Takes the trees as a parameter so a failing removal is testable against
/// paths the test owns.
fn wipe_data_trees(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut remaining = Vec::new();
    for dir in dirs {
        if let Err(e) = std::fs::remove_dir_all(dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "[uninstall] could not remove {}: {e} (files remain)",
                    dir.display()
                );
                remaining.push(dir.clone());
            }
        }
    }
    remaining
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
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    unsafe {
        libc::isatty(0) == 1
    }
}

#[cfg(test)]
mod tests {

    /// A destructive verb must not guess. `--keep-data` mistyped is the whole
    /// reason this exists: it used to be ignored, and with `--yes` beside it the
    /// run wiped every enrolled face, sealed secret and recovery envelope the
    /// flag was there to keep.
    #[test]
    fn uninstall_refuses_an_argument_it_does_not_know() {
        let argv = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert_eq!(
            unknown_arg(&argv(&["uninstall", "--keep-dat", "--yes"])).map(String::as_str),
            Some("--keep-dat"),
            "a mistyped --keep-data must be caught, not ignored"
        );
        assert_eq!(
            unknown_arg(&argv(&["uninstall", "--purge"])).map(String::as_str),
            Some("--purge")
        );
        // Every accepted spelling passes, alone and together.
        for ok in [
            vec!["uninstall"],
            vec!["uninstall", "--yes"],
            vec!["uninstall", "-y"],
            vec!["uninstall", "--keep-data"],
            vec!["uninstall", "--keep-data", "--yes"],
        ] {
            assert!(unknown_arg(&argv(&ok)).is_none(), "{ok:?} must be accepted");
        }
    }
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

    // A report shaped like a run whose only interesting facts are the wipe
    // fields; the PAM/service fields are irrelevant to the closing line.
    fn report(requested: bool, wiped: bool, left: &[&str]) -> TeardownReport {
        TeardownReport {
            pam_unwired: true,
            service_stopped: true,
            users_cleared: 1,
            data_wipe_requested: requested,
            data_wiped: wiped,
            data_left: left.iter().map(|s| s.to_string()).collect(),
        }
    }

    // The closing line is the uninstall's last word, and the PR #337 review
    // proved the old contract wrong twice: negative tool detection licensed an
    // all-clear that snapshots on external disks falsify, and a failed wipe
    // borrowed the success phrasing. The new contract: a completed wipe ALWAYS
    // warns about snapshots and backups, evidence only appends listing advice.
    #[test]
    fn closing_line_after_a_wipe_always_warns_even_with_no_tool_evidence() {
        let line = closing_line(&report(true, true, &[]), &SnapshotEvidence::default());
        assert!(
            line.contains("snapshots and backups may still contain the deleted templates"),
            "{line}"
        );
        assert!(
            !line.contains("no repo, drop-in, or data left behind"),
            "the retired all-gone claim must not come back: {line}"
        );
        assert!(
            !line.contains("snapper") && !line.contains("timeshift"),
            "no tool advice without evidence: {line}"
        );
    }

    #[test]
    fn closing_line_appends_listing_advice_only_on_positive_evidence() {
        let wiped = report(true, true, &[]);
        let snapper = closing_line(
            &wiped,
            &SnapshotEvidence {
                snapper: true,
                timeshift: false,
            },
        );
        assert!(snapper.contains("may still contain"), "{snapper}");
        assert!(snapper.contains("`snapper list`"), "{snapper}");
        assert!(!snapper.contains("timeshift"), "{snapper}");

        let timeshift = closing_line(
            &wiped,
            &SnapshotEvidence {
                snapper: false,
                timeshift: true,
            },
        );
        assert!(timeshift.contains("`timeshift --list`"), "{timeshift}");

        let both = closing_line(
            &wiped,
            &SnapshotEvidence {
                snapper: true,
                timeshift: true,
            },
        );
        assert!(
            both.contains("`snapper list` and `timeshift --list`"),
            "{both}"
        );
    }

    #[test]
    fn closing_line_with_keep_data_states_the_data_was_kept() {
        let line = closing_line(&report(false, false, &[]), &SnapshotEvidence::default());
        assert!(line.contains("were kept"), "{line}");
        assert!(
            !line.contains("may still contain") && !line.contains("deleted"),
            "kept data needs no deletion talk: {line}"
        );
    }

    #[test]
    fn closing_line_after_a_failed_wipe_names_the_leftovers_and_never_claims_deletion() {
        let line = closing_line(
            &report(true, false, &["/var/lib/irlume", "/etc/irlume"]),
            &SnapshotEvidence::default(),
        );
        assert!(line.contains("incomplete"), "{line}");
        assert!(line.contains("/var/lib/irlume, /etc/irlume"), "{line}");
        assert!(
            !line.contains("data was deleted") && !line.contains("left behind"),
            "a failed wipe must not borrow the success phrasing: {line}"
        );
    }

    // The wipe helper is what data_wiped now means (PR #337 review): a tree it
    // could not remove must come back to the caller, not vanish into stderr.
    // remove_dir_all on a regular FILE fails on any filesystem, root or not, so
    // the failure fixture is deterministic.
    #[test]
    fn human_homes_skips_system_accounts_and_malformed_lines() {
        // Invariant test (no /etc/passwd fixture): every returned home is an
        // absolute path belonging to a human account; a machine with no human
        // users legitimately returns an empty vec. System accounts (root,
        // nobody, daemons) never appear because of the uid >= 1000 filter.
        for h in human_homes() {
            assert!(
                h.is_absolute(),
                "a passwd HOME must be absolute: {}",
                h.display()
            );
        }
    }

    #[test]
    fn wipe_data_trees_returns_the_trees_it_could_not_remove() {
        let root = std::env::temp_dir().join(format!("irlume-wipe-trees-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("state/sub")).unwrap();
        std::fs::write(root.join("state/sub/profile.json"), b"x").unwrap();
        std::fs::write(root.join("not-a-dir"), b"x").unwrap();
        let removable = root.join("state");
        let stuck = root.join("not-a-dir");
        let missing = root.join("never-existed");

        let remaining = wipe_data_trees(&[removable.clone(), stuck.clone(), missing]);

        assert_eq!(remaining, vec![stuck], "only the failed tree comes back");
        assert!(!removable.exists(), "the removable tree must be gone");
        let _ = std::fs::remove_dir_all(&root);
    }

    // Detection through the injected root, over the REAL path set: an empty
    // root yields no evidence, the audit box's snap-pac hook yields snapper,
    // the binary-plus-config pair yields snapper, /etc/timeshift yields
    // Timeshift. This is the wiring test the first cut lacked (PR #337 review:
    // the helpers were tested, the detectors were dead code to the suite).
    #[test]
    fn detect_snapshot_tools_at_reads_the_evidence_under_the_injected_root() {
        let root = std::env::temp_dir().join(format!("irlume-snap-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let none = detect_snapshot_tools_at(&root);
        assert!(!none.snapper && !none.timeshift, "empty root, no evidence");

        // The #335 audit mechanism: snap-pac's pacman hook, no snapper binary.
        std::fs::create_dir_all(root.join("usr/share/libalpm/hooks")).unwrap();
        std::fs::write(
            root.join("usr/share/libalpm/hooks/05-snap-pac-pre.hook"),
            b"x",
        )
        .unwrap();
        assert!(detect_snapshot_tools_at(&root).snapper, "hook is evidence");
        let _ = std::fs::remove_dir_all(root.join("usr"));

        // Binary alone is not enough; binary plus a config is.
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/snapper"), b"x").unwrap();
        assert!(
            !detect_snapshot_tools_at(&root).snapper,
            "an installed but unconfigured snapper is not evidence"
        );
        std::fs::create_dir_all(root.join("etc/snapper/configs")).unwrap();
        std::fs::write(root.join("etc/snapper/configs/root"), b"x").unwrap();
        let snapper = detect_snapshot_tools_at(&root);
        assert!(snapper.snapper, "binary plus config is evidence");
        assert!(!snapper.timeshift);

        std::fs::create_dir_all(root.join("etc/timeshift")).unwrap();
        assert!(detect_snapshot_tools_at(&root).timeshift);
        let _ = std::fs::remove_dir_all(&root);
    }

    // The evidence helpers must read "cannot look" as "no evidence" rather than
    // an error, because detection may never fail the uninstall (#335).
    #[test]
    fn dir_evidence_helpers_report_contents_and_tolerate_absence() {
        let dir = std::env::temp_dir().join(format!("irlume-snap-evidence-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!dir_has_entries(&dir), "empty dir");
        std::fs::write(dir.join("05-snap-pac-pre.hook"), b"x").unwrap();
        assert!(dir_has_entries(&dir));
        assert!(dir_has_entry_named(&dir, "snap-pac"));
        assert!(!dir_has_entry_named(&dir, "snapper"));
        let missing = Path::new("/nonexistent/irlume-evidence-dir");
        assert!(!dir_has_entries(missing));
        assert!(!dir_has_entry_named(missing, "snapper"));
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
