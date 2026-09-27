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
//!   4. wipe enrolled templates, sealed secrets, and config
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
    /// What happened to the persisted TPM storage root key. Only attempted
    /// after a fully completed wipe: sealed envelopes are children of that
    /// key, so kept or leftover data must keep it (audit F4, 2026-09-17).
    pub srk_eviction: SrkOutcome,
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
    // is encrypted under. The one exception is what root does not own inside
    // an account's own ~/.local/share/irlume: only a root irlumed writes a
    // store there, so one that account wrote is named instead.
    // The sweep covers EVERY state root, not just the one this process's
    // environment resolves: a source install (install-host.sh) points the
    // daemon at the admin's ~/.local/share/irlume, which a root shell never
    // sees, and the homes wipe below would delete that envelope without this
    // refusal ever firing (2026-09-17 uninstall audit).
    let token_users = match sealed_token_holders() {
        Ok(sweep) => {
            for note in &sweep.notes {
                eprintln!("[uninstall] {note}");
            }
            sweep.holders
        }
        Err(store) => {
            eprintln!(
                "[uninstall] refusing: could not read the sealed-envelope store ({store}). \
                 One of these may hold a GNOME keyring token, and deleting it would \
                 leave that keyring encrypted under a secret nothing can reproduce. \
                 Fix the store (or move it aside deliberately) and re-run."
            );
            return ExitCode::FAILURE;
        }
    };
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
        println!("     sealed secret, and config file");
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
    println!(
        "[uninstall] TPM storage root key: {}",
        srk_outcome_line(&report.srk_eviction)
    );

    // A stack the disable had to leave as it is still names pam_irlume.so.
    // Removing the module under it would turn that rule into one PAM cannot
    // load, which a `required` rule an administrator wrote turns into a failed
    // login even with the right password. irlume stays installed until no
    // stack references it.
    if let Some(refusal) = removal_refusal(&report) {
        println!();
        println!("[uninstall] {refusal}");
        return ExitCode::FAILURE;
    }

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
    // Name the one deliberate leave-behind the audit found (F6): the polkit
    // action file `irlume bitwarden setup --apply` wrote serves Bitwarden, not
    // irlume, so it survives the uninstall - but never as a surprise.
    if let Some(notice) = bitwarden_polkit_notice() {
        println!("[uninstall] {notice}");
    }
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

/// Why irlume itself is not removed after this teardown, when it is not: a
/// PAM stack still references `pam_irlume.so` (one `login disable` keeps as
/// it is, such as a stack with a line that ends in `\`).
fn removal_refusal(report: &TeardownReport) -> Option<String> {
    (!report.pam_unwired).then(|| {
        "irlume stays installed: a PAM stack still references pam_irlume.so (the lines \
         above name it), and removing the module under it can make that stack fail. \
         Take irlume's lines out of it by hand (`irlume login status` shows which), \
         then run `sudo irlume uninstall` again."
            .to_string()
    })
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
        // -Rns to match the manual hint: without -n, pacman keeps a .pacsave
        // of the backup-marked /etc/pam.d/irlume-retry-reset.
        InstallOrigin::ArchPkg => run_pkg("pacman", arch_remove_args()),
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

/// The pacman removal arguments, pure so the hint parity is pinned by a test.
fn arch_remove_args() -> &'static [&'static str] {
    &["-Rns", "--noconfirm", "irlume"]
}

/// Delete the files a source install placed: the two binaries (this one and its
/// sibling irlumed), the PAM module, the systemd unit + drop-ins, and the model
/// tree. The state/config dirs are already gone from the teardown. Best-effort;
/// reports the count removed.
///
/// This also sweeps files only a PACKAGE lane places (the libexec helpers, the
/// retry-reset PAM service, the /usr/lib unit copies, the tmpfiles rule, the
/// AppArmor profile file): `install_origin()` reaches this function only when
/// the package database has no irlume entry, so by construction no package
/// owns those paths here and nothing else would ever remove them
/// (2026-09-17 uninstall audit).
fn remove_source_files() -> Result<String, String> {
    let mut targets: Vec<PathBuf> = Vec::new();

    // The running binary and irlumed next to it.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            targets.push(dir.join("irlumed"));
        }
        targets.push(exe);
    }
    targets.extend(source_file_targets());
    let _ = std::fs::remove_dir_all("/etc/systemd/system/irlumed.service.d");
    // The model tree (the two common source-install prefixes).
    for d in ["/usr/share/irlume", "/usr/local/share/irlume"] {
        let _ = std::fs::remove_dir_all(d);
    }
    // The wallet handoff helpers' directory (package lanes fill it; the
    // password-verify helper beside it is in the target list above).
    let _ = std::fs::remove_dir_all("/usr/libexec/irlume");

    let desktop_removed = remove_source_desktop_files(Path::new("/usr/local/share"))
        .map_err(|e| format!("could not remove the source-installed desktop entry: {e}"))?;
    let removed = desktop_removed
        + targets
            .iter()
            .filter(|p| p.exists() && std::fs::remove_file(p).is_ok())
            .count();
    let _ = systemctl(&["daemon-reload"]);
    if removed == 0 {
        return Err("found no source-installed files to remove (already gone?)".into());
    }
    Ok(format!("removed {removed} source-installed file(s)"))
}

/// The constant file targets of a source removal (everything except the
/// running binary and its sibling, which depend on `current_exe`). Pure so a
/// test can pin every lane artifact this must cover.
fn source_file_targets() -> Vec<PathBuf> {
    let mut targets: Vec<PathBuf> = Vec::new();
    // The PAM module, wherever the loader keeps modules on this distro.
    for d in [
        "/usr/lib/security",
        "/usr/lib64/security",
        "/lib/security",
        "/lib/x86_64-linux-gnu/security",
    ] {
        targets.push(PathBuf::from(d).join("pam_irlume.so"));
    }
    targets.push(PathBuf::from(
        "/usr/share/polkit-1/actions/org.irlume.enroll.policy",
    ));
    targets.push(PathBuf::from(
        "/usr/share/polkit-1/actions/org.irlume.recovery-manage.policy",
    ));
    targets.push(PathBuf::from("/etc/systemd/system/irlumed.service"));
    // Package-path unit copies: orphaned whenever this function runs (a
    // package entry would have routed removal through the package manager).
    for d in ["/usr/lib/systemd/system", "/lib/systemd/system"] {
        for unit in [
            "irlumed.service",
            "irlumed.socket",
            "irlume-reconcile.path",
            "irlume-reconcile.service",
            "irlume-reconcile.timer",
            "irlume-runner-prune.service",
            "irlume-runner-prune.timer",
        ] {
            targets.push(PathBuf::from(d).join(unit));
        }
    }
    // The tmpfiles rule (packaged location plus the admin override location)
    // and the AppArmor profile file; the profile itself is unloaded by the
    // teardown before this runs.
    for d in ["/usr/lib/tmpfiles.d", "/etc/tmpfiles.d"] {
        targets.push(PathBuf::from(d).join("irlume.conf"));
    }
    targets.push(PathBuf::from("/etc/apparmor.d/usr.bin.irlumed"));
    // The privileged-verification helper and irlume's PAM service file.
    targets.push(PathBuf::from("/usr/libexec/irlume-password-verify"));
    targets.push(PathBuf::from("/etc/pam.d/irlume-retry-reset"));
    targets
}

/// Only the two files placed by install-host.sh. Leave system package entries,
/// user overrides, and the shared applications/icon directories alone.
fn remove_source_desktop_files(share: &Path) -> std::io::Result<usize> {
    let mut removed = 0;
    for relative in [
        "applications/io.github.archledger.Irlume.desktop",
        "icons/hicolor/scalable/apps/io.github.archledger.Irlume.svg",
    ] {
        match std::fs::remove_file(share.join(relative)) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

/// Remove irlume artifacts a package `remove` leaves behind: the admin-created
/// `logs debug on` systemd drop-in (not package-owned), empty share dirs a
/// package manager can leave, and the install channel the installer added.
/// Runs for every install method.
fn clean_residuals(origin: &InstallOrigin) {
    // `irlume logs debug on` drops this in; it survives a package remove.
    let _ = std::fs::remove_dir_all("/etc/systemd/system/irlumed.service.d");
    let _ = systemctl(&["daemon-reload"]);
    // Empty model/onnxruntime dirs a package remove can leave behind.
    for d in ["/usr/share/irlume", "/usr/local/share/irlume"] {
        let _ = std::fs::remove_dir_all(d);
    }
    // Ask the same channel manager that created the repository to remove its
    // exact identity. Generated filenames vary by distro/release, and keyrings
    // are shared ownership domains, so neither is safe to infer and unlink.
    if let Err(e) = remove_install_channel(origin) {
        eprintln!("[uninstall] warning: install channel may remain: {e}");
    }
}

fn install_channel_command(
    origin: &InstallOrigin,
) -> Option<(&'static str, &'static [&'static str])> {
    match origin {
        InstallOrigin::Copr => Some(("dnf", &["-y", "copr", "remove", "archledger/irlume"])),
        InstallOrigin::Ppa => Some((
            "add-apt-repository",
            &["-y", "--remove", "--ppa", "ppa:archledger/irlume"],
        )),
        _ => None,
    }
}

fn remove_install_channel_with(
    origin: &InstallOrigin,
    mut run: impl FnMut(&str, &[&str]) -> Result<(), String>,
) -> Result<(), String> {
    let Some((bin, args)) = install_channel_command(origin) else {
        return Ok(());
    };
    run(bin, args)
}

fn remove_install_channel(origin: &InstallOrigin) -> Result<(), String> {
    remove_install_channel_with(origin, |bin, args| {
        match Command::new(bin).args(args).status() {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(format!("{bin} exited with {status}")),
            Err(e) => Err(format!("could not run {bin} ({e})")),
        }
    })
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
/// the snapshot evidence so every arm is unit tested. Repository-manager
/// removal is reported before this line, and shared signing keys may remain, so
/// no branch claims complete channel cleanup. After a wipe, this process also
/// cannot see inside snapshots or backups. A failed wipe never borrows the
/// deleted phrasing; it names the paths that still hold data.
fn closing_line(report: &TeardownReport, snapshots: &SnapshotEvidence) -> String {
    const CHANNEL_RESIDUAL_NOTE: &str =
        "The install-channel removal is reported separately; shared signing keys may remain.";
    if !report.data_wipe_requested {
        return format!(
            "irlume is removed; your enrolled faces, sealed secrets, models, and config \
             were kept (--keep-data). {CHANNEL_RESIDUAL_NOTE}"
        );
    }
    if !report.data_wiped {
        return format!(
            "irlume is removed, but the requested data wipe was incomplete: data \
             remains at {}; filesystem snapshots and backups may also retain copies. \
             {CHANNEL_RESIDUAL_NOTE}",
            report.data_left.join(", "),
        );
    }
    let mut line = format!(
        "irlume is removed. Live irlume data was deleted, but filesystem snapshots and \
         backups may still contain the deleted templates and sealed secrets. \
         {CHANNEL_RESIDUAL_NOTE}"
    );
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
    // The state roots outside the default, resolved before anything is
    // removed: the one irlumed's unit names is lost once the unit goes, and
    // every one of them is both disarmed and wiped below. The token guard
    // read the same roots before the teardown began and refused on an error;
    // one that appears only now (the unit became unreadable since) keeps the
    // wipe from counting as complete, and with it the SRK eviction.
    // Each account's own tree is held open from here on, and one that is not
    // a real directory of that account's or root's is only named. The unit's
    // root is used here only when it is no account's tree, since those are
    // never reached through a path again.
    let default_root = irlume_common::state_dir();
    let accounts = sweep_accounts();
    let homes = home_trees(&accounts, &default_root);
    let account_trees: Vec<PathBuf> = accounts.iter().map(|a| home_state_path(&a.home)).collect();
    let (extra_roots, roots_unknown) = match unit_state_roots(&default_root) {
        Ok(mut roots) => {
            roots.retain(|root| !account_trees.contains(root));
            (roots, None)
        }
        Err(e) => (Vec::new(), Some(e)),
    };
    // 1. PAM FIRST. Un-wire every greeter, the lock screen, sudo, and polkit
    //    (disable puts the opt-in stacks in scope regardless of flags) so no
    //    stack references pam_irlume.so once the module is removed.
    let _ = pamwire::run(
        Some("disable"),
        &["--apply".to_string(), "--with-sudo".to_string()],
    );
    // Every stack the disable covers, sudo and polkit-1 included: it keeps a
    // stack it cannot change safely as it is, and says so above.
    let pam_unwired = !pamwire::any_stack_wired();

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
        // The tmpfiles-created IR-emitter lock directory (#542): tmpfs, but
        // the uninstall's own cleanliness standard removed the stale socket
        // for exactly this residue class (0.11.0rc1 audit).
        let _ = std::fs::remove_dir_all("/run/lock/irlume");
        // The machine-API session lock's directory for root without a
        // runtime directory (`machine::ROOT_SESSION_DIR`); only root can
        // create it under /run.
        let _ = std::fs::remove_dir_all(crate::machine::ROOT_SESSION_DIR);
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
    if let Some(e) = &roots_unknown {
        data_left.push(format!(
            "state roots irlumed's unit names (could not be read: {e}; not disarmed or wiped)"
        ));
    }
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
    // Source-lane roots: disarm their seals too. The wipe below takes the
    // whole tree, but a --keep-data uninstall must still disarm, and the
    // count must reflect every user this teardown actually disarmed (the
    // default-root enumeration above is blind to these roots for the same
    // environment reason as the token guard; 2026-09-17 audit).
    let mut users_cleared = users.len() + disarm_home_trees(&homes);
    for root in &extra_roots {
        for user in irlume_core::storage::list_users_at(root) {
            let _ = irlume_core::keyring::forget_password_in(root, &user);
            users_cleared += 1;
        }
    }

    // 4 (cont). Remove the state and config trees: any
    //    remaining sealed envelopes, cameras.conf/settings.conf (and any
    //    legacy third-party-model leftovers from pre-ADR-0015 installs).
    //    Guarded so --keep-data leaves them for a later reinstall.
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
        // similar, and a source install's state. Root cannot know every
        // human's $HOME, so sweep the HOMEs of human accounts (uid >= 1000)
        // and root's own. Files owned by root inside a user HOME (written by a
        // past `sudo irlume` run) still remove fine here because teardown
        // itself runs as root; the residue the 0.11.0rc1 audit found was
        // exactly such a root-owned file a non-root sweep would miss. Only a
        // tree verified inside its home is removed, through the directory
        // that holds it; anything else there is named and left.
        data_left.extend(wipe_home_trees(&homes));
        // And the root irlumed's unit named, when it is no account's tree.
        // The unit's value comes from a configuration file, so only a
        // directory named `irlume`, as install-host.sh writes it, is removed
        // whole; any other is left and reported rather than trusted with a
        // recursive delete.
        let (ours, other): (Vec<PathBuf>, Vec<PathBuf>) = extra_roots
            .iter()
            .cloned()
            .partition(|root| root.file_name().is_some_and(|name| name == "irlume"));
        for dir in wipe_data_trees(&ours) {
            data_left.push(format!("{} (state root)", dir.display()));
        }
        for dir in other.iter().filter(|dir| dir.exists()) {
            data_left.push(format!(
                "{} (state root irlumed's unit names; not an `irlume` directory, so left for you)",
                dir.display()
            ));
        }
    }

    let data_wipe_requested = !keep_data;
    let data_wiped = data_wipe_requested && data_left.is_empty();
    // The persisted SRK is evicted only when NO sealed envelope can still
    // exist anywhere (audit F4 + the #757 review): `data_wiped` proves the
    // wiped trees are gone, but sealed data can live under the env overrides
    // (`IRLUME_KEYRING_DIR`, `IRLUME_RECOVERY_DIR`,
    // `IRLUME_TEMPLATE_KEY_DIR`) that the wipe never touched, so an active
    // override blocks eviction outright - and the multi-root envelope
    // enumeration must re-run EMPTY after the wipe (an unreadable store also
    // blocks it; the guard's own contract, and so does anything it only
    // named). Absent and Foreign are successes; a TPM error is non-fatal (the
    // key is a benign orphan).
    let srk_eviction = if may_evict_srk(
        data_wiped,
        srk_override_dirs_active(),
        sealed_token_holders().and_then(|sweep| match sweep.notes.first() {
            Some(note) => Err(note.clone()),
            None => Ok(sweep.holders),
        }),
    ) {
        match irlume_core::tpm::evict_persistent_srk() {
            Ok(irlume_core::tpm::SrkEviction::Evicted) => SrkOutcome::Evicted,
            Ok(irlume_core::tpm::SrkEviction::Absent) => SrkOutcome::Absent,
            Ok(irlume_core::tpm::SrkEviction::Foreign) => SrkOutcome::Foreign,
            Err(e) => SrkOutcome::Failed(e.to_string()),
        }
    } else {
        SrkOutcome::Kept
    };
    TeardownReport {
        pam_unwired,
        service_stopped,
        users_cleared,
        data_wipe_requested,
        data_wiped,
        data_left,
        srk_eviction,
    }
}

/// True when any of the env overrides that can hold sealed data OUTSIDE the
/// wiped trees is set for this process (the #757 review): the uninstaller can
/// enumerate and re-check its own roots, but it cannot know where an
/// overridden keyring/recovery/template-key dir points on a unit's behalf, so
/// the destructive TPM step stays off whenever one is visible.
fn srk_override_dirs_active() -> bool {
    [
        "IRLUME_KEYRING_DIR",
        "IRLUME_RECOVERY_DIR",
        "IRLUME_TEMPLATE_KEY_DIR",
    ]
    .iter()
    .any(|k| std::env::var_os(k).is_some())
}

/// The eviction gate, pure so its contract is testable: a completed wipe
/// alone is NOT sufficient - an active override means out-of-tree envelopes
/// may survive, and a non-empty or unreadable post-wipe enumeration means
/// sealed data is still there. Every blocker keeps the key.
fn may_evict_srk(
    data_wiped: bool,
    override_active: bool,
    token_holders: Result<Vec<String>, String>,
) -> bool {
    data_wiped && !override_active && matches!(token_holders, Ok(holders) if holders.is_empty())
}

/// An account whose home may hold per-user irlume state.
struct Account {
    name: String,
    uid: u32,
    home: PathBuf,
}

/// The accounts whose homes the uninstaller sweeps, from /etc/passwd: the
/// human ones and root. An unreadable passwd names none.
fn sweep_accounts() -> Vec<Account> {
    sweep_accounts_in(&std::fs::read_to_string("/etc/passwd").unwrap_or_default())
}

fn sweep_accounts_in(passwd: &str) -> Vec<Account> {
    let mut accounts = human_accounts_in(passwd);
    accounts.extend(root_home_in(passwd).map(|home| Account {
        name: "root".into(),
        uid: 0,
        home,
    }));
    accounts
}

/// Human accounts (uid 1000 to 60000, below the nobody range) with an
/// absolute home. A malformed line is skipped, not fatal.
fn human_accounts_in(passwd: &str) -> Vec<Account> {
    passwd
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let (name, uid, home) = (fields.first()?, fields.get(2)?, fields.get(5)?);
            let uid: u32 = uid.parse().ok()?;
            ((1000..=60000).contains(&uid) && home.starts_with('/')).then(|| Account {
                name: (*name).to_string(),
                uid,
                home: PathBuf::from(home),
            })
        })
        .collect()
}

/// Where an account's own irlume state lives below its home.
const HOME_STATE: [&str; 3] = [".local", "share", "irlume"];

fn home_state_path(home: &Path) -> PathBuf {
    home.join(HOME_STATE.iter().collect::<PathBuf>())
}

/// A per-account state tree, `<home>/.local/share/irlume`, as the uninstaller
/// found it. Every step below the home is opened without following a
/// symbolic link, so a tree is always the one inside that home.
#[derive(Debug)]
enum HomeTree {
    /// A real directory owned by root or by the account: its envelopes are
    /// read, its seals disarmed and the tree removed.
    Verified(VerifiedTree),
    /// Something else is there. It is neither read nor removed, and the
    /// output names it with the reason.
    Skipped {
        path: PathBuf,
        account: String,
        reason: String,
    },
}

/// A verified per-account tree, held open. Everything done to it goes
/// through these descriptors, never through its path again.
#[derive(Debug)]
struct VerifiedTree {
    /// For messages only.
    path: PathBuf,
    account: String,
    /// `<home>/.local/share`, the directory holding the tree.
    parent: std::fs::File,
    /// The tree itself.
    dir: std::fs::File,
}

/// The per-account trees below `accounts`' homes, each path once, leaving out
/// `default_root`, the state root this process already uses. A human
/// account's tree is where a source install keeps the machine state
/// (`install-host.sh` writes `IRLUME_STATE_DIR` into the unit, not the shell)
/// and the login runner keeps its records; root's is where `install-host.sh`
/// run directly as root keeps it.
fn home_trees(accounts: &[Account], default_root: &Path) -> Vec<HomeTree> {
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut trees = Vec::new();
    for account in accounts {
        let path = home_state_path(&account.home);
        if path == default_root || seen.contains(&path) {
            continue;
        }
        seen.push(path);
        trees.extend(resolve_home_tree(account));
    }
    trees
}

/// `account`'s state tree, `None` when there is none.
fn resolve_home_tree(account: &Account) -> Option<HomeTree> {
    use std::os::unix::fs::MetadataExt as _;
    let path = home_state_path(&account.home);
    let skipped = |reason: String| {
        Some(HomeTree::Skipped {
            path: path.clone(),
            account: account.name.clone(),
            reason,
        })
    };
    let (parent, dir) = match open_home_tree(&account.home, &path) {
        Ok(found) => found,
        Err(None) => return None,
        Err(Some(reason)) => return skipped(reason),
    };
    let owner = match dir.metadata() {
        Ok(meta) => meta.uid(),
        Err(e) => return skipped(format!("could not be inspected: {e}")),
    };
    if owner != 0 && owner != account.uid {
        return skipped(format!(
            "it is owned by uid {owner}, neither root nor {}",
            account.name
        ));
    }
    Some(HomeTree::Verified(VerifiedTree {
        path,
        account: account.name.clone(),
        parent,
        dir,
    }))
}

/// `<home>/.local/share` and the tree in it (`path`), each step below the
/// home opened without following a link. `Err(None)` when there is no tree,
/// `Err(Some(reason))` when something is there that is not one.
fn open_home_tree(
    home: &Path,
    path: &Path,
) -> Result<(std::fs::File, std::fs::File), Option<String>> {
    let uninspectable = |e: std::io::Error| Some(format!("could not be inspected: {e}"));
    // The home itself comes from the account database, which only root
    // writes, and may be reached through a link (/home is one on Fedora
    // Atomic).
    let mut dir = match open_dir(home) {
        Ok(dir) => dir,
        Err(e) if is_absent(&e) => return Err(None),
        Err(e) => return Err(uninspectable(e)),
    };
    let mut parent = None;
    for (at, name) in HOME_STATE.iter().enumerate() {
        let child = match open_child_dir(&dir, name).map_err(uninspectable)? {
            Child::Dir(child) => child,
            Child::Absent => return Err(None),
            // Name a link only when something is there through it.
            Child::Link => {
                return match std::fs::metadata(path) {
                    Err(e) if is_absent(&e) => Err(None),
                    _ => Err(Some(format!(
                        "{} is a symbolic link, which is not followed",
                        HOME_STATE[..=at].join("/")
                    ))),
                }
            }
            // A file on the way means there is no tree; one in its place is
            // named, since a plain removal could not take it.
            Child::Other if at + 1 < HOME_STATE.len() => return Err(None),
            Child::Other => return Err(Some("it is not a directory".into())),
        };
        parent = Some(std::mem::replace(&mut dir, child));
    }
    Ok((parent.ok_or(None)?, dir))
}

/// Whether an error means the path is not there: missing, or a file where a
/// directory would have to be.
fn is_absent(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// What [`open_child_dir`] found under a name.
enum Child {
    /// A real directory, open.
    Dir(std::fs::File),
    Absent,
    /// A symbolic link, not followed.
    Link,
    /// Anything else that is not a directory (a file, a FIFO, a device).
    Other,
}

/// Open the directory `path`, following links in it.
fn open_dir(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
}

/// Open `name` in the open directory `parent` as a directory, never through
/// a link. O_DIRECTORY refuses a FIFO or device before any open can block.
fn open_child_dir(parent: &std::fs::File, name: impl AsRef<Path>) -> std::io::Result<Child> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let path = fd_path(parent)?.join(name);
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(dir) => Ok(Child::Dir(dir)),
        Err(e) => match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => Ok(Child::Link),
            Ok(meta) if !meta.is_dir() => Ok(Child::Other),
            Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => Ok(Child::Absent),
            _ => Err(e),
        },
    }
}

/// The path of the open directory `dir` through `/proc/self/fd`. A name
/// joined to it resolves inside that very directory, wherever it has since
/// moved, and never through a link above it. Checked, so that a missing
/// `/proc` is an error rather than an empty directory.
fn fd_path(dir: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;
    let path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    let (held, seen) = (dir.metadata()?, std::fs::metadata(&path)?);
    if (held.dev(), held.ino()) != (seen.dev(), seen.ino()) {
        return Err(std::io::Error::other(
            "/proc/self/fd does not resolve to the open directory",
        ));
    }
    Ok(path)
}

/// Whether an envelope or keyring directory in an account's tree that
/// cannot be read refuses the uninstall, by its own `owner`: root's does,
/// and so does one whose owner cannot be read, which is never taken from
/// the directory above it. The account's own is only named.
fn unreadable_refuses(owner: Option<u32>, root_uid: u32) -> bool {
    owner.is_none_or(|uid| uid == root_uid)
}

/// Remove everything in the open directory `dir`, each entry relative to
/// the directory that holds it and never through a link: an entry is
/// examined without following it, a directory is opened without following
/// it and emptied only when it is the one examined, and a link is removed,
/// not what it points to. An entry that `owners` do not own is left in place
/// and added to `kept`, named below the tree (`at`): an account could have
/// moved it in, and root removing it would delete what that account cannot.
/// `links` counts the symbolic links removed.
fn clear_dir(
    dir: &std::fs::File,
    at: &Path,
    owners: &[u32],
    kept: &mut Vec<PathBuf>,
    links: &mut usize,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let here = fd_path(dir)?;
    let names = std::fs::read_dir(&here)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    let gone = |result: std::io::Result<()>| match result {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    };
    for name in names {
        let shown = at.join(&name);
        let seen = match std::fs::symlink_metadata(here.join(&name)) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if !owners.contains(&seen.uid()) {
            kept.push(shown);
            continue;
        }
        if !seen.is_dir() {
            gone(std::fs::remove_file(here.join(&name)))?;
            if seen.file_type().is_symlink() {
                *links += 1;
            }
            continue;
        }
        let child = match open_child_dir(dir, &name)? {
            Child::Dir(child) => child,
            Child::Absent => continue,
            // It changed since it was examined.
            Child::Link | Child::Other => {
                kept.push(shown);
                continue;
            }
        };
        let held = child.metadata()?;
        if (held.dev(), held.ino()) != (seen.dev(), seen.ino()) {
            kept.push(shown);
            continue;
        }
        clear_dir(&child, &shown, owners, kept, links)?;
        match std::fs::remove_dir(here.join(&name)) {
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                if !kept.iter().any(|path| path.starts_with(&shown)) {
                    kept.push(shown);
                }
            }
            other => gone(other)?,
        }
    }
    Ok(())
}

impl VerifiedTree {
    /// The tree's keyring directory, never through a link.
    fn keyring(&self) -> std::io::Result<Child> {
        open_child_dir(&self.dir, "keyring")
    }

    /// Whether the tree's keyring directory is a real directory owned by
    /// `uid` (root outside tests), which only a root irlumed writes, or a
    /// link to one ([`Self::linked_root_store`]), which [`Self::sweep`] then
    /// counts as that store. One that cannot be opened is judged by its own
    /// owner, not followed; when that cannot be read either, the answer is
    /// unknown.
    fn keeps_store_of(&self, uid: u32) -> Result<bool, String> {
        use std::os::unix::fs::MetadataExt as _;
        let shown = self.path.join("keyring");
        match self.keyring() {
            Ok(Child::Dir(dir)) => dir
                .metadata()
                .map(|meta| meta.uid() == uid)
                .map_err(|e| format!("{}: {e}", shown.display())),
            Ok(Child::Link) => self.linked_root_store(uid).map(|store| store.is_some()),
            Ok(_) => Ok(false),
            Err(e) => match self.keyring_owner() {
                Some(owner) => Ok(owner == uid),
                None => Err(format!("{}: {e}", shown.display())),
            },
        }
    }

    /// The owner of the tree's `keyring` entry itself, not followed; `None`
    /// when it cannot be read.
    fn keyring_owner(&self) -> Option<u32> {
        use std::os::unix::fs::MetadataExt as _;
        let tree = fd_path(&self.dir).ok()?;
        std::fs::symlink_metadata(tree.join("keyring"))
            .ok()
            .map(|meta| meta.uid())
    }

    /// Where a link at the tree's `keyring` leads, opened, when that is a
    /// directory `root_uid` owns: a root irlumed's store linked into the
    /// tree, whose tokens the wipe would strand by removing only the link.
    /// `None` when the link leads nowhere, into a loop, or to anything else;
    /// an error when where it leads cannot be established.
    fn linked_root_store(&self, root_uid: u32) -> Result<Option<std::fs::File>, String> {
        use std::os::unix::fs::MetadataExt as _;
        let shown = self.path.join("keyring");
        let fail = |e: std::io::Error| format!("{}: {e}", shown.display());
        let tree = fd_path(&self.dir).map_err(fail)?;
        let dir = match open_dir(&tree.join("keyring")) {
            Ok(dir) => dir,
            Err(e) if is_absent(&e) || e.raw_os_error() == Some(libc::ELOOP) => return Ok(None),
            Err(e) => return Err(fail(e)),
        };
        let owner = dir.metadata().map_err(fail)?.uid();
        Ok((owner == root_uid).then_some(dir))
    }

    /// The accounts with an enrollment in the tree.
    fn users(&self) -> Vec<String> {
        fd_path(&self.dir)
            .map(|dir| irlume_core::storage::list_users_at(&dir))
            .unwrap_or_default()
    }

    /// Delete `user`'s sealed envelope in the tree, if there is one. A
    /// keyring directory reached through a link is left alone.
    fn forget(&self, user: &str) -> std::io::Result<()> {
        let Child::Dir(keyring) = self.keyring()? else {
            return Ok(());
        };
        match std::fs::remove_file(fd_path(&keyring)?.join(format!("{user}.json"))) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    /// Remove the tree through the directory that holds it, and only while
    /// the name there is still the directory that was verified. A tree that
    /// is gone already counts as removed. The number of symbolic links the
    /// removal took ([`Self::remove_held`]).
    fn wipe(&self) -> std::io::Result<usize> {
        use std::os::unix::fs::MetadataExt as _;
        let path = fd_path(&self.parent)?.join("irlume");
        let now = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let verified = self.dir.metadata()?;
        if !now.is_dir() || (now.dev(), now.ino()) != (verified.dev(), verified.ino()) {
            return Err(std::io::Error::other(
                "it was replaced after it was checked",
            ));
        }
        self.remove_held(&[verified.uid(), 0])
    }

    /// The removal after [`Self::wipe`]'s check. The tree is emptied through
    /// the directory held since it was verified ([`clear_dir`]), so a tree
    /// renamed away and replaced after the check is still the one emptied,
    /// and what took its name is never read; that name is then removed only
    /// as an empty directory. What `owners` do not own is left in place and
    /// named in the error. The number of symbolic links removed: what they
    /// led to was not examined, and the account could have changed where one
    /// led up to its removal.
    fn remove_held(&self, owners: &[u32]) -> std::io::Result<usize> {
        let (mut kept, mut links) = (Vec::new(), 0);
        clear_dir(&self.dir, Path::new(""), owners, &mut kept, &mut links)?;
        match std::fs::remove_dir(fd_path(&self.parent)?.join("irlume")) {
            Ok(()) => Ok(links),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && kept.is_empty() => Ok(links),
            Err(_) if !kept.is_empty() => Err(std::io::Error::other(terminal_safe(&format!(
                "{} owned by another account, left in place",
                kept.iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))),
            Err(e) => Err(e),
        }
    }

    /// Count the tree's sealed envelopes into `sweep`. An envelope, or a
    /// keyring directory, that cannot be read refuses the uninstall when
    /// `root_uid` (root outside tests) owns it, or when whose it is cannot
    /// be read (never taken from the directory above it), as one a root
    /// irlumed wrote may hold the only copy of a keyring token. A link at the keyring's name is followed only to a
    /// directory root owns, which counts as that root store. Anything else in
    /// the tree the account could have put there itself, so it is named in
    /// `sweep` instead, and removed with the tree.
    fn sweep(&self, root_uid: u32, sweep: &mut TokenSweep) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;
        let shown = self.path.join("keyring");
        let refuses = |owner: Option<u32>| unreadable_refuses(owner, root_uid);
        let note = |sweep: &mut TokenSweep, what: &Path, why: &str| {
            sweep
                .notes
                .push(format!("{}: {} {why}", self.account, what.display()));
        };
        let unread = |e: &dyn std::fmt::Display| {
            format!(
                "could not be read ({e}); root does not own it, so it does not stop the uninstall"
            )
        };
        let dir = match self.keyring() {
            Ok(Child::Dir(dir)) => dir,
            Ok(Child::Absent) => return Ok(()),
            // The wipe removes only the link; a root store it leads to
            // stays, and the SRK eviction after the wipe would strand a token
            // there, so that store counts as any root store does.
            Ok(Child::Link) => match self.linked_root_store(root_uid)? {
                Some(dir) => dir,
                None => {
                    note(
                        sweep,
                        &shown,
                        "is a symbolic link to no directory root owns, which is not followed",
                    );
                    return Ok(());
                }
            },
            Ok(Child::Other) => {
                note(sweep, &shown, "is not a directory, so it was not read");
                return Ok(());
            }
            // Judged by its own owner, not the tree's: a root store inside an
            // account's tree cannot be opened (a root-squashed or FUSE mount,
            // an I/O error), or whose it is cannot be read.
            Err(e) => match self.keyring_owner() {
                Some(owner) if owner != root_uid => {
                    note(sweep, &shown, &unread(&e));
                    return Ok(());
                }
                _ => return Err(format!("{}: {e}", shown.display())),
            },
        };
        let dir_owner = dir.metadata().ok().map(|meta| meta.uid());
        let listed = fd_path(&dir).map_err(|e| e.to_string()).and_then(|pinned| {
            irlume_core::keyring::inspect_sealed_at(&pinned).map_err(|e| {
                e.to_string()
                    .replace(&pinned.display().to_string(), &shown.display().to_string())
            })
        });
        let entries = match listed {
            Ok(entries) => entries,
            Err(e) if refuses(dir_owner) => return Err(format!("{}: {e}", shown.display())),
            Err(e) => {
                note(sweep, &shown, &unread(&e));
                return Ok(());
            }
        };
        for entry in entries {
            let file = shown.join(&entry.file_name);
            match entry.kind {
                Ok(kind) => sweep.count(entry.user, kind),
                // An envelope root owns, linked in under an envelope's name:
                // the wipe removes only the link, so its token counts.
                Err(e) => match linked_root_envelope(&dir, &entry.file_name, root_uid) {
                    Some(kind) => sweep.count(entry.user, kind),
                    None if refuses(entry.owner) => {
                        return Err(format!("{}: {e}", file.display()));
                    }
                    None => note(sweep, &file, &unread(&e)),
                },
            }
        }
        Ok(())
    }
}

/// What a link at an envelope's name in the open keyring directory `keyring`
/// seals, when it leads to a regular file `root_uid` owns that loads as an
/// envelope: one a root irlumed wrote, linked there. `None` for an entry that
/// is no link, and for a link to anything else, which stays only named, so
/// an account cannot stop the uninstall by linking to some file of root's.
fn linked_root_envelope(
    keyring: &std::fs::File,
    name: &std::ffi::OsStr,
    root_uid: u32,
) -> Option<irlume_core::envelope::SecretKind> {
    use std::os::unix::fs::MetadataExt as _;
    let entry = fd_path(keyring).ok()?.join(name);
    if !std::fs::symlink_metadata(&entry)
        .ok()?
        .file_type()
        .is_symlink()
    {
        return None;
    }
    let target = std::fs::canonicalize(&entry).ok()?;
    let meta = std::fs::symlink_metadata(&target).ok()?;
    if !meta.is_file() || meta.uid() != root_uid {
        return None;
    }
    irlume_core::envelope::SealedEnvelope::load(&target)
        .ok()
        .map(|envelope| envelope.secret)
}

/// Disarm every seal in the verified trees of `homes`; the number of
/// enrolled accounts found in them.
fn disarm_home_trees(homes: &[HomeTree]) -> usize {
    let mut disarmed = 0;
    for home in homes {
        if let HomeTree::Verified(tree) = home {
            for user in tree.users() {
                let _ = tree.forget(&user);
                disarmed += 1;
            }
        }
    }
    disarmed
}

/// Remove the verified trees of `homes`, and return what still holds data
/// for the report: a tree that could not be removed, every skipped one, and
/// a keyring store a tree links to.
fn wipe_home_trees(homes: &[HomeTree]) -> Vec<String> {
    wipe_home_trees_as(homes, 0)
}

/// [`wipe_home_trees`] with root's uid injected (kept for the tests that
/// stand in for root). A symbolic link the removal takes is removed, never
/// followed, so a store it led to, which a root irlumed's envelopes may be
/// in, stays; and the account could have pointed it anywhere until the
/// moment it went. A tree whose removal took a link is therefore reported
/// among what may still hold data, which keeps the SRK (a key left in the
/// TPM does no harm; one evicted under a surviving envelope strands it).
fn wipe_home_trees_as(homes: &[HomeTree], _root_uid: u32) -> Vec<String> {
    let mut left = Vec::new();
    for home in homes {
        match home {
            HomeTree::Verified(tree) => match tree.wipe() {
                Ok(0) => {}
                Ok(links) => left.push(format!(
                    "{} (removed; it held {links} symbolic link(s), removed without following them, \
                     so what they led to was not examined and the TPM storage key is kept)",
                    tree.path.display()
                )),
                Err(e) => {
                    eprintln!(
                        "[uninstall] could not remove {}: {e} (files remain)",
                        tree.path.display()
                    );
                    left.push(format!("{} (user state)", tree.path.display()));
                }
            },
            HomeTree::Skipped { path, reason, .. } => left.push(format!(
                "{} (user state, not removed: {reason})",
                path.display()
            )),
        }
    }
    left
}

/// What the token guard found.
#[derive(Debug, Default)]
struct TokenSweep {
    /// The accounts whose sealed envelope is a GNOME keyring token.
    holders: Vec<String>,
    /// What it passed over, by path, for the output.
    notes: Vec<String>,
}

impl TokenSweep {
    fn collect(&mut self, sealed: Vec<(String, irlume_core::envelope::SecretKind)>) {
        for (user, kind) in sealed {
            self.count(user, kind);
        }
    }

    fn count(&mut self, user: String, kind: irlume_core::envelope::SecretKind) {
        if kind == irlume_core::envelope::SecretKind::GnomeKeyringToken
            && !self.holders.contains(&user)
        {
            self.holders.push(user);
        }
    }
}

/// The state root irlumed's unit names, when it is not `default` and exists
/// or cannot be inspected (reading it then fails and the sweep refuses,
/// instead of quietly leaving out the store the daemon uses).
/// `install-host.sh` writes it for a source install whatever account ran it
/// (one resolved through NSS, or with a UID outside the human range).
fn unit_state_roots(default: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(unit_env("IRLUME_STATE_DIR")?
        .filter(|root| root != default)
        .filter(|root| match std::fs::metadata(root) {
            Ok(meta) => meta.is_dir(),
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        })
        .into_iter()
        .collect())
}

/// systemd's unit directories for system services, highest precedence first.
const UNIT_LAYERS: [&str; 7] = [
    "etc/systemd/system.control",
    "run/systemd/system.control",
    "run/systemd/transient",
    "etc/systemd/system",
    "run/systemd/system",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
];

/// A directory variable (`IRLUME_STATE_DIR`, `IRLUME_KEYRING_DIR`) as systemd
/// gives it to irlumed: the unit file from the highest layer that has one
/// (`install-host.sh` writes /etc, a package ships /usr/lib), then every
/// layer's drop-ins merged by name, a higher layer's file masking a lower
/// one's, applied in name order; the last assignment wins, and an empty
/// `Environment=` resets. A file that exists and cannot be read is an error:
/// the directory it would name is unknown.
pub(crate) fn unit_env(var: &str) -> Result<Option<PathBuf>, String> {
    unit_env_under(Path::new("/"), var)
}

fn unit_env_under(root: &Path, var: &str) -> Result<Option<PathBuf>, String> {
    let read = |path: &Path| match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    };
    let mut texts = Vec::new();
    for layer in UNIT_LAYERS {
        if let Some(text) = read(&root.join(layer).join("irlumed.service"))? {
            texts.push(text);
            break;
        }
    }
    let mut drop_ins: std::collections::BTreeMap<std::ffi::OsString, PathBuf> =
        std::collections::BTreeMap::new();
    for layer in UNIT_LAYERS {
        let dir = root.join(layer).join("irlumed.service.d");
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        };
        for entry in entries {
            let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
            if path.extension().is_some_and(|ext| ext == "conf") {
                if let Some(name) = path.file_name() {
                    // Layers come highest first: the first file of a name wins.
                    drop_ins.entry(name.to_os_string()).or_insert(path);
                }
            }
        }
    }
    for path in drop_ins.values() {
        texts.extend(read(path)?);
    }
    let mut found = None;
    for text in &texts {
        found = unit_env_in(text, var, found);
    }
    // systemd applies `UnsetEnvironment=` after every `Environment=`, whatever
    // the order of the lines: a variable it names, bare or with the value it
    // has, is not in the daemon's environment.
    if let Some(value) = &found {
        let assignment = format!("{var}={}", value.display());
        if texts.iter().any(|text| unit_unsets(text, var, &assignment)) {
            found = None;
        }
    }
    Ok(found)
}

/// Whether a unit file's `UnsetEnvironment=` lines name `var`, bare or as the
/// exact `assignment` it has.
fn unit_unsets(unit: &str, var: &str, assignment: &str) -> bool {
    unit.lines()
        .filter_map(|line| line.trim().strip_prefix("UnsetEnvironment="))
        .flat_map(str::split_whitespace)
        .map(|word| word.trim_matches('"'))
        .any(|word| word == var || word == assignment)
}

/// The keyring directory irlumed's unit points `IRLUME_KEYRING_DIR` at, when
/// it is not the one this process uses: a separately started CLI does not
/// inherit the daemon's environment, so its own default misses that store.
fn unit_keyring_dirs() -> Result<Vec<PathBuf>, String> {
    Ok(unit_env("IRLUME_KEYRING_DIR")?.into_iter().collect())
}

/// `<var>` after a unit file's `Environment=` lines, starting from `found`:
/// each line holds space-separated assignments, any of them in double quotes,
/// and an empty `Environment=` resets the list.
fn unit_env_in(unit: &str, var: &str, mut found: Option<PathBuf>) -> Option<PathBuf> {
    for line in unit.lines() {
        let Some(value) = line.trim().strip_prefix("Environment=") else {
            continue;
        };
        if value.trim().is_empty() {
            found = None;
            continue;
        }
        let (mut word, mut quoted, mut words) = (String::new(), false, Vec::new());
        for c in value.chars() {
            match c {
                '"' => quoted = !quoted,
                ' ' | '\t' if !quoted => words.push(std::mem::take(&mut word)),
                c => word.push(c),
            }
        }
        words.push(word);
        for word in words {
            if let Some(dir) = word
                .strip_prefix(var)
                .and_then(|rest| rest.strip_prefix('='))
            {
                found = Some(PathBuf::from(dir));
            }
        }
    }
    found.filter(|dir| dir.is_absolute())
}

/// Root's home in a passwd text (uid 0), `None` when it names none.
fn root_home_in(passwd: &str) -> Option<PathBuf> {
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.get(2) == Some(&"0"))
            .then(|| fields.get(5).filter(|home| home.starts_with('/')))
            .flatten()
            .map(PathBuf::from)
    })
}

/// Users whose sealed envelope anywhere on this host is a GNOME keyring
/// token, with what the sweep passed over, or the store description on a
/// read failure that refuses. An envelope this cannot read is not one that
/// holds no token (the guard's own contract), so a failure refuses, except in
/// a per-account tree for what root does not own ([`VerifiedTree::sweep`]).
fn sealed_token_holders() -> Result<TokenSweep, String> {
    let default = irlume_common::state_dir();
    sealed_token_holders_with(
        irlume_core::keyring::list_sealed_kinds(),
        &home_trees(&sweep_accounts(), &default),
        &unit_state_roots(&default)?,
        &unit_keyring_dirs()?,
        0,
    )
}

/// [`sealed_token_holders`] for the login guards (`login disable`, a
/// stranding enable, a machine rollback): a per-user state root counts only
/// when its keyring directory is a real directory owned by root, which only
/// a root irlumed writes. A user owns their home, so without that anyone
/// could plant an envelope, or an unreadable one, that makes a root disable
/// refuse, and the machine API has no `--force` past it. The uninstall sweep
/// deletes those trees, so it counts every envelope in them that it can
/// read, and refuses on one it cannot only when root owns it.
pub(crate) fn root_sealed_token_holders() -> Result<Vec<String>, String> {
    let default = irlume_common::state_dir();
    let mut homes = Vec::new();
    let mut dirs = Vec::new();
    for home in home_trees(&sweep_accounts(), &default) {
        match home {
            HomeTree::Verified(tree) => {
                if tree.keeps_store_of(0)? {
                    homes.push(HomeTree::Verified(tree));
                }
            }
            // A tree uninstall does not remove can still hold a keyring
            // store a root irlumed wrote, and a login stack may deliver its
            // token: the guards keep counting it, through the directory the
            // check held (sealed_token_holders_with).
            skipped @ HomeTree::Skipped { .. } => homes.push(skipped),
        }
    }
    // What irlumed's own unit names is trusted by where it comes from (a unit
    // file only root writes), links followed as irlumed follows them.
    let roots = unit_state_roots(&default)?;
    for dir in unit_keyring_dirs()? {
        match std::fs::metadata(&dir) {
            Ok(meta) if meta.is_dir() => dirs.push(dir),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        }
    }
    Ok(sealed_token_holders_with(
        irlume_core::keyring::list_sealed_kinds(),
        &homes,
        &roots,
        &dirs,
        0,
    )?
    .holders)
}

/// A keyring store in a tree uninstall skips, held open: the directory the
/// ownership check was made on, and the path it is named by in messages.
struct HeldStore {
    shown: PathBuf,
    dir: std::fs::File,
}

impl HeldStore {
    /// The sealed envelopes in the held directory, read through its
    /// descriptor (so a directory put at its path since the check is never
    /// read), bounded and without following a link at an envelope's name.
    fn sealed_kinds(&self) -> Result<Vec<(String, irlume_core::envelope::SecretKind)>, String> {
        let shown = self.shown.display().to_string();
        let pinned = fd_path(&self.dir).map_err(|e| format!("{shown}: {e}"))?;
        irlume_core::keyring::list_sealed_kinds_at(&pinned).map_err(|e| {
            format!(
                "{shown}: {}",
                e.to_string().replace(&pinned.display().to_string(), &shown)
            )
        })
    }
}

/// The keyring store in a per-account tree uninstall skips, when it is a
/// directory that `root_uid` owns: the uninstall and login guards count its
/// tokens although the tree is not removed. A link at the store's name is
/// followed only to such a directory (a root irlumed's store linked there),
/// and the store is then named by where the link leads, as
/// [`VerifiedTree::linked_root_store`] does for a tree that is removed; a
/// link to anything else, to nothing or into a loop is no store, and so is a
/// path that cannot be followed because of a loop above it. The directory is
/// opened once and its owner is read from the open directory, which is what
/// the guards then read ([`HeldStore::sealed_kinds`]). `Ok(None)` when there
/// is no such store; an error when whether there is one cannot be
/// established, so the guards stay fail-closed.
fn skipped_tree_keyring(tree: &Path, root_uid: u32) -> Result<Option<HeldStore>, String> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let keyring = tree.join("keyring");
    let fail = |e: std::io::Error| format!("{}: {e}", keyring.display());
    let nothing = |e: &std::io::Error| is_absent(e) || e.raw_os_error() == Some(libc::ELOOP);
    let meta = match std::fs::symlink_metadata(&keyring) {
        Ok(meta) => meta,
        Err(e) if nothing(&e) => return Ok(None),
        Err(e) => return Err(fail(e)),
    };
    let (shown, opened) = if meta.file_type().is_symlink() {
        let target = match std::fs::canonicalize(&keyring) {
            Ok(target) => target,
            Err(e) if nothing(&e) => return Ok(None),
            Err(e) => return Err(fail(e)),
        };
        let opened = open_dir(&target);
        (target, opened)
    } else if meta.is_dir() {
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&keyring);
        (keyring.clone(), opened)
    } else {
        return Ok(None);
    };
    let dir = match opened {
        Ok(dir) => dir,
        Err(e) if nothing(&e) => return Ok(None),
        Err(e) => return Err(fail(e)),
    };
    let owner = dir.metadata().map_err(fail)?.uid();
    Ok((owner == root_uid).then_some(HeldStore { shown, dir }))
}

/// [`sealed_token_holders`] with the default-root enumeration, the
/// per-account trees, the unit's roots and keyring directories, and root's
/// uid injected, so the sweep and the failure contract are unit-testable.
/// Its notes, holders and error name files an account named, so they come
/// back [`terminal_safe`].
fn sealed_token_holders_with(
    default: irlume_common::Result<Vec<(String, irlume_core::envelope::SecretKind)>>,
    homes: &[HomeTree],
    roots: &[PathBuf],
    keyring_dirs: &[PathBuf],
    root_uid: u32,
) -> Result<TokenSweep, String> {
    match sweep_sealed_token_holders(default, homes, roots, keyring_dirs, root_uid) {
        Ok(sweep) => Ok(TokenSweep {
            holders: sweep.holders.iter().map(|h| terminal_safe(h)).collect(),
            notes: sweep.notes.iter().map(|n| terminal_safe(n)).collect(),
        }),
        Err(e) => Err(terminal_safe(&e)),
    }
}

/// Text that may hold a name an account chose, for the terminal: each
/// control character, and each invisible formatting character that changes
/// how the text around it is shown (bidirectional marks, embeddings,
/// overrides and isolates, zero-width characters), is written as its escape
/// (`\u{1b}`, `\n`, `\u{202e}`), so a crafted file name cannot move the
/// cursor, recolor, reorder or forge a line of the output.
fn terminal_safe(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() || is_format_char(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Invisible Unicode formatting characters that change how the text around
/// them is displayed: the Arabic letter mark, zero-width space, joiners and
/// direction marks, bidirectional embeddings and overrides, the word joiner
/// and invisible operators, bidirectional isolates, and the byte-order mark.
fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

fn sweep_sealed_token_holders(
    default: irlume_common::Result<Vec<(String, irlume_core::envelope::SecretKind)>>,
    homes: &[HomeTree],
    roots: &[PathBuf],
    keyring_dirs: &[PathBuf],
    root_uid: u32,
) -> Result<TokenSweep, String> {
    let mut sweep = TokenSweep::default();
    sweep.collect(default.map_err(|e| format!("{e}"))?);
    for home in homes {
        match home {
            HomeTree::Verified(tree) => tree.sweep(root_uid, &mut sweep)?,
            HomeTree::Skipped {
                path,
                account,
                reason,
            } => {
                sweep.notes.push(format!(
                    "{account}: {} is neither read nor removed: {reason}",
                    path.display()
                ));
                // The tree is not removed, but a keyring store in it that
                // root owns may hold a token a login stack delivers: it
                // counts, fail-closed, as a root store does.
                if let Some(store) = skipped_tree_keyring(path, root_uid)? {
                    sweep.collect(store.sealed_kinds()?);
                }
            }
        }
    }
    // A unit root that is an account's verified tree was swept above, under
    // the rules for what that account could have put there itself, as the
    // teardown handles it.
    let swept = |root: &PathBuf| {
        homes
            .iter()
            .any(|home| matches!(home, HomeTree::Verified(tree) if tree.path == *root))
    };
    for root in roots.iter().filter(|root| !swept(root)) {
        sweep.collect(
            irlume_core::keyring::list_sealed_kinds_in(root)
                .map_err(|e| format!("{}: {e}", root.join("keyring").display()))?,
        );
    }
    for dir in keyring_dirs {
        sweep.collect(
            irlume_core::keyring::list_sealed_kinds_at(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?,
        );
    }
    Ok(sweep)
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

/// What the teardown did - or deliberately did not - about irlume's persisted
/// TPM storage root key (audit F4, 2026-09-17: the persistent SRK handle was
/// live residue only irlume could name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrkOutcome {
    /// A full, completed wipe: our SRK was evicted from its persistent handle.
    Evicted,
    /// A full wipe, and no key occupied the handle (already clean).
    Absent,
    /// A full wipe, but the handle holds a key that is not ours; never touched.
    Foreign,
    /// No attempt: data was kept or the wipe did not complete, and sealed
    /// data that still exists may be a child of that key.
    Kept,
    /// Attempted but the TPM could not be reached. Non-fatal: the teardown
    /// still removed everything on disk; the key is a benign orphan.
    Failed(String),
}

/// One honest line per [`SrkOutcome`]. `Kept` and `Failed` must never read as
/// "cleaned": the exit code and the operator's next decision both hang on the
/// difference.
fn srk_outcome_line(outcome: &SrkOutcome) -> String {
    match outcome {
        SrkOutcome::Evicted => "evicted from its persistent handle".to_string(),
        SrkOutcome::Absent => "not present (already clean)".to_string(),
        SrkOutcome::Foreign => {
            "left in place: the persistent handle holds a key that is not irlume's".to_string()
        }
        SrkOutcome::Kept => "kept: sealed data was kept, the wipe was incomplete, or not every \
             envelope's location could be proven empty - the key survives for it"
            .to_string(),
        SrkOutcome::Failed(e) => {
            format!("could not check or evict ({e}); a benign orphan unless removed by hand")
        }
    }
}

/// The uninstaller's leave-behind notice for the Bitwarden polkit action
/// (audit F6, 2026-09-17): `irlume bitwarden setup --apply` writes Bitwarden's
/// own polkit policy file, and the uninstaller deliberately leaves it - it
/// serves Bitwarden, not irlume. Named in the output when present so the
/// residue is never a surprise.
fn bitwarden_polkit_notice_at(path: &std::path::Path) -> Option<String> {
    if path.exists() {
        Some(format!(
            "left in place (serves Bitwarden, not irlume): {}. Remove it by hand if \
             Bitwarden is not used on this machine.",
            path.display()
        ))
    } else {
        None
    }
}

fn bitwarden_polkit_notice() -> Option<String> {
    bitwarden_polkit_notice_at(std::path::Path::new(
        "/usr/share/polkit-1/actions/com.bitwarden.Bitwarden.policy",
    ))
}

#[cfg(test)]
mod tests {

    #[test]
    fn source_desktop_removal_preserves_neighbors_and_is_idempotent() {
        let root = std::env::temp_dir().join(format!(
            "irlume-desktop-removal-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        for relative in [
            "applications/io.github.archledger.Irlume.desktop",
            "icons/hicolor/scalable/apps/io.github.archledger.Irlume.svg",
        ] {
            let file = root.join(relative);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, b"irlume fixture").unwrap();
            std::fs::write(file.with_file_name("unrelated"), b"keep").unwrap();
        }
        assert_eq!(super::remove_source_desktop_files(&root).unwrap(), 2);
        assert_eq!(super::remove_source_desktop_files(&root).unwrap(), 0);
        for dir in ["applications", "icons/hicolor/scalable/apps"] {
            assert_eq!(
                std::fs::read(root.join(dir).join("unrelated")).unwrap(),
                b"keep"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_desktop_removal_reports_errors_without_removing_directories() {
        let root = std::env::temp_dir().join(format!(
            "irlume-desktop-removal-error-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let unexpected_dir = root.join("applications/io.github.archledger.Irlume.desktop");
        std::fs::create_dir_all(&unexpected_dir).unwrap();
        assert!(super::remove_source_desktop_files(&root).is_err());
        assert!(unexpected_dir.is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A destructive verb must not guess. `--keep-data` mistyped is the whole
    /// reason this exists: it used to be ignored, and with `--yes` beside it the
    /// run wiped every enrolled face, sealed secret and recovery envelope the
    /// flag was there to keep.
    /// Every SRK outcome line must say what actually happened, and the two
    /// non-cleaned outcomes (`Kept`, `Failed`) must never be mistakable for a
    /// cleaned one (the PR #337 rule, applied to the TPM key: a state that
    /// leaves residue may not borrow the success phrasing).
    #[test]
    fn srk_outcome_lines_are_distinct_and_honest() {
        let evicted = super::srk_outcome_line(&super::SrkOutcome::Evicted);
        let absent = super::srk_outcome_line(&super::SrkOutcome::Absent);
        let foreign = super::srk_outcome_line(&super::SrkOutcome::Foreign);
        let kept = super::srk_outcome_line(&super::SrkOutcome::Kept);
        let failed =
            super::srk_outcome_line(&super::SrkOutcome::Failed("no TPM device".to_string()));
        for (name, line) in [
            ("evicted", &evicted),
            ("absent", &absent),
            ("foreign", &foreign),
            ("kept", &kept),
            ("failed", &failed),
        ] {
            assert!(!line.is_empty(), "{name} line must exist");
        }
        let lines = [&evicted, &absent, &foreign, &kept, &failed];
        for i in 0..lines.len() {
            for j in (i + 1)..lines.len() {
                assert_ne!(lines[i], lines[j], "outcome lines must be distinct");
            }
        }
        assert!(evicted.contains("evicted"));
        assert!(
            kept.contains("kept") && !kept.contains("evicted"),
            "Kept must read as kept, not cleaned"
        );
        assert!(
            failed.contains("no TPM device") && !failed.contains("evicted from"),
            "Failed must carry the error and not read as cleaned"
        );
        assert!(
            foreign.contains("not irlume's"),
            "Foreign must say the key is not ours"
        );
    }

    /// The Bitwarden polkit notice names the exact file only when it exists,
    /// so the leave-behind is a named fact, never a surprise (audit F6).
    #[test]
    fn bitwarden_notice_names_the_file_only_when_present() {
        let dir = std::env::temp_dir().join(format!(
            "irlume-bw-notice-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let absent = dir.join("com.bitwarden.Bitwarden.policy");
        assert!(super::bitwarden_polkit_notice_at(&absent).is_none());

        std::fs::write(&absent, b"<policykit-policy/>").unwrap();
        let notice = super::bitwarden_polkit_notice_at(&absent).unwrap();
        assert!(
            notice.contains(absent.to_str().unwrap()),
            "must name the exact path"
        );
        assert!(
            notice.contains("serves Bitwarden"),
            "must say why it is left in place"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The eviction gate keeps the key on every blocker (#757 review): a
    /// completed wipe alone would miss envelopes under the env overrides, and
    /// a non-empty or unreadable post-wipe enumeration means sealed data is
    /// still on the host.
    #[test]
    fn srk_eviction_requires_proof_that_no_envelope_survives() {
        let holders = |v: Result<Vec<String>, String>| v;
        assert!(
            super::may_evict_srk(true, false, holders(Ok(Vec::new()))),
            "completed wipe + no overrides + empty enumeration = evict"
        );
        assert!(
            !super::may_evict_srk(false, false, holders(Ok(Vec::new()))),
            "kept data or an incomplete wipe keeps the key"
        );
        assert!(
            !super::may_evict_srk(true, true, holders(Ok(Vec::new()))),
            "an active override dir means out-of-tree envelopes may exist"
        );
        assert!(
            !super::may_evict_srk(true, false, holders(Ok(vec!["alice".to_string()]))),
            "a surviving envelope holder keeps the key"
        );
        assert!(
            !super::may_evict_srk(true, false, holders(Err("unreadable".to_string()))),
            "an unreadable store is not proof of emptiness"
        );
    }

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

    // Repository/key directories are shared ownership domains. A filename is
    // not proof that irlume or either channel manager owns an entry.
    #[test]
    fn channel_cleanup_preserves_unknown_entries_with_irlume_in_their_names() {
        let dir = std::env::temp_dir().join(format!("irlume-repo-clean-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let files = [
            "_copr:copr.fedorainfracloud.org:archledger:irlume.repo",
            "archledger-ubuntu-irlume-resolute.sources",
            "IRLUME-2026.gpg",
            "administrator-irlume-notes.repo",
            "shared-irlume-signing-key.gpg",
            "other-product.repo",
        ];
        for (index, f) in files.iter().enumerate() {
            std::fs::write(dir.join(f), format!("foreign bytes {index}\n")).unwrap();
        }
        std::os::unix::fs::symlink("other-product.repo", dir.join("irlume-current.repo")).unwrap();
        std::fs::create_dir(dir.join("irlume-repository.d")).unwrap();

        let mut invoked = None;
        remove_install_channel_with(&InstallOrigin::Ppa, |bin, args| {
            invoked = Some((
                bin.to_owned(),
                args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>(),
            ));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            invoked,
            Some((
                "add-apt-repository".to_owned(),
                vec![
                    "-y".to_owned(),
                    "--remove".to_owned(),
                    "--ppa".to_owned(),
                    "ppa:archledger/irlume".to_owned()
                ]
            ))
        );
        for (index, f) in files.iter().enumerate() {
            assert_eq!(
                std::fs::read(dir.join(f)).unwrap(),
                format!("foreign bytes {index}\n").as_bytes(),
                "unknown entry {f} must remain byte-identical"
            );
        }
        assert!(std::fs::symlink_metadata(dir.join("irlume-current.repo"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(dir.join("irlume-repository.d").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_channel_cleanup_uses_the_installer_repository_identity() {
        assert_eq!(
            install_channel_command(&InstallOrigin::Copr),
            Some(("dnf", &["-y", "copr", "remove", "archledger/irlume"][..]))
        );
        assert_eq!(
            install_channel_command(&InstallOrigin::Ppa),
            Some((
                "add-apt-repository",
                &["-y", "--remove", "--ppa", "ppa:archledger/irlume"][..]
            ))
        );
        assert_eq!(install_channel_command(&InstallOrigin::Source), None);
        assert_eq!(install_channel_command(&InstallOrigin::LocalDeb), None);
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
            srk_eviction: if wiped {
                SrkOutcome::Absent
            } else {
                SrkOutcome::Kept
            },
        }
    }

    /// irlume itself is removed only once no PAM stack references it.
    #[test]
    fn irlume_is_not_removed_while_a_pam_stack_references_it() {
        let mut wired = report(true, true, &[]);
        assert_eq!(removal_refusal(&wired), None);
        wired.pam_unwired = false;
        let refusal = removal_refusal(&wired).expect("a refusal");
        assert!(
            refusal.contains("stays installed") && refusal.contains("sudo irlume uninstall"),
            "{refusal}"
        );
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
            !line.contains("no repo or drop-in left behind"),
            "channel cleanup can fail and shared key material may remain: {line}"
        );
        assert!(
            line.contains("install-channel removal is reported separately")
                && line.contains("shared signing keys may remain"),
            "the closing copy must preserve the channel/key uncertainty: {line}"
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
        assert!(
            !line.contains("no repo or drop-in left behind")
                && line.contains("install-channel removal is reported separately")
                && line.contains("shared signing keys may remain"),
            "a channel-manager failure must not be contradicted by the closing copy: {line}"
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
    fn a_keyring_directory_or_link_root_owns_counts_for_the_login_guards() {
        let base = std::env::temp_dir().join(format!("irlume-root-owned-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let alice = test_account(&base, "alice");
        let tree_path = home_state_path(&alice.home);
        std::fs::create_dir_all(&tree_path).unwrap();
        let tree = verified(resolve_home_tree(&alice));
        assert_eq!(tree.keeps_store_of(0), Ok(false), "no keyring directory");
        std::os::unix::fs::symlink("/", tree_path.join("keyring")).unwrap();
        assert_eq!(
            tree.keeps_store_of(0),
            Ok(true),
            "a link to a root-owned directory is followed to it"
        );
        std::fs::remove_file(tree_path.join("keyring")).unwrap();
        std::fs::create_dir(tree_path.join("keyring")).unwrap();
        assert_eq!(tree.keeps_store_of(alice.uid), Ok(true), "its owner's");
        if !is_root() {
            assert_eq!(
                tree.keeps_store_of(0),
                Ok(false),
                "a directory this user owns"
            );
            // Inside a tree this process cannot search, the answer is unknown.
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tree_path, std::fs::Permissions::from_mode(0o000)).unwrap();
            let answer = tree.keeps_store_of(0);
            std::fs::set_permissions(&tree_path, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(answer.is_err_and(|e| e.contains("irlume/keyring")));
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A tree uninstall skips (for example one another account owns) can
    /// still hold a real keyring store root owns; the login guards count it.
    /// A link at the store's own name, or a store root does not own, is not.
    #[test]
    fn a_skipped_trees_root_owned_keyring_still_counts_for_the_login_guards() {
        use std::os::unix::fs::MetadataExt as _;
        // What the guards are handed: the store's path in messages.
        let shown = |answer: Result<Option<HeldStore>, String>| answer.map(|o| o.map(|h| h.shown));
        let base =
            std::env::temp_dir().join(format!("irlume-skipped-keyring-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let tree = base.join("irlume");
        std::fs::create_dir_all(&tree).unwrap();
        assert_eq!(
            shown(skipped_tree_keyring(&tree, 0)),
            Ok(None),
            "no keyring directory"
        );
        std::fs::create_dir(tree.join("keyring")).unwrap();
        let owner = std::fs::metadata(tree.join("keyring")).unwrap().uid();
        // This process stands in for root: the store is "root's" when the
        // injected root uid is its owner.
        assert_eq!(
            shown(skipped_tree_keyring(&tree, owner)),
            Ok(Some(tree.join("keyring")))
        );
        assert_eq!(
            shown(skipped_tree_keyring(&tree, owner + 1)),
            Ok(None),
            "not root's"
        );
        std::fs::remove_dir(tree.join("keyring")).unwrap();
        // A link counts only when it leads to a directory root owns, named by
        // where it leads; one to nothing or into a loop is no store.
        let store = base.join("store");
        std::fs::create_dir(&store).unwrap();
        std::os::unix::fs::symlink(&store, tree.join("keyring")).unwrap();
        assert_eq!(
            shown(skipped_tree_keyring(&tree, owner)),
            Ok(Some(std::fs::canonicalize(&store).unwrap())),
            "a link to root's store"
        );
        // Its tokens count for the guards although the tree is skipped.
        std::fs::write(store.join("carol.json"), TOKEN_ENVELOPE).unwrap();
        let skipped = HomeTree::Skipped {
            path: tree.clone(),
            account: "bob".into(),
            reason: "owned by another account".into(),
        };
        assert_eq!(
            sealed_token_holders_with(Ok(Vec::new()), &[skipped], &[], &[], owner)
                .unwrap()
                .holders,
            vec!["carol".to_string()]
        );
        std::fs::remove_file(store.join("carol.json")).unwrap();
        assert_eq!(
            shown(skipped_tree_keyring(&tree, owner + 1)),
            Ok(None),
            "a link to a store root does not own"
        );
        for target in [base.join("nowhere"), tree.join("keyring")] {
            std::fs::remove_file(tree.join("keyring")).unwrap();
            std::os::unix::fs::symlink(&target, tree.join("keyring")).unwrap();
            assert_eq!(
                shown(skipped_tree_keyring(&tree, owner)),
                Ok(None),
                "{target:?}"
            );
        }
        // Inside a tree this process cannot search, whether a store is there
        // cannot be established: an error, so the guards refuse.
        if !is_root() {
            std::fs::remove_file(tree.join("keyring")).unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o000)).unwrap();
            let answer = shown(skipped_tree_keyring(&tree, owner));
            std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(answer.is_err(), "{answer:?}");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The guards read a skipped tree's store through the directory the
    /// check held: one renamed away and replaced by an empty directory after
    /// the check still counts its token. A loop above the store, which no
    /// store can be inside, is no store rather than an error.
    #[test]
    fn a_skipped_store_is_read_through_the_held_directory_and_a_loop_above_it_is_none() {
        use std::os::unix::fs::MetadataExt as _;
        let base = std::env::temp_dir().join(format!("irlume-skipped-held-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let tree = base.join("irlume");
        std::fs::create_dir_all(tree.join("keyring")).unwrap();
        std::fs::write(tree.join("keyring/carol.json"), TOKEN_ENVELOPE).unwrap();
        let owner = std::fs::metadata(tree.join("keyring")).unwrap().uid();
        let held = skipped_tree_keyring(&tree, owner)
            .unwrap()
            .expect("root's store");
        std::fs::rename(tree.join("keyring"), base.join("moved")).unwrap();
        std::fs::create_dir(tree.join("keyring")).unwrap();
        let kinds = held.sealed_kinds().unwrap();
        assert_eq!(kinds.len(), 1, "{kinds:?}");
        assert_eq!(kinds[0].0, "carol");
        // A self-referential link above the store: the path cannot be
        // followed, and nothing is there.
        let looped = base.join("loop");
        std::os::unix::fs::symlink(&looped, &looped).unwrap();
        assert!(matches!(
            skipped_tree_keyring(&looped.join("share/irlume"), owner),
            Ok(None)
        ));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_unit_environment_follows_systemd_layering() {
        let root = std::env::temp_dir().join(format!("irlume-unit-layers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let put = |rel: &str, text: &str| {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        let env = |var: &str| unit_env_under(&root, var).unwrap();
        assert_eq!(env("IRLUME_STATE_DIR"), None, "no unit anywhere");
        // A packaged unit under /usr/lib, then /etc's copy of the unit wins.
        put(
            "usr/lib/systemd/system/irlumed.service",
            "[Service]\nEnvironment=IRLUME_STATE_DIR=/a\n",
        );
        assert_eq!(env("IRLUME_STATE_DIR"), Some(PathBuf::from("/a")));
        put(
            "etc/systemd/system/irlumed.service",
            "[Service]\nExecStart=/x\n",
        );
        assert_eq!(
            env("IRLUME_STATE_DIR"),
            None,
            "only the highest unit file counts"
        );
        // Drop-ins from every layer, in name order; /etc masks /run by name.
        put(
            "run/systemd/system/irlumed.service.d/10-state.conf",
            "[Service]\nEnvironment=IRLUME_STATE_DIR=/run\n",
        );
        assert_eq!(env("IRLUME_STATE_DIR"), Some(PathBuf::from("/run")));
        put(
            "etc/systemd/system/irlumed.service.d/10-state.conf",
            "[Service]\nEnvironment=IRLUME_STATE_DIR=/etc\n",
        );
        assert_eq!(env("IRLUME_STATE_DIR"), Some(PathBuf::from("/etc")));
        put(
            "usr/lib/systemd/system/irlumed.service.d/20-keys.conf",
            "[Service]\nEnvironment=IRLUME_KEYRING_DIR=/keys\n",
        );
        assert_eq!(env("IRLUME_KEYRING_DIR"), Some(PathBuf::from("/keys")));
        // An empty assignment resets what came before.
        put(
            "run/systemd/system/irlumed.service.d/30-reset.conf",
            "[Service]\nEnvironment=\n",
        );
        assert_eq!(env("IRLUME_STATE_DIR"), None);
        // UnsetEnvironment= removes a variable whatever came after it.
        put(
            "run/systemd/system/irlumed.service.d/30-reset.conf",
            "[Service]\nUnsetEnvironment=IRLUME_KEYRING_DIR\n",
        );
        put(
            "usr/lib/systemd/system/irlumed.service.d/40-keys.conf",
            "[Service]\nEnvironment=IRLUME_KEYRING_DIR=/later\n",
        );
        assert_eq!(env("IRLUME_KEYRING_DIR"), None);
        assert_eq!(env("IRLUME_STATE_DIR"), Some(PathBuf::from("/etc")));
        put(
            "run/systemd/system/irlumed.service.d/30-reset.conf",
            "[Service]\nUnsetEnvironment=IRLUME_STATE_DIR=/elsewhere\n",
        );
        assert_eq!(
            env("IRLUME_STATE_DIR"),
            Some(PathBuf::from("/etc")),
            "another value"
        );
        put(
            "run/systemd/system/irlumed.service.d/30-reset.conf",
            "[Service]\nUnsetEnvironment=IRLUME_STATE_DIR=/etc\n",
        );
        assert_eq!(env("IRLUME_STATE_DIR"), None, "the value it has");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_keyring_directory_the_unit_names_is_swept_too() {
        let dir = std::env::temp_dir().join(format!("irlume-unit-keyring-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("carol.json"), TOKEN_ENVELOPE).unwrap();
        let sweep = |dirs: &[PathBuf]| sealed_token_holders_with(Ok(Vec::new()), &[], &[], dirs, 0);
        assert_eq!(
            sweep(std::slice::from_ref(&dir)).unwrap().holders,
            vec!["carol".to_string()]
        );
        std::fs::write(dir.join("dave.json"), b"not an envelope").unwrap();
        let err = sweep(std::slice::from_ref(&dir)).unwrap_err();
        assert!(err.contains(dir.to_str().unwrap()), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            unit_env_in(
                "Environment=IRLUME_KEYRING_DIR=/srv/keys IRLUME_STATE_DIR_X=/x\n",
                "IRLUME_KEYRING_DIR",
                None
            ),
            Some(PathBuf::from("/srv/keys"))
        );
        assert_eq!(
            unit_env_in(
                "Environment=IRLUME_STATE_DIR_X=/x\n",
                "IRLUME_STATE_DIR",
                None
            ),
            None,
            "a longer name is another variable"
        );
    }

    #[test]
    fn the_unit_names_the_state_root_install_host_configured() {
        let unit = "[Service]\nExecStart=/usr/local/bin/irlumed\n\
            Environment=\"ORT_DYLIB_PATH=/opt/ort/libonnxruntime.so\"\n\
            Environment=\"IRLUME_STATE_DIR=/home/ldap user/.local/share/irlume\"\n";
        assert_eq!(
            unit_env_in(unit, "IRLUME_STATE_DIR", None),
            Some(PathBuf::from("/home/ldap user/.local/share/irlume"))
        );
        assert_eq!(
            unit_env_in(
                "Environment=A=1 IRLUME_STATE_DIR=/srv/irlume B=2\n",
                "IRLUME_STATE_DIR",
                None
            ),
            Some(PathBuf::from("/srv/irlume"))
        );
        assert_eq!(
            unit_env_in("[Service]\nExecStart=/x\n", "IRLUME_STATE_DIR", None),
            None
        );
        assert_eq!(
            unit_env_in(
                "Environment=IRLUME_STATE_DIR=relative\n",
                "IRLUME_STATE_DIR",
                None
            ),
            None
        );
    }

    #[test]
    fn root_home_comes_from_the_uid_0_entry() {
        assert_eq!(
            root_home_in("bin:x:1:1::/:/sbin/nologin\nroot:x:0:0:root:/var/root:/bin/sh\n"),
            Some(PathBuf::from("/var/root"))
        );
        assert_eq!(root_home_in("root:x:0:0:root::/bin/sh\n"), None, "no home");
        assert_eq!(
            root_home_in("alice:x:1000:1000::/home/alice:/bin/sh\n"),
            None
        );
    }

    #[test]
    fn human_homes_skips_system_accounts_and_malformed_lines() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\n\
            bin:x:1:1::/:/sbin/nologin\n\
            alice:x:1000:1000::/home/alice:/bin/sh\n\
            broken line\n\
            relative:x:1001:1001::home/relative:/bin/sh\n\
            nouid:x:abc:1002::/home/nouid:/bin/sh\n\
            nobody:x:65534:65534::/:/sbin/nologin\n\
            bob:x:60000:60000::/home/bob:/bin/bash\n";
        let named = |accounts: Vec<Account>| -> Vec<(String, u32, PathBuf)> {
            accounts
                .into_iter()
                .map(|a| (a.name, a.uid, a.home))
                .collect()
        };
        assert_eq!(
            named(human_accounts_in(passwd)),
            vec![
                ("alice".into(), 1000, PathBuf::from("/home/alice")),
                ("bob".into(), 60000, PathBuf::from("/home/bob")),
            ]
        );
        // The sweep adds root's own home.
        assert_eq!(
            named(sweep_accounts_in(passwd)).last(),
            Some(&("root".into(), 0, PathBuf::from("/root")))
        );
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
        // Even read-only PATH consumers must share the lock: the TUI child-
        // process fixtures temporarily replace PATH with a private tool tree.
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            run_pkg("true", &["remove", "irlume"]).unwrap(),
            "removed the true package"
        );
        let nonzero = run_pkg("false", &[]).unwrap_err();
        assert!(nonzero.contains("false exited with"), "{nonzero}");
        let missing = run_pkg("irlume-no-such-pkg-manager-xyz", &[]).unwrap_err();
        assert!(missing.contains("could not run"), "{missing}");
    }

    // ---- 2026-09-17 uninstall-audit coverage --------------------------------

    #[test]
    fn arch_removal_matches_the_manual_hint() {
        // The automatic path and the printed hint must agree; without -n,
        // pacman leaves a .pacsave of the backup-marked retry-reset file.
        assert_eq!(arch_remove_args(), &["-Rns", "--noconfirm", "irlume"]);
        assert!(removal_hint(&InstallOrigin::ArchPkg).contains("-Rns"));
    }

    #[test]
    fn source_targets_cover_every_source_and_dbless_lane_file() {
        let targets = source_file_targets();
        let has = |p: &str| targets.iter().any(|t| t == &PathBuf::from(p));
        // The original source lane.
        for p in [
            "/usr/lib64/security/pam_irlume.so",
            "/usr/share/polkit-1/actions/org.irlume.enroll.policy",
            "/etc/systemd/system/irlumed.service",
        ] {
            assert!(has(p), "missing source target {p}");
        }
        // The package-lane files that outlive a lost package database (the
        // audit's F2): only this function removes them when no package owns
        // them, so every one must be named here.
        for p in [
            "/usr/libexec/irlume-password-verify",
            "/etc/pam.d/irlume-retry-reset",
            "/usr/lib/systemd/system/irlumed.service",
            "/usr/lib/systemd/system/irlumed.socket",
            "/usr/lib/systemd/system/irlume-reconcile.timer",
            "/usr/lib/systemd/system/irlume-runner-prune.timer",
            "/lib/systemd/system/irlumed.service",
            "/usr/lib/tmpfiles.d/irlume.conf",
            "/etc/tmpfiles.d/irlume.conf",
            "/etc/apparmor.d/usr.bin.irlumed",
        ] {
            assert!(has(p), "missing dbless-lane target {p}");
        }
    }

    #[test]
    fn extra_state_roots_name_existing_home_state_only() {
        let base = std::env::temp_dir().join(format!("irlume-extra-roots-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let with_state = test_account(&base, "a");
        let without = test_account(&base, "b");
        let duplicated = test_account(&base, "a");
        let default = base.join("default-state");
        std::fs::create_dir_all(home_state_path(&with_state.home)).unwrap();
        // Existing home state is named once; a home without it and the
        // default root (however the environment resolved it) never appear.
        let paths = |trees: Vec<HomeTree>| -> Vec<PathBuf> {
            trees
                .into_iter()
                .map(|tree| verified(Some(tree)).path)
                .collect()
        };
        let accounts = [with_state, without, duplicated];
        assert_eq!(
            paths(home_trees(&accounts, &default)),
            vec![home_state_path(&accounts[0].home)]
        );
        // The default root is excluded even when a home points at it.
        let as_default = home_state_path(&accounts[0].home);
        assert!(home_trees(&accounts[..1], &as_default).is_empty());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn token_guard_sweeps_extra_roots_and_fails_closed_on_unreadable_ones() {
        // A root irlumed's unit names holding an envelope the loader cannot
        // parse must surface as a REFUSAL-grade error naming that root:
        // skipping it is what let the homes wipe destroy a token nobody
        // examined (audit F1).
        let base = std::env::temp_dir().join(format!("irlume-token-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("srv/irlume");
        std::fs::create_dir_all(root.join("keyring")).unwrap();
        std::fs::write(root.join("keyring/carol.json"), b"not an envelope").unwrap();
        let err =
            sealed_token_holders_with(Ok(Vec::new()), &[], std::slice::from_ref(&root), &[], 0)
                .unwrap_err();
        assert!(
            err.contains(root.join("keyring").to_str().unwrap()),
            "error must name the swept root: {err}"
        );
        let _ = std::fs::remove_dir_all(&base);
        // An empty sweep is an empty holder list, and non-token kinds in the
        // default root stay irrelevant.
        let sweep = sealed_token_holders_with(
            Ok(vec![(
                "alice".into(),
                irlume_core::envelope::SecretKind::LoginPassword,
            )]),
            &[],
            &[],
            &[],
            0,
        )
        .unwrap();
        assert!(sweep.holders.is_empty() && sweep.notes.is_empty());
    }

    // ---- per-account trees: read and removed only inside each home --------

    const TOKEN_ENVELOPE: &str =
        r#"{"version":1,"secret":"GnomeKeyringToken","pcrs":[],"public":"","private":""}"#;
    const PASSWORD_ENVELOPE: &str = r#"{"version":1,"pcrs":[],"public":"","private":""}"#;

    /// An account named `name` with a fresh home under `base`, whose uid is
    /// this process's, so the home and everything the test puts in it is
    /// that account's own.
    fn test_account(base: &Path, name: &str) -> Account {
        use std::os::unix::fs::MetadataExt as _;
        let home = base.join(name);
        std::fs::create_dir_all(&home).unwrap();
        let uid = std::fs::metadata(&home).unwrap().uid();
        Account {
            name: name.into(),
            uid,
            home,
        }
    }

    fn verified(tree: Option<HomeTree>) -> VerifiedTree {
        match tree {
            Some(HomeTree::Verified(tree)) => tree,
            other => panic!("expected a verified tree, got {other:?}"),
        }
    }

    fn skipped(tree: Option<HomeTree>) -> String {
        match tree {
            Some(HomeTree::Skipped { reason, .. }) => reason,
            other => panic!("expected a skipped tree, got {other:?}"),
        }
    }

    /// A directory named `irlume` somewhere else, as another account's
    /// checkout or data would be, with an envelope and an enrollment in it.
    fn outside_tree(base: &Path) -> PathBuf {
        let outside = base.join("bob/irlume");
        std::fs::create_dir_all(outside.join("keyring")).unwrap();
        std::fs::write(outside.join("keep.txt"), b"not irlume's").unwrap();
        std::fs::write(outside.join("dana.json"), b"{}").unwrap();
        std::fs::write(outside.join("keyring/dana.json"), PASSWORD_ENVELOPE).unwrap();
        std::fs::write(outside.join("keyring/bob.json"), b"not an envelope").unwrap();
        outside
    }

    fn outside_intact(outside: &Path) -> bool {
        [
            "keep.txt",
            "dana.json",
            "keyring/dana.json",
            "keyring/bob.json",
        ]
        .iter()
        .all(|name| outside.join(name).exists())
    }

    #[test]
    fn a_home_tree_reached_through_a_link_is_neither_read_nor_removed() {
        let base = std::env::temp_dir().join(format!("irlume-home-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let outside = outside_tree(&base);
        let default = base.join("default-state");
        // A link at each step below the home, to a place holding `irlume`.
        let cases: [(&str, &str, PathBuf); 3] = [
            (".local", ".local", base.join("bob").join("..").join("up")),
            (".local/share", ".local/share", base.join("bob")),
            (
                ".local/share/irlume",
                ".local/share/irlume",
                outside.clone(),
            ),
        ];
        std::fs::create_dir_all(base.join("up/share")).unwrap();
        std::os::unix::fs::symlink(&outside, base.join("up/share/irlume")).unwrap();
        for (at, named, target) in cases {
            let dana = test_account(&base, "dana");
            let link = dana.home.join(at);
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();

            let reason = skipped(resolve_home_tree(&dana));
            assert!(
                reason.contains(&format!("{named} is a symbolic link")),
                "{reason}"
            );
            let homes = home_trees(std::slice::from_ref(&dana), &default);
            let sweep = sealed_token_holders_with(Ok(Vec::new()), &homes, &[], &[], 0)
                .expect("what is behind the link is not read");
            assert!(sweep.holders.is_empty());
            assert!(
                sweep.notes.len() == 1 && sweep.notes[0].starts_with("dana: "),
                "{:?}",
                sweep.notes
            );
            assert_eq!(disarm_home_trees(&homes), 0);
            let left = wipe_home_trees(&homes);
            assert!(
                left.len() == 1 && left[0].contains("not removed"),
                "{left:?}"
            );
            assert!(outside_intact(&outside), "a link at {at} was followed");
            std::fs::remove_dir_all(&dana.home).unwrap();
        }
        // A link to nothing is no tree at all, and nothing is named.
        let dana = test_account(&base, "dana");
        std::fs::create_dir_all(dana.home.join(".local")).unwrap();
        std::os::unix::fs::symlink(base.join("nowhere"), dana.home.join(".local/share")).unwrap();
        assert!(resolve_home_tree(&dana).is_none());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_home_tree_another_account_owns_is_skipped() {
        let base = std::env::temp_dir().join(format!("irlume-home-owner-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let mut alice = test_account(&base, "alice");
        std::fs::create_dir_all(home_state_path(&alice.home)).unwrap();
        if alice.uid != 0 {
            // The tree is this process's, which is now neither root nor alice.
            alice.uid += 1;
            let reason = skipped(resolve_home_tree(&alice));
            assert!(reason.contains("owned by uid"), "{reason}");
        }
        // Something that is not a directory in the tree's place is named.
        let bob = test_account(&base, "bob");
        std::fs::create_dir_all(bob.home.join(".local/share")).unwrap();
        std::fs::write(home_state_path(&bob.home), b"x").unwrap();
        assert!(skipped(resolve_home_tree(&bob)).contains("not a directory"));
        // A FIFO there, or on the way, is never opened for reading.
        use std::os::unix::ffi::OsStrExt as _;
        let carol = test_account(&base, "carol");
        std::fs::create_dir_all(carol.home.join(".local/share")).unwrap();
        for fifo in [home_state_path(&carol.home), bob.home.join(".local/share")] {
            let _ = std::fs::remove_file(&fifo);
            let _ = std::fs::remove_dir_all(&fifo);
            let c_fifo = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
            // SAFETY: `c_fifo` is a valid NUL-terminated path that outlives the call.
            assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        }
        let accounts = [bob, carol];
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(
                accounts
                    .iter()
                    .map(|account| resolve_home_tree(account).map(|tree| format!("{tree:?}")))
                    .collect::<Vec<_>>(),
            );
        });
        let found = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a FIFO in a home must not block the sweep");
        assert!(found[0].is_none(), "a FIFO on the way means no tree");
        assert!(
            found[1]
                .as_deref()
                .is_some_and(|tree| tree.contains("not a directory")),
            "{found:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_envelope_that_is_a_fifo_or_too_large_neither_hangs_nor_blocks() {
        use std::os::unix::ffi::OsStrExt as _;
        let base = std::env::temp_dir().join(format!("irlume-home-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let alice = test_account(&base, "alice");
        let keyring = home_state_path(&alice.home).join("keyring");
        std::fs::create_dir_all(&keyring).unwrap();
        let fifo =
            std::ffi::CString::new(keyring.join("fifo.json").as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let large = irlume_core::envelope::MAX_ENVELOPE_BYTES as usize + 1;
        std::fs::write(keyring.join("large.json"), " ".repeat(large)).unwrap();
        let default = base.join("default-state");
        let sweep_as = |root_uid: u32| {
            let homes = home_trees(std::slice::from_ref(&alice), &default);
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(sealed_token_holders_with(
                    Ok(Vec::new()),
                    &homes,
                    &[],
                    &[],
                    root_uid,
                ));
            });
            rx.recv_timeout(std::time::Duration::from_secs(10))
                .expect("reading the envelopes must not block")
        };
        // The account's own files are named, not a refusal.
        let sweep = sweep_as(0).expect("the account's own files do not refuse");
        assert!(sweep.holders.is_empty());
        assert_eq!(sweep.notes.len(), 2, "{:?}", sweep.notes);
        assert!(
            sweep.notes[0].contains("fifo.json") && sweep.notes[0].contains("not a regular file")
        );
        assert!(sweep.notes[1].contains("large.json") && sweep.notes[1].contains("larger than"));
        // Owned by root, the same files refuse, still at once.
        let err = sweep_as(alice.uid).unwrap_err();
        assert!(err.contains("keyring/fifo.json"), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_malformed_envelope_the_account_owns_is_named_and_does_not_block() {
        let base =
            std::env::temp_dir().join(format!("irlume-home-malformed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let alice = test_account(&base, "alice");
        let keyring = home_state_path(&alice.home).join("keyring");
        std::fs::create_dir_all(&keyring).unwrap();
        std::fs::write(keyring.join("x.json"), "{}").unwrap();
        let default = base.join("default-state");
        let sweep_as = |root_uid: u32| {
            let homes = home_trees(std::slice::from_ref(&alice), &default);
            sealed_token_holders_with(Ok(Vec::new()), &homes, &[], &[], root_uid)
        };
        let sweep = sweep_as(0).expect("a malformed file the account owns does not refuse");
        assert!(sweep.holders.is_empty());
        assert!(
            sweep.notes.len() == 1
                && sweep.notes[0].starts_with("alice: ")
                && sweep.notes[0].contains(keyring.join("x.json").to_str().unwrap()),
            "{:?}",
            sweep.notes
        );
        // Owned by root it refuses, naming the file.
        let err = sweep_as(alice.uid).unwrap_err();
        assert!(
            err.contains(keyring.join("x.json").to_str().unwrap()),
            "{err}"
        );
        // An envelope that parses still counts: a token refuses as before.
        std::fs::write(keyring.join("carol.json"), TOKEN_ENVELOPE).unwrap();
        assert_eq!(sweep_as(0).unwrap().holders, vec!["carol".to_string()]);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A link at the keyring's name that leads to a directory root owns is
    /// that root store: its tokens count, and what in it cannot be read
    /// refuses. The wipe removes only the link. A link to anything else is
    /// named, not followed.
    #[test]
    fn a_keyring_link_to_a_root_store_counts_and_any_other_link_is_named() {
        use std::os::unix::fs::MetadataExt as _;
        let base =
            std::env::temp_dir().join(format!("irlume-home-keyring-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let alice = test_account(&base, "alice");
        let tree_path = home_state_path(&alice.home);
        std::fs::create_dir_all(&tree_path).unwrap();
        let store = base.join("srv/keyring");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("carol.json"), TOKEN_ENVELOPE).unwrap();
        let link = tree_path.join("keyring");
        std::os::unix::fs::symlink(&store, &link).unwrap();
        let owner = std::fs::metadata(&store).unwrap().uid();
        let default = base.join("default-state");
        let sweep_as = |root_uid: u32| {
            let homes = home_trees(std::slice::from_ref(&alice), &default);
            sealed_token_holders_with(Ok(Vec::new()), &homes, &[], &[], root_uid)
        };
        // This process stands in for root: the store is root's when the
        // injected root uid owns it.
        assert_eq!(sweep_as(owner).unwrap().holders, vec!["carol".to_string()]);
        std::fs::write(store.join("x.json"), "{}").unwrap();
        let err = sweep_as(owner).unwrap_err();
        assert!(err.contains("x.json"), "{err}");
        std::fs::remove_file(store.join("x.json")).unwrap();
        let sweep = sweep_as(owner.wrapping_add(1)).unwrap();
        assert!(sweep.holders.is_empty(), "{sweep:?}");
        assert!(
            sweep.notes.len() == 1
                && sweep.notes[0].contains("symbolic link to no directory root owns"),
            "{:?}",
            sweep.notes
        );
        // A link to nothing, or into a loop, is named too.
        for target in [base.join("nowhere"), link.clone()] {
            std::fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let sweep = sweep_as(owner).unwrap();
            assert!(
                sweep.holders.is_empty()
                    && sweep.notes.len() == 1
                    && sweep.notes[0].contains("symbolic link"),
                "{target:?}: {sweep:?}"
            );
        }
        // The login guards follow it to root's store too, and the wipe,
        // which removes only the link, reports that it did.
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&store, &link).unwrap();
        let homes = home_trees(std::slice::from_ref(&alice), &default);
        let HomeTree::Verified(tree) = &homes[0] else {
            panic!("{homes:?}");
        };
        assert_eq!(tree.keeps_store_of(owner), Ok(true));
        assert_eq!(tree.keeps_store_of(owner.wrapping_add(1)), Ok(false));
        let left = wipe_home_trees(&homes);
        assert!(
            left.len() == 1 && left[0].contains("1 symbolic link"),
            "{left:?}"
        );
        assert!(!tree_path.exists(), "the tree and its link are removed");
        assert!(store.join("carol.json").is_file(), "the store is not");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A keyring directory that cannot be opened is judged by its own owner:
    /// the account's is named, root's refuses, and one whose owner cannot be
    /// read refuses whoever owns the tree.
    #[test]
    fn an_unopenable_keyring_directory_is_judged_by_its_own_owner() {
        use std::os::unix::fs::PermissionsExt as _;
        if is_root() {
            return; // root opens any mode
        }
        let base =
            std::env::temp_dir().join(format!("irlume-home-keyring-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let alice = test_account(&base, "alice");
        let tree_path = home_state_path(&alice.home);
        let keyring = tree_path.join("keyring");
        std::fs::create_dir_all(&keyring).unwrap();
        let default = base.join("default-state");
        let homes = home_trees(std::slice::from_ref(&alice), &default);
        let sweep_as =
            |root_uid: u32| sealed_token_holders_with(Ok(Vec::new()), &homes, &[], &[], root_uid);
        let mode = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        mode(&keyring, 0o000);
        let (as_account, as_root) = (sweep_as(alice.uid + 1), sweep_as(alice.uid));
        mode(&keyring, 0o700);
        let sweep = as_account.expect("the account's own store does not refuse");
        assert!(
            sweep.notes.len() == 1 && sweep.notes[0].contains("could not be read"),
            "{:?}",
            sweep.notes
        );
        assert!(as_root.is_err_and(|e| e.contains("irlume/keyring")));
        // The tree cannot be searched: whose the store is is unknown.
        mode(&tree_path, 0o000);
        let unknown = sweep_as(alice.uid + 1);
        mode(&tree_path, 0o700);
        assert!(unknown.is_err_and(|e| e.contains("irlume/keyring")));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A unit root that is an account's verified tree is swept once, under
    /// the account-tree rules, as the teardown treats it; another unit root
    /// is still read strictly.
    #[test]
    fn a_unit_root_that_is_an_accounts_tree_is_swept_once() {
        let base =
            std::env::temp_dir().join(format!("irlume-home-unit-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let alice = test_account(&base, "alice");
        let tree_path = home_state_path(&alice.home);
        std::fs::create_dir_all(tree_path.join("keyring")).unwrap();
        std::fs::write(tree_path.join("keyring/x.json"), "{}").unwrap();
        let homes = home_trees(std::slice::from_ref(&alice), &base.join("default-state"));
        let sweep = sealed_token_holders_with(
            Ok(Vec::new()),
            &homes,
            std::slice::from_ref(&tree_path),
            &[],
            alice.uid.wrapping_add(1),
        )
        .expect("what the account wrote in its own tree does not refuse");
        assert!(
            sweep.notes.len() == 1 && sweep.notes[0].contains("x.json"),
            "{:?}",
            sweep.notes
        );
        let other = base.join("srv/irlume");
        std::fs::create_dir_all(other.join("keyring")).unwrap();
        std::fs::write(other.join("keyring/x.json"), "{}").unwrap();
        let err = sealed_token_holders_with(
            Ok(Vec::new()),
            &homes,
            &[tree_path, other.clone()],
            &[],
            alice.uid.wrapping_add(1),
        )
        .unwrap_err();
        assert!(err.contains(other.to_str().unwrap()), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_unreadable_entry_whose_owner_is_unknown_refuses() {
        assert!(unreadable_refuses(None, 0));
        assert!(unreadable_refuses(Some(0), 0));
        assert!(!unreadable_refuses(Some(1000), 0));
    }

    /// A file name an account chose reaches the terminal with its control
    /// characters escaped.
    #[test]
    fn a_crafted_envelope_name_is_escaped_in_the_notes() {
        assert_eq!(terminal_safe("a\u{1b}[2Jb\nc"), "a\\u{1b}[2Jb\\nc");
        // Bidirectional overrides and isolates, and zero-width characters,
        // are escaped too; ordinary text, accents included, is left alone.
        assert_eq!(
            terminal_safe("x\u{202e}y\u{2066}z\u{200b}é"),
            "x\\u{202e}y\\u{2066}z\\u{200b}é"
        );
        let base = std::env::temp_dir().join(format!("irlume-home-escape-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let alice = test_account(&base, "alice");
        let keyring = home_state_path(&alice.home).join("keyring");
        std::fs::create_dir_all(&keyring).unwrap();
        std::fs::write(keyring.join("\u{1b}[31mforged\n.json"), "{}").unwrap();
        let homes = home_trees(std::slice::from_ref(&alice), &base.join("default-state"));
        let sweep =
            sealed_token_holders_with(Ok(Vec::new()), &homes, &[], &[], alice.uid.wrapping_add(1))
                .unwrap();
        assert_eq!(sweep.notes.len(), 1, "{:?}", sweep.notes);
        assert!(
            !sweep.notes[0].chars().any(char::is_control)
                && sweep.notes[0].contains("\\u{1b}[31mforged\\n.json"),
            "{:?}",
            sweep.notes
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An envelope root owns, linked into an account's keyring under an
    /// envelope's name, counts: the wipe removes only the link. A link to a
    /// root file that is no envelope, or to one root does not own, is only
    /// named.
    #[test]
    fn a_linked_root_envelope_counts_and_other_linked_entries_are_named() {
        use std::os::unix::fs::MetadataExt as _;
        let base =
            std::env::temp_dir().join(format!("irlume-home-linked-entry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let alice = test_account(&base, "alice");
        let keyring = home_state_path(&alice.home).join("keyring");
        std::fs::create_dir_all(&keyring).unwrap();
        let outside = base.join("srv");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("token.json"), TOKEN_ENVELOPE).unwrap();
        std::fs::write(outside.join("other.txt"), "not an envelope").unwrap();
        std::os::unix::fs::symlink(outside.join("token.json"), keyring.join("carol.json")).unwrap();
        let owner = std::fs::metadata(&outside).unwrap().uid();
        let default = base.join("default-state");
        let sweep_as = |root_uid: u32| {
            let homes = home_trees(std::slice::from_ref(&alice), &default);
            sealed_token_holders_with(Ok(Vec::new()), &homes, &[], &[], root_uid)
        };
        // This process stands in for root: the linked envelope is "root's",
        // and its token counts.
        assert_eq!(sweep_as(owner).unwrap().holders, vec!["carol".to_string()]);
        // Neither link leads to a file of root's here: both are only named.
        std::os::unix::fs::symlink(outside.join("other.txt"), keyring.join("dana.json")).unwrap();
        let sweep = sweep_as(owner.wrapping_add(1)).unwrap();
        assert!(sweep.holders.is_empty(), "{sweep:?}");
        assert_eq!(sweep.notes.len(), 2, "{:?}", sweep.notes);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A dangling link at an envelope's name in an account's keyring is the
    /// account's (its owner is read without following it), so it is only
    /// named and does not stop the uninstall.
    #[test]
    fn a_dangling_link_in_an_accounts_keyring_is_only_named() {
        let base =
            std::env::temp_dir().join(format!("irlume-home-dangling-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let alice = test_account(&base, "alice");
        let keyring = home_state_path(&alice.home).join("keyring");
        std::fs::create_dir_all(&keyring).unwrap();
        std::os::unix::fs::symlink(base.join("nowhere.json"), keyring.join("foo.json")).unwrap();
        let homes = home_trees(std::slice::from_ref(&alice), &base.join("default-state"));
        let sweep =
            sealed_token_holders_with(Ok(Vec::new()), &homes, &[], &[], alice.uid.wrapping_add(1))
                .expect("a link the account owns does not refuse");
        assert!(
            sweep.holders.is_empty()
                && sweep.notes.len() == 1
                && sweep.notes[0].contains("foo.json"),
            "{sweep:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A tree whose removal takes a symbolic link is reported among what
    /// may still hold data, which keeps the SRK: the link is removed, never
    /// followed, and the account could point it anywhere until then. A tree
    /// without one is not.
    #[test]
    fn a_tree_whose_removal_takes_a_link_keeps_the_srk() {
        let base =
            std::env::temp_dir().join(format!("irlume-home-linked-left-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let store = base.join("srv/keyring");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("alice.json"), PASSWORD_ENVELOPE).unwrap();
        let alice = test_account(&base, "alice");
        let tree_path = home_state_path(&alice.home);
        let wipe = |link: bool| {
            std::fs::create_dir_all(tree_path.join("runner")).unwrap();
            if link {
                std::os::unix::fs::symlink(&store, tree_path.join("keyring")).unwrap();
            }
            let homes = home_trees(std::slice::from_ref(&alice), &base.join("default-state"));
            let left = wipe_home_trees(&homes);
            assert!(!tree_path.exists(), "the tree is removed");
            left
        };
        assert!(wipe(false).is_empty(), "no link, nothing left");
        let left = wipe(true);
        assert!(
            left.len() == 1
                && left[0].contains("1 symbolic link")
                && left[0].contains("the TPM storage key is kept"),
            "{left:?}"
        );
        assert!(store.join("alice.json").is_file(), "what it led to stays");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_accounts_own_tree_is_found_disarmed_and_removed() {
        let base = std::env::temp_dir().join(format!("irlume-home-normal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let alice = test_account(&base, "alice");
        let tree_path = home_state_path(&alice.home);
        std::fs::create_dir_all(tree_path.join("keyring")).unwrap();
        std::fs::create_dir_all(tree_path.join("runner")).unwrap();
        std::fs::write(tree_path.join("alice.json"), b"{}").unwrap();
        std::fs::write(tree_path.join("runner/record"), b"x").unwrap();
        std::fs::write(tree_path.join("keyring/alice.json"), PASSWORD_ENVELOPE).unwrap();
        let homes = home_trees(std::slice::from_ref(&alice), &base.join("default-state"));
        assert_eq!(homes.len(), 1);
        let sweep = sealed_token_holders_with(Ok(Vec::new()), &homes, &[], &[], 0).unwrap();
        assert!(
            sweep.holders.is_empty() && sweep.notes.is_empty(),
            "{sweep:?}"
        );
        assert_eq!(disarm_home_trees(&homes), 1);
        assert!(!tree_path.join("keyring/alice.json").exists(), "disarmed");
        assert!(wipe_home_trees(&homes).is_empty());
        assert!(!tree_path.exists(), "the tree is removed");
        assert!(
            alice.home.join(".local/share").is_dir(),
            "and only the tree"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn nothing_a_link_inside_the_tree_points_at_is_disarmed_or_removed() {
        let base = std::env::temp_dir().join(format!("irlume-home-inner-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let outside = outside_tree(&base);
        let dana = test_account(&base, "dana");
        let tree_path = home_state_path(&dana.home);
        std::fs::create_dir_all(&tree_path).unwrap();
        std::fs::write(tree_path.join("dana.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(outside.join("keyring"), tree_path.join("keyring")).unwrap();
        std::os::unix::fs::symlink(&outside, tree_path.join("elsewhere")).unwrap();
        let homes = home_trees(std::slice::from_ref(&dana), &base.join("default-state"));
        let sweep = sealed_token_holders_with(Ok(Vec::new()), &homes, &[], &[], 0).unwrap();
        assert!(
            sweep.notes[0].contains("symbolic link"),
            "{:?}",
            sweep.notes
        );
        // --keep-data disarms, and must not reach through the link.
        assert_eq!(disarm_home_trees(&homes), 1);
        let left = wipe_home_trees(&homes);
        assert!(
            left.len() == 1 && left[0].contains("2 symbolic link"),
            "{left:?}"
        );
        assert!(!tree_path.exists());
        assert!(outside_intact(&outside));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The removal after the check goes through the directory held since
    /// it was verified: a tree renamed away and replaced then is still the
    /// one emptied, and a replacement that is not empty is left whole.
    #[test]
    fn a_tree_replaced_after_the_check_is_emptied_where_it_went_and_its_replacement_kept() {
        let base = std::env::temp_dir().join(format!("irlume-home-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let alice = test_account(&base, "alice");
        let tree_path = home_state_path(&alice.home);
        std::fs::create_dir_all(tree_path.join("keyring")).unwrap();
        std::fs::write(tree_path.join("alice.json"), b"{}").unwrap();
        std::fs::write(tree_path.join("keyring/alice.json"), PASSWORD_ENVELOPE).unwrap();
        let homes = home_trees(std::slice::from_ref(&alice), &base.join("default-state"));
        let tree = match &homes[0] {
            HomeTree::Verified(tree) => tree,
            other => panic!("{other:?}"),
        };
        // Between the check and the removal the tree moves aside and a real
        // directory with someone's data takes its name.
        let moved = tree_path.with_file_name("moved");
        std::fs::rename(&tree_path, &moved).unwrap();
        std::fs::create_dir(&tree_path).unwrap();
        std::fs::write(tree_path.join("victim.txt"), b"not irlume's").unwrap();
        let owner = {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(&moved).unwrap().uid()
        };
        assert!(tree.remove_held(&[owner]).is_err());
        assert!(
            tree_path.join("victim.txt").is_file(),
            "the replacement is kept"
        );
        assert_eq!(
            std::fs::read_dir(&moved).unwrap().count(),
            0,
            "the tree is emptied"
        );
        // An empty replacement is removed: it held nothing.
        std::fs::remove_file(tree_path.join("victim.txt")).unwrap();
        assert!(tree.remove_held(&[owner]).is_ok());
        assert!(!tree_path.exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// What the given owners do not own is left in place and named, with
    /// everything below it; a link is removed, never what it points to.
    #[test]
    fn clearing_a_tree_leaves_what_another_account_owns() {
        use std::os::unix::fs::MetadataExt as _;
        let base = std::env::temp_dir().join(format!("irlume-home-clear-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let tree = base.join("tree");
        std::fs::create_dir_all(tree.join("sub/deeper")).unwrap();
        std::fs::write(tree.join("file"), b"x").unwrap();
        std::fs::write(tree.join("sub/deeper/file"), b"x").unwrap();
        let outside = outside_tree(&base);
        std::os::unix::fs::symlink(&outside, tree.join("link")).unwrap();
        let uid = std::fs::metadata(&tree).unwrap().uid();
        let dir = open_dir(&tree).unwrap();
        let (mut kept, mut links) = (Vec::new(), 0);
        clear_dir(
            &dir,
            Path::new(""),
            &[uid.wrapping_add(1)],
            &mut kept,
            &mut links,
        )
        .unwrap();
        assert_eq!(links, 0, "a link another account owns is kept, not removed");
        kept.sort();
        assert_eq!(
            kept,
            vec![
                PathBuf::from("file"),
                PathBuf::from("link"),
                PathBuf::from("sub")
            ]
        );
        assert!(tree.join("sub/deeper/file").is_file() && tree.join("file").is_file());
        let (mut kept, mut links) = (Vec::new(), 0);
        clear_dir(&dir, Path::new(""), &[uid], &mut kept, &mut links).unwrap();
        assert_eq!(links, 1, "the removed link is counted");
        assert!(kept.is_empty(), "{kept:?}");
        assert_eq!(std::fs::read_dir(&tree).unwrap().count(), 0);
        assert!(
            outside_intact(&outside),
            "the link was removed, not followed"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_tree_replaced_after_it_was_checked_is_left_in_place() {
        let base = std::env::temp_dir().join(format!("irlume-home-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let outside = outside_tree(&base);
        let alice = test_account(&base, "alice");
        let tree_path = home_state_path(&alice.home);
        std::fs::create_dir_all(&tree_path).unwrap();
        let homes = home_trees(std::slice::from_ref(&alice), &base.join("default-state"));
        // The tree moves aside and a link takes its name.
        std::fs::rename(&tree_path, tree_path.with_file_name("moved")).unwrap();
        std::os::unix::fs::symlink(&outside, &tree_path).unwrap();
        let left = wipe_home_trees(&homes);
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(outside_intact(&outside));
        // So does a fresh directory, which was never checked.
        std::fs::remove_file(&tree_path).unwrap();
        std::fs::create_dir(&tree_path).unwrap();
        assert_eq!(wipe_home_trees(&homes).len(), 1);
        assert!(tree_path.is_dir() && tree_path.with_file_name("moved").is_dir());
        // The parent moving away does not redirect the removal either: it is
        // made through the directory that was opened.
        let share = alice.home.join(".local/share");
        std::fs::remove_dir(&tree_path).unwrap();
        std::fs::rename(tree_path.with_file_name("moved"), &tree_path).unwrap();
        let homes = home_trees(std::slice::from_ref(&alice), &base.join("default-state"));
        std::fs::rename(&share, alice.home.join(".local/share-moved")).unwrap();
        std::os::unix::fs::symlink(base.join("bob"), &share).unwrap();
        assert!(wipe_home_trees(&homes).is_empty());
        assert!(!alice.home.join(".local/share-moved/irlume").exists());
        assert!(outside_intact(&outside));
        let _ = std::fs::remove_dir_all(&base);
    }
}
