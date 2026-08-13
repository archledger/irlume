// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume login <status|enable|disable>`: wire face auth into the login
//! greeters (GDM/SDDM/LightDM/plasmalogin), the KDE lock screen, and (opt-in)
//! sudo and polkit. The Rust replacement for scripts/deploy-keyring-unlock.sh.
//! Ported from
//! linhello's pamwire framework, adapted to irlume's keyring-unlock greeter
//! BLOCK (unseal + a pam_permit landing for the success=1 jump + a reseal
//! self-heal) and the `wait` lock stanza.
//!
//! FAIL-SAFE: every face line is `[success=1 default=ignore]` or `sufficient`,
//! so the password is always the floor; wiring cannot lock the user out.
//!
//! Two file strategies: real `/etc/pam.d` files (gdm-password/sddm/lightdm/sudo)
//! are backed up to `*.pre-irlume` and edited in place (restore = move the backup
//! back); vendor-only files (plasmalogin/kde-fingerprint, shipped in
//! `/usr/lib/pam.d`) get an `/etc` override materialized from the vendor copy and
//! marked (revert = delete the override).

use irlume_common::platform::{distro_family, DistroFamily};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

// Horizontal split by responsibility, innermost first: the bytes we write
// (`stanzas`), reading a stack (`grammar`), rewriting one (`transform`). All
// three are pure (no filesystem, no policy), which is what keeps this module's
// file handling and the wiring decisions testable apart from each other.
//
// Deliberately NOT split by modality: face and fingerprint lines share the same
// greeter files (a GDM box gets the face `unseal` line and the fingerprint
// keyring line in one `/etc/pam.d/gdm-password`, in a required order), so a
// face/fingerprint split would put one ordering invariant under two owners.
mod files;
mod grammar;
mod report;
mod stanzas;
mod transform;

use files::*;
use grammar::*;
use report::{report_keyring_handoff, status};
use stanzas::*;
use transform::*;

// Re-exported for the rest of the CLI, which reaches these as `pamwire::…`.
// A glob `use` binds names privately, so the public surface is listed here
// rather than inherited, which also keeps that surface visible in one place.
pub(crate) use files::{is_managed_path, lock_pam, restore_surface};
// The PAM-grammar items shared outside this module: `fingerprint.rs` and the
// TUI must read stack lines with the same comment and rule-field semantics
// the wiring uses, or the two would disagree about what a file configures.
pub(crate) use grammar::{directive, directive_has_auth_module, has_line_continuation};
pub(crate) use report::{
    keyring_handoff_warnings, login_manager_fact, status_report, surface_facts, HandoffWarning,
};
pub(crate) use stanzas::BACKUP;

/// A PAM service to wire. `vendor=Some` → materialize an /etc override from the
/// vendor copy; `vendor=None` → back up and edit the real /etc file.
struct Svc {
    etc: &'static str,
    vendor: Option<&'static str>,
}

const GREETERS: &[Svc] = &[
    Svc {
        etc: "/etc/pam.d/gdm-password",
        vendor: None,
    }, // GNOME / GDM
    Svc {
        etc: "/etc/pam.d/sddm",
        vendor: None,
    },
    Svc {
        etc: "/etc/pam.d/lightdm",
        vendor: None,
    },
    Svc {
        etc: "/etc/pam.d/plasmalogin",
        vendor: Some("/usr/lib/pam.d/plasmalogin"),
    }, // Plasma 6
    Svc {
        etc: "/etc/pam.d/cosmic-greeter",
        vendor: None,
    }, // COSMIC (Pop!_OS / System76)
    Svc {
        etc: "/etc/pam.d/greetd",
        vendor: None,
    }, // greetd (sway / wayland / tuigreet)
    Svc {
        etc: "/etc/pam.d/ly",
        vendor: None,
    }, // ly (TUI display manager; `auth include login`, unit is ly@<tty>)
];
// KDE lock: wire the submit-driven `kde` password service with the on-demand
// face block, NOT KDE's ambient `kde-fingerprint` parallel-biometric slot, so
// face engages only on an empty-field Enter (never continuously scanning). The
// `kde` service classifies as ScreenUnlock, so `ondemand` verifies identity and
// releases no credential.
const LOCKSCREEN: Svc = Svc {
    etc: "/etc/pam.d/kde",
    // Arch/Plasma ships the locker service only in the vendor dir; materialize
    // an /etc override from it (like plasmalogin) instead of skipping the lock
    // screen because /etc/pam.d/kde doesn't exist yet.
    vendor: Some("/usr/lib/pam.d/kde"),
};
/// GDM uses a SEPARATE PAM service for fingerprint logins (`gdm-fingerprint`),
/// distinct from `gdm-password` (password/face). It runs pam_fprintd then
/// pam_gnome_keyring, which finds no password and leaves the wallet locked. We
/// slot the `keyring` unseal line between them (ADR-0003) so a fingerprint login
/// opens the wallet. Only present on GNOME/GDM systems; skipped elsewhere.
const FP_GREETERS: &[Svc] = &[Svc {
    etc: "/etc/pam.d/gdm-fingerprint",
    vendor: None,
}];
const SUDO: &str = "/etc/pam.d/sudo";
/// polkit's agent helper always authenticates through the `polkit-1` PAM
/// service. Debian/Arch ship a real /etc file (edit-in-place with backup);
/// Fedora ships only the vendor copy (materialize an /etc override from it,
/// like plasmalogin). Opt-in via `--with-polkit`; this is what lets a face
/// match satisfy app prompts such as Bitwarden's biometric unlock.
const POLKIT: Svc = Svc {
    etc: "/etc/pam.d/polkit-1",
    vendor: Some("/usr/lib/pam.d/polkit-1"),
};

// ---- CLI entry ---------------------------------------------------------------

pub fn run(action: Option<&str>, args: &[String]) -> ExitCode {
    let apply = args.iter().any(|a| a == "--apply");
    let with_sudo = args.iter().any(|a| a == "--with-sudo");
    let with_polkit = args.iter().any(|a| a == "--with-polkit");
    match action {
        None | Some("status") => status(),
        Some("enable") => act(true, apply, with_sudo, with_polkit),
        Some("disable") => act(false, apply, with_sudo, with_polkit),
        Some("reconcile") => reconcile(),
        _ => {
            eprintln!(
                "usage: irlume login <status|enable|disable|reconcile> [--with-sudo] [--with-polkit] [--apply]"
            );
            eprintln!("  (without --apply, prints what it WOULD change: a dry run)");
            ExitCode::from(2)
        }
    }
}

/// True when any greeter or the lock screen carries the irlume wiring; the
/// "is face login actually wired" probe for the TUI dashboard (sudo excluded:
/// face-sudo alone doesn't make the login screen work).
/// Path of the marker recording that `login enable` was applied, and with which
/// flags. Its existence is the signal that irlume login *should* be wired; a
/// distro update that strips our PAM lines does not touch this file.
fn wired_marker_path() -> std::path::PathBuf {
    irlume_common::state_dir().join("login.wired")
}

/// Persist (on enable) or remove (on disable) the wiring marker. The body is a
/// tiny stable key=value record of the extra scopes so reconcile re-applies the
/// same `--with-sudo` / `--with-polkit` choice, not a bare login wiring.
pub(crate) fn write_wired_marker(
    enable: bool,
    with_sudo: bool,
    with_polkit: bool,
    with_lock: bool,
) {
    let path = wired_marker_path();
    if !enable {
        let _ = std::fs::remove_file(&path);
        return;
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // with_lock records whether we actually wired the KDE lock screen, so a later
    // absence of /etc/pam.d/kde is only a regression when it was ours to maintain
    // (a Plasma package's vendor /usr/lib/pam.d/kde on a GNOME box must not read
    // as a regression and loop reconcile forever).
    let body = format!("with_sudo={with_sudo}\nwith_polkit={with_polkit}\nwith_lock={with_lock}\n");
    // 0600, root-owned (enable/reconcile run as root): the marker must not be
    // plantable by a non-root user, since reconcile trusts its with_sudo flag.
    // A silent failure would leave self-heal disabled without the user knowing,
    // so warn rather than swallow it.
    // Atomic: a short write here reads back as all-false (see
    // `read_wired_marker`), which silently drops the sudo, polkit and lock
    // scopes from the self-heal. Reproduced on a full filesystem, where the
    // truncating helper left 4096 bytes of a partial marker while the atomic
    // one left the previous marker intact.
    if let Err(e) = irlume_common::write_0600_atomic(&path, body.as_bytes()) {
        eprintln!(
            "[login] warning: could not write the self-heal marker {}: {e}\n\
             [login] automatic re-wiring after a distro PAM update will not run.",
            path.display()
        );
    }
}

/// Re-read the marker's recorded flags. Returns `None` when login was never
/// enabled (no marker), so reconcile does nothing on machines that opted out.
pub(crate) fn read_wired_marker() -> Option<(bool, bool, bool)> {
    let path = wired_marker_path();
    // In production (default state dir) the marker must be root-owned: reconcile
    // acts on its with_sudo flag as root, so a marker a non-root user could plant
    // (were /var/lib/irlume perms ever to slip) must not drive wiring. Skipped
    // under an IRLUME_STATE_DIR sandbox (tests/dev), where it is user-owned and
    // reconcile never runs from the system path unit anyway.
    if std::env::var_os("IRLUME_STATE_DIR").is_none() {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata(&path).ok()?.uid();
        if uid != 0 {
            eprintln!(
                "[login] ignoring self-heal marker not owned by root (uid {uid}): {}",
                path.display()
            );
            return None;
        }
    }
    let body = std::fs::read_to_string(&path).ok()?;
    let flag = |key: &str| {
        body.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim() == "true")
            .unwrap_or(false)
    };
    // with_lock absent in a marker written before this field existed: default
    // false, so an old marker never triggers a false lock-screen regression; the
    // next `login enable` / adopt rewrites it with the real value.
    Some((flag("with_sudo"), flag("with_polkit"), flag("with_lock")))
}

/// Idempotent repair entry point, meant to run unattended from a systemd path
/// unit watching the greeter PAM files. If login was enabled (marker present)
/// but the PAM stack is no longer wired, re-apply the recorded configuration;
/// otherwise exit quietly. Always root (the path unit's service runs as root).
fn reconcile() -> ExitCode {
    // This unit fires when a PAM file changes, which is exactly what every other
    // irlume path does, so without the lock reconcile is the most likely thing
    // to be writing a stack somebody else is halfway through writing.
    let _lock = match lock_pam() {
        Ok(lock) => lock,
        Err(message) => {
            eprintln!("[login] reconcile cannot serialise: {message}");
            return ExitCode::FAILURE;
        }
    };
    let Some((with_sudo, with_polkit, with_lock)) = read_wired_marker() else {
        // No marker. Two sub-cases:
        //  - Login IS currently wired (an upgrade from a pre-marker version, or
        //    a hand-wired install): ADOPT the existing wiring into a marker so a
        //    FUTURE distro strip self-heals. This is what the marker migration
        //    covers; without it an upgrader stays un-self-healing until they
        //    happen to re-run `login enable` (the exact gap issue #93 hit).
        //  - Login was never wired: nothing to maintain.
        if !login_wired() {
            return ExitCode::SUCCESS;
        }
        if effective_uid() != 0 {
            // The root-owned marker can't be written as a normal user; the boot
            // service / path unit run as root, so this is only a manual-run edge.
            return ExitCode::SUCCESS;
        }
        let with_sudo = Path::new(SUDO).exists() && file_has_module(Path::new(SUDO));
        let with_polkit = polkit_wired() == Some(true);
        // Record the lock screen as ours only if the /etc override actually
        // carries the module now (it was wired), not merely because the vendor
        // file exists.
        let with_lock =
            Path::new(LOCKSCREEN.etc).exists() && file_has_module(Path::new(LOCKSCREEN.etc));
        write_wired_marker(true, with_sudo, with_polkit, with_lock);
        eprintln!(
            "[login] adopted the existing face-login wiring into the self-heal marker \
             (sudo={with_sudo}, polkit={with_polkit}, lock={with_lock}); a future distro PAM \
             update will now re-apply it automatically"
        );
        return ExitCode::SUCCESS;
    };
    if active_login_wired()
        && !lockscreen_regressed(with_lock)
        && !wired_surface_regressed(with_sudo, with_polkit)
    {
        // Still intact; the common case after a spurious file-change event.
        // Every surface the marker claims must be checked, not just the login
        // greeter: sudo, polkit and the fingerprint-keyring service can be
        // stripped on their own while the greeter stays wired.
        return ExitCode::SUCCESS;
    }
    if effective_uid() != 0 {
        eprintln!("[login] reconcile needs root; run: sudo irlume login reconcile");
        return ExitCode::FAILURE;
    }
    eprintln!("[login] greeter PAM configuration changed; re-applying irlume wiring");
    // The lock is already held above; taking it again would deadlock.
    act_holding_lock(true, true, with_sudo, with_polkit)
}

/// Whether the ACTIVE display manager's own greeter service carries the module.
/// [`login_wired`] is any-of (true if any greeter/lock file has the line), which
/// gives reconcile a blind spot: a distro update that strips only the active
/// greeter while a stale/inactive greeter file keeps the line would leave
/// `login_wired()` true and the real login broken. This checks the greeter the
/// active DM actually consults, so reconcile repairs the login that matters. An
/// absent active-greeter file counts as not-wired too (a deleted /etc override).
/// Falls back to `login_wired()` when the active DM is unknown/absent.
/// Does the KDE lock-screen override actually carry the module right now?
///
/// The self-heal marker records this so a later absence is only a regression
/// when the line was ours to maintain. Both apply paths must record what is
/// WIRED rather than what was asked for: writing `with_lock=true` on a host that
/// wires no lock screen makes reconcile chase a surface that was never there.
pub(crate) fn lock_wired() -> bool {
    Path::new(LOCKSCREEN.etc).exists() && file_has_module(Path::new(LOCKSCREEN.etc))
}

pub(crate) fn active_login_wired() -> bool {
    let Some(dm) = active_display_manager() else {
        return login_wired();
    };
    let (primary, _fp) = dm_pam_services(&dm);
    if primary == "(unknown)" {
        return login_wired();
    }
    let etc = PathBuf::from(format!("/etc/pam.d/{primary}"));
    etc.exists() && file_has_module(&etc)
}

/// Whether the KDE lock-screen face wiring regressed. Two shapes, both of which
/// `active_login_wired` (login greeter only) misses while the DM greeter stays
/// intact: a pambase / pam-auth-update regeneration STRIPS the module from the
/// /etc/pam.d/kde override, OR a package update DELETES the override entirely
/// (reverting to the vendor-only service). On a non-KDE box the vendor file is
/// absent, so a missing override is not a regression — there is nothing to
/// maintain there. reconcile re-materializes/re-wires in either case.
fn lockscreen_regressed(with_lock: bool) -> bool {
    // Only maintain the lock screen if we actually wired it (marker with_lock).
    // Otherwise a Plasma vendor file present on a non-KDE box, or a box that
    // chose fingerprint/RGB-less (no face lock), would read as a permanent
    // regression and loop reconcile.
    if !with_lock {
        return false;
    }
    lock_regressed(Path::new(LOCKSCREEN.etc), LOCKSCREEN.vendor.map(Path::new))
}

/// Testable core of [`lockscreen_regressed`]: the /etc override was stripped in
/// place (still there, lost the module), or it was deleted while a `vendor`
/// service remains (a KDE box `login enable` had materialized and a package
/// removed). A path taken from a real Svc so a temp path can drive it in tests.
fn lock_regressed(etc: &Path, vendor: Option<&Path>) -> bool {
    if etc.exists() {
        return !file_has_module(etc); // stripped in place
    }
    vendor.is_some_and(|v| v.exists()) // deleted, but re-materializable from vendor
}

fn path_regressed(etc: &Path) -> bool {
    etc.exists() && !file_has_module(etc)
}

/// Whether a surface we RECORDED as wired has since lost the module.
///
/// The login greeter and the KDE lock screen were checked; `sudo`, polkit and
/// the fingerprint-keyring service were not. That left the self-heal half open:
/// a distro update that rewrote only one of those healed nothing, because
/// reconcile saw the login greeter intact and returned "still intact" without
/// looking further. The feature then stopped working silently, which is the
/// exact failure mode the self-heal exists to prevent (issue #93).
///
/// Found on hardware: stripping `/etc/pam.d/gdm-fingerprint` on a wired box left
/// it stripped through both a manual `login reconcile` and the path unit's
/// automatic run.
///
/// Each surface is only maintained if the marker says we wired it, so a file
/// that was never ours cannot make reconcile loop forever.
/// Whether the polkit file carries the module on an OLD control that ignores
/// PAM_ABORT. The current stanza is `[success=done new_authtok_reqd=done
/// abort=die default=ignore]`; anything else with the module is a pre-#424
/// wiring whose head-shake decline silently does nothing.
fn polkit_stanza_stale(etc: &Path) -> bool {
    std::fs::read_to_string(etc).is_ok_and(|c| {
        c.lines().any(|l| {
            let d = grammar::directive(l);
            d.contains(stanzas::MODULE) && !d.contains("abort=die")
        })
    })
}

fn wired_surface_regressed(with_sudo: bool, with_polkit: bool) -> bool {
    let fp: Vec<&Path> = FP_GREETERS.iter().map(|s| Path::new(s.etc)).collect();
    surfaces_regressed(
        with_sudo.then(|| Path::new(SUDO)),
        with_polkit.then(|| (Path::new(POLKIT.etc), POLKIT.vendor.map(Path::new))),
        &fp,
    )
}

/// Testable core of [`wired_surface_regressed`], taking the paths so a temp
/// directory can drive it. `sudo`/`polkit` are `None` when the marker says we
/// never wired them.
fn surfaces_regressed(
    sudo: Option<&Path>,
    polkit: Option<(&Path, Option<&Path>)>,
    fp_services: &[&Path],
) -> bool {
    if sudo.is_some_and(path_regressed) {
        return true;
    }
    // polkit is materialized from a vendor copy on Fedora, so a DELETED /etc
    // override is a regression there exactly as it is for the lock screen.
    // A STALE stanza shape counts as regressed too: an older irlume wired
    // polkit with a plain `sufficient` line, under which a head shake's
    // PAM_ABORT is `default=ignore`d and the decline does nothing, while the
    // line still contains the module so the presence test alone said "not
    // regressed" and every packaging lane's post-upgrade `login reconcile`
    // no-opped. Treating the old shape as a regression is what makes the
    // upgrade migrate it automatically (wire_service strips first, then
    // rewires with the abort=die control).
    if polkit.is_some_and(|(etc, vendor)| lock_regressed(etc, vendor) || polkit_stanza_stale(etc)) {
        return true;
    }
    // The fingerprint-keyring line rides on a service the display manager owns;
    // we only ever add to a file that already exists, so a missing file is not a
    // regression, only a stripped one.
    fp_services.iter().copied().any(path_regressed)
}

/// Whether the self-heal marker says login WAS wired but the wiring no longer
/// holds: either the active greeter's stack lost the module (a distro PAM
/// regeneration stripped it) OR the KDE lock screen regressed. Exactly the
/// condition `login reconcile` repairs. The TUI's Repair tab uses this to offer
/// the fix.
pub(crate) fn reconcile_needed() -> bool {
    match read_wired_marker() {
        Some((with_sudo, with_polkit, with_lock)) => {
            !active_login_wired()
                || lockscreen_regressed(with_lock)
                || wired_surface_regressed(with_sudo, with_polkit)
        }
        None => false,
    }
}

pub(crate) fn login_wired() -> bool {
    for s in GREETERS
        .iter()
        .chain(FP_GREETERS.iter())
        .chain(std::iter::once(&LOCKSCREEN))
    {
        if let Some(p) = service_present(s) {
            if file_has_module(&p) {
                return true;
            }
        }
    }
    false
}

/// polkit-1 wiring state for doctor: `None` when the service file is absent
/// (no polkit on this host), else whether it carries the irlume line.
pub(crate) fn polkit_wired() -> Option<bool> {
    service_present(&POLKIT).map(|p| file_has_module(&p))
}

/// The PAM service name in an /etc/pam.d path (e.g. "/etc/pam.d/gdm-password" →
/// "gdm-password"). Borrows, so a `&'static str` path yields a `&'static str`
/// name the machine output can publish as a stable id.
fn service_name(etc: &str) -> &str {
    etc.rsplit('/').next().unwrap_or(etc)
}

/// The active login manager, from the `display-manager.service` symlink
/// (`gdm`, `gdm3`, `sddm`, `lightdm`, `greetd`, `ly`, …). None on a
/// non-graphical / greeter-less host.
/// Login managers that never create the `display-manager.service` symlink, so
/// the mechanism every other DM is found by does not apply to them.
///
/// `ly` is the case that motivated this. Measured on Arch's `ly` 1.4.1: the unit
/// is TEMPLATED (`ly@.service`, one instance per TTY) and carries no
/// `Alias=display-manager.service`, only `WantedBy=multi-user.target`. Enabling
/// it creates exactly one link, `multi-user.target.wants/ly@tty2.service`, so
/// `read_link` on the usual path fails and irlume reported "no display manager"
/// on a host that plainly has one.
const WANTS_ONLY_DMS: &[&str] = &["ly"];

/// The `.wants` directories an enabled display manager can land in.
const WANTS_DIRS: &[&str] = &[
    "/etc/systemd/system/multi-user.target.wants",
    "/etc/systemd/system/graphical.target.wants",
];

/// A display manager enabled without a `display-manager.service` symlink.
///
/// Deliberately narrow: it matches only names in [`WANTS_ONLY_DMS`], so this
/// cannot start reporting arbitrary enabled units as the login manager. Returns
/// the BASE name (`ly@tty2.service` → `ly`), which is what the PAM service and
/// the rest of the wiring are keyed on.
fn display_manager_from_wants() -> Option<String> {
    for dir in WANTS_DIRS {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".service") else {
                continue;
            };
            // Templated or plain: `ly@tty2` and `ly` both answer `ly`.
            let base = stem.split('@').next().unwrap_or(stem);
            if WANTS_ONLY_DMS.contains(&base) {
                return Some(base.to_string());
            }
        }
    }
    None
}

/// The active login manager's base name.
///
/// The `display-manager.service` symlink first, since that is what every DM that
/// sets one is found by, then the `.wants` fallback for the ones that do not.
/// A TEMPLATE INSTANCE is reduced to its base name (`ly@tty2` → `ly`): systemd
/// writes the instance into the unit name, while PAM services and this file's
/// tables are keyed on the bare name, so leaving the instance attached made a
/// supported DM read as unknown.
fn active_display_manager() -> Option<String> {
    let symlinked = std::fs::read_link("/etc/systemd/system/display-manager.service")
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .map(|stem| stem.split('@').next().unwrap_or(&stem).to_string());
    symlinked.or_else(display_manager_from_wants)
}

/// Minimum GNOME Shell major version that wires GDM with the consent-driven
/// `ondemand` face mode instead of `facefirst`. Hardware-validated on GNOME 50
/// (its gnome-shell greeter/lock submit an empty field to PAM); 46–49 are
/// inferred (same gnome-shell architecture) and degrade gracefully if wrong
/// (face just falls back to the password). Below this, GDM keeps `facefirst`
/// (older gnome-shell blocked the active probe, so ambient scan is the only
/// working face path). Lower as older versions are validated.
const GDM_ONDEMAND_MIN_GNOME: u32 = 46;

/// GNOME Shell major version via `gnome-shell --version` ("GNOME Shell 50.1" →
/// 50). None when gnome-shell is absent/unparseable (→ conservative facefirst).
fn gnome_shell_major() -> Option<u32> {
    let out = std::process::Command::new("gnome-shell")
        .arg("--version")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find_map(|tok| tok.split('.').next().and_then(|n| n.parse::<u32>().ok()))
}

/// Whether GDM should wire the consent-driven `ondemand` mode for this GNOME
/// version. `None` (undetected) → false, so an unknown GDM keeps facefirst.
fn gdm_uses_ondemand(gnome_major: Option<u32>) -> bool {
    gnome_major.is_some_and(|v| v >= GDM_ONDEMAND_MIN_GNOME)
}

/// Per-login-manager face-auth policy: irlume tailors the greeter PAM wiring to
/// the DETECTED login manager's greeter AND locker behaviour, instead of a
/// global one-size-fits-all control. Resolved from a greeter's PAM service path,
/// which identifies the DM. Different DMs answer the password probe and drive
/// their lock screens differently, and those differences we've validated on
/// hardware live here rather than scattered across the wiring code.
struct DmProfile {
    /// Face engages on an empty-field Enter (`ondemand`) vs GDM's
    /// scan-immediately (`facefirst`). For GDM this is gated by GNOME version.
    /// The cold-login-vs-warm-lock control tension (keyring unlock) is handled
    /// uniformly by the module's `kr` arg, so it needs no per-DM field here.
    ondemand: bool,
}

/// Resolve the [`DmProfile`] for a greeter PAM service path. `gnome` is the
/// detected GNOME Shell major (for GDM's version gate).
fn dm_profile(greeter_etc: &str, gnome: Option<u32>) -> DmProfile {
    match greeter_etc.rsplit('/').next().unwrap_or("") {
        // COSMIC (System76 / Pop!_OS): answers the probe on submit → ondemand.
        "cosmic-greeter" => DmProfile { ondemand: true },
        // GDM (GNOME): modern gnome-shell submits the empty field (ondemand);
        // older gnome-shell blocked the probe → facefirst.
        "gdm-password" => DmProfile {
            ondemand: gdm_uses_ondemand(gnome),
        },
        // LightDM (lightdm-gtk-greeter) and SDDM: both validated on Ubuntu 26.04;
        // they answer the active probe on submit and auto-log-in on face
        // success, so `ondemand` gives a clean empty-Enter→face with no spurious
        // "incorrect password" that facefirst caused.
        "lightdm" | "sddm" => DmProfile { ondemand: true },
        // greetd (agreety / tuigreet / sway sessions): a submit-driven greeter that
        // reads a password line then hands it to PAM; same on-demand family as
        // lightdm/sddm. (cosmic-greeter, itself an ondemand greetd greeter, is the
        // System76 case handled above.)
        "greetd" => DmProfile { ondemand: true },
        // plasmalogin (KDE's Plasma Login Manager, an SDDM fork): submit-driven,
        // answers the empty-field probe like sddm → ondemand. Validated live on
        // Fedora 44 KDE (the [success=1] substack layout).
        "plasmalogin" => DmProfile { ondemand: true },
        // other/unknown submit-driven greeters: default to the safe facefirst
        // until each is validated for the on-demand probe.
        _ => DmProfile { ondemand: false },
    }
}

/// Every login manager irlume knows, and the PAM services it consults.
///
/// A table rather than a `match` so a test can walk it: each entry claims irlume
/// understands that login manager, and a claim nothing can wire is exactly the
/// bug this shape prevents. Adding a row here without adding the matching `Svc`
/// fails `a_login_manager_is_recognized_only_when_something_can_wire_it`.
const DM_PAM_SERVICES: &[(&str, &str, Option<&str>)] = &[
    // GDM drives the password/face path and a SEPARATE fingerprint service.
    ("gdm", "gdm-password", Some("gdm-fingerprint")),
    ("gdm3", "gdm-password", Some("gdm-fingerprint")),
    // SDDM / Plasma: one greeter; KDE's fingerprint is the lock screen
    // (kde-fingerprint), wired separately as the lock service.
    ("sddm", "sddm", None),
    // Plasma 6 renamed the SDDM greeter service to `plasmalogin`; the
    // display-manager.service symlink resolves to it. Same shape as SDDM:
    // one greeter, KDE's fingerprint lives on the lock screen (kde-fingerprint).
    ("plasmalogin", "plasmalogin", None),
    ("lightdm", "lightdm", None),
    ("greetd", "greetd", None),
    // ly: a TUI display manager whose `/etc/pam.d/ly` is `auth include login`,
    // so irlume's line goes in that file like any other greeter. Found via
    // `display_manager_from_wants`, since ly sets no display-manager.service.
    ("ly", "ly", None),
    // COSMIC (System76 / Pop!_OS): cosmic-greeter drives BOTH the cold login
    // and the live lock screen through the SAME `cosmic-greeter` PAM service;
    // the SessionState in biopolicy::classify distinguishes them. No
    // separate fingerprint service.
    ("cosmic-greeter", "cosmic-greeter", None),
];

/// Login managers MEASURED not to show the user a `PAM_TEXT_INFO` message.
///
/// `pam_irlume` sends the consent-gesture instruction as `PAM_TEXT_INFO` before
/// the capture, because a greeter that just says "Password:" gives the user no
/// way to know a gesture is required. A login manager that drops that message
/// leaves the requirement undiscoverable: the user is asked for a gesture nobody
/// told them about, the watch window expires, and the keyring falls back to the
/// typed password with no explanation.
///
/// Only entries VERIFIED to drop it belong here. An empty warning is better than
/// a wrong one, so a login manager nobody has checked stays absent and produces
/// no warning at all; this is not a list of everything that might be broken.
///
/// `plasmalogin` (Plasma Login Manager 6.7.3): the helper forwards the message
/// and `GreeterProxy` emits `informationMessage`, but the greeter QML connects no
/// handler to that signal, so it is dropped before presentation. Confirmed on
/// hardware 2026-07-27 across two greeter logins that showed nothing, while the
/// same code path renders on the KDE lock screen, which is a different codebase.
const DM_HIDES_PAM_TEXT_INFO: &[&str] = &["plasmalogin"];

/// The active login manager, when it is one known to drop `PAM_TEXT_INFO`.
///
/// `None` covers both "no display manager" and "not known to drop it", because
/// doctor treats them the same: it warns only on a positive finding.
pub(crate) fn active_dm_hides_pam_instructions() -> Option<String> {
    let dm = active_display_manager()?;
    DM_HIDES_PAM_TEXT_INFO
        .iter()
        .any(|known| *known == dm)
        .then_some(dm)
}

/// The PAM services THIS login manager actually uses, so wiring targets what the
/// DM will really consult (and, above all, its separate FINGERPRINT service).
/// Returns `(greeter_label, fingerprint_label_or_none)`.
fn dm_pam_services(dm: &str) -> (&'static str, Option<&'static str>) {
    DM_PAM_SERVICES
        .iter()
        .find(|(name, _, _)| *name == dm)
        .map_or(("(unknown)", None), |(_, greeter, fp)| (greeter, *fp))
}

/// Whether `login enable` can actually wire this PAM service, i.e. whether one
/// of the `Svc` tables names it. Having a NAME for a service is not the same as
/// having a recipe for it: `dm_pam_services` maps `ly` to a `ly` service that no
/// `Svc` covers, so the wiring loop never touches it.
fn service_wirable(service: &str) -> bool {
    GREETERS
        .iter()
        .chain(FP_GREETERS.iter())
        .any(|s| service_name(s.etc) == service)
}

/// Whether irlume can wire face login for this login manager: it maps to a PAM
/// service, and that service is one the wiring loop writes.
fn dm_wirable(dm: &str) -> bool {
    let (greeter, _) = dm_pam_services(dm);
    greeter != "(unknown)" && service_wirable(greeter)
}

/// The active display manager and whether irlume can wire face login for it.
/// `None` when no display-manager.service is set (headless / a non-DM greeter).
///
/// Doctor uses the `false` case to warn. Two different machines land there: a
/// brand-new or renamed DM that has no `dm_pam_services` entry, and one that has
/// an entry naming a service no `Svc` covers. Both end the same way, with
/// `login enable` unable to target it and face login silently staying on the
/// password, so both must warn. Reporting only the first is how `ly` came to be
/// called supported while nothing could wire it. This is the proactive
/// counterpart to the biopolicy `Unknown` deny: catch it at `doctor` time
/// instead of at a failed unlock.
pub(crate) fn active_dm_recognized() -> Option<(String, bool)> {
    let dm = active_display_manager()?;
    let recognized = dm_wirable(&dm);
    Some((dm, recognized))
}

/// SELinux module load state for the TUI (None = can't tell without root).
pub(crate) fn selinux_state() -> Option<bool> {
    selinux_loaded()
}

/// True when the fingerprint keyring-unlock (`keyring`) line is present in EVERY
/// login service the active login manager consults that exists: for GDM that is
/// BOTH gdm-password AND gdm-fingerprint (the session opens via gdm-password even
/// on a fingerprint login), for KDE/others the single greeter. Used by the TUI
/// Repair tab to tell "fully wired" from "partially/not wired". Returns false if
/// no relevant service exists (nothing to unlock).
pub(crate) fn fp_keyring_wired() -> bool {
    let has_keyring = |path: &str| -> Option<bool> {
        std::fs::read_to_string(path).ok().map(|s| {
            s.lines().any(|l| {
                // The DIRECTIVE part, like every other PAM read here: a
                // trailing comment mentioning the module is not wiring, and
                // this check matching what libpam ignores is how the Repair
                // tab reports "fully wired" about a stack that is not.
                let d = directive(l);
                d.contains("pam_irlume.so") && d.contains("keyring")
            })
        })
    };
    let mut services: Vec<String> = Vec::new();
    if let Some(dm) = active_display_manager() {
        let (greeter, fp) = dm_pam_services(&dm);
        services.push(format!("/etc/pam.d/{greeter}"));
        if let Some(fp) = fp {
            services.push(format!("/etc/pam.d/{fp}"));
        }
    }
    if services.is_empty() {
        for g in ["gdm-password", "sddm", "plasmalogin", "lightdm"] {
            services.push(format!("/etc/pam.d/{g}"));
        }
    }
    let present: Vec<bool> = services.iter().filter_map(|p| has_keyring(p)).collect();
    !present.is_empty() && present.iter().all(|&b| b)
}

// ---- Wiring facts (shared by the human report and `login status --json`) -----

/// What a PAM surface is for. These strings are published by
/// `login status --json`, so they are public API: a role may be added, never
/// renamed and never repurposed.
const ROLE_LOGIN: &str = "login-screen";
const ROLE_LOGIN_FP: &str = "login-screen-fingerprint";
const ROLE_LOCK: &str = "lock-screen";
const ROLE_SUDO: &str = "sudo";
const ROLE_POLKIT: &str = "polkit";

/// Which factors this machine's hardware and configured method call for.
///
/// Extracted so the human `login enable` report and the machine plan derive
/// their intent from one place. Two copies of this rule drifting apart would
/// have the plan promise one thing and the apply do another.
pub(crate) struct Wants {
    /// Face releases the login credential only on the Secure (IR) tier.
    pub(crate) face_login: bool,
    /// Face verifies the lock screen on any camera.
    pub(crate) face_lock: bool,
    /// Fingerprint drives the keyring unlock.
    pub(crate) fp_keyring: bool,
}

/// `Auto` follows the hardware; an explicit method overrides it.
pub(crate) fn wants() -> Wants {
    let caps = crate::caps();
    let method = irlume_core::policy::method();
    let is_fp_method = method.face_disabled(); // Method::Fingerprint
    let is_face_method = matches!(method, irlume_core::policy::Method::Face);
    Wants {
        face_login: caps.ir_pair && !is_fp_method,
        face_lock: caps.rgb && !is_fp_method,
        fp_keyring: irlume_fingerprint::available() && !is_face_method,
    }
}

/// One surface's planned change, for machine output.
pub(crate) struct PlannedSurface {
    pub(crate) id: &'static str,
    pub(crate) role: &'static str,
    pub(crate) change: PlannedChange,
    /// Digest of the file this decision was made against, or `ABSENT`.
    ///
    /// The outcome NAME is not enough to identify what was planned. An admin can
    /// rewrite a stack and leave a valid anchor in place: the outcome stays
    /// `wire`, so a plan id built from names alone is unchanged, and an apply
    /// carrying that id would overwrite a stack the consumer was never shown.
    /// The digest is what makes the id describe a state rather than an intent.
    pub(crate) state: String,
}

/// What `login enable`/`login disable` would change, computed without writing.
///
/// This runs the identical decision the apply path runs, with `apply` false, so
/// the plan cannot describe an outcome the apply would not produce. It reads
/// PAM files and needs no privilege; only applying does.
/// Called once per surface: the service, its role, the wiring recipe for it,
/// and whether this configuration wants it wired.
type SurfaceVisitor<'a> = dyn FnMut(&Svc, &'static str, &dyn Fn(&str) -> (String, bool), bool) + 'a;

/// Walk every surface an enable/disable would touch, calling `visit` for each.
///
/// One list, walked by both `plan` and `apply`. Deciding which surfaces are in
/// scope, and with which wiring recipe, is the part that must not exist twice:
/// a plan that walked a different set than the apply would describe changes
/// that never happen, or miss ones that do.
fn walk_surfaces(enable: bool, with_sudo: bool, with_polkit: bool, visit: &mut SurfaceVisitor<'_>) {
    let Wants {
        face_login,
        face_lock,
        fp_keyring,
    } = wants();
    let gnome = gnome_shell_major();
    for s in GREETERS {
        let prof = dm_profile(s.etc, gnome);
        let unified_login_lock =
            s.etc.ends_with("/cosmic-greeter") || s.etc.ends_with("/gdm-password");
        let face = face_login || (unified_login_lock && face_lock);
        let greeter_wire = |c: &str| wire_greeter_impl(c, face, fp_keyring, prof.ondemand);
        visit(s, ROLE_LOGIN, &greeter_wire, face || fp_keyring);
    }
    for s in FP_GREETERS {
        let fp_wire = |c: &str| wire_fp_keyring(c, service_name(s.etc));
        visit(s, ROLE_LOGIN_FP, &fp_wire, fp_keyring);
    }
    visit(&LOCKSCREEN, ROLE_LOCK, &wire_lock, face_lock);
    if sudo_in_scope(enable, with_sudo) {
        visit(
            &Svc {
                etc: SUDO,
                vendor: None,
            },
            ROLE_SUDO,
            &wire_verify_service,
            true,
        );
    }
    if polkit_in_scope(enable, with_polkit) {
        visit(&POLKIT, ROLE_POLKIT, &wire_polkit_service, true);
    }
}

pub(crate) fn plan(enable: bool, with_sudo: bool, with_polkit: bool) -> Vec<PlannedSurface> {
    let mut out = Vec::new();
    walk_surfaces(
        enable,
        with_sudo,
        with_polkit,
        &mut |svc, role, wire, want| {
            // A service whose decision cannot even be computed (an unreadable file)
            // is reported as not-installed rather than omitted: a surface silently
            // missing from a plan is how a consumer comes to believe it was covered.
            let change = wire_service(svc, enable && want, false, wire)
                .map(|outcome| outcome.change)
                .unwrap_or(PlannedChange::NotInstalled);
            out.push(PlannedSurface {
                id: service_name(svc.etc),
                role,
                change,
                state: surface_state(Path::new(svc.etc)),
            });
        },
    );
    out
}

/// One surface after an apply, with what it took to undo it.
pub(crate) struct AppliedSurface {
    pub(crate) id: &'static str,
    pub(crate) role: &'static str,
    /// The `/etc` path. Needed to restore; never published in machine output.
    pub(crate) path: String,
    pub(crate) change: PlannedChange,
    /// Content before the change; `None` when the file did not exist, so a
    /// rollback removes it rather than writing an empty file.
    pub(crate) before: Option<String>,
    /// Mode, uid and gid before the change. Content alone does not describe a
    /// file, and these cannot be recovered later once it has been rewritten.
    pub(crate) before_metadata: Option<(u32, u32, u32)>,
    /// The `.pre-irlume` backup as it stood before the change, since wiring
    /// creates one and unwiring consumes one.
    pub(crate) sidecar_before: Option<String>,
    pub(crate) sidecar_metadata: Option<(u32, u32, u32)>,
    /// Whether the backup existed at all beforehand. Distinguishes "was absent,
    /// remove it on rollback" from "was present and empty".
    pub(crate) sidecar_existed: bool,
    pub(crate) after_sha256: String,
    /// The backup's digest as apply left it, so a rollback can tell whether the
    /// backup it is about to overwrite is still the one it created.
    pub(crate) sidecar_after_sha256: Option<String>,
    /// Set when this surface failed. The apply as a whole is reported as failed,
    /// and the surfaces that DID change are still recorded, so a rollback can
    /// undo a partial run.
    pub(crate) error: Option<String>,
}

/// Read every surface's pre-change state, writing nothing.
///
/// Exists so a record can be persisted BEFORE the first PAM write. Without that
/// ordering, a crash or a full disk between the writes and the record leaves a
/// changed login stack with nothing describing how to undo it, which is worse
/// than not having run at all.
pub(crate) fn prepare(enable: bool, with_sudo: bool, with_polkit: bool) -> Vec<AppliedSurface> {
    let mut out = Vec::new();
    walk_surfaces(
        enable,
        with_sudo,
        with_polkit,
        &mut |svc, role, wire, want| {
            let path = Path::new(svc.etc);
            let before_metadata = crate::logintx::file_metadata(path);
            // Wiring creates this and unwiring renames it away, so it is part of
            // what the transaction changed.
            let sidecar_path = PathBuf::from(format!("{}{BACKUP}", svc.etc));
            let sidecar_before = std::fs::read_to_string(&sidecar_path).ok();
            let sidecar_metadata = crate::logintx::file_metadata(&sidecar_path);
            let sidecar_existed = sidecar_path.exists();
            let (before, error) = match std::fs::read_to_string(path) {
                Ok(content) => (Some(content), None),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, None),
                Err(error) => (
                    None,
                    Some(format!(
                        "read {} before changing it: {error}",
                        path.display()
                    )),
                ),
            };
            // The outcome this surface is expected to reach, so a record written
            // now already says what was intended. Computed with writing off.
            let change = wire_service(svc, enable && want, false, wire)
                .map(|outcome| outcome.change)
                .unwrap_or(PlannedChange::NotInstalled);
            out.push(AppliedSurface {
                id: service_name(svc.etc),
                role,
                path: svc.etc.to_string(),
                change,
                before,
                before_metadata,
                sidecar_before,
                sidecar_metadata,
                sidecar_existed,
                // Not written yet, so there is no after-state. A record in this
                // condition is recognisable by its `prepared` status.
                after_sha256: crate::logintx::ABSENT.to_string(),
                sidecar_after_sha256: None,
                error,
            });
        },
    );
    out
}

/// Carry out an enable/disable, recording what each surface looked like first.
///
/// The before-content is read BEFORE `wire_service` runs, because that is the
/// only moment it exists to be read; afterwards the file has already changed.
/// Every surface is recorded even when a later one fails, since a partial apply
/// is exactly the case a rollback has to be able to undo.
/// The record for a surface irlume REFUSED to touch (a symlink, or a file with
/// more than one name).
///
/// It reports what is on disk, not "absent". The rollback precheck compares each
/// recorded after-digest against the live file, so claiming absence about a file
/// that exists made the whole transaction read as drift and refuse to roll back,
/// which is exactly when a partly applied enable needs undoing. `before: None`
/// also means "remove it" to a restore, the opposite of leaving it alone.
fn refused_surface_record(
    svc: &Svc,
    role: &'static str,
    path: &Path,
    message: String,
) -> AppliedSurface {
    let current = std::fs::read_to_string(path).ok();
    let current_meta = std::fs::symlink_metadata(path).ok().as_ref().map(|m| {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        (m.permissions().mode() & 0o7777, m.uid(), m.gid())
    });
    AppliedSurface {
        id: service_name(svc.etc),
        role,
        path: svc.etc.to_string(),
        change: PlannedChange::NotInstalled,
        before: current,
        before_metadata: current_meta,
        sidecar_before: None,
        sidecar_metadata: None,
        sidecar_existed: false,
        // The digest shape the applied path records and the precheck compares:
        // the live file alone, not the live+backup pair `surface_state` makes.
        after_sha256: match std::fs::read(path) {
            Ok(bytes) => crate::logintx::sha256_hex(&bytes),
            Err(_) => crate::logintx::ABSENT.to_string(),
        },
        sidecar_after_sha256: None,
        error: Some(message),
    }
}

pub(crate) fn apply(
    enable: bool,
    with_sudo: bool,
    with_polkit: bool,
    expected: &[PlannedSurface],
) -> Vec<AppliedSurface> {
    let mut out = Vec::new();
    walk_surfaces(
        enable,
        with_sudo,
        with_polkit,
        &mut |svc, role, wire, want| {
            let path = Path::new(svc.etc);
            // Re-check the state THIS surface was planned against, immediately
            // before writing it. Comparing plan ids once up front leaves a
            // window: `plan` and `apply` are separate filesystem walks, so a
            // change landing between them is never compared to anything. Doing
            // it per surface narrows that window to the gap between this check
            // and this write, which is as tight as it gets without holding a
            // lock nothing else in the system takes.
            // A symlinked surface is refused rather than written. write_atomic
            // renames over the path, which REPLACES the link with a regular
            // file, and a rollback restores content rather than the link, so the
            // conversion is silent and permanent. Writing through the link
            // instead is no better: on Fedora these point into /etc/authselect
            // and on Debian into /etc/alternatives, both shared targets that
            // other tooling owns. Neither choice is irlume's to make quietly.
            // Asked here as well as inside the write, so the refusal reaches the
            // consumer as a per-surface state with a reason rather than as one
            // failed operation. `inspect_target` also covers hard links, which
            // this check did not: a rename replaces one directory entry and
            // leaves every other name for the inode on the old content.
            if let Err(message) = inspect_target(path) {
                out.push(refused_surface_record(svc, role, path, message));
                return;
            }
            let planned_state = expected
                .iter()
                .find(|candidate| candidate.id == service_name(svc.etc))
                .map(|candidate| candidate.state.as_str());
            let now = surface_state(path);
            if let Some(planned_state) = planned_state {
                if planned_state != now {
                    out.push(AppliedSurface {
                        id: service_name(svc.etc),
                        role,
                        path: svc.etc.to_string(),
                        change: PlannedChange::NotInstalled,
                        before: None,
                        before_metadata: None,
                        sidecar_before: None,
                        sidecar_metadata: None,
                        sidecar_existed: false,
                        after_sha256: crate::logintx::ABSENT.to_string(),
                        sidecar_after_sha256: None,
                        error: Some(format!(
                            "{} changed between the plan and the write; not touched",
                            svc.etc
                        )),
                    });
                    return;
                }
            }
            // A file that exists but cannot be read is NOT the same as an
            // absent one. Collapsing the two with `.ok()` would record
            // `before: None`, and a later rollback would then DELETE a file it
            // never captured. Only a genuine NotFound may become None.
            let before_metadata = crate::logintx::file_metadata(path);
            // Wiring creates this and unwiring renames it away, so it is part of
            // what the transaction changed.
            let sidecar_path = PathBuf::from(format!("{}{BACKUP}", svc.etc));
            let sidecar_before = std::fs::read_to_string(&sidecar_path).ok();
            let sidecar_metadata = crate::logintx::file_metadata(&sidecar_path);
            let sidecar_existed = sidecar_path.exists();
            let (before, mut read_error) = match std::fs::read_to_string(path) {
                Ok(content) => (Some(content), None),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, None),
                Err(error) => (
                    None,
                    Some(format!(
                        "read {} before changing it: {error}",
                        path.display()
                    )),
                ),
            };
            if let Some(message) = read_error {
                // Not touched at all: without a usable before-state there is
                // nothing to roll back to, so writing would be irreversible.
                out.push(AppliedSurface {
                    id: service_name(svc.etc),
                    role,
                    path: svc.etc.to_string(),
                    change: PlannedChange::NotInstalled,
                    before: None,
                    before_metadata: None,
                    sidecar_before: None,
                    sidecar_metadata: None,
                    sidecar_existed: false,
                    after_sha256: crate::logintx::ABSENT.to_string(),
                    sidecar_after_sha256: None,
                    error: Some(message),
                });
                return;
            }
            let (change, error) = match wire_service(svc, enable && want, true, wire) {
                Ok(outcome) => (outcome.change, None),
                Err(message) => (PlannedChange::NotInstalled, Some(message)),
            };
            // Same rule after the write: only a real NotFound is ABSENT. An
            // unreadable file would otherwise record a digest
            // `unchanged_since_apply` can never match, so rollback would report
            // drift forever instead of the read problem it actually has.
            let after_sha256 = match std::fs::read(path) {
                Ok(bytes) => crate::logintx::sha256_hex(&bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    crate::logintx::ABSENT.to_string()
                }
                Err(error) => {
                    read_error = Some(format!(
                        "read {} after changing it: {error}",
                        path.display()
                    ));
                    crate::logintx::ABSENT.to_string()
                }
            };
            let error = error.or(read_error);
            // The same question for the backup: what did apply leave there. A
            // rollback that overwrites a backup somebody replaced afterwards is
            // the same defect as one that overwrites a stack, and the backup is
            // the origin a later enable rebuilds from.
            let sidecar_after_sha256 = Some(surface_digest(&sidecar_path));
            out.push(AppliedSurface {
                id: service_name(svc.etc),
                role,
                path: svc.etc.to_string(),
                change,
                before,
                before_metadata,
                sidecar_before,
                sidecar_metadata,
                sidecar_existed,
                after_sha256,
                sidecar_after_sha256,
                error,
            });
        },
    );
    out
}

fn act(enable: bool, apply: bool, with_sudo: bool, with_polkit: bool) -> ExitCode {
    if apply && effective_uid() != 0 {
        eprintln!(
            "[login] applying changes needs root; run: sudo irlume login {} --apply",
            if enable { "enable" } else { "disable" }
        );
        return ExitCode::FAILURE;
    }
    // Held for the whole run, so a machine transaction or the reconcile unit
    // cannot be writing the same stacks at the same time. A dry run changes
    // nothing and does not take it.
    let _lock = if apply {
        match lock_pam() {
            Ok(lock) => Some(lock),
            Err(message) => {
                eprintln!("[login] cannot serialise this change: {message}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };
    act_holding_lock(enable, apply, with_sudo, with_polkit)
}

/// The body of [`act`], for a caller that ALREADY holds the PAM lock.
///
/// `flock` is per open file description, so a second `lock_pam()` from the same
/// process blocks on the first one forever. `reconcile` took the lock, found a
/// regression, and called `act`, which took it again: the self-heal deadlocked
/// on exactly the condition it exists to repair, so it had never once worked.
/// The hung process is root and holds the lock exclusively, so every other
/// irlume PAM operation blocked behind it too, and the unit's `Type=oneshot`
/// default of `TimeoutStartUSec=infinity` meant systemd never killed it.
/// Whether a wiring run may proceed on this capability reading.
///
/// Pure, so both directions are tested without a daemon. See the comment at
/// the call site for why an unestablished reading must stop an ENABLE.
fn enable_permitted(enable: bool, caps_established: bool) -> Result<(), &'static str> {
    if enable && !caps_established {
        return Err(
            "[login] refusing: this machine's camera capabilities could not be \
             established (the daemon did not answer and the failure does not \
             prove it is absent), and enabling UNWIRES the surfaces that read \
             as unsupported. Nothing was changed.",
        );
    }
    Ok(())
}

fn act_holding_lock(enable: bool, apply: bool, with_sudo: bool, with_polkit: bool) -> ExitCode {
    if !apply {
        println!("[login] DRY RUN: showing what `--apply` would change (nothing is written):");
    }
    // An enable UNWIRES what the hardware does not support, so it must not run
    // on a capability answer nothing established. `caps()` falls back to
    // `{ir_pair: false, rgb: false}` when the daemon cannot be reached and the
    // failure does not prove it absent, which on a packaged install is the
    // ORDINARY shape of a dead daemon: socket activation keeps the socket
    // present, so the request times out rather than being refused. Acting on
    // that guess removed the face line from every greeter and the lock screen
    // and reported success, and the Repair row offering the fix sits on the
    // screen the TUI drops you on when the daemon is down. A disable is the
    // user asking for exactly that removal, so it needs no capabilities.
    if let Err(why) = enable_permitted(enable, crate::caps_established()) {
        eprintln!("{why}");
        eprintln!(
            "        start the daemon and retry: sudo systemctl start irlumed   \
             (or, if it will not start, `irlume doctor` says why)"
        );
        return ExitCode::FAILURE;
    }
    // Method + tier aware plan: wire exactly what the chosen method needs on
    // this hardware, and (on enable) UNWIRE what it doesn't, so switching method
    // re-configures cleanly instead of leaving stale lines. `want_*` gate each
    // factor; on disable everything is unwired.
    let caps = crate::caps();
    let method = irlume_core::policy::method();
    let Wants {
        face_login: want_face_login,
        face_lock: want_face_lock,
        fp_keyring: want_fp_keyring,
    } = wants();
    if enable {
        match active_display_manager() {
            Some(dm) => println!(
                "  login manager: {dm}   ·   method: {}   ·   {}",
                method.as_str(),
                if caps.ir_pair {
                    "IR/Secure tier"
                } else if caps.rgb {
                    "RGB/Convenience tier"
                } else {
                    "no camera"
                }
            ),
            None => println!(
                "  no active login manager (headless?)   ·   method: {}",
                method.as_str()
            ),
        }
        let onoff = |b: bool| if b { "on" } else { "off" };
        println!(
            "  plan → face login: {}   face lock: {}   fingerprint keyring: {}",
            onoff(want_face_login),
            onoff(want_face_lock),
            onoff(want_fp_keyring)
        );
        if caps.rgb && !caps.ir_pair && want_face_lock {
            println!(
                "  (RGB-only: face satisfies the LOCK SCREEN only; login/sudo keep the password)"
            );
        }
        // Tell the user HOW face will fire at their greeter; on-demand (the
        // consent model) is not discoverable from the greeter UI itself.
        if want_face_login {
            if let Some(dm) = active_display_manager() {
                let (greeter, _) = dm_pam_services(&dm);
                println!(
                    "  face trigger: {}",
                    if dm_profile(&format!("/etc/pam.d/{greeter}"), gnome_shell_major()).ondemand {
                        format!("on-demand; {ONDEMAND_HINT}")
                    } else {
                        "face-first; the camera verifies as soon as your account is selected"
                            .to_string()
                    }
                );
            }
        }
    }
    let mut errs = 0;
    let mut do_svc = |s: &Svc, wire: &dyn Fn(&str) -> (String, bool), want: bool| {
        // On enable, wire wanted factors and unwire unwanted ones; on disable,
        // unwire everything (want is ANDed with `enable`).
        match wire_service(s, enable && want, apply, wire) {
            Ok(msg) => println!("  {msg}"),
            Err(e) => {
                eprintln!("  ✗ {e}");
                errs += 1;
            }
        }
    };
    // Greeters (gdm-password etc.) carry the FACE lines (only Secure-tier face
    // login) AND the KEYRING line (fingerprint keyring unlock); independent, so
    // an RGB+fingerprint box gets keyring-only here, while GDM's session keyring
    // unlock (which runs through gdm-password) still finds the password.
    let gnome = gnome_shell_major();
    for s in GREETERS {
        // DM-aware: apply the wiring this login manager's greeter + locker want.
        let prof = dm_profile(s.etc, gnome);
        // cosmic-greeter and gdm-password each drive BOTH the cold login and the
        // live lock screen through ONE service, so they carry the face line
        // whenever face login OR face lock is wanted; an RGB (convenience) box
        // still gets face LOCK there (a cold login on that tier stays denied by
        // the daemon's credential-release gate).
        let unified_login_lock =
            s.etc.ends_with("/cosmic-greeter") || s.etc.ends_with("/gdm-password");
        let face = want_face_login || (unified_login_lock && want_face_lock);
        let greeter_wire = |c: &str| wire_greeter_impl(c, face, want_fp_keyring, prof.ondemand);
        do_svc(s, &greeter_wire, face || want_fp_keyring);
    }
    for s in FP_GREETERS {
        let fp_wire = |c: &str| wire_fp_keyring(c, service_name(s.etc));
        do_svc(s, &fp_wire, want_fp_keyring);
    }
    // A separate lock service (KDE `kde`) is a WARM screen unlock: the module
    // short-circuits (no `kr`), so the keyring (already open) isn't re-touched.
    do_svc(&LOCKSCREEN, &wire_lock, want_face_lock);
    if sudo_in_scope(enable, with_sudo) {
        match wire_service(
            &Svc {
                etc: SUDO,
                vendor: None,
            },
            enable,
            apply,
            &wire_verify_service,
        ) {
            Ok(msg) => println!("  {msg}"),
            Err(e) => {
                eprintln!("  ✗ {e}");
                errs += 1;
            }
        }
    }
    if polkit_in_scope(enable, with_polkit) {
        match wire_service(&POLKIT, enable, apply, &wire_polkit_service) {
            Ok(msg) => {
                println!("  {msg}");
                if enable && apply {
                    // The nod is the default gesture and needs NO calibration;
                    // `calibrate-closure` teaches the optional eye-closure
                    // alternative. This line used to present the calibration as a
                    // prerequisite and the closure as the way to approve, which
                    // sent every new polkit user through a step they did not need.
                    println!(
                        "    polkit prompts (Bitwarden unlock, pkexec) now take your face.\n    \
                         Keep nodding to approve; shake your head to decline.\n    \
                         No calibration needed. Optional eye-closure alternative:  sudo irlume calibrate-closure"
                    );
                }
            }
            Err(e) => {
                eprintln!("  ✗ {e}");
                errs += 1;
            }
        }
    }
    // SELinux (Fedora): the confined GDM/greeter needs the policy to reach the socket.
    if matches!(distro_family(), DistroFamily::Fedora) {
        match selinux(enable, apply) {
            Ok(msg) => println!("  {msg}"),
            Err(e) => {
                eprintln!("  ✗ {e}");
                errs += 1;
            }
        }
    }
    if !apply {
        println!("[login] re-run with --apply (as root) to perform these changes.");
    } else if errs == 0 {
        // Record the wiring intent so `irlume login reconcile` can re-apply it
        // after a distro update rewrites a greeter's PAM file out from under us
        // (authselect, pam-auth-update, or a package upgrade shipping a fresh
        // vendor copy). On disable we clear the marker so reconcile stays quiet.
        // Record what is WIRED, not what this invocation asked for. The scopes are
        // opt-in and independent: `login enable --with-polkit --apply` followed by
        // `login enable --with-sudo --apply` leaves polkit's stack wired (the
        // second run does not touch it, `polkit_in_scope` is false without the
        // flag) while the marker from that run said `with_polkit=false`. Reconcile
        // reads the marker, so the surface silently dropped out of the self-heal
        // and a later distro PAM rewrite would strip irlume from it for good.
        // Observed the same way `reconcile`'s adopt path already does it.
        if enable {
            let obs_sudo = Path::new(SUDO).exists() && file_has_module(Path::new(SUDO));
            let obs_polkit = polkit_wired() == Some(true);
            let obs_lock = lock_wired();
            write_wired_marker(enable, obs_sudo, obs_polkit, obs_lock);
        } else {
            write_wired_marker(enable, with_sudo, with_polkit, want_face_lock);
        }
        // Say it at the moment the user wired it, not only when they next run
        // `login status`: a wallet that still prompts after `enable --apply`
        // otherwise reads as irlume having failed.
        if enable {
            report_keyring_handoff();
        }
        println!("[login] done. Password remains the fallback everywhere.");
    }
    if errs == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Whether this invocation touches the sudo stack. face-sudo is opt-in on
/// enable (--with-sudo), but disable must ALWAYS unwire it: "disable --apply
/// undoes everything" is a documented promise, and a stale sudo line would
/// point at a module the user may remove next. Kept as a named seam (not
/// inline in `act`) so the promise stays unit-testable.
fn sudo_in_scope(enable: bool, with_sudo: bool) -> bool {
    with_sudo || !enable
}

/// Same promise for the polkit stack: opt-in on enable (`--with-polkit`),
/// always unwired on disable.
fn polkit_in_scope(enable: bool, with_polkit: bool) -> bool {
    with_polkit || !enable
}

/// Wire (or unwire) one service, choosing override-materialize vs edit-in-place.
/// What wiring a service would do, decided before anything is written.
///
/// Named outcomes rather than a rendered sentence, so the human report, the
/// machine plan and the decision that actually writes all come from one pass.
/// The alternative is a second implementation of the same rules for machine
/// callers, and two copies of this logic disagreeing is how a PAM stack ends up
/// in a state nobody chose.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PlannedChange {
    /// Create an irlume-owned /etc override from the vendor copy.
    MaterializeOverride,
    /// Write irlume lines into the admin's file, taking a backup first.
    Wire,
    /// Remove the irlume-owned override, restoring the vendor copy.
    RemoveOverride,
    /// Rename the backup back over the live file.
    RestoreBackup,
    /// Strip irlume lines in place, preserving edits made since wiring.
    StripInPlace,
    /// The file is already exactly as wiring would leave it.
    AlreadyCorrect,
    /// This service is not installed on this machine.
    NotInstalled,
    /// The file has no anchor line to wire against.
    NoAnchor,
    /// Not wired, and unwiring was asked for.
    NotWired,
}

impl PlannedChange {
    /// Whether applying this outcome would write to disk. The plan reports it
    /// so a consumer can say "3 files change" without interpreting outcome
    /// names it may not know.
    pub(crate) fn writes(self) -> bool {
        matches!(
            self,
            Self::MaterializeOverride
                | Self::Wire
                | Self::RemoveOverride
                | Self::RestoreBackup
                | Self::StripInPlace
        )
    }

    /// A stable identifier for machine output. Kebab-case, never derived from
    /// the human sentence.
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::MaterializeOverride => "materialize-override",
            Self::Wire => "wire",
            Self::RemoveOverride => "remove-override",
            Self::RestoreBackup => "restore-backup",
            Self::StripInPlace => "strip-in-place",
            Self::AlreadyCorrect => "already-correct",
            Self::NotInstalled => "not-installed",
            Self::NoAnchor => "no-anchor",
            Self::NotWired => "not-wired",
        }
    }
}

/// The decision plus the sentence the human report prints for it.
pub(crate) struct WireOutcome {
    pub(crate) change: PlannedChange,
    pub(crate) message: String,
}

impl std::fmt::Display for WireOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn wire_service(
    s: &Svc,
    enable: bool,
    apply: bool,
    wire: &dyn Fn(&str) -> (String, bool),
) -> Result<WireOutcome, String> {
    let out = |change: PlannedChange, message: String| Ok(WireOutcome { change, message });
    let etc = Path::new(s.etc);
    // vendor-only service with no admin /etc copy → override strategy.
    let use_override = s.vendor.is_some() && (!etc.exists() || file_is_created_override(etc));
    if enable {
        // RECONCILE, don't skip-if-present: re-wire always rebuilds the desired
        // line set from the ORIGINAL stack (the vendor copy / the backup) so a
        // method switch (which changes which lines are wanted) actually takes
        // effect instead of being a silent no-op when any pam_irlume line exists.
        if use_override {
            let vendor = s.vendor.unwrap();
            if !Path::new(vendor).exists() {
                return out(
                    PlannedChange::NotInstalled,
                    format!("· {}: not installed (skipped)", s.etc),
                );
            }
            let (base, _) = unwire_lines(&read(vendor)?);
            let (wired, changed) = wire(&base);
            // The transform saying "unchanged" means it REFUSED (no anchor, a
            // continued file): materializing anyway would shadow the vendor
            // file with a copy carrying no irlume line and report ✓ while face
            // login stayed off. The in-place branch below already refuses on
            // this; the override branch must too.
            if !changed {
                return out(
                    PlannedChange::NoAnchor,
                    format!("· {}: no anchor to wire (skipped)", s.etc),
                );
            }
            let body = format!(
                "{CREATED_PREFIX}{vendor}; delete this file to restore the vendor copy\n{wired}"
            );
            if etc.exists() && read(s.etc).ok().as_deref() == Some(body.as_str()) {
                return out(
                    PlannedChange::AlreadyCorrect,
                    format!("· {}: already correctly wired", s.etc),
                );
            }
            if apply {
                write_atomic(etc, &body)?;
            }
            out(
                PlannedChange::MaterializeOverride,
                format!("✓ {}: materialized override from {vendor}", s.etc),
            )
        } else {
            if !etc.exists() {
                return out(
                    PlannedChange::NotInstalled,
                    format!("· {}: not installed (skipped)", s.etc),
                );
            }
            let current = read(s.etc)?;
            // Rebuild from the CURRENT file with irlume's own lines stripped,
            // not from the backup.
            //
            // Taking the backup as origin discarded every change made to the
            // stack after irlume first wired it. A distro update that adds
            // `pam_faillock` lines is the ordinary case, and re-running
            // `login enable --apply` deleted them: a security control removed
            // with no mention, from a command whose stated job is to add a
            // line. The tail risk is worse than that, since a months-old backup
            // can name a module the system no longer ships, which is a stack
            // that denies every login.
            //
            // Stripping is a complete inverse: `unwire_lines` matches irlume's
            // module on the PAM directive and its landing lines on irlume's own
            // comment tags, so it removes what irlume added and nothing else.
            // The disable path already refuses to restore a backup that no
            // longer matches the stripped current file, for this same reason.
            let bak = PathBuf::from(format!("{}{BACKUP}", s.etc));
            let (base, _) = unwire_lines(&current);
            // Say so when the stack has moved since irlume wired it. Not a
            // failure: the rebuild above already keeps the change. The operator
            // should know their backup no longer describes the file.
            if bak.exists() {
                if let Ok(bak_content) = read(&bak.to_string_lossy()) {
                    if bak_content.trim() != base.trim() {
                        eprintln!(
                            "[login] note: {} changed since irlume first wired it; keeping \
                             those changes and re-applying irlume's lines on top",
                            s.etc
                        );
                    }
                }
            }
            let (wired, changed) = wire(&base);
            if !changed {
                return out(
                    PlannedChange::NoAnchor,
                    format!("· {}: no anchor to wire (skipped)", s.etc),
                );
            }
            if wired == current {
                return out(
                    PlannedChange::AlreadyCorrect,
                    format!("· {}: already correctly wired", s.etc),
                );
            }
            if apply {
                backup(etc)?;
                write_atomic(etc, &wired)?;
            }
            out(
                PlannedChange::Wire,
                format!("✓ {}: wired (backup {}{})", s.etc, s.etc, BACKUP),
            )
        }
    } else {
        // disable / unwire
        if use_override && etc.exists() && file_is_created_override(etc) {
            if apply {
                std::fs::remove_file(etc).map_err(|e| format!("rm {}: {e}", s.etc))?;
            }
            out(
                PlannedChange::RemoveOverride,
                format!("✓ {}: removed override (vendor restored)", s.etc),
            )
        } else if !use_override && etc.exists() {
            let bak = PathBuf::from(format!("{}{BACKUP}", s.etc));
            if bak.exists() {
                // Restore the backup ONLY when it equals the current file minus
                // our lines, i.e. nothing else changed since we wired. If an
                // admin (or another package) edited the file after wiring,
                // restoring the stale snapshot would silently revert their
                // change (e.g. a faillock line added to sudo): strip in place
                // instead and keep the backup for inspection.
                let (stripped, _) = unwire_lines(&read(s.etc)?);
                let bak_content = read(&bak.to_string_lossy())?;
                if stripped == bak_content {
                    if apply {
                        // The same refusal every other write path in this module
                        // applies. A rename over a SYMLINK replaces the link with
                        // a regular file, and a multiply-linked PAM file loses a
                        // name irlume cannot put back; both are exactly what
                        // `inspect_target` exists to stop, and this restore was
                        // the one path that skipped it.
                        inspect_target(etc)?;
                        std::fs::rename(&bak, etc)
                            .map_err(|e| format!("restore {}: {e}", s.etc))?;
                    }
                    out(
                        PlannedChange::RestoreBackup,
                        format!("✓ {}: restored from backup", s.etc),
                    )
                } else {
                    if apply {
                        write_atomic(etc, &stripped)?;
                    }
                    out(PlannedChange::StripInPlace, format!("✓ {}: stripped irlume lines (file changed since wiring; backup kept at {}{})", s.etc, s.etc, BACKUP))
                }
            } else if file_has_module(etc) {
                let (clean, _) = unwire_lines(&read(s.etc)?);
                if apply {
                    write_atomic(etc, &clean)?;
                }
                out(
                    PlannedChange::StripInPlace,
                    format!("✓ {}: stripped irlume lines", s.etc),
                )
            } else {
                out(PlannedChange::NotWired, format!("· {}: not wired", s.etc))
            }
        } else {
            out(PlannedChange::NotWired, format!("· {}: not wired", s.etc))
        }
    }
}

// ---- pure PAM-text mechanics (unit-tested) -----------------------------------

/// `Some(true/false)` when semodule could be queried (root), `None` otherwise.
fn selinux_loaded() -> Option<bool> {
    let out = Command::new("semodule").arg("-l").output().ok()?;
    if !out.status.success() {
        return None; // needs root to read the policy store
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|l| l.split_whitespace().next() == Some("irlume")),
    )
}
/// Locate the compiled SELinux policy module. Packaged installs ship it under
/// /usr/share/irlume/selinux; an env override and the in-repo build dir cover
/// dev/source builds. (The old hardcoded developer home path never existed on a
/// user's machine, so the module silently never loaded.)
fn selinux_pp() -> Option<String> {
    if let Some(p) = std::env::var_os("IRLUME_SELINUX_PP") {
        let p = p.to_string_lossy().into_owned();
        if Path::new(&p).exists() {
            return Some(p);
        }
    }
    for p in [
        // Where the irlume-selinux rpm actually installs it (the standard
        // SELinux packages dir). Missing here meant a Copr install could
        // never re-load the module after `login disable` removed it; the
        // rpm's own %post load at install time had masked the gap.
        "/usr/share/selinux/packages/irlume.pp",
        "/usr/share/irlume/selinux/irlume.pp",
        "/usr/lib/irlume/selinux/irlume.pp",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packaging/selinux/irlume.pp"
        ),
    ] {
        if Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

/// Settle `/run/irlume.sock`'s label after the policy module changes.
///
/// The already-bound socket keeps its pre-policy label; the greeter stays
/// blocked until the daemon rebinds. Restart it now so face login works at
/// the very next lock/login, not the next reboot. The restart alone is not
/// enough under socket activation, where systemd owns the socket file and a
/// service restart never recreates it, so the boot-time label survives;
/// `restorecon` (backed by the irlume.fc entry) settles the label in that
/// case and whenever the bind raced the policy commit. This lived only on
/// the `login enable` path while the TUI Repair fix and `selinux load` each
/// carried half of it, and the halves reported done for a relabel that had
/// not happened; one function so the sequence cannot drift apart again.
pub(crate) fn relabel_daemon_socket() {
    let _ = Command::new("systemctl")
        .args(["try-restart", "irlumed.service"])
        .status();
    let _ = Command::new("restorecon").arg("/run/irlume.sock").status();
}

fn selinux(enable: bool, apply: bool) -> Result<String, String> {
    if enable {
        if selinux_loaded() == Some(true) {
            return Ok("· SELinux module already loaded".into());
        }
        let Some(pp) = selinux_pp() else {
            return Ok(
                "· SELinux: irlume.pp not found (install the selinux subpackage); skipped".into(),
            );
        };
        if apply {
            let ok = Command::new("semodule")
                .args(["-i", pp.as_str()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                return Err("semodule -i irlume.pp failed".into());
            }
            relabel_daemon_socket();
            Ok("✓ SELinux module loaded (daemon restarted to relabel its socket)".into())
        } else {
            Ok("→ would load the SELinux module (greeter→daemon socket)".into())
        }
    } else {
        if selinux_loaded() == Some(false) {
            return Ok("· SELinux module not loaded".into());
        }
        if apply {
            // Checked, like the install side a few lines above. Discarding the
            // status and printing the tick regardless told the operator the
            // module was gone whenever `semodule -r` failed (policy busy, an
            // selinux-policy version that refuses, no semodule at all), and the
            // next `login status` would then disagree with the line they had
            // just been shown.
            match Command::new("semodule").args(["-r", "irlume"]).status() {
                Ok(st) if st.success() => Ok("✓ SELinux module removed".into()),
                Ok(st) => Err(format!(
                    "semodule -r irlume failed ({st}); the module is still loaded"
                )),
                Err(e) => Err(format!(
                    "could not run semodule ({e}); the module is still loaded"
                )),
            }
        } else {
            Ok("→ would remove the SELinux module (if loaded)".into())
        }
    }
}

fn effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("Uid:")
                    .map(|v| v.split_whitespace().nth(1).unwrap_or("1000").to_string())
            })
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
}

#[cfg(test)]
mod tests {

    /// Re-wiring rebuilds from the CURRENT file stripped of irlume's lines, not
    /// from the `.pre-irlume` backup.
    ///
    /// Taking the backup as origin discarded every change made to the stack
    /// after irlume first wired it. A distro update adding `pam_faillock` is the
    /// ordinary case, and `login enable --apply` then deleted it: a security
    /// control removed without a word, by a command whose job is to add a line.
    /// This pins the property the rebuild rests on, that stripping is a complete
    /// inverse which touches irlume's lines and nothing else.
    #[test]
    fn stripping_a_wired_stack_keeps_what_the_distro_added_later() {
        let stock = "auth       required     pam_env.so\n                     auth       sufficient   pam_unix.so try_first_pass nullok\n";
        let (wired, changed) = wire_greeter_impl(stock, true, true, false);
        assert!(changed, "the fixture must actually wire");

        // The distro later adds faillock above and below, as it does on a real
        // update; irlume never saw these lines and has no backup containing them.
        let after_update = wired.replace(
            "auth       required     pam_env.so",
            "auth       required     pam_faillock.so preauth\n             auth       required     pam_env.so",
        ) + "account    required     pam_faillock.so\n";

        let (base, _) = super::unwire_lines(&after_update);
        assert!(
            base.contains("pam_faillock.so preauth")
                && base.contains("account    required     pam_faillock.so"),
            "stripping must keep every line irlume did not add: {base}"
        );
        assert!(
            !base.contains("pam_irlume.so"),
            "and must remove every line irlume did add: {base}"
        );
        assert!(base.contains("pam_unix.so"), "{base}");
    }

    /// `flock` is per open file description, so a second `lock_pam()` from the
    /// SAME process blocks on the first one forever rather than succeeding.
    ///
    /// `reconcile` took the lock, found a regression, and called `act`, which
    /// took it again: the self-heal deadlocked on exactly the condition it
    /// exists to repair, so it had never once worked. The hung process is root
    /// and holds the lock exclusively, so every other irlume PAM operation
    /// queued behind it, and the unit's `Type=oneshot` default of
    /// `TimeoutStartUSec=infinity` meant systemd never killed it.
    ///
    /// This pins the hazard rather than the call graph, because the call graph
    /// is what drifts. If `lock_pam` is ever made reentrant this test fails and
    /// the split in `act`/`act_holding_lock` can be revisited.
    #[test]
    fn a_second_pam_lock_in_the_same_process_does_not_succeed() {
        let dir = std::env::temp_dir().join(format!("irlume-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lock_path = dir.join("pam.lock");
        std::env::set_var("IRLUME_PAM_LOCK", &lock_path);

        let first = super::lock_pam().expect("the first lock must be granted");

        // The second attempt runs on a thread so a deadlock cannot hang the
        // suite: we assert on whether it reports back, not on it returning.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _second = super::lock_pam();
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(2)).is_err(),
            "a second lock_pam() returned, so re-locking is now safe and the \
             act/act_holding_lock split should be re-examined"
        );

        drop(first);
        std::env::remove_var("IRLUME_PAM_LOCK");
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    /// A wiring ENABLE must refuse a capability reading nothing established,
    /// because enabling unwires whatever reads unsupported. Demonstrated on
    /// the shipped 0.9.0 binary against an unanswering socket with no
    /// configured pair: it planned `face login: off  face lock: off` and
    /// exited 0, which with --apply strips the face line from every greeter.
    /// A DISABLE needs no capabilities: removal is what the user asked for.
    #[test]
    fn enable_refuses_an_unestablished_capability_reading_and_disable_does_not() {
        assert!(enable_permitted(true, true).is_ok(), "established: proceed");
        assert!(
            enable_permitted(false, false).is_ok(),
            "a disable removes wiring on purpose and needs no capabilities"
        );
        assert!(
            enable_permitted(false, true).is_ok(),
            "a disable is unaffected by an established reading too"
        );
        let refused = enable_permitted(true, false)
            .expect_err("an enable on a guessed capability must refuse");
        assert!(
            refused.contains("could not be") && refused.contains("Nothing was changed"),
            "the refusal must say what was not established and that nothing changed: {refused}"
        );
    }

    // Reached through the submodule because the parent has no production use
    // for it; `use super::*` only carries what the parent itself imports.
    use super::report::label_of;

    // Fedora gdm-password layout (real /etc file, the GDM greeter).
    const GDM: &str = "#%PAM-1.0\nauth     [success=done ...] pam_selinux_permit.so\nauth     substack      password-auth\nauth     optional      pam_gnome_keyring.so\naccount  include       password-auth\nsession  include       password-auth\nsession  optional      pam_gnome_keyring.so auto_start\n";

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("irlume-pamfile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn strays(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("read dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect()
    }

    /// The PAM lock actually excludes, and releases on drop.
    ///
    /// Asserted against a SECOND PROCESS, because `flock` is per open file
    /// description: two locks taken in one process from separate opens do not
    /// block each other on Linux the way two processes do, so an in-process test
    /// could report exclusion that does not exist between the commands this is
    /// meant to serialise.
    #[test]
    fn the_pam_lock_excludes_another_process_and_frees_on_drop() {
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = scratch_dir("pamlock");
        let lock_path = dir.join("irlume-pam.lock");
        let previous = std::env::var_os("IRLUME_PAM_LOCK");
        // SAFETY: the env lock is held for the whole test.
        unsafe { std::env::set_var("IRLUME_PAM_LOCK", &lock_path) };

        // `flock -n` exits 1 when the lock is held; the shell is a separate
        // process, which is the case that matters.
        let contended = || {
            std::process::Command::new("flock")
                .arg("-n")
                .arg(&lock_path)
                .arg("true")
                .status()
                .expect("run flock")
                .success()
        };

        assert!(contended(), "nothing held the lock yet");
        let held = lock_pam().expect("take the lock");
        assert!(
            !contended(),
            "a second process took the PAM lock while irlume held it"
        );
        drop(held);
        assert!(contended(), "the lock was not released when dropped");

        // SAFETY: as above.
        unsafe {
            match previous {
                Some(value) => std::env::set_var("IRLUME_PAM_LOCK", value),
                None => std::env::remove_var("IRLUME_PAM_LOCK"),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two writes must never share a scratch name.
    ///
    /// Every write used to go through `.{service}.irlume.tmp`. Two irlume
    /// processes writing one PAM file opened that single inode and interleaved
    /// their bodies; whichever renamed first published whatever was in it. An
    /// atomic rename makes the NAME change indivisible, it does not make
    /// concurrent production of the source safe.
    #[test]
    fn each_write_gets_its_own_scratch_file() {
        let target = Path::new("/etc/pam.d/sudo");
        let a = scratch_path(target, "new");
        let b = scratch_path(target, "new");
        assert_ne!(a, b, "two writes shared one scratch path");
        assert_eq!(
            a.parent(),
            target.parent(),
            "scratch must be same-directory"
        );
        for p in [&a, &b] {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            assert!(name.starts_with('.'), "{name} is not hidden");
            assert!(name.contains("sudo"), "{name} does not name its target");
        }
        // A scratch file left by a crashed run is dropped, not written into: its
        // contents are somebody else's.
        let dir = scratch_dir("scratch");
        let stale = dir.join(".sudo.irlume-new.stale.tmp");
        std::fs::write(&stale, "SOMEBODY ELSE'S HALF-WRITTEN BODY").unwrap();
        create_scratch(&stale).expect("stale scratch must be replaced");
        assert_eq!(std::fs::read_to_string(&stale).unwrap(), "");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A write carries the mode and owner across, and leaves nothing behind.
    #[test]
    fn a_write_preserves_attributes_and_leaves_no_scratch() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("attrs");
        let target = dir.join("sudo");
        std::fs::write(&target, "old\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before_inode = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&target).unwrap().ino()
        };

        write_atomic(&target, "new\n").expect("write");

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new\n");
        let meta = std::fs::metadata(&target).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o640,
            "the replacement did not carry the mode across"
        );
        use std::os::unix::fs::MetadataExt;
        assert_ne!(meta.ino(), before_inode, "the file was rewritten in place");
        assert!(strays(&dir).is_empty(), "left scratch: {:?}", strays(&dir));

        // Restoring a file apply had REMOVED: there is no current file to copy
        // attributes from, so the recorded ones are the only source. Recorded as
        // this account rather than root, because the test does not run as root
        // and a chown to another owner is refused; production rollback --apply
        // is root-only and the refusal is reported there rather than ignored.
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let gone = dir.join("kde-fingerprint");
        restore_surface(&gone, Some("restored\n"), Some((0o600, uid, gid))).expect("restore");
        assert_eq!(
            std::fs::metadata(&gone).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert!(strays(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A symlink and a multiply-linked file are refused by EVERY write path.
    ///
    /// The check lived only in the machine `apply` path, so human
    /// enable/disable, reconcile and rollback would silently replace a symlink
    /// with a regular file. Nothing anywhere refused a hard link: a rename
    /// replaces one directory entry, so the other names keep referring to the
    /// old inode, PAM reads one and package tooling updates the other, and the
    /// link topology is recorded nowhere so it could not be restored.
    ///
    /// Asserted through `write_atomic`, the funnel every path uses, rather than
    /// on the checker alone: what matters is that a write is refused.
    #[test]
    fn a_symlink_or_a_hard_link_is_never_replaced_by_any_write_path() {
        let dir = scratch_dir("links");

        // A symlink standing in for the authselect/alternatives layout.
        let real = dir.join("password-auth");
        std::fs::write(&real, "the shared target\n").unwrap();
        let link = dir.join("gdm-password");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let refused = write_atomic(&link, "wired\n").expect_err("a symlink must be refused");
        assert!(refused.contains("symlink"), "{refused}");
        assert_eq!(
            std::fs::read_to_string(&real).unwrap(),
            "the shared target\n",
            "the symlink's target was written through"
        );
        assert!(link.is_symlink(), "the symlink was replaced");

        // Two names for one inode.
        let a = dir.join("sudo");
        std::fs::write(&a, "the original stack\n").unwrap();
        let b = dir.join("sudo-peer");
        std::fs::hard_link(&a, &b).unwrap();
        let refused = write_atomic(&a, "wired\n").expect_err("a hard link must be refused");
        assert!(refused.contains("hard link"), "{refused}");
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "the original stack\n");
        assert_eq!(
            std::fs::read_to_string(&b).unwrap(),
            "the original stack\n",
            "the peer name was detached from the content"
        );
        // Restore refuses on the same terms; it used to have no check at all.
        assert!(restore_surface(&a, Some("restored\n"), None).is_err());

        // REMOVING a surface is a write path too. Rollback removes a file that
        // was absent before the transaction, and that branch called remove_file
        // directly: a path now holding a symlink was unlinked despite the claim
        // that every path refuses one, and a multiply-linked file lost a name
        // irlume cannot put back.
        let gone_link = dir.join("was-absent");
        std::os::unix::fs::symlink(&real, &gone_link).unwrap();
        let refused = restore_surface(&gone_link, None, None)
            .expect_err("removing a symlink must be refused too");
        assert!(refused.contains("symlink"), "{refused}");
        assert!(gone_link.is_symlink(), "the symlink was unlinked");
        let peer = dir.join("linked-peer");
        std::fs::hard_link(&a, &peer).unwrap();
        assert!(
            restore_surface(&a, None, None).is_err(),
            "removing one name of a multiply-linked file must be refused"
        );
        std::fs::remove_file(&peer).unwrap();

        // Unlinking the peer makes it an ordinary file again, and writable.
        std::fs::remove_file(&b).unwrap();
        write_atomic(&a, "wired\n").expect("a single-linked regular file is fine");
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "wired\n");
        assert!(strays(&dir).is_empty(), "left scratch: {:?}", strays(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A target replaced DURING the write is not overwritten.
    ///
    /// The first look at the file and the rename that replaces it are two
    /// moments. Checking once up front proves what the name meant when the write
    /// started, and the rename acts on what it means when it finishes; between
    /// them a package, an administrator or another tool can put a different file
    /// — or a symlink into /etc/authselect — under that name.
    ///
    /// Reachable only from inside the write, hence the test hook. Removing the
    /// pre-rename recheck left every other test green.
    #[test]
    fn a_target_swapped_mid_write_is_left_alone() {
        let dir = scratch_dir("swap");
        let target = dir.join("sudo");
        std::fs::write(&target, "the original stack\n").unwrap();

        *SWAP_DURING_WRITE.lock().unwrap() = Some(target.clone());
        let refused = write_atomic(&target, "wired\n")
            .expect_err("a target replaced mid-write must not be overwritten");
        *SWAP_DURING_WRITE.lock().unwrap() = None;

        assert!(
            refused.contains("changed while irlume was writing"),
            "{refused}"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "SOMEONE ELSE'S FILE\n",
            "irlume overwrote the file that replaced its target"
        );
        assert!(strays(&dir).is_empty(), "left scratch: {:?}", strays(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A backup is complete or absent, and an existing one is never replaced.
    ///
    /// `std::fs::copy` straight to `.pre-irlume` could be killed part way, and a
    /// later enable treats an existing backup as the pristine origin to rebuild
    /// the live stack from. A truncated backup therefore became the authority
    /// for what the machine's PAM should contain.
    #[test]
    fn a_backup_is_never_published_half_written() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("backup");
        let target = dir.join("sudo");
        std::fs::write(&target, "the original stack\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

        backup(&target).expect("backup");
        let bak = dir.join(format!("sudo{BACKUP}"));
        assert_eq!(
            std::fs::read_to_string(&bak).unwrap(),
            "the original stack\n"
        );
        assert_eq!(
            std::fs::metadata(&bak).unwrap().permissions().mode() & 0o7777,
            0o644,
            "the backup did not carry the mode across"
        );
        assert!(strays(&dir).is_empty(), "left scratch: {:?}", strays(&dir));

        // The live file is now wired. A second backup must NOT overwrite the
        // pristine one with the already-wired content.
        std::fs::write(
            &target,
            "auth sufficient pam_irlume.so\nthe original stack\n",
        )
        .unwrap();
        backup(&target).expect("second backup");
        assert_eq!(
            std::fs::read_to_string(&bak).unwrap(),
            "the original stack\n",
            "a retry overwrote the pristine backup with wired content"
        );
        assert!(strays(&dir).is_empty());

        // An EXISTING backup is held to the same standard as the stack, and was
        // not. `exists()` follows a symlink, so a `.pre-irlume` pointing
        // elsewhere was accepted and then used as the pristine origin a later
        // enable rebuilds from.
        let linked = dir.join("sddm");
        std::fs::write(&linked, "the stack\n").unwrap();
        let elsewhere = dir.join("somewhere-else");
        std::fs::write(&elsewhere, "not this camera's business\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join(format!("sddm{BACKUP}"))).unwrap();
        let refused = backup(&linked).expect_err("a symlinked backup must be refused");
        assert!(refused.contains("symlink"), "{refused}");

        // A DANGLING one was worse: `exists()` said no, and publishing then
        // failed with EEXIST against the symlink's own name, which read as "a
        // backup is already there" when there was none at all.
        let dangling = dir.join("lightdm");
        std::fs::write(&dangling, "the stack\n").unwrap();
        std::os::unix::fs::symlink(
            dir.join("nothing-here"),
            dir.join(format!("lightdm{BACKUP}")),
        )
        .unwrap();
        let refused = backup(&dangling).expect_err("a dangling backup link must be refused");
        assert!(refused.contains("symlink"), "{refused}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_regressed_flags_only_a_stripped_existing_file() {
        let dir = std::env::temp_dir().join("irlume-pamwire-regress-test");
        let _ = std::fs::create_dir_all(&dir);
        let wired = dir.join("kde-wired");
        let stripped = dir.join("kde-stripped");
        let absent = dir.join("kde-absent");
        std::fs::write(&wired, "auth sufficient pam_irlume.so unseal ondemand\n").unwrap();
        std::fs::write(&stripped, "auth include system-local-login\n").unwrap();
        let _ = std::fs::remove_file(&absent);
        // Stripped: the file is there (it was wired) but lost the module -> repair.
        assert!(path_regressed(&stripped));
        // Still wired: not a regression.
        assert!(!path_regressed(&wired));
        // Absent (non-KDE box / never wired): nothing to maintain, not a regression.
        assert!(!path_regressed(&absent));

        // lock_regressed adds the deleted-override case: /etc gone but the vendor
        // service remains (a KDE box) is a regression; gone with no vendor is not.
        let vendor = dir.join("vendor-kde");
        std::fs::write(&vendor, "auth include something\n").unwrap();
        assert!(lock_regressed(&stripped, Some(&vendor))); // stripped in place
        assert!(!lock_regressed(&wired, Some(&vendor))); // still wired
        assert!(lock_regressed(&absent, Some(&vendor))); // deleted, vendor present
        assert!(!lock_regressed(&absent, None)); // deleted, no vendor (non-KDE)
        let missing_vendor = dir.join("no-such-vendor");
        assert!(!lock_regressed(&absent, Some(&missing_vendor))); // vendor also gone
                                                                  // The marker gate: if we never wired the lock (with_lock=false), no state
                                                                  // of /etc/pam.d/kde counts as a regression (a Plasma vendor file on a
                                                                  // GNOME box must not loop reconcile).
        assert!(!lockscreen_regressed(false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn greeter_block_wraps_password_substack() {
        let (w, changed) = wire_greeter_impl(GDM, true, true, false);
        assert!(changed);
        let lines: Vec<&str> = w.lines().collect();
        let unseal = lines.iter().position(|l| l.contains("unseal")).unwrap();
        let substack = lines
            .iter()
            .position(|l| l.contains("auth     substack      password-auth"))
            .unwrap();
        let permit = lines
            .iter()
            .position(|l| l.contains("pam_permit.so"))
            .unwrap();
        let reseal_auth = lines
            .iter()
            .position(|l| l.contains("auth") && l.contains("reseal"))
            .unwrap();
        // unseal BEFORE substack; permit + reseal AFTER it.
        assert!(unseal < substack && substack < permit && permit < reseal_auth);
        // session reseal present after the session substack.
        assert!(lines
            .iter()
            .any(|l| l.starts_with("session") && l.contains("reseal")));
    }

    // Regression: the substack (Fedora) branch emitted a BARE `unseal` where the
    // @include branch emitted `unseal facefirst`. Without the arg the module runs
    // the active probe and blocks until the user types, so on the greeters this
    // branch serves (old GDM below the GNOME gate, any unvalidated DM) the face
    // never fired at all.
    #[test]
    fn substack_greeter_without_ondemand_still_gets_facefirst() {
        let (w, changed) = wire_greeter_impl(GDM, true, false, false);
        assert!(changed);
        assert!(w.contains("pam_irlume.so unseal facefirst"), "{w}");
        assert!(!w.contains("unseal ondemand"));
        // Still the jump form (a substack IS skippable by success=1), with the
        // landing that jump needs.
        assert!(w.contains("[success=1 default=ignore]"));
        assert!(w.contains("irlume-landing"));
    }

    // Debian/Ubuntu cosmic-greeter layout (@include-based; one service drives
    // both the login and the lock screen).
    const COSMIC: &str = "#%PAM-1.0\nauth    requisite    pam_nologin.so\n@include common-auth\nauth    optional    pam_gnome_keyring.so\n@include common-account\n@include common-session\n@include common-password\n";

    #[test]
    fn cosmic_greeter_wires_ondemand_not_facefirst() {
        // ondemand=true → on-demand probe line (face only on empty-Enter), placed
        // before the password include so the password stays a fallback.
        let (w, changed) = wire_greeter_impl(COSMIC, true, false, true);
        assert!(changed);
        assert!(w.contains("pam_irlume.so unseal ondemand"));
        assert!(!w.contains("facefirst"));
        let lines: Vec<&str> = w.lines().collect();
        let unseal = lines
            .iter()
            .position(|l| l.contains("unseal ondemand"))
            .unwrap();
        let inc = lines
            .iter()
            .position(|l| l.trim_start().starts_with("@include common-auth"))
            .unwrap();
        assert!(unseal < inc);
        // A non-cosmic Debian greeter (ondemand=false) still gets facefirst.
        let (g, _) = wire_greeter_impl(COSMIC, true, false, false);
        assert!(g.contains("facefirst") && !g.contains("ondemand"));
    }

    // greetd layout: `@include login` (which itself pulls in common-auth) plus its
    // own keyring modules after, NOT a direct `@include common-auth`.
    const GREETD: &str = "#%PAM-1.0\n@include login\n-auth        optional        pam_gnome_keyring.so\n-auth        optional        pam_kwallet5.so\n-session     optional        pam_gnome_keyring.so auto_start\n-session     optional        pam_kwallet5.so auto_start\n";

    #[test]
    fn greetd_include_login_layout_wires_before_the_include() {
        // The face line must land before `@include login` (so face runs ahead of
        // the password stack), NOT before greetd's post-include keyring modules.
        let (w, changed) = wire_greeter_impl(GREETD, true, true, true);
        assert!(changed);
        assert!(w.contains("pam_irlume.so unseal ondemand"));
        let lines: Vec<&str> = w.lines().collect();
        let unseal = lines
            .iter()
            .position(|l| l.contains("unseal ondemand"))
            .unwrap();
        let inc = lines
            .iter()
            .position(|l| l.trim_start().starts_with("@include login"))
            .unwrap();
        assert!(unseal < inc, "face line must precede @include login");
        // keyring-unseal rides just after the include, ahead of greetd's own
        // pam_gnome_keyring so the unsealed AUTHTOK is in place for it.
        let kr = lines
            .iter()
            .position(|l| l.contains("pam_irlume.so keyring"))
            .unwrap();
        assert!(kr > inc);
    }

    #[test]
    fn dm_profile_tailors_per_login_manager() {
        // COSMIC answers the probe on submit → ondemand.
        assert!(dm_profile("/etc/pam.d/cosmic-greeter", Some(50)).ondemand);
        // GDM: ondemand is version-gated (modern GNOME) → facefirst below.
        assert!(dm_profile("/etc/pam.d/gdm-password", Some(50)).ondemand);
        assert!(!dm_profile("/etc/pam.d/gdm-password", Some(3)).ondemand); // old GNOME → facefirst
        assert!(!dm_profile("/etc/pam.d/gdm-password", None).ondemand); // undetected → facefirst
                                                                        // LightDM + SDDM: validated → on-demand.
        assert!(dm_profile("/etc/pam.d/lightdm", None).ondemand);
        assert!(dm_profile("/etc/pam.d/sddm", None).ondemand);
        // greetd: submit-driven family → on-demand.
        assert!(dm_profile("/etc/pam.d/greetd", None).ondemand);
        // plasmalogin (SDDM fork): submit-driven → on-demand.
        assert!(dm_profile("/etc/pam.d/plasmalogin", None).ondemand);
        // an untested/unknown greeter defaults to the safe facefirst.
        assert!(!dm_profile("/etc/pam.d/xdm", None).ondemand);
    }

    #[test]
    fn include_greeter_line_is_sufficient_plus_kr() {
        // Uniform `sufficient` for every DM; the module's `kr` arg (not the
        // control) drives cold-login keyring-continue. Greeters carry `kr`.
        let greeter = include_greeter_line("ondemand", true);
        assert!(greeter.contains("sufficient"));
        assert!(greeter.contains("pam_irlume.so unseal ondemand kr"));
        assert!(!greeter.contains("success=ok"));
        // A separate warm lock service short-circuits without `kr`.
        let lock = include_greeter_line("ondemand", false);
        assert!(lock.contains("sufficient") && lock.ends_with("unseal ondemand"));
        assert!(!lock.contains(" kr"));
    }

    #[test]
    fn arch_include_layout_uses_sufficient_not_jump() {
        // Arch greeters/lockers use `auth include system-login`/`system-local-login`,
        // an inline include a `success=N` jump can't skip. Both must get the
        // `sufficient` form, not the [success=1] jump that lands mid-include at
        // pam_unix (the bug that made face login/unlock still ask for a password).
        let arch_greeter = "#%PAM-1.0\nauth       include     system-login\naccount    include     system-login\npassword   include     system-login\nsession    include     system-login\n";
        let (g, changed) = wire_greeter_impl(arch_greeter, true, false, true);
        assert!(changed);
        assert!(g.contains("sufficient   pam_irlume.so unseal ondemand kr"));
        assert!(!g.contains("[success=1 default=ignore]   pam_irlume.so unseal"));
        // The face line lands BEFORE the auth include, not after it.
        let face_at = g.find("pam_irlume.so unseal").unwrap();
        let inc_at = g.find("auth       include     system-login").unwrap();
        assert!(face_at < inc_at);

        let arch_lock = "#%PAM-1.0\nauth       include     system-local-login\naccount    include     system-local-login\n";
        let (l, changed) = wire_lock(arch_lock);
        assert!(changed);
        assert!(l.contains("sufficient   pam_irlume.so unseal ondemand"));
        assert!(!l.contains(" kr")); // warm lock: no keyring-continue
        assert!(!l.contains("[success=1"));
    }

    #[test]
    fn fedora_substack_still_uses_the_jump_form() {
        // Regression guard: a Fedora `substack` is atomic for jump counting, so
        // it must keep the [success=1] jump, not switch to sufficient.
        let fedora = "#%PAM-1.0\nauth       substack     password-auth\nauth       optional     pam_permit.so\n";
        let (l, _) = wire_lock(fedora);
        assert!(l.contains("[success=1 default=ignore]   pam_irlume.so unseal ondemand"));
    }

    #[test]
    fn gdm_ondemand_is_version_gated() {
        // Modern GNOME (validated on 50) → on-demand; older → facefirst; unknown
        // → facefirst (conservative). Boundary at the documented cutoff.
        assert!(gdm_uses_ondemand(Some(50)));
        assert!(gdm_uses_ondemand(Some(GDM_ONDEMAND_MIN_GNOME)));
        assert!(!gdm_uses_ondemand(Some(GDM_ONDEMAND_MIN_GNOME - 1)));
        assert!(!gdm_uses_ondemand(Some(3))); // GNOME 3.x-era
        assert!(!gdm_uses_ondemand(None)); // undetected → facefirst
    }

    #[test]
    fn greeter_wiring_is_idempotent() {
        let (w1, _) = wire_greeter_impl(GDM, true, true, false);
        let (w2, changed) = wire_greeter_impl(&w1, true, true, false);
        assert!(!changed);
        assert_eq!(w1, w2);
    }

    #[test]
    fn method_switch_reconciles_the_line_set() {
        // face-only → (strip) → keyring-only must actually change the lines
        // (the method-switch case the old skip-if-present logic silently no-op'd).
        let (face_only, _) = wire_greeter_impl(GDM, true, false, false);
        assert!(
            face_only.contains("pam_irlume.so unseal")
                && !face_only.contains("pam_irlume.so keyring")
        );
        let (base, stripped) = unwire_lines(&face_only);
        assert!(stripped && !base.contains(MODULE));
        let (keyring_only, _) = wire_greeter_impl(&base, false, true, false);
        assert!(
            keyring_only.contains("pam_irlume.so keyring")
                && !keyring_only.contains("pam_irlume.so unseal")
        );
        assert_ne!(face_only, keyring_only);
    }

    #[test]
    fn unwire_keeps_a_foreign_pam_permit() {
        let stack = "auth optional pam_permit.so\nauth substack password-auth\n";
        let (clean, _) = unwire_lines(stack);
        assert!(clean.contains("pam_permit.so")); // foreign permit survives
    }

    #[test]
    fn single_stanza_and_unwire_roundtrip() {
        let base = "#%PAM-1.0\nauth required pam_unix.so\nsession required pam_unix.so\n";
        let (w, c) = wire_verify_service(base);
        assert!(c && content_has_module(&w));
        let (back, changed) = unwire_lines(&w);
        assert!(changed && !content_has_module(&back));
    }

    // Fedora KDE lock service `kde` (substack layout), the real file we validated.
    const KDE_LOCK: &str = "auth        substack      password-auth\nauth        include       postlogin\naccount     required      pam_nologin.so\npassword    include       password-auth\nsession     required      pam_selinux.so close\n";

    #[test]
    fn kde_lock_is_ondemand_not_ambient_wait() {
        let (w, changed) = wire_lock(KDE_LOCK);
        assert!(changed);
        // consent-driven on-demand, never the ambient `wait` mode, no reseal.
        assert!(w.contains("pam_irlume.so unseal ondemand"));
        assert!(!w.contains("pam_irlume.so wait"));
        assert!(!w.contains("reseal"));
        // face-first before the password substack, with the permit landing.
        let lines: Vec<&str> = w.lines().collect();
        let face = lines
            .iter()
            .position(|l| l.contains("unseal ondemand"))
            .unwrap();
        let substack = lines
            .iter()
            .position(|l| l.contains("substack      password-auth"))
            .unwrap();
        assert!(face < substack);
        assert!(w.contains("pam_permit.so") && w.contains("irlume-landing"));
        // fully reversible.
        let (back, undone) = unwire_lines(&w);
        assert!(undone && !content_has_module(&back));
    }

    // Regression: 0956be5. `login disable --apply` without --with-sudo left
    // /etc/pam.d/sudo wired; disable must put sudo in scope regardless of the
    // flag, while enable keeps face-sudo opt-in.
    #[test]
    fn disable_always_unwires_sudo_even_without_the_flag() {
        assert!(sudo_in_scope(false, false)); // the bug: this used to be false
        assert!(sudo_in_scope(false, true));
        assert!(sudo_in_scope(true, true));
        assert!(!sudo_in_scope(true, false)); // enable stays opt-in
    }

    #[test]
    fn disable_always_unwires_polkit_even_without_the_flag() {
        assert!(polkit_in_scope(false, false));
        assert!(polkit_in_scope(false, true));
        assert!(polkit_in_scope(true, true));
        assert!(!polkit_in_scope(true, false)); // enable stays opt-in
    }

    #[test]
    fn verify_service_inserts_the_stanza_before_the_first_auth_line() {
        // Fedora vendor layout (include system-auth) and Debian's @include
        // layout both anchor on the first auth directive; the stanza must land
        // above it so the face runs before the password modules, and the line
        // must be plain verify: no `unseal` (the daemon refuses credential
        // release for polkit anyway) and no mode arg.
        for stock in [
            "#%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\n",
            "#%PAM-1.0\n@include common-auth\n@include common-account\n",
        ] {
            let (wired, changed) = wire_verify_service(stock);
            assert!(changed, "{stock:?}");
            let face = wired
                .lines()
                .position(|l| l.contains(MODULE))
                .expect("stanza present");
            let first_auth = wired
                .lines()
                .position(|l| {
                    !l.contains(MODULE) && (l.starts_with("auth") || l.starts_with("@include"))
                })
                .unwrap();
            assert!(face < first_auth, "{wired}");
            let line = wired.lines().nth(face).unwrap();
            assert!(
                !line.contains("unseal") && !line.contains("ondemand"),
                "{line}"
            );
            // Idempotent and fully reversible.
            assert!(!wire_verify_service(&wired).1);
            let (back, undone) = unwire_lines(&wired);
            assert!(undone && !content_has_module(&back));
        }
    }

    #[test]
    fn verify_service_skips_a_file_with_no_auth_phase() {
        // With no auth anchor the stanza would become the ONLY auth module, and
        // a failed face (IGNORE) would then fail the prompt outright instead of
        // cascading to the password. Must skip, not append.
        let stock = "#%PAM-1.0\nsession    include      system-auth\n";
        let (out, changed) = wire_verify_service(stock);
        assert!(!changed);
        assert_eq!(out, stock);
    }

    #[test]
    fn polkit_service_inserts_the_abort_die_stanza() {
        // A shake must be able to CLOSE the polkit dialog, which needs the control
        // to `die` on PAM_ABORT; a plain `sufficient` `default=ignore`s it (pam.conf
        // (5)). So the polkit stanza carries `abort=die`, unlike sudo's `sufficient`.
        for stock in [
            "#%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\n",
            "#%PAM-1.0\n@include common-auth\n@include common-account\n",
        ] {
            let (wired, changed) = wire_polkit_service(stock);
            assert!(changed, "{stock:?}");
            let face = wired
                .lines()
                .find(|l| l.contains(MODULE))
                .expect("stanza present");
            assert!(
                face.contains("abort=die"),
                "polkit line must die on abort: {face}"
            );
            assert!(!face.contains("unseal"), "polkit is verify-only: {face}");
            // Above the first non-irlume auth anchor, like the sudo verify stanza.
            let face_i = wired.lines().position(|l| l.contains(MODULE)).unwrap();
            let anchor_i = wired
                .lines()
                .position(|l| {
                    !l.contains(MODULE) && (l.starts_with("auth") || l.starts_with("@include"))
                })
                .unwrap();
            assert!(face_i < anchor_i, "{wired}");
            // Idempotent and fully reversible.
            assert!(
                !wire_polkit_service(&wired).1,
                "second wire is a no-op: {wired}"
            );
            let (back, undone) = unwire_lines(&wired);
            assert!(undone && !content_has_module(&back));
        }
    }

    #[test]
    fn migrating_an_old_polkit_line_yields_the_abort_die_control() {
        // An older irlume wired polkit-1 with a plain `sufficient` line, under which
        // a shake's PAM_ABORT is `default=ignore`d and the dialog never closes.
        // `login reconcile`/`enable` must migrate it to the abort=die control. In
        // production that happens in `wire_service`, which strips every irlume line
        // with `unwire_lines` and THEN calls `wire_polkit_service` on the clean base.
        // Test that exact composition (not `wire_polkit_service` alone, which by
        // design refuses a file that still has the module), so the migration the doc
        // promises is the migration a real re-wire performs.
        let old = format!(
            "#%PAM-1.0\nauth       sufficient                   {MODULE}\n\
             auth       include      system-auth\naccount    include      system-auth\n"
        );
        let (base, stripped) = unwire_lines(&old);
        assert!(stripped, "the old irlume line must be stripped first");
        assert!(
            !content_has_module(&base),
            "no irlume line survives the strip: {base}"
        );
        let (wired, changed) = wire_polkit_service(&base);
        assert!(
            changed && wired.contains("abort=die"),
            "migrated line must die on abort: {wired}"
        );
        // Exactly ONE irlume line, and no plain-`sufficient` control survives.
        assert_eq!(
            wired.lines().filter(|l| l.contains(MODULE)).count(),
            1,
            "migration must not duplicate the irlume line: {wired}"
        );
        assert!(
            !wired
                .lines()
                .any(|l| l.contains(MODULE) && l.contains(" sufficient ")),
            "the plain sufficient control must be gone: {wired}"
        );
    }

    #[test]
    fn polkit_service_carries_the_fedora_vendor_path() {
        // Fedora ships polkit-1 only in /usr/lib/pam.d; without the vendor
        // path, wire_service would skip it there instead of materializing the
        // /etc override.
        assert_eq!(POLKIT.etc, "/etc/pam.d/polkit-1");
        assert_eq!(POLKIT.vendor, Some("/usr/lib/pam.d/polkit-1"));
    }

    // Regression: 7ec33fa. Arch/Plasma ships the locker service only in
    // /usr/lib/pam.d, and LOCKSCREEN had vendor: None, so the lock screen was
    // skipped entirely on the Arch layout. The vendor path is what lets
    // wire_service materialize an /etc override from the vendor copy.
    #[test]
    fn kde_lock_service_carries_the_arch_vendor_path() {
        assert_eq!(LOCKSCREEN.etc, "/etc/pam.d/kde");
        assert_eq!(LOCKSCREEN.vendor, Some("/usr/lib/pam.d/kde"));
    }

    /// Self-cleaning scratch dir for the wire_service file tests.
    struct TestDir(PathBuf);
    impl TestDir {
        fn new(tag: &str) -> Self {
            let d =
                std::env::temp_dir().join(format!("irlume-pamwire-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            TestDir(d)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `Svc.etc` is `&'static str`; leak the tempdir path to satisfy it.
    fn leak(p: &Path) -> &'static str {
        Box::leak(p.to_string_lossy().into_owned().into_boxed_str())
    }

    const SUDO_STOCK: &str = "#%PAM-1.0\nauth required pam_unix.so\nsession required pam_unix.so\n";

    // Regression: 0be786b. disable restored the stale .pre-irlume backup,
    // silently reverting admin PAM edits made after wiring (e.g. a faillock
    // line added to sudo). When backup != current-minus-our-lines, the
    // strip-in-place path must run: the foreign line survives, the irlume
    // lines go, and the backup is kept for inspection.
    #[test]
    fn disable_strips_in_place_when_the_file_changed_after_wiring() {
        let dir = TestDir::new("strip");
        let (wired, changed) = wire_verify_service(SUDO_STOCK);
        assert!(changed);
        let admin_line = "auth       required   pam_faillock.so preauth";
        let current = format!("{wired}{admin_line}\n");
        let etc = dir.0.join("sudo");
        std::fs::write(&etc, &current).unwrap();
        std::fs::write(dir.0.join(format!("sudo{BACKUP}")), SUDO_STOCK).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let msg = wire_service(&svc, false, true, &wire_verify_service).unwrap();
        assert!(msg.message.contains("stripped irlume lines"), "{msg}");
        let after = std::fs::read_to_string(&etc).unwrap();
        assert!(
            after.contains(admin_line),
            "admin's post-wiring line must survive disable, got:\n{after}"
        );
        assert!(!content_has_module(&after));
        assert!(
            dir.0.join(format!("sudo{BACKUP}")).exists(),
            "backup must be kept for inspection"
        );
    }

    // Companion to the strip-in-place case: when nothing changed since wiring
    // (current minus our lines equals the backup), the backup-restore path is
    // still the one taken and the backup is consumed.
    #[test]
    fn disable_restores_the_backup_when_nothing_else_changed() {
        let dir = TestDir::new("restore");
        let (wired, _) = wire_verify_service(SUDO_STOCK);
        let etc = dir.0.join("sudo");
        std::fs::write(&etc, &wired).unwrap();
        std::fs::write(dir.0.join(format!("sudo{BACKUP}")), SUDO_STOCK).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let msg = wire_service(&svc, false, true, &wire_verify_service).unwrap();
        assert!(msg.message.contains("restored from backup"), "{msg}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), SUDO_STOCK);
        assert!(!dir.0.join(format!("sudo{BACKUP}")).exists());
    }

    // ---- keyring hand-off (KWallet / gnome-keyring) --------------------------
    // A greeter can be wired perfectly and still leave the wallet locked, which
    // reaches the user as "KWallet asks for its password even though face login
    // worked". These pin the detection of that state.

    // The four `plasmalogin` stacks Plasma Login Manager actually ships.
    //
    // Source: KDE/plasma-login-manager @ master, `data/pam/<os>/plasmalogin`.
    // Its CMake installs them to `${prefix}/lib/pam.d`, which is the vendor path
    // irlume materializes its /etc override from.
    //
    // BYTE-FOR-BYTE, comments and blank lines included. That is load-bearing, not
    // tidiness: these pin what irlume's wiring is checked against, so a fixture
    // that has been "cleaned up" is a fixture that no longer describes any real
    // machine. An earlier revision of these constants had the comments stripped
    // and, in the Debian file, had silently lost a `session required pam_env.so`
    // directive along with them. Re-check with a diff against upstream rather
    // than by eye.

    const UPSTREAM_FEDORA: &str = r#"auth     [success=done ignore=ignore default=bad] pam_selinux_permit.so
auth        substack      password-auth
-auth        optional      pam_gnome_keyring.so
-auth        optional      pam_kwallet5.so
-auth        optional      pam_kwallet.so
auth        include       postlogin

account     required      pam_nologin.so
account     include       password-auth

password    include       password-auth

session     required      pam_selinux.so close
session     required      pam_loginuid.so
-session    optional    pam_ck_connector.so
session     required      pam_selinux.so open
session     optional      pam_keyinit.so force revoke
session     required      pam_namespace.so
session     include       password-auth
-session     optional      pam_gnome_keyring.so auto_start
-session     optional      pam_kwallet5.so auto_start
-session     optional      pam_kwallet.so auto_start
session     include       postlogin
"#;

    const UPSTREAM_ARCH: &str = r#"#%PAM-1.0

# SPDX-License-Identifier: CC0-1.0
# SPDX-FileCopyrightText: none

auth        include     system-login
-auth       optional    pam_gnome_keyring.so
-auth       optional    pam_kwallet5.so

account     include     system-login

password    include     system-login
-password   optional    pam_gnome_keyring.so    use_authtok

session     optional    pam_keyinit.so          force revoke
session     include     system-login
-session    optional    pam_gnome_keyring.so    auto_start
-session    optional    pam_kwallet5.so         auto_start
"#;

    const UPSTREAM_DEBIAN: &str = r#"#%PAM-1.0

# Block login if they are globally disabled
auth    requisite       pam_nologin.so
auth    required        pam_succeed_if.so user != root quiet_success

# auth    sufficient      pam_succeed_if.so user ingroup nopasswdlogin
@include common-auth

# gnome_keyring breaks QProcess
-auth   optional        pam_gnome_keyring.so
-auth   optional        pam_kwallet5.so

@include common-account

# SELinux needs to be the first session rule.  This ensures that any
# lingering context has been cleared.  Without this it is possible that a
# module could execute code in the wrong domain.
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close

# Create a new session keyring.
session optional        pam_keyinit.so force revoke
session required        pam_limits.so
session required        pam_loginuid.so

@include common-session

# SELinux needs to intervene at login time to ensure that the process starts
# in the proper default security context.  Only sessions which are intended
# to run in the user's context should be run after this.
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open
-session optional       pam_gnome_keyring.so auto_start
-session optional       pam_kwallet5.so auto_start

@include common-password

# From the pam_env man page
# Since setting of PAM environment variables can have side effects to other modules, this module should be the last one on the stack.

# Load environment from /etc/environment
session required        pam_env.so

# Load environment from /etc/default/locale and ~/.pam_environment
session required        pam_env.so envfile=/etc/default/locale user_readenv=1
"#;

    /// openSUSE's upstream `plasmalogin` carries NO keyring module at all.
    const UPSTREAM_SUSE: &str = r#"#%PAM-1.0
auth     requisite      pam_nologin.so
auth     substack       common-auth
account  substack       common-account
account  include        postlogin-account
password substack       common-password
password include        postlogin-password
session  required       pam_loginuid.so
session  optional       pam_keyinit.so revoke force
session  substack       common-session
session  include        postlogin-session

"#;

    #[test]
    fn upstream_plasmalogin_stacks_wire_into_a_complete_handoff() {
        // Fedora, Arch and Debian each ship a keyring module with both halves,
        // so wiring them must produce a stack this check passes silently. If
        // irlume's insertion point ever lands below the vendor's keyring auth
        // line, `complete` goes None here and the wallet would stop opening.
        for (os, vendor) in [
            ("fedora", UPSTREAM_FEDORA),
            ("arch", UPSTREAM_ARCH),
            ("debian", UPSTREAM_DEBIAN),
        ] {
            let (wired, changed) = wire_greeter_impl(vendor, true, false, true);
            assert!(changed, "{os}: upstream stack must be wirable");
            let h = keyring_handoff(&wired, "plasmalogin")
                .unwrap_or_else(|| panic!("{os}: releases a credential"));
            assert!(
                h.complete.is_some(),
                "{os}: expected a complete hand-off, got auth_only={:?}",
                h.auth_only
            );
            // And our line really does precede the vendor's keyring auth line.
            let face = wired.find("pam_irlume.so unseal").expect("face line");
            let consumer = wired
                .find("pam_gnome_keyring.so")
                .or_else(|| wired.find("pam_kwallet5.so"))
                .expect("a keyring module");
            assert!(face < consumer, "{os}: our line must precede the wallet's");
        }
    }

    // GDM's shipped stacks, byte-for-byte from GNOME/gdm @ tag 50.0 (the latest
    // release), `data/pam-<os>/gdm-password.pam`. Red Hat is the substack layout,
    // Arch the include layout.
    //
    // gnome-keyring's module needs the same two halves kwallet does: its
    // `pam_sm_authenticate` reads PAM_AUTHTOK and stashes it under
    // "gkr_system_authtok", and `pam_sm_open_session` is what acts on it.

    const UPSTREAM_GDM_REDHAT: &str = r#"auth     [success=done ignore=ignore default=bad] pam_selinux_permit.so
auth        substack      password-auth
auth        optional      pam_gnome_keyring.so
auth        include       postlogin

account     required      pam_nologin.so
account     include       password-auth

password    substack       password-auth
-password   optional       pam_gnome_keyring.so use_authtok

session     required      pam_selinux.so close
session     required      pam_loginuid.so
session     required      pam_selinux.so open
session     optional      pam_keyinit.so force revoke
session     required      pam_namespace.so
session     include       password-auth
session     optional      pam_gnome_keyring.so auto_start
session     include       postlogin
"#;

    const UPSTREAM_GDM_ARCH: &str = r#"#%PAM-1.0

auth       include                     system-local-login
auth       optional                    pam_gnome_keyring.so

account    include                     system-local-login

password   include                     system-local-login
password   optional                    pam_gnome_keyring.so use_authtok

session    include                     system-local-login
session    optional                    pam_gnome_keyring.so auto_start
"#;

    /// GDM `main`'s `data/pam-redhat/gdm-password.pam`, byte-for-byte: the shared
    /// stack is renamed to `gdm-password-auth-substack`, a file GDM does not itself
    /// ship. No release carries this: 45.0 through 50.1 and 51.alpha all still say
    /// `password-auth`. It is latent, and would arrive with an upgrade.
    const UPSTREAM_GDM_RENAMED_SUBSTACK: &str = r#"auth     [success=done ignore=ignore default=bad] pam_selinux_permit.so
auth        substack      gdm-password-auth-substack
auth        optional      pam_gnome_keyring.so
auth        include       postlogin

account     required      pam_nologin.so
account     include       password-auth

password    substack       gdm-password-auth-substack
-password   optional       pam_gnome_keyring.so use_authtok

session     required      pam_selinux.so close
session     required      pam_loginuid.so
session     required      pam_selinux.so open
session     optional      pam_keyinit.so force revoke
session     required      pam_namespace.so
session     include       password-auth
session     optional      pam_gnome_keyring.so auto_start
session     include       postlogin
"#;

    /// GDM's shipped `gdm-fingerprint.pam` (upstream `data/pam-redhat`, released
    /// 50.0). It names neither `pam_fprintd.so` nor any keyring module.
    const UPSTREAM_GDM_FINGERPRINT: &str = r#"auth        substack      fingerprint-auth
auth        include       postlogin

account     required      pam_nologin.so
account     include       fingerprint-auth

password    include       fingerprint-auth

session     required      pam_selinux.so close
session     required      pam_loginuid.so
session     required      pam_selinux.so open
session     optional      pam_keyinit.so force revoke
session     required      pam_namespace.so
session     include       fingerprint-auth
session     include       postlogin
"#;

    #[test]
    fn gdm_fingerprint_wires_the_unseal_and_supplies_the_missing_consumer() {
        // Two defects in one stack: no literal pam_fprintd.so to anchor on (so
        // this used to be a silent no-op), and no keyring module at all (so the
        // unseal line alone would release a token nothing reads).
        assert!(!UPSTREAM_GDM_FINGERPRINT.contains("pam_fprintd.so"));
        assert!(!UPSTREAM_GDM_FINGERPRINT.contains("pam_gnome_keyring.so"));

        let (w, changed) = wire_fp_keyring(UPSTREAM_GDM_FINGERPRINT, "gdm-fingerprint");
        assert!(changed, "the substack must serve as the anchor");
        let lines: Vec<&str> = w.lines().collect();
        let pos = |n: &str| lines.iter().position(|l| l.contains(n));

        let fp = pos("substack      fingerprint-auth").expect("fingerprint substack");
        let unseal = pos("pam_irlume.so keyring").expect("keyring unseal");
        let gkr_auth = lines
            .iter()
            .position(|l| l.contains("pam_gnome_keyring.so") && is_auth_directive(l))
            .expect("gnome-keyring auth line");
        assert_eq!(
            fp + 1,
            unseal,
            "unseal rides directly after the fingerprint auth"
        );
        assert_eq!(
            unseal + 1,
            gkr_auth,
            "the consumer reads it immediately after"
        );

        // Both halves present and paired, so the hand-off actually completes.
        let session_gkr = lines
            .iter()
            .any(|l| l.contains("pam_gnome_keyring.so") && l.contains("auto_start"));
        assert!(
            session_gkr,
            "gnome-keyring needs its session half to unlock"
        );
        // The lines we added are tagged, and use PAM's `-` so a machine without
        // gnome-keyring installed does not get an error logged.
        assert!(w.contains(KEYRING_TAG));
        assert!(w.contains("-auth") && w.contains("-session"));

        // Our OWN session half. On a GNOME account armed with a keyring token
        // (#250) the auth line above only releases the token into PAM data;
        // `open_session` is what delivers it to gnome-keyring's control
        // socket, because the user's runtime directory need not exist yet at
        // auth time. Without this line the token is released and dropped, and
        // the keyring stays locked with nothing naming the reason.
        let ours = lines
            .iter()
            .position(|l| l.contains("pam_irlume.so reseal"))
            .expect("irlume session line: without it a token is never delivered");
        let gkr_session = lines
            .iter()
            .position(|l| l.contains("pam_gnome_keyring.so") && l.contains("auto_start"))
            .expect("gnome-keyring session half");
        assert!(
            ours > gkr_session,
            "ours must run after the line that may START the daemon, or the \
             helper finds nothing listening"
        );
    }

    /// A stack that already carries an irlume session line must not get a
    /// second one: two `reseal` lines mean two reseals and two deliveries per
    /// login, and a duplicate that `unwire` would leave half of behind.
    #[test]
    fn wire_fp_keyring_adds_only_one_irlume_session_line() {
        let (once, _) = wire_fp_keyring(UPSTREAM_GDM_FINGERPRINT, "gdm-fingerprint");
        assert_eq!(once.matches("pam_irlume.so reseal").count(), 1);
        let (twice, _) = wire_fp_keyring(&once, "gdm-fingerprint");
        assert_eq!(
            twice.matches("pam_irlume.so reseal").count(),
            1,
            "re-wiring an already-wired stack duplicated our session line"
        );
    }

    #[test]
    fn wire_fp_keyring_does_not_duplicate_an_existing_keyring_module() {
        // gdm-fingerprint stacks that DO ship a keyring module must get the
        // unseal line only; adding a second consumer would be noise.
        let with_gkr = "#%PAM-1.0\nauth       required      pam_fprintd.so\n\
auth       optional      pam_gnome_keyring.so\n\
session    optional      pam_gnome_keyring.so auto_start\n";
        let (w, changed) = wire_fp_keyring(with_gkr, "gdm-fingerprint");
        assert!(changed);
        assert_eq!(
            w.matches("pam_gnome_keyring.so").count(),
            2,
            "must not add a third keyring line"
        );
        assert!(!w.contains(KEYRING_TAG), "nothing of ours to tag here");
    }

    #[test]
    fn unwiring_removes_our_keyring_lines_but_keeps_the_distros() {
        // Ours are tagged; a distro-shipped keyring line is not, and must survive.
        let (wired, _) = wire_fp_keyring(UPSTREAM_GDM_FINGERPRINT, "gdm-fingerprint");
        let (bare, changed) = unwire_lines(&wired);
        assert!(changed);
        assert!(!bare.contains("pam_gnome_keyring.so"), "ours must go");
        assert!(!bare.contains("pam_irlume.so"));
        // Round-trips back to the upstream content.
        assert_eq!(bare.trim_end(), UPSTREAM_GDM_FINGERPRINT.trim_end());

        // A foreign keyring line is untagged and survives.
        let foreign = "auth       required      pam_fprintd.so\n\
auth       optional      pam_gnome_keyring.so\n";
        let (kept, _) = unwire_lines(foreign);
        assert!(kept.contains("pam_gnome_keyring.so"));
    }

    #[test]
    fn upstream_gdm_stacks_wire_into_a_complete_gnome_keyring_handoff() {
        for (os, vendor) in [("redhat", UPSTREAM_GDM_REDHAT), ("arch", UPSTREAM_GDM_ARCH)] {
            let (wired, changed) = wire_greeter_impl(vendor, true, false, false);
            assert!(changed, "{os}: upstream GDM stack must be wirable");
            let h = keyring_handoff(&wired, "plasmalogin")
                .unwrap_or_else(|| panic!("{os}: releases a credential"));
            assert_eq!(
                h.complete,
                Some("pam_gnome_keyring.so"),
                "{os}: expected a complete hand-off, auth_only={:?}",
                h.auth_only
            );
            let face = wired.find("pam_irlume.so unseal").expect("face line");
            let gkr = wired.find("pam_gnome_keyring.so").expect("keyring module");
            assert!(face < gkr, "{os}: our line must precede gnome-keyring's");
        }
    }

    #[test]
    fn a_renamed_gdm_substack_still_anchors_on_the_substack() {
        // The named list cannot keep up with upstream renames, so an unrecognized
        // `substack` must still be preferred over the first-auth-line guess.
        // Otherwise the jump lands above pam_selinux_permit.so and the password
        // substack runs anyway: the openSUSE bug, arriving via a GDM upgrade.
        assert!(!is_passwd_substack(
            "auth        substack      gdm-password-auth-substack",
            "auth"
        ));
        let (w, changed) = wire_greeter_impl(UPSTREAM_GDM_RENAMED_SUBSTACK, true, false, false);
        assert!(changed);
        let lines: Vec<&str> = w.lines().collect();
        let pos = |n: &str| lines.iter().position(|l| l.contains(n));
        let selinux = pos("pam_selinux_permit.so").expect("selinux line");
        let face = pos("pam_irlume.so unseal").expect("face line");
        let substack = pos("gdm-password-auth-substack").expect("substack");
        let landing = pos("irlume-landing").expect("landing");
        assert!(
            selinux < face,
            "pam_selinux_permit must stay above our line"
        );
        assert!(
            face < substack,
            "our line must precede the password substack"
        );
        assert_eq!(
            substack + 1,
            landing,
            "the jump must land past the substack"
        );
        // The hand-off still resolves, so a rename costs nothing else.
        let h = keyring_handoff(&w, "gdm-password").expect("releases a credential");
        assert_eq!(h.complete, Some("pam_gnome_keyring.so"));
    }

    #[test]
    fn the_first_auth_line_guess_stays_the_last_resort() {
        // Anchor precedence: named stack, then any substack, then the guess.
        let named = ["auth substack password-auth", "auth substack whatever"];
        assert_eq!(find_auth_anchor(&named), Some(0));
        let unnamed = ["auth required pam_env.so", "auth substack whatever"];
        assert_eq!(
            find_auth_anchor(&unnamed),
            Some(1),
            "substack beats a guess"
        );
        let neither = ["auth required pam_env.so", "auth required pam_unix.so"];
        assert_eq!(
            find_auth_anchor(&neither),
            Some(0),
            "guess is still the floor"
        );
        let none: [&str; 0] = [];
        assert_eq!(find_auth_anchor(&none), None);
    }

    #[test]
    fn suse_common_auth_substack_is_the_jump_anchor_and_nologin_survives() {
        let (w, changed) = wire_greeter_impl(UPSTREAM_SUSE, true, false, true);
        assert!(changed);
        let lines: Vec<&str> = w.lines().collect();
        let pos = |needle: &str| lines.iter().position(|l| l.contains(needle));
        let nologin = pos("pam_nologin.so").expect("nologin line");
        let face = pos("pam_irlume.so unseal").expect("face line");
        let substack = pos("substack       common-auth").expect("common-auth substack");
        let landing = pos("irlume-landing").expect("permit landing");

        // The anchor is the password substack, NOT the first auth line. Before
        // this, the jump went above pam_nologin.so: a face match skipped the
        // nologin gate and then met `substack common-auth` anyway, so the user
        // typed a password regardless.
        assert!(
            nologin < face,
            "pam_nologin must still run before face auth"
        );
        assert!(
            face < substack,
            "face line must precede the password substack"
        );
        assert!(
            substack + 1 == landing,
            "success=1 must land on the permit directly after the substack"
        );
        // A substack is atomic for jump counting, so the jump form is right here
        // (an include would need the `sufficient` form instead).
        assert!(w.contains("[success=1 default=ignore]   pam_irlume.so unseal ondemand"));
        assert!(!w.contains("sufficient   pam_irlume.so unseal"));
        // The session reseal now anchors on `substack common-session` rather
        // than being appended at EOF.
        let sess = pos("substack       common-session").expect("common-session");
        let reseal = pos("session    optional                     pam_irlume.so reseal")
            .expect("session reseal");
        assert_eq!(
            sess + 1,
            reseal,
            "session reseal follows the session substack"
        );
    }

    #[test]
    fn common_auth_matching_is_kind_aware_and_leaves_other_phases_alone() {
        assert!(is_passwd_substack(
            "auth     substack   common-auth",
            "auth"
        ));
        assert!(is_passwd_substack(
            "session  substack   common-session",
            "session"
        ));
        // An auth line is not matched against a session-phase stack name, and
        // the account/password phases are never anchors at all.
        assert!(!is_passwd_substack(
            "auth     substack   common-session",
            "auth"
        ));
        assert!(!is_passwd_substack(
            "account  substack   common-account",
            "auth"
        ));
        assert!(!is_passwd_substack(
            "password substack   common-password",
            "session"
        ));
        // A bare `auth include common-auth` is an include a jump can't skip, so
        // it takes the `sufficient` path instead of becoming a jump anchor.
        assert!(is_include_auth_layout("auth include common-auth"));
        // Debian's @include form is still caught by the include layout first.
        assert!(is_include_auth_layout("@include common-auth"));
    }

    #[test]
    fn plasmalogin_fingerprint_keyring_line_lands_above_the_wallet_module() {
        // The KDE fingerprint→KWallet chain. Plasma's greeter runs ONE stack
        // for user auth (plasma-login-manager's PamBackend selects only
        // `plasmalogin` / `plasmalogin-greeter` / `plasmalogin-autologin`, and no
        // fingerprint service, unlike kscreenlocker's kde/kde-fingerprint/
        // kde-smartcard triple). So a greeter fingerprint login happens when
        // the distro's shared stack carries pam_fprintd, provides no password,
        // and the `keyring` line must then release the sealed one ABOVE the
        // vendor's pam_kwallet5 auth line for the wallet to open.
        for (os, vendor, od) in [
            ("fedora", UPSTREAM_FEDORA, true),
            ("arch", UPSTREAM_ARCH, true),
            ("debian", UPSTREAM_DEBIAN, true),
        ] {
            let (w, changed) = wire_greeter_impl(vendor, true, true, od);
            assert!(changed, "{os}");
            let lines: Vec<&str> = w.lines().collect();
            let keyring = lines
                .iter()
                .position(|l| l.contains("pam_irlume.so keyring"))
                .unwrap_or_else(|| panic!("{os}: keyring line missing"));
            let kwallet = lines
                .iter()
                .position(|l| is_auth_directive(l) && l.contains("pam_kwallet5.so"))
                .unwrap_or_else(|| panic!("{os}: kwallet auth line missing"));
            assert!(
                keyring < kwallet,
                "{os}: the released password must be set before pam_kwallet5 reads it"
            );
            let h = keyring_handoff(&w, "plasmalogin").expect("releases a credential");
            assert!(h.complete.is_some(), "{os}");
        }
    }

    #[test]
    fn a_keyring_only_greeter_is_still_checked_for_the_wallet_handoff() {
        // A fingerprint-only box (no face login) wires the greeter with ONLY
        // the `keyring` line and no `unseal` line. The hand-off check used to anchor
        // on `unseal` alone, so this stack was skipped entirely: a missing
        // wallet module after a fingerprint login had no warning at all.
        let (w, changed) = wire_greeter_impl(UPSTREAM_FEDORA, false, true, true);
        assert!(changed);
        assert!(!w.contains("unseal"), "no face line on this box");
        let h = keyring_handoff(&w, "plasmalogin")
            .expect("the keyring line releases a credential and must anchor the check");
        assert!(h.complete.is_some(), "fedora ships the wallet modules");
        // And on the stack that genuinely lacks a wallet module, the warning
        // now fires for the fingerprint path too.
        let (suse, changed) = wire_greeter_impl(UPSTREAM_SUSE, false, true, true);
        assert!(changed);
        let h = keyring_handoff(&suse, "plasmalogin").expect("releases a credential");
        assert_eq!(h.complete, None);
    }

    #[test]
    fn upstream_suse_plasmalogin_ships_no_keyring_module_and_is_flagged() {
        // openSUSE's upstream file has neither pam_kwallet5 nor pam_gnome_keyring,
        // so a face login there releases a password nothing reads. This is the
        // real-world case the warning exists for, not a synthetic one.
        assert!(!UPSTREAM_SUSE.contains("pam_kwallet"));
        assert!(!UPSTREAM_SUSE.contains("pam_gnome_keyring"));
        let (wired, changed) = wire_greeter_impl(UPSTREAM_SUSE, true, false, true);
        assert!(changed);
        let h = keyring_handoff(&wired, "plasmalogin").expect("releases a credential");
        assert_eq!(h.complete, None);
        assert!(h.auth_only.is_empty());
    }

    #[test]
    fn directive_cuts_at_the_comment_exactly_as_pam_does() {
        assert_eq!(
            directive("auth optional pam_unix.so"),
            "auth optional pam_unix.so"
        );
        assert_eq!(
            directive("  auth optional pam_unix.so  # note"),
            "auth optional pam_unix.so  "
        );
        assert_eq!(directive("# whole line comment"), "");
        assert_eq!(directive(""), "");
        // libpam truncates at '#' even mid-token (pam_exec received `arg` from
        // a literal `arg#embedded`), so cutting at the FIRST '#' anywhere is
        // the faithful reading, not an approximation.
        assert_eq!(
            directive("auth optional pam_unix.so arg#embedded"),
            "auth optional pam_unix.so arg"
        );
    }

    #[test]
    fn a_module_named_only_in_a_comment_is_never_treated_as_configured() {
        // libpam strips a trailing comment before tokenizing, so none of these
        // lines load the module they mention. Matching the raw line would make
        // irlume disagree with the thing it is configuring.
        //
        // content_has_module is the dangerous one: it gates the whole wiring
        // path, so a false positive means `login enable` silently writes
        // nothing and reports the stack as already wired.
        assert!(!content_has_module(
            "auth required pam_unix.so  # was pam_irlume.so\n"
        ));
        assert!(content_has_module("auth sufficient pam_irlume.so\n"));

        // Anchors must not be invented out of comment text either.
        assert!(!is_passwd_substack(
            "auth required pam_unix.so # substack password-auth",
            "auth"
        ));
        assert!(!is_include_auth_layout(
            "auth required pam_unix.so # @include common-auth"
        ));
        assert!(!is_auth_substack_anchor(
            "auth required pam_unix.so # substack whatever"
        ));
        assert!(!is_fingerprint_auth(
            "auth required pam_unix.so # substack fingerprint-auth"
        ));
        assert!(!is_auth_directive("# auth required pam_unix.so"));

        // Nor a keyring consumer.
        assert_eq!(
            consumer_active_for(
                "auth required pam_unix.so # see pam_gnome_keyring.so",
                "gdm-password"
            ),
            None
        );

        // A stack whose only mention of a keyring module is a comment has no
        // hand-off, however complete it looks to a grep.
        let commented = "#%PAM-1.0\n\
auth       [success=1 default=ignore]   pam_irlume.so unseal ondemand\n\
auth       substack      password-auth\n\
auth       optional                     pam_permit.so   # irlume-landing\n\
auth       optional      pam_deny.so    # pam_gnome_keyring.so would go here\n\
session    optional      pam_deny.so    # pam_gnome_keyring.so auto_start\n";
        let h = keyring_handoff(commented, "gdm-password").expect("releases a credential");
        assert_eq!(h.complete, None);
        assert!(h.auth_only.is_empty());
    }

    #[test]
    fn unwiring_matches_modules_on_the_directive_but_tags_on_the_raw_line() {
        // Our tags ARE comments, so they must still be found there; a foreign
        // line that merely names one of our modules in a comment must survive.
        let stack = "auth required pam_unix.so  # not pam_irlume.so, just a note\n\
auth       optional                     pam_permit.so   # irlume-landing\n\
-auth      optional      pam_gnome_keyring.so   # irlume-keyring\n\
-auth      optional      pam_gnome_keyring.so\n";
        let (out, changed) = unwire_lines(stack);
        assert!(changed);
        assert!(
            out.contains("not pam_irlume.so, just a note"),
            "comment-only mention survives"
        );
        assert!(!out.contains("irlume-landing"), "our tagged landing goes");
        assert!(
            !out.contains("irlume-keyring"),
            "our tagged keyring line goes"
        );
        assert!(
            out.contains("-auth      optional      pam_gnome_keyring.so\n"),
            "the distro's untagged keyring line survives"
        );
    }

    #[test]
    fn line_continuation_semantics_match_the_pam_assembler() {
        // Each row was executed against libpam via pam_exec.so:
        // a trailing backslash on a directive joins the NEXT physical line into
        // this one (the module received the next line's text as its argument);
        assert!(has_line_continuation(
            "auth optional pam_exec.so run.sh \\\n  CONT\n"
        ));
        // whitespace after the backslash does not defuse it (the follow-up
        // line was still swallowed);
        assert!(has_line_continuation(
            "auth optional pam_exec.so run.sh A \\   \n"
        ));
        // a backslash at the end of a COMMENT does not continue (both modules
        // ran as separate lines);
        assert!(!has_line_continuation(
            "auth optional pam_exec.so run.sh FIRST # note \\\nauth optional pam_exec.so run.sh SECOND\n"
        ));
        // and a whole-line comment ending in a backslash is still just a comment.
        assert!(!has_line_continuation("# just a comment \\\n"));
        // A backslash mid-line is an ordinary character, not a continuation.
        assert!(!has_line_continuation(
            "auth optional pam_unix.so arg\\more\n"
        ));
    }

    #[test]
    fn a_stack_using_line_continuations_is_never_rewritten() {
        // PAM evaluates a continued pair as ONE logical line, so a line-based
        // insertion after the anchor would splice our stanza into the middle of
        // it. Every transform must refuse the whole file: staged-never-written,
        // the same contract as a missing anchor.
        let cont =
            "#%PAM-1.0\nauth substack \\\n    password-auth\nsession include password-auth\n";
        assert!(has_line_continuation(cont));
        let (g, changed) = wire_greeter_impl(cont, true, true, true);
        assert!(!changed);
        assert_eq!(g, cont);
        let (l, changed) = wire_lock(cont);
        assert!(!changed);
        assert_eq!(l, cont);
        let (v, changed) = wire_verify_service(cont);
        assert!(!changed);
        assert_eq!(v, cont);
        let fp = "auth required pam_fprintd.so \\\n    likeauth\n";
        let (f, changed) = wire_fp_keyring(fp, "gdm-fingerprint");
        assert!(!changed);
        assert_eq!(f, fp);
        // The advisory stays silent too: a verdict from lines PAM does not
        // evaluate as written would be worse than no verdict.
        let wired = "auth sufficient pam_irlume.so unseal ondemand\n\
-auth optional pam_kwallet5.so \\\n    someopt\n";
        assert!(keyring_handoff(wired, "plasmalogin").is_none());
    }

    #[test]
    fn no_upstream_fixture_uses_line_continuations() {
        // What makes the refusal gate behaviour-neutral on real stacks. If a
        // distro starts shipping continuations, this fails and the gate needs
        // real assembly support instead of refusal.
        for (name, body) in [
            ("plasmalogin fedora", UPSTREAM_FEDORA),
            ("plasmalogin arch", UPSTREAM_ARCH),
            ("plasmalogin debian", UPSTREAM_DEBIAN),
            ("plasmalogin suse", UPSTREAM_SUSE),
            ("gdm redhat", UPSTREAM_GDM_REDHAT),
            ("gdm arch", UPSTREAM_GDM_ARCH),
            ("gdm renamed", UPSTREAM_GDM_RENAMED_SUBSTACK),
            ("gdm fingerprint", UPSTREAM_GDM_FINGERPRINT),
        ] {
            assert!(!has_line_continuation(body), "{name}");
        }
    }

    #[test]
    fn only_if_gating_is_matched_the_way_gkr_pam_matches_it() {
        // gkr-pam's `evaluate_inlist` matches whole comma-separated items, so a
        // prefix must NOT satisfy it: `only_if=gdm` leaves gdm-fingerprint out.
        let line = "-auth optional pam_gnome_keyring.so only_if=gdm,gdm-password";
        assert_eq!(
            consumer_active_for(line, "gdm-password"),
            Some("pam_gnome_keyring.so")
        );
        assert_eq!(consumer_active_for(line, "gdm-fingerprint"), None);
        assert_eq!(
            consumer_active_for(
                "-auth optional pam_gnome_keyring.so only_if=gdm",
                "gdm-fingerprint"
            ),
            None,
            "a prefix must not satisfy a whole-item list"
        );
        // No only_if= at all → active everywhere. kwallet has no such option.
        assert_eq!(
            consumer_active_for("-auth optional pam_gnome_keyring.so", "anything"),
            Some("pam_gnome_keyring.so")
        );
        assert_eq!(
            consumer_active_for("-auth optional pam_kwallet5.so", "plasmalogin"),
            Some("pam_kwallet5.so")
        );
        // A commented line is never a consumer.
        assert_eq!(
            consumer_active_for("# -auth optional pam_gnome_keyring.so", "plasmalogin"),
            None
        );
    }

    #[test]
    fn a_keyring_line_gated_off_for_this_service_is_not_a_hand_off() {
        // The stack names pam_gnome_keyring on both halves, but `only_if=` means
        // every entry point returns PAM_SUCCESS without reading the token. A
        // module-name grep would call this complete and reassure the user that a
        // wallet will open when nothing will.
        let gated = "#%PAM-1.0\n\
auth       [success=1 default=ignore]   pam_irlume.so unseal ondemand\n\
auth       substack      password-auth\n\
auth       optional                     pam_permit.so   # irlume-landing\n\
-auth      optional      pam_gnome_keyring.so only_if=gdm-password\n\
session    include       password-auth\n\
-session   optional      pam_gnome_keyring.so auto_start only_if=gdm-password\n";
        assert_eq!(
            keyring_handoff(gated, "gdm-password").unwrap().complete,
            Some("pam_gnome_keyring.so"),
            "on the listed service it really is a hand-off"
        );
        let h = keyring_handoff(gated, "gdm-fingerprint").expect("releases a credential");
        assert_eq!(
            h.complete, None,
            "gated off here, so nothing opens the wallet"
        );
        assert!(h.auth_only.is_empty());
    }

    #[test]
    fn wire_fp_keyring_supplies_a_consumer_when_the_existing_one_is_gated_off() {
        // Same trap on the fingerprint path: a gated line must not suppress the
        // consumer we would otherwise add, or the unlock silently does nothing.
        let gated = "#%PAM-1.0\nauth       required      pam_fprintd.so\n\
-auth      optional      pam_gnome_keyring.so only_if=gdm-password\n\
-session   optional      pam_gnome_keyring.so auto_start only_if=gdm-password\n";
        let (w, changed) = wire_fp_keyring(gated, "gdm-fingerprint");
        assert!(changed);
        assert!(
            w.contains(KEYRING_TAG),
            "must add our own consumer, the existing one stands down here"
        );
        // And on the service the existing line DOES cover, we add nothing.
        let (w2, _) = wire_fp_keyring(gated, "gdm-password");
        assert!(!w2.contains(KEYRING_TAG));
    }

    #[test]
    fn a_split_handoff_across_two_modules_is_not_complete() {
        // The reason the halves are paired per module: kwallet5 reads the token
        // but has no session line, while gnome-keyring has only a session line.
        // Counting the halves separately would call this complete; nothing opens.
        let split = "#%PAM-1.0\n\
auth       [success=1 default=ignore]   pam_irlume.so unseal ondemand\n\
auth       substack      password-auth\n\
auth       optional                     pam_permit.so   # irlume-landing\n\
-auth      optional      pam_kwallet5.so\n\
session    include       password-auth\n\
-session   optional      pam_gnome_keyring.so auto_start\n";
        let h = keyring_handoff(split, "plasmalogin").expect("releases a credential");
        assert_eq!(h.complete, None);
        assert_eq!(h.auth_only, vec!["pam_kwallet5.so"]);
    }

    /// Fedora KDE `plasmalogin` (substack layout) AFTER irlume wires it, with
    /// the vendor kwallet lines in their shipped positions.
    const PLASMA_WIRED: &str = "#%PAM-1.0\n\
auth       [success=1 default=ignore]   pam_irlume.so unseal ondemand\n\
auth       substack      password-auth\n\
auth       optional                     pam_permit.so   # irlume-landing\n\
auth       optional                     pam_irlume.so reseal\n\
-auth      optional      pam_kwallet5.so\n\
auth       include       postlogin\n\
account    include       password-auth\n\
session    include       password-auth\n\
-session   optional      pam_kwallet5.so auto_start\n\
session    optional                     pam_irlume.so reseal\n";

    #[test]
    fn plasmalogin_with_kwallet_has_a_complete_handoff() {
        let h = keyring_handoff(PLASMA_WIRED, "plasmalogin").expect("stack releases a credential");
        // The jump skips exactly the substack and lands on the permit, so the
        // vendor kwallet auth line below it does observe our PAM_AUTHTOK.
        assert_eq!(h.complete, Some("pam_kwallet5.so"));
        assert!(h.auth_only.is_empty());
    }

    /// The Fedora KDE vendor `plasmalogin` as shipped: kwallet lines in place,
    /// irlume not yet wired.
    const PLASMA_VENDOR: &str = "#%PAM-1.0\n\
auth       substack      password-auth\n\
-auth      optional      pam_kwallet5.so\n\
auth       include       postlogin\n\
account    include       password-auth\n\
session    include       password-auth\n\
-session   optional      pam_kwallet5.so auto_start\n";

    #[test]
    fn what_we_wire_is_what_the_handoff_check_approves() {
        // Closes the loop between the two halves: the wiring must insert the
        // unseal line ABOVE the vendor's kwallet auth line, which is exactly the
        // order the check demands. If either side moves, this fails rather than
        // shipping a stack we wire and then warn about.
        let (wired, changed) = wire_greeter_impl(PLASMA_VENDOR, true, false, true);
        assert!(changed);
        let h =
            keyring_handoff(&wired, "plasmalogin").expect("a wired greeter releases a credential");
        assert_eq!(h.complete, Some("pam_kwallet5.so"));
        assert!(h.auth_only.is_empty());
        let face = wired.find("pam_irlume.so unseal").unwrap();
        let kwallet = wired.find("pam_kwallet5.so").unwrap();
        assert!(face < kwallet, "our line must precede the wallet's");
    }

    #[test]
    fn arch_include_greeter_we_wire_also_passes_the_handoff_check() {
        const ARCH_VENDOR: &str = "#%PAM-1.0\n\
auth        include     system-login\n\
-auth       optional    pam_kwallet5.so\n\
account     include     system-login\n\
session     include     system-login\n\
-session    optional    pam_kwallet5.so auto_start\n";
        let (wired, changed) = wire_greeter_impl(ARCH_VENDOR, true, false, true);
        assert!(changed);
        let h =
            keyring_handoff(&wired, "plasmalogin").expect("a wired greeter releases a credential");
        assert_eq!(h.complete, Some("pam_kwallet5.so"));
        assert!(h.auth_only.is_empty());
    }

    #[test]
    fn plasmalogin_without_any_keyring_module_is_flagged() {
        let stripped: String = PLASMA_WIRED
            .lines()
            .filter(|l| !l.contains("pam_kwallet5.so"))
            .collect::<Vec<_>>()
            .join("\n");
        let h = keyring_handoff(&stripped, "plasmalogin").expect("stack releases a credential");
        // Nothing reads the released password: this is the silent case that used
        // to report as "wired ✓" while the wallet kept prompting.
        assert_eq!(h.complete, None);
        assert!(h.auth_only.is_empty());
    }

    #[test]
    fn kwallet_above_the_irlume_line_does_not_count_as_a_consumer() {
        // Ordering, not mere presence, is what matters: an auth line ABOVE ours
        // runs before the token exists, so the wallet stays locked.
        let above = "#%PAM-1.0\n\
-auth      optional      pam_kwallet5.so\n\
auth       [success=1 default=ignore]   pam_irlume.so unseal ondemand\n\
auth       substack      password-auth\n\
-session   optional      pam_kwallet5.so auto_start\n";
        let h = keyring_handoff(above, "plasmalogin").expect("stack releases a credential");
        assert_eq!(
            h.complete, None,
            "a consumer above our line cannot see the token"
        );
        assert!(h.auth_only.is_empty());
    }

    #[test]
    fn arch_include_layout_handoff_is_detected() {
        let arch = "#%PAM-1.0\n\
auth       sufficient   pam_irlume.so unseal ondemand kr\n\
auth       include     system-login\n\
auth       optional                     pam_irlume.so reseal\n\
-auth      optional    pam_kwallet5.so\n\
-session   optional    pam_kwallet5.so auto_start\n";
        let h = keyring_handoff(arch, "plasmalogin").expect("stack releases a credential");
        assert_eq!(h.complete, Some("pam_kwallet5.so"));
        assert!(h.auth_only.is_empty());
    }

    #[test]
    fn auth_line_without_a_session_line_is_reported_separately() {
        // pam_kwallet5 derives the key at auth time but it is the SESSION line
        // that starts the daemon and hands it over; auth alone opens nothing.
        let no_session: String = PLASMA_WIRED
            .lines()
            .filter(|l| !(l.contains("pam_kwallet5.so") && l.contains("session")))
            .collect::<Vec<_>>()
            .join("\n");
        let h = keyring_handoff(&no_session, "plasmalogin").expect("stack releases a credential");
        assert_eq!(h.complete, None);
        assert_eq!(h.auth_only, vec!["pam_kwallet5.so"]);
    }

    #[test]
    fn gnome_keyring_counts_as_a_consumer_too() {
        let gnome = PLASMA_WIRED.replace("pam_kwallet5.so", "pam_gnome_keyring.so");
        let h = keyring_handoff(&gnome, "plasmalogin").expect("stack releases a credential");
        assert_eq!(h.complete, Some("pam_gnome_keyring.so"));
        assert!(h.auth_only.is_empty());
    }

    #[test]
    fn a_verify_only_stack_is_not_judged_for_a_wallet() {
        // sudo / polkit carry the plain verify stanza: no `unseal`, so no
        // credential is released and there is nothing for a wallet to consume.
        let sudo = "#%PAM-1.0\nauth       sufficient                   pam_irlume.so\n\
@include common-auth\n";
        assert!(keyring_handoff(sudo, "plasmalogin").is_none());
    }

    #[test]
    fn a_commented_out_keyring_line_is_not_a_consumer() {
        let commented = PLASMA_WIRED.replace(
            "-auth      optional      pam_kwallet5.so",
            "#-auth      optional      pam_kwallet5.so",
        );
        let h = keyring_handoff(&commented, "plasmalogin").expect("stack releases a credential");
        assert_eq!(h.complete, None);
        assert!(h.auth_only.is_empty());
    }

    #[test]
    fn passwd_substack_matcher() {
        assert!(is_passwd_substack(
            "auth     substack      password-auth",
            "auth"
        ));
        assert!(is_passwd_substack("auth  include system-auth", "auth"));
        assert!(is_passwd_substack(
            "session include password-auth",
            "session"
        ));
        assert!(!is_passwd_substack("auth required pam_unix.so", "auth"));
        assert!(!is_passwd_substack("# auth substack password-auth", "auth"));
    }

    #[test]
    fn dm_pam_services_maps_each_login_manager_to_its_services() {
        // GDM (and the Debian gdm3 alias) drive a separate fingerprint service.
        assert_eq!(
            dm_pam_services("gdm"),
            ("gdm-password", Some("gdm-fingerprint"))
        );
        assert_eq!(
            dm_pam_services("gdm3"),
            ("gdm-password", Some("gdm-fingerprint"))
        );
        // Single-greeter DMs: KDE/others put fingerprint on the lock screen, so
        // no separate fingerprint service here.
        assert_eq!(dm_pam_services("sddm"), ("sddm", None));
        assert_eq!(dm_pam_services("plasmalogin"), ("plasmalogin", None));
        assert_eq!(dm_pam_services("lightdm"), ("lightdm", None));
        assert_eq!(dm_pam_services("greetd"), ("greetd", None));
        assert_eq!(dm_pam_services("ly"), ("ly", None));
        assert_eq!(dm_pam_services("cosmic-greeter"), ("cosmic-greeter", None));
        // Anything unrecognised is named "(unknown)" with no fingerprint service.
        assert_eq!(dm_pam_services("mystery-dm"), ("(unknown)", None));
    }

    /// The warning names a login manager, so every entry must be one irlume
    /// actually knows; a typo would warn about a DM that never runs, or stay
    /// silent on the one that does. The list is deliberately short: absence means
    /// "not measured", never "displays it fine".
    #[test]
    fn every_dm_that_hides_pam_text_info_is_a_login_manager_irlume_knows() {
        for dm in DM_HIDES_PAM_TEXT_INFO {
            assert!(
                DM_PAM_SERVICES.iter().any(|(name, _, _)| name == dm),
                "{dm} is not in DM_PAM_SERVICES, so the warning names a login \
                 manager irlume cannot otherwise identify"
            );
        }
        // The finding that motivated this: measured on hardware, twice.
        assert!(DM_HIDES_PAM_TEXT_INFO.contains(&"plasmalogin"));
        // An unmeasured login manager must not be warned about. sddm is the
        // near miss: same KDE family, different greeter, never checked here.
        assert!(!DM_HIDES_PAM_TEXT_INFO.contains(&"sddm"));
    }

    /// A templated unit carries its instance in the unit name, and the tables
    /// here are keyed on the bare name. `ly@tty2` must reduce to `ly`, or a DM
    /// irlume fully supports reads as unknown and gets no wiring.
    #[test]
    fn a_template_instance_reduces_to_the_base_display_manager_name() {
        for (unit, want) in [
            ("ly@tty2.service", "ly"),
            ("ly@tty1.service", "ly"),
            ("ly.service", "ly"),
            ("sddm.service", "sddm"),
        ] {
            let stem = std::path::Path::new(unit)
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let base = stem.split('@').next().unwrap_or(&stem);
            assert_eq!(base, want, "{unit}");
            assert!(
                dm_pam_services(base).0 != "(unknown)",
                "{unit} must resolve to a known PAM service"
            );
        }
    }

    /// The `.wants` fallback exists for display managers that set no
    /// `display-manager.service`, and must not start reporting arbitrary enabled
    /// units as the login manager.
    #[test]
    fn the_wants_fallback_only_matches_known_display_managers() {
        for dm in WANTS_ONLY_DMS {
            assert!(
                DM_PAM_SERVICES.iter().any(|(name, _, _)| name == dm),
                "{dm} is matched in .wants but is not a login manager irlume knows"
            );
            assert!(dm_wirable(dm), "{dm} is detected but cannot be wired");
        }
        // Plenty of unrelated services live in these directories.
        for other in ["NetworkManager", "sshd", "docker", "bluetooth"] {
            assert!(
                !WANTS_ONLY_DMS.contains(&other),
                "{other} must never be read as a display manager"
            );
        }
    }

    #[test]
    fn a_login_manager_is_recognized_only_when_something_can_wire_it() {
        // Walk the whole table, so a login manager added later cannot claim
        // support without a recipe. `ly` is the case that motivated this: it
        // mapped to a `ly` PAM service that no `Svc` covered, so `login enable`
        // never touched it while doctor called the machine supported. Every row
        // now has a recipe, and this fails if one is added without.
        for (dm, greeter, fp) in DM_PAM_SERVICES {
            assert!(dm_wirable(dm), "{dm} is claimed as supported");
            assert!(service_wirable(greeter), "{dm} greeter {greeter}");
            if let Some(fp) = fp {
                assert!(service_wirable(fp), "{dm} fingerprint service {fp}");
            }
        }
        // Never heard of it at all: the pre-existing case, still false.
        assert!(!dm_wirable("some-new-greeter"));
    }

    #[test]
    fn surface_facts_cover_every_wirable_service_in_report_order() {
        // The order is the order the human report prints, and the ids are
        // published by `login status --json`. Both are API: the first would
        // reshuffle a report people paste into bug threads, the second would
        // break a consumer keying off an id.
        let facts = surface_facts();
        let seen: Vec<(&str, &str)> = facts.iter().map(|f| (f.id, f.role)).collect();
        assert_eq!(
            seen,
            vec![
                ("gdm-password", ROLE_LOGIN),
                ("sddm", ROLE_LOGIN),
                ("lightdm", ROLE_LOGIN),
                ("plasmalogin", ROLE_LOGIN),
                ("cosmic-greeter", ROLE_LOGIN),
                ("greetd", ROLE_LOGIN),
                ("ly", ROLE_LOGIN),
                ("gdm-fingerprint", ROLE_LOGIN_FP),
                ("kde", ROLE_LOCK),
                ("sudo", ROLE_SUDO),
                ("polkit-1", ROLE_POLKIT),
            ]
        );
        for f in &facts {
            // A mode describes how face fires here; without wiring nothing fires.
            assert_eq!(f.mode.is_some(), f.wired, "{} mode vs wired", f.id);
            // An absent service is still reported, and reports nothing wired.
            assert!(f.present || !f.wired, "{} wired while absent", f.id);
        }
    }

    #[test]
    fn label_of_takes_the_basename() {
        assert_eq!(label_of("/etc/pam.d/gdm-password"), "gdm-password");
        assert_eq!(label_of("/etc/pam.d/kde"), "kde");
        assert_eq!(label_of("sudo"), "sudo"); // no slash → whole string
    }

    #[test]
    fn is_include_auth_layout_matches_only_the_inline_includes() {
        // Debian @include forms.
        assert!(is_include_auth_layout("@include common-auth"));
        assert!(is_include_auth_layout("@include login"));
        // Arch inline includes a success=N jump cannot skip.
        assert!(is_include_auth_layout(
            "auth       include     system-login"
        ));
        assert!(is_include_auth_layout("auth include system-local-login"));
        assert!(is_include_auth_layout("auth include system-auth"));
        // NOT an include-auth layout: a Fedora substack (atomic for jumps), a
        // different @include, or an include of a non-login file.
        assert!(!is_include_auth_layout(
            "auth     substack     password-auth"
        ));
        assert!(!is_include_auth_layout("@include common-account"));
        assert!(!is_include_auth_layout("auth include password-auth"));
        assert!(!is_include_auth_layout("account include system-login"));
    }

    #[test]
    fn is_auth_directive_recognises_auth_lines_only() {
        assert!(is_auth_directive("auth required pam_unix.so"));
        assert!(is_auth_directive("-auth optional pam_gnome_keyring.so")); // leading '-'
        assert!(is_auth_directive("   auth   substack password-auth")); // leading ws
        assert!(!is_auth_directive("# auth required pam_unix.so")); // comment
        assert!(!is_auth_directive("account required pam_unix.so"));
        assert!(!is_auth_directive("session optional pam_unix.so"));
    }

    // gdm-fingerprint: the keyring unseal must land right AFTER pam_fprintd's
    // auth line and BEFORE pam_gnome_keyring's auth line, so the sealed password
    // is set before the keyring module reads it.
    const GDM_FP: &str = "#%PAM-1.0\nauth       required      pam_env.so\nauth       required      pam_fprintd.so\nauth       optional      pam_gnome_keyring.so\nsession    optional      pam_gnome_keyring.so auto_start\n";

    #[test]
    fn wire_fp_keyring_inserts_between_fprintd_and_the_keyring_auth_line() {
        let (w, changed) = wire_fp_keyring(GDM_FP, "gdm-fingerprint");
        assert!(changed);
        let lines: Vec<&str> = w.lines().collect();
        let fp = lines
            .iter()
            .position(|l| l.contains("pam_fprintd.so"))
            .unwrap();
        let kr = lines
            .iter()
            .position(|l| l.contains("pam_irlume.so keyring"))
            .unwrap();
        let gk = lines
            .iter()
            .position(|l| l.trim_start().starts_with("auth") && l.contains("pam_gnome_keyring.so"))
            .unwrap();
        assert!(
            fp < kr && kr < gk,
            "keyring unseal must sit fprintd→keyring"
        );
        // Idempotent: a second pass is a no-op.
        let (w2, c2) = wire_fp_keyring(&w, "gdm-fingerprint");
        assert!(!c2 && w2 == w);
    }

    // A consumer only counts when ONE module holds BOTH halves in working
    // positions, the same per-module rule `keyring_handoff` reports by. Any
    // single keyring line used to suppress our pair, and the fingerprint
    // login then succeeded with the wallet still locked.

    #[test]
    fn fp_session_only_does_not_suppress_the_auth_consumer() {
        // Session half alone: nothing reads the token irlume releases.
        let stack = "auth required pam_fprintd.so\n\
-session optional pam_gnome_keyring.so auto_start\n";
        let (wired, changed) = wire_fp_keyring(stack, "gdm-fingerprint");
        assert!(changed);
        assert!(wired.contains(FP_GKR_AUTH), "{wired}");
        assert!(
            keyring_handoff(&wired, "gdm-fingerprint")
                .expect("wired stack releases a credential")
                .complete
                .is_some(),
            "the wired stack must form a complete hand-off:\n{wired}"
        );
    }

    #[test]
    fn fp_auth_only_does_not_suppress_the_session_consumer() {
        // Auth half alone: the key is stashed and dropped, no daemon starts.
        let stack = "auth required pam_fprintd.so\n\
-auth optional pam_gnome_keyring.so\n";
        let (wired, changed) = wire_fp_keyring(stack, "gdm-fingerprint");
        assert!(changed);
        assert!(wired.contains(FP_GKR_SESSION), "{wired}");
        assert!(
            keyring_handoff(&wired, "gdm-fingerprint")
                .expect("wired stack releases a credential")
                .complete
                .is_some(),
            "the wired stack must form a complete hand-off:\n{wired}"
        );
    }

    #[test]
    fn fp_consumer_above_the_anchor_does_not_count() {
        // Both halves present, but the auth half sits ABOVE pam_fprintd.so:
        // it runs before PAM_AUTHTOK exists, so it consumes nothing, and it
        // must not suppress a pair that would actually work.
        let stack = "-auth optional pam_gnome_keyring.so\n\
auth required pam_fprintd.so\n\
-session optional pam_gnome_keyring.so auto_start\n";
        let (wired, changed) = wire_fp_keyring(stack, "gdm-fingerprint");
        assert!(changed);
        let release = wired
            .find("pam_irlume.so keyring")
            .expect("unseal line present");
        let tagged_auth = wired.find(FP_GKR_AUTH).expect("tagged auth supplied");
        assert!(
            release < tagged_auth,
            "the supplied consumer must sit below the release:\n{wired}"
        );
    }

    // Regression for the vendor-override path: the transform refusing (a
    // continued vendor file has no judgeable lines) must refuse the
    // materialization too. This branch used to discard `changed`, write an
    // override with NO irlume line over the vendor file, and report ✓.
    #[test]
    fn wire_service_override_does_not_materialize_a_refused_vendor_stack() {
        let dir = TestDir::new("override-refused");
        let vendor = dir.0.join("plasmalogin.vendor");
        std::fs::write(
            &vendor,
            "auth substack \\\n    password-auth\nsession include password-auth\n",
        )
        .unwrap();
        let etc = dir.0.join("plasmalogin");
        let svc = Svc {
            etc: leak(&etc),
            vendor: Some(leak(&vendor)),
        };
        let wire = |c: &str| wire_greeter_impl(c, true, false, true);
        let outcome = wire_service(&svc, true, true, &wire).unwrap();
        assert_eq!(outcome.change, PlannedChange::NoAnchor);
        assert!(
            !etc.exists(),
            "a refused transform must not create an override"
        );
        assert!(
            !outcome.message.starts_with('✓'),
            "refusal must not read as successful wiring: {}",
            outcome.message
        );
    }

    #[test]
    fn wire_fp_keyring_needs_an_fprintd_anchor() {
        // No pam_fprintd line → nothing to anchor to → unchanged.
        let (w, changed) =
            wire_fp_keyring("#%PAM-1.0\nauth required pam_unix.so\n", "gdm-fingerprint");
        assert!(!changed);
        assert_eq!(w, "#%PAM-1.0\nauth required pam_unix.so\n");
        // A commented fprintd line is not an anchor either.
        let (_, c) = wire_fp_keyring(
            "#%PAM-1.0\n# auth required pam_fprintd.so\n",
            "gdm-fingerprint",
        );
        assert!(!c);
    }

    #[test]
    fn wire_greeter_keyring_only_in_include_layout_adds_no_face_line() {
        // face=false, keyring=true on a @include greeter: keyring + reseal ride
        // in, but no face `unseal` line and no permit landing.
        let (w, changed) = wire_greeter_impl(COSMIC, false, true, true);
        assert!(changed);
        assert!(w.contains("pam_irlume.so keyring"));
        assert!(w.contains("pam_irlume.so reseal"));
        assert!(!w.contains("unseal")); // no face line at all
    }

    #[test]
    fn wire_greeter_without_any_auth_anchor_is_a_noop() {
        // No include layout, no password substack, no auth directive → unchanged.
        let src = "#%PAM-1.0\naccount required pam_unix.so\nsession required pam_unix.so\n";
        let (w, changed) = wire_greeter_impl(src, true, false, false);
        assert!(!changed);
        assert_eq!(w, src);
    }

    // Regression: face-sudo was dead code on Debian/Ubuntu. The old anchor only
    // matched lines whose first token is `auth`, and Ubuntu 26.04's
    // /etc/pam.d/sudo has none (session lines plus `@include common-auth`), so
    // the stanza was appended at EOF — after the password stack, where it can
    // never grant: a wrong password dies in common-auth's pam_deny first, a
    // right one already succeeded via pam_unix.
    #[test]
    fn face_sudo_wires_above_the_ubuntu_include_layout() {
        // Verbatim from `podman run ubuntu:26.04` with the sudo package installed.
        const UBUNTU_SUDO: &str = "#%PAM-1.0\n\n# Set up user limits from /etc/security/limits.conf.\nsession    required   pam_limits.so\n\nsession    required   pam_env.so readenv=1 user_readenv=0\nsession    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0\n\n@include common-auth\n@include common-account\n@include common-session-noninteractive\n";
        let (wired, changed) = wire_verify_service(UBUNTU_SUDO);
        assert!(changed);
        let lines: Vec<&str> = wired.lines().collect();
        let stanza = lines.iter().position(|l| l.contains(MODULE)).unwrap();
        let common_auth = lines
            .iter()
            .position(|l| l.trim_start().starts_with("@include common-auth"))
            .unwrap();
        assert!(
            stanza < common_auth,
            "stanza must precede the password stack:\n{wired}"
        );
        assert!(
            !wired.trim_end().ends_with(VERIFY_STANZA),
            "must not append at EOF"
        );
        // The `session pam_env` line above it is not an auth anchor.
        assert!(stanza > 1, "{wired}");
    }

    // Regression found on hardware during the 0.7.0 soak: stripping
    // /etc/pam.d/gdm-fingerprint on a wired box survived BOTH a manual
    // `login reconcile` and the path unit's automatic run, because the
    // "is anything broken?" check only looked at the login greeter and the
    // lock screen. sudo and polkit had the same blind spot.
    #[test]
    fn every_wired_surface_counts_as_a_regression_not_just_the_greeter() {
        let dir = TestDir::new("surfaces");
        let wired = dir.0.join("wired");
        let polkit_ok = dir.0.join("polkit_ok");
        let stripped = dir.0.join("stripped");
        let vendor = dir.0.join("vendor");
        std::fs::write(&wired, "auth sufficient pam_irlume.so\n").unwrap();
        // polkit's INTACT shape is the abort=die stanza; a plain `sufficient`
        // there is the pre-#424 wiring whose shake-decline does nothing.
        std::fs::write(
            &polkit_ok,
            format!(
                "{}\nauth include system-auth\n",
                stanzas::POLKIT_VERIFY_STANZA
            ),
        )
        .unwrap();
        std::fs::write(&stripped, "auth include system-auth\n").unwrap();
        std::fs::write(&vendor, "auth include system-auth\n").unwrap();
        let gone = dir.0.join("gone");

        // Nothing recorded as wired: nothing to maintain.
        assert!(!surfaces_regressed(None, None, &[]));
        // Intact surfaces are not regressions.
        assert!(!surfaces_regressed(
            Some(&wired),
            Some((&polkit_ok, None)),
            &[&wired]
        ));
        // Each surface on its own must trigger a repair.
        assert!(surfaces_regressed(Some(&stripped), None, &[]));
        assert!(surfaces_regressed(None, Some((&stripped, None)), &[]));
        // The 0.9.0 polkit shape: module present on a plain `sufficient`.
        // Presence alone said "not regressed", every packaging lane's
        // post-upgrade reconcile no-opped, and the head-shake decline
        // silently did nothing while doctor claimed it worked.
        assert!(
            surfaces_regressed(None, Some((&wired, None)), &[]),
            "a pre-abort=die polkit stanza must count as regressed so the \
             upgrade migrates it"
        );
        assert!(surfaces_regressed(None, None, &[&stripped]));
        // polkit deleted while a vendor copy remains is re-materializable, so it
        // IS a regression; deleted with no vendor is not ours to restore.
        assert!(surfaces_regressed(None, Some((&gone, Some(&vendor))), &[]));
        assert!(!surfaces_regressed(None, Some((&gone, None)), &[]));
        // A fingerprint service that does not exist is not a regression: we only
        // ever add a line to a file the display manager already ships.
        assert!(!surfaces_regressed(None, None, &[&gone]));
        // A surface we never wired is ignored even when stripped.
        assert!(!surfaces_regressed(None, None, &[]));
    }

    #[test]
    fn wire_lock_without_an_auth_anchor_is_a_noop() {
        let (w, c) = wire_lock("#%PAM-1.0\naccount required pam_unix.so\n");
        assert!(!c);
        assert_eq!(w, "#%PAM-1.0\naccount required pam_unix.so\n");
    }

    #[test]
    fn status_report_labels_and_login_wired_agree() {
        // The report's rows are the greeters, the fingerprint service, the lock
        // screen, then sudo and polkit, in that order; labels come from the
        // constant paths.
        let rows = status_report();
        let labels: Vec<&str> = rows.iter().map(|(l, _, _)| l.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "gdm-password",
                "sddm",
                "lightdm",
                "plasmalogin",
                "cosmic-greeter",
                "greetd",
                "ly",
                "gdm-fingerprint",
                "kde",
                "sudo",
                "polkit (apps)",
            ]
        );
        // login_wired is exactly "any non-sudo row is wired" (sudo excluded).
        let any_login = rows[..rows.len() - 1].iter().any(|(_, _, w)| *w);
        assert_eq!(login_wired(), any_login);
    }

    #[test]
    fn effective_uid_matches_the_real_euid() {
        // SAFETY: takes no arguments, reads only this process's own
        // credentials, and is specified as always succeeding.
        assert_eq!(effective_uid(), unsafe { libc::geteuid() });
    }

    #[test]
    fn wired_marker_round_trips_flags_and_clears_on_disable() {
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = TestDir::new("wired-marker");
        let old = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_STATE_DIR", &dir.0);
        // No marker → reconcile has nothing to maintain.
        assert_eq!(read_wired_marker(), None);
        // Enable with only --with-polkit is recorded (sudo=false, polkit=true,
        // lock=false).
        write_wired_marker(true, false, true, false);
        assert_eq!(read_wired_marker(), Some((false, true, false)));
        // Re-enable with both flags + the lock screen overwrites cleanly.
        write_wired_marker(true, true, true, true);
        assert_eq!(read_wired_marker(), Some((true, true, true)));
        // A marker written before with_lock existed (only the two flags) reads
        // back with lock=false, so it never triggers a false lock regression.
        irlume_common::write_0600(&wired_marker_path(), b"with_sudo=true\nwith_polkit=false\n")
            .unwrap();
        assert_eq!(read_wired_marker(), Some((true, false, false)));
        // Disable clears the marker so the self-heal service stays quiet.
        write_wired_marker(false, false, false, false);
        assert_eq!(read_wired_marker(), None);
        match old {
            Some(v) => std::env::set_var("IRLUME_STATE_DIR", v),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
    }

    #[test]
    fn selinux_pp_honours_the_env_override_only_when_it_exists() {
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = TestDir::new("selinux-pp");
        let pp = dir.0.join("irlume.pp");
        std::fs::write(&pp, b"module").unwrap();
        let old = std::env::var_os("IRLUME_SELINUX_PP");
        // An existing override path is returned verbatim.
        std::env::set_var("IRLUME_SELINUX_PP", &pp);
        assert_eq!(selinux_pp(), Some(pp.to_string_lossy().into_owned()));
        // A nonexistent override is ignored (never returned) and the search
        // falls through to the packaged/in-repo locations instead.
        let missing = dir.0.join("missing.pp");
        std::env::set_var("IRLUME_SELINUX_PP", &missing);
        assert_ne!(selinux_pp().as_deref(), missing.to_str());
        match old {
            Some(v) => std::env::set_var("IRLUME_SELINUX_PP", v),
            None => std::env::remove_var("IRLUME_SELINUX_PP"),
        }
    }

    // ---- wire_service strategy matrix (override vs edit-in-place) -------------

    // A vendor-shipped greeter (Fedora substack layout), the kind plasmalogin/kde
    // materialize an /etc override from.
    const VENDOR_GREETER: &str = "#%PAM-1.0\nauth       substack      password-auth\nauth       optional      pam_gnome_keyring.so\naccount    include       password-auth\nsession    include       password-auth\n";

    #[test]
    fn restoring_writes_the_recorded_content_back() {
        let dir = std::env::temp_dir().join(format!("irlume-restore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("sudo");
        std::fs::write(&file, "changed by apply\n").expect("write");

        restore_surface(&file, Some("the original\n"), None).expect("restore");
        assert_eq!(
            std::fs::read_to_string(&file).expect("read"),
            "the original\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_paths_irlume_manages_are_restorable() {
        // Found by attacking, not by review: a record naming /etc/shadow with a
        // CORRECT digest rewrote it. Only root can plant a record and root can
        // already write that file, so it was not an escalation, but it made
        // rollback a write-anywhere-as-root primitive gated on a directory mode.
        for managed in [
            "/etc/pam.d/sudo",
            "/etc/pam.d/kde",
            "/etc/pam.d/plasmalogin",
            "/etc/pam.d/polkit-1",
            "/etc/pam.d/gdm-password",
            // A sidecar is restorable because its surface is.
            "/etc/pam.d/sudo.pre-irlume",
        ] {
            assert!(is_managed_path(managed), "{managed} must be restorable");
        }
        for stray in [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/root/.ssh/authorized_keys",
            "/etc/pam.d/../shadow",
            "/etc/pam.d/sshd",
            "/etc/pam.d/system-auth",
            "",
        ] {
            assert!(!is_managed_path(stray), "{stray} must NOT be restorable");
        }
    }

    #[test]
    fn restoring_puts_back_the_mode_not_just_the_bytes() {
        use std::os::unix::fs::PermissionsExt;
        // Codex found this on #178: write_atomic copies permissions from the
        // file it replaces, which is the wrong source and does not exist at all
        // when apply removed the file. A PAM stack that was 0640 coming back
        // 0644 is a real access change, not a cosmetic one.
        let dir = std::env::temp_dir().join(format!("irlume-restore-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("greeter");
        std::fs::write(&file, "rewritten by apply\n").expect("write");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        // The recorded pre-change state: same bytes, but a tighter mode.
        let meta = crate::logintx::file_metadata(&file).expect("metadata");
        restore_surface(&file, Some("the original\n"), Some((0o640, meta.1, meta.2)))
            .expect("restore");

        assert_eq!(
            std::fs::read_to_string(&file).expect("read"),
            "the original\n"
        );
        let mode = std::fs::metadata(&file).expect("stat").permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o640,
            "the recorded mode must come back, not the current one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restoring_a_file_that_did_not_exist_removes_it() {
        // `disable` can remove a file outright. Writing an empty one instead
        // would leave a stub shadowing the vendor copy, which is not the same
        // as the file being absent.
        let dir =
            std::env::temp_dir().join(format!("irlume-restore-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("materialized-override");
        std::fs::write(&file, "irlume made this\n").expect("write");

        restore_surface(&file, None, None).expect("restore");
        assert!(!file.exists(), "the file must be gone, not empty");

        // Restoring an already-absent file is not an error: a rollback that
        // partly ran and is run again must be able to finish.
        restore_surface(&file, None, None).expect("restoring an absent file is fine");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wire_service_override_materialize_idempotent_then_remove() {
        let dir = TestDir::new("wsvc-override");
        let vendor = dir.0.join("plasmalogin.vendor");
        std::fs::write(&vendor, VENDOR_GREETER).unwrap();
        let etc = dir.0.join("plasmalogin"); // no admin /etc copy yet
        let svc = Svc {
            etc: leak(&etc),
            vendor: Some(leak(&vendor)),
        };
        let wire = |c: &str| wire_greeter_impl(c, true, false, true);

        // First enable → materialize the override from the vendor copy.
        let msg = wire_service(&svc, true, true, &wire).unwrap();
        assert!(msg.message.contains("materialized override from"), "{msg}");
        assert!(etc.exists());
        let body = std::fs::read_to_string(&etc).unwrap();
        assert!(body.starts_with(CREATED_PREFIX));
        assert!(file_is_created_override(&etc));
        assert!(body.contains("pam_irlume.so unseal ondemand"));

        // Re-enable with the same inputs → recognised as already correct.
        let msg2 = wire_service(&svc, true, true, &wire).unwrap();
        assert!(msg2.message.contains("already correctly wired"), "{msg2}");

        // Disable → the created override is removed and the vendor copy restored.
        let msg3 = wire_service(&svc, false, true, &wire).unwrap();
        assert!(msg3.message.contains("removed override"), "{msg3}");
        assert!(!etc.exists());
    }

    #[test]
    fn wire_service_override_skips_when_vendor_absent() {
        let dir = TestDir::new("wsvc-novendor");
        let etc = dir.0.join("plasmalogin");
        let vendor = dir.0.join("plasmalogin.vendor"); // never created
        let svc = Svc {
            etc: leak(&etc),
            vendor: Some(leak(&vendor)),
        };
        let wire = |c: &str| wire_greeter_impl(c, true, false, true);
        let msg = wire_service(&svc, true, true, &wire).unwrap();
        assert!(msg.message.contains("not installed (skipped)"), "{msg}");
        assert!(!etc.exists());
    }

    #[test]
    fn wire_service_edit_skips_absent_and_anchorless_files() {
        let wire = |c: &str| wire_greeter_impl(c, true, false, false);

        // No /etc file at all → skipped.
        let dir = TestDir::new("wsvc-absent");
        let etc = dir.0.join("gdm-password");
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let msg = wire_service(&svc, true, true, &wire).unwrap();
        assert!(msg.message.contains("not installed (skipped)"), "{msg}");

        // Present but nothing to anchor to → skipped, no backup left behind.
        let dir2 = TestDir::new("wsvc-noanchor");
        let etc2 = dir2.0.join("greeter");
        std::fs::write(&etc2, "#%PAM-1.0\naccount required pam_unix.so\n").unwrap();
        let svc2 = Svc {
            etc: leak(&etc2),
            vendor: None,
        };
        let msg2 = wire_service(&svc2, true, true, &wire).unwrap();
        assert!(msg2.message.contains("no anchor to wire"), "{msg2}");
        assert!(!dir2.0.join(format!("greeter{BACKUP}")).exists());
    }

    #[test]
    fn wire_service_edit_enable_backs_up_then_recognises_already_wired() {
        let dir = TestDir::new("wsvc-enable");
        let etc = dir.0.join("gdm-password");
        std::fs::write(&etc, GDM).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let wire = |c: &str| wire_greeter_impl(c, true, true, false);

        let msg = wire_service(&svc, true, true, &wire).unwrap();
        assert!(msg.message.contains("wired (backup"), "{msg}");
        assert!(dir.0.join(format!("gdm-password{BACKUP}")).exists());
        let after = std::fs::read_to_string(&etc).unwrap();
        assert!(content_has_module(&after));

        // Second identical enable is a recognised no-op (rebuilt from backup).
        let msg2 = wire_service(&svc, true, true, &wire).unwrap();
        assert!(msg2.message.contains("already correctly wired"), "{msg2}");
    }

    /// A surface irlume REFUSED to touch must be recorded as it is on disk, not
    /// as absent.
    ///
    /// The rollback precheck compares each recorded after-digest with the file,
    /// so "absent before, absent after" about a file that exists reads as drift
    /// and refuses the WHOLE transaction: a partly applied enable could not be
    /// undone at all. `before: None` also means "remove it" to a restore, which
    /// is the opposite of leaving it alone.
    #[test]
    fn a_refused_surface_is_recorded_as_it_stands() {
        let dir = TestDir::new("wsvc-refused-record");
        // A symlinked PAM path: every write refuses it, so an apply records it
        // with an error and touches nothing.
        let real = dir.0.join("real-sudo");
        std::fs::write(
            &real,
            "auth include system-auth
",
        )
        .unwrap();
        let etc = dir.0.join("sudo");
        std::os::unix::fs::symlink(&real, &etc).unwrap();

        let refusal = inspect_target(&etc).expect_err("a symlink is refused");
        let rec = refused_surface_record(
            &Svc {
                etc: leak(&etc),
                vendor: None,
            },
            ROLE_SUDO,
            &etc,
            refusal,
        );
        assert!(rec.error.is_some(), "with the reason it was refused");
        assert_ne!(
            rec.after_sha256,
            crate::logintx::ABSENT,
            "the file exists, so recording it as absent makes the rollback see drift"
        );
        assert_eq!(
            rec.after_sha256,
            crate::logintx::sha256_hex(&std::fs::read(&etc).unwrap()),
            "the recorded digest is the file's own"
        );
        assert!(
            rec.before.is_some(),
            "before: None tells a restore to REMOVE a file irlume never touched"
        );
    }

    /// A disable that restores its backup must refuse a PAM path that is a
    /// symlink, like every other write in this module.
    ///
    /// The restore was a bare `rename`, and renaming over a symlink REPLACES the
    /// link with a regular file: a distro that symlinks a PAM service would have
    /// had the link silently converted, with the target left behind holding
    /// whatever it held.
    #[test]
    fn wire_service_disable_refuses_to_restore_over_a_symlink() {
        let dir = TestDir::new("wsvc-symlink");
        let (wired, _) = wire_greeter_impl(GDM, true, true, false);

        // The real file lives elsewhere; the PAM path is a link to it.
        let real = dir.0.join("real-gdm-password");
        std::fs::write(&real, &wired).unwrap();
        let etc = dir.0.join("gdm-password");
        std::os::unix::fs::symlink(&real, &etc).unwrap();

        // A backup that matches the stripped file, so the restore branch is the
        // one taken.
        let (stripped, _) = unwire_lines(&wired);
        std::fs::write(dir.0.join(format!("gdm-password{BACKUP}")), &stripped).unwrap();

        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let wire = |c: &str| wire_greeter_impl(c, true, true, false);
        let err = match wire_service(&svc, false, true, &wire) {
            Err(e) => e,
            Ok(msg) => panic!("restoring over a symlink must be refused, got: {msg}"),
        };
        assert!(
            err.to_lowercase().contains("symlink"),
            "the refusal must name why: {err}"
        );
        // The link is intact and still points at the real file.
        assert!(
            std::fs::symlink_metadata(&etc)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the PAM path must still be a symlink"
        );
    }

    #[test]
    fn wire_service_edit_disable_strips_when_no_backup_exists() {
        // Wired file, no .pre-irlume backup → strip in place (not restore).
        let dir = TestDir::new("wsvc-strip");
        let (wired, _) = wire_greeter_impl(GDM, true, true, false);
        let etc = dir.0.join("gdm-password");
        std::fs::write(&etc, &wired).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let wire = |c: &str| wire_greeter_impl(c, true, true, false);
        let msg = wire_service(&svc, false, true, &wire).unwrap();
        assert!(msg.message.contains("stripped irlume lines"), "{msg}");
        assert!(!msg.message.contains("backup kept")); // the no-backup phrasing
        let after = std::fs::read_to_string(&etc).unwrap();
        assert!(!content_has_module(&after));
    }

    #[test]
    fn wire_service_edit_disable_reports_a_clean_file_as_not_wired() {
        let dir = TestDir::new("wsvc-clean");
        let etc = dir.0.join("gdm-password");
        std::fs::write(&etc, GDM).unwrap(); // never wired
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let wire = |c: &str| wire_greeter_impl(c, true, true, false);
        let msg = wire_service(&svc, false, true, &wire).unwrap();
        assert!(msg.message.contains("not wired"), "{msg}");
    }
}
