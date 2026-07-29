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

const MODULE: &str = "pam_irlume.so";
const BACKUP: &str = ".pre-irlume";
const CREATED_PREFIX: &str = "# irlume: created from ";
/// The one sentence that explains the on-demand trigger; shared so the status
/// line, the plan line, and docs/SETUP.md's mirror never drift apart.
const ONDEMAND_HINT: &str = "leave the password empty and press Enter to use your face";

// Greeter block for a non-`@include` (Fedora `substack`) stack: a `success=1`
// jump over the password substack, plus the `PERMIT_LANDING` it lands on.
/// Jump-style face line for a submit-driven greeter we have NOT validated for the
/// on-demand probe (old GDM, unknown DM). `facefirst` is mandatory here: without
/// it the module runs the ACTIVE probe (`pam_get_authtok`), and a greeter that
/// blocks that probe until the user types means face never fires at all.
const GREETER_UNSEAL_FACEFIRST_JUMP: &str =
    "auth       [success=1 default=ignore]   pam_irlume.so unseal facefirst";
/// The greeter/locker face line for any INCLUDE layout: Debian/Ubuntu
/// `@include common-auth` and Arch `auth include system-login` alike (a
/// `success=N` jump can't skip an include expansion, so this can't be the jump
/// form). Always `sufficient`: the same control works for EVERY DM's locker
/// (GDM and cosmic alike short-circuit on a warm unlock). Cold-login keyring
/// unlock is handled by the module's `kr` arg, NOT the control: on a cold login
/// the module returns IGNORE (having set the token), so `sufficient` continues to
/// pam_unix + pam_gnome_keyring; a warm lock returns SUCCESS and short-circuits.
/// `mode` is `facefirst` (GDM scan-immediately) or `ondemand` (empty-Enter). `kr`
/// adds the keyring-continue arg: true for greeters (cold login unlocks the
/// keyring), false for a separate warm lock service (keyring already open).
fn include_greeter_line(mode: &str, kr: bool) -> String {
    let kr_arg = if kr { " kr" } else { "" };
    format!("auth       sufficient   pam_irlume.so unseal {mode}{kr_arg}")
}
/// Jump-style variant for a non-`@include` (e.g. Fedora) COSMIC stack.
const GREETER_UNSEAL_COSMIC_JUMP: &str =
    "auth       [success=1 default=ignore]   pam_irlume.so unseal ondemand";
// Tagged so unwire strips OUR landing but never a foreign pam_permit.so the
// stack legitimately carries (the trailing `#…` is a PAM comment, ignored).
const PERMIT_LANDING: &str =
    "auth       optional                     pam_permit.so   # irlume-landing";
const RESEAL_AUTH: &str = "auth       optional                     pam_irlume.so reseal";
/// Post-auth login-keyring unlock for the FINGERPRINT path: runs after a trusted
/// factor succeeded; if no password is present (fingerprint login) it unseals
/// the TPM-sealed password and sets PAM_AUTHTOK so pam_gnome_keyring opens the
/// wallet. No-op when the keyring isn't armed or a password is already set.
const KEYRING_UNSEAL: &str = "auth       optional                     pam_irlume.so keyring";
const RESEAL_SESSION: &str = "session    optional                     pam_irlume.so reseal";
/// The plain verify stanza, shared by `sudo` and polkit prompts (Bitwarden vault
/// unlock, pkexec, systemd unit control): no `unseal` (the daemon refuses
/// credential release for both classes anyway) and no mode arg (each surface runs
/// the PAM conversation as soon as it prompts, which IS the face-first trigger;
/// the daemon adds the forced consent gesture on top).
const VERIFY_STANZA: &str = "auth       sufficient                   pam_irlume.so";

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

/// Structured wiring status for the TUI: `(label, present, wired)` per service
/// plus a trailing SELinux row. Mirrors what `status()` prints.
pub(crate) fn status_report() -> Vec<(String, bool, bool)> {
    let mut out = Vec::new();
    for s in GREETERS
        .iter()
        .chain(FP_GREETERS.iter())
        .chain(std::iter::once(&LOCKSCREEN))
    {
        match service_present(s) {
            Some(p) => out.push((label_of(s.etc), true, file_has_module(&p))),
            None => out.push((label_of(s.etc), false, false)),
        }
    }
    let sudo = Path::new(SUDO);
    out.push((
        "sudo".into(),
        sudo.exists(),
        sudo.exists() && file_has_module(sudo),
    ));
    match service_present(&POLKIT) {
        Some(p) => out.push(("polkit (apps)".into(), true, file_has_module(&p))),
        None => out.push(("polkit (apps)".into(), false, false)),
    }
    out
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
fn write_wired_marker(enable: bool, with_sudo: bool, with_polkit: bool, with_lock: bool) {
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
    if let Err(e) = irlume_common::write_0600(&path, body.as_bytes()) {
        eprintln!(
            "[login] warning: could not write the self-heal marker {}: {e}\n\
             [login] automatic re-wiring after a distro PAM update will not run.",
            path.display()
        );
    }
}

/// Re-read the marker's recorded flags. Returns `None` when login was never
/// enabled (no marker), so reconcile does nothing on machines that opted out.
fn read_wired_marker() -> Option<(bool, bool, bool)> {
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
    act(true, true, with_sudo, with_polkit)
}

/// Whether the ACTIVE display manager's own greeter service carries the module.
/// [`login_wired`] is any-of (true if any greeter/lock file has the line), which
/// gives reconcile a blind spot: a distro update that strips only the active
/// greeter while a stale/inactive greeter file keeps the line would leave
/// `login_wired()` true and the real login broken. This checks the greeter the
/// active DM actually consults, so reconcile repairs the login that matters. An
/// absent active-greeter file counts as not-wired too (a deleted /etc override).
/// Falls back to `login_wired()` when the active DM is unknown/absent.
fn active_login_wired() -> bool {
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
    if polkit.is_some_and(|(etc, vendor)| lock_regressed(etc, vendor)) {
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

/// Short label from an /etc/pam.d path (e.g. "/etc/pam.d/gdm-password" → "gdm-password").
fn label_of(etc: &str) -> String {
    service_name(etc).to_string()
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
                let t = l.trim_start();
                !t.starts_with('#') && t.contains("pam_irlume.so") && t.contains("keyring")
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

/// One PAM surface irlume knows how to wire, as facts rather than a rendered
/// row. The human report prints these and `login status --json` serializes
/// them, so a single pass feeds both and the two cannot disagree about what is
/// wired; they can only differ in how they word it.
pub(crate) struct SurfaceFact {
    /// The PAM service name (`plasmalogin`, `kde`, `sudo`, …). Stable public id.
    pub(crate) id: &'static str,
    pub(crate) role: &'static str,
    /// The /etc path, for the human report only. Machine output publishes the
    /// service name instead, in keeping with the no-paths rule.
    pub(crate) path: &'static str,
    /// Whether this service exists here at all: a real /etc file, or a vendor
    /// copy an /etc override would be materialized from.
    pub(crate) present: bool,
    pub(crate) wired: bool,
    /// How face fires here when wired: `face-first`, `on-demand`, `keyring`
    /// (the fingerprint keyring-unlock line, which is not a face factor) or
    /// `verify` (the plain sudo/polkit stanza). `None` when not wired.
    pub(crate) mode: Option<&'static str>,
}

fn surface_fact(
    etc: &'static str,
    vendor: Option<&'static str>,
    role: &'static str,
) -> SurfaceFact {
    let path = service_present(&Svc { etc, vendor });
    let content = path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    let wired = content_has_module(&content);
    // Name HOW face fires on this service: on-demand (the consent model) is
    // invisible in the PAM file to a reader, and a keyring-only line is the
    // fingerprint unlock rather than face at all.
    let mode = if !wired {
        None
    } else if role == ROLE_SUDO || role == ROLE_POLKIT {
        Some("verify")
    } else if !content.contains("unseal") {
        Some("keyring")
    } else if content.contains("ondemand") {
        Some("on-demand")
    } else {
        Some("face-first")
    };
    SurfaceFact {
        id: service_name(etc),
        role,
        path: etc,
        present: path.is_some(),
        wired,
        mode,
    }
}

/// Every surface irlume can wire, present or not, in the order the human report
/// prints them. Absent services are kept in the list with `present: false`: a
/// consumer must be able to read an id it knows and cannot find as "this engine
/// does not wire that service" rather than as "not wired here".
pub(crate) fn surface_facts() -> Vec<SurfaceFact> {
    let mut out: Vec<SurfaceFact> = GREETERS
        .iter()
        .map(|s| surface_fact(s.etc, s.vendor, ROLE_LOGIN))
        .chain(
            FP_GREETERS
                .iter()
                .map(|s| surface_fact(s.etc, s.vendor, ROLE_LOGIN_FP)),
        )
        .collect();
    out.push(surface_fact(LOCKSCREEN.etc, LOCKSCREEN.vendor, ROLE_LOCK));
    out.push(surface_fact(SUDO, None, ROLE_SUDO));
    out.push(surface_fact(POLKIT.etc, POLKIT.vendor, ROLE_POLKIT));
    out
}

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
    let caps = irlume_camera::capabilities();
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
        visit(s, ROLE_LOGIN_FP, &wire_fp_keyring, fp_keyring);
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
        visit(&POLKIT, ROLE_POLKIT, &wire_verify_service, true);
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
    pub(crate) after_sha256: String,
    /// Set when this surface failed. The apply as a whole is reported as failed,
    /// and the surfaces that DID change are still recorded, so a rollback can
    /// undo a partial run.
    pub(crate) error: Option<String>,
}

/// Carry out an enable/disable, recording what each surface looked like first.
///
/// The before-content is read BEFORE `wire_service` runs, because that is the
/// only moment it exists to be read; afterwards the file has already changed.
/// Every surface is recorded even when a later one fails, since a partial apply
/// is exactly the case a rollback has to be able to undo.
pub(crate) fn apply(enable: bool, with_sudo: bool, with_polkit: bool) -> Vec<AppliedSurface> {
    let mut out = Vec::new();
    walk_surfaces(
        enable,
        with_sudo,
        with_polkit,
        &mut |svc, role, wire, want| {
            let path = Path::new(svc.etc);
            let before = std::fs::read_to_string(path).ok();
            let (change, error) = match wire_service(svc, enable && want, true, wire) {
                Ok(outcome) => (outcome.change, None),
                Err(message) => (PlannedChange::NotInstalled, Some(message)),
            };
            let after_sha256 = std::fs::read(path)
                .map(|bytes| crate::logintx::sha256_hex(&bytes))
                .unwrap_or_else(|_| crate::logintx::ABSENT.to_string());
            out.push(AppliedSurface {
                id: service_name(svc.etc),
                role,
                path: svc.etc.to_string(),
                change,
                before,
                after_sha256,
                error,
            });
        },
    );
    out
}

/// Put one surface back to the content recorded before a transaction.
///
/// Reuses the same atomic write the wiring path uses, so a restore lands the
/// way every other PAM write here does. The caller must have checked
/// `unchanged_since_apply` first; this does the write, not the decision.
///
/// `None` content means the file did not exist before, so it is removed rather
/// than written empty: an empty PAM file is not the same as an absent one, and
/// leaving one behind would shadow a vendor copy.
pub(crate) fn restore_surface(path: &Path, before: Option<&str>) -> Result<(), String> {
    match before {
        Some(content) => write_atomic(path, content),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("remove {}: {error}", path.display())),
        },
    }
}

/// The active login manager and the PAM services it consults.
pub(crate) struct LoginManagerFact {
    /// `None` when no login manager could be found at all: a headless host. A
    /// greeter that registers no `display-manager.service` is still found when
    /// it is one of [`WANTS_ONLY_DMS`]. Not the same as "no face login".
    pub(crate) name: Option<String>,
    /// Whether irlume can wire face login here. False covers both a login
    /// manager it has no mapping for and one whose mapped service it has no
    /// recipe for; either way `login enable` cannot target it.
    pub(crate) recognized: bool,
    /// The greeter service, plus the separate fingerprint service on the login
    /// managers that have one (GDM). Empty when unrecognized.
    pub(crate) services: Vec<&'static str>,
}

pub(crate) fn login_manager_fact() -> LoginManagerFact {
    let Some(dm) = active_display_manager() else {
        return LoginManagerFact {
            name: None,
            recognized: false,
            services: Vec::new(),
        };
    };
    let (greeter, fp) = dm_pam_services(&dm);
    // Named is not the same as wirable, so a service irlume cannot write must
    // not be published as one it consults.
    let recognized = dm_wirable(&dm);
    LoginManagerFact {
        name: Some(dm),
        recognized,
        services: if recognized {
            std::iter::once(greeter).chain(fp).collect()
        } else {
            Vec::new()
        },
    }
}

fn status() -> ExitCode {
    println!("[login] wiring status (face auth in PAM):");
    if let Some(dm) = active_display_manager() {
        let (greeter, fp) = dm_pam_services(&dm);
        match fp {
            Some(fp) => println!("  active login manager: {dm}  (uses {greeter} + {fp})"),
            None => println!("  active login manager: {dm}  (uses {greeter})"),
        }
    }
    let mut any = false;
    let mut any_ondemand = false;
    for f in surface_facts() {
        if !f.present {
            continue;
        }
        let label = match (f.role, f.mode) {
            (ROLE_SUDO, Some(_)) => "● wired (sudo)",
            (ROLE_SUDO, None) => "○ not wired (sudo)",
            (ROLE_POLKIT, Some(_)) => "● wired (polkit app prompts)",
            (ROLE_POLKIT, None) => "○ not wired (polkit app prompts)",
            (_, None) => "○ not wired",
            (_, Some("on-demand")) => {
                any_ondemand = true;
                "● wired (face on-demand)"
            }
            (_, Some("face-first")) => "● wired (face-first)",
            // keyring-only line
            (_, Some(_)) => "● wired",
        };
        // face-sudo alone does not make the login screen work, so it does not
        // silence the "enable with" hint below.
        any |= f.wired && f.role != ROLE_SUDO && f.role != ROLE_POLKIT;
        println!("  {:<34} {}", f.path, label);
    }
    if any_ondemand {
        println!("  on-demand: {ONDEMAND_HINT}");
    }
    println!(
        "[login] SELinux module: {}",
        match selinux_loaded() {
            Some(true) => "loaded",
            Some(false) => "not loaded",
            None => "unknown (run as root to check)",
        }
    );
    if !any {
        println!(
            "  → enable with:  sudo irlume login enable --apply   (add --with-sudo for face-sudo, \
             --with-polkit for app prompts like Bitwarden)"
        );
    }
    ExitCode::SUCCESS
}

fn act(enable: bool, apply: bool, with_sudo: bool, with_polkit: bool) -> ExitCode {
    if apply && effective_uid() != 0 {
        eprintln!(
            "[login] applying changes needs root; run: sudo irlume login {} --apply",
            if enable { "enable" } else { "disable" }
        );
        return ExitCode::FAILURE;
    }
    if !apply {
        println!("[login] DRY RUN: showing what `--apply` would change (nothing is written):");
    }
    // Method + tier aware plan: wire exactly what the chosen method needs on
    // this hardware, and (on enable) UNWIRE what it doesn't, so switching method
    // re-configures cleanly instead of leaving stale lines. `want_*` gate each
    // factor; on disable everything is unwired.
    let caps = irlume_camera::capabilities();
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
        do_svc(s, &wire_fp_keyring, want_fp_keyring);
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
        match wire_service(&POLKIT, enable, apply, &wire_verify_service) {
            Ok(msg) => {
                println!("  {msg}");
                if enable && apply {
                    println!(
                        "    polkit prompts (Bitwarden unlock, pkexec) will accept your face once\n    \
                         you calibrate the consent gesture:  sudo irlume calibrate-closure\n    \
                         Then approve a prompt by closing your eyes for ~1s and opening them."
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
        write_wired_marker(enable, with_sudo, with_polkit, want_face_lock);
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
            let (wired, _) = wire(&base);
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
            // Rebuild from the pristine stock: the backup if we've wired before,
            // else the current file, then strip any irlume lines and re-apply.
            let bak = PathBuf::from(format!("{}{BACKUP}", s.etc));
            let origin = if bak.exists() {
                read(&bak.to_string_lossy())?
            } else {
                current.clone()
            };
            let (base, _) = unwire_lines(&origin);
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

fn content_has_module(c: &str) -> bool {
    c.lines().any(|l| {
        let t = l.trim_start();
        !t.starts_with('#') && t.contains(MODULE)
    })
}

/// `<kind>` is `auth`/`session`; matches a `(substack|include) (password-auth|
/// system-auth)` line, the shared substack the success=1 jump skips.
/// An `auth`-phase line whose password path is an `include` a `success=N` jump
/// can't skip: Debian's `@include common-auth`/`login`, or Arch's
/// `auth include system-login`/`system-local-login`/`system-auth`. These need
/// the `sufficient` (module IGNOREs on cold login) form, NOT the jump form. A
/// Fedora `substack` is atomic for jump counting, so it deliberately does not
/// match here and keeps the jump stanza.
fn is_include_auth_layout(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with("@include common-auth") || t.starts_with("@include login") {
        return true;
    }
    let toks: Vec<&str> = t.split_whitespace().collect();
    toks.first() == Some(&"auth")
        && toks.get(1) == Some(&"include")
        && matches!(
            toks.get(2),
            Some(&"system-login") | Some(&"system-local-login") | Some(&"system-auth")
        )
}

fn is_passwd_substack(line: &str, kind: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with('#') {
        return false;
    }
    let toks: Vec<&str> = t
        .strip_prefix('-')
        .unwrap_or(t)
        .split_whitespace()
        .collect();
    toks.first() == Some(&kind)
        && toks.iter().any(|w| *w == "substack" || *w == "include")
        && toks
            .iter()
            .any(|w| *w == "password-auth" || *w == "system-auth")
}

fn is_auth_directive(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with('#') {
        return false;
    }
    t.strip_prefix('-').unwrap_or(t).split_whitespace().next() == Some("auth")
}

/// Insert irlume's greeter block: `unseal` before the password substack, a
/// `pam_permit` landing + `reseal` after it, and a `session reseal` after the
/// session substack. Idempotent; falls back to the first `auth` line if there's
/// no password substack.
/// Wire a display-manager greeter. `face` adds the face-first login lines
/// (Secure-tier credential release); `keyring` adds the post-auth keyring-unseal
/// line (fingerprint keyring unlock; needed in gdm-password too, since GDM's
/// SESSION keyring unlock runs through gdm-password even on a fingerprint login).
/// Reseal (self-heal of the sealed password) rides along whenever either is set.
fn wire_greeter_impl(content: &str, face: bool, keyring: bool, ondemand: bool) -> (String, bool) {
    if !face && !keyring {
        return (content.to_string(), false);
    }
    if content_has_module(content) {
        return (content.to_string(), false);
    }
    let lines: Vec<&str> = content.lines().collect();
    // Debian/Ubuntu layout: face-first `sufficient` before the password path;
    // keyring-unseal after it (runs on any auth success, incl. a fingerprint via
    // common-auth's pam_fprintd). Most greeters `@include common-auth` directly;
    // greetd instead `@include login` (which itself pulls in common-auth) and adds
    // its own keyring modules after; inserting the face line before that include
    // works identically (face IGNORE on cold login → the include's pam_unix +
    // greetd's pam_gnome_keyring run with the unsealed AUTHTOK → keyring unlocks).
    if let Some(inc_at) = lines.iter().position(|l| is_include_auth_layout(l)) {
        let mut out = Vec::with_capacity(lines.len() + 4);
        for (i, l) in lines.iter().enumerate() {
            if i == inc_at {
                if face {
                    out.push(include_greeter_line(
                        if ondemand { "ondemand" } else { "facefirst" },
                        true,
                    ));
                }
                out.push((*l).to_string());
                if keyring {
                    out.push(KEYRING_UNSEAL.to_string());
                }
                out.push(RESEAL_AUTH.to_string());
            } else if l.trim_start().starts_with("@include common-session") {
                out.push((*l).to_string());
                out.push(RESEAL_SESSION.to_string());
            } else {
                out.push((*l).to_string());
            }
        }
        if !out.iter().any(|l| l == RESEAL_SESSION) {
            out.push(RESEAL_SESSION.to_string());
        }
        return (format!("{}\n", out.join("\n")), true);
    }
    let auth_at = lines
        .iter()
        .position(|l| is_passwd_substack(l, "auth"))
        .or_else(|| lines.iter().position(|l| is_auth_directive(l)));
    let sess_at = lines.iter().position(|l| is_passwd_substack(l, "session"));
    let Some(auth_at) = auth_at else {
        return (content.to_string(), false);
    };
    let mut out = Vec::with_capacity(lines.len() + 5);
    for (i, l) in lines.iter().enumerate() {
        if i == auth_at {
            if face {
                out.push(
                    if ondemand {
                        GREETER_UNSEAL_COSMIC_JUMP
                    } else {
                        GREETER_UNSEAL_FACEFIRST_JUMP
                    }
                    .to_string(),
                );
                out.push((*l).to_string());
                out.push(PERMIT_LANDING.to_string());
            } else {
                out.push((*l).to_string());
            }
            if keyring {
                out.push(KEYRING_UNSEAL.to_string());
            }
            out.push(RESEAL_AUTH.to_string());
        } else if Some(i) == sess_at {
            out.push((*l).to_string());
            out.push(RESEAL_SESSION.to_string());
        } else {
            out.push((*l).to_string());
        }
    }
    if sess_at.is_none() {
        out.push(RESEAL_SESSION.to_string()); // harmless optional session line
    }
    (format!("{}\n", out.join("\n")), true)
}

/// Wire the KDE lock (`kde`) with the consent-driven on-demand face block: face
/// engages only on an empty-field Enter, verifies identity for the unlock, and
/// otherwise falls through to the password. Same `ondemand` mode as
/// cosmic-greeter, applied to KDE's submit-driven lock service. No reseal (a
/// screen unlock releases no credential). Handles both the Debian `@include`
/// and the Fedora `substack` layouts.
fn wire_lock(content: &str) -> (String, bool) {
    if content_has_module(content) {
        return (content.to_string(), false);
    }
    let lines: Vec<&str> = content.lines().collect();
    // Include layout (Debian `@include common-auth`, Arch `auth include
    // system-local-login`) → face-first `sufficient` before it. A warm lock so
    // no keyring-continue arg; on face success the module returns SUCCESS and
    // `sufficient` grants the unlock.
    if let Some(inc_at) = lines.iter().position(|l| is_include_auth_layout(l)) {
        let mut out = Vec::with_capacity(lines.len() + 1);
        for (i, l) in lines.iter().enumerate() {
            if i == inc_at {
                out.push(include_greeter_line("ondemand", false));
            }
            out.push((*l).to_string());
        }
        return (format!("{}\n", out.join("\n")), true);
    }
    // Fedora `substack password-auth` layout → jump stanza + permit landing.
    let auth_at = lines
        .iter()
        .position(|l| is_passwd_substack(l, "auth"))
        .or_else(|| lines.iter().position(|l| is_auth_directive(l)));
    let Some(auth_at) = auth_at else {
        return (content.to_string(), false);
    };
    let mut out = Vec::with_capacity(lines.len() + 2);
    for (i, l) in lines.iter().enumerate() {
        if i == auth_at {
            out.push(GREETER_UNSEAL_COSMIC_JUMP.to_string());
            out.push((*l).to_string());
            out.push(PERMIT_LANDING.to_string());
        } else {
            out.push((*l).to_string());
        }
    }
    (format!("{}\n", out.join("\n")), true)
}

/// Wire the `keyring` unseal line into a fingerprint login service
/// (`gdm-fingerprint`): insert it right after the `pam_fprintd.so` auth line so
/// the sealed password is set before pam_gnome_keyring's auth line runs.
fn wire_fp_keyring(content: &str) -> (String, bool) {
    if content.lines().any(|l| {
        let t = l.trim_start();
        !t.starts_with('#') && t.contains("pam_irlume.so") && t.contains("keyring")
    }) {
        return (content.to_string(), false); // already wired
    }
    let lines: Vec<&str> = content.lines().collect();
    let fp_at = lines.iter().position(|l| {
        let t = l.trim_start();
        !t.starts_with('#') && t.starts_with("auth") && t.contains("pam_fprintd.so")
    });
    let Some(fp_at) = fp_at else {
        return (content.to_string(), false);
    };
    let mut out = Vec::with_capacity(lines.len() + 1);
    for (i, l) in lines.iter().enumerate() {
        out.push((*l).to_string());
        if i == fp_at {
            out.push(KEYRING_UNSEAL.to_string());
        }
    }
    (format!("{}\n", out.join("\n")), true)
}
/// Wire a single-stanza verify service (`sudo`, `polkit-1`): the stanza goes
/// ABOVE the first auth-phase line, whether that is Fedora's `auth include
/// system-auth` or Debian/Ubuntu's `@include common-auth`. An anchor that only
/// matched a literal `auth` token missed the include layout entirely and the
/// stanza got appended at EOF, i.e. AFTER the password modules, where it is dead:
/// a wrong password already hit common-auth's pam_deny, a right one already
/// granted via pam_unix. No anchor at all → no wiring: appending to a file with
/// no auth phase would leave pam_irlume as the only auth module, and its IGNORE
/// on a failed face would then fail the whole prompt instead of falling back to
/// the password.
fn wire_verify_service(content: &str) -> (String, bool) {
    if content_has_module(content) {
        return (content.to_string(), false);
    }
    let lines: Vec<&str> = content.lines().collect();
    let anchor = lines
        .iter()
        .position(|l| is_include_auth_layout(l) || is_auth_directive(l));
    let Some(anchor) = anchor else {
        return (content.to_string(), false);
    };
    let mut out = Vec::with_capacity(lines.len() + 1);
    for (i, l) in lines.iter().enumerate() {
        if i == anchor {
            out.push(VERIFY_STANZA.to_string());
        }
        out.push((*l).to_string());
    }
    (format!("{}\n", out.join("\n")), true)
}

/// Remove every irlume line AND the pam_permit landing we added (used only when
/// no backup exists; the backup-restore path is preferred).
fn unwire_lines(content: &str) -> (String, bool) {
    // Strip every pam_irlume line, plus ONLY the pam_permit landing WE tagged
    // (`# irlume-landing`), never a foreign pam_permit.so.
    let mut changed = false;
    let kept: Vec<&str> = content
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            if t.starts_with('#') {
                return true;
            }
            let drop = t.contains(MODULE)
                || (t.contains("pam_permit.so") && l.contains("# irlume-landing"));
            if drop {
                changed = true;
            }
            !drop
        })
        .collect();
    (format!("{}\n", kept.join("\n")), changed)
}

// ---- file ops ----------------------------------------------------------------

fn read(p: &str) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("read {p}: {e}"))
}
fn file_has_module(p: &Path) -> bool {
    std::fs::read_to_string(p)
        .map(|c| content_has_module(&c))
        .unwrap_or(false)
}
fn file_is_created_override(p: &Path) -> bool {
    std::fs::read_to_string(p)
        .map(|c| c.starts_with(CREATED_PREFIX))
        .unwrap_or(false)
}
fn service_present(s: &Svc) -> Option<PathBuf> {
    if Path::new(s.etc).exists() {
        return Some(PathBuf::from(s.etc));
    }
    s.vendor
        .filter(|v| Path::new(v).exists())
        .map(|_| PathBuf::from(s.etc))
}
fn backup(path: &Path) -> Result<(), String> {
    let bak = PathBuf::from(format!("{}{BACKUP}", path.display()));
    if !bak.exists() {
        std::fs::copy(path, &bak).map_err(|e| format!("backup {}: {e}", path.display()))?;
    }
    Ok(())
}
fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("pam");
    let tmp = dir.join(format!(".{fname}.irlume.tmp"));
    std::fs::write(&tmp, contents).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("rename into {}: {e}", path.display())
    })
}

// ---- SELinux (Fedora) --------------------------------------------------------

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
            // The already-bound socket keeps its pre-policy label; the greeter
            // stays blocked until the daemon rebinds. Restart it now so face
            // login works at the very next lock/login, not the next reboot;
            // restorecon (backed by the irlume.fc entry) settles the label even
            // if the bind raced the policy commit.
            let _ = Command::new("systemctl")
                .args(["try-restart", "irlumed.service"])
                .status();
            let _ = Command::new("restorecon").arg("/run/irlume.sock").status();
            Ok("✓ SELinux module loaded (daemon restarted to relabel its socket)".into())
        } else {
            Ok("→ would load the SELinux module (greeter→daemon socket)".into())
        }
    } else {
        if selinux_loaded() == Some(false) {
            return Ok("· SELinux module not loaded".into());
        }
        if apply {
            let _ = Command::new("semodule").args(["-r", "irlume"]).status();
            Ok("✓ SELinux module removed".into())
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
    use super::*;

    // Fedora gdm-password layout (real /etc file, the GDM greeter).
    const GDM: &str = "#%PAM-1.0\nauth     [success=done ...] pam_selinux_permit.so\nauth     substack      password-auth\nauth     optional      pam_gnome_keyring.so\naccount  include       password-auth\nsession  include       password-auth\nsession  optional      pam_gnome_keyring.so auto_start\n";

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
        let (w, changed) = wire_fp_keyring(GDM_FP);
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
        let (w2, c2) = wire_fp_keyring(&w);
        assert!(!c2 && w2 == w);
    }

    #[test]
    fn wire_fp_keyring_needs_an_fprintd_anchor() {
        // No pam_fprintd line → nothing to anchor to → unchanged.
        let (w, changed) = wire_fp_keyring("#%PAM-1.0\nauth required pam_unix.so\n");
        assert!(!changed);
        assert_eq!(w, "#%PAM-1.0\nauth required pam_unix.so\n");
        // A commented fprintd line is not an anchor either.
        let (_, c) = wire_fp_keyring("#%PAM-1.0\n# auth required pam_fprintd.so\n");
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
        let stripped = dir.0.join("stripped");
        let vendor = dir.0.join("vendor");
        std::fs::write(&wired, "auth sufficient pam_irlume.so\n").unwrap();
        std::fs::write(&stripped, "auth include system-auth\n").unwrap();
        std::fs::write(&vendor, "auth include system-auth\n").unwrap();
        let gone = dir.0.join("gone");

        // Nothing recorded as wired: nothing to maintain.
        assert!(!surfaces_regressed(None, None, &[]));
        // Intact surfaces are not regressions.
        assert!(!surfaces_regressed(
            Some(&wired),
            Some((&wired, None)),
            &[&wired]
        ));
        // Each surface on its own must trigger a repair.
        assert!(surfaces_regressed(Some(&stripped), None, &[]));
        assert!(surfaces_regressed(None, Some((&stripped, None)), &[]));
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

        restore_surface(&file, Some("the original\n")).expect("restore");
        assert_eq!(
            std::fs::read_to_string(&file).expect("read"),
            "the original\n"
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

        restore_surface(&file, None).expect("restore");
        assert!(!file.exists(), "the file must be gone, not empty");

        // Restoring an already-absent file is not an error: a rollback that
        // partly ran and is run again must be able to finish.
        restore_surface(&file, None).expect("restoring an absent file is fine");
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
