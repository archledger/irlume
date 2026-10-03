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
//! Two file strategies: real `/etc/pam.d` files are backed up to `*.pre-irlume`
//! and edited in place (restore = move the backup back). A service a
//! distribution ships only in `/usr/lib/pam.d` (plasmalogin and polkit-1 on
//! Fedora, kde on Arch, sudo on openSUSE Tumbleweed, and others) gets an `/etc`
//! override made from the vendor copy. Its header records the vendor file and
//! the lines irlume wrote (`pamwire/overrides.rs`), so an override nobody
//! edited follows vendor updates and is deleted on disable, while one with an
//! administrator's lines keeps them: irlume then changes only its own lines.

use irlume_common::platform::{distro_family, DistroFamily, SystemCommand};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

// Horizontal split by responsibility, innermost first: the bytes we write
// (`stanzas`), reading a stack (`grammar`), rewriting one (`transform`). All
// three are pure (no filesystem, no policy), which is what keeps this module's
// file handling and the wiring decisions testable apart from each other. The
// one stack they read beyond the file they are given, the one a first auth
// `include` names, comes through the reader this module sets
// (`with_stack_reader`, `stack_reader`).
//
// Deliberately NOT split by modality: face and fingerprint lines share the same
// greeter files (a GDM box gets the face `unseal` line and the fingerprint
// keyring line in one `/etc/pam.d/gdm-password`, in a required order), so a
// face/fingerprint split would put one ordering invariant under two owners.
mod autologin;
mod files;
mod grammar;
mod lock;
mod overrides;
mod remote_seats;
mod report;
mod stanzas;
mod token;
mod transform;

#[cfg(test)]
mod override_tests;

use files::*;
use grammar::*;
use report::{report_keyring_handoff, status};
use stanzas::*;
use transform::*;

// Re-exported for the rest of the CLI, which reaches these as `pamwire::…`.
// A glob `use` binds names privately, so the public surface is listed here
// rather than inherited, which also keeps that surface visible in one place.
#[cfg(test)]
pub(crate) use files::restore_surface_with;
pub(crate) use files::{is_managed_path, restore_surface, UNREADABLE};
pub(crate) use lock::lock_pam;
// The PAM-grammar items shared outside this module: `fingerprint.rs` and the
// TUI must read stack lines with the same comment and rule-field semantics
// the wiring uses, or the two would disagree about what a file configures.
pub(crate) use grammar::{directive, directive_has_auth_module, has_line_continuation};
pub(crate) use overrides::Level as OverrideLevel;
pub(crate) use report::{
    active_login_wired_by_mode, keyring_handoff_warnings, login_manager_fact, login_wired_by_mode,
    status_report, surface_facts, HandoffWarning,
};
pub(crate) use stanzas::BACKUP;
pub(crate) use token::{
    token_delivery_refusal, tokens_a_disable_strands, tokens_a_restore_strands,
};

/// A PAM service to wire. With `vendor` set and no administrator's `/etc` file,
/// irlume keeps an `/etc` override made from the vendor copy; otherwise it
/// backs up and edits the real `/etc` file.
struct Svc {
    etc: &'static str,
    vendor: Option<&'static str>,
}

const GREETERS: &[Svc] = &[
    Svc {
        etc: "/etc/pam.d/gdm-password",
        vendor: Some("/usr/lib/pam.d/gdm-password"),
    }, // GNOME / GDM
    Svc {
        etc: "/etc/pam.d/sddm",
        // openSUSE ships this only in the vendor dir (2026-08-30 survey);
        // families with a real /etc file never consult the vendor path.
        vendor: Some("/usr/lib/pam.d/sddm"),
    },
    Svc {
        etc: "/etc/pam.d/lightdm",
        vendor: Some("/usr/lib/pam.d/lightdm"),
    },
    Svc {
        etc: "/etc/pam.d/plasmalogin",
        vendor: Some("/usr/lib/pam.d/plasmalogin"),
    }, // Plasma 6
    Svc {
        etc: "/etc/pam.d/cosmic-greeter",
        vendor: Some("/usr/lib/pam.d/cosmic-greeter"),
    }, // COSMIC (Pop!_OS / System76)
    Svc {
        etc: "/etc/pam.d/greetd",
        // Fedora 45 ships greetd's service only in the vendor dir; f44 and
        // earlier ship /etc/pam.d/greetd.
        vendor: Some("/usr/lib/pam.d/greetd"),
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

/// The stock Omarchy lock's password lane. Face rides the polkit-style
/// verify line, NOT the KDE on-demand block: the Omarchy lock dialog submits
/// a typed value (the same type-`yes` consent its polkit agent already
/// carries), and that exact line was live-validated on Omarchy 4.0.1. Its
/// fingerprint sibling lane (`omarchy-lock-fingerprint`) belongs to
/// `irlume fingerprint`, never to this wiring.
const OMARCHY_LOCKSCREEN: Svc = Svc {
    etc: "/etc/pam.d/omarchy-lock-password",
    vendor: None,
};

/// The lock surface for THIS machine. Omarchy's stock lock replaces KDE's:
/// with the distro's autologin default, the lock is where a cold boot
/// actually prompts, so wiring it is not optional there.
type LockSurface = (&'static Svc, fn(&str) -> (String, bool));

fn lock_surface() -> LockSurface {
    lock_surface_for(
        irlume_common::platform::omarchy_present(),
        std::path::Path::new(CINNAMON_LOCKSCREEN.etc).exists(),
    )
}

/// Testable core of [`lock_surface`].
/// The stock Cinnamon screensaver's service (Linux Mint, and any Cinnamon
/// desktop): Debian include-layout, so the KDE on-demand recipe applies, and
/// live-validated on Mint 22.3 the dialog DOES submit empty fields, which is
/// what the on-demand empty-Enter camera arm needs. Typed input never reaches
/// the camera here (by design); it goes to whatever the includes carry, which
/// on Mint is pam_fprintd then the password.
const CINNAMON_LOCKSCREEN: Svc = Svc {
    etc: "/etc/pam.d/cinnamon-screensaver",
    vendor: None,
};

fn lock_surface_for(omarchy: bool, cinnamon: bool) -> LockSurface {
    if omarchy {
        (&OMARCHY_LOCKSCREEN, wire_omarchy_lock)
    } else if cinnamon {
        (&CINNAMON_LOCKSCREEN, wire_lock)
    } else {
        (&LOCKSCREEN, wire_lock)
    }
}

/// Omarchy's dedicated face lock lane: created by
/// `omarchy-setup-security-face`, deleted by `omarchy-remove-security-face`,
/// and wired by Omarchy itself. While it exists it owns face-on-lock, and the
/// stock password lane below must not ALSO carry the face line: a face miss
/// there spends a real `pam_faillock` strike (deny=10) on a surface the
/// operator did not choose, the #584 collision arriving uninvited (#607).
const OMARCHY_FACE_LANE: &str = "/etc/pam.d/omarchy-lock-face";

/// Testable core of [`stock_lane_yielded`]: both facts, nothing else.
fn stock_lane_yielded_for(omarchy: bool, face_lane_present: bool) -> bool {
    omarchy && face_lane_present
}

/// Whether the dedicated Omarchy face lane exists and therefore owns
/// face-on-lock for this machine right now.
fn stock_lane_yielded() -> bool {
    stock_lane_yielded_for(
        irlume_common::platform::omarchy_present(),
        std::path::Path::new(OMARCHY_FACE_LANE).exists(),
    )
}

/// The yield fact the marker records (#607): an enable WANTED face-on-lock and
/// the dedicated lane suppressed the wiring. Testable core so the complement
/// property with the effective want stays pinned.
fn marker_face_lock_intent_for(want_face_lock: bool, yielded: bool) -> bool {
    want_face_lock && yielded
}

/// Whether THIS apply should record the yield intent.
pub(crate) fn marker_face_lock_intent(want_face_lock: bool) -> bool {
    marker_face_lock_intent_for(want_face_lock, stock_lane_yielded())
}

/// The reclaim read, as posted on #607: intent recorded, omarchy, the
/// dedicated lane gone, the stock lane not wired. Testable core; the caller
/// supplies "marker present" by having read one at all.
fn lane_reclaim_for(
    face_lock_intent: bool,
    omarchy: bool,
    face_lane_present: bool,
    stock_lane_wired: bool,
) -> bool {
    face_lock_intent && omarchy && !face_lane_present && !stock_lane_wired
}

/// The reverse regression: the dedicated lane APPEARED while our face line
/// still sits in the stock lane. Reconcile then re-applies, and the apply's
/// own yield removes the stock line. Only for a lane the marker says is ours
/// (`with_lock`) and a face want that still holds; testable core. The want is
/// a closure so production can keep the daemon roundtrip (`wants()`) off the
/// common path: `&&` short-circuits and never calls it unless the four cheap
/// facts already demand a decision.
fn lane_yield_for<F: FnOnce() -> bool>(
    omarchy: bool,
    face_lane_present: bool,
    stock_lane_wired: bool,
    with_lock: bool,
    face_lock_wanted: F,
) -> bool {
    omarchy && face_lane_present && stock_lane_wired && with_lock && face_lock_wanted()
}
/// GDM uses a SEPARATE PAM service for fingerprint logins (`gdm-fingerprint`),
/// distinct from `gdm-password` (password/face). It runs pam_fprintd then
/// pam_gnome_keyring, which finds no password and leaves the wallet locked. We
/// slot the `keyring` unseal line between them (ADR-0003) so a fingerprint login
/// opens the wallet. Only present on GNOME/GDM systems; skipped elsewhere.
const FP_GREETERS: &[Svc] = &[Svc {
    etc: "/etc/pam.d/gdm-fingerprint",
    vendor: None,
}];
/// Opt-in via `--with-sudo`. openSUSE Tumbleweed ships sudo's service only in
/// the vendor dir; most families ship a real /etc file.
const SUDO: Svc = Svc {
    etc: "/etc/pam.d/sudo",
    vendor: Some("/usr/lib/pam.d/sudo"),
};
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

const LOGIN_USAGE: &str = "usage: irlume login <status|enable|disable|reconcile> [--with-sudo] \
     [--with-polkit] [--apply] [--force] [--adjust-jumps]";

pub fn run(action: Option<&str>, args: &[String]) -> ExitCode {
    let apply = args.iter().any(|a| a == "--apply");
    let with_sudo = args.iter().any(|a| a == "--with-sudo");
    let with_polkit = args.iter().any(|a| a == "--with-polkit");
    let force = args.iter().any(|a| a == "--force");
    let adjust_jumps = args.iter().any(|a| a == "--adjust-jumps");
    // `--force` is a person overriding a refusal: an enable rebuilds
    // overrides an administrator edited, and a disable goes ahead although a
    // GNOME keyring token depends on the line it removes. Reconcile runs
    // unattended, and a status must never be mistaken for a way to apply it.
    if force && !matches!(action, Some("enable" | "disable")) {
        eprintln!("{LOGIN_USAGE}");
        eprintln!("  (--force applies to login enable and disable only)");
        return ExitCode::from(2);
    }
    // `--adjust-jumps` is a person agreeing to a change of a line irlume did
    // not write, for the same two commands.
    if adjust_jumps && !matches!(action, Some("enable" | "disable")) {
        eprintln!("{LOGIN_USAGE}");
        eprintln!("  (--adjust-jumps applies to login enable and disable only)");
        return ExitCode::from(2);
    }
    let flags = RunFlags {
        force,
        adjust_jumps,
    };
    // On NixOS the system configuration generates the stacks, and the flake
    // module writes irlume's rules. Refused ahead of the root check, the PAM
    // lock and the capability reading, so nothing is asked for or touched.
    let nixos =
        matches!(action, Some("enable" | "disable" | "reconcile")) && crate::nixos::host_is_nixos();
    match action {
        None | Some("status") => status(),
        Some("reconcile") if nixos => {
            eprintln!("{}", crate::nixos::RECONCILE_NOTICE);
            ExitCode::SUCCESS
        }
        Some("enable" | "disable") if nixos => {
            eprintln!("{}", crate::nixos::LOGIN_REFUSAL);
            ExitCode::FAILURE
        }
        Some("enable") => act(true, apply, with_sudo, with_polkit, flags),
        Some("disable") => act(false, apply, with_sudo, with_polkit, flags),
        Some("reconcile") => reconcile(),
        _ => {
            eprintln!("{LOGIN_USAGE}");
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

/// The facts the self-heal marker records (#607 grew `face_lock_intent`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WiredMarker {
    pub(crate) sudo: bool,
    pub(crate) polkit: bool,
    /// Whether the lock surface is OBSERVED wired. Stays an observation: the
    /// invariant `with_lock=true` implies a surface irlume really wired is
    /// what keeps reconcile from chasing a lock screen that was never ours.
    pub(crate) lock: bool,
    /// Whether an enable WANTED face-on-lock and the wiring was suppressed
    /// because Omarchy's dedicated face lane exists (#607). The recorded
    /// intent reconcile replays when that lane later disappears; absent in
    /// markers written before #607, defaulting false.
    pub(crate) face_lock_intent: bool,
}

/// Persist (on enable) or remove (on disable) the wiring marker. The body is a
/// tiny stable key=value record of the extra scopes so reconcile re-applies the
/// same `--with-sudo` / `--with-polkit` choice, not a bare login wiring.
pub(crate) fn write_wired_marker(enable: bool, marker: &WiredMarker) {
    let path = wired_marker_path();
    if !enable {
        let _ = std::fs::remove_file(&path);
        return;
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let WiredMarker {
        sudo: with_sudo,
        polkit: with_polkit,
        lock: with_lock,
        face_lock_intent,
    } = marker;
    // with_lock records whether we actually wired the lock screen, so a later
    // absence of /etc/pam.d/kde is only a regression when it was ours to maintain
    // (a Plasma package's vendor /usr/lib/pam.d/kde on a GNOME box must not read
    // as a regression and loop reconcile forever).
    let body = format!(
        "with_sudo={with_sudo}\nwith_polkit={with_polkit}\nwith_lock={with_lock}\nface_lock_intent={face_lock_intent}\n"
    );
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

/// Re-read the marker's recorded facts. Returns `None` when login was never
/// enabled (no marker), so reconcile does nothing on machines that opted out.
pub(crate) fn read_wired_marker() -> Option<WiredMarker> {
    let path = wired_marker_path();
    // In production (default state dir) the marker must be root-owned: reconcile
    // acts on its sudo flag as root, so a marker a non-root user could plant
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
    // next `login enable` / adopt rewrites it with the real value. Same default
    // for face_lock_intent (#607): an old marker records no yield, so it can
    // never drive a reclaim on its own.
    Some(WiredMarker {
        sudo: flag("with_sudo"),
        polkit: flag("with_polkit"),
        lock: flag("with_lock"),
        face_lock_intent: flag("face_lock_intent"),
    })
}

/// Idempotent repair entry point, meant to run unattended from a systemd path
/// unit watching the greeter PAM files. If login was enabled (marker present),
/// first remove blocked remote-seat authentication authority, then establish
/// capabilities before maintaining overrides and re-applying the recorded
/// configuration. Always root (the path unit's service runs as root).
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
    let Some(WiredMarker {
        sudo: with_sudo,
        polkit: with_polkit,
        lock: with_lock,
        face_lock_intent,
    }) = read_wired_marker()
    else {
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
        let with_sudo = sudo_wired();
        let with_polkit = polkit_wired() == Some(true);
        // Record the lock screen as ours only if the /etc override actually
        // carries the module now (it was wired), not merely because the vendor
        // file exists.
        let (lock_svc, _) = lock_surface();
        let with_lock =
            Path::new(lock_svc.etc).exists() && file_has_module(Path::new(lock_svc.etc));
        write_wired_marker(
            true,
            &WiredMarker {
                sudo: with_sudo,
                polkit: with_polkit,
                lock: with_lock,
                face_lock_intent: false,
            },
        );
        eprintln!(
            "[login] adopted the existing face-login wiring into the self-heal marker \
             (sudo={with_sudo}, polkit={with_polkit}, lock={with_lock}); a future distro PAM \
             update will now re-apply it automatically"
        );
        // The override maintenance a marked run does, on this run too: an
        // upgrade or a state-directory recovery lands here, and its legacy
        // overrides get their tracking line and a changed vendor copy is
        // followed now rather than on the next reconcile.
        if !prepare_reconcile() {
            return ExitCode::FAILURE;
        }
        let maintained = maintain_overrides();
        // Package upgrades start this run, so the face lines of a LightDM
        // that serves remote login screens come out here, not on a later one.
        // Safety removal can erase the last module before the remote-seat
        // classifier runs. Still perform normal regression detection so a
        // legacy adopted stack receives its reseal-only recipe when possible.
        let code = reconcile_wiring(with_sudo, with_polkit, with_lock, false);
        return if maintained { code } else { ExitCode::FAILURE };
    };
    // The marker records what `login enable` wired, and it can drift: a real
    // install was found with an irlume-created /etc/pam.d/polkit-1 while its
    // marker said with_polkit=false, so reconcile never maintained polkit and
    // the pre-abort=die stanza would have survived every upgrade unmigrated.
    // The FILE is the ground truth for "is this surface ours": adopt a wired
    // surface the marker missed, the same reasoning as the no-marker adoption
    // above, and record it so the next run agrees.
    let file_sudo = sudo_wired();
    let file_polkit = polkit_wired() == Some(true);
    let adopted = (file_sudo && !with_sudo) || (file_polkit && !with_polkit);
    let with_sudo = with_sudo || file_sudo;
    let with_polkit = with_polkit || file_polkit;
    if adopted && effective_uid() == 0 {
        write_wired_marker(
            true,
            &WiredMarker {
                sudo: with_sudo,
                polkit: with_polkit,
                lock: with_lock,
                face_lock_intent,
            },
        );
        eprintln!(
            "[login] adopted wired surfaces the marker missed \
             (sudo={with_sudo}, polkit={with_polkit})"
        );
    }
    // After safety removal and capability establishment, overrides irlume
    // created from vendor files are kept in step before the regression checks:
    // a matching file written by an older release gets its tracking line, and
    // one nobody edited is rebuilt from a changed vendor copy with the settings
    // its irlume lines already have. An override with lines irlume did not
    // write is never written here. None of this starts a re-apply.
    if !prepare_reconcile() {
        return ExitCode::FAILURE;
    }
    let maintained = effective_uid() != 0 || maintain_overrides();
    let code = reconcile_wiring(with_sudo, with_polkit, with_lock, face_lock_intent);
    if maintained {
        code
    } else {
        ExitCode::FAILURE
    }
}

/// Remove remote-seat authority before any capability query, camera fallback,
/// or override refresh. Repair can add authentication rules and must wait for
/// established capabilities; removing an existing grant path must not.
/// Called with the PAM lock held, including on the marker-adoption path.
fn prepare_reconcile() -> bool {
    for svc in GREETERS {
        if !remote_seats::governs(service_name(svc.etc)) {
            continue;
        }
        let Some(why) = remote_seats::face_blocked(service_name(svc.etc)) else {
            continue;
        };
        match strip_remote_auth(svc.etc) {
            Ok(true) => eprintln!(
                "[login] {why}; removing LightDM's face and fingerprint lines (pam_irlume only)"
            ),
            Ok(false) => {}
            Err(e) => {
                eprintln!("[login] cannot remove LightDM authentication authority: {e}");
                return false;
            }
        }
    }
    wait_for_daemon_start();
    if !crate::caps_established() {
        eprintln!("[login] cannot assess PAM repair until daemon capabilities are established");
        return false;
    }
    true
}

/// Replace only credential/face auth rules with the existing inert-slot form.
/// No insertion, backup restoration, include rewrite, or session change is
/// permitted here. Keeping one slot per rule also preserves jumps arriving
/// from included stacks; the reseal hand-off and password path stay in place.
fn strip_remote_auth(etc: &str) -> Result<bool, String> {
    let path = Path::new(etc);
    let current = match token::read_stack_file(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("{etc}: {error}")),
    };
    if !current.lines().any(irlume_auth_rule_beyond_reseal) {
        return Ok(false);
    }
    // Linked password/reseal-only stacks need no write and must not prevent
    // unrelated repairs. Validate replacement authority only after the bounded
    // pinned read establishes that an authentication rule needs removal.
    inspect_target(path)?;
    if effective_uid() != 0 {
        return Err("safety removal needs root; run: sudo irlume login reconcile".into());
    }
    // A physical-line replacement cannot safely reason about a continued or
    // unrecognized directive. Report failure without changing its bytes.
    if has_line_continuation(&current) || unreadable_line(&current).is_some() {
        return Err(format!(
            "{etc} contains a PAM line that cannot be safely rewritten"
        ));
    }
    if current
        .lines()
        .filter(|line| irlume_auth_rule_beyond_reseal(line))
        .filter_map(irlume_rule)
        .any(|rule| !control_ignores_module_ignore(rule.control))
    {
        return Err(format!(
            "{etc} gives PAM_IGNORE a non-inert control action; keeping the file"
        ));
    }
    let mut next = String::with_capacity(current.len());
    for line in current.split_inclusive('\n') {
        if irlume_auth_rule_beyond_reseal(line) {
            let inert = overrides::neutralize(line);
            next.push_str(inert.trim_end_matches('\n'));
            if line.ends_with('\n') {
                next.push('\n');
            }
        } else {
            next.push_str(line);
        }
    }
    write_atomic_checked_if(path, &next, Some(&current), &|| Ok(()))?;
    Ok(true)
}

/// Private daemon helper. No socket request or capability probe occurs here.
pub(crate) fn token_lock_helper() -> ExitCode {
    use std::io::Read as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    let serve = || -> Result<(), String> {
        if effective_uid() != 0 {
            return Err("token delivery lock helper requires root".into());
        }
        // SAFETY: fcntl validates stdin and creates a new owned descriptor.
        let descriptor = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
        if descriptor < 0 {
            return Err("private helper socket unavailable".into());
        }
        // SAFETY: descriptor was successfully duplicated and is uniquely owned.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let mut socket = UnixStream::from(descriptor);
        socket
            .peer_addr()
            .map_err(|_| "helper stdin is not a Unix socket")?;
        // SAFETY: ucred contains plain integers; getsockopt fills the checked buffer.
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
        // SAFETY: peer and size are live writable buffers with their actual extent.
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(peer).cast(),
                &mut size,
            )
        } != 0
            || size as usize != std::mem::size_of_val(&peer)
            || peer.uid != 0
        {
            return Err("helper socket must originate from root".into());
        }
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| e.to_string())?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        (&mut socket)
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err("invalid helper account".into());
        }
        let user = std::str::from_utf8(&bytes).map_err(|_| "invalid helper account")?;
        if user.contains(['\0', '\n', '\r']) {
            return Err("invalid helper account".into());
        }
        // Reuse the exact lock/recovery and delivery parser, including every
        // legacy exclusion descriptor. The parent bounds this whole process.
        let guard = lock_pam()?;
        if let Some(reason) = token::token_delivery_refusal(user) {
            return Err(reason);
        }
        guard
            .handoff(&socket, Instant::now() + Duration::from_secs(1))
            .map_err(|e| e.to_string())
    };
    match serve() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

/// Every surface with a vendor path, with the recipe its override takes.
fn override_surfaces() -> Vec<(&'static Svc, overrides::Recipe)> {
    GREETERS
        .iter()
        .filter(|s| s.vendor.is_some())
        .map(|s| (s, overrides::Recipe::Greeter))
        .chain([
            (&LOCKSCREEN, overrides::Recipe::Lock),
            (&SUDO, overrides::Recipe::Verify),
            (&POLKIT, overrides::Recipe::Polkit),
        ])
        .collect()
}

/// Reconcile's maintenance step over every override on this machine. Returns
/// false when a write failed, which fails the run.
fn maintain_overrides() -> bool {
    let mut ok = true;
    for (svc, recipe) in override_surfaces() {
        match maintain_override(svc, recipe) {
            Ok(Some(line)) => eprintln!("{line}"),
            Ok(None) => {}
            Err(e) => {
                eprintln!("[login] ✗ {e}");
                ok = false;
            }
        }
    }
    ok
}

/// Whether a failed write is the administrator's choice rather than a fault:
/// a file made immutable (`chattr +i`, EPERM) or a read-only mount (EROFS).
/// Reconcile then leaves the file alone and says so, instead of failing the
/// unit at every timer run; doctor keeps reporting the pending update.
fn write_refused_by_admin(error: &str) -> bool {
    [
        std::io::Error::from_raw_os_error(1).to_string(),
        std::io::Error::from_raw_os_error(30).to_string(),
    ]
    .iter()
    .any(|reason| error.ends_with(reason.as_str()))
}

/// The maintenance step for one surface: the line to log when it wrote.
fn maintain_override(svc: &Svc, recipe: overrides::Recipe) -> Result<Option<String>, String> {
    let (etc, Some(vendor_path)) = (Path::new(svc.etc), svc.vendor) else {
        return Ok(None);
    };
    // A symlink or a file with several names is refused by every write here;
    // skipping it keeps the unit from failing every half hour over a file
    // doctor already reports.
    if !file_is_created_override(etc) || inspect_target(etc).is_err() {
        return Ok(None);
    }
    let Some(current) = read_optional(etc)? else {
        return Ok(None);
    };
    let vendor = match read_optional(Path::new(vendor_path)) {
        Ok(vendor) => vendor,
        // Unreadable is not absent; leave the file for doctor to report.
        Err(_) => return Ok(None),
    };
    let decided = vendor
        .as_deref()
        .map(|v| crate::logintx::sha256_hex(v.as_bytes()));
    let maintenance = with_stack_reader(stack_reader(svc.etc), || {
        overrides::maintenance(recipe, &current, vendor_path, vendor.as_deref())
    });
    let (content, done) = match maintenance {
        overrides::Maintenance::Record(content) => (
            content,
            format!("recorded {vendor_path} in the override header; no PAM line changed"),
        ),
        overrides::Maintenance::Refresh(content) => (
            content,
            format!(
                "rebuilt from {vendor_path}, which changed since irlume created this override; \
                 irlume's lines keep their settings"
            ),
        ),
        overrides::Maintenance::Blocked(overrides::Hold::Unreadable) => {
            let why = overrides::maintenance_unread(&current, vendor_path, vendor.as_deref());
            return Ok(why.map(|why| {
                format!(
                    "[login] ⚠ {}: left as it is: {why}, and reconcile changes no file it \
                     cannot read as PAM does",
                    svc.etc
                )
            }));
        }
        overrides::Maintenance::Nothing | overrides::Maintenance::Blocked(_) => return Ok(None),
    };
    // The maintenance owner infers the reseal-only recipe from the reduced
    // stack. Let that recipe propagate vendor policy updates while remote
    // seats remain enabled, but never publish a result that restores their
    // authentication authority. Check again at publication if policy changes
    // after the first check; the PAM lock does not lock LightDM configuration.
    let check_remote = || {
        if (has_line_continuation(&content)
            || unreadable_line(&content).is_some()
            || content.lines().any(irlume_auth_rule_beyond_reseal))
            && remote_seats::face_blocked(service_name(svc.etc)).is_some()
        {
            Err(format!(
                "{}: override maintenance cannot prove remote-seat authentication stays disabled",
                svc.etc
            ))
        } else {
            Ok(())
        }
    };
    check_remote()?;
    // Made from the vendor copy read above, so kept only while that copy is
    // still the same once the file is in place, as in `wire_override`. A
    // package that changed it meanwhile starts another reconcile, which
    // decides afresh.
    let vendor_moved = std::cell::Cell::new(false);
    let still = || -> Result<(), String> {
        #[cfg(test)]
        change_vendor_for_test(Path::new(vendor_path));
        if vendor_digest_now(vendor_path) == decided {
            check_remote()
        } else {
            vendor_moved.set(true);
            Err(format!(
                "{vendor_path} changed while irlume was writing {}",
                svc.etc
            ))
        }
    };
    match write_atomic_checked_if(etc, &content, Some(&current), &still) {
        Ok(()) => Ok(Some(format!("[login] {}: {done}", svc.etc))),
        Err(e) if write_refused_by_admin(&e.message) => Ok(Some(format!(
            "[login] ⚠ {}: left as it is, since it cannot be written ({e})",
            svc.etc
        ))),
        Err(e) if vendor_moved.get() && !e.landed => Ok(Some(format!(
            "[login] ⚠ {}: left as it is: {e}; the next reconcile decides again",
            svc.etc
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Whether reconcile's maintenance step would rebuild an override from a
/// changed vendor copy: the TUI offers the reconcile for it. Kept apart from
/// [`reconcile_needed`], which means the wiring was lost and logins fall back
/// to the password; here the wiring works and only a vendor update waits.
/// Recording a tracking line is not offered (it changes no PAM line), nor is an
/// edited override (reconcile never writes one, so offering it would loop).
pub(crate) fn override_refresh_due() -> bool {
    if crate::nixos::host_is_nixos() {
        return false;
    }
    let stat = std::fs::symlink_metadata(wired_marker_path())
        .map(|_| ())
        .map_err(|e| e.kind());
    if !marked_for_maintenance(stat, || read_wired_marker().is_some(), login_wired) {
        return false;
    }
    override_surfaces()
        .into_iter()
        .any(|(svc, recipe)| refresh_due_for(svc, recipe))
}

/// Whether reconcile would run its maintenance step, as far as this process
/// can tell. Reconcile maintains overrides only with a marker, which lives in
/// the root-only state directory: the TUI runs as the person and usually
/// cannot even see whether it exists (`stat` is refused). The wiring itself
/// is readable, and a rebuild needs irlume's lines in the file anyway, so a
/// marker that cannot be looked at is judged by that.
fn marked_for_maintenance(
    stat: Result<(), std::io::ErrorKind>,
    marker: impl FnOnce() -> bool,
    wired: impl FnOnce() -> bool,
) -> bool {
    match stat {
        Ok(()) => marker(),
        Err(std::io::ErrorKind::NotFound) => false,
        Err(_) => wired(),
    }
}

/// [`override_refresh_due`] for one surface: the same reads and the same pure
/// decision [`maintain_override`] takes, so the offer and the repair agree.
fn refresh_due_for(svc: &Svc, recipe: overrides::Recipe) -> bool {
    let etc = Path::new(svc.etc);
    let Some(vendor_path) = svc.vendor else {
        return false;
    };
    if !file_is_created_override(etc) || inspect_target(etc).is_err() {
        return false;
    }
    let (Ok(Some(current)), Ok(vendor)) =
        (read_optional(etc), read_optional(Path::new(vendor_path)))
    else {
        return false;
    };
    matches!(
        with_stack_reader(stack_reader(svc.etc), || {
            overrides::maintenance(recipe, &current, vendor_path, vendor.as_deref())
        }),
        overrides::Maintenance::Refresh(_)
    )
}

/// One override that needs attention, for doctor and `login status`.
pub(crate) struct OverrideReport {
    /// The PAM service name. Never a path: doctor's detail is machine output.
    pub(crate) service: &'static str,
    /// The `/etc` path, for the human `login status` report only.
    pub(crate) path: &'static str,
    pub(crate) level: overrides::Level,
    pub(crate) note: String,
}

/// Every irlume-created override that is not simply in step with its vendor
/// copy, and why.
pub(crate) fn override_reports() -> Vec<OverrideReport> {
    override_surfaces()
        .into_iter()
        .filter_map(|(svc, recipe)| {
            let etc = Path::new(svc.etc);
            let vendor_path = svc.vendor?;
            if !file_is_created_override(etc) {
                return None;
            }
            let service = service_name(svc.etc);
            let report = |level, note: String| {
                Some(OverrideReport {
                    service,
                    path: svc.etc,
                    level,
                    note,
                })
            };
            if let Err(why) = inspect_target(etc) {
                return report(
                    overrides::Level::Info,
                    format!("not maintained: {}", why.replace(svc.etc, "the file")),
                );
            }
            let current = match read_optional(etc) {
                Ok(Some(current)) => current,
                Ok(None) => return None,
                // Informational: an unprivileged doctor may simply lack the
                // permission, which is no fault of the file.
                Err(_) => {
                    return report(overrides::Level::Info, "cannot be read here".to_string());
                }
            };
            let vendor = match read_optional(Path::new(vendor_path)) {
                Ok(vendor) => vendor,
                Err(_) => {
                    return report(
                        overrides::Level::Info,
                        "its vendor copy cannot be read here".to_string(),
                    );
                }
            };
            let siblings: Vec<String> = [".rpmnew", ".pacnew", ".dpkg-dist"]
                .iter()
                .map(|suffix| format!("{service}{suffix}"))
                .filter(|name| etc.with_file_name(name).exists())
                .collect();
            // A `.pre-irlume` holding another file stops `--force`, so the
            // note that suggests it says to move that file first.
            let backup_name = format!("{service}{BACKUP}");
            let stale_backup = matches!(
                read_optional(&etc.with_file_name(&backup_name)),
                Ok(Some(backup)) if backup != current
            );
            let assessed = with_stack_reader(stack_reader(svc.etc), || {
                overrides::assess(
                    recipe,
                    &current,
                    vendor_path,
                    vendor.as_deref(),
                    &siblings,
                    stale_backup.then_some(backup_name.as_str()),
                    scope_flag(svc.etc),
                )
            });
            match assessed {
                (overrides::Level::Pass, _) | (_, None) => None,
                (level, Some(note)) => report(level, note),
            }
        })
        .collect()
}

/// Whether deleting `path` would leave its service with no PAM configuration:
/// the file is a surface's `/etc` copy and that surface's vendor file is gone
/// (or cannot be seen). PAM then falls back to `other`, which denies, so every
/// login through that service fails, the password included. Verify and the
/// rollback precheck ask this before a rollback would remove a file apply
/// created; the removal itself asks [`vendor_gone_service`].
pub(crate) fn removal_orphans_service(path: &Path) -> bool {
    removal_orphans_in(&override_pairs(), path)
}

/// [`removal_orphans_service`] over a given list of `(etc, vendor)` paths, so
/// a test can name surfaces under a temporary root.
pub(crate) fn removal_orphans_in(surfaces: &[(&str, &str)], path: &Path) -> bool {
    surfaces.iter().any(|(etc, _)| Path::new(etc) == path)
        && removal_orphans_for(path.exists(), !vendor_gone_in(surfaces, path))
}

/// Whether `path` is a surface's `/etc` copy whose vendor file is gone, or is
/// not one PAM can use (see [`vendor_usable`]), whatever is at `path` now.
/// The removal a rollback makes asks this again once the file it removes is
/// out of the way, where [`removal_orphans_service`], which needs the file
/// there, says no.
pub(crate) fn vendor_gone_service(path: &Path) -> bool {
    vendor_gone_in(&override_pairs(), path)
}

/// [`vendor_gone_service`] over a given list of `(etc, vendor)` paths.
pub(crate) fn vendor_gone_in(surfaces: &[(&str, &str)], path: &Path) -> bool {
    surfaces
        .iter()
        .find(|(etc, _)| Path::new(etc) == path)
        .is_some_and(|(_, vendor)| !vendor_usable(vendor))
}

/// Whether PAM can use the vendor file at `vendor_path` as the service's
/// stack: a regular file (through a symlink too, as PAM follows one) that can
/// be opened. Something else at that path, such as a directory or a FIFO a
/// package transaction leaves there for a moment, is not one, and a service
/// whose `/etc` override is removed then has no configuration. A FIFO is never
/// opened: its type is checked first.
fn vendor_usable(vendor_path: &str) -> bool {
    std::fs::metadata(vendor_path).is_ok_and(|meta| meta.is_file())
        && std::fs::File::open(vendor_path).is_ok()
}

/// The `(etc, vendor)` paths of the surfaces irlume may create overrides for.
fn override_pairs() -> Vec<(&'static str, &'static str)> {
    override_surfaces()
        .iter()
        .filter_map(|(svc, _)| Some((svc.etc, svc.vendor?)))
        .collect()
}

/// Testable core of [`removal_orphans_in`].
fn removal_orphans_for(file_exists: bool, vendor_exists: bool) -> bool {
    file_exists && !vendor_exists
}

/// The rest of reconcile: the regression checks and, when one fires, the
/// re-apply of the recorded wiring.
/// Whether this surface counts for [`anchor_gone_regression`]: a surface
/// this configuration wants its recipe to land in, the active display
/// manager's own greeter among them. A remote-seat greeter is governed by
/// [`remote_seat_change`]; a surface nothing wants is unwired by any apply,
/// which reconcile's other checks scope as ever.
fn anchor_gone_counts(
    role: &str,
    want: bool,
    blocked: bool,
    primary: Option<&str>,
    svc: &str,
) -> bool {
    (role == ROLE_LOGIN && !blocked && want && primary == Some(svc))
        || (want
            && (role == ROLE_SUDO
                || role == ROLE_POLKIT
                || role == ROLE_LOCK
                || role == ROLE_LOGIN_FP))
}

/// Whether a wired surface's recipe can no longer land: the surface holds
/// irlume's lines, and the enable for it would only take them out, because
/// no anchor qualifies anymore (#932). The stale layout still answers every
/// presence check (the module is in the file), so reconcile re-applies the
/// wiring, which performs that removal, instead of fast-pathing over it:
/// every surface this configuration wants wired, the active login greeter
/// among them, the opt-in surfaces as [`wired_surface_regressed`] scopes
/// them.
fn anchor_gone_regression(with_sudo: bool, with_polkit: bool) -> bool {
    // `(unknown)` and no display manager at all name no greeter, so the
    // greeter leg of the walk never counts; the lock, fingerprint and
    // opt-in surfaces do not depend on the active display manager and are
    // probed as ever.
    let primary = active_display_manager()
        .map(|dm| dm_pam_services(&dm).0)
        .filter(|primary| *primary != "(unknown)");
    let mut gone = false;
    walk_surfaces(
        true,
        with_sudo,
        with_polkit,
        &mut |svc, role, wire, want, blocked| {
            if gone || !anchor_gone_counts(role, want, blocked, primary, service_name(svc.etc)) {
                return;
            }
            gone = wire_service(svc, true, false, wire)
                .is_ok_and(|o| enable_drops(true, false, Some(&o)));
        },
    );
    gone
}

fn reconcile_wiring(
    with_sudo: bool,
    with_polkit: bool,
    with_lock: bool,
    face_lock_intent: bool,
) -> ExitCode {
    // prepare_reconcile established capabilities before override maintenance
    // and this repair pass. Its safety-only removal ran before that query.
    // #607: the Omarchy lane pair is its own regression shape. The lane facts
    // are read once here and given to both pure cores, so this check and
    // `reconcile_needed` cannot disagree about them.
    let omarchy = irlume_common::platform::omarchy_present();
    let face_lane_present = Path::new(OMARCHY_FACE_LANE).exists();
    let stock_wired = lock_wired();
    let reclaim = lane_reclaim_for(face_lock_intent, omarchy, face_lane_present, stock_wired);
    let lane_yield = lane_yield_for(omarchy, face_lane_present, stock_wired, with_lock, || {
        wants().face_lock
    });
    // A greeter `remote_seats` governs can need its face lines stripped or
    // put back while the module stays in its stack.
    let remote_seat = remote_seat_change();
    if !active_login_regressed()
        && remote_seat.is_none()
        && !lockscreen_regressed(with_lock)
        && !wired_surface_regressed(with_sudo, with_polkit)
        && !anchor_gone_regression(with_sudo, with_polkit)
        && !reclaim
        && !lane_yield
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
    if reclaim {
        eprintln!("[login] the dedicated Omarchy face lane is gone; restoring the stock lock lane");
    } else if lane_yield {
        eprintln!("[login] the dedicated Omarchy face lane exists; yielding the stock lock lane");
    } else if let Some(RemoteSeat::Strip(why)) = &remote_seat {
        eprintln!("[login] {why}; removing LightDM's face and fingerprint lines");
    } else if let Some(RemoteSeat::Restore) = &remote_seat {
        eprintln!(
            "[login] LightDM no longer serves remote login screens; restoring its face lines"
        );
    } else if let Some(RemoteSeat::Unwire) = &remote_seat {
        eprintln!("[login] LightDM's reseal lines lost their anchor; removing them");
    } else {
        eprintln!("[login] greeter PAM configuration changed; re-applying irlume wiring");
    }
    // The lock is already held above; taking it again would deadlock.
    act_holding_lock(
        true,
        true,
        with_sudo,
        with_polkit,
        ScopeOrigin::Marker,
        RunFlags::default(),
    )
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
    let (svc, _) = lock_surface();
    Path::new(svc.etc).exists() && file_has_module(Path::new(svc.etc))
}

/// Does the sudo stack carry the module right now? irlume's line always lives
/// in the /etc file, whether it edited that file or materialized it from the
/// vendor copy.
fn sudo_wired() -> bool {
    let etc = Path::new(SUDO.etc);
    etc.exists() && file_has_module(etc)
}

/// Whether the active greeter's stack carries irlume's module, whatever its
/// lines do: reconcile's intactness rule, under which a greeter left with
/// only its reseal lines (`remote_seats`) is intact. Doctor reports face
/// login from [`active_login_wired_by_mode`] instead.
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

/// A missing active greeter is repairable only when today's recipe can land.
/// This also handles old markers: no new marker field is needed, and a later
/// PAM update that restores the anchor makes the greeter eligible again.
fn active_login_regressed() -> bool {
    if active_login_wired() {
        return false;
    }
    missing_greeter_regressed(crate::caps_established(), || {
        let Some(dm) = active_display_manager() else {
            return true;
        };
        let (primary, _) = dm_pam_services(&dm);
        if primary == "(unknown)" {
            return true;
        }
        let mut repairable = false;
        walk_surfaces(true, false, false, &mut |svc, role, wire, want, _| {
            if role == ROLE_LOGIN && service_name(svc.etc) == primary {
                repairable = greeter_repairable(svc, want, wire);
            }
        });
        repairable
    })
}

fn missing_greeter_regressed(ready: bool, probe: impl FnOnce() -> bool) -> bool {
    !ready || probe()
}

fn greeter_repairable(svc: &Svc, want: bool, wire: &dyn Fn(&str) -> (String, bool)) -> bool {
    want && wire_service(svc, true, false, wire).is_ok_and(|o| recipe_lands(&o))
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
    let (svc, _) = lock_surface();
    lock_regressed(Path::new(svc.etc), svc.vendor.map(Path::new))
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
/// wiring under which a module decline is silently ignored.
fn polkit_stanza_stale(etc: &Path) -> bool {
    std::fs::read_to_string(etc).is_ok_and(|c| {
        c.lines()
            .filter_map(irlume_rule)
            .any(|r| !r.control.contains("abort=die"))
    })
}

fn wired_surface_regressed(with_sudo: bool, with_polkit: bool) -> bool {
    let fp: Vec<&Path> = FP_GREETERS.iter().map(|s| Path::new(s.etc)).collect();
    surfaces_regressed(
        with_sudo.then(|| (Path::new(SUDO.etc), SUDO.vendor.map(Path::new))),
        with_polkit.then(|| (Path::new(POLKIT.etc), POLKIT.vendor.map(Path::new))),
        &fp,
    )
}

/// Testable core of [`wired_surface_regressed`], taking the paths so a temp
/// directory can drive it. `sudo`/`polkit` are `None` when the marker says we
/// never wired them; each carries its vendor path when it has one.
fn surfaces_regressed(
    sudo: Option<(&Path, Option<&Path>)>,
    polkit: Option<(&Path, Option<&Path>)>,
    fp_services: &[&Path],
) -> bool {
    // sudo is materialized from a vendor copy where the distribution ships it
    // only there (openSUSE Tumbleweed), so a deleted /etc override is a
    // regression the same way it is for polkit below. Elsewhere there is no
    // vendor copy and only a stripped file counts.
    if sudo.is_some_and(|(etc, vendor)| lock_regressed(etc, vendor)) {
        return true;
    }
    // polkit is materialized from a vendor copy on Fedora, so a DELETED /etc
    // override is a regression there exactly as it is for the lock screen.
    // A STALE stanza shape counts as regressed too: an older irlume wired
    // polkit with a plain `sufficient` line, under which the module's
    // PAM_ABORT (a decline; historically a head shake) is `default=ignore`d
    // and the decline does nothing, while the
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
    // `login reconcile` changes nothing on NixOS, so there is no repair to offer.
    if crate::nixos::host_is_nixos() {
        return false;
    }
    let Some(WiredMarker {
        sudo: with_sudo,
        polkit: with_polkit,
        lock: with_lock,
        face_lock_intent,
    }) = read_wired_marker()
    else {
        return false;
    };
    // The same #607 lane facts reconcile reads, so the TUI Repair offer and
    // the self-heal itself cannot disagree.
    let omarchy = irlume_common::platform::omarchy_present();
    let face_lane_present = Path::new(OMARCHY_FACE_LANE).exists();
    let stock_wired = lock_wired();
    active_login_regressed()
        || remote_seat_change().is_some()
        || lockscreen_regressed(with_lock)
        || wired_surface_regressed(with_sudo, with_polkit)
        || anchor_gone_regression(with_sudo, with_polkit)
        || lane_reclaim_for(face_lock_intent, omarchy, face_lane_present, stock_wired)
        || lane_yield_for(omarchy, face_lane_present, stock_wired, with_lock, || {
            wants().face_lock
        })
}

/// Whether any login surface's stack (a greeter, the fingerprint-keyring
/// service or the lock screen) carries irlume's module, whatever its lines
/// do, so a greeter holding only the reseal lines counts. What reconcile and
/// doctor's regeneration guard go by; reports of face login use
/// [`login_wired_by_mode`], and uninstall uses [`any_stack_wired`].
pub(crate) fn login_wired() -> bool {
    let (lock_svc, _) = lock_surface();
    for s in GREETERS
        .iter()
        .chain(FP_GREETERS.iter())
        .chain(std::iter::once(lock_svc))
    {
        if let Some(p) = service_present(s) {
            if file_has_module(&p) {
                return true;
            }
        }
    }
    false
}

/// Whether any stack `login disable` unwires still carries irlume's module: a
/// login surface ([`login_wired`]), sudo or polkit-1. Uninstall reports by it
/// after its disable, which leaves some stacks as they are (one with a line
/// that ends in `\`, say), sudo and polkit-1 among them.
pub(crate) fn any_stack_wired() -> bool {
    login_wired() || sudo_wired() || polkit_wired() == Some(true)
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
    let out = std::process::Command::new(SystemCommand::GnomeShell.path()?)
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
    /// Face engages on explicit input (`ondemand`: yes on COSMIC, empty Enter
    /// on other supported frontends) vs GDM's
    /// scan-immediately (`facefirst`). For GDM this is gated by GNOME version.
    /// The cold-login-vs-warm-lock control tension (keyring unlock) is handled
    /// uniformly by the module's `kr` arg, so it needs no per-DM field here.
    ondemand: bool,
}

/// Resolve the [`DmProfile`] for a greeter PAM service path. `gnome` is the
/// detected GNOME Shell major (for GDM's version gate).
fn dm_profile(greeter_etc: &str, gnome: Option<u32>) -> DmProfile {
    match greeter_etc.rsplit('/').next().unwrap_or("") {
        // COSMIC drops empty submits. The PAM module's service-specific hidden
        // prompt accepts an explicit nonempty yes; no ambient face-first switch.
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

/// Whether a greeter's wiring has something to do: a factor this run wants,
/// or, on a greeter whose face lines are kept out (`remote_seats`), a face or
/// fingerprint line an earlier enable left there. That line comes off even
/// while nothing wants a factor (the camera away for a moment): left there,
/// it serves the remote screens again once the camera is back.
fn greeter_wanted(s: &Svc, factors: bool, face_blocked: bool) -> bool {
    factors || (face_blocked && carries_face_lines(s.etc))
}

/// Whether a greeter gets irlume's lines. One whose face lines are kept out
/// (`remote_seats`) gets the reseal lines alone, but where that recipe cannot
/// land (no anchor, a continued line, lines irlume keeps as they are, or an
/// enable that would only take an earlier release's lines out because no
/// anchor qualifies anymore) it is unwired whole instead, so no face line
/// stays behind; the token guard then refuses a run that would strand a
/// keyring token that way.
fn greeter_want(
    s: &Svc,
    want: bool,
    face_blocked: bool,
    wire: &dyn Fn(&str) -> (String, bool),
) -> bool {
    if !(want && face_blocked) {
        return want;
    }
    // The recipe must land, not merely succeed: an enable that finds no
    // anchor in a file that holds irlume's lines takes them out, which
    // leaves the greeter with none of them, the outcome unwiring it whole
    // exists for. A kept override whose lines are the recipe's is landed:
    // the enable keeps them where they are.
    wire_service(s, true, false, wire).is_ok_and(|outcome| recipe_lands(&outcome))
}

fn recipe_lands(outcome: &WireOutcome) -> bool {
    !outcome.unmet
        && matches!(
            outcome.change,
            PlannedChange::Wire
                | PlannedChange::AlreadyCorrect
                | PlannedChange::MaterializeOverride
                | PlannedChange::RewireOverride
                | PlannedChange::KeepEditedOverride
        )
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

/// The active login manager and why irlume keeps face and fingerprint off
/// its greeter whatever the configuration wants (a LightDM that serves remote
/// login screens, see `remote_seats`), or `None`.
pub(crate) fn active_dm_face_blocked() -> Option<(String, String)> {
    let dm = active_display_manager()?;
    let (greeter, _) = dm_pam_services(&dm);
    remote_seats::face_blocked(greeter).map(|why| (dm, why))
}

/// Whether the active login manager's greeter stack carries irlume's `reseal`
/// session line, which hands a GNOME keyring token over.
pub(crate) fn active_greeter_hands_tokens_over() -> bool {
    active_display_manager().is_some_and(|dm| {
        let (greeter, _) = dm_pam_services(&dm);
        std::fs::read_to_string(format!("/etc/pam.d/{greeter}"))
            .is_ok_and(|text| token::delivers_tokens(&text))
    })
}

/// Whether the file at `etc` carries one of irlume's lines that reach the
/// camera or release a secret on their own: any irlume `auth` rule but the
/// `reseal` line.
fn carries_face_lines(etc: &str) -> bool {
    std::fs::read_to_string(etc).is_ok_and(|text| text.lines().any(irlume_auth_rule_beyond_reseal))
}

/// What reconcile has to change on a greeter `remote_seats` governs: strip
/// the face lines from one that is blocked (after an upgrade into this rule,
/// once XDMCP or VNC was turned on, or once LightDM's configuration changed
/// under a running LightDM), or put them back on one left with only its
/// `reseal` lines once nothing blocks it.
enum RemoteSeat {
    Strip(String),
    Restore,
    Unwire,
}

fn remote_seat_change() -> Option<RemoteSeat> {
    GREETERS.iter().find_map(|s| {
        let path = Path::new(s.etc);
        if !path.exists() || !file_has_module(path) {
            return None;
        }
        remote_seat_change_for(s, remote_seats::face_blocked(service_name(s.etc)))
    })
}

fn remote_seat_change_for(s: &Svc, blocked: Option<String>) -> Option<RemoteSeat> {
    match (blocked, carries_face_lines(s.etc)) {
        (Some(why), true) => Some(RemoteSeat::Strip(why)),
        (Some(_), false) => {
            let ondemand = dm_profile(s.etc, gnome_shell_major()).ondemand;
            let reseal_only = |c: &str| wire_greeter_impl(c, false, false, ondemand);
            (!greeter_want(s, true, true, &reseal_only)).then_some(RemoteSeat::Unwire)
        }
        // Only this rule leaves a greeter with irlume's module and no
        // face or keyring line: a greeter nothing wants is unwired whole.
        (None, false) if remote_seats::governs(service_name(s.etc)) => Some(RemoteSeat::Restore),
        _ => None,
    }
}

/// Login managers verified not to display PAM informational messages.
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
                // The module-path field and the arguments, like every other
                // PAM read here: a trailing comment, or another module's
                // argument, mentioning the module is not wiring, and this
                // check matching what libpam ignores is how the Repair tab
                // reports "fully wired" about a stack that is not.
                irlume_rule_has_arg(l, "keyring")
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
#[derive(Clone, Copy)]
pub(crate) struct Wants {
    /// Face releases the login credential only on the Secure (IR) tier.
    pub(crate) face_login: bool,
    /// Face verifies the lock screen on any camera.
    pub(crate) face_lock: bool,
    /// Fingerprint drives the keyring unlock.
    pub(crate) fp_keyring: bool,
}

/// `Auto` follows the hardware; an explicit method overrides it.
///
/// Read once per process, as the capabilities it starts from are
/// (`crate::caps`): the token guard, the plan and the writes of one run then
/// decide from the same method setting and fingerprint availability, instead
/// of each reading its own, which a method change or a reader coming and
/// going between them could make disagree.
pub(crate) fn wants() -> Wants {
    static WANTS: std::sync::OnceLock<Wants> = std::sync::OnceLock::new();
    *WANTS.get_or_init(read_wants)
}

fn read_wants() -> Wants {
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
    /// Whether the plan wanted irlume's lines here. Not only the files decide
    /// it: LightDM's remote-login settings do too (`remote_seats`), so an
    /// apply compares it as well as the state before writing.
    pub(crate) want: bool,
    /// Whether the plan kept the surface's face and fingerprint lines out
    /// (`remote_seats`), which the files it digests do not show either.
    pub(crate) face_blocked: bool,
    /// Whether the apply keeps the surface as it is although irlume's lines
    /// there are not the ones this run wants ([`WireOutcome`]'s `unmet`),
    /// which fails the apply. `keep-edited-override` covers that and an
    /// edited file whose irlume lines are already right, and the same file
    /// can be either, depending on the lines the configuration wants.
    pub(crate) kept: bool,
    /// Whether the person's `--adjust-jumps` would handle the surface
    /// differently because of an administrator's numeric jump
    /// ([`WireOutcome`]'s `adjustable`): an enable kept only because the
    /// update would move that jump, or a surface the run takes irlume's
    /// lines out of (every surface of a disable, and one an enable no longer
    /// wants wired) that keeps inactive lines where the flag removes them.
    /// The machine apply never changes such a line.
    pub(crate) adjustable: bool,
}

/// What `login enable`/`login disable` would change, computed without writing.
///
/// This runs the identical decision the apply path runs, with `apply` false, so
/// the plan cannot describe an outcome the apply would not produce. It reads
/// PAM files and needs no privilege; only applying does.
/// Called once per surface: the service, its role, the wiring recipe for it,
/// and whether this configuration wants it wired.
/// Called once per surface: the service, its role, the wiring recipe for it,
/// whether this configuration wants it wired, and whether its face and
/// fingerprint lines are kept out whatever the configuration wants
/// (`remote_seats`).
type SurfaceVisitor<'a> =
    dyn FnMut(&Svc, &'static str, &dyn Fn(&str) -> (String, bool), bool, bool) + 'a;

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
        // A login screen remote users reach keeps only irlume's `reseal`
        // lines, the keyring hand-off, which never reaches the camera
        // (`remote_seats`).
        let blocked = remote_seats::face_blocked(service_name(s.etc)).is_some();
        let (face_line, keyring_line) = if blocked {
            (false, false)
        } else {
            (face, fp_keyring)
        };
        let greeter_wire = |c: &str| wire_greeter_impl(c, face_line, keyring_line, prof.ondemand);
        let wanted = greeter_wanted(s, face || fp_keyring, blocked);
        let want = greeter_want(s, wanted, blocked, &greeter_wire);
        // The flag says face and fingerprint are kept out of a stack that
        // would carry them; a greeter nothing wants is unwired as ever, and
        // the token guard treats it as ever.
        visit(s, ROLE_LOGIN, &greeter_wire, want, blocked && wanted);
    }
    for s in FP_GREETERS {
        let fp_wire = |c: &str| wire_fp_keyring(c, service_name(s.etc));
        visit(s, ROLE_LOGIN_FP, &fp_wire, fp_keyring, false);
    }
    let (lock_svc, lock_wire) = lock_surface();
    // #607: the dedicated Omarchy face lane owns face-on-lock when it exists,
    // so the stock lane neither gains nor keeps our line (want=false unwires).
    visit(
        lock_svc,
        ROLE_LOCK,
        &lock_wire,
        face_lock && !stock_lane_yielded(),
        false,
    );
    if sudo_in_scope(enable, with_sudo) {
        visit(&SUDO, ROLE_SUDO, &wire_verify_service, true, false);
    }
    if polkit_in_scope(enable, with_polkit) {
        visit(&POLKIT, ROLE_POLKIT, &wire_polkit_service, true, false);
    }
}

/// Whether an enable leaves this surface without irlume's lines: it is not
/// wanted, or its recipe cannot land and the enable would only take the
/// lines an earlier release wired out (#932), which drops the delivery line
/// a keyring token needs with the rest. `probed` is the enable's own
/// decision for the surface ([`wire_service`], nothing applied); a
/// remote-seat greeter is never counted here, as ever.
fn enable_drops(want: bool, blocked: bool, probed: Option<&WireOutcome>) -> bool {
    if !want {
        return !blocked;
    }
    !blocked
        && probed.is_some_and(|o| {
            matches!(
                o.change,
                PlannedChange::StripInPlace
                    | PlannedChange::RestoreBackup
                    | PlannedChange::RemoveOverride
            )
        })
}

/// The accounts whose GNOME keyring token this login run would leave with
/// no delivery: every token holder when the run leaves a login stack that
/// carries irlume's `reseal` line without irlume's lines. A disable leaves
/// every one so, without asking what the configuration wants; an enable
/// leaves those the configuration no longer wants wired, and those whose
/// lines come out because no anchor qualifies anymore (#932).
pub(crate) fn tokens_a_run_strands(enable: bool) -> Result<Vec<String>, String> {
    if !enable {
        return tokens_a_disable_strands();
    }
    let mut dropping: Vec<&'static str> = Vec::new();
    walk_surfaces(true, false, false, &mut |svc, role, wire, want, blocked| {
        if role != ROLE_LOGIN && role != ROLE_LOGIN_FP {
            return;
        }
        // A login screen remote users reach loses its lines whatever a
        // token needs: leaving a face line there is the worse failure,
        // and the envelope still lets `irlume keyring forget` re-key the
        // keyring back (`greeter_want`, `remote_seats`).
        let probed = (want && !blocked)
            .then(|| wire_service(svc, true, false, wire).ok())
            .flatten();
        if enable_drops(want, blocked, probed.as_ref()) {
            dropping.push(svc.etc);
        }
    });
    token::tokens_stranded_by(&dropping)
}

pub(crate) fn plan(enable: bool, with_sudo: bool, with_polkit: bool) -> Vec<PlannedSurface> {
    let mut out = Vec::new();
    walk_surfaces(
        enable,
        with_sudo,
        with_polkit,
        &mut |svc, role, wire, want, blocked| {
            out.push(plan_surface(svc, role, wire, enable && want, blocked));
        },
    );
    out
}

/// One surface of a plan. `want` is whether this run wants irlume's lines in
/// it (the action and the configuration together).
fn plan_surface(
    svc: &Svc,
    role: &'static str,
    wire: &dyn Fn(&str) -> (String, bool),
    want: bool,
    face_blocked: bool,
) -> PlannedSurface {
    // A service whose decision cannot even be computed (an unreadable file)
    // is reported as not-installed rather than omitted: a surface silently
    // missing from a plan is how a consumer comes to believe it was covered.
    let (change, kept, adjustable) = wire_service(svc, want, false, wire)
        .map(|outcome| (outcome.change, outcome.unmet, outcome.adjustable))
        .unwrap_or((PlannedChange::NotInstalled, false, false));
    PlannedSurface {
        id: service_name(svc.etc),
        role,
        change,
        // The vendor file too, for a surface that has one: it decides what an
        // override becomes, so a vendor update makes the plan stale.
        state: surface_state_for(svc),
        want,
        face_blocked,
        kept,
        adjustable,
    }
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
    /// The failure is only that irlume kept the file as it was rather than
    /// change it as asked (see [`WireOutcome`]'s `unmet`): nothing went wrong
    /// with the machine, so the self-heal marker still follows the apply.
    pub(crate) kept: bool,
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
        &mut |svc, role, wire, want, _blocked| {
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
                kept: false,
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
        &mut |svc, role, wire, want, blocked| {
            out.push(apply_surface(
                svc,
                role,
                wire,
                enable && want,
                blocked,
                expected,
            ));
        },
    );
    out
}

/// A file's text and its digest, from one read. `(None, ABSENT)` when it is
/// absent, and also when it cannot be read or is not UTF-8, since then there
/// is no before-image a rollback could write back.
fn captured(path: &Path) -> (Option<String>, String) {
    match std::fs::read(path).map(String::from_utf8) {
        Ok(Ok(text)) => {
            let digest = crate::logintx::sha256_hex(text.as_bytes());
            (Some(text), digest)
        }
        _ => (None, crate::logintx::ABSENT.to_string()),
    }
}

/// The record for a surface this run did not write, with the reason: one
/// irlume refused (a symlink, or a file with more than one name), one that
/// changed between the plan and the write (its vendor copy included), or one
/// it could not read.
///
/// It records what is on disk, not "absent": the file's content and
/// attributes as the before-image and its digest as the after-state, and the
/// same for its `.pre-irlume` backup. The rollback precheck compares each
/// recorded after-digest with the live file, so claiming absence about a file
/// that exists made the whole transaction read as drift and refuse to roll
/// back, which is exactly when a partly applied run needs undoing. `before:
/// None` also means "remove it" to a restore, the opposite of leaving it
/// alone. A rollback leaves such a surface as it is: its file already holds
/// the recorded bytes, and a restore writes nothing over a file that does
/// (see [`restore_surface_with`]), so a link irlume refused stays a link and
/// an attribute changed since stays changed.
///
/// A file whose bytes cannot be captured is still recorded as absent: with no
/// before-image, a digest that matched the file would let a rollback delete
/// it, so it reads as drift instead. The backup is recorded only when a
/// restore of it could not fail: a regular file with one name, read as text.
fn untouched_record(svc: &Svc, role: &'static str, error: String) -> AppliedSurface {
    let path = Path::new(svc.etc);
    let (before, after_sha256) = captured(path);
    let sidecar = Sidecar::as_it_stands(&PathBuf::from(format!("{}{BACKUP}", svc.etc)));
    AppliedSurface {
        id: service_name(svc.etc),
        role,
        path: svc.etc.to_string(),
        change: PlannedChange::NotInstalled,
        before,
        before_metadata: crate::logintx::file_metadata(path),
        sidecar_before: sidecar.before,
        sidecar_metadata: sidecar.metadata,
        sidecar_existed: sidecar.existed,
        sidecar_after_sha256: sidecar.after_sha256,
        // The digest shape the applied path records and the precheck
        // compares: the live file alone, not the live+backup pair
        // `surface_state` makes.
        after_sha256,
        error: Some(error),
        kept: false,
    }
}

/// A surface's `.pre-irlume` backup, as its record describes it (see the
/// fields of the same names in [`AppliedSurface`]).
struct Sidecar {
    before: Option<String>,
    metadata: Option<(u32, u32, u32)>,
    existed: bool,
    after_sha256: Option<String>,
}

impl Sidecar {
    /// The backup before a write, with no after-state yet.
    fn before_write(path: &Path) -> Self {
        Self {
            before: std::fs::read_to_string(path).ok(),
            metadata: crate::logintx::file_metadata(path),
            existed: path.exists(),
            after_sha256: None,
        }
    }

    /// The backup as it stands, recorded as a surface left alone records
    /// it: its text as the before-image and its digest as the after-state, so
    /// a rollback leaves it as it is. Recorded only when a restore of it
    /// could not fail: a regular file with one name, read as text.
    fn as_it_stands(path: &Path) -> Self {
        match inspect_target(path).map(|found| found.map(|_| captured(path))) {
            Ok(Some((Some(text), digest))) => Self {
                before: Some(text),
                metadata: crate::logintx::file_metadata(path),
                existed: true,
                after_sha256: Some(digest),
            },
            _ => Self {
                before: None,
                metadata: None,
                existed: false,
                after_sha256: None,
            },
        }
    }

    /// The backup after this run's write, with the digest it has now. One
    /// that was absent before the write and is there now is the run's own
    /// only when this process published that very file (see
    /// [`published_here`]): one another writer put there meanwhile is
    /// recorded as it stands, so a rollback keeps it rather than deleting it
    /// as the run's.
    fn after_write(self, path: &Path) -> Self {
        let after = surface_digest(path);
        let appeared = !self.existed && after != crate::logintx::ABSENT && after != UNREADABLE;
        if appeared && !published_here(path) {
            return Self::as_it_stands(path);
        }
        Self {
            after_sha256: Some(after),
            ..self
        }
    }
}

/// Apply one surface of a machine transaction. `want` is whether this run
/// wants irlume's lines in it (the action and the configuration together).
fn apply_surface(
    svc: &Svc,
    role: &'static str,
    wire: &dyn Fn(&str) -> (String, bool),
    want: bool,
    face_blocked: bool,
    expected: &[PlannedSurface],
) -> AppliedSurface {
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
        return untouched_record(svc, role, message);
    }
    let planned = expected
        .iter()
        .find(|candidate| candidate.id == service_name(svc.etc));
    // What this run wants here can change without any file it digests
    // changing: LightDM's remote-login settings live elsewhere.
    if planned
        .is_some_and(|candidate| candidate.want != want || candidate.face_blocked != face_blocked)
    {
        return untouched_record(
            svc,
            role,
            format!(
                "{}: how it should be wired changed between the plan and the write \
                 (LightDM's remote login settings, say); not touched",
                svc.etc
            ),
        );
    }
    let planned_state = planned.map(|candidate| candidate.state.as_str());
    // The state covers the vendor file too: it decides what an override
    // becomes. The planned vendor digest is also handed to the write, which
    // compares it with the bytes it actually reads, so the check and the use
    // cannot see two versions of the vendor file.
    if let Some(planned_state) = planned_state {
        if planned_state != surface_state_for(svc) {
            return untouched_record(svc, role, drift_message(svc));
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
    let sidecar = Sidecar::before_write(&sidecar_path);
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
        return untouched_record(svc, role, message);
    }
    // Neither `--force` nor `--adjust-jumps`: the machine API never rebuilds
    // an edited override or changes a line irlume did not write.
    let opts = WireOpts {
        apply: true,
        force: false,
        adjust_jumps: false,
        enabling: false,
        expect_vendor: planned_state
            .filter(|_| svc.vendor.is_some())
            .and_then(|state| state.split(' ').nth(2))
            .map(str::to_string),
    };
    let (change, error, kept) = match wire_service_with(svc, want, &opts, wire) {
        // Kept rather than changed as asked: updating irlume's lines would
        // move a jump or one of them past an administrator's line, or the
        // file has a continued line. Nothing was written, and irlume's lines
        // are not the ones this run wanted, so the surface fails, as the
        // human command fails the run (`kept_unmet`), and the marker is not
        // written as if it had succeeded.
        Ok(outcome) if outcome.unmet => (outcome.change, Some(outcome.message), true),
        Ok(outcome) => (outcome.change, None, false),
        // Refused, or failed before anything was written: irlume changed
        // nothing at the path. What is there is the file this run read, or
        // one another writer put there meanwhile, which the checked write
        // refused to replace or remove. Recording the file this run read as
        // the before-image turned that refusal into a change a rollback
        // undid: it wrote the old bytes over the other writer's file, or
        // deleted a file created where there was none. So the file is
        // recorded as it stands, as a surface left alone is. The backup
        // keeps its own before and after, since the run may have made one
        // before the write was refused.
        Err(e) if !e.landed => {
            let (before, after_sha256) = captured(path);
            let sidecar = sidecar.after_write(&sidecar_path);
            return AppliedSurface {
                id: service_name(svc.etc),
                role,
                path: svc.etc.to_string(),
                change: PlannedChange::NotInstalled,
                before,
                before_metadata: crate::logintx::file_metadata(path),
                sidecar_before: sidecar.before,
                sidecar_metadata: sidecar.metadata,
                sidecar_existed: sidecar.existed,
                after_sha256,
                sidecar_after_sha256: sidecar.after_sha256,
                error: Some(e.message),
                kept: false,
            };
        }
        Err(e) => (PlannedChange::NotInstalled, Some(e.message), false),
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
    // Kept means this run wrote nothing there. A file that no longer reads as
    // it did before (another writer replaced or removed it meanwhile) is not
    // this run's to record as kept: it is recorded as it stands, untouched,
    // so neither the marker nor a rollback takes that other change for ours.
    if kept && read_error.is_none() && changed_since_read(before.as_deref(), &after_sha256) {
        return untouched_record(
            svc,
            role,
            format!(
                "{} changed while this run kept it as it was; recorded as it stands",
                svc.etc
            ),
        );
    }
    let (error, kept) = settle_surface(error, read_error, kept);
    // The same question for the backup: what did apply leave there. A
    // rollback that overwrites a backup somebody replaced afterwards is
    // the same defect as one that overwrites a stack.
    let sidecar = sidecar.after_write(&sidecar_path);
    AppliedSurface {
        id: service_name(svc.etc),
        role,
        path: svc.etc.to_string(),
        change,
        before,
        before_metadata,
        sidecar_before: sidecar.before,
        sidecar_metadata: sidecar.metadata,
        sidecar_existed: sidecar.existed,
        after_sha256,
        sidecar_after_sha256: sidecar.after_sha256,
        error,
        kept,
    }
}

/// Whether the file at a surface now differs from what this run read before
/// deciding: `before` is that content (`None` when absent), `after_sha256`
/// the digest read afterwards (`ABSENT` when gone).
fn changed_since_read(before: Option<&str>, after_sha256: &str) -> bool {
    let before_sha256 = before.map_or_else(
        || crate::logintx::ABSENT.to_string(),
        |text| crate::logintx::sha256_hex(text.as_bytes()),
    );
    before_sha256 != after_sha256
}

/// A surface's error and whether it was kept, once its after-state has been
/// read. A kept surface (irlume left it as it was rather than update it)
/// counts as kept only when that read succeeded: a file another writer made
/// unreadable meanwhile is an I/O failure, so the read error leads and the
/// surface is not kept, and `marker_follows` does not take it for a plain
/// refusal. Otherwise the write's error leads, as before.
fn settle_surface(
    error: Option<String>,
    read_error: Option<String>,
    kept: bool,
) -> (Option<String>, bool) {
    match (error, read_error) {
        (error, None) => (error, kept),
        (Some(refusal), Some(io)) if kept => (Some(format!("{io} (after: {refusal})")), false),
        (error, io) => (error.or(io), false),
    }
}

/// The flags of `login enable` and `login disable` that let a person past a
/// refusal. Reconcile passes neither.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RunFlags {
    /// `--force`.
    force: bool,
    /// `--adjust-jumps`.
    adjust_jumps: bool,
}

/// The command a person without root is told to run: the same action and
/// flags, with `--apply`, so following it literally does what they asked.
fn sudo_rerun_hint(enable: bool, with_sudo: bool, with_polkit: bool, flags: RunFlags) -> String {
    format!(
        "sudo irlume login {}{}{} --apply{}{}",
        if enable { "enable" } else { "disable" },
        if with_sudo { " --with-sudo" } else { "" },
        if with_polkit { " --with-polkit" } else { "" },
        if flags.force { " --force" } else { "" },
        if flags.adjust_jumps {
            " --adjust-jumps"
        } else {
            ""
        }
    )
}

fn act(enable: bool, apply: bool, with_sudo: bool, with_polkit: bool, flags: RunFlags) -> ExitCode {
    if apply && effective_uid() != 0 {
        eprintln!(
            "[login] applying changes needs root; run: {}",
            sudo_rerun_hint(enable, with_sudo, with_polkit, flags)
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
    act_holding_lock(
        enable,
        apply,
        with_sudo,
        with_polkit,
        ScopeOrigin::Command,
        flags,
    )
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

/// Who chose the opt-in scopes (`with_sudo`, `with_polkit`) of a run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ScopeOrigin {
    /// The command line: `--with-sudo` and `--with-polkit` are requests.
    Command,
    /// `reconcile` replaying the marker, which records what WAS wired.
    Marker,
}

/// Whether an opt-in surface asked for on the command line came to nothing:
/// no stack for it on this machine, no line irlume can wire next to, or an
/// anchor gone from a file an earlier release wired, whose lines an enable
/// then takes out, an unedited override removed with the vendor copy
/// restored among them. In each the surface ends the run unwired, which must
/// fail rather than report success. Reconcile only replays what an earlier
/// run observed, and a disable delivers nothing, so neither counts.
fn requested_scope_unmet(
    origin: ScopeOrigin,
    enable: bool,
    requested: bool,
    change: PlannedChange,
) -> bool {
    origin == ScopeOrigin::Command
        && enable
        && requested
        && matches!(
            change,
            PlannedChange::NotInstalled
                | PlannedChange::NoAnchor
                | PlannedChange::RestoreBackup
                | PlannedChange::StripInPlace
                | PlannedChange::RemoveOverride
        )
}

/// The line that names a requested opt-in surface this run did not wire, and
/// why. Printed after the per-file lines, so it is the last thing a reader
/// sees before the non-zero exit.
fn unmet_scope_line(flag: &str, service: &str, change: PlannedChange) -> String {
    let why = if change == PlannedChange::NotInstalled {
        format!("this machine has no {service} PAM service")
    } else {
        format!("irlume finds no line in the {service} PAM service to wire next to")
    };
    format!("[login] {flag}: not wired ({why})")
}

/// The lines one surface prints: its line and, for a person at the terminal,
/// its detail. Reconcile's output goes to the journal, which gets the line
/// only.
fn outcome_lines(outcome: &WireOutcome, origin: ScopeOrigin) -> Vec<String> {
    let mut lines = vec![format!("  {}", outcome.message)];
    if origin == ScopeOrigin::Command {
        if let Some(detail) = &outcome.detail {
            lines.push(detail.clone());
        }
    }
    lines
}

fn print_outcome(outcome: &WireOutcome, origin: ScopeOrigin) {
    for line in outcome_lines(outcome, origin) {
        println!("{line}");
    }
}

/// Whether a surface's irlume lines are not what a person asked for, because
/// updating or adding them was refused (a method switch refused in an
/// administrator's override, say): such a run fails, so face that was turned
/// off does not silently stay on, and a file left unwired is not reported as
/// done.
/// Reconcile only replays what an earlier run observed, so it does not count.
fn kept_unmet(origin: ScopeOrigin, outcome: &WireOutcome) -> bool {
    origin == ScopeOrigin::Command && outcome.unmet
}

fn act_holding_lock(
    enable: bool,
    apply: bool,
    with_sudo: bool,
    with_polkit: bool,
    origin: ScopeOrigin,
    flags: RunFlags,
) -> ExitCode {
    let RunFlags {
        force,
        adjust_jumps,
    } = flags;
    let opts = WireOpts {
        apply,
        force: force && enable && origin == ScopeOrigin::Command,
        // A person's run only: reconcile never changes a line irlume did not
        // write.
        adjust_jumps: adjust_jumps && origin == ScopeOrigin::Command,
        enabling: enable,
        expect_vendor: None,
    };
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
    // The packaging scriptlets run reconcile right after `try-restart`, which
    // lands inside the daemon's model-loading window (Ping answers
    // Ok("starting"); 21s measured exec-to-serving on a ThinkPad X13). In that
    // window capabilities cannot be established on a machine with no
    // configured pair, and the guard below would refuse the very migration
    // the scriptlet exists to run. A starting daemon is worth waiting for;
    // a dead or unreachable one is not, so the wait watches the
    // classification and stops the moment it is anything but Starting.
    if enable {
        wait_for_daemon_start();
    }
    if let Err(why) = enable_permitted(enable, crate::caps_established()) {
        eprintln!("{why}");
        eprintln!(
            "        start the daemon and retry: sudo systemctl start irlumed   \
             (or, if it will not start, `irlume doctor` says why)"
        );
        return ExitCode::FAILURE;
    }
    // A run that leaves a login stack without the session line delivering a
    // GNOME keyring token (every disable, and an enable whose configuration
    // no longer wants that stack wired) leaves that keyring locked at every
    // login under a secret nobody has seen. Refused while any account holds
    // one, unless the person says otherwise; `irlume uninstall` refuses the
    // same way first, and reconcile has no override. Asked after the
    // capability check, so an enable decides from established capabilities.
    // A dry run names the refusal the apply would make; unprivileged, it may
    // be unable to read the envelope store, and then only says the apply
    // will check.
    if !(origin == ScopeOrigin::Command && force) {
        match tokens_a_run_strands(enable) {
            Ok(users) if users.is_empty() => {}
            Ok(users) => {
                for line in token::stranded_lines(&users) {
                    eprintln!("{line}");
                }
                return ExitCode::FAILURE;
            }
            Err(store) if apply => {
                eprintln!(
                    "[login] refusing: could not read the sealed-envelope store ({store}), so \
                     irlume cannot tell whether a login keyring depends on the session line \
                     this run removes. Fix the store, or re-run with --force."
                );
                return ExitCode::FAILURE;
            }
            Err(store) => println!(
                "  (could not check for GNOME keyring tokens here: {store}; `--apply` checks \
                 as root)"
            ),
        }
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
                        format!("on-demand; {}", ondemand_hint(greeter))
                    } else {
                        "face-first; the camera verifies as soon as your account is selected"
                            .to_string()
                    }
                );
            }
        }
    }
    let mut errs = 0;
    let mut kept: Vec<&'static str> = Vec::new();
    let mut do_svc = |s: &Svc, wire: &dyn Fn(&str) -> (String, bool), want: bool| {
        // On enable, wire wanted factors and unwire unwanted ones; on disable,
        // unwire everything (want is ANDed with `enable`).
        match wire_service_with(s, enable && want, &opts, wire) {
            Ok(outcome) => {
                print_outcome(&outcome, origin);
                if kept_unmet(origin, &outcome) {
                    kept.push(s.etc);
                }
            }
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
        // still gets a face line there. Credential release alone cannot enforce
        // cold-login policy because PAM can fall back to identity verification.
        // The daemon separately admits only request-bound RGB unlock contexts;
        // ambiguous shared-greeter requests use the password.
        let unified_login_lock =
            s.etc.ends_with("/cosmic-greeter") || s.etc.ends_with("/gdm-password");
        let face = want_face_login || (unified_login_lock && want_face_lock);
        // A login screen remote users reach keeps only irlume's `reseal`
        // lines, the keyring hand-off, which never reaches the camera
        // (`remote_seats`); said wherever the service exists.
        let blocked = remote_seats::face_blocked(service_name(s.etc));
        if let Some(why) = &blocked {
            if enable && service_present(s).is_some() {
                println!("  {}: face and fingerprint left out: {why}", s.etc);
            }
        }
        let (face_line, keyring_line) = if blocked.is_some() {
            (false, false)
        } else {
            (face, want_fp_keyring)
        };
        let greeter_wire = |c: &str| wire_greeter_impl(c, face_line, keyring_line, prof.ondemand);
        let wanted = greeter_wanted(s, face || want_fp_keyring, blocked.is_some());
        let want = greeter_want(s, wanted, blocked.is_some(), &greeter_wire);
        if enable && blocked.is_some() && wanted && !want {
            println!(
                "  {}: irlume's reseal lines cannot be placed here, so every irlume line \
                 comes out; a GNOME keyring token armed for an account is no longer \
                 delivered at this login screen (`irlume keyring forget` re-keys the \
                 keyring back to the password)",
                s.etc
            );
        }
        do_svc(s, &greeter_wire, want);
    }
    for s in FP_GREETERS {
        let fp_wire = |c: &str| wire_fp_keyring(c, service_name(s.etc));
        do_svc(s, &fp_wire, want_fp_keyring);
    }
    // A separate lock service (KDE `kde`) is a WARM screen unlock: the module
    // short-circuits (no `kr`), so the keyring (already open) isn't re-touched.
    let (lock_svc, lock_wire) = lock_surface();
    // #607: with Omarchy's dedicated face lane present, the stock password lane
    // yields: want=false means unwire, which also removes our line if an older
    // enable had put it there.
    let lock_lane_yielded = want_face_lock && stock_lane_yielded();
    do_svc(
        lock_svc,
        &lock_wire,
        want_face_lock && !stock_lane_yielded(),
    );
    if lock_lane_yielded {
        println!(
            "  omarchy: the dedicated face lane ({OMARCHY_FACE_LANE}) owns the lock screen;\n  \
             leaving the stock password lane untouched; removing the dedicated lane restores it"
        );
    }
    // The opt-in scopes the command line asked for that came to nothing. They
    // fail the run, but unlike an error they still let the marker be written:
    // every other surface was handled, and the marker records what is wired.
    let mut unmet: Vec<(&str, &str, PlannedChange)> = Vec::new();
    if sudo_in_scope(enable, with_sudo) {
        match wire_service_with(&SUDO, enable, &opts, &wire_verify_service) {
            Ok(msg) => {
                print_outcome(&msg, origin);
                if kept_unmet(origin, &msg) {
                    kept.push(SUDO.etc);
                }
                if requested_scope_unmet(origin, enable, with_sudo, msg.change) {
                    unmet.push(("--with-sudo", "sudo", msg.change));
                }
            }
            Err(e) => {
                eprintln!("  ✗ {e}");
                errs += 1;
            }
        }
    }
    if polkit_in_scope(enable, with_polkit) {
        match wire_service_with(&POLKIT, enable, &opts, &wire_polkit_service) {
            Ok(msg) => {
                print_outcome(&msg, origin);
                if kept_unmet(origin, &msg) {
                    kept.push(POLKIT.etc);
                }
                if requested_scope_unmet(origin, enable, with_polkit, msg.change) {
                    unmet.push(("--with-polkit", "polkit-1", msg.change));
                } else if enable && apply && !msg.unmet {
                    // A kept stack (an override or in-place refusal) was
                    // left as it is, so its prompts did not change.
                    println!(
                        "    polkit prompts (Bitwarden unlock, pkexec) now take your face.\n    \
                         Type yes for one face attempt, or use your password."
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
            let obs_sudo = sudo_wired();
            let obs_polkit = polkit_wired() == Some(true);
            let obs_lock = lock_wired();
            // #607: alongside the observed facts, record the yield intent when
            // this apply wanted face-on-lock and the dedicated Omarchy lane
            // suppressed it, so a later lane removal can reclaim. Everywhere
            // else the marker stays purely observational.
            write_wired_marker(
                true,
                &WiredMarker {
                    sudo: obs_sudo,
                    polkit: obs_polkit,
                    lock: obs_lock,
                    face_lock_intent: marker_face_lock_intent(want_face_lock),
                },
            );
        } else {
            write_wired_marker(
                false,
                &WiredMarker {
                    sudo: with_sudo,
                    polkit: with_polkit,
                    lock: want_face_lock,
                    face_lock_intent: false,
                },
            );
        }
        // Say it at the moment the user wired it, not only when they next run
        // `login status`: a wallet that still prompts after `enable --apply`
        // otherwise reads as irlume having failed.
        if enable {
            report_keyring_handoff();
        }
        if unmet.is_empty() && kept.is_empty() {
            println!("[login] done. Password remains the fallback everywhere.");
        } else {
            let mut except: Vec<&str> = unmet.iter().map(|(flag, _, _)| *flag).collect();
            except.extend(kept.iter().copied());
            println!(
                "[login] done, except {}. Password remains the fallback everywhere.",
                except.join(" and ")
            );
        }
    }
    for (flag, service, change) in &unmet {
        eprintln!("{}", unmet_scope_line(flag, service, *change));
    }
    for etc in &kept {
        eprintln!("[login] {etc}: not updated (see the ⚠ line above)");
    }
    if errs == 0 && unmet.is_empty() && kept.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn wait_for_daemon_start() {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while crate::commands::classify_reach(irlume_common::client::request_poll(
        &irlume_common::Request::Ping,
    )) == crate::commands::DaemonReach::Starting
    {
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
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
    /// Create an irlume-owned /etc override from the vendor copy, or rebuild
    /// one nobody edited (after a vendor change, or when irlume's lines change).
    MaterializeOverride,
    /// Write irlume lines into the admin's file, taking a backup first.
    Wire,
    /// Remove the irlume-owned override, restoring the vendor copy.
    RemoveOverride,
    /// Update irlume's lines in an override in place, keeping every other line:
    /// one with lines irlume did not write, or one whose vendor copy is gone.
    RewireOverride,
    /// Leave an override as it is: it has lines irlume did not write and its
    /// vendor copy moved on, or a write would change where one of its numeric
    /// jumps lands. Also a stack irlume edits in place whose inactive lines,
    /// which a disable left where a numeric jump counts them, irlume's lines
    /// do not fit. Writes nothing.
    KeepEditedOverride,
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
                | Self::RewireOverride
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
            Self::RewireOverride => "rewire-override",
            Self::KeepEditedOverride => "keep-edited-override",
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
    /// More for a person at the terminal: how a kept override differs from
    /// its vendor copy, and the command that rebuilds it. Never printed by
    /// reconcile, whose output goes to the journal.
    pub(crate) detail: Option<String>,
    /// irlume's lines in the file are not the ones this run wanted: updating
    /// them was refused (it would have moved a jump or one of irlume's lines
    /// past an administrator's line), so the file keeps its earlier ones.
    pub(crate) unmet: bool,
    /// `--adjust-jumps` would handle the file differently because of a
    /// numeric jump: an enable refused (`unmet`) only because the update
    /// would move that jump, or a run taking irlume's lines out that leaves
    /// inactive lines where the flag removes them, lowering a jump that
    /// counts them or moving a landing off one of them.
    pub(crate) adjustable: bool,
}

/// How a `wire_service` call may act.
#[derive(Default)]
struct WireOpts {
    /// Write, rather than only decide.
    apply: bool,
    /// `login enable --force`: rebuild an override with lines irlume did not
    /// write from the vendor copy, keeping the old file as `.pre-irlume`.
    force: bool,
    /// `login enable --adjust-jumps` or `login disable --adjust-jumps`: in an
    /// override, change the value of a numeric jump irlume's lines would
    /// move, so it lands where it did, rather than keep the file.
    adjust_jumps: bool,
    /// The person's run is a `login enable`, which also takes irlume's lines
    /// out of a surface its configuration no longer wants them in: a message
    /// then offers `enable`, the command they ran, not `disable`.
    enabling: bool,
    /// The vendor file's digest the machine plan was computed against. A
    /// different one at the moment of reading refuses the surface, so the
    /// vendor copy a plan showed is the one the write uses.
    expect_vendor: Option<String>,
}

impl std::fmt::Display for WireOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Decide, and with `apply` write, one service. The plan and prepare paths and
/// the tests call this; apply and the human run go through
/// [`wire_service_with`] for the options only they use.
fn wire_service(
    s: &Svc,
    enable: bool,
    apply: bool,
    wire: &dyn Fn(&str) -> (String, bool),
) -> Result<WireOutcome, String> {
    wire_service_with(
        s,
        enable,
        &WireOpts {
            apply,
            ..WireOpts::default()
        },
        wire,
    )
    .map_err(String::from)
}

/// The opt-in flag that names a surface on the command line, for hints.
fn scope_flag(etc: &str) -> &'static str {
    match service_name(etc) {
        "sudo" => " --with-sudo",
        "polkit-1" => " --with-polkit",
        _ => "",
    }
}

/// Whether libpam loads the stack file `name` a `substack` line names as one
/// stack, as far as irlume can tell: `reader` ([`stack_reader`], the reader
/// the recipe uses for the file) finds it where libpam finds it and reads it,
/// and irlume reads every line of it as libpam does ([`unreadable_line`]),
/// none of them continued. libpam adds a module that always fails after a
/// substack whose file it cannot open or load, one with a module path it
/// takes no name from among its lines, so a jump over such a line skips two
/// modules. Anything else irlume cannot read, a name with a `/` in it among
/// them, reads as not loaded, which only keeps `--adjust-jumps` from changing
/// a jump.
fn substack_loads(reader: &StackReader, name: &str) -> bool {
    reader(name)
        .is_some_and(|text| !has_line_continuation(&text) && unreadable_line(&text).is_none())
}

/// The override strategy: an irlume-created `/etc` copy of a vendor file, or
/// none yet. Every decision is [`overrides::decide`]'s; this reads its inputs
/// and carries out what it chose.
fn wire_override(
    s: &Svc,
    vendor_path: &str,
    enable: bool,
    opts: &WireOpts,
    wire: &dyn Fn(&str) -> (String, bool),
) -> Result<WireOutcome, WriteError> {
    let etc = Path::new(s.etc);
    let current = read_optional(etc)?;
    if current.is_none() && !enable {
        return Ok(WireOutcome {
            change: PlannedChange::NotWired,
            message: format!("· {}: not wired", s.etc),
            detail: None,
            unmet: false,
            adjustable: false,
        });
    }
    // Read once, and compared with the plan's digest when there is one, so the
    // bytes decided on are the bytes the plan showed. An unreadable vendor file
    // is an error, never "removed": treating it as gone would wire the override
    // as the service's only configuration.
    let vendor = match std::fs::read(vendor_path) {
        Ok(bytes) => {
            let digest = crate::logintx::sha256_hex(&bytes);
            if opts.expect_vendor.as_ref().is_some_and(|e| *e != digest) {
                return Err(drift_message(s).into());
            }
            Some(String::from_utf8(bytes).map_err(|e| format!("read {vendor_path}: {e}"))?)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if opts
                .expect_vendor
                .as_ref()
                .is_some_and(|e| e != crate::logintx::ABSENT)
            {
                return Err(drift_message(s).into());
            }
            None
        }
        Err(e) => return Err(format!("read {vendor_path}: {e}").into()),
    };
    // `--force` compares it, so there it must be readable. Otherwise it only
    // lets the hint for a kept file say to move a different one away first.
    let backup_path = format!("{}{BACKUP}", s.etc);
    let backup = if opts.force && enable {
        read_optional(Path::new(&backup_path))?
    } else if enable {
        read_optional(Path::new(&backup_path)).ok().flatten()
    } else {
        None
    };
    // The stacks an include or a substack names are read where libpam finds
    // them for this file, as the recipe reads them.
    let reader = stack_reader(s.etc);
    let decision = with_stack_reader(reader.clone(), || {
        overrides::decide(&overrides::Input {
            etc: s.etc,
            vendor_path,
            current: current.as_deref(),
            vendor: vendor.as_deref(),
            backup: backup.as_deref(),
            enable,
            force: opts.force,
            adjust_jumps: opts.adjust_jumps,
            command: if enable || opts.enabling {
                "enable"
            } else {
                "disable"
            },
            scope_flag: scope_flag(s.etc),
            wire,
            opens: &|name| substack_loads(&reader, name),
        })
    })?;
    if opts.apply {
        // The vendor copy as decided on above, and as it is now. A package can
        // replace or remove it at any moment without taking irlume's lock.
        let decided = vendor
            .as_deref()
            .map(|v| crate::logintx::sha256_hex(v.as_bytes()));
        let vendor_now = || vendor_digest_now(vendor_path);
        match &decision.write {
            overrides::Write::Nothing => {}
            overrides::Write::Replace(content) => {
                if decision.keep_copy {
                    keep_copy(etc)?;
                }
                // Checked against the bytes decided on, immediately before the
                // rename: an editor saving in place in between is not
                // overwritten. And made from the vendor copy decided on, so it
                // stays only while that copy is still the same once it is in
                // place: an override made from a vendor copy a package has
                // since replaced would shadow the new one, with modules the
                // package may have removed. The file then goes back as it was.
                let still = || -> Result<(), String> {
                    #[cfg(test)]
                    change_vendor_for_test(Path::new(vendor_path));
                    if vendor_now() == decided {
                        Ok(())
                    } else {
                        Err(format!(
                            "{vendor_path} changed while irlume was writing {}; the file was \
                             left as it was, run again to decide afresh",
                            s.etc
                        ))
                    }
                };
                if let Err(e) = write_atomic_checked_if(etc, content, current.as_deref(), &still) {
                    return header_write_refused(s.etc, decision.header_only, e);
                }
            }
            overrides::Write::Remove => {
                // Deleting the override hands the service back to the vendor
                // copy decided on above. A package can remove or change that
                // copy meanwhile without taking irlume's lock, and a service
                // with neither file falls through to `other`, which refuses
                // every login, passwords included. So the vendor copy is
                // checked again once the override is out of the way, and the
                // override goes back if it is no longer the same.
                let still = || -> Result<(), String> {
                    #[cfg(test)]
                    remove_vendor_for_test(Path::new(vendor_path));
                    let now = vendor_now();
                    if now.is_some() && now == decided {
                        Ok(())
                    } else {
                        Err(format!(
                            "{vendor_path} changed while irlume was removing {}; the override \
                             was kept, run again to decide afresh",
                            s.etc
                        ))
                    }
                };
                remove_checked_if(etc, current.as_deref().map(str::as_bytes), &still)?;
            }
        }
    }
    Ok(WireOutcome {
        change: decision.change,
        message: decision.message,
        detail: decision.detail,
        unmet: decision.unmet,
        adjustable: decision.adjustable,
    })
}

/// The digest of the vendor file at `vendor_path` now, `None` when it is not
/// a regular file that can be read.
fn vendor_digest_now(vendor_path: &str) -> Option<String> {
    match std::fs::symlink_metadata(vendor_path) {
        Ok(meta) if meta.file_type().is_file() => std::fs::read(vendor_path)
            .ok()
            .map(|b| crate::logintx::sha256_hex(&b)),
        _ => None,
    }
}

/// A failed write. One that would only have added the tracking line to a
/// file an administrator made immutable or put on a read-only mount changes
/// nothing PAM reads, so it is reported and skipped, as reconcile's
/// maintenance step does; any other is an error.
fn header_write_refused(
    etc: &str,
    header_only: bool,
    error: WriteError,
) -> Result<WireOutcome, WriteError> {
    if !(header_only && write_refused_by_admin(&error.message)) {
        return Err(error);
    }
    Ok(WireOutcome {
        change: PlannedChange::AlreadyCorrect,
        message: format!(
            "⚠ {etc}: left as it is, since it cannot be written ({error}); its PAM lines are \
             already right"
        ),
        detail: None,
        unmet: false,
        adjustable: false,
    })
}

/// The refusal for a surface whose files moved after the plan was made.
fn drift_message(s: &Svc) -> String {
    match s.vendor {
        Some(_) => format!(
            "{} or its vendor copy changed between the plan and the write; not touched",
            s.etc
        ),
        None => format!(
            "{} changed between the plan and the write; not touched",
            s.etc
        ),
    }
}

/// [`wire_service`] with every option: the override strategy for an
/// irlume-created copy of a vendor file (or none yet), the in-place one for an
/// administrator's `/etc` file.
fn wire_service_with(
    s: &Svc,
    enable: bool,
    opts: &WireOpts,
    wire: &dyn Fn(&str) -> (String, bool),
) -> Result<WireOutcome, WriteError> {
    // The stack a first auth `include` names is read where libpam finds it
    // for this file.
    let reader = stack_reader(s.etc);
    let wire = &|c: &str| with_stack_reader(reader.clone(), || wire(c));
    let apply = opts.apply;
    let out = |change: PlannedChange, message: String| {
        Ok(WireOutcome {
            change,
            message,
            detail: None,
            unmet: false,
            adjustable: false,
        })
    };
    let etc = Path::new(s.etc);
    // vendor-only service with no admin /etc copy → override strategy.
    let use_override = s.vendor.is_some() && (!etc.exists() || file_is_created_override(etc));
    if enable {
        // RECONCILE, don't skip-if-present: re-wire always rebuilds the desired
        // line set from the current stack with irlume's lines stripped, so a
        // method switch (which changes which lines are wanted) actually takes
        // effect instead of being a silent no-op when any pam_irlume line exists.
        if let (true, Some(vendor_path)) = (use_override, s.vendor) {
            wire_override(s, vendor_path, true, opts, wire)
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
                // #932: the recipe cannot land, and a file that still holds
                // lines an earlier release wired around an anchor that no
                // longer qualifies would keep wiring that no longer works
                // (a face match there skips the included stack's first line
                // only, the password still asked). They come out, as a
                // disable takes them out, which restores a matching backup
                // whatever else the file carries, before any refusal holds;
                // a file without irlume's lines has nothing to take out and
                // is judged as ever.
                if holds_irlume_line(&current) {
                    let matching_backup = bak.exists()
                        && read(&bak.to_string_lossy()).is_ok_and(|saved| {
                            if current.contains('\r') {
                                without_irlume_lines(&current) == saved
                            } else {
                                base == saved
                            }
                        });
                    if matching_backup || recipe_has_no_anchor(&base, wire) {
                        return with_stack_reader(reader.clone(), || {
                            unwire_no_anchor(s.etc, etc, &current, &base, apply)
                        });
                    }
                    if continued_with_irlume_lines(&current) {
                        return Ok(kept_continued(s.etc, true));
                    }
                    if let Some(line) = unreadable_line(&current) {
                        return Ok(kept_unreadable(s.etc, true, &line));
                    }
                }
                if let Some(line) = unreadable_line(&current) {
                    return Ok(kept_unreadable(s.etc, true, &line));
                }
                return out(
                    PlannedChange::NoAnchor,
                    format!("· {}: no anchor to wire (skipped)", s.etc),
                );
            }
            // The recipes refuse a continued line in the lines irlume did not
            // write, but a `\` added to one of irlume's own lines is gone once
            // they are taken out, so the whole file is checked, as for an
            // override. A line irlume does not read as PAM does leaves it
            // unable to tell where a jump lands or which chain a line is in.
            if continued_with_irlume_lines(&current) {
                return Ok(kept_continued(s.etc, true));
            }
            if let Some(line) = unreadable_line(&current) {
                return Ok(kept_unreadable(s.etc, true, &line));
            }
            let already = || {
                out(
                    PlannedChange::AlreadyCorrect,
                    format!("· {}: already correctly wired", s.etc),
                )
            };
            // A numeric jump that counts irlume's lines, or the inactive lines
            // a disable left in their places, keeps its landing only while
            // they stay in those places.
            let (wired, note) =
                match with_stack_reader(reader.clone(), || keep_places(s.etc, &current, &wired)) {
                    None => (wired, String::new()),
                    Some(KeptPlaces::Unchanged) => return already(),
                    Some(KeptPlaces::Filled(text)) => {
                        let unused = if text.contains(INERT_TAG) {
                            "; an inactive line still holds the place of each of irlume's lines \
                         this configuration does not use"
                        } else {
                            ""
                        };
                        (
                            text,
                            format!(
                                "; irlume's lines take the places inactive lines held, so every \
                             jump lands where it did{unused}"
                            ),
                        )
                    }
                    Some(KeptPlaces::Refused(message)) => {
                        return Ok(WireOutcome {
                            change: PlannedChange::KeepEditedOverride,
                            message,
                            detail: None,
                            unmet: true,
                            adjustable: false,
                        });
                    }
                };
            if wired == current {
                return already();
            }
            if apply {
                backup(etc)?;
                write_atomic(etc, &wired)?;
            }
            out(
                PlannedChange::Wire,
                format!("✓ {}: wired (backup {}{}){note}", s.etc, s.etc, BACKUP),
            )
        }
    } else {
        // disable / unwire
        if let (true, Some(vendor_path)) = (use_override, s.vendor) {
            wire_override(s, vendor_path, false, opts, wire)
        } else if etc.exists() {
            let bak = PathBuf::from(format!("{}{BACKUP}", s.etc));
            if bak.exists() {
                // Restore the backup ONLY when it equals the current file minus
                // our lines, i.e. nothing else changed since we wired. If an
                // admin (or another package) edited the file after wiring,
                // restoring the stale snapshot would silently revert their
                // change (e.g. a faillock line added to sudo): strip in place
                // instead and keep the backup for inspection.
                let current = read(s.etc)?;
                let (stripped, _) = unwire_lines(&current);
                let bak_content = read(&bak.to_string_lossy())?;
                // `unwire_lines` ends every line in LF. A carriage return is
                // part of a line to PAM, so with one in the file only the
                // same bytes count: putting back an LF backup of a file since
                // saved with CRLF endings would change which lines PAM runs.
                let same = if current.contains('\r') {
                    without_irlume_lines(&current) == bak_content
                } else {
                    stripped == bak_content
                };
                if same {
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
                } else if continued_with_irlume_lines(&current) {
                    // Stripping takes out single physical lines, which a line
                    // that ends in `\` makes unsafe. Restoring the backup above
                    // puts back the whole file irlume first read, as deleting
                    // an override nobody edited does.
                    Ok(kept_continued(s.etc, false))
                } else if let Some(line) = unreadable_line(&current) {
                    // Likewise a line PAM reads differently from irlume.
                    if holds_irlume_line(&current) {
                        let note = format!(
                            " (file changed since wiring; backup kept at {}{})",
                            s.etc, BACKUP
                        );
                        disable_unread(s.etc, &current, &line, apply, &note)
                    } else {
                        out(PlannedChange::NotWired, format!("· {}: not wired", s.etc))
                    }
                } else {
                    let (body, change, message) = with_stack_reader(reader.clone(), || {
                        strip_in_place(s.etc, &current, false)
                    });
                    if let (true, Some(body)) = (apply, &body) {
                        write_atomic(etc, body)?;
                    }
                    out(
                        change,
                        format!(
                            "{message} (file changed since wiring; backup kept at {}{})",
                            s.etc, BACKUP
                        ),
                    )
                }
            } else if let Some(current) = read_optional(etc)?.filter(|text| holds_irlume_line(text))
            {
                // The module, or only inactive lines a disable left holding
                // irlume's places: either way there are lines of irlume's to
                // take out once no jump counts them, unless a line ends in `\`.
                if continued_with_irlume_lines(&current) {
                    return Ok(kept_continued(s.etc, false));
                }
                if let Some(line) = unreadable_line(&current) {
                    return disable_unread(s.etc, &current, &line, apply, "");
                }
                let (body, change, message) =
                    with_stack_reader(reader.clone(), || strip_in_place(s.etc, &current, false));
                if let (true, Some(body)) = (apply, &body) {
                    write_atomic(etc, body)?;
                }
                out(change, message)
            } else {
                out(PlannedChange::NotWired, format!("· {}: not wired", s.etc))
            }
        } else {
            out(PlannedChange::NotWired, format!("· {}: not wired", s.etc))
        }
    }
}

/// A stack irlume edits in place, kept as it is because it holds irlume's
/// lines and a line that ends in `\` ([`continued_with_irlume_lines`]): the
/// outcome and line an override in the same state gets, so `login enable`
/// and `login disable` exit 1 and a machine apply fails the surface.
fn kept_continued(etc: &str, enable: bool) -> WireOutcome {
    WireOutcome {
        change: PlannedChange::KeepEditedOverride,
        message: overrides::continued_message(etc, enable, None),
        detail: None,
        unmet: true,
        adjustable: false,
    }
}

/// A stack irlume edits in place, kept as it is because PAM reads one of its
/// lines differently from irlume ([`unreadable_line`]): the outcome and line
/// an override in the same state gets, so `login enable` and `login disable`
/// exit 1 and a machine apply fails the surface.
fn kept_unreadable(etc: &str, enable: bool, line: &UnreadLine<'_>) -> WireOutcome {
    WireOutcome {
        change: PlannedChange::KeepEditedOverride,
        message: overrides::unreadable_message(etc, enable, None, line),
        detail: None,
        unmet: true,
        adjustable: false,
    }
}

/// A disable of a stack irlume edits in place that holds irlume's lines and
/// a line irlume does not read as PAM does ([`unreadable_line`]). When no
/// numeric jump could count irlume's lines
/// ([`jump_could_count_irlume_lines`], the stacks an include names read
/// where libpam finds them for this file), they come out and every other byte
/// stays as it is ([`without_irlume_lines`]), so PAM reads each other line
/// as before. Otherwise the file is kept as it is ([`kept_unreadable`]).
/// `note` ends the line that reports a write.
fn disable_unread(
    etc: &str,
    current: &str,
    line: &UnreadLine<'_>,
    apply: bool,
    note: &str,
) -> Result<WireOutcome, WriteError> {
    if with_stack_reader(stack_reader(etc), || jump_could_count_irlume_lines(current)) {
        return Ok(kept_unreadable(etc, false, line));
    }
    if apply {
        write_atomic(Path::new(etc), &without_irlume_lines(current))?;
    }
    Ok(WireOutcome {
        change: PlannedChange::StripInPlace,
        message: format!(
            "✓ {etc}: removed irlume's lines and kept every other byte as it is, since {}{note}",
            overrides::unread_sentence(line, None)
        ),
        detail: None,
        unmet: false,
        adjustable: false,
    })
}

/// An enable or reconcile that finds no anchor in a file that holds lines an
/// earlier release wired ([`wire_service_with`]): they come out, as a
/// disable takes them out, in the disable's order. A backup that is the
/// current file without irlume's lines is restored and consumed first,
/// whatever else the file carries, as a disable restores it. An unreadable
/// or continued line permits byte-exact removal only when no jump counts the
/// removed lines and no continuation touches them; otherwise the file stays.
/// Readable files use the disable's in-place jump checks
/// ([`strip_in_place`]). Both facts are reported: no anchor, and what came
/// out. When the lines cannot come out because a jump another line carries
/// counts them, and inactive lines already hold their places, nothing is
/// written and the outcome is the no-anchor skip naming why they stay.
fn unwire_no_anchor(
    etc: &str,
    path: &Path,
    current: &str,
    stripped: &str,
    apply: bool,
) -> Result<WireOutcome, WriteError> {
    let bak = PathBuf::from(format!("{etc}{BACKUP}"));
    if bak.exists() {
        let bak_content = read(&bak.to_string_lossy())?;
        // The same comparison a disable makes, for the same reason: a
        // carriage return is part of a line to PAM, so with one in the file
        // only the same bytes count.
        let same = if current.contains('\r') {
            without_irlume_lines(current) == bak_content
        } else {
            stripped == bak_content
        };
        if same {
            // The same refusal every other write path in this module
            // applies, the restore among them: a rename over a SYMLINK or
            // a multiply-linked file changes what PAM loads in ways this
            // restore cannot put back.
            if apply {
                inspect_target(path)?;
                std::fs::rename(&bak, path).map_err(|e| format!("restore {etc}: {e}"))?;
            }
            return Ok(WireOutcome {
                change: PlannedChange::RestoreBackup,
                message: format!(
                    "✓ {etc}: no anchor to wire, so the lines an earlier release wired came \
                     out (restored from backup)"
                ),
                detail: None,
                unmet: false,
                adjustable: false,
            });
        }
    }
    // A line that ends in `\` joins lines PAM runs as one, and one irlume
    // does not read as PAM does hides where a jump lands: taking single
    // lines out of such a file can change another rule, so the file is kept
    // as it is, as the disable keeps it.
    if continued_with_irlume_lines(current) && !removal_preserves_continuations(current) {
        return Ok(kept_continued(etc, true));
    }
    if let Some(line) = unreadable_line(current) {
        return disable_unread(etc, current, &line, apply, "; no anchor to wire");
    }
    if has_line_continuation(current) {
        if with_stack_reader(stack_reader(etc), || jump_could_count_irlume_lines(current)) {
            return Ok(kept_continued(etc, true));
        }
        if apply {
            write_atomic(path, &without_irlume_lines(current))?;
        }
        return Ok(WireOutcome {
            change: PlannedChange::StripInPlace,
            message: format!(
                "✓ {etc}: no anchor to wire, so irlume's lines came out; every other byte was kept"
            ),
            detail: None,
            unmet: false,
            adjustable: false,
        });
    }
    let (body, change, message) = strip_in_place(etc, current, true);
    let change = match body {
        Some(body) => {
            if apply {
                write_atomic(path, &body)?;
            }
            change
        }
        None => PlannedChange::NoAnchor,
    };
    Ok(WireOutcome {
        change,
        message,
        detail: None,
        unmet: false,
        adjustable: false,
    })
}

/// Reads the stacks an include in the file at `path` names where libpam
/// finds them for that file: under the root the file sits in, in `etc/pam.d`
/// and then `usr/lib/pam.d`, the directories irlume reads a service from;
/// for a file anywhere else, in the directory it is in. A name with a `/`
/// in it, and a stack that is there but cannot be read, read as none.
fn stack_reader(path: &str) -> StackReader {
    let dir = Path::new(path).parent().unwrap_or_else(|| Path::new("/"));
    let root = if dir.ends_with("etc/pam.d") {
        dir.ancestors().nth(2)
    } else if dir.ends_with("usr/lib/pam.d") {
        dir.ancestors().nth(3)
    } else {
        None
    };
    let dirs = match root {
        Some(root) => vec![root.join("etc/pam.d"), root.join("usr/lib/pam.d")],
        None => vec![dir.to_path_buf()],
    };
    std::rc::Rc::new(move |name: &str| {
        if name.is_empty() || name.contains('/') {
            return None;
        }
        for dir in &dirs {
            match std::fs::read_to_string(dir.join(name)) {
                Ok(text) => return Some(text),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return None,
            }
        }
        None
    })
}

// ---- pure PAM-text mechanics (unit-tested) -----------------------------------

/// Whether a stack irlume edits in place is left as it is: it holds lines of
/// irlume's and a line that ends in `\`. PAM joins such a line with the next
/// one into one rule, so taking out or rewriting one physical line can change
/// another rule: remove irlume's line after a continued one and that rule
/// takes in the next line instead, the password line included. A stack
/// without irlume's lines has nothing to take out and is judged as ever.
fn continued_with_irlume_lines(current: &str) -> bool {
    has_line_continuation(current) && holds_irlume_line(current)
}

/// irlume's lines taken out of a stack irlume edits in place, for a disable
/// (`no_anchor` false) and for an enable that found no anchor in a file
/// holding them ([`unwire_no_anchor`], `no_anchor` true): removed, unless
/// that moves a numeric jump another line carries (an administrator who
/// wrote one counted irlume's lines as they stand). Then, as for an
/// override, each of irlume's rules becomes an inactive pam_permit.so line
/// in its place, so every jump lands where it does now. The text to write
/// (`None` when the file stays as it is), the change, and the line that
/// reports it; `no_anchor` words the report as the reason the lines come
/// out. A later disable takes the inactive lines out once no jump counts
/// them.
fn strip_in_place(
    etc: &str,
    current: &str,
    no_anchor: bool,
) -> (Option<String>, PlannedChange, String) {
    let (stripped, _) = unwire_lines(current);
    let shifts = overrides::jump_shifts(current, &stripped);
    if shifts.is_empty() {
        return (
            Some(stripped),
            PlannedChange::StripInPlace,
            if no_anchor {
                format!(
                    "✓ {etc}: no anchor to wire, so the lines an earlier release wired came out"
                )
            } else {
                format!("✓ {etc}: stripped irlume lines")
            },
        );
    }
    let why = overrides::shift_reason(&shifts, &[overrides::Names::whole(current)]).replacen(
        "would then land on",
        "would land on",
        1,
    );
    let inert = overrides::neutralize(current);
    if inert == overrides::normalize(current) {
        return (
            None,
            PlannedChange::NotWired,
            if no_anchor {
                format!(
                    "· {etc}: no anchor to wire; inactive lines hold the places of irlume's \
                     earlier lines, because without them {why}"
                )
            } else {
                format!(
                    "· {etc}: not wired; inactive lines hold the places of irlume's lines, \
                     because without them {why}"
                )
            },
        );
    }
    (
        Some(inert),
        PlannedChange::StripInPlace,
        if no_anchor {
            format!(
                "✓ {etc}: no anchor to wire, so the lines an earlier release wired turned into \
                 inactive pam_permit.so lines; removing them would change a jump: without them \
                 {why}"
            )
        } else {
            format!(
                "✓ {etc}: turned irlume's lines into inactive pam_permit.so lines; removing them \
                 would change a jump: without them {why}"
            )
        },
    )
}

/// What an enable does with a stack irlume edits in place when the stack the
/// recipe makes would move a numeric jump another line carries (see
/// [`keep_places`]).
#[derive(Debug, PartialEq, Eq)]
enum KeptPlaces {
    /// irlume's lines are already the recipe's, in the places the jump
    /// counts: nothing to write.
    Unchanged,
    /// The stack to write: irlume's lines in the places the inactive lines
    /// held.
    Filled(String),
    /// Nothing is written: irlume's lines do not fit those places. The line
    /// that says why.
    Refused(String),
}

/// irlume's lines for an enable of a stack irlume edits in place. `wired` is
/// what the recipe makes of the stack without irlume's lines. `None` when the
/// caller writes `wired`: its new lines do not move a readable included
/// stack's jump, or the stack holds no inactive line (see [`strip_in_place`])
/// and its irlume lines are not already the recipe's.
///
/// Otherwise a jump another line carries counts irlume's lines or the
/// inactive lines a disable left in their places, and writing `wired` would
/// move it. Each of irlume's lines, an inactive line included, then takes the
/// line `wired` has for the same job in its own place, so every jump lands
/// where it does now ([`overrides::refill`]). When irlume's lines do not fit
/// the places the inactive lines hold, nothing is written: a jump is never
/// moved to make room.
fn keep_places(etc: &str, current: &str, wired: &str) -> Option<KeptPlaces> {
    if !holds_irlume_line(current) {
        let shifts = overrides::included_jumps_moved_by_irlume(current, wired);
        return (!shifts.is_empty()).then(|| {
            KeptPlaces::Refused(format!(
                "⚠ {etc}: not wired, left as it is: wiring would move a jump: {}; a jump in an \
                 included stack cannot be adjusted from this file",
                overrides::shift_reason(&shifts, &[overrides::Names::whole(current)])
            ))
        });
    }
    let shifts = overrides::jump_shifts(current, wired);
    if shifts.is_empty() {
        return None;
    }
    let holds_places = current
        .lines()
        .any(|l| is_irlume_line(l) && l.contains(INERT_TAG));
    match overrides::refill(current, wired) {
        // Byte for byte, so a file whose comments end in a carriage return
        // is still rewritten. One with a carriage return PAM reads never
        // gets here: `unreadable_line` refuses it first.
        Some(filled) if filled == current => Some(KeptPlaces::Unchanged),
        Some(filled) if holds_places => Some(KeptPlaces::Filled(filled)),
        None if holds_places => {
            let state = if content_has_module(current) {
                "left as it is"
            } else {
                "not wired, left as it is"
            };
            Some(KeptPlaces::Refused(format!(
                "⚠ {etc}: {state}: irlume's lines do not fit the places its inactive lines \
                 hold, and wiring them without those places would move a jump: {}; adjust that \
                 line",
                overrides::shift_reason(&shifts, &[overrides::Names::whole(current)])
            )))
        }
        _ => None,
    }
}

/// `Some(true/false)` when semodule could be queried (root), `None` otherwise.
fn selinux_loaded() -> Option<bool> {
    let out = Command::new(SystemCommand::Semodule.path()?)
        .arg("-l")
        .output()
        .ok()?;
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
pub(crate) fn relabel_daemon_socket() -> Result<(), String> {
    // Statuses are CHECKED, not discarded: this function exists because two
    // surfaces reported a relabel they had not performed, and swallowing a
    // missing restorecon or a failed restart would be the same false success
    // one level down.
    let run = |what: &str, cmd: &mut Command| match cmd.status() {
        Ok(st) if st.success() => Ok(()),
        Ok(st) => Err(format!("{what} exited {st}")),
        Err(e) => Err(format!("could not run {what}: {e}")),
    };
    let systemctl = SystemCommand::Systemctl
        .path()
        .ok_or_else(|| "could not run systemctl: trusted executable not found".to_string())?;
    let restorecon = SystemCommand::Restorecon
        .path()
        .ok_or_else(|| "could not run restorecon: trusted executable not found".to_string())?;
    run(
        "systemctl try-restart irlumed.service",
        Command::new(systemctl).args(["try-restart", "irlumed.service"]),
    )?;
    run(
        "restorecon /run/irlume.sock",
        Command::new(restorecon).arg("/run/irlume.sock"),
    )
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
            let ok = SystemCommand::Semodule.path().is_some_and(|semodule| {
                Command::new(semodule)
                    .args(["-i", pp.as_str()])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            });
            if !ok {
                return Err("semodule -i irlume.pp failed".into());
            }
            relabel_daemon_socket().map_err(|e| {
                format!("SELinux module loaded, but the socket relabel FAILED: {e}")
            })?;
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
            let Some(semodule) = SystemCommand::Semodule.path() else {
                return Err(
                    "could not run semodule (trusted executable not found); the module is still loaded"
                        .into(),
                );
            };
            match Command::new(semodule).args(["-r", "irlume"]).status() {
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

    #[test]
    fn stripping_a_wired_stack_keeps_what_the_distro_added_later() {
        // A password substack below the gate, where the keyring line goes
        // after the password step.
        let stock = "auth       required     pam_env.so\n                     auth       substack     password-auth\n";
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
        assert!(base.contains("substack     password-auth"), "{base}");
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
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // In a directory the lock creates at 0700: one the umask left group
        // writable would be refused.
        let lock_path = dir.join("run").join("pam.lock");
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
    const GDM: &str = "#%PAM-1.0\nauth     [success=done ignore=ignore default=bad] pam_selinux_permit.so\nauth     substack      password-auth\nauth     optional      pam_gnome_keyring.so\naccount  include       password-auth\nsession  include       password-auth\nsession  optional      pam_gnome_keyring.so auto_start\n";

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
        // The lock refuses a directory group or others can write, as the umask
        // may leave `dir`, so it gets one of its own at 0700.
        let lock_dir = dir.join("run");
        std::fs::create_dir(&lock_dir).expect("create the lock directory");
        std::fs::set_permissions(
            &lock_dir,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .expect("make the lock directory private");
        let lock_path = lock_dir.join("pam.lock");
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
        restore_surface(&gone, Some("restored\n"), Some((0o600, uid, gid)), None).expect("restore");
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
        let refused =
            String::from(write_atomic(&link, "wired\n").expect_err("a symlink must be refused"));
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
        let refused =
            String::from(write_atomic(&a, "wired\n").expect_err("a hard link must be refused"));
        assert!(refused.contains("hard link"), "{refused}");
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "the original stack\n");
        assert_eq!(
            std::fs::read_to_string(&b).unwrap(),
            "the original stack\n",
            "the peer name was detached from the content"
        );
        // Restore refuses on the same terms; it used to have no check at all.
        assert!(restore_surface(&a, Some("restored\n"), None, None).is_err());

        // REMOVING a surface is a write path too. Rollback removes a file that
        // was absent before the transaction, and that branch called remove_file
        // directly: a path now holding a symlink was unlinked despite the claim
        // that every path refuses one, and a multiply-linked file lost a name
        // irlume cannot put back.
        let gone_link = dir.join("was-absent");
        std::os::unix::fs::symlink(&real, &gone_link).unwrap();
        let refused = restore_surface(&gone_link, None, None, None)
            .expect_err("removing a symlink must be refused too");
        assert!(refused.contains("symlink"), "{refused}");
        assert!(gone_link.is_symlink(), "the symlink was unlinked");
        let peer = dir.join("linked-peer");
        std::fs::hard_link(&a, &peer).unwrap();
        assert!(
            restore_surface(&a, None, None, None).is_err(),
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

        arm(&SWAP_DURING_WRITE, &target);
        let refused = write_atomic(&target, "wired\n")
            .map_err(String::from)
            .expect_err("a target replaced mid-write must not be overwritten");
        disarm(&SWAP_DURING_WRITE, &target);

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
        // ondemand=true → explicit on-demand choice (yes on COSMIC), placed
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
        // COSMIC answers a nonempty yes selection → ondemand.
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
        let fedora = "#%PAM-1.0\nauth       substack     password-auth\nauth        optional     pam_permit.so\n";
        let (l, _) = wire_lock(fedora);
        assert!(l.contains("[success=1 default=ignore]   pam_irlume.so unseal ondemand"));
    }

    /// #583-era research, live-validated on a fresh Omarchy thinkpad: the
    /// stock lock's password lane carries the polkit-style consent line
    /// (type `yes` in the lock's field fires the camera), the KDE on-demand
    /// shape does not apply there, and the line lands ABOVE the whole auth
    /// stack because the first auth directive is the faillock preauth.
    #[test]
    fn omarchy_lock_surface_uses_the_stock_lane_with_the_polkit_recipe() {
        let (svc, wire) = lock_surface_for(true, false);
        assert_eq!(svc.etc, "/etc/pam.d/omarchy-lock-password");
        assert!(svc.vendor.is_none(), "omarchy ships a real /etc file");

        // Byte-for-byte the stock file from a fresh Omarchy 4.0.1 install.
        let stock = "#%PAM-1.0\nauth       required                    pam_faillock.so preauth silent deny=10 unlock_time=120\n-auth      [success=2 default=ignore]  pam_systemd_home.so\nauth       [success=1 default=bad]     pam_unix.so try_first_pass nullok\nauth       [default=die]               pam_faillock.so authfail deny=10 unlock_time=120\nauth       optional                    pam_permit.so\nauth       required                    pam_env.so\nauth       required                    pam_faillock.so authsucc\naccount    include                     system-local-login\n";
        let (wired, changed) = wire(stock);
        assert!(changed);
        let face_at = wired
            .find("auth       [success=done new_authtok_reqd=done abort=die default=ignore]   pam_irlume.so")
            .expect("the exact line the live experiment validated");
        let first_auth = wired
            .find("pam_faillock.so")
            .expect("the stack's first auth line");
        assert!(
            face_at < first_auth,
            "the face line must precede the whole auth stack: {wired}"
        );
        // Idempotent: the module present means a second pass changes nothing.
        let (_, again) = wire(&wired);
        assert!(!again);

        // Non-omarchy keeps the KDE lane and its own recipe, untouched.
        let (kde_svc, kde_wire) = lock_surface_for(false, false);
        assert_eq!(kde_svc.etc, "/etc/pam.d/kde");
        let kde_stock = "#%PAM-1.0\nauth       include     system-local-login\naccount    include     system-local-login\n";
        let (w, changed) = kde_wire(kde_stock);
        assert!(changed);
        assert!(w.contains("ondemand"), "KDE keeps the on-demand shape");
    }

    /// Live-validated on Mint 22.3 (#585-era): the Cinnamon screensaver's
    /// Debian include-layout takes the SAME on-demand recipe as KDE, and its
    /// dialog submits empty fields, so empty-Enter arms the camera there.
    /// Omarchy, when present, still wins the lock.
    #[test]
    fn cinnamon_lock_surface_takes_the_kde_recipe_when_present() {
        let (svc, wire) = lock_surface_for(false, true);
        assert_eq!(svc.etc, "/etc/pam.d/cinnamon-screensaver");

        // Byte-for-byte the stock file from a Mint 22.3 install.
        let stock = "@include common-auth\nauth optional pam_gnome_keyring.so\n";
        let (wired, changed) = wire(stock);
        assert!(changed);
        assert!(
            wired.contains("sufficient   pam_irlume.so unseal ondemand"),
            "the on-demand line the live experiment validated: {wired}"
        );
        let face_at = wired.find("pam_irlume.so").expect("face line");
        let inc_at = wired.find("@include common-auth").expect("the include");
        assert!(face_at < inc_at, "face line leads the include");
        // Idempotent.
        let (_, again) = wire(&wired);
        assert!(!again);

        // Omarchy outranks Cinnamon when both signals somehow exist.
        let (omarchy_svc, _) = lock_surface_for(true, true);
        assert_eq!(omarchy_svc.etc, "/etc/pam.d/omarchy-lock-password");
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

    /// A kept surface is this run's to record only while the file reads as it
    /// did before: replaced or removed meanwhile, it is recorded as it stands.
    #[test]
    fn a_kept_surface_must_read_as_before() {
        let text = "auth include system-auth\n";
        let digest = crate::logintx::sha256_hex(text.as_bytes());
        assert!(!changed_since_read(Some(text), &digest));
        assert!(changed_since_read(Some(text), crate::logintx::ABSENT));
        assert!(changed_since_read(
            Some(text),
            &crate::logintx::sha256_hex(b"auth include other\n")
        ));
        assert!(!changed_since_read(None, crate::logintx::ABSENT));
        assert!(changed_since_read(None, &digest));
    }

    /// A kept surface stays kept only once its after-state was read; a read
    /// failure after the decision leads with the I/O error and is not kept,
    /// so the marker does not follow it as a plain refusal.
    #[test]
    fn a_kept_surface_needs_its_after_state() {
        let refusal = Some("kept: would move a jump".to_string());
        let io = Some("read /etc/pam.d/x after changing it: Is a directory".to_string());
        assert_eq!(
            settle_surface(refusal.clone(), None, true),
            (refusal.clone(), true)
        );
        let (error, kept) = settle_surface(refusal.clone(), io.clone(), true);
        assert!(!kept);
        let error = error.unwrap();
        assert!(
            error.starts_with("read /etc/pam.d/x after changing it"),
            "{error}"
        );
        assert!(error.contains("would move a jump"), "{error}");
        // Not kept: the write's error leads as before, else the read's.
        assert_eq!(
            settle_surface(Some("write failed".into()), io.clone(), false),
            (Some("write failed".to_string()), false)
        );
        assert_eq!(settle_surface(None, io.clone(), false), (io, false));
        assert_eq!(settle_surface(None, None, false), (None, false));
    }

    /// An administrator's gate above the password step stays above irlume's
    /// line, so a face cannot answer a prompt the gate refuses: the stanza
    /// goes just above the password step, not above the first auth line. A
    /// numeric jump that would then count irlume's line keeps the stanza
    /// above that jump, where nothing counts it.
    #[test]
    fn verify_stanza_stays_below_an_administrators_gate() {
        let gated = "#%PAM-1.0\n\
                     auth       requisite    pam_succeed_if.so user ingroup wheel\n\
                     auth       include      system-auth\n\
                     account    include      system-auth\n";
        for (wired, changed) in [wire_verify_service(gated), wire_polkit_service(gated)] {
            assert!(changed);
            let at = |needle: &str| wired.lines().position(|l| l.contains(needle)).unwrap();
            assert!(at("pam_succeed_if.so") < at(MODULE), "{wired}");
            assert!(at(MODULE) < at("auth       include"), "{wired}");
        }
        let unix = "auth required pam_env.so\n\
                    auth requisite pam_nologin.so\n\
                    auth required pam_unix.so\n";
        let (wired, _) = wire_verify_service(unix);
        let at = |needle: &str| wired.lines().position(|l| l.contains(needle)).unwrap();
        assert!(
            at("pam_nologin.so") < at(MODULE) && at(MODULE) < at("pam_unix.so"),
            "{wired}"
        );
        // `success=1` skips the password include for some users; a line between
        // them would be what it skips instead, so the stanza goes above it.
        let jumped = "auth [success=1 default=ignore] pam_succeed_if.so user ingroup nopasswd\n\
                      auth include system-auth\n\
                      auth required pam_deny.so\n";
        let (wired, _) = wire_verify_service(jumped);
        assert_eq!(
            wired.lines().position(|l| l.contains(MODULE)),
            Some(0),
            "{wired}"
        );
    }

    /// Disabling a stack irlume edits in place removes its lines, unless a
    /// numeric jump another line carries counts them: then they become
    /// inactive lines in their places, as in an override, so the jump lands
    /// where it did.
    #[test]
    fn an_in_place_strip_keeps_jumps_that_count_irlumes_lines() {
        let plain = format!("{VERIFY_STANZA}\nauth include system-auth\n");
        let (body, _, message) = strip_in_place("/etc/pam.d/sudo", &plain, false);
        assert_eq!(body.as_deref(), Some("auth include system-auth\n"));
        assert!(message.contains("stripped irlume lines"), "{message}");

        let counted = format!(
            "auth [success=2 default=ignore] pam_succeed_if.so user ingroup fast\n\
             {VERIFY_STANZA}\n\
             auth required pam_unix.so\n\
             auth required pam_deny.so\n\
             auth required pam_permit.so\n"
        );
        let (body, change, message) = strip_in_place("/etc/pam.d/sudo", &counted, false);
        let body = body.expect("inactive lines written");
        assert_eq!(change, PlannedChange::StripInPlace);
        assert!(!body.contains(MODULE), "{body}");
        assert_eq!(body.lines().count(), counted.lines().count(), "{body}");
        assert!(body.lines().nth(1).unwrap().contains(INERT_TAG), "{body}");
        assert!(
            message.contains("inactive pam_permit.so lines"),
            "{message}"
        );
        // The jump and the line it would land on, by their numbers, not
        // their text.
        assert!(
            message.contains("without them the jump on line 1 would land on line 5"),
            "{message}"
        );
        assert!(!message.contains("ingroup fast"), "{message}");
        // The next disable while the jump still counts them writes nothing;
        // once the jump is gone it takes the inactive lines out.
        let (again, change, message) = strip_in_place("/etc/pam.d/sudo", &body, false);
        assert_eq!(
            (again, change),
            (None, PlannedChange::NotWired),
            "{message}"
        );
        let unjumped = body.replacen("[success=2 default=ignore]", "requisite", 1);
        let (clean, change, _) = strip_in_place("/etc/pam.d/sudo", &unjumped, false);
        assert_eq!(change, PlannedChange::StripInPlace);
        assert!(!clean.unwrap().contains(INERT_TAG));
    }

    /// A stack irlume edits in place whose numeric jump counts irlume's
    /// line, for each verify recipe: the jump skips the line and
    /// `pam_unix.so` and lands on `pam_deny.so`.
    fn counted_verify_stack(stanza: &str) -> String {
        format!(
            "auth [success=2 default=ignore] pam_succeed_if.so user ingroup fast\n\
             {stanza}\n\
             auth required pam_unix.so\n\
             auth required pam_deny.so\n\
             auth required pam_permit.so\n"
        )
    }

    /// `login disable` then `login enable` on a stack irlume edits in place,
    /// where a numeric jump counts irlume's line: the disable leaves an
    /// inactive line in its place, and the enable puts irlume's line back in
    /// that place, so the jump lands on the same module throughout. Taking
    /// the inactive line out and wiring the stack without it made the jump
    /// land one module further (#859).
    #[test]
    fn an_in_place_disable_and_enable_keep_every_landing() {
        type Wire = fn(&str) -> (String, bool);
        for (tag, stanza, wire) in [
            ("refill-sudo", VERIFY_STANZA, wire_verify_service as Wire),
            (
                "refill-polkit",
                POLKIT_VERIFY_STANZA,
                wire_polkit_service as Wire,
            ),
        ] {
            let dir = TestDir::new(tag);
            let etc = dir.0.join("stack");
            let wired = counted_verify_stack(stanza);
            std::fs::write(&etc, &wired).unwrap();
            let svc = Svc {
                etc: leak(&etc),
                vendor: None,
            };
            let off = wire_service(&svc, false, true, &wire).unwrap();
            assert_eq!(off.change, PlannedChange::StripInPlace, "{off}");
            let held = std::fs::read_to_string(&etc).unwrap();
            assert!(held.lines().nth(1).unwrap().contains(INERT_TAG), "{held}");
            assert!(overrides::jump_shifts(&wired, &held).is_empty(), "{held}");

            let on = wire_service(&svc, true, true, &wire).unwrap();
            assert_eq!(on.change, PlannedChange::Wire, "{on}");
            assert!(!on.unmet, "{on}");
            let rewired = std::fs::read_to_string(&etc).unwrap();
            assert!(
                overrides::jump_shifts(&held, &rewired).is_empty(),
                "the jump must land where it did while the inactive line held the \
                 place:\n{held}\n{rewired}"
            );
            assert_eq!(rewired, wired, "the round trip gives back the wired stack");
            assert!(on.message.contains("inactive lines held"), "{on}");
            let again = wire_service(&svc, true, true, &wire).unwrap();
            assert_eq!(again.change, PlannedChange::AlreadyCorrect, "{again}");
        }
    }

    /// The enable decision for a stack irlume edits in place, by the lines it
    /// holds: inactive lines a jump counts are refilled, or the stack is left
    /// as it is when irlume's lines do not fit them; every other stack is
    /// wired as the recipe has it, except one whose irlume lines are already
    /// the recipe's in the places a jump counts, which is already correct.
    /// A gate an administrator adds between a held place and the password
    /// step after a disable is a line the recipe puts above irlume's line;
    /// refilling the place would put irlume's `sufficient` line above the
    /// gate, and a face match would end the stack before the gate ran. The
    /// refill is refused; a line the recipe puts below irlume's line (the
    /// jump the place is kept for) may stay above it.
    #[test]
    fn an_in_place_refill_keeps_the_recipes_gates_above_irlumes_line() {
        let jump = "auth [success=1 default=ignore] pam_succeed_if.so user ingroup fast";
        let gate = "auth requisite pam_succeed_if.so user ingroup wheel";
        let step = "auth substack system-login";
        let current = overrides::neutralize(&format!("{jump}\n{VERIFY_STANZA}\n{gate}\n{step}\n"));
        assert!(current.contains(INERT_TAG), "{current}");
        let below_gate = format!("{jump}\n{gate}\n{VERIFY_STANZA}\n{step}\n");
        assert_eq!(overrides::refill(&current, &below_gate), None);
        assert!(!overrides::recipe_lines_above_stay_above(
            &format!("{jump}\n{VERIFY_STANZA}\n{gate}\n{step}\n"),
            &below_gate
        ));
        // The recipe putting the line above the jump and the gate leaves the
        // refill free to hold the jump's place.
        let on_top = format!("{VERIFY_STANZA}\n{jump}\n{gate}\n{step}\n");
        assert!(overrides::recipe_lines_above_stay_above(
            &format!("{jump}\n{VERIFY_STANZA}\n{gate}\n{step}\n"),
            &on_top
        ));
        // Only a line with a numeric jump may move above irlume's line: a
        // keyring consumer the recipe keeps below it (it reads the password
        // irlume's line releases) refuses the refill.
        let consumer = "auth optional pam_gnome_keyring.so";
        assert!(!overrides::recipe_lines_above_stay_above(
            &format!("{consumer}\n{VERIFY_STANZA}\n{step}\n"),
            &format!("{VERIFY_STANZA}\n{consumer}\n{step}\n"),
        ));
        // irlume's own tagged keyring consumer is ordered the same way: it
        // must stay below the keyring unseal line the recipe puts above it.
        let tagged =
            format!("auth       optional                     pam_gnome_keyring.so {KEYRING_TAG}");
        assert!(is_irlume_line(&tagged), "{tagged}");
        assert!(!overrides::recipe_lines_above_stay_above(
            &format!("{tagged}\n{KEYRING_UNSEAL}\n{step}\n"),
            &format!("{KEYRING_UNSEAL}\n{tagged}\n{step}\n"),
        ));
        // Only lines of irlume's line's own phase are ordered: a session line
        // moved across an auth line is not, in either direction, while an
        // `@include common-auth` is an auth line.
        let session = "session optional pam_umask.so";
        assert!(overrides::recipe_lines_above_stay_above(
            &format!("{session}\n{VERIFY_STANZA}\n{gate}\n{step}\n"),
            &format!("{VERIFY_STANZA}\n{gate}\n{session}\n{step}\n"),
        ));
        assert!(overrides::recipe_lines_above_stay_above(
            &format!("{VERIFY_STANZA}\n{gate}\n{step}\n{session}\n"),
            &format!("{session}\n{VERIFY_STANZA}\n{gate}\n{step}\n"),
        ));
        assert!(!overrides::recipe_lines_above_stay_above(
            &format!("{VERIFY_STANZA}\n@include common-auth\n"),
            &format!("@include common-auth\n{VERIFY_STANZA}\n"),
        ));
        // An `@include` brings in every phase of its file, whatever its
        // name: one the recipe puts above irlume's session line stays above.
        assert!(!overrides::recipe_lines_above_stay_above(
            &format!("{RESEAL_SESSION}\n@include system-auth\n"),
            &format!("@include system-auth\n{RESEAL_SESSION}\n"),
        ));
        // Comments and blank lines do not order anything.
        assert!(overrides::recipe_lines_above_stay_above(
            &format!("{VERIFY_STANZA}\n# moved by hand\n\n{gate}\n{step}\n"),
            &format!("# moved by hand\n{VERIFY_STANZA}\n{gate}\n{step}\n"),
        ));
    }

    /// A place a disable held stops being the verify line's place once the
    /// password step moves across it: an administrator who moves
    /// `pam_unix.so` above the inactive line, while the jump still counts it,
    /// would otherwise get irlume's line back below the password step, where
    /// the recipe never puts it. The enable refuses and leaves the stack.
    #[test]
    fn an_in_place_refill_keeps_the_verify_line_above_the_password_step() {
        let etc = "/etc/pam.d/sudo";
        for (stanza, wire) in [
            (
                VERIFY_STANZA,
                wire_verify_service as fn(&str) -> (String, bool),
            ),
            (POLKIT_VERIFY_STANZA, wire_polkit_service),
        ] {
            let held = overrides::neutralize(&counted_verify_stack(stanza));
            let lines: Vec<&str> = held.lines().collect();
            assert!(lines[1].contains(INERT_TAG) && lines[2].contains("pam_unix.so"));
            let moved = format!(
                "{}\n{}\n{}\n{}\n",
                lines[0],
                lines[2],
                lines[1],
                lines[3..].join("\n")
            );
            let (wired, changed) = wire(&unwire_lines(&moved).0);
            assert!(changed, "{moved}");
            assert!(
                matches!(
                    keep_places(etc, &moved, &wired),
                    Some(KeptPlaces::Refused(_))
                ),
                "{moved}"
            );
            // Only auth lines are held to the step's side: a session line on
            // either side of it does not matter.
            let step = "auth required pam_unix.so";
            assert!(overrides::same_side_of_the_password_step(
                &format!("{stanza}\n{RESEAL_SESSION}\n{step}\n"),
                &format!("{stanza}\n{step}\n{RESEAL_SESSION}\n"),
            ));
            // The unmoved stack is still refilled in its place.
            let (wired, _) = wire(&unwire_lines(&held).0);
            assert!(
                matches!(keep_places(etc, &held, &wired), Some(KeptPlaces::Filled(_))),
                "{held}"
            );
        }
    }

    #[test]
    fn an_in_place_enable_refills_only_places_a_jump_counts() {
        let etc = "/etc/pam.d/sudo";
        let decide = |current: &str, wire: fn(&str) -> (String, bool)| {
            let (wired, changed) = wire(&unwire_lines(current).0);
            assert!(changed, "{current}");
            keep_places(etc, current, &wired)
        };
        for (stanza, wire) in [
            (
                VERIFY_STANZA,
                wire_verify_service as fn(&str) -> (String, bool),
            ),
            (POLKIT_VERIFY_STANZA, wire_polkit_service),
        ] {
            let counted = counted_verify_stack(stanza);
            let held = overrides::neutralize(&counted);
            assert!(held.contains(INERT_TAG), "{held}");
            assert_eq!(
                decide(&held, wire),
                Some(KeptPlaces::Filled(counted.clone()))
            );
            // Already the recipe's line in the place the jump counts. With
            // CRLF endings the bytes differ, so it is not `Unchanged`;
            // `wire_service` keeps such a file before this, since PAM reads
            // each carriage return as part of its line.
            assert_eq!(decide(&counted, wire), Some(KeptPlaces::Unchanged));
            assert_eq!(decide(&counted.replace('\n', "\r\n"), wire), None);
            // Inactive lines no jump counts: wired as the recipe has it.
            let unjumped = held.replacen("[success=2 default=ignore]", "requisite", 1);
            assert_eq!(decide(&unjumped, wire), None);
            // Stacks without inactive lines are the recipe's to wire.
            let gated = "auth requisite pam_succeed_if.so user ingroup wheel\n\
                         auth include system-auth\n";
            let on_top = format!("{stanza}\n{gated}");
            for stack in [gated, on_top.as_str(), "auth include system-auth\n"] {
                assert_eq!(decide(stack, wire), None, "{stack}");
            }
        }
        // A sudo stanza held by a disable is refilled with polkit's, since both
        // are the plain verify job; an inactive line for another job does not
        // fit, and the stack is left as it is rather than the jump moved.
        let held = overrides::neutralize(&counted_verify_stack(VERIFY_STANZA));
        assert_eq!(
            decide(&held, wire_polkit_service),
            Some(KeptPlaces::Filled(counted_verify_stack(
                POLKIT_VERIFY_STANZA
            )))
        );
        let odd = held.replacen(INERT_TAG, &format!("{INERT_TAG} unseal"), 1);
        match decide(&odd, wire_verify_service) {
            Some(KeptPlaces::Refused(message)) => {
                assert!(
                    message.starts_with("⚠ /etc/pam.d/sudo: not wired"),
                    "{message}"
                );
                // The jump's line and its landing by their numbers.
                assert!(
                    message.contains("the jump on line 1 would then land on line 5"),
                    "{message}"
                );
                assert!(!message.contains("ingroup fast"), "{message}");
            }
            other => panic!("expected a refusal: {other:?}"),
        }
    }

    /// A numeric jump in a stack an `include` above irlume's lines names
    /// that lands past it counts those lines (#934), so an enable of a
    /// stack irlume edits in place keeps them where they are: inactive
    /// lines a disable left are refilled in their places, and a stack whose
    /// places do not fit is left as it is. An include below irlume's lines
    /// of the phase it feeds holds nothing.
    #[test]
    fn an_in_place_enable_holds_the_places_an_included_jump_counts() {
        let dir = TestDir::new("inplace-included-jump");
        let etc = dir.0.join("sudo");
        std::fs::write(
            dir.0.join("leap-auth"),
            "auth [success=3 default=die] pam_foo.so\n",
        )
        .unwrap();
        let stock = format!(
            "auth       include       leap-auth\n{VERIFY_STANZA}\n             auth       required      pam_unix.so\nauth       required      pam_deny.so\n"
        );
        let decide = |current: &str| {
            with_stack_reader(stack_reader(&etc.display().to_string()), || {
                let (wired, changed) = wire_verify_service(&unwire_lines(current).0);
                assert!(changed, "{current}");
                keep_places("/etc/pam.d/sudo", current, &wired)
            })
        };
        let held = overrides::neutralize(&stock);
        assert!(held.contains(INERT_TAG), "{held}");
        // The recipe puts the verify line before this include, so an inactive
        // place after it cannot be refilled without moving that line.
        match decide(&held) {
            Some(KeptPlaces::Refused(message)) => {
                assert!(message.contains("the include on line 1"), "{message}");
            }
            other => panic!("expected a refusal: {other:?}"),
        }
        // Moving the inactive place does not make the recipe's line fit.
        let lines: Vec<&str> = held.lines().collect();
        let moved = format!(
            "{}\n{}\n{}\n{}\n",
            lines[0],
            lines[2],
            lines[1],
            lines[3..].join("\n")
        );
        match decide(&moved) {
            Some(KeptPlaces::Refused(message)) => {
                assert!(message.contains("the include on line 1"), "{message}");
                assert!(!message.contains("leap-auth"), "{message}");
            }
            other => panic!("expected a refusal: {other:?}"),
        }
        // An include below irlume's lines of the phase it feeds: the
        // recipe's own write.
        let below = format!(
            "{VERIFY_STANZA}\nauth       include       leap-auth\n             auth       required      pam_unix.so\nauth       required      pam_deny.so\n"
        );
        let held_below = overrides::neutralize(&below);
        assert_eq!(decide(&held_below), None);
    }

    /// The second include expands in the parent chain too. Counting it as
    /// one line would miss a jump from the first include that reaches past
    /// those expanded lines and counts irlume's line.
    #[test]
    fn an_included_jump_counts_past_a_second_include() {
        let dir = TestDir::new("nested-included-jump");
        let etc = dir.0.join("sudo");
        std::fs::write(
            dir.0.join("leap-auth"),
            "auth [success=4 default=die] pam_foo.so\n",
        )
        .unwrap();
        std::fs::write(
            dir.0.join("middle"),
            "auth optional pam_one.so\nauth optional pam_two.so\nauth optional pam_three.so\n",
        )
        .unwrap();
        let current = format!(
            "auth include leap-auth\nauth include middle\n{VERIFY_STANZA}\nauth required pam_unix.so\n"
        );
        let stripped = unwire_lines(&current).0;
        let shifts = with_stack_reader(stack_reader(&etc.display().to_string()), || {
            overrides::jump_shifts(&current, &stripped)
        });
        assert!(!shifts.is_empty(), "the included jump should move");
        assert!(
            overrides::shift_reason(&shifts, &[overrides::Names::whole(&current)])
                .contains("the include on line 1"),
            "the first include should be named"
        );
        std::fs::write(
            dir.0.join("short-leap"),
            "auth [success=1 default=die] pam_foo.so\n",
        )
        .unwrap();
        let within_middle = current.replace("leap-auth", "short-leap");
        let stripped = unwire_lines(&within_middle).0;
        let shifts = with_stack_reader(stack_reader(&etc.display().to_string()), || {
            overrides::jump_shifts(&within_middle, &stripped)
        });
        assert!(
            shifts.is_empty(),
            "a jump landing inside the second include should stay there"
        );
    }

    /// A later include with no auth modules contributes no jump-counted
    /// line. Treating its directive as one line hides a moved landing.
    #[test]
    fn an_empty_intervening_include_does_not_hide_a_moved_jump() {
        let dir = TestDir::new("empty-intervening-include");
        let etc = dir.0.join("sudo");
        std::fs::write(
            dir.0.join("leap-auth"),
            "auth [success=1 default=die] pam_foo.so\n",
        )
        .unwrap();
        std::fs::write(dir.0.join("empty-auth"), "account required pam_unix.so\n").unwrap();
        let before = "auth include leap-auth\nauth include empty-auth\nauth required pam_unix.so\n";
        let after = format!("{before}{VERIFY_STANZA}\n");
        let shifts = with_stack_reader(stack_reader(&etc.display().to_string()), || {
            overrides::jump_shifts(before, &after)
        });
        assert!(!shifts.is_empty(), "the included jump should move");
    }

    /// A vendor change can move the bare target even when the old and new
    /// wired files still land on the same irlume role.
    #[test]
    fn a_vendor_change_rechecks_an_included_jumps_bare_landing() {
        let dir = TestDir::new("included-vendor-change");
        let etc = dir.0.join("sudo");
        std::fs::write(
            dir.0.join("leap-auth"),
            "auth [success=1 default=die] pam_foo.so\n",
        )
        .unwrap();
        let before = format!(
            "auth include leap-auth\nauth required pam_gate.so\n{VERIFY_STANZA}\nauth required pam_old.so\n"
        );
        let after = before.replace("pam_old.so", "pam_new.so");
        let shifts = with_stack_reader(stack_reader(&etc.display().to_string()), || {
            overrides::jumps_moved_by_irlume(&before, &after)
        });
        assert!(!shifts.is_empty(), "the changed vendor landing should hold");
    }

    /// First-time in-place wiring has no inactive or active irlume line to
    /// refill, but an included jump can still count the new face block.
    #[test]
    fn a_first_in_place_enable_refuses_to_move_an_included_jump() {
        let dir = TestDir::new("first-inplace-included-jump");
        ship_fedora_stacks(&dir.0);
        let etc = dir.0.join("kde");
        std::fs::write(
            dir.0.join("leap-auth"),
            "auth [success=1 default=die] pam_foo.so\n",
        )
        .unwrap();
        let before =
            "auth include leap-auth\nauth substack password-auth\nauth required pam_deny.so\n";
        std::fs::write(&etc, before).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let planned = wire_service(&svc, true, false, &wire_lock).unwrap();
        assert_eq!(
            planned.change,
            PlannedChange::KeepEditedOverride,
            "{planned}"
        );
        assert!(planned.unmet, "{planned}");
        assert!(
            planned.message.contains("the include on line 1"),
            "{planned}"
        );
        let applied = wire_service(&svc, true, true, &wire_lock).unwrap();
        assert_eq!(
            applied.change,
            PlannedChange::KeepEditedOverride,
            "{applied}"
        );
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), before);
        // Landing on the first parent line moves as well when the face line
        // is inserted between this include and the password substack.
        std::fs::write(
            dir.0.join("leap-auth"),
            "auth [success=1 default=die] pam_foo.so\nauth required pam_bar.so\n",
        )
        .unwrap();
        let planned = wire_service(&svc, true, false, &wire_lock).unwrap();
        assert_eq!(
            planned.change,
            PlannedChange::KeepEditedOverride,
            "{planned}"
        );
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), before);
        // The same included jump below the changed block does not count any
        // new line; first-time wiring still proceeds there.
        let safe = "auth substack password-auth\nauth include leap-auth\nauth required pam_deny.so\nauth required pam_unix.so\n";
        std::fs::write(&etc, safe).unwrap();
        let applied = wire_service(&svc, true, true, &wire_lock).unwrap();
        assert_eq!(applied.change, PlannedChange::Wire, "{applied}");
    }

    /// A refusal on an enable writes nothing and fails the run: a greeter a
    /// disable left with inactive lines where a jump counts them, and whose
    /// configuration now wants a face line those lines have no place for.
    #[test]
    fn an_in_place_enable_that_would_move_a_jump_leaves_the_stack() {
        let dir = TestDir::new("refill-refused");
        ship_fedora_stacks(&dir.0);
        let etc = dir.0.join("gdm-password");
        let base = "auth       required     pam_env.so\n\
                    auth       [success=2 default=ignore] pam_succeed_if.so user ingroup kiosk\n\
                    auth       substack     password-auth\n\
                    auth       optional     pam_gnome_keyring.so\n\
                    session    substack     password-auth\n";
        let reseal_only = |c: &str| wire_greeter_impl(c, false, false, false);
        let with_face = |c: &str| wire_greeter_impl(c, true, false, false);
        let (wired, _) = reseal_only(base);
        std::fs::write(&etc, &wired).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let off = wire_service(&svc, false, true, &reseal_only).unwrap();
        assert_eq!(off.change, PlannedChange::StripInPlace, "{off}");
        let held = std::fs::read_to_string(&etc).unwrap();
        assert!(held.contains(INERT_TAG), "{held}");
        let on = wire_service(&svc, true, true, &with_face).unwrap();
        assert_eq!(on.change, PlannedChange::KeepEditedOverride, "{on}");
        assert!(on.unmet, "{on}");
        assert!(on.message.contains("do not fit"), "{on}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), held);
        assert!(!dir.0.join(format!("gdm-password{BACKUP}")).exists());
    }

    /// Greeters and lock screens irlume edits in place take the same path:
    /// with face login turned off between a disable and an enable, the face
    /// line's place stays held by an inactive line, so the jump that counts
    /// it lands where it did, and turning face login on again fills it.
    #[test]
    fn an_in_place_greeter_keeps_an_unused_place_held() {
        let dir = TestDir::new("refill-greeter");
        ship_fedora_stacks(&dir.0);
        let etc = dir.0.join("gdm-password");
        let base = "auth       required     pam_env.so\n\
                    auth       [success=4 default=ignore] pam_succeed_if.so user ingroup kiosk\n\
                    auth       substack     password-auth\n\
                    auth       optional     pam_gnome_keyring.so\n\
                    session    substack     password-auth\n";
        let with_face = |c: &str| wire_greeter_impl(c, true, false, false);
        let reseal_only = |c: &str| wire_greeter_impl(c, false, false, false);
        let (wired, _) = with_face(base);
        std::fs::write(&etc, &wired).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let off = wire_service(&svc, false, true, &with_face).unwrap();
        assert_eq!(off.change, PlannedChange::StripInPlace, "{off}");
        let held = std::fs::read_to_string(&etc).unwrap();
        let on = wire_service(&svc, true, true, &reseal_only).unwrap();
        assert_eq!(on.change, PlannedChange::Wire, "{on}");
        assert!(on.message.contains("still holds the place"), "{on}");
        let partial = std::fs::read_to_string(&etc).unwrap();
        assert!(
            overrides::jump_shifts(&held, &partial).is_empty(),
            "{partial}"
        );
        assert!(!content_has_module(&held), "{held}");
        assert!(
            partial.lines().any(|l| l == RESEAL_AUTH)
                && partial
                    .lines()
                    .any(|l| l.contains(&format!("{INERT_TAG} unseal"))),
            "{partial}"
        );
        let face = wire_service(&svc, true, true, &with_face).unwrap();
        assert!(!face.unmet, "{face}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), wired);
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

    /// The 2026-08-30 distro-PAM survey's one real gap: openSUSE ships its DM
    /// PAM services ONLY under /usr/lib/pam.d (verified on Tumbleweed:
    /// /etc/pam.d holds just the pam-config-generated common/postlogin set),
    /// so sddm/gdm-password/lightdm read NotInstalled there and the wiring
    /// skipped the whole distro. The vendor paths make wire_service
    /// materialize /etc overrides exactly as it already does for plasmalogin
    /// and kde on other layouts; on families that ship /etc/pam.d directly
    /// the vendor path is never consulted. Fedora 45 moved greetd there too
    /// (and GDM 51 moved gdm-password); openSUSE Tumbleweed also ships sudo
    /// only there.
    #[test]
    fn the_dm_greeters_carry_vendor_paths_for_the_suse_layout() {
        for (etc, vendor) in [
            ("/etc/pam.d/sddm", "/usr/lib/pam.d/sddm"),
            ("/etc/pam.d/gdm-password", "/usr/lib/pam.d/gdm-password"),
            ("/etc/pam.d/lightdm", "/usr/lib/pam.d/lightdm"),
            ("/etc/pam.d/cosmic-greeter", "/usr/lib/pam.d/cosmic-greeter"),
            ("/etc/pam.d/greetd", "/usr/lib/pam.d/greetd"),
        ] {
            let svc = GREETERS
                .iter()
                .find(|s| s.etc == etc)
                .unwrap_or_else(|| panic!("{etc} missing"));
            assert_eq!(svc.vendor, Some(vendor), "{etc}");
        }
        assert_eq!(SUDO.vendor, Some("/usr/lib/pam.d/sudo"));
        // No accidental over-reach: a greeter without a verified vendor-only
        // layout keeps vendor: None (ly ships only /etc/pam.d/ly).
        let ly = GREETERS
            .iter()
            .find(|s| s.etc == "/etc/pam.d/ly")
            .expect("ly missing");
        assert_eq!(ly.vendor, None);
    }

    /// End to end on the survey's openSUSE fixture: a vendor-only sddm (the
    /// exact bytes Tumbleweed ships in /usr/lib/pam.d) materializes an /etc
    /// override carrying the face line, through the same wire_service path a
    /// real `login enable --apply` runs.
    #[test]
    fn a_suse_vendor_only_sddm_materializes_and_wires() {
        let dir = TestDir::new("suse-sddm");
        ship_opensuse_stacks(&dir.0);
        let vendor = dir.0.join("sddm.vendor");
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pam/opensuse/sddm");
        std::fs::write(
            &vendor,
            std::fs::read_to_string(&fixture).expect("the openSUSE sddm fixture"),
        )
        .unwrap();
        let svc = Svc {
            etc: leak(&dir.0.join("sddm")),
            vendor: Some(leak(&vendor)),
        };
        let wire = |c: &str| wire_greeter_impl(c, true, true, false);
        let msg = wire_service(&svc, true, true, &wire).expect("materialize + wire");
        assert!(msg.message.contains("materialized override from"), "{msg}");
        let materialized = std::fs::read_to_string(dir.0.join("sddm")).unwrap();
        assert!(materialized.contains("pam_irlume.so"));
        assert!(
            materialized.contains("substack       common-auth"),
            "the vendor stack's carrier line survives: {materialized}"
        );
    }

    #[test]
    fn fedora_cosmic_vendor_service_materializes_and_removes_only_its_override() {
        let dir = TestDir::new("fedora-cosmic-vendor");
        ship_fedora_stacks(&dir.0.join("usr/lib/pam.d"));
        let declared = GREETERS
            .iter()
            .find(|service| service.etc == "/etc/pam.d/cosmic-greeter")
            .unwrap();
        let etc = dir.0.join(declared.etc.trim_start_matches('/'));
        let vendor = dir.0.join("usr/lib/pam.d/cosmic-greeter");
        std::fs::create_dir_all(etc.parent().unwrap()).unwrap();
        std::fs::create_dir_all(vendor.parent().unwrap()).unwrap();
        // Exact vendor file from cosmic-greeter-1.8.0-1.fc44.x86_64.
        let fixture = include_str!("../tests/fixtures/pam/fedora/cosmic-greeter");
        std::fs::write(&vendor, fixture).unwrap();
        let service = Svc {
            etc: leak(&etc),
            vendor: declared
                .vendor
                .map(|path| leak(&dir.0.join(path.trim_start_matches('/')))),
        };
        let profile = dm_profile(declared.etc, None);
        let wire = |content: &str| wire_greeter_impl(content, true, true, profile.ondemand);
        wire_service(&service, true, true, &wire).unwrap();
        let first = std::fs::read_to_string(&etc).expect("vendor-only COSMIC must be wired");
        assert!(first.contains("pam_irlume.so unseal ondemand"));
        assert!(
            first.contains("pam_oo7.so"),
            "keep the vendor's wallet module"
        );
        wire_service(&service, true, true, &wire).unwrap();
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), first);
        wire_service(&service, false, true, &wire).unwrap();
        assert!(
            !etc.exists(),
            "disable must expose the original vendor stack"
        );
        assert_eq!(std::fs::read_to_string(&vendor).unwrap(), fixture);
    }

    // ---- vendor-only services ------------------------------------------------
    //
    // Some distributions ship a service ONLY under /usr/lib/pam.d, so there is
    // no /etc/pam.d file to edit and wiring must materialize an /etc override
    // from the vendor copy. Fixture provenance, byte for byte:
    // - fedora-45/greetd: Fedora dist-git rpms/greetd, branch f45 at fe1afafe
    //   (greetd.pam, installed as %{_prefix}/lib/pam.d/greetd). f44 and
    //   earlier install it to /etc/pam.d.
    // - fedora-45/gdm-password: GNOME/gdm tag 51.0,
    //   data/pam-redhat/gdm-password.pam, which Fedora 45's gdm-51.0 installs
    //   unpatched under %{_prefix}/lib/pam.d.
    // - opensuse/sudo: openSUSE pool/sudo, branch factory (sudo.pamd,
    //   installed to %{_pam_vendordir} where %{_distconfdir} is defined, as on
    //   Tumbleweed).

    /// A declared surface moved under `root`, keeping its shape: its /etc path
    /// and, when it declares one, its vendor path.
    pub(super) fn under_root(root: &Path, declared: &Svc) -> Svc {
        Svc {
            etc: leak(&root.join(declared.etc.trim_start_matches('/'))),
            vendor: declared
                .vendor
                .map(|v| leak(&root.join(v.trim_start_matches('/')))),
        }
    }

    /// Lay out a service the way a vendor-only distribution ships it: the file
    /// under `root/usr/lib/pam.d`, and nothing for it under `root/etc/pam.d`.
    pub(super) fn ship_vendor_only(root: &Path, service: &str, content: &str) {
        let vendor = root.join("usr/lib/pam.d").join(service);
        std::fs::create_dir_all(vendor.parent().unwrap()).unwrap();
        std::fs::create_dir_all(root.join("etc/pam.d")).unwrap();
        std::fs::write(vendor, content).unwrap();
    }

    /// Supply the shared Fedora PAM files a service fixture refers to. Their
    /// auth and jump behavior is part of a file-level wiring test's setup.
    pub(super) fn ship_fedora_stacks(pam_d: &Path) {
        std::fs::create_dir_all(pam_d).unwrap();
        for (name, text) in [
            ("password-auth", FEDORA_PASSWORD_AUTH),
            ("system-auth", FEDORA_PASSWORD_AUTH),
            ("gdm-password-auth-substack", FEDORA_PASSWORD_AUTH),
            ("postlogin", FEDORA_POSTLOGIN),
        ] {
            std::fs::write(pam_d.join(name), text).unwrap();
        }
    }

    pub(super) fn ship_opensuse_stacks(pam_d: &Path) {
        std::fs::create_dir_all(pam_d).unwrap();
        std::fs::write(
            pam_d.join("common-auth"),
            fixture("opensuse", "common-auth"),
        )
        .unwrap();
    }

    pub(super) fn greeter(etc: &str) -> &'static Svc {
        GREETERS
            .iter()
            .find(|s| s.etc == etc)
            .unwrap_or_else(|| panic!("{etc} is not a declared greeter"))
    }

    /// The on-demand jump shape around the password carrier: the face line
    /// directly above it and irlume's permit landing directly below, so
    /// `success=1` skips exactly the carrier.
    fn assert_jump_around_carrier(wired: &str, carrier: &str) {
        let lines: Vec<&str> = wired.lines().collect();
        let at = lines
            .iter()
            .position(|l| directive(l).contains(carrier))
            .unwrap_or_else(|| panic!("the vendor carrier line is gone: {wired}"));
        assert!(at > 0, "nothing above the carrier: {wired}");
        assert_eq!(
            lines[at - 1],
            GREETER_UNSEAL_COSMIC_JUMP,
            "the face line sits directly above the carrier: {wired}"
        );
        assert_eq!(
            lines.get(at + 1).copied(),
            Some(PERMIT_LANDING),
            "the landing sits directly below the carrier: {wired}"
        );
    }

    /// Fedora 45 moved greetd's service to /usr/lib/pam.d. Wiring must find it
    /// there, materialize the override with the face line, and remove only
    /// that override on disable.
    #[test]
    fn fedora45_vendor_only_greetd_is_wired() {
        let dir = TestDir::new("f45-greetd");
        let declared = greeter("/etc/pam.d/greetd");
        let stock = fixture("fedora-45", "greetd");
        ship_vendor_only(&dir.0, "greetd", &stock);
        ship_fedora_stacks(&dir.0.join("usr/lib/pam.d"));
        let svc = under_root(&dir.0, declared);
        let ondemand = dm_profile(declared.etc, None).ondemand;
        assert!(ondemand, "greetd arms on an empty Enter");
        let wire = |c: &str| wire_greeter_impl(c, true, true, ondemand);
        let outcome = wire_service(&svc, true, true, &wire).unwrap();
        assert_eq!(
            outcome.change,
            PlannedChange::MaterializeOverride,
            "the vendor-only greetd must be wired: {outcome}"
        );
        let wired = std::fs::read_to_string(svc.etc).unwrap();
        assert!(wired.starts_with(CREATED_PREFIX), "{wired}");
        assert_jump_around_carrier(&wired, "substack    system-auth");
        let again = wire_service(&svc, true, true, &wire).unwrap();
        assert_eq!(again.change, PlannedChange::AlreadyCorrect, "{again}");
        let off = wire_service(&svc, false, true, &wire).unwrap();
        assert_eq!(off.change, PlannedChange::RemoveOverride, "{off}");
        assert!(!Path::new(svc.etc).exists());
        assert_eq!(
            std::fs::read_to_string(svc.vendor.unwrap()).unwrap(),
            stock,
            "the vendor file is never written"
        );
    }

    /// GDM 51 (Fedora 45) moved gdm-password to /usr/lib/pam.d, behind a
    /// `gdm-password-auth-substack` service and a leading
    /// `pam_selinux_permit` line. The face line must still wrap that carrier,
    /// below the SELinux line.
    #[test]
    fn fedora45_vendor_only_gdm_password_is_wired() {
        let dir = TestDir::new("f45-gdm-password");
        let declared = greeter("/etc/pam.d/gdm-password");
        let stock = fixture("fedora-45", "gdm-password");
        ship_vendor_only(&dir.0, "gdm-password", &stock);
        ship_fedora_stacks(&dir.0.join("usr/lib/pam.d"));
        let svc = under_root(&dir.0, declared);
        let ondemand = dm_profile(declared.etc, Some(51)).ondemand;
        let wire = |c: &str| wire_greeter_impl(c, true, true, ondemand);
        let outcome = wire_service(&svc, true, true, &wire).unwrap();
        assert_eq!(
            outcome.change,
            PlannedChange::MaterializeOverride,
            "{outcome}"
        );
        let wired = std::fs::read_to_string(svc.etc).unwrap();
        assert_jump_around_carrier(&wired, "substack      gdm-password-auth-substack");
        let lines: Vec<&str> = wired.lines().collect();
        let selinux = lines
            .iter()
            .position(|l| directive(l).contains("pam_selinux_permit.so"))
            .unwrap_or_else(|| panic!("the SELinux line is gone: {wired}"));
        let face = lines
            .iter()
            .position(|l| *l == GREETER_UNSEAL_COSMIC_JUMP)
            .unwrap();
        assert!(selinux < face, "the SELinux line still runs first: {wired}");
    }

    /// Tumbleweed ships sudo only in /usr/lib/pam.d, where `--with-sudo` said
    /// "not installed (skipped)" and wired nothing.
    #[test]
    fn opensuse_vendor_only_sudo_is_wired_on_request() {
        let dir = TestDir::new("suse-sudo");
        assert_eq!(SUDO.etc, "/etc/pam.d/sudo");
        let stock = fixture("opensuse", "sudo");
        ship_vendor_only(&dir.0, "sudo", &stock);
        ship_opensuse_stacks(&dir.0.join("usr/lib/pam.d"));
        let svc = under_root(&dir.0, &SUDO);
        let outcome = wire_service(&svc, true, true, &wire_verify_service).unwrap();
        assert_eq!(
            outcome.change,
            PlannedChange::MaterializeOverride,
            "{outcome}"
        );
        let wired = std::fs::read_to_string(svc.etc).unwrap();
        let lines: Vec<&str> = wired.lines().collect();
        let stanza = lines
            .iter()
            .position(|l| *l == VERIFY_STANZA)
            .unwrap_or_else(|| panic!("no verify stanza: {wired}"));
        assert_eq!(
            lines.get(stanza + 1).copied(),
            Some("auth     include        common-auth"),
            "the stanza sits above the password stack: {wired}"
        );
        let off = wire_service(&svc, false, true, &wire_verify_service).unwrap();
        assert_eq!(off.change, PlannedChange::RemoveOverride, "{off}");
        assert!(!Path::new(svc.etc).exists());
    }

    /// `--with-sudo` and `--with-polkit` are explicit requests: when the
    /// surface resolves to nothing (no stack at all, no auth line to anchor
    /// to, or an anchor gone from a file an earlier release wired, whose
    /// lines an enable then takes out, override included) the run fails
    /// instead of reporting success. Reconcile replays the marker rather
    /// than a request, and disable has nothing to deliver, so neither counts.
    #[test]
    fn a_requested_surface_that_resolves_to_nothing_fails_the_run() {
        use PlannedChange::*;
        use ScopeOrigin::{Command, Marker};
        for change in [
            NotInstalled,
            NoAnchor,
            RestoreBackup,
            StripInPlace,
            RemoveOverride,
        ] {
            assert!(
                requested_scope_unmet(Command, true, true, change),
                "{change:?}"
            );
            assert!(
                !requested_scope_unmet(Command, true, false, change),
                "{change:?}"
            );
            assert!(
                !requested_scope_unmet(Command, false, true, change),
                "{change:?}"
            );
            assert!(
                !requested_scope_unmet(Marker, true, true, change),
                "{change:?}"
            );
        }
        // A kept or rewired override is a met request: irlume's lines are
        // correct, whatever else the file carries.
        for change in [
            MaterializeOverride,
            Wire,
            AlreadyCorrect,
            RewireOverride,
            KeepEditedOverride,
            NotWired,
        ] {
            assert!(
                !requested_scope_unmet(Command, true, true, change),
                "{change:?}"
            );
        }
        // The closing line says which of the two it was, and claims nothing
        // about what an older run left in the file: an enable that took the
        // earlier lines out still found no line to wire next to.
        assert_eq!(
            unmet_scope_line("--with-sudo", "sudo", NotInstalled),
            "[login] --with-sudo: not wired (this machine has no sudo PAM service)"
        );
        assert_eq!(
            unmet_scope_line("--with-polkit", "polkit-1", NoAnchor),
            "[login] --with-polkit: not wired (irlume finds no line in the polkit-1 PAM \
             service to wire next to)"
        );
        assert_eq!(
            unmet_scope_line("--with-polkit", "polkit-1", StripInPlace),
            "[login] --with-polkit: not wired (irlume finds no line in the polkit-1 PAM \
             service to wire next to)"
        );
    }

    /// Self-cleaning scratch dir for the wire_service file tests.
    pub(super) struct TestDir(pub(super) PathBuf);
    impl TestDir {
        pub(super) fn new(tag: &str) -> Self {
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

    /// Debian's `sudo` stack, which irlume edits in place.
    const DEBIAN_SUDO: &str = "#%PAM-1.0\n\n\
        session    required   pam_limits.so\n\n\
        @include common-auth\n\
        @include common-account\n\
        @include common-session-noninteractive\n";

    /// A rule that ends in `\`: PAM joins it with the next line.
    const CONTINUED_RULE: &str = "auth       required   pam_faillock.so preauth \\";

    /// `DEBIAN_SUDO` wired by `wire`, with `CONTINUED_RULE` directly above
    /// irlume's line (`stanza`), so PAM joins the two. Without irlume's line
    /// the rule would take in the next one, `@include common-auth`.
    fn continued_above_irlume(stanza: &str, wire: &dyn Fn(&str) -> (String, bool)) -> String {
        let (wired, changed) = wire(DEBIAN_SUDO);
        assert!(changed);
        continue_into_irlume(&wired, stanza)
    }

    /// `wired` with `CONTINUED_RULE` put directly above irlume's line.
    fn continue_into_irlume(wired: &str, stanza: &str) -> String {
        let text = wired.replacen(stanza, &format!("{CONTINUED_RULE}\n{stanza}"), 1);
        assert!(has_line_continuation(&text), "{text}");
        assert_eq!(
            text.lines()
                .skip_while(|l| *l != CONTINUED_RULE)
                .nth(1)
                .map(|l| l.contains(MODULE)),
            Some(true),
            "{text}"
        );
        text
    }

    /// The outcome for a stack irlume edits in place and keeps as it is
    /// because a line in it ends in `\`: the kept, unmet outcome and the line
    /// an override without a vendor copy gets, so the run exits 1.
    fn assert_kept_continued(outcome: &WireOutcome, enable: bool) {
        assert_eq!(
            outcome.change,
            PlannedChange::KeepEditedOverride,
            "{outcome}"
        );
        assert!(outcome.unmet, "{outcome}");
        assert!(
            outcome
                .message
                .contains(": kept as it is: a line in it ends in `\\`, which PAM joins"),
            "{outcome}"
        );
        let way = if enable {
            "; join those lines by hand and run this again"
        } else {
            "; join those lines or take irlume's lines out by hand"
        };
        assert!(outcome.message.ends_with(way), "{outcome}");
    }

    /// `login disable` on a stack irlume edits in place, whose backup no
    /// longer matches it because a rule that ends in `\` was added directly
    /// above irlume's line after wiring. Taking irlume's line out would make
    /// that rule take in `@include common-auth`, so the file is kept byte
    /// for byte, irlume's line included, and so is the backup.
    #[test]
    fn disable_keeps_an_in_place_stack_with_a_continued_line_when_the_backup_differs() {
        let dir = TestDir::new("continued-backup");
        let current = continued_above_irlume(VERIFY_STANZA, &wire_verify_service);
        let etc = dir.0.join("sudo");
        let bak = dir.0.join(format!("sudo{BACKUP}"));
        std::fs::write(&etc, &current).unwrap();
        std::fs::write(&bak, DEBIAN_SUDO).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        for apply in [false, true] {
            let off = wire_service(&svc, false, apply, &wire_verify_service).unwrap();
            assert_kept_continued(&off, false);
        }
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), current);
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), DEBIAN_SUDO);
    }

    /// The same without a backup, for both verify recipes, and also where a
    /// numeric jump counts irlume's line (which would otherwise turn it into
    /// an inactive line in its place): the file is kept byte for byte.
    #[test]
    fn disable_keeps_an_in_place_stack_with_a_continued_line_without_a_backup() {
        type Wire = fn(&str) -> (String, bool);
        for (tag, stanza, wire) in [
            ("continued-sudo", VERIFY_STANZA, wire_verify_service as Wire),
            (
                "continued-polkit",
                POLKIT_VERIFY_STANZA,
                wire_polkit_service as Wire,
            ),
        ] {
            let plain = continued_above_irlume(stanza, &wire);
            let counted = continue_into_irlume(&counted_verify_stack(stanza), stanza);
            assert!(
                !overrides::jump_shifts(&counted, &unwire_lines(&counted).0).is_empty(),
                "{counted}"
            );
            for current in [plain, counted] {
                let dir = TestDir::new(tag);
                let etc = dir.0.join("stack");
                std::fs::write(&etc, &current).unwrap();
                let svc = Svc {
                    etc: leak(&etc),
                    vendor: None,
                };
                for apply in [false, true] {
                    let off = wire_service(&svc, false, apply, &wire).unwrap();
                    assert_kept_continued(&off, false);
                }
                assert_eq!(std::fs::read_to_string(&etc).unwrap(), current, "{tag}");
                assert!(!dir.0.join(format!("stack{BACKUP}")).exists(), "{tag}");
            }
        }
    }

    /// `login enable` on a stack irlume edits in place keeps it as it is
    /// when it holds irlume's line and a line that ends in `\`, irlume's own
    /// line included: the recipe sees the stack without irlume's lines, where
    /// that `\` is gone, and rewriting irlume's line would part it from the
    /// line PAM now joins to it. A stack without irlume's lines is judged by
    /// the recipe, which finds no anchor in it, as before.
    #[test]
    fn enable_keeps_an_in_place_stack_with_a_continued_line() {
        let dir = TestDir::new("continued-enable");
        let etc = dir.0.join("sudo");
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let (wired, _) = wire_verify_service(DEBIAN_SUDO);
        let own = wired.replacen(VERIFY_STANZA, &format!("{VERIFY_STANZA} \\"), 1);
        let above = continued_above_irlume(VERIFY_STANZA, &wire_verify_service);
        for current in [own, above] {
            std::fs::write(&etc, &current).unwrap();
            for apply in [false, true] {
                let on = wire_service(&svc, true, apply, &wire_verify_service).unwrap();
                assert_kept_continued(&on, true);
            }
            assert_eq!(std::fs::read_to_string(&etc).unwrap(), current);
            assert!(!dir.0.join(format!("sudo{BACKUP}")).exists());
        }
        let bare = DEBIAN_SUDO.replacen(
            "@include common-auth",
            &format!("{CONTINUED_RULE}\n@include common-auth"),
            1,
        );
        std::fs::write(&etc, &bare).unwrap();
        let on = wire_service(&svc, true, true, &wire_verify_service).unwrap();
        assert_eq!(on.change, PlannedChange::NoAnchor, "{on}");
        assert!(!on.unmet, "{on}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), bare);
    }

    /// A machine-API disable of that stack fails its surface as kept, as for
    /// an override (see `a_kept_override_fails_its_surface_in_a_machine_apply`),
    /// with nothing written.
    #[test]
    fn a_kept_in_place_stack_fails_its_surface_in_a_machine_apply() {
        let dir = TestDir::new("continued-apply");
        let current = continued_above_irlume(VERIFY_STANZA, &wire_verify_service);
        let etc = dir.0.join("sudo");
        std::fs::write(&etc, &current).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let planned = [plan_surface(
            &svc,
            ROLE_SUDO,
            &wire_verify_service,
            false,
            false,
        )];
        assert_eq!(planned[0].change, PlannedChange::KeepEditedOverride);
        let applied = apply_surface(
            &svc,
            ROLE_SUDO,
            &wire_verify_service,
            false,
            false,
            &planned,
        );
        let error = applied.error.clone().expect("the surface fails");
        assert!(error.contains("kept as it is"), "{error}");
        assert!(applied.kept);
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), current);
    }

    /// A rule whose type PAM does not know: PAM runs it as an auth line that
    /// always fails, in the auth chain of the file it reads for a service.
    const UNREAD_RULE: &str = "auht       required   pam_faillock.so preauth";

    /// `text` with `UNREAD_RULE` directly above `@include common-auth`.
    fn unread_above_include(text: &str) -> String {
        let out = text.replacen(
            "@include common-auth",
            &format!("{UNREAD_RULE}\n@include common-auth"),
            1,
        );
        assert_ne!(out, text, "{text}");
        out
    }

    /// The outcome for a stack irlume edits in place and keeps as it is
    /// because PAM reads a line of it differently from irlume: the kept,
    /// unmet outcome an override in that state gets, with the line named.
    fn assert_kept_unread(outcome: &WireOutcome, text: &str, enable: bool) {
        assert_eq!(
            outcome.change,
            PlannedChange::KeepEditedOverride,
            "{outcome}"
        );
        assert!(outcome.unmet, "{outcome}");
        let number = text.lines().position(|l| l == UNREAD_RULE).unwrap() + 1;
        assert!(
            outcome.message.contains(&format!(
                ": kept as it is: irlume does not read line {number} as PAM does (PAM does \
                 not know its type and runs it as an auth line that always \
                 fails), and it changes no file it cannot read as PAM does; "
            )),
            "{outcome}"
        );
        let way = if enable {
            "correct that line and run this again"
        } else {
            "correct that line or take irlume's lines out by hand"
        };
        assert!(outcome.message.ends_with(way), "{outcome}");
    }

    /// `login enable` keeps a bare stack it cannot read as PAM does. When an
    /// earlier wiring remains but its anchor no longer qualifies, it removes
    /// irlume's lines byte-exactly and names the unreadable line. `login disable`
    /// takes irlume's lines out and keeps every other byte, unless a numeric
    /// jump could count irlume's lines: then it keeps the file too. A
    /// disable still puts back a backup that is the file without irlume's
    /// lines, as for a continued line: that is the file irlume first read. A
    /// stack with none of irlume's lines has nothing to take out.
    #[test]
    fn an_in_place_stack_with_a_line_irlume_does_not_read_as_pam_does_is_kept() {
        let dir = TestDir::new("unread-in-place");
        std::fs::write(dir.0.join("common-auth"), fixture("debian", "common-auth")).unwrap();
        let etc = dir.0.join("sudo");
        let bak = dir.0.join(format!("sudo{BACKUP}"));
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let bare = unread_above_include(DEBIAN_SUDO);
        let (wired, changed) = wire_verify_service(DEBIAN_SUDO);
        assert!(changed);
        let wired = unread_above_include(&wired);
        for current in [&bare, &wired] {
            for apply in [false, true] {
                std::fs::write(&etc, current).unwrap();
                let on = wire_service(&svc, true, apply, &wire_verify_service).unwrap();
                if current == &wired {
                    assert_eq!(on.change, PlannedChange::StripInPlace, "{on}");
                    assert!(on.message.contains("no anchor to wire"), "{on}");
                } else {
                    assert_kept_unread(&on, current, true);
                }
                let expected = if current == &wired && apply {
                    &bare
                } else {
                    current
                };
                assert_eq!(&std::fs::read_to_string(&etc).unwrap(), expected);
            }
            assert!(!bak.exists());
        }
        // Disable without a backup, and with one that differs: irlume's
        // lines come out, every other byte stays.
        let number = wired.lines().position(|l| l == UNREAD_RULE).unwrap() + 1;
        let named = format!("irlume does not read line {number} as PAM does");
        for backup in [None, Some(DEBIAN_SUDO)] {
            std::fs::write(&etc, &wired).unwrap();
            if let Some(backup) = backup {
                std::fs::write(&bak, backup).unwrap();
            }
            for apply in [false, true] {
                let off = wire_service(&svc, false, apply, &wire_verify_service).unwrap();
                assert_eq!(off.change, PlannedChange::StripInPlace, "{off}");
                assert!(!off.unmet, "{off}");
                assert!(off.message.contains(&named), "{off}");
                assert_eq!(
                    off.message.contains("backup kept"),
                    backup.is_some(),
                    "{off}"
                );
                let expect = if apply { &bare } else { &wired };
                assert_eq!(&std::fs::read_to_string(&etc).unwrap(), expect);
            }
            assert_eq!(bak.exists(), backup.is_some());
        }
        // A numeric jump above irlume's lines could count them: kept.
        let jumped = format!("auth [success=1 default=ignore] pam_foo.so\n{wired}");
        std::fs::write(&etc, &jumped).unwrap();
        for apply in [false, true] {
            let off = wire_service(&svc, false, apply, &wire_verify_service).unwrap();
            assert_kept_unread(&off, &jumped, false);
        }
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), jumped);
        // Nothing of irlume's to take out: not wired, nothing written.
        std::fs::write(&etc, &bare).unwrap();
        let off = wire_service(&svc, false, true, &wire_verify_service).unwrap();
        assert_eq!(off.change, PlannedChange::NotWired, "{off}");
        assert!(!off.unmet, "{off}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), bare);
        // The backup is the file without irlume's lines: it goes back.
        std::fs::write(&etc, &wired).unwrap();
        std::fs::write(&bak, &bare).unwrap();
        let off = wire_service(&svc, false, true, &wire_verify_service).unwrap();
        assert_eq!(off.change, PlannedChange::RestoreBackup, "{off}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), bare);
        assert!(!bak.exists());
    }

    /// libpam reads the carriage return of a CRLF ending as part of the
    /// line: `pam_warn.so\r` names a module it cannot load, and a Debian
    /// `@include common-auth\r` a file it does not find. An enable keeps a
    /// bare stack as it is; a wired one has no usable anchor and removes only
    /// irlume's lines byte-exactly. A disable takes irlume's lines out
    /// and keeps every other byte, carriage returns included. A backup goes
    /// back only when it is the file without irlume's lines byte for byte.
    #[test]
    fn an_in_place_stack_with_crlf_endings_is_kept() {
        let dir = TestDir::new("crlf-in-place");
        let etc = dir.0.join("sudo");
        let bak = dir.0.join(format!("sudo{BACKUP}"));
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let lf = format!("{DEBIAN_SUDO}auth optional pam_warn.so\n");
        let (wired_lf, changed) = wire_verify_service(&lf);
        assert!(changed);
        let bare = lf.replace('\n', "\r\n");
        let wired = wired_lf.replace('\n', "\r\n");
        let kept = |outcome: &WireOutcome| {
            assert_eq!(
                outcome.change,
                PlannedChange::KeepEditedOverride,
                "{outcome}"
            );
            assert!(outcome.unmet, "{outcome}");
            assert!(outcome.message.contains("a CRLF line ending"), "{outcome}");
        };
        for current in [&bare, &wired] {
            for apply in [false, true] {
                std::fs::write(&etc, current).unwrap();
                let on = wire_service(&svc, true, apply, &wire_verify_service).unwrap();
                if current == &wired {
                    assert_eq!(on.change, PlannedChange::StripInPlace, "{on}");
                    assert!(on.message.contains("a CRLF line ending"), "{on}");
                } else {
                    kept(&on);
                }
                let expected = if current == &wired && apply {
                    &bare
                } else {
                    current
                };
                assert_eq!(&std::fs::read_to_string(&etc).unwrap(), expected);
            }
            assert!(!bak.exists());
        }
        // An LF backup of the file without irlume's lines stays where it is,
        // and irlume's lines come out with every other byte kept.
        std::fs::write(&etc, &wired).unwrap();
        std::fs::write(&bak, &lf).unwrap();
        for apply in [false, true] {
            let off = wire_service(&svc, false, apply, &wire_verify_service).unwrap();
            assert_eq!(off.change, PlannedChange::StripInPlace, "{off}");
            assert!(off.message.contains("a CRLF line ending"), "{off}");
            let expect = if apply { &bare } else { &wired };
            assert_eq!(&std::fs::read_to_string(&etc).unwrap(), expect);
        }
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), lf);
        // The same file with CRLF endings goes back.
        std::fs::write(&etc, &wired).unwrap();
        std::fs::write(&bak, &bare).unwrap();
        let off = wire_service(&svc, false, true, &wire_verify_service).unwrap();
        assert_eq!(off.change, PlannedChange::RestoreBackup, "{off}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), bare);
        assert!(!bak.exists());
    }

    /// A machine-API enable of such a stack fails its surface as kept, with
    /// nothing written, as for a continued line.
    #[test]
    fn a_stack_irlume_does_not_read_as_pam_does_fails_its_surface_in_a_machine_apply() {
        let dir = TestDir::new("unread-apply");
        let current = unread_above_include(DEBIAN_SUDO);
        let etc = dir.0.join("sudo");
        std::fs::write(&etc, &current).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let planned = [plan_surface(
            &svc,
            ROLE_SUDO,
            &wire_verify_service,
            true,
            false,
        )];
        assert_eq!(planned[0].change, PlannedChange::KeepEditedOverride);
        assert!(planned[0].kept);
        let applied = apply_surface(&svc, ROLE_SUDO, &wire_verify_service, true, false, &planned);
        let error = applied.error.clone().expect("the surface fails");
        assert!(error.contains("irlume does not read line"), "{error}");
        assert!(applied.kept);
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), current);
    }

    /// No recipe wires a stack with a line irlume does not read as PAM does,
    /// and the keyring hand-off report stays silent on one, as for a
    /// continued line: every conclusion would rest on lines PAM does not
    /// read as irlume does.
    #[test]
    fn no_recipe_wires_a_stack_irlume_does_not_read_as_pam_does() {
        let with = |stack: &str| format!("{stack}{UNREAD_RULE}\n");
        let greeter = with(UPSTREAM_FEDORA);
        let sudo = with(DEBIAN_SUDO);
        let fingerprint = with(UPSTREAM_GDM_FINGERPRINT);
        for (label, (out, changed), before) in [
            ("verify", wire_verify_service(&sudo), &sudo),
            ("polkit", wire_polkit_service(&sudo), &sudo),
            ("omarchy lock", wire_omarchy_lock(&sudo), &sudo),
            ("lock", wire_lock(&greeter), &greeter),
            (
                "greeter",
                wire_greeter_impl(&greeter, true, true, true),
                &greeter,
            ),
            (
                "fingerprint",
                wire_fp_keyring(&fingerprint, "gdm-fingerprint"),
                &fingerprint,
            ),
        ] {
            assert!(!changed, "{label}");
            assert_eq!(&out, before, "{label}");
        }
        let (wired, ok) = wire_greeter_impl(UPSTREAM_FEDORA, true, true, true);
        assert!(ok);
        assert!(keyring_handoff(&wired, "plasmalogin").is_some());
        assert!(keyring_handoff(&with(&wired), "plasmalogin").is_none());
    }

    /// libpam installs an auth line with no control, or with no module, as
    /// one that always fails, and runs one whose control it rejects as a line
    /// that is `bad` whatever its module returns: a stack that reaches it
    /// lets no one through unless a line before it ends the stack. No recipe
    /// wires such a file, wherever the line is, since a `sufficient` face
    /// line above it would let a face match through; a sudo stack of that
    /// line alone included. faillock's `[default=die]` branch, which a
    /// correct password jumps past, is no such line.
    #[test]
    fn no_recipe_wires_a_stack_with_an_auth_line_that_always_fails() {
        for failing in [
            "auth",
            "-auth",
            "auth       required",
            "auth       [default=ignore]",
            "auth       [success=bogus]   pam_unix.so",
            "AUTH       [success=bogus]   pam_unix.so",
            "auth       bogus             pam_unix.so",
        ] {
            let only = format!("#%PAM-1.0\n{failing}\n");
            let sudo_below = format!("{DEBIAN_SUDO}{failing}\n");
            let sudo_above = format!("#%PAM-1.0\n{failing}\n@include common-auth\n");
            let greeter = format!("{UPSTREAM_FEDORA}{failing}\n");
            let debian = format!("{}{failing}\n", fixture("debian", "lightdm"));
            for verify in [&only, &sudo_below, &sudo_above] {
                for (label, (out, changed)) in [
                    ("verify", wire_verify_service(verify)),
                    ("polkit", wire_polkit_service(verify)),
                    ("omarchy lock", wire_omarchy_lock(verify)),
                ] {
                    assert!(!changed, "{label}: {verify}");
                    assert_eq!(&out, verify, "{label}");
                }
            }
            for stack in [&greeter, &debian, &only] {
                for (label, (out, changed)) in [
                    ("lock", wire_lock(stack)),
                    ("greeter", wire_greeter_impl(stack, true, true, true)),
                    ("keyring", wire_greeter_impl(stack, false, true, false)),
                ] {
                    assert!(!changed, "{label}: {stack}");
                    assert_eq!(&out, stack, "{label}");
                }
            }
        }
        // The same lines of another type leave the auth stack as it was.
        let session = format!("{DEBIAN_SUDO}session\n");
        assert!(wire_verify_service(&session).1);
        assert!(!has_failing_auth_line(
            "auth [success=1 default=bad] pam_unix.so\n\
             auth [default=die] pam_faillock.so authfail\n"
        ));
    }

    #[test]
    fn a_missing_shared_auth_stack_is_not_wired() {
        for (label, content) in [
            ("include", "auth include system-auth\n"),
            ("substack", "auth substack system-auth\n"),
            ("debian include", "@include common-auth\n"),
        ] {
            let (wired, changed) = with_stack_reader(stacks_of(&[]), || {
                wire_greeter_impl(content, true, true, true)
            });
            assert!(!changed, "{label}: {wired}");
            assert_eq!(wired, content, "{label}");
        }
    }

    #[test]
    fn a_shared_auth_stack_with_an_unreadable_nested_stack_is_not_wired() {
        for nested in [
            "auth include system-auth\n",
            "auth substack system-auth\n",
            "@include system-auth\n",
        ] {
            let (wired, changed) =
                with_stack_reader(stacks_of(&[("system-login", nested)]), || {
                    wire_greeter_impl("auth include system-login\n", true, true, true)
                });
            assert!(!changed, "{nested}: {wired}");
            assert_eq!(wired, "auth include system-login\n");
        }

        let (wired, changed) = with_stack_reader(
            stacks_of(&[
                ("system-login", "auth include system-auth\n"),
                ("system-auth", "auth include system-login\n"),
            ]),
            || wire_greeter_impl("auth include system-login\n", true, true, true),
        );
        assert!(!changed, "cyclic include: {wired}");

        let (wired, changed) = with_stack_reader(
            stacks_of(&[
                ("system-login", "auth include system-auth\n"),
                ("system-auth", "auth required pam_unix.so\n"),
            ]),
            || wire_greeter_impl("auth include system-login\n", true, true, true),
        );
        assert!(changed, "readable nested include: {wired}");
    }

    #[test]
    fn a_service_is_wired_only_after_its_shared_password_stack_can_be_read() {
        let dir = TestDir::new("missing-password-stack");
        let etc = dir.0.join("kde");
        let stack = dir.0.join("password-auth");
        let original = "auth substack password-auth\n";
        std::fs::write(&etc, original).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };

        for unreadable in [false, true] {
            if unreadable {
                std::fs::create_dir(&stack).unwrap();
            }
            let result = wire_service(&svc, true, true, &wire_lock).unwrap();
            assert_eq!(result.change, PlannedChange::NoAnchor, "{result}");
            assert_eq!(std::fs::read_to_string(&etc).unwrap(), original);
            assert!(!dir.0.join(format!("kde{BACKUP}")).exists());
            if unreadable {
                std::fs::remove_dir(&stack).unwrap();
            }
        }

        std::fs::write(&stack, "auth required pam_unix.so\n").unwrap();
        let result = wire_service(&svc, true, true, &wire_lock).unwrap();
        assert_eq!(result.change, PlannedChange::Wire, "{result}");
        assert!(content_has_module(&std::fs::read_to_string(&etc).unwrap()));
    }

    #[test]
    fn a_service_is_not_wired_while_a_nested_shared_stack_is_missing() {
        let dir = TestDir::new("missing-nested-stack");
        let etc = dir.0.join("lightdm");
        let original = "auth include system-login\n";
        std::fs::write(&etc, original).unwrap();
        std::fs::write(dir.0.join("system-login"), "auth include system-auth\n").unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };

        let missing = wire_service(&svc, true, true, &wire_lock).unwrap();
        assert_eq!(missing.change, PlannedChange::NoAnchor, "{missing}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), original);
        assert!(!dir.0.join(format!("lightdm{BACKUP}")).exists());

        std::fs::write(dir.0.join("system-auth"), "auth required pam_unix.so\n").unwrap();
        let readable = wire_service(&svc, true, true, &wire_lock).unwrap();
        assert_eq!(readable.change, PlannedChange::Wire, "{readable}");
        assert!(content_has_module(&std::fs::read_to_string(&etc).unwrap()));
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

    pub(super) const UPSTREAM_FEDORA: &str = r#"auth     [success=done ignore=ignore default=bad] pam_selinux_permit.so
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

    /// Fedora's authselect `password-auth`, as the stack an `include` of it
    /// reads: its jumps land inside it.
    pub(super) const FEDORA_PASSWORD_AUTH: &str = "\
auth        required      pam_env.so
auth        required      pam_faildelay.so delay=2000000
auth        [default=1 ignore=ignore success=ok] pam_usertype.so isregular
auth        [default=1 ignore=ignore success=ok] pam_localuser.so
auth        sufficient    pam_unix.so nullok
auth        [default=1 ignore=ignore success=ok] pam_usertype.so isregular
auth        sufficient    pam_sss.so forward_pass
auth        required      pam_deny.so

account     required      pam_unix.so

password    requisite     pam_pwquality.so local_users_only
password    sufficient    pam_unix.so yescrypt shadow nullok use_authtok
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session    optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
";
    /// Fedora's authselect `postlogin`: its jumps land inside it too.
    pub(super) const FEDORA_POSTLOGIN: &str = "\
session     optional                   pam_umask.so silent
session     [success=1 default=ignore] pam_succeed_if.so service !~ gdm* service !~ su* quiet
session     [default=1]                pam_lastlog2.so silent
session     optional                   pam_lastlog2.so silent
";

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

    /// A complete pam_oo7 pair (auth below the fprintd anchor, plus a session
    /// line) consumes the released login password as pam_gnome_keyring's
    /// does, so it gets the unseal line only, and irlume adds no
    /// pam_gnome_keyring pair of its own beside it.
    #[test]
    fn wire_fp_keyring_counts_a_pam_oo7_pair_as_a_consumer() {
        let with_oo7 = "#%PAM-1.0\nauth       required      pam_fprintd.so\n\
-auth      optional      pam_oo7.so\n\
-session   optional      pam_oo7.so auto_start\n";
        let (w, changed) = wire_fp_keyring(with_oo7, "gdm-fingerprint");
        assert!(changed);
        assert!(w.contains("pam_irlume.so keyring"), "{w}");
        assert!(!w.contains("pam_gnome_keyring.so"), "{w}");
        assert_eq!(w.matches("pam_oo7.so").count(), 2, "{w}");
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

    /// GDM 51 on Fedora 45 lists pam_oo7 beside pam_gnome_keyring, both
    /// optional (`-`), after its renamed password substack. The fixture is
    /// /usr/lib/pam.d/gdm-password from gdm-51~rc-2.fc45.x86_64, byte for
    /// byte the same as GDM 51.0's pam-redhat/gdm-password.pam. pam_oo7 reads
    /// PAM_AUTHTOK in its auth half and hands it to oo7-daemon from its
    /// session half, so both keyring auth lines must sit below the face line,
    /// and oo7's pair alone is a complete hand-off: a stack that keeps only
    /// oo7's lines must not be reported as releasing a password nothing reads.
    #[test]
    fn fedora_45_gdm_password_hands_the_password_to_pam_oo7() {
        let stock = fixture("fedora-45", "gdm-password");
        let (wired, changed) = wire_greeter_impl(&stock, true, true, true);
        assert!(changed, "the Fedora 45 stack must be wirable");
        let lines: Vec<&str> = wired.lines().collect();
        let face = lines
            .iter()
            .position(|l| l.contains("pam_irlume.so unseal"))
            .expect("face line");
        for module in ["pam_gnome_keyring.so", "pam_oo7.so"] {
            let auth = lines
                .iter()
                .position(|l| is_auth_directive(l) && l.contains(module))
                .unwrap_or_else(|| panic!("{module}: vendor auth line kept"));
            assert!(face < auth, "{module} must read the released password");
        }
        let h = keyring_handoff(&wired, "gdm-password").expect("releases a credential");
        assert!(h.complete.is_some(), "auth_only={:?}", h.auth_only);

        let oo7_only: String = stock
            .lines()
            .filter(|l| !l.contains("pam_gnome_keyring.so"))
            .map(|l| format!("{l}\n"))
            .collect();
        let (wired, changed) = wire_greeter_impl(&oo7_only, true, true, true);
        assert!(changed);
        let h = keyring_handoff(&wired, "gdm-password").expect("releases a credential");
        assert_eq!(
            h.complete,
            Some("pam_oo7.so"),
            "auth_only={:?}",
            h.auth_only
        );
        let (_, again) = wire_greeter_impl(&wired, true, true, true);
        assert!(!again, "rewiring must be a no-op");
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
        let neither = [
            "auth required pam_unix.so",
            "-auth optional pam_gnome_keyring.so",
        ];
        assert_eq!(
            find_auth_anchor(&neither),
            Some(0),
            "guess is still the floor"
        );
        let none: [&str; 0] = [];
        assert_eq!(find_auth_anchor(&none), None);
    }

    /// A Debian greeter whose password include is a site's own copy
    /// (`@include common-auth-local`) keeps the include layout, as it always
    /// has: the face line right above the include, below `pam_nologin`, and
    /// the keyring and `reseal` lines below it, after the password step, as
    /// they are designed to be. The include is known by how its name starts,
    /// not by the exact name.
    #[test]
    fn a_suffixed_debian_password_include_keeps_the_include_layout() {
        for include in [
            "@include common-auth-local",
            "@include common-authx",
            "@include login-local",
        ] {
            let stock = format!(
                "#%PAM-1.0\n\
                 auth    requisite       pam_nologin.so\n\
                 auth    required        pam_succeed_if.so user != root quiet_success\n\
                 {include}\n\
                 -auth   optional        pam_gnome_keyring.so\n\
                 @include common-account\n\
                 session optional        pam_keyinit.so force revoke\n\
                 @include common-session-local\n\
                 -session optional       pam_gnome_keyring.so auto_start\n"
            );
            for (face, keyring) in [(true, true), (false, true), (true, false)] {
                let (wired, changed) = wire_greeter_impl(&stock, face, keyring, true);
                assert!(changed, "{include}");
                let lines: Vec<&str> = wired.lines().collect();
                let at = |pred: &dyn Fn(&str) -> bool| lines.iter().position(|l| pred(l));
                let nologin = at(&|l| l.contains("pam_nologin.so")).unwrap();
                let inc = at(&|l| l == include).unwrap();
                assert!(!wired.contains("pam_permit.so"), "{wired}");
                assert!(!wired.contains("success=1"), "{wired}");
                if face {
                    let face_at = at(&|l| irlume_rule_has_arg(l, "unseal")).unwrap();
                    assert_eq!(face_at + 1, inc, "{wired}");
                    assert!(nologin < face_at, "{wired}");
                    assert!(lines[face_at].contains("sufficient"), "{wired}");
                }
                let keyring_at = at(&|l| irlume_rule_has_arg(l, "keyring"));
                assert_eq!(keyring_at.is_some(), keyring, "{wired}");
                assert!(keyring_at.is_none_or(|k| k > inc), "{wired}");
                let reseal = at(&|l| l == RESEAL_AUTH).unwrap();
                assert!(reseal > inc, "{wired}");
                // The session `reseal` follows the session include.
                let session_inc = at(&|l| l == "@include common-session-local").unwrap();
                assert_eq!(lines[session_inc + 1], RESEAL_SESSION, "{wired}");
            }
        }
    }

    /// A reader of the stacks `stacks` names, for a test: no file is read.
    fn stacks_of(stacks: &[(&str, &str)]) -> StackReader {
        let stacks: Vec<(String, String)> = stacks
            .iter()
            .map(|(name, text)| ((*name).to_string(), (*text).to_string()))
            .collect();
        std::rc::Rc::new(move |name: &str| {
            stacks
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, text)| text.clone())
        })
    }

    /// Stacks a first auth `include` names on real systems, as their
    /// packages installed them on 2026-09-28: openSUSE Tumbleweed's
    /// `/usr/lib/pam.d/xdm` (package xdm, which its lightdm includes), Arch's
    /// `/etc/pam.d/login` (util-linux, which ly and cinnamon-screensaver
    /// include) and `system-local-login` (pambase), and Alpine's
    /// `/usr/lib/pam.d/base-auth` (linux-pam, which its lightdm includes).
    const OPENSUSE_XDM: &str = "#%PAM-1.0\nauth     substack       common-auth\n\
         auth     include        postlogin-auth\naccount  substack       common-account\n\
         account  include        postlogin-account\npassword substack       common-password\n\
         password include        postlogin-password\nsession  required       pam_loginuid.so\n\
         session  substack       common-session\nsession  include        postlogin-session\n\
         session  optional       pam_keyinit.so revoke force\n";
    const ARCH_LOGIN: &str = "#%PAM-1.0\n\nauth       requisite    pam_nologin.so\n\
         auth       include      system-local-login\naccount    include      system-local-login\n\
         session    include      system-local-login\npassword   include      system-local-login\n";
    const ARCH_SYSTEM_LOCAL_LOGIN: &str = "#%PAM-1.0\n\nauth      include   system-login\n\
         account   include   system-login\npassword  include   system-login\n\
         session   include   system-login\n";
    /// A `postlogin-auth` for `xdm` to include that holds only an optional
    /// keyring line, which a face match may skip. The real file is read
    /// where it is, and its lines decide.
    const OPENSUSE_POSTLOGIN_AUTH: &str =
        "#%PAM-1.0\nauth     optional       pam_gnome_keyring.so\n";
    const ALPINE_BASE_AUTH: &str = "# basic PAM configuration for Alpine.\n\n\
         auth required pam_unix.so nullok\nauth required pam_nologin.so\n\
         auth required pam_env.so\n\n-auth optional pam_gnome_keyring.so\n\
         -auth optional pam_kwallet5.so\n";

    /// The stacks the reviewer's layouts include: a password line whose
    /// failure the stack ignores, and a fingerprint line alone.
    const MY_SUFF: &str = "auth sufficient pam_unix.so\n";
    const MY_FP: &str = "auth sufficient pam_fprintd.so\n";

    /// irlume's permit landing, keyring and `reseal` lines are designed to
    /// follow the password step and a line whose failure fails the stack, so
    /// the first-auth-line guess, which puts them right below that line, is
    /// taken only where that line is such a step (a password module with a
    /// control that fails the stack) or an `include` of a stack that runs one,
    /// and where no auth line below it can check a password.
    #[test]
    fn the_first_auth_line_guess_is_refused_above_a_password_step() {
        for lines in [
            &["auth required pam_env.so", "auth required pam_unix.so"][..],
            &[
                "auth [success=done ignore=ignore default=bad] pam_selinux_permit.so",
                "auth include my-auth",
            ],
            &[
                "auth [success=done ignore=ignore default=bad] pam_selinux_permit.so",
                "auth sufficient pam_unix.so nullok",
                "auth required pam_deny.so",
            ],
            &[
                "auth requisite pam_nologin.so",
                "@include my-auth",
                "@include common-account",
            ],
            &["auth requisite pam_nologin.so", "auth required pam_sss.so"],
            &["auth sufficient pam_unix.so nullok"],
            &["auth optional pam_unix.so"],
            &["auth [success=ok default=ignore] pam_unix.so"],
            &[
                "auth [success=1 default=bad] pam_unix.so",
                "auth required pam_permit.so",
            ],
            &["auth [success=ok user_unknown=ignore default=bad] pam_unix.so"],
            // A password step whose success counts nothing: the stack
            // grants no one, and a face match must not grant either.
            &["auth [success=ignore default=die] pam_unix.so"],
            &["auth [success=reset default=bad] pam_unix.so"],
            &["auth"],
            // A first line that checks no password.
            &["auth required pam_env.so"],
            &[
                "auth requisite pam_nologin.so",
                "auth optional pam_gnome_keyring.so",
            ],
            &["auth required pam_faildelay.so delay=2000000"],
            &["auth required pam_sss.so ignore_unknown_user"],
            // An include of a stack irlume cannot read.
            &["auth include xdm", "account include xdm"],
        ] {
            assert_eq!(find_auth_anchor(lines), None, "{lines:?}");
            let text = format!("{}\n", lines.join("\n"));
            for (face, keyring) in [(true, true), (false, true), (true, false)] {
                assert_eq!(
                    wire_greeter_impl(&text, face, keyring, true),
                    (text.clone(), false),
                    "{lines:?}"
                );
            }
            assert_eq!(wire_lock(&text), (text.clone(), false), "{lines:?}");
        }
        for lines in [
            &["auth required pam_unix.so"][..],
            &[
                "auth requisite pam_unix.so",
                "auth optional pam_gnome_keyring.so",
            ],
            &[
                "auth [success=ok new_authtok_reqd=ok ignore=ignore default=bad] pam_unix.so",
                "auth required pam_deny.so",
            ],
            &["auth required pam_sss.so forward_pass"],
            &["auth [success=done default=die] pam_unix.so"],
            &["auth required /usr/lib64/security/pam_unix2.so"],
        ] {
            assert_eq!(find_auth_anchor(lines), Some(0), "{lines:?}");
        }
        // A later `@include` is read where libpam finds it: stacks with no
        // auth line keep the guess, and one that cannot be read refuses it.
        let later = [
            "auth required pam_unix.so",
            "@include common-account",
            "@include common-session",
            "account required pam_unix.so",
            "session optional pam_foo.so",
        ];
        let found = with_stack_reader(
            stacks_of(&[
                ("common-account", "account required pam_unix.so\n"),
                ("common-session", "session optional pam_foo.so\n"),
            ]),
            || find_auth_anchor(&later),
        );
        assert_eq!(found, Some(0));
        assert_eq!(find_auth_anchor(&later), None);
        // Such a file is read as the lines below the anchor are: an auth line
        // in it that checks a password refuses the guess, as it does written
        // in the file itself, and a gate does not.
        for (account, anchored) in [
            ("auth sufficient pam_sss.so\n", false),
            ("@include common-password\n", false),
            ("auth requisite pam_nologin.so\n", true),
            (
                "auth [success=die default=ignore] pam_succeed_if.so user ingroup x\n",
                true,
            ),
        ] {
            let found = with_stack_reader(
                stacks_of(&[
                    ("common-account", account),
                    ("common-password", "auth required pam_unix.so\n"),
                    ("common-session", "session optional pam_foo.so\n"),
                ]),
                || find_auth_anchor(&later),
            );
            assert_eq!(found, anchored.then_some(0), "{account}");
        }
        // openSUSE's `auth include xdm`: its stack runs the password
        // substack, read where libpam finds it.
        let xdm = ["auth include xdm", "account include xdm"];
        let found = with_stack_reader(
            stacks_of(&[
                ("xdm", OPENSUSE_XDM),
                ("postlogin-auth", OPENSUSE_POSTLOGIN_AUTH),
            ]),
            || find_auth_anchor(&xdm),
        );
        assert_eq!(found, Some(0));
    }

    /// The reviewer's layouts (i01, i02, i04, i05, i06, i07, i10, i11, u01):
    /// a first auth line that checks no password, or an include of a stack
    /// whose password line fails nothing or that runs a fingerprint line
    /// alone. No recipe wires them, with every stack they name readable or
    /// none.
    #[test]
    fn a_first_auth_line_that_decides_nothing_is_no_anchor() {
        let layouts = [
            "auth include my-suff\naccount include system-auth\nsession include system-auth\n",
            "auth include my-suff\n-auth optional pam_gnome_keyring.so\n\
             -auth optional pam_kwallet5.so\naccount include system-auth\n\
             session include system-auth\n",
            "auth include my-fp\naccount include system-auth\nsession include system-auth\n",
            "@include my-suff\nauth requisite pam_nologin.so\n@include common-account\n\
             @include common-session\n",
            "@include my-suff\nauth required pam_env.so\n@include common-account\n\
             @include common-session\n",
            "@include my-fp\nauth required pam_env.so\n-auth optional pam_gnome_keyring.so\n\
             @include common-account\n@include common-session\n",
            "auth requisite pam_nologin.so\naccount include system-auth\n\
             session include system-auth\n",
            "auth required pam_env.so\nauth required pam_faildelay.so delay=2000000\n\
             account include system-auth\nsession include system-auth\n",
            "AUTH requisite pam_nologin.so\nauth required pam_env.so\n\
             -auth optional pam_gnome_keyring.so\naccount include system-auth\n\
             session include system-auth\n",
        ];
        let readable = stacks_of(&[("my-suff", MY_SUFF), ("my-fp", MY_FP)]);
        for text in layouts {
            for reader in [None, Some(readable.clone())] {
                let wire = |text: &str| {
                    let (face, keyring, face_only, lock) = (
                        wire_greeter_impl(text, true, true, true),
                        wire_greeter_impl(text, false, true, false),
                        wire_greeter_impl(text, true, false, true),
                        wire_lock(text),
                    );
                    [face, keyring, face_only, lock]
                };
                let outs = match reader {
                    Some(reader) => with_stack_reader(reader, || wire(text)),
                    None => wire(text),
                };
                for out in outs {
                    assert_eq!(out, (text.to_string(), false), "{text}");
                }
            }
        }
    }

    /// Real layouts whose first auth line includes a stack that runs the
    /// password step: ly and cinnamon-screensaver on Arch (`auth include
    /// login`, which includes `system-local-login` below `pam_nologin.so`),
    /// LightDM on Alpine (`auth include base-auth`, `pam_unix.so` first) and
    /// on openSUSE (`auth include xdm`, its password substack first). libpam
    /// puts the included lines in the include's place and the face jump
    /// skips the first of them, so a stack whose first line is the password
    /// step is wired with the jump, once the stacks it names can be read,
    /// and every other line of it still runs on a face match, gates
    /// included. One whose first line is anything else is not, nor an
    /// include of a stack that includes itself or one too deep.
    #[test]
    fn a_first_auth_include_of_a_stack_that_decides_is_the_anchor() {
        let opensuse_auth = fixture("opensuse", "common-auth");
        let stacks = stacks_of(&[
            ("login", ARCH_LOGIN),
            ("system-local-login", ARCH_SYSTEM_LOCAL_LOGIN),
            ("base-auth", ALPINE_BASE_AUTH),
            ("xdm", OPENSUSE_XDM),
            ("common-auth", &opensuse_auth),
            ("postlogin-auth", OPENSUSE_POSTLOGIN_AUTH),
            ("loop", "auth include loop\n"),
            ("a", "auth include b\n"),
            ("b", "auth include c\n"),
            ("c", "auth include d\n"),
            ("d", "auth required pam_unix.so\n"),
            ("e", "auth include a\n"),
            (
                "gated",
                "auth [success=die default=ignore] pam_succeed_if.so user ingroup x\n\
                 auth required pam_unix.so\n",
            ),
            (
                "gated-after",
                "auth required pam_unix.so\n\
                 auth [success=die default=ignore] pam_succeed_if.so user ingroup x\n",
            ),
            ("shared", "auth include system-auth\n"),
            (
                "system-auth",
                "auth required pam_faillock.so preauth\nauth required pam_unix.so\n",
            ),
            (
                "twice",
                "auth required pam_unix.so\nauth required pam_sss.so\n",
            ),
            (
                "jumpy",
                "auth required pam_unix.so\n\
                 auth [success=1 default=ignore] pam_succeed_if.so user ingroup x\n",
            ),
            ("ignored", "auth [success=ignore default=die] pam_unix.so\n"),
            ("common-account", "auth requisite pam_nologin.so\n"),
        ]);
        let ly = "#%PAM-1.0\n\nauth       include      login\n\
                  -auth      optional     pam_gnome_keyring.so\n\
                  -auth      optional     pam_kwallet5.so\n\naccount    include      login\n\n\
                  password   include      login\n\
                  -password  optional     pam_gnome_keyring.so use_authtok\n\n\
                  -session   optional     pam_systemd.so       class=greeter\n\
                  -session   optional     pam_elogind.so\nsession    include      login\n\
                  -session   optional     pam_gnome_keyring.so auto_start\n\
                  -session   optional     pam_kwallet5.so      auto_start\n";
        let alpine = "auth       include      base-auth\n\
                      -auth      optional     pam_gnome_keyring.so\n\
                      account    include      base-account\n\
                      password   include      base-password\n\
                      session    include      base-session\n\
                      -session   optional     pam_gnome_keyring.so auto_start\n";
        let cinnamon = "#%PAM-1.0\nauth include login\n";
        let suse = fixture("opensuse", "lightdm");
        // Arch's `login` checks pam_nologin before the password: the jump
        // would skip that line and leave the password asked.
        for text in [ly, cinnamon] {
            let lines: Vec<&str> = text.lines().collect();
            let (anchor, face) = with_stack_reader(stacks.clone(), || {
                (
                    find_auth_anchor(&lines),
                    wire_greeter_impl(text, true, true, true),
                )
            });
            assert_eq!(anchor, None, "{text}");
            assert!(!face.1, "{text}");
        }
        for (text, include) in [
            (suse.as_str(), "auth\t include\txdm"),
            (alpine, "auth       include      base-auth"),
            ("auth include d\n", "auth include d"),
            ("auth include a\n", "auth include a"),
            ("auth include gated-after\n", "auth include gated-after"),
            (
                "auth include d\n@include common-account\n",
                "auth include d",
            ),
            (
                "auth include d\nauth requisite pam_nologin.so\n",
                "auth include d",
            ),
        ] {
            let lines: Vec<&str> = text.lines().collect();
            let at = lines.iter().position(|l| *l == include).unwrap();
            let (anchor, face, keyring, lock) = with_stack_reader(stacks.clone(), || {
                (
                    find_auth_anchor(&lines),
                    wire_greeter_impl(text, true, true, true),
                    wire_greeter_impl(text, false, true, false),
                    wire_lock(text),
                )
            });
            assert_eq!(anchor, Some(at), "{text}");
            assert!(face.1 && keyring.1 && lock.1, "{text}");
            // The face jump skips the first line the include puts in its
            // place, the password step, onto the landing after the include.
            let wired = face.0.lines().collect::<Vec<_>>();
            assert_eq!(wired[at], GREETER_UNSEAL_COSMIC_JUMP, "{}", face.0);
            assert_eq!(wired[at + 1], include, "{}", face.0);
            assert_eq!(wired[at + 2], PERMIT_LANDING, "{}", face.0);
            assert_eq!(wired[at + 3], KEYRING_UNSEAL, "{}", face.0);
            assert_eq!(wired[at + 4], RESEAL_AUTH, "{}", face.0);
            assert!(!face.0.contains("sufficient   pam_irlume"), "{}", face.0);
            let locked = lock.0.lines().collect::<Vec<_>>();
            assert!(
                locked[at].contains("[success=1 default=ignore]"),
                "{}",
                lock.0
            );
            assert_eq!(locked[at + 1], include, "{}", lock.0);
            assert_eq!(locked[at + 2], PERMIT_LANDING, "{}", lock.0);
            // Without the stack it names, the same file is no anchor.
            assert_eq!(find_auth_anchor(&lines), None, "{text}");
            assert!(!wire_greeter_impl(text, true, true, true).1, "{text}");
        }
        // The first line the include puts in its place must be the step: a
        // gate above it (in a stack it includes too), a stack that includes
        // itself or one too deep, a password check or a jump after the step,
        // or a step that counts no success is no anchor.
        for text in [
            "auth include loop\n",
            "auth include e\n",
            "auth include gated\n",
            "auth include shared\n",
            "auth include twice\n",
            "auth include jumpy\n",
            "auth include ignored\n",
        ] {
            let lines: Vec<&str> = text.lines().collect();
            let anchor = with_stack_reader(stacks.clone(), || find_auth_anchor(&lines));
            assert_eq!(anchor, None, "{text}");
        }
        // The jump layout skips only the password line, so a gate after a
        // password step still runs on a face match.
        let gated = ["auth required pam_unix.so", "auth requisite pam_nologin.so"];
        assert_eq!(find_auth_anchor(&gated), Some(0));
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
    fn every_irlume_auth_line_but_reseal_counts_as_face() {
        // What reconcile strips from a login screen `remote_seats` keeps the
        // camera off, and what status counts as wiring.
        for line in [
            "auth sufficient pam_irlume.so unseal ondemand kr",
            "auth optional pam_irlume.so keyring",
            "auth sufficient pam_irlume.so wait",
            "auth sufficient pam_irlume.so",
            "auth optional pam_irlume.so keyring reseal",
        ] {
            assert!(irlume_auth_rule_beyond_reseal(line), "{line}");
        }
        for line in [
            "auth optional pam_irlume.so reseal",
            "session optional pam_irlume.so reseal",
            "auth optional pam_permit.so # irlume-landing",
        ] {
            assert!(!irlume_auth_rule_beyond_reseal(line), "{line}");
        }
        let wait = "@include common-auth\nauth sufficient pam_irlume.so wait\n";
        assert_eq!(report::wiring_mode(ROLE_LOGIN, wait), Some("verify"));
        let reseal = "@include common-auth\nauth optional pam_irlume.so reseal\n\
                      session optional pam_irlume.so reseal\n";
        assert_eq!(report::wiring_mode(ROLE_LOGIN, reseal), None);
    }

    #[test]
    fn a_greeter_with_neither_face_nor_keyring_gets_only_the_reseal_lines() {
        // What a login screen `remote_seats` keeps the camera off gets, in
        // both layouts: the keyring hand-off, nothing that reaches the camera.
        let debian = "#%PAM-1.0\n@include common-auth\n@include common-account\n\
                      @include common-session\n";
        for (layout, stack) in [("include", debian), ("substack", UPSTREAM_FEDORA)] {
            let (wired, changed) = wire_greeter_impl(stack, false, false, true);
            assert!(changed, "{layout}");
            assert!(
                wired.contains(RESEAL_AUTH) && wired.contains(RESEAL_SESSION),
                "{layout}"
            );
            assert!(
                !wired
                    .lines()
                    .any(|l| irlume_rule_has_arg(l, "unseal") || irlume_rule_has_arg(l, "keyring")),
                "{layout}: {wired}"
            );
        }
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

    /// irlume's lines are the rules whose MODULE-PATH field is pam_irlume.so,
    /// read with libpam's field syntax: an optional `-` on the type, the
    /// type, a one-word or bracketed control (spaces allowed inside the
    /// brackets), then the module path, whose file name must be exactly
    /// `pam_irlume.so`. Matching the name anywhere in the directive took an
    /// administrator's `pam_exec.so .../check-pam_irlume.so` rule for one of
    /// irlume's: an override's digest then left it out, and a vendor update
    /// rebuilt the file without it.
    #[test]
    fn irlume_lines_are_told_by_the_module_path_field() {
        let store = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-irlume-0.9.0/lib/security";
        let loads = [
            "auth sufficient pam_irlume.so".to_string(),
            "auth       [success=1 default=ignore]   pam_irlume.so unseal facefirst".to_string(),
            "auth [success=done new_authtok_reqd=done abort=die default=ignore] pam_irlume.so"
                .to_string(),
            "-auth optional pam_irlume.so keyring".to_string(),
            "AUTH optional pam_irlume.so reseal".to_string(),
            "Session optional pam_irlume.so reseal".to_string(),
            "account required pam_irlume.so".to_string(),
            "password optional pam_irlume.so".to_string(),
            "session optional /usr/lib64/security/pam_irlume.so reseal".to_string(),
            "auth sufficient /usr/lib/x86_64-linux-gnu/security/pam_irlume.so".to_string(),
            format!("auth sufficient {store}/pam_irlume.so"),
            "auth\tsufficient\tpam_irlume.so   # a note".to_string(),
            "   auth sufficient pam_irlume.so".to_string(),
            // libpam starts the next field right after a control's `]`.
            "auth [default=ignore]pam_irlume.so".to_string(),
            // An escaped `]` does not close the control.
            "auth [default=ignore \\] x] pam_irlume.so".to_string(),
        ];
        for line in &loads {
            assert!(is_irlume_line(line), "{line}");
            assert!(content_has_module(line), "{line}");
        }
        let names_only = [
            "auth required pam_exec.so /usr/local/libexec/check-pam_irlume.so",
            "auth required pam_exec.so /usr/local/libexec/pam_irlume.so",
            "auth optional pam_exec.so pam_irlume.so keyring",
            "auth required pam_unix.so # was pam_irlume.so",
            "# auth sufficient pam_irlume.so",
            "auth sufficient pam_irlume.so.disabled",
            "auth sufficient /usr/lib64/security/pam_irlume.so.bak",
            "auth sufficient libpam_irlume.so",
            "auth sufficient pam_irlume.so/",
            "auth include pam_irlume.so",
            "auth substack pam_irlume.so",
            "-auth SUBSTACK pam_irlume.so",
            "@include pam_irlume.so",
            "authx sufficient pam_irlume.so",
            "sufficient pam_irlume.so",
            "pam_irlume.so",
            "auth sufficient",
            // Inside the control group, not the module path.
            "auth [success=1 pam_irlume.so default=ignore] pam_unix.so",
            // A control never closed swallows the rest of the line, so PAM
            // finds no module path at all.
            "auth [success=1 default=ignore pam_irlume.so unseal",
        ];
        for line in names_only {
            assert!(!is_irlume_line(line), "{line}");
            assert!(!content_has_module(line), "{line}");
            let (out, changed) = unwire_lines(&format!("{line}\n"));
            assert!(
                !changed && out == format!("{line}\n"),
                "unwiring keeps {line}"
            );
        }

        // Every line irlume writes is one of its own.
        for line in [
            GREETER_UNSEAL_FACEFIRST_JUMP.to_string(),
            GREETER_UNSEAL_COSMIC_JUMP.to_string(),
            include_greeter_line("ondemand", true),
            include_greeter_line("facefirst", false),
            RESEAL_AUTH.to_string(),
            KEYRING_UNSEAL.to_string(),
            RESEAL_SESSION.to_string(),
            VERIFY_STANZA.to_string(),
            POLKIT_VERIFY_STANZA.to_string(),
            PERMIT_LANDING.to_string(),
            FP_GKR_AUTH.to_string(),
            FP_GKR_SESSION.to_string(),
            inert_line("auth", "unseal"),
            inert_line("session", "reseal"),
            inert_line("auth", ""),
        ] {
            assert!(is_irlume_line(&line), "{line}");
        }
        // The tagged lines count by their module path too: a tag on a line
        // loading some other module is not irlume's.
        for (line, ours) in [
            (
                "auth optional /usr/lib64/security/pam_permit.so # irlume-landing",
                true,
            ),
            (
                "auth optional pam_exec.so /usr/bin/pam_permit.so # irlume-landing",
                false,
            ),
            ("auth optional pam_permit.so.old # irlume-landing", false),
            (
                "auth [default=ignore] pam_exec.so pam_permit.so # irlume-inert unseal",
                false,
            ),
            (
                "-auth optional pam_exec.so pam_gnome_keyring.so # irlume-keyring",
                false,
            ),
            ("auth optional pam_permit.so # a foreign landing", false),
            ("-auth optional pam_gnome_keyring.so", false),
        ] {
            assert_eq!(is_irlume_line(line), ours, "{line}");
        }
    }

    /// The fields of a rule, split as libpam's `_pam_tokenize` splits them.
    #[test]
    fn rule_fields_are_split_as_libpam_splits_them() {
        let r = irlume_rule("-auth [success=1 default=ignore] pam_irlume.so unseal ondemand kr")
            .expect("a rule");
        assert_eq!(r.phase, "auth");
        assert_eq!(r.control, "success=1 default=ignore");
        assert_eq!(r.module, "pam_irlume.so");
        assert_eq!(r.args, vec!["unseal", "ondemand", "kr"]);
        let r =
            rule("SESSION\toptional\t/usr/lib64/security/pam_env.so  readenv=1").expect("a rule");
        assert_eq!(
            (r.phase, r.control, r.module, r.args),
            (
                "session",
                "optional",
                "/usr/lib64/security/pam_env.so",
                vec!["readenv=1"]
            )
        );
        // The next field starts right after a control's `]`.
        let r = rule("auth [default=ignore]pam_permit.so").expect("a rule");
        assert_eq!((r.control, r.module), ("default=ignore", "pam_permit.so"));
        // Only space, tab and newline separate fields, as in libpam.
        assert!(rule("auth\u{a0}sufficient pam_irlume.so").is_none());
        assert!(rule("auth [success=1 default=ignore").is_none());
        assert!(rule("account include system-auth").is_none());
        assert!(rule("@include common-auth").is_none());
        assert!(rule_names_module(
            "auth required /usr/lib64/security/pam_faillock.so preauth",
            "pam_faillock.so"
        ));
        assert!(!rule_names_module(
            "auth required pam_exec.so pam_faillock.so",
            "pam_faillock.so"
        ));
        assert!(irlume_rule_has_arg(
            "auth optional pam_irlume.so keyring",
            "keyring"
        ));
        assert!(!irlume_rule_has_arg(
            "auth optional pam_exec.so /opt/pam_irlume.so keyring",
            "keyring"
        ));
        assert!(!irlume_rule_has_arg(
            "auth optional pam_irlume.so reseal # keyring",
            "keyring"
        ));
        assert!(!irlume_rule_has_arg(
            "auth optional pam_irlume.so keyrings",
            "keyring"
        ));
    }

    /// libpam takes the brackets off ANY field that has them, not only the
    /// control, and skips only spaces and tabs before the type. Each shape
    /// was run through libpam 1.7.2 with pam_permit.so and pam_exec.so
    /// standing in for the module: `[pam_permit.so]` and `[auth]` load the
    /// module, `[include]` includes a file, pam_exec receives a bracketed
    /// argument without its brackets, and a line led by a vertical tab, a
    /// form feed or a no-break space loads nothing (its type is unknown).
    #[test]
    fn bracketed_fields_and_leading_blanks_are_read_as_libpam_reads_them() {
        for line in [
            "auth sufficient [pam_irlume.so]",
            "auth sufficient [/usr/lib64/security/pam_irlume.so]",
            "[auth] sufficient pam_irlume.so",
            "[-auth] [sufficient] [pam_irlume.so] [unseal]",
        ] {
            assert!(is_irlume_line(line), "{line}");
            assert!(content_has_module(line), "{line}");
            let stack = format!("#%PAM-1.0\n{line}\nauth       include      system-auth\n");
            let (unwired, changed) = unwire_lines(&stack);
            assert!(changed && !unwired.contains("pam_irlume.so"), "{unwired}");
            let (rewired, _) = wire_verify_service(&stack);
            assert_eq!(
                rewired.matches("pam_irlume.so").count(),
                1,
                "a stack that loads the module is not wired twice:\n{rewired}"
            );
        }
        let r = irlume_rule("[-auth] [sufficient] [pam_irlume.so] [unseal]").expect("a rule");
        assert_eq!(
            (r.phase, r.control, r.module, r.args),
            ("auth", "sufficient", "pam_irlume.so", vec!["unseal"])
        );
        assert!(irlume_rule_has_arg(
            "auth optional pam_irlume.so [keyring]",
            "keyring"
        ));
        // A bracketed include or substack names a stack, not a module.
        for line in [
            "auth [include] pam_irlume.so",
            "auth [substack] pam_irlume.so",
            "auth [INCLUDE] pam_irlume.so",
        ] {
            assert!(rule(line).is_none(), "{line}");
            assert!(!is_irlume_line(line), "{line}");
        }
        // `-[auth]` keeps its brackets: libpam strips the `-` from a field
        // that did not open with `[`.
        assert!(rule("-[auth] sufficient pam_irlume.so").is_none());
        for lead in ["\u{b}", "\u{c}", "\u{a0}", "\u{2003}", "\r"] {
            let line = format!("{lead}auth sufficient pam_irlume.so");
            assert!(rule(&line).is_none(), "{line:?}");
            assert!(!is_irlume_line(&line), "{line:?}");
            let (out, changed) = unwire_lines(&format!("{line}\n"));
            assert!(!changed && out == format!("{line}\n"), "{line:?}");
        }
        assert!(is_irlume_line(" \t auth sufficient pam_irlume.so"));
    }

    /// A stack whose only mention of pam_irlume.so is another module's
    /// argument is not wired: every recipe wires it, unwiring leaves that
    /// rule alone, and none of the checks that read irlume's lines takes it
    /// for one of them.
    #[test]
    fn a_rule_naming_the_module_in_its_arguments_is_not_wiring() {
        let exec = "auth       required     pam_exec.so /usr/local/libexec/check-pam_irlume.so";
        let stack = format!("#%PAM-1.0\n{exec}\nauth       include      system-auth\n");
        assert!(!content_has_module(&stack));
        for (label, (out, changed)) in [
            ("verify", wire_verify_service(&stack)),
            ("polkit", wire_polkit_service(&stack)),
            ("lock", wire_lock(&stack)),
            ("greeter", wire_greeter_impl(&stack, true, true, false)),
        ] {
            assert!(changed, "{label}: wired");
            assert!(out.contains(exec), "{label}: the rule stays\n{out}");
            let (unwired, _) = unwire_lines(&out);
            assert!(
                unwired.contains(exec),
                "{label}: unwiring keeps it\n{unwired}"
            );
            assert!(!content_has_module(&unwired), "{label}\n{unwired}");
        }
        let fp = "auth       required     pam_fprintd.so\n\
             auth       optional     pam_exec.so /usr/local/libexec/pam_irlume.so keyring\n\
             session    optional     pam_exec.so /usr/local/libexec/pam_irlume.so reseal\n";
        let (out, changed) = wire_fp_keyring(fp, "gdm-fingerprint");
        assert!(changed, "the fingerprint keyring line is added:\n{out}");
        assert!(
            out.contains(KEYRING_UNSEAL) && out.contains(RESEAL_SESSION),
            "{out}"
        );
        let released = format!(
            "{exec} unseal\nauth substack password-auth\n-auth optional pam_gnome_keyring.so\n"
        );
        assert!(
            keyring_handoff(&released, "gdm-password").is_none(),
            "no line of irlume's releases a password here"
        );

        let dir = TestDir::new("exec-arg-polkit");
        let polkit = dir.0.join("polkit-1");
        std::fs::write(&polkit, format!("{POLKIT_VERIFY_STANZA}\n{exec}\n")).unwrap();
        assert!(
            !polkit_stanza_stale(&polkit),
            "only irlume's own rule is judged by its control"
        );
        std::fs::write(&polkit, format!("{VERIFY_STANZA}\n{exec}\n")).unwrap();
        assert!(polkit_stanza_stale(&polkit));
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
        // libpam skips only spaces, tabs and the newline back from the end
        // of a line, and looks for a `#` only up to a NUL byte: a backslash
        // before a carriage return or another blank does not continue, and
        // one before a comment is no line end either.
        let crlf = "auth optional pam_exec.so run.sh A \\\r\nauth optional pam_foo.so\r\n";
        assert!(!has_line_continuation(crlf));
        let named = unreadable_line(crlf).unwrap();
        assert_eq!((named.number, named.why), (1, Unread::CrlfEnding));
        assert!(named.why.describe().contains("a carriage return"));
        let nbsp = "auth optional pam_exec.so run.sh A \\\u{a0}\n";
        assert!(!has_line_continuation(nbsp));
        assert_eq!(
            unreadable_line(nbsp).map(|l| l.why),
            Some(Unread::Blank('\u{a0}'))
        );
        assert!(!has_line_continuation(
            "auth optional pam_exec.so run.sh A \\ # note\n"
        ));
        assert!(has_line_continuation(
            "auth optional pam_exec.so run.sh A\0 # note \\\n"
        ));
    }

    /// A login screen whose face lines are kept out (`remote_seats`) is
    /// unwired whole where its reseal-only recipe cannot land, so no face
    /// line stays behind. One with a line irlume does not read as PAM does
    /// is such a file: the unwire takes irlume's lines out, face lines
    /// included, and keeps every other byte, when the `password-auth` its
    /// `session include` names keeps its jumps inside it. With a numeric
    /// jump above irlume's lines, or CRLF endings (PAM then looks for a
    /// `password-auth` with a carriage return in its name, which irlume
    /// cannot read), it keeps the file and names the line.
    #[test]
    fn a_remote_seat_greeter_with_an_unread_line_loses_irlume_lines_on_the_unwire() {
        let wired = "auth     [success=done ignore=ignore default=bad] pam_selinux_permit.so\n\
                     auth       [success=1 default=ignore]   pam_irlume.so unseal ondemand\n\
                     auth        substack      password-auth\n\
                     auth       optional                     pam_permit.so   # irlume-landing\n\
                     auth       optional                     pam_irlume.so keyring\n\
                     auth       optional                     pam_irlume.so reseal\n\
                     -auth        optional      pam_gnome_keyring.so\n\
                     account     include       password-auth\n\
                     session     include       password-auth\n\
                     session    optional                     pam_irlume.so reseal\n";
        let typo = wired.replacen(
            "pam_selinux_permit.so\n",
            "pam_selinux_permit.so\nauht optional pam_foo.so\n",
            1,
        );
        let crlf = wired.replace('\n', "\r\n");
        // Every carriage return at a line's end is taken off before irlume
        // tells its own lines, so doubled ones are stripped too.
        let crcrlf = wired.replace('\n', "\r\r\n");
        let reseal_only = |c: &str| wire_greeter_impl(c, false, false, true);
        for text in [&typo, &crlf, &crcrlf] {
            let dir = TestDir::new("remote-unread");
            let etc = dir.0.join("lightdm");
            std::fs::write(&etc, text).unwrap();
            std::fs::write(dir.0.join("password-auth"), FEDORA_PASSWORD_AUTH).unwrap();
            let svc = Svc {
                etc: leak(&etc),
                vendor: None,
            };
            assert!(carries_face_lines(svc.etc));
            assert!(!greeter_want(&svc, true, true, &reseal_only), "{text}");
            let off = wire_service(&svc, false, true, &reseal_only).unwrap();
            if text != &typo {
                assert_eq!(off.change, PlannedChange::KeepEditedOverride, "{off}");
                assert!(off.unmet, "{off}");
                assert!(off.message.contains("a CRLF line ending"), "{off}");
                assert_eq!(&std::fs::read_to_string(&etc).unwrap(), text);
                continue;
            }
            assert_eq!(off.change, PlannedChange::StripInPlace, "{off}");
            assert!(!off.unmet, "{off}");
            let after = std::fs::read_to_string(&etc).unwrap();
            assert_eq!(after, without_irlume_lines(text));
            assert!(!carries_face_lines(svc.etc), "{after}");
            assert!(!after.lines().any(is_irlume_line), "{after}");
            assert_eq!(after.lines().count() + 5, text.lines().count(), "{after}");
            // A jump above irlume's lines could count them: kept.
            let jumped = format!("auth [success=2 default=ignore] pam_foo.so\n{text}");
            std::fs::write(&etc, &jumped).unwrap();
            let off = wire_service(&svc, false, true, &reseal_only).unwrap();
            assert_eq!(off.change, PlannedChange::KeepEditedOverride, "{off}");
            assert!(off.unmet, "{off}");
            assert_eq!(std::fs::read_to_string(&etc).unwrap(), jumped);
        }
    }

    /// Every carriage return at a line's end is taken off before irlume
    /// tells its own lines, so a verify line that ends in the module name
    /// with doubled carriage returns is still irlume's: it is stripped, and
    /// a jump above it counts it.
    #[test]
    fn a_line_of_irlume_s_with_doubled_carriage_returns_is_told() {
        let text = format!("{VERIFY_STANZA}\r\r\nauth       include      system-auth\r\r\n");
        assert_eq!(
            without_irlume_lines(&text),
            "auth       include      system-auth\r\r\n"
        );
        assert!(!jump_could_count_irlume_lines(&text));
        let jumped = format!("auth [success=1 default=ignore] pam_foo.so\r\r\n{text}");
        assert!(jump_could_count_irlume_lines(&jumped));
    }

    /// libpam reads a line up to its first NUL byte, so a line of irlume's
    /// with a NUL right after the module name is still irlume's: a disable
    /// finds it and takes it out, every other byte kept. A foreign line
    /// with irlume's tag after a NUL is not irlume's.
    #[test]
    fn a_line_of_irlume_s_followed_by_a_nul_is_told() {
        let line = format!("{VERIFY_STANZA}\0garbage");
        assert!(is_irlume_line(&line));
        // A tag after the NUL marks no line of irlume's: PAM reads only the
        // foreign line before it.
        for foreign in [
            "auth optional pam_permit.so\0 # irlume-landing",
            "auth optional pam_gnome_keyring.so\0 # irlume-keyring",
        ] {
            assert!(!is_irlume_line(foreign), "{foreign:?}");
        }
        let text = format!("{line}\nauth       include      system-auth\n");
        assert!(holds_irlume_line(&text));
        assert_eq!(
            without_irlume_lines(&text),
            "auth       include      system-auth\n"
        );
        let dir = TestDir::new("nul-disable");
        let etc = dir.0.join("sudo");
        std::fs::write(&etc, &text).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let off = wire_service(&svc, false, true, &wire_verify_service).unwrap();
        assert_eq!(off.change, PlannedChange::StripInPlace, "{off}");
        assert_eq!(
            std::fs::read_to_string(&etc).unwrap(),
            "auth       include      system-auth\n"
        );
    }

    /// The disable of a stack irlume edits in place tells a verify line that
    /// ends in the module name with doubled carriage returns as irlume's
    /// before anything else, and takes it out with every other byte kept.
    #[test]
    fn a_disable_finds_irlume_s_line_with_doubled_carriage_returns() {
        let dir = TestDir::new("crcrlf-disable");
        let etc = dir.0.join("sudo");
        let text = format!("{VERIFY_STANZA}\r\r\nauth       include      system-auth\r\r\n");
        std::fs::write(&etc, &text).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let off = wire_service(&svc, false, true, &wire_verify_service).unwrap();
        assert_eq!(off.change, PlannedChange::StripInPlace, "{off}");
        assert_eq!(
            std::fs::read_to_string(&etc).unwrap(),
            "auth       include      system-auth\r\r\n"
        );
    }

    /// libpam puts the lines of the stack an `include` names in its place,
    /// and all of a Debian `@include`'s file in every type's stack, so a
    /// numeric jump among them that lands past them counts the lines after
    /// the include. One that lands on the first line after the include skips
    /// included lines only: with irlume's lines taken out there, the same
    /// lines of the file run as before they were added. Each stack is read
    /// where libpam finds it; one that cannot be read counts, as does an
    /// include of a type PAM does not know. A `substack` is one line, whose
    /// jumps stay inside it.
    #[test]
    fn a_jump_in_an_included_stack_counts_irlume_s_lines_when_it_lands_past_it() {
        let (common_auth, system_login, system_auth) = (
            fixture("debian", "common-auth"),
            fixture("arch", "system-login"),
            fixture("arch", "system-auth"),
        );
        let stacks = stacks_of(&[
            ("common-auth", &common_auth),
            ("system-login", &system_login),
            ("system-auth", &system_auth),
            ("password-auth", FEDORA_PASSWORD_AUTH),
            ("postlogin", FEDORA_POSTLOGIN),
            ("leaves", "auth [success=1 default=ignore] pam_foo.so\n"),
            (
                "leaves-session",
                "session [success=2 default=ignore] pam_foo.so\nsession optional pam_bar.so\n",
            ),
            ("outer", "auth include leaves\nauth required pam_env.so\n"),
            (
                "outer-leaves",
                "auth required pam_env.so\nauth include leaves\n",
            ),
            ("typo", "auht optional pam_foo.so\n"),
            (
                "lands-after",
                "auth [success=1 default=ignore] pam_unix.so\nauth requisite pam_deny.so\n",
            ),
            (
                "lands-past",
                "auth [success=2 default=ignore] pam_unix.so\nauth requisite pam_deny.so\n",
            ),
        ]);
        let auth = format!("{KEYRING_UNSEAL}\n{RESEAL_AUTH}\n");
        let session = format!("{RESEAL_SESSION}\n");
        let counts =
            |text: &str| with_stack_reader(stacks.clone(), || jump_could_count_irlume_lines(text));
        for (above, below, expect) in [
            ("@include common-auth", &auth, false),
            ("auth include system-login", &auth, false),
            (
                "session include password-auth\nsession include postlogin",
                &session,
                false,
            ),
            ("auth include outer", &auth, false),
            ("auth substack leaves", &auth, false),
            ("session include leaves", &session, false),
            ("auth include leaves-session", &auth, false),
            ("account include leaves", &auth, false),
            ("auth include lands-after", &auth, false),
            ("auth include lands-past", &auth, true),
            ("auth include leaves", &auth, true),
            ("@include leaves", &auth, true),
            ("auth include outer-leaves", &auth, true),
            ("session include leaves-session", &session, true),
            ("@include leaves-session", &session, true),
            ("auth include missing", &auth, true),
            ("auth include typo", &auth, true),
            ("auht include postlogin", &auth, true),
        ] {
            let text = format!("{VERIFY_STANZA}\n{above}\n{below}");
            assert_eq!(counts(&text), expect, "{text}");
        }
        // Below irlume's last line, no include counts; with no reader, one
        // above them always does.
        let last = format!("{VERIFY_STANZA}\nauth include leaves\n@include missing\n");
        assert!(!jump_could_count_irlume_lines(&last));
        let unread = format!("{VERIFY_STANZA}\n@include common-auth\n{auth}");
        assert!(jump_could_count_irlume_lines(&unread));
    }

    /// ly on Arch as an earlier release wired it, with the jump layout
    /// around `auth include login`: the include's stack starts with
    /// `pam_nologin.so`, so an enable finds no anchor and takes the lines
    /// an earlier release wired out, as a disable does, reporting both. A
    /// file irlume's lines already left has nothing to take out, so an
    /// enable skips it as ever, and a disable finds it not wired.
    #[test]
    fn a_stack_an_earlier_release_wired_around_an_include_comes_out_on_enable_and_disable() {
        let stock = "#%PAM-1.0\n\nauth       include      login\n\
                     -auth      optional     pam_gnome_keyring.so\n\
                     account    include      login\npassword   include      login\n\
                     session    include      login\n";
        let old = stock.replacen(
            "auth       include      login\n",
            &format!(
                "{GREETER_UNSEAL_COSMIC_JUMP}\nauth       include      login\n\
                 {PERMIT_LANDING}\n{KEYRING_UNSEAL}\n{RESEAL_AUTH}\n"
            ),
            1,
        );
        let dir = TestDir::new("old-include-jump");
        let etc = dir.0.join("ly");
        std::fs::write(&etc, &old).unwrap();
        for (name, text) in [
            ("login", ARCH_LOGIN),
            ("system-local-login", ARCH_SYSTEM_LOCAL_LOGIN),
        ] {
            std::fs::write(dir.0.join(name), text).unwrap();
        }
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let wire = |c: &str| wire_greeter_impl(c, true, true, true);
        let on = wire_service(&svc, true, true, &wire).unwrap();
        assert_eq!(on.change, PlannedChange::StripInPlace, "{on}");
        assert!(!on.unmet, "{on}");
        assert!(on.message.contains("no anchor to wire"), "{on}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), stock);
        // The enable leaves nothing of irlume's in the file: a fresh enable
        // has no lines to take out, so it skips the file as it always did.
        let again = wire_service(&svc, true, true, &wire).unwrap();
        assert_eq!(again.change, PlannedChange::NoAnchor, "{again}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), stock);
        let off = wire_service(&svc, false, true, &wire).unwrap();
        assert_eq!(off.change, PlannedChange::NotWired, "{off}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), stock);
    }

    /// The same file with the backup the earlier release left behind: the
    /// backup is the current file without irlume's lines, so the no-anchor
    /// enable restores it, as a disable does, and the backup is consumed.
    /// One the file moved on from is kept, and the lines are stripped in
    /// place, as a disable keeps and strips.
    #[test]
    fn a_no_anchor_enable_restores_a_matching_backup_and_keeps_a_moved_one() {
        let stock = "#%PAM-1.0\n\nauth       include      login\n\
                     -auth      optional     pam_gnome_keyring.so\n\
                     account    include      login\npassword   include      login\n\
                     session    include      login\n";
        let old = stock.replacen(
            "auth       include      login\n",
            &format!(
                "{GREETER_UNSEAL_COSMIC_JUMP}\nauth       include      login\n\
                 {PERMIT_LANDING}\n{KEYRING_UNSEAL}\n{RESEAL_AUTH}\n"
            ),
            1,
        );
        for matches in [true, false] {
            let dir = TestDir::new("old-include-backup");
            let etc = dir.0.join("ly");
            std::fs::write(&etc, &old).unwrap();
            // The backup the earlier release took: the stock file, or a
            // stale one the stack moved on from after the wiring.
            let bak = dir.0.join(format!("ly{BACKUP}"));
            std::fs::write(&bak, if matches { stock } else { "#%PAM-1.0\n" }).unwrap();
            for (name, text) in [
                ("login", ARCH_LOGIN),
                ("system-local-login", ARCH_SYSTEM_LOCAL_LOGIN),
            ] {
                std::fs::write(dir.0.join(name), text).unwrap();
            }
            let svc = Svc {
                etc: leak(&etc),
                vendor: None,
            };
            let wire = |c: &str| wire_greeter_impl(c, true, true, true);
            let on = wire_service(&svc, true, true, &wire).unwrap();
            assert!(
                on.message.contains("no anchor to wire"),
                "{on} (backup matches: {matches})"
            );
            assert_eq!(std::fs::read_to_string(&etc).unwrap(), stock);
            if matches {
                assert_eq!(on.change, PlannedChange::RestoreBackup, "{on}");
                assert!(!bak.exists(), "the restore consumes the backup");
            } else {
                assert_eq!(on.change, PlannedChange::StripInPlace, "{on}");
                assert!(bak.exists(), "a backup the file moved on from is kept");
            }
        }
    }

    /// With no backup, a lost anchor removes old lines even when an unrelated
    /// unreadable or continued rule exists. All other physical bytes survive.
    #[test]
    fn no_anchor_cleanup_keeps_unreadable_and_safe_continued_bytes() {
        let wired = format!("{VERIFY_STANZA}\nsession required pam_limits.so\n");
        for flaw in [
            "auht optional pam_echo.so\n",
            "session optional pam_echo.so note \\\n    argument\n",
        ] {
            let dir = TestDir::new("no-anchor-flaw");
            let etc = dir.0.join("sudo");
            let before = format!("{wired}{flaw}");
            std::fs::write(&etc, &before).unwrap();
            let svc = Svc {
                etc: leak(&etc),
                vendor: None,
            };
            let on = wire_service(&svc, true, true, &wire_verify_service).unwrap();
            assert_eq!(on.change, PlannedChange::StripInPlace, "{on}");
            assert_eq!(
                std::fs::read_to_string(&etc).unwrap(),
                without_irlume_lines(&before)
            );
        }
    }

    #[test]
    fn an_unreadable_line_does_not_disguise_a_valid_anchor_as_missing() {
        let dir = TestDir::new("unread-with-anchor");
        let etc = dir.0.join("sudo");
        let before =
            format!("auth required pam_unix.so\n{VERIFY_STANZA}\nauht optional pam_echo.so\n");
        std::fs::write(&etc, &before).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let on = wire_service(&svc, true, true, &wire_verify_service).unwrap();
        assert_eq!(on.change, PlannedChange::KeepEditedOverride, "{on}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), before);
    }

    #[test]
    fn a_nul_tainted_password_anchor_does_not_trigger_no_anchor_cleanup() {
        let dir = TestDir::new("nul-password-anchor");
        let etc = dir.0.join("sudo");
        let before = format!("auth required pam_unix.so\0ignored\n{VERIFY_STANZA}\n");
        std::fs::write(&etc, &before).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let on = wire_service(&svc, true, true, &wire_verify_service).unwrap();
        assert_eq!(on.change, PlannedChange::KeepEditedOverride, "{on}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), before);
    }

    #[test]
    fn a_split_numeric_control_before_our_session_line_stays_untouched() {
        let dir = TestDir::new("split-control-no-anchor");
        let etc = dir.0.join("sudo");
        let before =
            format!("session [success=\\\n1 default=ignore] pam_echo.so\n{RESEAL_SESSION}\n");
        std::fs::write(&etc, &before).unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let on = wire_service(&svc, true, true, &wire_verify_service).unwrap();
        assert_eq!(on.change, PlannedChange::KeepEditedOverride, "{on}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), before);
    }

    /// A no-anchor enable on a file whose inactive lines hold irlume's
    /// places, because a numeric jump another line carries counts them
    /// (a disable left them so): nothing comes out and nothing is written,
    /// and the file reports no anchor and why its lines stay.
    #[test]
    fn a_no_anchor_enable_keeps_inactive_lines_a_jump_counts() {
        let stock = "#%PAM-1.0\n\nauth       include      login\n\
                     -auth      optional     pam_gnome_keyring.so\n\
                     account    include      login\npassword   include      login\n\
                     session    include      login\n";
        let old = stock.replacen(
            "auth       include      login\n",
            &format!(
                "{GREETER_UNSEAL_COSMIC_JUMP}\nauth       include      login\n\
                 {PERMIT_LANDING}\n{KEYRING_UNSEAL}\n{RESEAL_AUTH}\n"
            ),
            1,
        );
        let jumped = format!("auth [success=2 default=ignore] pam_foo.so\n{old}");
        let dir = TestDir::new("old-include-inert");
        let etc = dir.0.join("ly");
        std::fs::write(&etc, &jumped).unwrap();
        for (name, text) in [
            ("login", ARCH_LOGIN),
            ("system-local-login", ARCH_SYSTEM_LOCAL_LOGIN),
        ] {
            std::fs::write(dir.0.join(name), text).unwrap();
        }
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let wire = |c: &str| wire_greeter_impl(c, true, true, true);
        // The disable turns irlume's lines into the inactive lines that keep
        // the jump's landing, so the file holds only those of irlume's.
        let off = wire_service(&svc, false, true, &wire).unwrap();
        assert_eq!(off.change, PlannedChange::StripInPlace, "{off}");
        let inert = std::fs::read_to_string(&etc).unwrap();
        assert!(inert.contains(INERT_TAG), "{inert}");
        let on = wire_service(&svc, true, true, &wire).unwrap();
        assert_eq!(on.change, PlannedChange::NoAnchor, "{on}");
        assert!(!on.unmet, "{on}");
        assert!(on.message.contains("no anchor to wire"), "{on}");
        assert!(on.message.contains("inactive lines"), "{on}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), inert);
    }

    /// Which surfaces the reconcile regression counts: the active greeter
    /// whose recipe this configuration wants, the opt-in scopes, and the
    /// lock and fingerprint services this configuration wants; not a
    /// remote-seat greeter (remote_seat_change governs it), an unwanted
    /// one, or another greeter.
    #[test]
    fn the_anchor_gone_regression_counts_the_surfaces_reconcile_maintains() {
        for (role, want, blocked, svc, primary, counts) in [
            (ROLE_LOGIN, true, false, "ly", Some("ly"), true),
            (ROLE_LOGIN, true, false, "sddm", Some("ly"), false),
            (ROLE_LOGIN, false, false, "ly", Some("ly"), false),
            (ROLE_LOGIN, true, true, "ly", Some("ly"), false),
            // No active display manager names no greeter.
            (ROLE_LOGIN, true, false, "ly", None, false),
            (ROLE_SUDO, true, false, "sudo", None, true),
            (ROLE_LOCK, true, false, "kde", None, true),
            (ROLE_LOGIN_FP, true, false, "gdm-fingerprint", None, true),
            (ROLE_SUDO, true, false, "sudo", Some("ly"), true),
            (ROLE_POLKIT, true, false, "polkit-1", Some("ly"), true),
            (ROLE_SUDO, false, false, "sudo", Some("ly"), false),
            (ROLE_LOCK, true, false, "kde", Some("ly"), true),
            (ROLE_LOCK, false, false, "kde", Some("ly"), false),
            (
                ROLE_LOGIN_FP,
                true,
                false,
                "gdm-fingerprint",
                Some("ly"),
                true,
            ),
            (
                ROLE_LOGIN_FP,
                false,
                false,
                "gdm-fingerprint",
                Some("ly"),
                false,
            ),
        ] {
            assert_eq!(
                anchor_gone_counts(role, want, blocked, primary, svc),
                counts,
                "{role} {svc}"
            );
        }
    }

    /// A no-anchor file whose backup matches and which also carries a line
    /// that ends in `\`, or one irlume does not read as PAM does: the
    /// restore is a rename of the whole file, safe where taking single
    /// lines out is not, so it happens first, as a disable does it, and the
    /// refusals never fire.
    #[test]
    fn a_no_anchor_enable_restores_a_matching_backup_before_the_refusals() {
        let stock = "#%PAM-1.0\n\nauth       include      login \\\n\
                     -auth      optional     pam_gnome_keyring.so\n\
                     account    include      login\npassword   include      login\n\
                     session    include      login\n";
        let old = stock.replacen(
            "auth       include      login \\\n",
            &format!(
                "{GREETER_UNSEAL_COSMIC_JUMP}\nauth       include      login \\\n\
                 {PERMIT_LANDING}\n{KEYRING_UNSEAL}\n{RESEAL_AUTH}\n"
            ),
            1,
        );
        for unreadable in [false, true] {
            let current = if unreadable {
                old.replacen(
                    "-auth      optional     pam_gnome_keyring.so",
                    // A vertical tab inside a line: one irlume does not
                    // read as PAM does, and no line ends in `\`.
                    "-auth      optional\u{0b}    pam_gnome_keyring.so",
                    1,
                )
            } else {
                old.clone()
            };
            let dir = TestDir::new("old-include-restore-first");
            let etc = dir.0.join("ly");
            std::fs::write(&etc, &current).unwrap();
            // The backup the earlier release took, of the same flawed file.
            let flawed = if unreadable {
                stock.replacen(
                    "-auth      optional     pam_gnome_keyring.so",
                    "-auth      optional\u{0b}    pam_gnome_keyring.so",
                    1,
                )
            } else {
                stock.to_string()
            };
            std::fs::write(dir.0.join(format!("ly{BACKUP}")), &flawed).unwrap();
            for (name, text) in [
                ("login", ARCH_LOGIN),
                ("system-local-login", ARCH_SYSTEM_LOCAL_LOGIN),
            ] {
                std::fs::write(dir.0.join(name), text).unwrap();
            }
            let svc = Svc {
                etc: leak(&etc),
                vendor: None,
            };
            let wire = |c: &str| wire_greeter_impl(c, true, true, true);
            let on = wire_service(&svc, true, true, &wire).unwrap();
            assert_eq!(on.change, PlannedChange::RestoreBackup, "{on}");
            assert!(on.message.contains("no anchor to wire"), "{on}");
            assert_eq!(std::fs::read_to_string(&etc).unwrap(), flawed);
            assert!(!dir.0.join(format!("ly{BACKUP}")).exists());
        }
    }

    /// A remote-seat greeter an earlier release wired around an include
    /// whose stack starts with `pam_nologin.so`: the reseal-only recipe
    /// finds no anchor, and an enable would only take irlume's lines out,
    /// which is the greeter getting none of them; it is unwired whole, as
    /// ever, so the run warns about the keyring tokens that stops
    /// delivering, and the disable takes every irlume line out.
    #[test]
    fn a_remote_seat_greeter_with_no_anchor_is_unwired_whole() {
        let stock = "#%PAM-1.0\n\nauth       include      login\n\
                     -auth      optional     pam_gnome_keyring.so\n\
                     account    include      login\npassword   include      login\n\
                     session    include      login\n";
        let old = stock.replacen(
            "auth       include      login\n",
            &format!(
                "{GREETER_UNSEAL_COSMIC_JUMP}\nauth       include      login\n\
                 {PERMIT_LANDING}\n{KEYRING_UNSEAL}\n{RESEAL_AUTH}\n"
            ),
            1,
        );
        let dir = TestDir::new("old-include-remote");
        let etc = dir.0.join("ly");
        std::fs::write(&etc, &old).unwrap();
        for (name, text) in [
            ("login", ARCH_LOGIN),
            ("system-local-login", ARCH_SYSTEM_LOCAL_LOGIN),
        ] {
            std::fs::write(dir.0.join(name), text).unwrap();
        }
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let reseal_only = |c: &str| wire_greeter_impl(c, false, false, true);
        assert!(carries_face_lines(svc.etc));
        assert!(!greeter_want(&svc, true, true, &reseal_only));
        let off = wire_service(&svc, false, true, &reseal_only).unwrap();
        assert_eq!(off.change, PlannedChange::StripInPlace, "{off}");
        assert_eq!(std::fs::read_to_string(&etc).unwrap(), stock);
    }

    /// Reconcile stays quiet after a lost anchor, then can repair the greeter
    /// as soon as the included password stack offers a usable anchor again.
    /// A blocked LightDM with reseal-only lines must first be unwired when
    /// that anchor disappears.
    #[test]
    fn reconcile_tracks_reseal_only_anchor_loss_and_return() {
        let dir = TestDir::new("reconcile-reseal-anchor");
        let etc = dir.0.join("lightdm");
        let login = dir.0.join("login");
        std::fs::write(&etc, "auth include login\nsession include login\n").unwrap();
        std::fs::write(&login, "auth required pam_unix.so\n").unwrap();
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let reseal = |c: &str| wire_greeter_impl(c, false, false, true);
        let wired = wire_service(&svc, true, true, &reseal).unwrap();
        assert_eq!(wired.change, PlannedChange::Wire, "{wired}");
        assert!(!carries_face_lines(svc.etc));
        assert!(remote_seat_change_for(&svc, Some("remote seats".into())).is_none());

        std::fs::write(
            &login,
            "auth requisite pam_nologin.so\nauth required pam_unix.so\n",
        )
        .unwrap();
        assert!(matches!(
            remote_seat_change_for(&svc, Some("remote seats".into())),
            Some(RemoteSeat::Unwire)
        ));
        let off = wire_service(&svc, false, true, &reseal).unwrap();
        assert_eq!(off.change, PlannedChange::RestoreBackup, "{off}");
        assert!(!greeter_repairable(&svc, true, &reseal));
        assert!(!greeter_repairable(&svc, false, &reseal));
        std::fs::write(&login, "auth required pam_unix.so\n").unwrap();
        assert!(greeter_repairable(&svc, true, &reseal));
    }

    #[test]
    fn an_unestablished_capability_read_cannot_hide_a_missing_greeter() {
        assert!(missing_greeter_regressed(false, || {
            panic!("factor intent must not be read from transient capabilities")
        }));
        assert!(!missing_greeter_regressed(true, || false));
        assert!(missing_greeter_regressed(true, || true));
    }

    /// The token guard counts the no-anchor removal as dropping: a wanted
    /// surface whose lines an enable only takes out (#932) loses the
    /// `reseal` line a keyring token needs, exactly as an unwanted one
    /// does, so the run must refuse while a token is armed against it.
    #[test]
    fn the_token_guard_counts_a_no_anchor_removal_as_dropping() {
        let outcome = |change| WireOutcome {
            change,
            message: String::new(),
            detail: None,
            unmet: false,
            adjustable: false,
        };
        // Unwanted surfaces drop as ever, a remote-seat greeter apart.
        assert!(enable_drops(false, false, None));
        assert!(!enable_drops(false, true, None));
        // A wanted surface drops only when the enable's own decision says
        // its lines come out; wiring, keeping and skipping do not.
        for change in [
            PlannedChange::StripInPlace,
            PlannedChange::RestoreBackup,
            PlannedChange::RemoveOverride,
        ] {
            assert!(
                enable_drops(true, false, Some(&outcome(change))),
                "{change:?}"
            );
        }
        for change in [
            PlannedChange::Wire,
            PlannedChange::AlreadyCorrect,
            PlannedChange::NoAnchor,
            PlannedChange::NotWired,
            PlannedChange::KeepEditedOverride,
        ] {
            assert!(
                !enable_drops(true, false, Some(&outcome(change))),
                "{change:?}"
            );
        }
        assert!(!enable_drops(true, false, None));
        // The ly file itself: the enable's probe takes its lines out.
        let stock = "#%PAM-1.0\n\nauth       include      login\n\
                     -auth      optional     pam_gnome_keyring.so\n\
                     account    include      login\npassword   include      login\n\
                     session    include      login\n";
        let old = stock.replacen(
            "auth       include      login\n",
            &format!(
                "{GREETER_UNSEAL_COSMIC_JUMP}\nauth       include      login\n\
                 {PERMIT_LANDING}\n{KEYRING_UNSEAL}\n{RESEAL_AUTH}\n"
            ),
            1,
        );
        let dir = TestDir::new("old-include-guard");
        let etc = dir.0.join("ly");
        std::fs::write(&etc, &old).unwrap();
        for (name, text) in [
            ("login", ARCH_LOGIN),
            ("system-local-login", ARCH_SYSTEM_LOCAL_LOGIN),
        ] {
            std::fs::write(dir.0.join(name), text).unwrap();
        }
        let svc = Svc {
            etc: leak(&etc),
            vendor: None,
        };
        let wire = |c: &str| wire_greeter_impl(c, true, true, true);
        let probed = wire_service(&svc, true, false, &wire).unwrap();
        assert_eq!(probed.change, PlannedChange::StripInPlace, "{probed}");
        assert!(enable_drops(true, false, Some(&probed)));
    }

    /// The disable of a stack irlume edits in place with a line irlume does
    /// not read as PAM does reads the stacks its includes name where libpam
    /// finds them for that file: Arch's LightDM, which includes
    /// `system-login` above irlume's keyring and reseal lines, loses
    /// irlume's lines with every other byte kept, and is kept as it is when
    /// those stacks cannot be read.
    #[test]
    fn an_in_place_disable_reads_the_stacks_an_include_names() {
        let (wired, changed) = wire_greeter_impl(&fixture("arch", "lightdm"), true, true, true);
        assert!(changed);
        let typo = wired.replacen("#%PAM-1.0\n", "#%PAM-1.0\nauht optional pam_foo.so\n", 1);
        assert_ne!(typo, wired);
        for readable in [true, false] {
            let dir = TestDir::new("unread-include-disable");
            let etc = dir.0.join("lightdm");
            std::fs::write(&etc, &typo).unwrap();
            if readable {
                for name in ["system-login", "system-auth"] {
                    std::fs::write(dir.0.join(name), fixture("arch", name)).unwrap();
                }
            }
            let svc = Svc {
                etc: leak(&etc),
                vendor: None,
            };
            let off = wire_service(&svc, false, true, &|c: &str| {
                wire_greeter_impl(c, true, true, true)
            })
            .unwrap();
            let after = std::fs::read_to_string(&etc).unwrap();
            if readable {
                assert_eq!(off.change, PlannedChange::StripInPlace, "{off}");
                assert_eq!(after, without_irlume_lines(&typo));
                assert!(!holds_irlume_line(&after), "{after}");
            } else {
                assert_eq!(off.change, PlannedChange::KeepEditedOverride, "{off}");
                assert!(off.unmet, "{off}");
                assert_eq!(after, typo);
            }
        }
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

    /// Every upstream stack irlume pins is one irlume reads line by line as
    /// libpam does, so the refusal of [`unreadable_line`] changes nothing on
    /// them; every vendor fixture too.
    #[test]
    fn no_upstream_stack_has_a_line_irlume_does_not_read_as_pam_does() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pam");
        let mut stacks: Vec<(String, String)> = [
            ("plasmalogin fedora", UPSTREAM_FEDORA),
            ("plasmalogin arch", UPSTREAM_ARCH),
            ("plasmalogin debian", UPSTREAM_DEBIAN),
            ("plasmalogin suse", UPSTREAM_SUSE),
            ("gdm redhat", UPSTREAM_GDM_REDHAT),
            ("gdm arch", UPSTREAM_GDM_ARCH),
            ("gdm renamed", UPSTREAM_GDM_RENAMED_SUBSTACK),
            ("gdm fingerprint", UPSTREAM_GDM_FINGERPRINT),
        ]
        .iter()
        .map(|(name, body)| ((*name).to_string(), (*body).to_string()))
        .collect();
        for distro in std::fs::read_dir(&root).unwrap() {
            for file in std::fs::read_dir(distro.unwrap().path()).unwrap() {
                let path = file.unwrap().path();
                let body = std::fs::read_to_string(&path).unwrap();
                // Two captures (debian/login, fedora/postlogin) end in the
                // capture tool's own listing, from a `=====` line on, which
                // is not PAM text: only what comes before it is checked.
                let pam = body.split("\n=====").next().unwrap_or_default();
                stacks.push((path.display().to_string(), format!("{pam}\n")));
            }
        }
        assert!(stacks.len() > 8, "the fixtures are found");
        for (name, body) in &stacks {
            assert_eq!(unreadable_line(body), None, "{name}");
            for (label, (out, changed)) in [
                ("verify", wire_verify_service(body)),
                ("greeter", wire_greeter_impl(body, true, true, true)),
            ] {
                if changed {
                    assert_eq!(unreadable_line(&out), None, "{name} {label}\n{out}");
                }
            }
        }
    }

    /// The jumps of a control are the ones libpam's `_pam_parse_control`
    /// reads (linux-pam `libpam/pam_misc.c`): blanks before and after each
    /// `=`, no blank needed after an action or a jump, a later pair for the
    /// same value replacing an earlier one and `default` setting only the
    /// values no pair before it set. A control libpam rejects has no jump at
    /// all, every value being `bad`.
    #[test]
    fn a_control_is_parsed_as_libpam_parses_it() {
        let jumps = |control: &str| -> Vec<(String, usize)> {
            let line = format!("auth {control} pam_fprintd.so");
            let h = head(&line).expect("a head");
            numeric_actions(&h)
        };
        let one = |value: &str, n: usize| vec![(value.to_string(), n)];
        for (control, want) in [
            ("[success=1 default=ignore]", one("success", 1)),
            ("[success = 1 default=ignore]", one("success", 1)),
            ("[success =1 default = ignore]", one("success", 1)),
            ("[success=\t1 default=ignore]", one("success", 1)),
            ("[  success=1  ]", one("success", 1)),
            ("[success=1\u{b}default=ignore]", one("success", 1)),
            ("[success=1default=ignore]", one("success", 1)),
            ("[success=okdefault=2]", one("default", 2)),
            ("success=2", one("success", 2)),
            ("[default=1 success=ok]", one("default", 1)),
            ("[default=ignore success=1]", one("success", 1)),
            ("[success=01 default=ignore]", one("success", 1)),
            ("[default=1 default=2]", one("default", 1)),
            ("[success=2147483647]", one("success", 2_147_483_647)),
            (
                "[success=1 new_authtok_reqd=2 default=ignore]",
                vec![
                    ("success".to_string(), 1),
                    ("new_authtok_reqd".to_string(), 2),
                ],
            ),
            (
                "[authtok_expired=3 auth_err=4]",
                vec![
                    ("authtok_expired".to_string(), 3),
                    ("auth_err".to_string(), 4),
                ],
            ),
            // A later pair for the same value wins.
            ("[success=1 success=ok default=ignore]", vec![]),
            ("[success=ok success=3]", one("success", 3)),
            // Rejected by libpam: every value `bad`, no jump.
            ("[Success=1 default=ignore]", vec![]),
            ("[success=+1 default=ignore]", vec![]),
            ("[success=0 default=1]", vec![]),
            ("[success=2147483648 default=1]", vec![]),
            ("[success=1 default=ignore bogus=1]", vec![]),
            ("[success=1 default]", vec![]),
            ("[success=1 default=]", vec![]),
            ("[success 1]", vec![]),
            ("[success=1x default=2]", vec![]),
            ("[success=1\\] default=2]", vec![]),
            ("[success=1\u{a0}default=2]", vec![]),
            ("[success=1 pam_irlume.so default=2]", vec![]),
            // Keywords, read case-insensitively after the brackets come off.
            ("required", vec![]),
            ("[SUFFICIENT]", vec![]),
            ("Include", vec![]),
            ("[]", vec![]),
        ] {
            assert_eq!(jumps(control), want, "{control:?}");
        }
        // A line with no control is in its chain with every value `bad`.
        let lone = head("auth").expect("a head");
        assert_eq!((lone.phase, lone.control), ("auth", ""));
        assert!(numeric_actions(&lone).is_empty());
    }

    /// A line libpam installs in a chain counts there, whatever irlume's
    /// other tests make of it: a type libpam does not know puts the line in
    /// the auth chain, and a line with a type but no control is in its
    /// type's chain. Neither loads a module.
    #[test]
    fn every_line_libpam_installs_has_a_head() {
        for (line, phase) in [
            ("auht optional pam_foo.so", "auth"),
            ("sessoin [success=1 default=ignore] pam_foo.so", "auth"),
            ("\u{b}auth optional pam_foo.so", "auth"),
            ("\u{feff}auth optional pam_foo.so", "auth"),
            ("-[auth] optional pam_foo.so", "auth"),
            ("[] optional pam_foo.so", "auth"),
            ("-", "auth"),
            ("auth", "auth"),
            ("  -session", "session"),
            ("ACCOUNT [ ]", "account"),
            ("[-password] required pam_foo.so", "password"),
        ] {
            let h = head(line).unwrap_or_else(|| panic!("{line:?}"));
            assert_eq!(h.phase, phase, "{line:?}");
        }
        for line in [
            "auht optional pam_foo.so",
            "\u{b}auth optional pam_foo.so",
            "-[auth] optional pam_foo.so",
            "auth",
            "auth [success=1 default=ignore]",
        ] {
            assert!(rule(line).is_none(), "{line:?}");
        }
        assert!(rule("[-auth] optional pam_foo.so").is_some());
        for line in [
            "",
            "   ",
            "# auth optional x",
            "@include common-auth",
            "@INCLUDE x",
        ] {
            assert!(head(line).is_none(), "{line:?}");
        }
    }

    /// Debian's `@include` is a type field (its patch `031_pam_include`
    /// compares the type with `strcasecmp` after taking off the `-`), so it
    /// is read case-insensitively and must stand alone as a field; the file
    /// it names is the whole next field.
    #[test]
    fn a_debian_include_is_read_from_the_type_field() {
        for line in [
            "@include common-auth",
            "@INCLUDE common-auth",
            "-@include common-auth",
            "[@include] common-auth",
            " \t@include\tcommon-auth",
            "@include   common-auth   # note",
        ] {
            assert!(is_at_include(line), "{line:?}");
            assert!(is_include_auth_layout(line), "{line:?}");
        }
        // The file an `@include` names counts by its start, as it always
        // has: a site's own copy of the password stack is the password step
        // too, so irlume's keyring line never goes above it.
        for line in [
            "@include common-auth-local",
            "@include common-authx",
            "@include login-local",
            "@include logind",
        ] {
            assert!(is_include_auth_layout(line), "{line:?}");
            assert!(is_password_step(line), "{line:?}");
        }
        for line in [
            "@includecommon-auth",
            "# @include common-auth",
            "auth include common-auth-extra",
            "@include my-auth",
            "@include common-account",
        ] {
            assert!(!is_include_auth_layout(line), "{line:?}");
        }
        assert!(is_session_include("@include common-session"));
        assert!(is_session_include(
            "@include   common-session-noninteractive"
        ));
        assert!(!is_session_include("@include common-account"));
        assert!(!is_at_include("@includecommon-auth"));
        assert_eq!(at_include_target("@include   login"), Some("login"));
        assert_eq!(at_include_target("@include"), None);
    }

    /// The anchors irlume wires next to are read with libpam's field syntax:
    /// the type and the `include`/`substack` keyword case-insensitively and
    /// without brackets, and the stack as the third field, not any word of
    /// the line.
    #[test]
    fn anchor_lines_are_read_as_libpam_reads_them() {
        for line in [
            "auth substack password-auth",
            "AUTH SUBSTACK password-auth",
            "-auth [substack] password-auth",
            "[auth] include system-auth",
        ] {
            assert!(is_passwd_substack(line, "auth"), "{line}");
            assert!(is_password_step(line), "{line}");
        }
        for line in [
            "auth required pam_exec.so substack password-auth",
            "auth [success=1 default=ignore] pam_x.so include system-auth",
            "session substack password-auth",
            "auth substack password-auth-extra",
        ] {
            assert!(!is_passwd_substack(line, "auth"), "{line}");
        }
        assert!(is_passwd_substack(
            "Session Include password-auth",
            "session"
        ));
        assert!(is_auth_substack_anchor(
            "auth [SUBSTACK] gdm-password-auth-substack"
        ));
        assert!(!is_auth_substack_anchor(
            "auth required pam_exec.so substack"
        ));
        assert!(is_auth_directive("[auth] required pam_unix.so"));
        assert!(is_auth_directive("-AUTH optional pam_foo.so"));
        assert!(is_auth_directive("auth"));
        assert!(!is_auth_directive("auht required pam_unix.so"));
        assert!(!is_auth_directive("\u{a0}auth required pam_unix.so"));
        assert!(!is_auth_directive("@include common-auth"));
        assert!(is_include_auth_layout("auth INCLUDE system-auth"));
        assert!(is_include_auth_layout("-auth include system-login"));
        assert!(!is_include_auth_layout("auth include system-auth-extra"));
        assert!(is_fingerprint_auth("AUTH [substack] fingerprint-auth"));
        assert!(is_fingerprint_auth(
            "auth sufficient /usr/lib64/security/pam_fprintd.so"
        ));
        assert!(!is_fingerprint_auth(
            "auth optional pam_exec.so include /usr/bin/fingerprint-check"
        ));
        assert!(!is_fingerprint_auth("session optional pam_fprintd.so"));
        // The module is the module path, not an argument naming one.
        for line in [
            "auth optional pam_exec.so /usr/local/libexec/check-pam_fprintd.so",
            "[auth] optional pam_exec.so /usr/local/libexec/check-pam_fprintd.so",
            "auth substack password-auth fingerprint",
        ] {
            assert!(!is_fingerprint_auth(line), "{line}");
        }
        assert!(is_fingerprint_auth("[auth] sufficient pam_fprintd.so"));
        assert!(is_session_directive("-SESSION optional pam_kwallet5.so"));
        assert!(!is_session_directive("auth optional pam_kwallet5.so"));
    }

    /// The lines irlume does not read as libpam does, each named with its
    /// line number and why; everything else is read as libpam reads it.
    #[test]
    fn a_line_irlume_does_not_read_as_pam_does_is_named() {
        let stack = |line: &str| {
            format!("#%PAM-1.0\nauth [success=1 default=ignore] pam_x.so\n{line}\nauth substack password-auth\n")
        };
        for (line, why) in [
            (
                "auht optional pam_foo.so",
                Unread::UnknownType { names_stack: false },
            ),
            (
                "auht include password-auth",
                Unread::UnknownType { names_stack: true },
            ),
            (
                "auht substack password-auth",
                Unread::UnknownType { names_stack: true },
            ),
            ("\u{a0}auth optional pam_foo.so", Unread::Blank('\u{a0}')),
            ("\u{b}session optional pam_foo.so", Unread::Blank('\u{b}')),
            ("\u{c}auth optional pam_foo.so", Unread::Blank('\u{c}')),
            ("auth\u{b}optional pam_foo.so", Unread::Blank('\u{b}')),
            ("auth optional\rpam_foo.so", Unread::Blank('\r')),
            (
                "auth [success=1\u{2003}default=2] pam_foo.so",
                Unread::Blank('\u{2003}'),
            ),
            (
                "\u{feff}auth optional pam_foo.so",
                Unread::UnknownType { names_stack: false },
            ),
            (
                "-[auth] optional pam_foo.so",
                Unread::UnknownType { names_stack: false },
            ),
            (
                "sufficient pam_irlume.so",
                Unread::UnknownType { names_stack: false },
            ),
            ("auth optional pam_foo.so\0 # x", Unread::Nul),
            ("# a comment \0", Unread::Nul),
            ("@include", Unread::IncludeWithoutFile),
            ("auth substack", Unread::SubstackWithoutStack),
            ("auth optional .so", Unread::NoModuleName),
            ("auth optional /usr/lib64/security/", Unread::NoModuleName),
            ("auth optional ?.so", Unread::NoModuleName),
            ("auth substack .d", Unread::NoModuleName),
        ] {
            let text = stack(line);
            let found = unreadable_line(&text).unwrap_or_else(|| panic!("{line:?}"));
            assert_eq!(
                (found.number, found.text, found.why),
                (3, line, why),
                "{line:?}"
            );
        }
        for line in [
            "auth optional pam_foo.so",
            "AUTH [SUFFICIENT] [pam_foo.so]",
            "[-auth] optional pam_foo.so",
            "auth",
            "auth optional",
            "auth [success = 1 default=ignore] pam_foo.so",
            "auth include",
            "auth include no-such-stack",
            "@include common-auth",
            "auth optional pam_foo.so # a comment with \u{a0} in it",
            "auth optional pam_foo.so arg\u{1b}",
            "  \t  ",
            "",
        ] {
            assert_eq!(unreadable_line(&stack(line)), None, "{line:?}");
        }
        // libpam reads the carriage return of a CRLF ending as part of the
        // line's last field, and a blank CRLF line as a line whose type is
        // a carriage return: the first line PAM reads is named. One in a
        // comment is not read.
        for ending in ["\r\n", "\r\r\n"] {
            let crlf = stack("auth optional pam_foo.so").replace('\n', ending);
            let found = unreadable_line(&crlf).unwrap();
            assert_eq!((found.number, found.why), (2, Unread::CrlfEnding));
            assert!(found.text.ends_with('\r'), "{:?}", found.text);
        }
        let blank = "#%PAM-1.0\n\r\nauth required pam_unix.so\n";
        assert_eq!(
            unreadable_line(blank).map(|l| (l.number, l.why)),
            Some((2, Unread::CrlfEnding))
        );
        let in_comments = "#%PAM-1.0\r\n# note\r\nauth required pam_unix.so # x\r\n";
        assert_eq!(unreadable_line(in_comments), None);
        assert!(!has_read_carriage_return(in_comments));
        assert!(has_read_carriage_return(blank));
        // A continued file is `has_line_continuation`'s to report.
        let continued = stack("auth optional pam_foo.so \\\n  \u{b}arg");
        assert!(has_line_continuation(&continued));
        assert_eq!(unreadable_line(&continued), None);
    }

    /// Inside a bracketed control libpam keeps every byte up to the `]`
    /// (`_pam_tokenize`), and `_pam_parse_control` skips a vertical tab, form
    /// feed or carriage return (`isspace`) before a pair, around its `=` and
    /// between pairs, as a space: such a line is read as libpam reads it, the
    /// same as with spaces. Anywhere else libpam splits fields at spaces,
    /// tabs and newlines only, so the line is still named: between fields, in
    /// the type, the module path or its arguments, in a control written
    /// without brackets, never closed or rejected by libpam, and for a blank
    /// libpam does not skip (#931).
    #[test]
    fn a_blank_libpam_skips_inside_a_bracketed_control_is_read() {
        let stack = |line: &str| {
            format!("#%PAM-1.0\nauth [success=1 default=ignore] pam_x.so\n{line}\nauth substack password-auth\n")
        };
        for blank in ['\u{b}', '\u{c}', '\r'] {
            let b = blank.to_string();
            for (written, plain) in [
                (
                    format!("auth [success=1{b}default=ignore] pam_unix.so nullok"),
                    "auth [success=1 default=ignore] pam_unix.so nullok",
                ),
                (
                    format!("auth [success{b}={b}2{b}{b}default{b}={b}ignore] pam_unix.so"),
                    "auth [success = 2  default = ignore] pam_unix.so",
                ),
                (
                    format!("auth [{b}success=1 default=ignore{b}] pam_unix.so"),
                    "auth [ success=1 default=ignore ] pam_unix.so",
                ),
                (
                    format!("-auth [default=ignore{b}success=3] pam_fprintd.so"),
                    "-auth [default=ignore success=3] pam_fprintd.so",
                ),
                (
                    format!("auth [success=ok{b}new_authtok_reqd=ok{b}default=die] pam_unix.so"),
                    "auth [success=ok new_authtok_reqd=ok default=die] pam_unix.so",
                ),
                (format!("auth [{b}] pam_unix.so"), "auth [ ] pam_unix.so"),
            ] {
                assert_eq!(unreadable_line(&stack(&written)), None, "{written:?}");
                assert!(!has_read_carriage_return(&stack(&written)), "{written:?}");
                let (h, p) = (head(&written).unwrap(), head(plain).unwrap());
                assert_eq!(h.phase, p.phase, "{written:?}");
                assert_eq!(numeric_actions(&h), numeric_actions(&p), "{written:?}");
                let (r, q) = (rule(&written).unwrap(), rule(plain).unwrap());
                assert_eq!((r.module, &r.args), (q.module, &q.args), "{written:?}");
            }
            // A CRLF ending, a NUL byte and a blank libpam does not skip are
            // named as before, blanks inside the control or not.
            let crlf = format!("auth [success=1{b}default=ignore] pam_unix.so\r");
            assert_eq!(
                unreadable_line(&stack(&crlf)).map(|l| l.why),
                Some(Unread::CrlfEnding),
                "{crlf:?}"
            );
            let nul = format!("auth [success=1{b}default=ignore] pam_unix.so\0");
            assert_eq!(
                unreadable_line(&stack(&nul)).map(|l| l.why),
                Some(Unread::Nul),
                "{nul:?}"
            );
            for other in ['\u{a0}', '\u{2003}'] {
                let line = format!("auth [success=1{other}default=ignore{b}] pam_unix.so");
                assert_eq!(
                    unreadable_line(&stack(&line)).map(|l| l.why),
                    Some(Unread::Blank(other)),
                    "{line:?}"
                );
            }
            for line in [
                // Between fields.
                format!("auth{b}[success=1 default=ignore] pam_unix.so"),
                format!("auth [success=1 default=ignore]{b}pam_unix.so"),
                format!("auth [success=1 default=ignore] pam_unix.so{b}nullok"),
                format!("auth [success=1{b}default=ignore]{b} pam_unix.so"),
                // In the type, the module path and an argument.
                format!("{b}auth [success=1 default=ignore] pam_unix.so"),
                format!("au{b}th [success=1 default=ignore] pam_unix.so"),
                format!("[auth{b}] [success=1{b}default=ignore] pam_unix.so"),
                format!("auth [success=1{b}default=ignore] [pam_unix.so{b}]"),
                format!("auth [success=1 default=ignore] pam_unix.so [a{b}b]"),
                format!("auth [success=1{b}default=ignore] pam_unix.so null{b}ok"),
                // A stack an include names, and Debian's `@include`.
                format!("auth [include] [password{b}auth]"),
                format!("@include [common{b}auth]"),
                // A control without brackets, one never closed, and one
                // libpam rejects (a keyword is not one with a blank in it).
                format!("auth success=1{b}default=ignore pam_unix.so"),
                format!("auth [success=1{b}default=ignore pam_unix.so"),
                format!("auth [success=1{b}default=ignore"),
                format!("auth [required{b}] pam_unix.so"),
                format!("auth [success=1{b}bogus=2] pam_unix.so"),
                format!("auth [success=1{b}default=ignore\\]] pam_unix.so"),
            ] {
                assert_eq!(
                    unreadable_line(&stack(&line)).map(|l| (l.number, l.why)),
                    Some((3, Unread::Blank(blank))),
                    "{line:?}"
                );
                assert_eq!(
                    has_read_carriage_return(&stack(&line)),
                    blank == '\r',
                    "{line:?}"
                );
            }
        }
        // In a continued file a line may be the rest of the one before it,
        // with no control of its own: a carriage return anywhere in what
        // PAM reads is named.
        let continued = "#%PAM-1.0\nauth optional pam_foo.so \\\n  x\nauth [success=1\rdefault=ignore] pam_unix.so\n";
        assert!(has_line_continuation(continued));
        assert_eq!(unreadable_line(continued), None);
        assert_eq!(
            carriage_return_line(continued).map(|l| (l.number, l.why)),
            Some((4, Unread::Blank('\r')))
        );
        // A stack wired through such a control is wired as with spaces.
        let body = |control: &str| {
            format!(
                "#%PAM-1.0\nauth [{control}] pam_env.so\nauth include system-auth\n\
                 account include system-auth\n"
            )
        };
        let plain = wire_verify_service(&body("success=ok default=ignore"));
        assert!(plain.1, "{}", plain.0);
        for blank in ['\u{b}', '\u{c}', '\r'] {
            let control = format!("success=ok{blank}default=ignore");
            let wired = wire_verify_service(&body(&control));
            assert_eq!(
                wired,
                (plain.0.replace("success=ok default=ignore", &control), true),
                "{blank:?}"
            );
        }
    }

    /// Only spaces and tabs lead a line away from its type, as in libpam's
    /// `_pam_str_trim`; any other blank stays, and libpam reads it as part
    /// of the type.
    #[test]
    fn directive_skips_only_spaces_and_tabs() {
        assert_eq!(directive(" \t auth required x # c"), "auth required x ");
        assert_eq!(directive("\u{b}auth required x"), "\u{b}auth required x");
        assert_eq!(directive("\u{a0}# c"), "\u{a0}");
    }

    /// A keyring module is the rule's module path, never an argument: a
    /// `pam_exec.so` line that names one loads only pam_exec, so it neither
    /// counts as a consumer nor hides the pair irlume supplies, and a
    /// fingerprint keyring line goes below the real pam_fprintd line, not a
    /// line that only names it.
    #[test]
    fn a_module_named_in_an_argument_is_not_that_module() {
        for line in [
            "auth optional pam_exec.so /usr/local/libexec/pam_gnome_keyring.so",
            "[auth] optional pam_exec.so /usr/local/libexec/pam_gnome_keyring.so",
            "[session] optional pam_exec.so /usr/local/libexec/pam_gnome_keyring.so",
        ] {
            assert_eq!(consumer_active_for(line, "gdm-fingerprint"), None, "{line}");
        }
        let stack = "#%PAM-1.0\n\
                     [auth] optional pam_exec.so /usr/local/libexec/check-pam_fprintd.so\n\
                     auth sufficient pam_fprintd.so\n\
                     [auth] optional pam_exec.so /usr/local/libexec/pam_gnome_keyring.so\n\
                     [session] optional pam_exec.so /usr/local/libexec/pam_gnome_keyring.so\n";
        let (wired, changed) = wire_fp_keyring(stack, "gdm-fingerprint");
        assert!(changed, "{wired}");
        let lines: Vec<&str> = wired.lines().collect();
        let fprintd = lines
            .iter()
            .position(|l| *l == "auth sufficient pam_fprintd.so")
            .unwrap();
        let keyring = lines
            .iter()
            .position(|l| irlume_rule_has_arg(l, "keyring"))
            .unwrap();
        assert!(keyring > fprintd, "{wired}");
        assert!(wired.contains(FP_GKR_SESSION), "{wired}");
        // A session line that loads kwallet and names gnome-keyring in its
        // arguments is no gnome-keyring session line.
        let handoff = format!(
            "{KEYRING_UNSEAL}\nauth optional pam_gnome_keyring.so\n\
             session optional pam_kwallet5.so note=pam_gnome_keyring.so\n"
        );
        let found = keyring_handoff(&handoff, "plasmalogin").unwrap();
        assert_eq!(found.complete, None);
        assert_eq!(found.auth_only, vec!["pam_gnome_keyring.so"]);
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
            Some((&wired, None)),
            Some((&polkit_ok, None)),
            &[&wired]
        ));
        // Each surface on its own must trigger a repair.
        assert!(surfaces_regressed(Some((&stripped, None)), None, &[]));
        // sudo is materialized from a vendor copy where the distribution
        // ships one only there (openSUSE Tumbleweed), so it follows polkit:
        // deleted with the vendor copy still present is a regression, deleted
        // with none is not ours to restore.
        assert!(surfaces_regressed(Some((&gone, Some(&vendor))), None, &[]));
        assert!(!surfaces_regressed(Some((&gone, None)), None, &[]));
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
        // screen, then sudo and polkit, in that order. Pinned through the
        // testable seam (KDE fallback): the live status_report() reads the
        // host filesystem and would pick a different lock surface on
        // Omarchy or Cinnamon, breaking the exact-label assertion.
        let rows = report::status_report_for(false, false);
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
        // The TUI's login state is exactly "any row but sudo and polkit is
        // wired", read from the same facts as the rows.
        let any_login = rows[..rows.len() - 2].iter().any(|(_, _, w)| *w);
        assert_eq!(login_wired_by_mode(), any_login);
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
        write_wired_marker(
            true,
            &WiredMarker {
                sudo: false,
                polkit: true,
                lock: false,
                face_lock_intent: false,
            },
        );
        assert_eq!(
            read_wired_marker(),
            Some(WiredMarker {
                sudo: false,
                polkit: true,
                lock: false,
                face_lock_intent: false,
            })
        );
        // Re-enable with both flags + the lock screen overwrites cleanly.
        write_wired_marker(
            true,
            &WiredMarker {
                sudo: true,
                polkit: true,
                lock: true,
                face_lock_intent: false,
            },
        );
        assert_eq!(
            read_wired_marker(),
            Some(WiredMarker {
                sudo: true,
                polkit: true,
                lock: true,
                face_lock_intent: false,
            })
        );
        // A marker written before with_lock existed (only the two flags) reads
        // back with lock=false, so it never triggers a false lock regression.
        irlume_common::write_0600(&wired_marker_path(), b"with_sudo=true\nwith_polkit=false\n")
            .unwrap();
        assert_eq!(
            read_wired_marker(),
            Some(WiredMarker {
                sudo: true,
                polkit: false,
                lock: false,
                face_lock_intent: false,
            })
        );
        // Disable clears the marker so the self-heal service stays quiet.
        write_wired_marker(false, &WiredMarker::default());
        assert_eq!(read_wired_marker(), None);
        match old {
            Some(v) => std::env::set_var("IRLUME_STATE_DIR", v),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
    }

    /// `login reconcile` changes nothing on NixOS, so a self-heal marker there
    /// (an older reconcile adopted the module's lines into one) never offers
    /// that repair, whatever the marker claims.
    #[test]
    fn reconcile_is_never_needed_on_nixos() {
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = TestDir::new("reconcile-nixos");
        let old: Vec<_> = ["IRLUME_STATE_DIR", crate::os_release::OS_RELEASE_ENV]
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect();
        std::env::set_var("IRLUME_STATE_DIR", &dir.0);
        let os_release = dir.0.join("os-release");
        std::fs::write(&os_release, "NAME=NixOS\nID=nixos\n").unwrap();
        std::env::set_var(crate::os_release::OS_RELEASE_ENV, &os_release);
        write_wired_marker(
            true,
            &WiredMarker {
                sudo: true,
                polkit: true,
                lock: true,
                face_lock_intent: true,
            },
        );
        let needed = reconcile_needed();
        for (key, value) in old {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        assert!(!needed);
    }

    // ---- #607: yield the stock Omarchy lock lane to the dedicated lane ----

    #[test]
    fn omarchy_dedicated_lane_yields_only_when_both_facts_hold() {
        assert!(!stock_lane_yielded_for(false, false));
        assert!(
            !stock_lane_yielded_for(false, true),
            "a non-Omarchy host never yields"
        );
        assert!(
            !stock_lane_yielded_for(true, false),
            "no dedicated lane, nothing to yield to"
        );
        assert!(stock_lane_yielded_for(true, true));
    }

    /// The effective lock want and the recorded yield intent are complements:
    /// exactly one of them is true whenever face-on-lock was wanted, and the
    /// intent can never survive into a state where the wiring also happened.
    #[test]
    fn the_effective_lock_want_and_the_yield_intent_partition_face_lock() {
        for face_lock in [false, true] {
            for omarchy in [false, true] {
                for lane in [false, true] {
                    let yielded = stock_lane_yielded_for(omarchy, lane);
                    let effective = face_lock && !yielded;
                    let intent = marker_face_lock_intent_for(face_lock, yielded);
                    assert!(
                        !(effective && intent),
                        "wired and yielded at once: face_lock={face_lock} omarchy={omarchy} lane={lane}"
                    );
                    assert_eq!(
                        effective || intent,
                        face_lock,
                        "face_lock={face_lock} omarchy={omarchy} lane={lane}"
                    );
                }
            }
        }
    }

    #[test]
    fn wired_marker_round_trips_face_lock_intent_and_defaults_false() {
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = TestDir::new("wired-marker-intent");
        let old = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_STATE_DIR", &dir.0);
        // An enable that wanted face-on-lock but yielded to the dedicated lane
        // records the intent, with the observed lock still false.
        write_wired_marker(
            true,
            &WiredMarker {
                sudo: false,
                polkit: false,
                lock: false,
                face_lock_intent: true,
            },
        );
        assert_eq!(
            read_wired_marker(),
            Some(WiredMarker {
                sudo: false,
                polkit: false,
                lock: false,
                face_lock_intent: true,
            })
        );
        // A marker written before #607 (no intent line) reads intent=false, so
        // an old marker can never trigger a reclaim on its own.
        irlume_common::write_0600(
            &wired_marker_path(),
            b"with_sudo=true\nwith_polkit=false\nwith_lock=true\n",
        )
        .unwrap();
        assert_eq!(
            read_wired_marker(),
            Some(WiredMarker {
                sudo: true,
                polkit: false,
                lock: true,
                face_lock_intent: false,
            })
        );
        match old {
            Some(v) => std::env::set_var("IRLUME_STATE_DIR", v),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
    }

    /// The reclaim is the exact posted read: marker present (the caller's
    /// context), intent recorded, omarchy, dedicated lane gone, stock lane not
    /// wired. Every missing fact must veto it.
    #[test]
    fn reclaim_needs_every_condition_of_the_posted_read() {
        assert!(lane_reclaim_for(true, true, false, false));
        assert!(
            !lane_reclaim_for(false, true, false, false),
            "no recorded intent, no reclaim"
        );
        assert!(!lane_reclaim_for(true, false, false, false), "not omarchy");
        assert!(
            !lane_reclaim_for(true, true, true, false),
            "the dedicated lane still exists"
        );
        assert!(
            !lane_reclaim_for(true, true, false, true),
            "the stock lane is already wired"
        );
    }

    /// The reverse direction: the dedicated lane APPEARED while our face line
    /// sits in the stock lane. Only a lane we maintain, for a face want that
    /// still holds, on omarchy, with something to remove.
    #[test]
    fn yield_on_lane_appear_needs_our_wire_and_a_live_face_want() {
        assert!(lane_yield_for(true, true, true, true, || true));
        assert!(
            !lane_yield_for(false, true, true, true, || true),
            "not omarchy"
        );
        assert!(
            !lane_yield_for(true, false, true, true, || true),
            "no dedicated lane"
        );
        assert!(
            !lane_yield_for(true, true, false, true, || true),
            "stock lane not wired: nothing to yield"
        );
        assert!(
            !lane_yield_for(true, true, true, false, || true),
            "the marker never said the lock was ours"
        );
        assert!(
            !lane_yield_for(true, true, true, true, || false),
            "face-on-lock is no longer wanted"
        );
        // Laziness is part of the contract: the want probe must never run when
        // the cheap facts already decided (production points it at the daemon).
        let mut probed = false;
        assert!(!lane_yield_for(true, true, true, false, || {
            probed = true;
            true
        }));
        assert!(!probed, "the want probe ran although with_lock=false");
    }

    /// The path unit must watch both Omarchy lanes so setup and removal reach
    /// reconcile without waiting for the timer backstop. Pinned from the repo
    /// because nothing else keeps the unit's list honest against the surfaces.
    #[test]
    fn reconcile_path_unit_watches_both_omarchy_lanes() {
        let unit = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packaging/systemd/irlume-reconcile.path"
        ))
        .expect("the unit file ships in the repo");
        assert!(
            unit.contains("PathModified=/etc/pam.d/omarchy-lock-face"),
            "setup of the dedicated lane must wake reconcile"
        );
        assert!(
            unit.contains("PathModified=/etc/pam.d/omarchy-lock-password"),
            "removal of the dedicated lane must wake reconcile"
        );
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

        restore_surface(&file, Some("the original\n"), None, None).expect("restore");
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
            assert!(
                files::is_managed_path_for(false, false, managed),
                "{managed} must be restorable"
            );
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
            assert!(
                !files::is_managed_path_for(false, false, stray),
                "{stray} must NOT be restorable"
            );
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
        restore_surface(
            &file,
            Some("the original\n"),
            Some((0o640, meta.1, meta.2)),
            None,
        )
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

        restore_surface(&file, None, None, None).expect("restore");
        assert!(!file.exists(), "the file must be gone, not empty");

        // Restoring an already-absent file is not an error: a rollback that
        // partly ran and is run again must be able to finish.
        restore_surface(&file, None, None, None).expect("restoring an absent file is fine");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wire_service_override_materialize_idempotent_then_remove() {
        let dir = TestDir::new("wsvc-override");
        ship_fedora_stacks(&dir.0);
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
        // This test exercises backup/idempotence, not jumps inside Fedora's
        // shared session stack; supply a readable carrier without those jumps.
        std::fs::write(
            dir.0.join("password-auth"),
            "auth required pam_unix.so\nsession required pam_unix.so\n",
        )
        .unwrap();
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

        inspect_target(&etc).expect_err("a symlink is refused");
        let rec = apply_surface(
            &Svc {
                etc: leak(&etc),
                vendor: None,
            },
            ROLE_SUDO,
            &wire_verify_service,
            true,
            false,
            &[],
        );
        assert!(rec.error.is_some(), "with the reason it was refused");
        assert!(
            std::fs::symlink_metadata(&etc).unwrap().is_symlink(),
            "and touched nothing"
        );
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

    // ---- distro-PAM layout matrix (2026-08-30 survey) ----------------------
    //
    // The fixtures under tests/fixtures/pam/<distro>/ are the REAL shipped
    // service files, extracted from each family's container image with the
    // display managers installed (see docs/research/2026-08-30-distro-pam-
    // matrix.md for provenance). The survey question: does the wiring recipe
    // place its line on every dialect a user can actually meet?

    pub(super) fn fixture(distro: &str, service: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pam")
            .join(distro)
            .join(service);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// The include dialects (Debian @include, Arch include system-*) take the
    /// `sufficient` line; the substack dialects (Fedora password-auth,
    /// openSUSE common-auth) are atomic for jump counting and take the
    /// [success=1] jump stanza. Both must WIRE, not no-op, on every family's
    /// real file.
    #[test]
    fn the_wiring_recipe_wires_every_real_distro_dialect() {
        let expect_sufficient = ["arch", "debian"];
        let expect_jump = ["fedora", "fedora-45", "opensuse"];
        // Fedora 45 adds GDM 51's gdm-password, whose password substack is
        // renamed to gdm-password-auth-substack.
        let dialects = ["arch", "debian", "fedora", "opensuse"]
            .map(|distro| (distro, &["sddm", "gdm-password", "lightdm"][..]))
            .into_iter()
            .chain([("fedora-45", &["gdm-password"][..])]);
        for (distro, services) in dialects {
            for &service in services {
                let stock = fixture(distro, service);
                // The reader sees the shared files the distro ships beside
                // this service; a missing one is a different, failing stack.
                let stacks = match distro {
                    "arch" => {
                        let login = fixture("arch", "system-login");
                        let local = fixture("arch", "system-local-login");
                        let auth = fixture("arch", "system-auth");
                        stacks_of(&[
                            ("system-login", &login),
                            ("system-local-login", &local),
                            ("system-auth", &auth),
                        ])
                    }
                    "debian" => {
                        let auth = fixture("debian", "common-auth");
                        stacks_of(&[
                            ("common-auth", &auth),
                            ("common-account", "account required pam_unix.so\n"),
                        ])
                    }
                    "fedora" | "fedora-45" => stacks_of(&[
                        ("password-auth", FEDORA_PASSWORD_AUTH),
                        ("system-auth", FEDORA_PASSWORD_AUTH),
                        ("gdm-password-auth-substack", FEDORA_PASSWORD_AUTH),
                        ("postlogin", FEDORA_POSTLOGIN),
                    ]),
                    "opensuse" => {
                        let auth = fixture("opensuse", "common-auth");
                        stacks_of(&[
                            ("common-auth", &auth),
                            ("xdm", OPENSUSE_XDM),
                            ("postlogin-auth", OPENSUSE_POSTLOGIN_AUTH),
                        ])
                    }
                    _ => unreachable!(),
                };
                let (wired, changed) =
                    with_stack_reader(stacks, || wire_greeter_impl(&stock, true, true, false));
                assert!(
                    changed,
                    "{distro}/{service}: the recipe refused to wire the real shipped file"
                );
                assert!(
                    wired.contains("pam_irlume.so"),
                    "{distro}/{service}: the module must land in the stack"
                );
                // The original auth carrier line survives below our line.
                let carrier = ["include", "substack", "@include"]
                    .iter()
                    .find(|k| stock.contains(&format!(" {k} ")))
                    .or_else(|| {
                        ["@include", "include", "substack"]
                            .iter()
                            .find(|k| stock.contains(*k))
                    });
                if let Some(kind) = carrier {
                    assert!(
                        wired.contains(kind),
                        "{distro}/{service}: the original {kind} line must survive"
                    );
                }
                let got_sufficient = wired.contains("sufficient   pam_irlume.so unseal")
                    || wired.contains("sufficient pam_irlume.so unseal");
                let got_jump = wired.contains("success=1 default=ignore");
                // openSUSE's lightdm includes xdm as its first auth line:
                // libpam inlines xdm's lines there, and the jump skips the
                // first of them, xdm's password substack.
                if expect_sufficient.contains(&distro) {
                    assert!(
                        got_sufficient && !got_jump,
                        "{distro}/{service}: the include dialect takes the sufficient line"
                    );
                } else if expect_jump.contains(&distro) {
                    assert!(
                        got_jump && !got_sufficient,
                        "{distro}/{service}: the substack dialect takes the jump stanza"
                    );
                }
                // Idempotence on the real files too: a second pass changes
                // nothing.
                let (_, again) = wire_greeter_impl(&wired, true, true, false);
                assert!(!again, "{distro}/{service}: rewiring must be a no-op");
            }
        }
    }
}
