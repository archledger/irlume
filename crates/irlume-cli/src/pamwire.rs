//! `irlume login <status|enable|disable>` — wire face auth into the login
//! greeters (GDM/SDDM/LightDM/plasmalogin), the KDE lock screen, and (opt-in)
//! sudo. The Rust replacement for scripts/deploy-keyring-unlock.sh. Ported from
//! linhello's pamwire framework, adapted to irlume's keyring-unlock greeter
//! BLOCK (unseal + a pam_permit landing for the success=1 jump + a reseal
//! self-heal) and the `wait` lock stanza.
//!
//! FAIL-SAFE: every face line is `[success=1 default=ignore]` or `sufficient`,
//! so the password is always the floor — wiring cannot lock the user out.
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

// Greeter block (mirrors scripts/deploy-keyring-unlock.sh exactly).
const GREETER_UNSEAL: &str = "auth       [success=1 default=ignore]   pam_irlume.so unseal";
/// The Debian/Ubuntu greeter face line, for the `@include common-auth` layout
/// (a `success=N` jump can't skip an include expansion, so this can't be the
/// jump form). `continue_ctrl` picks the control:
///   * true → `[success=ok default=ignore]`: the face line UNSEALS (sets
///     PAM_AUTHTOK) and the stack CONTINUES, so pam_unix authenticates with the
///     released password AND pam_gnome_keyring unlocks the login keyring. Valid
///     only when the tier unseals (Secure) AND the DM's locker tolerates a
///     continue (per [`DmProfile`] — GDM yes, cosmic no). A bare `sufficient`
///     short-circuits before the keyring module (Debian/GDM keyring gap; the
///     Fedora success=1 layout continues past the jump, so its keyring unlocks).
///   * false → `sufficient` (short-circuit): the Convenience tier (verify only,
///     no token — else pam_unix would re-prompt), cosmic (locker needs the
///     short-circuit), and separate lock services (keyring already open).
/// `mode` is `facefirst` (GDM scan-immediately) or `ondemand` (empty-Enter).
fn debian_greeter_line(continue_ctrl: bool, mode: &str) -> String {
    let ctrl = if continue_ctrl { "[success=ok default=ignore]" } else { "sufficient" };
    format!("auth       {ctrl}   pam_irlume.so unseal {mode}")
}
/// Jump-style variant for a non-`@include` (e.g. Fedora) COSMIC stack.
const GREETER_UNSEAL_COSMIC_JUMP: &str = "auth       [success=1 default=ignore]   pam_irlume.so unseal ondemand";
// Tagged so unwire strips OUR landing but never a foreign pam_permit.so the
// stack legitimately carries (the trailing `#…` is a PAM comment, ignored).
const PERMIT_LANDING: &str = "auth       optional                     pam_permit.so   # irlume-landing";
const RESEAL_AUTH: &str = "auth       optional                     pam_irlume.so reseal";
/// Post-auth login-keyring unlock for the FINGERPRINT path: runs after a trusted
/// factor succeeded; if no password is present (fingerprint login) it unseals
/// the TPM-sealed password and sets PAM_AUTHTOK so pam_gnome_keyring opens the
/// wallet. No-op when the keyring isn't armed or a password is already set.
const KEYRING_UNSEAL: &str = "auth       optional                     pam_irlume.so keyring";
const RESEAL_SESSION: &str = "session    optional                     pam_irlume.so reseal";
const SUDO_STANZA: &str = "auth       sufficient                   pam_irlume.so";

/// A PAM service to wire. `vendor=Some` → materialize an /etc override from the
/// vendor copy; `vendor=None` → back up and edit the real /etc file.
struct Svc {
    etc: &'static str,
    vendor: Option<&'static str>,
}

const GREETERS: &[Svc] = &[
    Svc { etc: "/etc/pam.d/gdm-password", vendor: None }, // GNOME / GDM
    Svc { etc: "/etc/pam.d/sddm", vendor: None },
    Svc { etc: "/etc/pam.d/lightdm", vendor: None },
    Svc { etc: "/etc/pam.d/plasmalogin", vendor: Some("/usr/lib/pam.d/plasmalogin") }, // Plasma 6
    Svc { etc: "/etc/pam.d/cosmic-greeter", vendor: None }, // COSMIC (Pop!_OS / System76)
];
// KDE lock: wire the submit-driven `kde` password service with the on-demand
// face block, NOT KDE's ambient `kde-fingerprint` parallel-biometric slot — so
// face engages only on an empty-field Enter (never continuously scanning). The
// `kde` service classifies as ScreenUnlock, so `ondemand` verifies identity and
// releases no credential.
const LOCKSCREEN: Svc = Svc { etc: "/etc/pam.d/kde", vendor: None };
/// GDM uses a SEPARATE PAM service for fingerprint logins (`gdm-fingerprint`),
/// distinct from `gdm-password` (password/face). It runs pam_fprintd then
/// pam_gnome_keyring — which finds no password and leaves the wallet locked. We
/// slot the `keyring` unseal line between them (ADR-0003) so a fingerprint login
/// opens the wallet. Only present on GNOME/GDM systems; skipped elsewhere.
const FP_GREETERS: &[Svc] = &[
    Svc { etc: "/etc/pam.d/gdm-fingerprint", vendor: None },
];
const SUDO: &str = "/etc/pam.d/sudo";

// ---- CLI entry ---------------------------------------------------------------

pub fn run(action: Option<&str>, args: &[String]) -> ExitCode {
    let apply = args.iter().any(|a| a == "--apply");
    let with_sudo = args.iter().any(|a| a == "--with-sudo");
    match action {
        None | Some("status") => status(),
        Some("enable") => act(true, apply, with_sudo),
        Some("disable") => act(false, apply, with_sudo),
        _ => {
            eprintln!("usage: irlume login <status|enable|disable> [--with-sudo] [--apply]");
            eprintln!("  (without --apply, prints what it WOULD change — a dry run)");
            ExitCode::from(2)
        }
    }
}

/// Structured wiring status for the TUI: `(label, present, wired)` per service
/// plus a trailing SELinux row. Mirrors what `status()` prints.
pub(crate) fn status_report() -> Vec<(String, bool, bool)> {
    let mut out = Vec::new();
    for s in GREETERS.iter().chain(FP_GREETERS.iter()).chain(std::iter::once(&LOCKSCREEN)) {
        match service_present(s) {
            Some(p) => out.push((label_of(s.etc), true, file_has_module(&p))),
            None => out.push((label_of(s.etc), false, false)),
        }
    }
    let sudo = Path::new(SUDO);
    out.push(("sudo".into(), sudo.exists(), sudo.exists() && file_has_module(sudo)));
    out
}

/// True when any greeter or the lock screen carries the irlume wiring — the
/// "is face login actually wired" probe for the TUI dashboard (sudo excluded:
/// face-sudo alone doesn't make the login screen work).
pub(crate) fn login_wired() -> bool {
    for s in GREETERS.iter().chain(FP_GREETERS.iter()).chain(std::iter::once(&LOCKSCREEN)) {
        if let Some(p) = service_present(s) {
            if file_has_module(&p) {
                return true;
            }
        }
    }
    false
}

/// Short label from an /etc/pam.d path (e.g. "/etc/pam.d/gdm-password" → "gdm-password").
fn label_of(etc: &str) -> String {
    etc.rsplit('/').next().unwrap_or(etc).to_string()
}

/// The active login manager, from the `display-manager.service` symlink
/// (`gdm`, `gdm3`, `sddm`, `lightdm`, `greetd`, `ly`, …). None on a
/// non-graphical / greeter-less host.
fn active_display_manager() -> Option<String> {
    std::fs::read_link("/etc/systemd/system/display-manager.service")
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
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
    let out = std::process::Command::new("gnome-shell").arg("--version").output().ok()?;
    if !out.status.success() { return None; }
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
    /// Login-manager family, for diagnostics.
    dm: &'static str,
    /// Face engages on an empty-field Enter (`ondemand`) vs GDM's
    /// scan-immediately (`facefirst`). For GDM this is gated by GNOME version.
    ondemand: bool,
    /// Whether this DM's LOCKER tolerates a continue-style face line
    /// (`[success=ok default=ignore]`, which lets the login keyring unlock after
    /// a COLD face login). gnome-shell/GDM: yes (validated — keyring unlocks).
    /// cosmic-greeter's locker: NO — it needs the face line to short-circuit, so
    /// COSMIC uses a bare `sufficient` and its cold-login keyring stays a
    /// follow-up (would need context-aware module return codes to resolve the
    /// one-service-does-login-and-lock tension). Login-only greeters (KDE/SDDM,
    /// whose lock is a SEPARATE service) also accept a continue on their cold line.
    keyring_continue_ok: bool,
}

/// Resolve the [`DmProfile`] for a greeter PAM service path. `gnome` is the
/// detected GNOME Shell major (for GDM's version gate).
fn dm_profile(greeter_etc: &str, gnome: Option<u32>) -> DmProfile {
    match greeter_etc.rsplit('/').next().unwrap_or("") {
        // COSMIC (System76 / Pop!_OS): answers the probe on submit (ondemand),
        // but its locker can't handle a continue → short-circuit.
        "cosmic-greeter" => DmProfile { dm: "COSMIC", ondemand: true, keyring_continue_ok: false },
        // GDM (GNOME): modern gnome-shell submits the empty field (ondemand) and
        // its locker handles a continue (keyring unlocks on cold login); older
        // gnome-shell blocked the probe → facefirst.
        "gdm-password" => DmProfile { dm: "GDM", ondemand: gdm_uses_ondemand(gnome), keyring_continue_ok: true },
        // SDDM / plasmalogin / lightdm / …: submit-driven login greeters whose
        // lock is a SEPARATE service, so their cold-login line may continue.
        _ => DmProfile { dm: "generic", ondemand: false, keyring_continue_ok: true },
    }
}

/// The PAM services THIS login manager actually uses, so wiring targets what the
/// DM will really consult (and, crucially, its separate FINGERPRINT service).
/// Returns `(greeter_label, fingerprint_label_or_none)`.
fn dm_pam_services(dm: &str) -> (&'static str, Option<&'static str>) {
    match dm {
        // GDM drives the password/face path and a SEPARATE fingerprint service.
        "gdm" | "gdm3" => ("gdm-password", Some("gdm-fingerprint")),
        // SDDM / Plasma: one greeter; KDE's fingerprint is the lock screen
        // (kde-fingerprint), wired separately as the lock service.
        "sddm" => ("sddm", None),
        // Plasma 6 renamed the SDDM greeter service to `plasmalogin`; the
        // display-manager.service symlink resolves to it. Same shape as SDDM:
        // one greeter, KDE's fingerprint lives on the lock screen (kde-fingerprint).
        "plasmalogin" => ("plasmalogin", None),
        "lightdm" => ("lightdm", None),
        "greetd" => ("greetd", None),
        "ly" => ("ly", None),
        // COSMIC (System76 / Pop!_OS): cosmic-greeter drives BOTH the cold login
        // and the live lock screen through the SAME `cosmic-greeter` PAM service;
        // the warm/cold flag in biopolicy::classify distinguishes them. No
        // separate fingerprint service.
        "cosmic-greeter" => ("cosmic-greeter", None),
        _ => ("(unknown)", None),
    }
}

/// SELinux module load state for the TUI (None = can't tell without root).
pub(crate) fn selinux_state() -> Option<bool> {
    selinux_loaded()
}

/// True when the fingerprint keyring-unlock (`keyring`) line is present in EVERY
/// login service the active login manager consults that exists — for GDM that is
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
    for s in GREETERS.iter().chain(FP_GREETERS.iter()).chain(std::iter::once(&LOCKSCREEN)) {
        if let Some(present) = service_present(s) {
            let wired = file_has_module(&present);
            any |= wired;
            println!("  {:<34} {}", present.display(), if wired { "● wired" } else { "○ not wired" });
        }
    }
    if Path::new(SUDO).exists() {
        let wired = file_has_module(Path::new(SUDO));
        println!("  {:<34} {}", SUDO, if wired { "● wired (sudo)" } else { "○ not wired (sudo)" });
    }
    println!("[login] SELinux module: {}", match selinux_loaded() {
        Some(true) => "loaded",
        Some(false) => "not loaded",
        None => "unknown (run as root to check)",
    });
    if !any {
        println!("  → enable with:  sudo irlume login enable --apply   (add --with-sudo for face-sudo)");
    }
    ExitCode::SUCCESS
}

fn act(enable: bool, apply: bool, with_sudo: bool) -> ExitCode {
    if apply && effective_uid() != 0 {
        eprintln!("[login] applying changes needs root — run: sudo irlume login {} --apply", if enable { "enable" } else { "disable" });
        return ExitCode::FAILURE;
    }
    if !apply {
        println!("[login] DRY RUN — showing what `--apply` would change (nothing is written):");
    }
    // Method + tier aware plan: wire exactly what the chosen method needs on
    // this hardware, and (on enable) UNWIRE what it doesn't — so switching method
    // re-configures cleanly instead of leaving stale lines. `want_*` gate each
    // factor; on disable everything is unwired.
    let caps = irlume_camera::capabilities();
    let method = irlume_core::policy::method();
    let is_fp_method = method.face_disabled(); // Method::Fingerprint
    let is_face_method = matches!(method, irlume_core::policy::Method::Face);
    let fp_ready = irlume_fingerprint::available();
    // Face releases the login credential only on the Secure (IR) tier; face
    // verifies the lock screen on any camera; fingerprint drives the keyring
    // unlock. `Auto` follows the hardware; an explicit method overrides.
    let want_face_login = caps.ir_pair && !is_fp_method;
    let want_face_lock = caps.rgb && !is_fp_method;
    let want_fp_keyring = fp_ready && !is_face_method;
    if enable {
        match active_display_manager() {
            Some(dm) => println!("  login manager: {dm}   ·   method: {}   ·   {}",
                method.as_str(),
                if caps.ir_pair { "IR/Secure tier" } else if caps.rgb { "RGB/Convenience tier" } else { "no camera" }),
            None => println!("  no active login manager (headless?)   ·   method: {}", method.as_str()),
        }
        let onoff = |b: bool| if b { "on" } else { "—" };
        println!("  plan → face login: {}   face lock: {}   fingerprint keyring: {}",
            onoff(want_face_login), onoff(want_face_lock), onoff(want_fp_keyring));
        if caps.rgb && !caps.ir_pair && !is_fp_method {
            println!("  (RGB-only: face satisfies the LOCK SCREEN only; login/sudo keep the password)");
        }
    }
    let mut errs = 0;
    let mut do_svc = |s: &Svc, wire: &dyn Fn(&str) -> (String, bool), want: bool| {
        // On enable, wire wanted factors and unwire unwanted ones; on disable,
        // unwire everything (want is ANDed with `enable`).
        match wire_service(s, enable && want, apply, wire) {
            Ok(msg) => println!("  {msg}"),
            Err(e) => { eprintln!("  ✗ {e}"); errs += 1; }
        }
    };
    // Greeters (gdm-password etc.) carry the FACE lines (only Secure-tier face
    // login) AND the KEYRING line (fingerprint keyring unlock) — independent, so
    // an RGB+fingerprint box gets keyring-only here, while GDM's session keyring
    // unlock (which runs through gdm-password) still finds the password.
    let gnome = gnome_shell_major();
    for s in GREETERS {
        // DM-aware: apply the wiring this login manager's greeter + locker want.
        let prof = dm_profile(s.etc, gnome);
        // cosmic-greeter and gdm-password each drive BOTH the cold login and the
        // live lock screen through ONE service, so they carry the face line
        // whenever face login OR face lock is wanted — an RGB (convenience) box
        // still gets face LOCK there (a cold login on that tier stays denied by
        // the daemon's credential-release gate).
        let unified_login_lock = s.etc.ends_with("/cosmic-greeter") || s.etc.ends_with("/gdm-password");
        let face = want_face_login || (unified_login_lock && want_face_lock);
        // Continue-control (so the login keyring unlocks on a cold face login)
        // only when the tier UNSEALS (Secure — the face line sets a token) AND
        // the DM's locker tolerates a continue (per profile: GDM yes, cosmic no).
        let continue_ctrl = caps.ir_pair && prof.keyring_continue_ok;
        let greeter_wire = |c: &str| wire_greeter_impl(c, face, want_fp_keyring, prof.ondemand, continue_ctrl);
        do_svc(s, &greeter_wire, face || want_fp_keyring);
    }
    for s in FP_GREETERS {
        do_svc(s, &wire_fp_keyring, want_fp_keyring);
    }
    // A separate lock service (KDE `kde`) is a WARM screen unlock — the login
    // keyring is already open, so the face line should SHORT-CIRCUIT (no
    // continue-control needed, and it avoids a cosmic-style locker mismatch on a
    // Debian layout). The Fedora substack path uses the success=1 jump regardless.
    let lock_wire = |c: &str| wire_lock(c, false);
    do_svc(&LOCKSCREEN, &lock_wire, want_face_lock);
    // face-sudo is opt-in on enable (--with-sudo), but disable must ALWAYS
    // unwire it — "disable --apply undoes everything" is a documented promise,
    // and a stale sudo line would point at a module the user may remove next.
    if with_sudo || !enable {
        match wire_service(&Svc { etc: SUDO, vendor: None }, enable, apply, &wire_sudo) {
            Ok(msg) => println!("  {msg}"),
            Err(e) => { eprintln!("  ✗ {e}"); errs += 1; }
        }
    }
    // SELinux (Fedora): the confined GDM/greeter needs the policy to reach the socket.
    if matches!(distro_family(), DistroFamily::Fedora) {
        match selinux(enable, apply) {
            Ok(msg) => println!("  {msg}"),
            Err(e) => { eprintln!("  ✗ {e}"); errs += 1; }
        }
    }
    if !apply {
        println!("[login] re-run with --apply (as root) to perform these changes.");
    } else if errs == 0 {
        println!("[login] done. Password remains the fallback everywhere.");
    }
    if errs == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// Wire (or unwire) one service, choosing override-materialize vs edit-in-place.
fn wire_service(s: &Svc, enable: bool, apply: bool, wire: &dyn Fn(&str) -> (String, bool)) -> Result<String, String> {
    let etc = Path::new(s.etc);
    // vendor-only service with no admin /etc copy → override strategy.
    let use_override = s.vendor.is_some() && (!etc.exists() || file_is_created_override(etc));
    if enable {
        // RECONCILE, don't skip-if-present: re-wire always rebuilds the desired
        // line set from the ORIGINAL stack (the vendor copy / the backup) so a
        // method switch — which changes which lines are wanted — actually takes
        // effect instead of being a silent no-op when any pam_irlume line exists.
        if use_override {
            let vendor = s.vendor.unwrap();
            if !Path::new(vendor).exists() {
                return Ok(format!("· {} — not installed (skipped)", s.etc));
            }
            let (base, _) = unwire_lines(&read(vendor)?);
            let (wired, _) = wire(&base);
            let body = format!("{CREATED_PREFIX}{vendor} — delete this file to restore the vendor copy\n{wired}");
            if etc.exists() && read(s.etc).ok().as_deref() == Some(body.as_str()) {
                return Ok(format!("· {} — already correctly wired", s.etc));
            }
            if apply { write_atomic(etc, &body)?; }
            Ok(format!("✓ {} — materialized override from {vendor}", s.etc))
        } else {
            if !etc.exists() {
                return Ok(format!("· {} — not installed (skipped)", s.etc));
            }
            let current = read(s.etc)?;
            // Rebuild from the pristine stock: the backup if we've wired before,
            // else the current file — then strip any irlume lines and re-apply.
            let bak = PathBuf::from(format!("{}{BACKUP}", s.etc));
            let origin = if bak.exists() { read(&bak.to_string_lossy())? } else { current.clone() };
            let (base, _) = unwire_lines(&origin);
            let (wired, changed) = wire(&base);
            if !changed {
                return Ok(format!("· {} — no anchor to wire (skipped)", s.etc));
            }
            if wired == current {
                return Ok(format!("· {} — already correctly wired", s.etc));
            }
            if apply { backup(etc)?; write_atomic(etc, &wired)?; }
            Ok(format!("✓ {} — wired (backup {}{})", s.etc, s.etc, BACKUP))
        }
    } else {
        // disable / unwire
        if use_override && etc.exists() && file_is_created_override(etc) {
            if apply { std::fs::remove_file(etc).map_err(|e| format!("rm {}: {e}", s.etc))?; }
            Ok(format!("✓ {} — removed override (vendor restored)", s.etc))
        } else if !use_override && etc.exists() {
            let bak = PathBuf::from(format!("{}{BACKUP}", s.etc));
            if bak.exists() {
                // Restore the backup ONLY when it equals the current file minus
                // our lines — i.e. nothing else changed since we wired. If an
                // admin (or another package) edited the file after wiring,
                // restoring the stale snapshot would silently revert their
                // change (e.g. a faillock line added to sudo): strip in place
                // instead and keep the backup for inspection.
                let (stripped, _) = unwire_lines(&read(s.etc)?);
                let bak_content = read(&bak.to_string_lossy())?;
                if stripped == bak_content {
                    if apply { std::fs::rename(&bak, etc).map_err(|e| format!("restore {}: {e}", s.etc))?; }
                    Ok(format!("✓ {} — restored from backup", s.etc))
                } else {
                    if apply { write_atomic(etc, &stripped)?; }
                    Ok(format!("✓ {} — stripped irlume lines (file changed since wiring; backup kept at {}{})", s.etc, s.etc, BACKUP))
                }
            } else if file_has_module(etc) {
                let (clean, _) = unwire_lines(&read(s.etc)?);
                if apply { write_atomic(etc, &clean)?; }
                Ok(format!("✓ {} — stripped irlume lines", s.etc))
            } else {
                Ok(format!("· {} — not wired", s.etc))
            }
        } else {
            Ok(format!("· {} — not wired", s.etc))
        }
    }
}

// ---- pure PAM-text mechanics (unit-tested) -----------------------------------

fn content_has_module(c: &str) -> bool {
    c.lines().any(|l| { let t = l.trim_start(); !t.starts_with('#') && t.contains(MODULE) })
}

/// `<kind>` is `auth`/`session`; matches a `(substack|include) (password-auth|
/// system-auth)` line — the shared substack the success=1 jump skips.
fn is_passwd_substack(line: &str, kind: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with('#') { return false; }
    let toks: Vec<&str> = t.strip_prefix('-').unwrap_or(t).split_whitespace().collect();
    toks.first() == Some(&kind)
        && toks.iter().any(|w| *w == "substack" || *w == "include")
        && toks.iter().any(|w| *w == "password-auth" || *w == "system-auth")
}

fn is_auth_directive(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with('#') { return false; }
    t.strip_prefix('-').unwrap_or(t).split_whitespace().next() == Some("auth")
}

/// Insert irlume's greeter block: `unseal` before the password substack, a
/// `pam_permit` landing + `reseal` after it, and a `session reseal` after the
/// session substack. Idempotent; falls back to the first `auth` line if there's
/// no password substack.
/// Wire a display-manager greeter. `face` adds the face-first login lines
/// (Secure-tier credential release); `keyring` adds the post-auth keyring-unseal
/// line (fingerprint keyring unlock — needed in gdm-password too, since GDM's
/// SESSION keyring unlock runs through gdm-password even on a fingerprint login).
/// Reseal (self-heal of the sealed password) rides along whenever either is set.
fn wire_greeter_impl(content: &str, face: bool, keyring: bool, ondemand: bool, continue_ctrl: bool) -> (String, bool) {
    if !face && !keyring { return (content.to_string(), false); }
    if content_has_module(content) { return (content.to_string(), false); }
    let lines: Vec<&str> = content.lines().collect();
    // Debian/Ubuntu layout: face-first `sufficient` before `@include common-auth`
    // (password path); keyring-unseal after it (runs on any auth success — incl.
    // a fingerprint via common-auth's pam_fprintd).
    if let Some(inc_at) = lines.iter().position(|l| l.trim_start().starts_with("@include common-auth")) {
        let mut out = Vec::with_capacity(lines.len() + 4);
        for (i, l) in lines.iter().enumerate() {
            if i == inc_at {
                if face { out.push(debian_greeter_line(continue_ctrl, if ondemand { "ondemand" } else { "facefirst" })); }
                out.push((*l).to_string());
                if keyring { out.push(KEYRING_UNSEAL.to_string()); }
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
    let auth_at = lines.iter().position(|l| is_passwd_substack(l, "auth"))
        .or_else(|| lines.iter().position(|l| is_auth_directive(l)));
    let sess_at = lines.iter().position(|l| is_passwd_substack(l, "session"));
    let Some(auth_at) = auth_at else { return (content.to_string(), false); };
    let mut out = Vec::with_capacity(lines.len() + 5);
    for (i, l) in lines.iter().enumerate() {
        if i == auth_at {
            if face {
                out.push(if ondemand { GREETER_UNSEAL_COSMIC_JUMP } else { GREETER_UNSEAL }.to_string());
                out.push((*l).to_string());
                out.push(PERMIT_LANDING.to_string());
            } else {
                out.push((*l).to_string());
            }
            if keyring { out.push(KEYRING_UNSEAL.to_string()); }
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

fn wire_single(content: &str, stanza: &str) -> (String, bool) {
    if content_has_module(content) { return (content.to_string(), false); }
    let mut out = Vec::new();
    let mut done = false;
    for l in content.lines() {
        if !done && is_auth_directive(l) {
            out.push(stanza.to_string());
            done = true;
        }
        out.push(l.to_string());
    }
    if !done { out.push(stanza.to_string()); }
    (format!("{}\n", out.join("\n")), true)
}

/// Wire the KDE lock (`kde`) with the consent-driven on-demand face block: face
/// engages only on an empty-field Enter, verifies identity for the unlock, and
/// otherwise falls through to the password. Same `ondemand` mode as
/// cosmic-greeter, applied to KDE's submit-driven lock service. No reseal (a
/// screen unlock releases no credential). Handles both the Debian `@include`
/// and the Fedora `substack` layouts.
fn wire_lock(content: &str, continue_ctrl: bool) -> (String, bool) {
    if content_has_module(content) { return (content.to_string(), false); }
    let lines: Vec<&str> = content.lines().collect();
    // Debian `@include common-auth` layout → face-first `sufficient` before it.
    if let Some(inc_at) = lines.iter().position(|l| l.trim_start().starts_with("@include common-auth")) {
        let mut out = Vec::with_capacity(lines.len() + 1);
        for (i, l) in lines.iter().enumerate() {
            if i == inc_at { out.push(debian_greeter_line(continue_ctrl, "ondemand")); }
            out.push((*l).to_string());
        }
        return (format!("{}\n", out.join("\n")), true);
    }
    // Fedora `substack password-auth` layout → jump stanza + permit landing.
    let auth_at = lines.iter().position(|l| is_passwd_substack(l, "auth"))
        .or_else(|| lines.iter().position(|l| is_auth_directive(l)));
    let Some(auth_at) = auth_at else { return (content.to_string(), false); };
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
    let Some(fp_at) = fp_at else { return (content.to_string(), false); };
    let mut out = Vec::with_capacity(lines.len() + 1);
    for (i, l) in lines.iter().enumerate() {
        out.push((*l).to_string());
        if i == fp_at {
            out.push(KEYRING_UNSEAL.to_string());
        }
    }
    (format!("{}\n", out.join("\n")), true)
}
fn wire_sudo(content: &str) -> (String, bool) { wire_single(content, SUDO_STANZA) }

/// Remove every irlume line AND the pam_permit landing we added (used only when
/// no backup exists — the backup-restore path is preferred).
fn unwire_lines(content: &str) -> (String, bool) {
    // Strip every pam_irlume line, plus ONLY the pam_permit landing WE tagged
    // (`# irlume-landing`) — never a foreign pam_permit.so.
    let mut changed = false;
    let kept: Vec<&str> = content.lines().filter(|l| {
        let t = l.trim_start();
        if t.starts_with('#') { return true; }
        let drop = t.contains(MODULE)
            || (t.contains("pam_permit.so") && l.contains("# irlume-landing"));
        if drop { changed = true; }
        !drop
    }).collect();
    (format!("{}\n", kept.join("\n")), changed)
}

// ---- file ops ----------------------------------------------------------------

fn read(p: &str) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("read {p}: {e}"))
}
fn file_has_module(p: &Path) -> bool {
    std::fs::read_to_string(p).map(|c| content_has_module(&c)).unwrap_or(false)
}
fn file_is_created_override(p: &Path) -> bool {
    std::fs::read_to_string(p).map(|c| c.starts_with(CREATED_PREFIX)).unwrap_or(false)
}
fn service_present(s: &Svc) -> Option<PathBuf> {
    if Path::new(s.etc).exists() { return Some(PathBuf::from(s.etc)); }
    s.vendor.filter(|v| Path::new(v).exists()).map(|_| PathBuf::from(s.etc))
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
    std::fs::rename(&tmp, path).map_err(|e| { let _ = std::fs::remove_file(&tmp); format!("rename into {}: {e}", path.display()) })
}

// ---- SELinux (Fedora) --------------------------------------------------------

/// `Some(true/false)` when semodule could be queried (root), `None` otherwise.
fn selinux_loaded() -> Option<bool> {
    let out = Command::new("semodule").arg("-l").output().ok()?;
    if !out.status.success() {
        return None; // needs root to read the policy store
    }
    Some(String::from_utf8_lossy(&out.stdout).lines().any(|l| l.split_whitespace().next() == Some("irlume")))
}
/// Locate the compiled SELinux policy module. Packaged installs ship it under
/// /usr/share/irlume/selinux; an env override and the in-repo build dir cover
/// dev/source builds. (The old hardcoded developer home path never existed on a
/// user's machine, so the module silently never loaded.)
fn selinux_pp() -> Option<String> {
    if let Some(p) = std::env::var_os("IRLUME_SELINUX_PP") {
        let p = p.to_string_lossy().into_owned();
        if Path::new(&p).exists() { return Some(p); }
    }
    for p in [
        "/usr/share/irlume/selinux/irlume.pp",
        "/usr/lib/irlume/selinux/irlume.pp",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/selinux/irlume.pp"),
    ] {
        if Path::new(p).exists() { return Some(p.to_string()); }
    }
    None
}

fn selinux(enable: bool, apply: bool) -> Result<String, String> {
    if enable {
        if selinux_loaded() == Some(true) { return Ok("· SELinux module already loaded".into()); }
        let Some(pp) = selinux_pp() else {
            return Ok("· SELinux: irlume.pp not found (install the selinux subpackage) — skipped".into());
        };
        if apply {
            let ok = Command::new("semodule").args(["-i", pp.as_str()]).status().map(|s| s.success()).unwrap_or(false);
            if !ok { return Err("semodule -i irlume.pp failed".into()); }
            // The already-bound socket keeps its pre-policy label — the greeter
            // stays blocked until the daemon rebinds. Restart it now so face
            // login works at the very next lock/login, not the next reboot;
            // restorecon (backed by the irlume.fc entry) settles the label even
            // if the bind raced the policy commit.
            let _ = Command::new("systemctl").args(["try-restart", "irlumed.service"]).status();
            let _ = Command::new("restorecon").arg("/run/irlume.sock").status();
            Ok("✓ SELinux module loaded (daemon restarted to relabel its socket)".into())
        } else {
            Ok("→ would load the SELinux module (greeter→daemon socket)".into())
        }
    } else {
        if selinux_loaded() == Some(false) { return Ok("· SELinux module not loaded".into()); }
        if apply {
            let _ = Command::new("semodule").args(["-r", "irlume"]).status();
            Ok("✓ SELinux module removed".into())
        } else {
            Ok("→ would remove the SELinux module (if loaded)".into())
        }
    }
}

fn effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status").ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:").map(|v| v.split_whitespace().nth(1).unwrap_or("1000").to_string())))
        .and_then(|v| v.parse().ok()).unwrap_or(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fedora gdm-password layout (real /etc file, the GDM greeter).
    const GDM: &str = "#%PAM-1.0\nauth     [success=done ...] pam_selinux_permit.so\nauth     substack      password-auth\nauth     optional      pam_gnome_keyring.so\naccount  include       password-auth\nsession  include       password-auth\nsession  optional      pam_gnome_keyring.so auto_start\n";

    #[test]
    fn greeter_block_wraps_password_substack() {
        let (w, changed) = wire_greeter_impl(GDM, true, true, false, true);
        assert!(changed);
        let lines: Vec<&str> = w.lines().collect();
        let unseal = lines.iter().position(|l| l.contains("unseal")).unwrap();
        let substack = lines.iter().position(|l| l.contains("auth     substack      password-auth")).unwrap();
        let permit = lines.iter().position(|l| l.contains("pam_permit.so")).unwrap();
        let reseal_auth = lines.iter().position(|l| l.contains("auth") && l.contains("reseal")).unwrap();
        // unseal BEFORE substack; permit + reseal AFTER it.
        assert!(unseal < substack && substack < permit && permit < reseal_auth);
        // session reseal present after the session substack.
        assert!(lines.iter().any(|l| l.starts_with("session") && l.contains("reseal")));
    }

    // Debian/Ubuntu cosmic-greeter layout (@include-based; one service drives
    // both the login and the lock screen).
    const COSMIC: &str = "#%PAM-1.0\nauth    requisite    pam_nologin.so\n@include common-auth\nauth    optional    pam_gnome_keyring.so\n@include common-account\n@include common-session\n@include common-password\n";

    #[test]
    fn cosmic_greeter_wires_ondemand_not_facefirst() {
        // ondemand=true → on-demand probe line (face only on empty-Enter), placed
        // before the password include so the password stays a fallback.
        let (w, changed) = wire_greeter_impl(COSMIC, true, false, true, true);
        assert!(changed);
        assert!(w.contains("pam_irlume.so unseal ondemand"));
        assert!(!w.contains("facefirst"));
        let lines: Vec<&str> = w.lines().collect();
        let unseal = lines.iter().position(|l| l.contains("unseal ondemand")).unwrap();
        let inc = lines.iter().position(|l| l.trim_start().starts_with("@include common-auth")).unwrap();
        assert!(unseal < inc);
        // A non-cosmic Debian greeter (ondemand=false) still gets facefirst.
        let (g, _) = wire_greeter_impl(COSMIC, true, false, false, true);
        assert!(g.contains("facefirst") && !g.contains("ondemand"));
    }

    #[test]
    fn dm_profile_tailors_per_login_manager() {
        // COSMIC: ondemand, but its locker can't continue → no keyring-continue
        // (short-circuit), which is what fixes the cosmic lock regression.
        let cosmic = dm_profile("/etc/pam.d/cosmic-greeter", Some(50));
        assert!(cosmic.ondemand && !cosmic.keyring_continue_ok);
        // GDM: locker handles continue (keyring unlocks on cold login); ondemand
        // is version-gated.
        let gdm = dm_profile("/etc/pam.d/gdm-password", Some(50));
        assert!(gdm.ondemand && gdm.keyring_continue_ok);
        assert!(!dm_profile("/etc/pam.d/gdm-password", Some(3)).ondemand); // old GNOME → facefirst
        assert!(!dm_profile("/etc/pam.d/gdm-password", None).ondemand);    // undetected → facefirst
        // generic login-only greeters (separate lock): facefirst, continue OK.
        let sddm = dm_profile("/etc/pam.d/sddm", None);
        assert!(!sddm.ondemand && sddm.keyring_continue_ok);
    }

    #[test]
    fn debian_greeter_control_is_tier_aware() {
        // Secure (IR) tier: unseal sets the token, so CONTINUE past the include
        // (`[success=ok default=ignore]`) — pam_unix + pam_gnome_keyring run, so
        // the keyring unlocks after a face login. Convenience (RGB): verify only,
        // so short-circuit (`sufficient`) or pam_unix would re-prompt.
        let secure = debian_greeter_line(true, "ondemand");
        assert!(secure.contains("[success=ok default=ignore]"));
        assert!(!secure.contains("sufficient"));
        assert!(secure.contains("pam_irlume.so unseal ondemand"));
        let conv = debian_greeter_line(false, "facefirst");
        assert!(conv.contains("sufficient"));
        assert!(conv.contains("pam_irlume.so unseal facefirst"));
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
        let (w1, _) = wire_greeter_impl(GDM, true, true, false, true);
        let (w2, changed) = wire_greeter_impl(&w1, true, true, false, true);
        assert!(!changed);
        assert_eq!(w1, w2);
    }

    #[test]
    fn method_switch_reconciles_the_line_set() {
        // face-only → (strip) → keyring-only must actually change the lines
        // (the method-switch case the old skip-if-present logic silently no-op'd).
        let (face_only, _) = wire_greeter_impl(GDM, true, false, false, true);
        assert!(face_only.contains("pam_irlume.so unseal") && !face_only.contains("pam_irlume.so keyring"));
        let (base, stripped) = unwire_lines(&face_only);
        assert!(stripped && !base.contains(MODULE));
        let (keyring_only, _) = wire_greeter_impl(&base, false, true, false, true);
        assert!(keyring_only.contains("pam_irlume.so keyring") && !keyring_only.contains("pam_irlume.so unseal"));
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
        let (w, c) = wire_single(base, SUDO_STANZA);
        assert!(c && content_has_module(&w));
        let (back, changed) = unwire_lines(&w);
        assert!(changed && !content_has_module(&back));
    }

    // Fedora KDE lock service `kde` (substack layout), the real file we validated.
    const KDE_LOCK: &str = "auth        substack      password-auth\nauth        include       postlogin\naccount     required      pam_nologin.so\npassword    include       password-auth\nsession     required      pam_selinux.so close\n";

    #[test]
    fn kde_lock_is_ondemand_not_ambient_wait() {
        let (w, changed) = wire_lock(KDE_LOCK, false);
        assert!(changed);
        // consent-driven on-demand, never the ambient `wait` mode, no reseal.
        assert!(w.contains("pam_irlume.so unseal ondemand"));
        assert!(!w.contains("pam_irlume.so wait"));
        assert!(!w.contains("reseal"));
        // face-first before the password substack, with the permit landing.
        let lines: Vec<&str> = w.lines().collect();
        let face = lines.iter().position(|l| l.contains("unseal ondemand")).unwrap();
        let substack = lines.iter().position(|l| l.contains("substack      password-auth")).unwrap();
        assert!(face < substack);
        assert!(w.contains("pam_permit.so") && w.contains("irlume-landing"));
        // fully reversible.
        let (back, undone) = unwire_lines(&w);
        assert!(undone && !content_has_module(&back));
    }

    #[test]
    fn passwd_substack_matcher() {
        assert!(is_passwd_substack("auth     substack      password-auth", "auth"));
        assert!(is_passwd_substack("auth  include system-auth", "auth"));
        assert!(is_passwd_substack("session include password-auth", "session"));
        assert!(!is_passwd_substack("auth required pam_unix.so", "auth"));
        assert!(!is_passwd_substack("# auth substack password-auth", "auth"));
    }
}
