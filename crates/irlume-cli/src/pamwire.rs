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
/// Debian-family greeters (Ubuntu gdm-password): the stack is `@include`-based —
/// a `success=N` jump cannot skip an include expansion — and GDM's conversation
/// blocks on an active password probe, so wire a face-first `sufficient` line
/// directly before the password include instead.
const GREETER_UNSEAL_DEBIAN: &str = "auth       sufficient                   pam_irlume.so unseal facefirst";
const PERMIT_LANDING: &str = "auth       optional                     pam_permit.so";
const RESEAL_AUTH: &str = "auth       optional                     pam_irlume.so reseal";
const RESEAL_SESSION: &str = "session    optional                     pam_irlume.so reseal";
const LOCK_WAIT: &str = "auth       sufficient                   pam_irlume.so wait";
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
];
const LOCKSCREEN: Svc = Svc { etc: "/etc/pam.d/kde-fingerprint", vendor: Some("/usr/lib/pam.d/kde-fingerprint") };
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
    for s in GREETERS.iter().chain(std::iter::once(&LOCKSCREEN)) {
        match service_present(s) {
            Some(p) => out.push((label_of(s.etc), true, file_has_module(&p))),
            None => out.push((label_of(s.etc), false, false)),
        }
    }
    let sudo = Path::new(SUDO);
    out.push(("sudo".into(), sudo.exists(), sudo.exists() && file_has_module(sudo)));
    out
}

/// Short label from an /etc/pam.d path (e.g. "/etc/pam.d/gdm-password" → "gdm-password").
fn label_of(etc: &str) -> String {
    etc.rsplit('/').next().unwrap_or(etc).to_string()
}

/// SELinux module load state for the TUI (None = can't tell without root).
pub(crate) fn selinux_state() -> Option<bool> {
    selinux_loaded()
}

fn status() -> ExitCode {
    println!("[login] wiring status (face auth in PAM):");
    let mut any = false;
    for s in GREETERS.iter().chain(std::iter::once(&LOCKSCREEN)) {
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
    if enable {
        let caps = irlume_camera::capabilities();
        if !caps.rgb && !caps.ir_pair {
            println!("  ⚠ no camera detected on this device — face auth will fall through to the password until one is present");
        } else if !caps.ir_pair {
            println!("  ⚠ RGB-only camera — convenience tier: face satisfies the LOCK SCREEN only; login/sudo keep the password");
        }
    }
    let mut errs = 0;
    let mut do_svc = |s: &Svc, wire: fn(&str) -> (String, bool)| {
        match wire_service(s, enable, apply, wire) {
            Ok(msg) => println!("  {msg}"),
            Err(e) => { eprintln!("  ✗ {e}"); errs += 1; }
        }
    };
    for s in GREETERS {
        do_svc(s, wire_greeter);
    }
    do_svc(&LOCKSCREEN, wire_lock);
    if with_sudo {
        match wire_service(&Svc { etc: SUDO, vendor: None }, enable, apply, wire_sudo) {
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
fn wire_service(s: &Svc, enable: bool, apply: bool, wire: fn(&str) -> (String, bool)) -> Result<String, String> {
    let etc = Path::new(s.etc);
    // vendor-only service with no admin /etc copy → override strategy.
    let use_override = s.vendor.is_some() && (!etc.exists() || file_is_created_override(etc));
    if enable {
        if use_override {
            let vendor = s.vendor.unwrap();
            if !Path::new(vendor).exists() {
                return Ok(format!("· {} — not installed (skipped)", s.etc));
            }
            let vc = read(vendor)?;
            if file_has_module(etc) {
                return Ok(format!("· {} — already wired", s.etc));
            }
            let (wired, _) = wire(&vc);
            let body = format!("{CREATED_PREFIX}{vendor} — delete this file to restore the vendor copy\n{wired}");
            if apply { write_atomic(etc, &body)?; }
            Ok(format!("✓ {} — materialized override from {vendor}", s.etc))
        } else {
            if !etc.exists() {
                return Ok(format!("· {} — not installed (skipped)", s.etc));
            }
            let c = read(s.etc)?;
            if file_has_module(etc) {
                return Ok(format!("· {} — already wired", s.etc));
            }
            let (wired, changed) = wire(&c);
            if !changed {
                return Ok(format!("· {} — no anchor to wire (skipped)", s.etc));
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
                if apply { std::fs::rename(&bak, etc).map_err(|e| format!("restore {}: {e}", s.etc))?; }
                Ok(format!("✓ {} — restored from backup", s.etc))
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
fn wire_greeter(content: &str) -> (String, bool) {
    if content_has_module(content) { return (content.to_string(), false); }
    let lines: Vec<&str> = content.lines().collect();
    // Debian/Ubuntu layout: place a face-first `sufficient` line right before
    // `@include common-auth` (password path). nologin/succeed_if above us still
    // run; on face success the stack is satisfied; otherwise the password flows
    // exactly as stock. Reseal stash goes after the include (post-password).
    if let Some(inc_at) = lines.iter().position(|l| l.trim_start().starts_with("@include common-auth")) {
        let mut out = Vec::with_capacity(lines.len() + 3);
        for (i, l) in lines.iter().enumerate() {
            if i == inc_at {
                out.push(GREETER_UNSEAL_DEBIAN.to_string());
                out.push((*l).to_string());
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
    let mut out = Vec::with_capacity(lines.len() + 4);
    for (i, l) in lines.iter().enumerate() {
        if i == auth_at {
            out.push(GREETER_UNSEAL.to_string());
            out.push((*l).to_string());
            out.push(PERMIT_LANDING.to_string());
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

fn wire_lock(content: &str) -> (String, bool) { wire_single(content, LOCK_WAIT) }
fn wire_sudo(content: &str) -> (String, bool) { wire_single(content, SUDO_STANZA) }

/// Remove every irlume line AND the pam_permit landing we added (used only when
/// no backup exists — the backup-restore path is preferred).
fn unwire_lines(content: &str) -> (String, bool) {
    let mut changed = false;
    let kept: Vec<&str> = content.lines().filter(|l| {
        let t = l.trim_start();
        let drop = !t.starts_with('#') && (t.contains(MODULE) || t.contains("pam_permit.so"));
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
fn selinux(enable: bool, apply: bool) -> Result<String, String> {
    let pp = "/home/wisbfime/irlume/packaging/selinux/irlume.pp";
    if enable {
        if selinux_loaded() == Some(true) { return Ok("· SELinux module already loaded".into()); }
        if !Path::new(pp).exists() {
            return Ok(format!("· SELinux: {pp} not built (run make in packaging/selinux) — skipped"));
        }
        if apply {
            let ok = Command::new("semodule").args(["-i", pp]).status().map(|s| s.success()).unwrap_or(false);
            if !ok { return Err("semodule -i irlume.pp failed".into()); }
        }
        Ok("✓ SELinux module loaded (greeter→daemon socket)".into())
    } else {
        if selinux_loaded() == Some(false) { return Ok("· SELinux module not loaded".into()); }
        if apply { let _ = Command::new("semodule").args(["-r", "irlume"]).status(); }
        Ok("✓ SELinux module removed".into())
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
        let (w, changed) = wire_greeter(GDM);
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

    #[test]
    fn greeter_wiring_is_idempotent() {
        let (w1, _) = wire_greeter(GDM);
        let (w2, changed) = wire_greeter(&w1);
        assert!(!changed);
        assert_eq!(w1, w2);
    }

    #[test]
    fn single_stanza_and_unwire_roundtrip() {
        let base = "#%PAM-1.0\nauth required pam_unix.so\nsession required pam_unix.so\n";
        let (w, c) = wire_single(base, LOCK_WAIT);
        assert!(c && content_has_module(&w));
        let (back, changed) = unwire_lines(&w);
        assert!(changed && !content_has_module(&back));
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
