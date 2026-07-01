//! Extra operational CLI commands layered over the existing daemon protocol:
//! observability (`status`, `detect`, `identify`), diagnostics (`diag`,
//! `selinux`, `deps`), the safe manual re-bind (`reseal`), and the guided
//! `setup` wizard. These are thin orchestration over `irlumed` + local probes;
//! the daemon stays the only component that touches the camera / TPM / store.

use crate::{daemon_request, tpm_device, user_arg};
use irlume_common::{Request, Response};
use std::process::ExitCode;

const OK: &str = "\u{2705}";
const WARN: &str = "\u{26a0}";
const NO: &str = "\u{2717}";

/// Reachability: a Ping that returns true iff `irlumed` answered.
fn daemon_up() -> bool {
    matches!(daemon_request(&Request::Ping), Ok(Response::Pong))
}

/// `irlume status` — one-shot health dashboard. Always exits 0 (it reports state,
/// it doesn't gate anything); use `irlume detect` for script-friendly exit codes.
pub fn status(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    println!("irlume status for '{user}'");

    // Daemon + method.
    let up = daemon_up();
    println!("  daemon        : {}", if up { format!("running {OK}") } else { format!("NOT reachable {NO} (systemctl status irlumed)") });
    let method = irlume_core::policy::method();
    println!("  auth method   : {:?}{}", method, if method.face_disabled() { " (face disabled)" } else { "" });

    // Enrollment.
    match daemon_request(&Request::ListProfiles { user: user.clone() }) {
        Ok(Response::Enrollment { profiles, require_eyes_open, require_challenge }) if !profiles.is_empty() => {
            let scans: usize = profiles.iter().map(|p| p.scans.len()).sum();
            println!("  enrollment    : {} profile(s), {scans} scan(s) {OK}{}{}",
                profiles.len(),
                if require_eyes_open { " · eyes-open required" } else { "" },
                if require_challenge { " · blink-challenge required" } else { "" });
            for p in &profiles {
                println!("                  - {} ({} scan(s))", p.name, p.scans.len());
            }
        }
        Ok(Response::Enrollment { .. }) => println!("  enrollment    : none {WARN} (run `irlume enroll`)"),
        Ok(Response::Error(e)) => println!("  enrollment    : error: {e}"),
        _ => println!("  enrollment    : unknown (daemon unreachable)"),
    }

    // Keyring (TPM-sealed login password) + template encryption / recovery.
    match daemon_request(&Request::HasSealedPassword { user: user.clone() }) {
        Ok(Response::HasPassword(armed)) =>
            println!("  keyring unlock: {}", if armed { format!("armed {OK}") } else { "not armed (run `irlume keyring arm`)".into() }),
        _ => println!("  keyring unlock: unknown"),
    }
    match daemon_request(&Request::RecoveryStatus { user: user.clone() }) {
        Ok(Response::RecoveryStatus { encrypted, recovery_set, .. }) => {
            println!("  templates     : {}", if encrypted { format!("encrypted at rest {OK}") } else { format!("plaintext {WARN} (run `irlume recovery setup`)") });
            println!("  recovery pass : {}", if recovery_set { format!("set {OK}") } else { format!("not set {WARN}") });
        }
        _ => {}
    }

    // Biopolicy enforcement (opt-in).
    let bio = irlume_common::config::read_kv("settings.conf", "enforce_biopolicy")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    println!("  biopolicy     : {}", if bio { format!("ENFORCING {OK} (operation-class gate)") } else { "off (default)".into() });

    // Cameras.
    let (rgb, ir) = irlume_camera::select_pair();
    println!("  cameras       : rgb={rgb} ir={ir}");

    // Fingerprint.
    let fp = irlume_fingerprint::device_name()
        .map(|n| format!("{n} {OK}"))
        .unwrap_or_else(|| if irlume_fingerprint::available() { format!("present {OK}") } else { "none".into() });
    println!("  fingerprint   : {fp}");

    ExitCode::SUCCESS
}

/// `irlume detect` — script-friendly install-state probe. Exit codes:
///   0  = ready    (daemon reachable AND the user is enrolled)
///   10 = partial  (installed but not ready: daemon down or not enrolled)
///   20 = absent   (irlumed is not installed)
pub fn detect(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    let installed = ["/usr/local/bin/irlumed", "/usr/bin/irlumed"]
        .iter().any(|p| std::path::Path::new(p).exists());
    if !installed {
        println!("absent: irlumed is not installed");
        return ExitCode::from(20);
    }
    let up = daemon_up();
    let enrolled = matches!(
        daemon_request(&Request::ListProfiles { user }),
        Ok(Response::Enrollment { ref profiles, .. }) if !profiles.is_empty()
    );
    if up && enrolled {
        println!("ready: daemon running and a face is enrolled");
        ExitCode::SUCCESS
    } else {
        println!("partial: installed but not ready ({}{})",
            if up { "daemon up" } else { "daemon down" },
            if enrolled { ", enrolled" } else { ", not enrolled" });
        ExitCode::from(10)
    }
}

/// `irlume identify` — 1:N "who is this?" over a live capture (no claimed user).
pub fn identify(_args: &[String]) -> ExitCode {
    eprintln!("[identify] look at the camera…");
    match daemon_request(&Request::Identify) {
        Ok(Response::Identified { user: Some(u), profile, score, .. }) => {
            println!("[identify] {u} (profile '{}', score {score:.3}) {OK}", profile.unwrap_or_default());
            ExitCode::SUCCESS
        }
        Ok(Response::Identified { user: None, live, reason, .. }) => {
            println!("[identify] no match — {} ({reason})", if live { "live face, not enrolled" } else { "no live face" });
            ExitCode::from(1)
        }
        Ok(Response::Error(e)) => { eprintln!("[identify] error: {e}"); ExitCode::FAILURE }
        Ok(other) => { eprintln!("[identify] unexpected response: {other:?}"); ExitCode::FAILURE }
        Err(e) => { eprintln!("[identify] {e}"); ExitCode::FAILURE }
    }
}

/// `irlume diag` — TPM seal / PCR-drift diagnostics (the dbx/firmware debugger).
/// Needs root + TPM access to read the root-only envelope and replay PCRs; falls
/// back to a daemon-only summary otherwise.
pub fn diag(args: &[String]) -> ExitCode {
    use irlume_common::secureboot;
    let user = user_arg(args);
    println!("irlume diag for '{user}'");

    // Trust anchors.
    match tpm_device() {
        Some(d) => println!("  TPM           : {d} {OK}"),
        None => println!("  TPM           : none {NO}"),
    }
    println!("  boot mode     : {}", secureboot::detect_boot_mode().as_str());
    if secureboot::is_secure_boot_enabled() {
        println!("  secure boot   : enabled {OK}");
    } else if secureboot::is_setup_mode() {
        println!("  secure boot   : SETUP MODE {WARN}");
    } else if secureboot::secure_boot_present() {
        println!("  secure boot   : disabled {WARN}");
    } else {
        println!("  secure boot   : not a UEFI boot");
    }
    println!("  signed policy : {}", if irlume_core::pcrsig::signed_policy_available() {
        "PCR-11 signature present (kernel updates won't need re-seal)"
    } else {
        "none — literal PCR-7 seal (re-arm/restore after firmware updates)"
    });

    // Keyring envelope: policy kind, bound PCRs, drift (root + TPM only).
    let path = irlume_core::keyring::envelope_path(&user);
    match irlume_core::envelope::SealedEnvelope::load(&path) {
        Ok(env) => {
            let kind = match &env.policy {
                irlume_core::envelope::PolicyKind::PcrLiteral => "literal PolicyPCR (Tier 3)".to_string(),
                irlume_core::envelope::PolicyKind::Authorized { .. } => "signed PolicyAuthorize (Tier 1)".to_string(),
                irlume_core::envelope::PolicyKind::PcrlockNv { nv_index } => format!("pcrlock NV 0x{nv_index:x} (Tier 2)"),
            };
            println!("  seal envelope : {} {OK}", path.display());
            println!("  seal policy   : {kind}, bound PCRs {:?}", env.pcrs);
            match irlume_core::tpm::diagnose_pcrs(&env) {
                Ok(d) if d.is_empty() => println!("  PCR drift     : none {OK} — the seal still satisfies; face unlock will release the password"),
                Ok(d) => println!("  PCR drift     : DRIFTED at {d:?} {WARN} — unseal will FAIL until you `irlume keyring arm` (or `irlume recovery restore`)"),
                Err(e) => println!("  PCR drift     : could not replay PCRs ({e}) — need TPM access (tss group / root)"),
            }
        }
        Err(_) => {
            // No readable envelope: either not armed, or not root.
            match daemon_request(&Request::HasSealedPassword { user: user.clone() }) {
                Ok(Response::HasPassword(true)) =>
                    println!("  seal envelope : armed, but not readable here — run `sudo irlume diag` for PCR-drift detail"),
                Ok(Response::HasPassword(false)) =>
                    println!("  seal envelope : not armed (run `irlume keyring arm`)"),
                _ => println!("  seal envelope : unknown (daemon unreachable)"),
            }
        }
    }
    ExitCode::SUCCESS
}

/// `irlume selinux <status|load>` — manage the policy module that lets the
/// confined greeter (`xdm_t`) reach the daemon socket at login.
pub fn selinux(sub: Option<&str>, _args: &[String]) -> ExitCode {
    match sub {
        None | Some("status") => {
            // `semodule -l` needs root; as a normal user it returns nothing, so
            // an empty list ≠ "not loaded". The live socket label is a reliable
            // positive signal either way (only our type_transition sets it).
            let out = std::process::Command::new("semodule").args(["-l"]).output();
            let listed = out.as_ref().map(|o| o.status.success() && !o.stdout.is_empty()).unwrap_or(false);
            let in_list = out.as_ref().map(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.trim() == "irlume")).unwrap_or(false);
            let label = std::process::Command::new("ls").args(["-Z", irlume_common::SOCKET_PATH]).output()
                .ok().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
            let labeled = label.contains("irlume_runtime_t");
            let state = if in_list || labeled {
                format!("loaded {OK}")
            } else if !listed {
                format!("unknown {WARN} (run `sudo irlume selinux status` — semodule needs root)")
            } else {
                format!("not loaded {WARN} (run `sudo irlume selinux load`)")
            };
            println!("[selinux] module 'irlume': {state}");
            if !label.is_empty() {
                print!("[selinux] socket label: {label}");
            }
            ExitCode::SUCCESS
        }
        Some("load") => {
            let pp = ["packaging/selinux/irlume.pp", "/usr/share/irlume/selinux/irlume.pp"]
                .into_iter().find(|p| std::path::Path::new(p).exists());
            let Some(pp) = pp else {
                eprintln!("[selinux] irlume.pp not found — build it: make -f /usr/share/selinux/devel/Makefile -C packaging/selinux irlume.pp");
                return ExitCode::FAILURE;
            };
            eprintln!("[selinux] semodule -i {pp} (needs root)…");
            let st = std::process::Command::new("semodule").args(["-i", pp]).status();
            match st {
                Ok(s) if s.success() => { println!("[selinux] loaded {OK}; restart irlumed so the socket relabels"); ExitCode::SUCCESS }
                Ok(s) => { eprintln!("[selinux] semodule exited {s}"); ExitCode::FAILURE }
                Err(e) => { eprintln!("[selinux] could not run semodule: {e}"); ExitCode::FAILURE }
            }
        }
        Some(other) => { eprintln!("[selinux] unknown subcommand '{other}' (use: status | load)"); ExitCode::FAILURE }
    }
}

/// `irlume deps` — verify the runtime dependencies are present.
pub fn deps(_args: &[String]) -> ExitCode {
    let mut ok = true;
    let mut check = |label: &str, present: bool, hint: &str| {
        println!("  {label:<14}: {}", if present { format!("{OK}") } else { ok = false; format!("{NO} {hint}") });
    };
    // ONNX Runtime: explicit path, or a well-known system location.
    let ort_env = std::env::var("ORT_DYLIB_PATH").ok().filter(|p| std::path::Path::new(p).exists());
    let ort_sys = ["/usr/lib64/libonnxruntime.so", "/usr/lib/libonnxruntime.so"]
        .iter().any(|p| std::path::Path::new(p).exists());
    check("onnxruntime", ort_env.is_some() || ort_sys, "install onnxruntime or set ORT_DYLIB_PATH");
    for m in ["models/glintr100.onnx", "models/face_detection_yunet_2023mar.onnx"] {
        check(m.strip_prefix("models/").unwrap_or(m), std::path::Path::new(m).exists(), "fetch the model into models/");
    }
    check("TPM", tpm_device().is_some(), "no /dev/tpmrm0 (sealing unavailable)");
    let have_video = (0..10).any(|n| std::path::Path::new(&format!("/dev/video{n}")).exists());
    check("camera (v4l)", have_video, "no /dev/video* nodes");
    println!("deps: {}", if ok { format!("all present {OK}") } else { format!("missing dependencies {WARN}") });
    if ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

/// `irlume reseal` — safely re-bind the TPM-sealed login password to the CURRENT
/// PCR state (after a firmware / Secure Boot / kernel update that moved PCR 7).
/// This is the manual, verified path: you re-enter your login password, so a
/// stale seal can never be silently overwritten with a typo (the daemon's
/// automatic reseal only runs in the post-auth session phase for the same
/// reason). Functionally a re-arm against today's PCRs.
pub fn reseal(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    // Only meaningful if already armed (we never auto-arm from here).
    match daemon_request(&Request::HasSealedPassword { user: user.clone() }) {
        Ok(Response::HasPassword(false)) => {
            eprintln!("[reseal] '{user}' has no sealed password — nothing to re-bind. Run `irlume keyring arm` to set one up.");
            return ExitCode::from(2);
        }
        Ok(Response::HasPassword(true)) => {}
        _ => { eprintln!("[reseal] daemon unreachable"); return ExitCode::FAILURE; }
    }
    println!("[reseal] Re-binding '{user}'s sealed password to the current TPM/PCR state.");
    let Some(pw) = prompt_login_password() else { return ExitCode::from(2) };
    let req = Request::SealPassword { user, password: irlume_common::SecretBytes::new(pw.into_bytes()) };
    match daemon_request(&req) {
        Ok(Response::PasswordSealed) => { println!("[reseal] re-bound to current PCRs {OK} — face unlock will release it again."); ExitCode::SUCCESS }
        Ok(other) => { eprintln!("[reseal] unexpected response: {other:?}"); ExitCode::FAILURE }
        Err(e) => { eprintln!("[reseal] failed: {e}"); ExitCode::FAILURE }
    }
}

/// Shared no-echo login-password prompt with a confirm step (catches typos that
/// would silently break wallet unlock). Falls back to a single piped stdin line
/// for scripts/tests. Returns `None` on mismatch / empty / read error.
pub(crate) fn prompt_login_password() -> Option<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let a = rpassword::prompt_password("Login password: ").ok()?;
        let b = rpassword::prompt_password("Confirm login password: ").ok()?;
        if a != b { eprintln!("passwords do not match — aborted (nothing changed)."); return None; }
        if a.is_empty() { eprintln!("empty password — aborted."); return None; }
        Some(a)
    } else {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).ok()?;
        let pw = line.trim_end_matches(['\n', '\r']).to_string();
        if pw.is_empty() { return None; }
        Some(pw)
    }
}

/// `irlume setup` — guided onboarding that ties the existing pieces together:
/// preflight → camera pick → enroll → keyring arm → recovery → fingerprint →
/// login wiring. Each step is opt-in (y/N); nothing destructive runs unprompted.
pub fn setup(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    println!("=== irlume setup for '{user}' ===\n");

    // 1. Preflight.
    println!("[1/6] Preflight");
    if !daemon_up() {
        eprintln!("  daemon not reachable — start it first: sudo systemctl enable --now irlumed");
        return ExitCode::FAILURE;
    }
    println!("  daemon running {OK}");
    let _ = deps(args);
    let (rgb, ir) = irlume_camera::select_pair();
    println!("  cameras: rgb={rgb} ir={ir}");

    // 2. Enroll (reset if already enrolled and the user wants a clean start).
    println!("\n[2/6] Face enrollment");
    let enrolled = matches!(daemon_request(&Request::ListProfiles { user: user.clone() }),
        Ok(Response::Enrollment { ref profiles, .. }) if !profiles.is_empty());
    if enrolled {
        println!("  already enrolled.");
        if yes_no("  Re-enroll from scratch (wipes existing profiles)?", false) {
            run_enroll(&user, true);
        }
    } else if yes_no("  Enroll your face now?", true) {
        run_enroll(&user, false);
    }

    // 3. Keyring arm.
    println!("\n[3/6] Keyring unlock (face login opens your wallet)");
    if yes_no("  Arm keyring unlock now (you'll enter your login password)?", true) {
        if let Some(pw) = prompt_login_password() {
            match daemon_request(&Request::SealPassword { user: user.clone(), password: irlume_common::SecretBytes::new(pw.into_bytes()) }) {
                Ok(Response::PasswordSealed) => println!("  armed {OK}"),
                r => eprintln!("  arm failed: {r:?}"),
            }
        }
    }

    // 4. Recovery passphrase + template encryption.
    println!("\n[4/6] Recovery passphrase (encrypts templates; backstop for TPM/firmware changes)");
    if yes_no("  Set a recovery passphrase now?", true) {
        println!("  (run `irlume recovery setup` — it prompts for a separate recovery passphrase)");
    }

    // 5. Fingerprint.
    println!("\n[5/6] Fingerprint (optional companion factor)");
    match irlume_fingerprint::device_name() {
        Some(n) => println!("  reader '{n}' present — manage with `irlume fingerprint add` / `enable`"),
        None => println!("  no fingerprint reader detected — skipping"),
    }

    // 6. Login wiring.
    println!("\n[6/6] PAM login wiring");
    println!("  preview the changes with `irlume login enable` (dry-run), then apply with");
    println!("  `sudo irlume login enable --apply` to wire greeters + lock screen.");

    println!("\n=== setup complete. Check `irlume status` any time. ===");
    ExitCode::SUCCESS
}

/// Enroll via the daemon (capture happens daemon-side; no camera contention).
fn run_enroll(user: &str, reset: bool) {
    eprintln!("  capturing — stay in frame, look at the camera…");
    match daemon_request(&Request::Enroll { user: user.into(), profile: None, scans: None, reset }) {
        Ok(Response::Ok(msg)) => println!("  {msg} {OK}"),
        r => eprintln!("  enroll failed: {r:?}"),
    }
}

/// Minimal y/N prompt (default applied on empty input or a non-tty).
fn yes_no(q: &str, default_yes: bool) -> bool {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return default_yes;
    }
    print!("{q} [{}] ", if default_yes { "Y/n" } else { "y/N" });
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    use std::io::BufRead;
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return default_yes;
    }
    match line.trim().to_ascii_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    }
}

/// `irlume help` / no args — top-level command listing.
pub fn help() -> ExitCode {
    println!("\
irlume — local face authentication

USAGE: irlume <command> [options]   (default user = $USER; override with --user U)

SETUP & STATUS
  setup                 guided onboarding (enroll, keyring, recovery, wiring)
  status                health dashboard (daemon, enrollment, keyring, cameras)
  detect                script probe; exit 0=ready / 10=partial / 20=absent
  doctor                platform / TPM / Secure Boot / camera / model checks
  deps                  verify runtime dependencies (onnxruntime, models, TPM)

ENROLLMENT & AUTH
  enroll [--name N] [--scans K] [--reset]   capture a face profile
  profiles [list|add-scan|rename|delete|eyes-open]   manage profiles/scans
  verify                authenticate the current user (face)
  identify              1:N \"who is this?\" across all enrolled users

KEYRING / TPM
  keyring <arm|status|forget>     TPM-sealed login password for wallet unlock
  reseal                re-bind the sealed password to current PCRs (after a
                        firmware/kernel update) — safe, re-enters the password
  recovery <status|setup|restore|forget>   recovery passphrase + encryption
  diag                  TPM seal + PCR-drift diagnostics (run with sudo for detail)

SYSTEM INTEGRATION
  login <status|enable|disable> [--apply]   PAM wiring for greeters + lock screen
  fingerprint <status|add|enable|disable>   fprintd companion factor
  selinux <status|load>           SELinux module for the login greeter
  ir-setup [--dry-run]            auto-configure the IR emitter

CAMERA / DEV
  capture | liveness | blinkprobe | tui   capture/liveness/blink probes; the UI
  irbench | genuine | eval | selftest align   benchmarks & self-tests
  padcapture --species N --kind attack|bonafide --out LOG   ISO 30107-3 PAD capture
  padreport --in LOG [--md OUT]   PAD self-test report (APCER/BPCER; docs/PAD_SELFTEST.md)
");
    ExitCode::SUCCESS
}
