// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume fingerprint <status|add|enable|disable>`: fingerprint as a companion
//! auth modality via stock fprintd + pam_fprintd. irlume never claims the sensor;
//! it orchestrates enrollment (fprintd CLI) and wires pam_fprintd per distro.
//! `enable` also records the active method so the daemon disables face and lets
//! pam_fprintd drive. Ported from linhello.

use irlume_common::platform::{distro_family, DistroFamily};
use irlume_core::policy::{self, Method};
use irlume_fingerprint as fp;
use std::process::{Command, ExitCode};

pub fn run(action: Option<&str>, args: &[String]) -> ExitCode {
    let user = crate::user_arg(args);
    match action {
        None | Some("status") => status(&user),
        Some("add") => {
            if enroll_one(&user) {
                offer_verify(&user);
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some("verify") => verify(&user),
        Some("reset") => reset(&user, args),
        Some("enable") => enable(&user),
        Some("disable") => disable(),
        _ => {
            eprintln!(
                "usage: irlume fingerprint [--user U] <status|add|verify|reset|enable|disable>"
            );
            ExitCode::from(2)
        }
    }
}

fn status(user: &str) -> ExitCode {
    println!(
        "[fingerprint] fprintd tooling : {}",
        if fp::fprintd_present() {
            "installed"
        } else {
            "NOT installed (install the 'fprintd' package)"
        }
    );
    let names = fp::device_names();
    let reader = match names.len() {
        0 if fp::reader_present() => "present (unnamed)".into(),
        0 => "none detected".into(),
        _ => names.join(" + "),
    };
    println!("[fingerprint] reader         : {reader}");
    if let Some(unit) = fp::bus_owner_unit() {
        if unit != "fprintd.service" {
            println!(
                "[fingerprint] ⚠ the fprint bus is owned by '{unit}', not fprintd.service: \
                 a vendor driver stack (open-fprintd/python-validity) is answering; \
                 its enrollment data and failure modes differ from stock fprintd"
            );
        }
    }
    // The listing can fail in ways that are NOT "no fingers enrolled" (stale
    // claim, polkit refusal, readerless box); say which, or the advice below
    // points the wrong way.
    let listing = fp::list_fingers(user);
    let mut fingers: Vec<String> = Vec::new();
    let mut list_error = None;
    match &listing {
        fp::ListOutcome::Fingers(v) => {
            fingers = v.clone();
            if fingers.is_empty() {
                println!("[fingerprint] enrolled       : none for '{user}'");
            } else {
                println!(
                    "[fingerprint] enrolled       : {} ({})",
                    fingers.len(),
                    fingers.join(", ")
                );
            }
        }
        fp::ListOutcome::NoDevice => {
            println!("[fingerprint] enrolled       : (fprintd reports no reader)");
        }
        fp::ListOutcome::Error(e) => {
            println!("[fingerprint] enrolled       : could not list — {e}");
            list_error = Some(e.clone());
        }
    }
    println!(
        "[fingerprint] active method   : {}",
        policy::method().as_str()
    );
    // Recommendation. A failed listing means we do NOT know the enrollment
    // state; recommending `add` there sends the user the wrong way (live find:
    // over SSH, polkit refuses the listing while fingers are enrolled fine).
    if !fp::available() {
        println!("  → no usable reader; fingerprint unavailable on this device");
    } else if let Some(e) = list_error {
        println!("  → fix the listing first ({e}); enrollment state is unknown until then");
    } else if fingers.is_empty() {
        println!("  → reader present but no finger enrolled: run  irlume fingerprint add");
    } else if policy::method() != Method::Fingerprint {
        println!(
            "  → enrolled; to make fingerprint the unlock method: sudo irlume fingerprint enable"
        );
    } else {
        println!("  → fingerprint is the active unlock method");
    }
    ExitCode::SUCCESS
}

/// Enroll the first free finger for `user`. Returns success.
fn enroll_one(user: &str) -> bool {
    if !fp::fprintd_present() {
        eprintln!("[fingerprint] fprintd not installed; install the 'fprintd' package first");
        return false;
    }
    if !fp::reader_present() {
        eprintln!("[fingerprint] no fingerprint reader detected");
        return false;
    }
    let Some(finger) = fp::free_finger(user) else {
        eprintln!("[fingerprint] all 10 fingers are already enrolled for '{user}'");
        return false;
    };
    println!(
        "[fingerprint] enrolling '{finger}' for '{user}': place and lift your finger as prompted…"
    );
    match fp::enroll_finger(user, finger) {
        fp::EnrollOutcome::Enrolled => {
            println!("[fingerprint] ✓ enrolled '{finger}'");
            true
        }
        fp::EnrollOutcome::Duplicate => {
            eprintln!("[fingerprint] that finger is already enrolled");
            false
        }
        fp::EnrollOutcome::Failed(e) => {
            eprintln!("[fingerprint] enroll failed: {e}");
            false
        }
    }
}

/// Interactive yes/no prompt; returns `default_yes` on EOF or a bare Enter.
/// Never called when stdin is not a TTY (callers gate on that), so scripts
/// cannot hang here.
fn confirm(prompt: &str, default_yes: bool) -> bool {
    use std::io::Write;
    print!("{prompt} {} ", if default_yes { "[Y/n]" } else { "[y/N]" });
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return default_yes;
    }
    match line.trim() {
        "" => default_yes,
        s => s.eq_ignore_ascii_case("y") || s.eq_ignore_ascii_case("yes"),
    }
}

/// After a successful enrollment, offer one verification round. "Enroll
/// succeeds, verify never matches" is a top fprintd field complaint; one round
/// here catches it before the user relies on the print at the greeter.
fn offer_verify(user: &str) {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return;
    }
    if !confirm(
        "[fingerprint] verify the new print now?",
        /* default_yes: */ true,
    ) {
        return;
    }
    verify_round(user);
}

/// One verification round with outcome reporting; returns true on a match.
fn verify_round(user: &str) -> bool {
    println!("[fingerprint] place the enrolled finger on the reader…");
    match fp::verify_once(user) {
        fp::VerifyOutcome::Match => {
            println!("[fingerprint] ✓ verified");
            true
        }
        fp::VerifyOutcome::NoMatch => {
            eprintln!(
                "[fingerprint] ⚠ the reader did not match the finger you just enrolled. \
                 The enrollment may be low quality; run  irlume fingerprint reset  and \
                 re-enroll with slow, full placements."
            );
            false
        }
        fp::VerifyOutcome::Error(e) => {
            eprintln!("[fingerprint] verify failed: {e}");
            false
        }
    }
}

fn verify(user: &str) -> ExitCode {
    if !fp::available() {
        eprintln!("[fingerprint] no usable reader (need fprintd + a fingerprint reader)");
        return ExitCode::FAILURE;
    }
    // Use the checked listing: a polkit/claim failure must not masquerade as
    // "no finger enrolled" (live find: SSH sessions get polkit-refused).
    match fp::list_fingers(user) {
        fp::ListOutcome::Fingers(v) if v.is_empty() => {
            eprintln!("[fingerprint] no finger enrolled for '{user}'; run  irlume fingerprint add");
            return ExitCode::FAILURE;
        }
        fp::ListOutcome::Fingers(_) => {}
        fp::ListOutcome::NoDevice => {
            eprintln!("[fingerprint] fprintd reports no reader");
            return ExitCode::FAILURE;
        }
        fp::ListOutcome::Error(e) => {
            eprintln!("[fingerprint] cannot check enrollment: {e}");
            return ExitCode::FAILURE;
        }
    }
    if verify_round(user) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Delete every print fprintd holds for `user` and offer a fresh enrollment.
/// The remedy for chip/host template desync (Windows dual-boot enrollment, OS
/// reinstall, BIOS "clear fingerprints"): fprintd then lists fingers that never
/// verify, and only a full delete + re-enroll recovers.
fn reset(user: &str, args: &[String]) -> ExitCode {
    use std::io::IsTerminal;
    let assume_yes = args.iter().any(|a| a == "--yes");
    let fingers = match fp::list_fingers(user) {
        fp::ListOutcome::Fingers(v) => v,
        fp::ListOutcome::NoDevice => {
            eprintln!("[fingerprint] fprintd reports no reader; nothing to reset");
            return ExitCode::FAILURE;
        }
        fp::ListOutcome::Error(e) => {
            eprintln!("[fingerprint] cannot list current prints: {e}");
            return ExitCode::FAILURE;
        }
    };
    if fingers.is_empty() {
        println!("[fingerprint] no prints recorded for '{user}'; nothing to delete");
        return ExitCode::SUCCESS;
    }
    println!(
        "[fingerprint] this deletes ALL {} enrolled print(s) for '{user}': {}",
        fingers.len(),
        fingers.join(", ")
    );
    if !assume_yes {
        if !std::io::stdin().is_terminal() {
            eprintln!("[fingerprint] refusing to delete without a terminal; pass --yes to force");
            return ExitCode::FAILURE;
        }
        if !confirm("[fingerprint] delete them?", /* default_yes: */ false) {
            println!("[fingerprint] nothing deleted");
            return ExitCode::SUCCESS;
        }
    }
    if let Err(e) = fp::delete_all(user) {
        eprintln!("[fingerprint] delete failed: {e}");
        return ExitCode::FAILURE;
    }
    println!("[fingerprint] ✓ deleted {} print(s)", fingers.len());
    if std::io::stdin().is_terminal()
        && confirm(
            "[fingerprint] enroll a fresh print now?",
            /* default_yes: */ true,
        )
    {
        if enroll_one(user) {
            offer_verify(user);
        } else {
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn require_root(op: &str) -> bool {
    if effective_uid() != 0 {
        eprintln!("[fingerprint] '{op}' modifies the system PAM config; run with: sudo irlume fingerprint {op}");
        return false;
    }
    true
}

/// Effective uid, read from `/proc/self/status` (no libc dep in the CLI).
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

fn enable(user: &str) -> ExitCode {
    if !fp::available() {
        eprintln!("[fingerprint] no usable reader (need fprintd + a fingerprint reader)");
        return ExitCode::FAILURE;
    }
    if !require_root("enable") {
        return ExitCode::FAILURE;
    }
    // Enroll a finger first if the user has none.
    if !fp::has_enrollment(user) {
        println!("[fingerprint] no finger enrolled yet; enrolling one now");
        if !enroll_one(user) {
            return ExitCode::FAILURE;
        }
    }
    // Wire pam_fprintd into the auth stacks, per distro.
    let wired = match distro_family() {
        DistroFamily::Fedora => {
            run_cmd("authselect", &["enable-feature", "with-fingerprint"])
                && run_cmd("authselect", &["apply-changes"])
        }
        DistroFamily::Debian => run_cmd("pam-auth-update", &["--enable", "fprintd"]),
        // No supported wiring tool here. Proceed only when the admin has already
        // added the stanza: recording method=fingerprint with nothing wired
        // disables face while no biometric drives the prompt, silently leaving
        // the box password-only.
        DistroFamily::Arch | DistroFamily::Other => {
            let already = pam_fprintd_wired(std::path::Path::new(PAM_DIR));
            if already {
                println!(
                    "[fingerprint] found an active pam_fprintd.so line in {PAM_DIR}; using it"
                );
            } else {
                eprintln!("[fingerprint] no wiring tool on this distro; add the line yourself:");
                eprintln!("                auth  sufficient  pam_fprintd.so");
                eprintln!("              above pam_unix in your login/sudo PAM stacks");
                eprintln!("              (e.g. /etc/pam.d/system-local-login, /etc/pam.d/sudo),");
                eprintln!("              then re-run:  sudo irlume fingerprint enable");
            }
            already
        }
    };
    if !wired {
        eprintln!(
            "[fingerprint] method unchanged: face (irlume) stays active until pam_fprintd is wired"
        );
        return ExitCode::FAILURE;
    }
    // Verify the line actually landed before switching the method, even on the
    // tool paths: authselect/pam-auth-update can exit 0 without producing a
    // pam_fprintd line (e.g. a custom authselect profile lacking the feature).
    if !pam_fprintd_wired(std::path::Path::new(PAM_DIR)) {
        eprintln!(
            "[fingerprint] wiring reported success but {PAM_DIR} has no active pam_fprintd.so line"
        );
        eprintln!(
            "[fingerprint] method unchanged: face (irlume) stays active until pam_fprintd is wired"
        );
        return ExitCode::FAILURE;
    }
    if let Err(e) = policy::set_method(Method::Fingerprint) {
        eprintln!("[fingerprint] wired, but could not record method: {e}");
        return ExitCode::FAILURE;
    }
    println!("[fingerprint] ✓ enabled: fingerprint now unlocks; irlume face is disabled (pam_fprintd drives, password is the fallback)");
    ExitCode::SUCCESS
}

fn disable() -> ExitCode {
    if !require_root("disable") {
        return ExitCode::FAILURE;
    }
    let unwired = match distro_family() {
        DistroFamily::Fedora => {
            run_cmd("authselect", &["disable-feature", "with-fingerprint"])
                && run_cmd("authselect", &["apply-changes"])
        }
        DistroFamily::Debian => run_cmd("pam-auth-update", &["--disable", "fprintd"]),
        DistroFamily::Arch | DistroFamily::Other => {
            println!("[fingerprint] Remove the 'auth sufficient pam_fprintd.so' line you added.");
            true
        }
    };
    if !unwired {
        eprintln!("[fingerprint] failed to unwire pam_fprintd; check the output above");
        return ExitCode::FAILURE;
    }
    if let Err(e) = policy::set_method(Method::Auto) {
        eprintln!("[fingerprint] unwired, but could not reset method: {e}");
        return ExitCode::FAILURE;
    }
    println!("[fingerprint] ✓ disabled: face (irlume) is the active method again");
    ExitCode::SUCCESS
}

/// Where PAM service files live; a const so tests can exercise the scan on a
/// directory they control.
const PAM_DIR: &str = "/etc/pam.d";

/// Does `text` contain an ACTIVE (non-comment) line referencing `needle`?
fn has_active_line(text: &str, needle: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim_start();
        !t.starts_with('#') && t.contains(needle)
    })
}

/// True when any file in `pam_dir` carries an ACTIVE (non-comment) line
/// referencing `pam_fprintd.so`, i.e. something will actually drive the
/// fingerprint prompt. Unreadable dirs/files count as not wired.
fn pam_fprintd_wired(pam_dir: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(pam_dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        std::fs::read_to_string(e.path()).is_ok_and(|s| has_active_line(&s, "pam_fprintd.so"))
    })
}

/// True when one PAM service file stacks BOTH pam_faillock and pam_fprintd.
/// That combination locks accounts in the field: a touch sensor misread burns
/// all fingerprint retries in under two seconds, each one counting as a
/// faillock failure (fprintd#209/#215). Doctor surfaces it with the
/// `faillock --reset` remedy.
pub(crate) fn faillock_cohabits(pam_dir: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(pam_dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        std::fs::read_to_string(e.path()).is_ok_and(|s| {
            has_active_line(&s, "pam_faillock.so") && has_active_line(&s, "pam_fprintd.so")
        })
    })
}

/// True when the sudo PAM service reaches pam_fprintd, either directly or via
/// one level of `include`/`substack` (Fedora's sudo includes system-auth, which
/// is where authselect puts the fingerprint line). Paired with a running sshd
/// this stalls every `sudo` typed in an SSH session for the full fingerprint
/// timeout: the prompt waits on a reader the remote user cannot touch.
pub(crate) fn fprintd_in_sudo(pam_dir: &std::path::Path) -> bool {
    let Ok(sudo) = std::fs::read_to_string(pam_dir.join("sudo")) else {
        return false;
    };
    if has_active_line(&sudo, "pam_fprintd.so") {
        return true;
    }
    for l in sudo.lines() {
        let t = l.trim_start();
        if t.starts_with('#') {
            continue;
        }
        let mut parts = t.split_whitespace();
        // `auth include system-auth` / `auth substack system-auth`, and the
        // one-word `@include common-auth` Debian form.
        let target = match (parts.next(), parts.next(), parts.next()) {
            (Some("@include"), Some(name), _) => Some(name),
            (Some(_), Some("include" | "substack"), Some(name)) => Some(name),
            _ => None,
        };
        if let Some(name) = target {
            if std::fs::read_to_string(pam_dir.join(name))
                .is_ok_and(|s| has_active_line(&s, "pam_fprintd.so"))
            {
                return true;
            }
        }
    }
    false
}

/// True when an OpenSSH server is active or enabled (unit is `sshd` on
/// Fedora/Arch, `ssh` on Debian/Ubuntu).
pub(crate) fn sshd_present() -> bool {
    ["sshd", "ssh"].iter().any(|unit| {
        std::process::Command::new("/usr/bin/systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .is_ok_and(|s| s.success())
            || std::process::Command::new("/usr/bin/systemctl")
                .args(["is-enabled", "--quiet", unit])
                .status()
                .is_ok_and(|s| s.success())
    })
}

/// Run a system command, echoing it (transparency) and reporting success.
fn run_cmd(cmd: &str, args: &[&str]) -> bool {
    println!("[fingerprint] $ {cmd} {}", args.join(" "));
    match Command::new(cmd).args(args).status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("[fingerprint] {cmd} exited with {s}");
            false
        }
        Err(e) => {
            eprintln!("[fingerprint] could not run {cmd}: {e} (is it installed?)");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_uid_matches_the_real_euid() {
        // The /proc/self/status parse must yield the kernel's effective uid.
        assert_eq!(effective_uid(), unsafe { libc::geteuid() });
    }

    #[test]
    fn require_root_gates_on_the_effective_uid() {
        // Consistent with effective_uid: only uid 0 clears the gate.
        if effective_uid() == 0 {
            assert!(require_root("enable"));
        } else {
            assert!(!require_root("enable"));
        }
    }

    #[test]
    fn run_cmd_maps_spawn_and_exit_outcomes_to_a_bool() {
        // Zero exit → true, non-zero → false, un-spawnable → false. Uses the
        // harmless true/false shells, never a real authselect/pam-auth-update.
        assert!(run_cmd("true", &[]));
        assert!(!run_cmd("false", &[]));
        assert!(!run_cmd("irlume-no-such-command-xyz", &["arg"]));
    }

    #[test]
    fn pam_fprintd_wired_needs_an_active_line() {
        let dir = std::env::temp_dir().join(format!("irlume-fpwire-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Empty directory: nothing wired.
        assert!(!pam_fprintd_wired(&dir));
        // A commented-out line does not count.
        std::fs::write(dir.join("sudo"), "#auth sufficient pam_fprintd.so\n").unwrap();
        assert!(!pam_fprintd_wired(&dir));
        // Unrelated modules do not count.
        std::fs::write(dir.join("login"), "auth required pam_unix.so\n").unwrap();
        assert!(!pam_fprintd_wired(&dir));
        // An active line in any file does.
        std::fs::write(
            dir.join("system-local-login"),
            "auth  sufficient  pam_fprintd.so\nauth required pam_unix.so\n",
        )
        .unwrap();
        assert!(pam_fprintd_wired(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn faillock_cohabit_requires_both_modules_in_one_file() {
        let dir = std::env::temp_dir().join(format!("irlume-faillock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Modules in separate files: no cohabitation.
        std::fs::write(dir.join("a"), "auth required pam_faillock.so preauth\n").unwrap();
        std::fs::write(dir.join("b"), "auth sufficient pam_fprintd.so\n").unwrap();
        assert!(!faillock_cohabits(&dir));
        // Both in one stack: the lockout hazard exists.
        std::fs::write(
            dir.join("system-auth"),
            "auth required pam_faillock.so preauth\nauth sufficient pam_fprintd.so\n",
        )
        .unwrap();
        assert!(faillock_cohabits(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fprintd_in_sudo_follows_one_include_level() {
        let dir = std::env::temp_dir().join(format!("irlume-sudoinc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Not reachable: sudo includes a stack without fingerprint.
        std::fs::write(dir.join("sudo"), "auth include system-auth\n").unwrap();
        std::fs::write(dir.join("system-auth"), "auth required pam_unix.so\n").unwrap();
        assert!(!fprintd_in_sudo(&dir));
        // Fedora shape: sudo → system-auth → pam_fprintd.
        std::fs::write(
            dir.join("system-auth"),
            "auth sufficient pam_fprintd.so\nauth required pam_unix.so\n",
        )
        .unwrap();
        assert!(fprintd_in_sudo(&dir));
        // Debian shape: `@include common-auth`.
        std::fs::write(dir.join("sudo"), "@include common-auth\n").unwrap();
        std::fs::write(dir.join("common-auth"), "auth sufficient pam_fprintd.so\n").unwrap();
        assert!(fprintd_in_sudo(&dir));
        // Direct line in sudo itself.
        std::fs::write(dir.join("sudo"), "auth sufficient pam_fprintd.so\n").unwrap();
        assert!(fprintd_in_sudo(&dir));
        // Commented lines never count.
        std::fs::write(dir.join("sudo"), "#auth sufficient pam_fprintd.so\n").unwrap();
        std::fs::write(dir.join("common-auth"), "# pam_fprintd.so disabled\n").unwrap();
        assert!(!fprintd_in_sudo(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pam_fprintd_wired_is_false_for_a_missing_dir() {
        // The enable path must fail closed (method unchanged) when the PAM dir
        // cannot be read at all.
        assert!(!pam_fprintd_wired(std::path::Path::new(
            "/nonexistent-irlume-test-pam.d"
        )));
    }

    #[test]
    fn enroll_one_refuses_without_fprintd_or_a_reader() {
        // When the tooling or the sensor is missing, enrollment bails early with
        // false and never drives hardware. On a box that has both, this branch
        // isn't reachable without a live sensor, so it is skipped.
        if !fp::fprintd_present() || !fp::reader_present() {
            assert!(!enroll_one("irlume-nonexistent-test-user"));
        }
    }
}
