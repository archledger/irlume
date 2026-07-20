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
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some("enable") => enable(&user),
        Some("disable") => disable(),
        _ => {
            eprintln!("usage: irlume fingerprint [--user U] <status|add|enable|disable>");
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
    let reader = match fp::device_name() {
        Some(n) => n,
        None if fp::reader_present() => "present (unnamed)".into(),
        None => "none detected".into(),
    };
    println!("[fingerprint] reader         : {reader}");
    let fingers = fp::enrolled_fingers(user);
    if fingers.is_empty() {
        println!("[fingerprint] enrolled       : none for '{user}'");
    } else {
        println!(
            "[fingerprint] enrolled       : {} ({})",
            fingers.len(),
            fingers.join(", ")
        );
    }
    println!(
        "[fingerprint] active method   : {}",
        policy::method().as_str()
    );
    // Recommendation.
    if !fp::available() {
        println!("  → no usable reader; fingerprint unavailable on this device");
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
        DistroFamily::Arch | DistroFamily::Other => {
            println!("[fingerprint] On this distro, add  'auth sufficient pam_fprintd.so'  above pam_unix");
            println!("              in your login/sudo PAM stacks (e.g. /etc/pam.d/system-local-login, /etc/pam.d/sudo).");
            true // method still recorded below; manual stanza is the user's step
        }
    };
    if !wired {
        eprintln!("[fingerprint] failed to wire pam_fprintd; check the command output above");
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
    fn enroll_one_refuses_without_fprintd_or_a_reader() {
        // When the tooling or the sensor is missing, enrollment bails early with
        // false and never drives hardware. On a box that has both, this branch
        // isn't reachable without a live sensor, so it is skipped.
        if !fp::fprintd_present() || !fp::reader_present() {
            assert!(!enroll_one("irlume-nonexistent-test-user"));
        }
    }
}
