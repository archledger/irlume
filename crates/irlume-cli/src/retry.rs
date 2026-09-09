// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Explicit face retry recovery, separate from template-key recovery.
use irlume_common::{Request, Response, SecretBytes};
use std::process::ExitCode;

const USAGE: &str = "usage: irlume retry <status|reset> [--user U]";

pub(super) fn run(sub: Option<&str>, args: &[String]) -> ExitCode {
    if args.len() == 2 && matches!(args[1].as_str(), "--help" | "-h") {
        println!("{USAGE}\nReset verifies your current local login password; root performs an administrator reset.");
        return ExitCode::SUCCESS;
    }
    let action = sub.unwrap_or("status");
    if !valid_arguments(action, args) {
        eprintln!("{USAGE} (supply at most one non-empty --user)");
        return ExitCode::from(2);
    }
    let user = crate::user_arg(args);
    match execute(action, &user) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("[retry] {error}");
            ExitCode::FAILURE
        }
    }
}

// A reset must not silently retarget an empty --user or accept contradictory
// positional arguments. Keep both established --user U and --user=U spellings,
// in either position, while rejecting unknown flags before daemon contact.
fn valid_arguments(action: &str, args: &[String]) -> bool {
    if !matches!(action, "status" | "reset") {
        return false;
    }
    let mut tokens = args.iter().skip(1);
    let (mut have_user, mut have_action) = (false, false);
    while let Some(token) = tokens.next() {
        let user = if token == "--user" {
            tokens.next().map(String::as_str)
        } else {
            token.strip_prefix("--user=")
        };
        if let Some(user) = user {
            if have_user || user.is_empty() || user.starts_with('-') {
                return false;
            }
            have_user = true;
        } else if token == action && !have_action {
            have_action = true;
        } else {
            return false;
        }
    }
    true
}

fn execute(action: &str, user: &str) -> Result<String, String> {
    // Negotiate before reading a password: older daemons have no reset path.
    let state = crate::daemon_request(&Request::RetryStatus { user: user.into() })
        .map_err(|error| format!("could not inspect retry state: {error}; use ordinary password login and check that the daemon supports retry recovery"))?;
    let Response::RetryStatus {
        failures,
        cooldown_seconds,
        recovery_failures,
        recovery_cooldown_seconds,
        recovery_required,
        password_reset_available,
        face_budget,
    } = state
    else {
        return Err("daemon does not support retry recovery or refused access to retry state; use ordinary password login and ask an administrator to check the daemon and account".into());
    };
    if action == "status" {
        let cumulative = match face_budget {
            Some(budget) => match budget.unsuccessful_requests {
                Some(count) => format!("Cumulative face requests: {count}/{} consecutive unsuccessful; {}.", budget.limit, if budget.reset_required { "password-verified retry reset required" } else { "available after any cooldown" }),
                None => format!("Cumulative face budget: prospective {}-request limit starts at the next admitted request; earlier history unknown.", budget.limit),
            },
            None => "Cumulative face budget unavailable from this daemon; enforcement unknown.".into(),
        };
        return Ok(format!("Face retry state for '{user}': {failures} recorded failures, {cooldown_seconds}s cooldown.\n{cumulative}\nPassword-verified retry reset: {}; {recovery_failures} failed checks, {recovery_cooldown_seconds}s cooldown.\nOrdinary password login remains available.",
            if recovery_required { "administrator reset required" } else if password_reset_available { "available for supported local accounts" } else { "unavailable on this installation" }));
    }
    // SAFETY: geteuid has no preconditions.
    let admin = unsafe { libc::geteuid() } == 0;
    if !admin && recovery_required {
        return Err("password-verified retry reset requires administrator repair or reset; use ordinary password login and ask an administrator".into());
    }
    if !admin && recovery_cooldown_seconds > 0 {
        return Err(format!("password-verified retry reset is rate limited for {recovery_cooldown_seconds}s; wait before retrying or use ordinary password login"));
    }
    if !admin && !password_reset_available {
        return Err("password-only retry reset is unavailable; use ordinary password login and ask an administrator".into());
    }
    let password = if admin {
        eprintln!("[retry] Administrator reset for '{user}'.");
        SecretBytes::new(Vec::new())
    } else {
        let password = crate::read_password("Current login password: ")?;
        if password.is_empty() || password.len() > 4096 || password.as_bytes().contains(&0) {
            return Err("password must contain 1–4096 bytes without NUL".into());
        }
        SecretBytes::new(password.as_bytes().to_vec())
    };
    match crate::daemon_request(&Request::RetryReset {
        user: user.into(),
        password,
    })? {
        Response::Ok(message) => Ok(message),
        Response::Error(error) => Err(error),
        _ => Err("unexpected reply; retry state reset was not confirmed".into()),
    }
}
