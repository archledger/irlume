//! `irlume recovery <status|setup|restore|forget>`: manage the recovery
//! passphrase that backs up the per-user template key (the AES key encrypting
//! enrolled faces at rest). It's the manual backstop for when the TPM seal can
//! no longer be satisfied: Secure Boot off, TPM cleared, a dbx/firmware PCR
//! move, or the disk moved to another machine. Talks to `irlumed`, which owns
//! the TPM and the root-only key store.

use irlume_common::{Request, Response, SecretBytes};
use std::process::ExitCode;

use crate::daemon_request;

pub fn run(sub: Option<&str>, args: &[String]) -> ExitCode {
    let user = crate::user_arg(args);
    match sub {
        None | Some("status") => status(&user),
        Some("setup") => setup(&user),
        Some("restore") => restore(&user),
        Some("forget") => forget(&user),
        _ => {
            eprintln!("usage: irlume recovery <status|setup|restore|forget> [--user U]");
            ExitCode::from(2)
        }
    }
}

fn status(user: &str) -> ExitCode {
    match daemon_request(&Request::RecoveryStatus { user: user.into() }) {
        Ok(Response::RecoveryStatus {
            encrypted,
            recovery_set,
            tpm_present,
        }) => {
            println!("[recovery] '{user}':");
            println!(
                "  templates encrypted : {}",
                if encrypted {
                    "yes ✓ (template key sealed in the TPM)"
                } else {
                    "no (plaintext at rest)"
                }
            );
            println!(
                "  recovery passphrase : {}",
                if recovery_set { "SET ✓" } else { "not set" }
            );
            println!(
                "  TPM present         : {}",
                if tpm_present {
                    "yes"
                } else {
                    "no (templates stay plaintext on this host)"
                }
            );
            if encrypted && !recovery_set {
                println!("  → no backstop: if the TPM seal breaks (dbx/firmware update, TPM clear, disk move),");
                println!("    you'd have to re-enroll. Set one now:  irlume recovery setup");
            }
            ExitCode::SUCCESS
        }
        Ok(other) => {
            eprintln!("[recovery] unexpected response: {other:?}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[recovery] status failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn setup(user: &str) -> ExitCode {
    println!(
        "[recovery] Setting a recovery passphrase for '{user}'.\n\
         This wraps the face-template key so you can restore it after a TPM clear,\n\
         firmware/dbx update, or disk move, WITHOUT re-enrolling. It is separate\n\
         from your login password; store it somewhere safe (like a BitLocker/LUKS key)."
    );
    let Some(pass) = read_passphrase_confirmed() else {
        return ExitCode::from(2);
    };
    match daemon_request(&Request::RecoverySetup {
        user: user.into(),
        passphrase: SecretBytes::new(pass.into_bytes()),
    }) {
        Ok(Response::Ok(msg)) => {
            println!("[recovery] ✓ {msg}");
            ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!("[recovery] setup failed: {e}");
            if e.contains("no template key") {
                eprintln!("[recovery] (templates aren't encrypted yet; enroll a face first, then re-run this.)");
            }
            ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("[recovery] unexpected response: {other:?}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[recovery] setup failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn restore(user: &str) -> ExitCode {
    println!("[recovery] Restoring '{user}'s template key from the recovery passphrase and re-sealing it to this machine's TPM.");
    let Some(pass) = read_passphrase_once("Recovery passphrase: ") else {
        return ExitCode::from(2);
    };
    match daemon_request(&Request::RecoveryRestore {
        user: user.into(),
        passphrase: SecretBytes::new(pass.into_bytes()),
    }) {
        Ok(Response::Ok(msg)) => {
            println!("[recovery] ✓ {msg}");
            println!(
                "[recovery] Encrypted face templates are readable again; face unlock is restored."
            );
            ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!("[recovery] restore failed: {e}");
            ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("[recovery] unexpected response: {other:?}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[recovery] restore failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn forget(user: &str) -> ExitCode {
    match daemon_request(&Request::RecoveryForget { user: user.into() }) {
        Ok(Response::Ok(msg)) => {
            println!("[recovery] {msg}");
            ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!("[recovery] forget failed: {e}");
            ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("[recovery] unexpected response: {other:?}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[recovery] forget failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// No-echo passphrase prompt with confirmation (for `setup`); falls back to a
/// plain stdin line when piped (scripts / tests).
fn read_passphrase_confirmed() -> Option<String> {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let first = rpassword::prompt_password("Recovery passphrase: ").ok()?;
        let confirm = rpassword::prompt_password("Confirm recovery passphrase: ").ok()?;
        if first != confirm {
            eprintln!("[recovery] passphrases do not match; aborted (nothing set).");
            return None;
        }
        if first.is_empty() {
            eprintln!("[recovery] empty passphrase; aborted.");
            return None;
        }
        Some(first)
    } else {
        read_piped_line()
    }
}

fn read_passphrase_once(prompt: &str) -> Option<String> {
    let pass = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        rpassword::prompt_password(prompt).ok()?
    } else {
        read_piped_line()?
    };
    if pass.is_empty() {
        eprintln!("[recovery] empty passphrase; aborted.");
        return None;
    }
    Some(pass)
}

fn read_piped_line() -> Option<String> {
    use std::io::BufRead;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).ok()?;
    Some(line.trim_end_matches(['\n', '\r']).to_string())
}
