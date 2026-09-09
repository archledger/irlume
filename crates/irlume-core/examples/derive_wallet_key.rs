// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Print the KDE wallet key irlume would derive for an account.
//!
//! Exists so the handoff can be exercised end to end against a real `ksecretd`
//! using the SAME derivation the daemon seals, rather than a reimplementation
//! in the test that could agree with itself while both are wrong.
//!
//!   derive_wallet_key <user> <password>   # raw key bytes on stdout

fn main() {
    let mut a = std::env::args().skip(1);
    let (user, pw) = match (a.next(), a.next()) {
        (Some(user), Some(p)) => (user, p),
        _ => {
            eprintln!("usage: derive_wallet_key <user> <password>");
            std::process::exit(2);
        }
    };
    let salt = match irlume_common::client::read_wallet_salt(&user) {
        Ok(Some(salt)) => salt,
        Ok(None) => {
            eprintln!("derive: account has no KDE wallet salt");
            std::process::exit(3);
        }
        Err(e) => {
            eprintln!("derive: {e}");
            std::process::exit(1);
        }
    };
    match irlume_core::kwallet::derive_key(pw.as_bytes(), salt.expose()) {
        Ok(k) => {
            use std::io::Write;
            std::io::stdout().write_all(&k).expect("write key");
        }
        Err(e) => {
            eprintln!("derive: {e}");
            std::process::exit(1);
        }
    }
}
