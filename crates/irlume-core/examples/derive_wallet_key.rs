// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Print the KDE wallet key irlume would derive for a home directory.
//!
//! Exists so the handoff can be exercised end to end against a real `ksecretd`
//! using the SAME derivation the daemon seals, rather than a reimplementation
//! in the test that could agree with itself while both are wrong.
//!
//!   derive_wallet_key <home> <password>   # raw key bytes on stdout

fn main() {
    let mut a = std::env::args().skip(1);
    let (home, pw) = match (a.next(), a.next()) {
        (Some(h), Some(p)) => (h, p),
        _ => {
            eprintln!("usage: derive_wallet_key <home> <password>");
            std::process::exit(2);
        }
    };
    match irlume_core::kwallet::derive_for_home(pw.as_bytes(), std::path::Path::new(&home)) {
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
