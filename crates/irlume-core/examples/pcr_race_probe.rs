// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Seal once, then unseal repeatedly, reporting how many unseals failed.
//!
//! The harness for `scripts/tpm-pcr-race-swtpm.sh`, which runs this against a
//! software TPM while extending unbound PCRs, so the global `pcrUpdateCounter`
//! moves underneath an open policy session. That produces
//! `TPM2_RC_PCR_CHANGED`, the transient failure a fast post-reboot login hits
//! when systemd extends a PCR during the unseal, and which was reaching the
//! user as a keyring password prompt.
//!
//! A software TPM rather than real silicon because there is no PCR that is
//! both safe to extend on a live machine and able to move the counter: PCR 23
//! is TCG "Application Support", shared with other TPM consumers, so extending
//! it can invalidate objects irlume cannot enumerate.
//!
//! Deliberately an example, not a binary target: it seals to the TPM and must
//! never ship in a package.
//!
//!   cargo build --release -p irlume-core --example pcr_race_probe
//!   IRLUME_KEYRING_DIR=/tmp/x target/release/examples/pcr_race_probe 20

use irlume_core::{keyring, tpm};

fn main() -> std::process::ExitCode {
    let rounds: u32 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(20);

    let user = "pcr-race-probe";
    // Generated, not a literal, and generated without a zeroed buffer in the
    // way: a literal here reads as a hard-coded credential to a scanner, and
    // `[0u8; 32]` filled afterwards still leaves the literal in the dataflow
    // even though nothing ever uses those zeros. A fresh secret per run also
    // means a stale envelope from an earlier run cannot satisfy the readback
    // check below.
    let secret: [u8; 32] = rand::random();
    let secret = &secret;

    if let Err(e) = keyring::seal_password(user, secret) {
        eprintln!("seal failed: {e}");
        return std::process::ExitCode::FAILURE;
    }
    let env_path = keyring::envelope_path(user);
    let env = match irlume_core::envelope::SealedEnvelope::load(&env_path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("envelope load failed: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    println!(
        "sealed at {} ({})",
        env_path.display(),
        env.policy.describe()
    );

    let mut failures = 0u32;
    let mut wrong = 0u32;
    for i in 1..=rounds {
        match tpm::unseal(&env) {
            Ok(got) => {
                // Never just "it returned Ok": a retry that resumed a broken
                // session could plausibly hand back something else, and an
                // unseal whose bytes are wrong is worse than one that failed.
                if got.as_slice() != secret.as_slice() {
                    wrong += 1;
                    eprintln!("round {i}: unsealed the WRONG bytes");
                }
            }
            Err(e) => {
                failures += 1;
                let tag = if tpm::is_pcr_changed_race(&e) {
                    "unretried-race"
                } else {
                    "other"
                };
                eprintln!("round {i}: unseal failed [{tag}]: {e}");
            }
        }
    }

    let _ = keyring::forget_password(user);
    println!("rounds={rounds} failures={failures} wrong_bytes={wrong}");
    if failures == 0 && wrong == 0 {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
