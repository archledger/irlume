//! Tier 2: bind the sealed secret to a systemd-pcrlock NV-index policy via
//! `TPM2_PolicyAuthorizeNV`.
//!
//! `systemd-pcrlock make-policy` predicts the acceptable PCR states (PCR 0-7,
//! including the Secure Boot / dbx PCR 7) from the TPM event log and stores the
//! resulting policy in a TPM NV index. A sealed object whose `authPolicy` is a
//! `PolicyAuthorizeNV` over that index unseals whenever the live PCRs satisfy
//! the policy the index currently holds. After a firmware / Secure Boot update
//! the admin (or a packaging hook) re-runs `make-policy`, which rewrites the NV
//! index; no reseal of our object required. This is the GRUB2 answer to PCR 7
//! drift that the signed-UKI path (Tier 1) can't cover.
//!
//! Implementation path (scoped 2026-07-09 against tss-esapi 7.7.0 + systemd 259):
//!
//! 1. `TPM2_PolicyAuthorizeNV` has NO safe wrapper in tss-esapi (7.7.0, the
//!    latest release, has `policy_authorize`/`policy_pcr`/`policy_secret` but
//!    not `policy_authorize_nv` nor `policy_nv`). The raw `Esys_PolicyAuthorizeNV`
//!    binding exists in tss-esapi-sys, BUT it needs the `*mut ESYS_CONTEXT` and
//!    the `optional_session_*` handles, which are CRATE-PRIVATE on
//!    `tss_esapi::Context` (`mut_context()` is private, no public accessor). So
//!    the "drive it via raw FFI from here" plan is not possible from this crate.
//!    The correct path is to add the safe `policy_authorize_nv` wrapper to
//!    tss-esapi upstream (mirror `Context::policy_authorize`, ~15 lines),
//!    PR it to parallaxsecond/rust-tss-esapi, and use a `[patch.crates-io]`
//!    git/fork dependency until it releases.
//!
//! 2. systemd-pcrlock `make-policy` allocates the NV index dynamically (index +
//!    TPM info recorded in `/var/lib/systemd/pcrlock.json`; the index carries a
//!    self-referential policy binding it to itself, which is the `authHandle`
//!    for PolicyAuthorizeNV). Read that JSON for the live NV index.
//!
//! 3. `seal_pcrlock`: sealed object's `authPolicy` = the PolicyAuthorizeNV policy
//!    digest over the NV index (compute via a trial policy session running the
//!    new wrapper); create the object with that policy (mirror `seal_with_pcrs`).
//!
//! 4. `unseal_pcrlock`: load the object, start a Policy session, run
//!    `policy_authorize_nv(authHandle=nv, nvIndex=nv, session)`, unseal.
//!
//! 5. HW-validate on a provisioned box: seal → unseal, then re-run `make-policy`
//!    (rewrites the NV index) and confirm the SAME object still unseals without
//!    a reseal (the whole point vs. the literal PCR-7 seal).
//!
//! NOTE: implementation pending (task: Tier 2). The seal/unseal below return a
//! clear error until the upstream wrapper lands and the path is HW-validated.

use crate::envelope::SealedEnvelope;
use irlume_common::{Error, Result};
use zeroize::Zeroizing;

pub fn seal_pcrlock(_secret: &[u8], _nv_index: u32) -> Result<SealedEnvelope> {
    Err(Error::Policy(
        "pcrlock seal not yet implemented (provision with `systemd-pcrlock make-policy` first)"
            .into(),
    ))
}

pub fn unseal_pcrlock(_env: &SealedEnvelope, _nv_index: u32) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::Policy("pcrlock unseal not yet implemented".into()))
}
