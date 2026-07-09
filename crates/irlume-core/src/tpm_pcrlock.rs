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
//! tss-esapi 7.x ships the `Esys_PolicyAuthorizeNV` binding but no safe wrapper,
//! so the policy session is driven through that raw FFI here.
//!
//! NOTE: implementation pending (task: Tier 2). The seal/unseal below return a
//! clear error until the raw-FFI path is wired and HW-validated against a real
//! pcrlock NV index.

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
