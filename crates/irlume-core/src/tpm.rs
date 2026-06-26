//! TPM 2.0 sealing of the unlock secret (not the template).
//!
//! Seal a random release secret (or the user's password) into the TPM, gated by
//! a PCR policy reflecting trusted boot/software state. Unseal only on a
//! successful live+match. This mirrors Windows Hello's TPM-bound credential
//! model and gives revocability: re-seal under a fresh secret to revoke.
//!
//! Implementation: `tss-esapi` against /dev/tpmrm0. Consider combining the PCR
//! policy with a PolicyAuthValue (PIN) for two-factor unseal.

/// Opaque handle to a sealed object.
pub struct SealedSecret { /* TODO: persistent handle / blob */ }

/// Seal `secret` under the current PCR policy.
pub fn seal(_secret: &[u8]) -> irlume_common::Result<SealedSecret> {
    todo!("tss-esapi: create keyedhash sealed object under PolicyPCR")
}

/// Release the sealed secret iff PCR policy is satisfied.
pub fn unseal(_sealed: &SealedSecret) -> irlume_common::Result<Vec<u8>> {
    todo!("tss-esapi: tpm2_unseal under policy session")
}
