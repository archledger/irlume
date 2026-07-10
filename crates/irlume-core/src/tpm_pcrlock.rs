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
//! EXACT SEAL/UNSEAL SPEC (verified 2026-07-09 against systemd main
//! src/shared/tpm2-util.c + src/pcrlock/pcrlock.c). The two sides are
//! deliberately ASYMMETRIC; getting this wrong yields "seals but never unseals".
//!
//! pcrlock.json (/var/lib/systemd/pcrlock.json) fields to read: `pcrBank` (hash
//! alg), `pcrValues` (per-PCR allowed-value prediction, ≤8 each), `nvIndex`
//! (u32), `nvHandle` (base64 serialized ESYS_TR), `nvPublic` (base64 marshalled
//! TPM2B_NV_PUBLIC), `srkHandle`.
//!
//! SEAL (pure software policy calc, then Create under the SRK):
//!   1. Unmarshal `nvPublic` → TPM2B_NV_PUBLIC; copy it and set TPMA_NV_WRITTEN
//!      (CRITICAL: the index's Name uses the *written* public; omit and it never
//!      unseals).
//!   2. nvName = 0x000B ‖ SHA256(marshal(TPMS_NV_PUBLIC_with_WRITTEN)).
//!   3. authPolicy = SHA256( zero32 ‖ TPM_CC_PolicyAuthorizeNV(0x00000192, 4B BE)
//!      ‖ nvName ).  This is the WHOLE policy — NO PolicyPCR term (PolicyAuthorizeNV
//!      resets the running digest, discarding any prior PCR work).
//!   4. Esys_Create under SRK: inPublic.authPolicy = authPolicy, policy-only
//!      (clear userWithAuth), sensitive = secret. Store public/private in the
//!      envelope with PolicyKind::PcrlockNv { nv_index }.
//!
//! UNSEAL (real policy session):
//!   1. StartAuthSession TPM2_SE_POLICY, SHA256.
//!   2. Esys_TR_Deserialize(nvHandle) → NV ESYS_TR.
//!   3. Super-PCR replay reproducing what make-policy WROTE into the index (a
//!      single marshalled TPMT_HA = the "super PCR" digest): from a zero digest,
//!      one PolicyPCR over all SINGLE-value PCRs, then for each MULTI-value PCR
//!      (ascending) a PolicyPCR followed by a PolicyOR over its ≤8 precomputed
//!      branch digests. Bank = `pcrBank`, values from `pcrValues`.
//!   4. policy_authorize_nv(policy_session, authHandle = ESYS_TR_RH_OWNER with
//!      ESYS_TR_PASSWORD (empty owner auth; the index is TPMA_NV_OWNERREAD),
//!      nv_index = deserialized handle). Compares the session digest to the NV
//!      content and, on match, resets it to the authPolicy term of SEAL step 3.
//!   5. Esys_Unseal with the session.
//!   Failure at step 4 with TPM2_RC_VALUE (systemd EREMCHG) ⇒ the step-3 PCR
//!   replay didn't reproduce the stored digest; at step 5 ⇒ wrong Name (usually
//!   the missing WRITTEN bit).
//!
//! STATUS: implementation pending HW validation. The seal/unseal below return a
//! clear error. The required wrapper `Context::policy_authorize_nv` is absent
//! from released tss-esapi; a patched fork adding it exists at
//! archledger/rust-tss-esapi @ policy-authorize-nv (branched from v7.7.0,
//! compiles) and will be pinned via a workspace `[patch.crates-io]` in the same
//! commit that implements seal/unseal. The super-PCR replay and Name marshalling
//! are byte-exact-or-nothing and must be developed against a provisioned pcrlock
//! NV index on real hardware, not blind.

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
