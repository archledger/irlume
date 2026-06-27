//! TPM 2.0 sealing of the unlock secret (not the template).
//!
//! We seal a secret — the user's login password, used to unlock the
//! GNOME-keyring / KWallet after a face login — into the TPM under a
//! `PolicyPCR` over PCR 7 (the UEFI Secure Boot state). The TPM releases it only
//! while the machine boots in the same Secure Boot configuration it was sealed
//! under; `irlumed` then asks for it only after a successful live+match. This
//! mirrors Windows Hello's TPM-bound credential model and gives revocability:
//! re-seal under a fresh secret to revoke.
//!
//! Ported from linhello's literal-PolicyPCR path (the proven, self-contained
//! half of its TPM core). linhello additionally supports a signed
//! `PolicyAuthorize` policy that survives kernel updates without a re-seal; that
//! is deliberately NOT ported here yet. PCR 7 is stable across kernel updates
//! (it only moves on Secure Boot key / dbx changes), so a literal PCR-7 seal is
//! robust for day-to-day use; a Secure Boot config change requires a re-seal
//! (the daemon falls back to the password and the user re-arms keyring unlock).
//!
//! Every transient handle (SRK, loaded sealed object, trial/policy session) is
//! flushed on both success and error paths via the scope helpers below. TPMs
//! expose only a handful of session/transient-object slots, so leaking them
//! bricks the daemon after a few operations.

use crate::envelope::{PcrValue, SealedEnvelope};
use irlume_common::{Error, Result};
use std::convert::TryFrom;
use std::str::FromStr;
use zeroize::Zeroizing;

use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, SessionHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Auth, Digest, KeyedHashScheme, PcrSelectionList, PcrSelectionListBuilder, PcrSlot, Private,
    Public, PublicBuilder, PublicKeyedHashParameters, PublicRsaParameters, RsaExponent, RsaScheme,
    SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::ESYS_TR;
use tss_esapi::{Context, TctiNameConf};

const TCTI_DEFAULT: &str = "device:/dev/tpmrm0";

/// PCRs the secret is bound to by default: PCR 7 = UEFI Secure Boot policy.
/// Stable across kernel updates; moves only on Secure Boot key / dbx changes.
/// Override with `IRLUME_PCRS` (comma-separated, e.g. "7" or "0,7").
const DEFAULT_PCRS: &[u32] = &[7];

/// Owner-hierarchy persistent handle where irlume caches its SRK. In the owner
/// persistent range (0x81000000–0x817FFFFF), deliberately distinct from the
/// conventional 0x81000001 SRK and from linhello's 0x81010001, so we never
/// collide with another stack's storage key. Override with `IRLUME_SRK_HANDLE`
/// (hex) if needed.
const PERSISTENT_SRK_HANDLE: u32 = 0x8101_0002;

fn tpm_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Tpm(e.to_string())
}

fn open_context() -> Result<Context> {
    let tcti = std::env::var("IRLUME_TCTI").unwrap_or_else(|_| TCTI_DEFAULT.into());
    let conf = TctiNameConf::from_str(&tcti).map_err(tpm_err)?;
    Context::new(conf).map_err(tpm_err)
}

/// The PCRs to bind to: `IRLUME_PCRS` (comma-separated) or [`DEFAULT_PCRS`].
pub fn policy_pcrs() -> Vec<u32> {
    std::env::var("IRLUME_PCRS")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|p| p.trim().parse::<u32>().ok())
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_PCRS.to_vec())
}

fn pcr_selection(pcrs: &[u32]) -> Result<PcrSelectionList> {
    let slots: Vec<PcrSlot> = pcrs.iter().map(|&p| pcr_slot(p)).collect::<Result<_>>()?;
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots)
        .build()
        .map_err(tpm_err)
}

fn pcr_slot(index: u32) -> Result<PcrSlot> {
    Ok(match index {
        0 => PcrSlot::Slot0,
        1 => PcrSlot::Slot1,
        2 => PcrSlot::Slot2,
        3 => PcrSlot::Slot3,
        4 => PcrSlot::Slot4,
        5 => PcrSlot::Slot5,
        6 => PcrSlot::Slot6,
        7 => PcrSlot::Slot7,
        8 => PcrSlot::Slot8,
        9 => PcrSlot::Slot9,
        10 => PcrSlot::Slot10,
        11 => PcrSlot::Slot11,
        12 => PcrSlot::Slot12,
        13 => PcrSlot::Slot13,
        14 => PcrSlot::Slot14,
        15 => PcrSlot::Slot15,
        16 => PcrSlot::Slot16,
        23 => PcrSlot::Slot23,
        other => return Err(Error::Tpm(format!("unsupported PCR {other}"))),
    })
}

fn srk_template() -> Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(tpm_err)?;

    let params = PublicRsaParameters::new(
        SymmetricDefinitionObject::AES_128_CFB,
        RsaScheme::create(RsaSchemeAlgorithm::Null, None).map_err(tpm_err)?,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    );

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_rsa_parameters(params)
        .with_rsa_unique_identifier(tss_esapi::structures::PublicKeyRsa::default())
        .build()
        .map_err(tpm_err)
}

/// Read the SHA-256 values for `pcrs` and return them in the same order, stashed
/// in the envelope so an unseal failure can point at the PCR that shifted.
fn read_pcr_values(ctx: &mut Context, pcrs: &[u32]) -> Result<Vec<PcrValue>> {
    let mut out = Vec::with_capacity(pcrs.len());
    for &p in pcrs {
        let sel = pcr_selection(&[p])?;
        let (_c, _s, digests) = ctx.pcr_read(sel).map_err(tpm_err)?;
        let value = digests
            .value()
            .first()
            .map(|d| d.value().to_vec())
            .unwrap_or_default();
        out.push(PcrValue { pcr: p, value });
    }
    Ok(out)
}

/// Run `body` with an auth session of `kind`; flush the session on the way out
/// regardless of whether `body` succeeded.
fn with_session<T>(
    ctx: &mut Context,
    kind: SessionType,
    body: impl FnOnce(&mut Context, AuthSession) -> Result<T>,
) -> Result<T> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            kind,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(tpm_err)?
        .ok_or_else(|| Error::Tpm("start_auth_session returned None".into()))?;
    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    if let Err(e) = ctx.tr_sess_set_attributes(session, attrs, mask) {
        let _ = ctx.flush_context(SessionHandle::from(session).into());
        return Err(tpm_err(e));
    }
    let result = body(ctx, session);
    ctx.clear_sessions();
    let _ = ctx.flush_context(SessionHandle::from(session).into());
    result
}

/// Compute the PolicyPCR digest for a given PCR selection using a trial session.
/// The digest is what the sealed object commits to.
fn compute_policy_digest(ctx: &mut Context, pcrs: Option<&PcrSelectionList>) -> Result<Digest> {
    with_session(ctx, SessionType::Trial, |ctx, session| {
        if let Some(sel) = pcrs {
            let policy = PolicySession::try_from(session).map_err(tpm_err)?;
            ctx.policy_pcr(policy, Digest::default(), sel.clone())
                .map_err(tpm_err)?;
        }
        let policy = PolicySession::try_from(session).map_err(tpm_err)?;
        ctx.policy_get_digest(policy).map_err(tpm_err)
    })
}

fn sealed_template(policy_digest: Digest) -> Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .build()
        .map_err(tpm_err)?;

    let params = PublicKeyedHashParameters::new(KeyedHashScheme::Null);

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_auth_policy(policy_digest)
        .with_keyed_hash_parameters(params)
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(tpm_err)
}

fn create_srk(ctx: &mut Context) -> Result<KeyHandle> {
    let tmpl = srk_template()?;
    let primary = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, tmpl, None, None, None, None)
        })
        .map_err(tpm_err)?;
    Ok(primary.key_handle)
}

fn persistent_srk_handle() -> Result<PersistentTpmHandle> {
    let raw = std::env::var("IRLUME_SRK_HANDLE")
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(PERSISTENT_SRK_HANDLE);
    PersistentTpmHandle::new(raw).map_err(tpm_err)
}

/// True iff `public` is irlume's own SRK — RSA, our [`srk_template`] attributes,
/// SHA-256 name hash, an empty authPolicy, and a 2048-bit key. A non-match means
/// another stack's key is squatting our persistent handle (clevis /
/// systemd-cryptenroll keys carry a non-empty authPolicy, and may be ECC), so it
/// fails the comparison and we fall back to a transient SRK.
fn is_irlume_srk(public: &Public) -> Result<bool> {
    let Public::Rsa {
        object_attributes,
        name_hashing_algorithm,
        auth_policy,
        parameters,
        ..
    } = public
    else {
        return Ok(false);
    };
    let Public::Rsa {
        object_attributes: want_attrs,
        name_hashing_algorithm: want_hash,
        auth_policy: want_policy,
        parameters: want_params,
        ..
    } = srk_template()?
    else {
        return Ok(false);
    };
    // Compare key size, not the whole `parameters` struct: a TPM normalizes the
    // template's default RSA exponent (0) to 65537 on read-back, so a full
    // equality check would reject our OWN key and force the slow transient path
    // on every call. Attributes + empty authPolicy + RSA-2048 is already an
    // unambiguous signature.
    Ok(*object_attributes == want_attrs
        && *name_hashing_algorithm == want_hash
        && *auth_policy == want_policy
        && parameters.key_bits() == want_params.key_bits())
}

/// Get irlume's SRK, persisting it on first use.
///
/// `create_primary` over [`srk_template`] is deterministic, but deriving an
/// RSA-2048 primary costs >10s on slow firmware TPMs — too slow for the PAM
/// client timeout on every unseal. We derive it once and `evict_control` it to a
/// persistent handle; every later call just loads that handle. The persisted key
/// is bit-for-bit identical, so envelopes sealed earlier still load.
///
/// Returns the handle and whether it is persistent (a persistent handle must NOT
/// be flushed by the caller).
fn load_or_create_srk(ctx: &mut Context) -> Result<(KeyHandle, bool)> {
    let persistent = persistent_srk_handle()?;

    if let Ok(object) = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)) {
        let key_handle = KeyHandle::from(ESYS_TR::from(object));
        let is_ours = match ctx.read_public(key_handle) {
            Ok((public, _, _)) => is_irlume_srk(&public)?,
            Err(_) => false,
        };
        if is_ours {
            // A handle obtained via tr_from_tpm_public starts with no tracked
            // auth; our SRK was created with an empty authValue, so tell ESYS so
            // loading a child under it doesn't fail with TPM_RC_AUTH_UNAVAILABLE.
            ctx.tr_set_auth(object, Auth::default()).map_err(tpm_err)?;
            return Ok((key_handle, true));
        }
        // Persistent handle occupied by a foreign key: leave it untouched and
        // use a transient SRK this run (correct, just slower).
        let transient = create_srk(ctx)?;
        return Ok((transient, false));
    }

    // First run: derive the primary (one-time slow step) and persist it.
    let transient = create_srk(ctx)?;
    let persisted = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                Provision::Owner,
                transient.into(),
                Persistent::Persistent(persistent),
            )
        })
        .map_err(tpm_err)?;
    let _ = ctx.flush_context(transient.into());
    ctx.tr_set_auth(persisted, Auth::default()).map_err(tpm_err)?;
    Ok((KeyHandle::from(ESYS_TR::from(persisted)), true))
}

/// Run `body` with irlume's persistent SRK as parent. Never flushes the SRK when
/// persistent — persistence is the whole point (avoids re-deriving a slow RSA
/// primary on every call).
fn with_srk<T>(
    ctx: &mut Context,
    body: impl FnOnce(&mut Context, &KeyHandle) -> Result<T>,
) -> Result<T> {
    let (srk, persistent) = load_or_create_srk(ctx)?;
    let result = body(ctx, &srk);
    if !persistent {
        let _ = ctx.flush_context(srk.into());
    }
    result
}

/// Seal `secret` under a literal `PolicyPCR` over the configured PCRs
/// ([`policy_pcrs`]).
pub fn seal(secret: &[u8]) -> Result<SealedEnvelope> {
    seal_with_pcrs(secret, &policy_pcrs())
}

/// Seal `secret` under a literal `PolicyPCR` over `pcrs` (empty ⇒ no binding —
/// any boot state can unseal; use only for testing).
pub fn seal_with_pcrs(secret: &[u8], pcrs: &[u32]) -> Result<SealedEnvelope> {
    let pcrs = pcrs.to_vec();
    let mut ctx = open_context()?;
    let pcr_values = read_pcr_values(&mut ctx, &pcrs)?;

    with_srk(&mut ctx, |ctx, srk| {
        let selection = if pcrs.is_empty() {
            None
        } else {
            Some(pcr_selection(&pcrs)?)
        };
        let policy_digest = compute_policy_digest(ctx, selection.as_ref())?;
        let tmpl = sealed_template(policy_digest)?;

        let sensitive = SensitiveData::try_from(secret.to_vec()).map_err(tpm_err)?;
        let created = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create(*srk, tmpl, None, Some(sensitive), None, None)
            })
            .map_err(tpm_err)?;

        Ok(SealedEnvelope {
            version: crate::envelope::CURRENT_VERSION,
            pcrs: pcrs.clone(),
            public: created.out_public.marshall().map_err(tpm_err)?,
            private: created.out_private.to_vec(),
            pcr_values: pcr_values.clone(),
        })
    })
}

/// Release the sealed secret iff the bound PCR policy is satisfied.
#[allow(clippy::redundant_closure_call)]
pub fn unseal(env: &SealedEnvelope) -> Result<Zeroizing<Vec<u8>>> {
    let mut ctx = open_context()?;

    with_srk(&mut ctx, |ctx, srk| {
        let public = Public::unmarshall(&env.public).map_err(tpm_err)?;
        let private = Private::try_from(env.private.clone()).map_err(tpm_err)?;

        let sealed_handle = ctx
            .execute_with_nullauth_session(|ctx| ctx.load(*srk, private, public))
            .map_err(tpm_err)?;

        // Scoped fallible region so the loaded object is flushed on every exit.
        let result: Result<Zeroizing<Vec<u8>>> = (|| {
            with_session(ctx, SessionType::Policy, |ctx, session| {
                if !env.pcrs.is_empty() {
                    let sel = pcr_selection(&env.pcrs)?;
                    let policy = PolicySession::try_from(session).map_err(tpm_err)?;
                    ctx.policy_pcr(policy, Digest::default(), sel)
                        .map_err(tpm_err)?;
                }
                let data = ctx
                    .execute_with_session(Some(session), |ctx| ctx.unseal(sealed_handle.into()))
                    .map_err(|e| policy_aware_err(e, env))?;
                Ok(Zeroizing::new(data.to_vec()))
            })
        })();

        let _ = ctx.flush_context(sealed_handle.into());
        result
    })
}

/// If the TSS error looks like a policy mismatch, enrich it with the list of
/// PCRs that have changed since seal time.
fn policy_aware_err<E: std::fmt::Display>(e: E, env: &SealedEnvelope) -> Error {
    let base = e.to_string();
    match diagnose_pcrs(env) {
        Ok(changed) if !changed.is_empty() => {
            Error::Policy(format!("{base}: PCR mismatch: {changed:?} changed since seal"))
        }
        _ => Error::Tpm(base),
    }
}

/// Compare current PCR values against those stored in the envelope. Returns the
/// PCRs whose SHA-256 differs (empty ⇒ no drift, or no values captured at seal).
pub fn diagnose_pcrs(env: &SealedEnvelope) -> Result<Vec<u32>> {
    if env.pcr_values.is_empty() {
        return Ok(Vec::new());
    }
    let mut ctx = open_context()?;
    let current = read_pcr_values(&mut ctx, &env.pcrs)?;
    Ok(env
        .pcr_values
        .iter()
        .zip(current.iter())
        .filter(|(expected, now)| expected.pcr == now.pcr && expected.value != now.value)
        .map(|(expected, _)| expected.pcr)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srk_identity_match_accepts_ours_rejects_foreign() {
        assert!(is_irlume_srk(&srk_template().unwrap()).unwrap());
        let sealed = sealed_template(Digest::default()).unwrap();
        assert!(!is_irlume_srk(&sealed).unwrap());
    }

    #[test]
    fn policy_pcrs_parses_env() {
        // Default when unset is PCR 7.
        std::env::remove_var("IRLUME_PCRS");
        assert_eq!(policy_pcrs(), vec![7]);
    }

    /// Real seal→unseal round-trip on the host TPM. Ignored by default: needs
    /// /dev/tpmrm0 and write access (run as root or a tss-group member).
    #[test]
    #[ignore = "requires real TPM (/dev/tpmrm0); run as root"]
    fn seal_unseal_roundtrip_real_tpm() {
        let secret = b"irlume-keyring-secret-roundtrip!";
        let env = seal_with_pcrs(secret, &[7]).expect("seal");
        let got = unseal(&env).expect("unseal");
        assert_eq!(&*got, secret, "round-trip must match");
    }
}
