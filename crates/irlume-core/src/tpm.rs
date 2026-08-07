// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! TPM 2.0 sealing of the unlock secret (not the template).
//!
//! We seal a secret (the user's login password, used to unlock the
//! GNOME-keyring / KWallet after a face login) into the TPM under a
//! measured-boot policy. The TPM releases it only while the machine boots in a
//! state the policy accepts; `irlumed` then asks for it only after a
//! successful live+match. This mirrors Windows Hello's TPM-bound credential
//! model and gives revocability: re-seal under a fresh secret to revoke.
//!
//! [`seal`] picks the strongest policy the machine supports (the tier ladder):
//! a signed `PolicyAuthorize` over systemd's PCR signature (Tier 1, survives
//! kernel updates), `PolicyAuthorizeNV` against a provisioned systemd-pcrlock
//! NV index (Tier 2, survives firmware / Secure Boot updates once the admin
//! re-runs `make-policy`), or a literal `PolicyPCR` over PCR 7 (Tier 3, the
//! universal fallback; a Secure Boot config change requires a re-arm, and the
//! daemon falls back to the typed password until then).
//!
//! Every transient handle (SRK, loaded sealed object, trial/policy session) is
//! flushed on both success and error paths via the scope helpers below. TPMs
//! expose only a handful of session/transient-object slots, so leaking them
//! bricks the daemon after a few operations.

use crate::envelope::{PcrValue, PolicyKind, SealedEnvelope};
use irlume_common::{Error, Result};
use sha2::{Digest as _, Sha256};
use std::convert::TryFrom;
use std::str::FromStr;
use zeroize::Zeroizing;

use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{
    KeyHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle, PersistentTpmHandle, SessionHandle,
    TpmHandle,
};
use tss_esapi::interface_types::algorithm::{
    HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm,
};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::{Hierarchy, NvAuth, Provision};
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Auth, Digest, DigestList, KeyedHashScheme, Nonce, PcrSelectionList, PcrSelectionListBuilder,
    PcrSlot, Private, Public, PublicBuilder, PublicKeyRsa, PublicKeyedHashParameters,
    PublicRsaParameters, RsaExponent, RsaScheme, RsaSignature, SensitiveData, Signature,
    SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::ESYS_TR;
use tss_esapi::{Context, TctiNameConf};

const TCTI_DEFAULT: &str = "device:/dev/tpmrm0";

/// TPM2_PolicyAuthorize command code (big-endian), folded into the authorized
/// policy digest per the TPM2 spec.
const TPM_CC_POLICY_AUTHORIZE: [u8; 4] = [0x00, 0x00, 0x01, 0x6A];

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

/// The PCRs to bind to: `IRLUME_PCRS` (comma-separated) or `DEFAULT_PCRS`.
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

// PCRs 17-22 (DRTM / locality-restricted PCRs) are intentionally unsupported
// for sealing policies: nothing in the boot chains irlume binds to extends
// them, so a seal over them would add no protection.
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

/// True iff `public` is irlume's own SRK: RSA, our [`srk_template`] attributes,
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
/// RSA-2048 primary costs >10s on slow firmware TPMs, too slow for the PAM
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
    ctx.tr_set_auth(persisted, Auth::default())
        .map_err(tpm_err)?;
    Ok((KeyHandle::from(ESYS_TR::from(persisted)), true))
}

/// Run `body` with irlume's persistent SRK as parent. Never flushes the SRK when
/// persistent: persistence is the whole point (avoids re-deriving a slow RSA
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

/// True when this machine could seal under a strictly stronger tier than
/// `current` right now. Used by the login-time self-heal to auto-upgrade an
/// envelope sealed under a weaker tier (e.g. one written before signed-PCR
/// worked) without the user re-arming, and without churning the TPM on a
/// machine already at its best available tier. Only signals availability; the
/// actual round-trip verification happens in [`seal`].
pub fn stronger_tier_available_than(current: &PolicyKind) -> bool {
    match current {
        // Tier 1 is the strongest; nothing to upgrade to.
        PolicyKind::Authorized { .. } => false,
        // Tier 2 -> Tier 1 only if signed-PCR artifacts exist.
        PolicyKind::PcrlockNv { .. } => crate::pcrsig::signed_policy_available(),
        // Tier 3 -> a higher tier if either signed-PCR or pcrlock is available.
        PolicyKind::PcrLiteral => {
            crate::pcrsig::signed_policy_available() || pcrlock_provisioned().is_some()
        }
    }
}

/// Seal `secret` under the best policy available on this machine, trying each
/// tier in order and round-trip-verifying before trusting it:
///   * Tier 1: if systemd has published signed-PCR artifacts (UKI / systemd-boot),
///     a `PolicyAuthorize` over its signing key, binding the PCRs it signs
///     (typically PCR 11). Survives kernel updates with no reseal.
///   * Tier 2: if a systemd-pcrlock policy is provisioned
///     ([`pcrlock_provisioned`]), a `PolicyAuthorizeNV` against its NV index.
///     `make-policy` re-predicts the index across firmware / Secure Boot
///     updates, so those don't require a reseal either. Explicit sealing at
///     this tier is also available via [`seal_with_pcrlock`].
///   * Tier 3: otherwise a literal `PolicyPCR` over the configured PCRs
///     ([`policy_pcrs`], default PCR 7). If those PCRs move (dbx/Secure Boot
///     update) the envelope stops unsealing and the user re-runs `keyring arm`.
///
/// Every producer funnels through here (keyring arm, the template key, both
/// reseal self-heals), so a reseal re-runs the ladder: it can move an envelope
/// up a tier when one became available, and only lands on a lower tier when
/// the higher one genuinely does not unseal on this machine.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn seal(secret: &[u8]) -> Result<SealedEnvelope> {
    if crate::pcrsig::signed_policy_available() {
        match seal_authorized(secret) {
            // A signed seal can SUCCEED yet be un-unsealable on this boot: the
            // artifacts under /run/systemd are systemd's, signed for a PCR-11
            // value that only matches a UKI/measured-boot chain. On a GRUB box
            // (or any host where those don't correspond to the live PCRs) the
            // envelope seals fine but PolicyAuthorize fails at unseal (TPM
            // 0x4c4): the "sealed but unusable" trap that broke enrollment.
            // So round-trip it: only trust the authorized envelope if it
            // actually unseals right now; otherwise fall back to the literal
            // PCR seal, which is bound to values we read from this TPM.
            Ok(env) => match unseal(&env) {
                Ok(rt) if rt.as_slice() == secret => return Ok(env),
                Ok(_) => eprintln!(
                    "irlume: signed-PCR seal round-trip mismatch; falling back to literal PCR seal"
                ),
                Err(e) => eprintln!(
                    "irlume: signed-PCR seal doesn't unseal on this boot ({e}); falling back to literal PCR seal"
                ),
            },
            Err(e) => eprintln!(
                "irlume: signed-PCR seal unavailable ({e}); falling back to literal PCR seal"
            ),
        }
    }
    if let Some(nv_index) = pcrlock_provisioned() {
        // Same trap as Tier 1: a pcrlock seal can succeed yet not unseal on
        // this boot (e.g. the policy predicts a PCR this OS never extends, so
        // the super-PCR replay fails). Only trust it after a round-trip.
        match seal_pcrlock(secret, nv_index) {
            Ok(env) => match unseal(&env) {
                Ok(rt) if rt.as_slice() == secret => return Ok(env),
                Ok(_) => eprintln!(
                    "irlume: pcrlock seal round-trip mismatch; falling back to literal PCR seal"
                ),
                Err(e) => eprintln!(
                    "irlume: pcrlock seal doesn't unseal on this boot ({e}); falling back to literal PCR seal"
                ),
            },
            Err(e) => eprintln!(
                "irlume: pcrlock seal unavailable ({e}); falling back to literal PCR seal"
            ),
        }
    }
    seal_with_pcrs(secret, &policy_pcrs())
}

/// Seal `secret` under a literal `PolicyPCR` over `pcrs` (empty ⇒ no binding:
/// any boot state can unseal; use only for testing).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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
            // This layer seals bytes and does not know what they mean; the
            // keyring layer stamps the real kind before saving.
            secret: crate::envelope::SecretKind::default(),
            version: crate::envelope::CURRENT_VERSION,
            policy: PolicyKind::PcrLiteral,
            pcrs: pcrs.clone(),
            public: created.out_public.marshall().map_err(tpm_err)?,
            private: created.out_private.to_vec(),
            pcr_values: pcr_values.clone(),
            password_wrap: None,
        })
    })
}

/// Marker on the transient "a PCR moved while our policy session was open"
/// failure, so the retry decision never re-parses a TPM message itself.
const PCR_CHANGED_MARKER: &str = "pcr-update-counter-moved";

/// How many times to rebuild the policy session after [`Error::Tpm`] carrying
/// [`PCR_CHANGED_MARKER`].
///
/// Three, because the trigger is another process extending a PCR and the boot
/// window that produces them is short: systemd extends PCR 11 at each boot
/// phase and PCR 15 when a user session starts, and the second of those is
/// fired BY the login we are serving. Retrying forever would instead hide a
/// machine whose PCRs are genuinely churning.
const PCR_CHANGED_RETRIES: u32 = 3;

/// Ceiling on the time the retries may add, checked before starting another
/// attempt.
///
/// A count alone is the wrong bound here, because an unseal is not a fixed
/// cost: it is ~0.2s on an fTPM but ~2.7s on a discrete TPM replaying 8 bound
/// PCRs, so three retries is half a second on one machine and eight seconds on
/// another. This code runs inside the PAM auth stack, where the login BLOCKS on
/// it, and an 11-second login is the exact regression #246 existed to remove.
/// Whichever bound is reached first wins, so a slow TPM spends at most one more
/// attempt past this and a fast one still gets all three.
///
/// Exhausting the budget costs a keyring password prompt, not a failed login.
const PCR_CHANGED_RETRY_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

/// Turn a TPM failure into an [`Error`], tagging the one response code that is
/// worth retrying.
///
/// `TPM2_RC_PCR_CHANGED` (`TPM2_RC_VER1 + 0x028`) does not mean the policy was
/// wrong. `PolicyPCR` records the TPM's global `pcrUpdateCounter` in the
/// session; ANY process extending ANY PCR bumps that counter and invalidates
/// the session, whether or not the PCR it touched is one we bind. It is a race,
/// not a verdict, and the same attempt run again normally succeeds.
fn retryable_tpm_err(e: tss_esapi::Error) -> Error {
    use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
    if let tss_esapi::Error::Tss2Error(rc) = e {
        if rc.kind() == Some(Tss2ResponseCodeKind::PcrChanged) {
            return Error::Tpm(format!("{PCR_CHANGED_MARKER}: {e}"));
        }
    }
    Error::Tpm(e.to_string())
}

/// Whether `e` is the transient PCR-counter race, i.e. worth another attempt.
///
/// A predicate rather than an inline match so the retry decision is a value a
/// test can construct directly; the condition itself needs a concurrent PCR
/// extend to produce, which no unit test can arrange.
pub fn is_pcr_changed_race(e: &Error) -> bool {
    matches!(e, Error::Tpm(m) if m.contains(PCR_CHANGED_MARKER))
}

/// Release the sealed secret iff the bound policy is satisfied. Dispatches on the
/// envelope's [`PolicyKind`].
///
/// Retries the whole attempt on `TPM2_RC_PCR_CHANGED`, the race in which
/// another process extends a PCR and invalidates our open policy session (see
/// [`is_pcr_changed_race`]). Each try must start a FRESH session: once the TPM
/// has rejected a policy session for a moved counter, that session stays dead,
/// so re-running the dispatch (which opens its own session) is the recovery,
/// not re-issuing the failed command. This is the same gap systemd closed in
/// systemd/systemd#35657, where unsealing already retried but the `PolicyPCR`
/// leg did not.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn unseal(env: &SealedEnvelope) -> Result<Zeroizing<Vec<u8>>> {
    let out = retry_on_pcr_race(
        PCR_CHANGED_RETRIES,
        PCR_CHANGED_RETRY_BUDGET,
        || match &env.policy {
            PolicyKind::PcrLiteral => unseal_literal(env),
            PolicyKind::Authorized {
                pubkey_pem,
                policy_ref,
            } => unseal_authorized(env, pubkey_pem, policy_ref),
            PolicyKind::PcrlockNv { nv_index } => unseal_pcrlock(env, *nv_index),
        },
    )?;
    // Lock the unsealed secret (login password / template key) against swap and
    // core dumps for as long as it lives.
    irlume_common::memlock::lock_slice(&out);
    Ok(out)
}

/// Run `attempt` until it stops losing to the PCR-counter race, at most
/// `limit` extra times and never starting one past `budget`.
///
/// Both bounds, because they guard different things: `limit` stops a machine
/// whose PCRs churn constantly from looping, and `budget` stops a slow TPM from
/// turning three retries into an eight-second login. Whichever is reached first
/// ends it.
///
/// A separate function taking a closure because the CONDITION cannot be staged
/// in a unit test: producing a real `TPM2_RC_PCR_CHANGED` needs another process
/// to extend a counter-moving PCR at the right microsecond. The loop's
/// BEHAVIOUR is still a value a test can pin: how many times it re-runs, that
/// it stops on either bound, that it returns the successful result, and that it
/// gives up with the original error rather than a synthesised one.
fn retry_on_pcr_race<T, F>(limit: u32, budget: std::time::Duration, mut attempt: F) -> Result<T>
where
    F: FnMut() -> Result<T>,
{
    let start = std::time::Instant::now();
    let mut tries = 0;
    loop {
        match attempt() {
            Err(e) if is_pcr_changed_race(&e) && tries < limit && start.elapsed() < budget => {
                tries += 1;
                // Worth a line: without it a retried unseal is invisible, and
                // the difference between "this machine races occasionally" and
                // "this machine races every time" is the whole diagnosis.
                eprintln!(
                    "irlume: TPM policy session lost to a concurrent PCR extend; \
                     retrying unseal ({tries}/{limit})"
                );
            }
            other => return other,
        }
    }
}

/// Unseal a literal-`PolicyPCR` envelope: replay the bound PCRs into a policy
/// session and unseal.
#[allow(clippy::redundant_closure_call)]
fn unseal_literal(env: &SealedEnvelope) -> Result<Zeroizing<Vec<u8>>> {
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
                        .map_err(retryable_tpm_err)?;
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

// ---------------------------------------------------------------------------
// Tier 1: signed-PCR PolicyAuthorize (systemd UKI / systemd-boot).
// ---------------------------------------------------------------------------

/// Seal `secret` under a `PolicyAuthorize` over systemd's PCR-signing public
/// key. The object's `authPolicy` commits only to that key's Name (not to any
/// concrete PCR value), so any PCR state for which systemd has shipped a valid
/// signature can unseal, the basis for surviving kernel/UKI updates without a
/// reseal. Binds exactly the PCRs systemd signs (read from the signature file,
/// typically PCR 11). Uses an empty `policyRef`, matching systemd's convention.
fn seal_authorized(secret: &[u8]) -> Result<SealedEnvelope> {
    let pubkey_pem = crate::pcrsig::load_pubkey_pem()?;
    let pcrs = crate::pcrsig::signed_pcrs(crate::pcrsig::DEFAULT_BANK)
        .ok_or_else(|| Error::Policy("signed-PCR file has no usable signatures".into()))?;
    let policy_ref: Vec<u8> = Vec::new();

    let mut ctx = open_context()?;
    let pcr_values = read_pcr_values(&mut ctx, &pcrs)?;

    // The authorized policy depends only on the signing key's Name + policyRef.
    let key_name = {
        let key_handle = load_external_pubkey(&mut ctx, &pubkey_pem)?;
        let name = ctx.tr_get_name(key_handle.into()).map_err(tpm_err);
        let _ = ctx.flush_context(key_handle.into());
        name?
    };
    let auth_policy = authorize_policy_digest(key_name.value(), &policy_ref)?;

    with_srk(&mut ctx, |ctx, srk| {
        let tmpl = sealed_template(auth_policy.clone())?;
        let sensitive = SensitiveData::try_from(secret.to_vec()).map_err(tpm_err)?;
        let created = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create(*srk, tmpl, None, Some(sensitive), None, None)
            })
            .map_err(tpm_err)?;

        Ok(SealedEnvelope {
            // This layer seals bytes and does not know what they mean; the
            // keyring layer stamps the real kind before saving.
            secret: crate::envelope::SecretKind::default(),
            version: crate::envelope::CURRENT_VERSION,
            policy: PolicyKind::Authorized {
                pubkey_pem: pubkey_pem.clone(),
                policy_ref: policy_ref.clone(),
            },
            pcrs: pcrs.clone(),
            public: created.out_public.marshall().map_err(tpm_err)?,
            private: created.out_private.to_vec(),
            pcr_values: pcr_values.clone(),
            password_wrap: None,
        })
    })
}

/// Unseal a `PolicyAuthorize`-bound object: replay `PolicyPCR` over the current
/// PCRs, find a signature whose authorized policy matches the resulting digest,
/// verify it under the public key, and run `PolicyAuthorize` to satisfy the
/// object's policy.
#[allow(clippy::redundant_closure_call)]
fn unseal_authorized(
    env: &SealedEnvelope,
    pubkey_pem: &str,
    policy_ref: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut ctx = open_context()?;

    with_srk(&mut ctx, |ctx, srk| {
        let public = Public::unmarshall(&env.public).map_err(tpm_err)?;
        let private = Private::try_from(env.private.clone()).map_err(tpm_err)?;
        let sealed_handle = ctx
            .execute_with_nullauth_session(|ctx| ctx.load(*srk, private, public))
            .map_err(tpm_err)?;

        let result: Result<Zeroizing<Vec<u8>>> = (|| {
            with_session(ctx, SessionType::Policy, |ctx, session| {
                let policy_session = PolicySession::try_from(session).map_err(tpm_err)?;

                // 1. Fold the current PCR state in and read the resulting policy
                //    digest, the "approved policy" that must carry a signature.
                let sel = pcr_selection(&env.pcrs)?;
                ctx.policy_pcr(policy_session, Digest::default(), sel)
                    .map_err(retryable_tpm_err)?;
                let approved = ctx.policy_get_digest(policy_session).map_err(tpm_err)?;

                // 2. Find a signature for exactly this PCR set + policy digest.
                let sigs = crate::pcrsig::load_signatures(crate::pcrsig::DEFAULT_BANK)?;
                let sig = crate::pcrsig::find_for_policy(&sigs, &env.pcrs, approved.value())
                    .ok_or_else(|| {
                        Error::Policy(
                            "no signed PCR policy matches the current boot state \
                             (kernel/UKI not yet enrolled; re-sign required)"
                                .into(),
                        )
                    })?;

                // 3. Verify the signature over aHash = H(approvedPolicy ‖ ref)
                //    under the public key, yielding a verification ticket.
                let key_handle = load_external_pubkey(ctx, pubkey_pem)?;
                let verify_result: Result<Zeroizing<Vec<u8>>> = (|| {
                    let key_name = ctx.tr_get_name(key_handle.into()).map_err(tpm_err)?;
                    let a_hash = a_hash(approved.value(), policy_ref)?;
                    let signature = Signature::RsaSsa(
                        RsaSignature::create(
                            HashingAlgorithm::Sha256,
                            PublicKeyRsa::try_from(sig.sig.clone()).map_err(tpm_err)?,
                        )
                        .map_err(tpm_err)?,
                    );
                    let ticket = ctx
                        .verify_signature(key_handle, a_hash, signature)
                        .map_err(tpm_err)?;

                    // 4. Authorize: rewrite the session policy to the key-bound
                    //    value, which equals the object's authPolicy.
                    let ref_nonce = Nonce::try_from(policy_ref.to_vec()).map_err(tpm_err)?;
                    ctx.policy_authorize(
                        policy_session,
                        approved.clone(),
                        ref_nonce,
                        &key_name,
                        ticket,
                    )
                    .map_err(tpm_err)?;

                    // 5. Unseal under the now-satisfied policy session.
                    let data = ctx
                        .execute_with_session(Some(session), |ctx| ctx.unseal(sealed_handle.into()))
                        .map_err(|e| policy_aware_err(e, env))?;
                    Ok(Zeroizing::new(data.to_vec()))
                })();
                let _ = ctx.flush_context(key_handle.into());
                verify_result
            })
        })();

        let _ = ctx.flush_context(sealed_handle.into());
        result
    })
}

/// Load an external RSA public key (SPKI PEM) into the TPM under the Owner
/// hierarchy so its Name can be taken and signatures verified against it.
/// The hierarchy matters: `TPM2_VerifySignature` over a key loaded under the
/// Null hierarchy yields a null verification ticket, which `TPM2_PolicyAuthorize`
/// rejects with `TPM_RC_VALUE` on both swtpm and real TPMs, so the Tier-1
/// signed-PCR unseal always fell back. Loading under Owner produces a ticket
/// PolicyAuthorize accepts. The key's Name (which the sealed object's authPolicy
/// commits to) is hierarchy-independent, so this does not change the policy.
fn load_external_pubkey(ctx: &mut Context, pubkey_pem: &str) -> Result<KeyHandle> {
    let public = rsa_pem_to_public(pubkey_pem)?;
    ctx.load_external_public(public, Hierarchy::Owner)
        .map_err(tpm_err)
}

/// Build a tss-esapi `Public` for an external RSA verification key from a
/// SubjectPublicKeyInfo PEM.
fn rsa_pem_to_public(pubkey_pem: &str) -> Result<Public> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    let key = rsa::RsaPublicKey::from_public_key_pem(pubkey_pem)
        .map_err(|e| Error::Policy(format!("parse PCR public key: {e}")))?;
    let modulus = key.n().to_bytes_be();
    let key_bits = match modulus.len() * 8 {
        2048 => RsaKeyBits::Rsa2048,
        3072 => RsaKeyBits::Rsa3072,
        4096 => RsaKeyBits::Rsa4096,
        other => {
            return Err(Error::Policy(format!(
                "unsupported PCR key size: {other} bits"
            )))
        }
    };
    let exponent = {
        let e = key.e().to_bytes_be();
        if e.len() > 4 {
            return Err(Error::Policy("PCR key exponent too large".into()));
        }
        let mut buf = [0u8; 4];
        buf[4 - e.len()..].copy_from_slice(&e);
        RsaExponent::create(u32::from_be_bytes(buf)).map_err(tpm_err)?
    };

    let attrs = ObjectAttributesBuilder::new()
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_restricted(false)
        .with_fixed_tpm(false)
        .with_fixed_parent(false)
        .with_sensitive_data_origin(false)
        .build()
        .map_err(tpm_err)?;

    // Null scheme: the verification scheme (RSASSA/SHA-256) is supplied per
    // operation in the `Signature` passed to `verify_signature`.
    let params = PublicRsaParameters::new(
        SymmetricDefinitionObject::Null,
        RsaScheme::create(RsaSchemeAlgorithm::Null, None).map_err(tpm_err)?,
        key_bits,
        exponent,
    );

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_rsa_parameters(params)
        .with_rsa_unique_identifier(PublicKeyRsa::try_from(modulus).map_err(tpm_err)?)
        .build()
        .map_err(tpm_err)
}

/// Compute the object `authPolicy` produced by `TPM2_PolicyAuthorize` from an
/// empty starting policy: reset to a zero digest, fold in the command code + the
/// signing key's Name, then the policyRef. Mirrors the TPM2 spec so we don't
/// need a null verification ticket in a trial session.
fn authorize_policy_digest(key_name: &[u8], policy_ref: &[u8]) -> Result<Digest> {
    let mut h = Sha256::new();
    h.update([0u8; 32]); // reset to Zero Digest (SHA-256 size)
    h.update(TPM_CC_POLICY_AUTHORIZE);
    h.update(key_name);
    let d1 = h.finalize();

    let mut h2 = Sha256::new();
    h2.update(d1);
    h2.update(policy_ref);
    Digest::try_from(h2.finalize().to_vec()).map_err(tpm_err)
}

/// aHash = H(approvedPolicy ‖ policyRef), the message a PolicyAuthorize
/// signature must cover.
fn a_hash(approved_policy: &[u8], policy_ref: &[u8]) -> Result<Digest> {
    let mut h = Sha256::new();
    h.update(approved_policy);
    h.update(policy_ref);
    Digest::try_from(h.finalize().to_vec()).map_err(tpm_err)
}

// ---------------------------------------------------------------------------
// Tier 2: systemd-pcrlock PolicyAuthorizeNV (GRUB2 + Secure Boot/dbx). Binds the
// object to a pcrlock NV index that holds the currently-valid PCR policy; the
// admin re-runs `systemd-pcrlock make-policy` to re-predict it across firmware
// updates. See [`crate::tpm_pcrlock`] for the verified seal/unseal spec this
// implements. The seal side is a trial-session `PolicyAuthorizeNV` over the NV
// index; the unseal side replays systemd's "super PCR" policy (one PolicyPCR
// over the single-value PCRs, then PolicyPCR+PolicyOR per multi-value PCR) into
// a live policy session before the PolicyAuthorizeNV, exactly reproducing the
// digest `make-policy` stored in the index.
// ---------------------------------------------------------------------------

/// systemd's pcrlock prediction, read from `/var/lib/systemd/pcrlock.json`.
const PCRLOCK_JSON: &str = "/var/lib/systemd/pcrlock.json";

#[derive(serde::Deserialize)]
struct PcrlockJson {
    #[serde(rename = "pcrBank")]
    pcr_bank: String,
    #[serde(rename = "pcrValues")]
    pcr_values: Vec<PcrlockEntry>,
    /// The self-referential policy NV index, absent when `make-policy` ran
    /// without allocating one (e.g. `--recovery-pin=yes` setups).
    #[serde(rename = "nvIndex", default)]
    nv_index: Option<u64>,
}

#[derive(serde::Deserialize)]
struct PcrlockEntry {
    pcr: u32,
    /// One or more allowed SHA-256 PCR values (hex), as predicted by make-policy.
    values: Vec<String>,
}

fn read_pcrlock_json() -> Result<PcrlockJson> {
    // IRLUME_PCRLOCK_JSON redirects the prediction file, like the other
    // sandbox overrides; tests provision a TPM and point this at a fixture.
    let path = std::env::var("IRLUME_PCRLOCK_JSON").unwrap_or_else(|_| PCRLOCK_JSON.to_string());
    let raw = std::fs::read(&path).map_err(|e| {
        Error::Policy(format!(
            "cannot read {path}: {e} (run `systemd-pcrlock make-policy` first)"
        ))
    })?;
    parse_pcrlock_json(&raw, &path)
}

/// Parse and validate a pcrlock prediction. Rejects a policy that would provide
/// no measured-boot protection: an empty protection mask (zero PCRs) or any PCR
/// entry with no predicted values. `systemd-pcrlock make-policy` emits an empty
/// mask when nothing in the boot chain correlates with its components ("Set of
/// PCRs to use for policy is empty. Generated policy will not provide any
/// protection"); binding a secret to that is a false sense of security, so both
/// seal (refuse to arm) and unseal (fail-safe to the password) reject it here.
fn parse_pcrlock_json(raw: &[u8], source: &str) -> Result<PcrlockJson> {
    // `source` is the path the bytes came from (the IRLUME_PCRLOCK_JSON
    // override or the default), so the error names the file actually read.
    let plock: PcrlockJson = serde_json::from_slice(raw)
        .map_err(|e| Error::Policy(format!("malformed {source}: {e}")))?;
    if plock.pcr_bank != "sha256" {
        return Err(Error::Policy(format!(
            "pcrlock bank is {:?}; only sha256 is supported",
            plock.pcr_bank
        )));
    }
    if plock.pcr_values.is_empty() || plock.pcr_values.iter().any(|e| e.values.is_empty()) {
        return Err(Error::Policy(
            "pcrlock policy covers no PCRs (empty protection mask); it would provide no \
             measured-boot protection. Re-run `systemd-pcrlock make-policy` with a full \
             component set, or arm a literal-PCR / signed-PCR seal instead."
                .into(),
        ));
    }
    Ok(plock)
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    // Guard BEFORE the byte-indexed slice below: a multibyte UTF-8 char (with
    // s.len() still even) or an odd length would make `s[i..i+2]` split a char
    // boundary or run past the end and PANIC, turning a corrupt/partial
    // pcrlock.json into a login outage instead of a clean password fallback.
    // Same hardening as pcrsig::from_hex (a fuzzer found this class there).
    if !s.is_ascii() {
        return Err(Error::Policy(
            "non-hex characters in pcrlock.json PCR value".into(),
        ));
    }
    if !s.len().is_multiple_of(2) {
        return Err(Error::Policy(
            "odd-length hex in pcrlock.json PCR value".into(),
        ));
    }
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()
        .map_err(|e| Error::Policy(format!("bad hex in pcrlock.json: {e}")))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| Error::Policy("pcrlock PCR value is not 32 bytes".into()))
}

/// The `pcrDigest` a `TPM2_PolicyPCR` commits to for a selection: SHA-256 over
/// the selected PCR values, concatenated in ascending PCR order (the order the
/// TPM itself uses). `values` must already be in that order.
fn pcr_composite_digest(values: &[[u8; 32]]) -> Result<Digest> {
    let mut h = Sha256::new();
    for v in values {
        h.update(v);
    }
    Digest::try_from(h.finalize().to_vec()).map_err(tpm_err)
}

fn nv_index_handle(ctx: &mut Context, nv_index: u32) -> Result<NvIndexHandle> {
    let tpm_handle = NvIndexTpmHandle::new(nv_index).map_err(tpm_err)?;
    let obj: ObjectHandle = ctx
        .tr_from_tpm_public(TpmHandle::NvIndex(tpm_handle))
        .map_err(tpm_err)?;
    Ok(NvIndexHandle::from(obj))
}

/// One step of a systemd super-PCR policy, replayable in a trial session to
/// derive intermediate digests (the OR-branch digests the live session needs).
#[derive(Clone)]
enum PolicyStep {
    /// `TPM2_PolicyPCR` over `sel` committing to the given composite `digest`.
    Pcr { sel: Vec<u32>, digest: Digest },
    /// `TPM2_PolicyOR` over precomputed branch digests.
    Or(Vec<Digest>),
}

/// `TPM_CC_PolicyPCR`, TCG TPM 2.0 Library Part 2 "Structures", command codes.
const TPM_CC_POLICY_PCR: u32 = 0x0000_017F;
/// `TPM_CC_PolicyOR`.
const TPM_CC_POLICY_OR: u32 = 0x0000_0171;
/// `TPM_ALG_SHA256`.
const TPM_ALG_SHA256: u16 = 0x000B;

/// A `TPML_PCR_SELECTION` in the TPM's own wire encoding.
///
/// The policy digest is taken over the marshalled structure, so this has to
/// match the TPM byte for byte: `UINT32 count`, then per selection a
/// `TPMI_ALG_HASH` (UINT16), a `UINT8 sizeofSelect`, and that many bitmap
/// bytes, PCR n living in bit n%8 of byte n/8. Part 2 §10.9.7.
fn marshal_pcr_selection(pcrs: &[u32]) -> Vec<u8> {
    // Three bytes covers PCRs 0-23, which is every PCR irlume will select; the
    // TPM reports sizeofSelect=3 for SHA-256 on every part we have measured.
    let mut bitmap = [0u8; 3];
    for &p in pcrs {
        if let Some(byte) = bitmap.get_mut((p / 8) as usize) {
            *byte |= 1 << (p % 8);
        }
    }
    let mut out = Vec::with_capacity(4 + 2 + 1 + bitmap.len());
    out.extend_from_slice(&1u32.to_be_bytes()); // one selection: SHA-256
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out.push(bitmap.len() as u8);
    out.extend_from_slice(&bitmap);
    out
}

/// `TPM2_PolicyPCR`'s effect on a policy digest, computed without a TPM.
///
/// Part 3 §23.7 eq. 20: `policyDigest_new := H(policyDigest_old ||
/// TPM_CC_PolicyPCR || pcrs || pcrDigest)`. In a trial session the TPM uses the
/// supplied `pcrDigest` rather than reading PCRs, which is exactly the case
/// this replaces, so the two must agree; `super_pcr_matches_a_trial_session`
/// asserts that against real hardware.
fn policy_pcr_digest(old: &Digest, pcrs: &[u32], pcr_digest: &Digest) -> Result<Digest> {
    let mut h = Sha256::new();
    h.update(old.value());
    h.update(TPM_CC_POLICY_PCR.to_be_bytes());
    h.update(marshal_pcr_selection(pcrs));
    h.update(pcr_digest.value());
    Digest::try_from(h.finalize().to_vec()).map_err(tpm_err)
}

/// `TPM2_PolicyOR`'s effect on a policy digest, computed without a TPM.
///
/// Part 3 §23.6 NOTE 2: the running digest is RESET to zero first, then
/// `H(0...0 || TPM_CC_PolicyOR || digests)` where `digests` is the branch
/// digests concatenated, values only. The reset is why an OR erases whatever
/// came before it, and why the prefix has to be replayed per branch.
fn policy_or_digest(branches: &[Digest]) -> Result<Digest> {
    let mut h = Sha256::new();
    h.update([0u8; 32]);
    h.update(TPM_CC_POLICY_OR.to_be_bytes());
    for b in branches {
        h.update(b.value());
    }
    Digest::try_from(h.finalize().to_vec()).map_err(tpm_err)
}

/// Replay `steps` in software and return the resulting policy digest.
///
/// This is what a trial session was doing, without the TPM. The derivation cost
/// one trial session per predicted branch, measured at 8.2s on a ThinkPad X13
/// (17 branches on a discrete TPM), which is why it had to be memoized and then
/// warmed at startup; in software it is a handful of SHA-256 blocks (#248).
/// TCG Part 3 §23.19 says PolicyGetDigest ALLOWS the TPM to precompute a
/// policy, not that it is required, and systemd computes the same values the
/// same way.
fn software_replay(steps: &[PolicyStep]) -> Result<Digest> {
    let mut digest = Digest::try_from(vec![0u8; 32]).map_err(tpm_err)?;
    for step in steps {
        digest = match step {
            PolicyStep::Pcr { sel, digest: pcr } => policy_pcr_digest(&digest, sel, pcr)?,
            PolicyStep::Or(branches) => policy_or_digest(branches)?,
        };
    }
    Ok(digest)
}

/// Run `steps` in a fresh trial session and return the resulting policy digest.
///
/// No longer on any hot path: [`software_replay`] computes the same values
/// without the TPM. Kept because it is the ORACLE that proves it does, in
/// `software_digests_match_a_trial_session`.
/// Test-only, so a future edit that puts a trial session back on the hot path
/// has to say so explicitly.
#[cfg(test)]
fn trial_replay(ctx: &mut Context, steps: &[PolicyStep]) -> Result<Digest> {
    with_session(ctx, SessionType::Trial, |ctx, session| {
        let policy = PolicySession::try_from(session).map_err(tpm_err)?;
        for step in steps {
            match step {
                PolicyStep::Pcr { sel, digest } => {
                    ctx.policy_pcr(policy, digest.clone(), pcr_selection(sel)?)
                        .map_err(tpm_err)?;
                }
                PolicyStep::Or(branches) => {
                    ctx.policy_or(policy, digest_list(branches)?)
                        .map_err(tpm_err)?;
                }
            }
        }
        ctx.policy_get_digest(policy).map_err(tpm_err)
    })
}

fn digest_list(digests: &[Digest]) -> Result<DigestList> {
    let mut list = DigestList::new();
    for d in digests {
        list.add(d.clone()).map_err(tpm_err)?;
    }
    Ok(list)
}

/// A single-value PCR group plus the ordered multi-value PCRs of a super policy.
#[derive(Clone)]
struct SuperPcr {
    /// Single-value PCRs, ascending (replayed live as one PolicyPCR at unseal).
    singles: Vec<u32>,
    /// Multi-value PCRs, ascending: the PCR and its OR-branch policy digests.
    multis: Vec<(u32, Vec<Digest>)>,
}

/// Reconstruct systemd's super-PCR policy structure from the prediction, deriving
/// each multi-value PCR's OR-branch digests via trial replays of the growing
/// prefix (mirrors `tpm2_calculate_policy_super_pcr`).
/// Reconstruct systemd's super-PCR policy structure from the prediction.
///
/// Pure: the branch digests are hash recurrences defined by TCG Part 3 (§23.7
/// for PolicyPCR, §23.6 for PolicyOR), so no TPM is consulted. This used to run
/// one TRIAL SESSION per predicted branch, measured at 8.2s on a ThinkPad X13
/// with 17 branches on a discrete TPM, which then needed a memo to survive
/// repeat unseals and a startup warm-up so the first login did not pay it. Both
/// of those are deleted with this change (#248); `software_digests_match_a_trial_session`
/// pins the arithmetic against real hardware.
fn build_super_pcr(plock: &PcrlockJson) -> Result<SuperPcr> {
    let mut entries: Vec<(u32, Vec<[u8; 32]>)> = plock
        .pcr_values
        .iter()
        .map(|e| {
            let vals = e
                .values
                .iter()
                .map(|s| hex32(s))
                .collect::<Result<Vec<_>>>()?;
            Ok((e.pcr, vals))
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by_key(|(pcr, _)| *pcr);

    let singles: Vec<u32> = entries
        .iter()
        .filter(|(_, v)| v.len() == 1)
        .map(|(pcr, _)| *pcr)
        .collect();
    let single_values: Vec<[u8; 32]> = entries
        .iter()
        .filter(|(_, v)| v.len() == 1)
        .map(|(_, v)| v[0])
        .collect();

    // The growing prefix of policy steps, replayed in trial sessions to derive
    // each multi-value PCR's branch digests from the correct intermediate state.
    let mut prefix: Vec<PolicyStep> = Vec::new();
    if !singles.is_empty() {
        prefix.push(PolicyStep::Pcr {
            sel: singles.clone(),
            digest: pcr_composite_digest(&single_values)?,
        });
    }

    let mut multis: Vec<(u32, Vec<Digest>)> = Vec::new();
    for (pcr, values) in entries.iter().filter(|(_, v)| v.len() > 1) {
        let mut branches = Vec::with_capacity(values.len());
        for val in values {
            let mut steps = prefix.clone();
            steps.push(PolicyStep::Pcr {
                sel: vec![*pcr],
                digest: pcr_composite_digest(&[*val])?,
            });
            branches.push(software_replay(&steps)?);
        }
        // Advance the prefix past this PCR: PolicyPCR (any branch value; the
        // following PolicyOR collapses them to one digest) then PolicyOR.
        prefix.push(PolicyStep::Pcr {
            sel: vec![*pcr],
            digest: pcr_composite_digest(&[values[0]])?,
        });
        prefix.push(PolicyStep::Or(branches.clone()));
        multis.push((*pcr, branches));
    }

    Ok(SuperPcr { singles, multis })
}

/// Compute the sealed object's `authPolicy` (a `PolicyAuthorizeNV` over the NV
/// index) using a trial session. The index's Name (WRITTEN bit set once
/// make-policy has written it) fully determines the digest; the TPM reads it.
fn pcrlock_auth_policy(ctx: &mut Context, nv: NvIndexHandle) -> Result<Digest> {
    with_session(ctx, SessionType::Trial, |ctx, session| {
        let policy = PolicySession::try_from(session).map_err(tpm_err)?;
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.policy_authorize_nv(policy, NvAuth::Owner, nv)
        })
        .map_err(tpm_err)?;
        ctx.policy_get_digest(policy).map_err(tpm_err)
    })
}

/// Seal `secret` bound to the systemd-pcrlock NV index at `nv_index`.
fn seal_pcrlock(secret: &[u8], nv_index: u32) -> Result<SealedEnvelope> {
    let plock = read_pcrlock_json()?;
    let mut pcrs: Vec<u32> = plock.pcr_values.iter().map(|e| e.pcr).collect();
    pcrs.sort_unstable();

    let mut ctx = open_context()?;
    let pcr_values = read_pcr_values(&mut ctx, &pcrs)?;
    let nv = nv_index_handle(&mut ctx, nv_index)?;
    let auth_policy = pcrlock_auth_policy(&mut ctx, nv)?;

    with_srk(&mut ctx, |ctx, srk| {
        let tmpl = sealed_template(auth_policy.clone())?;
        let sensitive = SensitiveData::try_from(secret.to_vec()).map_err(tpm_err)?;
        let created = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create(*srk, tmpl, None, Some(sensitive), None, None)
            })
            .map_err(tpm_err)?;

        Ok(SealedEnvelope {
            // This layer seals bytes and does not know what they mean; the
            // keyring layer stamps the real kind before saving.
            secret: crate::envelope::SecretKind::default(),
            version: crate::envelope::CURRENT_VERSION,
            policy: PolicyKind::PcrlockNv { nv_index },
            pcrs: pcrs.clone(),
            public: created.out_public.marshall().map_err(tpm_err)?,
            private: created.out_private.to_vec(),
            pcr_values: pcr_values.clone(),
            password_wrap: None,
        })
    })
}

/// Unseal a `PolicyAuthorizeNV`-bound object against `nv_index`: replay the live
/// super-PCR policy, run PolicyAuthorizeNV, and unseal.
#[allow(clippy::redundant_closure_call)]
fn unseal_pcrlock(env: &SealedEnvelope, nv_index: u32) -> Result<Zeroizing<Vec<u8>>> {
    let plock = read_pcrlock_json()?;
    let mut ctx = open_context()?;
    let nv = nv_index_handle(&mut ctx, nv_index)?;
    let super_pcr = build_super_pcr(&plock)?;

    with_srk(&mut ctx, |ctx, srk| {
        let public = Public::unmarshall(&env.public).map_err(tpm_err)?;
        let private = Private::try_from(env.private.clone()).map_err(tpm_err)?;
        let sealed_handle = ctx
            .execute_with_nullauth_session(|ctx| ctx.load(*srk, private, public))
            .map_err(tpm_err)?;

        let result: Result<Zeroizing<Vec<u8>>> = (|| {
            with_session(ctx, SessionType::Policy, |ctx, session| {
                let policy = PolicySession::try_from(session).map_err(tpm_err)?;

                // Super-PCR replay against LIVE PCRs (empty digest => the TPM
                // reads current PCRs). Single-value PCRs first as one PolicyPCR,
                // then each multi-value PCR: live PolicyPCR + PolicyOR over the
                // precomputed branch digests. Unseal fails here if the live PCRs
                // don't match any predicted branch (i.e. the box booted into a
                // state make-policy didn't authorize).
                if !super_pcr.singles.is_empty() {
                    ctx.policy_pcr(
                        policy,
                        Digest::default(),
                        pcr_selection(&super_pcr.singles)?,
                    )
                    .map_err(retryable_tpm_err)?;
                }
                for (pcr, branches) in &super_pcr.multis {
                    ctx.policy_pcr(policy, Digest::default(), pcr_selection(&[*pcr])?)
                        .map_err(retryable_tpm_err)?;
                    ctx.policy_or(policy, digest_list(branches)?)
                        .map_err(retryable_tpm_err)?;
                }

                ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
                    ctx.policy_authorize_nv(policy, NvAuth::Owner, nv)
                })
                .map_err(|e| policy_aware_err(e, env))?;

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

/// Public entry point used by the CLI / daemon to arm a pcrlock-bound seal once
/// a pcrlock policy has been provisioned at `nv_index`.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn seal_with_pcrlock(secret: &[u8], nv_index: u32) -> Result<SealedEnvelope> {
    seal_pcrlock(secret, nv_index)
}

/// The NV index of a usable systemd-pcrlock policy, or `None` when this
/// machine has none: `pcrlock.json` absent (the common case), unparseable,
/// rejected by the empty-policy guard, or carrying no NV index. [`seal`] uses
/// this to decide whether the Tier 2 rung exists on this machine.
pub fn pcrlock_provisioned() -> Option<u32> {
    let plock = read_pcrlock_json().ok()?;
    u32::try_from(plock.nv_index?).ok()
}

/// Marker `policy_aware_err` embeds when it diagnoses PCR drift;
/// [`is_pcr_mismatch`] keys on it, so the two stay in sync here.
const PCR_MISMATCH_MARKER: &str = "PCR mismatch";

/// If the TSS error looks like a policy mismatch, enrich it with the list of
/// PCRs that have changed since seal time.
fn policy_aware_err(e: tss_esapi::Error, env: &SealedEnvelope) -> Error {
    // The counter race first, and it must not be diagnosed as drift: it is not
    // a statement about any PCR's VALUE, so `diagnose_pcrs` would find nothing
    // changed and the failure would be reported as a plain TPM error that
    // nothing retries. `Unseal` itself can return it, not just `PolicyPCR`.
    let retryable = retryable_tpm_err(e);
    if is_pcr_changed_race(&retryable) {
        return retryable;
    }
    let base = e.to_string();
    match diagnose_pcrs(env) {
        Ok(changed) if !changed.is_empty() => Error::Policy(format!(
            "{base}: {PCR_MISMATCH_MARKER}: {changed:?} changed since seal"
        )),
        _ => Error::Tpm(base),
    }
}

/// True when `e` is the PCR-drift unseal failure `policy_aware_err` tags
/// (Secure Boot / firmware / dbx change moved a bound PCR). Kept next to the
/// construction site so callers never re-parse the message themselves.
pub fn is_pcr_mismatch(e: &Error) -> bool {
    matches!(e, Error::Policy(m) if m.contains(PCR_MISMATCH_MARKER))
}

/// Compare current PCR values against those stored in the envelope. Returns the
/// PCRs whose SHA-256 differs (empty ⇒ no drift, or no values captured at seal).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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
    fn authorize_digest_deterministic_and_ref_sensitive() {
        let name = [0x00, 0x0b]
            .iter()
            .chain([0xab; 32].iter())
            .copied()
            .collect::<Vec<u8>>();
        let d1 = authorize_policy_digest(&name, &[]).unwrap();
        let d2 = authorize_policy_digest(&name, &[]).unwrap();
        assert_eq!(d1.value(), d2.value(), "must be deterministic");
        assert_eq!(d1.value().len(), 32);
        let d3 = authorize_policy_digest(&name, &[0x01]).unwrap();
        assert_ne!(d1.value(), d3.value(), "policyRef must change the digest");
        let d4 = authorize_policy_digest(&[0x00, 0x0b, 0x00], &[]).unwrap();
        assert_ne!(d1.value(), d4.value(), "key Name must change the digest");
    }

    #[test]
    fn a_hash_is_32_bytes_and_ref_sensitive() {
        let a = a_hash(&[0xaa; 32], &[]).unwrap();
        let b = a_hash(&[0xaa; 32], &[0x01]).unwrap();
        assert_eq!(a.value().len(), 32);
        assert_ne!(a.value(), b.value());
    }

    #[test]
    fn hex32_rejects_malformed_without_panicking() {
        // 64 valid hex chars -> 32 bytes.
        let good: String = "ab".repeat(32);
        assert!(hex32(&good).is_ok());
        // Odd length must error, not panic on the trailing slice.
        assert!(hex32("abc").is_err());
        // A multibyte char (even byte length) must error, not split a boundary.
        assert!(hex32("aé").is_err());
        // Right length, non-hex digits.
        assert!(hex32(&"zz".repeat(32)).is_err());
        // Valid hex but wrong byte count.
        assert!(hex32("aabb").is_err());
    }

    #[test]
    fn pcrlock_json_rejects_empty_protection_mask() {
        // A policy covering ≥1 PCR parses.
        let good = br#"{"pcrBank":"sha256","pcrValues":[{"pcr":7,"values":["aa"]}]}"#;
        assert!(parse_pcrlock_json(good, PCRLOCK_JSON).is_ok());
        // Empty protection mask (no PCRs) is refused: no measured-boot protection.
        let empty = br#"{"pcrBank":"sha256","pcrValues":[]}"#;
        assert!(matches!(
            parse_pcrlock_json(empty, PCRLOCK_JSON),
            Err(Error::Policy(_))
        ));
        // A PCR entry with no predicted values is refused (would be silently dropped).
        let novals = br#"{"pcrBank":"sha256","pcrValues":[{"pcr":7,"values":[]}]}"#;
        assert!(matches!(
            parse_pcrlock_json(novals, PCRLOCK_JSON),
            Err(Error::Policy(_))
        ));
        // Wrong bank is refused.
        let sha1 = br#"{"pcrBank":"sha1","pcrValues":[{"pcr":7,"values":["aa"]}]}"#;
        assert!(matches!(
            parse_pcrlock_json(sha1, PCRLOCK_JSON),
            Err(Error::Policy(_))
        ));
    }

    #[test]
    fn pcrlock_json_nv_index_is_optional() {
        // With an NV index (the make-policy default): parsed and exposed.
        let with_nv =
            br#"{"pcrBank":"sha256","pcrValues":[{"pcr":7,"values":["aa"]}],"nvIndex":26196898}"#;
        assert_eq!(
            parse_pcrlock_json(with_nv, PCRLOCK_JSON)
                .expect("parse")
                .nv_index,
            Some(26_196_898)
        );
        // Without one (recovery-pin setups): still a valid prediction, but no
        // Tier 2 rung.
        let without = br#"{"pcrBank":"sha256","pcrValues":[{"pcr":7,"values":["aa"]}]}"#;
        assert_eq!(
            parse_pcrlock_json(without, PCRLOCK_JSON)
                .expect("parse")
                .nv_index,
            None
        );
    }

    /// The retry decision, as a value.
    ///
    /// The condition it keys on needs another process to extend a PCR while our
    /// policy session is open, which no unit test can arrange; the CHOICE made
    /// about that condition is a pure function and is what is asserted here.
    /// `scripts/tpm-pcr-race-swtpm.sh` produces the real thing on hardware.
    #[test]
    fn only_the_pcr_counter_race_is_treated_as_retryable() {
        use tss_esapi::constants::response_code::Tss2ResponseCodeKind;

        // TPM2_RC_PCR_CHANGED = TPM2_RC_VER1 (0x100) + 0x028.
        let raced = tss_esapi::Error::Tss2Error(0x128u32.into());
        assert_eq!(
            match raced {
                tss_esapi::Error::Tss2Error(rc) => rc.kind(),
                _ => None,
            },
            Some(Tss2ResponseCodeKind::PcrChanged),
            "0x128 must decode as PcrChanged, or the mapper below keys on nothing"
        );
        assert!(
            is_pcr_changed_race(&retryable_tpm_err(raced)),
            "the counter race must be retryable"
        );

        // A neighbouring code must NOT be: retrying a real policy failure would
        // spin on a machine whose PCRs genuinely no longer match.
        for other in [
            0x12f_u32, // TPM2_RC_VER1 + 0x02f, a different VER1 code
            0x99f,     // PolicyFail-class, formatted differently
            0x1,       // a bare failure
        ] {
            let e = retryable_tpm_err(tss_esapi::Error::Tss2Error(other.into()));
            assert!(
                !is_pcr_changed_race(&e),
                "rc {other:#x} must not be retried: {e}"
            );
        }

        // A wrapper-level error carries no response code at all.
        assert!(!is_pcr_changed_race(&retryable_tpm_err(
            tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
        )));
    }

    /// PCR drift and the counter race are different failures and must not be
    /// confused: drift means the machine's state genuinely changed and the user
    /// must re-arm, the race means "try again". Reporting the race as drift
    /// would send someone to re-arm over a transient, and reporting drift as
    /// the race would retry three times and still fail.
    #[test]
    fn the_counter_race_is_not_reported_as_pcr_drift() {
        let raced = retryable_tpm_err(tss_esapi::Error::Tss2Error(0x128u32.into()));
        assert!(is_pcr_changed_race(&raced));
        assert!(
            !is_pcr_mismatch(&raced),
            "the race must not masquerade as drift: {raced}"
        );
    }

    /// The retry loop's mechanics, with the TPM replaced by a counter.
    ///
    /// The loop's behaviour is pinned here and the response-code mapping
    /// above; `scripts/tpm-pcr-race-swtpm.sh` drives the real error through a
    /// software TPM, where a PCR that moves the counter can be extended
    /// without endangering objects belonging to other TPM consumers.
    #[test]
    fn the_retry_loop_reruns_the_attempt_and_then_gives_up() {
        let race = || retryable_tpm_err(tss_esapi::Error::Tss2Error(0x128u32.into()));
        // Ample for four instant closure calls, so the COUNT is what stops
        // the loop here and the budget gets its own test below. Deliberately
        // seconds and not hours: with the count bound removed the always-race
        // case below spins until the budget expires, and an hour-long budget
        // turns that from a fast assertion failure into a hung test run.
        const AMPLE: std::time::Duration = std::time::Duration::from_secs(2);

        // Fails twice, then succeeds: the caller must see the SUCCESS, and the
        // attempt must have run exactly three times.
        let mut calls = 0;
        let got = retry_on_pcr_race(3, AMPLE, || {
            calls += 1;
            if calls < 3 {
                Err(race())
            } else {
                Ok(calls)
            }
        });
        assert_eq!(got.unwrap(), 3);
        assert_eq!(calls, 3, "should have re-run twice after two races");

        // Always racing: bounded at limit+1 attempts, and the error that comes
        // back is the race itself, not something invented by the loop.
        let mut calls = 0;
        let err = retry_on_pcr_race(3, AMPLE, || {
            calls += 1;
            Err::<(), _>(race())
        })
        .expect_err("a permanent race must still fail");
        assert_eq!(calls, 4, "1 initial + 3 retries, then stop");
        assert!(
            is_pcr_changed_race(&err),
            "the original error survives: {err}"
        );

        // A non-race error must not be retried even once: retrying a genuine
        // policy failure would spin and delay the password fallback.
        let mut calls = 0;
        let err = retry_on_pcr_race(3, AMPLE, || {
            calls += 1;
            Err::<(), _>(Error::Tpm("unseal refused: policy fail".into()))
        })
        .expect_err("still an error");
        assert_eq!(calls, 1, "a non-race error must be returned immediately");
        assert!(!is_pcr_changed_race(&err));

        // Success first time: exactly one attempt.
        let mut calls = 0;
        assert_eq!(
            retry_on_pcr_race(3, AMPLE, || {
                calls += 1;
                Ok::<_, Error>(7)
            })
            .unwrap(),
            7
        );
        assert_eq!(calls, 1);
    }

    /// The time bound, which is the one that matters on a discrete TPM: three
    /// retries there is roughly eight seconds, and this runs inside the PAM
    /// auth stack where the login blocks on it.
    ///
    /// A zero budget is the observable edge: the first failure is already past
    /// it, so no retry may start even though the count allows three.
    #[test]
    fn the_retry_loop_stops_when_the_time_budget_is_spent() {
        let race = || retryable_tpm_err(tss_esapi::Error::Tss2Error(0x128u32.into()));

        let mut calls = 0;
        let err = retry_on_pcr_race(3, std::time::Duration::ZERO, || {
            calls += 1;
            Err::<(), _>(race())
        })
        .expect_err("still an error");
        assert_eq!(
            calls, 1,
            "a spent budget must stop the loop even with retries left"
        );
        assert!(is_pcr_changed_race(&err), "the original error survives");

        // And the budget must not truncate a run that is inside it: with room
        // to spare the count is what stops it.
        let mut calls = 0;
        let _ = retry_on_pcr_race(2, std::time::Duration::from_secs(3600), || {
            calls += 1;
            Err::<(), _>(race())
        });
        assert_eq!(
            calls, 3,
            "1 initial + 2 retries while well inside the budget"
        );
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
    #[ignore = "requires a TPM: real /dev/tpmrm0 (root), or swtpm via IRLUME_TCTI (CI does this)"]
    fn seal_unseal_roundtrip_real_tpm() {
        let secret = b"irlume-keyring-secret-roundtrip!";
        let env = seal_with_pcrs(secret, &[7]).expect("seal");
        let got = unseal(&env).expect("unseal");
        assert_eq!(&*got, secret, "round-trip must match");
    }

    #[test]
    #[ignore = "requires a real TPM + fresh systemd signed-PCR artifacts (UKI/systemd-boot); covers Tier-1 PolicyAuthorize"]
    fn seal_unseal_signed_pcr_roundtrip_real_hardware() {
        let secret = b"irlume-keyring-secret-roundtrip!";
        let env = seal(secret).expect("ladder seal on signed-PCR hardware");
        assert!(
            matches!(env.policy, PolicyKind::Authorized { .. }),
            "on signed-PCR hardware the ladder must land on Tier-1 PolicyAuthorize, got {:?}",
            env.policy
        );
        let got = unseal(&env).expect("unseal the signed-PCR envelope");
        assert_eq!(&*got, secret, "signed-PCR round-trip must match");
    }

    /// Real Tier-2 pcrlock seal→unseal on the host TPM. Ignored by default: needs
    /// /dev/tpmrm0, root, and a provisioned pcrlock policy
    /// (`systemd-pcrlock make-policy`, NV index in /var/lib/systemd/pcrlock.json).
    /// Tier-2 pcrlock seal/unseal without systemd-pcrlock: the test provisions
    /// the NV index the way `systemd-pcrlock make-policy` does (owner-hierarchy
    /// NV space holding the alg-tagged policy digest of the predicted PCR
    /// state) and points IRLUME_PCRLOCK_JSON at a matching prediction. Runs
    /// against any TPM; CI uses swtpm. Also proves the drift case: a rewritten
    /// policy that no longer matches the live PCRs refuses the unseal.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0 (root), or swtpm via IRLUME_TCTI (CI does this)"]
    fn seal_unseal_pcrlock_roundtrip_provisioned_nv() {
        use tss_esapi::attributes::NvIndexAttributes;
        use tss_esapi::structures::{MaxNvBuffer, NvPublic};

        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        const NV_INDEX: u32 = 0x0181_C0DE;
        let secret = b"irlume-pcrlock-roundtrip-secret!";

        let mut ctx = open_context().expect("tpm context");
        // Current PCR 7 feeds both the prediction JSON and the policy digest.
        let pcr7 = read_pcr_values(&mut ctx, &[7])
            .expect("read pcr7")
            .remove(0);
        assert_eq!(pcr7.value.len(), 32, "sha256 bank expected");
        let hex: String = pcr7.value.iter().map(|b| format!("{b:02x}")).collect();

        let dir = std::env::temp_dir().join(format!("irlume-pcrlock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let json_path = dir.join("pcrlock.json");
        std::fs::write(
            &json_path,
            format!(
                r#"{{"pcrBank":"sha256","pcrValues":[{{"pcr":7,"values":["{hex}"]}}],"nvIndex":{NV_INDEX}}}"#
            ),
        )
        .unwrap();
        std::env::set_var("IRLUME_PCRLOCK_JSON", &json_path);

        // A leftover index from an aborted run has a different name lineage;
        // drop it before defining ours.
        let nv_handle_t = NvIndexTpmHandle::new(NV_INDEX).unwrap();
        if let Ok(obj) = ctx.tr_from_tpm_public(TpmHandle::NvIndex(nv_handle_t)) {
            let _ = ctx.execute_with_nullauth_session(|ctx| {
                ctx.nv_undefine_space(Provision::Owner, NvIndexHandle::from(obj))
            });
        }

        // Owner-hierarchy NV space, owner read/write, 34 bytes: a 2-byte hash
        // alg id plus the sha256 policy digest, systemd-pcrlock's layout.
        let attrs = NvIndexAttributes::builder()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .unwrap();
        let public = NvPublic::builder()
            .with_nv_index(nv_handle_t)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(attrs)
            .with_data_area_size(34)
            .build()
            .unwrap();
        let nv = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.nv_define_space(Provision::Owner, None, public)
            })
            .expect("nv define");

        // The digest a session holds after PolicyPCR(sel=[7], composite): what
        // the live unseal session presents when PolicyAuthorizeNV compares it
        // against the NV content.
        let composite: [u8; 32] = Sha256::digest(&pcr7.value).into();
        let policy_digest = with_session(&mut ctx, SessionType::Trial, |ctx, session| {
            let policy = PolicySession::try_from(session).map_err(tpm_err)?;
            ctx.policy_pcr(
                policy,
                Digest::try_from(composite.to_vec()).map_err(tpm_err)?,
                pcr_selection(&[7])?,
            )
            .map_err(tpm_err)?;
            ctx.policy_get_digest(policy).map_err(tpm_err)
        })
        .expect("trial policy digest");

        let mut content = vec![0x00u8, 0x0B]; // TPM2_ALG_SHA256, big-endian
        content.extend_from_slice(policy_digest.value());
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.nv_write(
                NvAuth::Owner,
                nv,
                MaxNvBuffer::try_from(content).unwrap(),
                0,
            )
        })
        .expect("nv write");
        drop(ctx);

        // Round trip through the public Tier-2 entry points.
        let env = seal_with_pcrlock(secret, NV_INDEX).expect("pcrlock seal");
        assert!(matches!(env.policy, PolicyKind::PcrlockNv { .. }));
        let got = unseal(&env).expect("pcrlock unseal");
        assert_eq!(&*got, secret, "round-trip must match");

        // Drift: rewrite the NV policy to one the live PCRs cannot satisfy
        // (what a firmware change looks like) and the unseal must refuse.
        let mut ctx = open_context().unwrap();
        let nv = nv_index_handle(&mut ctx, NV_INDEX).unwrap();
        let mut bogus = vec![0x00u8, 0x0B];
        bogus.extend_from_slice(&[0xAB; 32]);
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.nv_write(NvAuth::Owner, nv, MaxNvBuffer::try_from(bogus).unwrap(), 0)
        })
        .unwrap();
        drop(ctx);
        assert!(unseal(&env).is_err(), "stale policy must not unseal");

        // Cleanup: the NV space, the override, the fixture.
        let mut ctx = open_context().unwrap();
        let nv = nv_index_handle(&mut ctx, NV_INDEX).unwrap();
        let _ =
            ctx.execute_with_nullauth_session(|ctx| ctx.nv_undefine_space(Provision::Owner, nv));
        std::env::remove_var("IRLUME_PCRLOCK_JSON");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The software digests must equal what a trial session produces.
    ///
    /// This is the oracle for #248: the TPM has been computing these all along,
    /// so the replacement is only correct if it agrees with the chip on the
    /// exact policies this machine seals under. Compares step by step over the
    /// real prediction, so a marshalling error in TPML_PCR_SELECTION or a wrong
    /// command code shows up as a mismatch rather than as a later unseal
    /// failure nobody can attribute.
    #[test]
    #[ignore = "real TPM, run as root and BY NAME so it cannot be lost among the other ignored \
                TPM tests: sudo <test-binary> software_digests_match --ignored --nocapture"]
    fn software_digests_match_a_trial_session() {
        // FAILS rather than skips when the TPM is out of reach. This is the only
        // thing standing behind replacing a TPM computation with arithmetic, and
        // a test that reports success without observing the hardware it is named
        // for is worse than no test: it is already `#[ignore]`, so anyone running
        // it has asked for hardware.
        let mut ctx = open_context().unwrap_or_else(|e| {
            panic!(
                "this test exists to compare software digests against a real TPM, \
                 and no TPM context could be opened ({e}). Run it as root on a \
                 machine with a TPM; do not treat this as a skip."
            )
        });

        // A single-value PolicyPCR, the shape the singles group takes.
        let one = pcr_composite_digest(&[[0x11; 32]]).unwrap();
        let steps = vec![PolicyStep::Pcr {
            sel: vec![7],
            digest: one.clone(),
        }];
        assert_eq!(
            software_replay(&steps).unwrap().value(),
            trial_replay(&mut ctx, &steps).unwrap().value(),
            "PolicyPCR over one PCR disagrees with the TPM"
        );

        // Several PCRs in one selection, which is how the singles group is
        // actually issued, and where a bitmap error would show.
        let many = pcr_composite_digest(&[[0x22; 32], [0x33; 32], [0x44; 32]]).unwrap();
        let steps = vec![PolicyStep::Pcr {
            sel: vec![0, 2, 13, 15],
            digest: many.clone(),
        }];
        assert_eq!(
            software_replay(&steps).unwrap().value(),
            trial_replay(&mut ctx, &steps).unwrap().value(),
            "PolicyPCR over a multi-PCR selection disagrees with the TPM"
        );

        // PolicyPCR then PolicyOR then PolicyPCR: the OR resets the running
        // digest, and the prefix continues from the reset value. Getting that
        // wrong is the error that would silently produce an unusable policy.
        let branch_a = software_replay(&[PolicyStep::Pcr {
            sel: vec![5],
            digest: pcr_composite_digest(&[[0xAA; 32]]).unwrap(),
        }])
        .unwrap();
        let branch_b = software_replay(&[PolicyStep::Pcr {
            sel: vec![5],
            digest: pcr_composite_digest(&[[0xBB; 32]]).unwrap(),
        }])
        .unwrap();
        let steps = vec![
            PolicyStep::Pcr {
                sel: vec![7],
                digest: one,
            },
            PolicyStep::Or(vec![branch_a, branch_b]),
            PolicyStep::Pcr {
                sel: vec![1, 3],
                digest: many,
            },
        ];
        assert_eq!(
            software_replay(&steps).unwrap().value(),
            trial_replay(&mut ctx, &steps).unwrap().value(),
            "a PolicyPCR/PolicyOR/PolicyPCR chain disagrees with the TPM"
        );
    }

    #[test]
    #[ignore = "requires real TPM + provisioned systemd-pcrlock policy; run as root"]
    fn seal_unseal_pcrlock_roundtrip_real_tpm() {
        let nv_index = pcrlock_provisioned().expect("provisioned pcrlock policy with an NV index");

        let secret = b"irlume-pcrlock-roundtrip-secret!";
        let env = seal_with_pcrlock(secret, nv_index).expect("seal_pcrlock");
        assert!(
            matches!(env.policy, PolicyKind::PcrlockNv { .. }),
            "envelope must be a pcrlock policy"
        );
        let got = unseal(&env).expect("unseal_pcrlock");
        assert_eq!(&*got, secret, "pcrlock round-trip must match");
    }

    /// The auto-tier ladder in [`seal`] on real hardware: whatever tier it
    /// lands on must round-trip. When the pcrlock rung is genuinely usable
    /// (provisioned AND a direct pcrlock seal round-trips) and no signed
    /// policy outranks it, the ladder must land on Tier 2. When pcrlock is
    /// provisioned but broken (e.g. Pop!_OS predicts a PCR 15 the OS never
    /// extends, so the policy can never be satisfied), the ladder must NOT
    /// land there; falling through to the literal seal is the correct result.
    #[test]
    #[ignore = "requires real TPM + provisioned systemd-pcrlock policy; run as root"]
    fn seal_ladder_lands_on_pcrlock_real_tpm() {
        let nv_index = pcrlock_provisioned()
            .expect("test needs a provisioned pcrlock policy with an NV index");
        let secret = b"irlume-auto-ladder-roundtrip-ok!";

        let pcrlock_usable = seal_with_pcrlock(secret, nv_index)
            .ok()
            .and_then(|e| unseal(&e).ok())
            .is_some_and(|rt| rt.as_slice() == secret);

        let env = seal(secret).expect("seal");
        let got = unseal(&env).expect("unseal");
        assert_eq!(&*got, secret, "ladder round-trip must match");

        let landed_pcrlock = matches!(env.policy, PolicyKind::PcrlockNv { .. });
        if pcrlock_usable && !crate::pcrsig::signed_policy_available() {
            assert!(
                landed_pcrlock,
                "usable pcrlock + no signed policy: seal() must pick Tier 2, got {:?}",
                env.policy
            );
        }
        if !pcrlock_usable {
            assert!(
                !landed_pcrlock,
                "seal() must not land on a pcrlock policy that cannot unseal here"
            );
        }
    }

    /// Upgrade-path check, run on a box that armed its envelope with an OLDER
    /// irlume build: the current build must load and unseal it unchanged.
    /// Gated on `IRLUME_UPGRADE_CHECK_USER` naming the user whose envelope to
    /// test; needs root (the envelope is 0600 root) and the same TPM/boot
    /// state the envelope was sealed under.
    #[test]
    #[ignore = "upgrade check; run as root with IRLUME_UPGRADE_CHECK_USER set"]
    fn unseal_preexisting_user_envelope() {
        let user = std::env::var("IRLUME_UPGRADE_CHECK_USER").expect("IRLUME_UPGRADE_CHECK_USER");
        let secret = crate::keyring::unseal_password(&user).expect("old envelope must unseal");
        assert!(
            !secret.is_empty(),
            "unsealed password must not be empty for '{user}'"
        );
    }

    /// Durability phase 1: seal a pcrlock envelope and persist it to
    /// `$IRLUME_PCRLOCK_ENV_OUT`. Paired with the phase-2 test across a
    /// `systemd-pcrlock make-policy` NV rewrite to prove no reseal is needed.
    #[test]
    #[ignore = "durability phase 1; run as root with IRLUME_PCRLOCK_ENV_OUT set"]
    fn pcrlock_seal_to_file() {
        let out = std::env::var("IRLUME_PCRLOCK_ENV_OUT").expect("IRLUME_PCRLOCK_ENV_OUT");
        let nv_index = pcrlock_provisioned().expect("provisioned pcrlock policy with an NV index");
        let env = seal_with_pcrlock(b"durable-across-make-policy!!", nv_index).expect("seal");
        std::fs::write(&out, serde_json::to_vec(&env).expect("ser")).expect("write env");
    }

    /// Durability phase 2: unseal the envelope written by phase 1, after the NV
    /// index was rewritten. Must still release the secret with no reseal.
    #[test]
    #[ignore = "durability phase 2; run as root with IRLUME_PCRLOCK_ENV_IN set"]
    fn pcrlock_unseal_from_file() {
        let inp = std::env::var("IRLUME_PCRLOCK_ENV_IN").expect("IRLUME_PCRLOCK_ENV_IN");
        let raw = std::fs::read(&inp).expect("read env file");
        let env: SealedEnvelope = serde_json::from_slice(&raw).expect("deser env");
        let got = unseal(&env).expect("unseal after make-policy rewrite");
        assert_eq!(
            &*got, b"durable-across-make-policy!!",
            "must survive NV rewrite"
        );
    }

    // ---- Generic fault-injection hooks (battle test) ----
    // Seal to a file, inject a TPM fault out-of-band (tpm2_clear, pcrextend,
    // evictcontrol, nvundefine, blob corruption), then assert unseal fails
    // GRACEFULLY (Err, not panic/hang/segfault) so the daemon denies and PAM
    // falls back to the password. `*_expect_ok` verifies recovery after re-arm.
    const FAULT_SECRET: &[u8] = b"irlume-fault-injection-secret!!!";

    /// Seal via the auto-selected tier (`seal`) to `$IRLUME_ENV_OUT`.
    #[test]
    #[ignore = "fault-injection; run as root with IRLUME_ENV_OUT set"]
    fn fault_seal_default_to_file() {
        let out = std::env::var("IRLUME_ENV_OUT").expect("IRLUME_ENV_OUT");
        let env = seal(FAULT_SECRET).expect("seal");
        std::fs::write(&out, serde_json::to_vec(&env).expect("ser")).expect("write");
    }

    /// Seal a literal `PolicyPCR` over `$IRLUME_TEST_PCRS` (default 7) to
    /// `$IRLUME_ENV_OUT` (for the PCR-drift / firmware-update simulation).
    #[test]
    #[ignore = "fault-injection; run as root with IRLUME_ENV_OUT set"]
    fn fault_seal_pcrs_to_file() {
        let out = std::env::var("IRLUME_ENV_OUT").expect("IRLUME_ENV_OUT");
        let pcrs: Vec<u32> = std::env::var("IRLUME_TEST_PCRS")
            .unwrap_or_else(|_| "7".into())
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        let env = seal_with_pcrs(FAULT_SECRET, &pcrs).expect("seal_with_pcrs");
        std::fs::write(&out, serde_json::to_vec(&env).expect("ser")).expect("write");
    }

    /// Seal a Tier-2 pcrlock envelope to `$IRLUME_ENV_OUT`.
    #[test]
    #[ignore = "fault-injection; run as root with IRLUME_ENV_OUT set"]
    fn fault_seal_pcrlock_to_file() {
        let out = std::env::var("IRLUME_ENV_OUT").expect("IRLUME_ENV_OUT");
        let nv_index = pcrlock_provisioned().expect("provisioned pcrlock policy with an NV index");
        let env = seal_with_pcrlock(FAULT_SECRET, nv_index).expect("seal_pcrlock");
        std::fs::write(&out, serde_json::to_vec(&env).expect("ser")).expect("write");
    }

    /// Assert unseal of `$IRLUME_ENV_IN` fails GRACEFULLY (Err). Passing this
    /// test after a fault = fail-safe confirmed (daemon denies -> password).
    /// A wrongly SUCCESSFUL unseal (state should have invalidated it) is a
    /// security failure and panics loudly.
    #[test]
    #[ignore = "fault-injection; run as root with IRLUME_ENV_IN set"]
    fn fault_unseal_expect_err() {
        let inp = std::env::var("IRLUME_ENV_IN").expect("IRLUME_ENV_IN");
        let raw = std::fs::read(&inp).expect("read env");
        let env: SealedEnvelope = serde_json::from_slice(&raw).expect("deser");
        match unseal(&env) {
            Ok(_) => {
                panic!("SECURITY: unseal SUCCEEDED under injected fault (expected a graceful Err)")
            }
            Err(e) => eprintln!("GRACEFUL-ERR (fail-safe ok): {e}"),
        }
    }

    /// Assert unseal of `$IRLUME_ENV_IN` succeeds and matches (recovery check).
    #[test]
    #[ignore = "fault-injection; run as root with IRLUME_ENV_IN set"]
    fn fault_unseal_expect_ok() {
        let inp = std::env::var("IRLUME_ENV_IN").expect("IRLUME_ENV_IN");
        let raw = std::fs::read(&inp).expect("read env");
        let env: SealedEnvelope = serde_json::from_slice(&raw).expect("deser");
        let got = unseal(&env).expect("unseal should succeed after recovery");
        assert_eq!(&*got, FAULT_SECRET, "recovered secret must match");
    }

    /// Corrupt an envelope's sealed private blob (flip bytes) and rewrite it,
    /// so a following `fault_unseal_expect_err` exercises the load-failure path.
    #[test]
    #[ignore = "fault-injection; corrupts $IRLUME_ENV_IN in place"]
    fn fault_corrupt_env_blob() {
        let inp = std::env::var("IRLUME_ENV_IN").expect("IRLUME_ENV_IN");
        let raw = std::fs::read(&inp).expect("read env");
        let mut env: SealedEnvelope = serde_json::from_slice(&raw).expect("deser");
        for b in env.private.iter_mut().take(16) {
            *b ^= 0xff;
        }
        std::fs::write(&inp, serde_json::to_vec(&env).expect("ser")).expect("write");
    }
}
