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
//! `PolicyAuthorizeNV` against a provisioned systemd-pcrlock NV index (Tier 2,
//! survives firmware / Secure Boot updates once the admin re-runs
//! `make-policy`), else a literal `PolicyPCR` over PCR 7 (Tier 3, the
//! universal fallback; a Secure Boot config change requires a re-arm, and the
//! daemon falls back to the typed password until then). A signed
//! `PolicyAuthorize` over systemd's PCR 11 signature (Tier 1) is no longer
//! sealed: PCR 11 is measured by the operating system itself, so it binds
//! less of the platform than PCR 7 or pcrlock. Tier 1 envelopes written by
//! earlier releases still unseal and move to a bound tier on their next
//! verified reseal.
//!
//! Every transient handle (SRK, loaded sealed object, trial/policy session) is
//! flushed on both success and error paths via the scope helpers below. TPMs
//! expose only a handful of session/transient-object slots, so leaking them
//! bricks the daemon after a few operations.

use crate::envelope::{ParentKey, PcrValue, PolicyKind, SealedEnvelope};
use crate::storage_key;
use irlume_common::{Error, Result};
use sha2::{Digest as _, Sha256};
use std::convert::TryFrom;
use std::str::FromStr;
use zeroize::Zeroizing;

use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::tss::{
    TPM2_HR_HMAC_SESSION, TPM2_HR_NV_INDEX, TPM2_HR_PERSISTENT, TPM2_HR_POLICY_SESSION,
    TPM2_HR_TRANSIENT, TPM2_PERSISTENT_FIRST, TPM2_PERSISTENT_LAST,
};
use tss_esapi::constants::{CapabilityType, PropertyTag, SessionType};
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
    Auth, CapabilityData, Digest, DigestList, HandleList, KeyedHashScheme, Nonce, PcrSelectionList,
    PcrSelectionListBuilder, PcrSlot, Private, Public, PublicBuilder, PublicKeyRsa,
    PublicKeyedHashParameters, PublicRsaParameters, RsaExponent, RsaScheme, RsaSignature,
    SensitiveData, Signature, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::ESYS_TR;
use tss_esapi::{Context, TctiNameConf};

/// The raw TPM character device, tried first. The kernel resource manager
/// (`/dev/tpmrm0`) saves and flushes every session and transient object after
/// EVERY command so that spaces can share the chip; on AMD firmware TPMs each
/// of those context round trips costs 40–90 ms, which turned a Tier-1 unseal
/// of ~80 ms of TPM work into ~1.5 s (#797, ADR-0026). The raw device runs the
/// same commands with no juggling. It is exclusive-open, so anything else on
/// it (a userspace resource manager, another irlume process mid-unseal) makes
/// the open fail with EBUSY, and we fall back to the manager for that call.
const TCTI_RAW_DEVICE: &str = "device:/dev/tpm0";
/// The kernel resource manager: the fallback, and what `IRLUME_TCTI` should
/// name to pin the previous behaviour.
const TCTI_RESOURCE_MANAGER: &str = "device:/dev/tpmrm0";

/// TPM2_PolicyAuthorize command code (big-endian), folded into the authorized
/// policy digest per the TPM2 spec.
#[cfg(test)]
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

/// The persistent handles Owner Authorization may assign (Part 1 34.3);
/// 0x81800000 to 0x81FFFFFF need Platform Authorization.
pub(crate) const OWNER_PERSISTENT: std::ops::RangeInclusive<u32> = 0x8100_0000..=0x817F_FFFF;

/// The start of the `unique` of irlume's DA-exempt storage key template
/// ([`da_exempt_srk_template`]), zero-padded to [`RSA_2048_MODULUS_BYTES`].
/// Never change it: it decides which key the template derives.
const DA_EXEMPT_SRK_LABEL: &[u8] = b"irlume ADR-0034 storage key";

/// The size of an RSA-2048 modulus, which the TPM writes into `unique`.
const RSA_2048_MODULUS_BYTES: usize = 256;

/// Handles asked for per GetCapability page: as many as one capability
/// buffer of the TSS's size holds. A TPM may return fewer and set moreData.
const HANDLES_PER_PAGE: u32 = HandleList::MAX_SIZE as u32;

fn tpm_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Tpm(e.to_string())
}

/// One TPM conversation's context. Derefs to the ESAPI [`Context`]; on the raw
/// device it also carries the conversation marker (see [`RawConversation`]),
/// which is removed when the context is dropped on any normal exit.
pub(crate) struct TpmContext {
    ctx: Context,
    _conversation: Option<RawConversation>,
}

impl std::ops::Deref for TpmContext {
    type Target = Context;
    fn deref(&self) -> &Context {
        &self.ctx
    }
}

impl std::ops::DerefMut for TpmContext {
    fn deref_mut(&mut self) -> &mut Context {
        &mut self.ctx
    }
}

fn open_context() -> Result<TpmContext> {
    open_context_from(std::env::var("IRLUME_TCTI").ok().as_deref(), |tcti| {
        let conf = TctiNameConf::from_str(tcti).map_err(tpm_err)?;
        Context::new(conf).map_err(tpm_err)
    })
}

/// Transport order for one TPM conversation. An explicit `IRLUME_TCTI` is
/// obeyed alone (tests, swtpm, a pinned manager); otherwise the raw device is
/// tried and the resource manager is the fallback.
fn tcti_candidates(explicit: Option<&str>) -> Vec<&str> {
    match explicit {
        Some(tcti) => vec![tcti],
        None => vec![TCTI_RAW_DEVICE, TCTI_RESOURCE_MANAGER],
    }
}

/// Open the first transport in [`tcti_candidates`] that works. On the raw
/// device the conversation marker is consulted first: a marker left by a
/// predecessor that died mid-conversation triggers a sweep of that
/// predecessor's leaked handles (see [`RawConversation::begin`]); if the sweep
/// fails the context is dropped and the next transport is tried, so a raw
/// device that opens but misbehaves never strands a request.
fn open_context_from(
    explicit: Option<&str>,
    open: impl Fn(&str) -> Result<Context>,
) -> Result<TpmContext> {
    let candidates = tcti_candidates(explicit);
    let mut last = None;
    for (index, tcti) in candidates.iter().enumerate() {
        let attempt = open(tcti).and_then(|mut ctx| {
            let conversation = if *tcti == TCTI_RAW_DEVICE {
                RawConversation::begin(&mut ctx)?
            } else {
                None
            };
            Ok(TpmContext {
                ctx,
                _conversation: conversation,
            })
        });
        match attempt {
            Ok(ctx) => return Ok(ctx),
            Err(e) => {
                if index + 1 < candidates.len() {
                    note_fallback_once(tcti, &e);
                }
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| Error::Tpm("no TPM transport configured".into())))
}

/// Say once per process that the raw device was unavailable. EBUSY from a
/// concurrent opener is ordinary; a permanent denial is worth a line in the
/// journal because every later unseal then pays the manager's cost.
fn note_fallback_once(tcti: &str, error: &Error) {
    static NOTED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    NOTED.get_or_init(|| {
        irlume_common::dlog!(
            "irlume: TPM transport {tcti} unavailable ({error}); using {TCTI_RESOURCE_MANAGER} \
             (slower on some firmware TPMs; set IRLUME_TCTI to pin a transport)"
        );
    });
}

/// The handle ranges a raw-device sweep looks at. The chip answers a
/// loaded-session query from the HMAC range with EVERY loaded session, policy
/// sessions included (observed on the AMD fTPM and the Intel PTTs); the
/// policy range is still asked so a chip that separates them is covered.
const SWEEP_RANGES: [u32; 3] = [
    TPM2_HR_TRANSIENT,
    TPM2_HR_HMAC_SESSION,
    TPM2_HR_POLICY_SESSION,
];

/// Every loaded handle in `range` as the chip reports it.
fn loaded_handles(ctx: &mut Context, range: u32) -> Result<Vec<TpmHandle>> {
    let (data, _more) = ctx
        .get_capability(CapabilityType::Handles, range, 0xff)
        .map_err(tpm_err)?;
    let CapabilityData::Handles(list) = data else {
        return Err(Error::Tpm(
            "TPM returned a non-handle capability for a handle query".into(),
        ));
    };
    Ok(list.into_inner())
}

/// Every loaded handle across [`SWEEP_RANGES`], as raw handle numbers, sorted
/// and deduplicated (the HMAC and policy queries can list the same session).
fn loaded_handle_numbers(ctx: &mut Context) -> Result<Vec<u32>> {
    let mut numbers = Vec::new();
    for range in SWEEP_RANGES {
        numbers.extend(loaded_handles(ctx, range)?.into_iter().map(u32::from));
    }
    numbers.sort_unstable();
    numbers.dedup();
    Ok(numbers)
}

/// The marker of one raw-device conversation. Handles loaded through
/// `/dev/tpm0` belong to the chip, not to a process: nothing frees them if the
/// loading process dies mid-conversation (the kernel reclaims only
/// resource-manager spaces), and a chip whose handful of slots is full refuses
/// every later `Load`. Nor do they carry an owner, so "flush whatever is
/// loaded" would also destroy the state of another raw client that keeps a
/// handle loaded between its own opens. The marker separates the two: at the
/// start of a conversation it records the handles ALREADY loaded (someone
/// else's, to be preserved) and is removed on any normal exit. A marker still
/// present at the next open means irlume died mid-conversation, and only the
/// handles that appeared after that record are irlume's leaks and get flushed.
///
/// The marker lives on tmpfs under the daemon's lock directory, so a reboot
/// (which also resets the chip) clears it. Where the directory is missing or
/// not writable the conversation runs without a marker and without a sweep;
/// the raw device is still used, and only the crash recovery is lost.
struct RawConversation {
    path: std::path::PathBuf,
}

impl RawConversation {
    /// Recover from a predecessor's crash if its marker is present, then
    /// record this conversation's starting state. `None` when no marker can be
    /// kept (no lock directory): the raw device is used without recovery.
    fn begin(ctx: &mut Context) -> Result<Option<Self>> {
        let Some(path) = marker_path() else {
            return Ok(None);
        };
        if let Ok(text) = std::fs::read_to_string(&path) {
            sweep_after_crash(ctx, &parse_marker(&text))?;
        }
        let loaded = loaded_handle_numbers(ctx)?;
        if std::fs::write(&path, format_marker(&loaded)).is_err() {
            note_marker_unavailable_once(&path);
            return Ok(None);
        }
        Ok(Some(Self { path }))
    }
}

impl Drop for RawConversation {
    fn drop(&mut self) {
        // Every load in this module is paired with a flush on success and
        // error paths, so on a normal exit nothing of ours is left loaded and
        // the marker has served its purpose. A crash skips this, on purpose.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Flush the handles a crashed predecessor left loaded: those loaded now that
/// were NOT already loaded when it began (`prior`). Individual flush results
/// are not decisive: ESYS reports "invalid handle state" for a reconstructed
/// policy session AFTER the chip has flushed it (observed on the AMD fTPM).
/// What decides is the chip's view afterwards: the sweep fails only if one of
/// the predecessor's handles is still loaded, and then this context is
/// abandoned for the fallback transport.
fn sweep_after_crash(ctx: &mut Context, prior: &[u32]) -> Result<()> {
    for range in SWEEP_RANGES {
        for handle in loaded_handles(ctx, range)? {
            if !handles_to_flush(&[u32::from(handle)], prior).is_empty() {
                // The same route `tpm2_flushcontext --transient/--loaded-session`
                // takes: resolve the chip handle to an ESYS resource, then flush.
                if let Ok(object) = ctx.tr_from_tpm_public(handle) {
                    let _ = ctx.flush_context(object);
                }
            }
        }
    }
    let remaining = handles_to_flush(&loaded_handle_numbers(ctx)?, prior);
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(Error::Tpm(format!(
            "{} stale TPM handle(s) from an interrupted conversation could not be flushed",
            remaining.len()
        )))
    }
}

/// The handles a sweep may touch: loaded now and not in the recorded prior
/// set. Pure; the ownership rule of [`RawConversation`] in one place.
fn handles_to_flush(loaded: &[u32], prior: &[u32]) -> Vec<u32> {
    loaded
        .iter()
        .copied()
        .filter(|h| !prior.contains(h))
        .collect()
}

/// Marker file location: `IRLUME_TPM_MARKER_DIR` (tests, containers) or the
/// daemon's tmpfs lock directory. `None` when the directory does not exist.
fn marker_path() -> Option<std::path::PathBuf> {
    let dir = std::env::var_os("IRLUME_TPM_MARKER_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/run/lock/irlume"));
    dir.is_dir().then(|| dir.join("tpm-raw-conversation"))
}

fn format_marker(handles: &[u32]) -> String {
    handles.iter().map(|h| format!("{h:#010x}\n")).collect()
}

/// Lenient: a line that is not a hex handle is ignored rather than aborting
/// recovery, since an unreadable marker must not strand the raw device.
fn parse_marker(text: &str) -> Vec<u32> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let hex = line.strip_prefix("0x").unwrap_or(line);
            u32::from_str_radix(hex, 16).ok()
        })
        .collect()
}

fn note_marker_unavailable_once(path: &std::path::Path) {
    static NOTED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    NOTED.get_or_init(|| {
        irlume_common::dlog!(
            "irlume: cannot write the TPM conversation marker {}; raw-device crash recovery is off for this process",
            path.display()
        );
    });
}

pub use irlume_common::tpm_readiness::{
    roca_fingerprint, DerivedKey, FirmwareAdvisory, PcrBankReadiness, StorageKeyCheck, TpmIdentity,
    TpmLockout,
};

/// The ASCII text of TPM property words: printable characters only, runs of
/// padding spaces read as one.
fn property_text(words: &[u32]) -> String {
    words
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .filter(|b| b.is_ascii_graphic() || *b == b' ')
        .map(char::from)
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Read this TPM's manufacturer, vendor string and firmware version.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn tpm_identity() -> Result<TpmIdentity> {
    let mut ctx = open_context()?;
    let mut property = |tag| ctx.get_tpm_property(tag).map_err(tpm_err);
    identity_from(
        property(PropertyTag::Manufacturer)?,
        [
            property(PropertyTag::VendorString1)?,
            property(PropertyTag::VendorString2)?,
            property(PropertyTag::VendorString3)?,
            property(PropertyTag::VendorString4)?,
        ],
        property(PropertyTag::FirmwareVersion1)?,
    )
}

/// Read this TPM's dictionary-attack lockout state (ADR-0034 §4):
/// `TPM_PT_PERMANENT` and the four lockout properties, in one `GetCapability`
/// command, which needs no authorization. Creates and changes nothing, and
/// works while the TPM is in lockout.
///
/// # Errors
///
/// [`Error::Tpm`] when the TPM cannot be opened or read, or leaves out one of
/// the properties, which every TPM 2.0 reports.
pub fn lockout_state() -> Result<TpmLockout> {
    let mut ctx = open_context()?;
    // One command from TPM_PT_PERMANENT (0x200) through
    // TPM_PT_LOCKOUT_RECOVERY (0x211), so the lockout bit and the counter
    // are one reading: separate reads (tss-esapi's `get_tpm_property` asks
    // for four properties at a time) could straddle a failure or a recovery
    // and disagree. A context of its own also keeps `get_tpm_property`'s
    // per-context cache out of the way.
    let first = u32::from(PropertyTag::Permanent);
    let last = u32::from(PropertyTag::LockoutRecovery);
    let (data, _more) = ctx
        .get_capability(CapabilityType::TpmProperties, first, last - first + 1)
        .map_err(tpm_err)?;
    let CapabilityData::TpmProperties(list) = data else {
        return Err(Error::Tpm(
            "TPM returned a non-property capability for a property query".into(),
        ));
    };
    let value = |tag| list.find(tag).map(|property| property.value());
    lockout_from(
        [
            value(PropertyTag::Permanent),
            value(PropertyTag::LockoutCounter),
            value(PropertyTag::MaxAuthFail),
            value(PropertyTag::LockoutInterval),
            value(PropertyTag::LockoutRecovery),
        ],
        lockout_spares_irlume(&mut ctx),
    )
}

/// Whether a TPM lockout blocks none of irlume's envelopes: the DA-exempt key
/// irlumed recorded is at its handle with its name and shape, and every
/// envelope records it as its parent, so new seals and every unseal go
/// through it. An envelope store that cannot be read, or a TPM read that
/// fails, answers no, which keeps doctor's lockout warning.
fn lockout_spares_irlume(ctx: &mut Context) -> bool {
    let Some((handle, name)) = storage_key::recorded_key() else {
        return false;
    };
    da_exempt_key_at(ctx, handle, &name, true).is_ok_and(|key| key.is_some())
        && storage_key::every_envelope_on(&storage_key::hex(&name)).unwrap_or(false)
}

/// A [`TpmLockout`] from the properties `GetCapability` returned, in the
/// order `TPM_PT_PERMANENT`, `TPM_PT_LOCKOUT_COUNTER`, `TPM_PT_MAX_AUTH_FAIL`,
/// `TPM_PT_LOCKOUT_INTERVAL`, `TPM_PT_LOCKOUT_RECOVERY`. Every one is
/// required. `storage_key_no_da` is whether a lockout blocks none of
/// irlume's envelopes ([`lockout_spares_irlume`]).
fn lockout_from(properties: [Option<u32>; 5], storage_key_no_da: bool) -> Result<TpmLockout> {
    const NAMES: [&str; 5] = [
        "permanent attributes",
        "lockout counter",
        "maximum authorization failures",
        "lockout interval",
        "lockout recovery time",
    ];
    let mut values = [0u32; 5];
    for (slot, (value, name)) in values.iter_mut().zip(properties.into_iter().zip(NAMES)) {
        *slot = value.ok_or_else(|| Error::Tpm(format!("the TPM did not report its {name}")))?;
    }
    let [permanent, failed_tries, max_tries, recovery_time, lockout_recovery] = values;
    Ok(TpmLockout::from_properties(
        permanent,
        failed_tries,
        max_tries,
        recovery_time,
        lockout_recovery,
        storage_key_no_da,
    ))
}

/// A [`TpmIdentity`] from the properties `GetCapability` returned. The
/// manufacturer and firmware version are required; a TPM that leaves one out
/// (failure mode, a nonconforming part) is not identified. The vendor string
/// words are optional.
fn identity_from(
    manufacturer: Option<u32>,
    vendor: [Option<u32>; 4],
    version: Option<u32>,
) -> Result<TpmIdentity> {
    let required = |value: Option<u32>, what: &str| {
        value.ok_or_else(|| Error::Tpm(format!("the TPM did not report its {what}")))
    };
    let manufacturer = property_text(&[required(manufacturer, "manufacturer")?]);
    let version = required(version, "firmware version")?;
    Ok(TpmIdentity {
        manufacturer,
        vendor: property_text(&vendor.map(Option::unwrap_or_default)),
        firmware: ((version >> 16) as u16, version as u16),
    })
}

/// The readiness of `values`, the SHA-256 reading of the policy PCRs.
fn classify_pcr_bank(values: &[PcrValue]) -> PcrBankReadiness {
    let missing: Vec<u32> = values
        .iter()
        .filter(|v| v.value.len() != 32)
        .map(|v| v.pcr)
        .collect();
    if !missing.is_empty() {
        return PcrBankReadiness::Missing(missing);
    }
    let unextended: Vec<u32> = values
        .iter()
        .filter(|v| {
            crate::envelope::binds_firmware_state(&[v.pcr]) && v.value.iter().all(|&b| b == 0)
        })
        .map(|v| v.pcr)
        .collect();
    if unextended.is_empty() {
        PcrBankReadiness::Ready(values.iter().map(|v| v.pcr).collect())
    } else {
        PcrBankReadiness::Unextended(unextended)
    }
}

/// Check irlume's persistent storage key for the ROCA fingerprint. Reads the
/// public area of the key at irlume's handle and creates or changes nothing. A
/// handle that is empty, or holds another stack's key, is
/// [`StorageKeyCheck::Absent`]: irlume then derives a transient key each time,
/// from the same template, so the firmware version decides.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn storage_key_check() -> Result<StorageKeyCheck> {
    let mut ctx = open_context()?;
    let handle = persistent_srk_raw();
    let wanted = TpmHandle::Persistent(PersistentTpmHandle::new(handle).map_err(tpm_err)?);
    if !tpm_handle_exists(&mut ctx, TPM2_HR_PERSISTENT, wanted)? {
        return Ok(StorageKeyCheck::Absent);
    }
    let object = ctx.tr_from_tpm_public(wanted).map_err(tpm_err)?;
    let (public, _, _) = ctx
        .read_public(KeyHandle::from(ESYS_TR::from(object)))
        .map_err(tpm_err)?;
    if !is_irlume_srk(&public)? {
        return Ok(StorageKeyCheck::Absent);
    }
    let roca = matches!(&public, Public::Rsa { unique, .. } if roca_fingerprint(unique.value()));
    roca_verdict(roca, handle, || derived_srk(&mut ctx, &public))
}

/// The storage-key verdict. Only a key with the ROCA fingerprint, which doctor
/// then advises evicting, is compared with the key irlume's template derives,
/// since deriving it takes seconds on slow TPMs. A comparison that fails (an
/// owner-hierarchy password, say) leaves the fingerprint reported, with
/// `derived` unknown.
fn roca_verdict(
    roca: bool,
    handle: u32,
    derived: impl FnOnce() -> Result<DerivedKey>,
) -> Result<StorageKeyCheck> {
    if !roca {
        return Ok(StorageKeyCheck::Clean);
    }
    Ok(StorageKeyCheck::RocaFingerprint {
        handle,
        derived: derived().ok(),
    })
}

/// Compare `persisted` with the key irlume's [`srk_template`] derives under
/// the owner hierarchy today. The same template, seed and firmware always give
/// the same modulus, so a key with irlume's template and another modulus was
/// placed by another tool or derived before a firmware update changed the key
/// generation. Derives a transient primary to compare and flushes it.
fn derived_srk(ctx: &mut Context, persisted: &Public) -> Result<DerivedKey> {
    let derived = derive_public(ctx, srk_template()?)?;
    Ok(compare_moduli(persisted, &derived))
}

/// The public area of the key `template` derives under the owner hierarchy
/// today. Derives a transient primary, reads it and flushes it.
fn derive_public(ctx: &mut Context, template: Public) -> Result<Public> {
    let transient = create_storage_key(ctx, template)?;
    let derived = ctx.read_public(transient);
    let _ = ctx.flush_context(transient.into());
    // A read failure is a transport error, not evidence about identity (the
    // #757 review caught every-error-is-foreign).
    let (derived, _, _) = derived.map_err(tpm_err)?;
    Ok(derived)
}

/// [`DerivedKey::compare`] of two keys' moduli; a non-RSA key is
/// [`DerivedKey::Other`].
fn compare_moduli(persisted: &Public, derived: &Public) -> DerivedKey {
    match (rsa_modulus(persisted), rsa_modulus(derived)) {
        (Some(persisted), Some(derived)) => DerivedKey::compare(persisted, derived),
        _ => DerivedKey::Other,
    }
}

/// Whether `persisted` is the key irlume's [`srk_template`] derives today
/// ([`derived_srk`]).
fn derives_from_srk_template(ctx: &mut Context, persisted: &Public) -> Result<bool> {
    Ok(derived_srk(ctx, persisted)? == DerivedKey::Same)
}

/// Read the policy PCRs ([`policy_pcrs`]) from the SHA-256 bank and say
/// whether a literal seal over them can bind the boot state.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn pcr_bank_readiness() -> Result<PcrBankReadiness> {
    let mut ctx = open_context()?;
    Ok(classify_pcr_bank(&read_pcr_values(
        &mut ctx,
        &policy_pcrs(),
    )?))
}

/// The PCRs to bind to: `IRLUME_PCRS` (comma-separated) or `DEFAULT_PCRS`.
pub fn policy_pcrs() -> Vec<u32> {
    std::env::var("IRLUME_PCRS")
        .ok()
        .map(|s| parse_pcrs(&s))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_PCRS.to_vec())
}

/// The PCRs a comma-separated list names, each once, in the order first
/// given: a PCR named twice binds nothing more, and every copy would be
/// stored in the envelope.
fn parse_pcrs(list: &str) -> Vec<u32> {
    let mut pcrs = Vec::new();
    for pcr in list.split(',').filter_map(|p| p.trim().parse::<u32>().ok()) {
        if !pcrs.contains(&pcr) {
            pcrs.push(pcr);
        }
    }
    pcrs
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

/// The template of the storage key every irlume envelope so far is sealed
/// under. It lacks noDA, so a TPM in dictionary-attack lockout refuses to
/// load children under it (ADR-0034, "A gap found while checking").
fn srk_template() -> Result<Public> {
    storage_key_template(false, PublicKeyRsa::default())
}

/// The DA-exempt storage key template of ADR-0034 §3.1: [`srk_template`] with
/// noDA set and [`da_exempt_srk_unique`] in `unique`. Without the label it
/// would be the TCG shared storage key template (Provisioning Guidance
/// 7.5.1) that systemd and other stacks derive and persist, and CreatePrimary
/// derives the same key from the same template, so a key matching it would
/// not have to be irlume's (the section's 2026-10-15 amendment).
fn da_exempt_srk_template() -> Result<Public> {
    storage_key_template(true, da_exempt_srk_unique()?)
}

/// [`DA_EXEMPT_SRK_LABEL`] followed by zero bytes to the size of an RSA-2048
/// modulus, as the EK Credential Profile pads its nonce for template L-1.
/// Part 1 24.2.7 lets a caller place any value in `unique` that is structured
/// like the one the TPM writes there.
fn da_exempt_srk_unique() -> Result<PublicKeyRsa> {
    let mut unique = vec![0u8; RSA_2048_MODULUS_BYTES];
    unique[..DA_EXEMPT_SRK_LABEL.len()].copy_from_slice(DA_EXEMPT_SRK_LABEL);
    PublicKeyRsa::try_from(unique).map_err(tpm_err)
}

/// An RSA-2048 storage key template with the TCG storage key attributes,
/// noDA as `no_da` says, and `unique`, which CreatePrimary hashes into the
/// key's derivation with the rest of the template.
fn storage_key_template(no_da: bool, unique: PublicKeyRsa) -> Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(no_da)
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
        .with_rsa_unique_identifier(unique)
        .build()
        .map_err(tpm_err)
}

/// How many times [`read_pcr_values`] starts over when a PCR moved between the
/// `PCR_Read`s of one snapshot.
const PCR_SNAPSHOT_ATTEMPTS: usize = 3;

/// Read the SHA-256 values for `pcrs` as one snapshot and return them in the
/// same order, stashed in the envelope so an unseal failure can point at the
/// PCR that shifted. A literal seal's policy commits to them together, so a
/// mixture of values the TPM never held at once would never unseal.
///
/// One `PCR_Read` answers up to eight PCRs atomically, which covers every
/// selection irlume seals to by default. A TPM that answers part of the
/// selection is asked for the rest, and the answers count as one snapshot only
/// while its PCR update counter stays the same; otherwise the read starts
/// over. A PCR the TPM returns no value for (an unallocated bank) gets an
/// empty value, which [`literal_auth_policy`] refuses.
fn read_pcr_values(ctx: &mut Context, pcrs: &[u32]) -> Result<Vec<PcrValue>> {
    if pcrs.is_empty() {
        return Ok(Vec::new());
    }
    let wanted = pcr_selection(pcrs)?;
    for _ in 0..PCR_SNAPSHOT_ATTEMPTS {
        if let Some(read) = read_pcr_snapshot(ctx, wanted.clone())? {
            return Ok(pcrs
                .iter()
                .map(|&pcr| PcrValue {
                    pcr,
                    value: read
                        .iter()
                        .find(|v| v.pcr == pcr)
                        .map(|v| v.value.clone())
                        .unwrap_or_default(),
                })
                .collect());
        }
    }
    Err(Error::Tpm(format!(
        "PCRs {pcrs:?} kept changing while they were read; try again"
    )))
}

/// One snapshot of `remaining`, or `None` when the PCR update counter moved
/// between two of its `PCR_Read`s.
fn read_pcr_snapshot(
    ctx: &mut Context,
    mut remaining: PcrSelectionList,
) -> Result<Option<Vec<PcrValue>>> {
    let mut read = Vec::new();
    let mut counter = None;
    while !remaining.is_empty() {
        let (update_counter, answered, digests) =
            ctx.pcr_read(remaining.clone()).map_err(tpm_err)?;
        if counter.is_some_and(|c| c != update_counter) {
            return Ok(None);
        }
        counter = Some(update_counter);
        let slots: Vec<u32> = answered
            .get_selections()
            .iter()
            .filter(|s| s.hashing_algorithm() == HashingAlgorithm::Sha256)
            .flat_map(|s| s.selected())
            .map(|slot| u32::from(slot).trailing_zeros())
            .collect();
        if slots.is_empty() {
            // Nothing more comes back for the rest of the selection.
            break;
        }
        if slots.len() != digests.value().len() {
            return Err(Error::Tpm(format!(
                "PCR_Read answered {} PCRs with {} digests",
                slots.len(),
                digests.value().len()
            )));
        }
        read.extend(
            slots
                .into_iter()
                .zip(digests.value())
                .map(|(pcr, digest)| PcrValue {
                    pcr,
                    value: digest.value().to_vec(),
                }),
        );
        remaining.subtract(&answered).map_err(tpm_err)?;
    }
    Ok(Some(read))
}

/// Run `body` with an auth session of `kind`; flush the session on the way out
/// regardless of whether `body` succeeded.
fn with_session<T>(
    ctx: &mut Context,
    salt: Option<KeyHandle>,
    kind: SessionType,
    body: impl FnOnce(&mut Context, AuthSession) -> Result<T>,
) -> Result<T> {
    // `salt` is load-bearing, not decoration. ESYS parameter encryption derives
    // its key from the session key, and an UNSALTED, UNBOUND session has an
    // EMPTY session key: the TPM then returns the response parameter in the
    // clear while ESYS still "decrypts" it, so `unseal` hands back plausible
    // garbage instead of the sealed secret. The sealed object is fine; only the
    // response is mangled, which is why a tpm2-tools unseal of the very same
    // object succeeds. Salting against the SRK gives both sides the same key,
    // so the secret is genuinely protected on the bus AND comes back intact.
    // Trial sessions pass `None`: they carry no secret, and turning encryption
    // off there keeps them correct without a salt.
    let session = ctx
        .start_auth_session(
            salt,
            None,
            None,
            kind,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(tpm_err)?
        .ok_or_else(|| Error::Tpm("start_auth_session returned None".into()))?;
    let encrypted = salt.is_some();
    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(encrypted)
        .with_encrypt(encrypted)
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

/// The `authPolicy` a literal `PolicyPCR` seal commits to, computed from
/// `values`, the PCR values just read from this TPM.
///
/// Not a trial session: TCG Part 3 §23.7 lets a trial `PolicyPCR` with an
/// empty `pcrDigest` use the current PCRs (preferred) or refuse, and the
/// STMicroelectronics TPM in a ThinkPad T480 does neither: it hashes the empty
/// digest in, giving a policy no unseal session can satisfy (#1067). systemd
/// computes this value the same way, and the pcrlock tier already did (#248).
/// The composite is over the values in ascending PCR order, each PCR once, as
/// the TPM computes it. A PCR without a SHA-256 value refuses the seal, since
/// the TPM would drop it from the policy and the seal would not bind it.
fn literal_auth_policy(values: &[PcrValue]) -> Result<Digest> {
    let mut ordered = values
        .iter()
        .map(|v| {
            <[u8; 32]>::try_from(v.value.as_slice())
                .map(|value| (v.pcr, value))
                .map_err(|_| {
                    Error::Tpm(format!(
                        "PCR {} has no SHA-256 value on this TPM; refusing to seal to it",
                        v.pcr
                    ))
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let zero = Digest::try_from(vec![0u8; 32]).map_err(tpm_err)?;
    if ordered.is_empty() {
        return Ok(zero);
    }
    ordered.sort_unstable_by_key(|&(pcr, _)| pcr);
    ordered.dedup_by_key(|&mut (pcr, _)| pcr);
    let pcrs: Vec<u32> = ordered.iter().map(|&(pcr, _)| pcr).collect();
    let values: Vec<[u8; 32]> = ordered.iter().map(|&(_, value)| value).collect();
    policy_pcr_digest(&zero, &pcrs, &pcr_composite_digest(&values)?)
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
    create_storage_key(ctx, srk_template()?)
}

/// Derive the primary key `template` describes under the owner hierarchy, as
/// a transient object, with an empty owner authorization.
fn create_storage_key(ctx: &mut Context, template: Public) -> Result<KeyHandle> {
    let primary = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map_err(tpm_err)?;
    Ok(primary.key_handle)
}

/// irlume's persistent SRK handle: `IRLUME_SRK_HANDLE` (hex) or
/// [`PERSISTENT_SRK_HANDLE`].
fn persistent_srk_raw() -> u32 {
    std::env::var("IRLUME_SRK_HANDLE")
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(PERSISTENT_SRK_HANDLE)
}

fn persistent_srk_handle() -> Result<PersistentTpmHandle> {
    PersistentTpmHandle::new(persistent_srk_raw()).map_err(tpm_err)
}

/// Where irlume's DA-exempt storage key goes (ADR-0034 §3.2), from
/// `IRLUME_SRK_HANDLE`.
pub(crate) fn da_exempt_key_plan() -> std::result::Result<storage_key::Plan, String> {
    da_exempt_key_plan_for(std::env::var("IRLUME_SRK_HANDLE").ok().as_deref())
}

/// [`da_exempt_key_plan`] for an override value. The preferred handle is the
/// one after the original key's, or the one before for 0x817FFFFF, the top of
/// the owner range. The value is read as [`persistent_srk_raw`] reads it, so
/// both keys agree on the original handle; one that does not parse, which the
/// original key replaces with [`PERSISTENT_SRK_HANDLE`], or one outside the
/// owner persistent range is refused, and no new key is persisted.
pub(crate) fn da_exempt_key_plan_for(
    value: Option<&str>,
) -> std::result::Result<storage_key::Plan, String> {
    let original = match value {
        None => PERSISTENT_SRK_HANDLE,
        Some(text) => u32::from_str_radix(text.trim().trim_start_matches("0x"), 16)
            .map_err(|_| format!("IRLUME_SRK_HANDLE={text:?} does not parse as a hex handle"))?,
    };
    if !OWNER_PERSISTENT.contains(&original) {
        return Err(format!(
            "IRLUME_SRK_HANDLE={original:#010x} is outside the owner persistent range \
             0x81000000 to 0x817fffff"
        ));
    }
    let preferred = if original == *OWNER_PERSISTENT.end() {
        original - 1
    } else {
        original + 1
    };
    Ok(storage_key::Plan {
        preferred,
        original,
    })
}

/// [`storage_key::KeyTpm`] over one TPM context. Dropping it flushes the
/// derived key, which persists only as the copy `persist` made.
pub(crate) struct DaExemptKeyTpm {
    ctx: TpmContext,
    derived: Option<KeyHandle>,
}

impl DaExemptKeyTpm {
    pub(crate) fn open() -> Result<Self> {
        Ok(Self {
            ctx: open_context()?,
            derived: None,
        })
    }
}

impl Drop for DaExemptKeyTpm {
    fn drop(&mut self) {
        if let Some(derived) = self.derived.take() {
            let _ = self.ctx.flush_context(derived.into());
        }
    }
}

impl storage_key::KeyTpm for DaExemptKeyTpm {
    fn name_at(&mut self, handle: u32) -> Result<Option<Vec<u8>>> {
        // Probed first, so that a free handle logs no esys error (#601).
        if !persistent_handle_present(&mut self.ctx, handle)? {
            return Ok(None);
        }
        let persistent = PersistentTpmHandle::new(handle).map_err(tpm_err)?;
        let object = self
            .ctx
            .tr_from_tpm_public(TpmHandle::Persistent(persistent))
            .map_err(tpm_err)?;
        let (_, name, _) = self
            .ctx
            .read_public(KeyHandle::from(ESYS_TR::from(object)))
            .map_err(tpm_err)?;
        Ok(Some(name.value().to_vec()))
    }

    fn persistent_avail(&mut self) -> Result<u32> {
        let tag = PropertyTag::HrPersistentAvail;
        let (data, _more) = self
            .ctx
            .get_capability(CapabilityType::TpmProperties, u32::from(tag), 1)
            .map_err(tpm_err)?;
        let CapabilityData::TpmProperties(list) = data else {
            return Err(Error::Tpm(
                "TPM returned a non-property capability for a property query".into(),
            ));
        };
        list.find(tag)
            .map(|property| property.value())
            .ok_or_else(|| Error::Tpm("the TPM did not report TPM_PT_HR_PERSISTENT_AVAIL".into()))
    }

    fn derive(&mut self) -> std::result::Result<Vec<u8>, storage_key::Failure> {
        let template = da_exempt_srk_template().map_err(other_failure)?;
        let primary = self
            .ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
            })
            .map_err(classify_failure)?;
        if let Some(earlier) = self.derived.replace(primary.key_handle) {
            let _ = self.ctx.flush_context(earlier.into());
        }
        let (_, name, _) = self
            .ctx
            .read_public(primary.key_handle)
            .map_err(classify_failure)?;
        Ok(name.value().to_vec())
    }

    fn derives_original(&mut self, handle: u32) -> Result<Option<bool>> {
        // Probed first, so that a free handle logs no esys error (#601).
        if !persistent_handle_present(&mut self.ctx, handle)? {
            return Ok(None);
        }
        let persistent = PersistentTpmHandle::new(handle).map_err(tpm_err)?;
        let object = self
            .ctx
            .tr_from_tpm_public(TpmHandle::Persistent(persistent))
            .map_err(tpm_err)?;
        let (public, _, _) = self
            .ctx
            .read_public(KeyHandle::from(ESYS_TR::from(object)))
            .map_err(tpm_err)?;
        if !is_irlume_srk(&public)? {
            return Ok(None);
        }
        derives_from_srk_template(&mut self.ctx, &public).map(Some)
    }

    fn owner_names(&mut self) -> Result<Vec<(u32, Vec<u8>)>> {
        let mut names = Vec::new();
        for handle in persistent_handles(&mut self.ctx)? {
            if !OWNER_PERSISTENT.contains(&handle) {
                continue;
            }
            if let Some(name) = self.name_at(handle)? {
                names.push((handle, name));
            }
        }
        Ok(names)
    }

    fn persist(&mut self, handle: u32) -> std::result::Result<(), storage_key::Failure> {
        let Some(derived) = self.derived else {
            return Err(other_failure("no derived key to persist"));
        };
        let persistent = PersistentTpmHandle::new(handle).map_err(other_failure)?;
        self.ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.evict_control(
                    Provision::Owner,
                    derived.into(),
                    Persistent::Persistent(persistent),
                )
            })
            .map_err(classify_failure)?;
        Ok(())
    }
}

/// Classify a refused command for the record (#1083). `Tss2ResponseCode::kind`
/// does not look at the TSS layer, but no other layer's code can read as one
/// of these: the TSS base codes run to 54 (`tss2_common.h`), so as format-zero
/// codes they never reach `TPM_RC_NV_SPACE` (0x14B) or `TPM_RC_NV_DEFINED`
/// (0x14C), and they never set the format-one bit (0x80) of `TPM_RC_BAD_AUTH`
/// and `TPM_RC_AUTH_FAIL`. The owner hierarchy is DA-exempt (Part 1 16.8;
/// `IsDAExempted` in the reference code), so its wrong authorization is
/// `TPM_RC_BAD_AUTH` and counts toward no lockout.
fn classify_failure(error: tss_esapi::Error) -> storage_key::Failure {
    use storage_key::FailureClass;
    use tss_esapi::constants::response_code::Tss2ResponseCodeKind as Kind;
    let class = match error {
        tss_esapi::Error::Tss2Error(code) => match code.kind() {
            Some(Kind::NvSpace) => FailureClass::NoSpace,
            Some(Kind::NvDefined) => FailureClass::Taken,
            Some(Kind::BadAuth | Kind::AuthFail) => FailureClass::OwnerAuthorization,
            _ => FailureClass::Other,
        },
        tss_esapi::Error::WrapperError(_) => FailureClass::Other,
    };
    storage_key::Failure {
        class,
        detail: error.to_string(),
    }
}

fn other_failure(detail: impl std::fmt::Display) -> storage_key::Failure {
    storage_key::Failure {
        class: storage_key::FailureClass::Other,
        detail: detail.to_string(),
    }
}

/// Whether a persistent object is at `handle`. GetCapability lists handles
/// from the one asked for, so a one-handle query from `handle` answers it
/// without paging.
fn persistent_handle_present(ctx: &mut Context, handle: u32) -> Result<bool> {
    let (data, _more) = ctx
        .get_capability(CapabilityType::Handles, handle, 1)
        .map_err(tpm_err)?;
    let CapabilityData::Handles(list) = data else {
        return Err(Error::Tpm(
            "TPM returned a non-handle capability for a handle query".into(),
        ));
    };
    Ok(list
        .into_inner()
        .into_iter()
        .any(|listed| u32::from(listed) == handle))
}

/// Outcome of an uninstall-time attempt to evict the persisted SRK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrkEviction {
    /// Nothing occupies our persistent handle (already clean).
    Absent,
    /// Our SRK was there and has been evicted.
    Evicted,
    /// The handle is occupied by a key that is not ours (another stack
    /// squatting irlume's handle); left untouched.
    Foreign,
}

/// The RSA modulus (the public area's "unique" field) of `public`, or `None`
/// for a non-RSA key.
fn rsa_modulus(public: &Public) -> Option<&[u8]> {
    match public {
        Public::Rsa { unique, .. } => Some(unique.value()),
        _ => None,
    }
}

/// Evict irlume's persisted SRK from its owner-hierarchy persistent handle.
///
/// The uninstall path calls this only after every sealed envelope on the host
/// is provably gone, because envelopes are children of this key: evicting
/// while any remain would orphan secrets nothing could unseal again.
///
/// Identity is exact, not shape-level: the shape check used for parent
/// selection (`is_irlume_srk`: attributes + empty policy + RSA-2048) also
/// matches another stack's plain RSA-2048 primary, which is acceptable when
/// choosing a parent to USE but not when destroying a key. `create_primary`
/// over our SRK template is deterministic on a given
/// TPM, so our persisted SRK's modulus equals a fresh derivation bit-for-bit;
/// the eviction compares those moduli. The cost is one extra primary
/// derivation (seconds; the same one-time cost first use pays), acceptable at
/// uninstall time. A key at our handle with any other modulus is never
/// touched, and a missing handle is a success (the clean state), not an error.
///
/// # Errors
///
/// `Error::Tpm` when the TPM cannot be opened, its capabilities or public
/// areas cannot be read, the comparison primary cannot be derived, or the
/// eviction command itself is refused; callers treat this as a non-fatal
/// orphan (the key is harmless without irlume's data).
pub fn evict_persistent_srk() -> Result<SrkEviction> {
    let mut ctx = open_context()?;
    let persistent = persistent_srk_handle()?;
    let wanted = TpmHandle::Persistent(persistent);
    if !tpm_handle_exists(&mut ctx, TPM2_HR_PERSISTENT, wanted)? {
        return Ok(SrkEviction::Absent);
    }
    let object = ctx.tr_from_tpm_public(wanted).map_err(tpm_err)?;
    let key_handle = KeyHandle::from(ESYS_TR::from(object));
    // A read failure is a transport error, not evidence about identity (the
    // #757 review caught every-error-is-foreign): propagate it, so the
    // uninstall reports a failed check instead of a preserved foreign key.
    let (persisted_public, _, _) = ctx.read_public(key_handle).map_err(tpm_err)?;
    if !derives_from_srk_template(&mut ctx, &persisted_public)? {
        // A persistent object is never flushed (the load path's rule); the
        // ESYS reference goes away with the context.
        return Ok(SrkEviction::Foreign);
    }
    ctx.execute_with_nullauth_session(|ctx| {
        ctx.evict_control(
            Provision::Owner,
            key_handle.into(),
            Persistent::Persistent(persistent),
        )
    })
    .map_err(tpm_err)?;
    // No flush: evict_control already destroyed the object, so an ESYS flush
    // of the stale handle would log the exact ERROR noise #601 removed.
    Ok(SrkEviction::Evicted)
}

/// Evict irlume's DA-exempt storage key (ADR-0034 §3, the template
/// `da_exempt_srk_template` builds) from every owner persistent handle that
/// holds it, and return those handles; none is a success.
///
/// The key's handle is recorded in irlume's state directory, which uninstall
/// wipes first, so the handles are scanned instead. A key with the template's
/// shape is compared with one fresh derivation of the template and evicted
/// only when its modulus is the same, the rule of [`evict_persistent_srk`];
/// the label in the template's `unique` keeps another stack's TCG storage key
/// from matching. The derivation runs only when some key has that shape.
///
/// # Errors
///
/// `Error::Tpm` when the TPM cannot be opened, a handle or public area cannot
/// be read, the comparison key cannot be derived, or an eviction is refused.
/// Handles evicted before the error are not reported; a later call finds the
/// rest.
pub fn evict_da_exempt_srks() -> Result<Vec<u32>> {
    let mut ctx = open_context()?;
    let template = da_exempt_srk_template()?;
    let mut derived: Option<Public> = None;
    let mut evicted = Vec::new();
    for handle in persistent_handles(&mut ctx)? {
        if !OWNER_PERSISTENT.contains(&handle) {
            continue;
        }
        let persistent = PersistentTpmHandle::new(handle).map_err(tpm_err)?;
        let object = ctx
            .tr_from_tpm_public(TpmHandle::Persistent(persistent))
            .map_err(tpm_err)?;
        let key_handle = KeyHandle::from(ESYS_TR::from(object));
        // As in `evict_persistent_srk`, a read failure is not evidence.
        let (public, _, _) = ctx.read_public(key_handle).map_err(tpm_err)?;
        if !has_template_shape(&public, &template) {
            continue;
        }
        if derived.is_none() {
            derived = Some(derive_public(&mut ctx, template.clone())?);
        }
        let Some(derived) = &derived else {
            continue;
        };
        if compare_moduli(&public, derived) != DerivedKey::Same {
            continue;
        }
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                Provision::Owner,
                key_handle.into(),
                Persistent::Persistent(persistent),
            )
        })
        .map_err(tpm_err)?;
        evicted.push(handle);
    }
    Ok(evicted)
}

/// Every persistent handle the TPM reports, in order. A TPM returns at most
/// one capability buffer per GetCapability and sets moreData when handles
/// remain, so this asks again from the handle after the last one until it
/// does not (tpm2-tools' vacant-handle search reads one page only).
fn persistent_handles(ctx: &mut Context) -> Result<Vec<u32>> {
    let mut handles = Vec::new();
    let mut from = TPM2_PERSISTENT_FIRST;
    loop {
        let (data, more) = ctx
            .get_capability(CapabilityType::Handles, from, HANDLES_PER_PAGE)
            .map_err(tpm_err)?;
        let CapabilityData::Handles(list) = data else {
            return Err(Error::Tpm(
                "TPM returned a non-handle capability for a handle query".into(),
            ));
        };
        let page: Vec<u32> = list.into_inner().into_iter().map(u32::from).collect();
        let next = next_handle_page(more, from, &page)?;
        handles.extend(page);
        match next {
            Some(next) => from = next,
            None => return Ok(handles),
        }
    }
}

/// Where the next page of a persistent handle scan starts, or `None` when the
/// TPM said it returned the last. A page that claims more but does not move
/// past `from` is an error, not a loop.
fn next_handle_page(more: bool, from: u32, page: &[u32]) -> Result<Option<u32>> {
    if !more {
        return Ok(None);
    }
    match page.last() {
        Some(&last) if last >= from && last < TPM2_PERSISTENT_LAST => Ok(Some(last + 1)),
        _ => Err(Error::Tpm(format!(
            "TPM reported more persistent handles after {from:#010x} but returned none past it"
        ))),
    }
}

/// Whether `public` has the shape of irlume's original SRK: RSA, our
/// [`srk_template`] attributes, SHA-256 name hash, an empty authPolicy, and a
/// 2048-bit key. A non-match means another stack's key is squatting our
/// persistent handle (clevis / systemd-cryptenroll keys carry a non-empty
/// authPolicy, and may be ECC), so it fails the comparison and we fall back to
/// a transient SRK. A match is enough to use the key as a parent, not to
/// destroy it ([`evict_persistent_srk`] derives the key to compare).
fn is_irlume_srk(public: &Public) -> Result<bool> {
    Ok(has_template_shape(public, &srk_template()?))
}

/// Whether `public` has `template`'s RSA attributes, name hash, authPolicy and
/// key size. Another stack's key can have the same shape, so this picks a
/// parent to use or a candidate to compare, never a key to destroy.
fn has_template_shape(public: &Public, template: &Public) -> bool {
    let Public::Rsa {
        object_attributes,
        name_hashing_algorithm,
        auth_policy,
        parameters,
        ..
    } = public
    else {
        return false;
    };
    let Public::Rsa {
        object_attributes: want_attrs,
        name_hashing_algorithm: want_hash,
        auth_policy: want_policy,
        parameters: want_params,
        ..
    } = template
    else {
        return false;
    };
    // Compare key size, not the whole `parameters` struct: a TPM normalizes the
    // template's default RSA exponent (0) to 65537 on read-back, so a full
    // equality check would reject our OWN key and force the slow transient path
    // on every call. Attributes, authPolicy and key size are enough to choose
    // a parent; only a derivation tells whose key it is.
    object_attributes == want_attrs
        && name_hashing_algorithm == want_hash
        && auth_policy == want_policy
        && parameters.key_bits() == want_params.key_bits()
}

/// Get irlume's SRK, persisting it on first use.
///
/// `create_primary` over [`srk_template`] is deterministic, but deriving an
/// RSA-2048 primary costs >10s on slow firmware TPMs, too slow for the PAM
/// client timeout on every unseal. We derive it once and `evict_control` it to a
/// persistent handle; every later call just loads that handle. The persisted key
/// is bit-for-bit identical, so envelopes sealed earlier still load.
///
/// When another key holds the persistent handle, a transient SRK is derived
/// for this call in either mode. [`SrkMode::ReadOnly`] refuses only to
/// persist a new SRK at a free handle.
///
/// Returns the handle and whether it is persistent (a persistent handle must NOT
/// be flushed by the caller).
fn load_or_create_srk(ctx: &mut Context, mode: SrkMode) -> Result<(KeyHandle, bool)> {
    let persistent = persistent_srk_handle()?;
    let wanted = TpmHandle::Persistent(persistent);

    // Quiet first-use probe (#601): tr_from_tpm_public answers a handle that
    // does not exist yet with three esys ERROR lines in the journal, and the
    // missing handle is the EXPECTED state on a fresh install's first enroll.
    // Ask GetCapability first, so the expected miss never prints as an error;
    // the probe below then only runs against a handle that is really there.
    if tpm_handle_exists(ctx, TPM2_HR_PERSISTENT, wanted)? {
        if let Ok(object) = ctx.tr_from_tpm_public(wanted) {
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
            // use a transient SRK this run (correct, just slower). The
            // transient key persists nothing, so a read-only unseal takes this
            // path too; only persisting a new SRK needs `SrkMode::Initialize`.
            let transient = create_srk(ctx)?;
            return Ok((transient, false));
        }
    }

    // A read-only unseal never persists an SRK. The deterministic template
    // derives the same primary transiently, which is the parent an envelope
    // sealed while another key held the handle has, and which also opens one
    // sealed under a persistent SRK that has since been evicted.
    if mode == SrkMode::ReadOnly {
        let transient = create_srk(ctx)?;
        return Ok((transient, false));
    }
    mode.initialize(|| {
        // First run: derive the primary (one-time slow step) and persist it.
        // Said in our words, because the library's logging for the expected
        // handle miss this path replaces is three ERROR lines (#601).
        irlume_common::dlog!(
            "irlume: first TPM use on this machine: deriving and persisting the \
         storage root key (a few seconds on slow TPMs)"
        );
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
    })
}

/// Run `body` with irlume's persistent SRK as parent. Never flushes the SRK when
/// persistent: persistence is the whole point (avoids re-deriving a slow RSA
/// primary on every call).
fn with_srk<T>(
    ctx: &mut Context,
    body: impl FnOnce(&mut Context, &KeyHandle) -> Result<T>,
) -> Result<T> {
    with_srk_mode(ctx, SrkMode::Initialize, body)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SrkMode {
    /// Persist irlume's SRK at its free handle on first use.
    Initialize,
    /// Never persist an SRK: use the one at the handle, or a transient one
    /// derived from the same template when the handle is free or another key
    /// holds it.
    ReadOnly,
}

impl SrkMode {
    fn initialize<T>(self, initialize: impl FnOnce() -> Result<T>) -> Result<T> {
        if self == Self::ReadOnly {
            return Err(Error::Policy(
                "read-only unseal requires the existing irlume storage root key".into(),
            ));
        }
        initialize()
    }
}

fn with_srk_mode<T>(
    ctx: &mut Context,
    mode: SrkMode,
    body: impl FnOnce(&mut Context, &KeyHandle) -> Result<T>,
) -> Result<T> {
    let (srk, persistent) = load_or_create_srk(ctx, mode)?;
    let result = body(ctx, &srk);
    if !persistent {
        let _ = ctx.flush_context(srk.into());
    }
    result
}

/// The parent for a new seal (ADR-0034 §3.3): irlume's DA-exempt storage key
/// when irlumed recorded it and the key at that handle has the recorded TPM
/// name and the DA-exempt template's shape, with the record to keep in the
/// envelope; otherwise the original key, as [`with_srk`] finds or persists it.
/// A key with that shape has a sensitive area the TPM generated and never
/// releases (fixedTPM, sensitiveDataOrigin), so even a planted one keeps what
/// is sealed under it secret. The new key is never derived here: only
/// irlumed's start-up step persists it.
fn with_seal_parent<T>(
    ctx: &mut Context,
    body: impl FnOnce(&mut Context, &KeyHandle, Option<ParentKey>) -> Result<T>,
) -> Result<T> {
    if let Some((handle, name)) = storage_key::recorded_key() {
        if let Some(key) = da_exempt_key_at(ctx, handle, &name, true)? {
            let parent = ParentKey {
                handle,
                name: storage_key::hex(&name),
            };
            return body(ctx, &key, Some(parent));
        }
    }
    with_srk(ctx, |ctx, srk| body(ctx, srk, None))
}

/// The parent to load `env`'s object under: the key the envelope records,
/// found at its handle with its TPM name, or for an envelope without a record
/// the original key in `mode`. A recorded key that is not there is an error:
/// no other key can load the object, and finding the key by its name is
/// irlumed's start-up step's work, never an authentication's.
fn with_envelope_parent<T>(
    ctx: &mut Context,
    env: &SealedEnvelope,
    mode: SrkMode,
    body: impl FnOnce(&mut Context, &KeyHandle) -> Result<T>,
) -> Result<T> {
    let Some(parent) = &env.parent else {
        return with_srk_mode(ctx, mode, body);
    };
    let name = storage_key::unhex(&parent.name)
        .ok_or_else(|| Error::Protocol("the envelope's storage key name is not hex".into()))?;
    // The handle is a hint and the name decides (ADR-0034 §3.3): when the key
    // is no longer at the envelope's handle but irlumed recorded the same key
    // at another one, that is the parent.
    let mut key = da_exempt_key_at(ctx, parent.handle, &name, false)?;
    if key.is_none() {
        if let Some((handle, recorded)) = storage_key::recorded_key() {
            if recorded == name && handle != parent.handle {
                key = da_exempt_key_at(ctx, handle, &name, false)?;
            }
        }
    }
    let key = key.ok_or_else(|| {
        Error::Tpm(format!(
            "the storage key this envelope is sealed under is not at {:#010x}",
            parent.handle
        ))
    })?;
    body(ctx, &key)
}

/// The persistent key at `handle` when its TPM name is `name` and, with
/// `check_shape`, it has the DA-exempt template's shape; `None` otherwise.
/// The handle is probed first, so that a free one logs no esys error (#601).
/// A persistent object is never flushed.
fn da_exempt_key_at(
    ctx: &mut Context,
    handle: u32,
    name: &[u8],
    check_shape: bool,
) -> Result<Option<KeyHandle>> {
    if !OWNER_PERSISTENT.contains(&handle) || !persistent_handle_present(ctx, handle)? {
        return Ok(None);
    }
    let persistent = PersistentTpmHandle::new(handle).map_err(tpm_err)?;
    let object = ctx
        .tr_from_tpm_public(TpmHandle::Persistent(persistent))
        .map_err(tpm_err)?;
    let key = KeyHandle::from(ESYS_TR::from(object));
    let (public, found, _) = ctx.read_public(key).map_err(tpm_err)?;
    if found.value() != name
        || (check_shape && !has_template_shape(&public, &da_exempt_srk_template()?))
    {
        return Ok(None);
    }
    // The key's authValue is empty; tell ESYS so, as for the original key.
    ctx.tr_set_auth(object, Auth::default()).map_err(tpm_err)?;
    Ok(Some(key))
}

/// True when this machine could seal under a strictly stronger policy than
/// `current` right now. Used by the login-time self-heal to auto-upgrade an
/// envelope sealed under a weaker policy (a signed Tier 1 envelope from an
/// earlier release, or a literal one written before pcrlock was provisioned)
/// without the user re-arming, and without churning the TPM on a machine
/// already at its best available policy. Only signals availability; the
/// actual round-trip verification happens in [`seal`].
pub fn stronger_tier_available_than(current: &SealedEnvelope) -> bool {
    let binding = read_pcrlock_json().ok().and_then(|p| p.binding());
    let Some(rank) = current_strength_rank(current, binding.as_ref()) else {
        // An unrelated or unreadable prediction cannot establish that a
        // working envelope lost protection. Keep it until a verified reseal.
        return false;
    };
    stronger_tier_than(
        rank,
        || binding.is_some_and(|b| b.rank > 0),
        || crate::envelope::binds_firmware_state(&policy_pcrs()),
    )
}

/// True when `current` should move now: a strictly stronger policy is
/// available ([`stronger_tier_available_than`]), or `current` is under the
/// original storage key while irlumed recorded irlume's DA-exempt key as
/// persisted (ADR-0034 §3.3: being under the old key counts as a reason to
/// move, like a weaker tier). Reads the policy files and the storage-key
/// record only. The seal checks the recorded key at its handle, and a
/// candidate that did not land on it moves nothing (`move_gain`).
pub fn move_available(current: &SealedEnvelope) -> bool {
    stronger_tier_available_than(current) || on_original_key_with_da_exempt_key(current)
}

/// Whether `current` is under the original storage key while irlumed
/// recorded its DA-exempt key, with a policy whose rank is established: an
/// envelope bound to an unrelated or unreadable prediction is kept until a
/// verified reseal, as [`stronger_tier_available_than`] keeps it.
fn on_original_key_with_da_exempt_key(current: &SealedEnvelope) -> bool {
    if current.parent.is_some() || storage_key::recorded_key().is_none() {
        return false;
    }
    let binding = if matches!(current.policy, PolicyKind::PcrlockNv { .. }) {
        read_pcrlock_json().ok().and_then(|p| p.binding())
    } else {
        None
    };
    current_strength_rank(current, binding.as_ref()).is_some()
}

/// What moving an envelope to a candidate sealed for it gains (ADR-0034
/// §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveGain {
    /// A strictly stronger policy, on the same kind of storage key.
    StrongerPolicy,
    /// irlume's DA-exempt storage key in place of the original one, under a
    /// policy that is no weaker.
    DaExemptKey,
    /// Both.
    Both,
}

impl MoveGain {
    /// Where the envelope moved, for a log line.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::StrongerPolicy => "a stronger TPM policy",
            Self::DaExemptKey => "irlume's DA-exempt storage key",
            Self::Both => "a stronger TPM policy under irlume's DA-exempt storage key",
        }
    }
}

/// What `candidate`, sealed to replace `current`, gains: a strictly stronger
/// policy, the DA-exempt storage key in place of the original one under a
/// policy that is no weaker, or both. `None` when it gains neither, or when
/// it would take `current` off the DA-exempt key, where a lockout would stop
/// it again. Ranks both sides against the same current prediction, after
/// sealing and before publication. Unknown is not a weak rank: neither a
/// candidate nor an existing envelope with an unestablished binding may
/// authorize a move.
pub(crate) fn move_gain(candidate: &SealedEnvelope, current: &SealedEnvelope) -> Option<MoveGain> {
    if current.parent.is_some() && candidate.parent.is_none() {
        return None;
    }
    let binding = if matches!(candidate.policy, PolicyKind::PcrlockNv { .. })
        || matches!(current.policy, PolicyKind::PcrlockNv { .. })
    {
        read_pcrlock_json().ok().and_then(|p| p.binding())
    } else {
        None
    };
    let candidate_rank = current_strength_rank(candidate, binding.as_ref())?;
    let current_rank = current_strength_rank(current, binding.as_ref())?;
    let to_da_exempt_key = current.parent.is_none() && candidate.parent.is_some();
    match (candidate_rank.cmp(&current_rank), to_da_exempt_key) {
        (std::cmp::Ordering::Greater, false) => Some(MoveGain::StrongerPolicy),
        (std::cmp::Ordering::Greater, true) => Some(MoveGain::Both),
        (std::cmp::Ordering::Equal, true) => Some(MoveGain::DaExemptKey),
        _ => None,
    }
}

/// pcrlock replays the current prediction, not the seal-time PCR list. The NV
/// index must match; unseal still verifies the NV Name bound into the object's
/// authPolicy and the policy digest stored in that index. No TPM probe here.
fn current_strength_rank(env: &SealedEnvelope, binding: Option<&PcrlockBinding>) -> Option<u8> {
    match env.policy {
        PolicyKind::PcrlockNv { nv_index } => {
            let binding = binding.filter(|b| b.nv_index == nv_index)?;
            Some(binding.rank)
        }
        _ => Some(env.strength_rank()),
    }
}

/// Availability over the current rank, with the validated pcrlock binding and
/// configured literal firmware binding passed in. The final comparison reads
/// the prediction again, since it may change while a candidate is sealed.
fn stronger_tier_than(
    current: u8,
    pcrlock: impl FnOnce() -> bool,
    literal_binds_firmware: impl FnOnce() -> bool,
) -> bool {
    let pcrlock_rank = PolicyKind::PcrlockNv { nv_index: 0 }.strength_rank();
    (literal_binds_firmware() && current < PolicyKind::PcrLiteral.strength_rank())
        || (current < pcrlock_rank && pcrlock())
}

/// Seal `secret` under the best policy available on this machine, trying each
/// tier in order and round-trip-verifying before trusting it:
///   * Tier 2: if a systemd-pcrlock policy covering a firmware-measured PCR
///     is provisioned ([`pcrlock_for_sealing`]), a `PolicyAuthorizeNV`
///     against its NV index.
///     `make-policy` re-predicts the index across firmware / Secure Boot
///     updates, so those don't require a reseal either. Explicit sealing at
///     this tier is also available via [`seal_with_pcrlock`].
///   * Tier 3: otherwise a literal `PolicyPCR` over the configured PCRs
///     ([`policy_pcrs`], default PCR 7). If those PCRs move (dbx/Secure Boot
///     update) the envelope stops unsealing and the user re-runs `keyring arm`.
///
/// A signed `PolicyAuthorize` over systemd's PCR 11 signature (Tier 1) is
/// never tried, even where a UKI publishes one: it binds only what the
/// operating system measures, which a literal PCR 7 seal outranks.
///
/// Every producer funnels through here (keyring arm, the template key, both
/// reseal self-heals), so a reseal re-runs the ladder: it can move an envelope
/// up a tier when one became available, and only lands on a lower tier when
/// the higher one genuinely does not unseal on this machine.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn seal(secret: &[u8]) -> Result<SealedEnvelope> {
    if let Some(nv_index) = pcrlock_for_sealing() {
        // A pcrlock seal can SUCCEED yet be un-unsealable on this boot (e.g.
        // the policy predicts a PCR this OS never extends, so the super-PCR
        // replay fails): the "sealed but unusable" trap. Only trust it after
        // a round-trip; otherwise fall back to the literal PCR seal, which is
        // bound to values read from this TPM.
        match seal_pcrlock(secret, nv_index) {
            // The prediction is read again to seal, so a policy rewritten in
            // between is checked on the envelope it produced as well.
            Ok(env) if !crate::envelope::binds_firmware_state(&env.pcrs) => eprintln!(
                "irlume: the pcrlock policy covers no firmware-measured PCR; using the literal PCR seal"
            ),
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

    with_seal_parent(&mut ctx, |ctx, srk, parent| {
        // Read right before the object is created: the policy commits to these
        // values, and the copy stashed for diagnosis is the same reading.
        let pcr_values = read_pcr_values(ctx, &pcrs)?;
        let tmpl = sealed_template(literal_auth_policy(&pcr_values)?)?;

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
            pcr_values,
            password_wrap: None,
            uid: None,
            parent,
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
    unseal_with_mode(env, SrkMode::Initialize)
}

/// Unseal without persisting a storage root key. Where another key holds
/// irlume's SRK handle, this derives a transient SRK for the call, as a seal
/// there does; it persists nothing.
///
/// # Errors
/// Returns an error if the TPM cannot be opened, irlume's SRK handle is free
/// (no SRK was persisted there), or policy unsealing fails.
pub(crate) fn unseal_read_only(env: &SealedEnvelope) -> Result<Zeroizing<Vec<u8>>> {
    unseal_with_mode(env, SrkMode::ReadOnly)
}

fn unseal_with_mode(env: &SealedEnvelope, mode: SrkMode) -> Result<Zeroizing<Vec<u8>>> {
    env.validate_version()?;
    let out = retry_on_pcr_race(
        PCR_CHANGED_RETRIES,
        PCR_CHANGED_RETRY_BUDGET,
        || match &env.policy {
            PolicyKind::PcrLiteral => unseal_literal(env, mode),
            PolicyKind::Authorized {
                pubkey_pem,
                policy_ref,
            } => unseal_authorized(env, pubkey_pem, policy_ref, mode),
            PolicyKind::PcrlockNv { nv_index } => unseal_pcrlock(env, *nv_index, mode),
        },
    )?;
    // Lock the unsealed secret (login password / template key) against swap and
    // core dumps for as long as it lives.
    irlume_common::memlock::lock_slice(&out);
    Ok(out)
}

#[cfg(test)]
mod envelope_version_tests {
    use super::*;

    fn unknown_envelope(version: u32, pcr_values: Vec<PcrValue>) -> SealedEnvelope {
        SealedEnvelope {
            version,
            policy: PolicyKind::PcrLiteral,
            secret: crate::envelope::SecretKind::LoginPassword,
            pcrs: vec![7],
            public: Vec::new(),
            private: Vec::new(),
            pcr_values,
            password_wrap: None,
            uid: None,
            parent: None,
        }
    }

    #[test]
    fn unseal_rejects_unknown_envelope_version_before_opening_tpm() {
        for version in [0, crate::envelope::CURRENT_VERSION + 1] {
            let envelope = unknown_envelope(version, Vec::new());
            assert!(matches!(
                unseal(&envelope),
                Err(Error::Protocol(message)) if message.contains("unsupported TPM envelope version")
            ));
        }
    }

    #[test]
    fn diagnose_rejects_unknown_envelope_version_before_empty_return_or_tpm() {
        for pcr_values in [
            Vec::new(),
            vec![PcrValue {
                pcr: 7,
                value: vec![0; 32],
            }],
        ] {
            let envelope = unknown_envelope(crate::envelope::CURRENT_VERSION + 1, pcr_values);
            assert!(matches!(
                diagnose_pcrs(&envelope),
                Err(Error::Protocol(message)) if message.contains("unsupported TPM envelope version")
            ));
        }
    }
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
fn unseal_literal(env: &SealedEnvelope, mode: SrkMode) -> Result<Zeroizing<Vec<u8>>> {
    let mut ctx = open_context()?;

    with_envelope_parent(&mut ctx, env, mode, |ctx, srk| {
        let public = Public::unmarshall(&env.public).map_err(tpm_err)?;
        let private = Private::try_from(env.private.clone()).map_err(tpm_err)?;

        let sealed_handle = ctx
            .execute_with_nullauth_session(|ctx| ctx.load(*srk, private, public))
            .map_err(tpm_err)?;

        // Scoped fallible region so the loaded object is flushed on every exit.
        let result: Result<Zeroizing<Vec<u8>>> = (|| {
            with_session(ctx, Some(*srk), SessionType::Policy, |ctx, session| {
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
/// signature can unseal. Binds exactly the PCRs systemd signs (read from the
/// signature file, typically PCR 11). Uses an empty `policyRef`, matching
/// systemd's convention. [`seal`] no longer writes this policy; tests use it
/// to build the envelopes earlier releases wrote.
#[cfg(test)]
pub(crate) fn seal_authorized(secret: &[u8]) -> Result<SealedEnvelope> {
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
            uid: None,
            parent: None,
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
    mode: SrkMode,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut ctx = open_context()?;

    with_envelope_parent(&mut ctx, env, mode, |ctx, srk| {
        with_session(ctx, Some(*srk), SessionType::Policy, |ctx, session| {
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
            //    under the public key, yielding a verification ticket. The key
            //    is flushed as soon as the ticket exists, BEFORE the sealed
            //    object is loaded: the ticket and the key's Name are all
            //    PolicyAuthorize needs, so the conversation never holds more
            //    than one transient object at a time. On the raw device that
            //    leaves a minimum chip (three transient slots) two free slots
            //    for concurrent resource-manager clients (ADR-0026).
            let key_handle = load_external_pubkey(ctx, pubkey_pem)?;
            let verified: Result<(
                tss_esapi::structures::Name,
                tss_esapi::structures::VerifiedTicket,
            )> = (|| {
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
                Ok((key_name, ticket))
            })();
            let _ = ctx.flush_context(key_handle.into());
            let (key_name, ticket) = verified?;

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

            // 5. Load the sealed object and unseal it under the now-satisfied
            //    policy session. Scoped so the object is flushed on every exit.
            let public = Public::unmarshall(&env.public).map_err(tpm_err)?;
            let private = Private::try_from(env.private.clone()).map_err(tpm_err)?;
            let sealed_handle = ctx
                .execute_with_nullauth_session(|ctx| ctx.load(*srk, private, public))
                .map_err(tpm_err)?;
            let data = ctx
                .execute_with_session(Some(session), |ctx| ctx.unseal(sealed_handle.into()))
                .map_err(|e| policy_aware_err(e, env));
            let _ = ctx.flush_context(sealed_handle.into());
            Ok(Zeroizing::new(data?.to_vec()))
        })
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

/// Parse a SubjectPublicKeyInfo PEM into the RSA modulus and exponent.
///
/// Pure and unit-tested against a real key fixture. This deliberately parses
/// only the public SPKI/PKCS#1 structure: the systemd PCR-signing key is
/// public data, no RSA operation of any kind runs here, and the TPM performs
/// every verification. Using the der/spki parsers (the same RustCrypto stack,
/// without the rsa crate) keeps the dependency tree free of the Marvin
/// timing-side-channel advisory, whose risk lived entirely in private-key
/// operations this project never performs.
fn rsa_spki_parts(pubkey_pem: &str) -> Result<(Vec<u8>, u32)> {
    use der::asn1::ObjectIdentifier;
    use der::asn1::UintRef;
    use der::{Decode, Sequence};
    use spki::SubjectPublicKeyInfoOwned;

    /// PKCS#1 RSAPublicKey: SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    #[derive(Sequence)]
    struct RsaPublicKey<'a> {
        n: UintRef<'a>,
        e: UintRef<'a>,
    }

    // der 0.8.2's streaming PEM reader does not enforce complete nested values.
    // Decode the envelope first, then use the strict DER reader so an illicit
    // AlgorithmIdentifier field cannot be consumed as the outer public key.
    let (label, bytes) = der::pem::decode_vec(pubkey_pem.as_bytes())
        .map_err(|e| Error::Policy(format!("parse PCR public key: {e}")))?;
    if label != "PUBLIC KEY" {
        return Err(Error::Policy(
            "PCR public key must use the PUBLIC KEY PEM label".into(),
        ));
    }
    let spki = SubjectPublicKeyInfoOwned::from_der(&bytes)
        .map_err(|e| Error::Policy(format!("parse PCR public key: {e}")))?;
    // The previous decoder (the rsa crate) rejected non-RSA AlgorithmIdentifiers;
    // keep that strictness: a non-RSA SPKI whose BIT STRING happened to hold a
    // PKCS#1 sequence must never load as an RSA TPM key. RFC 3279 requires
    // rsaEncryption parameters to be NULL (absent-or-NULL is what the
    // RustCrypto decoders accept).
    const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    if spki.algorithm.oid != RSA_ENCRYPTION {
        return Err(Error::Policy(
            "PCR public key is not an RSA key (unexpected algorithm OID)".into(),
        ));
    }
    if let Some(params) = &spki.algorithm.parameters {
        if !params.is_null() {
            return Err(Error::Policy(
                "PCR public key has non-NULL rsaEncryption parameters".into(),
            ));
        }
    }
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::Policy("PCR public key bit string is not byte aligned".into()))?;
    let key = RsaPublicKey::from_der(key_bytes)
        .map_err(|e| Error::Policy(format!("parse PCR public key: {e}")))?;
    let e = key.e.as_bytes();
    if e.is_empty() || e.len() > 4 {
        return Err(Error::Policy("PCR key exponent too large".into()));
    }
    let mut buf = [0u8; 4];
    buf[4 - e.len()..].copy_from_slice(e);
    Ok((key.n.as_bytes().to_vec(), u32::from_be_bytes(buf)))
}

/// Build a tss-esapi `Public` for an external RSA verification key from a
/// SubjectPublicKeyInfo PEM.
fn rsa_pem_to_public(pubkey_pem: &str) -> Result<Public> {
    let (modulus, exponent_raw) = rsa_spki_parts(pubkey_pem)?;
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
    let exponent = RsaExponent::create(exponent_raw).map_err(tpm_err)?;

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
#[cfg(test)]
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

/// A usable prediction's association and firmware-binding rank. This is file
/// evidence for migration decisions, not proof that the TPM accepts the policy.
struct PcrlockBinding {
    nv_index: u32,
    rank: u8,
}

impl PcrlockJson {
    fn binding(&self) -> Option<PcrlockBinding> {
        let nv_index = u32::try_from(self.nv_index?).ok()?;
        NvIndexTpmHandle::new(nv_index).ok()?;
        // Validate every entry before calling an OS-only policy weak. The
        // parser checks the bank and nonempty mask; hex32 is also used by the
        // real policy replay. Duplicates and unsupported PCRs/OR fanout cannot
        // describe a usable systemd super-PCR policy.
        let mut seen = [false; 24];
        for entry in &self.pcr_values {
            let selected = seen.get_mut(entry.pcr as usize)?;
            if *selected || entry.values.len() > 8 {
                return None;
            }
            *selected = true;
            for value in &entry.values {
                hex32(value).ok()?;
            }
        }
        let pcrs: Vec<_> = self.pcr_values.iter().map(|e| e.pcr).collect();
        Some(PcrlockBinding {
            nv_index,
            rank: if crate::envelope::binds_firmware_state(&pcrs) {
                PolicyKind::PcrlockNv { nv_index }.strength_rank()
            } else {
                0
            },
        })
    }
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
    let wanted = TpmHandle::NvIndex(tpm_handle);
    // Same quiet-probe rationale as the SRK (#601): an undefined NV index is
    // the pcrlock-not-provisioned state, not an error worth three esys lines.
    if !tpm_handle_exists(ctx, TPM2_HR_NV_INDEX, wanted)? {
        return Err(Error::Tpm(format!(
            "NV index {nv_index:#x} is not defined on this TPM (pcrlock not provisioned)"
        )));
    }
    let obj: ObjectHandle = ctx.tr_from_tpm_public(wanted).map_err(tpm_err)?;
    Ok(NvIndexHandle::from(obj))
}

/// Whether a handle of `handle_type` (a TPM2_HT_* constant) exists, from one
/// GetCapability call. Exists so the expected-miss paths never reach
/// `tr_from_tpm_public`, whose library logging prints the miss as ERROR (#601).
fn tpm_handle_exists(ctx: &mut Context, handle_type: u32, wanted: TpmHandle) -> Result<bool> {
    let (data, _more) = ctx
        .get_capability(CapabilityType::Handles, handle_type, 0xff)
        .map_err(tpm_err)?;
    let CapabilityData::Handles(list) = data else {
        return Err(Error::Tpm(
            "TPM returned a non-handle capability for a handle query".into(),
        ));
    };
    Ok(capability_list_has(list, wanted))
}

/// Pure matching core of [`tpm_handle_exists`], testable without a TPM.
fn capability_list_has(list: HandleList, wanted: TpmHandle) -> bool {
    list.into_inner().contains(&wanted)
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
/// this replaces, so the two must agree; `software_digests_match_a_trial_session`
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
    with_session(ctx, None, SessionType::Trial, |ctx, session| {
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
    with_session(ctx, None, SessionType::Trial, |ctx, session| {
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

    with_seal_parent(&mut ctx, |ctx, srk, parent| {
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
            uid: None,
            parent,
        })
    })
}

/// Unseal a `PolicyAuthorizeNV`-bound object against `nv_index`: replay the live
/// super-PCR policy, run PolicyAuthorizeNV, and unseal.
#[allow(clippy::redundant_closure_call)]
fn unseal_pcrlock(
    env: &SealedEnvelope,
    nv_index: u32,
    mode: SrkMode,
) -> Result<Zeroizing<Vec<u8>>> {
    let plock = read_pcrlock_json()?;
    let mut ctx = open_context()?;
    let nv = nv_index_handle(&mut ctx, nv_index)?;
    let super_pcr = build_super_pcr(&plock)?;

    with_envelope_parent(&mut ctx, env, mode, |ctx, srk| {
        let public = Public::unmarshall(&env.public).map_err(tpm_err)?;
        let private = Private::try_from(env.private.clone()).map_err(tpm_err)?;
        let sealed_handle = ctx
            .execute_with_nullauth_session(|ctx| ctx.load(*srk, private, public))
            .map_err(tpm_err)?;

        let result: Result<Zeroizing<Vec<u8>>> = (|| {
            with_session(ctx, Some(*srk), SessionType::Policy, |ctx, session| {
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

/// The NV index of the provisioned pcrlock policy when [`seal`] uses it: one
/// that covers a firmware-measured PCR (0 to 7). A policy over OS-measured
/// PCRs only (PCR 15, say) binds less of the platform than the literal PCR 7
/// seal, so the ladder takes that instead, and the upgrade check does not
/// count it. `seal_with_pcrlock` still seals under any provisioned policy.
pub fn pcrlock_for_sealing() -> Option<u32> {
    let binding = read_pcrlock_json().ok()?.binding()?;
    (binding.rank > 0).then_some(binding.nv_index)
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
    env.validate_version()?;
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
pub(crate) mod tests {
    #[test]
    fn read_only_srk_refuses_initialization() {
        let result = super::SrkMode::ReadOnly.initialize(|| -> irlume_common::Result<()> {
            panic!("read-only unseal must not create or persist an SRK")
        });
        assert!(matches!(result, Err(irlume_common::Error::Policy(_))));
        assert_eq!(
            super::SrkMode::Initialize.initialize(|| Ok(17)).unwrap(),
            17
        );
    }
    use super::*;

    /// A real 2048-bit RSA SubjectPublicKeyInfo PEM (openssl-generated
    /// fixture). The parser must extract the exact modulus and exponent the
    /// old rsa-crate path produced; the TPM object builder is downstream.
    const RSA_PUB_FIXTURE: &str = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Dy2Frte+nNi0s3s87c9\n\
Q2Yv0uUlU4IlQ1/SAQj6I4lavYxqJ+SQmuaMfFkbnr3Vf4AHdvAV6XNKkXSCGAZ7\n\
45srB7lPO8TDVvH6adrsp7+HNQej78c6ziCb2dMjWrT05NOAsao9Daa+ImDZypwG\n\
plgUyLAK6Wzhjp36v32/oVodM4otWAnuDETOrbOnrY/xMu2wtpAyZ+tpoNUFZjr0\n\
WoTuNvyFOHwal/HAnsZ3agxc0OsF45deIAmduBgkmIWw+Ygz40oT1B6na1fht+JK\n\
D14jcv73sDp39RHVWoW+y2rcpDZL9RQUJ3gFraMptBVpK8zlVEkQWkqH35cjKZJ1\n\
awIDAQAB\n\
-----END PUBLIC KEY-----\n";

    // Hand-built ASN.1 fixtures keep malformed nesting independent of the
    // decoder under test. These contain synthetic public integers only.
    fn key_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let length = u16::try_from(body.len()).expect("small public-key fixture");
        let mut out = vec![tag];
        if length < 128 {
            out.push(length as u8);
        } else if length <= 255 {
            out.extend_from_slice(&[0x81, length as u8]);
        } else {
            out.push(0x82);
            out.extend_from_slice(&length.to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    fn key_bits(fill: u8, unused: u8) -> Vec<u8> {
        let mut modulus = vec![0, 0x80];
        modulus.extend(std::iter::repeat_n(fill, 255));
        let mut key = key_tlv(2, &modulus);
        key.extend_from_slice(&[2, 3, 1, 0, 1]); // exponent = 65537
        let mut bits = vec![unused];
        bits.extend(key_tlv(0x30, &key));
        key_tlv(3, &bits)
    }

    fn rsa_algorithm(with_null: bool) -> Vec<u8> {
        let mut fields = vec![6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1];
        if with_null {
            fields.extend_from_slice(&[5, 0]);
        }
        fields
    }

    fn public_key_pem(bytes: &[u8]) -> String {
        der::pem::encode_string("PUBLIC KEY", der::pem::LineEnding::LF, bytes).unwrap()
    }

    #[test]
    fn rsa_spki_rejects_keys_hidden_inside_algorithm_identifier() {
        for outer_key in [false, true] {
            let mut algorithm = rsa_algorithm(true);
            algorithm.extend(key_bits(0xb7, 0)); // An illegal field in AlgorithmIdentifier.
            let mut fields = key_tlv(0x30, &algorithm);
            if outer_key {
                fields.extend(key_bits(0xa5, 0));
            }
            let pem = public_key_pem(&key_tlv(0x30, &fields));
            assert!(
                rsa_spki_parts(&pem).is_err(),
                "accepted inner key, outer={outer_key}"
            );
        }
    }

    #[test]
    fn rsa_spki_rejects_trailing_data_inside_and_after_the_container() {
        let mut fields = key_tlv(0x30, &rsa_algorithm(true));
        fields.extend(key_bits(0xa5, 0));
        let mut outer_tail = key_tlv(0x30, &fields);
        outer_tail.extend_from_slice(&[5, 0]);
        fields.extend_from_slice(&[5, 0]);
        let inner_tail = key_tlv(0x30, &fields);
        for bytes in [inner_tail, outer_tail] {
            assert!(rsa_spki_parts(&public_key_pem(&bytes)).is_err());
        }
    }

    #[test]
    fn rsa_spki_requires_byte_aligned_public_key_bits() {
        use der::Decode;

        for unused in [1, 7] {
            let mut fields = key_tlv(0x30, &rsa_algorithm(true));
            fields.extend(key_bits(0xa5, unused));
            assert!(rsa_spki_parts(&public_key_pem(&key_tlv(0x30, &fields))).is_err());
        }
        // Legal zero padding is still not a byte-aligned PKCS#1 payload.
        // Unlike the cases above, DER's generic BIT STRING decoder accepts it;
        // the application must explicitly require as_bytes() to succeed.
        let mut bits = key_bits(0xa5, 1);
        *bits.last_mut().unwrap() &= !1;
        let mut fields = key_tlv(0x30, &rsa_algorithm(true));
        fields.extend(bits);
        let bytes = key_tlv(0x30, &fields);
        assert!(spki::SubjectPublicKeyInfoOwned::from_der(&bytes).is_ok());
        assert!(rsa_spki_parts(&public_key_pem(&bytes)).is_err());
    }

    #[test]
    fn rsa_spki_preserves_null_and_absent_rsa_parameters() {
        for with_null in [false, true] {
            let mut fields = key_tlv(0x30, &rsa_algorithm(with_null));
            fields.extend(key_bits(0xa5, 0));
            let (modulus, exponent) =
                rsa_spki_parts(&public_key_pem(&key_tlv(0x30, &fields))).unwrap();
            assert_eq!(modulus.len(), 256);
            assert_eq!(modulus[0], 0x80);
            assert!(modulus[1..].iter().all(|byte| *byte == 0xa5));
            assert_eq!(exponent, 65537);
        }
    }

    #[test]
    fn rsa_spki_requires_the_public_key_pem_label() {
        for label in ["CERTIFICATE", "RSA PUBLIC KEY"] {
            let pem = RSA_PUB_FIXTURE.replace("PUBLIC KEY", label);
            assert!(rsa_spki_parts(&pem).is_err());
        }
    }

    #[test]
    fn rsa_spki_parts_extracts_modulus_and_exponent() {
        let (modulus, exponent) = rsa_spki_parts(RSA_PUB_FIXTURE).expect("fixture parses");
        assert_eq!(modulus.len(), 256, "2048-bit key has a 256-byte modulus");
        assert_eq!(exponent, 65537, "the conventional RSA exponent");
        // Pin the EXACT modulus: sha256 of its big-endian bytes (openssl
        // "Modulus=" hex for this fixture). Length and top bit alone would
        // let a regression in the central extraction logic pass unnoticed.
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&modulus);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "bada6228f1aa0d2473962e0b416fb151261b2427bba568c6c48aa6be822e9c9c",
            "modulus bytes changed"
        );
    }

    #[test]
    fn rsa_spki_parts_refuses_malformed_and_unsupported_keys() {
        assert!(rsa_spki_parts("not a pem").is_err());
        assert!(
            rsa_spki_parts("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n").is_err()
        );
        // A structurally valid EC P-256 SPKI must be refused by the algorithm
        // check even though the container decodes. (openssl-generated fixture.)
        const EC_PUB_FIXTURE: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7egDfPRHj1TgRtw9ppW19+K1I/7j
UV+HrKUsvUeCjP7HZkREwl0xt89H9c1TiNQqTpXicwE4D1NeDA5ountiSQ==
-----END PUBLIC KEY-----
";
        let err = rsa_spki_parts(EC_PUB_FIXTURE).unwrap_err();
        assert!(
            err.to_string().contains("not an RSA key"),
            "EC key must be refused by the algorithm check: {err}"
        );
    }

    #[test]
    fn srk_identity_match_accepts_ours_rejects_foreign() {
        assert!(is_irlume_srk(&srk_template().unwrap()).unwrap());
        let sealed = sealed_template(Digest::default()).unwrap();
        assert!(!is_irlume_srk(&sealed).unwrap());
    }

    /// #601: the quiet-existence probe's matching core must find the exact
    /// persistent or NV handle in a capability list and miss everything else,
    /// because the probe decides whether the expected-miss path runs at all.
    #[test]
    fn capability_list_has_matches_exact_persistent_and_nv_handles() {
        let srk = TpmHandle::Persistent(PersistentTpmHandle::new(0x8101_0002).unwrap());
        let nv = TpmHandle::NvIndex(NvIndexTpmHandle::new(0x0140_0001).unwrap());
        let list = HandleList::try_from(vec![
            TpmHandle::Persistent(PersistentTpmHandle::new(0x8100_0001).unwrap()),
            srk,
        ])
        .unwrap();
        assert!(capability_list_has(list, srk));
        let empty = HandleList::try_from(Vec::new()).unwrap();
        assert!(
            !capability_list_has(empty, srk),
            "an empty TPM has no SRK: this is the first-use state"
        );
        let persistent_only = HandleList::try_from(vec![TpmHandle::Persistent(
            PersistentTpmHandle::new(0x8100_0001).unwrap(),
        )])
        .unwrap();
        assert!(
            !capability_list_has(persistent_only, nv),
            "an NV handle never matches a persistent-handle list"
        );
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

    /// Each PCR once, in the order first given; what does not parse is
    /// skipped.
    #[test]
    fn a_pcr_list_names_each_pcr_once() {
        assert_eq!(parse_pcrs("7,0,7, 0 ,x,11"), vec![7, 0, 11]);
        assert_eq!(parse_pcrs(&"7,".repeat(10_000)), vec![7]);
        assert!(parse_pcrs("").is_empty());
    }

    fn pcr(pcr: u32, byte: u8) -> PcrValue {
        PcrValue {
            pcr,
            value: vec![byte; 32],
        }
    }

    fn hex(d: &Digest) -> String {
        d.value().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Known answers computed independently from TCG Part 3 §23.7: the
    /// composite over the values in ascending PCR order, whatever order the
    /// list was given in.
    #[test]
    fn the_literal_policy_is_the_spec_policy_over_the_values_read() {
        assert_eq!(
            hex(&literal_auth_policy(&[pcr(7, 0x77)]).unwrap()),
            "584f1612373c93cb25fccd2c7dea58d5ebc61e4fec094958112f88a38c56f88c"
        );
        let two = "3ca24232249f78be2770f133f56cc0af778c790d532b223b28fb67a6fdffda27";
        assert_eq!(
            hex(&literal_auth_policy(&[pcr(0, 0x10), pcr(7, 0x77)]).unwrap()),
            two
        );
        assert_eq!(
            hex(&literal_auth_policy(&[pcr(7, 0x77), pcr(0, 0x10), pcr(7, 0x77)]).unwrap()),
            two,
            "order and a repeated PCR must not change the policy"
        );
        assert_eq!(
            literal_auth_policy(&[]).unwrap().value(),
            [0u8; 32],
            "no PCRs is a fresh session's digest"
        );
    }

    /// #1067: the T480's STMicroelectronics TPM stamped the policy of an empty
    /// `pcrDigest` (this value, over PCR 7) on its sealed objects. The literal
    /// policy must depend on the PCR value instead.
    #[test]
    fn the_literal_policy_is_never_the_empty_digest_policy() {
        let empty_digest_policy =
            "e987c3a4bc9a3d0af9c7bca78ccc78d06a7f3a7327f2074446f1d87833ea99d3";
        let empty = policy_pcr_digest(
            &Digest::try_from(vec![0u8; 32]).unwrap(),
            &[7],
            &Digest::default(),
        )
        .unwrap();
        assert_eq!(hex(&empty), empty_digest_policy);
        for byte in [0x00, 0x77, 0xff] {
            assert_ne!(
                hex(&literal_auth_policy(&[pcr(7, byte)]).unwrap()),
                empty_digest_policy
            );
        }
    }

    #[test]
    fn a_pcr_without_a_sha256_value_refuses_the_seal() {
        let err = literal_auth_policy(&[
            pcr(0, 0x10),
            PcrValue {
                pcr: 7,
                value: Vec::new(),
            },
        ])
        .unwrap_err();
        assert!(
            err.to_string().contains("PCR 7 has no SHA-256 value"),
            "{err}"
        );
    }

    /// The literal seal's policy against what an unseal presents: a live
    /// policy session over the same PCRs on this TPM (#1067).
    #[test]
    #[ignore = "needs a TPM; CI runs it by name on swtpm and on the real chip \
                (IRLUME_TCTI), and scripts/with-swtpm.sh runs it anywhere"]
    fn a_literal_seal_commits_to_the_policy_a_live_session_presents() {
        let pcrs = [7, 0];
        let secret = b"irlume-literal-policy-live-match";
        let env = seal_with_pcrs(secret, &pcrs).expect("seal");
        let sealed = Public::unmarshall(&env.public).expect("sealed public");
        let mut ctx = open_context().expect("TPM context");
        let live = with_srk(&mut ctx, |ctx, srk| {
            with_session(ctx, Some(*srk), SessionType::Policy, |ctx, session| {
                let policy = PolicySession::try_from(session).map_err(tpm_err)?;
                ctx.policy_pcr(policy, Digest::default(), pcr_selection(&pcrs)?)
                    .map_err(tpm_err)?;
                ctx.policy_get_digest(policy).map_err(tpm_err)
            })
        })
        .expect("live policy digest");
        drop(ctx);
        assert_eq!(
            sealed.auth_policy().value(),
            live.value(),
            "the sealed authPolicy must equal the live session's digest"
        );
        assert_eq!(&*unseal(&env).expect("unseal"), secret);
    }

    /// More PCRs than one `PCR_Read` answers (eight): the snapshot must still
    /// return every value, in the order asked, and a seal over them must
    /// commit to the policy a live session presents. swtpm only: on a real
    /// machine several of these PCRs move while the system runs.
    #[test]
    #[ignore = "needs a TPM; CI runs it by name on swtpm, and scripts/with-swtpm.sh \
                runs it anywhere"]
    fn a_pcr_snapshot_larger_than_one_read_is_complete() {
        let mut pcrs: Vec<u32> = (0..=16).rev().collect();
        pcrs.push(23);
        let mut ctx = open_context().expect("TPM context");
        let (_, first, _) = ctx
            .pcr_read(pcr_selection(&pcrs).unwrap())
            .expect("one PCR_Read");
        let first: usize = first
            .get_selections()
            .iter()
            .map(|s| s.selected().len())
            .sum();
        assert!(
            first < pcrs.len(),
            "one PCR_Read answered all {first}: this test needs a partial answer"
        );
        let snapshot = read_pcr_values(&mut ctx, &pcrs).expect("snapshot");
        assert_eq!(
            snapshot.iter().map(|v| v.pcr).collect::<Vec<_>>(),
            pcrs,
            "values come back in the order asked"
        );
        for v in &snapshot {
            let single = read_pcr_values(&mut ctx, &[v.pcr]).expect("single read");
            assert_eq!(v.value.len(), 32, "PCR {} has a SHA-256 value", v.pcr);
            assert_eq!(
                v.value, single[0].value,
                "PCR {} matches its own read",
                v.pcr
            );
        }
        let live = with_srk(&mut ctx, |ctx, srk| {
            with_session(ctx, Some(*srk), SessionType::Policy, |ctx, session| {
                let policy = PolicySession::try_from(session).map_err(tpm_err)?;
                ctx.policy_pcr(policy, Digest::default(), pcr_selection(&pcrs)?)
                    .map_err(tpm_err)?;
                ctx.policy_get_digest(policy).map_err(tpm_err)
            })
        })
        .expect("live policy digest");
        drop(ctx);
        let secret = b"irlume-eighteen-pcr-snapshot-sea";
        let env = seal_with_pcrs(secret, &pcrs).expect("seal");
        let sealed = Public::unmarshall(&env.public).expect("sealed public");
        assert_eq!(sealed.auth_policy().value(), live.value());
        assert_eq!(&*unseal(&env).expect("unseal"), secret);
    }

    #[test]
    fn a_tpm_without_its_required_properties_is_not_identified() {
        let stm = Some(u32::from_be_bytes(*b"STM "));
        let id = identity_from(stm, [None; 4], Some(0x0001_0301)).expect("identified");
        assert_eq!((id.manufacturer.as_str(), id.vendor.as_str()), ("STM", ""));
        assert_eq!(id.firmware, (1, 769));
        let missing = identity_from(None, [None; 4], Some(1)).unwrap_err();
        assert!(missing.to_string().contains("manufacturer"), "{missing}");
        let missing = identity_from(stm, [None; 4], None).unwrap_err();
        assert!(
            missing.to_string().contains("firmware version"),
            "{missing}"
        );
    }

    /// Every lockout property is required, each missing one is named, and the
    /// values land in the right fields.
    #[test]
    fn a_tpm_without_its_lockout_properties_reports_no_lockout_state() {
        let all = [Some(0x204), Some(2), Some(32), Some(7200), Some(86400)];
        let lockout = lockout_from(all, false).expect("read");
        assert!(lockout.lockout_auth_set && lockout.in_lockout);
        assert_eq!(
            (
                lockout.failed_tries,
                lockout.max_tries,
                lockout.recovery_time,
                lockout.lockout_recovery
            ),
            (2, 32, 7200, 86400)
        );
        assert!(!lockout.storage_key_no_da);
        for (i, name) in [
            "permanent attributes",
            "lockout counter",
            "maximum authorization failures",
            "lockout interval",
            "lockout recovery time",
        ]
        .into_iter()
        .enumerate()
        {
            let mut missing = all;
            missing[i] = None;
            let error = lockout_from(missing, false).unwrap_err().to_string();
            assert!(error.contains(name), "{error}");
        }
    }

    /// ADR-0034 §2: the objects irlume seals its secrets in are DA-exempt
    /// (`noDA`), and their empty authValue cannot authorize them
    /// (`userWithAuth` clear), so only their policy can. A lockout then never
    /// blocks them, and no wrong secret can count against the TPM's
    /// dictionary-attack counter through them.
    #[test]
    fn sealed_objects_are_da_exempt_and_open_only_by_policy() {
        let zero = Digest::try_from(vec![0u8; 32]).expect("digest");
        let attributes = sealed_template(zero).expect("template").object_attributes();
        assert!(attributes.no_da(), "a sealed object must have noDA");
        assert!(
            !attributes.user_with_auth(),
            "a sealed object must open only by its policy"
        );
    }

    /// The TCG shared storage key template for RSA (Provisioning Guidance
    /// 7.5.1, Table 1): what systemd's `tpm2_get_srk_template` builds for RSA,
    /// and persists at 0x81000001 when that handle is empty and the TPM does
    /// not support its ECC template (`tpm2_get_or_create_srk`).
    fn tcg_shared_rsa_srk_template() -> Public {
        storage_key_template(true, PublicKeyRsa::default()).expect("template")
    }

    /// Every irlume envelope so far is sealed under the key this template
    /// derives, and CreatePrimary hashes the marshaled template into the
    /// derivation, so its bytes must never change: RSA, SHA-256, fixedTPM,
    /// fixedParent, sensitiveDataOrigin, userWithAuth, restricted and decrypt
    /// (0x00030072), no noDA, an empty authPolicy, AES-128-CFB, a null scheme,
    /// 2048 bits, the default exponent and an empty `unique`.
    #[test]
    fn the_original_storage_key_template_is_unchanged() {
        let bytes = srk_template()
            .expect("template")
            .marshall()
            .expect("marshal");
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, "0001000b00030072000000060080004300100800000000000000");
    }

    /// ADR-0034 §3.1 and its 2026-10-15 amendment: the new template is the
    /// original with noDA and irlume's label in `unique`, and nothing else.
    /// Without the label it would be the TCG shared template, which has the
    /// same shape: only a derivation, which hashes `unique` in, tells them
    /// apart.
    #[test]
    fn the_da_exempt_template_is_the_original_with_no_da_and_irlumes_label() {
        let original = srk_template().expect("template");
        let exempt = da_exempt_srk_template().expect("template");
        assert_eq!(
            u32::from(exempt.object_attributes()),
            u32::from(original.object_attributes()) | (1 << 10),
            "the only attribute added is noDA (bit 10)"
        );
        let (
            Public::Rsa {
                name_hashing_algorithm: original_hash,
                auth_policy: original_policy,
                parameters: original_parameters,
                ..
            },
            Public::Rsa {
                name_hashing_algorithm,
                auth_policy,
                parameters,
                unique,
                ..
            },
        ) = (&original, &exempt)
        else {
            panic!("both storage keys are RSA");
        };
        assert_eq!(name_hashing_algorithm, original_hash);
        assert_eq!(auth_policy, original_policy);
        assert_eq!(parameters, original_parameters);
        let mut label = DA_EXEMPT_SRK_LABEL.to_vec();
        label.resize(256, 0);
        assert_eq!(unique.value(), label.as_slice());

        // The derivation input, pinned: the label decides the key, so a
        // change here would leave every envelope under the new key behind.
        let marshaled = exempt.marshall().expect("marshal");
        assert_eq!(marshaled.len(), 282);
        assert_eq!(
            irlume_common::sha256_hex(&marshaled),
            "a2d290239a5dccbd8d9b4a9982352741847f55939e559d3ffc3a00b282a11543"
        );

        let shared = tcg_shared_rsa_srk_template();
        assert!(has_template_shape(&shared, &exempt));
        assert_ne!(
            shared.marshall().expect("marshal"),
            marshaled,
            "the label must make the template, and so the key, irlume's own"
        );
        assert!(
            !is_irlume_srk(&exempt).expect("shape"),
            "a DA-exempt key is never a parent for an envelope under the original key"
        );
    }

    /// ADR-0034 §3.2 acceptance: the new key's handle is 0x81010003 by
    /// default, the one after an `IRLUME_SRK_HANDLE` override, and 0x817FFFFE
    /// for an override of 0x817FFFFF; never outside the owner range. An
    /// override in the platform range, outside the persistent range, or that
    /// does not parse as the original key's lookup reads it (a capital `0X`
    /// included, which that lookup also rejects) is refused.
    #[test]
    fn the_da_exempt_key_goes_next_to_the_original_key_in_the_owner_range() {
        let plan =
            |value| da_exempt_key_plan_for(value).map(|plan| (plan.preferred, plan.original));
        assert_eq!(plan(None), Ok((0x8101_0003, 0x8101_0002)));
        assert_eq!(plan(Some("0x81020000")), Ok((0x8102_0001, 0x8102_0000)));
        assert_eq!(plan(Some(" 81000010\n")), Ok((0x8100_0011, 0x8100_0010)));
        assert_eq!(plan(Some("0x817FFFFF")), Ok((0x817F_FFFE, 0x817F_FFFF)));
        for refused in [
            "0x81800000",
            "0x81ffffff",
            "0x01000000",
            "zz",
            "",
            "0X81010002",
        ] {
            assert!(plan(Some(refused)).is_err(), "{refused:?}");
        }
    }

    /// A handle scan asks again after the last handle of a page while the TPM
    /// says more remain, and stops when it does not; a page that claims more
    /// without moving on is an error, not an endless loop.
    #[test]
    fn a_persistent_handle_scan_pages_until_the_tpm_has_no_more() {
        let first = TPM2_PERSISTENT_FIRST;
        assert_eq!(
            next_handle_page(false, first, &[]).expect("last page"),
            None
        );
        assert_eq!(
            next_handle_page(false, first, &[0x8100_0001]).expect("last page"),
            None
        );
        assert_eq!(
            next_handle_page(true, first, &[0x8100_0001, 0x8101_0002]).expect("next page"),
            Some(0x8101_0003)
        );
        assert!(next_handle_page(true, first, &[]).is_err());
        assert!(next_handle_page(true, 0x8101_0003, &[0x8100_0001]).is_err());
        assert!(next_handle_page(true, first, &[TPM2_PERSISTENT_LAST]).is_err());
    }

    #[test]
    fn property_words_read_as_trimmed_ascii() {
        assert_eq!(property_text(&[u32::from_be_bytes(*b"STM ")]), "STM");
        assert_eq!(property_text(&[u32::from_be_bytes(*b"AMD\0")]), "AMD");
        assert_eq!(
            property_text(&[
                u32::from_be_bytes(*b"SLB9"),
                u32::from_be_bytes(*b"670\0"),
                0,
                0
            ]),
            "SLB9670"
        );
        assert_eq!(property_text(&[0x0102_0304]), "");
        // swtpm's vendor string pads its words with spaces.
        assert_eq!(
            property_text(&[u32::from_be_bytes(*b"SW  "), u32::from_be_bytes(*b" TPM")]),
            "SW TPM"
        );
    }

    #[test]
    fn the_pcr_bank_is_ready_only_with_extended_sha256_values() {
        let value = |pcr, byte: u8, len| PcrValue {
            pcr,
            value: vec![byte; len],
        };
        assert_eq!(
            classify_pcr_bank(&[value(7, 0x11, 32)]),
            PcrBankReadiness::Ready(vec![7])
        );
        assert_eq!(
            classify_pcr_bank(&[value(0, 0x11, 32), value(7, 0, 0)]),
            PcrBankReadiness::Missing(vec![7]),
            "no SHA-256 value: the bank is not active"
        );
        assert_eq!(
            classify_pcr_bank(&[value(7, 0, 32), value(11, 0, 32)]),
            PcrBankReadiness::Unextended(vec![7]),
            "a zero firmware PCR was never measured; a zero OS PCR may be unused"
        );
        assert_eq!(
            classify_pcr_bank(&[value(11, 0, 32)]),
            PcrBankReadiness::Ready(vec![11])
        );
    }

    /// The storage-key check reads the key a seal persisted, and swtpm's key
    /// carries no ROCA fingerprint.
    #[test]
    #[ignore = "needs a TPM; CI runs it by name on swtpm, and scripts/with-swtpm.sh \
                runs it anywhere"]
    fn the_storage_key_check_reads_the_persisted_key() {
        seal_with_pcrs(b"irlume-storage-key-check-secret!", &[7]).expect("seal");
        assert_eq!(storage_key_check().expect("check"), StorageKeyCheck::Clean);
    }

    /// Only a key with the ROCA fingerprint is compared with the key irlume's
    /// template derives, and the comparison decides `derived`.
    #[test]
    fn only_a_roca_key_is_compared_with_the_derived_one() {
        assert_eq!(
            roca_verdict(false, 0x8101_0002, || panic!("a clean key is not derived")).unwrap(),
            StorageKeyCheck::Clean
        );
        for derived in [DerivedKey::Same, DerivedKey::Unaffected, DerivedKey::Other] {
            assert_eq!(
                roca_verdict(true, 0x8100_0005, || Ok(derived)).unwrap(),
                StorageKeyCheck::RocaFingerprint {
                    handle: 0x8100_0005,
                    derived: Some(derived)
                }
            );
        }
        assert_eq!(
            roca_verdict(true, 0x8101_0002, || Err(Error::Tpm("owner auth".into()))).unwrap(),
            StorageKeyCheck::RocaFingerprint {
                handle: 0x8101_0002,
                derived: None
            },
            "a failed comparison keeps the fingerprint"
        );
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

    // --- transport selection (ADR-0026) ---------------------------------

    #[test]
    fn an_explicit_tcti_is_the_only_candidate() {
        assert_eq!(
            tcti_candidates(Some("swtpm:host=127.0.0.1,port=2321")),
            vec!["swtpm:host=127.0.0.1,port=2321"]
        );
        assert_eq!(
            tcti_candidates(Some(TCTI_RESOURCE_MANAGER)),
            vec![TCTI_RESOURCE_MANAGER],
            "pinning the manager must not also try the raw device"
        );
    }

    #[test]
    fn the_default_tries_the_raw_device_then_the_resource_manager() {
        assert_eq!(
            tcti_candidates(None),
            vec![TCTI_RAW_DEVICE, TCTI_RESOURCE_MANAGER]
        );
    }

    #[test]
    fn a_failed_raw_open_falls_back_and_a_failed_fallback_reports_its_own_error() {
        let tried = std::cell::RefCell::new(Vec::new());
        let result = open_context_from(None, |tcti| {
            tried.borrow_mut().push(tcti.to_string());
            Err(Error::Tpm(format!("cannot open {tcti}")))
        });
        assert_eq!(
            tried.into_inner(),
            vec![
                TCTI_RAW_DEVICE.to_string(),
                TCTI_RESOURCE_MANAGER.to_string()
            ],
            "raw first, manager second, nothing else"
        );
        let err = match result {
            Ok(_) => panic!("both transports failed, so no context can exist"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains(TCTI_RESOURCE_MANAGER),
            "the error a caller sees is the last transport's: {err}"
        );
    }

    #[test]
    fn an_explicit_tcti_that_fails_is_not_retried_elsewhere() {
        let tried = std::cell::RefCell::new(Vec::new());
        let result = open_context_from(Some("device:/dev/tpmrm9"), |tcti| {
            tried.borrow_mut().push(tcti.to_string());
            Err(Error::Tpm("no such device".into()))
        });
        assert_eq!(tried.into_inner(), vec!["device:/dev/tpmrm9".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn a_sweep_touches_only_handles_that_appeared_after_the_marker() {
        // Loaded now: a foreign session recorded at the start, plus two of ours.
        let prior = [0x0200_0000];
        let loaded = [0x0200_0000, 0x0200_0001, 0x8000_0000];
        assert_eq!(
            handles_to_flush(&loaded, &prior),
            vec![0x0200_0001, 0x8000_0000]
        );
        assert!(handles_to_flush(&prior, &prior).is_empty());
        assert!(handles_to_flush(&[], &prior).is_empty());
    }

    #[test]
    fn the_marker_round_trips_and_ignores_garbage_lines() {
        let handles = [0x0200_0000, 0x0300_0000, 0x8000_0001];
        let text = format_marker(&handles);
        assert_eq!(parse_marker(&text), handles);
        assert_eq!(parse_marker(""), Vec::<u32>::new());
        assert_eq!(parse_marker("nonsense\n0x80000002\n"), vec![0x8000_0002]);
    }

    #[test]
    fn no_lock_directory_means_no_marker_and_no_recovery() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let previous = std::env::var_os("IRLUME_TPM_MARKER_DIR");
        std::env::set_var("IRLUME_TPM_MARKER_DIR", "/nonexistent/irlume-marker-dir");
        let path = marker_path();
        match previous {
            Some(v) => std::env::set_var("IRLUME_TPM_MARKER_DIR", v),
            None => std::env::remove_var("IRLUME_TPM_MARKER_DIR"),
        }
        assert!(path.is_none());
    }

    /// Child half of the crash fixture below. Mode `foreign`: a plain raw
    /// context (no marker, as another raw client would be) starts an HMAC
    /// session and exits without flushing. Mode `leak`: the production
    /// `open_context` (which records the marker) starts a policy session and
    /// loads a transient object, then exits the PROCESS
    /// without flushing anything, exactly as a crash mid-unseal would. Runs
    /// only when the parent asks for it by name with the guard variable set.
    #[test]
    #[ignore = "helper for a_raw_open_sweeps_handles_a_dead_process_left_loaded; not a test on its own"]
    fn leak_raw_handles_then_exit_helper() {
        let Some(mode) = std::env::var_os("IRLUME_TEST_LEAK_RAW_HANDLES") else {
            return;
        };
        let decode = |hex: &str| -> Vec<u8> {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect()
        };
        let hmac = |ctx: &mut Context| {
            ctx.start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("hmac session");
        };
        if mode == "foreign" {
            let conf = TctiNameConf::from_str(TCTI_RAW_DEVICE).expect("tcti");
            let mut ctx = Context::new(conf).expect("raw device");
            hmac(&mut ctx);
            std::process::exit(0);
        }
        let public = std::env::var("IRLUME_TEST_LEAK_PUBLIC").expect("public");
        let private = std::env::var("IRLUME_TEST_LEAK_PRIVATE").expect("private");
        let mut ctx = open_context().expect("production open");
        let (srk, _) = load_or_create_srk(&mut ctx, SrkMode::ReadOnly).expect("srk");
        ctx.start_auth_session(
            Some(srk),
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("policy session");
        // Deliberately no second session: with the foreign one already loaded
        // a third would fill a minimum chip's three session slots, and the
        // Intel PTT then refuses even a password-authorized `Load` with
        // TPM_RC_SESSION_HANDLES. One session plus one object covers both
        // handle classes the sweep handles.
        let public = Public::unmarshall(&decode(&public)).expect("public");
        let private = Private::try_from(decode(&private)).expect("private");
        ctx.execute_with_nullauth_session(|ctx| ctx.load(srk, private, public))
            .expect("load");
        // No drop, no flush, no marker removal: abandoned with the process.
        std::process::exit(0);
    }

    /// The crash-recovery path, for real, with the ownership rule: first a
    /// foreign raw client leaves an HMAC session loaded and exits; then a child
    /// on the production path records the marker (the foreign session is in
    /// it), leaks a policy session and a transient object, and exits without
    /// a single flush. The next production open must sweep exactly irlume's
    /// two leaks, leave the foreign session loaded, remove
    /// the stale marker, and a full unseal must still succeed afterwards.
    #[test]
    #[ignore = "requires the raw TPM device (root); leaks and then reclaims chip slots on purpose"]
    fn a_raw_open_sweeps_handles_a_dead_process_left_loaded() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let previous_tcti = std::env::var_os("IRLUME_TCTI");
        let previous_dir = std::env::var_os("IRLUME_TPM_MARKER_DIR");
        let marker_dir = std::path::PathBuf::from(crate::test_tmp_dir("tpm-marker"));
        let _ = std::fs::remove_dir_all(&marker_dir);
        std::fs::create_dir_all(&marker_dir).expect("marker dir");
        std::env::remove_var("IRLUME_TCTI");
        std::env::set_var("IRLUME_TPM_MARKER_DIR", &marker_dir);
        let marker = marker_dir.join("tpm-raw-conversation");
        let raw = || {
            let conf = TctiNameConf::from_str(TCTI_RAW_DEVICE).map_err(tpm_err)?;
            Context::new(conf).map_err(tpm_err)
        };
        let encode = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let run_child = |mode: &str, env: &SealedEnvelope| -> Result<()> {
            let exe = std::env::current_exe().map_err(|e| Error::Io(e.to_string()))?;
            let status = std::process::Command::new(exe)
                .args([
                    "--ignored",
                    "--exact",
                    "tpm::tests::leak_raw_handles_then_exit_helper",
                    "--test-threads=1",
                ])
                .env("IRLUME_TEST_LEAK_RAW_HANDLES", mode)
                .env("IRLUME_TEST_LEAK_PUBLIC", encode(&env.public))
                .env("IRLUME_TEST_LEAK_PRIVATE", encode(&env.private))
                .env("IRLUME_TPM_MARKER_DIR", &marker_dir)
                .env_remove("IRLUME_TCTI")
                .stdout(std::process::Stdio::null())
                .status()
                .map_err(|e| Error::Io(e.to_string()))?;
            assert!(status.success(), "leak helper ({mode}) exited {status}");
            Ok(())
        };
        let flush_everything = |ctx: &mut Context| -> Result<()> {
            for range in SWEEP_RANGES {
                for handle in loaded_handles(ctx, range)? {
                    if let Ok(object) = ctx.tr_from_tpm_public(handle) {
                        let _ = ctx.flush_context(object);
                    }
                }
            }
            Ok(())
        };
        let outcome = (|| -> Result<()> {
            // Start from a clean chip: a failed earlier run of this test may
            // have left its fixtures loaded, and the preconditions are exact.
            let mut cleaner = raw()?;
            flush_everything(&mut cleaner)?;
            assert!(
                loaded_handle_numbers(&mut cleaner)?.is_empty(),
                "chip clean at start"
            );
            drop(cleaner);
            // Sealed before any child holds the exclusive device.
            let env = seal_with_pcrs(b"leak-fixture", &[7])?;
            assert!(!marker.exists(), "a normal conversation leaves no marker");

            run_child("foreign", &env)?;
            let mut observer = raw()?;
            let foreign = loaded_handle_numbers(&mut observer)?;
            drop(observer);
            assert_eq!(
                foreign.len(),
                1,
                "precondition: one foreign session loaded: {foreign:x?}"
            );

            run_child("leak", &env)?;
            assert!(
                marker.exists(),
                "the dead conversation left its marker behind"
            );
            assert_eq!(
                parse_marker(
                    &std::fs::read_to_string(&marker).map_err(|e| Error::Io(e.to_string()))?
                ),
                foreign,
                "the marker recorded the foreign session as prior state"
            );
            let mut observer = raw()?;
            let before = loaded_handle_numbers(&mut observer)?;
            drop(observer);
            assert_eq!(
                before.len(),
                3,
                "precondition: foreign + two of ours loaded, saw {before:x?}"
            );

            // The production open: recover, then usable.
            let mut ctx = open_context()?;
            let after = loaded_handle_numbers(&mut ctx)?;
            assert_eq!(
                after, foreign,
                "exactly irlume's leaks were swept; the foreign session survived"
            );
            assert!(marker.exists(), "this conversation holds its own marker");
            let _ = read_pcr_values(&mut ctx, &[7])?;
            drop(ctx);
            assert!(!marker.exists(), "a normal exit removed the marker");

            let got = unseal(&env)?;
            assert_eq!(&*got, b"leak-fixture");

            // Clean up the foreign session we planted (it is ours to flush).
            let mut cleaner = raw()?;
            flush_everything(&mut cleaner)?;
            assert!(
                loaded_handle_numbers(&mut cleaner)?.is_empty(),
                "left the chip clean"
            );
            Ok(())
        })();
        match previous_tcti {
            Some(v) => std::env::set_var("IRLUME_TCTI", v),
            None => std::env::remove_var("IRLUME_TCTI"),
        }
        match previous_dir {
            Some(v) => std::env::set_var("IRLUME_TPM_MARKER_DIR", v),
            None => std::env::remove_var("IRLUME_TPM_MARKER_DIR"),
        }
        let _ = std::fs::remove_dir_all(&marker_dir);
        outcome.expect("foreign preserved, own leaks swept, reuse over the raw device");
    }

    /// The production default (raw device, manager fallback) against the host
    /// TPM: a seal→unseal round trip with `IRLUME_TCTI` unset. On a machine
    /// where the raw device opens this exercises the stale-slot sweep and the
    /// exclusive-open path; where it does not, the fallback. Either way the
    /// secret must come back intact.
    #[test]
    #[ignore = "requires a real TPM (root); run with IRLUME_TCTI unset so the default transport order is exercised"]
    fn seal_unseal_roundtrip_default_transport_order() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let previous = std::env::var_os("IRLUME_TCTI");
        std::env::remove_var("IRLUME_TCTI");
        let secret = b"irlume-transport-order-roundtrip";
        let outcome = seal_with_pcrs(secret, &[7]).and_then(|env| unseal(&env));
        match previous {
            Some(v) => std::env::set_var("IRLUME_TCTI", v),
            None => std::env::remove_var("IRLUME_TCTI"),
        }
        let got = outcome.expect("seal then unseal over the default transport order");
        assert_eq!(&*got, secret, "round-trip must match");
    }

    /// The uninstall path's TPM cleanup (audit F4, 2026-09-17): after a seal
    /// persisted the SRK, eviction must remove exactly our key, and a second
    /// call must report the already-clean state. The Foreign arm is exercised
    /// for real: an ordinary RSA key CREATED under a parent carries an
    /// RNG-drawn modulus while sharing our exact public template - the
    /// same-template different-modulus key the #757 review asked for - and it
    /// must be left untouched.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0 (root), or swtpm via IRLUME_TCTI (CI does this)"]
    fn evict_persistent_srk_removes_ours_then_reports_absent() {
        // Persist the SRK the way production does: first seal derives and
        // evict-controls it to the persistent handle.
        let env = seal_with_pcrs(b"srk-eviction-probe", &[7]).expect("seal to persist the SRK");
        drop(unseal(&env).expect("unseal probe"));
        assert_eq!(
            evict_persistent_srk().expect("evict after persisting"),
            SrkEviction::Evicted,
            "our persisted SRK must be evicted"
        );
        assert_eq!(
            evict_persistent_srk().expect("second evict"),
            SrkEviction::Absent,
            "a clean handle must report Absent, not an error"
        );
    }

    /// Puts a foreign key created from `template` at our handle. Built with
    /// `create` + `load` under a transient SRK: an ordinary child key's
    /// modulus comes from the TPM RNG, so even with our exact template it
    /// cannot match the deterministic primary's - exactly the discriminator
    /// the #757 review demanded a test for.
    /// [`remove_foreign_key_at_srk_handle`] takes it away again.
    fn plant_foreign_key_at_srk_handle(template: Public) {
        // The CI lane serializes many irlume tests through one swtpm, and an
        // earlier test (any seal) may already have persisted OUR SRK at the
        // handle; the fixture below must own the handle, so clear our key
        // first. Every occupant this lane can produce is irlume's own, so a
        // Foreign here means the fixture cannot run, not a product defect.
        match evict_persistent_srk().expect("pre-test handle probe") {
            SrkEviction::Evicted | SrkEviction::Absent => {}
            SrkEviction::Foreign => panic!("handle already holds a foreign key"),
        }
        let mut ctx = open_context().expect("context");
        let parent = create_srk(&mut ctx).expect("transient SRK parent");
        // Child creation and loading run under the parent's (empty) auth, the
        // same nullauth-session pattern the seal path uses.
        let foreign = ctx
            .execute_with_nullauth_session(|ctx| {
                let created = ctx.create(parent, template, None, None, None, None)?;
                ctx.load(parent, created.out_private, created.out_public)
            })
            .expect("foreign fixture");
        let persistent = persistent_srk_handle().expect("handle");
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                Provision::Owner,
                foreign.into(),
                Persistent::Persistent(persistent),
            )
        })
        .expect("place foreign key at irlume's handle");
        let _ = ctx.flush_context(parent.into());
        let _ = ctx.flush_context(foreign.into());
    }

    /// Evicts the key [`plant_foreign_key_at_srk_handle`] placed, leaving the
    /// handle free.
    fn remove_foreign_key_at_srk_handle() {
        let persistent = persistent_srk_handle().expect("handle");
        let mut ctx = open_context().expect("context");
        let wanted = TpmHandle::Persistent(persistent);
        let object = ctx
            .tr_from_tpm_public(wanted)
            .expect("foreign key still present");
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                Provision::Owner,
                ObjectHandle::from(ESYS_TR::from(object)),
                Persistent::Persistent(persistent),
            )
        })
        .expect("manual foreign cleanup");
    }

    /// The check the ROCA advice relies on: irlume's own persisted SRK is the
    /// key its template derives; a key with irlume's template planted at the
    /// handle is not, though irlume would seal under it.
    #[test]
    #[ignore = "needs a TPM; CI runs it by name on swtpm, and scripts/with-swtpm.sh \
                runs it anywhere"]
    fn tpm_the_derived_key_check_tells_a_planted_key_from_irlumes() {
        let persisted = || {
            let mut ctx = open_context().expect("context");
            let wanted = TpmHandle::Persistent(persistent_srk_handle().expect("handle"));
            let object = ctx.tr_from_tpm_public(wanted).expect("a key at the handle");
            let (public, _, _) = ctx
                .read_public(KeyHandle::from(ESYS_TR::from(object)))
                .expect("read public");
            (ctx, public)
        };
        seal_with_pcrs(b"irlume-derived-key-check-secret!", &[7]).expect("seal");
        let (mut ctx, public) = persisted();
        assert_eq!(
            derived_srk(&mut ctx, &public).expect("derive"),
            DerivedKey::Same
        );
        drop(ctx);

        plant_foreign_key_at_srk_handle(srk_template().expect("template"));
        let (mut ctx, public) = persisted();
        assert!(is_irlume_srk(&public).expect("template check"));
        // swtpm derives no key with the ROCA fingerprint.
        assert_eq!(
            derived_srk(&mut ctx, &public).expect("derive"),
            DerivedKey::Unaffected
        );
        drop(ctx);
        remove_foreign_key_at_srk_handle();
    }

    /// A foreign RSA-2048 key with our exact template at our handle must
    /// survive an eviction attempt (the destructive-path identity contract).
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0 (root), or swtpm via IRLUME_TCTI (CI does this)"]
    fn evict_persistent_srk_never_touches_a_same_template_foreign_key() {
        plant_foreign_key_at_srk_handle(srk_template().expect("template"));
        assert_eq!(
            evict_persistent_srk().expect("evict probe"),
            SrkEviction::Foreign,
            "a same-template key with a foreign modulus must be reported, never evicted"
        );

        // The foreign key is still there; remove it so the instance is clean,
        // then the handle reports Absent as the post-uninstall state.
        remove_foreign_key_at_srk_handle();
        assert_eq!(
            evict_persistent_srk().expect("post-cleanup probe"),
            SrkEviction::Absent
        );
    }

    /// Persists `object` at `handle` with an empty owner authorization and
    /// flushes the transient copy.
    fn persist_at(ctx: &mut Context, object: KeyHandle, handle: u32) {
        let persistent = PersistentTpmHandle::new(handle).expect("handle");
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                Provision::Owner,
                object.into(),
                Persistent::Persistent(persistent),
            )
        })
        .expect("persist the fixture key");
        let _ = ctx.flush_context(object.into());
    }

    /// Evicts whatever a fixture left at `handle`; a free handle is fine, and
    /// is probed first so that esys logs no error for it (#601).
    fn evict_fixture_at(handle: u32) {
        let mut ctx = open_context().expect("context");
        let persistent = PersistentTpmHandle::new(handle).expect("handle");
        let wanted = TpmHandle::Persistent(persistent);
        if !tpm_handle_exists(&mut ctx, TPM2_HR_PERSISTENT, wanted).expect("handle probe") {
            return;
        }
        let Ok(object) = ctx.tr_from_tpm_public(wanted) else {
            return;
        };
        let _ = ctx.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                Provision::Owner,
                ObjectHandle::from(ESYS_TR::from(object)),
                Persistent::Persistent(persistent),
            )
        });
    }

    /// ADR-0034 §3 and its 2026-10-15 amendment: the DA-exempt key is found
    /// at any owner handle and evicted, while another stack's TCG storage key
    /// (systemd's RSA key at 0x81000001) and a key with irlume's DA-exempt
    /// template but a random modulus stay. The label gives irlume a key of its
    /// own, so the TCG key's modulus differs from irlume's.
    ///
    /// swtpm only. The fixture persists keys at three fixed handles and
    /// evicts what is there afterwards, and the eviction under test removes
    /// irlume's DA-exempt key wherever it is. On a real machine 0x81000001
    /// usually holds systemd's storage key, so the test refuses any transport
    /// but swtpm ([`open_context`] obeys an explicit `IRLUME_TCTI` alone), and
    /// any handle of its own that is already taken, before it writes anything.
    #[test]
    #[ignore = "needs swtpm; CI runs it by name on swtpm, and scripts/with-swtpm.sh \
                runs it anywhere"]
    fn tpm_only_irlumes_da_exempt_key_is_evicted() {
        const SHARED: u32 = 0x8100_0001;
        const OURS: u32 = 0x8101_0003;
        const PLANTED: u32 = 0x8101_0004;
        assert!(
            std::env::var("IRLUME_TCTI").is_ok_and(|tcti| tcti.starts_with("swtpm:")),
            "this fixture writes persistent handles: run it on swtpm, never on a real TPM"
        );
        let exempt = da_exempt_srk_template().expect("template");
        let mut ctx = open_context().expect("context");
        let taken: Vec<String> = persistent_handles(&mut ctx)
            .expect("handle scan")
            .into_iter()
            .filter(|handle| [SHARED, OURS, PLANTED].contains(handle))
            .map(|handle| format!("{handle:#010x}"))
            .collect();
        assert!(
            taken.is_empty(),
            "the fixture's handles {} are taken; it touches nothing it did not place",
            taken.join(", ")
        );
        let shared =
            create_storage_key(&mut ctx, tcg_shared_rsa_srk_template()).expect("TCG storage key");
        let (shared_public, _, _) = ctx.read_public(shared).expect("read the TCG key");
        persist_at(&mut ctx, shared, SHARED);
        let ours = create_storage_key(&mut ctx, exempt.clone()).expect("irlume's key");
        let (ours_public, _, _) = ctx.read_public(ours).expect("read irlume's key");
        persist_at(&mut ctx, ours, OURS);
        let parent = create_srk(&mut ctx).expect("transient parent");
        let planted = ctx
            .execute_with_nullauth_session(|ctx| {
                let created = ctx.create(parent, exempt, None, None, None, None)?;
                ctx.load(parent, created.out_private, created.out_public)
            })
            .expect("planted key");
        persist_at(&mut ctx, planted, PLANTED);
        let _ = ctx.flush_context(parent.into());
        drop(ctx);

        let first = evict_da_exempt_srks();
        let second = evict_da_exempt_srks();
        let left = open_context().and_then(|mut ctx| persistent_handles(&mut ctx));
        for handle in [SHARED, OURS, PLANTED] {
            evict_fixture_at(handle);
        }

        assert_ne!(
            rsa_modulus(&shared_public),
            rsa_modulus(&ours_public),
            "the TCG template and irlume's must derive different keys"
        );
        assert_eq!(first.expect("first scan"), vec![OURS]);
        assert_eq!(second.expect("second scan"), Vec::<u32>::new());
        let left = left.expect("handle scan");
        assert!(left.contains(&SHARED), "another stack's key stays");
        assert!(left.contains(&PLANTED), "a key with another modulus stays");
        assert!(!left.contains(&OURS));
    }

    /// Persists a child key of `template`, with a random modulus, at `handle`.
    fn persist_child_at(template: Public, handle: u32) {
        let mut ctx = open_context().expect("context");
        let parent = create_srk(&mut ctx).expect("transient parent");
        let child = ctx
            .execute_with_nullauth_session(|ctx| {
                let created = ctx.create(parent, template, None, None, None, None)?;
                ctx.load(parent, created.out_private, created.out_public)
            })
            .expect("child key");
        let _ = ctx.flush_context(parent.into());
        persist_at(&mut ctx, child, handle);
    }

    /// Persists copies of one key from 0x81000100 upward until the TPM
    /// answers `TPM_RC_NV_SPACE`, and returns their handles (swtpm holds 64).
    fn fill_persistent_capacity() -> Vec<u32> {
        let mut ctx = open_context().expect("context");
        let key = create_srk(&mut ctx).expect("transient key");
        let mut filled = Vec::new();
        for handle in 0x8100_0100..0x8100_0200 {
            let persistent = PersistentTpmHandle::new(handle).expect("handle");
            let result = ctx.execute_with_nullauth_session(|ctx| {
                ctx.evict_control(
                    Provision::Owner,
                    key.into(),
                    Persistent::Persistent(persistent),
                )
            });
            match result {
                Ok(_) => filled.push(handle),
                Err(error)
                    if classify_failure(error).class == storage_key::FailureClass::NoSpace =>
                {
                    break
                }
                Err(error) => panic!("filling the TPM: {error}"),
            }
        }
        let _ = ctx.flush_context(key.into());
        filled
    }

    /// Sets, or with `current` clears, the owner hierarchy's authorization.
    fn set_owner_auth(current: &[u8], new: &[u8]) {
        use tss_esapi::handles::AuthHandle;
        let mut ctx = open_context().expect("context");
        ctx.tr_set_auth(
            ObjectHandle::Owner,
            Auth::try_from(current.to_vec()).expect("auth"),
        )
        .expect("current owner auth");
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.hierarchy_change_auth(
                AuthHandle::Owner,
                Auth::try_from(new.to_vec()).expect("auth"),
            )
        })
        .expect("change the owner auth");
    }

    /// ADR-0034 §3.2 and #1083 on swtpm, through the real TPM operations: the
    /// key is persisted at the preferred handle, found there again with
    /// nothing derived, adopted by its name when the record is lost, moved on
    /// when another key holds the preferred handle, and refused with
    /// `TPM_RC_NV_SPACE` when the TPM is full and `TPM_RC_BAD_AUTH` when an
    /// owner authorization is set (`tpm2_changeauth -c o`). swtpm only: it
    /// persists keys at fixed handles, fills the TPM and sets an owner
    /// authorization, and it refuses any transport but swtpm.
    #[test]
    #[ignore = "needs swtpm; CI runs it by name on swtpm, and scripts/with-swtpm.sh \
                runs it anywhere"]
    fn tpm_the_da_exempt_key_is_persisted_found_and_refused() {
        use crate::storage_key::{ensure_with, Outcome, Plan, Record};
        use irlume_common::tpm_readiness::RefusalReason;
        const BOOT: &str = "0a1b2c3d-4e5f-6789-abcd-ef0123456789";
        const PREFERRED: u32 = 0x8101_0003;
        assert!(
            std::env::var("IRLUME_TCTI").is_ok_and(|tcti| tcti.starts_with("swtpm:")),
            "this test writes persistent handles: run it on swtpm, never on a real TPM"
        );
        let plan = Ok(Plan {
            preferred: PREFERRED,
            original: 0x8101_0002,
        });
        let step = |record: &Record| {
            let mut tpm = DaExemptKeyTpm::open().expect("context");
            ensure_with(&mut tpm, record, Some(BOOT), &plan).expect("the step runs")
        };
        let handles = || {
            let mut ctx = open_context().expect("context");
            persistent_handles(&mut ctx).expect("handle scan")
        };
        let before = handles();
        assert!(
            !before.contains(&PREFERRED) && !before.contains(&(PREFERRED + 1)),
            "the handles this test uses are taken: {before:x?}"
        );

        let (record, first) = step(&Record::default());
        let (_, again) = step(&record);
        let (_, adopted) = step(&Record::default());
        let with_key = handles();
        let removed = evict_da_exempt_srks();

        persist_child_at(da_exempt_srk_template().expect("template"), PREFERRED);
        let (_, moved) = step(&Record::default());
        let moved_removed = evict_da_exempt_srks();
        evict_fixture_at(PREFERRED);

        let filled = fill_persistent_capacity();
        let (_, full) = step(&Record::default());
        for handle in &filled {
            evict_fixture_at(*handle);
        }

        set_owner_auth(b"", b"irlume-test-owner");
        let (_, owner) = step(&Record::default());
        set_owner_auth(b"irlume-test-owner", b"");
        let after = handles();

        assert_eq!(first, Outcome::Persisted { handle: PREFERRED });
        assert_eq!(again, Outcome::Present { handle: PREFERRED });
        assert_eq!(adopted, Outcome::Adopted { handle: PREFERRED });
        assert_eq!(
            with_key.len(),
            before.len() + 1,
            "an adoption persists no second copy"
        );
        assert_eq!(removed.expect("evict"), vec![PREFERRED]);
        assert_eq!(
            moved,
            Outcome::Persisted {
                handle: PREFERRED + 1
            }
        );
        assert_eq!(moved_removed.expect("evict"), vec![PREFERRED + 1]);
        assert!(!filled.is_empty(), "the TPM had room before it was filled");
        let reason = |outcome: &Outcome| match outcome {
            Outcome::Refused(refusal) => refusal.reason,
            other => panic!("not refused: {other:?}"),
        };
        assert_eq!(reason(&full), RefusalReason::NoSpace);
        assert_eq!(reason(&owner), RefusalReason::OwnerAuthorization);
        assert_eq!(after, before, "the test leaves the TPM as it found it");
    }

    /// The state, template-key and keyring directories pointed at a fresh
    /// temporary tree until dropped. Hold `testenv::ENV_LOCK` first.
    struct StateDirs {
        dir: String,
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl StateDirs {
        fn new(name: &str) -> Self {
            let dir = crate::test_tmp_dir(name);
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(format!("{dir}/keyring")).expect("keyring dir");
            std::fs::create_dir_all(format!("{dir}/template-keys")).expect("template key dir");
            let vars = [
                ("IRLUME_STATE_DIR", dir.clone()),
                ("IRLUME_KEYRING_DIR", format!("{dir}/keyring")),
                ("IRLUME_TEMPLATE_KEY_DIR", format!("{dir}/template-keys")),
            ];
            let previous = vars
                .iter()
                .map(|(var, _)| (*var, std::env::var_os(var)))
                .collect();
            for (var, value) in &vars {
                std::env::set_var(var, value);
            }
            Self { dir, previous }
        }

        /// Writes `env` as `user`'s keyring envelope.
        fn store(&self, user: &str, env: &SealedEnvelope) {
            let bytes = serde_json::to_vec(env).expect("envelope json");
            std::fs::write(format!("{}/keyring/{user}.json", self.dir), bytes)
                .expect("write the envelope");
        }
    }

    impl Drop for StateDirs {
        fn drop(&mut self) {
            for (var, value) in self.previous.drain(..) {
                match value {
                    Some(value) => std::env::set_var(var, value),
                    None => std::env::remove_var(var),
                }
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn require_swtpm() {
        assert!(
            std::env::var("IRLUME_TCTI").is_ok_and(|tcti| tcti.starts_with("swtpm:")),
            "this test writes persistent handles: run it on swtpm, never on a real TPM"
        );
    }

    /// ADR-0034 §3.3 on swtpm: before irlumed persists the DA-exempt key a
    /// seal records no parent and uses the original key; once the start-up
    /// step persisted it, new seals record it and unseal through it while an
    /// envelope sealed before still unseals through the original key. A
    /// lockout spares irlume only once every envelope is on the new key. The
    /// envelope's handle is a hint: with the key re-persisted at another
    /// handle the recorded key opens it; with the key gone the load fails, and
    /// a new seal falls back to the original key.
    #[test]
    #[ignore = "needs swtpm; CI runs it by name on swtpm, and scripts/with-swtpm.sh \
                runs it anywhere"]
    fn tpm_new_seals_go_under_the_da_exempt_key_once_it_is_persisted() {
        const PREFERRED: u32 = 0x8101_0003;
        require_swtpm();
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dirs = StateDirs::new("seal-parent");
        let handles = || {
            let mut ctx = open_context().expect("context");
            persistent_handles(&mut ctx).expect("handle scan")
        };
        // The first seal persists the original key when no earlier test did,
        // so the handles are taken after it: what this test must leave as it
        // found is the DA-exempt key's.
        let old = seal_with_pcrs(b"sealed before", &[]).expect("seal");
        let before = handles();
        assert!(
            !before.contains(&PREFERRED) && !before.contains(&(PREFERRED + 1)),
            "the handles this test uses are taken: {before:x?}"
        );
        dirs.store("alice", &old);
        let persisted = crate::storage_key::ensure_at_start();
        let new = seal_with_pcrs(b"sealed after", &[]).expect("seal");
        let new_open = unseal(&new);
        let new_read_only = unseal_read_only(&new);
        let old_open = unseal(&old);
        let spared_mixed = lockout_state().map(|l| l.storage_key_no_da);
        dirs.store("alice", &new);
        let spared_all = lockout_state().map(|l| l.storage_key_no_da);

        let removed = evict_da_exempt_srks();
        persist_child_at(da_exempt_srk_template().expect("template"), PREFERRED);
        let moved = crate::storage_key::ensure_at_start();
        let through_record = unseal(&new);
        let removed_again = evict_da_exempt_srks();
        let gone = unseal(&new);
        let fallback = seal_with_pcrs(b"sealed without it", &[]);
        evict_fixture_at(PREFERRED);
        let after = handles();
        drop(dirs);

        assert!(
            old.parent.is_none(),
            "no parent before the key is persisted"
        );
        assert_eq!(
            persisted.expect("the step"),
            Some(crate::storage_key::Outcome::Persisted { handle: PREFERRED })
        );
        let parent = new.parent.clone().expect("a new seal records its parent");
        assert_eq!(parent.handle, PREFERRED);
        assert_eq!(
            new_open.expect("unseal under the new key").as_slice(),
            b"sealed after"
        );
        assert_eq!(
            new_read_only.expect("read-only unseal").as_slice(),
            b"sealed after"
        );
        assert_eq!(
            old_open.expect("the original key still opens").as_slice(),
            b"sealed before"
        );
        assert!(
            !spared_mixed.expect("lockout state"),
            "an envelope on the original key"
        );
        assert!(
            spared_all.expect("lockout state"),
            "every envelope on the new key"
        );
        assert_eq!(removed.expect("evict"), vec![PREFERRED]);
        assert_eq!(
            moved.expect("the step"),
            Some(crate::storage_key::Outcome::Persisted {
                handle: PREFERRED + 1
            })
        );
        assert_eq!(
            through_record
                .expect("the recorded key opens it at its new handle")
                .as_slice(),
            b"sealed after"
        );
        assert_eq!(removed_again.expect("evict"), vec![PREFERRED + 1]);
        assert!(
            gone.is_err(),
            "no other key opens an envelope with a parent"
        );
        assert!(
            fallback.expect("seal").parent.is_none(),
            "without the key a seal uses the original key"
        );
        assert_eq!(
            after, before,
            "the test leaves the TPM's handles as it found them"
        );
    }

    /// ADR-0034 §3.3 on swtpm: a template key, a login password and a GNOME
    /// keyring token sealed before irlumed persisted the DA-exempt key move
    /// onto it at their move points (irlumed's start for the template key, a
    /// login's reseal for the keyring), keeping kind, wrap and uid, and still
    /// unseal; a second pass finds nothing to move, and a lockout then spares
    /// irlume. doctor's report names all three before the moves and none
    /// after (§4). The ladder is pinned to the literal PCR 7 seal, so only the
    /// storage key changes.
    #[test]
    #[ignore = "needs swtpm; CI runs it by name on swtpm, and scripts/with-swtpm.sh \
                runs it anywhere"]
    fn tpm_envelopes_on_the_original_key_move_onto_the_da_exempt_key() {
        use crate::envelope::SecretKind;
        use crate::keyring::{envelope_path, reseal_password, unseal_password, Reseal};
        use irlume_common::tpm_readiness::{EnvelopeKind, OriginalKeyEnvelope};
        const PREFERRED: u32 = 0x8101_0003;
        require_swtpm();
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dirs = StateDirs::new("move-onto-da-exempt");
        // IRLUME_PCRS=7 and no prediction file: the literal PCR 7 seal.
        let _prediction = PredictionFixture::new();
        let handles = || {
            let mut ctx = open_context().expect("context");
            persistent_handles(&mut ctx).expect("handle scan")
        };
        let _alice = crate::account::remember("alice", 4150);
        let _bob = crate::account::remember("bob", 4151);
        let key = crate::crypto::generate_key();
        crate::template_key::reseal_key("alice", &key).expect("seal the template key");
        // The first seal persists the original key when no earlier test did,
        // so the handles are taken after it: what this test must leave as it
        // found is the DA-exempt key's.
        let before = handles();
        assert!(
            !before.contains(&PREFERRED),
            "the handle this test uses is taken: {before:x?}"
        );
        crate::keyring::seal_password("alice", b"alice-password").expect("arm the password");
        let token = b"bob-gnome-keyring-token-for-tests";
        let mut armed = seal_with_pcrs(token, &[7]).expect("seal the token");
        armed.secret = SecretKind::GnomeKeyringToken;
        armed.password_wrap = Some(crate::recovery::wrap(b"bob-password", token).expect("wrap"));
        armed.uid = Some(4151);
        armed.save(&envelope_path("bob")).expect("arm the token");
        let paths = [
            crate::template_key::key_path("alice"),
            envelope_path("alice"),
            envelope_path("bob"),
        ];
        // Read without panicking: the key is evicted before anything is
        // asserted, so a failure leaves the shared swtpm as it was.
        let parents = || {
            paths
                .iter()
                .map(|path| SealedEnvelope::load(path).map(|env| env.parent).ok())
                .collect::<Vec<_>>()
        };
        let sealed_before = parents();

        let persisted = crate::storage_key::ensure_at_start();
        let reported_before = crate::storage_key::report();
        let template_move = crate::template_key::move_to_stronger_policy("alice");
        let template_again = crate::template_key::move_to_stronger_policy("alice");
        let template_key = crate::template_key::load_key("alice");
        let password_move = reseal_password("alice", b"alice-password", None);
        let password_again = reseal_password("alice", b"alice-password", None);
        let password = unseal_password("alice");
        let token_move = reseal_password("bob", b"bob-password", None);
        let token_again = reseal_password("bob", b"bob-password", None);
        let token_open = unseal_password("bob");
        let token_env = SealedEnvelope::load(&envelope_path("bob"));
        let moved = parents();
        let reported_after = crate::storage_key::report();
        let spared = lockout_state().map(|l| l.storage_key_no_da);
        let removed = evict_da_exempt_srks();
        let after = handles();
        drop(dirs);

        assert!(
            sealed_before
                .iter()
                .all(|parent| matches!(parent, Some(None))),
            "sealed under the original key: {sealed_before:?}"
        );
        assert_eq!(
            persisted.expect("the step"),
            Some(crate::storage_key::Outcome::Persisted { handle: PREFERRED })
        );
        assert_eq!(
            template_move.expect("the startup move"),
            Some(MoveGain::DaExemptKey)
        );
        assert_eq!(template_again.expect("a second start"), None);
        assert_eq!(template_key.expect("load").as_slice(), key.as_slice());
        assert_eq!(
            password_move.expect("the reseal"),
            Reseal::MovedToDaExemptKey
        );
        assert_eq!(password_again.expect("a second login"), Reseal::Unchanged);
        assert_eq!(password.expect("unseal").as_slice(), b"alice-password");
        assert_eq!(token_move.expect("the reseal"), Reseal::MovedToDaExemptKey);
        assert_eq!(token_again.expect("a second login"), Reseal::Unchanged);
        assert_eq!(token_open.expect("unseal").as_slice(), token);
        let token_env = token_env.expect("the token envelope");
        assert_eq!(token_env.secret, SecretKind::GnomeKeyringToken);
        assert_eq!(token_env.uid, Some(4151));
        let wrap = token_env.password_wrap.as_ref().expect("the wrap");
        assert_eq!(
            &*crate::recovery::unwrap(b"bob-password", wrap).expect("the wrap opens"),
            token
        );
        assert!(
            moved.iter().all(|parent| matches!(
                parent,
                Some(Some(parent)) if parent.handle == PREFERRED
            )),
            "every envelope on the DA-exempt key: {moved:?}"
        );
        assert!(spared.expect("lockout state"), "a lockout spares irlume");
        // What doctor names (ADR-0034 §4): every envelope before the moves,
        // none after.
        let on_original = |report: Result<irlume_common::tpm_readiness::DaExemptKey>| {
            let report = report.expect("the report");
            assert_eq!(report.handle, Some(PREFERRED));
            report.on_original_key.expect("the list")
        };
        let before_moves = on_original(reported_before);
        let named = |user: &str, kind| OriginalKeyEnvelope {
            user: user.into(),
            kind,
        };
        assert_eq!(
            before_moves.named,
            [
                named("alice", EnvelopeKind::TemplateKey),
                named("alice", EnvelopeKind::KeyringSecret),
                named("bob", EnvelopeKind::KeyringSecret),
            ]
        );
        assert_eq!(before_moves.total, 3);
        let after_moves = on_original(reported_after);
        assert_eq!((after_moves.named.len(), after_moves.total), (0, 0));
        assert_eq!(removed.expect("evict"), vec![PREFERRED]);
        assert_eq!(
            after, before,
            "the test leaves the TPM's handles as it found them"
        );
    }

    /// ADR-0034 §3.3 acceptance on swtpm, recovery by name: a template key
    /// and a keyring secret record the DA-exempt key at 0x81010003; the key
    /// leaves that handle and another stack's key takes it. irlumed's start
    /// persists the key again by the section 3.2 rule (at 0x81010004, the
    /// next free handle). The template key then records that handle and
    /// opens through it with irlumed's record gone, where its old handle no
    /// longer opens it. The keyring envelope is not rewritten at start (its
    /// writers are ordered only by irlumed's worker) and opens through
    /// irlumed's record of the key. A second start finds nothing to do; with
    /// the key gone too, both are reported missing.
    #[test]
    #[ignore = "needs swtpm; CI runs it by name on swtpm, and scripts/with-swtpm.sh \
                runs it anywhere"]
    fn tpm_an_envelope_whose_handle_another_stack_took_is_recovered_by_name() {
        use crate::storage_key::{RepointOutcome, Repointed};
        use irlume_common::tpm_readiness::EnvelopeKind;
        const PREFERRED: u32 = 0x8101_0003;
        require_swtpm();
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dirs = StateDirs::new("repoint");
        let handles = || {
            let mut ctx = open_context().expect("context");
            persistent_handles(&mut ctx).expect("handle scan")
        };
        // The first seal persists the original key when no earlier test did,
        // so the handles are taken after it.
        let original = seal_with_pcrs(b"on the original key", &[]).expect("seal");
        let before = handles();
        assert!(
            !before.contains(&PREFERRED) && !before.contains(&(PREFERRED + 1)),
            "the handles this test uses are taken: {before:x?}"
        );
        dirs.store("alice", &original);
        let first = crate::storage_key::ensure_at_start();
        let template_path = crate::template_key::key_path("alice");
        let template = seal_with_pcrs(b"a template key", &[]).expect("seal");
        template
            .save(&template_path)
            .expect("save the template key");
        let keyring = seal_with_pcrs(b"a keyring secret", &[]).expect("seal");
        dirs.store("alice", &keyring);
        let keyring_path = crate::keyring::envelope_path("alice");
        let keyring_bytes = std::fs::read(&keyring_path).expect("the keyring envelope");

        let left = evict_da_exempt_srks();
        persist_child_at(srk_template().expect("template"), PREFERRED);
        let again = crate::storage_key::ensure_at_start();
        let repointed = crate::storage_key::repoint_at_start();
        let recorded = SealedEnvelope::load(&template_path);
        let keyring_kept = std::fs::read(&keyring_path).ok() == Some(keyring_bytes);
        let keyring_open = unseal(&keyring);
        std::fs::remove_file(format!("{}/tpm-storage-key", dirs.dir)).expect("drop the record");
        let opened = recorded.as_ref().ok().map(unseal);
        let stale = unseal(&template);
        let nothing = crate::storage_key::repoint_at_start();
        let gone = evict_da_exempt_srks();
        let missing = crate::storage_key::repoint_at_start();
        evict_fixture_at(PREFERRED);
        let after = handles();
        drop(dirs);

        assert_eq!(
            first.expect("the step"),
            Some(crate::storage_key::Outcome::Persisted { handle: PREFERRED })
        );
        assert_eq!(template.parent.as_ref().map(|p| p.handle), Some(PREFERRED));
        assert_eq!(left.expect("evict"), vec![PREFERRED]);
        assert_eq!(
            again.expect("the step"),
            Some(crate::storage_key::Outcome::Persisted {
                handle: PREFERRED + 1
            })
        );
        let entry = |kind, from, outcome| Repointed {
            user: "alice".into(),
            kind,
            from,
            outcome,
        };
        assert_eq!(
            repointed.expect("recovery by name"),
            [entry(
                EnvelopeKind::TemplateKey,
                PREFERRED,
                RepointOutcome::Moved(PREFERRED + 1)
            )]
        );
        let recorded = recorded.expect("the template key");
        assert_eq!(
            recorded.parent.as_ref().map(|p| (p.handle, &p.name)),
            template.parent.as_ref().map(|p| (PREFERRED + 1, &p.name)),
            "the handle changes and the name stays"
        );
        assert_eq!(
            opened
                .expect("parsed")
                .expect("it opens by its own handle")
                .as_slice(),
            b"a template key"
        );
        assert!(stale.is_err(), "the old handle holds another stack's key");
        assert!(keyring_kept, "a keyring envelope is not rewritten at start");
        assert_eq!(
            keyring_open
                .expect("it opens through irlumed's record")
                .as_slice(),
            b"a keyring secret"
        );
        assert_eq!(nothing.expect("the next start"), []);
        assert_eq!(gone.expect("evict"), vec![PREFERRED + 1]);
        assert_eq!(
            missing.expect("the step"),
            [
                entry(
                    EnvelopeKind::TemplateKey,
                    PREFERRED + 1,
                    RepointOutcome::Missing
                ),
                entry(
                    EnvelopeKind::KeyringSecret,
                    PREFERRED,
                    RepointOutcome::Missing
                ),
            ]
        );
        assert_eq!(
            after, before,
            "the test leaves the TPM's handles as it found them"
        );
    }

    /// ADR-0034 §3.4 on swtpm: irlumed's start records the original key's
    /// TPM name once today's derivation of the original template gives that
    /// key, at a start that derived nothing else: not at the start that
    /// persisted the DA-exempt key, but at the next one.
    #[test]
    #[ignore = "needs swtpm; CI runs it by name on swtpm, and scripts/with-swtpm.sh \
                runs it anywhere"]
    fn tpm_the_original_key_name_is_recorded_at_a_start_that_derives_nothing_else() {
        use crate::storage_key::KeyTpm as _;
        const PREFERRED: u32 = 0x8101_0003;
        require_swtpm();
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dirs = StateDirs::new("original-record");
        let handles = || {
            let mut ctx = open_context().expect("context");
            persistent_handles(&mut ctx).expect("handle scan")
        };
        // The first seal persists the original key when no earlier test did,
        // so the handles are taken after it.
        let original = seal_with_pcrs(b"on the original key", &[]).expect("seal");
        let before = handles();
        assert!(
            !before.contains(&PREFERRED),
            "the handle this test uses is taken: {before:x?}"
        );
        dirs.store("alice", &original);
        let record = || {
            let bytes = std::fs::read(format!("{}/tpm-storage-key", dirs.dir)).expect("record");
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("record json")
        };
        let first = crate::storage_key::ensure_at_start();
        let after_first = record();
        let second = crate::storage_key::ensure_at_start();
        let after_second = record();
        let name = DaExemptKeyTpm::open()
            .and_then(|mut tpm| tpm.name_at(PERSISTENT_SRK_HANDLE))
            .map(|name| name.map(|name| crate::storage_key::hex(&name)));
        let removed = evict_da_exempt_srks();
        let after = handles();
        drop(dirs);

        assert_eq!(
            first.expect("the step"),
            Some(crate::storage_key::Outcome::Persisted { handle: PREFERRED })
        );
        assert!(
            after_first.get("original").is_none(),
            "the start that derived the DA-exempt key leaves it: {after_first}"
        );
        assert_eq!(
            second.expect("the step"),
            Some(crate::storage_key::Outcome::Present { handle: PREFERRED })
        );
        let name = name.expect("read").expect("the original key");
        assert_eq!(
            after_second["original"],
            serde_json::json!({
                "handle": PERSISTENT_SRK_HANDLE, "name": name, "matched": true
            })
        );
        assert_eq!(removed.expect("evict"), vec![PREFERRED]);
        assert_eq!(
            after, before,
            "the test leaves the TPM's handles as it found them"
        );
    }

    /// Fails the authorization of a DA-protected object (no noDA, an
    /// authValue) under `parent` until the TPM answers `TPM_RC_LOCKOUT`.
    /// swtpm starts with maxTries 3 (ADR-0034's swtpm experiments).
    fn fail_until_lockout(ctx: &mut Context, parent: KeyHandle) {
        use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .build()
            .expect("attributes");
        let template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .expect("template");
        let right = Auth::try_from(b"right".to_vec()).expect("auth");
        let object = ctx
            .execute_with_nullauth_session(|ctx| {
                let created = ctx.create(
                    parent,
                    template,
                    Some(right),
                    Some(SensitiveData::try_from(b"x".to_vec())?),
                    None,
                    None,
                )?;
                ctx.load(parent, created.out_private, created.out_public)
            })
            .expect("a DA-protected object");
        ctx.tr_set_auth(
            object.into(),
            Auth::try_from(b"wrong".to_vec()).expect("auth"),
        )
        .expect("set the wrong auth");
        let mut locked = false;
        for _ in 0..16 {
            match ctx.execute_with_nullauth_session(|ctx| ctx.unseal(object.into())) {
                Ok(_) => panic!("a wrong authValue unsealed"),
                Err(tss_esapi::Error::Tss2Error(code))
                    if code.kind() == Some(Tss2ResponseCodeKind::Lockout) =>
                {
                    locked = true;
                    break;
                }
                Err(_) => {}
            }
        }
        let _ = ctx.flush_context(object.into());
        assert!(locked, "the TPM reached lockout");
    }

    /// ADR-0034 acceptance, in a swtpm of its own (the lockout lasts 1000 s
    /// on a fresh swtpm, so the shared lane never runs it): with the TPM in
    /// dictionary-attack lockout, a seal and an unseal under the DA-exempt key
    /// succeed, and an envelope under the original key does not load. A
    /// template key and a keyring secret moved at their move points onto the
    /// DA-exempt key unseal in lockout, and a template key still on the
    /// original key cannot move while it lasts. The moves run before the
    /// lockout: irlume never ends one (ADR-0034 §2, the source scan in
    /// `tests/no_dictionary_attack_commands.rs`) and a fresh swtpm's lasts
    /// 1000 s, and nothing in a move depends on an earlier lockout.
    #[test]
    #[ignore = "needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with \
                scripts/with-swtpm.sh); CI runs it so"]
    fn tpm_the_da_exempt_key_keeps_irlume_working_through_a_lockout() {
        require_swtpm();
        assert_eq!(
            std::env::var("IRLUME_TEST_OWN_SWTPM").as_deref(),
            Ok("1"),
            "this test puts the TPM in lockout: give it a swtpm of its own"
        );
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dirs = StateDirs::new("lockout");
        // IRLUME_PCRS=7 and no prediction file: the literal PCR 7 seal, so a
        // move changes only the storage key.
        let _prediction = PredictionFixture::new();
        let _alice = crate::account::remember("alice", 4160);
        let _carol = crate::account::remember("carol", 4161);
        let _dave = crate::account::remember("dave", 4162);
        let old = seal_with_pcrs(b"on the original key", &[7]).expect("seal");
        dirs.store("alice", &old);
        let template_key = crate::crypto::generate_key();
        crate::template_key::reseal_key("carol", &template_key).expect("seal a template key");
        crate::template_key::reseal_key("dave", &crate::crypto::generate_key())
            .expect("seal a template key");
        let dave = crate::template_key::key_path("dave");
        let persisted = crate::storage_key::ensure_at_start().expect("the step");
        let new = seal_with_pcrs(b"on the DA-exempt key", &[]).expect("seal");
        let template_move = crate::template_key::move_to_stronger_policy("carol");
        let keyring_move = crate::keyring::reseal_password("alice", b"on the original key", None);
        let (handle, name) = crate::storage_key::recorded_key().expect("recorded");
        let mut ctx = open_context().expect("context");
        let key = da_exempt_key_at(&mut ctx, handle, &name, true)
            .expect("probe")
            .expect("the DA-exempt key");
        fail_until_lockout(&mut ctx, key);
        drop(ctx);

        let state = lockout_state().expect("lockout state");
        let opened = unseal(&new);
        let during = seal_with_pcrs(b"sealed in lockout", &[]);
        let during_opened = during.as_ref().ok().map(unseal);
        let blocked = unseal(&old);
        let template_opened = crate::template_key::load_key("carol");
        let keyring_opened = crate::keyring::unseal_password("alice");
        let dave_before = std::fs::read(&dave).expect("the template key");
        let stuck = crate::template_key::move_to_stronger_policy("dave");
        let stuck_unchanged = std::fs::read(&dave).expect("the template key") == dave_before;
        drop(dirs);

        assert!(matches!(
            persisted,
            Some(crate::storage_key::Outcome::Persisted { .. })
        ));
        assert!(state.in_lockout, "the TPM is in lockout");
        assert_eq!(
            opened.expect("unseal under the new key").as_slice(),
            b"on the DA-exempt key"
        );
        assert!(during.expect("seal in lockout").parent.is_some());
        assert_eq!(
            during_opened
                .expect("sealed")
                .expect("unseal in lockout")
                .as_slice(),
            b"sealed in lockout"
        );
        assert!(blocked.is_err(), "the original key is blocked in lockout");
        assert_eq!(
            template_move.expect("the startup move"),
            Some(MoveGain::DaExemptKey)
        );
        assert_eq!(
            keyring_move.expect("the reseal"),
            crate::keyring::Reseal::MovedToDaExemptKey
        );
        assert_eq!(
            template_opened
                .expect("the moved template key in lockout")
                .as_slice(),
            template_key.as_slice()
        );
        assert_eq!(
            keyring_opened
                .expect("the moved keyring secret in lockout")
                .as_slice(),
            b"on the original key"
        );
        assert!(
            stuck.is_err() && stuck_unchanged,
            "a key on the original key cannot move in lockout"
        );
    }

    /// Our SRK template with a non-empty authPolicy, as another stack's
    /// storage keys (clevis, systemd-cryptenroll) carry: a key irlume never
    /// takes for its own SRK.
    fn policy_bound_srk_template() -> Public {
        let Public::Rsa {
            object_attributes,
            parameters,
            ..
        } = srk_template().expect("template")
        else {
            unreachable!("the SRK template is RSA")
        };
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_auth_policy(Digest::try_from(vec![0x5a; 32]).expect("policy digest"))
            .with_rsa_parameters(parameters)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .expect("policy-bound template")
    }

    /// While another key holds irlume's SRK handle, seals use a transient
    /// SRK, and a read-only unseal must too: a transient SRK persists
    /// nothing. The foreign key stays. Once the handle is free a read-only
    /// unseal derives the same SRK transiently, opens the envelope, and
    /// persists nothing at the handle.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0 (root), or swtpm via IRLUME_TCTI (CI does this)"]
    fn a_read_only_unseal_uses_a_transient_srk_while_another_key_holds_the_handle() {
        let secret = b"irlume-read-only-foreign-handle";
        let template = policy_bound_srk_template();
        assert!(
            !is_irlume_srk(&template).expect("identity check"),
            "precondition: irlume must not take the fixture for its SRK"
        );
        plant_foreign_key_at_srk_handle(template);
        let sealed = seal_with_pcrs(secret, &[7]);
        let unsealed = sealed.as_ref().ok().map(unseal_read_only);
        let occupant = evict_persistent_srk();
        remove_foreign_key_at_srk_handle();

        let env = sealed.expect("seal under a transient SRK");
        let got = unsealed
            .expect("sealed")
            .expect("a read-only unseal under a transient SRK");
        assert_eq!(&*got, secret);
        assert_eq!(
            occupant.expect("handle probe"),
            SrkEviction::Foreign,
            "the foreign key stays at the handle"
        );

        // With the handle free, a read-only unseal derives the SRK
        // transiently instead of persisting it.
        assert_eq!(
            &*unseal_read_only(&env).expect("a read-only unseal once the handle is free"),
            secret
        );
        assert_eq!(
            evict_persistent_srk().expect("post-unseal probe"),
            SrkEviction::Absent
        );
    }

    /// A Tier 1 envelope an earlier release wrote must keep unsealing, so its
    /// next verified reseal can move it, while the ladder itself never lands
    /// on the signed policy even where the boot chain publishes one.
    #[test]
    #[ignore = "requires a real TPM + fresh systemd signed-PCR artifacts (UKI/systemd-boot); covers Tier-1 PolicyAuthorize"]
    fn seal_unseal_signed_pcr_roundtrip_real_hardware() {
        let secret = b"irlume-keyring-secret-roundtrip!";
        let env = seal_authorized(secret).expect("signed-PCR seal");
        let got = unseal(&env).expect("unseal the signed-PCR envelope");
        assert_eq!(&*got, secret, "signed-PCR round-trip must match");
        let ladder = seal(secret).expect("ladder seal on signed-PCR hardware");
        assert!(
            !matches!(ladder.policy, PolicyKind::Authorized { .. }),
            "the ladder must bind PCR 7 or pcrlock, not PCR 11 alone"
        );
        assert_eq!(&*unseal(&ladder).expect("unseal the ladder seal"), secret);
    }

    /// Only a pcrlock policy covering a firmware-measured PCR is sealed under
    /// or counted as an upgrade: one over PCR 15 alone, as a real machine
    /// here provisioned, binds less than the literal PCR 7 seal.
    #[test]
    fn only_a_firmware_binding_pcrlock_policy_is_used_for_sealing() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::path::PathBuf::from(crate::test_tmp_dir("pcrlock-firmware"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let json = dir.join("pcrlock.json");
        let value = "ab".repeat(32);
        std::env::set_var("IRLUME_PCRLOCK_JSON", &json);
        for (pcrs, used) in [
            (&[15][..], false),
            (&[11, 15], false),
            (&[7], true),
            (&[0, 2, 4, 15], true),
        ] {
            let entries: Vec<String> = pcrs
                .iter()
                .map(|pcr| format!(r#"{{"pcr":{pcr},"values":["{value}"]}}"#))
                .collect();
            std::fs::write(
                &json,
                format!(
                    r#"{{"pcrBank":"sha256","pcrValues":[{}],"nvIndex":27981881}}"#,
                    entries.join(",")
                ),
            )
            .unwrap();
            assert_eq!(pcrlock_provisioned(), Some(27_981_881), "{pcrs:?}");
            assert_eq!(pcrlock_for_sealing().is_some(), used, "{pcrs:?}");
        }
        std::env::remove_var("IRLUME_PCRLOCK_JSON");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Prediction files only; no NV space or TPM operation. Hold ENV_LOCK.
    pub(crate) struct PredictionFixture {
        pub(crate) path: std::path::PathBuf,
        previous: Option<std::ffi::OsString>,
        previous_pcrs: Option<std::ffi::OsString>,
    }

    impl PredictionFixture {
        pub(crate) const NV: u32 = 0x0181_C859;

        pub(crate) fn new() -> Self {
            let path = std::path::PathBuf::from(crate::test_tmp_dir("prediction-859"));
            let previous = std::env::var_os("IRLUME_PCRLOCK_JSON");
            let previous_pcrs = std::env::var_os("IRLUME_PCRS");
            std::env::set_var("IRLUME_PCRLOCK_JSON", &path);
            std::env::set_var("IRLUME_PCRS", "7");
            Self {
                path,
                previous,
                previous_pcrs,
            }
        }

        pub(crate) fn write(&self, pcrs: &[u32]) {
            let entries: Vec<_> = pcrs
                .iter()
                .map(|pcr| serde_json::json!({"pcr": pcr, "values": ["ab".repeat(32)]}))
                .collect();
            std::fs::write(
                &self.path,
                serde_json::to_vec(&serde_json::json!({
                    "pcrBank": "sha256", "pcrValues": entries, "nvIndex": Self::NV
                }))
                .unwrap(),
            )
            .unwrap();
        }

        pub(crate) fn envelope(pcrs: &[u32]) -> SealedEnvelope {
            serde_json::from_value(serde_json::json!({
                "version": 1, "policy": {"kind": "PcrlockNv", "nv_index": Self::NV},
                "pcrs": pcrs, "public": "", "private": ""
            }))
            .unwrap()
        }
    }

    impl Drop for PredictionFixture {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var("IRLUME_PCRLOCK_JSON", value),
                None => std::env::remove_var("IRLUME_PCRLOCK_JSON"),
            }
            match &self.previous_pcrs {
                Some(value) => std::env::set_var("IRLUME_PCRS", value),
                None => std::env::remove_var("IRLUME_PCRS"),
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn reprovisioned_pcrlock_opens_the_upgrade_gate() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let prediction = PredictionFixture::new();
        let old = PredictionFixture::envelope(&[0, 7]);
        prediction.write(&[11, 15]);
        assert!(
            stronger_tier_available_than(&old),
            "current OS-only binding must move to literal PCR 7"
        );
    }

    #[test]
    fn reprovisioned_pcrlock_ranks_both_sides_from_the_same_current_policy() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let prediction = PredictionFixture::new();
        let firmware_record = PredictionFixture::envelope(&[0, 7]);
        let os_record = PredictionFixture::envelope(&[11, 15]);
        let mut literal = PredictionFixture::envelope(&[7]);
        literal.policy = PolicyKind::PcrLiteral;
        for pcrs in [&[7][..], &[0, 7, 15], &[11, 15]] {
            prediction.write(pcrs);
            let firmware = pcrs.contains(&7);
            for old in [&firmware_record, &os_record] {
                assert_eq!(stronger_tier_available_than(old), !firmware);
                assert_eq!(move_gain(&literal, old).is_some(), !firmware);
                assert_eq!(move_gain(old, &literal).is_some(), firmware);
                assert!(move_gain(&firmware_record, old).is_none());
                assert!(move_gain(&os_record, old).is_none());
            }
            assert_eq!(pcrlock_for_sealing().is_some(), firmware);
        }
        // A literal override covering no firmware PCR is not an upgrade from
        // the now OS-only pcrlock binding, and must not start any seal attempt.
        std::env::set_var("IRLUME_PCRS", "11,15");
        literal.pcrs = vec![11, 15];
        assert!(!stronger_tier_available_than(&firmware_record));
        assert!(move_gain(&literal, &firmware_record).is_none());
    }

    /// ADR-0034 §3.3: a move gains a stronger policy, irlume's DA-exempt
    /// storage key under a policy no weaker, or both, and never takes an
    /// envelope off that key, even for a stronger policy.
    #[test]
    fn a_move_gains_the_da_exempt_key_and_never_gives_it_up() {
        let envelope = |pcrs: &[u32], on_key: bool| {
            let mut env: SealedEnvelope = serde_json::from_value(serde_json::json!({
                "version": 1, "pcrs": pcrs, "public": "", "private": ""
            }))
            .unwrap();
            env.parent = on_key.then(|| ParentKey {
                handle: 0x8101_0003,
                name: "000b00".into(),
            });
            env
        };
        // Literal seals: PCR 7 binds the firmware state, no PCR binds nothing.
        let firmware = |on_key| envelope(&[7], on_key);
        let unbound = |on_key| envelope(&[], on_key);
        assert_eq!(
            move_gain(&firmware(true), &firmware(false)),
            Some(MoveGain::DaExemptKey)
        );
        assert_eq!(
            move_gain(&firmware(true), &unbound(false)),
            Some(MoveGain::Both)
        );
        assert_eq!(
            move_gain(&firmware(true), &unbound(true)),
            Some(MoveGain::StrongerPolicy)
        );
        assert_eq!(
            move_gain(&firmware(false), &unbound(false)),
            Some(MoveGain::StrongerPolicy)
        );
        assert_eq!(move_gain(&firmware(true), &firmware(true)), None);
        assert_eq!(move_gain(&firmware(false), &firmware(false)), None);
        assert_eq!(
            move_gain(&unbound(true), &firmware(false)),
            None,
            "a weaker policy is no move, even onto the DA-exempt key"
        );
        assert_eq!(
            move_gain(&firmware(false), &unbound(true)),
            None,
            "never off the DA-exempt key, even for a stronger policy"
        );
    }

    /// Being under the original storage key is a reason to move once
    /// irlumed recorded the DA-exempt key as persisted (ADR-0034 §3.3), read
    /// from the files alone; not for an envelope already on a key, nor for
    /// one whose binding is unknown, nor with a record that names no key.
    #[test]
    fn an_envelope_on_the_original_key_moves_once_the_da_exempt_key_is_recorded() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        // IRLUME_PCRS=7 and no prediction file: nothing stronger than a
        // literal PCR 7 seal is available.
        let prediction = PredictionFixture::new();
        let state = crate::test_tmp_dir("move-available");
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).unwrap();
        let previous = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_STATE_DIR", &state);
        let record = |name: &str| {
            let json = serde_json::json!({
                "version": 1, "persisted": {"handle": 0x8101_0003_u32, "name": name}
            });
            std::fs::write(format!("{state}/tpm-storage-key"), json.to_string()).unwrap();
        };
        let mut original = PredictionFixture::envelope(&[7]);
        original.policy = PolicyKind::PcrLiteral;
        let mut on_key = PredictionFixture::envelope(&[7]);
        on_key.policy = PolicyKind::PcrLiteral;
        on_key.parent = Some(ParentKey {
            handle: 0x8101_0003,
            name: "000b00".into(),
        });
        // Bound to a prediction this host does not have: an unknown rank.
        let unknown = PredictionFixture::envelope(&[7]);
        let available = || {
            [
                move_available(&original),
                move_available(&on_key),
                move_available(&unknown),
            ]
        };

        let without = available();
        record("000b00");
        let with = available();
        record("not hex");
        let not_hex = available();
        match previous {
            Some(value) => std::env::set_var("IRLUME_STATE_DIR", value),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&state);
        drop(prediction);

        assert_eq!(without, [false; 3], "no record, nothing stronger");
        assert_eq!(with, [true, false, false]);
        assert_eq!(not_hex, [false; 3], "a record naming no key is none");
    }

    #[test]
    fn reprovisioned_pcrlock_unknown_binding_never_authorizes_replacement() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let prediction = PredictionFixture::new();
        let mut literal = PredictionFixture::envelope(&[7]);
        literal.policy = PolicyKind::PcrLiteral;
        let refuse = || {
            for recorded in [&[7][..], &[11, 15]] {
                let old = PredictionFixture::envelope(recorded);
                assert!(!stronger_tier_available_than(&old));
                assert!(move_gain(&literal, &old).is_none());
                assert!(move_gain(&old, &literal).is_none());
            }
        };
        prediction.write(&[11, 15]);
        let valid: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&prediction.path).unwrap()).unwrap();
        let mut variants = Vec::new();
        for nv in [
            serde_json::Value::Null,
            serde_json::json!(PredictionFixture::NV + 1),
            serde_json::json!(u64::MAX),
            serde_json::json!(1),
        ] {
            let mut bad = valid.clone();
            bad["nvIndex"] = nv;
            variants.push(bad);
        }
        let mut missing_nv = valid.clone();
        missing_nv.as_object_mut().unwrap().remove("nvIndex");
        variants.push(missing_nv);
        for (field, value) in [
            ("pcrBank", serde_json::json!("sha1")),
            ("pcrValues", serde_json::json!([])),
            ("pcrValues", serde_json::json!([{"pcr": 11, "values": []}])),
            (
                "pcrValues",
                serde_json::json!([{"pcr": 24, "values": ["ab".repeat(32)]}]),
            ),
            (
                "pcrValues",
                serde_json::json!([{"pcr": 11, "values": ["zz".repeat(32)]}]),
            ),
            (
                "pcrValues",
                serde_json::json!([{"pcr": 11, "values": ["aa"]}]),
            ),
            (
                "pcrValues",
                serde_json::json!([{"pcr": 11, "values": vec!["ab".repeat(32); 9]}]),
            ),
            (
                "pcrValues",
                serde_json::json!([
                    {"pcr": 11, "values": ["ab".repeat(32)]},
                    {"pcr": 11, "values": ["cd".repeat(32)]}
                ]),
            ),
        ] {
            let mut bad = valid.clone();
            bad[field] = value;
            variants.push(bad);
        }
        for bad in variants {
            std::fs::write(&prediction.path, serde_json::to_vec(&bad).unwrap()).unwrap();
            refuse();
        }
        std::fs::write(&prediction.path, b"{broken").unwrap();
        refuse();
        std::fs::remove_file(&prediction.path).unwrap();
        refuse();
        std::fs::create_dir(&prediction.path).unwrap();
        refuse();
        std::fs::remove_dir(&prediction.path).unwrap();
    }

    /// The upgrade predicate: a signed envelope, or a literal one over no
    /// firmware-measured PCR, has a stronger policy to move to when pcrlock
    /// is provisioned or the configured literal PCRs bind firmware state (the
    /// default PCR 7 does); a literal PCR 7 one only once pcrlock is
    /// provisioned; a pcrlock one never, whatever the boot chain publishes.
    #[test]
    fn upgrades_move_toward_bound_policies_only() {
        let signed = PolicyKind::Authorized {
            pubkey_pem: String::new(),
            policy_ref: Vec::new(),
        }
        .strength_rank();
        let pcrlock = PolicyKind::PcrlockNv { nv_index: 1 }.strength_rank();
        let literal = PolicyKind::PcrLiteral.strength_rank();
        let unbound = 0;
        for provisioned in [false, true] {
            for firmware in [false, true] {
                for weak in [signed, unbound] {
                    assert_eq!(
                        stronger_tier_than(weak, || provisioned, || firmware),
                        provisioned || firmware
                    );
                }
                assert!(!stronger_tier_than(pcrlock, || provisioned, || firmware));
                assert_eq!(
                    stronger_tier_than(literal, || provisioned, || firmware),
                    provisioned
                );
            }
        }
    }

    /// A synthetic systemd-pcrlock policy, provisioned for the guard's lifetime.
    ///
    /// Extracted from `seal_unseal_pcrlock_roundtrip_provisioned_nv`, which built
    /// this inline, so the tier-climb tests can establish the precondition they
    /// were missing: `stronger_tier_available_than(PcrLiteral)` needs
    /// `pcrlock_provisioned()`, and on a bare swtpm that does not hold, so
    /// those tests asserted a climb that could not happen (#361).
    ///
    /// What this IS: a real owner-hierarchy NV space holding the alg-tagged
    /// policy digest of the live PCR state, laid out the way
    /// `systemd-pcrlock make-policy` writes it, plus a matching prediction JSON.
    /// A seal against it runs a genuine `PolicyAuthorizeNV` session and a real
    /// TPM round trip.
    ///
    /// What it is NOT: real systemd provisioning. It does not exercise
    /// `make-policy`, protected NV updates, event-log prediction, real firmware
    /// PCR movement, or Tier-1 signed-PCR behaviour. Those stay hardware work.
    ///
    /// Drop undefines the NV space and clears the override, so an assertion
    /// failure mid-test does not leave the index or the env var behind for the
    /// next one.
    pub(crate) struct PcrlockFixture {
        nv_index: u32,
        dir: std::path::PathBuf,
    }

    impl PcrlockFixture {
        /// Provision `nv_index` against the live PCR 7. The caller must hold
        /// `ENV_LOCK`: this sets a process-global override.
        pub(crate) fn provision(nv_index: u32) -> Self {
            use tss_esapi::attributes::NvIndexAttributes;
            use tss_esapi::structures::{MaxNvBuffer, NvPublic};

            let mut ctx = open_context().expect("tpm context");
            let pcr7 = read_pcr_values(&mut ctx, &[7])
                .expect("read pcr7")
                .remove(0);
            assert_eq!(pcr7.value.len(), 32, "sha256 bank expected");
            let hex: String = pcr7.value.iter().map(|b| format!("{b:02x}")).collect();

            let dir = std::env::temp_dir().join(format!(
                "irlume-pcrlock-{}-{nv_index:08x}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let json_path = dir.join("pcrlock.json");
            std::fs::write(
                &json_path,
                format!(
                    r#"{{"pcrBank":"sha256","pcrValues":[{{"pcr":7,"values":["{hex}"]}}],"nvIndex":{nv_index}}}"#
                ),
            )
            .unwrap();
            std::env::set_var("IRLUME_PCRLOCK_JSON", &json_path);

            // A leftover index from an aborted run has a different name lineage;
            // drop it before defining ours.
            let nv_handle_t = NvIndexTpmHandle::new(nv_index).unwrap();
            if let Ok(obj) = ctx.tr_from_tpm_public(TpmHandle::NvIndex(nv_handle_t)) {
                let _ = ctx.execute_with_nullauth_session(|ctx| {
                    ctx.nv_undefine_space(Provision::Owner, NvIndexHandle::from(obj))
                });
            }

            // Owner-hierarchy NV space, owner read/write, 34 bytes: a 2-byte
            // hash alg id plus the sha256 policy digest, systemd-pcrlock's
            // layout.
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

            // The digest a session holds after PolicyPCR(sel=[7], composite):
            // what the live unseal session presents when PolicyAuthorizeNV
            // compares it against the NV content.
            let composite: [u8; 32] = Sha256::digest(&pcr7.value).into();
            let policy_digest = with_session(&mut ctx, None, SessionType::Trial, |ctx, session| {
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

            Self { nv_index, dir }
        }

        /// Rewrite this fixture's existing NV index without changing its Name,
        /// then publish the matching prediction, as make-policy does. Test-only
        /// owner writes; this does not simulate systemd's protected NV update.
        pub(crate) fn reprovision(&self, pcrs: &[u32]) {
            use tss_esapi::structures::MaxNvBuffer;
            let mut ctx = open_context().unwrap();
            let values = read_pcr_values(&mut ctx, pcrs).unwrap();
            let digest = literal_auth_policy(&values).unwrap();
            let nv = nv_index_handle(&mut ctx, self.nv_index).unwrap();
            let mut content = vec![0x00, 0x0b];
            content.extend_from_slice(digest.value());
            ctx.execute_with_nullauth_session(|ctx| {
                ctx.nv_write(
                    NvAuth::Owner,
                    nv,
                    MaxNvBuffer::try_from(content).unwrap(),
                    0,
                )
            })
            .unwrap();
            let entries: Vec<_> = values
                .iter()
                .map(|v| {
                    let hex: String = v.value.iter().map(|b| format!("{b:02x}")).collect();
                    serde_json::json!({"pcr": v.pcr, "values": [hex]})
                })
                .collect();
            std::fs::write(
                self.dir.join("pcrlock.json"),
                serde_json::to_vec(&serde_json::json!({
                    "pcrBank": "sha256", "pcrValues": entries, "nvIndex": self.nv_index
                }))
                .unwrap(),
            )
            .unwrap();
        }
    }

    impl Drop for PcrlockFixture {
        fn drop(&mut self) {
            if let Ok(mut ctx) = open_context() {
                if let Ok(nv) = nv_index_handle(&mut ctx, self.nv_index) {
                    let _ = ctx.execute_with_nullauth_session(|ctx| {
                        ctx.nv_undefine_space(Provision::Owner, nv)
                    });
                }
            }
            std::env::remove_var("IRLUME_PCRLOCK_JSON");
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Tier-2 pcrlock seal/unseal without systemd-pcrlock: the test provisions
    /// the NV index the way `systemd-pcrlock make-policy` does (owner-hierarchy
    /// NV space holding the alg-tagged policy digest of the predicted PCR
    /// state) and points IRLUME_PCRLOCK_JSON at a matching prediction. Runs
    /// against any TPM; CI uses swtpm. Also proves the drift case: a rewritten
    /// policy that no longer matches the live PCRs refuses the unseal.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0 (root), or swtpm via IRLUME_TCTI (CI does this)"]
    fn seal_unseal_pcrlock_roundtrip_provisioned_nv() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        const NV_INDEX: u32 = 0x0181_C0DE;
        let secret = b"irlume-pcrlock-roundtrip-secret!";

        // Provisioning moved into PcrlockFixture so the tier-climb tests can
        // establish the same precondition; using it here is what keeps the two
        // honest, since a fixture only this test's twin exercised would drift.
        let fixture = PcrlockFixture::provision(NV_INDEX);

        // Round trip through the public Tier-2 entry points.
        let env = seal_with_pcrlock(secret, NV_INDEX).expect("pcrlock seal");
        assert!(matches!(env.policy, PolicyKind::PcrlockNv { .. }));
        let got = unseal(&env).expect("pcrlock unseal");
        assert_eq!(&*got, secret, "round-trip must match");

        // A healthy current binding does not churn. Reprovisioning the SAME
        // NV index to OS PCRs preserves unseal but changes the upgrade rank.
        assert!(!stronger_tier_available_than(&env));
        fixture.reprovision(&[11, 15]);
        assert_eq!(
            &*unseal(&env).expect("old envelope after reprovision"),
            secret
        );
        assert_eq!(env.pcrs, [7], "recorded PCRs did not change");
        assert!(stronger_tier_available_than(&env));
        let replacement = seal(secret).unwrap();
        assert_eq!(replacement.policy, PolicyKind::PcrLiteral);
        assert!(move_gain(&replacement, &env).is_some());
        assert_eq!(&*unseal(&replacement).unwrap(), secret);

        // Drift: rewrite the NV policy to one the live PCRs cannot satisfy
        // (what a firmware change looks like) and the unseal must refuse.
        use tss_esapi::structures::MaxNvBuffer;
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

        // Cleanup is the fixture's Drop, which also runs if an assertion above
        // fails; the hand-rolled version here did not.
        drop(fixture);
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
    #[ignore = "needs a TPM; CI runs it by name on swtpm and on the real chip \
                (IRLUME_TCTI), and scripts/with-swtpm.sh runs it anywhere"]
    fn software_digests_match_a_trial_session() {
        // FAILS rather than skips when the TPM is out of reach. This is the only
        // thing standing behind replacing a TPM computation with arithmetic, and
        // a test that reports success without observing the hardware it is named
        // for is worse than no test: it is already `#[ignore]`, so anyone running
        // it has asked for hardware.
        let mut ctx = open_context().unwrap_or_else(|e| {
            panic!(
                "this test exists to compare software digests against a TPM, and \
                 no TPM context could be opened ({e}). Run it with a TPM in reach \
                 (scripts/with-swtpm.sh, or IRLUME_TCTI); do not treat this as a skip."
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
    /// (provisioned, covering a firmware-measured PCR, AND a direct pcrlock
    /// seal round-trips), the ladder must land on Tier 2, whether or not a
    /// signed policy exists; over OS-measured PCRs only it must not. When pcrlock is
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
        let binds_firmware = pcrlock_for_sealing().is_some();
        if pcrlock_usable && binds_firmware {
            assert!(
                landed_pcrlock,
                "usable pcrlock: seal() must pick Tier 2, got {:?}",
                env.policy
            );
        }
        if !binds_firmware {
            assert!(
                !landed_pcrlock,
                "a pcrlock policy over no firmware-measured PCR must not be sealed under"
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
