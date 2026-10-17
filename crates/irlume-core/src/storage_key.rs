// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! irlume's DA-exempt storage key at irlumed's start (ADR-0034 §3.2): find
//! it, or derive and persist it, and record what happened. A refusal is
//! recorded with the boot ID, so a daemon restart in the same boot derives
//! nothing, unless the refusal was for lack of room and the TPM now reports
//! room (#1083).
//!
//! New seals go under the key once it is persisted, and each envelope records
//! it as its parent (`crate::tpm`, ADR-0034 §3.3); envelopes sealed before
//! move onto it at their move points. The key costs one owner persistent
//! handle, and uninstall evicts it (`tpm::evict_da_exempt_srks`).

use crate::{keyring, template_key, tpm};
use irlume_common::tpm_readiness::{
    DaExemptKey, EnvelopeKind, KeyRefusal, OriginalKey, OriginalKeyEnvelope, OriginalKeyEnvelopes,
    RefusalReason, RetirementWait, MAX_NAMED_ENVELOPES,
};
use irlume_common::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The version written into new records.
const RECORD_VERSION: u32 = 1;

/// The largest record read, in bytes: one is a few hundred, and the state
/// directory is untrusted where it is writable offline (ADR-0034 §5).
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// The longest refusal detail recorded or reported, in characters.
const MAX_DETAIL_CHARS: usize = 300;

/// The most superseded keys a record keeps or a start probes. A replacement
/// adds one, so a few are plenty; the state directory is untrusted where it
/// is writable offline (ADR-0034 §5), and each kept key costs TPM commands
/// at a start.
const MAX_SUPERSEDED: usize = 4;

/// How many taken handles a persist steps past before it gives up. Each
/// `TPM_RC_NV_DEFINED` means another stack took the handle between the scan
/// and the command, which systemd's `tpm2_persist_handle` also answers by
/// trying the next handle.
const PERSIST_ATTEMPTS: usize = 8;

/// irlumed's record of the key, root-only at `state_dir()/tpm-storage-key`.
/// It is not a `*.json` file directly in the state directory, which
/// `storage::list_users` reads as an account. The state directory is
/// untrusted where it is writable offline (ADR-0034 §5), so a start trusts a
/// recorded handle only while the key there has the recorded TPM name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Record {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    persisted: Option<Persisted>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refused: Option<Refused>,
    /// irlume's original storage key as a start last checked it (ADR-0034
    /// §3.4). Advisory: it lives in the state directory, so it never by
    /// itself authorizes evicting a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original: Option<Original>,
    /// The boot of the start whose census last found no envelope under the
    /// original storage key, with none found since (ADR-0034, Phase 3
    /// amendment, condition 1). Cleared before a move off the key publishes,
    /// and by a start whose census finds an envelope under it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unused_since: Option<String>,
    /// One entry per envelope whose move off the original key is not yet
    /// shown durable, with the boot of that move (condition 1). A census in
    /// that boot marks nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    moves: Vec<UnsettledMove>,
    /// The last retirement of the original key that was attempted and did
    /// not succeed (its proof or its eviction failed, or it stopped part
    /// way), with its boot: tried again only at the first start in a later
    /// boot, so a restart in the same boot pays no derivation (condition 2).
    /// Written before the proof's derivation, so it stands even when the
    /// write of the outcome fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retirement_attempt: Option<RetirementAttempt>,
    /// The DA-exempt keys the recorded one superseded, still persisted when
    /// they were (#1073 item 2): a weak key a replacement superseded, or a
    /// key the start-up step found away from its recorded handle and
    /// replaced with today's derivation. Kept so envelopes that still name
    /// one move off it, and so it can be reported once none does. irlume
    /// never evicts one: no derivation gives it now.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    superseded: Vec<Persisted>,
    /// For each superseded key (by TPM name in hex), the boot of the start
    /// whose census first found no envelope naming it, with none found since
    /// (as condition 1 keeps for the original key): doctor names the manual
    /// command for a weak superseded key only once this names another boot.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    superseded_unused: std::collections::BTreeMap<String, String>,
    /// The firmware version (`TPM_PT_FIRMWARE_VERSION_1` and `_2`) on which
    /// today's derivation of the DA-exempt template was weak too: no start
    /// derives for the weak key again until the TPM reads another version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    weak_derivation: Option<WeakDerivation>,
    /// Why the last replacement of a weak DA-exempt key could not be
    /// persisted, with the boot, retried by the rules of section 3.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replacement_refused: Option<Refused>,
}

/// Today's derivation of the DA-exempt template was weak on this firmware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WeakDerivation {
    firmware: [u32; 2],
}

/// A retirement of the original key that was attempted: its boot, and the
/// error once it failed (`None` while it ran, or if it stopped part way).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RetirementAttempt {
    /// `None` when the boot ID could not be read, which may be another boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure: Option<String>,
}

/// An envelope whose move off the original storage key was not yet shown
/// durable: its account and kind, and the boot of the move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UnsettledMove {
    user: String,
    kind: EnvelopeKind,
    /// `None` when the boot ID could not be read, which may be any boot, so
    /// the entry is never dropped as another boot's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_id: Option<String>,
}

/// The key at the original key's handle, by its TPM name, and whether today's
/// derivation of the original template gave the same key when a start
/// checked it. Only a matching key counts as recorded (ADR-0034 §3.4: "an old
/// key that no longer matches when Phase 2 first runs is not recorded");
/// one that does not match is kept too, so that no later start derives again
/// for the same key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Original {
    handle: u32,
    /// The key's TPM name in hex.
    name: String,
    matched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Persisted {
    handle: u32,
    /// The key's TPM name in hex: its name algorithm and the hash of its whole
    /// public area, so the same name is the same key.
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Refused {
    reason: RefusalReason,
    detail: String,
    /// The boot it happened in, or `None` when the boot ID could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_id: Option<String>,
}

/// Where the key goes: the preferred handle, next to the original key's, and
/// the original key's handle, which the new key never takes (both keys exist
/// while envelopes move).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) preferred: u32,
    pub(crate) original: u32,
}

/// A TPM command's failure, classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    pub(crate) class: FailureClass,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureClass {
    /// `TPM_RC_NV_SPACE`.
    NoSpace,
    /// `TPM_RC_NV_DEFINED`: the handle is taken.
    Taken,
    /// `TPM_RC_BAD_AUTH` or `TPM_RC_AUTH_FAIL`: an owner authorization is set.
    OwnerAuthorization,
    Other,
}

/// The TPM operations the start-up step needs, so that a fake can drive it.
pub(crate) trait KeyTpm {
    /// The TPM name of the persistent object at `handle`, or `None` when the
    /// handle is free.
    fn name_at(&mut self, handle: u32) -> Result<Option<Vec<u8>>>;
    /// `TPM_PT_HR_PERSISTENT_AVAIL`.
    fn persistent_avail(&mut self) -> Result<u32>;
    /// Derive the DA-exempt key as a transient object, kept for
    /// [`KeyTpm::persist`], and return its TPM name.
    fn derive(&mut self) -> std::result::Result<Vec<u8>, Failure>;
    /// Every owner persistent handle in use, with its object's TPM name.
    fn owner_names(&mut self) -> Result<Vec<(u32, Vec<u8>)>>;
    /// Make the derived key persistent at `handle`.
    fn persist(&mut self, handle: u32) -> std::result::Result<(), Failure>;
    /// Whether the persistent key at `handle` is the key irlume's original
    /// template derives today, by modulus, as uninstall compares it; `None`
    /// when the handle is free or the key there does not have the original
    /// template's shape, and then nothing is derived.
    fn derives_original(&mut self, handle: u32) -> Result<Option<bool>>;
    /// Evict the persistent key at `handle` when its TPM name is `name`;
    /// `false`, evicting nothing, when the handle is free or holds another
    /// key.
    fn evict(&mut self, handle: u32, name: &[u8]) -> Result<bool>;
    /// Whether the persistent key at `handle` has the TPM name `name` and
    /// the DA-exempt template's shape, as a seal requires of the key it
    /// seals under.
    fn holds_da_exempt_key(&mut self, handle: u32, name: &[u8]) -> Result<bool>;
    /// Whether the persistent key at `handle` carries the ROCA fingerprint
    /// (CVE-2017-15361); `false` for a free handle.
    fn is_weak(&mut self, handle: u32) -> Result<bool>;
    /// Whether the key [`KeyTpm::derive`] derived carries the ROCA
    /// fingerprint.
    fn derived_is_weak(&mut self) -> Result<bool>;
    /// `TPM_PT_FIRMWARE_VERSION_1` and `_2`, which `GetCapability` reads
    /// with no derivation.
    fn firmware(&mut self) -> Result<[u32; 2]>;
}

/// The [`KeyTpm`] for a refused override, which [`ensure_with`] records
/// before any TPM call; every call is refused, so none can reach a TPM.
struct Unopened;

impl KeyTpm for Unopened {
    fn name_at(&mut self, _: u32) -> Result<Option<Vec<u8>>> {
        Err(unopened())
    }
    fn persistent_avail(&mut self) -> Result<u32> {
        Err(unopened())
    }
    fn derive(&mut self) -> std::result::Result<Vec<u8>, Failure> {
        Err(unopened_failure())
    }
    fn owner_names(&mut self) -> Result<Vec<(u32, Vec<u8>)>> {
        Err(unopened())
    }
    fn persist(&mut self, _: u32) -> std::result::Result<(), Failure> {
        Err(unopened_failure())
    }
    fn derives_original(&mut self, _: u32) -> Result<Option<bool>> {
        Err(unopened())
    }
    fn evict(&mut self, _: u32, _: &[u8]) -> Result<bool> {
        Err(unopened())
    }
    fn holds_da_exempt_key(&mut self, _: u32, _: &[u8]) -> Result<bool> {
        Err(unopened())
    }
    fn is_weak(&mut self, _: u32) -> Result<bool> {
        Err(unopened())
    }
    fn derived_is_weak(&mut self) -> Result<bool> {
        Err(unopened())
    }
    fn firmware(&mut self) -> Result<[u32; 2]> {
        Err(unopened())
    }
}

fn unopened() -> Error {
    Error::Tpm("no TPM is opened for a refused IRLUME_SRK_HANDLE".into())
}

fn unopened_failure() -> Failure {
    Failure {
        class: FailureClass::Other,
        detail: unopened().to_string(),
    }
}

/// What the start-up step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The recorded key is at its handle. Nothing was derived.
    Present { handle: u32 },
    /// A copy persisted by an earlier start that stopped before writing its
    /// record was found by its name and recorded. Nothing new was persisted.
    Adopted { handle: u32 },
    /// Derived and persisted now.
    Persisted { handle: u32 },
    /// The recorded key was away from its recorded handle and was found by
    /// its TPM name at `handle`, where it is now recorded. Nothing was
    /// derived.
    Found { handle: u32 },
    /// Refused now, and recorded with the boot.
    Refused(KeyRefusal),
    /// A refusal earlier in this boot stands. Nothing was derived.
    Deferred(KeyRefusal),
    /// The recorded key at `from` carries the ROCA fingerprint and today's
    /// derivation of its template does not (ADR-0034, Phase 3 amendment,
    /// #1073 item 2): the derivation was adopted or persisted at `handle`
    /// and recorded as the DA-exempt key, and the weak key is kept in the
    /// record as superseded. Its envelopes move at their move points.
    Replaced { handle: u32, from: u32 },
    /// The recorded key at `handle` is weak and so is today's derivation,
    /// on firmware that still generates affected keys: nothing is replaced,
    /// and the firmware version is recorded.
    DerivationWeak { handle: u32 },
    /// The recorded key at `handle` is weak, and today's derivation was
    /// weak too on the same firmware version: nothing was derived.
    WeakKept { handle: u32 },
    /// The weak key at `from` could not be replaced: the refusal is
    /// recorded with the boot, and the weak key stays in use.
    ReplacementRefused { from: u32, refusal: KeyRefusal },
    /// A refused replacement earlier in this boot stands. Nothing was
    /// derived.
    ReplacementDeferred { from: u32, refusal: KeyRefusal },
}

/// irlumed's start-up step (ADR-0034 §3.2). It runs while any envelope
/// exists: those on the original key need the DA-exempt key persisted for
/// their move, and those on it need it still there. With none it returns
/// `None` and derives or persists no DA-exempt key, and a refusal recorded
/// earlier is cleared, since no envelope is left for it to concern.
///
/// Either way it keeps the record of the original key (§3.4, `original_with`):
/// that key can outlive the last envelope, and its name must be recorded
/// before a firmware update can change its derivation. The check is
/// advisory, so a TPM that cannot be opened or read changes nothing there.
///
/// The key is derived at most once, and only when the recorded key is not at
/// its handle and no refusal earlier in this boot stands. A copy already
/// persisted is adopted by its TPM name, so a power loss between
/// `TPM2_EvictControl` and the record never leaves a second copy, and neither
/// does a start that overlaps this one and persists the key first. Otherwise
/// the key is persisted at the first free owner handle from the preferred one
/// whatever `TPM_PT_HR_PERSISTENT_AVAIL` says, since a 0 there is an estimate
/// that promises nothing (Part 2 table 28).
///
/// # Errors
///
/// When an envelope directory cannot be read, the TPM cannot be opened or
/// read, or the record cannot be written. A key persisted before a failed
/// write is adopted at the next start.
pub fn ensure_at_start() -> Result<Option<Outcome>> {
    ensure_at_start_reporting().map(|(outcome, _)| outcome)
}

/// [`ensure_at_start`], and whether this start derived an RSA-2048 key: the
/// DA-exempt key, or the original key for its record. [`settle_at_start`]
/// derives nothing in a start that did (ADR-0034, Phase 3 amendment,
/// condition 2). A check of the original key that fails counts as one.
///
/// # Errors
///
/// As [`ensure_at_start`].
pub fn ensure_at_start_reporting() -> Result<(Option<Outcome>, bool)> {
    let envelope = any_envelope()?;
    // One transaction: two starts that overlap (a direct start beside the
    // service) would each read, decide and write the record, and a refusal
    // one of them recorded last would replace the key the other persisted.
    // Under the lock the second start reads the first one's record.
    let _lock = RecordLock::acquire()?;
    let record = load_record();
    let plan = tpm::da_exempt_key_plan();
    if !envelope {
        // This start derives nothing else, so it may check the original key.
        let (original, derived) = match &plan {
            Ok(chosen) => checked_original(
                tpm::DaExemptKeyTpm::open().and_then(|mut tpm| {
                    original_with(&mut tpm, chosen.original, record.original.clone(), false)
                }),
                &record,
            ),
            Err(_) => (record.original.clone(), false),
        };
        // Written only when it changes, so a host with nothing to record
        // gets no record file.
        // A refused replacement goes with the refusal: with no envelope left
        // it concerns nothing, and a new envelope gets a fresh try.
        if record.refused.is_some()
            || record.replacement_refused.is_some()
            || original != record.original
        {
            save_record(&Record {
                refused: None,
                replacement_refused: None,
                version: RECORD_VERSION,
                original,
                ..record
            })?;
        }
        return Ok((None, derived));
    }
    let boot = irlume_common::boot_id();
    // A refused override needs no TPM, so a transport that cannot be opened
    // does not hide it: `ensure_with` records it before any TPM call.
    let next = match &plan {
        Ok(chosen) => {
            let mut tpm = tpm::DaExemptKeyTpm::open()?;
            // `ensure_with` decides the DA-exempt key's part of the record;
            // the original key's part is decided here.
            let (mut next, mut outcome) =
                ensure_keeping_use(&mut tpm, &record, boot.as_deref(), &plan)?;
            keep_superseded(&mut tpm, &record, &mut next)?;
            // A weak key found at its handle is replaced by moving its
            // envelopes first (ADR-0034, Phase 3 amendment, #1073 item 2).
            if matches!(outcome, Outcome::Present { .. } | Outcome::Found { .. }) {
                if let Some((replaced, replacement)) =
                    replace_weak_with(&mut tpm, &next, boot.as_deref(), *chosen)?
                {
                    next = replaced;
                    outcome = replacement;
                }
            }
            // Advisory, so a failure to check costs nothing but a later try.
            let (original, derived_original) = checked_original(
                original_with(
                    &mut tpm,
                    chosen.original,
                    record.original.clone(),
                    derived_now(&outcome),
                ),
                &record,
            );
            next.original = original;
            let derived = derived_now(&outcome) || derived_original;
            (next, outcome, derived)
        }
        Err(_) => {
            let (mut next, outcome) =
                ensure_keeping_use(&mut Unopened, &record, boot.as_deref(), &plan)?;
            next.original = record.original.clone();
            (next, outcome, false)
        }
    };
    let (next, outcome, derived) = next;
    if next != record {
        save_record(&next)?;
    }
    Ok((Some(outcome), derived))
}

/// The original key's entry after [`original_with`]'s `checked` answer,
/// and whether that check derived the original key: it did when the entry
/// changed (a check that derives nothing returns the recorded entry), and a
/// check that failed counts as one, since it may have failed part way.
fn checked_original(
    checked: Result<Option<Original>>,
    record: &Record,
) -> (Option<Original>, bool) {
    match checked {
        Ok(original) => {
            let derived = original != record.original;
            (original, derived)
        }
        Err(_) => (record.original.clone(), true),
    }
}

/// What `irlume doctor` reports (ADR-0034 §4): the record, with the recorded
/// handle kept only while the key there has the recorded name, a recorded
/// refusal only while any envelope exists, the envelopes still under the
/// original storage key (`on_original_key`), and that key's retirement
/// (`original_key_state`, the Phase 3 amendment).
///
/// # Errors
///
/// When an envelope directory cannot be read, or the record names a key and
/// the TPM cannot be opened or read.
pub fn report() -> Result<DaExemptKey> {
    let mut record = load_record();
    let any_envelope = any_envelope()?;
    // With no envelope left a refusal concerns nothing, and irlumed's next
    // start clears it: a refused replacement goes with the refused persist.
    if !any_envelope {
        record.refused = None;
        record.replacement_refused = None;
    }
    let mut tpm = match (&record.persisted, &record.original) {
        (None, None) => None,
        _ => Some(tpm::DaExemptKeyTpm::open()?),
    };
    let handle = match (&record.persisted, tpm.as_mut()) {
        (Some(persisted), Some(tpm)) => {
            let name = tpm_name_hex(tpm, persisted.handle)?;
            (name.as_deref() == Some(persisted.name.as_str())).then_some(persisted.handle)
        }
        _ => None,
    };
    let original_key = match tpm.as_mut() {
        Some(tpm) => original_key_state(
            tpm,
            &record,
            any_under_original_key()?,
            tpm::da_exempt_key_plan().ok().map(|plan| plan.original),
            irlume_common::boot_id().as_deref(),
        )?,
        None => OriginalKey::NotRecorded,
    };
    Ok(DaExemptKey {
        handle,
        refused: record.refused.map(|refused| KeyRefusal {
            reason: refused.reason,
            // The record is in the state directory, which is untrusted where
            // it is writable offline (ADR-0034 §5): what it says goes out as
            // one bounded line with no control characters.
            detail: irlume_common::single_line(&refused.detail, MAX_DETAIL_CHARS),
        }),
        on_original_key: Some(on_original_key()?),
        original_key: Some(original_key),
        derivation_weak: record.weak_derivation.is_some(),
        replacement_refused: record.replacement_refused.map(|refused| KeyRefusal {
            reason: refused.reason,
            detail: irlume_common::single_line(&refused.detail, MAX_DETAIL_CHARS),
        }),
        any_envelope,
    })
}

/// The longest TPM name, in hex, a report carries: a SHA-512 name is 66
/// bytes, so 132 characters.
const MAX_NAME_HEX: usize = 160;

/// irlume's original storage key as `record` and `tpm` show it, for doctor:
/// retired, or what its retirement at irlumed's start waits for, in the
/// order irlumed's start checks it ([`settle_at_start`]). `in_use` is the
/// census (an envelope under the key, or one that cannot be read),
/// `original_handle` the original key's handle today (`None` for a refused
/// `IRLUME_SRK_HANDLE`), and `boot` this boot.
fn original_key_state(
    tpm: &mut impl KeyTpm,
    record: &Record,
    in_use: bool,
    original_handle: Option<u32>,
    boot: Option<&str>,
) -> Result<OriginalKey> {
    let Some(original) = &record.original else {
        return Ok(OriginalKey::NotRecorded);
    };
    let handle = original.handle;
    // The record is untrusted where it is writable offline (§5): only a
    // bounded hex name goes out.
    let name = if original.name.len() <= MAX_NAME_HEX
        && original.name.bytes().all(|b| b.is_ascii_hexdigit())
    {
        original.name.clone()
    } else {
        String::new()
    };
    let waiting = |wait| OriginalKey::Waiting {
        handle,
        name: name.clone(),
        wait,
    };
    if original_handle != Some(handle) {
        return Ok(waiting(RetirementWait::HandleChanged {
            configured: original_handle,
        }));
    }
    let Some(at_handle) = tpm.name_at(handle)? else {
        return Ok(OriginalKey::Retired { handle });
    };
    if unhex(&original.name).as_deref() != Some(at_handle.as_slice()) {
        return Ok(waiting(RetirementWait::Unchecked));
    }
    if !original.matched {
        return Ok(waiting(RetirementWait::NotReproduced { in_use }));
    }
    if in_use {
        return Ok(waiting(RetirementWait::Envelopes));
    }
    if let Some(attempt) = &record.retirement_attempt {
        let detail = attempt.failure.as_deref().map_or_else(
            || "the attempt did not finish".to_owned(),
            |failure| irlume_common::single_line(failure, MAX_DETAIL_CHARS),
        );
        let in_this_boot = boot.is_some() && attempt.boot_id.as_deref() == boot;
        return Ok(waiting(RetirementWait::Failed {
            detail,
            in_this_boot,
        }));
    }
    let usable = match &record.persisted {
        Some(persisted) => match unhex(&persisted.name) {
            Some(da_exempt) => tpm.holds_da_exempt_key(persisted.handle, &da_exempt)?,
            None => false,
        },
        None => false,
    };
    if !usable {
        return Ok(waiting(RetirementWait::DaExemptKey));
    }
    // The moves a census in this boot waits for, as `mark_with` reads them.
    let unsettled: Vec<&UnsettledMove> = record
        .moves
        .iter()
        .filter(|entry| match (boot, entry.boot_id.as_deref()) {
            (Some(now), Some(then)) => now == then,
            _ => true,
        })
        .collect();
    if !unsettled.is_empty() {
        // Every entry counts in the total, named or not.
        let total = u32::try_from(unsettled.len()).unwrap_or(u32::MAX);
        let mut envelopes: Vec<OriginalKeyEnvelope> = unsettled
            .into_iter()
            .filter(|entry| is_account_name(&entry.user))
            .map(|entry| OriginalKeyEnvelope {
                user: entry.user.clone(),
                kind: entry.kind,
            })
            .collect();
        envelopes.sort();
        envelopes.truncate(MAX_NAMED_ENVELOPES);
        return Ok(waiting(RetirementWait::UnsettledMoves { envelopes, total }));
    }
    Ok(waiting(match (record.unused_since.as_deref(), boot) {
        (None, _) => RetirementWait::Count,
        (Some(since), Some(now)) if since != now => RetirementWait::NextStart,
        // Marked in this boot, or this boot cannot be read, which is no
        // other boot.
        (Some(_), _) => RetirementWait::LaterBoot,
    }))
}

/// The envelopes (sealed template keys and keyring secrets) that record no
/// parent, and so are under the original storage key, which a TPM lockout
/// blocks (ADR-0034 §4). The file names come from the state directory, which
/// is untrusted where it is writable offline (§5): only a file named for an
/// account name irlumed accepts is named, at most [`MAX_NAMED_ENVELOPES`], and
/// every one counts in the total. An envelope that cannot be parsed is not
/// counted: it is under no key this census can tell.
pub(crate) fn on_original_key() -> Result<OriginalKeyEnvelopes> {
    let mut named = Vec::new();
    let mut total = 0u32;
    for (dir, kind) in [
        (template_key::key_dir(), EnvelopeKind::TemplateKey),
        (keyring::keyring_dir(), EnvelopeKind::KeyringSecret),
    ] {
        for path in envelope_paths(&dir)? {
            let on_original = crate::envelope::SealedEnvelope::load(&path)
                .is_ok_and(|envelope| envelope.parent.is_none());
            if !on_original {
                continue;
            }
            total = total.saturating_add(1);
            let user = path.file_stem().and_then(|stem| stem.to_str());
            if let Some(user) = user.filter(|user| is_account_name(user)) {
                named.push(OriginalKeyEnvelope {
                    user: user.to_owned(),
                    kind,
                });
            }
        }
    }
    named.sort();
    named.truncate(MAX_NAMED_ENVELOPES);
    Ok(OriginalKeyEnvelopes { named, total })
}

/// [`ensure_with`], keeping `record`'s account of the original key's use
/// (`unused_since`, the unsettled moves and a retirement attempt) in the
/// record it builds for the DA-exempt key.
fn ensure_keeping_use(
    tpm: &mut impl KeyTpm,
    record: &Record,
    boot: Option<&str>,
    plan: &std::result::Result<Plan, String>,
) -> Result<(Record, Outcome)> {
    let (mut next, outcome) = ensure_with(tpm, record, boot, plan)?;
    next.unused_since.clone_from(&record.unused_since);
    next.moves.clone_from(&record.moves);
    next.retirement_attempt
        .clone_from(&record.retirement_attempt);
    // A key persisted again keeps the weak key it superseded, and today's
    // derivation is the one the recorded firmware gave.
    next.superseded.clone_from(&record.superseded);
    next.superseded_unused.clone_from(&record.superseded_unused);
    next.weak_derivation.clone_from(&record.weak_derivation);
    if matches!(outcome, Outcome::Present { .. } | Outcome::Found { .. }) {
        next.replacement_refused
            .clone_from(&record.replacement_refused);
    }
    Ok((next, outcome))
}

/// Publish `next` as `user`'s envelope of `kind` at `path`, as every writer
/// of an envelope does (ADR-0034, Phase 3 amendment, condition 1). A write
/// that takes the envelope off the original storage key (the envelope there
/// records no parent, or cannot be read, and `next` records one) is preceded
/// by a durable record write that clears `unused_since` and sets this
/// envelope's entry to this boot. The entry is removed once the envelope's
/// write is durable, and stays when it is visible but not durable, since
/// after a power loss the envelope under the key can come back. A record
/// write that fails, or is not durable, stops the move: nothing is published.
///
/// Only while irlumed has recorded a DA-exempt key: the original key is
/// retired only beside one, and a move off it goes nowhere else.
///
/// # Errors
///
/// When the record cannot be locked or made durable before a move, and when
/// the envelope is not published; [`AtomicWrite::VisibleNotDurable`] is a
/// publication, as for [`SealedEnvelope::save_reporting`].
///
/// [`AtomicWrite::VisibleNotDurable`]: irlume_common::AtomicWrite::VisibleNotDurable
/// [`SealedEnvelope::save_reporting`]: crate::envelope::SealedEnvelope::save_reporting
pub(crate) fn publish_envelope(
    path: &Path,
    kind: EnvelopeKind,
    user: &str,
    next: &crate::envelope::SealedEnvelope,
) -> Result<irlume_common::AtomicWrite> {
    publish_with(
        path,
        kind,
        user,
        next,
        irlume_common::boot_id().as_deref(),
        save_record,
        |envelope, path| envelope.save_reporting(path),
    )
}

/// [`publish_envelope`] in boot `boot`, with the record written by `save`
/// and the envelope by `write`.
fn publish_with(
    path: &Path,
    kind: EnvelopeKind,
    user: &str,
    next: &crate::envelope::SealedEnvelope,
    boot: Option<&str>,
    mut save: impl FnMut(&Record) -> Result<()>,
    write: impl FnOnce(&crate::envelope::SealedEnvelope, &Path) -> Result<irlume_common::AtomicWrite>,
) -> Result<irlume_common::AtomicWrite> {
    let Some(to) = &next.parent else {
        return write(next, path);
    };
    let off_original = under_original_key(path);
    let moves_key = off_original
        || crate::envelope::SealedEnvelope::load(path)
            .ok()
            .and_then(|current| current.parent)
            .is_some_and(|from| from.name != to.name);
    // Checked before the lock, which a host with no record never creates.
    if !moves_key || load_record().persisted.is_none() {
        return write(next, path);
    }
    // One transaction with the start-up step, which holds the same lock: the
    // move lands only on the key the record holds now, so a start that
    // superseded the candidate's key since it was sealed (an overlapping
    // start replacing a weak key) makes it no move, and the next move point
    // seals again.
    let _lock = RecordLock::acquire()?;
    let mut record = load_record();
    if record
        .persisted
        .as_ref()
        .map(|persisted| persisted.name.as_str())
        != Some(to.name.as_str())
    {
        return Err(Error::Tpm(
            "the storage key this envelope was sealed under is no longer the one irlumed \
             records; it moves at its next move point"
                .into(),
        ));
    }
    if off_original {
        record.unused_since = None;
        record
            .moves
            .retain(|entry| !(entry.user == user && entry.kind == kind));
        record.moves.push(UnsettledMove {
            user: user.to_owned(),
            kind,
            boot_id: boot.map(str::to_owned),
        });
        save(&record)?;
    }
    let written = write(next, path)?;
    if off_original && matches!(written, irlume_common::AtomicWrite::Durable) {
        // An entry left behind only delays the retirement by a boot.
        let before = record.moves.len();
        record
            .moves
            .retain(|entry| !(entry.user == user && entry.kind == kind));
        if record.moves.len() != before {
            let _ = save(&record);
        }
    }
    Ok(written)
}

/// Whether the envelope at `path` is under the original storage key for the
/// census: it records no parent, or it exists and cannot be read.
fn under_original_key(path: &Path) -> bool {
    match crate::envelope::SealedEnvelope::load(path) {
        Ok(envelope) => envelope.parent.is_none(),
        Err(_) => std::fs::symlink_metadata(path).is_ok(),
    }
}

/// What irlumed's start found about the original storage key's use, after
/// its template key moves (ADR-0034, Phase 3 amendment, condition 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Census {
    /// An envelope is under the original key, or cannot be read.
    InUse,
    /// No envelope is under it, and it has been unused since the start in
    /// the boot named.
    Unused { since: String },
    /// No envelope is under it, but a move off it in this boot is not yet
    /// shown durable, or this boot or the move's cannot be read, so this
    /// start marks nothing.
    Unsettled,
}

/// What irlumed's start did about the original storage key after its
/// template key moves: the census, and the retirement when one was due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    pub census: Census,
    /// `None` when no retirement was due: the key is in use, was marked
    /// unused only in this boot, this start derived a key already, the
    /// DA-exempt key is not at its recorded handle, or the original key is
    /// not the one the record kept as matching today's derivation.
    pub retirement: Option<Retirement>,
}

/// A retirement of the original storage key that was due at this start
/// (ADR-0034, Phase 3 amendment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retirement {
    /// Proved by a fresh derivation and evicted from `handle`.
    Retired { handle: u32 },
    /// Today's derivation does not give the key at `handle`, so irlume
    /// never evicts it; the record keeps it as not matching, and nothing is
    /// derived for it again. Once no envelope is under it, doctor names the
    /// manual command (the #1079 path).
    NotReproduced { handle: u32 },
    /// The proof or the eviction failed (an owner authorization set since,
    /// a TPM error): recorded with this boot and tried again only at the
    /// first start in a later boot.
    Failed { handle: u32, detail: String },
    /// A retirement was attempted earlier in this boot and failed or did not
    /// finish, so this start derives nothing for it.
    Deferred { handle: u32, detail: String },
    /// The TPM could not be opened or read to check the keys; tried again
    /// at the next start.
    Unchecked { detail: String },
}

/// irlumed's start, after its template key moves, under the record lock
/// (ADR-0034, Phase 3 amendment). First the census of the original storage
/// key's use (condition 1): one that finds an envelope under the key, or one
/// it cannot read, clears `unused_since`; an empty one drops the entries of
/// moves that name another boot, since it read what the disk kept of that
/// boot's writes, and sets `unused_since` to this boot when no entry is left
/// that may be this boot's and none is set already.
///
/// Then the retirement, only when the census is empty and `unused_since`
/// names another boot (a boot ID that cannot be read is no other boot), in a
/// start that derived no key (`derived`, from
/// [`ensure_at_start_reporting`]), with the DA-exempt key at its recorded
/// handle with its recorded name (condition 3), and with the key at the
/// original handle the one the record kept as matching today's derivation.
/// A fresh derivation of the original template then proves it (condition 2)
/// before it is evicted. The TPM is opened only then, so an ordinary start
/// does no TPM work here.
///
/// `None` without a recorded DA-exempt key, beside which alone the key is
/// retired.
///
/// # Errors
///
/// When an envelope directory cannot be read, or the record cannot be locked
/// or written. A TPM that cannot be opened or read is
/// [`Retirement::Unchecked`].
pub fn settle_at_start(derived: bool) -> Result<Option<Settled>> {
    settle_in(
        irlume_common::boot_id().as_deref(),
        derived,
        tpm::DaExemptKeyTpm::open,
        save_record,
    )
}

/// [`settle_at_start`] in boot `boot`, with the TPM `open` gives and the
/// record written by `save`. What the census changed is made durable before
/// anything is evicted, and a write that fails, or is not durable, retires
/// nothing; the retirement writes its own changes ([`retire_with`]).
pub(crate) fn settle_in<T: KeyTpm>(
    boot: Option<&str>,
    derived: bool,
    open: impl FnOnce() -> Result<T>,
    mut save: impl FnMut(&Record) -> Result<()>,
) -> Result<Option<Settled>> {
    if load_record().persisted.is_none() {
        return Ok(None);
    }
    let _lock = RecordLock::acquire()?;
    let record = load_record();
    let in_use = any_under_original_key()?;
    let (mut next, census) = mark_with(&record, in_use, boot);
    mark_superseded(&mut next, boot)?;
    if next != record {
        save(&next)?;
    }
    let retirement = match (&census, boot) {
        (Census::Unused { since }, Some(boot)) if since != boot && !derived => {
            match tpm::da_exempt_key_plan() {
                Ok(plan) => match open() {
                    Ok(mut tpm) => retire_with(&mut tpm, &mut next, plan.original, boot, &mut save)
                        .unwrap_or_else(|e| {
                            Some(Retirement::Unchecked {
                                detail: irlume_common::single_line(
                                    &e.to_string(),
                                    MAX_DETAIL_CHARS,
                                ),
                            })
                        }),
                    Err(e) => Some(Retirement::Unchecked {
                        detail: irlume_common::single_line(&e.to_string(), MAX_DETAIL_CHARS),
                    }),
                },
                // A refused IRLUME_SRK_HANDLE names no original key to retire.
                Err(_) => None,
            }
        }
        _ => None,
    };
    Ok(Some(Settled { census, retirement }))
}

/// [`settle_at_start`] in boot `boot`, for a TPM test that needs another
/// boot than this one.
#[cfg(test)]
pub(crate) fn settle_at_start_in(boot: Option<&str>, derived: bool) -> Result<Option<Settled>> {
    settle_in(boot, derived, tpm::DaExemptKeyTpm::open, save_record)
}

/// The retirement of the original key at `handle`, its handle today, over
/// `tpm` in boot `boot`, once the census allows one; `next` is the record,
/// and `save` writes it. The attempt is recorded with its boot, durably,
/// before the proof's derivation: a write that fails then derives and evicts
/// nothing, and once it is written a restart in the same boot is
/// [`Retirement::Deferred`] however the attempt ended, even when the write of
/// its outcome fails. A successful retirement clears the attempt; should that
/// write fail, the next start that finds the key gone from its handle drops
/// it. `None` when condition 3, or the record's account of the key, does not
/// hold.
///
/// # Errors
///
/// When the TPM cannot be read, or the attempt cannot be recorded.
fn retire_with(
    tpm: &mut impl KeyTpm,
    next: &mut Record,
    handle: u32,
    boot: &str,
    save: &mut impl FnMut(&Record) -> Result<()>,
) -> Result<Option<Retirement>> {
    // Condition 3: the DA-exempt key, which an envelope that comes back
    // moves to, is at its recorded handle with its recorded name and the
    // DA-exempt template's shape, and irlume can seal under it. The record is
    // in the state directory, so it could name any key, the original one
    // included.
    let Some(persisted) = &next.persisted else {
        return Ok(None);
    };
    let Some(da_exempt) = unhex(&persisted.name) else {
        return Ok(None);
    };
    let da_exempt_handle = persisted.handle;
    // The key at the original handle is the one the record kept as matching
    // today's derivation. The record is advisory: what follows proves it.
    let Some(original) = next
        .original
        .as_ref()
        .filter(|original| original.matched && original.handle == handle)
    else {
        return Ok(None);
    };
    let Some(name) = unhex(&original.name) else {
        return Ok(None);
    };
    if tpm.name_at(handle)?.as_deref() != Some(name.as_slice()) {
        // The key left the handle (retired, evicted by hand, or another
        // stack's key is there now): an earlier attempt concerns nothing.
        if next.retirement_attempt.take().is_some() {
            save(next)?;
        }
        return Ok(None);
    }
    if let Some(attempt) = &next.retirement_attempt {
        if attempt.boot_id.as_deref() == Some(boot) {
            let detail = attempt.failure.as_deref().map_or_else(
                || "an attempt earlier in this boot did not finish".to_owned(),
                |failure| irlume_common::single_line(failure, MAX_DETAIL_CHARS),
            );
            return Ok(Some(Retirement::Deferred { handle, detail }));
        }
    }
    if !tpm.holds_da_exempt_key(da_exempt_handle, &da_exempt)? {
        return Ok(None);
    }
    next.retirement_attempt = Some(RetirementAttempt {
        boot_id: Some(boot.to_owned()),
        failure: None,
    });
    save(next)?;
    // Condition 2: a fresh derivation of the original template gives the
    // same key.
    match tpm.derives_original(handle) {
        Ok(Some(true)) => {}
        Ok(Some(false)) => {
            next.retirement_attempt = None;
            if let Some(original) = next.original.as_mut() {
                original.matched = false;
            }
            // Should this fail, the attempt stands for this boot and the
            // next boot's start finds the same.
            let _ = save(next);
            return Ok(Some(Retirement::NotReproduced { handle }));
        }
        // The key there is not the original template's shape after all.
        Ok(None) => {
            next.retirement_attempt = None;
            let _ = save(next);
            return Ok(None);
        }
        Err(e) => return Ok(Some(failed_retirement(next, handle, &e, save))),
    }
    match tpm.evict(handle, &name) {
        Ok(true) => {
            next.retirement_attempt = None;
            let _ = save(next);
            Ok(Some(Retirement::Retired { handle }))
        }
        // It left the handle since: nothing to retire.
        Ok(false) => {
            next.retirement_attempt = None;
            let _ = save(next);
            Ok(None)
        }
        Err(e) => Ok(Some(failed_retirement(next, handle, &e, save))),
    }
}

/// Record in `next`, already holding this boot's attempt, that the
/// retirement of the key at `handle` failed with `error`, and say so. Should
/// the write fail, the attempt written before still stands for this boot.
fn failed_retirement(
    next: &mut Record,
    handle: u32,
    error: &Error,
    save: &mut impl FnMut(&Record) -> Result<()>,
) -> Retirement {
    let detail = irlume_common::single_line(&error.to_string(), MAX_DETAIL_CHARS);
    if let Some(attempt) = next.retirement_attempt.as_mut() {
        attempt.failure = Some(detail.clone());
    }
    let _ = save(next);
    Retirement::Failed { handle, detail }
}

/// The census of the superseded keys' use in `next`, in boot `boot`, as
/// condition 1 keeps it for the original key: a key some envelope names, or
/// may name (one that cannot be read), has its mark cleared; one none names
/// is marked with this boot unless it is marked already. A boot ID that
/// cannot be read marks nothing. Marks for keys no longer kept go.
fn mark_superseded(next: &mut Record, boot: Option<&str>) -> Result<()> {
    bound_superseded(&mut next.superseded);
    let kept: Vec<String> = next
        .superseded
        .iter()
        .map(|kept| kept.name.clone())
        .collect();
    next.superseded_unused.retain(|name, _| kept.contains(name));
    for name in kept {
        let (named, unreadable) = envelopes_naming(&name)?;
        if named.total > 0 || unreadable {
            next.superseded_unused.remove(&name);
        } else if let Some(boot) = boot {
            next.superseded_unused
                .entry(name)
                .or_insert_with(|| boot.to_owned());
        }
    }
    Ok(())
}

/// The envelopes (sealed template keys and keyring secrets) that record the
/// key with TPM name `name` (hex) as their parent, named as
/// [`on_original_key`] names them, and whether some envelope cannot be read,
/// which may name it.
fn envelopes_naming(name: &str) -> Result<(OriginalKeyEnvelopes, bool)> {
    let mut named = Vec::new();
    let mut total = 0u32;
    let mut unreadable = false;
    for (dir, kind) in [
        (template_key::key_dir(), EnvelopeKind::TemplateKey),
        (keyring::keyring_dir(), EnvelopeKind::KeyringSecret),
    ] {
        for path in envelope_paths(&dir)? {
            let parent = match crate::envelope::SealedEnvelope::load(&path) {
                Ok(envelope) => envelope.parent,
                Err(_) => {
                    unreadable = true;
                    continue;
                }
            };
            if parent.is_none_or(|parent| parent.name != name) {
                continue;
            }
            total = total.saturating_add(1);
            let user = path.file_stem().and_then(|stem| stem.to_str());
            if let Some(user) = user.filter(|user| is_account_name(user)) {
                named.push(OriginalKeyEnvelope {
                    user: user.to_owned(),
                    kind,
                });
            }
        }
    }
    named.sort();
    named.truncate(MAX_NAMED_ENVELOPES);
    Ok((OriginalKeyEnvelopes { named, total }, unreadable))
}

/// Every storage key irlume knows of, for doctor's `tpm-firmware` check
/// (ADR-0034, Phase 3 amendment, #1073 item 2): the original key at its
/// handle with `original`, the check the same request already made of it
/// (`tpm::storage_key_check`, left out when that failed), then the recorded
/// DA-exempt key and each key it superseded, each checked for the ROCA
/// fingerprint with nothing derived, with the envelopes that still name
/// them. A superseded key is unused across boots only while no envelope
/// names it or cannot be read. The record is untrusted where it is writable
/// offline (§5): only bounded hex names and accepted account names go out.
///
/// # Errors
///
/// When an envelope directory cannot be read, or the TPM cannot be opened
/// or read.
pub fn storage_keys(
    original: Option<irlume_common::tpm_readiness::StorageKeyCheck>,
) -> Result<Vec<irlume_common::tpm_readiness::StorageKeyEntry>> {
    use irlume_common::tpm_readiness::{StorageKeyCheck, StorageKeyEntry, StorageKeyRole};
    let mut record = load_record();
    bound_superseded(&mut record.superseded);
    let boot = irlume_common::boot_id();
    let bounded = |name: &str| {
        if name.len() <= MAX_NAME_HEX && name.bytes().all(|b| b.is_ascii_hexdigit()) {
            name.to_owned()
        } else {
            String::new()
        }
    };
    let mut entries = Vec::new();
    if let Some(check) = original {
        let handle = tpm::persistent_srk_raw();
        let mut names = tpm::DaExemptKeyTpm::open()?;
        let name = names
            .name_at(handle)?
            .map(|name| hex(&name))
            .unwrap_or_default();
        entries.push(StorageKeyEntry {
            role: StorageKeyRole::Original,
            handle,
            name,
            check,
            envelopes: None,
            unused_across_boots: false,
        });
    }
    let keyed = |role, handle, name: &str| -> Result<StorageKeyEntry> {
        let check = match unhex(name) {
            Some(raw) => tpm::da_exempt_key_check(handle, &raw)?,
            None => StorageKeyCheck::Absent,
        };
        let (envelopes, unreadable) = envelopes_naming(name)?;
        let unused_across_boots = role == StorageKeyRole::Superseded
            && envelopes.total == 0
            && !unreadable
            && matches!(
                (record.superseded_unused.get(name), boot.as_deref()),
                (Some(since), Some(now)) if since != now
            );
        Ok(StorageKeyEntry {
            role,
            handle,
            name: bounded(name),
            check,
            envelopes: Some(envelopes),
            unused_across_boots,
        })
    };
    if let Some(persisted) = &record.persisted {
        entries.push(keyed(
            StorageKeyRole::DaExempt,
            persisted.handle,
            &persisted.name,
        )?);
    }
    let recorded = record
        .persisted
        .as_ref()
        .map(|persisted| persisted.name.clone());
    for kept in &record.superseded {
        if recorded.as_deref() == Some(kept.name.as_str()) {
            continue;
        }
        entries.push(keyed(StorageKeyRole::Superseded, kept.handle, &kept.name)?);
    }
    Ok(entries)
}

/// The record after a census that found an envelope under the original key
/// (`in_use`) or none, in boot `boot`, and what it found.
fn mark_with(record: &Record, in_use: bool, boot: Option<&str>) -> (Record, Census) {
    let mut next = record.clone();
    if in_use {
        next.unused_since = None;
        return (next, Census::InUse);
    }
    if let Some(boot) = boot {
        next.moves
            .retain(|entry| entry.boot_id.as_deref().is_none_or(|then| then == boot));
    }
    if let Some(since) = &next.unused_since {
        let census = Census::Unused {
            since: since.clone(),
        };
        return (next, census);
    }
    match boot {
        Some(boot) if next.moves.is_empty() => {
            next.unused_since = Some(boot.to_owned());
            let census = Census::Unused {
                since: boot.to_owned(),
            };
            (next, census)
        }
        _ => (next, Census::Unsettled),
    }
}

/// Whether some envelope is under the original storage key for the census:
/// one that records no parent, or one that cannot be read, whatever its file
/// is named.
fn any_under_original_key() -> Result<bool> {
    for dir in [template_key::key_dir(), keyring::keyring_dir()] {
        if envelope_paths(&dir)?
            .iter()
            .any(|path| under_original_key(path))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// An envelope whose recorded parent handle no longer holds a key with its
/// recorded TPM name, and what irlumed's start did about it (ADR-0034 §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repointed {
    /// The account the envelope belongs to.
    pub user: String,
    /// What it holds.
    pub kind: EnvelopeKind,
    /// The handle it recorded.
    pub from: u32,
    /// What happened.
    pub outcome: RepointOutcome,
}

/// What irlumed's start did for a [`Repointed`] envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepointOutcome {
    /// A key with the recorded name is persisted at this handle, which the
    /// template key now records.
    Moved(u32),
    /// No persisted owner key has the recorded name, so the envelope cannot
    /// load until it is sealed again.
    Missing,
    /// A key with the recorded name is persisted at this handle, but the
    /// template key could not be rewritten; the next start tries again.
    Unwritten(u32, String),
}

/// irlumed's start-up recovery by name (ADR-0034 §3.3: the recorded name
/// decides and the handle is a hint). A template key that records a parent
/// whose handle does not hold a key with the recorded TPM name, as when
/// another stack took the handle after the key left it, records instead the
/// owner handle where a key with that name is persisted. Only the handle in
/// the envelope changes: the sealed object is not touched, so nothing is
/// unsealed or sealed. It runs after [`ensure_at_start`], which persists the
/// DA-exempt key again when it went missing, so the envelope finds the key
/// where that step put it. With no envelope recording a parent it asks the
/// TPM nothing. An authentication never does this: it uses only the key at
/// the envelope's handle, or at the handle irlumed recorded for the same name.
///
/// A keyring envelope is checked but never rewritten here. Its writers
/// (`keyring arm`, a login's reseal) take no lock of their own: irlumed's
/// single worker is what orders them, and this step can run in a second
/// irlumed started beside the service, where a rewrite could put back a
/// secret the service has just replaced. One whose key is at another handle
/// still loads through irlumed's record of that key, and one that does not
/// load is sealed again by the next login's reseal.
///
/// # Errors
///
/// When an envelope directory cannot be read, or the TPM cannot be opened or
/// read. An envelope that cannot be rewritten is reported in the result.
pub fn repoint_at_start() -> Result<Vec<Repointed>> {
    let envelopes = recorded_parents()?;
    if envelopes.is_empty() {
        return Ok(Vec::new());
    }
    let mut tpm = tpm::DaExemptKeyTpm::open()?;
    repoint_with(&mut tpm, envelopes)
}

/// An envelope file that records a parent: its path, kind, account and the
/// parent it records.
pub(crate) type RecordedParent = (PathBuf, EnvelopeKind, String, crate::envelope::ParentKey);

/// The envelopes that record a parent, in the template-key and keyring stores.
/// Only a file named for an account name irlumed accepts is taken: irlume
/// writes no other, and the state directory is untrusted where it is
/// writable offline (§5). An envelope that cannot be parsed is left alone.
pub(crate) fn recorded_parents() -> Result<Vec<RecordedParent>> {
    let mut found = Vec::new();
    for (dir, kind) in [
        (template_key::key_dir(), EnvelopeKind::TemplateKey),
        (keyring::keyring_dir(), EnvelopeKind::KeyringSecret),
    ] {
        for path in envelope_paths(&dir)? {
            let user = path.file_stem().and_then(|stem| stem.to_str());
            let Some(user) = user.filter(|user| is_account_name(user)).map(str::to_owned) else {
                continue;
            };
            let parent = crate::envelope::SealedEnvelope::load(&path)
                .ok()
                .and_then(|envelope| envelope.parent);
            if let Some(parent) = parent {
                found.push((path, kind, user, parent));
            }
        }
    }
    found.sort_by(|a, b| (&a.2, a.1).cmp(&(&b.2, b.1)));
    Ok(found)
}

/// [`repoint_at_start`] over `tpm` for `envelopes`. The owner handles are
/// scanned at most once, and only when an envelope's handle is stale.
pub(crate) fn repoint_with(
    tpm: &mut impl KeyTpm,
    envelopes: Vec<RecordedParent>,
) -> Result<Vec<Repointed>> {
    let mut owners: Option<Vec<(u32, Vec<u8>)>> = None;
    let mut repointed = Vec::new();
    for (path, kind, user, parent) in envelopes {
        // A name that is not hex names no key, at its handle or elsewhere.
        let name = unhex(&parent.name);
        if let Some(name) = &name {
            if tpm::OWNER_PERSISTENT.contains(&parent.handle)
                && tpm.name_at(parent.handle)?.as_deref() == Some(name.as_slice())
            {
                continue;
            }
        }
        let found = match &name {
            Some(name) => {
                if owners.is_none() {
                    owners = Some(tpm.owner_names()?);
                }
                owners
                    .iter()
                    .flatten()
                    .find(|(_, owner)| owner == name)
                    .map(|(handle, _)| *handle)
            }
            None => None,
        };
        let outcome = match (found, kind) {
            (Some(to), EnvelopeKind::TemplateKey) => {
                match record_parent_handle(&path, &user, &parent, to) {
                    Ok(()) => RepointOutcome::Moved(to),
                    Err(e) => RepointOutcome::Unwritten(to, e.to_string()),
                }
            }
            // Not rewritten outside irlumed's worker (see `repoint_at_start`).
            (Some(_), EnvelopeKind::KeyringSecret | EnvelopeKind::Unknown) => continue,
            (None, _) => RepointOutcome::Missing,
        };
        repointed.push(Repointed {
            user,
            kind,
            from: parent.handle,
            outcome,
        });
    }
    Ok(repointed)
}

/// Rewrite `user`'s template key at `path` to record `handle` for its parent
/// when it still records `parent`'s name, under the user state lock every
/// template key writer holds. A visible write counts, as for a move: the old
/// handle is only a hint.
fn record_parent_handle(
    path: &Path,
    user: &str,
    parent: &crate::envelope::ParentKey,
    handle: u32,
) -> Result<()> {
    let _state = template_key::UserStateLock::acquire(user)?;
    let mut envelope = crate::envelope::SealedEnvelope::load(path)?;
    match envelope.parent.as_mut() {
        Some(recorded) if recorded.name == parent.name => recorded.handle = handle,
        // Rewritten since the scan: what it records now is not this one.
        _ => return Ok(()),
    }
    envelope.save_reporting(path).map(|_| ())
}

/// Whether `name` is an account name irlumed accepts in a request (its
/// `valid_username`): 1 to 64 bytes of ASCII letters, digits, `_`, `-`, `.`
/// and `$`, not starting with `-` or `.`.
fn is_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with(['-', '.'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$'))
}

/// [`ensure_at_start`] over `tpm`, from `record`, in boot `boot`, with the
/// handle `plan` or the reason the `IRLUME_SRK_HANDLE` override is refused.
/// Returns the record to keep and what happened.
pub(crate) fn ensure_with(
    tpm: &mut impl KeyTpm,
    record: &Record,
    boot: Option<&str>,
    plan: &std::result::Result<Plan, String>,
) -> Result<(Record, Outcome)> {
    let refuse = |reason: RefusalReason, detail: String| {
        let detail = irlume_common::single_line(&detail, MAX_DETAIL_CHARS);
        let refusal = KeyRefusal {
            reason,
            detail: detail.clone(),
        };
        let record = Record {
            version: RECORD_VERSION,
            persisted: None,
            refused: Some(Refused {
                reason,
                detail,
                boot_id: boot.map(str::to_owned),
            }),
            ..Record::default()
        };
        (record, Outcome::Refused(refusal))
    };
    let plan = match plan {
        Ok(plan) => *plan,
        Err(detail) => return Ok(refuse(RefusalReason::HandleOverride, detail.clone())),
    };
    if let Some(persisted) = &record.persisted {
        if tpm_name_hex(tpm, persisted.handle)?.as_deref() == Some(persisted.name.as_str()) {
            return Ok((
                record.clone(),
                Outcome::Present {
                    handle: persisted.handle,
                },
            ));
        }
        // The handle is a hint and the name decides (ADR-0034 §3.3): the
        // recorded key persisted at another handle, where irlume can still
        // seal under it, is followed there rather than replaced, so the
        // envelopes under it keep their key and nothing is derived.
        if let Some(name) = unhex(&persisted.name) {
            for (handle, found) in tpm.owner_names()? {
                if found == name && tpm.holds_da_exempt_key(handle, &name)? {
                    let mut next = record.clone();
                    next.persisted = Some(Persisted {
                        handle,
                        name: persisted.name.clone(),
                    });
                    next.refused = None;
                    return Ok((next, Outcome::Found { handle }));
                }
            }
        }
    }
    if let Some(refused) = &record.refused {
        // An unreadable boot ID, now or then, may be another boot: try again.
        let same_boot = matches!(
            (boot, refused.boot_id.as_deref()),
            (Some(now), Some(then)) if now == then
        );
        // A refused override is not the TPM's refusal: the plan above has
        // already passed, so the override was corrected, and nothing was
        // derived for it.
        let tpm_refusal = refused.reason != RefusalReason::HandleOverride;
        if same_boot
            && tpm_refusal
            && !(refused.reason.is_capacity() && tpm.persistent_avail()? >= 1)
        {
            let refusal = KeyRefusal {
                reason: refused.reason,
                detail: refused.detail.clone(),
            };
            return Ok((record.clone(), Outcome::Deferred(refusal)));
        }
    }
    let name = match tpm.derive() {
        Ok(name) => name,
        Err(failure) => return Ok(refuse(reason_for(failure.class), failure.detail)),
    };
    Ok(match place_derived(tpm, plan, &name)? {
        Placed::Adopted(handle) => (persisted_record(handle, &name), Outcome::Adopted { handle }),
        Placed::Persisted(handle) => (
            persisted_record(handle, &name),
            Outcome::Persisted { handle },
        ),
        Placed::Refused(reason, detail) => refuse(reason, detail),
    })
}

/// The replacement of a weak DA-exempt key (ADR-0034, Phase 3 amendment,
/// #1073 item 2), over `tpm` from `record`, whose key is at its recorded
/// handle, in boot `boot` with the handles `plan` names. `None` when the key
/// is not weak and nothing is to change. A weak key is never evicted here:
/// its envelopes move onto the replacement at their move points, so it is
/// replaced by moving them first.
///
/// - Today's derivation of the DA-exempt template is looked for among the
///   owner persistent handles first, by its TPM name, and adopted, so a
///   start stopped between persisting it and writing the record leaves no
///   second copy; only without one is it persisted at the next free owner
///   handle. It is recorded as the DA-exempt key, and the weak key as
///   superseded.
/// - A derivation that is weak too (firmware that still generates affected
///   keys) is recorded with the TPM's firmware version, and no start
///   derives for the weak key again until the TPM reads another version.
/// - A replacement that cannot be persisted is recorded with the boot and
///   tried again by the rules of section 3.2: at the first start in a later
///   boot, or sooner for lack of room once the TPM reports room. The weak
///   key stays the parent of new seals meanwhile.
fn replace_weak_with(
    tpm: &mut impl KeyTpm,
    record: &Record,
    boot: Option<&str>,
    plan: Plan,
) -> Result<Option<(Record, Outcome)>> {
    let Some(persisted) = record.persisted.clone() else {
        return Ok(None);
    };
    let handle = persisted.handle;
    let mut next = record.clone();
    if !tpm.is_weak(handle)? {
        // Nothing to replace; an account of an earlier weak key goes.
        if next.weak_derivation.take().is_none() && next.replacement_refused.take().is_none() {
            return Ok(None);
        }
        return Ok(Some((next, Outcome::Present { handle })));
    }
    let firmware = tpm.firmware()?;
    if record
        .weak_derivation
        .as_ref()
        .is_some_and(|weak| weak.firmware == firmware)
    {
        return Ok(Some((next, Outcome::WeakKept { handle })));
    }
    if let Some(refused) = &record.replacement_refused {
        // An unreadable boot ID, now or then, may be another boot: try again.
        let same_boot = matches!(
            (boot, refused.boot_id.as_deref()),
            (Some(now), Some(then)) if now == then
        );
        if same_boot && !(refused.reason.is_capacity() && tpm.persistent_avail()? >= 1) {
            let refusal = KeyRefusal {
                reason: refused.reason,
                detail: refused.detail.clone(),
            };
            return Ok(Some((
                next,
                Outcome::ReplacementDeferred {
                    from: handle,
                    refusal,
                },
            )));
        }
    }
    let refuse = |mut next: Record, reason: RefusalReason, detail: String| {
        let detail = irlume_common::single_line(&detail, MAX_DETAIL_CHARS);
        next.replacement_refused = Some(Refused {
            reason,
            detail: detail.clone(),
            boot_id: boot.map(str::to_owned),
        });
        let refusal = KeyRefusal { reason, detail };
        (
            next,
            Outcome::ReplacementRefused {
                from: handle,
                refusal,
            },
        )
    };
    let name = match tpm.derive() {
        Ok(name) => name,
        Err(failure) => {
            return Ok(Some(refuse(
                next,
                reason_for(failure.class),
                failure.detail,
            )))
        }
    };
    if hex(&name) == persisted.name || tpm.derived_is_weak()? {
        next.weak_derivation = Some(WeakDerivation { firmware });
        next.replacement_refused = None;
        return Ok(Some((next, Outcome::DerivationWeak { handle })));
    }
    let placed = match place_derived(tpm, plan, &name)? {
        Placed::Adopted(at) | Placed::Persisted(at) => at,
        Placed::Refused(reason, detail) => return Ok(Some(refuse(next, reason, detail))),
    };
    next.persisted = Some(Persisted {
        handle: placed,
        name: hex(&name),
    });
    supersede(&mut next, persisted);
    next.weak_derivation = None;
    next.replacement_refused = None;
    next.refused = None;
    Ok(Some((
        next,
        Outcome::Replaced {
            handle: placed,
            from: handle,
        },
    )))
}

/// `superseded` with each name once, at most [`MAX_SUPERSEDED`] of them, the
/// latest kept: a record edited offline could list any number.
fn bound_superseded(superseded: &mut Vec<Persisted>) {
    let mut seen = std::collections::HashSet::new();
    superseded.retain(|kept| seen.insert(kept.name.clone()));
    if superseded.len() > MAX_SUPERSEDED {
        superseded.drain(..superseded.len() - MAX_SUPERSEDED);
    }
}

/// Keep `old` in `next` as a superseded key, once, unless it is the key
/// `next` records.
fn supersede(next: &mut Record, old: Persisted) {
    let recorded = next
        .persisted
        .as_ref()
        .map(|persisted| persisted.name.as_str());
    if recorded != Some(old.name.as_str())
        && !next.superseded.iter().any(|kept| kept.name == old.name)
    {
        next.superseded.push(old);
        bound_superseded(&mut next.superseded);
    }
}

/// Keep the superseded keys in `next` findable by name. When the start-up
/// step recorded another DA-exempt key than `record` did (the recorded key
/// was away from its handle, and today's derivation was adopted or
/// persisted in its place), the old key is kept as superseded while it is
/// still persisted somewhere, found by its TPM name: its envelopes then move
/// off it, and load through it by name until they do; a key persisted
/// nowhere is not kept, since nothing can load under it. Every kept key
/// that is no longer at its recorded handle is looked for by its name among
/// the owner persistent handles and recorded where it is, since a keyring
/// envelope, which no start rewrites, loads through that handle; one found
/// nowhere keeps its entry, for the report.
fn keep_superseded(tpm: &mut impl KeyTpm, record: &Record, next: &mut Record) -> Result<()> {
    bound_superseded(&mut next.superseded);
    let mut owners = None;
    if let (Some(old), Some(new)) = (&record.persisted, &next.persisted) {
        if old.name != new.name {
            if let Some(name) = unhex(&old.name) {
                if let Some(handle) = persisted_by_name(tpm, &mut owners, &name)? {
                    let old = Persisted {
                        handle,
                        name: old.name.clone(),
                    };
                    supersede(next, old);
                }
            }
        }
    }
    for index in 0..next.superseded.len() {
        let Some(name) = unhex(&next.superseded[index].name) else {
            continue;
        };
        if tpm.holds_da_exempt_key(next.superseded[index].handle, &name)? {
            continue;
        }
        if let Some(handle) = persisted_by_name(tpm, &mut owners, &name)? {
            next.superseded[index].handle = handle;
        }
    }
    Ok(())
}

/// The owner persistent handle a key with TPM name `name` is at where irlume
/// can seal under it ([`KeyTpm::holds_da_exempt_key`]: the name does not
/// cover the authorization value), from one scan of them per start
/// (`owners`).
fn persisted_by_name(
    tpm: &mut impl KeyTpm,
    owners: &mut Option<Vec<(u32, Vec<u8>)>>,
    name: &[u8],
) -> Result<Option<u32>> {
    if owners.is_none() {
        *owners = Some(tpm.owner_names()?);
    }
    let candidates: Vec<u32> = owners
        .iter()
        .flatten()
        .filter(|(_, found)| found.as_slice() == name)
        .map(|(handle, _)| *handle)
        .collect();
    for handle in candidates {
        if tpm.holds_da_exempt_key(handle, name)? {
            return Ok(Some(handle));
        }
    }
    Ok(None)
}

/// The DA-exempt keys the recorded one superseded, as their handles and TPM
/// names, while the record keeps them; envelopes that name one move onto
/// the recorded DA-exempt key ([`crate::tpm::move_available`]). One that
/// names the recorded key itself is left out. Reads the record only.
pub(crate) fn superseded_keys() -> Vec<KeyAt> {
    da_exempt_keys().1
}

/// A key irlumed records: its handle and its TPM name in hex.
pub(crate) type KeyAt = (u32, String);

/// The recorded DA-exempt key and the keys it superseded
/// ([`superseded_keys`]), from one read of the record, so a caller that uses
/// both sees one state of it.
pub(crate) fn da_exempt_keys() -> (Option<KeyAt>, Vec<KeyAt>) {
    let mut record = load_record();
    bound_superseded(&mut record.superseded);
    let recorded = record
        .persisted
        .map(|persisted| (persisted.handle, persisted.name));
    let superseded = record
        .superseded
        .into_iter()
        .filter(|kept| recorded.as_ref().map(|(_, name)| name.as_str()) != Some(kept.name.as_str()))
        .map(|kept| (kept.handle, kept.name))
        .collect();
    (recorded, superseded)
}

/// Where a key [`KeyTpm::derive`] just derived, with TPM name `name`, ended
/// up: a copy already persisted, adopted by its name; a new copy persisted;
/// or why neither.
enum Placed {
    Adopted(u32),
    Persisted(u32),
    Refused(RefusalReason, String),
}

/// Adopt a persisted copy of the derived key `name` by its TPM name, so a
/// power loss between `TPM2_EvictControl` and the record never leaves a
/// second copy, or persist it at the first free owner handle from
/// `plan.preferred`, never the original key's. A taken handle that turns out
/// to hold the same key, which another start persisted a moment earlier, is
/// adopted; another is stepped past. A copy is adopted only where irlume can
/// seal under it ([`KeyTpm::holds_da_exempt_key`]).
fn place_derived(tpm: &mut impl KeyTpm, plan: Plan, name: &[u8]) -> Result<Placed> {
    let in_use = tpm.owner_names()?;
    // The TPM name covers the public area only: a copy another stack
    // persisted with its own authorization value has the same name, so a
    // copy is adopted only where irlume can seal under it.
    for (handle, used) in &in_use {
        if used.as_slice() == name && tpm.holds_da_exempt_key(*handle, name)? {
            return Ok(Placed::Adopted(*handle));
        }
    }
    let mut taken: Vec<u32> = in_use.into_iter().map(|(handle, _)| handle).collect();
    for _ in 0..PERSIST_ATTEMPTS {
        let Some(handle) = first_free_owner_handle(plan, &taken) else {
            return Ok(Placed::Refused(
                RefusalReason::NoFreeHandle,
                "every owner persistent handle is taken".to_owned(),
            ));
        };
        match tpm.persist(handle) {
            Ok(()) => return Ok(Placed::Persisted(handle)),
            // Another start may have just persisted the same key there: the
            // derivation is deterministic, so adopt it rather than persist a
            // second copy.
            Err(failure) if failure.class == FailureClass::Taken => {
                if tpm.name_at(handle)?.as_deref() == Some(name)
                    && tpm.holds_da_exempt_key(handle, name)?
                {
                    return Ok(Placed::Adopted(handle));
                }
                taken.push(handle);
            }
            Err(failure) => return Ok(Placed::Refused(reason_for(failure.class), failure.detail)),
        }
    }
    Ok(Placed::Refused(
        RefusalReason::NoFreeHandle,
        format!("{PERSIST_ATTEMPTS} handles in a row were taken while irlumed tried them"),
    ))
}

/// Whether `outcome` derived the DA-exempt key in this start: every outcome
/// but finding it present (weak or not, with nothing derived for it), or a
/// refusal earlier in this boot that stands.
fn derived_now(outcome: &Outcome) -> bool {
    !matches!(
        outcome,
        Outcome::Present { .. }
            | Outcome::Found { .. }
            | Outcome::Deferred(_)
            | Outcome::WeakKept { .. }
            | Outcome::ReplacementDeferred { .. }
    )
}

/// The record of irlume's original storage key after this start (ADR-0034
/// §3.4: "Phase 2 also records the old key's TPM name at the first start that
/// verifies it by derivation"). The entry is kept while the key at `handle`
/// still has the recorded name, and while the handle is free (an evicted key
/// is still the key the entry names). Otherwise the key there is compared
/// with today's derivation of the original template and recorded with
/// whether it matched, but only on a start that derived nothing else
/// (`derived_new` false), so that no start pays for two derivations of an
/// RSA-2048 primary, each more than 10 seconds on slow firmware TPMs. A key
/// without the original template's shape is not recorded.
fn original_with(
    tpm: &mut impl KeyTpm,
    handle: u32,
    recorded: Option<Original>,
    derived_new: bool,
) -> Result<Option<Original>> {
    let Some(name) = tpm.name_at(handle)? else {
        return Ok(recorded);
    };
    let name = hex(&name);
    if recorded
        .as_ref()
        .is_some_and(|original| original.handle == handle && original.name == name)
        || derived_new
    {
        return Ok(recorded);
    }
    Ok(match tpm.derives_original(handle)? {
        Some(matched) => Some(Original {
            handle,
            name,
            matched,
        }),
        None => recorded,
    })
}

/// The first free owner persistent handle from `plan.preferred` upward,
/// wrapping within 0x81000000 to 0x817FFFFF, never the original key's.
pub(crate) fn first_free_owner_handle(plan: Plan, taken: &[u32]) -> Option<u32> {
    let (first, last) = (*tpm::OWNER_PERSISTENT.start(), *tpm::OWNER_PERSISTENT.end());
    (plan.preferred..=last)
        .chain(first..plan.preferred)
        .find(|handle| *handle != plan.original && !taken.contains(handle))
}

fn reason_for(class: FailureClass) -> RefusalReason {
    match class {
        FailureClass::NoSpace => RefusalReason::NoSpace,
        FailureClass::OwnerAuthorization => RefusalReason::OwnerAuthorization,
        FailureClass::Taken | FailureClass::Other => RefusalReason::Other,
    }
}

fn persisted_record(handle: u32, name: &[u8]) -> Record {
    Record {
        version: RECORD_VERSION,
        persisted: Some(Persisted {
            handle,
            name: hex(name),
        }),
        ..Record::default()
    }
}

fn tpm_name_hex(tpm: &mut impl KeyTpm, handle: u32) -> Result<Option<String>> {
    Ok(tpm.name_at(handle)?.map(|name| hex(&name)))
}

/// The DA-exempt key irlumed recorded, as its handle and TPM name: what a
/// seal checks at that handle before it seals under it ([`crate::tpm`]).
/// `None` without a record of a persisted key, or with a name that is not
/// hex. Reads the record only.
pub(crate) fn recorded_key() -> Option<(u32, Vec<u8>)> {
    let persisted = load_record().persisted?;
    Some((persisted.handle, unhex(&persisted.name)?))
}

/// Whether every envelope (sealed template key or keyring secret) records
/// one of `names`, TPM names in hex, as its parent, so that a TPM lockout
/// blocks none of them. An envelope that cannot be parsed counts as not on
/// any.
pub(crate) fn every_envelope_on(names: &[&str]) -> Result<bool> {
    for dir in [template_key::key_dir(), keyring::keyring_dir()] {
        for path in envelope_paths(&dir)? {
            // The bounded loader: an oversized, linked or unreadable file
            // counts as not on the key, and cannot exhaust irlumed's memory.
            let on_key = crate::envelope::SealedEnvelope::load(&path)
                .ok()
                .and_then(|envelope| envelope.parent)
                .is_some_and(|parent| names.contains(&parent.name.as_str()));
            if !on_key {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// The `*.json` envelope files in `dir`; none for a missing directory, and
/// an error for one that cannot be read.
fn envelope_paths(dir: &Path) -> Result<Vec<PathBuf>> {
    let io = |e: std::io::Error| Error::Io(format!("{}: {e}", dir.display()));
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(e)),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry.map_err(io)?.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    Ok(paths)
}

/// `bytes` in lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `text` read as hex ([`hex`]), or `None` when it is not.
pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Whether some envelope exists: a sealed template key or keyring secret.
/// Envelopes on the original key need the DA-exempt key persisted for their
/// move, and envelopes on the DA-exempt key need it still there, so the
/// start-up step runs while any exists.
fn any_envelope() -> Result<bool> {
    Ok(has_envelope(&template_key::key_dir())? || has_envelope(&keyring::keyring_dir())?)
}

/// Whether `dir` holds an envelope. A missing directory holds none; any other
/// error is returned, so that an unreadable store never reads as empty and
/// skips the step.
fn has_envelope(dir: &Path) -> Result<bool> {
    Ok(!envelope_paths(dir)?.is_empty())
}

fn record_path() -> PathBuf {
    irlume_common::state_dir().join("tpm-storage-key")
}

/// An exclusive `flock` on `state_dir()/.tpm-storage-key.lock` for each
/// read, decision and write of the record (the start-up steps, and an
/// envelope writer's account of a move off the original key), held until it
/// is dropped. Like `template_key::UserStateLock`, every acquisition opens
/// the file anew, so it also excludes another thread of this process; for
/// the same reason nothing takes it while holding it, since a second
/// acquisition in the same thread would wait on the first.
struct RecordLock(std::fs::File);

impl RecordLock {
    fn acquire() -> Result<Self> {
        let path = irlume_common::state_dir().join(".tpm-storage-key.lock");
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = options
            .open(&path)
            .map_err(|e| Error::Io(format!("open {}: {e}", path.display())))?;
        let is_file = file
            .metadata()
            .map_err(|e| Error::Io(e.to_string()))?
            .file_type()
            .is_file();
        if !is_file {
            return Err(Error::Io(format!(
                "the storage key lock is not a regular file: {}",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: `file` owns this open descriptor, and the guard keeps it
            // open until the lock is released in Drop.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(Error::Io(format!(
                    "lock {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                )));
            }
        }
        Ok(Self(file))
    }
}

impl Drop for RecordLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: the guard still owns a valid descriptor throughout Drop.
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// The record, or an empty one when there is none. A record that is
/// unreadable, larger than [`MAX_RECORD_BYTES`], malformed or from a newer
/// release reads as none: the next step derives the key and adopts a
/// persisted copy by its name, so nothing is lost.
fn load_record() -> Record {
    crate::envelope::read_bounded(&record_path(), MAX_RECORD_BYTES)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Record>(&bytes).ok())
        .filter(|record| record.version <= RECORD_VERSION)
        .unwrap_or_default()
}

fn save_record(record: &Record) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(record).map_err(|e| Error::Protocol(e.to_string()))?;
    irlume_common::write_0600_atomic(&record_path(), &bytes).map_err(|e| Error::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const BOOT: &str = "0a1b2c3d-4e5f-6789-abcd-ef0123456789";
    const LATER_BOOT: &str = "1a1b2c3d-4e5f-6789-abcd-ef0123456789";
    const PLAN: Plan = Plan {
        preferred: 0x8101_0003,
        original: 0x8101_0002,
    };

    /// A TPM in memory: persistent objects by handle and name, what the next
    /// derive and persist answer, and how often each ran.
    struct FakeTpm {
        objects: BTreeMap<u32, Vec<u8>>,
        avail: u32,
        derive: std::result::Result<Vec<u8>, Failure>,
        persist: Vec<std::result::Result<(), Failure>>,
        derived: usize,
        persisted: Vec<u32>,
        /// A `Taken` answer means another start persisted this same key
        /// there a moment earlier.
        concurrent: bool,
        /// How many times the owner handles were scanned.
        scans: usize,
        /// What comparing the key at the original handle with today's
        /// derivation answers, and how many times it was asked.
        original: Option<bool>,
        original_derivations: usize,
        /// An error the comparison answers instead, as for an owner
        /// authorization set since.
        original_error: Option<String>,
        /// The handles evicted, and an error eviction answers instead.
        evicted: Vec<u32>,
        evict_error: Option<String>,
        /// The handles whose key lacks the DA-exempt template's shape, and
        /// those whose key refuses irlume's empty authorization.
        other_shape: Vec<u32>,
        other_auth: Vec<u32>,
        /// The handles whose key carries the ROCA fingerprint, whether the
        /// next derived key does, and the firmware version the TPM reads.
        weak: Vec<u32>,
        derived_weak: bool,
        firmware: [u32; 2],
    }

    impl FakeTpm {
        fn new() -> Self {
            Self {
                objects: BTreeMap::new(),
                avail: 4,
                derive: Ok(b"ours".to_vec()),
                persist: Vec::new(),
                derived: 0,
                persisted: Vec::new(),
                concurrent: false,
                scans: 0,
                original: Some(true),
                original_derivations: 0,
                original_error: None,
                evicted: Vec::new(),
                evict_error: None,
                other_shape: Vec::new(),
                other_auth: Vec::new(),
                weak: Vec::new(),
                derived_weak: false,
                firmware: [0x0007_0055, 0],
            }
        }
    }

    fn failure(class: FailureClass) -> Failure {
        Failure {
            class,
            detail: format!("{class:?}"),
        }
    }

    impl KeyTpm for FakeTpm {
        fn name_at(&mut self, handle: u32) -> Result<Option<Vec<u8>>> {
            Ok(self.objects.get(&handle).cloned())
        }
        fn persistent_avail(&mut self) -> Result<u32> {
            Ok(self.avail)
        }
        fn derive(&mut self) -> std::result::Result<Vec<u8>, Failure> {
            self.derived += 1;
            self.derive.clone()
        }
        fn derives_original(&mut self, handle: u32) -> Result<Option<bool>> {
            if !self.objects.contains_key(&handle) {
                return Ok(None);
            }
            self.original_derivations += 1;
            if let Some(error) = &self.original_error {
                return Err(Error::Tpm(error.clone()));
            }
            Ok(self.original)
        }
        fn evict(&mut self, handle: u32, name: &[u8]) -> Result<bool> {
            if let Some(error) = &self.evict_error {
                return Err(Error::Tpm(error.clone()));
            }
            if self.objects.get(&handle).map(Vec::as_slice) != Some(name) {
                return Ok(false);
            }
            self.objects.remove(&handle);
            self.evicted.push(handle);
            Ok(true)
        }
        fn holds_da_exempt_key(&mut self, handle: u32, name: &[u8]) -> Result<bool> {
            Ok(self.objects.get(&handle).map(Vec::as_slice) == Some(name)
                && !self.other_shape.contains(&handle)
                && !self.other_auth.contains(&handle))
        }
        fn is_weak(&mut self, handle: u32) -> Result<bool> {
            Ok(self.objects.contains_key(&handle) && self.weak.contains(&handle))
        }
        fn derived_is_weak(&mut self) -> Result<bool> {
            Ok(self.derived_weak)
        }
        fn firmware(&mut self) -> Result<[u32; 2]> {
            Ok(self.firmware)
        }
        fn owner_names(&mut self) -> Result<Vec<(u32, Vec<u8>)>> {
            self.scans += 1;
            Ok(self.objects.iter().map(|(h, n)| (*h, n.clone())).collect())
        }
        fn persist(&mut self, handle: u32) -> std::result::Result<(), Failure> {
            let answer = if self.persist.is_empty() {
                Ok(())
            } else {
                self.persist.remove(0)
            };
            let name = self.derive.clone().expect("a derived key");
            match &answer {
                Ok(()) => {
                    self.objects.insert(handle, name);
                    self.persisted.push(handle);
                }
                Err(failure) if failure.class == FailureClass::Taken && self.concurrent => {
                    self.objects.insert(handle, name);
                }
                Err(_) => {}
            }
            answer
        }
    }

    fn run(tpm: &mut FakeTpm, record: &Record, boot: &str) -> (Record, Outcome) {
        ensure_with(tpm, record, Some(boot), &Ok(PLAN)).expect("the step runs")
    }

    fn reason(outcome: &Outcome) -> RefusalReason {
        match outcome {
            Outcome::Refused(refusal) | Outcome::Deferred(refusal) => refusal.reason,
            other => panic!("not a refusal: {other:?}"),
        }
    }

    /// ADR-0034 acceptance: `TPM_PT_HR_PERSISTENT_AVAIL` reading 0 does not
    /// stop the attempt. The key goes to the preferred handle, and the next
    /// start finds it by its name without deriving it again.
    #[test]
    fn a_zero_persistent_estimate_does_not_stop_the_persist() {
        let mut tpm = FakeTpm::new();
        tpm.avail = 0;
        let (record, outcome) = run(&mut tpm, &Record::default(), BOOT);
        assert_eq!(
            outcome,
            Outcome::Persisted {
                handle: 0x8101_0003
            }
        );
        assert_eq!(tpm.persisted, vec![0x8101_0003]);
        let (again, outcome) = run(&mut tpm, &record, BOOT);
        assert_eq!(
            outcome,
            Outcome::Present {
                handle: 0x8101_0003
            }
        );
        assert_eq!(again, record);
        assert_eq!(
            tpm.derived, 1,
            "a start with the key present derives nothing"
        );
    }

    /// #1083: a refusal that is not about room is recorded with the boot; a
    /// restart in the same boot derives nothing even when the TPM reports
    /// room, and the first start in a later boot tries again.
    #[test]
    fn a_non_capacity_refusal_waits_for_a_later_boot() {
        let mut tpm = FakeTpm::new();
        tpm.persist = vec![Err(failure(FailureClass::Other))];
        let (record, outcome) = run(&mut tpm, &Record::default(), BOOT);
        assert_eq!(reason(&outcome), RefusalReason::Other);
        tpm.avail = 1;
        let (same, outcome) = run(&mut tpm, &record, BOOT);
        assert!(matches!(outcome, Outcome::Deferred(_)), "{outcome:?}");
        assert_eq!(same, record);
        assert_eq!(tpm.derived, 1);
        let (_, outcome) = run(&mut tpm, &record, LATER_BOOT);
        assert_eq!(
            outcome,
            Outcome::Persisted {
                handle: 0x8101_0003
            }
        );
        assert_eq!(tpm.derived, 2);
    }

    /// #1083: after `TPM_RC_NV_SPACE` a same-boot restart retries only once
    /// the TPM reports room for at least one more object.
    #[test]
    fn a_capacity_refusal_retries_in_the_same_boot_only_with_room() {
        let mut tpm = FakeTpm::new();
        tpm.avail = 0;
        tpm.persist = vec![Err(failure(FailureClass::NoSpace))];
        let (record, outcome) = run(&mut tpm, &Record::default(), BOOT);
        assert_eq!(reason(&outcome), RefusalReason::NoSpace);
        let (_, outcome) = run(&mut tpm, &record, BOOT);
        assert!(matches!(outcome, Outcome::Deferred(_)), "{outcome:?}");
        assert_eq!(tpm.derived, 1);
        tpm.avail = 1;
        let (_, outcome) = run(&mut tpm, &record, BOOT);
        assert_eq!(
            outcome,
            Outcome::Persisted {
                handle: 0x8101_0003
            }
        );
        assert_eq!(tpm.derived, 2);
    }

    /// A refused derivation (an owner authorization set) is classified and
    /// recorded, so the same boot does not derive again (#1083).
    #[test]
    fn a_refused_derivation_is_classified_and_recorded() {
        let mut tpm = FakeTpm::new();
        tpm.derive = Err(failure(FailureClass::OwnerAuthorization));
        let (record, outcome) = run(&mut tpm, &Record::default(), BOOT);
        assert_eq!(reason(&outcome), RefusalReason::OwnerAuthorization);
        assert!(tpm.persisted.is_empty());
        let (_, outcome) = run(&mut tpm, &record, BOOT);
        assert!(matches!(outcome, Outcome::Deferred(_)), "{outcome:?}");
        assert_eq!(tpm.derived, 1);
    }

    /// With the preferred handle held by another stack's key the key goes to
    /// the next free one, and a handle taken between the scan and the command
    /// (`TPM_RC_NV_DEFINED`) moves it on again; the original key's handle is
    /// never used.
    #[test]
    fn taken_handles_move_the_key_to_the_next_free_one() {
        let mut tpm = FakeTpm::new();
        tpm.objects.insert(0x8101_0003, b"another stack".to_vec());
        tpm.persist = vec![Err(failure(FailureClass::Taken))];
        let (_, outcome) = run(&mut tpm, &Record::default(), BOOT);
        assert_eq!(
            outcome,
            Outcome::Persisted {
                handle: 0x8101_0005
            }
        );
        let top = Plan {
            preferred: 0x817F_FFFE,
            original: 0x817F_FFFF,
        };
        assert_eq!(
            first_free_owner_handle(top, &[0x817F_FFFE]),
            Some(0x8100_0000)
        );
        assert_eq!(first_free_owner_handle(PLAN, &[]), Some(0x8101_0003));
    }

    /// Two starts that overlap derive the same key and both see the preferred
    /// handle free. The one whose persist finds it taken by that same key
    /// adopts it there, and persists no second copy.
    #[test]
    fn a_raced_handle_holding_the_same_key_is_adopted() {
        let mut tpm = FakeTpm::new();
        tpm.concurrent = true;
        tpm.persist = vec![Err(failure(FailureClass::Taken))];
        let (record, outcome) = run(&mut tpm, &Record::default(), BOOT);
        assert_eq!(
            outcome,
            Outcome::Adopted {
                handle: 0x8101_0003
            }
        );
        assert!(tpm.persisted.is_empty(), "no second copy");
        assert_eq!(record.persisted.expect("recorded").handle, 0x8101_0003);
    }

    /// A power loss between `TPM2_EvictControl` and the record leaves a
    /// persisted key and no record: the next start adopts it by its name and
    /// persists no second copy.
    #[test]
    fn a_key_persisted_without_a_record_is_adopted() {
        let mut tpm = FakeTpm::new();
        tpm.objects.insert(0x8101_0007, b"ours".to_vec());
        let (record, outcome) = run(&mut tpm, &Record::default(), BOOT);
        assert_eq!(
            outcome,
            Outcome::Adopted {
                handle: 0x8101_0007
            }
        );
        assert!(tpm.persisted.is_empty());
        assert_eq!(record.persisted.expect("recorded").handle, 0x8101_0007);
    }

    /// A record whose handle now holds another key is not trusted: the key is
    /// derived and persisted again.
    #[test]
    fn a_recorded_handle_with_another_key_is_not_trusted() {
        let mut tpm = FakeTpm::new();
        tpm.objects.insert(0x8101_0003, b"another stack".to_vec());
        let stale = persisted_record(0x8101_0003, b"ours");
        let (record, outcome) = run(&mut tpm, &stale, BOOT);
        assert_eq!(
            outcome,
            Outcome::Persisted {
                handle: 0x8101_0004
            }
        );
        assert_eq!(record.persisted.expect("recorded").handle, 0x8101_0004);
        assert_eq!(tpm.derived, 1);
    }

    /// A refused `IRLUME_SRK_HANDLE` override persists nothing and asks the
    /// TPM nothing.
    #[test]
    fn a_refused_override_touches_no_tpm() {
        let mut tpm = FakeTpm::new();
        let refused = Err("IRLUME_SRK_HANDLE=\"zz\" does not parse".to_owned());
        let (record, outcome) =
            ensure_with(&mut tpm, &Record::default(), Some(BOOT), &refused).expect("runs");
        assert_eq!(reason(&outcome), RefusalReason::HandleOverride);
        assert_eq!(tpm.derived, 0);
        assert_eq!(
            record.refused.expect("recorded").boot_id.as_deref(),
            Some(BOOT)
        );
    }

    /// A refused override is checked again at every start: once it is
    /// corrected, a restart in the same boot persists the key, where a TPM
    /// refusal would wait for a later boot.
    #[test]
    fn a_corrected_override_is_tried_again_in_the_same_boot() {
        let mut tpm = FakeTpm::new();
        let refused = Err("IRLUME_SRK_HANDLE=\"zz\" does not parse".to_owned());
        let (record, _) =
            ensure_with(&mut tpm, &Record::default(), Some(BOOT), &refused).expect("runs");
        let (_, outcome) = run(&mut tpm, &record, BOOT);
        assert_eq!(
            outcome,
            Outcome::Persisted {
                handle: 0x8101_0003
            }
        );
        assert_eq!(tpm.derived, 1);
    }

    /// A missing envelope directory holds no envelope; one that cannot be
    /// read is an error, never an empty store that would skip the step.
    #[test]
    fn an_unreadable_envelope_store_is_an_error_not_empty() {
        let dir = std::path::PathBuf::from(crate::test_tmp_dir("storage-key-scan"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!has_envelope(&dir.join("missing")).expect("a missing store is empty"));
        assert!(!has_envelope(&dir).expect("an empty store"));
        std::fs::write(dir.join("alice.json"), b"{}").unwrap();
        assert!(has_envelope(&dir).expect("one envelope"));
        // Not a directory: read_dir fails with something other than NotFound,
        // as it does for root too, unlike a permission bit.
        assert!(has_envelope(&dir.join("alice.json")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no envelope left, the start-up step clears a recorded refusal,
    /// and doctor's report no longer carries one. A TPM that cannot be
    /// opened stops neither: the original key's check is advisory. With
    /// nothing to record, no record file is written.
    #[test]
    fn a_refusal_is_dropped_once_no_envelope_remains() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = crate::test_tmp_dir("storage-key-no-envelope");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vars = [
            "IRLUME_STATE_DIR",
            "IRLUME_TEMPLATE_KEY_DIR",
            "IRLUME_KEYRING_DIR",
        ];
        let previous: Vec<_> = vars.iter().map(std::env::var_os).collect();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", format!("{dir}/template-keys"));
        std::env::set_var("IRLUME_KEYRING_DIR", format!("{dir}/keyring"));
        let empty = ensure_at_start();
        let no_file = !record_path().exists();
        let refused = Record {
            version: RECORD_VERSION,
            persisted: None,
            original: None,
            refused: Some(Refused {
                reason: RefusalReason::Other,
                detail: "refused".into(),
                boot_id: Some(BOOT.into()),
            }),
            ..Record::default()
        };
        save_record(&refused).expect("saved");
        let reported = report();
        let outcome = ensure_at_start();
        let kept = load_record();
        for (var, value) in vars.iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(var, value),
                None => std::env::remove_var(var),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(empty.expect("the step"), None);
        assert!(no_file, "nothing to record writes no record");
        assert_eq!(reported.expect("report").refused, None);
        assert_eq!(outcome.expect("the step"), None);
        assert_eq!(kept.refused, None);
    }

    #[test]
    fn a_tpm_name_round_trips_through_hex() {
        let name = [0x00, 0x0b, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hex(&name), "000bdeadbeef");
        assert_eq!(unhex("000bdeadbeef").as_deref(), Some(&name[..]));
        assert_eq!(unhex("000BDEADBEEF").as_deref(), Some(&name[..]));
        for bad in ["0", "0g", "000bdeadbee", "é0"] {
            assert_eq!(unhex(bad), None, "{bad:?}");
        }
    }

    /// The census behind doctor's lockout reading: every envelope must name
    /// the key, an envelope without a parent or that cannot be parsed keeps
    /// it from counting, and empty stores count.
    #[test]
    fn every_envelope_must_name_the_key_for_a_lockout_to_spare_irlume() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = crate::test_tmp_dir("storage-key-census");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(format!("{dir}/keyring")).unwrap();
        std::fs::create_dir_all(format!("{dir}/template-keys")).unwrap();
        let vars = ["IRLUME_TEMPLATE_KEY_DIR", "IRLUME_KEYRING_DIR"];
        let previous: Vec<_> = vars.iter().map(std::env::var_os).collect();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", format!("{dir}/template-keys"));
        std::env::set_var("IRLUME_KEYRING_DIR", format!("{dir}/keyring"));
        let envelope = |parent: Option<&str>| {
            let mut value = serde_json::json!({
                "version": 1, "pcrs": [7], "public": "", "private": ""
            });
            if let Some(name) = parent {
                value["parent"] = serde_json::json!({"handle": 0x8101_0003_u32, "name": name});
            }
            serde_json::to_vec(&value).unwrap()
        };
        let empty = every_envelope_on(&["aa"]);
        std::fs::write(format!("{dir}/keyring/alice.json"), envelope(Some("aa"))).unwrap();
        std::fs::write(format!("{dir}/template-keys/alice.json"), envelope(None)).unwrap();
        let mixed = every_envelope_on(&["aa"]);
        std::fs::write(
            format!("{dir}/template-keys/alice.json"),
            envelope(Some("aa")),
        )
        .unwrap();
        let all = every_envelope_on(&["aa"]);
        let other = every_envelope_on(&["bb"]);
        std::fs::write(format!("{dir}/keyring/bob.json"), b"not an envelope").unwrap();
        let unparsable = every_envelope_on(&["aa"]);
        for (var, value) in vars.iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(var, value),
                None => std::env::remove_var(var),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(empty.expect("census"), "no envelope blocks nothing");
        assert!(!mixed.expect("census"), "an envelope on the original key");
        assert!(all.expect("census"), "every envelope names the key");
        assert!(!other.expect("census"), "another key's name");
        assert!(
            !unparsable.expect("census"),
            "an envelope that cannot be read"
        );
    }

    /// ADR-0034 §4: doctor names the envelopes still under the original key,
    /// by account and kind, sorted. An envelope on a key is not named, one
    /// that cannot be parsed is not counted, a file name that is no account
    /// name is counted but not named, and the names stop at the cap.
    #[test]
    fn the_envelopes_on_the_original_key_are_named_by_account_and_kind() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = crate::test_tmp_dir("storage-key-named");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(format!("{dir}/keyring")).unwrap();
        std::fs::create_dir_all(format!("{dir}/template-keys")).unwrap();
        let vars = ["IRLUME_TEMPLATE_KEY_DIR", "IRLUME_KEYRING_DIR"];
        let previous: Vec<_> = vars.iter().map(std::env::var_os).collect();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", format!("{dir}/template-keys"));
        std::env::set_var("IRLUME_KEYRING_DIR", format!("{dir}/keyring"));
        let envelope = |on_key: bool| {
            let mut value = serde_json::json!({
                "version": 1, "pcrs": [7], "public": "", "private": ""
            });
            if on_key {
                value["parent"] = serde_json::json!({"handle": 0x8101_0003_u32, "name": "aa"});
            }
            serde_json::to_vec(&value).unwrap()
        };
        let write = |path: &str, bytes: &[u8]| std::fs::write(format!("{dir}/{path}"), bytes);
        let empty = on_original_key();
        write("template-keys/carol.json", &envelope(false)).unwrap();
        write("keyring/carol.json", &envelope(false)).unwrap();
        write("keyring/alice.json", &envelope(false)).unwrap();
        write("template-keys/alice.json", &envelope(true)).unwrap();
        write("keyring/bob.json", b"not an envelope").unwrap();
        write("keyring/-planted\u{1b}.json", &envelope(false)).unwrap();
        let some = on_original_key();
        for n in 0..MAX_NAMED_ENVELOPES {
            write(&format!("keyring/user{n:02}.json"), &envelope(false)).unwrap();
        }
        let many = on_original_key();
        for (var, value) in vars.iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(var, value),
                None => std::env::remove_var(var),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);

        let empty = empty.expect("census");
        assert_eq!((empty.named.len(), empty.total), (0, 0));
        let some = some.expect("census");
        let named: Vec<_> = some
            .named
            .iter()
            .map(|envelope| (envelope.user.as_str(), envelope.kind))
            .collect();
        assert_eq!(
            named,
            [
                ("alice", EnvelopeKind::KeyringSecret),
                ("carol", EnvelopeKind::TemplateKey),
                ("carol", EnvelopeKind::KeyringSecret),
            ]
        );
        assert_eq!(some.total, 4, "the planted name counts but is not named");
        let many = many.expect("census");
        assert_eq!(many.named.len(), MAX_NAMED_ENVELOPES);
        assert_eq!(many.total, 4 + MAX_NAMED_ENVELOPES as u32);
    }

    /// ADR-0034 §3.3, recovery by name with the TPM faked: a template key
    /// whose recorded handle holds another key records the handle where a key
    /// with its name is, keeping everything else; a keyring envelope in the
    /// same state is left as it is, since its writers are ordered only by
    /// irlumed's worker; one whose key is at its handle is not rewritten; one
    /// whose key is nowhere, or whose name is not hex, is reported missing and
    /// left as it was; an envelope with no parent, one that cannot be parsed
    /// and a file that is no account's are left alone. The owner handles are
    /// scanned once.
    #[test]
    fn an_envelope_whose_handle_another_key_took_records_where_its_key_is() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = crate::test_tmp_dir("storage-key-repoint");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(format!("{dir}/keyring")).unwrap();
        std::fs::create_dir_all(format!("{dir}/template-keys")).unwrap();
        let vars = ["IRLUME_TEMPLATE_KEY_DIR", "IRLUME_KEYRING_DIR"];
        let previous: Vec<_> = vars.iter().map(std::env::var_os).collect();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", format!("{dir}/template-keys"));
        std::env::set_var("IRLUME_KEYRING_DIR", format!("{dir}/keyring"));
        let envelope = |parent: Option<(u32, &str)>| {
            let mut value = serde_json::json!({
                "version": 1, "pcrs": [7], "public": "", "private": "", "uid": 4170
            });
            if let Some((handle, name)) = parent {
                value["parent"] = serde_json::json!({"handle": handle, "name": name});
            }
            serde_json::to_vec(&value).unwrap()
        };
        let path = |name: &str| format!("{dir}/{name}");
        let write = |name: &str, bytes: &[u8]| std::fs::write(path(name), bytes).unwrap();
        let read = |name: &str| std::fs::read(path(name)).unwrap();
        write(
            "template-keys/alice.json",
            &envelope(Some((0x8101_0003, "aa"))),
        );
        write("keyring/alice.json", &envelope(Some((0x8101_0004, "aa"))));
        write("keyring/bob.json", &envelope(Some((0x8101_0003, "bb"))));
        write("keyring/frank.json", &envelope(Some((0x8101_0003, "aa"))));
        write("keyring/carol.json", &envelope(None));
        write(
            "keyring/dave.json",
            &envelope(Some((0x8101_0004, "not hex"))),
        );
        write("keyring/erin.json", b"not an envelope");
        write(
            "keyring/-planted.json",
            &envelope(Some((0x8101_0003, "aa"))),
        );
        let untouched: Vec<_> = [
            "keyring/alice.json",
            "keyring/bob.json",
            "keyring/carol.json",
            "keyring/dave.json",
            "keyring/erin.json",
            "keyring/frank.json",
            "keyring/-planted.json",
        ]
        .into_iter()
        .map(|name| (name, read(name)))
        .collect();
        let mut tpm = FakeTpm::new();
        // Another stack's key took the handle; irlume's key is at the next.
        tpm.objects.insert(0x8101_0003, b"theirs".to_vec());
        tpm.objects.insert(0x8101_0004, vec![0xaa]);
        let repointed = recorded_parents().and_then(|found| repoint_with(&mut tpm, found));
        let moved =
            crate::envelope::SealedEnvelope::load(Path::new(&path("template-keys/alice.json")));
        let unchanged: Vec<_> = untouched
            .iter()
            .filter(|(name, before)| read(name) != *before)
            .map(|(name, _)| *name)
            .collect();
        let mut again = FakeTpm::new();
        again.objects = tpm.objects.clone();
        let second = recorded_parents().and_then(|found| repoint_with(&mut again, found));
        for (var, value) in vars.iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(var, value),
                None => std::env::remove_var(var),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);

        let entry = |user: &str, kind, from, outcome| Repointed {
            user: user.into(),
            kind,
            from,
            outcome,
        };
        assert_eq!(
            repointed.expect("the step"),
            [
                entry(
                    "alice",
                    EnvelopeKind::TemplateKey,
                    0x8101_0003,
                    RepointOutcome::Moved(0x8101_0004)
                ),
                entry(
                    "bob",
                    EnvelopeKind::KeyringSecret,
                    0x8101_0003,
                    RepointOutcome::Missing
                ),
                entry(
                    "dave",
                    EnvelopeKind::KeyringSecret,
                    0x8101_0004,
                    RepointOutcome::Missing
                ),
            ]
        );
        assert_eq!(tpm.scans, 1, "the owner handles are scanned once");
        let moved = moved.expect("the rewritten envelope");
        let parent = moved.parent.expect("its parent");
        assert_eq!((parent.handle, parent.name.as_str()), (0x8101_0004, "aa"));
        assert_eq!(moved.uid, Some(4170), "everything else is kept");
        assert!(unchanged.is_empty(), "rewritten: {unchanged:?}");
        let second = second.expect("the next start");
        assert!(
            second
                .iter()
                .all(|entry| entry.outcome == RepointOutcome::Missing),
            "only the missing ones again: {second:?}"
        );
    }

    /// ADR-0034 §3.4: the original key's TPM name is recorded at the first
    /// start that derived nothing else and whose derivation matches it. The
    /// entry stays, with no derivation, while the key at the handle has that
    /// name or the handle is free. Another key there that today's derivation
    /// does not give is kept as checked, not as recorded, and not derived
    /// again; a key without the original template's shape is not recorded.
    #[test]
    fn the_original_key_is_recorded_once_by_a_start_that_derives_nothing_else() {
        const ORIGINAL: u32 = 0x8101_0002;
        let mut tpm = FakeTpm::new();
        tpm.objects.insert(ORIGINAL, b"orig".to_vec());
        let first = original_with(&mut tpm, ORIGINAL, None, true);
        let derived_first = tpm.original_derivations;
        let recorded = original_with(&mut tpm, ORIGINAL, None, false).expect("checked");
        let derived_once = tpm.original_derivations;
        let kept = original_with(&mut tpm, ORIGINAL, recorded.clone(), false);
        tpm.objects.remove(&ORIGINAL);
        let evicted = original_with(&mut tpm, ORIGINAL, recorded.clone(), false);
        let derived_while_kept = tpm.original_derivations;
        tpm.objects.insert(ORIGINAL, b"other".to_vec());
        tpm.original = Some(false);
        let checked = original_with(&mut tpm, ORIGINAL, recorded.clone(), false).expect("checked");
        let checked_again = original_with(&mut tpm, ORIGINAL, checked.clone(), false);
        let derived_after = tpm.original_derivations;
        tpm.original = None;
        tpm.objects.insert(ORIGINAL, b"foreign".to_vec());
        let foreign = original_with(&mut tpm, ORIGINAL, None, false);

        assert_eq!(first.expect("checked"), None, "a start that derived waits");
        assert_eq!(derived_first, 0);
        assert_eq!(
            recorded,
            Some(Original {
                handle: ORIGINAL,
                name: hex(b"orig"),
                matched: true
            })
        );
        assert_eq!(derived_once, 1);
        assert_eq!(kept.expect("checked"), recorded);
        assert_eq!(evicted.expect("checked"), recorded);
        assert_eq!(derived_while_kept, 1, "no derivation while it is kept");
        assert_eq!(
            checked,
            Some(Original {
                handle: ORIGINAL,
                name: hex(b"other"),
                matched: false
            })
        );
        assert_eq!(checked_again.expect("checked"), checked);
        assert_eq!(
            derived_after, 2,
            "a key that does not match is not derived again"
        );
        assert_eq!(foreign.expect("checked"), None);
        assert!(!derived_now(&Outcome::Present { handle: 1 }));
        assert!(!derived_now(&Outcome::Deferred(KeyRefusal {
            reason: RefusalReason::NoSpace,
            detail: String::new()
        })));
        assert!(derived_now(&Outcome::Persisted { handle: 1 }));
        assert!(derived_now(&Outcome::Adopted { handle: 1 }));
    }

    /// The original key's entry is additive: a record without it, as an
    /// earlier release wrote, reads with none, and one with it reads back.
    #[test]
    fn a_record_reads_with_and_without_the_original_key() {
        let older: Record = serde_json::from_value(serde_json::json!({
            "version": 1, "persisted": {"handle": 0x8101_0003_u32, "name": "aa"}
        }))
        .expect("an older record");
        assert_eq!(older.original, None);
        let newer = Record {
            original: Some(Original {
                handle: 0x8101_0002,
                name: "bb".into(),
                matched: true,
            }),
            ..older
        };
        let back: Record =
            serde_json::from_slice(&serde_json::to_vec(&newer).unwrap()).expect("the record");
        assert_eq!(back, newer);
    }

    /// An oversized envelope or record in the state directory is refused by
    /// size before it is read: the census counts the envelope as not on the
    /// key, and the record reads as none.
    #[test]
    fn oversized_state_files_are_refused_unread() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = crate::test_tmp_dir("storage-key-oversized");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(format!("{dir}/keyring")).unwrap();
        std::fs::create_dir_all(format!("{dir}/template-keys")).unwrap();
        let vars = [
            "IRLUME_STATE_DIR",
            "IRLUME_TEMPLATE_KEY_DIR",
            "IRLUME_KEYRING_DIR",
        ];
        let previous: Vec<_> = vars.iter().map(std::env::var_os).collect();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", format!("{dir}/template-keys"));
        std::env::set_var("IRLUME_KEYRING_DIR", format!("{dir}/keyring"));
        // Sparse files: the length comes from the open file, so the test
        // never writes or reads the bytes.
        let sparse = |path: String, len: u64| {
            std::fs::File::create(path).unwrap().set_len(len).unwrap();
        };
        sparse(
            format!("{dir}/keyring/alice.json"),
            crate::envelope::MAX_ENVELOPE_BYTES + 1,
        );
        sparse(format!("{dir}/tpm-storage-key"), MAX_RECORD_BYTES + 1);
        let census = every_envelope_on(&["aa"]);
        let record = load_record();
        for (var, value) in vars.iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(var, value),
                None => std::env::remove_var(var),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !census.expect("census"),
            "an oversized envelope is not on the key"
        );
        assert_eq!(
            record,
            Record::default(),
            "an oversized record reads as none"
        );
    }

    /// The record lock excludes a second holder until the first is dropped,
    /// so overlapping starts run the step one after the other.
    #[test]
    fn the_record_lock_serializes_starts() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = crate::test_tmp_dir("storage-key-lock");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let previous = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        let first = RecordLock::acquire().expect("first holder");
        let released = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&released);
        let second = std::thread::spawn(move || {
            let _lock = RecordLock::acquire().expect("second holder");
            seen.load(Ordering::SeqCst)
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        released.store(true, Ordering::SeqCst);
        drop(first);
        let after_release = second.join().expect("second thread");
        match previous {
            Some(previous) => std::env::set_var("IRLUME_STATE_DIR", previous),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            after_release,
            "the second holder ran only after the first let go"
        );
    }

    /// A refusal detail goes out as one bounded line with no control
    /// characters, from the record (untrusted where the state directory is
    /// writable offline) and from the TPM's own words alike.
    #[test]
    fn a_refusal_detail_is_one_bounded_line() {
        let mut tpm = FakeTpm::new();
        tpm.derive = Err(Failure {
            class: FailureClass::Other,
            detail: format!("bad\x1b[2Jdetail\n{}", "x".repeat(1000)),
        });
        let (record, outcome) = run(&mut tpm, &Record::default(), BOOT);
        let Outcome::Refused(refusal) = outcome else {
            panic!("refused");
        };
        for detail in [refusal.detail, record.refused.expect("recorded").detail] {
            assert!(!detail.chars().any(char::is_control), "{detail:?}");
            assert!(
                detail.chars().count() <= MAX_DETAIL_CHARS + 3,
                "{}",
                detail.len()
            );
        }
    }

    /// A refused `IRLUME_SRK_HANDLE` is recorded without opening the TPM, so
    /// a transport that cannot be opened does not hide it from doctor.
    #[test]
    fn a_refused_override_is_recorded_when_the_tpm_cannot_be_opened() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = crate::test_tmp_dir("storage-key-override");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(format!("{dir}/keyring")).unwrap();
        std::fs::write(format!("{dir}/keyring/alice.json"), b"{}").unwrap();
        let vars = [
            "IRLUME_STATE_DIR",
            "IRLUME_TEMPLATE_KEY_DIR",
            "IRLUME_KEYRING_DIR",
            "IRLUME_SRK_HANDLE",
        ];
        let previous: Vec<_> = vars.iter().map(std::env::var_os).collect();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", format!("{dir}/template-keys"));
        std::env::set_var("IRLUME_KEYRING_DIR", format!("{dir}/keyring"));
        std::env::set_var("IRLUME_SRK_HANDLE", "0x81800000");
        let outcome = ensure_at_start();
        let reported = report();
        for (var, value) in vars.iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(var, value),
                None => std::env::remove_var(var),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        let Some(Outcome::Refused(refusal)) = outcome.expect("the step runs") else {
            panic!("a refused override is recorded");
        };
        assert_eq!(refusal.reason, RefusalReason::HandleOverride);
        assert_eq!(
            reported.expect("report").refused.map(|r| r.reason),
            Some(RefusalReason::HandleOverride)
        );
    }

    /// A record edited to carry terminal control characters reaches doctor's
    /// report as one bounded line.
    #[test]
    fn a_tampered_refusal_detail_is_reported_as_one_line() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = crate::test_tmp_dir("storage-key-tampered");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(format!("{dir}/template-keys")).unwrap();
        std::fs::write(format!("{dir}/template-keys/alice.json"), b"{}").unwrap();
        let vars = [
            "IRLUME_STATE_DIR",
            "IRLUME_TEMPLATE_KEY_DIR",
            "IRLUME_KEYRING_DIR",
        ];
        let previous: Vec<_> = vars.iter().map(std::env::var_os).collect();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", format!("{dir}/template-keys"));
        std::env::set_var("IRLUME_KEYRING_DIR", format!("{dir}/keyring"));
        let tampered = format!(
            r#"{{"version":1,"refused":{{"reason":"other","detail":"\u001b]0;owned\u0007\r\n{}"}}}}"#,
            "y".repeat(2000)
        );
        std::fs::write(record_path(), tampered).unwrap();
        let reported = report();
        for (var, value) in vars.iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(var, value),
                None => std::env::remove_var(var),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        let detail = reported
            .expect("report")
            .refused
            .expect("the refusal is reported")
            .detail;
        assert!(!detail.chars().any(char::is_control), "{detail:?}");
        assert!(detail.chars().count() <= MAX_DETAIL_CHARS + 3);
    }

    /// The record is not a `*.json` file in the state directory, which
    /// `storage::list_users` would read as an account, and it round-trips.
    /// The state, template-key and keyring directories in a fresh temporary
    /// tree until dropped. Hold `testenv::ENV_LOCK` first.
    struct Sandbox {
        dir: String,
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl Sandbox {
        fn new(name: &str) -> Self {
            let dir = crate::test_tmp_dir(name);
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(format!("{dir}/keyring")).unwrap();
            std::fs::create_dir_all(format!("{dir}/template-keys")).unwrap();
            let vars = [
                ("IRLUME_STATE_DIR", dir.clone()),
                ("IRLUME_TEMPLATE_KEY_DIR", format!("{dir}/template-keys")),
                ("IRLUME_KEYRING_DIR", format!("{dir}/keyring")),
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
    }

    impl Drop for Sandbox {
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

    /// An envelope under the DA-exempt key (`on_key`), as the tests' records
    /// name it (`persisted_record(0x8101_0003, b"ours")`), or the original one.
    fn envelope(on_key: bool) -> crate::envelope::SealedEnvelope {
        let mut value = serde_json::json!({
            "version": 1, "pcrs": [7], "public": "", "private": ""
        });
        if on_key {
            value["parent"] = serde_json::json!({"handle": 0x8101_0003_u32, "name": hex(b"ours")});
        }
        serde_json::from_value(value).unwrap()
    }

    /// The unsettled moves the record on disk holds, by account, kind and boot.
    fn entries() -> Vec<(String, EnvelopeKind, Option<String>)> {
        load_record()
            .moves
            .into_iter()
            .map(|entry| (entry.user, entry.kind, entry.boot_id))
            .collect()
    }

    fn entry(user: &str, kind: EnvelopeKind, boot: &str) -> (String, EnvelopeKind, Option<String>) {
        (user.to_owned(), kind, Some(boot.to_owned()))
    }

    /// Publishes `next` at `path` in `boot`, through the real record, with a
    /// write that answers `durable` or a visible write whose sync failed.
    /// Returns what the record held when the envelope was written, or `None`
    /// when the write did not run.
    fn publish_in(
        path: &Path,
        kind: EnvelopeKind,
        user: &str,
        next: &crate::envelope::SealedEnvelope,
        boot: &str,
        durable: bool,
    ) -> (Result<irlume_common::AtomicWrite>, Option<Record>) {
        let mut seen = None;
        let result = publish_with(
            path,
            kind,
            user,
            next,
            Some(boot),
            save_record,
            |env, path| {
                seen = Some(load_record());
                env.save(path)?;
                Ok(if durable {
                    irlume_common::AtomicWrite::Durable
                } else {
                    irlume_common::AtomicWrite::VisibleNotDurable(std::io::Error::other(
                        "the directory sync failed",
                    ))
                })
            },
        );
        (result, seen)
    }

    /// ADR-0034, Phase 3 amendment, condition 1: a move off the original key
    /// writes the record first, with `unused_since` cleared and the
    /// envelope's entry set to its boot; a durable write removes only its own
    /// envelope's entry, one that is not durable keeps it, and a later
    /// durable move of the same envelope removes it. A record write that
    /// fails stops the move. A write that is not a move off the key, or one
    /// with no DA-exempt key recorded, writes no record and takes no lock.
    #[test]
    fn a_move_off_the_original_key_is_recorded_before_it_publishes() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sandbox = Sandbox::new("storage-key-move-entries");
        save_record(&Record {
            unused_since: Some(BOOT.into()),
            ..persisted_record(0x8101_0003, b"ours")
        })
        .unwrap();
        let alice = template_key::key_path("alice");
        let bob = keyring::envelope_path("bob");
        let carol = keyring::envelope_path("carol");
        envelope(false).save(&alice).unwrap();
        envelope(false).save(&bob).unwrap();
        std::fs::write(&carol, b"not an envelope").unwrap();
        let (template, keyring) = (EnvelopeKind::TemplateKey, EnvelopeKind::KeyringSecret);

        let (not_durable, seen_first) =
            publish_in(&alice, template, "alice", &envelope(true), BOOT, false);
        let after_first = entries();
        let (durable, seen_second) = publish_in(&bob, keyring, "bob", &envelope(true), BOOT, true);
        let after_second = entries();
        // The unreadable envelope counts as under the original key.
        let (unreadable, _) = publish_in(&carol, keyring, "carol", &envelope(true), BOOT, true);
        let after_unreadable = entries();
        // A power loss brings alice's old envelope back; its next move is durable.
        envelope(false).save(&alice).unwrap();
        let (again, _) = publish_in(&alice, template, "alice", &envelope(true), LATER_BOOT, true);
        let after_again = entries();
        // A record write that fails stops the move.
        envelope(false).save(&bob).unwrap();
        let before_refused = std::fs::read(&bob).unwrap();
        let mut wrote = false;
        let refused = publish_with(
            &bob,
            keyring,
            "bob",
            &envelope(true),
            Some(BOOT),
            |_| Err(Error::Io("no space".into())),
            |_, _| {
                wrote = true;
                Ok(irlume_common::AtomicWrite::Durable)
            },
        );
        let bob_unchanged = std::fs::read(&bob).unwrap() == before_refused;
        // Not a move off the key: already on the DA-exempt key, or onto the
        // original key again.
        let saves = std::cell::Cell::new(0);
        let counting = |record: &Record| {
            saves.set(saves.get() + 1);
            save_record(record)
        };
        let written =
            |_: &crate::envelope::SealedEnvelope, _: &Path| Ok(irlume_common::AtomicWrite::Durable);
        let on_key = publish_with(
            &alice,
            template,
            "alice",
            &envelope(true),
            Some(BOOT),
            counting,
            written,
        );
        let onto_original = publish_with(
            &bob,
            keyring,
            "bob",
            &envelope(false),
            Some(BOOT),
            counting,
            written,
        );
        // No DA-exempt key recorded: no record write, and no lock taken.
        let _ = std::fs::remove_file(record_path());
        let lock = irlume_common::state_dir().join(".tpm-storage-key.lock");
        let _ = std::fs::remove_file(&lock);
        let unrecorded = publish_with(
            &bob,
            keyring,
            "bob",
            &envelope(true),
            Some(BOOT),
            counting,
            written,
        );
        let no_lock = !lock.exists();
        drop(sandbox);

        assert!(matches!(
            not_durable.expect("published"),
            irlume_common::AtomicWrite::VisibleNotDurable(_)
        ));
        let seen_first = seen_first.expect("the write ran");
        assert_eq!(seen_first.unused_since, None, "cleared before the write");
        assert_eq!(seen_first.moves.len(), 1, "the entry before the write");
        assert_eq!(
            after_first,
            [entry("alice", template, BOOT)],
            "a write that is not durable keeps it"
        );
        assert!(matches!(
            durable.expect("published"),
            irlume_common::AtomicWrite::Durable
        ));
        assert_eq!(seen_second.expect("the write ran").moves.len(), 2);
        assert_eq!(
            after_second,
            [entry("alice", template, BOOT)],
            "a durable move removes only its own entry"
        );
        assert!(unreadable.is_ok());
        assert_eq!(
            after_unreadable, after_second,
            "the unreadable one moved durably"
        );
        assert!(again.is_ok());
        assert_eq!(
            after_again,
            [],
            "a later durable move of the same envelope settles it"
        );
        assert!(refused.is_err(), "a failed record write stops the move");
        assert!(!wrote && bob_unchanged, "nothing is published");
        assert!(on_key.is_ok() && onto_original.is_ok() && unrecorded.is_ok());
        assert_eq!(saves.get(), 0, "no record write without a move off the key");
        assert!(no_lock, "no lock without a recorded DA-exempt key");
    }

    /// A write that moves an envelope to another key publishes only onto the
    /// key the record holds now, checked under the record lock that the
    /// start-up step holds, so a start that superseded the candidate's key
    /// since it was sealed makes it no move: the envelope stays as it was. A
    /// write that keeps the envelope's key is not a move.
    #[test]
    fn a_move_publishes_only_onto_the_recorded_key() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sandbox = Sandbox::new("storage-key-move-target");
        save_record(&Record {
            superseded: vec![Persisted {
                handle: 0x8101_0004,
                name: hex(b"weak"),
            }],
            ..persisted_record(0x8101_0003, b"ours")
        })
        .unwrap();
        let under = |name: &[u8]| {
            let mut env = envelope(true);
            if let Some(parent) = env.parent.as_mut() {
                parent.name = hex(name);
            }
            env
        };
        let write = |env: &crate::envelope::SealedEnvelope, path: &Path| env.save_reporting(path);
        let kind = EnvelopeKind::KeyringSecret;
        let alice = keyring::envelope_path("alice");
        let bob = keyring::envelope_path("bob");
        let carol = keyring::envelope_path("carol");
        envelope(false).save(&alice).unwrap();
        under(b"weak").save(&bob).unwrap();
        under(b"ours").save(&carol).unwrap();
        let bytes = |path: &Path| std::fs::read(path).unwrap();
        let (alice_before, carol_before) = (bytes(&alice), bytes(&carol));
        let record_before = load_record();

        let onto_unrecorded = publish_with(
            &alice,
            kind,
            "alice",
            &under(b"theirs"),
            Some(BOOT),
            save_record,
            write,
        );
        let alice_kept = bytes(&alice) == alice_before;
        let record_kept = load_record() == record_before;
        let off_superseded = publish_with(
            &bob,
            kind,
            "bob",
            &under(b"ours"),
            Some(BOOT),
            save_record,
            write,
        );
        let onto_superseded = publish_with(
            &carol,
            kind,
            "carol",
            &under(b"weak"),
            Some(BOOT),
            save_record,
            write,
        );
        let carol_kept = bytes(&carol) == carol_before;
        let rewrap = publish_with(
            &carol,
            kind,
            "carol",
            &under(b"ours"),
            Some(BOOT),
            save_record,
            write,
        );
        drop(sandbox);

        assert!(
            onto_unrecorded.is_err(),
            "onto a key the record does not hold"
        );
        assert!(alice_kept && record_kept, "nothing is written for it");
        assert!(
            off_superseded.is_ok(),
            "off a superseded key onto the recorded one"
        );
        assert!(
            onto_superseded.is_err() && carol_kept,
            "never onto a superseded key"
        );
        assert!(rewrap.is_ok(), "a write that keeps its key is not a move");
    }

    /// Condition 1's census: an envelope under the original key clears the
    /// mark; an empty census drops the entries of another boot's moves and
    /// marks this boot when no entry that may be this boot's is left, keeps
    /// an earlier mark, and marks nothing in a boot it cannot read.
    #[test]
    fn a_census_marks_the_original_key_unused_outside_an_unsettled_boot() {
        let kind = EnvelopeKind::KeyringSecret;
        let pending = |boot: Option<&str>| UnsettledMove {
            user: "bob".into(),
            kind,
            boot_id: boot.map(str::to_owned),
        };
        let with = |unused_since: Option<&str>, moves: Vec<UnsettledMove>| Record {
            unused_since: unused_since.map(str::to_owned),
            moves,
            ..persisted_record(0x8101_0003, b"ours")
        };
        let unused = |since: &str| Census::Unused {
            since: since.into(),
        };

        let (in_use, census) = mark_with(&with(Some(BOOT), vec![]), true, Some(LATER_BOOT));
        assert_eq!((in_use.unused_since, census), (None, Census::InUse));

        let (marked, census) = mark_with(&with(None, vec![]), false, Some(BOOT));
        assert_eq!(
            (marked.unused_since.as_deref(), census),
            (Some(BOOT), unused(BOOT))
        );

        let (kept, census) = mark_with(&with(Some(BOOT), vec![]), false, Some(LATER_BOOT));
        assert_eq!(
            (kept.unused_since.as_deref(), census),
            (Some(BOOT), unused(BOOT))
        );

        let (unsettled, census) =
            mark_with(&with(None, vec![pending(Some(BOOT))]), false, Some(BOOT));
        assert_eq!(
            census,
            Census::Unsettled,
            "a move in this boot is not yet durable"
        );
        assert_eq!((unsettled.unused_since, unsettled.moves.len()), (None, 1));

        let (dropped, census) = mark_with(
            &with(None, vec![pending(Some(BOOT))]),
            false,
            Some(LATER_BOOT),
        );
        assert_eq!(
            census,
            unused(LATER_BOOT),
            "another boot's move is on disk now"
        );
        assert!(dropped.moves.is_empty());

        let (unknown, census) =
            mark_with(&with(None, vec![pending(None)]), false, Some(LATER_BOOT));
        assert_eq!(
            census,
            Census::Unsettled,
            "a move whose boot was unreadable may be this boot's"
        );
        assert_eq!(unknown.moves.len(), 1, "and is kept");

        let (no_boot, census) = mark_with(&with(None, vec![]), false, None);
        assert_eq!((no_boot.unused_since, census), (None, Census::Unsettled));
    }

    /// The census of [`settle_in`] in boot `boot`, where no retirement is due.
    fn mark_in(boot: Option<&str>) -> Result<Option<Census>> {
        settle_in(
            boot,
            false,
            || -> Result<FakeTpm> { panic!("no retirement is due, so no TPM is opened") },
            save_record,
        )
        .map(|settled| settled.map(|settled| settled.census))
    }

    /// Condition 1 over boots, with fake boot IDs: a durable move is marked
    /// at a start in its boot, a move that is not durable is marked only in
    /// the next boot, and a durable move of another envelope in the same
    /// boot, after a restart, does not change that. A census that finds an
    /// envelope, or one it cannot read, marks nothing; with no DA-exempt key
    /// recorded nothing is counted or written.
    #[test]
    fn the_original_key_is_marked_unused_a_boot_later_after_a_move_that_was_not_durable() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sandbox = Sandbox::new("storage-key-marks");
        let unrecorded = mark_in(Some(BOOT));
        let no_record = !record_path().exists();
        save_record(&persisted_record(0x8101_0003, b"ours")).unwrap();
        let (template, keyring) = (EnvelopeKind::TemplateKey, EnvelopeKind::KeyringSecret);
        let alice = template_key::key_path("alice");
        let bob = keyring::envelope_path("bob");
        let carol = keyring::envelope_path("carol");
        envelope(false).save(&alice).unwrap();
        envelope(false).save(&bob).unwrap();
        envelope(true).save(&carol).unwrap();

        // Boot A's start moves alice's template key; bob's keyring waits.
        let (moved, _) = publish_in(&alice, template, "alice", &envelope(true), BOOT, true);
        let first_start = mark_in(Some(BOOT));
        // A login moves bob's keyring secret, and its sync fails.
        let (login, _) = publish_in(&bob, keyring, "bob", &envelope(true), BOOT, false);
        let restart = mark_in(Some(BOOT));
        // After another restart, carol's keyring moves durably in the same boot.
        envelope(false).save(&carol).unwrap();
        let (carol_moved, _) = publish_in(&carol, keyring, "carol", &envelope(true), BOOT, true);
        let mixed = mark_in(Some(BOOT));
        // The next boot's start reads what the disk kept.
        let next_boot = mark_in(Some(LATER_BOOT));
        let marked = load_record();
        // An envelope that cannot be read counts as under the original key.
        std::fs::write(&carol, b"not an envelope").unwrap();
        let unreadable = mark_in(Some(LATER_BOOT));
        let cleared = load_record();
        drop(sandbox);

        assert_eq!(unrecorded.expect("the census"), None);
        assert!(no_record, "nothing is written without a recorded key");
        assert!(moved.is_ok() && login.is_ok() && carol_moved.is_ok());
        assert_eq!(first_start.expect("the census"), Some(Census::InUse));
        assert_eq!(restart.expect("the census"), Some(Census::Unsettled));
        assert_eq!(mixed.expect("the census"), Some(Census::Unsettled));
        assert_eq!(
            next_boot.expect("the census"),
            Some(Census::Unused {
                since: LATER_BOOT.into()
            })
        );
        assert!(
            marked.moves.is_empty(),
            "the earlier boot's entry is dropped"
        );
        assert_eq!(unreadable.expect("the census"), Some(Census::InUse));
        assert_eq!(cleared.unused_since, None);
    }

    /// A borrowed fake, so a test can open it for [`settle_in`] and read it
    /// after.
    impl KeyTpm for &mut FakeTpm {
        fn name_at(&mut self, handle: u32) -> Result<Option<Vec<u8>>> {
            (**self).name_at(handle)
        }
        fn persistent_avail(&mut self) -> Result<u32> {
            (**self).persistent_avail()
        }
        fn derive(&mut self) -> std::result::Result<Vec<u8>, Failure> {
            (**self).derive()
        }
        fn owner_names(&mut self) -> Result<Vec<(u32, Vec<u8>)>> {
            (**self).owner_names()
        }
        fn persist(&mut self, handle: u32) -> std::result::Result<(), Failure> {
            (**self).persist(handle)
        }
        fn derives_original(&mut self, handle: u32) -> Result<Option<bool>> {
            (**self).derives_original(handle)
        }
        fn evict(&mut self, handle: u32, name: &[u8]) -> Result<bool> {
            (**self).evict(handle, name)
        }
        fn holds_da_exempt_key(&mut self, handle: u32, name: &[u8]) -> Result<bool> {
            (**self).holds_da_exempt_key(handle, name)
        }
        fn is_weak(&mut self, handle: u32) -> Result<bool> {
            (**self).is_weak(handle)
        }
        fn derived_is_weak(&mut self) -> Result<bool> {
            (**self).derived_is_weak()
        }
        fn firmware(&mut self) -> Result<[u32; 2]> {
            (**self).firmware()
        }
    }

    const ORIGINAL: u32 = 0x8101_0002;
    const DA_EXEMPT: u32 = 0x8101_0003;

    /// A record of a persisted DA-exempt key and an original key kept as
    /// matching today's derivation, unused since `since`.
    fn retiring_record(since: Option<&str>) -> Record {
        Record {
            original: Some(Original {
                handle: ORIGINAL,
                name: hex(b"orig"),
                matched: true,
            }),
            unused_since: since.map(str::to_owned),
            ..persisted_record(DA_EXEMPT, b"ours")
        }
    }

    /// A TPM holding both keys as [`retiring_record`] names them.
    fn retiring_tpm() -> FakeTpm {
        let mut tpm = FakeTpm::new();
        tpm.objects.insert(DA_EXEMPT, b"ours".to_vec());
        tpm.objects.insert(ORIGINAL, b"orig".to_vec());
        tpm
    }

    /// [`settle_in`] over `tpm` in `boot`, through the real record.
    fn settle(tpm: &mut FakeTpm, boot: Option<&str>, derived: bool) -> Settled {
        settle_in(boot, derived, || Ok(tpm), save_record)
            .expect("the step runs")
            .expect("a DA-exempt key is recorded")
    }

    /// ADR-0034, Phase 3 amendment: an original key unused since a start in
    /// an earlier boot is proved by a fresh derivation and evicted at the
    /// first start in a later boot, and not in the boot of the mark, not in
    /// a start that derived a key, and not in a boot that cannot be read.
    /// Once it is gone nothing is derived for it.
    #[test]
    fn the_original_key_is_retired_at_a_start_in_a_later_boot_once_proved() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sandbox = Sandbox::new("storage-key-retire");
        envelope(true)
            .save(&template_key::key_path("alice"))
            .unwrap();
        save_record(&retiring_record(None)).unwrap();
        let mut tpm = retiring_tpm();

        let marking = settle(&mut tpm, Some(BOOT), false);
        let derived_after_mark = tpm.original_derivations;
        let unreadable = settle(&mut tpm, None, false);
        let after_derivation = settle(&mut tpm, Some(LATER_BOOT), true);
        let derived_while_deriving = tpm.original_derivations;
        let retired = settle(&mut tpm, Some(LATER_BOOT), false);
        let derived_once = tpm.original_derivations;
        let gone = settle(&mut tpm, Some(LATER_BOOT), false);
        let kept = load_record();
        drop(sandbox);

        let unused = Census::Unused { since: BOOT.into() };
        assert_eq!(
            marking,
            Settled {
                census: unused.clone(),
                retirement: None
            }
        );
        assert_eq!(
            derived_after_mark, 0,
            "nothing is derived in the boot of the mark"
        );
        assert_eq!(
            unreadable.retirement, None,
            "an unreadable boot is no other boot"
        );
        assert_eq!(
            after_derivation.retirement, None,
            "a start that derived a key"
        );
        assert_eq!(derived_while_deriving, 0);
        assert_eq!(
            retired.retirement,
            Some(Retirement::Retired { handle: ORIGINAL })
        );
        assert_eq!(derived_once, 1, "one fresh derivation proves it");
        assert_eq!(tpm.evicted, [ORIGINAL]);
        assert!(
            tpm.objects.contains_key(&DA_EXEMPT),
            "the DA-exempt key stays"
        );
        assert_eq!(gone.retirement, None, "nothing left to retire");
        assert_eq!(tpm.original_derivations, 1, "and nothing derived for it");
        assert_eq!(kept.unused_since.as_deref(), Some(BOOT));
        assert_eq!(
            kept.original,
            retiring_record(None).original,
            "the entry stays"
        );
    }

    /// Conditions 2 and 3: no retirement without the DA-exempt key at its
    /// recorded handle with its recorded name and the DA-exempt template's
    /// shape (an edited record could name another key there, the original
    /// key included), or without the original key the record kept as
    /// matching at the original handle. A key today's
    /// derivation does not give is kept as not matching and never derived
    /// for again; one without the original template's shape is left.
    #[test]
    fn a_retirement_needs_the_da_exempt_key_and_the_kept_original_key() {
        let record = retiring_record(Some(BOOT));
        let retire = |tpm: &mut FakeTpm, record: &Record| {
            let mut next = record.clone();
            let retirement =
                retire_with(tpm, &mut next, ORIGINAL, LATER_BOOT, &mut |_: &Record| {
                    Ok(())
                })
                .expect("checked");
            (retirement, next)
        };
        let mut no_da_exempt = retiring_tpm();
        no_da_exempt.objects.remove(&DA_EXEMPT);
        assert_eq!(retire(&mut no_da_exempt, &record).0, None);
        let mut other_da_exempt = retiring_tpm();
        other_da_exempt
            .objects
            .insert(DA_EXEMPT, b"theirs".to_vec());
        assert_eq!(retire(&mut other_da_exempt, &record).0, None);
        // A key with the recorded name but not the DA-exempt template's
        // shape, as an edited record could name.
        let mut other_shape = retiring_tpm();
        other_shape.other_shape.push(DA_EXEMPT);
        assert_eq!(retire(&mut other_shape, &record).0, None);
        // The same key persisted with an authorization value irlume does not
        // hold has the same name and shape, but irlume cannot seal under it.
        let mut other_auth = retiring_tpm();
        other_auth.other_auth.push(DA_EXEMPT);
        assert_eq!(retire(&mut other_auth, &record).0, None);
        // A record edited to name the original key itself as the DA-exempt
        // one: no key would be left for an envelope that comes back.
        let mut itself = retiring_tpm();
        itself.other_shape.push(ORIGINAL);
        let names_itself = Record {
            persisted: Some(Persisted {
                handle: ORIGINAL,
                name: hex(b"orig"),
            }),
            ..record.clone()
        };
        assert_eq!(retire(&mut itself, &names_itself).0, None);
        let mut other_original = retiring_tpm();
        other_original.objects.insert(ORIGINAL, b"another".to_vec());
        assert_eq!(retire(&mut other_original, &record).0, None);
        let unmatched = Record {
            original: record.original.clone().map(|original| Original {
                matched: false,
                ..original
            }),
            ..record.clone()
        };
        assert_eq!(retire(&mut retiring_tpm(), &unmatched).0, None);
        let mut elsewhere = retiring_tpm();
        let mut next = record.clone();
        assert_eq!(
            retire_with(
                &mut elsewhere,
                &mut next,
                0x8101_0010,
                LATER_BOOT,
                &mut |_: &Record| Ok(())
            )
            .expect("checked"),
            None,
            "the original key's handle is not the one the record kept"
        );
        for tpm in [
            &no_da_exempt,
            &other_da_exempt,
            &other_shape,
            &other_auth,
            &itself,
            &other_original,
            &elsewhere,
        ] {
            assert_eq!((tpm.original_derivations, tpm.evicted.len()), (0, 0));
        }

        let mut not_reproduced = retiring_tpm();
        not_reproduced.original = Some(false);
        let (retirement, next) = retire(&mut not_reproduced, &record);
        assert_eq!(
            retirement,
            Some(Retirement::NotReproduced { handle: ORIGINAL })
        );
        assert!(!next.original.as_ref().expect("kept").matched);
        assert_eq!(
            retire(&mut not_reproduced, &next).0,
            None,
            "not derived again"
        );
        assert_eq!(not_reproduced.original_derivations, 1);
        assert!(not_reproduced.evicted.is_empty());

        let mut not_original_shape = retiring_tpm();
        not_original_shape.original = None;
        assert_eq!(retire(&mut not_original_shape, &record).0, None);
        assert!(not_original_shape.evicted.is_empty());
    }

    /// Condition 2: a derivation that fails proves nothing. The attempt is
    /// recorded with its boot before the derivation, so a write that fails
    /// there derives nothing, and a restart in the same boot derives nothing
    /// however the attempt ended, even when the write of its outcome failed.
    /// A later boot derives again; a success clears the attempt, and an
    /// attempt whose key has left the handle is dropped. An eviction that
    /// fails is recorded the same way.
    #[test]
    fn a_failed_retirement_is_tried_again_only_in_a_later_boot() {
        const THIRD_BOOT: &str = "2a1b2c3d-4e5f-6789-abcd-ef0123456789";
        let record = retiring_record(Some(BOOT));
        let ok = |_: &Record| -> Result<()> { Ok(()) };

        // The derivation fails: the failure is recorded with the boot.
        let mut tpm = retiring_tpm();
        tpm.original_error = Some("TPM_RC_BAD_AUTH".into());
        let mut next = record.clone();
        let failed =
            retire_with(&mut tpm, &mut next, ORIGINAL, LATER_BOOT, &mut { ok }).expect("checked");
        assert!(
            matches!(&failed, Some(Retirement::Failed { handle: ORIGINAL, detail }) if detail.contains("TPM_RC_BAD_AUTH")),
            "{failed:?}"
        );
        let attempt = next.retirement_attempt.clone().expect("recorded");
        assert_eq!(attempt.boot_id.as_deref(), Some(LATER_BOOT));
        assert!(attempt
            .failure
            .is_some_and(|failure| failure.contains("TPM_RC_BAD_AUTH")));
        let deferred =
            retire_with(&mut tpm, &mut next, ORIGINAL, LATER_BOOT, &mut { ok }).expect("checked");
        assert!(
            matches!(&deferred, Some(Retirement::Deferred { detail, .. }) if detail.contains("TPM_RC_BAD_AUTH")),
            "{deferred:?}"
        );
        assert_eq!(
            tpm.original_derivations, 1,
            "a restart in the same boot derives nothing"
        );
        tpm.original_error = None;
        let retried =
            retire_with(&mut tpm, &mut next, ORIGINAL, THIRD_BOOT, &mut { ok }).expect("checked");
        assert_eq!(retried, Some(Retirement::Retired { handle: ORIGINAL }));
        assert_eq!(tpm.original_derivations, 2, "a later boot derives again");
        assert_eq!(next.retirement_attempt, None, "cleared once it succeeds");

        // The attempt cannot be recorded: nothing is derived or evicted.
        let mut unwritten = retiring_tpm();
        let mut next = record.clone();
        let refused = retire_with(&mut unwritten, &mut next, ORIGINAL, LATER_BOOT, &mut |_| {
            Err(Error::Io("the directory sync failed".into()))
        });
        assert!(refused.is_err());
        assert_eq!(
            (unwritten.original_derivations, unwritten.evicted.len()),
            (0, 0)
        );

        // The eviction fails and so does the write of that failure: the
        // attempt recorded before the proof keeps a restart from retrying.
        let mut refuses = retiring_tpm();
        refuses.evict_error = Some("TPM_RC_BAD_AUTH".into());
        let mut written = Vec::new();
        let mut next = record.clone();
        let evict_failed = retire_with(&mut refuses, &mut next, ORIGINAL, LATER_BOOT, &mut |r| {
            if written.is_empty() {
                written.push(r.clone());
                Ok(())
            } else {
                Err(Error::Io("the directory sync failed".into()))
            }
        });
        assert!(
            matches!(evict_failed, Ok(Some(Retirement::Failed { .. }))),
            "{evict_failed:?}"
        );
        assert!(refuses.objects.contains_key(&ORIGINAL));
        let mut on_disk = written[0].clone();
        assert_eq!(
            on_disk.retirement_attempt,
            Some(RetirementAttempt {
                boot_id: Some(LATER_BOOT.into()),
                failure: None
            }),
            "the attempt was durable before the proof"
        );
        refuses.evict_error = None;
        let restart = retire_with(&mut refuses, &mut on_disk, ORIGINAL, LATER_BOOT, &mut {
            ok
        })
        .expect("checked");
        assert!(
            matches!(&restart, Some(Retirement::Deferred { detail, .. }) if detail.contains("did not finish")),
            "{restart:?}"
        );
        assert_eq!(
            refuses.original_derivations, 1,
            "no second proof in the boot"
        );

        // A success whose last write fails leaves the attempt; the next start
        // that finds the key gone drops it.
        let mut retires = retiring_tpm();
        let mut stale = None;
        let mut next = record.clone();
        let retired = retire_with(&mut retires, &mut next, ORIGINAL, LATER_BOOT, &mut |r| {
            if stale.is_none() {
                stale = Some(r.clone());
                Ok(())
            } else {
                Err(Error::Io("the directory sync failed".into()))
            }
        });
        assert_eq!(
            retired.expect("retired whatever the last write did"),
            Some(Retirement::Retired { handle: ORIGINAL })
        );
        let mut stale = stale.expect("the attempt");
        assert!(stale.retirement_attempt.is_some());
        let dropped = retire_with(&mut retires, &mut stale, ORIGINAL, THIRD_BOOT, &mut { ok })
            .expect("checked");
        assert_eq!(dropped, None);
        assert_eq!(
            stale.retirement_attempt, None,
            "dropped once the key is gone"
        );
    }

    /// The amendment's acceptance tests for condition 1 with retirement,
    /// over fake boot IDs: a template key moved durably at a start is
    /// retired at the first start in a later boot; a keyring secret moved
    /// after the start delays that by one boot, and a move that was not
    /// durable by one more; an envelope restored by a simulated power loss,
    /// and one that cannot be parsed, keep the key; a returning envelope
    /// whose move stopped between publishing and the record update leaves a
    /// same-boot restart retiring nothing; a record write that fails retires
    /// nothing.
    #[test]
    fn the_original_key_is_retired_only_a_boot_after_every_move_off_it_is_durable() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        const BOOT_C: &str = "2a1b2c3d-4e5f-6789-abcd-ef0123456789";
        let (template, keyring) = (EnvelopeKind::TemplateKey, EnvelopeKind::KeyringSecret);
        let retired = Some(Retirement::Retired { handle: ORIGINAL });

        // A template key moved durably at a start in boot A.
        let sandbox = Sandbox::new("storage-key-retire-timeline");
        save_record(&retiring_record(None)).unwrap();
        let alice = template_key::key_path("alice");
        envelope(false).save(&alice).unwrap();
        let mut tpm = retiring_tpm();
        let (moved, _) = publish_in(&alice, template, "alice", &envelope(true), BOOT, true);
        assert!(moved.is_ok());
        assert_eq!(settle(&mut tpm, Some(BOOT), false).retirement, None);
        assert_eq!(
            settle(&mut tpm, Some(LATER_BOOT), false).retirement,
            retired
        );
        drop(sandbox);

        // A keyring secret moved at a login after the start, durably or not.
        for durable in [true, false] {
            let sandbox = Sandbox::new("storage-key-retire-keyring");
            save_record(&retiring_record(None)).unwrap();
            let bob = keyring::envelope_path("bob");
            envelope(false).save(&bob).unwrap();
            let mut tpm = retiring_tpm();
            assert_eq!(settle(&mut tpm, Some(BOOT), false).census, Census::InUse);
            let (login, _) = publish_in(&bob, keyring, "bob", &envelope(true), BOOT, durable);
            assert!(login.is_ok());
            let restart = settle(&mut tpm, Some(BOOT), false);
            let next_boot = settle(&mut tpm, Some(LATER_BOOT), false);
            let after = settle(&mut tpm, Some(BOOT_C), false);
            drop(sandbox);
            if durable {
                // Marked at the restart in boot A, retired in boot B.
                assert_eq!(restart.census, Census::Unused { since: BOOT.into() });
                assert_eq!(next_boot.retirement, retired);
            } else {
                // The restart marks nothing, boot B marks, boot C retires.
                assert_eq!(restart.census, Census::Unsettled);
                assert_eq!(
                    next_boot.census,
                    Census::Unused {
                        since: LATER_BOOT.into()
                    }
                );
                assert_eq!(next_boot.retirement, None);
                assert_eq!(after.retirement, retired);
            }
            assert_eq!(tpm.evicted, [ORIGINAL], "retired once");
        }

        // An envelope a power loss brings back, and one that cannot be parsed.
        let under_original = serde_json::to_vec(&envelope(false)).unwrap();
        for restored in [under_original, b"not an envelope".to_vec()] {
            let sandbox = Sandbox::new("storage-key-retire-restored");
            save_record(&retiring_record(Some(BOOT))).unwrap();
            std::fs::write(keyring::envelope_path("bob"), &restored).unwrap();
            let mut tpm = retiring_tpm();
            let kept = settle(&mut tpm, Some(LATER_BOOT), false);
            let record = load_record();
            drop(sandbox);
            assert_eq!((kept.census, kept.retirement), (Census::InUse, None));
            assert_eq!(record.unused_since, None);
            assert!(tpm.evicted.is_empty() && tpm.original_derivations == 0);
        }

        // A returning envelope whose move stops between publishing and the
        // record update, with an old mark from boot A: a restart in boot B
        // retires nothing.
        let sandbox = Sandbox::new("storage-key-retire-stopped");
        save_record(&retiring_record(Some(BOOT))).unwrap();
        let carol = template_key::key_path("carol");
        envelope(false).save(&carol).unwrap();
        let mut saves = 0;
        let stopped = publish_with(
            &carol,
            template,
            "carol",
            &envelope(true),
            Some(LATER_BOOT),
            |record| {
                saves += 1;
                if saves == 1 {
                    save_record(record)
                } else {
                    Err(Error::Io("stopped before the record update".into()))
                }
            },
            |env, path| env.save_reporting(path),
        );
        let mut tpm = retiring_tpm();
        let restart = settle(&mut tpm, Some(LATER_BOOT), false);
        drop(sandbox);
        assert!(stopped.is_ok(), "the envelope was published");
        assert_eq!(
            (restart.census, restart.retirement),
            (Census::Unsettled, None)
        );
        assert!(tpm.evicted.is_empty());

        // A record write that fails before the retirement retires nothing.
        let sandbox = Sandbox::new("storage-key-retire-unwritten");
        save_record(&Record {
            moves: vec![UnsettledMove {
                user: "dave".into(),
                kind: keyring,
                boot_id: Some(BOOT.into()),
            }],
            ..retiring_record(Some(BOOT))
        })
        .unwrap();
        let mut tpm = retiring_tpm();
        let unwritten = settle_in(
            Some(LATER_BOOT),
            false,
            || Ok(&mut tpm),
            |_| Err(Error::Io("the directory sync failed".into())),
        );
        drop(sandbox);
        assert!(unwritten.is_err());
        assert!(tpm.evicted.is_empty() && tpm.original_derivations == 0);
    }

    /// A check of the original key that changes its entry derived it, one
    /// that fails counts as one, and one that leaves it derived nothing.
    #[test]
    fn a_check_of_the_original_key_says_whether_it_derived() {
        let record = retiring_record(None);
        let changed = Some(Original {
            handle: ORIGINAL,
            name: hex(b"new"),
            matched: true,
        });
        assert_eq!(
            checked_original(Ok(record.original.clone()), &record),
            (record.original.clone(), false)
        );
        assert_eq!(
            checked_original(Ok(changed.clone()), &record),
            (changed, true)
        );
        assert_eq!(
            checked_original(Err(Error::Tpm("read failed".into())), &record),
            (record.original.clone(), true)
        );
    }

    /// What doctor reads about the original key's retirement (ADR-0034,
    /// Phase 3 amendment): each wait in the order irlumed's start checks it,
    /// with the name sent only as bounded hex and only accepted account
    /// names among the unsettled moves.
    #[test]
    fn the_original_keys_retirement_is_reported_with_what_it_waits_for() {
        use RetirementWait::{
            Count, DaExemptKey, Envelopes, Failed, HandleChanged, LaterBoot, NextStart,
            NotReproduced, Unchecked, UnsettledMoves,
        };
        let now = Some(LATER_BOOT);
        let state = |tpm: &mut FakeTpm, record: &Record, in_use: bool| {
            original_key_state(tpm, record, in_use, Some(ORIGINAL), now).expect("read")
        };
        let waiting = |wait| OriginalKey::Waiting {
            handle: ORIGINAL,
            name: hex(b"orig"),
            wait,
        };
        let record = retiring_record(Some(BOOT));
        let with = |change: &dyn Fn(&mut Record)| {
            let mut changed = record.clone();
            change(&mut changed);
            changed
        };

        assert_eq!(
            state(&mut retiring_tpm(), &Record::default(), false),
            OriginalKey::NotRecorded
        );
        let mut gone = retiring_tpm();
        gone.objects.remove(&ORIGINAL);
        assert_eq!(
            state(&mut gone, &record, false),
            OriginalKey::Retired { handle: ORIGINAL }
        );
        let mut other = retiring_tpm();
        other.objects.insert(ORIGINAL, b"another".to_vec());
        assert_eq!(state(&mut other, &record, false), waiting(Unchecked));
        assert_eq!(
            original_key_state(&mut retiring_tpm(), &record, false, Some(0x8101_0010), now)
                .expect("read"),
            waiting(HandleChanged {
                configured: Some(0x8101_0010)
            }),
            "the original key's handle changed"
        );
        assert_eq!(
            original_key_state(&mut retiring_tpm(), &record, false, None, now).expect("read"),
            waiting(HandleChanged { configured: None }),
            "IRLUME_SRK_HANDLE is refused"
        );
        let unmatched = with(&|r| {
            if let Some(original) = r.original.as_mut() {
                original.matched = false;
            }
        });
        assert_eq!(
            state(&mut retiring_tpm(), &unmatched, false),
            waiting(NotReproduced { in_use: false })
        );
        // The census counts an envelope it cannot read, which doctor's list
        // of envelopes does not name.
        assert_eq!(
            state(&mut retiring_tpm(), &unmatched, true),
            waiting(NotReproduced { in_use: true })
        );
        assert_eq!(
            state(&mut retiring_tpm(), &record, true),
            waiting(Envelopes)
        );
        let failed = with(&|r| {
            r.retirement_attempt = Some(RetirementAttempt {
                boot_id: Some(LATER_BOOT.into()),
                failure: Some("TPM_RC_BAD_AUTH\nforged line".into()),
            });
        });
        assert_eq!(
            state(&mut retiring_tpm(), &failed, false),
            waiting(Failed {
                detail: irlume_common::single_line("TPM_RC_BAD_AUTH\nforged line", 300),
                in_this_boot: true
            })
        );
        let unfinished = with(&|r| {
            r.retirement_attempt = Some(RetirementAttempt {
                boot_id: Some(BOOT.into()),
                failure: None,
            });
        });
        assert_eq!(
            state(&mut retiring_tpm(), &unfinished, false),
            waiting(Failed {
                detail: "the attempt did not finish".into(),
                in_this_boot: false
            })
        );
        let mut no_da_exempt = retiring_tpm();
        no_da_exempt.objects.remove(&DA_EXEMPT);
        assert_eq!(
            state(&mut no_da_exempt, &record, false),
            waiting(DaExemptKey)
        );
        let mut other_auth = retiring_tpm();
        other_auth.other_auth.push(DA_EXEMPT);
        assert_eq!(state(&mut other_auth, &record, false), waiting(DaExemptKey));
        let entry = |user: &str, boot: Option<&str>| UnsettledMove {
            user: user.into(),
            kind: EnvelopeKind::KeyringSecret,
            boot_id: boot.map(str::to_owned),
        };
        let moving = with(&|r| {
            r.unused_since = None;
            r.moves = vec![
                entry("bob", Some(LATER_BOOT)),
                entry("-planted\u{1b}", Some(LATER_BOOT)),
                entry("carol", Some(BOOT)),
            ];
        });
        assert_eq!(
            state(&mut retiring_tpm(), &moving, false),
            waiting(UnsettledMoves {
                envelopes: vec![OriginalKeyEnvelope {
                    user: "bob".into(),
                    kind: EnvelopeKind::KeyringSecret
                }],
                total: 2
            })
        );
        let settled = with(&|r| {
            r.unused_since = None;
            r.moves = vec![entry("carol", Some(BOOT))];
        });
        assert_eq!(
            state(&mut retiring_tpm(), &settled, false),
            waiting(Count),
            "another boot's move is on disk"
        );
        let marked_now = with(&|r| r.unused_since = Some(LATER_BOOT.into()));
        assert_eq!(
            state(&mut retiring_tpm(), &marked_now, false),
            waiting(LaterBoot)
        );
        assert_eq!(
            state(&mut retiring_tpm(), &record, false),
            waiting(NextStart)
        );
        assert_eq!(
            original_key_state(&mut retiring_tpm(), &record, false, Some(ORIGINAL), None)
                .expect("read"),
            waiting(LaterBoot),
            "an unreadable boot is no other boot"
        );
        let unhexed = with(&|r| {
            if let Some(original) = r.original.as_mut() {
                original.name = "\u{1b}[31mnot hex".into();
            }
        });
        let mut planted = retiring_tpm();
        planted.objects.remove(&ORIGINAL);
        assert_eq!(
            state(&mut planted, &unhexed, false),
            OriginalKey::Retired { handle: ORIGINAL }
        );
        assert!(matches!(
            original_key_state(&mut retiring_tpm(), &unhexed, false, Some(0x8101_0010), now),
            Ok(OriginalKey::Waiting { name, .. }) if name.is_empty()
        ));
    }

    /// The recorded key away from its handle is followed by its TPM name
    /// where irlume can seal under it, with nothing derived; a copy irlume
    /// cannot seal under is replaced by today's derivation and not kept, nor
    /// is a key persisted nowhere. A kept superseded key that moved is
    /// recorded where irlume can seal under it, and one found nowhere keeps
    /// its entry.
    #[test]
    fn a_recorded_key_away_from_its_handle_is_followed_by_name() {
        const ELSEWHERE: u32 = 0x8101_0009;
        let record = persisted_record(DA_EXEMPT, b"weak");
        let start = |tpm: &mut FakeTpm| {
            let (mut next, outcome) =
                ensure_keeping_use(tpm, &record, Some(BOOT), &Ok(PLAN)).expect("the step");
            keep_superseded(tpm, &record, &mut next).expect("kept");
            (next, outcome)
        };
        let relocated = Persisted {
            handle: ELSEWHERE,
            name: hex(b"weak"),
        };

        // Followed by its name, where irlume can seal under it: nothing is
        // derived or superseded.
        let mut tpm = FakeTpm::new();
        tpm.objects.insert(ELSEWHERE, b"weak".to_vec());
        tpm.derive = Ok(b"clean".to_vec());
        let (followed, outcome) = start(&mut tpm);
        assert_eq!(outcome, Outcome::Found { handle: ELSEWHERE });
        assert!(!derived_now(&outcome));
        assert_eq!(followed.persisted, Some(relocated.clone()));
        assert!(followed.superseded.is_empty() && tpm.derived == 0);

        // Where irlume cannot seal under it (a copy with another
        // authorization value), today's derivation takes its place, and it is
        // not kept: nothing could load under it either.
        let mut unusable = FakeTpm::new();
        unusable.objects.insert(ELSEWHERE, b"weak".to_vec());
        unusable.other_auth.push(ELSEWHERE);
        unusable.derive = Ok(b"clean".to_vec());
        let (next, outcome) = start(&mut unusable);
        assert_eq!(outcome, Outcome::Persisted { handle: DA_EXEMPT });
        assert!(next.superseded.is_empty());

        let mut gone = FakeTpm::new();
        gone.derive = Ok(b"clean".to_vec());
        assert!(
            start(&mut gone).0.superseded.is_empty(),
            "persisted nowhere"
        );

        // A kept key found at another handle since is recorded there; one
        // found nowhere keeps its entry.
        let mut moved = FakeTpm::new();
        moved.objects.insert(DA_EXEMPT, b"ours".to_vec());
        moved.objects.insert(0x8101_000a, b"weak".to_vec());
        let kept = Record {
            superseded: vec![relocated.clone()],
            ..persisted_record(DA_EXEMPT, b"ours")
        };
        let mut refreshed = kept.clone();
        keep_superseded(&mut moved, &kept, &mut refreshed).expect("refreshed");
        assert_eq!(refreshed.superseded[0].handle, 0x8101_000a);
        let mut nowhere = FakeTpm::new();
        nowhere.objects.insert(DA_EXEMPT, b"ours".to_vec());
        let mut stale = kept.clone();
        keep_superseded(&mut nowhere, &kept, &mut stale).expect("kept");
        assert_eq!(stale.superseded, kept.superseded, "kept for the report");

        let mut itself = persisted_record(DA_EXEMPT, b"weak");
        supersede(
            &mut itself,
            Persisted {
                handle: DA_EXEMPT,
                name: hex(b"weak"),
            },
        );
        assert!(
            itself.superseded.is_empty(),
            "never the recorded key itself"
        );
    }

    /// A record edited offline to list the same superseded key many times,
    /// or many keys, is bounded before any TPM command: each name once, at
    /// most `MAX_SUPERSEDED`, the latest kept.
    #[test]
    fn the_superseded_keys_are_bounded_before_the_tpm_is_asked() {
        let entry = |n: u32| Persisted {
            handle: 0x8101_0010 + n,
            name: hex(&n.to_be_bytes()),
        };
        let mut repeated: Vec<Persisted> = (0..300).map(|_| entry(1)).collect();
        bound_superseded(&mut repeated);
        assert_eq!(repeated, vec![entry(1)]);
        let mut many: Vec<Persisted> = (0..20).map(entry).collect();
        bound_superseded(&mut many);
        assert_eq!(many, (16..20).map(entry).collect::<Vec<_>>());

        let record = Record {
            superseded: (0..300).map(|_| entry(1)).collect(),
            ..persisted_record(DA_EXEMPT, b"ours")
        };
        let mut tpm = FakeTpm::new();
        tpm.objects.insert(DA_EXEMPT, b"ours".to_vec());
        let mut next = record.clone();
        keep_superseded(&mut tpm, &record, &mut next).expect("kept");
        assert_eq!(next.superseded, vec![entry(1)]);
        assert!(tpm.scans <= 1, "one scan of the owner handles at most");
    }

    /// With no envelope left, a refused replacement goes with the ordinary
    /// refusal, so an envelope made later in the same boot gets a fresh try.
    #[test]
    fn a_refused_replacement_is_dropped_once_no_envelope_remains() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let sandbox = Sandbox::new("storage-key-replacement-refused");
        let refused = Refused {
            reason: RefusalReason::OwnerAuthorization,
            detail: "an owner authorization".into(),
            boot_id: Some(BOOT.into()),
        };
        save_record(&Record {
            replacement_refused: Some(refused),
            ..persisted_record(DA_EXEMPT, b"weak")
        })
        .unwrap();
        let step = ensure_at_start_reporting();
        let kept = load_record();
        drop(sandbox);
        assert!(step.is_ok(), "{step:?}");
        assert_eq!(kept.replacement_refused, None);
    }

    /// doctor's report hides a refused replacement once no envelope is left,
    /// as it hides a refused persist: irlumed's next start clears both.
    #[test]
    fn a_refused_replacement_is_not_reported_without_an_envelope() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let sandbox = Sandbox::new("storage-key-report-refused-replacement");
        save_record(&Record {
            version: RECORD_VERSION,
            replacement_refused: Some(Refused {
                reason: RefusalReason::NoSpace,
                detail: "no room".into(),
                boot_id: Some(BOOT.into()),
            }),
            ..Record::default()
        })
        .unwrap();
        let without = report();
        envelope(false)
            .save(&template_key::key_path("alice"))
            .unwrap();
        let with = report();
        drop(sandbox);
        let (without, with) = (without.expect("the report"), with.expect("the report"));
        assert_eq!(without.replacement_refused, None);
        assert!(!without.any_envelope);
        assert!(with.replacement_refused.is_some());
        assert!(with.any_envelope);
    }

    /// The census of a superseded key's use, as condition 1 keeps it for the
    /// original key: an envelope naming it, or one that cannot be read,
    /// clears the mark; none marks the boot, keeping an earlier mark; an
    /// unreadable boot marks nothing; a key no longer kept loses its mark.
    #[test]
    fn a_superseded_key_is_marked_unused_when_no_envelope_names_it() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sandbox = Sandbox::new("storage-key-superseded-marks");
        let weak = Persisted {
            handle: 0x8101_0004,
            name: hex(b"weak"),
        };
        let record = Record {
            superseded: vec![weak.clone()],
            ..persisted_record(0x8101_0003, b"ours")
        };
        let mark = |record: &Record, boot: Option<&str>| {
            let mut next = record.clone();
            mark_superseded(&mut next, boot).expect("the census");
            next.superseded_unused
        };
        let mut under_weak = envelope(true);
        if let Some(parent) = under_weak.parent.as_mut() {
            parent.name = hex(b"weak");
        }
        let alice = template_key::key_path("alice");

        under_weak.save(&alice).unwrap();
        let named = mark(&record, Some(BOOT));
        envelope(true).save(&alice).unwrap();
        let none = mark(&record, Some(BOOT));
        let marked = Record {
            superseded_unused: none.clone(),
            ..record.clone()
        };
        let kept = mark(&marked, Some(LATER_BOOT));
        let no_boot = mark(&record, None);
        std::fs::write(keyring::envelope_path("bob"), b"not an envelope").unwrap();
        let unreadable = mark(&marked, Some(LATER_BOOT));
        let dropped = mark(
            &Record {
                superseded: Vec::new(),
                ..marked.clone()
            },
            Some(LATER_BOOT),
        );
        drop(sandbox);

        assert!(named.is_empty(), "an envelope still names it");
        assert_eq!(none.get(&weak.name).map(String::as_str), Some(BOOT));
        assert_eq!(kept, none, "an earlier mark is kept");
        assert!(no_boot.is_empty(), "an unreadable boot marks nothing");
        assert!(
            unreadable.is_empty(),
            "an envelope that cannot be read may name it"
        );
        assert!(dropped.is_empty(), "a key no longer kept loses its mark");
    }

    /// ADR-0034, Phase 3 amendment (#1073 item 2), over a fake TPM: a weak
    /// DA-exempt key is replaced by today's derivation when that is clean,
    /// adopted by its name when a copy is persisted and persisted at the next
    /// free handle otherwise, with the weak key kept as superseded and never
    /// evicted. A derivation that is weak too is recorded with the firmware
    /// version, and no start derives again until the version changes. A
    /// refused persist is recorded with the boot, the weak key stays in use,
    /// and it is tried again by the rules of section 3.2.
    #[test]
    fn a_weak_da_exempt_key_is_replaced_by_moving_its_envelopes_first() {
        const NEXT: u32 = 0x8101_0004;
        let weak_record = persisted_record(DA_EXEMPT, b"weak");
        let weak_tpm = || {
            let mut tpm = FakeTpm::new();
            tpm.objects.insert(DA_EXEMPT, b"weak".to_vec());
            tpm.weak.push(DA_EXEMPT);
            tpm.derive = Ok(b"clean".to_vec());
            tpm
        };
        let replace = |tpm: &mut FakeTpm, record: &Record, boot: &str| {
            replace_weak_with(tpm, record, Some(boot), PLAN).expect("the step runs")
        };

        // A clean key: nothing changes, and nothing is derived.
        let mut clean = FakeTpm::new();
        clean.objects.insert(DA_EXEMPT, b"weak".to_vec());
        assert_eq!(replace(&mut clean, &weak_record, BOOT), None);
        assert_eq!(clean.derived, 0);

        // Replaced by a new copy at the next free handle.
        let mut tpm = weak_tpm();
        let (replaced, outcome) = replace(&mut tpm, &weak_record, BOOT).expect("replaced");
        assert_eq!(
            outcome,
            Outcome::Replaced {
                handle: NEXT,
                from: DA_EXEMPT
            }
        );
        assert_eq!(
            replaced.persisted,
            persisted_record(NEXT, b"clean").persisted
        );
        assert_eq!(
            replaced.superseded,
            weak_record
                .persisted
                .clone()
                .into_iter()
                .collect::<Vec<_>>(),
            "the weak key is kept"
        );
        assert!(tpm.objects.contains_key(&DA_EXEMPT) && tpm.evicted.is_empty());
        assert!(derived_now(&outcome));
        // The replacement is clean, so the next start changes nothing.
        let mut after = weak_tpm();
        after.objects.insert(NEXT, b"clean".to_vec());
        assert_eq!(replace(&mut after, &replaced, BOOT), None);

        // A copy an earlier start persisted is adopted, with no second copy.
        let mut copied = weak_tpm();
        copied.objects.insert(0x8101_0007, b"clean".to_vec());
        let (_, outcome) = replace(&mut copied, &weak_record, BOOT).expect("adopted");
        assert_eq!(
            outcome,
            Outcome::Replaced {
                handle: 0x8101_0007,
                from: DA_EXEMPT
            }
        );
        assert!(copied.persisted.is_empty(), "no second copy");
        // A copy irlume cannot seal under (another stack's, persisted with its
        // own authorization value) is not adopted: a usable one is persisted.
        let mut foreign_copy = weak_tpm();
        foreign_copy.objects.insert(0x8101_0007, b"clean".to_vec());
        foreign_copy.other_auth.push(0x8101_0007);
        let (_, outcome) = replace(&mut foreign_copy, &weak_record, BOOT).expect("replaced");
        assert_eq!(
            outcome,
            Outcome::Replaced {
                handle: NEXT,
                from: DA_EXEMPT
            }
        );
        assert_eq!(foreign_copy.persisted, [NEXT]);

        // Today's derivation is weak too, or gives the weak key itself.
        for (derive, derived_weak) in [(b"clean".to_vec(), true), (b"weak".to_vec(), false)] {
            let mut tpm = weak_tpm();
            tpm.derive = Ok(derive);
            tpm.derived_weak = derived_weak;
            let (kept, outcome) = replace(&mut tpm, &weak_record, BOOT).expect("recorded");
            assert_eq!(outcome, Outcome::DerivationWeak { handle: DA_EXEMPT });
            assert!(derived_now(&outcome));
            assert_eq!(
                kept.weak_derivation,
                Some(WeakDerivation {
                    firmware: tpm.firmware
                })
            );
            assert_eq!(
                (kept.persisted.clone(), kept.superseded.is_empty()),
                (weak_record.persisted.clone(), true)
            );
            // Same firmware: nothing is derived again, in any boot.
            let (_, again) = replace(&mut tpm, &kept, LATER_BOOT).expect("kept");
            assert_eq!(again, Outcome::WeakKept { handle: DA_EXEMPT });
            assert!(!derived_now(&again));
            assert_eq!(tpm.derived, 1);
            // Another firmware version derives again.
            tpm.firmware = [0x0007_0056, 0];
            tpm.derive = Ok(b"clean".to_vec());
            tpm.derived_weak = false;
            let (_, updated) = replace(&mut tpm, &kept, LATER_BOOT).expect("replaced");
            assert!(matches!(updated, Outcome::Replaced { .. }), "{updated:?}");
            assert_eq!(tpm.derived, 2);
        }

        // No room: the refusal is recorded and the weak key stays in use.
        let mut full = weak_tpm();
        full.persist = vec![Err(failure(FailureClass::NoSpace))];
        full.avail = 0;
        let (refused, outcome) = replace(&mut full, &weak_record, BOOT).expect("refused");
        assert!(
            matches!(&outcome, Outcome::ReplacementRefused { from: DA_EXEMPT, refusal } if refusal.reason == RefusalReason::NoSpace),
            "{outcome:?}"
        );
        assert_eq!(
            refused.persisted, weak_record.persisted,
            "the weak key stays"
        );
        assert_eq!(
            refused
                .replacement_refused
                .as_ref()
                .and_then(|r| r.boot_id.as_deref()),
            Some(BOOT)
        );
        let (_, deferred) = replace(&mut full, &refused, BOOT).expect("deferred");
        assert!(
            matches!(deferred, Outcome::ReplacementDeferred { .. }),
            "{deferred:?}"
        );
        assert!(!derived_now(&deferred));
        assert_eq!(
            full.derived, 1,
            "a restart in the same boot derives nothing"
        );
        full.avail = 1;
        let (_, room) = replace(&mut full, &refused, BOOT).expect("retried");
        assert!(
            matches!(room, Outcome::Replaced { .. }),
            "room retries in the boot: {room:?}"
        );
        let mut later = weak_tpm();
        let (_, next_boot) = replace(&mut later, &refused, LATER_BOOT).expect("retried");
        assert!(
            matches!(next_boot, Outcome::Replaced { .. }),
            "{next_boot:?}"
        );

        // An owner authorization refuses the derivation.
        let mut owner = weak_tpm();
        owner.derive = Err(failure(FailureClass::OwnerAuthorization));
        let (_, outcome) = replace(&mut owner, &weak_record, BOOT).expect("refused");
        assert!(
            matches!(&outcome, Outcome::ReplacementRefused { refusal, .. } if refusal.reason == RefusalReason::OwnerAuthorization),
            "{outcome:?}"
        );

        // A clean key drops an earlier account of a weak one.
        let stale = Record {
            weak_derivation: Some(WeakDerivation { firmware: [1, 0] }),
            ..weak_record.clone()
        };
        let mut clean = FakeTpm::new();
        clean.objects.insert(DA_EXEMPT, b"weak".to_vec());
        let (cleared, outcome) = replace(&mut clean, &stale, BOOT).expect("cleared");
        assert_eq!(outcome, Outcome::Present { handle: DA_EXEMPT });
        assert_eq!(cleared.weak_derivation, None);
    }

    /// The start-up step decides the DA-exempt key's part of the record and
    /// keeps the account of the original key's use, a failed retirement
    /// included, as it found it.
    #[test]
    fn the_start_up_step_keeps_the_original_keys_use() {
        let pending = UnsettledMove {
            user: "bob".into(),
            kind: EnvelopeKind::KeyringSecret,
            boot_id: Some(BOOT.into()),
        };
        let record = Record {
            version: RECORD_VERSION,
            unused_since: Some(BOOT.into()),
            moves: vec![pending],
            retirement_attempt: Some(RetirementAttempt {
                boot_id: Some(BOOT.into()),
                failure: Some("TPM_RC_BAD_AUTH".into()),
            }),
            ..Record::default()
        };
        let mut persists = FakeTpm::new();
        let (persisted, outcome) =
            ensure_keeping_use(&mut persists, &record, Some(LATER_BOOT), &Ok(PLAN)).unwrap();
        assert!(matches!(outcome, Outcome::Persisted { .. }), "{outcome:?}");
        let mut refuses = FakeTpm::new();
        refuses.derive = Err(failure(FailureClass::NoSpace));
        let (refused, outcome) =
            ensure_keeping_use(&mut refuses, &record, Some(LATER_BOOT), &Ok(PLAN)).unwrap();
        assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");
        for next in [persisted, refused] {
            assert_eq!(next.unused_since, record.unused_since);
            assert_eq!(next.moves, record.moves);
            assert_eq!(next.retirement_attempt, record.retirement_attempt);
        }
    }

    #[test]
    fn the_record_is_not_an_account_and_round_trips() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = crate::test_tmp_dir("storage-key-record");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let previous = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        let record = persisted_record(0x8101_0003, b"ours");
        save_record(&record).expect("saved");
        let loaded = load_record();
        let users = crate::storage::list_users();
        match previous {
            Some(previous) => std::env::set_var("IRLUME_STATE_DIR", previous),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(loaded, record);
        assert!(users.is_empty(), "{users:?}");
    }
}
