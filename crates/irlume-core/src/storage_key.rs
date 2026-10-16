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
    DaExemptKey, EnvelopeKind, KeyRefusal, OriginalKeyEnvelope, OriginalKeyEnvelopes,
    RefusalReason, MAX_NAMED_ENVELOPES,
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
    /// Refused now, and recorded with the boot.
    Refused(KeyRefusal),
    /// A refusal earlier in this boot stands. Nothing was derived.
    Deferred(KeyRefusal),
}

/// irlumed's start-up step (ADR-0034 §3.2). It runs while any envelope
/// exists: those on the original key need the DA-exempt key persisted for
/// their move, and those on it need it still there. With none it returns
/// `None` and asks the TPM nothing, and a refusal recorded earlier is cleared,
/// since no envelope is left for it to concern.
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
    let envelope = any_envelope()?;
    if !envelope && load_record().refused.is_none() {
        return Ok(None);
    }
    // One transaction: two starts that overlap (a direct start beside the
    // service) would each read, decide and write the record, and a refusal
    // one of them recorded last would replace the key the other persisted.
    // Under the lock the second start reads the first one's record.
    let _lock = RecordLock::acquire()?;
    let record = load_record();
    if !envelope {
        if record.refused.is_some() {
            save_record(&Record {
                refused: None,
                version: RECORD_VERSION,
                ..record
            })?;
        }
        return Ok(None);
    }
    let plan = tpm::da_exempt_key_plan();
    let boot = irlume_common::boot_id();
    // A refused override needs no TPM, so a transport that cannot be opened
    // does not hide it: `ensure_with` records it before any TPM call.
    let (next, outcome) = match &plan {
        Ok(_) => {
            let mut tpm = tpm::DaExemptKeyTpm::open()?;
            ensure_with(&mut tpm, &record, boot.as_deref(), &plan)?
        }
        Err(_) => ensure_with(&mut Unopened, &record, boot.as_deref(), &plan)?,
    };
    if next != record {
        save_record(&next)?;
    }
    Ok(Some(outcome))
}

/// What `irlume doctor` reports (ADR-0034 §4): the record, with the recorded
/// handle kept only while the key there has the recorded name, a recorded
/// refusal only while any envelope exists, and the envelopes still under the
/// original storage key (`on_original_key`).
///
/// # Errors
///
/// When an envelope directory cannot be read, or the record names a handle
/// and the TPM cannot be opened or read.
pub fn report() -> Result<DaExemptKey> {
    let mut record = load_record();
    if !any_envelope()? {
        record.refused = None;
    }
    let handle = match &record.persisted {
        Some(persisted) => {
            let mut tpm = tpm::DaExemptKeyTpm::open()?;
            let name = tpm_name_hex(&mut tpm, persisted.handle)?;
            (name.as_deref() == Some(persisted.name.as_str())).then_some(persisted.handle)
        }
        None => None,
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
    })
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
    let in_use = tpm.owner_names()?;
    if let Some((handle, _)) = in_use.iter().find(|(_, used)| *used == name) {
        return Ok((
            persisted_record(*handle, &name),
            Outcome::Adopted { handle: *handle },
        ));
    }
    let mut taken: Vec<u32> = in_use.into_iter().map(|(handle, _)| handle).collect();
    for _ in 0..PERSIST_ATTEMPTS {
        let Some(handle) = first_free_owner_handle(plan, &taken) else {
            return Ok(refuse(
                RefusalReason::NoFreeHandle,
                "every owner persistent handle is taken".to_owned(),
            ));
        };
        match tpm.persist(handle) {
            Ok(()) => {
                return Ok((
                    persisted_record(handle, &name),
                    Outcome::Persisted { handle },
                ))
            }
            // Another start may have just persisted the same key there: the
            // derivation is deterministic, so adopt it rather than persist a
            // second copy.
            Err(failure) if failure.class == FailureClass::Taken => {
                if tpm.name_at(handle)?.as_deref() == Some(name.as_slice()) {
                    return Ok((persisted_record(handle, &name), Outcome::Adopted { handle }));
                }
                taken.push(handle);
            }
            Err(failure) => return Ok(refuse(reason_for(failure.class), failure.detail)),
        }
    }
    Ok(refuse(
        RefusalReason::NoFreeHandle,
        format!("{PERSIST_ATTEMPTS} handles in a row were taken while irlumed tried them"),
    ))
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
        refused: None,
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
/// `name`, a TPM name in hex, as its parent, so that a TPM lockout blocks
/// none of them. An envelope that cannot be parsed counts as not on it.
pub(crate) fn every_envelope_on(name: &str) -> Result<bool> {
    for dir in [template_key::key_dir(), keyring::keyring_dir()] {
        for path in envelope_paths(&dir)? {
            // The bounded loader: an oversized, linked or unreadable file
            // counts as not on the key, and cannot exhaust irlumed's memory.
            let on_key = crate::envelope::SealedEnvelope::load(&path)
                .ok()
                .and_then(|envelope| envelope.parent)
                .is_some_and(|parent| parent.name == name);
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

/// An exclusive `flock` on `state_dir()/.tpm-storage-key.lock` for the
/// start-up step's read, decision and write of the record, held until it is
/// dropped. Like `template_key::UserStateLock`, every acquisition opens the
/// file anew, so it also excludes another thread of this process.
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
        fn owner_names(&mut self) -> Result<Vec<(u32, Vec<u8>)>> {
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

    /// With no envelope left, the start-up step clears a recorded refusal
    /// without asking the TPM, and doctor's report no longer carries one.
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
        let refused = Record {
            version: RECORD_VERSION,
            persisted: None,
            refused: Some(Refused {
                reason: RefusalReason::Other,
                detail: "refused".into(),
                boot_id: Some(BOOT.into()),
            }),
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
        let empty = every_envelope_on("aa");
        std::fs::write(format!("{dir}/keyring/alice.json"), envelope(Some("aa"))).unwrap();
        std::fs::write(format!("{dir}/template-keys/alice.json"), envelope(None)).unwrap();
        let mixed = every_envelope_on("aa");
        std::fs::write(
            format!("{dir}/template-keys/alice.json"),
            envelope(Some("aa")),
        )
        .unwrap();
        let all = every_envelope_on("aa");
        let other = every_envelope_on("bb");
        std::fs::write(format!("{dir}/keyring/bob.json"), b"not an envelope").unwrap();
        let unparsable = every_envelope_on("aa");
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
        let census = every_envelope_on("aa");
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
