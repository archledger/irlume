//! irlume's DA-exempt storage key at irlumed's start (ADR-0034 §3.2): find
//! it, or derive and persist it, and record what happened. A refusal is
//! recorded with the boot ID, so a daemon restart in the same boot derives
//! nothing, unless the refusal was for lack of room and the TPM now reports
//! room (#1083).
//!
//! Nothing seals under the key yet. The envelopes' record of their parent and
//! the moves to the new key follow; persisting the key first costs one owner
//! persistent handle, and uninstall evicts it (`tpm::evict_da_exempt_srks`).

use crate::{keyring, template_key, tpm};
use irlume_common::tpm_readiness::{DaExemptKey, KeyRefusal, RefusalReason};
use irlume_common::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The version written into new records.
const RECORD_VERSION: u32 = 1;

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

/// irlumed's start-up step (ADR-0034 §3.2). It runs only while some envelope
/// is under the original key, which in this phase is every envelope; with
/// none it returns `None` and touches nothing.
///
/// The key is derived at most once, and only when the recorded key is not at
/// its handle and no refusal earlier in this boot stands. A copy already
/// persisted is adopted by its TPM name, so a power loss between
/// `TPM2_EvictControl` and the record never leaves a second copy. Otherwise
/// the key is persisted at the first free owner handle from the preferred one
/// whatever `TPM_PT_HR_PERSISTENT_AVAIL` says, since a 0 there is an estimate
/// that promises nothing (Part 2 table 28).
///
/// # Errors
///
/// When the TPM cannot be opened or read, or the record cannot be written.
/// A key persisted before a failed write is adopted at the next start.
pub fn ensure_at_start() -> Result<Option<Outcome>> {
    if !envelope_under_original_key() {
        return Ok(None);
    }
    let record = load_record();
    let plan = tpm::da_exempt_key_plan();
    let mut tpm = tpm::DaExemptKeyTpm::open()?;
    let boot = irlume_common::boot_id();
    let (next, outcome) = ensure_with(&mut tpm, &record, boot.as_deref(), &plan)?;
    drop(tpm);
    if next != record {
        save_record(&next)?;
    }
    Ok(Some(outcome))
}

/// What `irlume doctor` reports (ADR-0034 §4): the record, with the recorded
/// handle kept only while the key there has the recorded name.
///
/// # Errors
///
/// When the record names a handle and the TPM cannot be opened or read.
pub fn report() -> Result<DaExemptKey> {
    let record = load_record();
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
            detail: refused.detail,
        }),
    })
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
        if same_boot && !(refused.reason.is_capacity() && tpm.persistent_avail()? >= 1) {
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
            Err(failure) if failure.class == FailureClass::Taken => taken.push(handle),
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether some envelope is under the original key. Every envelope is, until
/// envelopes record their parent: a sealed template key or keyring secret.
fn envelope_under_original_key() -> bool {
    has_envelope(&template_key::key_dir()) || has_envelope(&keyring::keyring_dir())
}

fn has_envelope(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            let path = entry.path();
            path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json")
        })
    })
}

fn record_path() -> PathBuf {
    irlume_common::state_dir().join("tpm-storage-key")
}

/// The record, or an empty one when there is none. A record that is
/// unreadable, malformed or from a newer release reads as none: the next step
/// derives the key and adopts a persisted copy by its name, so nothing is lost.
fn load_record() -> Record {
    std::fs::read(record_path())
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
            if answer.is_ok() {
                let name = self.derive.clone().expect("a derived key");
                self.objects.insert(handle, name);
                self.persisted.push(handle);
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
