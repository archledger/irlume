// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Cross-store commit and grant-boundary validation (ADR-0024 Phase 1,
//! §4.1/§4.2): the explicit protocol that makes two durable file writes one
//! transaction, and the serialized final check every secondary grant must
//! pass against the CURRENT state of BOTH stores.
//!
//! ## Commit protocol (§4.1)
//!
//! A secondary-store republish (the add/remove-group mutation) runs as:
//!
//! 1. Write the intent journal (`intent` record carrying the serialized NEW
//!    secondary store and the digests it must match), fsync file + dir.
//! 2. Write the new secondary to a temporary file, fsync.
//! 3. Rename over the secondary store, fsync the directory.
//! 4. Remove the journal, fsync the directory.
//!
//! The COMMIT POINT is step 3. Recovery is deterministic RECOVER-FORWARD:
//! the operation was authorized before the journal existed, so a journal
//! found at load time is completed by rewriting the secondary from the
//! journal's own bytes (steps 2-4 again), never by guessing or by mixing
//! generations. A crash may cost secondary availability; it cannot activate
//! a binding against the wrong primary (the activation digest still
//! governs) or silently restore revoked authorization.
//!
//! ## Grant boundary (§4.2)
//!
//! [`grant_boundary_check`] is the final, serialized decision input for a
//! secondary authentication: it re-validates the pinned generation AND the
//! CURRENT primary bytes (the caller must read them AT the boundary - an
//! fd retained from the attempt's start does not establish the currently
//! published snapshot, because `rename(2)` leaves open descriptors
//! unaffected). A changed, missing, unreadable, or otherwise invalid
//! primary refuses the attempt before any grant decision - including for
//! an attempt already in progress.

use super::{load_secondary, Activation, SecondaryStore, SecondaryStoreError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One recorded two-store intent. The journal carries everything recovery
/// needs to finish deterministically: the exact serialized new secondary
/// store and the primary digest context the authorization was captured
/// against.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitIntent {
    pub format_version: u32,
    /// The operation's monotonic secondary generation being published.
    pub generation: u64,
    /// The primary digest the new secondary is bound to (must equal
    /// `new_store.primary_snapshot_sha256`).
    pub primary_snapshot_sha256: String,
    /// The complete serialized new secondary store (recover-forward payload).
    pub new_secondary_b64: String,
}

/// The only intent-journal format version.
pub const INTENT_FORMAT_VERSION: u32 = 1;

/// Recovery never guesses: each outcome names what happened.
#[derive(Debug, PartialEq, Eq)]
pub enum CommitResolution {
    /// No journal: the store on disk is the committed state.
    Clean,
    /// A journal existed and recovery-forward completed the publication.
    Completed,
}

#[derive(Debug)]
pub enum CommitError {
    Store(SecondaryStoreError),
    Io(String),
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitError::Store(error) => write!(f, "{error}"),
            CommitError::Io(detail) => write!(f, "commit io failure: {detail}"),
        }
    }
}

impl std::error::Error for CommitError {}

impl From<SecondaryStoreError> for CommitError {
    fn from(error: SecondaryStoreError) -> Self {
        CommitError::Store(error)
    }
}

/// The journal path for a secondary store path.
#[must_use]
pub fn intent_path_for(secondary: &Path) -> PathBuf {
    let mut name = secondary
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "secondary".into());
    name.push_str(".intent");
    secondary
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

fn fsync_dir(dir: &Path) -> Result<(), CommitError> {
    let file = std::fs::File::open(dir).map_err(|e| CommitError::Io(e.to_string()))?;
    file.sync_all()
        .map_err(|e| CommitError::Io(e.to_string()))?;
    Ok(())
}

fn durable_write(path: &Path, bytes: &[u8]) -> Result<(), CommitError> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let temp = dir.join(format!(
        ".{}.commit-tmp-{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "store".into()),
        std::process::id()
    ));
    let mut file = std::fs::File::create(&temp).map_err(|e| CommitError::Io(e.to_string()))?;
    file.write_all(bytes)
        .map_err(|e| CommitError::Io(e.to_string()))?;
    file.sync_all()
        .map_err(|e| CommitError::Io(e.to_string()))?;
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        CommitError::Io(e.to_string())
    })?;
    fsync_dir(dir)
}

/// Publishes a new secondary store under the protocol: journal first
/// (durable), then the store (durable rename), then journal removal.
/// `new_store` must be valid and bound to `primary_snapshot_sha256`.
///
/// # Errors
///
/// Returns [`CommitError`] when validation or any durable step fails. A
/// failure before the commit point leaves the previous store authoritative
/// and the journal for [`resolve_commit`] to finish or discard.
pub fn publish_with_intent(
    secondary_path: &Path,
    new_store: &SecondaryStore,
    primary_snapshot_sha256: &str,
) -> Result<(), CommitError> {
    new_store.validate()?;
    if new_store.primary_snapshot_sha256 != primary_snapshot_sha256 {
        return Err(CommitError::Store(SecondaryStoreError::Invalid(
            "store binding disagrees with the transaction's primary digest".into(),
        )));
    }
    let bytes = serde_json::to_vec(new_store).map_err(|e| CommitError::Io(e.to_string()))?;
    // Writers create the store's directory before publication (the fixed
    // location sits in a `cameras/` subdirectory legacy code never made).
    if let Some(parent) = secondary_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CommitError::Io(e.to_string()))?;
    }
    use base64::Engine as _;
    let intent = CommitIntent {
        format_version: INTENT_FORMAT_VERSION,
        generation: new_store.generation,
        primary_snapshot_sha256: primary_snapshot_sha256.to_owned(),
        new_secondary_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
    };
    let journal = serde_json::to_vec(&intent).map_err(|e| CommitError::Io(e.to_string()))?;
    let intent_path = intent_path_for(secondary_path);
    durable_write(&intent_path, &journal)?;
    // Commit point: the durable rename of the new store.
    durable_write(secondary_path, &bytes)?;
    std::fs::remove_file(&intent_path)
        .map_err(|e| CommitError::Io(e.to_string()))
        .and_then(|()| fsync_dir(intent_path.parent().unwrap_or_else(|| Path::new("."))))?;
    Ok(())
}

/// Resolves any leftover journal deterministically (recover-forward): if a
/// journal exists, the publication it describes was already authorized, so
/// it is completed from the journal's own payload and the journal removed.
/// The activation digest still governs whether the recovered store is
/// ACTIVE against the current primary.
///
/// # Errors
///
/// Returns [`CommitError`] when the journal is unreadable/corrupt (the
/// caller must refuse affected secondary groups, never guess) or the
/// completion writes fail.
pub fn resolve_commit(secondary_path: &Path) -> Result<CommitResolution, CommitError> {
    let intent_path = intent_path_for(secondary_path);
    let journal = match std::fs::read(&intent_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CommitResolution::Clean);
        }
        Err(error) => return Err(CommitError::Io(error.to_string())),
    };
    let intent: CommitIntent = serde_json::from_slice(&journal)
        .map_err(|e| CommitError::Io(format!("corrupt journal: {e}")))?;
    if intent.format_version != INTENT_FORMAT_VERSION {
        return Err(CommitError::Io(format!(
            "unsupported journal version {}",
            intent.format_version
        )));
    }
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&intent.new_secondary_b64)
        .map_err(|e| CommitError::Io(format!("journal payload undecodable: {e}")))?;
    let store: SecondaryStore = serde_json::from_slice(&bytes)
        .map_err(|e| CommitError::Io(format!("journal payload corrupt: {e}")))?;
    store.validate()?;
    if store.generation != intent.generation
        || store.primary_snapshot_sha256 != intent.primary_snapshot_sha256
    {
        return Err(CommitError::Io(
            "journal payload disagrees with its own metadata".into(),
        ));
    }
    // Recover-forward: complete the publication from the journal's payload.
    durable_write(secondary_path, &bytes)?;
    std::fs::remove_file(&intent_path).map_err(|e| CommitError::Io(e.to_string()))?;
    fsync_dir(intent_path.parent().unwrap_or_else(|| Path::new(".")))?;
    Ok(CommitResolution::Completed)
}

/// What an authentication attempt pinned at its start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantContext {
    pub secondary_generation: u64,
    pub primary_snapshot_sha256: String,
    pub group_id: String,
}

/// The serialized grant-boundary verdict (§4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantDecision {
    /// Both stores are exactly the pinned state: the group may grant.
    Grant,
    /// Refused, with the boundary that failed. Every refusal reason names
    /// the ADR clause it enforces.
    Refuse(&'static str),
}

/// The final grant-boundary check. `current_primary_bytes` MUST be read at
/// this boundary (not retained from the attempt's start: `rename(2)`
/// replaces the pathname while old descriptors keep the old bytes).
/// `current_secondary` is the freshly loaded store; absence refuses.
///
/// This function is pure over its inputs so the serialized boundary can be
/// tested exhaustively without a daemon.
#[must_use]
pub fn grant_boundary_check(
    pinned: &GrantContext,
    current_primary_bytes: Option<&[u8]>,
    current_secondary: Option<&SecondaryStore>,
) -> GrantDecision {
    let Some(secondary) = current_secondary else {
        return GrantDecision::Refuse("secondary store absent at the grant boundary");
    };
    if secondary.generation != pinned.secondary_generation {
        return GrantDecision::Refuse(
            "secondary generation changed during the attempt (§4.2: pinned enrollment generation)",
        );
    }
    let Some(bytes) = current_primary_bytes else {
        return GrantDecision::Refuse(
            "primary store missing or unreadable at the grant boundary (§1.1)",
        );
    };
    if irlume_common::sha256_hex(bytes) != pinned.primary_snapshot_sha256 {
        return GrantDecision::Refuse(
            "primary snapshot changed during the attempt (§4.2: legacy rewrite with unchanged secondary generation)",
        );
    }
    if !matches!(
        secondary.activation_against(Some(bytes)),
        Activation::Active
    ) {
        return GrantDecision::Refuse("secondary activation binding stale (§1.1)");
    }
    if !secondary
        .groups
        .iter()
        .any(|group| group.id.as_str() == pinned.group_id)
    {
        return GrantDecision::Refuse("pinned group no longer present (§4.2 revocation)");
    }
    GrantDecision::Grant
}

/// Convenience: loads the current secondary (journal resolved first) and
/// reads the primary bytes, then runs [`grant_boundary_check`]. Reading
/// both AT the boundary is the caller-visible contract.
///
/// # Errors
///
/// Returns [`CommitError`] when resolution or loading fails; the caller
/// refuses the attempt (never guesses).
pub fn grant_boundary_now(
    pinned: &GrantContext,
    secondary_path: &Path,
    primary_path: &Path,
) -> Result<GrantDecision, CommitError> {
    resolve_commit(secondary_path)?;
    let secondary = match load_secondary(secondary_path)? {
        Some(store) => store,
        None => return Ok(grant_boundary_check(pinned, None, None)),
    };
    let primary_bytes = std::fs::read(primary_path).ok();
    Ok(grant_boundary_check(
        pinned,
        primary_bytes.as_deref(),
        Some(&secondary),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::{CameraGroupId, GroupPair, SecondaryGroup, SecondaryProfileScans};
    use super::*;
    use crate::storage::FaceScan;

    fn scan() -> FaceScan {
        FaceScan {
            name: "s".into(),
            rgb: vec![0.5; 4],
            ir: None,
            ir_space: None,
            embed_space: None,
            ir_center_edge_ratio: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
        }
    }

    fn store_for(primary_digest: &str, generation: u64) -> SecondaryStore {
        SecondaryStore {
            format_version: super::super::SECONDARY_STORE_VERSION,
            owner: "alice".into(),
            generation,
            primary_snapshot_sha256: primary_digest.to_owned(),
            groups: vec![SecondaryGroup {
                id: CameraGroupId::new("desk".into()).unwrap(),
                pair: GroupPair {
                    rgb: Some("3443:c803".into()),
                    ir: Some("3443:c803".into()),
                },
                profiles: vec![SecondaryProfileScans {
                    ir_calibs: Default::default(),
                    profile: "main".into(),
                    scans: vec![scan()],
                }],
            }],
        }
    }

    fn paths(tag: &str) -> (PathBuf, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("irlume-commit-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        (dir.join("secondary.json"), dir.join("primary.json"))
    }

    #[test]
    fn publish_is_clean_without_a_journal_and_round_trips() {
        let (secondary_path, _) = paths("clean");
        let primary_digest = irlume_common::sha256_hex(b"primary-v1");
        let store = store_for(&primary_digest, 1);
        publish_with_intent(&secondary_path, &store, &primary_digest).expect("publish");
        assert!(matches!(
            resolve_commit(&secondary_path),
            Ok(CommitResolution::Clean)
        ));
        assert!(load_secondary(&secondary_path).expect("load").is_some());
        let _ = std::fs::remove_dir_all(secondary_path.parent().unwrap());
    }

    #[test]
    fn a_crash_after_the_journal_recovers_forward_from_the_journal_payload() {
        let (secondary_path, _) = paths("crash");
        let primary_digest = irlume_common::sha256_hex(b"primary-v1");
        let store = store_for(&primary_digest, 7);
        // Simulate a crash after step 1: journal written, store not yet.
        let bytes = serde_json::to_vec(&store).unwrap();
        use base64::Engine as _;
        let intent = CommitIntent {
            format_version: INTENT_FORMAT_VERSION,
            generation: 7,
            primary_snapshot_sha256: primary_digest.clone(),
            new_secondary_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
        };
        let journal = serde_json::to_vec(&intent).unwrap();
        durable_write(&intent_path_for(&secondary_path), &journal).expect("journal");
        assert!(matches!(
            resolve_commit(&secondary_path),
            Ok(CommitResolution::Completed)
        ));
        // The recovered store is exactly the journal's payload.
        let recovered = load_secondary(&secondary_path)
            .expect("load")
            .expect("present");
        assert_eq!(recovered.generation, 7);
        assert!(matches!(
            resolve_commit(&secondary_path),
            Ok(CommitResolution::Clean)
        ));
        let _ = std::fs::remove_dir_all(secondary_path.parent().unwrap());
    }

    #[test]
    fn a_binding_disagreement_refuses_publication_before_any_write() {
        let (secondary_path, _) = paths("disagree");
        let store = store_for(&"a".repeat(64), 1);
        let error = publish_with_intent(&secondary_path, &store, &"b".repeat(64))
            .expect_err("disagreement refuses");
        assert!(error.to_string().contains("disagrees"));
        // Nothing was written, journal included.
        assert!(!intent_path_for(&secondary_path).exists());
        let _ = std::fs::remove_dir_all(secondary_path.parent().unwrap());
    }

    #[test]
    fn the_grant_boundary_refuses_every_stale_state() {
        let primary = b"primary-bytes";
        let digest = irlume_common::sha256_hex(primary);
        let store = store_for(&digest, 12);
        let pinned = GrantContext {
            secondary_generation: 12,
            primary_snapshot_sha256: digest.clone(),
            group_id: "desk".into(),
        };
        assert_eq!(
            grant_boundary_check(&pinned, Some(primary), Some(&store)),
            GrantDecision::Grant
        );
        // Generation bumped mid-attempt.
        let bumped = store_for(&digest, 13);
        assert_eq!(
            grant_boundary_check(&pinned, Some(primary), Some(&bumped)),
            GrantDecision::Refuse(
                "secondary generation changed during the attempt (§4.2: pinned enrollment generation)"
            )
        );
        // Primary rewritten mid-attempt with the secondary generation
        // unchanged: the acceptance-matrix case.
        assert_eq!(
            grant_boundary_check(&pinned, Some(b"primary-rewritten"), Some(&store)),
            GrantDecision::Refuse(
                "primary snapshot changed during the attempt (§4.2: legacy rewrite with unchanged secondary generation)"
            )
        );
        // Primary missing.
        assert_eq!(
            grant_boundary_check(&pinned, None, Some(&store)),
            GrantDecision::Refuse(
                "primary store missing or unreadable at the grant boundary (§1.1)"
            )
        );
        // Secondary absent.
        assert_eq!(
            grant_boundary_check(&pinned, Some(primary), None),
            GrantDecision::Refuse("secondary store absent at the grant boundary")
        );
        // Group removed (revocation).
        let mut revoked = store_for(&digest, 12);
        revoked.groups.clear();
        assert_eq!(
            grant_boundary_check(&pinned, Some(primary), Some(&revoked)),
            GrantDecision::Refuse("pinned group no longer present (§4.2 revocation)")
        );
    }

    #[test]
    fn grant_boundary_now_reads_both_stores_at_the_boundary() {
        let (secondary_path, primary_path) = paths("now");
        let primary = b"primary-bytes";
        std::fs::write(&primary_path, primary).expect("primary");
        let digest = irlume_common::sha256_hex(primary);
        let store = store_for(&digest, 3);
        publish_with_intent(&secondary_path, &store, &digest).expect("publish");
        let pinned = GrantContext {
            secondary_generation: 3,
            primary_snapshot_sha256: digest,
            group_id: "desk".into(),
        };
        assert!(matches!(
            grant_boundary_now(&pinned, &secondary_path, &primary_path),
            Ok(GrantDecision::Grant)
        ));
        // A legacy rewrite of the primary between the attempt's start and
        // the boundary refuses - even though the secondary is untouched.
        std::fs::write(&primary_path, b"primary-rewritten-by-legacy").expect("rewrite");
        assert!(matches!(
            grant_boundary_now(&pinned, &secondary_path, &primary_path),
            Ok(GrantDecision::Refuse(_))
        ));
        let _ = std::fs::remove_dir_all(secondary_path.parent().unwrap());
    }
}
