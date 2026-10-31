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

#[cfg(test)]
use super::load_secondary;
use super::{Activation, GroupPair, SecondaryStore, SecondaryStoreError};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::OpenOptionsExt;
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
    let temp = super::staging_path(path, super::COMMIT_STAGING_TAG);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| CommitError::Io(e.to_string()))?;
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
    prepare_with_intent(secondary_path, new_store, primary_snapshot_sha256)?.publish()
}

/// Prepare a one-shot encrypted publication without authorizing recover-forward.
/// Key resolution and validation finish before the caller's admission boundary.
///
/// # Errors
/// Returns key, validation, encryption or serialization errors; writes no intent/store.
pub fn prepare_with_intent(
    secondary_path: &Path,
    new_store: &SecondaryStore,
    primary_snapshot_sha256: &str,
) -> Result<PreparedSecondaryCommit, CommitError> {
    // Production key resolution: the account template key of the store's
    // owner (the file stem), mirroring the primary store's at-write
    // resolution. Journal and store both carry the ENCRYPTED bytes, so no
    // plaintext embeddings ever touch the intent journal.
    let user = secondary_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or_else(|| CommitError::Io("secondary path has no file stem".into()))?;
    if crate::template_key::tpm_available() {
        return crate::template_key::with_camera_store_key(
            &user,
            &crate::storage::key_is_another_accounts,
            |key, state| {
                Ok(prepare_with_key_context(
                    secondary_path,
                    new_store,
                    primary_snapshot_sha256,
                    &key,
                    &user,
                    state,
                ))
            },
        )
        .map_err(|error| {
            CommitError::Store(SecondaryStoreError::Invalid(format!(
                "the account template key is unavailable: {error}"
            )))
        })?;
    }
    prepare_with_intent_key(secondary_path, new_store, primary_snapshot_sha256, None)
}

/// [`publish_with_intent`] with an explicit key: `Some` journals and writes
/// the encrypted envelope; `None` writes the legacy plaintext format
/// (no-TPM degraded hosts, documented).
///
/// # Errors
///
/// Returns [`CommitError`] when validation or any durable step fails. A
/// failure before the commit point leaves the previous store authoritative
/// and the journal for [`resolve_commit`] to finish or discard.
#[cfg(test)]
pub(crate) fn publish_with_intent_key(
    secondary_path: &Path,
    new_store: &SecondaryStore,
    primary_snapshot_sha256: &str,
    key: Option<&[u8]>,
) -> Result<(), CommitError> {
    prepare_with_intent_key(secondary_path, new_store, primary_snapshot_sha256, key)?.publish()
}

fn prepare_with_intent_key(
    secondary_path: &Path,
    new_store: &SecondaryStore,
    primary_snapshot_sha256: &str,
    key: Option<&[u8]>,
) -> Result<PreparedSecondaryCommit, CommitError> {
    new_store.validate()?;
    if new_store.primary_snapshot_sha256 != primary_snapshot_sha256 {
        return Err(CommitError::Store(SecondaryStoreError::Invalid(
            "store binding disagrees with the transaction's primary digest".into(),
        )));
    }
    let plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(new_store).map_err(|e| CommitError::Io(e.to_string()))?,
    );
    let bytes = zeroize::Zeroizing::new(match key {
        Some(key) => {
            let blob = crate::crypto::encrypt(key, &plaintext)
                .map_err(|e| CommitError::Io(e.to_string()))?;
            use base64::Engine as _;
            let envelope = serde_json::json!({
                "format_version": super::SECONDARY_ENC_ENVELOPE_VERSION,
                "key_id": irlume_common::sha256_hex(key),
                "enc": base64::engine::general_purpose::STANDARD.encode(&blob),
            });
            serde_json::to_vec(&envelope).map_err(|e| CommitError::Io(e.to_string()))?
        }
        None => plaintext.to_vec(),
    });
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
        new_secondary_b64: base64::engine::general_purpose::STANDARD.encode(bytes.as_slice()),
    };
    let journal = zeroize::Zeroizing::new(
        serde_json::to_vec(&intent).map_err(|e| CommitError::Io(e.to_string()))?,
    );
    let intent_path = intent_path_for(secondary_path);
    Ok(PreparedSecondaryCommit {
        owner: new_store.owner.clone(),
        secondary_path: secondary_path.to_owned(),
        intent_path,
        bytes,
        journal,
        key_context: None,
    })
}

fn prepare_with_key_context(
    secondary_path: &Path,
    new_store: &SecondaryStore,
    primary_snapshot_sha256: &str,
    key: &[u8],
    user: &str,
    _state: &crate::template_key::UserStateLock,
) -> Result<PreparedSecondaryCommit, CommitError> {
    let mut prepared = prepare_with_intent_key(
        secondary_path,
        new_store,
        primary_snapshot_sha256,
        Some(key),
    )?;
    let path = crate::template_key::key_path(user);
    let envelope = std::fs::read(&path).map_err(|error| CommitError::Io(error.to_string()))?;
    prepared.key_context = Some((path, irlume_common::sha256_hex(&envelope)));
    Ok(prepared)
}

/// Prepared private persistence payload. Admission must precede consuming publish.
/// It is neither cloneable nor printable, retains no key, and zeroizes its payloads.
/// Documented no-TPM publication retains plaintext bytes under owner-only protection.
pub struct PreparedSecondaryCommit {
    owner: String,
    secondary_path: std::path::PathBuf,
    intent_path: std::path::PathBuf,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    journal: zeroize::Zeroizing<Vec<u8>>,
    key_context: Option<(PathBuf, String)>,
}

impl PreparedSecondaryCommit {
    /// Enter the account's late publication boundary after key/payload preparation.
    /// The retained store owner and configured store path must both name `user`.
    /// Production encrypted preparation retains the exact sealed-key envelope
    /// after key resolution, under its lock. A changed/missing envelope refuses
    /// here, without another unseal; first sealing and preparation's legitimate
    /// policy upgrade are observed after they finish, not mistaken for drift.
    /// Core holds the private account-state lock, settling an interrupted primary
    /// replacement before invoking `publication`. The one-shot token cannot escape
    /// this scope, and its publisher does no key resolution or lock acquisition.
    ///
    /// The caller must revalidate current primary/secondary bytes, account and
    /// operation authority, and fresh time after any inventory/configuration wait
    /// and before consuming the token. Machine locks follow the account lock;
    /// AUTH performs its final admission inside that boundary. Use unlocked readers
    /// with an already loaded key: account-locking loaders or key helpers inside
    /// this scope would deadlock.
    /// This is serialization, not authorization. No check runs after the callback,
    /// so its actual persistence result (including recoverable errors) is preserved.
    ///
    /// The scoped token cannot be returned for publication after lock release:
    ///
    /// ```compile_fail
    /// use irlume_core::multi_camera::commit::{AccountSecondaryPublication, PreparedSecondaryCommit};
    /// fn escape(prepared: PreparedSecondaryCommit) -> irlume_common::Result<AccountSecondaryPublication<'static>> {
    ///     prepared.with_account_publication("alice", |publication| Ok(publication))
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns account binding, locking, settlement or callback errors.
    pub fn with_account_publication<R>(
        self,
        user: &str,
        publication: impl for<'a> FnOnce(AccountSecondaryPublication<'a>) -> irlume_common::Result<R>,
    ) -> irlume_common::Result<R> {
        if Path::new(user).file_name() != Some(std::ffi::OsStr::new(user))
            || user.contains('\0')
            || self.owner != user
            || self.secondary_path != super::secondary_store_path(user)
        {
            return Err(irlume_common::Error::Policy(
                "prepared secondary publication does not belong to the target account store".into(),
            ));
        }
        let state = crate::template_key::UserStateLock::acquire(user)?;
        if let Some((path, digest)) = &self.key_context {
            let unchanged = path == &crate::template_key::key_path(user)
                && std::fs::read(path)
                    .is_ok_and(|bytes| irlume_common::sha256_hex(&bytes) == *digest);
            if !unchanged {
                return Err(irlume_common::Error::Policy(
                    "the account template key changed after secondary publication preparation"
                        .into(),
                ));
            }
        }
        publication(AccountSecondaryPublication {
            commit: self,
            _state: &state,
        })
    }

    /// Authorize recover-forward with the intent, then publish and remove it.
    ///
    /// # Errors
    /// A persistence error may leave an already authorized recoverable intent.
    /// Camera admission must not be rechecked between intent and store writes.
    pub fn publish(self) -> Result<(), CommitError> {
        durable_write(&self.intent_path, &self.journal)?;
        // Commit point: the durable rename of the new store.
        durable_write(&self.secondary_path, &self.bytes)?;
        std::fs::remove_file(&self.intent_path)
            .map_err(|e| CommitError::Io(e.to_string()))
            .and_then(|()| {
                fsync_dir(self.intent_path.parent().unwrap_or_else(|| Path::new(".")))
            })?;
        Ok(())
    }
}

/// One-shot persistence confined to a held account publication scope.
pub struct AccountSecondaryPublication<'a> {
    commit: PreparedSecondaryCommit,
    _state: &'a crate::template_key::UserStateLock,
}

impl AccountSecondaryPublication<'_> {
    /// Consume the existing intent/store publisher without new admission checks.
    ///
    /// # Errors
    /// A persistence error may leave an already authorized recoverable intent.
    pub fn publish(self) -> Result<(), CommitError> {
        self.commit.publish()
    }
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
    // The payload may be a plaintext v1 store (legacy journals) or the
    // encrypted envelope (keyed publications). Recovery is verbatim either
    // way - the envelope is never decrypted here (no key is needed to
    // complete a publication that was already authorized) - so validation
    // is structural only: the envelope's fields were checked at publish
    // time and the store is fully validated on the next load.
    let doc: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| CommitError::Io(format!("journal payload corrupt: {e}")))?;
    let declared = doc
        .get("format_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| CommitError::Io("journal payload has no format_version".into()))?;
    if declared == super::SECONDARY_ENC_ENVELOPE_VERSION {
        // A truncated or fabricated envelope must never overwrite the last
        // good store: require the key binding and a decodable ciphertext of
        // plausible length (nonce + tag at minimum). The store itself is
        // validated on the next load.
        use base64::Engine as _;
        let key_id = doc
            .get("key_id")
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CommitError::Io("journal envelope has no usable key_id".into()))?;
        let enc = doc
            .get("enc")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CommitError::Io("journal envelope has no enc field".into()))?;
        let blob = base64::engine::general_purpose::STANDARD
            .decode(enc)
            .map_err(|e| CommitError::Io(format!("journal enc is not base64: {e}")))?;
        if blob.len() <= 12 + 16 || key_id.is_empty() {
            return Err(CommitError::Io(
                "journal envelope ciphertext is implausibly short".into(),
            ));
        }
        let _ = key_id;
    }
    if declared != super::SECONDARY_ENC_ENVELOPE_VERSION {
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
/// This metadata-only compatibility path admits ordinary groups only. A
/// split group requires [`grant_boundary_check_bound`] with the retained pair.
#[must_use]
pub fn grant_boundary_check(
    pinned: &GrantContext,
    current_primary_bytes: Option<&[u8]>,
    current_secondary: Option<&SecondaryStore>,
) -> GrantDecision {
    grant_boundary_check_impl(pinned, None, current_primary_bytes, current_secondary)
}

/// The grant-boundary check with the exact pair retained at pinning. Every
/// metadata check of [`grant_boundary_check`] still applies, and the group's
/// whole binding must equal `pair`, even if generation and group id are unchanged.
/// Ordinary partial bindings are compared exactly, without completing them.
#[must_use]
pub fn grant_boundary_check_bound(
    pinned: &GrantContext,
    pair: &GroupPair,
    current_primary_bytes: Option<&[u8]>,
    current_secondary: Option<&SecondaryStore>,
) -> GrantDecision {
    grant_boundary_check_impl(pinned, Some(pair), current_primary_bytes, current_secondary)
}

fn grant_boundary_check_impl(
    pinned: &GrantContext,
    pair: Option<&GroupPair>,
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
    let Some(group) = secondary
        .groups
        .iter()
        .find(|group| group.id.as_str() == pinned.group_id)
    else {
        return GrantDecision::Refuse("pinned group no longer present (§4.2 revocation)");
    };
    match pair {
        Some(pair) if pair.validate().is_err() || &group.pair != pair => {
            return GrantDecision::Refuse("pinned pair changed during the attempt (§4.2 binding)");
        }
        None if matches!(&group.pair, GroupPair::Split(_)) => {
            return GrantDecision::Refuse("split group requires a whole-pair grant context");
        }
        Some(_) | None => {}
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
    grant_boundary_now_with(
        pinned,
        secondary_path,
        primary_path,
        &mut crate::template_key::RequestTemplateKey::production(),
    )
}

/// [`grant_boundary_now`] lending the request's template key to the
/// secondary re-read (ADR-0025). Every read and check is unchanged; only the
/// key resolution is.
///
/// # Errors
///
/// As [`grant_boundary_now`].
pub fn grant_boundary_now_with(
    pinned: &GrantContext,
    secondary_path: &Path,
    primary_path: &Path,
    keys: &mut dyn crate::template_key::TemplateKeySource,
) -> Result<GrantDecision, CommitError> {
    grant_boundary_now_impl(pinned, None, secondary_path, primary_path, keys)
}

/// Reads both current stores and applies [`grant_boundary_check_bound`] with
/// the pair retained at pinning. Journal recovery and key resolution are shared
/// with the ordinary metadata-only reader.
///
/// # Errors
///
/// Returns [`CommitError`] when journal resolution or store loading fails.
pub fn grant_boundary_now_bound(
    pinned: &GrantContext,
    pair: &GroupPair,
    secondary_path: &Path,
    primary_path: &Path,
) -> Result<GrantDecision, CommitError> {
    grant_boundary_now_bound_with(
        pinned,
        pair,
        secondary_path,
        primary_path,
        &mut crate::template_key::RequestTemplateKey::production(),
    )
}

/// [`grant_boundary_now_bound`] lending the request's existing template key.
/// The current primary is checked by its exact bytes and needs no key.
///
/// # Errors
///
/// As [`grant_boundary_now_bound`].
pub fn grant_boundary_now_bound_with(
    pinned: &GrantContext,
    pair: &GroupPair,
    secondary_path: &Path,
    primary_path: &Path,
    keys: &mut dyn crate::template_key::TemplateKeySource,
) -> Result<GrantDecision, CommitError> {
    grant_boundary_now_impl(pinned, Some(pair), secondary_path, primary_path, keys)
}

fn grant_boundary_now_impl(
    pinned: &GrantContext,
    pair: Option<&GroupPair>,
    secondary_path: &Path,
    primary_path: &Path,
    keys: &mut dyn crate::template_key::TemplateKeySource,
) -> Result<GrantDecision, CommitError> {
    resolve_commit(secondary_path)?;
    let secondary = match super::load_secondary_with_source(secondary_path, keys)? {
        Some(store) => store,
        None => return Ok(grant_boundary_check_impl(pinned, pair, None, None)),
    };
    let primary_bytes = std::fs::read(primary_path).ok();
    Ok(grant_boundary_check_impl(
        pinned,
        pair,
        primary_bytes.as_deref(),
        Some(&secondary),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::{CameraGroupId, GroupPair, SecondaryGroup, SecondaryProfileScans};
    use super::*;
    use crate::storage::FaceScan;
    use irlume_common::split_key::{SplitDomain, SplitPairKey};

    fn split_pair() -> GroupPair {
        GroupPair::Split(
            SplitPairKey::parse_canonical(
                "split1;5986:2113:rgb|0000:00:14.0|usb2|8;5986:1141:ir|0000:00:14.0|usb2|5",
            )
            .unwrap(),
        )
    }

    #[test]
    fn metadata_only_boundary_never_admits_split_but_bound_check_can() {
        let primary = b"primary-bytes";
        let digest = irlume_common::sha256_hex(primary);
        let mut store = store_for(&digest, 12);
        let pair = split_pair();
        store.groups[0].pair = pair.clone();
        let pinned = GrantContext {
            secondary_generation: 12,
            primary_snapshot_sha256: digest,
            group_id: "desk".into(),
        };
        assert!(matches!(
            grant_boundary_check(&pinned, Some(primary), Some(&store)),
            GrantDecision::Refuse(_)
        ));
        assert_eq!(
            grant_boundary_check_bound(&pinned, &pair, Some(primary), Some(&store)),
            GrantDecision::Grant
        );
    }

    #[test]
    fn bound_boundary_refuses_role_location_class_and_same_generation_pair_drift() {
        let primary = b"primary-bytes";
        let digest = irlume_common::sha256_hex(primary);
        let mut store = store_for(&digest, 12);
        let pair = split_pair();
        store.groups[0].pair = pair.clone();
        let pinned = GrantContext {
            secondary_generation: 12,
            primary_snapshot_sha256: digest,
            group_id: "desk".into(),
        };
        let GroupPair::Split(key) = &pair else {
            unreachable!()
        };
        let mut swapped = key.clone();
        std::mem::swap(&mut swapped.rgb, &mut swapped.ir);
        let mut wrong_pairs = vec![
            GroupPair::Split(swapped),
            GroupPair::Ordinary {
                rgb: Some(key.rgb.identity.clone()),
                ir: Some(key.ir.identity.clone()),
            },
        ];
        for rgb in [true, false] {
            for change in 0..4 {
                let mut wrong = key.clone();
                let side = if rgb { &mut wrong.rgb } else { &mut wrong.ir };
                match change {
                    0 => side.identity = "other".into(),
                    1 => side.controller = "0000:00:15.0".into(),
                    2 => side.domain = SplitDomain::SuperSpeed,
                    _ => side.ports.push(1),
                }
                wrong_pairs.push(GroupPair::Split(wrong));
            }
        }
        for wrong in wrong_pairs {
            assert!(matches!(
                grant_boundary_check_bound(&pinned, &wrong, Some(primary), Some(&store)),
                GrantDecision::Refuse(_)
            ));
            let mut edited = store.clone();
            edited.groups[0].pair = wrong;
            assert!(matches!(
                grant_boundary_check_bound(&pinned, &pair, Some(primary), Some(&edited)),
                GrantDecision::Refuse(_)
            ));
        }
        let mut invalid = key.clone();
        invalid.rgb.ports = vec![0];
        let invalid = GroupPair::Split(invalid);
        store.groups[0].pair = invalid.clone();
        assert!(matches!(
            grant_boundary_check_bound(&pinned, &invalid, Some(primary), Some(&store)),
            GrantDecision::Refuse(_)
        ));
    }

    #[test]
    fn bound_ordinary_boundary_retains_partial_pairs_and_checks_exact_pair_drift() {
        let primary = b"primary-bytes";
        let digest = irlume_common::sha256_hex(primary);
        let mut store = store_for(&digest, 12);
        let pinned = GrantContext {
            secondary_generation: 12,
            primary_snapshot_sha256: digest,
            group_id: "desk".into(),
        };
        for pair in [
            store.groups[0].pair.clone(),
            GroupPair::Ordinary {
                rgb: None,
                ir: Some("ir".into()),
            },
        ] {
            store.groups[0].pair = pair.clone();
            assert_eq!(
                grant_boundary_check_bound(&pinned, &pair, Some(primary), Some(&store)),
                GrantDecision::Grant
            );
            store.groups[0].pair = GroupPair::Ordinary {
                rgb: Some("changed".into()),
                ir: Some("ir".into()),
            };
            assert!(matches!(
                grant_boundary_check_bound(&pinned, &pair, Some(primary), Some(&store)),
                GrantDecision::Refuse(_)
            ));
            // The metadata-only ordinary compatibility path keeps its old contract.
            assert_eq!(
                grant_boundary_check(&pinned, Some(primary), Some(&store)),
                GrantDecision::Grant
            );
        }
    }

    #[test]
    fn bound_split_boundary_keeps_generation_digest_activation_and_revocation_checks() {
        let primary = b"primary-bytes";
        let digest = irlume_common::sha256_hex(primary);
        let mut store = store_for(&digest, 12);
        let pair = split_pair();
        store.groups[0].pair = pair.clone();
        let pinned = GrantContext {
            secondary_generation: 12,
            primary_snapshot_sha256: digest,
            group_id: "desk".into(),
        };
        assert_eq!(
            grant_boundary_check_bound(&pinned, &pair, Some(primary), Some(&store)),
            GrantDecision::Grant
        );
        assert!(matches!(
            grant_boundary_check_bound(&pinned, &pair, None, Some(&store)),
            GrantDecision::Refuse(_)
        ));
        assert!(matches!(
            grant_boundary_check_bound(&pinned, &pair, Some(primary), None),
            GrantDecision::Refuse(_)
        ));
        assert!(matches!(
            grant_boundary_check_bound(&pinned, &pair, Some(b"rewritten"), Some(&store)),
            GrantDecision::Refuse(_)
        ));
        for change in 0..3 {
            let mut edited = store.clone();
            match change {
                0 => edited.generation += 1,
                1 => edited.primary_snapshot_sha256 = "a".repeat(64),
                _ => edited.groups.clear(),
            }
            assert!(matches!(
                grant_boundary_check_bound(&pinned, &pair, Some(primary), Some(&edited)),
                GrantDecision::Refuse(_)
            ));
        }
    }

    #[test]
    fn bound_and_metadata_readers_share_current_file_checks_without_split_fallback() {
        let _env = crate::testenv::ENV_LOCK.lock().unwrap();
        let (secondary_path, primary_path) = paths("bound-now");
        let primary = b"primary-bytes";
        std::fs::write(&primary_path, primary).unwrap();
        let digest = irlume_common::sha256_hex(primary);
        let mut store = store_for(&digest, 12);
        let pair = split_pair();
        store.groups[0].pair = pair.clone();
        let pinned = GrantContext {
            secondary_generation: 12,
            primary_snapshot_sha256: digest.clone(),
            group_id: "desk".into(),
        };
        publish_with_intent_key(&secondary_path, &store, &digest, None).unwrap();
        let mut keys = crate::template_key::RequestTemplateKey::with_unsealer(|_| {
            panic!("plaintext needs no key")
        });
        assert!(matches!(
            grant_boundary_now_with(&pinned, &secondary_path, &primary_path, &mut keys),
            Ok(GrantDecision::Refuse(_))
        ));
        assert!(matches!(
            grant_boundary_now_bound_with(
                &pinned,
                &pair,
                &secondary_path,
                &primary_path,
                &mut keys
            ),
            Ok(GrantDecision::Grant)
        ));
        assert!(matches!(
            grant_boundary_now_bound(&pinned, &pair, &secondary_path, &primary_path),
            Ok(GrantDecision::Grant)
        ));
        store.groups[0].pair = GroupPair::Ordinary {
            rgb: Some("rgb".into()),
            ir: Some("ir".into()),
        };
        publish_with_intent_key(&secondary_path, &store, &digest, None).unwrap();
        assert!(matches!(
            grant_boundary_now_bound_with(
                &pinned,
                &pair,
                &secondary_path,
                &primary_path,
                &mut keys
            ),
            Ok(GrantDecision::Refuse(_))
        ));
        assert_eq!(keys.unseals(), 0);
        std::fs::remove_dir_all(secondary_path.parent().unwrap()).unwrap();
    }

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
            captured_at: None,
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
                pair: GroupPair::Ordinary {
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

    struct AccountFixture {
        dir: PathBuf,
        old_state: Option<std::ffi::OsString>,
        old_keys: Option<std::ffi::OsString>,
    }

    impl AccountFixture {
        fn new(tag: &str) -> Self {
            let (path, _) = paths(tag);
            let dir = path.parent().unwrap().to_owned();
            let fixture = Self {
                old_state: std::env::var_os("IRLUME_STATE_DIR"),
                old_keys: std::env::var_os("IRLUME_TEMPLATE_KEY_DIR"),
                dir,
            };
            std::env::set_var("IRLUME_STATE_DIR", &fixture.dir);
            std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", fixture.dir.join("keys"));
            fixture
        }

        fn prepare(&self, owner: &str, generation: u64) -> PreparedSecondaryCommit {
            let digest = irlume_common::sha256_hex(b"primary-v1");
            let mut store = store_for(&digest, generation);
            store.owner = owner.into();
            store.groups[0].pair = split_pair();
            prepare_with_intent_key(
                &super::super::secondary_store_path("alice"),
                &store,
                &digest,
                Some(&[0x51; 32]),
            )
            .unwrap()
        }
    }

    impl Drop for AccountFixture {
        fn drop(&mut self) {
            for (name, old) in [
                ("IRLUME_STATE_DIR", &self.old_state),
                ("IRLUME_TEMPLATE_KEY_DIR", &self.old_keys),
            ] {
                match old {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    // Independent open description: tests real contention, not lock-file existence.
    fn state_lock_available(user: &str) -> bool {
        use std::os::fd::AsRawFd;
        let path = crate::template_key::key_dir().join(".locks").join(format!(
            "{}.lock",
            irlume_common::sha256_hex(user.as_bytes())
        ));
        let Ok(file) = std::fs::OpenOptions::new().read(true).open(path) else {
            return true;
        };
        // SAFETY: the independently opened file owns a live descriptor until return.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            true // Closing this independent description releases its lock.
        } else {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EWOULDBLOCK)
            );
            false
        }
    }

    fn commit_error(error: CommitError) -> irlume_common::Error {
        irlume_common::Error::Io(error.to_string())
    }

    #[test]
    fn account_publication_holds_real_lock_through_checks_and_publish_once() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fixture = AccountFixture::new("account-once");
        let prepared = fixture.prepare("alice", 2);
        drop(crate::template_key::UserStateLock::acquire("bob").unwrap());
        assert!(
            state_lock_available("alice"),
            "preparation retains no transaction lock"
        );
        let path = super::super::secondary_store_path("alice");
        let mut calls = 0;
        let result = prepared
            .with_account_publication("alice", |publication| {
                calls += 1;
                assert!(
                    !state_lock_available("alice"),
                    "late admission must exclude account writers"
                );
                assert!(
                    state_lock_available("bob"),
                    "other accounts are independent"
                );
                assert!(!intent_path_for(&path).exists());
                publication.publish().map_err(commit_error)?;
                assert!(
                    !state_lock_available("alice"),
                    "guard must survive consuming persistence"
                );
                Ok(37)
            })
            .unwrap();
        assert_eq!(result, 37);
        assert_eq!(calls, 1);
        assert!(state_lock_available("alice"));
        let store = super::super::load_secondary_with_key(&path, Some(&[0x51; 32]))
            .unwrap()
            .unwrap();
        assert_eq!(store.generation, 2);
        assert_eq!(store.groups[0].pair, split_pair());
        assert_eq!(resolve_commit(&path).unwrap(), CommitResolution::Clean);
    }

    #[test]
    fn account_publication_denied_admission_changes_neither_store_nor_intent() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fixture = AccountFixture::new("account-denied");
        let path = super::super::secondary_store_path("alice");
        fixture.prepare("alice", 1).publish().unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut calls = 0;
        let result: irlume_common::Result<()> = fixture
            .prepare("alice", 2)
            .with_account_publication("alice", |_publication| {
                calls += 1;
                assert!(!state_lock_available("alice"));
                Err(irlume_common::Error::Policy("admission denied".into()))
            });
        assert!(
            matches!(result, Err(irlume_common::Error::Policy(ref s)) if s == "admission denied")
        );
        assert_eq!(calls, 1);
        assert!(state_lock_available("alice"));
        assert!(!intent_path_for(&path).exists());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(resolve_commit(&path).unwrap(), CommitResolution::Clean);
    }

    #[test]
    fn account_publication_rejects_wrong_user_owner_and_path_before_callback() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fixture = AccountFixture::new("account-binding");
        let path = super::super::secondary_store_path("alice");
        for (owner, user) in [("alice", "bob"), ("bob", "alice")] {
            let result = fixture
                .prepare(owner, 1)
                .with_account_publication(user, |publication| {
                    publication.publish().map_err(commit_error)
                });
            assert!(matches!(result, Err(irlume_common::Error::Policy(_))));
            assert!(!path.exists());
            assert!(!intent_path_for(&path).exists());
        }
        let digest = irlume_common::sha256_hex(b"primary-v1");
        let alias = fixture.dir.join("alice.json");
        let prepared =
            prepare_with_intent_key(&alias, &store_for(&digest, 1), &digest, None).unwrap();
        assert!(prepared
            .with_account_publication("alice", |_| -> irlume_common::Result<()> {
                panic!("foreign store path must never enter admission")
            })
            .is_err());
        assert!(!alias.exists());
        assert!(!intent_path_for(&alias).exists());
    }

    #[test]
    fn account_publication_unwind_releases_lock_without_authorizing_recovery() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fixture = AccountFixture::new("account-unwind");
        let mut entered = false;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fixture.prepare("alice", 1).with_account_publication(
                "alice",
                |_| -> irlume_common::Result<()> {
                    entered = true;
                    assert!(!state_lock_available("alice"));
                    panic!("admission unwind")
                },
            )
        }));
        assert!(entered);
        let panic = result.expect_err("callback must unwind");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"admission unwind"));
        assert!(state_lock_available("alice"));
        let path = super::super::secondary_store_path("alice");
        assert!(!path.exists());
        assert_eq!(resolve_commit(&path).unwrap(), CommitResolution::Clean);
    }

    #[test]
    fn account_publication_store_failure_retains_admitted_intent_for_recovery() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fixture = AccountFixture::new("account-recovery");
        let path = super::super::secondary_store_path("alice");
        fixture.prepare("alice", 1).publish().unwrap();
        let before = std::fs::read(&path).unwrap();
        let prepared = fixture.prepare("alice", 2);
        let staging = super::super::staging_path(&path, super::super::COMMIT_STAGING_TAG);
        std::fs::write(&staging, b"block store staging only").unwrap();
        let mut entered = false;
        let result = prepared.with_account_publication("alice", |publication| {
            entered = true;
            assert!(!state_lock_available("alice"));
            publication.publish().map_err(commit_error)
        });
        assert!(entered);
        assert!(result.is_err());
        assert!(state_lock_available("alice"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(
            intent_path_for(&path).is_file(),
            "already admitted intent must survive error"
        );
        std::fs::remove_file(staging).unwrap();
        assert_eq!(resolve_commit(&path).unwrap(), CommitResolution::Completed);
        assert_eq!(
            super::super::load_secondary_with_key(&path, Some(&[0x51; 32]))
                .unwrap()
                .unwrap()
                .generation,
            2
        );
    }

    #[test]
    fn account_publication_returns_post_visible_callback_error_without_rollback() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fixture = AccountFixture::new("account-visible");
        let path = super::super::secondary_store_path("alice");
        let result: irlume_common::Result<()> = fixture
            .prepare("alice", 4)
            .with_account_publication("alice", |publication| {
                publication.publish().map_err(commit_error)?;
                Err(irlume_common::Error::Io(
                    "caller observed visible publication".into(),
                ))
            });
        assert!(
            matches!(result, Err(irlume_common::Error::Io(ref s)) if s == "caller observed visible publication")
        );
        assert!(state_lock_available("alice"));
        assert_eq!(
            super::super::load_secondary_with_key(&path, Some(&[0x51; 32]))
                .unwrap()
                .unwrap()
                .generation,
            4
        );
        assert_eq!(resolve_commit(&path).unwrap(), CommitResolution::Clean);
    }

    #[test]
    fn account_publication_settles_visible_primary_replacement_before_admission() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fixture = AccountFixture::new("account-settlement");
        let primary = super::super::primary_enrollment_path("alice");
        std::fs::write(&primary, b"old primary bytes").unwrap();
        fixture.prepare("alice", 1).publish().unwrap();
        let prepared = fixture.prepare("alice", 2);
        {
            let _state = crate::template_key::UserStateLock::acquire("alice").unwrap();
            crate::replacement::begin("alice", None).unwrap();
            std::fs::write(&primary, b"visible replacement primary bytes").unwrap();
        }
        let path = super::super::secondary_store_path("alice");
        assert!(path.exists());
        assert!(crate::replacement::record_path("alice").exists());
        let mut entered = false;
        let result: irlume_common::Result<()> = prepared.with_account_publication("alice", |_| {
            entered = true;
            assert!(!state_lock_available("alice"));
            assert!(
                !path.exists(),
                "replacement must settle before secondary admission"
            );
            assert!(!crate::replacement::record_path("alice").exists());
            assert_eq!(
                std::fs::read(&primary).unwrap(),
                b"visible replacement primary bytes"
            );
            Err(irlume_common::Error::Policy(
                "source snapshot changed".into(),
            ))
        });
        assert!(entered);
        assert!(result.is_err());
        assert!(!path.exists());
        assert!(state_lock_available("alice"));
        assert_eq!(resolve_commit(&path).unwrap(), CommitResolution::Clean);
    }

    fn prepare_synthetic_account_key(
        fixture: &AccountFixture,
    ) -> (PreparedSecondaryCommit, zeroize::Zeroizing<Vec<u8>>) {
        let user = "alice";
        let state = crate::template_key::UserStateLock::acquire(user).unwrap();
        let persisted = std::cell::RefCell::new(zeroize::Zeroizing::new(vec![0x51; 32]));
        let key = crate::template_key::camera_store_key_with(
            user,
            &mut crate::account::Account::new(user),
            &|_, _, _| Ok(false),
            |_, _| Ok(persisted.borrow().clone()),
            |user, _| {
                std::fs::write(
                    crate::template_key::key_path(user),
                    b"upgraded seal of same key",
                )
                .unwrap()
            },
            |user, key, _| {
                *persisted.borrow_mut() = zeroize::Zeroizing::new(key.to_vec());
                std::fs::write(crate::template_key::key_path(user), b"first synthetic seal")
                    .map_err(|e| irlume_common::Error::Io(e.to_string()))
            },
        )
        .unwrap();
        assert!(fixture.dir.exists());
        let digest = irlume_common::sha256_hex(b"primary-v1");
        let prepared = prepare_with_key_context(
            &super::super::secondary_store_path(user),
            &store_for(&digest, 2),
            &digest,
            &key,
            user,
            &state,
        )
        .unwrap();
        (prepared, key)
    }

    #[test]
    fn account_publication_refuses_key_envelope_drift_after_preparation() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fixture = AccountFixture::new("account-key-drift");
        let _account = crate::account::remember("alice", 41001);
        for replacement in [Some(b"different seal".as_slice()), None] {
            let (prepared, _key) = prepare_synthetic_account_key(&fixture);
            let key_path = crate::template_key::key_path("alice");
            match replacement {
                Some(bytes) => std::fs::write(&key_path, bytes).unwrap(),
                None => std::fs::remove_file(&key_path).unwrap(),
            }
            let mut entered = false;
            let result = prepared.with_account_publication("alice", |publication| {
                entered = true;
                publication.publish().map_err(commit_error)
            });
            assert!(result.is_err(), "changed encryption context must refuse");
            assert!(!entered, "key drift must precede AUTH admission");
            let path = super::super::secondary_store_path("alice");
            assert!(!path.exists());
            assert_eq!(resolve_commit(&path).unwrap(), CommitResolution::Clean);
            assert!(state_lock_available("alice"));
        }
    }

    #[test]
    fn account_publication_accepts_first_seal_and_legitimate_preparation_upgrade() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fixture = AccountFixture::new("account-key-upgrade");
        let _account = crate::account::remember("alice", 41001);
        for expected in [
            b"first synthetic seal".as_slice(),
            b"upgraded seal of same key".as_slice(),
        ] {
            let (prepared, key) = prepare_synthetic_account_key(&fixture);
            assert_eq!(
                std::fs::read(crate::template_key::key_path("alice")).unwrap(),
                expected
            );
            prepared
                .with_account_publication("alice", |publication| {
                    assert!(!state_lock_available("alice"));
                    publication.publish().map_err(commit_error)
                })
                .unwrap();
            let path = super::super::secondary_store_path("alice");
            assert_eq!(
                super::super::load_secondary_with_key(&path, Some(&key))
                    .unwrap()
                    .unwrap()
                    .generation,
                2
            );
        }
    }

    #[test]
    fn publish_is_clean_without_a_journal_and_round_trips() {
        let (secondary_path, _) = paths("clean");
        let primary_digest = irlume_common::sha256_hex(b"primary-v1");
        let store = store_for(&primary_digest, 1);
        publish_with_intent_key(&secondary_path, &store, &primary_digest, None).expect("publish");
        assert!(matches!(
            resolve_commit(&secondary_path),
            Ok(CommitResolution::Clean)
        ));
        assert!(load_secondary(&secondary_path).expect("load").is_some());
        let _ = std::fs::remove_dir_all(secondary_path.parent().unwrap());
    }

    #[test]
    fn prepared_secondary_refusal_leaves_no_recover_forward_intent() {
        let (path, _) = paths("prepared-refusal");
        let digest = irlume_common::sha256_hex(b"primary-v1");
        let old = store_for(&digest, 1);
        publish_with_intent_key(&path, &old, &digest, None).unwrap();
        let before = std::fs::read(&path).unwrap();
        let prepared =
            prepare_with_intent_key(&path, &store_for(&digest, 2), &digest, None).unwrap();
        assert!(
            !intent_path_for(&path).exists(),
            "preparation must not authorize recovery"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(prepared); // Admission refused; the one-shot payload is never published.
        assert!(matches!(resolve_commit(&path), Ok(CommitResolution::Clean)));
        assert_eq!(std::fs::read(&path).unwrap(), before);

        prepare_with_intent_key(&path, &store_for(&digest, 2), &digest, None)
            .unwrap()
            .publish()
            .unwrap();
        assert_eq!(load_secondary(&path).unwrap().unwrap().generation, 2);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
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
        let error = publish_with_intent_key(&secondary_path, &store, &"b".repeat(64), None)
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
        publish_with_intent_key(&secondary_path, &store, &digest, None).expect("publish");
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
