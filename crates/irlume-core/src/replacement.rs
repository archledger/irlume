// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The record an enrollment write keeps while it replaces another uid's
//! enrollment (#904).
//!
//! Such a write seals a new template key over the replaced one before it
//! publishes the new enrollment, and once that enrollment is durable it
//! removes the replaced key's recovery envelope and the replaced
//! enrollment's added-camera store and its commit journal. Before it changes
//! anything it records, durably, what it replaces: the replaced key's
//! envelope file, and digests of the enrollment, recovery envelope,
//! added-camera store and journal files as they are then. The record lives
//! beside the account's state lock, under the template-key directory. It
//! goes, durably, once the write has finished or undone the replacement and
//! synced what that changed ([`finish`], [`undo`]).
//!
//! A record left behind, because the write stopped part way, its enrollment
//! may not survive a power loss, or a step failed, is settled the next time
//! the account's state lock is taken ([`settle_interrupted`]). While the
//! stored enrollment is still the replaced one, the replacement published
//! nothing that stayed, and the replaced key goes back. Otherwise the new
//! enrollment was published: the replacement is finished. Finishing removes
//! only files that are still as recorded, so it never removes a recovery
//! envelope, store or journal written since.

use crate::{multi_camera, storage, template_key};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use irlume_common::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    /// The replaced template key's envelope file, base64; `None` when the
    /// write replaces no key (a plaintext enrollment on a host without a
    /// TPM, or one beside a key the write keeps).
    key: Option<String>,
    /// SHA-256 (hex) of the enrollment file the write replaces; `None`
    /// when none was stored.
    enrollment: Option<String>,
    /// SHA-256 of the replaced key's recovery envelope; `None` when none
    /// was stored or no key is replaced (it restores only that key).
    recovery: Option<String>,
    /// SHA-256 of the replaced enrollment's added-camera store; `None`
    /// when none was stored.
    camera_store: Option<String>,
    /// SHA-256 of that store's commit journal, which can publish a store
    /// on its own; `None` when none was stored.
    camera_journal: Option<String>,
}

/// Where the record of `user`'s replacement is kept: in the template-key
/// directory, beside the state lock it is settled under
/// (`template_key::UserStateLock`), under a name no listing reads.
#[must_use]
pub(crate) fn record_path(user: &str) -> PathBuf {
    template_key::key_dir().join(format!("{user}.replacing"))
}

/// SHA-256 of the file at `path`, or `None` when there is none. The files
/// may hold plaintext templates (a host without a TPM), so they are hashed
/// through one zeroized buffer, never copied whole.
fn digest(path: &Path) -> Result<Option<String>> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    let unreadable = |e: std::io::Error| Error::Io(format!("read {}: {e}", path.display()));
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(unreadable(e)),
    };
    let mut hasher = Sha256::new();
    let mut buffer = zeroize::Zeroizing::new([0u8; 8192]);
    loop {
        match file.read(&mut buffer[..]) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(unreadable(e)),
        }
    }
    Ok(Some(
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    ))
}

/// Sync the directory holding `path`, so a rename or removal in it lasts.
/// A directory that does not exist holds nothing to sync.
fn sync_parent(path: &Path) -> std::io::Result<()> {
    match path.parent().map(std::fs::File::open) {
        Some(Ok(dir)) => dir.sync_all(),
        Some(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Some(Err(e)) => Err(e),
        None => Ok(()),
    }
}

/// Remove the file at `path` while it is as recorded (`recorded`, its
/// digest), then sync its directory whether or not this call removed it,
/// so a removal an earlier attempt made lasts too.
fn remove_if_recorded(path: &Path, recorded: Option<&String>) -> std::io::Result<bool> {
    let mut removed = false;
    if recorded.is_some()
        && digest(path)
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .as_ref()
            == recorded
    {
        match std::fs::remove_file(path) {
            Ok(()) => removed = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    sync_parent(path)?;
    Ok(removed)
}

/// Record, durably, that a write under `user`'s state lock is about to
/// replace another uid's enrollment, and `key`, the replaced template key's
/// envelope file (`None`: no key is replaced). Nothing is replaced unless
/// this succeeds.
///
/// # Errors
/// A file the record describes cannot be read, or the record cannot be
/// written durably: the write is refused with nothing replaced.
pub(crate) fn begin(user: &str, key: Option<&[u8]>) -> Result<()> {
    let record = Record {
        version: VERSION,
        key: key.map(|key| STANDARD.encode(key)),
        enrollment: digest(&storage::profile_path(user))?,
        recovery: match key {
            Some(_) => digest(&template_key::recovery_path(user))?,
            None => None,
        },
        camera_store: digest(&multi_camera::secondary_store_path(user))?,
        camera_journal: digest(&multi_camera::commit::intent_path_for(
            &multi_camera::secondary_store_path(user),
        ))?,
    };
    let bytes = serde_json::to_vec(&record).map_err(|e| Error::Io(e.to_string()))?;
    let path = record_path(user);
    let refused = |why: String| {
        Error::Io(format!(
            "the enrollment of '{user}' replaces another uid's, and the record of that \
             replacement could not be written to {} ({why}), so nothing was replaced",
            path.display()
        ))
    };
    match irlume_common::write_atomic_reporting(&path, &bytes, 0o600) {
        // The template-key directory may have just been created (the state
        // lock creates it on a host without a TPM): its own entry must last
        // too, or the record goes with it.
        Ok(irlume_common::AtomicWrite::Durable) => {
            let dir = template_key::key_dir();
            sync_parent(&dir).map_err(|error| {
                let _ = std::fs::remove_file(&path);
                refused(error.to_string())
            })
        }
        Ok(irlume_common::AtomicWrite::VisibleNotDurable(error)) => {
            // Nothing is replaced yet: a record that stays is settled as a
            // replacement that published nothing.
            let _ = std::fs::remove_file(&path);
            Err(refused(error.to_string()))
        }
        Err(error) => Err(refused(error.to_string())),
    }
}

fn read(user: &str) -> Result<Option<Record>> {
    let path = record_path(user);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(unreadable(user, &path, &e.to_string())),
    };
    let record: Record =
        serde_json::from_slice(&bytes).map_err(|e| unreadable(user, &path, &e.to_string()))?;
    if record.version != VERSION {
        return Err(unreadable(
            user,
            &path,
            &format!("version {} is not known", record.version),
        ));
    }
    Ok(Some(record))
}

fn unreadable(user: &str, path: &Path, why: &str) -> Error {
    Error::Io(format!(
        "an enrollment write of '{user}' that replaced another uid's did not finish, and its \
         record {} cannot be read ({why}); nothing of '{user}' changes until it is: check the \
         enrollment and template key, then move the record away",
        path.display()
    ))
}

/// The record goes: the replacement is finished or undone.
fn end(user: &str) -> Result<()> {
    let path = record_path(user);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(Error::Io(format!(
                "the replacement of the enrollment of '{user}' is settled, but its record {} \
                 could not be removed: {e}",
                path.display()
            )))
        }
    }
    sync_parent(&path).map_err(|e| {
        Error::Io(format!(
            "the replacement of the enrollment of '{user}' is settled, but the removal of its \
             record {} may not last: {e}",
            path.display()
        ))
    })
}

/// Finish `user`'s replacement once its enrollment is published: remove
/// the replaced key's recovery envelope, which can only restore that key,
/// and the replaced enrollment's added-camera store, each only while it is
/// as recorded, then the record. The store's groups were captured for the
/// replaced enrollment, are bound to its bytes, and on a host without a TPM
/// are plaintext, so they are not left for the account the name now
/// resolves to. A step that fails keeps the record, and
/// the next acquisition of the state lock tries again. Nothing to do
/// without a record.
///
/// # Errors
/// The record cannot be read, the enrollment's directory cannot be synced
/// (the enrollment might not survive a power loss yet), or a removal
/// failed.
pub(crate) fn finish(user: &str) -> Result<()> {
    let Some(record) = read(user)? else {
        return Ok(());
    };
    sync_parent(&storage::profile_path(user)).map_err(|e| {
        Error::Io(format!(
            "the enrollment of '{user}' replaced another uid's, but it may not survive a power \
             loss yet ({e}); the replaced key's recovery envelope and added-camera store are \
             kept until it does"
        ))
    })?;
    remove_if_recorded(&template_key::recovery_path(user), record.recovery.as_ref()).map_err(
        |e| {
            Error::Io(format!(
                "the enrollment of '{user}' was saved under a new template key, but the \
                 recovery envelope of the replaced key could not be removed: {e}"
            ))
        },
    )?;
    let store = multi_camera::secondary_store_path(user);
    let journal = multi_camera::commit::intent_path_for(&store);
    let store_error = |e: std::io::Error| {
        Error::Io(format!(
            "the enrollment of '{user}' was saved, but the added-camera store of the enrollment \
             it replaced, which belonged to another uid, could not be removed ({e}); irlume \
             tries again the next time it reads or changes the records of '{user}', or remove \
             {} and {} by hand",
            store.display(),
            journal.display()
        ))
    };
    // The journal first: it can publish a store on its own.
    let journal_removed =
        remove_if_recorded(&journal, record.camera_journal.as_ref()).map_err(store_error)?;
    let store_removed =
        remove_if_recorded(&store, record.camera_store.as_ref()).map_err(store_error)?;
    if journal_removed || store_removed {
        irlume_common::jout_notice!(
            "irlume: removed the added-camera store of the enrollment of '{user}' that belonged \
             to another uid"
        );
    }
    end(user)
}

/// Undo `user`'s replacement, which published nothing that stayed: put the
/// replaced template key back when the key file is no longer it, then the
/// record goes. Nothing to do without a record.
///
/// # Errors
/// The record cannot be read, or the key cannot be put back durably: the
/// record stays.
pub(crate) fn undo(user: &str) -> Result<()> {
    let Some(record) = read(user)? else {
        return Ok(());
    };
    if let Some(key) = &record.key {
        let path = record_path(user);
        let replaced = STANDARD
            .decode(key)
            .map_err(|e| unreadable(user, &path, &e.to_string()))?;
        let key_path = template_key::key_path(user);
        let put_back = |e: std::io::Error| {
            Error::Io(format!(
                "the enrollment of '{user}' was not written, and the template key it replaced \
                 could not be put back ({e}); its recovery envelope is kept"
            ))
        };
        if std::fs::read(&key_path).ok().as_deref() != Some(replaced.as_slice()) {
            irlume_common::write_0600_atomic(&key_path, &replaced).map_err(put_back)?;
        }
        // Whether or not this call wrote it: an earlier put-back may have
        // renamed the key in without its directory reaching the disk.
        sync_parent(&key_path).map_err(put_back)?;
    }
    end(user)
}

/// Settle a replacement of `user`'s enrollment that a write left
/// unfinished: undo it while the stored enrollment is still the replaced
/// one, else finish it. Called with the state lock held, before the
/// operation that took it. For a load (`loading`), a finish that fails is
/// logged instead: the new enrollment is in place, and what is left to
/// remove belonged to the replaced one, so the load goes on and the next
/// acquisition of the lock tries again.
///
/// # Errors
/// As [`undo`] and [`finish`] (for a load, as [`undo`], or the record or
/// enrollment cannot be read); the operation that took the lock is then
/// refused, and the record stays for the next one.
pub(crate) fn settle_interrupted(user: &str, loading: bool) -> Result<()> {
    let Some(record) = read(user)? else {
        return Ok(());
    };
    if digest(&storage::profile_path(user))? == record.enrollment {
        return undo(user);
    }
    match finish(user) {
        Err(error) if loading => {
            irlume_common::jout_warn!("irlume: {error}");
            Ok(())
        }
        settled => settled,
    }
}

#[cfg(test)]
mod tests {
    use super::digest;

    /// The streamed digest is the digest of the whole file, across buffer
    /// boundaries; a missing file has none, and a directory is an error.
    #[test]
    fn a_streamed_digest_is_the_whole_files() {
        let dir = std::path::PathBuf::from(crate::test_tmp_dir("replacement-digest"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file");
        for len in [0usize, 1, 8191, 8192, 8193, 20_000] {
            let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            std::fs::write(&path, &bytes).unwrap();
            assert_eq!(
                digest(&path).unwrap(),
                Some(irlume_common::sha256_hex(&bytes)),
                "{len} bytes"
            );
        }
        assert_eq!(digest(&dir.join("missing")).unwrap(), None);
        assert!(digest(&dir).is_err(), "a directory");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
