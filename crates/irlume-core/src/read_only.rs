// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Non-creating account reads for developer measurements, never authentication authority.

use crate::{account, multi_camera, storage, template_key};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Closed failures: no account names, paths, digests or operating-system errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    #[error("account state unavailable")]
    Unavailable,
    #[error("account state requires repair")]
    PendingRepair,
    #[error("account state changed")]
    Changed,
}

/// A short-lived read transaction. Never retain it while capturing a face:
/// [`Self::finish`] releases the lock so revocation can proceed between reads.
pub struct AccountView {
    state: AccountStatePin,
    lock: template_key::UserStateLock,
    _account: account::RememberedUid,
}

/// Private source identities retained between admission and the final check.
/// No biometrics or keys are stored here; this type is deliberately not serialized.
pub struct AccountStatePin {
    user: String,
    uid: u32,
    paths: [PathBuf; 3],
    files: [Option<FileStamp>; 3],
}

#[derive(PartialEq, Eq)]
struct FileStamp {
    metadata: [u64; 9],
    digest: String,
}

impl AccountView {
    /// Open existing account state without waiting, creating files or recovering journals.
    ///
    /// # Errors
    /// Refuses missing/busy locks, unresolved accounts, unreadable or non-regular
    /// files, pending journals and state that changes during the read.
    pub fn open(user: &str) -> Result<Self, ReadError> {
        if user.is_empty()
            || user.len() > 256
            || matches!(user, "." | "..")
            || user.bytes().any(|b| b == b'/' || b == 0)
        {
            return Err(ReadError::Unavailable);
        }
        let lock = template_key::UserStateLock::try_acquire_read_only(user)
            .map_err(|_| ReadError::Unavailable)?;
        let account::Resolution::Uid(uid) = account::resolve_fresh(user) else {
            return Err(ReadError::Unavailable);
        };
        // The shared parser and key loader honor process-wide account holds.
        // Bind both to this fresh UID, or refuse a conflicting in-flight hold.
        let held = account::hold(user, uid).map_err(|_| ReadError::Changed)?;
        let paths = [
            storage::profile_path(user),
            multi_camera::secondary_store_path(user),
            template_key::key_path(user),
        ];
        let files = capture(user, &paths)?;
        Ok(Self {
            state: AccountStatePin {
                user: user.into(),
                uid,
                paths,
                files,
            },
            lock,
            _account: held,
        })
    }

    /// Load the primary through the production parser and read-only key unsealer.
    ///
    /// # Errors
    /// Refuses parse/key/account failures or state changes. Never reenters the lock.
    pub fn load_primary(&self) -> Result<Option<storage::PrimarySnapshot>, ReadError> {
        self.load_primary_with(template_key::load_key_read_only_as)
    }

    fn load_primary_with(
        &self,
        load_key: impl FnOnce(
            &str,
            &mut account::Account<'_>,
        ) -> irlume_common::Result<Zeroizing<Vec<u8>>>,
    ) -> Result<Option<storage::PrimarySnapshot>, ReadError> {
        self.state.check()?;
        let Some(mut bytes) = read_file(&self.state.paths[0])? else {
            return Ok(None);
        };
        let loaded = storage::snapshot_locked(
            &self.state.user,
            std::mem::take(&mut *bytes),
            &self.lock,
            load_key,
        )
        .map_err(|_| ReadError::Unavailable)?;
        self.state.check()?;
        if loaded
            .as_ref()
            .is_some_and(|s| s.enrollment.user != self.state.user)
        {
            return Err(ReadError::Unavailable);
        }
        Ok(loaded)
    }

    /// Load current secondary data with the request's one borrowed key source.
    ///
    /// # Errors
    /// Refuses parsing, decryption or source changes. No journal recovery occurs.
    pub fn load_secondary(
        &self,
        keys: &mut dyn template_key::TemplateKeySource,
    ) -> Result<Option<multi_camera::SecondaryStore>, ReadError> {
        self.state.check()?;
        let store = read_file(&self.state.paths[1])?
            .map(|bytes| {
                multi_camera::parse_secondary_with_source(&self.state.paths[1], &bytes, keys)
                    .map_err(|_| ReadError::Unavailable)
            })
            .transpose()?;
        self.state.check()?;
        if store.as_ref().is_some_and(|s| s.owner != self.state.user) {
            return Err(ReadError::Unavailable);
        }
        Ok(store)
    }

    /// Current primary bytes for the production pure secondary-boundary predicate.
    ///
    /// # Errors
    /// Refuses unavailable or changed state.
    pub fn primary_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>, ReadError> {
        self.state.check()?;
        let bytes = read_file(&self.state.paths[0])?;
        self.state.check()?;
        Ok(bytes)
    }

    /// Check for late changes, release the account lock, and retain the source pin.
    ///
    /// # Errors
    /// Refuses any late journal, file or account change.
    pub fn finish(self) -> Result<AccountStatePin, ReadError> {
        self.state.check()?;
        Ok(self.state)
    }
}

impl AccountStatePin {
    /// Reacquire a short read transaction at a later request boundary.
    ///
    /// # Errors
    /// Refuses any changed account, path, file, journal, or unavailable lock.
    pub fn reopen(&self) -> Result<AccountView, ReadError> {
        let view = AccountView::open(&self.user)?;
        if view.state.uid != self.uid
            || view.state.paths != self.paths
            || view.state.files != self.files
        {
            return Err(ReadError::Changed);
        }
        Ok(view)
    }

    fn check(&self) -> Result<(), ReadError> {
        if account::resolve_fresh(&self.user) != account::Resolution::Uid(self.uid)
            || capture(&self.user, &self.paths)? != self.files
        {
            return Err(ReadError::Changed);
        }
        Ok(())
    }
}

fn no_journals(user: &str, secondary: &Path) -> Result<(), ReadError> {
    for path in [
        crate::replacement::record_path(user),
        multi_camera::commit::intent_path_for(secondary),
    ] {
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Err(ReadError::PendingRepair),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ReadError::Unavailable),
        }
    }
    Ok(())
}

fn metadata(m: &std::fs::Metadata) -> [u64; 9] {
    [
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
        u64::from(m.mode()),
        (u64::from(m.uid()) << 32) | u64::from(m.gid()),
    ]
}

// A stricter diagnostic ceiling, not a new production enrollment limit.
fn read_file(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, ReadError> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ReadError::Unavailable),
    };
    let before = file.metadata().map_err(|_| ReadError::Unavailable)?;
    if !before.is_file() || before.len() > multi_camera::MAX_STORE_BYTES as u64 {
        return Err(ReadError::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&file)
        .take(multi_camera::MAX_STORE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadError::Unavailable)?;
    let after = std::fs::symlink_metadata(path).map_err(|_| ReadError::Changed)?;
    if bytes.len() > multi_camera::MAX_STORE_BYTES || metadata(&before) != metadata(&after) {
        return Err(ReadError::Changed);
    }
    Ok(Some(bytes))
}

fn capture(user: &str, paths: &[PathBuf; 3]) -> Result<[Option<FileStamp>; 3], ReadError> {
    no_journals(user, &paths[1])?;
    let mut stamps = [None, None, None];
    for (path, stamp) in paths.iter().zip(&mut stamps) {
        if let Some(bytes) = read_file(path)? {
            let m = std::fs::symlink_metadata(path).map_err(|_| ReadError::Changed)?;
            *stamp = Some(FileStamp {
                metadata: metadata(&m),
                digest: irlume_common::sha256_hex(&bytes),
            });
        }
    }
    no_journals(user, &paths[1])?;
    Ok(stamps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account, multi_camera, storage, template_key};
    use std::path::PathBuf;

    struct Fixture {
        dir: PathBuf,
        previous: Option<std::ffi::OsString>,
        _uid: account::RememberedUid,
        _tpm: crate::testenv::NoTpm,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = PathBuf::from(crate::test_tmp_dir("read-only-view"));
            let _ = std::fs::remove_dir_all(&dir);
            let previous = std::env::var_os("IRLUME_STATE_DIR");
            std::env::set_var("IRLUME_STATE_DIR", &dir);
            Self {
                dir,
                previous,
                _uid: account::remember("u", 1000),
                _tpm: crate::testenv::NoTpm::set(),
            }
        }

        fn populate(&self) {
            drop(template_key::UserStateLock::acquire("u").unwrap());
            let path = storage::profile_path("u");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                path,
                storage::serialize_enrollment(&storage::Enrollment::new("u"), None).unwrap(),
            )
            .unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var("IRLUME_STATE_DIR", value),
                None => std::env::remove_var("IRLUME_STATE_DIR"),
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn read_only_view_requires_existing_state_and_releases_the_lock() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        assert!(AccountView::open("u").is_err());
        assert!(!f.dir.exists());
        f.populate();
        let before = std::fs::read(storage::profile_path("u")).unwrap();
        let view = AccountView::open("u").unwrap();
        assert!(AccountView::open("u").is_err());
        assert_eq!(view.load_primary().unwrap().unwrap().enrollment.user, "u");
        let pin = view.finish().unwrap();
        pin.reopen().unwrap().finish().unwrap();
        assert_eq!(std::fs::read(storage::profile_path("u")).unwrap(), before);
    }

    #[test]
    fn read_only_view_refuses_both_journals_without_recovery() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.populate();
        for path in [
            crate::replacement::record_path("u"),
            multi_camera::commit::intent_path_for(&multi_camera::secondary_store_path("u")),
        ] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"pending").unwrap();
            assert!(matches!(
                AccountView::open("u"),
                Err(ReadError::PendingRepair)
            ));
            assert_eq!(std::fs::read(&path).unwrap(), b"pending");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn read_only_view_refuses_late_journal_and_unlocked_rewrite() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.populate();
        let view = AccountView::open("u").unwrap();
        let journal = crate::replacement::record_path("u");
        std::fs::write(&journal, b"pending").unwrap();
        assert!(matches!(view.finish(), Err(ReadError::PendingRepair)));
        std::fs::remove_file(journal).unwrap();
        let view = AccountView::open("u").unwrap();
        let path = storage::profile_path("u");
        let bytes = std::fs::read(&path).unwrap();
        // Even an identical replacement changes the source object.
        let replacement = path.with_extension("new");
        std::fs::write(&replacement, bytes).unwrap();
        std::fs::rename(replacement, path).unwrap();
        assert!(matches!(view.finish(), Err(ReadError::Changed)));
    }

    #[test]
    fn read_only_pin_refuses_revocation_and_account_reassignment() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.populate();
        let pin = AccountView::open("u").unwrap().finish().unwrap();
        let changed = account::remember("u", 1001);
        assert!(matches!(pin.reopen(), Err(ReadError::Changed)));
        drop(changed);
        pin.reopen().unwrap().finish().unwrap();
        std::fs::remove_file(storage::profile_path("u")).unwrap();
        assert!(matches!(pin.reopen(), Err(ReadError::Changed)));
    }

    #[test]
    fn read_only_view_refuses_a_conflicting_process_account_hold() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.populate();
        let mut enrollment = storage::Enrollment::new("u");
        enrollment.uid = Some(1000);
        std::fs::write(
            storage::profile_path("u"),
            storage::serialize_enrollment(&enrollment, None).unwrap(),
        )
        .unwrap();
        let _held = account::hold("u", 1000).unwrap();
        let _fresh = account::remember("u", 1001);
        assert!(matches!(AccountView::open("u"), Err(ReadError::Changed)));
    }

    #[test]
    fn read_only_secondary_reuses_one_key_and_preserves_all_files() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.populate();
        let path = multi_camera::secondary_store_path("u");
        let store = multi_camera::SecondaryStore {
            format_version: multi_camera::SECONDARY_STORE_VERSION,
            owner: "u".into(),
            generation: 7,
            primary_snapshot_sha256: irlume_common::sha256_hex(
                &std::fs::read(storage::profile_path("u")).unwrap(),
            ),
            groups: Vec::new(),
        };
        multi_camera::save_secondary_with_key(&path, &store, Some(&[42; 32])).unwrap();
        std::fs::write(template_key::key_path("u"), b"untouched key envelope").unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut keys = template_key::RequestTemplateKey::with_unsealer(|user| {
            assert_eq!(user, "u");
            Ok(Some(Zeroizing::new(vec![42; 32])))
        });
        let view = AccountView::open("u").unwrap();
        assert_eq!(
            view.load_secondary(&mut keys).unwrap().unwrap().generation,
            7
        );
        let pin = view.finish().unwrap();
        let view = pin.reopen().unwrap();
        assert_eq!(
            view.load_secondary(&mut keys).unwrap().unwrap().generation,
            7
        );
        view.finish().unwrap();
        assert_eq!(keys.unseals(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            std::fs::read(template_key::key_path("u")).unwrap(),
            b"untouched key envelope"
        );

        let view = pin.reopen().unwrap();
        let journal = multi_camera::commit::intent_path_for(&path);
        let mut racing_key = template_key::RequestTemplateKey::with_unsealer(move |_| {
            std::fs::write(&journal, b"late journal").unwrap();
            Ok(Some(Zeroizing::new(vec![42; 32])))
        });
        assert!(matches!(
            view.load_secondary(&mut racing_key),
            Err(ReadError::PendingRepair)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn read_only_encrypted_primary_key_is_adopted_without_another_unseal() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.populate();
        let primary_path = storage::profile_path("u");
        let mut enrollment = storage::Enrollment::new("u");
        enrollment.uid = Some(1000);
        let primary_bytes = storage::serialize_enrollment(&enrollment, Some(&[42; 32])).unwrap();
        std::fs::write(&primary_path, &primary_bytes).unwrap();
        let secondary_path = multi_camera::secondary_store_path("u");
        let store = multi_camera::SecondaryStore {
            format_version: multi_camera::SECONDARY_STORE_VERSION,
            owner: "u".into(),
            generation: 1,
            primary_snapshot_sha256: irlume_common::sha256_hex(&primary_bytes),
            groups: Vec::new(),
        };
        multi_camera::save_secondary_with_key(&secondary_path, &store, Some(&[42; 32])).unwrap();
        let secondary_bytes = std::fs::read(&secondary_path).unwrap();
        let view = AccountView::open("u").unwrap();
        let calls = std::cell::Cell::new(0);
        let mut primary = view
            .load_primary_with(|user, _| {
                assert_eq!(user, "u");
                calls.set(calls.get() + 1);
                Ok(Zeroizing::new(vec![42; 32]))
            })
            .unwrap()
            .unwrap();
        assert_eq!(calls.get(), 1);
        let mut keys = template_key::RequestTemplateKey::with_unsealer(|_| {
            panic!("request must borrow the primary's key")
        });
        keys.adopt("u", primary.key.take());
        assert_eq!(
            view.load_secondary(&mut keys).unwrap().unwrap().generation,
            1
        );
        let pin = view.finish().unwrap();
        let view = pin.reopen().unwrap();
        assert!(view.load_secondary(&mut keys).unwrap().is_some());
        assert!(matches!(
            view.load_primary_with(|_, _| Err(irlume_common::Error::Policy(
                "synthetic failure".into()
            ))),
            Err(ReadError::Unavailable)
        ));
        view.finish().unwrap();
        assert_eq!(keys.unseals(), 0);
        assert_eq!(std::fs::read(primary_path).unwrap(), primary_bytes);
        assert_eq!(std::fs::read(secondary_path).unwrap(), secondary_bytes);
        keys.clear();
        assert!(!keys.holds_key());
        assert!(
            account::hold("u", 1001).is_ok(),
            "the read transaction must release its account hold"
        );
    }

    #[test]
    fn read_only_pin_detects_secondary_and_key_envelope_changes() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.populate();
        for path in [
            multi_camera::secondary_store_path("u"),
            template_key::key_path("u"),
        ] {
            let pin = AccountView::open("u").unwrap().finish().unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"changed").unwrap();
            assert!(matches!(pin.reopen(), Err(ReadError::Changed)));
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn read_only_view_refuses_nonregular_oversized_and_malformed_sources() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.populate();
        let path = storage::profile_path("u");
        std::fs::write(&path, b"malformed").unwrap();
        let view = AccountView::open("u").unwrap();
        assert!(matches!(view.load_primary(), Err(ReadError::Unavailable)));
        drop(view);
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(multi_camera::MAX_STORE_BYTES as u64 + 1)
            .unwrap();
        assert!(matches!(
            AccountView::open("u"),
            Err(ReadError::Unavailable)
        ));
        drop(file);
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(f.dir.join("missing"), &path).unwrap();
        assert!(matches!(
            AccountView::open("u"),
            Err(ReadError::Unavailable)
        ));
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(matches!(
            AccountView::open("u"),
            Err(ReadError::Unavailable)
        ));
    }
}
