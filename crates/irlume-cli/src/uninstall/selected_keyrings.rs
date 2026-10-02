// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Destructive handling of explicitly selected stores. Never recursively remove
//! an administrator-selected directory: it may contain unrelated data.

use super::{fd_path, open_dir, terminal_safe, HeldStore};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

pub(super) fn hold(paths: &[PathBuf], owner: u32) -> Result<Vec<HeldStore>, String> {
    let mut stores = Vec::new();
    for path in paths {
        let fail = |e| terminal_safe(&format!("{}: {e}", path.display()));
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(fail(e.to_string())),
        };
        if !meta.is_dir() || meta.uid() != owner || meta.mode() & 0o022 != 0 {
            return Err(fail(
                "selected keyring must be a real, owner-controlled directory".into(),
            ));
        }
        let dir = open_dir(path).map_err(|e| fail(e.to_string()))?;
        let held = dir.metadata().map_err(|e| fail(e.to_string()))?;
        if (held.dev(), held.ino(), held.uid(), held.mode())
            != (meta.dev(), meta.ino(), meta.uid(), meta.mode())
        {
            return Err(fail("selected keyring changed while opening".into()));
        }
        stores.push(HeldStore {
            shown: path.clone(),
            dir,
        });
    }
    Ok(stores)
}

/// Disarm every envelope, including accounts without enrollment. Failure keeps
/// the entry and is reported to the wipe/SRK gates. Even with --keep-data the
/// historical uninstall contract disarms seals; it keeps enrollment data.
pub(super) fn disarm(stores: &[HeldStore], owner: u32) -> (usize, Vec<String>) {
    disarm_with(stores, owner, |path| std::fs::remove_file(path))
}

fn disarm_with(
    stores: &[HeldStore],
    owner: u32,
    mut unlink: impl FnMut(&Path) -> std::io::Result<()>,
) -> (usize, Vec<String>) {
    let mut removed = 0;
    let mut left = Vec::new();
    for store in stores {
        let result = disarm_store(store, owner, &mut removed, &mut unlink);
        if let Err(e) = result {
            left.push(terminal_safe(&format!(
                "{} (selected keyring: {e})",
                store.shown.display()
            )));
        }
    }
    (removed, left)
}

fn disarm_store(
    store: &HeldStore,
    owner: u32,
    removed: &mut usize,
    unlink: &mut impl FnMut(&Path) -> std::io::Result<()>,
) -> Result<(), String> {
    let fail = |e: std::io::Error| e.to_string();
    let held = store.dir.metadata().map_err(fail)?;
    let now = std::fs::symlink_metadata(&store.shown).map_err(fail)?;
    if !now.is_dir()
        || held.uid() != owner
        || now.uid() != owner
        || (held.dev(), held.ino(), held.mode()) != (now.dev(), now.ino(), now.mode())
        || held.mode() & 0o022 != 0
    {
        return Err("directory identity, owner or permissions changed".into());
    }
    let path = fd_path(&store.dir).map_err(fail)?;
    let entries = std::fs::read_dir(&path).map_err(fail)?;
    for entry in entries {
        let entry = entry.map_err(fail)?;
        let file = entry.path();
        let meta = std::fs::symlink_metadata(&file).map_err(fail)?;
        if !meta.is_file()
            || meta.uid() != owner
            || meta.nlink() != 1
            || meta.mode() & 0o022 != 0
            || file.extension().is_none_or(|e| e != "json")
        {
            return Err("unrecognized, linked or foreign-owned entry left in place".into());
        }
        let envelope = irlume_core::envelope::SealedEnvelope::load(&file)
            .map_err(|_| "unreadable envelope left in place".to_string())?;
        if envelope.secret == irlume_core::envelope::SecretKind::GnomeKeyringToken {
            return Err(
                "GNOME token appeared since preflight; disarm it in its session first".into(),
            );
        }
        let now = std::fs::symlink_metadata(&file).map_err(fail)?;
        if !now.is_file()
            || (
                meta.dev(),
                meta.ino(),
                meta.uid(),
                meta.nlink(),
                meta.mode(),
            ) != (now.dev(), now.ino(), now.uid(), now.nlink(), now.mode())
        {
            return Err("envelope identity changed".into());
        }
        unlink(&file).map_err(fail)?;
        *removed += 1;
    }
    Ok(())
}

/// Recheck both the pinned store and the configured name, not a new unit read
/// after uninstall has deleted the unit. Any uncertainty keeps the SRK.
pub(super) fn empty(stores: &[HeldStore], paths: &[PathBuf]) -> Result<(), String> {
    for store in stores {
        let path = fd_path(&store.dir).map_err(|e| e.to_string())?;
        if std::fs::read_dir(path)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        {
            return Err(terminal_safe(&format!(
                "{} still holds data",
                store.shown.display()
            )));
        }
    }
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Ok(meta) if meta.is_dir() => {}
            _ => return Err("selected keyring path cannot be rechecked".into()),
        }
        if std::fs::read_dir(path)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        {
            return Err(terminal_safe(&format!(
                "{} still holds data",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    const PASSWORD: &str = r#"{"version":1,"pcrs":[],"public":"","private":""}"#;
    const KDE: &str = r#"{"version":1,"pcrs":[],"public":"","private":"","secret":"KdeWalletKey"}"#;

    fn fixture(name: &str) -> (PathBuf, u32) {
        let dir =
            std::env::temp_dir().join(format!("irlume-selected-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let uid = std::fs::metadata(&dir).unwrap().uid();
        (dir, uid)
    }

    #[test]
    fn environment_review_two_attempts_keep_unit_after_custom_unlink_failure() {
        use super::super::{
            finish_teardown, removal_refusal, retention::Retention, unit_env_under, SrkOutcome,
            TeardownReport,
        };
        let (root, uid) = fixture("two-attempts");
        let store = root.join("custom");
        std::fs::create_dir(&store).unwrap();
        std::fs::write(store.join("alice.json"), PASSWORD).unwrap();
        let unit = root.join("etc/systemd/system/irlumed.service");
        let vendor = root.join("usr/lib/systemd/system/irlumed.service");
        for path in [&unit, &vendor] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        }
        std::fs::write(
            &unit,
            format!(
                "[Service]\nEnvironment=IRLUME_KEYRING_DIR={}\n",
                store.display()
            ),
        )
        .unwrap();
        std::fs::write(
            &vendor,
            "[Service]\nEnvironment=IRLUME_KEYRING_DIR=/vendor\n",
        )
        .unwrap();
        let retained = Retention::begin(&root.join("retain"), uid).unwrap();
        let paths = vec![unit_env_under(&root, "IRLUME_KEYRING_DIR")
            .unwrap()
            .unwrap()];
        let held = hold(&paths, uid).unwrap();
        let mut calls = 0;
        let (removed, left) = disarm_with(&held, uid, |path| {
            assert_eq!(path.file_name().unwrap(), "alice.json");
            calls += 1;
            Err(std::io::Error::from_raw_os_error(libc::EROFS))
        });
        assert_eq!(
            calls, 1,
            "the real scanner reached the failing unlink boundary"
        );
        assert_eq!(removed, 0);
        let failed = TeardownReport {
            pam_unwired: true,
            service_stopped: true,
            users_cleared: removed,
            data_wipe_requested: true,
            data_wiped: false,
            data_left: left,
            srk_eviction: SrkOutcome::Kept,
            retention: super::super::RetentionState::Retained,
        };
        assert_eq!(
            finish_teardown(&failed, || {
                std::fs::remove_file(&unit).unwrap();
                true
            }),
            None
        );
        assert!(
            removal_refusal(&failed).is_some(),
            "CLI must not remove the application either"
        );
        assert!(unit.exists());
        assert!(store.join("alice.json").exists());
        drop(retained);

        let retry = Retention::begin(&root.join("retain"), uid).unwrap();
        assert_eq!(
            unit_env_under(&root, "IRLUME_KEYRING_DIR").unwrap(),
            Some(store.clone())
        );
        let refused = super::super::refused_teardown(false, retry.require_fresh().unwrap_err());
        assert_eq!(
            finish_teardown(&refused, || {
                std::fs::remove_file(&unit).unwrap();
                true
            }),
            None
        );
        assert!(removal_refusal(&refused).is_some());
        assert!(unit.exists());
        assert!(store.join("alice.json").exists());
        // Even an external removal/deployment exposing the vendor unit cannot
        // erase the durable refusal on a later attempt.
        std::fs::remove_file(&unit).unwrap();
        assert_eq!(
            unit_env_under(&root, "IRLUME_KEYRING_DIR").unwrap(),
            Some("/vendor".into())
        );
        assert!(
            !super::super::may_evict_srk(true, retry.prior_uncertain, Ok(Vec::new())),
            "vendor fallback cannot erase prior uncertainty"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn environment_selected_store_survives_unit_removal_and_disarms_unenrolled_accounts() {
        let (root, uid) = fixture("disarm");
        let store = root.join("custom");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("alice.json"), PASSWORD).unwrap();
        std::fs::write(store.join("bob.json"), KDE).unwrap();
        let unit = root.join("etc/systemd/system/irlumed.service");
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        std::fs::write(
            &unit,
            format!(
                "[Service]\nEnvironment=IRLUME_KEYRING_DIR={}\n",
                store.display()
            ),
        )
        .unwrap();
        let dirs = vec![super::super::unit_env_under(&root, "IRLUME_KEYRING_DIR")
            .unwrap()
            .unwrap()];
        let held = hold(&dirs, uid).unwrap();
        std::fs::remove_file(unit).unwrap();
        assert!(!super::super::may_evict_srk(
            true,
            false,
            empty(&held, &dirs).map(|()| Vec::new())
        ));
        let (count, left) = disarm(&held, uid);
        assert_eq!(count, 2);
        assert!(left.is_empty(), "{left:?}");
        assert!(!store.join("alice.json").exists());
        assert!(!store.join("bob.json").exists());
        assert!(empty(&held, &dirs).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn environment_selected_store_leftovers_keep_the_pcr_parent_key() {
        let (dir, uid) = fixture("leftovers");
        let dirs = vec![dir.clone()];
        let held = hold(&dirs, uid).unwrap();
        for data in [
            "not an envelope",
            r#"{"version":1,"pcrs":[7],"public":"","private":"","secret":"GnomeKeyringToken"}"#,
        ] {
            std::fs::write(dir.join("alice.json"), data).unwrap();
            let (count, left) = disarm(&held, uid);
            assert_eq!(count, 0);
            assert!(left.iter().any(|s| s.contains(dir.to_str().unwrap())));
            if data.contains("GnomeKeyringToken") {
                assert!(left[0].contains("GNOME token appeared"));
            }
            assert_eq!(
                std::fs::read_to_string(dir.join("alice.json")).unwrap(),
                data
            );
            assert!(!super::super::may_evict_srk(
                left.is_empty(),
                false,
                empty(&held, &dirs).map(|()| Vec::new())
            ));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn environment_selected_store_refuses_foreign_owners_links_and_replacements() {
        let (root, uid) = fixture("identity");
        let dir = root.join("keys");
        std::fs::create_dir(&dir).unwrap();
        let dirs = vec![dir.clone()];
        assert!(hold(&dirs, uid.wrapping_add(1)).is_err());
        let held = hold(&dirs, uid).unwrap();
        let outside = root.join("outside.json");
        std::fs::write(&outside, PASSWORD).unwrap();
        symlink(&outside, dir.join("alice.json")).unwrap();
        assert!(!disarm(&held, uid).1.is_empty());
        assert!(outside.exists());
        assert!(std::fs::symlink_metadata(dir.join("alice.json"))
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::rename(&dir, root.join("moved")).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("bob.json"), PASSWORD).unwrap();
        assert!(!disarm(&held, uid).1.is_empty());
        assert!(dir.join("bob.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
