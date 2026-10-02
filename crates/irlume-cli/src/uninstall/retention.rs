// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! A single durable SRK-retention bit, outside every uninstall wipe tree.
//! An interrupted/refused attempt may have observed a store no longer named by
//! current configuration. Later attempts cannot infer that those earlier
//! stores are empty and refuse destruction until that uncertainty is reconciled.

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

pub(super) const PATH: &str = "/var/lib/irlume-uninstall-srk-retention";
const DIRTY: &[u8] = b"irlume-uninstall-srk-v1: retain\n";
const CLEAN: &[u8] = b"irlume-uninstall-srk-v1: clean\n";

pub(super) const RECOVERY_GUIDE: &str =
    "https://github.com/archledger/irlume/blob/main/docs/DISABLE.md#manual-uninstall-recovery";

pub(super) fn manual_recovery() -> String {
    format!("Fixing the reported error alone does not clear {PATH}. Later teardown requires manual recovery: preserve earlier unit/envfile configurations and store-path evidence; keep data and the SRK if that evidence cannot be reconstructed. Do not unlink or replace the record. Follow {RECOVERY_GUIDE} for exclusive-flock, same-inode recovery; no automatic reset exists.")
}

pub(super) struct Retention {
    file: std::fs::File,
    pub prior_uncertain: bool,
    state: super::RetentionState,
}

impl Retention {
    pub fn require_fresh(&self) -> Result<(), String> {
        if self.prior_uncertain {
            Err(format!(
                "an earlier uninstall left retained state; this teardown refuses destruction. {}",
                manual_recovery()
            ))
        } else {
            Ok(())
        }
    }

    pub fn begin(path: &Path, owner: u32) -> Result<Self, String> {
        let run = || -> std::io::Result<Self> {
            let parent = super::open_dir(
                path.parent()
                    .ok_or_else(|| std::io::Error::other("no retention parent"))?,
            )?;
            let meta = parent.metadata()?;
            if meta.uid() != owner || meta.mode() & 0o022 != 0 {
                return Err(std::io::Error::other(
                    "retention parent is not owner-controlled",
                ));
            }
            let name = path
                .file_name()
                .ok_or_else(|| std::io::Error::other("no retention name"))?;
            let entry = super::fd_path(&parent)?.join(name);
            let (mut file, fresh) = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&entry)
            {
                Ok(file) => (file, true),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let pin = std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(entry)?;
                    let meta = pin.metadata()?;
                    if !meta.is_file()
                        || meta.uid() != owner
                        || meta.mode() & 0o077 != 0
                        || meta.nlink() != 1
                    {
                        return Err(std::io::Error::other("invalid SRK retention file"));
                    }
                    (
                        std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(super::fd_path(&pin)?)?,
                        false,
                    )
                }
                Err(e) => return Err(e),
            };
            // SAFETY: file owns the live descriptor; nonblocking flock only
            // coordinates uninstallers. Never unlink this lock-bearing inode.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut previous = Vec::new();
            (&mut file).take(128).read_to_end(&mut previous)?;
            if !previous.is_empty() && previous != DIRTY && previous != CLEAN {
                return Err(std::io::Error::other("unrecognized SRK retention state"));
            }
            let prior_uncertain = !fresh && previous != CLEAN;
            let mut result = Self {
                file,
                prior_uncertain,
                state: super::RetentionState::Retained,
            };
            result.write(DIRTY)?;
            parent.sync_all()?;
            Ok(result)
        };
        run().map_err(|e| format!("SRK retention could not be established: {e}"))
    }

    pub fn complete(&mut self) -> Result<(), String> {
        if self.prior_uncertain {
            return Err("an earlier incomplete uninstall keeps the SRK".into());
        }
        self.state = super::RetentionState::Unverified;
        self.write(CLEAN)
            .map_err(|e| format!("cannot complete SRK retention record: {e}"))?;
        self.state = super::RetentionState::Clean;
        Ok(())
    }

    pub fn state(&self) -> super::RetentionState {
        self.state
    }

    fn write(&mut self, value: &[u8]) -> std::io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(value)?;
        self.file.set_len(value.len() as u64)?;
        self.file.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_review_failed_attempt_keeps_srk_across_retry_and_config_change() {
        let dir = std::env::temp_dir().join(format!("irlume-retain-review-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let uid = std::fs::metadata(&dir).unwrap().uid();
        let path = dir.join("retention");
        let first = Retention::begin(&path, uid).unwrap();
        assert!(!first.prior_uncertain);
        assert!(
            Retention::begin(&path, uid).is_err(),
            "serialize concurrent uninstallers"
        );
        drop(first); // interrupted, or generation changed/unlink failed
        let mut retry = Retention::begin(&path, uid).unwrap();
        assert!(retry.prior_uncertain);
        assert!(retry.require_fresh().is_err());
        assert!(!super::super::may_evict_srk(
            true,
            retry.prior_uncertain,
            Ok(Vec::new())
        ));
        assert!(retry.complete().is_err());
        drop(retry);
        assert_eq!(std::fs::read(&path).unwrap(), DIRTY);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn environment_review_clean_completion_and_invalid_retention_files() {
        let dir = std::env::temp_dir().join(format!("irlume-retain-clean-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let uid = std::fs::metadata(&dir).unwrap().uid();
        let path = dir.join("retention");
        Retention::begin(&path, uid).unwrap().complete().unwrap();
        assert!(!Retention::begin(&path, uid).unwrap().prior_uncertain);
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.join("missing"), &path).unwrap();
        assert!(Retention::begin(&path, uid).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
