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
    owner_pid: libc::pid_t,
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
                // SAFETY: getpid has no preconditions.
                owner_pid: unsafe { libc::getpid() },
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

impl Drop for Retention {
    fn drop(&mut self) {
        // A duplicate inherited by an unrelated child must not extend this
        // operation's flock. A copied guard in that child must not release
        // the parent's live lock, matching retry accounting's owner guard.
        // SAFETY: getpid has no preconditions, including after fork.
        if unsafe { libc::getpid() } == self.owner_pid {
            // SAFETY: the descriptor remains owned until File drops below.
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_owner_drop_releases_lock_despite_a_duplicate_descriptor() {
        let dir = std::env::temp_dir().join(format!("irlume-retain-dup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let uid = std::fs::metadata(&dir).unwrap().uid();
        let path = dir.join("retention");
        let first = Retention::begin(&path, uid).unwrap();
        let duplicate = first.file.try_clone().unwrap();
        assert!(Retention::begin(&path, uid).is_err());
        drop(first);
        let retry = Retention::begin(&path, uid)
            .expect("a non-owner descriptor must not extend the completed guard's lock");
        assert!(
            retry.prior_uncertain,
            "unlock must not clear retained state"
        );
        assert!(retry.require_fresh().is_err());
        drop(retry);
        drop(duplicate);
        assert_eq!(std::fs::read(&path).unwrap(), DIRTY);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retention_guard_dropped_by_a_fork_child_does_not_unlock_the_parent() {
        use std::os::unix::ffi::OsStrExt as _;
        let dir = std::env::temp_dir().join(format!("irlume-retain-fork-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let uid = std::fs::metadata(&dir).unwrap().uid();
        let path = dir.join("retention");
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let owner = Retention::begin(&path, uid).unwrap();
        // SAFETY: the child performs descriptor teardown and direct Linux
        // descriptor calls, then _exit, without allocation or harness reentry.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            drop(owner);
            // SAFETY: cpath was allocated before fork and is NUL-terminated.
            let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
            // SAFETY: fd is checked before descriptor calls; _exit never
            // returns to Rust or runs inherited harness cleanup.
            unsafe {
                if fd < 0 {
                    libc::_exit(2);
                }
                let locked = libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) == 0;
                // Linux libc returns this thread's live errno location.
                let excluded = !locked && *libc::__errno_location() == libc::EWOULDBLOCK;
                libc::close(fd);
                libc::_exit(i32::from(!excluded));
            }
        }
        let mut status = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            // SAFETY: child is our fork child; status is a live writable integer.
            let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
            if waited == child {
                break;
            }
            assert!(
                waited == 0
                    || (waited == -1
                        && std::io::Error::last_os_error().kind()
                            == std::io::ErrorKind::Interrupted),
                "could not reap retention test child"
            );
            if std::time::Instant::now() >= deadline {
                // SAFETY: child has not been reaped, so its PID still identifies
                // our child. Terminate it before reporting the test failure.
                unsafe {
                    libc::kill(child, libc::SIGKILL);
                    libc::waitpid(child, &mut status, 0);
                }
                panic!("retention test child exceeded its deadline");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child released the parent's lock"
        );
        assert!(Retention::begin(&path, uid).is_err());
        drop(owner);
        assert!(Retention::begin(&path, uid).unwrap().prior_uncertain);
        std::fs::remove_dir_all(dir).unwrap();
    }

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
