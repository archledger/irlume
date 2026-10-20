// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Secure, no-replace publication for user-visible diagnostic artifacts.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A diagnostic artifact that is visible only under a clearly named partial
/// path until [`SecureArtifact::commit`] publishes it atomically.
pub struct SecureArtifact {
    file: File,
    owner_uid: libc::uid_t,
    final_path: PathBuf,
    partial_path: PathBuf,
    bytes: u64,
    limit: u64,
}

/// The final state of a successfully published artifact.
#[derive(Debug, Eq, PartialEq)]
pub struct PublishedArtifact {
    pub final_path: PathBuf,
    pub bytes: u64,
    pub durability_warning: Option<String>,
}

impl SecureArtifact {
    /// Create a fresh, creator-owned mode-0600 partial beside `final_path`.
    ///
    /// The final path is intentionally checked only by [`Self::commit`], where
    /// the kernel can enforce no-replace publication atomically.
    /// # Errors
    ///
    /// Refuses known unqualified network filesystems, ownership or permissions
    /// that do not meet the private-artifact contract, and filesystem errors.
    pub fn create(final_path: &Path, limit: u64) -> io::Result<Self> {
        // SAFETY: geteuid takes no arguments and returns this thread's current
        // effective uid without changing process state.
        let owner_uid = unsafe { libc::geteuid() };
        let parent = artifact_parent(final_path);
        let name = final_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing artifact name"))?;

        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let (file, partial_path) = loop {
            let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let partial_name = format!(
                ".{}.partial.{}.{}",
                name.to_string_lossy(),
                std::process::id(),
                sequence
            );
            let partial_path = parent.join(partial_name);
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&partial_path)
            {
                Ok(file) => break (file, partial_path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        };

        // Umask can only narrow the creation mode. Reassert owner read/write on
        // the already-open inode, never through the attacker-visible pathname.
        // SAFETY: `file` owns a live descriptor and fchmod reads no pointers.
        let chmod_result = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
        if chmod_result != 0 {
            return Err(io::Error::last_os_error());
        }

        reject_unqualified_network_filesystem(&file)?;
        verify_private_permissions(&file, owner_uid)?;
        Ok(Self {
            file,
            owner_uid,
            final_path: final_path.to_owned(),
            partial_path,
            bytes: 0,
            limit,
        })
    }

    /// Append one chunk only while the opened artifact remains private.
    ///
    /// # Errors
    ///
    /// Refuses changed ownership or permissions, a chunk that would cross the
    /// byte limit, and filesystem write errors.
    pub fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        verify_private_permissions(&self.file, self.owner_uid)?;
        let chunk_len = u64::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::FileTooLarge, "artifact size overflow"))?;
        let next_len = self
            .bytes
            .checked_add(chunk_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::FileTooLarge, "artifact size overflow"))?;
        if next_len > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "artifact byte limit exceeded",
            ));
        }
        self.file.write_all(bytes)?;
        self.bytes = next_len;
        Ok(())
    }

    /// The recoverable partial path used until commit succeeds.
    #[must_use]
    pub fn partial_path(&self) -> &Path {
        &self.partial_path
    }

    /// Sync and publish the artifact without replacing an existing path.
    ///
    /// # Errors
    ///
    /// Refuses changed ownership or permissions, failed file synchronization,
    /// and no-replace publication errors. Parent-sync failures remain warnings.
    pub fn commit(self) -> io::Result<PublishedArtifact> {
        let Self {
            file,
            owner_uid,
            final_path,
            partial_path,
            bytes,
            limit: _,
        } = self;
        verify_private_permissions(&file, owner_uid)?;
        file.sync_all()?;
        verify_private_permissions(&file, owner_uid)?;
        drop(file);

        if let Err(error) = rename_noreplace(&partial_path, &final_path) {
            // A failed renameat2 did not publish the source. Do not leave a
            // failed collision's partial behind as though it were recoverable.
            let _ = std::fs::remove_file(&partial_path);
            return Err(error);
        }

        let parent = artifact_parent(&final_path);
        let durability_warning = crate::fsync_dir(parent)
            .err()
            .map(|error| format!("artifact is visible but parent sync failed: {error}"));

        Ok(PublishedArtifact {
            final_path,
            bytes,
            durability_warning,
        })
    }
}

fn artifact_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn rename_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "partial path contains NUL"))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "final path contains NUL"))?;
    // SAFETY: both C strings are NUL-terminated and live for the syscall; the
    // remaining arguments are Linux constants with no borrowed memory.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn verify_private_permissions(file: &File, owner_uid: libc::uid_t) -> io::Result<()> {
    // Query the opened inode, not a pathname that could name another file.
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "diagnostic artifact must remain a regular mode-0600 file owned by its creator",
        ));
    }
    Ok(())
}

fn reject_unqualified_network_filesystem(file: &File) -> io::Result<()> {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: `file` owns a live descriptor and `stats` points to enough writable
    // storage for one `statfs`. A zero return is checked before initialization.
    let result = unsafe { libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs returned zero, so it initialized the complete structure.
    let filesystem_type = unsafe { stats.assume_init() }.f_type as u64;
    if is_known_network_filesystem(filesystem_type) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private diagnostic artifacts are not supported on unqualified network filesystems; choose a private local directory",
        ));
    }
    Ok(())
}

fn is_known_network_filesystem(filesystem_type: u64) -> bool {
    // Linux UAPI filesystem magic values are 32-bit constants. Normalize a
    // sign-extended f_type as well as its native 64-bit representation.
    let filesystem_type = filesystem_type & u64::from(u32::MAX);
    // A successful chmod is not evidence of private access on these sinks:
    // CIFS nounix/noperm can ignore it or bypass client permission checks.
    const NETWORK_FILESYSTEMS: &[u64] = &[
        0x0000_6969, // NFS
        0x0000_517b, // legacy SMB
        0xff53_4d42, // CIFS
        0xfe53_4d42, // SMB2
        0x0000_564c, // NCP
        0x7375_7245, // Coda
        0x5346_414f, // legacy AFS
        0x6b41_4653, // Linux AFS
        0x00c3_6400, // Ceph
        0x0102_1997, // 9P
    ];
    NETWORK_FILESYSTEMS.contains(&filesystem_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn sandbox(label: &str) -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("irlume-{label}-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn commit_publishes_one_0600_file_without_replacing() {
        let dir = sandbox("artifact-publish");
        let target = dir.join("report.txt");
        let mut first = SecureArtifact::create(&target, 32).unwrap();
        first.write_chunk(b"first").unwrap();
        first.commit().unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut second = SecureArtifact::create(&target, 32).unwrap();
        second.write_chunk(b"second").unwrap();
        assert_eq!(
            second.commit().unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
    }

    #[test]
    fn an_uncommitted_writer_leaves_only_a_named_partial() {
        let dir = sandbox("artifact-partial");
        let target = dir.join("trace.jsonl");
        let partial = {
            let mut artifact = SecureArtifact::create(&target, 32).unwrap();
            artifact.write_chunk(b"recoverable").unwrap();
            artifact.partial_path().to_owned()
        };
        assert!(!target.exists());
        assert_eq!(std::fs::read(partial).unwrap(), b"recoverable");
    }

    #[test]
    fn byte_limit_is_enforced_before_the_extra_chunk_is_written() {
        let dir = sandbox("artifact-limit");
        let target = dir.join("report.txt");
        let mut artifact = SecureArtifact::create(&target, 5).unwrap();
        artifact.write_chunk(b"12345").unwrap();
        assert_eq!(
            artifact.write_chunk(b"6").unwrap_err().kind(),
            io::ErrorKind::FileTooLarge
        );
        assert_eq!(std::fs::read(artifact.partial_path()).unwrap(), b"12345");
    }

    #[test]
    fn a_symlink_at_the_destination_is_not_followed_or_replaced() {
        let dir = sandbox("artifact-symlink");
        let victim = dir.join("victim.txt");
        let target = dir.join("report.txt");
        std::fs::write(&victim, b"victim").unwrap();
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        let mut artifact = SecureArtifact::create(&target, 32).unwrap();
        artifact.write_chunk(b"report").unwrap();
        assert_eq!(
            artifact.commit().unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(victim).unwrap(), b"victim");
        assert!(std::fs::symlink_metadata(target)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn a_shared_partial_is_refused_before_any_extra_bytes_are_written() {
        let dir = sandbox("artifact-shared-write");
        let target = dir.join("trace.jsonl");
        let mut artifact = SecureArtifact::create(&target, 32).unwrap();
        let partial = artifact.partial_path().to_owned();
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o660)).unwrap();

        let error = artifact
            .write_chunk(b"must-not-be-written")
            .expect_err("a successful chmod must not substitute for private permissions");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(std::fs::read(&partial).unwrap().is_empty());
        assert!(!target.exists());
    }

    #[test]
    fn a_shared_partial_is_never_published() {
        let dir = sandbox("artifact-shared-commit");
        let target = dir.join("trace.jsonl");
        let mut artifact = SecureArtifact::create(&target, 32).unwrap();
        artifact.write_chunk(b"recoverable").unwrap();
        let partial = artifact.partial_path().to_owned();
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o660)).unwrap();

        let error = artifact
            .commit()
            .expect_err("publication requires the partial to remain private");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!target.exists());
        assert_eq!(std::fs::read(&partial).unwrap(), b"recoverable");
    }

    #[test]
    fn an_owner_mismatch_refuses_writing_and_publication() {
        let dir = sandbox("artifact-owner-mismatch");
        let target = dir.join("trace.jsonl");
        let mut artifact = SecureArtifact::create(&target, 32).unwrap();
        let partial = artifact.partial_path().to_owned();
        // Simulate a mismatch with the captured creator identity without
        // changing real process credentials or requiring chown privileges.
        artifact.owner_uid ^= 1;
        assert_eq!(
            artifact
                .write_chunk(b"must-not-be-written")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            artifact.commit().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!target.exists());
        assert!(std::fs::read(partial).unwrap().is_empty());
    }

    #[test]
    fn known_network_magic_values_are_refused_including_sign_extension() {
        for magic in [
            0x6969,
            0xff53_4d42,
            0xfe53_4d42,
            0x564c,
            0x7375_7245,
            0x5346_414f,
            0x00c3_6400,
            0x0102_1997,
            0xffff_ffff_ff53_4d42,
            0xffff_ffff_fe53_4d42,
        ] {
            assert!(is_known_network_filesystem(magic), "{magic:x}");
        }
        for magic in [0xef53, 0x9123_683e, 0x0102_1994, 0x794c_7630] {
            assert!(!is_known_network_filesystem(magic), "{magic:x}");
        }
    }

    #[test]
    fn linux_afs_is_refused_as_an_unqualified_network_filesystem() {
        assert!(is_known_network_filesystem(0x6b41_4653));
    }

    #[test]
    fn legacy_smb_is_refused_as_an_unqualified_network_filesystem() {
        assert!(is_known_network_filesystem(0x517b));
    }
}
