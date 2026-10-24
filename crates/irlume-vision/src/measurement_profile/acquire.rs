// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Constrained fixture acquisition, not native-loading admission.
//!
//! Linux x86-64 only. Callers supply a controlled, responsive local directory
//! without concurrent writers. A directory descriptor constrains resolution;
//! it does not freeze content or make metadata checks atomic. Root ownership
//! proves neither historical permissions nor absence of retained writers.

use super::observe::{
    observe_fixture_files, trusted_metadata, valid_limits, valid_path, FileStamp, FixtureFile,
    FixtureScope, ObservationError, ObservationLimits, ObservedFixtureFiles,
};
use super::{MAX_FILES, MAX_TEXT_BYTES};
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, PathBuf};

// Linux v7.2 introduced this openat2-only UAPI flag in the upper 32 bits.
// libc 0.2.190 has open_how but does not export this flag. Do not narrow it
// through open()/openat() or OpenOptionsExt::custom_flags(i32).
// https://github.com/torvalds/linux/blob/v7.2/include/uapi/linux/openat2.h
const OPENAT2_REGULAR: u64 = 1u64 << 32;
const OPEN_HOW_V0_SIZE: usize = 24;
const HARD_OPEN_ATTEMPTS: u32 = 8192;

const _: () = assert!(std::mem::size_of::<libc::open_how>() == OPEN_HOW_V0_SIZE);

/// Independent limits for acquiring descriptors and observing their bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcquisitionLimits {
    /// Existing per-file, retained-byte and positional-read limits.
    pub observations: ObservationLimits,
    /// Batch-wide open attempts, including EINTR/EAGAIN; maximum 8,192.
    pub open_attempts: u32,
}

impl Default for AcquisitionLimits {
    fn default() -> Self {
        Self {
            observations: ObservationLimits::default(),
            open_attempts: 1024,
        }
    }
}

/// Value-redacted refusal kinds; no path, native output or content is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquisitionError {
    /// Zero or excessive open attempts, or invalid observation limits.
    InvalidLimits,
    /// At least one input path is required.
    EmptyBatch,
    /// More than 256 paths were supplied.
    TooManyPaths,
    /// The scope is not a bounded absolute UTF-8 path.
    InvalidScope,
    /// Invalid relative spelling or oversized complete path.
    InvalidPath { file: usize },
    /// The exact relative spelling occurs more than once.
    DuplicatePath { file: usize },
    /// The initial root is not a trusted directory matching its original path.
    RootRefused,
    /// The root descriptor or its original pathname no longer matches.
    RootChanged,
    /// The required syscall/flags/ABI are unavailable; no fallback was attempted.
    Unsupported,
    /// A constrained open failed for a non-retryable reason.
    OpenRefused { file: usize },
    /// A returned descriptor is not a regular file under the fixture policy.
    LeafRefused { file: usize },
    /// A leaf's full descriptor stamp changed after acquisition.
    LeafChanged { file: usize },
    /// The batch-wide open-attempt budget was exhausted.
    AttemptsExhausted { file: usize },
    /// A bounded output-vector reservation failed.
    AllocationFailed,
    /// Existing descriptor observation refused the acquired files.
    Observation(ObservationError),
}

impl fmt::Display for AcquisitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixture acquisition refused: {self:?}")
    }
}

impl std::error::Error for AcquisitionError {}

/// Acquire a bounded batch of regular fixture files and observe their bytes.
///
/// Every leaf is opened relative to the supplied directory with the full
/// Linux 7.2 regular-file-only and constrained-resolution flags. Unsupported
/// kernels refuse; there is no weaker open or retry policy. Root descriptor
/// and original pathname stamps are compared before each attempt and after
/// observation. This detects observed changes, not all transient mutations.
/// The scope must name a controlled, responsive local fixture directory with
/// no concurrent writers. Its UID is fixture policy, not root authorization.
///
/// The directory is consumed and closed on every return. A successful result
/// owns the leaf descriptors and immutable hashed allocations; it exposes no
/// descriptor or launch capability. No provider, environment or installed
/// runtime is loaded or discovered. Call budgets do not bound blocking I/O.
///
/// # Errors
/// Returns fixed indexed errors for invalid input, unsupported capability,
/// root/leaf policy failures, observed changes, exhausted open attempts or
/// failed allocation/observation. Partial leaf ownership is dropped on error.
pub fn acquire_and_observe(
    scope: &FixtureScope,
    directory: File,
    relative_paths: &[PathBuf],
    limits: AcquisitionLimits,
) -> Result<ObservedFixtureFiles, AcquisitionError> {
    acquire_with(scope, directory, relative_paths, limits, &mut SystemIo)
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Checkpoint {
    BeforeOpen,
    AfterOpen,
    BeforeObserve,
    AfterObserve,
}

// Private syscall/mutation seams, never an externally supplied capability.
trait AcquisitionIo {
    fn openat2(
        &mut self,
        directory: &File,
        path: &CStr,
        how: &libc::open_how,
        size: usize,
    ) -> io::Result<File>;

    #[cfg(test)]
    fn checkpoint(&mut self, _directory: &File, _file: usize, _point: Checkpoint) {}
}

struct SystemIo;

impl AcquisitionIo for SystemIo {
    fn openat2(
        &mut self,
        directory: &File,
        path: &CStr,
        how: &libc::open_how,
        size: usize,
    ) -> io::Result<File> {
        // SAFETY: the borrowed directory remains open; path is NUL-terminated;
        // how points to a live, zero-initialized v0 structure of verified size.
        // The kernel returns a new owned descriptor or -1 with errno.
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                directory.as_raw_fd(),
                path.as_ptr(),
                how as *const libc::open_how,
                size,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = RawFd::try_from(result).map_err(|_| io::ErrorKind::InvalidData)?;
        // SAFETY: successful openat2 returns an unshared newly owned descriptor,
        // representable as RawFd. Exactly this File assumes its ownership.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn make_how() -> libc::open_how {
    // SAFETY: open_how is the repr(C) UAPI structure of three u64 fields.
    // Zero initializes all fields, including reserved fields in its v0 ABI.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64 | OPENAT2_REGULAR;
    how.resolve = libc::RESOLVE_BENEATH
        | libc::RESOLVE_NO_SYMLINKS
        | libc::RESOLVE_NO_MAGICLINKS
        | libc::RESOLVE_NO_XDEV;
    how
}

fn root_stamp(scope: &FixtureScope, directory: &File) -> Result<FileStamp, AcquisitionError> {
    let descriptor = directory
        .metadata()
        .map_err(|_| AcquisitionError::RootRefused)?;
    // lstat on a trailing slash/dot can follow a root symlink. Inspect the
    // component spelling too, preserving '..' semantics, then stat the original.
    let named = fs::symlink_metadata(scope.root.components().collect::<PathBuf>())
        .map_err(|_| AcquisitionError::RootRefused)?;
    if !descriptor.is_dir()
        || !named.is_dir()
        || !trusted_metadata(&descriptor, scope.expected_uid)
        || !trusted_metadata(&named, scope.expected_uid)
    {
        return Err(AcquisitionError::RootRefused);
    }
    let original = fs::metadata(&scope.root).map_err(|_| AcquisitionError::RootRefused)?;
    let initial = FileStamp::from(&descriptor);
    if FileStamp::from(&named) != initial || FileStamp::from(&original) != initial {
        return Err(AcquisitionError::RootRefused);
    }
    Ok(initial)
}

fn check_root(
    scope: &FixtureScope,
    directory: &File,
    initial: FileStamp,
) -> Result<(), AcquisitionError> {
    if root_stamp(scope, directory).map_err(|_| AcquisitionError::RootChanged)? != initial {
        return Err(AcquisitionError::RootChanged);
    }
    Ok(())
}

fn acquire_with(
    scope: &FixtureScope,
    directory: File,
    relative_paths: &[PathBuf],
    limits: AcquisitionLimits,
    io: &mut impl AcquisitionIo,
) -> Result<ObservedFixtureFiles, AcquisitionError> {
    if limits.open_attempts == 0
        || limits.open_attempts > HARD_OPEN_ATTEMPTS
        || !valid_limits(limits.observations)
    {
        return Err(AcquisitionError::InvalidLimits);
    }
    if relative_paths.is_empty() {
        return Err(AcquisitionError::EmptyBatch);
    }
    if relative_paths.len() > MAX_FILES {
        return Err(AcquisitionError::TooManyPaths);
    }
    if !valid_path(&scope.root) {
        return Err(AcquisitionError::InvalidScope);
    }
    let mut joined = Vec::new();
    joined
        .try_reserve_exact(relative_paths.len())
        .map_err(|_| AcquisitionError::AllocationFailed)?;
    for (file, path) in relative_paths.iter().enumerate() {
        if path.is_absolute()
            || !path.to_str().is_some_and(|text| {
                !text.is_empty() && text.len() <= MAX_TEXT_BYTES && !text.contains('\0')
            })
            || path.components().any(|part| part == Component::ParentDir)
        {
            return Err(AcquisitionError::InvalidPath { file });
        }
        if relative_paths[..file]
            .iter()
            .any(|other| other.as_os_str() == path.as_os_str())
        {
            return Err(AcquisitionError::DuplicatePath { file });
        }
        let absolute = scope.root.join(path);
        if !valid_path(&absolute) {
            return Err(AcquisitionError::InvalidPath { file });
        }
        joined.push(absolute);
    }
    let initial = root_stamp(scope, &directory)?;
    let mut files = Vec::new();
    files
        .try_reserve_exact(relative_paths.len())
        .map_err(|_| AcquisitionError::AllocationFailed)?;
    let mut stamps = Vec::new();
    stamps
        .try_reserve_exact(relative_paths.len())
        .map_err(|_| AcquisitionError::AllocationFailed)?;
    let mut remaining = limits.open_attempts;
    let how = make_how();
    for (index, (relative, absolute)) in relative_paths.iter().zip(joined).enumerate() {
        let path = CString::new(relative.as_os_str().as_bytes())
            .map_err(|_| AcquisitionError::InvalidPath { file: index })?;
        let file = loop {
            #[cfg(test)]
            io.checkpoint(&directory, index, Checkpoint::BeforeOpen);
            check_root(scope, &directory, initial)?;
            remaining = remaining
                .checked_sub(1)
                .ok_or(AcquisitionError::AttemptsExhausted { file: index })?;
            match io.openat2(&directory, &path, &how, OPEN_HOW_V0_SIZE) {
                Ok(file) => break file,
                Err(error) => match error.raw_os_error() {
                    Some(libc::EINTR | libc::EAGAIN) => continue,
                    Some(libc::ENOSYS | libc::EINVAL | libc::E2BIG) => {
                        return Err(AcquisitionError::Unsupported)
                    }
                    _ => return Err(AcquisitionError::OpenRefused { file: index }),
                },
            }
        };
        let metadata = file
            .metadata()
            .map_err(|_| AcquisitionError::LeafRefused { file: index })?;
        if !metadata.is_file() || !trusted_metadata(&metadata, scope.expected_uid) {
            return Err(AcquisitionError::LeafRefused { file: index });
        }
        let stamp = FileStamp::from(&metadata);
        #[cfg(test)]
        io.checkpoint(&directory, index, Checkpoint::AfterOpen);
        check_root(scope, &directory, initial)?;
        check_leaf(&file, stamp, index)?;
        files.push(FixtureFile {
            declared_path: absolute,
            file,
        });
        stamps.push(stamp);
    }
    #[cfg(test)]
    io.checkpoint(&directory, 0, Checkpoint::BeforeObserve);
    check_root(scope, &directory, initial)?;
    for (index, (file, stamp)) in files.iter().zip(&stamps).enumerate() {
        check_leaf(&file.file, *stamp, index)?;
    }
    let result = observe_fixture_files(scope, files, limits.observations)
        .map_err(AcquisitionError::Observation)?;
    #[cfg(test)]
    io.checkpoint(&directory, 0, Checkpoint::AfterObserve);
    check_root(scope, &directory, initial)?;
    for (index, (file, stamp)) in result.files().iter().zip(&stamps).enumerate() {
        if file.current_stamp().ok() != Some(*stamp) {
            return Err(AcquisitionError::LeafChanged { file: index });
        }
    }
    Ok(result)
}

fn check_leaf(file: &File, initial: FileStamp, index: usize) -> Result<(), AcquisitionError> {
    if file
        .metadata()
        .map(|metadata| FileStamp::from(&metadata))
        .ok()
        != Some(initial)
    {
        return Err(AcquisitionError::LeafChanged { file: index });
    }
    Ok(())
}

#[cfg(test)]
#[path = "acquire_tests.rs"]
mod tests;
