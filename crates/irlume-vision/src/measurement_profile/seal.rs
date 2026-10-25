// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Fresh sealed copies of already-observed fixture bytes, not launch authority.
//!
//! No source pathname is reopened. Successful copies have no execute mode bits
//! and cannot acquire them, but this does not prohibit executable mappings or
//! interpreter-mediated use. No descriptor, mutable bytes or native capability
//! is exposed. Mount publication and complete-generation retention are separate.

use super::observe::{ObservedFixtureFiles, HARD_FILE_BYTES, HARD_TOTAL_BYTES};
use super::{FileObservation, MAX_FILES};
use std::fmt;
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};

const IO_BYTES: usize = 64 * 1024;
const IO_CALLS: u32 = 65_536;
const CREATE_FLAGS: u32 = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | libc::MFD_NOEXEC_SEAL;
const REQUIRED_SEALS: i32 = libc::F_SEAL_WRITE
    | libc::F_SEAL_GROW
    | libc::F_SEAL_SHRINK
    | libc::F_SEAL_EXEC
    | libc::F_SEAL_SEAL;

/// Fixed, indexed refusal reasons, without source paths, bytes or OS messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The batch is empty or exceeds the existing file-count ceiling.
    InvalidCount,
    /// Empty or oversized file, aggregate size or arithmetic overflow.
    InvalidSize { file: usize },
    /// Reserving the bounded output vector failed.
    AllocationFailed,
    /// Explicit memfd/sealing support is unavailable; no fallback was attempted.
    Unsupported { file: usize },
    /// A fresh memfd could not be created.
    CreateFailed { file: usize },
    /// Writing failed, returned zero or reported an invalid count.
    WriteFailed { file: usize },
    /// Setting the non-executable read-only mode failed.
    ModeFailed { file: usize },
    /// Applying or reading the required seals failed.
    SealFailed { file: usize },
    /// At least one required seal was absent on readback.
    SealMismatch { file: usize },
    /// Size, type, mode or close-on-exec did not match the required state.
    MetadataMismatch { file: usize },
    /// Reading the sealed copy failed or reported an invalid count.
    ReadFailed { file: usize },
    /// The sealed bytes or their exact length differed from the observation.
    ContentMismatch { file: usize },
    /// The batch-wide read/write-call budget, including EINTR, was exhausted.
    AttemptsExhausted { file: usize },
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixture sealing refused: {self:?}")
    }
}

impl std::error::Error for SealError {}

/// Owned sealed copies. Descriptive accessors confer no launch permission.
///
/// ```
/// use irlume_vision::measurement_profile::seal::SealedFixtureFiles;
/// fn count(files: &SealedFixtureFiles) -> usize { files.files().len() }
/// ```
///
/// ```compile_fail
/// use irlume_vision::measurement_profile::seal::SealedFixtureFiles;
/// fn cannot_launch(files: &SealedFixtureFiles) { files.launch(); }
/// ```
pub struct SealedFixtureFiles {
    files: Vec<SealedFixtureFile>,
}

impl SealedFixtureFiles {
    /// Borrow descriptions in input order. The underlying handles stay private.
    pub fn files(&self) -> &[SealedFixtureFile] {
        &self.files
    }
}

/// One retained sealed file and its original descriptive observation.
pub struct SealedFixtureFile {
    _file: File,
    observation: FileObservation,
}

impl SealedFixtureFile {
    /// Original path/hash facts, not a current pathname or trust assessment.
    pub fn observation(&self) -> &FileObservation {
        &self.observation
    }
}

impl fmt::Debug for SealedFixtureFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedFixtureFile").finish_non_exhaustive()
    }
}

impl fmt::Debug for SealedFixtureFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedFixtureFiles")
            .field("file_count", &self.files.len())
            .finish_non_exhaustive()
    }
}

/// Copy immutable observed buffers to fresh memfds and verify their seals/bytes.
///
/// Consumes the observer, closing its original descriptors on every return.
/// Failure also drops every partial copy. Success retains sealed copies only;
/// exact positional readback establishes their equality with the already-hashed
/// buffers. The old source path may since have changed and is never reopened.
///
/// Limits are 256 files, 256 MiB per file, 1 GiB total, and 65,536 batch-wide
/// read/write attempts including interruptions. Original allocations coexist
/// with copies during construction: these are content/call ceilings, not total
/// memory or elapsed-time bounds. Small metadata allocations can still abort.
/// No environment, device, process, mount or native loader is accessed.
///
/// # Errors
/// Returns [`SealError`] for invalid sizes, unsupported memfd/seal capability,
/// allocation/I/O failures, exhausted attempts or mismatched sealed state.
pub fn seal_observed_files(
    observed: ObservedFixtureFiles,
) -> Result<SealedFixtureFiles, SealError> {
    seal_with(observed, &mut SystemIo, IO_CALLS)
}

// Private failure-injection seam. Real ownership and seals are tested on files.
trait SealIo {
    fn create(&mut self) -> io::Result<File> {
        // SAFETY: the constant name is NUL-terminated; memfd_create returns a
        // fresh owned descriptor or -1. Flags explicitly require no-exec mode.
        let fd = unsafe { libc::memfd_create(c"irlume-fixture".as_ptr(), CREATE_FLAGS) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the newly returned descriptor has exactly this owner.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn write(&mut self, file: &File, bytes: &[u8], offset: u64) -> io::Result<usize> {
        file.write_at(bytes, offset)
    }

    fn read(&mut self, file: &File, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
        file.read_at(bytes, offset)
    }

    fn mode(&mut self, file: &File) -> io::Result<()> {
        // SAFETY: changes only this newly owned memfd. Use one call, not std's
        // EINTR-retrying set_permissions, to keep metadata operations bounded.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o400) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn add_seals(&mut self, file: &File) -> io::Result<()> {
        fcntl(file, libc::F_ADD_SEALS, REQUIRED_SEALS).map(|_| ())
    }

    fn seals(&mut self, file: &File) -> io::Result<i32> {
        fcntl(file, libc::F_GET_SEALS, 0)
    }

    fn flags(&mut self, file: &File) -> io::Result<i32> {
        fcntl(file, libc::F_GETFD, 0)
    }

    fn metadata(&mut self, file: &File) -> io::Result<Metadata> {
        file.metadata()
    }
}

struct SystemIo;
impl SealIo for SystemIo {}

fn fcntl(file: &File, command: i32, argument: i32) -> io::Result<i32> {
    // SAFETY: the file stays open; every caller uses an integer-valued fcntl
    // command, never one requiring a pointer or a differently typed argument.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), command, argument) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)
    )
}

fn spend(remaining: &mut u32, file: usize) -> Result<(), SealError> {
    *remaining = remaining
        .checked_sub(1)
        .ok_or(SealError::AttemptsExhausted { file })?;
    Ok(())
}

fn checked_total(total: u64, size: u64, file: usize) -> Result<u64, SealError> {
    let next = total
        .checked_add(size)
        .ok_or(SealError::InvalidSize { file })?;
    if size == 0 || size > HARD_FILE_BYTES || next > HARD_TOTAL_BYTES {
        return Err(SealError::InvalidSize { file });
    }
    Ok(next)
}

fn seal_with(
    observed: ObservedFixtureFiles,
    io: &mut impl SealIo,
    mut remaining: u32,
) -> Result<SealedFixtureFiles, SealError> {
    if observed.files().is_empty() || observed.files().len() > MAX_FILES {
        return Err(SealError::InvalidCount);
    }
    let mut total = 0u64;
    for (file, input) in observed.files().iter().enumerate() {
        let size = input.bytes().len() as u64;
        total = checked_total(total, size, file)?;
    }
    let mut files = Vec::new();
    files
        .try_reserve_exact(observed.files().len())
        .map_err(|_| SealError::AllocationFailed)?;
    for (index, input) in observed.files().iter().enumerate() {
        let file = io.create().map_err(|error| {
            if unsupported(&error) {
                SealError::Unsupported { file: index }
            } else {
                SealError::CreateFailed { file: index }
            }
        })?;
        let source = input.bytes();
        let mut offset = 0;
        while offset < source.len() {
            spend(&mut remaining, index)?;
            let chunk = &source[offset..source.len().min(offset + IO_BYTES)];
            match io.write(&file, chunk, offset as u64) {
                Ok(n) if n > 0 && n <= chunk.len() => offset += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                _ => return Err(SealError::WriteFailed { file: index }),
            }
        }
        io.mode(&file)
            .map_err(|_| SealError::ModeFailed { file: index })?;
        io.add_seals(&file).map_err(|error| {
            if unsupported(&error) {
                SealError::Unsupported { file: index }
            } else {
                SealError::SealFailed { file: index }
            }
        })?;
        let seals = io
            .seals(&file)
            .map_err(|_| SealError::SealFailed { file: index })?;
        if seals & REQUIRED_SEALS != REQUIRED_SEALS {
            return Err(SealError::SealMismatch { file: index });
        }
        let metadata = io
            .metadata(&file)
            .map_err(|_| SealError::MetadataMismatch { file: index })?;
        let flags = io
            .flags(&file)
            .map_err(|_| SealError::MetadataMismatch { file: index })?;
        if !metadata.is_file()
            || metadata.len() != source.len() as u64
            || metadata.mode() & 0o7777 != 0o400
            || flags & libc::FD_CLOEXEC == 0
        {
            return Err(SealError::MetadataMismatch { file: index });
        }
        let mut buffer = [0u8; IO_BYTES];
        offset = 0;
        loop {
            spend(&mut remaining, index)?;
            let length = (source.len() - offset).clamp(1, IO_BYTES);
            match io.read(&file, &mut buffer[..length], offset as u64) {
                Ok(0) if offset == source.len() => break,
                Ok(n) if n > 0 && n <= length && n <= source.len() - offset => {
                    if buffer[..n] != source[offset..offset + n] {
                        return Err(SealError::ContentMismatch { file: index });
                    }
                    offset += n;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(_) => return Err(SealError::ContentMismatch { file: index }),
                Err(_) => return Err(SealError::ReadFailed { file: index }),
            }
        }
        files.push(SealedFixtureFile {
            _file: file,
            observation: input.observation().clone(),
        });
    }
    Ok(SealedFixtureFiles { files })
}

#[cfg(test)]
#[path = "seal_tests.rs"]
mod tests;
