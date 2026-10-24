// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Descriptor-backed observations of explicitly supplied local fixture files.
//!
//! This is not a launcher, acquisition API, atomic snapshot or closure proof.
//! Callers provide owned files from a controlled, responsive local fixture
//! directory, with no concurrent writers. Metadata rechecks can detect changes,
//! not rule out every transient change. Read-call budgets do not bound blocking
//! file I/O. Fallible large-buffer reservations cannot prevent kernel OOM kills
//! or every failure of small metadata/hash allocations.

use super::{FileObservation, SuppliedPathTrust, MAX_FILES, MAX_TEXT_BYTES};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

const HARD_FILE_BYTES: u64 = 256 * 1024 * 1024;
const HARD_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const HARD_READ_CALLS: u32 = 65536;
const READ_BYTES: usize = 64 * 1024;

/// Fixture ownership policy, never a production trust or admission token.
pub struct FixtureScope {
    /// Explicit absolute fixture boundary; no automatic root discovery.
    pub root: PathBuf,
    /// Owner required for the fixture's files, ancestors and symlink hops.
    pub expected_uid: u32,
}

/// An already-open fixture file. The observer never opens content by path.
pub struct FixtureFile {
    /// Fixture pathname whose current endpoint must agree with the descriptor.
    pub declared_path: PathBuf,
    /// Ownership transfers to the result on success, with no descriptor export.
    pub file: File,
}

impl fmt::Debug for FixtureScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixtureScope").finish_non_exhaustive()
    }
}

impl fmt::Debug for FixtureFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixtureFile").finish_non_exhaustive()
    }
}

/// Bounded content and read-attempt limits. Zero permits no corresponding work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservationLimits {
    /// Maximum retained bytes for each file, at most 256 MiB.
    pub per_file_bytes: u64,
    /// Maximum retained bytes across all files, at most 1 GiB. Aliases count.
    pub total_bytes: u64,
    /// Batch-wide read attempts, including EINTR and EOF/growth probes.
    pub read_calls: u32,
}

impl Default for ObservationLimits {
    fn default() -> Self {
        Self {
            per_file_bytes: 64 * 1024 * 1024,
            total_bytes: 256 * 1024 * 1024,
            read_calls: 8192,
        }
    }
}

/// Read-only byte snapshots retaining their original descriptors and buffers.
/// No permission to load, execute, or trust a complete dependency set follows.
///
/// ```
/// use irlume_vision::measurement_profile::observe::ObservedFixtureFiles;
/// fn count(description: &ObservedFixtureFiles) -> usize {
///     description.files().len()
/// }
/// ```
///
/// ```compile_fail
/// use irlume_vision::measurement_profile::observe::ObservedFixtureFiles;
/// fn cannot_launch(description: &ObservedFixtureFiles) {
///     description.launch();
/// }
/// ```
pub struct ObservedFixtureFiles {
    files: Vec<ObservedFile>,
}

impl ObservedFixtureFiles {
    /// Borrow the retained observations. Their order matches the supplied files.
    pub fn files(&self) -> &[ObservedFile] {
        &self.files
    }
}

/// One retained descriptor and its exact hashed byte allocation.
pub struct ObservedFile {
    file: File,
    bytes: Vec<u8>,
    stamp: FileStamp,
    observation: FileObservation,
}

impl ObservedFile {
    /// Borrow the original hashed allocation for offline parsing; never reopen.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Descriptive path/hash facts, not a trust, closure or launch capability.
    pub fn observation(&self) -> &FileObservation {
        &self.observation
    }

    pub(super) fn current_stamp(&self) -> io::Result<FileStamp> {
        self.file
            .metadata()
            .map(|metadata| FileStamp::from(&metadata))
    }
}

impl fmt::Debug for ObservedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedFile").finish_non_exhaustive()
    }
}

impl fmt::Debug for ObservedFixtureFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedFixtureFiles")
            .field("file_count", &self.files.len())
            .finish_non_exhaustive()
    }
}

/// Fixed refusal kinds; no raw paths, contents, hashes or OS errors are exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationError {
    /// A requested limit exceeds its hard ceiling.
    InvalidLimits,
    /// More than the description's maximum file count was supplied.
    TooManyFiles,
    /// The fixture boundary is not a bounded absolute UTF-8 path.
    InvalidScope,
    /// An input path is not a bounded absolute UTF-8 path.
    InvalidPath { file: usize },
    /// The existing trusted-path walk refused the fixture path.
    PathRefused { file: usize },
    /// A descriptor or endpoint's metadata could not be read.
    MetadataRead { file: usize },
    /// A supplied descriptor is not a regular file.
    NotRegular { file: usize },
    /// Descriptor ownership or group/other write permissions fail the policy.
    UntrustedFile { file: usize },
    /// The path and descriptor identify different objects.
    DescriptorMismatch { file: usize },
    /// A path, metadata stamp or observed file length changed during observation.
    Changed { file: usize },
    /// A file exceeds the per-file budget.
    FileTooLarge { file: usize },
    /// This allocation would exceed the batch retained-byte budget.
    TotalTooLarge { file: usize },
    /// The batch has exhausted its read-attempt budget.
    ReadLimit { file: usize },
    /// A positional read failed or returned an invalid count.
    ReadFailed { file: usize },
    /// A fallible buffer or result-vector reservation failed.
    AllocationFailed,
    /// Aliased paths or descriptors have conflicting stamps or digests.
    AliasConflict { file: usize },
}

impl fmt::Display for ObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixture observation refused: {self:?}")
    }
}

impl std::error::Error for ObservationError {}

/// Observe owned fixture descriptors and retain their exact hashed buffers.
///
/// The caller supplies files opened in a controlled, responsive local fixture
/// directory. This function never opens file content by pathname, selects a
/// runtime, or grants loading permission. It uses pathname metadata only to
/// check the supplied descriptors. It does not establish race-free acquisition,
/// closure completeness or the absence of transient concurrent mutations.
/// Aliases each consume their own retained-byte budget. Every positional read
/// attempt, including interrupted calls and EOF probes, consumes the same
/// batch-wide budget. These counts do not bound blocking filesystem I/O.
///
/// # Errors
/// Returns a fixed, value-redacted error for invalid limits/paths, unavailable
/// or unacceptable metadata, descriptor mismatch, detected change, conflicting
/// aliases, failed allocation/read, or exhausted resource budgets. On failure
/// all acquired input ownership and partial results are dropped.
pub fn observe_fixture_files(
    scope: &FixtureScope,
    inputs: Vec<FixtureFile>,
    limits: ObservationLimits,
) -> Result<ObservedFixtureFiles, ObservationError> {
    observe_with(scope, inputs, limits, &mut SystemIo)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    AfterRead,
    BeforeFinalCheck,
}

// Private seams for deterministic syscall/reservation/mutation tests. No public
// caller can supply fabricated metadata, buffers or observation results.
trait ObservationIo {
    fn read_at(&mut self, file: &File, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
        file.read_at(bytes, offset)
    }

    fn reserve(&mut self, bytes: &mut Vec<u8>, length: usize) -> Result<(), ObservationError> {
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ObservationError::AllocationFailed)
    }

    fn buffer_ready(&mut self, _file: usize, _bytes: &[u8]) {}

    fn checkpoint(&mut self, _file: usize, _phase: Phase) {}
}

struct SystemIo;
impl ObservationIo for SystemIo {}

fn observe_with(
    scope: &FixtureScope,
    inputs: Vec<FixtureFile>,
    limits: ObservationLimits,
    io: &mut impl ObservationIo,
) -> Result<ObservedFixtureFiles, ObservationError> {
    if !valid_limits(limits) {
        return Err(ObservationError::InvalidLimits);
    }
    if inputs.len() > MAX_FILES {
        return Err(ObservationError::TooManyFiles);
    }
    if !valid_path(&scope.root) {
        return Err(ObservationError::InvalidScope);
    }
    for (file, input) in inputs.iter().enumerate() {
        if !valid_path(&input.declared_path) {
            return Err(ObservationError::InvalidPath { file });
        }
    }
    let mut files: Vec<ObservedFile> = Vec::new();
    files
        .try_reserve_exact(inputs.len())
        .map_err(|_| ObservationError::AllocationFailed)?;
    let mut total = 0u64;
    let mut remaining = limits.read_calls;
    for (index, input) in inputs.into_iter().enumerate() {
        let metadata = input
            .file
            .metadata()
            .map_err(|_| ObservationError::MetadataRead { file: index })?;
        if !metadata.is_file() {
            return Err(ObservationError::NotRegular { file: index });
        }
        if !trusted_metadata(&metadata, scope.expected_uid) {
            return Err(ObservationError::UntrustedFile { file: index });
        }
        let stamp = FileStamp::from(&metadata);
        if stamp.size > limits.per_file_bytes {
            return Err(ObservationError::FileTooLarge { file: index });
        }
        total = total
            .checked_add(stamp.size)
            .filter(|total| *total <= limits.total_bytes)
            .ok_or(ObservationError::TotalTooLarge { file: index })?;
        let (resolved_path, endpoint) = endpoint(scope, &input.declared_path, index)?;
        if (endpoint.dev, endpoint.ino) != (stamp.dev, stamp.ino) {
            return Err(ObservationError::DescriptorMismatch { file: index });
        }
        if endpoint != stamp {
            return Err(ObservationError::Changed { file: index });
        }
        let length = usize::try_from(stamp.size)
            .map_err(|_| ObservationError::FileTooLarge { file: index })?;
        let mut bytes = Vec::new();
        io.reserve(&mut bytes, length)?;
        bytes.resize(length, 0);
        let mut offset = 0;
        while offset < length {
            let end = offset + READ_BYTES.min(length - offset);
            let read = read_once(
                io,
                &mut remaining,
                index,
                &input.file,
                &mut bytes[offset..end],
                u64::try_from(offset)
                    .map_err(|_| ObservationError::FileTooLarge { file: index })?,
            )?;
            if read == 0 {
                return Err(ObservationError::Changed { file: index });
            }
            offset += read;
        }
        if read_once(io, &mut remaining, index, &input.file, &mut [0], stamp.size)? != 0 {
            return Err(ObservationError::Changed { file: index });
        }
        io.buffer_ready(index, &bytes);
        let sha256 = irlume_common::sha256_hex(&bytes);
        io.checkpoint(index, Phase::AfterRead);
        let observed = ObservedFile {
            file: input.file,
            bytes,
            stamp,
            observation: FileObservation {
                path: input.declared_path,
                resolved_path,
                sha256,
                regular_file: true,
                path_trust: SuppliedPathTrust::Acceptable,
            },
        };
        recheck(scope, &observed, index)?;
        for previous in &files {
            let same_path = previous.observation.resolved_path.as_os_str()
                == observed.observation.resolved_path.as_os_str();
            let same_file = (previous.stamp.dev, previous.stamp.ino)
                == (observed.stamp.dev, observed.stamp.ino);
            if (same_path || same_file)
                && (previous.stamp != observed.stamp
                    || previous.observation.sha256 != observed.observation.sha256)
            {
                return Err(ObservationError::AliasConflict { file: index });
            }
        }
        files.push(observed);
    }
    for (index, file) in files.iter().enumerate() {
        io.checkpoint(index, Phase::BeforeFinalCheck);
        recheck(scope, file, index)?;
    }
    Ok(ObservedFixtureFiles { files })
}

pub(super) fn valid_path(path: &Path) -> bool {
    // Parent components remain meaningful after a resolved directory symlink;
    // the shared walker, not lexical normalization, checks their boundary.
    path.to_str().is_some_and(|text| {
        path.is_absolute() && text.len() <= MAX_TEXT_BYTES && !text.contains('\0')
    })
}

pub(super) fn valid_limits(limits: ObservationLimits) -> bool {
    limits.per_file_bytes <= HARD_FILE_BYTES
        && limits.total_bytes <= HARD_TOTAL_BYTES
        && limits.read_calls <= HARD_READ_CALLS
}

pub(super) fn trusted_metadata(metadata: &Metadata, owner: u32) -> bool {
    crate::npu::fixture_trusted_metadata(metadata.uid(), metadata.mode(), owner)
}

fn endpoint(
    scope: &FixtureScope,
    path: &Path,
    file: usize,
) -> Result<(PathBuf, FileStamp), ObservationError> {
    let resolved = crate::npu::fixture_trusted_path(path, &scope.root, scope.expected_uid)
        .map_err(|_| ObservationError::PathRefused { file })?;
    // The component walk preserves the production policy but normalizes some
    // spelling details. The original path must also resolve: a regular file
    // followed by '/' or '/.' is ENOTDIR even when the walk reaches that file.
    let original = fs::metadata(path).map_err(|_| ObservationError::MetadataRead { file })?;
    let metadata = fs::metadata(&resolved).map_err(|_| ObservationError::MetadataRead { file })?;
    let stamp = FileStamp::from(&metadata);
    if FileStamp::from(&original) != stamp {
        return Err(ObservationError::Changed { file });
    }
    Ok((resolved, stamp))
}

fn recheck(
    scope: &FixtureScope,
    observed: &ObservedFile,
    file: usize,
) -> Result<(), ObservationError> {
    let metadata = observed
        .file
        .metadata()
        .map_err(|_| ObservationError::Changed { file })?;
    let (resolved, stamp) = endpoint(scope, &observed.observation.path, file)
        .map_err(|_| ObservationError::Changed { file })?;
    if FileStamp::from(&metadata) != observed.stamp
        || stamp != observed.stamp
        || resolved.as_os_str() != observed.observation.resolved_path.as_os_str()
    {
        return Err(ObservationError::Changed { file });
    }
    Ok(())
}

fn read_once(
    io: &mut impl ObservationIo,
    remaining: &mut u32,
    index: usize,
    file: &File,
    bytes: &mut [u8],
    offset: u64,
) -> Result<usize, ObservationError> {
    loop {
        *remaining = remaining
            .checked_sub(1)
            .ok_or(ObservationError::ReadLimit { file: index })?;
        match io.read_at(file, bytes, offset) {
            Ok(count) if count <= bytes.len() => return Ok(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err(ObservationError::ReadFailed { file: index }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileStamp {
    dev: u64,
    ino: u64,
    size: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl From<&Metadata> for FileStamp {
    fn from(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

#[cfg(test)]
#[path = "observe_tests.rs"]
mod tests;
