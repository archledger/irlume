// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Non-authorizing measurement descriptions (ADR-0022 measurement amendment).
//!
//! Inputs are supplied snapshots, not observations collected by this module.
//! A checked description verifies only the declared/observed facts and their
//! consistency. It proves neither their authenticity nor completeness of the
//! native dependency/plugin closure, and gives no permission to load or launch.
//! The pure checker inspects no environment, filesystem or runtime. The
//! evidence-only fixture observer reads explicitly supplied file handles and
//! checks their fixture paths; it does not acquire files or inspect an installed
//! runtime. There is no serialized format or production admission path here.

use std::ffi::OsString;
use std::path::PathBuf;

mod validate;
pub use validate::check_description;

#[cfg(feature = "npu")]
pub mod observe;

#[cfg(all(feature = "npu", target_os = "linux", target_arch = "x86_64"))]
pub mod acquire;

#[cfg(all(feature = "npu", target_os = "linux", target_arch = "x86_64"))]
pub mod seal;

#[cfg(test)]
mod tests;

/// The in-memory description contract, not a launch-profile format version.
pub const DESCRIPTION_VERSION: u32 = 1;
/// Maximum declared files and maximum supplied file observations, separately.
pub const MAX_FILES: usize = 256;
/// Maximum entries in each environment list, before duplicate checking.
pub const MAX_ENVIRONMENT_ENTRIES: usize = 64;
/// Maximum bytes in a path or environment value; no lossy conversion is used.
pub const MAX_TEXT_BYTES: usize = 4096;
/// Maximum bytes in a profile ID or environment variable name.
pub const MAX_NAME_BYTES: usize = 128;

/// The declared role of a file, not a claim that all relevant files are listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileRole {
    /// Exactly one measurement executable must be described.
    Executable,
    /// Exactly one CPU-reference ONNX Runtime must be described.
    OrtRuntime,
    /// Exactly one CPU-reference LiteRT runtime must be described.
    LiteRtRuntime,
    /// Exactly one OpenVINO C API file must be described.
    OpenVinoC,
    /// Any additional declared native library, plugin or dynamic linker.
    NativeDependency,
    /// Any declared loader, plugin or driver configuration file.
    Configuration,
}

/// One expected file. Paths and hashes remain unvalidated until checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredFile {
    /// The four primary roles must occur exactly once; other roles may repeat.
    pub role: FileRole,
    /// Absolute, bounded UTF-8 path without NUL or parent-directory components.
    pub path: PathBuf,
    /// Exactly 64 lowercase hexadecimal digits describing the expected bytes.
    pub sha256: String,
}

/// A path-trust assessment supplied by a caller, not verified by this API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuppliedPathTrust {
    /// The caller asserts acceptable file and component/symlink ownership and
    /// permissions. This label is not evidence that the assessment occurred.
    Acceptable,
    /// The caller reports an unacceptable path or file.
    Rejected,
    /// The caller has no complete assessment of the path and file.
    Unknown,
}

/// Supplied facts about one file. This module does not read the named file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileObservation {
    /// The exact declared path this record answers, without normalization.
    pub path: PathBuf,
    /// The caller's reported absolute resolved endpoint, subject to path syntax
    /// checks only. This module neither resolves nor authenticates symlinks.
    pub resolved_path: PathBuf,
    /// The caller's reported content digest, compared with the declaration.
    pub sha256: String,
    /// Whether the caller reports a regular file at the resolved endpoint.
    pub regular_file: bool,
    /// A supplied assessment, including all relevant path components.
    pub path_trust: SuppliedPathTrust,
}

/// One raw entry. Lists preserve duplicates and absent versus empty values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentEntry {
    /// Bounded ASCII name matching `[A-Za-z_][A-Za-z0-9_]*`.
    pub name: OsString,
    /// Bounded UTF-8 value without NUL. An empty value is explicitly present.
    pub value: OsString,
}

/// A proposed measurement description, never an executable launch request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementProfile {
    /// Must equal [`DESCRIPTION_VERSION`].
    pub version: u32,
    /// Nonempty bounded ASCII identifier using letters, digits, `.`, `_`, `-`.
    pub id: String,
    /// Declared build-record SHA-256. Only its syntax is checked in this wave;
    /// the executable's content digest is a separate declared file fact.
    pub build_sha256: String,
    /// A bounded declared inventory with no duplicate path or primary role.
    pub files: Vec<DeclaredFile>,
    /// Exact permitted entries and values, not a wildcard or inherited set.
    /// All `LD_*` variables and `IRLUME_TEST_ALLOW_UNCERTIFIED_EP` are refused
    /// even when explicitly listed. This is not an exhaustive loader policy.
    pub environment: Vec<EnvironmentEntry>,
}

/// Supplied file and environment snapshots. Authenticity is outside this API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileObservations {
    /// Exactly one record per declared path; no undeclared observations.
    pub files: Vec<FileObservation>,
    /// Must equal the declaration as a set of exact, unique name/value pairs.
    /// There is no read or modification of the current process environment.
    pub environment: Vec<EnvironmentEntry>,
}

/// A description whose supplied facts agree, not a launch capability.
///
/// The borrow retains immutable inputs, not filesystem stability. Rechecking
/// this description cannot replace a future trusted observer or launcher.
/// No conversion to production admission, placement or certification exists.
///
/// The type is importable and its descriptive accessor is usable in an evidence
/// build. This positive example must accompany the negative example below so
/// an unavailable module or import cannot alone establish the intended refusal.
///
/// ```
/// use irlume_vision::measurement_profile::CheckedDescription;
/// fn describe(description: &CheckedDescription<'_>) {
///     let _: &str = description.profile_id();
/// }
/// ```
///
/// ```compile_fail
/// use irlume_vision::measurement_profile::CheckedDescription;
/// fn cannot_launch(description: &CheckedDescription<'_>) {
///     description.launch();
/// }
/// ```
pub struct CheckedDescription<'a> {
    profile: &'a MeasurementProfile,
    _observations: &'a ProfileObservations,
}

impl CheckedDescription<'_> {
    /// The supplied profile identifier, not an admission or certification key.
    pub fn profile_id(&self) -> &str {
        &self.profile.id
    }

    /// Number of declared files, not the size of a proven complete closure.
    pub fn declared_file_count(&self) -> usize {
        self.profile.files.len()
    }
}

/// Value-redacted refusal reasons. Indices identify supplied list entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// The in-memory contract version is unsupported.
    UnsupportedVersion,
    /// The profile ID is empty, oversized or has unsupported characters.
    InvalidProfileId,
    /// The declared build digest is not canonical SHA-256 text.
    InvalidBuildDigest,
    /// Either file list exceeds [`MAX_FILES`].
    TooManyFiles,
    /// Either environment list exceeds [`MAX_ENVIRONMENT_ENTRIES`].
    TooManyEnvironmentEntries,
    /// The declared path is unsupported.
    InvalidFilePath { file: usize },
    /// The declared digest is not canonical SHA-256 text.
    InvalidFileDigest { file: usize },
    /// A required primary role has no declaration.
    MissingRole(FileRole),
    /// A primary role occurs more than once, even with identical declarations.
    DuplicateRole(FileRole),
    /// A declared path occurs more than once.
    DuplicateFilePath { file: usize },
    /// No observation answers the declared path.
    MissingObservation { file: usize },
    /// A supplied observation has an invalid resolved path or different digest.
    ObservationMismatch { file: usize },
    /// The supplied path assessment is rejected or unknown.
    UntrustedObservation { file: usize },
    /// The supplied observation does not describe a regular file.
    NonRegularFile { file: usize },
    /// More than one supplied record answers the same path.
    DuplicateObservation { observation: usize },
    /// Different digests are supplied for the exact same resolved-path bytes.
    ConflictingAliasObservation { observation: usize },
    /// A supplied observation answers no declared path.
    UndeclaredObservation { observation: usize },
    /// An environment name/value is unsupported, oversized or prohibited.
    InvalidEnvironment { entry: usize },
    /// A name repeats within either environment list, even with equal values.
    DuplicateEnvironment { entry: usize },
    /// The unique name/value sets disagree, including absent versus empty.
    EnvironmentMismatch,
}
