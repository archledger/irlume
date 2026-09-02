// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Offline release and local evidence composition for exact camera profiles.
//!
//! The superseded owner-local protocol is not a public product surface.
//!
//! ```compile_fail
//! use irlume_camera::profile_evaluation::ProfileEvaluationProtocolManifest;
//! ```
//!
//! Release evidence cannot be fabricated outside camera verification.
//!
//! ```compile_fail
//! use irlume_camera::release_qualification_signature::VerifiedReleaseQualification;
//! let _ = VerifiedReleaseQualification::new_for_test();
//! ```
//!
//! Local commissioning evidence cannot be fabricated from release data.
//!
//! ```compile_fail
//! use irlume_camera::profile_commissioning::ValidatedLocalCommissioning;
//! let _ = ValidatedLocalCommissioning::new_for_test();
//! ```
//!
//! Profile-selection publication is not an external API.
//!
//! ```compile_fail
//! let store = irlume_camera::profile_qualification::ProfileSelectionStore::system();
//! let record = irlume_camera::profile_qualification::ProfileSelectionRecord::from_json(b"{}")
//!     .unwrap();
//! store.save(record, None).unwrap();
//! ```

use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io::Read as _,
    path::{Path, PathBuf},
};

use crate::{
    capture_qualification::{
        CameraEndpoint, QualificationContext, QualificationError, QualifiedStreamRole,
    },
    profile::{
        rank_balanced, CandidateVerdict, CaptureSchedule, PairTransportProfile,
        QualifiedProfileMetrics, RankingBudget,
    },
    profile_commissioning::{ProfileCommissioningError, ValidatedLocalCommissioning},
    release_qualification::{
        ReleaseQualificationError, HARDWARE_SCOPE_MATCH_POLICY_VERSION,
        RELEASE_QUALIFICATION_POLICY_VERSION, RELEASE_QUALIFICATION_PRODUCER_VERSION,
    },
    release_qualification_signature::{ReleaseSignatureError, VerifiedReleaseQualification},
};

/// Profile-selection record shape understood by this build.
pub const PROFILE_SELECTION_SCHEMA_VERSION: u32 = 1;
/// Profile-selection policy understood by this build.
pub const PROFILE_SELECTION_POLICY_VERSION: u32 = 1;
/// Version of the profile qualification producer.
pub const PROFILE_QUALIFICATION_PRODUCER_VERSION: u32 = 1;
/// Hard bound on candidates in one deterministic selection operation.
pub const MAX_PROFILE_CANDIDATES: usize = 32;
/// Profile selections are bounded machine summaries, not a general document store.
pub const MAX_PROFILE_SELECTION_RECORD_BYTES: usize = 256 * 1024;

const MAX_PROFILE_ID_BYTES: usize = 256;

/// Camera-pair identity and connection facts collected before format selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileScope {
    rgb_endpoint: CameraEndpoint,
    ir_endpoint: CameraEndpoint,
}

impl ProfileScope {
    /// Projects one exact stream context into its pre-format pair scope.
    ///
    /// # Errors
    ///
    /// Returns an error when either endpoint identity, role, or connection is invalid.
    pub fn from_context(context: &QualificationContext) -> Result<Self, ProfileQualificationError> {
        let value = Self {
            rgb_endpoint: context.rgb_endpoint().clone(),
            ir_endpoint: context.ir_endpoint().clone(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProfileQualificationError> {
        self.rgb_endpoint
            .validate()
            .map_err(ProfileQualificationError::Context)?;
        self.ir_endpoint
            .validate()
            .map_err(ProfileQualificationError::Context)?;
        if self.rgb_endpoint.role() != QualifiedStreamRole::Rgb
            || self.ir_endpoint.role() != QualifiedStreamRole::Ir
        {
            return Err(ProfileQualificationError::InvalidEvidence);
        }
        Ok(())
    }

    fn filing_key(&self) -> Result<String, ProfileQualificationError> {
        self.validate()?;
        let rgb = self.rgb_endpoint.filing_key();
        let ir = self.ir_endpoint.filing_key();
        Ok(irlume_common::sha256_hex(
            format!(
                "profile-rgb:{}:{rgb}|profile-ir:{}:{ir}",
                rgb.len(),
                ir.len()
            )
            .as_bytes(),
        ))
    }
}

/// Current installed contracts against which opaque evidence is checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QualificationAuthorityContext {
    model_contract_sha256: String,
    preprocessing_contract_sha256: String,
    conditioning_catalog_sha256: String,
    selected_policy_sha256: String,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "reserved for reviewed profile-selection integration"
    )
)]
impl QualificationAuthorityContext {
    pub(crate) fn new(
        model_contract_sha256: String,
        preprocessing_contract_sha256: String,
        conditioning_catalog_sha256: String,
        selected_policy_sha256: String,
    ) -> Result<Self, ProfileQualificationError> {
        let value = Self {
            model_contract_sha256,
            preprocessing_contract_sha256,
            conditioning_catalog_sha256,
            selected_policy_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProfileQualificationError> {
        validate_digest(&self.model_contract_sha256)?;
        validate_digest(&self.preprocessing_contract_sha256)?;
        validate_digest(&self.conditioning_catalog_sha256)?;
        validate_digest(&self.selected_policy_sha256)
    }
}

/// One candidate backed by separate verified release and local evidence.
#[derive(Debug)]
pub(crate) struct QualifiedCandidateEvidence {
    release: VerifiedReleaseQualification,
    local: ValidatedLocalCommissioning,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "reserved for reviewed profile-selection integration"
    )
)]
impl QualifiedCandidateEvidence {
    pub(crate) fn new(
        release: VerifiedReleaseQualification,
        local: ValidatedLocalCommissioning,
        authority: &QualificationAuthorityContext,
    ) -> Result<Self, ProfileQualificationError> {
        let value = Self { release, local };
        value.validate_for(authority)?;
        Ok(value)
    }

    fn validate_for(
        &self,
        authority: &QualificationAuthorityContext,
    ) -> Result<(), ProfileQualificationError> {
        authority.validate()?;
        let artifact = self.release.artifact();
        let release_profile = artifact
            .candidate_profile()
            .to_profile()
            .map_err(|_| ProfileQualificationError::InvalidEvidence)?;
        if release_profile != *self.local.profile() {
            return Err(ProfileQualificationError::ProfileMismatch);
        }
        if !artifact
            .hardware_scope()
            .matches_context(self.local.context(), self.local.interface_layout_sha256())
        {
            return Err(ProfileQualificationError::HardwareScopeMismatch);
        }
        if artifact.model_contract_sha256() != authority.model_contract_sha256 {
            return Err(ProfileQualificationError::ModelContractChanged);
        }
        if artifact.preprocessing_contract_sha256() != authority.preprocessing_contract_sha256 {
            return Err(ProfileQualificationError::PreprocessingContractChanged);
        }
        if artifact.conditioning_catalog_sha256() != authority.conditioning_catalog_sha256
            || self.local.conditioning_catalog_sha256() != authority.conditioning_catalog_sha256
        {
            return Err(ProfileQualificationError::ConditioningCatalogChanged);
        }
        if artifact.selected_policy_sha256() != authority.selected_policy_sha256
            || self.local.selected_policy_sha256() != authority.selected_policy_sha256
        {
            return Err(ProfileQualificationError::SelectedPolicyChanged);
        }
        Ok(())
    }

    fn to_record(&self) -> QualifiedProfileRecord {
        QualifiedProfileRecord {
            profile_id: self.local.profile_id().to_owned(),
            context: self.local.context().clone(),
            schedule: self.local.profile().schedule(),
            p50_latency_ms: self.local.p50_latency_ms(),
            p95_latency_ms: self.local.p95_latency_ms(),
            release_qualification_sha256: self.release.artifact_sha256().to_owned(),
            local_commissioning_sha256: self.local.record_sha256().to_owned(),
        }
    }
}

/// One exact profile whose full-quality gates passed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedProfileRecord {
    profile_id: String,
    context: QualificationContext,
    schedule: CaptureSchedule,
    p50_latency_ms: u64,
    p95_latency_ms: u64,
    release_qualification_sha256: String,
    local_commissioning_sha256: String,
}

impl QualifiedProfileRecord {
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub const fn schedule(&self) -> CaptureSchedule {
        self.schedule
    }

    #[must_use]
    pub fn release_qualification_sha256(&self) -> &str {
        &self.release_qualification_sha256
    }

    #[must_use]
    pub fn local_commissioning_sha256(&self) -> &str {
        &self.local_commissioning_sha256
    }

    fn profile(&self) -> Result<PairTransportProfile, ProfileQualificationError> {
        validate_profile_id(&self.profile_id)?;
        validate_digest(&self.release_qualification_sha256)?;
        validate_digest(&self.local_commissioning_sha256)?;
        if self.p50_latency_ms == 0
            || self.p95_latency_ms == 0
            || self.p50_latency_ms > self.p95_latency_ms
        {
            return Err(ProfileQualificationError::InvalidEvidence);
        }
        self.context
            .validate()
            .map_err(ProfileQualificationError::Context)?;
        PairTransportProfile::from_negotiated(
            self.profile_id.clone(),
            self.context
                .rgb_stream()
                .requested_tuple()
                .ok_or(ProfileQualificationError::InvalidEvidence)?,
            self.context
                .rgb_stream()
                .accepted_tuple()
                .ok_or(ProfileQualificationError::InvalidEvidence)?,
            self.context
                .ir_stream()
                .requested_tuple()
                .ok_or(ProfileQualificationError::InvalidEvidence)?,
            self.context
                .ir_stream()
                .accepted_tuple()
                .ok_or(ProfileQualificationError::InvalidEvidence)?,
            self.schedule,
        )
        .map_err(|_| ProfileQualificationError::InvalidEvidence)
    }

    fn metrics(&self) -> Result<QualifiedProfileMetrics, ProfileQualificationError> {
        QualifiedProfileMetrics::new(
            self.profile()?,
            self.p95_latency_ms,
            CandidateVerdict::Passed,
        )
        .map_err(|_| ProfileQualificationError::InvalidEvidence)
    }
}

/// Separate, versioned profile-selection authority for one physical pair scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionRecord {
    schema_version: u32,
    policy_version: u32,
    producer_version: u32,
    measured_at_unix: u64,
    scope: ProfileScope,
    release_policy_version: u32,
    release_producer_version: u32,
    hardware_match_policy_version: u32,
    campaign_id: String,
    campaign_protocol_sha256: String,
    campaign_result_sha256: String,
    baseline_profile_sha256: String,
    model_contract_sha256: String,
    preprocessing_contract_sha256: String,
    conditioning_catalog_sha256: String,
    selected_policy_sha256: String,
    selected: QualifiedProfileRecord,
    sequential_fallback: Option<QualifiedProfileRecord>,
}

impl ProfileSelectionRecord {
    /// Serialize only after every authority invariant has been revalidated.
    ///
    /// # Errors
    ///
    /// Returns an error when authority is invalid or JSON serialization fails.
    pub fn to_json(&self) -> Result<String, ProfileQualificationError> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(|_| ProfileQualificationError::Json)
    }

    /// Parse bounded untrusted bytes and revalidate all nested authority.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, unsupported, or inconsistent input.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProfileQualificationError> {
        if bytes.len() > MAX_PROFILE_SELECTION_RECORD_BYTES {
            return Err(ProfileQualificationError::RecordTooLarge);
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| ProfileQualificationError::Json)?;
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn scope(&self) -> &ProfileScope {
        &self.scope
    }

    #[must_use]
    pub const fn selected(&self) -> &QualifiedProfileRecord {
        &self.selected
    }

    #[must_use]
    pub const fn sequential_fallback(&self) -> Option<&QualifiedProfileRecord> {
        self.sequential_fallback.as_ref()
    }

    #[must_use]
    pub fn model_contract_sha256(&self) -> &str {
        &self.model_contract_sha256
    }

    fn validate(&self) -> Result<(), ProfileQualificationError> {
        if self.schema_version != PROFILE_SELECTION_SCHEMA_VERSION {
            return Err(ProfileQualificationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.policy_version != PROFILE_SELECTION_POLICY_VERSION {
            return Err(ProfileQualificationError::UnsupportedPolicy(
                self.policy_version,
            ));
        }
        if self.producer_version != PROFILE_QUALIFICATION_PRODUCER_VERSION
            || self.measured_at_unix == 0
            || self.release_policy_version != RELEASE_QUALIFICATION_POLICY_VERSION
            || self.release_producer_version != RELEASE_QUALIFICATION_PRODUCER_VERSION
            || self.hardware_match_policy_version != HARDWARE_SCOPE_MATCH_POLICY_VERSION
        {
            return Err(ProfileQualificationError::InvalidEvidence);
        }
        self.scope.validate()?;
        validate_profile_id(&self.campaign_id)?;
        for digest in [
            &self.campaign_protocol_sha256,
            &self.campaign_result_sha256,
            &self.baseline_profile_sha256,
            &self.model_contract_sha256,
            &self.preprocessing_contract_sha256,
            &self.conditioning_catalog_sha256,
            &self.selected_policy_sha256,
        ] {
            validate_digest(digest)?;
        }
        self.selected.profile()?;
        if ProfileScope::from_context(&self.selected.context)? != self.scope {
            return Err(ProfileQualificationError::ContextChanged);
        }
        if let Some(fallback) = &self.sequential_fallback {
            fallback.profile()?;
            if fallback.schedule != CaptureSchedule::Sequential
                || ProfileScope::from_context(&fallback.context)? != self.scope
            {
                return Err(ProfileQualificationError::InvalidEvidence);
            }
        }
        Ok(())
    }
}

/// One revisioned selection read from the atomic machine store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredProfileSelection {
    revision: u64,
    record: ProfileSelectionRecord,
}

impl StoredProfileSelection {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn record(&self) -> &ProfileSelectionRecord {
        &self.record
    }

    fn validate(&self) -> Result<(), ProfileQualificationError> {
        if self.revision == 0 {
            return Err(ProfileQualificationError::InvalidEvidence);
        }
        self.record.validate()
    }
}

/// Failure to read or compare-and-set the separate profile-selection store.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileSelectionStoreError {
    Io(String),
    InvalidRecord(ProfileQualificationError),
    StaleRevision {
        expected: Option<u64>,
        actual: Option<u64>,
    },
    RevisionExhausted,
    VisibleNotDurable(String),
}

impl std::fmt::Display for ProfileSelectionStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "profile selection store failed: {self:?}")
    }
}

impl std::error::Error for ProfileSelectionStoreError {}

impl From<ProfileQualificationError> for ProfileSelectionStoreError {
    fn from(error: ProfileQualificationError) -> Self {
        Self::InvalidRecord(error)
    }
}

/// Root-owned atomic store, separate from legacy schema-2 capture qualification.
#[derive(Clone, Debug)]
pub struct ProfileSelectionStore {
    dir: PathBuf,
}

impl ProfileSelectionStore {
    /// Production machine-state location. Merely constructing it performs no I/O.
    #[must_use]
    pub fn system() -> Self {
        Self::at(irlume_common::state_dir().join("profile-selections"))
    }

    pub(crate) fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Loads one pair's record. Absence means no profile-selection authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the scope or existing file cannot be trusted.
    pub fn load(
        &self,
        scope: &ProfileScope,
    ) -> Result<Option<StoredProfileSelection>, ProfileSelectionStoreError> {
        scope.validate()?;
        read_stored_selection(&self.record_path(scope)?)
    }

    /// Atomically compare-and-sets a fully validated selection record.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid authority, stale revision, or publication failure.
    #[cfg(test)]
    pub(crate) fn save(
        &self,
        record: ProfileSelectionRecord,
        expected_revision: Option<u64>,
    ) -> Result<StoredProfileSelection, ProfileSelectionStoreError> {
        record.validate()?;
        self.ensure_dir()?;
        let path = self.record_path(record.scope())?;
        let _lock = ProfileStoreLock::acquire(&path.with_extension("lock"))?;
        let previous = read_stored_selection(&path)?;
        let actual_revision = previous.as_ref().map(StoredProfileSelection::revision);
        if expected_revision != actual_revision {
            return Err(ProfileSelectionStoreError::StaleRevision {
                expected: expected_revision,
                actual: actual_revision,
            });
        }
        let revision = actual_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ProfileSelectionStoreError::RevisionExhausted)?;
        let stored = StoredProfileSelection { revision, record };
        stored.validate()?;
        let mut body =
            serde_json::to_vec_pretty(&stored).map_err(|_| ProfileQualificationError::Json)?;
        body.push(b'\n');
        if body.len() > MAX_PROFILE_SELECTION_RECORD_BYTES {
            return Err(ProfileQualificationError::RecordTooLarge.into());
        }
        match irlume_common::write_atomic_reporting(&path, &body, 0o600)
            .map_err(|error| profile_store_io("publish", &path, &error))?
        {
            irlume_common::AtomicWrite::Durable => Ok(stored),
            irlume_common::AtomicWrite::VisibleNotDurable(error) => {
                Err(ProfileSelectionStoreError::VisibleNotDurable(format!(
                    "{}: {error}",
                    path.display()
                )))
            }
        }
    }

    #[cfg(test)]
    fn ensure_dir(&self) -> Result<(), ProfileSelectionStoreError> {
        let existed = self.dir.exists();
        std::fs::create_dir_all(&self.dir)
            .map_err(|error| profile_store_io("create", &self.dir, &error))?;
        irlume_common::restrict(&self.dir, 0o700).map_err(ProfileSelectionStoreError::Io)?;
        if !existed {
            irlume_common::fsync_ancestors(&self.dir).map_err(ProfileSelectionStoreError::Io)?;
        }
        Ok(())
    }

    fn record_path(&self, scope: &ProfileScope) -> Result<PathBuf, ProfileSelectionStoreError> {
        Ok(self.dir.join(format!("{}.json", scope.filing_key()?)))
    }

    #[cfg(test)]
    fn record_path_for_test(&self, scope: &ProfileScope) -> PathBuf {
        self.record_path(scope).expect("valid fixture scope")
    }
}

fn read_stored_selection(
    path: &Path,
) -> Result<Option<StoredProfileSelection>, ProfileSelectionStoreError> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(profile_store_io("open", path, &error)),
    };
    #[cfg(unix)]
    {
        let metadata = file
            .metadata()
            .map_err(|error| profile_store_io("inspect", path, &error))?;
        if !metadata.file_type().is_file()
            || metadata.mode() & 0o777 != 0o600
            // SAFETY: geteuid has no preconditions or side effects.
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(ProfileSelectionStoreError::Io(format!(
                "refusing profile selection with unsafe ownership or mode: {}",
                path.display()
            )));
        }
    }
    let mut body = Vec::new();
    file.by_ref()
        .take((MAX_PROFILE_SELECTION_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|error| profile_store_io("read", path, &error))?;
    if body.len() > MAX_PROFILE_SELECTION_RECORD_BYTES {
        return Err(ProfileQualificationError::RecordTooLarge.into());
    }
    let stored: StoredProfileSelection =
        serde_json::from_slice(&body).map_err(|_| ProfileQualificationError::Json)?;
    stored.validate()?;
    Ok(Some(stored))
}

#[cfg(test)]
struct ProfileStoreLock {
    _file: std::fs::File,
}

#[cfg(test)]
impl ProfileStoreLock {
    fn acquire(path: &Path) -> Result<Self, ProfileSelectionStoreError> {
        #[cfg(unix)]
        {
            use std::os::{fd::AsRawFd as _, unix::fs::OpenOptionsExt as _};
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .map_err(|error| profile_store_io("open lock", path, &error))?;
            // SAFETY: flock borrows this live descriptor and takes no ownership.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(profile_store_io(
                    "lock",
                    path,
                    &std::io::Error::last_os_error(),
                ));
            }
            Ok(Self { _file: file })
        }
        #[cfg(not(unix))]
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)
                .map_err(|error| profile_store_io("open lock", path, &error))?;
            Ok(Self { _file: file })
        }
    }
}

fn profile_store_io(
    action: &str,
    path: &Path,
    error: &std::io::Error,
) -> ProfileSelectionStoreError {
    ProfileSelectionStoreError::Io(format!("{action} {}: {error}", path.display()))
}

/// Selects a deterministic passing profile and retains a passing sequential fallback.
///
/// # Errors
///
/// Returns an error when candidate evidence or shared authority is inconsistent.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "reserved for reviewed profile-selection integration"
    )
)]
pub(crate) fn select_profiles(
    candidates: Vec<QualifiedCandidateEvidence>,
    authority: QualificationAuthorityContext,
    budget: RankingBudget,
) -> Result<ProfileSelectionRecord, ProfileQualificationError> {
    if candidates.is_empty() || candidates.len() > MAX_PROFILE_CANDIDATES {
        return Err(ProfileQualificationError::CandidateCount);
    }
    authority.validate()?;
    let first = &candidates[0];
    first.validate_for(&authority)?;
    let first_artifact = first.release.artifact();
    let scope = ProfileScope::from_context(first.local.context())?;
    let release_policy_version = first_artifact.policy_version();
    let release_producer_version = first_artifact.producer_version();
    let hardware_match_policy_version = first_artifact.hardware_scope().match_policy_version();
    let campaign_id = first_artifact.campaign_id().to_owned();
    let campaign_protocol_sha256 = first_artifact.campaign_protocol_sha256().to_owned();
    let campaign_result_sha256 = first_artifact.campaign_result_sha256().to_owned();
    let baseline_profile_sha256 = first_artifact
        .baseline_profile_sha256()
        .map_err(|_| ProfileQualificationError::InvalidEvidence)?;
    let measured_at_unix = candidates
        .iter()
        .map(|candidate| candidate.local.measured_at_unix())
        .max()
        .ok_or(ProfileQualificationError::CandidateCount)?;
    let mut unique_candidates = HashSet::with_capacity(candidates.len());
    let mut qualified = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        candidate.validate_for(&authority)?;
        let artifact = candidate.release.artifact();
        if !unique_candidates.insert((
            candidate.local.profile_id().to_owned(),
            candidate.local.profile().schedule(),
        )) {
            return Err(ProfileQualificationError::DuplicateCandidate);
        }
        if ProfileScope::from_context(candidate.local.context())? != scope {
            return Err(ProfileQualificationError::ContextChanged);
        }
        if artifact
            .baseline_profile_sha256()
            .map_err(|_| ProfileQualificationError::InvalidEvidence)?
            != baseline_profile_sha256
        {
            return Err(ProfileQualificationError::BaselineProfileMismatch);
        }
        if artifact.policy_version() != release_policy_version
            || artifact.producer_version() != release_producer_version
            || artifact.hardware_scope().match_policy_version() != hardware_match_policy_version
            || artifact.campaign_id() != campaign_id
            || artifact.campaign_protocol_sha256() != campaign_protocol_sha256
            || artifact.campaign_result_sha256() != campaign_result_sha256
        {
            return Err(ProfileQualificationError::ContextChanged);
        }
        qualified.push(candidate.to_record());
    }
    let concurrent: Vec<_> = qualified
        .iter()
        .filter(|candidate| candidate.schedule == CaptureSchedule::Concurrent)
        .map(QualifiedProfileRecord::metrics)
        .collect::<Result<_, _>>()?;
    let sequential: Vec<_> = qualified
        .iter()
        .filter(|candidate| candidate.schedule == CaptureSchedule::Sequential)
        .map(QualifiedProfileRecord::metrics)
        .collect::<Result<_, _>>()?;
    let selected_metrics = if concurrent.is_empty() {
        rank_balanced(&sequential, budget)
    } else {
        rank_balanced(&concurrent, budget)
    }
    .ok_or(ProfileQualificationError::InvalidEvidence)?;
    let selected = qualified
        .iter()
        .find(|candidate| {
            candidate.profile_id == selected_metrics.id()
                && candidate.schedule == selected_metrics.profile().schedule()
        })
        .cloned()
        .ok_or(ProfileQualificationError::InvalidEvidence)?;
    let fallback_metrics = rank_balanced(&sequential, budget);
    let sequential_fallback = fallback_metrics
        .and_then(|metrics| {
            qualified.iter().find(|candidate| {
                candidate.profile_id == metrics.id()
                    && candidate.schedule == metrics.profile().schedule()
            })
        })
        .cloned();
    let record = ProfileSelectionRecord {
        schema_version: PROFILE_SELECTION_SCHEMA_VERSION,
        policy_version: PROFILE_SELECTION_POLICY_VERSION,
        producer_version: PROFILE_QUALIFICATION_PRODUCER_VERSION,
        measured_at_unix,
        scope,
        release_policy_version,
        release_producer_version,
        hardware_match_policy_version,
        campaign_id,
        campaign_protocol_sha256,
        campaign_result_sha256,
        baseline_profile_sha256,
        model_contract_sha256: authority.model_contract_sha256,
        preprocessing_contract_sha256: authority.preprocessing_contract_sha256,
        conditioning_catalog_sha256: authority.conditioning_catalog_sha256,
        selected_policy_sha256: authority.selected_policy_sha256,
        selected,
        sequential_fallback,
    };
    record.validate()?;
    Ok(record)
}

fn validate_profile_id(value: &str) -> Result<(), ProfileQualificationError> {
    if value.is_empty() || value.len() > MAX_PROFILE_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(ProfileQualificationError::InvalidProfileId);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ProfileQualificationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProfileQualificationError::InvalidDigest);
    }
    Ok(())
}

/// Why dual profile evidence cannot grant selection authority.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileQualificationError {
    ProfileMismatch,
    HardwareScopeMismatch,
    BaselineProfileMismatch,
    ModelContractChanged,
    PreprocessingContractChanged,
    ConditioningCatalogChanged,
    SelectedPolicyChanged,
    ContextChanged,
    DuplicateCandidate,
    InvalidEvidence,
    InvalidProfileId,
    InvalidDigest,
    CandidateCount,
    UnsupportedSchema(u32),
    UnsupportedPolicy(u32),
    RecordTooLarge,
    Json,
    Context(QualificationError),
}

impl std::fmt::Display for ProfileQualificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let category = match self {
            Self::ProfileMismatch => "profile_mismatch",
            Self::HardwareScopeMismatch => "hardware_scope_mismatch",
            Self::BaselineProfileMismatch => "baseline_profile_mismatch",
            Self::ModelContractChanged => "model_contract_changed",
            Self::PreprocessingContractChanged => "preprocessing_contract_changed",
            Self::ConditioningCatalogChanged => "conditioning_catalog_changed",
            Self::SelectedPolicyChanged => "selected_policy_changed",
            Self::ContextChanged => "camera_context_changed",
            Self::DuplicateCandidate => "duplicate_candidate",
            Self::InvalidEvidence => "profile_evidence_invalid",
            Self::InvalidProfileId => "profile_identifier_invalid",
            Self::InvalidDigest => "profile_digest_invalid",
            Self::CandidateCount => "profile_candidate_count_invalid",
            Self::UnsupportedSchema(_) => "profile_selection_schema_unsupported",
            Self::UnsupportedPolicy(_) => "profile_selection_policy_unsupported",
            Self::RecordTooLarge => "profile_selection_too_large",
            Self::Json => "profile_selection_json_invalid",
            Self::Context(_) => "profile_context_invalid",
        };
        formatter.write_str(category)
    }
}

impl std::error::Error for ProfileQualificationError {}

/// Share-safe reason that profile qualification authority is unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileQualificationDiagnostic {
    /// No signed release artifact is available.
    ArtifactMissing,
    /// The signed release artifact exceeds its bound.
    ArtifactTooLarge,
    /// The release artifact schema or policy is unsupported or malformed.
    ArtifactSchemaUnsupported,
    /// The detached release signature is absent.
    SignatureMissing,
    /// The detached release signature cannot be verified.
    SignatureInvalid,
    /// The release signer is not trusted.
    SignerUntrusted,
    /// The release artifact is outside its validity interval.
    ArtifactExpired,
    /// Release hardware scope does not match the local camera pair.
    HardwareScopeMismatch,
    /// Candidates do not share one exact release baseline.
    BaselineProfileMismatch,
    /// Release and local profile tuples or schedules differ.
    ProfileTupleMismatch,
    /// Local camera identity or connection context differs.
    CameraContextMismatch,
    /// The installed model contract differs from release evidence.
    ModelDigestChanged,
    /// The installed preprocessing contract differs from release evidence.
    PreprocessingDigestChanged,
    /// Conditioning catalog or selected policy evidence differs.
    ConditioningDigestChanged,
    /// No valid local commissioning authority is available.
    CommissioningMissing,
    /// Local commissioning evidence is outside its validity interval.
    CommissioningStale,
    /// At least one release qualification gate failed.
    ReleaseGateFailed,
    /// At least one local commissioning gate failed.
    LocalGateFailed,
}

impl std::fmt::Display for ProfileQualificationDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ArtifactMissing => "artifact_missing",
            Self::ArtifactTooLarge => "artifact_too_large",
            Self::ArtifactSchemaUnsupported => "artifact_schema_unsupported",
            Self::SignatureMissing => "signature_missing",
            Self::SignatureInvalid => "signature_invalid",
            Self::SignerUntrusted => "signer_untrusted",
            Self::ArtifactExpired => "artifact_expired",
            Self::HardwareScopeMismatch => "hardware_scope_mismatch",
            Self::BaselineProfileMismatch => "baseline_profile_mismatch",
            Self::ProfileTupleMismatch => "profile_tuple_mismatch",
            Self::CameraContextMismatch => "camera_context_mismatch",
            Self::ModelDigestChanged => "model_digest_changed",
            Self::PreprocessingDigestChanged => "preprocessing_digest_changed",
            Self::ConditioningDigestChanged => "conditioning_digest_changed",
            Self::CommissioningMissing => "commissioning_missing",
            Self::CommissioningStale => "commissioning_stale",
            Self::ReleaseGateFailed => "release_gate_failed",
            Self::LocalGateFailed => "local_gate_failed",
        })
    }
}

impl std::error::Error for ProfileQualificationDiagnostic {}

impl From<ReleaseQualificationError> for ProfileQualificationDiagnostic {
    fn from(error: ReleaseQualificationError) -> Self {
        match error {
            ReleaseQualificationError::DocumentTooLarge => Self::ArtifactTooLarge,
            ReleaseQualificationError::UnsupportedHardwareMatchPolicy(_) => {
                Self::HardwareScopeMismatch
            }
            ReleaseQualificationError::InvalidSignerFingerprint => Self::SignerUntrusted,
            ReleaseQualificationError::InvalidProfile
            | ReleaseQualificationError::IdenticalProfiles => Self::ProfileTupleMismatch,
            ReleaseQualificationError::InvalidTime
            | ReleaseQualificationError::ArtifactNotYetValid
            | ReleaseQualificationError::ArtifactExpired => Self::ArtifactExpired,
            ReleaseQualificationError::ReleaseGateFailed => Self::ReleaseGateFailed,
            ReleaseQualificationError::Json
            | ReleaseQualificationError::UnsupportedSchema(_)
            | ReleaseQualificationError::UnsupportedPolicy(_)
            | ReleaseQualificationError::UnsupportedProducer(_)
            | ReleaseQualificationError::InvalidIdentifier
            | ReleaseQualificationError::InvalidDigest => Self::ArtifactSchemaUnsupported,
        }
    }
}

impl From<ReleaseSignatureError> for ProfileQualificationDiagnostic {
    fn from(error: ReleaseSignatureError) -> Self {
        match error {
            ReleaseSignatureError::Artifact(error) => error.into(),
            ReleaseSignatureError::ArtifactMissing | ReleaseSignatureError::FileMissing => {
                Self::ArtifactMissing
            }
            ReleaseSignatureError::ArtifactTooLarge | ReleaseSignatureError::FileTooLarge => {
                Self::ArtifactTooLarge
            }
            ReleaseSignatureError::SignatureMissing => Self::SignatureMissing,
            ReleaseSignatureError::SignerUntrusted
            | ReleaseSignatureError::MetadataSignerMismatch => Self::SignerUntrusted,
            ReleaseSignatureError::SignatureTooLarge
            | ReleaseSignatureError::InvalidSignature
            | ReleaseSignatureError::InvalidConfiguration
            | ReleaseSignatureError::TrustedKeyMissing
            | ReleaseSignatureError::TrustedKeyTooLarge
            | ReleaseSignatureError::Io
            | ReleaseSignatureError::ProcessFailed
            | ReleaseSignatureError::Timeout
            | ReleaseSignatureError::StatusTooLarge
            | ReleaseSignatureError::InvalidStatus
            | ReleaseSignatureError::InvalidArtifactName
            | ReleaseSignatureError::UnsafeFile => Self::SignatureInvalid,
        }
    }
}

impl From<ProfileCommissioningError> for ProfileQualificationDiagnostic {
    fn from(error: ProfileCommissioningError) -> Self {
        match error {
            ProfileCommissioningError::InvalidTime
            | ProfileCommissioningError::NotYetValid
            | ProfileCommissioningError::Stale => Self::CommissioningStale,
            ProfileCommissioningError::InvalidContext
            | ProfileCommissioningError::ContextMismatch => Self::CameraContextMismatch,
            ProfileCommissioningError::InvalidLatency
            | ProfileCommissioningError::LocalGateFailed => Self::LocalGateFailed,
            ProfileCommissioningError::HardwareScopeMismatch => Self::HardwareScopeMismatch,
            ProfileCommissioningError::ProfileMismatch => Self::ProfileTupleMismatch,
            ProfileCommissioningError::ConditioningMismatch => Self::ConditioningDigestChanged,
            ProfileCommissioningError::UnsupportedSchema(_)
            | ProfileCommissioningError::UnsupportedPolicy(_)
            | ProfileCommissioningError::UnsupportedProducer(_)
            | ProfileCommissioningError::InvalidIdentifier
            | ProfileCommissioningError::InvalidDigest
            | ProfileCommissioningError::DocumentTooLarge
            | ProfileCommissioningError::Json => Self::CommissioningMissing,
        }
    }
}

impl From<ProfileQualificationError> for ProfileQualificationDiagnostic {
    fn from(error: ProfileQualificationError) -> Self {
        match error {
            ProfileQualificationError::ProfileMismatch
            | ProfileQualificationError::InvalidProfileId => Self::ProfileTupleMismatch,
            ProfileQualificationError::HardwareScopeMismatch => Self::HardwareScopeMismatch,
            ProfileQualificationError::BaselineProfileMismatch => Self::BaselineProfileMismatch,
            ProfileQualificationError::ModelContractChanged => Self::ModelDigestChanged,
            ProfileQualificationError::PreprocessingContractChanged => {
                Self::PreprocessingDigestChanged
            }
            ProfileQualificationError::ConditioningCatalogChanged
            | ProfileQualificationError::SelectedPolicyChanged => Self::ConditioningDigestChanged,
            ProfileQualificationError::ContextChanged | ProfileQualificationError::Context(_) => {
                Self::CameraContextMismatch
            }
            ProfileQualificationError::DuplicateCandidate
            | ProfileQualificationError::InvalidEvidence
            | ProfileQualificationError::InvalidDigest
            | ProfileQualificationError::CandidateCount
            | ProfileQualificationError::UnsupportedSchema(_)
            | ProfileQualificationError::UnsupportedPolicy(_)
            | ProfileQualificationError::RecordTooLarge
            | ProfileQualificationError::Json => Self::CommissioningMissing,
        }
    }
}

impl From<ProfileSelectionStoreError> for ProfileQualificationDiagnostic {
    fn from(error: ProfileSelectionStoreError) -> Self {
        match error {
            ProfileSelectionStoreError::InvalidRecord(error) => error.into(),
            ProfileSelectionStoreError::Io(_)
            | ProfileSelectionStoreError::StaleRevision { .. }
            | ProfileSelectionStoreError::RevisionExhausted
            | ProfileSelectionStoreError::VisibleNotDurable(_) => Self::CommissioningMissing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        profile::{CaptureSchedule, RankingBudget},
        profile_commissioning::{
            validated_commissioning_fixture, validated_commissioning_fixture_with_bindings,
            validated_commissioning_fixture_with_serial, ProfileCommissioningError,
        },
        release_qualification::ReleaseQualificationError,
        release_qualification_signature::{
            verified_release_fixture, verified_release_fixture_with_descriptor,
            ReleaseSignatureError,
        },
    };

    const FIXED_NOW: u64 = 1_788_192_050;

    fn authority_fixture() -> QualificationAuthorityContext {
        QualificationAuthorityContext::new(
            "77".repeat(32),
            "66".repeat(32),
            "44".repeat(32),
            "55".repeat(32),
        )
        .unwrap()
    }

    fn candidate_fixture(
        id: &str,
        rgb_fps: u32,
        ir_fps: u32,
        schedule: CaptureSchedule,
    ) -> QualifiedCandidateEvidence {
        candidate_fixture_with_release("baseline-30-15", id, rgb_fps, ir_fps, schedule, 0x44)
    }

    fn candidate_fixture_with_release(
        baseline_id: &str,
        id: &str,
        rgb_fps: u32,
        ir_fps: u32,
        schedule: CaptureSchedule,
        campaign_byte: u8,
    ) -> QualifiedCandidateEvidence {
        let release = verified_release_fixture(
            baseline_id,
            id,
            rgb_fps,
            ir_fps,
            schedule,
            campaign_byte,
            FIXED_NOW,
        );
        let local = validated_commissioning_fixture(id, rgb_fps, ir_fps, schedule, FIXED_NOW);
        QualifiedCandidateEvidence::new(release, local, &authority_fixture()).unwrap()
    }

    fn candidate_with_profile_mismatch(
    ) -> Result<QualifiedCandidateEvidence, ProfileQualificationError> {
        let release = verified_release_fixture(
            "baseline-30-15",
            "release-candidate",
            15,
            15,
            CaptureSchedule::Concurrent,
            0x44,
            FIXED_NOW,
        );
        let local = validated_commissioning_fixture(
            "local-candidate",
            15,
            15,
            CaptureSchedule::Concurrent,
            FIXED_NOW,
        );
        QualifiedCandidateEvidence::new(release, local, &authority_fixture())
    }

    fn candidate_with_scope_mismatch(
    ) -> Result<QualifiedCandidateEvidence, ProfileQualificationError> {
        let release = verified_release_fixture_with_descriptor(
            "baseline-30-15",
            "candidate-15-15",
            15,
            15,
            CaptureSchedule::Concurrent,
            0x44,
            FIXED_NOW,
            &"cd".repeat(32),
        );
        let local = validated_commissioning_fixture(
            "candidate-15-15",
            15,
            15,
            CaptureSchedule::Concurrent,
            FIXED_NOW,
        );
        QualifiedCandidateEvidence::new(release, local, &authority_fixture())
    }

    fn candidate_with_model_drift() -> Result<QualifiedCandidateEvidence, ProfileQualificationError>
    {
        let release = verified_release_fixture(
            "baseline-30-15",
            "candidate-15-15",
            15,
            15,
            CaptureSchedule::Concurrent,
            0x44,
            FIXED_NOW,
        );
        let local = validated_commissioning_fixture(
            "candidate-15-15",
            15,
            15,
            CaptureSchedule::Concurrent,
            FIXED_NOW,
        );
        let authority = QualificationAuthorityContext::new(
            "78".repeat(32),
            "66".repeat(32),
            "44".repeat(32),
            "55".repeat(32),
        )
        .unwrap();
        QualifiedCandidateEvidence::new(release, local, &authority)
    }

    #[test]
    fn release_and_local_pass_select_balanced_candidate_and_sequential_fallback() {
        let candidates = vec![
            candidate_fixture("concurrent-30-15", 30, 15, CaptureSchedule::Concurrent),
            candidate_fixture("concurrent-15-15", 15, 15, CaptureSchedule::Concurrent),
            candidate_fixture("sequential-15-15", 15, 15, CaptureSchedule::Sequential),
        ];
        let record = select_profiles(
            candidates,
            authority_fixture(),
            RankingBudget::new(1, 20_000_000, 10_000).unwrap(),
        )
        .unwrap();

        assert_eq!(record.selected().profile_id(), "concurrent-15-15");
        assert_eq!(
            record.sequential_fallback().unwrap().profile_id(),
            "sequential-15-15"
        );
        assert_ne!(
            record.selected().release_qualification_sha256(),
            record.selected().local_commissioning_sha256(),
        );
        assert_eq!(record.model_contract_sha256(), "77".repeat(32));
    }

    #[test]
    fn mismatched_evidence_never_enters_ranking() {
        assert_eq!(
            candidate_with_profile_mismatch().unwrap_err(),
            ProfileQualificationError::ProfileMismatch,
        );
        assert_eq!(
            candidate_with_scope_mismatch().unwrap_err(),
            ProfileQualificationError::HardwareScopeMismatch,
        );
        assert_eq!(
            candidate_with_model_drift().unwrap_err(),
            ProfileQualificationError::ModelContractChanged,
        );
    }

    #[test]
    fn every_current_contract_binding_is_mandatory() {
        let authority_cases = [
            (
                QualificationAuthorityContext::new(
                    "77".repeat(32),
                    "67".repeat(32),
                    "44".repeat(32),
                    "55".repeat(32),
                )
                .unwrap(),
                ProfileQualificationError::PreprocessingContractChanged,
            ),
            (
                QualificationAuthorityContext::new(
                    "77".repeat(32),
                    "66".repeat(32),
                    "45".repeat(32),
                    "55".repeat(32),
                )
                .unwrap(),
                ProfileQualificationError::ConditioningCatalogChanged,
            ),
            (
                QualificationAuthorityContext::new(
                    "77".repeat(32),
                    "66".repeat(32),
                    "44".repeat(32),
                    "56".repeat(32),
                )
                .unwrap(),
                ProfileQualificationError::SelectedPolicyChanged,
            ),
        ];
        for (authority, expected) in authority_cases {
            let release = verified_release_fixture(
                "baseline-30-15",
                "candidate-15-15",
                15,
                15,
                CaptureSchedule::Concurrent,
                0x44,
                FIXED_NOW,
            );
            let local = validated_commissioning_fixture(
                "candidate-15-15",
                15,
                15,
                CaptureSchedule::Concurrent,
                FIXED_NOW,
            );
            assert_eq!(
                QualifiedCandidateEvidence::new(release, local, &authority).unwrap_err(),
                expected,
            );
        }

        for (catalog_byte, policy_byte, expected) in [
            (
                0x45,
                0x55,
                ProfileQualificationError::ConditioningCatalogChanged,
            ),
            (0x44, 0x56, ProfileQualificationError::SelectedPolicyChanged),
        ] {
            let release = verified_release_fixture(
                "baseline-30-15",
                "candidate-15-15",
                15,
                15,
                CaptureSchedule::Concurrent,
                0x44,
                FIXED_NOW,
            );
            let local = validated_commissioning_fixture_with_bindings(
                "candidate-15-15",
                15,
                15,
                CaptureSchedule::Concurrent,
                FIXED_NOW,
                catalog_byte,
                policy_byte,
            );
            assert_eq!(
                QualifiedCandidateEvidence::new(release, local, &authority_fixture()).unwrap_err(),
                expected,
            );
        }
    }

    #[test]
    fn mixed_baselines_campaigns_scopes_and_duplicate_pairs_fail_closed() {
        let budget = RankingBudget::new(1, 20_000_000, 10_000).unwrap();
        assert_eq!(
            select_profiles(
                vec![
                    candidate_fixture_with_release(
                        "baseline-30-15",
                        "candidate-a",
                        15,
                        15,
                        CaptureSchedule::Concurrent,
                        0x44,
                    ),
                    candidate_fixture_with_release(
                        "other-baseline",
                        "candidate-b",
                        15,
                        15,
                        CaptureSchedule::Concurrent,
                        0x44,
                    ),
                ],
                authority_fixture(),
                budget,
            )
            .unwrap_err(),
            ProfileQualificationError::BaselineProfileMismatch,
        );
        assert_eq!(
            select_profiles(
                vec![
                    candidate_fixture_with_release(
                        "baseline-30-15",
                        "candidate-a",
                        15,
                        15,
                        CaptureSchedule::Concurrent,
                        0x44,
                    ),
                    candidate_fixture_with_release(
                        "baseline-30-15",
                        "candidate-b",
                        15,
                        15,
                        CaptureSchedule::Concurrent,
                        0x45,
                    ),
                ],
                authority_fixture(),
                budget,
            )
            .unwrap_err(),
            ProfileQualificationError::ContextChanged,
        );

        let changed_context_release = verified_release_fixture(
            "baseline-30-15",
            "candidate-b",
            15,
            15,
            CaptureSchedule::Concurrent,
            0x44,
            FIXED_NOW,
        );
        let changed_context_local = validated_commissioning_fixture_with_serial(
            "candidate-b",
            15,
            15,
            CaptureSchedule::Concurrent,
            FIXED_NOW,
            "other-device",
        );
        let changed_context = QualifiedCandidateEvidence::new(
            changed_context_release,
            changed_context_local,
            &authority_fixture(),
        )
        .unwrap();
        assert_eq!(
            select_profiles(
                vec![
                    candidate_fixture("candidate-a", 15, 15, CaptureSchedule::Concurrent),
                    changed_context,
                ],
                authority_fixture(),
                budget,
            )
            .unwrap_err(),
            ProfileQualificationError::ContextChanged,
        );

        assert_eq!(
            select_profiles(
                vec![
                    candidate_fixture("duplicate", 15, 15, CaptureSchedule::Concurrent),
                    candidate_fixture("duplicate", 15, 15, CaptureSchedule::Concurrent),
                ],
                authority_fixture(),
                budget,
            )
            .unwrap_err(),
            ProfileQualificationError::DuplicateCandidate,
        );
    }

    #[test]
    fn sequential_only_candidates_rank_without_fabricating_a_concurrent_profile() {
        let record = select_profiles(
            vec![
                candidate_fixture("sequential-30-15", 30, 15, CaptureSchedule::Sequential),
                candidate_fixture("sequential-15-15", 15, 15, CaptureSchedule::Sequential),
            ],
            authority_fixture(),
            RankingBudget::new(1, 20_000_000, 10_000).unwrap(),
        )
        .unwrap();
        assert_eq!(record.selected().profile_id(), "sequential-15-15");
        assert_eq!(record.selected().schedule(), CaptureSchedule::Sequential);
        assert_eq!(
            record.sequential_fallback().unwrap().profile_id(),
            "sequential-15-15",
        );

        let same_id = select_profiles(
            vec![
                candidate_fixture("same-id", 15, 15, CaptureSchedule::Concurrent),
                candidate_fixture("same-id", 15, 15, CaptureSchedule::Sequential),
            ],
            authority_fixture(),
            RankingBudget::new(1, 20_000_000, 10_000).unwrap(),
        )
        .unwrap();
        assert_eq!(same_id.selected().schedule(), CaptureSchedule::Concurrent);
        assert_eq!(
            same_id.sequential_fallback().unwrap().schedule(),
            CaptureSchedule::Sequential,
        );
    }

    #[test]
    fn candidate_count_is_bounded_before_ranking() {
        let budget = RankingBudget::new(1, 20_000_000, 10_000).unwrap();
        assert_eq!(
            select_profiles(Vec::new(), authority_fixture(), budget).unwrap_err(),
            ProfileQualificationError::CandidateCount,
        );
        let candidates = (0..33)
            .map(|index| {
                candidate_fixture(
                    &format!("candidate-{index:02}"),
                    15,
                    15,
                    CaptureSchedule::Concurrent,
                )
            })
            .collect();
        assert_eq!(
            select_profiles(candidates, authority_fixture(), budget).unwrap_err(),
            ProfileQualificationError::CandidateCount,
        );
    }

    #[test]
    fn internal_failures_project_to_the_fixed_diagnostic_vocabulary() {
        assert_eq!(
            ProfileQualificationDiagnostic::from(ReleaseSignatureError::ArtifactMissing),
            ProfileQualificationDiagnostic::ArtifactMissing,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ReleaseQualificationError::DocumentTooLarge),
            ProfileQualificationDiagnostic::ArtifactTooLarge,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ReleaseQualificationError::UnsupportedSchema(2)),
            ProfileQualificationDiagnostic::ArtifactSchemaUnsupported,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ReleaseSignatureError::SignatureMissing),
            ProfileQualificationDiagnostic::SignatureMissing,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ReleaseSignatureError::InvalidSignature),
            ProfileQualificationDiagnostic::SignatureInvalid,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ReleaseSignatureError::SignerUntrusted),
            ProfileQualificationDiagnostic::SignerUntrusted,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ReleaseQualificationError::ArtifactExpired),
            ProfileQualificationDiagnostic::ArtifactExpired,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ProfileQualificationError::HardwareScopeMismatch,),
            ProfileQualificationDiagnostic::HardwareScopeMismatch,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(
                ProfileQualificationError::BaselineProfileMismatch,
            ),
            ProfileQualificationDiagnostic::BaselineProfileMismatch,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ProfileQualificationError::ProfileMismatch),
            ProfileQualificationDiagnostic::ProfileTupleMismatch,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ProfileQualificationError::ContextChanged),
            ProfileQualificationDiagnostic::CameraContextMismatch,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ProfileQualificationError::ModelContractChanged,),
            ProfileQualificationDiagnostic::ModelDigestChanged,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(
                ProfileQualificationError::PreprocessingContractChanged,
            ),
            ProfileQualificationDiagnostic::PreprocessingDigestChanged,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(
                ProfileQualificationError::ConditioningCatalogChanged,
            ),
            ProfileQualificationDiagnostic::ConditioningDigestChanged,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ProfileCommissioningError::Json),
            ProfileQualificationDiagnostic::CommissioningMissing,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ProfileCommissioningError::Stale),
            ProfileQualificationDiagnostic::CommissioningStale,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ReleaseQualificationError::ReleaseGateFailed,),
            ProfileQualificationDiagnostic::ReleaseGateFailed,
        );
        assert_eq!(
            ProfileQualificationDiagnostic::from(ProfileCommissioningError::LocalGateFailed),
            ProfileQualificationDiagnostic::LocalGateFailed,
        );
    }

    #[test]
    fn diagnostic_display_is_exact_and_never_leaks_internal_text() {
        let cases = [
            (
                ProfileQualificationDiagnostic::ArtifactMissing,
                "artifact_missing",
            ),
            (
                ProfileQualificationDiagnostic::ArtifactTooLarge,
                "artifact_too_large",
            ),
            (
                ProfileQualificationDiagnostic::ArtifactSchemaUnsupported,
                "artifact_schema_unsupported",
            ),
            (
                ProfileQualificationDiagnostic::SignatureMissing,
                "signature_missing",
            ),
            (
                ProfileQualificationDiagnostic::SignatureInvalid,
                "signature_invalid",
            ),
            (
                ProfileQualificationDiagnostic::SignerUntrusted,
                "signer_untrusted",
            ),
            (
                ProfileQualificationDiagnostic::ArtifactExpired,
                "artifact_expired",
            ),
            (
                ProfileQualificationDiagnostic::HardwareScopeMismatch,
                "hardware_scope_mismatch",
            ),
            (
                ProfileQualificationDiagnostic::BaselineProfileMismatch,
                "baseline_profile_mismatch",
            ),
            (
                ProfileQualificationDiagnostic::ProfileTupleMismatch,
                "profile_tuple_mismatch",
            ),
            (
                ProfileQualificationDiagnostic::CameraContextMismatch,
                "camera_context_mismatch",
            ),
            (
                ProfileQualificationDiagnostic::ModelDigestChanged,
                "model_digest_changed",
            ),
            (
                ProfileQualificationDiagnostic::PreprocessingDigestChanged,
                "preprocessing_digest_changed",
            ),
            (
                ProfileQualificationDiagnostic::ConditioningDigestChanged,
                "conditioning_digest_changed",
            ),
            (
                ProfileQualificationDiagnostic::CommissioningMissing,
                "commissioning_missing",
            ),
            (
                ProfileQualificationDiagnostic::CommissioningStale,
                "commissioning_stale",
            ),
            (
                ProfileQualificationDiagnostic::ReleaseGateFailed,
                "release_gate_failed",
            ),
            (
                ProfileQualificationDiagnostic::LocalGateFailed,
                "local_gate_failed",
            ),
        ];
        for (diagnostic, expected) in cases {
            assert_eq!(diagnostic.to_string(), expected);
        }

        let unsafe_text = "gpg: /tmp/private/campaign serial score fixture-id";
        for diagnostic in [
            ProfileQualificationDiagnostic::from(ProfileQualificationError::Context(
                QualificationError::System(unsafe_text.to_owned()),
            )),
            ProfileQualificationDiagnostic::from(ProfileSelectionStoreError::Io(
                unsafe_text.to_owned(),
            )),
            ProfileQualificationDiagnostic::from(ProfileSelectionStoreError::VisibleNotDurable(
                unsafe_text.to_owned(),
            )),
        ] {
            let rendered = diagnostic.to_string();
            for forbidden in [
                "/",
                "\\",
                "gpg:",
                "campaign",
                "serial",
                "score",
                "fixture-id",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "{rendered} leaked {forbidden}"
                );
            }
        }
    }

    struct TempStore {
        path: std::path::PathBuf,
    }

    impl TempStore {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "irlume-profile-selection-{}-{id}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn store(&self) -> ProfileSelectionStore {
            ProfileSelectionStore::at(self.path.clone())
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn selection_record() -> ProfileSelectionRecord {
        select_profiles(
            vec![
                candidate_fixture("concurrent-15-15", 15, 15, CaptureSchedule::Concurrent),
                candidate_fixture("sequential-15-15", 15, 15, CaptureSchedule::Sequential),
            ],
            authority_fixture(),
            RankingBudget::new(1, 20_000_000, 10_000).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn selection_record_revalidates_after_deserialization() {
        let record = selection_record();
        let body = record.to_json().unwrap();
        assert_eq!(
            ProfileSelectionRecord::from_json(body.as_bytes()).unwrap(),
            record
        );

        let mut value: serde_json::Value = serde_json::from_str(&body).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert_eq!(
            ProfileSelectionRecord::from_json(value.to_string().as_bytes()).unwrap_err(),
            ProfileQualificationError::Json,
        );

        let mut value: serde_json::Value = serde_json::from_str(&body).unwrap();
        value["selected"]["unknown"] = serde_json::json!(true);
        assert_eq!(
            ProfileSelectionRecord::from_json(value.to_string().as_bytes()).unwrap_err(),
            ProfileQualificationError::Json,
        );

        let mut unsupported: serde_json::Value = serde_json::from_str(&body).unwrap();
        unsupported["schema_version"] = serde_json::json!(99);
        assert_eq!(
            ProfileSelectionRecord::from_json(unsupported.to_string().as_bytes()).unwrap_err(),
            ProfileQualificationError::UnsupportedSchema(99)
        );

        for field in ["release_qualification_sha256", "local_commissioning_sha256"] {
            let mut malformed: serde_json::Value = serde_json::from_str(&body).unwrap();
            malformed["selected"][field] = serde_json::json!("not-a-digest");
            assert_eq!(
                ProfileSelectionRecord::from_json(malformed.to_string().as_bytes()).unwrap_err(),
                ProfileQualificationError::InvalidDigest,
                "{field}",
            );
        }

        let mut changed_scope: serde_json::Value = serde_json::from_str(&body).unwrap();
        changed_scope["selected"]["context"]["rgb_endpoint"]["serial"] =
            serde_json::json!("different-device");
        assert_eq!(
            ProfileSelectionRecord::from_json(changed_scope.to_string().as_bytes()).unwrap_err(),
            ProfileQualificationError::ContextChanged,
        );
        assert_eq!(
            ProfileSelectionRecord::from_json(&vec![b' '; MAX_PROFILE_SELECTION_RECORD_BYTES + 1])
                .unwrap_err(),
            ProfileQualificationError::RecordTooLarge
        );
    }

    #[test]
    fn selection_store_is_atomic_mode_limited_and_revision_guarded() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempStore::new();
        let store = temp.store();
        let record = selection_record();
        assert!(store.load(record.scope()).unwrap().is_none());

        let first = store.save(record.clone(), None).unwrap();
        assert_eq!(first.revision(), 1);
        assert_eq!(store.load(record.scope()).unwrap().unwrap(), first);
        assert_eq!(
            store.save(record.clone(), None).unwrap_err(),
            ProfileSelectionStoreError::StaleRevision {
                expected: None,
                actual: Some(1),
            }
        );
        let second = store.save(record.clone(), Some(1)).unwrap();
        assert_eq!(second.revision(), 2);
        let mode = std::fs::metadata(store.record_path_for_test(record.scope()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn selection_store_refuses_symlink_records() {
        use std::os::unix::fs::symlink;

        let temp = TempStore::new();
        let store = temp.store();
        let record = selection_record();
        let path = store.record_path_for_test(record.scope());
        let target = temp.path.join("attacker.json");
        std::fs::write(&target, record.to_json().unwrap()).unwrap();
        symlink(&target, &path).unwrap();

        assert!(matches!(
            store.load(record.scope()),
            Err(ProfileSelectionStoreError::Io(_))
        ));
    }
}
