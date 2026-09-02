// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Full-quality, no-authority qualification of exact camera profiles.

use serde::{Deserialize, Serialize};
use std::{
    io::Read as _,
    path::{Path, PathBuf},
};

use crate::{
    capture_qualification::{
        CameraEndpoint, QualificationContext, QualificationError, QualifiedStreamRole,
    },
    profile::{
        rank_balanced, CandidateVerdict, CaptureSchedule, PairTransportProfile, ProfileGate,
        QualificationScene, QualifiedProfileMetrics, RankingBudget,
    },
};

/// Profile-selection record shape understood by this build.
pub const PROFILE_SELECTION_SCHEMA_VERSION: u32 = 1;
/// Full-quality gate policy understood by this build.
pub const PROFILE_SELECTION_POLICY_VERSION: u32 = 1;
/// Version of the profile qualification producer.
pub const PROFILE_QUALIFICATION_PRODUCER_VERSION: u32 = 1;
/// Hard bound on candidates in one deterministic selection operation.
pub const MAX_PROFILE_CANDIDATES: usize = 32;
/// Profile selections are bounded machine summaries, not a general document store.
pub const MAX_PROFILE_SELECTION_RECORD_BYTES: usize = 256 * 1024;

const MAX_PROFILE_ID_BYTES: usize = 256;

/// Aggregate result for one gate. Scores and biometric outputs are deliberately absent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Passed,
    Failed,
    NotApplicable,
}

/// Aggregate model-gate output. It cannot carry identities, scores, or authority writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProfileAuthGateEvidence {
    detection: GateStatus,
    recognition: GateStatus,
    liveness: GateStatus,
    rgb_pad: GateStatus,
    ir_pad: GateStatus,
}

impl ProfileAuthGateEvidence {
    /// Constructs one aggregate model assessment without biometric values.
    #[must_use]
    #[expect(
        dead_code,
        reason = "reserved for a future authorizing qualification runner"
    )]
    pub(crate) const fn new(
        detection: GateStatus,
        recognition: GateStatus,
        liveness: GateStatus,
        rgb_pad: GateStatus,
        ir_pad: GateStatus,
    ) -> Self {
        Self {
            detection,
            recognition,
            liveness,
            rgb_pad,
            ir_pad,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct SceneGateEvidence {
    required: bool,
    status: Option<GateStatus>,
}

/// Bounded aggregate evidence for every full-quality hard gate.
///
/// Aggregate model evidence is not constructible outside camera qualification.
///
/// ```compile_fail
/// use irlume_camera::profile_qualification::ProfileAuthGateEvidence;
/// let _ = ProfileAuthGateEvidence::new(
///     irlume_camera::profile_qualification::GateStatus::Passed,
///     irlume_camera::profile_qualification::GateStatus::Passed,
///     irlume_camera::profile_qualification::GateStatus::Passed,
///     irlume_camera::profile_qualification::GateStatus::Passed,
///     irlume_camera::profile_qualification::GateStatus::Passed,
/// );
/// ```
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfileGateEvidence {
    negotiation: Option<GateStatus>,
    transport: Option<GateStatus>,
    lit: SceneGateEvidence,
    backlit: SceneGateEvidence,
    low_light: SceneGateEvidence,
    dark_ir: SceneGateEvidence,
    detection: Option<GateStatus>,
    recognition: Option<GateStatus>,
    liveness: Option<GateStatus>,
    rgb_pad: Option<GateStatus>,
    ir_pad: Option<GateStatus>,
    p50_latency_ms: Option<u64>,
    p95_latency_ms: Option<u64>,
    latency_budget_ms: Option<u64>,
}

impl ProfileGateEvidence {
    /// Starts an incomplete diagnostic attempt. It grants no authority until complete.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            negotiation: None,
            transport: None,
            lit: SceneGateEvidence {
                required: false,
                status: None,
            },
            backlit: SceneGateEvidence {
                required: false,
                status: None,
            },
            low_light: SceneGateEvidence {
                required: false,
                status: None,
            },
            dark_ir: SceneGateEvidence {
                required: false,
                status: None,
            },
            detection: None,
            recognition: None,
            liveness: None,
            rgb_pad: None,
            ir_pad: None,
            p50_latency_ms: None,
            p95_latency_ms: None,
            latency_budget_ms: None,
        }
    }

    /// Records one non-scene gate without exposing model scores.
    #[must_use]
    pub fn with_gate(mut self, gate: ProfileGate, status: GateStatus) -> Self {
        match gate {
            ProfileGate::Negotiation => self.negotiation = Some(status),
            ProfileGate::Transport => self.transport = Some(status),
            ProfileGate::Detection => self.detection = Some(status),
            ProfileGate::Recognition => self.recognition = Some(status),
            ProfileGate::Liveness => self.liveness = Some(status),
            ProfileGate::Signal | ProfileGate::Pad | ProfileGate::Latency => {}
        }
        self
    }

    /// Records whether one fixed scene is applicable and its aggregate result.
    #[must_use]
    pub fn with_scene(
        mut self,
        scene: QualificationScene,
        required: bool,
        status: GateStatus,
    ) -> Self {
        *self.scene_mut(scene) = SceneGateEvidence {
            required,
            status: Some(status),
        };
        self
    }

    /// Records aggregate RGB and IR PAD dispositions independently.
    #[must_use]
    pub const fn with_pad(mut self, rgb: GateStatus, ir: GateStatus) -> Self {
        self.rgb_pad = Some(rgb);
        self.ir_pad = Some(ir);
        self
    }

    /// Records bounded wall-time percentiles and the fixed policy ceiling.
    #[must_use]
    pub const fn with_latency(mut self, p50_ms: u64, p95_ms: u64, budget_ms: u64) -> Self {
        self.p50_latency_ms = Some(p50_ms);
        self.p95_latency_ms = Some(p95_ms);
        self.latency_budget_ms = Some(budget_ms);
        self
    }

    #[cfg(test)]
    fn without_gate(mut self, gate: ProfileGate) -> Self {
        match gate {
            ProfileGate::Negotiation => self.negotiation = None,
            ProfileGate::Transport => self.transport = None,
            ProfileGate::Detection => self.detection = None,
            ProfileGate::Recognition => self.recognition = None,
            ProfileGate::Liveness => self.liveness = None,
            ProfileGate::Pad => {
                self.rgb_pad = None;
                self.ir_pad = None;
            }
            ProfileGate::Latency => {
                self.p50_latency_ms = None;
                self.p95_latency_ms = None;
                self.latency_budget_ms = None;
            }
            ProfileGate::Signal => {
                self.lit.status = None;
            }
        }
        self
    }

    fn scene_mut(&mut self, scene: QualificationScene) -> &mut SceneGateEvidence {
        match scene {
            QualificationScene::Lit => &mut self.lit,
            QualificationScene::Backlit => &mut self.backlit,
            QualificationScene::LowLight => &mut self.low_light,
            QualificationScene::DarkIr => &mut self.dark_ir,
        }
    }

    fn validate(&self) -> Result<(), ProfileQualificationError> {
        require_gate(ProfileGate::Negotiation, self.negotiation)?;
        require_gate(ProfileGate::Transport, self.transport)?;
        for scene in [self.lit, self.backlit, self.low_light, self.dark_ir] {
            match (scene.required, scene.status) {
                (true, None) | (false, None) => {
                    return Err(ProfileQualificationError::MissingGate(ProfileGate::Signal));
                }
                (true, Some(GateStatus::Passed)) | (false, Some(GateStatus::NotApplicable)) => {}
                (true, Some(GateStatus::Failed)) => {
                    return Err(ProfileQualificationError::RejectedGate(ProfileGate::Signal));
                }
                _ => return Err(ProfileQualificationError::InvalidEvidence),
            }
        }
        require_gate(ProfileGate::Detection, self.detection)?;
        require_gate(ProfileGate::Recognition, self.recognition)?;
        require_gate(ProfileGate::Liveness, self.liveness)?;
        let (Some(rgb_pad), Some(ir_pad)) = (self.rgb_pad, self.ir_pad) else {
            return Err(ProfileQualificationError::MissingGate(ProfileGate::Pad));
        };
        if matches!(rgb_pad, GateStatus::Failed) || matches!(ir_pad, GateStatus::Failed) {
            return Err(ProfileQualificationError::RejectedGate(ProfileGate::Pad));
        }
        if !matches!(rgb_pad, GateStatus::Passed) && !matches!(ir_pad, GateStatus::Passed) {
            return Err(ProfileQualificationError::InvalidEvidence);
        }
        let (Some(p50), Some(p95), Some(budget)) = (
            self.p50_latency_ms,
            self.p95_latency_ms,
            self.latency_budget_ms,
        ) else {
            return Err(ProfileQualificationError::MissingGate(ProfileGate::Latency));
        };
        if p50 == 0 || p95 == 0 || budget == 0 || p50 > p95 {
            return Err(ProfileQualificationError::InvalidEvidence);
        }
        if p95 > budget {
            return Err(ProfileQualificationError::RejectedGate(
                ProfileGate::Latency,
            ));
        }
        Ok(())
    }
}

fn require_gate(
    gate: ProfileGate,
    status: Option<GateStatus>,
) -> Result<(), ProfileQualificationError> {
    match status {
        None => Err(ProfileQualificationError::MissingGate(gate)),
        Some(GateStatus::Passed) => Ok(()),
        Some(GateStatus::Failed) => Err(ProfileQualificationError::RejectedGate(gate)),
        Some(GateStatus::NotApplicable) => Err(ProfileQualificationError::InvalidEvidence),
    }
}

/// Camera-pair identity and connection facts collected before format selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

/// Current model and conditioning authority against which attempts are checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationAuthorityContext {
    model_contract_digest: String,
    conditioning_catalog_digest: String,
}

impl QualificationAuthorityContext {
    #[must_use]
    pub const fn new(model_contract_digest: String, conditioning_catalog_digest: String) -> Self {
        Self {
            model_contract_digest,
            conditioning_catalog_digest,
        }
    }

    fn validate(&self) -> Result<(), ProfileQualificationError> {
        validate_digest(&self.model_contract_digest)?;
        validate_digest(&self.conditioning_catalog_digest)
    }
}

/// One candidate attempt. Incomplete evidence remains diagnostic-only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfileQualificationAttempt {
    producer_version: u32,
    measured_at_unix: u64,
    profile_id: String,
    context: QualificationContext,
    schedule: CaptureSchedule,
    gates: ProfileGateEvidence,
    model_contract_digest: String,
    conditioning_catalog_digest: String,
    evaluation_manifest_digest: String,
    pre_scope: ProfileScope,
    post_scope: ProfileScope,
}

impl ProfileQualificationAttempt {
    /// Constructs a bounded attempt without treating incomplete gates as authority.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid profile, context, version, or digest facts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        measured_at_unix: u64,
        profile_id: String,
        context: QualificationContext,
        schedule: CaptureSchedule,
        gates: ProfileGateEvidence,
        model_contract_digest: String,
        conditioning_catalog_digest: String,
        evaluation_manifest_digest: String,
        post_scope: ProfileScope,
    ) -> Result<Self, ProfileQualificationError> {
        let pre_scope = ProfileScope::from_context(&context)?;
        let value = Self {
            producer_version: PROFILE_QUALIFICATION_PRODUCER_VERSION,
            measured_at_unix,
            profile_id,
            context,
            schedule,
            gates,
            model_contract_digest,
            conditioning_catalog_digest,
            evaluation_manifest_digest,
            pre_scope,
            post_scope,
        };
        value.validate_structure()?;
        Ok(value)
    }

    fn validate_structure(&self) -> Result<(), ProfileQualificationError> {
        if self.producer_version != PROFILE_QUALIFICATION_PRODUCER_VERSION
            || self.measured_at_unix == 0
        {
            return Err(ProfileQualificationError::InvalidEvidence);
        }
        validate_profile_id(&self.profile_id)?;
        self.pre_scope.validate()?;
        self.post_scope.validate()?;
        validate_digest(&self.model_contract_digest)?;
        validate_digest(&self.conditioning_catalog_digest)?;
        validate_digest(&self.evaluation_manifest_digest)?;
        self.profile()?;
        Ok(())
    }

    /// Resolves this attempt against the authority it recorded.
    ///
    /// # Errors
    ///
    /// Returns the first missing, failed, stale, or inconsistent qualification gate.
    pub fn qualified(&self) -> Result<QualifiedProfileRecord, ProfileQualificationError> {
        self.qualified_for(&QualificationAuthorityContext::new(
            self.model_contract_digest.clone(),
            self.conditioning_catalog_digest.clone(),
        ))
    }

    /// Resolves this attempt only if current model and catalog authority still match.
    ///
    /// # Errors
    ///
    /// Returns the first missing, failed, stale, or inconsistent qualification gate.
    pub fn qualified_for(
        &self,
        authority: &QualificationAuthorityContext,
    ) -> Result<QualifiedProfileRecord, ProfileQualificationError> {
        self.validate_structure()?;
        authority.validate()?;
        if self.model_contract_digest != authority.model_contract_digest {
            return Err(ProfileQualificationError::ModelContractChanged);
        }
        if self.conditioning_catalog_digest != authority.conditioning_catalog_digest {
            return Err(ProfileQualificationError::ConditioningCatalogChanged);
        }
        if self.pre_scope != self.post_scope {
            return Err(ProfileQualificationError::ContextChanged);
        }
        self.gates.validate()?;
        let p50_latency_ms = self
            .gates
            .p50_latency_ms
            .ok_or(ProfileQualificationError::MissingGate(ProfileGate::Latency))?;
        let p95_latency_ms = self
            .gates
            .p95_latency_ms
            .ok_or(ProfileQualificationError::MissingGate(ProfileGate::Latency))?;
        Ok(QualifiedProfileRecord {
            profile_id: self.profile_id.clone(),
            context: self.context.clone(),
            schedule: self.schedule,
            p50_latency_ms,
            p95_latency_ms,
            evaluation_manifest_digest: self.evaluation_manifest_digest.clone(),
        })
    }

    fn profile(&self) -> Result<PairTransportProfile, ProfileQualificationError> {
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
}

/// One exact profile whose full-quality gates passed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QualifiedProfileRecord {
    profile_id: String,
    context: QualificationContext,
    schedule: CaptureSchedule,
    p50_latency_ms: u64,
    p95_latency_ms: u64,
    evaluation_manifest_digest: String,
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

    fn profile(&self) -> Result<PairTransportProfile, ProfileQualificationError> {
        validate_profile_id(&self.profile_id)?;
        validate_digest(&self.evaluation_manifest_digest)?;
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
pub struct ProfileSelectionRecord {
    schema_version: u32,
    policy_version: u32,
    producer_version: u32,
    measured_at_unix: u64,
    scope: ProfileScope,
    model_contract_digest: String,
    conditioning_catalog_digest: String,
    evaluation_manifest_digest: String,
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
        serde_json::to_string_pretty(self)
            .map_err(|error| ProfileQualificationError::Json(error.to_string()))
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
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ProfileQualificationError::Json(error.to_string()))?;
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
    pub fn model_contract_digest(&self) -> &str {
        &self.model_contract_digest
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
        {
            return Err(ProfileQualificationError::InvalidEvidence);
        }
        self.scope.validate()?;
        validate_digest(&self.model_contract_digest)?;
        validate_digest(&self.conditioning_catalog_digest)?;
        validate_digest(&self.evaluation_manifest_digest)?;
        self.selected.profile()?;
        if ProfileScope::from_context(&self.selected.context)? != self.scope {
            return Err(ProfileQualificationError::ContextChanged);
        }
        if self.selected.evaluation_manifest_digest != self.evaluation_manifest_digest {
            return Err(ProfileQualificationError::InvalidEvidence);
        }
        if let Some(fallback) = &self.sequential_fallback {
            fallback.profile()?;
            if fallback.schedule != CaptureSchedule::Sequential
                || fallback.evaluation_manifest_digest != self.evaluation_manifest_digest
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

    fn at(dir: PathBuf) -> Self {
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
    pub fn save(
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
        let mut body = serde_json::to_vec_pretty(&stored)
            .map_err(|error| ProfileQualificationError::Json(error.to_string()))?;
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
    let stored: StoredProfileSelection = serde_json::from_slice(&body)
        .map_err(|error| ProfileQualificationError::Json(error.to_string()))?;
    stored.validate()?;
    Ok(Some(stored))
}

struct ProfileStoreLock {
    _file: std::fs::File,
}

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
/// Returns an error when no complete candidate passes or shared authority is inconsistent.
pub fn select_profiles(
    attempts: Vec<ProfileQualificationAttempt>,
    authority: QualificationAuthorityContext,
    budget: RankingBudget,
) -> Result<ProfileSelectionRecord, ProfileQualificationError> {
    if attempts.is_empty() || attempts.len() > MAX_PROFILE_CANDIDATES {
        return Err(ProfileQualificationError::CandidateCount);
    }
    authority.validate()?;
    let measured_at_unix = attempts
        .iter()
        .map(|attempt| attempt.measured_at_unix)
        .max()
        .ok_or(ProfileQualificationError::CandidateCount)?;
    let scope = attempts[0].pre_scope.clone();
    let manifest = attempts[0].evaluation_manifest_digest.clone();
    let mut qualified = Vec::with_capacity(attempts.len());
    for attempt in attempts {
        if attempt.pre_scope != scope || attempt.evaluation_manifest_digest != manifest {
            return Err(ProfileQualificationError::ContextChanged);
        }
        match attempt.qualified_for(&authority) {
            Ok(candidate) => qualified.push(candidate),
            Err(
                ProfileQualificationError::MissingGate(_)
                | ProfileQualificationError::RejectedGate(_),
            ) => {}
            Err(error) => return Err(error),
        }
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
    .ok_or(ProfileQualificationError::NoPassingProfile)?;
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
        model_contract_digest: authority.model_contract_digest,
        conditioning_catalog_digest: authority.conditioning_catalog_digest,
        evaluation_manifest_digest: manifest,
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

/// Why incomplete or stale full-quality evidence cannot grant selection authority.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileQualificationError {
    MissingGate(ProfileGate),
    RejectedGate(ProfileGate),
    ModelContractChanged,
    ConditioningCatalogChanged,
    ContextChanged,
    InvalidEvidence,
    InvalidProfileId,
    InvalidDigest,
    CandidateCount,
    NoPassingProfile,
    UnsupportedSchema(u32),
    UnsupportedPolicy(u32),
    RecordTooLarge,
    Json(String),
    Context(QualificationError),
}

impl std::fmt::Display for ProfileQualificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "profile qualification failed: {self:?}")
    }
}

impl std::error::Error for ProfileQualificationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capture_qualification::{
            AcceptedStream, CameraEndpoint, ConnectionContext, ExactInterval, ExactRate,
            QualificationContext, QualifiedStreamRole, RequestedStream, StreamContract,
        },
        profile::{CaptureSchedule, ProfileGate, RankingBudget},
    };

    fn endpoint(role: QualifiedStreamRole) -> CameraEndpoint {
        CameraEndpoint::new(
            "ab".repeat(32),
            0x0bda,
            0x5678,
            Some("fixture-serial".into()),
            match role {
                QualifiedStreamRole::Rgb => 0,
                QualifiedStreamRole::Ir => 2,
            },
            "/devices/pci0000:00/0000:00:14.0/usb4/4-2".into(),
            role,
            ConnectionContext::new(
                "/devices/pci0000:00/0000:00:14.0".into(),
                5_000_000,
                "uvcvideo".into(),
                "v4l2-uvc".into(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn stream(role: QualifiedStreamRole, height: u32, fps: u32) -> StreamContract {
        let fourcc = match role {
            QualifiedStreamRole::Rgb => "YUYV",
            QualifiedStreamRole::Ir => "GREY",
        };
        StreamContract::new(
            role,
            RequestedStream::new(
                640,
                height,
                fourcc.into(),
                ExactInterval::new(1, fps).unwrap(),
            )
            .unwrap(),
            AcceptedStream::new(
                640,
                height,
                fourcc.into(),
                1_280,
                640 * height * 2,
                0,
                8,
                1,
                1,
                0,
                ExactInterval::new(1, fps).unwrap(),
            )
            .unwrap(),
            ExactRate::new(15, 2).unwrap(),
        )
        .unwrap()
    }

    fn context(fps: u32) -> QualificationContext {
        QualificationContext::new(
            endpoint(QualifiedStreamRole::Rgb),
            endpoint(QualifiedStreamRole::Ir),
            stream(QualifiedStreamRole::Rgb, 480, fps),
            stream(QualifiedStreamRole::Ir, 400, fps),
        )
        .unwrap()
    }

    fn complete_gates() -> ProfileGateEvidence {
        ProfileGateEvidence::empty()
            .with_gate(ProfileGate::Negotiation, GateStatus::Passed)
            .with_gate(ProfileGate::Transport, GateStatus::Passed)
            .with_scene(QualificationScene::Lit, true, GateStatus::Passed)
            .with_scene(QualificationScene::Backlit, true, GateStatus::Passed)
            .with_scene(QualificationScene::LowLight, true, GateStatus::Passed)
            .with_scene(QualificationScene::DarkIr, true, GateStatus::Passed)
            .with_gate(ProfileGate::Detection, GateStatus::Passed)
            .with_gate(ProfileGate::Recognition, GateStatus::Passed)
            .with_gate(ProfileGate::Liveness, GateStatus::Passed)
            .with_pad(GateStatus::Passed, GateStatus::Passed)
            .with_latency(4_000, 6_000, 8_000)
    }

    fn attempt(
        id: &str,
        fps: u32,
        schedule: CaptureSchedule,
        gates: ProfileGateEvidence,
    ) -> ProfileQualificationAttempt {
        let context = context(fps);
        let post_scope = ProfileScope::from_context(&context).unwrap();
        ProfileQualificationAttempt::new(
            1_788_192_000,
            id.into(),
            context,
            schedule,
            gates,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            post_scope,
        )
        .unwrap()
    }

    #[test]
    fn transport_only_attempt_cannot_select_a_profile() {
        let gates = ProfileGateEvidence::empty()
            .with_gate(ProfileGate::Negotiation, GateStatus::Passed)
            .with_gate(ProfileGate::Transport, GateStatus::Passed)
            .with_scene(QualificationScene::Lit, true, GateStatus::Passed)
            .with_scene(
                QualificationScene::Backlit,
                false,
                GateStatus::NotApplicable,
            )
            .with_scene(
                QualificationScene::LowLight,
                false,
                GateStatus::NotApplicable,
            )
            .with_scene(QualificationScene::DarkIr, false, GateStatus::NotApplicable);
        let attempt = attempt("transport-only", 15, CaptureSchedule::Concurrent, gates);

        assert_eq!(
            attempt.qualified().unwrap_err(),
            ProfileQualificationError::MissingGate(ProfileGate::Detection)
        );
    }

    #[test]
    fn every_model_quality_and_latency_gate_is_mandatory() {
        let cases = [
            (
                ProfileGate::Detection,
                complete_gates().without_gate(ProfileGate::Detection),
            ),
            (
                ProfileGate::Recognition,
                complete_gates().without_gate(ProfileGate::Recognition),
            ),
            (
                ProfileGate::Liveness,
                complete_gates().without_gate(ProfileGate::Liveness),
            ),
            (
                ProfileGate::Pad,
                complete_gates().without_gate(ProfileGate::Pad),
            ),
            (
                ProfileGate::Latency,
                complete_gates().without_gate(ProfileGate::Latency),
            ),
        ];
        for (missing, gates) in cases {
            let attempt = attempt("missing-gate", 15, CaptureSchedule::Concurrent, gates);
            assert_eq!(
                attempt.qualified().unwrap_err(),
                ProfileQualificationError::MissingGate(missing)
            );
        }
    }

    #[test]
    fn digest_or_endpoint_context_drift_authorizes_nothing() {
        let mut digest_drift = attempt(
            "digest-drift",
            15,
            CaptureSchedule::Concurrent,
            complete_gates(),
        );
        digest_drift.model_contract_digest = "44".repeat(32);
        assert_eq!(
            digest_drift
                .qualified_for(&QualificationAuthorityContext::new(
                    "11".repeat(32),
                    "22".repeat(32),
                ))
                .unwrap_err(),
            ProfileQualificationError::ModelContractChanged
        );

        let mut context_drift = attempt(
            "context-drift",
            15,
            CaptureSchedule::Concurrent,
            complete_gates(),
        );
        context_drift.post_scope = ProfileScope::from_context(&context(30)).unwrap();
        context_drift.post_scope.rgb_endpoint = CameraEndpoint::new(
            "cd".repeat(32),
            0x0bda,
            0x5678,
            Some("replacement".into()),
            0,
            "/devices/pci0000:00/0000:00:14.0/usb4/4-3".into(),
            QualifiedStreamRole::Rgb,
            ConnectionContext::new(
                "/devices/pci0000:00/0000:00:14.0".into(),
                5_000_000,
                "uvcvideo".into(),
                "v4l2-uvc".into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            context_drift.qualified().unwrap_err(),
            ProfileQualificationError::ContextChanged
        );
    }

    #[test]
    fn complete_record_selects_balanced_winner_and_sequential_fallback() {
        let attempts = vec![
            attempt(
                "concurrent-30",
                30,
                CaptureSchedule::Concurrent,
                complete_gates(),
            ),
            attempt(
                "concurrent-15",
                15,
                CaptureSchedule::Concurrent,
                complete_gates(),
            ),
            attempt(
                "sequential-15",
                15,
                CaptureSchedule::Sequential,
                complete_gates(),
            ),
        ];
        let authority = QualificationAuthorityContext::new("11".repeat(32), "22".repeat(32));
        let record = select_profiles(
            attempts,
            authority,
            RankingBudget::new(1, 20_000_000, 10_000).unwrap(),
        )
        .unwrap();

        assert_eq!(record.selected().profile_id(), "concurrent-15");
        assert_eq!(
            record.sequential_fallback().unwrap().profile_id(),
            "sequential-15"
        );
        assert_eq!(record.model_contract_digest(), "11".repeat(32));
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
                attempt(
                    "concurrent-15",
                    15,
                    CaptureSchedule::Concurrent,
                    complete_gates(),
                ),
                attempt(
                    "sequential-15",
                    15,
                    CaptureSchedule::Sequential,
                    complete_gates(),
                ),
            ],
            QualificationAuthorityContext::new("11".repeat(32), "22".repeat(32)),
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

        let mut unsupported: serde_json::Value = serde_json::from_str(&body).unwrap();
        unsupported["schema_version"] = serde_json::json!(99);
        assert_eq!(
            ProfileSelectionRecord::from_json(unsupported.to_string().as_bytes()).unwrap_err(),
            ProfileQualificationError::UnsupportedSchema(99)
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
