// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Immutable camera-owned authority for one capture attempt.

use std::{num::NonZeroUsize, time::Duration};

use crate::{
    conditioning::{ConditioningContext, ConditioningSelection, SceneObservation, SceneStatistics},
    evidence::{CanonicalIrEvidence, CanonicalRgbEvidence},
    profile::{CaptureSchedule, PairTransportProfile},
    RuntimePairContract, RuntimePairViolation,
};

/// Fixed v1 maximum separation between RGB and IR window starts.
pub const EVIDENCE_PAIR_BOUND_V1: Duration = Duration::from_secs(8);
/// Version of the fixed contributor and role-pair timing rules.
pub const EVIDENCE_WINDOW_RULES_VERSION: u32 = 1;

/// Canonical pair and process-local observation produced by camera orchestration.
pub struct ValidatedAttemptCapture {
    rgb: CanonicalRgbEvidence,
    ir: CanonicalIrEvidence,
    observation: SceneObservation,
}

impl ValidatedAttemptCapture {
    #[must_use]
    pub const fn rgb(&self) -> &CanonicalRgbEvidence {
        &self.rgb
    }

    #[must_use]
    pub const fn ir(&self) -> &CanonicalIrEvidence {
        &self.ir
    }

    #[must_use]
    pub const fn observation(&self) -> &SceneObservation {
        &self.observation
    }
}

/// Captures one exact diagnostic profile and mints an observation only after validation.
///
/// # Errors
///
/// Returns an error for lease, open, capture, manifest, or immutable-plan failure.
pub fn capture_profile_observation(
    contract: &CameraAttemptContract,
    rgb_device: &str,
    ir_device: &str,
) -> irlume_common::Result<ValidatedAttemptCapture> {
    let operation = crate::lease::acquire_camera_operation(
        &[rgb_device, ir_device],
        crate::lease::CameraOperationKind::Diagnostics,
        Duration::from_secs(2),
    )
    .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?;
    operation
        .run(|| {
            let rgb_camera = crate::RgbCamera::open_profile(rgb_device, contract.profile().rgb())?;
            let ir_camera = crate::IrCamera::open_profile(ir_device, contract.profile().ir())?;
            let observed_runtime =
                crate::runtime_pair_contract_from_cameras(&rgb_camera, &ir_camera)?;
            contract
                .validate_authority(
                    &observed_runtime,
                    contract.profile(),
                    contract.conditioning_context(),
                    contract.conditioning(),
                )
                .map_err(plan_error)?;
            let (rgb, ir) = match contract.profile().schedule() {
                CaptureSchedule::Sequential => {
                    let rgb = rgb_camera.session()?.denoised()?;
                    let ir = ir_camera.session()?.capture_with_stats()?;
                    (rgb, ir)
                }
                CaptureSchedule::Concurrent => {
                    let mut rgb_session = rgb_camera.session()?;
                    let mut ir_session = ir_camera.session()?;
                    std::thread::scope(|scope| {
                        let ir_capture = scope.spawn(|| ir_session.capture_with_stats());
                        let rgb = rgb_session.denoised()?;
                        let ir = ir_capture.join().map_err(|_| {
                            irlume_common::Error::Hardware("IR capture thread panicked".into())
                        })??;
                        Ok((rgb, ir))
                    })?
                }
            };
            let observation = contract
                .mint_observation(
                    &observed_runtime,
                    contract.profile(),
                    contract.conditioning_context(),
                    contract.conditioning(),
                    &rgb,
                    &ir,
                    scene_statistics(&rgb, &ir)?,
                )
                .map_err(plan_error)?;
            Ok(ValidatedAttemptCapture {
                rgb,
                ir,
                observation,
            })
        })
        .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?
}

fn plan_error(violation: CapturePlanViolation) -> irlume_common::Error {
    irlume_common::Error::Hardware(format!("attempt capture plan violation: {violation:?}"))
}

fn scene_statistics(
    rgb: &CanonicalRgbEvidence,
    ir: &CanonicalIrEvidence,
) -> irlume_common::Result<SceneStatistics> {
    let mut luma: Vec<u8> = rgb
        .pixels()
        .chunks_exact(3)
        .map(|pixel| {
            let weighted = 77_u32 * u32::from(pixel[0])
                + 150_u32 * u32::from(pixel[1])
                + 29_u32 * u32::from(pixel[2]);
            u8::try_from(weighted >> 8).unwrap_or(u8::MAX)
        })
        .collect();
    if luma.is_empty() {
        return Err(irlume_common::Error::Hardware(
            "canonical RGB evidence has no pixels".into(),
        ));
    }
    luma.sort_unstable();
    let percentile = |numerator: usize| luma[(luma.len() - 1) * numerator / 10];
    let p10 = percentile(1);
    let median = percentile(5);
    let p90 = percentile(9);
    let clipped = luma.iter().filter(|value| **value >= 250).count();
    let clipped_basis_points =
        u16::try_from(clipped.saturating_mul(10_000) / luma.len()).unwrap_or(10_000);
    let ir_stats = ir.stats();
    SceneStatistics::new(
        crate::conditioning::BrightnessDistribution::new(p10, median, p90)
            .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?,
        clipped_basis_points,
        p90.saturating_sub(p10),
        crate::conditioning::IlluminationFacts::new(
            ir_stats.ambient_observed && ir_stats.ambient_mean <= crate::LOW_AMBIENT_SKIP as f32,
            ir.manifest().runtime_provenance().illumination()
                == crate::contracts::IlluminationProvenance::ActiveIr,
        ),
    )
    .map_err(|error| irlume_common::Error::Hardware(error.to_string()))
}

/// Why an observed capture cannot satisfy its immutable attempt authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CapturePlanViolation {
    /// Camera incarnation or lifecycle generation changed.
    CameraGeneration,
    /// Physical connection or endpoint context changed.
    Connection,
    /// The RGB requested or accepted stream tuple changed.
    RgbTuple,
    /// The IR requested or accepted stream tuple changed.
    IrTuple,
    /// The pair capture schedule changed.
    CaptureSchedule,
    /// Stable transport profile identity changed.
    TransportProfile,
    /// Conditioning context or selected policy changed.
    Conditioning,
    /// Conditioning catalog version changed.
    CatalogVersion,
    /// Evidence-window counts, bound, or policy version are invalid or changed.
    EvidenceWindowRules,
    /// Qualification key, producer, policy, invalidation facts, or fallback changed.
    Qualification,
    /// Canonical evidence failed delivered-rate validation.
    DeliveredRate,
    /// Canonical evidence lost stream continuity.
    Continuity,
    /// IR evidence lacks active-emitter provenance.
    ActiveIr,
    /// RGB canonical evidence contributor count changed.
    RgbManifest,
    /// IR canonical evidence contributor count changed.
    IrManifest,
    /// RGB and IR evidence windows exceed the fixed role-pair bound.
    EvidencePairWindow,
    /// Canonical preprocessing versions changed.
    Preprocessing,
    /// Cross-spectrum calibration identity changed.
    Calibration,
    /// Complete model input contracts changed.
    ModelContract,
}

/// Versioned qualification facts that do not duplicate live camera context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationAuthority {
    producer_engine_version: u32,
    policy_version: u32,
    invalidation_generation: u64,
    sequential_fallback_eligible: bool,
}

impl QualificationAuthority {
    /// Constructs nonzero producer and policy versions.
    ///
    /// # Errors
    ///
    /// Returns [`CapturePlanViolation::Qualification`] for a zero version.
    pub const fn new(
        producer_engine_version: u32,
        policy_version: u32,
        invalidation_generation: u64,
        sequential_fallback_eligible: bool,
    ) -> Result<Self, CapturePlanViolation> {
        if producer_engine_version == 0 || policy_version == 0 {
            return Err(CapturePlanViolation::Qualification);
        }
        Ok(Self {
            producer_engine_version,
            policy_version,
            invalidation_generation,
            sequential_fallback_eligible,
        })
    }

    #[must_use]
    pub const fn producer_engine_version(self) -> u32 {
        self.producer_engine_version
    }

    #[must_use]
    pub const fn policy_version(self) -> u32 {
        self.policy_version
    }

    #[must_use]
    pub const fn invalidation_generation(self) -> u64 {
        self.invalidation_generation
    }

    #[must_use]
    pub const fn sequential_fallback_eligible(self) -> bool {
        self.sequential_fallback_eligible
    }
}

/// Fixed contributor counts and role-pair timing policy for one attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceWindowRules {
    rgb_contributors: NonZeroUsize,
    ir_contributors: NonZeroUsize,
    role_pair_bound: Duration,
    version: u32,
}

impl EvidenceWindowRules {
    /// Constructs nonzero, versioned evidence-window rules.
    ///
    /// # Errors
    ///
    /// Returns [`CapturePlanViolation::EvidenceWindowRules`] for any zero field.
    pub fn new(
        rgb_contributors: usize,
        ir_contributors: usize,
        role_pair_bound: Duration,
        version: u32,
    ) -> Result<Self, CapturePlanViolation> {
        if role_pair_bound.is_zero() || version == 0 {
            return Err(CapturePlanViolation::EvidenceWindowRules);
        }
        Ok(Self {
            rgb_contributors: NonZeroUsize::new(rgb_contributors)
                .ok_or(CapturePlanViolation::EvidenceWindowRules)?,
            ir_contributors: NonZeroUsize::new(ir_contributors)
                .ok_or(CapturePlanViolation::EvidenceWindowRules)?,
            role_pair_bound,
            version,
        })
    }

    #[must_use]
    pub const fn rgb_contributors(self) -> usize {
        self.rgb_contributors.get()
    }

    #[must_use]
    pub const fn ir_contributors(self) -> usize {
        self.ir_contributors.get()
    }

    #[must_use]
    pub const fn role_pair_bound(self) -> Duration {
        self.role_pair_bound
    }

    #[must_use]
    pub const fn version(self) -> u32 {
        self.version
    }
}

/// Camera-owned immutable authority for one pair capture attempt.
#[derive(Clone, Debug)]
pub struct CameraAttemptContract {
    runtime: RuntimePairContract,
    profile: PairTransportProfile,
    conditioning_context: ConditioningContext,
    conditioning: ConditioningSelection,
    evidence_windows: EvidenceWindowRules,
    qualification: QualificationAuthority,
}

impl CameraAttemptContract {
    /// Freezes current camera-owned authority from an exact opened pair.
    ///
    /// # Errors
    ///
    /// Returns the specific violation for a non-exact tuple or invalid policy fact.
    pub fn from_runtime(
        runtime: RuntimePairContract,
        schedule: CaptureSchedule,
        sequential_fallback_eligible: bool,
    ) -> Result<Self, CapturePlanViolation> {
        let rgb = runtime
            .context()
            .rgb_stream()
            .exact_tuple()
            .ok_or(CapturePlanViolation::RgbTuple)?;
        let ir = runtime
            .context()
            .ir_stream()
            .exact_tuple()
            .ok_or(CapturePlanViolation::IrTuple)?;
        let profile_key = format!("{}:{schedule:?}", runtime.runtime_key());
        let profile = PairTransportProfile::new(
            format!(
                "attempt-{}",
                irlume_common::sha256_hex(profile_key.as_bytes())
            ),
            rgb,
            ir,
            schedule,
        )
        .map_err(|_| CapturePlanViolation::TransportProfile)?;
        let conditioning_context = ConditioningContext::new(
            runtime.rgb_binding().camera_instance_id().clone(),
            runtime.rgb_binding().generation(),
            runtime.context().rgb_endpoint().connection().clone(),
            profile.clone(),
        );
        let conditioning = crate::conditioning::current_catalog().select(
            &conditioning_context,
            std::time::Instant::now(),
            crate::conditioning::ConditioningAttempt::First,
        );
        Self::new(
            runtime,
            profile,
            conditioning_context,
            conditioning,
            EvidenceWindowRules::new(
                crate::RGB_BURST,
                crate::IR_BURST,
                EVIDENCE_PAIR_BOUND_V1,
                EVIDENCE_WINDOW_RULES_VERSION,
            )?,
            QualificationAuthority::new(
                crate::capture_qualification::PRODUCER_ENGINE_VERSION,
                crate::capture_qualification::POLICY_VERSION,
                0,
                sequential_fallback_eligible,
            )?,
        )
    }

    /// Binds one exact opened pair and all camera-owned attempt policy facts.
    ///
    /// # Errors
    ///
    /// Returns the specific violation when nested camera authority is inconsistent.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        runtime: RuntimePairContract,
        profile: PairTransportProfile,
        conditioning_context: ConditioningContext,
        conditioning: ConditioningSelection,
        evidence_windows: EvidenceWindowRules,
        qualification: QualificationAuthority,
    ) -> Result<Self, CapturePlanViolation> {
        if !runtime
            .context()
            .rgb_stream()
            .matches_exact_tuple(profile.rgb())
        {
            return Err(CapturePlanViolation::RgbTuple);
        }
        if !runtime
            .context()
            .ir_stream()
            .matches_exact_tuple(profile.ir())
        {
            return Err(CapturePlanViolation::IrTuple);
        }
        if conditioning.catalog_version() == 0 {
            return Err(CapturePlanViolation::CatalogVersion);
        }
        if conditioning_context.camera_instance_id() != runtime.rgb_binding().camera_instance_id()
            || conditioning_context.camera_generation().get() != runtime.rgb_generation()
            || conditioning_context.connection() != runtime.context().rgb_endpoint().connection()
            || conditioning_context.transport_profile() != &profile
        {
            return Err(CapturePlanViolation::Conditioning);
        }
        Ok(Self {
            runtime,
            profile,
            conditioning_context,
            conditioning,
            evidence_windows,
            qualification,
        })
    }

    #[must_use]
    pub const fn runtime(&self) -> &RuntimePairContract {
        &self.runtime
    }

    #[must_use]
    pub const fn profile(&self) -> &PairTransportProfile {
        &self.profile
    }

    #[must_use]
    pub const fn conditioning(&self) -> ConditioningSelection {
        self.conditioning
    }

    #[must_use]
    pub const fn conditioning_context(&self) -> &ConditioningContext {
        &self.conditioning_context
    }

    #[must_use]
    pub const fn evidence_windows(&self) -> EvidenceWindowRules {
        self.evidence_windows
    }

    #[must_use]
    pub const fn qualification(&self) -> QualificationAuthority {
        self.qualification
    }

    /// Validates canonical manifests before authentication constructs model inputs.
    ///
    /// # Errors
    ///
    /// Returns the first manifest, provenance, rate, continuity, or window violation.
    pub fn validate_canonical_pair(
        &self,
        rgb: &CanonicalRgbEvidence,
        ir: &CanonicalIrEvidence,
    ) -> Result<(), CapturePlanViolation> {
        self.validate_manifests(rgb, ir)
    }

    /// Validates every immutable camera-owned field against another attempt.
    ///
    /// # Errors
    ///
    /// Returns the first field-specific immutable-plan violation.
    pub fn validate_contract(&self, observed: &Self) -> Result<(), CapturePlanViolation> {
        self.validate_authority(
            &observed.runtime,
            &observed.profile,
            &observed.conditioning_context,
            observed.conditioning,
        )?;
        if self.profile.id() != observed.profile.id() {
            return Err(CapturePlanViolation::TransportProfile);
        }
        if self.evidence_windows != observed.evidence_windows {
            return Err(CapturePlanViolation::EvidenceWindowRules);
        }
        if self.qualification != observed.qualification {
            return Err(CapturePlanViolation::Qualification);
        }
        Ok(())
    }

    /// Validates camera authority and canonical manifests before minting an observation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn mint_observation(
        &self,
        observed_runtime: &RuntimePairContract,
        observed_profile: &PairTransportProfile,
        observed_conditioning_context: &ConditioningContext,
        observed_conditioning: ConditioningSelection,
        rgb: &CanonicalRgbEvidence,
        ir: &CanonicalIrEvidence,
        statistics: SceneStatistics,
    ) -> Result<SceneObservation, CapturePlanViolation> {
        self.validate_authority(
            observed_runtime,
            observed_profile,
            observed_conditioning_context,
            observed_conditioning,
        )?;
        self.validate_manifests(rgb, ir)?;
        let rgb_start = rgb.capture_window().start;
        let ir_start = ir.capture_window().start;
        Ok(SceneObservation::from_validated_attempt(
            self.conditioning_context.clone(),
            self.conditioning.catalog_version(),
            rgb_start.min(ir_start),
            statistics,
        ))
    }

    fn validate_manifests(
        &self,
        rgb: &CanonicalRgbEvidence,
        ir: &CanonicalIrEvidence,
    ) -> Result<(), CapturePlanViolation> {
        if rgb.manifest().contributor_count() != self.evidence_windows.rgb_contributors() {
            return Err(CapturePlanViolation::RgbManifest);
        }
        if ir.manifest().contributor_count() != self.evidence_windows.ir_contributors() {
            return Err(CapturePlanViolation::IrManifest);
        }
        if !self
            .runtime
            .context()
            .rgb_stream()
            .matches_runtime(rgb.manifest().runtime_provenance())
        {
            return Err(CapturePlanViolation::RgbTuple);
        }
        if !self
            .runtime
            .context()
            .ir_stream()
            .matches_runtime(ir.manifest().runtime_provenance())
        {
            return Err(CapturePlanViolation::IrTuple);
        }
        self.runtime
            .validate_canonical_pair(rgb, ir)
            .map_err(map_runtime_violation)?;
        let rgb_start = rgb.capture_window().start;
        let ir_start = ir.capture_window().start;
        let start_separation = if rgb_start <= ir_start {
            ir_start.duration_since(rgb_start)
        } else {
            rgb_start.duration_since(ir_start)
        };
        if start_separation > self.evidence_windows.role_pair_bound() {
            return Err(CapturePlanViolation::EvidencePairWindow);
        }
        Ok(())
    }

    fn validate_authority(
        &self,
        observed_runtime: &RuntimePairContract,
        observed_profile: &PairTransportProfile,
        observed_conditioning_context: &ConditioningContext,
        observed_conditioning: ConditioningSelection,
    ) -> Result<(), CapturePlanViolation> {
        if self.runtime.rgb_binding() != observed_runtime.rgb_binding()
            || self.runtime.ir_binding() != observed_runtime.ir_binding()
        {
            return Err(CapturePlanViolation::CameraGeneration);
        }
        if self.runtime.context().rgb_endpoint() != observed_runtime.context().rgb_endpoint()
            || self.runtime.context().ir_endpoint() != observed_runtime.context().ir_endpoint()
        {
            return Err(CapturePlanViolation::Connection);
        }
        if self.profile.rgb() != observed_profile.rgb()
            || self.runtime.context().rgb_stream() != observed_runtime.context().rgb_stream()
        {
            return Err(CapturePlanViolation::RgbTuple);
        }
        if self.profile.ir() != observed_profile.ir()
            || self.runtime.context().ir_stream() != observed_runtime.context().ir_stream()
        {
            return Err(CapturePlanViolation::IrTuple);
        }
        if self.profile.schedule() != observed_profile.schedule() {
            return Err(CapturePlanViolation::CaptureSchedule);
        }
        if self.runtime.runtime_key() != observed_runtime.runtime_key() {
            return Err(CapturePlanViolation::Qualification);
        }
        if self.conditioning_context != *observed_conditioning_context
            || self.conditioning.policy_id() != observed_conditioning.policy_id()
            || self.conditioning.scene() != observed_conditioning.scene()
        {
            return Err(CapturePlanViolation::Conditioning);
        }
        if self.conditioning.catalog_version() != observed_conditioning.catalog_version() {
            return Err(CapturePlanViolation::CatalogVersion);
        }
        Ok(())
    }
}

const fn map_runtime_violation(violation: RuntimePairViolation) -> CapturePlanViolation {
    match violation {
        RuntimePairViolation::CameraGeneration => CapturePlanViolation::CameraGeneration,
        RuntimePairViolation::StreamContract => CapturePlanViolation::RgbTuple,
        RuntimePairViolation::DeliveredRate => CapturePlanViolation::DeliveredRate,
        RuntimePairViolation::Continuity => CapturePlanViolation::Continuity,
        RuntimePairViolation::ActiveIr => CapturePlanViolation::ActiveIr,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CapturePlanViolation, EvidenceWindowRules, QualificationAuthority};

    #[test]
    fn external_callers_cannot_forge_camera_attempt_authority() {
        let production = include_str!("attempt_contract.rs")
            .split_once("#[cfg(test)]\nmod tests")
            .expect("test module marker remains present")
            .0;
        let constructor = production
            .split_once("impl CameraAttemptContract {")
            .and_then(|(_, implementation)| implementation.split_once("    #[must_use]"))
            .map(|(constructor, _)| constructor)
            .expect("camera attempt constructor remains before accessors");

        assert!(constructor.contains("pub(crate) fn new("));
        assert!(!constructor.contains("\n    pub fn new(\n"));
    }

    #[test]
    fn evidence_pair_bound_must_be_nonzero_and_versioned() {
        assert_eq!(
            EvidenceWindowRules::new(5, 10, Duration::ZERO, 1).unwrap_err(),
            CapturePlanViolation::EvidenceWindowRules
        );
        assert_eq!(
            EvidenceWindowRules::new(5, 10, Duration::from_millis(750), 0).unwrap_err(),
            CapturePlanViolation::EvidenceWindowRules
        );

        let rules = EvidenceWindowRules::new(5, 10, Duration::from_millis(750), 1)
            .expect("valid fixed evidence rules");
        assert_eq!(rules.rgb_contributors(), 5);
        assert_eq!(rules.ir_contributors(), 10);
        assert_eq!(rules.role_pair_bound(), Duration::from_millis(750));
        assert_eq!(rules.version(), 1);
    }

    #[test]
    fn qualification_authority_requires_versioned_producer_and_policy() {
        assert_eq!(
            QualificationAuthority::new(0, 1, 0, false).unwrap_err(),
            CapturePlanViolation::Qualification
        );
        assert_eq!(
            QualificationAuthority::new(1, 0, 0, false).unwrap_err(),
            CapturePlanViolation::Qualification
        );
        let authority = QualificationAuthority::new(2, 3, 4, true).unwrap();
        assert_eq!(authority.producer_engine_version(), 2);
        assert_eq!(authority.policy_version(), 3);
        assert_eq!(authority.invalidation_generation(), 4);
        assert!(authority.sequential_fallback_eligible());
    }
}
