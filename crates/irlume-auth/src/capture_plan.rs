// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Authentication-owned composition of camera and model attempt authority.

use irlume_camera::attempt_contract::{CameraAttemptContract, CapturePlanViolation};
use irlume_vision::model_input::ModelContractSet;

/// Immutable preprocessing and calibration identifiers for one attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptPlanVersions {
    calibration_id: String,
    rgb_preprocessing: String,
    ir_preprocessing: String,
}

impl AttemptPlanVersions {
    /// Constructs bounded nonempty version identifiers.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or control-bearing identifier.
    pub fn new(
        calibration_id: impl Into<String>,
        rgb_preprocessing: impl Into<String>,
        ir_preprocessing: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let value = Self {
            calibration_id: calibration_id.into(),
            rgb_preprocessing: rgb_preprocessing.into(),
            ir_preprocessing: ir_preprocessing.into(),
        };
        if [
            value.calibration_id.as_str(),
            value.rgb_preprocessing.as_str(),
            value.ir_preprocessing.as_str(),
        ]
        .iter()
        .any(|field| field.is_empty() || field.len() > 256 || field.chars().any(char::is_control))
        {
            return Err("invalid attempt plan version");
        }
        Ok(value)
    }

    #[must_use]
    pub fn calibration_id(&self) -> &str {
        &self.calibration_id
    }

    #[must_use]
    pub fn rgb_preprocessing(&self) -> &str {
        &self.rgb_preprocessing
    }

    #[must_use]
    pub fn ir_preprocessing(&self) -> &str {
        &self.ir_preprocessing
    }

    fn validate(&self, observed: &Self) -> Result<(), CapturePlanViolation> {
        if self.calibration_id != observed.calibration_id {
            return Err(CapturePlanViolation::Calibration);
        }
        if self.rgb_preprocessing != observed.rgb_preprocessing
            || self.ir_preprocessing != observed.ir_preprocessing
        {
            return Err(CapturePlanViolation::Preprocessing);
        }
        Ok(())
    }
}

/// Frozen producer authority expected by one authentication attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InferenceAuthority {
    versions: AttemptPlanVersions,
    model_contracts: ModelContractSet,
}

/// Independently reconstructed producer authority at the pre-input boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedInferenceAuthority {
    versions: AttemptPlanVersions,
    model_contracts: ModelContractSet,
}

impl InferenceAuthority {
    #[must_use]
    pub const fn new(versions: AttemptPlanVersions, model_contracts: ModelContractSet) -> Self {
        Self {
            versions,
            model_contracts,
        }
    }

    #[must_use]
    pub const fn observed(
        versions: AttemptPlanVersions,
        model_contracts: ModelContractSet,
    ) -> ObservedInferenceAuthority {
        ObservedInferenceAuthority {
            versions,
            model_contracts,
        }
    }

    /// Refuses independently observed producer drift before typed input construction.
    ///
    /// # Errors
    ///
    /// Returns the first field-specific authority violation.
    pub fn validate_observed(
        &self,
        observed: &ObservedInferenceAuthority,
    ) -> Result<(), CapturePlanViolation> {
        self.versions.validate(&observed.versions)?;
        if self.model_contracts != observed.model_contracts {
            return Err(CapturePlanViolation::ModelContract);
        }
        Ok(())
    }

    #[cfg(test)]
    fn observed_with_versions_for_test(
        &self,
        versions: AttemptPlanVersions,
    ) -> ObservedInferenceAuthority {
        Self::observed(versions, self.model_contracts)
    }

    #[cfg(test)]
    fn observed_with_model_for_test(
        &self,
        index: usize,
        model: Option<irlume_vision::model_input::ModelInputContractId>,
    ) -> ObservedInferenceAuthority {
        let mut slots = self.model_contracts.slots();
        slots[index] = model;
        Self::observed(self.versions.clone(), ModelContractSet::from_slots(slots))
    }
}

/// Authentication-owned composition of camera, preprocessing, and model authority.
#[derive(Clone, Debug)]
pub struct AttemptCapturePlan {
    camera: CameraAttemptContract,
    versions: AttemptPlanVersions,
    model_contracts: ModelContractSet,
}

impl AttemptCapturePlan {
    /// Composes camera authority with canonical preprocessing and model contracts.
    #[must_use]
    pub const fn new(
        camera: CameraAttemptContract,
        versions: AttemptPlanVersions,
        model_contracts: ModelContractSet,
    ) -> Self {
        Self {
            camera,
            versions,
            model_contracts,
        }
    }

    #[must_use]
    pub const fn camera(&self) -> &CameraAttemptContract {
        &self.camera
    }

    #[must_use]
    pub const fn versions(&self) -> &AttemptPlanVersions {
        &self.versions
    }

    #[must_use]
    pub const fn model_contracts(&self) -> ModelContractSet {
        self.model_contracts
    }

    #[must_use]
    pub fn inference_authority(&self) -> InferenceAuthority {
        InferenceAuthority::new(self.versions.clone(), self.model_contracts)
    }

    /// Refuses camera, preprocessing, calibration, or model drift.
    ///
    /// # Errors
    ///
    /// Returns the first field-specific immutable-plan violation.
    pub fn validate(&self, observed: &Self) -> Result<(), CapturePlanViolation> {
        self.camera.validate_contract(&observed.camera)?;
        self.inference_authority()
            .validate_observed(&InferenceAuthority::observed(
                observed.versions.clone(),
                observed.model_contracts,
            ))
    }

    /// Validates both immutable layers and canonical camera manifests.
    ///
    /// # Errors
    ///
    /// Returns the first composite-plan or canonical-manifest violation.
    pub fn validate_canonical_pair(
        &self,
        observed: &Self,
        rgb: &irlume_camera::CanonicalRgbEvidence,
        ir: &irlume_camera::CanonicalIrEvidence,
    ) -> Result<(), CapturePlanViolation> {
        self.validate(observed)?;
        self.camera.validate_canonical_pair(rgb, ir)
    }
}

#[cfg(test)]
mod tests {
    use super::{AttemptCapturePlan, AttemptPlanVersions, InferenceAuthority};

    fn authority() -> InferenceAuthority {
        InferenceAuthority::new(
            AttemptPlanVersions::new(
                "uncalibrated-cross-spectrum-v1",
                "canonical-rgb8-v1",
                "canonical-grey8-v1",
            )
            .unwrap(),
            irlume_vision::model_input::ModelContractSet::production_v1(),
        )
    }

    #[test]
    fn independently_observed_model_drift_fails_at_the_pre_input_seam() {
        let expected = authority();
        let observed = expected.observed_with_model_for_test(
            3,
            Some(irlume_vision::model_input::ModelInputContractId::ArcFace112RgbV1),
        );
        assert_eq!(
            expected.validate_observed(&observed),
            Err(irlume_camera::attempt_contract::CapturePlanViolation::ModelContract)
        );
    }

    #[test]
    fn independently_observed_preprocessing_and_calibration_drift_fail_at_the_pre_input_seam() {
        let expected = authority();
        let calibration = expected.observed_with_versions_for_test(
            AttemptPlanVersions::new(
                "different-calibration",
                "canonical-rgb8-v1",
                "canonical-grey8-v1",
            )
            .unwrap(),
        );
        let rgb_preprocessing = expected.observed_with_versions_for_test(
            AttemptPlanVersions::new(
                "uncalibrated-cross-spectrum-v1",
                "different-rgb-preprocessing",
                "canonical-grey8-v1",
            )
            .unwrap(),
        );
        let ir_preprocessing = expected.observed_with_versions_for_test(
            AttemptPlanVersions::new(
                "uncalibrated-cross-spectrum-v1",
                "canonical-rgb8-v1",
                "different-ir-preprocessing",
            )
            .unwrap(),
        );

        assert_eq!(
            expected.validate_observed(&calibration),
            Err(irlume_camera::attempt_contract::CapturePlanViolation::Calibration)
        );
        assert_eq!(
            expected.validate_observed(&rgb_preprocessing),
            Err(irlume_camera::attempt_contract::CapturePlanViolation::Preprocessing)
        );
        assert_eq!(
            expected.validate_observed(&ir_preprocessing),
            Err(irlume_camera::attempt_contract::CapturePlanViolation::Preprocessing)
        );
    }

    #[test]
    fn plan_versions_reject_empty_preprocessing_or_calibration_identity() {
        assert!(AttemptPlanVersions::new("", "rgb-v1", "ir-v1").is_err());
        assert!(AttemptPlanVersions::new("cal-v1", "", "ir-v1").is_err());
        assert!(AttemptPlanVersions::new("cal-v1", "rgb-v1", "").is_err());
    }

    #[test]
    fn changed_calibration_and_preprocessing_have_specific_violations() {
        let expected = AttemptPlanVersions::new("cal-v1", "rgb-v1", "ir-v1").unwrap();
        let calibration = AttemptPlanVersions::new("cal-v2", "rgb-v1", "ir-v1").unwrap();
        let preprocessing = AttemptPlanVersions::new("cal-v1", "rgb-v2", "ir-v1").unwrap();
        assert_eq!(
            expected.validate(&calibration),
            Err(irlume_camera::attempt_contract::CapturePlanViolation::Calibration)
        );
        assert_eq!(
            expected.validate(&preprocessing),
            Err(irlume_camera::attempt_contract::CapturePlanViolation::Preprocessing)
        );
    }

    #[test]
    fn attempt_capture_plan_is_an_immutable_composition_type() {
        fn accepts_plan(_: &AttemptCapturePlan) {}
        let _ = accepts_plan;
    }
}
