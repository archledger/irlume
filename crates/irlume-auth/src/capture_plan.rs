// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Authentication-owned composition of camera and model attempt authority.

use irlume_camera::attempt_contract::{CameraAttemptContract, CapturePlanViolation};
use irlume_vision::model_input::ModelContractSet;

fn validate_model_contract_ids(
    expected: &[irlume_vision::model_input::ModelInputContractId],
    observed: &[irlume_vision::model_input::ModelInputContractId],
) -> Result<(), CapturePlanViolation> {
    if expected != observed {
        return Err(CapturePlanViolation::ModelContract);
    }
    Ok(())
}

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

    /// Refuses camera, preprocessing, calibration, or model drift.
    ///
    /// # Errors
    ///
    /// Returns the first field-specific immutable-plan violation.
    pub fn validate(&self, observed: &Self) -> Result<(), CapturePlanViolation> {
        self.camera.validate_contract(&observed.camera)?;
        self.versions.validate(&observed.versions)?;
        validate_model_contract_ids(self.model_contracts.ids(), observed.model_contracts.ids())
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
    use super::{AttemptCapturePlan, AttemptPlanVersions};

    #[test]
    fn changed_model_contract_invalidates_the_attempt_plan() {
        let expected = irlume_vision::model_input::ModelContractSet::production_v1().ids();
        let mut observed = expected.to_vec();
        observed[3] = irlume_vision::model_input::ModelInputContractId::ArcFace112RgbV1;

        assert_eq!(
            super::validate_model_contract_ids(expected, &observed),
            Err(irlume_camera::attempt_contract::CapturePlanViolation::ModelContract)
        );
    }

    #[test]
    fn authentication_does_not_validate_a_plan_against_itself() {
        let production = include_str!("lib.rs");
        let forbidden = ["validate_canonical_pair(", "plan,"].concat();

        assert!(!production.contains(&forbidden));
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
