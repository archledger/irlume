// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    canonical::private, CampaignError, CanonicalDocument, Identifier, SignatureMetadata,
    SignerRole, MAX_CAMPAIGN_DOCUMENT_BYTES,
};

pub const CAMPAIGN_POLICY_SCHEMA_VERSION: u32 = 1;
pub const CAMPAIGN_POLICY_VERSION: u32 = 1;
pub const ONE_SIDED_ALPHA_PPB: u64 = 50_000_000;
pub const REQUIRED_POWER_PPB: u64 = 800_000_000;
pub const OVERALL_MARGIN_PPB: i64 = -20_000_000;
pub const STRATUM_MARGIN_PPB: i64 = -50_000_000;
pub const LATENCY_BUDGET_FRACTION_PPB: u64 = 50_000_000;
pub const LATENCY_BOOTSTRAP_RESAMPLES: u32 = 10_000;
pub const MAX_PRIVATE_RETENTION_SECONDS: u64 = 31_536_000;
pub const MAX_CAPTURE_SHARD_CASES: usize = 128;
pub const MAX_ASSETS_PER_ROLE_PER_CASE: usize = 32;
pub const MAX_ASSET_BYTES: u64 = 64 * 1024 * 1024;

const NONINFERIORITY_METHOD: &str = "paired_mover_wilson_v1";
const SECURITY_BOUND_METHOD: &str = "clopper_pearson_upper_v1";
const POWER_METHOD: &str = "paired_power_normal_v1";
const LATENCY_METHOD: &str = "cluster_bootstrap_latency_v1";
const MAX_EQUIPMENT_REPEATS: u32 = 16;

pub(crate) fn parse_canonical<T>(bytes: &[u8]) -> Result<T, CampaignError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_CAMPAIGN_DOCUMENT_BYTES {
        return Err(CampaignError::DocumentTooLarge);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| CampaignError::CanonicalInvalid)?;
    let canonical = serde_json::to_vec(&value).map_err(|_| CampaignError::CanonicalInvalid)?;
    if canonical != bytes {
        return Err(CampaignError::CanonicalInvalid);
    }
    Ok(value)
}

pub(crate) fn to_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, CampaignError> {
    let bytes = serde_json::to_vec(value).map_err(|_| CampaignError::CanonicalInvalid)?;
    if bytes.len() > MAX_CAMPAIGN_DOCUMENT_BYTES {
        return Err(CampaignError::DocumentTooLarge);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    Accept,
    Reject,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationClass {
    BonaFide,
    DisplayReplay,
    NoFace,
    NonMatedLiveCrossIdentity,
    Print,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaiSpecies {
    ActiveIr,
    DisplayReplay,
    Print,
    ThreeDimensionalMask,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryGate {
    Detection,
    IrPad,
    Liveness,
    Recognition,
    RgbPad,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StratificationAxis {
    Age,
    Eyewear,
    Gender,
    Lighting,
    Range,
    SkinTone,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingnessRule {
    CountAsIncorrect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalRule {
    InvalidateBeforePublicationDeleteAfterPublication,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoppingRule {
    LockedSampleNoOptionalStopping,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StratificationRule {
    axis: StratificationAxis,
    categories: Vec<Identifier>,
    minimum_cases: u32,
}

impl StratificationRule {
    fn validate(&self) -> Result<(), CampaignError> {
        if self.minimum_cases == 0 || !strictly_sorted(&self.categories) {
            return Err(CampaignError::PolicyUnsupported);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpiryRules {
    artifact_seconds: u64,
    bundle_seconds: u64,
    protocol_seconds: u64,
    result_seconds: u64,
    review_seconds: u64,
}

impl ExpiryRules {
    fn validate(&self) -> Result<(), CampaignError> {
        if self.artifact_seconds == 0
            || self.bundle_seconds == 0
            || self.protocol_seconds == 0
            || self.result_seconds == 0
            || self.review_seconds == 0
            || self.artifact_seconds > MAX_PRIVATE_RETENTION_SECONDS
            || self.bundle_seconds > MAX_PRIVATE_RETENTION_SECONDS
            || self.protocol_seconds > MAX_PRIVATE_RETENTION_SECONDS
            || self.result_seconds > MAX_PRIVATE_RETENTION_SECONDS
            || self.review_seconds > self.result_seconds
        {
            return Err(CampaignError::PolicyUnsupported);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignPolicy {
    allowed_equipment_repeats: u32,
    binary_gates: Vec<BinaryGate>,
    demographic_axes: Vec<StratificationRule>,
    excluded_pai_species: Vec<PaiSpecies>,
    expiry_rules: ExpiryRules,
    latency_bootstrap_resamples: u32,
    latency_budget_fraction_ppb: u64,
    latency_method: Identifier,
    minimum_public_cell_size: u32,
    missingness_rule: MissingnessRule,
    noninferiority_method: Identifier,
    one_sided_alpha_ppb: u64,
    operational_axes: Vec<StratificationRule>,
    overall_margin_ppb: i64,
    paired_crossover: bool,
    permitted_hardware_classes: Vec<Identifier>,
    policy_id: Identifier,
    policy_version: u32,
    power_method: Identifier,
    presentation_classes: Vec<PresentationClass>,
    private_asset_retention_seconds: u64,
    required_pai_species: Vec<PaiSpecies>,
    required_power_ppb: u64,
    role_separation_required: bool,
    schema_version: u32,
    security_bound_method: Identifier,
    signature: SignatureMetadata,
    stopping_rule: StoppingRule,
    stratum_margin_ppb: i64,
    target_population: Identifier,
    withdrawal_rule: WithdrawalRule,
}

impl CampaignPolicy {
    fn validate(&self) -> Result<(), CampaignError> {
        if self.schema_version != CAMPAIGN_POLICY_SCHEMA_VERSION
            || self.policy_version != CAMPAIGN_POLICY_VERSION
            || self.binary_gates
                != [
                    BinaryGate::Detection,
                    BinaryGate::IrPad,
                    BinaryGate::Liveness,
                    BinaryGate::Recognition,
                    BinaryGate::RgbPad,
                ]
            || self.presentation_classes
                != [
                    PresentationClass::BonaFide,
                    PresentationClass::DisplayReplay,
                    PresentationClass::NoFace,
                    PresentationClass::NonMatedLiveCrossIdentity,
                    PresentationClass::Print,
                ]
            || self.required_pai_species != [PaiSpecies::DisplayReplay, PaiSpecies::Print]
            || self.excluded_pai_species != [PaiSpecies::ActiveIr, PaiSpecies::ThreeDimensionalMask]
            || self.one_sided_alpha_ppb != ONE_SIDED_ALPHA_PPB
            || self.required_power_ppb != REQUIRED_POWER_PPB
            || self.overall_margin_ppb != OVERALL_MARGIN_PPB
            || self.stratum_margin_ppb != STRATUM_MARGIN_PPB
            || self.latency_budget_fraction_ppb != LATENCY_BUDGET_FRACTION_PPB
            || self.latency_bootstrap_resamples != LATENCY_BOOTSTRAP_RESAMPLES
            || self.noninferiority_method.as_str() != NONINFERIORITY_METHOD
            || self.security_bound_method.as_str() != SECURITY_BOUND_METHOD
            || self.power_method.as_str() != POWER_METHOD
            || self.latency_method.as_str() != LATENCY_METHOD
            || !self.paired_crossover
            || !self.role_separation_required
            || self.permitted_hardware_classes.is_empty()
            || !strictly_sorted(&self.permitted_hardware_classes)
            || self.allowed_equipment_repeats == 0
            || self.allowed_equipment_repeats > MAX_EQUIPMENT_REPEATS
            || self.minimum_public_cell_size == 0
            || self.private_asset_retention_seconds == 0
            || self.private_asset_retention_seconds > MAX_PRIVATE_RETENTION_SECONDS
            || self.signature.role() != SignerRole::PolicyAuthor
        {
            return Err(CampaignError::PolicyUnsupported);
        }
        validate_axes(
            &self.demographic_axes,
            &[
                StratificationAxis::Age,
                StratificationAxis::Gender,
                StratificationAxis::SkinTone,
            ],
        )?;
        validate_axes(
            &self.operational_axes,
            &[
                StratificationAxis::Eyewear,
                StratificationAxis::Lighting,
                StratificationAxis::Range,
            ],
        )?;
        self.expiry_rules.validate()
    }

    #[must_use]
    pub fn policy_id(&self) -> &Identifier {
        &self.policy_id
    }

    #[must_use]
    pub const fn private_asset_retention_seconds(&self) -> u64 {
        self.private_asset_retention_seconds
    }

    pub(crate) fn protocol_expiry_seconds(&self) -> u64 {
        self.expiry_rules.protocol_seconds
    }

    pub(crate) fn permits_hardware_class(&self, hardware_class: &Identifier) -> bool {
        self.permitted_hardware_classes
            .binary_search(hardware_class)
            .is_ok()
    }

    pub(crate) const fn allowed_equipment_repeats(&self) -> u32 {
        self.allowed_equipment_repeats
    }

    pub(crate) fn stratum_minimum(
        &self,
        axis: StratificationAxis,
        category: &Identifier,
    ) -> Option<u32> {
        self.demographic_axes
            .iter()
            .chain(&self.operational_axes)
            .find(|rule| rule.axis == axis && rule.categories.binary_search(category).is_ok())
            .map(|rule| rule.minimum_cases)
    }

    pub(crate) fn stratum_count(&self) -> usize {
        self.demographic_axes
            .iter()
            .chain(&self.operational_axes)
            .map(|rule| rule.categories.len())
            .sum()
    }
}

impl private::Sealed for CampaignPolicy {}

impl CanonicalDocument for CampaignPolicy {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
        let policy: Self = parse_canonical(bytes)?;
        policy.validate()?;
        Ok(policy)
    }

    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError> {
        self.validate()?;
        to_canonical(self)
    }

    fn signature_metadata(&self) -> &SignatureMetadata {
        &self.signature
    }
}

fn validate_axes(
    rules: &[StratificationRule],
    required: &[StratificationAxis],
) -> Result<(), CampaignError> {
    if rules.len() != required.len()
        || !rules
            .iter()
            .zip(required)
            .all(|(rule, axis)| rule.axis == *axis && rule.validate().is_ok())
    {
        return Err(CampaignError::PolicyUnsupported);
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::{CampaignError, CanonicalDocument};

    pub(crate) fn policy_value() -> Value {
        json!({
            "allowed_equipment_repeats": 2,
            "binary_gates": ["detection", "ir_pad", "liveness", "recognition", "rgb_pad"],
            "demographic_axes": [
                {"axis": "age", "categories": ["adult", "older_adult"], "minimum_cases": 40},
                {"axis": "gender", "categories": ["female", "male", "nonbinary"], "minimum_cases": 40},
                {"axis": "skin_tone", "categories": ["dark", "light", "medium"], "minimum_cases": 40}
            ],
            "excluded_pai_species": ["active_ir", "three_dimensional_mask"],
            "expiry_rules": {
                "artifact_seconds": 31536000,
                "bundle_seconds": 2592000,
                "protocol_seconds": 2592000,
                "result_seconds": 2592000,
                "review_seconds": 604800
            },
            "latency_bootstrap_resamples": 10000,
            "latency_budget_fraction_ppb": 50000000,
            "latency_method": "cluster_bootstrap_latency_v1",
            "minimum_public_cell_size": 20,
            "missingness_rule": "count_as_incorrect",
            "noninferiority_method": "paired_mover_wilson_v1",
            "one_sided_alpha_ppb": 50000000,
            "operational_axes": [
                {"axis": "eyewear", "categories": ["absent", "present"], "minimum_cases": 40},
                {"axis": "lighting", "categories": ["dim", "ordinary"], "minimum_cases": 40},
                {"axis": "range", "categories": ["near", "ordinary"], "minimum_cases": 40}
            ],
            "overall_margin_ppb": -20000000,
            "paired_crossover": true,
            "permitted_hardware_classes": ["usb-rgb-ir-v1"],
            "policy_id": "maintainer-camera-profile-v1",
            "policy_version": 1,
            "power_method": "paired_power_normal_v1",
            "presentation_classes": ["bona_fide", "display_replay", "no_face", "non_mated_live_cross_identity", "print"],
            "private_asset_retention_seconds": 31536000,
            "required_pai_species": ["display_replay", "print"],
            "required_power_ppb": 800000000,
            "role_separation_required": true,
            "schema_version": 1,
            "security_bound_method": "clopper_pearson_upper_v1",
            "signature": {
                "algorithm": "open_pgp",
                "role": "policy_author",
                "signer_fingerprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            },
            "stopping_rule": "locked_sample_no_optional_stopping",
            "stratum_margin_ppb": -50000000,
            "target_population": "consenting-adults-in-declared-operating-range",
            "withdrawal_rule": "invalidate_before_publication_delete_after_publication"
        })
    }

    fn canonical(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    fn parse(value: &Value) -> Result<CampaignPolicy, CampaignError> {
        CampaignPolicy::from_canonical_json(&canonical(value))
    }

    #[test]
    fn policy_v1_accepts_only_frozen_methods_and_lifecycle_rules() {
        assert!(parse(&policy_value()).is_ok());

        for (field, replacement) in [
            ("schema_version", json!(2)),
            ("policy_version", json!(2)),
            ("noninferiority_method", json!("another_method")),
            ("security_bound_method", json!("another_method")),
            ("power_method", json!("another_method")),
            ("latency_method", json!("another_method")),
            ("one_sided_alpha_ppb", json!(50000001)),
            ("required_power_ppb", json!(799999999)),
            ("overall_margin_ppb", json!(-20000001)),
            ("stratum_margin_ppb", json!(-50000001)),
            ("latency_budget_fraction_ppb", json!(50000001)),
            ("latency_bootstrap_resamples", json!(9999)),
            ("paired_crossover", json!(false)),
            ("role_separation_required", json!(false)),
        ] {
            let mut value = policy_value();
            value[field] = replacement;
            assert_eq!(
                parse(&value),
                Err(CampaignError::PolicyUnsupported),
                "{field}"
            );
        }
        for (field, replacement) in [
            ("missingness_rule", json!("drop_from_denominator")),
            ("withdrawal_rule", json!("retract_publication")),
            ("stopping_rule", json!("stop_when_passing")),
        ] {
            let mut value = policy_value();
            value[field] = replacement;
            assert_eq!(
                parse(&value),
                Err(CampaignError::CanonicalInvalid),
                "{field}"
            );
        }
    }

    #[test]
    fn policy_v1_requires_every_gate_attack_and_stratification_axis() {
        let mut without_hardware_class = policy_value();
        without_hardware_class["permitted_hardware_classes"] = json!([]);
        assert_eq!(
            parse(&without_hardware_class),
            Err(CampaignError::PolicyUnsupported)
        );

        for (field, required) in [
            ("binary_gates", "detection"),
            ("binary_gates", "ir_pad"),
            ("binary_gates", "liveness"),
            ("binary_gates", "recognition"),
            ("binary_gates", "rgb_pad"),
            ("presentation_classes", "bona_fide"),
            ("presentation_classes", "no_face"),
            ("presentation_classes", "non_mated_live_cross_identity"),
            ("presentation_classes", "print"),
            ("presentation_classes", "display_replay"),
            ("required_pai_species", "print"),
            ("required_pai_species", "display_replay"),
        ] {
            let mut value = policy_value();
            value[field]
                .as_array_mut()
                .unwrap()
                .retain(|entry| entry != required);
            assert_eq!(
                parse(&value),
                Err(CampaignError::PolicyUnsupported),
                "{field}:{required}"
            );
        }

        for (field, required) in [
            ("demographic_axes", "age"),
            ("demographic_axes", "gender"),
            ("demographic_axes", "skin_tone"),
            ("operational_axes", "eyewear"),
            ("operational_axes", "lighting"),
            ("operational_axes", "range"),
        ] {
            let mut value = policy_value();
            value[field]
                .as_array_mut()
                .unwrap()
                .retain(|entry| entry["axis"] != required);
            assert_eq!(
                parse(&value),
                Err(CampaignError::PolicyUnsupported),
                "{field}:{required}"
            );
        }
    }

    #[test]
    fn policy_v1_rejects_unsafe_bounds_duplicates_reordering_and_unknown_fields() {
        for (field, replacement) in [
            ("minimum_public_cell_size", json!(0)),
            ("allowed_equipment_repeats", json!(0)),
            ("allowed_equipment_repeats", json!(17)),
            ("private_asset_retention_seconds", json!(31536001)),
        ] {
            let mut value = policy_value();
            value[field] = replacement;
            assert_eq!(
                parse(&value),
                Err(CampaignError::PolicyUnsupported),
                "{field}"
            );
        }

        for field in [
            "binary_gates",
            "required_pai_species",
            "presentation_classes",
        ] {
            let mut duplicate = policy_value();
            let entries = duplicate[field].as_array_mut().unwrap();
            entries.insert(1, entries[0].clone());
            assert_eq!(
                parse(&duplicate),
                Err(CampaignError::PolicyUnsupported),
                "duplicate {field}"
            );

            let mut reordered = policy_value();
            reordered[field].as_array_mut().unwrap().swap(0, 1);
            assert_eq!(
                parse(&reordered),
                Err(CampaignError::PolicyUnsupported),
                "reordered {field}"
            );
        }

        let mut duplicate_category = policy_value();
        duplicate_category["demographic_axes"][0]["categories"] = json!(["adult", "adult"]);
        assert_eq!(
            parse(&duplicate_category),
            Err(CampaignError::PolicyUnsupported)
        );

        let mut reordered_category = policy_value();
        reordered_category["demographic_axes"][0]["categories"] = json!(["older_adult", "adult"]);
        assert_eq!(
            parse(&reordered_category),
            Err(CampaignError::PolicyUnsupported)
        );

        let mut reordered_axes = policy_value();
        reordered_axes["demographic_axes"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert_eq!(
            parse(&reordered_axes),
            Err(CampaignError::PolicyUnsupported)
        );

        for field in [
            "artifact_seconds",
            "bundle_seconds",
            "protocol_seconds",
            "result_seconds",
        ] {
            let mut expiry = policy_value();
            expiry["expiry_rules"][field] = json!(31536001);
            assert_eq!(
                parse(&expiry),
                Err(CampaignError::PolicyUnsupported),
                "{field}"
            );
        }
        let mut review_expiry = policy_value();
        review_expiry["expiry_rules"]["review_seconds"] = json!(2592001);
        assert_eq!(parse(&review_expiry), Err(CampaignError::PolicyUnsupported));

        let mut wrong_signature_role = policy_value();
        wrong_signature_role["signature"]["role"] = json!("operator");
        assert_eq!(
            parse(&wrong_signature_role),
            Err(CampaignError::PolicyUnsupported)
        );

        let mut unknown = policy_value();
        unknown["operator_override"] = json!(true);
        assert_eq!(parse(&unknown), Err(CampaignError::CanonicalInvalid));

        let bytes = canonical(&policy_value());
        assert_eq!(
            CampaignPolicy::from_canonical_json(
                &serde_json::to_vec_pretty(&policy_value()).unwrap()
            ),
            Err(CampaignError::CanonicalInvalid)
        );
        let mut trailing = bytes;
        trailing.push(b'\n');
        assert_eq!(
            CampaignPolicy::from_canonical_json(&trailing),
            Err(CampaignError::CanonicalInvalid)
        );
        assert_eq!(
            CampaignPolicy::from_canonical_json(&vec![b' '; MAX_CAMPAIGN_DOCUMENT_BYTES + 1]),
            Err(CampaignError::DocumentTooLarge)
        );
    }
}
