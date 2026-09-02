// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Non-biometric local commissioning evidence for camera profiles.

#![allow(
    dead_code,
    reason = "selection consumes validated commissioning evidence in the next plan task"
)]

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    capture_qualification::QualificationContext,
    profile::{CaptureSchedule, PairTransportProfile},
    release_qualification::ReleaseHardwareScope,
};

const LOCAL_COMMISSIONING_SCHEMA_VERSION: u32 = 1;
const LOCAL_COMMISSIONING_POLICY_VERSION: u32 = 1;
const LOCAL_COMMISSIONING_PRODUCER_VERSION: u32 = 1;
const MAX_LOCAL_COMMISSIONING_BYTES: usize = 256 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProfileCommissioningError {
    UnsupportedSchema(u32),
    UnsupportedPolicy(u32),
    UnsupportedProducer(u32),
    InvalidIdentifier,
    InvalidDigest,
    InvalidTime,
    InvalidContext,
    InvalidLatency,
    LocalGateFailed,
    NotYetValid,
    Stale,
    ContextMismatch,
    HardwareScopeMismatch,
    ProfileMismatch,
    ConditioningMismatch,
    DocumentTooLarge,
    Json,
}

impl fmt::Display for ProfileCommissioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema(version) => {
                write!(
                    formatter,
                    "unsupported local commissioning schema {version}"
                )
            }
            Self::UnsupportedPolicy(version) => {
                write!(
                    formatter,
                    "unsupported local commissioning policy {version}"
                )
            }
            Self::UnsupportedProducer(version) => {
                write!(
                    formatter,
                    "unsupported local commissioning producer {version}"
                )
            }
            Self::InvalidIdentifier => formatter.write_str("invalid commissioning identifier"),
            Self::InvalidDigest => formatter.write_str("invalid commissioning digest"),
            Self::InvalidTime => formatter.write_str("invalid commissioning time interval"),
            Self::InvalidContext => formatter.write_str("invalid commissioning context"),
            Self::InvalidLatency => formatter.write_str("invalid commissioning latency"),
            Self::LocalGateFailed => formatter.write_str("local commissioning gate failed"),
            Self::NotYetValid => formatter.write_str("local commissioning is not yet valid"),
            Self::Stale => formatter.write_str("local commissioning is stale"),
            Self::ContextMismatch => formatter.write_str("local commissioning context changed"),
            Self::HardwareScopeMismatch => {
                formatter.write_str("local commissioning hardware scope changed")
            }
            Self::ProfileMismatch => formatter.write_str("local commissioning profile changed"),
            Self::ConditioningMismatch => {
                formatter.write_str("local commissioning conditioning changed")
            }
            Self::DocumentTooLarge => {
                formatter.write_str("local commissioning document exceeds its size limit")
            }
            Self::Json => formatter.write_str("invalid local commissioning JSON"),
        }
    }
}

impl std::error::Error for ProfileCommissioningError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalCommissioningGates {
    negotiation_passed: bool,
    transport_passed: bool,
    continuity_passed: bool,
    signal_sanity_passed: bool,
    conditioning_applied: bool,
    restoration_exact: bool,
    runtime_degradation_compatible: bool,
    p50_latency_ms: u64,
    p95_latency_ms: u64,
    latency_budget_ms: u64,
}

impl LocalCommissioningGates {
    fn validate(&self) -> Result<(), ProfileCommissioningError> {
        if [
            self.negotiation_passed,
            self.transport_passed,
            self.continuity_passed,
            self.signal_sanity_passed,
            self.conditioning_applied,
            self.restoration_exact,
            self.runtime_degradation_compatible,
        ]
        .into_iter()
        .all(|gate| gate)
        {
            if self.p50_latency_ms > 0
                && self.p50_latency_ms <= self.p95_latency_ms
                && self.p95_latency_ms <= self.latency_budget_ms
            {
                Ok(())
            } else {
                Err(ProfileCommissioningError::InvalidLatency)
            }
        } else {
            Err(ProfileCommissioningError::LocalGateFailed)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalCommissioningRecord {
    schema_version: u32,
    policy_version: u32,
    producer_version: u32,
    measured_at_unix: u64,
    expires_at_unix: u64,
    profile_id: String,
    context: QualificationContext,
    schedule: CaptureSchedule,
    conditioning_catalog_sha256: String,
    selected_policy_sha256: String,
    interface_layout_sha256: String,
    gates: LocalCommissioningGates,
}

impl LocalCommissioningRecord {
    pub(crate) fn from_canonical_json(bytes: &[u8]) -> Result<Self, ProfileCommissioningError> {
        if bytes.len() > MAX_LOCAL_COMMISSIONING_BYTES {
            return Err(ProfileCommissioningError::DocumentTooLarge);
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| ProfileCommissioningError::Json)?;
        record.validate_structure()?;
        if serde_json::to_vec(&record).map_err(|_| ProfileCommissioningError::Json)? != bytes {
            return Err(ProfileCommissioningError::Json);
        }
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_for(
        &self,
        release_scope: &ReleaseHardwareScope,
        candidate: &PairTransportProfile,
        current_context: &QualificationContext,
        expected_conditioning_catalog_sha256: &str,
        expected_selected_policy_sha256: &str,
        now_unix: u64,
    ) -> Result<ValidatedLocalCommissioning, ProfileCommissioningError> {
        self.validate_structure()?;
        if now_unix < self.measured_at_unix {
            return Err(ProfileCommissioningError::NotYetValid);
        }
        if now_unix >= self.expires_at_unix {
            return Err(ProfileCommissioningError::Stale);
        }
        current_context
            .validate()
            .map_err(|_| ProfileCommissioningError::InvalidContext)?;
        if self.context != *current_context {
            return Err(ProfileCommissioningError::ContextMismatch);
        }

        let profile = self.to_profile()?;
        if profile != *candidate {
            return Err(ProfileCommissioningError::ProfileMismatch);
        }
        if !release_scope.matches_context(&self.context, &self.interface_layout_sha256) {
            return Err(ProfileCommissioningError::HardwareScopeMismatch);
        }
        if self.conditioning_catalog_sha256 != expected_conditioning_catalog_sha256
            || self.selected_policy_sha256 != expected_selected_policy_sha256
        {
            return Err(ProfileCommissioningError::ConditioningMismatch);
        }

        let canonical = serde_json::to_vec(self).map_err(|_| ProfileCommissioningError::Json)?;
        Ok(ValidatedLocalCommissioning {
            profile,
            context: self.context.clone(),
            conditioning_catalog_sha256: self.conditioning_catalog_sha256.clone(),
            selected_policy_sha256: self.selected_policy_sha256.clone(),
            interface_layout_sha256: self.interface_layout_sha256.clone(),
            measured_at_unix: self.measured_at_unix,
            p50_latency_ms: self.gates.p50_latency_ms,
            p95_latency_ms: self.gates.p95_latency_ms,
            record_sha256: irlume_common::sha256_hex(&canonical),
        })
    }

    fn validate_structure(&self) -> Result<(), ProfileCommissioningError> {
        if self.schema_version != LOCAL_COMMISSIONING_SCHEMA_VERSION {
            return Err(ProfileCommissioningError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.policy_version != LOCAL_COMMISSIONING_POLICY_VERSION {
            return Err(ProfileCommissioningError::UnsupportedPolicy(
                self.policy_version,
            ));
        }
        if self.producer_version != LOCAL_COMMISSIONING_PRODUCER_VERSION {
            return Err(ProfileCommissioningError::UnsupportedProducer(
                self.producer_version,
            ));
        }
        validate_identifier(&self.profile_id)?;
        validate_digest(&self.interface_layout_sha256)?;
        validate_digest(&self.conditioning_catalog_sha256)?;
        validate_digest(&self.selected_policy_sha256)?;
        if self.measured_at_unix == 0
            || self.expires_at_unix == 0
            || self.measured_at_unix >= self.expires_at_unix
        {
            return Err(ProfileCommissioningError::InvalidTime);
        }
        self.context
            .validate()
            .map_err(|_| ProfileCommissioningError::InvalidContext)?;
        self.gates.validate()
    }

    fn to_profile(&self) -> Result<PairTransportProfile, ProfileCommissioningError> {
        PairTransportProfile::from_negotiated(
            self.profile_id.clone(),
            self.context
                .rgb_stream()
                .requested_tuple()
                .ok_or(ProfileCommissioningError::InvalidContext)?,
            self.context
                .rgb_stream()
                .accepted_tuple()
                .ok_or(ProfileCommissioningError::InvalidContext)?,
            self.context
                .ir_stream()
                .requested_tuple()
                .ok_or(ProfileCommissioningError::InvalidContext)?,
            self.context
                .ir_stream()
                .accepted_tuple()
                .ok_or(ProfileCommissioningError::InvalidContext)?,
            self.schedule,
        )
        .map_err(|_| ProfileCommissioningError::InvalidContext)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedLocalCommissioning {
    profile: PairTransportProfile,
    context: QualificationContext,
    conditioning_catalog_sha256: String,
    selected_policy_sha256: String,
    interface_layout_sha256: String,
    measured_at_unix: u64,
    p50_latency_ms: u64,
    p95_latency_ms: u64,
    record_sha256: String,
}

impl ValidatedLocalCommissioning {
    pub(crate) const fn profile(&self) -> &PairTransportProfile {
        &self.profile
    }

    pub(crate) fn profile_id(&self) -> &str {
        self.profile.id()
    }

    pub(crate) const fn context(&self) -> &QualificationContext {
        &self.context
    }

    pub(crate) const fn p95_latency_ms(&self) -> u64 {
        self.p95_latency_ms
    }

    pub(crate) const fn p50_latency_ms(&self) -> u64 {
        self.p50_latency_ms
    }

    pub(crate) fn conditioning_catalog_sha256(&self) -> &str {
        &self.conditioning_catalog_sha256
    }

    pub(crate) fn selected_policy_sha256(&self) -> &str {
        &self.selected_policy_sha256
    }

    pub(crate) const fn measured_at_unix(&self) -> u64 {
        self.measured_at_unix
    }

    pub(crate) fn record_sha256(&self) -> &str {
        &self.record_sha256
    }

    pub(crate) fn interface_layout_sha256(&self) -> &str {
        &self.interface_layout_sha256
    }
}

fn validate_identifier(value: &str) -> Result<(), ProfileCommissioningError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(ProfileCommissioningError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ProfileCommissioningError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProfileCommissioningError::InvalidDigest);
    }
    Ok(())
}

#[cfg(test)]
use crate::{
    capture_qualification::{
        AcceptedStream, CameraEndpoint, ConnectionContext, ExactInterval, ExactRate,
        QualifiedStreamRole, RequestedStream, StreamContract,
    },
    contracts::StreamRole,
    frame_interval::FrameInterval,
    profile::{DecodedPixelFormat, StreamTuple},
};

#[cfg(test)]
const FIXTURE_CONDITIONING_CATALOG_SHA256: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
#[cfg(test)]
const FIXTURE_SELECTED_POLICY_SHA256: &str =
    "5555555555555555555555555555555555555555555555555555555555555555";

#[cfg(test)]
#[derive(Clone)]
struct ContextOverrides {
    rgb_descriptor_sha256: String,
    rgb_vid: u16,
    rgb_pid: u16,
    rgb_serial: Option<String>,
    rgb_interface: u8,
    rgb_devpath: String,
    ir_descriptor_sha256: String,
    ir_vid: u16,
    ir_pid: u16,
    ir_interface: u8,
    driver: String,
    backend: String,
    speed_millimbps: u64,
}

#[cfg(test)]
impl Default for ContextOverrides {
    fn default() -> Self {
        Self {
            rgb_descriptor_sha256: "ab".repeat(32),
            rgb_vid: 0x0bda,
            rgb_pid: 0x5678,
            rgb_serial: Some("synthetic-camera".to_owned()),
            rgb_interface: 0,
            rgb_devpath: "/devices/pci0000:00/usb1/1-1/1-1:1.0".to_owned(),
            ir_descriptor_sha256: "ab".repeat(32),
            ir_vid: 0x0bda,
            ir_pid: 0x5678,
            ir_interface: 2,
            driver: "uvcvideo".to_owned(),
            backend: "v4l2-uvc".to_owned(),
            speed_millimbps: 5_000_000,
        }
    }
}

#[cfg(test)]
fn fixture_context_with(
    rgb_fps: u32,
    ir_fps: u32,
    overrides: &ContextOverrides,
) -> QualificationContext {
    let connection = |controller: &str| {
        ConnectionContext::new(
            controller.to_owned(),
            overrides.speed_millimbps,
            overrides.driver.clone(),
            overrides.backend.clone(),
        )
        .unwrap()
    };
    let rgb_endpoint = CameraEndpoint::new(
        overrides.rgb_descriptor_sha256.clone(),
        overrides.rgb_vid,
        overrides.rgb_pid,
        overrides.rgb_serial.clone(),
        overrides.rgb_interface,
        overrides.rgb_devpath.clone(),
        QualifiedStreamRole::Rgb,
        connection("/devices/pci0000:00/usb1/1-1"),
    )
    .unwrap();
    let ir_endpoint = CameraEndpoint::new(
        overrides.ir_descriptor_sha256.clone(),
        overrides.ir_vid,
        overrides.ir_pid,
        Some("synthetic-camera".to_owned()),
        overrides.ir_interface,
        "/devices/pci0000:00/usb1/1-1/1-1:1.2".to_owned(),
        QualifiedStreamRole::Ir,
        connection("/devices/pci0000:00/usb1/1-1"),
    )
    .unwrap();
    let stream = |role, width, height, fourcc: &str, fps, stride| {
        StreamContract::new(
            role,
            RequestedStream::new(
                width,
                height,
                fourcc.to_owned(),
                ExactInterval::new(1, fps).unwrap(),
            )
            .unwrap(),
            AcceptedStream::new(
                width,
                height,
                fourcc.to_owned(),
                stride,
                stride * height,
                1,
                8,
                1,
                1,
                0,
                ExactInterval::new(1, fps).unwrap(),
            )
            .unwrap(),
            ExactRate::new(fps, 1).unwrap(),
        )
        .unwrap()
    };
    QualificationContext::new(
        rgb_endpoint,
        ir_endpoint,
        stream(QualifiedStreamRole::Rgb, 640, 480, "YUYV", rgb_fps, 1280),
        stream(QualifiedStreamRole::Ir, 640, 400, "GREY", ir_fps, 640),
    )
    .unwrap()
}

#[cfg(test)]
pub(crate) fn fixture_current_context(rgb_fps: u32, ir_fps: u32) -> QualificationContext {
    fixture_context_with(rgb_fps, ir_fps, &ContextOverrides::default())
}

#[cfg(test)]
pub(crate) fn fixture_candidate_profile(
    id: &str,
    rgb_fps: u32,
    ir_fps: u32,
    schedule: CaptureSchedule,
) -> PairTransportProfile {
    let tuple = |role, format, width, height, fps| {
        StreamTuple::new(
            role,
            format,
            width,
            height,
            FrameInterval::new(1, fps).unwrap(),
        )
        .unwrap()
    };
    PairTransportProfile::new(
        id,
        tuple(StreamRole::Rgb, DecodedPixelFormat::Yuyv, 640, 480, rgb_fps),
        tuple(StreamRole::Ir, DecodedPixelFormat::Grey8, 640, 400, ir_fps),
        schedule,
    )
    .unwrap()
}

#[cfg(test)]
pub(crate) fn fixture_commissioning_value(
    id: &str,
    rgb_fps: u32,
    ir_fps: u32,
    schedule: CaptureSchedule,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "policy_version": 1,
        "producer_version": 1,
        "measured_at_unix": 1_788_192_000_u64,
        "expires_at_unix": 1_788_278_400_u64,
        "profile_id": id,
        "context": fixture_current_context(rgb_fps, ir_fps),
        "schedule": schedule,
        "conditioning_catalog_sha256": FIXTURE_CONDITIONING_CATALOG_SHA256,
        "selected_policy_sha256": FIXTURE_SELECTED_POLICY_SHA256,
        "interface_layout_sha256": "33".repeat(32),
        "gates": {
            "negotiation_passed": true,
            "transport_passed": true,
            "continuity_passed": true,
            "signal_sanity_passed": true,
            "conditioning_applied": true,
            "restoration_exact": true,
            "runtime_degradation_compatible": true,
            "p50_latency_ms": 4_000,
            "p95_latency_ms": 6_000,
            "latency_budget_ms": 8_000,
        },
    })
}

#[cfg(test)]
pub(crate) fn validated_commissioning_fixture(
    candidate_id: &str,
    candidate_rgb_fps: u32,
    candidate_ir_fps: u32,
    candidate_schedule: CaptureSchedule,
    now_unix: u64,
) -> ValidatedLocalCommissioning {
    validated_commissioning_fixture_with(
        candidate_id,
        candidate_rgb_fps,
        candidate_ir_fps,
        candidate_schedule,
        now_unix,
        fixture_current_context(candidate_rgb_fps, candidate_ir_fps),
        FIXTURE_CONDITIONING_CATALOG_SHA256.to_owned(),
        FIXTURE_SELECTED_POLICY_SHA256.to_owned(),
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn validated_commissioning_fixture_with_bindings(
    candidate_id: &str,
    candidate_rgb_fps: u32,
    candidate_ir_fps: u32,
    candidate_schedule: CaptureSchedule,
    now_unix: u64,
    conditioning_catalog_byte: u8,
    selected_policy_byte: u8,
) -> ValidatedLocalCommissioning {
    validated_commissioning_fixture_with(
        candidate_id,
        candidate_rgb_fps,
        candidate_ir_fps,
        candidate_schedule,
        now_unix,
        fixture_current_context(candidate_rgb_fps, candidate_ir_fps),
        format!("{conditioning_catalog_byte:02x}").repeat(32),
        format!("{selected_policy_byte:02x}").repeat(32),
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn validated_commissioning_fixture_with_serial(
    candidate_id: &str,
    candidate_rgb_fps: u32,
    candidate_ir_fps: u32,
    candidate_schedule: CaptureSchedule,
    now_unix: u64,
    serial: &str,
) -> ValidatedLocalCommissioning {
    let context = fixture_context_with(
        candidate_rgb_fps,
        candidate_ir_fps,
        &ContextOverrides {
            rgb_serial: Some(serial.to_owned()),
            ..ContextOverrides::default()
        },
    );
    validated_commissioning_fixture_with(
        candidate_id,
        candidate_rgb_fps,
        candidate_ir_fps,
        candidate_schedule,
        now_unix,
        context,
        FIXTURE_CONDITIONING_CATALOG_SHA256.to_owned(),
        FIXTURE_SELECTED_POLICY_SHA256.to_owned(),
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn validated_commissioning_fixture_with(
    candidate_id: &str,
    candidate_rgb_fps: u32,
    candidate_ir_fps: u32,
    candidate_schedule: CaptureSchedule,
    now_unix: u64,
    context: QualificationContext,
    conditioning_catalog_sha256: String,
    selected_policy_sha256: String,
) -> ValidatedLocalCommissioning {
    let mut value = fixture_commissioning_value(
        candidate_id,
        candidate_rgb_fps,
        candidate_ir_fps,
        candidate_schedule,
    );
    value["measured_at_unix"] = serde_json::json!(now_unix.checked_sub(50).unwrap());
    value["expires_at_unix"] = serde_json::json!(now_unix.checked_add(86_400).unwrap());
    value["context"] = serde_json::to_value(&context).unwrap();
    value["conditioning_catalog_sha256"] = serde_json::json!(conditioning_catalog_sha256.clone());
    value["selected_policy_sha256"] = serde_json::json!(selected_policy_sha256.clone());
    let wire: LocalCommissioningRecord = serde_json::from_value(value).unwrap();
    let canonical = serde_json::to_vec(&wire).unwrap();
    LocalCommissioningRecord::from_canonical_json(&canonical)
        .unwrap()
        .validate_for(
            &crate::release_qualification::fixture_release_scope(),
            &fixture_candidate_profile(
                candidate_id,
                candidate_rgb_fps,
                candidate_ir_fps,
                candidate_schedule,
            ),
            &context,
            &conditioning_catalog_sha256,
            &selected_policy_sha256,
            now_unix,
        )
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_qualification::fixture_release_scope;

    const FIXED_NOW: u64 = 1_788_192_050;

    fn record_from_value(value: serde_json::Value) -> LocalCommissioningRecord {
        let record: LocalCommissioningRecord = serde_json::from_value(value).unwrap();
        LocalCommissioningRecord::from_canonical_json(&serde_json::to_vec(&record).unwrap())
            .unwrap()
    }

    fn fixture_commissioning() -> LocalCommissioningRecord {
        record_from_value(fixture_commissioning_value(
            "candidate-15-15",
            15,
            15,
            CaptureSchedule::Concurrent,
        ))
    }

    fn validate_record(
        record: &LocalCommissioningRecord,
        candidate: &PairTransportProfile,
        context: &QualificationContext,
    ) -> Result<ValidatedLocalCommissioning, ProfileCommissioningError> {
        record.validate_for(
            &fixture_release_scope(),
            candidate,
            context,
            FIXTURE_CONDITIONING_CATALOG_SHA256,
            FIXTURE_SELECTED_POLICY_SHA256,
            FIXED_NOW,
        )
    }

    fn validate_mutation(
        field: &str,
        value: serde_json::Value,
    ) -> Result<ValidatedLocalCommissioning, ProfileCommissioningError> {
        let mut fixture =
            fixture_commissioning_value("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
        fixture[field] = value;
        validate_record(
            &record_from_value(fixture),
            &fixture_candidate_profile("candidate-15-15", 15, 15, CaptureSchedule::Concurrent),
            &fixture_current_context(15, 15),
        )
    }

    fn validate_changed_connection(
    ) -> Result<ValidatedLocalCommissioning, ProfileCommissioningError> {
        let overrides = ContextOverrides {
            backend: "alternate-backend".to_owned(),
            ..ContextOverrides::default()
        };
        let context = fixture_context_with(15, 15, &overrides);
        let mut value =
            fixture_commissioning_value("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
        value["context"] = serde_json::to_value(&context).unwrap();
        validate_record(
            &record_from_value(value),
            &fixture_candidate_profile("candidate-15-15", 15, 15, CaptureSchedule::Concurrent),
            &context,
        )
    }

    fn validate_changed_tuple() -> Result<ValidatedLocalCommissioning, ProfileCommissioningError> {
        let record = record_from_value(fixture_commissioning_value(
            "candidate-15-15",
            10,
            15,
            CaptureSchedule::Concurrent,
        ));
        validate_record(
            &record,
            &fixture_candidate_profile("candidate-15-15", 15, 15, CaptureSchedule::Concurrent),
            &fixture_current_context(10, 15),
        )
    }

    fn validate_failed_restoration(
    ) -> Result<ValidatedLocalCommissioning, ProfileCommissioningError> {
        let mut value =
            fixture_commissioning_value("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
        value["gates"]["restoration_exact"] = serde_json::json!(false);
        let wire: LocalCommissioningRecord = serde_json::from_value(value).unwrap();
        let record =
            LocalCommissioningRecord::from_canonical_json(&serde_json::to_vec(&wire).unwrap())?;
        validate_record(
            &record,
            &fixture_candidate_profile("candidate-15-15", 15, 15, CaptureSchedule::Concurrent),
            &fixture_current_context(15, 15),
        )
    }

    #[test]
    fn complete_fresh_local_record_matches_one_exact_device_and_release_scope() {
        let validated = fixture_commissioning()
            .validate_for(
                &fixture_release_scope(),
                &fixture_candidate_profile("candidate-15-15", 15, 15, CaptureSchedule::Concurrent),
                &fixture_current_context(15, 15),
                FIXTURE_CONDITIONING_CATALOG_SHA256,
                FIXTURE_SELECTED_POLICY_SHA256,
                FIXED_NOW,
            )
            .unwrap();
        assert_eq!(validated.profile_id(), "candidate-15-15");
        assert_eq!(validated.p95_latency_ms(), 6_000);
        assert_eq!(validated.context(), &fixture_current_context(15, 15));
        assert_eq!(validated.record_sha256.len(), 64);
    }

    #[test]
    fn model_or_biometric_fields_are_not_local_commissioning_vocabulary() {
        for field in ["recognition", "liveness", "rgb_pad", "ir_pad", "scene"] {
            let mut value =
                fixture_commissioning_value("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
            value[field] = serde_json::json!("passed");
            assert_eq!(
                LocalCommissioningRecord::from_canonical_json(value.to_string().as_bytes()),
                Err(ProfileCommissioningError::Json),
                "{field}"
            );
        }
    }

    #[test]
    fn stale_scope_tuple_or_restoration_failure_authorizes_nothing() {
        assert_eq!(
            validate_mutation("expires_at_unix", serde_json::json!(FIXED_NOW)),
            Err(ProfileCommissioningError::Stale),
        );
        assert_eq!(
            fixture_commissioning().validate_for(
                &fixture_release_scope(),
                &fixture_candidate_profile("candidate-15-15", 15, 15, CaptureSchedule::Concurrent,),
                &fixture_current_context(15, 15),
                FIXTURE_CONDITIONING_CATALOG_SHA256,
                FIXTURE_SELECTED_POLICY_SHA256,
                1_788_191_999,
            ),
            Err(ProfileCommissioningError::NotYetValid),
        );
        assert_eq!(
            validate_changed_connection(),
            Err(ProfileCommissioningError::HardwareScopeMismatch),
        );
        assert_eq!(
            validate_changed_tuple(),
            Err(ProfileCommissioningError::ProfileMismatch),
        );
        assert_eq!(
            validate_failed_restoration(),
            Err(ProfileCommissioningError::LocalGateFailed),
        );
    }

    #[test]
    fn versions_identifiers_digests_and_times_are_closed_and_bounded() {
        for (field, value, expected) in [
            (
                "schema_version",
                serde_json::json!(2),
                ProfileCommissioningError::UnsupportedSchema(2),
            ),
            (
                "policy_version",
                serde_json::json!(2),
                ProfileCommissioningError::UnsupportedPolicy(2),
            ),
            (
                "producer_version",
                serde_json::json!(2),
                ProfileCommissioningError::UnsupportedProducer(2),
            ),
            (
                "profile_id",
                serde_json::json!(""),
                ProfileCommissioningError::InvalidIdentifier,
            ),
            (
                "profile_id",
                serde_json::json!("x".repeat(257)),
                ProfileCommissioningError::InvalidIdentifier,
            ),
            (
                "measured_at_unix",
                serde_json::json!(0),
                ProfileCommissioningError::InvalidTime,
            ),
            (
                "expires_at_unix",
                serde_json::json!(1_788_192_000_u64),
                ProfileCommissioningError::InvalidTime,
            ),
        ] {
            let mut fixture =
                fixture_commissioning_value("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
            fixture[field] = value;
            let wire: LocalCommissioningRecord = serde_json::from_value(fixture).unwrap();
            assert_eq!(
                LocalCommissioningRecord::from_canonical_json(&serde_json::to_vec(&wire).unwrap()),
                Err(expected),
                "{field}"
            );
        }
        for field in [
            "conditioning_catalog_sha256",
            "selected_policy_sha256",
            "interface_layout_sha256",
        ] {
            let mut fixture =
                fixture_commissioning_value("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
            fixture[field] = serde_json::json!("not-a-digest");
            let wire: LocalCommissioningRecord = serde_json::from_value(fixture).unwrap();
            assert_eq!(
                LocalCommissioningRecord::from_canonical_json(&serde_json::to_vec(&wire).unwrap()),
                Err(ProfileCommissioningError::InvalidDigest),
                "{field}"
            );
        }
        assert_eq!(
            LocalCommissioningRecord::from_canonical_json(&vec![b' '; 256 * 1024 + 1]),
            Err(ProfileCommissioningError::DocumentTooLarge),
        );
    }

    #[test]
    fn exact_context_rejects_serial_devpath_role_and_release_hardware_drift() {
        let record = fixture_commissioning();
        let candidate =
            fixture_candidate_profile("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
        for overrides in [
            ContextOverrides {
                rgb_serial: Some("changed-serial".to_owned()),
                ..ContextOverrides::default()
            },
            ContextOverrides {
                rgb_devpath: "/devices/pci0000:00/usb1/1-9/1-9:1.0".to_owned(),
                ..ContextOverrides::default()
            },
        ] {
            assert_eq!(
                validate_record(
                    &record,
                    &candidate,
                    &fixture_context_with(15, 15, &overrides)
                ),
                Err(ProfileCommissioningError::ContextMismatch),
            );
        }

        for overrides in [
            ContextOverrides {
                rgb_descriptor_sha256: "ac".repeat(32),
                ..ContextOverrides::default()
            },
            ContextOverrides {
                ir_descriptor_sha256: "ac".repeat(32),
                ..ContextOverrides::default()
            },
            ContextOverrides {
                rgb_vid: 0x1234,
                ..ContextOverrides::default()
            },
            ContextOverrides {
                rgb_pid: 0x1234,
                ..ContextOverrides::default()
            },
            ContextOverrides {
                rgb_interface: 1,
                ..ContextOverrides::default()
            },
            ContextOverrides {
                driver: "other-driver".to_owned(),
                ..ContextOverrides::default()
            },
            ContextOverrides {
                backend: "other-backend".to_owned(),
                ..ContextOverrides::default()
            },
            ContextOverrides {
                speed_millimbps: 480_000,
                ..ContextOverrides::default()
            },
        ] {
            let context = fixture_context_with(15, 15, &overrides);
            let mut value =
                fixture_commissioning_value("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
            value["context"] = serde_json::to_value(&context).unwrap();
            assert_eq!(
                validate_record(&record_from_value(value), &candidate, &context),
                Err(ProfileCommissioningError::HardwareScopeMismatch),
            );
        }

        let mut wrong_role =
            fixture_commissioning_value("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
        wrong_role["context"]["rgb_endpoint"]["role"] = serde_json::json!("ir");
        let wire: LocalCommissioningRecord = serde_json::from_value(wrong_role).unwrap();
        assert_eq!(
            LocalCommissioningRecord::from_canonical_json(&serde_json::to_vec(&wire).unwrap()),
            Err(ProfileCommissioningError::InvalidContext),
        );
    }

    #[test]
    fn schedule_conditioning_layout_gates_and_latency_all_fail_closed() {
        assert_eq!(
            validate_mutation("schedule", serde_json::json!("sequential")),
            Err(ProfileCommissioningError::ProfileMismatch),
        );
        assert_eq!(
            validate_mutation(
                "interface_layout_sha256",
                serde_json::json!("34".repeat(32))
            ),
            Err(ProfileCommissioningError::HardwareScopeMismatch),
        );

        let record = fixture_commissioning();
        assert_eq!(
            record.validate_for(
                &fixture_release_scope(),
                &fixture_candidate_profile("candidate-15-15", 15, 15, CaptureSchedule::Concurrent,),
                &fixture_current_context(15, 15),
                &"45".repeat(32),
                FIXTURE_SELECTED_POLICY_SHA256,
                FIXED_NOW,
            ),
            Err(ProfileCommissioningError::ConditioningMismatch),
        );
        assert_eq!(
            record.validate_for(
                &fixture_release_scope(),
                &fixture_candidate_profile("candidate-15-15", 15, 15, CaptureSchedule::Concurrent,),
                &fixture_current_context(15, 15),
                FIXTURE_CONDITIONING_CATALOG_SHA256,
                &"56".repeat(32),
                FIXED_NOW,
            ),
            Err(ProfileCommissioningError::ConditioningMismatch),
        );

        for gate in [
            "negotiation_passed",
            "transport_passed",
            "continuity_passed",
            "signal_sanity_passed",
            "conditioning_applied",
            "restoration_exact",
            "runtime_degradation_compatible",
        ] {
            let mut value =
                fixture_commissioning_value("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
            value["gates"][gate] = serde_json::json!(false);
            let wire: LocalCommissioningRecord = serde_json::from_value(value).unwrap();
            assert_eq!(
                LocalCommissioningRecord::from_canonical_json(&serde_json::to_vec(&wire).unwrap()),
                Err(ProfileCommissioningError::LocalGateFailed),
                "{gate}"
            );
        }

        for (p50, p95, budget) in [
            (0, 6_000, 8_000),
            (7_000, 6_000, 8_000),
            (4_000, 9_000, 8_000),
        ] {
            let mut value =
                fixture_commissioning_value("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
            value["gates"]["p50_latency_ms"] = serde_json::json!(p50);
            value["gates"]["p95_latency_ms"] = serde_json::json!(p95);
            value["gates"]["latency_budget_ms"] = serde_json::json!(budget);
            let wire: LocalCommissioningRecord = serde_json::from_value(value).unwrap();
            assert_eq!(
                LocalCommissioningRecord::from_canonical_json(&serde_json::to_vec(&wire).unwrap()),
                Err(ProfileCommissioningError::InvalidLatency),
            );
        }
    }

    #[test]
    fn unknown_or_noncanonical_json_authorizes_nothing() {
        let mut unknown =
            fixture_commissioning_value("candidate-15-15", 15, 15, CaptureSchedule::Concurrent);
        unknown["unknown"] = serde_json::json!(true);
        assert_eq!(
            LocalCommissioningRecord::from_canonical_json(unknown.to_string().as_bytes()),
            Err(ProfileCommissioningError::Json),
        );
        assert_eq!(
            LocalCommissioningRecord::from_canonical_json(
                serde_json::to_string_pretty(&fixture_commissioning_value(
                    "candidate-15-15",
                    15,
                    15,
                    CaptureSchedule::Concurrent,
                ))
                .unwrap()
                .as_bytes(),
            ),
            Err(ProfileCommissioningError::Json),
        );
    }
}
