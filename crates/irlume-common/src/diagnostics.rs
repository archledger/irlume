// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Structurally share-safe diagnostic facts.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::num::NonZeroU32;

pub const SUPPORT_SCHEMA_VERSION: u32 = 1;
pub const MAX_SHARE_SAFE_EVENTS: usize = 256;
pub const MAX_SANITIZED_CAMERAS: usize = 8;
pub const MAX_UNAVAILABLE_SECTIONS: usize = 16;
pub const MAX_HISTORY_MS: u64 = 30 * 60 * 1_000;
const MAX_SAFE_LABEL_BYTES: usize = 64;
const MAX_USB_PORT_DEPTH: usize = 8;

/// A daemon-generated opaque identifier shared by events from one operation.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct OperationId([u8; 16]);

impl OperationId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OperationId")
            .field(&encode_hex(&self.0))
            .finish()
    }
}

impl Serialize for OperationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        decode_hex::<16>(&value)
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("operation ID must be 32 lowercase hex digits"))
    }
}

/// A fixed 16-hex-character correlation token derived from a larger digest.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct DigestToken([u8; 8]);

impl DigestToken {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Debug for DigestToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DigestToken")
            .field(&encode_hex(&self.0))
            .finish()
    }
}

impl Serialize for DigestToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for DigestToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        decode_hex::<8>(&value)
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("digest token must be 16 lowercase hex digits"))
    }
}

/// A short injection-safe hardware or backend label.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SafeLabel(String);

impl SafeLabel {
    /// Validate a diagnostic label.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, non-ASCII, or path-like input.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidDiagnosticValue> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_SAFE_LABEL_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+' | b':')
            })
        {
            return Err(InvalidDiagnosticValue);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for SafeLabel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SafeLabel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid diagnostic label"))
    }
}

/// Four printable ASCII bytes identifying a stream format.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FourCc([u8; 4]);

impl FourCc {
    /// Validate a four-character code.
    ///
    /// # Errors
    ///
    /// Returns an error if any byte is not printable ASCII.
    pub fn new(value: [u8; 4]) -> Result<Self, InvalidDiagnosticValue> {
        if !value.iter().all(u8::is_ascii_graphic) {
            return Err(InvalidDiagnosticValue);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }
}

impl Serialize for FourCc {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = std::str::from_utf8(&self.0)
            .map_err(|_| serde::ser::Error::custom("validated FourCC was not ASCII"))?;
        serializer.serialize_str(value)
    }
}

impl<'de> Deserialize<'de> for FourCc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let bytes: [u8; 4] = value
            .as_bytes()
            .try_into()
            .map_err(|_| serde::de::Error::custom("FourCC must have four bytes"))?;
        Self::new(bytes).map_err(|_| serde::de::Error::custom("FourCC must be printable ASCII"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ExactFraction {
    pub numerator: NonZeroU32,
    pub denominator: NonZeroU32,
}

impl ExactFraction {
    /// Construct a positive exact fraction.
    ///
    /// # Errors
    ///
    /// Returns an error when either component is zero.
    pub fn new(numerator: u32, denominator: u32) -> Result<Self, InvalidDiagnosticValue> {
        Ok(Self {
            numerator: NonZeroU32::new(numerator).ok_or(InvalidDiagnosticValue)?,
            denominator: NonZeroU32::new(denominator).ok_or(InvalidDiagnosticValue)?,
        })
    }
}

impl<'de> Deserialize<'de> for ExactFraction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            numerator: u32,
            denominator: u32,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.numerator, wire.denominator)
            .map_err(|_| serde::de::Error::custom("fraction components must be nonzero"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExactStreamContract {
    pub width: u32,
    pub height: u32,
    pub fourcc: FourCc,
    pub interval: ExactFraction,
}

impl<'de> Deserialize<'de> for ExactStreamContract {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            width: u32,
            height: u32,
            fourcc: FourCc,
            interval: ExactFraction,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.width == 0 || wire.height == 0 {
            return Err(serde::de::Error::custom("stream geometry must be nonzero"));
        }
        Ok(Self {
            width: wire.width,
            height: wire.height,
            fourcc: wire.fourcc,
            interval: wire.interval,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraRoleLabel {
    Rgb,
    Ir,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SanitizedCameraContext {
    pub vid: u16,
    pub pid: u16,
    pub role: CameraRoleLabel,
    pub interface_number: u8,
    pub driver: SafeLabel,
    pub backend: SafeLabel,
    pub speed_millimbps: u64,
    pub controller: SafeLabel,
    pub usb_bus: u16,
    pub usb_port_chain: Vec<u8>,
    pub lifecycle_generation: u64,
    pub serial_present: bool,
    pub descriptor_token: DigestToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification_token: Option<DigestToken>,
    pub requested: ExactStreamContract,
    pub accepted: ExactStreamContract,
}

impl<'de> Deserialize<'de> for SanitizedCameraContext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            vid: u16,
            pid: u16,
            role: CameraRoleLabel,
            interface_number: u8,
            driver: SafeLabel,
            backend: SafeLabel,
            speed_millimbps: u64,
            controller: SafeLabel,
            usb_bus: u16,
            usb_port_chain: Vec<u8>,
            lifecycle_generation: u64,
            serial_present: bool,
            descriptor_token: DigestToken,
            #[serde(default)]
            qualification_token: Option<DigestToken>,
            requested: ExactStreamContract,
            accepted: ExactStreamContract,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.speed_millimbps == 0
            || wire.usb_bus == 0
            || wire.usb_port_chain.is_empty()
            || wire.usb_port_chain.len() > MAX_USB_PORT_DEPTH
            || wire.usb_port_chain.contains(&0)
        {
            return Err(serde::de::Error::custom("invalid sanitized USB context"));
        }
        Ok(Self {
            vid: wire.vid,
            pid: wire.pid,
            role: wire.role,
            interface_number: wire.interface_number,
            driver: wire.driver,
            backend: wire.backend,
            speed_millimbps: wire.speed_millimbps,
            controller: wire.controller,
            usb_bus: wire.usb_bus,
            usb_port_chain: wire.usb_port_chain,
            lifecycle_generation: wire.lifecycle_generation,
            serial_present: wire.serial_present,
            descriptor_token: wire.descriptor_token,
            qualification_token: wire.qualification_token,
            requested: wire.requested,
            accepted: wire.accepted,
        })
    }
}

macro_rules! diagnostic_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}

diagnostic_enum!(CaptureSchedule {
    Sequential,
    Concurrent
});
diagnostic_enum!(CaptureScheduleSource {
    EnvironmentOverride,
    StoredQualification,
    SequentialDefault,
    RuntimeHealth,
    NoIrPair,
});
diagnostic_enum!(QualificationState {
    QualifiedConcurrent,
    MeasuredSequential,
    UnqualifiedNoAuthority,
    UnqualifiedContextChanged,
    Inconclusive,
    Unreadable,
    NoIrPair,
});
diagnostic_enum!(QualificationReason {
    ConcurrentUnavailable,
    DeliveredRateShortfall,
    SignalLoss,
    InvalidProvenance,
    NoStoredAuthority,
    ContextChanged,
    IncompleteRounds,
    DimScene,
    ContractDrift,
    MissingProvenance,
    StoreUnreadable,
});
diagnostic_enum!(RuntimeViolationLabel {
    ConcurrentCaptureFailure,
    PairOpenFailure,
    PairArmFailure,
    PairRateEstablishmentFailure,
    StreamRecovery,
    MissingRuntimeContract,
    CameraGenerationChanged,
    StreamContractMismatch,
    DeliveredRateShortfall,
    ContinuityLoss,
    ActiveIrMissing,
    ConfirmedSignalLoss,
});
diagnostic_enum!(OperationClass {
    Authentication,
    Enrollment,
    Identification,
    CaptureQualification,
    CameraDiagnostics,
    SupportProbe,
    Status,
    Lifecycle,
});
diagnostic_enum!(CategoricalOutcome {
    Granted,
    Denied,
    Completed,
    Failed,
    Cancelled,
    Unavailable,
});
diagnostic_enum!(ProbeOutcome {
    Captured,
    FallbackCaptured,
    RgbOnlyCaptured,
    Unavailable,
    Failed,
});
diagnostic_enum!(ProbeRoleOutcome {
    Captured,
    Missing,
    Failed
});
diagnostic_enum!(SupportSection {
    Daemon,
    CameraContext,
    CaptureSchedule,
    RecentEvents,
    SupportProbe,
});
diagnostic_enum!(UnavailableReason {
    DaemonUnavailable,
    DaemonRestarted,
    NoCamera,
    NoIrPair,
    NotAuthorized,
    CollectionFailed,
});

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureStatus {
    pub schedule: CaptureSchedule,
    pub source: CaptureScheduleSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_context: Option<DigestToken>,
    pub qualification_state: QualificationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification_reason: Option<QualificationReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification_context: Option<DigestToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_degradation: Option<RuntimeViolationLabel>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShareSafeEvent {
    pub sequence: u64,
    pub age_ms: u64,
    pub operation_id: OperationId,
    pub operation: OperationClass,
    pub kind: ShareSafeEventKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ShareSafeEventKind {
    LifecycleChanged {
        role: CameraRoleLabel,
        generation: u64,
    },
    CaptureScheduleSelected {
        schedule: CaptureSchedule,
        source: CaptureScheduleSource,
    },
    QualificationChanged {
        state: QualificationState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<QualificationReason>,
    },
    CaptureFallback {
        reason: RuntimeViolationLabel,
    },
    OperationFinished {
        outcome: CategoricalOutcome,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupportUnavailable {
    pub section: SupportSection,
    pub reason: UnavailableReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SupportSnapshot {
    pub support_schema: u32,
    pub daemon_uptime_ms: u64,
    pub retained_history_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureStatus>,
    pub cameras: Vec<SanitizedCameraContext>,
    pub events: Vec<ShareSafeEvent>,
    pub unavailable: Vec<SupportUnavailable>,
}

impl SupportSnapshot {
    #[must_use]
    pub fn bounded(
        daemon_uptime_ms: u64,
        retained_history_ms: u64,
        capture: Option<CaptureStatus>,
        mut cameras: Vec<SanitizedCameraContext>,
        mut events: Vec<ShareSafeEvent>,
        mut unavailable: Vec<SupportUnavailable>,
    ) -> Self {
        cameras.truncate(MAX_SANITIZED_CAMERAS);
        if events.len() > MAX_SHARE_SAFE_EVENTS {
            events.drain(..events.len() - MAX_SHARE_SAFE_EVENTS);
        }
        unavailable.truncate(MAX_UNAVAILABLE_SECTIONS);
        Self {
            support_schema: SUPPORT_SCHEMA_VERSION,
            daemon_uptime_ms,
            retained_history_ms: retained_history_ms.min(MAX_HISTORY_MS),
            capture,
            cameras,
            events,
            unavailable,
        }
    }
}

impl<'de> Deserialize<'de> for SupportSnapshot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            support_schema: u32,
            daemon_uptime_ms: u64,
            retained_history_ms: u64,
            #[serde(default)]
            capture: Option<CaptureStatus>,
            #[serde(default)]
            cameras: Vec<SanitizedCameraContext>,
            #[serde(default)]
            events: Vec<ShareSafeEvent>,
            #[serde(default)]
            unavailable: Vec<SupportUnavailable>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.support_schema != SUPPORT_SCHEMA_VERSION
            || wire.retained_history_ms > MAX_HISTORY_MS
            || wire.cameras.len() > MAX_SANITIZED_CAMERAS
            || wire.events.len() > MAX_SHARE_SAFE_EVENTS
            || wire
                .events
                .iter()
                .any(|event| event.age_ms > MAX_HISTORY_MS)
            || wire.unavailable.len() > MAX_UNAVAILABLE_SECTIONS
        {
            return Err(serde::de::Error::custom(
                "support snapshot exceeds its contract",
            ));
        }
        Ok(Self {
            support_schema: wire.support_schema,
            daemon_uptime_ms: wire.daemon_uptime_ms,
            retained_history_ms: wire.retained_history_ms,
            capture: wire.capture,
            cameras: wire.cameras,
            events: wire.events,
            unavailable: wire.unavailable,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupportProbeResult {
    pub snapshot: SupportSnapshot,
    pub schedule: CaptureSchedule,
    pub source: CaptureScheduleSource,
    pub outcome: ProbeOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<RuntimeViolationLabel>,
    pub rgb: ProbeRoleOutcome,
    pub ir: ProbeRoleOutcome,
}

/// A non-blocking recipient for already-sanitized production decisions.
pub trait DiagnosticSink: Send + Sync {
    fn emit_share_safe(&self, _kind: ShareSafeEventKind) {}
}

impl DiagnosticSink for () {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDiagnosticValue;

impl fmt::Display for InvalidDiagnosticValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid bounded diagnostic value")
    }
}

impl std::error::Error for InvalidDiagnosticValue {}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    // Uppercase would create multiple wire spellings for one token.
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    let mut result = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        result[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(result)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Request, Response};
    use serde_json::Value;
    use std::collections::BTreeSet;

    fn stream(fourcc: &[u8; 4]) -> ExactStreamContract {
        ExactStreamContract {
            width: 640,
            height: 480,
            fourcc: FourCc::new(*fourcc).unwrap(),
            interval: ExactFraction::new(1, 30).unwrap(),
        }
    }

    fn camera(role: CameraRoleLabel) -> SanitizedCameraContext {
        SanitizedCameraContext {
            vid: 0x046d,
            pid: 0x085e,
            role,
            interface_number: 2,
            driver: SafeLabel::new("uvcvideo").unwrap(),
            backend: SafeLabel::new("uvc_v4l2").unwrap(),
            speed_millimbps: 5_000_000,
            controller: SafeLabel::new("0000:00:14.0").unwrap(),
            usb_bus: 3,
            usb_port_chain: vec![4, 2],
            lifecycle_generation: 7,
            serial_present: true,
            descriptor_token: DigestToken::from_bytes([0x12; 8]),
            qualification_token: Some(DigestToken::from_bytes([0x34; 8])),
            requested: stream(b"MJPG"),
            accepted: stream(b"MJPG"),
        }
    }

    fn capture_status() -> CaptureStatus {
        CaptureStatus {
            schedule: CaptureSchedule::Sequential,
            source: CaptureScheduleSource::StoredQualification,
            runtime_context: Some(DigestToken::from_bytes([0x56; 8])),
            qualification_state: QualificationState::MeasuredSequential,
            qualification_reason: Some(QualificationReason::DeliveredRateShortfall),
            qualification_context: Some(DigestToken::from_bytes([0x78; 8])),
            runtime_degradation: Some(RuntimeViolationLabel::DeliveredRateShortfall),
        }
    }

    fn event(sequence: u64) -> ShareSafeEvent {
        ShareSafeEvent {
            sequence,
            age_ms: 25,
            operation_id: OperationId::from_bytes([sequence as u8; 16]),
            operation: OperationClass::Authentication,
            kind: ShareSafeEventKind::CaptureFallback {
                reason: RuntimeViolationLabel::DeliveredRateShortfall,
            },
        }
    }

    fn snapshot() -> SupportSnapshot {
        SupportSnapshot {
            support_schema: SUPPORT_SCHEMA_VERSION,
            daemon_uptime_ms: 42_000,
            retained_history_ms: 30 * 60 * 1_000,
            capture: Some(capture_status()),
            cameras: vec![camera(CameraRoleLabel::Rgb), camera(CameraRoleLabel::Ir)],
            events: vec![event(1)],
            unavailable: vec![SupportUnavailable {
                section: SupportSection::RecentEvents,
                reason: UnavailableReason::DaemonRestarted,
            }],
        }
    }

    fn collect_keys(value: &Value, keys: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    keys.insert(key.clone());
                    collect_keys(value, keys);
                }
            }
            Value::Array(values) => {
                for value in values {
                    collect_keys(value, keys);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn share_safe_serialization_has_no_identity_or_biometric_fields() {
        let mut keys = BTreeSet::new();
        collect_keys(&serde_json::to_value(snapshot()).unwrap(), &mut keys);
        for forbidden in [
            "user",
            "username",
            "profile",
            "serial",
            "raw_serial",
            "device_path",
            "frame",
            "crop",
            "embedding",
            "landmark",
            "score",
            "threshold",
            "credential",
            "payload",
        ] {
            assert!(!keys.contains(forbidden), "forbidden field: {forbidden}");
        }
    }

    #[test]
    fn public_diagnostic_struct_fields_exclude_raw_or_identity_names() {
        let source = include_str!("diagnostics.rs");
        for line in source.lines().map(str::trim) {
            let Some(field) = line
                .strip_prefix("pub ")
                .and_then(|rest| rest.split(':').next())
            else {
                continue;
            };
            assert!(
                !matches!(
                    field,
                    "user"
                        | "username"
                        | "profile"
                        | "serial"
                        | "raw_serial"
                        | "device_path"
                        | "frame"
                        | "crop"
                        | "embedding"
                        | "landmark"
                        | "score"
                        | "threshold"
                        | "credential"
                        | "payload"
                ),
                "forbidden public diagnostic field: {field}"
            );
        }
    }

    #[test]
    fn support_snapshot_round_trips_with_every_optional_section_populated() {
        let snapshot = snapshot();
        let bytes = serde_json::to_vec(&snapshot).unwrap();
        assert_eq!(
            serde_json::from_slice::<SupportSnapshot>(&bytes).unwrap(),
            snapshot
        );
    }

    #[test]
    fn deserialization_rejects_oversized_history_and_malformed_tokens() {
        let mut value = serde_json::to_value(snapshot()).unwrap();
        let valid_event = serde_json::to_value(event(1)).unwrap();
        value["events"] = Value::Array(
            (0..=MAX_SHARE_SAFE_EVENTS)
                .map(|_| valid_event.clone())
                .collect(),
        );
        assert!(serde_json::from_value::<SupportSnapshot>(value).is_err());

        assert!(serde_json::from_str::<DigestToken>(r#""0123456789abcdeZ""#).is_err());
        assert!(serde_json::from_str::<SafeLabel>(r#""/dev/video0""#).is_err());
    }

    #[test]
    fn bounded_construction_keeps_the_newest_history_and_caps_all_vectors() {
        let snapshot = SupportSnapshot::bounded(
            1,
            u64::MAX,
            None,
            (0..MAX_SANITIZED_CAMERAS + 1)
                .map(|_| camera(CameraRoleLabel::Rgb))
                .collect(),
            (0..MAX_SHARE_SAFE_EVENTS as u64 + 2).map(event).collect(),
            (0..MAX_UNAVAILABLE_SECTIONS + 1)
                .map(|_| SupportUnavailable {
                    section: SupportSection::RecentEvents,
                    reason: UnavailableReason::DaemonRestarted,
                })
                .collect(),
        );
        assert_eq!(snapshot.cameras.len(), MAX_SANITIZED_CAMERAS);
        assert_eq!(snapshot.events.len(), MAX_SHARE_SAFE_EVENTS);
        assert_eq!(snapshot.events.first().unwrap().sequence, 2);
        assert_eq!(snapshot.unavailable.len(), MAX_UNAVAILABLE_SECTIONS);
        assert_eq!(snapshot.retained_history_ms, MAX_HISTORY_MS);
    }

    #[test]
    fn future_optional_snapshot_sections_are_ignored_but_core_bounds_remain() {
        let mut value = serde_json::to_value(snapshot()).unwrap();
        value["future_optional_section"] = serde_json::json!({"state": "unknown"});
        assert!(serde_json::from_value::<SupportSnapshot>(value).is_ok());

        let mut invalid_camera = serde_json::to_value(camera(CameraRoleLabel::Rgb)).unwrap();
        invalid_camera["usb_port_chain"] = serde_json::json!([1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert!(serde_json::from_value::<SanitizedCameraContext>(invalid_camera).is_err());
        assert!(ExactFraction::new(0, 30).is_err());
        assert!(SafeLabel::new("a".repeat(MAX_SAFE_LABEL_BYTES + 1)).is_err());
    }

    #[test]
    fn support_requests_and_responses_round_trip_without_caller_correlation() {
        for request in [
            Request::SupportSnapshot { since_ms: 60_000 },
            Request::SupportProbe { since_ms: 60_000 },
        ] {
            let json = serde_json::to_string(&request).unwrap();
            assert!(!json.contains("operation_id"));
            assert!(serde_json::from_str::<Request>(&json).is_ok());
        }

        let probe = SupportProbeResult {
            snapshot: snapshot(),
            schedule: CaptureSchedule::Sequential,
            source: CaptureScheduleSource::StoredQualification,
            outcome: ProbeOutcome::FallbackCaptured,
            fallback_reason: Some(RuntimeViolationLabel::DeliveredRateShortfall),
            rgb: ProbeRoleOutcome::Captured,
            ir: ProbeRoleOutcome::Captured,
        };
        for response in [
            Response::SupportSnapshot(Box::new(snapshot())),
            Response::SupportProbe(Box::new(probe)),
        ] {
            let json = serde_json::to_string(&response).unwrap();
            assert!(serde_json::from_str::<Response>(&json).is_ok());
        }
    }
}
