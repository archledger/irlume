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
pub const TRACE_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_TRACE_DURATION_MS: u64 = 60_000;
pub const MAX_TRACE_DURATION_MS: u64 = 5 * 60_000;
pub const MAX_TRACE_EVENTS: u64 = 50_000;
pub const MAX_TRACE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TRACE_LINE_BYTES: usize = 64 * 1024;
const MAX_TRACE_MEASUREMENTS: usize = 32;
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

    #[must_use]
    pub fn capture(&self) -> Option<&CaptureStatus> {
        self.capture.as_ref()
    }

    #[must_use]
    pub fn cameras(&self) -> &[SanitizedCameraContext] {
        &self.cameras
    }

    #[must_use]
    pub fn events(&self) -> &[ShareSafeEvent] {
        &self.events
    }

    #[must_use]
    pub fn unavailable(&self) -> &[SupportUnavailable] {
        &self.unavailable
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceLimits {
    pub duration_ms: u64,
    pub max_events: u64,
    pub max_bytes: u64,
}

impl TraceLimits {
    #[must_use]
    pub const fn bounded(duration_ms: u64) -> Self {
        Self {
            duration_ms: if duration_ms == 0 {
                DEFAULT_TRACE_DURATION_MS
            } else if duration_ms > MAX_TRACE_DURATION_MS {
                MAX_TRACE_DURATION_MS
            } else {
                duration_ms
            },
            max_events: MAX_TRACE_EVENTS,
            max_bytes: MAX_TRACE_BYTES,
        }
    }

    fn valid(self) -> bool {
        self.duration_ms > 0
            && self.duration_ms <= MAX_TRACE_DURATION_MS
            && self.max_events > 0
            && self.max_events <= MAX_TRACE_EVENTS
            && self.max_bytes > 0
            && self.max_bytes <= MAX_TRACE_BYTES
    }
}

diagnostic_enum!(TraceWarning {
    PrivilegedDiagnosticOracle,
});
diagnostic_enum!(TraceStage {
    CameraOpen,
    StreamArm,
    RateEstablishment,
    RgbCapture,
    IrCapture,
    Detection,
    Liveness,
    Matching,
    EmitterRestore,
});
diagnostic_enum!(TraceMetric {
    DeliveredFramesPerSecond,
    MinimumFramesPerSecond,
    CaptureSkewMilliseconds,
    RgbBrightness,
    RgbSpecularFraction,
    RgbMoireScore,
    IrBrightness,
    IrAmbientShare,
    IrCenterEdgeRatio,
    IrEyeGlint,
    IrSaturatedFraction,
    FaceFraction,
    HeadYawAsymmetry,
    HeadPitchFraction,
    LivenessScore,
    MatchCosine,
    FusionProbability,
});
diagnostic_enum!(TraceVerdict {
    Live,
    Spoof,
    Uncertain,
    Match,
    NoMatch,
});
diagnostic_enum!(EmitterTraceOutcome {
    Applied,
    AlreadyActive,
    Refused,
    Restored,
    RestoreFailed,
    Unavailable,
});

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct TraceMeasurement {
    pub metric: TraceMetric,
    pub value: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
}

impl TraceMeasurement {
    /// Construct one finite diagnostic measurement.
    ///
    /// # Errors
    ///
    /// Returns an error when the value or optional threshold is not finite.
    pub fn new(
        metric: TraceMetric,
        value: f64,
        threshold: Option<f64>,
    ) -> Result<Self, InvalidDiagnosticValue> {
        if !value.is_finite() || threshold.is_some_and(|value| !value.is_finite()) {
            return Err(InvalidDiagnosticValue);
        }
        Ok(Self {
            metric,
            value,
            threshold,
        })
    }
}

impl<'de> Deserialize<'de> for TraceMeasurement {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            metric: TraceMetric,
            value: f64,
            #[serde(default)]
            threshold: Option<f64>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.metric, wire.value, wire.threshold)
            .map_err(|_| serde::de::Error::custom("trace measurements must be finite"))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TraceEventKind {
    TraceStarted {
        limits: TraceLimits,
        warning: TraceWarning,
    },
    Shared {
        transition: ShareSafeEventKind,
    },
    StreamContract {
        role: CameraRoleLabel,
        requested: ExactStreamContract,
        accepted: ExactStreamContract,
    },
    StreamEvidence {
        role: CameraRoleLabel,
        delivered: ExactFraction,
        minimum: ExactFraction,
        dropped_frames: u64,
        continuity_epoch: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_ir: Option<bool>,
    },
    Emitter {
        outcome: EmitterTraceOutcome,
    },
    StageTiming {
        stage: TraceStage,
        elapsed_us: u64,
    },
    DetectorCount {
        role: CameraRoleLabel,
        count: u32,
    },
    Decision {
        verdict: TraceVerdict,
        measurements: Vec<TraceMeasurement>,
    },
    EventsDropped {
        count: u64,
    },
    Finished {
        outcome: CategoricalOutcome,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TraceRecord {
    pub trace_schema: u32,
    pub sequence: u64,
    pub monotonic_us: u64,
    pub utc_unix_ms: u64,
    pub operation_id: OperationId,
    pub operation: OperationClass,
    pub event: TraceEventKind,
    pub terminal: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedTrace {
    records: Vec<TraceRecord>,
}

/// Incremental validator for a live trace stream. A caller may persist each
/// line only after [`Self::push_line`] accepts it, then publish only after
/// [`Self::finish`] confirms one final terminal record.
pub struct TraceValidator {
    limits: TraceLimits,
    total_bytes: u64,
    records: u64,
    terminal_seen: bool,
}

impl TraceValidator {
    /// Start validating against daemon-applied bounds.
    ///
    /// # Errors
    ///
    /// Refuses limits outside the public trace contract.
    pub fn new(limits: TraceLimits) -> Result<Self, TraceParseError> {
        if !limits.valid() {
            return Err(TraceParseError::Limit);
        }
        Ok(Self {
            limits,
            total_bytes: 0,
            records: 0,
            terminal_seen: false,
        })
    }

    /// Validate and return one complete JSONL record.
    ///
    /// # Errors
    ///
    /// Refuses byte/record limits, malformed schema, sequence gaps, invalid
    /// event bounds, or any record after the terminal.
    pub fn push_line(&mut self, line: &[u8]) -> Result<TraceRecord, TraceParseError> {
        let line_bytes = u64::try_from(line.len()).map_err(|_| TraceParseError::Limit)?;
        self.total_bytes = self
            .total_bytes
            .checked_add(line_bytes)
            .ok_or(TraceParseError::Limit)?;
        if self.total_bytes > self.limits.max_bytes
            || line.len() > MAX_TRACE_LINE_BYTES
            || self.records >= self.limits.max_events
        {
            return Err(TraceParseError::Limit);
        }
        if self.terminal_seen {
            return Err(TraceParseError::Terminal);
        }
        let record: TraceRecord = serde_json::from_slice(line).map_err(TraceParseError::Json)?;
        if record.trace_schema != TRACE_SCHEMA_VERSION {
            return Err(TraceParseError::Schema);
        }
        if record.sequence != self.records {
            return Err(TraceParseError::Sequence);
        }
        validate_trace_event(&record.event)?;
        self.terminal_seen = record.terminal;
        if record.terminal && !matches!(record.event, TraceEventKind::Finished { .. }) {
            return Err(TraceParseError::Terminal);
        }
        self.records = self.records.saturating_add(1);
        Ok(record)
    }

    /// Confirm the stream ended after exactly one final terminal record.
    ///
    /// # Errors
    ///
    /// Refuses an empty or truncated stream.
    pub fn finish(self) -> Result<(), TraceParseError> {
        if self.records == 0 || !self.terminal_seen {
            return Err(TraceParseError::Terminal);
        }
        Ok(())
    }
}

impl ParsedTrace {
    #[must_use]
    pub fn records(&self) -> &[TraceRecord] {
        &self.records
    }
}

#[derive(Debug)]
pub enum TraceParseError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Limit,
    Schema,
    Sequence,
    Terminal,
    InvalidEvent,
}

impl fmt::Display for TraceParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "trace read failed: {error}"),
            Self::Json(error) => write!(formatter, "invalid trace JSON: {error}"),
            Self::Limit => formatter.write_str("trace exceeds its bounded limits"),
            Self::Schema => formatter.write_str("unsupported trace schema"),
            Self::Sequence => formatter.write_str("trace sequence is not contiguous"),
            Self::Terminal => formatter.write_str("trace needs exactly one final terminal record"),
            Self::InvalidEvent => formatter.write_str("trace event violates its contract"),
        }
    }
}

impl std::error::Error for TraceParseError {}

/// Parse and validate one complete bounded JSONL trace.
///
/// # Errors
///
/// Rejects I/O/JSON errors, oversized input, schema or sequence drift, invalid
/// event bounds, and missing/duplicate/non-final terminal records.
pub fn parse_trace<R: std::io::BufRead>(
    mut reader: R,
    limits: TraceLimits,
) -> Result<ParsedTrace, TraceParseError> {
    let mut validator = TraceValidator::new(limits)?;
    let mut records = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .map_err(TraceParseError::Io)?;
        if read == 0 {
            break;
        }
        records.push(validator.push_line(&line)?);
    }
    validator.finish()?;
    Ok(ParsedTrace { records })
}

fn validate_trace_event(event: &TraceEventKind) -> Result<(), TraceParseError> {
    match event {
        TraceEventKind::TraceStarted { limits, .. } if !limits.valid() => {
            Err(TraceParseError::Limit)
        }
        TraceEventKind::Decision { measurements, .. }
            if measurements.len() > MAX_TRACE_MEASUREMENTS =>
        {
            Err(TraceParseError::InvalidEvent)
        }
        TraceEventKind::EventsDropped { count: 0 } => Err(TraceParseError::InvalidEvent),
        _ => Ok(()),
    }
}

/// A non-blocking recipient for already-sanitized production decisions.
pub trait DiagnosticSink: Send + Sync {
    fn emit_share_safe(&self, _kind: ShareSafeEventKind) {}

    fn emit_trace(&self, _kind: TraceEventKind) {}
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

    fn trace_record(sequence: u64, event: TraceEventKind, terminal: bool) -> TraceRecord {
        TraceRecord {
            trace_schema: TRACE_SCHEMA_VERSION,
            sequence,
            monotonic_us: sequence * 10,
            utc_unix_ms: 1_700_000_000_000 + sequence,
            operation_id: OperationId::from_bytes([0x42; 16]),
            operation: OperationClass::Authentication,
            event,
            terminal,
        }
    }

    fn trace_jsonl(records: &[TraceRecord]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for record in records {
            serde_json::to_writer(&mut bytes, record).unwrap();
            bytes.push(b'\n');
        }
        bytes
    }

    #[test]
    fn trace_schema_allows_finite_measurements_but_forbids_biometric_payloads() {
        let record = trace_record(
            0,
            TraceEventKind::Decision {
                verdict: TraceVerdict::Live,
                measurements: vec![TraceMeasurement::new(
                    TraceMetric::LivenessScore,
                    0.82,
                    Some(0.75),
                )
                .unwrap()],
            },
            false,
        );
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(value["event"]["measurements"][0]["value"], 0.82);
        assert_eq!(value["event"]["measurements"][0]["threshold"], 0.75);
        let mut keys = BTreeSet::new();
        collect_keys(&value, &mut keys);
        for forbidden in [
            "user",
            "username",
            "profile",
            "serial",
            "device_path",
            "frame",
            "crop",
            "landmark",
            "embedding",
            "credential",
            "emitter_payload",
        ] {
            assert!(
                !keys.contains(forbidden),
                "forbidden trace key: {forbidden}"
            );
        }
        assert!(TraceMeasurement::new(TraceMetric::MatchCosine, f64::NAN, None).is_err());
    }

    #[test]
    fn trace_parser_accepts_one_contiguous_stream_with_one_final_terminal() {
        let limits = TraceLimits::bounded(60_000);
        let records = vec![
            trace_record(
                0,
                TraceEventKind::TraceStarted {
                    limits,
                    warning: TraceWarning::PrivilegedDiagnosticOracle,
                },
                false,
            ),
            trace_record(
                1,
                TraceEventKind::Finished {
                    outcome: CategoricalOutcome::Completed,
                },
                true,
            ),
        ];
        let parsed = parse_trace(std::io::Cursor::new(trace_jsonl(&records)), limits).unwrap();
        assert_eq!(parsed.records(), records);
    }

    #[test]
    fn trace_parser_rejects_gaps_duplicate_terminal_and_oversize() {
        let limits = TraceLimits::bounded(60_000);
        let finished = |sequence| {
            trace_record(
                sequence,
                TraceEventKind::Finished {
                    outcome: CategoricalOutcome::Completed,
                },
                true,
            )
        };
        assert!(matches!(
            parse_trace(std::io::Cursor::new(trace_jsonl(&[finished(1)])), limits),
            Err(TraceParseError::Sequence)
        ));
        assert!(matches!(
            parse_trace(
                std::io::Cursor::new(trace_jsonl(&[finished(0), finished(1)])),
                limits
            ),
            Err(TraceParseError::Terminal)
        ));
        let oversized = vec![b'x'; MAX_TRACE_LINE_BYTES + 1];
        assert!(matches!(
            parse_trace(std::io::Cursor::new(oversized), limits),
            Err(TraceParseError::Limit)
        ));
    }
}
