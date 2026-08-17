// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Durable evidence that one exact RGB+IR stream pair may capture concurrently.

use serde::{Deserialize, Serialize};
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// Record shape understood by this build. Unknown versions authorize nothing.
pub const SCHEMA_VERSION: u32 = 2;
/// Evidence policy understood by this build. Bump when qualification rules change.
pub const POLICY_VERSION: u32 = 1;
/// Records are machine-generated summaries, not an unbounded document store.
pub const MAX_RECORD_BYTES: usize = 256 * 1024;

const MAX_TEXT_BYTES: usize = 512;
const CONCURRENT_SIGNAL_FLOOR: f32 = 0.80;
const CONCLUSIVE_RGB_MEAN: f32 = 100.0;

/// Failure to construct or trust a capture qualification.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum QualificationError {
    ZeroInterval,
    InvalidText,
    InvalidFourcc,
    InvalidDigest,
    InvalidPath,
    InvalidRole,
    InvalidEvidence,
    InconclusiveAuthority,
    RecordTooLarge,
    UnsupportedSchema(u32),
    UnsupportedPolicy(u32),
    Json(String),
}

impl std::fmt::Display for QualificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroInterval => f.write_str("frame interval components must be nonzero"),
            Self::InvalidText => f.write_str("qualification text field is empty or oversized"),
            Self::InvalidFourcc => f.write_str("fourcc must contain exactly four ASCII bytes"),
            Self::InvalidDigest => f.write_str("descriptor digest must be lowercase sha256 hex"),
            Self::InvalidPath => f.write_str("qualification sysfs path is not canonical"),
            Self::InvalidRole => f.write_str("RGB and IR qualification roles do not agree"),
            Self::InvalidEvidence => f.write_str("qualification evidence is inconsistent"),
            Self::InconclusiveAuthority => {
                f.write_str("inconclusive evidence cannot be authoritative")
            }
            Self::RecordTooLarge => f.write_str("qualification record exceeds its size limit"),
            Self::UnsupportedSchema(version) => {
                write!(f, "unsupported qualification schema {version}")
            }
            Self::UnsupportedPolicy(version) => {
                write!(f, "unsupported qualification policy {version}")
            }
            Self::Json(error) => write!(f, "invalid qualification JSON: {error}"),
        }
    }
}

impl std::error::Error for QualificationError {}

/// Stream role recorded independently of process-scoped inventory identity.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum QualifiedStreamRole {
    Rgb,
    Ir,
}

/// Positive frame interval represented exactly and canonically.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ExactInterval {
    numerator: u32,
    denominator: u32,
}

impl ExactInterval {
    /// Construct a reduced positive interval.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationError::ZeroInterval`] when either component is zero.
    pub fn new(numerator: u32, denominator: u32) -> Result<Self, QualificationError> {
        if numerator == 0 || denominator == 0 {
            return Err(QualificationError::ZeroInterval);
        }
        let divisor = gcd(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    #[must_use]
    pub const fn parts(self) -> (u32, u32) {
        (self.numerator, self.denominator)
    }

    fn validate(self) -> Result<(), QualificationError> {
        if self.numerator == 0
            || self.denominator == 0
            || gcd(self.numerator, self.denominator) != 1
        {
            return Err(QualificationError::InvalidEvidence);
        }
        Ok(())
    }
}

const fn gcd(mut left: u32, mut right: u32) -> u32 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

/// USB and backend facts whose change invalidates a measurement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionContext {
    controller_path: String,
    speed_mbps: u32,
    driver: String,
    backend: String,
}

impl ConnectionContext {
    /// Construct the USB connection facts that scope a measurement.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid controller path, zero speed, or empty
    /// driver/backend identifier.
    pub fn new(
        controller_path: String,
        speed_mbps: u32,
        driver: String,
        backend: String,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            controller_path,
            speed_mbps,
            driver,
            backend,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        validate_path(&self.controller_path)?;
        if self.speed_mbps == 0 {
            return Err(QualificationError::InvalidEvidence);
        }
        validate_text(&self.driver)?;
        validate_text(&self.backend)
    }
}

/// Persistent identity of one endpoint, collected from its opened fd.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CameraEndpoint {
    descriptor_sha256: String,
    vid: u16,
    pid: u16,
    serial: Option<String>,
    interface_number: u8,
    usb_devpath: String,
    role: QualifiedStreamRole,
    connection: ConnectionContext,
}

impl CameraEndpoint {
    /// Construct one fd-derived endpoint identity.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed descriptor digest, serial, sysfs path,
    /// or connection context.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        descriptor_sha256: String,
        vid: u16,
        pid: u16,
        serial: Option<String>,
        interface_number: u8,
        usb_devpath: String,
        role: QualifiedStreamRole,
        connection: ConnectionContext,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            descriptor_sha256,
            vid,
            pid,
            serial,
            interface_number,
            usb_devpath,
            role,
            connection,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        if self.descriptor_sha256.len() != 64
            || !self
                .descriptor_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(QualificationError::InvalidDigest);
        }
        if let Some(serial) = &self.serial {
            validate_text(serial)?;
        }
        validate_path(&self.usb_devpath)?;
        self.connection.validate()
    }

    /// Stable, injection-safe filename material for this endpoint.
    #[must_use]
    pub fn filing_key(&self) -> String {
        let serial = self.serial.as_deref().unwrap_or("");
        irlume_common::sha256_hex(
            format!(
                "descriptor:{}:{}|vid:{:04x}|pid:{:04x}|serial:{}:{}|interface:{}|port:{}:{}|role:{:?}",
                self.descriptor_sha256.len(),
                self.descriptor_sha256,
                self.vid,
                self.pid,
                serial.len(),
                serial,
                self.interface_number,
                self.usb_devpath.len(),
                self.usb_devpath,
                self.role,
            )
            .as_bytes(),
        )
    }

    #[cfg(test)]
    fn clear_serial_for_test(&mut self) {
        self.serial = None;
    }
}

/// The stream irlume requested before the driver adjusted it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestedStream {
    width: u32,
    height: u32,
    fourcc: String,
    interval: ExactInterval,
}

impl RequestedStream {
    /// Construct the exact stream request.
    ///
    /// # Errors
    ///
    /// Returns an error for zero geometry, a malformed fourcc, or an invalid interval.
    pub fn new(
        width: u32,
        height: u32,
        fourcc: String,
        interval: ExactInterval,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            width,
            height,
            fourcc,
            interval,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        validate_geometry(self.width, self.height)?;
        validate_fourcc(&self.fourcc)?;
        self.interval.validate()
    }
}

/// Every relevant field the driver returned after format and interval setup.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptedStream {
    width: u32,
    height: u32,
    fourcc: String,
    stride: u32,
    image_size: u32,
    field_order: u32,
    colorspace: u32,
    quantization: u32,
    transfer: u32,
    flags: u32,
    interval: ExactInterval,
}

impl AcceptedStream {
    /// Construct the complete format and interval echoed by the driver.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid geometry, fourcc, stride, image size, or interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        width: u32,
        height: u32,
        fourcc: String,
        stride: u32,
        image_size: u32,
        field_order: u32,
        colorspace: u32,
        quantization: u32,
        transfer: u32,
        flags: u32,
        interval: ExactInterval,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            width,
            height,
            fourcc,
            stride,
            image_size,
            field_order,
            colorspace,
            quantization,
            transfer,
            flags,
            interval,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        validate_geometry(self.width, self.height)?;
        validate_fourcc(&self.fourcc)?;
        if self.stride == 0 || self.image_size == 0 {
            return Err(QualificationError::InvalidEvidence);
        }
        self.interval.validate()
    }
}

/// Exact requested, accepted, and minimum-rate contract for one role.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamContract {
    role: QualifiedStreamRole,
    requested: RequestedStream,
    accepted: AcceptedStream,
    minimum_interval: ExactInterval,
}

impl StreamContract {
    /// Bind the requested, accepted, and minimum-rate facts for one role.
    ///
    /// # Errors
    ///
    /// Returns an error when any nested stream fact is invalid.
    pub fn new(
        role: QualifiedStreamRole,
        requested: RequestedStream,
        accepted: AcceptedStream,
        minimum_interval: ExactInterval,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            role,
            requested,
            accepted,
            minimum_interval,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        self.requested.validate()?;
        self.accepted.validate()?;
        self.minimum_interval.validate()
    }
}

/// All persistent facts that must match before concurrent capture is selected.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QualificationContext {
    rgb_endpoint: CameraEndpoint,
    ir_endpoint: CameraEndpoint,
    rgb_stream: StreamContract,
    ir_stream: StreamContract,
}

impl QualificationContext {
    /// Construct the exact pair context a qualification may authorize.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint/stream roles disagree or nested facts are invalid.
    pub fn new(
        rgb_endpoint: CameraEndpoint,
        ir_endpoint: CameraEndpoint,
        rgb_stream: StreamContract,
        ir_stream: StreamContract,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            rgb_endpoint,
            ir_endpoint,
            rgb_stream,
            ir_stream,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        if self.rgb_endpoint.role != QualifiedStreamRole::Rgb
            || self.rgb_stream.role != QualifiedStreamRole::Rgb
            || self.ir_endpoint.role != QualifiedStreamRole::Ir
            || self.ir_stream.role != QualifiedStreamRole::Ir
        {
            return Err(QualificationError::InvalidRole);
        }
        self.rgb_endpoint.validate()?;
        self.ir_endpoint.validate()?;
        self.rgb_stream.validate()?;
        self.ir_stream.validate()
    }

    #[must_use]
    pub const fn rgb_endpoint(&self) -> &CameraEndpoint {
        &self.rgb_endpoint
    }
    #[must_use]
    pub const fn ir_endpoint(&self) -> &CameraEndpoint {
        &self.ir_endpoint
    }
    #[must_use]
    pub const fn rgb_stream(&self) -> &StreamContract {
        &self.rgb_stream
    }
    #[must_use]
    pub const fn ir_stream(&self) -> &StreamContract {
        &self.ir_stream
    }
}

/// Summary of one sequential or concurrent probe arm.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ArmEvidence {
    requested_rounds: u32,
    completed_rounds: u32,
    failed_rounds: u32,
    meets_rate_floor: bool,
    continuous: bool,
    rgb_mean: f32,
    ir_mean: f32,
    elapsed_ms: u64,
}

impl ArmEvidence {
    /// Construct a bounded summary of one probe arm.
    ///
    /// # Errors
    ///
    /// Returns an error for zero requested rounds, impossible counts, or non-finite means.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requested_rounds: u32,
        completed_rounds: u32,
        failed_rounds: u32,
        meets_rate_floor: bool,
        continuous: bool,
        rgb_mean: f32,
        ir_mean: f32,
        elapsed_ms: u64,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            requested_rounds,
            completed_rounds,
            failed_rounds,
            meets_rate_floor,
            continuous,
            rgb_mean,
            ir_mean,
            elapsed_ms,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        if self.requested_rounds == 0
            || self.completed_rounds.saturating_add(self.failed_rounds) > self.requested_rounds
            || !self.rgb_mean.is_finite()
            || !self.ir_mean.is_finite()
            || self.rgb_mean < 0.0
            || self.ir_mean < 0.0
        {
            return Err(QualificationError::InvalidEvidence);
        }
        Ok(())
    }

    fn complete_and_healthy(&self) -> bool {
        self.completed_rounds == self.requested_rounds
            && self.failed_rounds == 0
            && self.meets_rate_floor
            && self.continuous
    }
}

/// Conclusive reason the measured pair must stay sequential.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SequentialReason {
    ConcurrentOpenOrArmFailed,
    DeliveredRateShortfall,
    SignalLoss,
    InvalidProvenance,
}

/// Why an attempt cannot replace authoritative state.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InconclusiveReason {
    IncompleteRounds,
    DimScene,
    ContractDrift,
    MissingProvenance,
}

/// What one controlled measurement established.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind", content = "reason")]
pub enum AttemptOutcome {
    ConcurrentQualified,
    SequentialRequired(SequentialReason),
    Inconclusive(InconclusiveReason),
}

/// One measurement and all evidence needed to interpret it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct QualificationAttempt {
    measured_at_unix: u64,
    context: QualificationContext,
    sequential: ArmEvidence,
    concurrent: ArmEvidence,
    outcome: AttemptOutcome,
}

impl QualificationAttempt {
    /// Construct and validate one complete qualification attempt.
    ///
    /// # Errors
    ///
    /// Returns an error when the evidence does not support the claimed outcome.
    pub fn new(
        measured_at_unix: u64,
        context: QualificationContext,
        sequential: ArmEvidence,
        concurrent: ArmEvidence,
        outcome: AttemptOutcome,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            measured_at_unix,
            context,
            sequential,
            concurrent,
            outcome,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        self.context.validate()?;
        self.sequential.validate()?;
        self.concurrent.validate()?;
        if self.measured_at_unix == 0 {
            return Err(QualificationError::InvalidEvidence);
        }
        match self.outcome {
            AttemptOutcome::ConcurrentQualified => {
                let ratios_healthy = retained(self.concurrent.rgb_mean, self.sequential.rgb_mean)
                    >= CONCURRENT_SIGNAL_FLOOR
                    && retained(self.concurrent.ir_mean, self.sequential.ir_mean)
                        >= CONCURRENT_SIGNAL_FLOOR;
                if !self.sequential.complete_and_healthy()
                    || !self.concurrent.complete_and_healthy()
                    || self.sequential.rgb_mean < CONCLUSIVE_RGB_MEAN
                    || !ratios_healthy
                {
                    return Err(QualificationError::InvalidEvidence);
                }
            }
            AttemptOutcome::SequentialRequired(reason) => {
                if !self.sequential.complete_and_healthy() {
                    return Err(QualificationError::InvalidEvidence);
                }
                let supported = match reason {
                    SequentialReason::ConcurrentOpenOrArmFailed => {
                        self.concurrent.completed_rounds == 0
                            && self.concurrent.failed_rounds == self.concurrent.requested_rounds
                    }
                    SequentialReason::DeliveredRateShortfall => !self.concurrent.meets_rate_floor,
                    SequentialReason::SignalLoss => {
                        retained(self.concurrent.rgb_mean, self.sequential.rgb_mean)
                            < CONCURRENT_SIGNAL_FLOOR
                            || retained(self.concurrent.ir_mean, self.sequential.ir_mean)
                                < CONCURRENT_SIGNAL_FLOOR
                    }
                    SequentialReason::InvalidProvenance => !self.concurrent.continuous,
                };
                if !supported {
                    return Err(QualificationError::InvalidEvidence);
                }
            }
            AttemptOutcome::Inconclusive(_) => {}
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(&self) -> &QualificationContext {
        &self.context
    }

    fn authoritative(&self) -> bool {
        !matches!(self.outcome, AttemptOutcome::Inconclusive(_))
    }
}

fn retained(held: f32, solo: f32) -> f32 {
    if solo <= f32::EPSILON {
        1.0
    } else {
        held / solo
    }
}

/// A complete, atomically published state record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CaptureQualificationRecord {
    schema_version: u32,
    policy_version: u32,
    revision: u64,
    last_attempt: QualificationAttempt,
    authoritative: Option<QualificationAttempt>,
}

impl CaptureQualificationRecord {
    /// Construct one complete record at `revision`.
    ///
    /// # Errors
    ///
    /// Returns an error for zero revision, invalid attempts, or inconclusive authority.
    pub fn new(
        revision: u64,
        last_attempt: QualificationAttempt,
        authoritative: Option<QualificationAttempt>,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            schema_version: SCHEMA_VERSION,
            policy_version: POLICY_VERSION,
            revision,
            last_attempt,
            authoritative,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(QualificationError::UnsupportedSchema(self.schema_version));
        }
        if self.policy_version != POLICY_VERSION {
            return Err(QualificationError::UnsupportedPolicy(self.policy_version));
        }
        if self.revision == 0 {
            return Err(QualificationError::InvalidEvidence);
        }
        self.last_attempt.validate()?;
        if let Some(authoritative) = &self.authoritative {
            authoritative.validate()?;
            if !authoritative.authoritative() {
                return Err(QualificationError::InconclusiveAuthority);
            }
        }
        Ok(())
    }

    /// Serialize a record only after revalidating all authorization invariants.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is invalid or serialization fails.
    pub fn to_json(&self) -> Result<String, QualificationError> {
        self.validate()?;
        serde_json::to_string_pretty(self)
            .map_err(|error| QualificationError::Json(error.to_string()))
    }

    /// Parse a bounded record and revalidate every authorization invariant.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, unsupported, or inconsistent input.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(QualificationError::RecordTooLarge);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| QualificationError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    /// Resolve only exact, conclusive authority. Every mismatch is unqualified.
    #[must_use]
    pub fn resolve(&self, current: &QualificationContext) -> QualificationResolution {
        let Some(authoritative) = &self.authoritative else {
            return QualificationResolution::Unqualified(QualificationMismatch::NoAuthority);
        };
        if &authoritative.context != current {
            return QualificationResolution::Unqualified(QualificationMismatch::ContextChanged);
        }
        match authoritative.outcome {
            AttemptOutcome::ConcurrentQualified => QualificationResolution::ConcurrentQualified,
            AttemptOutcome::SequentialRequired(reason) => {
                QualificationResolution::SequentialRequired(reason)
            }
            AttemptOutcome::Inconclusive(_) => {
                QualificationResolution::Unqualified(QualificationMismatch::NoAuthority)
            }
        }
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn last_attempt(&self) -> &QualificationAttempt {
        &self.last_attempt
    }

    #[must_use]
    pub const fn authoritative(&self) -> Option<&QualificationAttempt> {
        self.authoritative.as_ref()
    }
}

/// Why the safe sequential default was selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QualificationMismatch {
    NoAuthority,
    ContextChanged,
}

/// Exact qualification answer for an operation context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QualificationResolution {
    ConcurrentQualified,
    SequentialRequired(SequentialReason),
    Unqualified(QualificationMismatch),
}

/// Failure to read or atomically update the machine qualification store.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum QualificationStoreError {
    Io(String),
    InvalidRecord(QualificationError),
    StaleRevision {
        expected: Option<u64>,
        actual: Option<u64>,
    },
    RevisionExhausted,
    /// The new record is visible, but its directory fsync failed.
    VisibleNotDurable(String),
}

impl std::fmt::Display for QualificationStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => f.write_str(error),
            Self::InvalidRecord(error) => write!(f, "invalid qualification record: {error}"),
            Self::StaleRevision { expected, actual } => write!(
                f,
                "qualification revision changed (expected {expected:?}, actual {actual:?})"
            ),
            Self::RevisionExhausted => f.write_str("qualification revision is exhausted"),
            Self::VisibleNotDurable(error) => write!(
                f,
                "qualification was published but may not survive power loss: {error}"
            ),
        }
    }
}

impl std::error::Error for QualificationStoreError {}

impl From<QualificationError> for QualificationStoreError {
    fn from(value: QualificationError) -> Self {
        Self::InvalidRecord(value)
    }
}

/// Root-owned, atomic store of context-bound capture qualifications.
#[derive(Clone, Debug)]
pub struct QualificationStore {
    dir: PathBuf,
}

impl QualificationStore {
    /// The production machine-state store.
    #[must_use]
    pub fn system() -> Self {
        Self::at(irlume_common::state_dir().join("capture-qualifications"))
    }

    fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Load this physical pair's record. Absence means unqualified.
    ///
    /// # Errors
    ///
    /// Returns an error when the context is invalid or the live record cannot be trusted.
    pub fn load(
        &self,
        context: &QualificationContext,
    ) -> Result<Option<CaptureQualificationRecord>, QualificationStoreError> {
        context.validate()?;
        read_record(&self.record_path(context))
    }

    /// Compare-and-set one probe attempt under the pair's stable lock.
    ///
    /// A conclusive attempt becomes authoritative. An inconclusive attempt is
    /// retained for diagnostics while any previous authority remains intact.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid evidence, I/O or durability failure, or a
    /// compare-and-set revision mismatch.
    pub fn save_attempt(
        &self,
        attempt: QualificationAttempt,
        expected_revision: Option<u64>,
    ) -> Result<CaptureQualificationRecord, QualificationStoreError> {
        attempt.validate()?;
        self.ensure_dir()?;
        let path = self.record_path(attempt.context());
        let _lock = StoreLock::acquire(&path.with_extension("lock"))?;
        let previous = read_record(&path)?;
        let actual_revision = previous.as_ref().map(CaptureQualificationRecord::revision);
        if actual_revision != expected_revision {
            return Err(QualificationStoreError::StaleRevision {
                expected: expected_revision,
                actual: actual_revision,
            });
        }
        let revision = actual_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(QualificationStoreError::RevisionExhausted)?;
        let authoritative = if attempt.authoritative() {
            Some(attempt.clone())
        } else {
            previous.and_then(|record| record.authoritative)
        };
        let record = CaptureQualificationRecord::new(revision, attempt, authoritative)?;
        let mut body = record.to_json()?.into_bytes();
        body.push(b'\n');
        if body.len() > MAX_RECORD_BYTES {
            return Err(QualificationError::RecordTooLarge.into());
        }
        match irlume_common::write_atomic_reporting(&path, &body, 0o600)
            .map_err(|error| io_error("publish", &path, &error))?
        {
            irlume_common::AtomicWrite::Durable => Ok(record),
            irlume_common::AtomicWrite::VisibleNotDurable(error) => Err(
                QualificationStoreError::VisibleNotDurable(format!("{}: {error}", path.display())),
            ),
        }
    }

    fn ensure_dir(&self) -> Result<(), QualificationStoreError> {
        let existed = self.dir.exists();
        std::fs::create_dir_all(&self.dir)
            .map_err(|error| io_error("create", &self.dir, &error))?;
        irlume_common::restrict(&self.dir, 0o700).map_err(QualificationStoreError::Io)?;
        if !existed {
            irlume_common::fsync_ancestors(&self.dir).map_err(QualificationStoreError::Io)?;
        }
        Ok(())
    }

    fn record_path(&self, context: &QualificationContext) -> PathBuf {
        self.dir.join(format!("{}.json", pair_filing_key(context)))
    }

    #[cfg(test)]
    fn record_path_for_test(&self, context: &QualificationContext) -> PathBuf {
        self.record_path(context)
    }
}

fn pair_filing_key(context: &QualificationContext) -> String {
    let rgb = context.rgb_endpoint.filing_key();
    let ir = context.ir_endpoint.filing_key();
    irlume_common::sha256_hex(format!("rgb:{}:{rgb}|ir:{}:{ir}", rgb.len(), ir.len()).as_bytes())
}

fn read_record(path: &Path) -> Result<Option<CaptureQualificationRecord>, QualificationStoreError> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("open", path, &error)),
    };
    let mut body = Vec::new();
    file.by_ref()
        .take((MAX_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|error| io_error("read", path, &error))?;
    if body.len() > MAX_RECORD_BYTES {
        return Err(QualificationError::RecordTooLarge.into());
    }
    CaptureQualificationRecord::from_json(&body)
        .map(Some)
        .map_err(Into::into)
}

struct StoreLock {
    _file: std::fs::File,
}

impl StoreLock {
    fn acquire(path: &Path) -> Result<Self, QualificationStoreError> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .map_err(|error| io_error("open lock", path, &error))?;
            // SAFETY: flock observes but does not take ownership of this live fd.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(io_error("lock", path, &std::io::Error::last_os_error()));
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
                .map_err(|error| io_error("open lock", path, &error))?;
            Ok(Self { _file: file })
        }
    }
}

fn io_error(action: &str, path: &Path, error: &std::io::Error) -> QualificationStoreError {
    QualificationStoreError::Io(format!("{action} {}: {error}", path.display()))
}

fn validate_text(value: &str) -> Result<(), QualificationError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
        return Err(QualificationError::InvalidText);
    }
    Ok(())
}

fn validate_path(value: &str) -> Result<(), QualificationError> {
    validate_text(value)?;
    if !value.starts_with("/devices/") || value.contains("/../") {
        return Err(QualificationError::InvalidPath);
    }
    Ok(())
}

fn validate_fourcc(value: &str) -> Result<(), QualificationError> {
    if value.len() != 4 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(QualificationError::InvalidFourcc);
    }
    Ok(())
}

fn validate_geometry(width: u32, height: u32) -> Result<(), QualificationError> {
    if width == 0 || height == 0 {
        return Err(QualificationError::InvalidEvidence);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempStore {
        path: std::path::PathBuf,
    }

    impl TempStore {
        fn new(label: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "irlume-capture-qualification-{label}-{}-{id}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn store(&self) -> QualificationStore {
            QualificationStore::at(self.path.clone())
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn endpoint(role: QualifiedStreamRole, port: &str) -> CameraEndpoint {
        CameraEndpoint::new(
            "ab".repeat(32),
            0x046d,
            0x085e,
            Some("batch-serial".into()),
            match role {
                QualifiedStreamRole::Rgb => 0,
                QualifiedStreamRole::Ir => 2,
            },
            port.into(),
            role,
            ConnectionContext::new(
                "/devices/pci0000:00/0000:00:14.0".into(),
                5_000,
                "uvcvideo".into(),
                "v4l2-uvc".into(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn stream(role: QualifiedStreamRole, fourcc: &str, height: u32) -> StreamContract {
        StreamContract::new(
            role,
            RequestedStream::new(
                640,
                height,
                fourcc.into(),
                ExactInterval::new(1, 30).unwrap(),
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
                ExactInterval::new(1, 30).unwrap(),
            )
            .unwrap(),
            ExactInterval::new(1, 24).unwrap(),
        )
        .unwrap()
    }

    fn context(port: &str) -> QualificationContext {
        QualificationContext::new(
            endpoint(QualifiedStreamRole::Rgb, port),
            endpoint(QualifiedStreamRole::Ir, port),
            stream(QualifiedStreamRole::Rgb, "YUYV", 480),
            stream(QualifiedStreamRole::Ir, "GREY", 400),
        )
        .unwrap()
    }

    fn arm(rounds: u32) -> ArmEvidence {
        ArmEvidence::new(rounds, rounds, 0, true, true, 140.0, 120.0, 850).unwrap()
    }

    fn concurrent_attempt(port: &str) -> QualificationAttempt {
        QualificationAttempt::new(
            1_786_944_000,
            context(port),
            arm(6),
            arm(6),
            AttemptOutcome::ConcurrentQualified,
        )
        .unwrap()
    }

    #[test]
    fn complete_concurrent_record_round_trips_and_authorizes_only_exact_context() {
        let attempt = concurrent_attempt("/devices/pci0000:00/usb3/3-2");
        let record = CaptureQualificationRecord::new(7, attempt.clone(), Some(attempt.clone()))
            .expect("valid record");
        let body = record.to_json().expect("serialize");
        let decoded = CaptureQualificationRecord::from_json(body.as_bytes()).expect("parse");

        assert_eq!(decoded, record);
        assert_eq!(
            decoded.resolve(attempt.context()),
            QualificationResolution::ConcurrentQualified
        );

        let moved = context("/devices/pci0000:00/usb2/2-1");
        assert!(matches!(
            decoded.resolve(&moved),
            QualificationResolution::Unqualified(QualificationMismatch::ContextChanged)
        ));
    }

    #[test]
    fn one_stream_tuple_change_invalidates_concurrent_authority() {
        let attempt = concurrent_attempt("/devices/pci0000:00/usb3/3-2");
        let record =
            CaptureQualificationRecord::new(1, attempt.clone(), Some(attempt.clone())).unwrap();
        let changed = QualificationContext::new(
            attempt.context().rgb_endpoint().clone(),
            attempt.context().ir_endpoint().clone(),
            stream(QualifiedStreamRole::Rgb, "NV12", 480),
            attempt.context().ir_stream().clone(),
        )
        .unwrap();

        assert!(matches!(
            record.resolve(&changed),
            QualificationResolution::Unqualified(QualificationMismatch::ContextChanged)
        ));
    }

    #[test]
    fn inconclusive_attempt_cannot_become_authoritative() {
        let ctx = context("/devices/pci0000:00/usb3/3-2");
        let attempt = QualificationAttempt::new(
            1_786_944_000,
            ctx,
            arm(6),
            ArmEvidence::new(6, 3, 3, false, false, 80.0, 90.0, 2_000).unwrap(),
            AttemptOutcome::Inconclusive(InconclusiveReason::IncompleteRounds),
        )
        .unwrap();

        let error = CaptureQualificationRecord::new(1, attempt.clone(), Some(attempt))
            .expect_err("inconclusive evidence must not authorize");
        assert_eq!(error, QualificationError::InconclusiveAuthority);
    }

    #[test]
    fn weak_or_malformed_evidence_is_rejected() {
        assert_eq!(
            ExactInterval::new(0, 30),
            Err(QualificationError::ZeroInterval)
        );
        assert!(
            RequestedStream::new(640, 480, "RGB".into(), ExactInterval::new(1, 30).unwrap())
                .is_err()
        );
        assert!(CameraEndpoint::new(
            "not-a-digest".into(),
            1,
            2,
            None,
            0,
            "/devices/x".into(),
            QualifiedStreamRole::Rgb,
            ConnectionContext::new(
                "/devices/controller".into(),
                480,
                "uvcvideo".into(),
                "v4l2-uvc".into()
            )
            .unwrap()
        )
        .is_err());
    }

    #[test]
    fn future_schema_and_oversized_records_fail_closed() {
        let attempt = concurrent_attempt("/devices/pci0000:00/usb3/3-2");
        let record = CaptureQualificationRecord::new(1, attempt.clone(), Some(attempt)).unwrap();
        let mut future: serde_json::Value =
            serde_json::from_str(&record.to_json().unwrap()).unwrap();
        future["schema_version"] = serde_json::json!(999);
        let future = serde_json::to_vec(&future).unwrap();
        assert_eq!(
            CaptureQualificationRecord::from_json(&future),
            Err(QualificationError::UnsupportedSchema(999))
        );
        assert_eq!(
            CaptureQualificationRecord::from_json(&vec![b' '; MAX_RECORD_BYTES + 1]),
            Err(QualificationError::RecordTooLarge)
        );
    }

    #[test]
    fn serial_less_identical_units_on_different_ports_have_different_keys() {
        let mut first = endpoint(QualifiedStreamRole::Rgb, "/devices/usb3/3-1");
        let mut second = endpoint(QualifiedStreamRole::Rgb, "/devices/usb3/3-2");
        first.clear_serial_for_test();
        second.clear_serial_for_test();
        assert_ne!(first.filing_key(), second.filing_key());
    }

    #[test]
    fn store_publishes_one_atomic_0600_record_and_loads_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempStore::new("round-trip");
        let store = temp.store();
        let attempt = concurrent_attempt("/devices/pci0000:00/usb3/3-2");
        let written = store
            .save_attempt(attempt.clone(), None)
            .expect("first publish");
        assert_eq!(written.revision(), 1);

        let loaded = store
            .load(attempt.context())
            .expect("load")
            .expect("record");
        assert_eq!(loaded, written);
        let path = store.record_path_for_test(attempt.context());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(std::fs::read_dir(&temp.path)
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp.")));
    }

    #[test]
    fn store_compare_and_set_refuses_a_stale_measurement() {
        let temp = TempStore::new("cas");
        let store = temp.store();
        let first = concurrent_attempt("/devices/pci0000:00/usb3/3-2");
        store.save_attempt(first.clone(), None).unwrap();

        assert_eq!(
            store.save_attempt(first, None),
            Err(QualificationStoreError::StaleRevision {
                expected: None,
                actual: Some(1),
            })
        );
    }

    #[test]
    fn inconclusive_retest_updates_diagnostics_without_erasing_authority() {
        let temp = TempStore::new("inconclusive");
        let store = temp.store();
        let conclusive = concurrent_attempt("/devices/pci0000:00/usb3/3-2");
        store.save_attempt(conclusive.clone(), None).unwrap();
        let inconclusive = QualificationAttempt::new(
            1_786_944_001,
            conclusive.context().clone(),
            arm(6),
            ArmEvidence::new(6, 4, 2, false, false, 80.0, 90.0, 2_000).unwrap(),
            AttemptOutcome::Inconclusive(InconclusiveReason::IncompleteRounds),
        )
        .unwrap();

        let updated = store.save_attempt(inconclusive.clone(), Some(1)).unwrap();
        assert_eq!(updated.revision(), 2);
        assert_eq!(updated.last_attempt(), &inconclusive);
        assert_eq!(updated.authoritative(), Some(&conclusive));
        assert_eq!(
            updated.resolve(conclusive.context()),
            QualificationResolution::ConcurrentQualified
        );
    }
}
