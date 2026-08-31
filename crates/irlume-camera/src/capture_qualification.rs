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
/// Version of the measurement engine that produced persisted arm evidence.
pub const PRODUCER_ENGINE_VERSION: u32 = 1;
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
    System(String),
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
            Self::System(error) => f.write_str(error),
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

/// Positive frame rate in frames per second, represented exactly and canonically.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ExactRate {
    numerator: u32,
    denominator: u32,
}

impl ExactRate {
    /// Construct a reduced positive rate.
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
    /// Exact sysfs link speed in thousandths of a megabit per second.
    speed_millimbps: u64,
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
        speed_millimbps: u64,
        driver: String,
        backend: String,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            controller_path,
            speed_millimbps,
            driver,
            backend,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        validate_path(&self.controller_path)?;
        if self.speed_millimbps == 0 {
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

    /// Collect persistent identity and USB connection facts from a live camera fd.
    ///
    /// `backend` names the capture implementation that negotiated this endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when fd identity, descriptors, topology, link speed, or
    /// driver facts cannot be read and validated.
    pub fn from_fd(
        fd: std::os::fd::RawFd,
        role: QualifiedStreamRole,
        backend: &str,
    ) -> Result<Self, QualificationError> {
        let observed = crate::uvc_descriptor::identity_and_connection_from_fd(fd)
            .map_err(|error| QualificationError::System(error.to_string()))?;
        let identity = observed.identity;
        let connection = ConnectionContext::new(
            observed.connection.controller_devpath,
            observed.connection.speed_millimbps,
            observed.connection.driver,
            backend.to_owned(),
        )?;
        Self::new(
            irlume_common::sha256_hex(&identity.descriptors),
            identity.vid,
            identity.pid,
            identity.serial,
            identity.interface_number,
            identity.usb_devpath,
            role,
            connection,
        )
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

    #[must_use]
    pub const fn interval(&self) -> ExactInterval {
        self.interval
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

    #[must_use]
    pub const fn interval(&self) -> ExactInterval {
        self.interval
    }
}

/// Exact requested, accepted, and minimum-rate contract for one role.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamContract {
    role: QualifiedStreamRole,
    requested: RequestedStream,
    accepted: AcceptedStream,
    minimum_rate: ExactRate,
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
        minimum_rate: ExactRate,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            role,
            requested,
            accepted,
            minimum_rate,
        };
        value.validate()?;
        Ok(value)
    }

    /// Snapshot the request and every driver-echoed stream field without floats.
    ///
    /// # Errors
    ///
    /// Returns an error when a fourcc is not printable ASCII or any exact
    /// format/rate fact violates the qualification contract.
    pub(crate) fn from_negotiated(
        role: QualifiedStreamRole,
        requested_width: u32,
        requested_height: u32,
        requested_fourcc: [u8; 4],
        requested_interval: crate::frame_interval::FrameInterval,
        accepted: &v4l::Format,
        accepted_interval: crate::frame_interval::FrameInterval,
    ) -> Result<Self, QualificationError> {
        let requested_fourcc = String::from_utf8(requested_fourcc.to_vec())
            .map_err(|_| QualificationError::InvalidFourcc)?;
        let accepted_fourcc = String::from_utf8(accepted.fourcc.repr.to_vec())
            .map_err(|_| QualificationError::InvalidFourcc)?;
        let (requested_num, requested_den) = requested_interval.parts();
        let (accepted_num, accepted_den) = accepted_interval.parts();
        let minimum_rate = match role {
            QualifiedStreamRole::Rgb => ExactRate::new(
                crate::rate_gate::RGB_FLOOR_NUM,
                crate::rate_gate::RGB_FLOOR_DEN,
            )?,
            QualifiedStreamRole::Ir => ExactRate::new(
                crate::rate_gate::IR_FLOOR_NUM,
                crate::rate_gate::IR_FLOOR_DEN,
            )?,
        };
        Self::new(
            role,
            RequestedStream::new(
                requested_width,
                requested_height,
                requested_fourcc,
                ExactInterval::new(requested_num, requested_den)?,
            )?,
            AcceptedStream::new(
                accepted.width,
                accepted.height,
                accepted_fourcc,
                accepted.stride,
                accepted.size,
                accepted.field_order as u32,
                accepted.colorspace as u32,
                accepted.quantization as u32,
                accepted.transfer as u32,
                accepted.flags.bits(),
                ExactInterval::new(accepted_num, accepted_den)?,
            )?,
            minimum_rate,
        )
    }

    fn validate(&self) -> Result<(), QualificationError> {
        self.requested.validate()?;
        self.accepted.validate()?;
        self.minimum_rate.validate()
    }

    #[must_use]
    pub const fn requested(&self) -> &RequestedStream {
        &self.requested
    }

    #[must_use]
    pub const fn accepted(&self) -> &AcceptedStream {
        &self.accepted
    }

    #[must_use]
    pub const fn minimum_rate(&self) -> ExactRate {
        self.minimum_rate
    }

    pub(crate) fn diagnostic_contracts(
        &self,
    ) -> Result<
        (
            irlume_common::diagnostics::ExactStreamContract,
            irlume_common::diagnostics::ExactStreamContract,
        ),
        irlume_common::diagnostics::InvalidDiagnosticValue,
    > {
        use irlume_common::diagnostics::{ExactFraction, ExactStreamContract, FourCc};

        fn fourcc(
            value: &str,
        ) -> Result<FourCc, irlume_common::diagnostics::InvalidDiagnosticValue> {
            let bytes: [u8; 4] = value
                .as_bytes()
                .try_into()
                .map_err(|_| irlume_common::diagnostics::InvalidDiagnosticValue)?;
            FourCc::new(bytes)
        }

        let requested_interval = self.requested.interval.parts();
        let accepted_interval = self.accepted.interval.parts();
        Ok((
            ExactStreamContract {
                width: self.requested.width,
                height: self.requested.height,
                fourcc: fourcc(&self.requested.fourcc)?,
                interval: ExactFraction::new(requested_interval.0, requested_interval.1)?,
            },
            ExactStreamContract {
                width: self.accepted.width,
                height: self.accepted.height,
                fourcc: fourcc(&self.accepted.fourcc)?,
                interval: ExactFraction::new(accepted_interval.0, accepted_interval.1)?,
            },
        ))
    }

    /// Verify that one delivered frame carries this exact accepted format and
    /// the same requested/accepted frame intervals and floor rate used by
    /// qualification.
    pub(crate) fn matches_runtime(
        &self,
        provenance: &crate::frame_provenance::RuntimeFrameProvenance,
    ) -> bool {
        use crate::contracts::StreamRole;

        let role = match self.role {
            QualifiedStreamRole::Rgb => StreamRole::Rgb,
            QualifiedStreamRole::Ir => StreamRole::Ir,
        };
        let format = provenance.format();
        let rate = provenance.rate_evidence();
        let requested_interval = self.requested.interval.parts();
        let accepted_interval = self.accepted.interval.parts();
        provenance.stream_role() == role
            && rate.role() == role
            && self.accepted.fourcc.as_bytes() == format.fourcc()
            && self.accepted.width == format.width()
            && self.accepted.height == format.height()
            && self.accepted.stride == format.stride()
            && self.accepted.image_size == format.image_size()
            && self.accepted.field_order == format.field_order()
            && self.accepted.colorspace == format.colorspace()
            && self.accepted.quantization == format.quantization()
            && self.accepted.transfer == format.transfer()
            && self.accepted.flags == format.flags()
            && rate.requested() == requested_interval
            && rate.accepted() == accepted_interval
            && rate.floor() == self.minimum_rate.parts()
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

    /// Project the exact pair into the structurally share-safe support schema.
    /// Raw sysfs paths and serial values are reduced to topology components,
    /// safe labels, presence, and fixed correlation tokens here, in the module
    /// that owns the unsanitized facts.
    ///
    /// # Errors
    ///
    /// Returns an error when topology components or diagnostic labels cannot
    /// be represented by the bounded support schema.
    pub fn diagnostic_camera_contexts(
        &self,
        rgb_generation: u64,
        ir_generation: u64,
    ) -> Result<
        [irlume_common::diagnostics::SanitizedCameraContext; 2],
        irlume_common::diagnostics::InvalidDiagnosticValue,
    > {
        let qualification_token = irlume_common::diagnostics::DigestToken::from_sha256_hex(
            &self
                .runtime_key()
                .map_err(|_| irlume_common::diagnostics::InvalidDiagnosticValue)?,
        )?;
        Ok([
            diagnostic_camera_context(
                &self.rgb_endpoint,
                &self.rgb_stream,
                rgb_generation,
                Some(qualification_token),
            )?,
            diagnostic_camera_context(
                &self.ir_endpoint,
                &self.ir_stream,
                ir_generation,
                Some(qualification_token),
            )?,
        ])
    }

    /// Stable key over every fact that makes this exact live context equal.
    ///
    /// Unlike the persistent pair filename, this includes connection and
    /// stream-contract fields. It is suitable for process-local health state:
    /// moving the camera, changing link speed, or renegotiating either stream
    /// cannot inherit a degradation observed under another context.
    ///
    /// # Errors
    ///
    /// Returns an error if the validated context cannot be encoded.
    pub fn runtime_key(&self) -> Result<String, QualificationError> {
        let encoded = serde_json::to_vec(self)
            .map_err(|error| QualificationError::Json(error.to_string()))?;
        Ok(irlume_common::sha256_hex(&encoded))
    }
}

pub(crate) fn diagnostic_camera_context(
    endpoint: &CameraEndpoint,
    stream: &StreamContract,
    lifecycle_generation: u64,
    qualification_token: Option<irlume_common::diagnostics::DigestToken>,
) -> Result<
    irlume_common::diagnostics::SanitizedCameraContext,
    irlume_common::diagnostics::InvalidDiagnosticValue,
> {
    use irlume_common::diagnostics::{
        CameraRoleLabel, InvalidDiagnosticValue, SafeLabel, SanitizedCameraContext,
    };

    let controller = std::path::Path::new(&endpoint.connection.controller_path)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(InvalidDiagnosticValue)?;
    let usb_component = std::path::Path::new(&endpoint.usb_devpath)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(InvalidDiagnosticValue)?;
    let (bus, ports) = usb_component
        .split_once('-')
        .ok_or(InvalidDiagnosticValue)?;
    let usb_bus = bus.parse::<u16>().map_err(|_| InvalidDiagnosticValue)?;
    let usb_port_chain = ports
        .split('.')
        .map(|port| port.parse::<u8>().map_err(|_| InvalidDiagnosticValue))
        .collect::<Result<Vec<_>, _>>()?;
    if usb_bus == 0 || usb_port_chain.is_empty() || usb_port_chain.contains(&0) {
        return Err(InvalidDiagnosticValue);
    }
    let (requested, accepted) = stream.diagnostic_contracts()?;
    Ok(SanitizedCameraContext {
        vid: endpoint.vid,
        pid: endpoint.pid,
        role: match endpoint.role {
            QualifiedStreamRole::Rgb => CameraRoleLabel::Rgb,
            QualifiedStreamRole::Ir => CameraRoleLabel::Ir,
        },
        interface_number: endpoint.interface_number,
        driver: SafeLabel::new(endpoint.connection.driver.clone())?,
        backend: SafeLabel::new(endpoint.connection.backend.clone())?,
        speed_millimbps: endpoint.connection.speed_millimbps,
        controller: SafeLabel::new(controller)?,
        usb_bus,
        usb_port_chain,
        lifecycle_generation,
        serial_present: endpoint.serial.is_some(),
        descriptor_token: irlume_common::diagnostics::DigestToken::from_sha256_hex(
            &endpoint.descriptor_sha256,
        )?,
        qualification_token,
        requested,
        accepted,
    })
}

/// Summary of one sequential or concurrent probe arm.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ArmEvidence {
    requested_rounds: u32,
    completed_rounds: u32,
    failed_rounds: u32,
    contract_rounds: u32,
    rate_floor_rounds: u32,
    continuous_rounds: u32,
    active_ir_rounds: u32,
    contract_failures: u32,
    rate_failures: u32,
    continuity_failures: u32,
    illumination_failures: u32,
    open_failures: u32,
    arm_failures: u32,
    capture_failures: u32,
    /// Failed rounds carrying typed below-floor delivery evidence.
    #[serde(default)]
    rate_shortfall_failures: u32,
    /// Per-role typed below-floor details. `None` means a legacy producer did
    /// not record them; `Some(default)` means a fresh arm measured none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_shortfalls: Option<irlume_common::diagnostics::RateShortfallsByRole>,
    /// Per-fact counts of capture-level round failures (#606), naming HOW an
    /// arm's rounds errored (stream delivery, rate-window establishment).
    /// Additive and defaulted, like `rate_shortfall_failures` before it, so
    /// schema-version-2 records written without this field still parse and
    /// revalidate.
    #[serde(default)]
    capture_failure_facts: std::collections::BTreeMap<String, u32>,
    /// Burst frames the camera's illumination metadata classified as lit or
    /// dark, summed over the arm's completed rounds (#606). `None` means the
    /// schema-2 record predates this measurement; `Some(0)` is a measured zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    ir_camera_classified_frames: Option<u32>,
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
        contract_rounds: u32,
        rate_floor_rounds: u32,
        continuous_rounds: u32,
        active_ir_rounds: u32,
        contract_failures: u32,
        rate_failures: u32,
        continuity_failures: u32,
        illumination_failures: u32,
        open_failures: u32,
        arm_failures: u32,
        capture_failures: u32,
        rate_shortfall_failures: u32,
        rate_shortfalls: irlume_common::diagnostics::RateShortfallsByRole,
        capture_failure_facts: std::collections::BTreeMap<String, u32>,
        ir_camera_classified_frames: u32,
        rgb_mean: f32,
        ir_mean: f32,
        elapsed_ms: u64,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            requested_rounds,
            completed_rounds,
            failed_rounds,
            contract_rounds,
            rate_floor_rounds,
            continuous_rounds,
            active_ir_rounds,
            contract_failures,
            rate_failures,
            continuity_failures,
            illumination_failures,
            open_failures,
            arm_failures,
            capture_failures,
            rate_shortfall_failures,
            rate_shortfalls: Some(rate_shortfalls),
            capture_failure_facts,
            ir_camera_classified_frames: Some(ir_camera_classified_frames),
            rgb_mean,
            ir_mean,
            elapsed_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Burst frames the camera's illumination metadata classified as lit or
    /// dark across the arm's completed rounds, or `None` when an older producer
    /// did not record the measurement (#606).
    #[must_use]
    pub const fn ir_camera_classified_frames(&self) -> Option<u32> {
        self.ir_camera_classified_frames
    }

    /// Per-role delivered-rate shortfalls, or `None` for a legacy arm.
    #[must_use]
    pub const fn rate_shortfalls(
        &self,
    ) -> Option<&irlume_common::diagnostics::RateShortfallsByRole> {
        self.rate_shortfalls.as_ref()
    }

    fn validate(&self) -> Result<(), QualificationError> {
        let valid_shortfall =
            |evidence: &irlume_common::diagnostics::RateShortfallEvidence,
             role: irlume_common::diagnostics::CameraRoleLabel| {
                evidence.role == role
                    && evidence.failure_count != 0
                    && evidence.delivered_den != 0
                    && evidence.floor_den != 0
            };
        let rate_shortfalls_valid = self.rate_shortfalls.as_ref().is_none_or(|shortfalls| {
            shortfalls.rgb.as_ref().is_none_or(|evidence| {
                valid_shortfall(evidence, irlume_common::diagnostics::CameraRoleLabel::Rgb)
            }) && shortfalls.ir.as_ref().is_none_or(|evidence| {
                valid_shortfall(evidence, irlume_common::diagnostics::CameraRoleLabel::Ir)
            })
        });
        let exceeds_completed = |healthy: u32, failed: u32| {
            healthy
                .checked_add(failed)
                .is_none_or(|total| total > self.completed_rounds)
        };
        if self.requested_rounds == 0
            || self.completed_rounds.saturating_add(self.failed_rounds) > self.requested_rounds
            || self.contract_rounds > self.completed_rounds
            || self.rate_floor_rounds > self.completed_rounds
            || self.continuous_rounds > self.completed_rounds
            || self.active_ir_rounds > self.completed_rounds
            || self.contract_failures > self.completed_rounds
            || self.rate_failures > self.completed_rounds
            || self.continuity_failures > self.completed_rounds
            || self.illumination_failures > self.completed_rounds
            || exceeds_completed(self.contract_rounds, self.contract_failures)
            || exceeds_completed(self.rate_floor_rounds, self.rate_failures)
            || exceeds_completed(self.continuous_rounds, self.continuity_failures)
            || exceeds_completed(self.active_ir_rounds, self.illumination_failures)
            || self
                .open_failures
                .checked_add(self.arm_failures)
                .and_then(|total| total.checked_add(self.capture_failures))
                .and_then(|total| total.checked_add(self.rate_shortfall_failures))
                != Some(self.failed_rounds)
            || !self.rgb_mean.is_finite()
            || !self.ir_mean.is_finite()
            || self.rgb_mean < 0.0
            || self.ir_mean < 0.0
            || !rate_shortfalls_valid
        {
            return Err(QualificationError::InvalidEvidence);
        }
        Ok(())
    }

    fn complete_and_healthy(&self) -> bool {
        self.rounds_complete() && self.complete_provenance()
    }

    fn rounds_complete(&self) -> bool {
        self.completed_rounds == self.requested_rounds && self.failed_rounds == 0
    }

    fn provenance_accounted(&self) -> bool {
        self.contract_rounds.checked_add(self.contract_failures) == Some(self.completed_rounds)
            && self.rate_floor_rounds.checked_add(self.rate_failures) == Some(self.completed_rounds)
            && self.continuous_rounds.checked_add(self.continuity_failures)
                == Some(self.completed_rounds)
            && self
                .active_ir_rounds
                .checked_add(self.illumination_failures)
                == Some(self.completed_rounds)
    }

    fn complete_provenance(&self) -> bool {
        self.contract_rounds == self.completed_rounds
            && self.rate_floor_rounds == self.completed_rounds
            && self.continuous_rounds == self.completed_rounds
            && self.active_ir_rounds == self.completed_rounds
            && self.contract_failures == 0
            && self.rate_failures == 0
            && self.continuity_failures == 0
            && self.illumination_failures == 0
    }
}

/// Conclusive reason the measured pair must stay sequential.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SequentialReason {
    ConcurrentUnavailable,
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

/// Whether the IR image node's MS-XU metadata sibling was discoverable when
/// a measurement ran (#568).
///
/// Evidence, never authorization: this is recorded on the attempt so a
/// support reader can tell a metadata-capable pair from a metadata-less one,
/// and deliberately NOT on [`QualificationContext`], whose equality and
/// runtime key gate stored authority. A camera gaining or losing its
/// metadata node cannot invalidate a stored qualification, because
/// illumination ingestion is opportunistic by design.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IlluminationMetadataPresence {
    /// A same-interface sibling above the IR node offered the UVCM format.
    Present,
    /// No sibling offered it, or the diagnostic kill switch was set.
    Absent,
}

/// One measurement and all evidence needed to interpret it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct QualificationAttempt {
    producer_engine_version: u32,
    measured_at_unix: u64,
    context: QualificationContext,
    sequential: ArmEvidence,
    concurrent: ArmEvidence,
    trailing_sequential_control: bool,
    outcome: AttemptOutcome,
    /// MS-XU illumination metadata node presence for the IR endpoint.
    /// `None` means "not recorded" (every record written before #568).
    ir_illumination_metadata: Option<IlluminationMetadataPresence>,
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
        trailing_sequential_control: bool,
        outcome: AttemptOutcome,
        ir_illumination_metadata: Option<IlluminationMetadataPresence>,
    ) -> Result<Self, QualificationError> {
        let value = Self {
            producer_engine_version: PRODUCER_ENGINE_VERSION,
            measured_at_unix,
            context,
            sequential,
            concurrent,
            trailing_sequential_control,
            outcome,
            ir_illumination_metadata,
        };
        value.validate()?;
        Ok(value)
    }

    /// MS-XU illumination metadata node presence observed for the IR endpoint,
    /// or `None` when the attempt predates #568.
    #[must_use]
    pub const fn ir_illumination_metadata(&self) -> Option<IlluminationMetadataPresence> {
        self.ir_illumination_metadata
    }

    /// Per-role delivered-rate shortfalls projected by capture schedule.
    #[must_use]
    pub fn rate_shortfalls(&self) -> irlume_common::diagnostics::RateShortfallsByArm {
        irlume_common::diagnostics::RateShortfallsByArm {
            sequential: self.sequential.rate_shortfalls.clone(),
            concurrent: self.concurrent.rate_shortfalls.clone(),
        }
    }

    fn validate(&self) -> Result<(), QualificationError> {
        self.context.validate()?;
        self.sequential.validate()?;
        self.concurrent.validate()?;
        if self.producer_engine_version != PRODUCER_ENGINE_VERSION || self.measured_at_unix == 0 {
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
                    SequentialReason::ConcurrentUnavailable => {
                        self.concurrent.completed_rounds == 0
                            && self.concurrent.failed_rounds == self.concurrent.requested_rounds
                            && self.trailing_sequential_control
                    }
                    SequentialReason::DeliveredRateShortfall => {
                        self.concurrent.rate_failures > 0
                            || (self.concurrent.completed_rounds == 0
                                && self.concurrent.failed_rounds
                                    == self.concurrent.requested_rounds
                                && self.concurrent.rate_shortfall_failures
                                    == self.concurrent.requested_rounds
                                && self.trailing_sequential_control)
                    }
                    SequentialReason::SignalLoss => {
                        retained(self.concurrent.rgb_mean, self.sequential.rgb_mean)
                            < CONCURRENT_SIGNAL_FLOOR
                            || retained(self.concurrent.ir_mean, self.sequential.ir_mean)
                                < CONCURRENT_SIGNAL_FLOOR
                    }
                    SequentialReason::InvalidProvenance => {
                        self.concurrent.contract_failures > 0
                            || self.concurrent.continuity_failures > 0
                    }
                };
                let complete_concurrent_evidence = match reason {
                    SequentialReason::ConcurrentUnavailable => true,
                    SequentialReason::DeliveredRateShortfall => {
                        (self.concurrent.completed_rounds == 0
                            && self.concurrent.failed_rounds == self.concurrent.requested_rounds
                            && self.concurrent.rate_shortfall_failures
                                == self.concurrent.requested_rounds
                            && self.trailing_sequential_control)
                            || (self.concurrent.rounds_complete()
                                && self.concurrent.provenance_accounted()
                                && self.concurrent.contract_failures == 0
                                && self.concurrent.continuity_failures == 0
                                && self.concurrent.illumination_failures == 0)
                    }
                    SequentialReason::SignalLoss => self.concurrent.complete_and_healthy(),
                    SequentialReason::InvalidProvenance => {
                        self.concurrent.rounds_complete()
                            && self.concurrent.provenance_accounted()
                            && self.concurrent.illumination_failures == 0
                    }
                };
                if !supported || !complete_concurrent_evidence {
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

    #[must_use]
    pub const fn outcome(&self) -> &AttemptOutcome {
        &self.outcome
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
    if value.len() != 4 || !value.bytes().all(|byte| (b' '..=b'~').contains(&byte)) {
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
                5_000_000,
                "uvcvideo".into(),
                "v4l2-uvc".into(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn stream(role: QualifiedStreamRole, fourcc: &str, height: u32) -> StreamContract {
        let minimum_rate = match role {
            QualifiedStreamRole::Rgb => ExactRate::new(15, 2).unwrap(),
            QualifiedStreamRole::Ir => ExactRate::new(15, 1).unwrap(),
        };
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
            minimum_rate,
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

    #[test]
    fn diagnostic_camera_contexts_remove_paths_and_serial_values() {
        let contexts = context("/devices/pci0000:00/0000:00:14.0/usb4/4-2")
            .diagnostic_camera_contexts(7, 9)
            .unwrap();
        let json = serde_json::to_string(&contexts).unwrap();

        assert_eq!(contexts[0].usb_bus, 4);
        assert_eq!(contexts[0].usb_port_chain, [2]);
        assert_eq!(contexts[0].lifecycle_generation, 7);
        assert_eq!(contexts[1].lifecycle_generation, 9);
        assert!(contexts.iter().all(|camera| camera.serial_present));
        assert!(!json.contains("batch-serial"));
        assert!(!json.contains("/devices/"));
        assert!(!json.contains("/dev/video"));
    }

    fn arm(rounds: u32) -> ArmEvidence {
        arm_with_ir_classified(rounds, 0)
    }

    fn arm_with_ir_classified(rounds: u32, ir_camera_classified: u32) -> ArmEvidence {
        arm_with_rate_shortfalls(
            rounds,
            ir_camera_classified,
            irlume_common::diagnostics::RateShortfallsByRole::default(),
        )
    }

    fn arm_with_rate_shortfalls(
        rounds: u32,
        ir_camera_classified: u32,
        rate_shortfalls: irlume_common::diagnostics::RateShortfallsByRole,
    ) -> ArmEvidence {
        ArmEvidence::new(
            rounds,
            rounds,
            0,
            rounds,
            rounds,
            rounds,
            rounds,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            rate_shortfalls,
            Default::default(),
            ir_camera_classified,
            140.0,
            120.0,
            850,
        )
        .unwrap()
    }

    fn rate_shortfall(
        role: irlume_common::diagnostics::CameraRoleLabel,
    ) -> irlume_common::diagnostics::RateShortfallEvidence {
        irlume_common::diagnostics::RateShortfallEvidence {
            role,
            failure_count: 2,
            delivered_num: 29,
            delivered_den: 2,
            floor_num: 15,
            floor_den: 1,
            tolerance_percent: 98,
            window_count: 30,
            window_span_us: 2_000_000,
        }
    }

    /// #606: absence means an older producer did not measure the count, while
    /// an explicit zero means a current producer measured no classified frames.
    #[test]
    fn ir_camera_classified_frames_preserves_unknown_and_measured_values() {
        let json = serde_json::to_value(arm_with_ir_classified(6, 47)).unwrap();
        let mut legacy = json.clone();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("ir_camera_classified_frames");
        let decoded: ArmEvidence = serde_json::from_value(legacy).expect("legacy record parses");
        let legacy_again = serde_json::to_value(decoded).unwrap();
        assert!(
            legacy_again.get("ir_camera_classified_frames").is_none(),
            "an unknown legacy count must not become a measured zero: {legacy_again}"
        );

        let measured_zero = serde_json::to_value(arm_with_ir_classified(6, 0)).unwrap();
        assert_eq!(
            measured_zero.get("ir_camera_classified_frames"),
            Some(&serde_json::json!(0)),
            "a measured zero must remain explicit"
        );
        let back: ArmEvidence = serde_json::from_value(json).expect("the new record round-trips");
        assert_eq!(back.ir_camera_classified_frames(), Some(47));
    }

    #[test]
    fn rate_shortfall_persistence_preserves_unknown_measured_empty_and_roles() {
        use irlume_common::diagnostics::{CameraRoleLabel, RateShortfallsByRole};

        let fresh = arm(6);
        assert_eq!(
            fresh.rate_shortfalls(),
            Some(&RateShortfallsByRole::default())
        );
        assert_eq!(SCHEMA_VERSION, 2);

        let mut legacy = serde_json::to_value(&fresh).unwrap();
        legacy.as_object_mut().unwrap().remove("rate_shortfalls");
        let legacy: ArmEvidence = serde_json::from_value(legacy).expect("legacy record parses");
        assert_eq!(legacy.rate_shortfalls(), None);

        let shortfalls = RateShortfallsByRole {
            rgb: Some(rate_shortfall(CameraRoleLabel::Rgb)),
            ir: Some(rate_shortfall(CameraRoleLabel::Ir)),
        };
        let populated = arm_with_rate_shortfalls(6, 0, shortfalls.clone());
        let json = serde_json::to_vec(&populated).unwrap();
        let decoded: ArmEvidence = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.rate_shortfalls(), Some(&shortfalls));
    }

    #[test]
    fn rate_shortfall_populated_slots_validate_role_counts_and_denominators() {
        use irlume_common::diagnostics::{CameraRoleLabel, RateShortfallsByRole};

        let valid = rate_shortfall(CameraRoleLabel::Rgb);
        let mut invalid_values = Vec::new();

        let mut wrong_role = valid.clone();
        wrong_role.role = CameraRoleLabel::Ir;
        invalid_values.push(wrong_role);
        let mut zero_count = valid.clone();
        zero_count.failure_count = 0;
        invalid_values.push(zero_count);
        let mut zero_delivered_den = valid.clone();
        zero_delivered_den.delivered_den = 0;
        invalid_values.push(zero_delivered_den);
        let mut zero_floor_den = valid;
        zero_floor_den.floor_den = 0;
        invalid_values.push(zero_floor_den);

        for invalid in invalid_values {
            let mut arm = arm(6);
            arm.rate_shortfalls = Some(RateShortfallsByRole {
                rgb: Some(invalid),
                ir: None,
            });
            assert_eq!(arm.validate(), Err(QualificationError::InvalidEvidence));
        }
    }

    #[test]
    fn rate_shortfall_qualification_attempt_projects_both_arms() {
        use irlume_common::diagnostics::{
            CameraRoleLabel, RateShortfallsByArm, RateShortfallsByRole,
        };

        let concurrent = RateShortfallsByRole {
            rgb: Some(rate_shortfall(CameraRoleLabel::Rgb)),
            ir: None,
        };
        let attempt = QualificationAttempt::new(
            1_786_944_000,
            context("/devices/pci0000:00/usb3/3-2"),
            arm(6),
            arm_with_rate_shortfalls(6, 0, concurrent.clone()),
            false,
            AttemptOutcome::ConcurrentQualified,
            None,
        )
        .unwrap();

        assert_eq!(
            attempt.rate_shortfalls(),
            RateShortfallsByArm {
                sequential: Some(RateShortfallsByRole::default()),
                concurrent: Some(concurrent),
            }
        );
    }

    fn concurrent_attempt(port: &str) -> QualificationAttempt {
        concurrent_attempt_with_presence(port, None)
    }

    fn concurrent_attempt_with_presence(
        port: &str,
        ir_illumination_metadata: Option<IlluminationMetadataPresence>,
    ) -> QualificationAttempt {
        QualificationAttempt::new(
            1_786_944_000,
            context(port),
            arm(6),
            arm(6),
            false,
            AttemptOutcome::ConcurrentQualified,
            ir_illumination_metadata,
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
    fn illumination_metadata_presence_round_trips_and_names_the_wire_field() {
        let attempt = concurrent_attempt_with_presence(
            "/devices/pci0000:00/usb3/3-2",
            Some(IlluminationMetadataPresence::Present),
        );
        assert_eq!(
            attempt.ir_illumination_metadata(),
            Some(IlluminationMetadataPresence::Present)
        );
        let record = CaptureQualificationRecord::new(7, attempt.clone(), Some(attempt)).unwrap();
        let body = record.to_json().unwrap();
        assert!(
            body.contains("\"ir_illumination_metadata\": \"present\""),
            "the wire field must keep its documented name: {body}"
        );
        let decoded = CaptureQualificationRecord::from_json(body.as_bytes()).unwrap();
        assert_eq!(
            decoded.authoritative().unwrap().ir_illumination_metadata(),
            Some(IlluminationMetadataPresence::Present)
        );
    }

    /// Records written before #568 carry no illumination-metadata field at
    /// all. They must keep parsing, keep their authority, and simply read as
    /// "not recorded": the presence is evidence on the attempt, never part of
    /// the context equality that gates authorization.
    #[test]
    fn legacy_records_without_illumination_metadata_still_authorize() {
        let port = "/devices/pci0000:00/usb3/3-2";
        let recorded =
            concurrent_attempt_with_presence(port, Some(IlluminationMetadataPresence::Present));
        let record =
            CaptureQualificationRecord::new(7, recorded.clone(), Some(recorded.clone())).unwrap();
        let mut legacy: serde_json::Value =
            serde_json::from_str(&record.to_json().unwrap()).unwrap();
        for attempt in ["last_attempt", "authoritative"] {
            legacy[attempt]
                .as_object_mut()
                .unwrap()
                .remove("ir_illumination_metadata");
        }
        let legacy = serde_json::to_vec(&legacy).unwrap();

        let decoded = CaptureQualificationRecord::from_json(&legacy)
            .expect("a pre-#568 record must keep parsing");
        assert_eq!(
            decoded.authoritative().unwrap().ir_illumination_metadata(),
            None,
            "a stripped record reads as not-recorded, never as absent hardware"
        );
        assert_eq!(
            decoded.resolve(recorded.context()),
            QualificationResolution::ConcurrentQualified,
            "metadata presence must not gate stored authority"
        );
        let without_field = concurrent_attempt_with_presence(port, None);
        let expected =
            CaptureQualificationRecord::new(7, without_field.clone(), Some(without_field)).unwrap();
        assert_eq!(decoded, expected);
    }

    /// #606: `capture_failure_facts` is additive. A schema-version-2 record
    /// written before the field existed must still parse, revalidate, and
    /// authorize the exact same context, so stored authority survives the
    /// upgrade and a downgrade can still read new records (serde ignores the
    /// unknown key on the old binary).
    #[test]
    fn records_written_before_failure_facts_still_authorize() {
        fn strip_facts(value: &mut serde_json::Value) {
            if let serde_json::Value::Object(map) = value {
                map.remove("capture_failure_facts");
                for (_, nested) in map.iter_mut() {
                    strip_facts(nested);
                }
            }
        }
        let attempt = concurrent_attempt("/devices/pci0000:00/usb3/3-2");
        let record =
            CaptureQualificationRecord::new(1, attempt.clone(), Some(attempt.clone())).unwrap();
        let json = record.to_json().unwrap();
        let mut legacy: serde_json::Value = serde_json::from_str(&json).unwrap();
        strip_facts(&mut legacy);
        assert!(
            !legacy.to_string().contains("capture_failure_facts"),
            "fixture genuinely models a pre-field record"
        );
        let parsed = CaptureQualificationRecord::from_json(legacy.to_string().as_bytes())
            .expect("a pre-field schema-version-2 record parses and revalidates");
        assert_eq!(
            parsed.resolve(attempt.context()),
            QualificationResolution::ConcurrentQualified,
            "stored authority is untouched by the additive field"
        );
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
            ArmEvidence::new(
                6,
                3,
                3,
                3,
                3,
                3,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                3,
                0,
                Default::default(),
                Default::default(),
                0,
                80.0,
                90.0,
                2_000,
            )
            .unwrap(),
            false,
            AttemptOutcome::Inconclusive(InconclusiveReason::IncompleteRounds),
            None,
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
        assert!(
            ArmEvidence::new(
                1,
                1,
                0,
                1,
                1,
                1,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                Default::default(),
                Default::default(),
                0,
                1.0,
                1.0,
                1
            )
            .is_err(),
            "one completed round cannot both match and fail the same contract"
        );
        let partial_rate_failure = ArmEvidence::new(
            6,
            1,
            0,
            1,
            0,
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            Default::default(),
            Default::default(),
            0,
            1.0,
            1.0,
            1,
        )
        .unwrap();
        assert!(
            QualificationAttempt::new(
                1,
                context("/devices/usb3/3-2"),
                arm(6),
                partial_rate_failure,
                false,
                AttemptOutcome::SequentialRequired(SequentialReason::DeliveredRateShortfall),
                None,
            )
            .is_err(),
            "one rate-failed frame cannot authorize a six-round sequential verdict"
        );
        let typed_rate_shortfall = ArmEvidence::new(
            6,
            0,
            6,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            6,
            Default::default(),
            Default::default(),
            0,
            0.0,
            0.0,
            1,
        )
        .unwrap();
        assert!(
            QualificationAttempt::new(
                1,
                context("/devices/usb3/3-2"),
                arm(6),
                typed_rate_shortfall,
                true,
                AttemptOutcome::SequentialRequired(SequentialReason::DeliveredRateShortfall),
                None,
            )
            .is_ok(),
            "six typed concurrent rate failures plus a healthy trailing control are authority"
        );
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
        let mut future_engine: serde_json::Value =
            serde_json::from_str(&record.to_json().unwrap()).unwrap();
        future_engine["last_attempt"]["producer_engine_version"] = serde_json::json!(999);
        assert_eq!(
            CaptureQualificationRecord::from_json(&serde_json::to_vec(&future_engine).unwrap()),
            Err(QualificationError::InvalidEvidence)
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
    fn runtime_context_key_covers_stream_and_connection_context() {
        let original = context("/devices/usb3/3-2");
        let changed_stream = QualificationContext::new(
            original.rgb_endpoint().clone(),
            original.ir_endpoint().clone(),
            stream(QualifiedStreamRole::Rgb, "NV12", 480),
            original.ir_stream().clone(),
        )
        .unwrap();

        let mut moved_rgb = original.rgb_endpoint().clone();
        moved_rgb.connection = ConnectionContext::new(
            "/devices/pci0000:00/0000:00:08.1".into(),
            480_000,
            "uvcvideo".into(),
            "v4l2-uvc".into(),
        )
        .unwrap();
        let changed_connection = QualificationContext::new(
            moved_rgb,
            original.ir_endpoint().clone(),
            original.rgb_stream().clone(),
            original.ir_stream().clone(),
        )
        .unwrap();

        let key = original.runtime_key().unwrap();
        assert_ne!(key, changed_stream.runtime_key().unwrap());
        assert_ne!(key, changed_connection.runtime_key().unwrap());
    }

    #[test]
    fn stream_contract_keeps_rate_and_interval_as_distinct_exact_units() {
        let rgb = stream(QualifiedStreamRole::Rgb, "YUYV", 480);
        assert_eq!(rgb.requested().interval().parts(), (1, 30));
        assert_eq!(rgb.accepted().interval().parts(), (1, 30));
        assert_eq!(rgb.minimum_rate().parts(), (15, 2));
    }

    #[test]
    fn negotiated_contract_keeps_the_request_and_every_driver_echo_field() {
        let mut accepted = v4l::Format::new(800, 600, v4l::FourCC::new(b"NV12"));
        accepted.stride = 832;
        accepted.size = 748_800;
        accepted.flags = v4l::format::Flags::PREMUL_ALPHA;
        let contract = StreamContract::from_negotiated(
            QualifiedStreamRole::Rgb,
            640,
            480,
            *b"YUYV",
            crate::frame_interval::FrameInterval::new(1, 30).unwrap(),
            &accepted,
            crate::frame_interval::FrameInterval::new(1, 25).unwrap(),
        )
        .unwrap();

        assert_eq!(contract.requested.width, 640);
        assert_eq!(contract.requested.height, 480);
        assert_eq!(contract.requested.fourcc, "YUYV");
        assert_eq!(contract.requested.interval.parts(), (1, 30));
        assert_eq!(contract.accepted.width, 800);
        assert_eq!(contract.accepted.height, 600);
        assert_eq!(contract.accepted.fourcc, "NV12");
        assert_eq!(contract.accepted.stride, 832);
        assert_eq!(contract.accepted.image_size, 748_800);
        assert_eq!(contract.accepted.field_order, accepted.field_order as u32);
        assert_eq!(contract.accepted.colorspace, accepted.colorspace as u32);
        assert_eq!(contract.accepted.quantization, accepted.quantization as u32);
        assert_eq!(contract.accepted.transfer, accepted.transfer as u32);
        assert_eq!(contract.accepted.flags, accepted.flags.bits());
        assert_eq!(contract.accepted.interval.parts(), (1, 25));
        assert_eq!(contract.minimum_rate.parts(), (15, 2));
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
        let record =
            CaptureQualificationRecord::new(1, conclusive.clone(), Some(conclusive.clone()))
                .unwrap();
        let mut legacy: serde_json::Value =
            serde_json::from_str(&record.to_json().unwrap()).unwrap();
        for attempt in ["last_attempt", "authoritative"] {
            for arm in ["sequential", "concurrent"] {
                legacy[attempt][arm]
                    .as_object_mut()
                    .unwrap()
                    .remove("ir_camera_classified_frames");
            }
        }
        store.ensure_dir().unwrap();
        let path = store.record_path_for_test(conclusive.context());
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let legacy_authority = store
            .load(conclusive.context())
            .unwrap()
            .unwrap()
            .authoritative()
            .unwrap()
            .clone();
        let inconclusive = QualificationAttempt::new(
            1_786_944_001,
            conclusive.context().clone(),
            arm(6),
            ArmEvidence::new(
                6,
                4,
                2,
                4,
                4,
                4,
                4,
                0,
                0,
                0,
                0,
                0,
                0,
                2,
                0,
                Default::default(),
                Default::default(),
                0,
                80.0,
                90.0,
                2_000,
            )
            .unwrap(),
            false,
            AttemptOutcome::Inconclusive(InconclusiveReason::IncompleteRounds),
            None,
        )
        .unwrap();

        let updated = store.save_attempt(inconclusive.clone(), Some(1)).unwrap();
        assert_eq!(updated.revision(), 2);
        assert_eq!(updated.last_attempt(), &inconclusive);
        assert_eq!(updated.authoritative(), Some(&legacy_authority));
        assert_eq!(
            updated.resolve(conclusive.context()),
            QualificationResolution::ConcurrentQualified
        );
        let persisted: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for arm in ["sequential", "concurrent"] {
            assert!(
                persisted["authoritative"][arm]
                    .get("ir_camera_classified_frames")
                    .is_none(),
                "preserved authority must not gain a fabricated zero: {persisted}"
            );
        }
    }
}
