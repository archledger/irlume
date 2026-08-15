// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Versioned, backend-neutral camera evidence contracts.
//!
//! Schema v1 is additive and UVC-only. It does not replace any legacy camera,
//! enrollment, or emitter state. It deliberately permits only ambiguous physical
//! identity: stronger binding must be introduced by a later schema together with
//! the trusted evidence producer that proves it.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

/// Current camera evidence schema version.
pub const CAMERA_CONTRACT_SCHEMA_VERSION: u32 = 1;
/// Largest accepted serialized camera contract.
///
/// Both public readers parse a small header before the complete value. This cap
/// bounds both passes and every string/vector allocation reachable from them.
pub const MAX_CAMERA_CONTRACT_BYTES: usize = 64 * 1024;

const MAX_TOPOLOGY_PATH_BYTES: usize = 4096;
const MAX_SERIAL_BYTES: usize = 256;
const CAMERA_INSTANCE_ID_HEX_BYTES: usize = 32;

/// Capture backend that produced a normalized contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// Existing direct V4L2 backend for video-node-centric UVC cameras.
    UvcV4l2,
}

/// Raw, untrusted identity evidence for a physical camera.
///
/// `topology_path` is the canonical sysfs path relative to `/sys`, beginning
/// with `/devices/`. It is useful for re-enumeration within one host, but schema
/// v1 never upgrades it into a strong or portable security identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhysicalCameraId {
    topology_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<String>,
}

impl PhysicalCameraId {
    /// Validate raw physical-camera identity evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical topology path or an empty, control-
    /// containing, or oversized serial value.
    pub fn new(
        topology_path: impl Into<String>,
        serial: Option<String>,
    ) -> Result<Self, CameraContractError> {
        let topology_path = topology_path.into();
        validate_topology_path(&topology_path)?;
        validate_serial(serial.as_deref())?;
        Ok(Self {
            topology_path,
            serial,
        })
    }

    /// Canonical sysfs path relative to `/sys`.
    #[must_use]
    pub fn topology_path(&self) -> &str {
        &self.topology_path
    }

    /// Device-declared serial, when present; not by itself a uniqueness proof.
    #[must_use]
    pub fn serial(&self) -> Option<&str> {
        self.serial.as_deref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhysicalCameraIdWire {
    topology_path: String,
    #[serde(default)]
    serial: Option<String>,
}

impl TryFrom<PhysicalCameraIdWire> for PhysicalCameraId {
    type Error = CameraContractError;

    fn try_from(wire: PhysicalCameraIdWire) -> Result<Self, Self::Error> {
        Self::new(wire.topology_path, wire.serial)
    }
}

/// Strength of a physical-camera identity claim.
///
/// Schema v1 exposes only `Ambiguous`. Callers cannot self-assert a stronger
/// value. A future schema may add stronger variants only with a trusted evidence
/// producer and explicit migration rules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum IdentityStrength {
    /// Evidence is insufficient for a durable anti-swap binding.
    #[default]
    Ambiguous,
}

/// Logical stream role established by a capture backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum StreamRole {
    /// Visible-light color stream.
    Rgb,
    /// Near-infrared monochrome stream.
    Ir,
}

/// Evidence relating timing across streams.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SynchronizationProvenance {
    /// No synchronization claim is supported.
    #[default]
    Unknown,
    /// Streams are known to run independently.
    Independent,
    /// Host timestamps correlated at least two streams.
    HostCorrelated,
    /// Device metadata correlated at least two streams.
    DeviceCorrelated,
    /// Hardware synchronization was qualified for at least two streams.
    HardwareSynchronized,
}

/// Evidence that a frame or stream supports a particular illumination state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum IlluminationProvenance {
    /// No trustworthy illumination evidence exists.
    #[default]
    Unknown,
    /// Ambient-only illumination is known.
    Ambient,
    /// Active near-infrared illumination is known.
    ActiveIr,
}

/// Process-scoped identity for one physical-camera incarnation.
///
/// A supervisor must mint a new nonzero 128-bit identifier after each process
/// restart and whenever the prior incarnation cannot be proven continuous. A
/// generation number has meaning only together with this identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct CameraInstanceId(String);

impl CameraInstanceId {
    /// Validate a lowercase nonzero 128-bit hexadecimal identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CameraContractError::InvalidCameraInstanceId`] unless the input
    /// contains exactly 32 lowercase hexadecimal characters and is not all zero.
    pub fn new(value: impl Into<String>) -> Result<Self, CameraContractError> {
        let value = value.into();
        let valid = value.len() == CAMERA_INSTANCE_ID_HEX_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && value.bytes().any(|byte| byte != b'0');
        if !valid {
            return Err(CameraContractError::InvalidCameraInstanceId);
        }
        Ok(Self(value))
    }

    /// Lowercase hexadecimal identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Monotonic lifecycle generation within one [`CameraInstanceId`].
///
/// Generation zero is reserved. Before incrementing `u64::MAX`, the supervisor
/// must retire the instance and mint a new camera-instance identifier; wrapping
/// or saturating would allow stale frames to alias current ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct CameraGeneration(u64);

impl CameraGeneration {
    /// First generation of a newly minted camera instance.
    pub const INITIAL: Self = Self(1);

    /// Construct a nonzero generation.
    ///
    /// # Errors
    ///
    /// Returns [`CameraContractError::ZeroGeneration`] for zero.
    pub const fn new(value: u64) -> Result<Self, CameraContractError> {
        if value == 0 {
            Err(CameraContractError::ZeroGeneration)
        } else {
            Ok(Self(value))
        }
    }

    /// Advance without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`CameraContractError::GenerationExhausted`] at `u64::MAX`; the
    /// caller must mint a new [`CameraInstanceId`] instead.
    pub const fn next(self) -> Result<Self, CameraContractError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(CameraContractError::GenerationExhausted),
        }
    }

    /// Numeric generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Conservative backend capability declaration.
///
/// This is a producer claim, not security proof. Deserializing or constructing
/// it does not establish that the producer measured the claimed synchronization
/// or illumination behavior. Authentication consumers must accept capabilities
/// only from a trusted, qualified backend/profile and validate them against the
/// current camera instance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CameraCapabilities {
    stream_roles: Vec<StreamRole>,
    synchronization: SynchronizationProvenance,
    illumination_provenance: Vec<IlluminationProvenance>,
}

impl CameraCapabilities {
    /// Construct a coherent capability set.
    ///
    /// Empty lists and `Unknown` are valid and make no capability claim.
    ///
    /// # Errors
    ///
    /// Rejects duplicates, active-IR support without an IR stream, and any
    /// cross-stream correlation claim without at least two distinct streams.
    pub fn new(
        stream_roles: Vec<StreamRole>,
        synchronization: SynchronizationProvenance,
        illumination_provenance: Vec<IlluminationProvenance>,
    ) -> Result<Self, CameraContractError> {
        reject_duplicates(&stream_roles, CameraContractError::DuplicateStreamRole)?;
        reject_duplicates(
            &illumination_provenance,
            CameraContractError::DuplicateIllumination,
        )?;
        if illumination_provenance.contains(&IlluminationProvenance::ActiveIr)
            && !stream_roles.contains(&StreamRole::Ir)
        {
            return Err(CameraContractError::ActiveIrRequiresIrStream);
        }
        if matches!(
            synchronization,
            SynchronizationProvenance::HostCorrelated
                | SynchronizationProvenance::DeviceCorrelated
                | SynchronizationProvenance::HardwareSynchronized
        ) && stream_roles.len() < 2
        {
            return Err(CameraContractError::SynchronizationRequiresMultipleStreams(
                synchronization,
            ));
        }
        Ok(Self {
            stream_roles,
            synchronization,
            illumination_provenance,
        })
    }

    /// Established logical stream roles.
    #[must_use]
    pub fn stream_roles(&self) -> &[StreamRole] {
        &self.stream_roles
    }

    /// Established cross-stream timing provenance.
    #[must_use]
    pub const fn synchronization(&self) -> SynchronizationProvenance {
        self.synchronization
    }

    /// Established illumination evidence mechanisms.
    #[must_use]
    pub fn illumination_provenance(&self) -> &[IlluminationProvenance] {
        &self.illumination_provenance
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CameraCapabilitiesWire {
    #[serde(default)]
    stream_roles: Vec<StreamRole>,
    #[serde(default)]
    synchronization: SynchronizationProvenance,
    #[serde(default)]
    illumination_provenance: Vec<IlluminationProvenance>,
}

impl TryFrom<CameraCapabilitiesWire> for CameraCapabilities {
    type Error = CameraContractError;

    fn try_from(wire: CameraCapabilitiesWire) -> Result<Self, Self::Error> {
        Self::new(
            wire.stream_roles,
            wire.synchronization,
            wire.illumination_provenance,
        )
    }
}

/// Versioned normalized description of one physical-camera incarnation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CameraDescriptor {
    schema_version: u32,
    backend: BackendKind,
    physical_id: PhysicalCameraId,
    identity_strength: IdentityStrength,
    camera_instance_id: CameraInstanceId,
    generation: CameraGeneration,
    capabilities: CameraCapabilities,
}

impl CameraDescriptor {
    /// Construct a schema-v1 descriptor with fail-closed identity strength.
    #[must_use]
    pub fn new(
        backend: BackendKind,
        physical_id: PhysicalCameraId,
        camera_instance_id: CameraInstanceId,
        generation: CameraGeneration,
        capabilities: CameraCapabilities,
    ) -> Self {
        Self {
            schema_version: CAMERA_CONTRACT_SCHEMA_VERSION,
            backend,
            physical_id,
            identity_strength: IdentityStrength::Ambiguous,
            camera_instance_id,
            generation,
            capabilities,
        }
    }

    /// Parse one bounded schema-v1 descriptor.
    ///
    /// # Errors
    ///
    /// Rejects oversized/malformed input, unsupported versions, unknown fields
    /// or enum variants, invalid identity evidence, contradictory capabilities,
    /// and self-asserted identity strength.
    pub fn from_json(input: &str) -> Result<Self, CameraContractReadError> {
        check_input_size(input)?;
        require_supported_version(input)?;
        let wire: CameraDescriptorWire = serde_json::from_str(input)?;
        Self::try_from(wire).map_err(CameraContractReadError::Invalid)
    }

    /// Schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Capture backend kind.
    #[must_use]
    pub const fn backend(&self) -> BackendKind {
        self.backend
    }

    /// Raw physical-camera identity evidence.
    #[must_use]
    pub const fn physical_id(&self) -> &PhysicalCameraId {
        &self.physical_id
    }

    /// Conservative identity strength; always `Ambiguous` in schema v1.
    #[must_use]
    pub const fn identity_strength(&self) -> IdentityStrength {
        self.identity_strength
    }

    /// Camera-incarnation scope shared with every frame.
    #[must_use]
    pub const fn camera_instance_id(&self) -> &CameraInstanceId {
        &self.camera_instance_id
    }

    /// Current generation within the camera instance.
    #[must_use]
    pub const fn generation(&self) -> CameraGeneration {
        self.generation
    }

    /// Conservative backend capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> &CameraCapabilities {
        &self.capabilities
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CameraDescriptorWire {
    schema_version: u32,
    backend: BackendKind,
    physical_id: PhysicalCameraIdWire,
    #[serde(default)]
    identity_strength: IdentityStrength,
    camera_instance_id: String,
    generation: u64,
    #[serde(default)]
    capabilities: CameraCapabilitiesWire,
}

impl TryFrom<CameraDescriptorWire> for CameraDescriptor {
    type Error = CameraContractError;

    fn try_from(wire: CameraDescriptorWire) -> Result<Self, Self::Error> {
        if wire.schema_version != CAMERA_CONTRACT_SCHEMA_VERSION {
            return Err(CameraContractError::UnsupportedSchemaVersion(
                wire.schema_version,
            ));
        }
        match wire.identity_strength {
            IdentityStrength::Ambiguous => {}
        }
        Ok(Self::new(
            wire.backend,
            PhysicalCameraId::try_from(wire.physical_id)?,
            CameraInstanceId::new(wire.camera_instance_id)?,
            CameraGeneration::new(wire.generation)?,
            CameraCapabilities::try_from(wire.capabilities)?,
        ))
    }
}

/// Per-frame evidence emitted by a capture backend.
///
/// This structure records what a producer claims for one frame; it does not
/// authenticate that producer or prove hardware synchronization/illumination.
/// Security-sensitive consumers must bind it to a trusted backend session and
/// a currently qualified camera profile before treating any field as evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrameMetadata {
    schema_version: u32,
    camera_instance_id: CameraInstanceId,
    generation: CameraGeneration,
    stream_role: StreamRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    sequence: Option<u64>,
    synchronization: SynchronizationProvenance,
    illumination: IlluminationProvenance,
}

impl FrameMetadata {
    /// Construct coherent metadata from explicit backend evidence.
    ///
    /// # Errors
    ///
    /// Rejects active-IR provenance on a non-IR frame.
    pub fn new(
        camera_instance_id: CameraInstanceId,
        generation: CameraGeneration,
        stream_role: StreamRole,
        sequence: Option<u64>,
        synchronization: SynchronizationProvenance,
        illumination: IlluminationProvenance,
    ) -> Result<Self, CameraContractError> {
        if matches!(illumination, IlluminationProvenance::ActiveIr)
            && matches!(stream_role, StreamRole::Rgb)
        {
            return Err(CameraContractError::ActiveIrRequiresIrStream);
        }
        Ok(Self {
            schema_version: CAMERA_CONTRACT_SCHEMA_VERSION,
            camera_instance_id,
            generation,
            stream_role,
            sequence,
            synchronization,
            illumination,
        })
    }

    /// Parse one bounded schema-v1 frame metadata value.
    ///
    /// # Errors
    ///
    /// Rejects oversized/malformed input, unsupported versions, unknown fields
    /// or enum variants, invalid instance/generation values, and contradictory
    /// role/illumination evidence.
    pub fn from_json(input: &str) -> Result<Self, CameraContractReadError> {
        check_input_size(input)?;
        require_supported_version(input)?;
        let wire: FrameMetadataWire = serde_json::from_str(input)?;
        Self::try_from(wire).map_err(CameraContractReadError::Invalid)
    }

    /// Camera-incarnation scope for the generation and sequence.
    #[must_use]
    pub const fn camera_instance_id(&self) -> &CameraInstanceId {
        &self.camera_instance_id
    }

    /// Camera generation that produced the frame.
    #[must_use]
    pub const fn generation(&self) -> CameraGeneration {
        self.generation
    }

    /// Logical stream role.
    #[must_use]
    pub const fn stream_role(&self) -> StreamRole {
        self.stream_role
    }

    /// Backend sequence number, when available.
    #[must_use]
    pub const fn sequence(&self) -> Option<u64> {
        self.sequence
    }

    /// Proven synchronization relationship.
    #[must_use]
    pub const fn synchronization(&self) -> SynchronizationProvenance {
        self.synchronization
    }

    /// Per-frame illumination evidence.
    #[must_use]
    pub const fn illumination(&self) -> IlluminationProvenance {
        self.illumination
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameMetadataWire {
    schema_version: u32,
    camera_instance_id: String,
    generation: u64,
    stream_role: StreamRole,
    #[serde(default)]
    sequence: Option<u64>,
    #[serde(default)]
    synchronization: SynchronizationProvenance,
    #[serde(default)]
    illumination: IlluminationProvenance,
}

impl TryFrom<FrameMetadataWire> for FrameMetadata {
    type Error = CameraContractError;

    fn try_from(wire: FrameMetadataWire) -> Result<Self, Self::Error> {
        if wire.schema_version != CAMERA_CONTRACT_SCHEMA_VERSION {
            return Err(CameraContractError::UnsupportedSchemaVersion(
                wire.schema_version,
            ));
        }
        Self::new(
            CameraInstanceId::new(wire.camera_instance_id)?,
            CameraGeneration::new(wire.generation)?,
            wire.stream_role,
            wire.sequence,
            wire.synchronization,
            wire.illumination,
        )
    }
}

fn validate_topology_path(value: &str) -> Result<(), CameraContractError> {
    let canonical = value.starts_with("/devices/")
        && !value.ends_with('/')
        && value.len() <= MAX_TOPOLOGY_PATH_BYTES
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..");
    if canonical {
        Ok(())
    } else {
        Err(CameraContractError::InvalidTopologyPath)
    }
}

fn validate_serial(value: Option<&str>) -> Result<(), CameraContractError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.trim().is_empty() {
        return Err(CameraContractError::EmptySerial);
    }
    if value.len() > MAX_SERIAL_BYTES || value.chars().any(char::is_control) {
        return Err(CameraContractError::InvalidSerial);
    }
    Ok(())
}

fn reject_duplicates<T: Copy + Ord>(
    values: &[T],
    error: impl Fn(T) -> CameraContractError,
) -> Result<(), CameraContractError> {
    let mut seen = BTreeSet::new();
    for &value in values {
        if !seen.insert(value) {
            return Err(error(value));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct SchemaHeader {
    schema_version: u32,
}

fn check_input_size(input: &str) -> Result<(), CameraContractReadError> {
    if input.len() > MAX_CAMERA_CONTRACT_BYTES {
        return Err(CameraContractReadError::Invalid(
            CameraContractError::InputTooLarge {
                actual: input.len(),
                maximum: MAX_CAMERA_CONTRACT_BYTES,
            },
        ));
    }
    Ok(())
}

fn require_supported_version(input: &str) -> Result<(), CameraContractReadError> {
    let header: SchemaHeader = serde_json::from_str(input)?;
    if header.schema_version != CAMERA_CONTRACT_SCHEMA_VERSION {
        return Err(CameraContractReadError::Invalid(
            CameraContractError::UnsupportedSchemaVersion(header.schema_version),
        ));
    }
    Ok(())
}

/// Semantic camera-contract validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CameraContractError {
    /// Input exceeded the documented parser ceiling.
    InputTooLarge { actual: usize, maximum: usize },
    /// Exact schema version is not supported.
    UnsupportedSchemaVersion(u32),
    /// Sysfs topology path is not in canonical `/devices/...` form.
    InvalidTopologyPath,
    /// A present serial was empty.
    EmptySerial,
    /// A serial was oversized or contained control characters.
    InvalidSerial,
    /// Camera-instance identifier was malformed or all zero.
    InvalidCameraInstanceId,
    /// Generation zero could allow stale and current instances to alias.
    ZeroGeneration,
    /// Generation cannot advance without wrapping.
    GenerationExhausted,
    /// A logical stream role appeared more than once.
    DuplicateStreamRole(StreamRole),
    /// An illumination provenance value appeared more than once.
    DuplicateIllumination(IlluminationProvenance),
    /// Active-IR evidence was claimed without an IR stream.
    ActiveIrRequiresIrStream,
    /// A cross-stream synchronization claim had fewer than two streams.
    SynchronizationRequiresMultipleStreams(SynchronizationProvenance),
}

impl fmt::Display for CameraContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { actual, maximum } => write!(
                formatter,
                "camera contract is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::UnsupportedSchemaVersion(version) => write!(
                formatter,
                "unsupported camera contract schema version {version}"
            ),
            Self::InvalidTopologyPath => formatter
                .write_str("camera topology path must be canonical ASCII /devices/... form"),
            Self::EmptySerial => formatter.write_str("camera serial is empty"),
            Self::InvalidSerial => formatter.write_str("camera serial is invalid"),
            Self::InvalidCameraInstanceId => formatter
                .write_str("camera instance id must be nonzero 128-bit lowercase hexadecimal"),
            Self::ZeroGeneration => formatter.write_str("camera generation must be non-zero"),
            Self::GenerationExhausted => {
                formatter.write_str("camera generation exhausted; mint a new camera instance id")
            }
            Self::DuplicateStreamRole(role) => {
                write!(formatter, "camera capabilities repeat stream role {role:?}")
            }
            Self::DuplicateIllumination(illumination) => write!(
                formatter,
                "camera capabilities repeat illumination provenance {illumination:?}"
            ),
            Self::ActiveIrRequiresIrStream => {
                formatter.write_str("active-IR evidence requires an IR stream")
            }
            Self::SynchronizationRequiresMultipleStreams(provenance) => write!(
                formatter,
                "synchronization provenance {provenance:?} requires at least two streams"
            ),
        }
    }
}

impl std::error::Error for CameraContractError {}

/// Error returned while decoding a serialized camera contract.
#[derive(Debug)]
#[non_exhaustive]
pub enum CameraContractReadError {
    /// JSON syntax, type, duplicate-field, or unknown-field error.
    Malformed(serde_json::Error),
    /// Well-formed JSON that violated a semantic contract rule.
    Invalid(CameraContractError),
}

impl fmt::Display for CameraContractReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(formatter, "malformed camera contract: {error}"),
            Self::Invalid(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CameraContractReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed(error) => Some(error),
            Self::Invalid(error) => Some(error),
        }
    }
}

impl From<serde_json::Error> for CameraContractReadError {
    fn from(error: serde_json::Error) -> Self {
        Self::Malformed(error)
    }
}
