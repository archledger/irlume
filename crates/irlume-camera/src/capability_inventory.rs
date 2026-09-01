// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bounded, observation-only V4L2 capability inventory.

use std::{
    collections::HashSet,
    fs::File,
    num::NonZeroU32,
    os::fd::{AsRawFd, RawFd},
};

use crate::{
    contracts::StreamRole,
    frame_interval::{FrameInterval, FrameIntervalDomain, FrameIntervalError, FrameIntervalQuery},
    profile::{DecodedPixelFormat, ProfileError, StreamTuple},
};

const MAX_FORMATS: usize = 64;
const MAX_GEOMETRIES_PER_FORMAT: usize = 256;
const MAX_INTERVALS_PER_TUPLE: usize = 256;
const MAX_CONTROLS: usize = 256;
const MAX_MENU_VALUES: usize = 256;

const V4L2_CTRL_CLASS_MASK: u32 = 0x0fff_0000;
const V4L2_CTRL_CLASS_USER: u32 = 0x0098_0000;
const V4L2_CTRL_CLASS_CAMERA: u32 = 0x009a_0000;
const V4L2_CTRL_CLASS_IMAGE_SOURCE: u32 = 0x009e_0000;
const V4L2_CTRL_FLAG_DISABLED: u32 = 0x0001;
const V4L2_CTRL_FLAG_READ_ONLY: u32 = 0x0004;
const V4L2_CTRL_FLAG_WRITE_ONLY: u32 = 0x0040;
const V4L2_CTRL_FLAG_EXECUTE_ON_WRITE: u32 = 0x0200;
const V4L2_CTRL_FLAG_NEXT_CTRL: u32 = 0x8000_0000;
const V4L2_CTRL_TYPE_INTEGER: u32 = 1;
const V4L2_CTRL_TYPE_BOOLEAN: u32 = 2;
const V4L2_CTRL_TYPE_MENU: u32 = 3;
const V4L2_CTRL_TYPE_BUTTON: u32 = 4;
#[cfg(test)]
const V4L2_CTRL_TYPE_INTEGER64: u32 = 5;
const V4L2_CTRL_TYPE_CTRL_CLASS: u32 = 6;
#[cfg(test)]
const V4L2_CTRL_TYPE_STRING: u32 = 7;
const V4L2_CTRL_TYPE_INTEGER_MENU: u32 = 9;

/// Version of the finite geometry and interval requirements used for range intersections.
pub const CANDIDATE_REQUIREMENTS_VERSION: u32 = 1;

/// One exact nonzero frame geometry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Geometry {
    width: NonZeroU32,
    height: NonZeroU32,
}

impl Geometry {
    /// Constructs an exact geometry.
    ///
    /// # Errors
    ///
    /// Returns an error when either dimension is zero.
    pub fn new(width: u32, height: u32) -> Result<Self, CapabilityError> {
        Ok(Self {
            width: NonZeroU32::new(width).ok_or(CapabilityError::InvalidGeometry)?,
            height: NonZeroU32::new(height).ok_or(CapabilityError::InvalidGeometry)?,
        })
    }

    /// Returns the width in pixels.
    #[must_use]
    pub const fn width(self) -> u32 {
        self.width.get()
    }

    /// Returns the height in pixels.
    #[must_use]
    pub const fn height(self) -> u32 {
        self.height.get()
    }
}

/// Exact advertised frame-size domain with a finite candidate projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeometryDomain {
    kind: GeometryDomainKind,
    materialized: Vec<Geometry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GeometryDomainKind {
    Discrete(Vec<Geometry>),
    Continuous {
        min: Geometry,
        max: Geometry,
    },
    Stepwise {
        min: Geometry,
        max: Geometry,
        step: Geometry,
    },
}

impl GeometryDomain {
    /// Constructs a canonical nonempty discrete domain.
    ///
    /// # Errors
    ///
    /// Returns an error when no geometry was advertised.
    pub fn discrete(mut values: Vec<Geometry>) -> Result<Self, CapabilityError> {
        if values.is_empty() {
            return Err(CapabilityError::Empty {
                stage: CapabilityStage::Geometries,
            });
        }
        values.sort_unstable();
        values.dedup();
        Ok(Self {
            kind: GeometryDomainKind::Discrete(values.clone()),
            materialized: values,
        })
    }

    #[cfg(test)]
    fn discrete_unchecked(values: Vec<Geometry>) -> Self {
        Self {
            kind: GeometryDomainKind::Discrete(values.clone()),
            materialized: values,
        }
    }

    /// Constructs a continuous inclusive frame-size range.
    ///
    /// # Errors
    ///
    /// Returns an error for an inverted range.
    pub fn continuous(min: Geometry, max: Geometry) -> Result<Self, CapabilityError> {
        validate_geometry_range(min, max)?;
        Ok(Self {
            kind: GeometryDomainKind::Continuous { min, max },
            materialized: vec![min, max],
        })
    }

    /// Constructs a stepwise inclusive frame-size range.
    ///
    /// # Errors
    ///
    /// Returns an error for an inverted range. Zero steps are unrepresentable.
    pub fn stepwise(min: Geometry, max: Geometry, step: Geometry) -> Result<Self, CapabilityError> {
        validate_geometry_range(min, max)?;
        Ok(Self {
            kind: GeometryDomainKind::Stepwise { min, max, step },
            materialized: vec![min, max],
        })
    }

    /// Returns the finite exact points selected from this domain.
    #[must_use]
    pub fn materialized(&self) -> &[Geometry] {
        &self.materialized
    }

    /// Returns continuous bounds when this is a continuous domain.
    #[must_use]
    pub const fn continuous_bounds(&self) -> Option<(Geometry, Geometry)> {
        match self.kind {
            GeometryDomainKind::Continuous { min, max } => Some((min, max)),
            GeometryDomainKind::Discrete(_) | GeometryDomainKind::Stepwise { .. } => None,
        }
    }

    /// Returns stepwise bounds and lattice step when this is a stepwise domain.
    #[must_use]
    pub const fn stepwise_parts(&self) -> Option<(Geometry, Geometry, Geometry)> {
        match self.kind {
            GeometryDomainKind::Stepwise { min, max, step } => Some((min, max, step)),
            GeometryDomainKind::Discrete(_) | GeometryDomainKind::Continuous { .. } => None,
        }
    }

    fn advertised_count(&self) -> usize {
        match &self.kind {
            GeometryDomainKind::Discrete(values) => values.len(),
            GeometryDomainKind::Continuous { .. } | GeometryDomainKind::Stepwise { .. } => 1,
        }
    }

    fn contains(&self, geometry: Geometry) -> bool {
        match &self.kind {
            GeometryDomainKind::Discrete(values) => values.binary_search(&geometry).is_ok(),
            GeometryDomainKind::Continuous { min, max } => {
                geometry.width() >= min.width()
                    && geometry.width() <= max.width()
                    && geometry.height() >= min.height()
                    && geometry.height() <= max.height()
            }
            GeometryDomainKind::Stepwise { min, max, step } => {
                geometry.width() >= min.width()
                    && geometry.width() <= max.width()
                    && geometry.height() >= min.height()
                    && geometry.height() <= max.height()
                    && (geometry.width() - min.width()).is_multiple_of(step.width())
                    && (geometry.height() - min.height()).is_multiple_of(step.height())
            }
        }
    }

    fn materialize_for(&mut self, role: StreamRole) {
        if matches!(self.kind, GeometryDomainKind::Discrete(_)) {
            return;
        }
        let intersections: Vec<_> = geometry_requirements(role)
            .iter()
            .copied()
            .filter(|geometry| self.contains(*geometry))
            .collect();
        self.materialized.extend(intersections);
        self.materialized.sort_unstable();
        self.materialized.dedup();
    }
}

fn validate_geometry_range(min: Geometry, max: Geometry) -> Result<(), CapabilityError> {
    if min.width() > max.width() || min.height() > max.height() {
        return Err(CapabilityError::InvalidGeometry);
    }
    Ok(())
}

fn geometry_requirements(role: StreamRole) -> &'static [Geometry] {
    const RGB: [Geometry; 1] = [Geometry {
        width: NonZeroU32::new(640).unwrap(),
        height: NonZeroU32::new(480).unwrap(),
    }];
    const IR: [Geometry; 3] = [
        Geometry {
            width: NonZeroU32::new(340).unwrap(),
            height: NonZeroU32::new(340).unwrap(),
        },
        Geometry {
            width: NonZeroU32::new(640).unwrap(),
            height: NonZeroU32::new(360).unwrap(),
        },
        Geometry {
            width: NonZeroU32::new(640).unwrap(),
            height: NonZeroU32::new(400).unwrap(),
        },
    ];
    match role {
        StreamRole::Rgb => &RGB,
        StreamRole::Ir => &IR,
    }
}

fn interval_requirements() -> [FrameInterval; 7] {
    [
        FrameInterval::new(1, 30).expect("nonzero requirement"),
        FrameInterval::new(1, 24).expect("nonzero requirement"),
        FrameInterval::new(1, 20).expect("nonzero requirement"),
        FrameInterval::new(1, 15).expect("nonzero requirement"),
        FrameInterval::new(1, 10).expect("nonzero requirement"),
        FrameInterval::new(2, 15).expect("nonzero requirement"),
        FrameInterval::new(1, 5).expect("nonzero requirement"),
    ]
}

/// Exact interval domain for one materialized geometry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeometryIntervals {
    geometry: Geometry,
    domain: FrameIntervalDomain,
}

impl GeometryIntervals {
    /// Returns the exact geometry.
    #[must_use]
    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// Returns the complete advertised interval domain.
    #[must_use]
    pub const fn domain(&self) -> &FrameIntervalDomain {
        &self.domain
    }
}

/// One decoded format and its exact advertised geometry and interval domains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormatCapability {
    fourcc: [u8; 4],
    decoded_format: DecodedPixelFormat,
    geometries: GeometryDomain,
    intervals: Vec<GeometryIntervals>,
}

impl FormatCapability {
    /// Returns the exact advertised fourcc.
    #[must_use]
    pub const fn fourcc(&self) -> [u8; 4] {
        self.fourcc
    }

    /// Returns the existing decoder selected for this format.
    #[must_use]
    pub const fn decoded_format(&self) -> DecodedPixelFormat {
        self.decoded_format
    }

    /// Returns the complete geometry domain and finite materialization.
    #[must_use]
    pub const fn geometries(&self) -> &GeometryDomain {
        &self.geometries
    }

    /// Returns exact interval domains for materialized geometries.
    #[must_use]
    pub fn intervals(&self) -> &[GeometryIntervals] {
        &self.intervals
    }
}

/// One bounded menu item retained without UTF-8 assumptions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MenuValue {
    /// Named menu item, including any NUL padding from the ABI.
    Name { index: u32, bytes: [u8; 32] },
    /// Integer menu item.
    Integer { index: u32, value: i64 },
}

impl MenuValue {
    const fn index(self) -> u32 {
        match self {
            Self::Name { index, .. } | Self::Integer { index, .. } => index,
        }
    }
}

/// One raw standard V4L2 control description and its policy eligibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandardControlCapability {
    id: u32,
    control_type: u32,
    minimum: i32,
    maximum: i32,
    step: i32,
    default: i32,
    flags: u32,
    menu_values: Vec<MenuValue>,
    policy_eligible: bool,
}

impl StandardControlCapability {
    /// Returns the V4L2 control identifier.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the raw V4L2 control type.
    #[must_use]
    pub const fn control_type(&self) -> u32 {
        self.control_type
    }

    /// Returns the inclusive minimum.
    #[must_use]
    pub const fn minimum(&self) -> i32 {
        self.minimum
    }

    /// Returns the inclusive maximum.
    #[must_use]
    pub const fn maximum(&self) -> i32 {
        self.maximum
    }

    /// Returns the exact control step.
    #[must_use]
    pub const fn step(&self) -> i32 {
        self.step
    }

    /// Returns the driver-advertised default.
    #[must_use]
    pub const fn default(&self) -> i32 {
        self.default
    }

    /// Returns the raw V4L2 flags.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns bounded exact menu entries.
    #[must_use]
    pub fn menu_values(&self) -> &[MenuValue] {
        &self.menu_values
    }

    /// Returns whether a later qualified policy may name this control.
    #[must_use]
    pub const fn policy_eligible(&self) -> bool {
        self.policy_eligible
    }
}

/// Stage at which an observation failed or exceeded its bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityStage {
    Formats,
    Geometries,
    Intervals,
    Controls,
    MenuValues,
}

/// Fail-closed capability observation error.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CapabilityError {
    Enumeration {
        stage: CapabilityStage,
        errno: Option<i32>,
    },
    Empty {
        stage: CapabilityStage,
    },
    Capacity {
        stage: CapabilityStage,
        limit: usize,
    },
    InvalidGeometry,
    InvalidControl {
        id: u32,
        reason: &'static str,
    },
    Malformed {
        stage: CapabilityStage,
        reason: &'static str,
    },
    Device(String),
    Profile(ProfileError),
}

impl CapabilityError {
    const fn enumeration(stage: CapabilityStage, errno: Option<i32>) -> Self {
        Self::Enumeration { stage, errno }
    }
}

impl std::fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enumeration { stage, errno } => {
                write!(
                    formatter,
                    "capability {stage:?} enumeration failed (errno {errno:?})"
                )
            }
            Self::Empty { stage } => write!(formatter, "capability {stage:?} observation is empty"),
            Self::Capacity { stage, limit } => {
                write!(formatter, "capability {stage:?} exceeded limit {limit}")
            }
            Self::InvalidGeometry => formatter.write_str("invalid capability geometry"),
            Self::InvalidControl { id, reason } => {
                write!(formatter, "invalid V4L2 control {id:#x}: {reason}")
            }
            Self::Malformed { stage, reason } => {
                write!(formatter, "malformed capability {stage:?}: {reason}")
            }
            Self::Device(message) => formatter.write_str(message),
            Self::Profile(error) => write!(formatter, "invalid candidate tuple: {error}"),
        }
    }
}

impl std::error::Error for CapabilityError {}

/// One complete observation-only capability snapshot for a stream endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityInventory {
    requirements_version: u32,
    formats: Vec<FormatCapability>,
    tuples: Vec<StreamTuple>,
    controls: Vec<StandardControlCapability>,
    unsupported_format_count: usize,
}

impl CapabilityInventory {
    /// Reads a bounded inventory through one pinned, leased, read-only fd.
    ///
    /// # Errors
    ///
    /// Returns an error for lifecycle, open, enumeration, validation, or cap failure.
    pub fn read(device: &str, role: StreamRole) -> Result<Self, CapabilityError> {
        crate::verify_pinned(device).map_err(|error| CapabilityError::Device(error.to_string()))?;
        let permit = crate::lease::permit_for_endpoint(
            device,
            crate::lease::CameraOperationKind::Diagnostics,
            std::time::Duration::from_secs(2),
        )
        .map_err(|error| CapabilityError::Device(error.to_string()))?;
        permit
            .require_endpoint(device)
            .map_err(|error| CapabilityError::Device(error.to_string()))?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(device)
            .map_err(|error| CapabilityError::Device(format!("{device}: {error}")))?;
        let mut source = IoctlSource { file };
        let inventory = inventory_from_source(&mut source, role)?;
        permit
            .require_endpoint(device)
            .map_err(|error| CapabilityError::Device(error.to_string()))?;
        Ok(inventory)
    }

    /// Returns the versioned finite-intersection policy.
    #[must_use]
    pub const fn requirements_version(&self) -> u32 {
        self.requirements_version
    }

    /// Returns decoded format domains.
    #[must_use]
    pub fn formats(&self) -> &[FormatCapability] {
        &self.formats
    }

    /// Returns finite exact candidate tuples without qualification authority.
    #[must_use]
    pub fn tuples(&self) -> &[StreamTuple] {
        &self.tuples
    }

    /// Returns bounded standard control observations.
    #[must_use]
    pub fn controls(&self) -> &[StandardControlCapability] {
        &self.controls
    }

    /// Returns the number of unique advertised formats with no current decoder for this role.
    #[must_use]
    pub const fn unsupported_format_count(&self) -> usize {
        self.unsupported_format_count
    }
}

trait CapabilitySource {
    fn formats(&mut self) -> Result<Vec<[u8; 4]>, CapabilityError>;
    fn frame_sizes(&mut self, fourcc: [u8; 4]) -> Result<GeometryDomain, CapabilityError>;
    fn intervals(
        &mut self,
        query: FrameIntervalQuery,
    ) -> Result<FrameIntervalDomain, CapabilityError>;
    fn controls(&mut self) -> Result<Vec<StandardControlCapability>, CapabilityError>;
}

fn inventory_from_source<S: CapabilitySource>(
    source: &mut S,
    role: StreamRole,
) -> Result<CapabilityInventory, CapabilityError> {
    let raw_formats = source.formats()?;
    if raw_formats.is_empty() {
        return Err(CapabilityError::Empty {
            stage: CapabilityStage::Formats,
        });
    }
    enforce_capacity(raw_formats.len(), MAX_FORMATS, CapabilityStage::Formats)?;

    let mut seen_formats = HashSet::new();
    let formats: Vec<_> = raw_formats
        .into_iter()
        .filter(|fourcc| seen_formats.insert(*fourcc))
        .collect();
    let mut unsupported_format_count = 0;
    let mut capabilities = Vec::new();
    let mut tuples = Vec::new();
    let mut seen_tuples = HashSet::new();

    for fourcc in formats {
        let Some(decoded_format) = DecodedPixelFormat::from_fourcc(fourcc)
            .filter(|format| format_allowed_for_role(role, *format))
        else {
            unsupported_format_count += 1;
            continue;
        };
        let mut geometries = source.frame_sizes(fourcc)?;
        enforce_capacity(
            geometries.advertised_count(),
            MAX_GEOMETRIES_PER_FORMAT,
            CapabilityStage::Geometries,
        )?;
        geometries.materialize_for(role);

        let mut interval_capabilities = Vec::with_capacity(geometries.materialized().len());
        for geometry in geometries.materialized().iter().copied() {
            let query = FrameIntervalQuery::new(fourcc, geometry.width(), geometry.height())
                .map_err(map_interval_error)?;
            let domain = source.intervals(query)?;
            if let Some(values) = domain.discrete_values() {
                enforce_capacity(
                    values.len(),
                    MAX_INTERVALS_PER_TUPLE,
                    CapabilityStage::Intervals,
                )?;
            }
            for interval in domain.candidate_values(&interval_requirements()) {
                let tuple = StreamTuple::new(
                    role,
                    decoded_format,
                    geometry.width(),
                    geometry.height(),
                    interval,
                )
                .map_err(CapabilityError::Profile)?;
                if seen_tuples.insert(tuple.clone()) {
                    tuples.push(tuple);
                }
            }
            interval_capabilities.push(GeometryIntervals { geometry, domain });
        }
        capabilities.push(FormatCapability {
            fourcc,
            decoded_format,
            geometries,
            intervals: interval_capabilities,
        });
    }

    let mut controls = source.controls()?;
    enforce_capacity(controls.len(), MAX_CONTROLS, CapabilityStage::Controls)?;
    controls.retain(|control| is_standard_control_class(control.id));
    for control in &mut controls {
        validate_control(control)?;
        control.policy_eligible = matches!(
            control.control_type,
            V4L2_CTRL_TYPE_INTEGER
                | V4L2_CTRL_TYPE_BOOLEAN
                | V4L2_CTRL_TYPE_MENU
                | V4L2_CTRL_TYPE_INTEGER_MENU
        ) && control.flags
            & (V4L2_CTRL_FLAG_DISABLED
                | V4L2_CTRL_FLAG_READ_ONLY
                | V4L2_CTRL_FLAG_WRITE_ONLY
                | V4L2_CTRL_FLAG_EXECUTE_ON_WRITE)
            == 0;
    }

    Ok(CapabilityInventory {
        requirements_version: CANDIDATE_REQUIREMENTS_VERSION,
        formats: capabilities,
        tuples,
        controls,
        unsupported_format_count,
    })
}

fn enforce_capacity(
    actual: usize,
    limit: usize,
    stage: CapabilityStage,
) -> Result<(), CapabilityError> {
    if actual > limit {
        return Err(CapabilityError::Capacity { stage, limit });
    }
    Ok(())
}

const fn format_allowed_for_role(role: StreamRole, format: DecodedPixelFormat) -> bool {
    match role {
        StreamRole::Rgb => matches!(format, DecodedPixelFormat::Yuyv | DecodedPixelFormat::Nv12),
        StreamRole::Ir => true,
    }
}

const fn is_standard_control_class(id: u32) -> bool {
    matches!(
        id & V4L2_CTRL_CLASS_MASK,
        V4L2_CTRL_CLASS_USER | V4L2_CTRL_CLASS_CAMERA | V4L2_CTRL_CLASS_IMAGE_SOURCE
    )
}

fn validate_control(control: &StandardControlCapability) -> Result<(), CapabilityError> {
    enforce_capacity(
        control.menu_values.len(),
        MAX_MENU_VALUES,
        CapabilityStage::MenuValues,
    )?;
    match control.control_type {
        V4L2_CTRL_TYPE_BUTTON | V4L2_CTRL_TYPE_CTRL_CLASS => {
            if (
                control.minimum,
                control.maximum,
                control.step,
                control.default,
            ) != (0, 0, 0, 0)
            {
                return Err(CapabilityError::InvalidControl {
                    id: control.id,
                    reason: "special control has scalar range",
                });
            }
        }
        V4L2_CTRL_TYPE_INTEGER
        | V4L2_CTRL_TYPE_BOOLEAN
        | V4L2_CTRL_TYPE_MENU
        | V4L2_CTRL_TYPE_INTEGER_MENU => {
            if control.minimum > control.maximum {
                return Err(CapabilityError::InvalidControl {
                    id: control.id,
                    reason: "minimum exceeds maximum",
                });
            }
            if control.step <= 0 {
                return Err(CapabilityError::InvalidControl {
                    id: control.id,
                    reason: "step is not positive",
                });
            }
            if control.default < control.minimum || control.default > control.maximum {
                return Err(CapabilityError::InvalidControl {
                    id: control.id,
                    reason: "default is outside range",
                });
            }
            if (i64::from(control.default) - i64::from(control.minimum)) % i64::from(control.step)
                != 0
            {
                return Err(CapabilityError::InvalidControl {
                    id: control.id,
                    reason: "default is off the control lattice",
                });
            }
        }
        _ => {}
    }

    let is_menu = matches!(
        control.control_type,
        V4L2_CTRL_TYPE_MENU | V4L2_CTRL_TYPE_INTEGER_MENU
    );
    if !is_menu && !control.menu_values.is_empty() {
        return Err(CapabilityError::InvalidControl {
            id: control.id,
            reason: "non-menu control has menu values",
        });
    }
    let mut indexes = HashSet::new();
    for value in &control.menu_values {
        let index = value.index();
        if index > i32::MAX as u32
            || (index as i32) < control.minimum
            || (index as i32) > control.maximum
            || !indexes.insert(index)
        {
            return Err(CapabilityError::InvalidControl {
                id: control.id,
                reason: "invalid menu index",
            });
        }
    }
    if is_menu && !indexes.contains(&(control.default as u32)) {
        return Err(CapabilityError::InvalidControl {
            id: control.id,
            reason: "menu does not contain its default index",
        });
    }
    Ok(())
}

fn map_interval_error(error: FrameIntervalError) -> CapabilityError {
    match error {
        FrameIntervalError::TooMany => CapabilityError::Capacity {
            stage: CapabilityStage::Intervals,
            limit: MAX_INTERVALS_PER_TUPLE,
        },
        FrameIntervalError::Io { errno, .. } => {
            CapabilityError::enumeration(CapabilityStage::Intervals, errno)
        }
        FrameIntervalError::InitialQueryUnsupported => {
            CapabilityError::enumeration(CapabilityStage::Intervals, Some(libc::EINVAL))
        }
        _ => CapabilityError::Malformed {
            stage: CapabilityStage::Intervals,
            reason: "invalid frame interval response",
        },
    }
}

struct IoctlSource {
    file: File,
}

impl CapabilitySource for IoctlSource {
    fn formats(&mut self) -> Result<Vec<[u8; 4]>, CapabilityError> {
        enumerate_formats(self.file.as_raw_fd())
    }

    fn frame_sizes(&mut self, fourcc: [u8; 4]) -> Result<GeometryDomain, CapabilityError> {
        enumerate_frame_sizes(self.file.as_raw_fd(), fourcc)
    }

    fn intervals(
        &mut self,
        query: FrameIntervalQuery,
    ) -> Result<FrameIntervalDomain, CapabilityError> {
        let (fourcc, width, height) = query.parts();
        crate::frame_interval::frame_interval_capabilities_for_fd(
            "capability inventory fd",
            self.file.as_raw_fd(),
            fourcc,
            width,
            height,
        )
        .map_err(map_interval_error)
    }

    fn controls(&mut self) -> Result<Vec<StandardControlCapability>, CapabilityError> {
        enumerate_controls(self.file.as_raw_fd())
    }
}

fn enumerate_formats(fd: RawFd) -> Result<Vec<[u8; 4]>, CapabilityError> {
    let mut values = Vec::with_capacity(MAX_FORMATS);
    for index in 0..=MAX_FORMATS {
        // SAFETY: v4l2_fmtdesc is a plain C ABI structure and zero is a valid
        // initialization before setting its documented input fields.
        let mut raw: v4l::v4l_sys::v4l2_fmtdesc = unsafe { std::mem::zeroed() };
        raw.index = index as u32;
        raw.type_ = v4l::buffer::Type::VideoCapture as u32;
        match ioctl(fd, v4l::v4l2::vidioc::VIDIOC_ENUM_FMT, &mut raw) {
            Ok(()) => {
                if index == MAX_FORMATS {
                    return Err(CapabilityError::Capacity {
                        stage: CapabilityStage::Formats,
                        limit: MAX_FORMATS,
                    });
                }
                if raw.index != index as u32
                    || raw.type_ != v4l::buffer::Type::VideoCapture as u32
                    || raw.reserved != [0; 3]
                {
                    return Err(CapabilityError::Malformed {
                        stage: CapabilityStage::Formats,
                        reason: "format query echo or reserved field mismatch",
                    });
                }
                values.push(raw.pixelformat.to_le_bytes());
            }
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => return Ok(values),
            Err(error) => {
                return Err(CapabilityError::enumeration(
                    CapabilityStage::Formats,
                    error.raw_os_error(),
                ));
            }
        }
    }
    unreachable!("bounded format loop returns at its cap")
}

fn enumerate_frame_sizes(fd: RawFd, fourcc: [u8; 4]) -> Result<GeometryDomain, CapabilityError> {
    let mut discrete = Vec::with_capacity(MAX_GEOMETRIES_PER_FORMAT);
    for index in 0..=MAX_GEOMETRIES_PER_FORMAT {
        // SAFETY: v4l2_frmsizeenum is a plain C ABI structure and zero is a
        // valid initialization before setting its documented input fields.
        let mut raw: v4l::v4l_sys::v4l2_frmsizeenum = unsafe { std::mem::zeroed() };
        raw.index = index as u32;
        raw.pixel_format = u32::from_le_bytes(fourcc);
        match ioctl(fd, v4l::v4l2::vidioc::VIDIOC_ENUM_FRAMESIZES, &mut raw) {
            Ok(()) => {
                if raw.index != index as u32
                    || raw.pixel_format != u32::from_le_bytes(fourcc)
                    || raw.reserved != [0; 2]
                {
                    return Err(CapabilityError::Malformed {
                        stage: CapabilityStage::Geometries,
                        reason: "frame-size query echo or reserved field mismatch",
                    });
                }
                match raw.type_ {
                    v4l::v4l_sys::v4l2_frmsizetypes_V4L2_FRMSIZE_TYPE_DISCRETE => {
                        if index == MAX_GEOMETRIES_PER_FORMAT {
                            return Err(CapabilityError::Capacity {
                                stage: CapabilityStage::Geometries,
                                limit: MAX_GEOMETRIES_PER_FORMAT,
                            });
                        }
                        // SAFETY: the driver selected the discrete union arm.
                        let value = unsafe { raw.__bindgen_anon_1.discrete };
                        discrete.push(Geometry::new(value.width, value.height)?);
                    }
                    v4l::v4l_sys::v4l2_frmsizetypes_V4L2_FRMSIZE_TYPE_CONTINUOUS
                    | v4l::v4l_sys::v4l2_frmsizetypes_V4L2_FRMSIZE_TYPE_STEPWISE => {
                        if index != 0 {
                            return Err(CapabilityError::Malformed {
                                stage: CapabilityStage::Geometries,
                                reason: "frame-size response changed domain type",
                            });
                        }
                        // SAFETY: both range types use the stepwise union arm.
                        let value = unsafe { raw.__bindgen_anon_1.stepwise };
                        let min = Geometry::new(value.min_width, value.min_height)?;
                        let max = Geometry::new(value.max_width, value.max_height)?;
                        let domain = if raw.type_
                            == v4l::v4l_sys::v4l2_frmsizetypes_V4L2_FRMSIZE_TYPE_CONTINUOUS
                        {
                            GeometryDomain::continuous(min, max)?
                        } else {
                            GeometryDomain::stepwise(
                                min,
                                max,
                                Geometry::new(value.step_width, value.step_height)?,
                            )?
                        };
                        ensure_no_extra_frame_size(fd, fourcc)?;
                        return Ok(domain);
                    }
                    _ => {
                        return Err(CapabilityError::Malformed {
                            stage: CapabilityStage::Geometries,
                            reason: "unknown frame-size domain type",
                        });
                    }
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
                return GeometryDomain::discrete(discrete);
            }
            Err(error) => {
                return Err(CapabilityError::enumeration(
                    CapabilityStage::Geometries,
                    error.raw_os_error(),
                ));
            }
        }
    }
    unreachable!("bounded geometry loop returns at its cap")
}

fn ensure_no_extra_frame_size(fd: RawFd, fourcc: [u8; 4]) -> Result<(), CapabilityError> {
    // SAFETY: v4l2_frmsizeenum is a plain C ABI structure and zero is a valid
    // initialization before setting its documented input fields.
    let mut raw: v4l::v4l_sys::v4l2_frmsizeenum = unsafe { std::mem::zeroed() };
    raw.index = 1;
    raw.pixel_format = u32::from_le_bytes(fourcc);
    match ioctl(fd, v4l::v4l2::vidioc::VIDIOC_ENUM_FRAMESIZES, &mut raw) {
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => Ok(()),
        Ok(()) => Err(CapabilityError::Malformed {
            stage: CapabilityStage::Geometries,
            reason: "range frame-size domain has an extra record",
        }),
        Err(error) => Err(CapabilityError::enumeration(
            CapabilityStage::Geometries,
            error.raw_os_error(),
        )),
    }
}

fn enumerate_controls(fd: RawFd) -> Result<Vec<StandardControlCapability>, CapabilityError> {
    let mut controls = Vec::with_capacity(MAX_CONTROLS);
    let mut previous_id = None;
    let mut next_id = V4L2_CTRL_FLAG_NEXT_CTRL;
    for index in 0..=MAX_CONTROLS {
        // SAFETY: v4l2_queryctrl is a plain C ABI structure and zero is a
        // valid initialization before setting its documented query id.
        let mut raw: v4l::v4l_sys::v4l2_queryctrl = unsafe { std::mem::zeroed() };
        raw.id = next_id;
        match ioctl(fd, v4l::v4l2::vidioc::VIDIOC_QUERYCTRL, &mut raw) {
            Ok(()) => {
                if index == MAX_CONTROLS {
                    return Err(CapabilityError::Capacity {
                        stage: CapabilityStage::Controls,
                        limit: MAX_CONTROLS,
                    });
                }
                if raw.reserved != [0; 2] || previous_id.is_some_and(|previous| raw.id <= previous)
                {
                    return Err(CapabilityError::Malformed {
                        stage: CapabilityStage::Controls,
                        reason: "control id did not advance or reserved field is nonzero",
                    });
                }
                let menu_values = if is_standard_control_class(raw.id)
                    && matches!(raw.type_, V4L2_CTRL_TYPE_MENU | V4L2_CTRL_TYPE_INTEGER_MENU)
                {
                    enumerate_menu(fd, &raw)?
                } else {
                    Vec::new()
                };
                controls.push(StandardControlCapability {
                    id: raw.id,
                    control_type: raw.type_,
                    minimum: raw.minimum,
                    maximum: raw.maximum,
                    step: raw.step,
                    default: raw.default_value,
                    flags: raw.flags,
                    menu_values,
                    policy_eligible: false,
                });
                previous_id = Some(raw.id);
                next_id = raw.id | V4L2_CTRL_FLAG_NEXT_CTRL;
            }
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => return Ok(controls),
            Err(error) => {
                return Err(CapabilityError::enumeration(
                    CapabilityStage::Controls,
                    error.raw_os_error(),
                ));
            }
        }
    }
    unreachable!("bounded control loop returns at its cap")
}

fn enumerate_menu(
    fd: RawFd,
    control: &v4l::v4l_sys::v4l2_queryctrl,
) -> Result<Vec<MenuValue>, CapabilityError> {
    if control.minimum < 0 || control.maximum < control.minimum {
        return Err(CapabilityError::InvalidControl {
            id: control.id,
            reason: "menu index range is invalid",
        });
    }
    let count = i64::from(control.maximum) - i64::from(control.minimum) + 1;
    if count > MAX_MENU_VALUES as i64 {
        return Err(CapabilityError::Capacity {
            stage: CapabilityStage::MenuValues,
            limit: MAX_MENU_VALUES,
        });
    }
    let mut values = Vec::new();
    for index in control.minimum..=control.maximum {
        // SAFETY: v4l2_querymenu is a plain C ABI structure and zero is a valid
        // initialization before setting its documented id and index.
        let mut raw: v4l::v4l_sys::v4l2_querymenu = unsafe { std::mem::zeroed() };
        raw.id = control.id;
        raw.index = index as u32;
        match ioctl(fd, v4l::v4l2::vidioc::VIDIOC_QUERYMENU, &mut raw) {
            Ok(()) => {
                if raw.reserved != 0 || raw.id != control.id || raw.index != index as u32 {
                    return Err(CapabilityError::Malformed {
                        stage: CapabilityStage::MenuValues,
                        reason: "menu query echo or reserved field mismatch",
                    });
                }
                let value = if control.type_ == V4L2_CTRL_TYPE_MENU {
                    // SAFETY: menu controls select the name union arm.
                    let bytes = unsafe { raw.__bindgen_anon_1.name };
                    MenuValue::Name {
                        index: raw.index,
                        bytes,
                    }
                } else {
                    // SAFETY: integer-menu controls select the value union arm.
                    let value = unsafe { raw.__bindgen_anon_1.value };
                    MenuValue::Integer {
                        index: raw.index,
                        value,
                    }
                };
                values.push(value);
            }
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {}
            Err(error) => {
                return Err(CapabilityError::enumeration(
                    CapabilityStage::MenuValues,
                    error.raw_os_error(),
                ));
            }
        }
    }
    Ok(values)
}

fn ioctl<T>(fd: RawFd, request: libc::c_ulong, value: &mut T) -> std::io::Result<()> {
    // SAFETY: each caller supplies the ABI structure matching `request`; the
    // borrowed fd and mutable structure remain valid for the complete call.
    let result = unsafe { libc::ioctl(fd, request, value as *mut T as *mut libc::c_void) };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        contracts::StreamRole,
        frame_interval::{FrameInterval, FrameIntervalDomain, FrameIntervalQuery},
        profile::DecodedPixelFormat,
    };
    use std::collections::BTreeMap;

    fn interval(numerator: u32, denominator: u32) -> FrameInterval {
        FrameInterval::new(numerator, denominator).unwrap()
    }

    fn discrete_intervals(values: &[(u32, u32)]) -> FrameIntervalDomain {
        FrameIntervalDomain::discrete(
            values
                .iter()
                .map(|&(numerator, denominator)| interval(numerator, denominator))
                .collect(),
        )
        .unwrap()
    }

    fn discrete_sizes(values: &[(u32, u32)]) -> GeometryDomain {
        GeometryDomain::discrete(
            values
                .iter()
                .map(|&(width, height)| Geometry::new(width, height).unwrap())
                .collect(),
        )
        .unwrap()
    }

    struct FakeSource {
        formats: Result<Vec<[u8; 4]>, CapabilityError>,
        sizes: BTreeMap<[u8; 4], Result<GeometryDomain, CapabilityError>>,
        intervals: BTreeMap<([u8; 4], u32, u32), Result<FrameIntervalDomain, CapabilityError>>,
        controls: Result<Vec<StandardControlCapability>, CapabilityError>,
    }

    impl FakeSource {
        fn new(formats: Vec<[u8; 4]>) -> Self {
            Self {
                formats: Ok(formats),
                sizes: BTreeMap::new(),
                intervals: BTreeMap::new(),
                controls: Ok(Vec::new()),
            }
        }

        fn format_error(errno: i32) -> Self {
            Self {
                formats: Err(CapabilityError::enumeration(
                    CapabilityStage::Formats,
                    Some(errno),
                )),
                sizes: BTreeMap::new(),
                intervals: BTreeMap::new(),
                controls: Ok(Vec::new()),
            }
        }

        fn with_format(
            mut self,
            fourcc: [u8; 4],
            sizes: GeometryDomain,
            intervals: impl IntoIterator<
                Item = ((u32, u32), Result<FrameIntervalDomain, CapabilityError>),
            >,
        ) -> Self {
            self.sizes.insert(fourcc, Ok(sizes));
            self.intervals.extend(
                intervals
                    .into_iter()
                    .map(|((width, height), domain)| ((fourcc, width, height), domain)),
            );
            self
        }
    }

    impl CapabilitySource for FakeSource {
        fn formats(&mut self) -> Result<Vec<[u8; 4]>, CapabilityError> {
            std::mem::replace(
                &mut self.formats,
                Err(CapabilityError::enumeration(
                    CapabilityStage::Formats,
                    Some(libc::EIO),
                )),
            )
        }

        fn frame_sizes(&mut self, fourcc: [u8; 4]) -> Result<GeometryDomain, CapabilityError> {
            self.sizes.remove(&fourcc).unwrap_or_else(|| {
                Err(CapabilityError::enumeration(
                    CapabilityStage::Geometries,
                    Some(libc::EINVAL),
                ))
            })
        }

        fn intervals(
            &mut self,
            query: FrameIntervalQuery,
        ) -> Result<FrameIntervalDomain, CapabilityError> {
            let (fourcc, width, height) = query.parts();
            self.intervals
                .remove(&(fourcc, width, height))
                .unwrap_or_else(|| {
                    Err(CapabilityError::enumeration(
                        CapabilityStage::Intervals,
                        Some(libc::EINVAL),
                    ))
                })
        }

        fn controls(&mut self) -> Result<Vec<StandardControlCapability>, CapabilityError> {
            std::mem::replace(
                &mut self.controls,
                Err(CapabilityError::enumeration(
                    CapabilityStage::Controls,
                    Some(libc::EIO),
                )),
            )
        }
    }

    fn tuple_parts(
        inventory: &CapabilityInventory,
    ) -> Vec<(DecodedPixelFormat, u32, u32, (u32, u32))> {
        inventory
            .tuples()
            .iter()
            .map(|tuple| {
                (
                    tuple.format(),
                    tuple.width(),
                    tuple.height(),
                    tuple.interval().parts(),
                )
            })
            .collect()
    }

    fn asus_fixture(role: StreamRole) -> FakeSource {
        match role {
            StreamRole::Rgb => FakeSource::new(vec![*b"YUYV", *b"MJPG"]).with_format(
                *b"YUYV",
                discrete_sizes(&[(640, 480)]),
                [((640, 480), Ok(discrete_intervals(&[(1, 30), (1, 15)])))],
            ),
            StreamRole::Ir => FakeSource::new(vec![*b"GREY"]).with_format(
                *b"GREY",
                discrete_sizes(&[(640, 400)]),
                [((640, 400), Ok(discrete_intervals(&[(1, 15)])))],
            ),
        }
    }

    fn brio_fixture(role: StreamRole) -> FakeSource {
        match role {
            StreamRole::Rgb => FakeSource::new(vec![*b"YUYV", *b"MJPG"]).with_format(
                *b"YUYV",
                discrete_sizes(&[(640, 480)]),
                [(
                    (640, 480),
                    Ok(discrete_intervals(&[
                        (1, 30),
                        (1, 24),
                        (1, 20),
                        (1, 15),
                        (1, 10),
                        (2, 15),
                        (1, 5),
                    ])),
                )],
            ),
            StreamRole::Ir => FakeSource::new(vec![*b"GREY"]).with_format(
                *b"GREY",
                discrete_sizes(&[(340, 340)]),
                [((340, 340), Ok(discrete_intervals(&[(1, 30)])))],
            ),
        }
    }

    fn nexigo_fixture(role: StreamRole) -> FakeSource {
        match role {
            StreamRole::Rgb => FakeSource::new(vec![*b"YUYV", *b"MJPG"]).with_format(
                *b"YUYV",
                discrete_sizes(&[(640, 480)]),
                [((640, 480), Ok(discrete_intervals(&[(1, 30)])))],
            ),
            StreamRole::Ir => FakeSource::new(vec![*b"GREY"]).with_format(
                *b"GREY",
                discrete_sizes(&[(640, 360)]),
                [((640, 360), Ok(discrete_intervals(&[(1, 30)])))],
            ),
        }
    }

    #[test]
    fn failed_or_missing_format_enumeration_is_not_an_empty_capability_claim() {
        let error =
            inventory_from_source(&mut FakeSource::format_error(libc::EIO), StreamRole::Rgb)
                .unwrap_err();
        assert!(matches!(
            error,
            CapabilityError::Enumeration {
                stage: CapabilityStage::Formats,
                errno: Some(libc::EIO)
            }
        ));

        let error =
            inventory_from_source(&mut FakeSource::new(Vec::new()), StreamRole::Rgb).unwrap_err();
        assert_eq!(
            error,
            CapabilityError::Empty {
                stage: CapabilityStage::Formats
            }
        );
    }

    #[test]
    fn only_role_decodable_exact_tuples_become_candidates() {
        let inventory =
            inventory_from_source(&mut asus_fixture(StreamRole::Rgb), StreamRole::Rgb).unwrap();
        assert_eq!(inventory.unsupported_format_count(), 1);
        assert_eq!(
            tuple_parts(&inventory),
            vec![
                (DecodedPixelFormat::Yuyv, 640, 480, (1, 30)),
                (DecodedPixelFormat::Yuyv, 640, 480, (1, 15)),
            ]
        );

        let mut wrong_role = FakeSource::new(vec![*b"GREY"]).with_format(
            *b"GREY",
            discrete_sizes(&[(640, 480)]),
            [((640, 480), Ok(discrete_intervals(&[(1, 30)])))],
        );
        let inventory = inventory_from_source(&mut wrong_role, StreamRole::Rgb).unwrap();
        assert!(inventory.tuples().is_empty());
        assert_eq!(inventory.unsupported_format_count(), 1);
    }

    #[test]
    fn discrete_and_range_domains_materialize_only_exact_bounded_points() {
        let sizes = GeometryDomain::stepwise(
            Geometry::new(320, 240).unwrap(),
            Geometry::new(800, 600).unwrap(),
            Geometry::new(160, 120).unwrap(),
        )
        .unwrap();
        let range = FrameIntervalDomain::continuous(interval(1, 30), interval(1, 5)).unwrap();
        let mut source = FakeSource::new(vec![*b"YUYV"]).with_format(
            *b"YUYV",
            sizes,
            [
                ((320, 240), Ok(range.clone())),
                ((640, 480), Ok(range.clone())),
                ((800, 600), Ok(range)),
            ],
        );

        let inventory = inventory_from_source(&mut source, StreamRole::Rgb).unwrap();
        assert_eq!(inventory.formats()[0].geometries().materialized().len(), 3);
        assert_eq!(inventory.tuples().len(), 21);
        assert!(inventory
            .tuples()
            .iter()
            .any(|tuple| tuple.width() == 640 && tuple.interval() == interval(1, 24)));
        assert!(!inventory
            .tuples()
            .iter()
            .any(|tuple| tuple.interval() == interval(1, 17)));
    }

    #[test]
    fn stepwise_intersections_must_lie_on_both_exact_lattices() {
        let sizes = GeometryDomain::stepwise(
            Geometry::new(300, 220).unwrap(),
            Geometry::new(700, 520).unwrap(),
            Geometry::new(200, 150).unwrap(),
        )
        .unwrap();
        let intervals =
            FrameIntervalDomain::stepwise(interval(1, 30), interval(1, 10), interval(1, 60))
                .unwrap();
        let mut source = FakeSource::new(vec![*b"YUYV"]).with_format(
            *b"YUYV",
            sizes,
            [
                ((300, 220), Ok(intervals.clone())),
                ((700, 520), Ok(intervals)),
            ],
        );

        let inventory = inventory_from_source(&mut source, StreamRole::Rgb).unwrap();
        assert!(inventory
            .tuples()
            .iter()
            .all(|tuple| tuple.width() != 640 || tuple.height() != 480));
        assert!(inventory
            .tuples()
            .iter()
            .all(|tuple| tuple.interval() != interval(1, 24)));
        assert!(inventory
            .tuples()
            .iter()
            .any(|tuple| tuple.interval() == interval(1, 20)));
    }

    #[test]
    fn range_geometry_domains_remain_observable_after_materialization() {
        let min = Geometry::new(320, 240).unwrap();
        let max = Geometry::new(800, 600).unwrap();
        let step = Geometry::new(160, 120).unwrap();
        assert_eq!(
            GeometryDomain::continuous(min, max)
                .unwrap()
                .continuous_bounds(),
            Some((min, max))
        );
        assert_eq!(
            GeometryDomain::stepwise(min, max, step)
                .unwrap()
                .stepwise_parts(),
            Some((min, max, step))
        );
    }

    #[test]
    fn duplicate_advertisements_never_duplicate_candidate_tuples() {
        let mut source = FakeSource::new(vec![*b"YUYV", *b"YUYV"]);
        source
            .sizes
            .insert(*b"YUYV", Ok(discrete_sizes(&[(640, 480), (640, 480)])));
        source
            .intervals
            .insert((*b"YUYV", 640, 480), Ok(discrete_intervals(&[(1, 30)])));
        let inventory = inventory_from_source(&mut source, StreamRole::Rgb).unwrap();
        assert_eq!(inventory.tuples().len(), 1);
    }

    #[test]
    fn every_enumeration_dimension_is_hard_capped() {
        let formats = (0..=MAX_FORMATS)
            .map(|index| (index as u32).to_le_bytes())
            .collect();
        assert!(matches!(
            inventory_from_source(&mut FakeSource::new(formats), StreamRole::Rgb),
            Err(CapabilityError::Capacity {
                stage: CapabilityStage::Formats,
                limit: MAX_FORMATS
            })
        ));

        let mut geometry_source = FakeSource::new(vec![*b"YUYV"]);
        geometry_source.sizes.insert(
            *b"YUYV",
            Ok(GeometryDomain::discrete_unchecked(
                (1..=MAX_GEOMETRIES_PER_FORMAT + 1)
                    .map(|width| Geometry::new(width as u32, 1).unwrap())
                    .collect(),
            )),
        );
        assert!(matches!(
            inventory_from_source(&mut geometry_source, StreamRole::Rgb),
            Err(CapabilityError::Capacity {
                stage: CapabilityStage::Geometries,
                limit: MAX_GEOMETRIES_PER_FORMAT
            })
        ));

        let mut interval_source = FakeSource::new(vec![*b"YUYV"]).with_format(
            *b"YUYV",
            discrete_sizes(&[(640, 480)]),
            [(
                (640, 480),
                Ok(FrameIntervalDomain::discrete(
                    (1..=MAX_INTERVALS_PER_TUPLE + 1)
                        .map(|numerator| interval(numerator as u32, 300))
                        .collect(),
                )
                .unwrap()),
            )],
        );
        assert!(matches!(
            inventory_from_source(&mut interval_source, StreamRole::Rgb),
            Err(CapabilityError::Capacity {
                stage: CapabilityStage::Intervals,
                limit: MAX_INTERVALS_PER_TUPLE
            })
        ));

        let mut control_source = FakeSource::new(vec![*b"MJPG"]);
        control_source.controls = Ok((0..=MAX_CONTROLS)
            .map(|offset| valid_control(V4L2_CTRL_CLASS_USER | 0x900 | offset as u32))
            .collect());
        assert!(matches!(
            inventory_from_source(&mut control_source, StreamRole::Rgb),
            Err(CapabilityError::Capacity {
                stage: CapabilityStage::Controls,
                limit: MAX_CONTROLS
            })
        ));
    }

    fn valid_control(id: u32) -> StandardControlCapability {
        StandardControlCapability {
            id,
            control_type: V4L2_CTRL_TYPE_INTEGER,
            minimum: 0,
            maximum: 10,
            step: 1,
            default: 5,
            flags: 0,
            menu_values: Vec::new(),
            policy_eligible: false,
        }
    }

    #[test]
    fn invalid_controls_fail_instead_of_becoming_policy_inputs() {
        let mut source = FakeSource::new(vec![*b"MJPG"]);
        let mut invalid = valid_control(V4L2_CTRL_CLASS_USER | 0x900);
        invalid.minimum = 10;
        invalid.maximum = 0;
        source.controls = Ok(vec![invalid]);
        assert!(matches!(
            inventory_from_source(&mut source, StreamRole::Rgb),
            Err(CapabilityError::InvalidControl { .. })
        ));

        let mut source = FakeSource::new(vec![*b"MJPG"]);
        let mut off_lattice = valid_control(V4L2_CTRL_CLASS_USER | 0x901);
        off_lattice.step = 4;
        off_lattice.default = 5;
        source.controls = Ok(vec![off_lattice]);
        assert!(matches!(
            inventory_from_source(&mut source, StreamRole::Rgb),
            Err(CapabilityError::InvalidControl { .. })
        ));

        let mut source = FakeSource::new(vec![*b"MJPG"]);
        let mut overflow = valid_control(V4L2_CTRL_CLASS_USER | 0x902);
        overflow.minimum = i32::MIN;
        overflow.maximum = i32::MAX;
        overflow.step = 2;
        overflow.default = i32::MAX;
        source.controls = Ok(vec![overflow]);
        assert!(matches!(
            inventory_from_source(&mut source, StreamRole::Rgb),
            Err(CapabilityError::InvalidControl { .. })
        ));
    }

    #[test]
    fn controls_retain_only_standard_classes_and_gate_dangerous_flags() {
        let mut source = FakeSource::new(vec![*b"MJPG"]);
        let eligible = valid_control(V4L2_CTRL_CLASS_CAMERA | 0x900);
        let mut disabled = valid_control(V4L2_CTRL_CLASS_IMAGE_SOURCE | 0x901);
        disabled.flags = V4L2_CTRL_FLAG_DISABLED;
        let mut write_only = valid_control(V4L2_CTRL_CLASS_USER | 0x902);
        write_only.flags = V4L2_CTRL_FLAG_WRITE_ONLY;
        let mut execute = valid_control(V4L2_CTRL_CLASS_USER | 0x903);
        execute.flags = V4L2_CTRL_FLAG_EXECUTE_ON_WRITE;
        let mut read_only = valid_control(V4L2_CTRL_CLASS_USER | 0x904);
        read_only.flags = V4L2_CTRL_FLAG_READ_ONLY;
        let vendor = valid_control(0x0800_0001);
        source.controls = Ok(vec![
            eligible, disabled, write_only, execute, read_only, vendor,
        ]);

        let inventory = inventory_from_source(&mut source, StreamRole::Rgb).unwrap();
        assert_eq!(inventory.controls().len(), 5);
        assert!(inventory.controls()[0].policy_eligible());
        assert!(inventory.controls()[1..]
            .iter()
            .all(|control| !control.policy_eligible()));
    }

    #[test]
    fn unsupported_control_types_remain_diagnostic_and_policy_ineligible() {
        let mut source = FakeSource::new(vec![*b"MJPG"]);
        let mut integer64 = valid_control(V4L2_CTRL_CLASS_USER | 0x900);
        integer64.control_type = V4L2_CTRL_TYPE_INTEGER64;
        integer64.minimum = 0;
        integer64.maximum = 0;
        integer64.step = 0;
        integer64.default = 0;
        let mut string = valid_control(V4L2_CTRL_CLASS_USER | 0x901);
        string.control_type = V4L2_CTRL_TYPE_STRING;
        string.minimum = 1;
        string.maximum = 32;
        string.default = 0;
        let mut unknown = valid_control(V4L2_CTRL_CLASS_USER | 0x902);
        unknown.control_type = 0x100;
        source.controls = Ok(vec![integer64, string, unknown]);

        let inventory = inventory_from_source(&mut source, StreamRole::Rgb).unwrap();
        assert_eq!(inventory.controls().len(), 3);
        assert!(inventory
            .controls()
            .iter()
            .all(|control| !control.policy_eligible()));
    }

    #[test]
    fn incomplete_menus_fail_closed() {
        for (id, values) in [
            (V4L2_CTRL_CLASS_USER | 0x900, Vec::new()),
            (
                V4L2_CTRL_CLASS_USER | 0x901,
                vec![
                    MenuValue::Name {
                        index: 0,
                        bytes: [0; 32],
                    },
                    MenuValue::Name {
                        index: 2,
                        bytes: [0; 32],
                    },
                ],
            ),
        ] {
            let mut source = FakeSource::new(vec![*b"MJPG"]);
            let mut menu = valid_control(id);
            menu.control_type = V4L2_CTRL_TYPE_MENU;
            menu.minimum = 0;
            menu.maximum = 2;
            menu.default = 1;
            menu.menu_values = values;
            source.controls = Ok(vec![menu]);

            assert!(matches!(
                inventory_from_source(&mut source, StreamRole::Rgb),
                Err(CapabilityError::InvalidControl { id: actual, .. }) if actual == id
            ));
        }
    }

    #[test]
    fn sparse_menu_with_its_default_is_recorded_exactly() {
        let mut source = FakeSource::new(vec![*b"MJPG"]);
        let mut menu = valid_control(V4L2_CTRL_CLASS_USER | 0x900);
        menu.control_type = V4L2_CTRL_TYPE_MENU;
        menu.minimum = 0;
        menu.maximum = 3;
        menu.default = 1;
        menu.menu_values = vec![
            MenuValue::Name {
                index: 0,
                bytes: *b"auto\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            },
            MenuValue::Name {
                index: 1,
                bytes: *b"manual\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            },
            MenuValue::Name {
                index: 3,
                bytes: *b"night\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            },
        ];
        source.controls = Ok(vec![menu]);

        let inventory = inventory_from_source(&mut source, StreamRole::Rgb).unwrap();
        assert_eq!(inventory.controls()[0].menu_values().len(), 3);
    }

    #[test]
    fn asus_brio_and_nexigo_fixtures_retain_observed_rates_only() {
        let asus_rgb =
            inventory_from_source(&mut asus_fixture(StreamRole::Rgb), StreamRole::Rgb).unwrap();
        let asus_ir =
            inventory_from_source(&mut asus_fixture(StreamRole::Ir), StreamRole::Ir).unwrap();
        assert_eq!(
            tuple_parts(&asus_rgb),
            vec![
                (DecodedPixelFormat::Yuyv, 640, 480, (1, 30)),
                (DecodedPixelFormat::Yuyv, 640, 480, (1, 15)),
            ]
        );
        assert_eq!(
            tuple_parts(&asus_ir),
            vec![(DecodedPixelFormat::Grey8, 640, 400, (1, 15))]
        );

        let brio_rgb =
            inventory_from_source(&mut brio_fixture(StreamRole::Rgb), StreamRole::Rgb).unwrap();
        let brio_ir =
            inventory_from_source(&mut brio_fixture(StreamRole::Ir), StreamRole::Ir).unwrap();
        assert_eq!(
            tuple_parts(&brio_rgb),
            vec![
                (DecodedPixelFormat::Yuyv, 640, 480, (1, 30)),
                (DecodedPixelFormat::Yuyv, 640, 480, (1, 24)),
                (DecodedPixelFormat::Yuyv, 640, 480, (1, 20)),
                (DecodedPixelFormat::Yuyv, 640, 480, (1, 15)),
                (DecodedPixelFormat::Yuyv, 640, 480, (1, 10)),
                (DecodedPixelFormat::Yuyv, 640, 480, (2, 15)),
                (DecodedPixelFormat::Yuyv, 640, 480, (1, 5)),
            ]
        );
        assert_eq!(
            tuple_parts(&brio_ir),
            vec![(DecodedPixelFormat::Grey8, 340, 340, (1, 30))]
        );

        let nexigo_rgb =
            inventory_from_source(&mut nexigo_fixture(StreamRole::Rgb), StreamRole::Rgb).unwrap();
        let nexigo_ir =
            inventory_from_source(&mut nexigo_fixture(StreamRole::Ir), StreamRole::Ir).unwrap();
        assert_eq!(
            tuple_parts(&nexigo_rgb),
            vec![(DecodedPixelFormat::Yuyv, 640, 480, (1, 30))]
        );
        assert_eq!(
            tuple_parts(&nexigo_ir),
            vec![(DecodedPixelFormat::Grey8, 640, 360, (1, 30))]
        );

        assert!(asus_ir
            .tuples()
            .iter()
            .chain(brio_ir.tuples())
            .chain(nexigo_ir.tuples())
            .all(
                |tuple| tuple.interval() == interval(1, 15) || tuple.interval() == interval(1, 30)
            ));
    }
}
