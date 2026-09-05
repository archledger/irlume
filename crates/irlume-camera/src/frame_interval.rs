// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Exact, bounded V4L2 frame-interval capability enumeration.

use std::{cmp::Ordering, fs::File, num::NonZeroU32, os::fd::AsRawFd};

const MAX_DISCRETE_INTERVALS: u32 = 256;

/// A positive, nonzero frame interval represented exactly in reduced form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameInterval {
    numerator: NonZeroU32,
    denominator: NonZeroU32,
}

impl FrameInterval {
    /// Constructs and canonicalizes an interval.
    ///
    /// # Errors
    ///
    /// Returns an error when either component is zero.
    pub fn new(numerator: u32, denominator: u32) -> Result<Self, FrameIntervalError> {
        let numerator = NonZeroU32::new(numerator).ok_or(FrameIntervalError::ZeroNumerator)?;
        let denominator =
            NonZeroU32::new(denominator).ok_or(FrameIntervalError::ZeroDenominator)?;
        let divisor = gcd(numerator.get(), denominator.get());
        Ok(Self {
            numerator: NonZeroU32::new(numerator.get() / divisor)
                .ok_or(FrameIntervalError::ZeroNumerator)?,
            denominator: NonZeroU32::new(denominator.get() / divisor)
                .ok_or(FrameIntervalError::ZeroDenominator)?,
        })
    }

    /// Returns the canonical numerator and denominator.
    #[must_use]
    pub const fn parts(self) -> (u32, u32) {
        (self.numerator.get(), self.denominator.get())
    }
}

impl PartialOrd for FrameInterval {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FrameInterval {
    fn cmp(&self, other: &Self) -> Ordering {
        (u128::from(self.numerator.get()) * u128::from(other.denominator.get()))
            .cmp(&(u128::from(other.numerator.get()) * u128::from(self.denominator.get())))
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

/// Canonical discrete interval capabilities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscreteFrameIntervals {
    values: Vec<FrameInterval>,
}

impl DiscreteFrameIntervals {
    /// Returns the canonical ascending interval list.
    #[must_use]
    pub fn values(&self) -> &[FrameInterval] {
        &self.values
    }
}

/// A continuous exact interval range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContinuousFrameIntervals {
    min: FrameInterval,
    max: FrameInterval,
}

impl ContinuousFrameIntervals {
    /// Returns the inclusive range bounds.
    #[must_use]
    pub const fn bounds(self) -> (FrameInterval, FrameInterval) {
        (self.min, self.max)
    }
}

/// A stepwise exact interval range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepwiseFrameIntervals {
    min: FrameInterval,
    max: FrameInterval,
    step: FrameInterval,
}

impl StepwiseFrameIntervals {
    /// Returns the inclusive bounds and exact lattice step.
    #[must_use]
    pub const fn parts(self) -> (FrameInterval, FrameInterval, FrameInterval) {
        (self.min, self.max, self.step)
    }
}

/// Exact frame-interval capabilities for one format and geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameIntervalDomain {
    /// A nonempty canonical list with no duplicates.
    Discrete(DiscreteFrameIntervals),
    /// Every rational interval in the inclusive range is supported.
    Continuous(ContinuousFrameIntervals),
    /// Intervals on the exact `min + k * step` lattice are supported.
    Stepwise(StepwiseFrameIntervals),
}

impl FrameIntervalDomain {
    /// Constructs a canonical discrete domain.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty list or any duplicate after reduction.
    pub fn discrete(mut values: Vec<FrameInterval>) -> Result<Self, FrameIntervalError> {
        if values.is_empty() {
            return Err(FrameIntervalError::EmptyDiscrete);
        }
        values.sort_unstable();
        if let Some(duplicate) = values.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(FrameIntervalError::DuplicateDiscrete(duplicate[0]));
        }
        Ok(Self::Discrete(DiscreteFrameIntervals { values }))
    }

    /// Constructs a continuous domain.
    ///
    /// # Errors
    ///
    /// Returns an error when `min > max`.
    pub fn continuous(min: FrameInterval, max: FrameInterval) -> Result<Self, FrameIntervalError> {
        if min > max {
            return Err(FrameIntervalError::InvertedRange);
        }
        Ok(Self::Continuous(ContinuousFrameIntervals { min, max }))
    }

    /// Constructs a stepwise domain.
    ///
    /// # Errors
    ///
    /// Returns an error when `min > max`. A zero step is unrepresentable by
    /// [`FrameInterval`].
    pub fn stepwise(
        min: FrameInterval,
        max: FrameInterval,
        step: FrameInterval,
    ) -> Result<Self, FrameIntervalError> {
        if min > max {
            return Err(FrameIntervalError::InvertedRange);
        }
        Ok(Self::Stepwise(StepwiseFrameIntervals { min, max, step }))
    }

    #[cfg(test)]
    fn stepwise_raw(
        min: (u32, u32),
        max: (u32, u32),
        step: (u32, u32),
    ) -> Result<Self, FrameIntervalError> {
        Self::stepwise(
            FrameInterval::new(min.0, min.1)?,
            FrameInterval::new(max.0, max.1)?,
            FrameInterval::new(step.0, step.1)?,
        )
    }

    /// Tests exact membership without floating-point conversion or expansion.
    #[must_use]
    pub fn contains(&self, value: FrameInterval) -> bool {
        match self {
            Self::Discrete(discrete) => discrete.values.binary_search(&value).is_ok(),
            Self::Continuous(continuous) => value >= continuous.min && value <= continuous.max,
            Self::Stepwise(stepwise) => {
                if value < stepwise.min || value > stepwise.max {
                    return false;
                }
                let (value_num, value_den) = value.parts();
                let (min_num, min_den) = stepwise.min.parts();
                let (step_num, step_den) = stepwise.step.parts();
                // The range check above proves this subtraction cannot underflow.
                let delta = u128::from(value_num) * u128::from(min_den)
                    - u128::from(min_num) * u128::from(value_den);
                let dividend = delta * u128::from(step_den);
                let divisor = u128::from(step_num) * u128::from(value_den) * u128::from(min_den);
                dividend % divisor == 0
            }
        }
    }

    /// Returns discrete values, or `None` for range domains.
    #[must_use]
    pub fn discrete_values(&self) -> Option<&[FrameInterval]> {
        match self {
            Self::Discrete(discrete) => Some(discrete.values()),
            Self::Continuous(_) | Self::Stepwise(_) => None,
        }
    }
}

/// Exact V4L2 frame-interval query identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameIntervalQuery {
    fourcc: [u8; 4],
    width: NonZeroU32,
    height: NonZeroU32,
}

impl FrameIntervalQuery {
    /// Constructs a query with nonzero geometry.
    ///
    /// # Errors
    ///
    /// Returns an error when width or height is zero.
    pub fn new(fourcc: [u8; 4], width: u32, height: u32) -> Result<Self, FrameIntervalError> {
        Ok(Self {
            fourcc,
            width: NonZeroU32::new(width).ok_or(FrameIntervalError::ZeroWidth)?,
            height: NonZeroU32::new(height).ok_or(FrameIntervalError::ZeroHeight)?,
        })
    }

    /// Returns the exact fourcc and geometry.
    #[must_use]
    pub const fn parts(self) -> ([u8; 4], u32, u32) {
        (self.fourcc, self.width.get(), self.height.get())
    }

    const fn pixel_format(self) -> u32 {
        u32::from_le_bytes(self.fourcc)
    }
}

/// Fail-closed capability construction or enumeration error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameIntervalError {
    ZeroNumerator,
    ZeroDenominator,
    ZeroWidth,
    ZeroHeight,
    EmptyDiscrete,
    DuplicateDiscrete(FrameInterval),
    InvertedRange,
    UnknownRawType(u32),
    MalformedResponse {
        index: u32,
        reason: &'static str,
    },
    InitialQueryUnsupported,
    Io {
        device: Option<String>,
        query: FrameIntervalQuery,
        index: u32,
        errno: Option<i32>,
    },
    TooMany,
    MixedType,
    ExtraRecord,
    Device {
        device: String,
        message: String,
    },
}

impl FrameIntervalError {
    fn with_device(self, device: &str) -> Self {
        match self {
            Self::Io {
                query,
                index,
                errno,
                ..
            } => Self::Io {
                device: Some(device.to_owned()),
                query,
                index,
                errno,
            },
            other => other,
        }
    }
}

impl std::fmt::Display for FrameIntervalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroNumerator => formatter.write_str("frame interval numerator is zero"),
            Self::ZeroDenominator => formatter.write_str("frame interval denominator is zero"),
            Self::ZeroWidth => formatter.write_str("frame interval query width is zero"),
            Self::ZeroHeight => formatter.write_str("frame interval query height is zero"),
            Self::EmptyDiscrete => formatter.write_str("discrete frame interval domain is empty"),
            Self::DuplicateDiscrete(value) => {
                write!(formatter, "duplicate discrete frame interval {value:?}")
            }
            Self::InvertedRange => formatter.write_str("frame interval range is inverted"),
            Self::UnknownRawType(kind) => {
                write!(formatter, "unknown V4L2 frame interval type {kind}")
            }
            Self::MalformedResponse { index, reason } => {
                write!(
                    formatter,
                    "malformed frame interval response at index {index}: {reason}"
                )
            }
            Self::InitialQueryUnsupported => {
                formatter.write_str("driver rejected frame interval query at index zero")
            }
            Self::Io {
                device,
                query,
                index,
                errno,
            } => write!(
                formatter,
                "{}frame interval query {query:?} failed at index {index} (errno {errno:?})",
                device
                    .as_deref()
                    .map_or(String::new(), |path| format!("{path}: "))
            ),
            Self::TooMany => formatter.write_str("more than 256 discrete frame intervals"),
            Self::MixedType => formatter.write_str("frame interval response changed type"),
            Self::ExtraRecord => {
                formatter.write_str("non-discrete frame interval has extra record")
            }
            Self::Device { device, message } => write!(formatter, "{device}: {message}"),
        }
    }
}

impl std::error::Error for FrameIntervalError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawKind {
    Discrete(FrameInterval),
    Continuous {
        min: FrameInterval,
        max: FrameInterval,
    },
    Stepwise {
        min: FrameInterval,
        max: FrameInterval,
        step: FrameInterval,
    },
    Unknown(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RawRecord {
    index: u32,
    pixel_format: u32,
    width: u32,
    height: u32,
    reserved: [u32; 2],
    kind: RawKind,
}

trait RecordSource {
    fn record(
        &mut self,
        query: FrameIntervalQuery,
        index: u32,
    ) -> Result<RawRecord, std::io::Error>;
}

fn validate_record(
    query: FrameIntervalQuery,
    expected_index: u32,
    record: RawRecord,
) -> Result<RawKind, FrameIntervalError> {
    let reason = if record.index != expected_index {
        Some("index echo mismatch")
    } else if record.pixel_format != query.pixel_format() {
        Some("fourcc echo mismatch")
    } else if record.width != query.width.get() {
        Some("width echo mismatch")
    } else if record.height != query.height.get() {
        Some("height echo mismatch")
    } else if record.reserved != [0, 0] {
        Some("reserved fields are nonzero")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(FrameIntervalError::MalformedResponse {
            index: expected_index,
            reason,
        });
    }
    if let RawKind::Unknown(kind) = record.kind {
        return Err(FrameIntervalError::UnknownRawType(kind));
    }
    Ok(record.kind)
}

fn malformed_rational_reason(error: &std::io::Error) -> Option<&'static str> {
    match error.get_ref()?.downcast_ref::<FrameIntervalError>()? {
        FrameIntervalError::ZeroNumerator => Some("zero numerator in driver response"),
        FrameIntervalError::ZeroDenominator => Some("zero denominator in driver response"),
        _ => None,
    }
}

fn read_record<S: RecordSource>(
    source: &mut S,
    query: FrameIntervalQuery,
    index: u32,
) -> Result<Option<RawKind>, FrameIntervalError> {
    match source.record(query, index) {
        Ok(record) => validate_record(query, index, record).map(Some),
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => Ok(None),
        Err(error) => {
            if let Some(reason) = malformed_rational_reason(&error) {
                return Err(FrameIntervalError::MalformedResponse { index, reason });
            }
            Err(FrameIntervalError::Io {
                device: None,
                query,
                index,
                errno: error.raw_os_error(),
            })
        }
    }
}

fn enumerate_via<S: RecordSource>(
    query: FrameIntervalQuery,
    source: &mut S,
) -> Result<FrameIntervalDomain, FrameIntervalError> {
    let first =
        read_record(source, query, 0)?.ok_or(FrameIntervalError::InitialQueryUnsupported)?;
    match first {
        RawKind::Discrete(value) => {
            let mut values = Vec::with_capacity(MAX_DISCRETE_INTERVALS as usize);
            values.push(value);
            for index in 1..MAX_DISCRETE_INTERVALS {
                match read_record(source, query, index)? {
                    Some(RawKind::Discrete(value)) => values.push(value),
                    Some(RawKind::Continuous { .. } | RawKind::Stepwise { .. }) => {
                        return Err(FrameIntervalError::MixedType);
                    }
                    Some(RawKind::Unknown(_)) => unreachable!("unknown types fail validation"),
                    None => return FrameIntervalDomain::discrete(values),
                }
            }
            match read_record(source, query, MAX_DISCRETE_INTERVALS)? {
                None => FrameIntervalDomain::discrete(values),
                Some(_) => Err(FrameIntervalError::TooMany),
            }
        }
        RawKind::Continuous { min, max } => {
            if read_record(source, query, 1)?.is_some() {
                return Err(FrameIntervalError::ExtraRecord);
            }
            FrameIntervalDomain::continuous(min, max)
        }
        RawKind::Stepwise { min, max, step } => {
            if read_record(source, query, 1)?.is_some() {
                return Err(FrameIntervalError::ExtraRecord);
            }
            FrameIntervalDomain::stepwise(min, max, step)
        }
        RawKind::Unknown(_) => unreachable!("unknown types fail validation"),
    }
}

struct DirectSource {
    file: File,
}

struct BorrowedFdSource {
    fd: std::os::fd::RawFd,
}

impl RecordSource for BorrowedFdSource {
    fn record(
        &mut self,
        query: FrameIntervalQuery,
        index: u32,
    ) -> Result<RawRecord, std::io::Error> {
        direct_record(self.fd, query, index)
    }
}

impl RecordSource for DirectSource {
    fn record(
        &mut self,
        query: FrameIntervalQuery,
        index: u32,
    ) -> Result<RawRecord, std::io::Error> {
        direct_record(self.file.as_raw_fd(), query, index)
    }
}

/// The sole unsafe V4L2 boundary for this module. It zeroes the ABI struct,
/// writes only documented input fields, performs only ENUM_FRAMEINTERVALS,
/// checks the returned raw type before reading its authorized union arm, and
/// immediately copies every returned field into safe owned values.
fn direct_record(
    fd: std::os::fd::RawFd,
    query: FrameIntervalQuery,
    index: u32,
) -> Result<RawRecord, std::io::Error> {
    #[expect(
        clippy::undocumented_unsafe_blocks,
        reason = "documented function choke point"
    )]
    let mut raw: v4l::v4l_sys::v4l2_frmivalenum = unsafe { std::mem::zeroed() };
    raw.index = index;
    raw.pixel_format = query.pixel_format();
    raw.width = query.width.get();
    raw.height = query.height.get();

    #[expect(
        clippy::undocumented_unsafe_blocks,
        reason = "documented function choke point"
    )]
    let result = unsafe {
        libc::ioctl(
            fd,
            v4l::v4l2::vidioc::VIDIOC_ENUM_FRAMEINTERVALS,
            &mut raw as *mut _ as *mut libc::c_void,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let kind = match raw.type_ {
        v4l::v4l_sys::v4l2_frmivaltypes_V4L2_FRMIVAL_TYPE_DISCRETE => {
            #[expect(
                clippy::undocumented_unsafe_blocks,
                reason = "documented function choke point"
            )]
            let value = unsafe { raw.__bindgen_anon_1.discrete };
            RawKind::Discrete(
                FrameInterval::new(value.numerator, value.denominator)
                    .map_err(std::io::Error::other)?,
            )
        }
        v4l::v4l_sys::v4l2_frmivaltypes_V4L2_FRMIVAL_TYPE_CONTINUOUS => {
            #[expect(
                clippy::undocumented_unsafe_blocks,
                reason = "documented function choke point"
            )]
            let value = unsafe { raw.__bindgen_anon_1.stepwise };
            RawKind::Continuous {
                min: FrameInterval::new(value.min.numerator, value.min.denominator)
                    .map_err(std::io::Error::other)?,
                max: FrameInterval::new(value.max.numerator, value.max.denominator)
                    .map_err(std::io::Error::other)?,
            }
        }
        v4l::v4l_sys::v4l2_frmivaltypes_V4L2_FRMIVAL_TYPE_STEPWISE => {
            #[expect(
                clippy::undocumented_unsafe_blocks,
                reason = "documented function choke point"
            )]
            let value = unsafe { raw.__bindgen_anon_1.stepwise };
            RawKind::Stepwise {
                min: FrameInterval::new(value.min.numerator, value.min.denominator)
                    .map_err(std::io::Error::other)?,
                max: FrameInterval::new(value.max.numerator, value.max.denominator)
                    .map_err(std::io::Error::other)?,
                step: FrameInterval::new(value.step.numerator, value.step.denominator)
                    .map_err(std::io::Error::other)?,
            }
        }
        unknown => RawKind::Unknown(unknown),
    };

    Ok(RawRecord {
        index: raw.index,
        pixel_format: raw.pixel_format,
        width: raw.width,
        height: raw.height,
        reserved: raw.reserved,
        kind,
    })
}

/// Enumerates exact frame intervals on a caller-owned, already authorized fd.
///
/// This crate-private entrypoint performs no open, lease acquisition, endpoint
/// lookup, or device-state mutation. The caller owns those lifecycle checks.
pub(crate) fn frame_interval_capabilities_for_fd(
    device: &str,
    fd: std::os::fd::RawFd,
    fourcc: [u8; 4],
    width: u32,
    height: u32,
) -> Result<FrameIntervalDomain, FrameIntervalError> {
    let query = FrameIntervalQuery::new(fourcc, width, height)?;
    let mut source = BorrowedFdSource { fd };
    enumerate_via(query, &mut source).map_err(|error| error.with_device(device))
}

/// Enumerates exact frame-interval capabilities without changing device state.
///
/// The endpoint is pinned and covered by a Diagnostics operation permit before
/// the node is opened read-only. Coverage is revalidated after the complete
/// bounded enumeration, and no partial domain is ever returned.
///
/// # Errors
///
/// Returns a fail-closed error for invalid geometry, pin/permit/open failures,
/// malformed driver responses, unexpected errno, or protocol/capacity breach.
pub fn frame_interval_capabilities(
    device: &str,
    fourcc: [u8; 4],
    width: u32,
    height: u32,
) -> Result<FrameIntervalDomain, FrameIntervalError> {
    entrypoint_via(device, fourcc, width, height, &mut DeviceEntrypoint)
}

// One lifecycle for the real endpoint and deterministic tests. The owned permit
// stays alive until enumeration and the final coverage check have completed.
trait EntrypointHooks {
    type Permit;
    type Source: RecordSource;

    fn verify(&mut self, device: &str) -> Result<(), FrameIntervalError>;
    fn permit(&mut self, device: &str) -> Result<Self::Permit, FrameIntervalError>;
    fn require_endpoint(
        &mut self,
        permit: &Self::Permit,
        device: &str,
    ) -> Result<(), FrameIntervalError>;
    fn open(&mut self, device: &str) -> Result<Self::Source, FrameIntervalError>;
}

struct DeviceEntrypoint;

impl EntrypointHooks for DeviceEntrypoint {
    type Permit = crate::lease::CameraLease;
    type Source = DirectSource;

    fn verify(&mut self, device: &str) -> Result<(), FrameIntervalError> {
        crate::verify_pinned(device).map_err(|error| FrameIntervalError::Device {
            device: device.to_owned(),
            message: error.to_string(),
        })
    }

    fn permit(&mut self, device: &str) -> Result<Self::Permit, FrameIntervalError> {
        crate::lease::permit_for_endpoint(
            device,
            crate::lease::CameraOperationKind::Diagnostics,
            std::time::Duration::from_secs(2),
        )
        .map_err(|error| FrameIntervalError::Device {
            device: device.to_owned(),
            message: error.to_string(),
        })
    }

    fn require_endpoint(
        &mut self,
        permit: &Self::Permit,
        device: &str,
    ) -> Result<(), FrameIntervalError> {
        permit
            .require_endpoint(device)
            .map_err(|error| FrameIntervalError::Device {
                device: device.to_owned(),
                message: error.to_string(),
            })
    }

    fn open(&mut self, device: &str) -> Result<Self::Source, FrameIntervalError> {
        std::fs::OpenOptions::new()
            .read(true)
            .open(device)
            .map(|file| DirectSource { file })
            .map_err(|error| FrameIntervalError::Device {
                device: device.to_owned(),
                message: error.to_string(),
            })
    }
}

fn entrypoint_via<H: EntrypointHooks>(
    device: &str,
    fourcc: [u8; 4],
    width: u32,
    height: u32,
    hooks: &mut H,
) -> Result<FrameIntervalDomain, FrameIntervalError> {
    let query = FrameIntervalQuery::new(fourcc, width, height)?;
    hooks.verify(device)?;
    let permit = hooks.permit(device)?;
    hooks.require_endpoint(&permit, device)?;
    let mut source = hooks.open(device)?;
    let domain = enumerate_via(query, &mut source).map_err(|error| error.with_device(device))?;
    hooks.require_endpoint(&permit, device)?;
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    fn interval(numerator: u32, denominator: u32) -> FrameInterval {
        FrameInterval::new(numerator, denominator).unwrap()
    }

    fn query() -> FrameIntervalQuery {
        FrameIntervalQuery::new(*b"YUYV", 640, 480).unwrap()
    }

    fn discrete(index: u32, value: FrameInterval) -> RawRecord {
        RawRecord {
            index,
            pixel_format: u32::from_le_bytes(*b"YUYV"),
            width: 640,
            height: 480,
            reserved: [0, 0],
            kind: RawKind::Discrete(value),
        }
    }

    #[derive(Default)]
    struct FixtureSource {
        answers: VecDeque<Result<RawRecord, std::io::Error>>,
    }

    impl FixtureSource {
        fn new(answers: impl IntoIterator<Item = Result<RawRecord, std::io::Error>>) -> Self {
            Self {
                answers: answers.into_iter().collect(),
            }
        }
    }

    impl RecordSource for FixtureSource {
        fn record(
            &mut self,
            _query: FrameIntervalQuery,
            _index: u32,
        ) -> Result<RawRecord, std::io::Error> {
            self.answers
                .pop_front()
                .expect("fixture must cover every bounded query")
        }
    }

    fn errno(code: i32) -> std::io::Error {
        std::io::Error::from_raw_os_error(code)
    }

    #[test]
    fn same_fd_entrypoint_borrows_descriptor_and_retains_device_context() {
        let file = File::open("/dev/null").expect("test fd");
        let error = frame_interval_capabilities_for_fd(
            "/dev/fake-owned-by-caller",
            file.as_raw_fd(),
            *b"YUYV",
            640,
            480,
        )
        .unwrap_err();
        assert!(error.to_string().contains("/dev/fake-owned-by-caller"));
        assert!(
            file.metadata().is_ok(),
            "same-fd enumeration closed caller fd"
        );
    }

    #[test]
    fn reduced_fractions_are_equal() {
        assert_eq!(interval(1, 2), interval(2, 4));
        assert_eq!(interval(2, 4).parts(), (1, 2));
    }

    #[test]
    fn exact_ordering_near_u32_max() {
        assert!(interval(u32::MAX - 1, u32::MAX) < interval(u32::MAX, u32::MAX - 1));
    }

    #[test]
    fn discrete_values_are_canonical_sorted() {
        let domain =
            FrameIntervalDomain::discrete(vec![interval(1, 30), interval(1, 15), interval(1, 60)])
                .unwrap();
        assert_eq!(
            domain.discrete_values().unwrap(),
            &[interval(1, 60), interval(1, 30), interval(1, 15)]
        );
    }

    #[test]
    fn discrete_membership_is_exact() {
        let domain = FrameIntervalDomain::discrete(vec![interval(1, 30), interval(1, 15)]).unwrap();
        assert!(domain.contains(interval(1, 30)));
        assert!(!domain.contains(interval(1, 20)));
    }

    #[test]
    fn discrete_rejects_duplicates() {
        assert_eq!(
            FrameIntervalDomain::discrete(vec![interval(1, 30), interval(2, 60)]),
            Err(FrameIntervalError::DuplicateDiscrete(interval(1, 30)))
        );
    }

    #[test]
    fn empty_and_zero_rationals_are_rejected() {
        assert_eq!(
            FrameIntervalDomain::discrete(Vec::new()),
            Err(FrameIntervalError::EmptyDiscrete)
        );
        assert_eq!(
            FrameInterval::new(0, 1),
            Err(FrameIntervalError::ZeroNumerator)
        );
        assert_eq!(
            FrameInterval::new(1, 0),
            Err(FrameIntervalError::ZeroDenominator)
        );
    }

    #[test]
    fn stepwise_membership_uses_exact_lattice() {
        let domain =
            FrameIntervalDomain::stepwise(interval(1, 60), interval(1, 30), interval(1, 180))
                .unwrap();
        assert!(domain.contains(interval(1, 45)));
        assert!(!domain.contains(interval(1, 50)));
    }

    #[test]
    fn stepwise_handles_fractional_denominators() {
        let domain =
            FrameIntervalDomain::stepwise(interval(1, 30), interval(1, 10), interval(1, 60))
                .unwrap();
        assert!(domain.contains(interval(1, 20)));
    }

    #[test]
    fn stepwise_large_denominators_do_not_overflow() {
        let min = interval(1, u32::MAX);
        let domain = FrameIntervalDomain::stepwise(min, interval(3, u32::MAX), min).unwrap();
        assert!(domain.contains(min));
        assert!(domain.contains(interval(2, u32::MAX)));
    }

    #[test]
    fn stepwise_rejects_inverted_range() {
        assert_eq!(
            FrameIntervalDomain::stepwise(interval(1, 30), interval(1, 60), interval(1, 60)),
            Err(FrameIntervalError::InvertedRange)
        );
    }

    #[test]
    fn stepwise_rejects_zero_step() {
        assert_eq!(
            FrameIntervalDomain::stepwise_raw((1, 60), (1, 30), (0, 1)),
            Err(FrameIntervalError::ZeroNumerator)
        );
    }

    #[test]
    fn continuous_membership_is_range_only() {
        let domain = FrameIntervalDomain::continuous(interval(1, 60), interval(1, 30)).unwrap();
        assert!(domain.contains(interval(1, 50)));
        assert!(!domain.contains(interval(1, 15)));
    }

    #[test]
    fn raw_continuous_type_is_preserved() {
        let raw = RawRecord {
            index: 0,
            pixel_format: u32::from_le_bytes(*b"YUYV"),
            width: 640,
            height: 480,
            reserved: [0, 0],
            kind: RawKind::Continuous {
                min: interval(1, 60),
                max: interval(1, 30),
            },
        };
        let mut source = FixtureSource::new([Ok(raw), Err(errno(libc::EINVAL))]);
        assert!(matches!(
            enumerate_via(query(), &mut source).unwrap(),
            FrameIntervalDomain::Continuous(_)
        ));
    }

    #[test]
    fn unknown_raw_type_fails_closed() {
        let raw = RawRecord {
            index: 0,
            pixel_format: u32::from_le_bytes(*b"YUYV"),
            width: 640,
            height: 480,
            reserved: [0, 0],
            kind: RawKind::Unknown(4),
        };
        let mut source = FixtureSource::new([Ok(raw)]);
        assert_eq!(
            enumerate_via(query(), &mut source),
            Err(FrameIntervalError::UnknownRawType(4))
        );
    }

    #[test]
    fn echoed_query_index_and_reserved_are_validated() {
        for malformed in [
            RawRecord {
                pixel_format: u32::from_le_bytes(*b"MJPG"),
                ..discrete(0, interval(1, 30))
            },
            RawRecord {
                width: 800,
                ..discrete(0, interval(1, 30))
            },
            RawRecord {
                height: 600,
                ..discrete(0, interval(1, 30))
            },
            RawRecord {
                index: 1,
                ..discrete(0, interval(1, 30))
            },
            RawRecord {
                reserved: [1, 0],
                ..discrete(0, interval(1, 30))
            },
        ] {
            let mut source = FixtureSource::new([Ok(malformed)]);
            assert!(matches!(
                enumerate_via(query(), &mut source),
                Err(FrameIntervalError::MalformedResponse { .. })
            ));
        }
    }

    #[test]
    fn malformed_rational_reason_survives_the_record_boundary() {
        for (cause, reason) in [
            (
                FrameIntervalError::ZeroNumerator,
                "zero numerator in driver response",
            ),
            (
                FrameIntervalError::ZeroDenominator,
                "zero denominator in driver response",
            ),
        ] {
            let mut source = FixtureSource::new([Err(std::io::Error::other(cause))]);
            assert_eq!(
                enumerate_via(query(), &mut source),
                Err(FrameIntervalError::MalformedResponse { index: 0, reason })
            );
        }
    }

    #[test]
    fn only_einval_terminates_discrete_enumeration() {
        let mut initial = FixtureSource::new([Err(errno(libc::EINVAL))]);
        assert_eq!(
            enumerate_via(query(), &mut initial),
            Err(FrameIntervalError::InitialQueryUnsupported)
        );

        let mut complete = FixtureSource::new(
            (0..5)
                .map(|index| Ok(discrete(index, interval(1, index + 1))))
                .chain([Err(errno(libc::EINVAL))]),
        );
        assert_eq!(
            enumerate_via(query(), &mut complete)
                .unwrap()
                .discrete_values()
                .unwrap()
                .len(),
            5
        );

        let mut failed = FixtureSource::new(
            (0..5)
                .map(|index| Ok(discrete(index, interval(1, index + 1))))
                .chain([Err(errno(libc::ENODEV))]),
        );
        assert!(matches!(
            enumerate_via(query(), &mut failed),
            Err(FrameIntervalError::Io { index: 5, .. })
        ));
    }

    #[test]
    fn protocol_is_bounded_and_type_stable() {
        let records = (0..256).map(|index| Ok(discrete(index, interval(index + 1, 257))));
        let mut exact = FixtureSource::new(records.clone().chain([Err(errno(libc::EINVAL))]));
        assert_eq!(
            enumerate_via(query(), &mut exact)
                .unwrap()
                .discrete_values()
                .unwrap()
                .len(),
            256
        );

        let mut overflow =
            FixtureSource::new(records.clone().chain([Ok(discrete(256, interval(1, 1)))]));
        assert_eq!(
            enumerate_via(query(), &mut overflow),
            Err(FrameIntervalError::TooMany)
        );

        let changed = RawRecord {
            index: 3,
            kind: RawKind::Continuous {
                min: interval(1, 60),
                max: interval(1, 30),
            },
            ..discrete(3, interval(1, 30))
        };
        let mut mixed = FixtureSource::new(
            (0..3)
                .map(|index| Ok(discrete(index, interval(1, index + 1))))
                .chain([Ok(changed)]),
        );
        assert_eq!(
            enumerate_via(query(), &mut mixed),
            Err(FrameIntervalError::MixedType)
        );

        let continuous = RawRecord {
            kind: RawKind::Continuous {
                min: interval(1, 60),
                max: interval(1, 30),
            },
            ..discrete(0, interval(1, 30))
        };
        let mut extra = FixtureSource::new([Ok(continuous), Ok(discrete(1, interval(1, 30)))]);
        assert_eq!(
            enumerate_via(query(), &mut extra),
            Err(FrameIntervalError::ExtraRecord)
        );
    }

    struct TestPermit(Rc<RefCell<Vec<&'static str>>>);

    impl Drop for TestPermit {
        fn drop(&mut self) {
            self.0.borrow_mut().push("release");
        }
    }

    struct LoggedSource {
        source: FixtureSource,
        log: Rc<RefCell<Vec<&'static str>>>,
    }

    impl RecordSource for LoggedSource {
        fn record(
            &mut self,
            query: FrameIntervalQuery,
            index: u32,
        ) -> Result<RawRecord, std::io::Error> {
            self.log.borrow_mut().push("record");
            self.source.record(query, index)
        }
    }

    impl Drop for LoggedSource {
        fn drop(&mut self) {
            self.log.borrow_mut().push("close");
        }
    }

    struct Hooks {
        log: Rc<RefCell<Vec<&'static str>>>,
        source: Option<FixtureSource>,
        coverage: VecDeque<Result<(), FrameIntervalError>>,
        fail_at: Option<&'static str>,
    }

    impl Hooks {
        fn new(last_errno: i32) -> Self {
            Self {
                log: Rc::new(RefCell::new(Vec::new())),
                source: Some(FixtureSource::new([
                    Ok(discrete(0, interval(1, 30))),
                    Err(errno(last_errno)),
                ])),
                coverage: [Ok(()), Ok(())].into(),
                fail_at: None,
            }
        }

        fn step(&mut self, device: &str, name: &'static str) -> Result<(), FrameIntervalError> {
            assert_eq!(device, "/dev/video-test");
            self.log.borrow_mut().push(name);
            if self.fail_at == Some(name) {
                Err(FrameIntervalError::Device {
                    device: device.into(),
                    message: name.into(),
                })
            } else {
                Ok(())
            }
        }
    }

    impl EntrypointHooks for Hooks {
        type Permit = TestPermit;
        type Source = LoggedSource;

        fn verify(&mut self, device: &str) -> Result<(), FrameIntervalError> {
            self.step(device, "verify")
        }

        fn permit(&mut self, device: &str) -> Result<Self::Permit, FrameIntervalError> {
            self.step(device, "permit")?;
            Ok(TestPermit(Rc::clone(&self.log)))
        }

        fn require_endpoint(
            &mut self,
            _permit: &Self::Permit,
            device: &str,
        ) -> Result<(), FrameIntervalError> {
            self.step(device, "coverage")?;
            self.coverage
                .pop_front()
                .expect("fixture must cover every endpoint check")
        }

        fn open(&mut self, device: &str) -> Result<Self::Source, FrameIntervalError> {
            self.step(device, "open")?;
            Ok(LoggedSource {
                source: self.source.take().unwrap(),
                log: Rc::clone(&self.log),
            })
        }
    }

    #[test]
    fn entrypoint_orders_guards_and_never_returns_partial_capabilities() {
        let mut hooks = Hooks::new(libc::EINVAL);
        let domain = entrypoint_via("/dev/video-test", *b"YUYV", 640, 480, &mut hooks).unwrap();
        assert_eq!(domain.discrete_values().unwrap(), &[interval(1, 30)]);
        assert_eq!(
            &*hooks.log.borrow(),
            &[
                "verify", "permit", "coverage", "open", "record", "record", "coverage", "close",
                "release"
            ]
        );

        let mut fail_hooks = Hooks::new(libc::ENODEV);
        assert!(matches!(
            entrypoint_via("/dev/video-test", *b"YUYV", 640, 480, &mut fail_hooks),
            Err(FrameIntervalError::Io { device: Some(device), index: 1, errno: Some(libc::ENODEV), .. })
                if device == "/dev/video-test"
        ));
        assert_eq!(
            &*fail_hooks.log.borrow(),
            &["verify", "permit", "coverage", "open", "record", "record", "close", "release"]
        );

        let mut post_hooks = Hooks::new(libc::EINVAL);
        let stale = FrameIntervalError::Device {
            device: "/dev/video-test".into(),
            message: "stale endpoint".into(),
        };
        post_hooks.coverage = [Ok(()), Err(stale.clone())].into();
        assert_eq!(
            entrypoint_via("/dev/video-test", *b"YUYV", 640, 480, &mut post_hooks),
            Err(stale)
        );
        assert_eq!(
            &*post_hooks.log.borrow(),
            &[
                "verify", "permit", "coverage", "open", "record", "record", "coverage", "close",
                "release"
            ]
        );
    }

    #[test]
    fn entrypoint_invalid_geometry_has_no_device_side_effects() {
        for (width, height, expected) in [
            (0, 480, FrameIntervalError::ZeroWidth),
            (640, 0, FrameIntervalError::ZeroHeight),
        ] {
            let mut hooks = Hooks::new(libc::EINVAL);
            assert_eq!(
                entrypoint_via("/dev/video-test", *b"YUYV", width, height, &mut hooks),
                Err(expected.clone())
            );
            assert!(hooks.log.borrow().is_empty());
            assert_eq!(
                frame_interval_capabilities("/dev/video-test", *b"YUYV", width, height),
                Err(expected)
            );
        }
    }

    #[test]
    fn entrypoint_stops_before_device_access_on_guard_or_open_failure() {
        for (stage, expected) in [
            ("verify", vec!["verify"]),
            ("permit", vec!["verify", "permit"]),
            ("coverage", vec!["verify", "permit", "coverage", "release"]),
            (
                "open",
                vec!["verify", "permit", "coverage", "open", "release"],
            ),
        ] {
            let mut hooks = Hooks::new(libc::EINVAL);
            hooks.fail_at = Some(stage);
            assert_eq!(
                entrypoint_via("/dev/video-test", *b"YUYV", 640, 480, &mut hooks),
                Err(FrameIntervalError::Device {
                    device: "/dev/video-test".into(),
                    message: stage.into(),
                })
            );
            assert_eq!(&*hooks.log.borrow(), &expected);
        }
    }
}
