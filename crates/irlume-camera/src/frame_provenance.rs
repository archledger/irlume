// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Strict runtime evidence bound to one immutable camera lease reference.

use crate::contracts::{CameraGeneration, CameraInstanceId, IlluminationProvenance, StreamRole};
use crate::CaptureWindow;

/// Clock domain reported in the known V4L2 timestamp-type bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampClock {
    Unknown,
    Monotonic,
    Copy,
}

/// Capture event represented by the V4L2 timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampSource {
    EndOfFrame,
    StartOfExposure,
}

/// Derived continuity facts for one trusted V4L2 timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimestampObservation {
    micros: i64,
    delta_micros: Option<u64>,
    clock: TimestampClock,
    source: TimestampSource,
    discontinuity: bool,
    stream_epoch: u64,
}

impl TimestampObservation {
    #[must_use]
    pub const fn micros(&self) -> i64 {
        self.micros
    }
    #[must_use]
    pub const fn delta_micros(&self) -> Option<u64> {
        self.delta_micros
    }
    #[must_use]
    pub const fn clock(&self) -> TimestampClock {
        self.clock
    }
    #[must_use]
    pub const fn source(&self) -> TimestampSource {
        self.source
    }
    #[must_use]
    pub const fn discontinuity(&self) -> bool {
        self.discontinuity
    }
    #[must_use]
    pub const fn stream_epoch(&self) -> u64 {
        self.stream_epoch
    }
}

/// Why trusted timestamp continuity cannot advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimestampTrackerError {
    /// The first timestamp did not name the monotonic clock.
    UntrustedClock(TimestampClock),
    /// Zero cannot identify a valid frame instant.
    ZeroTimestamp,
    /// Negative keys are outside the normalized dequeue domain.
    NegativeTimestamp(i64),
    /// The timestamp clock changed inside a live stream epoch.
    ClockChanged {
        expected: TimestampClock,
        actual: TimestampClock,
    },
    /// The driver-selected timestamp event changed inside a live stream epoch.
    SourceChanged {
        expected: TimestampSource,
        actual: TimestampSource,
    },
    /// The timestamp repeated or moved backward inside an epoch.
    NonIncreasing { previous: i64, current: i64 },
    /// The epoch counter cannot advance without wrapping.
    StreamEpochOverflow,
    /// This epoch saw invalid evidence and requires explicit recovery.
    EpochFailed,
    /// Checked arithmetic previously exhausted and permanently poisoned the tracker.
    TrackerFailed,
}

impl std::fmt::Display for TimestampTrackerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UntrustedClock(clock) => write!(f, "untrusted timestamp clock {clock:?}"),
            Self::ZeroTimestamp => f.write_str("zero timestamp cannot identify a frame instant"),
            Self::NegativeTimestamp(value) => write!(f, "negative timestamp {value}us"),
            Self::ClockChanged { expected, actual } => {
                write!(f, "timestamp clock changed from {expected:?} to {actual:?}")
            }
            Self::SourceChanged { expected, actual } => {
                write!(
                    f,
                    "timestamp source changed from {expected:?} to {actual:?}"
                )
            }
            Self::NonIncreasing { previous, current } => write!(
                f,
                "timestamp did not increase: previous {previous}us, current {current}us"
            ),
            Self::StreamEpochOverflow => f.write_str("timestamp stream epoch overflow"),
            Self::EpochFailed => f.write_str("timestamp epoch is failed; recovery is required"),
            Self::TrackerFailed => f.write_str("timestamp tracker is permanently failed"),
        }
    }
}

impl std::error::Error for TimestampTrackerError {}

/// Timestamp continuity state for one logical capture stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TimestampTracker {
    previous: Option<i64>,
    domain: Option<(TimestampClock, TimestampSource)>,
    stream_epoch: u64,
    pending_discontinuity: bool,
    epoch_failed: bool,
    failed: bool,
}

impl TimestampTracker {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            previous: None,
            domain: None,
            stream_epoch: 0,
            pending_discontinuity: false,
            epoch_failed: false,
            failed: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn force_stream_epoch_overflow_on_recovery(&mut self) {
        self.stream_epoch = u64::MAX;
    }

    #[cfg(test)]
    pub(crate) const fn stream_epoch_for_test(&self) -> u64 {
        self.stream_epoch
    }

    #[cfg(test)]
    pub(crate) const fn failed_for_test(&self) -> bool {
        self.failed
    }

    #[cfg(test)]
    pub(crate) const fn previous_for_test(&self) -> Option<i64> {
        self.previous
    }

    #[cfg(test)]
    pub(crate) const fn continuity_state_for_test(
        &self,
    ) -> (
        Option<i64>,
        Option<(TimestampClock, TimestampSource)>,
        u64,
        bool,
    ) {
        (
            self.previous,
            self.domain,
            self.stream_epoch,
            self.pending_discontinuity,
        )
    }

    #[cfg(test)]
    pub(crate) const fn epoch_failed_for_test(&self) -> bool {
        self.epoch_failed
    }

    pub(crate) fn fail_current_epoch(&mut self) {
        if !self.failed {
            self.epoch_failed = true;
        }
    }

    pub(crate) fn observe_discarded(
        &mut self,
        micros: i64,
        clock: TimestampClock,
        source: TimestampSource,
    ) -> Result<TimestampObservation, TimestampTrackerError> {
        let observation = self.observe(micros, clock, source)?;
        if observation.discontinuity() {
            self.pending_discontinuity = true;
        }
        Ok(observation)
    }

    /// Starts a recovered stream epoch and resets its timestamp domain.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampTrackerError::StreamEpochOverflow`] when the epoch
    /// counter is exhausted, permanently poisoning the tracker, or
    /// [`TimestampTrackerError::TrackerFailed`] when it was already poisoned.
    pub fn begin_new_epoch(&mut self) -> Result<(), TimestampTrackerError> {
        if self.failed {
            return Err(TimestampTrackerError::TrackerFailed);
        }
        let Some(next_epoch) = self.stream_epoch.checked_add(1) else {
            self.failed = true;
            return Err(TimestampTrackerError::StreamEpochOverflow);
        };
        self.stream_epoch = next_epoch;
        self.previous = None;
        self.domain = None;
        self.pending_discontinuity = true;
        self.epoch_failed = false;
        Ok(())
    }

    /// Validates and records one timestamp in the current stream epoch.
    ///
    /// # Errors
    ///
    /// Returns a [`TimestampTrackerError`] for an untrusted or changed domain,
    /// a non-positive or non-increasing timestamp, or a previously failed
    /// timestamp epoch. A continuity error keeps the epoch failed until
    /// [`Self::begin_new_epoch`] succeeds.
    pub fn observe(
        &mut self,
        micros: i64,
        clock: TimestampClock,
        source: TimestampSource,
    ) -> Result<TimestampObservation, TimestampTrackerError> {
        if self.failed {
            return Err(TimestampTrackerError::TrackerFailed);
        }
        if self.epoch_failed {
            return Err(TimestampTrackerError::EpochFailed);
        }
        if let Some((expected_clock, expected_source)) = self.domain {
            if clock != expected_clock {
                self.epoch_failed = true;
                return Err(TimestampTrackerError::ClockChanged {
                    expected: expected_clock,
                    actual: clock,
                });
            }
            if source != expected_source {
                self.epoch_failed = true;
                return Err(TimestampTrackerError::SourceChanged {
                    expected: expected_source,
                    actual: source,
                });
            }
        }
        if clock != TimestampClock::Monotonic {
            self.epoch_failed = true;
            return Err(TimestampTrackerError::UntrustedClock(clock));
        }
        if micros < 0 {
            self.epoch_failed = true;
            return Err(TimestampTrackerError::NegativeTimestamp(micros));
        }
        if micros == 0 {
            self.epoch_failed = true;
            return Err(TimestampTrackerError::ZeroTimestamp);
        }
        if let Some(previous) = self.previous {
            if micros <= previous {
                self.epoch_failed = true;
                return Err(TimestampTrackerError::NonIncreasing {
                    previous,
                    current: micros,
                });
            }
        }
        let delta_micros = self
            .previous
            .and_then(|previous| micros.checked_sub(previous))
            .and_then(|delta| u64::try_from(delta).ok());
        self.previous = Some(micros);
        self.domain = Some((clock, source));
        let discontinuity = self.pending_discontinuity;
        self.pending_discontinuity = false;
        Ok(TimestampObservation {
            micros,
            delta_micros,
            clock,
            source,
            discontinuity,
            stream_epoch: self.stream_epoch,
        })
    }
}

/// Why sequence continuity can no longer be represented safely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SequenceTrackerError {
    DropCounterOverflow,
    StreamEpochOverflow,
    TrackerFailed,
}

impl std::fmt::Display for SequenceTrackerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DropCounterOverflow => f.write_str("V4L2 sequence drop counter overflowed"),
            Self::StreamEpochOverflow => f.write_str("V4L2 sequence stream epoch overflowed"),
            Self::TrackerFailed => f.write_str("V4L2 sequence tracker is permanently failed"),
        }
    }
}

impl std::error::Error for SequenceTrackerError {}

/// Derived continuity facts for one dequeued V4L2 sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceObservation {
    raw: u32,
    advance: Option<u32>,
    gap: u32,
    cumulative_drops: u64,
    discontinuity: bool,
    stream_epoch: u64,
}

impl SequenceObservation {
    #[must_use]
    pub const fn raw(&self) -> u32 {
        self.raw
    }

    #[must_use]
    pub const fn advance(&self) -> Option<u32> {
        self.advance
    }

    #[must_use]
    pub const fn gap(&self) -> u32 {
        self.gap
    }

    #[must_use]
    pub const fn cumulative_drops(&self) -> u64 {
        self.cumulative_drops
    }

    #[must_use]
    pub const fn discontinuity(&self) -> bool {
        self.discontinuity
    }

    #[must_use]
    pub const fn stream_epoch(&self) -> u64 {
        self.stream_epoch
    }
}

/// Stateful RFC-1982 sequence continuity tracker for one logical stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SequenceTracker {
    previous: Option<u32>,
    cumulative_drops: u64,
    stream_epoch: u64,
    pending_discontinuity: bool,
    failed: bool,
}

impl SequenceTracker {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            previous: None,
            cumulative_drops: 0,
            stream_epoch: 0,
            pending_discontinuity: false,
            failed: false,
        }
    }

    #[cfg(test)]
    pub(crate) const fn previous_for_test(&self) -> Option<u32> {
        self.previous
    }

    #[cfg(test)]
    pub(crate) const fn continuity_state_for_test(&self) -> (Option<u32>, u64, u64, bool, bool) {
        (
            self.previous,
            self.cumulative_drops,
            self.stream_epoch,
            self.pending_discontinuity,
            self.failed,
        )
    }

    #[cfg(test)]
    pub(crate) fn force_stream_epoch_overflow_on_recovery(&mut self) {
        self.stream_epoch = u64::MAX;
    }

    #[cfg(test)]
    pub(crate) const fn stream_epoch_for_test(&self) -> u64 {
        self.stream_epoch
    }

    #[cfg(test)]
    pub(crate) const fn failed_for_test(&self) -> bool {
        self.failed
    }

    #[cfg(test)]
    pub(crate) fn force_drop_overflow_on_next_gap(&mut self) {
        self.previous = Some(1);
        self.cumulative_drops = u64::MAX;
    }

    /// Mark a successfully replaced stream as a new discontinuous epoch.
    ///
    /// The marker remains pending until the next observed (delivered) frame, so
    /// discarded warm-up dequeues cannot consume the recovery evidence.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceTrackerError::StreamEpochOverflow`] and permanently
    /// fails the tracker when the epoch cannot be represented.
    pub fn begin_new_epoch(&mut self) -> Result<(), SequenceTrackerError> {
        if self.failed {
            return Err(SequenceTrackerError::TrackerFailed);
        }
        let Some(stream_epoch) = self.stream_epoch.checked_add(1) else {
            self.failed = true;
            return Err(SequenceTrackerError::StreamEpochOverflow);
        };
        self.stream_epoch = stream_epoch;
        self.previous = None;
        self.pending_discontinuity = true;
        Ok(())
    }

    pub(crate) fn observe_discarded(
        &mut self,
        raw: u32,
    ) -> Result<SequenceObservation, SequenceTrackerError> {
        let observation = self.observe(raw)?;
        if observation.discontinuity() {
            self.pending_discontinuity = true;
        }
        Ok(observation)
    }

    /// Observe one raw sequence value.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceTrackerError`] after an unrepresentable counter state.
    pub fn observe(&mut self, raw: u32) -> Result<SequenceObservation, SequenceTrackerError> {
        if self.failed {
            return Err(SequenceTrackerError::TrackerFailed);
        }
        let (gap, transition_discontinuity, advance) =
            self.previous.map_or((0, false, None), |previous| {
                let delta = raw.wrapping_sub(previous);
                if (1..(1_u32 << 31)).contains(&delta) {
                    (delta - 1, false, Some(delta))
                } else {
                    (0, true, None)
                }
            });
        if transition_discontinuity {
            let Some(stream_epoch) = self.stream_epoch.checked_add(1) else {
                self.failed = true;
                return Err(SequenceTrackerError::StreamEpochOverflow);
            };
            self.stream_epoch = stream_epoch;
        }
        if gap != 0 {
            let Some(cumulative_drops) = self.cumulative_drops.checked_add(u64::from(gap)) else {
                self.failed = true;
                return Err(SequenceTrackerError::DropCounterOverflow);
            };
            self.cumulative_drops = cumulative_drops;
        }
        let discontinuity = transition_discontinuity || self.pending_discontinuity;
        self.previous = Some(raw);
        self.pending_discontinuity = false;
        Ok(SequenceObservation {
            raw,
            advance,
            gap,
            cumulative_drops: self.cumulative_drops,
            discontinuity,
            stream_epoch: self.stream_epoch,
        })
    }
}

/// Why a dequeued buffer cannot enter the trusted decode boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DequeuedBufferError {
    /// V4L2 marked the dequeued payload as corrupt.
    DriverReportedCorruption,
    /// The driver returned a timestamp that cannot identify a valid instant.
    InvalidTimestamp { seconds: i64, microseconds: i64 },
    /// The known timestamp mask carried a value with no defined semantics.
    UnsupportedTimestampClock(u32),
    /// The known timestamp-source mask carried a value with no defined semantics.
    UnsupportedTimestampSource(u32),
    /// The negotiated format has no strict payload rule in this boundary.
    UnsupportedFormat([u8; 4]),
    /// Zero geometry cannot describe a decodable image payload.
    InvalidGeometry { width: u32, height: u32 },
    /// Existing decoders require tightly packed rows.
    UnsupportedStride { expected: usize, actual: usize },
    /// Geometry arithmetic exceeded the target address space.
    PayloadSizeOverflow,
    /// The initialized payload cannot contain the negotiated image.
    PayloadTooShort { bytes_used: usize, minimum: usize },
    /// The driver claims more initialized payload than exists in the mmap slot.
    PayloadExceedsMapping {
        bytes_used: usize,
        mapped_len: usize,
    },
    /// The kernel's payload length cannot be represented on this target.
    PayloadLengthUnsupported(u32),
}

impl std::fmt::Display for DequeuedBufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DriverReportedCorruption => {
                f.write_str("V4L2 marked the dequeued payload as corrupt")
            }
            Self::InvalidTimestamp {
                seconds,
                microseconds,
            } => write!(f, "invalid V4L2 timestamp {seconds}s {microseconds}us"),
            Self::UnsupportedTimestampClock(bits) => {
                write!(f, "unsupported V4L2 timestamp clock bits 0x{bits:08x}")
            }
            Self::UnsupportedTimestampSource(bits) => {
                write!(f, "unsupported V4L2 timestamp source bits 0x{bits:08x}")
            }
            Self::UnsupportedFormat(fourcc) => write!(
                f,
                "unsupported dequeued pixel format {:?}",
                String::from_utf8_lossy(fourcc)
            ),
            Self::InvalidGeometry { width, height } => {
                write!(f, "invalid dequeued geometry {width}x{height}")
            }
            Self::UnsupportedStride { expected, actual } => write!(
                f,
                "unsupported row stride {actual}; tight decoder requires {expected}"
            ),
            Self::PayloadSizeOverflow => f.write_str("dequeued payload geometry overflows usize"),
            Self::PayloadTooShort {
                bytes_used,
                minimum,
            } => write!(
                f,
                "dequeued payload uses {bytes_used} bytes but format requires at least {minimum}"
            ),
            Self::PayloadExceedsMapping {
                bytes_used,
                mapped_len,
            } => write!(
                f,
                "dequeued payload uses {bytes_used} bytes but mapping has {mapped_len}"
            ),
            Self::PayloadLengthUnsupported(bytes_used) => write!(
                f,
                "dequeued payload length {bytes_used} is unsupported on this target"
            ),
        }
    }
}

impl std::error::Error for DequeuedBufferError {}

/// Checked minimum payload for one negotiated, tightly packed image format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PayloadLayout {
    minimum: usize,
}

impl PayloadLayout {
    pub(crate) fn new(
        fourcc: [u8; 4],
        width: u32,
        height: u32,
        stride: u32,
    ) -> Result<Self, DequeuedBufferError> {
        if width == 0 || height == 0 {
            return Err(DequeuedBufferError::InvalidGeometry { width, height });
        }
        if (fourcc == *b"YUYV" && !width.is_multiple_of(2))
            || (fourcc == *b"NV12" && (!width.is_multiple_of(2) || !height.is_multiple_of(2)))
        {
            return Err(DequeuedBufferError::InvalidGeometry { width, height });
        }
        let width = usize::try_from(width).map_err(|_| DequeuedBufferError::PayloadSizeOverflow)?;
        let height =
            usize::try_from(height).map_err(|_| DequeuedBufferError::PayloadSizeOverflow)?;
        let actual_stride =
            usize::try_from(stride).map_err(|_| DequeuedBufferError::PayloadSizeOverflow)?;
        let expected_stride = match &fourcc {
            b"GREY" | b"Y8  " | b"Y800" | b"NV12" => width,
            b"Y16 " | b"Y10 " | b"Y12 " | b"YUYV" => width
                .checked_mul(2)
                .ok_or(DequeuedBufferError::PayloadSizeOverflow)?,
            _ => return Err(DequeuedBufferError::UnsupportedFormat(fourcc)),
        };
        if actual_stride != expected_stride {
            return Err(DequeuedBufferError::UnsupportedStride {
                expected: expected_stride,
                actual: actual_stride,
            });
        }
        let image_rows = expected_stride
            .checked_mul(height)
            .ok_or(DequeuedBufferError::PayloadSizeOverflow)?;
        let minimum = if fourcc == *b"NV12" {
            image_rows
                .checked_add(image_rows / 2)
                .ok_or(DequeuedBufferError::PayloadSizeOverflow)?
        } else {
            image_rows
        };
        Ok(Self { minimum })
    }

    pub(crate) fn validate(self, facts: &DequeuedBufferFacts) -> Result<(), DequeuedBufferError> {
        if facts.bytes_used < self.minimum {
            return Err(DequeuedBufferError::PayloadTooShort {
                bytes_used: facts.bytes_used,
                minimum: self.minimum,
            });
        }
        Ok(())
    }
}

/// Owned kernel facts copied from one reusable V4L2 dequeue slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DequeuedBufferFacts {
    bytes_used: usize,
    known_flags: u32,
    sequence_raw: u32,
    timestamp_seconds: i64,
    timestamp_microseconds: i64,
    timestamp_micros: i64,
    timestamp_clock: TimestampClock,
    timestamp_source: TimestampSource,
}

fn widen_timestamp_component<T>(value: T) -> i64
where
    i64: From<T>,
{
    i64::from(value)
}

impl DequeuedBufferFacts {
    /// Copy and validate metadata before the ring slot can be reused.
    ///
    /// # Errors
    ///
    /// Returns [`DequeuedBufferError`] for malformed timestamp semantics or a
    /// payload outside the mmap boundary. Driver-reported payload corruption is
    /// retained as metadata so continuity can observe the dequeue while the
    /// trusted payload boundary rejects delivery.
    pub(crate) fn from_v4l(
        metadata: &v4l::buffer::Metadata,
        mapped_len: usize,
    ) -> Result<Self, DequeuedBufferError> {
        let bytes_used = usize::try_from(metadata.bytesused)
            .map_err(|_| DequeuedBufferError::PayloadLengthUnsupported(metadata.bytesused))?;
        if bytes_used > mapped_len {
            return Err(DequeuedBufferError::PayloadExceedsMapping {
                bytes_used,
                mapped_len,
            });
        }
        let timestamp_seconds = widen_timestamp_component(metadata.timestamp.sec);
        let timestamp_microseconds = widen_timestamp_component(metadata.timestamp.usec);
        if timestamp_seconds < 0 || !(0..1_000_000).contains(&timestamp_microseconds) {
            return Err(DequeuedBufferError::InvalidTimestamp {
                seconds: timestamp_seconds,
                microseconds: timestamp_microseconds,
            });
        }
        let timestamp_micros = timestamp_seconds
            .checked_mul(1_000_000)
            .and_then(|seconds| seconds.checked_add(timestamp_microseconds))
            .ok_or(DequeuedBufferError::InvalidTimestamp {
                seconds: timestamp_seconds,
                microseconds: timestamp_microseconds,
            })?;
        let flag_bits = metadata.flags.bits();
        let clock_bits = flag_bits & v4l::buffer::Flags::TIMESTAMP_MASK.bits();
        let timestamp_clock = match clock_bits {
            bits if bits == v4l::buffer::Flags::TIMESTAMP_UNKNOWN.bits() => TimestampClock::Unknown,
            bits if bits == v4l::buffer::Flags::TIMESTAMP_MONOTONIC.bits() => {
                TimestampClock::Monotonic
            }
            bits if bits == v4l::buffer::Flags::TIMESTAMP_COPY.bits() => TimestampClock::Copy,
            bits => return Err(DequeuedBufferError::UnsupportedTimestampClock(bits)),
        };
        let source_bits = flag_bits & v4l::buffer::Flags::TSTAMP_SRC_MASK.bits();
        let timestamp_source = match source_bits {
            bits if bits == v4l::buffer::Flags::TSTAMP_SRC_EOF.bits() => {
                TimestampSource::EndOfFrame
            }
            bits if bits == v4l::buffer::Flags::TSTAMP_SRC_SOE.bits() => {
                TimestampSource::StartOfExposure
            }
            bits => return Err(DequeuedBufferError::UnsupportedTimestampSource(bits)),
        };
        Ok(Self {
            bytes_used,
            known_flags: flag_bits,
            sequence_raw: metadata.sequence,
            timestamp_seconds,
            timestamp_microseconds,
            timestamp_micros,
            timestamp_clock,
            timestamp_source,
        })
    }

    /// Number of initialized payload bytes reported by the driver.
    #[must_use]
    pub const fn bytes_used(&self) -> usize {
        self.bytes_used
    }

    /// All flag bits preserved by pinned `v4l` 0.14.0.
    #[must_use]
    pub const fn known_flags(&self) -> u32 {
        self.known_flags
    }

    /// Whether V4L2 marked this successfully dequeued payload as corrupt.
    #[must_use]
    pub const fn driver_reported_corruption(&self) -> bool {
        self.known_flags & v4l::buffer::Flags::ERROR.bits() != 0
    }

    /// Raw wrapping V4L2 sequence number.
    #[must_use]
    pub const fn sequence_raw(&self) -> u32 {
        self.sequence_raw
    }

    /// Whole seconds from the V4L2 buffer timestamp.
    #[must_use]
    pub const fn timestamp_seconds(&self) -> i64 {
        self.timestamp_seconds
    }

    /// Sub-second microseconds from the V4L2 buffer timestamp.
    #[must_use]
    pub const fn timestamp_microseconds(&self) -> i64 {
        self.timestamp_microseconds
    }

    /// Checked total timestamp in microseconds for same-domain correlation.
    #[must_use]
    pub const fn timestamp_micros(&self) -> i64 {
        self.timestamp_micros
    }

    /// Clock domain declared by the V4L2 timestamp flags.
    #[must_use]
    pub const fn timestamp_clock(&self) -> TimestampClock {
        self.timestamp_clock
    }

    /// Capture event declared by the V4L2 timestamp flags.
    #[must_use]
    pub const fn timestamp_source(&self) -> TimestampSource {
        self.timestamp_source
    }
}

/// Immutable camera identity and logical role copied from a validated lease.
///
/// This value owns its identity so a dequeued frame never depends on a later
/// `/dev/videoN` lookup or a mutable inventory observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameBinding {
    camera_instance_id: CameraInstanceId,
    generation: CameraGeneration,
    stream_role: StreamRole,
}

impl FrameBinding {
    pub(crate) fn new(
        camera_instance_id: CameraInstanceId,
        generation: CameraGeneration,
        stream_role: StreamRole,
    ) -> Self {
        Self {
            camera_instance_id,
            generation,
            stream_role,
        }
    }

    /// Process-scoped identity of the physical camera incarnation.
    #[must_use]
    pub const fn camera_instance_id(&self) -> &CameraInstanceId {
        &self.camera_instance_id
    }

    /// Lifecycle generation validated when the lease was acquired.
    #[must_use]
    pub const fn generation(&self) -> CameraGeneration {
        self.generation
    }

    /// Logical role of the endpoint producing frames under this binding.
    #[must_use]
    pub const fn stream_role(&self) -> StreamRole {
        self.stream_role
    }
}

/// Complete identity of the format proven stable after the V4L2 buffer claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedFormatIdentity {
    fourcc: [u8; 4],
    width: u32,
    height: u32,
    stride: u32,
    image_size: u32,
    field_order: u32,
    colorspace: u32,
    quantization: u32,
    transfer: u32,
    flags: u32,
}

impl ValidatedFormatIdentity {
    /// Copy every field category compared by the post-claim format check.
    #[must_use]
    pub(crate) fn from_stable_format(format: &v4l::Format) -> Self {
        Self {
            fourcc: format.fourcc.repr,
            width: format.width,
            height: format.height,
            stride: format.stride,
            image_size: format.size,
            field_order: format.field_order as u32,
            colorspace: format.colorspace as u32,
            quantization: format.quantization as u32,
            transfer: format.transfer as u32,
            flags: format.flags.bits(),
        }
    }

    #[must_use]
    pub const fn fourcc(&self) -> [u8; 4] {
        self.fourcc
    }

    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    #[must_use]
    pub const fn stride(&self) -> u32 {
        self.stride
    }

    #[must_use]
    pub const fn image_size(&self) -> u32 {
        self.image_size
    }

    #[must_use]
    pub const fn field_order(&self) -> u32 {
        self.field_order
    }

    #[must_use]
    pub const fn colorspace(&self) -> u32 {
        self.colorspace
    }

    #[must_use]
    pub const fn quantization(&self) -> u32 {
        self.quantization
    }

    #[must_use]
    pub const fn transfer(&self) -> u32 {
        self.transfer
    }

    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }
}

/// Why captured evidence cannot be published as runtime frame provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeProvenanceError {
    FactsSequenceMismatch,
    FactsTimestampMismatch,
    ContinuityMismatch,
    DriverReportedCorruption,
    SingleWindowMustBePoint,
    ActiveIrRequiresIrStream,
    TooFewContributors,
    TooManyContributors,
    InvalidSelection,
    EqualSubtractionIndices,
    MixedBinding,
    MixedFormat,
    MixedRole,
    MixedTimestampDomain,
    MixedContinuityEpoch,
    ContributorDiscontinuity,
    NonIncreasingTimestamp,
    NonConsecutiveSequence,
    TimestampDeltaMismatch,
    CounterUnderflow,
    TimestampSpanOverflow,
}

impl std::fmt::Display for RuntimeProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FactsSequenceMismatch => "dequeue facts and sequence observation disagree",
            Self::FactsTimestampMismatch => "dequeue facts and timestamp observation disagree",
            Self::ContinuityMismatch => "sequence and timestamp continuity disagree",
            Self::DriverReportedCorruption => "V4L2 marked a provenance contributor corrupt",
            Self::SingleWindowMustBePoint => "single-frame capture window is not a point",
            Self::ActiveIrRequiresIrStream => "active-IR evidence requires an IR stream",
            Self::TooFewContributors => "aggregate provenance requires at least two contributors",
            Self::TooManyContributors => "aggregate provenance exceeds 64 contributors",
            Self::InvalidSelection => "aggregate contributor selection is out of bounds",
            Self::EqualSubtractionIndices => "subtraction contributors must be distinct",
            Self::MixedBinding => "aggregate contributors have mixed camera bindings",
            Self::MixedFormat => "aggregate contributors have mixed validated formats",
            Self::MixedRole => "aggregate contributors have mixed stream roles",
            Self::MixedTimestampDomain => "aggregate contributors have mixed timestamp domains",
            Self::MixedContinuityEpoch => "aggregate contributors have mixed continuity epochs",
            Self::ContributorDiscontinuity => "aggregate contributor reports a discontinuity",
            Self::NonIncreasingTimestamp => "aggregate timestamps are not strictly increasing",
            Self::NonConsecutiveSequence => "aggregate sequence observations are not consecutive",
            Self::TimestampDeltaMismatch => {
                "aggregate timestamp delta disagrees with its observation"
            }
            Self::CounterUnderflow => "aggregate cumulative drop counter moved backward",
            Self::TimestampSpanOverflow => "aggregate timestamp span cannot be represented",
        })
    }
}

impl std::error::Error for RuntimeProvenanceError {}

/// Validated evidence awaiting an explicit, consuming illumination decision.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PendingSingleFrameProvenance {
    binding: FrameBinding,
    format: ValidatedFormatIdentity,
    facts: DequeuedBufferFacts,
    sequence: SequenceObservation,
    timestamp: TimestampObservation,
    capture_window: CaptureWindow,
}

/// Complete trusted runtime evidence for one delivered dequeue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleFrameProvenance {
    binding: FrameBinding,
    format: ValidatedFormatIdentity,
    facts: DequeuedBufferFacts,
    sequence: SequenceObservation,
    timestamp: TimestampObservation,
    capture_window: CaptureWindow,
    illumination: IlluminationProvenance,
}

impl SingleFrameProvenance {
    pub(crate) fn begin(
        binding: FrameBinding,
        format: ValidatedFormatIdentity,
        facts: DequeuedBufferFacts,
        sequence: SequenceObservation,
        timestamp: TimestampObservation,
        capture_window: CaptureWindow,
    ) -> Result<PendingSingleFrameProvenance, RuntimeProvenanceError> {
        if facts.sequence_raw() != sequence.raw() {
            return Err(RuntimeProvenanceError::FactsSequenceMismatch);
        }
        if facts.timestamp_micros() != timestamp.micros()
            || facts.timestamp_clock() != timestamp.clock()
            || facts.timestamp_source() != timestamp.source()
        {
            return Err(RuntimeProvenanceError::FactsTimestampMismatch);
        }
        if sequence.stream_epoch() != timestamp.stream_epoch()
            || sequence.discontinuity() != timestamp.discontinuity()
        {
            return Err(RuntimeProvenanceError::ContinuityMismatch);
        }
        if facts.driver_reported_corruption() {
            return Err(RuntimeProvenanceError::DriverReportedCorruption);
        }
        if capture_window.start != capture_window.end {
            return Err(RuntimeProvenanceError::SingleWindowMustBePoint);
        }
        Ok(PendingSingleFrameProvenance {
            binding,
            format,
            facts,
            sequence,
            timestamp,
            capture_window,
        })
    }

    #[must_use]
    pub const fn binding(&self) -> &FrameBinding {
        &self.binding
    }

    #[must_use]
    pub const fn format(&self) -> &ValidatedFormatIdentity {
        &self.format
    }

    #[must_use]
    pub const fn facts(&self) -> &DequeuedBufferFacts {
        &self.facts
    }

    #[must_use]
    pub const fn sequence(&self) -> &SequenceObservation {
        &self.sequence
    }

    #[must_use]
    pub const fn timestamp(&self) -> &TimestampObservation {
        &self.timestamp
    }

    #[must_use]
    pub const fn capture_window(&self) -> CaptureWindow {
        self.capture_window
    }

    #[must_use]
    pub const fn illumination(&self) -> IlluminationProvenance {
        self.illumination
    }
}

impl PendingSingleFrameProvenance {
    pub(crate) fn finalize_illumination(
        self,
        illumination: IlluminationProvenance,
    ) -> Result<SingleFrameProvenance, RuntimeProvenanceError> {
        if illumination == IlluminationProvenance::ActiveIr
            && self.binding.stream_role() != StreamRole::Ir
        {
            return Err(RuntimeProvenanceError::ActiveIrRequiresIrStream);
        }
        Ok(SingleFrameProvenance {
            binding: self.binding,
            format: self.format,
            facts: self.facts,
            sequence: self.sequence,
            timestamp: self.timestamp,
            capture_window: self.capture_window,
            illumination,
        })
    }
}

/// How contributors influenced a derived frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContributorSelection {
    Selected {
        index: usize,
    },
    ReducedOverAll,
    Subtracted {
        lit_index: usize,
        ambient_index: usize,
    },
}

/// Validated provenance for a frame derived from multiple single dequeues.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateFrameProvenance {
    contributors: Vec<SingleFrameProvenance>,
    selection: ContributorSelection,
    capture_window: CaptureWindow,
    illumination: IlluminationProvenance,
    cumulative_drops_start: u64,
    cumulative_drops_end: u64,
    drops_within: u64,
    worst_gap: u32,
    worst_delta_micros: Option<u64>,
    timestamp_span_micros: u64,
}

impl AggregateFrameProvenance {
    pub(crate) fn new(
        contributors: Vec<SingleFrameProvenance>,
        selection: ContributorSelection,
    ) -> Result<Self, RuntimeProvenanceError> {
        if contributors.len() < 2 {
            return Err(RuntimeProvenanceError::TooFewContributors);
        }
        if contributors.len() > 64 {
            return Err(RuntimeProvenanceError::TooManyContributors);
        }
        let len = contributors.len();
        let illumination = match selection {
            ContributorSelection::Selected { index } => contributors
                .get(index)
                .ok_or(RuntimeProvenanceError::InvalidSelection)?
                .illumination(),
            ContributorSelection::ReducedOverAll => {
                let first = contributors[0].illumination();
                if contributors
                    .iter()
                    .all(|contributor| contributor.illumination() == first)
                {
                    first
                } else {
                    IlluminationProvenance::Unknown
                }
            }
            ContributorSelection::Subtracted {
                lit_index,
                ambient_index,
            } => {
                if lit_index == ambient_index {
                    return Err(RuntimeProvenanceError::EqualSubtractionIndices);
                }
                let lit = contributors
                    .get(lit_index)
                    .ok_or(RuntimeProvenanceError::InvalidSelection)?;
                let ambient = contributors
                    .get(ambient_index)
                    .ok_or(RuntimeProvenanceError::InvalidSelection)?;
                if lit.illumination() == IlluminationProvenance::ActiveIr
                    && ambient.illumination() == IlluminationProvenance::Ambient
                {
                    IlluminationProvenance::ActiveIr
                } else {
                    IlluminationProvenance::Unknown
                }
            }
        };
        debug_assert!(len >= 2);
        let first = &contributors[0];
        if contributors
            .iter()
            .any(|contributor| contributor.binding().stream_role() != first.binding().stream_role())
        {
            return Err(RuntimeProvenanceError::MixedRole);
        }
        if contributors.iter().any(|contributor| {
            contributor.binding().camera_instance_id() != first.binding().camera_instance_id()
                || contributor.binding().generation() != first.binding().generation()
        }) {
            return Err(RuntimeProvenanceError::MixedBinding);
        }
        if contributors
            .iter()
            .any(|contributor| contributor.format() != first.format())
        {
            return Err(RuntimeProvenanceError::MixedFormat);
        }
        if contributors.iter().any(|contributor| {
            contributor.timestamp().clock() != first.timestamp().clock()
                || contributor.timestamp().source() != first.timestamp().source()
        }) {
            return Err(RuntimeProvenanceError::MixedTimestampDomain);
        }
        if contributors.iter().any(|contributor| {
            contributor.sequence().stream_epoch() != first.sequence().stream_epoch()
                || contributor.timestamp().stream_epoch() != first.timestamp().stream_epoch()
        }) {
            return Err(RuntimeProvenanceError::MixedContinuityEpoch);
        }
        if contributors.iter().any(|contributor| {
            contributor.facts().driver_reported_corruption()
                || contributor.sequence().discontinuity()
                || contributor.timestamp().discontinuity()
        }) {
            return Err(RuntimeProvenanceError::ContributorDiscontinuity);
        }
        for pair in contributors.windows(2) {
            let previous = &pair[0];
            let current = &pair[1];
            let Some(timestamp_delta) = current
                .timestamp()
                .micros()
                .checked_sub(previous.timestamp().micros())
            else {
                return Err(RuntimeProvenanceError::TimestampSpanOverflow);
            };
            if timestamp_delta <= 0 {
                return Err(RuntimeProvenanceError::NonIncreasingTimestamp);
            }
            let Some(advance) = current.sequence().advance() else {
                return Err(RuntimeProvenanceError::NonConsecutiveSequence);
            };
            if current.sequence().raw() != previous.sequence().raw().wrapping_add(advance) {
                return Err(RuntimeProvenanceError::NonConsecutiveSequence);
            }
            if u64::try_from(timestamp_delta).ok() != current.timestamp().delta_micros() {
                return Err(RuntimeProvenanceError::TimestampDeltaMismatch);
            }
        }
        let last = contributors.last().expect("aggregate has contributors");
        let cumulative_drops_start = first.sequence().cumulative_drops();
        let cumulative_drops_end = last.sequence().cumulative_drops();
        let drops_within = cumulative_drops_end
            .checked_sub(cumulative_drops_start)
            .ok_or(RuntimeProvenanceError::CounterUnderflow)?;
        let timestamp_span = last
            .timestamp()
            .micros()
            .checked_sub(first.timestamp().micros())
            .and_then(|span| u64::try_from(span).ok())
            .ok_or(RuntimeProvenanceError::TimestampSpanOverflow)?;
        let capture_window = contributors
            .iter()
            .map(SingleFrameProvenance::capture_window)
            .reduce(CaptureWindow::union)
            .expect("aggregate has contributors");
        let worst_gap = contributors
            .iter()
            .map(|contributor| contributor.sequence().gap())
            .max()
            .expect("aggregate has contributors");
        let worst_delta_micros = contributors
            .iter()
            .filter_map(|contributor| contributor.timestamp().delta_micros())
            .max();
        Ok(Self {
            contributors,
            selection,
            capture_window,
            illumination,
            cumulative_drops_start,
            cumulative_drops_end,
            drops_within,
            worst_gap,
            worst_delta_micros,
            timestamp_span_micros: timestamp_span,
        })
    }

    #[must_use]
    pub fn contributors(&self) -> &[SingleFrameProvenance] {
        &self.contributors
    }

    #[must_use]
    pub const fn selection(&self) -> ContributorSelection {
        self.selection
    }

    #[must_use]
    pub const fn capture_window(&self) -> CaptureWindow {
        self.capture_window
    }

    #[must_use]
    pub const fn illumination(&self) -> IlluminationProvenance {
        self.illumination
    }

    #[must_use]
    pub const fn cumulative_drops_start(&self) -> u64 {
        self.cumulative_drops_start
    }

    #[must_use]
    pub const fn cumulative_drops_end(&self) -> u64 {
        self.cumulative_drops_end
    }

    #[must_use]
    pub const fn drops_within(&self) -> u64 {
        self.drops_within
    }

    #[must_use]
    pub const fn worst_gap(&self) -> u32 {
        self.worst_gap
    }

    #[must_use]
    pub const fn worst_delta_micros(&self) -> Option<u64> {
        self.worst_delta_micros
    }

    #[must_use]
    pub const fn timestamp_span_micros(&self) -> u64 {
        self.timestamp_span_micros
    }
}

/// Mandatory runtime evidence owned by every frame.
#[derive(Clone, Debug)]
pub enum RuntimeFrameProvenance {
    Single(SingleFrameProvenance),
    Aggregate(AggregateFrameProvenance),
}

impl RuntimeFrameProvenance {
    #[must_use]
    pub const fn capture_window(&self) -> CaptureWindow {
        match self {
            Self::Single(single) => single.capture_window(),
            Self::Aggregate(aggregate) => aggregate.capture_window(),
        }
    }

    #[must_use]
    pub const fn illumination(&self) -> IlluminationProvenance {
        match self {
            Self::Single(single) => single.illumination(),
            Self::Aggregate(aggregate) => aggregate.illumination(),
        }
    }

    #[must_use]
    pub fn stream_role(&self) -> StreamRole {
        match self {
            Self::Single(single) => single.binding().stream_role(),
            Self::Aggregate(aggregate) => aggregate.contributors[0].binding().stream_role(),
        }
    }

    #[must_use]
    pub fn format(&self) -> &ValidatedFormatIdentity {
        match self {
            Self::Single(single) => single.format(),
            Self::Aggregate(aggregate) => aggregate.contributors[0].format(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DequeuedBufferError, DequeuedBufferFacts, PayloadLayout, SequenceTracker,
        SequenceTrackerError, TimestampClock, TimestampSource, TimestampTracker,
        TimestampTrackerError,
    };
    use crate::contracts::IlluminationProvenance;

    #[test]
    fn first_monotonic_timestamp_establishes_a_clean_epoch() {
        let mut tracker = TimestampTracker::new();
        let observation = tracker
            .observe(
                1_000_000,
                TimestampClock::Monotonic,
                TimestampSource::EndOfFrame,
            )
            .expect("first timestamp is valid");

        assert_eq!(observation.micros(), 1_000_000);
        assert_eq!(observation.delta_micros(), None);
        assert_eq!(observation.clock(), TimestampClock::Monotonic);
        assert_eq!(observation.source(), TimestampSource::EndOfFrame);
        assert!(!observation.discontinuity());
        assert_eq!(observation.stream_epoch(), 0);
    }

    #[test]
    fn monotonic_timestamps_report_positive_deltas() {
        let mut tracker = TimestampTracker::new();
        tracker
            .observe(
                1_000_000,
                TimestampClock::Monotonic,
                TimestampSource::StartOfExposure,
            )
            .expect("baseline");
        let observation = tracker
            .observe(
                1_033_333,
                TimestampClock::Monotonic,
                TimestampSource::StartOfExposure,
            )
            .expect("increasing timestamp");

        assert_eq!(observation.delta_micros(), Some(33_333));
        assert!(!observation.discontinuity());
        assert_eq!(observation.stream_epoch(), 0);
    }

    #[test]
    fn untrusted_timestamp_clocks_fail_the_current_epoch() {
        for clock in [TimestampClock::Unknown, TimestampClock::Copy] {
            let mut tracker = TimestampTracker::new();
            assert_eq!(
                tracker.observe(1, clock, TimestampSource::EndOfFrame),
                Err(TimestampTrackerError::UntrustedClock(clock))
            );
            assert_eq!(
                tracker.observe(2, TimestampClock::Monotonic, TimestampSource::EndOfFrame),
                Err(TimestampTrackerError::EpochFailed)
            );
        }
    }

    #[test]
    fn invalid_timestamp_ordering_stays_failed_until_recovery() {
        let mut zero = TimestampTracker::new();
        assert_eq!(
            zero.observe(0, TimestampClock::Monotonic, TimestampSource::EndOfFrame),
            Err(TimestampTrackerError::ZeroTimestamp)
        );

        for current in [100, 99] {
            let mut tracker = TimestampTracker::new();
            tracker
                .observe(100, TimestampClock::Monotonic, TimestampSource::EndOfFrame)
                .expect("baseline");
            assert_eq!(
                tracker.observe(
                    current,
                    TimestampClock::Monotonic,
                    TimestampSource::EndOfFrame
                ),
                Err(TimestampTrackerError::NonIncreasing {
                    previous: 100,
                    current
                })
            );
            assert_eq!(
                tracker.observe(101, TimestampClock::Monotonic, TimestampSource::EndOfFrame),
                Err(TimestampTrackerError::EpochFailed)
            );
        }
    }

    #[test]
    fn timestamp_domain_changes_fail_the_current_epoch() {
        let mut source = TimestampTracker::new();
        source
            .observe(10, TimestampClock::Monotonic, TimestampSource::EndOfFrame)
            .expect("baseline");
        assert_eq!(
            source.observe(
                11,
                TimestampClock::Monotonic,
                TimestampSource::StartOfExposure
            ),
            Err(TimestampTrackerError::SourceChanged {
                expected: TimestampSource::EndOfFrame,
                actual: TimestampSource::StartOfExposure,
            })
        );

        let mut clock = TimestampTracker::new();
        clock
            .observe(10, TimestampClock::Monotonic, TimestampSource::EndOfFrame)
            .expect("baseline");
        assert_eq!(
            clock.observe(11, TimestampClock::Copy, TimestampSource::EndOfFrame),
            Err(TimestampTrackerError::ClockChanged {
                expected: TimestampClock::Monotonic,
                actual: TimestampClock::Copy,
            })
        );
    }

    #[test]
    fn recovered_timestamp_epoch_marks_only_its_first_observation() {
        let mut tracker = TimestampTracker::new();
        tracker
            .observe(100, TimestampClock::Monotonic, TimestampSource::EndOfFrame)
            .expect("baseline");
        assert!(tracker
            .observe(99, TimestampClock::Monotonic, TimestampSource::EndOfFrame)
            .is_err());

        tracker.begin_new_epoch().expect("recovery epoch");
        let first = tracker
            .observe(
                1,
                TimestampClock::Monotonic,
                TimestampSource::StartOfExposure,
            )
            .expect("new baseline");
        assert!(first.discontinuity());
        assert_eq!(first.stream_epoch(), 1);
        assert_eq!(first.delta_micros(), None);

        let second = tracker
            .observe(
                2,
                TimestampClock::Monotonic,
                TimestampSource::StartOfExposure,
            )
            .expect("same epoch");
        assert!(!second.discontinuity());
    }

    #[test]
    fn timestamp_epoch_overflow_permanently_poisons_tracker() {
        let mut tracker = TimestampTracker::new();
        tracker.stream_epoch = u64::MAX;

        assert_eq!(
            tracker.begin_new_epoch(),
            Err(TimestampTrackerError::StreamEpochOverflow)
        );
        assert_eq!(
            tracker.begin_new_epoch(),
            Err(TimestampTrackerError::TrackerFailed)
        );
        assert_eq!(
            tracker.observe(1, TimestampClock::Monotonic, TimestampSource::EndOfFrame),
            Err(TimestampTrackerError::TrackerFailed)
        );
    }

    #[test]
    fn negative_timestamp_fails_the_current_epoch() {
        let mut tracker = TimestampTracker::new();
        assert_eq!(
            tracker.observe(-1, TimestampClock::Monotonic, TimestampSource::EndOfFrame),
            Err(TimestampTrackerError::NegativeTimestamp(-1))
        );
        assert_eq!(
            tracker.observe(1, TimestampClock::Monotonic, TimestampSource::EndOfFrame),
            Err(TimestampTrackerError::EpochFailed)
        );
    }

    #[test]
    fn sequence_observation_reports_only_same_epoch_forward_advance() {
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(41).expect("baseline").advance(), None);
        assert_eq!(tracker.observe(45).expect("forward gap").advance(), Some(4));
        tracker.begin_new_epoch().expect("recovery epoch");
        assert_eq!(
            tracker
                .observe_discarded(u32::MAX)
                .expect("recovery baseline")
                .advance(),
            None
        );
        assert_eq!(
            tracker.observe(0).expect("wrapped advance").advance(),
            Some(1)
        );
    }

    #[test]
    fn first_sequence_establishes_a_clean_baseline() {
        let mut tracker = SequenceTracker::new();

        let observation = tracker.observe(41).expect("first sequence is valid");

        assert_eq!(observation.raw(), 41);
        assert_eq!(observation.gap(), 0);
        assert_eq!(observation.cumulative_drops(), 0);
        assert!(!observation.discontinuity());
        assert_eq!(observation.stream_epoch(), 0);
    }

    #[test]
    fn forward_sequences_count_only_missing_frames() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(41).expect("baseline");

        let contiguous = tracker.observe(42).expect("contiguous sequence");
        assert_eq!(contiguous.gap(), 0);
        assert_eq!(contiguous.cumulative_drops(), 0);
        assert!(!contiguous.discontinuity());

        let gap = tracker.observe(45).expect("small forward gap");
        assert_eq!(gap.gap(), 2);
        assert_eq!(gap.cumulative_drops(), 2);
        assert!(!gap.discontinuity());
        assert_eq!(gap.stream_epoch(), 0);
    }

    #[test]
    fn sequence_wrap_is_contiguous() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(u32::MAX).expect("baseline");

        let wrapped = tracker.observe(0).expect("serial wrap");

        assert_eq!(wrapped.gap(), 0);
        assert_eq!(wrapped.cumulative_drops(), 0);
        assert!(!wrapped.discontinuity());
        assert_eq!(wrapped.stream_epoch(), 0);
    }

    #[test]
    fn non_forward_sequences_start_bounded_discontinuous_epochs() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(10).expect("baseline");

        let duplicate = tracker.observe(10).expect("duplicate is represented");
        assert_eq!(duplicate.gap(), 0);
        assert_eq!(duplicate.cumulative_drops(), 0);
        assert!(duplicate.discontinuity());
        assert_eq!(duplicate.stream_epoch(), 1);

        let backward = tracker.observe(9).expect("backward reset is represented");
        assert_eq!(backward.gap(), 0);
        assert_eq!(backward.cumulative_drops(), 0);
        assert!(backward.discontinuity());
        assert_eq!(backward.stream_epoch(), 2);

        let ambiguous = tracker
            .observe(9_u32.wrapping_add(1_u32 << 31))
            .expect("half-range delta is represented");
        assert_eq!(ambiguous.gap(), 0);
        assert_eq!(ambiguous.cumulative_drops(), 0);
        assert!(ambiguous.discontinuity());
        assert_eq!(ambiguous.stream_epoch(), 3);
    }

    #[test]
    fn explicit_restart_is_sticky_until_the_next_observation() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(100).expect("baseline");
        tracker.begin_new_epoch().expect("representable epoch");

        let restarted = tracker.observe(3).expect("first restarted frame");
        assert_eq!(restarted.gap(), 0);
        assert_eq!(restarted.cumulative_drops(), 0);
        assert!(restarted.discontinuity());
        assert_eq!(restarted.stream_epoch(), 1);

        let next = tracker.observe(4).expect("new epoch continues");
        assert!(!next.discontinuity());
        assert_eq!(next.stream_epoch(), 1);
    }

    #[test]
    fn drop_counter_overflow_permanently_fails_the_tracker() {
        let mut tracker = SequenceTracker {
            previous: Some(10),
            cumulative_drops: u64::MAX,
            stream_epoch: 0,
            pending_discontinuity: false,
            failed: false,
        };

        assert_eq!(
            tracker.observe(12),
            Err(SequenceTrackerError::DropCounterOverflow)
        );
        assert_eq!(
            tracker.observe(13),
            Err(SequenceTrackerError::TrackerFailed)
        );
    }

    #[test]
    fn stream_epoch_overflow_permanently_fails_the_tracker() {
        let mut tracker = SequenceTracker {
            previous: Some(10),
            cumulative_drops: 0,
            stream_epoch: u64::MAX,
            pending_discontinuity: false,
            failed: false,
        };

        assert_eq!(
            tracker.observe(10),
            Err(SequenceTrackerError::StreamEpochOverflow)
        );
        assert_eq!(
            tracker.observe(11),
            Err(SequenceTrackerError::TrackerFailed)
        );
    }

    #[test]
    fn largest_defined_forward_delta_is_counted_not_ambiguous() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(0).expect("baseline");

        let observation = tracker
            .observe(0x7fff_ffff)
            .expect("largest RFC-1982 forward delta");

        assert_eq!(observation.gap(), 0x7fff_fffe);
        assert_eq!(observation.cumulative_drops(), u64::from(0x7fff_fffe_u32));
        assert!(!observation.discontinuity());
    }

    #[test]
    fn wrapped_forward_gap_counts_only_missing_frames() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(u32::MAX - 1).expect("baseline");

        let observation = tracker.observe(1).expect("wrapped forward gap");

        assert_eq!(observation.gap(), 2);
        assert_eq!(observation.cumulative_drops(), 2);
        assert!(!observation.discontinuity());
    }

    #[test]
    fn explicit_epoch_overflow_permanently_fails_the_tracker() {
        let mut tracker = SequenceTracker {
            previous: Some(10),
            cumulative_drops: 0,
            stream_epoch: u64::MAX,
            pending_discontinuity: false,
            failed: false,
        };

        assert_eq!(
            tracker.begin_new_epoch(),
            Err(SequenceTrackerError::StreamEpochOverflow)
        );
        assert_eq!(
            tracker.begin_new_epoch(),
            Err(SequenceTrackerError::TrackerFailed)
        );
    }

    #[test]
    fn dequeue_rejects_bytes_used_beyond_the_mapping() {
        let metadata = v4l::buffer::Metadata {
            bytesused: 8,
            ..v4l::buffer::Metadata::default()
        };

        assert_eq!(
            DequeuedBufferFacts::from_v4l(&metadata, 7),
            Err(DequeuedBufferError::PayloadExceedsMapping {
                bytes_used: 8,
                mapped_len: 7,
            })
        );
    }

    #[test]
    fn dequeue_retains_driver_error_status_with_valid_continuity_facts() {
        let metadata = v4l::buffer::Metadata {
            bytesused: 4,
            flags: v4l::buffer::Flags::ERROR | v4l::buffer::Flags::TIMESTAMP_MONOTONIC,
            sequence: 7,
            timestamp: v4l::timestamp::Timestamp::new(3, 4),
            ..Default::default()
        };

        let facts = DequeuedBufferFacts::from_v4l(&metadata, 4)
            .expect("corruption does not erase valid continuity metadata");
        assert!(facts.driver_reported_corruption());
        assert_eq!(facts.sequence_raw(), 7);
        assert_eq!(facts.timestamp_micros(), 3_000_004);
    }

    #[test]
    fn dequeue_rejects_out_of_range_timestamp_microseconds() {
        let metadata = v4l::buffer::Metadata {
            timestamp: v4l::timestamp::Timestamp::new(7, 1_000_000),
            ..v4l::buffer::Metadata::default()
        };

        assert_eq!(
            DequeuedBufferFacts::from_v4l(&metadata, 0),
            Err(DequeuedBufferError::InvalidTimestamp {
                seconds: 7,
                microseconds: 1_000_000,
            })
        );
    }

    #[test]
    fn dequeue_rejects_negative_timestamp_seconds() {
        let metadata = v4l::buffer::Metadata {
            timestamp: v4l::timestamp::Timestamp::new(-1, 0),
            ..v4l::buffer::Metadata::default()
        };

        assert_eq!(
            DequeuedBufferFacts::from_v4l(&metadata, 0),
            Err(DequeuedBufferError::InvalidTimestamp {
                seconds: -1,
                microseconds: 0,
            })
        );
    }

    #[test]
    fn dequeue_rejects_timestamp_that_cannot_form_a_microsecond_key() {
        let metadata = v4l::buffer::Metadata {
            timestamp: v4l::timestamp::Timestamp::new(i64::MAX, 0),
            ..v4l::buffer::Metadata::default()
        };

        assert_eq!(
            DequeuedBufferFacts::from_v4l(&metadata, 0),
            Err(DequeuedBufferError::InvalidTimestamp {
                seconds: i64::MAX,
                microseconds: 0,
            })
        );
    }

    #[test]
    fn dequeue_normalizes_monotonic_start_of_exposure_metadata() {
        let flags = v4l::buffer::Flags::TIMESTAMP_MONOTONIC
            | v4l::buffer::Flags::TSTAMP_SRC_SOE
            | v4l::buffer::Flags::KEYFRAME;
        let metadata = v4l::buffer::Metadata {
            bytesused: 3,
            flags,
            timestamp: v4l::timestamp::Timestamp::new(7, 11),
            sequence: 42,
            ..v4l::buffer::Metadata::default()
        };

        let facts = DequeuedBufferFacts::from_v4l(&metadata, 4).expect("valid metadata");
        assert_eq!(facts.bytes_used(), 3);
        assert_eq!(facts.sequence_raw(), 42);
        assert_eq!(facts.timestamp_seconds(), 7);
        assert_eq!(facts.timestamp_microseconds(), 11);
        assert_eq!(facts.timestamp_clock(), TimestampClock::Monotonic);
        assert_eq!(facts.timestamp_source(), TimestampSource::StartOfExposure);
        assert_eq!(facts.known_flags(), flags.bits());
    }

    #[test]
    fn dequeue_normalizes_monotonic_end_of_frame_metadata() {
        let metadata = v4l::buffer::Metadata {
            flags: v4l::buffer::Flags::TIMESTAMP_MONOTONIC | v4l::buffer::Flags::TSTAMP_SRC_EOF,
            timestamp: v4l::timestamp::Timestamp::new(1, 2),
            ..v4l::buffer::Metadata::default()
        };

        let facts = DequeuedBufferFacts::from_v4l(&metadata, 0).expect("valid metadata");
        assert_eq!(facts.timestamp_clock(), TimestampClock::Monotonic);
        assert_eq!(facts.timestamp_source(), TimestampSource::EndOfFrame);
    }

    #[test]
    fn grey_layout_rejects_short_payload() {
        let layout = PayloadLayout::new(*b"GREY", 4, 3, 4).expect("tight GREY layout");
        let metadata = v4l::buffer::Metadata {
            bytesused: 11,
            ..v4l::buffer::Metadata::default()
        };
        let facts = DequeuedBufferFacts::from_v4l(&metadata, 12).expect("bounded metadata");

        assert_eq!(
            layout.validate(&facts),
            Err(DequeuedBufferError::PayloadTooShort {
                bytes_used: 11,
                minimum: 12,
            })
        );
    }

    #[test]
    fn every_decoded_format_rejects_a_short_payload() {
        let cases = [
            (*b"GREY", 4, 16),
            (*b"Y8  ", 4, 16),
            (*b"Y800", 4, 16),
            (*b"Y16 ", 8, 32),
            (*b"Y10 ", 8, 32),
            (*b"Y12 ", 8, 32),
            (*b"YUYV", 8, 32),
            (*b"NV12", 4, 24),
        ];

        for (fourcc, stride, minimum) in cases {
            let layout = PayloadLayout::new(fourcc, 4, 4, stride).expect("supported layout");
            let metadata = v4l::buffer::Metadata {
                bytesused: minimum - 1,
                ..v4l::buffer::Metadata::default()
            };
            let facts = DequeuedBufferFacts::from_v4l(&metadata, minimum as usize)
                .expect("bounded metadata");
            assert_eq!(
                layout.validate(&facts),
                Err(DequeuedBufferError::PayloadTooShort {
                    bytes_used: minimum as usize - 1,
                    minimum: minimum as usize,
                }),
                "{}",
                String::from_utf8_lossy(&fourcc)
            );
        }
    }

    #[test]
    fn payload_geometry_overflow_is_rejected() {
        let dimension = u32::MAX - 1;
        assert_eq!(
            PayloadLayout::new(*b"NV12", dimension, dimension, dimension),
            Err(DequeuedBufferError::PayloadSizeOverflow)
        );
    }

    #[test]
    fn padded_stride_is_rejected_until_decoders_support_rows() {
        assert_eq!(
            PayloadLayout::new(*b"GREY", 4, 3, 8),
            Err(DequeuedBufferError::UnsupportedStride {
                expected: 4,
                actual: 8,
            })
        );
    }

    #[test]
    fn yuyv_requires_complete_two_pixel_macropixels() {
        assert_eq!(
            PayloadLayout::new(*b"YUYV", 3, 2, 6),
            Err(DequeuedBufferError::InvalidGeometry {
                width: 3,
                height: 2,
            })
        );
    }

    #[test]
    fn single_runtime_provenance_echoes_complete_evidence() {
        use crate::contracts::{
            CameraGeneration, CameraInstanceId, IlluminationProvenance, StreamRole,
        };
        use crate::CaptureWindow;

        let binding = super::FrameBinding::new(
            CameraInstanceId::new("11111111111111111111111111111111").expect("test identity"),
            CameraGeneration::INITIAL,
            StreamRole::Ir,
        );
        let format = v4l::Format::new(4, 3, v4l::FourCC::new(b"GREY"));
        let format = super::ValidatedFormatIdentity::from_stable_format(&format);
        let metadata = v4l::buffer::Metadata {
            bytesused: 12,
            flags: v4l::buffer::Flags::TIMESTAMP_MONOTONIC
                | v4l::buffer::Flags::TSTAMP_SRC_SOE
                | v4l::buffer::Flags::KEYFRAME,
            sequence: 7,
            timestamp: v4l::timestamp::Timestamp::new(3, 4),
            ..Default::default()
        };
        let facts = super::DequeuedBufferFacts::from_v4l(&metadata, 12).expect("valid facts");
        let sequence = super::SequenceTracker::new()
            .observe(7)
            .expect("valid sequence");
        let timestamp = super::TimestampTracker::new()
            .observe(
                3_000_004,
                super::TimestampClock::Monotonic,
                super::TimestampSource::StartOfExposure,
            )
            .expect("valid timestamp");
        let at = std::time::Instant::now();

        let provenance = super::SingleFrameProvenance::begin(
            binding.clone(),
            format.clone(),
            facts.clone(),
            sequence,
            timestamp,
            CaptureWindow::at(at),
        )
        .expect("coherent evidence")
        .finalize_illumination(IlluminationProvenance::ActiveIr)
        .expect("IR may carry authoritative active illumination");

        assert_eq!(provenance.binding(), &binding);
        assert_eq!(provenance.format(), &format);
        assert_eq!(provenance.facts(), &facts);
        assert_eq!(provenance.sequence(), &sequence);
        assert_eq!(provenance.timestamp(), &timestamp);
        assert_eq!(provenance.capture_window(), CaptureWindow::at(at));
        assert_eq!(provenance.illumination(), IlluminationProvenance::ActiveIr);
    }

    fn runtime_series(
        raws: &[u32],
        micros: &[i64],
        illumination: &[IlluminationProvenance],
    ) -> Vec<super::SingleFrameProvenance> {
        use crate::contracts::{CameraGeneration, CameraInstanceId, StreamRole};
        use crate::CaptureWindow;
        use std::time::{Duration, Instant};

        let binding = super::FrameBinding::new(
            CameraInstanceId::new("33333333333333333333333333333333").expect("test identity"),
            CameraGeneration::INITIAL,
            StreamRole::Ir,
        );
        let mut stable = v4l::Format::new(8, 6, v4l::FourCC::new(b"GREY"));
        stable.stride = 8;
        stable.size = 48;
        stable.field_order = v4l::format::FieldOrder::Progressive;
        stable.colorspace = v4l::format::Colorspace::SRGB;
        stable.flags = v4l::format::Flags::PREMUL_ALPHA;
        stable.quantization = v4l::format::Quantization::FullRange;
        stable.transfer = v4l::format::TransferFunction::SRGB;
        let format = super::ValidatedFormatIdentity::from_stable_format(&stable);
        let mut sequence_tracker = super::SequenceTracker::new();
        let mut timestamp_tracker = super::TimestampTracker::new();
        let base = Instant::now();

        raws.iter()
            .zip(micros)
            .zip(illumination)
            .map(|((&raw, &micros), &illumination)| {
                let metadata = v4l::buffer::Metadata {
                    bytesused: 48,
                    sequence: raw,
                    timestamp: v4l::timestamp::Timestamp::new(0, micros),
                    flags: v4l::buffer::Flags::TIMESTAMP_MONOTONIC,
                    ..Default::default()
                };
                let facts =
                    super::DequeuedBufferFacts::from_v4l(&metadata, 48).expect("valid test facts");
                let sequence = sequence_tracker.observe(raw).expect("valid test sequence");
                let timestamp = timestamp_tracker
                    .observe(
                        micros,
                        super::TimestampClock::Monotonic,
                        super::TimestampSource::EndOfFrame,
                    )
                    .expect("valid test timestamp");
                let at = base + Duration::from_micros(micros.unsigned_abs());
                super::SingleFrameProvenance::begin(
                    binding.clone(),
                    format.clone(),
                    facts,
                    sequence,
                    timestamp,
                    CaptureWindow::at(at),
                )
                .expect("coherent test evidence")
                .finalize_illumination(illumination)
                .expect("coherent test illumination")
            })
            .collect()
    }

    #[test]
    fn validated_format_identity_retains_every_discriminant() {
        let mut format = v4l::Format::new(640, 400, v4l::FourCC::new(b"GREY"));
        format.stride = 672;
        format.size = 268_800;
        format.field_order = v4l::format::FieldOrder::Interlaced;
        format.colorspace = v4l::format::Colorspace::Rec709;
        format.flags = v4l::format::Flags::PREMUL_ALPHA;
        format.quantization = v4l::format::Quantization::LimitedRange;
        format.transfer = v4l::format::TransferFunction::Rec709;
        let identity = super::ValidatedFormatIdentity::from_stable_format(&format);
        assert_eq!(identity.width(), 640);
        assert_eq!(identity.height(), 400);
        assert_eq!(identity.fourcc(), *b"GREY");
        assert_eq!(identity.stride(), 672);
        assert_eq!(identity.image_size(), 268_800);
        assert_eq!(identity.field_order(), format.field_order as u32);
        assert_eq!(identity.colorspace(), format.colorspace as u32);
        assert_eq!(identity.flags(), format.flags.bits());
        assert_eq!(identity.quantization(), format.quantization as u32);
        assert_eq!(identity.transfer(), format.transfer as u32);
    }

    #[test]
    fn single_rejects_raw_metadata_and_observation_disagreement() {
        let mut single = runtime_series(&[9], &[1_000], &[IlluminationProvenance::Unknown])
            .pop()
            .expect("one single");
        single.facts.sequence_raw = 10;
        assert_eq!(
            super::SingleFrameProvenance::begin(
                single.binding,
                single.format,
                single.facts,
                single.sequence,
                single.timestamp,
                single.capture_window,
            ),
            Err(super::RuntimeProvenanceError::FactsSequenceMismatch)
        );
    }

    #[test]
    fn single_rejects_timestamp_facts_and_observation_disagreement() {
        let mut single = runtime_series(&[9], &[1_000], &[IlluminationProvenance::Unknown])
            .pop()
            .expect("one single");
        single.facts.timestamp_micros += 1;
        assert_eq!(
            super::SingleFrameProvenance::begin(
                single.binding,
                single.format,
                single.facts,
                single.sequence,
                single.timestamp,
                single.capture_window,
            ),
            Err(super::RuntimeProvenanceError::FactsTimestampMismatch)
        );
    }

    #[test]
    fn single_rejects_corrupt_buffers_and_non_point_capture_windows() {
        let mut corrupt = runtime_series(&[9], &[1_000], &[IlluminationProvenance::Unknown])
            .pop()
            .expect("one single");
        corrupt.facts.known_flags |= v4l::buffer::Flags::ERROR.bits();
        assert_eq!(
            super::SingleFrameProvenance::begin(
                corrupt.binding.clone(),
                corrupt.format.clone(),
                corrupt.facts.clone(),
                corrupt.sequence,
                corrupt.timestamp,
                corrupt.capture_window,
            ),
            Err(super::RuntimeProvenanceError::DriverReportedCorruption)
        );
        corrupt.facts.known_flags &= !v4l::buffer::Flags::ERROR.bits();
        let end = corrupt.capture_window.end + std::time::Duration::from_millis(1);
        assert_eq!(
            super::SingleFrameProvenance::begin(
                corrupt.binding,
                corrupt.format,
                corrupt.facts,
                corrupt.sequence,
                corrupt.timestamp,
                crate::CaptureWindow {
                    start: corrupt.capture_window.start,
                    end,
                },
            ),
            Err(super::RuntimeProvenanceError::SingleWindowMustBePoint)
        );
    }

    #[test]
    fn illumination_finalization_rejects_active_ir_on_rgb() {
        let mut single = runtime_series(&[1], &[1], &[IlluminationProvenance::Unknown])
            .pop()
            .expect("one single");
        single.binding.stream_role = crate::contracts::StreamRole::Rgb;
        let pending = super::SingleFrameProvenance::begin(
            single.binding,
            single.format,
            single.facts,
            single.sequence,
            single.timestamp,
            single.capture_window,
        )
        .expect("otherwise coherent");
        assert_eq!(
            pending.finalize_illumination(IlluminationProvenance::ActiveIr),
            Err(super::RuntimeProvenanceError::ActiveIrRequiresIrStream)
        );
    }

    #[test]
    fn aggregate_accumulates_drop_span_gap_delta_and_union() {
        let contributors = runtime_series(
            &[10, 13, 17],
            &[100, 200, 500],
            &[
                IlluminationProvenance::Unknown,
                IlluminationProvenance::Ambient,
                IlluminationProvenance::ActiveIr,
            ],
        );
        let expected_start = contributors[0].capture_window().start;
        let expected_end = contributors[2].capture_window().end;
        let aggregate = super::AggregateFrameProvenance::new(
            contributors,
            super::ContributorSelection::Selected { index: 2 },
        )
        .expect("coherent aggregate");
        assert_eq!(aggregate.drops_within(), 5);
        assert_eq!(aggregate.timestamp_span_micros(), 400);
        assert_eq!(aggregate.worst_gap(), 3);
        assert_eq!(aggregate.worst_delta_micros(), Some(300));
        assert_eq!(aggregate.capture_window().start, expected_start);
        assert_eq!(aggregate.capture_window().end, expected_end);
        assert_eq!(aggregate.illumination(), IlluminationProvenance::ActiveIr);
    }

    #[test]
    fn aggregate_accepts_checked_u32_wrap_continuity() {
        let aggregate = super::AggregateFrameProvenance::new(
            runtime_series(
                &[u32::MAX - 1, u32::MAX, 0],
                &[100, 200, 300],
                &[IlluminationProvenance::Unknown; 3],
            ),
            super::ContributorSelection::ReducedOverAll,
        )
        .expect("wrap is consecutive");
        assert_eq!(aggregate.drops_within(), 0);
        assert_eq!(aggregate.worst_gap(), 0);
    }

    #[test]
    fn aggregate_enforces_contributor_bounds_and_selection_indices() {
        let one = runtime_series(&[1], &[1], &[IlluminationProvenance::Unknown]);
        assert_eq!(
            super::AggregateFrameProvenance::new(one, super::ContributorSelection::ReducedOverAll),
            Err(super::RuntimeProvenanceError::TooFewContributors)
        );
        let too_many = runtime_series(
            &(1..=65).collect::<Vec<_>>(),
            &(1..=65).map(i64::from).collect::<Vec<_>>(),
            &[IlluminationProvenance::Unknown; 65],
        );
        assert_eq!(
            super::AggregateFrameProvenance::new(
                too_many,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::TooManyContributors)
        );
        let two = runtime_series(&[1, 2], &[1, 2], &[IlluminationProvenance::Unknown; 2]);
        assert_eq!(
            super::AggregateFrameProvenance::new(
                two,
                super::ContributorSelection::Selected { index: 2 }
            ),
            Err(super::RuntimeProvenanceError::InvalidSelection)
        );
    }

    #[test]
    fn aggregate_rejects_mixed_binding_role_format_and_timestamp_domain() {
        let base = runtime_series(&[1, 2], &[100, 200], &[IlluminationProvenance::Unknown; 2]);
        let mut mixed = base.clone();
        mixed[1].binding.generation =
            crate::contracts::CameraGeneration::new(2).expect("generation");
        assert_eq!(
            super::AggregateFrameProvenance::new(
                mixed,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::MixedBinding)
        );
        let mut mixed = base.clone();
        mixed[1].binding.stream_role = crate::contracts::StreamRole::Rgb;
        assert_eq!(
            super::AggregateFrameProvenance::new(
                mixed,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::MixedRole)
        );
        let mut mixed = base.clone();
        mixed[1].format.flags ^= 1;
        assert_eq!(
            super::AggregateFrameProvenance::new(
                mixed,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::MixedFormat)
        );
        let mut mixed = base;
        mixed[1].timestamp.source = super::TimestampSource::StartOfExposure;
        assert_eq!(
            super::AggregateFrameProvenance::new(
                mixed,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::MixedTimestampDomain)
        );
    }

    #[test]
    fn aggregate_rejects_discontinuity_nonconsecutive_and_counter_underflow() {
        let base = runtime_series(&[5, 6], &[100, 200], &[IlluminationProvenance::Unknown; 2]);
        let mut broken = base.clone();
        broken[1].sequence.discontinuity = true;
        broken[1].timestamp.discontinuity = true;
        assert_eq!(
            super::AggregateFrameProvenance::new(
                broken,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::ContributorDiscontinuity)
        );
        let mut broken = base.clone();
        broken[1].facts.known_flags |= v4l::buffer::Flags::ERROR.bits();
        assert_eq!(
            super::AggregateFrameProvenance::new(
                broken,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::ContributorDiscontinuity)
        );
        let mut broken = base.clone();
        broken[1].sequence.advance = Some(2);
        assert_eq!(
            super::AggregateFrameProvenance::new(
                broken,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::NonConsecutiveSequence)
        );
        let mut broken = base;
        broken[1].sequence.cumulative_drops = 0;
        broken[0].sequence.cumulative_drops = 1;
        assert_eq!(
            super::AggregateFrameProvenance::new(
                broken,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::CounterUnderflow)
        );
    }

    #[test]
    fn aggregate_rejects_mixed_continuity_epoch() {
        let mut broken =
            runtime_series(&[5, 6], &[100, 200], &[IlluminationProvenance::Unknown; 2]);
        broken[1].sequence.stream_epoch = 1;
        broken[1].timestamp.stream_epoch = 1;
        assert_eq!(
            super::AggregateFrameProvenance::new(
                broken,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::MixedContinuityEpoch)
        );
    }

    #[test]
    fn aggregate_rejects_non_increasing_or_inconsistent_timestamps() {
        let base = runtime_series(&[1, 2], &[100, 200], &[IlluminationProvenance::Unknown; 2]);
        let mut broken = base.clone();
        broken[1].timestamp.micros = 100;
        assert_eq!(
            super::AggregateFrameProvenance::new(
                broken,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::NonIncreasingTimestamp)
        );
        let mut broken = base;
        broken[1].timestamp.delta_micros = Some(99);
        assert_eq!(
            super::AggregateFrameProvenance::new(
                broken,
                super::ContributorSelection::ReducedOverAll
            ),
            Err(super::RuntimeProvenanceError::TimestampDeltaMismatch)
        );
    }

    #[test]
    fn aggregate_subtraction_requires_distinct_lit_and_ambient_evidence() {
        let contributors = runtime_series(
            &[1, 2],
            &[100, 200],
            &[
                IlluminationProvenance::ActiveIr,
                IlluminationProvenance::Ambient,
            ],
        );
        let aggregate = super::AggregateFrameProvenance::new(
            contributors.clone(),
            super::ContributorSelection::Subtracted {
                lit_index: 0,
                ambient_index: 1,
            },
        )
        .expect("valid subtraction");
        assert_eq!(aggregate.illumination(), IlluminationProvenance::ActiveIr);
        assert_eq!(
            super::AggregateFrameProvenance::new(
                contributors,
                super::ContributorSelection::Subtracted {
                    lit_index: 0,
                    ambient_index: 0,
                },
            ),
            Err(super::RuntimeProvenanceError::EqualSubtractionIndices)
        );
    }
}
