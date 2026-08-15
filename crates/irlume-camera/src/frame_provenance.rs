// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Strict runtime evidence bound to one immutable camera lease reference.

use crate::contracts::{CameraGeneration, CameraInstanceId, StreamRole};

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

    /// Observe one raw sequence value.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceTrackerError`] after an unrepresentable counter state.
    pub fn observe(&mut self, raw: u32) -> Result<SequenceObservation, SequenceTrackerError> {
        if self.failed {
            return Err(SequenceTrackerError::TrackerFailed);
        }
        let (gap, transition_discontinuity) = self.previous.map_or((0, false), |previous| {
            let delta = raw.wrapping_sub(previous);
            if (1..(1_u32 << 31)).contains(&delta) {
                (delta - 1, false)
            } else {
                (0, true)
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
    /// Returns [`DequeuedBufferError`] when the driver reports corruption,
    /// malformed timestamp semantics, or a payload outside the mmap boundary.
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
        if metadata.flags.contains(v4l::buffer::Flags::ERROR) {
            return Err(DequeuedBufferError::DriverReportedCorruption);
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

#[cfg(test)]
mod tests {
    use super::{
        DequeuedBufferError, DequeuedBufferFacts, PayloadLayout, SequenceTracker,
        SequenceTrackerError, TimestampClock, TimestampSource,
    };

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
    fn dequeue_rejects_driver_error_status() {
        let metadata = v4l::buffer::Metadata {
            bytesused: 4,
            flags: v4l::buffer::Flags::ERROR,
            ..v4l::buffer::Metadata::default()
        };

        assert_eq!(
            DequeuedBufferFacts::from_v4l(&metadata, 4),
            Err(DequeuedBufferError::DriverReportedCorruption)
        );
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
}
