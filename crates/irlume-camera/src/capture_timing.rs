//! Numeric and categorical developer measurements. No camera data or error payloads.

/// Payload-free failure observed while establishing an IR startup rate window.
/// Available only with developer capture timing; never an authentication result.
#[cfg(feature = "capture-timing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateFillFailure {
    IoPermissionDenied,
    IoInvalidArgument,
    IoDevice,
    IoNoSpace,
    IoTimeout,
    IoOther,
    BufferTimestamp,
    BufferClock,
    BufferSource,
    BufferLayout,
    TimestampNonIncreasing,
    TimestampClock,
    TimestampSource,
    TimestampEpoch,
    Sequence,
    RateWindow,
    PrivacyBoundary,
    PrivacyEngaged,
    PrivacyReadPermissionDenied,
    PrivacyReadDevice,
    PrivacyReadTimeout,
    PrivacyReadBusy,
    PrivacyReadOther,
    LeaseBoundary,
    StreamState,
    ContinuityAlignment,
    ContinuityAccounting,
    IncompleteWindow,
    MissingStream,
    StoppedStream,
    Other,
}

#[cfg(feature = "capture-timing")]
impl RateFillFailure {
    fn classify(error: &std::io::Error) -> Self {
        use crate::frame_provenance::{
            DequeuedBufferError as Buffer, SequenceTrackerError, TimestampTrackerError as Timestamp,
        };
        if let Some(inner) = error.get_ref() {
            if let Some(error) = inner.downcast_ref::<Buffer>() {
                return match error {
                    Buffer::InvalidTimestamp { .. } => Self::BufferTimestamp,
                    Buffer::UnsupportedTimestampClock(_) => Self::BufferClock,
                    Buffer::UnsupportedTimestampSource(_) => Self::BufferSource,
                    _ => Self::BufferLayout,
                };
            }
            if let Some(error) = inner.downcast_ref::<Timestamp>() {
                return match error {
                    Timestamp::NonIncreasing { .. } => Self::TimestampNonIncreasing,
                    Timestamp::UntrustedClock(_) | Timestamp::ClockChanged { .. } => {
                        Self::TimestampClock
                    }
                    Timestamp::SourceChanged { .. } => Self::TimestampSource,
                    _ => Self::TimestampEpoch,
                };
            }
            if inner.is::<SequenceTrackerError>() {
                return Self::Sequence;
            }
            if inner.is::<crate::rate_gate::RateWindowError>() {
                return Self::RateWindow;
            }
            if let Some(refusal) = inner.downcast_ref::<crate::PrivacyBoundaryRefusal>() {
                return match refusal.cause {
                    None => Self::PrivacyBoundary,
                    Some(crate::PrivacyBoundaryCause::Engaged) => Self::PrivacyEngaged,
                    Some(crate::PrivacyBoundaryCause::ReadFailure { raw_errno, kind }) => {
                        match raw_errno {
                            Some(libc::EACCES | libc::EPERM) => Self::PrivacyReadPermissionDenied,
                            Some(libc::EIO | libc::ENODEV) => Self::PrivacyReadDevice,
                            Some(libc::ETIMEDOUT) => Self::PrivacyReadTimeout,
                            Some(libc::EBUSY) => Self::PrivacyReadBusy,
                            _ => match kind {
                                std::io::ErrorKind::PermissionDenied => {
                                    Self::PrivacyReadPermissionDenied
                                }
                                std::io::ErrorKind::TimedOut => Self::PrivacyReadTimeout,
                                _ => Self::PrivacyReadOther,
                            },
                        }
                    }
                };
            }
            if inner.is::<crate::lease::CameraLeaseError>() {
                return Self::LeaseBoundary;
            }
            if inner.is::<irlume_common::Error>() {
                return Self::StreamState;
            }
            if let Some(error) = inner.downcast_ref::<crate::CaptureEvidenceError>() {
                return match error {
                    crate::CaptureEvidenceError::ContinuityAlignment => Self::ContinuityAlignment,
                    crate::CaptureEvidenceError::ContinuityAccounting => Self::ContinuityAccounting,
                    crate::CaptureEvidenceError::IncompleteWindow => Self::IncompleteWindow,
                    crate::CaptureEvidenceError::MissingStream => Self::MissingStream,
                    crate::CaptureEvidenceError::StoppedStream => Self::StoppedStream,
                };
            }
        }
        match error.raw_os_error() {
            Some(libc::EACCES | libc::EPERM) => Self::IoPermissionDenied,
            Some(libc::EINVAL) => Self::IoInvalidArgument,
            Some(libc::EIO) => Self::IoDevice,
            Some(libc::ENOSPC) => Self::IoNoSpace,
            Some(libc::ETIMEDOUT) => Self::IoTimeout,
            _ => match error.kind() {
                std::io::ErrorKind::PermissionDenied => Self::IoPermissionDenied,
                std::io::ErrorKind::TimedOut => Self::IoTimeout,
                _ if error.get_ref().is_some() => Self::Other,
                _ => Self::IoOther,
            },
        }
    }

    /// Fixed diagnostic refusal label, without driver strings or numeric values.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IoPermissionDenied => "camera_rate_fill_io_permission_denied",
            Self::IoInvalidArgument => "camera_rate_fill_io_invalid_argument",
            Self::IoDevice => "camera_rate_fill_io_device",
            Self::IoNoSpace => "camera_rate_fill_io_no_space",
            Self::IoTimeout => "camera_rate_fill_io_timeout",
            Self::IoOther => "camera_rate_fill_io_other",
            Self::BufferTimestamp => "camera_rate_fill_buffer_timestamp",
            Self::BufferClock => "camera_rate_fill_buffer_clock",
            Self::BufferSource => "camera_rate_fill_buffer_source",
            Self::BufferLayout => "camera_rate_fill_buffer_layout",
            Self::TimestampNonIncreasing => "camera_rate_fill_timestamp_non_increasing",
            Self::TimestampClock => "camera_rate_fill_timestamp_clock",
            Self::TimestampSource => "camera_rate_fill_timestamp_source",
            Self::TimestampEpoch => "camera_rate_fill_timestamp_epoch",
            Self::Sequence => "camera_rate_fill_sequence",
            Self::RateWindow => "camera_rate_fill_rate_window",
            Self::PrivacyBoundary => "camera_rate_fill_privacy_boundary",
            Self::PrivacyEngaged => "camera_rate_fill_privacy_engaged",
            Self::PrivacyReadPermissionDenied => "camera_rate_fill_privacy_read_permission_denied",
            Self::PrivacyReadDevice => "camera_rate_fill_privacy_read_device",
            Self::PrivacyReadTimeout => "camera_rate_fill_privacy_read_timeout",
            Self::PrivacyReadBusy => "camera_rate_fill_privacy_read_busy",
            Self::PrivacyReadOther => "camera_rate_fill_privacy_read_other",
            Self::LeaseBoundary => "camera_rate_fill_lease_boundary",
            Self::StreamState => "camera_rate_fill_stream_state",
            Self::ContinuityAlignment => "camera_rate_fill_continuity_alignment",
            Self::ContinuityAccounting => "camera_rate_fill_continuity_accounting",
            Self::IncompleteWindow => "camera_rate_fill_incomplete_window",
            Self::MissingStream => "camera_rate_fill_missing_stream",
            Self::StoppedStream => "camera_rate_fill_stopped_stream",
            Self::Other => "camera_rate_fill_other",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Stage {
    Open,
    SessionSetup,
    Buffers,
    Metadata,
    Emitter,
    Warmup,
    RateFill,
    Frames,
    SessionRelease,
    ImageStop,
    MetadataStreamoff,
    MetadataBuffers,
    MetadataFormat,
    MetadataClose,
    EmitterRestore,
}

#[cfg(feature = "capture-timing")]
mod enabled {
    use super::{RateFillFailure, Stage};
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    const LABELS: [&str; 15] = [
        "open",
        "session_setup",
        "buffers",
        "metadata",
        "emitter",
        "warmup",
        "rate_fill",
        "frames",
        "session_release",
        "image_stop",
        "metadata_streamoff",
        "metadata_buffers",
        "metadata_format",
        "metadata_close",
        "emitter_restore",
    ];

    /// Per-operation fixed-size timing storage, enabled only for diagnostics.
    /// Null means unreached. Nested stages overlap and must not be summed.
    #[derive(Clone, Default, Debug)]
    pub struct CaptureTimings(
        Arc<Mutex<[Option<Duration>; 15]>>,
        Arc<Mutex<Option<RateFillFailure>>>,
    );

    impl CaptureTimings {
        /// First startup fill failure in this request, if one was observed.
        pub fn rate_fill_failure(&self) -> Option<RateFillFailure> {
            *self
                .1
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        pub(super) fn record_rate_fill_failure(&self, error: &std::io::Error) {
            self.1
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_or_insert_with(|| RateFillFailure::classify(error));
        }

        /// Snapshot only fixed labels and elapsed milliseconds, including errors.
        pub fn snapshot(&self) -> BTreeMap<&'static str, Option<u64>> {
            let values = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            LABELS
                .into_iter()
                .zip(
                    values
                        .iter()
                        .map(|v| v.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))),
                )
                .collect()
        }

        pub(super) fn start(&self, stage: Stage) -> Span {
            Span {
                timings: self.clone(),
                stage,
                start: Instant::now(),
            }
        }
    }

    pub(super) struct Span {
        timings: CaptureTimings,
        stage: Stage,
        start: Instant,
    }

    impl Drop for Span {
        fn drop(&mut self) {
            let elapsed = self.start.elapsed();
            let mut values = self
                .timings
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let slot = &mut values[self.stage as usize];
            *slot = Some(slot.unwrap_or_default().saturating_add(elapsed));
        }
    }
}

#[cfg(feature = "capture-timing")]
pub use enabled::CaptureTimings;

pub(crate) struct Span {
    #[cfg(feature = "capture-timing")]
    _inner: Option<enabled::Span>,
}

/// A timing-only handle carried by cleanup owners. Zero-sized in normal builds.
#[derive(Clone, Default)]
pub(crate) struct Recorder {
    #[cfg(feature = "capture-timing")]
    timings: Option<CaptureTimings>,
}

impl Recorder {
    pub(crate) fn from_control(control: &crate::CaptureControl) -> Self {
        #[cfg(feature = "capture-timing")]
        {
            Self {
                timings: control.capture_timings(),
            }
        }
        #[cfg(not(feature = "capture-timing"))]
        {
            let _ = control;
            Self {}
        }
    }

    pub(crate) fn stage(&self, stage: Stage) -> Span {
        #[cfg(feature = "capture-timing")]
        {
            Span {
                _inner: self.timings.as_ref().map(|t| t.start(stage)),
            }
        }
        #[cfg(not(feature = "capture-timing"))]
        {
            let _ = stage;
            Span {}
        }
    }
}

impl crate::CaptureControl {
    #[cfg(feature = "capture-timing")]
    pub(crate) fn record_rate_fill_failure(&self, error: &std::io::Error) {
        if let Some(timings) = &self.timings {
            timings.record_rate_fill_failure(error);
        }
    }

    pub(crate) fn stage(&self, stage: Stage) -> Span {
        #[cfg(feature = "capture-timing")]
        {
            Span {
                _inner: self.timings.as_ref().map(|t| t.start(stage)),
            }
        }
        #[cfg(not(feature = "capture-timing"))]
        {
            let _ = stage;
            Span {}
        }
    }
}

#[cfg(all(test, feature = "capture-timing"))]
mod tests {
    use super::*;
    use crate::CaptureControl;

    #[test]
    fn privacy_observation_detail_preserves_refusal_and_private_payloads() {
        use std::io::{Error, ErrorKind};
        let cases = [
            (Ok(Some(true)), "privacy_engaged"),
            (
                Err(Error::from_raw_os_error(libc::EACCES)),
                "privacy_read_permission_denied",
            ),
            (
                Err(Error::from_raw_os_error(libc::EPERM)),
                "privacy_read_permission_denied",
            ),
            (
                Err(Error::from_raw_os_error(libc::EIO)),
                "privacy_read_device",
            ),
            (
                Err(Error::from_raw_os_error(libc::ENODEV)),
                "privacy_read_device",
            ),
            (
                Err(Error::from_raw_os_error(libc::ETIMEDOUT)),
                "privacy_read_timeout",
            ),
            (
                Err(Error::new(ErrorKind::TimedOut, "private timeout payload")),
                "privacy_read_timeout",
            ),
            (
                Err(Error::from_raw_os_error(libc::EBUSY)),
                "privacy_read_busy",
            ),
            (
                Err(Error::other("private unsupported payload")),
                "privacy_read_other",
            ),
        ];
        for (observed, suffix) in cases {
            let error = crate::privacy_capture_boundary(observed).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Other);
            assert!(crate::is_privacy_boundary_error(&error));
            let prior_text = error.to_string();
            let timings = CaptureTimings::default();
            let control = crate::CaptureControl::with_progress(crate::no_progress())
                .with_capture_timings(Some(timings.clone()));
            control.record_rate_fill_failure(&error);
            control.record_rate_fill_failure(&Error::other("later private error"));
            assert_eq!(
                timings.rate_fill_failure().unwrap().as_str(),
                format!("camera_rate_fill_{suffix}")
            );
            assert_eq!(error.to_string(), prior_text);
            assert!(!timings
                .rate_fill_failure()
                .unwrap()
                .as_str()
                .contains("payload"));
        }
        assert!(crate::privacy_capture_boundary(Ok(Some(false))).is_ok());
        assert!(crate::privacy_capture_boundary(Ok(None)).is_ok());
    }

    #[test]
    fn rate_fill_diagnostic_erases_typed_and_transport_payloads() {
        use crate::frame_provenance::{
            DequeuedBufferError as B, SequenceTrackerError as S, TimestampClock as C,
            TimestampSource as T, TimestampTrackerError as E,
        };
        use std::io::Error;
        let cases = [
            (
                Error::new(std::io::ErrorKind::TimedOut, "private VIDIOC_DQBUF payload"),
                "io_timeout",
            ),
            (
                Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "private permission payload",
                ),
                "io_permission_denied",
            ),
            (
                Error::from_raw_os_error(libc::EACCES),
                "io_permission_denied",
            ),
            (
                Error::from_raw_os_error(libc::EPERM),
                "io_permission_denied",
            ),
            (
                Error::from_raw_os_error(libc::EINVAL),
                "io_invalid_argument",
            ),
            (Error::from_raw_os_error(libc::EIO), "io_device"),
            (Error::from_raw_os_error(libc::ENOSPC), "io_no_space"),
            (Error::from_raw_os_error(libc::ETIMEDOUT), "io_timeout"),
            (Error::from_raw_os_error(libc::EINTR), "io_other"),
            (
                Error::other(B::InvalidTimestamp {
                    seconds: 123456789,
                    microseconds: 1000000,
                }),
                "buffer_timestamp",
            ),
            (
                Error::other(B::UnsupportedTimestampClock(123456789)),
                "buffer_clock",
            ),
            (
                Error::other(B::UnsupportedTimestampSource(123456789)),
                "buffer_source",
            ),
            (
                Error::other(B::PayloadTooShort {
                    bytes_used: 1,
                    minimum: 123456789,
                }),
                "buffer_layout",
            ),
            (
                Error::other(E::NonIncreasing {
                    previous: 123456789,
                    current: 1,
                }),
                "timestamp_non_increasing",
            ),
            (
                Error::other(E::UntrustedClock(C::Unknown)),
                "timestamp_clock",
            ),
            (
                Error::other(E::ClockChanged {
                    expected: C::Monotonic,
                    actual: C::Copy,
                }),
                "timestamp_clock",
            ),
            (
                Error::other(E::SourceChanged {
                    expected: T::EndOfFrame,
                    actual: T::StartOfExposure,
                }),
                "timestamp_source",
            ),
            (Error::other(E::EpochFailed), "timestamp_epoch"),
            (Error::other(S::TrackerFailed), "sequence"),
            (
                Error::other(crate::rate_gate::RateWindowError::Overflow),
                "rate_window",
            ),
            (
                crate::privacy_boundary_error("private privacy payload 123456789".into()),
                "privacy_boundary",
            ),
            (
                Error::other(crate::lease::CameraLeaseError::InvalidEndpoint(
                    "private endpoint 123456789".into(),
                )),
                "lease_boundary",
            ),
            (
                Error::other(irlume_common::Error::Hardware(
                    "private stream payload 123456789".into(),
                )),
                "stream_state",
            ),
            (
                Error::other(crate::CaptureEvidenceError::StoppedStream),
                "stopped_stream",
            ),
            (Error::other("private driver payload 123456789"), "other"),
        ];
        for (error, suffix) in cases {
            let original = error.to_string();
            let timings = CaptureTimings::default();
            let control = CaptureControl::with_progress(crate::no_progress())
                .with_capture_timings(Some(timings.clone()));
            control.record_rate_fill_failure(&error);
            // Later errors cannot obscure the originating failure in a request.
            control.record_rate_fill_failure(&Error::other("later private payload"));
            assert_eq!(
                timings.rate_fill_failure().unwrap().as_str(),
                format!("camera_rate_fill_{suffix}")
            );
            assert_eq!(error.to_string(), original);
            let debug = format!("{timings:?}");
            assert!(!debug.contains("private") && !debug.contains("123456789"));
        }
    }

    #[test]
    fn timing_keeps_early_error_and_nested_cleanup_without_payloads() {
        let timings = CaptureTimings::default();
        let control = CaptureControl::with_progress(crate::no_progress())
            .with_capture_timings(Some(timings.clone()));
        let fail = |reject: bool| -> Result<(), &'static str> {
            let _setup = control.stage(Stage::SessionSetup);
            let _warmup = control.stage(Stage::Warmup);
            if reject {
                return Err("private driver payload");
            }
            Ok(())
        };
        assert_eq!(fail(true), Err("private driver payload"));
        let snapshot = timings.snapshot();
        assert!(snapshot["session_setup"].is_some());
        assert!(snapshot["warmup"].is_some());
        assert!(snapshot["frames"].is_none());
        assert_eq!(snapshot.len(), 15);
        assert!(!serde_json::to_string(&snapshot)
            .unwrap()
            .contains("private"));
    }

    #[test]
    fn timing_is_request_local_and_preserves_cancel_and_deadline() {
        let first = CaptureTimings::default();
        let second = CaptureTimings::default();
        let control = CaptureControl::new(crate::no_progress(), std::sync::Arc::new(|| true))
            .with_capture_timings(Some(first.clone()));
        {
            let _span = control.clone().stage(Stage::Open);
        }
        assert!(control.check().is_err());
        assert!(first.snapshot()["open"].is_some());
        assert!(second.snapshot().values().all(Option::is_none));
        let expired = CaptureControl::with_progress(crate::no_progress())
            .with_deadline(Some(std::time::Instant::now()))
            .with_capture_timings(Some(second));
        assert!(matches!(
            expired.check(),
            Err(irlume_common::Error::DeadlineExpired)
        ));
    }
}
