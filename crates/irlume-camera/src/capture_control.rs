use crate::Progress;
use irlume_common::{Error, Result};
use std::sync::Arc;

/// Watchdog reporting and cooperative cancellation for one camera request.
///
/// Cancellation is checked at returned driver-call boundaries. It never kills
/// a thread or skips the stream/control owners' ordinary cleanup.
#[derive(Clone)]
pub struct CaptureControl {
    pub(crate) progress: Progress,
    cancelled: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    deadline: Option<std::time::Instant>,
    #[cfg(feature = "capture-timing")]
    pub(crate) timings: Option<crate::CaptureTimings>,
}

impl CaptureControl {
    /// Keep the existing watchdog behavior with cancellation disabled.
    pub fn with_progress(progress: Progress) -> Self {
        Self {
            progress,
            cancelled: None,
            deadline: None,
            #[cfg(feature = "capture-timing")]
            timings: None,
        }
    }

    /// Observe cancellation of this request, separately from scheduler yield.
    pub fn new(progress: Progress, cancelled: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        Self {
            progress,
            cancelled: Some(cancelled),
            deadline: None,
            #[cfg(feature = "capture-timing")]
            timings: None,
        }
    }

    /// Attach request-local developer timing storage. Does not change control.
    #[cfg(feature = "capture-timing")]
    pub fn with_capture_timings(mut self, timings: Option<crate::CaptureTimings>) -> Self {
        self.timings = timings;
        self
    }

    /// Clone the optional developer timing handle for a bounded child operation.
    #[cfg(feature = "capture-timing")]
    pub fn capture_timings(&self) -> Option<crate::CaptureTimings> {
        self.timings.clone()
    }

    /// Apply the authentication window to this capture.
    pub fn with_deadline(mut self, deadline: Option<std::time::Instant>) -> Self {
        self.deadline = deadline;
        self
    }

    /// Check whether the request still wants camera work.
    ///
    /// # Errors
    /// Returns [`Error::Preempted`] on cancellation or [`Error::DeadlineExpired`]
    /// when the authentication window has ended.
    pub fn check(&self) -> Result<()> {
        self.check_io().map_err(|error| {
            if is_expired(&error) {
                Error::DeadlineExpired
            } else {
                Error::Preempted("camera capture cancelled".into())
            }
        })
    }

    pub(crate) fn check_io(&self) -> std::io::Result<()> {
        if self.cancelled.as_ref().is_some_and(|signal| signal()) {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                CaptureCancelled,
            ))
        } else if self
            .deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                CaptureExpired,
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct CaptureCancelled;

impl std::fmt::Display for CaptureCancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("camera capture cancelled")
    }
}

impl std::error::Error for CaptureCancelled {}

pub(crate) fn is_cancelled(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<CaptureCancelled>())
}

#[derive(Debug)]
struct CaptureExpired;

impl std::fmt::Display for CaptureExpired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("authentication window expired")
    }
}

impl std::error::Error for CaptureExpired {}

pub(crate) fn is_expired(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<CaptureExpired>())
}
