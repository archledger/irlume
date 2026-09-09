use std::time::{Duration, Instant};

/// One presence window, retained through the daemon's response admission.
/// Zero milliseconds preserves the explicit legacy one-shot configuration.
#[derive(Clone, Copy)]
pub struct AuthenticationWindow {
    pub(crate) deadline: Instant,
    pub(crate) milliseconds: u64,
}

impl AuthenticationWindow {
    /// Start the configured window for a PAM service.
    pub fn for_service(service: Option<&str>) -> Self {
        Self::new(super::grace_window_ms(service))
    }

    pub(crate) fn new(milliseconds: u64) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_millis(milliseconds),
            milliseconds,
        }
    }

    pub(crate) fn capture_deadline(self) -> Option<Instant> {
        (self.milliseconds != 0).then_some(self.deadline)
    }

    /// Remaining response-write budget, or None for legacy one-shot mode.
    pub fn remaining(self) -> Option<Duration> {
        self.capture_deadline()
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// Check response eligibility; this cannot interrupt a blocking system call.
    ///
    /// # Errors
    /// Returns [`irlume_common::Error::DeadlineExpired`] once the window expires.
    pub fn check(self) -> irlume_common::Result<()> {
        if self
            .capture_deadline()
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Err(irlume_common::Error::DeadlineExpired)
        } else {
            Ok(())
        }
    }
}

/// Restore request-local state on early return and unwind. The reusable engine's
/// enrollment/diagnostic paths must never inherit an authentication deadline.
pub(super) struct Scope<'a> {
    pub(super) engine: &'a mut super::Engine,
    pub(super) previous: Option<Instant>,
}

impl Drop for Scope<'_> {
    fn drop(&mut self) {
        self.engine.authentication_deadline = self.previous;
    }
}
