// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::time::{Duration, Instant};

/// One presence window, retained through the daemon's response admission.
/// Zero milliseconds preserves the explicit legacy one-shot configuration.
#[derive(Clone, Copy)]
pub struct AuthenticationWindow {
    pub(crate) deadline: Instant,
    pub(crate) milliseconds: u64,
}

impl AuthenticationWindow {
    pub(crate) fn origin(self) -> Instant {
        self.deadline - Duration::from_millis(self.milliseconds)
    }

    pub(crate) fn clipped_to(self, allowance: Self) -> Self {
        if self.milliseconds == 0
            || allowance.milliseconds == 0
            || allowance.deadline >= self.deadline
        {
            return self;
        }
        Self {
            deadline: allowance.deadline,
            milliseconds: allowance.milliseconds.min(self.milliseconds),
        }
    }
    /// Start the configured window for a PAM service.
    pub fn for_service(service: Option<&str>) -> Self {
        Self::new(super::grace_window_ms(service))
    }

    pub(crate) fn new(milliseconds: u64) -> Self {
        Self::from_started(Instant::now(), milliseconds)
    }

    pub(crate) fn from_started(started: Instant, milliseconds: u64) -> Self {
        Self {
            deadline: started + Duration::from_millis(milliseconds),
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
        // An NPU admission belongs to this request only (ADR-0022 §2).
        self.engine.npu_probe = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_allowance_preserves_original_origin_and_never_widens_a_cap() {
        let started = Instant::now();
        for (cap, allowance, expected) in [(500, 2000, 500), (2000, 500, 500), (500, 500, 500)] {
            let original = AuthenticationWindow::from_started(started, cap);
            let selected = AuthenticationWindow::from_started(started, allowance);
            let clipped = original.clipped_to(selected);
            assert_eq!(clipped.origin(), started);
            assert_eq!(clipped.milliseconds, expected);
            assert_eq!(
                clipped.capture_deadline(),
                Some(started + Duration::from_millis(expected))
            );
        }
    }

    #[test]
    fn selected_zero_cannot_remove_a_finite_cap_and_original_zero_stays_one_shot() {
        let started = Instant::now();
        let finite = AuthenticationWindow::from_started(started, 500);
        let one_shot = AuthenticationWindow::from_started(started, 0);
        assert_eq!(
            finite.clipped_to(one_shot).capture_deadline(),
            finite.capture_deadline()
        );
        assert_eq!(one_shot.clipped_to(finite).capture_deadline(), None);
        assert_eq!(one_shot.clipped_to(finite).origin(), started);
    }

    #[test]
    fn clipped_expired_allowance_does_not_restart_the_clock() {
        let started = Instant::now() - Duration::from_secs(1);
        let original = AuthenticationWindow::from_started(started, 2000);
        original.check().unwrap();
        let clipped = original.clipped_to(AuthenticationWindow::from_started(started, 100));
        assert!(matches!(
            clipped.check(),
            Err(irlume_common::Error::DeadlineExpired)
        ));
    }
}
