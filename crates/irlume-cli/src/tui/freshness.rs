// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Observation age and bounded refresh generations, independent of I/O and UI.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub(super) enum Source {
    Live,
    Health,
    Preferences,
    Wallet,
    Recovery,
    Profiles,
    Cameras,
    CameraPrivacy,
    Qualification,
    Machine,
    FingerprintReader,
    Fingerprint,
    Apps,
}

impl Source {
    pub const ALL: [Self; 13] = [
        Self::Live,
        Self::Health,
        Self::Preferences,
        Self::Wallet,
        Self::Recovery,
        Self::Profiles,
        Self::Cameras,
        Self::CameraPrivacy,
        Self::Qualification,
        Self::Machine,
        Self::FingerprintReader,
        Self::Fingerprint,
        Self::Apps,
    ];

    pub fn max_age(self) -> Duration {
        Duration::from_secs(match self {
            Self::Live => 4,
            Self::Health
            | Self::Preferences
            | Self::Wallet
            | Self::Recovery
            | Self::CameraPrivacy => 20,
            Self::Profiles => 60,
            Self::Machine | Self::FingerprintReader | Self::Fingerprint => 30,
            Self::Apps => 10,
            // Classification is bound to a still-current passive inventory
            // epoch; qualification is an explicitly historical observation.
            Self::Cameras | Self::Qualification => u64::MAX,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Worker {
    Live,
    Light,
    Profiles,
    Cameras,
    Qualification,
    Machine,
    Apps,
}

#[derive(Default)]
pub(super) struct Freshness {
    observations: [Observation; 13],
    cycles: [RefreshCycle; 7],
}

impl Freshness {
    pub fn observation(&self, source: Source) -> Observation {
        self.observations[source as usize]
    }
    pub fn observation_mut(&mut self, source: Source) -> &mut Observation {
        &mut self.observations[source as usize]
    }
    pub fn cycle(&self, worker: Worker) -> RefreshCycle {
        self.cycles[worker as usize]
    }
    pub fn cycle_mut(&mut self, worker: Worker) -> &mut RefreshCycle {
        &mut self.cycles[worker as usize]
    }
    pub fn usable(&self, source: Source, now: Instant) -> bool {
        self.observation(source).usable(now, source.max_age())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Observation {
    pub last_success: Option<Instant>,
    unavailable: bool,
}

impl Observation {
    pub fn record(&mut self, success: bool, at: Instant) {
        self.unavailable = !success;
        if success {
            self.last_success = Some(at);
        }
    }

    pub fn invalidate(&mut self) {
        self.unavailable = true;
    }

    pub fn usable(self, now: Instant, max_age: Duration) -> bool {
        !self.unavailable
            && self
                .last_success
                .is_some_and(|at| now.saturating_duration_since(at) <= max_age)
    }

    pub fn describe(self, now: Instant, max_age: Duration, loading: bool) -> String {
        match (self.last_success, self.usable(now, max_age)) {
            (Some(at), true) => format!(
                "checked {}s ago",
                now.saturating_duration_since(at).as_secs()
            ),
            (Some(at), false) => format!(
                "unavailable; last successful check {}s ago{}",
                now.saturating_duration_since(at).as_secs(),
                if loading { "; updating" } else { "" }
            ),
            (None, _) if loading => "checking…".into(),
            (None, _) => "unavailable; not observed".into(),
        }
    }
}

/// One receiver at a time. Only explicit invalidation queues a replacement;
/// an ordinary timer tick can never starve a slow worker by changing its epoch.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct RefreshCycle {
    generation: u64,
    running: Option<u64>,
    pending: bool,
    pub completed: Option<Instant>,
}

impl RefreshCycle {
    pub fn begin(&mut self) -> bool {
        if self.running.is_some() {
            return false;
        }
        self.running = Some(self.generation);
        self.pending = false;
        true
    }

    pub fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.pending = true;
    }

    pub fn finish(&mut self, now: Instant) -> bool {
        self.completed = Some(now);
        // Synthetic receiver fixtures can omit begin; production cannot.
        let observed = self.running.take().unwrap_or(self.generation);
        let current = observed == self.generation;
        if !current {
            self.pending = true;
        }
        current
    }

    pub fn due(self, now: Instant, interval: Duration) -> bool {
        self.running.is_none()
            && (self.pending
                || self
                    .completed
                    .is_none_or(|at| now.saturating_duration_since(at) >= interval))
    }

    pub fn pending(self) -> bool {
        self.pending && self.running.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_observation_expires_even_without_new_input() {
        let now = Instant::now();
        let mut state = Observation::default();
        assert!(!state.usable(now, Duration::from_secs(4)));
        state.record(true, now);
        assert!(state.usable(now + Duration::from_secs(3), Duration::from_secs(4)));
        assert!(!state.usable(now + Duration::from_secs(5), Duration::from_secs(4)));
        assert!(state
            .describe(now + Duration::from_secs(5), Duration::from_secs(4), false)
            .contains("unavailable"));
    }

    #[test]
    fn failure_does_not_refresh_success_age_and_recovery_is_explicit() {
        let now = Instant::now();
        let mut state = Observation::default();
        state.record(true, now);
        state.record(false, now + Duration::from_secs(1));
        assert_eq!(state.last_success, Some(now));
        assert!(!state.usable(now + Duration::from_secs(2), Duration::from_secs(30)));
        state.record(true, now + Duration::from_secs(3));
        assert!(state.usable(now + Duration::from_secs(3), Duration::from_secs(30)));
    }

    #[test]
    fn invalidated_worker_cannot_publish_and_gets_one_replacement() {
        let now = Instant::now();
        let mut cycle = RefreshCycle::default();
        assert!(cycle.begin());
        cycle.invalidate();
        cycle.invalidate();
        assert!(!cycle.begin());
        assert!(!cycle.finish(now));
        assert!(cycle.pending());
        assert!(cycle.begin());
        assert!(!cycle.pending());
        assert!(!cycle.begin());
        assert!(cycle.finish(now));
        assert!(!cycle.pending());
    }

    #[test]
    fn timer_checks_do_not_invalidate_or_duplicate_slow_work() {
        let now = Instant::now();
        let mut cycle = RefreshCycle::default();
        assert!(cycle.begin());
        for seconds in 0..60 {
            assert!(!cycle.due(now + Duration::from_secs(seconds), Duration::from_secs(1)));
            assert!(!cycle.begin());
        }
        assert!(cycle.finish(now + Duration::from_secs(60)));
        assert!(!cycle.due(now + Duration::from_secs(89), Duration::from_secs(30)));
        assert!(cycle.due(now + Duration::from_secs(90), Duration::from_secs(30)));
    }
}
