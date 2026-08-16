// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Exact delivered-rate enforcement for a single logical capture stream.
//!
//! The gate is deliberately independent of the continuity trackers in
//! [`crate::frame_provenance`]: it owns its own `last_successful_timestamp_micros`
//! baseline so a corrupt dequeue (which advances the continuity trackers but
//! delivers no frame) does not advance the rate baseline. The next successful
//! delta therefore spans the corrupt frame, which is the conservative
//! (fail-closed) direction.
//!
//! All comparisons are exact integer arithmetic. No `f32`/`f64` appears in any
//! gate path: a floating-point comparison would let a boundary value round the
//! wrong way and admit a stream that is actually below floor.

use crate::contracts::StreamRole;
use crate::frame_interval::FrameInterval;

/// Number of positive deltas the window holds and requires before it can judge.
///
/// Thirty deltas is approximately two seconds at the binding IR floor (15 fps)
/// and is above the empirically minimal 25 measured in the concurrent probe;
/// five/ten-delta enforcement was measured invalid (see the slice-8 design).
pub(crate) const RATE_WINDOW_CAPACITY: usize = 30;

/// Whole-percent tolerance applied to the floor. 98% is the smallest
/// whole-percent floor below the measured 14.714 Hz (98.093% of 15 fps) and
/// rejects 10 Hz.
pub(crate) const DEFAULT_TOLERANCE_PERCENT: u32 = 98;

/// Exact IR floor: 15 frames per second.
pub(crate) const IR_FLOOR_NUM: u32 = 15;
pub(crate) const IR_FLOOR_DEN: u32 = 1;

/// Exact RGB floor: 15/2 = 7.5 frames per second.
pub(crate) const RGB_FLOOR_NUM: u32 = 15;
pub(crate) const RGB_FLOOR_DEN: u32 = 2;

/// Why a successful dequeue could not advance the rate window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RateWindowError {
    /// The timestamp did not strictly increase past the last successful one.
    NonIncreasing { previous: i64, current: i64 },
    /// Checked subtraction overflowed (a negative baseline against a positive
    /// current, or vice versa).
    Overflow,
}

impl std::fmt::Display for RateWindowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonIncreasing { previous, current } => write!(
                f,
                "rate timestamp did not increase: previous {previous}us, current {current}us"
            ),
            Self::Overflow => f.write_str("rate timestamp delta overflow"),
        }
    }
}

impl std::error::Error for RateWindowError {}

const fn gcd_u64(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

/// A fixed-capacity ring of exactly [`RATE_WINDOW_CAPACITY`] positive deltas.
///
/// Allocation-free after construction: the ring is a stack array. The window
/// owns its own `last_successful_timestamp_micros` baseline and never reads
/// [`crate::frame_provenance::TimestampObservation::delta_micros`], so a corrupt
/// dequeue cannot advance the rate baseline.
#[derive(Clone, Debug)]
pub(crate) struct RateWindow {
    deltas: [u64; RATE_WINDOW_CAPACITY],
    len: usize,
    head: usize,
    last_successful_timestamp_micros: Option<i64>,
}

impl RateWindow {
    pub(crate) const fn new() -> Self {
        Self {
            deltas: [0; RATE_WINDOW_CAPACITY],
            len: 0,
            head: 0,
            last_successful_timestamp_micros: None,
        }
    }

    /// Record a successful dequeue timestamp.
    ///
    /// The first successful timestamp only seeds the baseline and contributes no
    /// delta. Every later one appends `current - last_successful` as a positive
    /// `u64` delta and advances the baseline.
    ///
    /// # Errors
    ///
    /// Returns [`RateWindowError::NonIncreasing`] when the timestamp does not
    /// strictly increase, and [`RateWindowError::Overflow`] when the checked
    /// subtraction overflows. Both fail closed.
    pub(crate) fn observe_success(&mut self, timestamp_micros: i64) -> Result<(), RateWindowError> {
        if let Some(last) = self.last_successful_timestamp_micros {
            let delta = timestamp_micros
                .checked_sub(last)
                .ok_or(RateWindowError::Overflow)?;
            if delta <= 0 {
                return Err(RateWindowError::NonIncreasing {
                    previous: last,
                    current: timestamp_micros,
                });
            }
            self.push(delta as u64);
        }
        self.last_successful_timestamp_micros = Some(timestamp_micros);
        Ok(())
    }

    fn push(&mut self, delta: u64) {
        if self.len < RATE_WINDOW_CAPACITY {
            self.deltas[(self.head + self.len) % RATE_WINDOW_CAPACITY] = delta;
            self.len += 1;
        } else {
            self.deltas[self.head] = delta;
            self.head = (self.head + 1) % RATE_WINDOW_CAPACITY;
        }
    }

    /// Clear the ring and baseline for recovery. The first post-recovery
    /// successful timestamp seeds the empty window and contributes no
    /// cross-epoch delta.
    pub(crate) fn reset(&mut self) {
        self.deltas = [0; RATE_WINDOW_CAPACITY];
        self.len = 0;
        self.head = 0;
        self.last_successful_timestamp_micros = None;
    }

    /// Number of deltas currently held (0..=[`RATE_WINDOW_CAPACITY`]).
    #[must_use]
    pub(crate) const fn count(&self) -> usize {
        self.len
    }

    /// Whether the window holds the full [`RATE_WINDOW_CAPACITY`] deltas.
    #[must_use]
    pub(crate) const fn ready(&self) -> bool {
        self.len == RATE_WINDOW_CAPACITY
    }

    /// Sum of the held deltas in microseconds.
    #[must_use]
    pub(crate) fn span_us(&self) -> u64 {
        (0..self.len)
            .map(|i| self.deltas[(self.head + i) % RATE_WINDOW_CAPACITY])
            .sum()
    }

    /// Exact delivered rate as a reduced `(numerator, denominator)` fraction in
    /// frames per second: `count * 1_000_000 / span_us`, reduced for reporting.
    #[must_use]
    pub(crate) fn delivered_rate(&self) -> (u64, u64) {
        let numerator = self.len as u64 * 1_000_000;
        let denominator = self.span_us();
        if denominator == 0 {
            return (0, 1);
        }
        let divisor = gcd_u64(numerator, denominator);
        (numerator / divisor, denominator / divisor)
    }

    /// Exact 98%-floor comparison using checked `u128` arithmetic only:
    /// `count * 1_000_000 * floor_den * 100 >= span_us * floor_num * tolerance`.
    #[must_use]
    pub(crate) fn meets_floor(
        &self,
        floor_num: u32,
        floor_den: u32,
        tolerance_percent: u32,
    ) -> bool {
        let count = self.len as u128;
        let span = self.span_us() as u128;
        let lhs = count * 1_000_000 * u128::from(floor_den) * 100;
        let rhs = span * u128::from(floor_num) * u128::from(tolerance_percent);
        lhs >= rhs
    }
}

/// Immutable delivered-rate policy for one stream role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RatePolicy {
    floor_num: u32,
    floor_den: u32,
    tolerance_percent: u32,
    window: usize,
}

impl RatePolicy {
    pub(crate) const fn new(
        floor_num: u32,
        floor_den: u32,
        tolerance_percent: u32,
        window: usize,
    ) -> Self {
        Self {
            floor_num,
            floor_den,
            tolerance_percent,
            window,
        }
    }

    #[must_use]
    pub(crate) const fn floor_num(&self) -> u32 {
        self.floor_num
    }

    #[must_use]
    pub(crate) const fn floor_den(&self) -> u32 {
        self.floor_den
    }

    #[must_use]
    pub(crate) const fn tolerance_percent(&self) -> u32 {
        self.tolerance_percent
    }

    #[must_use]
    #[cfg_attr(not(test), expect(dead_code, reason = "used by tests"))]
    pub(crate) const fn window(&self) -> usize {
        self.window
    }
}

/// Immutable per-stream rate configuration threaded through every production
/// [`crate::TrackedStream`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StreamRateConfig {
    role: StreamRole,
    policy: RatePolicy,
    requested: FrameInterval,
    accepted: FrameInterval,
}

impl StreamRateConfig {
    pub(crate) const fn new(
        role: StreamRole,
        requested: FrameInterval,
        accepted: FrameInterval,
    ) -> Self {
        let (floor_num, floor_den) = match role {
            StreamRole::Rgb => (RGB_FLOOR_NUM, RGB_FLOOR_DEN),
            StreamRole::Ir => (IR_FLOOR_NUM, IR_FLOOR_DEN),
        };
        Self {
            role,
            policy: RatePolicy::new(
                floor_num,
                floor_den,
                DEFAULT_TOLERANCE_PERCENT,
                RATE_WINDOW_CAPACITY,
            ),
            requested,
            accepted,
        }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> StreamRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn policy(&self) -> RatePolicy {
        self.policy
    }

    #[must_use]
    pub(crate) const fn requested(&self) -> FrameInterval {
        self.requested
    }

    #[must_use]
    pub(crate) const fn accepted(&self) -> FrameInterval {
        self.accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ir_config() -> StreamRateConfig {
        StreamRateConfig::new(
            StreamRole::Ir,
            FrameInterval::new(1, 15).expect("valid requested interval"),
            FrameInterval::new(1, 15).expect("valid accepted interval"),
        )
    }

    #[test]
    fn first_successful_timestamp_seeds_without_a_delta() {
        let mut window = RateWindow::new();
        window.observe_success(1_000_000).expect("first seed");
        assert_eq!(window.count(), 0);
        assert!(!window.ready());
        assert_eq!(window.span_us(), 0);
    }

    #[test]
    fn positive_deltas_accumulate_to_capacity() {
        let mut window = RateWindow::new();
        for i in 0..=RATE_WINDOW_CAPACITY {
            window
                .observe_success(i as i64 * 1_000_000)
                .expect("monotonic");
        }
        assert_eq!(window.count(), RATE_WINDOW_CAPACITY);
        assert!(window.ready());
        assert_eq!(window.span_us(), RATE_WINDOW_CAPACITY as u64 * 1_000_000);
    }

    #[test]
    fn non_increasing_timestamp_fails_closed() {
        let mut window = RateWindow::new();
        window.observe_success(1_000_000).expect("baseline");
        assert_eq!(
            window.observe_success(1_000_000),
            Err(RateWindowError::NonIncreasing {
                previous: 1_000_000,
                current: 1_000_000,
            })
        );
        assert_eq!(
            window.observe_success(999_999),
            Err(RateWindowError::NonIncreasing {
                previous: 1_000_000,
                current: 999_999,
            })
        );
    }

    #[test]
    fn overflow_fails_closed() {
        let mut window = RateWindow::new();
        window.observe_success(i64::MIN).expect("negative baseline");
        assert_eq!(
            window.observe_success(i64::MAX),
            Err(RateWindowError::Overflow)
        );
    }

    #[test]
    fn reset_clears_ring_and_baseline() {
        let mut window = RateWindow::new();
        for i in 0..=RATE_WINDOW_CAPACITY {
            window
                .observe_success(i as i64 * 1_000_000)
                .expect("monotonic");
        }
        assert!(window.ready());
        window.reset();
        assert_eq!(window.count(), 0);
        assert!(!window.ready());
        // First post-reset timestamp seeds, no cross-epoch delta.
        window.observe_success(5_000_000).expect("post-reset seed");
        assert_eq!(window.count(), 0);
    }

    #[test]
    fn ring_stays_exactly_thirty_and_displaces_oldest() {
        let mut window = RateWindow::new();
        // Deltas 1..=31 us: seed at 0, then cumulative timestamps.
        let mut t = 0_i64;
        window.observe_success(t).expect("seed");
        for delta in 1..=31_u64 {
            t += delta as i64;
            window.observe_success(t).expect("monotonic");
        }
        assert_eq!(window.count(), RATE_WINDOW_CAPACITY);
        // The 31 deltas were 1..=31; the oldest (1) was displaced, so the ring
        // holds 2..=31, whose sum is (31*32/2) - 1 = 495.
        assert_eq!(window.span_us(), 495);
    }

    #[test]
    fn exact_ir_boundary_passes_and_one_microsecond_fails() {
        // count 30, floor 15/1, tolerance 98: max passing span is
        // floor(30 * 1_000_000 * 100 / (15 * 98)) = 2_040_816 us.
        let mut window = RateWindow::new();
        // Seed + 30 deltas of equal size summing to the boundary span.
        let delta = 2_040_816 / RATE_WINDOW_CAPACITY as u64;
        let mut t = 0_i64;
        window.observe_success(t).expect("seed");
        for _ in 0..RATE_WINDOW_CAPACITY {
            t += delta as i64;
            window.observe_success(t).expect("monotonic");
        }
        // Adjust the last delta so the span is exactly the boundary.
        // Rebuild precisely instead of approximating.
        let mut exact = RateWindow::new();
        let mut t = 0_i64;
        exact.observe_success(t).expect("seed");
        for i in 0..RATE_WINDOW_CAPACITY {
            let step = if i == RATE_WINDOW_CAPACITY - 1 {
                2_040_816 - (RATE_WINDOW_CAPACITY as u64 - 1) * delta
            } else {
                delta
            };
            t += step as i64;
            exact.observe_success(t).expect("monotonic");
        }
        assert_eq!(exact.span_us(), 2_040_816);
        assert!(exact.meets_floor(IR_FLOOR_NUM, IR_FLOOR_DEN, DEFAULT_TOLERANCE_PERCENT));

        // +1 us fails.
        let mut over = RateWindow::new();
        let mut t = 0_i64;
        over.observe_success(t).expect("seed");
        for i in 0..RATE_WINDOW_CAPACITY {
            let step = if i == RATE_WINDOW_CAPACITY - 1 {
                2_040_817 - (RATE_WINDOW_CAPACITY as u64 - 1) * delta
            } else {
                delta
            };
            t += step as i64;
            over.observe_success(t).expect("monotonic");
        }
        assert_eq!(over.span_us(), 2_040_817);
        assert!(!over.meets_floor(IR_FLOOR_NUM, IR_FLOOR_DEN, DEFAULT_TOLERANCE_PERCENT));
    }

    #[test]
    fn ten_hz_ir_fails_and_rgb_seven_point_five_passes() {
        // 10 Hz IR: 30 deltas of 100_000 us = 3_000_000 us span.
        let mut ir = RateWindow::new();
        let mut t = 0_i64;
        ir.observe_success(t).expect("seed");
        for _ in 0..RATE_WINDOW_CAPACITY {
            t += 100_000;
            ir.observe_success(t).expect("monotonic");
        }
        assert_eq!(ir.span_us(), 3_000_000);
        assert!(!ir.meets_floor(IR_FLOOR_NUM, IR_FLOOR_DEN, DEFAULT_TOLERANCE_PERCENT));

        // RGB 7.5 fps exact: 30 deltas of 133_333.33... -> use exact 15/2 floor.
        // 7.5 fps = 1/7.5 s = 133_333.33 us per frame; 30 deltas = 4_000_000 us.
        let mut rgb = RateWindow::new();
        let mut t = 0_i64;
        rgb.observe_success(t).expect("seed");
        for _ in 0..RATE_WINDOW_CAPACITY {
            t += 133_333;
            rgb.observe_success(t).expect("monotonic");
        }
        // 30 * 133_333 = 3_999_990 us, slightly faster than 7.5 fps -> passes.
        assert!(rgb.meets_floor(RGB_FLOOR_NUM, RGB_FLOOR_DEN, DEFAULT_TOLERANCE_PERCENT));
    }

    #[test]
    fn delivered_rate_is_reduced() {
        let mut window = RateWindow::new();
        let mut t = 0_i64;
        window.observe_success(t).expect("seed");
        for _ in 0..RATE_WINDOW_CAPACITY {
            t += 100_000;
            window.observe_success(t).expect("monotonic");
        }
        // 30 * 1_000_000 / 3_000_000 = 10 fps, reduced to 10/1.
        assert_eq!(window.delivered_rate(), (10, 1));
    }

    #[test]
    fn config_derives_exact_floor_from_role() {
        let ir = ir_config();
        assert_eq!(ir.role(), StreamRole::Ir);
        assert_eq!(ir.policy().floor_num(), IR_FLOOR_NUM);
        assert_eq!(ir.policy().floor_den(), IR_FLOOR_DEN);
        assert_eq!(ir.policy().tolerance_percent(), DEFAULT_TOLERANCE_PERCENT);
        assert_eq!(ir.policy().window(), RATE_WINDOW_CAPACITY);

        let rgb = StreamRateConfig::new(
            StreamRole::Rgb,
            FrameInterval::new(1, 7).expect("valid"),
            FrameInterval::new(1, 7).expect("valid"),
        );
        assert_eq!(rgb.policy().floor_num(), RGB_FLOOR_NUM);
        assert_eq!(rgb.policy().floor_den(), RGB_FLOOR_DEN);
    }
}
