// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Pure clock-uncertainty checks, not device-suspend or qualification evidence.

#![cfg(test)]

use std::time::Duration;

/// Lower and upper bounds on this boot's BOOTTIME-minus-MONOTONIC offset.
#[derive(Clone, Copy, Debug)]
pub(super) struct SleepOffsetBounds {
    lower: Duration,
    upper: Duration,
}

impl SleepOffsetBounds {
    /// Reject an unordered pair rather than manufacturing a usable bound.
    pub(super) fn new(lower: Duration, upper: Duration) -> Option<Self> {
        (lower <= upper).then_some(Self { lower, upper })
    }
}

/// Exclude system-sleep growth above the existing one-millisecond budget.
///
/// This is not zero-sleep or device-runtime-suspend proof. Missing readings,
/// wide uncertainty and backward offsets cannot establish the exclusion.
pub(super) fn excludes_material_system_sleep(
    start: Option<SleepOffsetBounds>,
    end: Option<SleepOffsetBounds>,
) -> bool {
    let (Some(start), Some(end)) = (start, end) else {
        return false;
    };
    end.upper
        .checked_sub(start.lower)
        .is_some_and(|maximum_growth| maximum_growth <= crate::npu::RESUME_GRANULARITY)
}

/// Apply the existing positive system-suspend proof with conservative bounds.
pub(super) fn proves_system_sleep(
    start: Option<SleepOffsetBounds>,
    end: Option<SleepOffsetBounds>,
) -> bool {
    let (Some(start), Some(end)) = (start, end) else {
        return false;
    };
    super::gpu_groundwork_tests::suspend_is_proven(start.upper, end.lower)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn bounds(lower: Duration, upper: Duration) -> Option<SleepOffsetBounds> {
        SleepOffsetBounds::new(lower, upper)
    }

    fn point(value: Duration) -> Option<SleepOffsetBounds> {
        bounds(value, value)
    }

    #[test]
    fn unavailable_clock_bounds_never_supply_either_witness() {
        let known = point(Duration::from_secs(20));
        for (start, end) in [(None, known), (known, None), (None, None)] {
            assert!(!excludes_material_system_sleep(start, end));
            assert!(!proves_system_sleep(start, end));
        }
    }

    #[test]
    fn reversed_bounds_are_rejected_before_comparison() {
        assert!(bounds(Duration::from_millis(2), Duration::from_millis(1)).is_none());
        assert!(bounds(Duration::ZERO, Duration::ZERO).is_some());
    }

    #[test]
    fn existing_sleep_offset_is_not_a_new_system_event() {
        for offset in [Duration::ZERO, Duration::from_secs(20), Duration::MAX] {
            let sample = point(offset);
            assert!(excludes_material_system_sleep(sample, sample));
            assert!(!proves_system_sleep(sample, sample));
        }
    }

    #[test]
    fn runtime_exclusion_uses_start_lower_not_upper() {
        let start = bounds(Duration::from_millis(20), Duration::from_millis(30));
        let end = point(Duration::from_millis(31));
        assert!(!excludes_material_system_sleep(start, end));
    }

    #[test]
    fn runtime_exclusion_uses_end_upper_not_lower() {
        let start = point(Duration::from_millis(20));
        let end = bounds(
            Duration::from_millis(21),
            Duration::from_millis(21) + Duration::from_nanos(1),
        );
        assert!(!excludes_material_system_sleep(start, end));
    }

    #[test]
    fn delayed_reads_without_sleep_are_not_absence_proof() {
        let true_offset = Duration::from_secs(20);
        let start = bounds(
            true_offset - Duration::from_millis(3),
            true_offset + Duration::from_millis(3),
        );
        let end = bounds(
            true_offset - Duration::from_millis(5),
            true_offset + Duration::from_millis(5),
        );
        assert!(!excludes_material_system_sleep(start, end));
        assert!(!proves_system_sleep(start, end));
    }

    #[test]
    fn runtime_exclusion_is_inclusive_only_at_one_millisecond() {
        let offset = Duration::from_secs(20);
        let start = point(offset);
        for (growth, excluded) in [
            (Duration::ZERO, true),
            (crate::npu::RESUME_GRANULARITY, true),
            (
                crate::npu::RESUME_GRANULARITY + Duration::from_nanos(1),
                false,
            ),
        ] {
            assert_eq!(
                excludes_material_system_sleep(start, point(offset + growth)),
                excluded
            );
        }
    }

    #[test]
    fn backward_offset_does_not_saturate_into_absence_proof() {
        let start = point(Duration::from_millis(20));
        let end = point(Duration::from_millis(19));
        assert!(!excludes_material_system_sleep(start, end));
        assert!(!proves_system_sleep(start, end));
    }

    #[test]
    fn system_event_uses_baseline_upper_not_lower() {
        let start = bounds(Duration::from_millis(20), Duration::from_millis(25));
        let end = point(Duration::from_millis(22));
        assert!(!proves_system_sleep(start, end));
    }

    #[test]
    fn system_event_uses_later_lower_not_upper() {
        let start = point(Duration::from_millis(20));
        let end = bounds(Duration::from_millis(20), Duration::from_millis(25));
        assert!(!proves_system_sleep(start, end));
    }

    #[test]
    fn system_event_requires_strictly_more_than_one_millisecond() {
        let offset = Duration::from_secs(20);
        let start = point(offset);
        for (growth, proven) in [
            (Duration::ZERO, false),
            (crate::npu::RESUME_GRANULARITY, false),
            (
                crate::npu::RESUME_GRANULARITY + Duration::from_nanos(1),
                true,
            ),
        ] {
            assert_eq!(proves_system_sleep(start, point(offset + growth)), proven);
        }
    }
}
