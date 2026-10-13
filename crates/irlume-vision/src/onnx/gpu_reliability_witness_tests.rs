// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Pure validation of supplied runtime-PM observations, not hardware evidence.

#![cfg(test)]

use super::gpu_reliability_clock_tests::{excludes_material_system_sleep, SleepOffsetBounds};
use std::time::Duration;

// Linux v7.2.9 drivers/base/power/runtime.c stores u64 nanoseconds and
// sysfs.c floors each total by NSEC_PER_MSEC. Larger totals are not its output.
const MAX_RUNTIME_MS: u64 = u64::MAX / 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DeviceBinding<'a> {
    pub(super) canonical_device: &'a str,
    pub(super) pci: &'a str,
    pub(super) vendor: &'a str,
    pub(super) device: &'a str,
    pub(super) driver: &'a str,
    pub(super) boot_id: &'a str,
}

impl DeviceBinding<'_> {
    fn complete(self) -> bool {
        [
            self.canonical_device,
            self.pci,
            self.vendor,
            self.device,
            self.driver,
            self.boot_id,
        ]
        .iter()
        .all(|field| !field.trim().is_empty())
    }
}

/// Before/after metadata surrounds both separately read counters.
///
/// The reader must supply canonical bindings, normalized status/control text,
/// and one common monotonic origin. This type performs no OS reads or attestation.
#[derive(Clone, Copy, Debug)]
pub(super) struct RuntimeSample<'a> {
    pub(super) binding: [Option<DeviceBinding<'a>>; 2],
    pub(super) control: [Option<&'a str>; 2],
    pub(super) status: [Option<&'a str>; 2],
    pub(super) read_window: [Duration; 2],
    pub(super) active_ms: Option<u64>,
    pub(super) suspended_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CounterGrowth {
    pub(super) lower_ms: u64,
    pub(super) upper_ms: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum WitnessError {
    Binding,
    Posture,
    ReadOrder,
    Counter,
    NoSuspendedGrowth,
    SystemSleepNotExcluded,
}

/// Parse an unsigned decimal total, rejecting values outside the kernel range.
pub(super) fn parse_runtime_ms(text: &str) -> Option<u64> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value <= MAX_RUNTIME_MS)
}

fn counter_growth(before: Option<u64>, after: Option<u64>) -> Result<CounterGrowth, WitnessError> {
    let before = before
        .filter(|v| *v <= MAX_RUNTIME_MS)
        .ok_or(WitnessError::Counter)?;
    let after = after
        .filter(|v| *v <= MAX_RUNTIME_MS)
        .ok_or(WitnessError::Counter)?;
    let delta = after.checked_sub(before).ok_or(WitnessError::Counter)?;
    Ok(CounterGrowth {
        lower_ms: delta.saturating_sub(1),
        upper_ms: delta.checked_add(1).ok_or(WitnessError::Counter)?,
    })
}

/// Validate four supplied active/suspended/suspended/active occurrence samples.
///
/// The returned interval concerns the middle suspended-counter increase only.
/// Stable endpoints do not establish continuous residency, D3cold, wake cause
/// or reliability coverage. Clock bounds must bracket the entire runtime leg,
/// including the first post-event calls; their provenance is the reader's job.
///
/// # Errors
///
/// Refuses missing/rebound metadata, non-AUTO or unstable/wrong endpoints,
/// unordered read windows, missing/decreasing/out-of-range/impossible counters,
/// no positive suspended lower bound or no bounded system-sleep exclusion.
pub(super) fn validate_runtime_witness(
    expected: DeviceBinding<'_>,
    samples: &[RuntimeSample<'_>; 4],
    sleep_start: Option<SleepOffsetBounds>,
    sleep_end: Option<SleepOffsetBounds>,
) -> Result<CounterGrowth, WitnessError> {
    if !expected.complete() {
        return Err(WitnessError::Binding);
    }
    for (sample, status) in samples
        .iter()
        .zip(["active", "suspended", "suspended", "active"])
    {
        if sample.binding != [Some(expected); 2] {
            return Err(WitnessError::Binding);
        }
        if sample.control != [Some("auto"); 2] || sample.status != [Some(status); 2] {
            return Err(WitnessError::Posture);
        }
        if sample.read_window[0] > sample.read_window[1] {
            return Err(WitnessError::ReadOrder);
        }
    }
    // Reuse the same endpoints over all six ordered pairs: adjacent floor
    // allowances cannot be spent repeatedly to hide impossible total growth.
    for (index, before) in samples.iter().enumerate() {
        for after in samples.iter().skip(index + 1) {
            if before.read_window[1] > after.read_window[0] {
                return Err(WitnessError::ReadOrder);
            }
            let maximum_elapsed = after.read_window[1]
                .checked_sub(before.read_window[0])
                .ok_or(WitnessError::ReadOrder)?;
            let active = counter_growth(before.active_ms, after.active_ms)?;
            let suspended = counter_growth(before.suspended_ms, after.suspended_ms)?;
            // Separate non-atomic reads fit inside the OUTER capture bracket.
            // Both accounts partition that interval. Each observed D>0 from
            // floored u64 nanoseconds requires at least (D-1) ms + 1 ns. Keep
            // the closed ms report interval conservative, but do not accept its
            // unattainable lower endpoint as a feasible elapsed-time bound.
            // Active growth alone is never runtime-suspend evidence.
            let minimum_growth = active
                .lower_ms
                .checked_add(suspended.lower_ms)
                .ok_or(WitnessError::Counter)?;
            let remainder_ns = u64::from(active.upper_ms > 1) + u64::from(suspended.upper_ms > 1);
            let minimum_growth = Duration::from_millis(minimum_growth)
                .checked_add(Duration::from_nanos(remainder_ns))
                .ok_or(WitnessError::Counter)?;
            if minimum_growth > maximum_elapsed {
                return Err(WitnessError::Counter);
            }
        }
    }
    let middle = counter_growth(samples[1].suspended_ms, samples[2].suspended_ms)?;
    if middle.lower_ms == 0 {
        return Err(WitnessError::NoSuspendedGrowth);
    }
    if !excludes_material_system_sleep(sleep_start, sleep_end) {
        return Err(WitnessError::SystemSleepNotExcluded);
    }
    Ok(middle)
}

#[cfg(test)]
mod tests {
    use super::super::gpu_reliability_clock_tests::SleepOffsetBounds;
    use super::*;
    use std::time::Duration;

    const DEVICE: DeviceBinding<'static> = DeviceBinding {
        canonical_device: "/sys/devices/pci0000:00/0000:00:02.0",
        pci: "0000:00:02.0",
        vendor: "8086",
        device: "64a0",
        driver: "xe",
        boot_id: "synthetic-boot",
    };

    fn samples() -> [RuntimeSample<'static>; 4] {
        std::array::from_fn(|i| RuntimeSample {
            binding: [Some(DEVICE); 2],
            control: [Some("auto"); 2],
            status: [Some(if i == 0 || i == 3 {
                "active"
            } else {
                "suspended"
            }); 2],
            read_window: [
                Duration::from_millis(i as u64 * 10),
                Duration::from_millis(i as u64 * 10 + 1),
            ],
            active_ms: Some([100, 105, 105, 110][i]),
            suspended_ms: Some(1000 + i as u64 * 5),
        })
    }

    fn witness(samples: &[RuntimeSample<'_>; 4]) -> Result<CounterGrowth, WitnessError> {
        let clock = SleepOffsetBounds::new(Duration::from_secs(20), Duration::from_secs(20));
        validate_runtime_witness(DEVICE, samples, clock, clock)
    }

    #[test]
    fn valid_supplied_occurrence_returns_conservative_middle_growth() {
        assert_eq!(
            witness(&samples()),
            Ok(CounterGrowth {
                lower_ms: 4,
                upper_ms: 6
            })
        );
    }

    #[test]
    fn parser_rejects_malformed_overflow_and_out_of_kernel_range_totals() {
        for text in [
            "",
            " ",
            "+2",
            "-2",
            "1.0",
            "2x",
            "1 2",
            "18446744073709551616",
            "18446744073710",
        ] {
            assert_eq!(parse_runtime_ms(text), None, "{text:?}");
        }
        assert_eq!(parse_runtime_ms("0\n"), Some(0));
        assert_eq!(parse_runtime_ms(" 123\n"), Some(123));
        assert_eq!(
            parse_runtime_ms("18446744073709"),
            Some(u64::MAX / 1_000_000)
        );
    }

    #[test]
    fn incomplete_expected_binding_is_not_a_self_consistent_device() {
        for field in 0..6 {
            let mut expected = DEVICE;
            match field {
                0 => expected.canonical_device = "",
                1 => expected.pci = "",
                2 => expected.vendor = "",
                3 => expected.device = "",
                4 => expected.driver = "",
                5 => expected.boot_id = " \t",
                _ => unreachable!(),
            }
            let mut data = samples();
            for sample in &mut data {
                sample.binding = [Some(expected); 2];
            }
            assert_eq!(
                validate_runtime_witness(expected, &data, None, None),
                Err(WitnessError::Binding)
            );
        }
    }

    #[test]
    fn every_binding_component_and_each_endpoint_must_match() {
        for field in 0..6 {
            let mut other = DEVICE;
            match field {
                0 => other.canonical_device = "/sys/devices/other",
                1 => other.pci = "0000:01:00.0",
                2 => other.vendor = "1234",
                3 => other.device = "abcd",
                4 => other.driver = "other",
                5 => other.boot_id = "new-boot",
                _ => unreachable!(),
            }
            for i in 0..4 {
                for endpoint in 0..2 {
                    let mut data = samples();
                    data[i].binding[endpoint] = Some(other);
                    assert_eq!(witness(&data), Err(WitnessError::Binding));
                }
            }
        }
    }

    #[test]
    fn missing_binding_at_any_endpoint_refuses() {
        for i in 0..4 {
            for endpoint in 0..2 {
                let mut data = samples();
                data[i].binding[endpoint] = None;
                assert_eq!(witness(&data), Err(WitnessError::Binding));
            }
        }
    }

    #[test]
    fn on_unreadable_or_noncanonical_control_refuses_at_either_endpoint() {
        for control in [None, Some("on"), Some("AUTO"), Some("auto "), Some("error")] {
            for i in 0..4 {
                for endpoint in 0..2 {
                    let mut data = samples();
                    data[i].control[endpoint] = control;
                    assert_eq!(witness(&data), Err(WitnessError::Posture));
                }
            }
        }
    }

    #[test]
    fn transitional_mixed_or_missing_status_never_replaces_stable_endpoints() {
        for status in [
            None,
            Some("suspending"),
            Some("resuming"),
            Some("error"),
            Some("unsupported"),
            Some("unknown"),
        ] {
            for i in 0..4 {
                for endpoint in 0..2 {
                    let mut data = samples();
                    data[i].status[endpoint] = status;
                    assert_eq!(witness(&data), Err(WitnessError::Posture));
                }
            }
        }
        for i in 0..4 {
            for endpoint in 0..2 {
                let mut data = samples();
                data[i].status[endpoint] = Some(if i == 0 || i == 3 {
                    "suspended"
                } else {
                    "active"
                });
                assert_eq!(witness(&data), Err(WitnessError::Posture));
            }
        }
    }

    #[test]
    fn increasing_historical_totals_without_suspended_observations_refuse() {
        let mut data = samples();
        for sample in &mut data {
            sample.status = [Some("active"); 2];
        }
        assert_eq!(witness(&data), Err(WitnessError::Posture));
    }

    #[test]
    fn middle_delta_zero_or_one_does_not_have_a_positive_lower_bound() {
        for delta in 0..=2 {
            let mut data = samples();
            data[2].suspended_ms = Some(1005 + delta);
            // Keep the later pair valid while isolating the middle delta.
            data[3].suspended_ms = Some(1010 + delta);
            let expected = if delta == 2 {
                Ok(CounterGrowth {
                    lower_ms: 1,
                    upper_ms: 3,
                })
            } else {
                Err(WitnessError::NoSuspendedGrowth)
            };
            assert_eq!(witness(&data), expected);
        }
    }

    #[test]
    fn active_growth_does_not_substitute_for_suspended_growth() {
        let mut data = samples();
        data[2].active_ms = Some(110);
        data[2].suspended_ms = data[1].suspended_ms;
        assert_eq!(witness(&data), Err(WitnessError::NoSuspendedGrowth));
    }

    #[test]
    fn missing_out_of_range_or_decreasing_counters_refuse() {
        for i in 0..4 {
            for active in [false, true] {
                for value in [None, Some(u64::MAX)] {
                    let mut data = samples();
                    if active {
                        data[i].active_ms = value;
                    } else {
                        data[i].suspended_ms = value;
                    }
                    assert_eq!(witness(&data), Err(WitnessError::Counter));
                }
            }
        }
        for i in 1..4 {
            for active in [false, true] {
                let mut data = samples();
                if active {
                    data[i].active_ms = Some(data[i - 1].active_ms.unwrap() - 1);
                } else {
                    data[i].suspended_ms = Some(data[i - 1].suspended_ms.unwrap() - 1);
                }
                assert_eq!(witness(&data), Err(WitnessError::Counter));
            }
        }
    }

    #[test]
    fn reversed_or_overlapping_read_windows_refuse() {
        for i in 0..4 {
            let mut data = samples();
            data[i].read_window.swap(0, 1);
            assert_eq!(witness(&data), Err(WitnessError::ReadOrder));
        }
        for i in 1..4 {
            let mut data = samples();
            data[i].read_window[0] = data[i - 1].read_window[1] - Duration::from_nanos(1);
            assert_eq!(witness(&data), Err(WitnessError::ReadOrder));
        }
    }

    #[test]
    fn floor_quantization_uses_outer_not_inner_read_brackets() {
        let mut data = samples();
        data[1].read_window = [Duration::from_millis(10), Duration::from_millis(14)];
        data[2].read_window = [Duration::from_millis(15), Duration::from_millis(18)];
        assert_eq!(
            witness(&data),
            Ok(CounterGrowth {
                lower_ms: 4,
                upper_ms: 6
            })
        );
    }

    #[test]
    fn impossible_counter_growth_in_any_adjacent_window_refuses() {
        for i in 1..4 {
            for active in [false, true] {
                let mut data = samples();
                if active {
                    data[i].active_ms = Some(data[i - 1].active_ms.unwrap() + 30);
                } else {
                    data[i].suspended_ms = Some(data[i - 1].suspended_ms.unwrap() + 30);
                }
                assert_eq!(witness(&data), Err(WitnessError::Counter));
            }
        }
    }

    #[test]
    fn jointly_impossible_growth_refuses_even_when_each_counter_fits_alone() {
        let mut data = samples();
        data[2].active_ms = Some(113);
        data[2].suspended_ms = Some(1013);
        data[3].active_ms = Some(118);
        data[3].suspended_ms = Some(1018);
        // Each minimum is 7 ms, but their sum is 14 ms in an 11 ms outer bracket.
        assert_eq!(witness(&data), Err(WitnessError::Counter));
    }

    #[test]
    fn inconsistent_post_counter_fixture_stays_rejected() {
        for delta in 0..=2 {
            let mut data = samples();
            data[2].suspended_ms = Some(1005 + delta);
            // Leaving the final total at 1015 makes this last pair impossible.
            // Its summed lower bound is 13, 12 or 11 ms in an 11 ms bracket;
            // any observed floor increase strictly exceeds that lower bound.
            assert_eq!(witness(&data), Err(WitnessError::Counter));
        }
    }

    #[test]
    fn observed_floor_growth_cannot_fit_exactly_at_its_lower_endpoint() {
        let mut data = samples();
        data[2].read_window = [Duration::from_millis(13), Duration::from_millis(14)];
        // D=5 implies true growth >4 ms, not growth equal to 4 ms.
        assert_eq!(witness(&data), Err(WitnessError::Counter));
    }

    #[test]
    fn each_increasing_nanosecond_account_needs_its_own_floor_remainder() {
        for (extra_ns, accepted) in [(1, false), (2, true)] {
            let mut data = samples();
            data[2].active_ms = Some(110);
            data[2].read_window = [
                Duration::from_millis(17),
                Duration::from_millis(18) + Duration::from_nanos(extra_ns),
            ];
            // Both D=5 accounts require at least 4 ms + 1 ns each.
            assert_eq!(witness(&data).is_ok(), accepted);
        }
    }

    #[test]
    fn adjacent_floor_allowances_cannot_hide_impossible_cumulative_growth() {
        let mut data = samples();
        for (i, sample) in data.iter_mut().enumerate() {
            let [start, end] = [[0, 100], [200, 300], [1400, 1500], [1600, 1700]][i];
            sample.read_window = [Duration::from_micros(start), Duration::from_micros(end)];
            sample.active_ms = Some(100);
            sample.suspended_ms = Some([1000, 1001, 1003, 1004][i]);
        }
        // Adjacent minima fit, but first-to-last D=4 needs 3 ms + 1 ns
        // while the complete outer capture bracket is only 1.7 ms.
        assert_eq!(witness(&data), Err(WitnessError::Counter));
    }

    #[test]
    fn old_cumulative_suspended_time_does_not_prove_a_new_occurrence() {
        let mut data = samples();
        for sample in &mut data {
            sample.suspended_ms = Some(185_284);
        }
        assert_eq!(witness(&data), Err(WitnessError::NoSuspendedGrowth));
    }

    #[test]
    fn clock_exclusion_is_required_not_merely_absence_of_positive_proof() {
        let start = SleepOffsetBounds::new(Duration::from_secs(20), Duration::from_secs(20));
        for end in [
            None,
            SleepOffsetBounds::new(
                Duration::from_secs(20),
                Duration::from_secs(20) + Duration::from_millis(5),
            ),
            SleepOffsetBounds::new(Duration::from_secs(21), Duration::from_secs(21)),
        ] {
            assert_eq!(
                validate_runtime_witness(DEVICE, &samples(), start, end),
                Err(WitnessError::SystemSleepNotExcluded)
            );
        }
        assert_eq!(
            validate_runtime_witness(DEVICE, &samples(), None, start),
            Err(WitnessError::SystemSleepNotExcluded)
        );
    }

    #[test]
    fn one_millisecond_clock_allowance_is_not_silently_changed() {
        let offset = Duration::from_secs(20);
        let start = SleepOffsetBounds::new(offset, offset);
        for (growth, accepted) in [
            (Duration::from_millis(1), true),
            (Duration::from_millis(1) + Duration::from_nanos(1), false),
        ] {
            let end = SleepOffsetBounds::new(offset + growth, offset + growth);
            assert_eq!(
                validate_runtime_witness(DEVICE, &samples(), start, end).is_ok(),
                accepted
            );
        }
    }
}
