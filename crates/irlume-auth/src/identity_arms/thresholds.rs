// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::{arm_threshold, ThresholdArm};

pub(super) const MAX_TEMPLATE_COUNT: usize = 4096;
pub(super) const MAX_THRESHOLD_RECORDS: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ThresholdError {
    InvalidScale,
    CapUnreachable,
    CountBudgetExceeded,
    RecordBudgetExceeded,
    InvalidThreshold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Domain {
    Enrollable,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(super) enum Role {
    Rgb = 0,
    LitFallback = 1,
    LitCentroid = 2,
    DarkBest = 3,
    DarkCentroid = 4,
}

impl Role {
    fn is_centroid(self) -> bool {
        matches!(self, Self::LitCentroid | Self::DarkCentroid)
    }

    fn threshold(self, adapter: bool, count: usize) -> f32 {
        let arm = match self {
            Self::Rgb => ThresholdArm::Rgb {
                base: irlume_core::RGB_MATCH_THRESHOLD,
            },
            Self::LitFallback => ThresholdArm::LitFallback { adapter },
            Self::LitCentroid => ThresholdArm::LitCentroid { adapter },
            Self::DarkBest => ThresholdArm::DarkBest { adapter },
            Self::DarkCentroid => ThresholdArm::DarkCentroid { adapter },
        };
        arm_threshold(arm, count)
    }
}

pub(super) struct Point {
    pub(super) role: Role,
    pub(super) adapter: bool,
    pub(super) count: usize,
    pub(super) value: f32,
}

pub(super) struct ThresholdSet {
    pub(super) saturation: usize,
    pub(super) records: Vec<Point>,
    pub(super) rgb: Vec<f32>,
    pub(super) ir: Vec<f32>,
    pub(super) fusion_probability: f32,
    pub(super) fusion_modality_floor: f32,
}

pub(super) fn generate(domain: Domain) -> Result<ThresholdSet, ThresholdError> {
    generate_with_record_budget(domain, MAX_THRESHOLD_RECORDS)
}

fn push_record(
    records: &mut Vec<Point>,
    budget: usize,
    point: Point,
) -> Result<(), ThresholdError> {
    if records.len() >= budget {
        return Err(ThresholdError::RecordBudgetExceeded);
    }
    records.push(point);
    Ok(())
}

fn generate_with_record_budget(
    domain: Domain,
    record_budget: usize,
) -> Result<ThresholdSet, ThresholdError> {
    if record_budget > MAX_THRESHOLD_RECORDS {
        return Err(ThresholdError::RecordBudgetExceeded);
    }
    if !irlume_core::TEMPLATE_SCALE_STEP.is_finite() || irlume_core::TEMPLATE_SCALE_STEP <= 0.0 {
        return Err(ThresholdError::InvalidScale);
    }
    let saturation = saturation_with(
        MAX_TEMPLATE_COUNT,
        irlume_core::TEMPLATE_SCALE_MAX_BUMP,
        |count| irlume_core::scaled_threshold(0.0, count),
    )?;
    let (templates, profiles) = match domain {
        Domain::Enrollable => (
            irlume_core::storage::MAX_PROFILES
                .checked_mul(irlume_core::storage::MAX_SCANS_PER_PROFILE)
                .ok_or(ThresholdError::CountBudgetExceeded)?,
            irlume_core::storage::MAX_PROFILES,
        ),
        Domain::Complete => (saturation, saturation),
    };
    if templates > MAX_TEMPLATE_COUNT || profiles > MAX_TEMPLATE_COUNT {
        return Err(ThresholdError::CountBudgetExceeded);
    }
    let mut series = Vec::with_capacity(9);
    let mut record_count = 0usize;
    for role in [
        Role::Rgb,
        Role::LitFallback,
        Role::LitCentroid,
        Role::DarkBest,
        Role::DarkCentroid,
    ] {
        for adapter in [false, true] {
            if (role == Role::Rgb && adapter)
                || (domain == Domain::Enrollable && role.is_centroid() && adapter)
            {
                continue;
            }
            let last = if role.is_centroid() {
                profiles
            } else {
                templates
            };
            record_count = record_count
                .checked_add(last + 1)
                .ok_or(ThresholdError::RecordBudgetExceeded)?;
            if record_count > record_budget {
                return Err(ThresholdError::RecordBudgetExceeded);
            }
            series.push((role, adapter, last));
        }
    }
    let mut records = Vec::with_capacity(record_count);
    for (role, adapter, last) in series {
        for count in 0..=last {
            let value = role.threshold(adapter, count);
            if !value.is_finite() {
                return Err(ThresholdError::InvalidThreshold);
            }
            push_record(
                &mut records,
                record_budget,
                Point {
                    role,
                    adapter,
                    count,
                    value,
                },
            )?;
        }
    }
    let distinct = |rgb: bool| {
        let mut values: Vec<_> = records
            .iter()
            .filter(|point| !point.adapter && point.count > 0 && (point.role == Role::Rgb) == rgb)
            .map(|point| point.value)
            .collect();
        values.sort_by(f32::total_cmp);
        values.dedup_by(|a, b| a.to_bits() == b.to_bits());
        values
    };
    let rgb = distinct(true);
    let ir = distinct(false);
    let fusion_probability = irlume_core::fusion::FUSION_PROB_THRESHOLD;
    let fusion_modality_floor = irlume_core::fusion::FUSION_MIN_PER_MODALITY_PROB;
    if ![fusion_probability, fusion_modality_floor]
        .into_iter()
        .all(|value| value.is_finite() && (0.0..=1.0).contains(&value))
    {
        return Err(ThresholdError::InvalidThreshold);
    }
    Ok(ThresholdSet {
        saturation,
        records,
        rgb,
        ir,
        fusion_probability,
        fusion_modality_floor,
    })
}

fn saturation_with(
    max_count: usize,
    cap: f32,
    bump: impl Fn(usize) -> f32,
) -> Result<usize, ThresholdError> {
    if !cap.is_finite() || cap <= 0.0 {
        return Err(ThresholdError::InvalidScale);
    }
    if max_count > MAX_TEMPLATE_COUNT {
        return Err(ThresholdError::CountBudgetExceeded);
    }
    let last = bump(usize::MAX);
    if !last.is_finite() || last < 0.0 || last > cap {
        return Err(ThresholdError::InvalidScale);
    }
    if last.to_bits() != cap.to_bits() {
        return Err(ThresholdError::CapUnreachable);
    }
    let mut previous = 0.0;
    for count in 0..=max_count {
        let value = bump(count);
        if !value.is_finite() || value < previous || value > cap {
            return Err(ThresholdError::InvalidScale);
        }
        if count <= 1 && value.to_bits() != 0.0f32.to_bits() {
            return Err(ThresholdError::InvalidScale);
        }
        if value.to_bits() == cap.to_bits() {
            return Ok(count);
        }
        previous = value;
    }
    Err(ThresholdError::CountBudgetExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn saturation_is_the_first_exact_capped_bump() {
        let cap = irlume_core::TEMPLATE_SCALE_MAX_BUMP;
        let count = saturation_with(MAX_TEMPLATE_COUNT, cap, |n| {
            irlume_core::scaled_threshold(0.0, n)
        })
        .unwrap();
        assert_eq!(count, 102);
        for n in 0..count {
            assert!(irlume_core::scaled_threshold(0.0, n) < cap);
        }
        for n in (count..=10000)
            .chain(
                (0..usize::BITS)
                    .map(|k| 1usize << k)
                    .filter(|n| *n >= count),
            )
            .chain([usize::MAX])
        {
            assert_eq!(
                irlume_core::scaled_threshold(0.0, n).to_bits(),
                cap.to_bits()
            );
        }
    }

    #[test]
    fn cap_discovery_distinguishes_unreachable_and_over_budget() {
        assert_eq!(
            saturation_with(4, 0.1, |_| 0.0),
            Err(ThresholdError::CapUnreachable)
        );
        let calls = Cell::new(0);
        let result = saturation_with(4, 0.1, |n| {
            calls.set(calls.get() + 1);
            if n >= 5000 {
                0.1
            } else {
                0.0
            }
        });
        assert_eq!(result, Err(ThresholdError::CountBudgetExceeded));
        assert!(calls.get() <= 6);
    }

    #[test]
    fn cap_discovery_rejects_invalid_scale_results() {
        assert_eq!(
            saturation_with(4, f32::NAN, |_| 0.0),
            Err(ThresholdError::InvalidScale)
        );
        assert_eq!(
            saturation_with(4, 0.1, |_| f32::NAN),
            Err(ThresholdError::InvalidScale)
        );
        assert_eq!(
            saturation_with(4, 0.1, |n| match n {
                usize::MAX => 0.1,
                0 => 0.0,
                1 => 0.05,
                _ => 0.01,
            }),
            Err(ThresholdError::InvalidScale)
        );
    }

    #[test]
    fn cap_discovery_rejects_a_decrease_after_the_zero_count_region() {
        assert_eq!(
            saturation_with(4, 0.1, |n| match n {
                usize::MAX => 0.1,
                0 | 1 => 0.0,
                2 => 0.05,
                3 => 0.01,
                _ => 0.1,
            }),
            Err(ThresholdError::InvalidScale)
        );
    }

    #[test]
    fn record_append_cannot_overrun_its_budget() {
        let point = || Point {
            role: Role::Rgb,
            adapter: false,
            count: 1,
            value: 0.55,
        };
        let mut records = Vec::new();
        push_record(&mut records, 1, point()).unwrap();
        assert_eq!(
            push_record(&mut records, 1, point()),
            Err(ThresholdError::RecordBudgetExceeded)
        );
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn generated_domains_keep_records_and_certification_projections_separate() {
        let enrolled = generate(Domain::Enrollable).unwrap();
        let complete = generate(Domain::Complete).unwrap();
        assert_eq!(enrolled.saturation, 102);
        assert_eq!(complete.saturation, 102);
        assert_eq!((enrolled.records.len(), complete.records.len()), (463, 927));
        assert_eq!((enrolled.rgb.len(), enrolled.ir.len()), (90, 180));
        assert_eq!((complete.rgb.len(), complete.ir.len()), (102, 204));
        for set in [&enrolled, &complete] {
            for values in [&set.rgb, &set.ir] {
                assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
            }
            assert_eq!(
                set.fusion_probability.to_bits(),
                irlume_core::fusion::FUSION_PROB_THRESHOLD.to_bits()
            );
            assert_eq!(
                set.fusion_modality_floor.to_bits(),
                irlume_core::fusion::FUSION_MIN_PER_MODALITY_PROB.to_bits()
            );
            assert!(set.records.iter().any(|point| point.count == 0));
        }
        assert!(!enrolled
            .records
            .iter()
            .any(|point| point.adapter && point.role.is_centroid()));
        assert!(complete
            .records
            .iter()
            .any(|point| point.adapter && point.role.is_centroid()));
    }

    #[test]
    fn generation_refuses_an_insufficient_or_unsupported_record_budget() {
        assert!(matches!(
            generate_with_record_budget(Domain::Complete, 1),
            Err(ThresholdError::RecordBudgetExceeded)
        ));
        assert!(matches!(
            generate_with_record_budget(Domain::Complete, usize::MAX),
            Err(ThresholdError::RecordBudgetExceeded)
        ));
        assert!(matches!(
            generate_with_record_budget(Domain::Complete, 926),
            Err(ThresholdError::RecordBudgetExceeded)
        ));
        assert_eq!(
            generate_with_record_budget(Domain::Complete, 927)
                .unwrap()
                .records
                .len(),
            927
        );
    }

    #[test]
    fn every_role_and_count_has_exactly_its_production_value() {
        for domain in [Domain::Enrollable, Domain::Complete] {
            let set = generate(domain).unwrap();
            for role in [
                Role::Rgb,
                Role::LitFallback,
                Role::LitCentroid,
                Role::DarkBest,
                Role::DarkCentroid,
            ] {
                for adapter in [false, true] {
                    let rows: Vec<_> = set
                        .records
                        .iter()
                        .filter(|point| point.role == role && point.adapter == adapter)
                        .collect();
                    if (role == Role::Rgb && adapter)
                        || (domain == Domain::Enrollable && role.is_centroid() && adapter)
                    {
                        assert!(rows.is_empty());
                        continue;
                    }
                    let last = match (domain, role.is_centroid()) {
                        (Domain::Complete, _) => 102,
                        (Domain::Enrollable, true) => 3,
                        (Domain::Enrollable, false) => 90,
                    };
                    assert_eq!(rows.len(), last + 1);
                    for count in 0..=last {
                        let points: Vec<_> =
                            rows.iter().filter(|point| point.count == count).collect();
                        assert_eq!(points.len(), 1, "{domain:?} {role:?} {adapter} {count}");
                        let expected = match role {
                            Role::Rgb => irlume_core::scaled_threshold(
                                irlume_core::RGB_MATCH_THRESHOLD,
                                count,
                            ),
                            Role::LitFallback | Role::LitCentroid => {
                                let base = if adapter {
                                    irlume_core::IR_ADAPTED_MATCH_THRESHOLD
                                } else {
                                    irlume_core::IR_MATCH_THRESHOLD
                                };
                                irlume_core::scaled_threshold(base, count)
                                    + irlume_core::IR_FALLBACK_MARGIN
                            }
                            Role::DarkBest | Role::DarkCentroid => {
                                let base = if adapter {
                                    irlume_core::IR_ADAPTED_MATCH_THRESHOLD
                                } else {
                                    irlume_core::IR_DARK_MATCH_THRESHOLD
                                };
                                irlume_core::scaled_threshold(base, count)
                            }
                        };
                        assert_eq!(points[0].value.to_bits(), expected.to_bits());
                    }
                }
            }
        }
    }

    #[test]
    fn certification_projections_equal_independent_raw_count_series() {
        for (domain, last) in [(Domain::Enrollable, 90), (Domain::Complete, 102)] {
            let set = generate(domain).unwrap();
            let mut rgb: Vec<_> = (1..=last)
                .map(|count| {
                    irlume_core::scaled_threshold(irlume_core::RGB_MATCH_THRESHOLD, count).to_bits()
                })
                .collect();
            let mut ir: Vec<_> = (1..=last)
                .flat_map(|count| {
                    [
                        (irlume_core::scaled_threshold(irlume_core::IR_MATCH_THRESHOLD, count)
                            + irlume_core::IR_FALLBACK_MARGIN)
                            .to_bits(),
                        irlume_core::scaled_threshold(irlume_core::IR_DARK_MATCH_THRESHOLD, count)
                            .to_bits(),
                    ]
                })
                .collect();
            rgb.sort_unstable();
            rgb.dedup();
            ir.sort_unstable();
            ir.dedup();
            assert_eq!(set.rgb.iter().map(|v| v.to_bits()).collect::<Vec<_>>(), rgb);
            assert_eq!(set.ir.iter().map(|v| v.to_bits()).collect::<Vec<_>>(), ir);
        }
    }
}
