// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Private GPU measurement budgets only, never certification or admission.
//! Call separately for each population, corpus/group and decision arm. Scores
//! are borrowed for the calculation, never retained or logged. This evaluates
//! only `score >= threshold`; it does not implement a production grant path.

#![cfg(test)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Population {
    Genuine,
    Impostor,
    Attack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Pass,
    Fail,
    Inconclusive,
}

impl Outcome {
    fn from_pass(passes: bool) -> Self {
        if passes {
            Self::Pass
        } else {
            Self::Fail
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Inconclusive => "INCONCLUSIVE",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct VerdictCounts {
    pub(super) accepts: u64,
    pub(super) rejects: u64,
}

impl VerdictCounts {
    fn add(&mut self, accepts: bool) {
        if accepts {
            self.accepts += 1;
        } else {
            self.rejects += 1;
        }
    }

    fn errors(self, population: Population) -> u64 {
        match population {
            Population::Genuine => self.rejects,
            Population::Impostor | Population::Attack => self.accepts,
        }
    }
}

/// A signed rate change as an exact fraction, not percentage points rounded
/// for display. A denominator exists only when there are valid samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RateDelta {
    pub(super) numerator: i128,
    pub(super) denominator: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct ThresholdShift {
    /// Rounded display value only; verdict counts use the exact drift.
    pub(super) threshold: f64,
    pub(super) cpu: VerdictCounts,
    pub(super) error_rate_delta: RateDelta,
    pub(super) outcome: Outcome,
}

/// Private in-memory audit metadata, with no identity, path or raw scores.
/// Deliberately not Debug/Serialize: aggregate output must not dump this table.
pub(super) struct VerdictDifference {
    pub(super) ordinal: usize,
    pub(super) cpu_accept: bool,
    pub(super) gpu_accept: bool,
    pub(super) cpu_margin: f64,
    pub(super) cpu_margin_residual: f64,
    pub(super) gpu_margin: f64,
    pub(super) gpu_margin_residual: f64,
}

/// A partial measured-budget report. `Pass` never certifies a GPU or admits
/// loading: corpus coverage, production-shaped arms and all other gates are
/// outside this helper. No Debug/Serialize to keep differences private.
pub(super) struct MeasuredBudget {
    pub(super) population: Population,
    pub(super) threshold: f32,
    pub(super) samples: u64,
    pub(super) cpu: VerdictCounts,
    pub(super) gpu: VerdictCounts,
    pub(super) cpu_accept_gpu_reject: u64,
    pub(super) cpu_reject_gpu_accept: u64,
    pub(super) max_abs_drift: Option<f64>,
    /// Together with max_abs_drift, the exact difference of finite f32 scores.
    pub(super) max_abs_drift_residual: Option<f64>,
    pub(super) error_rate_delta: Option<RateDelta>,
    pub(super) verdict_budget: Outcome,
    /// Lower then upper CPU thresholds, using the actual maximum drift.
    pub(super) threshold_shifts: Option<[ThresholdShift; 2]>,
    pub(super) outcome: Outcome,
    differences: Vec<VerdictDifference>,
}

impl MeasuredBudget {
    pub(super) fn differences(&self) -> &[VerdictDifference] {
        &self.differences
    }

    /// Aggregate output only. Rate deltas are exact signed fractions of the
    /// population, not rounded rates used to make an acceptance decision.
    pub(super) fn line(&self) -> String {
        let delta = self.error_rate_delta.map_or_else(
            || "undefined".to_owned(),
            |delta| format!("{}/{}", delta.numerator, delta.denominator),
        );
        let mut line = format!(
            "MEASURED_BUDGET population={:?} outcome={} verdict_budget={} certification=NOT_EVALUATED threshold={:?} samples={} cpu_accepts={} cpu_rejects={} gpu_accepts={} gpu_rejects={} cpu_accept_gpu_reject={} cpu_reject_gpu_accept={} max_abs_drift={:?} max_abs_drift_residual={:?} error_rate_delta={delta}",
            self.population, self.outcome.label(), self.verdict_budget.label(), self.threshold, self.samples,
            self.cpu.accepts, self.cpu.rejects, self.gpu.accepts, self.gpu.rejects,
            self.cpu_accept_gpu_reject, self.cpu_reject_gpu_accept, self.max_abs_drift, self.max_abs_drift_residual,
        );
        if let Some(shifts) = self.threshold_shifts {
            for (direction, shift) in ["lower", "upper"].into_iter().zip(shifts) {
                line.push_str(&format!(
                    " {direction}_threshold_approx={:?} {direction}_cpu_accepts={} {direction}_cpu_rejects={} {direction}_error_rate_delta={}/{} {direction}_budget={}",
                    shift.threshold, shift.cpu.accepts, shift.cpu.rejects,
                    shift.error_rate_delta.numerator, shift.error_rate_delta.denominator,
                    shift.outcome.label(),
                ));
            }
        }
        line
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum InvalidEvidence {
    Threshold,
    Comparison { ordinal: usize },
    SampleCount,
}

/// An error-free two-part difference of promoted finite f32 values. f64 has
/// ample exponent range for every intermediate, including f32 subnormals.
/// Keep the residual: a rounded f64 difference alone can undercount shifts.
#[derive(Clone, Copy, Default)]
struct ScoreDifference {
    rounded: f64,
    residual: f64,
}

impl ScoreDifference {
    fn between(a: f64, b: f64) -> Self {
        let rounded = a - b;
        let b_virtual = a - rounded;
        let a_virtual = rounded + b_virtual;
        let b_roundoff = b_virtual - b;
        let a_roundoff = a - a_virtual;
        Self {
            rounded,
            residual: a_roundoff + b_roundoff,
        }
    }

    fn negated(self) -> Self {
        Self {
            rounded: -self.rounded,
            residual: -self.residual,
        }
    }

    fn abs(self) -> Self {
        if self.rounded < 0.0 {
            self.negated()
        } else {
            self
        }
    }

    fn at_least(self, other: Self) -> bool {
        // Rounded heads are monotone. Equal heads compare their exact tails,
        // so this is an exact ordering, not a floating-point tolerance.
        self.rounded > other.rounded
            || (self.rounded == other.rounded && self.residual >= other.residual)
    }
}

/// Measure one population and one fixed, higher-is-accept threshold/arm.
/// Every supplied comparison counts; there is no filtering or pooling API.
/// Finite f32 inputs are promoted and their differences retain the residual.
/// Shift counts compare exact CPU margins against the exact drift, never the
/// formatted drift or rounded displayed shifted threshold.
///
/// # Errors
/// Refuses a nonfinite threshold or score, or a sample count exceeding u64.
/// Invalid comparisons refuse the whole report, even after valid comparisons.
pub(super) fn measure(
    population: Population,
    threshold: f32,
    scores: &[(f32, f32)],
) -> Result<MeasuredBudget, InvalidEvidence> {
    if !threshold.is_finite() {
        return Err(InvalidEvidence::Threshold);
    }
    let samples = u64::try_from(scores.len()).map_err(|_| InvalidEvidence::SampleCount)?;
    let mut report = MeasuredBudget {
        population,
        threshold,
        samples,
        cpu: VerdictCounts::default(),
        gpu: VerdictCounts::default(),
        cpu_accept_gpu_reject: 0,
        cpu_reject_gpu_accept: 0,
        max_abs_drift: None,
        max_abs_drift_residual: None,
        error_rate_delta: None,
        verdict_budget: Outcome::Inconclusive,
        threshold_shifts: None,
        outcome: Outcome::Inconclusive,
        differences: Vec::new(),
    };
    let threshold = f64::from(threshold);
    let mut drift = ScoreDifference::default();
    for (ordinal, &(cpu, gpu)) in scores.iter().enumerate() {
        if !cpu.is_finite() || !gpu.is_finite() {
            return Err(InvalidEvidence::Comparison { ordinal });
        }
        let (cpu, gpu) = (f64::from(cpu), f64::from(gpu));
        let difference = ScoreDifference::between(cpu, gpu).abs();
        if difference.at_least(drift) {
            drift = difference;
        }
        let (cpu_accept, gpu_accept) = (cpu >= threshold, gpu >= threshold);
        report.cpu.add(cpu_accept);
        report.gpu.add(gpu_accept);
        if cpu_accept != gpu_accept {
            if cpu_accept {
                report.cpu_accept_gpu_reject += 1;
            } else {
                report.cpu_reject_gpu_accept += 1;
            }
            let cpu_margin = ScoreDifference::between(cpu, threshold);
            let gpu_margin = ScoreDifference::between(gpu, threshold);
            report.differences.push(VerdictDifference {
                ordinal,
                cpu_accept,
                gpu_accept,
                cpu_margin: cpu_margin.rounded,
                cpu_margin_residual: cpu_margin.residual,
                gpu_margin: gpu_margin.rounded,
                gpu_margin_residual: gpu_margin.residual,
            });
        }
    }
    if samples == 0 {
        return Ok(report);
    }
    report.max_abs_drift = Some(drift.rounded);
    report.max_abs_drift_residual = Some(drift.residual);
    let baseline_errors = report.cpu.errors(population);
    let delta = |errors: u64| RateDelta {
        numerator: i128::from(errors) - i128::from(baseline_errors),
        denominator: samples,
    };
    let actual_delta = delta(report.gpu.errors(population));
    report.error_rate_delta = Some(actual_delta);
    // ADR-0022 section 7.4: genuine NET FRR may rise by 1/500 inclusive;
    // no new negative grant is allowed, regardless of aggregate improvement.
    report.verdict_budget = Outcome::from_pass(match population {
        Population::Genuine => {
            actual_delta.numerator <= 0
                || actual_delta.numerator.unsigned_abs() * 500 <= u128::from(samples)
        }
        Population::Impostor | Population::Attack => {
            report.cpu_reject_gpu_accept == 0 && actual_delta.numerator <= 0
        }
    });
    let shifts = [drift.negated(), drift].map(|shift| {
        let shifted_threshold = (threshold + shift.rounded) + shift.residual;
        let mut cpu = VerdictCounts::default();
        for &(score, _) in scores {
            cpu.add(ScoreDifference::between(f64::from(score), threshold).at_least(shift));
        }
        let error_rate_delta = delta(cpu.errors(population));
        let movement = error_rate_delta.numerator.unsigned_abs();
        // Section 7.5 says "moves", so improvements count too, in both
        // directions. Widened integers preserve the exact inclusive limits.
        let passes = match population {
            Population::Genuine => movement * 500 <= u128::from(samples),
            Population::Impostor | Population::Attack if baseline_errors == 0 => {
                movement * 100_000 <= u128::from(samples)
            }
            Population::Impostor | Population::Attack => {
                movement * 10 <= u128::from(baseline_errors)
            }
        };
        ThresholdShift {
            threshold: shifted_threshold,
            cpu,
            error_rate_delta,
            outcome: Outcome::from_pass(passes),
        }
    });
    report.outcome = Outcome::from_pass(
        report.verdict_budget == Outcome::Pass
            && shifts.iter().all(|shift| shift.outcome == Outcome::Pass),
    );
    report.threshold_shifts = Some(shifts);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_extra_reject(n: usize) -> Vec<(f32, f32)> {
        let mut scores = vec![(0.875, 0.875); n];
        scores[0] = (0.625, 0.375);
        scores
    }

    #[test]
    fn gpu_budget_one_extra_genuine_reject_in_339_fails() {
        let report = measure(Population::Genuine, 0.5, &one_extra_reject(339)).unwrap();
        assert_eq!(report.samples, 339);
        assert_eq!(
            report.cpu,
            VerdictCounts {
                accepts: 339,
                rejects: 0
            }
        );
        assert_eq!(
            report.gpu,
            VerdictCounts {
                accepts: 338,
                rejects: 1
            }
        );
        assert_eq!(report.cpu_accept_gpu_reject, 1);
        assert_eq!(report.cpu_reject_gpu_accept, 0);
        assert_eq!(
            report.error_rate_delta,
            Some(RateDelta {
                numerator: 1,
                denominator: 339
            })
        );
        assert_eq!(report.verdict_budget, Outcome::Fail);
        assert_eq!(report.outcome, Outcome::Fail);
        let shifts = report.threshold_shifts.unwrap();
        assert_eq!(shifts[1].error_rate_delta.numerator, 1);
        assert_eq!(shifts[1].outcome, Outcome::Fail);
    }

    #[test]
    fn gpu_budget_one_in_500_is_inclusive_for_actual_and_shifted_frr() {
        for n in [499, 500, 501] {
            let report = measure(Population::Genuine, 0.5, &one_extra_reject(n)).unwrap();
            let expected = if n < 500 {
                Outcome::Fail
            } else {
                Outcome::Pass
            };
            assert_eq!(report.verdict_budget, expected);
            assert_eq!(report.outcome, expected);
            let shifts = report.threshold_shifts.unwrap();
            assert_eq!(shifts[0].threshold, 0.25);
            assert_eq!(shifts[1].threshold, 0.75);
            assert_eq!(shifts[1].cpu.rejects, 1);
            assert_eq!(shifts[1].error_rate_delta.numerator, 1);
            assert_eq!(shifts[1].outcome, expected);
        }
    }

    #[test]
    fn gpu_budget_empty_population_is_inconclusive_not_zero_rate() {
        for population in [
            Population::Genuine,
            Population::Impostor,
            Population::Attack,
        ] {
            let report = measure(population, 0.5, &[]).unwrap();
            assert_eq!(report.population, population);
            assert_eq!(report.outcome, Outcome::Inconclusive);
            assert_eq!(report.verdict_budget, Outcome::Inconclusive);
            assert_eq!(report.max_abs_drift, None);
            assert_eq!(report.error_rate_delta, None);
            assert_eq!(report.threshold_shifts, None);
            assert!(report.differences().is_empty());
            assert!(report.line().contains("INCONCLUSIVE"));
            assert!(!report.line().contains("0/0"));
        }
    }

    #[test]
    fn gpu_budget_genuine_net_frr_explicitly_accounts_for_improvements() {
        let mut scores = one_extra_reject(1000);
        scores[1] = (0.375, 0.625);
        scores[2] = (0.375, 0.625);
        let report = measure(Population::Genuine, 0.5, &scores).unwrap();
        assert_eq!(report.cpu.rejects, 2);
        assert_eq!(report.gpu.rejects, 1);
        assert_eq!(report.cpu_accept_gpu_reject, 1);
        assert_eq!(report.cpu_reject_gpu_accept, 2);
        assert_eq!(report.error_rate_delta.unwrap().numerator, -1);
        assert_eq!(report.verdict_budget, Outcome::Pass);
        assert_eq!(report.outcome, Outcome::Pass);
    }

    #[test]
    fn gpu_budget_new_negative_grant_fails_even_when_aggregate_far_improves() {
        for population in [Population::Impostor, Population::Attack] {
            let scores = [(0.375, 0.625), (0.625, 0.375), (0.625, 0.375)];
            let report = measure(population, 0.5, &scores).unwrap();
            assert_eq!(report.cpu.accepts, 2);
            assert_eq!(report.gpu.accepts, 1);
            assert_eq!(report.error_rate_delta.unwrap().numerator, -1);
            assert_eq!(report.cpu_reject_gpu_accept, 1);
            assert_eq!(report.verdict_budget, Outcome::Fail);
            assert_eq!(report.outcome, Outcome::Fail);
        }
    }

    #[test]
    fn gpu_budget_zero_far_shift_allowance_is_exactly_one_in_100000() {
        for population in [Population::Impostor, Population::Attack] {
            for n in [99_999, 100_000, 100_001] {
                let mut scores = vec![(0.0, 0.0); n];
                // No GPU grant. The maximum drift lowers the CPU threshold
                // to 0.25, making exactly this CPU comparison accept.
                scores[0] = (0.25, 0.0);
                let report = measure(population, 0.5, &scores).unwrap();
                assert_eq!(report.cpu.accepts, 0);
                assert_eq!(report.gpu.accepts, 0);
                assert_eq!(report.verdict_budget, Outcome::Pass);
                let shifts = report.threshold_shifts.unwrap();
                assert_eq!(shifts[0].cpu.accepts, 1);
                assert_eq!(shifts[0].error_rate_delta.numerator, 1);
                let expected = if n < 100_000 {
                    Outcome::Fail
                } else {
                    Outcome::Pass
                };
                assert_eq!(shifts[0].outcome, expected);
                assert_eq!(report.outcome, expected);
            }
        }
    }

    #[test]
    fn gpu_budget_positive_far_shift_uses_ten_percent_of_baseline_not_samples() {
        for baseline in [9, 10, 11] {
            let mut scores = vec![(0.875, 0.875); baseline];
            scores.push((0.25, 0.0));
            scores.extend(vec![(0.0, 0.0); 1000]);
            let report = measure(Population::Impostor, 0.5, &scores).unwrap();
            assert_eq!(report.cpu.accepts, baseline as u64);
            let shifts = report.threshold_shifts.unwrap();
            assert_eq!(shifts[0].error_rate_delta.numerator, 1);
            let expected = if baseline < 10 {
                Outcome::Fail
            } else {
                Outcome::Pass
            };
            assert_eq!(shifts[0].outcome, expected);
            assert_eq!(report.outcome, expected);
        }
    }

    #[test]
    fn gpu_budget_shift_rate_movement_is_absolute_in_both_directions() {
        let mut negative = vec![(0.625, 0.625); 10];
        negative.push((0.0, 0.25));
        let report = measure(Population::Attack, 0.5, &negative).unwrap();
        assert_eq!(report.verdict_budget, Outcome::Pass);
        let shifts = report.threshold_shifts.unwrap();
        assert_eq!(shifts[0].error_rate_delta.numerator, 0);
        assert_eq!(shifts[1].error_rate_delta.numerator, -10);
        assert_eq!(shifts[1].outcome, Outcome::Fail);
        assert_eq!(report.outcome, Outcome::Fail);

        let mut genuine = vec![(0.0, 0.0); 499];
        genuine[0] = (0.25, 0.0);
        let report = measure(Population::Genuine, 0.5, &genuine).unwrap();
        assert_eq!(report.verdict_budget, Outcome::Pass);
        assert_eq!(
            report.threshold_shifts.unwrap()[0]
                .error_rate_delta
                .numerator,
            -1
        );
        assert_eq!(report.outcome, Outcome::Fail);
    }

    #[test]
    fn gpu_budget_invalid_floats_refuse_without_omitting_comparisons() {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert!(matches!(
                measure(Population::Genuine, value, &[]),
                Err(InvalidEvidence::Threshold)
            ));
            for scores in [
                vec![(0.875, 0.875), (value, 0.0)],
                vec![(0.875, 0.875), (0.0, value)],
            ] {
                assert!(matches!(
                    measure(Population::Genuine, 0.5, &scores),
                    Err(InvalidEvidence::Comparison { ordinal: 1 })
                ));
            }
        }
    }

    #[test]
    fn gpu_budget_actual_float_drift_not_rounded_display_controls_shifts() {
        let threshold = 0.55_f32;
        let cpu = f32::from_bits(threshold.to_bits() + 1);
        let gpu = f32::from_bits(threshold.to_bits() - 1);
        let mut scores = vec![(0.875, 0.875); 500];
        scores[0] = (cpu, gpu);
        let report = measure(Population::Genuine, threshold, &scores).unwrap();
        let d = f64::from(cpu) - f64::from(gpu);
        assert_eq!(format!("{d:.6}"), "0.000000");
        assert_eq!(report.max_abs_drift, Some(d));
        let shifts = report.threshold_shifts.unwrap();
        assert_eq!(shifts[1].threshold, f64::from(threshold) + d);
        assert_eq!(shifts[1].cpu.rejects, 1);
        assert_eq!(shifts[1].error_rate_delta.numerator, 1);
    }

    #[test]
    fn gpu_budget_f64_subtraction_must_not_lose_a_small_drift_tail() {
        let tiny = f32::from_bits(1);
        // Even f64 rounds (0.5 + tiny) to 0.5. The exact lower threshold
        // is -tiny, and the CPU score equals it, so the shifted CPU accepts.
        let report = measure(Population::Genuine, 0.5, &[(-tiny, 0.5)]).unwrap();
        assert_eq!(report.verdict_budget, Outcome::Pass);
        assert_eq!(report.max_abs_drift, Some(0.5));
        assert_eq!(report.max_abs_drift_residual, Some(f64::from(tiny)));
        let shifts = report.threshold_shifts.unwrap();
        assert_eq!(shifts[0].cpu.accepts, 1);
        assert_eq!(shifts[0].error_rate_delta.numerator, -1);
        assert_eq!(shifts[0].outcome, Outcome::Fail);
        assert_eq!(report.outcome, Outcome::Fail);
    }

    #[test]
    fn gpu_budget_maximum_drift_uses_residual_even_when_rounded_heads_match() {
        let tiny = f32::from_bits(1);
        for scores in [[(0.0, 0.5), (-tiny, 0.5)], [(-tiny, 0.5), (0.0, 0.5)]] {
            let report = measure(Population::Genuine, 0.5, &scores).unwrap();
            assert_eq!(report.max_abs_drift, Some(0.5));
            assert_eq!(report.max_abs_drift_residual, Some(f64::from(tiny)));
            assert_eq!(report.threshold_shifts.unwrap()[0].cpu.accepts, 2);
            assert_eq!(report.outcome, Outcome::Fail);
        }
    }

    #[test]
    fn gpu_budget_upper_shift_counts_are_not_taken_from_rounded_threshold() {
        let tiny = f32::from_bits(1);
        let report = measure(Population::Genuine, 0.0, &[(0.5, 0.5), (-tiny, 0.5)]).unwrap();
        let upper = report.threshold_shifts.unwrap()[1];
        assert_eq!(upper.threshold, 0.5); // Display rounds away the tail.
        assert_eq!(upper.cpu.accepts, 0); // Exact upper threshold exceeds 0.5.
        assert_eq!(upper.error_rate_delta.numerator, 1);
        assert_eq!(upper.outcome, Outcome::Fail);
    }

    #[test]
    fn gpu_budget_unchanged_nonempty_samples_pass_only_measured_budgets() {
        for population in [
            Population::Genuine,
            Population::Impostor,
            Population::Attack,
        ] {
            let report = measure(population, 0.5, &[(0.5, 0.5), (0.0, 0.0)]).unwrap();
            assert_eq!(report.max_abs_drift, Some(0.0));
            assert_eq!(report.max_abs_drift_residual, Some(0.0));
            assert_eq!(report.error_rate_delta.unwrap().numerator, 0);
            assert_eq!(report.outcome, Outcome::Pass);
            for shift in report.threshold_shifts.unwrap() {
                assert_eq!(shift.cpu, report.cpu);
                assert_eq!(shift.error_rate_delta.numerator, 0);
                assert_eq!(shift.outcome, Outcome::Pass);
            }
            assert!(report.differences().is_empty());
            assert!(report.line().contains("outcome=PASS"));
            assert!(report.line().contains("certification=NOT_EVALUATED"));
        }
    }

    #[test]
    fn gpu_budget_private_verdict_table_has_only_ordinals_and_margins() {
        let scores = [(0.875, 0.875), (0.5, 0.375), (0.375, 0.5)];
        let report = measure(Population::Genuine, 0.5, &scores).unwrap();
        let differences = report.differences();
        assert_eq!(differences.len(), 2);
        assert_eq!(differences[0].ordinal, 1);
        assert!(differences[0].cpu_accept && !differences[0].gpu_accept);
        assert_eq!(differences[0].cpu_margin, 0.0);
        assert_eq!(differences[0].cpu_margin_residual, 0.0);
        assert_eq!(differences[0].gpu_margin, -0.125);
        assert_eq!(differences[0].gpu_margin_residual, 0.0);
        assert_eq!(differences[1].ordinal, 2);
        assert!(!differences[1].cpu_accept && differences[1].gpu_accept);
        assert_eq!(differences[1].cpu_margin, -0.125);
        assert_eq!(differences[1].cpu_margin_residual, 0.0);
        assert_eq!(differences[1].gpu_margin, 0.0);
        assert_eq!(differences[1].gpu_margin_residual, 0.0);
        for difference in differences {
            assert!(difference.cpu_margin.abs() <= report.max_abs_drift.unwrap());
            assert!(difference.gpu_margin.abs() <= report.max_abs_drift.unwrap());
        }
        let line = report.line();
        assert!(line.starts_with("MEASURED_BUDGET "));
        assert!(line.contains("certification=NOT_EVALUATED"));
        assert!(line.contains("cpu_accepts=2 cpu_rejects=1"));
        assert!(line.contains("gpu_accepts=2 gpu_rejects=1"));
        assert!(!line.contains("ordinal"));
        assert!(!line.contains("margin"));
        assert!(!line.contains("0.875"));
        assert!(!line.contains("CERTIFICATION_PASS"));
    }
}
