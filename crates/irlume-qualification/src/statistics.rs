// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use crate::{
    CampaignError, Identifier, RatePpb, Sha256Digest, SignedRateDifferencePpb,
    LATENCY_BOOTSTRAP_RESAMPLES, LATENCY_BUDGET_FRACTION_PPB, ONE_SIDED_ALPHA_PPB, RATE_SCALE_PPB,
    REQUIRED_POWER_PPB,
};

const ONE_SIDED_NORMAL_95: f64 = 1.644_853_626_951_472_2;
const MAX_POWER_PAIRS: u64 = 10_000_000;
const MAX_EXACT_F64_INTEGER: u64 = 1_u64 << 53;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairedTable {
    both_fail: u64,
    candidate_only_success: u64,
    baseline_only_success: u64,
    both_succeed: u64,
}

impl PairedTable {
    #[must_use]
    pub const fn new(
        both_fail: u64,
        candidate_only_success: u64,
        baseline_only_success: u64,
        both_succeed: u64,
    ) -> Self {
        Self {
            both_fail,
            candidate_only_success,
            baseline_only_success,
            both_succeed,
        }
    }

    fn total(self) -> Result<u64, CampaignError> {
        self.both_fail
            .checked_add(self.candidate_only_success)
            .and_then(|count| count.checked_add(self.baseline_only_success))
            .and_then(|count| count.checked_add(self.both_succeed))
            .filter(|count| *count != 0 && *count <= MAX_EXACT_F64_INTEGER)
            .ok_or(CampaignError::ProtocolInvalid)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MoverWilsonResult {
    estimate_ppb: SignedRateDifferencePpb,
    lower_ppb: SignedRateDifferencePpb,
    upper_ppb: SignedRateDifferencePpb,
}

impl MoverWilsonResult {
    #[must_use]
    pub const fn estimate_ppb(self) -> SignedRateDifferencePpb {
        self.estimate_ppb
    }

    #[must_use]
    pub const fn lower_ppb(self) -> SignedRateDifferencePpb {
        self.lower_ppb
    }

    #[must_use]
    pub const fn upper_ppb(self) -> SignedRateDifferencePpb {
        self.upper_ppb
    }

    #[must_use]
    pub const fn decision(self, margin_ppb: SignedRateDifferencePpb) -> IntersectionDecision {
        if self.lower_ppb.get() > margin_ppb.get() {
            IntersectionDecision::Pass
        } else {
            IntersectionDecision::Fail
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClopperPearsonUpper {
    accepts: u64,
    trials: u64,
    upper_ppb: RatePpb,
}

impl ClopperPearsonUpper {
    #[must_use]
    pub const fn accepts(self) -> u64 {
        self.accepts
    }

    #[must_use]
    pub const fn trials(self) -> u64 {
        self.trials
    }

    #[must_use]
    pub const fn upper_ppb(self) -> RatePpb {
        self.upper_ppb
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntersectionDecision {
    Pass,
    Fail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowerPlan {
    candidate_only_success_ppb: RatePpb,
    baseline_only_success_ppb: RatePpb,
    margin_ppb: RatePpb,
    alpha_ppb: RatePpb,
    target_power_ppb: RatePpb,
    minimum_pairs: u64,
}

impl PowerPlan {
    #[must_use]
    pub const fn candidate_only_success_ppb(self) -> RatePpb {
        self.candidate_only_success_ppb
    }

    #[must_use]
    pub const fn baseline_only_success_ppb(self) -> RatePpb {
        self.baseline_only_success_ppb
    }

    #[must_use]
    pub const fn margin_ppb(self) -> RatePpb {
        self.margin_ppb
    }

    #[must_use]
    pub const fn alpha_ppb(self) -> RatePpb {
        self.alpha_ppb
    }

    #[must_use]
    pub const fn target_power_ppb(self) -> RatePpb {
        self.target_power_ppb
    }

    #[must_use]
    pub const fn minimum_pairs(self) -> u64 {
        self.minimum_pairs
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairedLatencyUs {
    baseline_us: u64,
    candidate_us: u64,
}

impl PairedLatencyUs {
    #[must_use]
    pub const fn new(baseline_us: u64, candidate_us: u64) -> Self {
        Self {
            baseline_us,
            candidate_us,
        }
    }

    #[must_use]
    pub const fn baseline_us(self) -> u64 {
        self.baseline_us
    }

    #[must_use]
    pub const fn candidate_us(self) -> u64 {
        self.candidate_us
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterLatency {
    cluster_id: Identifier,
    observations: Vec<PairedLatencyUs>,
}

impl ClusterLatency {
    #[must_use]
    pub const fn new(cluster_id: Identifier, observations: Vec<PairedLatencyUs>) -> Self {
        Self {
            cluster_id,
            observations,
        }
    }

    #[must_use]
    pub const fn cluster_id(&self) -> &Identifier {
        &self.cluster_id
    }

    #[must_use]
    pub fn observations(&self) -> &[PairedLatencyUs] {
        &self.observations
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LatencyResult {
    baseline_p50_us: u64,
    baseline_p95_us: u64,
    candidate_p50_us: u64,
    candidate_p95_us: u64,
    upper_increase_us: i64,
    budget_us: u64,
    allowed_increase_us: u64,
    decision: IntersectionDecision,
}

impl LatencyResult {
    #[must_use]
    pub const fn baseline_p50_us(self) -> u64 {
        self.baseline_p50_us
    }

    #[must_use]
    pub const fn baseline_p95_us(self) -> u64 {
        self.baseline_p95_us
    }

    #[must_use]
    pub const fn candidate_p50_us(self) -> u64 {
        self.candidate_p50_us
    }

    #[must_use]
    pub const fn candidate_p95_us(self) -> u64 {
        self.candidate_p95_us
    }

    #[must_use]
    pub const fn upper_increase_us(self) -> i64 {
        self.upper_increase_us
    }

    #[must_use]
    pub const fn budget_us(self) -> u64 {
        self.budget_us
    }

    #[must_use]
    pub const fn allowed_increase_us(self) -> u64 {
        self.allowed_increase_us
    }

    #[must_use]
    pub const fn decision(self) -> IntersectionDecision {
        self.decision
    }
}

/// Computes the policy-v1 MOVER-Wilson interval for a paired success table.
///
/// # Errors
///
/// Returns `ProtocolInvalid` when the table is empty, its count sum overflows,
/// or its counts exceed the method's exact integer-to-float domain.
pub fn paired_mover_wilson(table: PairedTable) -> Result<MoverWilsonResult, CampaignError> {
    let total = table.total()? as f64;
    let candidate_success = table
        .candidate_only_success
        .checked_add(table.both_succeed)
        .ok_or(CampaignError::ProtocolInvalid)? as f64;
    let baseline_success = table
        .baseline_only_success
        .checked_add(table.both_succeed)
        .ok_or(CampaignError::ProtocolInvalid)? as f64;
    let candidate_rate = candidate_success / total;
    let baseline_rate = baseline_success / total;
    let both_succeed_rate = table.both_succeed as f64 / total;
    let (candidate_lower, candidate_upper) = wilson_interval(candidate_rate, total);
    let (baseline_lower, baseline_upper) = wilson_interval(baseline_rate, total);
    let covariance_denominator =
        (baseline_rate * (1.0 - baseline_rate) * candidate_rate * (1.0 - candidate_rate)).sqrt();
    let correlation = if covariance_denominator == 0.0 {
        0.0
    } else {
        ((both_succeed_rate - baseline_rate * candidate_rate) / covariance_denominator)
            .clamp(-1.0, 1.0)
    };
    let difference = candidate_rate - baseline_rate;
    let candidate_lower_distance = candidate_rate - candidate_lower;
    let baseline_upper_distance = baseline_upper - baseline_rate;
    let lower = difference
        - correlated_radius(
            candidate_lower_distance,
            baseline_upper_distance,
            correlation,
        );
    let candidate_upper_distance = candidate_upper - candidate_rate;
    let baseline_lower_distance = baseline_rate - baseline_lower;
    let upper = difference
        + correlated_radius(
            candidate_upper_distance,
            baseline_lower_distance,
            correlation,
        );

    Ok(MoverWilsonResult {
        estimate_ppb: quantize_signed_rate(difference)?,
        lower_ppb: quantize_signed_rate(lower.clamp(-1.0, 1.0))?,
        upper_ppb: quantize_signed_rate(upper.clamp(-1.0, 1.0))?,
    })
}

/// Computes only the policy-v1 one-sided lower MOVER-Wilson bound.
///
/// # Errors
///
/// Returns `ProtocolInvalid` when the table is empty, its count sum overflows,
/// or its counts exceed the method's exact integer-to-float domain.
pub fn paired_mover_wilson_lower(
    table: PairedTable,
) -> Result<SignedRateDifferencePpb, CampaignError> {
    paired_mover_wilson(table).map(MoverWilsonResult::lower_ppb)
}

/// Computes the exact policy-v1 one-sided Clopper-Pearson result.
///
/// # Errors
///
/// Returns `ProtocolInvalid` for a zero or unsupported denominator or accepts
/// above trials.
pub fn clopper_pearson(accepts: u64, trials: u64) -> Result<ClopperPearsonUpper, CampaignError> {
    if trials == 0 || trials > MAX_EXACT_F64_INTEGER || accepts > trials {
        return Err(CampaignError::ProtocolInvalid);
    }
    let upper = if accepts == trials {
        RatePpb::new(RATE_SCALE_PPB)?
    } else {
        quantize_rate(beta_inv(
            0.95,
            accepts as f64 + 1.0,
            (trials - accepts) as f64,
        ))?
    };
    Ok(ClopperPearsonUpper {
        accepts,
        trials,
        upper_ppb: upper,
    })
}

/// Computes the exact policy-v1 one-sided Clopper-Pearson upper bound.
///
/// # Errors
///
/// Returns `ProtocolInvalid` for a zero or unsupported denominator or accepts
/// above trials.
pub fn clopper_pearson_upper(accepts: u64, trials: u64) -> Result<RatePpb, CampaignError> {
    clopper_pearson(accepts, trials).map(ClopperPearsonUpper::upper_ppb)
}

/// Finds the smallest paired sample with policy-v1 planned power of at least 80 percent.
///
/// # Errors
///
/// Returns `ProtocolInvalid` when probabilities are inconsistent, the effect
/// cannot prove non-inferiority, variance is zero, or more than ten million
/// pairs would be required.
pub fn minimum_paired_sample_size(
    candidate_only_success_ppb: RatePpb,
    baseline_only_success_ppb: RatePpb,
    margin_ppb: RatePpb,
) -> Result<PowerPlan, CampaignError> {
    let candidate_only_ppb = candidate_only_success_ppb.get();
    let baseline_only_ppb = baseline_only_success_ppb.get();
    if candidate_only_ppb
        .checked_add(baseline_only_ppb)
        .is_none_or(|sum| sum > RATE_SCALE_PPB)
    {
        return Err(CampaignError::ProtocolInvalid);
    }
    let scale = RATE_SCALE_PPB as f64;
    let candidate_only = candidate_only_ppb as f64 / scale;
    let baseline_only = baseline_only_ppb as f64 / scale;
    let margin = margin_ppb.get() as f64 / scale;
    let difference = candidate_only - baseline_only;
    let variance = candidate_only + baseline_only - difference * difference;
    let effect = difference + margin;
    if effect <= 0.0 || variance <= 0.0 || !variance.is_finite() {
        return Err(CampaignError::ProtocolInvalid);
    }
    let target_power = REQUIRED_POWER_PPB as f64 / scale;
    if paired_power(effect, variance, MAX_POWER_PAIRS) < target_power {
        return Err(CampaignError::ProtocolInvalid);
    }
    let (mut below, mut passing) = (0, MAX_POWER_PAIRS);
    while passing - below > 1 {
        let midpoint = below + (passing - below) / 2;
        if paired_power(effect, variance, midpoint) >= target_power {
            passing = midpoint;
        } else {
            below = midpoint;
        }
    }
    Ok(PowerPlan {
        candidate_only_success_ppb,
        baseline_only_success_ppb,
        margin_ppb,
        alpha_ppb: RatePpb::new(ONE_SIDED_ALPHA_PPB)?,
        target_power_ppb: RatePpb::new(REQUIRED_POWER_PPB)?,
        minimum_pairs: passing,
    })
}

/// Computes policy-v1 deterministic participant-cluster bootstrap latency bounds.
///
/// # Errors
///
/// Returns `ProtocolInvalid` for empty or duplicate clusters, an empty cluster,
/// a zero budget, count/allocation overflow, or a signed latency delta overflow.
pub fn cluster_bootstrap_latency(
    clusters: &[ClusterLatency],
    budget_us: u64,
    seed: &Sha256Digest,
) -> Result<LatencyResult, CampaignError> {
    if clusters.is_empty() || budget_us == 0 {
        return Err(CampaignError::ProtocolInvalid);
    }
    let mut ordered: Vec<_> = clusters.iter().collect();
    ordered.sort_by(|left, right| left.cluster_id.cmp(&right.cluster_id));
    if ordered
        .iter()
        .any(|cluster| cluster.observations.is_empty())
        || ordered
            .windows(2)
            .any(|pair| pair[0].cluster_id == pair[1].cluster_id)
    {
        return Err(CampaignError::ProtocolInvalid);
    }

    let observation_count = ordered.iter().try_fold(0usize, |count, cluster| {
        count.checked_add(cluster.observations.len())
    });
    let observation_count = observation_count.ok_or(CampaignError::ProtocolInvalid)?;
    let maximum_resample_observations = ordered
        .iter()
        .map(|cluster| cluster.observations.len())
        .max()
        .and_then(|maximum| maximum.checked_mul(ordered.len()))
        .ok_or(CampaignError::ProtocolInvalid)?;

    let mut baseline = Vec::new();
    let mut candidate = Vec::new();
    baseline
        .try_reserve_exact(observation_count)
        .map_err(|_| CampaignError::ProtocolInvalid)?;
    candidate
        .try_reserve_exact(observation_count)
        .map_err(|_| CampaignError::ProtocolInvalid)?;
    for cluster in &ordered {
        for observation in &cluster.observations {
            baseline.push(observation.baseline_us);
            candidate.push(observation.candidate_us);
        }
    }
    let baseline_p50_us = nearest_rank(&mut baseline, 50)?;
    let baseline_p95_us = nearest_rank(&mut baseline, 95)?;
    let candidate_p50_us = nearest_rank(&mut candidate, 50)?;
    let candidate_p95_us = nearest_rank(&mut candidate, 95)?;

    let seed_prefix = u64::from_str_radix(&seed.as_str()[..16], 16)
        .map_err(|_| CampaignError::ProtocolInvalid)?;
    let mut generator = SplitMix64(seed_prefix);
    let cluster_count = u64::try_from(ordered.len()).map_err(|_| CampaignError::ProtocolInvalid)?;
    let mut sampled_baseline = Vec::new();
    let mut sampled_candidate = Vec::new();
    sampled_baseline
        .try_reserve_exact(maximum_resample_observations)
        .map_err(|_| CampaignError::ProtocolInvalid)?;
    sampled_candidate
        .try_reserve_exact(maximum_resample_observations)
        .map_err(|_| CampaignError::ProtocolInvalid)?;
    let mut deltas = Vec::new();
    deltas
        .try_reserve_exact(LATENCY_BOOTSTRAP_RESAMPLES as usize)
        .map_err(|_| CampaignError::ProtocolInvalid)?;
    for _ in 0..LATENCY_BOOTSTRAP_RESAMPLES {
        sampled_baseline.clear();
        sampled_candidate.clear();
        for _ in 0..cluster_count {
            let index = usize::try_from(generator.unbiased_index(cluster_count))
                .map_err(|_| CampaignError::ProtocolInvalid)?;
            for observation in &ordered[index].observations {
                sampled_baseline.push(observation.baseline_us);
                sampled_candidate.push(observation.candidate_us);
            }
        }
        let sampled_baseline_p95 = nearest_rank(&mut sampled_baseline, 95)?;
        let sampled_candidate_p95 = nearest_rank(&mut sampled_candidate, 95)?;
        let delta = i128::from(sampled_candidate_p95) - i128::from(sampled_baseline_p95);
        deltas.push(i64::try_from(delta).map_err(|_| CampaignError::ProtocolInvalid)?);
    }
    deltas.sort_unstable();
    let upper_index = nearest_rank_index(deltas.len(), 95)?;
    let upper_increase_us = deltas[upper_index];
    let allowed_increase_us = u64::try_from(
        u128::from(budget_us) * u128::from(LATENCY_BUDGET_FRACTION_PPB)
            / u128::from(RATE_SCALE_PPB),
    )
    .map_err(|_| CampaignError::ProtocolInvalid)?;
    let decision = if candidate_p95_us <= budget_us
        && i128::from(upper_increase_us) <= i128::from(allowed_increase_us)
    {
        IntersectionDecision::Pass
    } else {
        IntersectionDecision::Fail
    };
    Ok(LatencyResult {
        baseline_p50_us,
        baseline_p95_us,
        candidate_p50_us,
        candidate_p95_us,
        upper_increase_us,
        budget_us,
        allowed_increase_us,
        decision,
    })
}

fn nearest_rank(values: &mut [u64], percentile: usize) -> Result<u64, CampaignError> {
    values.sort_unstable();
    nearest_rank_index(values.len(), percentile).map(|index| values[index])
}

fn nearest_rank_index(length: usize, percentile: usize) -> Result<usize, CampaignError> {
    length
        .checked_mul(percentile)
        .and_then(|scaled| scaled.checked_add(99))
        .map(|rounded| rounded / 100)
        .and_then(|rank| rank.checked_sub(1))
        .ok_or(CampaignError::ProtocolInvalid)
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn unbiased_index(&mut self, bound: u64) -> u64 {
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let value = self.next();
            if value >= threshold {
                return value % bound;
            }
        }
    }
}

fn paired_power(effect: f64, variance: f64, pairs: u64) -> f64 {
    normal_cdf(effect * (pairs as f64 / variance).sqrt() - ONE_SIDED_NORMAL_95)
}

// Abramowitz-Stegun 7.1.26, with the policy-v1 coefficient precision pinned here.
fn normal_cdf(value: f64) -> f64 {
    const P: f64 = 0.231_641_9;
    const B1: f64 = 0.319_381_530;
    const B2: f64 = -0.356_563_782;
    const B3: f64 = 1.781_477_937;
    const B4: f64 = -1.821_255_978;
    const B5: f64 = 1.330_274_429;
    if value < 0.0 {
        return 1.0 - normal_cdf(-value);
    }
    let factor = 1.0 / (1.0 + P * value);
    let polynomial = factor * (B1 + factor * (B2 + factor * (B3 + factor * (B4 + factor * B5))));
    1.0 - (-0.5 * value * value).exp() / (2.0 * std::f64::consts::PI).sqrt() * polynomial
}

fn wilson_interval(rate: f64, total: f64) -> (f64, f64) {
    let z_squared = ONE_SIDED_NORMAL_95 * ONE_SIDED_NORMAL_95;
    let denominator = 1.0 + z_squared / total;
    let center = (rate + z_squared / (2.0 * total)) / denominator;
    let variance = rate.mul_add(1.0 - rate, z_squared / (4.0 * total)) / total;
    let half = ONE_SIDED_NORMAL_95 * variance.sqrt() / denominator;
    (center - half, center + half)
}

fn correlated_radius(left: f64, right: f64, correlation: f64) -> f64 {
    ((left - right).mul_add(left - right, 2.0 * (1.0 - correlation) * left * right))
        .max(0.0)
        .sqrt()
}

fn quantize_rate(rate: f64) -> Result<RatePpb, CampaignError> {
    if !rate.is_finite() || !(0.0..=1.0).contains(&rate) {
        return Err(CampaignError::ProtocolInvalid);
    }
    RatePpb::new((rate * RATE_SCALE_PPB as f64).round() as u64)
}

fn quantize_signed_rate(rate: f64) -> Result<SignedRateDifferencePpb, CampaignError> {
    if !rate.is_finite() || !(-1.0..=1.0).contains(&rate) {
        return Err(CampaignError::ProtocolInvalid);
    }
    SignedRateDifferencePpb::new((rate * RATE_SCALE_PPB as f64).round() as i64)
}

fn beta_inv(probability: f64, alpha: f64, beta: f64) -> f64 {
    let (mut lower, mut upper) = (0.0, 1.0);
    for _ in 0..100 {
        let midpoint = 0.5 * (lower + upper);
        if regularized_incomplete_beta(alpha, beta, midpoint) < probability {
            lower = midpoint;
        } else {
            upper = midpoint;
        }
    }
    0.5 * (lower + upper)
}

fn regularized_incomplete_beta(alpha: f64, beta: f64, value: f64) -> f64 {
    if value <= 0.0 {
        return 0.0;
    }
    if value >= 1.0 {
        return 1.0;
    }
    let factor = (ln_gamma(alpha + beta) - ln_gamma(alpha) - ln_gamma(beta)
        + alpha * value.ln()
        + beta * (1.0 - value).ln())
    .exp();
    if value < (alpha + 1.0) / (alpha + beta + 2.0) {
        factor * beta_continued_fraction(alpha, beta, value) / alpha
    } else {
        1.0 - factor * beta_continued_fraction(beta, alpha, 1.0 - value) / beta
    }
}

// Lentz's method, pinned to the repository's existing incomplete-beta implementation.
fn beta_continued_fraction(alpha: f64, beta: f64, value: f64) -> f64 {
    const MAX_ITERATIONS: usize = 300;
    const EPSILON: f64 = 3.0e-14;
    const MINIMUM: f64 = 1.0e-300;
    let sum = alpha + beta;
    let alpha_plus_one = alpha + 1.0;
    let alpha_minus_one = alpha - 1.0;
    let mut numerator = 1.0;
    let mut denominator = 1.0 - sum * value / alpha_plus_one;
    if denominator.abs() < MINIMUM {
        denominator = MINIMUM;
    }
    denominator = 1.0 / denominator;
    let mut result = denominator;
    for iteration in 1..=MAX_ITERATIONS {
        let iteration = iteration as f64;
        let doubled = 2.0 * iteration;
        let mut term = iteration * (beta - iteration) * value
            / ((alpha_minus_one + doubled) * (alpha + doubled));
        denominator = 1.0 + term * denominator;
        if denominator.abs() < MINIMUM {
            denominator = MINIMUM;
        }
        numerator = 1.0 + term / numerator;
        if numerator.abs() < MINIMUM {
            numerator = MINIMUM;
        }
        denominator = 1.0 / denominator;
        result *= denominator * numerator;
        term = -(alpha + iteration) * (sum + iteration) * value
            / ((alpha + doubled) * (alpha_plus_one + doubled));
        denominator = 1.0 + term * denominator;
        if denominator.abs() < MINIMUM {
            denominator = MINIMUM;
        }
        numerator = 1.0 + term / numerator;
        if numerator.abs() < MINIMUM {
            numerator = MINIMUM;
        }
        denominator = 1.0 / denominator;
        let delta = denominator * numerator;
        result *= delta;
        if (delta - 1.0).abs() < EPSILON {
            break;
        }
    }
    result
}

// Lanczos g=7, n=9 coefficients shared with the repository's PAD statistics.
fn ln_gamma(value: f64) -> f64 {
    const COEFFICIENTS: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_1,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    let adjusted = value - 1.0;
    let shifted = adjusted + 7.5;
    let mut series = COEFFICIENTS[0];
    for (index, coefficient) in COEFFICIENTS.iter().enumerate().skip(1) {
        series += coefficient / (adjusted + index as f64);
    }
    0.5 * (2.0 * std::f64::consts::PI).ln() + (adjusted + 0.5) * shifted.ln() - shifted
        + series.ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(counts: [u64; 4]) -> PairedTable {
        PairedTable::new(counts[0], counts[1], counts[2], counts[3])
    }

    #[test]
    fn paired_mover_wilson_matches_pinned_vectors_and_boundaries() {
        let vectors = [
            ([40, 5, 10, 45], -50_000_000, -111_850_291, 12_850_063),
            ([0, 1, 0, 0], 1_000_000_000, -32_565_478, 1_000_000_000),
            ([0, 0, 1, 0], -1_000_000_000, -1_000_000_000, 32_565_478),
            ([10, 0, 0, 0], 0, -212_941_970, 212_941_970),
            ([0, 0, 0, 10], 0, -212_941_970, 212_941_970),
            ([3, 7, 2, 12], 208_333_333, 10_329_963, 385_896_821),
        ];

        for (counts, estimate, lower, upper) in vectors {
            let result = paired_mover_wilson(table(counts)).unwrap();
            assert_eq!(result.estimate_ppb().get(), estimate, "{counts:?}");
            assert_eq!(result.lower_ppb().get(), lower, "{counts:?}");
            assert_eq!(result.upper_ppb().get(), upper, "{counts:?}");
            assert_eq!(
                paired_mover_wilson_lower(table(counts)).unwrap(),
                result.lower_ppb()
            );
        }

        assert_eq!(
            paired_mover_wilson(table([0, 0, 0, 0])),
            Err(CampaignError::ProtocolInvalid)
        );
        assert_eq!(
            paired_mover_wilson(table([(1_u64 << 53) + 1, 0, 0, 0])),
            Err(CampaignError::ProtocolInvalid)
        );
    }

    #[test]
    fn paired_mover_wilson_is_swap_symmetric_and_baseline_monotone_for_small_tables() {
        for n in 1..=24 {
            for both_fail in 0..=n {
                for candidate_only in 0..=n - both_fail {
                    for baseline_only in 0..=n - both_fail - candidate_only {
                        let both_succeed = n - both_fail - candidate_only - baseline_only;
                        let counts = [both_fail, candidate_only, baseline_only, both_succeed];
                        let result = paired_mover_wilson(table(counts)).unwrap();
                        let swapped = paired_mover_wilson(table([
                            both_fail,
                            baseline_only,
                            candidate_only,
                            both_succeed,
                        ]))
                        .unwrap();
                        assert_eq!(
                            result.lower_ppb().get(),
                            -swapped.upper_ppb().get(),
                            "{counts:?}"
                        );
                        assert_eq!(
                            result.upper_ppb().get(),
                            -swapped.lower_ppb().get(),
                            "{counts:?}"
                        );

                        if both_fail > 0 {
                            let added_baseline = paired_mover_wilson(table([
                                both_fail - 1,
                                candidate_only,
                                baseline_only + 1,
                                both_succeed,
                            ]))
                            .unwrap();
                            assert!(added_baseline.lower_ppb() <= result.lower_ppb());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn paired_mover_wilson_requires_strict_margin_exceedance() {
        let result = paired_mover_wilson(table([3, 7, 2, 12])).unwrap();
        assert_eq!(
            result.decision(result.lower_ppb()),
            IntersectionDecision::Fail
        );
        assert_eq!(
            result.decision(SignedRateDifferencePpb::new(10_329_962).unwrap()),
            IntersectionDecision::Pass
        );
    }

    #[test]
    fn paired_clopper_pearson_matches_exact_one_sided_vectors() {
        let vectors = [
            (0, 10, 258_865_551),
            (0, 20, 139_108_341),
            (1, 20, 216_106_164),
            (20, 20, 1_000_000_000),
        ];
        for (accepts, trials, expected) in vectors {
            assert_eq!(
                clopper_pearson_upper(accepts, trials).unwrap(),
                RatePpb::new(expected).unwrap()
            );
        }
        assert_eq!(
            clopper_pearson_upper(0, 0),
            Err(CampaignError::ProtocolInvalid)
        );
        assert_eq!(
            clopper_pearson_upper(2, 1),
            Err(CampaignError::ProtocolInvalid)
        );
        assert_eq!(
            clopper_pearson_upper(0, (1_u64 << 53) + 1),
            Err(CampaignError::ProtocolInvalid)
        );
    }

    fn reference_normal_cdf(value: f64) -> f64 {
        const P: f64 = 0.231_641_9;
        const B1: f64 = 0.319_381_530;
        const B2: f64 = -0.356_563_782;
        const B3: f64 = 1.781_477_937;
        const B4: f64 = -1.821_255_978;
        const B5: f64 = 1.330_274_429;
        if value < 0.0 {
            return 1.0 - reference_normal_cdf(-value);
        }
        let factor = 1.0 / (1.0 + P * value);
        let polynomial =
            factor * (B1 + factor * (B2 + factor * (B3 + factor * (B4 + factor * B5))));
        1.0 - (-0.5 * value * value).exp() / (2.0 * std::f64::consts::PI).sqrt() * polynomial
    }

    fn reference_power(
        candidate_only_ppb: u64,
        baseline_only_ppb: u64,
        margin_ppb: u64,
        pairs: u64,
    ) -> f64 {
        let scale = crate::RATE_SCALE_PPB as f64;
        let candidate_only = candidate_only_ppb as f64 / scale;
        let baseline_only = baseline_only_ppb as f64 / scale;
        let margin = margin_ppb as f64 / scale;
        let difference = candidate_only - baseline_only;
        let variance = candidate_only + baseline_only - difference * difference;
        reference_normal_cdf(
            (difference + margin) * (pairs as f64 / variance).sqrt() - ONE_SIDED_NORMAL_95,
        )
    }

    #[test]
    fn power_minimum_sample_size_matches_pinned_vectors() {
        let vectors = [
            (20_000_000, 20_000_000, 20_000_000, 619),
            (20_000_000, 20_000_000, 50_000_000, 99),
            (30_000_000, 10_000_000, 20_000_000, 154),
            (10_000_000, 30_000_000, 50_000_000, 273),
        ];
        for (candidate_only, baseline_only, margin, expected_pairs) in vectors {
            let plan = minimum_paired_sample_size(
                RatePpb::new(candidate_only).unwrap(),
                RatePpb::new(baseline_only).unwrap(),
                RatePpb::new(margin).unwrap(),
            )
            .unwrap();
            assert_eq!(plan.minimum_pairs(), expected_pairs);
            assert_eq!(plan.alpha_ppb().get(), 50_000_000);
            assert_eq!(plan.target_power_ppb().get(), 800_000_000);
            assert!(reference_power(candidate_only, baseline_only, margin, expected_pairs) >= 0.8);
            assert!(
                reference_power(candidate_only, baseline_only, margin, expected_pairs - 1) < 0.8
            );
        }
    }

    #[test]
    fn power_rejects_invalid_or_unbounded_plans() {
        let rate = |value| RatePpb::new(value).unwrap();
        for (candidate_only, baseline_only, margin) in [
            (0, 0, 20_000_000),
            (10_000_000, 30_000_000, 20_000_000),
            (600_000_000, 500_000_000, 20_000_000),
            (500_000_000, 500_000_000, 1),
        ] {
            assert_eq!(
                minimum_paired_sample_size(rate(candidate_only), rate(baseline_only), rate(margin),),
                Err(CampaignError::ProtocolInvalid)
            );
        }
    }

    fn cluster(id: &str, observations: &[(u64, u64)]) -> ClusterLatency {
        ClusterLatency::new(
            crate::Identifier::new(id).unwrap(),
            observations
                .iter()
                .map(|&(baseline, candidate)| PairedLatencyUs::new(baseline, candidate))
                .collect(),
        )
    }

    fn seed(prefix: &str) -> crate::Sha256Digest {
        crate::Sha256Digest::new(&format!("{prefix}{}", "0".repeat(64 - prefix.len()))).unwrap()
    }

    #[test]
    fn latency_bootstrap_matches_pinned_vector_and_is_order_independent() {
        let clusters = vec![
            cluster("a", &[(100, 110), (120, 140)]),
            cluster("b", &[(90, 100), (200, 250), (210, 260)]),
            cluster("c", &[(80, 70), (300, 360)]),
        ];
        let protocol_seed = seed("0123456789abcdef");
        let expected = cluster_bootstrap_latency(&clusters, 2_000, &protocol_seed).unwrap();
        assert_eq!(expected.baseline_p50_us(), 120);
        assert_eq!(expected.baseline_p95_us(), 300);
        assert_eq!(expected.candidate_p50_us(), 140);
        assert_eq!(expected.candidate_p95_us(), 360);
        assert_eq!(expected.upper_increase_us(), 60);
        assert_eq!(expected.decision(), IntersectionDecision::Pass);
        assert_eq!(
            cluster_bootstrap_latency(&clusters, 2_000, &protocol_seed).unwrap(),
            expected
        );

        let mut reordered = clusters.clone();
        reordered.reverse();
        for cluster in &mut reordered {
            cluster.observations.reverse();
        }
        assert_eq!(
            cluster_bootstrap_latency(&reordered, 2_000, &protocol_seed).unwrap(),
            expected
        );
    }

    #[test]
    fn latency_bootstrap_uses_seeded_cluster_not_frame_resampling() {
        let mut clusters = Vec::new();
        for index in 0..78 {
            clusters.push(cluster(&format!("cluster-{index:02}"), &[(100, 100)]));
        }
        clusters.push(cluster("cluster-78", &[(100, 1_100)]));
        clusters.push(cluster("cluster-79", &[(100, 1_100)]));

        let zero_seed = seed("0000000000000000");
        let one_seed = seed("0000000000000001");
        let zero_result = cluster_bootstrap_latency(&clusters, 1_000, &zero_seed).unwrap();
        let one_result = cluster_bootstrap_latency(&clusters, 1_000, &one_seed).unwrap();
        assert_eq!(zero_result.upper_increase_us(), 0);
        assert_eq!(zero_result.decision(), IntersectionDecision::Pass);
        assert_eq!(one_result.upper_increase_us(), 1_000);
        assert_eq!(one_result.decision(), IntersectionDecision::Fail);
    }

    #[test]
    fn latency_bootstrap_rejects_empty_duplicate_and_overflowing_inputs() {
        let protocol_seed = seed("0123456789abcdef");
        assert_eq!(
            cluster_bootstrap_latency(&[], 1_000, &protocol_seed),
            Err(CampaignError::ProtocolInvalid)
        );
        assert_eq!(
            cluster_bootstrap_latency(&[cluster("zero-budget", &[(0, 0)])], 0, &protocol_seed),
            Err(CampaignError::ProtocolInvalid)
        );
        assert_eq!(
            cluster_bootstrap_latency(&[cluster("empty", &[])], 1_000, &protocol_seed),
            Err(CampaignError::ProtocolInvalid)
        );
        assert_eq!(
            cluster_bootstrap_latency(
                &[cluster("same", &[(1, 1)]), cluster("same", &[(2, 2)])],
                1_000,
                &protocol_seed,
            ),
            Err(CampaignError::ProtocolInvalid)
        );
        assert_eq!(
            cluster_bootstrap_latency(
                &[cluster("overflow", &[(0, u64::MAX)])],
                u64::MAX,
                &protocol_seed,
            ),
            Err(CampaignError::ProtocolInvalid)
        );
    }

    #[test]
    fn latency_bootstrap_passes_exact_margin_and_fails_one_microsecond_over() {
        let protocol_seed = seed("0123456789abcdef");
        let exact =
            cluster_bootstrap_latency(&[cluster("exact", &[(100, 150)])], 1_000, &protocol_seed)
                .unwrap();
        assert_eq!(exact.allowed_increase_us(), 50);
        assert_eq!(exact.upper_increase_us(), 50);
        assert_eq!(exact.decision(), IntersectionDecision::Pass);

        let over =
            cluster_bootstrap_latency(&[cluster("over", &[(100, 151)])], 1_000, &protocol_seed)
                .unwrap();
        assert_eq!(over.upper_increase_us(), 51);
        assert_eq!(over.decision(), IntersectionDecision::Fail);

        let over_budget = cluster_bootstrap_latency(
            &[cluster("over-budget", &[(1_001, 1_001)])],
            1_000,
            &protocol_seed,
        )
        .unwrap();
        assert_eq!(over_budget.upper_increase_us(), 0);
        assert_eq!(over_budget.decision(), IntersectionDecision::Fail);
    }
}
