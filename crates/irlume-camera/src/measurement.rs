//! camera-tune measurement records (ADR-0023): evidence-grade observations,
//! distinct from any executable capture preference.
//!
//! Every type here is data about a measurement that already happened. Nothing
//! in this module satisfies an admission requirement, seeds runtime rate
//! evidence, replaces observed timestamps, or authorizes amortization; a
//! measurement is an observation, never an instruction.
//!
//! Three facts that are easy to conflate stay distinct by construction
//! ([`RateRound`]): the wall-clock duration of the fill stage, the count and
//! timestamp span of the delivered deltas, and the production `meets_floor`
//! verdict computed by the exact production arithmetic. A stage timer must
//! never silently become a delivered-fps measurement.
//!
//! Stage timings are SPANS, not exclusive durations: spans may nest or
//! overlap (open contains negotiate; the floor window runs inside the
//! capture), so no consumer may sum them. [`SpannedStage`] documents this on
//! the type. Transport stabilization and image-signal stabilization are
//! separate [`StageKind`]s because a stable delivery rate is not itself a
//! definition of exposure settling.
//!
//! Serialization is deterministic: serializing the same completed record
//! produces byte-for-byte identical output, and re-measurement creates a new
//! record. Every struct rejects unknown fields at every level: for supported
//! schema versions a file with an unknown key, an unknown role, or an invalid
//! value is rejected whole, never partially parsed.

use serde::{Deserialize, Serialize};

/// Schema version of the measurement-record format itself.
pub const MEASUREMENT_SCHEMA_VERSION: u32 = 1;

/// Upper bound on recorded rounds per role (bounded-by-construction policy).
pub const MAX_ROUNDS: usize = 4096;

/// Upper bound on string fields carried in a record.
pub const MAX_STRING_BYTES: usize = 256;

/// The stream role a rate observation belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum MeasuredRole {
    Rgb,
    Ir,
}

/// One measured stage. `span_us` is a monotonic span that may nest inside or
/// overlap other stages; consumers must never sum stage spans.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpannedStage {
    pub kind: StageKind,
    pub span_us: u64,
}

/// The closed set of measured stages. `TransportSettle` (delivery reaching a
/// stable rate) and `SignalSettle` (the image signal reaching its named
/// criterion) are distinct because they measure different phenomena.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum StageKind {
    Open,
    Negotiate,
    FirstFrame,
    TransportSettle,
    SignalSettle,
    Flush,
    FloorWindow,
    Burst,
}

/// The percentile basis of an aggregated distribution. v1 has exactly one
/// basis: percentiles are taken over ROUND-LEVEL rates (one rate per
/// completed round), never over individual frame intervals, which describe a
/// different thing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum PercentileBasis {
    RoundLevelRate,
}

/// One completed rate round: the three facts that must stay distinct.
///
/// `deltas` and `timestamp_span_us` derive from the same production
/// timestamp arithmetic the rate gate uses; `wall_clock_us` is a stage
/// timer and MUST NOT be divided into `deltas` to claim a delivered rate;
/// `meets_floor` is the production verdict, recorded as it was computed.
/// `wall_clock_us` and `max_inter_frame_gap_us` are `None` unless the
/// producing path actually observed them separately: recording a stage
/// timer or a gap the source never measured would be fabrication, and a
/// `None` keeps the record honest about what was observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateRound {
    /// Positive delivered deltas counted by the production arithmetic.
    pub deltas: u32,
    /// Span from the first to the last counted delta's timestamp, in us.
    pub timestamp_span_us: u64,
    /// Wall-clock duration of the fill stage when separately staged.
    pub wall_clock_us: Option<u64>,
    /// Largest gap between consecutive counted deltas, when observed.
    pub max_inter_frame_gap_us: Option<u64>,
    /// Continuity errors the production ring reported in this round.
    pub continuity_errors: u32,
    /// The production `meets_floor` verdict for this round.
    pub meets_floor: bool,
}

impl RateRound {
    /// Records a round from the production window facts: the delta count,
    /// the timestamp span, the ring's cumulative drops, the largest
    /// inter-frame gap the window observed, and the production floor
    /// verdict. The stage timer stays `None` because no production path
    /// times the fill separately from the capture yet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRounds`] when the deltas or span are zero or
    /// the observed gap exceeds the span.
    pub fn from_window_facts(
        deltas: u32,
        timestamp_span_us: u64,
        cumulative_drops: u64,
        max_inter_frame_gap_us: u64,
        meets_floor: bool,
    ) -> Result<Self, Error> {
        if deltas == 0 || timestamp_span_us == 0 {
            return Err(Error::InvalidRounds);
        }
        if max_inter_frame_gap_us > timestamp_span_us {
            return Err(Error::InvalidRounds);
        }
        Ok(Self {
            deltas,
            timestamp_span_us,
            wall_clock_us: None,
            max_inter_frame_gap_us: Some(max_inter_frame_gap_us),
            continuity_errors: u32::try_from(cumulative_drops).unwrap_or(u32::MAX),
            meets_floor,
        })
    }
}

/// Aggregated delivered-rate evidence for one role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateEvidence {
    pub rounds_completed: u32,
    pub rounds_failed: u32,
    /// Minimum round-level rate, as exact (deltas, span) pairs.
    pub rate_min: RateRational,
    pub rate_p05: RateRational,
    pub rate_p50: RateRational,
    pub rate_max: RateRational,
    /// Largest inter-frame gap observed across rounds, when any round
    /// observed one.
    pub max_inter_frame_gap_us: Option<u64>,
    /// Total continuity errors across rounds.
    pub continuity_errors: u32,
    pub basis: PercentileBasis,
    /// Every round, in order, so the aggregate is auditable.
    pub rounds: Vec<RateRound>,
}

/// An exact rational rate: `deltas` delivered frames per `span_us`
/// microseconds. Never converted to floating point for comparison; ordering
/// uses cross-multiplication in u128.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateRational {
    pub deltas: u32,
    pub span_us: u64,
}

/// The versioned acceptance policy. Thresholds are recorded with the record
/// BEFORE comparison and are never relaxed after observing results; an
/// unstable baseline remains useful evidence while a weak candidate never
/// becomes an approved recommendation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptancePolicy {
    pub policy_version: u32,
    /// Minimum completed rounds per role for authoritative emission.
    pub min_completed_rounds: u32,
    /// Maximum failed rounds tolerated across roles.
    pub max_failed_rounds: u32,
    /// Any round with a larger observed inter-frame gap fails acceptance.
    /// `None` declines to judge gaps at all; `Some` with rounds that lack
    /// gap observations fails as unverifiable rather than silently passing.
    pub max_inter_frame_gap_us: Option<u64>,
    /// Whether every completed round must have met the production floor.
    pub require_all_rounds_meet_floor: bool,
}

/// Why a record failed its own recorded policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum AcceptanceFailure {
    TooFewCompletedRounds {
        role: MeasuredRole,
        completed: u32,
        required: u32,
    },
    TooManyFailedRounds {
        failed: u32,
        tolerated: u32,
    },
    InterFrameGapExceeded {
        role: MeasuredRole,
        gap_us: u64,
        limit_us: u64,
    },
    GapUnverifiable {
        role: MeasuredRole,
    },
    FloorNotMet {
        role: MeasuredRole,
        round: u32,
    },
}

/// The acceptance verdict of a record, evaluated against the record's own
/// policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub accepted: bool,
    pub failures: Vec<AcceptanceFailure>,
}

/// A completed measurement record. Deterministic serialization; unknown
/// fields rejected at every level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementRecord {
    pub schema_version: u32,
    pub policy: AcceptancePolicy,
    pub tool_revision: String,
    pub measured_at_unix: u64,
    pub method: String,
    pub stages: Vec<SpannedStage>,
    pub rates: Vec<(MeasuredRole, RateEvidence)>,
    /// Rounds the whole arm lost to errors before either role delivered a
    /// window. Arm-level by construction: summing per-role failed counts
    /// would double-count one failed round.
    pub arm_failed_rounds: u32,
    pub acceptance: Acceptance,
}

impl RateRational {
    /// Constructs a valid rational: positive deltas, positive span.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRate`] when either part is zero.
    pub fn new(deltas: u32, span_us: u64) -> Result<Self, Error> {
        if deltas == 0 || span_us == 0 {
            return Err(Error::InvalidRate);
        }
        Ok(Self { deltas, span_us })
    }

    /// Exact ordering by cross-multiplication.
    #[must_use]
    pub fn lt(&self, other: &Self) -> bool {
        u128::from(self.deltas) * u128::from(other.span_us)
            < u128::from(other.deltas) * u128::from(self.span_us)
    }
}

impl RateEvidence {
    /// Aggregates completed rounds into distribution evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized round set or any invalid
    /// round (nonpositive deltas or span, wall clock below the timestamp
    /// span, or a gap exceeding the span).
    pub fn from_rounds(rounds: &[RateRound], rounds_failed: u32) -> Result<Self, Error> {
        if rounds.is_empty() || rounds.len() > MAX_ROUNDS {
            return Err(Error::InvalidRounds);
        }
        for round in rounds {
            if round.deltas == 0 || round.timestamp_span_us == 0 {
                return Err(Error::InvalidRounds);
            }
            if round
                .wall_clock_us
                .is_some_and(|wall| wall < round.timestamp_span_us)
            {
                return Err(Error::InvalidRounds);
            }
            if round
                .max_inter_frame_gap_us
                .is_some_and(|gap| gap > round.timestamp_span_us)
            {
                return Err(Error::InvalidRounds);
            }
        }
        let rates: Vec<RateRational> = rounds
            .iter()
            .map(|round| RateRational {
                deltas: round.deltas,
                span_us: round.timestamp_span_us,
            })
            .collect();
        let mut sorted = rates.clone();
        sorted.sort_by(|a, b| {
            if a.lt(b) {
                std::cmp::Ordering::Less
            } else if b.lt(a) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });
        let nearest_rank = |p: u32| -> RateRational {
            // Nearest-rank percentile over N sorted samples:
            // rank = ceil(p/100 * N), clamped into 1..=N.
            let n = sorted.len();
            let rank = usize::try_from(
                (u64::from(p) * u64::try_from(n).unwrap_or(u64::MAX)).div_ceil(100),
            )
            .unwrap_or(1)
            .clamp(1, n);
            sorted[rank - 1]
        };
        Ok(Self {
            rounds_completed: u32::try_from(rounds.len()).map_err(|_| Error::InvalidRounds)?,
            rounds_failed,
            rate_min: sorted[0],
            rate_p05: nearest_rank(5),
            rate_p50: nearest_rank(50),
            rate_max: sorted[sorted.len() - 1],
            max_inter_frame_gap_us: rounds
                .iter()
                .filter_map(|round| round.max_inter_frame_gap_us)
                .max(),
            continuity_errors: rounds.iter().map(|round| round.continuity_errors).sum(),
            basis: PercentileBasis::RoundLevelRate,
            rounds: rounds.to_vec(),
        })
    }
}

impl MeasurementRecord {
    /// Validates field bounds (schema version, string lengths, role
    /// uniqueness, round counts).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRecord`] describing the first violated bound.
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != MEASUREMENT_SCHEMA_VERSION {
            return Err(Error::InvalidRecord("unsupported schema version"));
        }
        for text in [&self.tool_revision, &self.method] {
            if text.is_empty() || text.len() > MAX_STRING_BYTES {
                return Err(Error::InvalidRecord("string field out of bounds"));
            }
        }
        for (role, _) in &self.rates {
            if self.rates.iter().filter(|(r, _)| r == role).count() > 1 {
                return Err(Error::InvalidRecord("duplicate role"));
            }
        }
        if self.rates.len() > 2 {
            return Err(Error::InvalidRecord("at most two roles"));
        }
        Ok(())
    }

    /// Re-evaluates acceptance against the record's OWN recorded policy.
    /// The policy travels with the evidence so thresholds cannot be swapped
    /// after the fact.
    ///
    /// # Errors
    ///
    /// Returns an error when the record fails [`Self::validate`].
    pub fn evaluate_acceptance(&self) -> Result<Acceptance, Error> {
        self.validate()?;
        let policy = &self.policy;
        let mut failures = Vec::new();
        for (role, evidence) in &self.rates {
            if evidence.rounds_completed < policy.min_completed_rounds {
                failures.push(AcceptanceFailure::TooFewCompletedRounds {
                    role: *role,
                    completed: evidence.rounds_completed,
                    required: policy.min_completed_rounds,
                });
            }
            if let Some(limit_us) = policy.max_inter_frame_gap_us {
                let mut unverifiable = false;
                for round in &evidence.rounds {
                    match round.max_inter_frame_gap_us {
                        Some(gap_us) if gap_us > limit_us => {
                            failures.push(AcceptanceFailure::InterFrameGapExceeded {
                                role: *role,
                                gap_us,
                                limit_us,
                            });
                        }
                        Some(_) => {}
                        None => unverifiable = true,
                    }
                }
                if unverifiable {
                    failures.push(AcceptanceFailure::GapUnverifiable { role: *role });
                }
            }
            if policy.require_all_rounds_meet_floor {
                for (index, round) in evidence.rounds.iter().enumerate() {
                    if !round.meets_floor {
                        failures.push(AcceptanceFailure::FloorNotMet {
                            role: *role,
                            round: u32::try_from(index).unwrap_or(u32::MAX),
                        });
                    }
                }
            }
        }
        if self.arm_failed_rounds > policy.max_failed_rounds {
            failures.push(AcceptanceFailure::TooManyFailedRounds {
                failed: self.arm_failed_rounds,
                tolerated: policy.max_failed_rounds,
            });
        }
        Ok(Acceptance {
            accepted: failures.is_empty(),
            failures,
        })
    }
}

/// Fail-closed construction or validation error for measurement data.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRate,
    InvalidRounds,
    InvalidRecord(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(deltas: u32, span_us: u64, gap_us: u64, meets_floor: bool) -> RateRound {
        RateRound {
            deltas,
            timestamp_span_us: span_us,
            wall_clock_us: Some(span_us + 100),
            max_inter_frame_gap_us: Some(gap_us),
            continuity_errors: 0,
            meets_floor,
        }
    }

    fn round_without_stage_observation(
        deltas: u32,
        span_us: u64,
        drops: u64,
        meets_floor: bool,
    ) -> RateRound {
        RateRound::from_window_facts(deltas, span_us, drops, span_us / 2, meets_floor)
            .expect("valid window facts")
    }

    #[test]
    fn rate_rational_orders_exactly_by_cross_multiplication() {
        let a = RateRational::new(30, 1_000_000).unwrap();
        let b = RateRational::new(25, 1_000_000).unwrap();
        let c = RateRational::new(60, 2_000_000).unwrap();
        assert!(b.lt(&a));
        assert!(!a.lt(&b));
        assert!(!a.lt(&c) && !c.lt(&a));
    }

    #[test]
    fn rate_rational_rejects_zero_parts() {
        assert_eq!(RateRational::new(0, 1), Err(Error::InvalidRate));
        assert_eq!(RateRational::new(1, 0), Err(Error::InvalidRate));
    }

    #[test]
    fn distribution_uses_nearest_rank_over_round_level_rates() {
        // Five round rates: 10, 20, 30, 40, 50 deltas per 1s.
        let rounds: Vec<RateRound> = (1..=5u32)
            .map(|n| round(n * 10, 1_000_000, 100_000, true))
            .collect();
        let evidence = RateEvidence::from_rounds(&rounds, 0).unwrap();
        assert_eq!(evidence.basis, PercentileBasis::RoundLevelRate);
        assert_eq!(evidence.rate_min, RateRational::new(10, 1_000_000).unwrap());
        assert_eq!(evidence.rate_max, RateRational::new(50, 1_000_000).unwrap());
        // Nearest-rank p05 of N=5: ceil(0.05*5)=1 -> the minimum.
        assert_eq!(evidence.rate_p05, evidence.rate_min);
        // Nearest-rank p50 of N=5: ceil(0.5*5)=3 -> the middle sample (30).
        assert_eq!(evidence.rate_p50, RateRational::new(30, 1_000_000).unwrap());
    }

    #[test]
    fn evidence_rejects_empty_oversized_and_inconsistent_rounds() {
        assert_eq!(RateEvidence::from_rounds(&[], 0), Err(Error::InvalidRounds));
        let mut wall_below_span = round(30, 1_000_000, 100_000, true);
        wall_below_span.wall_clock_us = Some(999_999);
        assert_eq!(
            RateEvidence::from_rounds(&[wall_below_span], 0),
            Err(Error::InvalidRounds)
        );
        let mut gap_above_span = round(30, 1_000_000, 2_000_000, true);
        gap_above_span.max_inter_frame_gap_us = Some(2_000_001);
        assert_eq!(
            RateEvidence::from_rounds(&[gap_above_span], 0),
            Err(Error::InvalidRounds)
        );
    }

    #[test]
    fn aggregates_report_max_gap_and_continuity_across_rounds() {
        let rounds = [
            round(30, 1_000_000, 90_000, true),
            round(28, 1_000_000, 625_000, true),
        ];
        let mut jittery = rounds[1];
        jittery.continuity_errors = 2;
        let evidence = RateEvidence::from_rounds(&[rounds[0], jittery], 1).unwrap();
        assert_eq!(evidence.max_inter_frame_gap_us, Some(625_000));
        assert_eq!(evidence.continuity_errors, 2);
        assert_eq!(evidence.rounds_failed, 1);
    }

    fn record_with(policy: AcceptancePolicy, rounds: &[RateRound]) -> MeasurementRecord {
        MeasurementRecord {
            schema_version: MEASUREMENT_SCHEMA_VERSION,
            policy: policy.clone(),
            tool_revision: "irlume camera-tune 0.13".into(),
            measured_at_unix: 1_789_000_000,
            method: "attended decomposition".into(),
            stages: vec![SpannedStage {
                kind: StageKind::FloorWindow,
                span_us: 2_174_000,
            }],
            rates: vec![(
                MeasuredRole::Ir,
                RateEvidence::from_rounds(rounds, 0).expect("valid rounds"),
            )],
            acceptance: Acceptance {
                accepted: true,
                failures: Vec::new(),
            },
            arm_failed_rounds: 0,
        }
    }

    fn lenient_policy() -> AcceptancePolicy {
        AcceptancePolicy {
            policy_version: 1,
            min_completed_rounds: 1,
            max_failed_rounds: 0,
            max_inter_frame_gap_us: None,
            require_all_rounds_meet_floor: true,
        }
    }

    #[test]
    fn acceptance_reports_every_violated_threshold() {
        let policy = AcceptancePolicy {
            policy_version: 1,
            min_completed_rounds: 6,
            max_failed_rounds: 0,
            max_inter_frame_gap_us: Some(100_000),
            require_all_rounds_meet_floor: true,
        };
        let rounds = vec![
            round(30, 1_000_000, 90_000, true),
            round(28, 1_000_000, 625_000, false),
        ];
        let record = record_with(policy, &rounds);
        let verdict = record.evaluate_acceptance().unwrap();
        assert!(!verdict.accepted);
        assert!(verdict
            .failures
            .contains(&AcceptanceFailure::TooFewCompletedRounds {
                role: MeasuredRole::Ir,
                completed: 2,
                required: 6,
            }));
        assert!(verdict
            .failures
            .contains(&AcceptanceFailure::InterFrameGapExceeded {
                role: MeasuredRole::Ir,
                gap_us: 625_000,
                limit_us: 100_000,
            }));
        assert!(verdict.failures.contains(&AcceptanceFailure::FloorNotMet {
            role: MeasuredRole::Ir,
            round: 1,
        }));
    }

    #[test]
    fn acceptance_passes_a_strong_record() {
        let rounds: Vec<RateRound> = (0..6).map(|_| round(30, 1_000_000, 80_000, true)).collect();
        let record = record_with(lenient_policy(), &rounds);
        assert!(record.evaluate_acceptance().unwrap().accepted);
    }

    #[test]
    fn wall_clock_span_and_floor_verdict_stay_three_distinct_facts() {
        let rounds = vec![round(30, 2_174_000, 625_000, false)];
        let evidence = RateEvidence::from_rounds(&rounds, 0).unwrap();
        let stored = evidence.rounds[0];
        assert_eq!(stored.wall_clock_us, Some(2_174_100));
        assert_eq!(stored.timestamp_span_us, 2_174_000);
        assert!(!stored.meets_floor);
        // The round's rate is its deltas over its TIMESTAMP SPAN, never the
        // stage timer.
        assert_eq!(stored.deltas, 30);
    }

    #[test]
    fn serializing_the_same_record_is_byte_identical() {
        let rounds: Vec<RateRound> = (0..3).map(|_| round(30, 1_000_000, 80_000, true)).collect();
        let record = record_with(lenient_policy(), &rounds);
        let first = serde_json::to_vec(&record).expect("serialize");
        let second = serde_json::to_vec(&record).expect("serialize again");
        assert_eq!(first, second);
        let parsed: MeasurementRecord = serde_json::from_slice(&first).expect("round trip");
        assert_eq!(parsed, record);
    }

    #[test]
    fn unknown_keys_reject_at_every_level() {
        let rounds: Vec<RateRound> = (0..3).map(|_| round(30, 1_000_000, 80_000, true)).collect();
        let record = record_with(lenient_policy(), &rounds);
        let mut json: serde_json::Value = serde_json::to_value(&record).expect("serialize");
        // Top level.
        json["speculative_knob"] = serde_json::json!(true);
        assert!(serde_json::from_value::<MeasurementRecord>(json.clone()).is_err());
        // Nested level.
        let mut json: serde_json::Value = serde_json::to_value(&record).expect("serialize");
        json["policy"]["relaxed_after_seeing_results"] = serde_json::json!(true);
        assert!(serde_json::from_value::<MeasurementRecord>(json).is_err());
        // Round level: a tuple serializes as [role, evidence].
        let mut json: serde_json::Value = serde_json::to_value(&record).expect("serialize");
        json["rates"][0][1]["rounds"][0]["estimated_fps"] = serde_json::json!(13.8);
        assert!(serde_json::from_value::<MeasurementRecord>(json).is_err());
    }

    #[test]
    fn from_window_facts_records_production_facts_with_unobserved_stages_none() {
        let round = round_without_stage_observation(30, 2_174_000, 2, false);
        assert_eq!(round.deltas, 30);
        assert_eq!(round.timestamp_span_us, 2_174_000);
        assert_eq!(round.continuity_errors, 2);
        assert!(!round.meets_floor);
        assert_eq!(round.wall_clock_us, None);
        assert_eq!(round.max_inter_frame_gap_us, Some(2_174_000 / 2));
        assert_eq!(
            RateRound::from_window_facts(0, 1_000, 0, 0, true),
            Err(Error::InvalidRounds)
        );
        assert_eq!(
            RateRound::from_window_facts(30, 1_000, 0, 2_000, true),
            Err(Error::InvalidRounds)
        );
    }

    #[test]
    fn a_gap_limit_without_gap_observations_is_unverifiable_not_passed() {
        let policy = AcceptancePolicy {
            policy_version: 1,
            min_completed_rounds: 1,
            max_failed_rounds: 0,
            max_inter_frame_gap_us: Some(100_000),
            require_all_rounds_meet_floor: true,
        };
        let mut unobserved = round_without_stage_observation(30, 1_000_000, 0, true);
        unobserved.max_inter_frame_gap_us = None;
        let rounds = vec![unobserved];
        let record = record_with(policy, &rounds);
        let verdict = record.evaluate_acceptance().unwrap();
        assert!(!verdict.accepted);
        assert!(verdict
            .failures
            .contains(&AcceptanceFailure::GapUnverifiable {
                role: MeasuredRole::Ir
            }));
    }

    #[test]
    fn record_validation_rejects_bad_versions_strings_and_duplicate_roles() {
        let rounds = vec![round(30, 1_000_000, 80_000, true)];
        let mut record = record_with(lenient_policy(), &rounds);
        record.schema_version = 2;
        assert_eq!(
            record.validate(),
            Err(Error::InvalidRecord("unsupported schema version"))
        );

        let mut record = record_with(lenient_policy(), &rounds);
        record.method = String::new();
        assert_eq!(
            record.validate(),
            Err(Error::InvalidRecord("string field out of bounds"))
        );

        let mut record = record_with(lenient_policy(), &rounds);
        let evidence = record.rates[0].1.clone();
        record.rates.push((MeasuredRole::Rgb, evidence));
        assert!(record.validate().is_ok());
        record.rates.push(record.rates[0].clone());
        assert_eq!(
            record.validate(),
            Err(Error::InvalidRecord("duplicate role"))
        );
    }
}
