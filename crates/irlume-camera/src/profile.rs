// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Pure contracts for exact camera transport profiles and qualification ranking.

use std::{
    hash::{Hash, Hasher},
    num::{NonZeroU128, NonZeroU32, NonZeroU64},
};

use serde::{Deserialize, Serialize};

use crate::{contracts::StreamRole, frame_interval::FrameInterval};

const MAX_PROFILE_ID_BYTES: usize = 256;
const FIXED_POINT_MILLION: u128 = 1_000_000;

/// A camera pixel format decoded by the existing capture boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum DecodedPixelFormat {
    /// Packed YUYV 4:2:2, two bytes per pixel.
    Yuyv,
    /// Planar NV12 4:2:0, three bytes per two pixels.
    Nv12,
    /// Eight-bit greyscale, one byte per pixel.
    Grey8,
    /// Sixteen-bit greyscale, two bytes per pixel.
    Grey16,
}

impl DecodedPixelFormat {
    /// Maps an exact camera fourcc only when the existing capture path can decode it.
    #[must_use]
    pub const fn from_fourcc(fourcc: [u8; 4]) -> Option<Self> {
        match &fourcc {
            b"YUYV" => Some(Self::Yuyv),
            b"NV12" => Some(Self::Nv12),
            b"GREY" | b"Y8  " | b"Y800" => Some(Self::Grey8),
            b"Y16 " | b"Y10 " | b"Y12 " => Some(Self::Grey16),
            _ => None,
        }
    }

    fn bytes_per_frame(self, width: u32, height: u32) -> Option<u128> {
        let pixels = u128::from(width).checked_mul(u128::from(height))?;
        match self {
            Self::Yuyv | Self::Grey16 => pixels.checked_mul(2),
            Self::Nv12 => pixels.checked_mul(3)?.checked_add(1)?.checked_div(2),
            Self::Grey8 => Some(pixels),
        }
    }
}

/// Ordering used to acquire the RGB and IR streams in one transport profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSchedule {
    /// Capture one stream after the other.
    Sequential,
    /// Hold and drain both streams together.
    Concurrent,
}

/// An exact decoded format, geometry, interval, and logical stream role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamTuple {
    role: StreamRole,
    format: DecodedPixelFormat,
    width: NonZeroU32,
    height: NonZeroU32,
    interval: FrameInterval,
}

impl Hash for StreamTuple {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(&self.role).hash(state);
        self.format.hash(state);
        self.width.hash(state);
        self.height.hash(state);
        self.interval.hash(state);
    }
}

impl StreamTuple {
    /// Constructs an exact stream tuple with nonzero geometry.
    ///
    /// # Errors
    ///
    /// Returns an error when width or height is zero.
    pub fn new(
        role: StreamRole,
        format: DecodedPixelFormat,
        width: u32,
        height: u32,
        interval: FrameInterval,
    ) -> Result<Self, ProfileError> {
        Ok(Self {
            role,
            format,
            width: NonZeroU32::new(width).ok_or(ProfileError::ZeroWidth)?,
            height: NonZeroU32::new(height).ok_or(ProfileError::ZeroHeight)?,
            interval,
        })
    }

    /// Returns the logical stream role.
    #[must_use]
    pub const fn role(&self) -> StreamRole {
        self.role
    }

    /// Returns the decoded pixel format.
    #[must_use]
    pub const fn format(&self) -> DecodedPixelFormat {
        self.format
    }

    /// Returns the nonzero width in pixels.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width.get()
    }

    /// Returns the nonzero height in pixels.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height.get()
    }

    /// Returns the exact reduced frame interval.
    #[must_use]
    pub const fn interval(&self) -> FrameInterval {
        self.interval
    }

    /// Returns nominal decoded bytes per second, rounded up conservatively.
    ///
    /// `None` means checked arithmetic could not represent the payload cost.
    #[must_use]
    pub fn nominal_payload_bytes_per_second(&self) -> Option<u128> {
        let bytes_per_frame = self
            .format
            .bytes_per_frame(self.width.get(), self.height.get())?;
        let (interval_numerator, interval_denominator) = self.interval.parts();
        let numerator = bytes_per_frame.checked_mul(u128::from(interval_denominator))?;
        checked_ceil_div(numerator, u128::from(interval_numerator))
    }
}

/// One exact RGB and IR transport profile and capture schedule.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PairTransportProfile {
    id: String,
    requested_rgb: StreamTuple,
    accepted_rgb: StreamTuple,
    requested_ir: StreamTuple,
    accepted_ir: StreamTuple,
    schedule: CaptureSchedule,
}

impl PairTransportProfile {
    /// Constructs a bounded profile with an RGB tuple followed by an IR tuple.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or control-bearing identifier,
    /// or when either stream has the wrong logical role.
    pub fn new(
        id: impl Into<String>,
        rgb: StreamTuple,
        ir: StreamTuple,
        schedule: CaptureSchedule,
    ) -> Result<Self, ProfileError> {
        Self::from_negotiated(id, rgb.clone(), rgb, ir.clone(), ir, schedule)
    }

    pub(crate) fn from_negotiated(
        id: impl Into<String>,
        requested_rgb: StreamTuple,
        accepted_rgb: StreamTuple,
        requested_ir: StreamTuple,
        accepted_ir: StreamTuple,
        schedule: CaptureSchedule,
    ) -> Result<Self, ProfileError> {
        let id = id.into();
        if id.is_empty() {
            return Err(ProfileError::EmptyProfileId);
        }
        if id.len() > MAX_PROFILE_ID_BYTES || id.chars().any(char::is_control) {
            return Err(ProfileError::InvalidProfileId);
        }
        if requested_rgb.role != StreamRole::Rgb
            || accepted_rgb.role != StreamRole::Rgb
            || requested_ir.role != StreamRole::Ir
            || accepted_ir.role != StreamRole::Ir
        {
            return Err(ProfileError::WrongStreamRole);
        }
        Ok(Self {
            id,
            requested_rgb,
            accepted_rgb,
            requested_ir,
            accepted_ir,
            schedule,
        })
    }

    /// Returns the stable profile identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the exact RGB stream tuple.
    #[must_use]
    pub const fn rgb(&self) -> &StreamTuple {
        &self.requested_rgb
    }

    /// Returns the exact IR stream tuple.
    #[must_use]
    pub const fn ir(&self) -> &StreamTuple {
        &self.requested_ir
    }

    /// Returns the exact requested RGB stream tuple.
    #[must_use]
    pub const fn requested_rgb(&self) -> &StreamTuple {
        &self.requested_rgb
    }

    /// Returns the exact driver-accepted RGB stream tuple.
    #[must_use]
    pub const fn accepted_rgb(&self) -> &StreamTuple {
        &self.accepted_rgb
    }

    /// Returns the exact requested IR stream tuple.
    #[must_use]
    pub const fn requested_ir(&self) -> &StreamTuple {
        &self.requested_ir
    }

    /// Returns the exact driver-accepted IR stream tuple.
    #[must_use]
    pub const fn accepted_ir(&self) -> &StreamTuple {
        &self.accepted_ir
    }

    /// Returns whether neither role was adjusted by the driver.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.requested_rgb == self.accepted_rgb && self.requested_ir == self.accepted_ir
    }

    /// Returns the capture schedule.
    #[must_use]
    pub const fn schedule(&self) -> CaptureSchedule {
        self.schedule
    }

    /// Returns the checked sum of both streams' nominal decoded payloads.
    #[must_use]
    pub fn nominal_payload_bytes_per_second(&self) -> Option<u128> {
        self.requested_rgb
            .nominal_payload_bytes_per_second()?
            .checked_add(self.requested_ir.nominal_payload_bytes_per_second()?)
    }
}

/// One fail-closed qualification gate for a transport profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileGate {
    /// Exact negotiation and readback.
    Negotiation,
    /// Delivered transport behavior.
    Transport,
    /// Bright, backlit, low-light, or dark-IR signal quality.
    Signal,
    /// Face detection regression.
    Detection,
    /// Identity recognition regression.
    Recognition,
    /// Liveness regression.
    Liveness,
    /// Presentation-attack detection regression.
    Pad,
    /// End-to-end latency policy.
    Latency,
}

/// Fixed scene slots supported by profile qualification and evaluation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationScene {
    Lit,
    Backlit,
    LowLight,
    DarkIr,
}

/// Final hard-gate disposition for one candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateVerdict {
    /// Every applicable qualification gate passed.
    Passed,
    /// The named qualification gate rejected the candidate.
    Rejected(ProfileGate),
}

/// Qualified transport metrics used only after hard-gate disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualifiedProfileMetrics {
    profile: PairTransportProfile,
    nominal_payload_bytes_per_second: u128,
    p95_latency_ms: u64,
    verdict: CandidateVerdict,
}

impl QualifiedProfileMetrics {
    /// Binds latency and a hard-gate verdict to an exact profile.
    ///
    /// Nominal payload is derived from the profile and cannot be supplied by a
    /// caller independently.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile's checked nominal payload is not
    /// representable.
    pub fn new(
        profile: PairTransportProfile,
        p95_latency_ms: u64,
        verdict: CandidateVerdict,
    ) -> Result<Self, ProfileError> {
        let nominal_payload_bytes_per_second = profile
            .nominal_payload_bytes_per_second()
            .ok_or(ProfileError::NominalPayloadOverflow)?;
        Ok(Self {
            profile,
            nominal_payload_bytes_per_second,
            p95_latency_ms,
            verdict,
        })
    }

    /// Returns the stable profile identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        self.profile.id()
    }

    /// Returns the exact transport profile.
    #[must_use]
    pub const fn profile(&self) -> &PairTransportProfile {
        &self.profile
    }

    /// Returns nominal decoded payload bytes per second.
    #[must_use]
    pub const fn nominal_payload_bytes_per_second(&self) -> u128 {
        self.nominal_payload_bytes_per_second
    }

    /// Returns measured p95 end-to-end authentication latency in milliseconds.
    #[must_use]
    pub const fn p95_latency_ms(&self) -> u64 {
        self.p95_latency_ms
    }

    /// Returns the hard-gate verdict.
    #[must_use]
    pub const fn verdict(&self) -> CandidateVerdict {
        self.verdict
    }
}

/// Fixed, versioned normalization denominators for balanced ranking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RankingBudget {
    version: NonZeroU32,
    payload_bytes_per_second: NonZeroU128,
    p95_latency_ms: NonZeroU64,
}

impl RankingBudget {
    /// Constructs a fixed nonzero policy budget.
    ///
    /// # Errors
    ///
    /// Returns an error when the version or either denominator is zero.
    pub fn new(
        version: u32,
        payload_bytes_per_second: u128,
        p95_latency_ms: u64,
    ) -> Result<Self, ProfileError> {
        Ok(Self {
            version: NonZeroU32::new(version).ok_or(ProfileError::InvalidRankingBudget)?,
            payload_bytes_per_second: NonZeroU128::new(payload_bytes_per_second)
                .ok_or(ProfileError::InvalidRankingBudget)?,
            p95_latency_ms: NonZeroU64::new(p95_latency_ms)
                .ok_or(ProfileError::InvalidRankingBudget)?,
        })
    }

    /// Returns the policy version.
    #[must_use]
    pub const fn version(self) -> u32 {
        self.version.get()
    }
}

/// Returns passing candidates that no other passing candidate improves on both axes.
#[must_use]
pub fn pareto_frontier(candidates: &[QualifiedProfileMetrics]) -> Vec<&QualifiedProfileMetrics> {
    candidates
        .iter()
        .filter(|candidate| candidate.verdict == CandidateVerdict::Passed)
        .filter(|candidate| {
            !candidates.iter().any(|other| {
                other.verdict == CandidateVerdict::Passed && dominates(other, candidate)
            })
        })
        .collect()
}

/// Selects the lowest fixed-budget payload-plus-latency cost among passing profiles.
///
/// Equal costs prefer lower nominal payload, then lexicographically lower profile ID.
#[must_use]
pub fn rank_balanced(
    candidates: &[QualifiedProfileMetrics],
    budget: RankingBudget,
) -> Option<&QualifiedProfileMetrics> {
    pareto_frontier(candidates)
        .into_iter()
        .map(|candidate| (candidate, normalized_cost(candidate, budget)))
        .min_by(|(left, left_cost), (right, right_cost)| {
            left_cost
                .cmp(right_cost)
                .then_with(|| {
                    left.nominal_payload_bytes_per_second
                        .cmp(&right.nominal_payload_bytes_per_second)
                })
                .then_with(|| left.id().cmp(right.id()))
        })
        .map(|(candidate, _)| candidate)
}

fn dominates(left: &QualifiedProfileMetrics, right: &QualifiedProfileMetrics) -> bool {
    let payload_no_worse =
        left.nominal_payload_bytes_per_second <= right.nominal_payload_bytes_per_second;
    let latency_no_worse = left.p95_latency_ms <= right.p95_latency_ms;
    let improves_one = left.nominal_payload_bytes_per_second
        < right.nominal_payload_bytes_per_second
        || left.p95_latency_ms < right.p95_latency_ms;
    payload_no_worse && latency_no_worse && improves_one
}

fn normalized_cost(candidate: &QualifiedProfileMetrics, budget: RankingBudget) -> u128 {
    let payload = candidate
        .nominal_payload_bytes_per_second
        .checked_mul(FIXED_POINT_MILLION)
        .expect("derived profile payload fits fixed-point normalization")
        / budget.payload_bytes_per_second.get();
    let latency = u128::from(candidate.p95_latency_ms)
        .checked_mul(FIXED_POINT_MILLION)
        .expect("u64 latency fits fixed-point normalization")
        / u128::from(budget.p95_latency_ms.get());
    payload
        .checked_add(latency)
        .expect("valid profile and latency costs fit their fixed-point sum")
}

fn checked_ceil_div(numerator: u128, denominator: u128) -> Option<u128> {
    let quotient = numerator.checked_div(denominator)?;
    let remainder = numerator.checked_rem(denominator)?;
    quotient.checked_add(u128::from(remainder != 0))
}

/// Invalid pure transport-profile or ranking contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileError {
    /// Stream width was zero.
    ZeroWidth,
    /// Stream height was zero.
    ZeroHeight,
    /// Profile identifier was empty.
    EmptyProfileId,
    /// Profile identifier was oversized or contained a control character.
    InvalidProfileId,
    /// RGB or IR tuple had the wrong logical role.
    WrongStreamRole,
    /// Ranking version or a normalization denominator was zero.
    InvalidRankingBudget,
    /// The exact profile's nominal payload was not representable.
    NominalPayloadOverflow,
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ZeroWidth => "stream tuple width is zero",
            Self::ZeroHeight => "stream tuple height is zero",
            Self::EmptyProfileId => "transport profile identifier is empty",
            Self::InvalidProfileId => "transport profile identifier is invalid",
            Self::WrongStreamRole => "transport profile stream role is invalid",
            Self::InvalidRankingBudget => "ranking budget contains zero",
            Self::NominalPayloadOverflow => "transport profile nominal payload overflowed",
        })
    }
}

impl std::error::Error for ProfileError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{contracts::StreamRole, frame_interval::FrameInterval};

    fn interval(numerator: u32, denominator: u32) -> FrameInterval {
        FrameInterval::new(numerator, denominator).unwrap()
    }

    fn stream(
        role: StreamRole,
        format: DecodedPixelFormat,
        width: u32,
        height: u32,
        fps: u32,
    ) -> StreamTuple {
        StreamTuple::new(role, format, width, height, interval(1, fps)).unwrap()
    }

    fn profile(id: &str) -> PairTransportProfile {
        PairTransportProfile::new(
            id,
            stream(StreamRole::Rgb, DecodedPixelFormat::Yuyv, 640, 480, 15),
            stream(StreamRole::Ir, DecodedPixelFormat::Grey8, 640, 400, 15),
            CaptureSchedule::Concurrent,
        )
        .unwrap()
    }

    fn profile_with_payload(id: &str, payload_bytes_per_second: u32) -> PairTransportProfile {
        assert!(payload_bytes_per_second >= 2);
        PairTransportProfile::new(
            id,
            stream(
                StreamRole::Rgb,
                DecodedPixelFormat::Grey8,
                1,
                payload_bytes_per_second - 1,
                1,
            ),
            stream(StreamRole::Ir, DecodedPixelFormat::Grey8, 1, 1, 1),
            CaptureSchedule::Sequential,
        )
        .unwrap()
    }

    fn candidate(
        id: &str,
        payload_bytes_per_second: u32,
        p95_latency_ms: u64,
        verdict: CandidateVerdict,
    ) -> QualifiedProfileMetrics {
        QualifiedProfileMetrics::new(
            profile_with_payload(id, payload_bytes_per_second),
            p95_latency_ms,
            verdict,
        )
        .unwrap()
    }

    fn budget() -> RankingBudget {
        RankingBudget::new(1, 20_000_000, 10_000).unwrap()
    }

    #[test]
    fn stream_tuple_rejects_zero_geometry_and_retains_exact_interval() {
        let exact = interval(2, 30);
        assert_eq!(
            StreamTuple::new(StreamRole::Rgb, DecodedPixelFormat::Yuyv, 0, 480, exact,),
            Err(ProfileError::ZeroWidth)
        );
        assert_eq!(
            StreamTuple::new(StreamRole::Rgb, DecodedPixelFormat::Yuyv, 640, 0, exact,),
            Err(ProfileError::ZeroHeight)
        );

        let tuple =
            StreamTuple::new(StreamRole::Rgb, DecodedPixelFormat::Yuyv, 640, 480, exact).unwrap();
        assert_eq!(tuple.interval().parts(), (1, 15));
    }

    #[test]
    fn decoded_formats_have_bounded_nominal_payloads() {
        let cases = [
            (DecodedPixelFormat::Yuyv, 18_432_000),
            (DecodedPixelFormat::Nv12, 13_824_000),
            (DecodedPixelFormat::Grey8, 9_216_000),
            (DecodedPixelFormat::Grey16, 18_432_000),
        ];
        for (format, expected) in cases {
            let tuple = stream(StreamRole::Rgb, format, 640, 480, 30);
            assert_eq!(tuple.nominal_payload_bytes_per_second(), Some(expected));
        }

        let fractional_fps = StreamTuple::new(
            StreamRole::Rgb,
            DecodedPixelFormat::Grey8,
            1,
            1,
            interval(2, 3),
        )
        .unwrap();
        assert_eq!(fractional_fps.nominal_payload_bytes_per_second(), Some(2));
    }

    #[test]
    fn compressed_and_unknown_fourcc_are_not_decodable() {
        assert_eq!(
            DecodedPixelFormat::from_fourcc(*b"YUYV"),
            Some(DecodedPixelFormat::Yuyv)
        );
        assert_eq!(
            DecodedPixelFormat::from_fourcc(*b"NV12"),
            Some(DecodedPixelFormat::Nv12)
        );
        assert_eq!(
            DecodedPixelFormat::from_fourcc(*b"GREY"),
            Some(DecodedPixelFormat::Grey8)
        );
        assert_eq!(
            DecodedPixelFormat::from_fourcc(*b"Y16 "),
            Some(DecodedPixelFormat::Grey16)
        );
        assert_eq!(
            DecodedPixelFormat::from_fourcc(*b"Y8  "),
            Some(DecodedPixelFormat::Grey8)
        );
        assert_eq!(
            DecodedPixelFormat::from_fourcc(*b"Y800"),
            Some(DecodedPixelFormat::Grey8)
        );
        assert_eq!(
            DecodedPixelFormat::from_fourcc(*b"Y10 "),
            Some(DecodedPixelFormat::Grey16)
        );
        assert_eq!(
            DecodedPixelFormat::from_fourcc(*b"Y12 "),
            Some(DecodedPixelFormat::Grey16)
        );
        assert_eq!(DecodedPixelFormat::from_fourcc(*b"MJPG"), None);
        assert_eq!(DecodedPixelFormat::from_fourcc(*b"????"), None);
    }

    #[test]
    fn pair_profile_rejects_invalid_ids_and_roles() {
        let rgb = stream(StreamRole::Rgb, DecodedPixelFormat::Yuyv, 640, 480, 15);
        let ir = stream(StreamRole::Ir, DecodedPixelFormat::Grey8, 640, 400, 15);
        assert_eq!(
            PairTransportProfile::new("", rgb.clone(), ir.clone(), CaptureSchedule::Sequential),
            Err(ProfileError::EmptyProfileId)
        );
        assert_eq!(
            PairTransportProfile::new(
                "bad\nid",
                rgb.clone(),
                ir.clone(),
                CaptureSchedule::Sequential,
            ),
            Err(ProfileError::InvalidProfileId)
        );
        assert_eq!(
            PairTransportProfile::new(
                "x".repeat(257),
                rgb.clone(),
                ir.clone(),
                CaptureSchedule::Sequential,
            ),
            Err(ProfileError::InvalidProfileId)
        );
        assert_eq!(
            PairTransportProfile::new("swapped", ir, rgb, CaptureSchedule::Sequential),
            Err(ProfileError::WrongStreamRole)
        );
    }

    #[test]
    fn pair_payload_is_the_checked_sum_of_both_streams() {
        assert_eq!(
            profile("asus-15-15").nominal_payload_bytes_per_second(),
            Some(13_056_000)
        );
    }

    #[test]
    fn qualified_metrics_derive_payload_from_the_bound_profile() {
        let metrics = QualifiedProfileMetrics::new(
            profile("derived-payload"),
            6_400,
            CandidateVerdict::Passed,
        )
        .unwrap();

        assert_eq!(metrics.nominal_payload_bytes_per_second(), 13_056_000);
    }

    #[test]
    fn maximum_valid_profile_remains_rankable_with_minimum_budgets() {
        let maximum_stream = |role| {
            StreamTuple::new(
                role,
                DecodedPixelFormat::Yuyv,
                u32::MAX,
                u32::MAX,
                interval(1, u32::MAX),
            )
            .unwrap()
        };
        let maximum = PairTransportProfile::new(
            "maximum",
            maximum_stream(StreamRole::Rgb),
            maximum_stream(StreamRole::Ir),
            CaptureSchedule::Concurrent,
        )
        .unwrap();
        let candidate =
            QualifiedProfileMetrics::new(maximum, u64::MAX, CandidateVerdict::Passed).unwrap();

        assert_eq!(
            candidate.nominal_payload_bytes_per_second(),
            316_912_649_835_696_421_541_200_789_500
        );
        assert_eq!(
            rank_balanced(
                std::slice::from_ref(&candidate),
                RankingBudget::new(1, 1, 1).unwrap(),
            )
            .map(QualifiedProfileMetrics::id),
            Some("maximum")
        );
    }

    #[test]
    fn pareto_frontier_removes_a_profile_worse_on_both_axes() {
        let better = candidate("better", 13_000_000, 6_000, CandidateVerdict::Passed);
        let dominated = candidate("dominated", 18_000_000, 7_000, CandidateVerdict::Passed);
        let candidates = [dominated, better];
        let ids: Vec<_> = pareto_frontier(&candidates)
            .into_iter()
            .map(QualifiedProfileMetrics::id)
            .collect();
        assert_eq!(ids, vec!["better"]);
    }

    #[test]
    fn pareto_and_balanced_ranking_never_admit_failed_quality() {
        let passing = candidate("asus-15-15", 13_056_000, 6_400, CandidateVerdict::Passed);
        let faster_but_failed = candidate(
            "failed-pad",
            9_000_000,
            5_000,
            CandidateVerdict::Rejected(ProfileGate::Pad),
        );
        let candidates = [faster_but_failed, passing];
        assert_eq!(
            pareto_frontier(&candidates)
                .into_iter()
                .map(QualifiedProfileMetrics::id)
                .collect::<Vec<_>>(),
            vec!["asus-15-15"]
        );
        assert_eq!(
            rank_balanced(&candidates, budget()).unwrap().id(),
            "asus-15-15"
        );
    }

    #[test]
    fn balanced_ranking_uses_fixed_budgets_not_candidate_extrema() {
        let lower_fixed_cost = candidate("balanced", 50, 20, CandidateVerdict::Passed);
        let other = candidate("payload-light", 20, 60, CandidateVerdict::Passed);
        let unrelated = candidate("dominated", 50, 100, CandidateVerdict::Passed);
        let fixed = RankingBudget::new(7, 100, 100).unwrap();

        assert_eq!(
            rank_balanced(&[other.clone(), lower_fixed_cost.clone()], fixed)
                .unwrap()
                .id(),
            "balanced"
        );
        assert_eq!(
            rank_balanced(&[other, lower_fixed_cost, unrelated], fixed)
                .unwrap()
                .id(),
            "balanced"
        );
    }

    #[test]
    fn balanced_ranking_breaks_equal_scores_by_payload_then_id() {
        let payload_light = candidate("zeta", 2_000_000, 8_000, CandidateVerdict::Passed);
        let latency_light = candidate("alpha", 8_000_000, 2_000, CandidateVerdict::Passed);
        let equal_payload_zeta = candidate("zeta", 2_000_000, 8_000, CandidateVerdict::Passed);
        let equal_payload_alpha = candidate("alpha", 2_000_000, 8_000, CandidateVerdict::Passed);
        let fixed = RankingBudget::new(1, 10_000_000, 10_000).unwrap();

        assert_eq!(
            rank_balanced(&[latency_light, payload_light], fixed)
                .unwrap()
                .id(),
            "zeta"
        );
        assert_eq!(
            rank_balanced(&[equal_payload_zeta, equal_payload_alpha], fixed)
                .unwrap()
                .id(),
            "alpha"
        );
    }

    #[test]
    fn ranking_budget_rejects_zero_version_and_denominators() {
        assert_eq!(
            RankingBudget::new(0, 1, 1),
            Err(ProfileError::InvalidRankingBudget)
        );
        assert_eq!(
            RankingBudget::new(1, 0, 1),
            Err(ProfileError::InvalidRankingBudget)
        );
        assert_eq!(
            RankingBudget::new(1, 1, 0),
            Err(ProfileError::InvalidRankingBudget)
        );
    }
}
