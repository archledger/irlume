//! The identity arms that turn match scores into a grant, as pure
//! functions. Authentication calls them, and [`decision_fingerprint`] runs
//! exactly this code on fixed synthetic inputs, so a certified NPU entry is
//! bound to the decision it was measured through (ADR-0022 §3).
//!
//! Gates (liveness, PAD, the per-user IR floor, scene routing) run before
//! these arms and stay in the engine: they decide whether an attempt may be
//! scored at all, not what a score means.

use super::{
    ir_assessment::IdentityThresholds, ir_match_in, rgb_primary_grant_admissible, IrMatch,
};
use irlume_core::fusion::{self, Fusion};
use sha2::{Digest, Sha256};

/// Best RGB match over labeled templates: (score, profile name). `>` keeps
/// the first template on a tie.
pub(super) fn best_rgb(probe: &[f32], scans: &[(&str, &str, &[f32])]) -> (f32, String) {
    // Fold over borrowed names and allocate only the winner's String, not
    // one per template.
    let (score, who) = scans
        .iter()
        .map(|(profile, _scan, template)| (irlume_vision::align::cosine(probe, template), *profile))
        .fold(
            (f32::NEG_INFINITY, ""),
            |acc, x| if x.0 > acc.0 { x } else { acc },
        );
    (score, who.to_string())
}

/// The RGB-primary arm: the threshold for `templates` templates of base
/// `base`, and whether `score` grants on it. A sequential-schedule pair
/// never grants on RGB alone (ADR-0014).
pub(super) fn rgb_arm(score: f32, base: f32, templates: usize, sequential: bool) -> (f32, bool) {
    let threshold = irlume_core::scaled_threshold(base, templates);
    (
        threshold,
        rgb_primary_grant_admissible(score, threshold, sequential),
    )
}

/// Which lit IR arm granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IrArm {
    Fusion,
    Fallback,
    Centroid,
}

/// The lit-path IR arms after the RGB-primary arm did not grant: their
/// values for tracing, and the arm that granted, if any.
#[derive(Clone, Copy, Debug)]
pub(super) struct IrArms {
    pub(super) fusion: Fusion,
    pub(super) fallback_threshold: f32,
    pub(super) centroid_threshold: Option<f32>,
    pub(super) grant: Option<IrArm>,
}

/// The lit-path IR arms for an IR match with templates: brightness-weighted
/// fusion (never for a sequential-schedule pair, ADR-0014), the pure IR
/// fallback, and the calibrated centroid at the base threshold scaled by
/// profile count (ADR-0004).
pub(super) fn lit_ir_arms(
    rgb_score: f32,
    rgb_brightness: f32,
    matched: &IrMatch,
    ir_brightness: f32,
    sequential: bool,
    adapter: bool,
    profiles: usize,
) -> IrArms {
    let ir_score = matched.best;
    let fusion = fusion::fuse(
        fusion::rgb_genuine_prob(rgb_score),
        fusion::rgb_quality_weight(rgb_brightness),
        fusion::ir_genuine_prob(ir_score),
        fusion::ir_quality_weight(true, ir_brightness),
    );
    let base = if adapter {
        irlume_core::IR_ADAPTED_MATCH_THRESHOLD
    } else {
        irlume_core::IR_MATCH_THRESHOLD
    };
    let fallback_threshold =
        irlume_core::scaled_threshold(base, matched.n_templates) + irlume_core::IR_FALLBACK_MARGIN;
    let centroid_threshold = matched
        .centroid
        .as_ref()
        .map(|_| irlume_core::scaled_threshold(base, profiles) + irlume_core::IR_FALLBACK_MARGIN);
    let grant = if fusion.grant && !sequential {
        Some(IrArm::Fusion)
    } else if ir_score >= fallback_threshold {
        Some(IrArm::Fallback)
    } else if matched
        .centroid
        .as_ref()
        .zip(centroid_threshold)
        .is_some_and(|((score, _), threshold)| *score >= threshold)
    {
        Some(IrArm::Centroid)
    } else {
        None
    };
    IrArms {
        fusion,
        fallback_threshold,
        centroid_threshold,
        grant,
    }
}

/// How often each arm granted and denied over the fingerprint's grid, so a
/// test can show the grid crosses every boundary.
#[derive(Debug, Default)]
pub(super) struct Coverage {
    pub(super) rgb: [usize; 2],
    pub(super) fusion: [usize; 2],
    pub(super) fallback: [usize; 2],
    pub(super) centroid: [usize; 2],
    pub(super) dark_best: [usize; 2],
    pub(super) dark_centroid: [usize; 2],
    pub(super) calibrated: usize,
}

/// Count a grid outcome for [`Coverage`] and return it as a byte.
fn count(value: bool, counts: &mut [usize; 2]) -> u8 {
    counts[usize::from(value)] += 1;
    u8::from(value)
}

/// The recognizer space the fingerprint's synthetic templates live in.
const SPACE: &str = "embed:decision-fingerprint";

/// A unit vector of `dim` components, varied by `seed`.
fn unit(dim: usize, seed: usize) -> Vec<f32> {
    let mut v: Vec<f32> = (0..dim)
        .map(|i| (((i + 1) * (seed * 7 + 3)) % 17) as f32 - 8.0 + 0.5 * seed as f32)
        .collect();
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    for x in &mut v {
        *x /= norm;
    }
    v
}

fn scan(name: &str, seed: usize, dim: usize) -> irlume_core::storage::FaceScan {
    irlume_core::storage::FaceScan {
        name: name.into(),
        rgb: unit(dim, seed),
        ir: Some(unit(dim, seed + 40)),
        ir_space: Some(irlume_core::storage::IR_RAW_SPACE.into()),
        embed_space: Some(SPACE.into()),
        embed_producer: None,
        ir_center_edge_ratio: 0.0,
        ir_brightness: 0.0,
        pitch: 0.0,
        captured_at: None,
    }
}

/// A synthetic enrollment: one profile with an IR calibration fitted as
/// enrollment fits it, and one without.
fn enrollment(dim: usize) -> irlume_core::storage::Enrollment {
    let mut enrollment = irlume_core::storage::Enrollment::new("fingerprint");
    for (p, calibrated) in [(0usize, true), (1, false)] {
        let scans: Vec<_> = (0..4)
            .map(|s| scan(&format!("p{p}s{s}"), p * 10 + s, dim))
            .collect();
        let mut ir_calibs = std::collections::BTreeMap::new();
        if calibrated {
            let ir: Vec<Vec<f32>> = scans.iter().filter_map(|s| s.ir.clone()).collect();
            let rgb: Vec<Vec<f32>> = scans.iter().map(|s| s.rgb.clone()).collect();
            if let Some(calibration) = irlume_core::calib::fit(&ir, &rgb) {
                ir_calibs.insert(SPACE.to_owned(), calibration);
            }
        }
        enrollment.profiles.push(irlume_core::storage::FaceProfile {
            name: format!("profile{p}"),
            scans,
            ir_calib: None,
            ir_calibs,
        });
    }
    enrollment
}

/// Run the production decision code over a fixed synthetic grid, writing
/// every output to `out`.
pub(super) fn decision_grid(out: &mut dyn FnMut(&[u8]), coverage: &mut Coverage) {
    let f = |out: &mut dyn FnMut(&[u8]), value: f32| out(&value.to_bits().to_le_bytes());
    // RGB matching over labeled templates.
    let dim = 8;
    let templates: Vec<Vec<f32>> = (0..6).map(|s| unit(dim, s)).collect();
    let labeled: Vec<(&str, &str, &[f32])> = templates
        .iter()
        .enumerate()
        .map(|(i, t)| (["a", "b", "c"][i % 3], "scan", t.as_slice()))
        .collect();
    for probe in 0..4 {
        let (score, who) = best_rgb(&unit(dim, probe + 2), &labeled);
        f(out, score);
        out(who.as_bytes());
    }
    // The IR matcher with and without a fitted calibration, raw space.
    let enrollment = enrollment(dim);
    for probe in 0..6 {
        let matched = ir_match_in(
            irlume_core::storage::IR_RAW_SPACE,
            SPACE,
            false,
            &enrollment,
            &unit(dim, probe + 41),
        );
        f(out, matched.best);
        out(matched.best_who.as_bytes());
        out(&matched.n_templates.to_le_bytes());
        if let Some((score, who)) = &matched.centroid {
            coverage.calibrated += 1;
            f(out, *score);
            out(who.as_bytes());
        }
    }
    let scores = [
        0.30f32, 0.45, 0.52, 0.55, 0.56, 0.58, 0.60, 0.62, 0.635, 0.66, 0.70, 0.80,
    ];
    let counts = [1usize, 2, 3, 5, 10, 30, 90];
    // The RGB-primary arm.
    for &score in &scores {
        for &n in &counts {
            for sequential in [false, true] {
                let (threshold, grants) =
                    rgb_arm(score, irlume_core::RGB_MATCH_THRESHOLD, n, sequential);
                f(out, threshold);
                out(&[count(grants, &mut coverage.rgb)]);
            }
        }
    }
    // The lit IR arms.
    for &rgb in &[0.30f32, 0.45, 0.52, 0.56, 0.70] {
        for &ir in &scores {
            for centroid in [None, Some(0.55f32), Some(0.62), Some(0.70)] {
                for &n in &[1usize, 10, 90] {
                    let matched = IrMatch {
                        best: ir,
                        best_who: "p".into(),
                        n_templates: n,
                        centroid: centroid.map(|c| (c, "c".to_owned())),
                    };
                    for &rgb_brightness in &[20.0f32, 60.0, 120.0, 200.0] {
                        for &ir_brightness in &[20.0f32, 60.0, 140.0] {
                            for sequential in [false, true] {
                                for adapter in [false, true] {
                                    for profiles in [1usize, 3] {
                                        let arms = lit_ir_arms(
                                            rgb,
                                            rgb_brightness,
                                            &matched,
                                            ir_brightness,
                                            sequential,
                                            adapter,
                                            profiles,
                                        );
                                        f(out, arms.fusion.prob);
                                        f(out, arms.fusion.p_rgb);
                                        f(out, arms.fusion.p_ir);
                                        f(out, arms.fallback_threshold);
                                        f(out, arms.centroid_threshold.unwrap_or(f32::NAN));
                                        let arm = arms.grant;
                                        out(&[
                                            u8::from(arms.fusion.grant),
                                            count(arm == Some(IrArm::Fusion), &mut coverage.fusion),
                                            count(
                                                arm == Some(IrArm::Fallback),
                                                &mut coverage.fallback,
                                            ),
                                            count(
                                                arm == Some(IrArm::Centroid),
                                                &mut coverage.centroid,
                                            ),
                                        ]);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // The dark path's IR arms.
    for &ir in &scores {
        for centroid in [None, Some(0.62f32), Some(0.70)] {
            for &n in &counts {
                for profiles in [1usize, 3] {
                    for adapter in [false, true] {
                        let matched = IrMatch {
                            best: ir,
                            best_who: "p".into(),
                            n_templates: n,
                            centroid: centroid.map(|c| (c, "c".to_owned())),
                        };
                        let thresholds = IdentityThresholds::new(n, profiles, adapter);
                        let (best, centroid) = thresholds.arms(&matched);
                        f(out, thresholds.best);
                        f(out, thresholds.centroid);
                        out(&[
                            count(best, &mut coverage.dark_best),
                            count(centroid, &mut coverage.dark_centroid),
                        ]);
                    }
                }
            }
        }
    }
}

/// The recognition decision's fingerprint (ADR-0022 §3): the SHA-256 of
/// everything the production decision code returns over a fixed synthetic
/// grid: RGB matching, the IR matcher with and without a fitted
/// calibration, the RGB-primary, fusion, IR-fallback and calibrated-centroid
/// arms, the dark path's arms, and the Platt scaling, brightness weighting
/// and template-count scaling inside them. A change to any of it changes
/// the fingerprint, and a certification entry bound to the old one no
/// longer applies.
pub fn decision_fingerprint() -> String {
    let mut hasher = Sha256::new();
    decision_grid(
        &mut |bytes: &[u8]| {
            hasher.update((bytes.len() as u32).to_le_bytes());
            hasher.update(bytes);
        },
        &mut Coverage::default(),
    );
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched(best: f32, n_templates: usize, centroid: Option<f32>) -> IrMatch {
        IrMatch {
            best,
            best_who: "p".into(),
            n_templates,
            centroid: centroid.map(|score| (score, "c".to_owned())),
        }
    }

    #[test]
    fn the_decision_fingerprint_is_stable_and_crosses_every_boundary() {
        assert_eq!(decision_fingerprint(), decision_fingerprint());
        assert_eq!(decision_fingerprint().len(), 64);
        let mut coverage = Coverage::default();
        decision_grid(&mut |_: &[u8]| {}, &mut coverage);
        for (arm, counts) in [
            ("rgb", coverage.rgb),
            ("fusion", coverage.fusion),
            ("fallback", coverage.fallback),
            ("centroid", coverage.centroid),
            ("dark best", coverage.dark_best),
            ("dark centroid", coverage.dark_centroid),
        ] {
            assert!(counts[0] > 0 && counts[1] > 0, "{arm} never {counts:?}");
        }
        assert!(coverage.calibrated > 0, "the calibrated IR matcher ran");
    }

    #[test]
    fn the_rgb_arm_is_the_scaled_threshold_and_never_grants_a_sequential_pair_alone() {
        let base = irlume_core::RGB_MATCH_THRESHOLD;
        for n in [1, 2, 10, 90] {
            let (threshold, _) = rgb_arm(0.0, base, n, false);
            assert_eq!(threshold, irlume_core::scaled_threshold(base, n));
        }
        assert!(rgb_arm(0.95, base, 1, false).1);
        assert!(!rgb_arm(0.95, base, 1, true).1, "ADR-0014");
        assert!(!rgb_arm(base - 0.01, base, 1, false).1);
    }

    #[test]
    fn the_lit_ir_arms_grant_in_order_and_a_sequential_pair_never_fuses() {
        // Fusion first, unless the pair is sequential.
        let strong = matched(0.70, 1, None);
        let fused = lit_ir_arms(0.52, 120.0, &strong, 60.0, false, false, 1);
        assert_eq!(fused.grant, Some(IrArm::Fusion));
        let sequential = lit_ir_arms(0.52, 120.0, &strong, 60.0, true, false, 1);
        assert!(sequential.fusion.grant);
        assert_eq!(
            sequential.grant,
            Some(IrArm::Fallback),
            "IR identity arms only"
        );
        // A weak IR score: no fallback; the centroid decides alone.
        let weak = matched(0.40, 10, Some(0.70));
        let arms = lit_ir_arms(0.30, 120.0, &weak, 60.0, true, false, 1);
        assert_eq!(arms.grant, Some(IrArm::Centroid));
        assert_eq!(
            arms.centroid_threshold,
            Some(
                irlume_core::scaled_threshold(irlume_core::IR_MATCH_THRESHOLD, 1)
                    + irlume_core::IR_FALLBACK_MARGIN
            )
        );
        let none = lit_ir_arms(0.30, 120.0, &matched(0.40, 10, None), 60.0, true, false, 1);
        assert_eq!(none.grant, None);
        assert_eq!(none.centroid_threshold, None);
    }

    /// A certification entry applies only through the decision code it was
    /// measured with (ADR-0022 §3).
    #[cfg(feature = "npu")]
    #[test]
    fn certified_entries_carry_this_decision_fingerprint() {
        let now = decision_fingerprint();
        for entry in irlume_vision::npu::CERTIFIED {
            assert_eq!(entry.decision_fingerprint, now, "{}", entry.model_sha256);
        }
    }
}
