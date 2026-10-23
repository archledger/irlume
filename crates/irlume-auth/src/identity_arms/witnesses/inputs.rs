// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use crate::identity_arms::{
    ir_match_in, lit_verdict, DecisionContext, IrMatch, LitProbe, LitVerdict,
};
use irlume_core::calib::IrCalibration;
use irlume_core::storage::{Enrollment, FaceProfile, FaceScan};

const SPACE: &str = "embed:witness";
const IR_SPACE: &str = "raw";

pub(super) struct Inputs {
    pub(super) enrollment: Enrollment,
    pub(super) rgb: Vec<f32>,
    pub(super) ir: Vec<f32>,
    pub(super) ir_present: bool,
    pub(super) adapter: bool,
    pub(super) sequential: bool,
    pub(super) rgb_brightness: f32,
    pub(super) ir_brightness: f32,
}

impl Inputs {
    pub(super) fn set_rgb_scores(&mut self, score: f32) {
        for profile in &mut self.enrollment.profiles {
            for scan in &mut profile.scans {
                scan.rgb = vector(score);
            }
        }
    }

    pub(super) fn lit(&self) -> LitVerdict {
        lit_verdict(
            &DecisionContext {
                embed_space: SPACE,
                ir_space: IR_SPACE,
                adapter: self.adapter,
                rgb_base: irlume_core::RGB_MATCH_THRESHOLD,
            },
            &self.enrollment,
            &LitProbe {
                rgb: &self.rgb,
                ir: self.ir_present.then_some(self.ir.as_slice()),
                rgb_brightness: self.rgb_brightness,
                ir_brightness: self.ir_brightness,
                sequential: self.sequential,
            },
        )
    }

    pub(super) fn matched(&self) -> IrMatch {
        ir_match_in(IR_SPACE, SPACE, self.adapter, &self.enrollment, &self.ir)
    }
}

fn vector(cosine: f32) -> Vec<f32> {
    let mut v = vec![0.0; 8];
    v[0] = cosine;
    let x = f64::from(cosine);
    let mut y = (1.0 - x * x).sqrt() as f32;
    if x * x + f64::from(y).powi(2) > 1.0 {
        y = y.next_down();
    }
    v[1] = y;
    v[2] = (1.0 - x * x - f64::from(y).powi(2)).sqrt() as f32;
    v
}

fn scan(rgb: Vec<f32>, ir: Vec<f32>) -> FaceScan {
    FaceScan {
        name: "synthetic".into(),
        rgb,
        ir: Some(ir),
        ir_space: Some(IR_SPACE.into()),
        embed_space: Some(SPACE.into()),
        embed_producer: None,
        ir_center_edge_ratio: 0.0,
        ir_brightness: 0.0,
        pitch: 0.0,
        captured_at: None,
    }
}

fn profile(name: &str, scans: Vec<FaceScan>) -> FaceProfile {
    FaceProfile {
        name: name.into(),
        scans,
        ir_calib: None,
        ir_calibs: Default::default(),
    }
}

fn inputs(profiles: Vec<FaceProfile>) -> Inputs {
    let mut enrollment = Enrollment::new("synthetic");
    enrollment.profiles = profiles;
    Inputs {
        enrollment,
        rgb: vector(1.0),
        ir: vector(1.0),
        ir_present: true,
        adapter: false,
        sequential: false,
        rgb_brightness: 130.0,
        ir_brightness: 110.0,
    }
}

pub(super) fn accumulation() -> Inputs {
    let mut v = vec![0.0; 512];
    for index in [0, 8, 248, 504] {
        v[index] = 0.5;
    }
    let mut input = inputs(vec![profile(
        "accumulation",
        vec![scan(v.clone(), v.clone())],
    )]);
    input.rgb = v.clone();
    input.ir = v;
    input
}

pub(super) fn provenance(mixed: bool) -> Inputs {
    let mut p = profile("provenance", vec![scan(vector(0.1), vector(0.4))]);
    let mut m = vec![vec![0.0]; 8];
    m[0][0] = 1.0;
    let mut n = vec![0.0; 8];
    n[0] = 1.0;
    p.set_calib_for(
        SPACE,
        Some(IrCalibration {
            m,
            n_rows: vec![n],
            lambda: 0.5,
            fitted_pairs: 3,
        }),
    );
    if mixed {
        let mut untagged = scan(vector(0.1), vector(0.9));
        untagged.ir_space = None;
        p.scans.push(untagged);
    }
    inputs(vec![p])
}

pub(super) fn fusion_winner(ir_score: f32, rgb_brightness: f32, ir_brightness: f32) -> Inputs {
    let mut input = inputs(vec![
        profile("ir-winner", vec![scan(vector(0.4), vector(ir_score))]),
        profile("rgb-winner", vec![scan(vector(0.5), vector(0.1))]),
    ]);
    input.rgb_brightness = rgb_brightness;
    input.ir_brightness = ir_brightness;
    input
}

pub(super) fn rgb_boundary(count: usize, score: f32) -> Inputs {
    inputs(vec![profile(
        "rgb-boundary",
        vec![scan(vector(score), vector(0.1)); count],
    )])
}

pub(super) fn fallback_boundary(count: usize, score: f32) -> Inputs {
    inputs(vec![profile(
        "ir-boundary",
        vec![scan(vector(0.1), vector(score)); count],
    )])
}

pub(super) fn centroid_boundary(profiles: usize, score: f32) -> Inputs {
    let mut positive = vector(0.25);
    // Keep the centroid on e0 while the probe's orthogonal components
    // remain in dimensions 1/2 and cancel neither template's dimension 3.
    positive[3] = positive[1];
    positive[1] = 0.0;
    positive[2] = 0.0;
    let mut negative = positive.clone();
    negative[3] = -negative[3];
    let mut p = profile(
        "ir-centroid",
        vec![scan(vector(0.1), positive), scan(vector(0.1), negative)],
    );
    p.set_calib_for(
        SPACE,
        Some(IrCalibration {
            m: vec![vec![0.0]; 8],
            n_rows: vec![vec![0.0; 8]],
            lambda: 0.5,
            fitted_pairs: 3,
        }),
    );
    let mut input = inputs(vec![p; profiles]);
    for (index, profile) in input.enrollment.profiles.iter_mut().enumerate().skip(1) {
        profile.name = format!("ir-centroid-{index}");
    }
    input.ir = vector(score);
    input
}

pub(super) fn competing() -> Inputs {
    let mut input = centroid_boundary(1, 1.0);
    input
        .enrollment
        .profiles
        .insert(0, profile("ir-best", vec![scan(vector(0.4), vector(0.8))]));
    input
}

pub(super) fn rgb_priority() -> Inputs {
    let mut input = competing();
    input
        .enrollment
        .profiles
        .push(profile("rgb-winner", vec![scan(vector(0.9), vector(0.1))]));
    input
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Unavailable {
    NoProbe,
    NoTemplate,
    ForeignTag,
    ForeignRecognizer,
    WrongWidth,
    ZeroAdaptedProbe,
    Empty,
    MalformedCalibration,
}

pub(super) fn unavailable(kind: Unavailable) -> Inputs {
    let mut input = provenance(false);
    match kind {
        Unavailable::NoProbe => input.ir_present = false,
        Unavailable::NoTemplate => input.enrollment.profiles[0].scans[0].ir = None,
        Unavailable::ForeignTag => {
            input.enrollment.profiles[0].scans[0].ir_space = Some("foreign".into())
        }
        Unavailable::ForeignRecognizer => {
            input.enrollment.profiles[0].scans[0].embed_space = Some("foreign".into())
        }
        Unavailable::WrongWidth => input.enrollment.profiles[0].scans[0].ir = Some(vec![1.0]),
        Unavailable::ZeroAdaptedProbe => {
            input.ir.fill(0.0);
            input.adapter = true;
        }
        Unavailable::Empty => input.enrollment.profiles.clear(),
        Unavailable::MalformedCalibration => {
            input.enrollment.profiles[0].set_calib_for(
                SPACE,
                Some(IrCalibration {
                    m: vec![vec![0.0]; 1],
                    n_rows: vec![vec![0.0]],
                    lambda: 0.5,
                    fitted_pairs: 3,
                }),
            );
        }
    }
    input
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_arms::{dark_verdict, DarkGrant, LitGrant};

    #[test]
    fn production_width_witness_uses_successive_accumulation_chunks() {
        let mut input = accumulation();
        assert_eq!(input.rgb.len(), 512);
        let lit = input.lit();
        assert_eq!(lit.rgb.score.to_bits(), 1.0f32.to_bits());
        assert!(matches!(
            lit.grant(),
            Some(LitGrant::Rgb {
                who: "accumulation",
                ..
            })
        ));
        input.sequential = true;
        let lit = input.lit();
        assert!(lit.rgb.deferred);
        assert_eq!(
            lit.ir.as_ref().unwrap().matched.best.to_bits(),
            1.0f32.to_bits()
        );
        assert!(matches!(
            lit.grant(),
            Some(LitGrant::Fallback {
                who: "accumulation",
                ..
            })
        ));
        let matched = input.matched();
        assert!(matches!(
            dark_verdict(&matched, 1, false).grant,
            Some(DarkGrant::Best {
                score: 1.0,
                who: "accumulation"
            })
        ));
    }

    #[test]
    fn mixed_provenance_withholds_a_distinguishable_calibration() {
        let calibrated = provenance(false).matched();
        let raw = provenance(true).matched();
        assert_eq!(calibrated.n_templates, 1);
        assert_eq!(raw.n_templates, 1);
        assert_ne!(calibrated.best.to_bits(), 0.4f32.to_bits());
        assert!(calibrated.centroid.is_some());
        assert_eq!(raw.best.to_bits(), 0.4f32.to_bits());
        assert!(raw.centroid.is_none());
        assert_eq!(raw.best_who, "provenance");
    }

    #[test]
    fn all_fixed_fusion_winners_and_the_tie_are_observable() {
        for ir_score in [0.4, 0.5, 0.6] {
            for rgb_brightness in [60.0, 130.0] {
                for ir_brightness in [35.0, 110.0] {
                    let input = fusion_winner(ir_score, rgb_brightness, ir_brightness);
                    let lit = input.lit();
                    let expected = if ir_score < 0.5 {
                        "rgb-winner"
                    } else {
                        "ir-winner"
                    };
                    assert_eq!(lit.rgb.score.to_bits(), 0.5f32.to_bits());
                    assert_eq!(
                        lit.ir.as_ref().unwrap().matched.best.to_bits(),
                        ir_score.to_bits()
                    );
                    assert!(
                        matches!(lit.grant(), Some(LitGrant::Fusion { who, .. }) if who == expected)
                    );
                }
            }
        }
    }

    #[test]
    fn matched_boundary_scores_remain_exact_with_and_without_normalization() {
        use crate::identity_arms::{arm_threshold, ThresholdArm};
        for count in [1, 17, 90, 102] {
            let threshold = arm_threshold(
                ThresholdArm::Rgb {
                    base: irlume_core::RGB_MATCH_THRESHOLD,
                },
                count,
            );
            for score in [threshold.next_down(), threshold, threshold.next_up()] {
                let lit = rgb_boundary(count, score).lit();
                assert_eq!(lit.rgb.score.to_bits(), score.to_bits());
                assert_eq!(lit.rgb.grants, score >= threshold);
            }
            for adapter in [false, true] {
                let threshold = arm_threshold(ThresholdArm::LitFallback { adapter }, count);
                for score in [threshold.next_down(), threshold, threshold.next_up()] {
                    for sequential in [false, true] {
                        let mut input = fallback_boundary(count, score);
                        input.adapter = adapter;
                        input.sequential = sequential;
                        let lit = input.lit();
                        let matched = &lit.ir.as_ref().unwrap().matched;
                        assert_eq!(matched.best.to_bits(), score.to_bits());
                        assert_eq!(matched.n_templates, count);
                        assert_eq!(
                            matches!(lit.grant(), Some(LitGrant::Fallback { .. })),
                            score >= threshold
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn normalized_centroid_boundaries_remain_exact() {
        use crate::identity_arms::{arm_threshold, ThresholdArm};
        for count in [1, 2, 3] {
            let threshold = arm_threshold(ThresholdArm::LitCentroid { adapter: false }, count);
            for score in [threshold.next_down(), threshold, threshold.next_up()] {
                for sequential in [false, true] {
                    let mut input = centroid_boundary(count, score);
                    input.sequential = sequential;
                    let lit = input.lit();
                    let matched = &lit.ir.as_ref().unwrap().matched;
                    assert!(matched.best < 0.3);
                    assert_eq!(
                        matched.centroid.as_ref().unwrap().0.to_bits(),
                        score.to_bits()
                    );
                    assert_eq!(
                        matches!(lit.grant(), Some(LitGrant::Centroid { .. })),
                        score >= threshold
                    );
                }
            }
        }
    }

    #[test]
    fn calibrated_profile_ties_keep_the_first_distinct_name() {
        for count in [2, 3] {
            let input = centroid_boundary(count, 1.0);
            assert_ne!(
                input.enrollment.profiles[0].name,
                input.enrollment.profiles[1].name
            );
            let matched = input.matched();
            assert_eq!(matched.centroid.as_ref().unwrap().1, "ir-centroid");
            assert!(matches!(
                input.lit().grant(),
                Some(LitGrant::Centroid {
                    who: "ir-centroid",
                    ..
                })
            ));
        }
    }

    #[test]
    fn priorities_have_distinct_successful_alternatives() {
        let mut input = competing();
        let lit = input.lit();
        let ir = lit.ir.as_ref().unwrap();
        assert!(ir.matched.best >= ir.arms.fallback_threshold);
        assert!(ir.matched.centroid.as_ref().unwrap().0 >= ir.arms.centroid_threshold.unwrap());
        assert_eq!(ir.matched.best_who, "ir-best");
        assert_eq!(ir.matched.centroid.as_ref().unwrap().1, "ir-centroid");
        assert!(matches!(
            lit.grant(),
            Some(LitGrant::Fusion { who: "ir-best", .. })
        ));
        input.sequential = true;
        let lit = input.lit();
        assert!(lit.ir.as_ref().unwrap().fusion_deferred);
        assert!(matches!(
            lit.grant(),
            Some(LitGrant::Fallback { who: "ir-best", .. })
        ));
        input.sequential = false;
        for profile in &mut input.enrollment.profiles {
            for scan in &mut profile.scans {
                scan.rgb = vector(0.1);
            }
        }
        assert!(matches!(
            input.lit().grant(),
            Some(LitGrant::Fallback { who: "ir-best", .. })
        ));
        input.enrollment.profiles[0].scans[0].rgb = vector(0.9);
        let lit = input.lit();
        assert!(lit.ir.is_none());
        assert!(matches!(
            lit.grant(),
            Some(LitGrant::Rgb { who: "ir-best", .. })
        ));
        assert!(matches!(
            dark_verdict(&input.matched(), 2, false).grant,
            Some(DarkGrant::Best { who: "ir-best", .. })
        ));
    }

    #[test]
    fn unavailable_ir_layouts_keep_their_expected_refusals() {
        for kind in [
            Unavailable::NoProbe,
            Unavailable::NoTemplate,
            Unavailable::ForeignTag,
            Unavailable::ForeignRecognizer,
            Unavailable::WrongWidth,
            Unavailable::ZeroAdaptedProbe,
            Unavailable::Empty,
        ] {
            let input = unavailable(kind);
            assert!(input.lit().grant().is_none());
        }
        let input = unavailable(Unavailable::MalformedCalibration);
        let matched = input.matched();
        assert_eq!(matched.best.to_bits(), 0.4f32.to_bits());
        assert!(matched.centroid.is_none());
    }
}
