// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use irlume_core::storage::{Enrollment, FaceProfile, FaceScan};

fn context() -> DecisionContext<'static> {
    DecisionContext {
        embed_space: "test-recognizer",
        ir_space: "raw",
        adapter: false,
        rgb_base: irlume_core::RGB_MATCH_THRESHOLD,
    }
}

fn enrollment() -> Enrollment {
    let mut enrollment = Enrollment::new("synthetic");
    enrollment.profiles.push(FaceProfile {
        name: "profile".into(),
        scans: vec![FaceScan {
            name: "scan".into(),
            rgb: vec![1.0, 0.0],
            ir: Some(vec![1.0, 0.0]),
            ir_space: Some("raw".into()),
            embed_space: Some("test-recognizer".into()),
            ir_center_edge_ratio: 1.5,
            ir_brightness: 100.0,
            pitch: 0.5,
            captured_at: None,
        }],
        ir_calib: None,
        ir_calibs: Default::default(),
    });
    enrollment
}

fn probe<'a>(rgb: &'a [f32], ir: Option<&'a [f32]>, sequential: bool) -> LitProbe<'a> {
    LitProbe {
        rgb,
        ir,
        rgb_brightness: 100.0,
        ir_brightness: 100.0,
        sequential,
    }
}

#[test]
fn rgb_acceptance_has_no_ir_stage() {
    let input = probe(&[1.0, 0.0], Some(&[1.0, 0.0]), false);
    let verdict = lit_verdict(&context(), &enrollment(), &input);
    assert!(verdict.rgb.grants);
    assert!(!verdict.rgb.deferred);
    assert_eq!(verdict.rgb.templates, 1);
    assert!(verdict.ir.is_none());
    let Some(LitGrant::Rgb { score, who }) = verdict.grant() else {
        panic!("expected RGB grant");
    };
    assert_eq!(score.to_bits(), 1.0f32.to_bits());
    assert_eq!(who, "profile");
}

#[test]
fn missing_ir_preserves_rgb_and_sequential_deferral() {
    for sequential in [false, true] {
        let input = probe(&[1.0, 0.0], None, sequential);
        let verdict = lit_verdict(&context(), &enrollment(), &input);
        assert_eq!(verdict.rgb.grants, !sequential);
        assert_eq!(verdict.rgb.deferred, sequential);
        assert!(verdict.ir.is_none());
    }
}

#[test]
fn sequential_posture_defers_both_rgb_and_fusion() {
    let ir = [0.4, (1.0f32 - 0.4 * 0.4).sqrt()];
    let input = probe(&[1.0, 0.0], Some(&ir), true);
    let verdict = lit_verdict(&context(), &enrollment(), &input);
    assert!(!verdict.rgb.grants);
    assert!(verdict.rgb.deferred);
    assert!(verdict.grant().is_none());
    let ir = verdict.ir.unwrap();
    assert!(ir.arms.fusion.grant);
    assert!(ir.fusion_deferred);
    assert_eq!(ir.arms.grant, None);
}

#[test]
fn fallback_retains_its_score_and_profile() {
    let rgb = [0.2, (1.0f32 - 0.2 * 0.2).sqrt()];
    let input = probe(&rgb, Some(&[1.0, 0.0]), false);
    let verdict = lit_verdict(&context(), &enrollment(), &input);
    let Some(LitGrant::Fallback { score, who }) = verdict.grant() else {
        panic!("expected IR fallback");
    };
    assert_eq!(score.to_bits(), 1.0f32.to_bits());
    assert_eq!(who, "profile");
}

fn unit2(cosine: f32) -> Vec<f32> {
    vec![cosine, (1.0 - cosine * cosine).sqrt()]
}

#[test]
fn fusion_uses_ir_on_a_score_tie_and_otherwise_the_stronger_profile() {
    for ir_score in [0.4, 0.5, 0.6] {
        let mut en = enrollment();
        let mut rgb_profile = en.profiles[0].clone();
        rgb_profile.name = "rgb-profile".into();
        rgb_profile.scans[0].rgb = unit2(0.5);
        rgb_profile.scans[0].ir = Some(unit2(0.1));
        en.profiles[0].name = "ir-profile".into();
        en.profiles[0].scans[0].rgb = unit2(0.4);
        en.profiles[0].scans[0].ir = Some(unit2(ir_score));
        en.profiles.push(rgb_profile);
        let input = probe(&[1.0, 0.0], Some(&[1.0, 0.0]), false);
        let verdict = lit_verdict(&context(), &en, &input);
        let Some(LitGrant::Fusion { score, who }) = verdict.grant() else {
            panic!("expected fusion grant");
        };
        let expected = fusion::fuse(
            fusion::rgb_genuine_prob(0.5),
            fusion::rgb_quality_weight(100.0),
            fusion::ir_genuine_prob(ir_score),
            fusion::ir_quality_weight(true, 100.0),
        );
        assert_eq!(score.to_bits(), expected.prob.to_bits());
        assert_eq!(
            who,
            if ir_score >= 0.5 {
                "ir-profile"
            } else {
                "rgb-profile"
            }
        );
    }
}

#[test]
fn centroid_retains_its_own_score_and_profile() {
    let mut en = enrollment();
    let profile = &mut en.profiles[0];
    let mut second = profile.scans[0].clone();
    profile.scans[0].ir = Some(unit2(0.4));
    let mut reflected = unit2(0.4);
    reflected[1] = -reflected[1];
    second.ir = Some(reflected);
    profile.scans.push(second);
    profile.set_calib_for(
        "test-recognizer",
        Some(irlume_core::calib::IrCalibration {
            m: vec![vec![0.0; 3]; 2],
            n_rows: vec![vec![0.0; 2]; 3],
            lambda: 0.5,
            fitted_pairs: 3,
        }),
    );
    let rgb = unit2(0.2);
    let input = probe(&rgb, Some(&[1.0, 0.0]), false);
    let verdict = lit_verdict(&context(), &en, &input);
    let Some(LitGrant::Centroid { score, who }) = verdict.grant() else {
        panic!("expected centroid grant");
    };
    assert_eq!(score.to_bits(), 1.0f32.to_bits());
    assert_eq!(who, "profile");
}

#[test]
fn incompatible_ir_has_no_ir_decision() {
    let mut en = enrollment();
    en.profiles[0].scans[0].ir_space = Some("other-pipeline".into());
    let rgb = unit2(0.2);
    let input = probe(&rgb, Some(&[1.0, 0.0]), false);
    let verdict = lit_verdict(&context(), &en, &input);
    assert!(verdict.ir.is_none());
    assert!(verdict.grant().is_none());
}

#[derive(Debug, PartialEq, Eq)]
struct IrSnapshot {
    best: (u32, String, usize),
    centroid: Option<(u32, String)>,
    fusion: (u32, u32, u32, bool),
    thresholds: (u32, Option<u32>),
    arm: Option<IrArm>,
    deferred: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    rgb: (u32, String, usize, u32, bool, bool),
    ir: Option<IrSnapshot>,
    grant: Option<(u8, u32, String)>,
}

fn ir_snapshot(matched: &IrMatch, arms: &IrArms, sequential: bool) -> IrSnapshot {
    IrSnapshot {
        best: (
            matched.best.to_bits(),
            matched.best_who.clone(),
            matched.n_templates,
        ),
        centroid: matched
            .centroid
            .as_ref()
            .map(|(score, who)| (score.to_bits(), who.clone())),
        fusion: (
            arms.fusion.prob.to_bits(),
            arms.fusion.p_rgb.to_bits(),
            arms.fusion.p_ir.to_bits(),
            arms.fusion.grant,
        ),
        thresholds: (
            arms.fallback_threshold.to_bits(),
            arms.centroid_threshold.map(f32::to_bits),
        ),
        arm: arms.grant,
        deferred: arms.fusion.grant && sequential,
    }
}

// Transcribed from the engine before lit_verdict: this does not call the new
// constructor or its grant selector. The old arm helpers remain independently
// pinned by the fixed arm-grid fingerprint.
fn old_composition(ctx: &DecisionContext<'_>, en: &Enrollment, input: &LitProbe<'_>) -> Snapshot {
    let scans = en.rgb_scans_in(ctx.embed_space);
    let (score, who) = best_rgb(input.rgb, &scans);
    let (threshold, grants) = rgb_arm(score, ctx.rgb_base, scans.len(), input.sequential);
    let mut result = Snapshot {
        rgb: (
            score.to_bits(),
            who.clone(),
            scans.len(),
            threshold.to_bits(),
            grants,
            input.sequential && score >= threshold,
        ),
        ir: None,
        grant: None,
    };
    if grants {
        result.grant = Some((0, score.to_bits(), who));
        return result;
    }
    let Some(ir_probe) = input.ir else {
        return result;
    };
    let matched = ir_match_in(ctx.ir_space, ctx.embed_space, ctx.adapter, en, ir_probe);
    if matched.n_templates == 0 {
        return result;
    }
    let arms = lit_ir_arms(
        score,
        input.rgb_brightness,
        &matched,
        input.ir_brightness,
        input.sequential,
        ctx.adapter,
        en.profiles.len(),
    );
    result.ir = Some(ir_snapshot(&matched, &arms, input.sequential));
    result.grant = match arms.grant {
        Some(IrArm::Fusion) => Some((
            1,
            arms.fusion.prob.to_bits(),
            if matched.best >= score {
                matched.best_who
            } else {
                who
            },
        )),
        Some(IrArm::Fallback) => Some((2, matched.best.to_bits(), matched.best_who)),
        Some(IrArm::Centroid) => matched
            .centroid
            .map(|(score, who)| (3, score.to_bits(), who)),
        None => None,
    };
    result
}

fn new_composition(ctx: &DecisionContext<'_>, en: &Enrollment, input: &LitProbe<'_>) -> Snapshot {
    let verdict = lit_verdict(ctx, en, input);
    let grant = verdict.grant().map(|grant| match grant {
        LitGrant::Rgb { score, who } => (0, score.to_bits(), who.to_owned()),
        LitGrant::Fusion { score, who } => (1, score.to_bits(), who.to_owned()),
        LitGrant::Fallback { score, who } => (2, score.to_bits(), who.to_owned()),
        LitGrant::Centroid { score, who } => (3, score.to_bits(), who.to_owned()),
    });
    let ir = verdict.ir.as_ref().map(|ir| {
        let mut snapshot = ir_snapshot(&ir.matched, &ir.arms, input.sequential);
        snapshot.deferred = ir.fusion_deferred;
        snapshot
    });
    Snapshot {
        rgb: (
            verdict.rgb.score.to_bits(),
            verdict.rgb.who,
            verdict.rgb.templates,
            verdict.rgb.threshold.to_bits(),
            verdict.rgb.grants,
            verdict.rgb.deferred,
        ),
        ir,
        grant,
    }
}

#[test]
fn lit_verdict_matches_the_old_composition_on_directed_inputs() {
    for sequential in [false, true] {
        for rgb in [0.2, 0.5, 1.0] {
            let rgb = unit2(rgb);
            for ir in [None, Some(unit2(0.2)), Some(unit2(0.4)), Some(unit2(0.9))] {
                let input = probe(&rgb, ir.as_deref(), sequential);
                assert_eq!(
                    new_composition(&context(), &enrollment(), &input),
                    old_composition(&context(), &enrollment(), &input)
                );
            }
        }
    }
}

fn enrollment_shapes() -> Vec<Enrollment> {
    let ordinary = enrollment();
    let mut absent_ir = ordinary.clone();
    absent_ir.profiles[0].scans[0].ir = None;
    let mut stale_ir = ordinary.clone();
    stale_ir.profiles[0].scans[0].ir_space = None;
    let mut foreign = ordinary.clone();
    foreign.profiles[0].scans[0].embed_space = Some("other-recognizer".into());
    let mut wrong_dimension = ordinary.clone();
    wrong_dimension.profiles[0].scans[0].ir = Some(vec![1.0]);
    let mut profiles = ordinary.clone();
    let mut second = profiles.profiles[0].clone();
    second.name = "second".into();
    second.scans[0].rgb = unit2(0.5);
    second.scans[0].ir = Some(unit2(0.1));
    profiles.profiles[0].scans[0].rgb = unit2(0.4);
    profiles.profiles[0].scans[0].ir = Some(unit2(0.6));
    profiles.profiles.push(second);
    let mut calibrated = ordinary.clone();
    let profile = &mut calibrated.profiles[0];
    let mut second = profile.scans[0].clone();
    profile.scans[0].ir = Some(unit2(0.4));
    let mut reflected = unit2(0.4);
    reflected[1] = -reflected[1];
    second.ir = Some(reflected);
    profile.scans.push(second);
    profile.set_calib_for(
        "test-recognizer",
        Some(irlume_core::calib::IrCalibration {
            m: vec![vec![0.0; 3]; 2],
            n_rows: vec![vec![0.0; 2]; 3],
            lambda: 0.5,
            fitted_pairs: 3,
        }),
    );
    let mut incompatible_calibration = ordinary.clone();
    incompatible_calibration.profiles[0].set_calib_for(
        "test-recognizer",
        Some(irlume_core::calib::IrCalibration {
            m: vec![vec![0.0]],
            n_rows: vec![vec![0.0]],
            lambda: 0.5,
            fitted_pairs: 3,
        }),
    );
    vec![
        ordinary,
        absent_ir,
        stale_ir,
        foreign,
        wrong_dimension,
        profiles,
        calibrated,
        incompatible_calibration,
        Enrollment::new("empty"),
    ]
}

#[test]
fn lit_verdict_matches_the_old_composition_for_enrollment_shapes() {
    for en in enrollment_shapes() {
        for adapter in [false, true] {
            let mut ctx = context();
            ctx.adapter = adapter;
            let rgb = unit2(0.2);
            let input = probe(&rgb, Some(&[1.0, 0.0]), true);
            assert_eq!(
                new_composition(&ctx, &en, &input),
                old_composition(&ctx, &en, &input)
            );
        }
    }
}

fn next_coordinate(state: &mut u64) -> f32 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    ((*state >> 40) as u32) as f32 / 16_777_216.0 * 2.0 - 1.0
}

#[test]
fn lit_verdict_matches_200000_generated_old_compositions() {
    let shapes = enrollment_shapes();
    let mut state = 0x5d3a_b691_7428_e0c7;
    let special = [
        -0.0,
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        irlume_core::RGB_MATCH_THRESHOLD.next_down(),
        irlume_core::RGB_MATCH_THRESHOLD,
        irlume_core::RGB_MATCH_THRESHOLD.next_up(),
        irlume_core::IR_MATCH_THRESHOLD + irlume_core::IR_FALLBACK_MARGIN,
    ];
    let brightness = [
        0.0,
        35.0,
        60.0,
        100.0,
        110.0,
        130.0,
        f32::NAN,
        f32::INFINITY,
    ];
    let mut grants = [0usize; 5];
    let mut deferrals = [0usize; 2];
    for i in 0..200_000 {
        let mut ctx = context();
        ctx.adapter = (i / shapes.len()) % 2 != 0;
        ctx.rgb_base = [0.55, 0.4, 0.7, -0.0][(i / 37) % 4];
        let mut rgb = [next_coordinate(&mut state), next_coordinate(&mut state)];
        let mut ir = [next_coordinate(&mut state), next_coordinate(&mut state)];
        if i % 29 == 0 {
            rgb[0] = special[(i / 29) % special.len()];
        }
        if i % 31 == 0 {
            ir[0] = special[(i / 31) % special.len()];
        }
        let input = LitProbe {
            rgb: &rgb,
            ir: (i % 7 != 0).then_some(ir.as_slice()),
            rgb_brightness: brightness[(i / 11) % brightness.len()],
            ir_brightness: brightness[(i / 13) % brightness.len()],
            sequential: i % 3 == 0,
        };
        let en = &shapes[i % shapes.len()];
        let actual = new_composition(&ctx, en, &input);
        let expected = old_composition(&ctx, en, &input);
        assert_eq!(actual, expected, "generated case {i}");
        grants[actual
            .grant
            .as_ref()
            .map_or(4, |grant| usize::from(grant.0))] += 1;
        deferrals[0] += usize::from(actual.rgb.5);
        deferrals[1] += usize::from(actual.ir.as_ref().is_some_and(|ir| ir.deferred));
    }
    assert!(
        grants.into_iter().all(|count| count > 0),
        "missing grant/deny arm: {grants:?}"
    );
    assert!(
        deferrals.into_iter().all(|count| count > 0),
        "missing deferral: {deferrals:?}"
    );
}
