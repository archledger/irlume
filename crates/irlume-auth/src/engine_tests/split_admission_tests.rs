// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use crate::grouped_auth::PreparedGroup;
use std::cell::Cell;
use std::time::{Duration, Instant};

fn probe(cosine: f32) -> [f32; EMBED_DIM] {
    let mut embedding = [0.0; EMBED_DIM];
    embedding[0] = cosine;
    embedding[1] = (1.0 - cosine * cosine).sqrt();
    embedding
}

fn compatible_pair(
    engine: &Engine,
    rgb_cosine: f32,
    ir_cosine: f32,
    skew_ms: u64,
    split: bool,
) -> (Enrollment, Assessment) {
    let (mut enrollment, mut assessment) = pad_matching_fixture(0.1, false);
    let scan = &mut enrollment.profiles[0].scans[0];
    scan.ir = Some(scan.rgb.clone());
    scan.ir_space = Some(engine.ir_space().into());
    scan.embed_space = Some(engine.embed_space().into());
    assessment.embedding = Some(probe(rgb_cosine));
    assessment.ir_embedding = Some(probe(ir_cosine).to_vec());
    assessment.signals.rgb_face = Some(irlume_liveness::FaceBox {
        cx: 0.5,
        cy: 0.5,
        score: 0.9,
    });
    assessment.signals.ir_face = assessment.signals.rgb_face;
    assessment.signals.rgb_face_brightness = 130.0;
    assessment.ir_brightness = 35.0;
    assessment.ir_pad = PadEvidence::Score(0.1);
    assessment.sequential_pair = pair_admitted_sequentially(Duration::from_millis(skew_ms), true);
    assessment.split_pair = split;
    (enrollment, assessment)
}

fn assert_compatible_but_insufficient_ir(engine: &Engine, enrollment: &Enrollment, a: &Assessment) {
    let matched = engine.ir_match(enrollment, a.ir_embedding.as_ref().unwrap());
    assert_eq!(
        matched.n_templates, 1,
        "the IR template must actually be compared"
    );
    assert!((matched.best - 0.4).abs() < 1e-6);
    assert!(matched.centroid.is_none());
    assert!(matched.best < irlume_core::IR_MATCH_THRESHOLD + irlume_core::IR_FALLBACK_MARGIN);
}

#[test]
fn split_compatible_ir_cannot_grant_via_rgb_primary_or_fusion_at_any_skew() {
    let _guard = env_guard();
    let mut shared = shared();
    let engine = &mut shared.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    // 0.9 exercises RGB-primary; 0.5 misses its 0.55 bar but the compatible
    // 0.4 IR score lets the ordinary brightness-weighted fusion arm grant.
    for (rgb_cosine, ordinary_arm) in [(0.9, "(rgb)"), (0.5, "rgb+ir fusion")] {
        assert_eq!(
            rgb_cosine >= engine.rgb_grant_threshold(1),
            rgb_cosine == 0.9
        );
        for skew_ms in [2999, 3000, 3001] {
            for purpose in [
                AuthenticationPurpose::Verify,
                AuthenticationPurpose::AppConsent,
                AuthenticationPurpose::CredentialRelease,
            ] {
                for split in [false, true] {
                    let (enrollment, a) = compatible_pair(engine, rgb_cosine, 0.4, skew_ms, split);
                    assert_compatible_but_insufficient_ir(engine, &enrollment, &a);
                    let out = engine
                        .authenticate_qualified_assessment(
                            &enrollment,
                            purpose,
                            Some("login"),
                            a,
                            &(),
                        )
                        .unwrap();
                    // Literal ordinary boundary expectations: equality is still
                    // concurrent, while split provenance always requires IR identity.
                    let should_grant = !split && skew_ms <= 3000;
                    assert_eq!(
                        out.granted, should_grant,
                        "split={split}, skew={skew_ms}, rgb={rgb_cosine}: {out:?}"
                    );
                    if should_grant {
                        assert!(out.reason.contains(ordinary_arm), "{}", out.reason);
                    } else {
                        assert_eq!(out.kind, OutcomeKind::BelowThreshold);
                        assert!(out.live, "this must be an identity refusal, not failed PAD");
                        assert!(!presence_retryable(&out));
                    }
                }
                let (enrollment, a) = compatible_pair(engine, rgb_cosine, 0.8, skew_ms, true);
                let out = engine
                    .authenticate_qualified_assessment(&enrollment, purpose, Some("login"), a, &())
                    .unwrap();
                assert!(out.granted, "qualifying IR must remain admissible: {out:?}");
                assert!(out.reason.contains("ir-fallback"), "{}", out.reason);
            }
        }
    }
    engine.ir_available = previous_ir;
}

#[test]
fn split_pad_retries_keep_ir_identity_required_on_the_final_vote() {
    let _guard = env_guard();
    let mut shared = shared();
    let engine = &mut shared.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    for rgb_cosine in [0.9, 0.5] {
        for skew_ms in [2999, 3000, 3001] {
            for ir_cosine in [0.4, 0.8] {
                engine.vit_scores.clear();
                let start = Instant::now();
                let clock = Cell::new(start);
                let calls = Cell::new(0);
                let mut costliest = Duration::ZERO;
                let (result, fallback, deferred) = engine.authentication_attempt_loop_with(
                    start + Duration::from_secs(15),
                    15_000,
                    &mut costliest,
                    |engine| {
                        let index = calls.get();
                        assert!(index < 5, "final identity refusal must not retry");
                        calls.set(index + 1);
                        clock.set(clock.get() + Duration::from_millis(1));
                        let deny = engine.vit_pad_votes_deny(0.1);
                        assert!(!deny);
                        let (enrollment, a) =
                            compatible_pair(engine, rgb_cosine, ir_cosine, skew_ms, true);
                        if ir_cosine == 0.4 {
                            assert_compatible_but_insufficient_ir(engine, &enrollment, &a);
                        }
                        let result = engine.authenticate_assessment(
                            &enrollment,
                            AuthenticationPurpose::Verify,
                            Some("login"),
                            a,
                            &(),
                        );
                        if index < 4 {
                            assert_eq!(result.as_ref().unwrap().kind, OutcomeKind::RgbPadPending);
                            assert!(!result.as_ref().unwrap().granted);
                        }
                        (result, false, None::<()>)
                    },
                    || clock.get(),
                );
                let out = result.unwrap();
                assert_eq!(calls.get(), 5);
                assert!(!fallback);
                assert!(deferred.is_none());
                assert_eq!(
                    out.granted,
                    ir_cosine == 0.8,
                    "rgb={rgb_cosine}, skew={skew_ms}: {out:?}"
                );
                if ir_cosine == 0.4 {
                    assert_eq!(out.kind, OutcomeKind::BelowThreshold);
                    assert!(out.live);
                } else {
                    assert!(out.reason.contains("ir-fallback"), "{}", out.reason);
                }
            }
        }
    }
    engine.vit_scores.clear();
    engine.ir_available = previous_ir;
}

#[test]
fn grouped_split_materialization_keeps_provenance_and_classifies_final_ir_identity() {
    let _guard = env_guard();
    let mut shared = shared();
    let engine = &mut shared.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    for rgb_cosine in [0.9, 0.5] {
        for skew_ms in [2999, 3000, 3001] {
            for ir_cosine in [0.4, 0.8] {
                for purpose in [
                    AuthenticationPurpose::Verify,
                    AuthenticationPurpose::CredentialRelease,
                ] {
                    let identities = Cell::new(0);
                    let mut enrollment = None;
                    let prepared = engine
                        .evaluate_grouped_samples_with(
                            (0..5).collect(),
                            Instant::now() + Duration::from_secs(15),
                            |engine, index| {
                                assert!(!engine.vit_pad_votes_deny(0.1));
                                // Earlier matching IR cannot substitute for the
                                // final sample's insufficient identity evidence.
                                let score = if index == 4 { ir_cosine } else { 0.8 };
                                let (_, mut assessment) =
                                    compatible_pair(engine, rgb_cosine, score, skew_ms, true);
                                let rgb = assessment.embedding.take().unwrap();
                                let ir = assessment.ir_embedding.take().unwrap();
                                Ok(DeferredAssessment {
                                    assessment,
                                    identity: (index, rgb, ir),
                                })
                            },
                            |engine, mut evidence| {
                                identities.set(identities.get() + 1);
                                assert_eq!(evidence.identity.0, 4);
                                assert!(evidence.assessment.split_pair);
                                assert!(evidence.assessment.sequential_pair);
                                evidence.assessment.embedding = Some(evidence.identity.1);
                                evidence.assessment.ir_embedding = Some(evidence.identity.2);
                                let (enr, _) =
                                    compatible_pair(engine, rgb_cosine, ir_cosine, skew_ms, true);
                                enrollment = Some(enr);
                                Ok(evidence.assessment)
                            },
                            Instant::now,
                        )
                        .unwrap();
                    assert_eq!(identities.get(), 1);
                    let PreparedGroup::Ready(a) = prepared else {
                        panic!("live grouped evidence must reach identity")
                    };
                    assert!(a.split_pair);
                    assert!(a.sequential_pair);
                    let enrollment = enrollment.unwrap();
                    if ir_cosine == 0.4 {
                        assert_compatible_but_insufficient_ir(engine, &enrollment, &a);
                    }
                    let out = engine
                        .authenticate_qualified_assessment(
                            &enrollment,
                            purpose,
                            Some("login"),
                            *a,
                            &(),
                        )
                        .unwrap();
                    assert_eq!(
                        out.granted,
                        ir_cosine == 0.8,
                        "rgb={rgb_cosine}, skew={skew_ms}: {out:?}"
                    );
                    if ir_cosine == 0.4 {
                        assert_eq!(out.kind, OutcomeKind::BelowThreshold);
                        assert!(out.live);
                    } else {
                        assert!(out.reason.contains("ir-fallback"), "{}", out.reason);
                    }
                }
            }
        }
    }
    engine.vit_scores.clear();
    engine.ir_available = previous_ir;
}
