use super::*;
use crate::grouped_auth::PreparedGroup;
use std::cell::Cell;
use std::time::{Duration, Instant};

fn sample(
    e: &mut Engine,
    index: usize,
    score: f32,
) -> DeferredAssessment<(usize, [f32; EMBED_DIM])> {
    let deny = e.vit_pad_votes_deny(score);
    let (_, mut assessment) = pad_matching_fixture(score, deny);
    assessment.signals.rgb_face = Some(irlume_liveness::FaceBox {
        cx: 0.5,
        cy: 0.5,
        score: 0.9,
    });
    assessment.ir_pad = PadEvidence::Score(0.1);
    let identity = (index, assessment.embedding.take().unwrap());
    DeferredAssessment {
        assessment,
        identity,
    }
}

#[test]
fn grouped_five_votes_materialize_only_final_sample_and_admit_once_qualified() {
    let _guard = env_guard();
    let mut s = shared();
    let e = &mut s.engine;
    let calls = Cell::new(0);
    let result = e
        .evaluate_grouped_samples_with(
            (0..5).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, i| Ok(sample(e, i, 0.2)),
            |_, mut evidence| {
                calls.set(calls.get() + 1);
                assert_eq!(evidence.identity.0, 4);
                evidence.assessment.embedding = Some(evidence.identity.1);
                evidence.assessment.ir_embedding = Some(evidence.identity.1.to_vec());
                Ok(evidence.assessment)
            },
            Instant::now,
        )
        .unwrap();
    assert_eq!(calls.get(), 1);
    let PreparedGroup::Ready(a) = result else {
        panic!("complete live group refused")
    };
    let (mut enr, _) = pad_matching_fixture(0.2, false);
    enr.profiles[0].scans[0].ir = Some(enr.profiles[0].scans[0].rgb.clone());
    let prior_ir = e.ir_available;
    e.ir_available = true;
    let out = e
        .authenticate_qualified_assessment(
            &enr,
            AuthenticationPurpose::Verify,
            Some("login"),
            *a,
            &(),
        )
        .unwrap();
    e.vit_scores.clear();
    e.ir_available = prior_ir;
    assert!(out.granted, "{}", out.reason);
}

#[test]
fn grouped_incomplete_or_spoof_evidence_never_materializes_identity() {
    let _guard = env_guard();
    let mut s = shared();
    for (count, score) in [(4, 0.2), (0, 0.2), (6, 0.2), (5, 0.99)] {
        s.engine.vit_scores.extend([0.2; 4]);
        let calls = Cell::new(0);
        let result = s.engine.evaluate_grouped_samples_with(
            (0..count).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, i| Ok(sample(e, i, score)),
            |_, evidence| {
                calls.set(calls.get() + 1);
                Ok(evidence.assessment)
            },
            Instant::now,
        );
        assert_eq!(calls.get(), 0, "count={count}, score={score}");
        assert!(!matches!(result, Ok(PreparedGroup::Ready(_))));
        assert!(s.engine.vit_scores.is_empty());
    }
}

#[test]
fn grouped_interrupted_evidence_does_not_reuse_prior_votes() {
    let _guard = env_guard();
    let mut s = shared();
    s.engine.vit_scores.extend([0.2; 4]);
    let result = s
        .engine
        .evaluate_grouped_samples_with(
            (0..5).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, i| {
                let mut v = sample(e, i, 0.2);
                if i == 2 {
                    v.assessment.verdict = Verdict::Uncertain;
                    v.assessment.reason = "unusable evidence".into();
                }
                Ok(v)
            },
            |_, _| panic!("interrupted votes reached identity"),
            Instant::now,
        )
        .unwrap();
    assert!(matches!(result, PreparedGroup::Refused(_)));
    assert!(s.engine.vit_scores.is_empty());
}

#[test]
fn grouped_required_pad_failure_is_terminal_before_identity() {
    let _guard = env_guard();
    let mut s = shared();
    for rgb_failure in [false, true] {
        let calls = Cell::new(0);
        let result = s
            .engine
            .evaluate_grouped_samples_with(
                (0..5).collect(),
                Instant::now() + Duration::from_secs(15),
                |e, i| {
                    calls.set(calls.get() + 1);
                    let mut v = sample(e, i, 0.2);
                    if rgb_failure {
                        v.assessment.rgb_pad = PadEvidence::Score(f32::NAN);
                    } else {
                        v.assessment.ir_pad = PadEvidence::InferenceFailed;
                    }
                    Ok(v)
                },
                |_, _| panic!("failed PAD reached identity"),
                Instant::now,
            )
            .unwrap();
        let PreparedGroup::Refused(out) = result else {
            panic!("failed PAD admitted")
        };
        assert_eq!(out.kind, OutcomeKind::OtherDeny);
        assert_eq!(calls.get(), 1);
        assert!(s.engine.vit_scores.is_empty());
    }
}

#[test]
fn grouped_deadline_checks_before_and_after_inference() {
    let _guard = env_guard();
    let mut s = shared();
    for expire_at in [0, 1, 5, 6] {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(15);
        let clock = Cell::new(start);
        if expire_at == 0 {
            clock.set(deadline);
        }
        let identities = Cell::new(0);
        let assessed = Cell::new(0);
        let result = s
            .engine
            .evaluate_grouped_samples_with(
                (0..5).collect(),
                deadline,
                |e, i| {
                    assessed.set(assessed.get() + 1);
                    let v = sample(e, i, 0.2);
                    if expire_at == i + 1 {
                        clock.set(deadline);
                    }
                    Ok(v)
                },
                |_, v| {
                    identities.set(identities.get() + 1);
                    clock.set(deadline);
                    Ok(v.assessment)
                },
                || clock.get(),
            )
            .unwrap();
        assert!(matches!(result, PreparedGroup::Refused(_)));
        assert_eq!(identities.get(), usize::from(expire_at == 6));
        if expire_at == 0 {
            assert_eq!(assessed.get(), 0);
        }
        assert!(s.engine.vit_scores.is_empty());
    }
}

#[test]
fn grouped_inference_errors_clear_all_evidence() {
    let _guard = env_guard();
    let mut s = shared();
    for fail_materialize in [false, true] {
        let result = s.engine.evaluate_grouped_samples_with(
            (0..5).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, i| {
                let v = sample(e, i, 0.2);
                if i == 2 && !fail_materialize {
                    Err(irlume_common::Error::Hardware("scripted failure".into()))
                } else {
                    Ok(v)
                }
            },
            |_, _| {
                Err(irlume_common::Error::Hardware(
                    "scripted identity failure".into(),
                ))
            },
            Instant::now,
        );
        assert!(result.is_err());
        assert!(s.engine.vit_scores.is_empty());
    }
}

#[test]
fn grouped_sequential_pair_requires_final_ir_identity() {
    let _guard = env_guard();
    let mut s = shared();
    let e = &mut s.engine;
    let prior_ir = e.ir_available;
    e.ir_available = true;
    for (gap_ms, ir_matches) in [
        (1000, false),
        (3000, false),
        (3001, false),
        (1000, true),
        (3000, true),
        (3001, true),
    ] {
        let identities = Cell::new(0);
        let result = e
            .evaluate_grouped_samples_with(
                (0..5).collect(),
                Instant::now() + Duration::from_secs(15),
                |e, i| {
                    let mut v = sample(e, i, 0.2);
                    // Emulate the shared legacy assessment's result; grouped
                    // preparation must enforce its separated capture policy.
                    v.assessment.sequential_pair =
                        pair_admitted_sequentially(Duration::from_millis(gap_ms), true);
                    Ok(v)
                },
                |_, mut v| {
                    identities.set(identities.get() + 1);
                    v.assessment.embedding = Some(v.identity.1);
                    let mut ir = v.identity.1.to_vec();
                    if !ir_matches {
                        ir[0] = 0.0;
                        ir[1] = 1.0;
                    }
                    v.assessment.ir_embedding = Some(ir);
                    Ok(v.assessment)
                },
                Instant::now,
            )
            .unwrap();
        let PreparedGroup::Ready(a) = result else {
            panic!("live paired group refused before match")
        };
        let (mut enr, _) = pad_matching_fixture(0.2, false);
        enr.profiles[0].scans[0].ir = Some(enr.profiles[0].scans[0].rgb.clone());
        let out = e
            .authenticate_qualified_assessment(
                &enr,
                AuthenticationPurpose::Verify,
                Some("login"),
                *a,
                &(),
            )
            .unwrap();
        assert_eq!(identities.get(), 1);
        assert_eq!(out.granted, ir_matches, "{}", out.reason);
        if !ir_matches {
            assert_eq!(out.kind, OutcomeKind::BelowThreshold);
            assert!(!presence_retryable(&out));
        }
    }
    e.ir_available = prior_ir;
    e.vit_scores.clear();
}

#[test]
fn grouped_dark_final_sample_uses_real_ir_presence_and_existing_gates() {
    let _guard = env_guard();
    let mut s = shared();
    let e = &mut s.engine;
    let prior_ir = e.ir_available;
    e.ir_available = true;
    for (lit, ir_failure, ir_matches) in [
        (false, false, true),
        (true, false, true),
        (false, true, true),
        (false, false, false),
    ] {
        let identities = Cell::new(0);
        let result = e
            .evaluate_grouped_samples_with(
                (0..5).collect(),
                Instant::now() + Duration::from_secs(15),
                |e, i| {
                    let mut v = sample(e, i, 0.2);
                    v.assessment.signals = Signals {
                        rgb_face: None,
                        ir_face: Some(irlume_liveness::FaceBox {
                            cx: 0.5,
                            cy: 0.5,
                            score: 0.9,
                        }),
                        ir_face_brightness: 90.0,
                        ir_center_edge_ratio: 1.2,
                        ir_eye_glint: Some(220.0),
                        ir_ceiling_known: true,
                        ir_saturated_frac: Some(0.0),
                        ..Signals::default()
                    };
                    v.assessment.verdict = Verdict::Uncertain;
                    v.assessment.reason = "no RGB face".into();
                    v.assessment.rgb_pad = PadEvidence::NotApplicable;
                    v.assessment.rgb_frame_mean = if lit { 120.0 } else { 10.0 };
                    if ir_failure {
                        v.assessment.ir_pad = PadEvidence::InferenceFailed;
                    }
                    Ok(v)
                },
                |_, mut v| {
                    identities.set(identities.get() + 1);
                    let mut ir = v.identity.1.to_vec();
                    if !ir_matches {
                        ir[0] = 0.0;
                        ir[1] = 1.0;
                    }
                    v.assessment.ir_embedding = Some(ir);
                    Ok(v.assessment)
                },
                Instant::now,
            )
            .unwrap();
        let out = match result {
            PreparedGroup::Refused(o) => o,
            PreparedGroup::Ready(a) => {
                assert!(a.embedding.is_none());
                let (mut enr, _) = pad_matching_fixture(0.2, false);
                enr.profiles[0].scans[0].ir = Some(enr.profiles[0].scans[0].rgb.clone());
                e.authenticate_qualified_assessment(
                    &enr,
                    AuthenticationPurpose::Verify,
                    Some("login"),
                    *a,
                    &(),
                )
                .unwrap()
            }
        };
        assert_eq!(
            out.granted,
            !lit && !ir_failure && ir_matches,
            "{}",
            out.reason
        );
        assert_eq!(identities.get(), usize::from(!lit && !ir_failure));
    }
    e.ir_available = prior_ir;
    e.vit_scores.clear();
}

#[test]
fn grouped_pending_retry_keeps_existing_budget_and_never_adds_identity_attempts() {
    let _guard = env_guard();
    let mut s = shared();
    let start = Instant::now();
    let clock = Cell::new(start);
    let groups = Cell::new(0);
    let mut worst = Duration::ZERO;
    let (result, fallback) = s.engine.authentication_attempt_loop_with(
        start + Duration::from_secs(15),
        15_000,
        &mut worst,
        |e| {
            groups.set(groups.get() + 1);
            assert_eq!(groups.get(), 1, "extra expensive group");
            let prepared = e
                .evaluate_grouped_samples_with(
                    (0..5).collect(),
                    start + Duration::from_secs(15),
                    |e, i| {
                        clock.set(clock.get() + Duration::from_millis(2000));
                        let mut v = sample(e, i, 0.2);
                        if i == 1 {
                            v.assessment.verdict = Verdict::Uncertain;
                            v.assessment.reason = "unusable".into();
                        }
                        Ok(v)
                    },
                    |_, _| panic!("incomplete group reached identity"),
                    || clock.get(),
                )
                .unwrap();
            let PreparedGroup::Refused(o) = prepared else {
                panic!("pending group admitted")
            };
            (Ok(o), false)
        },
        || clock.get(),
    );
    assert!(!fallback);
    assert!(!result.unwrap().granted);
    assert_eq!(groups.get(), 1);
    assert_eq!(worst, Duration::from_secs(10));
}

#[test]
fn grouped_required_pad_failures_precede_retryable_outcomes_and_stop_before_dark_final() {
    let _guard = env_guard();
    let mut s = shared();
    for failure in [
        PadEvidence::Unavailable,
        PadEvidence::InferenceFailed,
        PadEvidence::Score(f32::NAN),
        PadEvidence::Score(f32::INFINITY),
    ] {
        for route in 0..4 {
            let assessed = Cell::new(0);
            let identities = Cell::new(0);
            let result = s
                .engine
                .evaluate_grouped_samples_with(
                    (0..5).collect(),
                    Instant::now() + Duration::from_secs(15),
                    |e, i| {
                        assessed.set(assessed.get() + 1);
                        let mut v = sample(e, i, 0.2);
                        v.assessment.signals.ir_face = Some(irlume_liveness::FaceBox {
                            cx: 0.5,
                            cy: 0.5,
                            score: 0.9,
                        });
                        if i == 0 {
                            v.assessment.verdict = Verdict::Uncertain;
                            v.assessment.rgb_pad = PadEvidence::NotApplicable;
                            v.assessment.ir_pad = failure;
                            if route > 0 {
                                v.assessment.signals.rgb_face = None;
                            }
                            v.assessment.rgb_frame_mean = if route == 1 { 120.0 } else { 10.0 };
                            if route == 3 {
                                v.assessment.signals.rgb_face = Some(irlume_liveness::FaceBox {
                                    cx: 0.5,
                                    cy: 0.5,
                                    score: 0.9,
                                });
                                v.assessment.rgb_pad = failure;
                                v.assessment.ir_pad = PadEvidence::Score(0.1);
                            }
                        } else {
                            // If the failure is swallowed, later evidence can reach
                            // the independent dark identity route without RGB votes.
                            v.assessment.signals = Signals {
                                ir_face: v.assessment.signals.ir_face,
                                ir_face_brightness: 90.0,
                                ir_center_edge_ratio: 1.2,
                                ir_eye_glint: Some(220.0),
                                ir_ceiling_known: true,
                                ir_saturated_frac: Some(0.0),
                                ..Signals::default()
                            };
                            v.assessment.verdict = Verdict::Uncertain;
                            v.assessment.rgb_pad = PadEvidence::NotApplicable;
                            v.assessment.rgb_frame_mean = 10.0;
                        }
                        Ok(v)
                    },
                    |_, v| {
                        identities.set(identities.get() + 1);
                        Ok(v.assessment)
                    },
                    Instant::now,
                )
                .unwrap();
            assert_eq!(identities.get(), 0, "route={route}, failure={failure:?}");
            assert_eq!(
                assessed.get(),
                1,
                "required failure must terminate the batch"
            );
            let PreparedGroup::Refused(out) = result else {
                panic!("failure reached final identity")
            };
            assert_eq!(out.kind, OutcomeKind::OtherDeny);
            assert!(!presence_retryable(&out));
            assert!(s.engine.vit_scores.is_empty());
        }
    }
}

#[test]
fn grouped_deadline_facts_are_current_or_empty_before_any_assessment() {
    let _guard = env_guard();
    let mut s = shared();
    for expire_after in [0, 1, 2] {
        s.engine.last_attempt_facts = AttemptFacts {
            rgb_face: Some((0.9, 0.9)),
            face_frac: 0.2,
            ..AttemptFacts::default()
        };
        let start = Instant::now();
        let deadline = start + Duration::from_secs(15);
        let clock = Cell::new(if expire_after == 0 { deadline } else { start });
        let result = s
            .engine
            .evaluate_grouped_samples_with(
                (0..5).collect(),
                deadline,
                |e, i| {
                    let mut v = sample(e, i, 0.2);
                    v.assessment.signals.face_frac = 0.2;
                    v.assessment.signals.rgb_face_brightness = 150.0;
                    v.assessment.signals.head_yaw_asym =
                        if i + 1 == expire_after { 1.0 } else { 0.0 };
                    if i + 1 == expire_after {
                        clock.set(deadline);
                    }
                    Ok(v)
                },
                |_, _| panic!("expired group reached identity"),
                || clock.get(),
            )
            .unwrap();
        let PreparedGroup::Refused(out) = result else {
            panic!("expired group admitted")
        };
        assert_eq!(
            auth_attempt_situation(out.kind, &s.engine.last_attempt_facts),
            if expire_after == 0 {
                AttemptSituation::NoFace
            } else {
                AttemptSituation::LookingAway
            }
        );
    }
}

fn measured_sequential_configuration() -> CaptureModeSelection {
    CaptureModeSelection {
        sequential: true,
        source: STORED_CAPTURE_MODE_SOURCE,
        runtime_key: Some("fixture".into()),
        runtime_contract: None,
        qualification_state: irlume_common::diagnostics::QualificationState::MeasuredSequential,
        qualification_reason: None,
        authoritative_rate_shortfalls: None,
        latest_attempt_rate_shortfalls: None,
        operation_demoted: Cell::new(false),
    }
}

#[test]
fn grouped_eligibility_keeps_service_and_purpose_scope_despite_long_override() {
    let _guard = env_guard();
    let saved = std::env::var_os("IRLUME_GRACE_MS");
    std::env::set_var("IRLUME_GRACE_MS", "30000");
    let mode = measured_sequential_configuration();
    let mut results = Vec::new();
    for (service, expected) in [
        (Some("login"), true),
        (Some("swaylock"), true),
        (None, true),
        (Some("unknown-local-service"), true),
        (Some(" sudo "), false),
        (Some("su"), false),
        (Some("doas"), false),
        (Some("polkit-1"), false),
        (Some("sshd"), false),
    ] {
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::AppConsent,
            AuthenticationPurpose::CredentialRelease {
                temporal_challenge: false,
            },
            AuthenticationPurpose::CredentialRelease {
                temporal_challenge: true,
            },
        ] {
            let actual = crate::grouped_auth::eligible_configuration(
                &mode,
                true,
                true,
                true,
                grace_window_ms(service),
                purpose,
                service,
            );
            results.push((
                service,
                purpose,
                actual,
                expected && purpose == AuthenticationPurpose::Verify,
            ));
        }
    }
    match saved {
        Some(v) => std::env::set_var("IRLUME_GRACE_MS", v),
        None => std::env::remove_var("IRLUME_GRACE_MS"),
    }
    for (service, purpose, actual, expected) in results {
        assert_eq!(actual, expected, "service={service:?}, purpose={purpose:?}");
    }
}

#[test]
fn grouped_eligibility_requires_qualification_models_budget_and_exact_contract() {
    use irlume_common::diagnostics::QualificationState;
    let check = |mode: &CaptureModeSelection, ir, rgb_pad, ir_pad, window| {
        crate::grouped_auth::eligible_configuration(
            mode,
            ir,
            rgb_pad,
            ir_pad,
            window,
            AuthenticationPurpose::Verify,
            Some("login"),
        )
    };
    let mut mode = measured_sequential_configuration();
    assert!(check(&mode, true, true, true, 15000));
    assert!(check(&mode, true, true, true, 30000));
    for (ir, rgb_pad, ir_pad, window) in [
        (false, true, true, 15000),
        (true, false, true, 15000),
        (true, true, false, 15000),
        (true, true, true, 14999),
    ] {
        assert!(!check(&mode, ir, rgb_pad, ir_pad, window));
    }
    assert!(
        !crate::grouped_auth::eligible(
            &mode,
            true,
            true,
            true,
            15000,
            AuthenticationPurpose::Verify,
            Some("login")
        ),
        "configuration cannot manufacture a runtime contract"
    );
    mode.sequential = false;
    assert!(!check(&mode, true, true, true, 15000));
    mode.sequential = true;
    mode.source = ENV_CAPTURE_MODE_SOURCE;
    assert!(!check(&mode, true, true, true, 15000));
    mode.source = STORED_CAPTURE_MODE_SOURCE;
    mode.qualification_state = QualificationState::QualifiedConcurrent;
    assert!(!check(&mode, true, true, true, 15000));
    mode.qualification_state = QualificationState::MeasuredSequential;
    mode.operation_demoted.set(true);
    assert!(!check(&mode, true, true, true, 15000));
}

#[test]
fn grouped_missing_face_not_applicable_is_retryable_before_valid_dark_identity() {
    let _guard = env_guard();
    let mut s = shared();
    for rgb_present in [false, true] {
        let assessed = Cell::new(0);
        let identities = Cell::new(0);
        let result = s
            .engine
            .evaluate_grouped_samples_with(
                (0..5).collect(),
                Instant::now() + Duration::from_secs(15),
                |e, i| {
                    assessed.set(assessed.get() + 1);
                    let mut v = sample(e, i, 0.2);
                    v.assessment.verdict = Verdict::Uncertain;
                    v.assessment.rgb_pad = PadEvidence::NotApplicable;
                    v.assessment.ir_pad = PadEvidence::NotApplicable;
                    if !rgb_present {
                        v.assessment.signals.rgb_face = None;
                    }
                    if i == 4 {
                        v.assessment.signals = Signals {
                            ir_face: Some(irlume_liveness::FaceBox {
                                cx: 0.5,
                                cy: 0.5,
                                score: 0.9,
                            }),
                            ir_face_brightness: 90.0,
                            ir_center_edge_ratio: 1.2,
                            ir_eye_glint: Some(220.0),
                            ir_ceiling_known: true,
                            ir_saturated_frac: Some(0.0),
                            ..Signals::default()
                        };
                        v.assessment.ir_pad = PadEvidence::Score(0.1);
                        v.assessment.rgb_frame_mean = 10.0;
                    }
                    Ok(v)
                },
                |_, mut v| {
                    identities.set(identities.get() + 1);
                    assert_eq!(v.identity.0, 4);
                    v.assessment.ir_embedding = Some(v.identity.1.to_vec());
                    Ok(v.assessment)
                },
                Instant::now,
            )
            .unwrap();
        assert_eq!(assessed.get(), 5);
        assert_eq!(identities.get(), 1);
        let PreparedGroup::Ready(a) = result else {
            panic!("missing face permanently denied later dark evidence")
        };
        let (mut enr, _) = pad_matching_fixture(0.2, false);
        enr.profiles[0].scans[0].ir = Some(enr.profiles[0].scans[0].rgb.clone());
        let prior_ir = s.engine.ir_available;
        s.engine.ir_available = true;
        let out = s
            .engine
            .authenticate_qualified_assessment(
                &enr,
                AuthenticationPurpose::Verify,
                Some("login"),
                *a,
                &(),
            )
            .unwrap();
        s.engine.ir_available = prior_ir;
        s.engine.vit_scores.clear();
        assert!(out.granted, "{}", out.reason);
    }
}
