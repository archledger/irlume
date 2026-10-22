// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

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
    for purpose in [
        AuthenticationPurpose::Verify,
        AuthenticationPurpose::CredentialRelease,
    ] {
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
        // This fixture models a new raw-IR capture, whose producer records a tag.
        enr.profiles[0].scans[0].ir_space = Some("raw".into());
        let prior_ir = e.ir_available;
        e.ir_available = true;
        let out = e
            .authenticate_qualified_assessment(&enr, purpose, Some("login"), *a, &())
            .unwrap();
        e.vit_scores.clear();
        e.ir_available = prior_ir;
        assert!(out.granted, "{}", out.reason);
    }
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
        assert_eq!(out.kind, OutcomeKind::RuntimeUnavailable);
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
        let PreparedGroup::Refused(out) = result else {
            panic!("expired group admitted")
        };
        assert_eq!(out.kind, OutcomeKind::DeadlineExpired);
        assert!(!out.granted);
        assert!(!out.live);
        assert_eq!(out.score, 0.0);
        assert!(!presence_retryable(&out));
        assert_eq!(identities.get(), usize::from(expire_at == 6));
        if expire_at == 0 {
            assert_eq!(assessed.get(), 0);
        }
        assert!(s.engine.vit_scores.is_empty());
    }
}

#[test]
fn grouped_request_cancellation_checks_before_and_after_inference() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let _guard = env_guard();
    let mut s = shared();
    for cancel_at in [0, 1, 5, 6] {
        let cancelled = std::sync::Arc::new(AtomicBool::new(cancel_at == 0));
        let signal = std::sync::Arc::clone(&cancelled);
        s.engine
            .set_request_cancel_signal(std::sync::Arc::new(move || signal.load(Ordering::SeqCst)));
        let identities = Cell::new(0);
        let assessed = Cell::new(0);
        let result = s.engine.evaluate_grouped_samples_with(
            (0..5).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, i| {
                assessed.set(assessed.get() + 1);
                let evidence = sample(e, i, 0.2);
                if cancel_at == i + 1 {
                    cancelled.store(true, Ordering::SeqCst);
                }
                Ok(evidence)
            },
            |_, evidence| {
                identities.set(identities.get() + 1);
                cancelled.store(true, Ordering::SeqCst);
                Ok(evidence.assessment)
            },
            Instant::now,
        );
        s.engine.request_cancelled = None;
        let cleared = s.engine.vit_scores.is_empty();
        s.engine.vit_scores.clear();
        assert!(matches!(result, Err(irlume_common::Error::Preempted(_))));
        assert_eq!(identities.get(), usize::from(cancel_at == 6));
        assert_eq!(assessed.get(), cancel_at.min(5));
        assert!(cleared, "cancelled group must discard pending evidence");
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
    for (gap_ms, ir_matches, tagged) in [
        (1000, false, true),
        (3000, false, true),
        (3001, false, true),
        (1000, true, true),
        (3000, true, true),
        (3001, true, true),
        (1000, true, false),
        (3000, true, false),
        (3001, true, false),
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
        // This fixture models a new raw-IR capture, whose producer records a tag.
        enr.profiles[0].scans[0].ir_space = tagged.then(|| "raw".into());
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
        assert_eq!(out.granted, ir_matches && tagged, "{}", out.reason);
        if !ir_matches || !tagged {
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
    for (lit, ir_failure, ir_matches, tagged) in [
        (false, false, true, true),
        (true, false, true, true),
        (false, true, true, true),
        (false, false, false, true),
        (false, false, true, false),
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
                // This fixture models a new raw-IR capture, whose producer records a tag.
                enr.profiles[0].scans[0].ir_space = tagged.then(|| "raw".into());
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
            !lit && !ir_failure && ir_matches && tagged,
            "{}",
            out.reason
        );
        assert_eq!(identities.get(), usize::from(!lit && !ir_failure));
        if !tagged {
            assert_eq!(out.kind, OutcomeKind::OtherDeny);
            assert!(out.reason.contains("no enrolled IR scans are compatible"));
        }
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
    let (result, fallback, _deferred) = s.engine.authentication_attempt_loop_with(
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
            (Ok(o), false, None::<()>)
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
            assert_eq!(out.kind, OutcomeKind::RuntimeUnavailable);
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
        let facts = &s.engine.last_attempt_facts;
        if expire_after == 0 {
            assert!(facts.rgb_face.is_none());
            assert_eq!(facts.face_frac, 0.0);
            assert_eq!(facts.yaw_asym, 0.0);
        } else {
            assert_eq!(facts.face_frac, 0.2);
            assert_eq!(facts.rgb_face_brightness, 150.0);
            assert_eq!(facts.yaw_asym, 1.0);
            assert_ne!(facts.rgb_face, Some((0.9, 0.9)));
        }
        assert_eq!(
            attempt_situation_label(auth_attempt_situation(out.kind, facts)),
            "timed out"
        );
    }
}

#[test]
fn grouped_deadline_keeps_timeout_label_through_retry_loop() {
    let _guard = env_guard();
    let mut s = shared();
    let start = Instant::now();
    let deadline = start + Duration::from_secs(15);
    let clock = Cell::new(start);
    let mut calls = 0;
    let mut costliest = Duration::ZERO;
    let (result, fallback, _deferred) = s.engine.authentication_attempt_loop_with(
        deadline,
        15_000,
        &mut costliest,
        |engine| {
            calls += 1;
            assert_eq!(calls, 1, "expired evidence must not be retried");
            let prepared = engine.evaluate_grouped_samples_with(
                (0..5).collect(),
                deadline,
                |e, i| {
                    let mut v = sample(e, i, 0.2);
                    v.assessment.signals.face_frac = 0.2;
                    v.assessment.signals.rgb_face_brightness = 150.0;
                    v.assessment.signals.ir_eye_glint = Some(0.0);
                    clock.set(deadline);
                    Ok(v)
                },
                |_, _| panic!("expired group reached identity"),
                || clock.get(),
            );
            let PreparedGroup::Refused(out) = prepared.unwrap() else {
                panic!("expired group admitted")
            };
            (Ok(out), false, None::<()>)
        },
        || clock.get(),
    );
    let out = result.unwrap();
    assert_eq!(calls, 1);
    assert_eq!(costliest, Duration::from_secs(15));
    assert!(!fallback);
    assert_eq!(out.kind, OutcomeKind::DeadlineExpired);
    assert!(!out.granted);
    assert!(!presence_retryable(&out));
    assert_eq!(s.engine.last_attempt_situation_label(), Some("timed out"));
    let facts = &s.engine.last_attempt_facts;
    assert_eq!(facts.glint, Some(0.0));
    assert!(attempt_situation_line(out.kind, out.score, facts).starts_with("attempt: timed out;"));
    assert_eq!(
        auth_attempt_situation(OutcomeKind::OtherDeny, facts),
        AttemptSituation::GlintBelow,
        "ordinary refusals must retain their framing classification"
    );
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
    for (service, verify, release) in [
        (Some("login"), true, true),
        (Some("swaylock"), true, true),
        (None, true, false),
        (Some("unknown-local-service"), true, false),
        (Some(" sudo "), false, false),
        (Some("su"), false, false),
        (Some("doas"), false, false),
        (Some("polkit-1"), false, false),
        (Some("sshd"), false, false),
    ] {
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::AppConsent,
            AuthenticationPurpose::CredentialRelease,
        ] {
            let actual = crate::grouped_auth::eligible_configuration(
                &mode,
                true,
                true,
                true,
                grace_window_ms(service),
                purpose,
                service,
                false,
            );
            results.push((
                service,
                purpose,
                actual,
                match purpose {
                    AuthenticationPurpose::Verify => verify,
                    AuthenticationPurpose::CredentialRelease => release,
                    AuthenticationPurpose::AppConsent => false,
                },
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

/// A split group serves exactly the services and purposes an ordinary
/// measured sequential group serves (ADR-0032, amendment 2026-10-13,
/// section 8), privileged opt-in included.
#[test]
fn split_grouped_scope_matches_the_ordinary_grouped_scope() {
    let mode = measured_sequential_configuration();
    for service in [
        Some("login"),
        Some("swaylock"),
        Some("gdm-password"),
        None,
        Some("unknown-local-service"),
        Some("sudo"),
        Some("polkit-1"),
        Some("sshd"),
    ] {
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::AppConsent,
            AuthenticationPurpose::CredentialRelease,
        ] {
            for opt_in in [false, true] {
                let window = crate::GRACE_WINDOW_MS;
                assert_eq!(
                    crate::grouped_auth::split_eligible_configuration(
                        true, true, true, window, purpose, service, opt_in,
                    ),
                    crate::grouped_auth::eligible_configuration(
                        &mode, true, true, true, window, purpose, service, opt_in,
                    ),
                    "service={service:?}, purpose={purpose:?}, opt_in={opt_in}"
                );
            }
        }
    }
}

/// A split group needs IR, both PAD models and a window of at least
/// `GRACE_WINDOW_MS`; there is no qualification to require.
#[test]
fn split_grouped_eligibility_requires_ir_both_pad_models_and_the_window() {
    let eligible = |ir, rgb_pad, ir_pad, window| {
        crate::grouped_auth::split_eligible_configuration(
            ir,
            rgb_pad,
            ir_pad,
            window,
            AuthenticationPurpose::Verify,
            Some("login"),
            false,
        )
    };
    let window = crate::GRACE_WINDOW_MS;
    assert!(eligible(true, true, true, window));
    assert!(eligible(true, true, true, window + 1));
    assert!(!eligible(true, true, true, window - 1));
    assert!(!eligible(false, true, true, window));
    assert!(!eligible(true, false, true, window));
    assert!(!eligible(true, true, false, window));
}

#[test]
fn grouped_cold_login_release_uses_complete_collection_only_for_known_local_services() {
    let mode = measured_sequential_configuration();
    for (service, expected) in [
        (Some("plasmalogin"), true),
        (Some("gdm-password"), true),
        (Some("cosmic-greeter"), true),
        (Some("login"), true),
        (Some("kde"), true),
        (Some("sudo"), false),
        (Some("polkit-1"), false),
        (Some("sshd"), false),
        (Some("unknown-local-service"), false),
        (None, false),
    ] {
        assert_eq!(
            crate::grouped_auth::eligible_configuration(
                &mode,
                true,
                true,
                true,
                15_000,
                AuthenticationPurpose::CredentialRelease,
                service,
                false,
            ),
            expected,
            "service={service:?}"
        );
    }
}

/// The owner's opt-in widens the collector to the privileged surfaces and to
/// nothing else. Credential release keeps its own rule (a wallet secret must
/// name a known local login/lock service), a remote service stays out, and every
/// runtime requirement below the scope check still binds.
#[test]
fn privileged_opt_in_widens_scope_without_touching_credential_release() {
    let mode = measured_sequential_configuration();
    let check = |purpose, service, opt_in| {
        crate::grouped_auth::eligible_configuration(
            &mode, true, true, true, 15_000, purpose, service, opt_in,
        )
    };
    for service in [Some("sudo"), Some("su"), Some("doas")] {
        assert!(
            !check(AuthenticationPurpose::Verify, service, false),
            "{service:?} without the opt-in"
        );
        assert!(
            check(AuthenticationPurpose::Verify, service, true),
            "{service:?} with the opt-in"
        );
        assert!(
            !check(AuthenticationPurpose::CredentialRelease, service, true),
            "{service:?} must not reach a wallet secret"
        );
    }
    // polkit reaches the daemon as AppConsent, the arm that was a hard false.
    assert!(!check(
        AuthenticationPurpose::AppConsent,
        Some("polkit-1"),
        false
    ));
    assert!(check(
        AuthenticationPurpose::AppConsent,
        Some("polkit-1"),
        true
    ));
    assert!(!check(
        AuthenticationPurpose::CredentialRelease,
        Some("polkit-1"),
        true
    ));
    // Remote is neither privileged nor local, so the opt-in cannot reach it.
    assert!(!check(AuthenticationPurpose::Verify, Some("sshd"), true));
    // Scope only: the budget requirement is unchanged by the opt-in.
    assert!(!crate::grouped_auth::eligible_configuration(
        &mode,
        true,
        true,
        true,
        14_999,
        AuthenticationPurpose::Verify,
        Some("sudo"),
        true,
    ));
}

/// The newly eligible privileged services behave like the greeter inside the
/// collector: a complete vote window grants, an incomplete one never reaches
/// identity, and a deadline or a cancellation is terminal with the evidence
/// discarded.
#[test]
fn privileged_grouped_collection_grants_refuses_and_expires_like_a_greeter() {
    let _guard = env_guard();
    let mut s = shared();
    for (service, purpose) in [
        (Some("sudo"), AuthenticationPurpose::Verify),
        (Some("polkit-1"), AuthenticationPurpose::AppConsent),
    ] {
        // Complete evidence: identity runs once, on the final sample, and grants.
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
        assert_eq!(calls.get(), 1, "{service:?}");
        let PreparedGroup::Ready(a) = result else {
            panic!("{service:?}: complete live group refused")
        };
        let (mut enr, _) = pad_matching_fixture(0.2, false);
        enr.profiles[0].scans[0].ir = Some(enr.profiles[0].scans[0].rgb.clone());
        enr.profiles[0].scans[0].ir_space = Some("raw".into());
        let prior_ir = e.ir_available;
        e.ir_available = true;
        let out = e
            .authenticate_qualified_assessment(&enr, purpose, service, *a, &())
            .unwrap();
        e.vit_scores.clear();
        e.ir_available = prior_ir;
        assert!(out.granted, "{service:?}: {}", out.reason);

        // Incomplete evidence: no identity, no grant, ring cleared.
        let calls = Cell::new(0);
        let result = e.evaluate_grouped_samples_with(
            (0..4).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, i| Ok(sample(e, i, 0.2)),
            |_, evidence| {
                calls.set(calls.get() + 1);
                Ok(evidence.assessment)
            },
            Instant::now,
        );
        assert_eq!(calls.get(), 0, "{service:?}");
        assert!(!matches!(result, Ok(PreparedGroup::Ready(_))));
        assert!(e.vit_scores.is_empty(), "{service:?}");

        // Deadline: terminal, not retryable, nothing retained.
        let start = Instant::now();
        let deadline = start + Duration::from_secs(15);
        let clock = Cell::new(start);
        let result = e
            .evaluate_grouped_samples_with(
                (0..5).collect(),
                deadline,
                |e, i| {
                    let v = sample(e, i, 0.2);
                    if i == 1 {
                        clock.set(deadline);
                    }
                    Ok(v)
                },
                |_, v| Ok(v.assessment),
                || clock.get(),
            )
            .unwrap();
        let PreparedGroup::Refused(out) = result else {
            panic!("{service:?}: expired group admitted")
        };
        assert_eq!(out.kind, OutcomeKind::DeadlineExpired);
        assert!(!presence_retryable(&out), "{service:?}");
        assert!(e.vit_scores.is_empty(), "{service:?}");

        // Cancellation: preempted, evidence discarded.
        use std::sync::atomic::{AtomicBool, Ordering};
        let cancelled = std::sync::Arc::new(AtomicBool::new(false));
        let signal = std::sync::Arc::clone(&cancelled);
        e.set_request_cancel_signal(std::sync::Arc::new(move || signal.load(Ordering::SeqCst)));
        let result = e.evaluate_grouped_samples_with(
            (0..5).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, i| {
                let v = sample(e, i, 0.2);
                if i == 1 {
                    cancelled.store(true, Ordering::SeqCst);
                }
                Ok(v)
            },
            |_, v| Ok(v.assessment),
            Instant::now,
        );
        e.request_cancelled = None;
        let cleared = e.vit_scores.is_empty();
        e.vit_scores.clear();
        assert!(
            matches!(result, Err(irlume_common::Error::Preempted(_))),
            "{service:?}"
        );
        assert!(
            cleared,
            "{service:?}: cancelled group must discard evidence"
        );
    }
}

/// With the opt-in on, the budget replacement follows the request's capture
/// route: a privileged request that could use the collector gets the login
/// window, and one that could not keeps the short one. This is the invariant
/// that a flag applied inside `grace_window_ms` broke — there the route is not
/// known yet, so concurrent, unqualified, runtime-demoted and IR-only requests
/// were handed a longer failure budget they cannot spend.
#[test]
fn privileged_budget_follows_the_capture_route_not_the_service_name() {
    use irlume_common::diagnostics::QualificationState;
    let ready = |mode: &CaptureModeSelection, ir, rgb_pad, ir_pad, service| {
        crate::grouped_auth::eligible_configuration(
            mode,
            ir,
            rgb_pad,
            ir_pad,
            crate::GRACE_WINDOW_MS,
            AuthenticationPurpose::Verify,
            service,
            true,
        )
    };
    let mode = measured_sequential_configuration();
    assert!(ready(&mode, true, true, true, Some("sudo")));
    assert_eq!(
        crate::privileged_budget_for_route(crate::SUDO_GRACE_WINDOW_MS, false, true, || true),
        Some(crate::GRACE_WINDOW_MS)
    );

    // Each non-grouped route, with the flag still on: no replacement.
    for (label, broken) in [
        ("models absent", None),
        ("concurrent", Some(QualificationState::QualifiedConcurrent)),
        (
            "unqualified",
            Some(QualificationState::UnqualifiedNoAuthority),
        ),
    ] {
        let mut m = mode.clone();
        let ir_pad = match broken {
            Some(state) => {
                m.qualification_state = state;
                true
            }
            None => false,
        };
        let route_ready = ready(&m, true, true, ir_pad, Some("sudo"));
        assert!(!route_ready, "{label} must not reach grouped collection");
        assert_eq!(
            crate::privileged_budget_for_route(
                crate::SUDO_GRACE_WINDOW_MS,
                false,
                route_ready,
                || true
            ),
            None,
            "{label} must keep the short privileged window"
        );
    }
    let demoted = mode.clone();
    demoted.operation_demoted.set(true);
    assert!(!ready(&demoted, true, true, true, Some("sudo")));

    // Experimental IR-only never consults this collector: it returns on its own
    // route before the decision, so the short window stands whatever the flag
    // says. Asserted as the sensor policy's own early return in
    // `authenticate_in_window_inner`; here we pin the budget half.
    assert_eq!(
        crate::privileged_budget_for_route(crate::SUDO_GRACE_WINDOW_MS, false, false, || true),
        None
    );
}

#[test]
fn grouped_eligibility_requires_qualification_models_budget_and_exact_contract() {
    use irlume_common::diagnostics::QualificationState;
    for purpose in [
        AuthenticationPurpose::Verify,
        AuthenticationPurpose::CredentialRelease,
    ] {
        let check = |mode: &CaptureModeSelection, ir, rgb_pad, ir_pad, window| {
            crate::grouped_auth::eligible_configuration(
                mode,
                ir,
                rgb_pad,
                ir_pad,
                window,
                purpose,
                Some("login"),
                false,
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
            !crate::grouped_auth::eligible(&mode, true, true, true, 15000, purpose, Some("login")),
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
        // This fixture models a new raw-IR capture, whose producer records a tag.
        enr.profiles[0].scans[0].ir_space = Some("raw".into());
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

#[test]
fn grouped_deadline_classification_survives_the_real_engine_scope() {
    let _guard = env_guard();
    let mut state = shared();
    let expired = Instant::now();
    state.engine.authentication_deadline = Some(expired);
    let result = state.engine.evaluate_grouped_samples_with(
        (0..5).collect(),
        expired,
        |_, _| panic!("expired group must not assess evidence"),
        |_, _: DeferredAssessment<()>| panic!("expired group must not materialize identity"),
        Instant::now,
    );
    state.engine.authentication_deadline = None;
    assert!(
        matches!(result, Ok(PreparedGroup::Refused(ref outcome)) if outcome.kind == OutcomeKind::DeadlineExpired)
    );
}

/// One convenience-tier RGB sample: a live fixture face whose PAD score is
/// pushed into the vote, identity carried as the deferred RGB image.
fn rgb_only_sample(e: &mut Engine, score: f32) -> DeferredAssessment<PairIdentity> {
    let deny = e.vit_pad_votes_deny(score);
    let (_, mut assessment) = pad_matching_fixture(score, deny);
    assessment.signals.rgb_face = Some(irlume_liveness::FaceBox {
        cx: 0.5,
        cy: 0.5,
        score: 0.9,
    });
    let identity_image = assessment.embedding.take().map(|_| IdentityImage {
        data: vec![128u8; 16],
        width: 4,
        height: 4,
        face: Detection {
            bbox: [0.0, 0.0, 1.0, 1.0],
            score: 0.9,
            landmarks: [(0.0, 0.0); 5],
        },
    });
    DeferredAssessment {
        assessment,
        identity: (identity_image, None),
    }
}

/// An RGB sample with no face: no PAD score is contributed.
fn rgb_only_no_face_sample() -> DeferredAssessment<PairIdentity> {
    let (_, mut assessment) = pad_matching_fixture(0.2, false);
    assessment.signals.rgb_face = None;
    assessment.rgb_pad = PadEvidence::NotApplicable;
    DeferredAssessment {
        assessment,
        identity: (None, None),
    }
}

#[test]
fn rgb_only_group_completes_the_vote_and_never_marks_a_pair() {
    let _guard = env_guard();
    let mut s = shared();
    let materialized = Cell::new(0);
    let result = s
        .engine
        .evaluate_grouped_rgb_samples_with(
            (0..5).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, _i| Ok(rgb_only_sample(e, 0.2)),
            |_, mut evidence| {
                materialized.set(materialized.get() + 1);
                assert!(
                    !evidence.assessment.sequential_pair,
                    "RGB-only identity inputs are never a pair"
                );
                evidence.assessment.embedding = Some([0.0; EMBED_DIM]);
                Ok(evidence.assessment)
            },
            Instant::now,
        )
        .unwrap();
    assert_eq!(materialized.get(), 1, "identity only on the final sample");
    let PreparedGroup::Ready(a) = result else {
        panic!("complete live rgb group refused")
    };
    assert!(!a.sequential_pair);
    assert_eq!(a.rgb_pad, PadEvidence::Score(0.2));
}

#[test]
fn rgb_only_group_spoof_median_denies_before_identity() {
    let _guard = env_guard();
    let mut s = shared();
    let result = s.engine.evaluate_grouped_rgb_samples_with(
        (0..5).collect(),
        Instant::now() + Duration::from_secs(15),
        |e, _i| Ok(rgb_only_sample(e, 0.99)),
        |_, _| panic!("spoof group reached identity"),
        Instant::now,
    );
    let Ok(PreparedGroup::Refused(outcome)) = result else {
        panic!("spoof group must refuse")
    };
    assert_eq!(outcome.kind, OutcomeKind::Spoof);
    assert!(s.engine.vit_scores.is_empty());
}

#[test]
fn rgb_only_group_missing_face_sample_leaves_the_vote_pending() {
    let _guard = env_guard();
    let mut s = shared();
    let result = s
        .engine
        .evaluate_grouped_rgb_samples_with(
            vec![0, 1, 2, 3, 4],
            Instant::now() + Duration::from_secs(15),
            |e, i| {
                if i == 2 {
                    Ok(rgb_only_no_face_sample())
                } else {
                    Ok(rgb_only_sample(e, 0.2))
                }
            },
            |_, _| panic!("pending group reached identity"),
            Instant::now,
        )
        .unwrap();
    let PreparedGroup::Refused(outcome) = result else {
        panic!("incomplete group must refuse")
    };
    assert_eq!(outcome.kind, OutcomeKind::RgbPadPending);
    assert_eq!(outcome.reason, "collecting RGB PAD evidence");
    assert!(presence_retryable(&outcome));
    assert!(s.engine.vit_scores.is_empty());
}

#[test]
fn rgb_only_group_dark_sample_refuses_with_the_rgb_reason() {
    let _guard = env_guard();
    let mut s = shared();
    let result = s
        .engine
        .evaluate_grouped_rgb_samples_with(
            (0..5).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, _i| {
                let mut v = rgb_only_sample(e, 0.2);
                v.assessment.verdict = Verdict::Uncertain;
                v.assessment.reason =
                    "too dark: add light on your face (RGB-only mode needs a lit face)".into();
                Ok(v)
            },
            |_, _| panic!("dark group reached identity"),
            Instant::now,
        )
        .unwrap();
    let PreparedGroup::Refused(outcome) = result else {
        panic!("dark group must refuse")
    };
    assert_eq!(outcome.kind, OutcomeKind::Uncertain);
    assert!(outcome.reason.contains("too dark"));
}

#[test]
fn rgb_only_grouped_route_requires_convenience_shape() {
    use crate::grouped_auth::rgb_only_eligible;
    use AuthenticationPurpose::*;
    let ready =
        |ir, pad, window, service, purpose| rgb_only_eligible(ir, pad, window, purpose, service);
    // The admitted shape: convenience tier, PAD cue loaded, default-or-longer
    // window, and the engine's local-session scope.
    assert!(ready(false, true, 15_000, Some("kde"), Verify));
    assert!(ready(false, true, 15_000, Some("sddm"), Verify));
    assert!(ready(false, true, 15_000, None, Verify));
    assert!(ready(
        false,
        true,
        15_000,
        Some("omarchy-lock-face"),
        CredentialRelease
    ));
    // Every single requirement is load-bearing.
    assert!(
        !ready(true, true, 15_000, Some("kde"), Verify),
        "IR box: not this route"
    );
    assert!(
        !ready(false, false, 15_000, Some("kde"), Verify),
        "PAD model absent"
    );
    assert!(
        !ready(false, true, 0, Some("kde"), Verify),
        "one-shot window"
    );
    assert!(
        !ready(false, true, 14_999, Some("kde"), Verify),
        "short window"
    );
    assert!(
        !ready(false, true, 15_000, Some("sudo"), Verify),
        "elevation"
    );
    assert!(
        !ready(false, true, 15_000, Some("polkit-1"), AppConsent),
        "app consent"
    );
    assert!(!ready(false, true, 15_000, Some("sshd"), Verify), "remote");
    // Unknown service names mirror the pair route's Verify default: the
    // engine admits them and the daemon's tier gate stays the fail-closed
    // authority that never routes them here on RGB-only hardware.
    assert!(
        ready(false, true, 15_000, Some("mystery-service"), Verify),
        "unknown"
    );
    assert!(
        !ready(false, true, 15_000, Some("sudo"), CredentialRelease),
        "credential release needs a local login or lock service"
    );
}

#[derive(Default)]
struct StageSink(std::sync::Mutex<Vec<irlume_common::diagnostics::TraceEventKind>>);

impl irlume_common::diagnostics::DiagnosticSink for StageSink {
    fn emit_trace(&self, kind: irlume_common::diagnostics::TraceEventKind) {
        self.0.lock().unwrap().push(kind);
    }
}

impl StageSink {
    fn stages(&self) -> Vec<irlume_common::diagnostics::TraceStage> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                irlume_common::diagnostics::TraceEventKind::StageTiming { stage, .. } => {
                    Some(*stage)
                }
                _ => None,
            })
            .collect()
    }
}

/// Each phase of the grouped route's sequential batch becomes its own
/// schema 5 stage carrying only the elapsed time, which a schema 4
/// subscriber never receives.
#[test]
fn grouped_batch_phases_report_their_own_schema_5_stages() {
    use irlume_camera::SequentialBatchPhase as Phase;
    use irlume_common::diagnostics::{
        TraceEventKind, TraceStage, CURRENT_TRACE_SCHEMA_VERSION, V4_TRACE_SCHEMA_VERSION,
    };
    let sink = StageSink::default();
    let phases = [
        (Phase::RgbStart, TraceStage::SequentialRgbStart),
        (Phase::RgbSample, TraceStage::SequentialRgbSample),
        (Phase::RgbRelease, TraceStage::SequentialRgbRelease),
        (Phase::IrStart, TraceStage::SequentialIrStart),
        (Phase::IrSample, TraceStage::SequentialIrSample),
        (Phase::IrRelease, TraceStage::SequentialIrRelease),
    ];
    for (index, (phase, _)) in phases.iter().enumerate() {
        crate::grouped_auth::emit_batch_phase(
            &sink,
            *phase,
            Duration::from_micros(1_000 + index as u64),
        );
    }
    let events = sink.0.lock().unwrap();
    assert_eq!(events.len(), phases.len());
    for (index, (event, (_, stage))) in events.iter().zip(phases).enumerate() {
        assert_eq!(
            *event,
            TraceEventKind::StageTiming {
                stage,
                elapsed_us: 1_000 + index as u64,
            }
        );
        assert!(event.supports_schema(CURRENT_TRACE_SCHEMA_VERSION));
        assert!(!event.supports_schema(V4_TRACE_SCHEMA_VERSION), "{event:?}");
    }
}

/// The grouped evaluation is one stage per group, reported after the
/// per-sample stages it contains, whether the group is ready, refused or
/// failed.
#[test]
fn grouped_evaluation_is_one_stage_after_its_samples_on_every_result() {
    use crate::grouped_auth::in_grouped_evaluation;
    use irlume_common::diagnostics::{DiagnosticSink, TraceEventKind, TraceStage};
    let _guard = env_guard();
    let mut s = shared();
    let detection = |sink: &StageSink| {
        sink.emit_trace(TraceEventKind::StageTiming {
            stage: TraceStage::Detection,
            elapsed_us: 1,
        });
    };
    let expected = |samples: usize| {
        let mut stages = vec![TraceStage::Detection; samples];
        stages.push(TraceStage::GroupedEvaluation);
        stages
    };

    let sink = StageSink::default();
    let ready = in_grouped_evaluation(&sink, || {
        s.engine.evaluate_grouped_samples_with(
            (0..5).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, i| {
                detection(&sink);
                Ok(sample(e, i, 0.2))
            },
            |_, mut evidence| {
                evidence.assessment.embedding = Some(evidence.identity.1);
                Ok(evidence.assessment)
            },
            Instant::now,
        )
    });
    assert!(matches!(ready, Ok(PreparedGroup::Ready(_))));
    assert_eq!(sink.stages(), expected(5));
    s.engine.vit_scores.clear();

    let sink = StageSink::default();
    let assessed = Cell::new(0);
    let refused = in_grouped_evaluation(&sink, || {
        s.engine.evaluate_grouped_samples_with(
            (0..5).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, i| {
                detection(&sink);
                assessed.set(assessed.get() + 1);
                let mut v = sample(e, i, 0.2);
                if i == 2 {
                    v.assessment.verdict = Verdict::Uncertain;
                    v.assessment.reason = "unusable evidence".into();
                }
                Ok(v)
            },
            |_, _| panic!("a refused group reached identity"),
            Instant::now,
        )
    });
    assert!(matches!(refused, Ok(PreparedGroup::Refused(_))));
    assert!(assessed.get() > 2);
    assert_eq!(sink.stages(), expected(assessed.get()));

    let sink = StageSink::default();
    let failed = in_grouped_evaluation(&sink, || {
        s.engine.evaluate_grouped_samples_with(
            (0..5).collect(),
            Instant::now() + Duration::from_secs(15),
            |e, i| {
                detection(&sink);
                if i == 1 {
                    return Err(irlume_common::Error::Hardware("scripted failure".into()));
                }
                Ok(sample(e, i, 0.2))
            },
            |_, _| panic!("a failed group reached identity"),
            Instant::now,
        )
    });
    assert!(failed.is_err());
    assert_eq!(sink.stages(), expected(2));
}

/// A synthetic face for the RGB-half tests: a box keyed by `n`, so each
/// view's answer is recognizable.
fn half_face(n: usize) -> Detection {
    let x = 4.0 + n as f32;
    Detection {
        bbox: [x, 4.0, x + 20.0, 24.0],
        score: 0.9,
        landmarks: [(10.0, 10.0); 5],
    }
}

/// Five 2x2 views whose first byte names their index.
fn half_frames() -> Vec<Vec<u8>> {
    (0..5u8).map(|n| vec![n; 2 * 2 * 3]).collect()
}

/// The views of `frames`, each with a capture window 33 ms after the last.
fn half_views(
    frames: &[Vec<u8>],
    base: Instant,
) -> impl ExactSizeIterator<Item = (align::RgbView<'_>, irlume_camera::CaptureWindow)> {
    frames.iter().enumerate().map(move |(n, data)| {
        let view = align::RgbView {
            data,
            width: 2,
            height: 2,
        };
        (view, half_window(base, n))
    })
}

fn half_window(base: Instant, n: usize) -> irlume_camera::CaptureWindow {
    irlume_camera::CaptureWindow::at(base + Duration::from_millis(33 * n as u64))
}

/// The overlap worker computes each sample's detector answer in capture
/// order and the ViT answer only for a view whose detector found a face,
/// for exactly that top box, stamps each half with its own frame's window,
/// and reports each call's timing before the next call starts.
#[test]
fn rgb_halves_cover_every_sample_in_order_and_score_only_found_faces() {
    use crate::grouped_auth::precompute_rgb_halves;
    use irlume_common::diagnostics::TraceStage;
    let frames = half_frames();
    let base = Instant::now();
    let sink = StageSink::default();
    let scored = std::cell::RefCell::new(Vec::new());
    // The records already reported when each call starts.
    let reported = std::cell::RefCell::new(Vec::new());
    let halves = precompute_rgb_halves(
        half_views(&frames, base),
        |view| {
            reported.borrow_mut().push(sink.stages().len());
            let n = usize::from(view.data[0]);
            Ok(if n == 2 { vec![] } else { vec![half_face(n)] })
        },
        Some(|view: &align::RgbView<'_>, bbox: &[f32; 4]| {
            reported.borrow_mut().push(sink.stages().len());
            let n = usize::from(view.data[0]);
            assert_eq!(*bbox, half_face(n).bbox, "the top box of this view");
            scored.borrow_mut().push(n);
            Ok(n as f32 / 10.0)
        }),
        &|| false,
        &sink,
    );
    assert_eq!(*scored.borrow(), [0, 1, 3, 4]);
    // Detect 0, score 0, detect 1, score 1, detect 2, detect 3, score 3,
    // detect 4, score 4: each call finds every earlier call reported.
    assert_eq!(*reported.borrow(), [0, 1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(halves.len(), 5);
    for (n, half) in halves.into_iter().enumerate() {
        let half = half.expect("every sample reached");
        assert_eq!(
            half.captured,
            half_window(base, n),
            "its own frame's window"
        );
        assert_eq!(half.faces.unwrap().len(), usize::from(n != 2));
        match half.vit {
            Some(score) => {
                assert_ne!(n, 2);
                assert_eq!(score.bbox, half_face(n).bbox);
                assert_eq!(score.answer, Ok(n as f32 / 10.0));
            }
            None => assert_eq!(n, 2, "only the faceless view goes unscored"),
        }
    }
    use TraceStage::{Detection as D, Liveness as L};
    assert_eq!(sink.stages(), [D, L, D, L, D, D, L, D, L]);
}

/// A stop between samples leaves the rest to the evaluation, and a stop
/// between the detector and the ViT keeps the detector's answer unscored.
#[test]
fn rgb_halves_stop_when_asked_and_leave_the_rest_to_the_evaluation() {
    use crate::grouped_auth::precompute_rgb_halves;
    let frames = half_frames();
    let checks = Cell::new(0);
    // Checks run before each detection and before each score: the fourth
    // check is the one before the second sample's score.
    let halves = precompute_rgb_halves(
        half_views(&frames, Instant::now()),
        |view| Ok(vec![half_face(usize::from(view.data[0]))]),
        Some(|_: &align::RgbView<'_>, _: &[f32; 4]| Ok(0.1)),
        &|| {
            checks.set(checks.get() + 1);
            checks.get() >= 4
        },
        &(),
    );
    assert_eq!(halves.len(), 5);
    let first = halves[0].as_ref().expect("first sample reached");
    assert!(first.vit.is_some());
    let second = halves[1].as_ref().expect("second sample detected");
    assert!(second.faces.is_ok() && second.vit.is_none());
    assert!(halves[2..].iter().all(Option::is_none));
}

/// A detector error ends the worker at that sample: the evaluation meets
/// the same error there, as it would have met it calling the detector.
#[test]
fn rgb_halves_end_at_a_detector_error() {
    use crate::grouped_auth::precompute_rgb_halves;
    use irlume_common::diagnostics::TraceStage;
    let frames = half_frames();
    let sink = StageSink::default();
    let halves = precompute_rgb_halves(
        half_views(&frames, Instant::now()),
        |view| match view.data[0] {
            1 => Err(irlume_common::Error::Hardware(
                "scripted detector failure".into(),
            )),
            n => Ok(vec![half_face(usize::from(n))]),
        },
        None::<fn(&align::RgbView<'_>, &[f32; 4]) -> irlume_common::Result<f32>>,
        &|| false,
        &sink,
    );
    assert!(halves[0].as_ref().unwrap().faces.is_ok());
    assert!(matches!(
        halves[1].as_ref().unwrap().faces,
        Err(irlume_common::Error::Hardware(_))
    ));
    assert!(halves[2..].iter().all(Option::is_none));
    // No ViT session: nothing scored; the failed call reports no timing.
    assert!(halves[0].as_ref().unwrap().vit.is_none());
    assert_eq!(sink.stages(), [TraceStage::Detection]);
}

/// A precomputed ViT answer stands in only for the unreplaced frame and the
/// bit-identical box; anything else runs the model.
#[test]
fn rgb_pad_answer_uses_a_precomputed_score_only_for_the_same_frame_and_box() {
    use crate::grouped_auth::{rgb_pad_answer, RgbPadScore};
    let bbox = [4.0, 0.0, 24.0, 20.0];
    let score = |bbox, answer| Some(RgbPadScore { bbox, answer });
    let computed = || Ok(0.75);
    assert_eq!(
        rgb_pad_answer(score(bbox, Ok(0.25)), false, &bbox, computed),
        Ok(0.25)
    );
    assert_eq!(
        rgb_pad_answer(score(bbox, Err("scripted".into())), false, &bbox, computed),
        Err("scripted".into())
    );
    assert_eq!(rgb_pad_answer(None, false, &bbox, computed), Ok(0.75));
    assert_eq!(
        rgb_pad_answer(score(bbox, Ok(0.25)), true, &bbox, computed),
        Ok(0.75)
    );
    // Equal as numbers but not as bits, and one ulp apart: both recompute.
    let signed_zero = [4.0, -0.0, 24.0, 20.0];
    assert_eq!(
        rgb_pad_answer(score(signed_zero, Ok(0.25)), false, &bbox, computed),
        Ok(0.75)
    );
    let ulp = [f32::from_bits(4.0f32.to_bits() + 1), 0.0, 24.0, 20.0];
    assert_eq!(
        rgb_pad_answer(score(ulp, Ok(0.25)), false, &bbox, computed),
        Ok(0.75)
    );
}

/// Adopting a detector answer computed during the IR phase gives what the
/// direct detection gives on the same frame (here a faceless one; that both
/// end in the same rescue tail is pinned by
/// `the_grouped_route_wires_each_half_to_its_own_sample`), keeps exactly the
/// faces it is handed, and keeps the direct path's error, cancellation and
/// deadline points, a request signal coming before the detector's error.
#[test]
fn adopted_rgb_detection_answers_like_the_direct_detector() {
    let _guard = env_guard();
    let mut s = shared();
    let e = &mut s.engine;
    let (width, height) = (320u32, 240u32);
    let data: Vec<u8> = (0..width * height * 3).map(|i| (i % 251) as u8).collect();
    let view = align::RgbView {
        data: &data,
        width,
        height,
    };
    let summary = |(faces, top): (Vec<Detection>, Option<Detection>)| {
        let boxes = |d: &Detection| (d.bbox.map(f32::to_bits), d.score.to_bits());
        (
            faces.iter().map(boxes).collect::<Vec<_>>(),
            top.as_ref().map(boxes),
        )
    };
    let direct = summary(e.detect_rgb_assessment_view(&view, None, &()).unwrap());
    let faces = e.det.detect(&view);
    let adopted = summary(e.adopt_rgb_detection(&view, faces).unwrap());
    assert_eq!(direct, adopted);
    // A face the worker found is the one the evaluation goes on with.
    let face = Detection {
        bbox: [80.0, 40.0, 240.0, 200.0],
        score: 0.9,
        landmarks: [(160.0, 120.0); 5],
    };
    let found = summary(
        e.adopt_rgb_detection(&view, Ok(vec![face.clone()]))
            .unwrap(),
    );
    assert_eq!(found, summary((vec![face.clone()], Some(face))));
    let failure = e.adopt_rgb_detection(
        &view,
        Err(irlume_common::Error::Hardware(
            "scripted detector failure".into(),
        )),
    );
    assert!(matches!(failure, Err(irlume_common::Error::Hardware(_))));
    // The shared engine's request signals are restored even if an assertion
    // fails, so later tests never see a cancelled or expired engine.
    let prior = (
        e.request_cancelled.take(),
        e.authentication_deadline.take(),
        e.last_attempt_situation.take(),
    );
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e.request_cancelled = Some(std::sync::Arc::new(|| true));
        let failed = || {
            Err(irlume_common::Error::Hardware(
                "scripted detector failure".into(),
            ))
        };
        let cancelled = e.adopt_rgb_detection(&view, Ok(vec![]));
        assert!(matches!(cancelled, Err(irlume_common::Error::Preempted(_))));
        let cancelled = e.adopt_rgb_detection(&view, failed());
        assert!(matches!(cancelled, Err(irlume_common::Error::Preempted(_))));
        e.request_cancelled = None;
        e.authentication_deadline = Some(Instant::now());
        let expired = e.adopt_rgb_detection(&view, failed());
        assert!(matches!(
            expired,
            Err(irlume_common::Error::DeadlineExpired)
        ));
        let expired = e.adopt_rgb_detection(&view, Ok(vec![]));
        assert!(matches!(
            expired,
            Err(irlume_common::Error::DeadlineExpired)
        ));
        assert_eq!(e.last_attempt_situation, Some(AttemptSituation::TimedOut));
    }));
    (
        e.request_cancelled,
        e.authentication_deadline,
        e.last_attempt_situation,
    ) = prior;
    e.vit_scores.clear();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// A precomputed RGB half is consumed only for the frame whose window it
/// carries, so a half paired with any other sample falls back to the direct
/// calls.
#[test]
fn rgb_halves_stand_in_only_for_their_own_frame() {
    use crate::grouped_auth::{half_for_frame, RgbHalf};
    let base = Instant::now();
    let window = irlume_camera::CaptureWindow::at(base);
    let other = irlume_camera::CaptureWindow::at(base + Duration::from_millis(33));
    let half = |captured| {
        Some(RgbHalf {
            captured,
            faces: Ok(vec![]),
            vit: None,
        })
    };
    assert!(half_for_frame(half(window), window).is_some());
    assert!(half_for_frame(half(other), window).is_none());
    assert!(half_for_frame(None, window).is_none());
}

/// The overlap worker's ViT answer is the very call the evaluation would
/// make: a real session scored from a scoped thread gives the same bits as
/// the same call on the evaluating thread, for every sample.
#[test]
fn rgb_half_vit_answer_matches_the_direct_call_across_threads() {
    use crate::grouped_auth::precompute_rgb_halves;
    let _guard = env_guard();
    drop(shared());
    let mut pad =
        irlume_vision::PadVit::load_from_file(&model_path("liveness_vit.onnx")).expect("vit pad");
    let (width, height) = (640u32, 480u32);
    let frames: Vec<Vec<u8>> = (0..5usize)
        .map(|k| {
            (0..(width * height * 3) as usize)
                .map(|i| ((i * (5 + k) + i / 11 + k * 31) % 256) as u8)
                .collect()
        })
        .collect();
    let base = Instant::now();
    let views = || {
        frames.iter().enumerate().map(move |(n, data)| {
            let view = align::RgbView {
                data,
                width,
                height,
            };
            (view, half_window(base, n))
        })
    };
    let face = Detection {
        bbox: [200.0, 120.0, 440.0, 360.0],
        score: 0.9,
        landmarks: [(300.0, 200.0); 5],
    };
    let halves = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                precompute_rgb_halves(
                    views(),
                    |_| Ok(vec![face.clone()]),
                    Some(|view: &align::RgbView<'_>, bbox: &[f32; 4]| pad.p_spoof(view, bbox)),
                    &|| false,
                    &(),
                )
            })
            .join()
            .expect("worker")
    });
    for ((view, _), half) in views().zip(halves) {
        let worker = half
            .expect("reached")
            .vit
            .expect("scored")
            .answer
            .expect("score");
        let direct = pad.p_spoof(&view, &face.bbox).expect("score");
        assert_eq!(worker.to_bits(), direct.to_bits());
    }
}

/// The ViT site takes a precomputed answer only for a Live frame, the
/// unreplaced frame and the bit-identical box, and runs the model otherwise;
/// a frame the verdict does not call Live runs nothing.
#[test]
fn vit_pad_evidence_consumes_a_precomputed_answer_only_where_the_model_would_run() {
    use crate::grouped_auth::RgbPadScore;
    use irlume_liveness::Verdict;
    let face = half_face(3);
    let precomputed = |answer| {
        Some(RgbPadScore {
            bbox: face.bbox,
            answer,
        })
    };
    let never = Some(|_: &[f32; 4]| -> Result<f32, String> { panic!("the model must not run") });
    let model = Some(|bbox: &[f32; 4]| -> Result<f32, String> {
        assert_eq!(*bbox, face.bbox, "the model scores the top face");
        Ok(0.75)
    });
    assert_eq!(
        crate::vit_pad_evidence(
            Verdict::Live,
            Some(&face),
            never,
            precomputed(Ok(0.25)),
            false
        ),
        PadEvidence::Score(0.25)
    );
    assert_eq!(
        crate::vit_pad_evidence(
            Verdict::Live,
            Some(&face),
            model,
            precomputed(Ok(0.25)),
            true
        ),
        PadEvidence::Score(0.75),
        "a replaced frame runs the model"
    );
    let other = RgbPadScore {
        bbox: half_face(4).bbox,
        answer: Ok(0.25),
    };
    assert_eq!(
        crate::vit_pad_evidence(Verdict::Live, Some(&face), model, Some(other), false),
        PadEvidence::Score(0.75),
        "another box runs the model"
    );
    assert_eq!(
        crate::vit_pad_evidence(Verdict::Live, Some(&face), model, None, false),
        PadEvidence::Score(0.75)
    );
    assert_eq!(
        crate::vit_pad_evidence(
            Verdict::Live,
            Some(&face),
            never,
            precomputed(Ok(f32::NAN)),
            false
        ),
        PadEvidence::InferenceFailed
    );
    assert_eq!(
        crate::vit_pad_evidence(
            Verdict::Live,
            Some(&face),
            never,
            precomputed(Err("scripted".into())),
            false
        ),
        PadEvidence::InferenceFailed
    );
    for verdict in [Verdict::Spoof, Verdict::Uncertain] {
        assert_eq!(
            crate::vit_pad_evidence(verdict, Some(&face), never, precomputed(Ok(0.25)), false),
            PadEvidence::NotApplicable,
            "{verdict:?} consumes no score"
        );
    }
    assert_eq!(
        crate::vit_pad_evidence(Verdict::Live, None, never, precomputed(Ok(0.25)), false),
        PadEvidence::NotApplicable
    );
    let unloaded = None::<fn(&[f32; 4]) -> Result<f32, String>>;
    assert_eq!(
        crate::vit_pad_evidence(
            Verdict::Live,
            Some(&face),
            unloaded,
            precomputed(Ok(0.25)),
            false
        ),
        PadEvidence::Unavailable,
        "no ViT session reads as unavailable, whatever was precomputed"
    );
}

/// The grouped route's wiring, which only a camera reaches: the worker's
/// halves pair with their own samples, a half stands in only for its frame,
/// the ViT answer reaches the ViT site, the worker stops with the batch, and
/// an adopted detection ends in the direct path's rescue tail.
#[test]
fn the_grouped_route_wires_each_half_to_its_own_sample() {
    let grouped = include_str!("../grouped_auth.rs");
    let attempt = grouped
        .split("pub(super) fn authenticate_grouped_once(")
        .nth(1)
        .and_then(|rest| rest.split("\n    pub(super) fn ").next())
        .expect("authenticate_grouped_once");
    for wiring in [
        "rgb_half.precompute(frames, &|| stop.requested(), diagnostics)",
        ".chain(std::iter::repeat_with(|| None))",
        "match half_for_frame(half, rgb.captured) {",
        "(engine.adopt_rgb_detection(&view, faces)?, vit)",
        "None => (engine.detect_rgb_assessment(&rgb, None, diagnostics)?, None),",
        "                                rgb_pad_score,\n",
    ] {
        assert!(attempt.contains(wiring), "missing: {wiring}");
    }
    assert_eq!(attempt.matches(".zip(").count(), 1, "one pairing of halves");
    let models = grouped
        .split("pub(super) fn precompute(")
        .nth(1)
        .and_then(|rest| rest.split("\n    }\n}").next())
        .expect("RgbHalfModels::precompute");
    for stop in [
        "stop()",
        "cancelled.as_ref().is_some_and(|cancelled| cancelled())",
        "deadline.is_some_and(|deadline| Instant::now() >= deadline)",
        "(view, frame.captured)",
    ] {
        assert!(models.contains(stop), "missing: {stop}");
    }
    let lib = include_str!("../lib.rs");
    let adopt = lib
        .split("fn adopt_rgb_detection(")
        .nth(1)
        .and_then(|rest| rest.split("\n    }\n").next())
        .expect("adopt_rgb_detection");
    assert!(adopt
        .trim_end()
        .ends_with("self.finish_rgb_detection(rgb, None, rgb_faces)"));
    let site = lib
        .split("let rgb_pad = vit_pad_evidence(")
        .nth(1)
        .and_then(|rest| rest.split("\n        );\n").next())
        .expect("the ViT site");
    assert!(site.contains("rgb_pad_score,\n            rgb_recaptured,"));
}
