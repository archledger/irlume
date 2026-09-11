// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::pair_identity_tests::{
    materialize_synthetic_pair, paired_enrollment, visible_pair_sample,
};
use super::*;
use std::cell::Cell;
use std::time::{Duration, Instant};

#[test]
fn managed_pending_collects_five_fresh_samples_and_materializes_only_the_last() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    // Another transaction's partial vote must not shorten this collection.
    engine.vit_scores.extend([0.2; 4]);
    let mut samples = 0;
    let mut identities = Vec::new();
    let prepared = engine
        .collect_concurrent_pending_with(
            Instant::now() + Duration::from_secs(15),
            |engine| {
                let sample = samples;
                samples += 1;
                let evidence = visible_pair_sample(engine, sample, 0.2, false);
                engine
                    .prepare_pair_authentication_with(evidence, |_, evidence| {
                        identities.push(evidence.identity.0.as_ref().unwrap().data[0]);
                        assert_eq!(evidence.identity.1.as_ref().unwrap().data[0], sample);
                        Ok(materialize_synthetic_pair(evidence))
                    })
                    .map_err(CapturePathError::from)
            },
            Instant::now,
        )
        .map_err(CapturePathError::into_inner)
        .unwrap();
    assert_eq!(samples, 5);
    assert_eq!(identities, [4]);
    assert!(
        engine.vit_scores.is_empty(),
        "transaction must retire its vote"
    );
    let out = engine
        .finish_pair_authentication(
            &paired_enrollment(),
            AuthenticationPurpose::Verify,
            Some("login"),
            Ok(prepared),
            None,
            &(),
        )
        .unwrap();
    engine.ir_available = previous_ir;
    assert!(
        out.granted,
        "complete concurrent identity must retain its grant arms"
    );
}

#[test]
fn managed_pending_hard_ir_failure_stops_without_identity_or_a_sixth_sample() {
    let _guard = env_guard();
    let mut state = shared();
    for fail_at in 0..5 {
        let mut samples = 0;
        let prepared = state
            .engine
            .collect_concurrent_pending_with(
                Instant::now() + Duration::from_secs(15),
                |engine| {
                    let mut evidence = visible_pair_sample(engine, samples, 0.2, false);
                    if samples == fail_at {
                        evidence.assessment.ir_pad = PadEvidence::InferenceFailed;
                    }
                    samples += 1;
                    engine
                        .prepare_pair_authentication_with(evidence, |_, _| {
                            panic!("identity on failed PAD")
                        })
                        .map_err(CapturePathError::from)
                },
                Instant::now,
            )
            .map_err(CapturePathError::into_inner)
            .unwrap();
        let PreparedPairAuthentication::Refused(outcome) = prepared else {
            panic!("PAD failure admitted");
        };
        assert_eq!(outcome.kind, OutcomeKind::RuntimeUnavailable);
        assert_eq!(samples, fail_at + 1);
        assert!(state.engine.vit_scores.is_empty());
    }
    let mut samples = 0;
    let prepared = state
        .engine
        .collect_concurrent_pending_with(
            Instant::now() + Duration::from_secs(15),
            |_| {
                samples += 1;
                Ok(PreparedPairAuthentication::Refused(Outcome::deny(
                    OutcomeKind::RgbPadPending,
                    "synthetic pending",
                )))
            },
            Instant::now,
        )
        .map_err(CapturePathError::into_inner)
        .unwrap();
    assert_eq!(samples, VIT_PAD_VOTE_N);
    assert!(matches!(
        prepared,
        PreparedPairAuthentication::Refused(Outcome {
            kind: OutcomeKind::RgbPadPending,
            ..
        })
    ));
}

#[test]
fn managed_non_live_ends_the_collection_and_preserves_eager_preparation() {
    let _guard = env_guard();
    let mut state = shared();
    for verdict in [Verdict::Uncertain, Verdict::Spoof] {
        let mut samples = 0;
        let mut identities = 0;
        let prepared = state
            .engine
            .collect_concurrent_pending_with(
                Instant::now() + Duration::from_secs(15),
                |engine| {
                    let mut evidence = visible_pair_sample(engine, samples, 0.2, false);
                    if samples == 1 {
                        evidence.assessment.verdict = verdict;
                    }
                    samples += 1;
                    engine
                        .prepare_pair_authentication_with(evidence, |_, evidence| {
                            identities += 1;
                            Ok(materialize_synthetic_pair(evidence))
                        })
                        .map_err(CapturePathError::from)
                },
                Instant::now,
            )
            .map_err(CapturePathError::into_inner)
            .unwrap();
        assert_eq!(samples, 2);
        assert_eq!(identities, 1);
        assert!(matches!(prepared, PreparedPairAuthentication::Ready(_)));
        assert!(state.engine.vit_scores.is_empty());
    }
}

#[test]
fn managed_transport_or_inference_failure_discards_prepared_evidence_and_facts() {
    let _guard = env_guard();
    let mut state = shared();
    for transport in [false, true] {
        let mut samples = 0;
        let mut identities = 0;
        let result = state.engine.collect_concurrent_pending_with(
            Instant::now() + Duration::from_secs(15),
            |engine| {
                let evidence = visible_pair_sample(engine, samples, 0.2, false);
                samples += 1;
                let prepared = engine
                    .prepare_pair_authentication_with(evidence, |_, evidence| {
                        identities += 1;
                        if transport {
                            Ok(materialize_synthetic_pair(evidence))
                        } else {
                            Err(irlume_common::Error::Hardware("synthetic inference".into()))
                        }
                    })
                    .map_err(CapturePathError::from)?;
                if samples == 5 {
                    drop(prepared); // Successful work is invalidated by its tail drain.
                    Err(CapturePathError::ConcurrentPair(
                        irlume_common::Error::Hardware("synthetic tail".into()),
                    ))
                } else {
                    Ok(prepared)
                }
            },
            Instant::now,
        );
        assert_eq!(samples, 5);
        assert_eq!(identities, 1);
        assert_eq!(
            matches!(&result, Err(CapturePathError::ConcurrentPair(_))),
            transport
        );
        assert!(result.is_err());
        assert!(state.engine.vit_scores.is_empty());
        assert_eq!(state.engine.last_attempt_facts.rgb_face, None);
    }
}

#[test]
fn managed_completed_pending_at_expiry_and_panic_clear_votes_without_later_work() {
    let _guard = env_guard();
    let mut state = shared();
    let start = Instant::now();
    let clock = Cell::new(start);
    let deadline = start + Duration::from_secs(15);
    let mut samples = 0;
    let result = state.engine.collect_concurrent_pending_with(
        deadline,
        |engine| {
            samples += 1;
            let evidence = visible_pair_sample(engine, 0, 0.2, false);
            let prepared = engine
                .prepare_pair_authentication_with(evidence, |_, _| panic!("pending identity"))
                .map_err(CapturePathError::from);
            clock.set(deadline);
            prepared
        },
        || clock.get(),
    );
    assert_eq!(samples, 1);
    assert!(matches!(
        result,
        Ok(PreparedPairAuthentication::Refused(Outcome {
            kind: OutcomeKind::RgbPadPending,
            ..
        }))
    ));
    assert!(state.engine.vit_scores.is_empty());
    assert!(
        state.engine.last_attempt_facts.rgb_face.is_some(),
        "completed denial retains its own facts"
    );

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.engine.collect_concurrent_pending_with(
            deadline,
            |engine| {
                engine.vit_scores.push(0.2);
                engine.last_attempt_facts.rgb_face = Some((0.5, 0.5));
                panic!("synthetic processing panic")
            },
            || start,
        )
    }));
    assert!(panic.is_err());
    assert!(state.engine.vit_scores.is_empty());
    assert_eq!(state.engine.last_attempt_facts.rgb_face, None);
}

fn concurrent_mode() -> CaptureModeSelection {
    CaptureModeSelection {
        sequential: false,
        source: STORED_CAPTURE_MODE_SOURCE,
        runtime_key: Some("synthetic".into()),
        runtime_contract: None,
        qualification_state: irlume_common::diagnostics::QualificationState::QualifiedConcurrent,
        qualification_reason: None,
        authoritative_rate_shortfalls: None,
        latest_attempt_rate_shortfalls: None,
        operation_demoted: Cell::new(false),
    }
}

#[test]
fn managed_eligibility_preserves_authority_models_service_and_window_scope() {
    for source in [
        STORED_CAPTURE_MODE_SOURCE,
        ENV_CAPTURE_MODE_SOURCE,
        "default",
        RUNTIME_CAPTURE_MODE_SOURCE,
    ] {
        for (service, verify, release) in [
            (Some("login"), true, true),
            (Some("kde-fingerprint"), true, true),
            (None, true, false),
            (Some("unknown-local-service"), true, false),
            (Some("sudo"), false, false),
            (Some("sshd"), false, false),
        ] {
            let mut mode = concurrent_mode();
            mode.source = source;
            for purpose in [
                AuthenticationPurpose::Verify,
                AuthenticationPurpose::CredentialRelease,
                AuthenticationPurpose::AppConsent,
            ] {
                let purpose_allowed = match purpose {
                    AuthenticationPurpose::Verify => verify,
                    AuthenticationPurpose::CredentialRelease => release,
                    AuthenticationPurpose::AppConsent => false,
                };
                assert_eq!(
                    crate::managed_pad::eligible_configuration(
                        &mode, true, true, true, 15_000, purpose, service
                    ),
                    purpose_allowed
                        && matches!(source, STORED_CAPTURE_MODE_SOURCE | ENV_CAPTURE_MODE_SOURCE)
                );
            }
        }
    }
    let mut mode = concurrent_mode();
    assert!(
        !crate::managed_pad::eligible(
            &mode,
            true,
            true,
            true,
            15_000,
            AuthenticationPurpose::Verify,
            Some("login")
        ),
        "no exact live contract"
    );
    for (ir, rgb_pad, ir_pad, window) in [
        (false, true, true, 15_000),
        (true, false, true, 15_000),
        (true, true, false, 15_000),
        (true, true, true, 14_999),
    ] {
        assert!(!crate::managed_pad::eligible_configuration(
            &mode,
            ir,
            rgb_pad,
            ir_pad,
            window,
            AuthenticationPurpose::Verify,
            Some("login")
        ));
    }
    mode.qualification_state = irlume_common::diagnostics::QualificationState::MeasuredSequential;
    assert!(!crate::managed_pad::eligible_configuration(
        &mode,
        true,
        true,
        true,
        15_000,
        AuthenticationPurpose::Verify,
        Some("login")
    ));
    mode.source = ENV_CAPTURE_MODE_SOURCE;
    assert!(crate::managed_pad::eligible_configuration(
        &mode,
        true,
        true,
        true,
        15_000,
        AuthenticationPurpose::Verify,
        Some("login")
    ));
    mode.operation_demoted.set(true);
    assert!(!crate::managed_pad::eligible_configuration(
        &mode,
        true,
        true,
        true,
        15_000,
        AuthenticationPurpose::Verify,
        Some("login")
    ));
}

#[test]
fn managed_cancel_between_samples_stops_and_releases_both_owners_without_fallback() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    struct Owner<'a>(&'a Cell<usize>);
    impl Drop for Owner<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let _guard = env_guard();
    let mut state = shared();
    let signal = Arc::new(AtomicBool::new(false));
    let hook = signal.clone();
    state
        .engine
        .set_request_cancel_signal(Arc::new(move || hook.load(Ordering::SeqCst)));
    let released = Cell::new(0);
    let mut samples = 0;
    let prepared = with_owned_pair((Owner(&released), Owner(&released)), &(), |_, _| {
        state.engine.collect_concurrent_pending_with(
            Instant::now() + Duration::from_secs(15),
            |engine| {
                assert_eq!(released.get(), 0);
                samples += 1;
                let evidence = visible_pair_sample(engine, 0, 0.2, false);
                let result = engine
                    .prepare_pair_authentication_with(evidence, |_, _| panic!("pending identity"))
                    .map_err(CapturePathError::from);
                signal.store(true, Ordering::SeqCst);
                result
            },
            Instant::now,
        )
    });
    state.engine.request_cancelled = None;
    assert_eq!(released.get(), 2);
    let mut fallback = false;
    let result = state.engine.finish_pair_authentication(
        &paired_enrollment(),
        AuthenticationPurpose::Verify,
        Some("login"),
        prepared,
        Some(&mut fallback),
        &(),
    );
    assert_eq!(samples, 1);
    assert!(!fallback);
    assert!(matches!(result, Err(irlume_common::Error::Preempted(_))));
    assert!(state.engine.vit_scores.is_empty());
    assert_eq!(state.engine.last_attempt_facts.rgb_face, None);
}

#[test]
fn managed_complete_batch_is_one_outer_attempt_and_preserves_final_match_decision() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    for matching in [true, false] {
        let started = Instant::now();
        let clock = Cell::new(started);
        let attempts = Cell::new(0);
        let mut samples = 0;
        let mut identities = 0;
        let mut costliest = Duration::ZERO;
        let (result, fallback) = engine.authentication_attempt_loop_with(
            started + Duration::from_secs(15),
            15_000,
            &mut costliest,
            |engine| {
                attempts.set(attempts.get() + 1);
                assert_eq!(attempts.get(), 1, "identity decision must not repeat");
                // Includes startup, every sample, processing and owner release.
                clock.set(clock.get() + Duration::from_secs(3));
                let prepared = engine.collect_concurrent_pending_with(
                    started + Duration::from_secs(15),
                    |engine| {
                        let mut evidence = visible_pair_sample(engine, samples, 0.2, false);
                        samples += 1;
                        if !matching {
                            evidence.identity.0.as_mut().unwrap().data[1] = 1;
                            evidence.identity.1.as_mut().unwrap().data[1] = 1;
                        }
                        clock.set(clock.get() + Duration::from_millis(400));
                        engine
                            .prepare_pair_authentication_with(evidence, |_, evidence| {
                                identities += 1;
                                Ok(materialize_synthetic_pair(evidence))
                            })
                            .map_err(CapturePathError::from)
                    },
                    || clock.get(),
                );
                (
                    engine.finish_pair_authentication(
                        &paired_enrollment(),
                        AuthenticationPurpose::Verify,
                        Some("login"),
                        prepared,
                        None,
                        &(),
                    ),
                    false,
                )
            },
            || clock.get(),
        );
        assert!(!fallback);
        assert_eq!(samples, 5);
        assert_eq!(identities, 1);
        assert_eq!(costliest, Duration::from_secs(5));
        assert_eq!(
            result.unwrap().kind,
            if matching {
                OutcomeKind::Granted
            } else {
                OutcomeKind::BelowThreshold
            }
        );
    }
    engine.ir_available = previous_ir;
}

#[test]
fn managed_missing_face_retires_votes_before_another_presentation() {
    let _guard = env_guard();
    let mut state = shared();
    let mut samples = 0;
    let prepared = state.engine.collect_concurrent_pending_with(
        Instant::now() + Duration::from_secs(15),
        |engine| {
            let mut evidence = visible_pair_sample(engine, samples, 0.2, false);
            samples += 1;
            if samples == 5 {
                evidence.identity = (None, None);
                evidence.assessment.signals = Signals::default();
                evidence.assessment.verdict = Verdict::Uncertain;
                evidence.assessment.rgb_pad = PadEvidence::NotApplicable;
                evidence.assessment.ir_pad = PadEvidence::NotApplicable;
            }
            engine
                .prepare_pair_authentication_with(evidence, |_, evidence| {
                    Ok(materialize_synthetic_pair(evidence))
                })
                .map_err(CapturePathError::from)
        },
        Instant::now,
    );
    let result = state
        .engine
        .finish_pair_authentication(
            &paired_enrollment(),
            AuthenticationPurpose::Verify,
            Some("login"),
            prepared,
            None,
            &(),
        )
        .unwrap();
    assert_eq!(result.kind, OutcomeKind::Uncertain);
    assert!(state.engine.vit_scores.is_empty());
    let mut fresh = 0;
    let prepared = state
        .engine
        .collect_concurrent_pending_with(
            Instant::now() + Duration::from_secs(15),
            |engine| {
                let evidence = visible_pair_sample(engine, fresh, 0.2, false);
                fresh += 1;
                engine
                    .prepare_pair_authentication_with(evidence, |_, evidence| {
                        Ok(materialize_synthetic_pair(evidence))
                    })
                    .map_err(CapturePathError::from)
            },
            Instant::now,
        )
        .map_err(CapturePathError::into_inner)
        .unwrap();
    assert_eq!(fresh, 5);
    assert!(matches!(prepared, PreparedPairAuthentication::Ready(_)));
    assert!(state.engine.vit_scores.is_empty());
}

#[test]
fn managed_pair_windows_reject_replay_overlap_reversal_and_accept_drain_gaps() {
    use crate::managed_pad::PairWindows;
    use irlume_camera::CaptureWindow;
    let start = Instant::now();
    let window = |a, b| CaptureWindow {
        start: start + Duration::from_millis(a),
        end: start + Duration::from_millis(b),
    };
    for (rgb, ir) in [
        (window(0, 20), window(5, 25)),   // replay
        (window(20, 40), window(30, 50)), // shared RGB endpoint
        (window(21, 40), window(24, 50)), // overlapping IR
        (window(15, 10), window(30, 50)), // reversed window
        (window(30, 50), window(35, 31)), // reversed IR
    ] {
        let mut windows = PairWindows::default();
        assert!(windows.advance(window(0, 20), window(5, 25)));
        assert!(!windows.advance(rgb, ir));
        assert!(
            windows.advance(window(200, 220), window(205, 225)),
            "validated drained frames need not be samples"
        );
    }
    let mut windows = PairWindows::default();
    assert!(
        !windows.advance(window(20, 0), window(5, 25)),
        "first sample must be well ordered"
    );
    assert!(windows.advance(window(0, 20), window(5, 25)));
    assert!(windows.advance(window(21, 41), window(26, 46)));
}

#[test]
fn managed_pair_arms_and_establishes_once_and_releases_before_admission() {
    use crate::managed_pad::with_managed_pair;
    struct Owner<'a>(&'a Cell<usize>);
    impl Drop for Owner<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let _guard = env_guard();
    let mut state = shared();
    let released = Cell::new(0);
    let armed = Cell::new(0);
    let rate = Cell::new(0);
    let mut samples = 0;
    let prepared = with_managed_pair(
        || {
            armed.set(armed.get() + 1);
            Ok((Owner(&released), Owner(&released)))
        },
        |_, _| {
            assert_eq!(released.get(), 0);
            rate.set(rate.get() + 1);
            Ok(())
        },
        |_, _| {
            state.engine.collect_concurrent_pending_with(
                Instant::now() + Duration::from_secs(15),
                |engine| {
                    assert_eq!(armed.get(), 1);
                    assert_eq!(rate.get(), 1);
                    assert_eq!(released.get(), 0);
                    let sample = visible_pair_sample(engine, samples, 0.2, false);
                    samples += 1;
                    engine
                        .prepare_pair_authentication_with(sample, |_, evidence| {
                            assert_eq!(
                                released.get(),
                                0,
                                "identity processing still owns serviced queues"
                            );
                            Ok(materialize_synthetic_pair(evidence))
                        })
                        .map_err(CapturePathError::from)
                },
                Instant::now,
            )
        },
        &(),
    );
    assert_eq!(
        (armed.get(), rate.get(), samples, released.get()),
        (1, 1, 5, 2)
    );
    let previous_ir = state.engine.ir_available;
    state.engine.ir_available = true;
    let result = state.engine.finish_pair_authentication(
        &paired_enrollment(),
        AuthenticationPurpose::Verify,
        Some("login"),
        prepared,
        None,
        &(),
    );
    state.engine.ir_available = previous_ir;
    assert!(result.unwrap().granted);
}

#[test]
fn managed_pair_releases_on_rate_processing_error_and_panic_without_admission() {
    use crate::managed_pad::with_managed_pair;
    struct Owner<'a>(&'a Cell<usize>);
    impl Drop for Owner<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    for fault in ["rate", "processing", "panic"] {
        let released = Cell::new(0);
        let processed = Cell::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_managed_pair(
                || Ok((Owner(&released), Owner(&released))),
                |_, _| {
                    if fault == "rate" {
                        Err(CapturePathError::ConcurrentPair(
                            irlume_common::Error::Hardware("rate failure".into()),
                        ))
                    } else {
                        Ok(())
                    }
                },
                |_, _| {
                    processed.set(processed.get() + 1);
                    assert_ne!(fault, "panic", "processing panic");
                    Err::<(), _>(CapturePathError::Other(irlume_common::Error::Hardware(
                        "inference failure".into(),
                    )))
                },
                &(),
            )
        }));
        assert_eq!(released.get(), 2);
        assert_eq!(processed.get(), usize::from(fault != "rate"));
        match result {
            Ok(Err(error)) => assert_eq!(
                matches!(error, CapturePathError::ConcurrentPair(_)),
                fault == "rate"
            ),
            Err(_) => assert_eq!(fault, "panic"),
            Ok(Ok(_)) => panic!("failed work admitted"),
        }
    }
}

#[test]
fn managed_deadline_preserves_completed_hard_refusal_but_never_admits_ready_or_starts_expired() {
    let _guard = env_guard();
    let mut state = shared();
    let start = Instant::now();
    let deadline = start + Duration::from_secs(15);
    for hard_failure in [false, true] {
        let clock = Cell::new(start);
        let mut samples = 0;
        let result = state.engine.collect_concurrent_pending_with(
            deadline,
            |engine| {
                let mut evidence = visible_pair_sample(engine, samples, 0.2, false);
                samples += 1;
                if hard_failure {
                    evidence.assessment.ir_pad = PadEvidence::InferenceFailed;
                }
                let prepared = engine
                    .prepare_pair_authentication_with(evidence, |_, evidence| {
                        Ok(materialize_synthetic_pair(evidence))
                    })
                    .map_err(CapturePathError::from);
                if hard_failure || samples == 5 {
                    clock.set(deadline);
                }
                prepared
            },
            || clock.get(),
        );
        if hard_failure {
            assert_eq!(samples, 1);
            assert!(matches!(
                result,
                Ok(PreparedPairAuthentication::Refused(Outcome {
                    kind: OutcomeKind::RuntimeUnavailable,
                    ..
                }))
            ));
            assert!(state.engine.last_attempt_facts.rgb_face.is_some());
        } else {
            assert_eq!(samples, 5);
            assert!(matches!(
                result,
                Err(CapturePathError::Other(
                    irlume_common::Error::DeadlineExpired
                ))
            ));
            assert_eq!(state.engine.last_attempt_facts.rgb_face, None);
        }
        assert!(state.engine.vit_scores.is_empty());
    }
    let result = state.engine.collect_concurrent_pending_with(
        deadline,
        |_| panic!("expired sample must not start"),
        || deadline,
    );
    assert!(matches!(
        result,
        Err(CapturePathError::Other(
            irlume_common::Error::DeadlineExpired
        ))
    ));
    assert!(state.engine.vit_scores.is_empty());
}
