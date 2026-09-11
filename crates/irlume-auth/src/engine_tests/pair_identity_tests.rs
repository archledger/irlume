// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use irlume_common::diagnostics::{DiagnosticSink, TraceEventKind, TraceRefusalReason, TraceStage};

#[derive(Debug)]
enum Recorded {
    Trace(TraceEventKind),
    Dropped(&'static str),
}

#[derive(Default)]
struct RecordingSink(Mutex<Vec<Recorded>>);

impl DiagnosticSink for RecordingSink {
    fn emit_trace(&self, kind: TraceEventKind) {
        self.0.lock().unwrap().push(Recorded::Trace(kind));
    }
}

impl RecordingSink {
    fn traces(&self) -> Vec<TraceEventKind> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter_map(|record| match record {
                Recorded::Trace(event) => Some(event.clone()),
                Recorded::Dropped(_) => None,
            })
            .collect()
    }
}

#[test]
fn rgb_pad_pending_is_distinct_from_liveness_uncertain_and_still_retryable() {
    let rgb = pad_evidence_refusal(PadModality::Rgb, PadEvidence::Pending).unwrap();
    let ir = pad_evidence_refusal(PadModality::Ir, PadEvidence::Pending).unwrap();
    assert_eq!(rgb.kind, OutcomeKind::RgbPadPending);
    assert_eq!(ir.kind, OutcomeKind::Uncertain);
    assert!(presence_retryable(&rgb));
    assert!(!rgb.granted && !rgb.live);
    assert_eq!(rgb.score, 0.0);
    assert_eq!(rgb.reason, "collecting RGB PAD evidence");
    let facts = AttemptFacts::default();
    assert_eq!(
        auth_attempt_situation(rgb.kind, &facts),
        auth_attempt_situation(OutcomeKind::Uncertain, &facts)
    );
}

#[test]
fn pending_rgb_does_not_replace_a_required_ir_refusal() {
    for ir in [
        PadEvidence::Unavailable,
        PadEvidence::InferenceFailed,
        PadEvidence::NotApplicable,
    ] {
        let refusal =
            pad_policy_refusal(PadRequirements::RgbAndIr, PadEvidence::Pending, ir).unwrap();
        assert_eq!(refusal.kind, OutcomeKind::RuntimeUnavailable);
        assert!(!presence_retryable(&refusal));
    }
    let ir_pending = pad_policy_refusal(
        PadRequirements::RgbAndIr,
        PadEvidence::Pending,
        PadEvidence::Pending,
    )
    .unwrap();
    assert_eq!(ir_pending.kind, OutcomeKind::Uncertain);
    assert_eq!(ir_pending.reason, "collecting IR PAD evidence");
}

#[test]
fn ordinary_authentication_traces_the_selected_refusal_without_prose() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    let mut results = Vec::new();
    for ir in [PadEvidence::Score(0.1), PadEvidence::InferenceFailed] {
        engine.vit_scores.clear();
        engine.vit_pad_votes_deny(0.2);
        let (enrollment, mut assessment) = pad_matching_fixture(0.2, false);
        assessment.ir_pad = ir;
        assessment.reason = "private reason canary".into();
        let sink = RecordingSink::default();
        let result = engine.authenticate_assessment(
            &enrollment,
            AuthenticationPurpose::Verify,
            None,
            assessment,
            &sink,
        );
        results.push((result, sink.traces()));
    }
    engine.ir_available = previous_ir;
    engine.vit_scores.clear();
    for ((result, traces), expected) in results.into_iter().zip([
        TraceRefusalReason::RgbPadPending,
        TraceRefusalReason::RuntimeUnavailable,
    ]) {
        assert!(!result.unwrap().granted);
        let refusals: Vec<_> = traces
            .iter()
            .filter_map(|event| match event {
                TraceEventKind::AuthenticationRefusal { reason } => Some(*reason),
                _ => None,
            })
            .collect();
        assert_eq!(refusals, [expected]);
        assert!(!serde_json::to_string(&traces)
            .unwrap()
            .contains("private reason canary"));
    }
}

#[test]
fn refusal_trace_uses_only_typed_kinds_and_omits_grants() {
    for (kind, expected) in [
        (
            OutcomeKind::RgbPadPending,
            TraceRefusalReason::RgbPadPending,
        ),
        (OutcomeKind::NoFace, TraceRefusalReason::NoFace),
        (OutcomeKind::Uncertain, TraceRefusalReason::Uncertain),
        (
            OutcomeKind::SpoofNoIrFace,
            TraceRefusalReason::SpoofNoIrFace,
        ),
        (OutcomeKind::Spoof, TraceRefusalReason::Spoof),
        (
            OutcomeKind::BelowThreshold,
            TraceRefusalReason::BelowThreshold,
        ),
        (
            OutcomeKind::SetupUnavailable,
            TraceRefusalReason::SetupUnavailable,
        ),
        (
            OutcomeKind::DeadlineExpired,
            TraceRefusalReason::DeadlineExpired,
        ),
        (
            OutcomeKind::RuntimeUnavailable,
            TraceRefusalReason::RuntimeUnavailable,
        ),
        (OutcomeKind::OtherDeny, TraceRefusalReason::OtherDeny),
    ] {
        for prose in ["collecting RGB PAD evidence", "unrelated private reason"] {
            let sink = RecordingSink::default();
            emit_authentication_refusal(&sink, &Outcome::deny_live(kind, 0.12345, prose));
            let traces = sink.traces();
            assert!(matches!(traces.as_slice(), [
                TraceEventKind::AuthenticationRefusal { reason }
            ] if *reason == expected));
            let json = serde_json::to_value(&traces[0]).unwrap();
            assert_eq!(json.as_object().unwrap().len(), 2);
            assert!(json.get("score").is_none());
            assert!(!json.to_string().contains(prose));
        }
    }
    let sink = RecordingSink::default();
    emit_authentication_refusal(&sink, &Outcome::grant(0.12345, "private grant reason"));
    assert!(sink.traces().is_empty());
}

struct DropStream<'a>(&'a RecordingSink, &'static str);

impl Drop for DropStream<'_> {
    fn drop(&mut self) {
        std::thread::sleep(std::time::Duration::from_millis(1));
        self.0 .0.lock().unwrap().push(Recorded::Dropped(self.1));
    }
}

fn assert_pair_released(sink: &RecordingSink) {
    let recorded = sink.0.lock().unwrap();
    assert!(
        matches!(recorded.as_slice(), [
            Recorded::Dropped("rgb"),
            Recorded::Dropped("ir"),
            Recorded::Trace(TraceEventKind::StageTiming {
                stage: TraceStage::StreamOwnerRelease,
                elapsed_us,
            }),
        ] if *elapsed_us >= 2_000),
        "both owner destructors must complete in the measured release interval: {recorded:?}"
    );
}

#[test]
fn stream_release_trace_follows_both_destructors_on_success_and_error() {
    for succeed in [true, false] {
        let sink = RecordingSink::default();
        let result = with_owned_pair(
            (DropStream(&sink, "rgb"), DropStream(&sink, "ir")),
            &sink,
            |_, _| {
                assert!(sink.traces().is_empty());
                if succeed {
                    Ok(7)
                } else {
                    Err("assessment error")
                }
            },
        );
        assert_eq!(
            result,
            if succeed {
                Ok(7)
            } else {
                Err("assessment error")
            }
        );
        assert_pair_released(&sink);
    }
}

#[test]
fn stream_release_trace_follows_both_destructors_during_unwind() {
    let sink = RecordingSink::default();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_owned_pair(
            (DropStream(&sink, "rgb"), DropStream(&sink, "ir")),
            &sink,
            |_, _| panic!("synthetic assessment panic"),
        );
    }));
    assert!(result.is_err());
    assert_pair_released(&sink);
}

fn synthetic_identity(landmarks: Landmarks5) -> IdentityImage {
    IdentityImage {
        data: (0..112 * 112 * 3).map(|i| (i % 251) as u8).collect(),
        width: 112,
        height: 112,
        face: Detection {
            bbox: [0.0, 0.0, 111.0, 111.0],
            score: 1.0,
            landmarks,
        },
    }
}

#[test]
fn identity_timing_covers_eager_materialization_and_alignment_failure() {
    let _guard = env_guard();
    let mut state = shared();
    for succeeds in [true, false] {
        let (_, mut assessment) = pad_matching_fixture(0.2, false);
        assessment.embedding = None;
        let landmarks = if succeeds {
            align::ARCFACE_REF_112
        } else {
            [(0.0, 0.0); 5]
        };
        let sink = RecordingSink::default();
        let result = state.engine.materialize_pair_identity(
            DeferredAssessment {
                assessment,
                identity: (
                    Some(synthetic_identity(landmarks)),
                    Some(synthetic_identity(landmarks)),
                ),
            },
            &sink,
        );
        if succeeds {
            let assessment = result.unwrap();
            assert!(assessment.embedding.is_some());
            assert!(assessment.ir_embedding.is_some());
            assert_eq!(assessment.rgb_pad, PadEvidence::Score(0.2));
        } else {
            assert!(matches!(result, Err(irlume_common::Error::Protocol(_))));
        }
        let traces = sink.traces();
        assert!(matches!(
            traces.as_slice(),
            [TraceEventKind::StageTiming {
                stage: TraceStage::IdentityInference,
                ..
            }]
        ));
        let json = serde_json::to_value(&traces[0]).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 3);
        assert!(json["elapsed_us"].is_u64());
    }
}

#[test]
fn identity_timing_preserves_empty_input_and_deadline_refusal() {
    let _guard = env_guard();
    let mut state = shared();
    for expired in [false, true] {
        let (_, mut assessment) = pad_matching_fixture(0.2, false);
        assessment.embedding = None;
        let sink = RecordingSink::default();
        let previous = state.engine.authentication_deadline;
        if expired {
            state.engine.authentication_deadline = Some(std::time::Instant::now());
        }
        let result = state.engine.materialize_pair_identity(
            DeferredAssessment {
                assessment,
                identity: (None, None),
            },
            &sink,
        );
        state.engine.authentication_deadline = previous;
        if expired {
            assert!(matches!(result, Err(irlume_common::Error::DeadlineExpired)));
        } else {
            let assessment = result.unwrap();
            assert!(assessment.embedding.is_none() && assessment.ir_embedding.is_none());
        }
        assert!(matches!(
            sink.traces().as_slice(),
            [TraceEventKind::StageTiming {
                stage: TraceStage::IdentityInference,
                ..
            }]
        ));
    }
}

pub(super) fn visible_pair_sample(
    engine: &mut Engine,
    sample: u8,
    score: f32,
    sequential: bool,
) -> DeferredAssessment<PairIdentity> {
    let deny = engine.vit_pad_votes_deny(score);
    let (_, mut assessment) = pad_matching_fixture(score, deny);
    assessment.embedding = None;
    assessment.signals = Signals {
        rgb_face: Some(irlume_liveness::FaceBox {
            cx: 0.5,
            cy: 0.5,
            score: 0.9,
        }),
        ir_face: Some(irlume_liveness::FaceBox {
            cx: 0.5,
            cy: 0.5,
            score: 0.9,
        }),
        face_frac: 0.3,
        ir_face_brightness: 90.0,
        ir_center_edge_ratio: 1.2,
        ir_eye_glint: Some(220.0),
        ir_ceiling_known: true,
        ir_saturated_frac: Some(0.0),
        rgb_face_brightness: 120.0,
        ..Signals::default()
    };
    assessment.ir_pad = PadEvidence::Score(0.1);
    assessment.sequential_pair = sequential;
    let image = || {
        let mut image = synthetic_identity(align::ARCFACE_REF_112);
        image.data[0] = sample;
        image.data[1] = 0; // synthetic matching identity; separate from sample provenance
        image
    };
    DeferredAssessment {
        assessment,
        identity: (Some(image()), Some(image())),
    }
}

pub(super) fn materialize_synthetic_pair(evidence: DeferredAssessment<PairIdentity>) -> Assessment {
    let mut assessment = evidence.assessment;
    let embedding = |image: IdentityImage| {
        let mut embedding = [0.0; EMBED_DIM];
        embedding[usize::from(image.data[1])] = 1.0;
        embedding
    };
    assessment.embedding = evidence.identity.0.map(embedding);
    assessment.ir_embedding = evidence.identity.1.map(|image| embedding(image).to_vec());
    assessment
}

pub(super) fn paired_enrollment() -> Enrollment {
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    let scan = &mut enrollment.profiles[0].scans[0];
    scan.ir = Some(scan.rgb.clone());
    scan.ir_space = Some("raw".into());
    enrollment
}

#[test]
fn ordinary_preparation_materializes_every_sample_before_pad_qualification() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    for sequential in [false, true] {
        engine.vit_scores.clear();
        let mut identities = Vec::new();
        for sample in 0..5 {
            let evidence = visible_pair_sample(engine, sample, 0.2, sequential);
            let prepared = engine
                .prepare_ordinary_pair_authentication_with(evidence, |_, evidence| {
                    assert_eq!(evidence.assessment.rgb_pad, PadEvidence::Score(0.2));
                    identities.push(evidence.identity.0.as_ref().unwrap().data[0]);
                    Ok(materialize_synthetic_pair(evidence))
                })
                .unwrap();
            assert_eq!(
                identities.len(),
                usize::from(sample) + 1,
                "ordinary authentication must materialize even incomplete PAD"
            );
            let outcome = engine
                .finish_pair_authentication(
                    &paired_enrollment(),
                    AuthenticationPurpose::Verify,
                    Some("login"),
                    Ok(prepared),
                    None,
                    &(),
                )
                .unwrap();
            assert_eq!(outcome.granted, sample == 4);
            assert_eq!(engine.vit_scores.len(), usize::from(sample) + 1);
            if sample < 4 {
                assert_eq!(outcome.kind, OutcomeKind::RgbPadPending);
            }
        }
        assert_eq!(identities, [0, 1, 2, 3, 4]);
    }
    engine.ir_available = previous_ir;
    engine.vit_scores.clear();
}

#[test]
fn ordinary_preparation_preserves_identity_failure_before_pad_refusal() {
    let _guard = env_guard();
    let mut state = shared();
    for ir_pad in [PadEvidence::Score(0.1), PadEvidence::InferenceFailed] {
        state.engine.vit_scores.clear();
        let mut evidence = visible_pair_sample(&mut state.engine, 0, 0.2, false);
        evidence.assessment.ir_pad = ir_pad;
        let prepared = state
            .engine
            .prepare_ordinary_pair_authentication_with(evidence, |_, _| {
                Err(irlume_common::Error::Hardware(
                    "identity inference failed".into(),
                ))
            })
            .map_err(CapturePathError::from);
        let mut fallback = false;
        let result = state.engine.finish_pair_authentication(
            &paired_enrollment(),
            AuthenticationPurpose::Verify,
            Some("login"),
            prepared,
            Some(&mut fallback),
            &(),
        );
        assert!(matches!(
            result,
            Err(irlume_common::Error::Hardware(ref message))
                if message == "identity inference failed"
        ));
        assert!(!fallback, "identity failure must not demote capture");
        assert!(state.engine.vit_scores.is_empty());
    }
}

#[test]
fn managed_preparation_keeps_pending_votes_and_materializes_only_the_final_sample() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    for sequential in [false, true] {
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::CredentialRelease,
        ] {
            engine.vit_scores.clear();
            let mut materialized = Vec::new();
            let mut admitted = 0;
            for (index, score) in [0.2, 0.2, 0.99, 0.2, 0.2].into_iter().enumerate() {
                let sample = visible_pair_sample(engine, index as u8, score, sequential);
                let prepared = engine
                    .prepare_pair_authentication_with(sample, |_, evidence| {
                        materialized.push(evidence.identity.0.as_ref().unwrap().data[0]);
                        assert_eq!(evidence.identity.1.as_ref().unwrap().data[0], index as u8);
                        Ok(materialize_synthetic_pair(evidence))
                    })
                    .unwrap();
                if matches!(prepared, PreparedPairAuthentication::Ready(_)) {
                    admitted += 1;
                }
                let out = engine
                    .finish_pair_authentication(
                        &paired_enrollment(),
                        purpose,
                        Some("login"),
                        Ok(prepared),
                        None,
                        &(),
                    )
                    .unwrap();
                assert_eq!(out.granted, index == 4, "sample {index}: {out:?}");
                assert_eq!(
                    engine.vit_scores.len(),
                    index + 1,
                    "qualification must happen once"
                );
                if index < 4 {
                    assert_eq!(out.kind, OutcomeKind::RgbPadPending);
                    assert!(!out.live && out.score == 0.0);
                    assert!(materialized.is_empty());
                    assert_eq!(engine.last_attempt_facts.rgb_face, Some((0.5, 0.5)));
                }
            }
            assert_eq!(materialized, [4]);
            assert_eq!(admitted, 1);
        }
    }
    engine.ir_available = previous_ir;
    engine.vit_scores.clear();
}

#[test]
fn managed_preparation_required_pad_refusals_do_not_materialize_identity() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    for (rgb, ir, expected) in [
        (
            PadEvidence::Score(0.2),
            PadEvidence::Unavailable,
            OutcomeKind::RuntimeUnavailable,
        ),
        (
            PadEvidence::Score(0.2),
            PadEvidence::InferenceFailed,
            OutcomeKind::RuntimeUnavailable,
        ),
        (
            PadEvidence::Score(0.2),
            PadEvidence::NotApplicable,
            OutcomeKind::RuntimeUnavailable,
        ),
        (
            PadEvidence::Score(0.2),
            PadEvidence::Pending,
            OutcomeKind::Uncertain,
        ),
        (
            PadEvidence::Unavailable,
            PadEvidence::Score(0.1),
            OutcomeKind::RuntimeUnavailable,
        ),
        (
            PadEvidence::InferenceFailed,
            PadEvidence::Score(0.1),
            OutcomeKind::RuntimeUnavailable,
        ),
        (
            PadEvidence::NotApplicable,
            PadEvidence::Score(0.1),
            OutcomeKind::RuntimeUnavailable,
        ),
        (
            PadEvidence::Score(f32::NAN),
            PadEvidence::Score(0.1),
            OutcomeKind::RuntimeUnavailable,
        ),
    ] {
        engine.vit_scores.clear();
        let mut sample = visible_pair_sample(engine, 0, 0.2, false);
        sample.assessment.rgb_pad = rgb;
        sample.assessment.ir_pad = ir;
        let prepared = engine
            .prepare_pair_authentication_with(sample, |_, _| {
                panic!("refused PAD must not attempt identity, even if its inputs would fail")
            })
            .unwrap();
        let PreparedPairAuthentication::Refused(out) = prepared else {
            panic!("PAD admitted");
        };
        assert_eq!(out.kind, expected);
        assert!(!out.granted && !out.live && out.score == 0.0);
    }
    engine.vit_scores.clear();
}

#[test]
fn managed_preparation_interruption_resets_votes_but_pending_does_not() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    for interruption in [
        "no-face",
        "uncertain",
        "spoof",
        "missing-pad",
        "invalid-pad",
    ] {
        engine.vit_scores.clear();
        for i in 0..4 {
            let sample = visible_pair_sample(engine, i, 0.2, false);
            assert!(matches!(
                engine.prepare_pair_authentication_with(sample, |_, _| panic!("pending identity")),
                Ok(PreparedPairAuthentication::Refused(_))
            ));
        }
        assert_eq!(engine.vit_scores.len(), 4);
        let mut interrupted = visible_pair_sample(engine, 4, 0.2, false);
        match interruption {
            "no-face" => {
                interrupted.identity = (None, None);
                interrupted.assessment.signals.rgb_face = None;
                interrupted.assessment.signals.ir_face = None;
                interrupted.assessment.verdict = Verdict::Uncertain;
                interrupted.assessment.rgb_pad = PadEvidence::NotApplicable;
            }
            "uncertain" => interrupted.assessment.verdict = Verdict::Uncertain,
            "spoof" => interrupted.assessment.verdict = Verdict::Spoof,
            "missing-pad" => interrupted.assessment.rgb_pad = PadEvidence::NotApplicable,
            "invalid-pad" => interrupted.assessment.rgb_pad = PadEvidence::Score(f32::NAN),
            _ => unreachable!(),
        }
        engine
            .prepare_pair_authentication_with(interrupted, |_, evidence| {
                Ok(materialize_synthetic_pair(evidence))
            })
            .unwrap();
        assert!(engine.vit_scores.is_empty(), "interruption {interruption}");
        let sample = visible_pair_sample(engine, 5, 0.2, false);
        assert!(matches!(
            engine.prepare_pair_authentication_with(sample, |_, _| panic!(
                "new presentation identity"
            )),
            Ok(PreparedPairAuthentication::Refused(Outcome {
                kind: OutcomeKind::RgbPadPending,
                ..
            }))
        ));
        assert_eq!(engine.vit_scores.len(), 1);
    }
    engine.vit_scores.clear();
}

#[test]
fn managed_preparation_non_live_precedence_matches_eager_admission() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    for (verdict, reason) in [
        (Verdict::Uncertain, "framing fixture"),
        (Verdict::Uncertain, "IR exposure unmeasurable fixture"),
        (Verdict::Spoof, "no face in IR fixture"),
        (Verdict::Spoof, "spoof fixture"),
    ] {
        for (rgb, ir) in [(true, true), (true, false), (false, true), (false, false)] {
            let make = |engine: &mut Engine| {
                engine.vit_scores.clear();
                let mut sample = visible_pair_sample(engine, 0, 0.2, false);
                sample.assessment.verdict = verdict;
                sample.assessment.reason = reason.into();
                sample.assessment.ir_pad = PadEvidence::InferenceFailed;
                if !rgb {
                    sample.identity.0 = None;
                    sample.assessment.signals.rgb_face = None;
                }
                if !ir {
                    sample.identity.1 = None;
                    sample.assessment.signals.ir_face = None;
                }
                sample
            };
            let sample = make(engine);
            let mut calls = 0;
            let prepared = engine
                .prepare_pair_authentication_with(sample, |engine, evidence| {
                    calls += 1;
                    assert_eq!(
                        engine.vit_scores.len(),
                        1,
                        "non-Live still materializes before qualification"
                    );
                    Ok(materialize_synthetic_pair(evidence))
                })
                .unwrap();
            let actual = engine
                .finish_pair_authentication(
                    &paired_enrollment(),
                    AuthenticationPurpose::Verify,
                    None,
                    Ok(prepared),
                    None,
                    &(),
                )
                .unwrap();
            let eager = materialize_synthetic_pair(make(engine));
            let expected = engine
                .authenticate_assessment(
                    &paired_enrollment(),
                    AuthenticationPurpose::Verify,
                    None,
                    eager,
                    &(),
                )
                .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(
                (
                    actual.kind,
                    actual.granted,
                    actual.live,
                    actual.score,
                    actual.reason
                ),
                (
                    expected.kind,
                    expected.granted,
                    expected.live,
                    expected.score,
                    expected.reason
                )
            );
        }
    }
    engine.ir_available = previous_ir;
    engine.vit_scores.clear();
}

#[test]
fn managed_preparation_dark_routes_keep_eager_identity_and_existing_gate_order() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    for (lit, ir_failure, ir_matches, tagged) in [
        (false, false, true, true),
        (true, false, true, true),
        (false, true, true, true),
        (false, false, false, true),
        (false, false, true, false),
        (false, true, true, false),
    ] {
        engine.vit_scores.clear();
        let mut sample = visible_pair_sample(engine, 0, 0.2, true);
        sample.identity.0 = None;
        sample.assessment.signals.rgb_face = None;
        sample.assessment.verdict = Verdict::Uncertain;
        sample.assessment.rgb_pad = PadEvidence::NotApplicable;
        sample.assessment.rgb_frame_mean = if lit {
            irlume_camera::CONCLUSIVE_SCENE_BRIGHTNESS
        } else {
            10.0
        };
        if ir_failure {
            sample.assessment.ir_pad = PadEvidence::InferenceFailed;
        }
        if !ir_matches {
            sample.identity.1.as_mut().unwrap().data[1] = 1;
        }
        let mut calls = 0;
        let prepared = engine
            .prepare_pair_authentication_with(sample, |_, evidence| {
                calls += 1;
                Ok(materialize_synthetic_pair(evidence))
            })
            .unwrap();
        let mut enrollment = paired_enrollment();
        if !tagged {
            enrollment.profiles[0].scans[0].ir_space = None;
        }
        let out = engine
            .finish_pair_authentication(
                &enrollment,
                AuthenticationPurpose::Verify,
                None,
                Ok(prepared),
                None,
                &(),
            )
            .unwrap();
        assert_eq!(calls, 1, "dark identity must remain eager");
        assert_eq!(
            out.granted,
            !lit && !ir_failure && ir_matches && tagged,
            "{out:?}"
        );
        if !tagged {
            assert_eq!(
                out.kind,
                OutcomeKind::OtherDeny,
                "template compatibility precedes dark PAD"
            );
        }
        if lit {
            assert_eq!(out.kind, OutcomeKind::Uncertain);
        }
    }
    engine.ir_available = previous_ir;
    engine.vit_scores.clear();
}

#[test]
fn managed_preparation_ready_preserves_sequential_identity_restriction() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    for sequential in [false, true] {
        engine.vit_scores = vec![0.2; 4];
        let mut sample = visible_pair_sample(engine, 4, 0.2, sequential);
        sample.identity.1.as_mut().unwrap().data[1] = 1;
        let prepared = engine
            .prepare_pair_authentication_with(sample, |_, evidence| {
                assert_eq!(evidence.assessment.sequential_pair, sequential);
                Ok(materialize_synthetic_pair(evidence))
            })
            .unwrap();
        let out = engine
            .finish_pair_authentication(
                &paired_enrollment(),
                AuthenticationPurpose::Verify,
                None,
                Ok(prepared),
                None,
                &(),
            )
            .unwrap();
        assert_eq!(out.granted, !sequential);
        if sequential {
            assert_eq!(out.kind, OutcomeKind::BelowThreshold);
            assert!(!presence_retryable(&out));
        }
    }
    engine.ir_available = previous_ir;
    engine.vit_scores.clear();
}

#[test]
fn managed_preparation_checks_cancellation_and_deadline_around_identity() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    for cancel in [false, true] {
        for before in [false, true] {
            engine.vit_scores = vec![0.2; 4];
            let sample = visible_pair_sample(engine, 4, 0.2, false);
            let cancelled = Arc::new(AtomicBool::new(cancel && before));
            let signal = cancelled.clone();
            engine.set_request_cancel_signal(Arc::new(move || signal.load(Ordering::SeqCst)));
            engine.authentication_deadline = (!cancel && before).then(std::time::Instant::now);
            let mut calls = 0;
            let prepared = engine
                .prepare_pair_authentication_with(sample, |engine, evidence| {
                    calls += 1;
                    if cancel {
                        cancelled.store(true, Ordering::SeqCst);
                    } else {
                        engine.authentication_deadline = Some(std::time::Instant::now());
                    }
                    Ok(materialize_synthetic_pair(evidence))
                })
                .map_err(CapturePathError::from);
            let mut fallback = false;
            let out = engine.finish_pair_authentication(
                &paired_enrollment(),
                AuthenticationPurpose::Verify,
                None,
                prepared,
                Some(&mut fallback),
                &(),
            );
            engine.request_cancelled = None;
            engine.authentication_deadline = None;
            assert_eq!(calls, usize::from(!before));
            assert!(!fallback);
            assert!(engine.vit_scores.is_empty());
            assert!(if cancel {
                matches!(out, Err(irlume_common::Error::Preempted(_)))
            } else {
                matches!(out, Err(irlume_common::Error::DeadlineExpired))
            });
        }
    }
}

#[test]
fn managed_preparation_required_identity_errors_clear_votes_without_capture_fallback() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    engine.vit_scores = vec![0.2; 4];
    let sample = visible_pair_sample(engine, 4, 0.2, false);
    let mut materialized = 0;
    let prepared = engine
        .prepare_pair_authentication_with(sample, |_, _| {
            materialized += 1;
            Err(irlume_common::Error::Protocol(
                "synthetic identity failure".into(),
            ))
        })
        .map_err(CapturePathError::from);
    let mut fallback = false;
    let result = engine.finish_pair_authentication(
        &paired_enrollment(),
        AuthenticationPurpose::Verify,
        None,
        prepared,
        Some(&mut fallback),
        &(),
    );
    assert_eq!(materialized, 1);
    assert!(matches!(result, Err(irlume_common::Error::Protocol(_))));
    assert!(!fallback && engine.vit_scores.is_empty());
    engine.vit_scores = vec![0.2; 4];
    let result = engine.finish_pair_authentication(
        &paired_enrollment(),
        AuthenticationPurpose::Verify,
        None,
        Err(CapturePathError::ConcurrentPair(
            irlume_common::Error::Hardware("synthetic capture failure".into()),
        )),
        Some(&mut fallback),
        &(),
    );
    assert!(matches!(result, Err(irlume_common::Error::Hardware(_))));
    assert!(fallback && engine.vit_scores.is_empty());
}

#[test]
fn managed_preparation_admission_and_refusal_follow_stream_owner_release() {
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    for ready in [false, true] {
        engine.vit_scores = vec![0.2; if ready { 4 } else { 0 }];
        let sample = visible_pair_sample(engine, 4, 0.2, false);
        let sink = RecordingSink::default();
        let prepared = with_owned_pair(
            (DropStream(&sink, "rgb"), DropStream(&sink, "ir")),
            &sink,
            |_, _| {
                engine
                    .prepare_pair_authentication_with(sample, |_, evidence| {
                        assert!(ready);
                        assert!(
                            sink.0.lock().unwrap().is_empty(),
                            "materialization still owns streams"
                        );
                        Ok(materialize_synthetic_pair(evidence))
                    })
                    .map_err(CapturePathError::from)
            },
        );
        assert_pair_released(&sink);
        let outcome = engine
            .finish_pair_authentication(
                &paired_enrollment(),
                AuthenticationPurpose::Verify,
                None,
                prepared,
                None,
                &sink,
            )
            .unwrap();
        assert_eq!(outcome.granted, ready);
        let records = sink.0.lock().unwrap();
        assert!(
            matches!(records[3], Recorded::Trace(TraceEventKind::Decision { .. })) && ready
                || matches!(
                    records[3],
                    Recorded::Trace(TraceEventKind::AuthenticationRefusal {
                        reason: TraceRefusalReason::RgbPadPending
                    })
                ) && !ready
        );
    }
    engine.ir_available = previous_ir;
    engine.vit_scores.clear();
}

#[test]
fn managed_preparation_retry_loop_reaches_identity_once_and_stops_after_a_match_decision() {
    use std::{
        cell::Cell,
        time::{Duration, Instant},
    };
    let _guard = env_guard();
    let mut state = shared();
    let engine = &mut state.engine;
    let previous_ir = engine.ir_available;
    engine.ir_available = true;
    for (score, matches, expected) in [
        (0.2, true, OutcomeKind::Granted),
        (0.2, false, OutcomeKind::BelowThreshold),
        (0.99, true, OutcomeKind::Spoof),
    ] {
        engine.vit_scores.clear();
        let started = Instant::now();
        let clock = Cell::new(started);
        let attempts = Cell::new(0);
        let identities = Cell::new(0);
        let mut costliest = Duration::ZERO;
        let (result, fallback) = engine.authentication_attempt_loop_with(
            started + Duration::from_secs(15),
            15_000,
            &mut costliest,
            |engine| {
                let sample_id = attempts.get();
                assert!(sample_id < 5, "completed admission must not retry");
                attempts.set(sample_id + 1);
                let mut sample = visible_pair_sample(engine, sample_id, score, false);
                if !matches {
                    sample.identity.0.as_mut().unwrap().data[1] = 1;
                    sample.identity.1.as_mut().unwrap().data[1] = 1;
                }
                let prepared = engine
                    .prepare_pair_authentication_with(sample, |_, evidence| {
                        identities.set(identities.get() + 1);
                        Ok(materialize_synthetic_pair(evidence))
                    })
                    .map_err(CapturePathError::from);
                let out = engine.finish_pair_authentication(
                    &paired_enrollment(),
                    AuthenticationPurpose::Verify,
                    Some("login"),
                    prepared,
                    None,
                    &(),
                );
                clock.set(clock.get() + Duration::from_millis(1000));
                (out, false)
            },
            || clock.get(),
        );
        assert!(!fallback);
        assert_eq!(result.unwrap().kind, expected);
        assert_eq!(attempts.get(), 5);
        // The terminal Spoof remains deliberately eager outside the Live-only optimization.
        assert_eq!(identities.get(), 1);
        assert_eq!(costliest, Duration::from_millis(1000));
    }
    engine.ir_available = previous_ir;
    engine.vit_scores.clear();
}
