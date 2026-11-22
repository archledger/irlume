// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Synthetic assessment boundaries, not physical PAD qualification. Managed
//! Unavailable cases are defensive method tests: eligible production managed
//! capture requires a loaded IR cue and can instead report InferenceFailed.

use super::pair_identity_tests::{
    materialize_synthetic_pair, paired_enrollment, visible_pair_sample,
};
use super::*;
use std::cell::Cell;
use std::time::{Duration, Instant};

struct RestoredEngine {
    state: std::sync::MutexGuard<'static, Shared>,
    previous_ir: bool,
    previous_votes: Vec<f32>,
}

impl RestoredEngine {
    fn new(mut state: std::sync::MutexGuard<'static, Shared>) -> Self {
        let previous_ir = state.engine.ir_available;
        let previous_votes = std::mem::take(&mut state.engine.vit_scores);
        Self {
            state,
            previous_ir,
            previous_votes,
        }
    }
}

impl std::ops::Deref for RestoredEngine {
    type Target = Shared;

    fn deref(&self) -> &Shared {
        &self.state
    }
}

impl std::ops::DerefMut for RestoredEngine {
    fn deref_mut(&mut self) -> &mut Shared {
        &mut self.state
    }
}

impl Drop for RestoredEngine {
    fn drop(&mut self) {
        self.state.engine.ir_available = self.previous_ir;
        self.state.engine.vit_scores = std::mem::take(&mut self.previous_votes);
    }
}

#[test]
fn shared_engine_settings_are_restored_after_fixture_panic() {
    let _guard = env_guard();
    let state = shared();
    let previous_ir = state.engine.ir_available;
    let previous_votes = state.engine.vit_scores.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut state = RestoredEngine::new(state);
        state.engine.ir_available = !previous_ir;
        state.engine.vit_scores.push(0.4);
        panic!("synthetic fixture panic");
    }));
    assert!(result.is_err());
    let state = shared();
    assert_eq!(state.engine.ir_available, previous_ir);
    assert_eq!(state.engine.vit_scores, previous_votes);
}

#[derive(Clone, Copy, Debug)]
enum Scene {
    VisibleFraming,
    VisibleLowConfidenceIr,
    DarkLit,
    DarkClipped,
}

fn sample(
    engine: &mut Engine,
    scene: Scene,
    ir_pad: PadEvidence,
) -> DeferredAssessment<PairIdentity> {
    engine.vit_scores.clear();
    let mut evidence = visible_pair_sample(engine, 0, 0.2, false);
    evidence.assessment.verdict = Verdict::Uncertain;
    evidence.assessment.deny_cause = irlume_liveness::DenyCause::Other;
    evidence.assessment.reason = "synthetic retryable framing".into();
    // RGB execution failures are recorded only while the frame is still Live
    // before RGB PAD; IR failures can coexist with non-Live gate results.
    evidence.assessment.rgb_pad = PadEvidence::NotApplicable;
    evidence.assessment.ir_pad = ir_pad;
    evidence.assessment.shipped_ir_fake = match ir_pad {
        PadEvidence::Score(p) if p.is_finite() => Some(p),
        _ => None,
    };
    if matches!(scene, Scene::VisibleLowConfidenceIr) {
        // Rescue detection accepts this score, while the liveness gate's
        // stricter face cutoff rejects it. Generate the real gate result
        // rather than assuming Uncertain is the only retryable verdict.
        evidence.assessment.signals.ir_face.as_mut().unwrap().score = 0.55;
        let (verdict, cues, reason) = engine.gate.evaluate(&evidence.assessment.signals);
        evidence.assessment.verdict = verdict;
        evidence.assessment.deny_cause = cues.deny_cause;
        evidence.assessment.reason = reason;
    }
    if matches!(scene, Scene::DarkLit | Scene::DarkClipped) {
        evidence.identity.0 = None;
        evidence.assessment.signals.rgb_face = None;
        evidence.assessment.rgb_frame_mean = match scene {
            Scene::DarkLit => irlume_camera::CONCLUSIVE_SCENE_BRIGHTNESS,
            Scene::DarkClipped => 10.0,
            Scene::VisibleFraming | Scene::VisibleLowConfidenceIr => unreachable!(),
        };
    }
    if matches!(scene, Scene::DarkClipped) {
        evidence.assessment.signals.ir_ceiling_known = true;
        evidence.assessment.signals.ir_saturated_frac = Some(1.0);
    }
    evidence
}

fn finish(
    engine: &mut Engine,
    managed: bool,
    evidence: DeferredAssessment<PairIdentity>,
    identities: &Cell<usize>,
    enrollment: &Enrollment,
) -> irlume_common::Result<Outcome> {
    let materialize = |_: &mut Engine, evidence: DeferredAssessment<PairIdentity>| {
        identities.set(identities.get() + 1);
        Ok(materialize_synthetic_pair(evidence))
    };
    let prepared = if managed {
        engine.prepare_pair_authentication_with(evidence, materialize)?
    } else {
        engine.prepare_ordinary_pair_authentication_with(evidence, materialize)?
    };
    engine.finish_pair_authentication(
        enrollment,
        AuthenticationPurpose::Verify,
        Some("login"),
        Ok(prepared),
        None,
        &(),
    )
}

#[test]
fn ordinary_and_managed_required_ir_failures_preempt_retryable_refusals() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    state.engine.ir_available = true;
    let mut results = Vec::new();
    for managed in [false, true] {
        for scene in [Scene::VisibleFraming, Scene::DarkLit, Scene::DarkClipped] {
            for failure in [PadEvidence::Unavailable, PadEvidence::InferenceFailed] {
                let identities = Cell::new(0);
                let evidence = sample(&mut state.engine, scene, failure);
                let result = finish(
                    &mut state.engine,
                    managed,
                    evidence,
                    &identities,
                    &paired_enrollment(),
                );
                results.push((managed, scene, failure, result, identities.get()));
            }
        }
    }
    // Release the restored shared fixture before assertions.
    drop(state);

    for (managed, scene, failure, result, identities) in results {
        let outcome = result.unwrap();
        assert_eq!(identities, 1, "non-Live identity work remains eager");
        assert_eq!(
            outcome.kind,
            OutcomeKind::RuntimeUnavailable,
            "required IR execution failure must win: managed={managed}, {scene:?}"
        );
        assert!(!outcome.granted && !outcome.live);
        assert!(!presence_retryable(&outcome));
        assert_eq!(
            outcome.reason,
            match failure {
                PadEvidence::Unavailable => "IR PAD is unavailable; use your password",
                PadEvidence::InferenceFailed => "IR PAD inference failed; use your password",
                _ => unreachable!(),
            }
        );
    }
}

#[test]
fn framing_with_produced_ir_evidence_remains_retryable_in_both_routes() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    state.engine.ir_available = true;
    let mut results = Vec::new();
    for managed in [false, true] {
        for scene in [
            Scene::VisibleFraming,
            Scene::VisibleLowConfidenceIr,
            Scene::DarkLit,
            Scene::DarkClipped,
        ] {
            let identities = Cell::new(0);
            let evidence = sample(&mut state.engine, scene, PadEvidence::Score(0.1));
            results.push((
                managed,
                scene,
                finish(
                    &mut state.engine,
                    managed,
                    evidence,
                    &identities,
                    &paired_enrollment(),
                ),
                identities.get(),
            ));
        }
    }
    drop(state);

    for (managed, scene, result, identities) in results {
        let outcome = result.unwrap();
        assert_eq!(identities, 1);
        assert_eq!(
            outcome.kind,
            if matches!(scene, Scene::VisibleLowConfidenceIr) {
                OutcomeKind::SpoofNoIrFace
            } else {
                OutcomeKind::Uncertain
            },
            "produced evidence must not invent a runtime failure: managed={managed}, {scene:?}"
        );
        assert!(presence_retryable(&outcome));
        assert!(!outcome.granted && !outcome.live);
    }
}

struct LoopObservation {
    result: irlume_common::Result<Outcome>,
    captures: usize,
    identities: usize,
    first_kind: Option<OutcomeKind>,
    situation: Option<AttemptSituation>,
    fallback: bool,
    deferred: bool,
}

fn outer_case(
    engine: &mut Engine,
    managed: bool,
    scene: Scene,
    ir_pad: PadEvidence,
) -> LoopObservation {
    let started = Instant::now();
    let clock = Cell::new(started);
    let captures = Cell::new(0);
    let identities = Cell::new(0);
    let first_kind = Cell::new(None);
    let mut costliest = Duration::ZERO;
    let (result, fallback, deferred) = engine.authentication_attempt_loop_with(
        started + Duration::from_secs(20),
        20_000,
        &mut costliest,
        |engine| {
            captures.set(captures.get() + 1);
            clock.set(clock.get() + Duration::from_secs(1));
            let result = if captures.get() == 1 {
                let evidence = sample(engine, scene, ir_pad);
                let result = finish(engine, managed, evidence, &identities, &paired_enrollment());
                first_kind.set(result.as_ref().ok().map(|outcome| outcome.kind));
                result
            } else {
                // A reachable terminal second-capture sentinel, not a panic
                // or an exhausted clock, proves that framing really retried.
                Ok(Outcome::deny(
                    OutcomeKind::OtherDeny,
                    "synthetic second-capture sentinel",
                ))
            };
            (result, false, None::<()>)
        },
        || clock.get(),
    );
    LoopObservation {
        result,
        captures: captures.get(),
        identities: identities.get(),
        first_kind: first_kind.get(),
        situation: engine.last_attempt_situation,
        fallback,
        deferred: deferred.is_some(),
    }
}

#[test]
fn outer_grace_stops_on_required_ir_failure_but_still_retries_framing() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    state.engine.ir_available = true;
    let mut results = Vec::new();
    for managed in [false, true] {
        for scene in [Scene::VisibleFraming, Scene::DarkLit, Scene::DarkClipped] {
            for (ir_pad, should_retry) in [
                (PadEvidence::Score(0.1), true),
                (PadEvidence::Unavailable, false),
                (PadEvidence::InferenceFailed, false),
            ] {
                results.push((
                    managed,
                    scene,
                    should_retry,
                    outer_case(&mut state.engine, managed, scene, ir_pad),
                ));
            }
        }
    }
    drop(state);

    for (managed, scene, should_retry, observed) in results {
        let outcome = observed.result.unwrap();
        assert!(!observed.fallback && !observed.deferred);
        assert_eq!(observed.identities, 1);
        assert_eq!(
            observed.captures,
            if should_retry { 2 } else { 1 },
            "grace decision: managed={managed}, {scene:?}, retry={should_retry}"
        );
        assert_eq!(
            outcome.kind,
            if should_retry {
                OutcomeKind::OtherDeny
            } else {
                OutcomeKind::RuntimeUnavailable
            }
        );
        assert!(!outcome.granted && !outcome.live);
        if should_retry {
            assert_ne!(observed.situation, Some(AttemptSituation::Unavailable));
        } else {
            assert_eq!(observed.situation, Some(AttemptSituation::Unavailable));
        }
        assert_eq!(
            observed.first_kind,
            Some(if should_retry {
                OutcomeKind::Uncertain
            } else {
                OutcomeKind::RuntimeUnavailable
            })
        );
        if should_retry {
            assert_eq!(outcome.reason, "synthetic second-capture sentinel");
        }
    }
}

#[test]
fn rescued_low_confidence_ir_failure_stops_missing_face_grace_retry() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    state.engine.ir_available = true;
    let mut results = Vec::new();
    for managed in [false, true] {
        for (evidence, should_retry) in [
            (PadEvidence::Score(0.1), true),
            (PadEvidence::Unavailable, false),
            (PadEvidence::InferenceFailed, false),
        ] {
            results.push((
                should_retry,
                outer_case(
                    &mut state.engine,
                    managed,
                    Scene::VisibleLowConfidenceIr,
                    evidence,
                ),
            ));
        }
    }
    drop(state);

    for (should_retry, observed) in results {
        let outcome = observed.result.unwrap();
        assert!(!observed.fallback && !observed.deferred);
        assert_eq!(observed.identities, 1);
        assert_eq!(
            observed.captures,
            if should_retry { 2 } else { 1 },
            "rescued IR face must not hide a required execution failure"
        );
        assert_eq!(
            observed.first_kind,
            Some(if should_retry {
                OutcomeKind::SpoofNoIrFace
            } else {
                OutcomeKind::RuntimeUnavailable
            })
        );
        assert_eq!(
            outcome.kind,
            if should_retry {
                OutcomeKind::OtherDeny
            } else {
                OutcomeKind::RuntimeUnavailable
            }
        );
        assert!(!outcome.granted && !outcome.live);
        if should_retry {
            assert_ne!(observed.situation, Some(AttemptSituation::Unavailable));
        } else {
            assert_eq!(observed.situation, Some(AttemptSituation::Unavailable));
            assert_eq!(outcome.cause, Some(OutcomeCause::Other));
        }
    }
}

#[test]
fn existing_terminal_refusals_keep_precedence_over_required_ir_failure() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    state.engine.ir_available = true;
    let mut results = Vec::new();
    for managed in [false, true] {
        for case in 0..5 {
            let identities = Cell::new(0);
            let mut enrollment = paired_enrollment();
            let mut evidence = sample(
                &mut state.engine,
                if case >= 2 {
                    Scene::DarkClipped
                } else {
                    Scene::VisibleFraming
                },
                PadEvidence::InferenceFailed,
            );
            let (kind, fragment) = match case {
                0 => {
                    evidence.assessment.signals.ir_ceiling_known = false;
                    evidence.assessment.signals.ir_saturated_frac = None;
                    evidence.assessment.deny_cause =
                        irlume_liveness::DenyCause::ExposureUnmeasurable;
                    evidence.assessment.reason = "synthetic unmeasurable exposure".into();
                    (
                        OutcomeKind::RuntimeUnavailable,
                        "synthetic unmeasurable exposure",
                    )
                }
                1 => {
                    evidence.assessment.verdict = Verdict::Spoof;
                    evidence.assessment.reason = "synthetic terminal spoof".into();
                    (OutcomeKind::Spoof, "synthetic terminal spoof")
                }
                2 => {
                    enrollment.profiles[0].scans[0].ir_space = None;
                    (OutcomeKind::OtherDeny, "")
                }
                3 => {
                    evidence.assessment.signals.ir_ceiling_known = false;
                    evidence.assessment.signals.ir_saturated_frac = None;
                    (OutcomeKind::RuntimeUnavailable, "IR exposure unmeasurable")
                }
                _ => {
                    evidence.assessment.signals.ir_saturated_frac = Some(0.0);
                    evidence.assessment.signals.ir_face_brightness = 0.0;
                    (OutcomeKind::Spoof, "IR face too dark")
                }
            };
            let result = finish(
                &mut state.engine,
                managed,
                evidence,
                &identities,
                &enrollment,
            );
            results.push((case, kind, fragment, result, identities.get()));
        }
    }
    drop(state);

    for (case, kind, fragment, result, identities) in results {
        let outcome = result.unwrap();
        assert_eq!(identities, 1);
        assert_eq!(outcome.kind, kind);
        assert!(!outcome.granted && !presence_retryable(&outcome));
        assert!(!outcome.reason.contains("IR PAD"));
        if case == 2 {
            assert_eq!(outcome.cause, Some(OutcomeCause::SetupUnavailable));
        } else {
            assert!(outcome.reason.contains(fragment));
        }
    }
}

#[test]
fn lit_scene_failure_stops_retry_before_unreached_template_gate() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    state.engine.ir_available = true;
    let mut results = Vec::new();
    for managed in [false, true] {
        for (ir_pad, execution_failed) in [
            (PadEvidence::Score(0.1), false),
            (PadEvidence::Unavailable, true),
            (PadEvidence::InferenceFailed, true),
        ] {
            let identities = Cell::new(0);
            let mut enrollment = paired_enrollment();
            enrollment.profiles[0].scans[0].ir_space = None;
            let evidence = sample(&mut state.engine, Scene::DarkLit, ir_pad);
            results.push((
                execution_failed,
                finish(
                    &mut state.engine,
                    managed,
                    evidence,
                    &identities,
                    &enrollment,
                ),
                identities.get(),
            ));
        }
    }
    drop(state);

    for (execution_failed, result, identities) in results {
        let outcome = result.unwrap();
        assert_eq!(identities, 1);
        assert_eq!(
            outcome.kind,
            if execution_failed {
                OutcomeKind::RuntimeUnavailable
            } else {
                OutcomeKind::Uncertain
            }
        );
        assert_eq!(presence_retryable(&outcome), !execution_failed);
        assert!(!outcome.granted && !outcome.live);
        if execution_failed {
            assert!(outcome.reason.contains("IR PAD"));
        }
    }
}

#[test]
fn eager_identity_errors_remain_prior_to_required_ir_failure() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    state.engine.ir_available = true;
    let mut results = Vec::new();
    for managed in [false, true] {
        let calls = Cell::new(0);
        let evidence = sample(
            &mut state.engine,
            Scene::VisibleFraming,
            PadEvidence::InferenceFailed,
        );
        let materialize = |_: &mut Engine, _: DeferredAssessment<PairIdentity>| {
            calls.set(calls.get() + 1);
            Err(irlume_common::Error::Hardware(
                "synthetic identity error before PAD".into(),
            ))
        };
        let result = if managed {
            state
                .engine
                .prepare_pair_authentication_with(evidence, materialize)
        } else {
            state
                .engine
                .prepare_ordinary_pair_authentication_with(evidence, materialize)
        };
        results.push((result, calls.get()));
    }
    drop(state);

    for (result, calls) in results {
        assert_eq!(calls, 1);
        assert!(matches!(
            result,
            Err(irlume_common::Error::Hardware(reason))
                if reason == "synthetic identity error before PAD"
        ));
    }
}

#[test]
fn absence_inapplicability_and_finite_scores_do_not_invent_execution_failure() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    state.engine.ir_available = true;
    let mut results = Vec::new();
    for managed in [false, true] {
        for case in 0..4 {
            let identities = Cell::new(0);
            let mut evidence = sample(
                &mut state.engine,
                Scene::VisibleFraming,
                if case == 3 {
                    PadEvidence::Score(1.0)
                } else {
                    PadEvidence::NotApplicable
                },
            );
            let kind = match case {
                0 => {
                    evidence.identity = (None, None);
                    evidence.assessment.signals = Signals::default();
                    OutcomeKind::Uncertain
                }
                1 => {
                    evidence.identity.1 = None;
                    evidence.assessment.signals.ir_face = None;
                    evidence.assessment.verdict = Verdict::Spoof;
                    evidence.assessment.deny_cause = irlume_liveness::DenyCause::NoIrFace;
                    OutcomeKind::SpoofNoIrFace
                }
                _ => OutcomeKind::Uncertain,
            };
            let result = finish(
                &mut state.engine,
                managed,
                evidence,
                &identities,
                &paired_enrollment(),
            );
            results.push((kind, result, identities.get()));
        }
    }
    drop(state);

    for (kind, result, identities) in results {
        let outcome = result.unwrap();
        assert_eq!(identities, 1);
        assert_eq!(outcome.kind, kind);
        assert!(presence_retryable(&outcome));
        assert!(!outcome.granted && !outcome.live);
    }
}

#[test]
fn retryable_rgb_routes_still_require_recorded_rgb_execution() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    let mut results = Vec::new();
    for paired in [false, true] {
        state.engine.ir_available = paired;
        for managed in [false, true] {
            for failure in [PadEvidence::Unavailable, PadEvidence::InferenceFailed] {
                // Defensive admission coverage: today's non-Live producer
                // records NotApplicable, not an RGB execution failure.
                let mut evidence = sample(
                    &mut state.engine,
                    Scene::VisibleFraming,
                    PadEvidence::Score(0.1),
                );
                evidence.assessment.rgb_pad = failure;
                let identities = Cell::new(0);
                results.push((
                    failure,
                    finish(
                        &mut state.engine,
                        managed,
                        evidence,
                        &identities,
                        &paired_enrollment(),
                    ),
                ));
            }
        }
    }
    drop(state);

    for (failure, result) in results {
        let outcome = result.unwrap();
        assert_eq!(outcome.kind, OutcomeKind::RuntimeUnavailable);
        assert!(!outcome.granted && !outcome.live && !presence_retryable(&outcome));
        assert_eq!(
            outcome.reason,
            match failure {
                PadEvidence::Unavailable => "RGB PAD is unavailable; use your password",
                PadEvidence::InferenceFailed => "RGB PAD inference failed; use your password",
                _ => unreachable!(),
            }
        );
    }
}

#[test]
fn missing_embeddings_add_no_required_model_preflight() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    let mut results = Vec::new();
    for paired in [false, true] {
        state.engine.ir_available = paired;
        for managed in [false, true] {
            for failure in [PadEvidence::Unavailable, PadEvidence::InferenceFailed] {
                // Inconsistent evidence is a defensive private-boundary case,
                // not a claim that a producer scores a face it did not find.
                let mut evidence = sample(&mut state.engine, Scene::VisibleFraming, failure);
                evidence.identity = (None, None);
                evidence.assessment.signals = Signals::default();
                evidence.assessment.rgb_pad = failure;
                let identities = Cell::new(0);
                results.push(finish(
                    &mut state.engine,
                    managed,
                    evidence,
                    &identities,
                    &paired_enrollment(),
                ));
            }
        }
    }
    drop(state);

    for result in results {
        let outcome = result.unwrap();
        assert_eq!(outcome.kind, OutcomeKind::Uncertain);
        assert!(presence_retryable(&outcome));
        assert!(!outcome.granted && !outcome.live);
    }
}

#[test]
fn optional_pad_modalities_do_not_become_new_grant_requirements() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    let mut results = Vec::new();
    for failure in [PadEvidence::Unavailable, PadEvidence::InferenceFailed] {
        state.engine.ir_available = true;
        for managed in [false, true] {
            let identities = Cell::new(0);
            let mut evidence = sample(
                &mut state.engine,
                Scene::DarkClipped,
                PadEvidence::Score(0.1),
            );
            evidence.assessment.signals.ir_saturated_frac = Some(0.0);
            evidence.assessment.rgb_pad = failure;
            results.push(finish(
                &mut state.engine,
                managed,
                evidence,
                &identities,
                &paired_enrollment(),
            ));
        }
        state.engine.ir_available = false;
        state.engine.vit_scores = vec![0.2; VIT_PAD_VOTE_N];
        let (enrollment, mut assessment) = pad_matching_fixture(0.2, false);
        assessment.ir_pad = failure;
        results.push(state.engine.authenticate_assessment(
            &enrollment,
            AuthenticationPurpose::Verify,
            None,
            assessment,
            &(),
        ));
    }
    drop(state);

    for result in results {
        assert_eq!(result.unwrap().kind, OutcomeKind::Granted);
    }
}

#[test]
fn optional_pad_failures_do_not_preempt_retryable_presence() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    let mut results = Vec::new();
    for failure in [PadEvidence::Unavailable, PadEvidence::InferenceFailed] {
        state.engine.ir_available = true;
        for managed in [false, true] {
            for scene in [Scene::DarkLit, Scene::DarkClipped] {
                let identities = Cell::new(0);
                let mut evidence = sample(&mut state.engine, scene, PadEvidence::Score(0.1));
                evidence.assessment.rgb_pad = failure;
                results.push(finish(
                    &mut state.engine,
                    managed,
                    evidence,
                    &identities,
                    &paired_enrollment(),
                ));
            }
        }
        // The real RGB-only path is eager, not an eligible managed pair.
        state.engine.ir_available = false;
        let identities = Cell::new(0);
        let mut evidence = sample(&mut state.engine, Scene::VisibleFraming, failure);
        evidence.identity.1 = None;
        evidence.assessment.signals.ir_face = None;
        results.push(finish(
            &mut state.engine,
            false,
            evidence,
            &identities,
            &paired_enrollment(),
        ));
    }
    drop(state);

    for result in results {
        let outcome = result.unwrap();
        assert_eq!(outcome.kind, OutcomeKind::Uncertain);
        assert!(presence_retryable(&outcome));
        assert!(!outcome.granted && !outcome.live);
    }
}

#[test]
fn otherwise_admissible_samples_still_require_all_applicable_pad_evidence() {
    let _guard = env_guard();
    let mut state = RestoredEngine::new(shared());
    let mut results = Vec::new();
    for paired in [false, true] {
        for missing in [
            PadEvidence::NotApplicable,
            PadEvidence::Unavailable,
            PadEvidence::InferenceFailed,
        ] {
            state.engine.ir_available = paired;
            state.engine.vit_scores = vec![0.2; VIT_PAD_VOTE_N];
            let (enrollment, mut assessment) = pad_matching_fixture(0.2, false);
            assessment.rgb_pad = if paired {
                PadEvidence::Score(0.2)
            } else {
                missing
            };
            assessment.ir_pad = if paired {
                missing
            } else {
                PadEvidence::NotApplicable
            };
            results.push(state.engine.authenticate_assessment(
                &enrollment,
                AuthenticationPurpose::Verify,
                None,
                assessment,
                &(),
            ));
        }
    }
    drop(state);

    for result in results {
        let outcome = result.unwrap();
        assert_eq!(outcome.kind, OutcomeKind::RuntimeUnavailable);
        assert!(!outcome.granted && !outcome.live && !presence_retryable(&outcome));
    }
}
