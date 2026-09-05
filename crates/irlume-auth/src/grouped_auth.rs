//! Bounded sequential evidence evaluation. Unfinished identity inputs remain
//! private and only the final admissible sample can reach identity inference.

use super::*;
use std::time::Instant;

pub(super) enum PreparedGroup {
    Ready(Box<Assessment>),
    Refused(Outcome),
}

pub(super) fn eligible(
    mode: &CaptureModeSelection,
    has_ir: bool,
    has_rgb_pad: bool,
    has_ir_pad: bool,
    window: u64,
    purpose: AuthenticationPurpose,
    service: Option<&str>,
) -> bool {
    mode.runtime_contract.is_some()
        && eligible_configuration(
            mode,
            has_ir,
            has_rgb_pad,
            has_ir_pad,
            window,
            purpose,
            service,
        )
}

// Keep exact runtime authority in the outer gate; this policy decision is
// testable without manufacturing camera contracts or widening their API.
pub(super) fn eligible_configuration(
    mode: &CaptureModeSelection,
    has_ir: bool,
    has_rgb_pad: bool,
    has_ir_pad: bool,
    window: u64,
    purpose: AuthenticationPurpose,
    service: Option<&str>,
) -> bool {
    // Unknown/absent services deliberately share the login eligibility default.
    // A budget override cannot opt elevation, app consent or release into it.
    purpose == AuthenticationPurpose::Verify
        && matches!(
            service.and_then(irlume_common::pam_service::classify),
            None | Some(
                irlume_common::pam_service::ServiceKind::Greeter
                    | irlume_common::pam_service::ServiceKind::ScreenUnlock
            )
        )
        && mode.is_sequential()
        && mode.source == STORED_CAPTURE_MODE_SOURCE
        && !mode.operation_demoted.get()
        && mode.qualification_state
            == irlume_common::diagnostics::QualificationState::MeasuredSequential
        && has_ir
        && has_rgb_pad
        && has_ir_pad
        && window >= GRACE_WINDOW_MS
}

fn expired() -> Outcome {
    Outcome::deny(
        OutcomeKind::OtherDeny,
        "authentication window expired while collecting complete face evidence; use your password",
    )
}

impl Engine {
    fn begin_grouped_attempt(&mut self) {
        self.vit_scores.clear();
        self.last_attempt_facts = AttemptFacts::default();
    }

    /// Pre-identity gates use detected face presence, never missing embeddings
    /// from an unfinished assessment. Final admission repeats its existing gates.
    fn grouped_evidence_refusal(&self, a: &Assessment) -> Option<Outcome> {
        let rgb = a.signals.rgb_face.is_some();
        let ir = a.signals.ir_face.is_some();
        // Actual required execution failures are terminal even when scene or
        // liveness evidence would otherwise invite another sample. Missing
        // faces can legitimately produce NotApplicable; optional dark RGB
        // evidence must not become a new requirement.
        for (modality, required, evidence) in [
            (PadModality::Rgb, rgb, a.rgb_pad),
            (PadModality::Ir, rgb || ir, a.ir_pad),
        ] {
            if !required {
                continue;
            }
            let failure = match evidence {
                PadEvidence::Unavailable | PadEvidence::InferenceFailed => Some(evidence),
                PadEvidence::Score(p) if !p.is_finite() => Some(PadEvidence::InferenceFailed),
                _ => None,
            };
            if let Some(failure) = failure {
                return pad_evidence_refusal(modality, failure);
            }
        }
        if uncertain_short_circuits(a.verdict, rgb, ir) || (rgb && a.verdict != Verdict::Live) {
            return Some(Outcome::deny(
                liveness_deny_kind(a.verdict, &a.reason),
                format!("liveness {:?}: {}", a.verdict, a.reason),
            ));
        }
        if rgb {
            return pad_policy_refusal(PadRequirements::RgbAndIr, a.rgb_pad, a.ir_pad);
        }
        if !ir {
            return Some(Outcome::deny(OutcomeKind::NoFace, "no face detected"));
        }
        // Preserve the independent dark route, including scene and IR PAD
        // gates, without spending an identity comparison on intermediate frames.
        if scene_conclusively_lit(a.rgb_frame_mean) {
            return Some(Outcome::deny(
                OutcomeKind::Uncertain,
                "the room is lit but no face is visible to the RGB camera; dark (IR-only) authentication requires a dark room — add light so the RGB camera can see you, or use your password",
            ));
        }
        let (verdict, _, reason) = self.gate.evaluate_ir_only(&a.signals);
        if verdict != Verdict::Live {
            return Some(Outcome::deny(
                liveness_deny_kind(verdict, &reason),
                format!("dark liveness {verdict:?}: {reason}"),
            ));
        }
        if let Some(refusal) = pad_policy_refusal(PadRequirements::IrOnly, a.rgb_pad, a.ir_pad) {
            return Some(refusal);
        }
        if pad_downgrades(verdict, a.shipped_ir_fake, IR_PAD_THRESHOLD) {
            return Some(Outcome::deny(
                OutcomeKind::Spoof,
                "dark liveness: IR PAD cue flags a spoof; use your password",
            ));
        }
        None
    }

    /// Clock and inference boundaries are replaceable for behavioral tests;
    /// PAD qualification and readiness decisions remain production code.
    pub(super) fn evaluate_grouped_samples_with<T, I>(
        &mut self,
        samples: Vec<T>,
        deadline: Instant,
        mut assess: impl FnMut(&mut Self, T) -> irlume_common::Result<DeferredAssessment<I>>,
        mut materialize: impl FnMut(
            &mut Self,
            DeferredAssessment<I>,
        ) -> irlume_common::Result<Assessment>,
        now: impl Fn() -> Instant,
    ) -> irlume_common::Result<PreparedGroup> {
        self.begin_grouped_attempt();
        // The closure makes all errors and refusals share the evidence reset.
        let result = (|| {
            if samples.len() != VIT_PAD_VOTE_N {
                return Err(irlume_common::Error::Hardware(
                    "incomplete grouped evidence".into(),
                ));
            }
            for (index, sample) in samples.into_iter().enumerate() {
                self.note_capture_boundary();
                if now() >= deadline {
                    return Ok(PreparedGroup::Refused(expired()));
                }
                let mut evidence = assess(self, sample)?;
                self.last_attempt_facts = AttemptFacts::from_assessment(&evidence.assessment);
                if now() >= deadline {
                    return Ok(PreparedGroup::Refused(expired()));
                }
                // Grouped capture always separates the RGB and IR phases,
                // including gaps inside the legacy concurrent skew ceiling.
                // Preserve this identity requirement before deferred inputs can
                // materialize; the legacy single-pair classifier is unchanged.
                evidence.assessment.sequential_pair |=
                    evidence.assessment.signals.rgb_face.is_some();
                self.qualify_rgb_pad_evidence(&mut evidence.assessment);
                let final_sample = index + 1 == VIT_PAD_VOTE_N;
                if let Some(outcome) = self.grouped_evidence_refusal(&evidence.assessment) {
                    if final_sample || !presence_retryable(&outcome) {
                        return Ok(PreparedGroup::Refused(outcome));
                    }
                    continue;
                }
                if final_sample {
                    if now() >= deadline {
                        return Ok(PreparedGroup::Refused(expired()));
                    }
                    let assessment = materialize(self, evidence)?;
                    if now() >= deadline {
                        return Ok(PreparedGroup::Refused(expired()));
                    }
                    return Ok(PreparedGroup::Ready(Box::new(assessment)));
                }
                // Dropping unfinished inputs here performs no identity work.
            }
            Err(irlume_common::Error::Hardware(
                "group ended without final evidence".into(),
            ))
        })();
        if !matches!(result, Ok(PreparedGroup::Ready(_))) {
            self.vit_scores.clear();
        }
        result
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the existing scoped authentication attempt"
    )]
    pub(super) fn authenticate_grouped_once(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        cameras: &(irlume_camera::RgbCamera, irlume_camera::IrCamera),
        mode: &CaptureModeSelection,
        deadline: Instant,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Outcome> {
        self.begin_grouped_attempt();
        if Instant::now() >= deadline {
            return Ok(expired());
        }
        let contract = mode.runtime_contract.as_ref().ok_or_else(|| {
            irlume_common::Error::Hardware(
                "grouped capture requires an exact runtime contract".into(),
            )
        })?;
        let progress = self.capture_progress();
        let started = Instant::now();
        let samples = irlume_camera::capture_sequential_batch_with_progress(
            &cameras.0,
            &cameras.1,
            contract,
            irlume_camera::SequentialBatchRequest {
                pairs: VIT_PAD_VOTE_N,
                pair_gap_limit: SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW,
                deadline,
            },
            &progress,
        )?;
        irlume_common::dlog!(
            "[assessment-stage] grouped-capture: pairs={} elapsed={}ms",
            samples.len(),
            started.elapsed().as_millis()
        );
        let prepared = self.evaluate_grouped_samples_with(
            samples,
            deadline,
            |engine, (rgb, ir, stats)| {
                let detected = engine.detect_rgb_assessment(&rgb, None, diagnostics)?;
                engine
                    .assess_captured_pair(
                        rgb,
                        ir,
                        stats,
                        detected,
                        PairAssessmentContext {
                            sequential: true,
                            pair_sequential_retried: false,
                            rgb_hard_retried: false,
                            held_sessions: false,
                            ir_ms: None,
                            diagnostics,
                        },
                    )
                    .map_err(CapturePathError::into_inner)
            },
            |engine, evidence| engine.materialize_pair_identity(evidence),
            Instant::now,
        )?;
        match prepared {
            PreparedGroup::Refused(outcome) => Ok(outcome),
            PreparedGroup::Ready(a) => {
                if Instant::now() >= deadline {
                    self.vit_scores.clear();
                    return Ok(expired());
                }
                let outcome =
                    self.authenticate_qualified_assessment(enr, purpose, service, *a, diagnostics);
                self.vit_scores.clear();
                if Instant::now() >= deadline {
                    return Ok(expired());
                }
                outcome
            }
        }
    }
}
