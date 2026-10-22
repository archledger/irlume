// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

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
            irlume_common::config::privileged_grouped_pad_evidence_enabled(),
        )
}

// Keep exact runtime authority in the outer gate; this policy decision is
// testable without manufacturing camera contracts or widening their API.
#[expect(
    clippy::too_many_arguments,
    reason = "the owner opt-in is read by the caller so this stays a pure policy \
              decision, testable without a config file on the test host"
)]
pub(super) fn eligible_configuration(
    mode: &CaptureModeSelection,
    has_ir: bool,
    has_rgb_pad: bool,
    has_ir_pad: bool,
    window: u64,
    purpose: AuthenticationPurpose,
    service: Option<&str>,
    privileged_opt_in: bool,
) -> bool {
    grouped_scope(purpose, service, privileged_opt_in)
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

/// The services and purposes a grouped collection may serve, whatever the
/// camera class: local login and lock surfaces, privileged ones only with the
/// owner's opt-in, and Verify's unknown-service default.
fn grouped_scope(
    purpose: AuthenticationPurpose,
    service: Option<&str>,
    privileged_opt_in: bool,
) -> bool {
    let local_session = matches!(
        service.and_then(irlume_common::pam_service::classify),
        Some(
            irlume_common::pam_service::ServiceKind::Greeter
                | irlume_common::pam_service::ServiceKind::ScreenUnlock
        )
    );
    // The machine owner's opt-in (`privileged_grouped_pad_evidence`) lets the
    // privileged surfaces reach this collector. Without it nothing below moves.
    // It widens SCOPE only: every sample, threshold and vote count downstream is
    // the greeter's, so a privileged grant still closes the whole vote window.
    // Credential release stays out either way — a wallet secret must name a
    // recognized local login/lock service, and an owner preference is not a
    // reason to widen that.
    let privileged = privileged_opt_in
        && matches!(
            service.and_then(irlume_common::pam_service::classify),
            Some(
                irlume_common::pam_service::ServiceKind::Elevation
                    | irlume_common::pam_service::ServiceKind::AppConsent
            )
        );
    // Preserve Verify's unknown-service default. Credential release must name
    // a recognized local login/lock service; budgets cannot widen this scope.
    match purpose {
        AuthenticationPurpose::Verify => {
            local_session
                || privileged
                || service
                    .and_then(irlume_common::pam_service::classify)
                    .is_none()
        }
        AuthenticationPurpose::CredentialRelease => local_session,
        AuthenticationPurpose::AppConsent => privileged,
    }
}

/// Whether a split authentication collects one grouped batch (ADR-0032,
/// amendment 2026-10-13, section 8): the grouped scope of an ordinary
/// sequential pair, both PAD models and IR, and a window of at least
/// [`GRACE_WINDOW_MS`]. A split pair has no stored qualification or runtime
/// contract to require; its sequential posture holds at any skew.
pub(super) fn split_eligible_configuration(
    has_ir: bool,
    has_rgb_pad: bool,
    has_ir_pad: bool,
    window: u64,
    purpose: AuthenticationPurpose,
    service: Option<&str>,
    privileged_opt_in: bool,
) -> bool {
    grouped_scope(purpose, service, privileged_opt_in)
        && has_ir
        && has_rgb_pad
        && has_ir_pad
        && window >= GRACE_WINDOW_MS
}

/// Report one phase of the grouped route's sequential batch as its trace
/// schema 5 stage: an elapsed time only.
pub(super) fn emit_batch_phase(
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    phase: irlume_camera::SequentialBatchPhase,
    elapsed: std::time::Duration,
) {
    use irlume_camera::SequentialBatchPhase as Phase;
    use irlume_common::diagnostics::TraceStage;
    let stage = match phase {
        Phase::RgbStart => TraceStage::SequentialRgbStart,
        Phase::RgbSample => TraceStage::SequentialRgbSample,
        Phase::RgbRelease => TraceStage::SequentialRgbRelease,
        Phase::IrStart => TraceStage::SequentialIrStart,
        Phase::IrSample => TraceStage::SequentialIrSample,
        Phase::IrRelease => TraceStage::SequentialIrRelease,
    };
    diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::StageTiming {
        stage,
        elapsed_us: u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
    });
}

/// Run a grouped route's evaluation of its collected samples inside the
/// `GroupedEvaluation` stage, reported once whatever the result. The batch
/// released its sessions before returning, so this lies inside
/// `Finalization`; the rest of that interval is the final matching, camera
/// handle close and lease release.
pub(super) fn in_grouped_evaluation<T>(
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    evaluate: impl FnOnce() -> T,
) -> T {
    let _timing = TraceStageTimer::new(
        diagnostics,
        irlume_common::diagnostics::TraceStage::GroupedEvaluation,
    );
    evaluate()
}

/// The ViT RGB PAD answer for one RGB face, computed while the IR session
/// captured; [`Engine::assess_captured_pair`] uses it in place of the same
/// call for the same unreplaced frame and the bit-identical box.
pub(super) struct RgbPadScore {
    pub(super) bbox: [f32; 4],
    pub(super) answer: Result<f32, String>,
}

/// The RGB half of one grouped sample, computed during the IR phase: the
/// detector's answer and, when it found a face, the ViT answer for its top
/// face. The evaluation consumes it at the points it would have made these
/// calls, so every check, log line and vote keeps its order, and so does
/// every outcome unless a deadline falls in the wait for the worker's call
/// in flight (`authenticate_grouped_once`); the rescue detector and the
/// decision itself still run there.
pub(super) struct RgbHalf {
    /// The capture window of the frame it was computed from, carried with
    /// that frame through the worker; the evaluation consumes the half only
    /// for that frame ([`half_for_frame`]).
    pub(super) captured: irlume_camera::CaptureWindow,
    pub(super) faces: irlume_common::Result<Vec<Detection>>,
    pub(super) vit: Option<RgbPadScore>,
}

/// `half` when it was computed for the frame captured in `captured`, so a
/// half can never stand in for another frame's calls.
pub(super) fn half_for_frame(
    half: Option<RgbHalf>,
    captured: irlume_camera::CaptureWindow,
) -> Option<RgbHalf> {
    half.filter(|half| half.captured == captured)
}

/// What the RGB-half worker borrows from the engine for the IR phase: the
/// detector and the ViT session (the IR phase uses neither), and side-effect
/// free reads of the request's cancellation and window.
pub(super) struct RgbHalfModels<'a> {
    pub(super) det: &'a mut Detector,
    pub(super) vit: Option<&'a mut irlume_vision::PadVit>,
    pub(super) cancelled: Option<std::sync::Arc<dyn Fn() -> bool + Send + Sync>>,
    pub(super) deadline: Option<Instant>,
}

impl RgbHalfModels<'_> {
    /// The RGB half of each frame, for the IR phase's overlap worker;
    /// `stop` is the batch's [`irlume_camera::OverlapStop`].
    pub(super) fn precompute(
        self,
        frames: &[irlume_camera::Frame],
        stop: &dyn Fn() -> bool,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> Vec<Option<RgbHalf>> {
        let RgbHalfModels {
            det,
            vit,
            cancelled,
            deadline,
        } = self;
        let should_stop = || {
            stop()
                || cancelled.as_ref().is_some_and(|cancelled| cancelled())
                || deadline.is_some_and(|deadline| Instant::now() >= deadline)
        };
        precompute_rgb_halves(
            frames.iter().map(|frame| {
                let view = align::RgbView {
                    data: &frame.data,
                    width: frame.width,
                    height: frame.height,
                };
                (view, frame.captured)
            }),
            |view| det.detect(view),
            vit.map(|pad| {
                move |view: &align::RgbView<'_>, bbox: &[f32; 4]| pad.p_spoof(view, bbox)
            }),
            &should_stop,
            diagnostics,
        )
    }
}

/// The RGB half of each view in order, each stamped with its own frame's
/// capture window, until `should_stop` answers true or the detector errs; a
/// view not reached is `None`, and the evaluation then computes that sample
/// itself. Timings are reported as the work happens, so they lie inside the
/// IR phase. The model calls are injectable for the behavioral tests.
pub(super) fn precompute_rgb_halves<'v>(
    views: impl ExactSizeIterator<Item = (align::RgbView<'v>, irlume_camera::CaptureWindow)>,
    mut detect: impl FnMut(&align::RgbView<'_>) -> irlume_common::Result<Vec<Detection>>,
    mut score: Option<impl FnMut(&align::RgbView<'_>, &[f32; 4]) -> irlume_common::Result<f32>>,
    should_stop: &dyn Fn() -> bool,
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
) -> Vec<Option<RgbHalf>> {
    use irlume_common::diagnostics::{TraceEventKind, TraceStage};
    let count = views.len();
    let mut halves = Vec::with_capacity(count);
    for (view, captured) in views {
        if should_stop() {
            break;
        }
        let started = Instant::now();
        let faces = detect(&view);
        if faces.is_ok() {
            diagnostics.emit_trace(TraceEventKind::StageTiming {
                stage: TraceStage::Detection,
                elapsed_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            });
        }
        let top = faces
            .as_ref()
            .ok()
            .and_then(|faces| top_detection(faces))
            .map(|face| face.bbox);
        let mut vit = None;
        if let (Some(bbox), Some(score)) = (top, score.as_mut()) {
            if !should_stop() {
                let started = Instant::now();
                let answer = score(&view, &bbox).map_err(|e| e.to_string());
                diagnostics.emit_trace(TraceEventKind::StageTiming {
                    stage: TraceStage::Liveness,
                    elapsed_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
                });
                vit = Some(RgbPadScore { bbox, answer });
            }
        }
        let failed = faces.is_err();
        halves.push(Some(RgbHalf {
            captured,
            faces,
            vit,
        }));
        if failed {
            break;
        }
    }
    halves.resize_with(count, || None);
    halves
}

/// The ViT answer for the face at `bbox`: the one `precomputed` carries
/// when it was computed for this unreplaced frame and this exact box (bit
/// for bit), otherwise `compute`'s.
pub(super) fn rgb_pad_answer(
    precomputed: Option<RgbPadScore>,
    frame_replaced: bool,
    bbox: &[f32; 4],
    compute: impl FnOnce() -> Result<f32, String>,
) -> Result<f32, String> {
    match precomputed
        .filter(|score| !frame_replaced && score.bbox.map(f32::to_bits) == bbox.map(f32::to_bits))
    {
        Some(score) => score.answer,
        None => compute(),
    }
}

fn expired() -> Outcome {
    Outcome::deny(
        OutcomeKind::DeadlineExpired,
        "authentication window expired while collecting complete face evidence; use your password",
    )
}

/// Which evidence a grouped collection evaluates: the cross-spectrum pair
/// group or the convenience-tier RGB-only group. Pair groups run the pair
/// gates and mark every rgb-visible sample a sequential pair; RGB-only groups
/// run the rgb-only gates and never mark a pair (no pair exists, and the
/// matching schedule keys on that flag).
#[derive(Clone, Copy, PartialEq)]
pub(super) enum GroupModality {
    Pair,
    RgbOnly,
}

/// The convenience-tier route's eligibility: no IR pair at all, the ViT RGB
/// PAD cue loaded (its five-score median is the collection's whole purpose),
/// a default-or-longer presence window (the group must fit inside it), and
/// the same local-session scope as the pair group minus the privileged
/// opt-in, which stays pair-only. The daemon's tier gate remains the outer
/// authority: on RGB-only hardware face may only satisfy a screen unlock.
pub(super) fn rgb_only_eligible(
    has_ir: bool,
    has_rgb_pad: bool,
    window: u64,
    purpose: AuthenticationPurpose,
    service: Option<&str>,
) -> bool {
    let service_kind = service.and_then(irlume_common::pam_service::classify);
    let local_session = matches!(
        service_kind,
        Some(
            irlume_common::pam_service::ServiceKind::Greeter
                | irlume_common::pam_service::ServiceKind::ScreenUnlock
        )
    );
    let in_scope = match purpose {
        AuthenticationPurpose::Verify => local_session || service_kind.is_none(),
        AuthenticationPurpose::CredentialRelease => local_session,
        AuthenticationPurpose::AppConsent => false,
    };
    !has_ir && has_rgb_pad && window >= GRACE_WINDOW_MS && in_scope
}

impl Engine {
    fn begin_grouped_attempt(&mut self) {
        self.vit_scores.clear();
        self.last_attempt_facts = AttemptFacts::default();
    }

    /// Pre-identity gates use detected face presence, never missing embeddings
    /// from an unfinished assessment. Final admission repeats its existing gates.
    fn grouped_evidence_refusal(&self, a: &Assessment) -> Option<Outcome> {
        if let Some(refusal) = self.split_evidence_refusal(a) {
            return Some(refusal);
        }
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
                liveness_deny_kind(a.verdict, a.deny_cause),
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
        let (verdict, cues, reason) = self.gate.evaluate_ir_only(&a.signals);
        if verdict != Verdict::Live {
            return Some(Outcome::deny(
                liveness_deny_kind(verdict, cues.deny_cause),
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

    /// Pre-identity gates for the convenience tier's RGB-only group, mirroring
    /// the eager single-attempt refusals in their producing order: PAD
    /// execution failures are terminal, a non-Live verdict with a face is the
    /// liveness refusal (too dark, not facing, spoof), and the vote policy is
    /// the RGB-only requirement. A frame with no face is the retryable NoFace
    /// outcome; there is no dark route to preserve because no IR face exists.
    fn grouped_rgb_only_evidence_refusal(&self, a: &Assessment) -> Option<Outcome> {
        let rgb = a.signals.rgb_face.is_some();
        for (modality, required, evidence) in [(PadModality::Rgb, rgb, a.rgb_pad)] {
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
        if uncertain_short_circuits(a.verdict, rgb, false) || (rgb && a.verdict != Verdict::Live) {
            return Some(Outcome::deny(
                liveness_deny_kind(a.verdict, a.deny_cause),
                format!("liveness {:?}: {}", a.verdict, a.reason),
            ));
        }
        if rgb {
            return pad_policy_refusal(PadRequirements::RgbOnly, a.rgb_pad, a.ir_pad);
        }
        Some(Outcome::deny(OutcomeKind::NoFace, "no face detected"))
    }

    /// Clock and inference boundaries are replaceable for behavioral tests;
    /// PAD qualification and readiness decisions remain production code.
    pub(super) fn evaluate_grouped_samples_with<T, I>(
        &mut self,
        samples: Vec<T>,
        deadline: Instant,
        assess: impl FnMut(&mut Self, T) -> irlume_common::Result<DeferredAssessment<I>>,
        materialize: impl FnMut(&mut Self, DeferredAssessment<I>) -> irlume_common::Result<Assessment>,
        now: impl Fn() -> Instant,
    ) -> irlume_common::Result<PreparedGroup> {
        self.evaluate_grouped_samples_ex(
            samples,
            deadline,
            assess,
            materialize,
            now,
            GroupModality::Pair,
        )
    }

    /// [`Self::evaluate_grouped_samples_with`] for the convenience tier's
    /// RGB-only group: rgb-only gates, identity deferred exactly like the
    /// pair group, and never a sequential-pair marking.
    pub(super) fn evaluate_grouped_rgb_samples_with<T>(
        &mut self,
        samples: Vec<T>,
        deadline: Instant,
        assess: impl FnMut(&mut Self, T) -> irlume_common::Result<DeferredAssessment<PairIdentity>>,
        materialize: impl FnMut(
            &mut Self,
            DeferredAssessment<PairIdentity>,
        ) -> irlume_common::Result<Assessment>,
        now: impl Fn() -> Instant,
    ) -> irlume_common::Result<PreparedGroup> {
        self.evaluate_grouped_samples_ex(
            samples,
            deadline,
            assess,
            materialize,
            now,
            GroupModality::RgbOnly,
        )
    }

    fn evaluate_grouped_samples_ex<T, I>(
        &mut self,
        samples: Vec<T>,
        deadline: Instant,
        mut assess: impl FnMut(&mut Self, T) -> irlume_common::Result<DeferredAssessment<I>>,
        mut materialize: impl FnMut(
            &mut Self,
            DeferredAssessment<I>,
        ) -> irlume_common::Result<Assessment>,
        now: impl Fn() -> Instant,
        modality: GroupModality,
    ) -> irlume_common::Result<PreparedGroup> {
        self.begin_grouped_attempt();
        // The closure makes all errors and refusals share the evidence reset.
        let result = (|| {
            self.check_request_cancelled()?;
            if samples.len() != VIT_PAD_VOTE_N {
                return Err(irlume_common::Error::Hardware(
                    "incomplete grouped evidence".into(),
                ));
            }
            for (index, sample) in samples.into_iter().enumerate() {
                self.note_capture_boundary();
                self.check_request_cancelled()?;
                if now() >= deadline {
                    return Ok(PreparedGroup::Refused(expired()));
                }
                let mut evidence = assess(self, sample)?;
                self.check_request_cancelled()?;
                self.last_attempt_facts = AttemptFacts::from_assessment(&evidence.assessment);
                if now() >= deadline {
                    return Ok(PreparedGroup::Refused(expired()));
                }
                // Grouped capture always separates the RGB and IR phases,
                // including gaps inside the legacy concurrent skew ceiling.
                // Preserve this identity requirement before deferred inputs can
                // materialize; the legacy single-pair classifier is unchanged.
                // RGB-only groups never mark a pair: no pair exists, and the
                // matching schedule keys on this flag.
                if modality == GroupModality::Pair {
                    evidence.assessment.sequential_pair |=
                        evidence.assessment.signals.rgb_face.is_some()
                            || evidence.assessment.split_pair;
                }
                self.qualify_rgb_pad_evidence(&mut evidence.assessment);
                let final_sample = index + 1 == VIT_PAD_VOTE_N;
                let refusal = match modality {
                    GroupModality::Pair => self.grouped_evidence_refusal(&evidence.assessment),
                    GroupModality::RgbOnly => {
                        self.grouped_rgb_only_evidence_refusal(&evidence.assessment)
                    }
                };
                if let Some(outcome) = refusal {
                    if final_sample || !presence_retryable(&outcome) {
                        return Ok(PreparedGroup::Refused(outcome));
                    }
                    continue;
                }
                if final_sample {
                    self.check_request_cancelled()?;
                    if now() >= deadline {
                        return Ok(PreparedGroup::Refused(expired()));
                    }
                    let assessment = materialize(self, evidence)?;
                    self.check_request_cancelled()?;
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
        operation: &irlume_camera::lease::CameraOperationSession,
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
        let control = self.capture_control();
        self.emit_capture_setup(diagnostics);
        let started = Instant::now();
        // When the IR session was released: the batch returns only after the
        // worker's call in flight, which the capture marker reports apart.
        let ir_released = std::cell::Cell::new(None);
        // The RGB half of every sample depends on its RGB frame alone, so it
        // runs while the IR session captures; the detector and the ViT
        // session are the worker's until the batch returns. When the IR phase
        // ends the worker finishes only its call in flight and the evaluation
        // does the rest, so the decision's inputs are those of the serial
        // order and only its timing differs, near a deadline in either
        // direction: the evaluation is shorter, so an attempt the serial
        // order would have expired can reach its grant or refusal, and the
        // call in flight is waited for. That call can be one the serial order
        // never makes (the worker scores the top RGB face of every sample it
        // reaches, the serial order only a Live sample's), so an attempt the
        // serial order would have decided can expire instead, which strikes:
        // one it would have refused without a retry strike (an uncertain or
        // IR-faceless sample) or granted (the final sample on the dark IR-only
        // route after such samples). Either way it is a password-fallback
        // denial or a grant on complete evidence.
        let rgb_half = RgbHalfModels {
            det: &mut self.det,
            vit: self.vit_pad.as_mut(),
            cancelled: self.request_cancelled.clone(),
            deadline: self.authentication_deadline,
        };
        let batch = irlume_camera::capture_sequential_batch_overlapped(
            &cameras.0,
            &cameras.1,
            contract,
            irlume_camera::SequentialBatchRequest {
                pairs: VIT_PAD_VOTE_N,
                pair_gap_limit: SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW,
                deadline,
            },
            &control,
            &|phase, elapsed| {
                if phase == irlume_camera::SequentialBatchPhase::IrRelease {
                    ir_released.set(Some(Instant::now()));
                }
                emit_batch_phase(diagnostics, phase, elapsed);
            },
            move |frames, stop| rgb_half.precompute(frames, &|| stop.requested(), diagnostics),
        );
        let returned = Instant::now();
        // A completed batch opened and released both streams; a failed one
        // may have opened none.
        if batch.is_ok() {
            self.arm_finalization();
        }
        let (samples, halves) = batch?;
        irlume_common::dlog!(
            "[assessment-stage] grouped-capture: pairs={} elapsed={}ms after-ir-release={}ms",
            samples.len(),
            returned.duration_since(started).as_millis(),
            ir_released.get().map_or(0, |released: Instant| returned
                .saturating_duration_since(released)
                .as_millis())
        );
        let samples: Vec<_> = samples
            .into_iter()
            .zip(
                halves
                    .unwrap_or_default()
                    .into_iter()
                    .chain(std::iter::repeat_with(|| None)),
            )
            .collect();
        let prepared = in_grouped_evaluation(diagnostics, || {
            self.evaluate_grouped_samples_with(
                samples,
                deadline,
                |engine, ((rgb, ir, stats), half)| {
                    let (detected, rgb_pad_score) = match half_for_frame(half, rgb.captured) {
                        Some(RgbHalf { faces, vit, .. }) => {
                            let view = align::RgbView {
                                data: &rgb.data,
                                width: rgb.width,
                                height: rgb.height,
                            };
                            (engine.adopt_rgb_detection(&view, faces)?, vit)
                        }
                        None => (engine.detect_rgb_assessment(&rgb, None, diagnostics)?, None),
                    };
                    engine
                        .assess_captured_pair(
                            PairCapture::Ordinary(rgb, ir, stats),
                            detected,
                            PairAssessmentContext {
                                operation,
                                capture_mode: Some(mode),
                                sequential: true,
                                pair_sequential_retried: false,
                                rgb_hard_retried: false,
                                held_sessions: false,
                                ir_ms: None,
                                rgb_pad_score,
                                diagnostics,
                            },
                        )
                        .map_err(CapturePathError::into_inner)
                },
                |engine, evidence| engine.materialize_pair_identity(evidence, diagnostics),
                Instant::now,
            )
        })?;
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

    /// One grouped split attempt (ADR-0032, amendment 2026-10-13, section 8):
    /// the whole five-sample PAD vote from ONE split batch under the original
    /// split Authentication operation, each pair assessed as split evidence in
    /// order, identity only on the final admissible sample. The grant boundary,
    /// `split_grant_refusal` included, is the ordinary one.
    pub(super) fn authenticate_split_grouped_once(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        operation: &irlume_camera::lease::CameraOperationSession,
        deadline: Instant,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Outcome> {
        self.begin_grouped_attempt();
        if Instant::now() >= deadline {
            return Ok(expired());
        }
        #[cfg(feature = "test-support")]
        if crate::test_support::fixture_installed() {
            let prepared = in_grouped_evaluation(diagnostics, || {
                self.evaluate_grouped_samples_ex(
                    vec![(); VIT_PAD_VOTE_N],
                    deadline,
                    |engine, ()| {
                        let assessment =
                            engine.fixture_assessment(operation)?.ok_or_else(|| {
                                irlume_common::Error::Hardware(
                                    "split assessment fixture supplied no assessment".into(),
                                )
                            })?;
                        Ok(DeferredAssessment {
                            assessment,
                            identity: (),
                        })
                    },
                    |_, evidence| Ok(evidence.assessment),
                    Instant::now,
                    GroupModality::Pair,
                )
            })?;
            return self.finish_grouped(enr, purpose, service, prepared, deadline, diagnostics);
        }
        let control = self.capture_control();
        self.emit_capture_setup(diagnostics);
        let started = Instant::now();
        let batch = irlume_camera::capture_split_batch_observed(
            &self.rgb_dev,
            &self.ir_dev,
            operation,
            &control,
            irlume_camera::SplitBatchRequest {
                pairs: VIT_PAD_VOTE_N,
                deadline,
            },
            &|phase, elapsed| emit_batch_phase(diagnostics, phase, elapsed),
        );
        if batch.is_ok() {
            self.arm_finalization();
        }
        let samples = batch?.into_pair_captures(operation)?;
        irlume_common::dlog!(
            "[assessment-stage] split-grouped-capture: pairs={} elapsed={}ms",
            samples.len(),
            started.elapsed().as_millis()
        );
        let prepared = in_grouped_evaluation(diagnostics, || {
            self.evaluate_grouped_samples_with(
                samples,
                deadline,
                |engine, captured| {
                    captured.revalidate(operation)?;
                    let detected =
                        engine.detect_rgb_assessment(captured.rgb(), None, diagnostics)?;
                    engine
                        .assess_captured_pair(
                            PairCapture::Split(captured),
                            detected,
                            PairAssessmentContext {
                                operation,
                                capture_mode: None,
                                sequential: true,
                                pair_sequential_retried: false,
                                rgb_hard_retried: false,
                                held_sessions: false,
                                ir_ms: None,
                                rgb_pad_score: None,
                                diagnostics,
                            },
                        )
                        .map_err(CapturePathError::into_inner)
                },
                |engine, evidence| engine.materialize_pair_identity(evidence, diagnostics),
                Instant::now,
            )
        })?;
        self.finish_grouped(enr, purpose, service, prepared, deadline, diagnostics)
    }

    /// The shared end of a grouped attempt: a refused group answers as it is;
    /// a ready one reaches the ordinary grant boundary inside the deadline,
    /// and the vote ring never outlives the attempt.
    fn finish_grouped(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        prepared: PreparedGroup,
        deadline: Instant,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Outcome> {
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

    /// The convenience tier's grouped attempt: collect the whole five-sample
    /// ViT PAD vote from ONE armed RGB session (the per-sample stream setup
    /// of the eager loop is what made the vote unreachable inside the default
    /// presence window on slow RGB sensors, measured 2026-09-17), assess each
    /// sample, and materialize identity only on the final admissible sample.
    /// Vote arithmetic, thresholds and the grant boundary are unchanged.
    pub(super) fn authenticate_grouped_rgb_only_once(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        rgb: &irlume_camera::RgbCamera,
        deadline: Instant,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Outcome> {
        self.begin_grouped_attempt();
        if Instant::now() >= deadline {
            return Ok(expired());
        }
        let control = self.capture_control();
        self.emit_capture_setup(diagnostics);
        let started = Instant::now();
        let frames = irlume_camera::capture_rgb_denoised_batch_with_control(
            rgb,
            irlume_camera::RgbBatchRequest {
                samples: VIT_PAD_VOTE_N,
                deadline,
            },
            &control,
        );
        if frames.is_ok() {
            self.arm_finalization();
        }
        // The whole sequential RGB batch is the capture: reported at its
        // endpoint whether or not it succeeded, so the sequential envelope
        // covers this no-IR route's production batch (#1147).
        emit_trace_stage_ms(
            diagnostics,
            irlume_common::diagnostics::TraceStage::SequentialRgbSample,
            started.elapsed().as_millis(),
        );
        let frames = frames?;
        irlume_common::dlog!(
            "[assessment-stage] grouped-rgb-capture: samples={} elapsed={}ms",
            frames.len(),
            started.elapsed().as_millis()
        );
        let prepared = in_grouped_evaluation(diagnostics, || {
            self.evaluate_grouped_rgb_samples_with(
                frames,
                deadline,
                |engine, frame| engine.assess_rgb_only_frame_deferred(frame, diagnostics),
                |engine, evidence| engine.materialize_pair_identity(evidence, diagnostics),
                Instant::now,
            )
        })?;
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
