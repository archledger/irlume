// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! One concurrent capture transaction for incomplete ordinary RGB PAD evidence.
//! Processing stays inside active queue servicing; admission follows owner Drop.

use super::*;
use std::time::Instant;

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

pub(super) fn eligible_configuration(
    mode: &CaptureModeSelection,
    has_ir: bool,
    has_rgb_pad: bool,
    has_ir_pad: bool,
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
    let authority = mode.source == ENV_CAPTURE_MODE_SOURCE
        || (mode.source == STORED_CAPTURE_MODE_SOURCE
            && mode.qualification_state
                == irlume_common::diagnostics::QualificationState::QualifiedConcurrent);
    in_scope
        && authority
        && !mode.is_sequential()
        && !mode.operation_demoted.get()
        && has_ir
        && has_rgb_pad
        && has_ir_pad
        && window >= GRACE_WINDOW_MS
}

/// Votes belong to this transaction, including callback side effects that a
/// failed tail dequeue subsequently invalidates. Never retain them on unwind.
struct CollectionState<'a> {
    engine: &'a mut Engine,
    retain_facts: bool,
}

impl<'a> CollectionState<'a> {
    fn new(engine: &'a mut Engine) -> Self {
        engine.vit_scores.clear();
        engine.last_attempt_facts = AttemptFacts::default();
        Self {
            engine,
            retain_facts: false,
        }
    }
}

impl Drop for CollectionState<'_> {
    fn drop(&mut self) {
        self.engine.vit_scores.clear();
        if !self.retain_facts {
            self.engine.last_attempt_facts = AttemptFacts::default();
        }
    }
}

/// Underlying tracked delivery validates intentional drain gaps. This adds
/// distinctness of analyzed acquisition windows, not sequence adjacency.
#[derive(Default)]
pub(super) struct PairWindows(Option<(irlume_camera::CaptureWindow, irlume_camera::CaptureWindow)>);

impl PairWindows {
    pub(super) fn advance(
        &mut self,
        rgb: irlume_camera::CaptureWindow,
        ir: irlume_camera::CaptureWindow,
    ) -> bool {
        let ordered = rgb.start <= rgb.end
            && ir.start <= ir.end
            && self.0.is_none_or(|(previous_rgb, previous_ir)| {
                rgb.start > previous_rgb.end && ir.start > previous_ir.end
            });
        if ordered {
            self.0 = Some((rgb, ir));
        }
        ordered
    }
}

fn transport_error(
    mode: &CaptureModeSelection,
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    reason: RuntimeDegradation,
    error: irlume_common::Error,
) -> CapturePathError {
    if matches!(
        error,
        irlume_common::Error::Preempted(_) | irlume_common::Error::DeadlineExpired
    ) {
        return CapturePathError::Other(error);
    }
    emit_capture_fallback(reason, diagnostics);
    if let Some(key) = mode.runtime_key.as_deref() {
        trip_runtime_capture_health(key, reason);
    }
    CapturePathError::ConcurrentPair(error)
}

/// One startup/rate boundary and one owned streaming scope per collection.
/// Dependencies are injectable so real owner and collector behavior can be
/// tested without opening cameras; a result cannot borrow either owner.
pub(super) fn with_managed_pair<R, I, T>(
    arm: impl FnOnce() -> Result<(R, I), CapturePathError>,
    establish: impl FnOnce(&mut R, &mut I) -> Result<(), CapturePathError>,
    collect: impl FnOnce(&mut R, &mut I) -> Result<T, CapturePathError>,
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
) -> Result<T, CapturePathError> {
    let pair = {
        let _timing = TraceStageTimer::new(
            diagnostics,
            irlume_common::diagnostics::TraceStage::StreamArm,
        );
        arm()?
    };
    with_owned_pair(pair, diagnostics, |rgb, ir| {
        {
            let _timing = TraceStageTimer::new(
                diagnostics,
                irlume_common::diagnostics::TraceStage::RateEstablishment,
            );
            establish(rgb, ir)?;
        }
        collect(rgb, ir)
    })
}

impl Engine {
    /// Only the ordinary Live + eligible RGB preparation can produce Pending.
    /// The callback includes capture, contract checks, and completed tail drains.
    /// Returning Ready never authorizes looking for a better identity sample.
    pub(super) fn collect_concurrent_pending_with(
        &mut self,
        deadline: Instant,
        mut next: impl FnMut(&mut Self) -> Result<PreparedPairAuthentication, CapturePathError>,
        mut now: impl FnMut() -> Instant,
    ) -> Result<PreparedPairAuthentication, CapturePathError> {
        let mut state = CollectionState::new(self);
        for sample in 0..VIT_PAD_VOTE_N {
            state.engine.check_request_active()?;
            if now() >= deadline {
                state.engine.last_attempt_situation = Some(AttemptSituation::TimedOut);
                return Err(irlume_common::Error::DeadlineExpired.into());
            }
            let prepared = next(state.engine)?;
            state.engine.check_request_cancelled()?;
            let expired = now() >= deadline
                || state
                    .engine
                    .authentication_deadline
                    .is_some_and(|end| Instant::now() >= end);
            if expired {
                // Like the outer retry loop, preserve an already completed
                // denial's accounting. Expiry permits no subsequent sample or
                // identity admission; transport errors never reach this branch.
                if matches!(&prepared, PreparedPairAuthentication::Refused(_)) {
                    state.retain_facts = true;
                    return Ok(prepared);
                }
                state.engine.last_attempt_situation = Some(AttemptSituation::TimedOut);
                return Err(irlume_common::Error::DeadlineExpired.into());
            }
            if sample + 1 == VIT_PAD_VOTE_N
                || !matches!(
                    &prepared,
                    PreparedPairAuthentication::Refused(Outcome {
                        kind: OutcomeKind::RgbPadPending,
                        ..
                    })
                )
            {
                state.retain_facts = true;
                return Ok(prepared);
            }
            state.engine.note_capture_boundary();
        }
        unreachable!("the bounded final sample always returns its prepared result")
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn authenticate_managed_concurrent_once(
        &mut self,
        enrollment: &irlume_core::storage::Enrollment,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        cameras: &(irlume_camera::RgbCamera, irlume_camera::IrCamera),
        mode: &CaptureModeSelection,
        deadline: Instant,
        held_pair_failed: &mut bool,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Outcome> {
        // This outer owner also covers setup, stream destruction and admission.
        let mut state = CollectionState::new(self);
        let result = state.engine.managed_concurrent_attempt(
            enrollment,
            purpose,
            service,
            cameras,
            mode,
            deadline,
            held_pair_failed,
            diagnostics,
        );
        state.retain_facts = result.is_ok();
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn managed_concurrent_attempt(
        &mut self,
        enrollment: &irlume_core::storage::Enrollment,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        cameras: &(irlume_camera::RgbCamera, irlume_camera::IrCamera),
        mode: &CaptureModeSelection,
        deadline: Instant,
        held_pair_failed: &mut bool,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Outcome> {
        let prepared = (|| {
            self.check_request_active()?;
            let control = self.capture_control();
            with_managed_pair(
                || {
                    arm_pair_transactionally(
                        || cameras.0.session_with_control(&control),
                        || cameras.1.session_for_pair_with_control(&control),
                    )
                    .map_err(|error| {
                        concurrent_setup_error(
                            Some(mode),
                            diagnostics,
                            RuntimeDegradation::PairArmFailure,
                            error,
                        )
                    })
                },
                |rgb, ir| {
                    irlume_camera::establish_pair_rate(rgb, ir).map_err(|error| {
                        concurrent_setup_error(
                            Some(mode),
                            diagnostics,
                            RuntimeDegradation::PairRateEstablishmentFailure,
                            error,
                        )
                    })
                },
                |rgb, ir| {
                    let mut windows = PairWindows::default();
                    let mut sample = 0;
                    self.collect_concurrent_pending_with(
                        deadline,
                        |engine| {
                            sample += 1;
                            let prepared = engine.prepare_managed_concurrent_sample(
                                rgb,
                                ir,
                                mode,
                                &mut windows,
                                diagnostics,
                            )?;
                            // The final selected refusal is emitted by admission below;
                            // intermediate Pending events describe continued evidence.
                            if sample < VIT_PAD_VOTE_N {
                                if let PreparedPairAuthentication::Refused(outcome) = &prepared {
                                    if outcome.kind == OutcomeKind::RgbPadPending {
                                        emit_authentication_refusal(diagnostics, outcome);
                                    }
                                }
                            }
                            Ok(prepared)
                        },
                        Instant::now,
                    )
                },
                diagnostics,
            )
        })();
        // The streaming owners and processing workers have finished before
        // cancellation/deadline admission checks or any identity comparison.
        self.check_request_cancelled()?;
        if matches!(&prepared, Ok(PreparedPairAuthentication::Ready(_))) {
            self.check_request_active()?;
        }
        self.finish_pair_authentication(
            enrollment,
            purpose,
            service,
            prepared,
            Some(held_pair_failed),
            diagnostics,
        )
    }

    fn prepare_managed_concurrent_sample(
        &mut self,
        rgb: &mut irlume_camera::RgbSession<'_>,
        ir: &mut irlume_camera::IrSession<'_>,
        mode: &CaptureModeSelection,
        windows: &mut PairWindows,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> Result<PreparedPairAuthentication, CapturePathError> {
        let (mut rgb_ms, mut ir_ms) = (0, 0);
        // No recovery within an evidence transaction: either side failing
        // invalidates both, and the existing outer fallback owns any reopen.
        let (rgb_result, ir_result) = irlume_camera::capture_pair_with(
            rgb,
            ir,
            |session| {
                let started = Instant::now();
                let frame = session.denoised();
                rgb_ms = started.elapsed().as_millis();
                frame
            },
            |session| {
                let started = Instant::now();
                let frame = session.capture_with_stats();
                ir_ms = started.elapsed().as_millis();
                frame
            },
        );
        self.check_request_active()?;
        // A simultaneous failure on the other stream cannot hide cancellation.
        let errors = [rgb_result.as_ref().err(), ir_result.as_ref().err()];
        if errors
            .iter()
            .flatten()
            .any(|error| matches!(error, irlume_common::Error::Preempted(_)))
        {
            return Err(irlume_common::Error::Preempted("camera capture cancelled".into()).into());
        }
        if errors
            .iter()
            .flatten()
            .any(|error| matches!(error, irlume_common::Error::DeadlineExpired))
        {
            return Err(irlume_common::Error::DeadlineExpired.into());
        }
        emit_trace_stage_ms(
            diagnostics,
            irlume_common::diagnostics::TraceStage::RgbCapture,
            rgb_ms,
        );
        emit_trace_stage_ms(
            diagnostics,
            irlume_common::diagnostics::TraceStage::IrCapture,
            ir_ms,
        );
        let capture_error = |error| {
            transport_error(
                mode,
                diagnostics,
                RuntimeDegradation::ConcurrentCaptureFailure,
                error,
            )
        };
        let rgb_frame = rgb_result.map_err(capture_error)?;
        let (ir_frame, ir_stats) = ir_result.map_err(capture_error)?;
        let contract = mode.runtime_contract.as_ref().ok_or_else(|| {
            transport_error(
                mode,
                diagnostics,
                RuntimeDegradation::MissingRuntimeContract,
                irlume_common::Error::Hardware("managed pair has no runtime contract".into()),
            )
        })?;
        let events = contract
            .diagnostic_trace_events(&rgb_frame, &ir_frame)
            .map_err(|violation| {
                transport_error(
                    mode,
                    diagnostics,
                    runtime_violation_degradation(violation),
                    irlume_common::Error::Hardware(
                        "managed pair failed its runtime contract".into(),
                    ),
                )
            })?;
        if !windows.advance(rgb_frame.captured, ir_frame.captured) {
            return Err(transport_error(
                mode,
                diagnostics,
                RuntimeDegradation::ContinuityLoss,
                irlume_common::Error::Hardware(
                    "managed pair acquisition windows did not advance".into(),
                ),
            ));
        }
        for event in events {
            diagnostics.emit_trace(event);
        }
        // Transport and inference Results deliberately remain nested. A failed
        // final drain discards prepared identity and the collection guard clears
        // any PAD vote mutated by this callback. Held ownership disables reopen.
        irlume_camera::process_pair_while_draining(rgb, ir, || {
            self.check_request_active()?;
            let detections = self.detect_rgb_assessment(&rgb_frame, Some(rgb_ms), diagnostics)?;
            let evidence = self.assess_captured_pair(
                rgb_frame,
                ir_frame,
                ir_stats,
                detections,
                PairAssessmentContext {
                    sequential: false,
                    pair_sequential_retried: false,
                    rgb_hard_retried: false,
                    held_sessions: true,
                    ir_ms: Some(ir_ms),
                    diagnostics,
                },
            )?;
            self.prepare_pair_authentication_with(evidence, |engine, evidence| {
                engine.materialize_pair_identity(evidence, diagnostics)
            })
            .map_err(CapturePathError::from)
        })
        .map_err(capture_error)?
    }
}
