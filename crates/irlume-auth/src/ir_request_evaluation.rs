// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Whole-request IR measurements. Reports never authorize access or release secrets.

use super::ir_only_evaluation::IdentityAcceptance;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

pub(super) type SharedContext = Arc<Mutex<Context>>;
#[cfg(test)]
pub(super) type TestAssessor = dyn FnMut(
        &irlume_camera::CaptureControl,
        Option<std::time::Instant>,
    ) -> super::ir_assessment::AssessmentRun
    + Send;

#[derive(Default)]
pub(super) struct Context {
    observation: Observation,
    pin: Option<Arc<irlume_core::read_only::AccountStatePin>>,
    refusal: Option<RefusalCause>,
}

/// A mutable Engine borrow keeps the diagnostic context request-local, including unwind.
pub(super) struct Scope<'a> {
    pub(super) engine: &'a mut super::Engine,
}

impl<'a> Scope<'a> {
    pub(super) fn enter(engine: &'a mut super::Engine, context: SharedContext) -> Option<Self> {
        if engine.request_evaluation.is_some() || engine.camera_selection.is_some() {
            return None;
        }
        engine.request_evaluation = Some(context);
        Some(Self { engine })
    }
}

impl Drop for Scope<'_> {
    fn drop(&mut self) {
        self.engine.request_evaluation = None;
    }
}

impl RefusalCause {
    fn from_read(error: irlume_core::read_only::ReadError) -> Self {
        use irlume_core::read_only::ReadError;
        match error {
            ReadError::Unavailable => Self::StateUnavailable,
            ReadError::PendingRepair => Self::StateRequiresRepair,
            ReadError::Changed => Self::StateChanged,
        }
    }

    fn from_error(error: &irlume_common::Error) -> Self {
        match error {
            irlume_common::Error::DeadlineExpired => Self::DeadlineExpired,
            irlume_common::Error::Preempted(_) => Self::Cancelled,
            irlume_common::Error::Policy(_) => Self::Policy,
            _ => Self::RuntimeUnavailable,
        }
    }
}

pub(super) fn load(
    context: &SharedContext,
    user: &str,
) -> irlume_common::Result<Option<irlume_core::storage::PrimarySnapshot>> {
    let started = std::time::Instant::now();
    let loaded = (|| {
        let view = irlume_core::read_only::AccountView::open(user)?;
        let primary = view.load_primary()?;
        let pin = view.finish()?;
        Ok::<_, irlume_core::read_only::ReadError>((primary, pin))
    })();
    let mut context = context.lock().unwrap_or_else(|p| p.into_inner());
    context.observation.add_time(
        0,
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    );
    match loaded {
        Ok((primary, pin)) => {
            context.pin = Some(Arc::new(pin));
            Ok(primary)
        }
        Err(error) => {
            context.refusal = Some(RefusalCause::from_read(error));
            Err(irlume_common::Error::Policy(
                "read-only account state refused".into(),
            ))
        }
    }
}

impl super::Engine {
    pub(super) fn observe_evaluation_scope(&self, scope: irlume_common::IrScope) {
        if let Some(context) = &self.request_evaluation {
            context
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .observation
                .scope = Some(scope);
        }
    }

    pub(super) fn evaluation_read_error(&self, error: irlume_core::read_only::ReadError) {
        if let Some(context) = &self.request_evaluation {
            context.lock().unwrap_or_else(|p| p.into_inner()).refusal =
                Some(RefusalCause::from_read(error));
        }
    }

    pub(super) fn evaluation_view(
        &self,
    ) -> Result<irlume_core::read_only::AccountView, irlume_core::read_only::ReadError> {
        let pin = self
            .request_evaluation
            .as_ref()
            .and_then(|c| c.lock().unwrap_or_else(|p| p.into_inner()).pin.clone())
            .ok_or(irlume_core::read_only::ReadError::Unavailable)?;
        pin.reopen()
    }

    pub(super) fn observe_ir_request(
        &self,
        run: &super::ir_assessment::AssessmentRun,
        profiles: usize,
        adapter: bool,
    ) {
        if let Some(context) = &self.request_evaluation {
            let acceptance = run.result.as_ref().ok().and_then(|assessment| {
                let verdict =
                    super::identity_arms::dark_verdict(&assessment.matched, profiles, adapter);
                match (verdict.best, verdict.centroid) {
                    (true, true) => Some(IdentityAcceptance::Both),
                    (true, false) => Some(IdentityAcceptance::BestTemplate),
                    (false, true) => Some(IdentityAcceptance::Centroid),
                    (false, false) => None,
                }
            });
            context
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .observation
                .observe(
                    [
                        run.capture_ms,
                        run.detection_ms,
                        run.pad_ms,
                        run.identity_ms,
                    ],
                    acceptance,
                );
        }
    }

    pub(super) fn validate_evaluation_request(
        &self,
        policy: irlume_common::config::FaceSensorPolicy,
    ) -> irlume_common::Result<()> {
        if self.request_evaluation.is_some()
            && (policy != irlume_common::config::FaceSensorPolicy::IrOnlyExperimental
                || self.camera_selection.as_ref().is_none_or(|selection| {
                    selection.automatic() || selection.pending_pin().is_some()
                }))
        {
            return Err(irlume_common::Error::Policy(
                "request evaluation requires an explicit ordinary IR target".into(),
            ));
        }
        Ok(())
    }

    /// Measure a production IR verification request without returning authentication authority.
    /// Model initialization is outside the window. The caller must provide the same
    /// privacy controls and attended supervision as the developer executable.
    #[must_use]
    pub fn evaluate_ir_request(&mut self, user: &str, service: &str, phase: Phase) -> Report {
        use irlume_common::{
            config::FaceSensorPolicy,
            pam_service::{self, ServiceKind},
        };
        let started = std::time::Instant::now();
        if !matches!(
            pam_service::classify(service),
            Some(ServiceKind::Greeter | ServiceKind::ScreenUnlock)
        ) {
            return Report::refused(phase, RefusalCause::InvalidRequest);
        }
        let policy = match irlume_common::config::observe_face_sensor_policy().resolve() {
            Ok(FaceSensorPolicy::IrOnlyExperimental) => FaceSensorPolicy::IrOnlyExperimental,
            _ => return Report::refused(phase, RefusalCause::Policy),
        };
        let selected = irlume_common::split_publish::read_camera_selection();
        if !matches!(
            selected.observation().selection,
            irlume_common::config::CameraSelectionObservation::Pinned { .. }
        ) || !matches!(
            selected.split(),
            irlume_common::split_publish::SplitReadState::Absent
        ) || irlume_core::policy::method().face_disabled()
        {
            return Report::refused(phase, RefusalCause::Policy);
        }
        let window = self.authentication_window_from(
            started,
            Some(service),
            super::AuthenticationPurpose::Verify,
            policy,
        );
        if window.milliseconds == 0 || window.milliseconds > MAX_MEASURED_MS {
            return Report::refused(phase, RefusalCause::InvalidRequest);
        }
        let context = Arc::new(Mutex::new(Context::default()));
        let Some(scope) = Scope::enter(self, context.clone()) else {
            return Report::refused(phase, RefusalCause::InvalidRequest);
        };
        let settled = match phase {
            Phase::Evaluation => match scope.engine.authenticate_for_in_window(
                user,
                Some(service),
                super::AuthenticationPurpose::Verify,
                window,
                &(),
            ) {
                Ok(outcome) if outcome.granted => Settled::WouldGrant,
                Ok(outcome) => Settled::Refused(match outcome.kind {
                    super::OutcomeKind::NoFace => RefusalCause::NoFace,
                    super::OutcomeKind::BelowThreshold => RefusalCause::IdentityMismatch,
                    super::OutcomeKind::Spoof
                    | super::OutcomeKind::SpoofNoIrFace
                    | super::OutcomeKind::Uncertain
                    | super::OutcomeKind::RgbPadPending => RefusalCause::LivenessRefused,
                    super::OutcomeKind::SetupUnavailable => RefusalCause::SetupUnavailable,
                    super::OutcomeKind::DeadlineExpired => RefusalCause::DeadlineExpired,
                    super::OutcomeKind::OtherDeny => match outcome.cause {
                        Some(
                            irlume_common::OutcomeCause::CameraUnavailable
                            | irlume_common::OutcomeCause::PrivacyShutter,
                        ) => RefusalCause::CameraUnavailable,
                        Some(irlume_common::OutcomeCause::LivenessRefused) => {
                            RefusalCause::LivenessRefused
                        }
                        _ => RefusalCause::Policy,
                    },
                    super::OutcomeKind::RuntimeUnavailable | super::OutcomeKind::Granted => {
                        RefusalCause::RuntimeUnavailable
                    }
                }),
                Err(error) => Settled::Refused(RefusalCause::from_error(&error)),
            },
            Phase::Preflight => {
                let preflight = scope.engine.ir_only_preflight_details(user);
                context
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .observation
                    .scope = preflight.scope;
                if preflight.readiness
                    == irlume_common::IrOnlyReadiness::ReadyForExperimentalAttempt
                {
                    match scope
                        .engine
                        .evaluation_view()
                        .and_then(|view| view.finish())
                    {
                        Ok(_) => Settled::Ready,
                        Err(error) => {
                            scope.engine.evaluation_read_error(error);
                            Settled::Refused(RefusalCause::from_read(error))
                        }
                    }
                } else {
                    Settled::Refused(RefusalCause::SetupUnavailable)
                }
            }
        };
        let settled = context
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .refusal
            .map(Settled::Refused)
            .unwrap_or(settled);
        let settled = finish_after_revalidation(
            settled,
            || selected == irlume_common::split_publish::read_camera_selection(),
            || scope.engine.check_authentication_completion(window),
        );
        drop(scope);
        let mut context = context.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut context.observation).report(
            phase,
            window.milliseconds,
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            settled,
        )
    }
}

const MAX_MEASURED_MS: u64 = 120_000;
const MAX_COUNT: u32 = 1_000_000;

/// Preflight cannot supply evidence that a verification request would grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Preflight,
    Evaluation,
}

/// Closed precondition and engine refusal vocabulary. No free-form error is exported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalCause {
    InvalidRequest,
    RootRequired,
    ModelsUnavailable,
    StateUnavailable,
    StateRequiresRepair,
    StateChanged,
    NoFace,
    LivenessRefused,
    IdentityMismatch,
    CameraUnavailable,
    SetupUnavailable,
    Policy,
    Cancelled,
    DeadlineExpired,
    RuntimeUnavailable,
}

impl RefusalCause {
    fn label(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::RootRequired => "root_required",
            Self::ModelsUnavailable => "models_unavailable",
            Self::StateUnavailable => "state_unavailable",
            Self::StateRequiresRepair => "state_requires_repair",
            Self::StateChanged => "state_changed",
            Self::NoFace => "no_face",
            Self::LivenessRefused => "liveness_refused",
            Self::IdentityMismatch => "identity_mismatch",
            Self::CameraUnavailable => "camera_unavailable",
            Self::SetupUnavailable => "setup_unavailable",
            Self::Policy => "policy",
            Self::Cancelled => "cancelled",
            Self::DeadlineExpired => "deadline_expired",
            Self::RuntimeUnavailable => "runtime_unavailable",
        }
    }
}

enum Settled {
    Ready,
    WouldGrant,
    Refused(RefusalCause),
}

fn finish_after_revalidation(
    settled: Settled,
    revalidate: impl FnOnce() -> bool,
    completion: impl FnOnce() -> irlume_common::Result<()>,
) -> Settled {
    let unchanged = revalidate();
    // Revalidation itself may block. Settle cancellation and time only after it.
    let complete = completion();
    match complete {
        Err(error) => Settled::Refused(RefusalCause::from_error(&error)),
        Ok(()) if !unchanged => Settled::Refused(RefusalCause::Policy),
        Ok(()) => settled,
    }
}
enum ResultKind {
    Ready,
    WouldGrant(IdentityAcceptance),
    Refused(RefusalCause),
    Incomplete(MeasurementFailure),
}

#[derive(Clone, Copy)]
enum MeasurementFailure {
    MissingEvidence,
    Overflow,
}

/// Metadata-only report. Success variants can only be constructed by this evaluator.
pub struct Report {
    phase: Phase,
    result: ResultKind,
    scope: Option<irlume_common::IrScope>,
    window_ms: u64,
    elapsed_ms: u64,
    initialization_ms: Option<u64>,
    counts: [u32; 5],
    timings: [Option<u64>; 5],
}

impl Report {
    /// Record model initialization and its camera-free prerequisites separately.
    #[must_use]
    pub fn with_initialization_time(mut self, elapsed: std::time::Duration) -> Self {
        let milliseconds = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        self.initialization_ms = Some(milliseconds.min(MAX_MEASURED_MS));
        if milliseconds > MAX_MEASURED_MS {
            self.result = ResultKind::Incomplete(MeasurementFailure::Overflow);
        }
        self
    }
    /// A refusal before entering the engine (for example, invalid CLI input).
    #[must_use]
    pub fn refused(phase: Phase, cause: RefusalCause) -> Self {
        Observation::default().report(phase, 0, 0, Settled::Refused(cause))
    }

    /// Serialize only fixed keys and categorical metadata; never an engine `Outcome`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let result = match self.result {
            ResultKind::Ready => json!({"kind":"ready"}),
            ResultKind::WouldGrant(acceptance) => {
                json!({"kind":"would_grant", "identity_acceptance": match acceptance {
                    IdentityAcceptance::BestTemplate => "best_template", IdentityAcceptance::Centroid => "centroid", IdentityAcceptance::Both => "both",
                }})
            }
            ResultKind::Refused(cause) => json!({"kind":"refused", "cause":cause.label()}),
            ResultKind::Incomplete(cause) => json!({"kind":"incomplete", "cause":match cause {
                MeasurementFailure::MissingEvidence => "missing_evidence", MeasurementFailure::Overflow => "measurement_overflow",
            }}),
        };
        json!({"schema":1, "operation":"ir_request_evaluation", "authentication_granted":false,
            "phase": match self.phase { Phase::Preflight => "preflight", Phase::Evaluation => "evaluation" },
            "result":result, "scope":self.scope.and_then(|s| match s { irlume_common::IrScope::Primary => Some("primary"), irlume_common::IrScope::Secondary => Some("secondary"), irlume_common::IrScope::Unknown => None }),
            "window_ms":self.window_ms, "elapsed_ms":self.elapsed_ms, "initialization_ms":self.initialization_ms,
            "counts":{"assessments":self.counts[0],"captures":self.counts[1],"detections":self.counts[2],"pad":self.counts[3],"identity":self.counts[4]},
            "timings_ms":{"load":self.timings[0],"capture":self.timings[1],"detection":self.timings[2],"pad":self.timings[3],"identity":self.timings[4]}})
    }
}

#[derive(Default)]
struct Observation {
    counts: [u32; 5],
    timings: [Option<u64>; 5],
    acceptance: Option<IdentityAcceptance>,
    scope: Option<irlume_common::IrScope>,
    overflow: bool,
}

impl Observation {
    fn observe(&mut self, stages: [Option<u64>; 4], acceptance: Option<IdentityAcceptance>) {
        self.acceptance = acceptance;
        self.increment(0);
        for (index, elapsed) in stages.into_iter().enumerate() {
            if let Some(elapsed) = elapsed {
                self.increment(index + 1);
                self.add_time(index + 1, elapsed);
            }
        }
    }

    fn increment(&mut self, index: usize) {
        if self.counts[index] < MAX_COUNT {
            self.counts[index] += 1;
        } else {
            self.overflow = true;
        }
    }

    fn add_time(&mut self, index: usize, elapsed: u64) {
        match self.timings[index].unwrap_or(0).checked_add(elapsed) {
            Some(sum) if sum <= MAX_MEASURED_MS => self.timings[index] = Some(sum),
            _ => self.overflow = true,
        }
    }

    fn report(self, phase: Phase, window_ms: u64, elapsed_ms: u64, settled: Settled) -> Report {
        let result = if self.overflow || window_ms > MAX_MEASURED_MS || elapsed_ms > MAX_MEASURED_MS
        {
            ResultKind::Incomplete(MeasurementFailure::Overflow)
        } else {
            match (phase, settled) {
                (Phase::Preflight, Settled::Ready)
                    if self.counts == [0; 5]
                        && matches!(
                            self.scope,
                            Some(
                                irlume_common::IrScope::Primary | irlume_common::IrScope::Secondary
                            )
                        ) =>
                {
                    ResultKind::Ready
                }
                (Phase::Evaluation, Settled::WouldGrant)
                    if self.counts[4] > 0
                        && matches!(
                            self.scope,
                            Some(
                                irlume_common::IrScope::Primary | irlume_common::IrScope::Secondary
                            )
                        ) =>
                {
                    match self.acceptance {
                        Some(acceptance) => ResultKind::WouldGrant(acceptance),
                        None => ResultKind::Incomplete(MeasurementFailure::MissingEvidence),
                    }
                }
                (_, Settled::Refused(cause)) => ResultKind::Refused(cause),
                _ => ResultKind::Incomplete(MeasurementFailure::MissingEvidence),
            }
        };
        Report {
            phase,
            result,
            scope: self.scope,
            window_ms: window_ms.min(MAX_MEASURED_MS),
            elapsed_ms: elapsed_ms.min(MAX_MEASURED_MS),
            initialization_ms: None,
            counts: self.counts,
            timings: self.timings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_finalization_rechecks_cancellation_after_configuration_read() {
        let cancelled = std::cell::Cell::new(false);
        let result = finish_after_revalidation(
            Settled::WouldGrant,
            || {
                cancelled.set(true);
                true
            },
            || {
                if cancelled.get() {
                    Err(irlume_common::Error::Preempted("synthetic".into()))
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(result, Settled::Refused(RefusalCause::Cancelled)));
    }

    #[test]
    fn request_finalization_rechecks_expiry_after_configuration_read() {
        let now = std::cell::Cell::new(0);
        let result = finish_after_revalidation(
            Settled::WouldGrant,
            || {
                now.set(100);
                true
            },
            || {
                if now.get() >= 100 {
                    Err(irlume_common::Error::DeadlineExpired)
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(
            result,
            Settled::Refused(RefusalCause::DeadlineExpired)
        ));
    }

    #[test]
    fn request_report_erases_candidate_after_final_refusal() {
        let mut observation = Observation::default();
        observation.observe(
            [Some(12), Some(2), Some(1), Some(4)],
            Some(IdentityAcceptance::Both),
        );
        let report = observation.report(
            Phase::Evaluation,
            15000,
            25,
            Settled::Refused(RefusalCause::StateChanged),
        );
        let json = report.to_json();
        assert_eq!(json["authentication_granted"], false);
        assert_eq!(
            json["result"],
            serde_json::json!({"kind":"refused", "cause":"state_changed"})
        );
        assert_eq!(json["counts"]["assessments"], 1);
        assert!(!json.to_string().contains("both"));
    }

    #[test]
    fn request_report_counts_all_rounds_and_keeps_absent_stages_null() {
        let mut observation = Observation {
            scope: Some(irlume_common::IrScope::Primary),
            ..Observation::default()
        };
        observation.observe([Some(10), None, None, None], None);
        observation.observe(
            [Some(20), Some(3), Some(2), Some(5)],
            Some(IdentityAcceptance::Centroid),
        );
        let report = observation.report(Phase::Evaluation, 15000, 45, Settled::WouldGrant);
        let json = report.to_json();
        assert_eq!(
            json["counts"],
            serde_json::json!({"assessments":2,"captures":2,"detections":1,"pad":1,"identity":1})
        );
        assert_eq!(
            json["timings_ms"],
            serde_json::json!({"load":null,"capture":30,"detection":3,"pad":2,"identity":5})
        );
        assert_eq!(
            json["result"],
            serde_json::json!({"kind":"would_grant","identity_acceptance":"centroid"})
        );
        assert!(json.to_string().len() < 16384);
    }

    #[test]
    fn request_report_refuses_inconsistent_or_overflowed_success() {
        let json = Observation::default()
            .report(Phase::Evaluation, 15000, 0, Settled::WouldGrant)
            .to_json();
        assert_eq!(json["result"]["kind"], "incomplete");
        let mut observation = Observation::default();
        observation.observe(
            [Some(u64::MAX), Some(0), Some(0), Some(0)],
            Some(IdentityAcceptance::Both),
        );
        let json = observation
            .report(Phase::Evaluation, 15000, 1, Settled::WouldGrant)
            .to_json();
        assert_eq!(
            json["result"],
            serde_json::json!({"kind":"incomplete","cause":"measurement_overflow"})
        );
        assert_eq!(json["authentication_granted"], false);
    }

    #[test]
    fn request_report_never_confuses_preflight_and_evaluation() {
        let ready = Observation {
            scope: Some(irlume_common::IrScope::Primary),
            ..Observation::default()
        };
        assert_eq!(
            ready
                .report(Phase::Preflight, 15000, 0, Settled::Ready)
                .to_json()["result"]["kind"],
            "ready"
        );
        for (phase, result) in [
            (Phase::Evaluation, Settled::Ready),
            (Phase::Preflight, Settled::WouldGrant),
        ] {
            let json = Observation::default()
                .report(phase, 15000, 0, result)
                .to_json();
            assert_eq!(json["result"]["kind"], "incomplete");
        }
    }

    #[test]
    fn request_report_requires_resolved_scope_for_success() {
        for scope in [None, Some(irlume_common::IrScope::Unknown)] {
            let mut observation = Observation {
                scope,
                ..Observation::default()
            };
            observation.observe([Some(1); 4], Some(IdentityAcceptance::Both));
            assert_eq!(
                observation
                    .report(Phase::Evaluation, 15000, 4, Settled::WouldGrant)
                    .to_json()["result"]["kind"],
                "incomplete"
            );
            let observation = Observation {
                scope,
                ..Observation::default()
            };
            assert_eq!(
                observation
                    .report(Phase::Preflight, 15000, 0, Settled::Ready)
                    .to_json()["result"]["kind"],
                "incomplete"
            );
        }
    }
}
