// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Experimental IR evidence evaluation, isolated from authentication policy.
//! A candidate is never authentication and must not be used to release credentials.

use super::ir_assessment::{self, AssessmentStages, DetectedIr, IrFailure, IrInference};
use super::*;
use irlume_camera::CaptureControl;
use irlume_core::storage::Enrollment;
use std::time::{Duration, Instant};

/// Bounded diagnostic categories; none authorizes any action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    CandidateMatch,
    IdentityMismatch,
    NoFace,
    LivenessRefused,
    PadUnavailable,
    PadInvalid,
    PadRefused,
    IncompatibleEnrollment,
    InvalidFrame,
    InferenceFailed,
    CameraUnavailable,
    CameraBusy,
    CameraRateRefused,
    CameraLeaseTimeout,
    CameraLeaseRefused,
    CameraIoFailed,
    CameraHardwareFailed,
    CameraRateFillFailed(irlume_camera::RateFillFailure),
    CameraAuthorizationRefused,
    CameraPolicyRefused,
    CameraCaptureFailed,

    Cancelled,
    DeadlineExpired,
    InvalidRequest,
    Ready,
    EnrollmentUnavailable,
    ModelsUnavailable,
    RootRequired,
}

impl Category {
    fn with_rate_fill_failure(self, failure: Option<irlume_camera::RateFillFailure>) -> Self {
        match (self, failure) {
            (Self::CameraHardwareFailed, Some(failure)) => Self::CameraRateFillFailed(failure),
            _ => self,
        }
    }

    /// Stable metadata-only wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CandidateMatch => "candidate_match",
            Self::IdentityMismatch => "identity_mismatch",
            Self::NoFace => "no_face",
            Self::LivenessRefused => "liveness_refused",
            Self::PadUnavailable => "pad_unavailable",
            Self::PadInvalid => "pad_invalid",
            Self::PadRefused => "pad_refused",
            Self::IncompatibleEnrollment => "incompatible_enrollment",
            Self::InvalidFrame => "invalid_frame",
            Self::InferenceFailed => "inference_failed",
            Self::CameraUnavailable => "camera_unavailable",
            Self::CameraBusy => "camera_busy",
            Self::CameraRateRefused => "camera_rate_refused",
            Self::CameraLeaseTimeout => "camera_lease_timeout",
            Self::CameraLeaseRefused => "camera_lease_refused",
            Self::CameraIoFailed => "camera_io_failed",
            Self::CameraHardwareFailed => "camera_hardware_failed",
            Self::CameraRateFillFailed(failure) => failure.as_str(),
            Self::CameraAuthorizationRefused => "camera_authorization_refused",
            Self::CameraPolicyRefused => "camera_policy_refused",
            Self::CameraCaptureFailed => "camera_capture_failed",

            Self::Cancelled => "cancelled",
            Self::DeadlineExpired => "deadline_expired",
            Self::InvalidRequest => "invalid_request",
            Self::Ready => "ready",
            Self::EnrollmentUnavailable => "enrollment_unavailable",
            Self::ModelsUnavailable => "models_unavailable",
            Self::RootRequired => "root_required",
        }
    }
}

/// Bounded evidence identifying which existing identity predicate accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityAcceptance {
    BestTemplate,
    Centroid,
    Both,
}

impl IdentityAcceptance {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BestTemplate => "best_template",
            Self::Centroid => "centroid",
            Self::Both => "both",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdentityResult {
    category: Category,
    acceptance: Option<IdentityAcceptance>,
}

/// Only category and elapsed times, never names, images, embeddings or scores.
#[derive(Debug)]
pub struct Report {
    pub category: Category,
    pub identity_acceptance: Option<IdentityAcceptance>,
    pub elapsed_ms: u64,
    pub capture_ms: Option<u64>,
    pub detection_ms: Option<u64>,
    pub pad_ms: Option<u64>,
    pub identity_ms: Option<u64>,
    pub capture_stages_ms: std::collections::BTreeMap<&'static str, Option<u64>>,
}

impl Report {
    /// Construct a report for a pre-capture refusal or preflight result.
    pub fn new(category: Category) -> Self {
        Self {
            category,
            identity_acceptance: None,
            elapsed_ms: 0,
            capture_ms: None,
            detection_ms: None,
            pad_ms: None,
            identity_ms: None,
            capture_stages_ms: irlume_camera::CaptureTimings::default().snapshot(),
        }
    }

    /// Serialize the fixed, non-granting diagnostic record.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "schema": 4, "operation": "ir_only_evaluation",
            "authentication_granted": false, "category": self.category.as_str(),
            "identity_acceptance": self.identity_acceptance.map(IdentityAcceptance::as_str),
            "elapsed_ms": self.elapsed_ms, "capture_ms": self.capture_ms,
            "detection_ms": self.detection_ms, "pad_ms": self.pad_ms, "identity_ms": self.identity_ms,
            "capture_stages_ms": self.capture_stages_ms })
    }
}

/// Accept a finite, bounded cooperative camera/inference budget.
#[must_use]
pub fn valid_budget(budget: Duration) -> bool {
    (Duration::from_millis(100)..=Duration::from_secs(30)).contains(&budget)
}

impl From<IrFailure> for Category {
    fn from(failure: IrFailure) -> Self {
        match failure {
            IrFailure::NoFace => Self::NoFace,
            IrFailure::LivenessRefused => Self::LivenessRefused,
            IrFailure::PadUnavailable => Self::PadUnavailable,
            IrFailure::PadInvalid => Self::PadInvalid,
            IrFailure::PadRefused => Self::PadRefused,
            IrFailure::IncompatibleEnrollment => Self::IncompatibleEnrollment,
            IrFailure::InvalidFrame => Self::InvalidFrame,
            IrFailure::InferenceFailed => Self::InferenceFailed,
            IrFailure::CameraUnavailable => Self::CameraUnavailable,
            IrFailure::CameraBusy => Self::CameraBusy,
            IrFailure::CameraRateRefused => Self::CameraRateRefused,
            IrFailure::CameraLeaseTimeout => Self::CameraLeaseTimeout,
            IrFailure::CameraLeaseRefused => Self::CameraLeaseRefused,
            IrFailure::CameraIoFailed => Self::CameraIoFailed,
            IrFailure::CameraHardwareFailed => Self::CameraHardwareFailed,
            IrFailure::CameraAuthorizationRefused => Self::CameraAuthorizationRefused,
            IrFailure::CameraPolicyRefused => Self::CameraPolicyRefused,
            IrFailure::CameraCaptureFailed => Self::CameraCaptureFailed,
            IrFailure::Cancelled => Self::Cancelled,
            IrFailure::DeadlineExpired => Self::DeadlineExpired,
            IrFailure::InvalidRequest => Self::InvalidRequest,
        }
    }
}

#[cfg(test)]
fn active(control: &CaptureControl, deadline: Instant) -> Result<(), Category> {
    ir_assessment::active(control, Some(deadline)).map_err(Into::into)
}

#[cfg(test)]
fn error_category(error: irlume_common::Error) -> Category {
    ir_assessment::error_failure(error).into()
}

#[cfg(test)]
fn lease_error_category(error: lease::CameraLeaseError) -> Category {
    ir_assessment::lease_error_failure(error).into()
}

fn capture_selected_ir<T>(
    endpoint: &str,
    control: &CaptureControl,
    deadline: Instant,
    capture: impl FnOnce(&str, &CaptureControl) -> Result<T, IrFailure>,
) -> Result<T, IrFailure> {
    ir_assessment::active(control, Some(deadline))?;
    // Preserve the caller's cancellation AND any earlier deadline while adding
    // our mandatory local budget. Original check classifies expiry accurately
    // after the driver returns, even though the callback is a boolean signal.
    let original = control.clone();
    let bounded = CaptureControl::new(
        irlume_camera::no_progress(),
        std::sync::Arc::new(move || original.check().is_err()),
    )
    .with_deadline(Some(deadline))
    .with_capture_timings(control.capture_timings());
    let captured = capture(endpoint, &bounded);
    ir_assessment::active(control, Some(deadline))?;
    captured
}

#[cfg(test)]
use ir_assessment::valid_frame_shape;

#[cfg(test)]
fn gate_policy(
    signals: &Signals,
    pad: Option<irlume_common::Result<f32>>,
    enr: &Enrollment,
) -> Result<(), Category> {
    ir_assessment::gate_policy(signals, pad, enr).map_err(Into::into)
}

fn identity_category(matched: IrMatch, profiles: usize, adapter: bool) -> IdentityResult {
    if matched.n_templates == 0 {
        return IdentityResult {
            category: Category::IncompatibleEnrollment,
            acceptance: None,
        };
    }
    let (best, centroid) =
        ir_assessment::IdentityThresholds::new(matched.n_templates, profiles, adapter)
            .arms(&matched);
    let acceptance = match (best, centroid) {
        (true, true) => Some(IdentityAcceptance::Both),
        (true, false) => Some(IdentityAcceptance::BestTemplate),
        (false, true) => Some(IdentityAcceptance::Centroid),
        (false, false) => None,
    };
    IdentityResult {
        category: if acceptance.is_some() {
            Category::CandidateMatch
        } else {
            Category::IdentityMismatch
        },
        acceptance,
    }
}

fn evaluate_stages(
    stages: &mut impl AssessmentStages,
    control: &CaptureControl,
    budget: Duration,
    profiles: usize,
    adapter: bool,
) -> Report {
    if !valid_budget(budget) {
        return Report::new(Category::InvalidRequest);
    }
    let start = Instant::now();
    let run = ir_assessment::assess_stages(stages, control, Some(start + budget));
    let identity = run
        .result
        .map(|assessment| identity_category(assessment.matched, profiles, adapter));
    let identity = ir_assessment::active(control, Some(start + budget)).and(identity);
    let (category, identity_acceptance) = match identity {
        Ok(identity) => (identity.category, identity.acceptance),
        Err(failure) => (
            Category::from(failure).with_rate_fill_failure(run.rate_fill_failure),
            None,
        ),
    };
    Report {
        category,
        identity_acceptance,
        elapsed_ms: run.elapsed_ms,
        capture_ms: run.capture_ms,
        detection_ms: run.detection_ms,
        pad_ms: run.pad_ms,
        identity_ms: run.identity_ms,
        capture_stages_ms: run.capture_stages_ms,
    }
}

impl Engine {
    /// Camera-free readiness check. Does not probe, capture or change enrollment.
    /// Models and protected enrollment must already have been loaded by the caller.
    pub fn ir_only_evaluation_preflight(&self, enr: &Enrollment) -> Category {
        self.evaluation_target(enr)
            .map_or_else(Into::into, |_| Category::Ready)
    }

    fn evaluation_target(
        &self,
        enr: &Enrollment,
    ) -> Result<irlume_camera::IrCaptureTarget, IrFailure> {
        let target =
            irlume_camera::configured_ir_target().map_err(|_| IrFailure::CameraUnavailable)?;
        let selected =
            std::fs::canonicalize(&self.ir_dev).map_err(|_| IrFailure::CameraUnavailable)?;
        if selected != std::path::Path::new(target.endpoint()) {
            return Err(IrFailure::CameraUnavailable);
        }
        self.evaluation_preflight(enr)?;
        Ok(target)
    }

    fn evaluation_preflight(&self, enr: &Enrollment) -> Result<(), IrFailure> {
        if irlume_common::dbglog::on() {
            return Err(IrFailure::InvalidRequest);
        }
        if !self.ir_available || self.ir_dev == self.rgb_dev {
            return Err(IrFailure::CameraUnavailable);
        }
        if enr
            .camera_binding
            .as_ref()
            .and_then(|b| b.ir.as_ref())
            .is_some_and(|want| irlume_camera::device_identity(&self.ir_dev).as_ref() != Some(want))
        {
            return Err(IrFailure::CameraUnavailable);
        }
        if !self.has_pad_ir() {
            return Err(IrFailure::PadUnavailable);
        }
        if self.ir_match(enr, &[0.0; EMBED_DIM]).n_templates == 0 {
            return Err(IrFailure::IncompatibleEnrollment);
        }
        Ok(())
    }

    /// Evaluate one IR-only presentation. Never calls authentication, PAM, grants,
    /// credential release, dual-camera assessment, or a production scene gate.
    ///
    /// `budget` must be 100ms..=30s. Cancellation/deadline checks surround capture
    /// and every inference stage, including final reporting. Driver/model calls
    /// are cooperative: a blocked call may return after the nominal deadline.
    /// Capture uses the configured, sysfs-validated IR image and exact metadata
    /// companion with a Diagnostics lease and pinned, authorized emitter path.
    /// Unsupported or changed topology refuses without fallback discovery.
    /// No retry or explicit RGB capture occurs in this operation.
    pub fn evaluate_ir_only(
        &mut self,
        enr: &Enrollment,
        control: &CaptureControl,
        budget: Duration,
    ) -> Report {
        let adapter = self.ir_adapter.is_some();
        evaluate_stages(
            &mut IrStages {
                inference: IrInference {
                    engine: self,
                    enrollment: enr,
                },
                target: None,
            },
            control,
            budget,
            enr.profiles.len(),
            adapter,
        )
    }
}

struct IrStages<'a> {
    inference: IrInference<'a>,
    target: Option<irlume_camera::IrCaptureTarget>,
}

impl AssessmentStages for IrStages<'_> {
    type Captured = (irlume_camera::Frame, irlume_camera::IrCaptureStats);
    type Detected = DetectedIr;
    type Aligned = Vec<u8>;
    type Embedded = Vec<f32>;
    fn preflight(&mut self) -> Result<(), IrFailure> {
        self.target = Some(
            self.inference
                .engine
                .evaluation_target(self.inference.enrollment)?,
        );
        Ok(())
    }
    fn capture(
        &mut self,
        control: &CaptureControl,
        deadline: Option<Instant>,
    ) -> Result<Self::Captured, IrFailure> {
        let deadline = deadline.ok_or(IrFailure::InvalidRequest)?;
        let target = self.target.as_ref().ok_or(IrFailure::InvalidRequest)?;
        capture_selected_ir(target.endpoint(), control, deadline, |_, bounded| {
            let timeout = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100));
            let operation = lease::acquire_camera_operation(
                &target.lease_endpoints(),
                lease::CameraOperationKind::Diagnostics,
                timeout,
            )
            .map_err(ir_assessment::lease_error_failure)?;
            bounded.check().map_err(ir_assessment::error_failure)?;
            target
                .capture_with_stats_and_control(&operation, bounded)
                .map_err(ir_assessment::error_failure)
        })
    }

    fn detect(&mut self, captured: Self::Captured) -> Result<DetectedIr, IrFailure> {
        self.inference.detect(captured)
    }
    fn signals(&self, detected: &DetectedIr) -> Signals {
        detected.signals()
    }
    fn pad(&mut self, detected: &DetectedIr) -> Result<PadEvidence, IrFailure> {
        self.inference.pad(detected)
    }
    fn align(&mut self, detected: DetectedIr) -> Result<Vec<u8>, IrFailure> {
        self.inference.align(detected)
    }
    fn embed(&mut self, aligned: Vec<u8>) -> Result<Vec<f32>, IrFailure> {
        self.inference.embed(aligned)
    }
    fn adapt(&mut self, embedded: Vec<f32>) -> Result<Vec<f32>, IrFailure> {
        self.inference.adapt(embedded)
    }
    fn identify(&mut self, probe: &[f32]) -> IrMatch {
        self.inference.identify(probe)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ir_only_evaluation_teardown_schema_has_exact_unreached_fields() {
        let record = super::Report::new(super::Category::InvalidRequest).to_json();
        assert_eq!(record["schema"], 4);
        assert!(record["identity_acceptance"].is_null());
        for label in [
            "image_stop",
            "metadata_streamoff",
            "metadata_buffers",
            "metadata_format",
            "metadata_close",
            "emitter_restore",
        ] {
            assert!(record["capture_stages_ms"]
                .as_object()
                .unwrap()
                .contains_key(label));
            assert!(record["capture_stages_ms"][label].is_null());
        }
        assert_eq!(record["capture_stages_ms"].as_object().unwrap().len(), 15);
    }

    #[test]
    fn capture_selected_keeps_timings_on_error_and_still_observes_cancellation() {
        let signal = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = signal.clone();
        let control = irlume_camera::CaptureControl::new(
            irlume_camera::no_progress(),
            std::sync::Arc::new(move || observed.load(std::sync::atomic::Ordering::Acquire)),
        )
        .with_capture_timings(Some(irlume_camera::CaptureTimings::default()));
        let result: Result<(), super::IrFailure> = super::capture_selected_ir(
            "unused endpoint",
            &control,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            |_, bounded| {
                assert!(bounded.capture_timings().is_some());
                signal.store(true, std::sync::atomic::Ordering::Release);
                assert!(bounded.check().is_err());
                Err(super::IrFailure::CameraIoFailed)
            },
        );
        assert_eq!(result, Err(super::IrFailure::Cancelled));
    }
    #[test]
    fn ir_only_evaluation_stage_schema_preserves_unreached_stages() {
        let record = super::Report::new(super::Category::InvalidRequest).to_json();
        assert_eq!(record["schema"], 4);
        assert!(record["identity_acceptance"].is_null());
        let stages = record["capture_stages_ms"]
            .as_object()
            .expect("fixed timings");
        assert_eq!(stages.len(), 15);
        assert!(stages.values().all(serde_json::Value::is_null));
        assert_eq!(record["authentication_granted"], false);
    }
    use super::*;
    use irlume_core::storage::{FaceProfile, FaceScan, LEGACY_RECOGNIZER_SPACE};

    fn policy(
        signals: &Signals,
        pad: Option<irlume_common::Result<f32>>,
        enr: &Enrollment,
        probe: &[f32],
        adapter: bool,
        space: &str,
        embed_space: &str,
    ) -> Category {
        if let Err(category) = gate_policy(signals, pad, enr) {
            return category;
        }
        if probe.len() != EMBED_DIM || probe.iter().any(|v| !v.is_finite()) {
            return Category::InferenceFailed;
        }
        identity_category(
            ir_match_in(space, embed_space, adapter, enr, probe),
            enr.profiles.len(),
            adapter,
        )
        .category
    }
    fn genuine() -> (Signals, Enrollment, Vec<f32>) {
        let mut probe = vec![0.0; EMBED_DIM];
        probe[0] = 1.0;
        let signals = Signals {
            ir_face: Some(irlume_liveness::FaceBox {
                cx: 0.5,
                cy: 0.5,
                score: 0.99,
            }),
            ir_face_brightness: 100.0,
            ir_center_edge_ratio: 1.5,
            ir_ceiling_known: true,
            ir_saturated_frac: Some(0.0),
            ..Default::default()
        };
        let mut enr = Enrollment::new("private-user");
        enr.profiles.push(FaceProfile {
            name: "private-profile".into(),
            ir_calib: None,
            ir_calibs: Default::default(),
            scans: vec![FaceScan {
                name: "private-scan".into(),
                rgb: probe.clone(),
                ir: Some(probe.clone()),
                ir_space: Some("raw".into()),
                embed_space: None,
                ir_center_edge_ratio: 0.0,
                ir_brightness: 0.0,
                pitch: 0.0,
            }],
        });
        (signals, enr, probe)
    }

    fn evaluate(
        signals: &Signals,
        pad: Option<irlume_common::Result<f32>>,
        enr: &Enrollment,
        probe: &[f32],
    ) -> Category {
        policy(
            signals,
            pad,
            enr,
            probe,
            false,
            "raw",
            LEGACY_RECOGNIZER_SPACE,
        )
    }

    #[test]
    fn ir_only_evaluation_missing_pad_cannot_match() {
        let (s, e, p) = genuine();
        assert_eq!(evaluate(&s, None, &e, &p), Category::PadUnavailable);
    }

    #[test]
    fn ir_only_evaluation_invalid_pad_cannot_match() {
        let (s, e, p) = genuine();
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.01, 1.01] {
            assert_eq!(evaluate(&s, Some(Ok(value)), &e, &p), Category::PadInvalid);
        }
        assert_eq!(
            evaluate(
                &s,
                Some(Err(irlume_common::Error::Hardware(
                    "private failure".into()
                ))),
                &e,
                &p
            ),
            Category::PadInvalid
        );
    }

    #[test]
    fn ir_only_evaluation_spoof_pad_and_failed_gate_refuse() {
        let (mut s, e, p) = genuine();
        assert_eq!(evaluate(&s, Some(Ok(0.9)), &e, &p), Category::PadRefused);
        s.ir_center_edge_ratio = 0.5;
        assert_eq!(
            evaluate(&s, Some(Ok(0.0)), &e, &p),
            Category::LivenessRefused
        );
        s.ir_face = None;
        assert_eq!(evaluate(&s, Some(Ok(0.0)), &e, &p), Category::NoFace);
    }

    #[test]
    fn ir_only_evaluation_compatible_identity_is_required() {
        let (s, mut e, mut p) = genuine();
        assert_eq!(
            evaluate(&s, Some(Ok(0.0)), &e, &p),
            Category::CandidateMatch
        );
        p.swap(0, 1);
        assert_eq!(
            evaluate(&s, Some(Ok(0.0)), &e, &p),
            Category::IdentityMismatch
        );
        e.profiles[0].scans[0].ir_space = None;
        assert_eq!(
            evaluate(&s, Some(Ok(0.0)), &e, &p),
            Category::IncompatibleEnrollment
        );
    }
    #[test]
    fn ir_only_evaluation_cancellation_prevents_camera_access() {
        let control =
            CaptureControl::new(irlume_camera::no_progress(), std::sync::Arc::new(|| true));
        let result = capture_selected_ir(
            "/dev/video-selected-ir",
            &control,
            Instant::now() + Duration::from_secs(1),
            |_, _| {
                panic!("cancelled request reached camera boundary");
                #[allow(unreachable_code)]
                Ok(())
            },
        );
        assert_eq!(result, Err(IrFailure::Cancelled));
    }

    #[test]
    fn ir_only_evaluation_capture_uses_only_selected_ir_and_preserves_caller_expiry() {
        let control = CaptureControl::with_progress(irlume_camera::no_progress())
            .with_deadline(Some(Instant::now()));
        assert_eq!(
            capture_selected_ir(
                "/dev/video-selected-ir",
                &control,
                Instant::now() + Duration::from_secs(1),
                |endpoint, bounded| {
                    assert_eq!(endpoint, "/dev/video-selected-ir");
                    bounded.check().map_err(|_| IrFailure::DeadlineExpired)
                }
            ),
            Err(IrFailure::DeadlineExpired)
        );
        let control = CaptureControl::with_progress(irlume_camera::no_progress());
        assert_eq!(
            capture_selected_ir(
                "/dev/video-selected-ir",
                &control,
                Instant::now() + Duration::from_secs(1),
                |endpoint, _| {
                    assert_eq!(endpoint, "/dev/video-selected-ir");
                    Ok(7)
                }
            ),
            Ok(7)
        );
    }

    #[test]
    fn ir_only_evaluation_late_cancellation_and_expiry_override_candidate() {
        let control =
            CaptureControl::new(irlume_camera::no_progress(), std::sync::Arc::new(|| true));
        assert_eq!(
            active(&control, Instant::now() + Duration::from_secs(1)),
            Err(Category::Cancelled)
        );
        let control = CaptureControl::with_progress(irlume_camera::no_progress());
        assert_eq!(
            active(&control, Instant::now()),
            Err(Category::DeadlineExpired)
        );
    }

    #[test]
    fn ir_only_evaluation_malformed_frame_is_refused() {
        for (w, h, n, raw) in [
            (0, 4, 0, None),
            (4, 0, 0, None),
            (4, 4, 15, None),
            (4, 4, 16, Some(15)),
            (u32::MAX, u32::MAX, 0, None),
        ] {
            assert!(!valid_frame_shape(w, h, n, raw));
        }
        assert!(valid_frame_shape(4, 4, 16, Some(16)));
    }

    #[test]
    fn ir_only_evaluation_enrolled_falloff_floor_is_enforced() {
        let (s, mut e, p) = genuine();
        e.profiles[0].scans[0].ir_center_edge_ratio = 2.4;
        let scan = e.profiles[0].scans[0].clone();
        e.profiles[0].scans.push(scan);
        assert_eq!(
            evaluate(&s, Some(Ok(0.0)), &e, &p),
            Category::LivenessRefused
        );
    }

    #[test]
    fn ir_only_evaluation_foreign_recognizer_and_dimension_refuse() {
        let (s, mut e, p) = genuine();
        e.profiles[0].scans[0].embed_space = Some("embed:foreign".into());
        assert_eq!(
            evaluate(&s, Some(Ok(0.0)), &e, &p),
            Category::IncompatibleEnrollment
        );
        e.profiles[0].scans[0].embed_space = None;
        e.profiles[0].scans[0].ir = Some(vec![1.0]);
        assert_eq!(
            evaluate(&s, Some(Ok(0.0)), &e, &p),
            Category::IncompatibleEnrollment
        );
    }

    #[test]
    fn ir_only_evaluation_centroid_arm_uses_profile_count_and_finite_scores() {
        let matched = |score| IrMatch {
            best: 0.0,
            best_who: "private".into(),
            n_templates: 30,
            centroid: Some((score, "private".into())),
        };
        assert_eq!(
            identity_category(matched(0.65), 1, false).category,
            Category::CandidateMatch
        );
        assert_eq!(
            identity_category(matched(0.1), 1, false).category,
            Category::IdentityMismatch
        );
        assert_eq!(
            identity_category(matched(f32::INFINITY), 1, false).category,
            Category::IdentityMismatch
        );
    }

    #[test]
    fn ir_only_evaluation_reports_each_identity_acceptance_truth_table_arm() {
        let base = irlume_core::IR_DARK_MATCH_THRESHOLD;
        let templates = 30;
        let profiles = 2;
        let best_threshold = irlume_core::scaled_threshold(base, templates);
        let centroid_threshold = irlume_core::scaled_threshold(base, profiles);
        let matched = |best, centroid| IrMatch {
            best,
            best_who: "private".into(),
            n_templates: templates,
            centroid: Some((centroid, "private".into())),
        };
        for (best, centroid, category, acceptance, serialized) in [
            (
                best_threshold - 0.01,
                centroid_threshold - 0.01,
                Category::IdentityMismatch,
                None,
                serde_json::Value::Null,
            ),
            (
                best_threshold + 0.01,
                centroid_threshold - 0.01,
                Category::CandidateMatch,
                Some(IdentityAcceptance::BestTemplate),
                serde_json::json!("best_template"),
            ),
            (
                best_threshold - 0.01,
                centroid_threshold + 0.01,
                Category::CandidateMatch,
                Some(IdentityAcceptance::Centroid),
                serde_json::json!("centroid"),
            ),
            (
                best_threshold + 0.01,
                centroid_threshold + 0.01,
                Category::CandidateMatch,
                Some(IdentityAcceptance::Both),
                serde_json::json!("both"),
            ),
        ] {
            let result = identity_category(matched(best, centroid), profiles, false);
            assert_eq!(result.category, category);
            assert_eq!(result.acceptance, acceptance);
            let mut report = Report::new(result.category);
            report.identity_acceptance = result.acceptance;
            assert_eq!(report.to_json()["identity_acceptance"], serialized);
        }
    }

    #[test]
    fn ir_only_evaluation_identity_acceptance_uses_adapter_threshold_and_compatibility() {
        let base = irlume_core::IR_ADAPTED_MATCH_THRESHOLD;
        let templates = 3;
        let profiles = 2;
        let result = identity_category(
            IrMatch {
                best: irlume_core::scaled_threshold(base, templates),
                best_who: "private".into(),
                n_templates: templates,
                centroid: Some((
                    irlume_core::scaled_threshold(base, profiles),
                    "private".into(),
                )),
            },
            profiles,
            true,
        );
        assert_eq!(result.acceptance, Some(IdentityAcceptance::Both));
        let incompatible = identity_category(
            IrMatch {
                best: f32::INFINITY,
                best_who: "private".into(),
                n_templates: 0,
                centroid: Some((f32::NAN, "private".into())),
            },
            profiles,
            true,
        );
        assert_eq!(incompatible.category, Category::IncompatibleEnrollment);
        assert_eq!(incompatible.acceptance, None);
    }

    #[test]
    fn ir_only_evaluation_rate_fill_detail_refines_only_hardware_refusal() {
        use irlume_camera::RateFillFailure;
        let detail = Some(RateFillFailure::TimestampNonIncreasing);
        let refined =
            Category::from(IrFailure::CameraHardwareFailed).with_rate_fill_failure(detail);
        let json = Report::new(refined).to_json();
        assert_eq!(
            json["category"],
            "camera_rate_fill_timestamp_non_increasing"
        );
        assert_eq!(json["authentication_granted"], false);
        assert!(json["identity_acceptance"].is_null());
        assert!(json["detection_ms"].is_null());
        assert_eq!(
            Category::CameraHardwareFailed.with_rate_fill_failure(None),
            Category::CameraHardwareFailed
        );
        for unchanged in [
            Category::Cancelled,
            Category::DeadlineExpired,
            Category::CameraBusy,
            Category::CameraRateRefused,
            Category::CameraIoFailed,
            Category::Ready,
            Category::CandidateMatch,
            Category::IdentityMismatch,
        ] {
            assert_eq!(unchanged.with_rate_fill_failure(detail), unchanged);
        }
    }

    #[test]
    fn ir_only_evaluation_json_has_only_fixed_categories_and_nullable_timings() {
        let report = Report::new(Category::InvalidRequest);
        assert_eq!(
            report.to_json(),
            serde_json::json!({ "schema": 4, "operation": "ir_only_evaluation",
            "authentication_granted": false, "category": "invalid_request", "elapsed_ms": 0,
            "identity_acceptance": null,
            "capture_ms": null, "detection_ms": null, "pad_ms": null, "identity_ms": null,
            "capture_stages_ms": irlume_camera::CaptureTimings::default().snapshot() })
        );
    }

    #[test]
    fn ir_only_evaluation_nonfinite_identity_scores_never_accept() {
        for score in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let best = identity_category(
                IrMatch {
                    best: score,
                    best_who: "private".into(),
                    n_templates: 1,
                    centroid: None,
                },
                1,
                false,
            );
            assert_eq!(best.category, Category::IdentityMismatch);
            assert_eq!(best.acceptance, None);
            let centroid = identity_category(
                IrMatch {
                    best: 0.0,
                    best_who: "private".into(),
                    n_templates: 1,
                    centroid: Some((score, "private".into())),
                },
                1,
                false,
            );
            assert_eq!(centroid.category, Category::IdentityMismatch);
            assert_eq!(centroid.acceptance, None);
        }
    }
    #[test]
    fn capture_failure_categories_preserve_types_without_disclosing_messages() {
        use irlume_common::Error;
        for (error, want) in [
            (
                Error::CameraBusy("private device holder".into()),
                "camera_busy",
            ),
            (Error::Io("private io path".into()), "camera_io_failed"),
            (
                Error::Hardware("camera busy is only prose".into()),
                "camera_hardware_failed",
            ),
            (
                Error::NotAuthorized("private user".into()),
                "camera_authorization_refused",
            ),
            (
                Error::Policy("private policy".into()),
                "camera_policy_refused",
            ),
            (
                Error::Protocol("private protocol".into()),
                "camera_capture_failed",
            ),
            (
                Error::Tpm("private TPM detail".into()),
                "camera_capture_failed",
            ),
            (Error::Preempted("private cancellation".into()), "cancelled"),
            (Error::DeadlineExpired, "deadline_expired"),
        ] {
            let json = Report::new(error_category(error)).to_json();
            assert_eq!(
                json,
                serde_json::json!({
                    "schema": 4, "operation": "ir_only_evaluation",
                    "authentication_granted": false, "category": want,
                    "identity_acceptance": null,
                    "elapsed_ms": 0, "capture_ms": null, "detection_ms": null,
                    "pad_ms": null, "identity_ms": null,
                    "capture_stages_ms": irlume_camera::CaptureTimings::default().snapshot()
                })
            );
        }
    }

    #[test]
    fn capture_lease_timeout_is_not_the_authentication_deadline() {
        use lease::CameraLeaseError as E;
        for (error, want) in [
            (
                E::DeadlineExpired {
                    current_owner: None,
                },
                "camera_lease_timeout",
            ),
            (
                E::DeadlineExpired {
                    current_owner: Some(lease::CameraOperationKind::Diagnostics),
                },
                "camera_lease_timeout",
            ),
            (E::Stale, "camera_lease_refused"),
            (E::UnknownEndpoint, "camera_lease_refused"),
            (E::Poisoned, "camera_lease_refused"),
            (
                E::InvalidEndpoint("private path".into()),
                "camera_lease_refused",
            ),
        ] {
            let json = Report::new(lease_error_category(error)).to_json();
            assert_eq!(json["category"], want);
            assert_eq!(json["authentication_granted"], false);
            assert!(!json.to_string().contains("private"));
            assert_eq!(json.as_object().unwrap().len(), 11);
        }
    }

    #[test]
    fn capture_rate_refusal_does_not_serialize_the_evidence_payload() {
        let evidence = irlume_common::CameraStreamRateEvidence {
            role: "private role".into(),
            requested_num: 1,
            requested_den: 15,
            accepted_num: 1,
            accepted_den: 15,
            floor_num: 15,
            floor_den: 1,
            tolerance_percent: 98,
            window_count: 30,
            window_span_us: 3_000_000,
            delivered_num: 10,
            delivered_den: 1,
            meets_floor: false,
            sequence_gap: 0,
            cumulative_drops: 0,
            clock: "private clock".into(),
            source: "private source".into(),
            latest_timestamp_us: 123_456_789,
            stream_epoch: 1,
        };
        let json = Report::new(error_category(irlume_common::Error::DeliveredRate(
            Box::new(evidence),
        )))
        .to_json();
        assert_eq!(json["category"], "camera_rate_refused");
        assert_eq!(json["authentication_granted"], false);
        assert_eq!(json.as_object().unwrap().len(), 11);
        assert!(!json.to_string().contains("private"));
        assert!(!json.to_string().contains("123456789"));
    }

    #[test]
    fn capture_failure_stops_inference_and_cancellation_still_takes_precedence() {
        for category in [
            IrFailure::CameraBusy,
            IrFailure::CameraRateRefused,
            IrFailure::CameraLeaseTimeout,
            IrFailure::CameraLeaseRefused,
            IrFailure::CameraIoFailed,
            IrFailure::CameraHardwareFailed,
            IrFailure::CameraAuthorizationRefused,
            IrFailure::CameraPolicyRefused,
            IrFailure::CameraCaptureFailed,
        ] {
            for cancel in [false, true] {
                let signal = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let observed = signal.clone();
                let control = CaptureControl::new(
                    irlume_camera::no_progress(),
                    std::sync::Arc::new(move || {
                        observed.load(std::sync::atomic::Ordering::Acquire)
                    }),
                );
                let mut stages = InterruptStages {
                    stop_at: if cancel { "capture" } else { "" },
                    expire: false,
                    capture_failure: Some(category),
                    signal,
                    reached: Vec::new(),
                };
                let report =
                    evaluate_stages(&mut stages, &control, Duration::from_secs(1), 1, false);
                assert_eq!(
                    report.category,
                    if cancel {
                        Category::Cancelled
                    } else {
                        category.into()
                    }
                );
                assert!(report.capture_ms.is_some());
                assert_eq!(
                    (report.detection_ms, report.pad_ms, report.identity_ms),
                    (None, None, None)
                );
                assert_eq!(stages.reached, ["preflight", "capture"]);
                assert_eq!(report.to_json()["authentication_granted"], false);
            }
        }
    }

    struct InterruptStages {
        stop_at: &'static str,
        expire: bool,
        capture_failure: Option<IrFailure>,
        signal: std::sync::Arc<std::sync::atomic::AtomicBool>,
        reached: Vec<&'static str>,
    }
    impl InterruptStages {
        fn step(&mut self, label: &'static str) {
            self.reached.push(label);
            if label == self.stop_at {
                if self.expire {
                    std::thread::sleep(Duration::from_millis(110));
                } else {
                    self.signal
                        .store(true, std::sync::atomic::Ordering::Release);
                }
            }
        }
    }
    impl AssessmentStages for InterruptStages {
        type Captured = ();
        type Detected = ();
        type Aligned = ();
        type Embedded = ();
        fn preflight(&mut self) -> Result<(), IrFailure> {
            self.step("preflight");
            Ok(())
        }
        fn capture(&mut self, _: &CaptureControl, _: Option<Instant>) -> Result<(), IrFailure> {
            self.step("capture");
            if let Some(category) = self.capture_failure {
                Err(category)
            } else {
                Ok(())
            }
        }
        fn detect(&mut self, _: ()) -> Result<(), IrFailure> {
            self.step("detect");
            Ok(())
        }
        fn signals(&self, _: &()) -> Signals {
            Signals::default()
        }
        fn pad(&mut self, _: &()) -> Result<PadEvidence, IrFailure> {
            self.step("pad");
            Ok(PadEvidence::Score(0.1))
        }
        fn align(&mut self, _: ()) -> Result<(), IrFailure> {
            self.step("align");
            Ok(())
        }
        fn embed(&mut self, _: ()) -> Result<(), IrFailure> {
            self.step("embed");
            Ok(())
        }
        fn adapt(&mut self, _: ()) -> Result<Vec<f32>, IrFailure> {
            self.step("adapt");
            Ok(vec![0.0; EMBED_DIM])
        }
        fn identify(&mut self, _: &[f32]) -> IrMatch {
            self.step("identify");
            IrMatch {
                best: 1.0,
                best_who: "synthetic".into(),
                n_templates: 1,
                centroid: None,
            }
        }
    }

    #[test]
    fn ir_only_evaluation_orchestrator_stops_after_every_cancelled_stage() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        for stage in [
            "preflight",
            "capture",
            "detect",
            "pad",
            "align",
            "embed",
            "adapt",
            "identify",
        ] {
            let signal = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&signal);
            let control = CaptureControl::new(
                irlume_camera::no_progress(),
                Arc::new(move || observed.load(Ordering::Acquire)),
            );
            let mut stages = InterruptStages {
                stop_at: stage,
                expire: false,
                capture_failure: None,
                signal,
                reached: Vec::new(),
            };
            let report = evaluate_stages(&mut stages, &control, Duration::from_secs(1), 1, false);
            assert_eq!(report.category, Category::Cancelled, "late stage {stage}");
            assert_eq!(report.identity_acceptance, None, "late stage {stage}");
            assert_eq!(
                stages.reached.last(),
                Some(&stage),
                "work continued after cancellation"
            );
        }
    }

    #[test]
    fn ir_only_evaluation_orchestrator_stops_after_expired_inference_stages() {
        for stage in ["detect", "pad", "embed", "identify"] {
            let control = CaptureControl::with_progress(irlume_camera::no_progress());
            let mut stages = InterruptStages {
                stop_at: stage,
                expire: true,
                capture_failure: None,
                signal: Default::default(),
                reached: Vec::new(),
            };
            let report =
                evaluate_stages(&mut stages, &control, Duration::from_millis(100), 1, false);
            assert_eq!(
                report.category,
                Category::DeadlineExpired,
                "late stage {stage}"
            );
            assert_eq!(report.identity_acceptance, None, "late stage {stage}");
            assert_eq!(
                stages.reached.last(),
                Some(&stage),
                "work continued after expiry"
            );
        }
    }

    #[test]
    fn ir_only_evaluation_completed_candidate_retains_acceptance_arm() {
        let control = CaptureControl::with_progress(irlume_camera::no_progress());
        let mut stages = InterruptStages {
            stop_at: "",
            expire: false,
            capture_failure: None,
            signal: Default::default(),
            reached: Vec::new(),
        };
        let report = evaluate_stages(&mut stages, &control, Duration::from_secs(1), 1, false);
        assert_eq!(report.category, Category::CandidateMatch);
        assert_eq!(
            report.identity_acceptance,
            Some(IdentityAcceptance::BestTemplate)
        );
        assert_eq!(report.to_json()["identity_acceptance"], "best_template");
    }

    #[test]
    fn ir_only_evaluation_failed_capture_does_not_report_unrun_detection() {
        let control = CaptureControl::with_progress(irlume_camera::no_progress());
        let mut stages = InterruptStages {
            stop_at: "",
            expire: false,
            capture_failure: Some(IrFailure::CameraUnavailable),
            signal: Default::default(),
            reached: Vec::new(),
        };
        let report = evaluate_stages(&mut stages, &control, Duration::from_secs(1), 1, false);
        assert_eq!(report.category, Category::CameraUnavailable);
        assert!(report.capture_ms.is_some());
        assert_eq!(
            (report.detection_ms, report.pad_ms, report.identity_ms),
            (None, None, None)
        );
        assert_eq!(stages.reached, ["preflight", "capture"]);
    }

    #[test]
    fn ir_only_evaluation_orchestrator_validates_budget_before_any_work() {
        let control = CaptureControl::with_progress(irlume_camera::no_progress());
        for budget in [
            Duration::ZERO,
            Duration::from_millis(99),
            Duration::from_millis(30001),
            Duration::MAX,
        ] {
            let mut stages = InterruptStages {
                stop_at: "",
                expire: false,
                capture_failure: None,
                signal: Default::default(),
                reached: Vec::new(),
            };
            let report = evaluate_stages(&mut stages, &control, budget, 1, false);
            assert_eq!(report.category, Category::InvalidRequest);
            assert!(stages.reached.is_empty());
        }
    }

    #[test]
    fn ir_only_evaluation_orchestrator_completes_only_after_all_stages() {
        let control = CaptureControl::with_progress(irlume_camera::no_progress());
        let mut stages = InterruptStages {
            stop_at: "",
            expire: false,
            capture_failure: None,
            signal: Default::default(),
            reached: Vec::new(),
        };
        let report = evaluate_stages(&mut stages, &control, Duration::from_secs(1), 1, false);
        assert_eq!(report.category, Category::CandidateMatch);
        assert_eq!(
            stages.reached,
            [
                "preflight",
                "capture",
                "detect",
                "pad",
                "align",
                "embed",
                "adapt",
                "identify"
            ]
        );
        assert!(
            report.capture_ms.is_some()
                && report.detection_ms.is_some()
                && report.pad_ms.is_some()
                && report.identity_ms.is_some()
        );
        assert_eq!(report.to_json()["authentication_granted"], false);
    }
}
