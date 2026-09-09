// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Private IR evidence shared by diagnostic and authentication consumers.

use super::*;

pub(super) struct IrAssessment {
    pub(super) matched: IrMatch,
    pub(super) signals: Signals,
    pub(super) pad: PadEvidence,
}

fn enrollment_readiness(
    enrollment: &irlume_core::storage::Enrollment,
    identity: &str,
    compatible_templates: usize,
) -> irlume_common::IrOnlyReadiness {
    use irlume_common::IrOnlyReadiness as Ready;
    if legacy_eye_policy(enrollment).is_err() {
        return Ready::IncompatibleEnrollment;
    }
    let Some(binding) = enrollment
        .camera_binding
        .as_ref()
        .and_then(|binding| binding.ir.as_deref())
    else {
        return Ready::BindingUnavailable;
    };
    if binding != identity {
        return Ready::BindingMismatch;
    }
    if compatible_templates == 0 {
        return Ready::IncompatibleEnrollment;
    }
    Ready::ReadyForExperimentalAttempt
}

fn model_readiness(
    target_available: bool,
    adapter_required: bool,
    adapter_loaded: bool,
    pad_loaded: bool,
) -> Option<irlume_common::IrOnlyReadiness> {
    use irlume_common::IrOnlyReadiness as Ready;
    if !target_available {
        Some(Ready::TargetUnavailable)
    } else if adapter_required && !adapter_loaded {
        Some(Ready::ModelsUnavailable)
    } else if !pad_loaded {
        Some(Ready::PadUnavailable)
    } else {
        None
    }
}

pub(super) fn assessed_outcome(
    assessment: &IrAssessment,
    enrollment: &irlume_core::storage::Enrollment,
    adapter: bool,
) -> Outcome {
    let pad = match assessment.pad {
        PadEvidence::Score(score) => Some(Ok(score)),
        PadEvidence::InferenceFailed => Some(Err(irlume_common::Error::Hardware(
            "IR PAD unavailable".into(),
        ))),
        _ => None,
    };
    if let Err(failure) = gate_policy(&assessment.signals, pad, enrollment) {
        return refusal_outcome(failure);
    }
    let matched = &assessment.matched;
    if matched.n_templates == 0 {
        return refusal_outcome(IrFailure::IncompatibleEnrollment);
    }
    let (best, centroid) =
        IdentityThresholds::new(matched.n_templates, enrollment.profiles.len(), adapter)
            .arms(matched);
    if best {
        return Outcome::grant(
            matched.best,
            format!("match: {} (experimental IR-only)", matched.best_who),
        );
    }
    if centroid {
        if let Some((score, who)) = &matched.centroid {
            return Outcome::grant(
                *score,
                format!("match: {who} (experimental IR-only centroid)"),
            );
        }
    }
    Outcome::deny_live(
        OutcomeKind::BelowThreshold,
        matched.best,
        "below threshold (experimental IR-only)",
    )
}

pub(super) fn refusal_outcome(failure: IrFailure) -> Outcome {
    let (kind, reason) = match failure {
        IrFailure::NoFace => (OutcomeKind::NoFace, "no face in IR"),
        IrFailure::PadRefused => (
            OutcomeKind::Spoof,
            "IR PAD refused the presentation; use your password",
        ),
        IrFailure::LivenessRefused => (
            OutcomeKind::OtherDeny,
            "IR liveness refused the presentation; use your password",
        ),
        IrFailure::IncompatibleEnrollment => (
            OutcomeKind::SetupUnavailable,
            "no compatible IR enrollment; add fresh scans or use your password",
        ),
        IrFailure::PadUnavailable | IrFailure::PadInvalid => (
            OutcomeKind::RuntimeUnavailable,
            "required IR PAD evidence is unavailable; use your password",
        ),
        IrFailure::DeadlineExpired => (
            OutcomeKind::DeadlineExpired,
            "authentication deadline expired",
        ),
        _ => (
            OutcomeKind::RuntimeUnavailable,
            "IR assessment is unavailable; use your password",
        ),
    };
    Outcome::deny(kind, reason)
}

pub(super) struct IdentityThresholds {
    pub(super) best: f32,
    pub(super) centroid: f32,
}

impl IdentityThresholds {
    pub(super) fn new(templates: usize, profiles: usize, adapter: bool) -> Self {
        let base = if adapter {
            irlume_core::IR_ADAPTED_MATCH_THRESHOLD
        } else {
            irlume_core::IR_DARK_MATCH_THRESHOLD
        };
        Self {
            best: irlume_core::scaled_threshold(base, templates),
            centroid: irlume_core::scaled_threshold(base, profiles),
        }
    }

    pub(super) fn arms(&self, matched: &IrMatch) -> (bool, bool) {
        if matched.n_templates == 0 {
            return (false, false);
        }
        (
            matched.best.is_finite() && matched.best >= self.best,
            matched
                .centroid
                .as_ref()
                .is_some_and(|(score, _)| score.is_finite() && *score >= self.centroid),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_ir_model_readiness_requires_pad_and_explicit_adapter() {
        use irlume_common::IrOnlyReadiness as Ready;
        for available in [false, true] {
            for required in [false, true] {
                for adapter in [false, true] {
                    for pad in [false, true] {
                        let result = model_readiness(available, required, adapter, pad);
                        assert_eq!(result.is_none(), available && (!required || adapter) && pad);
                        if !available {
                            assert_eq!(result, Some(Ready::TargetUnavailable));
                        } else if required && !adapter {
                            assert_eq!(result, Some(Ready::ModelsUnavailable));
                        } else if !pad {
                            assert_eq!(result, Some(Ready::PadUnavailable));
                        }
                    }
                }
            }
        }
    }

    struct SyntheticStages {
        at: Option<&'static str>,
        fail: Option<IrFailure>,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
        reached: Vec<&'static str>,
        pad: PadEvidence,
    }
    impl SyntheticStages {
        fn step(&mut self, at: &'static str) -> Result<(), IrFailure> {
            self.reached.push(at);
            if self.at == Some(at) {
                if let Some(fail) = self.fail {
                    return Err(fail);
                }
                self.cancel
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            Ok(())
        }
    }
    impl AssessmentStages for SyntheticStages {
        type Captured = ();
        type Detected = ();
        type Aligned = ();
        type Embedded = ();
        fn preflight(&mut self) -> Result<(), IrFailure> {
            self.step("preflight")
        }
        fn capture(
            &mut self,
            _: &irlume_camera::CaptureControl,
            _: Option<std::time::Instant>,
        ) -> Result<(), IrFailure> {
            self.step("capture")
        }
        fn detect(&mut self, _: ()) -> Result<(), IrFailure> {
            self.step("detect")
        }
        fn signals(&self, _: &()) -> Signals {
            Signals {
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
            }
        }
        fn pad(&mut self, _: &()) -> Result<PadEvidence, IrFailure> {
            self.step("pad")?;
            Ok(self.pad)
        }
        fn align(&mut self, _: ()) -> Result<(), IrFailure> {
            self.step("align")
        }
        fn embed(&mut self, _: ()) -> Result<(), IrFailure> {
            self.step("embed")
        }
        fn adapt(&mut self, _: ()) -> Result<Vec<f32>, IrFailure> {
            self.step("adapt")?;
            Ok(vec![1.0; EMBED_DIM])
        }
        fn identify(&mut self, _: &[f32]) -> IrMatch {
            self.step("identify").unwrap();
            IrMatch {
                best: 1.0,
                best_who: "synthetic".into(),
                n_templates: 1,
                centroid: None,
            }
        }
    }

    #[test]
    fn production_ir_pipeline_cancels_before_any_later_stage_or_grant() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let order = [
            "preflight",
            "capture",
            "detect",
            "pad",
            "align",
            "embed",
            "adapt",
            "identify",
        ];
        for stop in 0..order.len() {
            let cancel = Arc::new(AtomicBool::new(false));
            let observed = cancel.clone();
            let control = irlume_camera::CaptureControl::new(
                irlume_camera::no_progress(),
                Arc::new(move || observed.load(Ordering::Acquire)),
            );
            let mut stages = SyntheticStages {
                at: Some(order[stop]),
                fail: None,
                cancel,
                reached: Vec::new(),
                pad: PadEvidence::Score(0.1),
            };
            let run = assess_stages(&mut stages, &control, None);
            assert!(
                matches!(run.result, Err(IrFailure::Cancelled)),
                "{}",
                order[stop]
            );
            assert_eq!(stages.reached, order[..=stop]);
        }
    }

    #[test]
    fn production_ir_pipeline_preserves_zero_window_and_refuses_expiry_and_stage_errors() {
        let enrollment = irlume_core::storage::Enrollment::new("synthetic");
        let make = || SyntheticStages {
            at: None,
            fail: None,
            cancel: Default::default(),
            reached: Vec::new(),
            pad: PadEvidence::Score(0.1),
        };
        let control = irlume_camera::CaptureControl::new(
            irlume_camera::no_progress(),
            std::sync::Arc::new(|| false),
        );
        let mut stages = make();
        let run = assess_stages(&mut stages, &control, None);
        assert!(assessed_outcome(&run.result.unwrap(), &enrollment, false).granted);
        let mut stages = make();
        let run = assess_stages(&mut stages, &control, Some(std::time::Instant::now()));
        assert!(matches!(run.result, Err(IrFailure::DeadlineExpired)));
        assert!(stages.reached.is_empty());
        for (at, failure) in [
            ("preflight", IrFailure::IncompatibleEnrollment),
            ("capture", IrFailure::CameraCaptureFailed),
            ("detect", IrFailure::NoFace),
            ("detect", IrFailure::InvalidFrame),
            ("pad", IrFailure::PadInvalid),
            ("align", IrFailure::InferenceFailed),
            ("embed", IrFailure::InferenceFailed),
            ("adapt", IrFailure::InferenceFailed),
        ] {
            let mut stages = make();
            stages.at = Some(at);
            stages.fail = Some(failure);
            let run = assess_stages(&mut stages, &control, None);
            assert!(matches!(run.result, Err(found) if found == failure));
            assert_eq!(stages.reached.last(), Some(&at));
            assert!(!refusal_outcome(failure).granted);
        }
        for pad in [
            PadEvidence::Unavailable,
            PadEvidence::InferenceFailed,
            PadEvidence::Score(f32::NAN),
            PadEvidence::Score(-1.0),
            PadEvidence::Score(1.1),
        ] {
            let mut stages = make();
            stages.pad = pad;
            let run = assess_stages(&mut stages, &control, None);
            assert!(!assessed_outcome(&run.result.unwrap(), &enrollment, false).granted);
        }
    }

    #[test]
    fn production_ir_attempt_facts_do_not_invent_rgb_measurements() {
        let signals = Signals {
            ir_face_brightness: 103.0,
            face_frac: 0.2,
            ..Default::default()
        };
        let facts = AttemptFacts::from_ir_signals(Some(&signals));
        let line = attempt_situation_line(OutcomeKind::NoFace, 0.0, &facts);
        assert!(line.contains("face_frac=0.20") && line.contains("ir_bright=103"));
        assert!(line.contains("yaw=n/a") && line.contains("rgb_bright=n/a"));
    }

    #[test]
    fn ir_preflight_requires_current_binding_and_compatible_templates() {
        use irlume_common::IrOnlyReadiness as Ready;
        use irlume_core::storage::{CameraBinding, Enrollment};
        let mut enrollment = Enrollment::new("synthetic");
        assert_eq!(
            enrollment_readiness(&enrollment, "target", 1),
            Ready::BindingUnavailable
        );
        enrollment.camera_binding = Some(CameraBinding {
            rgb: Some("irrelevant RGB".into()),
            ir: None,
        });
        assert_eq!(
            enrollment_readiness(&enrollment, "target", 1),
            Ready::BindingUnavailable
        );
        enrollment.camera_binding.as_mut().unwrap().ir = Some("different".into());
        assert_eq!(
            enrollment_readiness(&enrollment, "target", 1),
            Ready::BindingMismatch
        );
        enrollment.camera_binding.as_mut().unwrap().ir = Some("target".into());
        assert_eq!(
            enrollment_readiness(&enrollment, "target", 0),
            Ready::IncompatibleEnrollment
        );
        assert_eq!(
            enrollment_readiness(&enrollment, "target", 1),
            Ready::ReadyForExperimentalAttempt
        );
        enrollment.require_eyes_open = true;
        assert_eq!(
            enrollment_readiness(&enrollment, "target", 1),
            Ready::IncompatibleEnrollment
        );
    }

    #[test]
    fn production_ir_outcome_requires_real_pad_gate_and_identity() {
        let enrollment = irlume_core::storage::Enrollment::new("synthetic");
        for adapter in [false, true] {
            let base = if adapter {
                irlume_core::IR_ADAPTED_MATCH_THRESHOLD
            } else {
                irlume_core::IR_DARK_MATCH_THRESHOLD
            };
            let assessment = |pad, best, ratio| IrAssessment {
                matched: IrMatch {
                    best,
                    best_who: "synthetic".into(),
                    n_templates: 1,
                    centroid: None,
                },
                signals: Signals {
                    ir_face: Some(irlume_liveness::FaceBox {
                        cx: 0.5,
                        cy: 0.5,
                        score: 0.99,
                    }),
                    ir_face_brightness: 100.0,
                    ir_center_edge_ratio: ratio,
                    ir_ceiling_known: true,
                    ir_saturated_frac: Some(0.0),
                    ..Default::default()
                },
                pad,
            };
            assert!(
                assessed_outcome(
                    &assessment(PadEvidence::Score(0.1), base, 1.5),
                    &enrollment,
                    adapter
                )
                .granted
            );
            for pad in [
                PadEvidence::Unavailable,
                PadEvidence::InferenceFailed,
                PadEvidence::NotApplicable,
                PadEvidence::Pending,
                PadEvidence::Score(f32::NAN),
                PadEvidence::Score(f32::INFINITY),
                PadEvidence::Score(-0.01),
                PadEvidence::Score(1.01),
                PadEvidence::Score(0.9),
            ] {
                assert!(
                    !assessed_outcome(&assessment(pad, 1.0, 1.5), &enrollment, adapter).granted,
                    "{pad:?}"
                );
            }
            assert!(
                !assessed_outcome(
                    &assessment(PadEvidence::Score(0.1), 1.0, 0.5),
                    &enrollment,
                    adapter
                )
                .granted
            );
            let mismatch = assessed_outcome(
                &assessment(PadEvidence::Score(0.1), base - 0.01, 1.5),
                &enrollment,
                adapter,
            );
            assert!(!mismatch.granted);
            assert_eq!(mismatch.kind, OutcomeKind::BelowThreshold);
            assert!(!presence_retryable(&mismatch));
        }
    }

    #[test]
    fn ir_identity_thresholds_preserve_each_raw_and_adapter_boundary_arm() {
        for adapter in [false, true] {
            let base = if adapter {
                irlume_core::IR_ADAPTED_MATCH_THRESHOLD
            } else {
                irlume_core::IR_DARK_MATCH_THRESHOLD
            };
            let best = irlume_core::scaled_threshold(base, 30);
            let centroid = irlume_core::scaled_threshold(base, 2);
            for (b, c, want) in [
                (best - 0.01, centroid - 0.01, (false, false)),
                (best, centroid - 0.01, (true, false)),
                (best - 0.01, centroid, (false, true)),
                (best, centroid, (true, true)),
                (f32::NAN, f32::INFINITY, (false, false)),
            ] {
                let matched = IrMatch {
                    best: b,
                    best_who: "synthetic".into(),
                    n_templates: 30,
                    centroid: Some((c, "synthetic".into())),
                };
                assert_eq!(IdentityThresholds::new(30, 2, adapter).arms(&matched), want);
            }
            let incompatible = IrMatch {
                best: 1.0,
                best_who: "synthetic".into(),
                n_templates: 0,
                centroid: Some((1.0, "synthetic".into())),
            };
            assert_eq!(
                IdentityThresholds::new(0, 2, adapter).arms(&incompatible),
                (false, false)
            );
        }
    }
}

mod pipeline {
    use super::*;
    use irlume_camera::CaptureControl;
    use irlume_core::storage::Enrollment;
    use std::time::Instant;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum IrFailure {
        NoFace,
        LivenessRefused,
        PadUnavailable,
        PadInvalid,
        PadRefused,
        IncompatibleEnrollment,
        InvalidFrame,
        InferenceFailed,
        #[cfg(feature = "ir-only-evaluation")]
        CameraUnavailable,
        CameraBusy,
        CameraRateRefused,
        CameraLeaseTimeout,
        CameraLeaseRefused,
        CameraIoFailed,
        CameraHardwareFailed,
        CameraAuthorizationRefused,
        CameraPolicyRefused,
        CameraCaptureFailed,

        Cancelled,
        DeadlineExpired,
        #[cfg(feature = "ir-only-evaluation")]
        InvalidRequest,
    }
    pub(crate) fn error_failure(error: irlume_common::Error) -> IrFailure {
        match error {
            irlume_common::Error::Preempted(_) => IrFailure::Cancelled,
            irlume_common::Error::DeadlineExpired => IrFailure::DeadlineExpired,
            irlume_common::Error::CameraBusy(_) => IrFailure::CameraBusy,
            irlume_common::Error::DeliveredRate(_) => IrFailure::CameraRateRefused,
            irlume_common::Error::Io(_) => IrFailure::CameraIoFailed,
            irlume_common::Error::Hardware(_) => IrFailure::CameraHardwareFailed,
            irlume_common::Error::NotAuthorized(_) => IrFailure::CameraAuthorizationRefused,
            irlume_common::Error::Policy(_) => IrFailure::CameraPolicyRefused,
            irlume_common::Error::Protocol(_) | irlume_common::Error::Tpm(_) => {
                IrFailure::CameraCaptureFailed
            }
        }
    }

    // Classify only typed evidence. Never parse or serialize error messages, owner
    // details, paths, or rate payloads. A lease's short acquisition timeout is not
    // the authentication deadline; active() still gives caller expiry precedence.
    pub(crate) fn lease_error_failure(error: lease::CameraLeaseError) -> IrFailure {
        match error {
            lease::CameraLeaseError::DeadlineExpired { .. } => IrFailure::CameraLeaseTimeout,
            _ => IrFailure::CameraLeaseRefused,
        }
    }

    pub(crate) fn active(
        control: &CaptureControl,
        deadline: Option<Instant>,
    ) -> Result<(), IrFailure> {
        control.check().map_err(error_failure)?;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(IrFailure::DeadlineExpired);
        }
        Ok(())
    }

    pub(crate) fn valid_frame_shape(
        width: u32,
        height: u32,
        len: usize,
        raw_len: Option<usize>,
    ) -> bool {
        width > 0
            && height > 0
            && usize::try_from(width)
                .ok()
                .and_then(|w| usize::try_from(height).ok().and_then(|h| w.checked_mul(h)))
                .is_some_and(|n| n == len && raw_len.is_none_or(|raw| raw == n))
    }

    pub(crate) fn gate_policy(
        signals: &Signals,
        pad: Option<irlume_common::Result<f32>>,
        enr: &Enrollment,
    ) -> Result<(), IrFailure> {
        if signals.ir_face.is_none() {
            return Err(IrFailure::NoFace);
        }
        if signals
            .ir_face
            .is_some_and(|face| !face.score.is_finite() || !(0.0..=1.0).contains(&face.score))
            || !signals.ir_face_brightness.is_finite()
            || !(0.0..=255.0).contains(&signals.ir_face_brightness)
            || !signals.ir_center_edge_ratio.is_finite()
            || !signals.ir_ambient.is_finite()
            || signals
                .ir_saturated_frac
                .is_some_and(|v| !v.is_finite() || !(0.0..=1.0).contains(&v))
        {
            return Err(IrFailure::InvalidFrame);
        }
        if LivenessGate::new().evaluate_ir_only(signals).0 != Verdict::Live {
            return Err(IrFailure::LivenessRefused);
        }
        match pad {
            None => return Err(IrFailure::PadUnavailable),
            Some(Ok(p)) if p.is_finite() && (0.0..=1.0).contains(&p) => {
                if p >= IR_PAD_THRESHOLD {
                    return Err(IrFailure::PadRefused);
                }
            }
            Some(_) => return Err(IrFailure::PadInvalid),
        }
        if enr
            .ir_center_edge_ratio_floor()
            .is_some_and(|floor| !floor.is_finite() || signals.ir_center_edge_ratio < floor)
        {
            return Err(IrFailure::LivenessRefused);
        }
        Ok(())
    }

    pub(crate) trait AssessmentStages {
        type Captured;
        type Detected;
        type Aligned;
        type Embedded;
        fn preflight(&mut self) -> Result<(), IrFailure>;
        fn capture(
            &mut self,
            control: &CaptureControl,
            deadline: Option<Instant>,
        ) -> Result<Self::Captured, IrFailure>;
        fn detect(&mut self, captured: Self::Captured) -> Result<Self::Detected, IrFailure>;
        fn signals(&self, detected: &Self::Detected) -> Signals;
        fn pad(&mut self, detected: &Self::Detected) -> Result<PadEvidence, IrFailure>;
        fn align(&mut self, detected: Self::Detected) -> Result<Self::Aligned, IrFailure>;
        fn embed(&mut self, aligned: Self::Aligned) -> Result<Self::Embedded, IrFailure>;
        fn adapt(&mut self, embedded: Self::Embedded) -> Result<Vec<f32>, IrFailure>;
        fn identify(&mut self, probe: &[f32]) -> IrMatch;
    }

    fn millis(start: Instant) -> u64 {
        u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn timed<T>(slot: &mut Option<u64>, operation: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let result = operation();
        *slot = Some(millis(start));
        result
    }

    pub(crate) struct AssessmentRun {
        pub(crate) result: Result<IrAssessment, IrFailure>,
        pub(crate) observations: Option<Signals>,
        pub(crate) elapsed_ms: u64,
        pub(crate) capture_ms: Option<u64>,
        pub(crate) detection_ms: Option<u64>,
        pub(crate) pad_ms: Option<u64>,
        pub(crate) identity_ms: Option<u64>,
        #[cfg(feature = "ir-only-evaluation")]
        pub(crate) capture_stages_ms: std::collections::BTreeMap<&'static str, Option<u64>>,
        #[cfg(feature = "ir-only-evaluation")]
        pub(crate) rate_fill_failure: Option<irlume_camera::RateFillFailure>,
    }

    /// Collect checked IR evidence. This function never grants or classifies a match.
    pub(crate) fn assess_stages(
        stages: &mut impl AssessmentStages,
        control: &CaptureControl,
        deadline: Option<Instant>,
    ) -> AssessmentRun {
        let start = Instant::now();
        let mut capture_ms = None;
        let mut detection_ms = None;
        let mut pad_ms = None;
        let mut identity_ms = None;
        let mut observations = None;
        #[cfg(feature = "ir-only-evaluation")]
        let timings = irlume_camera::CaptureTimings::default();
        #[cfg(feature = "ir-only-evaluation")]
        let timed_control = control.clone().with_capture_timings(Some(timings.clone()));
        #[cfg(feature = "ir-only-evaluation")]
        let control = &timed_control;
        let result = (|| {
            active(control, deadline)?;
            let ready = stages.preflight();
            active(control, deadline)?;
            ready?;
            let captured = timed(&mut capture_ms, || stages.capture(control, deadline));
            active(control, deadline)?;
            let captured = captured?;
            let detected = timed(&mut detection_ms, || stages.detect(captured));
            active(control, deadline)?;
            let detected = detected?;
            let signals = stages.signals(&detected);
            observations = Some(signals.clone());
            let pad = timed(&mut pad_ms, || stages.pad(&detected));
            active(control, deadline)?;
            let pad = pad?;
            timed(&mut identity_ms, || {
                let aligned = stages.align(detected);
                active(control, deadline)?;
                let embedded = stages.embed(aligned?);
                active(control, deadline)?;
                let probe = stages.adapt(embedded?);
                active(control, deadline)?;
                let matched = stages.identify(&probe?);
                active(control, deadline)?;
                Ok(IrAssessment {
                    matched,
                    signals,
                    pad,
                })
            })
        })();
        AssessmentRun {
            result: active(control, deadline).and(result),
            observations,
            elapsed_ms: millis(start),
            capture_ms,
            detection_ms,
            pad_ms,
            identity_ms,
            #[cfg(feature = "ir-only-evaluation")]
            capture_stages_ms: timings.snapshot(),
            #[cfg(feature = "ir-only-evaluation")]
            rate_fill_failure: timings.rate_fill_failure(),
        }
    }
    pub(crate) struct DetectedIr {
        pixels: Vec<u8>,
        width: u32,
        height: u32,
        face: Detection,
        signals: Signals,
    }

    impl DetectedIr {
        pub(crate) fn signals(&self) -> Signals {
            self.signals.clone()
        }
        fn view(&self) -> align::RgbView<'_> {
            align::RgbView {
                data: &self.pixels,
                width: self.width,
                height: self.height,
            }
        }
    }

    pub(crate) struct IrInference<'a> {
        pub(crate) engine: &'a mut Engine,
        pub(crate) enrollment: &'a Enrollment,
    }

    impl IrInference<'_> {
        pub(crate) fn detect(
            &mut self,
            (ir, stats): (irlume_camera::Frame, irlume_camera::IrCaptureStats),
        ) -> Result<DetectedIr, IrFailure> {
            if ir.spectrum != irlume_camera::Spectrum::Ir
                || ir.provenance().stream_role() != irlume_camera::contracts::StreamRole::Ir
                || !ir.provenance().is_continuous()
                || !valid_frame_shape(
                    ir.width,
                    ir.height,
                    ir.data.len(),
                    stats.saturation_frame.as_ref().map(Vec::len),
                )
            {
                return Err(IrFailure::InvalidFrame);
            }
            let pixels = irlume_camera::grey_to_rgb(&ir.data);
            let view = align::RgbView {
                data: &pixels,
                width: ir.width,
                height: ir.height,
            };
            let detection = self.engine.det.detect(&view);
            let faces = detection.map_err(|_| IrFailure::InferenceFailed)?;
            let face = top_detection(&faces).ok_or(IrFailure::NoFace)?;
            if !face.score.is_finite()
                || !(0.0..=1.0).contains(&face.score)
                || face.bbox.iter().any(|v| !v.is_finite())
                || face.bbox[2] <= face.bbox[0]
                || face.bbox[3] <= face.bbox[1]
                || face
                    .landmarks
                    .iter()
                    .any(|(x, y)| !x.is_finite() || !y.is_finite())
            {
                return Err(IrFailure::InvalidFrame);
            }
            let raw = stats.saturation_frame.as_deref().unwrap_or(&ir.data);
            // RGB-only fields remain unused defaults. This object is consumed ONLY
            // by the IR-only gate, and contains no synthetic RGB scene brightness.
            let signals = Signals {
                ir_face: Some(irlume_liveness::FaceBox {
                    cx: (face.bbox[0] + face.bbox[2]) / 2.0 / ir.width as f32,
                    cy: (face.bbox[1] + face.bbox[3]) / 2.0 / ir.height as f32,
                    score: face.score,
                }),
                ir_face_brightness: mean_in_bbox(&ir.data, ir.width, ir.height, &face.bbox),
                ir_center_edge_ratio: center_edge_ratio(&ir.data, ir.width, ir.height, &face.bbox),
                ir_eye_glint: eye_glint_of(
                    raw,
                    ir.width,
                    ir.height,
                    Some(&face.landmarks),
                    stats.white_level,
                ),
                ir_ambient: stats.ambient_mean,
                ir_ceiling_known: stats.white_level.is_some(),
                face_frac: face_frac_of(Some(&face.bbox), ir.width),
                ir_saturated_frac: saturated_frac_of(
                    raw,
                    ir.width,
                    ir.height,
                    Some(&face.bbox),
                    stats.white_level,
                ),
                ir_persistent_saturated_frac: stats.persistent_saturated_frac,
                ..Default::default()
            };

            Ok(DetectedIr {
                pixels,
                width: ir.width,
                height: ir.height,
                face: face.clone(),
                signals,
            })
        }

        pub(crate) fn pad(&mut self, detected: &DetectedIr) -> Result<PadEvidence, IrFailure> {
            let pad = self
                .engine
                .pad_ir
                .as_mut()
                .map(|pad| pad.p_fake(&detected.view(), &detected.face.bbox));
            let evidence = match &pad {
                Some(Ok(score)) => PadEvidence::Score(*score),
                Some(Err(_)) => PadEvidence::InferenceFailed,
                None => PadEvidence::Unavailable,
            };
            gate_policy(&detected.signals, pad, self.enrollment)?;
            Ok(evidence)
        }

        pub(crate) fn align(&mut self, detected: DetectedIr) -> Result<Vec<u8>, IrFailure> {
            align::align_to_arcface(&detected.view(), &detected.face.landmarks)
                .map_err(|_| IrFailure::InferenceFailed)
        }

        pub(crate) fn embed(&mut self, aligned: Vec<u8>) -> Result<Vec<f32>, IrFailure> {
            self.engine
                .emb
                .embed(&aligned)
                .map(|raw| raw.to_vec())
                .map_err(|_| IrFailure::InferenceFailed)
        }

        pub(crate) fn adapt(&mut self, embedded: Vec<f32>) -> Result<Vec<f32>, IrFailure> {
            let probe = match &mut self.engine.ir_adapter {
                Some(adapter) => adapter
                    .apply(&embedded)
                    .map_err(|_| IrFailure::InferenceFailed)?,
                None => embedded,
            };
            if probe.len() != EMBED_DIM || probe.iter().any(|v| !v.is_finite()) {
                return Err(IrFailure::InferenceFailed);
            }
            Ok(probe)
        }

        pub(crate) fn identify(&self, probe: &[f32]) -> IrMatch {
            self.engine.ir_match(self.enrollment, probe)
        }
    }
}
pub(super) use pipeline::*;

fn readiness_refusal(readiness: irlume_common::IrOnlyReadiness) -> Outcome {
    use irlume_common::IrOnlyReadiness as Ready;
    let reason = match readiness {
        Ready::TargetUnavailable => "configured IR target unavailable; use your password",
        Ready::BindingUnavailable => {
            "IR enrollment has no camera binding; add fresh scans or use your password"
        }
        Ready::BindingMismatch => {
            "IR camera differs from enrollment; re-enroll on this camera or use your password"
        }
        Ready::ModelsUnavailable => "required IR model is unavailable; use your password",
        Ready::PadUnavailable => "required IR PAD model is unavailable; use your password",
        Ready::EnrollmentUnavailable => "IR enrollment is unavailable; enroll or use your password",
        Ready::IncompatibleEnrollment => {
            "IR enrollment is incompatible with this pipeline; add fresh scans or use your password"
        }
        _ => "experimental IR prerequisites are unavailable; use your password",
    };
    Outcome::deny(OutcomeKind::SetupUnavailable, reason)
}

impl Engine {
    /// Require an explicitly configured adapter for experimental IR assessment.
    /// An absent optional default adapter still selects the existing raw space.
    pub fn with_ir_adapter_required(mut self, required: bool) -> Self {
        self.ir_adapter_required = required;
        self
    }

    fn ir_model_readiness(
        &self,
        target: &irlume_camera::IrCaptureTarget,
    ) -> Option<irlume_common::IrOnlyReadiness> {
        model_readiness(
            selected_ir_available(target.endpoint()) && target.validate().is_ok(),
            self.ir_adapter_required,
            self.has_ir_adapter(),
            self.has_pad_ir(),
        )
    }

    fn ir_enrollment_readiness(
        &self,
        enrollment: &irlume_core::storage::Enrollment,
        target: &irlume_camera::IrCaptureTarget,
    ) -> irlume_common::IrOnlyReadiness {
        enrollment_readiness(
            enrollment,
            target.identity(),
            self.ir_match(enrollment, &[0.0; EMBED_DIM]).n_templates,
        )
    }

    // Retain the existing helper lifetime rule: a cancelled/expired caller
    // drains the loader before returning. No camera or lease is held here.
    fn load_ir_enrollment(
        &self,
        user: &str,
        window: AuthenticationWindow,
        read_only: bool,
    ) -> irlume_common::Result<Option<irlume_core::storage::Enrollment>> {
        self.check_authentication_completion(window)?;
        let (sender, receiver) = std::sync::mpsc::channel();
        let user = user.to_string();
        std::thread::Builder::new()
            .name("irlume-ir-enrollment".into())
            .spawn(move || {
                let loaded = if read_only {
                    irlume_core::storage::load_read_only(&user)
                } else {
                    irlume_core::storage::load(&user)
                };
                let _ = sender.send(loaded);
            })
            .map_err(|_| irlume_common::Error::Io("enrollment loader unavailable".into()))?;
        let mut loader = PendingEnrollmentLoad {
            receiver: Some(receiver),
        };
        let loaded = loop {
            self.check_authentication_completion(window)?;
            let wait = window
                .remaining()
                .unwrap_or(std::time::Duration::from_millis(50))
                .min(std::time::Duration::from_millis(50));
            let received = loader
                .receiver
                .as_ref()
                .expect("owned loader receiver")
                .recv_timeout(wait);
            if matches!(received, Err(std::sync::mpsc::RecvTimeoutError::Timeout)) {
                continue;
            }
            break resolve_loader(received);
        };
        loader.receiver.take();
        self.check_authentication_completion(window)?;
        match loaded {
            Ok(enrollment) => Ok(Some(enrollment)),
            Err(LoaderExit::NotEnrolled) => Ok(None),
            Err(LoaderExit::Fallback(error)) => Err(error),
        }
    }

    /// Check experimental IR prerequisites without opening video nodes or
    /// changing enrollment. Template-key unseal may be needed for protected data.
    /// Readiness does not establish capture latency, identity or qualification.
    pub fn ir_only_preflight(&self, user: &str) -> irlume_common::IrOnlyReadiness {
        use irlume_common::IrOnlyReadiness as Ready;
        let window = AuthenticationWindow::new(GRACE_WINDOW_MS);
        let target = match irlume_camera::configured_ir_target() {
            Ok(target) => target,
            Err(_) => return Ready::TargetUnavailable,
        };
        if let Some(refusal) = self.ir_model_readiness(&target) {
            return refusal;
        }
        let enrollment = match self.load_ir_enrollment(user, window, true) {
            Ok(Some(enrollment)) => enrollment,
            _ => return Ready::EnrollmentUnavailable,
        };
        if self.check_authentication_completion(window).is_err() {
            return Ready::Unavailable;
        }
        self.ir_enrollment_readiness(&enrollment, &target)
    }

    pub(super) fn authenticate_ir_in_window(
        &mut self,
        user: &str,
        window: AuthenticationWindow,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Outcome> {
        use irlume_common::IrOnlyReadiness as Ready;
        self.check_request_active()?;
        let target = match irlume_camera::configured_ir_target() {
            Ok(target) => target,
            Err(_) => return Ok(readiness_refusal(Ready::TargetUnavailable)),
        };
        if let Some(refusal) = self.ir_model_readiness(&target) {
            return Ok(readiness_refusal(refusal));
        }
        let enrollment = match self.load_ir_enrollment(user, window, false)? {
            Some(enrollment) => enrollment,
            None => return Ok(readiness_refusal(Ready::EnrollmentUnavailable)),
        };
        let readiness = self.ir_enrollment_readiness(&enrollment, &target);
        if readiness != Ready::ReadyForExperimentalAttempt {
            return Ok(readiness_refusal(readiness));
        }
        self.check_request_active()?;
        let operation = match lease::acquire_camera_operation(
            &target.lease_endpoints(),
            lease::CameraOperationKind::Authentication,
            window
                .remaining()
                .unwrap_or(std::time::Duration::from_secs(2))
                .min(std::time::Duration::from_secs(2)),
        ) {
            Ok(operation) => operation,
            Err(error) => {
                self.check_request_active()?;
                return Ok(refusal_outcome(lease_error_failure(error)));
            }
        };
        let mut costliest = std::time::Duration::ZERO;
        self.authentication_attempt_loop_with(
            window.deadline,
            window.milliseconds,
            &mut costliest,
            |engine| {
                (
                    engine.authenticate_ir_target_attempt(
                        &enrollment,
                        &target,
                        &operation,
                        diagnostics,
                    ),
                    false,
                )
            },
            std::time::Instant::now,
        )
        .0
    }

    fn authenticate_ir_target_attempt(
        &mut self,
        enrollment: &irlume_core::storage::Enrollment,
        target: &irlume_camera::IrCaptureTarget,
        operation: &lease::CameraOperationSession,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Outcome> {
        let control = self.capture_control();
        let deadline = self.authentication_deadline;
        let adapter = self.has_ir_adapter();
        let run = assess_stages(
            &mut TargetStages {
                inference: IrInference {
                    engine: self,
                    enrollment,
                },
                target,
                operation,
            },
            &control,
            deadline,
        );
        self.last_attempt_facts = AttemptFacts::from_ir_signals(run.observations.as_ref());
        use irlume_common::diagnostics::{TraceEventKind, TraceStage};
        for (stage, millis) in [
            (TraceStage::IrCapture, run.capture_ms),
            (TraceStage::Detection, run.detection_ms),
            (TraceStage::Liveness, run.pad_ms),
            (TraceStage::Matching, run.identity_ms),
        ] {
            if let Some(millis) = millis {
                diagnostics.emit_trace(TraceEventKind::StageTiming {
                    stage,
                    elapsed_us: millis.saturating_mul(1000),
                });
            }
        }
        irlume_common::dlog!("experimental IR assessment elapsed {}ms", run.elapsed_ms);
        self.check_request_active()?;
        let outcome = match run.result {
            Ok(assessment) => assessed_outcome(&assessment, enrollment, adapter),
            Err(IrFailure::Cancelled) => {
                return Err(irlume_common::Error::Preempted(
                    "authentication cancelled".into(),
                ))
            }
            Err(IrFailure::DeadlineExpired) => return Err(irlume_common::Error::DeadlineExpired),
            Err(failure) => refusal_outcome(failure),
        };
        self.check_request_active()?;
        Ok(outcome)
    }
}

struct TargetStages<'a> {
    inference: IrInference<'a>,
    target: &'a irlume_camera::IrCaptureTarget,
    operation: &'a lease::CameraOperationSession,
}
impl AssessmentStages for TargetStages<'_> {
    type Captured = (irlume_camera::Frame, irlume_camera::IrCaptureStats);
    type Detected = DetectedIr;
    type Aligned = Vec<u8>;
    type Embedded = Vec<f32>;
    fn preflight(&mut self) -> Result<(), IrFailure> {
        Ok(())
    }
    fn capture(
        &mut self,
        control: &irlume_camera::CaptureControl,
        deadline: Option<std::time::Instant>,
    ) -> Result<Self::Captured, IrFailure> {
        active(control, deadline)?;
        let captured = self
            .target
            .capture_with_stats_and_control(self.operation, control)
            .map_err(error_failure);
        active(control, deadline)?;
        captured
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
