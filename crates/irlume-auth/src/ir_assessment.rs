// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Private IR evidence shared by diagnostic and authentication consumers.

use super::*;

pub(super) struct IrAssessment {
    pub(super) matched: IrMatch,
    pub(super) signals: Signals,
    pub(super) pad: PadEvidence,
}

/// Whether the configured pair is the primary binding: the bound IR
/// identity must match; a bound RGB identity must match the configured
/// RGB side when both are known (an unbound side is unchecked, as
/// `GroupPair::matches` treats it on the dual path).
fn primary_binding_matches(
    enrollment: &irlume_core::storage::Enrollment,
    rgb_identity: Option<&str>,
    ir_identity: &str,
) -> Option<bool> {
    let binding = enrollment.camera_binding.as_ref()?;
    let ir = binding.ir.as_deref()?;
    let rgb_matches = match (binding.rgb.as_deref(), rgb_identity) {
        (Some(bound), Some(configured)) => bound == configured,
        _ => true,
    };
    Some(ir == ir_identity && rgb_matches)
}

fn enrollment_readiness(
    enrollment: &irlume_core::storage::Enrollment,
    rgb_identity: Option<&str>,
    ir_identity: &str,
    compatible_templates: usize,
) -> irlume_common::IrOnlyReadiness {
    use irlume_common::IrOnlyReadiness as Ready;
    if legacy_eye_policy(enrollment).is_err() {
        return Ready::IncompatibleEnrollment;
    }
    match primary_binding_matches(enrollment, rgb_identity, ir_identity) {
        None => return Ready::BindingUnavailable,
        Some(false) => return Ready::BindingMismatch,
        Some(true) => {}
    }
    if compatible_templates == 0 {
        return Ready::IncompatibleEnrollment;
    }
    Ready::ReadyForExperimentalAttempt
}

/// The validation hook that lifts the Phase 1 gate on the secondary scope
/// (ADR-0028 §7): set only in the daemon's environment during hardware
/// validation; the gate's removal is its own change.
fn secondary_route_enabled() -> bool {
    std::env::var_os("IRLUME_IR_ONLY_SECONDARY").is_some_and(|value| value == "1")
}

/// What an IR-only attempt scores against and the pin its grant boundary
/// re-checks (ADR-0028 §3-4). Resolved before the camera opens; hotplug or
/// configuration changes cannot redirect a resolved attempt (§6).
#[derive(Debug)]
pub(super) enum IrOnlyScope {
    /// The primary enrollment, pinned by the digest of the bytes it was
    /// parsed from.
    Primary {
        path: std::path::PathBuf,
        digest: String,
    },
    /// One active secondary group, pinned by the coordinator.
    Secondary(irlume_core::multi_camera::coordinator::SecondaryAuthContext),
}

impl IrOnlyScope {
    /// The wire report: the scope and, for a group, its 1-based store
    /// position (an ordinal, never an identity).
    pub(super) fn report(&self) -> (irlume_common::IrScope, Option<usize>) {
        match self {
            Self::Primary { .. } => (irlume_common::IrScope::Primary, None),
            Self::Secondary(context) => (
                irlume_common::IrScope::Secondary,
                Some(context.store_index() + 1),
            ),
        }
    }

    /// The grant boundary (ADR-0028 §4), run immediately before every
    /// IR-only grant: the primary scope re-reads the primary file and
    /// requires the pinned digest; the secondary scope is the dual path's
    /// serialized boundary step under the request key. Any change refuses.
    pub(super) fn boundary_refusal(
        &self,
        keys: &mut dyn irlume_core::template_key::TemplateKeySource,
    ) -> Option<Outcome> {
        use irlume_core::multi_camera::commit::GrantDecision;
        match self {
            Self::Primary { path, digest } => match std::fs::read(path) {
                Ok(bytes) if irlume_common::sha256_hex(&bytes) == *digest => None,
                Ok(_) => Some(Outcome::deny(
                    OutcomeKind::OtherDeny,
                    "enrollment changed during authentication; use your password",
                )),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(Outcome::deny(
                    OutcomeKind::OtherDeny,
                    "enrollment removed during authentication; use your password",
                )),
                Err(error) => Some(Outcome::deny(
                    OutcomeKind::SetupUnavailable,
                    format!("enrollment unreadable at the grant boundary: {error}"),
                )),
            },
            Self::Secondary(context) => match context.boundary_check_now_with(keys) {
                Ok(GrantDecision::Grant) => None,
                Ok(GrantDecision::Refuse(clause)) => Some(Outcome::deny(
                    OutcomeKind::OtherDeny,
                    format!("secondary grant refused at the boundary: {clause}"),
                )),
                Err(error) => Some(Outcome::deny(
                    OutcomeKind::SetupUnavailable,
                    format!("secondary grant boundary unreadable: {error}"),
                )),
            },
        }
    }
}

/// A resolved IR-only attempt: the enrollment it scores (the primary, or a
/// group's camera-scoped bridge) and its scope.
#[derive(Debug)]
pub(super) struct IrOnlyResolution {
    pub(super) enrollment: irlume_core::storage::Enrollment,
    pub(super) scope: IrOnlyScope,
}

/// A camera-free IR-only refusal with the scope it was found in, when one
/// resolved far enough to name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrOnlyRefusal {
    pub readiness: irlume_common::IrOnlyReadiness,
    pub scope: Option<irlume_common::IrScope>,
    pub scope_index: Option<usize>,
}

impl IrOnlyRefusal {
    fn unscoped(readiness: irlume_common::IrOnlyReadiness) -> Self {
        Self {
            readiness,
            scope: None,
            scope_index: None,
        }
    }

    fn secondary(readiness: irlume_common::IrOnlyReadiness, index: Option<usize>) -> Self {
        Self {
            readiness,
            scope: Some(irlume_common::IrScope::Secondary),
            scope_index: index,
        }
    }
}

/// The IR-only preflight report: the readiness, the closed target-refusal
/// cause, and the scope the configured pair resolved to when it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrOnlyPreflight {
    pub readiness: irlume_common::IrOnlyReadiness,
    pub target_issue: Option<irlume_common::IrTargetIssue>,
    pub scope: Option<irlume_common::IrScope>,
    pub scope_index: Option<usize>,
}

impl IrOnlyPreflight {
    fn target(
        readiness: irlume_common::IrOnlyReadiness,
        issue: irlume_common::IrTargetIssue,
    ) -> Self {
        Self {
            readiness,
            target_issue: Some(issue),
            scope: None,
            scope_index: None,
        }
    }

    fn unscoped(readiness: irlume_common::IrOnlyReadiness) -> Self {
        Self {
            readiness,
            target_issue: None,
            scope: None,
            scope_index: None,
        }
    }
}

impl From<IrOnlyRefusal> for IrOnlyPreflight {
    fn from(refusal: IrOnlyRefusal) -> Self {
        Self {
            readiness: refusal.readiness,
            target_issue: None,
            scope: refusal.scope,
            scope_index: refusal.scope_index,
        }
    }
}

/// The account's stores an IR-only resolution reads.
struct IrOnlyStores<'a> {
    user: &'a str,
    primary_path: &'a std::path::Path,
    secondary_path: &'a std::path::Path,
}

/// Resolve the configured pair `(rgb, ir)` to the scope an IR-only attempt
/// scores against (ADR-0028 §1-3): account policy on the real primary
/// first, then the primary binding, then an ACTIVE secondary group by
/// strict equality of both sides, read through `keys`. The primary keeps
/// precedence; a secondary refusal never falls back to another group, and
/// no device is discovered or opened (the identities are the only input).
/// `compatible_templates` counts the IR templates the live recognizer can
/// score in an enrollment; `secondary_enabled` is the Phase 1 gate (§7).
fn resolve_ir_only_scope_at(
    stores: &IrOnlyStores<'_>,
    primary: irlume_core::storage::PrimarySnapshot,
    (rgb, ir): (&str, &str),
    compatible_templates: &dyn Fn(&irlume_core::storage::Enrollment) -> usize,
    keys: &mut dyn irlume_core::template_key::TemplateKeySource,
    secondary_enabled: bool,
) -> Result<IrOnlyResolution, IrOnlyRefusal> {
    use irlume_common::IrOnlyReadiness as Ready;
    use irlume_core::multi_camera::coordinator::{PinError, SecondaryAuthContext};
    let irlume_core::storage::PrimarySnapshot {
        enrollment, bytes, ..
    } = primary;
    // Today's primary readiness, in its order: account policy on the real
    // primary, then the binding, then the compatible templates. Only a
    // binding mismatch goes on to the secondary store.
    let primary_readiness = enrollment_readiness(
        &enrollment,
        Some(rgb),
        ir,
        compatible_templates(&enrollment),
    );
    match primary_readiness {
        Ready::ReadyForExperimentalAttempt => {
            return Ok(IrOnlyResolution {
                scope: IrOnlyScope::Primary {
                    path: stores.primary_path.to_owned(),
                    digest: irlume_common::sha256_hex(&bytes),
                },
                enrollment,
            });
        }
        Ready::BindingMismatch => {}
        Ready::IncompatibleEnrollment if legacy_eye_policy(&enrollment).is_ok() => {
            return Err(IrOnlyRefusal {
                readiness: Ready::IncompatibleEnrollment,
                scope: Some(irlume_common::IrScope::Primary),
                scope_index: None,
            });
        }
        other => return Err(IrOnlyRefusal::unscoped(other)),
    }
    // No existence pre-check: the pin resolves the commit journal first, so
    // a store missing after a crashed publication is recovered rather than
    // reported absent; an absent store is then a binding mismatch.
    let pinned = SecondaryAuthContext::pin_strict_with_source(
        irlume_core::multi_camera::coordinator::StrictPinStores {
            user: stores.user,
            secondary_path: stores.secondary_path,
            primary_path: stores.primary_path,
        },
        &enrollment,
        &bytes,
        rgb,
        ir,
        keys,
    );
    let context = match pinned {
        Ok(context) => context,
        Err(PinError::GroupInactive { index, detail }) => {
            irlume_common::dlog!("ir-only: secondary group inactive: {detail}");
            return Err(IrOnlyRefusal::secondary(
                Ready::SecondaryInactive,
                Some(index + 1),
            ));
        }
        Err(error) => {
            // No strict match, an ambiguous, absent, foreign-owned or
            // unusable store: the binding-mismatch refusal answers, never
            // store order.
            irlume_common::dlog!("ir-only: secondary pin refused: {error}");
            return Err(IrOnlyRefusal::unscoped(Ready::BindingMismatch));
        }
    };
    let index = Some(context.store_index() + 1);
    if !secondary_enabled {
        return Err(IrOnlyRefusal::secondary(Ready::SecondaryUnvalidated, index));
    }
    let scoped = context.group_view().matching_enrollment(stores.user);
    if compatible_templates(&scoped) == 0 {
        return Err(IrOnlyRefusal::secondary(
            Ready::IncompatibleEnrollment,
            index,
        ));
    }
    Ok(IrOnlyResolution {
        enrollment: scoped,
        scope: IrOnlyScope::Secondary(context),
    })
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
    fn target_issue_mapping_is_closed_and_never_exports_error_prose() {
        use irlume_camera::IrTargetError as Error;
        use irlume_common::IrTargetIssue as Issue;
        for (error, expected) in [
            (Error::Unconfigured, Issue::Unconfigured),
            (
                Error::InvalidEndpoint("private endpoint".into()),
                Issue::Unavailable,
            ),
            (
                Error::UnsupportedTopology("private topology".into()),
                Issue::UnsupportedTopology,
            ),
            (
                Error::BindingUnavailable("private binding".into()),
                Issue::BindingUnavailable,
            ),
            (Error::Changed, Issue::Changed),
        ] {
            assert_eq!(target_issue(&error), expected);
            assert!(!serde_json::to_string(&target_issue(&error))
                .unwrap()
                .contains("private"));
        }
    }

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
            enrollment_readiness(&enrollment, None, "target", 1),
            Ready::BindingUnavailable
        );
        enrollment.camera_binding = Some(CameraBinding {
            rgb: Some("irrelevant RGB".into()),
            ir: None,
        });
        assert_eq!(
            enrollment_readiness(&enrollment, None, "target", 1),
            Ready::BindingUnavailable
        );
        enrollment.camera_binding.as_mut().unwrap().ir = Some("different".into());
        assert_eq!(
            enrollment_readiness(&enrollment, None, "target", 1),
            Ready::BindingMismatch
        );
        enrollment.camera_binding.as_mut().unwrap().ir = Some("target".into());
        assert_eq!(
            enrollment_readiness(&enrollment, None, "target", 0),
            Ready::IncompatibleEnrollment
        );
        assert_eq!(
            enrollment_readiness(&enrollment, None, "target", 1),
            Ready::ReadyForExperimentalAttempt
        );
        enrollment.require_eyes_open = true;
        assert_eq!(
            enrollment_readiness(&enrollment, None, "target", 1),
            Ready::IncompatibleEnrollment
        );
    }

    /// ADR-0028 fixtures: a primary bound to (RGB-P, IR-P) and a secondary
    /// store beside it, at paths under a private temp dir. Nothing reads
    /// the state dir or the environment.
    mod adr28 {
        use super::super::*;
        use irlume_core::multi_camera::{
            CameraGroupId, GroupPair, SecondaryGroup, SecondaryProfileScans, SecondaryStore,
            SECONDARY_STORE_VERSION,
        };
        use irlume_core::storage::{CameraBinding, Enrollment, FaceProfile, FaceScan};
        use irlume_core::template_key::RequestTemplateKey;
        use std::path::{Path, PathBuf};

        pub(super) const USER: &str = "alice";
        pub(super) const RGB_P: &str = "046d:085e:P";
        pub(super) const IR_P: &str = "046d:085e:P-ir";
        pub(super) const RGB_A: &str = "1bcf:28c4:A";
        pub(super) const RGB_B: &str = "1bcf:28c4:B";
        pub(super) const IR_X: &str = "1bcf:28c4:X-ir";

        pub(super) struct Rig {
            pub(super) dir: PathBuf,
        }

        impl Rig {
            pub(super) fn new(tag: &str) -> Self {
                let dir = std::env::temp_dir()
                    .join(format!("irlume-auth-adr28-{tag}-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).expect("dir");
                Self { dir }
            }

            pub(super) fn primary_path(&self) -> PathBuf {
                self.dir.join(format!("{USER}.json"))
            }

            pub(super) fn secondary_path(&self) -> PathBuf {
                self.dir.join("cameras").join(format!("{USER}.json"))
            }

            pub(super) fn stores(&self) -> (PathBuf, PathBuf) {
                (self.primary_path(), self.secondary_path())
            }

            /// Writes the primary (plaintext, or sealed under `key`) and
            /// returns its exact bytes.
            pub(super) fn write_primary(
                &self,
                enrollment: &Enrollment,
                key: Option<&[u8]>,
            ) -> Vec<u8> {
                let bytes = irlume_core::storage::serialize_enrollment(enrollment, key)
                    .expect("primary bytes");
                std::fs::write(self.primary_path(), &bytes).expect("primary write");
                bytes
            }

            /// Writes a plaintext secondary store declaring `owner`.
            pub(super) fn write_secondary_owned(
                &self,
                owner: &str,
                groups: Vec<SecondaryGroup>,
                primary_bytes: &[u8],
            ) {
                self.write_store(owner, groups, primary_bytes, None);
            }

            /// Writes a secondary store activated against `primary_bytes`.
            pub(super) fn write_secondary(
                &self,
                groups: Vec<SecondaryGroup>,
                primary_bytes: &[u8],
                key: Option<&[u8]>,
            ) {
                self.write_store(USER, groups, primary_bytes, key);
            }

            fn write_store(
                &self,
                owner: &str,
                groups: Vec<SecondaryGroup>,
                primary_bytes: &[u8],
                key: Option<&[u8]>,
            ) {
                let store = SecondaryStore {
                    format_version: SECONDARY_STORE_VERSION,
                    owner: owner.into(),
                    generation: 1,
                    primary_snapshot_sha256: irlume_common::sha256_hex(primary_bytes),
                    groups,
                };
                std::fs::create_dir_all(self.secondary_path().parent().unwrap()).unwrap();
                let key = key.map(<[u8]>::to_vec);
                irlume_core::multi_camera::save_secondary_resolved(
                    &self.secondary_path(),
                    &store,
                    move |_| {
                        Ok(key
                            .clone()
                            .map(irlume_core::template_key::UnsealedKey::from))
                    },
                )
                .expect("secondary write");
            }
        }

        impl Drop for Rig {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }

        pub(super) fn scan(pitch: f32, with_ir: bool) -> FaceScan {
            FaceScan {
                name: "s".into(),
                rgb: vec![0.5; 8],
                ir: with_ir.then(|| vec![0.25; 4]),
                ir_space: Some("raw".into()),
                embed_space: Some("embed:test".into()),
                ir_center_edge_ratio: 2.0,
                ir_brightness: 1.0,
                pitch,
            }
        }

        pub(super) fn primary() -> Enrollment {
            Enrollment {
                user: USER.into(),
                profiles: vec![FaceProfile {
                    name: "main".into(),
                    scans: vec![scan(0.1, true), scan(0.12, true), scan(0.14, true)],
                    ir_calib: None,
                    ir_calibs: Default::default(),
                }],
                camera_binding: Some(CameraBinding {
                    rgb: Some(RGB_P.into()),
                    ir: Some(IR_P.into()),
                }),
                ..Enrollment::default()
            }
        }

        pub(super) fn group(
            id: &str,
            rgb: Option<&str>,
            ir: Option<&str>,
            pitch: f32,
            with_ir: bool,
        ) -> SecondaryGroup {
            SecondaryGroup {
                id: CameraGroupId::new(id.into()).unwrap(),
                pair: GroupPair {
                    rgb: rgb.map(str::to_owned),
                    ir: ir.map(str::to_owned),
                },
                profiles: vec![SecondaryProfileScans {
                    ir_calibs: Default::default(),
                    profile: "main".into(),
                    scans: vec![scan(pitch, with_ir), scan(pitch, with_ir)],
                }],
            }
        }

        /// The recognizer stand-in: every scan carrying an IR template is
        /// compatible.
        pub(super) fn compatible(enrollment: &Enrollment) -> usize {
            enrollment
                .profiles
                .iter()
                .flat_map(|profile| profile.scans.iter())
                .filter(|scan| scan.ir.is_some())
                .count()
        }

        pub(super) fn snapshot(
            enrollment: Enrollment,
            bytes: &[u8],
            key: Option<&[u8]>,
        ) -> irlume_core::storage::PrimarySnapshot {
            irlume_core::storage::PrimarySnapshot {
                enrollment,
                key: key.map(|key| irlume_core::template_key::UnsealedKey::from(key.to_vec())),
                bytes: bytes.to_vec(),
            }
        }

        pub(super) fn resolve(
            rig: &Rig,
            enrollment: Enrollment,
            bytes: &[u8],
            pair: (&str, &str),
            keys: &mut RequestTemplateKey,
            enabled: bool,
        ) -> Result<IrOnlyResolution, IrOnlyRefusal> {
            let (primary_path, secondary_path) = rig.stores();
            resolve_ir_only_scope_at(
                &IrOnlyStores {
                    user: USER,
                    primary_path: &primary_path,
                    secondary_path: &secondary_path,
                },
                snapshot(enrollment, bytes, None),
                pair,
                &compatible,
                keys,
                enabled,
            )
        }

        pub(super) fn readiness(
            result: &Result<IrOnlyResolution, IrOnlyRefusal>,
        ) -> irlume_common::IrOnlyReadiness {
            match result {
                Ok(_) => irlume_common::IrOnlyReadiness::ReadyForExperimentalAttempt,
                Err(refusal) => refusal.readiness,
            }
        }

        pub(super) fn no_key() -> RequestTemplateKey {
            RequestTemplateKey::with_unsealer(|_| Ok(None))
        }

        /// Standard base64 without a dependency: the journal payload field.
        pub(super) fn base64_std(bytes: &[u8]) -> String {
            const TABLE: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let mut word = [0u8; 3];
                word[..chunk.len()].copy_from_slice(chunk);
                let n = (u32::from(word[0]) << 16) | (u32::from(word[1]) << 8) | u32::from(word[2]);
                for i in 0..4 {
                    if i <= chunk.len() {
                        out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
                    } else {
                        out.push('=');
                    }
                }
            }
            out
        }

        pub(super) fn digest_of(path: &Path) -> String {
            irlume_common::sha256_hex(&std::fs::read(path).unwrap())
        }
    }

    /// ADR-0028 acceptance: resolution, pure.
    #[test]
    fn ir_only_scope_resolves_the_primary_before_any_secondary_group() {
        use adr28::*;
        use irlume_common::IrScope;
        let rig = Rig::new("primary-first");
        let bytes = rig.write_primary(&primary(), None);
        rig.write_secondary(
            vec![group("desk", Some(RGB_P), Some(IR_P), 0.5, true)],
            &bytes,
            None,
        );
        // The primary's own pair resolves to the primary even when a group
        // duplicates it.
        let resolution =
            resolve(&rig, primary(), &bytes, (RGB_P, IR_P), &mut no_key(), true).expect("primary");
        assert_eq!(resolution.scope.report(), (IrScope::Primary, None));
        match &resolution.scope {
            IrOnlyScope::Primary { path, digest } => {
                assert_eq!(path, &rig.primary_path());
                assert_eq!(digest, &irlume_common::sha256_hex(&bytes));
            }
            IrOnlyScope::Secondary(_) => panic!("primary scope expected"),
        }
        assert_eq!(resolution.enrollment.profiles[0].scans[0].pitch, 0.1);
        // An unbound primary is BindingUnavailable, as today; no group is
        // consulted.
        let mut unbound = primary();
        unbound.camera_binding = None;
        let unbound_bytes = rig.write_primary(&unbound, None);
        assert_eq!(
            readiness(&resolve(
                &rig,
                unbound,
                &unbound_bytes,
                (RGB_P, IR_P),
                &mut no_key(),
                true
            )),
            irlume_common::IrOnlyReadiness::BindingUnavailable
        );
        // A bound primary whose IR templates the recognizer cannot score is
        // IncompatibleEnrollment in the primary scope.
        let mut foreign = primary();
        for scan in &mut foreign.profiles[0].scans {
            scan.ir = None;
        }
        let foreign_bytes = rig.write_primary(&foreign, None);
        let refusal = resolve(
            &rig,
            foreign,
            &foreign_bytes,
            (RGB_P, IR_P),
            &mut no_key(),
            true,
        )
        .unwrap_err();
        assert_eq!(
            refusal.readiness,
            irlume_common::IrOnlyReadiness::IncompatibleEnrollment
        );
        assert_eq!(refusal.scope, Some(IrScope::Primary));
    }

    #[test]
    fn ir_only_scope_resolves_a_strict_secondary_match_to_its_group_only() {
        use adr28::*;
        use irlume_common::{IrOnlyReadiness as Ready, IrScope};
        let rig = Rig::new("strict");
        let bytes = rig.write_primary(&primary(), None);
        // Two groups share IR-X with different RGB sides (ADR-0024 permits
        // shared endpoints); a one-sided (None, IR-X) group sits beside them.
        rig.write_secondary(
            vec![
                group("a", Some(RGB_A), Some(IR_X), 0.5, true),
                group("b", Some(RGB_B), Some(IR_X), 0.7, true),
                group("one-sided", None, Some(IR_X), 0.9, true),
            ],
            &bytes,
            None,
        );
        // The configured pair naming group B resolves to B: position 2,
        // scoring B's scans and nothing of the primary's.
        let resolution =
            resolve(&rig, primary(), &bytes, (RGB_B, IR_X), &mut no_key(), true).expect("group b");
        assert_eq!(resolution.scope.report(), (IrScope::Secondary, Some(2)));
        let pitches: Vec<f32> = resolution.enrollment.profiles[0]
            .scans
            .iter()
            .map(|scan| scan.pitch)
            .collect();
        assert_eq!(pitches, vec![0.7, 0.7]);
        assert_eq!(resolution.enrollment.profiles.len(), 1);
        // Naming group A resolves to A, never the one-sided group.
        let resolution =
            resolve(&rig, primary(), &bytes, (RGB_A, IR_X), &mut no_key(), true).expect("group a");
        assert_eq!(resolution.scope.report(), (IrScope::Secondary, Some(1)));
        // A configured pair carrying only the IR identity, or an RGB side no
        // group has, is BindingMismatch: the one-sided group never wildcards
        // and store order never decides.
        for pair in [("", IR_X), ("046d:0000:other", IR_X)] {
            let refusal = resolve(&rig, primary(), &bytes, pair, &mut no_key(), true).unwrap_err();
            assert_eq!(refusal.readiness, Ready::BindingMismatch, "{pair:?}");
            assert_eq!(refusal.scope, None);
        }
        // No group at all for the pair: BindingMismatch.
        assert_eq!(
            readiness(&resolve(
                &rig,
                primary(),
                &bytes,
                (RGB_A, "0000:0000:none"),
                &mut no_key(),
                true
            )),
            Ready::BindingMismatch
        );
    }

    #[test]
    fn ir_only_scope_refuses_duplicate_pairs_and_an_absent_store() {
        use adr28::*;
        use irlume_common::IrOnlyReadiness as Ready;
        let rig = Rig::new("duplicates");
        let bytes = rig.write_primary(&primary(), None);
        // No store: the binding mismatch answers.
        assert_eq!(
            readiness(&resolve(
                &rig,
                primary(),
                &bytes,
                (RGB_A, IR_X),
                &mut no_key(),
                true
            )),
            Ready::BindingMismatch
        );
        // Two groups with identical pairs: ambiguous, refused as
        // BindingMismatch rather than resolved by store order.
        rig.write_secondary(
            vec![
                group("first", Some(RGB_A), Some(IR_X), 0.5, true),
                group("second", Some(RGB_A), Some(IR_X), 0.7, true),
            ],
            &bytes,
            None,
        );
        let refusal =
            resolve(&rig, primary(), &bytes, (RGB_A, IR_X), &mut no_key(), true).unwrap_err();
        assert_eq!(refusal.readiness, Ready::BindingMismatch);
        assert_eq!(refusal.scope, None);
    }

    #[test]
    fn ir_only_scope_reports_inactive_unvalidated_and_incompatible_groups() {
        use adr28::*;
        use irlume_common::{IrOnlyReadiness as Ready, IrScope};
        let rig = Rig::new("causes");
        let bytes = rig.write_primary(&primary(), None);
        rig.write_secondary(
            vec![
                group("a", Some(RGB_A), Some(IR_X), 0.5, true),
                group("no-ir", Some(RGB_B), Some(IR_X), 0.7, false),
            ],
            &bytes,
            None,
        );
        // The Phase 1 gate: a matched, active group without the validation
        // hook is SecondaryUnvalidated, named with its position.
        let refusal =
            resolve(&rig, primary(), &bytes, (RGB_A, IR_X), &mut no_key(), false).unwrap_err();
        assert_eq!(refusal.readiness, Ready::SecondaryUnvalidated);
        assert_eq!(
            (refusal.scope, refusal.scope_index),
            (Some(IrScope::Secondary), Some(1))
        );
        // A matched group whose IR view is empty is IncompatibleEnrollment,
        // as the primary would be.
        let refusal =
            resolve(&rig, primary(), &bytes, (RGB_B, IR_X), &mut no_key(), true).unwrap_err();
        assert_eq!(refusal.readiness, Ready::IncompatibleEnrollment);
        assert_eq!(
            (refusal.scope, refusal.scope_index),
            (Some(IrScope::Secondary), Some(2))
        );
        // The primary changed since the store was authorized: the exact
        // group is found but the store is inactive.
        let mut changed = primary();
        changed.profiles[0].scans.push(scan(0.3, true));
        let changed_bytes = rig.write_primary(&changed, None);
        let refusal = resolve(
            &rig,
            changed,
            &changed_bytes,
            (RGB_A, IR_X),
            &mut no_key(),
            true,
        )
        .unwrap_err();
        assert_eq!(refusal.readiness, Ready::SecondaryInactive);
        assert_eq!(
            (refusal.scope, refusal.scope_index),
            (Some(IrScope::Secondary), Some(1)),
            "an inactive group is still named by its position"
        );
    }

    /// A store at the account's path that names another owner never lends
    /// its groups to this account, whatever its digest says.
    #[test]
    fn ir_only_scope_refuses_a_store_naming_another_owner() {
        use adr28::*;
        use irlume_common::IrOnlyReadiness as Ready;
        let rig = Rig::new("owner");
        let bytes = rig.write_primary(&primary(), None);
        rig.write_secondary_owned(
            "mallory",
            vec![group("a", Some(RGB_A), Some(IR_X), 0.5, true)],
            &bytes,
        );
        let refusal =
            resolve(&rig, primary(), &bytes, (RGB_A, IR_X), &mut no_key(), true).unwrap_err();
        assert_eq!(refusal.readiness, Ready::BindingMismatch);
        assert_eq!(refusal.scope, None);
    }

    /// A publication that crashed after journaling its intent and before the
    /// rename leaves no store file; the resolution recovers the journal
    /// forward instead of reporting the store absent (ADR-0024 §4.1).
    #[test]
    fn ir_only_scope_recovers_a_journaled_store_before_resolving() {
        use adr28::*;
        use irlume_common::IrScope;
        let rig = Rig::new("journal");
        let bytes = rig.write_primary(&primary(), None);
        rig.write_secondary(
            vec![group("a", Some(RGB_A), Some(IR_X), 0.5, true)],
            &bytes,
            None,
        );
        // Model the crash: the intent journal carries the committed store
        // and the store file itself is missing.
        let store_path = rig.secondary_path();
        let store_bytes = std::fs::read(&store_path).unwrap();
        std::fs::remove_file(&store_path).unwrap();
        let intent = serde_json::json!({
            "format_version": irlume_core::multi_camera::commit::INTENT_FORMAT_VERSION,
            "generation": 1,
            "primary_snapshot_sha256": irlume_common::sha256_hex(&bytes),
            "new_secondary_b64": base64_std(&store_bytes),
        });
        std::fs::write(
            irlume_core::multi_camera::commit::intent_path_for(&store_path),
            serde_json::to_vec(&intent).unwrap(),
        )
        .unwrap();
        let resolution = resolve(&rig, primary(), &bytes, (RGB_A, IR_X), &mut no_key(), true)
            .expect("recovered");
        assert_eq!(resolution.scope.report(), (IrScope::Secondary, Some(1)));
        assert!(store_path.exists(), "the journal was committed");
    }

    /// ADR-0028 §2: account policy is checked on the REAL primary before the
    /// scoped view exists, so a legacy enrollment is IncompatibleEnrollment
    /// on the secondary scope exactly as on the primary.
    #[test]
    fn ir_only_scope_applies_account_policy_to_the_real_primary_for_every_scope() {
        use adr28::*;
        use irlume_common::IrOnlyReadiness as Ready;
        let rig = Rig::new("legacy-policy");
        let mut legacy = primary();
        legacy.require_eyes_open = true;
        let bytes = rig.write_primary(&legacy, None);
        rig.write_secondary(
            vec![group("a", Some(RGB_A), Some(IR_X), 0.5, true)],
            &bytes,
            None,
        );
        assert!(legacy_eye_policy(&legacy).is_err());
        for pair in [(RGB_P, IR_P), (RGB_A, IR_X)] {
            let refusal =
                resolve(&rig, legacy.clone(), &bytes, pair, &mut no_key(), true).unwrap_err();
            assert_eq!(refusal.readiness, Ready::IncompatibleEnrollment, "{pair:?}");
            assert_eq!(refusal.scope, None, "refused before any scope resolved");
        }
    }

    /// ADR-0028 §4: the grant boundary for both scopes.
    #[test]
    fn ir_only_grant_boundary_refuses_any_store_change_for_both_scopes() {
        use adr28::*;
        let rig = Rig::new("boundary");
        let bytes = rig.write_primary(&primary(), None);
        rig.write_secondary(
            vec![group("a", Some(RGB_A), Some(IR_X), 0.5, true)],
            &bytes,
            None,
        );
        let primary_scope = resolve(&rig, primary(), &bytes, (RGB_P, IR_P), &mut no_key(), true)
            .expect("primary")
            .scope;
        let secondary_scope = resolve(&rig, primary(), &bytes, (RGB_A, IR_X), &mut no_key(), true)
            .expect("secondary")
            .scope;
        // Unchanged stores grant.
        assert!(primary_scope.boundary_refusal(&mut no_key()).is_none());
        assert!(secondary_scope.boundary_refusal(&mut no_key()).is_none());
        // Removing the group refuses the secondary scope; the primary scope
        // never reads the secondary store.
        rig.write_secondary(
            vec![group("b", Some(RGB_B), Some(IR_X), 0.7, true)],
            &bytes,
            None,
        );
        let refusal = secondary_scope
            .boundary_refusal(&mut no_key())
            .expect("group removed");
        assert!(!refusal.granted);
        assert_eq!(refusal.kind, OutcomeKind::OtherDeny);
        assert!(primary_scope.boundary_refusal(&mut no_key()).is_none());
        // Replacing the store with one holding the same group under a new
        // generation refuses too: the pin is the generation, not the id.
        rig.write_secondary(
            vec![group("a", Some(RGB_A), Some(IR_X), 0.5, true)],
            &bytes,
            None,
        );
        let mut replaced = irlume_core::multi_camera::load_secondary(&rig.secondary_path())
            .unwrap()
            .unwrap();
        replaced.generation += 1;
        irlume_core::multi_camera::save_secondary_resolved(
            &rig.secondary_path(),
            &replaced,
            |_| Ok(None),
        )
        .unwrap();
        assert_eq!(
            secondary_scope
                .boundary_refusal(&mut no_key())
                .map(|o| o.kind),
            Some(OutcomeKind::OtherDeny)
        );
        // Changing the primary file refuses BOTH scopes: the secondary store
        // deactivates and the primary digest no longer matches.
        let mut changed = primary();
        changed.profiles[0].scans.push(scan(0.3, true));
        let changed_bytes = rig.write_primary(&changed, None);
        assert_ne!(
            digest_of(&rig.primary_path()),
            irlume_common::sha256_hex(&bytes)
        );
        rig.write_secondary(
            vec![group("a", Some(RGB_A), Some(IR_X), 0.5, true)],
            &changed_bytes,
            None,
        );
        let refusal = primary_scope
            .boundary_refusal(&mut no_key())
            .expect("primary changed");
        assert_eq!(refusal.kind, OutcomeKind::OtherDeny);
        assert!(
            refusal.reason.contains("enrollment changed"),
            "{}",
            refusal.reason
        );
        assert_eq!(
            secondary_scope
                .boundary_refusal(&mut no_key())
                .map(|o| o.kind),
            Some(OutcomeKind::OtherDeny)
        );
        // Removing the primary during capture refuses the primary scope
        // with its own cause, and never as an unreadable-store error.
        std::fs::remove_file(rig.primary_path()).unwrap();
        let refusal = primary_scope
            .boundary_refusal(&mut no_key())
            .expect("primary removed");
        assert_eq!(refusal.kind, OutcomeKind::OtherDeny);
        assert!(refusal.reason.contains("removed"), "{}", refusal.reason);
    }

    /// ADR-0028 §5: with the load's key adopted, resolution and the boundary
    /// borrow it and the request never unseals; without adoption the request
    /// unseals exactly once for both.
    #[test]
    fn ir_only_secondary_scope_unseals_the_request_key_at_most_once() {
        use adr28::*;
        use irlume_core::template_key::RequestTemplateKey;
        let rig = Rig::new("one-unseal");
        let key = irlume_core::crypto::generate_key();
        let bytes = rig.write_primary(&primary(), Some(&key));
        rig.write_secondary(
            vec![group("a", Some(RGB_A), Some(IR_X), 0.5, true)],
            &bytes,
            Some(&key),
        );
        let counting = || {
            let key = key.clone();
            RequestTemplateKey::with_unsealer(move |user| {
                assert_eq!(user, USER);
                Ok(Some(key.clone()))
            })
        };
        let (primary_path, secondary_path) = rig.stores();
        let stores = IrOnlyStores {
            user: USER,
            primary_path: &primary_path,
            secondary_path: &secondary_path,
        };
        // Adopted from the load, as the authentication path and the
        // preflight both do: zero unseals through the request source.
        let mut adopted = counting();
        adopted.adopt(USER, Some(key.clone()));
        let resolution = resolve_ir_only_scope_at(
            &stores,
            snapshot(primary(), &bytes, Some(&key)),
            (RGB_A, IR_X),
            &compatible,
            &mut adopted,
            true,
        )
        .expect("secondary");
        assert!(resolution.scope.boundary_refusal(&mut adopted).is_none());
        assert_eq!(adopted.unseals(), 0);
        // Not adopted: one unseal serves the store read and the boundary.
        let mut lazy = counting();
        let resolution = resolve_ir_only_scope_at(
            &stores,
            snapshot(primary(), &bytes, Some(&key)),
            (RGB_A, IR_X),
            &compatible,
            &mut lazy,
            true,
        )
        .expect("secondary");
        assert!(resolution.scope.boundary_refusal(&mut lazy).is_none());
        assert_eq!(lazy.unseals(), 1);
    }

    #[test]
    fn ir_only_readiness_wire_mapping_keeps_the_pre_change_vocabulary() {
        use irlume_common::IrOnlyReadiness as Ready;
        for (detail, compatible) in [
            (Ready::SecondaryInactive, Ready::BindingMismatch),
            (Ready::SecondaryUnvalidated, Ready::BindingMismatch),
            (Ready::Unknown, Ready::BindingMismatch),
            (Ready::BindingMismatch, Ready::BindingMismatch),
            (
                Ready::ReadyForExperimentalAttempt,
                Ready::ReadyForExperimentalAttempt,
            ),
            (Ready::IncompatibleEnrollment, Ready::IncompatibleEnrollment),
        ] {
            assert_eq!(detail.wire_compatible(), compatible);
        }
        assert!(readiness_refusal(Ready::SecondaryInactive)
            .reason
            .contains("inactive since the primary enrollment changed"));
        assert!(readiness_refusal(Ready::SecondaryUnvalidated)
            .reason
            .contains("not yet validated"));
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
        Ready::SecondaryInactive => {
            "this camera's authorization is inactive since the primary enrollment changed; \
             remove your added cameras and add back the ones you use, or use your password"
        }
        Ready::SecondaryUnvalidated => {
            "IR-only on additional cameras is not yet validated on this build; use your password"
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

fn target_issue(error: &irlume_camera::IrTargetError) -> irlume_common::IrTargetIssue {
    use irlume_camera::IrTargetError as Error;
    use irlume_common::IrTargetIssue as Issue;
    match error {
        Error::Unconfigured => Issue::Unconfigured,
        Error::InvalidEndpoint(_) => Issue::Unavailable,
        Error::UnsupportedTopology(_) => Issue::UnsupportedTopology,
        Error::BindingUnavailable(_) => Issue::BindingUnavailable,
        Error::Changed => Issue::Changed,
    }
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

    fn compatible_ir_templates(&self, enrollment: &irlume_core::storage::Enrollment) -> usize {
        self.ir_match(enrollment, &[0.0; EMBED_DIM]).n_templates
    }

    /// Resolve the configured pair to the scope an IR-only attempt scores
    /// against (ADR-0028 §1-3), reading the account's stores through `keys`.
    fn resolve_ir_only_scope(
        &self,
        user: &str,
        primary: irlume_core::storage::PrimarySnapshot,
        target: &irlume_camera::IrCaptureTarget,
        keys: &mut dyn irlume_core::template_key::TemplateKeySource,
    ) -> Result<IrOnlyResolution, IrOnlyRefusal> {
        resolve_ir_only_scope_at(
            &IrOnlyStores {
                user,
                primary_path: &irlume_core::multi_camera::primary_enrollment_path(user),
                secondary_path: &irlume_core::multi_camera::secondary_store_path(user),
            },
            primary,
            (target.rgb_identity(), target.identity()),
            &|enrollment| self.compatible_ir_templates(enrollment),
            keys,
            secondary_route_enabled(),
        )
    }

    // Retain the existing helper lifetime rule: a cancelled/expired caller
    // drains the loader before returning. No camera or lease is held here.
    pub(super) fn load_ir_enrollment(
        &self,
        user: &str,
        window: AuthenticationWindow,
        read_only: bool,
        diagnostics: Option<&dyn irlume_common::diagnostics::DiagnosticSink>,
    ) -> irlume_common::Result<Option<irlume_core::storage::PrimarySnapshot>> {
        self.check_authentication_completion(window)?;
        // This route dispatches before the dual-sensor loader's timing site.
        // Include resolution and any cancellation drain, but not a request
        // rejected before loading. Read-only readiness probes pass no sink.
        let _timer = diagnostics.map(|sink| {
            TraceStageTimer::new(sink, irlume_common::diagnostics::TraceStage::EnrollmentLoad)
        });
        let (sender, receiver) = std::sync::mpsc::channel();
        let user = user.to_string();
        std::thread::Builder::new()
            .name("irlume-ir-enrollment".into())
            .spawn(move || {
                // The snapshot keeps the key and the bytes: the caller
                // adopts the key into its request source and pins the
                // scope by the bytes (ADR-0028 §4-5).
                let loaded = if read_only {
                    irlume_core::storage::load_snapshot_read_only(&user)
                } else {
                    irlume_core::storage::load_snapshot(&user)
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
            Ok(snapshot) => Ok(Some(snapshot)),
            Err(LoaderExit::NotEnrolled) => Ok(None),
            Err(LoaderExit::Fallback(error)) => Err(error),
        }
    }

    /// Check experimental IR prerequisites without opening video nodes or
    /// changing enrollment. Template-key unseal may be needed for protected data.
    /// Readiness does not establish capture latency, identity or qualification.
    pub fn ir_only_preflight(&self, user: &str) -> irlume_common::IrOnlyReadiness {
        self.ir_only_preflight_details(user).readiness
    }

    /// Preserve the closed target-refusal cause without repeating resolution or
    /// exposing driver/path error strings, and name the scope the configured
    /// pair resolved to (ADR-0028 §3). This never discovers or opens a camera.
    /// Not an authentication request: the key its read-only load unsealed is
    /// lent to the secondary store read for this call only (§5).
    pub fn ir_only_preflight_details(&self, user: &str) -> IrOnlyPreflight {
        use irlume_common::IrOnlyReadiness as Ready;
        use irlume_common::IrTargetIssue as Issue;
        let window = AuthenticationWindow::new(GRACE_WINDOW_MS);
        let target = match irlume_camera::configured_ir_target() {
            Ok(target) => target,
            Err(error) => {
                return IrOnlyPreflight::target(Ready::TargetUnavailable, target_issue(&error))
            }
        };
        if !selected_ir_available(target.endpoint()) {
            return IrOnlyPreflight::target(Ready::TargetUnavailable, Issue::Unavailable);
        }
        if let Err(error) = target.validate() {
            return IrOnlyPreflight::target(Ready::TargetUnavailable, target_issue(&error));
        }
        if let Some(refusal) = model_readiness(
            true,
            self.ir_adapter_required,
            self.has_ir_adapter(),
            self.has_pad_ir(),
        ) {
            return IrOnlyPreflight::unscoped(refusal);
        }
        let mut snapshot = match self.load_ir_enrollment(user, window, true, None) {
            Ok(Some(snapshot)) => snapshot,
            _ => return IrOnlyPreflight::unscoped(Ready::EnrollmentUnavailable),
        };
        if self.check_authentication_completion(window).is_err() {
            return IrOnlyPreflight::unscoped(Ready::Unavailable);
        }
        // The one unsealed allocation moves into the call's source; nothing
        // keeps a second copy.
        let mut keys = irlume_core::template_key::RequestTemplateKey::production();
        keys.adopt(user, snapshot.key.take());
        match self.resolve_ir_only_scope(user, snapshot, &target, &mut keys) {
            Ok(resolution) => {
                let (scope, scope_index) = resolution.scope.report();
                IrOnlyPreflight {
                    readiness: Ready::ReadyForExperimentalAttempt,
                    target_issue: None,
                    scope: Some(scope),
                    scope_index,
                }
            }
            Err(refusal) => refusal.into(),
        }
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
        let mut snapshot = match self.load_ir_enrollment(user, window, false, Some(diagnostics))? {
            Some(snapshot) => snapshot,
            None => return Ok(readiness_refusal(Ready::EnrollmentUnavailable)),
        };
        // The request key (ADR-0025 §3, ADR-0028 §5): the load's one key
        // allocation moves into the request source, which lends it to the
        // secondary store read and the grant boundary.
        self.request_key().adopt(user, snapshot.key.take());
        let resolved = {
            let mut keys = self.request_key();
            self.resolve_ir_only_scope(user, snapshot, &target, &mut *keys)
        };
        let IrOnlyResolution { enrollment, scope } = match resolved {
            Ok(resolution) => resolution,
            Err(refusal) => return Ok(readiness_refusal(refusal.readiness)),
        };
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
                        &scope,
                        &target,
                        &operation,
                        diagnostics,
                    ),
                    false,
                    None::<()>,
                )
            },
            std::time::Instant::now,
        )
        .0
    }

    fn authenticate_ir_target_attempt(
        &mut self,
        enrollment: &irlume_core::storage::Enrollment,
        scope: &IrOnlyScope,
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
            Ok(assessment) => {
                let outcome = assessed_outcome(&assessment, enrollment, adapter);
                if outcome.granted {
                    // The grant boundary (ADR-0028 §4): the stores the
                    // attempt was pinned to must still be in that state at
                    // the moment of the decision.
                    scope
                        .boundary_refusal(&mut *self.request_key())
                        .unwrap_or(outcome)
                } else {
                    outcome
                }
            }
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
