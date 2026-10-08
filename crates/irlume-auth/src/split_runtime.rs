// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Dedicated Engine entries for split enrollment (ADR-0032 Step 5): primary
//! enrollment or reset, and a secondary add-group, on the original retained
//! split choice of a prepared request. Also the dual split authentication
//! arm and its grant boundary, for a split that account routing installed.
//!
//! Each enrollment entry declares the split Enrollment trust entry for the
//! whole call and leaves it on every exit, unwind included. While the camera
//! activation predicate is closed, which production keeps, the declaration
//! refuses with the closed text before any side effect. Admitted, the entry
//! runs the prepared enrollment internals on the split route: no IR
//! preflight, qualification read, probe or held session. Each capture loop
//! leases both original sides once, under the retained split lease request,
//! and captures RGB then IR. Publication goes through the real primary and
//! secondary publishers under the retained proof.
//!
//! Authentication reaches a split only through classified account routing,
//! which installs it for the authentication call's own Authentication entry;
//! production never admits that entry. The routed split's one Authentication
//! lease covers both original sides for every attempt, each attempt captures
//! RGB then IR in the split capture branch, and no held pair, probe,
//! qualification read, grouped collector or managed pair runs. The grant
//! boundary refuses unless the split's late authority, both original sides
//! with IR, the account scope, the complete binding and split evidence all
//! still hold.

use crate::request_preparation::SplitTrustEntry;
use crate::{
    Assessment, AuthenticationPurpose, AuthenticationWindow, CaptureShape, CapturedScan, Engine,
    EnrollOutcome, EnrollmentObserver, EnrollmentPublication, EnrollmentRoute, Outcome,
    OutcomeCause, OutcomeKind,
};
use irlume_camera::lease::{CameraOperationKind, CameraOperationSession};
use irlume_common::diagnostics::DiagnosticSink;
use irlume_common::split_key::SplitPairKey;
use irlume_core::multi_camera::authz::EnrollmentAuthorization;
use irlume_core::multi_camera::{CompletePairKey, GroupPair};
use irlume_core::storage::Enrollment;
use std::ops::{Deref, DerefMut};

/// The schedule source the split route reports. A split pair has no stored
/// qualification and no runtime key: it is sequential by construction.
const SPLIT_CAPTURE_MODE_SOURCE: &str = "split-sequential";

/// The body of one split capture loop, run while its split Enrollment lease
/// is held.
type SplitScans<'a> = dyn FnMut(
        &mut Engine,
        &CameraOperationSession,
        usize,
        Option<f32>,
        &mut CaptureShape,
        &dyn EnrollmentObserver,
    ) -> irlume_common::Result<Vec<CapturedScan>>
    + 'a;

impl Engine {
    /// Enroll a new primary profile, or with `replace` reset the primary, on
    /// the retained split choice of this prepared request.
    ///
    /// The daemon calls this only on the scope that
    /// [`Self::prepare_split_enrollment_camera`] returned, after
    /// [`Self::validate_enrollment_camera_activation`] and the primary check.
    /// A non-reset enrollment keeps the exact complete binding rule, an
    /// empty-but-bound store included; a reset publishes through the
    /// key-retaining replacement publisher.
    ///
    /// # Errors
    /// Refuses with the closed split activation text while split enrollment
    /// is not admitted, before any side effect. Admitted, refuses without IR,
    /// on a binding of another camera, on any retained proof, lease or
    /// authorization drift, or on a capture, validation or storage failure.
    pub fn enroll_split_prepared(
        &mut self,
        user: &str,
        profile_name: Option<String>,
        want: usize,
        replace: bool,
        diagnostics: &dyn DiagnosticSink,
    ) -> irlume_common::Result<EnrollOutcome> {
        self.enroll_split_with(
            user,
            profile_name,
            want,
            replace,
            &mut |engine: &mut Engine,
                  operation: &CameraOperationSession,
                  count: usize,
                  pitch: Option<f32>,
                  observed: &mut CaptureShape,
                  observer: &dyn EnrollmentObserver| {
                engine.split_capture_loop(operation, count, pitch, observed, diagnostics, observer)
            },
            diagnostics,
        )
    }

    /// Add the retained split choice of this prepared request as a secondary
    /// camera group, published only under the caller's `authorization`.
    ///
    /// The daemon calls this only on the scope that
    /// [`Self::prepare_split_enrollment_camera`] returned, after
    /// [`Self::validate_enrollment_camera_activation`]. The group binds the
    /// retained whole split key, so only an authorization for that exact
    /// split addition and group validates.
    ///
    /// # Errors
    /// Refuses with the closed split activation text while split enrollment
    /// is not admitted, before any side effect. Admitted, refuses without IR,
    /// on an authorization of any other scope, a different face, any retained
    /// proof, lease, primary or authorization drift, or a capture or storage
    /// failure. Nothing is published unless every step succeeds.
    pub fn add_split_camera_group_prepared(
        &mut self,
        user: &str,
        profile_name: Option<String>,
        want: usize,
        authorization: &EnrollmentAuthorization,
        diagnostics: &dyn DiagnosticSink,
    ) -> irlume_common::Result<String> {
        self.add_split_group_with(
            user,
            profile_name,
            want,
            authorization,
            &mut |engine: &mut Engine,
                  operation: &CameraOperationSession,
                  count: usize,
                  pitch: Option<f32>,
                  observed: &mut CaptureShape,
                  observer: &dyn EnrollmentObserver| {
                engine.split_capture_loop(operation, count, pitch, observed, diagnostics, observer)
            },
            diagnostics,
        )
    }

    fn enroll_split_with(
        &mut self,
        user: &str,
        profile_name: Option<String>,
        want: usize,
        replace: bool,
        scans: &mut SplitScans<'_>,
        diagnostics: &dyn DiagnosticSink,
    ) -> irlume_common::Result<EnrollOutcome> {
        let mut entry = SplitEnrollment::enter(self)?;
        let mut capture = |engine: &mut Engine,
                           count: usize,
                           pitch: Option<f32>,
                           observed: &mut CaptureShape,
                           observer: &dyn EnrollmentObserver| {
            engine.split_enrollment_loop(count, pitch, observed, observer, &mut *scans)
        };
        entry.enroll_profile_capture_prepared(
            user,
            profile_name,
            want,
            EnrollmentRoute::split(&mut capture),
            diagnostics,
            EnrollmentPublication {
                replace,
                observer: &(),
            },
        )
    }

    fn add_split_group_with(
        &mut self,
        user: &str,
        profile_name: Option<String>,
        want: usize,
        authorization: &EnrollmentAuthorization,
        scans: &mut SplitScans<'_>,
        diagnostics: &dyn DiagnosticSink,
    ) -> irlume_common::Result<String> {
        let mut entry = SplitEnrollment::enter(self)?;
        let mut capture = |engine: &mut Engine,
                           count: usize,
                           pitch: Option<f32>,
                           observed: &mut CaptureShape,
                           observer: &dyn EnrollmentObserver| {
            engine.split_enrollment_loop(count, pitch, observed, observer, &mut *scans)
        };
        entry.add_camera_group_prepared(
            user,
            profile_name,
            want,
            authorization,
            EnrollmentRoute::split(&mut capture),
            diagnostics,
            &(),
        )
    }

    /// One split enrollment capture loop: the gate, one split Enrollment
    /// lease over both original sides under the retained lease request, the
    /// gate again while it is held, then `scans`. The lease is released when
    /// the loop returns; the next loop reacquires the same original sides.
    fn split_enrollment_loop(
        &mut self,
        count: usize,
        pitch_neutral: Option<f32>,
        observed: &mut CaptureShape,
        observer: &dyn EnrollmentObserver,
        scans: &mut SplitScans<'_>,
    ) -> irlume_common::Result<Vec<CapturedScan>> {
        observer.check()?;
        // One PAD vote ring per capture loop, as on the ordinary route.
        self.vit_scores.clear();
        // Asked to yield before the first frame: do not even lease the pair.
        if self.should_stop() {
            return Err(irlume_common::Error::Preempted(
                "an authentication needed the camera; nothing was saved, please retry".into(),
            ));
        }
        let (rgb_dev, ir_dev) = (self.rgb_dev.clone(), self.ir_dev.clone());
        self.validate_camera_request()?;
        let operation = self
            .acquire_account_camera(
                &[rgb_dev.as_str(), ir_dev.as_str()],
                irlume_camera::lease::CameraOperationKind::Enrollment,
                std::time::Duration::from_secs(2),
            )
            .map_err(crate::lease_unavailable)?;
        // Revoked or drifted state after a lease wait refuses before any open.
        self.validate_camera_request()?;
        if !operation.lease().is_split_pair() {
            return Err(irlume_common::Error::Hardware(
                "split enrollment requires its split camera operation".into(),
            ));
        }
        scans(self, &operation, count, pitch_neutral, observed, observer)
    }

    /// The production body of a split capture loop: the shared enrollment
    /// loop with no held sessions and IR required, which reaches the
    /// sequential split branch of the full assessment on every attempt.
    fn split_capture_loop(
        &mut self,
        operation: &CameraOperationSession,
        count: usize,
        pitch_neutral: Option<f32>,
        observed: &mut CaptureShape,
        diagnostics: &dyn DiagnosticSink,
        observer: &dyn EnrollmentObserver,
    ) -> irlume_common::Result<Vec<CapturedScan>> {
        let mode = split_capture_mode_selection();
        crate::emit_capture_context(&mode, true, diagnostics);
        self.capture_scan_loop(
            count,
            pitch_neutral,
            None,
            crate::EnrollmentCapturePolicy {
                mode: &mode,
                use_ir: true,
                diagnostics,
                observer,
            },
            operation,
            observed,
            std::time::Instant::now(),
        )
        .map_err(crate::CapturePathError::into_inner)
    }
}

/// The split route's explicit schedule: sequential, with no runtime key, no
/// stored qualification and no environment override.
fn split_capture_mode_selection() -> crate::CaptureModeSelection {
    crate::CaptureModeSelection {
        sequential: true,
        source: SPLIT_CAPTURE_MODE_SOURCE,
        runtime_key: None,
        runtime_contract: None,
        qualification_state: irlume_common::diagnostics::QualificationState::UnqualifiedNoAuthority,
        qualification_reason: Some(
            irlume_common::diagnostics::QualificationReason::NoStoredAuthority,
        ),
        authoritative_rate_shortfalls: None,
        latest_attempt_rate_shortfalls: None,
        operation_demoted: std::cell::Cell::new(false),
    }
}

/// The declared split Enrollment trust entry of one Engine call. Dropping it
/// leaves the entry on every exit, unwind included; the retained request
/// scope stays with its owner.
struct SplitEnrollment<'a> {
    engine: &'a mut Engine,
}

impl<'a> SplitEnrollment<'a> {
    fn enter(engine: &'a mut Engine) -> irlume_common::Result<Self> {
        engine.enter_split_trust(SplitTrustEntry::Enrollment)?;
        Ok(Self { engine })
    }
}

impl Deref for SplitEnrollment<'_> {
    type Target = Engine;
    fn deref(&self) -> &Engine {
        self.engine
    }
}

impl DerefMut for SplitEnrollment<'_> {
    fn deref_mut(&mut self) -> &mut Engine {
        self.engine
    }
}

impl Drop for SplitEnrollment<'_> {
    fn drop(&mut self) {
        self.engine.leave_split_trust();
    }
}

/// A grant boundary refusal with its wire cause.
type SplitGrantRefusal = (OutcomeCause, &'static str);

const SPLIT_GRANT_SIDES: SplitGrantRefusal = (
    OutcomeCause::CameraUnavailable,
    "split camera authentication needs both original sides with IR; use your password",
);
const SPLIT_GRANT_SCOPE: SplitGrantRefusal = (
    OutcomeCause::SetupUnavailable,
    "split camera authentication has no account scope; use your password",
);
const SPLIT_GRANT_BINDING: SplitGrantRefusal = (
    OutcomeCause::NotEnrolledOnThisCamera,
    "this enrollment is not bound to the routed split camera pair; use your password",
);
const SPLIT_GRANT_EVIDENCE: SplitGrantRefusal = (
    OutcomeCause::SetupUnavailable,
    "split camera authentication needs evidence from its split capture; use your password",
);

impl Engine {
    /// The complete key of the split this request installed, if any. On the
    /// authentication path only classified account routing installs one,
    /// for the call's own Authentication entry.
    pub(crate) fn installed_split_key(&self) -> Option<SplitPairKey> {
        match self.camera_selection.as_ref()?.binding()? {
            GroupPair::Split(key) => Some(key),
            GroupPair::Ordinary { .. } => None,
        }
    }

    /// The dual split authentication arm (plan W2a-2): every attempt of the
    /// grace window runs under the routed split's one Authentication
    /// operation, already leased over both original sides. Each attempt
    /// captures RGB then IR as complete sequential one-shots in the split
    /// capture branch, with the split schedule and no held pair, capture-mode
    /// probe, stored qualification, grouped collector or managed pair. The
    /// grant boundary then applies [`Self::split_grant_refusal`].
    pub(crate) fn authenticate_split_routed(
        &mut self,
        enrollment: &Enrollment,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        window: AuthenticationWindow,
        operation: &CameraOperationSession,
        diagnostics: &dyn DiagnosticSink,
    ) -> irlume_common::Result<Outcome> {
        if !self.ir_available
            || !operation.lease().is_split_pair()
            || operation.lease().operation() != CameraOperationKind::Authentication
        {
            return Err(irlume_common::Error::Hardware(
                "split authentication requires its split Authentication operation".into(),
            ));
        }
        let mode = split_capture_mode_selection();
        crate::emit_capture_context(&mode, true, diagnostics);
        let mut costliest_attempt = std::time::Duration::ZERO;
        self.authentication_attempt_loop(
            enrollment,
            purpose,
            service,
            window.deadline,
            window.milliseconds,
            None,
            &mode,
            operation,
            diagnostics,
            &mut costliest_attempt,
        )
        .0
    }

    /// The grant boundary of an installed split (plan C6, D10; ADR-0032
    /// section 5 and case 15), after the account boundaries and before any
    /// grant arm. None unless a split is installed. Otherwise it refuses on
    /// the late machine authority first
    /// ([`Self::split_grant_authority_refusal`]: the declared, admitted
    /// entry and a lock-free read of the retained publication), then without
    /// both original sides and IR, without the routed account scope, for an
    /// enrollment not bound to the installed complete key, and for evidence
    /// that did not come from the split capture. An installed enrollment
    /// split has no account scope, so it never grants either. Every grant
    /// arm after this keeps the split sequential posture.
    pub(crate) fn split_grant_refusal(
        &self,
        enrollment: &Enrollment,
        assessment: &Assessment,
    ) -> Option<Outcome> {
        let key = self.installed_split_key()?;
        if let Some(refusal) = self.split_grant_authority_refusal() {
            return Some(refusal);
        }
        let sides = self
            .camera_selection
            .as_ref()
            .is_some_and(|selection| selection.matches_devices(&self.rgb_dev, &self.ir_dev, true));
        let (cause, reason) = if irlume_camera::ir_forced_off() || !self.ir_available || !sides {
            SPLIT_GRANT_SIDES
        } else if self.primary_attempt.is_none() && self.secondary_attempt.is_none() {
            SPLIT_GRANT_SCOPE
        } else if enrollment
            .camera_binding
            .as_ref()
            .and_then(GroupPair::complete_key)
            != Some(CompletePairKey::Split(key))
        {
            SPLIT_GRANT_BINDING
        } else if !assessment.split_pair {
            SPLIT_GRANT_EVIDENCE
        } else {
            return None;
        };
        Some(Outcome::deny_because(OutcomeKind::OtherDeny, cause, reason))
    }
}

/// The closed split activation refusal, the same policy error and text the
/// AUTH activation gate returns (`CameraLeaseError::SplitActivationDisabled`).
#[cfg(test)]
fn split_entry_closed() -> irlume_common::Error {
    irlume_common::Error::Policy(
        irlume_camera::lease::CameraLeaseError::SplitActivationDisabled.to_string(),
    )
}

#[cfg(test)]
impl Engine {
    /// Capture-injection twin of [`Self::enroll_split_prepared`]: `capture`
    /// replaces only each loop's body, under its held split lease, while the
    /// declared entry, per-loop gate and lease, binding rules and real
    /// publishers run unchanged.
    pub(crate) fn enroll_split_prepared_with_capture(
        &mut self,
        user: &str,
        profile_name: Option<String>,
        want: usize,
        replace: bool,
        diagnostics: &dyn DiagnosticSink,
        mut capture: impl FnMut(
            &mut Engine,
            usize,
            Option<f32>,
            &mut CaptureShape,
        ) -> irlume_common::Result<Vec<CapturedScan>>,
    ) -> irlume_common::Result<EnrollOutcome> {
        self.enroll_split_with(
            user,
            profile_name,
            want,
            replace,
            &mut |engine: &mut Engine,
                  _: &CameraOperationSession,
                  count: usize,
                  pitch: Option<f32>,
                  observed: &mut CaptureShape,
                  _: &dyn EnrollmentObserver| {
                capture(engine, count, pitch, observed)
            },
            diagnostics,
        )
    }

    /// Capture-injection twin of [`Self::add_split_camera_group_prepared`],
    /// with the same boundary as [`Self::enroll_split_prepared_with_capture`].
    pub(crate) fn add_split_camera_group_prepared_with_capture(
        &mut self,
        user: &str,
        profile_name: Option<String>,
        want: usize,
        authorization: &EnrollmentAuthorization,
        diagnostics: &dyn DiagnosticSink,
        mut capture: impl FnMut(
            &mut Engine,
            usize,
            Option<f32>,
            &mut CaptureShape,
        ) -> irlume_common::Result<Vec<CapturedScan>>,
    ) -> irlume_common::Result<String> {
        self.add_split_group_with(
            user,
            profile_name,
            want,
            authorization,
            &mut |engine: &mut Engine,
                  _: &CameraOperationSession,
                  count: usize,
                  pitch: Option<f32>,
                  observed: &mut CaptureShape,
                  _: &dyn EnrollmentObserver| {
                capture(engine, count, pitch, observed)
            },
            diagnostics,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_camera::lease::CameraLeaseError;
    use irlume_camera::test_support::Guard;
    use irlume_core::multi_camera::authz::{AuthorizationVia, EnrollmentOperation};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    const CLOSED: &str = "split enrollment and authentication are not enabled";
    const USER: &str = "split-runtime";
    const NO_RGB: &str = "/dev/irlume-split-runtime-none-rgb";
    const NO_IR: &str = "/dev/irlume-split-runtime-none-ir";
    const SPLIT_KEY: &str =
        "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5";

    fn closed<T>(result: &irlume_common::Result<T>) -> bool {
        matches!(result, Err(irlume_common::Error::Policy(text)) if text == CLOSED)
    }

    fn model_path(name: &str) -> String {
        format!("{}/../../models/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// A sandboxed state and config directory, restored on drop.
    struct Sandbox {
        dir: PathBuf,
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl Sandbox {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "irlume-split-runtime-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let keys = [
                "IRLUME_CONFIG_DIR",
                "IRLUME_STATE_DIR",
                "IRLUME_TEMPLATE_KEY_DIR",
                "IRLUME_TCTI",
                "IRLUME_RGB_DEVICE",
                "IRLUME_IR_DEVICE",
            ];
            let saved = keys
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect();
            std::env::set_var("IRLUME_CONFIG_DIR", &dir);
            std::env::set_var("IRLUME_STATE_DIR", &dir);
            std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", dir.join("private-template-keys"));
            // No key resolution is expected; a failed transport still keeps
            // any accidental one off the host TPM.
            std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-test-tpm");
            std::env::remove_var("IRLUME_RGB_DEVICE");
            std::env::remove_var("IRLUME_IR_DEVICE");
            Self { dir, saved }
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Every path below `dir` with its bytes; `None` marks a directory.
    fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    out.insert(path.clone(), None);
                    walk(&path, out);
                } else {
                    let bytes = std::fs::read(&path).unwrap();
                    out.insert(path, Some(bytes));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(dir, &mut out);
        out
    }

    #[test]
    fn split_entry_refusal_is_the_closed_activation_text() {
        assert_eq!(
            CameraLeaseError::SplitActivationDisabled.to_string(),
            CLOSED
        );
        let refusal = split_entry_closed();
        assert!(
            matches!(&refusal, irlume_common::Error::Policy(text) if text == CLOSED),
            "the daemon relays the AUTH gate's closed text unchanged: {refusal:?}"
        );
        assert!(refusal.to_string().contains(CLOSED), "{refusal}");
    }

    #[test]
    fn split_entries_refuse_closed_without_a_prepared_split_before_any_side_effect() {
        let _env = crate::tests::env_guard();
        // The shared engine initializes the ONNX runtime; this test loads its
        // own engine, as the builder tests do.
        drop(crate::engine_tests::shared());
        let sandbox = Sandbox::new();
        let recorder = Guard::install(&[]).unwrap();
        let counts = recorder.lease_counts_observer();
        let mut engine = Engine::load(
            &model_path("face_detection_yunet_2023mar.onnx"),
            &model_path("glintr100.onnx"),
        )
        .expect("engine load")
        .with_devices(NO_RGB, NO_IR);
        let devices = (
            engine.rgb_dev.clone(),
            engine.ir_dev.clone(),
            engine.ir_available,
        );
        let enrollment = irlume_core::storage::Enrollment::new(USER);
        std::fs::write(
            sandbox.dir.join(format!("{USER}.json")),
            serde_json::to_vec(&enrollment).unwrap(),
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = irlume_common::split_key::SplitPairKey::parse_canonical(SPLIT_KEY).unwrap();
        let authorization = EnrollmentAuthorization::mint(
            USER.into(),
            EnrollmentOperation::add_group(
                "split-runtime".into(),
                &irlume_core::multi_camera::GroupPair::Split(key),
            ),
            now,
            900,
            "split-runtime".into(),
            AuthorizationVia::ElevatedPeer { uid: 0 },
        )
        .unwrap();
        let before = snapshot(&sandbox.dir);
        for replace in [false, true] {
            let result = engine.enroll_split_prepared(USER, None, 1, replace, &());
            assert!(closed(&result), "replace={replace}: {result:?}");
        }
        let result = engine.add_split_camera_group_prepared(
            USER,
            Some("Face Profile 1".into()),
            1,
            &authorization,
            &(),
        );
        assert!(closed(&result), "{result:?}");
        assert!(
            recorder.calls().is_empty(),
            "a closed split entry reaches no camera boundary: {:?}",
            recorder.calls()
        );
        assert_eq!(counts(), (0, 0));
        assert_eq!(
            snapshot(&sandbox.dir),
            before,
            "a closed split entry writes no state and takes no lock file"
        );
        assert!(engine.camera_selection.is_none());
        let after = (
            engine.rgb_dev.clone(),
            engine.ir_dev.clone(),
            engine.ir_available,
        );
        assert_eq!(after, devices);
    }

    #[test]
    fn split_runtime_never_names_the_split_store() {
        // Assembled needles keep this file free of the text it pins.
        let source = include_str!("split_runtime.rs");
        assert!(
            source.contains("pub fn enroll_split_prepared(")
                && source.contains("pub fn add_split_camera_group_prepared("),
            "the scan must read the split runtime entries"
        );
        for needle in [["split", "_publish"].concat(), ["split", "_wire"].concat()] {
            assert!(
                !source.contains(&needle),
                "the split runtime must not reach the split store ({needle})"
            );
        }
    }

    #[test]
    fn lib_registers_split_runtime_and_keeps_the_split_routing_tests() {
        let lib = include_str!("lib.rs");
        assert_eq!(
            lib.lines()
                .filter(|line| *line == "mod split_runtime;")
                .count(),
            1
        );
        let opener = "mod engine_tests {";
        assert_eq!(lib.matches(opener).count(), 1);
        let registrations = lib
            .split_once(opener)
            .and_then(|(_, rest)| rest.split_once("\n    use "))
            .map(|(registrations, _)| registrations)
            .expect("engine test registrations precede the first use");
        assert_eq!(
            registrations
                .lines()
                .filter(|line| *line == "    mod split_routing_tests;")
                .count(),
            1,
            "the split routing tests must stay registered"
        );
    }

    /// A registered suite cannot notice its own absence, so this module,
    /// which the production `mod split_runtime;` always compiles, pins the
    /// split enrollment registration: one exact line inside the engine test
    /// registrations, no attribute that could compile it out, and a suite
    /// that keeps its fifteen tests with none ignored or compiled out. The
    /// name avoids the registered module's name, so a filter on that name
    /// still lists only the suite.
    #[test]
    fn lib_keeps_the_split_enrollment_suite_registered_and_ungated() {
        let lib = include_str!("lib.rs");
        let registrations = lib
            .split_once("mod engine_tests {")
            .and_then(|(_, rest)| rest.split_once("\n    use "))
            .map(|(registrations, _)| registrations)
            .expect("engine test registrations precede the first use");
        let lines: Vec<&str> = registrations.lines().collect();
        for line in [
            "    mod split_enrollment_tests;",
            "    mod split_routing_tests;",
        ] {
            assert_eq!(
                lib.lines().filter(|text| *text == line).count(),
                1,
                "{line} must appear exactly once"
            );
            let at = lines
                .iter()
                .position(|text| *text == line)
                .unwrap_or_else(|| panic!("{line} must stay inside the engine test registrations"));
            assert!(
                !lines[at - 1].trim_start().starts_with("#["),
                "{line} must carry no attribute that could compile it out: {}",
                lines[at - 1]
            );
        }
        let suite = include_str!("engine_tests/split_enrollment_tests.rs");
        assert!(
            suite.lines().filter(|text| *text == "#[test]").count() >= 15,
            "the split enrollment suite keeps its fifteen tests"
        );
        for gate in ["#[ignore", "#[cfg", "#![cfg"] {
            assert!(
                !suite
                    .lines()
                    .any(|text| text.trim_start().starts_with(gate)),
                "the split enrollment suite must not be ignored or compiled out ({gate})"
            );
        }
    }

    /// The dual split authentication suite, pinned the same way: one exact
    /// registration inside the engine test registrations, no attribute that
    /// could compile it out, and a suite that keeps its seven tests with
    /// none ignored or compiled out. The name avoids the registered module's
    /// name, so a filter on that name still lists only the suite.
    #[test]
    fn lib_keeps_the_dual_split_suite_registered_and_ungated() {
        let lib = include_str!("lib.rs");
        let registrations = lib
            .split_once("mod engine_tests {")
            .and_then(|(_, rest)| rest.split_once("\n    use "))
            .map(|(registrations, _)| registrations)
            .expect("engine test registrations precede the first use");
        let lines: Vec<&str> = registrations.lines().collect();
        let line = "    mod split_authentication_tests;";
        assert_eq!(
            lib.lines().filter(|text| *text == line).count(),
            1,
            "{line} must appear exactly once"
        );
        let at = lines
            .iter()
            .position(|text| *text == line)
            .unwrap_or_else(|| panic!("{line} must stay inside the engine test registrations"));
        assert!(
            !lines[at - 1].trim_start().starts_with("#["),
            "{line} must carry no attribute that could compile it out: {}",
            lines[at - 1]
        );
        let suite = include_str!("engine_tests/split_authentication_tests.rs");
        assert!(
            suite.lines().filter(|text| *text == "#[test]").count() >= 7,
            "the dual split authentication suite keeps its seven tests"
        );
        for gate in ["#[ignore", "#[cfg", "#![cfg"] {
            assert!(
                !suite
                    .lines()
                    .any(|text| text.trim_start().starts_with(gate)),
                "the dual split authentication suite must not be ignored or compiled out ({gate})"
            );
        }
    }

    /// The routed scope rows of the dual split suite, pinned the same way:
    /// one exact child registration in the suite with no attribute that
    /// could compile it out, and a child that keeps its six tests with none
    /// ignored or compiled out. The name avoids the child module's name, so
    /// a filter on that name still lists only its rows.
    #[test]
    fn the_dual_split_suite_keeps_its_routed_scope_rows() {
        let suite = include_str!("engine_tests/split_authentication_tests.rs");
        let lines: Vec<&str> = suite.lines().collect();
        let line = "mod split_routed_grant_tests;";
        assert_eq!(
            lines.iter().filter(|text| **text == line).count(),
            1,
            "{line} must appear exactly once in the dual split suite"
        );
        let at = lines
            .iter()
            .position(|text| *text == line)
            .expect("the routed scope rows stay registered");
        assert!(
            at > 0 && !lines[at - 1].trim_start().starts_with("#["),
            "{line} must carry no attribute that could compile it out"
        );
        let rows =
            include_str!("engine_tests/split_authentication_tests/split_routed_grant_tests.rs");
        assert!(
            rows.lines().filter(|text| *text == "#[test]").count() >= 6,
            "the routed scope rows keep their six tests"
        );
        for gate in ["#[ignore", "#[cfg", "#![cfg"] {
            assert!(
                !rows.lines().any(|text| text.trim_start().starts_with(gate)),
                "the routed scope rows must not be ignored or compiled out ({gate})"
            );
        }
    }

    /// The registration `line` appears exactly once in `source`, and the
    /// nearest earlier line that is neither blank nor a comment carries no
    /// attribute, so no attribute separated from it by comments or blank
    /// lines can compile it out either.
    fn ungated_registration(source: &str, line: &str) -> Result<(), String> {
        let lines: Vec<&str> = source.lines().collect();
        let mut found = lines
            .iter()
            .enumerate()
            .filter(|(_, text)| **text == line)
            .map(|(at, _)| at);
        let at = found
            .next()
            .ok_or_else(|| format!("{line} is not registered"))?;
        if found.next().is_some() {
            return Err(format!("{line} is registered more than once"));
        }
        let previous = lines[..at]
            .iter()
            .map(|text| text.trim_start())
            .rfind(|text| !text.is_empty() && !text.starts_with("//"));
        if let Some(text) = previous.filter(|text| text.starts_with("#[")) {
            return Err(format!("{line} carries an attribute: {text}"));
        }
        Ok(())
    }

    /// The pinned configuration rows of the dual split suite: one exact
    /// child registration with no attribute that could compile it out, not
    /// even one separated from it by comments or blank lines, and a child
    /// that keeps its four tests with none ignored or compiled out. The same
    /// stricter reading holds for the suite's own registration and for its
    /// routed scope rows. The name avoids the child module's name, so a
    /// filter on that name still lists only its rows.
    #[test]
    fn the_dual_split_suite_keeps_its_pinned_configuration_rows() {
        let lib = include_str!("lib.rs");
        let suite = include_str!("engine_tests/split_authentication_tests.rs");
        let rows =
            include_str!("engine_tests/split_authentication_tests/split_pinned_config_tests.rs");
        let child = "mod split_pinned_config_tests;";
        for (source, line) in [
            (lib, "    mod split_authentication_tests;"),
            (suite, child),
            (suite, "mod split_routed_grant_tests;"),
        ] {
            assert_eq!(ungated_registration(source, line), Ok(()));
        }
        // Mutation control: an attribute separated from the registration by
        // a doc comment and a blank line still compiles it out, and fails.
        let gated = suite.replacen(child, &format!("#[cfg(any())]\n/// note\n\n{child}"), 1);
        assert!(ungated_registration(&gated, child).is_err());
        assert!(
            rows.lines().filter(|text| *text == "#[test]").count() >= 4,
            "the pinned configuration rows keep their four tests"
        );
        for gate in ["#[ignore", "#[cfg", "#![cfg"] {
            assert!(
                !rows.lines().any(|text| text.trim_start().starts_with(gate)),
                "the pinned configuration rows must not be ignored or compiled out ({gate})"
            );
        }
    }
}
