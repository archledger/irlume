// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The split trust activation predicate and its only override, the
//! non-granting fixture's thread-local admission (ADR-0032 acceptance cases
//! 12 and 15). A build without `test-support` keeps every trust kind closed.

/// Runs in the camera gate built without `test-support`: no override exists
/// there, so the predicate is the production answer for every kind.
#[cfg(not(feature = "test-support"))]
#[test]
fn split_trust_is_closed_for_every_kind_without_test_support() {
    use super::{split_trust_admitted, CameraOperationKind};
    for kind in [
        CameraOperationKind::Authentication,
        CameraOperationKind::Enrollment,
        CameraOperationKind::Capture,
        CameraOperationKind::Preview,
        CameraOperationKind::Diagnostics,
        CameraOperationKind::Setup,
    ] {
        assert!(
            !split_trust_admitted(kind),
            "{kind:?} must stay closed in a build without test-support"
        );
    }
}

/// Production code never names the fixture override: only test files, inline
/// top-level `#[cfg(test)]` modules and the defining fixture module may.
#[test]
fn admit_split_trust_is_named_only_by_test_code() {
    use std::path::{Path, PathBuf};

    fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("readable source entry").path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_owned();
            if path.is_dir() {
                if name != "target" && !name.starts_with('.') {
                    collect(&path, files);
                }
            } else if name.ends_with(".rs") {
                files.push(path);
            }
        }
    }

    fn test_file(relative: &str) -> bool {
        let name = relative.rsplit('/').next().unwrap_or(relative);
        name.ends_with("_tests.rs") || name == "tests.rs" || relative.contains("/tests/")
    }

    /// Lines outside top-level `#[cfg(test)]` or `#[cfg(all(test, ...))]`
    /// module blocks; rustfmt closes such a module with a lone `}`.
    fn production_lines(text: &str) -> Vec<(usize, &str)> {
        let mut lines = Vec::new();
        let mut gated = false;
        let mut in_test_module = false;
        for (index, line) in text.lines().enumerate() {
            let code = line.trim_end();
            if in_test_module {
                in_test_module = code != "}";
                continue;
            }
            let opens_module = ["mod ", "pub mod ", "pub(crate) mod ", "pub(super) mod "]
                .iter()
                .any(|prefix| code.starts_with(prefix))
                && code.ends_with('{');
            if gated && opens_module {
                gated = false;
                in_test_module = true;
                continue;
            }
            if code == "#[cfg(test)]" || code.starts_with("#[cfg(all(test,") {
                gated = true;
            } else if !code.starts_with("#[") {
                gated = false;
            }
            lines.push((index + 1, line));
        }
        lines
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(
        root.join("Cargo.toml").is_file() && root.join("crates").is_dir(),
        "the workspace root moved; update this scan"
    );
    let mut files = Vec::new();
    collect(&root.join("crates"), &mut files);
    collect(&root.join("fuzz"), &mut files);
    let needle = "admit_split_trust";
    let mut defined = false;
    let mut test_users = Vec::new();
    let mut violations = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        if !text.contains(needle) {
            continue;
        }
        let relative = path.strip_prefix(&root).map_or_else(
            |_| path.display().to_string(),
            |relative| relative.display().to_string(),
        );
        if relative == "crates/irlume-camera/src/backend/test_support.rs" {
            defined = text.contains("pub fn admit_split_trust(&self");
        } else if test_file(&relative) {
            test_users.push(relative);
        } else {
            violations.extend(
                production_lines(&text)
                    .into_iter()
                    .filter(|(_, line)| line.contains(needle))
                    .map(|(number, _)| format!("{relative}:{number}")),
            );
        }
    }
    assert!(
        defined,
        "the fixture override moved out of test_support.rs; update this scan with it"
    );
    assert!(
        test_users
            .iter()
            .any(|path| path.ends_with("irlume-camera/src/split_trust_tests.rs")),
        "the scan must see this test file: {test_users:?}"
    );
    assert!(
        violations.is_empty(),
        "production code names the split trust fixture override: {violations:?}"
    );
}

#[cfg(feature = "test-support")]
mod admitted {
    use crate::contracts::StreamRole;
    use crate::lease::{
        acquire_split_camera_operation, split_trust_admitted, CameraLeaseError,
        CameraOperationKind::{
            self, Authentication, Capture, Diagnostics, Enrollment, Preview, Setup,
        },
        CameraOperationSession, SplitLeaseRequest,
    };
    use crate::test_support::{
        capture_uniform_split_pair, capture_uniform_split_pair_at, Call, Camera, Endpoint, Guard,
        SplitTrustAdmission,
    };
    use crate::{
        camera_inventory_publication, capture_split_pair_with_control, no_progress, CaptureControl,
        Role, SplitSideExpectation,
    };
    use std::time::{Duration, Instant};

    const RGB: &str = "/dev/split-trust-rgb";
    const IR: &str = "/dev/split-trust-ir";
    const TRUST: [CameraOperationKind; 3] = [Authentication, Enrollment, Capture];
    const CAPTURE_CLOSED: &str = "split capture requires a supported two-device operation";
    const RGB_OPEN_REFUSED: &str = "fixture RGB open refused";
    const IR_OPEN_REFUSED: &str = "fixture IR open refused";

    fn fixture() -> (Guard, SplitLeaseRequest) {
        let camera = |port: u8, path: &str, format: [u8; 4]| Camera {
            topology: format!("/devices/split-trust/{port}"),
            identity: format!("1234:000{port}"),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
            endpoints: vec![Endpoint {
                path: path.into(),
                formats: vec![format],
            }],
        };
        let guard = Guard::install(&[camera(1, RGB, *b"YUYV"), camera(2, IR, *b"GREY")])
            .expect("split trust fixture");
        let (snapshot, sides) = camera_inventory_publication();
        let side = |role| {
            let side = sides
                .iter()
                .find(|side| side.role == role)
                .expect("classified fixture side");
            SplitSideExpectation {
                instance_id: side.instance_id.clone(),
                generation: side.generation,
                endpoint: side.endpoint.clone(),
                identity: side.identity.clone(),
                controller: side.controller.clone(),
                domain: side.domain.clone(),
                ports: side.ports.clone(),
            }
        };
        let expected = SplitLeaseRequest {
            supervisor_id: snapshot.supervisor_id.expect("fixture supervisor"),
            revision: snapshot.revision,
            rgb: side(Role::Rgb),
            ir: side(Role::Ir),
        };
        (guard, expected)
    }

    fn acquire(
        expected: &SplitLeaseRequest,
        kind: CameraOperationKind,
    ) -> Result<CameraOperationSession, CameraLeaseError> {
        acquire_split_camera_operation(expected, kind, Duration::ZERO)
    }

    /// Both reservations without the public acquisition gate, so the capture
    /// gate is exercised on its own. This records no lease call.
    fn reserve_ungated(
        expected: &SplitLeaseRequest,
        kind: CameraOperationKind,
    ) -> CameraOperationSession {
        crate::backend::with_camera_supervisor(|supervisor| {
            supervisor.acquire_split_operation(expected, kind, Instant::now())
        })
        .expect("ungated split reservation")
    }

    fn lease_call(kind: CameraOperationKind) -> Call {
        Call::Lease {
            endpoints: vec![RGB.into(), IR.into()],
            kind,
        }
    }

    fn capture_refusal(operation: &CameraOperationSession) -> String {
        match capture_uniform_split_pair(operation, RGB, IR) {
            Ok(_) => panic!(
                "the split capture gate admitted {:?}",
                operation.lease().operation()
            ),
            Err(error) => error.to_string(),
        }
    }

    /// The production split capture, which opens through the backend, under
    /// `operation`; the refusing fixture can never return evidence.
    fn production_capture_refusal(operation: &CameraOperationSession) -> String {
        let control = CaptureControl::with_progress(no_progress());
        match capture_split_pair_with_control(RGB, IR, operation, &control) {
            Ok(_) => panic!(
                "the refusing fixture produced split evidence under {:?}",
                operation.lease().operation()
            ),
            Err(error) => error.to_string(),
        }
    }

    // RED: these need a working admission.

    #[test]
    fn split_trust_admission_allows_an_enrollment_lease_only_while_the_token_lives() {
        let (guard, expected) = fixture();
        let counts = guard.lease_counts_observer();
        let token = guard.admit_split_trust(&[Enrollment]);
        assert!(
            split_trust_admitted(Enrollment),
            "the fixture admission must open Enrollment"
        );
        let operation = acquire(&expected, Enrollment).expect("an admitted Enrollment split lease");
        assert!(operation.lease().is_split_pair());
        assert_eq!(operation.lease().operation(), Enrollment);
        assert_eq!(counts(), (2, 0), "one permit reserves both incarnations");
        drop(operation);
        assert_eq!(counts(), (0, 0));
        drop(token);
        assert!(!split_trust_admitted(Enrollment));
        assert_eq!(
            acquire(&expected, Enrollment).err(),
            Some(CameraLeaseError::SplitActivationDisabled)
        );
        assert_eq!(counts(), (0, 0));
        assert_eq!(
            guard.calls(),
            vec![lease_call(Enrollment), lease_call(Enrollment)],
            "lease attempts only; nothing opens"
        );
    }

    #[test]
    fn split_capture_admits_an_admitted_enrollment_operation_in_rgb_then_ir_order() {
        let (guard, expected) = fixture();
        let _token = guard.admit_split_trust(&[Enrollment]);
        let operation = acquire(&expected, Enrollment).expect("an admitted Enrollment split lease");
        let capture = capture_uniform_split_pair(&operation, RGB, IR)
            .expect("admitted Enrollment split capture");
        assert!(
            capture.rgb().captured.end <= capture.ir().captured.start,
            "RGB is captured before IR"
        );
        for (frame, role, side) in [
            (capture.rgb(), StreamRole::Rgb, &expected.rgb),
            (capture.ir(), StreamRole::Ir, &expected.ir),
        ] {
            let binding = frame.provenance().binding();
            assert_eq!(binding.stream_role(), role);
            assert_eq!(binding.camera_instance_id().as_str(), side.instance_id);
            assert_eq!(binding.generation().get(), side.generation);
        }
        let (rgb, ir, _stats) = capture
            .into_parts(&operation)
            .expect("the original admitted operation");
        assert_ne!(
            rgb.provenance().binding().camera_instance_id(),
            ir.provenance().binding().camera_instance_id()
        );
        assert_eq!(
            guard.calls(),
            vec![lease_call(Enrollment)],
            "uniform fixture frames open no device"
        );
        drop(operation);
        assert_eq!(guard.lease_counts_observer()(), (0, 0));
    }

    #[test]
    fn split_trust_admission_allows_an_authentication_lease_and_capture() {
        let (guard, expected) = fixture();
        let token = guard.admit_split_trust(&[Authentication]);
        let operation =
            acquire(&expected, Authentication).expect("an admitted Authentication split lease");
        let capture = capture_uniform_split_pair(&operation, RGB, IR)
            .expect("admitted Authentication split capture");
        capture
            .revalidate(&operation)
            .expect("the original admitted operation");
        drop(capture);
        drop(operation);
        drop(token);
        assert_eq!(guard.calls(), vec![lease_call(Authentication)]);
        assert_eq!(guard.lease_counts_observer()(), (0, 0));
    }

    /// The `admit_split_trust` doc claim on the production capture path: an
    /// admitted trust lease runs the real one-shot RGB capture, which reaches
    /// this fixture's refusing open, so an admission opens no device and IR
    /// is never attempted. With the admission closed, the same call stops at
    /// the split gate before any open.
    #[test]
    fn admitted_split_capture_reaches_only_the_refusing_fixture_open() {
        for kind in [Enrollment, Authentication] {
            let (guard, expected) = fixture();
            let counts = guard.lease_counts_observer();
            let token = guard.admit_split_trust(&[kind]);
            let operation = acquire(&expected, kind)
                .unwrap_or_else(|error| panic!("an admitted {kind:?} split lease: {error}"));
            let refusal = production_capture_refusal(&operation);
            assert!(refusal.contains(RGB_OPEN_REFUSED), "{kind:?}: {refusal}");
            assert_eq!(
                guard.calls(),
                vec![lease_call(kind), Call::OpenRgb(RGB.into())],
                "{kind:?}: RGB reaches the refusing fixture open and IR is never opened"
            );
            for (opened, refusal) in [
                (operation.open_rgb(RGB).err(), RGB_OPEN_REFUSED),
                (operation.open_ir(IR).err(), IR_OPEN_REFUSED),
            ] {
                let error = opened
                    .unwrap_or_else(|| panic!("{kind:?}: a fixture open succeeded"))
                    .to_string();
                assert!(error.contains(refusal), "{kind:?}: {error}");
            }
            assert_eq!(
                guard.calls(),
                vec![
                    lease_call(kind),
                    Call::OpenRgb(RGB.into()),
                    Call::OpenRgb(RGB.into()),
                    Call::OpenIr(IR.into()),
                ],
                "{kind:?}: direct opens under the admitted lease reach the same fixture"
            );
            assert_eq!(counts(), (2, 0), "{kind:?}: both sides stay reserved");
            drop(operation);
            assert_eq!(counts(), (0, 0), "{kind:?}");
            drop(token);
            let opened = guard.calls();
            let operation = reserve_ungated(&expected, kind);
            let refusal = production_capture_refusal(&operation);
            assert!(refusal.contains(CAPTURE_CLOSED), "{kind:?}: {refusal}");
            assert_eq!(
                guard.calls(),
                opened,
                "{kind:?}: the closed gate opens nothing"
            );
            drop(operation);
            assert_eq!(counts(), (0, 0), "{kind:?}");
        }
    }

    #[test]
    fn split_capture_gate_admits_only_the_admitted_kind_and_closes_with_its_token() {
        let (guard, expected) = fixture();
        let token = guard.admit_split_trust(&[Authentication]);
        let operation = reserve_ungated(&expected, Authentication);
        let capture = capture_uniform_split_pair(&operation, RGB, IR)
            .expect("the capture gate admits admitted Authentication");
        drop(token);
        let error = capture
            .revalidate(&operation)
            .expect_err("a receipt is unusable once its admission closes");
        assert!(error.to_string().contains(CAPTURE_CLOSED), "{error}");
        assert!(capture.into_parts(&operation).is_err());
        drop(operation);
        let _token = guard.admit_split_trust(&[Authentication]);
        let operation = reserve_ungated(&expected, Enrollment);
        assert!(capture_refusal(&operation).contains(CAPTURE_CLOSED));
        assert!(
            guard.calls().is_empty(),
            "ungated reservations record no lease and nothing opens"
        );
    }

    #[test]
    fn split_trust_admission_is_bound_to_its_own_fixture() {
        let (outer, expected) = fixture();
        let token = outer.admit_split_trust(&[Enrollment]);
        assert!(
            split_trust_admitted(Enrollment),
            "the installed fixture is admitted"
        );
        let (inner, inner_expected) = fixture();
        assert!(
            !split_trust_admitted(Enrollment),
            "a later fixture does not inherit the admission"
        );
        assert_eq!(
            acquire(&inner_expected, Enrollment).err(),
            Some(CameraLeaseError::SplitActivationDisabled)
        );
        assert_eq!(inner.calls(), vec![lease_call(Enrollment)]);
        drop(inner);
        assert!(
            split_trust_admitted(Enrollment),
            "restoring the admitted fixture restores its admission"
        );
        drop(acquire(&expected, Enrollment).expect("the admitted fixture"));
        drop(token);
        assert_eq!(outer.calls(), vec![lease_call(Enrollment)]);
    }

    #[test]
    fn overlapping_admissions_close_only_after_every_token_drops() {
        let (guard, _expected) = fixture();
        let first = guard.admit_split_trust(&[Enrollment]);
        let second = guard.admit_split_trust(&[Enrollment, Authentication]);
        drop(first);
        assert!(
            split_trust_admitted(Enrollment) && split_trust_admitted(Authentication),
            "the second token still admits both kinds"
        );
        drop(second);
        for kind in TRUST {
            assert!(!split_trust_admitted(kind), "{kind:?}");
        }
        let third = guard.admit_split_trust(&[Authentication]);
        assert!(!split_trust_admitted(Enrollment));
        assert!(split_trust_admitted(Authentication));
        drop(third);
        assert!(!split_trust_admitted(Authentication));
    }

    #[test]
    fn an_unwinding_test_releases_its_admission() {
        let (guard, _expected) = fixture();
        let admitted_inside = std::cell::Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _token = guard.admit_split_trust(&[Enrollment]);
            admitted_inside.set(split_trust_admitted(Enrollment));
            panic!("synthetic unwind with a live admission");
        }));
        assert!(result.is_err());
        assert!(
            admitted_inside.get(),
            "the token admitted Enrollment before the unwind"
        );
        assert!(!split_trust_admitted(Enrollment));
    }

    #[test]
    fn scripted_split_capture_keeps_each_skew_under_one_reservation() {
        let (guard, expected) = fixture();
        let operation = acquire(&expected, Diagnostics).expect("Diagnostics split lease");
        let base = Instant::now();
        for millis in [0, 1, 2_999, 3_000, 3_001, 7_999, 8_000, 8_001] {
            let skew = Duration::from_millis(millis);
            let capture = capture_uniform_split_pair_at(&operation, RGB, IR, base, base + skew)
                .unwrap_or_else(|error| panic!("{millis} ms: {error}"));
            assert_eq!(capture.rgb().captured.start, base);
            assert_eq!(capture.ir().captured.start, base + skew);
            assert_eq!(
                capture
                    .ir()
                    .captured
                    .start
                    .duration_since(capture.rgb().captured.end),
                skew,
                "{millis} ms"
            );
            capture
                .revalidate(&operation)
                .unwrap_or_else(|error| panic!("{millis} ms: {error}"));
        }
        let error = capture_uniform_split_pair_at(
            &operation,
            RGB,
            IR,
            base + Duration::from_millis(1),
            base,
        )
        .err()
        .expect("IR before RGB refuses");
        assert!(
            error
                .to_string()
                .contains("split capture windows are not RGB then IR"),
            "{error}"
        );
        assert_eq!(guard.calls(), vec![lease_call(Diagnostics)]);
        drop(operation);
        assert_eq!(guard.lease_counts_observer()(), (0, 0));
    }

    // Negative controls: these hold before and after the admission works.

    #[test]
    fn split_trust_stays_closed_on_the_installed_fixture_without_a_token() {
        let (guard, expected) = fixture();
        for kind in TRUST {
            assert!(!split_trust_admitted(kind), "{kind:?}");
            assert_eq!(
                acquire(&expected, kind).err(),
                Some(CameraLeaseError::SplitActivationDisabled),
                "{kind:?}"
            );
        }
        for kind in [Preview, Diagnostics, Setup] {
            assert!(!split_trust_admitted(kind), "{kind:?} is not a trust kind");
        }
        assert_eq!(guard.calls(), TRUST.map(lease_call).to_vec());
        assert_eq!(guard.lease_counts_observer()(), (0, 0));
        // Positive control: the Diagnostics path still reserves both sides.
        drop(acquire(&expected, Diagnostics).expect("Diagnostics split lease"));
    }

    #[test]
    fn split_capture_gate_refuses_ungated_trust_reservations_without_admission() {
        let (guard, expected) = fixture();
        for kind in TRUST {
            let operation = reserve_ungated(&expected, kind);
            let refusal = capture_refusal(&operation);
            assert!(refusal.contains(CAPTURE_CLOSED), "{kind:?}: {refusal}");
        }
        assert!(guard.calls().is_empty());
        assert_eq!(guard.lease_counts_observer()(), (0, 0));
    }

    #[test]
    fn admitting_one_trust_kind_admits_no_other() {
        for (admitted, other) in [(Enrollment, Authentication), (Authentication, Enrollment)] {
            let (guard, expected) = fixture();
            let _token = guard.admit_split_trust(&[admitted]);
            for kind in [other, Capture] {
                assert!(
                    !split_trust_admitted(kind),
                    "{admitted:?} also admitted {kind:?}"
                );
                assert_eq!(
                    acquire(&expected, kind).err(),
                    Some(CameraLeaseError::SplitActivationDisabled)
                );
                let operation = reserve_ungated(&expected, kind);
                assert!(capture_refusal(&operation).contains(CAPTURE_CLOSED));
            }
            assert_eq!(guard.calls(), vec![lease_call(other), lease_call(Capture)]);
        }
    }

    #[test]
    fn capture_is_never_admitted() {
        let (guard, expected) = fixture();
        let _token = guard.admit_split_trust(&[
            Capture,
            Enrollment,
            Authentication,
            Preview,
            Diagnostics,
            Setup,
        ]);
        assert!(!split_trust_admitted(Capture));
        for kind in [Preview, Diagnostics, Setup] {
            assert!(!split_trust_admitted(kind), "{kind:?} is not a trust kind");
        }
        assert_eq!(
            acquire(&expected, Capture).err(),
            Some(CameraLeaseError::SplitActivationDisabled)
        );
        let operation = reserve_ungated(&expected, Capture);
        assert!(capture_refusal(&operation).contains(CAPTURE_CLOSED));
        assert_eq!(guard.calls(), vec![lease_call(Capture)]);
    }

    #[test]
    fn dropping_the_admission_closes_acquisition_and_capture_again() {
        let (guard, expected) = fixture();
        let operation = reserve_ungated(&expected, Enrollment);
        drop(guard.admit_split_trust(&[Enrollment, Authentication]));
        for kind in TRUST {
            assert!(!split_trust_admitted(kind), "{kind:?}");
        }
        assert!(capture_refusal(&operation).contains(CAPTURE_CLOSED));
        drop(operation);
        assert_eq!(
            acquire(&expected, Enrollment).err(),
            Some(CameraLeaseError::SplitActivationDisabled)
        );
        assert_eq!(guard.calls(), vec![lease_call(Enrollment)]);
    }

    #[test]
    fn another_thread_is_refused_while_this_thread_is_admitted() {
        let (guard, _expected) = fixture();
        let _token = guard.admit_split_trust(&[Enrollment, Authentication]);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    for kind in TRUST {
                        assert!(
                            !split_trust_admitted(kind),
                            "{kind:?} leaked to another thread"
                        );
                    }
                    // That thread's own fixture, without a token, stays closed.
                    let (other, other_expected) = fixture();
                    for kind in TRUST {
                        assert_eq!(
                            acquire(&other_expected, kind).err(),
                            Some(CameraLeaseError::SplitActivationDisabled)
                        );
                    }
                    assert_eq!(other.calls(), TRUST.map(lease_call).to_vec());
                })
                .join()
                .expect("the other thread's assertions");
        });
    }

    #[test]
    fn split_trust_admission_token_cannot_leave_its_thread() {
        // Compile-time proof: were the token Send, `_` below would match both
        // impls and this test would not build.
        trait AmbiguousIfSend<A> {
            fn some_item() {}
        }
        impl<T: ?Sized> AmbiguousIfSend<()> for T {}
        impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
        let _ = <SplitTrustAdmission<'static> as AmbiguousIfSend<_>>::some_item;
    }
}
