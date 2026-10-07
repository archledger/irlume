// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// The closed default for the remaining camera entries (ADR-0032 acceptance
// case 15, plan W4). With a saved selected split and no admission token,
// elevation, app-consent and login `Authenticate`, `UnsealPassword`,
// `SupportProbe`, `TuneCaptureMode`, `CaptureModeStatus` and the liveness
// `SelfTest` never lease or open either side. `CameraDiagnostics` measures
// the selected pair under one split Diagnostics operation, never a trust
// kind (ADR-0032, selection-aware diagnostics amendment). The alignment
// `SelfTest` checks model determinism on any face frame and keeps the
// standing device, with at most one single-endpoint Capture lease, never a
// split lease or both sides. No row grants, releases or writes trust or
// qualification. The enrollment, identify, position and
// unlock-service rows live in `request_preparation_tests.rs`.

mod split_closed_matrix {
    use super::*;
    use irlume_camera::lease::CameraOperationKind;
    use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
    use irlume_common::split_schema::{AuthorizationRecord, SideFields};

    const RGB: &str = "/dev/irlume-split-closed-rgb";
    const IR: &str = "/dev/irlume-split-closed-ir";

    /// Clears the device and IR overrides the shared engine sets and pins
    /// the TPM transport to a node that does not exist. Restores every
    /// value on drop.
    struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl Environment {
        fn clear() -> Self {
            let keys = [
                "IRLUME_RGB_DEVICE",
                "IRLUME_IR_DEVICE",
                "IRLUME_FORCE_NO_IR",
                "IRLUME_TCTI",
            ];
            let saved = keys
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect();
            for key in keys {
                std::env::remove_var(key);
            }
            std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-split-closed-tpm");
            Self(saved)
        }
    }
    impl Drop for Environment {
        fn drop(&mut self) {
            for (key, value) in self.0.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// The split pair's two fixed single-endpoint devices. Every open is
    /// refused and recorded.
    fn fixture() -> Guard {
        let camera = |topology: &str, identity: &str, port: u8, path: &str, format| Camera {
            topology: topology.into(),
            identity: identity.into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
            endpoints: vec![Endpoint {
                path: path.into(),
                formats: vec![format],
            }],
        };
        Guard::install(&[
            camera(
                "/devices/split-closed/rgb",
                "1234:0001:rgb",
                8,
                RGB,
                *b"YUYV",
            ),
            camera("/devices/split-closed/ir", "1234:0002:ir", 5, IR, *b"GREY"),
        ])
        .unwrap()
    }

    /// Authorize the fixture pair and save it as the selection.
    fn select_split() {
        let side = |identity: &str, path: &str, port| SideFields {
            identity: identity.into(),
            path: path.into(),
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
        };
        let record = AuthorizationRecord {
            rgb: side("1234:0001:rgb", RGB, 8),
            ir: side("1234:0002:ir", IR, 5),
        };
        let key = irlume_common::split_key::SplitPairKey::parse_canonical(
            "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5",
        )
        .unwrap();
        irlume_common::split_publish::publish_split(&[record], Some(&key)).unwrap();
    }

    /// What a diagnostic entry may do on the standing device: nothing, or
    /// one single-endpoint Capture lease on the standing RGB node and its
    /// open.
    fn standing_diagnostic(calls: &[Call]) -> bool {
        let lease = Call::Lease {
            endpoints: vec![RGB.into()],
            kind: CameraOperationKind::Capture,
        };
        calls.is_empty() || calls == [lease, Call::OpenRgb(RGB.into())]
    }

    /// What the selection-aware diagnostics do for the selected split: one
    /// split Diagnostics operation over both original sides, RGB then IR.
    fn split_diagnostic(calls: &[Call]) -> bool {
        let lease = Call::Lease {
            endpoints: vec![RGB.into(), IR.into()],
            kind: CameraOperationKind::Diagnostics,
        };
        calls == [lease, Call::OpenRgb(RGB.into()), Call::OpenIr(IR.into())]
    }

    /// What one row may do at the camera boundary.
    #[derive(Clone, Copy)]
    enum Expect {
        /// Lease and open nothing.
        Nothing,
        /// [`standing_diagnostic`].
        Standing,
        /// [`split_diagnostic`].
        SplitDiagnostics,
    }

    fn authenticate(user: &str, service: &str) -> Request {
        Request::Authenticate {
            structured_errors: false,
            user: user.into(),
            service: Some(service.into()),
            intent_confirmation: None,
        }
    }

    #[test]
    fn selected_split_keeps_every_remaining_camera_entry_closed() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("split-closed-matrix");
        let _environment = Environment::clear();
        let recorder = fixture();
        engine.set_devices(RGB, IR);
        select_split();
        let user = users::name_for_uid(0).unwrap();
        write_enrollment(&sb.dir, &enrollment_with(&user, &["Face Scan 1"]));
        plant_fake_envelope(&user);
        let account = sb.dir.join(format!("{user}.json"));
        let enrolled = std::fs::read(&account).unwrap();
        let envelope = irlume_core::keyring::envelope_path(&user);
        let sealed = std::fs::read(&envelope).unwrap();
        let unseal = Request::UnsealPassword {
            user: user.clone(),
            service: Some("login".into()),
        };
        let tune = Request::TuneCaptureMode {
            rounds: Some(1),
            emit_record_path: None,
        };
        let self_test = |kind| Request::SelfTest { kind };
        // (row, what it may do at the camera boundary, request)
        let requests = [
            ("elevation", Expect::Nothing, authenticate(&user, "sudo")),
            (
                "app consent",
                Expect::Nothing,
                authenticate(&user, "polkit-1"),
            ),
            ("login", Expect::Nothing, authenticate(&user, "login")),
            ("unseal", Expect::Nothing, unseal),
            (
                "support probe",
                Expect::Nothing,
                Request::SupportProbe { since_ms: 0 },
            ),
            ("tune", Expect::Nothing, tune),
            ("capture mode", Expect::Nothing, Request::CaptureModeStatus),
            (
                "liveness self-test",
                Expect::Nothing,
                self_test(irlume_common::SelfTestKind::Liveness),
            ),
            (
                "diagnostics",
                Expect::SplitDiagnostics,
                Request::CameraDiagnostics,
            ),
            (
                "alignment self-test",
                Expect::Standing,
                self_test(irlume_common::SelfTestKind::AlignmentIdentity),
            ),
        ];
        let mut seen = 0;
        for (row, expect, request) in requests {
            let response = dispatch(request, &peer(0), &mut engine);
            assert!(!is_face_grant(&response), "{row}: {response:?}");
            assert!(
                !matches!(response, Response::PasswordUnsealed { .. }),
                "{row}: {response:?}"
            );
            let calls = recorder.calls()[seen..].to_vec();
            seen += calls.len();
            match expect {
                Expect::Nothing => assert!(
                    calls.is_empty(),
                    "{row}: a selected split leases and opens nothing while activation is closed: \
                     {calls:?} -> {response:?}"
                ),
                Expect::Standing => assert!(
                    standing_diagnostic(&calls),
                    "{row}: a diagnostic entry stays on the standing device: {calls:?} -> {response:?}"
                ),
                Expect::SplitDiagnostics => assert!(
                    split_diagnostic(&calls),
                    "{row}: diagnostics measure the selected pair under one split Diagnostics \
                     operation: {calls:?} -> {response:?}"
                ),
            }
        }
        assert_eq!(std::fs::read(&account).unwrap(), enrolled);
        assert_eq!(std::fs::read(&envelope).unwrap(), sealed);
        assert!(!sb.dir.join("capture-qualifications").exists());
        engine.set_devices(NO_RGB, NO_IR);
    }
}
