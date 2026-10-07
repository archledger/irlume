// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// The closed default for the remaining camera entries (ADR-0032 acceptance
// case 15, plan W4). With a saved selected split and no admission token,
// elevation, app-consent and login `Authenticate`, `UnsealPassword`,
// `SupportProbe`, `TuneCaptureMode`, `CaptureModeStatus` and the liveness
// `SelfTest` never lease or open either side. `CameraDiagnostics` and the
// alignment `SelfTest` keep their existing diagnostic gate (ADR-0032,
// guarded split operation-choice amendment): they act on the standing
// device with at most one single-endpoint Capture lease, never a split
// lease, a trust kind or both sides. No row grants, releases or writes
// trust or qualification. The enrollment, identify, position and
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
            camera("/devices/split-closed/rgb", "1234:0001:rgb", 8, RGB, *b"YUYV"),
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
        // (row, a diagnostic entry on the standing device, request)
        let requests = [
            ("elevation", false, authenticate(&user, "sudo")),
            ("app consent", false, authenticate(&user, "polkit-1")),
            ("login", false, authenticate(&user, "login")),
            ("unseal", false, unseal),
            ("support probe", false, Request::SupportProbe { since_ms: 0 }),
            ("tune", false, tune),
            ("capture mode", false, Request::CaptureModeStatus),
            (
                "liveness self-test",
                false,
                self_test(irlume_common::SelfTestKind::Liveness),
            ),
            ("diagnostics", true, Request::CameraDiagnostics),
            (
                "alignment self-test",
                true,
                self_test(irlume_common::SelfTestKind::AlignmentIdentity),
            ),
        ];
        let mut seen = 0;
        for (row, diagnostic, request) in requests {
            let response = dispatch(request, &peer(0), &mut engine);
            assert!(!is_face_grant(&response), "{row}: {response:?}");
            assert!(
                !matches!(response, Response::PasswordUnsealed { .. }),
                "{row}: {response:?}"
            );
            let calls = recorder.calls()[seen..].to_vec();
            seen += calls.len();
            if diagnostic {
                assert!(
                    standing_diagnostic(&calls),
                    "{row}: a diagnostic entry stays on the standing device: {calls:?} -> {response:?}"
                );
            } else {
                assert!(
                    calls.is_empty(),
                    "{row}: a selected split leases and opens nothing while activation is closed: \
                     {calls:?} -> {response:?}"
                );
            }
        }
        assert_eq!(std::fs::read(&account).unwrap(), enrolled);
        assert_eq!(std::fs::read(&envelope).unwrap(), sealed);
        assert!(!sb.dir.join("capture-qualifications").exists());
        engine.set_devices(NO_RGB, NO_IR);
    }
}
