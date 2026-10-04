// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

mod request_preparation_gates {
    use super::*;
    use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
    use irlume_common::split_schema::{AuthorizationRecord, SideFields};

    const RGB: &str = "/dev/irlume-request-fixture-rgb";
    const IR: &str = "/dev/irlume-request-fixture-ir";
    const CLOSED: &str = "split enrollment and authentication are not enabled";

    struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl Environment {
        fn clear() -> Self {
            let keys = [
                "IRLUME_RGB_DEVICE",
                "IRLUME_IR_DEVICE",
                "IRLUME_FORCE_NO_IR",
            ];
            let saved = keys
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect();
            for key in keys {
                std::env::remove_var(key);
            }
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

    fn fixture(split: bool) -> Guard {
        let camera = |topology: &str, identity: &str, port: u8, endpoints| Camera {
            topology: topology.into(),
            identity: identity.into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
            endpoints,
        };
        let rgb = Endpoint {
            path: RGB.into(),
            formats: vec![*b"YUYV"],
        };
        let ir = Endpoint {
            path: IR.into(),
            formats: vec![*b"GREY"],
        };
        let cameras = if split {
            vec![
                camera(
                    "/devices/request-fixture/rgb",
                    "1234:0001:rgb",
                    8,
                    vec![rgb],
                ),
                camera("/devices/request-fixture/ir", "1234:0002:ir", 5, vec![ir]),
            ]
        } else {
            vec![camera(
                "/devices/request-fixture/ordinary",
                "1234:0001:ordinary",
                8,
                vec![rgb, ir],
            )]
        };
        assert_eq!(
            irlume_camera::test_support::grey_fixture(),
            [0, 64, 128, 255]
        );
        Guard::install(&cameras).unwrap()
    }

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

    #[test]
    fn selected_split_dispatch_matrix_refuses_before_real_lease_and_trust_write() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("request-preparation-matrix");
        let _environment = Environment::clear();
        let recorder = fixture(true);
        engine.set_devices(RGB, IR);
        select_split();
        let user = users::name_for_uid(0).unwrap();
        write_enrollment(&sb.dir, &enrollment_with(&user, &["Face Scan 1"]));
        let before = std::fs::read(sb.dir.join(format!("{user}.json"))).unwrap();
        let requests = vec![
            Request::Enroll {
                user: user.clone(),
                profile: None,
                scans: Some(1),
                reset: false,
            },
            Request::Enroll {
                user: user.clone(),
                profile: None,
                scans: Some(1),
                reset: true,
            },
            Request::AddScan {
                user: user.clone(),
                profile: "fixture".into(),
                scans: Some(1),
                report_enrollment: true,
            },
            Request::AddCameraGroup {
                user: user.clone(),
                profile: None,
                scans: Some(1),
            },
            Request::Identify,
            Request::IdentifyFor { user: user.clone() },
            Request::PositionSample { user: None },
        ];
        for request in requests {
            let response = dispatch(request, &peer(0), &mut engine);
            assert!(
                matches!(response, Response::Error(ref reason) if reason.contains(CLOSED)),
                "{response:?}"
            );
            assert!(recorder.calls().is_empty(), "{:?}", recorder.calls());
        }
        for policy in ["dual", "ir-only-experimental"] {
            std::fs::write(
                sb.dir.join("config/settings.conf"),
                format!("face_sensor_policy={policy}\n"),
            )
            .unwrap();
            let response = dispatch(
                Request::Authenticate {
                    user: user.clone(),
                    service: Some("kscreensaver".into()),
                    structured_errors: false,
                    intent_confirmation: None,
                },
                &peer(0),
                &mut engine,
            );
            assert!(format!("{response:?}").contains(CLOSED), "{response:?}");
            assert!(recorder.calls().is_empty());
        }
        // The actual face-backed release helper retains its normal retry/key
        // ownership. A bogus armed envelope must never reach secret preparation.
        plant_fake_envelope(&user);
        let envelope_path = irlume_core::keyring::envelope_path(&user);
        let envelope_before = std::fs::read(&envelope_path).unwrap();
        let response = do_unseal_password(&user, None, &mut engine);
        assert!(
            matches!(response, Response::Error(ref reason) if reason.contains(CLOSED)),
            "{response:?}"
        );
        assert!(recorder.calls().is_empty());
        assert_eq!(std::fs::read(envelope_path).unwrap(), envelope_before);
        assert_eq!(
            std::fs::read(sb.dir.join(format!("{user}.json"))).unwrap(),
            before
        );
        engine.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn selected_split_sessions_refuse_before_started_events() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("request-preparation-sessions");
        let _environment = Environment::clear();
        let recorder = fixture(true);
        engine.set_devices(RGB, IR);
        select_split();
        let user = users::name_for_uid(0).unwrap();
        for improve in [false, true] {
            let (worker, mut connection) = enrollment_session::channel(arbiter::CancelToken::new());
            let request = Request::EnrollmentSession {
                user: user.clone(),
                profile: improve.then(|| "fixture".into()),
                scans: 1,
                improve,
            };
            let state = diagnostics::DiagnosticState::default();
            let scope = state.begin_for(
                diagnostic_operation_class(&request),
                diagnostic_owner(&request, &peer(0)),
            );
            let reply = dispatch_scoped_session(
                request,
                &peer(0),
                &mut engine,
                &scope,
                None,
                Some(&worker),
                None,
            );
            assert!(
                matches!(reply.response, Response::Error(ref reason) if reason.contains(CLOSED)),
                "{:?}",
                reply.response
            );
            let (ours, mut theirs) = UnixStream::pair().unwrap();
            connection.pump(&ours).unwrap();
            theirs.set_nonblocking(true).unwrap();
            let mut byte = [0];
            assert_eq!(
                std::io::Read::read(&mut theirs, &mut byte)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        let (worker, mut connection) = position_session::channel(arbiter::CancelToken::new());
        let request = Request::PositionSession { user: None };
        let state = diagnostics::DiagnosticState::default();
        let scope = state.begin_for(
            diagnostic_operation_class(&request),
            diagnostic_owner(&request, &peer(0)),
        );
        let reply = dispatch_scoped_session(
            request,
            &peer(0),
            &mut engine,
            &scope,
            None,
            None,
            Some(&worker),
        );
        assert!(
            matches!(reply.response, Response::Error(ref reason) if reason.contains(CLOSED)),
            "{:?}",
            reply.response
        );
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        connection.pump(&ours).unwrap();
        theirs.set_nonblocking(true).unwrap();
        let mut byte = [0];
        assert_eq!(
            std::io::Read::read(&mut theirs, &mut byte)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(recorder.calls().is_empty());
        engine.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn ordinary_position_dispatch_control_reaches_real_lease_and_open() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("request-preparation-ordinary");
        let _environment = Environment::clear();
        let recorder = fixture(false);
        engine.set_devices(RGB, IR);
        let response = dispatch(
            Request::PositionSample { user: None },
            &peer(0),
            &mut engine,
        );
        assert!(
            matches!(response, Response::Error(_)),
            "non-granting fixture must refuse capture"
        );
        let calls = recorder.calls();
        assert!(
            calls.iter().any(|call| matches!(call, Call::Lease { .. })),
            "{calls:?}"
        );
        assert!(calls.contains(&Call::OpenRgb(RGB.into())), "{calls:?}");
        engine.set_devices(NO_RGB, NO_IR);
    }
}
