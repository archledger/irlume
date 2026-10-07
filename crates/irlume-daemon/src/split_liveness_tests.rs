// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// The liveness self-test follows the saved camera selection (ADR-0032, split
// liveness self-test amendment). With a split pair selected and no ordinary
// environment override, `SelfTest { Liveness }` runs the non-granting split
// assessment under one split Diagnostics operation over both original sides,
// with the Engine's endpoints on those sides only for the request. IR forced
// off, an unplugged selected pair and unverifiable split configuration refuse
// before any lease. Nothing here loads an enrollment, matches an account,
// grants or releases anything; the fixture refuses every open.

mod split_liveness {
    use super::*;
    use irlume_camera::lease::CameraOperationKind;
    use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
    use irlume_common::split_schema::{AuthorizationRecord, SideFields};

    const RGB: &str = "/dev/irlume-split-live-rgb";
    const IR: &str = "/dev/irlume-split-live-ir";
    const KEY: &str = "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5";
    const CLOSED: &str = "split enrollment and authentication are not enabled";

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
                "IRLUME_CAMERA_REQUIRE_FIXED",
                "IRLUME_FORBID_EXTERNAL_CAMERAS",
                "IRLUME_TCTI",
            ];
            let saved = keys
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect();
            for key in keys {
                std::env::remove_var(key);
            }
            std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-split-live-tpm");
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

    /// The split pair's RGB side and its IR side as one ordinary RGB+IR
    /// camera, which the ordinary pairing rule claims.
    fn ordinary_ir_fixture() -> Guard {
        let endpoint = |path: &str, format| Endpoint {
            path: path.into(),
            formats: vec![format],
        };
        let camera = |topology: &str, identity: &str, port: u8, endpoints| Camera {
            topology: topology.into(),
            identity: identity.into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
            endpoints,
        };
        Guard::install(&[
            camera(
                "/devices/split-live/rgb",
                "1234:0001:rgb",
                8,
                vec![endpoint(RGB, *b"YUYV")],
            ),
            camera(
                "/devices/split-live/ir",
                "1234:0002:ir",
                5,
                vec![
                    endpoint("/dev/irlume-split-live-ir-color", *b"YUYV"),
                    endpoint(IR, *b"GREY"),
                ],
            ),
        ])
        .unwrap()
    }

    /// The split pair's RGB side and, when `ir`, its IR side, each a fixed
    /// single-endpoint USB device. Every open is refused and recorded.
    fn fixture(ir: bool) -> Guard {
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
        let mut cameras = vec![camera(
            "/devices/split-live/rgb",
            "1234:0001:rgb",
            8,
            RGB,
            *b"YUYV",
        )];
        if ir {
            cameras.push(camera(
                "/devices/split-live/ir",
                "1234:0002:ir",
                5,
                IR,
                *b"GREY",
            ));
        }
        Guard::install(&cameras).unwrap()
    }

    /// Authorize the fixture split pair, saving it as the selection when
    /// `selected`.
    fn authorize(selected: bool) {
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
        let key = irlume_common::split_key::SplitPairKey::parse_canonical(KEY).unwrap();
        irlume_common::split_publish::publish_split(&[record], selected.then_some(&key)).unwrap();
    }

    /// The daemon's standing devices on a split-only machine: the first RGB
    /// node, here the split's own RGB side, and no IR.
    fn standing_fallback(engine: &mut irlume_auth::Engine) {
        engine.set_devices(RGB, "");
        assert!(!engine.ir_available());
    }

    fn liveness(engine: &mut irlume_auth::Engine) -> String {
        match dispatch(
            Request::SelfTest {
                kind: irlume_common::SelfTestKind::Liveness,
            },
            &peer(0),
            engine,
        ) {
            Response::Error(reason) => reason,
            Response::SelfTest { passed, detail } => format!("self-test {passed}: {detail}"),
            other => panic!("unexpected self-test reply: {other:?}"),
        }
    }

    fn standing(engine: &irlume_auth::Engine) -> (String, String, bool) {
        (
            engine.rgb_device().to_owned(),
            engine.ir_device().to_owned(),
            engine.ir_available(),
        )
    }

    // RED: these need the selection-aware liveness self-test.

    #[test]
    fn liveness_selftest_assesses_the_selected_split_under_one_diagnostics_operation() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("split-live-selected");
        let _environment = Environment::clear();
        let recorder = fixture(true);
        let counts = recorder.lease_counts_observer();
        authorize(true);
        standing_fallback(&mut engine);
        let before = standing(&engine);
        let reply = liveness(&mut engine);
        assert!(!reply.contains(CLOSED), "{reply}");
        assert!(
            reply.contains("fixture RGB open refused"),
            "the refusing fixture ends the split capture at its RGB side: {reply}"
        );
        assert_eq!(
            recorder.calls(),
            vec![
                Call::Lease {
                    endpoints: vec![RGB.into(), IR.into()],
                    kind: CameraOperationKind::Diagnostics,
                },
                Call::OpenRgb(RGB.into()),
            ],
            "one split Diagnostics operation over both original sides: no trust kind, \
             no single-endpoint lease and no IR open after the refused RGB side"
        );
        assert_eq!(counts(), (0, 0), "both reservations released");
        assert_eq!(
            standing(&engine),
            before,
            "the standing endpoints come back"
        );
        engine.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn liveness_selftest_refuses_a_selected_split_with_ir_forced_off_before_any_lease() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("split-live-ir-off");
        let _environment = Environment::clear();
        let recorder = fixture(true);
        authorize(true);
        standing_fallback(&mut engine);
        std::env::set_var("IRLUME_FORCE_NO_IR", "1");
        let reply = liveness(&mut engine);
        std::env::remove_var("IRLUME_FORCE_NO_IR");
        assert!(reply.contains("IR is forced off"), "{reply}");
        assert!(recorder.calls().is_empty(), "{:?}", recorder.calls());
        engine.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn liveness_selftest_refuses_an_unplugged_selected_split_before_any_lease() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("split-live-unplugged");
        let _environment = Environment::clear();
        let recorder = fixture(false);
        authorize(true);
        standing_fallback(&mut engine);
        let reply = liveness(&mut engine);
        assert!(reply.contains("not connected"), "{reply}");
        assert!(
            recorder.calls().is_empty(),
            "no standing fallback: {:?}",
            recorder.calls()
        );
        engine.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn liveness_selftest_names_an_ordinary_camera_claim_on_a_selected_split() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("split-live-ordinary-claim");
        let _environment = Environment::clear();
        let recorder = ordinary_ir_fixture();
        authorize(true);
        standing_fallback(&mut engine);
        let reply = liveness(&mut engine);
        assert!(
            reply.contains("belongs to an ordinary RGB+IR camera"),
            "a connected side that an ordinary pair claims is named as such: {reply}"
        );
        let diagnostics = match dispatch(Request::CameraDiagnostics, &peer(0), &mut engine) {
            Response::CameraDiagnostics(report) => *report,
            other => panic!("expected a diagnostics report, got {other:?}"),
        };
        assert_eq!(
            (
                diagnostics.rgb.state.as_str(),
                diagnostics.ir.state.as_str()
            ),
            ("missing", "missing"),
            "diagnostics keep their documented unresolved-selection report"
        );
        assert!(
            recorder.calls().is_empty(),
            "nothing is opened for a pair that does not resolve: {:?}",
            recorder.calls()
        );
        engine.set_devices(NO_RGB, NO_IR);
    }

    // Control: GREEN before and after.

    #[test]
    fn liveness_selftest_without_a_selected_split_never_takes_a_split_lease() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("split-live-unselected");
        let _environment = Environment::clear();
        let recorder = fixture(true);
        authorize(false);
        standing_fallback(&mut engine);
        let _ = liveness(&mut engine);
        let calls = recorder.calls();
        assert!(
            !calls.iter().any(|call| matches!(
                call,
                Call::Lease { endpoints, .. } if endpoints.len() == 2
            )),
            "an authorization alone selects nothing: {calls:?}"
        );
        assert!(
            !calls.contains(&Call::OpenIr(IR.into())),
            "the unselected split's IR side is never opened: {calls:?}"
        );
        engine.set_devices(NO_RGB, NO_IR);
    }
}
