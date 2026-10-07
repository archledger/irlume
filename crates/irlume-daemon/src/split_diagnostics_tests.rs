// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// Camera diagnostics follow the saved camera selection (ADR-0032,
// selection-aware diagnostics amendment). With a split pair selected and no
// ordinary environment override, `CameraDiagnostics` measures the selected
// pair's two original sides, RGB then IR, under one split Diagnostics
// operation, never the daemon's standing fallback camera and never a
// single-endpoint lease on a split side. A selected pair that is not
// connected reads as missing, and a split publication that cannot be
// verified reads as unknown, with no camera opened. Without a selected
// split, or with an ordinary override, the report is the standing pair's,
// as before. Diagnostics is not a trust kind: nothing here can enroll,
// authenticate or grant, and the fixture refuses every open.

mod split_diagnostics {
    use super::*;
    use irlume_camera::lease::CameraOperationKind;
    use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
    use irlume_common::split_schema::{AuthorizationRecord, SideFields};

    const RGB: &str = "/dev/irlume-split-diag-rgb";
    const IR: &str = "/dev/irlume-split-diag-ir";
    const O_RGB: &str = "/dev/irlume-split-diag-ordinary-rgb";
    const O_IR: &str = "/dev/irlume-split-diag-ordinary-ir";
    const KEY: &str = "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5";

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
            std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-split-diag-tpm");
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

    /// The split pair's RGB side and, when `ir`, its IR side, each a fixed
    /// single-endpoint USB device, plus one fixed ordinary RGB+IR unit when
    /// `ordinary`. Every open is refused and recorded.
    fn fixture(ir: bool, ordinary: bool) -> Guard {
        let camera = |topology: &str, identity: &str, port: u8, endpoints| Camera {
            topology: topology.into(),
            identity: identity.into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
            endpoints,
        };
        let endpoint = |path: &str, format| Endpoint {
            path: path.into(),
            formats: vec![format],
        };
        let mut cameras = vec![camera(
            "/devices/split-diag/rgb",
            "1234:0001:rgb",
            8,
            vec![endpoint(RGB, *b"YUYV")],
        )];
        if ir {
            cameras.push(camera(
                "/devices/split-diag/ir",
                "1234:0002:ir",
                5,
                vec![endpoint(IR, *b"GREY")],
            ));
        }
        if ordinary {
            cameras.push(camera(
                "/devices/split-diag/ordinary",
                "1234:0003:ordinary",
                3,
                vec![endpoint(O_RGB, *b"YUYV"), endpoint(O_IR, *b"GREY")],
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

    fn diagnose(engine: &mut irlume_auth::Engine) -> irlume_common::CameraDiagnosticsReport {
        match dispatch(Request::CameraDiagnostics, &peer(0), engine) {
            Response::CameraDiagnostics(report) => *report,
            other => panic!("expected a diagnostics report, got {other:?}"),
        }
    }

    fn split_diagnostics_lease() -> Call {
        Call::Lease {
            endpoints: vec![RGB.into(), IR.into()],
            kind: CameraOperationKind::Diagnostics,
        }
    }

    fn touches_split_side(call: &Call) -> bool {
        match call {
            Call::Lease { endpoints, .. } => endpoints.iter().any(|e| e == RGB || e == IR),
            Call::OpenRgb(path) | Call::OpenIr(path) => path == RGB || path == IR,
            Call::Scan => false,
        }
    }

    // RED: these need selection-aware diagnostics.

    #[test]
    fn camera_diagnostics_measure_the_selected_split_under_one_diagnostics_operation() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("split-diag-selected");
        let _environment = Environment::clear();
        let recorder = fixture(true, false);
        authorize(true);
        standing_fallback(&mut engine);
        let report = diagnose(&mut engine);
        assert_eq!(
            recorder.calls(),
            vec![
                split_diagnostics_lease(),
                Call::OpenRgb(RGB.into()),
                Call::OpenIr(IR.into()),
            ],
            "one split Diagnostics operation over both original sides, RGB then IR: \
             no single-endpoint lease and no standing fallback"
        );
        assert!(report.rgb.known && report.ir.known, "{report:?}");
        assert_eq!(
            (report.rgb.state.as_str(), report.ir.state.as_str()),
            ("unknown", "unknown"),
            "the fixture refuses both opens, so each role is unmeasured, never missing"
        );
        assert!(
            report.illumination.is_some(),
            "the IR side's illumination state"
        );
        assert_eq!(report.capture_strategy, "burst");
        engine.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn camera_diagnostics_report_an_unplugged_selected_split_as_missing() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("split-diag-unplugged");
        let _environment = Environment::clear();
        let recorder = fixture(false, false);
        authorize(true);
        standing_fallback(&mut engine);
        let report = diagnose(&mut engine);
        assert!(
            recorder.calls().is_empty(),
            "an unplugged selected split opens nothing, not the standing RGB side: {:?}",
            recorder.calls()
        );
        assert!(report.rgb.known && report.ir.known, "{report:?}");
        assert_eq!(
            (report.rgb.state.as_str(), report.ir.state.as_str()),
            ("missing", "missing")
        );
        assert!(report.rgb.evidence.is_none() && report.ir.evidence.is_none());
        assert!(report.skew_us.is_none() && report.illumination.is_none());
        engine.set_devices(NO_RGB, NO_IR);
    }

    /// Rewrite `split_digest` in the sandbox's `cameras.conf`.
    fn set_split_digest(dir: &std::path::Path, digest: &str) {
        let conf = dir.join("config/cameras.conf");
        let text = std::fs::read_to_string(&conf).unwrap();
        let rewritten: String = text
            .lines()
            .map(|line| match line.strip_prefix("split_digest=") {
                Some(_) => format!("split_digest={digest}"),
                None => line.to_owned(),
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&conf, rewritten + "\n").unwrap();
    }

    #[test]
    fn camera_diagnostics_report_an_unverifiable_split_publication_as_unknown() {
        // A referenced generation whose bytes no longer match a well-formed
        // digest, and a split key that breaks the configuration rule.
        let zeros = format!("sha256:{}", "0".repeat(64));
        for digest in [zeros.as_str(), "not-a-digest"] {
            let _guard = env_lock();
            let mut engine = engine();
            let sb = sandbox("split-diag-unverifiable");
            let _environment = Environment::clear();
            let recorder = fixture(true, false);
            authorize(true);
            set_split_digest(&sb.dir, digest);
            standing_fallback(&mut engine);
            let report = diagnose(&mut engine);
            assert!(
                recorder.calls().is_empty(),
                "{digest}: unverifiable split configuration opens nothing: {:?}",
                recorder.calls()
            );
            assert!(report.rgb.known && report.ir.known, "{digest}: {report:?}");
            assert_eq!(
                (report.rgb.state.as_str(), report.ir.state.as_str()),
                ("unknown", "unknown"),
                "{digest}"
            );
            engine.set_devices(NO_RGB, NO_IR);
        }
    }

    // Controls: GREEN before and after.

    #[test]
    fn camera_diagnostics_without_a_selected_split_keep_the_standing_device() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("split-diag-unselected");
        let _environment = Environment::clear();
        let recorder = fixture(true, false);
        authorize(false);
        standing_fallback(&mut engine);
        let report = diagnose(&mut engine);
        assert_eq!(
            recorder.calls(),
            vec![
                Call::Lease {
                    endpoints: vec![RGB.into()],
                    kind: CameraOperationKind::Capture,
                },
                Call::OpenRgb(RGB.into()),
            ],
            "an authorization alone selects nothing: the standing device, as before"
        );
        assert!(report.rgb.known && !report.ir.known, "{report:?}");
        assert_eq!(report.ir.state, "missing");
        engine.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn camera_diagnostics_keep_the_standing_device_when_cameras_conf_has_no_split_key() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("split-diag-no-split-key");
        let _environment = Environment::clear();
        let recorder = fixture(true, false);
        // A malformed ordinary file with no split key: a machine without
        // split cameras keeps exactly the report it had.
        std::fs::write(sb.dir.join("config/cameras.conf"), "mode=sideways\n").unwrap();
        standing_fallback(&mut engine);
        let report = diagnose(&mut engine);
        assert_eq!(
            recorder.calls(),
            vec![
                Call::Lease {
                    endpoints: vec![RGB.into()],
                    kind: CameraOperationKind::Capture,
                },
                Call::OpenRgb(RGB.into()),
            ]
        );
        assert!(report.rgb.known && !report.ir.known, "{report:?}");
        engine.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn camera_diagnostics_follow_an_ordinary_environment_override_over_a_selected_split() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("split-diag-override");
        let _environment = Environment::clear();
        let recorder = fixture(true, true);
        authorize(true);
        std::env::set_var("IRLUME_RGB_DEVICE", O_RGB);
        std::env::set_var("IRLUME_IR_DEVICE", O_IR);
        engine.set_devices(O_RGB, O_IR);
        let report = diagnose(&mut engine);
        let calls = recorder.calls();
        assert!(
            !calls.iter().any(touches_split_side),
            "an ordinary override decides, as for every request: {calls:?}"
        );
        assert!(
            calls.contains(&Call::OpenRgb(O_RGB.into())),
            "the override pair is measured: {calls:?}"
        );
        assert!(report.rgb.known, "{report:?}");
        engine.set_devices(NO_RGB, NO_IR);
    }
}
