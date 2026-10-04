// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
use irlume_common::split_schema::{AuthorizationRecord, SideFields};
use std::{cell::Cell, ffi::OsString, path::PathBuf};

struct Fixture {
    dir: PathBuf,
    rgb: String,
    ir: String,
    saved: Vec<(&'static str, Option<OsString>)>,
    recorder: Guard,
}

impl Fixture {
    fn new(split: bool) -> Self {
        Self::with_fixed(split, true)
    }

    fn with_fixed(split: bool, fixed: bool) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "irlume-request-prep-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let rgb = "/dev/irlume-fixture-rgb".to_owned();
        let ir = "/dev/irlume-fixture-ir".to_owned();
        let keys = [
            "IRLUME_CONFIG_DIR",
            "IRLUME_STATE_DIR",
            "IRLUME_RGB_DEVICE",
            "IRLUME_IR_DEVICE",
            "IRLUME_FORCE_NO_IR",
            "IRLUME_CAMERA_REQUIRE_FIXED",
            "IRLUME_TEMPLATE_KEY_DIR",
        ];
        let saved = keys
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", dir.join("private-template-keys"));
        for key in [
            "IRLUME_RGB_DEVICE",
            "IRLUME_IR_DEVICE",
            "IRLUME_FORCE_NO_IR",
        ] {
            std::env::remove_var(key);
        }
        let unit = |topology: &str, identity: &str, port: u8, endpoints| Camera {
            topology: topology.into(),
            identity: identity.into(),
            fixed,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
            endpoints,
        };
        let rgb_endpoint = Endpoint {
            path: rgb.clone(),
            formats: vec![*b"YUYV"],
        };
        let ir_endpoint = Endpoint {
            path: ir.clone(),
            formats: vec![*b"GREY"],
        };
        let cameras = if split {
            vec![
                unit(
                    "/devices/fixture/rgb",
                    "1234:0001:rgb",
                    8,
                    vec![rgb_endpoint],
                ),
                unit("/devices/fixture/ir", "1234:0002:ir", 5, vec![ir_endpoint]),
            ]
        } else {
            vec![unit(
                "/devices/fixture/ordinary",
                "1234:0001:ordinary",
                8,
                vec![rgb_endpoint, ir_endpoint],
            )]
        };
        let recorder = Guard::install(&cameras).unwrap();
        assert_eq!(
            irlume_camera::test_support::grey_fixture(),
            [0, 64, 128, 255]
        );
        Self {
            dir,
            rgb,
            ir,
            saved,
            recorder,
        }
    }

    fn select_split(&self) {
        let side = |identity: &str, path: &str, port| SideFields {
            identity: identity.into(),
            path: path.into(),
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
        };
        let record = AuthorizationRecord {
            rgb: side("1234:0001:rgb", &self.rgb, 8),
            ir: side("1234:0002:ir", &self.ir, 5),
        };
        let key = irlume_common::split_key::SplitPairKey::parse_canonical(
            "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5",
        )
        .unwrap();
        irlume_common::split_publish::publish_split(&[record], Some(&key)).unwrap();
    }
}

impl Drop for Fixture {
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

struct Devices<'a> {
    engine: &'a mut Engine,
    previous: (String, String, bool),
}
impl<'a> Devices<'a> {
    fn new(engine: &'a mut Engine, fixture: &Fixture) -> Self {
        let previous = (
            engine.rgb_dev.clone(),
            engine.ir_dev.clone(),
            engine.ir_available,
        );
        engine.set_devices(&fixture.rgb, &fixture.ir);
        // The synthetic inventory has a native GREY IR endpoint. No /dev node
        // is created; only this private test field supplies its availability.
        engine.ir_available = true;
        assert!(engine.ir_available);
        Self { engine, previous }
    }
}
impl Drop for Devices<'_> {
    fn drop(&mut self) {
        self.engine.rgb_dev = std::mem::take(&mut self.previous.0);
        self.engine.ir_dev = std::mem::take(&mut self.previous.1);
        self.engine.ir_available = self.previous.2;
    }
}

struct StopAfterOpens(Cell<usize>);
impl EnrollmentObserver for StopAfterOpens {
    fn check(&self) -> irlume_common::Result<()> {
        self.0.set(self.0.get() + 1);
        if self.0.get() >= 3 {
            Err(irlume_common::Error::Preempted(
                "fixture capture stop".into(),
            ))
        } else {
            Ok(())
        }
    }
}

#[test]
fn selected_split_enroll_refuses_before_preflight_and_lease() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    fixture.select_split();
    let devices = Devices::new(&mut shared.engine, &fixture);
    let preflights = Cell::new(0);
    let result = devices.engine.enroll_profile_observed(
        "request-fixture",
        None,
        1,
        |_| {
            preflights.set(preflights.get() + 1);
            true
        },
        &(),
        &StopAfterOpens(Cell::new(0)),
    );
    assert_eq!(
        preflights.get(),
        0,
        "closed split selection must precede IR preflight"
    );
    assert!(
        fixture.recorder.calls().is_empty(),
        "{:?}",
        fixture.recorder.calls()
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("split enrollment and authentication are not enabled"));
    assert!(!fixture.dir.join("request-fixture.json").exists());
}

#[test]
fn ordinary_enroll_control_reaches_preflight_and_open() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let devices = Devices::new(&mut shared.engine, &fixture);
    let preflights = Cell::new(0);
    let result = devices.engine.enroll_profile_observed(
        "request-fixture",
        None,
        1,
        |_| {
            preflights.set(preflights.get() + 1);
            true
        },
        &(),
        &StopAfterOpens(Cell::new(0)),
    );
    assert!(result.is_err(), "fixture backend cannot grant or publish");
    assert_eq!(preflights.get(), 1);
    let calls = fixture.recorder.calls();
    assert!(
        calls.iter().any(|call| matches!(call, Call::Lease { .. })),
        "{calls:?}"
    );
    assert!(
        calls.contains(&Call::OpenRgb(fixture.rgb.clone())),
        "{calls:?}"
    );
    assert!(
        calls.contains(&Call::OpenIr(fixture.ir.clone())),
        "{calls:?}"
    );
    assert!(!fixture.dir.join("request-fixture.json").exists());
}

struct Position;
impl PositionObserver for Position {
    fn next(&self) -> irlume_common::Result<Option<irlume_common::PositionSessionControl>> {
        Ok(Some(irlume_common::PositionSessionControl::Finish))
    }
    fn report(&self, _: irlume_common::PositionReport) -> irlume_common::Result<()> {
        Ok(())
    }
}

#[test]
fn selected_split_direct_entry_matrix_stops_before_camera_and_publication() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    fixture.select_split();
    let devices = Devices::new(&mut shared.engine, &fixture);
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    enrollment.user = "request-fixture".into();
    let bytes = serde_json::to_vec(&enrollment).unwrap();
    std::fs::write(fixture.dir.join("request-fixture.json"), &bytes).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let authz = irlume_core::multi_camera::authz::EnrollmentAuthorization::mint(
        "request-fixture".into(),
        irlume_core::multi_camera::authz::EnrollmentOperation::add_group(
            "fixture".into(),
            &irlume_core::multi_camera::GroupPair::Split(
                irlume_common::split_key::SplitPairKey::parse_canonical(
                    "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5",
                )
                .unwrap(),
            ),
        ),
        now,
        900,
        "request-fixture".into(),
        irlume_core::multi_camera::authz::AuthorizationVia::ElevatedPeer { uid: 0 },
    )
    .unwrap();
    let preflights = Cell::new(0);
    let closed = "split enrollment and authentication are not enabled";
    let mut refusals = Vec::new();
    refusals.push(
        devices
            .engine
            .replace_enrollment_with_ir_preflight_and_diagnostics(
                "request-fixture",
                None,
                1,
                |_| {
                    preflights.set(preflights.get() + 1);
                    true
                },
                &(),
            )
            .unwrap_err()
            .to_string(),
    );
    refusals.push(
        devices
            .engine
            .add_scan_observed(
                "request-fixture",
                "fixture",
                1,
                |_| {
                    preflights.set(preflights.get() + 1);
                    true
                },
                &(),
            )
            .unwrap_err()
            .to_string(),
    );
    refusals.push(
        devices
            .engine
            .add_camera_group_observed(
                "request-fixture",
                None,
                1,
                &authz,
                |_| {
                    preflights.set(preflights.get() + 1);
                    true
                },
                &(),
                &(),
            )
            .unwrap_err()
            .to_string(),
    );
    for policy in [
        irlume_common::config::FaceSensorPolicy::Dual,
        irlume_common::config::FaceSensorPolicy::IrOnlyExperimental,
    ] {
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::CredentialRelease,
        ] {
            refusals.push(
                devices
                    .engine
                    .authenticate_for_in_window_with_policy(
                        "request-fixture",
                        None,
                        purpose,
                        AuthenticationWindow::new(1000),
                        policy,
                        &(),
                    )
                    .unwrap_err()
                    .to_string(),
            );
        }
    }
    refusals.push(
        devices
            .engine
            .identify_with_diagnostics(&())
            .unwrap_err()
            .to_string(),
    );
    refusals.push(
        devices
            .engine
            .identify_within_with_diagnostics("request-fixture", &())
            .unwrap_err()
            .to_string(),
    );
    refusals.push(
        devices
            .engine
            .position_sample(None)
            .unwrap_err()
            .to_string(),
    );
    refusals.push(
        devices
            .engine
            .position_session(None, &Position)
            .unwrap_err()
            .to_string(),
    );
    assert_eq!(refusals.len(), 11);
    for refusal in refusals {
        assert!(refusal.contains(closed), "{refusal}");
    }
    assert_eq!(preflights.get(), 0);
    assert!(
        fixture.recorder.calls().is_empty(),
        "{:?}",
        fixture.recorder.calls()
    );
    assert_eq!(
        std::fs::read(fixture.dir.join("request-fixture.json")).unwrap(),
        bytes
    );
    assert!(
        devices.engine.camera_selection.is_none(),
        "request state must be cleared on refusal"
    );
}

#[test]
fn ordinary_environment_overrides_valid_split_but_not_invalid_selection() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    fixture.select_split();
    std::env::set_var("IRLUME_RGB_DEVICE", &fixture.rgb);
    std::env::set_var("IRLUME_IR_DEVICE", &fixture.ir);
    let devices = Devices::new(&mut shared.engine, &fixture);
    {
        let request = devices
            .engine
            .prepare_camera_request()
            .expect("Current ordinary override");
        assert_eq!(
            request.live_pair(),
            irlume_core::multi_camera::GroupPair::Ordinary {
                rgb: Some("1234:0001:ordinary".into()),
                ir: Some("1234:0001:ordinary".into()),
            }
        );
    }
    std::fs::write(fixture.dir.join("cameras.conf"), "mode=pinned\n").unwrap();
    let error = match devices.engine.prepare_camera_request() {
        Ok(_) => panic!("invalid selection bypassed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("invalid or unreadable"));
    assert!(fixture.recorder.calls().is_empty());
}

#[test]
fn nested_request_keeps_one_observation_and_next_request_revalidates() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let devices = Devices::new(&mut shared.engine, &fixture);
    {
        let mut request = devices.engine.prepare_camera_request().unwrap();
        fixture.select_split();
        let _nested = request
            .prepare_camera_request()
            .expect("same request observation");
    }
    assert!(devices.engine.camera_selection.is_none());
    assert!(
        devices.engine.prepare_camera_request().is_err(),
        "next request must see selected split"
    );
}

#[test]
fn prepared_request_clears_state_on_unwind() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let devices = Devices::new(&mut shared.engine, &fixture);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _request = devices.engine.prepare_camera_request().unwrap();
        panic!("fixture unwind");
    }));
    assert!(result.is_err());
    assert!(devices.engine.camera_selection.is_none());
    assert_eq!(devices.engine.rgb_device(), fixture.rgb);
    fixture.select_split();
    assert!(devices.engine.prepare_camera_request().is_err());
}

#[test]
fn legacy_fixed_policy_refuses_external_override_before_camera() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::with_fixed(false, false);
    fixture.select_split();
    std::env::set_var("IRLUME_RGB_DEVICE", &fixture.rgb);
    std::env::set_var("IRLUME_IR_DEVICE", &fixture.ir);
    std::env::set_var("IRLUME_CAMERA_REQUIRE_FIXED", "1");
    let devices = Devices::new(&mut shared.engine, &fixture);
    let error = match devices.engine.prepare_camera_request() {
        Ok(_) => panic!("legacy fixed gate bypassed by ordinary environment override"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("external and forbidden"));
    assert!(fixture.recorder.calls().is_empty());
}

#[test]
fn device_mutation_inside_prepared_scope_refuses_nested_camera_entry() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let devices = Devices::new(&mut shared.engine, &fixture);
    {
        let mut request = devices.engine.prepare_camera_request().unwrap();
        let authorized = request.live_pair();
        request.set_devices("/dev/changed-rgb", "/dev/changed-ir");
        assert!(
            request.prepare_camera_request().is_err(),
            "changed endpoints reused stale selection"
        );
        assert_ne!(
            request.live_pair(),
            authorized,
            "a changed pair must not retain A's authorization binding"
        );
        let preflights = Cell::new(0);
        let result = request.enroll_profile_observed(
            "request-fixture",
            None,
            1,
            |_| {
                preflights.set(preflights.get() + 1);
                true
            },
            &(),
            &(),
        );
        assert!(result.unwrap_err().to_string().contains("changed during"));
        assert_eq!(preflights.get(), 0);
        assert!(fixture.recorder.calls().is_empty());
    }
    assert_eq!(devices.engine.rgb_device(), fixture.rgb);
    assert_eq!(devices.engine.ir_device(), fixture.ir);
    assert!(devices.engine.camera_selection.is_none());
}

#[test]
fn override_scope_restores_substituted_devices_and_availability() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    fixture.select_split();
    std::env::set_var("IRLUME_RGB_DEVICE", &fixture.rgb);
    std::env::set_var("IRLUME_IR_DEVICE", &fixture.ir);
    let devices = Devices::new(&mut shared.engine, &fixture);
    devices.engine.rgb_dev = "/dev/standing-rgb".into();
    devices.engine.ir_dev = "/dev/standing-ir".into();
    devices.engine.ir_available = true;
    {
        let request = devices.engine.prepare_camera_request().unwrap();
        assert_eq!(request.rgb_device(), fixture.rgb);
        assert_eq!(request.ir_device(), fixture.ir);
        assert!(!request.ir_available(), "no physical fixture node exists");
    }
    assert_eq!(devices.engine.rgb_device(), "/dev/standing-rgb");
    assert_eq!(devices.engine.ir_device(), "/dev/standing-ir");
    assert!(devices.engine.ir_available());
    assert!(devices.engine.camera_selection.is_none());
}

#[test]
fn inventory_replacement_cannot_reuse_prepared_ordinary_binding() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let devices = Devices::new(&mut shared.engine, &fixture);
    let mut request = devices.engine.prepare_camera_request().unwrap();
    let authorized = request.live_pair();
    let _replacement = Guard::install(&[Camera {
        topology: "/devices/fixture/replacement".into(),
        identity: "1234:9999:replacement".into(),
        fixed: true,
        controller: "0000:00:14.0".into(),
        domain: irlume_common::split_key::SplitDomain::Usb2,
        ports: vec![8],
        endpoints: vec![
            Endpoint {
                path: fixture.rgb.clone(),
                formats: vec![*b"YUYV"],
            },
            Endpoint {
                path: fixture.ir.clone(),
                formats: vec![*b"GREY"],
            },
        ],
    }])
    .unwrap();
    assert!(
        request.prepare_camera_request().is_err(),
        "replacement inventory reused prepared A"
    );
    assert_ne!(
        request.live_pair(),
        authorized,
        "old ordinary authority must not survive a replaced publication"
    );
    assert!(fixture.recorder.calls().is_empty());
}

#[test]
fn encrypted_primary_load_failure_precedes_all_camera_work() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let devices = Devices::new(&mut shared.engine, &fixture);
    // Pure synthetic encryption fixture. The private key directory is absent;
    // no hardware key or real enrollment is accessed by this test.
    let enrollment = Enrollment::new("request-fixture");
    let bytes = irlume_core::storage::serialize_enrollment(&enrollment, Some(&[0x42; 32])).unwrap();
    let path = fixture.dir.join("request-fixture.json");
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(
        irlume_core::storage::store_is_encrypted("request-fixture").unwrap(),
        Some(true)
    );
    let result = devices.engine.authenticate_for_in_window_with_policy(
        "request-fixture",
        None,
        AuthenticationPurpose::Verify,
        AuthenticationWindow::new(2000),
        irlume_common::config::FaceSensorPolicy::Dual,
        &(),
    );
    assert!(
        result.is_err(),
        "unavailable protected enrollment must not grant"
    );
    assert!(
        fixture.recorder.calls().is_empty(),
        "camera reached before protected load resolved: {:?}",
        fixture.recorder.calls()
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(!devices.engine.request_key().holds_key());
}

#[test]
fn stored_split_primary_refuses_before_ordinary_camera_acquisition() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let devices = Devices::new(&mut shared.engine, &fixture);
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    enrollment.user = "request-fixture".into();
    enrollment.camera_binding = Some(CameraBinding::Split(
        irlume_common::split_key::SplitPairKey::parse_canonical(
            "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5",
        )
        .unwrap(),
    ));
    let bytes = serde_json::to_vec(&enrollment).unwrap();
    std::fs::write(fixture.dir.join("request-fixture.json"), &bytes).unwrap();
    let outcome = devices
        .engine
        .authenticate_for_in_window_with_policy(
            "request-fixture",
            None,
            AuthenticationPurpose::Verify,
            AuthenticationWindow::new(2000),
            irlume_common::config::FaceSensorPolicy::Dual,
            &(),
        )
        .unwrap();
    assert!(
        !outcome.granted
            && outcome
                .reason
                .contains("split enrollment and authentication are not enabled")
    );
    assert!(fixture.recorder.calls().is_empty());
    assert_eq!(
        std::fs::read(fixture.dir.join("request-fixture.json")).unwrap(),
        bytes
    );
}

#[test]
fn inventory_drift_during_primary_load_refuses_before_camera() {
    use irlume_common::diagnostics::{DiagnosticSink, TraceEventKind, TraceStage};
    thread_local! {
        static LOAD_REPLACEMENT: std::cell::RefCell<Option<Guard>> = const { std::cell::RefCell::new(None) };
    }
    struct ClearReplacement;
    impl Drop for ClearReplacement {
        fn drop(&mut self) {
            LOAD_REPLACEMENT.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    struct ReplaceOnLoad {
        cameras: Vec<Camera>,
    }
    impl DiagnosticSink for ReplaceOnLoad {
        fn emit_trace(&self, event: TraceEventKind) {
            if matches!(
                event,
                TraceEventKind::StageTiming {
                    stage: TraceStage::EnrollmentLoad,
                    ..
                }
            ) {
                LOAD_REPLACEMENT
                    .with(|slot| *slot.borrow_mut() = Some(Guard::install(&self.cameras).unwrap()));
            }
        }
    }
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let devices = Devices::new(&mut shared.engine, &fixture);
    let _clear = ClearReplacement;
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    enrollment.user = "request-fixture".into();
    enrollment.camera_binding = None;
    std::fs::write(
        fixture.dir.join("request-fixture.json"),
        serde_json::to_vec(&enrollment).unwrap(),
    )
    .unwrap();
    let sink = ReplaceOnLoad {
        cameras: vec![Camera {
            topology: "/devices/fixture/load-replacement".into(),
            identity: "1234:9999:load-replacement".into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![8],
            endpoints: vec![
                Endpoint {
                    path: fixture.rgb.clone(),
                    formats: vec![*b"YUYV"],
                },
                Endpoint {
                    path: fixture.ir.clone(),
                    formats: vec![*b"GREY"],
                },
            ],
        }],
    };
    let error = devices
        .engine
        .authenticate_for_in_window_with_policy(
            "request-fixture",
            None,
            AuthenticationPurpose::Verify,
            AuthenticationWindow::new(2000),
            irlume_common::config::FaceSensorPolicy::Dual,
            &sink,
        )
        .unwrap_err();
    assert!(error.to_string().contains("no longer Current"), "{error}");
    LOAD_REPLACEMENT.with(|slot| assert!(slot.borrow().as_ref().unwrap().calls().is_empty()));
    assert!(fixture.recorder.calls().is_empty());
}
