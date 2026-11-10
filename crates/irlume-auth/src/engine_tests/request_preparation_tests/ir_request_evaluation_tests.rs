// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use crate::ir_assessment::{assess_stages, AssessmentStages, IrFailure};
use crate::ir_request_evaluation::Phase;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

const USER: &str = "ir-request-synthetic";
const ID: &str = "1234:0001:ordinary";

#[derive(Clone, Copy, Debug)]
enum Case {
    Best,
    Centroid,
    Both,
    Neither,
    Retry,
    Pad,
    CancelCapture,
    CancelPad,
    CancelIdentity,
    Revoke,
    Journal,
}

struct Stages {
    case: Case,
    round: usize,
    cancel: Arc<AtomicBool>,
    primary: PathBuf,
    journal: PathBuf,
}
impl AssessmentStages for Stages {
    type Captured = ();
    type Detected = ();
    type Aligned = ();
    type Embedded = ();
    fn preflight(&mut self) -> Result<(), IrFailure> {
        Ok(())
    }
    fn capture(
        &mut self,
        _: &irlume_camera::CaptureControl,
        _: Option<std::time::Instant>,
    ) -> Result<(), IrFailure> {
        if matches!(self.case, Case::CancelCapture) {
            self.cancel.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
    fn detect(&mut self, _: ()) -> Result<(), IrFailure> {
        if matches!(self.case, Case::Retry) && self.round == 0 {
            Err(IrFailure::NoFace)
        } else {
            Ok(())
        }
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
        if matches!(self.case, Case::CancelPad) {
            self.cancel.store(true, Ordering::SeqCst);
        }
        if matches!(self.case, Case::Pad) {
            Err(IrFailure::PadUnavailable)
        } else {
            Ok(PadEvidence::Score(0.1))
        }
    }
    fn align(&mut self, _: ()) -> Result<(), IrFailure> {
        Ok(())
    }
    fn embed(&mut self, _: ()) -> Result<(), IrFailure> {
        Ok(())
    }
    fn adapt(&mut self, _: ()) -> Result<Vec<f32>, IrFailure> {
        Ok(vec![0.0; EMBED_DIM])
    }
    fn identify(&mut self, _: &[f32]) -> IrMatch {
        if matches!(self.case, Case::CancelIdentity) {
            self.cancel.store(true, Ordering::SeqCst);
        }
        if matches!(self.case, Case::Revoke) {
            std::fs::remove_file(&self.primary).unwrap();
        }
        if matches!(self.case, Case::Journal) {
            std::fs::write(&self.journal, b"late intent").unwrap();
        }
        IrMatch {
            best: if matches!(self.case, Case::Centroid | Case::Neither) {
                0.0
            } else {
                1.0
            },
            best_who: "private synthetic label".into(),
            n_templates: 1,
            centroid: matches!(self.case, Case::Centroid | Case::Both)
                .then(|| (1.0, "private centroid".into())),
        }
    }
}

fn install_script(engine: &mut Engine, root: &std::path::Path, case: Case) -> Arc<AtomicUsize> {
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    engine.request_cancelled = Some(Arc::new(move || signal.load(Ordering::SeqCst)));
    let primary = root.join(format!("{USER}.json"));
    let journal = root.join("template-keys").join(format!("{USER}.replacing"));
    engine.ir_request_assessor = Some(Box::new(move |control, deadline| {
        let round = seen.fetch_add(1, Ordering::SeqCst);
        assert!(round < 3, "unexpected retry after a terminal assessment");
        assess_stages(
            &mut Stages {
                case,
                round,
                cancel: cancel.clone(),
                primary: primary.clone(),
                journal: journal.clone(),
            },
            control,
            deadline,
        )
    }));
    count
}

fn plant(engine: &Engine, root: &std::path::Path, secondary: bool) {
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    enrollment.user = USER.into();
    enrollment.uid = Some(12000);
    enrollment.camera_binding = Some(CameraBinding::Ordinary {
        rgb: Some(if secondary { "1234:0002:primary" } else { ID }.into()),
        ir: Some(if secondary { "1234:0002:primary" } else { ID }.into()),
    });
    for scan in &mut enrollment.profiles[0].scans {
        scan.ir = Some(vec![0.0; engine.ir_dim()]);
        scan.ir_space = Some(engine.ir_space().into());
        scan.embed_space = Some(engine.embed_space().into());
    }
    let bytes = serde_json::to_vec(&enrollment).unwrap();
    std::fs::write(root.join(format!("{USER}.json")), &bytes).unwrap();
    let secondary_path = irlume_core::multi_camera::secondary_store_path(USER);
    if secondary {
        use irlume_core::multi_camera::*;
        let store = SecondaryStore {
            format_version: SECONDARY_STORE_VERSION,
            owner: USER.into(),
            generation: 1,
            primary_snapshot_sha256: irlume_common::sha256_hex(&bytes),
            groups: vec![SecondaryGroup {
                id: CameraGroupId::new("synthetic-group".into()).unwrap(),
                pair: GroupPair::Ordinary {
                    rgb: Some(ID.into()),
                    ir: Some(ID.into()),
                },
                profiles: vec![SecondaryProfileScans {
                    profile: enrollment.profiles[0].name.clone(),
                    scans: enrollment.profiles[0].scans.clone(),
                    ir_calibs: Default::default(),
                }],
            }],
        };
        std::fs::create_dir_all(secondary_path.parent().unwrap()).unwrap();
        std::fs::write(secondary_path, serde_json::to_vec(&store).unwrap()).unwrap();
    } else {
        let _ = std::fs::remove_file(secondary_path);
    }
    let _ = std::fs::remove_file(root.join("template-keys").join(format!("{USER}.replacing")));
    // Seed only the synthetic account lock through the existing production loader.
    assert!(storage::load_snapshot(USER).unwrap().is_some());
}

fn child(root: &std::path::Path) {
    let _env = env_guard();
    let mut shared = shared();
    let _account = irlume_core::account::remember(USER, 12000);
    let _tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
    for (key, value) in [
        ("IRLUME_CONFIG_DIR", root.to_str().unwrap()),
        ("IRLUME_STATE_DIR", root.to_str().unwrap()),
        ("IRLUME_GRACE_MS", "5000"),
        ("IRLUME_TCTI", "device:/nonexistent/irlume-test-tpm"),
    ] {
        std::env::set_var(key, value);
    }
    std::env::set_var("IRLUME_METHOD_CONF", root.join("method"));
    std::env::remove_var("IRLUME_FORCE_NO_IR");
    std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
    std::env::remove_var("IRLUME_RGB_DEVICE");
    std::env::remove_var("IRLUME_IR_DEVICE");
    std::fs::write(
        root.join("settings.conf"),
        "face_sensor_policy=ir-only-experimental\n",
    )
    .unwrap();
    std::fs::write(
        root.join("cameras.conf"),
        format!("mode=pinned\nrgb=/dev/video0\nir=/dev/video2\nrgb_id={ID}\nir_id={ID}\n"),
    )
    .unwrap();
    let recorder = Guard::install(&[Camera {
        topology: "/devices/fixture".into(),
        identity: ID.into(),
        fixed: true,
        controller: "0000:00:14.0".into(),
        domain: irlume_common::split_key::SplitDomain::Usb2,
        ports: vec![8],
        endpoints: vec![
            Endpoint {
                path: "/dev/video0".into(),
                formats: vec![*b"YUYV"],
            },
            Endpoint {
                path: "/dev/video2".into(),
                formats: vec![*b"GREY"],
            },
        ],
    }])
    .unwrap();
    let engine = &mut shared.engine;
    engine.set_devices("/dev/video0", "/dev/video2");
    engine.pad_ir = Some(irlume_vision::PadIr::load_from_file(&model_path("flir.onnx")).unwrap());
    plant(engine, root, false);
    let calls = install_script(engine, root, Case::Both);
    let before_preflight = recorder.calls().len();
    let ready = engine
        .evaluate_ir_request(USER, "kde", Phase::Preflight)
        .to_json();
    assert_eq!(ready["result"]["kind"], "ready", "{ready}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(recorder.calls().len(), before_preflight);
    for service in ["sudo", "sshd", "unknown"] {
        let refused = engine
            .evaluate_ir_request(USER, service, Phase::Evaluation)
            .to_json();
        assert_eq!(refused["result"]["cause"], "invalid_request");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    let pending = root.join("template-keys").join(format!("{USER}.replacing"));
    std::fs::write(&pending, b"pending").unwrap();
    let refused = engine
        .evaluate_ir_request(USER, "kde", Phase::Evaluation)
        .to_json();
    assert_eq!(
        refused["result"]["cause"], "state_requires_repair",
        "{refused}"
    );
    assert_eq!(std::fs::read(&pending).unwrap(), b"pending");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    std::fs::remove_file(pending).unwrap();
    for secondary in [false, true] {
        for case in [
            Case::Best,
            Case::Centroid,
            Case::Both,
            Case::Neither,
            Case::Retry,
            Case::Pad,
            Case::CancelCapture,
            Case::CancelPad,
            Case::CancelIdentity,
            Case::Revoke,
            Case::Journal,
        ] {
            plant(engine, root, secondary);
            let calls = install_script(engine, root, case);
            let report = engine
                .evaluate_ir_request(USER, "kde", Phase::Evaluation)
                .to_json();
            let success = matches!(case, Case::Best | Case::Centroid | Case::Both | Case::Retry);
            assert_eq!(
                report["result"]["kind"] == "would_grant",
                success,
                "{secondary}/{case:?}: {report}"
            );
            assert_eq!(report["authentication_granted"], false);
            if success {
                assert_eq!(
                    report["result"]["identity_acceptance"],
                    match case {
                        Case::Centroid => "centroid",
                        Case::Both => "both",
                        _ => "best_template",
                    }
                );
            } else {
                assert!(report["result"].get("identity_acceptance").is_none());
            }
            assert!(!report.to_string().contains("private"));
            assert_eq!(
                calls.load(Ordering::SeqCst),
                if matches!(case, Case::Retry) { 2 } else { 1 },
                "{case:?}: {report}"
            );
            assert_eq!(
                report["counts"]["assessments"],
                calls.load(Ordering::SeqCst)
            );
            assert!(engine.request_evaluation.is_none());
            assert!(!engine.request_key().holds_key());
            assert_eq!(
                report["scope"],
                if secondary { "secondary" } else { "primary" }
            );
            if success || matches!(case, Case::Neither | Case::Pad) {
                plant(engine, root, secondary);
                install_script(engine, root, case);
                let outcome = engine
                    .authenticate_for(USER, Some("kde"), AuthenticationPurpose::Verify)
                    .unwrap();
                assert_eq!(outcome.granted, success, "normal entry disagrees: {case:?}");
            }
        }
    }
    engine.ir_request_assessor = None;
    engine.request_cancelled = None;
    // All captures used synthetic stages. Leases still used the real scoped API.
    assert!(!recorder
        .calls()
        .iter()
        .any(|call| matches!(call, Call::OpenRgb(_) | Call::OpenIr(_))));
}

#[test]
fn request_evaluator_matches_production_and_refuses_late_changes() {
    if let Some(root) = std::env::var_os("IRLUME_REQUEST_EVALUATOR_FIXTURE") {
        child(std::path::Path::new(&root));
        return;
    }
    let root =
        std::env::temp_dir().join(format!("irlume-request-evaluation-{}", std::process::id()));
    std::fs::create_dir_all(root.join("sys/devices/fixture/rgb")).unwrap();
    std::fs::create_dir_all(root.join("sys/devices/fixture/ir")).unwrap();
    for (name, value) in [
        ("idVendor", "1234"),
        ("idProduct", "0001"),
        ("serial", "ordinary"),
    ] {
        std::fs::write(root.join("sys/devices/fixture").join(name), value).unwrap();
    }
    for (node, interface, device) in [("video0", "rgb", "1:3"), ("video2", "ir", "1:5")] {
        let path = root.join("sys/class/video4linux").join(node);
        std::fs::create_dir_all(&path).unwrap();
        std::os::unix::fs::symlink(
            format!("../../../devices/fixture/{interface}"),
            path.join("device"),
        )
        .unwrap();
        std::fs::write(path.join("index"), "0").unwrap();
        std::fs::write(path.join("name"), interface).unwrap();
        std::fs::write(path.join("dev"), device).unwrap();
    }
    let test="engine_tests::request_preparation_tests::ir_request_evaluation_tests::request_evaluator_matches_production_and_refuses_late_changes";
    let output = std::process::Command::new("timeout")
        .args(["90", "/usr/bin/bwrap"])
        .args([
            "--die-with-parent",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--ro-bind",
            "/dev/null",
            "/dev/video0",
            "--ro-bind",
            "/dev/zero",
            "/dev/video2",
        ])
        .arg("--bind")
        .arg(&root)
        .arg(&root)
        .arg("--ro-bind")
        .arg(root.join("sys"))
        .arg("/sys")
        .env("IRLUME_REQUEST_EVALUATOR_FIXTURE", &root)
        .env("TMPDIR", &root)
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("1 passed; 0 failed"),
        "child did not execute: {stdout}"
    );
    std::fs::remove_dir_all(root).unwrap();
}
