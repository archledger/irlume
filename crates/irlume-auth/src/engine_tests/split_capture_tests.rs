// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use irlume_camera::{lease::*, test_support::*};
use std::time::{Duration, Instant};

fn fixture() -> (Guard, SplitLeaseRequest) {
    let camera = |port, path: &str, format| Camera {
        topology: format!("/devices/split-capture/{port}"),
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
    let guard = Guard::install(&[camera(1, NO_RGB, *b"YUYV"), camera(2, NO_IR, *b"GREY")]).unwrap();
    let (snapshot, sides) = irlume_camera::camera_inventory_publication();
    let side = |role| {
        let side = sides.iter().find(|side| side.role == role).unwrap();
        irlume_camera::SplitSideExpectation {
            instance_id: side.instance_id.clone(),
            generation: side.generation,
            endpoint: side.endpoint.clone(),
            identity: side.identity.clone(),
            controller: side.controller.clone(),
            domain: side.domain.clone(),
            ports: side.ports.clone(),
        }
    };
    let request = SplitLeaseRequest {
        supervisor_id: snapshot.supervisor_id.unwrap(),
        revision: snapshot.revision,
        rgb: side(irlume_camera::Role::Rgb),
        ir: side(irlume_camera::Role::Ir),
    };
    (guard, request)
}

#[test]
fn split_capture_assessment_preserves_real_lease_provenance_at_short_skew() {
    let _env = env_guard();
    let mut shared = shared();
    let engine = &mut shared.engine;
    let (_guard, request) = fixture();
    let operation =
        acquire_split_camera_operation(&request, CameraOperationKind::Diagnostics, Duration::ZERO)
            .unwrap();
    let capture = capture_uniform_split_pair(&operation, NO_RGB, NO_IR).unwrap();
    assert!(capture.rgb().captured.gap_to(capture.ir().captured) < MAX_CROSS_SPECTRUM_SKEW);
    let face = Detection {
        bbox: [4.0, 4.0, 28.0, 28.0],
        score: 0.99,
        landmarks: [
            (10.0, 10.0),
            (22.0, 10.0),
            (16.0, 16.0),
            (11.0, 22.0),
            (21.0, 22.0),
        ],
    };
    let evidence = engine
        .assess_captured_pair(
            PairCapture::Split(capture),
            (vec![face.clone()], Some(face)),
            PairAssessmentContext {
                operation: &operation,
                sequential: true,
                pair_sequential_retried: false,
                rgb_hard_retried: false,
                held_sessions: false,
                ir_ms: None,
                diagnostics: &(),
            },
        )
        .map_err(CapturePathError::into_inner)
        .unwrap();
    assert!(
        evidence.assessment.split_pair,
        "actual two-incarnation provenance must reach the assessment"
    );
    assert!(
        evidence.assessment.sequential_pair,
        "a paired split capture remains sequential below the ordinary skew ceiling"
    );
    assert!(!rgb_primary_grant_admissible(
        0.9,
        0.6,
        evidence.assessment.sequential_posture()
    ));
}

#[test]
fn split_capture_attempt_ignores_an_ordinary_concurrent_override_and_does_not_retry_a_side() {
    let _env = env_guard();
    let mut shared = shared();
    let engine = &mut shared.engine;
    let (guard, request) = fixture();
    let operation =
        acquire_split_camera_operation(&request, CameraOperationKind::Diagnostics, Duration::ZERO)
            .unwrap();
    let mut selection = unavailable_capture_mode_selection();
    selection.sequential = false;
    assert!(engine
        .assess_full_with_finish(None, Some(&selection), &operation, &(), |_, _| panic!(
            "failed split capture must never materialize partial identity"
        ),)
        .map(|_: ()| ())
        .is_err());
    assert_eq!(
        guard.calls(),
        vec![
            Call::Lease {
                endpoints: vec![NO_RGB.into(), NO_IR.into()],
                kind: CameraOperationKind::Diagnostics
            },
            Call::OpenRgb(NO_RGB.into()),
        ],
        "split must neither open IR concurrently nor retry only RGB"
    );
}

#[test]
fn split_capture_assessor_rejects_stale_pair_before_inference() {
    let _env = env_guard();
    let mut shared = shared();
    let engine = &mut shared.engine;
    let (guard, request) = fixture();
    let operation =
        acquire_split_camera_operation(&request, CameraOperationKind::Diagnostics, Duration::ZERO)
            .unwrap();
    let capture = capture_uniform_split_pair(&operation, NO_RGB, NO_IR).unwrap();
    guard.invalidation_observer()();
    assert!(engine
        .assess_captured_pair(
            PairCapture::Split(capture),
            (vec![], None),
            PairAssessmentContext {
                operation: &operation,
                sequential: false,
                pair_sequential_retried: false,
                rgb_hard_retried: false,
                held_sessions: false,
                ir_ms: None,
                diagnostics: &(),
            },
        )
        .is_err());
    drop(operation);
    assert_eq!(guard.lease_counts_observer()(), (0, 0));
}

#[test]
fn split_capture_assessor_refuses_separated_frames_without_their_receipt() {
    let _env = env_guard();
    let mut shared = shared();
    let (_guard, request) = fixture();
    let operation =
        acquire_split_camera_operation(&request, CameraOperationKind::Diagnostics, Duration::ZERO)
            .unwrap();
    let captured = capture_uniform_split_pair(&operation, NO_RGB, NO_IR).unwrap();
    let (rgb, ir, stats) = captured.into_parts(&operation).unwrap();
    assert!(shared
        .engine
        .assess_captured_pair(
            PairCapture::Ordinary(rgb, ir, stats),
            (vec![], None),
            PairAssessmentContext {
                operation: &operation,
                sequential: true,
                pair_sequential_retried: false,
                rgb_hard_retried: false,
                held_sessions: false,
                ir_ms: None,
                diagnostics: &()
            }
        )
        .is_err());
}

#[test]
fn split_capture_diagnostic_entry_refuses_an_ordinary_operation_without_opens() {
    let _env = env_guard();
    let mut shared = shared();
    let (guard, _) = fixture();
    let operation =
        acquire_camera_operation(&[NO_RGB], CameraOperationKind::Diagnostics, Duration::ZERO)
            .unwrap();
    assert!(shared
        .engine
        .assess_split_in_operation(&operation, &())
        .is_err());
    assert_eq!(
        guard.calls(),
        vec![Call::Lease {
            endpoints: vec![NO_RGB.into()],
            kind: CameraOperationKind::Diagnostics,
        }]
    );
}

#[test]
fn split_capture_diagnostic_entry_keeps_the_forced_ir_off_refusal() {
    let _env = env_guard();
    let mut shared = shared();
    let (guard, request) = fixture();
    let operation =
        acquire_split_camera_operation(&request, CameraOperationKind::Diagnostics, Duration::ZERO)
            .unwrap();
    let previous = shared.engine.ir_available;
    shared.engine.ir_available = false;
    let result = shared.engine.assess_split_in_operation(&operation, &());
    shared.engine.ir_available = previous;
    assert!(result.is_err());
    assert_eq!(
        guard.calls(),
        vec![Call::Lease {
            endpoints: vec![NO_RGB.into(), NO_IR.into()],
            kind: CameraOperationKind::Diagnostics,
        }]
    );
}

#[test]
fn split_capture_refused_diagnostic_preserves_pending_engine_state() {
    let _env = env_guard();
    let mut shared = shared();
    let engine = &mut shared.engine;
    for fault in ["stale", "endpoint", "pending"] {
        let (guard, request) = fixture();
        let operation = acquire_split_camera_operation(
            &request,
            CameraOperationKind::Diagnostics,
            Duration::ZERO,
        )
        .unwrap();
        let previous_ir = engine.ir_available;
        let previous_rgb = engine.rgb_dev.clone();
        let previous_votes = std::mem::replace(&mut engine.vit_scores, vec![0.1, 0.2]);
        let stamp = Instant::now();
        let previous_setup = engine.capture_setup_started.replace(stamp);
        engine.ir_available = true;
        if fault == "stale" {
            guard.invalidation_observer()();
        } else if fault == "endpoint" {
            engine.rgb_dev = "/dev/foreign-diagnostic".into();
        }
        let result = engine.assess_split_in_operation(&operation, &());
        let votes = std::mem::replace(&mut engine.vit_scores, previous_votes);
        let setup = std::mem::replace(&mut engine.capture_setup_started, previous_setup);
        engine.ir_available = previous_ir;
        engine.rgb_dev = previous_rgb;
        assert!(result.is_err());
        assert_eq!(
            votes,
            vec![0.1, 0.2],
            "refused {fault} diagnostic must not erase pending PAD votes"
        );
        assert_eq!(
            setup,
            Some(stamp),
            "refused {fault} diagnostic must not consume pending setup accounting"
        );
    }
}

#[test]
fn split_capture_diagnostic_state_does_not_survive_error_or_unwind() {
    let _env = env_guard();
    let mut shared = shared();
    let engine = &mut shared.engine;
    let (_guard, request) = fixture();
    let operation =
        acquire_split_camera_operation(&request, CameraOperationKind::Diagnostics, Duration::ZERO)
            .unwrap();
    let previous_ir = engine.ir_available;
    let previous_votes = std::mem::take(&mut engine.vit_scores);
    let previous_setup = engine.capture_setup_started.take();
    let previous_selection = engine.camera_selection.take();
    let previous_primary = engine.primary_attempt.take();
    let previous_secondary = engine.secondary_attempt.take();
    let previous_cancel = engine.request_cancelled.take();
    let previous_deadline = engine.authentication_deadline.take();
    engine.ir_available = true;
    let result = engine.with_split_diagnostic_state(&operation, &(), |engine| {
        engine.vit_scores.push(0.1);
        engine.capture_setup_started = Some(Instant::now());
        Err::<(), _>(irlume_common::Error::Hardware(
            "synthetic model error".into(),
        ))
    });
    let error_state_clean = engine.vit_scores.is_empty() && engine.capture_setup_started.is_none();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: irlume_common::Result<()> =
            engine.with_split_diagnostic_state(&operation, &(), |engine| {
                engine.vit_scores.push(0.2);
                engine.capture_setup_started = Some(Instant::now());
                panic!("synthetic model panic")
            });
    }));
    let panic_state_clean = engine.vit_scores.is_empty() && engine.capture_setup_started.is_none();
    engine.ir_available = previous_ir;
    engine.vit_scores = previous_votes;
    engine.capture_setup_started = previous_setup;
    engine.camera_selection = previous_selection;
    engine.primary_attempt = previous_primary;
    engine.secondary_attempt = previous_secondary;
    engine.request_cancelled = previous_cancel;
    engine.authentication_deadline = previous_deadline;
    assert!(result.is_err());
    assert!(error_state_clean);
    assert!(panic.is_err());
    assert!(panic_state_clean);
}
