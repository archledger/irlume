// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::validate_split_pair_in_operation;
use crate::*;
use crate::{lease::*, test_support::*};
use std::cell::Cell;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

const RGB: &str = "/dev/split-capture-rgb";
const IR: &str = "/dev/split-capture-ir";

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
    let guard = Guard::install(&[camera(1, RGB, *b"YUYV"), camera(2, IR, *b"GREY")]).unwrap();
    let (snapshot, sides) = camera_inventory_publication();
    let side = |role| {
        let side = sides.iter().find(|side| side.role == role).unwrap();
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
        supervisor_id: snapshot.supervisor_id.unwrap(),
        revision: snapshot.revision,
        rgb: side(Role::Rgb),
        ir: side(Role::Ir),
    };
    (guard, expected)
}

fn acquire(expected: &SplitLeaseRequest) -> CameraOperationSession {
    acquire_split_camera_operation(expected, CameraOperationKind::Diagnostics, Duration::ZERO)
        .unwrap()
}

fn frames(operation: &CameraOperationSession) -> (Frame, Frame, IrCaptureStats) {
    let now = Instant::now();
    (
        bound_uniform_frame(
            operation
                .lease()
                .frame_binding(RGB, contracts::StreamRole::Rgb)
                .unwrap(),
            now,
        ),
        bound_uniform_frame(
            operation
                .lease()
                .frame_binding(IR, contracts::StreamRole::Ir)
                .unwrap(),
            now + Duration::from_millis(1),
        ),
        uniform_ir_stats(),
    )
}

#[test]
fn split_capture_returns_complete_bound_pair_and_stops_rgb_before_ir() {
    let (guard, expected) = fixture();
    let operation = acquire(&expected);
    let (rgb, ir, stats) = frames(&operation);
    let control = CaptureControl::with_progress(no_progress());
    let phase = Cell::new(0);
    let result = crate::split_capture::capture_split_pair_with(
        RGB,
        IR,
        &operation,
        &control,
        || {
            operation.lease().start_stream().unwrap();
            phase.set(1);
            operation.lease().stop_stream();
            Ok(rgb)
        },
        || {
            assert_eq!(phase.get(), 1);
            operation.lease().start_stream().unwrap();
            phase.set(2);
            operation.lease().stop_stream();
            Ok((ir, stats))
        },
    )
    .unwrap();
    assert_eq!(phase.get(), 2);
    assert_ne!(
        result.rgb().provenance().binding().camera_instance_id(),
        result.ir().provenance().binding().camera_instance_id()
    );
    assert_eq!(operation.state(), CameraSessionState::Stopping);
    drop(result);
    drop(operation);
    assert_eq!(guard.lease_counts_observer()(), (0, 0));
    assert!(
        acquire_camera_operation(&[RGB], CameraOperationKind::Diagnostics, Duration::ZERO).is_ok()
    );
    assert!(
        acquire_camera_operation(&[IR], CameraOperationKind::Diagnostics, Duration::ZERO).is_ok()
    );
}

#[test]
fn split_capture_rgb_failure_never_opens_ir_or_keeps_evidence() {
    let (guard, expected) = fixture();
    let operation = acquire(&expected);
    let result = crate::split_capture::capture_split_pair_with(
        RGB,
        IR,
        &operation,
        &CaptureControl::with_progress(no_progress()),
        || Err(Error::PrivacyShutter("fixture shutter".into())),
        || panic!("IR must not start after an RGB failure"),
    );
    assert!(matches!(result, Err(Error::PrivacyShutter(_))));
    drop(operation);
    assert_eq!(guard.lease_counts_observer()(), (0, 0));
}

#[test]
fn split_capture_ir_failure_discards_rgb_and_releases_both_reservations() {
    let (guard, expected) = fixture();
    let operation = acquire(&expected);
    let (rgb, _, _) = frames(&operation);
    let result = crate::split_capture::capture_split_pair_with(
        RGB,
        IR,
        &operation,
        &CaptureControl::with_progress(no_progress()),
        || Ok(rgb),
        || Err(Error::CameraBusy("fixture second open".into())),
    );
    assert!(matches!(result, Err(Error::CameraBusy(_))));
    drop(operation);
    assert_eq!(guard.lease_counts_observer()(), (0, 0));
}

#[test]
fn split_capture_cancellation_between_sides_never_opens_ir() {
    let (guard, expected) = fixture();
    let operation = acquire(&expected);
    let (rgb, _, _) = frames(&operation);
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancelled);
    let control = CaptureControl::new(no_progress(), Arc::new(move || flag.load(Ordering::SeqCst)));
    let result = crate::split_capture::capture_split_pair_with(
        RGB,
        IR,
        &operation,
        &control,
        || {
            cancelled.store(true, Ordering::SeqCst);
            Ok(rgb)
        },
        || panic!("cancelled request must not fire IR"),
    );
    assert!(matches!(result, Err(Error::Preempted(_))));
    drop(operation);
    assert_eq!(guard.lease_counts_observer()(), (0, 0));
}

#[test]
fn split_capture_invalidation_after_rgb_refuses_before_ir() {
    let (guard, expected) = fixture();
    let operation = acquire(&expected);
    let (rgb, _, _) = frames(&operation);
    let result = crate::split_capture::capture_split_pair_with(
        RGB,
        IR,
        &operation,
        &CaptureControl::with_progress(no_progress()),
        || {
            guard.invalidation_observer()();
            Ok(rgb)
        },
        || panic!("invalidated pair must not open IR"),
    );
    assert!(result.is_err());
    drop(operation);
    assert_eq!(guard.lease_counts_observer()(), (0, 0));
}

#[test]
fn split_capture_invalidation_after_ir_discards_both_frames() {
    let (guard, expected) = fixture();
    let operation = acquire(&expected);
    let (rgb, ir, stats) = frames(&operation);
    let result = crate::split_capture::capture_split_pair_with(
        RGB,
        IR,
        &operation,
        &CaptureControl::with_progress(no_progress()),
        || Ok(rgb),
        || {
            guard.invalidation_observer()();
            Ok((ir, stats))
        },
    );
    assert!(result.is_err());
    drop(operation);
    assert_eq!(guard.lease_counts_observer()(), (0, 0));
}

#[test]
fn split_capture_rejects_wrong_role_paths_before_any_capture() {
    let (_guard, expected) = fixture();
    let operation = acquire(&expected);
    assert!(crate::split_capture::capture_split_pair_with(
        IR,
        RGB,
        &operation,
        &CaptureControl::with_progress(no_progress()),
        || panic!("wrong-role RGB must not open"),
        || panic!("wrong-role IR must not open"),
    )
    .is_err());
}

#[test]
fn split_capture_rejects_foreign_frame_binding() {
    let (_guard, expected) = fixture();
    let operation = acquire(&expected);
    let (_, ir, _) = frames(&operation);
    let rgb = bound_uniform_frame(
        frame_provenance::FrameBinding::new(
            contracts::CameraInstanceId::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            contracts::CameraGeneration::INITIAL,
            contracts::StreamRole::Rgb,
        ),
        Instant::now(),
    );
    assert!(validate_split_pair_in_operation(RGB, IR, &operation, &rgb, &ir).is_err());
}

#[test]
fn split_capture_rejects_evidence_from_a_prior_operation_on_the_same_incarnations() {
    let (guard, expected) = fixture();
    let original = acquire(&expected);
    let (rgb, ir, stats) = frames(&original);
    let capture = super::capture_split_pair_with(
        RGB,
        IR,
        &original,
        &CaptureControl::with_progress(no_progress()),
        || Ok(rgb),
        || Ok((ir, stats)),
    )
    .unwrap();
    drop(original);
    // A retained receipt cannot lend its frames to a later same-incarnation
    // operation: it retains the reservation and its original session expired.
    assert!(matches!(
        acquire_split_camera_operation(&expected, CameraOperationKind::Diagnostics, Duration::ZERO),
        Err(CameraLeaseError::DeadlineExpired { .. })
    ));
    assert!(capture.operation.validate().is_err());
    drop(capture);
    assert_eq!(guard.lease_counts_observer()(), (0, 0));
    drop(acquire(&expected));
}

#[test]
fn split_capture_rejects_unhealthy_delivery_or_unknown_ir_illumination() {
    let (_guard, expected) = fixture();
    let operation = acquire(&expected);
    for (role, illumination, floor, discontinuous) in [
        (
            contracts::StreamRole::Rgb,
            contracts::IlluminationProvenance::Unknown,
            false,
            false,
        ),
        (
            contracts::StreamRole::Rgb,
            contracts::IlluminationProvenance::Unknown,
            true,
            true,
        ),
        (
            contracts::StreamRole::Ir,
            contracts::IlluminationProvenance::Unknown,
            true,
            false,
        ),
        (
            contracts::StreamRole::Ir,
            contracts::IlluminationProvenance::ActiveIr,
            false,
            false,
        ),
        (
            contracts::StreamRole::Ir,
            contracts::IlluminationProvenance::ActiveIr,
            true,
            true,
        ),
    ] {
        let (mut rgb, mut ir, _) = frames(&operation);
        let endpoint = if role == contracts::StreamRole::Rgb {
            RGB
        } else {
            IR
        };
        let at = if role == contracts::StreamRole::Rgb {
            rgb.captured.start
        } else {
            ir.captured.start
        };
        let frame = bound_uniform_frame_with(
            operation.lease().frame_binding(endpoint, role).unwrap(),
            at,
            illumination,
            floor,
            discontinuous,
        );
        if role == contracts::StreamRole::Rgb {
            rgb = frame;
        } else {
            ir = frame;
        }
        assert!(validate_split_pair_in_operation(RGB, IR, &operation, &rgb, &ir).is_err());
    }
}

#[test]
fn split_capture_rejects_mutated_geometry_role_or_window() {
    let (_guard, expected) = fixture();
    let operation = acquire(&expected);
    for fault in ["geometry", "spectrum", "window"] {
        let (mut rgb, ir, _) = frames(&operation);
        match fault {
            "geometry" => rgb.width += 1,
            "spectrum" => rgb.spectrum = Spectrum::Ir,
            "window" => rgb.captured = CaptureWindow::at(Instant::now() + Duration::from_secs(1)),
            _ => unreachable!(),
        }
        assert!(
            validate_split_pair_in_operation(RGB, IR, &operation, &rgb, &ir).is_err(),
            "{fault}"
        );
    }
}

#[test]
fn split_capture_deadline_refuses_before_any_capture() {
    let (guard, expected) = fixture();
    let operation = acquire(&expected);
    let control = CaptureControl::with_progress(no_progress()).with_deadline(Some(Instant::now()));
    assert!(matches!(
        crate::split_capture::capture_split_pair_with(
            RGB,
            IR,
            &operation,
            &control,
            || panic!("expired request must not open RGB"),
            || panic!("expired request must not open IR"),
        ),
        Err(Error::DeadlineExpired)
    ));
    drop(operation);
    assert_eq!(guard.lease_counts_observer()(), (0, 0));
}

#[test]
fn split_capture_public_path_reuses_backend_under_the_original_reservation() {
    let (guard, expected) = fixture();
    let operation = acquire(&expected);
    assert!(capture_split_pair_with_control(
        RGB,
        IR,
        &operation,
        &CaptureControl::with_progress(no_progress())
    )
    .is_err());
    assert_eq!(
        guard.calls(),
        vec![
            Call::Lease {
                endpoints: vec![RGB.into(), IR.into()],
                kind: CameraOperationKind::Diagnostics
            },
            Call::OpenRgb(RGB.into()),
        ]
    );
    drop(operation);
    assert_eq!(guard.lease_counts_observer()(), (0, 0));
}

#[test]
fn split_native_open_refuses_a_foreign_fd_before_format_negotiation() {
    use std::os::unix::fs::symlink;
    let _env = crate::testenv::ENV_LOCK.lock().unwrap();
    let _virtual = crate::testenv::EnvGuard::set("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA", "/dev/null");
    let _roots = crate::hostfs::test::fixture_with(|dev, sys| {
        symlink("/dev/null", dev.join("null")).unwrap();
        let usb = sys.join("devices/pci0000:00/0000:00:14.0/usb2/2-9");
        let iface = usb.join("2-9:1.0");
        std::fs::create_dir_all(&iface).unwrap();
        std::fs::create_dir_all(sys.join("dev/char")).unwrap();
        symlink(&iface, sys.join("dev/char/1:3")).unwrap();
        std::fs::write(usb.join("idVendor"), "1234\n").unwrap();
        std::fs::write(usb.join("idProduct"), "0009\n").unwrap();
        std::fs::write(usb.join("bConfigurationValue"), "1\n").unwrap();
        std::fs::write(iface.join("bInterfaceNumber"), "00\n").unwrap();
        let raw = [
            18, 1, 0, 2, 0, 0, 0, 64, 0x34, 0x12, 9, 0, 0, 1, 0, 0, 0, 1, 9, 2, 18, 0, 1, 1, 0,
            0x80, 50, 9, 4, 0, 0, 0, 14, 1, 0, 0,
        ];
        std::fs::write(usb.join("descriptors"), raw).unwrap();
    });
    let camera = |port, path: &str, format| Camera {
        topology: format!("/devices/selected-native/{port}"),
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
    let _guard =
        Guard::install(&[camera(1, "/dev/null", *b"YUYV"), camera(2, IR, *b"GREY")]).unwrap();
    let (snapshot, sides) = camera_inventory_publication();
    let side = |role| {
        let e = sides.iter().find(|e| e.role == role).unwrap();
        SplitSideExpectation {
            instance_id: e.instance_id.clone(),
            generation: e.generation,
            endpoint: e.endpoint.clone(),
            identity: e.identity.clone(),
            controller: e.controller.clone(),
            domain: e.domain.clone(),
            ports: e.ports.clone(),
        }
    };
    let expected = SplitLeaseRequest {
        supervisor_id: snapshot.supervisor_id.unwrap(),
        revision: snapshot.revision,
        rgb: side(Role::Rgb),
        ir: side(Role::Ir),
    };
    let operation = acquire(&expected);
    // The real fd collector resolves the foreign identity while the retained
    // inventory still names the selected one. No hardware camera is opened.
    let dev = crate::hostfs::open_video("/dev/null").unwrap();
    let identity = crate::uvc_descriptor::identity_from_fd(dev.handle().fd()).unwrap();
    assert_eq!(identity.pid, 9);
    drop(dev);
    let result = operation
        .run(|| crate::RgbCamera::open_uvc("/dev/null", operation.lease().clone()))
        .unwrap();
    let error = result.err().expect("foreign descriptor must refuse");
    assert!(
        error
            .to_string()
            .contains("opened descriptor differs from selected camera"),
        "must refuse at fd admission, before the foreign fd's format ioctls: {error}"
    );
}

#[test]
fn split_rgb_restore_admission_survives_peer_loss_without_reopening_capture() {
    use std::os::unix::fs::symlink;
    let roots = crate::hostfs::test::fixture_with(|_, sys| {
        let hub = sys.join("devices/pci0000:00/0000:00:14.0/usb2");
        let usb = hub.join("2-1");
        let iface = usb.join("2-1:1.0");
        std::fs::create_dir_all(&iface).unwrap();
        std::fs::create_dir_all(sys.join("dev/char")).unwrap();
        symlink(&iface, sys.join("dev/char/1:3")).unwrap();
        std::fs::write(hub.join("idProduct"), "0002\n").unwrap();
        std::fs::write(usb.join("idVendor"), "1234\n").unwrap();
        std::fs::write(usb.join("idProduct"), "0001\n").unwrap();
        std::fs::write(usb.join("bConfigurationValue"), "1\n").unwrap();
        std::fs::write(iface.join("bInterfaceNumber"), "00\n").unwrap();
        std::fs::write(
            usb.join("descriptors"),
            [
                18, 1, 0, 2, 0, 0, 0, 64, 0x34, 0x12, 1, 0, 0, 1, 0, 0, 0, 1, 9, 2, 18, 0, 1, 1, 0,
                0x80, 50, 9, 4, 0, 0, 0, 14, 1, 0, 0,
            ],
        )
        .unwrap();
    });
    let camera = |port, path: &str, format| Camera {
        topology: format!("/devices/pci0000:00/0000:00:14.0/usb2/2-{port}"),
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
    let guard =
        Guard::install(&[camera(1, "/dev/null", *b"YUYV"), camera(2, IR, *b"GREY")]).unwrap();
    let (snapshot, sides) = camera_inventory_publication();
    let side = |role| {
        let e = sides.iter().find(|e| e.role == role).unwrap();
        SplitSideExpectation {
            instance_id: e.instance_id.clone(),
            generation: e.generation,
            endpoint: e.endpoint.clone(),
            identity: e.identity.clone(),
            controller: e.controller.clone(),
            domain: e.domain.clone(),
            ports: e.ports.clone(),
        }
    };
    let expected = SplitLeaseRequest {
        supervisor_id: snapshot.supervisor_id.unwrap(),
        revision: snapshot.revision,
        rgb: side(Role::Rgb),
        ir: side(Role::Ir),
    };
    let operation = acquire(&expected);
    let dev = v4l::Device::with_path("/dev/null").unwrap();
    let current = Cell::new(0_i64);
    let reads = Cell::new(0);
    let writes = std::cell::RefCell::new(Vec::new());
    let restore = crate::apply_blc_with(
        operation.lease(),
        "/dev/null",
        dev.handle().fd(),
        || {
            reads.set(reads.get() + 1);
            if reads.get() == 2 {
                guard.endpoint_invalidation_observer(IR)();
            }
            Ok(v4l::control::Control {
                id: crate::V4L2_CID_BACKLIGHT_COMPENSATION,
                value: v4l::control::Value::Integer(current.get()),
            })
        },
        |value| {
            writes.borrow_mut().push(value);
            current.set(if value == crate::BLC_WANTED { 1 } else { value });
            Ok(())
        },
    );
    assert!(
        restore.is_none(),
        "clamped control must not arm a restore guard"
    );
    assert_eq!(
        *writes.borrow(),
        vec![2, 0],
        "failed confirmation must undo the owned write after peer-only loss"
    );
    assert_eq!(current.get(), 0);
    assert!(operation.lease().validate().is_err());
    assert!(
        operation
            .lease()
            .require_restore_fd("/dev/null", dev.handle().fd())
            .is_ok(),
        "BLC restore's original RGB fd is still valid"
    );
    assert!(operation.lease().require_endpoint("/dev/null").is_err());
    assert!(
        operation.lease().start_stream().is_err(),
        "cleanup must not reactivate capture"
    );
    let product = roots
        .sys()
        .join("devices/pci0000:00/0000:00:14.0/usb2/2-1/idProduct");
    std::fs::write(&product, "0009\n").unwrap();
    assert!(
        operation
            .lease()
            .require_restore_fd("/dev/null", dev.handle().fd())
            .is_err(),
        "changed fd cannot restore"
    );
    std::fs::write(&product, "0001\n").unwrap();
    guard.endpoint_invalidation_observer("/dev/null")();
    assert!(
        operation
            .lease()
            .require_restore_fd("/dev/null", dev.handle().fd())
            .is_err(),
        "lost own incarnation cannot restore"
    );
}
