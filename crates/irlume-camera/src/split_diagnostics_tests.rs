// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Delivered-rate diagnostics under a held split operation (ADR-0032,
//! selection-aware diagnostics amendment). The per-role measurement runs only
//! inside a split Diagnostics operation, RGB then IR, taking that operation's
//! permit for each open; any other operation measures nothing and opens
//! nothing. The fixture refuses every open, so measured roles read unknown.

use crate::lease::{
    acquire_camera_operation, acquire_split_camera_operation,
    CameraOperationKind::{self, Diagnostics, Preview, Setup},
    SplitLeaseRequest,
};
use crate::test_support::{Call, Camera, Endpoint, Guard};
use crate::{
    camera_inventory_publication, camera_rate_diagnostics_in_split_operation, Role,
    SplitSideExpectation,
};
use std::time::Duration;

const RGB: &str = "/dev/split-diagnostics-rgb";
const IR: &str = "/dev/split-diagnostics-ir";

fn fixture() -> (Guard, SplitLeaseRequest) {
    let camera = |port: u8, path: &str, format: [u8; 4]| Camera {
        topology: format!("/devices/split-diagnostics/{port}"),
        identity: format!("1234:00a{port}"),
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
        .expect("split diagnostics fixture");
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

fn split_lease(kind: CameraOperationKind) -> Call {
    Call::Lease {
        endpoints: vec![RGB.into(), IR.into()],
        kind,
    }
}

fn unmeasured(report: &irlume_common::CameraDiagnosticsReport) -> bool {
    report.rgb.known
        && report.ir.known
        && report.rgb.state == "unknown"
        && report.ir.state == "unknown"
        && report.rgb.evidence.is_none()
        && report.ir.evidence.is_none()
        && report.illumination.is_none()
}

#[test]
fn rate_diagnostics_measure_both_sides_inside_a_split_diagnostics_operation() {
    // Hermetic host roots: the IR side's metadata-node probe reads sysfs.
    let _roots = crate::hostfs::test::empty_fixture();
    let (guard, expected) = fixture();
    let operation =
        acquire_split_camera_operation(&expected, Diagnostics, Duration::ZERO).expect("lease");
    let report = camera_rate_diagnostics_in_split_operation(&operation, RGB, IR);
    assert_eq!(
        guard.calls(),
        vec![
            split_lease(Diagnostics),
            Call::OpenRgb(RGB.into()),
            Call::OpenIr(IR.into()),
        ],
        "both opens take the held operation's permit, RGB then IR"
    );
    assert!(report.rgb.known && report.ir.known, "{report:?}");
    assert_eq!(
        (report.rgb.state.as_str(), report.ir.state.as_str()),
        ("unknown", "unknown")
    );
    assert!(
        report.illumination.is_some(),
        "the IR side's illumination state"
    );
    drop(operation);
    assert_eq!(guard.lease_counts_observer()(), (0, 0));
}

#[test]
fn rate_diagnostics_measure_nothing_under_any_other_operation() {
    let _roots = crate::hostfs::test::empty_fixture();
    let (guard, expected) = fixture();
    for kind in [Preview, Setup] {
        let operation =
            acquire_split_camera_operation(&expected, kind, Duration::ZERO).expect("lease");
        let report = camera_rate_diagnostics_in_split_operation(&operation, RGB, IR);
        assert!(unmeasured(&report), "{kind:?}: {report:?}");
    }
    let ordinary =
        acquire_camera_operation(&[RGB], Diagnostics, Duration::ZERO).expect("ordinary lease");
    let report = camera_rate_diagnostics_in_split_operation(&ordinary, RGB, IR);
    assert!(unmeasured(&report), "ordinary: {report:?}");
    drop(ordinary);
    assert!(
        !guard
            .calls()
            .iter()
            .any(|call| matches!(call, Call::OpenRgb(_) | Call::OpenIr(_))),
        "no camera opens outside a split Diagnostics operation: {:?}",
        guard.calls()
    );
}
