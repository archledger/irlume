// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use irlume_camera::contracts::{
    BackendKind, CameraCapabilities, CameraDescriptor, CameraGeneration, CameraInstanceId,
    FrameMetadata, IdentityStrength, IlluminationProvenance, PhysicalCameraId, StreamRole,
    SynchronizationProvenance, MAX_CAMERA_CONTRACT_BYTES,
};

const TOPOLOGY: &str = "/devices/pci0000:00/usb1/1-2/1-2.1";
const INSTANCE_ID: &str = "00000000000000000000000000000001";

fn physical_id() -> PhysicalCameraId {
    PhysicalCameraId::new(TOPOLOGY, Some("200901010001".into()))
        .expect("valid raw identity evidence")
}

fn instance_id() -> CameraInstanceId {
    CameraInstanceId::new(INSTANCE_ID).expect("valid process camera-instance id")
}

fn capabilities() -> CameraCapabilities {
    CameraCapabilities::new(
        vec![StreamRole::Rgb, StreamRole::Ir],
        SynchronizationProvenance::HostCorrelated,
        vec![
            IlluminationProvenance::Ambient,
            IlluminationProvenance::ActiveIr,
        ],
    )
    .expect("coherent capability evidence")
}

#[test]
fn safe_stream_validates_both_sides_of_blocking_dequeue() {
    let source = include_str!("../src/lib.rs");
    let start = source
        .find("    fn next(&mut self) -> std::io::Result<(&[u8], &v4l::buffer::Metadata)> {")
        .expect("SafeStream::next exists");
    let body = &source[start
        ..source[start..]
            .find(
                "
    }
}

impl<'a> std::ops::Deref",
            )
            .map(|end| start + end)
            .expect("SafeStream::next body ends before Deref")];
    let dequeue = body
        .find("CaptureStream::next")
        .expect("blocking dequeue exists");
    let checks: Vec<_> = body
        .match_indices("require_endpoint")
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        checks.len(),
        2,
        "SafeStream must validate before and after dequeue"
    );
    assert!(checks[0] < dequeue && dequeue < checks[1]);
}

#[test]
fn camera_descriptor_v1_has_a_stable_wire_shape() {
    let descriptor = CameraDescriptor::new(
        BackendKind::UvcV4l2,
        physical_id(),
        instance_id(),
        CameraGeneration::new(7).expect("non-zero generation"),
        capabilities(),
    );

    let wire = serde_json::to_string(&descriptor).expect("serialize descriptor");
    assert_eq!(
        wire,
        r#"{"schema_version":1,"backend":"uvc_v4l2","physical_id":{"topology_path":"/devices/pci0000:00/usb1/1-2/1-2.1","serial":"200901010001"},"identity_strength":"ambiguous","camera_instance_id":"00000000000000000000000000000001","generation":7,"capabilities":{"stream_roles":["rgb","ir"],"synchronization":"host_correlated","illumination_provenance":["ambient","active_ir"]}}"#
    );
    assert_eq!(
        CameraDescriptor::from_json(&wire).expect("parse supported descriptor"),
        descriptor
    );
}

#[test]
fn conservative_camera_fields_default_to_no_claim() {
    let wire = format!(
        r#"{{"schema_version":1,"backend":"uvc_v4l2","physical_id":{{"topology_path":"{TOPOLOGY}"}},"camera_instance_id":"{INSTANCE_ID}","generation":1}}"#
    );
    let descriptor = CameraDescriptor::from_json(&wire).expect("parse conservative descriptor");

    assert_eq!(descriptor.identity_strength(), IdentityStrength::Ambiguous);
    assert_eq!(descriptor.capabilities(), &CameraCapabilities::default());
    assert_eq!(descriptor.physical_id().serial(), None);
}

#[test]
fn frame_metadata_v1_has_a_stable_wire_shape() {
    let metadata = FrameMetadata::new(
        instance_id(),
        CameraGeneration::new(7).expect("non-zero generation"),
        StreamRole::Ir,
        Some(42),
        SynchronizationProvenance::HostCorrelated,
        IlluminationProvenance::ActiveIr,
    )
    .expect("active IR is valid for an IR frame");

    let wire = serde_json::to_string(&metadata).expect("serialize frame metadata");
    assert_eq!(
        wire,
        r#"{"schema_version":1,"camera_instance_id":"00000000000000000000000000000001","generation":7,"stream_role":"ir","sequence":42,"synchronization":"host_correlated","illumination":"active_ir"}"#
    );
    assert_eq!(
        FrameMetadata::from_json(&wire).expect("parse supported frame metadata"),
        metadata
    );
}

#[test]
fn frame_generation_is_scoped_by_the_same_camera_instance_as_the_descriptor() {
    let descriptor = CameraDescriptor::new(
        BackendKind::UvcV4l2,
        physical_id(),
        instance_id(),
        CameraGeneration::INITIAL,
        CameraCapabilities::default(),
    );
    let metadata = FrameMetadata::new(
        instance_id(),
        CameraGeneration::INITIAL,
        StreamRole::Ir,
        None,
        SynchronizationProvenance::Unknown,
        IlluminationProvenance::Unknown,
    )
    .expect("unknown evidence is conservative");

    assert_eq!(
        metadata.camera_instance_id(),
        descriptor.camera_instance_id()
    );
}

#[test]
fn missing_frame_evidence_defaults_to_unknown_not_proven() {
    let wire = format!(
        r#"{{"schema_version":1,"camera_instance_id":"{INSTANCE_ID}","generation":7,"stream_role":"ir"}}"#
    );
    let metadata = FrameMetadata::from_json(&wire).expect("parse conservative frame metadata");

    assert_eq!(metadata.sequence(), None);
    assert_eq!(
        metadata.synchronization(),
        SynchronizationProvenance::Unknown
    );
    assert_eq!(metadata.illumination(), IlluminationProvenance::Unknown);
}

#[test]
fn both_roots_reject_old_and_new_schema_versions() {
    for version in [0, 2] {
        let descriptor = format!(
            r#"{{"schema_version":{version},"backend":"uvc_v4l2","physical_id":{{"topology_path":"{TOPOLOGY}"}},"camera_instance_id":"{INSTANCE_ID}","generation":1}}"#
        );
        let frame = format!(
            r#"{{"schema_version":{version},"camera_instance_id":"{INSTANCE_ID}","generation":1,"stream_role":"ir"}}"#
        );

        assert!(CameraDescriptor::from_json(&descriptor)
            .expect_err("unsupported descriptor schema must fail")
            .to_string()
            .contains(&format!(
                "unsupported camera contract schema version {version}"
            )));
        assert!(FrameMetadata::from_json(&frame)
            .expect_err("unsupported frame schema must fail")
            .to_string()
            .contains(&format!(
                "unsupported camera contract schema version {version}"
            )));
    }
}

#[test]
fn identity_evidence_is_canonical_and_never_self_upgrades_strength() {
    for topology in ["", "x", "/devices/", "/devices/a//b", "/devices/a/../b"] {
        assert!(PhysicalCameraId::new(topology, None).is_err());
    }
    assert!(PhysicalCameraId::new(TOPOLOGY, Some(String::new())).is_err());

    let self_asserted = format!(
        r#"{{"schema_version":1,"backend":"uvc_v4l2","physical_id":{{"topology_path":"{TOPOLOGY}"}},"identity_strength":"topology_bound","camera_instance_id":"{INSTANCE_ID}","generation":1}}"#
    );
    assert!(CameraDescriptor::from_json(&self_asserted).is_err());
}

#[test]
fn instance_and_generation_identifiers_reject_zero_or_malformed_values() {
    assert!(CameraGeneration::new(0).is_err());
    assert!(CameraGeneration::new(u64::MAX)
        .expect("maximum is a valid current generation")
        .next()
        .is_err());
    for id in [
        "",
        "00000000000000000000000000000000",
        "0000000000000000000000000000000g",
        "000000000000000000000000000000001",
    ] {
        assert!(CameraInstanceId::new(id).is_err());
    }
}

#[test]
fn contradictory_and_duplicate_capability_claims_are_rejected() {
    assert!(CameraCapabilities::new(
        vec![StreamRole::Rgb, StreamRole::Rgb],
        SynchronizationProvenance::Unknown,
        Vec::new(),
    )
    .is_err());
    assert!(CameraCapabilities::new(
        vec![StreamRole::Rgb],
        SynchronizationProvenance::Unknown,
        vec![IlluminationProvenance::ActiveIr],
    )
    .is_err());
    assert!(CameraCapabilities::new(
        vec![StreamRole::Rgb],
        SynchronizationProvenance::HardwareSynchronized,
        Vec::new(),
    )
    .is_err());
    assert!(CameraCapabilities::new(
        Vec::new(),
        SynchronizationProvenance::Unknown,
        vec![
            IlluminationProvenance::Ambient,
            IlluminationProvenance::Ambient,
        ],
    )
    .is_err());
}

#[test]
fn active_ir_is_rejected_on_an_rgb_frame() {
    assert!(FrameMetadata::new(
        instance_id(),
        CameraGeneration::INITIAL,
        StreamRole::Rgb,
        None,
        SynchronizationProvenance::Unknown,
        IlluminationProvenance::ActiveIr,
    )
    .is_err());
}

#[test]
fn malformed_duplicate_unknown_and_oversized_inputs_fail_closed() {
    let duplicate_version = format!(
        r#"{{"schema_version":1,"schema_version":1,"backend":"uvc_v4l2","physical_id":{{"topology_path":"{TOPOLOGY}"}},"camera_instance_id":"{INSTANCE_ID}","generation":1}}"#
    );
    let unknown_backend = format!(
        r#"{{"schema_version":1,"backend":"libcamera","physical_id":{{"topology_path":"{TOPOLOGY}"}},"camera_instance_id":"{INSTANCE_ID}","generation":1}}"#
    );
    let unknown_role = format!(
        r#"{{"schema_version":1,"camera_instance_id":"{INSTANCE_ID}","generation":1,"stream_role":"depth"}}"#
    );
    let unknown_field = format!(
        r#"{{"schema_version":1,"camera_instance_id":"{INSTANCE_ID}","generation":1,"stream_role":"ir","future":true}}"#
    );
    let oversized = "x".repeat(MAX_CAMERA_CONTRACT_BYTES + 1);

    assert!(CameraDescriptor::from_json(&duplicate_version).is_err());
    assert!(CameraDescriptor::from_json(&unknown_backend).is_err());
    assert!(FrameMetadata::from_json(&unknown_role).is_err());
    assert!(FrameMetadata::from_json(&unknown_field).is_err());
    assert!(CameraDescriptor::from_json(&oversized).is_err());
    assert!(FrameMetadata::from_json(&oversized).is_err());
}

#[test]
fn missing_schema_version_is_rejected() {
    let descriptor = format!(
        r#"{{"backend":"uvc_v4l2","physical_id":{{"topology_path":"{TOPOLOGY}"}},"camera_instance_id":"{INSTANCE_ID}","generation":1}}"#
    );
    let frame =
        format!(r#"{{"camera_instance_id":"{INSTANCE_ID}","generation":1,"stream_role":"ir"}}"#);
    assert!(CameraDescriptor::from_json(&descriptor).is_err());
    assert!(FrameMetadata::from_json(&frame).is_err());
}
