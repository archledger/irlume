// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;

#[derive(Deserialize)]
enum LegacyResponse {
    FaceSensorStatus {
        policy: config::FaceSensorPolicyObservation,
        ir_readiness: Option<IrOnlyReadiness>,
    },
}

#[test]
fn target_detail_preserves_old_and_new_wire_readers() {
    let old = r#"{"FaceSensorStatus":{"policy":{"explicit":"ir-only-experimental"},"ir_readiness":"target_unavailable"}}"#;
    assert!(matches!(
        serde_json::from_str::<Response>(old).unwrap(),
        Response::FaceSensorStatus {
            ir_readiness: Some(IrOnlyReadiness::TargetUnavailable),
            ir_target_issue: None,
            ..
        }
    ));
    let new = Response::FaceSensorStatus {
        policy: config::FaceSensorPolicyObservation::Explicit(
            config::FaceSensorPolicy::IrOnlyExperimental,
        ),
        ir_readiness: Some(IrOnlyReadiness::TargetUnavailable),
        ir_target_issue: Some(IrTargetIssue::Unconfigured),
        ir_readiness_detail: None,
        ir_scope: None,
        ir_scope_index: None,
    };
    let wire = serde_json::to_string(&new).unwrap();
    let LegacyResponse::FaceSensorStatus {
        policy,
        ir_readiness,
    } = serde_json::from_str(&wire).unwrap();
    assert_eq!(
        policy,
        config::FaceSensorPolicyObservation::Explicit(config::FaceSensorPolicy::IrOnlyExperimental)
    );
    assert_eq!(ir_readiness, Some(IrOnlyReadiness::TargetUnavailable));
    let future = wire.replace("unconfigured", "future_target_issue");
    assert!(matches!(
        serde_json::from_str::<Response>(&future).unwrap(),
        Response::FaceSensorStatus {
            ir_target_issue: Some(IrTargetIssue::Unknown),
            ir_readiness: Some(IrOnlyReadiness::TargetUnavailable),
            ..
        }
    ));
}

#[test]
fn ordinary_sensor_status_omits_absent_detail() {
    let status = Response::FaceSensorStatus {
        policy: config::FaceSensorPolicyObservation::DefaultDual,
        ir_readiness: None,
        ir_target_issue: None,
        ir_readiness_detail: None,
        ir_scope: None,
        ir_scope_index: None,
    };
    let wire = serde_json::to_value(status).unwrap();
    assert_eq!(wire["FaceSensorStatus"].as_object().unwrap().len(), 2);
    assert!(wire["FaceSensorStatus"].get("ir_target_issue").is_none());
}

/// A frozen copy of the pre-ADR-0028 types: the readiness vocabulary had
/// no fallback, so an unknown value rejected the whole status.
mod frozen {
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum IrOnlyReadiness {
        Unavailable,
        ReadyForExperimentalAttempt,
        InvalidPolicy,
        TargetUnavailable,
        BindingUnavailable,
        BindingMismatch,
        ModelsUnavailable,
        PadUnavailable,
        EnrollmentUnavailable,
        IncompatibleEnrollment,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum IrTargetIssue {
        Unconfigured,
        Unavailable,
        UnsupportedTopology,
        BindingUnavailable,
        Changed,
        #[serde(other)]
        Unknown,
    }

    #[derive(Debug, Deserialize)]
    pub enum Response {
        FaceSensorStatus {
            policy: crate::config::FaceSensorPolicyObservation,
            ir_readiness: Option<IrOnlyReadiness>,
            #[serde(default)]
            ir_target_issue: Option<IrTargetIssue>,
        },
    }
}

/// ADR-0028 §3: a new daemon's status for each new readiness value decodes
/// with the pre-change types (`ir_readiness` reads `binding_mismatch`, the
/// extra fields are ignored), and a new client reads the detail and the
/// scope. A status carrying the new value in the OLD field would have been
/// rejected outright, which is what the mapping prevents.
#[test]
fn secondary_readiness_decodes_with_pre_change_clients() {
    let policy =
        config::FaceSensorPolicyObservation::Explicit(config::FaceSensorPolicy::IrOnlyExperimental);
    for detail in [
        IrOnlyReadiness::SecondaryInactive,
        IrOnlyReadiness::SecondaryUnvalidated,
    ] {
        let status = Response::FaceSensorStatus {
            policy,
            ir_readiness: Some(detail.wire_compatible()),
            ir_target_issue: None,
            ir_readiness_detail: Some(detail),
            ir_scope: Some(IrScope::Secondary),
            ir_scope_index: Some(2),
        };
        let wire = serde_json::to_string(&status).unwrap();
        let frozen::Response::FaceSensorStatus {
            policy: seen,
            ir_readiness,
            ir_target_issue,
        } = serde_json::from_str(&wire).unwrap();
        assert_eq!(seen, policy);
        assert_eq!(ir_readiness, Some(frozen::IrOnlyReadiness::BindingMismatch));
        assert_eq!(ir_target_issue, None);
        // The unmapped value in the old field is exactly what an old client
        // could not decode.
        let unmapped = wire.replacen(
            "\"binding_mismatch\"",
            &format!(
                "\"{}\"",
                serde_json::to_string(&detail).unwrap().trim_matches('"')
            ),
            1,
        );
        assert!(serde_json::from_str::<frozen::Response>(&unmapped).is_err());
        // A new client reads the detail and the scope.
        assert!(matches!(
            serde_json::from_str::<Response>(&wire).unwrap(),
            Response::FaceSensorStatus {
                ir_readiness: Some(IrOnlyReadiness::BindingMismatch),
                ir_readiness_detail: Some(d),
                ir_scope: Some(IrScope::Secondary),
                ir_scope_index: Some(2),
                ..
            } if d == detail
        ));
    }
    // A value neither side knows yet lands on the fallbacks, never on a
    // rejected status.
    let future = r#"{"FaceSensorStatus":{"policy":{"explicit":"ir-only-experimental"},"ir_readiness":"binding_mismatch","ir_readiness_detail":"later_cause","ir_scope":"tertiary","ir_scope_index":1}}"#;
    assert!(matches!(
        serde_json::from_str::<Response>(future).unwrap(),
        Response::FaceSensorStatus {
            ir_readiness_detail: Some(IrOnlyReadiness::Unknown),
            ir_scope: Some(IrScope::Unknown),
            ..
        }
    ));
}

/// ADR-0029: the camera listing and the enrollment binding are additive.
/// A frozen copy of the pre-change `CameraPairInfo` decodes a new daemon's
/// row; a new client reads an old daemon's row with the fields absent.
#[test]
fn camera_names_and_binding_are_additive_on_the_wire() {
    #[derive(Debug, serde::Deserialize)]
    struct FrozenCameraPairInfo {
        rgb: String,
        ir: String,
        id: Option<String>,
        fixed: bool,
        #[serde(default)]
        privacy: bool,
    }
    let new = CameraPairInfo {
        rgb: "/dev/video4".into(),
        ir: "/dev/video6".into(),
        id: Some("3443:c803".into()),
        fixed: false,
        privacy: false,
        name: Some("NexiGo N930W".into()),
        identity: Some("3443:c803".into()),
        serial_present: false,
        handle: Some("9f1c2a7b4d0e6f13".into()),
    };
    let wire = serde_json::to_string(&new).unwrap();
    let frozen: FrozenCameraPairInfo = serde_json::from_str(&wire).unwrap();
    assert_eq!(
        (frozen.rgb.as_str(), frozen.ir.as_str()),
        ("/dev/video4", "/dev/video6")
    );
    assert_eq!(frozen.id.as_deref(), Some("3443:c803"));
    assert!(!frozen.fixed && !frozen.privacy);
    let old = r#"{"rgb":"/dev/video0","ir":"/dev/video2","id":"3277:0059","fixed":true}"#;
    let decoded: CameraPairInfo = serde_json::from_str(old).unwrap();
    assert!(decoded.name.is_none() && decoded.identity.is_none() && !decoded.serial_present);
    // An unnamed pair omits the optional fields rather than sending null.
    let unnamed = CameraPairInfo {
        name: None,
        identity: None,
        ..new
    };
    let wire = serde_json::to_value(&unnamed).unwrap();
    assert!(wire.get("name").is_none() && wire.get("identity").is_none());
    // The enrollment binding is optional in both directions.
    let legacy = serde_json::json!({"Enrollment": {
        "profiles": [], "require_eyes_open": false,
        "closure_calibrated": false, "ir_ratio_calibrated": false
    }});
    assert!(matches!(
        serde_json::from_value::<Response>(legacy).unwrap(),
        Response::Enrollment {
            primary_camera: None,
            ..
        }
    ));
    let modern = Response::Enrollment {
        profiles: Vec::new(),
        require_eyes_open: false,
        closure_calibrated: false,
        ir_ratio_calibrated: false,
        camera_groups: Vec::new(),
        camera_store_error: None,
        primary_camera: Some(PrimaryCameraBinding {
            rgb: Some("046d:085e:e179cb54".into()),
            ir: Some("046d:085e:e179cb54".into()),
            connected_handle: Some("9f1c2a7b4d0e6f13".into()),
        }),
    };
    let wire = serde_json::to_value(&modern).unwrap();
    assert_eq!(
        wire["Enrollment"]["primary_camera"]["rgb"],
        "046d:085e:e179cb54"
    );
    assert_eq!(
        wire["Enrollment"]["primary_camera"]["connected_handle"],
        "9f1c2a7b4d0e6f13"
    );
    // A binding without a handle (older daemon, or nothing connected)
    // omits the field, and a client decodes it as None.
    let legacy: PrimaryCameraBinding =
        serde_json::from_str(r#"{"rgb":"046d:085e","ir":"046d:085e"}"#).unwrap();
    assert_eq!(legacy.connected_handle, None);
}
