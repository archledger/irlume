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
    };
    let wire = serde_json::to_value(status).unwrap();
    assert_eq!(wire["FaceSensorStatus"].as_object().unwrap().len(), 2);
    assert!(wire["FaceSensorStatus"].get("ir_target_issue").is_none());
}
