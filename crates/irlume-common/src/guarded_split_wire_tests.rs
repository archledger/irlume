// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Operation-choice compatibility at the real Request/Response serde boundary.

use crate::{Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn operation(kind: &str) -> Value {
    let mut payload = json!({
        "user": "alice", "profile": null, "scans": 1,
        "pair": {
            "expected": {
                "supervisor_id": "11111111111111111111111111111111", "revision": 7,
                "rgb": {"instance_id": "22222222222222222222222222222222", "generation": 1, "endpoint": "0123456789abcdef"},
                "ir": {"instance_id": "33333333333333333333333333333333", "generation": 2, "endpoint": "fedcba9876543210"}
            },
            "authorization": {"generation": 3, "token": "a".repeat(64)}
        }
    });
    if kind == "EnrollSplitOn" {
        payload["reset"] = false.into();
    }
    json!({kind: payload})
}

fn decode(wire: &Value) -> Result<Request, serde_json::Error> {
    // Exercise the same from_str entry as read_request and ipc_request, rather
    // than only Value's deserializer.
    serde_json::from_str(&serde_json::to_string(wire).unwrap())
}

#[test]
fn split_operations_preserve_original_two_incarnations_and_publication_proof() {
    for kind in ["EnrollSplitOn", "AddSplitCameraGroupOn"] {
        let wire = operation(kind);
        let request = decode(&wire).expect("guarded split operation must be supported");
        assert_eq!(serde_json::to_value(request).unwrap(), wire);
    }
}

#[test]
fn split_enrollment_omitted_reset_is_false_and_explicit_reset_survives() {
    let mut wire = operation("EnrollSplitOn");
    wire["EnrollSplitOn"]
        .as_object_mut()
        .unwrap()
        .remove("reset");
    let request = decode(&wire).expect("omitted reset must decode");
    wire["EnrollSplitOn"]["reset"] = false.into();
    assert_eq!(serde_json::to_value(request).unwrap(), wire);
    wire["EnrollSplitOn"]["reset"] = true.into();
    assert_eq!(serde_json::to_value(decode(&wire).unwrap()).unwrap(), wire);
}

#[test]
fn split_operations_refuse_missing_malformed_and_unbounded_choice_controls() {
    for kind in ["EnrollSplitOn", "AddSplitCameraGroupOn"] {
        let good = operation(kind);
        decode(&good).expect("positive control excludes blanket variant refusal");
        for pointer in [
            "/pair",
            "/pair/expected",
            "/pair/authorization",
            "/pair/expected/rgb",
            "/pair/expected/ir",
        ] {
            let mut wire = good.clone();
            *wire[kind].pointer_mut(pointer).unwrap() = Value::Null;
            assert!(decode(&wire).is_err(), "accepted null {pointer}");
        }
        for (parent, field) in [
            ("", "pair"),
            ("/pair", "expected"),
            ("/pair", "authorization"),
            ("/pair/expected", "supervisor_id"),
            ("/pair/expected", "revision"),
            ("/pair/expected", "rgb"),
            ("/pair/expected", "ir"),
            ("/pair/expected/rgb", "instance_id"),
            ("/pair/expected/rgb", "generation"),
            ("/pair/expected/rgb", "endpoint"),
            ("/pair/expected/ir", "endpoint"),
            ("/pair/authorization", "generation"),
            ("/pair/authorization", "token"),
        ] {
            let mut wire = good.clone();
            wire[kind]
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(decode(&wire).is_err(), "accepted missing {parent}/{field}");
        }
        for parent in [
            "/pair",
            "/pair/expected",
            "/pair/expected/rgb",
            "/pair/expected/ir",
            "/pair/authorization",
        ] {
            let mut wire = good.clone();
            wire[kind].pointer_mut(parent).unwrap()["class"] = "ordinary".into();
            assert!(
                decode(&wire).is_err(),
                "accepted unknown control in {parent}"
            );
        }
        for pointer in [
            "/pair/expected/revision",
            "/pair/expected/rgb/generation",
            "/pair/expected/ir/generation",
            "/pair/authorization/generation",
        ] {
            for value in [json!(0), json!(-1), json!(1.5), json!("1"), Value::Null] {
                let mut wire = good.clone();
                *wire[kind].pointer_mut(pointer).unwrap() = value;
                assert!(decode(&wire).is_err(), "accepted invalid {pointer}");
            }
        }
        for token in [
            "".into(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            "\n".repeat(64),
            "é".repeat(32),
            "a".repeat(65536),
        ] {
            let mut wire = good.clone();
            wire[kind]["pair"]["authorization"]["token"] = token.into();
            assert!(decode(&wire).is_err(), "accepted invalid token");
        }
        for pointer in [
            "/pair/expected/supervisor_id",
            "/pair/expected/rgb/instance_id",
            "/pair/expected/ir/instance_id",
        ] {
            for id in [
                "0".repeat(32),
                "A".repeat(32),
                "a".repeat(31),
                "a".repeat(33),
            ] {
                let mut wire = good.clone();
                *wire[kind].pointer_mut(pointer).unwrap() = id.into();
                assert!(decode(&wire).is_err(), "accepted invalid {pointer}");
            }
        }
        for side in ["rgb", "ir"] {
            for endpoint in [
                "".into(),
                "x".repeat(97),
                "video\n0".into(),
                "video\0x".into(),
                "video\u{7f}".into(),
                "video\u{85}".into(),
                "x".repeat(65536),
            ] {
                let mut wire = good.clone();
                wire[kind]["pair"]["expected"][side]["endpoint"] = endpoint.into();
                assert!(decode(&wire).is_err(), "accepted invalid {side} endpoint");
            }
        }
        for field in ["instance_id", "endpoint"] {
            let mut wire = good.clone();
            wire[kind]["pair"]["expected"]["ir"][field] =
                wire[kind]["pair"]["expected"]["rgb"][field].clone();
            assert!(decode(&wire).is_err(), "accepted shared {field}");
        }
        // Exact endpoint byte bound and u64 maxima are supported, no truncation.
        let mut wire = good;
        wire[kind]["pair"]["expected"]["rgb"]["endpoint"] = "x".repeat(96).into();
        wire[kind]["pair"]["authorization"]["generation"] = u64::MAX.into();
        assert_eq!(serde_json::to_value(decode(&wire).unwrap()).unwrap(), wire);
    }
}

#[test]
fn split_operations_refuse_duplicate_guard_fields_in_text() {
    let text = serde_json::to_string(&operation("EnrollSplitOn")).unwrap();
    serde_json::from_str::<Request>(&text).expect("positive text control");
    for field in [
        "authorization",
        "expected",
        "rgb",
        "ir",
        "token",
        "endpoint",
        "instance_id",
        "supervisor_id",
        "revision",
        "generation",
    ] {
        let marker = format!("\"{field}\":");
        let bad = text.replacen(&marker, &format!("\"{field}\":null,{marker}"), 1);
        assert!(
            serde_json::from_str::<Request>(&bad).is_err(),
            "accepted duplicate {field}"
        );
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum FrozenOrdinaryRequest {
    Enroll {
        user: String,
        profile: Option<String>,
        scans: Option<usize>,
        #[serde(default)]
        reset: bool,
    },
    EnrollOn {
        user: String,
        profile: Option<String>,
        scans: Option<usize>,
        #[serde(default)]
        reset: bool,
        pair: Box<crate::live_camera::EnrollmentCameraChoice>,
    },
    AddCameraGroup {
        user: String,
        profile: Option<String>,
        #[serde(default)]
        scans: Option<usize>,
    },
    AddCameraGroupOn {
        user: String,
        profile: Option<String>,
        scans: Option<usize>,
        pair: Box<crate::live_camera::EnrollmentCameraChoice>,
    },
    SetCameras {
        rgb: String,
        ir: String,
    },
}

#[test]
fn frozen_ordinary_requests_refuse_split_variants_and_keep_existing_encodings() {
    for kind in ["EnrollSplitOn", "AddSplitCameraGroupOn"] {
        let wire = operation(kind);
        decode(&wire).expect("positive split control");
        assert!(serde_json::from_value::<FrozenOrdinaryRequest>(wire).is_err());
    }
    let ordinary = json!({"rgb":"/dev/video0","ir":"/dev/video1","expected":{
        "supervisor_id":"11111111111111111111111111111111","candidate":{
            "instance_id":"22222222222222222222222222222222","generation":7,
            "endpoint_paths":["/dev/video0","/dev/video1"]}}});
    for wire in [
        json!({"Enroll":{"user":"alice","profile":null,"scans":1,"reset":false}}),
        json!({"AddCameraGroup":{"user":"alice","profile":null,"scans":1}}),
        json!({"EnrollOn":{"user":"alice","profile":null,"scans":1,"reset":true,"pair":ordinary}}),
        json!({"AddCameraGroupOn":{"user":"alice","profile":null,"scans":1,"pair":ordinary}}),
        json!({"SetCameras":{"rgb":"/dev/video0","ir":"/dev/video1"}}),
    ] {
        let old: FrozenOrdinaryRequest = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(old).unwrap(), wire);
        assert_eq!(serde_json::to_value(decode(&wire).unwrap()).unwrap(), wire);
    }
}

fn listing() -> Value {
    json!({"SplitInventory":{
        "supervisor_id":"11111111111111111111111111111111","revision":7,
        "store_state":"Valid","records":[],"selected":{"ShareSafe":{"resolves":true}},
        "candidates":[], "authorization":{"generation":3,"token":"a".repeat(64)}
    }})
}

#[test]
fn split_listing_preserves_optional_share_safe_publication_proof() {
    let wire = listing();
    let response: Response = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        wire,
        "listing proof must survive decoding"
    );
    let mut legacy = wire.clone();
    legacy["SplitInventory"]
        .as_object_mut()
        .unwrap()
        .remove("authorization");
    let response: Response = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        legacy,
        "absent proof must not be synthesized"
    );
    let mut null = legacy.clone();
    null["SplitInventory"]["authorization"] = Value::Null;
    let response: Response = serde_json::from_value(null).unwrap();
    assert_eq!(serde_json::to_value(response).unwrap(), legacy);
    for forbidden in [
        "/dev/",
        "identity",
        "serial",
        "digest",
        "controller",
        "split1;",
    ] {
        assert!(!serde_json::to_string(&wire).unwrap().contains(forbidden));
    }
    // Older listing decoder remains open, unlike frozen ordinary candidates.
    #[derive(Deserialize)]
    enum OldResponse {
        SplitInventory(OldView),
    }
    #[derive(Deserialize, Serialize)]
    struct OldView {
        supervisor_id: String,
        revision: u64,
        store_state: crate::split_wire::SplitStoreState,
        records: Vec<crate::split_wire::SplitRecordView>,
        selected: Option<crate::split_wire::SplitSelectionView>,
        #[serde(default)]
        candidates: Vec<crate::split_wire::SplitCandidateView>,
    }
    let OldResponse::SplitInventory(old) = serde_json::from_value(wire).unwrap();
    assert_eq!(serde_json::to_value(old).unwrap(), legacy["SplitInventory"]);
}

#[test]
fn split_listing_present_malformed_proof_refuses_instead_of_becoming_absent() {
    let wire = listing();
    let _: Response = serde_json::from_value(wire.clone()).unwrap();
    for proof in [
        json!({}),
        json!({"generation":0,"token":"a".repeat(64)}),
        json!({"generation":3,"token":"a".repeat(65)}),
        json!({"generation":3,"token":"a".repeat(64),"digest":"raw"}),
    ] {
        let mut bad = wire.clone();
        bad["SplitInventory"]["authorization"] = proof;
        assert!(serde_json::from_value::<Response>(bad).is_err());
    }
}

#[test]
fn split_operation_fuzz_seeds_reach_the_valid_choice_decoder() {
    for (kind, seed) in [
        (
            "EnrollSplitOn",
            include_str!("../../../fuzz/seeds/ipc_request/enroll-split-on-guarded.json"),
        ),
        (
            "AddSplitCameraGroupOn",
            include_str!("../../../fuzz/seeds/ipc_request/add-split-camera-group-on-guarded.json"),
        ),
    ] {
        let request: Request =
            serde_json::from_str(seed).expect("seed must enter the valid choice path");
        let wire: Value = serde_json::from_str(seed).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), wire);
        assert_eq!(wire[kind]["pair"]["authorization"]["generation"], 3);
    }
}
