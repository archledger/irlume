// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use crate::multi_camera::{
    self, CameraGroupId, GroupPair, SecondaryGroup, SecondaryProfileScans, SecondaryStore,
};

const SPLIT: &str = "split1;5986:2113:rgb|0000:00:14.0|usb2|8;5986:1141:ir|0000:00:14.0|usb2|5";

// Frozen pre-split binding decoders. Do not share the new binding type.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct OldPrimaryBinding {
    #[serde(default)]
    rgb: Option<String>,
    #[serde(default)]
    ir: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OldGroupPair {
    #[serde(default)]
    rgb: Option<String>,
    #[serde(default)]
    ir: Option<String>,
}

#[derive(Deserialize)]
struct OldPrimary {
    camera_binding: Option<OldPrimaryBinding>,
}

#[derive(Deserialize)]
struct OldSecondaryGroup {
    pair: OldGroupPair,
}

#[derive(Deserialize)]
struct OldSecondary {
    groups: Vec<OldSecondaryGroup>,
}

fn primary(binding: serde_json::Value) -> Enrollment {
    serde_json::from_value(
        serde_json::json!({"user": "alice", "profiles": [], "camera_binding": binding}),
    )
    .unwrap()
}

fn secondary(pair: GroupPair, primary: &[u8]) -> SecondaryStore {
    SecondaryStore {
        format_version: 1,
        owner: "alice".into(),
        generation: 1,
        primary_snapshot_sha256: irlume_common::sha256_hex(primary),
        groups: vec![SecondaryGroup {
            id: CameraGroupId::new("desk".into()).unwrap(),
            pair,
            profiles: vec![SecondaryProfileScans {
                profile: "main".into(),
                scans: vec![FaceScan {
                    name: "synthetic".into(),
                    rgb: vec![],
                    ir: None,
                    ir_space: None,
                    embed_space: None,
                    embed_producer: None,
                    ir_center_edge_ratio: 0.0,
                    ir_brightness: 0.0,
                    pitch: 0.0,
                    captured_at: None,
                }],
                ir_calibs: Default::default(),
            }],
        }],
    }
}

fn plaintext(bytes: &[u8], key: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    match value.get("enc") {
        Some(enc) => crypto::decrypt(
            key.unwrap(),
            &STANDARD.decode(enc.as_str().unwrap()).unwrap(),
        )
        .unwrap(),
        None => Zeroizing::new(bytes.to_vec()),
    }
}

#[test]
fn ordinary_binding_bytes_and_frozen_readers_survive_both_envelopes() {
    let _guard = crate::testenv::ENV_LOCK.lock().unwrap();
    let dir = PathBuf::from(crate::test_tmp_dir("ordinary-binding-contract"));
    std::fs::create_dir_all(&dir).unwrap();
    let old = OldPrimaryBinding {
        rgb: Some("rgb".into()),
        ir: None,
    };
    let enrollment = primary(serde_json::json!({"rgb": "rgb", "ir": null}));
    assert_eq!(
        serde_json::to_vec(enrollment.camera_binding.as_ref().unwrap()).unwrap(),
        serde_json::to_vec(&old).unwrap()
    );
    let pair: GroupPair = serde_json::from_str("{\"rgb\":\"rgb\",\"ir\":null}").unwrap();
    assert_eq!(
        serde_json::to_string(&pair).unwrap(),
        "{\"rgb\":\"rgb\",\"ir\":null}"
    );
    let key = [19u8; 32];
    for key in [None, Some(key.as_slice())] {
        let bytes = serialize_enrollment(&enrollment, key).unwrap();
        assert_eq!(
            deserialize_enrollment(&bytes, key).unwrap().camera_binding,
            enrollment.camera_binding
        );
        let old_primary: OldPrimary = serde_json::from_slice(&plaintext(&bytes, key)).unwrap();
        assert_eq!(old_primary.camera_binding.unwrap(), old);
        let store = secondary(pair.clone(), &bytes);
        let path = dir.join("alice.json");
        multi_camera::save_secondary_with_key(&path, &store, key).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let old_secondary: OldSecondary = serde_json::from_slice(&plaintext(&bytes, key)).unwrap();
        assert_eq!(old_secondary.groups[0].pair.rgb.as_deref(), Some("rgb"));
        assert_eq!(old_secondary.groups[0].pair.ir, None);
        assert_eq!(
            multi_camera::load_secondary_with_key(&path, key)
                .unwrap()
                .unwrap()
                .groups[0]
                .pair,
            pair
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn split_binding_is_a_string_and_frozen_readers_refuse_both_envelopes() {
    let _guard = crate::testenv::ENV_LOCK.lock().unwrap();
    let dir = PathBuf::from(crate::test_tmp_dir("split-binding-contract"));
    std::fs::create_dir_all(&dir).unwrap();
    let enrollment = primary(serde_json::json!(SPLIT));
    let pair: GroupPair = serde_json::from_value(serde_json::json!(SPLIT)).unwrap();
    let key = [23u8; 32];
    for key in [None, Some(key.as_slice())] {
        let bytes = serialize_enrollment(&enrollment, key).unwrap();
        let plain = plaintext(&bytes, key);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&plain).unwrap()["camera_binding"],
            SPLIT
        );
        assert!(serde_json::from_slice::<OldPrimary>(&plain).is_err());
        assert_eq!(
            deserialize_enrollment(&bytes, key).unwrap().camera_binding,
            enrollment.camera_binding
        );
        let store = secondary(pair.clone(), &bytes);
        let path = dir.join("alice.json");
        multi_camera::save_secondary_with_key(&path, &store, key).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let plain = plaintext(&bytes, key);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&plain).unwrap()["groups"][0]["pair"],
            SPLIT
        );
        assert!(serde_json::from_slice::<OldSecondary>(&plain).is_err());
        assert_eq!(
            multi_camera::load_secondary_with_key(&path, key)
                .unwrap()
                .unwrap()
                .groups[0]
                .pair,
            pair
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unknown_binding_objects_refuse_instead_of_becoming_unbound() {
    let input = br#"{"user":"alice","profiles":[],"camera_binding":{"split_key":"unknown"}}"#;
    assert!(deserialize_enrollment(input, None).is_err());
}
