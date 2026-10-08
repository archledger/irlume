// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
use irlume_common::split_schema::{AuthorizationRecord, SideFields};
use irlume_core::storage;
use std::{cell::Cell, ffi::OsString, path::PathBuf};

struct Fixture {
    dir: PathBuf,
    rgb: String,
    ir: String,
    saved: Vec<(&'static str, Option<OsString>)>,
    recorder: Guard,
    /// Every fixture test takes the no-TPM plaintext branch: the dead
    /// `IRLUME_TCTI` below cannot reach a TPM, and on a host with /dev/tpm*
    /// the device-node probe would otherwise force a seal onto it.
    _no_tpm: irlume_core::template_key::test_support::TpmPresence,
}

fn split_choice(
    fixture: &Fixture,
) -> (
    irlume_common::split_wire::SplitMutationGuard,
    irlume_common::split_publish::Published,
) {
    fixture.select_split();
    let snapshot = irlume_common::split_publish::read_camera_selection();
    let records = match snapshot.split() {
        irlume_common::split_publish::SplitReadState::Valid { records, .. } => records,
        state => panic!("fixture publication refused: {state:?}"),
    };
    let pair = irlume_camera::connected_pairs_with_split(records)
        .split_pairs
        .remove(0);
    let lease = pair.lease_request();
    let side =
        |expected: irlume_camera::SplitSideExpectation| irlume_common::split_wire::SplitSideGuard {
            instance_id: expected.instance_id,
            generation: expected.generation,
            endpoint: expected.endpoint,
        };
    let guard = irlume_common::split_wire::SplitMutationGuard {
        supervisor_id: lease.supervisor_id,
        revision: lease.revision,
        rgb: side(lease.rgb),
        ir: side(lease.ir),
    };
    let irlume_common::config::SplitConfObservation::Reference {
        generation, digest, ..
    } = snapshot.observation().split.clone()
    else {
        panic!("missing reference")
    };
    (
        guard,
        irlume_common::split_publish::Published { generation, digest },
    )
}

fn fixture_split_binding() -> storage::CameraBinding {
    storage::CameraBinding::Split(
        irlume_common::split_key::SplitPairKey::parse_canonical(
            "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5",
        )
        .unwrap(),
    )
}

#[test]
fn guarded_split_preparation_keeps_whole_binding_and_restores_without_camera_work() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = split_choice(&fixture);
    let config_before = std::fs::read(fixture.dir.join("cameras.conf")).unwrap();
    let previous = (
        shared.engine.rgb_dev.clone(),
        shared.engine.ir_dev.clone(),
        shared.engine.ir_available,
    );
    {
        let request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        assert_eq!(
            request.prepared_enrollment_binding().unwrap(),
            fixture_split_binding()
        );
        assert_eq!(request.current_binding(), fixture_split_binding());
        assert_eq!(request.live_pair(), fixture_split_binding());
        assert!(request.prepared_camera_lease().is_none());
        assert!(request.validate_enrollment_camera_activation().is_err());
        assert!(fixture.recorder.calls().is_empty());
    }
    assert_eq!(
        (
            shared.engine.rgb_dev.clone(),
            shared.engine.ir_dev.clone(),
            shared.engine.ir_available
        ),
        previous
    );
    assert!(shared.engine.camera_selection.is_none());
    assert_eq!(
        std::fs::read(fixture.dir.join("cameras.conf")).unwrap(),
        config_before
    );
}

#[test]
fn guarded_split_primary_requires_exact_key_even_when_bound_store_is_empty() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = split_choice(&fixture);
    let request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    let mut enrollment = storage::Enrollment::new("split-primary-check");
    request
        .validate_operation_primary(&enrollment, false)
        .unwrap();
    enrollment.camera_binding = Some(fixture_split_binding());
    request
        .validate_operation_primary(&enrollment, false)
        .unwrap();
    let primary_path = fixture.dir.join("split-primary-check.json");
    std::fs::write(&primary_path, serde_json::to_vec(&enrollment).unwrap()).unwrap();
    request
        .validate_enrollment_camera_primary("split-primary-check", false)
        .unwrap();
    let storage::CameraBinding::Split(mut different) = fixture_split_binding() else {
        unreachable!()
    };
    different.ir.ports = vec![6];
    for binding in [
        storage::CameraBinding::Split(different),
        storage::CameraBinding::Ordinary {
            rgb: Some("1234:0001:rgb".into()),
            ir: Some("1234:0002:ir".into()),
        },
        storage::CameraBinding::Ordinary {
            rgb: Some("1234:0001:rgb".into()),
            ir: None,
        },
    ] {
        enrollment.camera_binding = Some(binding);
        assert!(request
            .validate_operation_primary(&enrollment, false)
            .is_err());
        request
            .validate_operation_primary(&enrollment, true)
            .unwrap();
        std::fs::write(&primary_path, serde_json::to_vec(&enrollment).unwrap()).unwrap();
        assert!(request
            .validate_enrollment_camera_primary("split-primary-check", false)
            .is_err());
        request
            .validate_enrollment_camera_primary("split-primary-check", true)
            .unwrap();
    }
    let storage::CameraBinding::Split(key) = fixture_split_binding() else {
        unreachable!()
    };
    for rgb in [true, false] {
        for field in ["controller", "domain", "ports", "identity"] {
            let mut changed = key.clone();
            let side = if rgb {
                &mut changed.rgb
            } else {
                &mut changed.ir
            };
            match field {
                "controller" => side.controller = "0000:00:15.0".into(),
                "domain" => side.domain = irlume_common::split_key::SplitDomain::SuperSpeed,
                "ports" => side.ports = vec![10],
                "identity" => side.identity = "1234:9999:other".into(),
                _ => unreachable!(),
            }
            enrollment.camera_binding = Some(storage::CameraBinding::Split(changed));
            assert!(
                request
                    .validate_operation_primary(&enrollment, false)
                    .is_err(),
                "{rgb}/{field}"
            );
        }
    }
    enrollment.camera_binding = Some(storage::CameraBinding::Split(
        irlume_common::split_key::SplitPairKey {
            rgb: key.ir,
            ir: key.rgb,
        },
    ));
    assert!(request
        .validate_operation_primary(&enrollment, false)
        .is_err());
    let (mut unbound_scans, _) = pad_matching_fixture(0.2, false);
    unbound_scans.camera_binding = None;
    assert!(request
        .validate_operation_primary(&unbound_scans, false)
        .is_err());
    assert!(fixture.recorder.calls().is_empty());
}

#[test]
fn guarded_split_operation_can_choose_unselected_authorization_without_writing_selection() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, _) = split_choice(&fixture);
    let snapshot = irlume_common::split_publish::read_camera_selection();
    let irlume_common::split_publish::SplitReadState::Valid { records, .. } = snapshot.split()
    else {
        unreachable!()
    };
    let mut other = records[0].clone();
    other.rgb.identity = "1234:0003:other-rgb".into();
    other.rgb.path = "/dev/unselected-other-rgb".into();
    other.rgb.ports = vec![3];
    other.ir.identity = "1234:0004:other-ir".into();
    other.ir.path = "/dev/unselected-other-ir".into();
    other.ir.ports = vec![4];
    let other_key = other.pair_key();
    for selected in [Some(&other_key), None] {
        let publication = irlume_common::split_publish::publish_split(
            &[other.clone(), records[0].clone()],
            selected,
        )
        .unwrap();
        let before = std::fs::read(fixture.dir.join("cameras.conf")).unwrap();
        let request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        assert_eq!(
            request.prepared_enrollment_binding().unwrap(),
            fixture_split_binding()
        );
        drop(request);
        assert_eq!(
            std::fs::read(fixture.dir.join("cameras.conf")).unwrap(),
            before
        );
    }
    assert!(fixture.recorder.calls().is_empty());
}

#[test]
fn guarded_split_preparation_applies_external_policy_to_either_side() {
    let _env = env_guard();
    let mut shared = shared();
    for (rgb_fixed, ir_fixed) in [(false, true), (true, false), (false, false)] {
        let mut fixture = Fixture::new(true);
        fixture.saved.push((
            "IRLUME_FORBID_EXTERNAL_CAMERAS",
            std::env::var_os("IRLUME_FORBID_EXTERNAL_CAMERAS"),
        ));
        let camera = |rgb: bool| Camera {
            topology: if rgb {
                "/devices/fixture/rgb"
            } else {
                "/devices/fixture/ir"
            }
            .into(),
            identity: if rgb { "1234:0001:rgb" } else { "1234:0002:ir" }.into(),
            fixed: if rgb { rgb_fixed } else { ir_fixed },
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![if rgb { 8 } else { 5 }],
            endpoints: vec![Endpoint {
                path: if rgb {
                    fixture.rgb.clone()
                } else {
                    fixture.ir.clone()
                },
                formats: vec![if rgb { *b"YUYV" } else { *b"GREY" }],
            }],
        };
        let recorder = Guard::install(&[camera(true), camera(false)]).unwrap();
        let (guard, publication) = split_choice(&fixture);
        std::env::set_var("IRLUME_FORBID_EXTERNAL_CAMERAS", "0");
        std::env::remove_var("IRLUME_CAMERA_REQUIRE_FIXED");
        drop(
            shared
                .engine
                .prepare_split_enrollment_camera(&guard, &publication)
                .unwrap(),
        );
        std::env::set_var("IRLUME_FORBID_EXTERNAL_CAMERAS", "1");
        assert!(shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .is_err());
        std::env::set_var("IRLUME_FORBID_EXTERNAL_CAMERAS", "0");
        std::env::set_var("IRLUME_CAMERA_REQUIRE_FIXED", "1");
        assert!(shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .is_err());
        assert!(recorder.calls().is_empty());
    }
}

#[test]
fn guarded_split_scope_clears_whole_proof_on_unwind_and_refuses_device_drift() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = split_choice(&fixture);
    drop(
        shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap(),
    );
    let previous = (
        shared.engine.rgb_dev.clone(),
        shared.engine.ir_dev.clone(),
        shared.engine.ir_available,
    );
    std::env::set_var("IRLUME_FORCE_NO_IR", "1");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        assert!(!request.ir_available());
        assert!(request
            .prepare_split_enrollment_camera(&guard, &publication)
            .is_err());
        request.set_devices("/dev/changed-split-rgb", "/dev/changed-split-ir");
        assert!(request.prepared_enrollment_binding().is_err());
        // Even a lost proof never manufactures an ordinary identity projection.
        assert!(matches!(
            request.current_binding(),
            storage::CameraBinding::Split(_)
        ));
        panic!("synthetic split unwind");
    }));
    assert!(result.is_err());
    assert!(shared.engine.camera_selection.is_none());
    assert_eq!(
        (
            shared.engine.rgb_dev.clone(),
            shared.engine.ir_dev.clone(),
            shared.engine.ir_available
        ),
        previous
    );
    assert!(fixture.recorder.calls().is_empty());
}

#[test]
fn guarded_split_preparation_refuses_each_original_side_and_machine_publication_drift() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = split_choice(&fixture);
    drop(
        shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap(),
    );
    let mut changed_guards = Vec::new();
    let mut changed = guard.clone();
    changed.revision += 1;
    changed_guards.push(changed);
    let mut changed = guard.clone();
    changed.supervisor_id = "a".repeat(32);
    changed_guards.push(changed);
    for rgb in [true, false] {
        for field in ["instance", "generation", "endpoint"] {
            let mut changed = guard.clone();
            let side = if rgb {
                &mut changed.rgb
            } else {
                &mut changed.ir
            };
            match field {
                "instance" => side.instance_id = "b".repeat(32),
                "generation" => side.generation += 1,
                "endpoint" => side.endpoint = "/dev/wrong-split-endpoint".into(),
                _ => unreachable!(),
            }
            changed_guards.push(changed);
        }
    }
    for changed in changed_guards {
        assert!(shared
            .engine
            .prepare_split_enrollment_camera(&changed, &publication)
            .is_err());
        assert!(shared.engine.camera_selection.is_none());
    }
    for changed in [
        irlume_common::split_publish::Published {
            generation: publication.generation + 1,
            ..publication.clone()
        },
        irlume_common::split_publish::Published {
            digest: format!("sha256:{}", "0".repeat(64)),
            ..publication.clone()
        },
    ] {
        assert!(shared
            .engine
            .prepare_split_enrollment_camera(&guard, &changed)
            .is_err());
    }
    std::fs::write(fixture.dir.join("cameras.conf"), "mode=pinned\n").unwrap();
    assert!(shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .is_err());
    assert!(fixture.recorder.calls().is_empty());
}

#[test]
fn guarded_split_preparation_refuses_all_invalid_configuration_classes_without_environment_fallback(
) {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = split_choice(&fixture);
    let config = fixture.dir.join("cameras.conf");
    let valid = std::fs::read_to_string(&config).unwrap();
    std::env::set_var("IRLUME_RGB_DEVICE", &fixture.rgb);
    std::env::set_var("IRLUME_IR_DEVICE", &fixture.ir);
    for text in [
        String::new(),
        "mode=automatic\n".into(),
        "mode=pinned\n".into(),
        valid.replace(&publication.digest, &format!("sha256:{}", "0".repeat(64))),
        valid.replace(
            &format!("split_generation={}", publication.generation),
            "split_generation=0",
        ),
        valid.replace("usb2|5", "usb2|6"),
    ] {
        std::fs::write(&config, text).unwrap();
        assert!(shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .is_err());
        assert!(shared.engine.camera_selection.is_none());
    }
    let generation = fixture
        .dir
        .join("split-pairs")
        .join(format!("{}.conf", publication.generation));
    let generation_bytes = std::fs::read(&generation).unwrap();
    std::fs::write(&config, &valid).unwrap();
    std::fs::remove_file(&generation).unwrap();
    assert!(shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .is_err());
    std::fs::create_dir(&generation).unwrap();
    assert!(shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .is_err());
    std::fs::remove_dir(&generation).unwrap();
    std::fs::write(&generation, b"not a split generation").unwrap();
    let bad_digest = format!(
        "sha256:{}",
        irlume_common::sha256_hex(b"not a split generation")
    );
    std::fs::write(&config, valid.replace(&publication.digest, &bad_digest)).unwrap();
    let malformed = irlume_common::split_publish::Published {
        generation: publication.generation,
        digest: bad_digest,
    };
    assert!(shared
        .engine
        .prepare_split_enrollment_camera(&guard, &malformed)
        .is_err());
    std::fs::write(&generation, generation_bytes).unwrap();
    std::fs::remove_file(&config).unwrap();
    std::fs::create_dir(&config).unwrap();
    assert!(shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .is_err());
    assert!(fixture.recorder.calls().is_empty());
}

#[test]
fn guarded_split_retained_scope_refuses_direct_trust_entries_before_preflight_or_storage() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = split_choice(&fixture);
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    enrollment.user = "guarded-direct".into();
    let before = serde_json::to_vec(&enrollment).unwrap();
    let path = fixture.dir.join("guarded-direct.json");
    std::fs::write(&path, &before).unwrap();
    let authorization = irlume_core::multi_camera::authz::EnrollmentAuthorization::mint(
        enrollment.user.clone(),
        irlume_core::multi_camera::authz::EnrollmentOperation::add_group(
            "new-split".into(),
            &fixture_split_binding(),
        ),
        1_000_000,
        900,
        "guarded-direct".into(),
        irlume_core::multi_camera::authz::AuthorizationVia::ElevatedPeer { uid: 0 },
    )
    .unwrap();
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    let preflight = Cell::new(0);
    assert!(request
        .enroll_profile_with_ir_preflight("guarded-direct", None, 1, |_| {
            preflight.set(preflight.get() + 1);
            true
        })
        .is_err());
    assert!(request
        .replace_enrollment_with_ir_preflight_and_diagnostics(
            "guarded-direct",
            None,
            1,
            |_| {
                preflight.set(preflight.get() + 1);
                true
            },
            &()
        )
        .is_err());
    assert!(request
        .add_camera_group_observed(
            "guarded-direct",
            None,
            1,
            &authorization,
            |_| {
                preflight.set(preflight.get() + 1);
                true
            },
            &(),
            &()
        )
        .is_err());
    assert!(request.prepare_camera_request().is_err());
    assert!(request.capture_qualification_for_request().is_err());
    let closed = "split enrollment and authentication are not enabled";
    assert!(request
        .add_scan_observed(
            "guarded-direct",
            "fixture",
            1,
            |_| {
                preflight.set(preflight.get() + 1);
                true
            },
            &()
        )
        .unwrap_err()
        .to_string()
        .contains(closed));
    for policy in [
        irlume_common::config::FaceSensorPolicy::Dual,
        irlume_common::config::FaceSensorPolicy::IrOnlyExperimental,
    ] {
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::CredentialRelease,
        ] {
            assert!(request
                .authenticate_for_in_window_with_policy(
                    "guarded-direct",
                    None,
                    purpose,
                    AuthenticationWindow::new(1000),
                    policy,
                    &()
                )
                .unwrap_err()
                .to_string()
                .contains(closed));
        }
    }
    assert!(request
        .identify_with_diagnostics(&())
        .unwrap_err()
        .to_string()
        .contains(closed));
    assert!(request
        .identify_within_with_diagnostics("guarded-direct", &())
        .unwrap_err()
        .to_string()
        .contains(closed));
    assert!(request
        .position_sample(None)
        .unwrap_err()
        .to_string()
        .contains(closed));
    assert!(request
        .position_session(None, &Position)
        .unwrap_err()
        .to_string()
        .contains(closed));
    assert_eq!(preflight.get(), 0);
    assert!(fixture.recorder.calls().is_empty());
    assert_eq!(std::fs::read(path).unwrap(), before);
    let secondary = irlume_core::multi_camera::secondary_store_path("guarded-direct");
    assert!(!secondary.exists());
    assert!(!irlume_core::multi_camera::commit::intent_path_for(&secondary).exists());
    assert!(!request.request_key().holds_key());
    assert!(request.primary_attempt.is_none() && request.secondary_attempt.is_none());
}

#[test]
fn guarded_split_real_primary_publishers_refuse_revocation_after_preparation() {
    let _env = env_guard();
    let mut shared = shared();
    for replace in [false, true] {
        let fixture = Fixture::new(true);
        let (guard, publication) = split_choice(&fixture);
        let request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        let (mut enrollment, _) = pad_matching_fixture(0.2, false);
        enrollment.user = "guarded-split-publication".into();
        enrollment.camera_binding = Some(fixture_split_binding());
        let path = fixture.dir.join("guarded-split-publication.json");
        let before = serde_json::to_vec(&enrollment).unwrap();
        std::fs::write(&path, &before).unwrap();
        enrollment.profiles[0].name = "new split profile".into();
        let healthy = |path: &std::path::Path, bytes: &[u8]| {
            request.with_prepared_camera_publication(|| {
                irlume_common::write_atomic_reporting(path, bytes, 0o600)
                    .map_err(|error| irlume_common::Error::Io(error.to_string()))
            })
        };
        if replace {
            storage::save_replacement_with_publisher(&enrollment, healthy).unwrap();
        } else {
            storage::save_with_publisher(&enrollment, healthy).unwrap();
        }
        assert_ne!(std::fs::read(&path).unwrap(), before);
        std::fs::write(&path, &before).unwrap();
        let called = Cell::new(false);
        let revoked = |path: &std::path::Path, bytes: &[u8]| {
            called.set(true);
            irlume_common::split_publish::publish_split(&[], None).unwrap();
            request.with_prepared_camera_publication(|| {
                irlume_common::write_atomic_reporting(path, bytes, 0o600)
                    .map_err(|error| irlume_common::Error::Io(error.to_string()))
            })
        };
        let result = if replace {
            storage::save_replacement_with_publisher(&enrollment, revoked)
        } else {
            storage::save_with_publisher(&enrollment, revoked)
        };
        assert!(
            called.get(),
            "real storage preparation must reach late admission"
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(fixture.recorder.calls().is_empty());
    }
}

#[test]
fn guarded_split_secondary_real_intent_is_issued_only_after_retained_machine_admission() {
    let _env = env_guard();
    let mut shared = shared();
    for revoke in [true, false] {
        let fixture = Fixture::new(true);
        let (guard, publication) = split_choice(&fixture);
        let request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        let pair = request.prepared_enrollment_binding().unwrap();
        let (mut enrollment, _) = pad_matching_fixture(0.2, false);
        enrollment.user = "guarded-split-secondary".into();
        enrollment.camera_binding = Some(storage::CameraBinding::Ordinary {
            rgb: Some("standing-primary".into()),
            ir: Some("standing-primary".into()),
        });
        let primary = serde_json::to_vec(&enrollment).unwrap();
        let primary_path = fixture.dir.join("guarded-split-secondary.json");
        std::fs::write(&primary_path, &primary).unwrap();
        let empty = irlume_core::multi_camera::SecondaryStore {
            format_version: irlume_core::multi_camera::SECONDARY_STORE_VERSION,
            owner: enrollment.user.clone(),
            generation: 0,
            primary_snapshot_sha256: String::new(),
            groups: vec![],
        };
        let group = irlume_core::multi_camera::derive_group_id(
            &empty,
            pair.rgb_identity(),
            pair.ir_identity(),
        )
        .as_str()
        .to_owned();
        let authorization = irlume_core::multi_camera::authz::EnrollmentAuthorization::mint(
            enrollment.user.clone(),
            irlume_core::multi_camera::authz::EnrollmentOperation::add_group(group.clone(), &pair),
            1_000_000,
            900,
            "guarded-secondary".into(),
            irlume_core::multi_camera::authz::AuthorizationVia::ElevatedPeer { uid: 0 },
        )
        .unwrap();
        let payload = irlume_core::multi_camera::SecondaryProfileScans {
            profile: enrollment.profiles[0].name.clone(),
            scans: enrollment.profiles[0].scans.clone(),
            ir_calibs: Default::default(),
        };
        let path = irlume_core::multi_camera::secondary_store_path(&enrollment.user);
        let intent = irlume_core::multi_camera::commit::intent_path_for(&path);
        let called = Cell::new(false);
        let result = publish_camera_group_with(
            CameraGroupPublication {
                user: &enrollment.user,
                pair: &pair,
                group_id: &group,
                profile: &payload,
                start_enr: &enrollment,
                start_primary_sha256: &irlume_common::sha256_hex(&primary),
                authorization: &authorization,
                now_unix: 1_000_300,
            },
            |prepared| {
                called.set(true);
                assert!(
                    !intent.exists(),
                    "preparation cannot authorize recover-forward"
                );
                if revoke {
                    irlume_common::split_publish::publish_split(&[], None).unwrap();
                }
                request.with_prepared_camera_publication(|| prepared.publish())
            },
            || 1_000_300,
        );
        assert!(called.get());
        assert_eq!(std::fs::read(primary_path).unwrap(), primary);
        assert!(!intent.exists());
        if revoke {
            assert!(result.is_err());
            assert!(!path.exists());
            assert!(matches!(
                irlume_core::multi_camera::commit::resolve_commit(&path),
                Ok(irlume_core::multi_camera::commit::CommitResolution::Clean)
            ));
        } else {
            assert_eq!(result.unwrap(), group);
            let store = irlume_core::multi_camera::load_secondary(&path)
                .unwrap()
                .unwrap();
            assert_eq!(store.groups[0].pair, fixture_split_binding());
            assert_eq!(store.generation, 1);
        }
        assert!(fixture.recorder.calls().is_empty());
    }
}

#[test]
fn guarded_split_replacement_keeps_visible_not_durable_receipt_without_postwrite_revalidation() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = split_choice(&fixture);
    let request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    enrollment.user = "guarded-split-visible".into();
    enrollment.camera_binding = Some(fixture_split_binding());
    let path = fixture.dir.join("guarded-split-visible.json");
    let before = serde_json::to_vec(&enrollment).unwrap();
    std::fs::write(&path, &before).unwrap();
    enrollment.profiles[0].name = "visible split replacement".into();
    let error = storage::save_replacement_with_publisher(&enrollment, |path, bytes| {
        request.with_prepared_camera_publication(|| {
            irlume_common::write_atomic_reporting(path, bytes, 0o600)
                .map_err(|error| irlume_common::Error::Io(error.to_string()))?;
            // Deliberate noncooperative fault AFTER visible publication, only in
            // the isolated temporary config. It cannot turn the receipt into
            // a claim that storage published nothing.
            std::fs::write(fixture.dir.join("cameras.conf"), "mode=pinned\n")
                .map_err(|error| irlume_common::Error::Io(error.to_string()))?;
            Ok(irlume_common::AtomicWrite::VisibleNotDurable(
                std::io::Error::other("injected directory sync failure"),
            ))
        })
    })
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("published") && error.contains("durability"),
        "{error}"
    );
    assert_ne!(std::fs::read(path).unwrap(), before);
    assert!(fixture.recorder.calls().is_empty());
}

#[test]
fn guarded_split_retained_proof_refuses_either_side_loss_and_revocation_across_diagnostic_wait() {
    use irlume_camera::lease::{acquire_split_camera_operation, CameraOperationKind};
    let _env = env_guard();
    let mut shared = shared();
    for drift in ["rgb", "ir", "authorization"] {
        let fixture = Fixture::new(true);
        let (guard, publication) = split_choice(&fixture);
        let request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        let snapshot = irlume_common::split_publish::read_camera_selection();
        let irlume_common::split_publish::SplitReadState::Valid { records, .. } = snapshot.split()
        else {
            unreachable!()
        };
        let expected = irlume_camera::connected_pairs_with_split(records)
            .split_pairs
            .remove(0)
            .lease_request();
        let held = acquire_split_camera_operation(
            &expected,
            CameraOperationKind::Diagnostics,
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        let counts = fixture.recorder.lease_counts_observer();
        let invalidate = fixture
            .recorder
            .endpoint_invalidation_observer(if drift == "ir" {
                &fixture.ir
            } else {
                &fixture.rgb
            });
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while counts().1 == 0 {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "diagnostic waiter never registered"
                    );
                    std::thread::yield_now();
                }
                if drift == "authorization" {
                    irlume_common::split_publish::publish_split(&[], None).unwrap();
                } else {
                    invalidate();
                }
                drop(held);
            });
            let waited = acquire_split_camera_operation(
                &expected,
                CameraOperationKind::Diagnostics,
                std::time::Duration::from_secs(5),
            );
            writer.join().unwrap();
            if drift == "authorization" {
                drop(waited.expect("lease does not confer machine configuration authority"));
            } else {
                assert!(waited.is_err(), "retired side acquired a diagnostic lease");
            }
        });
        assert!(request.prepared_enrollment_binding().is_err());
        let called = Cell::new(false);
        assert!(request
            .with_prepared_camera_publication(|| {
                called.set(true);
                Ok(())
            })
            .is_err());
        assert!(!called.get());
        assert!(matches!(
            request.current_binding(),
            storage::CameraBinding::Split(_)
        ));
        assert_eq!(counts(), (0, 0));
        assert!(!fixture
            .recorder
            .calls()
            .iter()
            .any(|call| matches!(call, Call::OpenRgb(_) | Call::OpenIr(_))));
    }
}

#[test]
fn guarded_split_publication_holds_config_writer_lock_and_releases_on_error_and_unwind() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = split_choice(&fixture);
    let request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    let try_writer = || {
        std::process::Command::new("flock")
            .args(["--exclusive", "--nonblock"])
            .arg(fixture.dir.join("cameras.conf.lock"))
            .arg("true")
            .status()
            .unwrap()
            .code()
    };
    assert_eq!(try_writer(), Some(0));
    for unwind in [false, true] {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            request.with_prepared_camera_publication::<()>(|| {
                assert_eq!(
                    try_writer(),
                    Some(1),
                    "config writer entered admitted publication"
                );
                if unwind {
                    panic!("synthetic persistence unwind");
                }
                Err(irlume_common::Error::Io(
                    "synthetic persistence error".into(),
                ))
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(try_writer(), Some(0));
        // Re-entry establishes release; an unwound std mutex stays poisoned
        // and must refuse, whereas a normal callback error keeps proof usable.
        if unwind {
            assert!(request.prepared_enrollment_binding().is_err());
        } else {
            assert!(request.prepared_enrollment_binding().is_ok());
        }
    }
    assert!(fixture.recorder.calls().is_empty());
}

impl Fixture {
    fn new(split: bool) -> Self {
        Self::with_fixed(split, true)
    }

    fn with_fixed(split: bool, fixed: bool) -> Self {
        let no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
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
            "IRLUME_GRACE_MS",
            "IRLUME_TCTI",
        ];
        let saved = keys
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", dir.join("private-template-keys"));
        // Publication tests may resolve a key. An explicit failed transport
        // cannot fall back to the host TPM, even outside the private runner.
        std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-test-tpm");
        for key in [
            "IRLUME_RGB_DEVICE",
            "IRLUME_IR_DEVICE",
            "IRLUME_FORCE_NO_IR",
            "IRLUME_GRACE_MS",
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
            _no_tpm: no_tpm,
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

    fn replace_camera(&self) -> Guard {
        Guard::install(&[Camera {
            topology: "/devices/fixture/replacement".into(),
            identity: "1234:0001:ordinary".into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![8],
            endpoints: vec![
                Endpoint {
                    path: self.rgb.clone(),
                    formats: vec![*b"YUYV"],
                },
                Endpoint {
                    path: self.ir.clone(),
                    formats: vec![*b"GREY"],
                },
            ],
        }])
        .unwrap()
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

fn enrollment_choice(fixture: &Fixture) -> irlume_common::live_camera::EnrollmentCameraChoice {
    let inventory = irlume_camera::camera_inventory_snapshot();
    let candidate = inventory
        .candidates
        .iter()
        .find(|candidate| candidate.endpoint_paths.contains(&fixture.rgb))
        .unwrap()
        .clone();
    irlume_common::live_camera::EnrollmentCameraChoice {
        rgb: fixture.rgb.clone(),
        ir: fixture.ir.clone(),
        expected: irlume_common::live_camera::CameraSelection {
            supervisor_id: inventory.supervisor_id.unwrap(),
            candidate,
        },
    }
}

#[test]
fn operation_choice_engine_captures_chosen_pair_and_restores_on_error_and_unwind() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let choice = enrollment_choice(&fixture);
    let previous = (
        shared.engine.rgb_dev.clone(),
        shared.engine.ir_dev.clone(),
        shared.engine.ir_available,
    );
    {
        let mut request = shared.engine.prepare_enrollment_camera(&choice).unwrap();
        assert!(request
            .enroll_profile_observed(
                "operation-fixture",
                None,
                1,
                |_| true,
                &(),
                &StopAfterOpens(Cell::new(0))
            )
            .is_err());
    }
    assert!(fixture
        .recorder
        .calls()
        .contains(&Call::OpenRgb(fixture.rgb.clone())));
    assert!(fixture
        .recorder
        .calls()
        .contains(&Call::OpenIr(fixture.ir.clone())));
    assert!(fixture.recorder.calls().iter().any(|call| matches!(
        call,
        Call::Lease {
            kind: irlume_camera::lease::CameraOperationKind::Enrollment,
            ..
        }
    )));
    assert_eq!(
        (
            &shared.engine.rgb_dev,
            &shared.engine.ir_dev,
            shared.engine.ir_available
        ),
        (&previous.0, &previous.1, previous.2)
    );
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _request = shared.engine.prepare_enrollment_camera(&choice).unwrap();
        panic!("operation choice unwind");
    }));
    assert!(unwound.is_err());
    assert!(shared.engine.camera_selection.is_none());
    assert_eq!(
        (
            &shared.engine.rgb_dev,
            &shared.engine.ir_dev,
            shared.engine.ir_available
        ),
        (&previous.0, &previous.1, previous.2)
    );
    assert!(!fixture.dir.join("cameras.conf").exists());
}

#[test]
fn operation_choice_engine_refuses_stale_guards_wrong_roles_and_invalid_configuration() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let choice = enrollment_choice(&fixture);
    // Positive scope control prevents absent inventory or a blanket refusal
    // from satisfying the negative cases below.
    drop(shared.engine.prepare_enrollment_camera(&choice).unwrap());
    let mut wrong = Vec::new();
    let mut changed = choice.clone();
    changed.expected.supervisor_id = "99999999999999999999999999999999".into();
    wrong.push(changed);
    let mut changed = choice.clone();
    changed.expected.candidate.generation += 1;
    wrong.push(changed);
    let mut changed = choice.clone();
    std::mem::swap(&mut changed.rgb, &mut changed.ir);
    wrong.push(changed);
    let mut changed = choice.clone();
    changed
        .expected
        .candidate
        .endpoint_paths
        .push("/dev/unobserved".into());
    wrong.push(changed);
    for changed in wrong {
        assert!(shared.engine.prepare_enrollment_camera(&changed).is_err());
    }
    std::fs::write(fixture.dir.join("cameras.conf"), "mode=pinned\n").unwrap();
    assert!(shared.engine.prepare_enrollment_camera(&choice).is_err());
    assert!(fixture.recorder.calls().is_empty());
}

#[test]
fn operation_choice_nonreset_enrollment_cannot_mix_a_different_primary_camera() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let choice = enrollment_choice(&fixture);
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    enrollment.user = "operation-fixture".into();
    enrollment.camera_binding = Some(irlume_core::storage::CameraBinding::Ordinary {
        rgb: Some("standing-primary".into()),
        ir: Some("standing-primary".into()),
    });
    let bytes = serde_json::to_vec(&enrollment).unwrap();
    let path = fixture.dir.join("operation-fixture.json");
    std::fs::write(&path, &bytes).unwrap();
    let mut request = shared.engine.prepare_enrollment_camera(&choice).unwrap();
    let result = request.enroll_profile_observed(
        "operation-fixture",
        Some("New".into()),
        1,
        |_| true,
        &(),
        &StopAfterOpens(Cell::new(0)),
    );
    assert!(result.is_err());
    assert!(
        fixture.recorder.calls().is_empty(),
        "changing the primary capture pair needs reset or an added group, before camera work: {:?}",
        fixture.recorder.calls()
    );
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn operation_choice_engine_refuses_loss_during_registered_enrollment_lease_wait() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let choice = enrollment_choice(&fixture);
    let mut request = shared.engine.prepare_enrollment_camera(&choice).unwrap();
    let held = irlume_camera::lease::acquire_camera_operation(
        &[fixture.rgb.as_str()],
        irlume_camera::lease::CameraOperationKind::Setup,
        std::time::Duration::ZERO,
    )
    .unwrap();
    let counts = fixture.recorder.lease_counts_observer();
    let invalidate = fixture.recorder.invalidation_observer();
    std::thread::scope(|threads| {
        let writer = threads.spawn(|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while counts().1 == 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "enrollment did not register its waiter"
                );
                std::thread::yield_now();
            }
            invalidate();
            drop(held);
        });
        assert!(request
            .enroll_profile_observed("operation-fixture", None, 1, |_| true, &(), &())
            .is_err());
        writer.join().unwrap();
    });
    assert!(!fixture
        .recorder
        .calls()
        .iter()
        .any(|call| matches!(call, Call::OpenRgb(_) | Call::OpenIr(_))));
    assert_eq!(counts(), (0, 0), "no lease or waiter may survive refusal");
}

#[test]
fn operation_choice_ancillary_helpers_refuse_a_replacement_at_the_same_paths() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let choice = enrollment_choice(&fixture);
    let mut request = shared.engine.prepare_enrollment_camera(&choice).unwrap();
    let shape = CaptureShape {
        held_sessions: true,
        attempts: 3,
        ir_only_attempts: 3,
        rgb_mean_sum: 30.0,
        consecutive_ir_only: 3,
    };
    // Each healthy helper reaches a real open attempt. Its error is only the
    // non-granting backend, so unconditional refusal cannot satisfy this test.
    for helper in 0..3 {
        let before = fixture.recorder.calls().len();
        match helper {
            0 => {
                assert!(request.capture_qualification_for_request().is_err());
            }
            1 => {
                assert!(request.solo_rgb_starvation_probe(shape).is_none());
            }
            _ => {
                assert!(!request.aba_check_confirms(10.0, 100.0));
            }
        }
        let calls = fixture.recorder.calls();
        assert!(
            calls[before..].contains(&Call::OpenRgb(fixture.rgb.clone())),
            "helper {helper}: {calls:?}"
        );
    }
    let replacement = fixture.replace_camera();
    assert_eq!(
        irlume_camera::camera_inventory_snapshot().state,
        irlume_common::live_camera::CameraInventoryState::Current
    );
    assert!(request.capture_qualification_for_request().is_err());
    assert!(
        replacement.calls().is_empty(),
        "qualification re-resolved stale paths"
    );
    assert!(request.solo_rgb_starvation_probe(shape).is_none());
    assert!(
        replacement.calls().is_empty(),
        "solo probe re-resolved stale paths"
    );
    assert!(!request.aba_check_confirms(10.0, 100.0));
    assert!(
        replacement.calls().is_empty(),
        "A/B/A probe re-resolved stale paths"
    );
}

#[test]
fn operation_choice_runtime_degradation_lookup_refuses_a_replacement() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let choice = enrollment_choice(&fixture);
    let mut request = shared.engine.prepare_enrollment_camera(&choice).unwrap();
    request.maybe_switch_capture_mode_from_enrolment(3, 10.0, 100.0);
    assert!(
        fixture
            .recorder
            .calls()
            .contains(&Call::OpenRgb(fixture.rgb.clone())),
        "the healthy control must reach the qualification lookup"
    );
    let replacement = fixture.replace_camera();
    request.maybe_switch_capture_mode_from_enrolment(3, 10.0, 100.0);
    assert!(
        replacement.calls().is_empty(),
        "runtime degradation refreshed the selected incarnation: {:?}",
        replacement.calls()
    );
}

#[test]
fn operation_choice_primary_publisher_refuses_loss_after_storage_preparation() {
    let _env = env_guard();
    let mut shared = shared();
    for replacing in [false, true] {
        let fixture = Fixture::new(false);
        let choice = enrollment_choice(&fixture);
        let request = shared.engine.prepare_enrollment_camera(&choice).unwrap();
        assert!(request.prepared_camera_lease().is_some());
        let (mut enrollment, _) = pad_matching_fixture(0.2, false);
        enrollment.user = "operation-publication".into();
        let path = fixture.dir.join("operation-publication.json");
        let before = serde_json::to_vec(&enrollment).unwrap();
        std::fs::write(&path, &before).unwrap();
        enrollment.profiles[0].name = "New profile".into();
        let healthy = |path: &std::path::Path, bytes: &[u8]| {
            request.with_prepared_camera_publication(|| {
                irlume_common::write_atomic_reporting(path, bytes, 0o600)
                    .map_err(|error| irlume_common::Error::Io(error.to_string()))
            })
        };
        if replacing {
            storage::save_replacement_with_publisher(&enrollment, healthy).unwrap();
        } else {
            storage::save_with_publisher(&enrollment, healthy).unwrap();
        }
        assert!(
            std::fs::read(&path).unwrap() != before,
            "healthy publication must actually replace bytes"
        );
        std::fs::write(&path, &before).unwrap();
        let called = Cell::new(false);
        let publish = |path: &std::path::Path, bytes: &[u8]| {
            called.set(true);
            fixture.recorder.invalidation_observer()();
            request.with_prepared_camera_publication(|| {
                irlume_common::write_atomic_reporting(path, bytes, 0o600)
                    .map_err(|error| irlume_common::Error::Io(error.to_string()))
            })
        };
        let result = if replacing {
            storage::save_replacement_with_publisher(&enrollment, publish)
        } else {
            storage::save_with_publisher(&enrollment, publish)
        };
        assert!(
            called.get(),
            "storage/key preparation never reached the admission boundary"
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read(path).unwrap(), before);
        assert!(fixture.recorder.calls().is_empty());
        drop(request);
    }
}

#[test]
fn operation_choice_group_refusal_after_preparation_cannot_recover_forward() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let choice = enrollment_choice(&fixture);
    let request = shared.engine.prepare_enrollment_camera(&choice).unwrap();
    assert!(request.prepared_camera_lease().is_some());
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    enrollment.user = "operation-group-publication".into();
    enrollment.camera_binding = Some(storage::CameraBinding::Ordinary {
        rgb: Some("standing-primary".into()),
        ir: Some("standing-primary".into()),
    });
    let primary = serde_json::to_vec(&enrollment).unwrap();
    let primary_path = fixture.dir.join("operation-group-publication.json");
    std::fs::write(&primary_path, &primary).unwrap();
    let pair = irlume_core::multi_camera::GroupPair::Ordinary {
        rgb: Some("1234:0001:ordinary".into()),
        ir: Some("1234:0001:ordinary".into()),
    };
    let authorization = irlume_core::multi_camera::authz::EnrollmentAuthorization::mint(
        enrollment.user.clone(),
        irlume_core::multi_camera::authz::EnrollmentOperation::add_group(
            "cam-1234-0001-ordinary".into(),
            &pair,
        ),
        1_000_000,
        900,
        enrollment.user.clone(),
        irlume_core::multi_camera::authz::AuthorizationVia::ElevatedPeer { uid: 0 },
    )
    .unwrap();
    let profile = irlume_core::multi_camera::SecondaryProfileScans {
        profile: enrollment.profiles[0].name.clone(),
        scans: enrollment.profiles[0].scans.clone(),
        ir_calibs: Default::default(),
    };
    let path = irlume_core::multi_camera::secondary_store_path(&enrollment.user);
    let intent = irlume_core::multi_camera::commit::intent_path_for(&path);
    let called = Cell::new(false);
    let result = publish_camera_group_with(
        CameraGroupPublication {
            user: &enrollment.user,
            pair: &pair,
            group_id: "cam-1234-0001-ordinary",
            profile: &profile,
            start_enr: &enrollment,
            start_primary_sha256: &irlume_common::sha256_hex(&primary),
            authorization: &authorization,
            now_unix: 1_000_300,
        },
        |prepared| {
            called.set(true);
            assert!(
                !intent.exists(),
                "preparation already authorized recover-forward"
            );
            fixture.recorder.invalidation_observer()();
            request.with_prepared_camera_publication(|| {
                prepared
                    .publish()
                    .map_err(|error| irlume_common::Error::Protocol(error.to_string()))
            })
        },
        || 1_000_300,
    );
    assert!(
        called.get(),
        "the real group preparation must precede this injected loss"
    );
    assert!(result.is_err());
    assert!(!path.exists() && !intent.exists());
    assert!(matches!(
        irlume_core::multi_camera::commit::resolve_commit(&path),
        Ok(irlume_core::multi_camera::commit::CommitResolution::Clean)
    ));
    assert_eq!(std::fs::read(primary_path).unwrap(), primary);
    assert!(fixture.recorder.calls().is_empty());
    drop(request);
    let _replacement = fixture.replace_camera();
    let current = enrollment_choice(&fixture);
    let request = shared.engine.prepare_enrollment_camera(&current).unwrap();
    let published = publish_camera_group_with(
        CameraGroupPublication {
            user: &enrollment.user,
            pair: &pair,
            group_id: "cam-1234-0001-ordinary",
            profile: &profile,
            start_enr: &enrollment,
            start_primary_sha256: &irlume_common::sha256_hex(&primary),
            authorization: &authorization,
            now_unix: 1_000_300,
        },
        |prepared| {
            request.with_prepared_camera_publication(|| {
                prepared
                    .publish()
                    .map_err(|error| irlume_common::Error::Protocol(error.to_string()))
            })
        },
        || 1_000_300,
    )
    .unwrap();
    assert_eq!(published, "cam-1234-0001-ordinary");
    assert_eq!(
        irlume_core::multi_camera::load_secondary(&path)
            .unwrap()
            .unwrap()
            .generation,
        1
    );
    assert!(!intent.exists());
}

/// A wording contract on the shared ordinary-path refusal, not an execution
/// test of split activation.
///
/// This asserts properties of one constant. It never installs or enables the
/// activation predicate, never admits a split trust entry and never reaches a
/// camera, an engine or storage, so it says nothing about what a build with
/// production activation would do at runtime. The admitted-state invariant is
/// covered elsewhere, by
/// `pinned_split_routes_only_its_key_with_no_legacy_or_ordinary_fallback`,
/// which admits split authentication trust and shows an ordinary preparation
/// refusing on a saved selection before any camera work.
///
/// What this pins is that the sentence stays true once activation is admitted:
/// it must describe the ordinary path rather than the predicate, and the clause
/// it carries must name the split-enrollment entry point without presenting
/// that command as a remedy for every refused operation.
#[test]
fn ordinary_split_refusal_wording_is_activation_independent() {
    let text = crate::request_preparation::ORDINARY_PATH_SPLIT_REFUSAL;
    assert!(text.contains("ordinary camera path"), "{text}");
    assert!(text.contains("never opens a split camera pair"), "{text}");
    assert!(
        text.contains("explicit split enrollment uses `irlume enroll --split-camera-choice`"),
        "the split-enrollment entry point must be named: {text}"
    );
    for remedy in ["identify", "add-scan", "positioning", "remedy", "instead"] {
        assert!(
            !text.contains(remedy),
            "the shared sentence must not offer {remedy} as a remedy: {text}"
        );
    }
    for predicate in ["not enabled", "activation", "disabled", "is closed"] {
        assert!(
            !text.contains(predicate),
            "an ordinary refusal may not depend on the activation predicate ({predicate}): {text}"
        );
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
    assert!(result.unwrap_err().to_string().contains(
        "this request uses the ordinary camera path, which never opens a split camera pair"
    ));
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
    let ordinary =
        "this request uses the ordinary camera path, which never opens a split camera pair";
    let mut refusals = Vec::new();
    let mut authentication_refusals = Vec::new();
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
            authentication_refusals.push(
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
    assert_eq!(refusals.len(), 7);
    assert_eq!(authentication_refusals.len(), 4);
    for refusal in refusals {
        assert!(refusal.contains(ordinary), "{refusal}");
        assert!(
            !refusal.contains("split enrollment and authentication are not enabled"),
            "an ordinary refusal must not blame the closed predicate: {refusal}"
        );
    }
    for refusal in authentication_refusals {
        assert!(
            refusal.contains("split enrollment and authentication are not enabled"),
            "account-routed authentication must name its activation gate: {refusal}"
        );
        assert!(!refusal.contains(ordinary), "{refusal}");
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
fn automatic_account_primary_is_selected_instead_of_standing_pair_before_open() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let chosen_rgb = "/dev/automatic-chosen-rgb";
    let chosen_ir = "/dev/automatic-chosen-ir";
    let camera = |topology: &str, identity: &str, port, rgb: &str, ir: &str| Camera {
        topology: topology.into(),
        identity: identity.into(),
        fixed: true,
        controller: "0000:00:14.0".into(),
        domain: irlume_common::split_key::SplitDomain::Usb2,
        ports: vec![port],
        endpoints: vec![
            Endpoint {
                path: rgb.into(),
                formats: vec![*b"YUYV"],
            },
            Endpoint {
                path: ir.into(),
                formats: vec![*b"GREY"],
            },
        ],
    };
    let recorder = Guard::install(&[
        camera(
            "/devices/auto-standing",
            "1234:0001:ordinary",
            8,
            &fixture.rgb,
            &fixture.ir,
        ),
        camera(
            "/devices/auto-chosen",
            "1234:0002:chosen",
            5,
            chosen_rgb,
            chosen_ir,
        ),
    ])
    .unwrap();
    let devices = Devices::new(&mut shared.engine, &fixture);
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    enrollment.user = "request-fixture".into();
    enrollment.camera_binding = Some(CameraBinding::Ordinary {
        rgb: Some("1234:0002:chosen".into()),
        ir: Some("1234:0002:chosen".into()),
    });
    enrollment.profiles[0].scans[0].ir = Some(vec![0.0; devices.engine.ir_dim()]);
    enrollment.profiles[0].scans[0].ir_space = Some(devices.engine.ir_space().into());
    std::fs::write(
        fixture.dir.join("request-fixture.json"),
        serde_json::to_vec(&enrollment).unwrap(),
    )
    .unwrap();
    // A read-only load must not create the account lock. Seed it through the
    // normal plaintext loader before checking positive account readiness.
    let missing_lock = devices.engine.ir_only_preflight_details("request-fixture");
    assert_eq!(
        missing_lock.readiness,
        irlume_common::IrOnlyReadiness::EnrollmentUnavailable
    );
    assert!(!fixture.dir.join("private-template-keys").exists());
    assert!(irlume_core::storage::load_snapshot("request-fixture")
        .unwrap()
        .is_some());
    let readiness = devices.engine.ir_only_preflight_details("request-fixture");
    assert_eq!(
        readiness.readiness,
        irlume_common::IrOnlyReadiness::TargetUnavailable
    );
    assert_eq!(
        readiness.target_issue,
        Some(irlume_common::IrTargetIssue::Unavailable)
    );
    assert_eq!(
        devices.engine.rgb_device(),
        fixture.rgb,
        "readiness mutated standing pair"
    );
    assert!(recorder.calls().is_empty());
    let window = AuthenticationWindow::new(2000);
    let mut admitted = 0;
    let _result = devices
        .engine
        .authenticate_for_in_window_with_policy_preparing_delivering(
            "request-fixture",
            None,
            AuthenticationPurpose::Verify,
            window,
            irlume_common::config::FaceSensorPolicy::Dual,
            &(),
            &mut |engine, final_window| {
                admitted += 1;
                assert_eq!(engine.rgb_device(), chosen_rgb);
                assert_eq!(engine.ir_device(), chosen_ir);
                assert_eq!(final_window.origin(), window.origin());
                assert!(final_window.deadline <= window.deadline);
                assert_eq!(
                    engine.authentication_deadline,
                    final_window.capture_deadline()
                );
                assert!(
                    recorder.calls().is_empty(),
                    "admission must precede lease/open"
                );
                Ok(())
            },
            &mut |_, _| {},
        );
    assert_eq!(admitted, 1);
    let calls = recorder.calls();
    assert!(
        calls.contains(&Call::OpenRgb(chosen_rgb.into())),
        "eligible enrolled primary not chosen before open: {calls:?}"
    );
    assert!(
        !calls.contains(&Call::OpenRgb(fixture.rgb.clone())),
        "standing unenrolled pair opened: {calls:?}"
    );
    let before = recorder.calls();
    let refusal = devices
        .engine
        .authenticate_for_in_window_with_policy_preparing_delivering(
            "request-fixture",
            None,
            AuthenticationPurpose::Verify,
            AuthenticationWindow::new(2000),
            irlume_common::config::FaceSensorPolicy::Dual,
            &(),
            &mut |engine, _| {
                assert_eq!(engine.rgb_device(), chosen_rgb);
                Err(irlume_common::Error::Policy("selected tier refused".into()))
            },
            &mut |_, _| panic!("preparation refusal cannot deliver a grant"),
        )
        .unwrap_err();
    assert!(matches!(refusal, irlume_common::Error::Policy(_)));
    assert_eq!(
        recorder.calls(),
        before,
        "late refusal reached camera lease/open"
    );
    assert!(devices.engine.camera_selection.is_none());
    assert_eq!(
        devices.engine.rgb_device(),
        chosen_rgb,
        "automatic standing choice retained"
    );
    devices.engine.set_devices(&fixture.rgb, &fixture.ir);
    devices.engine.ir_available = true;
    let outcome = devices
        .engine
        .authenticate_for_in_window_with_policy(
            "request-fixture",
            None,
            AuthenticationPurpose::Verify,
            AuthenticationWindow::new(2000),
            irlume_common::config::FaceSensorPolicy::IrOnlyExperimental,
            &(),
        )
        .unwrap();
    assert!(!outcome.granted);
    assert_eq!(
        devices.engine.rgb_device(),
        chosen_rgb,
        "IR authentication did not choose enrolled pair"
    );
    assert_eq!(
        recorder.calls(),
        before,
        "missing physical IR target reached capture"
    );

    // With the complete primary disconnected, resolve the actual eligible
    // secondary view and retain its generation through pre-open admission.
    use irlume_core::multi_camera::{
        CameraGroupId, GroupPair, SecondaryGroup, SecondaryProfileScans, SecondaryStore,
        SECONDARY_STORE_VERSION,
    };
    enrollment.camera_binding = Some(CameraBinding::Ordinary {
        rgb: Some("1234:0003:disconnected".into()),
        ir: Some("1234:0003:disconnected".into()),
    });
    let bytes = serde_json::to_vec(&enrollment).unwrap();
    let primary_path = fixture.dir.join("request-fixture.json");
    std::fs::write(&primary_path, &bytes).unwrap();
    let secondary_path = irlume_core::multi_camera::secondary_store_path("request-fixture");
    let store = SecondaryStore {
        format_version: SECONDARY_STORE_VERSION,
        owner: "request-fixture".into(),
        generation: 5,
        primary_snapshot_sha256: irlume_common::sha256_hex(&bytes),
        groups: vec![SecondaryGroup {
            id: CameraGroupId::new("chosen".into()).unwrap(),
            pair: GroupPair::Ordinary {
                rgb: Some("1234:0002:chosen".into()),
                ir: Some("1234:0002:chosen".into()),
            },
            profiles: vec![SecondaryProfileScans {
                profile: enrollment.profiles[0].name.clone(),
                scans: enrollment.profiles[0].scans.clone(),
                ir_calibs: Default::default(),
            }],
        }],
    };
    std::fs::create_dir_all(secondary_path.parent().unwrap()).unwrap();
    irlume_core::multi_camera::save_secondary_resolved(&secondary_path, &store, |_| Ok(None))
        .unwrap();
    let mut secondary_admitted = false;
    let error = devices
        .engine
        .authenticate_for_in_window_with_policy_preparing_delivering(
            "request-fixture",
            None,
            AuthenticationPurpose::Verify,
            AuthenticationWindow::new(2000),
            irlume_common::config::FaceSensorPolicy::Dual,
            &(),
            &mut |engine, _| {
                secondary_admitted = true;
                let pinned = engine
                    .secondary_attempt
                    .as_ref()
                    .expect("chosen secondary pin");
                assert_eq!(pinned.store_index(), 0);
                assert_eq!(pinned.pinned().secondary_generation, 5);
                assert_eq!(engine.rgb_device(), chosen_rgb);
                Err(irlume_common::Error::Policy(
                    "stop after secondary preparation".into(),
                ))
            },
            &mut |_, _| panic!("preparation refusal cannot deliver"),
        )
        .unwrap_err();
    assert!(matches!(error, irlume_common::Error::Policy(_)) && secondary_admitted);
    assert_eq!(recorder.calls(), before);
    assert!(
        devices.engine.secondary_attempt.is_none(),
        "request-local secondary authority survived refusal"
    );
    assert!(
        devices.engine.primary_attempt.is_none(),
        "request-local primary authority survived refusal"
    );
    for invalid in [false, true] {
        if invalid {
            std::fs::write(&secondary_path, b"malformed secondary").unwrap();
        } else {
            let mut drifted = bytes.clone();
            drifted.push(b' ');
            std::fs::write(&primary_path, drifted).unwrap();
        }
        let outcome = devices
            .engine
            .authenticate_for_in_window_with_policy_preparing_delivering(
                "request-fixture",
                None,
                AuthenticationPurpose::Verify,
                AuthenticationWindow::new(2000),
                irlume_common::config::FaceSensorPolicy::Dual,
                &(),
                &mut |_, _| panic!("inactive/unreadable selection reached camera admission"),
                &mut |_, _| {},
            )
            .unwrap();
        assert!(!outcome.granted);
        assert_eq!(recorder.calls(), before);
    }
    std::fs::write(&primary_path, &bytes).unwrap();
    irlume_core::multi_camera::save_secondary_resolved(&secondary_path, &store, |_| Ok(None))
        .unwrap();
    for (cap, override_ms, expected) in [
        (0, None, 0),
        (2000, Some("60000"), 2000),
        (30000, None, GRACE_WINDOW_MS),
    ] {
        if let Some(value) = override_ms {
            std::env::set_var("IRLUME_GRACE_MS", value);
        } else {
            std::env::remove_var("IRLUME_GRACE_MS");
        }
        let window = AuthenticationWindow::new(cap);
        let mut reached = false;
        let error = devices
            .engine
            .authenticate_for_in_window_with_policy_preparing_delivering(
                "request-fixture",
                None,
                AuthenticationPurpose::Verify,
                window,
                irlume_common::config::FaceSensorPolicy::Dual,
                &(),
                &mut |engine, final_window| {
                    reached = true;
                    assert_eq!(final_window.origin(), window.origin());
                    assert_eq!(final_window.milliseconds, expected);
                    assert_eq!(
                        engine.authentication_deadline,
                        final_window.capture_deadline()
                    );
                    Err(irlume_common::Error::Policy(
                        "window observed before capture".into(),
                    ))
                },
                &mut |_, _| {},
            )
            .unwrap_err();
        assert!(matches!(error, irlume_common::Error::Policy(_)) && reached);
        assert_eq!(recorder.calls(), before);
    }
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = devices
            .engine
            .authenticate_for_in_window_with_policy_preparing_delivering(
                "request-fixture",
                None,
                AuthenticationPurpose::Verify,
                AuthenticationWindow::new(2000),
                irlume_common::config::FaceSensorPolicy::Dual,
                &(),
                &mut |_, _| panic!("test admission unwind"),
                &mut |_, _| {},
            );
    }));
    assert!(unwound.is_err());
    assert!(devices.engine.camera_selection.is_none());
    assert!(devices.engine.secondary_attempt.is_none() && devices.engine.primary_attempt.is_none());
    assert!(devices.engine.authentication_deadline.is_none());
    assert_eq!(recorder.calls(), before);
    // Revocation after successful preparation admission must precede opens.
    for during_wait in [false, true] {
        let stored = std::fs::read(&secondary_path).unwrap();
        let calls_before = recorder.calls();
        let outcome = if during_wait {
            let held = irlume_camera::lease::acquire_camera_operation(
                &[chosen_ir],
                irlume_camera::lease::CameraOperationKind::Setup,
                std::time::Duration::ZERO,
            )
            .unwrap();
            let counts = recorder.lease_counts_observer();
            let path = secondary_path.clone();
            std::thread::scope(|threads| {
                let writer = threads.spawn(move || {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                    while counts().1 == 0 {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "authentication never registered lease wait"
                        );
                        std::thread::yield_now();
                    }
                    std::fs::remove_file(path).unwrap();
                    drop(held);
                });
                let result = devices.engine.authenticate_for_in_window_with_policy(
                    "request-fixture",
                    None,
                    AuthenticationPurpose::Verify,
                    AuthenticationWindow::new(5000),
                    irlume_common::config::FaceSensorPolicy::Dual,
                    &(),
                );
                writer.join().unwrap();
                result
            })
        } else {
            devices
                .engine
                .authenticate_for_in_window_with_policy_preparing_delivering(
                    "request-fixture",
                    None,
                    AuthenticationPurpose::Verify,
                    AuthenticationWindow::new(2000),
                    irlume_common::config::FaceSensorPolicy::Dual,
                    &(),
                    &mut |_, _| {
                        std::fs::remove_file(&secondary_path).unwrap();
                        Ok(())
                    },
                    &mut |_, _| {},
                )
        };
        let calls = recorder.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, Call::OpenRgb(_) | Call::OpenIr(_)))
                .count(),
            calls_before
                .iter()
                .filter(|call| matches!(call, Call::OpenRgb(_) | Call::OpenIr(_)))
                .count(),
            "store revocation reached camera open (wait={during_wait}): {calls:?}"
        );
        assert!(!outcome.unwrap().granted);
        std::fs::write(&secondary_path, stored).unwrap();
    }
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
fn ordinary_override_refuses_split_primary_with_ordinary_reason_before_camera() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let devices = Devices::new(&mut shared.engine, &fixture);
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    enrollment.user = "request-fixture".into();
    enrollment.camera_binding = Some(fixture_split_binding());
    let bytes = serde_json::to_vec(&enrollment).unwrap();
    let path = fixture.dir.join("request-fixture.json");
    std::fs::write(&path, &bytes).unwrap();
    // A proven ordinary override bypasses automatic account ranking, so the
    // actual authentication call must still refuse the split primary itself.
    std::env::set_var("IRLUME_RGB_DEVICE", &fixture.rgb);
    std::env::set_var("IRLUME_IR_DEVICE", &fixture.ir);
    for admitted in [false, true] {
        let _admitted = admitted.then(|| {
            fixture
                .recorder
                .admit_split_trust(&[irlume_camera::lease::CameraOperationKind::Authentication])
        });
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::CredentialRelease,
        ] {
            let outcome = devices
                .engine
                .authenticate_for_in_window_with_policy(
                    "request-fixture",
                    None,
                    purpose,
                    AuthenticationWindow::new(2000),
                    irlume_common::config::FaceSensorPolicy::Dual,
                    &(),
                )
                .unwrap();
            assert!(!outcome.granted, "admitted={admitted} {purpose:?}");
            assert_eq!(outcome.kind, OutcomeKind::OtherDeny);
            assert_eq!(outcome.cause, Some(OutcomeCause::NotEnrolledOnThisCamera));
            assert!(
                outcome.reason.contains(
                    "this request uses the ordinary camera path, which never opens a split camera pair"
                ),
                "admitted={admitted} {purpose:?}: {}",
                outcome.reason
            );
            assert!(fixture.recorder.calls().is_empty());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert!(devices.engine.camera_selection.is_none());
        }
    }
}

#[test]
fn automatic_ir_without_candidates_preserves_target_guard_before_protected_load() {
    use irlume_common::diagnostics::{DiagnosticSink, TraceEventKind, TraceStage};
    struct NoProtectedLoad;
    impl DiagnosticSink for NoProtectedLoad {
        fn emit_trace(&self, event: TraceEventKind) {
            assert!(
                !matches!(
                    event,
                    TraceEventKind::StageTiming {
                        stage: TraceStage::EnrollmentLoad,
                        ..
                    }
                ),
                "unconfigured IR target reached protected loading"
            );
        }
    }
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let _empty = Guard::install(&[]).unwrap();
    let devices = Devices::new(&mut shared.engine, &fixture);
    for config in ["", "mode=automatic\n"] {
        std::fs::write(fixture.dir.join("cameras.conf"), config).unwrap();
        for enrolled in [false, true] {
            if enrolled {
                let (mut enrollment, _) = pad_matching_fixture(0.2, false);
                enrollment.user = "request-fixture".into();
                std::fs::write(
                    fixture.dir.join("request-fixture.json"),
                    serde_json::to_vec(&enrollment).unwrap(),
                )
                .unwrap();
            }
            let readiness = devices.engine.ir_only_preflight_details("request-fixture");
            assert_eq!(
                readiness.target_issue,
                Some(irlume_common::IrTargetIssue::Unconfigured)
            );
            let outcome = devices
                .engine
                .authenticate_for_in_window_with_policy(
                    "request-fixture",
                    None,
                    AuthenticationPurpose::Verify,
                    AuthenticationWindow::new(2000),
                    irlume_common::config::FaceSensorPolicy::IrOnlyExperimental,
                    &NoProtectedLoad,
                )
                .unwrap();
            assert!(!outcome.granted);
            assert_eq!(
                outcome.cause,
                Some(irlume_common::OutcomeCause::Configuration)
            );
            assert!(!fixture.dir.join("private-template-keys").exists());
            if enrolled {
                std::fs::remove_file(fixture.dir.join("request-fixture.json")).unwrap();
            }
        }
    }
    assert!(fixture.recorder.calls().is_empty());
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
