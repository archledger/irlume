// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

mod publication {
    use super::*;

    #[test]
    fn split_whole_nonreset_merge_keeps_old_scans_and_next_authenticate_routes() {
        let _guard = env_lock();
        let mut engine = engine();
        let _environment = Environment::clear();
        let _no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let user = known_user();
        for pinned in [false, true] {
            let sb = private_sandbox("split-whole-merge");
            engine.set_devices(NO_RGB, NO_IR);
            let camera = camera_fixture();
            authorize(pinned);
            let original = primary(&user, &engine, CameraBinding::Split(key()));
            let original_scan = original.profiles[0].scans[0].clone();
            write_enrollment(&sb.dir, &original);
            {
                let _admit = camera.admit_split_trust(&[CameraOperationKind::Enrollment]);
                let samples = script(CameraOperationKind::Enrollment, 10, |_| {
                    Ok(sample(1.0, 1.0, 2999, true))
                });
                let mut request = enrollment_request(&user, false, false);
                let Request::EnrollSplitOn { profile, .. } = &mut request else {
                    unreachable!()
                };
                *profile = None; // Real automatic same-person merge, not duplicate-name refusal.
                let response = delivered(worker_reply(request, &mut engine));
                assert!(matches!(
                    response,
                    Response::Enrolled {
                        created: false,
                        added: 2,
                        total: 3,
                        ..
                    }
                ));
                assert_eq!(samples.calls(), 10);
                let stored = irlume_core::storage::load_unmoved(&user).unwrap().unwrap();
                assert_eq!(stored.camera_binding, Some(CameraBinding::Split(key())));
                assert_eq!(stored.profiles.len(), 1);
                assert_eq!(stored.profiles[0].name, PROFILE);
                assert_eq!(stored.profiles[0].scans.len(), 3);
                // FaceScan has no PartialEq; compare every serialized field in
                // memory without printing embeddings or calibration values.
                assert!(
                    serde_json::to_value(&stored.profiles[0].scans[0]).unwrap()
                        == serde_json::to_value(&original_scan).unwrap(),
                    "merge changed the original synthetic scan"
                );
            }
            let _admit = camera.admit_split_trust(&[CameraOperationKind::Authentication]);
            let samples = script(CameraOperationKind::Authentication, 5, |_| {
                Ok(sample(0.5, 0.8, 3000, true))
            });
            assert_granted(&delivered(worker_reply(authenticate(&user), &mut engine)));
            assert_reset(&sb, &user);
            assert_eq!(samples.calls(), 5);
            assert_no_intent(&user);
            assert_eq!(camera.lease_counts_observer()(), (0, 0));
        }
    }

    #[test]
    fn split_whole_final_enrollment_sample_drift_publishes_nothing() {
        let _guard = env_lock();
        let mut engine = engine();
        let _environment = Environment::clear();
        let _no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let user = known_user();
        for pinned in [false, true] {
            for (reset, add_group) in [(false, false), (true, false), (false, true)] {
                for change in ["revoked", "reselected", "rgb lost", "ir lost"] {
                    let sb = private_sandbox("split-whole-publication-drift");
                    engine.set_devices(NO_RGB, NO_IR);
                    let camera = camera_fixture();
                    authorize(pinned);
                    let old = primary(
                        &user,
                        &engine,
                        if reset || add_group {
                            absent_binding()
                        } else {
                            CameraBinding::Split(key())
                        },
                    );
                    write_enrollment(&sb.dir, &old);
                    let before = std::fs::read(primary_path(&sb, &user)).unwrap();
                    let _admit = camera.admit_split_trust(&[CameraOperationKind::Enrollment]);
                    let lost_rgb = camera.endpoint_invalidation_observer(RGB);
                    let lost_ir = camera.endpoint_invalidation_observer(IR);
                    let samples = script(CameraOperationKind::Enrollment, 10, move |context| {
                        if context.index == 9 {
                            match change {
                                "revoked" => {
                                    irlume_common::split_publish::publish_split(&[], None).unwrap();
                                }
                                "reselected" => authorize(!pinned),
                                "rgb lost" => lost_rgb(),
                                _ => lost_ir(),
                            }
                        }
                        Ok(sample(1.0, 1.0, 3000, true))
                    });
                    let mut request = enrollment_request(&user, reset, add_group);
                    if !reset && !add_group {
                        let Request::EnrollSplitOn { profile, .. } = &mut request else {
                            unreachable!()
                        };
                        *profile = None;
                    }
                    let observer = UnsealObserver::install().unwrap();
                    let response = delivered(worker_reply(request, &mut engine));
                    assert!(
                        matches!(response, Response::Error(_)),
                        "late publication must refuse"
                    );
                    assert_eq!(
                        samples.calls(),
                        10,
                        "reached final assessed scan before publication"
                    );
                    assert_eq!(std::fs::read(primary_path(&sb, &user)).unwrap(), before);
                    assert!(!irlume_core::multi_camera::secondary_store_path(&user).exists());
                    assert_no_intent(&user);
                    assert!(!sb.dir.join("capture-qualifications").exists());
                    assert_eq!((observer.calls(), observer.successes()), (0, 0));
                    assert_eq!(camera.lease_counts_observer()(), (0, 0));
                    assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
                }
            }
        }
    }

    #[test]
    #[ignore = "requires disposable swtpm with explicit IRLUME_TCTI and private devices; never host TPM"]
    fn tpm_split_whole_reset_preserves_template_key_and_next_authenticate_routes() {
        let _guard = env_lock();
        let transport = credentials::swtpm_transport();
        let mut engine = engine();
        let _environment = Environment::clear();
        std::env::set_var("IRLUME_TCTI", transport);
        let _present = irlume_core::template_key::test_support::TpmPresence::force(true);
        let user = known_user();
        for pinned in [false, true] {
            let sb = private_sandbox("split-whole-encrypted-reset");
            engine.set_devices(NO_RGB, NO_IR);
            let camera = camera_fixture();
            authorize(pinned);
            let mut old = primary(&user, &engine, absent_binding());
            old.profiles[0].name = "Old Encrypted Profile".into();
            plant_enrollment(&sb, &user, &old, false, true);
            let before_key = irlume_core::template_key::load_key(&user).unwrap();
            {
                let _admit = camera.admit_split_trust(&[CameraOperationKind::Enrollment]);
                let samples = script(CameraOperationKind::Enrollment, 10, |_| {
                    Ok(sample(1.0, 1.0, 3000, true))
                });
                let response = delivered(worker_reply(
                    enrollment_request(&user, true, false),
                    &mut engine,
                ));
                assert!(matches!(
                    response,
                    Response::Enrolled {
                        created: true,
                        added: 2,
                        total: 2,
                        ..
                    }
                ));
                assert_eq!(samples.calls(), 10);
            }
            let after_key = irlume_core::template_key::load_key(&user).unwrap();
            // Compare without printing key bytes on assertion failure. A policy
            // reseal is allowed; replacing the encryption key is not.
            assert!(
                before_key.as_slice() == after_key.as_slice(),
                "reset replaced its retained template key"
            );
            let stored = irlume_core::storage::load_unmoved(&user).unwrap().unwrap();
            assert_eq!(stored.camera_binding, Some(CameraBinding::Split(key())));
            assert_eq!(stored.profiles.len(), 1);
            assert_eq!(stored.profiles[0].name, PROFILE);
            assert_eq!(stored.profiles[0].scans.len(), 2);
            let _admit = camera.admit_split_trust(&[CameraOperationKind::Authentication]);
            let samples = script(CameraOperationKind::Authentication, 5, |_| {
                Ok(sample(0.5, 0.8, 3001, true))
            });
            assert_granted(&delivered(worker_reply(authenticate(&user), &mut engine)));
            assert_reset(&sb, &user);
            assert_eq!(samples.calls(), 5);
            assert_eq!(camera.lease_counts_observer()(), (0, 0));
        }
    }
}
