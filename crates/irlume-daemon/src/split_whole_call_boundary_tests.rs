// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

mod boundaries {
    use super::*;

    // Empty and consumed-last-item controls from PR #1038, adapted to the
    // retained assessment seam. A guard survives multiple worker calls; failed
    // samples cannot become absent fixtures, physical capture or reused evidence.
    fn finite_script(kind: CameraOperationKind, available: usize) -> AssessmentGuard {
        let mut remaining = available;
        script(kind, available + 2, move |_| {
            if remaining == 0 {
                return Err(irlume_common::Error::Hardware(
                    "assessment script exhausted".into(),
                ));
            }
            remaining -= 1;
            // A complete authentication batch denies IR identity. Enrollment
            // still captures real scan-loop outputs from these assessed inputs.
            Ok(sample(0.9, 0.4, 3000, true))
        })
    }

    fn assert_exhausted(reply: WorkerReply) {
        assert!(reply.completion.is_none());
        let response = delivered(reply);
        assert!(
            matches!(&response, Response::Error(reason) if reason.contains("assessment script exhausted")),
            "installed exhaustion must survive the whole worker call: {response:?}"
        );
    }

    #[test]
    fn split_whole_authentication_empty_and_exhausted_scripts_never_fall_through() {
        let _guard = env_lock();
        let mut engine = engine();
        let _environment = Environment::clear();
        let _no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let user = known_user();
        for pinned in [false, true] {
            for secondary in [false, true] {
                for entry in ENTRIES {
                    for available in [0, 1, 5] {
                        let sb = private_sandbox("split-whole-auth-exhaustion");
                        engine.set_devices(NO_RGB, NO_IR);
                        let camera = camera_fixture();
                        let _admit =
                            camera.admit_split_trust(&[CameraOperationKind::Authentication]);
                        authorize(pinned);
                        plant_account(&sb, &user, &engine, secondary);
                        plant_fake_envelope(&user);
                        let envelope = irlume_core::keyring::envelope_path(&user);
                        let sealed = std::fs::read(&envelope).unwrap();
                        let before = std::fs::read(primary_path(&sb, &user)).unwrap();
                        let secondary_path = irlume_core::multi_camera::secondary_store_path(&user);
                        let before_secondary = std::fs::read(&secondary_path).ok();
                        let observer = UnsealObserver::install().unwrap();
                        let samples = finite_script(CameraOperationKind::Authentication, available);
                        let first = worker_reply(entry.request(&user), &mut engine);
                        if available == 5 {
                            assert!(first.completion.is_none());
                            let response = delivered(first);
                            match (&entry, &response) {
                                (Entry::Authenticate, Response::AuthResult {
                                    granted: false, live: true, reason, ..
                                }) => assert!(reason.contains("requires an IR-verified match")),
                                // UnsealPassword preserves the older PAM's
                                // Error reply shape for a real face denial.
                                (Entry::UnsealPassword, Response::Error(reason)) => {
                                    assert!(reason.starts_with("face not granted: "));
                                    assert!(reason.contains("requires an IR-verified match"));
                                }
                                _ => panic!("the last full batch denies IR identity: {response:?}"),
                            }
                        } else {
                            assert_exhausted(first);
                        }
                        assert_eq!(samples.calls(), available + usize::from(available < 5));
                        assert_eq!(retry(&sb, &user)["budget"]["unsuccessful_requests"], 1);
                        // Same installed guard, fresh request: no samples remain.
                        assert_exhausted(worker_reply(entry.request(&user), &mut engine));
                        assert_eq!(samples.calls(), available + 1 + usize::from(available < 5));
                        assert_eq!(retry(&sb, &user)["budget"]["unsuccessful_requests"], 2);
                        assert_eq!((observer.calls(), observer.successes()), (0, 0));
                        assert_eq!(std::fs::read(&envelope).unwrap(), sealed);
                        assert_eq!(std::fs::read(primary_path(&sb, &user)).unwrap(), before);
                        assert_eq!(std::fs::read(&secondary_path).ok(), before_secondary);
                        assert_eq!(camera.calls(), vec![lease(CameraOperationKind::Authentication); 2]);
                        assert_eq!(camera.lease_counts_observer()(), (0, 0));
                        assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
                    }
                }
            }
        }
    }

    #[test]
    fn split_whole_enrollment_empty_and_exhausted_scripts_publish_nothing() {
        let _guard = env_lock();
        let mut engine = engine();
        let _environment = Environment::clear();
        let _no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let user = known_user();
        for pinned in [false, true] {
            for (reset, add_group) in [(false, false), (true, false), (false, true)] {
                for available in [0, 1, 5] {
                    let sb = private_sandbox("split-whole-enroll-exhaustion");
                    engine.set_devices(NO_RGB, NO_IR);
                    let camera = camera_fixture();
                    let _admit = camera.admit_split_trust(&[CameraOperationKind::Enrollment]);
                    authorize(pinned);
                    if reset || add_group {
                        let mut old = primary(&user, &engine, absent_binding());
                        if reset {
                            old.profiles[0].name = "Old Profile".into();
                        }
                        write_enrollment(&sb.dir, &old);
                    }
                    let before = std::fs::read(primary_path(&sb, &user)).ok();
                    let config = std::fs::read(sb.dir.join("config/cameras.conf")).unwrap();
                    let samples = finite_script(CameraOperationKind::Enrollment, available);
                    for attempt in 0..2 {
                        assert_exhausted(worker_reply(
                            enrollment_request(&user, reset, add_group),
                            &mut engine,
                        ));
                        assert_eq!(samples.calls(), available + attempt + 1);
                        assert_eq!(std::fs::read(primary_path(&sb, &user)).ok(), before);
                        assert!(!irlume_core::multi_camera::secondary_store_path(&user).exists());
                        assert_no_intent(&user);
                        assert_eq!(camera.lease_counts_observer()(), (0, 0));
                        assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
                    }
                    // Five samples complete the first scan, then the second
                    // scan's exhaustion prevents even partial publication.
                    let per_attempt = if available == 5 { 2 } else { 1 };
                    assert_eq!(
                        camera.calls(),
                        vec![lease(CameraOperationKind::Enrollment); per_attempt + 1]
                    );
                    assert_eq!(std::fs::read(sb.dir.join("config/cameras.conf")).unwrap(), config);
                    assert!(!sb.dir.join("capture-qualifications").exists());
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Change {
        Revoked,
        Reselected,
        RgbLost,
        IrLost,
        PrimaryBytes,
        SecondaryBinding,
        SecondaryGeneration,
    }

    const CHANGES: [Change; 7] = [
        Change::Revoked,
        Change::Reselected,
        Change::RgbLost,
        Change::IrLost,
        Change::PrimaryBytes,
        Change::SecondaryBinding,
        Change::SecondaryGeneration,
    ];

    #[test]
    fn split_whole_final_sample_drift_refuses_without_release_or_erasing_charge() {
        let _guard = env_lock();
        let mut engine = engine();
        let _environment = Environment::clear();
        let _no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let user = known_user();
        for pinned in [false, true] {
            for secondary in [false, true] {
                for entry in ENTRIES {
                    for change in CHANGES {
                        if !secondary
                            && matches!(
                                change,
                                Change::SecondaryBinding | Change::SecondaryGeneration
                            )
                        {
                            continue;
                        }
                        let row =
                            format!("{entry:?} pin={pinned} secondary={secondary} {change:?}");
                        let sb = private_sandbox("split-whole-late-drift");
                        engine.set_devices(NO_RGB, NO_IR);
                        let camera = camera_fixture();
                        let counts = camera.lease_counts_observer();
                        let _admit =
                            camera.admit_split_trust(&[CameraOperationKind::Authentication]);
                        authorize(pinned);
                        plant_account(&sb, &user, &engine, secondary);
                        plant_fake_envelope(&user);
                        let envelope = irlume_core::keyring::envelope_path(&user);
                        let sealed = std::fs::read(&envelope).unwrap();
                        let primary = primary_path(&sb, &user);
                        let secondary_path = irlume_core::multi_camera::secondary_store_path(&user);
                        let before_primary = std::fs::read(&primary).unwrap();
                        let before_secondary = std::fs::read(&secondary_path).ok();
                        let mut changed_primary = before_primary.clone();
                        changed_primary.push(b'\n');
                        let mut changed_secondary = None;
                        if matches!(
                            change,
                            Change::SecondaryBinding | Change::SecondaryGeneration
                        ) {
                            let mut store =
                                irlume_core::multi_camera::load_secondary(&secondary_path)
                                    .unwrap()
                                    .unwrap();
                            if matches!(change, Change::SecondaryBinding) {
                                // Whole binding changes with the SAME generation.
                                store.groups[0].pair = GroupPair::Split(
                                    SplitPairKey::parse_canonical(OTHER_KEY).unwrap(),
                                );
                            } else {
                                store.generation += 1;
                            }
                            changed_secondary = Some(store);
                        }
                        let expected_secondary = changed_secondary
                            .as_ref()
                            .map(|store| serde_json::to_vec(store).unwrap());
                        let invalidate_rgb = camera.endpoint_invalidation_observer(RGB);
                        let invalidate_ir = camera.endpoint_invalidation_observer(IR);
                        let mutation_primary = primary.clone();
                        let mutation_secondary = secondary_path.clone();
                        let write_primary = changed_primary.clone();
                        let samples =
                            script(CameraOperationKind::Authentication, 5, move |context| {
                                assert_eq!(
                                    counts(),
                                    (2, 0),
                                    "mutation is under both retained leases"
                                );
                                if context.index == 4 {
                                    match change {
                                        Change::Revoked => {
                                            irlume_common::split_publish::publish_split(&[], None)
                                                .unwrap();
                                        }
                                        Change::Reselected => authorize(!pinned),
                                        Change::RgbLost => invalidate_rgb(),
                                        Change::IrLost => invalidate_ir(),
                                        Change::PrimaryBytes => {
                                            std::fs::write(&mutation_primary, &write_primary)
                                                .unwrap()
                                        }
                                        Change::SecondaryBinding | Change::SecondaryGeneration => {
                                            irlume_core::multi_camera::save_secondary(
                                                &mutation_secondary,
                                                changed_secondary.as_ref().unwrap(),
                                            )
                                            .unwrap();
                                        }
                                    }
                                }
                                Ok(sample(0.5, 0.8, 3000, true))
                            });
                        let observer = UnsealObserver::install().unwrap();
                        let response = assert_refused(
                            worker_reply(entry.request(&user), &mut engine),
                            &sb,
                            &user,
                            &observer,
                        );
                        assert_eq!(
                            samples.calls(),
                            5,
                            "{row}: reached the final otherwise-granting sample"
                        );
                        let text = serde_json::to_string(&response).unwrap();
                        match change {
                            Change::Revoked | Change::Reselected => assert!(
                                text.contains("authorization changed"),
                                "{row}: wrong boundary: {text}"
                            ),
                            Change::RgbLost | Change::IrLost => assert!(
                                text.contains("lifecycle reference is stale"),
                                "{row}: wrong boundary: {text}"
                            ),
                            Change::PrimaryBytes if !secondary => assert!(
                                text.contains("enrollment changed during authentication"),
                                "{row}: {text}"
                            ),
                            _ => assert!(text.contains("secondary grant"), "{row}: {text}"),
                        }
                        assert_eq!(
                            std::fs::read(&envelope).unwrap(),
                            sealed,
                            "{row}: sealed envelope"
                        );
                        assert_eq!(
                            std::fs::read(&primary).unwrap(),
                            if matches!(change, Change::PrimaryBytes) {
                                changed_primary
                            } else {
                                before_primary
                            },
                            "{row}: no adaptation or rollback of external drift"
                        );
                        if matches!(
                            change,
                            Change::SecondaryBinding | Change::SecondaryGeneration
                        ) {
                            let store = irlume_core::multi_camera::load_secondary(&secondary_path)
                                .unwrap()
                                .unwrap();
                            if matches!(change, Change::SecondaryBinding) {
                                assert_eq!(store.generation, 1);
                                assert_eq!(
                                    store.groups[0].pair,
                                    GroupPair::Split(
                                        SplitPairKey::parse_canonical(OTHER_KEY).unwrap()
                                    )
                                );
                            } else {
                                assert_eq!(store.generation, 2);
                            }
                            assert_eq!(
                                std::fs::read(&secondary_path).ok(),
                                expected_secondary,
                                "authentication preserves the exact external secondary rewrite"
                            );
                        } else {
                            assert_eq!(std::fs::read(&secondary_path).ok(), before_secondary);
                        }
                        assert_eq!(
                            camera.calls(),
                            vec![lease(CameraOperationKind::Authentication)],
                            "{row}"
                        );
                        assert_eq!(camera.lease_counts_observer()(), (0, 0), "{row}");
                        assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
                    }
                }
            }
        }
    }

    #[test]
    fn split_whole_complete_binding_mismatch_never_reaches_assessment_or_release() {
        let _guard = env_lock();
        let mut engine = engine();
        let _environment = Environment::clear();
        let _no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let user = known_user();
        let mut swapped = key();
        std::mem::swap(&mut swapped.rgb, &mut swapped.ir);
        let mismatches = [
            CameraBinding::Split(SplitPairKey::parse_canonical(OTHER_KEY).unwrap()),
            CameraBinding::Split(swapped),
            CameraBinding::Ordinary {
                rgb: Some("1234:0001:rgb".into()),
                ir: Some("1234:0002:ir".into()),
            },
        ];
        for pinned in [false, true] {
            for secondary in [false, true] {
                for entry in ENTRIES {
                    for binding in &mismatches {
                        let sb = private_sandbox("split-whole-wrong-binding");
                        engine.set_devices(NO_RGB, NO_IR);
                        let camera = camera_fixture();
                        let _admit =
                            camera.admit_split_trust(&[CameraOperationKind::Authentication]);
                        authorize(pinned);
                        plant_account(&sb, &user, &engine, secondary);
                        if secondary {
                            let path = irlume_core::multi_camera::secondary_store_path(&user);
                            let mut store = irlume_core::multi_camera::load_secondary(&path)
                                .unwrap()
                                .unwrap();
                            store.groups[0].pair = binding.clone();
                            irlume_core::multi_camera::save_secondary(&path, &store).unwrap();
                        } else {
                            write_enrollment(&sb.dir, &primary(&user, &engine, binding.clone()));
                        }
                        plant_fake_envelope(&user);
                        let envelope = irlume_core::keyring::envelope_path(&user);
                        let before = std::fs::read(primary_path(&sb, &user)).unwrap();
                        let secondary_path = irlume_core::multi_camera::secondary_store_path(&user);
                        let before_secondary = std::fs::read(&secondary_path).ok();
                        let sealed = std::fs::read(&envelope).unwrap();
                        let samples = script(CameraOperationKind::Authentication, 1, |_| {
                            panic!("a mismatched complete key cannot assess")
                        });
                        let observer = UnsealObserver::install().unwrap();
                        let response = assert_refused(
                            worker_reply(entry.request(&user), &mut engine),
                            &sb,
                            &user,
                            &observer,
                        );
                        assert!(serde_json::to_string(&response)
                            .unwrap()
                            .contains("no eligible enrolled camera"));
                        assert_eq!(samples.calls(), 0);
                        assert!(camera.calls().is_empty());
                        assert_eq!(std::fs::read(primary_path(&sb, &user)).unwrap(), before);
                        assert_eq!(std::fs::read(&envelope).unwrap(), sealed);
                        assert_eq!(std::fs::read(&secondary_path).ok(), before_secondary);
                        assert_eq!(camera.lease_counts_observer()(), (0, 0));
                    }
                }
            }
        }
    }

    #[test]
    fn split_whole_unmarked_evidence_refuses_before_identity_even_with_strong_ir() {
        let _guard = env_lock();
        let mut engine = engine();
        let _environment = Environment::clear();
        let _no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let user = known_user();
        for pinned in [false, true] {
            for secondary in [false, true] {
                for entry in ENTRIES {
                    let sb = private_sandbox("split-whole-unmarked");
                    engine.set_devices(NO_RGB, NO_IR);
                    let camera = camera_fixture();
                    let _admit = camera.admit_split_trust(&[CameraOperationKind::Authentication]);
                    authorize(pinned);
                    plant_account(&sb, &user, &engine, secondary);
                    plant_fake_envelope(&user);
                    let envelope = irlume_core::keyring::envelope_path(&user);
                    let sealed = std::fs::read(&envelope).unwrap();
                    let before_primary = std::fs::read(primary_path(&sb, &user)).unwrap();
                    let secondary_path = irlume_core::multi_camera::secondary_store_path(&user);
                    let before_secondary = std::fs::read(&secondary_path).ok();
                    let samples = script(CameraOperationKind::Authentication, 1, |_| {
                        Ok(sample(0.9, 0.8, 2999, false))
                    });
                    let observer = UnsealObserver::install().unwrap();
                    let response = assert_refused(
                        worker_reply(entry.request(&user), &mut engine),
                        &sb,
                        &user,
                        &observer,
                    );
                    assert!(serde_json::to_string(&response)
                        .unwrap()
                        .contains("evidence from its split capture"));
                    assert_eq!(
                        samples.calls(),
                        1,
                        "the provenance guard precedes every identity arm"
                    );
                    assert_eq!(std::fs::read(&envelope).unwrap(), sealed);
                    assert_eq!(
                        std::fs::read(primary_path(&sb, &user)).unwrap(),
                        before_primary
                    );
                    assert_eq!(std::fs::read(&secondary_path).ok(), before_secondary);
                    assert_eq!(camera.lease_counts_observer()(), (0, 0));
                }
            }
        }
    }
}
