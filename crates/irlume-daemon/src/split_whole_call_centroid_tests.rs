// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

mod centroid {
    use super::*;

    fn centroid_enrollment(
        user: &str,
        engine: &irlume_auth::Engine,
        secondary: bool,
    ) -> Enrollment {
        assert_eq!(
            engine.ir_space(),
            "raw",
            "per-profile calibration is unavailable with a global adapter"
        );
        let mut enrollment = primary(
            user,
            engine,
            if secondary {
                absent_binding()
            } else {
                CameraBinding::Split(key())
            },
        );
        let profile = &mut enrollment.profiles[0];
        let seed = profile.scans[0].clone();
        // Four unit directions: (0.5, +/-sqrt(0.75), 0) and
        // (0.5, 0, +/-sqrt(0.75)). Their normalized sum is e0, but
        // every individual score against e0 is 0.5.
        let directions: Vec<Vec<f32>> = [(1, 1.0), (1, -1.0), (2, 1.0), (2, -1.0)]
            .into_iter()
            .map(|(axis, sign)| {
                let mut direction = vec![0.0; 512];
                direction[0] = 0.5;
                direction[axis] = sign * 0.75_f32.sqrt();
                direction
            })
            .collect();
        profile.scans = directions
            .iter()
            .enumerate()
            .map(|(index, direction)| {
                let mut scan = seed.clone();
                scan.name = format!("Arithmetic Centroid {}", index + 1);
                scan.rgb = direction.clone();
                scan.ir = Some(direction.clone());
                scan
            })
            .collect();
        // Use the real fitter: identical IR/RGB rows give N=B-A=0, so the
        // stored ridge transform is identity followed by normalization.
        let calibration = irlume_core::calib::fit(&directions, &directions)
            .expect("four compatible real fit pairs");
        let scored_probe = calibration.apply(&probe(1.0)).unwrap();
        let mut best = f32::NEG_INFINITY;
        let mut sum = vec![0.0_f32; 512];
        for direction in &directions {
            let scored = calibration.apply(direction).unwrap();
            let score: f32 = scored_probe.iter().zip(&scored).map(|(x, y)| x * y).sum();
            best = best.max(score);
            for (sum, value) in sum.iter_mut().zip(scored) {
                *sum += value;
            }
        }
        let norm = sum.iter().map(|value| value * value).sum::<f32>().sqrt();
        let center: f32 = scored_probe
            .iter()
            .zip(&sum)
            .map(|(x, y)| x * y / norm)
            .sum();
        assert!((best - 0.5).abs() < 1e-5);
        assert!((center - 1.0).abs() < 1e-5);
        assert!(
            best < irlume_core::scaled_threshold(irlume_core::IR_MATCH_THRESHOLD, directions.len())
                + irlume_core::IR_FALLBACK_MARGIN,
            "best-template arm must miss"
        );
        assert!(
            center
                > irlume_core::scaled_threshold(irlume_core::IR_MATCH_THRESHOLD, 1)
                    + irlume_core::IR_FALLBACK_MARGIN,
            "centroid arm must clear its real profile-count bar"
        );
        profile.set_calib_for(engine.embed_space(), Some(calibration));
        enrollment
    }

    #[test]
    fn split_whole_authenticate_grants_through_calibrated_centroid_at_each_skew() {
        let _guard = env_lock();
        let mut engine = engine();
        let _environment = Environment::clear();
        let _no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let user = known_user();
        // Fit once outside presence windows, then reuse only constructed state.
        for secondary in [false, true] {
            let enrollment = centroid_enrollment(&user, &engine, secondary);
            for pinned in [false, true] {
                for skew in [2999, 3000, 3001] {
                    let sb = private_sandbox("split-whole-centroid");
                    engine.set_devices(NO_RGB, NO_IR);
                    let camera = camera_fixture();
                    let _admit = camera.admit_split_trust(&[CameraOperationKind::Authentication]);
                    authorize(pinned);
                    plant_enrollment(&sb, &user, &enrollment, secondary, false);
                    let observer = UnsealObserver::install().unwrap();
                    let samples = script(CameraOperationKind::Authentication, 5, move |_| {
                        Ok(sample(0.0, 1.0, skew, true))
                    });
                    let reply = worker_reply(authenticate(&user), &mut engine);
                    assert!(
                        matches!(&reply.response, Response::AuthResult { granted: true, reason, .. } if reason.contains("calibrated centroid") && !reason.contains("ir-fallback"))
                    );
                    let response = delivered(reply);
                    assert!(matches!(
                        response,
                        Response::AuthResult { granted: true, .. }
                    ));
                    assert_reset(&sb, &user);
                    assert_eq!((observer.calls(), observer.successes()), (0, 0));
                    assert_eq!(samples.calls(), 5);
                    assert_eq!(
                        camera.calls(),
                        vec![lease(CameraOperationKind::Authentication)]
                    );
                    assert_eq!(camera.lease_counts_observer()(), (0, 0));
                }
            }
        }
    }

    #[test]
    #[ignore = "requires disposable swtpm with explicit IRLUME_TCTI and private devices; never host TPM"]
    fn tpm_split_whole_centroid_identity_releases_once_at_each_skew() {
        let _guard = env_lock();
        let transport = credentials::swtpm_transport();
        let mut engine = engine();
        let _environment = Environment::clear();
        std::env::set_var("IRLUME_TCTI", transport);
        let _present = irlume_core::template_key::test_support::TpmPresence::force(true);
        let user = known_user();
        for secondary in [false, true] {
            let enrollment = centroid_enrollment(&user, &engine, secondary);
            for pinned in [false, true] {
                for skew in [2999, 3000, 3001] {
                    let sb = private_sandbox("split-whole-centroid-release");
                    engine.set_devices(NO_RGB, NO_IR);
                    let camera = camera_fixture();
                    let _admit = camera.admit_split_trust(&[CameraOperationKind::Authentication]);
                    authorize(pinned);
                    plant_enrollment(&sb, &user, &enrollment, secondary, true);
                    let secret = credentials::synthetic_secret();
                    credentials::arm(&user, &secret);
                    let envelope = irlume_core::keyring::envelope_path(&user);
                    let sealed = std::fs::read(&envelope).unwrap();
                    let observer = UnsealObserver::install().unwrap();
                    let samples = script(CameraOperationKind::Authentication, 5, move |_| {
                        Ok(sample(0.0, 1.0, skew, true))
                    });
                    // First run the actual verify call to observe which identity
                    // arm this exact encrypted account and evidence select.
                    let verify = worker_reply(authenticate(&user), &mut engine);
                    assert!(
                        matches!(&verify.response, Response::AuthResult { granted: true, reason, .. } if reason.contains("calibrated centroid"))
                    );
                    delivered(verify);
                    assert_eq!((observer.calls(), observer.successes()), (0, 0));
                    assert_eq!(samples.calls(), 5);
                    drop(samples);
                    let samples = script(CameraOperationKind::Authentication, 5, move |_| {
                        Ok(sample(0.0, 1.0, skew, true))
                    });
                    let reply = worker_reply(Entry::UnsealPassword.request(&user), &mut engine);
                    credentials::assert_credential(&reply.response, &secret);
                    assert_eq!(retry(&sb, &user)["budget"]["unsuccessful_requests"], 1);
                    assert_eq!((observer.calls(), observer.successes()), (1, 1));
                    credentials::assert_credential(&delivered(reply), &secret);
                    assert_reset(&sb, &user);
                    assert_eq!(samples.calls(), 5);
                    assert_eq!((observer.calls(), observer.successes()), (1, 1));
                    assert!(
                        std::fs::read(&envelope).unwrap() == sealed,
                        "credential envelope changed"
                    );
                    assert_eq!(
                        camera.calls(),
                        vec![lease(CameraOperationKind::Authentication); 2]
                    );
                    assert_eq!(camera.lease_counts_observer()(), (0, 0));
                }
            }
        }
    }
}
