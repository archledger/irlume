// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

mod credentials {
    use super::*;

    pub(super) fn swtpm_transport() -> String {
        let transport = std::env::var("IRLUME_TCTI")
            .expect("explicit swtpm transport required; no skip or hardware fallback");
        assert!(
            transport.starts_with("swtpm:"),
            "only an explicit software TPM is admitted"
        );
        assert!(
            !std::path::Path::new("/dev/tpm0").exists()
                && !std::path::Path::new("/dev/tpmrm0").exists(),
            "run this lane with private devices, never host TPM nodes"
        );
        transport
    }

    pub(super) fn synthetic_secret() -> irlume_common::SecretBytes {
        irlume_common::SecretBytes::new((0..32).map(|index| b'A' + index % 26).collect())
    }

    pub(super) fn arm(user: &str, secret: &irlume_common::SecretBytes) {
        irlume_core::keyring::seal_secret(
            user,
            secret.expose(),
            irlume_core::envelope::SecretKind::LoginPassword,
        )
        .expect("real software-TPM seal");
        let envelope =
            irlume_core::envelope::SealedEnvelope::load(&irlume_core::keyring::envelope_path(user))
                .unwrap();
        assert_eq!(envelope.uid, Some(uid_of(user).unwrap()));
        assert_eq!(
            envelope.secret,
            irlume_core::envelope::SecretKind::LoginPassword
        );
    }

    pub(super) fn assert_credential(response: &Response, expected: &irlume_common::SecretBytes) {
        let Response::PasswordUnsealed { kind, secret } = response else {
            panic!("expected one actually unsealed credential response");
        };
        assert_eq!(*kind, irlume_common::KeyringSecretKind::LoginPassword);
        // Assertion failures must not print secret bytes.
        assert!(
            secret.expose() == expected.expose(),
            "real unsealed bytes differ from the synthetic sealed bytes"
        );
    }

    pub(super) fn protected_account(
        sb: &Sandbox,
        user: &str,
        engine: &irlume_auth::Engine,
        secondary: bool,
    ) {
        let enrollment = primary(
            user,
            engine,
            if secondary {
                absent_binding()
            } else {
                CameraBinding::Split(key())
            },
        );
        plant_enrollment(sb, user, &enrollment, secondary, true);
        let stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(primary_path(sb, user)).unwrap()).unwrap();
        assert!(
            stored["enc"].is_string(),
            "the swtpm lane loads an actual encrypted primary"
        );
        assert!(irlume_core::template_key::key_path(user).exists());
        if secondary {
            let stored: serde_json::Value = serde_json::from_slice(
                &std::fs::read(irlume_core::multi_camera::secondary_store_path(user)).unwrap(),
            )
            .unwrap();
            assert!(
                stored["enc"].is_string(),
                "secondary must use the real retained template key"
            );
        }
    }

    #[test]
    #[ignore = "requires disposable swtpm with explicit IRLUME_TCTI and private devices; never host TPM"]
    fn tpm_split_whole_unseal_releases_once_at_each_skew_and_resets_only_after_delivery() {
        let _guard = env_lock();
        let transport = swtpm_transport();
        let mut engine = engine();
        let _environment = Environment::clear();
        std::env::set_var("IRLUME_TCTI", transport);
        let _present = irlume_core::template_key::test_support::TpmPresence::force(true);
        let user = known_user();
        for pinned in [false, true] {
            for secondary in [false, true] {
                for skew in [2999, 3000, 3001] {
                    for rgb in [0.9, 0.5] {
                        let sb = private_sandbox("split-whole-real-unseal");
                        engine.set_devices(NO_RGB, NO_IR);
                        let camera = camera_fixture();
                        let _admit =
                            camera.admit_split_trust(&[CameraOperationKind::Authentication]);
                        authorize(pinned);
                        protected_account(&sb, &user, &engine, secondary);
                        let secret = synthetic_secret();
                        arm(&user, &secret);
                        let envelope = irlume_core::keyring::envelope_path(&user);
                        let sealed = std::fs::read(&envelope).unwrap();
                        let primary = std::fs::read(primary_path(&sb, &user)).unwrap();
                        let secondary_bytes =
                            std::fs::read(irlume_core::multi_camera::secondary_store_path(&user))
                                .ok();
                        {
                            let observer = UnsealObserver::install().unwrap();
                            let samples =
                                script(CameraOperationKind::Authentication, 5, move |_| {
                                    Ok(sample(rgb, 0.4, skew, true))
                                });
                            assert_refused(
                                worker_reply(Entry::UnsealPassword.request(&user), &mut engine),
                                &sb,
                                &user,
                                &observer,
                            );
                            assert_eq!(
                                samples.calls(),
                                5,
                                "IR identity denial, not pre-capture refusal"
                            );
                        }
                        {
                            let observer = UnsealObserver::install().unwrap();
                            let samples =
                                script(CameraOperationKind::Authentication, 5, move |_| {
                                    Ok(sample(rgb, 0.8, skew, true))
                                });
                            let reply =
                                worker_reply(Entry::UnsealPassword.request(&user), &mut engine);
                            assert_credential(&reply.response, &secret);
                            assert!(reply.completion.is_some());
                            assert_eq!(
                                (observer.calls(), observer.successes()),
                                (1, 1),
                                "one real credential release, distinct from template-key unseals"
                            );
                            assert_eq!(retry(&sb, &user)["budget"]["unsuccessful_requests"], 2);
                            assert_eq!(retry(&sb, &user)["budget"]["pending"], true);
                            assert_credential(&delivered(reply), &secret);
                            assert_reset(&sb, &user);
                            assert_eq!(
                                (observer.calls(), observer.successes()),
                                (1, 1),
                                "responding cannot re-unseal"
                            );
                            assert_eq!(samples.calls(), 5);
                        }
                        assert!(
                            std::fs::read(&envelope).unwrap() == sealed,
                            "credential envelope changed"
                        );
                        assert!(
                            std::fs::read(primary_path(&sb, &user)).unwrap() == primary,
                            "encrypted primary changed"
                        );
                        assert!(
                            std::fs::read(irlume_core::multi_camera::secondary_store_path(&user))
                                .ok()
                                == secondary_bytes,
                            "encrypted secondary changed"
                        );
                        assert_eq!(
                            camera.calls(),
                            vec![lease(CameraOperationKind::Authentication); 2]
                        );
                        assert_eq!(camera.lease_counts_observer()(), (0, 0));
                        assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
                    }
                }
            }
        }
    }

    #[test]
    #[ignore = "requires disposable swtpm with explicit IRLUME_TCTI and private devices; never host TPM"]
    fn tpm_split_whole_unwritten_credential_keeps_the_charge_after_one_real_release() {
        let _guard = env_lock();
        let transport = swtpm_transport();
        let mut engine = engine();
        let _environment = Environment::clear();
        std::env::set_var("IRLUME_TCTI", transport);
        let _present = irlume_core::template_key::test_support::TpmPresence::force(true);
        let user = known_user();
        for pinned in [false, true] {
            for secondary in [false, true] {
                let sb = private_sandbox("split-whole-unwritten-credential");
                engine.set_devices(NO_RGB, NO_IR);
                let camera = camera_fixture();
                let _admit = camera.admit_split_trust(&[CameraOperationKind::Authentication]);
                authorize(pinned);
                protected_account(&sb, &user, &engine, secondary);
                let secret = synthetic_secret();
                arm(&user, &secret);
                let envelope = irlume_core::keyring::envelope_path(&user);
                let sealed = std::fs::read(&envelope).unwrap();
                let observer = UnsealObserver::install().unwrap();
                let samples = script(CameraOperationKind::Authentication, 5, |_| {
                    Ok(sample(0.5, 0.8, 3000, true))
                });
                let reply = worker_reply(Entry::UnsealPassword.request(&user), &mut engine);
                assert_credential(&reply.response, &secret);
                let (server, client) = UnixStream::pair().unwrap();
                drop(client);
                assert!(reply.respond(server).is_err());
                assert_eq!((observer.calls(), observer.successes()), (1, 1));
                assert_eq!(retry(&sb, &user)["budget"]["unsuccessful_requests"], 1);
                assert_eq!(retry(&sb, &user)["budget"]["pending"], true);
                assert_eq!(samples.calls(), 5);
                assert!(
                    std::fs::read(&envelope).unwrap() == sealed,
                    "credential envelope changed"
                );
                assert_eq!(camera.lease_counts_observer()(), (0, 0));
            }
        }
    }

    #[test]
    #[ignore = "requires disposable swtpm with explicit IRLUME_TCTI and private devices; never host TPM"]
    fn tpm_split_whole_broken_credential_envelope_refuses_release_and_keeps_charge() {
        let _guard = env_lock();
        let transport = swtpm_transport();
        let mut engine = engine();
        let _environment = Environment::clear();
        std::env::set_var("IRLUME_TCTI", transport);
        let _present = irlume_core::template_key::test_support::TpmPresence::force(true);
        let user = known_user();
        for pinned in [false, true] {
            for secondary in [false, true] {
                let sb = private_sandbox("split-whole-broken-credential");
                engine.set_devices(NO_RGB, NO_IR);
                let camera = camera_fixture();
                let _admit = camera.admit_split_trust(&[CameraOperationKind::Authentication]);
                authorize(pinned);
                protected_account(&sb, &user, &engine, secondary);
                let secret = synthetic_secret();
                arm(&user, &secret);
                let envelope = irlume_core::keyring::envelope_path(&user);
                std::fs::write(&envelope, b"not a credential envelope").unwrap();
                let broken = std::fs::read(&envelope).unwrap();
                let primary = std::fs::read(primary_path(&sb, &user)).unwrap();
                let observer = UnsealObserver::install().unwrap();
                let samples = script(CameraOperationKind::Authentication, 5, |_| {
                    Ok(sample(0.5, 0.8, 3001, true))
                });
                let reply = worker_reply(Entry::UnsealPassword.request(&user), &mut engine);
                assert!(!is_face_grant(&reply.response));
                assert!(reply.completion.is_none());
                assert!(!is_face_grant(&delivered(reply)));
                assert_eq!(
                    (observer.calls(), observer.successes()),
                    (1, 0),
                    "face reached the real credential loader, which failed"
                );
                assert_eq!(samples.calls(), 5);
                assert_eq!(retry(&sb, &user)["budget"]["unsuccessful_requests"], 1);
                assert_eq!(retry(&sb, &user)["budget"]["pending"], true);
                assert_eq!(std::fs::read(&envelope).unwrap(), broken);
                assert_eq!(std::fs::read(primary_path(&sb, &user)).unwrap(), primary);
                assert_eq!(camera.lease_counts_observer()(), (0, 0));
            }
        }
    }
}
