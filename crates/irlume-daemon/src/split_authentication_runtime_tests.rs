// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// Split authentication through the daemon (ADR-0032 Step 5, plan W3;
// acceptance cases 11, 12 and 15). While a test-support token admits
// Authentication on this thread, `Authenticate` and `UnsealPassword` route a
// split account, automatic or pinned, to one split Authentication lease over
// both original sides. The camera fixture refuses every open, so the request
// ends at the RGB side: nothing is granted or released, the sealed envelope
// is unchanged and the request keeps its retry charge. An unplugged pin
// denies before any lease and never resets the retry budget, and an IR-only
// request refuses with the split IR-only refusal before any lease without
// spending a strike. No shipped build has the token.

mod split_authentication_gates {
    use super::*;
    use irlume_camera::lease::CameraOperationKind;
    use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
    use irlume_common::split_key::SplitPairKey;
    use irlume_common::split_schema::{AuthorizationRecord, SideFields};
    use irlume_core::storage::CameraBinding;

    const RGB: &str = "/dev/irlume-split-auth-rgb";
    const IR: &str = "/dev/irlume-split-auth-ir";
    const KEY: &str =
        "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5";
    const CLOSED: &str = "split enrollment and authentication are not enabled";
    const D9: &str = "split camera IR-only authentication is not supported";

    /// Clears the device and IR overrides the shared engine sets and pins
    /// the TPM transport to a node that does not exist, so nothing here can
    /// fall back to the host TPM. Restores every value on drop.
    struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl Environment {
        fn clear() -> Self {
            let keys = [
                "IRLUME_RGB_DEVICE",
                "IRLUME_IR_DEVICE",
                "IRLUME_FORCE_NO_IR",
                "IRLUME_CAMERA_REQUIRE_FIXED",
                "IRLUME_FORBID_EXTERNAL_CAMERAS",
                "IRLUME_SEQUENTIAL_CAPTURE",
                "IRLUME_GRACE_MS",
                "IRLUME_TCTI",
            ];
            let saved = keys
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect();
            for key in keys {
                std::env::remove_var(key);
            }
            std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-split-auth-tpm");
            Self(saved)
        }
    }
    impl Drop for Environment {
        fn drop(&mut self) {
            for (key, value) in self.0.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// Two fixed single-endpoint USB devices on one controller, an RGB side
    /// and a native GREY IR side; `ir` false leaves the IR side unplugged.
    /// Every open is refused and recorded.
    fn fixture(ir: bool) -> Guard {
        let camera = |topology: &str, identity: &str, port: u8, path: &str, format| Camera {
            topology: topology.into(),
            identity: identity.into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
            endpoints: vec![Endpoint {
                path: path.into(),
                formats: vec![format],
            }],
        };
        let mut cameras = vec![camera(
            "/devices/split-auth/rgb",
            "1234:0001:rgb",
            8,
            RGB,
            *b"YUYV",
        )];
        if ir {
            cameras.push(camera(
                "/devices/split-auth/ir",
                "1234:0002:ir",
                5,
                IR,
                *b"GREY",
            ));
        }
        Guard::install(&cameras).unwrap()
    }

    fn key() -> SplitPairKey {
        SplitPairKey::parse_canonical(KEY).unwrap()
    }

    /// The administrator authorization for the fixture pair, with the pair
    /// saved as the selection when `pinned`.
    fn authorize(pinned: bool) {
        let side = |identity: &str, path: &str, port| SideFields {
            identity: identity.into(),
            path: path.into(),
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
        };
        let record = AuthorizationRecord {
            rgb: side("1234:0001:rgb", RGB, 8),
            ir: side("1234:0002:ir", IR, 5),
        };
        let key = key();
        irlume_common::split_publish::publish_split(&[record], pinned.then_some(&key)).unwrap();
    }

    /// A primary enrolled on the split pair.
    fn split_primary(user: &str) -> Enrollment {
        let mut enrollment = enrollment_with(user, &["Face Scan 1"]);
        enrollment.camera_binding = Some(CameraBinding::Split(key()));
        enrollment
    }

    /// The split primary with IR templates the engine's IR-only matcher
    /// counts as compatible, so IR-only routing classifies the split.
    fn ir_eligible_split_primary(user: &str, engine: &irlume_auth::Engine) -> Enrollment {
        let mut enrollment = split_primary(user);
        for scan in &mut enrollment.profiles[0].scans {
            scan.ir = Some(scan.rgb.clone());
            scan.ir_space = Some(engine.ir_space().into());
            scan.embed_space = Some(engine.embed_space().into());
        }
        enrollment
    }

    fn split_lease() -> Call {
        Call::Lease {
            endpoints: vec![RGB.into(), IR.into()],
            kind: CameraOperationKind::Authentication,
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Entry {
        Authenticate,
        UnsealPassword,
    }

    const ENTRIES: [Entry; 2] = [Entry::Authenticate, Entry::UnsealPassword];

    fn request(entry: Entry, user: &str) -> Request {
        match entry {
            Entry::Authenticate => Request::Authenticate {
                structured_errors: false,
                user: user.into(),
                service: None,
                intent_confirmation: None,
            },
            Entry::UnsealPassword => Request::UnsealPassword {
                user: user.into(),
                service: None,
            },
        }
    }

    /// A reply that grants nothing and releases no credential.
    fn grants_nothing(response: &Response) -> bool {
        !is_face_grant(response)
            && !matches!(
                response,
                Response::PasswordUnsealed { .. } | Response::AuthResult { granted: true, .. }
            )
    }

    fn reply_text(response: &Response) -> String {
        serde_json::to_string(response).unwrap()
    }

    fn retry_record(dir: &std::path::Path) -> Option<Vec<u8>> {
        std::fs::read(dir.join("retry/0.json")).ok()
    }

    fn unsuccessful_requests(record: &[u8]) -> u64 {
        let value: serde_json::Value = serde_json::from_slice(record).unwrap();
        value["budget"]["unsuccessful_requests"].as_u64().unwrap()
    }

    // RED: the pinned Authenticate row needs the daemon's outer scope to be
    // the account-routed authentication preparation.

    #[test]
    fn split_runtime_admitted_authentication_leases_both_sides_and_releases_nothing() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("split-auth-admitted");
        let _environment = Environment::clear();
        engine.set_devices(NO_RGB, NO_IR);
        let user = users::name_for_uid(0).unwrap();
        plant_fake_envelope(&user);
        let envelope = irlume_core::keyring::envelope_path(&user);
        let sealed = std::fs::read(&envelope).unwrap();
        let mut charged = retry_record(&sb.dir).map_or(0, |record| unsuccessful_requests(&record));
        for pinned in [false, true] {
            for entry in ENTRIES {
                let row = format!("{entry:?}/pinned={pinned}");
                let recorder = fixture(true);
                let counts = recorder.lease_counts_observer();
                let _admitted = recorder.admit_split_trust(&[CameraOperationKind::Authentication]);
                authorize(pinned);
                write_enrollment(&sb.dir, &split_primary(&user));
                let response = dispatch(request(entry, &user), &peer(0), &mut engine);
                assert!(grants_nothing(&response), "{row}: {response:?}");
                assert!(
                    !reply_text(&response).contains(CLOSED),
                    "{row}: an admitted split account routes, it is not refused closed: {response:?}"
                );
                assert_eq!(
                    recorder.calls(),
                    vec![split_lease(), Call::OpenRgb(RGB.into())],
                    "{row}: one split Authentication lease over both original sides, then the \
                     sequential RGB attempt only: no probe, no single-endpoint lease and no IR \
                     open after the refused RGB side"
                );
                assert_eq!(counts(), (0, 0), "{row}: both reservations released");
                assert_eq!(std::fs::read(&envelope).unwrap(), sealed, "{row}: envelope");
                let record = retry_record(&sb.dir).expect("the request is charged");
                charged += 1;
                assert_eq!(unsuccessful_requests(&record), charged, "{row}: retry charge");
                assert_eq!(
                    (engine.rgb_device(), engine.ir_device()),
                    (NO_RGB, NO_IR),
                    "{row}: the request scope restores the standing pair"
                );
            }
        }
    }

    #[test]
    fn split_runtime_unplugged_pin_denies_before_any_lease_and_keeps_the_charge() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("split-auth-unplugged");
        let _environment = Environment::clear();
        engine.set_devices(NO_RGB, NO_IR);
        let user = users::name_for_uid(0).unwrap();
        plant_fake_envelope(&user);
        let envelope = irlume_core::keyring::envelope_path(&user);
        let sealed = std::fs::read(&envelope).unwrap();
        for entry in ENTRIES {
            let row = format!("{entry:?}");
            let charged = retry_record(&sb.dir).map_or(0, |record| unsuccessful_requests(&record));
            let recorder = fixture(false);
            let _admitted = recorder.admit_split_trust(&[CameraOperationKind::Authentication]);
            authorize(true);
            write_enrollment(&sb.dir, &split_primary(&user));
            let response = dispatch(request(entry, &user), &peer(0), &mut engine);
            assert!(grants_nothing(&response), "{row}: {response:?}");
            assert!(
                recorder.calls().is_empty(),
                "{row}: an unplugged pin leases and opens nothing: {:?}",
                recorder.calls()
            );
            assert_eq!(std::fs::read(&envelope).unwrap(), sealed, "{row}: envelope");
            // A denial never resets the account's retry budget.
            let after = retry_record(&sb.dir).map_or(0, |record| unsuccessful_requests(&record));
            assert!(after >= charged, "{row}: retry budget {charged} -> {after}");
            assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
        }
    }

    #[test]
    fn split_runtime_ir_only_refuses_a_split_account_before_any_lease_without_a_strike() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("split-auth-ir-only");
        let _environment = Environment::clear();
        engine.set_devices(NO_RGB, NO_IR);
        std::fs::write(
            sb.dir.join("config/settings.conf"),
            "face_sensor_policy=ir-only-experimental\n",
        )
        .unwrap();
        let user = users::name_for_uid(0).unwrap();
        plant_fake_envelope(&user);
        let envelope = irlume_core::keyring::envelope_path(&user);
        let sealed = std::fs::read(&envelope).unwrap();
        for entry in ENTRIES {
            let row = format!("{entry:?}");
            let recorder = fixture(true);
            let _admitted = recorder.admit_split_trust(&[CameraOperationKind::Authentication]);
            authorize(false);
            write_enrollment(&sb.dir, &ir_eligible_split_primary(&user, &engine));
            let before = retry_record(&sb.dir);
            let response = dispatch(request(entry, &user), &peer(0), &mut engine);
            assert!(grants_nothing(&response), "{row}: {response:?}");
            assert!(
                reply_text(&response).contains(D9),
                "{row}: the split IR-only refusal: {response:?}"
            );
            assert!(
                recorder.calls().is_empty(),
                "{row}: refused before any lease: {:?}",
                recorder.calls()
            );
            assert_eq!(std::fs::read(&envelope).unwrap(), sealed, "{row}: envelope");
            let after = retry_record(&sb.dir).expect("the request is charged");
            let count = before.as_deref().map_or(0, unsuccessful_requests) + 1;
            assert_short_history_and_charge(&before, &after, count as u32, false);
        }
    }
}
