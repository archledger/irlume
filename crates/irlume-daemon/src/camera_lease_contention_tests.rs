// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// The camera-LEASE row of the contention matrix: another Irlume operation in
// this process holds the camera when an authentication arrives and still
// holds it at the request's acquisition deadline. The request runs through
// the complete daemon worker handler and the real Engine, and the lease is
// the real one; only the inventory is the non-granting fixture, which refuses
// every open. A kernel EBUSY from another application is classified in the
// camera crate, which has no device-free seam into this handler.

mod camera_lease_contention {
    use super::*;
    use irlume_camera::lease::CameraOperationKind;
    use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
    use irlume_core::storage::CameraBinding;
    use std::time::{Duration, Instant};

    const RGB: &str = "/dev/irlume-lease-contention-rgb";
    const IR: &str = "/dev/irlume-lease-contention-ir";
    /// The fixture camera's USB identity, as an enrollment records it.
    const CAMERA: &str = "1234:0105:ordinary";

    /// How long an authentication waits for the camera lease at most: the
    /// shorter of two seconds and the request window that remains. The
    /// request here has the whole default greeter window left, so this cap
    /// is the deadline it meets.
    const ACQUISITION_DEADLINE: Duration = Duration::from_secs(2);

    /// A generous ceiling on the same wait, and under the window this request
    /// gets. A longer cap that still ends inside the window answers with the
    /// same refusal, so the time is what tells it apart. The margin is wide on
    /// purpose, because a loaded machine may wake the waiter late.
    ///
    /// Read together, the two bounds catch a default that became very short
    /// (under two seconds) or left the window's scale (a wait that ran to the
    /// window, or lost its bound). They do not measure the cap to the
    /// second: a default of, say, five seconds would pass both.
    const ACQUISITION_CEILING: Duration = Duration::from_secs(10);

    /// Clears device, IR, retry and grace overrides, uses a nonexistent TPM
    /// path, then restores every value on drop.
    struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl Environment {
        fn clear() -> Self {
            let keys = [
                "IRLUME_RGB_DEVICE",
                "IRLUME_IR_DEVICE",
                "IRLUME_FORCE_NO_IR",
                "IRLUME_CAMERA_REQUIRE_FIXED",
                "IRLUME_FORBID_EXTERNAL_CAMERAS",
                "IRLUME_GRACE_MS",
                "IRLUME_RATE_LIMIT",
                "IRLUME_RATE_COOLDOWN_SECS",
                "IRLUME_TCTI",
            ];
            let saved = keys
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect();
            for key in keys {
                std::env::remove_var(key);
            }
            std::env::set_var(
                "IRLUME_TCTI",
                "device:/nonexistent/irlume-lease-contention-tpm",
            );
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

    /// Restore the shared engine's fixture defaults even if an assertion
    /// unwinds while it is using the contention camera pair.
    struct FixtureDevices<'a>(&'a mut irlume_auth::Engine);

    impl<'a> FixtureDevices<'a> {
        fn new(engine: &'a mut irlume_auth::Engine) -> Self {
            engine.set_devices(RGB, IR);
            Self(engine)
        }
    }

    impl Drop for FixtureDevices<'_> {
        fn drop(&mut self) {
            self.0.set_devices(NO_RGB, NO_IR);
        }
    }

    /// One ordinary RGB+IR camera. Every lease request and every open is
    /// recorded, and every open is refused.
    fn fixture() -> Guard {
        let endpoint = |path: &str, format| Endpoint {
            path: path.into(),
            formats: vec![format],
        };
        Guard::install(&[Camera {
            topology: "/devices/lease-contention/ordinary".into(),
            identity: CAMERA.into(),
            fixed: true,
            controller: "0000:00.14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![8],
            endpoints: vec![endpoint(RGB, *b"YUYV"), endpoint(IR, *b"GREY")],
        }])
        .unwrap()
    }

    /// Unsuccessful requests charged so far to the account `uid`; zero
    /// before the account has a retry record.
    fn charges(sb: &Sandbox, uid: u32) -> u64 {
        let path = sb.dir.join(format!("retry/{uid}.json"));
        if !path.exists() {
            return 0;
        }
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        record["budget"]["unsuccessful_requests"]
            .as_u64()
            .expect("the retry record counts unsuccessful requests")
    }

    /// Run one request as root through the worker handler, with how long the
    /// reply took.
    fn timed(request: Request, engine: &mut irlume_auth::Engine) -> (Response, Duration) {
        let started = Instant::now();
        let response = dispatch(request, &peer(0), engine);
        (response, started.elapsed())
    }

    #[test]
    fn a_held_camera_lease_ends_an_authentication_at_its_acquisition_deadline() {
        let _guard = env_lock();
        let mut engine = engine();
        let _environment = Environment::clear();
        let user = users::name_for_uid(0).unwrap();

        // Two other Irlume operations an authentication can meet holding
        // its camera: a client's enrollment, and a live preview. Each gets a
        // fresh account state, so the retry rate limit that five refusals in
        // half a minute start never reaches the control below.
        for (holder, tag) in [
            (
                CameraOperationKind::Enrollment,
                "camera-lease-contention-enrollment",
            ),
            (
                CameraOperationKind::Preview,
                "camera-lease-contention-preview",
            ),
        ] {
            let sb = sandbox(tag);
            let mut enrollment = enrollment_with(&user, &["Face Scan 1"]);
            enrollment.camera_binding = Some(CameraBinding::Ordinary {
                rgb: Some(CAMERA.into()),
                ir: Some(CAMERA.into()),
            });
            write_enrollment(&sb.dir, &enrollment);
            let authenticate = |structured_errors: bool| Request::Authenticate {
                user: user.clone(),
                service: Some("gdm-password".into()),
                structured_errors,
                intent_confirmation: None,
            };
            assert_eq!(charges(&sb, 0), 0);
            let mut charged = 0;

            let recorder = fixture();
            let counts = recorder.lease_counts_observer();
            let camera = FixtureDevices::new(&mut engine);
            // Taken through the public entry on the request's own thread, so
            // it is the lease authority the request then contends on.
            let held =
                irlume_camera::lease::acquire_camera_operation(&[RGB, IR], holder, Duration::ZERO)
                    .unwrap();
            assert_eq!(counts(), (1, 0));
            // The request leases the whole pair its enrollment is bound to,
            // RGB then IR, as the other operation does.
            let lease = |kind| Call::Lease {
                endpoints: vec![RGB.to_owned(), IR.to_owned()],
                kind,
            };

            for structured_errors in [false, true] {
                let seen = recorder.calls().len();
                let (response, took) = timed(authenticate(structured_errors), camera.0);
                assert!(
                    !is_face_grant(&response),
                    "a camera another operation holds grants nothing: {response:?}"
                );
                match (&response, structured_errors) {
                    // The reply a PAM module asks for: prose, as it opts out
                    // of structured errors. It is the lease's own refusal,
                    // naming the kind of operation that holds the camera and
                    // nothing else.
                    (Response::Error(reason), false) => assert_eq!(
                        reason,
                        &format!(
                            "hardware: camera lease deadline expired; current owner: {holder:?}"
                        )
                    ),
                    // A structured client gets the camera's own cause.
                    (
                        Response::OperationError {
                            cause: Some(irlume_common::OutcomeCause::CameraUnavailable),
                            ..
                        },
                        true,
                    ) => {}
                    _ => panic!("structured={structured_errors}: {response:?}"),
                }
                assert!(
                    took >= ACQUISITION_DEADLINE,
                    "the request gave up on the lease before its acquisition deadline: {took:?}"
                );
                assert!(
                    took < ACQUISITION_CEILING,
                    "the lease wait outran its acquisition deadline: {took:?}"
                );
                // One lease request of its own and no camera attempt: no
                // open, no second lease, no waiter left behind.
                assert_eq!(
                    &recorder.calls()[seen..],
                    &[lease(CameraOperationKind::Authentication)],
                    "structured={structured_errors}: a refused acquisition opens nothing"
                );
                assert_eq!(counts(), (1, 0), "only the other operation's lease remains");
                charged += 1;
                assert_eq!(
                    charges(&sb, 0),
                    charged,
                    "the refusal keeps exactly its own charge"
                );
            }

            drop(held);
            assert_eq!(counts(), (0, 0));

            // Control: with the lease free, the same request takes it and
            // reaches the camera, where the fixture's refused open ends it.
            let calls = recorder.calls().len();
            let (response, _) = timed(authenticate(false), camera.0);
            assert!(!is_face_grant(&response), "{response:?}");
            let reached = &recorder.calls()[calls..];
            assert!(
                reached.contains(&Call::OpenRgb(RGB.into())),
                "the refusals above were the held lease, not an earlier gate: {reached:?}"
            );
            assert_eq!(counts(), (0, 0));
            charged += 1;
            assert_eq!(charges(&sb, 0), charged);
        }
    }
}
