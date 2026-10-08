// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

mod request_preparation_gates {
    use super::*;
    use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
    use irlume_common::split_schema::{AuthorizationRecord, SideFields};

    const RGB: &str = "/dev/irlume-request-fixture-rgb";
    const IR: &str = "/dev/irlume-request-fixture-ir";
    const CLOSED: &str = "split enrollment and authentication are not enabled";
    /// An ordinary request that meets a saved split selection. It refuses
    /// because the ordinary path never opens a split camera pair, which stays
    /// true once split activation is admitted, so the text must not blame the
    /// closed predicate.
    const ORDINARY: &str =
        "this request uses the ordinary camera path, which never opens a split camera pair";

    struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl Environment {
        fn clear() -> Self {
            let keys = [
                "IRLUME_RGB_DEVICE",
                "IRLUME_IR_DEVICE",
                "IRLUME_FORCE_NO_IR",
            ];
            let saved = keys
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect();
            for key in keys {
                std::env::remove_var(key);
            }
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

    fn fixture(split: bool) -> Guard {
        let camera = |topology: &str, identity: &str, port: u8, endpoints| Camera {
            topology: topology.into(),
            identity: identity.into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
            endpoints,
        };
        let rgb = Endpoint {
            path: RGB.into(),
            formats: vec![*b"YUYV"],
        };
        let ir = Endpoint {
            path: IR.into(),
            formats: vec![*b"GREY"],
        };
        let cameras = if split {
            vec![
                camera(
                    "/devices/request-fixture/rgb",
                    "1234:0001:rgb",
                    8,
                    vec![rgb],
                ),
                camera("/devices/request-fixture/ir", "1234:0002:ir", 5, vec![ir]),
            ]
        } else {
            vec![camera(
                "/devices/request-fixture/ordinary",
                "1234:0001:ordinary",
                8,
                vec![rgb, ir],
            )]
        };
        assert_eq!(
            irlume_camera::test_support::grey_fixture(),
            [0, 64, 128, 255]
        );
        Guard::install(&cameras).unwrap()
    }

    fn select_split() {
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
        let key = irlume_common::split_key::SplitPairKey::parse_canonical(
            "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5",
        )
        .unwrap();
        irlume_common::split_publish::publish_split(&[record], Some(&key)).unwrap();
    }

    #[test]
    fn selected_split_dispatch_matrix_refuses_before_real_lease_and_trust_write() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("request-preparation-matrix");
        let _environment = Environment::clear();
        let recorder = fixture(true);
        engine.set_devices(RGB, IR);
        select_split();
        let user = users::name_for_uid(0).unwrap();
        write_enrollment(&sb.dir, &enrollment_with(&user, &["Face Scan 1"]));
        let before = std::fs::read(sb.dir.join(format!("{user}.json"))).unwrap();
        let requests = vec![
            Request::Enroll {
                user: user.clone(),
                profile: None,
                scans: Some(1),
                reset: false,
            },
            Request::Enroll {
                user: user.clone(),
                profile: None,
                scans: Some(1),
                reset: true,
            },
            Request::AddScan {
                user: user.clone(),
                profile: "fixture".into(),
                scans: Some(1),
                report_enrollment: true,
            },
            Request::AddCameraGroup {
                user: user.clone(),
                profile: None,
                scans: Some(1),
            },
            Request::Identify,
            Request::IdentifyFor { user: user.clone() },
            Request::PositionSample { user: None },
            Request::PositionSession { user: None },
            Request::SupportProbe { since_ms: 0 },
        ];
        for request in requests {
            let response = dispatch(request, &peer(0), &mut engine);
            assert!(
                matches!(response, Response::Error(ref reason) if reason.contains(ORDINARY)),
                "{response:?}"
            );
            assert!(
                !format!("{response:?}").contains(CLOSED),
                "an ordinary refusal must not blame the closed predicate: {response:?}"
            );
            assert!(recorder.calls().is_empty(), "{:?}", recorder.calls());
        }
        for policy in ["dual", "ir-only-experimental"] {
            std::fs::write(
                sb.dir.join("config/settings.conf"),
                format!("face_sensor_policy={policy}\n"),
            )
            .unwrap();
            let response = dispatch(
                Request::Authenticate {
                    user: user.clone(),
                    service: Some("kscreensaver".into()),
                    structured_errors: false,
                    intent_confirmation: None,
                },
                &peer(0),
                &mut engine,
            );
            assert!(
                matches!(response, Response::Error(ref reason) if reason.contains(ORDINARY)),
                "{response:?}"
            );
            assert!(recorder.calls().is_empty());
        }
        // The actual face-backed release helper retains its normal retry/key
        // ownership. A bogus armed envelope must never reach secret preparation.
        plant_fake_envelope(&user);
        let envelope_path = irlume_core::keyring::envelope_path(&user);
        let envelope_before = std::fs::read(&envelope_path).unwrap();
        let response = do_unseal_password(&user, None, &mut engine);
        assert!(
            matches!(response, Response::Error(ref reason) if reason.contains(ORDINARY)),
            "{response:?}"
        );
        assert!(recorder.calls().is_empty());
        assert_eq!(std::fs::read(envelope_path).unwrap(), envelope_before);
        assert_eq!(
            std::fs::read(sb.dir.join(format!("{user}.json"))).unwrap(),
            before
        );
        engine.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn selected_split_sessions_refuse_before_started_events() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("request-preparation-sessions");
        let _environment = Environment::clear();
        let recorder = fixture(true);
        engine.set_devices(RGB, IR);
        select_split();
        let user = users::name_for_uid(0).unwrap();
        for improve in [false, true] {
            let (worker, mut connection) = enrollment_session::channel(arbiter::CancelToken::new());
            let request = Request::EnrollmentSession {
                user: user.clone(),
                profile: improve.then(|| "fixture".into()),
                scans: 1,
                improve,
            };
            let state = diagnostics::DiagnosticState::default();
            let scope = state.begin_for(
                diagnostic_operation_class(&request),
                diagnostic_owner(&request, &peer(0)),
            );
            let reply = dispatch_scoped_session(
                request,
                &peer(0),
                &mut engine,
                &scope,
                None,
                Some(&worker),
                None,
            );
            assert!(
                matches!(reply.response, Response::Error(ref reason) if reason.contains(ORDINARY)),
                "{:?}",
                reply.response
            );
            let (ours, mut theirs) = UnixStream::pair().unwrap();
            connection.pump(&ours).unwrap();
            theirs.set_nonblocking(true).unwrap();
            let mut byte = [0];
            assert_eq!(
                std::io::Read::read(&mut theirs, &mut byte)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        let (worker, mut connection) = position_session::channel(arbiter::CancelToken::new());
        let request = Request::PositionSession { user: None };
        let state = diagnostics::DiagnosticState::default();
        let scope = state.begin_for(
            diagnostic_operation_class(&request),
            diagnostic_owner(&request, &peer(0)),
        );
        let reply = dispatch_scoped_session(
            request,
            &peer(0),
            &mut engine,
            &scope,
            None,
            None,
            Some(&worker),
        );
        assert!(
            matches!(reply.response, Response::Error(ref reason) if reason.contains(ORDINARY)),
            "{:?}",
            reply.response
        );
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        connection.pump(&ours).unwrap();
        theirs.set_nonblocking(true).unwrap();
        let mut byte = [0];
        assert_eq!(
            std::io::Read::read(&mut theirs, &mut byte)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(recorder.calls().is_empty());
        engine.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn ordinary_position_dispatch_control_reaches_real_lease_and_open() {
        let _guard = env_lock();
        let mut engine = engine();
        let _sb = sandbox("request-preparation-ordinary");
        let _environment = Environment::clear();
        let recorder = fixture(false);
        engine.set_devices(RGB, IR);
        let response = dispatch(
            Request::PositionSample { user: None },
            &peer(0),
            &mut engine,
        );
        assert!(
            matches!(response, Response::Error(_)),
            "non-granting fixture must refuse capture"
        );
        let calls = recorder.calls();
        assert!(
            calls.iter().any(|call| matches!(call, Call::Lease { .. })),
            "{calls:?}"
        );
        assert!(calls.contains(&Call::OpenRgb(RGB.into())), "{calls:?}");
        engine.set_devices(NO_RGB, NO_IR);
    }

    fn operation_choice(user: &str, variant: &str) -> Request {
        let inventory = irlume_auth::camera_inventory_snapshot();
        let candidate = inventory.candidates.iter()
            .find(|camera| camera.endpoint_paths.contains(&RGB.to_owned()))
            .unwrap();
        let mut payload = serde_json::json!({
            "user": user, "profile": null, "scans": 1,
            "pair": {"rgb": RGB, "ir": IR, "expected": {
                "supervisor_id": inventory.supervisor_id,
                "candidate": candidate
            }}
        });
        if variant == "EnrollOn" {
            payload["reset"] = serde_json::json!(true);
        }
        serde_json::from_value(serde_json::json!({variant: payload}))
            .expect("operation-scoped enrollment request must be supported")
    }

    fn split_operation_choice(user: &str, variant: &str, reset: bool) -> Request {
        use irlume_common::split_wire::{SplitCandidateRole, SplitMutationGuard, SplitEnrollmentCameraChoice};
        let Response::SplitInventory(view) = split_list_response(uid_of(user).unwrap(), &irlume_auth::camera_inventory_publication()) else { panic!("listing"); };
        let rgb = view.candidates.iter().find(|c| c.role == SplitCandidateRole::Rgb).unwrap();
        let ir = view.candidates.iter().find(|c| c.role == SplitCandidateRole::Ir).unwrap();
        let pair = Box::new(SplitEnrollmentCameraChoice {
            expected: SplitMutationGuard { supervisor_id: view.supervisor_id, revision: view.revision, rgb: rgb.guard.clone(), ir: ir.guard.clone() },
            authorization: view.authorization.expect("verified listing proof"),
        });
        if variant == "EnrollSplitOn" {
            Request::EnrollSplitOn { user: user.into(), profile: None, scans: Some(1), reset, pair }
        } else {
            Request::AddSplitCameraGroupOn { user: user.into(), profile: None, scans: Some(1), pair }
        }
    }

    #[test]
    fn guarded_split_dispatch_refuses_activation_before_camera_or_account_mutation() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("guarded-split-closed");
        let _environment = Environment::clear();
        let recorder = fixture(true);
        select_split();
        let irlume_common::split_publish::SplitReadState::Valid { records, .. } = irlume_common::split_publish::read_split() else { panic!("verified authorization"); };
        irlume_common::split_publish::publish_split(&records, None).unwrap();
        let user = users::name_for_uid(0).unwrap();
        write_enrollment(&sb.dir, &enrollment_with(&user, &["Face Scan 1"]));
        engine.set_devices(NO_RGB, NO_IR);
        let account = sb.dir.join(format!("{user}.json"));
        let before = std::fs::read(&account).unwrap();
        let config = std::fs::read(sb.dir.join("config/cameras.conf")).unwrap();
        let listing = Request::ListProfiles { user: user.clone(), structured_errors: false, handles: false };
        assert!(matches!(dispatch(listing.clone(), &peer(0), &mut engine), Response::Enrollment { .. }));
        assert!(dispatch_status(&listing, &peer(0)).is_some());
        for (variant, reset) in [("EnrollSplitOn", false), ("EnrollSplitOn", true), ("AddSplitCameraGroupOn", false)] {
            let request = split_operation_choice(&user, variant, reset);
            let response = dispatch(request, &peer(0), &mut engine);
            assert!(matches!(response, Response::Error(ref reason) if reason.contains(CLOSED)), "{response:?}");
            assert!(recorder.calls().is_empty(), "closed activation spent camera work: {:?}", recorder.calls());
            assert_eq!(std::fs::read(&account).unwrap(), before);
            assert_eq!(std::fs::read(sb.dir.join("config/cameras.conf")).unwrap(), config);
            assert_eq!(engine.rgb_device(), NO_RGB);
            assert_eq!(engine.ir_device(), NO_IR);
            assert!(!sb.dir.join("capture-qualifications").exists());
            assert!(dispatch_status(&listing, &peer(0)).is_some(), "closed split request invalidated the published summary");
        }
    }

    #[test]
    fn guarded_split_queued_original_refuses_publication_or_either_side_drift() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("guarded-split-queue-drift");
        let _environment = Environment::clear();
        // SAFETY: credential getters have no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let owner = Peer { uid, gid, pid: std::process::id() as i32 };
        let user = users::name_for_uid(uid).unwrap();
        let _seat = seat_fixture("guarded-split-queue-drift", Some(uid));
        for (variant, drift) in ["EnrollSplitOn", "AddSplitCameraGroupOn"].into_iter().flat_map(|variant| (0..3).map(move |drift| (variant, drift))) {
            let recorder = fixture(true);
            select_split();
            let request = split_operation_choice(&user, variant, true);
            let original = serde_json::to_vec(&request).unwrap();
            let (server, _client) = std::os::unix::net::UnixStream::pair().unwrap();
            let authorization = operation_authorization::authorize_for_test(&request, &owner, &server).unwrap();
            assert_eq!(authorization.is_some(), uid != 0);
            let diagnostics = diagnostics::DiagnosticState::default();
            let scope = diagnostics.begin_for(diagnostic_operation_class(&request), diagnostic_owner(&request, &owner));
            let (reply, _answer) = std::sync::mpsc::channel();
            let class = arbiter::classify(&request);
            let queued = Queued {
                authorization, session: None, position: None, req: request, peer: owner.clone(), reply,
                link: std::sync::Arc::new(ClientLink::default()), scope,
                enqueued_at: std::time::Instant::now(), attempt: None,
            };
            let arbiter = arbiter::Arbiter::<Queued>::new();
            arbiter.submit(class, uid, queued).unwrap();
            match drift {
                0 => select_split(),
                1 => recorder.endpoint_invalidation_observer(RGB)(),
                _ => recorder.endpoint_invalidation_observer(IR)(),
            }
            let queued = arbiter.take().unwrap().payload;
            assert_eq!(serde_json::to_vec(&queued.req).unwrap(), original, "queue refreshed displayed choice");
            let before = std::fs::read(sb.dir.join("config/cameras.conf")).unwrap();
            let response = dispatch_scoped(queued.req, &queued.peer, &mut engine, &queued.scope, queued.authorization);
            assert!(matches!(response, Response::Error(ref why) if why.contains("list and confirm")), "{response:?}");
            assert!(recorder.calls().is_empty());
            assert_eq!(std::fs::read(sb.dir.join("config/cameras.conf")).unwrap(), before);
            assert!(!sb.dir.join(format!("{user}.json")).exists());
            arbiter.close();
        }
    }

    #[test]
    fn guarded_split_socket_refuses_foreign_account_before_approval_and_queue() {
        use std::io::{BufRead as _, BufReader, Write as _};
        let _guard = env_lock();
        let sb = sandbox("guarded-split-socket-refusal");
        let _environment = Environment::clear();
        let recorder = fixture(true);
        select_split();
        let before = std::fs::read(sb.dir.join("config/cameras.conf")).unwrap();
        let user = users::name_for_uid(0).unwrap();
        let arbiter = arbiter::Arbiter::<Queued>::new();
        arbiter.close();
        let ready = std::sync::atomic::AtomicBool::new(true);
        let diagnostics = diagnostics::DiagnosticState::default();
        for variant in ["EnrollSplitOn", "AddSplitCameraGroupOn"] {
            let request = split_operation_choice(&user, variant, false);
            let response = with_serve_as_peer_and_diagnostics(&arbiter, &ready, &diagnostics, peer(NOBODY), |client| {
                serde_json::to_writer(client, &request).unwrap();
                (&*client).write_all(b"\n").unwrap();
                let mut line = String::new();
                BufReader::new(client).read_line(&mut line).unwrap();
                serde_json::from_str::<Response>(&line).unwrap()
            });
            assert!(matches!(response, Response::Error(ref why) if why == &format!("not authorized to enroll '{user}'")), "{response:?}");
        }
        assert!(arbiter.take().is_none());
        assert!(recorder.calls().is_empty());
        assert_eq!(std::fs::read(sb.dir.join("config/cameras.conf")).unwrap(), before);
        assert!(!sb.dir.join("capture-qualifications").exists());
    }

    #[test]
    fn operation_choice_dispatch_uses_chosen_camera_and_restores_standing_pair() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("operation-camera-choice");
        let _environment = Environment::clear();
        let recorder = fixture(false);
        let user = users::name_for_uid(0).unwrap();
        let mut enrollment = enrollment_with(&user, &["Face Scan 1"]);
        enrollment.camera_binding = Some(irlume_core::storage::CameraBinding::Ordinary {
            rgb: Some("standing-camera".into()), ir: Some("standing-camera".into()),
        });
        write_enrollment(&sb.dir, &enrollment);
        engine.set_devices(NO_RGB, NO_IR);
        let before = std::fs::read(sb.dir.join(format!("{user}.json"))).unwrap();
        for variant in ["EnrollOn", "AddCameraGroupOn"] {
            let first_call = recorder.calls().len();
            let response = dispatch(operation_choice(&user, variant), &peer(0), &mut engine);
            assert!(!is_face_grant(&response), "fixture never grants: {response:?}");
            let all_calls = recorder.calls();
            let calls = &all_calls[first_call..];
            assert!(calls.contains(&Call::OpenRgb(RGB.into())),
                "{variant} must capture on the operation's camera, not the standing pair: {response:?} {calls:?}");
            assert!(!calls.contains(&Call::OpenRgb(NO_RGB.into())), "{calls:?}");
            assert_eq!(engine.rgb_device(), NO_RGB);
            assert_eq!(engine.ir_device(), NO_IR);
            assert!(!sb.dir.join("config/cameras.conf").exists());
            assert_eq!(std::fs::read(sb.dir.join(format!("{user}.json"))).unwrap(), before);
        }
    }

    #[test]
    fn operation_choice_nonreset_dispatch_refuses_foreign_primary_before_any_probe() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("operation-choice-primary-dispatch");
        let _environment = Environment::clear();
        let recorder = fixture(false);
        let user = users::name_for_uid(0).unwrap();
        let mut enrollment = enrollment_with(&user, &["Face Scan 1"]);
        enrollment.camera_binding = Some(irlume_core::storage::CameraBinding::Ordinary {
            rgb: Some("standing-primary".into()), ir: Some("standing-primary".into()),
        });
        write_enrollment(&sb.dir, &enrollment);
        let before = std::fs::read(sb.dir.join(format!("{user}.json"))).unwrap();
        let mut request = operation_choice(&user, "EnrollOn");
        if let Request::EnrollOn { reset, .. } = &mut request { *reset = false; }
        let response = dispatch(request, &peer(0), &mut engine);
        assert!(matches!(response, Response::Error(_)), "{response:?}");
        assert!(recorder.calls().is_empty(), "foreign primary reached qualification/probe: {:?}", recorder.calls());
        assert_eq!(std::fs::read(sb.dir.join(format!("{user}.json"))).unwrap(), before);
    }

    #[test]
    fn operation_choice_empty_bound_primary_refuses_before_any_probe() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("operation-choice-empty-bound-primary");
        let _environment = Environment::clear();
        let recorder = fixture(false);
        let user = users::name_for_uid(0).unwrap();
        for binding in [
            irlume_core::storage::CameraBinding::Ordinary {
                rgb: Some("standing-primary".into()), ir: Some("standing-primary".into()),
            },
            irlume_core::storage::CameraBinding::Ordinary { rgb: None, ir: None },
        ] {
            let mut enrollment = enrollment_with(&user, &[]);
            enrollment.camera_binding = Some(binding);
            write_enrollment(&sb.dir, &enrollment);
            let before = std::fs::read(sb.dir.join(format!("{user}.json"))).unwrap();
            let mut request = operation_choice(&user, "EnrollOn");
            if let Request::EnrollOn { reset, .. } = &mut request { *reset = false; }
            let response = dispatch(request, &peer(0), &mut engine);
            assert!(matches!(response, Response::Error(_)), "{response:?}");
            assert!(recorder.calls().is_empty(), "an empty bound primary reached camera work: {:?}", recorder.calls());
            assert_eq!(std::fs::read(sb.dir.join(format!("{user}.json"))).unwrap(), before);
            assert!(!sb.dir.join("capture-qualifications").exists());
        }
    }

    fn publication_attempt() -> irlume_auth::QualificationAttempt {
        use irlume_camera::capture_qualification::*;
        let endpoint = |role| CameraEndpoint::new(
            "ab".repeat(32), 0x046d, 0x085e, None,
            if role == QualifiedStreamRole::Rgb { 0 } else { 2 },
            "/devices/fixture/qualification".into(), role,
            ConnectionContext::new("/devices/fixture/controller".into(), 5_000_000,
                "uvcvideo".into(), "v4l2-uvc".into()).unwrap(),
        ).unwrap();
        let stream = |role, fourcc: &str, height| StreamContract::new(
            role,
            RequestedStream::new(640, height, fourcc.into(), ExactInterval::new(1, 30).unwrap()).unwrap(),
            AcceptedStream::new(640, height, fourcc.into(), 1280, 640 * height * 2,
                0, 8, 1, 1, 0, ExactInterval::new(1, 30).unwrap()).unwrap(),
            if role == QualifiedStreamRole::Rgb { ExactRate::new(15, 2).unwrap() } else { ExactRate::new(15, 1).unwrap() },
        ).unwrap();
        let context = QualificationContext::new(
            endpoint(QualifiedStreamRole::Rgb), endpoint(QualifiedStreamRole::Ir),
            stream(QualifiedStreamRole::Rgb, "YUYV", 480),
            stream(QualifiedStreamRole::Ir, "GREY", 400),
        ).unwrap();
        let arm = ArmEvidence::new(6, 6, 0, 6, 6, 6, 6, 0, 0, 0, 0, 0, 0, 0, 0,
            Default::default(), Default::default(), 0, 140.0, 120.0, 850).unwrap();
        QualificationAttempt::new(1_786_944_000, context, arm.clone(), arm, false,
            AttemptOutcome::ConcurrentQualified, None).unwrap()
    }

    #[test]
    fn operation_choice_qualification_publisher_uses_real_selected_save_composition() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("operation-choice-selected-save");
        let _environment = Environment::clear();
        let recorder = fixture(false);
        let user = users::name_for_uid(0).unwrap();
        let choice = match operation_choice(&user, "EnrollOn") {
            Request::EnrollOn { pair, .. } => pair,
            _ => unreachable!(),
        };
        let request = engine.prepare_enrollment_camera(&choice).unwrap();
        let expected = request.prepared_camera_lease().unwrap();
        let store = irlume_auth::QualificationStore::system();
        let attempt = publication_attempt();
        let record = save_selected_capture_qualification(&store, attempt.clone(), None, Some(&expected)).unwrap();
        assert_eq!(record.revision(), 1);
        let record_path = std::fs::read_dir(sb.dir.join("capture-qualifications")).unwrap()
            .map(|entry| entry.unwrap().path()).find(|path| path.extension().is_some_and(|ext| ext == "json")).unwrap();
        let before = std::fs::read(&record_path).unwrap();
        recorder.invalidation_observer()();
        assert!(matches!(save_selected_capture_qualification(&store, attempt.clone(), Some(1), Some(&expected)),
            Err(irlume_auth::QualificationStoreError::PublicationRefused(_))));
        assert_eq!(std::fs::read(record_path).unwrap(), before);
        assert_eq!(store.load(attempt.context()).unwrap().unwrap().revision(), 1);
        assert!(recorder.calls().is_empty());
    }

    #[test]
    fn operation_choice_nonroot_socket_refuses_foreign_account_before_queueing() {
        use std::io::{BufRead as _, BufReader, Write as _};
        let _guard = env_lock();
        let sb = sandbox("operation-choice-socket-refusal");
        let _environment = Environment::clear();
        let recorder = fixture(false);
        let user = users::name_for_uid(0).unwrap();
        let arbiter = arbiter::Arbiter::<Queued>::new();
        arbiter.close();
        let ready = std::sync::atomic::AtomicBool::new(true);
        let diagnostics = diagnostics::DiagnosticState::default();
        for variant in ["EnrollOn", "AddCameraGroupOn"] {
            let request = operation_choice(&user, variant);
            let response = with_serve_as_peer_and_diagnostics(&arbiter, &ready, &diagnostics, peer(NOBODY), |client| {
                serde_json::to_writer(client, &request).unwrap();
                (&*client).write_all(b"\n").unwrap();
                let mut line = String::new();
                BufReader::new(client).read_line(&mut line).unwrap();
                serde_json::from_str::<Response>(&line).unwrap()
            });
            assert!(matches!(response, Response::Error(ref message) if message == &format!("not authorized to enroll '{user}'")), "{response:?}");
        }
        assert!(arbiter.take().is_none());
        assert!(recorder.calls().is_empty());
        assert!(!sb.dir.join("capture-qualifications").exists());
        assert!(!sb.dir.join("config/cameras.conf").exists());
    }

    #[test]
    fn automatic_enrolled_pair_defers_standing_tier_and_retains_admitted_charges() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("automatic-account-dispatch");
        let _environment = Environment::clear();
        let recorder = fixture(false);
        engine.set_devices(RGB, IR);
        assert_eq!(engine.tier(), irlume_core::biopolicy::Tier::Convenience);
        let user = users::name_for_uid(0).unwrap();
        let mut enrollment = enrollment_with(&user, &["Face Scan 1"]);
        enrollment.camera_binding = Some(irlume_core::storage::CameraBinding::Ordinary {
            rgb: Some("1234:0001:ordinary".into()), ir: Some("1234:0001:ordinary".into()),
        });
        write_enrollment(&sb.dir, &enrollment);
        let request = |service: &str| Request::Authenticate {
            user: user.clone(), service: Some(service.into()), structured_errors: false, intent_confirmation: None,
        };
        let response = dispatch(request("gdm-password"), &peer(0), &mut engine);
        assert!(!is_face_grant(&response), "fixture never grants: {response:?}");
        assert!(recorder.calls().contains(&Call::OpenRgb(RGB.into())), "standing convenience tier denied before automatic selection: {response:?}");
        let record_path = sb.dir.join("retry/0.json");
        let record: serde_json::Value = serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        assert_eq!(record["budget"]["unsuccessful_requests"], 1);

        // Reset only standing availability. The enrolled route remains Secure,
        // and its late remote-service refusal must retain the reserved charge.
        engine.set_devices(RGB, IR);
        std::fs::write(sb.dir.join("config/settings.conf"), "enforce_biopolicy=1\n").unwrap();
        let before = recorder.calls();
        let response = dispatch(request("sshd"), &peer(0), &mut engine);
        assert!(matches!(response, Response::Error(ref reason) if reason.contains("biopolicy")), "{response:?}");
        assert_eq!(recorder.calls(), before, "late selected-tier refusal acquired a camera");
        let record: serde_json::Value = serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        assert_eq!(record["budget"]["unsuccessful_requests"], 2);
        assert_eq!(record["budget"]["pending"], true);
        engine.set_devices(NO_RGB, NO_IR);
    }
}
