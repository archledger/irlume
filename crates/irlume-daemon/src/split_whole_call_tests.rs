// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// ADR-0032 / #1030: original Requests enter the complete daemon worker handler,
// real Engine entry, publishers and WorkerReply socket responder. Only assessed
// camera evidence is scripted. This runner skips request parsing, serve/queue and
// SO_PEERCRED; its constructed root Peer is not proof of filesystem ownership.
// All thread-local guards live on the actual Engine execution thread. Arithmetic
// vectors are generated here, with no captured biometric or model fixture files.

mod split_whole_call {
    use super::*;
    use irlume_auth::test_support::{
        assessment, AssessmentContext, Guard as AssessmentGuard, PadInput,
    };
    use irlume_camera::lease::{CameraOperationKind, SplitLeaseRequest};
    use irlume_camera::test_support::{Call, Camera, Endpoint, Guard as CameraGuard};
    use irlume_common::split_key::{SplitDomain, SplitPairKey};
    use irlume_common::split_schema::{AuthorizationRecord, SideFields};
    use irlume_common::split_wire::{
        SplitCandidateRole, SplitEnrollmentCameraChoice, SplitMutationGuard,
    };
    use irlume_core::keyring::test_support::UnsealObserver;
    use irlume_core::multi_camera::{
        CameraGroupId, GroupPair, SecondaryGroup, SecondaryProfileScans, SecondaryStore,
        SECONDARY_STORE_VERSION,
    };
    use irlume_core::storage::CameraBinding;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    const RGB: &str = "/dev/irlume-whole-call-rgb";
    const IR: &str = "/dev/irlume-whole-call-ir";
    const PROFILE: &str = "Arithmetic Profile";
    const KEY: &str = "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5";
    const OTHER_KEY: &str =
        "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|6";

    include!("split_whole_call_boundary_tests.rs");
    include!("split_whole_call_credential_tests.rs");
    include!("split_whole_call_centroid_tests.rs");
    include!("split_whole_call_publication_tests.rs");

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
                "IRLUME_RATE_LIMIT",
                "IRLUME_RATE_COOLDOWN_SECS",
            ];
            let saved = keys
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect();
            for key in keys {
                std::env::remove_var(key);
            }
            std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-whole-call-tpm");
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

    fn key() -> SplitPairKey {
        SplitPairKey::parse_canonical(KEY).unwrap()
    }

    fn record() -> AuthorizationRecord {
        let side = |identity: &str, path: &str, port| SideFields {
            identity: identity.into(),
            path: path.into(),
            controller: "0000:00:14.0".into(),
            domain: SplitDomain::Usb2,
            ports: vec![port],
        };
        AuthorizationRecord {
            rgb: side("1234:0001:rgb", RGB, 8),
            ir: side("1234:0002:ir", IR, 5),
        }
    }

    fn authorize(pinned: bool) {
        irlume_common::split_publish::publish_split(&[record()], pinned.then_some(&key())).unwrap();
    }

    fn camera_fixture() -> CameraGuard {
        let camera = |topology: &str, identity: &str, port, path: &str, format| Camera {
            topology: topology.into(),
            identity: identity.into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: SplitDomain::Usb2,
            ports: vec![port],
            endpoints: vec![Endpoint {
                path: path.into(),
                formats: vec![format],
            }],
        };
        CameraGuard::install(&[
            camera("/devices/whole-call/rgb", "1234:0001:rgb", 8, RGB, *b"YUYV"),
            camera("/devices/whole-call/ir", "1234:0002:ir", 5, IR, *b"GREY"),
        ])
        .unwrap()
    }

    fn expected() -> SplitLeaseRequest {
        let irlume_common::split_publish::SplitReadState::Valid { records, .. } =
            irlume_common::split_publish::read_split()
        else {
            panic!("fixture authorization must verify");
        };
        let mut view = irlume_camera::connected_pairs_with_split(&records);
        assert_eq!(view.split_pairs.len(), 1);
        view.split_pairs.remove(0).lease_request()
    }

    fn lease(kind: CameraOperationKind) -> Call {
        Call::Lease {
            endpoints: vec![RGB.into(), IR.into()],
            kind,
        }
    }

    fn probe(cosine: f32) -> [f32; 512] {
        let mut vector = [0.0; 512];
        vector[0] = cosine;
        vector[1] = (1.0 - cosine * cosine).sqrt();
        vector
    }

    fn sample(rgb: f32, ir: f32, skew_ms: u64, split: bool) -> irlume_auth::Assessment {
        let mut a = assessment(PadInput::Score(0.1), PadInput::Score(0.1));
        a.verdict = irlume_liveness::Verdict::Live;
        a.reason = "constructed live assessment".into();
        a.embedding = Some(probe(rgb));
        a.ir_embedding = Some(probe(ir).to_vec());
        a.signals.rgb_face = Some(irlume_liveness::FaceBox {
            cx: 0.5,
            cy: 0.5,
            score: 0.9,
        });
        a.signals.ir_face = a.signals.rgb_face;
        a.signals.rgb_face_brightness = 130.0;
        a.signals.head_pitch_frac = 0.5;
        a.ir_center_edge_ratio = 1.3;
        a.ir_brightness = 35.0;
        a.rgb_frame_mean = 120.0;
        // Supplied assessment posture, not elapsed physical-camera timing.
        // At <=3s, split provenance must independently block RGB/fusion.
        a.sequential_pair = skew_ms > 3000;
        a.split_pair = split;
        a
    }

    fn script(
        kind: CameraOperationKind,
        limit: usize,
        mut next: impl FnMut(&AssessmentContext) -> irlume_common::Result<irlume_auth::Assessment>
            + 'static,
    ) -> AssessmentGuard {
        let expected = expected();
        let retained = expected.clone();
        AssessmentGuard::install(expected, kind, move |context| {
            assert_eq!(context.expected, retained, "original two-incarnation route");
            assert_eq!(context.kind, kind);
            assert!(
                context.index < limit,
                "unexpected extra assessment: {}",
                context.index
            );
            next(context)
        })
        .unwrap()
    }

    fn primary(user: &str, engine: &irlume_auth::Engine, binding: CameraBinding) -> Enrollment {
        let mut enrollment = Enrollment::new(user);
        enrollment.camera_binding = Some(binding);
        enrollment.profiles.push(FaceProfile {
            name: PROFILE.into(),
            scans: vec![FaceScan {
                name: "Arithmetic Scan".into(),
                rgb: probe(1.0).to_vec(),
                ir: Some(probe(1.0).to_vec()),
                ir_space: Some(engine.ir_space().into()),
                embed_space: Some(engine.embed_space().into()),
                embed_producer: None,
                ir_center_edge_ratio: 1.3,
                ir_brightness: 35.0,
                pitch: 0.5,
                captured_at: None,
            }],
            ir_calib: None,
            ir_calibs: Default::default(),
        });
        enrollment
    }

    fn absent_binding() -> CameraBinding {
        CameraBinding::Ordinary {
            rgb: Some("absent-primary".into()),
            ir: Some("absent-primary".into()),
        }
    }

    fn plant_account(sb: &Sandbox, user: &str, engine: &irlume_auth::Engine, secondary: bool) {
        let enrollment = primary(
            user,
            engine,
            if secondary {
                absent_binding()
            } else {
                CameraBinding::Split(key())
            },
        );
        plant_enrollment(sb, user, &enrollment, secondary, false);
    }

    fn plant_enrollment(
        sb: &Sandbox,
        user: &str,
        enrollment: &Enrollment,
        secondary: bool,
        protected: bool,
    ) {
        if protected {
            // Only swtpm-only callers with an explicit transport may take this branch.
            irlume_core::storage::save(enrollment).unwrap();
        } else {
            write_enrollment(&sb.dir, enrollment);
        }
        if secondary {
            let store = SecondaryStore {
                format_version: SECONDARY_STORE_VERSION,
                owner: user.into(),
                generation: 1,
                primary_snapshot_sha256: irlume_common::sha256_hex(
                    &std::fs::read(primary_path(sb, user)).unwrap(),
                ),
                groups: vec![SecondaryGroup {
                    id: CameraGroupId::new("arithmetic-split".into()).unwrap(),
                    pair: GroupPair::Split(key()),
                    profiles: vec![SecondaryProfileScans {
                        profile: PROFILE.into(),
                        scans: enrollment.profiles[0].scans.clone(),
                        ir_calibs: enrollment.profiles[0].ir_calibs.clone(),
                    }],
                }],
            };
            irlume_core::multi_camera::save_secondary(
                &irlume_core::multi_camera::secondary_store_path(user),
                &store,
            )
            .unwrap();
        }
    }

    fn primary_path(sb: &Sandbox, user: &str) -> PathBuf {
        sb.dir.join(format!("{user}.json"))
    }

    fn private_sandbox(tag: &str) -> Sandbox {
        let sb = sandbox(tag);
        // Retry's trusted parent is private even under a developer's umask 0002.
        std::fs::set_permissions(&sb.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        sb
    }

    fn retry_path(sb: &Sandbox, user: &str) -> PathBuf {
        sb.dir.join(format!("retry/{}.json", uid_of(user).unwrap()))
    }

    fn retry(sb: &Sandbox, user: &str) -> serde_json::Value {
        serde_json::from_slice(
            &std::fs::read(retry_path(sb, user)).expect("real charged retry record"),
        )
        .unwrap()
    }

    fn authenticate(user: &str) -> Request {
        Request::Authenticate {
            user: user.into(),
            service: Some("login".into()),
            intent_confirmation: None,
            structured_errors: false,
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Entry {
        Authenticate,
        UnsealPassword,
    }

    const ENTRIES: [Entry; 2] = [Entry::Authenticate, Entry::UnsealPassword];

    impl Entry {
        fn request(self, user: &str) -> Request {
            match self {
                Self::Authenticate => authenticate(user),
                Self::UnsealPassword => Request::UnsealPassword {
                    user: user.into(),
                    service: Some("login".into()),
                },
            }
        }
    }

    fn known_user() -> String {
        // SAFETY: geteuid has no preconditions.
        users::name_for_uid(unsafe { libc::geteuid() }).unwrap()
    }

    fn assert_refused(
        reply: WorkerReply,
        sb: &Sandbox,
        user: &str,
        observer: &UnsealObserver,
    ) -> Response {
        assert!(
            !is_face_grant(&reply.response),
            "a boundary refusal cannot grant"
        );
        assert!(reply.completion.is_none());
        let response = delivered(reply);
        assert!(!is_face_grant(&response));
        assert_eq!(
            (observer.calls(), observer.successes()),
            (0, 0),
            "refused before credential entry"
        );
        assert_eq!(
            retry(sb, user)["budget"]["unsuccessful_requests"],
            1,
            "refusal keeps its exact charge"
        );
        response
    }

    // Returns the full worker reply rather than dispatch()'s Response, so the
    // real FaceCompletion survives until the real responder writes the grant.
    fn worker_reply(req: Request, engine: &mut irlume_auth::Engine) -> WorkerReply {
        let root = peer(0);
        let state = diagnostics::DiagnosticState::default();
        let scope = state.begin_for(
            diagnostic_operation_class(&req),
            diagnostic_owner(&req, &root),
        );
        dispatch_scoped_session(req, &root, engine, &scope, None, None, None)
    }

    fn delivered(reply: WorkerReply) -> Response {
        let (server, mut client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        reply.respond(server).expect("real admitted socket write");
        let mut wire = zeroize::Zeroizing::new(Vec::new());
        client
            .read_to_end(&mut wire)
            .expect("responder closes after one reply");
        assert_eq!(
            wire.iter().filter(|byte| **byte == b'\n').count(),
            1,
            "exactly one response"
        );
        serde_json::from_slice(&wire).expect("actual socket response")
    }

    fn assert_granted(reply: &Response) {
        assert!(
            matches!(reply, Response::AuthResult { granted: true, live: true, reason, .. } if reason.contains("ir-fallback")),
            "IR-identity arm: {reply:?}"
        );
    }

    fn assert_reset(sb: &Sandbox, user: &str) {
        let record = retry(sb, user);
        assert_eq!(record["budget"]["unsuccessful_requests"], 0);
        assert_eq!(record["budget"]["pending"], false);
        assert_eq!(record["strikes"], 0);
        assert!(record["cooldown"].is_null());
    }

    fn enrollment_request(user: &str, reset: bool, add_group: bool) -> Request {
        let Response::SplitInventory(view) =
            split_list_response(0, &irlume_auth::camera_inventory_publication())
        else {
            panic!("split listing");
        };
        let side = |role| {
            view.candidates
                .iter()
                .find(|candidate| candidate.role == role)
                .unwrap()
                .guard
                .clone()
        };
        let rgb = side(SplitCandidateRole::Rgb);
        let ir = side(SplitCandidateRole::Ir);
        let pair = Box::new(SplitEnrollmentCameraChoice {
            expected: SplitMutationGuard {
                supervisor_id: view.supervisor_id,
                revision: view.revision,
                rgb,
                ir,
            },
            authorization: view.authorization.expect("verified opaque proof"),
        });
        if add_group {
            Request::AddSplitCameraGroupOn {
                user: user.into(),
                profile: Some(PROFILE.into()),
                scans: Some(2),
                pair,
            }
        } else {
            Request::EnrollSplitOn {
                user: user.into(),
                profile: Some(PROFILE.into()),
                scans: Some(2),
                reset,
                pair,
            }
        }
    }

    fn assert_no_intent(user: &str) {
        let secondary = irlume_core::multi_camera::secondary_store_path(user);
        assert!(!irlume_core::multi_camera::commit::intent_path_for(&secondary).exists());
    }

    fn run_publication(reset: bool, add_group: bool) {
        let mut engine = engine();
        let _environment = Environment::clear();
        let _no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let user = users::name_for_uid(uid).unwrap();
        for pinned in [false, true] {
            let sb = private_sandbox("split-whole-publication");
            engine.set_devices(NO_RGB, NO_IR);
            let camera = camera_fixture();
            let counts = camera.lease_counts_observer();
            authorize(pinned);
            let config = std::fs::read(sb.dir.join("config/cameras.conf")).unwrap();
            if reset || add_group {
                let mut old = primary(&user, &engine, absent_binding());
                if reset {
                    old.profiles[0].name = "Old Profile".into();
                }
                write_enrollment(&sb.dir, &old);
            }
            let before = std::fs::read(primary_path(&sb, &user)).ok();
            {
                let _admit = camera.admit_split_trust(&[CameraOperationKind::Enrollment]);
                let samples = script(CameraOperationKind::Enrollment, 10, move |_| {
                    Ok(sample(1.0, 1.0, 2999, true))
                });
                let reply = delivered(worker_reply(
                    enrollment_request(&user, reset, add_group),
                    &mut engine,
                ));
                assert_eq!(
                    samples.calls(),
                    10,
                    "five raw PAD votes per loop; response={reply:?}"
                );
                if add_group {
                    assert!(matches!(reply, Response::Ok(_)), "{reply:?}");
                    assert_eq!(
                        std::fs::read(primary_path(&sb, &user)).unwrap(),
                        before.unwrap()
                    );
                    let store = irlume_core::multi_camera::load_secondary(
                        &irlume_core::multi_camera::secondary_store_path(&user),
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(store.owner, user);
                    assert_eq!(store.generation, 1);
                    assert_eq!(
                        store.primary_snapshot_sha256,
                        irlume_common::sha256_hex(
                            &std::fs::read(primary_path(&sb, &user)).unwrap()
                        )
                    );
                    assert_eq!(store.groups.len(), 1);
                    assert_eq!(store.groups[0].pair, GroupPair::Split(key()));
                    assert_eq!(store.groups[0].profiles[0].profile, PROFILE);
                    assert_eq!(store.groups[0].profiles[0].scans.len(), 2);
                } else {
                    assert!(
                        matches!(&reply, Response::Enrolled { profile, created: true, added: 2, total: 2, .. } if profile == PROFILE),
                        "{reply:?}"
                    );
                    let stored = irlume_core::storage::load_unmoved(&user).unwrap().unwrap();
                    assert_eq!(stored.camera_binding, Some(CameraBinding::Split(key())));
                    assert_eq!(stored.profiles.len(), 1);
                    assert_eq!(stored.profiles[0].name, PROFILE);
                    assert_eq!(stored.profiles[0].scans.len(), 2);
                    assert!(stored.profiles[0].scans.iter().all(|scan| scan.ir.is_some()
                        && scan.ir_space.as_deref() == Some(engine.ir_space())
                        && scan.embed_space.as_deref() == Some(engine.embed_space())));
                }
            }
            assert_eq!(
                camera.calls(),
                vec![lease(CameraOperationKind::Enrollment); 2]
            );
            assert_eq!(counts(), (0, 0));
            assert_no_intent(&user);
            assert!(!sb.dir.join("capture-qualifications").exists());
            assert_eq!(
                std::fs::read(sb.dir.join("config/cameras.conf")).unwrap(),
                config
            );
            assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
            // A fresh call uses only the just-published enrollment; no seed or
            // hand-installed route/account scope appears between these calls.
            let published = std::fs::read(primary_path(&sb, &user)).unwrap();
            let _admit = camera.admit_split_trust(&[CameraOperationKind::Authentication]);
            let samples = script(CameraOperationKind::Authentication, 5, move |_| {
                Ok(sample(0.5, 0.8, 2999, true))
            });
            let reply = worker_reply(authenticate(&user), &mut engine);
            assert_granted(&reply.response);
            assert!(reply.completion.is_some());
            assert_eq!(retry(&sb, &user)["budget"]["unsuccessful_requests"], 1);
            assert_eq!(retry(&sb, &user)["budget"]["pending"], true);
            assert_granted(&delivered(reply));
            assert_reset(&sb, &user);
            assert_eq!(samples.calls(), 5);
            assert_eq!(
                camera.calls(),
                vec![
                    lease(CameraOperationKind::Enrollment),
                    lease(CameraOperationKind::Enrollment),
                    lease(CameraOperationKind::Authentication)
                ]
            );
            assert_eq!(counts(), (0, 0));
            assert_eq!(std::fs::read(primary_path(&sb, &user)).unwrap(), published);
            assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
        }
    }

    #[test]
    fn split_whole_nonreset_publishes_and_the_next_authenticate_routes() {
        let _guard = env_lock();
        run_publication(false, false);
    }

    #[test]
    fn split_whole_reset_publishes_and_the_next_authenticate_routes() {
        let _guard = env_lock();
        run_publication(true, false);
    }

    #[test]
    fn split_whole_add_group_publishes_and_the_next_authenticate_routes() {
        let _guard = env_lock();
        run_publication(false, true);
    }

    #[test]
    fn split_whole_authenticate_requires_ir_identity_at_each_skew_and_clears_delivered_charge() {
        let _guard = env_lock();
        let mut engine = engine();
        let _environment = Environment::clear();
        let _no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let user = users::name_for_uid(0).unwrap();
        for pinned in [false, true] {
            for secondary in [false, true] {
                for skew in [2999, 3000, 3001] {
                    for rgb in [0.9, 0.5] {
                        let row =
                            format!("pin={pinned}, secondary={secondary}, skew={skew}, rgb={rgb}");
                        let sb = private_sandbox("split-whole-identity");
                        engine.set_devices(NO_RGB, NO_IR);
                        let camera = camera_fixture();
                        let counts = camera.lease_counts_observer();
                        let _admit =
                            camera.admit_split_trust(&[CameraOperationKind::Authentication]);
                        authorize(pinned);
                        plant_account(&sb, &user, &engine, secondary);
                        let before = std::fs::read(primary_path(&sb, &user)).unwrap();
                        {
                            let samples =
                                script(CameraOperationKind::Authentication, 5, move |_| {
                                    Ok(sample(rgb, 0.4, skew, true))
                                });
                            let response =
                                delivered(worker_reply(authenticate(&user), &mut engine));
                            assert_eq!(
                                samples.calls(),
                                5,
                                "{row}: real PAD retries; response={response:?}"
                            );
                            assert!(
                                matches!(
                                    response,
                                    Response::AuthResult {
                                        granted: false,
                                        live: true,
                                        ..
                                    }
                                ),
                                "{row}: {response:?}"
                            );
                            assert_eq!(
                                retry(&sb, &user)["budget"]["unsuccessful_requests"],
                                1,
                                "{row}"
                            );
                        }
                        {
                            let samples =
                                script(CameraOperationKind::Authentication, 5, move |_| {
                                    Ok(sample(rgb, 0.8, skew, true))
                                });
                            let reply = worker_reply(authenticate(&user), &mut engine);
                            assert_granted(&reply.response);
                            assert_eq!(
                                retry(&sb, &user)["budget"]["unsuccessful_requests"],
                                2,
                                "grant remains charged before delivery"
                            );
                            assert_granted(&delivered(reply));
                            assert_reset(&sb, &user);
                            assert_eq!(samples.calls(), 5, "{row}");
                        }
                        assert_eq!(
                            camera.calls(),
                            vec![lease(CameraOperationKind::Authentication); 2],
                            "{row}"
                        );
                        assert_eq!(counts(), (0, 0), "{row}");
                        assert_eq!(
                            std::fs::read(primary_path(&sb, &user)).unwrap(),
                            before,
                            "no adaptation"
                        );
                        assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
                    }
                }
            }
        }
    }

    #[test]
    fn split_whole_undelivered_authenticate_grant_keeps_its_charge() {
        let _guard = env_lock();
        let mut engine = engine();
        let _environment = Environment::clear();
        let _no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let user = users::name_for_uid(0).unwrap();
        for pinned in [false, true] {
            let sb = private_sandbox("split-whole-undelivered");
            engine.set_devices(NO_RGB, NO_IR);
            let camera = camera_fixture();
            let _admit = camera.admit_split_trust(&[CameraOperationKind::Authentication]);
            authorize(pinned);
            plant_account(&sb, &user, &engine, false);
            let samples = script(CameraOperationKind::Authentication, 5, move |_| {
                Ok(sample(0.5, 0.8, 3000, true))
            });
            let reply = worker_reply(authenticate(&user), &mut engine);
            assert_granted(&reply.response);
            let (server, client) = UnixStream::pair().unwrap();
            drop(client);
            assert!(
                reply.respond(server).is_err(),
                "closed peer cannot receive a grant"
            );
            assert_eq!(retry(&sb, &user)["budget"]["unsuccessful_requests"], 1);
            assert_eq!(retry(&sb, &user)["budget"]["pending"], true);
            assert_eq!(samples.calls(), 5);
            assert_eq!(camera.lease_counts_observer()(), (0, 0));
        }
    }
}
