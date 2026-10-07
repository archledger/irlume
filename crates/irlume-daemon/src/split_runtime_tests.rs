// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// The retained split enrollment handlers (ADR-0032 Step 5, plan D5 and D6;
// acceptance cases 11, 12, 14 and 15). `EnrollSplitOn`, reset or not, and
// `AddSplitCameraGroupOn` run the dedicated Engine split entry on the
// original retained split choice, only after the approval, the explicit
// activation gate and, for enrollment, the primary check. The camera fixture
// refuses every open, so an admitted handler ends at the RGB side. The
// admission is a test-support token on this thread; no shipped build has it.

mod split_runtime_gates {
    use super::*;
    use irlume_camera::lease::CameraOperationKind;
    use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
    use irlume_common::split_key::SplitPairKey;
    use irlume_common::split_schema::{AuthorizationRecord, SideFields};
    use irlume_core::storage::CameraBinding;

    const RGB: &str = "/dev/irlume-split-runtime-rgb";
    const IR: &str = "/dev/irlume-split-runtime-ir";
    const CLOSED: &str = "split enrollment and authentication are not enabled";
    const IR_OFF: &str = "split camera trust needs both sides and IR is unavailable or forced off";
    const OTHER_CAMERA: &str = "belongs to another or unbound camera";
    const KEY: &str =
        "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5";
    /// The same two devices with the IR side on another port: another
    /// complete key.
    const OTHER_KEY: &str =
        "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|6";
    /// The fixed replies a peer other than root gets (plan D6).
    const ENROLL_REFUSED: &str = "split camera enrollment did not complete";
    const GROUP_REFUSED: &str = "split camera group enrollment did not complete";
    const GROUP_ENROLLED: &str =
        "split camera group enrolled; it can now authenticate this account";
    /// What no reply to a peer other than root may carry (ADR-0032 section 6):
    /// an identity or the group id seeded from one, a node or topology path,
    /// the raw controller or the complete binding key.
    const FORBIDDEN: [&str; 8] = [
        "1234:0001",
        "1234:0002",
        "1234-0001",
        "/dev/",
        "/devices/",
        "0000:00:14.0",
        "split1;",
        "cam-1234",
    ];
    const VARIANTS: [(&str, bool); 3] = [
        ("EnrollSplitOn", false),
        ("EnrollSplitOn", true),
        ("AddSplitCameraGroupOn", false),
    ];

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
            std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-split-runtime-tpm");
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
    /// and a native GREY IR side. Every open is refused and recorded.
    fn fixture() -> Guard {
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
        Guard::install(&[
            camera("/devices/split-runtime/rgb", "1234:0001:rgb", 8, RGB, *b"YUYV"),
            camera("/devices/split-runtime/ir", "1234:0002:ir", 5, IR, *b"GREY"),
        ])
        .unwrap()
    }

    /// The administrator authorization for the fixture pair, with no saved
    /// selection: an operation choice needs the authorization only.
    fn authorize() {
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
        irlume_common::split_publish::publish_split(&[record], None).unwrap();
    }

    /// The original request as a client sends it: the displayed guards and
    /// the listing's authorization proof for the one authorized pair.
    fn choice(user: &str, variant: &str, reset: bool) -> Request {
        use irlume_common::split_wire::{
            SplitCandidateRole, SplitEnrollmentCameraChoice, SplitMutationGuard,
        };
        let Response::SplitInventory(view) = split_list_response(
            uid_of(user).unwrap(),
            &irlume_auth::camera_inventory_publication(),
        ) else {
            panic!("listing");
        };
        let side = |role| {
            view.candidates
                .iter()
                .find(|candidate| candidate.role == role)
                .unwrap()
                .guard
                .clone()
        };
        let pair = Box::new(SplitEnrollmentCameraChoice {
            expected: SplitMutationGuard {
                supervisor_id: view.supervisor_id,
                revision: view.revision,
                rgb: side(SplitCandidateRole::Rgb),
                ir: side(SplitCandidateRole::Ir),
            },
            authorization: view.authorization.expect("verified listing proof"),
        });
        if variant == "EnrollSplitOn" {
            Request::EnrollSplitOn {
                user: user.into(),
                profile: None,
                scans: Some(1),
                reset,
                pair,
            }
        } else {
            Request::AddSplitCameraGroupOn {
                user: user.into(),
                profile: None,
                scans: Some(1),
                pair,
            }
        }
    }

    /// A primary each handler accepts: one bound to this split pair for a
    /// non-reset enrollment, a standing ordinary primary for a reset or a
    /// group addition.
    fn primary(user: &str, variant: &str, reset: bool) -> Enrollment {
        let mut enrollment = enrollment_with(user, &["Face Scan 1"]);
        enrollment.camera_binding = Some(if variant == "EnrollSplitOn" && !reset {
            CameraBinding::Split(SplitPairKey::parse_canonical(KEY).unwrap())
        } else {
            CameraBinding::Ordinary {
                rgb: Some("standing-primary".into()),
                ir: Some("standing-primary".into()),
            }
        });
        enrollment
    }

    fn split_lease() -> Call {
        Call::Lease {
            endpoints: vec![RGB.into(), IR.into()],
            kind: CameraOperationKind::Enrollment,
        }
    }

    fn listing(user: &str) -> Request {
        Request::ListProfiles {
            user: user.into(),
            structured_errors: false,
            handles: false,
        }
    }

    /// Publish `user`'s enrollment summary through a worker-side listing.
    fn publish_summary(engine: &mut irlume_auth::Engine, user: &str) {
        assert!(matches!(
            dispatch(listing(user), &peer(0), engine),
            Response::Enrollment { .. }
        ));
        assert!(summary_published(user));
    }

    fn summary_published(user: &str) -> bool {
        dispatch_status(&listing(user), &peer(0)).is_some()
    }

    fn no_secondary_publication(user: &str) -> bool {
        let path = irlume_core::multi_camera::secondary_store_path(user);
        !path.exists() && !irlume_core::multi_camera::commit::intent_path_for(&path).exists()
    }

    fn refused(variant: &str) -> &'static str {
        if variant == "EnrollSplitOn" {
            ENROLL_REFUSED
        } else {
            GROUP_REFUSED
        }
    }

    fn wire(response: &Response) -> String {
        serde_json::to_string(response).unwrap()
    }

    // RED: these need the dedicated split handlers (plan D5, D6).

    #[test]
    fn split_runtime_admitted_enrollment_leases_both_sides_then_meets_the_refused_rgb_open() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("split-runtime-admitted");
        let _environment = Environment::clear();
        engine.set_devices(NO_RGB, NO_IR);
        let user = users::name_for_uid(0).unwrap();
        let account = sb.dir.join(format!("{user}.json"));
        for (variant, reset) in VARIANTS {
            let recorder = fixture();
            let counts = recorder.lease_counts_observer();
            let _admitted = recorder.admit_split_trust(&[CameraOperationKind::Enrollment]);
            authorize();
            write_enrollment(&sb.dir, &primary(&user, variant, reset));
            publish_summary(&mut engine, &user);
            let before = std::fs::read(&account).unwrap();
            let response = dispatch(choice(&user, variant, reset), &peer(0), &mut engine);
            let Response::Error(reason) = &response else {
                panic!("{variant}/{reset}: the refusing fixture cannot enroll: {response:?}");
            };
            assert!(
                !reason.contains(CLOSED),
                "{variant}/{reset}: an admitted handler must run its Engine split entry: {reason}"
            );
            assert_eq!(
                recorder.calls(),
                vec![split_lease(), Call::OpenRgb(RGB.into())],
                "{variant}/{reset}: one split Enrollment lease over both original sides, then \
                 the sequential RGB attempt only: no probe, no qualification read, no \
                 single-endpoint lease and no IR open after the refused RGB side"
            );
            assert_eq!(counts(), (0, 0), "{variant}/{reset}: both reservations released");
            assert_eq!(std::fs::read(&account).unwrap(), before, "{variant}/{reset}");
            assert!(no_secondary_publication(&user), "{variant}/{reset}: no secondary intent");
            assert!(
                !sb.dir.join("capture-qualifications").exists(),
                "{variant}/{reset}: the split route reads and writes no qualification"
            );
            assert_eq!(
                (engine.rgb_device(), engine.ir_device()),
                (NO_RGB, NO_IR),
                "{variant}/{reset}: the request scope restores the standing pair"
            );
            assert!(
                !summary_published(&user),
                "{variant}/{reset}: past every gate the summary is dropped before the Engine entry"
            );
        }
    }

    #[test]
    fn split_runtime_admitted_enrollment_without_ir_refuses_before_any_lease() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("split-runtime-ir-off");
        let _environment = Environment::clear();
        engine.set_devices(NO_RGB, NO_IR);
        let user = users::name_for_uid(0).unwrap();
        let account = sb.dir.join(format!("{user}.json"));
        for (variant, reset) in VARIANTS {
            let recorder = fixture();
            let _admitted = recorder.admit_split_trust(&[CameraOperationKind::Enrollment]);
            authorize();
            write_enrollment(&sb.dir, &primary(&user, variant, reset));
            let before = std::fs::read(&account).unwrap();
            let request = choice(&user, variant, reset);
            std::env::set_var("IRLUME_FORCE_NO_IR", "1");
            let response = dispatch(request, &peer(0), &mut engine);
            std::env::remove_var("IRLUME_FORCE_NO_IR");
            assert!(
                matches!(response, Response::Error(ref reason) if reason.contains(IR_OFF)),
                "{variant}/{reset}: no RGB-only or convenience split enrollment: {response:?}"
            );
            assert!(
                recorder.calls().is_empty(),
                "{variant}/{reset}: refused before any lease: {:?}",
                recorder.calls()
            );
            assert_eq!(std::fs::read(&account).unwrap(), before, "{variant}/{reset}");
            assert!(no_secondary_publication(&user), "{variant}/{reset}");
            assert!(!sb.dir.join("capture-qualifications").exists());
            assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
        }
    }

    #[test]
    fn split_runtime_non_root_replies_carry_only_static_per_variant_reasons() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("split-runtime-redaction");
        let _environment = Environment::clear();
        engine.set_devices(NO_RGB, NO_IR);
        // SAFETY: credential getters have no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let owner = Peer {
            uid,
            gid,
            pid: std::process::id() as i32,
        };
        let user = users::name_for_uid(uid).unwrap();
        let _seat = seat_fixture("split-runtime-redaction", Some(uid));
        let mut requests = Vec::new();
        for (variant, reset) in VARIANTS {
            let recorder = fixture();
            let _admitted = recorder.admit_split_trust(&[CameraOperationKind::Enrollment]);
            authorize();
            write_enrollment(&sb.dir, &primary(&user, variant, reset));
            let request = choice(&user, variant, reset);
            let (server, _client) = std::os::unix::net::UnixStream::pair().unwrap();
            let authorization =
                operation_authorization::authorize_for_test(&request, &owner, &server).unwrap();
            assert_eq!(authorization.is_some(), uid != 0);
            let state = diagnostics::DiagnosticState::default();
            let scope = state.begin_for(
                diagnostic_operation_class(&request),
                diagnostic_owner(&request, &owner),
            );
            let response =
                dispatch_scoped(request.clone(), &owner, &mut engine, &scope, authorization);
            assert_eq!(
                recorder.calls(),
                vec![split_lease(), Call::OpenRgb(RGB.into())],
                "{variant}/{reset}: the owner's request ran the Engine split entry: {response:?}"
            );
            let fixed = wire(&Response::Error(refused(variant).into()));
            if uid == 0 {
                // Root gets the Engine text (plan D6).
                assert!(
                    matches!(&response, Response::Error(reason)
                        if reason != refused(variant) && !reason.contains(CLOSED)),
                    "{variant}/{reset}: {response:?}"
                );
            } else {
                assert_eq!(
                    wire(&response),
                    fixed,
                    "{variant}/{reset}: a peer other than root gets only the static reason"
                );
            }
            // The projection itself, whoever runs the suite.
            assert_eq!(wire(&split_reply_for_peer(&request, response.clone(), uid.max(1))), fixed);
            requests.push((variant, request));
        }

        // The pure projection over replies that name every forbidden fact.
        let leaking = format!(
            "hardware: {RGB} and {IR} (1234:0001:rgb, 1234:0002:ir at \
             /devices/pci0000:00/0000:00:14.0) refused {KEY} for group cam-1234-0001-rgb"
        );
        let mut non_root = Vec::new();
        for (variant, request) in &requests {
            let failure = Response::Error(leaking.clone());
            let projected = split_reply_for_peer(request, failure.clone(), 1000);
            assert_eq!(wire(&projected), wire(&Response::Error(refused(variant).into())));
            assert_eq!(
                wire(&split_reply_for_peer(request, failure.clone(), 0)),
                wire(&failure),
                "{variant}: root replies pass unchanged"
            );
            non_root.push(projected);
            if *variant == "EnrollSplitOn" {
                // An enrollment reply names the profile and its scans only, as
                // an ordinary enrollment does.
                let enrolled = enroll_response(irlume_auth::EnrollOutcome::New {
                    name: "Face Profile 2".into(),
                    scans: 1,
                    ambient_lit: 0,
                });
                assert_eq!(
                    wire(&split_reply_for_peer(request, enrolled.clone(), 1000)),
                    wire(&enrolled)
                );
                // Anything else becomes the static refusal.
                let projected = split_reply_for_peer(request, Response::Ok(leaking.clone()), 1000);
                assert_eq!(wire(&projected), wire(&Response::Error(ENROLL_REFUSED.into())));
                non_root.push(projected);
            } else {
                // The group id is seeded from a device identity.
                let added = Response::Ok(
                    "camera group 'cam-1234-0001-rgb' enrolled on this split pair; it can now \
                     authenticate this account"
                        .into(),
                );
                let projected = split_reply_for_peer(request, added.clone(), 1000);
                assert_eq!(wire(&projected), wire(&Response::Ok(GROUP_ENROLLED.into())));
                assert_eq!(wire(&split_reply_for_peer(request, added.clone(), 0)), wire(&added));
                non_root.push(projected);
            }
        }
        assert_ne!(ENROLL_REFUSED, GROUP_REFUSED, "one static reason per request variant");
        for reply in &non_root {
            let surface = wire(reply);
            for forbidden in FORBIDDEN {
                assert!(
                    !surface.contains(forbidden),
                    "a non-root reply leaked {forbidden}: {surface}"
                );
            }
        }
        // Other requests are not this projection's to change.
        let other = Response::Error(leaking);
        assert_eq!(
            wire(&split_reply_for_peer(&Request::Ping, other.clone(), 1000)),
            wire(&other)
        );
        engine.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn split_runtime_handlers_never_lower_to_an_ordinary_dispatch() {
        let source = include_str!("main.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .unwrap();
        let body = |start: &str, end: &str| -> &'static str {
            production
                .split(start)
                .nth(1)
                .unwrap_or_else(|| panic!("main.rs lost {start}"))
                .split(end)
                .next()
                .unwrap()
        };
        let arm = body(
            "| Request::AddSplitCameraGroupOn { pair, .. } = &req",
            "| Request::AddCameraGroupOn { pair, .. } = &req",
        );
        // Plan D5: approval was consumed above this arm; then resolve and
        // prepare, the explicit activation gate, the primary check, and only
        // then the dedicated handler, whose reply is projected per peer.
        let mut last = 0;
        for step in [
            "resolve_split_enrollment_choice(",
            "prepare_split_enrollment_camera(",
            "validate_enrollment_camera_activation()",
            "validate_enrollment_camera_primary(",
            "split_enrollment_handler(",
            "split_reply_for_peer(",
        ] {
            let at = arm
                .find(step)
                .unwrap_or_else(|| panic!("the split arm lost {step}"));
            assert!(at >= last, "{step} moved ahead of an earlier step");
            last = at;
        }
        for lowering in [
            "dispatch_after_authorization(",
            "Request::Enroll {",
            "Request::AddCameraGroup {",
            "invalidate_enrollment_summary(",
        ] {
            assert!(
                !arm.contains(lowering),
                "the split arm must not reach {lowering} before its handler"
            );
        }
        let handler = body("fn split_enrollment_handler(", "\n}\n");
        let authorization = body("fn split_group_authorization(", "\n}\n");
        let dropped = handler
            .find("invalidate_enrollment_summary(")
            .expect("the handler drops the summary");
        for entry in [
            "enroll_split_prepared(",
            "add_split_camera_group_prepared(",
            "split_group_authorization(",
        ] {
            assert!(
                handler.find(entry).is_some_and(|at| at > dropped),
                "{entry} must run, and only after the summary is dropped"
            );
        }
        for needle in [
            "prepared_enrollment_binding()",
            "derive_group_id(",
            "EnrollmentOperation::add_group(",
            "mint_group_authorization(",
        ] {
            assert!(
                authorization.contains(needle),
                "the split group authorization lost {needle}"
            );
        }
        for ordinary in [
            "dispatch_after_authorization(",
            "enroll_with_capture_probe(",
            "run_capture_mode_probe",
            "capture_qualification_for_request",
            "prepare_enrollment_ir",
            "prepared_camera_lease()",
            "live_pair()",
            "add_camera_group_observed(",
            "enroll_profile_",
            "replace_enrollment_",
        ] {
            assert!(
                !handler.contains(ordinary) && !authorization.contains(ordinary),
                "the split handlers must not reach the ordinary {ordinary}"
            );
        }
        // A split request that ever reaches the ordinary dispatch still refuses.
        let ordinary = body("fn dispatch_after_authorization(", "\n}\n");
        assert!(ordinary.contains(concat!(
            "| Request::EnrollSplitOn { .. }\n",
            "        | Request::AddSplitCameraGroupOn { .. } => {\n",
            "            Response::Error(\"operation camera choice requires its prepared request ",
            "scope\".into())",
        )));
    }

    // Negative controls: GREEN before and after the handlers land.

    #[test]
    fn split_runtime_closed_default_refuses_before_camera_and_keeps_the_summary() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("split-runtime-closed");
        let _environment = Environment::clear();
        engine.set_devices(NO_RGB, NO_IR);
        let user = users::name_for_uid(0).unwrap();
        let account = sb.dir.join(format!("{user}.json"));
        let authentication_only = [CameraOperationKind::Authentication];
        for admitted in [&[][..], &authentication_only[..]] {
            for (variant, reset) in VARIANTS {
                let recorder = fixture();
                let _token = recorder.admit_split_trust(admitted);
                authorize();
                write_enrollment(&sb.dir, &primary(&user, variant, reset));
                publish_summary(&mut engine, &user);
                let before = std::fs::read(&account).unwrap();
                let config = std::fs::read(sb.dir.join("config/cameras.conf")).unwrap();
                let response = dispatch(choice(&user, variant, reset), &peer(0), &mut engine);
                assert!(
                    matches!(response, Response::Error(ref reason) if reason.contains(CLOSED)),
                    "{admitted:?} {variant}/{reset}: {response:?}"
                );
                assert!(
                    recorder.calls().is_empty(),
                    "{admitted:?} {variant}/{reset}: closed activation spent camera work: {:?}",
                    recorder.calls()
                );
                assert_eq!(std::fs::read(&account).unwrap(), before);
                assert_eq!(
                    std::fs::read(sb.dir.join("config/cameras.conf")).unwrap(),
                    config
                );
                assert!(no_secondary_publication(&user));
                assert!(!sb.dir.join("capture-qualifications").exists());
                assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
                assert!(
                    summary_published(&user),
                    "{admitted:?} {variant}/{reset}: a closed refusal changed the summary"
                );
            }
        }
    }

    #[test]
    fn split_runtime_admitted_primary_refusal_keeps_the_summary_and_the_camera_idle() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("split-runtime-primary");
        let _environment = Environment::clear();
        engine.set_devices(NO_RGB, NO_IR);
        let user = users::name_for_uid(0).unwrap();
        let account = sb.dir.join(format!("{user}.json"));
        let other = || CameraBinding::Split(SplitPairKey::parse_canonical(OTHER_KEY).unwrap());
        let standing = || CameraBinding::Ordinary {
            rgb: Some("standing-primary".into()),
            ir: Some("standing-primary".into()),
        };
        for (binding, scans) in [
            (Some(other()), &["Face Scan 1"][..]),
            (Some(standing()), &["Face Scan 1"][..]),
            (None, &["Face Scan 1"][..]),
            // Empty but bound to another pair.
            (Some(other()), &[][..]),
        ] {
            let recorder = fixture();
            let _admitted = recorder.admit_split_trust(&[CameraOperationKind::Enrollment]);
            authorize();
            let mut enrollment = enrollment_with(&user, scans);
            enrollment.camera_binding = binding.clone();
            write_enrollment(&sb.dir, &enrollment);
            publish_summary(&mut engine, &user);
            let before = std::fs::read(&account).unwrap();
            let response = dispatch(choice(&user, "EnrollSplitOn", false), &peer(0), &mut engine);
            assert!(
                matches!(response, Response::Error(ref reason) if reason.contains(OTHER_CAMERA)),
                "{binding:?}: {response:?}"
            );
            assert!(
                recorder.calls().is_empty(),
                "{binding:?}: a refused primary spent camera work: {:?}",
                recorder.calls()
            );
            assert_eq!(std::fs::read(&account).unwrap(), before);
            assert!(!sb.dir.join("capture-qualifications").exists());
            assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
            assert!(
                summary_published(&user),
                "{binding:?}: the summary is dropped only past the primary check"
            );
        }
    }

    // Field pins: the handlers hand the request's own `reset`, `profile` and
    // `scans` to the Engine entry. The refusing fixture ends every capture at
    // the RGB side, so these cases are told apart by the Engine's checks
    // before the lease: a substituted value changes whether the pair is
    // leased at all.

    /// `request` naming `name` as its profile.
    fn naming(mut request: Request, name: Option<&str>) -> Request {
        match &mut request {
            Request::EnrollSplitOn { profile, .. }
            | Request::AddSplitCameraGroupOn { profile, .. } => {
                *profile = name.map(Into::into);
            }
            _ => unreachable!("only split enrollment requests name a profile here"),
        }
        request
    }

    #[test]
    fn split_runtime_admitted_handlers_pass_the_request_reset_and_profile_through() {
        let _guard = env_lock();
        let mut engine = engine();
        let sb = sandbox("split-runtime-fields");
        let _environment = Environment::clear();
        engine.set_devices(NO_RGB, NO_IR);
        let user = users::name_for_uid(0).unwrap();
        let account = sb.dir.join(format!("{user}.json"));
        // The primary bound to this split pair, holding "Face Profile 1".
        let bound = primary(&user, "EnrollSplitOn", false);
        // A standing ordinary primary holding "Face Profile 1" and "Face
        // Profile 2", which a group addition must name one of.
        let mut two = primary(&user, "AddSplitCameraGroupOn", false);
        let mut second = enrollment_with(&user, &["Face Scan 2"]).profiles.remove(0);
        second.name = "Face Profile 2".into();
        two.profiles.push(second);
        /// The request variant, its `reset`, the primary on disk, the profile
        /// the request names, and the Engine's refusal before the lease.
        type Case<'a> = (&'a str, bool, &'a Enrollment, Option<&'a str>, Option<&'a str>);
        let cases: [Case<'_>; 6] = [
            // Not a reset: the Engine loads the bound primary, which already
            // holds the named profile. With `reset` true or the name dropped,
            // the same request would lease the pair.
            (
                "EnrollSplitOn",
                false,
                &bound,
                Some("Face Profile 1"),
                Some("a face profile named 'Face Profile 1' already exists"),
            ),
            // A reset starts from an empty enrollment, so the same name
            // leases. With `reset` false it would be refused as a duplicate.
            ("EnrollSplitOn", true, &bound, Some("Face Profile 1"), None),
            // A new name on the bound primary leases.
            ("EnrollSplitOn", false, &bound, Some("Face Profile 2"), None),
            // A group names one primary profile: an unknown name is refused
            // before the lease. With the name dropped, the Engine would
            // refuse for a different reason (several profiles).
            (
                "AddSplitCameraGroupOn",
                false,
                &two,
                Some("No Such Profile"),
                Some("no face profile named 'No Such Profile' to add this camera to"),
            ),
            // A known name among several leases...
            ("AddSplitCameraGroupOn", false, &two, Some("Face Profile 2"), None),
            // ...because it reached the Engine: naming none is refused.
            (
                "AddSplitCameraGroupOn",
                false,
                &two,
                None,
                Some("has multiple face profiles; name which one this camera enrolls"),
            ),
        ];
        for (variant, reset, enrollment, name, refusal) in cases {
            let recorder = fixture();
            let counts = recorder.lease_counts_observer();
            let _admitted = recorder.admit_split_trust(&[CameraOperationKind::Enrollment]);
            authorize();
            write_enrollment(&sb.dir, enrollment);
            let before = std::fs::read(&account).unwrap();
            let request = naming(choice(&user, variant, reset), name);
            let response = dispatch(request, &peer(0), &mut engine);
            let Response::Error(reason) = &response else {
                panic!(
                    "{variant}/{reset}/{name:?}: the refusing fixture cannot enroll: {response:?}"
                );
            };
            assert!(
                !reason.contains(CLOSED),
                "{variant}/{reset}/{name:?}: an admitted handler runs its Engine entry: {reason}"
            );
            match refusal {
                Some(text) => {
                    assert!(
                        reason.contains(text),
                        "{variant}/{reset}/{name:?}: expected {text:?}, got {reason}"
                    );
                    assert!(
                        recorder.calls().is_empty(),
                        "{variant}/{reset}/{name:?}: refused before any lease: {:?}",
                        recorder.calls()
                    );
                }
                None => assert_eq!(
                    recorder.calls(),
                    vec![split_lease(), Call::OpenRgb(RGB.into())],
                    "{variant}/{reset}/{name:?}: past the Engine checks, one split lease and \
                     the refused RGB open: {reason}"
                ),
            }
            assert_eq!(counts(), (0, 0), "{variant}/{reset}/{name:?}");
            assert_eq!(std::fs::read(&account).unwrap(), before, "{variant}/{reset}/{name:?}");
            assert!(no_secondary_publication(&user), "{variant}/{reset}/{name:?}");
            assert!(!sb.dir.join("capture-qualifications").exists());
            assert_eq!((engine.rgb_device(), engine.ir_device()), (NO_RGB, NO_IR));
        }
    }

    /// The Engine clamps the scan count and reads it only after a live probe
    /// scan (`enroll_profile_capture_prepared` and `add_camera_group_prepared`
    /// in irlume-auth), which the refusing fixture never yields. No dispatch
    /// here can observe `scans`, so its pass-through is pinned in source,
    /// next to the `reset` and `profile` arguments the test above observes.
    #[test]
    fn split_runtime_handlers_hand_every_request_field_to_the_engine_entry() {
        let source = include_str!("main.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .unwrap();
        let handler = production
            .split("fn split_enrollment_handler(")
            .nth(1)
            .expect("main.rs lost split_enrollment_handler")
            .split("\n}\n")
            .next()
            .unwrap();
        // Line breaks and a trailing argument comma are rustfmt's choice.
        let flat = handler
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .replace(",)", ")");
        let (enroll, group) = flat
            .split_once("Request::AddSplitCameraGroupOn{")
            .expect("the handler lost its group arm");
        let want = "letwant=scans.unwrap_or(irlume_core::storage::DEFAULT_ENROLL_SCANS);";
        for (arm, fields, entry) in [
            (
                enroll,
                "Request::EnrollSplitOn{user,profile,scans,reset,..}=>",
                "enroll_split_prepared(user,profile.clone(),want,*reset,diagnostics)",
            ),
            (
                group,
                "user,profile,scans,..}=>",
                concat!(
                    "add_split_camera_group_prepared(user,profile.clone(),want,",
                    "&authorization,diagnostics)"
                ),
            ),
        ] {
            assert!(arm.contains(fields), "{entry}: the arm lost its {fields}");
            assert_eq!(arm.matches("letwant=").count(), 1, "{entry}: one scan count");
            assert!(
                arm.contains(want),
                "{entry}: the scan count is the request's, else the ordinary default"
            );
            assert!(arm.contains(entry), "the arm lost {entry}");
        }
    }
}
