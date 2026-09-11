// SPDX-License-Identifier: GPL-3.0-or-later
// Synthetic observation, generation, and selection regressions. No I/O.

fn live_test_snapshot() -> irlume_common::live::LiveStatusSnapshot {
    serde_json::from_value(serde_json::json!({
        "live_schema":1, "daemon_instance":"11111111111111111111111111111111",
        "daemon_uptime_ms":60000, "state_revision":0, "stage":"ready",
        "worker":null, "background":[], "waiting":[], "tracking_available":true,
        "cameras":{"state":"current", "supervisor_id":"22222222222222222222222222222222",
            "revision":1, "observed_ago_ms":3600000, "reason":null,
            "candidates":[{"instance_id":"33333333333333333333333333333333",
                "generation":1,"endpoint_paths":["/dev/video40","/dev/video42"]}]}
    }))
    .unwrap()
}

fn live_test_health() -> HealthInfo {
    HealthInfo {
        tier: "secure".into(),
        rgb_dev: Some("/dev/video40".into()),
        ir_dev: Some("/dev/video42".into()),
        mesh: true,
        adapter: false,
        rgb_pad: Some(irlume_common::PadModelStatus::Loaded),
        ir_pad: Some(irlume_common::PadModelStatus::Loaded),
        version: env!("CARGO_PKG_VERSION").into(),
        apparmor: None,
    }
}

fn live_test_app() -> App {
    let mut app = test_app();
    let now = Instant::now();
    app.clock_override = Some(now);
    app.mark_fixture_observations_fresh(now);
    app.health = Some(live_test_health());
    app.apply_live_snapshot(live_test_snapshot(), now);
    app
}

fn live_test_pair() -> irlume_common::CameraPairInfo {
    irlume_common::CameraPairInfo {
        rgb: "/dev/video40".into(),
        ir: "/dev/video42".into(),
        id: None,
        fixed: false,
        privacy: false,
    }
}

fn live_test_land_profiles(app: &mut App, profiles: Vec<ProfileSummary>) {
    let (tx, rx) = mpsc::channel();
    app.profiles_load = Some(rx);
    tx.send(ProfilesOutcome::Loaded { profiles }).unwrap();
    app.poll();
}

fn live_test_land_cameras(app: &mut App) {
    let (tx, rx) = mpsc::channel();
    app.camera_load = Some(rx);
    tx.send(CameraListing {
        pairs: Some(vec![live_test_pair()]),
    })
    .unwrap();
    app.poll();
}

#[test]
fn live_freshness_partial_status_failure_cannot_borrow_sibling_success() {
    let mut app = live_test_app();
    let before = app.now();
    app.recovery = Some(RecoveryInfo {
        encrypted: true,
        recovery_set: true,
        tpm_present: true,
        key_present: true,
    });
    app.profiles_loaded = true;
    app.clock_override = Some(before + Duration::from_secs(2));
    app.apply_light(LightState {
        observed_at: [Some(app.now()), None, None, None],
        daemon_up: true,
        reach: crate::commands::DaemonReach::Running,
        health: Some(live_test_health()),
        preferences: None,
        keyring_armed: None,
        keyring_policy: None,
        keyring_kind: None,
        recovery: None,
    });
    assert!(app.source_usable(Source::Health));
    assert!(!app.source_usable(Source::Recovery));
    assert!(app.recovery.is_none());
    assert_eq!(
        app.freshness.observation(Source::Recovery).last_success,
        Some(before)
    );
    assert!(app
        .source_status(Source::Recovery)
        .contains("last successful check 2s ago"));
    assert!(app.profiles_load.is_none());
}

#[test]
fn live_freshness_profile_identity_survives_invalidation_and_reorder() {
    let mut app = live_test_app();
    app.profiles = vec![profile("Alice", &["a"]), profile("Bob", &["b"])];
    app.sel = 3; // Bob's scan, not its numeric position after the next load.
    app.invalidate_source(Source::Profiles);
    assert!(app.profiles.is_empty());
    live_test_land_profiles(
        &mut app,
        vec![profile("Bob", &["b"]), profile("Alice", &["a"])],
    );
    assert_eq!(
        app.selected_profile_row(),
        Some(("Bob".into(), Some("b".into())))
    );
    app.invalidate_source(Source::Profiles);
    live_test_land_profiles(&mut app, vec![profile("Alice", &["a"])]);
    assert!(
        app.selected_profile_row().is_none(),
        "removed identity must not select a different scan"
    );
}

#[test]
fn live_freshness_old_profile_result_is_discarded_with_one_pending_replacement() {
    let mut app = live_test_app();
    assert!(app.freshness.cycle_mut(Worker::Profiles).begin());
    app.invalidate_daemon_observations();
    live_test_land_profiles(&mut app, vec![profile("old", &["old"])]);
    assert!(app.profiles.is_empty());
    assert!(app.freshness.cycle(Worker::Profiles).pending());
    assert!(app.freshness.cycle_mut(Worker::Profiles).begin());
    assert!(!app.freshness.cycle_mut(Worker::Profiles).begin());
    live_test_land_profiles(&mut app, vec![profile("new", &["new"])]);
    assert_eq!(app.profiles[0].name, "new");
    assert!(!app.freshness.cycle(Worker::Profiles).pending());
}

#[test]
fn live_freshness_profile_timer_is_visible_idle_and_completion_bounded() {
    let mut app = live_test_app();
    let now = app.now();
    app.screen = SC_PROFILES;
    app.freshness.cycle_mut(Worker::Profiles).begin();
    app.freshness.cycle_mut(Worker::Profiles).finish(now);
    assert!(!app.profiles_refresh_due(now + Duration::from_secs(29), true));
    assert!(app.profiles_refresh_due(now + Duration::from_secs(30), true));
    assert!(!app.profiles_refresh_due(now + Duration::from_secs(30), false));
    for screen in [SC_WELCOME, SC_REPAIR, SC_DONE] {
        app.screen = screen;
        assert!(app.profiles_refresh_due(now + Duration::from_secs(61), true));
    }
    app.screen = SC_SETTINGS;
    assert!(!app.profiles_refresh_due(now + Duration::from_secs(90), true));
    app.screen = SC_PROFILES;
    let (_sender, op) = fake_op();
    app.op = Some(op);
    assert!(!app.profiles_refresh_due(now + Duration::from_secs(90), true));
}

#[test]
fn live_freshness_fingerprint_list_failure_is_unknown_not_zero_enrollment() {
    let mut app = live_test_app();
    app.screen = SC_FINGERPRINT;
    let (tx, rx) = mpsc::channel();
    app.probes_load = Some(rx);
    tx.send(Probes {
        fp_present: Some(true),
        fp_enrollment_observed: false,
        fp: FpInfo {
            available: true,
            device: Some("Synthetic reader".into()),
            enrolled: vec![],
            method: "fingerprint".into(),
        },
        ..Probes::default()
    })
    .unwrap();
    app.poll();
    assert!(app.source_usable(Source::FingerprintReader));
    assert!(!app.source_usable(Source::Fingerprint));
    let text = draw_text(&app);
    assert!(
        text.contains("enrollment observation unavailable"),
        "{text}"
    );
    assert!(!app
        .repair
        .iter()
        .any(|check| check.detail.contains("no finger is enrolled")));
    assert_eq!(
        app.hub_rows()
            .iter()
            .find(|(_, _, screen)| *screen == SC_FINGERPRINT)
            .map(|(_, state, _)| *state),
        Some(None)
    );
}

#[test]
fn live_freshness_expiry_and_tracking_failure_never_claim_idle_or_camera_ready() {
    let mut app = live_test_app();
    assert!(app.live_summary().contains("worker idle"));
    assert!(app.caps.ir_pair);
    let mut live = live_test_snapshot();
    live.tracking_available = false;
    app.apply_live_snapshot(live, app.now());
    assert!(!app.live_summary().contains("idle"));
    assert!(app.live_summary().contains("unavailable"));
    app.clock_override = Some(app.now() + Duration::from_secs(5));
    app.expire_observations(app.now());
    assert!(app.current_inventory().is_none());
    assert!(!app.caps.rgb && !app.caps.ir_pair);
    assert!(!app.live_summary().contains("idle"));
}

#[test]
fn live_freshness_background_qualification_is_separate_from_worker_idle() {
    let mut app = live_test_app();
    let mut live = live_test_snapshot();
    live.background.push(
        serde_json::from_value(serde_json::json!({
            "operation_id":"44444444444444444444444444444444", "kind":"capture_qualification",
            "elapsed_ms":2300,"cancellation_requested":false
        }))
        .unwrap(),
    );
    app.apply_live_snapshot(live, app.now());
    assert!(!app.live_summary().contains("idle"));
    let details = app.live_details();
    assert!(
        details.contains("Background: capture qualification · 2s"),
        "{details}"
    );
}

#[test]
fn live_freshness_same_inventory_keeps_roles_despite_old_publication_age() {
    let mut app = live_test_app();
    live_test_land_cameras(&mut app);
    app.classified_epoch = app.camera_epoch.clone();
    let epoch = app.classified_epoch.clone();
    app.apply_live_snapshot(live_test_snapshot(), app.now());
    assert!(
        app.current_inventory().is_some(),
        "stable supervisor publication age is not RPC age"
    );
    assert!(app.source_usable(Source::Cameras));
    assert_eq!(app.classified_epoch, epoch);
    assert_eq!(app.pairs.len(), 1);
}

#[test]
fn live_freshness_path_reuse_does_not_retarget_camera_selection() {
    let mut app = live_test_app();
    live_test_land_cameras(&mut app);
    app.cam_sel = 0;
    let mut replaced = live_test_snapshot();
    replaced.cameras.revision = 2;
    replaced.cameras.candidates[0].generation = 2;
    replaced.cameras.candidates[0].instance_id = "55555555555555555555555555555555".into();
    app.apply_live_snapshot(replaced, app.now());
    assert!(app.pairs.is_empty());
    live_test_land_cameras(&mut app);
    assert!(
        app.pairs.get(app.cam_sel).is_none(),
        "same endpoint names with a new instance are a different camera"
    );
}

#[test]
fn live_freshness_inventory_loss_clears_pending_camera_confirmation() {
    let mut app = live_test_app();
    live_test_land_cameras(&mut app);
    app.screen = SC_CAMERAS;
    app.cam_sel = 0;
    app.on_key(KeyCode::Enter);
    assert!(app.confirm.is_some());
    assert!(app.camera_confirmation.is_some());
    app.clock_override = Some(app.now() + Duration::from_secs(5));
    app.expire_observations(app.now());
    assert!(app.confirm.is_none());
    assert!(app.camera_confirmation.is_none());
    assert!(app.suspend.is_none());
    assert!(!app.caps.rgb);
}

#[test]
fn live_freshness_unclassified_candidate_is_visible_at_40_by_12() {
    let mut app = live_test_app();
    app.screen = SC_CAMERAS;
    let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    let text = rendered(&terminal);
    assert!(text.contains("Attached; inspect roles"), "{text}");
    assert!(!text.contains("No UVC candidates"), "{text}");
}

#[test]
fn live_freshness_f4_click_owns_its_hit_region_during_an_operation() {
    let mut app = live_test_app();
    let (_sender, op) = fake_op();
    app.op = Some(op);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    let rect = app
        .click_targets
        .borrow()
        .iter()
        .find_map(|(rect, click)| matches!(click, Click::Key(KeyCode::F(4))).then_some(*rect))
        .unwrap();
    app.on_click(rect.x, rect.y, Rect::new(0, 0, 80, 24));
    assert!(app.show_live);
    assert!(!app.activity_open);
    assert!(app.op.is_some());
    app.on_key(KeyCode::Esc);
    assert!(!app.show_live);
    assert!(app.op.is_some());
}

#[test]
fn live_freshness_a_later_confirmation_owns_input_over_f4() {
    let mut app = live_test_app();
    app.on_key(KeyCode::F(4));
    app.confirm = Some((
        "Synthetic confirmation".into(),
        "Inspect",
        ConfirmAct::CameraQualification,
    ));
    assert!(!app.live_overlay_visible());
    app.on_key(KeyCode::Esc);
    assert!(
        app.confirm.is_none(),
        "Esc dismisses the visible confirmation, not the obscured F4 overlay"
    );
    assert!(app.show_live);
    assert!(app.qualification_load.is_none());
}

#[test]
fn live_freshness_starting_and_unknown_replies_are_not_described_as_no_response() {
    for stage in [
        irlume_common::live::LiveStage::Starting,
        irlume_common::live::LiveStage::Unknown,
    ] {
        let mut app = live_test_app();
        let mut snapshot = live_test_snapshot();
        snapshot.stage = stage;
        app.apply_live_snapshot(snapshot, app.now());
        app.screen = SC_WELCOME;
        let text = draw_text(&app);
        assert!(text.contains("daemon responded"), "{text}");
        assert!(!text.contains("service is not responding"), "{text}");
    }
}

#[test]
fn live_freshness_done_cannot_claim_all_set_after_live_expiry() {
    let mut app = live_test_app();
    app.screen = SC_DONE;
    app.profiles_loaded = true;
    app.profiles = vec![profile("Alice", &["a"])];
    app.probes_landed = true;
    app.probes.login_wired = true;
    assert!(draw_text(&app).contains("All set"));
    app.clock_override = Some(app.now() + Duration::from_secs(5));
    app.expire_observations(app.now());
    app.screen = SC_DONE;
    let text = draw_text(&app);
    assert!(!text.contains("All set"), "{text}");
    assert!(text.contains("readiness unavailable"), "{text}");
}

#[test]
fn live_freshness_known_uvc_history_is_bounded_to_configured_endpoints() {
    let mut app = live_test_app();
    for revision in 2..50 {
        let mut snapshot = live_test_snapshot();
        snapshot.cameras.revision = revision;
        snapshot.cameras.candidates[0]
            .endpoint_paths
            .push(format!("/dev/video{}", 100 + revision));
        app.apply_live_snapshot(snapshot, app.now());
    }
    assert!(app.known_uvc_paths.len() <= 2);
    assert!(app.known_uvc_paths.contains(&"/dev/video40".into()));
}

#[test]
fn live_freshness_capture_qualification_is_a_separate_explicit_request() {
    use std::io::{BufRead, Write};
    let _guard = dead_socket();
    let socket = std::env::temp_dir().join(format!(
        "irlume-qualification-fixture-{}.sock",
        std::process::id()
    ));
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::env::set_var("IRLUME_SOCKET", &socket);
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("qualification fixture accept did not finish: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(&stream)
            .read_line(&mut line)
            .unwrap();
        let request: Request = serde_json::from_str(&line).unwrap();
        writeln!(
            stream,
            "{}",
            serde_json::to_string(&Response::Error("fixture: unavailable".into())).unwrap()
        )
        .unwrap();
        request
    });
    let mut app = live_test_app();
    app.screen = SC_CAMERAS;
    app.on_key(KeyCode::Char('c'));
    assert!(app.confirm.is_some());
    assert!(
        app.qualification_load.is_none(),
        "disclosure must precede the request"
    );
    app.on_key(KeyCode::Char('y'));
    let request = server.join().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while app.qualification_load.is_some() && Instant::now() < deadline {
        app.poll();
        std::thread::sleep(Duration::from_millis(5));
    }
    std::fs::remove_file(socket).unwrap();
    assert!(matches!(request, Request::CaptureModeStatus));
    assert!(app.qualification_load.is_none());
    assert!(app.camera_load.is_none());
    assert!(!app.source_usable(Source::Qualification));
}

#[test]
fn live_freshness_unavailable_tracking_does_not_present_background_as_current() {
    let mut app = live_test_app();
    let mut snapshot = live_test_snapshot();
    snapshot.tracking_available = false;
    snapshot.background.push(
        serde_json::from_value(serde_json::json!({
            "operation_id":"44444444444444444444444444444444", "kind":"capture_qualification",
            "elapsed_ms":2300,"cancellation_requested":false
        }))
        .unwrap(),
    );
    app.apply_live_snapshot(snapshot, app.now());
    let text = app.live_details();
    assert!(text.contains("activity unavailable"), "{text}");
    assert!(
        !text.contains("Background:"),
        "unavailable metadata cannot look current: {text}"
    );
}

#[test]
fn live_freshness_open_camera_page_survives_removal_and_unavailability() {
    let mut app = live_test_app();
    app.screen = SC_CAMERAS;
    let mut snapshot = live_test_snapshot();
    snapshot.cameras.revision = 2;
    snapshot.cameras.candidates.clear();
    app.apply_live_snapshot(snapshot, app.now());
    assert_eq!(app.screen, SC_CAMERAS);
    assert!(draw_text(&app).contains("No UVC candidates"));
    app.invalidate_source(Source::Live);
    app.expire_observations(app.now());
    app.recompute_visible();
    assert_eq!(app.screen, SC_CAMERAS);
    assert!(draw_text(&app).contains("Current camera inventory unavailable"));
    assert!(app.camera_load.is_none() && app.qualification_load.is_none());
}

#[test]
fn live_freshness_unknown_reader_cannot_start_enrollment_or_claim_absence() {
    let mut app = live_test_app();
    app.screen = SC_FINGERPRINT;
    app.fp.available = true;
    app.invalidate_source(Source::FingerprintReader);
    for key in ['a', 't'] {
        app.on_key(KeyCode::Char(key));
        assert!(app.suspend.is_none());
        let (_, message) = app.activity.last().unwrap();
        assert!(message.contains("observation unavailable"));
        assert!(!message.contains("no fingerprint reader"));
    }
}

#[test]
fn live_freshness_manual_camera_refresh_preserves_identity_and_queues_one_replacement() {
    let mut app = live_test_app();
    let mut snapshot = live_test_snapshot();
    snapshot.cameras.revision = 2;
    let mut candidate = snapshot.cameras.candidates[0].clone();
    candidate.instance_id = "66666666666666666666666666666666".into();
    candidate.endpoint_paths = vec!["/dev/video60".into(), "/dev/video62".into()];
    snapshot.cameras.candidates.push(candidate);
    app.apply_live_snapshot(snapshot, app.now());
    let second = irlume_common::CameraPairInfo {
        rgb: "/dev/video60".into(),
        ir: "/dev/video62".into(),
        id: None,
        fixed: false,
        privacy: false,
    };
    app.pairs = vec![live_test_pair(), second.clone()];
    app.cam_sel = 1;
    app.screen = SC_CAMERAS;
    app.classified_epoch = app.camera_epoch.clone();
    app.freshness.cycle_mut(Worker::Cameras).begin();
    let (old_sender, old_receiver) = mpsc::channel();
    app.camera_load = Some(old_receiver); // prevents any I/O from the manual key
    app.on_key(KeyCode::Char('r'));
    assert!(app.pairs.is_empty());
    old_sender
        .send(CameraListing {
            pairs: Some(vec![live_test_pair(), second.clone()]),
        })
        .unwrap();
    app.poll();
    assert!(app.pairs.is_empty(), "pre-refresh listing cannot publish");
    assert!(
        app.cameras_refresh_due(true),
        "one requested replacement remains due even at the same inventory epoch"
    );
    assert!(app.freshness.cycle_mut(Worker::Cameras).begin());
    assert!(!app.freshness.cycle_mut(Worker::Cameras).begin());
    let (sender, receiver) = mpsc::channel();
    app.camera_load = Some(receiver);
    sender
        .send(CameraListing {
            pairs: Some(vec![second, live_test_pair()]),
        })
        .unwrap();
    app.poll();
    assert_eq!(app.pairs[app.cam_sel].rgb, "/dev/video60");
    assert!(!app.cameras_refresh_due(true));
}

#[test]
fn live_freshness_observed_empty_camera_selection_stays_clear_through_failure_and_replacement() {
    let mut app = live_test_app();
    live_test_land_cameras(&mut app);
    let (sender, receiver) = mpsc::channel();
    app.camera_load = Some(receiver);
    sender
        .send(CameraListing {
            pairs: Some(vec![]),
        })
        .unwrap();
    app.poll();
    assert!(app.pairs_known && app.pairs.is_empty());
    let (sender, receiver) = mpsc::channel();
    app.camera_load = Some(receiver);
    sender.send(CameraListing { pairs: None }).unwrap();
    app.poll();
    assert!(!app.pairs_known);
    let mut snapshot = live_test_snapshot();
    snapshot.cameras.revision = 2;
    snapshot.cameras.candidates[0].instance_id = "77777777777777777777777777777777".into();
    app.apply_live_snapshot(snapshot, app.now());
    live_test_land_cameras(&mut app);
    assert_eq!(app.pairs.len(), 1);
    assert!(
        app.pairs.get(app.cam_sel).is_none(),
        "an observed empty selection cannot silently select a replacement camera"
    );
}

#[test]
fn live_freshness_observed_empty_profiles_do_not_select_a_new_person() {
    let mut app = live_test_app();
    live_test_land_profiles(&mut app, vec![profile("Alice", &["a"])]);
    live_test_land_profiles(&mut app, vec![]);
    assert!(app.profiles_loaded && app.profiles.is_empty());
    app.invalidate_source(Source::Profiles);
    live_test_land_profiles(&mut app, vec![profile("Bob", &["b"])]);
    assert!(
        app.selected_profile_row().is_none(),
        "an empty prior selection cannot become another person"
    );
}
