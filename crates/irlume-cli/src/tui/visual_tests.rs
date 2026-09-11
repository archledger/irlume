// SPDX-License-Identifier: GPL-3.0-or-later
// Included inside tui::tests. Only synthetic state and TestBackend rendering:
// never App::new, poll, enter_screen, or an operation/command dispatch.

fn visual_fixture(screen: usize) -> App {
    let mut app = test_app();
    app.user = "synthetic-sample".into();
    app.screen = screen;
    app.advanced = true;
    app.visible = (0..SCREENS.len()).collect();
    app.caps = irlume_camera::Caps {
        ir_pair: true,
        rgb: true,
    };
    app.reported_caps = app.caps;
    let now = Instant::now();
    app.clock_override = Some(now);
    let live = visual_live_snapshot("ready", true);
    app.live_epoch = Some((live.daemon_instance, live.state_revision));
    app.camera_epoch = Some(CameraEpoch {
        supervisor: live.cameras.supervisor_id.clone().unwrap(),
        revision: live.cameras.revision,
    });
    app.known_uvc_paths = vec!["/dev/video40".into(), "/dev/video42".into()];
    app.live = Some(live);
    app.daemon_up = true;
    app.daemon_reach = crate::commands::DaemonReach::Running;
    app.profiles_loaded = true;
    app.profiles = vec![
        profile(
            "Synthetic daily profile",
            &["sample-front", "sample-glasses", "sample-side"],
        ),
        profile("Synthetic alternate profile", &["sample-front"]),
    ];
    app.probes_landed = true;
    app.preferences = Some(preference_fixture(true));
    app.health = Some(HealthInfo {
        tier: "secure".into(),
        rgb_dev: Some("/dev/video40".into()),
        ir_dev: Some("/dev/video42".into()),
        mesh: true,
        adapter: false,
        rgb_pad: Some(irlume_common::PadModelStatus::Loaded),
        ir_pad: Some(irlume_common::PadModelStatus::Loaded),
        version: "synthetic fixture".into(),
        apparmor: None,
    });
    app.fp_present = true;
    app.fp = FpInfo {
        available: true,
        device: Some("Synthetic reader".into()),
        enrolled: vec!["right-index-finger".into()],
        method: "face".into(),
    };
    app.keyring_armed = Some(true);
    app.recovery = Some(RecoveryInfo {
        encrypted: true,
        recovery_set: false,
        tpm_present: true,
        key_present: true,
    });
    app.repair = vec![
        Check {
            label: "Synthetic daemon status".into(),
            sev: Sev::Ok,
            detail: "Fixture state only; no daemon was contacted".into(),
            fix: Fix::None,
        },
        Check {
            label: "Synthetic recovery reminder".into(),
            sev: Sev::Warn,
            detail: "Sample warning with enough text to exercise a narrow layout".into(),
            fix: Fix::None,
        },
    ];
    for index in 0..24 {
        app.log(
            '·',
            format!("Synthetic sample event {index:02}: no operation was performed"),
        );
    }
    app.log('!', "Synthetic long activity entry: this is deliberately longer than one terminal row. It represents a sample explanation that should wrap and remain readable in session history; it contains no hardware observation or real-user information.");
    app.log(
        '✓',
        "Synthetic latest result: fixture rendering completed; no authentication attempted",
    );
    app.mark_fixture_observations_fresh(now);
    app
}

fn visual_assert_no_work(app: &App) {
    visual_assert_expected_work(app, None);
}

fn visual_assert_expected_work(app: &App, synthetic_op: Option<&str>) {
    visual_assert_expected_state(app, synthetic_op, None);
}

fn visual_assert_expected_state(
    app: &App,
    synthetic_op: Option<&str>,
    synthetic_enroll: Option<&str>,
) {
    assert_eq!(app.op.as_ref().map(|op| op.label.as_str()), synthetic_op);
    assert_eq!(
        app.enroll.as_ref().map(|enroll| enroll.profile.as_str()),
        synthetic_enroll
    );
    assert!(app.suspend.is_none());
    assert!(
        app.live_load.is_none()
            && app.qualification_load.is_none()
            && app.light_load.is_none()
            && app.probes_load.is_none()
            && app.profiles_load.is_none()
            && app.camera_load.is_none()
            && app.heavy_load.is_none()
            && app.keyring_load.is_none()
    );
}

fn visual_frame(app: &App, label: &str, width: u16, height: u16) -> serde_json::Value {
    visual_frame_with_op(app, label, width, height, None)
}

fn visual_frame_with_op(
    app: &App,
    label: &str,
    width: u16,
    height: u16,
    synthetic_op: Option<&str>,
) -> serde_json::Value {
    visual_frame_with_state(app, label, width, height, synthetic_op, None)
}

fn visual_frame_with_state(
    app: &App,
    label: &str,
    width: u16,
    height: u16,
    synthetic_op: Option<&str>,
    synthetic_enroll: Option<&str>,
) -> serde_json::Value {
    visual_assert_expected_state(app, synthetic_op, synthetic_enroll);
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.draw_window(frame)).unwrap();
    visual_assert_expected_state(app, synthetic_op, synthetic_enroll);
    let buffer = terminal.backend().buffer();
    assert_eq!(buffer.area, Rect::new(0, 0, width, height));
    assert_eq!(
        buffer.content.len(),
        usize::from(width) * usize::from(height)
    );
    assert!(
        buffer
            .content
            .iter()
            .any(|cell| !cell.symbol().trim().is_empty()),
        "blank {label}"
    );
    for (target, _) in app.click_targets.borrow().iter() {
        if !target.is_empty() {
            assert!(
                target.x < width
                    && target.y < height
                    && target.right() <= width
                    && target.bottom() <= height,
                "{label} {width}x{height}: click target {target:?} exceeds frame"
            );
        }
    }
    let mut styles = Vec::<serde_json::Value>::new();
    let mut cells = Vec::with_capacity(buffer.content.len());
    for cell in &buffer.content {
        let style = serde_json::json!({
            "fg": format!("{:?}", cell.fg), "bg": format!("{:?}", cell.bg),
            "modifiers": format!("{:?}", cell.modifier),
            "diff": format!("{:?}", cell.diff_option),
        });
        let index = styles
            .iter()
            .position(|known| *known == style)
            .unwrap_or_else(|| {
                styles.push(style);
                styles.len() - 1
            });
        cells.push(serde_json::json!([cell.symbol(), index]));
    }
    serde_json::json!({"label":label, "width":width, "height":height,
        "synthetic":true, "styles":styles, "cells":cells})
}

fn visual_live_snapshot(stage: &str, connected: bool) -> irlume_common::live::LiveStatusSnapshot {
    serde_json::from_value(serde_json::json!({
        "live_schema":1, "daemon_instance":"11111111111111111111111111111111",
        "daemon_uptime_ms":60000, "state_revision":0, "stage":stage,
        "worker":null, "background":[], "waiting":[], "tracking_available":true,
        "cameras":{"state":"current", "supervisor_id":"22222222222222222222222222222222",
            "revision":1, "observed_ago_ms":0, "reason":null,
            "candidates":if connected { serde_json::json!([{
                "instance_id":"33333333333333333333333333333333", "generation":1,
                "endpoint_paths":["/dev/video40","/dev/video42"]
            }]) } else { serde_json::json!([]) }}
    }))
    .unwrap()
}

fn visual_live_fixture(screen: usize, snapshot: irlume_common::live::LiveStatusSnapshot) -> App {
    let mut app = visual_fixture(screen);
    let now = Instant::now();
    app.clock_override = Some(now);
    // Landing copied fixture metadata schedules no request; the normal polling
    // loop is never called. Refresh generations may become pending in memory.
    app.apply_live_snapshot(snapshot, now);
    app.mark_fixture_observations_fresh(now);
    app.screen = screen;
    visual_assert_no_work(&app);
    app
}

#[test]
fn synthetic_visual_gallery_all_screens_and_overlays() {
    use sha2::Digest;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // The key cases below only open UI overlays. A dead socket is an extra
    // guard if a future shortcut accidentally starts a request; no polling or
    // execution loop runs, and visual_assert_no_work rejects worker state.
    let _guard = dead_socket();
    let mut frames = Vec::new();
    for (screen, name) in SCREENS.iter().enumerate() {
        for (width, height) in [(80, 24), (100, 30), (120, 40)] {
            let app = visual_fixture(screen);
            let frame = visual_frame(&app, name, width, height);
            if width >= 80 {
                let text: String = frame["cells"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|cell| cell[0].as_str().unwrap())
                    .collect();
                assert!(
                    text.contains(name),
                    "missing screen name {name} at {width}x{height}"
                );
            }
            frames.push(frame);
        }
    }
    for (label, screen, key) in [
        ("Context help", SC_SETTINGS, KeyCode::Char('?')),
        ("More actions F2", SC_SETTINGS, KeyCode::F(2)),
        ("Sections F3", SC_SETTINGS, KeyCode::F(3)),
        ("Current observations F4", SC_SETTINGS, KeyCode::F(4)),
        ("Preferences action focus F6", SC_SETTINGS, KeyCode::F(6)),
        ("Full Activity Shift+L", SC_WELCOME, KeyCode::Char('L')),
    ] {
        for (width, height) in [(80, 24), (100, 30), (120, 40)] {
            let mut app = visual_fixture(screen);
            // Seed page geometry before opening or focusing the UI overlay.
            let _ = visual_frame(&app, "before overlay", width, height);
            app.on_key(key);
            match key {
                KeyCode::Char('?') => assert!(app.show_help),
                KeyCode::F(2) => assert!(app.more_actions.is_some()),
                KeyCode::F(3) => assert!(app.sections.is_some()),
                KeyCode::F(4) => assert!(app.show_live),
                KeyCode::F(6) => assert!(app.focused_action().is_some()),
                KeyCode::Char('L') => assert!(app.activity_history_open),
                _ => unreachable!(),
            }
            frames.push(visual_frame(&app, label, width, height));
        }
    }
    for (width, height) in [(80, 24), (100, 30), (120, 40)] {
        let mut first_run = visual_fixture(SC_WELCOME);
        first_run.profiles.clear();
        assert!(first_run.is_first_run());
        frames.push(visual_frame(
            &first_run,
            "Synthetic first run",
            width,
            height,
        ));
        first_run.on_key(KeyCode::F(6));
        assert!(first_run.focused_action().is_some());
        frames.push(visual_frame(
            &first_run,
            "First-run action focus F6",
            width,
            height,
        ));

        // Only a channel and Op value: fake_op spawns no worker, and no poll
        // is performed. The busy label must survive all history-only keys.
        let mut busy = visual_fixture(SC_IDENTIFY);
        let (_sender, mut op) = fake_op();
        op.label = "Synthetic pending request; no operation is running".into();
        busy.op = Some(op);
        let expected = Some("Synthetic pending request; no operation is running");
        frames.push(visual_frame_with_op(
            &busy,
            "Synthetic busy state",
            width,
            height,
            expected,
        ));
        busy.on_key(KeyCode::Char('L'));
        for key in [
            KeyCode::Char('e'),
            KeyCode::Char('q'),
            KeyCode::F(3),
            KeyCode::F(6),
        ] {
            busy.on_key(key);
            visual_assert_expected_work(&busy, expected);
            assert!(busy.activity_history_open && !busy.quit);
        }
        frames.push(visual_frame_with_op(
            &busy,
            "Busy state full Activity",
            width,
            height,
            expected,
        ));
        busy.on_key(KeyCode::Esc);
        assert!(!busy.activity_history_open && !busy.quit);
        visual_assert_expected_work(&busy, expected);

        let long_detail = (0..48)
            .map(|index| {
                format!("Synthetic detail {index:02}: a fixture explanation; no action happened.\n")
            })
            .collect::<String>()
            + "SYNTHETIC_DIALOG_TAIL";
        for is_error in [false, true] {
            let mut dialog = visual_fixture(SC_RECOVERY);
            let label = if is_error {
                dialog.error = Some(long_detail.clone());
                "Synthetic long error"
            } else {
                dialog.confirm = Some((
                    long_detail.clone(),
                    "Forget",
                    ConfirmAct::Daemon(Request::RecoveryForget {
                        user: "synthetic-sample".into(),
                    }),
                ));
                "Synthetic confirmation"
            };
            frames.push(visual_frame(&dialog, label, width, height));
            assert!(dialog.dialog_view.get().1 > 0);
            for _ in 0..128 {
                dialog.on_key(KeyCode::PageDown);
            }
            assert!(if is_error {
                dialog.error.is_some()
            } else {
                dialog.confirm.is_some()
            });
            assert_eq!(
                dialog.act_scroll, 0,
                "dialog reading must not scroll Activity"
            );
            let frame = visual_frame(&dialog, &format!("{label} scrolled tail"), width, height);
            let text: String = frame["cells"]
                .as_array()
                .unwrap()
                .iter()
                .map(|cell| cell[0].as_str().unwrap())
                .collect();
            assert!(
                text.contains("SYNTHETIC_DIALOG_TAIL"),
                "dialog tail unreachable at {width}x{height}"
            );
            frames.push(frame);
        }

        let mut input = visual_fixture(SC_RECOVERY);
        input.input = Some((
            "Synthetic masked input; no real secret".into(),
            "synthetic-placeholder".into(),
            Pending::RecoveryRestorePw,
        ));
        let frame = visual_frame(&input, "Synthetic masked input", width, height);
        let text: String = frame["cells"]
            .as_array()
            .unwrap()
            .iter()
            .map(|cell| cell[0].as_str().unwrap())
            .collect();
        assert!(!text.contains("synthetic-placeholder"));
        frames.push(frame);
        visual_assert_no_work(&input);

        for state in ["guidance", "countdown", "stalled"] {
            let mut app = visual_fixture(SC_PROFILES);
            // Pure in-memory channel/report fixtures. No enrollment worker,
            // camera request, poll, cancellation or command is invoked.
            let (_sender, mut enrollment) = fake_enroll(0, 4);
            enrollment.profile = "Synthetic enrollment".into();
            enrollment.captured = 1;
            enrollment.last = Some(good_report("Synthetic guidance: hold still"));
            if state == "countdown" {
                enrollment.count = Some(3);
            } else if state == "stalled" {
                enrollment.stalled = Some("Synthetic guide timeout; no camera was opened".into());
            }
            let stop = enrollment.stop.clone();
            app.enroll = Some(enrollment);
            frames.push(visual_frame_with_state(
                &app,
                &format!("Synthetic enrollment {state}"),
                width,
                height,
                None,
                Some("Synthetic enrollment"),
            ));
            assert!(
                !stop.load(Ordering::Relaxed),
                "drawing cannot request cancellation"
            );
        }
    }
    for (width, height) in [(80, 24), (100, 30), (120, 40)] {
        let ready = visual_live_fixture(SC_WELCOME, visual_live_snapshot("ready", false));
        frames.push(visual_frame(
            &ready,
            "Synthetic live daemon idle",
            width,
            height,
        ));

        let mut work = visual_live_snapshot("ready", true);
        work.worker = Some(irlume_common::live::LiveWorkerOperation {
            operation_id: irlume_common::diagnostics::OperationId::from_bytes([4; 16]),
            kind: irlume_common::live::LiveOperationKind::Enrollment,
            elapsed_ms: 12000,
            cancellation_requested: true,
        });
        work.waiting.push(irlume_common::live::LiveWaitingCount {
            kind: irlume_common::live::LiveOperationKind::Authentication,
            count: 1,
        });
        let mut busy = visual_live_fixture(SC_PROFILES, work);
        frames.push(visual_frame(
            &busy,
            "Synthetic external daemon work",
            width,
            height,
        ));
        busy.activity_history_open = true;
        frames.push(visual_frame(
            &busy,
            "Synthetic live work and session history",
            width,
            height,
        ));
        busy.show_live = true;
        frames.push(visual_frame(
            &busy,
            "Synthetic current work details F4",
            width,
            height,
        ));

        let starting = visual_live_fixture(SC_WELCOME, visual_live_snapshot("starting", false));
        frames.push(visual_frame(
            &starting,
            "Synthetic daemon starting",
            width,
            height,
        ));

        let mut background = visual_live_snapshot("ready", true);
        background
            .background
            .push(irlume_common::live::LiveWorkerOperation {
                operation_id: irlume_common::diagnostics::OperationId::from_bytes([5; 16]),
                kind: irlume_common::live::LiveOperationKind::CaptureQualification,
                elapsed_ms: 5000,
                cancellation_requested: false,
            });
        let mut background = visual_live_fixture(SC_CAMERAS, background);
        background.show_live = true;
        frames.push(visual_frame(
            &background,
            "Synthetic automatic qualification details",
            width,
            height,
        ));

        let mut unavailable = visual_live_fixture(SC_WELCOME, visual_live_snapshot("ready", false));
        unavailable.invalidate_source(Source::Live);
        frames.push(visual_frame(
            &unavailable,
            "Synthetic live status unavailable",
            width,
            height,
        ));

        let arrived = visual_live_fixture(SC_CAMERAS, visual_live_snapshot("ready", true));
        frames.push(visual_frame(
            &arrived,
            "Synthetic attached camera awaiting inspection",
            width,
            height,
        ));

        let mut classified = visual_live_fixture(SC_CAMERAS, visual_live_snapshot("ready", true));
        classified.pairs = vec![irlume_common::CameraPairInfo {
            rgb: "/dev/video40".into(),
            ir: "/dev/video42".into(),
            id: Some("synthetic".into()),
            fixed: true,
            privacy: false,
        }];
        classified.pairs_known = true;
        classified.health.as_mut().unwrap().rgb_dev = Some("/dev/video40".into());
        classified.health.as_mut().unwrap().ir_dev = Some("/dev/video42".into());
        frames.push(visual_frame(
            &classified,
            "Synthetic connected classified camera",
            width,
            height,
        ));
        classified.invalidate_source(Source::CameraPrivacy);
        frames.push(visual_frame(
            &classified,
            "Synthetic camera privacy observation unavailable",
            width,
            height,
        ));

        let mut removed = visual_live_fixture(SC_CAMERAS, visual_live_snapshot("ready", true));
        let mut empty = visual_live_snapshot("ready", false);
        empty.cameras.revision = 2;
        removed.apply_live_snapshot(empty, removed.now());
        removed.screen = SC_CAMERAS;
        assert!(removed
            .camera_choice("/dev/video40", "/dev/video42")
            .is_none());
        frames.push(visual_frame(
            &removed,
            "Synthetic camera disconnected",
            width,
            height,
        ));

        let mut stale = visual_live_fixture(SC_SETTINGS, visual_live_snapshot("ready", false));
        let expired = stale.now() + Duration::from_secs(65);
        stale.clock_override = Some(expired);
        stale.expire_observations(expired);
        assert!(!stale.source_usable(Source::Preferences));
        frames.push(visual_frame(
            &stale,
            "Synthetic expired preferences",
            width,
            height,
        ));
    }
    for (width, height) in [(40, 12), (79, 24), (80, 23), (30, 8), (20, 6)] {
        let app = visual_fixture(SC_SETTINGS);
        let frame = visual_frame(&app, "Window too small", width, height);
        let text: String = frame["cells"]
            .as_array()
            .unwrap()
            .iter()
            .map(|cell| cell[0].as_str().unwrap())
            .collect();
        assert!(text.contains("Window too small"));
        assert!(text.contains("Minimum: 80 × 24"));
        assert!(!text.contains("Preferences"));
        assert!(app.click_targets.borrow().is_empty());
        frames.push(frame);
    }
    assert_eq!(frames.len(), SCREENS.len() * 3 + 95);
    if let Some(output) = std::env::var_os("IRLUME_TUI_GALLERY_DIR") {
        let directory = std::path::PathBuf::from(output);
        assert!(
            directory.is_absolute(),
            "gallery directory must be absolute"
        );
        std::fs::create_dir_all(&directory).unwrap();
        let document = serde_json::json!({
            "schema":1, "synthetic":true,
            "description":"Synthetic fixtures rendered by the actual Irlume Ratatui draw functions; no live data or operations",
            "cell_order":"row-major; cells are [symbol, style-index]",
            "color_encoding":"Ratatui Color Debug; Reset means the terminal default",
            "tui_source_sha256": sha2::Sha256::digest(include_bytes!("../tui.rs")).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "visual_test_sha256": sha2::Sha256::digest(include_bytes!("visual_tests.rs")).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "activity_source_sha256": sha2::Sha256::digest(include_bytes!("activity.rs")).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "actions_source_sha256": sha2::Sha256::digest(include_bytes!("actions.rs")).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "freshness_source_sha256": sha2::Sha256::digest(include_bytes!("freshness.rs")).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "frames":frames,
        });
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("gallery.json"))
            .unwrap();
        serde_json::to_writer(&mut file, &document).unwrap();
        file.write_all(b"\n").unwrap();
    }
}
