// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

fn observation_page(app: &App, width: u16, height: u16) -> String {
    let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
    term.draw(|frame| match app.screen {
        SC_PROFILES => app.draw_profiles(frame, frame.area()),
        SC_SETTINGS => app.draw_settings(frame, frame.area()),
        SC_DONE => app.draw_done(frame, frame.area()),
        SC_FINGERPRINT => app.draw_fingerprint(frame, frame.area()),
        _ => panic!("unexpected observation page"),
    })
    .unwrap();
    rendered(&term)
}

struct ObservationConsentEnv(Option<std::ffi::OsString>);

impl ObservationConsentEnv {
    fn set(value: Option<&str>) -> Self {
        let old = std::env::var_os("IRLUME_PRIVILEGED_FACE_CONSENT");
        match value {
            Some(value) => std::env::set_var("IRLUME_PRIVILEGED_FACE_CONSENT", value),
            None => std::env::remove_var("IRLUME_PRIVILEGED_FACE_CONSENT"),
        }
        Self(old)
    }
}

impl Drop for ObservationConsentEnv {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => std::env::set_var("IRLUME_PRIVILEGED_FACE_CONSENT", value),
            None => std::env::remove_var("IRLUME_PRIVILEGED_FACE_CONSENT"),
        }
    }
}

fn observation_preferences() -> App {
    let mut app = test_app();
    app.screen = SC_SETTINGS;
    app.preferences = Some(irlume_common::PreferencesState {
        face_sensor_policy: irlume_common::config::FaceSensorPolicyObservation::DefaultDual,
        privileged_face_consent: Some(true),
        enforce_biopolicy: Some(false),
        consent_overridden: false,
        biopolicy_overridden: false,
        forbid_external_cameras: Some(false),
    });
    app
}

fn observation_result(text: &str) -> String {
    text.lines()
        .skip_while(|line| !line.contains("Last recognition test"))
        .take_while(|line| {
            line.contains("Last recognition test")
                || line.contains("synthetic")
                || line.contains("TAIL_SENTINEL")
                || line.contains('…')
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn tui_observation_short_recognition_result_is_visible() {
    let _guard = dead_socket();
    let mut app = test_app();
    app.screen = SC_PROFILES;
    app.profiles_loaded = true;
    app.profiles = vec![profile("P", &["scan"])];
    app.identify_result = Some(map_identify(Response::Error("synthetic failure".into())));
    app.identify_checked_at = Some(app.now());
    let text = observation_page(&app, 80, 12);
    assert!(
        text.contains("synthetic failure") && text.contains("just now"),
        "{text}"
    );
}

#[test]
fn tui_observation_long_recognition_result_has_visible_overflow() {
    let _guard = dead_socket();
    let mut app = test_app();
    app.screen = SC_PROFILES;
    app.profiles_loaded = true;
    app.profiles = vec![profile("P", &["scan"])];
    let result = map_identify(Response::Error(format!(
        "{}TAIL_SENTINEL",
        "synthetic detail ".repeat(100)
    )));
    app.log('·', result.1.clone());
    app.identify_result = Some(result);
    app.identify_checked_at = Some(app.now());
    app.activity_open = true;
    let text = draw_text_at(&app, 80, 24);
    let result = observation_result(&text);
    assert!(!result.is_empty(), "result must appear on Faces: {text}");
    assert!(
        result.contains("TAIL_SENTINEL") || result.contains('…'),
        "silently clipped result: {result}"
    );
    assert!(app
        .activity
        .iter()
        .any(|(_, text)| text.contains("TAIL_SENTINEL")));
}

#[test]
fn tui_observation_unoverridden_consent_can_open_confirmation() {
    let _guard = dead_socket();
    let _env = ObservationConsentEnv::set(None);
    let mut app = observation_preferences();
    app.on_key(KeyCode::Char('p'));
    let confirmed = app.confirm.is_some();
    drain_loads(&mut app);
    assert!(confirmed);
}

#[test]
fn tui_observation_local_consent_override_is_not_actionable() {
    let _guard = dead_socket();
    let _env = ObservationConsentEnv::set(Some("1"));
    let app = observation_preferences();
    let text = observation_page(&app, 120, 40);
    assert!(text.contains("Local environment override"), "{text}");
    assert!(!app.focus_actions().iter().any(|(key, _)| *key == "p"));
}

#[test]
fn tui_observation_local_consent_override_cannot_dispatch() {
    let _guard = dead_socket();
    let _env = ObservationConsentEnv::set(Some("1"));
    let mut app = observation_preferences();
    app.on_key(KeyCode::Char('p'));
    let queued = app.confirm.is_some() || app.suspend.is_some();
    drain_loads(&mut app);
    assert!(!queued, "local override still opened a setting action");
}

fn observation_done(compatible: bool) -> App {
    let mut app = live_test_app();
    app.screen = SC_DONE;
    app.daemon_up = true;
    app.profiles_loaded = true;
    app.probes_landed = true;
    app.probes.login_wired = true;
    app.fp.method = "face".into();
    app.caps = irlume_camera::Caps {
        rgb: true,
        ir_pair: true,
    };
    let mut p = profile("P", &["scan"]);
    p.live_recognizer = Some("current".into());
    p.scans_by_recognizer = [(if compatible { "current" } else { "old" }.into(), 1)].into();
    app.profiles = vec![p];
    app
}

#[test]
fn tui_observation_compatible_setup_keeps_its_facts() {
    let _guard = dead_socket();
    let app = observation_done(true);
    assert_eq!(app.live_scans(), Some(1));
    let text = observation_page(&app, 120, 40);
    assert!(
        text.contains("login connection") && text.contains("1 profile"),
        "{text}"
    );
}

#[test]
fn tui_observation_incompatible_setup_is_not_all_set() {
    let _guard = dead_socket();
    let app = observation_done(false);
    assert_eq!(app.live_scans(), Some(0));
    let text = observation_page(&app, 120, 40);
    assert!(text.contains("none for the loaded recognizer"), "{text}");
    assert!(!text.contains("All set."), "{text}");
}

#[test]
fn tui_observation_fingerprint_only_does_not_promise_face() {
    let _guard = dead_socket();
    let mut app = test_app();
    app.screen = SC_FINGERPRINT;
    app.fp.available = true;
    app.fp_present = true;
    app.fp.method = "fingerprint".into();
    let text = observation_page(&app, 120, 40);
    assert!(!text.contains("alongside face, never instead"), "{text}");
}

#[test]
fn tui_observation_no_camera_does_not_offer_both() {
    let _guard = dead_socket();
    let mut app = test_app();
    app.screen = SC_FINGERPRINT;
    app.fp.available = true;
    app.fp_present = true;
    app.fp.method = "fingerprint".into();
    assert!(!app.caps.rgb);
    let text = observation_page(&app, 120, 40);
    assert!(!text.contains("face OR fingerprint"), "{text}");
    assert!(!app
        .screen_actions()
        .iter()
        .any(|(_, label)| label.contains("Enable Both")));
}

#[test]
fn tui_observation_camera_and_reader_keep_the_enable_action() {
    let _guard = dead_socket();
    let mut app = test_app();
    app.screen = SC_FINGERPRINT;
    app.fp.available = true;
    app.fp_present = true;
    app.fp.method = "both".into();
    app.caps.rgb = true;
    let text = observation_page(&app, 120, 40);
    assert!(text.contains("fingerprint"), "{text}");
    assert!(app.screen_actions().iter().any(|(key, _)| *key == "e"));
}

#[test]
fn tui_observation_sealing_does_not_guarantee_wallet_delivery() {
    let (ok, message) = map_sealed(Response::PasswordSealed);
    assert!(ok && message.contains("keyring armed"));
    assert!(!message.contains("will open your wallet"), "{message}");
}

#[test]
fn tui_observation_footer_handles_exact_fit_unicode_and_empty_areas() {
    let _guard = dead_socket();
    let mut app = test_app();
    app.screen = SC_PROFILES;
    app.profiles_loaded = true;
    app.profiles = vec![profile("P", &["scan"])];
    app.identify_result = Some((false, "synthetic short result".into()));
    app.identify_checked_at = Some(app.now());
    let lines = Paragraph::new(vec![app.recognition_test_line().unwrap()])
        .wrap(Wrap { trim: false })
        .line_count(38);
    let height = u16::try_from(lines * 2).unwrap();
    let exact = observation_page(&app, 40, height);
    assert!(!observation_result(&exact).contains('…'), "{exact}");
    assert!(exact.contains("just now"), "{exact}");

    app.identify_result = Some((
        false,
        format!("{}TAIL_SENTINEL", "synthetic 界 ".repeat(100)),
    ));
    let narrow = observation_page(&app, 40, 8);
    let result = observation_result(&narrow);
    assert!(result.contains('…'), "{narrow}");
    let marker = result.lines().find(|line| line.contains('…')).unwrap();
    assert!(
        !marker.contains('界'),
        "the marker row must not retain a wide glyph: {marker}"
    );
    for (width, height) in [(80, 0), (1, 1), (2, 1), (40, 2)] {
        let _ = observation_page(&app, width, height);
    }
}

#[test]
fn tui_observation_consent_override_matrix_preserves_confirmation() {
    let _guard = dead_socket();
    for (local, daemon, fresh, consent) in [
        (false, false, true, Some(true)),
        (false, false, true, Some(false)),
        (true, false, true, Some(true)),
        (false, true, true, Some(true)),
        (true, true, true, Some(false)),
        (true, true, false, Some(true)),
        (false, true, false, Some(true)),
        (false, false, true, None),
    ] {
        let _env = ObservationConsentEnv::set(local.then_some("1"));
        let mut app = observation_preferences();
        let mut state = app.preferences.unwrap();
        state.consent_overridden = daemon;
        state.privileged_face_consent = consent;
        if !fresh {
            app.invalidate_source(Source::Preferences);
            app.screen = SC_SETTINGS;
        }
        app.preferences = Some(state);
        let blocked = local || (daemon && fresh);
        let actions = app.focus_actions();
        assert_eq!(actions.iter().any(|(key, _)| *key == "p"), !blocked);
        let text = observation_page(&app, 120, 45);
        if local && !fresh {
            assert!(text.contains("Local environment override"), "{text}");
            assert!(!text.contains("Daemon environment override"), "{text}");
        }
        app.on_key(KeyCode::Char('p'));
        let queued = app.confirm.is_some() || app.suspend.is_some();
        assert_eq!(queued, !blocked && fresh && consent.is_some());
        if queued {
            assert!(app.confirm.is_some() && app.suspend.is_none());
        }
        drain_loads(&mut app);
    }
}

#[test]
fn tui_observation_setup_summary_never_certifies_authentication_readiness() {
    let _guard = dead_socket();
    for case in 0..7 {
        let mut app = observation_done(case == 0);
        match case {
            2 | 3 => {
                let mut group = camera_group("secondary", &[("P", 2)], None);
                group.selected = true;
                group.stale = case == 3;
                group.connected = case == 2;
                app.camera_groups = vec![group];
            }
            4 => {
                app.roles_epoch = Some(CameraEpoch {
                    supervisor: "older inventory".into(),
                    revision: 0,
                });
                assert_ne!(app.roles_epoch, app.camera_epoch);
            }
            5 => {
                app.profiles.clear();
                app.fp.available = true;
                app.fp_present = true;
                app.fp.method = "fingerprint".into();
                app.caps = irlume_camera::Caps {
                    rgb: false,
                    ir_pair: false,
                };
            }
            6 => {
                app.invalidate_source(Source::Live);
                app.screen = SC_DONE;
            }
            _ => {}
        }
        let text = observation_page(&app, 120, 40);
        assert!(
            text.contains("not an authentication-readiness check"),
            "case {case}: {text}"
        );
        assert!(!text.contains("All set."), "case {case}: {text}");
        assert!(!text.contains("Not set up yet"), "case {case}: {text}");
    }
}

#[test]
fn tui_observation_fingerprint_confirmation_does_not_predict_face_availability() {
    let _guard = dead_socket();
    for (rgb, method) in [(false, "fingerprint"), (true, "both"), (false, "none")] {
        let mut app = test_app();
        app.screen = SC_FINGERPRINT;
        app.fp.available = true;
        app.fp_present = true;
        app.fp.method = method.into();
        app.caps.rgb = rgb;
        let text = observation_page(&app, 120, 40);
        assert!(text.contains("enable fingerprint login"), "{text}");
        assert!(!text.contains("never instead"), "{text}");
        app.on_key(KeyCode::Char('e'));
        let question = &app.confirm.as_ref().expect("confirmation").0;
        assert!(question.contains("Face availability depends"), "{question}");
        assert!(
            !question.contains("accept face or fingerprint"),
            "{question}"
        );
        app.on_key(KeyCode::Esc);
        assert!(app.confirm.is_none() && app.suspend.is_none());
        app.on_key(KeyCode::Char('e'));
        app.on_key(KeyCode::Char('y'));
        assert!(matches!(app.suspend, Some(Suspend::FingerprintEnable)));
        app.suspend = None;
        drain_loads(&mut app);
    }
}

#[test]
fn tui_observation_sealing_errors_remain_failures() {
    let (ok, message) = map_sealed(Response::Error("synthetic refusal".into()));
    assert!(!ok && message == "arm failed: synthetic refusal");
    assert!(!map_sealed(Response::Pong).0);
}
