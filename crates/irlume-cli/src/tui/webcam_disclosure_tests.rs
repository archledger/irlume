// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

fn webcam_setup_app() -> App {
    let mut app = live_test_app();
    app.health.as_mut().unwrap().tier = "convenience".into();
    app.health.as_mut().unwrap().ir_dev = None;
    app.preferences = Some(irlume_common::PreferencesState {
        face_sensor_policy: irlume_common::config::FaceSensorPolicyObservation::DefaultDual,
        ..preference_fixture(false)
    });
    let mut snapshot = live_test_snapshot();
    snapshot.cameras.candidates[0].endpoint_paths.truncate(1);
    app.apply_live_snapshot(snapshot, app.now());
    app.profiles_loaded = true;
    app
}

fn assert_webcam_setup_copy(text: &str) {
    assert!(text.contains("easier to fool"), "{text}");
    assert!(text.contains("supported lock screens"), "{text}");
    assert!(text.contains("sign you in"), "{text}");
    assert!(text.contains("sudo or app prompts"), "{text}");
    assert!(text.contains("password wallet"), "{text}");
    assert!(text.contains("still use your password"), "{text}");
}

#[test]
fn webcam_setup_disclosure_is_visible_before_overview_and_faces_enrollment() {
    let _guard = dead_socket();
    let area = Rect::new(0, 0, 80, 24);
    let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
    for screen in [SC_WELCOME, SC_PROFILES] {
        let mut app = webcam_setup_app();
        app.screen = screen;
        terminal.draw(|f| app.draw_window(f)).unwrap();
        if screen == SC_WELCOME {
            let text = rendered(&terminal);
            assert!(text.contains("Scan my face"), "{text}");
            assert!(text.contains("easier to fool"), "{text}");
            assert!(text.contains("supported lock screens"), "{text}");
            let (button, _) = app
                .click_targets
                .borrow()
                .iter()
                .find(|(_, click)| matches!(click, Click::Key(KeyCode::Char('e'))))
                .copied()
                .unwrap();
            app.on_click(button.x, button.y, area);
        } else {
            app.on_key(KeyCode::Char('e'));
        }
        assert!(matches!(app.input, Some((_, _, Pending::EnrollName))));
        assert!(app.enroll.is_none() && app.suspend.is_none() && app.op.is_none());
        terminal.draw(|f| app.draw_window(f)).unwrap();
        let text = rendered(&terminal);
        assert_webcam_setup_copy(&text);
        assert!(
            text.contains("[Enter] Continue") && text.contains("[Esc] Cancel"),
            "{text}"
        );
        if screen == SC_WELCOME {
            let cancel = target_rect(&app, |click| {
                matches!(click, Click::DialogKey(KeyCode::Esc))
            })
            .unwrap();
            app.on_click(cancel.x, cancel.y, area);
        } else {
            app.on_key(KeyCode::Esc);
        }
        assert!(app.input.is_none() && app.resume_enroll.is_none());
        assert!(app.enroll.is_none() && app.suspend.is_none() && app.op.is_none());
    }
}

#[test]
fn webcam_setup_disclosure_preserves_login_confirmation_and_cancels() {
    for screen in [SC_WELCOME, SC_PAM, SC_DONE] {
        let mut app = webcam_setup_app();
        app.screen = screen;
        app.on_key(KeyCode::Char('w'));
        let text = draw_text_at(&app, 80, 24);
        assert_webcam_setup_copy(&text);
        assert!(
            text.contains("Administrator approval is required"),
            "{text}"
        );
        assert!(text.contains("system authentication settings"), "{text}");
        assert!(
            !text.contains("Wire face authentication into login"),
            "{text}"
        );
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::PageDown);
        assert!(app.confirm.is_some() && app.suspend.is_none());
        if screen == SC_PAM {
            click_text(&mut app, "[Esc] Cancel");
        } else {
            app.on_key(KeyCode::Char('n'));
        }
        assert!(app.confirm.is_none() && app.suspend.is_none() && app.op.is_none());
        app.on_key(KeyCode::Char('w'));
        app.on_key(KeyCode::Char('y'));
        assert!(matches!(app.suspend, Some(Suspend::LoginEnable)));
        assert!(app.confirm.is_none() && app.enroll.is_none() && app.op.is_none());
    }

    // Diagnostics can offer the exact same wiring action, with its own question.
    let mut app = webcam_setup_app();
    app.screen = SC_REPAIR;
    app.repair = vec![check_row(
        "wiring",
        Sev::Fail,
        Fix::Root(RootFix::LoginEnable),
    )];
    app.apply_fix(0);
    let text = draw_text_at(&app, 80, 24);
    assert_webcam_setup_copy(&text);
    assert!(text.contains("[y] Fix") && app.suspend.is_none(), "{text}");
    app.on_key(KeyCode::Esc);
    assert!(app.confirm.is_none() && app.suspend.is_none());
}

#[test]
fn webcam_setup_disclosure_covers_dedicated_sudo_and_app_reviews() {
    for key in ['u', 'p'] {
        let mut app = webcam_setup_app();
        app.screen = SC_PAM;
        app.on_key(KeyCode::Char(key));
        let text = draw_text_at(&app, 80, 24);
        assert_webcam_setup_copy(&text);
        assert!(text.contains("where supported"), "{text}");
        assert!(app.confirm.is_some() && app.suspend.is_none() && app.op.is_none());

        app.freshness.observation_mut(Source::Health).invalidate();
        assert!(!draw_text_at(&app, 80, 24).contains("easier to fool"));
        assert!(app.confirm.is_some() && app.suspend.is_none());
        app.on_key(KeyCode::Esc);
        assert!(app.confirm.is_none() && app.suspend.is_none() && app.op.is_none());

        let mut app = webcam_setup_app();
        app.screen = SC_PAM;
        app.on_key(KeyCode::Char(key));
        app.on_key(KeyCode::Char('y'));
        assert!(matches!(
            (key, app.suspend),
            ('u', Some(Suspend::LoginEnableSudo)) | ('p', Some(Suspend::LoginEnablePolkit))
        ));
        assert!(app.confirm.is_none() && app.op.is_none());
    }
}

#[test]
fn webcam_setup_disclosure_ignores_missing_or_stale_tier_evidence() {
    for case in [
        "secure",
        "no health",
        "IR present",
        "stale inventory",
        "expired health",
        "no preferences",
        "IR-only",
    ] {
        let mut app = webcam_setup_app();
        let now = app.now();
        match case {
            "secure" => app.health.as_mut().unwrap().tier = "secure".into(),
            "no health" => app.health = None,
            "IR present" => app.health.as_mut().unwrap().ir_dev = Some("/dev/video42".into()),
            "stale inventory" => app.clock_override = Some(now + Duration::from_secs(5)),
            "expired health" => app
                .freshness
                .observation_mut(Source::Health)
                .record(true, now - Duration::from_secs(21)),
            "no preferences" => app.preferences = None,
            "IR-only" => {
                use irlume_common::config::{FaceSensorPolicy, FaceSensorPolicyObservation};
                app.preferences.as_mut().unwrap().face_sensor_policy =
                    FaceSensorPolicyObservation::Explicit(FaceSensorPolicy::IrOnlyExperimental);
            }
            _ => unreachable!(),
        }
        assert!(!app.recommended().contains("Face (RGB)"), "{case}");
        assert!(
            !draw_text_at(&app, 80, 24).contains("easier to fool"),
            "{case}"
        );
        app.screen = SC_PROFILES;
        app.on_key(KeyCode::Char('e'));
        assert!(
            !draw_text_at(&app, 80, 24).contains("easier to fool"),
            "{case}"
        );
        app.on_key(KeyCode::Esc);
        app.screen = SC_PAM;
        app.on_key(KeyCode::Char('w'));
        assert!(
            !draw_text_at(&app, 80, 24).contains("easier to fool"),
            "{case}"
        );
        assert!(app.confirm.is_some() && app.suspend.is_none());
    }
}

#[test]
fn webcam_setup_disclosure_is_rechecked_while_existing_reviews_are_open() {
    let mut app = webcam_setup_app();
    app.screen = SC_PROFILES;
    app.on_key(KeyCode::Char('e'));
    assert_webcam_setup_copy(&draw_text_at(&app, 80, 24));
    app.on_key(KeyCode::Char('X'));
    app.freshness.observation_mut(Source::Live).invalidate();
    assert!(!draw_text_at(&app, 80, 24).contains("easier to fool"));
    assert!(matches!(app.input, Some((_, name, Pending::EnrollName)) if name == "X"));

    let mut app = webcam_setup_app();
    app.screen = SC_PAM;
    app.on_key(KeyCode::Char('w'));
    assert_webcam_setup_copy(&draw_text_at(&app, 80, 24));
    app.freshness.observation_mut(Source::Health).invalidate();
    assert!(!draw_text_at(&app, 80, 24).contains("easier to fool"));
    assert!(app.confirm.is_some() && app.suspend.is_none());
}

#[test]
fn webcam_setup_disclosure_applies_only_to_matching_more_actions_reviews() {
    for (args, fields, tail, disclosed) in [
        (
            &["enroll"][..],
            &["Profile", "3"][..],
            &["--name", "Profile", "--scans", "3", "--user", "testuser"][..],
            true,
        ),
        (
            &["enroll", "--reset"][..],
            &["", ""][..],
            &["--user", "testuser"][..],
            true,
        ),
        (
            &["login", "enable", "--with-sudo", "--with-polkit", "--apply"][..],
            &[][..],
            &[][..],
            true,
        ),
        (&["login", "enable"][..], &[][..], &[][..], false),
    ] {
        let mut app = webcam_setup_app();
        app.screen = SC_PROFILES;
        let action = actions::ACTIONS
            .iter()
            .find(|action| action.args == args)
            .unwrap();
        app.prepare_action(actions::Invocation {
            action,
            values: fields.iter().map(|value| (*value).into()).collect(),
        });
        let text = draw_text_at(&app, 80, 24);
        if disclosed {
            assert_webcam_setup_copy(&text);
        } else {
            assert!(!text.contains("easier to fool"), "{text}");
        }
        assert!(app.suspend.is_none());
        app.on_key(KeyCode::Char('y'));
        let Some(Suspend::MoreAction(invocation)) = app.suspend else {
            panic!("review must schedule only the existing CLI action");
        };
        let expected: Vec<_> = args.iter().chain(tail).copied().collect();
        assert_eq!(invocation.args(&app.user), expected);
        assert_eq!(invocation.action.root, args.first() == Some(&"login"));
    }
}
