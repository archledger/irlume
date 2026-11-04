// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

fn bitwarden_body_has_setup(app: &App) -> bool {
    app.click_targets.borrow_mut().clear();
    let mut terminal = Terminal::new(TestBackend::new(120, 60)).unwrap();
    terminal
        .draw(|frame| app.draw_pam(frame, frame.area()))
        .unwrap();
    app.click_targets
        .borrow()
        .iter()
        .any(|(_, click)| matches!(click, Click::Key(KeyCode::Char('b'))))
}

#[test]
fn bitwarden_setup_action_waits_for_an_observed_missing_policy() {
    let _guard = dead_socket();
    use crate::bitwarden::TuiState;
    for (state, known, expected) in [
        (None, true, false),
        (None, false, false),
        (Some(TuiState::Ready), true, false),
        (Some(TuiState::SnapMissing), true, false),
        (Some(TuiState::NeedsSetup), true, true),
        (Some(TuiState::NeedsSetup), false, false),
    ] {
        let mut app = test_app();
        app.screen = SC_PAM;
        app.heavy = state;
        app.heavy_known = known;
        assert_eq!(bitwarden_body_has_setup(&app), expected, "page action");
        assert_eq!(
            app.screen_actions().iter().any(|(key, _)| *key == "b"),
            expected,
            "advertised action"
        );
        assert_eq!(
            app.help_body().contains("Configure App Unlock"),
            expected,
            "help action"
        );
        app.on_key(KeyCode::F(6));
        let mut reached = false;
        for _ in 0..app.focus_actions().len() {
            reached |= app.focused_action().is_some_and(|(key, _)| key == "b");
            app.on_key(KeyCode::Down);
        }
        assert_eq!(reached, expected, "F6 walk");
        assert!(app.suspend.is_none() && app.confirm.is_none() && app.op.is_none());
    }
}

#[test]
fn bitwarden_setup_focus_is_withdrawn_when_its_observation_is_invalidated() {
    let _guard = dead_socket();
    let mut app = test_app();
    app.screen = SC_PAM;
    app.heavy = Some(crate::bitwarden::TuiState::NeedsSetup);
    app.heavy_known = true;
    app.action_focus = Some((SC_PAM, "b"));
    assert!(app.focused_action().is_some());
    app.invalidate_source(Source::Apps);
    assert!(app.focused_action().is_none());
    assert!(!bitwarden_body_has_setup(&app));
    app.on_key(KeyCode::F(6));
    assert_eq!(app.focused_action().map(|(key, _)| key), Some("w"));
}

#[test]
fn bitwarden_setup_focus_reveals_the_matching_body_action() {
    let _guard = dead_socket();
    let mut app = test_app();
    app.screen = SC_PAM;
    app.heavy = Some(crate::bitwarden::TuiState::NeedsSetup);
    app.heavy_known = true;
    app.on_key(KeyCode::F(6));
    for _ in 0..app.focus_actions().len() {
        if app.focused_action().map(|(key, _)| key) == Some("b") {
            break;
        }
        app.on_key(KeyCode::Down);
    }
    assert_eq!(app.focused_action().map(|(key, _)| key), Some("b"));
    let text = draw_text_at(&app, 100, 30);
    assert!(text.contains("Set up Bitwarden"), "{text}");
    assert!(text.contains("Action: Configure App Unlock"), "{text}");
    // Do not activate: the real handler rechecks the host before confirming.
    assert!(app.suspend.is_none() && app.confirm.is_none() && app.op.is_none());
}
