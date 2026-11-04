// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

fn camera_layout_fixture() -> App {
    let mut app = live_test_app();
    let now = app.now();
    app.mark_fixture_observations_fresh(now);
    app.screen = SC_CAMERAS;
    let mut pair = live_test_pair();
    pair.name = Some("Synthetic camera".into());
    pair.id = Some("1111:2222".into());
    pair.identity = Some("1111:2222:synthetic".into());
    app.primary_camera = Some(irlume_common::PrimaryCameraBinding {
        rgb: pair.identity.clone(),
        ir: pair.identity.clone(),
        connected_handle: None,
    });
    app.pairs = vec![pair];
    app.pairs_known = true;
    app.classified_epoch = app.camera_epoch.clone();
    app.roles_epoch = app.camera_epoch.clone();
    app.profiles_loaded = true;
    let mut face = profile("synthetic", &["scan-1"]);
    face.live_recognizer = Some("synthetic-recognizer".into());
    face.scans_by_recognizer
        .insert("synthetic-recognizer".into(), 1);
    app.profiles = vec![face];
    app.preferences = Some(irlume_common::PreferencesState {
        forbid_external_cameras: Some(false),
        ..app.preference_state()
    });
    app.invalidate_source(Source::CameraPrivacy);
    app
}

#[test]
fn camera_layout_marks_clipped_status_and_keeps_the_warning_style() {
    let _guard = dead_socket();
    let app = camera_layout_fixture();
    let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
    terminal
        .draw(|frame| app.draw_cameras(frame, frame.area()))
        .unwrap();
    let text = rendered(&terminal);
    let row = text
        .lines()
        .find(|line| line.contains("● Synthetic camera"))
        .unwrap();
    assert!(row.trim_end().ends_with('…'), "{row}");
    assert!(row.contains("privacy"), "{row}");
    let y = text
        .lines()
        .position(|line| line.contains("● Synthetic camera"))
        .unwrap() as u16;
    let cell = &terminal.backend().buffer()[(79, y)];
    assert_eq!(cell.symbol(), "…");
    assert_eq!(cell.fg, th().warn);
}

#[test]
fn camera_layout_full_frame_marks_clipped_status_at_supported_widths() {
    let _guard = dead_socket();
    let app = camera_layout_fixture();
    for width in [80, 100, 120, 160] {
        let text = draw_text_at(&app, width, 40);
        let row = text
            .lines()
            .find(|line| line.contains("● Synthetic camera"))
            .unwrap();
        let status = row
            .split("● Synthetic camera")
            .nth(1)
            .unwrap()
            .trim_end_matches([' ', '│']);
        assert!(
            status.contains("privacy unobserved") || status.ends_with('…'),
            "{width}: {row}"
        );
    }
}

#[test]
fn camera_layout_keeps_complete_status_when_the_row_fits() {
    let _guard = dead_socket();
    let app = camera_layout_fixture();
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal
        .draw(|frame| app.draw_cameras(frame, frame.area()))
        .unwrap();
    let text = rendered(&terminal);
    let row = text
        .lines()
        .find(|line| line.contains("● Synthetic camera"))
        .unwrap();
    assert!(row.contains("◐ privacy unobserved"), "{row}");
    assert!(!row.contains('…'), "{row}");
}

#[test]
fn camera_layout_clipping_keeps_selection_and_full_details() {
    let _guard = dead_socket();
    let mut app = camera_layout_fixture();
    app.cam_details = true;
    let text = draw_text_at(&app, 100, 40);
    assert!(text.contains("privacy     unobserved"), "{text}");
    assert!(app
        .click_targets
        .borrow()
        .iter()
        .any(|(_, click)| matches!(click, Click::Select(0))));
    assert_eq!(app.cam_sel, 0);
}
