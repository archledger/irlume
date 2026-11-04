// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

fn coexistence_snapshot(method: &str, face_wired: bool, fingers: bool, observed: bool) -> App {
    let mut app = live_test_app();
    app.mark_fixture_observations_fresh(app.now());
    app.profiles_loaded = true;
    app.profiles = vec![profile("enrolled-face", &["scan-1"])];
    let probes = Probes {
        fprintd_wired: true,
        login_wired: face_wired,
        face_login_wired: Some(face_wired),
        login_module_present: face_wired,
        fp_present: Some(true),
        fp_enrollment_observed: observed,
        fp: FpInfo {
            available: true,
            enrolled: if fingers { vec!["right-index-finger".into()] } else { vec![] },
            method: method.into(),
            ..FpInfo::default()
        },
        ..Probes::default()
    };
    let (tx, rx) = mpsc::channel();
    assert!(app.freshness.cycle_mut(Worker::Machine).begin());
    app.probes_load = Some(rx);
    tx.send(probes).unwrap();
    drop(tx);
    app.poll();
    assert!(app.probes_load.is_none());
    app
}

fn coexistence_row(app: &App) -> &Check {
    app.repair.iter().find(|row| row.label == "Method wiring").expect("method wiring row")
}

#[test]
fn coexistence_both_requires_face_wiring() {
    let _guard = dead_socket();
    let app = coexistence_snapshot("both", false, true, true);
    let row = coexistence_row(&app);
    assert!(row.sev != Sev::Ok);
    assert!(matches!(row.fix, Fix::Root(RootFix::LoginEnable)));
}

#[test]
fn coexistence_auto_requires_face_wiring() {
    let _guard = dead_socket();
    let app = coexistence_snapshot("auto", false, true, true);
    assert!(coexistence_row(&app).sev != Sev::Ok);
}

#[test]
fn coexistence_keyring_only_is_not_face_wiring() {
    let _guard = dead_socket();
    let mut app = coexistence_snapshot("both", false, true, true);
    app.probes.login_wired = true;
    app.probes.login_module_present = true;
    app.recompute_checks();
    assert!(coexistence_row(&app).sev != Sev::Ok);
}

#[test]
fn coexistence_empty_fingerprint_enrollment_needs_enrollment() {
    let _guard = dead_socket();
    let app = coexistence_snapshot("both", true, false, true);
    let row = coexistence_row(&app);
    assert!(row.sev != Sev::Ok);
    assert!(matches!(row.fix, Fix::Root(RootFix::FingerprintAdd)));
}

#[test]
fn coexistence_unknown_fingerprint_enrollment_has_no_mutating_advice() {
    let _guard = dead_socket();
    let app = coexistence_snapshot("both", true, false, false);
    let row = coexistence_row(&app);
    assert!(row.sev == Sev::Unknown);
    assert!(matches!(row.fix, Fix::None));
}

#[test]
fn coexistence_unknown_profiles_do_not_reuse_old_enrollment() {
    let _guard = dead_socket();
    let mut app = coexistence_snapshot("both", true, true, true);
    app.freshness.observation_mut(Source::Profiles).invalidate();
    app.run_checks();
    let row = coexistence_row(&app);
    assert!(row.sev == Sev::Unknown);
    assert!(matches!(row.fix, Fix::None));
}

#[test]
fn coexistence_missing_face_enrollment_offers_enrollment() {
    let _guard = dead_socket();
    let mut app = coexistence_snapshot("both", true, true, true);
    app.profiles.clear();
    app.run_checks();
    let row = coexistence_row(&app);
    assert!(row.sev != Sev::Ok);
    assert!(matches!(row.fix, Fix::Goto(GotoFix::Enroll)));
}

#[test]
fn coexistence_observed_paths_and_enrollment_are_reported() {
    let _guard = dead_socket();
    for method in ["both", "auto"] {
        let mut app = coexistence_snapshot(method, true, true, true);
        assert!(coexistence_row(&app).sev == Sev::Ok);
        assert!(matches!(coexistence_row(&app).fix, Fix::None));
        app.screen = SC_REPAIR;
        app.repair_sel = app.repair.iter().position(|row| row.label == "Method wiring").unwrap();
        app.repair_expanded = true;
        assert!(draw_text_at(&app, 160, 45).contains("face + fingerprint"));
    }
}

#[test]
fn coexistence_auto_does_not_require_face_enrollment_on_fingerprint_only_hosts() {
    let _guard = dead_socket();
    let mut app = coexistence_snapshot("auto", false, true, true);
    app.profiles.clear();
    app.health.as_mut().unwrap().rgb_dev = None;
    app.update_camera_availability();
    app.run_checks();
    assert!(!app.repair.iter().any(|row| row.label == "Method wiring"));
}

#[test]
fn coexistence_unknown_camera_does_not_recommend_wiring() {
    let _guard = dead_socket();
    let mut app = coexistence_snapshot("auto", false, true, true);
    app.freshness.observation_mut(Source::Health).invalidate();
    app.run_checks();
    let row = coexistence_row(&app);
    assert!(row.sev == Sev::Unknown);
    assert!(matches!(row.fix, Fix::None));
}

#[test]
fn coexistence_unreadable_face_wiring_does_not_recommend_rewiring() {
    let _guard = dead_socket();
    let mut app = coexistence_snapshot("both", true, true, true);
    app.probes.face_login_wired = None;
    app.recompute_checks();
    let row = coexistence_row(&app);
    assert!(row.sev == Sev::Unknown);
    assert!(matches!(row.fix, Fix::None));
    assert!(row.detail.contains("wiring is unavailable"));
}

#[test]
fn coexistence_disconnected_camera_does_not_recommend_wiring() {
    let _guard = dead_socket();
    let mut app = coexistence_snapshot("both", false, true, true);
    app.known_uvc_paths = vec!["/dev/video40".into()];
    app.live.as_mut().unwrap().cameras.candidates.clear();
    app.update_camera_availability();
    assert_eq!(app.face_camera_presence(), Some(false));
    app.run_checks();
    let row = coexistence_row(&app);
    assert!(row.sev == Sev::Warn);
    assert!(matches!(row.fix, Fix::None));
}
