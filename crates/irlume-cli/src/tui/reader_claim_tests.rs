// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

fn reader_claim_snapshot(enrollment_observed: bool, claimed: bool) -> App {
    let mut app = live_test_app();
    let probes = Probes {
        fp_present: Some(true),
        fp_enrollment_observed: enrollment_observed,
        reader_stuck: claimed,
        fp: FpInfo {
            available: true,
            device: Some("Synthetic reader".into()),
            enrolled: if enrollment_observed {
                vec!["right-index-finger".into()]
            } else {
                Vec::new()
            },
            method: "fingerprint".into(),
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
    assert!(app.source_usable(Source::Machine));
    assert!(app.source_usable(Source::FingerprintReader));
    assert_eq!(app.source_usable(Source::Fingerprint), enrollment_observed);
    assert!(app.suspend.is_none() && app.op.is_none());
    app
}

fn reader_claim_fix(app: &App) -> Option<usize> {
    app.repair
        .iter()
        .position(|row| matches!(row.fix, Fix::Root(RootFix::RestartFprintd)))
}

#[test]
fn reader_claim_survives_unavailable_enrollment() {
    let _guard = dead_socket();
    let app = reader_claim_snapshot(false, true);
    let claim = app.repair.iter().find(|row| row.label == "Fingerprint reader");
    assert!(claim.is_some_and(|row| row.sev == Sev::Fail));
    assert!(reader_claim_fix(&app).is_some());
    assert!(app.repair.iter().any(|row| {
        row.label == "Fingerprint enrollment" && row.sev == Sev::Unknown
    }));
    assert!(!app.source_usable(Source::Fingerprint));
}

#[test]
fn reader_claim_is_rendered_beside_unknown_enrollment() {
    let _guard = dead_socket();
    let mut app = reader_claim_snapshot(false, true);
    app.screen = SC_REPAIR;
    app.repair_sel = reader_claim_fix(&app).expect("claim remedy remains available");
    app.repair_expanded = true;
    let text = draw_text_at(&app, 160, 45);
    assert!(text.contains("Fingerprint reader"), "{text}");
    assert!(text.contains("Fingerprint enrollment"), "{text}");
    assert!(text.contains("claim"), "{text}");
}

#[test]
fn reader_claim_with_known_enrollment_still_offers_restart() {
    let _guard = dead_socket();
    let app = reader_claim_snapshot(true, true);
    assert!(reader_claim_fix(&app).is_some());
    assert!(!app.repair.iter().any(|row| {
        row.label == "Fingerprint reader" && row.sev == Sev::Ok
    }));
}

#[test]
fn reader_claim_unknown_enrollment_alone_does_not_offer_restart() {
    let _guard = dead_socket();
    let app = reader_claim_snapshot(false, false);
    assert!(reader_claim_fix(&app).is_none());
    assert!(app.repair.iter().any(|row| {
        row.label == "Fingerprint enrollment" && row.sev == Sev::Unknown
    }));
}

#[test]
fn reader_claim_healthy_refresh_clears_old_remedy() {
    let _guard = dead_socket();
    let mut app = reader_claim_snapshot(true, true);
    assert!(reader_claim_fix(&app).is_some());
    app.probes.reader_stuck = false;
    app.recompute_checks();
    assert!(reader_claim_fix(&app).is_none());
    assert!(app.repair.iter().any(|row| {
        row.label == "Fingerprint reader" && row.sev == Sev::Ok
    }));
}

#[test]
fn reader_claim_expired_machine_observation_cannot_offer_restart() {
    let _guard = dead_socket();
    let mut app = reader_claim_snapshot(true, true);
    assert!(reader_claim_fix(&app).is_some());
    app.freshness.observation_mut(Source::Machine).invalidate();
    app.run_checks();
    assert!(reader_claim_fix(&app).is_none());
}

#[test]
fn reader_claim_restart_requires_confirmation_and_can_cancel() {
    let _guard = dead_socket();
    let mut app = reader_claim_snapshot(true, true);
    app.apply_fix(reader_claim_fix(&app).unwrap());
    assert!(matches!(app.confirm, Some((_, _, ConfirmAct::Sus(Suspend::RestartFprintd)))));
    assert!(app.suspend.is_none());
    app.on_key(KeyCode::Esc);
    assert!(app.confirm.is_none() && app.suspend.is_none());
}
