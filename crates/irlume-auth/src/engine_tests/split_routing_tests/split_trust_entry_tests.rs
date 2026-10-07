// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The declaration rules of the split trust entry itself (ADR-0032 cases 12
//! and 15): one declaration per request, a marker that a failed declaration
//! rolls back, and the reason an entry without IR names. They reuse the
//! parent's non-granting fixture and leave its rows unchanged.

use super::*;

const ALREADY_RUNNING: &str = "a split camera trust entry is already running in this request";
const IR_OFF: &str = "split camera trust needs both sides and IR is unavailable or forced off";
const DRIFT: &str = "camera endpoints or availability changed during prepared request";
const CHANGED: &str = "split authorization is absent, invalid or changed; select it again";

/// The exact policy reason of a refusal; anything else fails the test.
fn policy_refusal(result: irlume_common::Result<()>) -> String {
    match result {
        Err(irlume_common::Error::Policy(reason)) => reason,
        other => panic!("expected a policy refusal, got {other:?}"),
    }
}

#[test]
fn a_second_split_trust_declaration_refuses_and_keeps_the_first() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let _admitted = fixture
        .recorder
        .admit_split_trust(&[Enrollment, Authentication]);
    // Leaving with no retained selection is a no-op.
    shared.engine.leave_split_trust();
    assert!(shared.engine.camera_selection.is_none());
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    request
        .enter_split_trust(SplitTrustEntry::Enrollment)
        .expect("the admitted Enrollment entry is declared");
    // No nesting: the same entry again refuses with its own reason, and the
    // other entry still answers with the closed text first.
    assert_eq!(
        policy_refusal(request.enter_split_trust(SplitTrustEntry::Enrollment)),
        ALREADY_RUNNING
    );
    assert_eq!(
        policy_refusal(request.enter_split_trust(SplitTrustEntry::Authentication)),
        CLOSED
    );
    // Neither refusal disturbed the first declaration.
    request
        .validate_camera_request()
        .expect("the first declaration still validates");
    let operation = acquire(&request, &[RGB, IR], Enrollment)
        .expect("the first declaration still leases both original sides");
    assert!(operation.lease().is_split_pair());
    assert_eq!(operation.lease().operation(), Enrollment);
    drop(operation);
    // One leave closes it: a refused declaration added no nesting level.
    request.leave_split_trust();
    assert_eq!(policy_refusal(request.validate_camera_request()), CLOSED);
    assert_eq!(
        acquire(&request, &[RGB, IR], Enrollment).err(),
        Some(CameraLeaseError::SplitActivationDisabled)
    );
    drop(request);
    assert!(shared.engine.camera_selection.is_none());
    assert_eq!(fixture.recorder.calls(), vec![lease_call(Enrollment)]);
}

#[test]
fn a_failed_split_trust_declaration_rolls_its_marker_back() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let _admitted = fixture.recorder.admit_split_trust(&[Enrollment]);
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();

    // Endpoint drift after preparation fails the declaration's own check.
    request.rgb_dev = "/dev/irlume-split-routing-drift".into();
    assert_eq!(
        policy_refusal(request.enter_split_trust(SplitTrustEntry::Enrollment)),
        DRIFT
    );
    // The closed gate answers, not the drift: the marker was rolled back.
    assert_eq!(policy_refusal(request.validate_camera_request()), CLOSED);
    // Undoing the drift does not revive the refused declaration.
    request.rgb_dev = RGB.into();
    assert_eq!(policy_refusal(request.validate_camera_request()), CLOSED);
    assert!(refusal(request.prepare_camera_request()).contains(CLOSED));
    assert_eq!(
        acquire(&request, &[RGB, IR], Enrollment).err(),
        Some(CameraLeaseError::SplitActivationDisabled)
    );
    // A rolled back marker never blocks a later valid declaration.
    request
        .enter_split_trust(SplitTrustEntry::Enrollment)
        .expect("the restored scope declares its entry");
    request.leave_split_trust();

    // A fresh machine authorization supersedes the retained publication.
    let _superseding = fixture.choice();
    assert_eq!(
        policy_refusal(request.enter_split_trust(SplitTrustEntry::Enrollment)),
        CHANGED
    );
    assert_eq!(policy_refusal(request.validate_camera_request()), CLOSED);
    // The lease arm does not reread the publication, so only the rolled back
    // marker keeps the stale scope from leasing here.
    assert_eq!(
        acquire(&request, &[RGB, IR], Enrollment).err(),
        Some(CameraLeaseError::SplitActivationDisabled)
    );
    drop(request);
    assert!(
        fixture.recorder.calls().is_empty(),
        "a failed declaration reached the camera boundary: {:?}",
        fixture.recorder.calls()
    );
}

#[test]
fn split_enrollment_entry_names_the_missing_ir_side() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    std::env::set_var("IRLUME_FORCE_NO_IR", "1");
    for admitted in [false, true] {
        let kinds: &[CameraOperationKind] = if admitted { &[Enrollment] } else { &[] };
        let _token = fixture.recorder.admit_split_trust(kinds);
        let mut request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        assert!(!request.ir_available);
        // The closed predicate answers first; once admitted, the IR reason.
        let expected = if admitted { IR_OFF } else { CLOSED };
        assert_eq!(
            policy_refusal(request.enter_split_trust(SplitTrustEntry::Enrollment)),
            expected,
            "admitted={admitted}"
        );
        assert_eq!(
            policy_refusal(request.validate_camera_request()),
            CLOSED,
            "admitted={admitted}"
        );
    }
    assert!(shared.engine.camera_selection.is_none());
    assert!(fixture.recorder.calls().is_empty());
}
