// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! An Authentication entry ends with the authentication call that routed
//! it, whether routing was pinned or automatic (ADR-0032 cases 8, 12 and 15;
//! plan D3, D8, C5 and C6). Once the call's nested scope drops, the outer
//! request keeps the routed split installed but closed: no validation, lease,
//! late authority, publication, second call or re-entry. A routed
//! Authentication split never publishes, inside or after its call. The rows
//! reuse the parent's non-granting rig; none reaches a grant.

use super::*;

const NO_ENROLLMENT_PROOF: &str = "split publication has no retained enrollment proof";

/// The error text of a refused entry, or a marker when it was admitted.
fn reply<T>(result: irlume_common::Result<T>) -> String {
    match result {
        Ok(_) => "admitted".into(),
        Err(error) => error.to_string(),
    }
}

/// The account-routed authentication preparation, or the generic one a
/// daemon holds today and an unmigrated authentication entry still nests.
fn prepare(
    engine: &mut Engine,
    authentication: bool,
) -> irlume_common::Result<CameraRequestScope<'_>> {
    if authentication {
        engine.prepare_authentication_camera_request()
    } else {
        engine.prepare_camera_request()
    }
}

/// Attempt one publication under `engine`'s retained proof and report
/// whether the persistence callback ran.
fn publish(engine: &Engine) -> (String, bool) {
    let ran = Cell::new(false);
    let result = engine.with_prepared_camera_publication(|| {
        ran.set(true);
        Ok(())
    });
    (reply(result), ran.get())
}

/// One automatic route through a call nested in an outer request scope.
/// After the call's scope drops, its routed entry must be over: the outer
/// keeps the split installed and closed for every later use.
fn the_call_ends_its_routed_entry(outer_authentication: bool, call_authentication: bool) {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(false);
    let counts = rig.recorder.lease_counts_observer();
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        // The outer request scope a daemon holds around one call.
        let mut outer = prepare(&mut *standing.engine, outer_authentication).unwrap();
        {
            let selection = outer.camera_selection.as_ref().unwrap();
            assert!(selection.pending_pin().is_none());
            assert!(selection.routes_accounts());
        }
        {
            let mut call = prepare(&mut outer, call_authentication)
                .expect("the call nests in the automatic request");
            let (split, _) = expect_split(route(&call, rig.primary(split_binding()), false).0);
            call.select_account_split_camera(*split).unwrap();
            call.validate_camera_request()
                .expect("the call validates its own routed split");
            let operation = lease(&call, &[S_RGB, S_IR], Authentication)
                .expect("the call's one split Authentication lease");
            assert_eq!(counts(), (2, 0));
            assert!(call.pre_open_account_refusal().is_none());
            drop(operation);
        }
        // The call is over, and the entry its routing declared ended with it.
        let after = reply(outer.validate_camera_request());
        assert!(
            after.contains(CLOSED),
            "the outer scope still admits: {after}"
        );
        assert_eq!(
            lease(&outer, &[S_RGB, S_IR], Authentication).err(),
            Some(CameraLeaseError::SplitActivationDisabled)
        );
        assert!(outer.split_grant_authority_refusal().is_some());
        assert!(outer.pre_open_account_refusal().is_some());
        for authentication in [true, false] {
            assert!(
                reply(prepare(&mut outer, authentication)).contains(CLOSED),
                "a later nested call, authentication={authentication}"
            );
        }
        assert!(closed(
            outer.enter_split_trust(SplitTrustEntry::Authentication)
        ));
        let (published, ran) = publish(&outer);
        assert!(published.contains(NO_ENROLLMENT_PROOF), "{published}");
        assert!(!ran);
        // Nothing reroutes or reinstalls the ended route.
        let (again, _) = expect_split(route(&outer, rig.primary(split_binding()), false).0);
        assert!(closed(outer.select_account_split_camera(*again)));
        assert_eq!(
            installed_binding(&outer),
            Some(GroupPair::Split(Rig::key()))
        );
        assert_eq!(counts(), (0, 0));
    }
    assert_eq!(rig.recorder.calls(), vec![split_lease(Authentication)]);
    assert_eq!(counts(), (0, 0));
    assert!(!rig.lock().exists());
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

// RED: before this fix only a nested call over a pending pin ended its
// entry, so an automatically routed split stayed declared in the outer scope.

#[test]
fn an_automatic_route_ends_with_the_authentication_call_in_a_daemon_scope() {
    the_call_ends_its_routed_entry(false, true);
}

#[test]
fn an_automatic_route_ends_with_the_authentication_call_in_an_authentication_scope() {
    the_call_ends_its_routed_entry(true, true);
}

#[test]
fn an_automatic_route_ends_with_an_unmigrated_generic_call_in_a_daemon_scope() {
    the_call_ends_its_routed_entry(false, false);
}

#[test]
fn an_automatic_route_ends_with_an_unmigrated_generic_call_in_an_authentication_scope() {
    the_call_ends_its_routed_entry(true, false);
}

// Mutation guard: GREEN before this fix. Only an Enrollment split publishes;
// the install's split proof alone would otherwise reach the writer lock.

#[test]
fn a_routed_authentication_split_never_publishes_inside_its_call() {
    let _env = env_guard();
    let mut shared = shared();
    for pinned in [false, true] {
        let rig = Rig::new(WITH_ORDINARY);
        rig.authorize(pinned);
        // Enrollment is admitted too: it never lends an Authentication
        // split a publication.
        let _admitted = rig
            .recorder
            .admit_split_trust(&[Authentication, Enrollment]);
        let standing = Standing::new(&mut shared.engine);
        {
            let mut call = standing
                .engine
                .prepare_authentication_camera_request()
                .unwrap();
            let (split, _) = expect_split(route(&call, rig.primary(split_binding()), false).0);
            call.select_account_split_camera(*split).unwrap();
            call.validate_camera_request()
                .expect("the routed entry is declared and admitted");
            let (published, ran) = publish(&call);
            assert!(
                published.contains(NO_ENROLLMENT_PROOF),
                "pinned={pinned}: {published}"
            );
            assert!(!ran, "pinned={pinned}: the publication callback ran");
            assert!(
                !rig.lock().exists(),
                "pinned={pinned}: publication took the cameras.conf lock"
            );
            assert!(rig.recorder.calls().is_empty(), "pinned={pinned}");
            // The call's own lease lends it nothing either.
            let operation = lease(&call, &[S_RGB, S_IR], Authentication).unwrap();
            drop(operation);
            let (published, ran) = publish(&call);
            assert!(
                published.contains(NO_ENROLLMENT_PROOF),
                "pinned={pinned}: {published}"
            );
            assert!(!ran, "pinned={pinned}");
            assert!(!rig.lock().exists(), "pinned={pinned}");
            assert_eq!(
                rig.recorder.calls(),
                vec![split_lease(Authentication)],
                "pinned={pinned}"
            );
        }
        assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
    }
}
