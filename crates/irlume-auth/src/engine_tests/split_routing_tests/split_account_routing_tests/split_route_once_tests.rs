// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Account routing runs at most once per request (ADR-0032 case 8; plan D8
//! and C5). An ordinary pair routed in a request, accepted or refused at its
//! validation, never yields to a split choice afterwards, in the same call
//! or a later one: no fallback and no rerank. The devices stay on the
//! ordinary pair and no split lease is taken. A standing ordinary pair that
//! no account route chose is not a route. The rows reuse the parent's
//! non-granting rig; none reaches a grant.

use super::*;

const NOT_ROUTABLE: &str = "split account routing needs an unrouted automatic or pinned request";
const STALE: &str = "prepared ordinary camera pair is no longer Current";

/// The error text of a refused entry, or a marker when it was admitted.
fn reply<T>(result: irlume_common::Result<T>) -> String {
    match result {
        Ok(_) => "admitted".into(),
        Err(error) => error.to_string(),
    }
}

fn devices(engine: &Engine) -> (&str, &str, bool) {
    (
        engine.rgb_dev.as_str(),
        engine.ir_dev.as_str(),
        engine.ir_available,
    )
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

/// The rig's one ordinary pair, as this request's retained view lists it.
fn listed_ordinary(engine: &Engine) -> irlume_camera::ConnectedPair {
    let pairs = &engine
        .camera_selection
        .as_ref()
        .unwrap()
        .view()
        .ordinary
        .pairs;
    assert_eq!(pairs.len(), 1);
    pairs[0].clone()
}

/// A primary bound to the rig's ordinary unit.
fn ordinary_account() -> Option<CameraBinding> {
    Some(CameraBinding::Ordinary {
        rgb: Some(ORDINARY_UNIT.into()),
        ir: Some(ORDINARY_UNIT.into()),
    })
}

fn ordinary_binding(pair: &irlume_camera::ConnectedPair) -> Option<GroupPair> {
    Some(GroupPair::Ordinary {
        rgb: Some(pair.identity.clone()),
        ir: Some(pair.identity.clone()),
    })
}

/// Route the account's one classified ordinary choice in a top-level
/// authentication call, accepted or refused (`stale`) at its validation,
/// then offer the call a split choice classified before the route and one
/// classified after it, as a fallback would. Both must refuse and leave the
/// call on the ordinary pair with no lease.
fn the_call_keeps_its_ordinary_route(stale: bool) {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(false);
    let counts = rig.recorder.lease_counts_observer();
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        assert!(request.camera_selection.as_ref().unwrap().routes_accounts());
        // A split choice this request classified before its route.
        let (held, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        // The account's one classified choice is the ordinary pair.
        let ordinary = match route(&request, rig.primary(ordinary_account()), false).0 {
            Ok(ClassifiedChoice::Ordinary { pair, .. }) => pair,
            other => panic!("expected an ordinary choice, got {}", describe(&other)),
        };
        assert_eq!(ordinary, listed_ordinary(&request));
        // A stale generation stands for an ordinary pair that changed
        // between ranking and the install, so its validation refuses.
        let routed = if stale {
            irlume_camera::ConnectedPair {
                generation: ordinary.generation + 1,
                ..ordinary.clone()
            }
        } else {
            ordinary.clone()
        };
        let ordinary_route = reply(request.select_account_camera(routed.clone()));
        if stale {
            assert!(ordinary_route.contains(STALE), "{ordinary_route}");
        } else {
            assert_eq!(ordinary_route, "admitted");
        }
        let (fallback, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        for (name, choice) in [("held", held), ("fallback", fallback)] {
            let refused = reply(request.select_account_split_camera(*choice));
            assert!(refused.contains(NOT_ROUTABLE), "{name}: {refused}");
            assert_eq!(devices(&request), (O_RGB, O_IR, true), "{name}");
            assert_eq!(
                installed_binding(&request),
                ordinary_binding(&routed),
                "{name}"
            );
            assert_eq!(
                request
                    .prepared_camera_lease()
                    .map(|expected| expected.pair),
                Some(routed.clone()),
                "{name}"
            );
        }
        if !stale {
            request
                .validate_camera_request()
                .expect("the ordinary route stays valid");
        }
        assert_eq!(counts(), (0, 0));
    }
    // No lease request, split or ordinary, reached the camera boundary.
    assert!(rig.recorder.calls().is_empty());
    assert_eq!(counts(), (0, 0));
    assert!(!rig.lock().exists());
    if !stale {
        // The accepted ordinary route stays the standing choice.
        assert_eq!(standing.devices(), (O_RGB, O_IR, true));
    }
}

/// One call nested in an outer request routes the ordinary pair. A later
/// call in the same request, and the outer request itself, must refuse a
/// split choice and keep the ordinary route.
fn a_later_call_keeps_the_ordinary_route(outer_authentication: bool, call_authentication: bool) {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(false);
    let counts = rig.recorder.lease_counts_observer();
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        // The outer request scope a daemon holds around its calls.
        let mut outer = prepare(&mut *standing.engine, outer_authentication).unwrap();
        let ordinary = listed_ordinary(&outer);
        {
            let mut call = prepare(&mut outer, call_authentication)
                .expect("the first call nests in the automatic request");
            let pair = match route(&call, rig.primary(ordinary_account()), false).0 {
                Ok(ClassifiedChoice::Ordinary { pair, .. }) => pair,
                other => panic!("expected an ordinary choice, got {}", describe(&other)),
            };
            assert_eq!(pair, ordinary);
            call.select_account_camera(pair)
                .expect("the first call routes the ordinary pair");
        }
        {
            let mut call = prepare(&mut outer, call_authentication)
                .expect("a later call nests over the ordinary route");
            let (split, _) = expect_split(route(&call, rig.primary(split_binding()), false).0);
            let refused = reply(call.select_account_split_camera(*split));
            assert!(refused.contains(NOT_ROUTABLE), "later call: {refused}");
            assert_eq!(devices(&call), (O_RGB, O_IR, true));
            assert_eq!(installed_binding(&call), ordinary_binding(&ordinary));
            call.validate_camera_request()
                .expect("the later call keeps the ordinary route");
        }
        // The outer request itself never reroutes either.
        let (split, _) = expect_split(route(&outer, rig.primary(split_binding()), false).0);
        let refused = reply(outer.select_account_split_camera(*split));
        assert!(refused.contains(NOT_ROUTABLE), "outer: {refused}");
        assert_eq!(devices(&outer), (O_RGB, O_IR, true));
        assert_eq!(installed_binding(&outer), ordinary_binding(&ordinary));
        assert_eq!(counts(), (0, 0));
    }
    assert!(rig.recorder.calls().is_empty());
    assert_eq!(counts(), (0, 0));
    assert!(!rig.lock().exists());
    assert_eq!(standing.devices(), (O_RGB, O_IR, true));
}

// RED: before this fix a split installed after an ordinary route.

#[test]
fn a_split_never_installs_after_an_accepted_ordinary_route() {
    the_call_keeps_its_ordinary_route(false);
}

#[test]
fn a_split_never_installs_after_a_refused_ordinary_route() {
    the_call_keeps_its_ordinary_route(true);
}

#[test]
fn a_later_authentication_call_never_reroutes_an_ordinary_route_in_a_daemon_scope() {
    a_later_call_keeps_the_ordinary_route(false, true);
}

#[test]
fn a_later_authentication_call_never_reroutes_an_ordinary_route_in_an_authentication_scope() {
    a_later_call_keeps_the_ordinary_route(true, true);
}

#[test]
fn a_later_unmigrated_generic_call_never_reroutes_an_ordinary_route_in_a_daemon_scope() {
    a_later_call_keeps_the_ordinary_route(false, false);
}

#[test]
fn a_later_unmigrated_generic_call_never_reroutes_an_ordinary_route_in_an_authentication_scope() {
    a_later_call_keeps_the_ordinary_route(true, false);
}

// Mutation guard: GREEN before this fix. Only an account route counts; a
// standing ordinary pair the request merely retained still lets automatic
// routing install the account's split.

#[test]
fn a_standing_ordinary_pair_is_not_a_route_and_a_split_still_installs() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(false);
    let counts = rig.recorder.lease_counts_observer();
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    standing.engine.set_devices(O_RGB, O_IR);
    standing.engine.ir_available = true;
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let ordinary = listed_ordinary(&request);
        // The standing devices are the listed ordinary pair, retained
        // without any account route.
        assert_eq!(
            request
                .prepared_camera_lease()
                .map(|expected| expected.pair),
            Some(ordinary.clone())
        );
        assert!(request.camera_selection.as_ref().unwrap().routes_accounts());
        let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        request
            .select_account_split_camera(*split)
            .expect("a retained standing pair is not a route");
        assert_eq!(devices(&request), (S_RGB, S_IR, true));
        assert_eq!(
            installed_binding(&request),
            Some(GroupPair::Split(Rig::key()))
        );
        let operation = lease(&request, &[S_RGB, S_IR], Authentication)
            .expect("the one split Authentication lease");
        assert_eq!(counts(), (2, 0));
        drop(operation);
    }
    assert_eq!(rig.recorder.calls(), vec![split_lease(Authentication)]);
    assert_eq!(counts(), (0, 0));
    assert!(!rig.lock().exists());
    // No standing split choice: the scope restores the standing devices.
    assert_eq!(standing.devices(), (O_RGB, O_IR, true));
}
