// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! A split install that refuses before it installs still ends account
//! routing for its request (ADR-0032 case 8; plan D8 and C5). Once IR is
//! forced off or a side is external at the install, the request never
//! routes the ordinary pair or leases a standing or ordinary camera
//! afterwards, even when the refusal's cause has cleared: nothing falls
//! back from a split to an ordinary path. The same split, ranked again
//! once its cause clears, still installs; that is not a rerank. A nested
//! authentication call inside a call that routed a split refuses without
//! ending the running call's entry. The rows reuse the parent's
//! non-granting rig; none reaches a grant.

use super::*;

/// Why a split install refuses before it installs anything.
#[derive(Clone, Copy, Debug)]
enum PureRefusal {
    IrForcedOff,
    ExternalSide,
}

impl PureRefusal {
    fn shape(self) -> Shape {
        match self {
            Self::IrForcedOff => WITH_ORDINARY,
            Self::ExternalSide => Shape {
                ir_fixed: false,
                ..WITH_ORDINARY
            },
        }
    }

    fn variable(self) -> &'static str {
        match self {
            Self::IrForcedOff => "IRLUME_FORCE_NO_IR",
            Self::ExternalSide => "IRLUME_CAMERA_REQUIRE_FIXED",
        }
    }

    fn text(self) -> &'static str {
        match self {
            Self::IrForcedOff => "IR is forced off",
            Self::ExternalSide => "external side",
        }
    }
}

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

fn a_refused_split_install_ends_account_routing(refusal: PureRefusal) {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(refusal.shape());
    rig.authorize(false);
    let counts = rig.recorder.lease_counts_observer();
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        std::env::set_var(refusal.variable(), "1");
        let refused = reply(request.select_account_split_camera(*split));
        std::env::remove_var(refusal.variable());
        assert!(refused.contains(refusal.text()), "{refusal:?}: {refused}");
        assert!(installed_binding(&request).is_none(), "{refusal:?}");
        assert_eq!(
            devices(&request),
            (STANDING_RGB, STANDING_IR, false),
            "{refusal:?}"
        );
        // The fallback a consumer could try once the cause cleared: the
        // ordinary pair this request lists, then any non-split lease.
        let ordinary = listed_ordinary(&request);
        let fallback = reply(request.select_account_camera(ordinary));
        assert!(fallback.contains(CLOSED), "{refusal:?}: {fallback}");
        assert_eq!(
            devices(&request),
            (STANDING_RGB, STANDING_IR, false),
            "{refusal:?}"
        );
        assert!(installed_binding(&request).is_none(), "{refusal:?}");
        for endpoints in [[O_RGB, O_IR], [STANDING_RGB, STANDING_IR]] {
            assert!(
                lease(&request, &endpoints, Authentication).is_err(),
                "{refusal:?}: {endpoints:?}"
            );
        }
        assert_eq!(counts(), (0, 0), "{refusal:?}");
        assert!(rig.recorder.calls().is_empty(), "{refusal:?}");
        // The same split, ranked again, still installs and leases both
        // sides: a retry, not a rerank.
        let (again, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        assert_eq!(again.key(), &Rig::key());
        request.select_account_split_camera(*again).unwrap();
        assert_eq!(devices(&request), (S_RGB, S_IR, true), "{refusal:?}");
        let operation = lease(&request, &[S_RGB, S_IR], Authentication).unwrap();
        assert_eq!(counts(), (2, 0), "{refusal:?}");
        drop(operation);
    }
    assert_eq!(rig.recorder.calls(), vec![split_lease(Authentication)]);
    assert_eq!(counts(), (0, 0));
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn a_split_refused_for_forced_off_ir_never_falls_back_to_an_ordinary_route() {
    a_refused_split_install_ends_account_routing(PureRefusal::IrForcedOff);
}

#[test]
fn a_split_refused_for_an_external_side_never_falls_back_to_an_ordinary_route() {
    a_refused_split_install_ends_account_routing(PureRefusal::ExternalSide);
}

/// Inside a call that routed a split, automatic or pinned, a nested
/// authentication preparation refuses with the closed text and creates no
/// scope, so the running call keeps its entry and its own lease.
#[test]
fn a_nested_authentication_call_never_runs_inside_a_routed_split_call() {
    for pinned in [false, true] {
        let _env = env_guard();
        let mut shared = shared();
        let rig = Rig::new(SPLIT_ONLY);
        rig.authorize(pinned);
        let counts = rig.recorder.lease_counts_observer();
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        let standing = Standing::new(&mut shared.engine);
        {
            let mut call = standing
                .engine
                .prepare_authentication_camera_request()
                .unwrap();
            assert_eq!(
                call.camera_selection.as_ref().unwrap().pending_pin(),
                pinned.then(Rig::key).as_ref(),
                "pinned={pinned}"
            );
            let (split, _) = expect_split(route(&call, rig.primary(split_binding()), false).0);
            call.select_account_split_camera(*split).unwrap();
            let nested = reply(call.prepare_authentication_camera_request());
            assert!(nested.contains(CLOSED), "pinned={pinned}: {nested}");
            call.validate_camera_request()
                .expect("the running call keeps its entry");
            let operation = lease(&call, &[S_RGB, S_IR], Authentication)
                .expect("the running call keeps its own lease");
            assert_eq!(counts(), (2, 0), "pinned={pinned}");
            drop(operation);
        }
        assert_eq!(
            rig.recorder.calls(),
            vec![split_lease(Authentication)],
            "pinned={pinned}"
        );
        assert_eq!(counts(), (0, 0), "pinned={pinned}");
    }
}
