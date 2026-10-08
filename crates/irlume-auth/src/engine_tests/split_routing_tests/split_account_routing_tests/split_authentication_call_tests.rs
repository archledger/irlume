// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The Authentication entry belongs to the one authentication call that
//! routes a pending pin (ADR-0032 cases 8, 10, 12 and 15; plan D3, D8, C5
//! and C7). Under a pending pin or a routed split every nested or ordinary
//! entry refuses with the closed text before any preflight, storage or
//! lease, and the entry ends with that call. A routed or refused split
//! never yields to an ordinary pair, a second route or a re-entry. A proven
//! ordinary override keeps precedence, and only an automatic or pinned
//! request routes a split. The rows reuse the parent's non-granting rig;
//! none reaches a grant.

use super::*;
use irlume_core::multi_camera::authz::{
    AuthorizationVia, EnrollmentAuthorization, EnrollmentOperation,
};

const OVERRIDE_UNPROVEN: &str = "ordinary camera override is not a unique Current ordinary pair";
const NOT_ROUTABLE: &str = "split account routing needs an unrouted automatic or pinned request";

/// A framing observer that finishes at once; no row reaches its camera.
struct Finish;

impl PositionObserver for Finish {
    fn next(&self) -> irlume_common::Result<Option<irlume_common::PositionSessionControl>> {
        Ok(Some(irlume_common::PositionSessionControl::Finish))
    }
    fn report(&self, _: irlume_common::PositionReport) -> irlume_common::Result<()> {
        Ok(())
    }
}

/// The error text of a refused entry, or a marker when it was admitted.
fn reply<T>(result: irlume_common::Result<T>) -> String {
    match result {
        Ok(_) => "admitted".into(),
        Err(error) => error.to_string(),
    }
}

/// Point the ordinary override at `rgb` and `ir`; the rig restores both.
fn set_override(rgb: &str, ir: &str) {
    std::env::set_var("IRLUME_RGB_DEVICE", rgb);
    std::env::set_var("IRLUME_IR_DEVICE", ir);
}

fn clear_override() {
    std::env::remove_var("IRLUME_RGB_DEVICE");
    std::env::remove_var("IRLUME_IR_DEVICE");
}

fn devices(engine: &Engine) -> (&str, &str, bool) {
    (
        engine.rgb_dev.as_str(),
        engine.ir_dev.as_str(),
        engine.ir_available,
    )
}

/// The operation-scoped enrollment choice of the rig's ordinary unit.
fn ordinary_enrollment_choice() -> irlume_common::live_camera::EnrollmentCameraChoice {
    let inventory = irlume_camera::camera_inventory_snapshot();
    let candidate = inventory
        .candidates
        .iter()
        .find(|candidate| candidate.endpoint_paths.iter().any(|path| path == O_RGB))
        .expect("the rig lists its ordinary unit")
        .clone();
    irlume_common::live_camera::EnrollmentCameraChoice {
        rgb: O_RGB.into(),
        ir: O_IR.into(),
        expected: irlume_common::live_camera::CameraSelection {
            supervisor_id: inventory
                .supervisor_id
                .expect("an installed fixture supervisor"),
            candidate,
        },
    }
}

// RED: the entry belongs to the authentication call alone.

#[test]
fn a_pending_pin_closes_every_nested_and_ordinary_entry_before_any_lease() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(true);
    rig.primary(split_binding());
    let path = rig.dir.join(format!("{USER}.json"));
    let before = std::fs::read(&path).unwrap();
    let authorization = EnrollmentAuthorization::mint(
        USER.into(),
        EnrollmentOperation::add_group("split-desk".into(), &GroupPair::Split(Rig::key())),
        1_000_000,
        900,
        USER.into(),
        AuthorizationVia::ElevatedPeer { uid: 0 },
    )
    .unwrap();
    // Both trust kinds are admitted; only the authentication call may route.
    let _admitted = rig
        .recorder
        .admit_split_trust(&[Authentication, Enrollment]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        assert_eq!(
            request.camera_selection.as_ref().unwrap().pending_pin(),
            Some(&Rig::key())
        );
        let preflight = &Cell::new(0);
        let probe = || {
            move |_: &mut irlume_vision::Detector| {
                preflight.set(preflight.get() + 1);
                true
            }
        };
        let entries = vec![
            (
                "nested preparation",
                reply(request.prepare_camera_request()),
            ),
            ("assess", reply(request.assess())),
            ("support probe", reply(request.support_probe(&()))),
            (
                "position session",
                reply(request.position_session(Some(USER), &Finish)),
            ),
            (
                "position sample",
                reply(request.position_sample(Some(USER))),
            ),
            ("liveness self-test", reply(request.liveness_selftest())),
            ("identify", reply(request.identify_with_diagnostics(&()))),
            (
                "identify within",
                reply(request.identify_within_with_diagnostics(USER, &())),
            ),
            (
                "enroll",
                reply(request.enroll_profile_with_ir_preflight(USER, None, 1, probe())),
            ),
            (
                "reset enrollment",
                reply(
                    request.replace_enrollment_with_ir_preflight_and_diagnostics(
                        USER,
                        None,
                        1,
                        probe(),
                        &(),
                    ),
                ),
            ),
            (
                "add scan",
                reply(request.add_scan_observed(USER, "fixture", 1, probe(), &())),
            ),
            (
                "add camera group",
                reply(request.add_camera_group_observed(
                    USER,
                    None,
                    1,
                    &authorization,
                    probe(),
                    &(),
                    &(),
                )),
            ),
        ];
        let open: Vec<_> = entries
            .iter()
            .filter(|(_, reply)| !reply.contains(CLOSED))
            .collect();
        assert!(open.is_empty(), "entries past a pending pin: {open:?}");
        assert_eq!(preflight.get(), 0, "an IR preflight ran under the pin");
        assert!(
            rig.recorder.calls().is_empty(),
            "a lease was attempted under the pin: {:?}",
            rig.recorder.calls()
        );
        assert!(request.capture_qualification_for_request().is_err());
        assert!(request.with_prepared_camera_publication(|| Ok(())).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let secondary = secondary_store_path(USER);
        assert!(!secondary.exists());
        assert!(!irlume_core::multi_camera::commit::intent_path_for(&secondary).exists());
        assert!(!rig.dir.join("capture-qualifications").exists());
        assert!(!request.request_key().holds_key());
        assert!(request.primary_attempt.is_none() && request.secondary_attempt.is_none());
        // The pin itself still waits for its authentication call.
        let selection = request.camera_selection.as_ref().unwrap();
        assert_eq!(selection.pending_pin(), Some(&Rig::key()));
        assert_eq!(
            devices(&request),
            (STANDING_RGB, STANDING_IR, false),
            "nothing moved the request onto another pair"
        );
    }
    assert!(standing.engine.camera_selection.is_none());
    assert!(rig.recorder.calls().is_empty());
}

#[test]
fn a_routed_split_keeps_nested_and_ordinary_entries_closed_inside_the_call() {
    let _env = env_guard();
    let mut shared = shared();
    for pinned in [false, true] {
        let rig = Rig::new(WITH_ORDINARY);
        rig.authorize(pinned);
        let counts = rig.recorder.lease_counts_observer();
        let _admitted = rig
            .recorder
            .admit_split_trust(&[Authentication, Enrollment]);
        let standing = Standing::new(&mut shared.engine);
        {
            // The authentication call with no outer scope: its own
            // preparation is the request.
            let mut call = standing
                .engine
                .prepare_authentication_camera_request()
                .unwrap();
            let (split, _) = expect_split(route(&call, rig.primary(split_binding()), false).0);
            call.select_account_split_camera(*split).unwrap();
            let entries = [
                ("nested preparation", reply(call.prepare_camera_request())),
                ("assess", reply(call.assess())),
                ("support probe", reply(call.support_probe(&()))),
                (
                    "position session",
                    reply(call.position_session(Some(USER), &Finish)),
                ),
                ("position sample", reply(call.position_sample(Some(USER)))),
                ("identify", reply(call.identify_with_diagnostics(&()))),
            ];
            let open: Vec<_> = entries
                .iter()
                .filter(|(_, reply)| !reply.contains(CLOSED))
                .collect();
            assert!(
                open.is_empty(),
                "pinned={pinned}: entries inside a routed split: {open:?}"
            );
            assert!(rig.recorder.calls().is_empty(), "pinned={pinned}");
            // The call's own split Authentication lease is unaffected.
            assert_eq!(devices(&call), (S_RGB, S_IR, true));
            let operation = lease(&call, &[S_RGB, S_IR], Authentication)
                .expect("the call keeps its one split Authentication lease");
            assert_eq!(counts(), (2, 0));
            assert!(call.pre_open_account_refusal().is_none());
            drop(operation);
        }
        assert_eq!(
            rig.recorder.calls(),
            vec![split_lease(Authentication)],
            "pinned={pinned}"
        );
        assert_eq!(counts(), (0, 0));
        assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
    }
}

#[test]
fn the_authentication_entry_ends_with_the_nested_call_that_routes_the_pin() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(true);
    let counts = rig.recorder.lease_counts_observer();
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        // The outer request scope a daemon holds around one authentication.
        let mut outer = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        {
            let mut call = outer
                .prepare_authentication_camera_request()
                .expect("the authentication call nests over the outer pin");
            call.validate_camera_request()
                .expect("the call validates its pending pin");
            let (split, _) = expect_split(route(&call, rig.primary(split_binding()), false).0);
            call.select_account_split_camera(*split).unwrap();
            let operation = lease(&call, &[S_RGB, S_IR], Authentication).unwrap();
            assert_eq!(counts(), (2, 0));
            assert!(call.pre_open_account_refusal().is_none());
            drop(operation);
        }
        // The call is over, and its entry ended with it.
        assert!(closed(outer.validate_camera_request()));
        assert_eq!(
            lease(&outer, &[S_RGB, S_IR], Authentication).err(),
            Some(CameraLeaseError::SplitActivationDisabled)
        );
        assert!(outer.split_grant_authority_refusal().is_some());
        assert!(outer.pre_open_account_refusal().is_some());
        assert!(reply(outer.prepare_authentication_camera_request()).contains(CLOSED));
        assert!(reply(outer.prepare_camera_request()).contains(CLOSED));
        assert!(closed(
            outer.enter_split_trust(SplitTrustEntry::Authentication)
        ));
    }
    {
        // A call that routes nothing still ends the entry it held.
        let mut outer = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        {
            let call = outer.prepare_authentication_camera_request().unwrap();
            call.validate_camera_request().unwrap();
        }
        assert!(closed(outer.validate_camera_request()));
        assert!(reply(outer.prepare_authentication_camera_request()).contains(CLOSED));
        let (split, _) = expect_split(route(&outer, rig.primary(split_binding()), false).0);
        assert!(closed(outer.select_account_split_camera(*split)));
        assert!(installed_binding(&outer).is_none());
    }
    assert_eq!(rig.recorder.calls(), vec![split_lease(Authentication)]);
    assert_eq!(counts(), (0, 0));
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn an_authentication_call_never_nests_in_a_split_enrollment_scope() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let (guard, publication) = rig.displayed();
    let _admitted = rig
        .recorder
        .admit_split_trust(&[Authentication, Enrollment]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        assert!(reply(request.prepare_authentication_camera_request()).contains(CLOSED));
        request
            .enter_split_trust(SplitTrustEntry::Enrollment)
            .unwrap();
        // The declared Enrollment entry admits its own nested preparation,
        // never an authentication call.
        assert!(reply(request.prepare_authentication_camera_request()).contains(CLOSED));
        request
            .prepare_camera_request()
            .expect("the Enrollment entry keeps its nested preparation");
        request.leave_split_trust();
    }
    assert!(rig.recorder.calls().is_empty());
}

#[test]
fn a_routed_split_never_yields_to_an_ordinary_pair_or_a_reentry() {
    let _env = env_guard();
    let mut shared = shared();
    for pinned in [false, true] {
        let rig = Rig::new(WITH_ORDINARY);
        rig.authorize(pinned);
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        let standing = Standing::new(&mut shared.engine);
        {
            let mut request = standing
                .engine
                .prepare_authentication_camera_request()
                .unwrap();
            let ordinary = request
                .camera_selection
                .as_ref()
                .unwrap()
                .view()
                .ordinary
                .pairs[0]
                .clone();
            let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
            let (again, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
            request.select_account_split_camera(*split).unwrap();
            // Plan D8: an installed split has no ordinary fallback.
            assert!(
                closed(request.select_account_camera(ordinary)),
                "pinned={pinned}"
            );
            assert_eq!(devices(&request), (S_RGB, S_IR, true));
            assert_eq!(
                installed_binding(&request),
                Some(GroupPair::Split(Rig::key()))
            );
            assert!(request.prepared_camera_lease().is_none());
            assert!(lease(&request, &[O_RGB, O_IR], Authentication).is_err());
            assert!(request.select_account_split_camera(*again).is_err());
            // Only account routing declares the entry, once: no re-entry.
            request.leave_split_trust();
            assert!(closed(
                request.enter_split_trust(SplitTrustEntry::Authentication)
            ));
            assert!(closed(request.validate_camera_request()));
        }
        assert!(rig.recorder.calls().is_empty(), "pinned={pinned}");
        assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
    }
}

#[test]
fn a_refused_split_install_stays_closed_to_ordinary_rerouting_and_reentry() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let ordinary = request
            .camera_selection
            .as_ref()
            .unwrap()
            .view()
            .ordinary
            .pairs[0]
            .clone();
        let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        let (again, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        // The machine authority is revoked between routing and the install,
        // so the install's own validation refuses it.
        rig.revoke();
        let refused = request
            .select_account_split_camera(*split)
            .expect_err("a revoked split never installs");
        assert!(
            refused.to_string().contains("split authorization"),
            "{refused}"
        );
        // Nothing reranks after the refusal: no ordinary pair, no second
        // route and no re-entry.
        assert!(closed(request.select_account_camera(ordinary)));
        assert!(request.select_account_split_camera(*again).is_err());
        assert!(closed(
            request.enter_split_trust(SplitTrustEntry::Authentication)
        ));
        assert!(closed(request.validate_camera_request()));
        for endpoints in [[S_RGB, S_IR], [O_RGB, O_IR]] {
            assert!(
                lease(&request, &endpoints, Authentication).is_err(),
                "{endpoints:?}"
            );
        }
        assert!(request.prepared_camera_lease().is_none());
        assert!(!rig.lock().exists());
    }
    assert!(rig.recorder.calls().is_empty());
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn classified_routing_keeps_split_closed_for_an_override_or_enrollment_choice() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    for enrollment_choice in [false, true] {
        let request = if enrollment_choice {
            clear_override();
            standing
                .engine
                .prepare_enrollment_camera(&ordinary_enrollment_choice())
                .unwrap()
        } else {
            set_override(O_RGB, O_IR);
            standing
                .engine
                .prepare_authentication_camera_request()
                .unwrap()
        };
        assert!(!request.camera_selection.as_ref().unwrap().routes_accounts());
        // A split primary refuses before any secondary load (plan D1, D8).
        // An override or enrollment choice is an ordinary entry meeting that
        // credential, so it refuses for the ordinary path's own reason.
        let intent = plant_pending_intent();
        let (choice, unseals) = route(&request, rig.primary(split_binding()), false);
        let denied = expect_denied(choice);
        assert_eq!(denied.reason, ORDINARY, "enrollment={enrollment_choice}");
        assert_eq!(unseals, 0);
        assert!(intent.exists() && !secondary_store_path(USER).exists());
        std::fs::remove_file(&intent).unwrap();
        // A ranked split secondary is also refused by the ordinary-only
        // context, despite Authentication being admitted above.
        let primary = rig.primary(absent_binding());
        rig.secondary(&primary, &[("split-desk", GroupPair::Split(Rig::key()))]);
        assert_eq!(
            expect_denied(route(&request, primary, false).0).reason,
            ORDINARY
        );
        std::fs::remove_file(secondary_store_path(USER)).unwrap();
        // Ordinary routing is unchanged.
        match route(
            &request,
            rig.primary(Some(CameraBinding::Ordinary {
                rgb: Some(ORDINARY_UNIT.into()),
                ir: Some(ORDINARY_UNIT.into()),
            })),
            false,
        )
        .0
        {
            Ok(ClassifiedChoice::Ordinary { pair, .. }) => assert_eq!(pair.rgb, O_RGB),
            other => panic!("expected the ordinary primary, got {}", describe(&other)),
        }
    }
    clear_override();
    assert!(rig.recorder.calls().is_empty());
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn a_pin_beside_an_ordinary_pin_line_routes_without_reading_as_automatic() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    std::fs::write(
        rig.dir.join("cameras.conf"),
        format!("rgb={O_RGB}\nir={O_IR}\n"),
    )
    .unwrap();
    rig.authorize(true);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let selection = request.camera_selection.as_ref().unwrap();
        assert_eq!(selection.pending_pin(), Some(&Rig::key()));
        // With ordinary rgb=/ir= lines beside the pin, automatic() is false;
        // with split keys only it is true. Only classified routing, through
        // routes_accounts(), sees the pin in either shape.
        assert!(!selection.automatic());
        assert!(selection.routes_accounts());
        assert!(request.may_select_account_camera());
        let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        request.select_account_split_camera(*split).unwrap();
        let operation = lease(&request, &[S_RGB, S_IR], Authentication).unwrap();
        drop(operation);
    }
    assert_eq!(rig.recorder.calls(), vec![split_lease(Authentication)]);
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

// Mutation guards: GREEN before this fix; they pin D8 precedence and the
// install's own routing requirement.

#[test]
fn a_proven_ordinary_override_keeps_precedence_over_a_pinned_split() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(true);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    set_override(O_RGB, O_IR);
    for authentication in [true, false] {
        let request = if authentication {
            standing.engine.prepare_authentication_camera_request()
        } else {
            standing.engine.prepare_camera_request()
        }
        .expect("a proven ordinary override prepares");
        let selection = request.camera_selection.as_ref().unwrap();
        assert!(
            selection.pending_pin().is_none(),
            "authentication={authentication}: the override keeps precedence"
        );
        assert!(!selection.automatic() && !selection.routes_accounts());
        assert_eq!(installed_binding(&request), Some(ordinary_group()));
        let expected = request
            .prepared_camera_lease()
            .expect("the proven ordinary pair");
        assert_eq!(
            (expected.pair.rgb.as_str(), expected.pair.ir.as_str()),
            (O_RGB, O_IR)
        );
        assert_eq!(
            (request.rgb_dev.as_str(), request.ir_dev.as_str()),
            (O_RGB, O_IR)
        );
        assert!(!request.may_select_account_camera());
        request.validate_camera_request().unwrap();
    }
    // An override naming the split paths is not a proven ordinary pair.
    set_override(S_RGB, S_IR);
    for authentication in [true, false] {
        let refused = if authentication {
            reply(standing.engine.prepare_authentication_camera_request())
        } else {
            reply(standing.engine.prepare_camera_request())
        };
        assert!(
            refused.contains(OVERRIDE_UNPROVEN),
            "authentication={authentication}: {refused}"
        );
        assert!(standing.engine.camera_selection.is_none());
    }
    clear_override();
    assert!(rig.recorder.calls().is_empty());
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn a_split_choice_never_installs_into_an_override_or_enrollment_choice_request() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    for enrollment_choice in [false, true] {
        if enrollment_choice {
            clear_override();
        } else {
            set_override(O_RGB, O_IR);
            // An engine started under the override runs on that pair.
            standing.engine.set_devices(O_RGB, O_IR);
        }
        let outside = (
            standing.engine.rgb_dev.clone(),
            standing.engine.ir_dev.clone(),
            standing.engine.ir_available,
        );
        {
            let mut request = if enrollment_choice {
                standing
                    .engine
                    .prepare_enrollment_camera(&ordinary_enrollment_choice())
                    .unwrap()
            } else {
                standing
                    .engine
                    .prepare_authentication_camera_request()
                    .unwrap()
            };
            // The retained view still lists the split pair, so a choice for
            // it builds; the install alone must refuse it.
            let choice = request
                .camera_selection
                .as_ref()
                .unwrap()
                .split_choice(0)
                .expect("the retained view lists the authorized split pair");
            assert_eq!(choice.key(), &Rig::key());
            let before = (
                request.rgb_dev.clone(),
                request.ir_dev.clone(),
                request.ir_available,
            );
            let refused = reply(request.select_account_split_camera(choice));
            assert!(
                refused.contains(NOT_ROUTABLE),
                "enrollment={enrollment_choice}: {refused}"
            );
            assert_eq!(
                (
                    request.rgb_dev.clone(),
                    request.ir_dev.clone(),
                    request.ir_available
                ),
                before
            );
            assert_eq!(
                (before.0.as_str(), before.1.as_str()),
                (O_RGB, O_IR),
                "enrollment={enrollment_choice}"
            );
            assert_eq!(installed_binding(&request), Some(ordinary_group()));
            assert!(request.prepared_camera_lease().is_some());
        }
        assert_eq!(
            (
                standing.engine.rgb_dev.clone(),
                standing.engine.ir_dev.clone(),
                standing.engine.ir_available,
            ),
            outside
        );
    }
    clear_override();
    assert!(rig.recorder.calls().is_empty());
}
