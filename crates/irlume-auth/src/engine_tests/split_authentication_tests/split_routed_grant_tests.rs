// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The routed split's account scope and boundaries through the real
//! authentication call (plan W2a-2, C6 and D10; ADR-0032 cases 10 and 15).
//! Classified routing records the attempt's primary or secondary account
//! scope with the installed split before camera admission. Account drift
//! after routing refuses at the pre-open account boundary under the held
//! split lease, before either side opens; an authority change at admission
//! refuses before the lease. A secondary-scoped split decides
//! its grant against the matching enrollment's group binding, at the same
//! split grant boundary as a primary. The rows reuse the parent's
//! non-granting rig; no camera attempt reaches a grant.

use super::*;

const ACQUIRE: &str = "self.acquire_account_camera(";
const OPEN_RGB: &str = "camera_operation.open_rgb";
const PRE_OPEN: &str = "self.pre_open_account_refusal()";
const DISPATCH: &str = "self.installed_split_key().is_some()";
const ROUTED: &str = "self.authenticate_split_routed(";
const PRE_OPEN_FIRST: &str = "the pre-open account refusal precedes the split dispatch";

/// Plant the account of one routed shape: a primary bound to the split, or
/// a primary bound to an absent unit whose one secondary group is the split.
fn plant(rig: &Rig, engine: &Engine, secondary: bool) -> PrimarySnapshot {
    if secondary {
        let primary = rig.primary(engine, Some(absent_binding()));
        rig.secondary(&primary);
        primary
    } else {
        rig.primary(engine, Some(split_binding()))
    }
}

/// Prepare the authentication call, route the account's split secondary and
/// install it exactly as the authentication call does: the choice, its
/// Authentication entry and the secondary account scope of the attempt.
fn install_secondary<'a>(
    engine: &'a mut Engine,
    rig: &Rig,
) -> (CameraRequestScope<'a>, Enrollment) {
    let mut call = engine.prepare_authentication_camera_request().unwrap();
    let primary = plant(rig, &call, true);
    let (enrollment, split, scope) = match route(&call, primary) {
        Ok(ClassifiedChoice::Split {
            enrollment,
            split,
            scope,
        }) => (enrollment, split, scope),
        Ok(_) => panic!("expected the split choice, got another class"),
        Err(outcome) => panic!("expected the split choice, got {}", outcome.reason),
    };
    let IrOnlyScope::Secondary(context) = scope else {
        panic!("expected the secondary account scope");
    };
    call.select_account_split_camera(*split).unwrap();
    call.secondary_attempt = Some(*context);
    (call, enrollment)
}

/// The authentication call with camera admission, as the daemon runs it:
/// `admit` sees the routed request after routing and before the lease.
fn authenticate_admitting(
    engine: &mut Engine,
    admit: &mut dyn FnMut(&Engine) -> irlume_common::Result<()>,
) -> irlume_common::Result<Outcome> {
    engine.authenticate_for_in_window_with_policy_preparing_delivering(
        USER,
        Some("login"),
        AuthenticationPurpose::Verify,
        AuthenticationWindow::new(2000),
        irlume_common::config::FaceSensorPolicy::Dual,
        &(),
        &mut |engine, _| admit(engine),
        &mut |_, _| panic!("the non-granting fixture cannot deliver a grant"),
    )
}

/// What camera admission sees of the routed request.
#[derive(Debug)]
struct Routed {
    calls: Vec<Call>,
    key: Option<SplitPairKey>,
    scope: (bool, bool),
    devices: (String, String, bool),
    granting: Option<Outcome>,
    unmarked: Option<Outcome>,
    elsewhere: Option<Outcome>,
}

impl Routed {
    /// The routed state, and the split grant boundary as the routed request
    /// would apply it: to an enrollment bound to the split with granting
    /// split evidence, to the same with unmarked evidence, and to an
    /// enrollment bound elsewhere.
    fn observe(engine: &Engine, calls: Vec<Call>) -> Self {
        let bound = compatible_enrollment(engine, Some(split_binding()));
        let elsewhere = compatible_enrollment(engine, Some(absent_binding()));
        Self {
            calls,
            key: engine.installed_split_key(),
            scope: (
                engine.primary_attempt.is_some(),
                engine.secondary_attempt.is_some(),
            ),
            devices: (
                engine.rgb_dev.clone(),
                engine.ir_dev.clone(),
                engine.ir_available,
            ),
            granting: engine.split_grant_refusal(&bound, &granting()),
            unmarked: engine.split_grant_refusal(&bound, &assessment(0.9, 0.4, false)),
            elsewhere: engine.split_grant_refusal(&elsewhere, &granting()),
        }
    }
}

/// Where the split dispatch sits in the authentication call's source: after
/// the one account camera acquisition and the pre-open account refusal,
/// before the first RGB open, and running the routed split arm.
fn split_dispatch_order(call: &str) -> Result<(), &'static str> {
    let acquire = call
        .find(ACQUIRE)
        .ok_or("the call acquires its camera operation")?;
    let open = call
        .find(OPEN_RGB)
        .ok_or("the call opens its leased RGB side")?;
    let dispatch = call[acquire..]
        .find(DISPATCH)
        .map(|offset| acquire + offset)
        .ok_or("the split dispatch follows the acquisition")?;
    if dispatch > open {
        return Err("the split dispatch precedes the first RGB open");
    }
    if !call[acquire..dispatch].contains(PRE_OPEN) {
        return Err(PRE_OPEN_FIRST);
    }
    if !call[dispatch..open].contains(ROUTED) {
        return Err("the split dispatch runs the routed split arm");
    }
    Ok(())
}

// Review mutant R10: the routed split records the attempt's account scope.

#[test]
fn routing_records_the_split_account_scope_before_camera_admission() {
    let _env = env_guard();
    let mut shared = shared();
    for pinned in [false, true] {
        for secondary in [false, true] {
            let case = format!("pinned={pinned} secondary={secondary}");
            let rig = Rig::new(false);
            rig.authorize(pinned);
            let counts = rig.recorder.lease_counts_observer();
            let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
            let standing = Standing::new(&mut shared.engine);
            let primary = plant(&rig, standing.engine, secondary);
            let mut seen = None;
            let result = authenticate_admitting(standing.engine, &mut |engine| {
                seen = Some(Routed::observe(engine, rig.recorder.calls()));
                Ok(())
            });
            let seen = seen.unwrap_or_else(|| {
                panic!("{case}: camera admission never ran ({})", reply(&result))
            });
            assert!(
                seen.calls.is_empty(),
                "{case}: admission precedes the lease: {:?}",
                seen.calls
            );
            assert_eq!(seen.key, Some(key()), "{case}: the routed split");
            assert_eq!(
                seen.scope,
                (!secondary, secondary),
                "{case}: the attempt's account scope is recorded with the routed split"
            );
            assert_eq!(
                seen.devices,
                (S_RGB.to_string(), S_IR.to_string(), true),
                "{case}: both original sides with IR"
            );
            assert!(
                seen.granting.is_none(),
                "{case}: the routed request passes its split grant boundary: {:?}",
                seen.granting
            );
            let unmarked = seen
                .unmarked
                .as_ref()
                .unwrap_or_else(|| panic!("{case}: unmarked evidence passed the boundary"));
            assert_refused(
                unmarked,
                EVIDENCE,
                OutcomeCause::SetupUnavailable,
                &format!("{case} unmarked"),
            );
            let elsewhere = seen
                .elsewhere
                .as_ref()
                .unwrap_or_else(|| panic!("{case}: another binding passed the boundary"));
            assert_refused(
                elsewhere,
                BINDING,
                OutcomeCause::NotEnrolledOnThisCamera,
                &format!("{case} elsewhere"),
            );
            // The admitted call then runs the routed split arm as before.
            assert_eq!(
                rig.recorder.calls(),
                vec![split_lease(), Call::OpenRgb(S_RGB.into())],
                "{case}: {}",
                reply(&result)
            );
            assert!(!granted(&result), "{case}: {}", reply(&result));
            assert_eq!(counts(), (0, 0), "{case}: both reservations released");
            assert!(standing.engine.camera_selection.is_none(), "{case}");
            assert_eq!(
                standing.devices(),
                (STANDING_RGB, STANDING_IR, false),
                "{case}"
            );
            assert_eq!(
                std::fs::read(rig.primary_path()).unwrap(),
                primary.bytes,
                "{case}"
            );
            assert!(!rig.lock().exists(), "{case}: no cameras.conf lock file");
        }
    }
}

// Review mutant R1: the pre-open account refusal runs before the split arm.

#[test]
fn account_drift_after_routing_refuses_under_the_split_lease_before_any_open() {
    let _env = env_guard();
    let mut shared = shared();
    for pinned in [false, true] {
        for secondary in [false, true] {
            let case = format!("pinned={pinned} secondary={secondary}");
            let rig = Rig::new(false);
            rig.authorize(pinned);
            let counts = rig.recorder.lease_counts_observer();
            let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
            let standing = Standing::new(&mut shared.engine);
            let primary = plant(&rig, standing.engine, secondary);
            let mut drifted = primary.bytes.clone();
            drifted.push(b'\n');
            let mut seen = None;
            // The account store changes after routing and camera admission,
            // while the call waits for its lease. Only the pre-open account
            // boundary, under the held split lease, can still see it.
            let result = authenticate_admitting(standing.engine, &mut |engine| {
                seen = Some((rig.recorder.calls(), engine.installed_split_key()));
                std::fs::write(rig.primary_path(), &drifted).unwrap();
                Ok(())
            });
            assert_eq!(
                seen,
                Some((Vec::new(), Some(key()))),
                "{case}: camera admission sees the routed split before any lease"
            );
            assert_eq!(
                rig.recorder.calls(),
                vec![split_lease()],
                "{case}: the account boundary refuses under the one split lease, before \
                 either side opens ({})",
                reply(&result)
            );
            let boundary = if secondary {
                "secondary camera preparation"
            } else {
                "enrollment changed during authentication"
            };
            assert!(
                !granted(&result) && reply(&result).contains(boundary),
                "{case}: {}",
                reply(&result)
            );
            assert_eq!(counts(), (0, 0), "{case}: both reservations released");
            assert!(standing.engine.camera_selection.is_none(), "{case}");
            assert_eq!(
                standing.devices(),
                (STANDING_RGB, STANDING_IR, false),
                "{case}"
            );
            assert_eq!(
                std::fs::read(rig.primary_path()).unwrap(),
                drifted,
                "{case}: the refused call rewrites nothing"
            );
            assert!(!rig.lock().exists(), "{case}: no cameras.conf lock file");
        }
    }
}

#[test]
fn an_authority_change_at_admission_refuses_before_the_split_lease() {
    let _env = env_guard();
    let mut shared = shared();
    for pinned in [false, true] {
        for secondary in [false, true] {
            for change in ["revoked", "reselected"] {
                let case = format!("pinned={pinned} secondary={secondary} {change}");
                let rig = Rig::new(false);
                rig.authorize(pinned);
                let counts = rig.recorder.lease_counts_observer();
                let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
                let standing = Standing::new(&mut shared.engine);
                let primary = plant(&rig, standing.engine, secondary);
                let mut seen = None;
                // The administrator changes the split authorization after
                // routing, at camera admission: the window never widens.
                let result = authenticate_admitting(standing.engine, &mut |engine| {
                    seen = Some(engine.installed_split_key());
                    if change == "revoked" {
                        rig.revoke();
                    } else {
                        rig.authorize(!pinned);
                    }
                    Ok(())
                });
                assert_eq!(seen, Some(Some(key())), "{case}: the routed split");
                assert!(
                    rig.recorder.calls().is_empty(),
                    "{case}: refused before any lease: {:?} ({})",
                    rig.recorder.calls(),
                    reply(&result)
                );
                assert!(!granted(&result), "{case}: {}", reply(&result));
                assert_eq!(counts(), (0, 0), "{case}");
                assert!(standing.engine.camera_selection.is_none(), "{case}");
                assert_eq!(
                    standing.devices(),
                    (STANDING_RGB, STANDING_IR, false),
                    "{case}"
                );
                assert_eq!(
                    std::fs::read(rig.primary_path()).unwrap(),
                    primary.bytes,
                    "{case}"
                );
                assert!(!rig.lock().exists(), "{case}: no cameras.conf lock file");
            }
        }
    }
}

#[test]
fn the_pre_open_refusal_precedes_the_split_dispatch_in_the_authentication_call() {
    // The same span the no-probe pin reads: the authentication call up to
    // its attempt loop.
    let lib = include_str!("../../lib.rs");
    let start = lib
        .find("    pub fn authenticate_for(")
        .expect("the authentication call exists");
    let end = lib[start..]
        .find("    fn authentication_attempt_loop<")
        .map(|offset| start + offset)
        .expect("its attempt loop follows the authentication call");
    let call = &lib[start..end];
    assert_eq!(split_dispatch_order(call), Ok(()));
    // Mutation control: the split dispatch moved above the pre-open refusal,
    // directly after the acquisition, fails the pin.
    let acquired = call.find(ACQUIRE).unwrap() + ACQUIRE.len();
    let dispatch = acquired + call[acquired..].find(DISPATCH).unwrap();
    let moved = format!(
        "{}{DISPATCH}{}{}",
        &call[..acquired],
        &call[acquired..dispatch],
        &call[dispatch + DISPATCH.len()..]
    );
    assert_eq!(split_dispatch_order(&moved), Err(PRE_OPEN_FIRST));
}

// Review mutant R2: a secondary-scoped split reaches its grant boundary.

#[test]
fn a_secondary_scoped_split_grants_only_through_the_ir_identity_arms() {
    let _env = env_guard();
    let mut shared = shared();
    for pinned in [false, true] {
        let rig = Rig::new(false);
        rig.authorize(pinned);
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        let standing = Standing::new(&mut shared.engine);
        {
            let (mut call, enrollment) = install_secondary(standing.engine, &rig);
            assert_eq!(call.installed_split_key(), Some(key()), "pinned={pinned}");
            assert!(
                call.primary_attempt.is_none() && call.secondary_attempt.is_some(),
                "pinned={pinned}: only the secondary account scope"
            );
            assert!(
                matches!(
                    &enrollment.camera_binding,
                    Some(CameraBinding::Split(bound)) if *bound == key()
                ),
                "pinned={pinned}: the matching enrollment carries the group's split pair: {:?}",
                enrollment.camera_binding
            );
            for purpose in [
                AuthenticationPurpose::Verify,
                AuthenticationPurpose::AppConsent,
                AuthenticationPurpose::CredentialRelease,
            ] {
                // 0.9 clears the RGB-primary bar; 0.5 misses it, where the
                // ordinary fusion arm would grant with the 0.4 IR score.
                for rgb in [0.9, 0.5] {
                    let case = format!("pinned={pinned} {purpose:?} rgb={rgb}");
                    let out =
                        decide_for(&mut call, &enrollment, purpose, assessment(rgb, 0.4, true));
                    assert!(
                        !out.granted,
                        "{case}: RGB-primary or fusion granted: {out:?}"
                    );
                    assert_eq!(out.kind, OutcomeKind::BelowThreshold, "{case}: {out:?}");
                    assert!(out.live, "{case}: an identity refusal, not failed PAD");
                    let out =
                        decide_for(&mut call, &enrollment, purpose, assessment(rgb, 0.8, true));
                    assert!(
                        out.granted,
                        "{case}: a qualifying IR identity grants: {out:?}"
                    );
                    assert!(out.reason.contains("ir-fallback"), "{case}: {}", out.reason);
                    for ir in [0.4, 0.8] {
                        let out =
                            decide_for(&mut call, &enrollment, purpose, assessment(rgb, ir, false));
                        assert_refused(
                            &out,
                            EVIDENCE,
                            OutcomeCause::SetupUnavailable,
                            &format!("{case} ir={ir}"),
                        );
                    }
                }
            }
        }
        assert!(rig.recorder.calls().is_empty(), "pinned={pinned}");
        assert!(!rig.lock().exists(), "pinned={pinned}");
        assert_eq!(
            standing.devices(),
            (STANDING_RGB, STANDING_IR, false),
            "pinned={pinned}"
        );
    }
}

#[test]
fn a_secondary_scoped_split_refuses_at_the_split_grant_boundary() {
    let _env = env_guard();
    let mut shared = shared();
    let changes = [
        ("revoked", LATE_REFUSAL, OutcomeCause::SetupUnavailable),
        ("reselected", LATE_REFUSAL, OutcomeCause::SetupUnavailable),
        ("entry left", LATE_REFUSAL, OutcomeCause::SetupUnavailable),
        (
            "admission ended",
            LATE_REFUSAL,
            OutcomeCause::SetupUnavailable,
        ),
        ("ir unavailable", SIDES, OutcomeCause::CameraUnavailable),
        ("ir forced off", SIDES, OutcomeCause::CameraUnavailable),
        ("rgb moved", SIDES, OutcomeCause::CameraUnavailable),
        ("ir moved", SIDES, OutcomeCause::CameraUnavailable),
        ("no scope", SCOPE, OutcomeCause::SetupUnavailable),
    ];
    for pinned in [false, true] {
        for (change, reason, cause) in changes {
            let case = format!("pinned={pinned} {change}");
            let rig = Rig::new(false);
            rig.authorize(pinned);
            let mut admitted = Some(rig.recorder.admit_split_trust(&[Authentication]));
            let standing = Standing::new(&mut shared.engine);
            {
                let (mut call, enrollment) = install_secondary(standing.engine, &rig);
                let out = decide(&mut call, &enrollment, granting());
                assert!(out.granted, "{case}: control before the change: {out:?}");
                match change {
                    "revoked" => rig.revoke(),
                    "reselected" => rig.authorize(!pinned),
                    "entry left" => call.leave_split_trust(),
                    "admission ended" => drop(admitted.take()),
                    "ir unavailable" => call.ir_available = false,
                    "ir forced off" => std::env::set_var("IRLUME_FORCE_NO_IR", "1"),
                    "rgb moved" => call.rgb_dev = MOVED.into(),
                    "ir moved" => call.ir_dev = MOVED.into(),
                    _ => call.secondary_attempt = None,
                }
                let out = decide(&mut call, &enrollment, granting());
                std::env::remove_var("IRLUME_FORCE_NO_IR");
                assert_refused(&out, reason, cause, &case);
                assert!(
                    !rig.lock().exists(),
                    "{case}: the grant boundary takes no configuration lock"
                );
            }
            assert!(rig.recorder.calls().is_empty(), "{case}");
            assert_eq!(
                standing.devices(),
                (STANDING_RGB, STANDING_IR, false),
                "{case}"
            );
        }
        // A decision against any binding but the group's split pair refuses
        // before any arm, with the secondary scope set.
        let rig = Rig::new(false);
        rig.authorize(pinned);
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        let standing = Standing::new(&mut shared.engine);
        {
            let (mut call, enrollment) = install_secondary(standing.engine, &rig);
            for binding in [
                Some(CameraBinding::Split(other_key())),
                Some(ordinary_binding()),
                Some(CameraBinding::Ordinary {
                    rgb: Some(RGB_UNIT.into()),
                    ir: Some(IR_UNIT.into()),
                }),
                Some(absent_binding()),
                None,
            ] {
                let case = format!("pinned={pinned} {binding:?}");
                let mut other = enrollment.clone();
                other.camera_binding = binding;
                let out = decide(&mut call, &other, granting());
                assert_refused(&out, BINDING, OutcomeCause::NotEnrolledOnThisCamera, &case);
            }
            let out = decide(&mut call, &enrollment, granting());
            assert!(out.granted, "pinned={pinned}: control after: {out:?}");
        }
        assert!(rig.recorder.calls().is_empty(), "pinned={pinned}");
    }
}
