// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! IR-only routing scope rows (ADR-0032 Step 5; plan C7, D1, D8 and D9),
//! on the parent's non-granting rig. No row reaches a grant.
//!
//! - A pending pin routes IR-only readiness and authentication only through
//!   its own key under both cameras.conf shapes: split keys only, where the
//!   selection reads as automatic, and ordinary `rgb=`/`ir=` lines beside the
//!   selected split, where it does not. Neither path reaches the configured
//!   IR target, also when the pinned pair is away.
//! - A pin whose authentication entry ended refuses IR-only authentication
//!   with the closed text before any account storage is read or recovered.
//! - Without a pin, a non-automatic ordinary selection keeps the configured
//!   IR target and never routes to the account's own pair (D1).
//! - IR-only authentication still recovers a pending secondary journal
//!   before routing, as the ordinary automatic path always did.

use super::*;

const C_RGB: &str = "/dev/irlume-split-ir-only-configured-rgb";
const C_IR: &str = "/dev/irlume-split-ir-only-configured-ir";
const CONFIGURED_UNIT: &str = "5679:0004:qcfg";

/// The two cameras.conf shapes a saved selected split can sit in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Conf {
    /// Only the published split keys: the selection reads Fresh, so
    /// `automatic()` is true under the pin.
    SplitKeysOnly,
    /// Ordinary `rgb=`/`ir=` lines beside the selected split: `automatic()`
    /// is false under the pin.
    OrdinaryLines,
}

const BOTH: [Conf; 2] = [Conf::SplitKeysOnly, Conf::OrdinaryLines];

impl Conf {
    /// Write this shape's ordinary lines. The split is published beside
    /// them afterwards.
    fn write(self, rig: &Rig) {
        if self == Self::OrdinaryLines {
            std::fs::write(
                rig.dir.join("cameras.conf"),
                format!("rgb={O_RGB}\nir={O_IR}\n"),
            )
            .unwrap();
        }
    }
}

/// How a non-automatic ordinary selection names its configured pair.
#[derive(Clone, Copy, Debug)]
enum Override {
    /// `rgb=`/`ir=` lines in cameras.conf.
    ConfigLines,
    /// The `IRLUME_RGB_DEVICE`/`IRLUME_IR_DEVICE` pair.
    Environment,
}

fn devices(engine: &Engine) -> (&str, &str, bool) {
    (
        engine.rgb_dev.as_str(),
        engine.ir_dev.as_str(),
        engine.ir_available,
    )
}

#[test]
fn a_pin_routes_ir_only_through_its_own_key_under_both_config_shapes() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let standing = Standing::new(&mut shared.engine);
    for conf in BOTH {
        let rig = Rig::new(WITH_ORDINARY);
        conf.write(&rig);
        rig.authorize(true);
        let counts = rig.recorder.lease_counts_observer();
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        for (bound, expected) in [
            (Bound::Split, D9),
            (Bound::SplitGroup, D9),
            // The connected ordinary pair the account is bound to is not
            // ranked under the pin.
            (Bound::Ordinary, NOT_CONNECTED),
            // No legacy fallback under a pin.
            (Bound::Unbound, PIN_NOT_ENROLLED),
        ] {
            let row = format!("{conf:?} {bound:?}");
            rig.account(&spaces, bound);
            let mut request = standing
                .engine
                .prepare_authentication_camera_request()
                .expect("the admitted authentication call retains the pin");
            let selection = request.camera_selection.as_ref().unwrap();
            assert_eq!(selection.pending_pin(), Some(&Rig::key()), "{row}");
            assert_eq!(
                selection.automatic(),
                conf == Conf::SplitKeysOnly,
                "{row}: the config shape"
            );
            let readiness = request.ir_only_preflight_details(USER);
            assert_eq!(
                (readiness.readiness, readiness.target_issue, readiness.scope),
                (Ready::BindingMismatch, None, None),
                "{row}: {readiness:?}"
            );
            let (result, admitted) = ir_only_in_scope(&mut request);
            let shown = describe(&result);
            let refused = expect_refusal(result);
            assert!(refused.reason.contains(expected), "{row}: {shown}");
            if expected == D9 {
                assert_d9(&refused, &row);
            } else {
                assert_eq!(
                    refused.cause,
                    Some(OutcomeCause::NotEnrolledOnThisCamera),
                    "{row}: {shown}"
                );
            }
            assert_eq!(admitted, 0, "{row}: the admission hook ran");
            assert!(installed_binding(&request).is_none(), "{row}");
            assert_eq!(
                devices(&request),
                (STANDING_RGB, STANDING_IR, false),
                "{row}: the request left its standing devices"
            );
        }
        // The daemon's call shape: the public entry prepares and declares
        // the pin itself.
        rig.account(&spaces, Bound::Split);
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::CredentialRelease,
        ] {
            let shown = ir_only_authenticate(standing.engine, purpose);
            assert!(shown.contains(D9), "{conf:?} {purpose:?}: {shown}");
            assert!(standing.engine.camera_selection.is_none(), "{conf:?}");
            assert_eq!(
                standing.devices(),
                (STANDING_RGB, STANDING_IR, false),
                "{conf:?} {purpose:?}"
            );
        }
        // The daemon's unscoped readiness query (FaceSensorStatus): the
        // generic preparation refuses a saved selected split, so it is never
        // Ready.
        let unscoped = standing.engine.ir_only_preflight_details(USER);
        assert_eq!(
            (unscoped.readiness, unscoped.target_issue, unscoped.scope),
            (
                Ready::TargetUnavailable,
                Some(irlume_common::IrTargetIssue::Unavailable),
                None
            ),
            "{conf:?}: {unscoped:?}"
        );
        assert!(standing.engine.camera_selection.is_none(), "{conf:?}");
        // Readiness never recovers a pending journal under a pin.
        let (journal, journal_bytes) = plant_recoverable_journal();
        {
            let request = standing
                .engine
                .prepare_authentication_camera_request()
                .unwrap();
            assert_eq!(
                request.ir_only_preflight_details(USER).readiness,
                Ready::BindingMismatch,
                "{conf:?}"
            );
        }
        assert_eq!(
            std::fs::read(&journal).ok(),
            Some(journal_bytes),
            "{conf:?}: readiness consumed the pending journal"
        );
        assert!(
            !secondary_store_path(USER).exists(),
            "{conf:?}: readiness recovered the secondary store"
        );
        std::fs::remove_file(&journal).unwrap();
        assert_untouched(&rig.recorder);
        assert_eq!(counts(), (0, 0), "{conf:?}");
        assert!(
            !rig.lock().exists(),
            "{conf:?}: IR-only routing took the writer lock"
        );
    }
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn an_away_pin_never_reaches_the_configured_ir_target_under_either_config_shape() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let standing = Standing::new(&mut shared.engine);
    for conf in BOTH {
        let rig = Rig::new(SPLIT_ONLY);
        conf.write(&rig);
        rig.authorize(true);
        // The IR side is unplugged: the pinned pair resolves to nothing and
        // the inventory lists no other pair, so there is no candidate.
        let unplugged = Guard::install(&Rig::cameras(Shape {
            ir_unit: false,
            ..SPLIT_ONLY
        }))
        .unwrap();
        let _admitted = unplugged.admit_split_trust(&[Authentication]);
        rig.account(&spaces, Bound::Split);
        {
            let mut request = standing
                .engine
                .prepare_authentication_camera_request()
                .expect("the pin is retained while its pair is away");
            let selection = request.camera_selection.as_ref().unwrap();
            assert_eq!(selection.pending_pin(), Some(&Rig::key()), "{conf:?}");
            assert_eq!(
                selection.automatic(),
                conf == Conf::SplitKeysOnly,
                "{conf:?}"
            );
            assert!(!selection.has_account_candidates(), "{conf:?}");
            let readiness = request.ir_only_preflight_details(USER);
            assert_eq!(
                (readiness.readiness, readiness.target_issue, readiness.scope),
                (Ready::BindingMismatch, None, None),
                "{conf:?}: {readiness:?}"
            );
            let (result, admitted) = ir_only_in_scope(&mut request);
            let shown = describe(&result);
            let refused = expect_refusal(result);
            assert_eq!(
                refused.cause,
                Some(OutcomeCause::NotEnrolledOnThisCamera),
                "{conf:?}: {shown}"
            );
            assert!(
                !refused.reason.contains(D9) && !refused.reason.contains(CLOSED),
                "{conf:?}: {shown}"
            );
            assert_eq!(admitted, 0, "{conf:?}: the admission hook ran");
            assert!(installed_binding(&request).is_none(), "{conf:?}");
            assert_eq!(
                devices(&request),
                (STANDING_RGB, STANDING_IR, false),
                "{conf:?}"
            );
        }
        assert_untouched(&unplugged);
        assert_untouched(&rig.recorder);
        assert!(!rig.lock().exists(), "{conf:?}");
    }
}

// RED: a pin whose declared Authentication entry ended is closed. IR-only
// authentication refuses with the closed text before it loads the account
// or recovers its pending secondary journal, as every other entry does.

#[test]
fn a_closed_pin_refuses_ir_only_authentication_before_any_storage_work() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let standing = Standing::new(&mut shared.engine);
    for conf in BOTH {
        let rig = Rig::new(WITH_ORDINARY);
        conf.write(&rig);
        rig.authorize(true);
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        rig.account(&spaces, Bound::Split);
        let (journal, journal_bytes) = plant_recoverable_journal();
        {
            let mut outer = standing
                .engine
                .prepare_authentication_camera_request()
                .unwrap();
            // A nested authentication call takes the declaration over and
            // ends it when it drops; nothing reopens it.
            drop(outer.prepare_authentication_camera_request().unwrap());
            assert_eq!(
                outer.camera_selection.as_ref().unwrap().pending_pin(),
                Some(&Rig::key()),
                "{conf:?}"
            );
            let closed = outer.validate_camera_request();
            assert!(
                matches!(&closed, Err(error) if error.to_string().contains(CLOSED)),
                "{conf:?}: {closed:?}"
            );
            // Readiness already validates first.
            let readiness = outer.ir_only_preflight_details(USER);
            assert_eq!(
                (readiness.readiness, readiness.target_issue),
                (
                    Ready::TargetUnavailable,
                    Some(irlume_common::IrTargetIssue::Unavailable)
                ),
                "{conf:?}: {readiness:?}"
            );
            let (result, admitted) = ir_only_in_scope(&mut outer);
            let shown = describe(&result);
            assert!(
                shown.starts_with("Err(") && shown.contains(CLOSED),
                "{conf:?}: a closed pin answered {shown}"
            );
            assert_eq!(admitted, 0, "{conf:?}: the admission hook ran");
            assert!(installed_binding(&outer).is_none(), "{conf:?}");
        }
        assert_eq!(
            std::fs::read(&journal).ok(),
            Some(journal_bytes),
            "{conf:?}: a closed pin recovered the pending journal"
        );
        assert!(
            !secondary_store_path(USER).exists(),
            "{conf:?}: a closed pin wrote the secondary store"
        );
        assert_untouched(&rig.recorder);
        assert!(!rig.lock().exists(), "{conf:?}");
    }
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

// Negative controls: GREEN before and after. Each pins a D1 rule of the
// routing predicate that a mutant of ir_assessment.rs would break.

#[test]
fn a_non_automatic_ordinary_selection_keeps_the_configured_ir_target() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let standing = Standing::new(&mut shared.engine);
    for way in [Override::ConfigLines, Override::Environment] {
        let rig = Rig::new(WITH_ORDINARY);
        // A second ordinary unit is the configured pair; the account is
        // bound to the other one.
        let mut cameras = Rig::cameras(WITH_ORDINARY);
        cameras.push(Camera {
            topology: "/devices/split-ir-only/configured".into(),
            identity: CONFIGURED_UNIT.into(),
            fixed: true,
            controller: CONTROLLER.into(),
            domain: SplitDomain::Usb2,
            ports: vec![4],
            endpoints: vec![
                Endpoint {
                    path: C_RGB.into(),
                    formats: vec![*b"YUYV"],
                },
                Endpoint {
                    path: C_IR.into(),
                    formats: vec![*b"GREY"],
                },
            ],
        });
        let inventory = Guard::install(&cameras).unwrap();
        match way {
            Override::ConfigLines => std::fs::write(
                rig.dir.join("cameras.conf"),
                format!("rgb={C_RGB}\nir={C_IR}\n"),
            )
            .unwrap(),
            Override::Environment => {
                std::env::set_var("IRLUME_RGB_DEVICE", C_RGB);
                std::env::set_var("IRLUME_IR_DEVICE", C_IR);
            }
        }
        // Authorized split records, none selected: no pin.
        rig.authorize(false);
        for admitted in [false, true] {
            let _admission = admitted.then(|| inventory.admit_split_trust(&[Authentication]));
            for bound in [Bound::Ordinary, Bound::Split] {
                let row = format!("{way:?} admitted={admitted} {bound:?}");
                rig.account(&spaces, bound);
                let mut request = standing
                    .engine
                    .prepare_authentication_camera_request()
                    .unwrap();
                let selection = request.camera_selection.as_ref().unwrap();
                assert!(
                    !selection.automatic()
                        && !selection.routes_accounts()
                        && selection.pending_pin().is_none()
                        && selection.has_account_candidates(),
                    "{row}: not a non-automatic selection with account candidates"
                );
                // The configured pair is not a video node in this fixture,
                // so its target is unavailable before the account is read.
                let readiness = request.ir_only_preflight_details(USER);
                assert_eq!(
                    (readiness.readiness, readiness.target_issue, readiness.scope),
                    (
                        Ready::TargetUnavailable,
                        Some(irlume_common::IrTargetIssue::Unavailable),
                        None
                    ),
                    "{row}: {readiness:?}"
                );
                let (result, hooks) = ir_only_in_scope(&mut request);
                let shown = describe(&result);
                let refused = expect_refusal(result);
                assert_eq!(
                    (refused.kind, refused.cause),
                    (
                        OutcomeKind::SetupUnavailable,
                        Some(OutcomeCause::CameraUnavailable)
                    ),
                    "{row}: {shown}"
                );
                assert!(
                    [D9, CLOSED, NOT_CONNECTED]
                        .iter()
                        .all(|text| !refused.reason.contains(text)),
                    "{row}: {shown}"
                );
                assert_eq!(hooks, 0, "{row}: the admission hook ran");
                // Never routed to the account's own pair.
                assert!(installed_binding(&request).is_none(), "{row}");
                assert_eq!(
                    devices(&request),
                    (STANDING_RGB, STANDING_IR, false),
                    "{row}: account routing moved the request"
                );
                drop(request);
                // The public entry answers the same and keeps the standing
                // devices.
                let public = ir_only_authenticate(standing.engine, AuthenticationPurpose::Verify);
                assert_eq!(public, shown, "{row}");
                assert_eq!(
                    standing.devices(),
                    (STANDING_RGB, STANDING_IR, false),
                    "{row}"
                );
            }
        }
        assert_untouched(&inventory);
        assert!(!rig.lock().exists(), "{way:?}");
    }
}

#[test]
fn ir_only_authentication_recovers_a_pending_secondary_journal_before_routing() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(false);
    rig.account(&spaces, Bound::Ordinary);
    let standing = Standing::new(&mut shared.engine);
    for admitted in [false, true] {
        let _admission = admitted.then(|| rig.recorder.admit_split_trust(&[Authentication]));
        let _ = std::fs::remove_file(secondary_store_path(USER));
        let (journal, _) = plant_recoverable_journal();
        let result = standing.engine.authenticate_for_in_window_with_policy(
            USER,
            None,
            AuthenticationPurpose::Verify,
            AuthenticationWindow::new(2000),
            irlume_common::config::FaceSensorPolicy::IrOnlyExperimental,
            &(),
        );
        let shown = describe(&result);
        if let Ok(outcome) = &result {
            assert!(!outcome.granted && !outcome.live, "{shown}");
        }
        assert!(
            !journal.exists(),
            "admitted={admitted}: IR-only authentication left the pending journal: {shown}"
        );
        assert!(
            secondary_store_path(USER).exists(),
            "admitted={admitted}: the journal was not recovered forward: {shown}"
        );
        // An ordinary account route stays the standing choice (plan D8);
        // start the next run from the same standing devices.
        standing.engine.set_devices(STANDING_RGB, STANDING_IR);
        standing.engine.ir_available = false;
    }
    let calls = rig.recorder.calls();
    assert!(
        calls.iter().all(|call| !matches!(
            call,
            irlume_camera::test_support::Call::Lease { endpoints, .. }
                if endpoints.iter().any(|endpoint| endpoint == S_RGB || endpoint == S_IR)
        )),
        "{calls:?}"
    );
    assert!(!rig.lock().exists());
}
