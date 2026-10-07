// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! A saved selected split routes the same way in both saved configurations
//! (ADR-0032 cases 8 and 10; plan C7 and D8): split keys only, where the
//! request also reads as automatic, and ordinary `rgb=`/`ir=` lines beside
//! the selected split, where it does not. The authentication call branches
//! on account routing, never on the raw automatic observation, so inside a
//! pin scope it never resolves the standing or configured ordinary pair:
//! the pin routes onto its own split, or denies with no fallback when it
//! cannot route. Account routing also runs at most once per request: a
//! standing pair the request only retained is no route, a refused split
//! install never falls back to the ordinary pair, and a call after an
//! ordinary route in its request fails closed. The rows reuse the parent's
//! non-granting rig; no attempt reaches a grant.

use super::*;

const NOT_ROUTABLE: &str = "split account routing needs an unrouted automatic or pinned request";

/// Where the saved split authorization sits in cameras.conf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Saved {
    /// Split keys only: the request reads as automatic, also under a pin.
    SplitKeysOnly,
    /// Ordinary `rgb=`/`ir=` lines naming the connected ordinary pair beside
    /// the split keys: a configured selection, never automatic.
    OrdinaryLines,
}

impl Saved {
    /// Save this configuration with the split pair, selected or not.
    fn save(self, rig: &Rig, pinned: bool) {
        if self == Self::OrdinaryLines {
            std::fs::write(
                rig.dir.join("cameras.conf"),
                format!("rgb={O_RGB}\nir={O_IR}\n"),
            )
            .unwrap();
        }
        rig.authorize(pinned);
    }

    fn automatic(self) -> bool {
        self == Self::SplitKeysOnly
    }
}

/// The routed rows: automatic routing exists only with split keys only; a
/// pin exists in both configurations.
const ROUTED: [(Saved, bool); 3] = [
    (Saved::SplitKeysOnly, false),
    (Saved::SplitKeysOnly, true),
    (Saved::OrdinaryLines, true),
];

/// The engine's standing devices before the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Before {
    /// Devices the inventory does not list, without IR.
    Unlisted,
    /// The connected ordinary pair with IR, as a daemon configured with the
    /// ordinary lines holds it.
    ListedOrdinary,
}

impl Before {
    fn apply(self, engine: &mut Engine) {
        if self == Self::ListedOrdinary {
            engine.set_devices(O_RGB, O_IR);
            engine.ir_available = true;
        }
    }

    fn devices(self) -> (&'static str, &'static str, bool) {
        match self {
            Self::Unlisted => (STANDING_RGB, STANDING_IR, false),
            Self::ListedOrdinary => (O_RGB, O_IR, true),
        }
    }
}

/// What the authentication call's own preparation retains, read from a
/// probe preparation dropped before the call: the pending pin, the raw
/// automatic observation, whether account routing applies and whether any
/// account candidate is Current.
#[derive(Debug, PartialEq)]
struct Retained {
    pin: Option<SplitPairKey>,
    automatic: bool,
    routes: bool,
    candidates: bool,
}

impl Retained {
    fn read(engine: &mut Engine) -> Self {
        let probe = engine.prepare_authentication_camera_request().unwrap();
        let selection = probe.camera_selection.as_ref().unwrap();
        Self {
            pin: selection.pending_pin().cloned(),
            automatic: selection.automatic(),
            routes: selection.routes_accounts(),
            candidates: selection.has_account_candidates(),
        }
    }
}

/// What camera admission sees of the routed request.
#[derive(Debug, PartialEq)]
struct Admitted {
    calls: Vec<Call>,
    key: Option<SplitPairKey>,
    pending: bool,
    automatic: bool,
    scope: (bool, bool),
    devices: (String, String, bool),
}

/// The authentication call as the daemon runs it, recording what camera
/// admission sees after routing and before the lease.
fn authenticate_observed(
    engine: &mut Engine,
    recorder: &Guard,
) -> (irlume_common::Result<Outcome>, Option<Admitted>) {
    let mut seen = None;
    let result = engine.authenticate_for_in_window_with_policy_preparing_delivering(
        USER,
        Some("login"),
        AuthenticationPurpose::Verify,
        AuthenticationWindow::new(2000),
        irlume_common::config::FaceSensorPolicy::Dual,
        &(),
        &mut |engine, _| {
            let selection = engine.camera_selection.as_ref().expect("a prepared call");
            seen = Some(Admitted {
                calls: recorder.calls(),
                key: engine.installed_split_key(),
                pending: selection.pending_pin().is_some(),
                automatic: selection.automatic(),
                scope: (
                    engine.primary_attempt.is_some(),
                    engine.secondary_attempt.is_some(),
                ),
                devices: (
                    engine.rgb_dev.clone(),
                    engine.ir_dev.clone(),
                    engine.ir_available,
                ),
            });
            Ok(())
        },
        &mut |_, outcome| assert!(!outcome.granted, "the fixture never grants: {outcome:?}"),
    );
    (result, seen)
}

/// Plant the account of one shape: a primary bound to the split, or a
/// primary bound to an absent unit whose one secondary group is the split.
fn plant(rig: &Rig, engine: &Engine, secondary: bool) -> PrimarySnapshot {
    if secondary {
        let primary = rig.primary(engine, Some(absent_binding()));
        rig.secondary(&primary);
        primary
    } else {
        rig.primary(engine, Some(split_binding()))
    }
}

/// The secondary store's pending commit intent.
fn secondary_intent() -> PathBuf {
    irlume_core::multi_camera::commit::intent_path_for(&secondary_store_path(USER))
}

/// A fixture inventory installed over the rig's own without the split IR
/// unit: the split RGB unit, beside the ordinary unit when `ordinary`. The
/// saved authorization and selection still name the unplugged side.
fn without_the_split_ir_unit(ordinary: bool) -> Guard {
    let unit = |topology: &str, identity: &str, port: u8, endpoints| Camera {
        topology: topology.into(),
        identity: identity.into(),
        fixed: true,
        controller: CONTROLLER.into(),
        domain: SplitDomain::Usb2,
        ports: vec![port],
        endpoints,
    };
    let endpoint = |path: &str, format: [u8; 4]| Endpoint {
        path: path.into(),
        formats: vec![format],
    };
    let mut cameras = vec![unit(
        "/devices/split-authentication/rgb",
        RGB_UNIT,
        8,
        vec![endpoint(S_RGB, *b"YUYV")],
    )];
    if ordinary {
        cameras.push(unit(
            "/devices/split-authentication/ordinary",
            ORDINARY_UNIT,
            3,
            vec![endpoint(O_RGB, *b"YUYV"), endpoint(O_IR, *b"GREY")],
        ));
    }
    Guard::install(&cameras).unwrap()
}

/// Why a saved selected split cannot route in this request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unroutable {
    /// The pinned IR side is unplugged; the ordinary pair stays Current.
    IrUnpluggedBesideTheOrdinaryPair,
    /// The pinned IR side is unplugged and nothing else is connected.
    IrUnpluggedAlone,
    /// The inventory is refreshing, so nothing is Current.
    InventoryRefreshing,
    /// The pinned pair is connected; the account is bound to another split.
    BoundToAnotherSplit,
    /// The pinned pair is connected; the account is bound to the connected
    /// ordinary pair the ordinary lines name.
    BoundToTheOrdinaryPair,
}

impl Unroutable {
    const ALL: [Self; 5] = [
        Self::IrUnpluggedBesideTheOrdinaryPair,
        Self::IrUnpluggedAlone,
        Self::InventoryRefreshing,
        Self::BoundToAnotherSplit,
        Self::BoundToTheOrdinaryPair,
    ];

    /// Whether the request still lists any Current account candidate.
    fn candidates(self) -> bool {
        !matches!(self, Self::IrUnpluggedAlone | Self::InventoryRefreshing)
    }

    /// The account shapes of this row: both for a lost side, the primary
    /// for a binding elsewhere.
    fn shapes(self) -> &'static [bool] {
        match self {
            Self::BoundToAnotherSplit | Self::BoundToTheOrdinaryPair => &[false],
            _ => &[false, true],
        }
    }

    fn plant(self, rig: &Rig, engine: &Engine, secondary: bool) -> PrimarySnapshot {
        match self {
            Self::BoundToAnotherSplit => {
                rig.primary(engine, Some(CameraBinding::Split(other_key())))
            }
            Self::BoundToTheOrdinaryPair => rig.primary(engine, Some(ordinary_binding())),
            _ => plant(rig, engine, secondary),
        }
    }
}

// Branch condition (W1b round-3 review, finding 1): a pin routes through
// classified account routing in both configurations, never through the raw
// automatic observation, and a standing pair the request only retained is
// no account route (F1b round 3).

#[test]
fn a_saved_selected_split_routes_alike_beside_ordinary_lines_or_split_keys_only() {
    let _env = env_guard();
    let mut shared = shared();
    for (saved, pinned) in ROUTED {
        for secondary in [false, true] {
            for before in [Before::Unlisted, Before::ListedOrdinary] {
                let case =
                    format!("{saved:?} pinned={pinned} secondary={secondary} before={before:?}");
                let rig = Rig::new(true);
                saved.save(&rig, pinned);
                let counts = rig.recorder.lease_counts_observer();
                let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
                let standing = Standing::new(&mut shared.engine);
                before.apply(standing.engine);
                assert_eq!(
                    Retained::read(standing.engine),
                    Retained {
                        pin: pinned.then(key),
                        automatic: saved.automatic(),
                        routes: true,
                        candidates: true,
                    },
                    "{case}: the configuration this row claims"
                );
                let primary = plant(&rig, standing.engine, secondary);
                let (result, seen) = authenticate_observed(standing.engine, &rig.recorder);
                assert_eq!(
                    seen,
                    Some(Admitted {
                        calls: Vec::new(),
                        key: Some(key()),
                        pending: false,
                        automatic: saved.automatic(),
                        scope: (!secondary, secondary),
                        devices: (S_RGB.into(), S_IR.into(), true),
                    }),
                    "{case}: routed onto the split before camera admission ({})",
                    reply(&result)
                );
                assert_eq!(
                    rig.recorder.calls(),
                    vec![split_lease(), Call::OpenRgb(S_RGB.into())],
                    "{case}: one split Authentication lease, then the sequential RGB attempt; \
                     the standing or configured ordinary pair is never leased or opened ({})",
                    reply(&result)
                );
                assert!(!granted(&result), "{case}: {}", reply(&result));
                assert!(
                    !reply(&result).contains(CLOSED),
                    "{case}: {}",
                    reply(&result)
                );
                assert_eq!(counts(), (0, 0), "{case}: both reservations released");
                assert!(standing.engine.camera_selection.is_none(), "{case}");
                assert_eq!(
                    standing.devices(),
                    before.devices(),
                    "{case}: no standing split choice; the standing devices return"
                );
                assert_eq!(
                    std::fs::read(rig.primary_path()).unwrap(),
                    primary.bytes,
                    "{case}"
                );
                assert!(!rig.lock().exists(), "{case}: no cameras.conf lock file");
                assert!(
                    !rig.dir.join("capture-qualifications").exists(),
                    "{case}: no qualification read or write"
                );
            }
        }
    }
}

// The standing and configured branches are never reached under a pin, also
// when the pin cannot route: it denies at account routing, before camera
// admission, in both configurations and with or without any Current account
// candidate.

#[test]
fn a_saved_selected_split_that_cannot_route_denies_without_a_standing_or_configured_fallback() {
    let _env = env_guard();
    let mut shared = shared();
    for saved in [Saved::SplitKeysOnly, Saved::OrdinaryLines] {
        for unroutable in Unroutable::ALL {
            for &secondary in unroutable.shapes() {
                let case = format!("{saved:?} {unroutable:?} secondary={secondary}");
                let rig = Rig::new(true);
                saved.save(&rig, true);
                let unplugged = match unroutable {
                    Unroutable::IrUnpluggedBesideTheOrdinaryPair => {
                        Some(without_the_split_ir_unit(true))
                    }
                    Unroutable::IrUnpluggedAlone => Some(without_the_split_ir_unit(false)),
                    _ => None,
                };
                let recorder = unplugged.as_ref().unwrap_or(&rig.recorder);
                let counts = recorder.lease_counts_observer();
                let _admitted = recorder.admit_split_trust(&[Authentication]);
                if unroutable == Unroutable::InventoryRefreshing {
                    recorder.invalidation_observer()();
                }
                let standing = Standing::new(&mut shared.engine);
                Before::ListedOrdinary.apply(standing.engine);
                assert_eq!(
                    Retained::read(standing.engine),
                    Retained {
                        pin: Some(key()),
                        automatic: saved.automatic(),
                        routes: true,
                        candidates: unroutable.candidates(),
                    },
                    "{case}: the configuration this row claims"
                );
                let primary = unroutable.plant(&rig, standing.engine, secondary);
                let (result, seen) = authenticate_observed(standing.engine, recorder);
                let outcome = result
                    .as_ref()
                    .unwrap_or_else(|error| panic!("{case}: expected a deny, got {error}"));
                assert!(
                    !outcome.granted && outcome.reason.contains(NOT_CONNECTED),
                    "{case}: the pin denies at account routing: {outcome:?}"
                );
                assert_eq!(outcome.kind, OutcomeKind::SetupUnavailable, "{case}");
                assert_eq!(
                    outcome.cause,
                    Some(OutcomeCause::NotEnrolledOnThisCamera),
                    "{case}"
                );
                assert_eq!(seen, None, "{case}: denied before camera admission");
                assert!(
                    recorder.calls().is_empty(),
                    "{case}: no lease or open of any pair: {:?}",
                    recorder.calls()
                );
                assert_eq!(counts(), (0, 0), "{case}");
                assert!(standing.engine.camera_selection.is_none(), "{case}");
                assert_eq!(
                    standing.devices(),
                    Before::ListedOrdinary.devices(),
                    "{case}"
                );
                assert_eq!(
                    std::fs::read(rig.primary_path()).unwrap(),
                    primary.bytes,
                    "{case}"
                );
                assert!(!rig.lock().exists(), "{case}: no cameras.conf lock file");
                assert!(!secondary_intent().exists(), "{case}: no secondary intent");
            }
        }
    }
}

// Route once (F1b round 3; W1b round-4 review): the call returns on a
// refused split install and never reaches the connected ordinary pair.

#[test]
fn a_refused_split_install_never_falls_back_to_the_ordinary_pair() {
    let _env = env_guard();
    let mut shared = shared();
    for (saved, pinned) in ROUTED {
        for secondary in [false, true] {
            let case = format!("{saved:?} pinned={pinned} secondary={secondary}");
            let rig = Rig::new(true);
            saved.save(&rig, pinned);
            let counts = rig.recorder.lease_counts_observer();
            let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
            let standing = Standing::new(&mut shared.engine);
            Before::ListedOrdinary.apply(standing.engine);
            assert_eq!(
                Retained::read(standing.engine),
                Retained {
                    pin: pinned.then(key),
                    automatic: saved.automatic(),
                    routes: true,
                    candidates: true,
                },
                "{case}: the configuration this row claims"
            );
            let primary = plant(&rig, standing.engine, secondary);
            std::env::set_var("IRLUME_FORCE_NO_IR", "1");
            let (result, seen) = authenticate_observed(standing.engine, &rig.recorder);
            std::env::remove_var("IRLUME_FORCE_NO_IR");
            assert!(
                result.is_err() && reply(&result).contains(IR_FORCED_OFF),
                "{case}: {}",
                reply(&result)
            );
            assert_eq!(seen, None, "{case}: refused before camera admission");
            assert!(
                rig.recorder.calls().is_empty(),
                "{case}: no split or ordinary lease: {:?}",
                rig.recorder.calls()
            );
            assert_eq!(counts(), (0, 0), "{case}");
            assert!(standing.engine.camera_selection.is_none(), "{case}");
            assert_eq!(
                standing.devices(),
                Before::ListedOrdinary.devices(),
                "{case}"
            );
            assert_eq!(
                std::fs::read(rig.primary_path()).unwrap(),
                primary.bytes,
                "{case}"
            );
            assert!(!rig.lock().exists(), "{case}");
        }
    }
}

#[test]
fn an_authentication_call_after_an_ordinary_route_in_its_request_fails_closed() {
    let _env = env_guard();
    let mut shared = shared();
    for outer_authentication in [false, true] {
        for secondary in [false, true] {
            let case = format!("outer={outer_authentication} secondary={secondary}");
            let rig = Rig::new(true);
            Saved::SplitKeysOnly.save(&rig, false);
            let counts = rig.recorder.lease_counts_observer();
            let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
            let standing = Standing::new(&mut shared.engine);
            let primary = plant(&rig, standing.engine, secondary);
            {
                // The outer request a daemon holds routed the ordinary pair.
                let mut outer = if outer_authentication {
                    standing.engine.prepare_authentication_camera_request()
                } else {
                    standing.engine.prepare_camera_request()
                }
                .unwrap();
                let pairs = &outer
                    .camera_selection
                    .as_ref()
                    .unwrap()
                    .view()
                    .ordinary
                    .pairs;
                assert_eq!(pairs.len(), 1, "{case}");
                let ordinary = pairs[0].clone();
                outer
                    .select_account_camera(ordinary)
                    .expect("the outer request routes the ordinary pair");
                let (result, seen) = authenticate_observed(&mut outer, &rig.recorder);
                assert!(
                    result.is_err() && reply(&result).contains(NOT_ROUTABLE),
                    "{case}: the account's split never reroutes the request: {}",
                    reply(&result)
                );
                assert_eq!(seen, None, "{case}: refused before camera admission");
                assert_eq!(
                    (
                        outer.rgb_dev.as_str(),
                        outer.ir_dev.as_str(),
                        outer.ir_available
                    ),
                    (O_RGB, O_IR, true),
                    "{case}: the request keeps its ordinary route"
                );
                assert_eq!(outer.installed_split_key(), None, "{case}");
            }
            assert!(
                rig.recorder.calls().is_empty(),
                "{case}: no split or ordinary lease: {:?}",
                rig.recorder.calls()
            );
            assert_eq!(counts(), (0, 0), "{case}");
            assert!(standing.engine.camera_selection.is_none(), "{case}");
            assert_eq!(
                standing.devices(),
                (O_RGB, O_IR, true),
                "{case}: the accepted ordinary route stays the standing choice"
            );
            assert_eq!(
                std::fs::read(rig.primary_path()).unwrap(),
                primary.bytes,
                "{case}"
            );
            assert!(!rig.lock().exists(), "{case}");
        }
    }
}
