// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! IR-only experimental policy on a split pair (ADR-0032 Step 5, plan D9,
//! with the C7 pin and D8 no-fallback rules). An IR-only attempt whose
//! classified account choice is a split pair refuses with the explicit D9
//! text before any admission hook or lease, and readiness reports the
//! existing `BindingMismatch` without the cameras.conf writer lock. A
//! pending pin routes only its own key, also when the selection does not
//! read as automatic and when the pinned pair is away, so neither path
//! falls back to an ordinary, legacy or configured IR target. The fixture
//! refuses every open and no row reaches a grant.

mod split_ir_only_scope_tests;
use super::*;
use irlume_camera::lease::CameraOperationKind::Authentication;
use irlume_camera::test_support::{Camera, Endpoint, Guard};
use irlume_common::split_key::{SplitDomain, SplitPairKey, SplitUnitKey};
use irlume_common::split_schema::{AuthorizationRecord, SideFields};
use irlume_common::IrOnlyReadiness as Ready;
use irlume_core::multi_camera::{
    save_secondary, secondary_store_path, CameraGroupId, GroupPair, SecondaryGroup,
    SecondaryProfileScans, SecondaryStore, SECONDARY_STORE_VERSION,
};
use std::{cell::Cell, ffi::OsString, path::PathBuf};

const USER: &str = "split-ir-only";
const S_RGB: &str = "/dev/irlume-split-ir-only-rgb";
const S_IR: &str = "/dev/irlume-split-ir-only-ir";
const O_RGB: &str = "/dev/irlume-split-ir-only-ordinary-rgb";
const O_IR: &str = "/dev/irlume-split-ir-only-ordinary-ir";
const STANDING_RGB: &str = "/dev/irlume-split-ir-only-standing-rgb";
const STANDING_IR: &str = "/dev/irlume-split-ir-only-standing-ir";
const RGB_UNIT: &str = "5679:0001:qrgb";
const IR_UNIT: &str = "5679:0002:qir";
const ORDINARY_UNIT: &str = "5679:0003:qord";
const ABSENT_UNIT: &str = "5679:00ff:qabsent";
const CONTROLLER: &str = "0000:00:14.0";
const D9: &str = "split camera IR-only authentication is not supported; use your password";
const CLOSED: &str = "split enrollment and authentication are not enabled";
const NOT_CONNECTED: &str = "no eligible enrolled camera is connected";
const PIN_NOT_ENROLLED: &str = "the selected split camera pair is not enrolled for this account";

#[derive(Clone, Copy)]
struct Shape {
    ordinary: bool,
    ir_unit: bool,
}

const SPLIT_ONLY: Shape = Shape {
    ordinary: false,
    ir_unit: true,
};
const WITH_ORDINARY: Shape = Shape {
    ordinary: true,
    ir_unit: true,
};

/// The account bindings the rows plant.
#[derive(Clone, Copy, Debug)]
enum Bound {
    /// The primary is bound to the authorized split pair.
    Split,
    /// The primary is bound to an absent camera and one active secondary
    /// group is bound to the authorized split pair.
    SplitGroup,
    /// The primary is bound to the connected ordinary unit.
    Ordinary,
    /// The primary has no camera binding.
    Unbound,
}

/// The recognizer spaces of the shared engine, so the planted templates
/// count as compatible IR templates for its IR-only matcher.
struct Spaces {
    ir: String,
    embed: String,
}

impl Spaces {
    fn of(engine: &Engine) -> Self {
        Self {
            ir: engine.ir_space().to_owned(),
            embed: engine.embed_space().to_owned(),
        }
    }
}

/// A sandboxed state and config directory and a non-granting inventory:
/// one split pair on two single-endpoint USB units, optionally beside one
/// ordinary RGB+IR unit. Distinct paths and identities from the other
/// split fixtures.
struct Rig {
    dir: PathBuf,
    saved: Vec<(&'static str, Option<OsString>)>,
    recorder: Guard,
    /// Every rig test takes the no-TPM plaintext branch: the dead
    /// `IRLUME_TCTI` cannot reach a TPM, and on a host with /dev/tpm* the
    /// device-node probe would otherwise force a seal onto it.
    _no_tpm: irlume_core::template_key::test_support::TpmPresence,
}

impl Rig {
    fn new(shape: Shape) -> Self {
        let no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let dir = std::env::temp_dir().join(format!(
            "irlume-split-ir-only-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let keys = [
            "IRLUME_CONFIG_DIR",
            "IRLUME_STATE_DIR",
            "IRLUME_RGB_DEVICE",
            "IRLUME_IR_DEVICE",
            "IRLUME_FORCE_NO_IR",
            "IRLUME_CAMERA_REQUIRE_FIXED",
            "IRLUME_FORBID_EXTERNAL_CAMERAS",
            "IRLUME_TEMPLATE_KEY_DIR",
            "IRLUME_GRACE_MS",
            "IRLUME_TCTI",
        ];
        let saved = keys
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", dir.join("private-template-keys"));
        // No key resolution is expected; an explicit failed transport still
        // keeps any accidental one off the host TPM.
        std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-test-tpm");
        for key in [
            "IRLUME_RGB_DEVICE",
            "IRLUME_IR_DEVICE",
            "IRLUME_FORCE_NO_IR",
            "IRLUME_CAMERA_REQUIRE_FIXED",
            "IRLUME_FORBID_EXTERNAL_CAMERAS",
            "IRLUME_GRACE_MS",
        ] {
            std::env::remove_var(key);
        }
        let recorder = Guard::install(&Self::cameras(shape)).unwrap();
        Self {
            dir,
            saved,
            recorder,
            _no_tpm: no_tpm,
        }
    }

    fn cameras(shape: Shape) -> Vec<Camera> {
        let unit = |topology: &str, identity: &str, port, endpoints| Camera {
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
            "/devices/split-ir-only/rgb",
            RGB_UNIT,
            8,
            vec![endpoint(S_RGB, *b"YUYV")],
        )];
        if shape.ir_unit {
            cameras.push(unit(
                "/devices/split-ir-only/ir",
                IR_UNIT,
                5,
                vec![endpoint(S_IR, *b"GREY")],
            ));
        }
        if shape.ordinary {
            cameras.push(unit(
                "/devices/split-ir-only/ordinary",
                ORDINARY_UNIT,
                3,
                vec![endpoint(O_RGB, *b"YUYV"), endpoint(O_IR, *b"GREY")],
            ));
        }
        cameras
    }

    fn unit_key(identity: &str, port: u8) -> SplitUnitKey {
        SplitUnitKey {
            identity: identity.into(),
            controller: CONTROLLER.into(),
            domain: SplitDomain::Usb2,
            ports: vec![port],
        }
    }

    fn key() -> SplitPairKey {
        SplitPairKey {
            rgb: Self::unit_key(RGB_UNIT, 8),
            ir: Self::unit_key(IR_UNIT, 5),
        }
    }

    fn side(identity: &str, path: &str, port: u8) -> SideFields {
        SideFields {
            identity: identity.into(),
            path: path.into(),
            controller: CONTROLLER.into(),
            domain: SplitDomain::Usb2,
            ports: vec![port],
        }
    }

    /// Publish the one administrator-authorized split pair, selected
    /// (pinned) or not, then remove the writer's lock file, so a later one
    /// proves a later lock.
    fn authorize(&self, pinned: bool) {
        let key = Self::key();
        let record = AuthorizationRecord {
            rgb: Self::side(RGB_UNIT, S_RGB, 8),
            ir: Self::side(IR_UNIT, S_IR, 5),
        };
        irlume_common::split_publish::publish_split(&[record], pinned.then_some(&key)).unwrap();
        let _ = std::fs::remove_file(self.lock());
    }

    fn lock(&self) -> PathBuf {
        self.dir.join("cameras.conf.lock")
    }

    /// Plant a plaintext account whose scans the shared engine's IR-only
    /// matcher counts as compatible, bound as `bound` says.
    fn account(&self, spaces: &Spaces, bound: Bound) {
        let _ = std::fs::remove_file(secondary_store_path(USER));
        let (mut enrollment, _) = pad_matching_fixture(0.2, false);
        enrollment.user = USER.into();
        for scan in &mut enrollment.profiles[0].scans {
            scan.ir = Some(scan.rgb.clone());
            scan.ir_space = Some(spaces.ir.clone());
            scan.embed_space = Some(spaces.embed.clone());
        }
        let ordinary = |identity: &str| CameraBinding::Ordinary {
            rgb: Some(identity.into()),
            ir: Some(identity.into()),
        };
        enrollment.camera_binding = match bound {
            Bound::Split => Some(CameraBinding::Split(Self::key())),
            Bound::SplitGroup => Some(ordinary(ABSENT_UNIT)),
            Bound::Ordinary => Some(ordinary(ORDINARY_UNIT)),
            Bound::Unbound => None,
        };
        let bytes = serde_json::to_vec(&enrollment).unwrap();
        std::fs::write(self.dir.join(format!("{USER}.json")), &bytes).unwrap();
        // A read-only readiness load never creates the account's state
        // lock; the normal plaintext loader seeds it, as enrollment would.
        assert!(irlume_core::storage::load_snapshot(USER).unwrap().is_some());
        if matches!(bound, Bound::SplitGroup) {
            let store = SecondaryStore {
                format_version: SECONDARY_STORE_VERSION,
                owner: USER.into(),
                generation: 1,
                primary_snapshot_sha256: irlume_common::sha256_hex(&bytes),
                groups: vec![SecondaryGroup {
                    id: CameraGroupId::new("split-desk".into()).unwrap(),
                    pair: GroupPair::Split(Self::key()),
                    profiles: vec![SecondaryProfileScans {
                        ir_calibs: Default::default(),
                        profile: enrollment.profiles[0].name.clone(),
                        scans: enrollment.profiles[0].scans.clone(),
                    }],
                }],
            };
            save_secondary(&secondary_store_path(USER), &store).unwrap();
        }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Points the shared engine at standing devices the inventory does not
/// list, without IR, and restores the engine on drop.
struct Standing<'a> {
    engine: &'a mut Engine,
    previous: (String, String, bool),
}

impl<'a> Standing<'a> {
    fn new(engine: &'a mut Engine) -> Self {
        let previous = (
            engine.rgb_dev.clone(),
            engine.ir_dev.clone(),
            engine.ir_available,
        );
        engine.set_devices(STANDING_RGB, STANDING_IR);
        engine.ir_available = false;
        Self { engine, previous }
    }

    fn devices(&self) -> (&str, &str, bool) {
        (
            self.engine.rgb_dev.as_str(),
            self.engine.ir_dev.as_str(),
            self.engine.ir_available,
        )
    }
}

impl Drop for Standing<'_> {
    fn drop(&mut self) {
        self.engine.rgb_dev = std::mem::take(&mut self.previous.0);
        self.engine.ir_dev = std::mem::take(&mut self.previous.1);
        self.engine.ir_available = self.previous.2;
        self.engine.primary_attempt = None;
        self.engine.secondary_attempt = None;
        self.engine.request_key().clear();
    }
}

fn describe(result: &irlume_common::Result<Outcome>) -> String {
    match result {
        Ok(outcome) => format!(
            "Ok({:?}/{:?}: {})",
            outcome.kind, outcome.cause, outcome.reason
        ),
        Err(error) => format!("Err({error})"),
    }
}

/// A non-granting refusal outcome, never an error.
fn expect_refusal(result: irlume_common::Result<Outcome>) -> Outcome {
    let shown = describe(&result);
    match result {
        Ok(outcome) => {
            assert!(!outcome.granted && !outcome.live, "{shown}");
            outcome
        }
        Err(_) => panic!("expected a refusal outcome, got {shown}"),
    }
}

/// The D9 refusal: the explicit text, a setup class that keeps retry
/// accounting, and no camera cause.
fn assert_d9(outcome: &Outcome, row: &str) {
    assert_eq!(outcome.reason, D9, "{row}");
    assert_eq!(outcome.kind, OutcomeKind::SetupUnavailable, "{row}");
    assert_eq!(outcome.cause, Some(OutcomeCause::SetupUnavailable), "{row}");
}

/// The public IR-only authentication entry, as the daemon calls it.
fn ir_only_authenticate(engine: &mut Engine, purpose: AuthenticationPurpose) -> String {
    describe(&engine.authenticate_for_in_window_with_policy(
        USER,
        None,
        purpose,
        AuthenticationWindow::new(2000),
        irlume_common::config::FaceSensorPolicy::IrOnlyExperimental,
        &(),
    ))
}

/// The IR-only branch of one authentication call inside its own prepared
/// scope, with a counting admission hook. Returns the result and how often
/// the hook ran.
fn ir_only_in_scope(engine: &mut Engine) -> (irlume_common::Result<Outcome>, usize) {
    let admitted = Cell::new(0);
    let mut admission = |_: &Engine, _: AuthenticationWindow| -> irlume_common::Result<()> {
        admitted.set(admitted.get() + 1);
        Ok(())
    };
    engine.begin_attempt();
    let result = engine.authenticate_ir_in_window(
        USER,
        AuthenticationWindow::new(2000),
        &(),
        &mut admission,
    );
    engine.request_key().clear();
    (result, admitted.get())
}

/// The camera boundary saw no lease attempt and no open.
fn assert_untouched(recorder: &Guard) {
    let calls = recorder.calls();
    assert!(calls.is_empty(), "{calls:?}");
}

fn installed_binding(engine: &Engine) -> Option<GroupPair> {
    engine
        .camera_selection
        .as_ref()
        .and_then(|selection| selection.binding())
}

/// A valid pending secondary journal for the account, which only a writing
/// path may recover. Its recover-forward payload is an empty generation-2
/// plaintext store owned by `USER` with an all-zero activation digest: no
/// biometric data. Returns the journal path and its exact bytes.
fn plant_recoverable_journal() -> (PathBuf, Vec<u8>) {
    use irlume_core::multi_camera::commit::{intent_path_for, CommitIntent, INTENT_FORMAT_VERSION};
    let intent = CommitIntent {
        format_version: INTENT_FORMAT_VERSION,
        generation: 2,
        primary_snapshot_sha256: "0".repeat(64),
        new_secondary_b64: concat!(
            "eyJmb3JtYXRfdmVyc2lvbiI6MSwib3duZXIiOiJzcGxpdC1pci1vbmx5IiwiZ2VuZXJhdGlvbiI6Miwi",
            "cHJpbWFyeV9zbmFwc2hvdF9zaGEyNTYiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw",
            "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwiZ3JvdXBzIjpbXX0=",
        )
        .into(),
    };
    let journal = intent_path_for(&secondary_store_path(USER));
    std::fs::create_dir_all(journal.parent().unwrap()).unwrap();
    let bytes = serde_json::to_vec(&intent).unwrap();
    std::fs::write(&journal, &bytes).unwrap();
    (journal, bytes)
}

// RED: Authentication admitted. Each needs D9 or the pin-aware routing.

#[test]
fn an_ir_only_automatic_split_choice_refuses_with_the_d9_text_before_any_lease() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let counts = rig.recorder.lease_counts_observer();
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    for bound in [Bound::Split, Bound::SplitGroup] {
        rig.account(&spaces, bound);
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::CredentialRelease,
        ] {
            let row = format!("{bound:?} {purpose:?}");
            let shown = ir_only_authenticate(standing.engine, purpose);
            assert!(shown.contains(D9), "{row}: {shown}");
            assert!(
                standing.engine.camera_selection.is_none(),
                "{row}: the request scope outlived the call"
            );
            assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
        }
        // The outcome itself, through one authentication call's own scope.
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        assert!(request
            .camera_selection
            .as_ref()
            .unwrap()
            .pending_pin()
            .is_none());
        let (result, admitted) = ir_only_in_scope(&mut request);
        let refused = expect_refusal(result);
        assert_d9(&refused, &format!("{bound:?} in scope"));
        assert_eq!(admitted, 0, "{bound:?}: the admission hook ran");
        assert!(installed_binding(&request).is_none(), "{bound:?}");
        assert_eq!(
            (request.rgb_dev.as_str(), request.ir_dev.as_str()),
            (STANDING_RGB, STANDING_IR),
            "{bound:?}: the split was installed"
        );
        drop(request);
        assert!(standing.engine.camera_selection.is_none());
    }
    // Refused before any lease: the camera boundary saw no attempt at all.
    assert_untouched(&rig.recorder);
    assert_eq!(counts(), (0, 0));
    assert!(!rig.lock().exists(), "IR-only routing took the writer lock");
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn an_ir_only_pinned_split_routes_only_its_key_and_refuses_before_any_lease() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(true);
    let counts = rig.recorder.lease_counts_observer();
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    for (bound, expected) in [
        (Bound::Split, D9),
        (Bound::SplitGroup, D9),
        // The connected ordinary pair the account is bound to is not routed.
        (Bound::Ordinary, NOT_CONNECTED),
        // No legacy fallback under a pin.
        (Bound::Unbound, PIN_NOT_ENROLLED),
    ] {
        rig.account(&spaces, bound);
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .expect("the admitted authentication call retains the pin");
        assert_eq!(
            request.camera_selection.as_ref().unwrap().pending_pin(),
            Some(&Rig::key())
        );
        let (result, admitted) = ir_only_in_scope(&mut request);
        let shown = describe(&result);
        let refused = expect_refusal(result);
        assert!(refused.reason.contains(expected), "{bound:?}: {shown}");
        if expected == D9 {
            assert_d9(&refused, &format!("{bound:?}"));
        } else {
            assert_eq!(
                refused.cause,
                Some(OutcomeCause::NotEnrolledOnThisCamera),
                "{bound:?}: {shown}"
            );
        }
        assert_eq!(admitted, 0, "{bound:?}: the admission hook ran");
        assert!(installed_binding(&request).is_none(), "{bound:?}");
        assert_eq!(
            (request.rgb_dev.as_str(), request.ir_dev.as_str()),
            (STANDING_RGB, STANDING_IR),
            "{bound:?}"
        );
    }
    assert_untouched(&rig.recorder);
    assert_eq!(counts(), (0, 0));
    assert!(!rig.lock().exists(), "IR-only routing took the writer lock");
    assert!(standing.engine.camera_selection.is_none());
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn ir_only_readiness_in_a_pinned_split_scope_is_binding_mismatch_without_a_config_lock() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(true);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    for bound in [
        Bound::Split,
        Bound::SplitGroup,
        Bound::Ordinary,
        Bound::Unbound,
    ] {
        rig.account(&spaces, bound);
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        assert!(request
            .camera_selection
            .as_ref()
            .unwrap()
            .pending_pin()
            .is_some());
        let readiness = request.ir_only_preflight_details(USER);
        assert_eq!(
            (readiness.readiness, readiness.target_issue, readiness.scope),
            (Ready::BindingMismatch, None, None),
            "{bound:?}: {readiness:?}"
        );
        assert!(installed_binding(&request).is_none(), "{bound:?}");
    }
    // A readiness query never recovers a pending journal under a pin either.
    rig.account(&spaces, Bound::Split);
    let (journal, journal_bytes) = plant_recoverable_journal();
    {
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        assert_eq!(
            request.ir_only_preflight_details(USER).readiness,
            Ready::BindingMismatch
        );
    }
    assert_eq!(
        std::fs::read(&journal).ok(),
        Some(journal_bytes),
        "readiness consumed the pending journal"
    );
    assert!(
        !secondary_store_path(USER).exists(),
        "readiness recovered the secondary store"
    );
    assert!(
        !rig.lock().exists(),
        "IR-only readiness created cameras.conf.lock"
    );
    // Control: a writing path does recover this journal.
    assert_eq!(
        irlume_core::multi_camera::commit::resolve_commit(&secondary_store_path(USER)).unwrap(),
        irlume_core::multi_camera::commit::CommitResolution::Completed
    );
    assert!(!journal.exists() && secondary_store_path(USER).exists());
    assert_untouched(&rig.recorder);
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn a_pin_beside_ordinary_pin_lines_routes_ir_only_through_the_pin() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let rig = Rig::new(WITH_ORDINARY);
    std::fs::write(
        rig.dir.join("cameras.conf"),
        format!("rgb={O_RGB}\nir={O_IR}\n"),
    )
    .unwrap();
    rig.authorize(true);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    for bound in [Bound::Split, Bound::Ordinary] {
        rig.account(&spaces, bound);
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let selection = request.camera_selection.as_ref().unwrap();
        // The selection does not read as automatic, but the pin routes.
        assert!(!selection.automatic() && selection.routes_accounts());
        let readiness = request.ir_only_preflight_details(USER);
        assert_eq!(
            readiness.readiness,
            Ready::BindingMismatch,
            "{bound:?}: {readiness:?}"
        );
        let (result, admitted) = ir_only_in_scope(&mut request);
        let shown = describe(&result);
        let refused = expect_refusal(result);
        match bound {
            Bound::Split => assert_d9(&refused, &shown),
            _ => assert!(refused.reason.contains(NOT_CONNECTED), "{shown}"),
        }
        assert_eq!(admitted, 0, "{bound:?}: the admission hook ran");
        assert!(installed_binding(&request).is_none(), "{bound:?}");
    }
    assert_untouched(&rig.recorder);
    assert!(!rig.lock().exists());
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn an_away_pinned_split_never_falls_back_to_the_configured_ir_target() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(true);
    // The IR side is unplugged: the pinned pair resolves to nothing and the
    // inventory lists no other pair.
    let unplugged = Guard::install(&Rig::cameras(Shape {
        ir_unit: false,
        ..SPLIT_ONLY
    }))
    .unwrap();
    let _admitted = unplugged.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    rig.account(&spaces, Bound::Split);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .expect("the pin is retained while its pair is away");
        let selection = request.camera_selection.as_ref().unwrap();
        assert_eq!(selection.pending_pin(), Some(&Rig::key()));
        assert!(!selection.has_account_candidates());
        let readiness = request.ir_only_preflight_details(USER);
        assert_eq!(
            (readiness.readiness, readiness.target_issue),
            (Ready::BindingMismatch, None),
            "{readiness:?}"
        );
        let (result, admitted) = ir_only_in_scope(&mut request);
        let shown = describe(&result);
        let refused = expect_refusal(result);
        assert_eq!(
            refused.cause,
            Some(OutcomeCause::NotEnrolledOnThisCamera),
            "{shown}"
        );
        assert!(
            !refused.reason.contains(D9) && !refused.reason.contains(CLOSED),
            "{shown}"
        );
        assert_eq!(admitted, 0);
        assert!(installed_binding(&request).is_none());
    }
    assert_untouched(&unplugged);
    assert_untouched(&rig.recorder);
    assert!(!rig.lock().exists());
}

// Mutation guards: GREEN before this change (the closed wrapper already
// refused these); they pin that readiness never proceeds on a split choice.

#[test]
fn ir_only_readiness_for_an_automatic_split_choice_is_binding_mismatch() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    for bound in [Bound::Split, Bound::SplitGroup] {
        rig.account(&spaces, bound);
        // The daemon's unscoped readiness query.
        let unscoped = standing.engine.ir_only_preflight_details(USER);
        assert_eq!(
            (unscoped.readiness, unscoped.target_issue, unscoped.scope),
            (Ready::BindingMismatch, None, None),
            "{bound:?}: {unscoped:?}"
        );
        assert!(standing.engine.camera_selection.is_none());
        // And inside one authentication call's scope.
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        assert!(request.camera_selection.as_ref().unwrap().automatic());
        let scoped = request.ir_only_preflight_details(USER);
        assert_eq!(
            (scoped.readiness, scoped.target_issue, scoped.scope),
            (Ready::BindingMismatch, None, None),
            "{bound:?}: {scoped:?}"
        );
        assert!(installed_binding(&request).is_none());
    }
    assert!(
        !rig.lock().exists(),
        "IR-only readiness created cameras.conf.lock"
    );
    assert_untouched(&rig.recorder);
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

// Negative controls: GREEN from the start and after.

#[test]
fn closed_default_ir_only_split_keeps_the_closed_text_and_readiness() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let standing = Standing::new(&mut shared.engine);
    for bound in [Bound::Split, Bound::SplitGroup] {
        rig.account(&spaces, bound);
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::CredentialRelease,
        ] {
            let shown = ir_only_authenticate(standing.engine, purpose);
            // Automatic routing can select either split scope after admission,
            // so both refusals name activation while it remains closed.
            assert_eq!(
                shown,
                format!("Ok(OtherDeny/Some(NotEnrolledOnThisCamera): {CLOSED})"),
                "{bound:?} {purpose:?}"
            );
        }
        let readiness = standing.engine.ir_only_preflight_details(USER);
        assert_eq!(readiness.readiness, Ready::BindingMismatch, "{bound:?}");
    }
    // A saved selected split also routes only after admission; unscoped
    // readiness stays TargetUnavailable while the predicate is closed.
    rig.authorize(true);
    rig.account(&spaces, Bound::Split);
    let shown = ir_only_authenticate(standing.engine, AuthenticationPurpose::Verify);
    assert!(
        shown.starts_with("Err(") && shown.contains(CLOSED),
        "{shown}"
    );
    let readiness = standing.engine.ir_only_preflight_details(USER);
    assert_eq!(
        (readiness.readiness, readiness.target_issue),
        (
            Ready::TargetUnavailable,
            Some(irlume_common::IrTargetIssue::Unavailable)
        )
    );
    assert!(standing.engine.camera_selection.is_none());
    assert_untouched(&rig.recorder);
    assert!(!rig.lock().exists());
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn ordinary_ir_only_routing_is_unchanged_by_split_admission() {
    let _env = env_guard();
    let mut shared = shared();
    let spaces = Spaces::of(&shared.engine);
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(false);
    rig.account(&spaces, Bound::Ordinary);
    let mut standing = Standing::new(&mut shared.engine);
    // An ordinary automatic route keeps its standing choice (plan D8), so
    // each run starts from, and returns to, the same standing devices.
    let observe = |standing: &mut Standing<'_>| {
        let before = rig.recorder.calls().len();
        let readiness = standing.engine.ir_only_preflight_details(USER);
        let shown = ir_only_authenticate(standing.engine, AuthenticationPurpose::Verify);
        let calls = rig.recorder.calls()[before..].to_vec();
        let devices = (
            standing.engine.rgb_dev.clone(),
            standing.engine.ir_dev.clone(),
        );
        standing.engine.set_devices(STANDING_RGB, STANDING_IR);
        standing.engine.ir_available = false;
        (shown, readiness, calls, devices)
    };
    let closed = observe(&mut standing);
    let admitted = {
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        observe(&mut standing)
    };
    assert_eq!(closed, admitted);
    let (shown, readiness, calls, _) = admitted;
    assert!(
        !shown.contains(D9) && !shown.contains(CLOSED) && !shown.contains(NOT_CONNECTED),
        "{shown}"
    );
    assert_ne!(readiness.readiness, Ready::BindingMismatch, "{readiness:?}");
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
