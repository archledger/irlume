// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Runtime account routing onto a split pair (ADR-0032 cases 7 to 10, 12
//! and 15; plan C4 to C7, D7, D8 and D10), at the AUTH routing seam: the
//! class-aware choice, the split Authentication install, its one split
//! lease and the lock-free late authority. The fixture refuses every open
//! and no row reaches a grant.

mod split_authentication_call_tests;
mod split_authentication_scope_tests;
mod split_refused_install_tests;
mod split_route_once_tests;
use super::*;
use crate::account_selection::{select_account_classified, ClassifiedChoice};
use crate::ir_assessment::IrOnlyScope;
use crate::request_preparation::SplitChoice;
use irlume_common::split_key::{SplitDomain, SplitPairKey, SplitUnitKey};
use irlume_core::multi_camera::{
    save_secondary, secondary_store_path, CameraGroupId, GroupPair, SecondaryGroup,
    SecondaryProfileScans, SecondaryStore, SECONDARY_STORE_VERSION,
};
use irlume_core::storage::PrimarySnapshot;
use irlume_core::template_key::RequestTemplateKey;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

const USER: &str = "split-account";
const S_RGB: &str = "/dev/irlume-split-account-rgb";
const S_IR: &str = "/dev/irlume-split-account-ir";
const S2_RGB: &str = "/dev/irlume-split-account-second-rgb";
const S2_IR: &str = "/dev/irlume-split-account-second-ir";
const O_RGB: &str = "/dev/irlume-split-account-ordinary-rgb";
const O_IR: &str = "/dev/irlume-split-account-ordinary-ir";
const STANDING_RGB: &str = "/dev/irlume-split-account-standing-rgb";
const STANDING_IR: &str = "/dev/irlume-split-account-standing-ir";
const RGB_UNIT: &str = "5678:0001:srgb";
const IR_UNIT: &str = "5678:0002:sir";
const SECOND_RGB_UNIT: &str = "5678:0011:srgb";
const SECOND_IR_UNIT: &str = "5678:0012:sir";
const ORDINARY_UNIT: &str = "5678:0003:ord";
const ABSENT_UNIT: &str = "5678:00ff:absent";
const CONTROLLER: &str = "0000:00:14.0";
const NOT_CONNECTED: &str = "no eligible enrolled camera is connected";
const PIN_NOT_ENROLLED: &str = "the selected split camera pair is not enrolled for this account";
const LATE_REFUSAL: &str = "split camera authorization changed during the request";

#[derive(Clone, Copy)]
struct Shape {
    ordinary: bool,
    ir_unit: bool,
    ir_fixed: bool,
    second_split: bool,
}

const SPLIT_ONLY: Shape = Shape {
    ordinary: false,
    ir_unit: true,
    ir_fixed: true,
    second_split: false,
};
const WITH_ORDINARY: Shape = Shape {
    ordinary: true,
    ir_unit: true,
    ir_fixed: true,
    second_split: false,
};

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
    generation: std::cell::Cell<u64>,
}

impl Rig {
    fn new(shape: Shape) -> Self {
        let no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let dir = std::env::temp_dir().join(format!(
            "irlume-split-account-{}-{:?}",
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
            generation: std::cell::Cell::new(0),
            _no_tpm: no_tpm,
        }
    }

    fn cameras(shape: Shape) -> Vec<Camera> {
        let unit = |topology: &str, identity: &str, fixed, port, endpoints| Camera {
            topology: topology.into(),
            identity: identity.into(),
            fixed,
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
            "/devices/split-account/rgb",
            RGB_UNIT,
            true,
            8,
            vec![endpoint(S_RGB, *b"YUYV")],
        )];
        if shape.ir_unit {
            cameras.push(unit(
                "/devices/split-account/ir",
                IR_UNIT,
                shape.ir_fixed,
                5,
                vec![endpoint(S_IR, *b"GREY")],
            ));
        }
        if shape.ordinary {
            cameras.push(unit(
                "/devices/split-account/ordinary",
                ORDINARY_UNIT,
                true,
                3,
                vec![endpoint(O_RGB, *b"YUYV"), endpoint(O_IR, *b"GREY")],
            ));
        }
        if shape.second_split {
            cameras.push(unit(
                "/devices/split-account/second-rgb",
                SECOND_RGB_UNIT,
                true,
                6,
                vec![endpoint(S2_RGB, *b"YUYV")],
            ));
            cameras.push(unit(
                "/devices/split-account/second-ir",
                SECOND_IR_UNIT,
                true,
                7,
                vec![endpoint(S2_IR, *b"GREY")],
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

    fn second_key() -> SplitPairKey {
        SplitPairKey {
            rgb: Self::unit_key(SECOND_RGB_UNIT, 6),
            ir: Self::unit_key(SECOND_IR_UNIT, 7),
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

    fn record() -> AuthorizationRecord {
        AuthorizationRecord {
            rgb: Self::side(RGB_UNIT, S_RGB, 8),
            ir: Self::side(IR_UNIT, S_IR, 5),
        }
    }

    fn second_record() -> AuthorizationRecord {
        AuthorizationRecord {
            rgb: Self::side(SECOND_RGB_UNIT, S2_RGB, 6),
            ir: Self::side(SECOND_IR_UNIT, S2_IR, 7),
        }
    }

    /// Publish `records` with `selected` as the saved selection, then
    /// remove the writer's lock file, so a later one proves a later lock.
    fn publish(&self, records: &[AuthorizationRecord], selected: Option<&SplitPairKey>) {
        irlume_common::split_publish::publish_split(records, selected).unwrap();
        let _ = std::fs::remove_file(self.lock());
    }

    /// Publish the one administrator-authorized split pair, selected
    /// (pinned) or not.
    fn authorize(&self, pinned: bool) {
        let key = Self::key();
        self.publish(&[Self::record()], pinned.then_some(&key));
    }

    /// Remove every split authorization, then the writer's lock file.
    fn revoke(&self) {
        irlume_common::split_publish::publish_split(&[], None).unwrap();
        let _ = std::fs::remove_file(self.lock());
    }

    fn lock(&self) -> PathBuf {
        self.dir.join("cameras.conf.lock")
    }

    /// The guard and publication a daemon would hand to split enrollment,
    /// read from the current publication without republishing.
    fn displayed(
        &self,
    ) -> (
        irlume_common::split_wire::SplitMutationGuard,
        irlume_common::split_publish::Published,
    ) {
        let snapshot = irlume_common::split_publish::read_camera_selection();
        let records = match snapshot.split() {
            irlume_common::split_publish::SplitReadState::Valid { records, .. } => records,
            state => panic!("fixture publication refused: {state:?}"),
        };
        let lease = irlume_camera::connected_pairs_with_split(records)
            .split_pairs
            .remove(0)
            .lease_request();
        let side =
            |side: irlume_camera::SplitSideExpectation| irlume_common::split_wire::SplitSideGuard {
                instance_id: side.instance_id,
                generation: side.generation,
                endpoint: side.endpoint,
            };
        let guard = irlume_common::split_wire::SplitMutationGuard {
            supervisor_id: lease.supervisor_id,
            revision: lease.revision,
            rgb: side(lease.rgb),
            ir: side(lease.ir),
        };
        let irlume_common::config::SplitConfObservation::Reference {
            generation, digest, ..
        } = snapshot.observation().split.clone()
        else {
            panic!("missing split reference")
        };
        (
            guard,
            irlume_common::split_publish::Published { generation, digest },
        )
    }

    /// Plant a plaintext primary with `binding` and return its snapshot.
    fn primary(&self, binding: Option<CameraBinding>) -> PrimarySnapshot {
        let (mut enrollment, _) = pad_matching_fixture(0.2, false);
        enrollment.user = USER.into();
        enrollment.camera_binding = binding;
        let bytes = serde_json::to_vec(&enrollment).unwrap();
        std::fs::write(self.dir.join(format!("{USER}.json")), &bytes).unwrap();
        PrimarySnapshot {
            enrollment,
            key: None,
            bytes,
        }
    }

    /// Plant an active secondary store holding `groups`, in store order.
    fn secondary(&self, primary: &PrimarySnapshot, groups: &[(&str, GroupPair)]) {
        self.generation.set(self.generation.get() + 1);
        let scans = primary.enrollment.profiles[0].scans.clone();
        let store = SecondaryStore {
            format_version: SECONDARY_STORE_VERSION,
            owner: USER.into(),
            generation: self.generation.get(),
            primary_snapshot_sha256: irlume_common::sha256_hex(&primary.bytes),
            groups: groups
                .iter()
                .map(|(id, pair)| SecondaryGroup {
                    id: CameraGroupId::new((*id).into()).unwrap(),
                    pair: pair.clone(),
                    profiles: vec![SecondaryProfileScans {
                        ir_calibs: Default::default(),
                        profile: "fixture".into(),
                        scans: scans.clone(),
                    }],
                })
                .collect(),
        };
        save_secondary(&secondary_store_path(USER), &store).unwrap();
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
    }
}

/// Holds the cameras.conf writer lock on another thread until released or
/// until `max` passes. The flag drops before the lock does, so a caller that
/// returns while the flag is still set never waited for this lock.
struct Writer {
    held: Arc<AtomicBool>,
    release: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Writer {
    fn hold(max: Duration) -> Self {
        let held = Arc::new(AtomicBool::new(false));
        let (release, wait) = mpsc::channel::<()>();
        let (ready, started) = mpsc::channel::<()>();
        let flag = Arc::clone(&held);
        let thread = std::thread::spawn(move || {
            let lock = irlume_common::config::lock_exclusive("cameras.conf")
                .expect("the fixture writer takes the cameras.conf lock");
            flag.store(true, Ordering::SeqCst);
            ready.send(()).unwrap();
            let _ = wait.recv_timeout(max);
            flag.store(false, Ordering::SeqCst);
            drop(lock);
        });
        started.recv().unwrap();
        Self {
            held,
            release,
            thread: Some(thread),
        }
    }

    fn still_held(&self) -> bool {
        self.held.load(Ordering::SeqCst)
    }

    fn release(mut self) {
        let _ = self.release.send(());
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn eligible(enrollment: &irlume_core::storage::Enrollment) -> bool {
    enrollment
        .profiles
        .iter()
        .any(|profile| !profile.scans.is_empty())
}

/// Route one account through the request's retained selection with a
/// counting key source; returns the choice and the unseal count.
fn route(
    engine: &Engine,
    primary: PrimarySnapshot,
    read_only: bool,
) -> (Result<ClassifiedChoice, Outcome>, usize) {
    let mut keys = RequestTemplateKey::with_unsealer(|_: &str| Ok(None));
    let selection = engine
        .camera_selection
        .as_ref()
        .expect("a prepared request");
    let choice =
        select_account_classified(USER, primary, selection, eligible, &mut keys, read_only);
    (choice, keys.unseals())
}

fn describe(choice: &Result<ClassifiedChoice, Outcome>) -> String {
    match choice {
        Ok(ClassifiedChoice::Legacy(_)) => "Legacy".into(),
        Ok(ClassifiedChoice::Ordinary { pair, .. }) => format!("Ordinary({})", pair.rgb),
        Ok(ClassifiedChoice::Split { split, .. }) => format!("Split({})", split.pair().rgb.path),
        Err(outcome) => format!("Err({})", outcome.reason),
    }
}

fn expect_split(choice: Result<ClassifiedChoice, Outcome>) -> (Box<SplitChoice>, IrOnlyScope) {
    match choice {
        Ok(ClassifiedChoice::Split {
            enrollment,
            split,
            scope,
        }) => {
            // The routed credential is this account's own scoped enrollment.
            assert_eq!(enrollment.user, USER);
            assert!(eligible(&enrollment));
            (split, scope)
        }
        other => panic!("expected a split choice, got {}", describe(&other)),
    }
}

fn expect_denied(choice: Result<ClassifiedChoice, Outcome>) -> Outcome {
    match choice {
        Err(outcome) => {
            assert!(!outcome.granted && !outcome.live, "{}", outcome.reason);
            outcome
        }
        other => panic!("expected a denial, got {}", describe(&other)),
    }
}

fn lease(
    engine: &Engine,
    endpoints: &[&str],
    kind: CameraOperationKind,
) -> Result<CameraOperationSession, CameraLeaseError> {
    engine.acquire_account_camera(endpoints, kind, WAIT)
}

fn split_lease(kind: CameraOperationKind) -> Call {
    Call::Lease {
        endpoints: vec![S_RGB.into(), S_IR.into()],
        kind,
    }
}

fn split_binding() -> Option<CameraBinding> {
    Some(CameraBinding::Split(Rig::key()))
}

fn absent_binding() -> Option<CameraBinding> {
    Some(CameraBinding::Ordinary {
        rgb: Some(ABSENT_UNIT.into()),
        ir: Some(ABSENT_UNIT.into()),
    })
}

fn ordinary_group() -> GroupPair {
    GroupPair::Ordinary {
        rgb: Some(ORDINARY_UNIT.into()),
        ir: Some(ORDINARY_UNIT.into()),
    }
}

/// A pending secondary journal for the account, which only a writing
/// route may recover.
fn plant_pending_intent() -> PathBuf {
    let intent = irlume_core::multi_camera::commit::intent_path_for(&secondary_store_path(USER));
    std::fs::create_dir_all(intent.parent().unwrap()).unwrap();
    std::fs::write(&intent, b"pending").unwrap();
    intent
}

fn installed_binding(engine: &Engine) -> Option<GroupPair> {
    engine
        .camera_selection
        .as_ref()
        .and_then(|selection| selection.binding())
}

// RED: Authentication admitted. Each needs C4 to C7 or D10.

#[test]
fn admitted_automatic_split_primary_routes_to_one_authentication_split_lease() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let counts = rig.recorder.lease_counts_observer();
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let selection = request.camera_selection.as_ref().unwrap();
        assert!(selection.automatic() && selection.pending_pin().is_none());
        let listed = selection.view().split_pairs.clone();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].pair_key().unwrap(), Rig::key());
        let (choice, unseals) = route(&request, rig.primary(split_binding()), false);
        let (split, scope) = expect_split(choice);
        assert_eq!(split.pair(), &listed[0], "the retained view's own pair");
        assert_eq!(split.key(), &Rig::key());
        assert_eq!(split.lease_request(), &listed[0].lease_request());
        assert!(matches!(scope, IrOnlyScope::Primary { .. }));
        assert!(unseals <= 1, "{unseals} unseals");
        assert!(request.camera_selection.as_ref().unwrap().automatic());
        request
            .select_account_split_camera(*split)
            .expect("an admitted split installs for the Authentication entry");
        assert_eq!(
            (
                request.rgb_dev.as_str(),
                request.ir_dev.as_str(),
                request.ir_available
            ),
            (S_RGB, S_IR, true)
        );
        assert_eq!(
            installed_binding(&request),
            Some(GroupPair::Split(Rig::key()))
        );
        assert!(request.prepared_camera_lease().is_none());
        request
            .validate_camera_request()
            .expect("the installed Authentication split validates");
        let operation = lease(&request, &[S_RGB, S_IR], Authentication)
            .expect("one split Authentication lease over both original sides");
        assert!(operation.lease().is_split_pair());
        assert_eq!(operation.lease().operation(), Authentication);
        assert_eq!(counts(), (2, 0), "one permit reserves both incarnations");
        request
            .validate_camera_request()
            .expect("the held split lease still validates");
        assert!(request.pre_open_account_refusal().is_none());
        drop(operation);
        assert_eq!(counts(), (0, 0));
        // Only both original sides, and only the Authentication kind.
        assert!(matches!(
            lease(&request, &[S_RGB], Authentication).err(),
            Some(CameraLeaseError::InvalidEndpoint(_))
        ));
        for kind in [Enrollment, Diagnostics, Capture] {
            assert_eq!(
                lease(&request, &[S_RGB, S_IR], kind).err(),
                Some(CameraLeaseError::SplitActivationDisabled),
                "{kind:?}"
            );
        }
        // Leaving the entry closes the installed split, late authority too.
        request.leave_split_trust();
        assert!(closed(request.validate_camera_request()));
        assert!(request.split_grant_authority_refusal().is_some());
        assert!(request.pre_open_account_refusal().is_some());
        assert_eq!(
            lease(&request, &[S_RGB, S_IR], Authentication).err(),
            Some(CameraLeaseError::SplitActivationDisabled)
        );
    }
    // No standing split choice outlives the request (plan D8).
    assert!(standing.engine.camera_selection.is_none());
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
    assert_eq!(rig.recorder.calls(), vec![split_lease(Authentication)]);
    assert_eq!(counts(), (0, 0));
}

#[test]
fn admitted_split_secondary_pins_its_group_from_the_loaded_store() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let primary = rig.primary(absent_binding());
        rig.secondary(&primary, &[("split-desk", GroupPair::Split(Rig::key()))]);
        let (choice, unseals) = route(&request, primary, false);
        let (split, scope) = expect_split(choice);
        // The loaded store pins its group; a plaintext request unseals at most once.
        assert!(unseals <= 1, "{unseals} unseals");
        let IrOnlyScope::Secondary(context) = scope else {
            panic!("a split secondary routes through its pinned group")
        };
        assert_eq!(context.store_index(), 0);
        request.select_account_split_camera(*split).unwrap();
        request.secondary_attempt = Some(*context);
        assert!(request.pre_open_account_refusal().is_none());
        let operation = lease(&request, &[S_RGB, S_IR], Authentication).unwrap();
        assert!(operation.lease().is_split_pair());
        drop(operation);
    }
    assert_eq!(rig.recorder.calls(), vec![split_lease(Authentication)]);
}

#[test]
fn split_ranking_keeps_primary_first_and_ordinary_before_split_secondaries() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        // Store order lists the split group first; canonical order ranks the
        // ordinary group ahead of it (case 8).
        let primary = rig.primary(absent_binding());
        rig.secondary(
            &primary,
            &[
                ("split-desk", GroupPair::Split(Rig::key())),
                ("ordinary-desk", ordinary_group()),
            ],
        );
        match route(&request, primary, false).0 {
            Ok(ClassifiedChoice::Ordinary {
                pair,
                scope: IrOnlyScope::Secondary(context),
                ..
            }) => {
                assert_eq!((pair.rgb.as_str(), pair.ir.as_str()), (O_RGB, O_IR));
                assert_eq!(context.store_index(), 1);
            }
            other => panic!("expected the ordinary secondary, got {}", describe(&other)),
        }
        // A split primary ranks ahead of every ordinary secondary.
        let primary = rig.primary(split_binding());
        rig.secondary(&primary, &[("ordinary-desk", ordinary_group())]);
        let (split, scope) = expect_split(route(&request, primary, false).0);
        assert_eq!(split.key(), &Rig::key());
        assert!(matches!(scope, IrOnlyScope::Primary { .. }));
        // Two groups holding one split key are ambiguous: a denial, never a
        // pick by store order.
        let primary = rig.primary(absent_binding());
        rig.secondary(
            &primary,
            &[
                ("split-a", GroupPair::Split(Rig::key())),
                ("split-b", GroupPair::Split(Rig::key())),
            ],
        );
        let denied = expect_denied(route(&request, primary, false).0);
        assert!(
            denied.reason.contains(NOT_CONNECTED) && denied.reason.contains("AmbiguousGroups"),
            "{}",
            denied.reason
        );
    }
    assert!(rig.recorder.calls().is_empty());
}

#[test]
fn hybrid_and_role_swapped_bindings_never_select_the_split_pair() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    let key = Rig::key();
    let swapped = SplitPairKey {
        rgb: key.ir.clone(),
        ir: key.rgb.clone(),
    };
    {
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        // Case 7: the role-swapped key and an ordinary hybrid of both units'
        // identities are other credentials, refused by ranking, not by the gate.
        for binding in [
            CameraBinding::Split(swapped.clone()),
            CameraBinding::Ordinary {
                rgb: Some(RGB_UNIT.into()),
                ir: Some(IR_UNIT.into()),
            },
        ] {
            let denied = expect_denied(route(&request, rig.primary(Some(binding)), false).0);
            assert!(denied.reason.contains(NOT_CONNECTED), "{}", denied.reason);
        }
        let primary = rig.primary(absent_binding());
        rig.secondary(&primary, &[("swapped", GroupPair::Split(swapped))]);
        let denied = expect_denied(route(&request, primary, false).0);
        assert!(denied.reason.contains(NOT_CONNECTED), "{}", denied.reason);
        // The genuine key still routes, so the refusals above were ranking.
        expect_split(route(&request, rig.primary(split_binding()), false).0);
        assert!(installed_binding(&request).is_none());
    }
    assert!(rig.recorder.calls().is_empty());
}

#[test]
fn not_applicable_keeps_the_standing_path_and_never_admits_a_connected_split() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        // Case 9: an unbound primary is NotApplicable, which keeps the
        // standing ordinary path and never authorizes the connected split.
        match route(&request, rig.primary(None), false).0 {
            Ok(ClassifiedChoice::Legacy(_)) => {}
            other => panic!("expected the legacy path, got {}", describe(&other)),
        }
        assert!(installed_binding(&request).is_none());
        // An enrolled split group of that same account still routes.
        let primary = rig.primary(None);
        rig.secondary(&primary, &[("split-desk", GroupPair::Split(Rig::key()))]);
        let (_, scope) = expect_split(route(&request, primary, false).0);
        assert!(matches!(scope, IrOnlyScope::Secondary(_)));
    }
}

#[test]
fn pinned_split_routes_only_its_key_with_no_legacy_or_ordinary_fallback() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(true);
    let counts = rig.recorder.lease_counts_observer();
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    // Every other preparation keeps the closed refusal, admitted or not.
    assert!(refusal(standing.engine.prepare_camera_request()).contains(CLOSED));
    assert!(standing.engine.camera_selection.is_none());
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .expect("the admitted authentication entry retains the pin");
        let selection = request.camera_selection.as_ref().unwrap();
        assert_eq!(selection.pending_pin(), Some(&Rig::key()));
        assert!(selection.automatic());
        assert!(
            request.may_select_account_camera(),
            "the advisory applies selected-route tier and policy to a resolving pin"
        );
        request
            .validate_camera_request()
            .expect("the declared pending pin validates");
        // A pending pin leases nothing until routing installs it.
        for endpoints in [[S_RGB, S_IR], [O_RGB, O_IR], [STANDING_RGB, STANDING_IR]] {
            assert_eq!(
                lease(&request, &endpoints, Authentication).err(),
                Some(CameraLeaseError::SplitActivationDisabled),
                "{endpoints:?}"
            );
        }
        // The connected ordinary pair the account is bound to is not routed.
        let ordinary = Some(CameraBinding::Ordinary {
            rgb: Some(ORDINARY_UNIT.into()),
            ir: Some(ORDINARY_UNIT.into()),
        });
        let denied = expect_denied(route(&request, rig.primary(ordinary), false).0);
        assert!(denied.reason.contains(NOT_CONNECTED), "{}", denied.reason);
        // An unbound account has no legacy fallback under a pin.
        let denied = expect_denied(route(&request, rig.primary(None), false).0);
        assert!(
            denied.reason.contains(PIN_NOT_ENROLLED),
            "{}",
            denied.reason
        );
        // The pinned key itself routes.
        let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        request.select_account_split_camera(*split).unwrap();
        assert!(request
            .camera_selection
            .as_ref()
            .unwrap()
            .pending_pin()
            .is_none());
        let operation = lease(&request, &[S_RGB, S_IR], Authentication).unwrap();
        assert_eq!(counts(), (2, 0));
        drop(operation);
    }
    assert_eq!(rig.recorder.calls(), vec![split_lease(Authentication)]);
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
}

#[test]
fn pinned_split_never_ranks_another_authorized_split_pair() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(Shape {
        second_split: true,
        ..SPLIT_ONLY
    });
    let records = [Rig::record(), Rig::second_record()];
    rig.publish(&records, None);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    let second = Some(CameraBinding::Split(Rig::second_key()));
    {
        // Automatic: the account bound to the second authorized pair routes
        // to exactly that pair.
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let listed = request
            .camera_selection
            .as_ref()
            .unwrap()
            .view()
            .split_pairs
            .clone();
        assert_eq!(listed.len(), 2);
        let (split, _) = expect_split(route(&request, rig.primary(second.clone()), false).0);
        assert_eq!(split.key(), &Rig::second_key());
        assert!(listed.contains(split.pair()));
    }
    rig.publish(&records, Some(&Rig::key()));
    {
        // Pinned to the first pair: the second is never even ranked.
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let denied = expect_denied(route(&request, rig.primary(second), false).0);
        assert!(denied.reason.contains(NOT_CONNECTED), "{}", denied.reason);
        let primary = rig.primary(absent_binding());
        rig.secondary(&primary, &[("second", GroupPair::Split(Rig::second_key()))]);
        let denied = expect_denied(route(&request, primary, false).0);
        assert!(denied.reason.contains(NOT_CONNECTED), "{}", denied.reason);
        let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        assert_eq!(split.key(), &Rig::key());
    }
    assert!(rig.recorder.calls().is_empty());
}

#[test]
fn pinned_split_with_an_unplugged_side_denies_without_legacy() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(true);
    let unplugged = Guard::install(&Rig::cameras(Shape {
        ir_unit: false,
        ..WITH_ORDINARY
    }))
    .unwrap();
    let _admitted = unplugged.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .expect("the pin is retained while its pair is away");
        let selection = request.camera_selection.as_ref().unwrap();
        assert_eq!(selection.pending_pin(), Some(&Rig::key()));
        assert!(selection.view().split_pairs.is_empty());
        assert!(
            !request.may_select_account_camera(),
            "the advisory follows the pinned key"
        );
        for binding in [
            split_binding(),
            None,
            Some(CameraBinding::Ordinary {
                rgb: Some(ORDINARY_UNIT.into()),
                ir: Some(ORDINARY_UNIT.into()),
            }),
        ] {
            let denied = expect_denied(route(&request, rig.primary(binding), false).0);
            assert!(!denied.reason.contains(CLOSED), "{}", denied.reason);
        }
        assert!(installed_binding(&request).is_none());
    }
    assert!(unplugged.calls().is_empty());
    assert!(rig.recorder.calls().is_empty());
}

#[test]
fn an_external_split_side_refuses_ranking_install_and_the_grant_boundary() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(Shape {
        ir_fixed: false,
        ..SPLIT_ONLY
    });
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        // The external-camera setting: ranking skips the pair, no choice.
        std::env::set_var("IRLUME_FORBID_EXTERNAL_CAMERAS", "1");
        let denied = expect_denied(route(&request, rig.primary(split_binding()), false).0);
        assert!(
            denied.reason.contains("ExternalForbidden"),
            "{}",
            denied.reason
        );
        std::env::remove_var("IRLUME_FORBID_EXTERNAL_CAMERAS");
        // The legacy fixed-camera gate refuses at the install.
        let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        std::env::set_var("IRLUME_CAMERA_REQUIRE_FIXED", "1");
        let refused = request
            .select_account_split_camera(*split)
            .expect_err("an external side never installs");
        assert!(refused.to_string().contains("external side"), "{refused}");
        assert!(installed_binding(&request).is_none());
        assert_eq!(
            (request.rgb_dev.as_str(), request.ir_dev.as_str()),
            (STANDING_RGB, STANDING_IR)
        );
        std::env::remove_var("IRLUME_CAMERA_REQUIRE_FIXED");
        // Allowed at the install, forbidden before the open: C6 refuses.
        let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        request.select_account_split_camera(*split).unwrap();
        let operation = lease(&request, &[S_RGB, S_IR], Authentication).unwrap();
        assert!(request.pre_open_account_refusal().is_none());
        std::env::set_var("IRLUME_CAMERA_REQUIRE_FIXED", "1");
        let denied = request
            .pre_open_account_refusal()
            .expect("the late check refuses a now-forbidden side");
        assert!(!denied.granted && denied.reason.contains(LATE_REFUSAL));
        assert_eq!(denied.cause, Some(OutcomeCause::SetupUnavailable));
        assert!(request.split_grant_authority_refusal().is_some());
        assert!(request.validate_camera_request().is_err());
        drop(operation);
    }
    assert_eq!(rig.recorder.calls(), vec![split_lease(Authentication)]);
}

#[test]
fn revoked_or_superseded_split_authorization_denies_before_any_open() {
    let _env = env_guard();
    let mut shared = shared();
    for supersede in [false, true] {
        let rig = Rig::new(SPLIT_ONLY);
        rig.authorize(false);
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        let standing = Standing::new(&mut shared.engine);
        {
            let mut request = standing
                .engine
                .prepare_authentication_camera_request()
                .unwrap();
            let (split, scope) =
                expect_split(route(&request, rig.primary(split_binding()), false).0);
            request.select_account_split_camera(*split).unwrap();
            request.primary_attempt = Some(scope);
            let operation = lease(&request, &[S_RGB, S_IR], Authentication).unwrap();
            assert!(request.pre_open_account_refusal().is_none());
            assert!(request.split_grant_authority_refusal().is_none());
            if supersede {
                rig.authorize(false);
            } else {
                rig.revoke();
            }
            let denied = request
                .pre_open_account_refusal()
                .expect("changed machine authority refuses before the open");
            assert!(!denied.granted && !denied.live);
            assert!(denied.reason.contains(LATE_REFUSAL), "{}", denied.reason);
            assert_eq!(denied.cause, Some(OutcomeCause::SetupUnavailable));
            assert!(request.split_grant_authority_refusal().is_some());
            assert!(request.validate_camera_request().is_err());
            assert!(
                !rig.lock().exists(),
                "late split authority took the cameras.conf writer lock"
            );
            drop(operation);
        }
        assert_eq!(
            rig.recorder.calls(),
            vec![split_lease(Authentication)],
            "supersede={supersede}: no open after the refusal"
        );
    }
}

#[test]
fn authentication_split_authority_takes_no_config_lock_while_enrollment_keeps_it() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let _admitted = rig
        .recorder
        .admit_split_trust(&[Authentication, Enrollment]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let (split, scope) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        request.select_account_split_camera(*split).unwrap();
        request.primary_attempt = Some(scope);
        let operation = lease(&request, &[S_RGB, S_IR], Authentication).unwrap();
        request.validate_camera_request().unwrap();
        assert!(request.pre_open_account_refusal().is_none());
        assert!(request.split_grant_authority_refusal().is_none());
        assert!(
            !rig.lock().exists(),
            "the Authentication path created cameras.conf.lock"
        );
        // A writer holding the cameras.conf lock never blocks it either.
        let writer = Writer::hold(Duration::from_secs(10));
        request.validate_camera_request().unwrap();
        assert!(request.pre_open_account_refusal().is_none());
        assert!(request.split_grant_authority_refusal().is_none());
        assert!(
            writer.still_held(),
            "the Authentication path waited for the cameras.conf writer lock"
        );
        writer.release();
        drop(operation);
    }
    // Control: the Enrollment split keeps its locked canonical validation.
    let (guard, publication) = rig.displayed();
    {
        let _ = std::fs::remove_file(rig.lock());
        let mut request = standing
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        assert!(
            rig.lock().exists(),
            "split enrollment takes the writer lock"
        );
        request
            .enter_split_trust(SplitTrustEntry::Enrollment)
            .unwrap();
        let writer = Writer::hold(Duration::from_millis(750));
        request.validate_camera_request().unwrap();
        assert!(
            !writer.still_held(),
            "Enrollment validation must wait for the cameras.conf writer lock"
        );
        writer.release();
        request.leave_split_trust();
    }
    assert_eq!(rig.recorder.calls(), vec![split_lease(Authentication)]);
}

#[test]
fn a_pending_pin_keeps_every_non_routing_use_closed() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(true);
    let admitted = rig
        .recorder
        .admit_split_trust(&[Authentication, Enrollment]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        assert!(request
            .camera_selection
            .as_ref()
            .unwrap()
            .pending_pin()
            .is_some());
        // No ordinary route, publication, qualification or enrollment use.
        let ordinary = request
            .camera_selection
            .as_ref()
            .unwrap()
            .view()
            .ordinary
            .pairs[0]
            .clone();
        assert!(closed(request.select_account_camera(ordinary)));
        assert_eq!(
            (request.rgb_dev.as_str(), request.ir_dev.as_str()),
            (STANDING_RGB, STANDING_IR)
        );
        assert!(request.with_prepared_camera_publication(|| Ok(())).is_err());
        assert!(request.capture_qualification_for_request().is_err());
        assert!(closed(request.validate_enrollment_camera_activation()));
        assert!(closed(
            request.enter_split_trust(SplitTrustEntry::Enrollment)
        ));
        assert!(closed(
            request.enter_split_trust(SplitTrustEntry::Authentication)
        ));
        for (endpoints, kind) in [
            (&[S_RGB, S_IR][..], Diagnostics),
            (&[S_RGB][..], Authentication),
            (&[O_RGB, O_IR][..], Authentication),
            (&[STANDING_RGB][..], Enrollment),
        ] {
            assert_eq!(
                lease(&request, endpoints, kind).err(),
                Some(CameraLeaseError::SplitActivationDisabled),
                "{endpoints:?} {kind:?}"
            );
        }
        // Leaving the entry closes the pin itself, and routing cannot reopen it.
        request.leave_split_trust();
        assert!(closed(request.validate_camera_request()));
        assert!(refusal(request.prepare_camera_request()).contains(CLOSED));
        let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        assert!(closed(request.select_account_split_camera(*split)));
        assert!(installed_binding(&request).is_none());
    }
    {
        // An ended admission closes a pin and its routing.
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        drop(admitted);
        assert!(closed(request.validate_camera_request()));
        let denied = expect_denied(route(&request, rig.primary(split_binding()), false).0);
        assert_eq!(denied.reason, CLOSED);
    }
    {
        // A changed publication invalidates a pending pin before routing,
        // without the writer lock.
        let _again = rig.recorder.admit_split_trust(&[Authentication]);
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        request.validate_camera_request().unwrap();
        let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        rig.authorize(true);
        let changed = request.validate_camera_request().unwrap_err().to_string();
        assert!(changed.contains("split authorization changed"), "{changed}");
        assert!(request.select_account_split_camera(*split).is_err());
        assert!(!rig.lock().exists());
    }
    assert!(rig.recorder.calls().is_empty());
}

#[test]
fn a_lost_split_side_after_routing_refuses_validation_before_any_lease() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let (split, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        request.select_account_split_camera(*split).unwrap();
        // The IR side leaves after routing; the machine authority is unchanged
        // and the replacement inventory admits Authentication too.
        let unplugged = Guard::install(&Rig::cameras(Shape {
            ir_unit: false,
            ..SPLIT_ONLY
        }))
        .unwrap();
        let _replacement = unplugged.admit_split_trust(&[Authentication]);
        let refused = request.validate_camera_request().unwrap_err().to_string();
        assert!(refused.contains("no longer Current"), "{refused}");
        assert!(!rig.lock().exists());
        assert!(unplugged.calls().is_empty());
    }
    assert!(rig.recorder.calls().is_empty());
}

#[test]
fn a_split_choice_installs_only_into_the_request_that_built_it() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    let (split, _) = {
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        expect_split(route(&request, rig.primary(split_binding()), false).0)
    };
    // A later publication of the same pair is another authority.
    rig.authorize(false);
    {
        let mut request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        let refused = request
            .select_account_split_camera(*split)
            .expect_err("a choice never crosses requests");
        assert!(
            refused.to_string().contains("split authorization"),
            "{refused}"
        );
        assert!(installed_binding(&request).is_none());
        // Its own choice installs once; a second install is refused.
        let (own, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        let (again, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        request.select_account_split_camera(*own).unwrap();
        assert!(request.select_account_split_camera(*again).is_err());
        request.validate_camera_request().unwrap();
    }
    assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
    assert!(rig.recorder.calls().is_empty());
}

// Negative controls: GREEN from the stub on.

#[test]
fn closed_default_classified_routing_keeps_the_closed_refusal() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(WITH_ORDINARY);
    rig.authorize(false);
    let standing = Standing::new(&mut shared.engine);
    {
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        // A split primary: the closed text before any secondary load, so a
        // pending secondary intent is not recovered (plan D1, test 2450).
        let intent = plant_pending_intent();
        let (choice, unseals) = route(&request, rig.primary(split_binding()), false);
        assert_eq!(expect_denied(choice).reason, CLOSED);
        assert_eq!(unseals, 0);
        assert!(intent.exists() && !secondary_store_path(USER).exists());
        std::fs::remove_file(&intent).unwrap();
        // A ranked split secondary: the closed text, never a choice.
        let primary = rig.primary(absent_binding());
        rig.secondary(&primary, &[("split-desk", GroupPair::Split(Rig::key()))]);
        assert_eq!(
            expect_denied(route(&request, primary, false).0).reason,
            CLOSED
        );
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
        assert!(request.split_grant_authority_refusal().is_none());
        assert!(request.pre_open_account_refusal().is_none());
    }
    // A pinned split: every preparation refuses with the closed text.
    rig.authorize(true);
    assert!(refusal(standing.engine.prepare_authentication_camera_request()).contains(CLOSED));
    assert!(refusal(standing.engine.prepare_camera_request()).contains(CLOSED));
    assert!(standing.engine.camera_selection.is_none());
    assert!(rig.recorder.calls().is_empty());
}

#[test]
fn read_only_split_routing_and_readiness_create_no_config_lock() {
    let _env = env_guard();
    let mut shared = shared();
    let rig = Rig::new(SPLIT_ONLY);
    rig.authorize(false);
    let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
    let standing = Standing::new(&mut shared.engine);
    {
        let request = standing
            .engine
            .prepare_authentication_camera_request()
            .unwrap();
        // A readiness query never recovers a pending journal.
        plant_pending_intent();
        let _ = route(&request, rig.primary(split_binding()), true);
        let _ = request.ir_only_preflight_details(USER);
        assert!(installed_binding(&request).is_none());
    }
    let _ = standing.engine.ir_only_preflight_details(USER);
    assert!(
        !rig.lock().exists(),
        "read-only routing or readiness created cameras.conf.lock"
    );
    let intent = irlume_core::multi_camera::commit::intent_path_for(&secondary_store_path(USER));
    assert!(intent.exists() && !secondary_store_path(USER).exists());
    assert!(rig.recorder.calls().is_empty());
}

#[test]
fn ir_forced_off_refuses_the_split_install_without_reranking() {
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
        let primary = rig.primary(split_binding());
        rig.secondary(&primary, &[("ordinary-desk", ordinary_group())]);
        std::env::set_var("IRLUME_FORCE_NO_IR", "1");
        let (split, _) = expect_split(route(&request, primary, false).0);
        let refused = request
            .select_account_split_camera(*split)
            .expect_err("no RGB-only or convenience split authentication");
        assert!(
            refused.to_string().contains("IR is forced off"),
            "{refused}"
        );
        assert!(installed_binding(&request).is_none());
        assert_eq!(
            (request.rgb_dev.as_str(), request.ir_dev.as_str()),
            (STANDING_RGB, STANDING_IR)
        );
        // The same request ranks the same split again: nothing reranks onto
        // the ordinary secondary after the refusal.
        let (again, _) = expect_split(route(&request, rig.primary(split_binding()), false).0);
        assert_eq!(again.key(), &Rig::key());
    }
    assert!(rig.recorder.calls().is_empty());
}
