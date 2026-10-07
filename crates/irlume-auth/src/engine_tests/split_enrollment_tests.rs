// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The dedicated split enrollment entries (ADR-0032 Step 5; acceptance cases
//! 6, 9, 11, 12, 13 and 15): primary enrollment, reset and secondary
//! add-group on the original retained split choice of a prepared request.
//!
//! The camera fixture refuses every open, so a real split capture ends at
//! the RGB side. The capture-injection twins replace only the body of each
//! capture loop: the declared trust entry, the per-loop split Enrollment
//! lease, the binding rules and the real publishers run unchanged. No frame,
//! template or key here is biometric.

use super::*;
use irlume_camera::lease::CameraOperationKind;
use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
use irlume_common::split_key::SplitPairKey;
use irlume_common::split_schema::{AuthorizationRecord, SideFields};
use irlume_core::multi_camera::authz::{
    AuthorizationVia, EnrollmentAuthorization, EnrollmentOperation,
};
use irlume_core::multi_camera::GroupPair;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CLOSED: &str = "split enrollment and authentication are not enabled";
const IR_OFF: &str = "IR is unavailable or forced off";
const OTHER_CAMERA: &str = "belongs to another or unbound camera";
const RGB: &str = "/dev/irlume-split-enrollment-rgb";
const IR: &str = "/dev/irlume-split-enrollment-ir";
const USER: &str = "split-enrollment";
const PROFILE: &str = "Split Profile";
const KEY: &str = "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5";

/// A sandboxed state and config directory with a non-granting inventory:
/// two fixed single-endpoint USB devices (split) or one fixed RGB+IR unit.
struct Fixture {
    dir: PathBuf,
    saved: Vec<(&'static str, Option<OsString>)>,
    recorder: Guard,
    /// Every rig test takes the no-TPM plaintext branch: the dead
    /// `IRLUME_TCTI` cannot reach a TPM, and on a host with /dev/tpm* the
    /// device-node probe would otherwise force a seal onto it.
    _no_tpm: irlume_core::template_key::test_support::TpmPresence,
}

impl Fixture {
    fn new(split: bool) -> Self {
        let no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let dir = std::env::temp_dir().join(format!(
            "irlume-split-enrollment-{}-{:?}",
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
            "IRLUME_TEMPLATE_KEY_DIR",
            "IRLUME_GRACE_MS",
            "IRLUME_TCTI",
            "IRLUME_SEQUENTIAL_CAPTURE",
        ];
        let saved = keys
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", dir.join("private-template-keys"));
        // Publication may resolve a key. An explicit failed transport cannot
        // fall back to the host TPM.
        std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-test-tpm");
        for key in [
            "IRLUME_RGB_DEVICE",
            "IRLUME_IR_DEVICE",
            "IRLUME_FORCE_NO_IR",
            "IRLUME_CAMERA_REQUIRE_FIXED",
            "IRLUME_GRACE_MS",
            "IRLUME_SEQUENTIAL_CAPTURE",
        ] {
            std::env::remove_var(key);
        }
        let unit = |topology: &str, identity: &str, port: u8, endpoints| Camera {
            topology: topology.into(),
            identity: identity.into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
            endpoints,
        };
        let rgb = Endpoint {
            path: RGB.into(),
            formats: vec![*b"YUYV"],
        };
        let ir = Endpoint {
            path: IR.into(),
            formats: vec![*b"GREY"],
        };
        let cameras = if split {
            vec![
                unit(
                    "/devices/split-enrollment/rgb",
                    "1234:0001:rgb",
                    8,
                    vec![rgb],
                ),
                unit("/devices/split-enrollment/ir", "1234:0002:ir", 5, vec![ir]),
            ]
        } else {
            vec![unit(
                "/devices/split-enrollment/ordinary",
                "1234:0001:ordinary",
                8,
                vec![rgb, ir],
            )]
        };
        let recorder = Guard::install(&cameras).unwrap();
        Self {
            dir,
            saved,
            recorder,
            _no_tpm: no_tpm,
        }
    }

    /// Publish the one administrator-authorized split pair and return the
    /// displayed guard and publication the daemon hands to AUTH.
    fn choice(
        &self,
    ) -> (
        irlume_common::split_wire::SplitMutationGuard,
        irlume_common::split_publish::Published,
    ) {
        let side = |identity: &str, path: &str, port| SideFields {
            identity: identity.into(),
            path: path.into(),
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
        };
        let record = AuthorizationRecord {
            rgb: side("1234:0001:rgb", RGB, 8),
            ir: side("1234:0002:ir", IR, 5),
        };
        irlume_common::split_publish::publish_split(&[record], Some(&key())).unwrap();
        let snapshot = irlume_common::split_publish::read_camera_selection();
        let records = match snapshot.split() {
            irlume_common::split_publish::SplitReadState::Valid { records, .. } => records,
            state => panic!("fixture publication refused: {state:?}"),
        };
        let lease = irlume_camera::connected_pairs_with_split(records)
            .split_pairs
            .remove(0)
            .lease_request();
        let side = |expected: irlume_camera::SplitSideExpectation| {
            irlume_common::split_wire::SplitSideGuard {
                instance_id: expected.instance_id,
                generation: expected.generation,
                endpoint: expected.endpoint,
            }
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

    /// Withdraw every split authorization, as an administrator would.
    fn revoke() {
        irlume_common::split_publish::publish_split(&[], None).unwrap();
    }

    fn primary(&self) -> PathBuf {
        self.dir.join(format!("{USER}.json"))
    }

    /// Store a plaintext primary (what a no-TPM host keeps); returns its bytes.
    fn write_primary(&self, enrollment: &Enrollment) -> Vec<u8> {
        let bytes = serde_json::to_vec(enrollment).unwrap();
        std::fs::write(self.primary(), &bytes).unwrap();
        bytes
    }

    fn primary_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.primary()).ok()
    }

    fn stored(&self) -> Enrollment {
        irlume_core::storage::load_unmoved(USER)
            .unwrap()
            .expect("a published primary")
    }

    fn sealed_key(&self) -> PathBuf {
        self.dir
            .join("private-template-keys")
            .join(format!("{USER}.json"))
    }

    fn qualifications(&self) -> PathBuf {
        self.dir.join("capture-qualifications")
    }

    /// The live lease request of the authorized split pair, read now.
    fn expected(&self) -> irlume_camera::lease::SplitLeaseRequest {
        let snapshot = irlume_common::split_publish::read_camera_selection();
        let records = match snapshot.split() {
            irlume_common::split_publish::SplitReadState::Valid { records, .. } => records,
            state => panic!("fixture publication refused: {state:?}"),
        };
        irlume_camera::connected_pairs_with_split(records)
            .split_pairs
            .remove(0)
            .lease_request()
    }
}

impl Drop for Fixture {
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

/// Points the shared engine at the fixture endpoints and restores it on drop.
struct Devices<'a> {
    engine: &'a mut Engine,
    previous: (String, String, bool),
}

impl<'a> Devices<'a> {
    fn new(engine: &'a mut Engine) -> Self {
        let previous = devices(engine);
        engine.set_devices(RGB, IR);
        engine.ir_available = true;
        Self { engine, previous }
    }
}

impl Drop for Devices<'_> {
    fn drop(&mut self) {
        self.engine.rgb_dev = std::mem::take(&mut self.previous.0);
        self.engine.ir_dev = std::mem::take(&mut self.previous.1);
        self.engine.ir_available = self.previous.2;
    }
}

fn devices(engine: &Engine) -> (String, String, bool) {
    (
        engine.rgb_dev.clone(),
        engine.ir_dev.clone(),
        engine.ir_available,
    )
}

fn key() -> SplitPairKey {
    SplitPairKey::parse_canonical(KEY).unwrap()
}

fn split_binding() -> CameraBinding {
    CameraBinding::Split(key())
}

/// The same two devices on another IR port: a different complete key.
fn other_key() -> SplitPairKey {
    let mut other = key();
    other.ir.ports = vec![6];
    other
}

fn standing_binding() -> CameraBinding {
    CameraBinding::Ordinary {
        rgb: Some("standing-primary".into()),
        ir: Some("standing-primary".into()),
    }
}

fn lease_call() -> Call {
    Call::Lease {
        endpoints: vec![RGB.into(), IR.into()],
        kind: CameraOperationKind::Enrollment,
    }
}

/// A synthetic admitted scan; `unit512` vectors all match one person.
fn scan(seed: usize) -> CapturedScan {
    CapturedScan {
        rgb: unit512(seed),
        ir: Some(unit512(seed + 100)),
        center_edge_ratio: 1.3,
        brightness: 90.0,
        pitch: 0.5,
        ambient_share: None,
    }
}

fn scans(count: usize) -> irlume_common::Result<Vec<CapturedScan>> {
    Ok((1..=count).map(scan).collect())
}

/// A primary with one profile, with or without scans, under `binding`.
fn primary_with(binding: Option<CameraBinding>, with_scans: bool) -> Enrollment {
    let mut enrollment = Enrollment::new(USER);
    if with_scans {
        enrollment.profiles.push(FaceProfile {
            name: PROFILE.into(),
            scans: vec![scan512(1, true, None)],
            ir_calib: None,
            ir_calibs: Default::default(),
        });
    }
    enrollment.camera_binding = binding;
    enrollment
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The opaque group id the daemon derives for `pair` on an empty store.
fn group_id(pair: &GroupPair) -> String {
    let empty = irlume_core::multi_camera::SecondaryStore {
        format_version: irlume_core::multi_camera::SECONDARY_STORE_VERSION,
        owner: USER.into(),
        generation: 0,
        primary_snapshot_sha256: String::new(),
        groups: Vec::new(),
    };
    irlume_core::multi_camera::derive_group_id(&empty, pair.rgb_identity(), pair.ir_identity())
        .as_str()
        .to_owned()
}

fn authorization(operation: EnrollmentOperation) -> EnrollmentAuthorization {
    EnrollmentAuthorization::mint(
        USER.into(),
        operation,
        now_unix(),
        900,
        "split-enrollment".into(),
        AuthorizationVia::ElevatedPeer { uid: 0 },
    )
    .unwrap()
}

/// The daemon's add-group authorization for the retained split binding.
fn split_authorization() -> (String, EnrollmentAuthorization) {
    let pair = GroupPair::Split(key());
    let group = group_id(&pair);
    let operation = EnrollmentOperation::add_group(group.clone(), &pair);
    assert!(matches!(
        operation,
        EnrollmentOperation::AddSplitGroup { .. }
    ));
    (group, authorization(operation))
}

fn secondary() -> PathBuf {
    irlume_core::multi_camera::secondary_store_path(USER)
}

fn no_secondary_publication() -> bool {
    let path = secondary();
    !path.exists() && !irlume_core::multi_camera::commit::intent_path_for(&path).exists()
}

/// Every path below `dir` with its bytes; `None` marks a directory.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                out.insert(path.clone(), None);
                walk(&path, out);
            } else {
                let bytes = std::fs::read(&path).unwrap();
                out.insert(path, Some(bytes));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, &mut out);
    out
}

fn refusal<T>(result: irlume_common::Result<T>) -> String {
    match result {
        Ok(_) => panic!("a split enrollment entry succeeded where it must refuse"),
        Err(error) => error.to_string(),
    }
}

#[derive(Clone, Copy, Debug)]
enum Target {
    Enroll { replace: bool },
    AddGroup,
}

const TARGETS: [Target; 3] = [
    Target::Enroll { replace: false },
    Target::Enroll { replace: true },
    Target::AddGroup,
];

/// The primary each target starts from: a store already bound to this split
/// pair for enrollment, a standing ordinary primary for add-group.
fn target_primary(target: Target) -> Enrollment {
    match target {
        Target::Enroll { .. } => primary_with(Some(split_binding()), true),
        Target::AddGroup => primary_with(Some(standing_binding()), true),
    }
}

/// Run one entry through its capture-injection twin with `want` scans.
fn run_injected(
    engine: &mut Engine,
    target: Target,
    want: usize,
    authorization: &EnrollmentAuthorization,
    capture: impl FnMut(
        &mut Engine,
        usize,
        Option<f32>,
        &mut CaptureShape,
    ) -> irlume_common::Result<Vec<CapturedScan>>,
) -> irlume_common::Result<()> {
    match target {
        Target::Enroll { replace } => engine
            .enroll_split_prepared_with_capture(USER, None, want, replace, &(), capture)
            .map(|_| ()),
        Target::AddGroup => engine
            .add_split_camera_group_prepared_with_capture(
                USER,
                None,
                want,
                authorization,
                &(),
                capture,
            )
            .map(|_| ()),
    }
}

/// Run one entry through its production capture.
fn run_real(
    engine: &mut Engine,
    target: Target,
    authorization: &EnrollmentAuthorization,
) -> irlume_common::Result<()> {
    match target {
        Target::Enroll { replace } => engine
            .enroll_split_prepared(USER, None, 1, replace, &())
            .map(|_| ()),
        Target::AddGroup => engine
            .add_split_camera_group_prepared(USER, None, 1, authorization, &())
            .map(|_| ()),
    }
}

// RED: these need the real split entries (plan C8, D4).

#[test]
fn admitted_split_enroll_requests_one_enrollment_split_lease_then_attempts_rgb_only() {
    let _env = env_guard();
    let mut shared = shared();
    for target in TARGETS {
        let fixture = Fixture::new(true);
        let (guard, publication) = fixture.choice();
        let counts = fixture.recorder.lease_counts_observer();
        let _admitted = fixture
            .recorder
            .admit_split_trust(&[CameraOperationKind::Enrollment]);
        let before = fixture.write_primary(&target_primary(target));
        let (_, authorization) = split_authorization();
        let previous = devices(&shared.engine);
        {
            let mut request = shared
                .engine
                .prepare_split_enrollment_camera(&guard, &publication)
                .unwrap();
            let error = refusal(run_real(&mut request, target, &authorization));
            assert!(
                !error.contains(CLOSED),
                "{target:?}: the admitted entry must reach the camera: {error}"
            );
            assert_eq!(
                fixture.recorder.calls(),
                vec![lease_call(), Call::OpenRgb(RGB.into())],
                "{target:?}: one split Enrollment lease over both original sides, then \
                 the sequential RGB attempt only: no probe, no qualification read, no \
                 held pair and no IR open after the refused RGB side"
            );
            assert_eq!(counts(), (0, 0), "{target:?}: both reservations released");
            assert!(
                refusal(request.validate_camera_request()).contains(CLOSED),
                "{target:?}: the entry is left when it returns"
            );
        }
        assert_eq!(fixture.primary_bytes(), Some(before), "{target:?}");
        assert!(no_secondary_publication(), "{target:?}");
        assert!(!fixture.qualifications().exists(), "{target:?}");
        assert!(shared.engine.camera_selection.is_none());
        assert_eq!(devices(&shared.engine), previous);
    }
}

#[test]
fn injected_split_enrollment_publishes_the_prepared_split_binding() {
    let _env = env_guard();
    let mut shared = shared();
    for existing in ["absent", "empty and unbound", "bound to this pair"] {
        let fixture = Fixture::new(true);
        let (guard, publication) = fixture.choice();
        let counts = fixture.recorder.lease_counts_observer();
        let _admitted = fixture
            .recorder
            .admit_split_trust(&[CameraOperationKind::Enrollment]);
        match existing {
            "empty and unbound" => {
                fixture.write_primary(&Enrollment::new(USER));
            }
            "bound to this pair" => {
                fixture.write_primary(&primary_with(Some(split_binding()), true));
            }
            _ => {}
        }
        let mut loops = Vec::new();
        let outcome = {
            let mut request = shared
                .engine
                .prepare_split_enrollment_camera(&guard, &publication)
                .unwrap();
            let outcome = request
                .enroll_split_prepared_with_capture(
                    USER,
                    None,
                    2,
                    false,
                    &(),
                    |engine, count, _, _| {
                        // The loop's own split lease is held, and the declared
                        // entry still validates while it is.
                        assert_eq!(counts(), (2, 0), "{existing}: both sides reserved");
                        engine
                            .validate_camera_request()
                            .expect("the declared entry validates under its lease");
                        loops.push(count);
                        scans(count)
                    },
                )
                .unwrap_or_else(|error| panic!("{existing}: {error}"));
            assert!(refusal(request.validate_camera_request()).contains(CLOSED));
            outcome
        };
        assert_eq!(
            loops,
            vec![1, 1],
            "{existing}: a 1-scan probe, then the top-up"
        );
        assert_eq!(
            fixture.recorder.calls(),
            vec![lease_call(), lease_call()],
            "{existing}: one split Enrollment lease per capture loop, no open"
        );
        assert_eq!(counts(), (0, 0));
        let stored = fixture.stored();
        assert_eq!(stored.camera_binding, Some(split_binding()), "{existing}");
        match existing {
            "bound to this pair" => {
                assert!(
                    matches!(
                        outcome,
                        EnrollOutcome::Merged {
                            added: 2,
                            total: 3,
                            ..
                        }
                    ),
                    "{outcome:?}"
                );
                assert_eq!(stored.profiles.len(), 1);
            }
            _ => {
                assert!(
                    matches!(outcome, EnrollOutcome::New { scans: 2, .. }),
                    "{outcome:?}"
                );
                assert_eq!(stored.profiles.len(), 1);
                assert_eq!(stored.profiles[0].scans.len(), 2);
            }
        }
        assert!(no_secondary_publication());
        assert!(shared.engine.camera_selection.is_none());
    }
}

#[test]
fn injected_split_reset_replaces_the_binding_and_keeps_the_template_key() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let _admitted = fixture
        .recorder
        .admit_split_trust(&[CameraOperationKind::Enrollment]);
    let mut old = primary_with(Some(CameraBinding::Split(other_key())), true);
    old.profiles[0].name = "Old Profile".into();
    fixture.write_primary(&old);
    let keys = fixture.dir.join("private-template-keys");
    assert!(!fixture.sealed_key().exists());
    {
        let mut request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        let outcome = request
            .enroll_split_prepared_with_capture(
                USER,
                Some("Reset Profile".into()),
                1,
                true,
                &(),
                |_, count, _, _| scans(count),
            )
            .expect("a complete injected reset publishes");
        assert!(
            matches!(&outcome, EnrollOutcome::New { name, scans: 1, .. } if name == "Reset Profile"),
            "{outcome:?}"
        );
    }
    let stored = fixture.stored();
    assert_eq!(stored.camera_binding, Some(split_binding()));
    assert_eq!(stored.profiles.len(), 1, "a reset keeps no old profile");
    assert_eq!(stored.profiles[0].name, "Reset Profile");
    assert!(
        !fixture.sealed_key().exists(),
        "a keyless reset on a host without a TPM seals no key"
    );
    // A reset never mints a replacement key or falls back to plaintext: with
    // a sealed key it cannot unseal it refuses, keeping the key and the bytes.
    let published = fixture.primary_bytes().unwrap();
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(fixture.sealed_key(), b"not a sealed template key").unwrap();
    {
        let mut request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        let error = refusal(request.enroll_split_prepared_with_capture(
            USER,
            Some("Second Reset".into()),
            1,
            true,
            &(),
            |_, count, _, _| scans(count),
        ));
        assert!(!error.contains(CLOSED), "{error}");
    }
    assert_eq!(
        std::fs::read(fixture.sealed_key()).unwrap(),
        b"not a sealed template key"
    );
    assert_eq!(fixture.primary_bytes(), Some(published));
    assert_eq!(fixture.recorder.calls(), vec![lease_call(), lease_call()]);
    assert_eq!(fixture.recorder.lease_counts_observer()(), (0, 0));
}

#[test]
fn injected_split_nonreset_refuses_another_binding_and_an_empty_but_bound_store() {
    let _env = env_guard();
    let mut shared = shared();
    let ordinary_ids = CameraBinding::Ordinary {
        rgb: Some("1234:0001:rgb".into()),
        ir: Some("1234:0002:ir".into()),
    };
    for (store, binding, with_scans) in [
        (
            "another split key",
            Some(CameraBinding::Split(other_key())),
            true,
        ),
        (
            "empty but bound to another split key",
            Some(CameraBinding::Split(other_key())),
            false,
        ),
        (
            "empty but ordinary bound to the same identities",
            Some(ordinary_ids),
            false,
        ),
        ("unbound with scans", None, true),
    ] {
        let fixture = Fixture::new(true);
        let (guard, publication) = fixture.choice();
        let _admitted = fixture
            .recorder
            .admit_split_trust(&[CameraOperationKind::Enrollment]);
        let before = fixture.write_primary(&primary_with(binding, with_scans));
        let captured = Cell::new(0);
        {
            let mut request = shared
                .engine
                .prepare_split_enrollment_camera(&guard, &publication)
                .unwrap();
            let error = refusal(request.enroll_split_prepared_with_capture(
                USER,
                None,
                1,
                false,
                &(),
                |_, count, _, _| {
                    captured.set(captured.get() + 1);
                    scans(count)
                },
            ));
            assert!(error.contains(OTHER_CAMERA), "{store}: {error}");
            assert_eq!(captured.get(), 0, "{store}: refused before capture");
            assert!(
                fixture.recorder.calls().is_empty(),
                "{store}: refused before any lease: {:?}",
                fixture.recorder.calls()
            );
            assert_eq!(fixture.primary_bytes(), Some(before), "{store}");
            // Control: the same store accepts this pair only by an explicit reset.
            request
                .enroll_split_prepared_with_capture(USER, None, 1, true, &(), |_, count, _, _| {
                    scans(count)
                })
                .unwrap_or_else(|error| panic!("{store}: {error}"));
        }
        assert_eq!(fixture.stored().camera_binding, Some(split_binding()));
        assert_eq!(fixture.recorder.calls(), vec![lease_call()], "{store}");
    }
}

#[test]
fn injected_split_add_group_publishes_the_split_key_under_its_split_scope() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let counts = fixture.recorder.lease_counts_observer();
    let _admitted = fixture
        .recorder
        .admit_split_trust(&[CameraOperationKind::Enrollment]);
    let before = fixture.write_primary(&primary_with(Some(standing_binding()), true));
    let (group, authorization) = split_authorization();
    let published = {
        let mut request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        request
            .add_split_camera_group_prepared_with_capture(
                USER,
                None,
                1,
                &authorization,
                &(),
                |engine, count, _, _| {
                    assert_eq!(counts(), (2, 0), "both sides reserved");
                    engine
                        .validate_camera_request()
                        .expect("the declared entry validates under its lease");
                    scans(count)
                },
            )
            .expect("a complete injected split group publishes")
    };
    assert_eq!(published, group);
    let store = irlume_core::multi_camera::load_secondary(&secondary())
        .unwrap()
        .expect("a published secondary store");
    assert_eq!(store.generation, 1);
    assert_eq!(store.groups.len(), 1);
    assert_eq!(store.groups[0].id.as_str(), group);
    assert_eq!(store.groups[0].pair, split_binding(), "the whole split key");
    assert_eq!(store.groups[0].profiles[0].profile, PROFILE);
    assert!(!irlume_core::multi_camera::commit::intent_path_for(&secondary()).exists());
    assert_eq!(
        fixture.primary_bytes(),
        Some(before),
        "the primary is untouched"
    );
    assert_eq!(fixture.recorder.calls(), vec![lease_call()]);
    assert_eq!(counts(), (0, 0));
}

#[test]
fn split_add_group_refuses_an_authorization_of_any_other_scope() {
    let _env = env_guard();
    let mut shared = shared();
    let (group, _) = split_authorization();
    for (scope, operation) in [
        (
            "ordinary pair with the same identities",
            EnrollmentOperation::add_group(
                group.clone(),
                &GroupPair::Ordinary {
                    rgb: Some("1234:0001:rgb".into()),
                    ir: Some("1234:0002:ir".into()),
                },
            ),
        ),
        (
            "another split key",
            EnrollmentOperation::add_group(group.clone(), &GroupPair::Split(other_key())),
        ),
        (
            "another group",
            EnrollmentOperation::add_group("another-group".into(), &GroupPair::Split(key())),
        ),
    ] {
        let fixture = Fixture::new(true);
        let (guard, publication) = fixture.choice();
        let _admitted = fixture
            .recorder
            .admit_split_trust(&[CameraOperationKind::Enrollment]);
        let before = fixture.write_primary(&primary_with(Some(standing_binding()), true));
        let authorization = authorization(operation);
        let captured = Cell::new(0);
        {
            let mut request = shared
                .engine
                .prepare_split_enrollment_camera(&guard, &publication)
                .unwrap();
            let error = refusal(request.add_split_camera_group_prepared_with_capture(
                USER,
                None,
                1,
                &authorization,
                &(),
                |_, count, _, _| {
                    captured.set(captured.get() + 1);
                    scans(count)
                },
            ));
            assert!(!error.contains(CLOSED), "{scope}: {error}");
        }
        assert_eq!(captured.get(), 0, "{scope}: refused before capture");
        assert!(fixture.recorder.calls().is_empty(), "{scope}");
        assert!(no_secondary_publication(), "{scope}");
        assert_eq!(fixture.primary_bytes(), Some(before), "{scope}");
    }
}

#[test]
fn split_revocation_or_side_change_between_capture_and_publish_keeps_the_old_bytes() {
    let _env = env_guard();
    let mut shared = shared();
    for change in ["revocation", "rgb side", "ir side"] {
        for target in TARGETS {
            let fixture = Fixture::new(true);
            let (guard, publication) = fixture.choice();
            let counts = fixture.recorder.lease_counts_observer();
            let _admitted = fixture
                .recorder
                .admit_split_trust(&[CameraOperationKind::Enrollment]);
            let before = fixture.write_primary(&target_primary(target));
            let (_, authorization) = split_authorization();
            let rgb_lost = fixture.recorder.endpoint_invalidation_observer(RGB);
            let ir_lost = fixture.recorder.endpoint_invalidation_observer(IR);
            let error = {
                let mut request = shared
                    .engine
                    .prepare_split_enrollment_camera(&guard, &publication)
                    .unwrap();
                refusal(run_injected(
                    &mut request,
                    target,
                    1,
                    &authorization,
                    |_, count, _, _| {
                        // A complete capture, then the change before publication.
                        match change {
                            "revocation" => Fixture::revoke(),
                            "rgb side" => rgb_lost(),
                            _ => ir_lost(),
                        }
                        scans(count)
                    },
                ))
            };
            assert!(!error.contains(CLOSED), "{change} {target:?}: {error}");
            assert_eq!(
                fixture.primary_bytes(),
                Some(before),
                "{change} {target:?}: nothing published and a reset keeps the old bytes"
            );
            assert!(no_secondary_publication(), "{change} {target:?}");
            assert_eq!(
                fixture.recorder.calls(),
                vec![lease_call()],
                "{change} {target:?}"
            );
            assert_eq!(counts(), (0, 0), "{change} {target:?}");
        }
    }
}

#[test]
fn split_side_loss_between_probe_and_top_up_refuses_before_the_next_lease() {
    let _env = env_guard();
    let mut shared = shared();
    for side in [RGB, IR] {
        for target in TARGETS {
            let fixture = Fixture::new(true);
            let (guard, publication) = fixture.choice();
            let counts = fixture.recorder.lease_counts_observer();
            let _admitted = fixture
                .recorder
                .admit_split_trust(&[CameraOperationKind::Enrollment]);
            let before = fixture.write_primary(&target_primary(target));
            // A reset starts from no profile, so a 2-scan reset tops up too.
            let (_, authorization) = split_authorization();
            let lost = fixture.recorder.endpoint_invalidation_observer(side);
            let mut loops = 0;
            let error = {
                let mut request = shared
                    .engine
                    .prepare_split_enrollment_camera(&guard, &publication)
                    .unwrap();
                refusal(run_injected(
                    &mut request,
                    target,
                    2,
                    &authorization,
                    |_, count, _, _| {
                        loops += 1;
                        if loops == 1 {
                            lost();
                        }
                        scans(count)
                    },
                ))
            };
            assert!(!error.contains(CLOSED), "{side} {target:?}: {error}");
            assert_eq!(loops, 1, "{side} {target:?}: the top-up never captures");
            assert_eq!(
                fixture.recorder.calls(),
                vec![lease_call()],
                "{side} {target:?}: the lost side gets no second lease or open"
            );
            assert_eq!(counts(), (0, 0));
            assert_eq!(fixture.primary_bytes(), Some(before), "{side} {target:?}");
            assert!(no_secondary_publication(), "{side} {target:?}");
        }
    }
}

#[test]
fn split_revocation_during_a_registered_lease_wait_refuses_before_any_open() {
    let _env = env_guard();
    let mut shared = shared();
    for target in TARGETS {
        let fixture = Fixture::new(true);
        let (guard, publication) = fixture.choice();
        let counts = fixture.recorder.lease_counts_observer();
        let _admitted = fixture
            .recorder
            .admit_split_trust(&[CameraOperationKind::Enrollment]);
        let before = fixture.write_primary(&target_primary(target));
        let (_, authorization) = split_authorization();
        let expected = fixture.expected();
        let mut request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        // Another holder owns both sides until the entry's waiter registers;
        // the administrator then revokes and the holder releases.
        let held = irlume_camera::lease::acquire_split_camera_operation(
            &expected,
            CameraOperationKind::Diagnostics,
            Duration::ZERO,
        )
        .unwrap();
        let waiting = fixture.recorder.lease_counts_observer();
        let error = std::thread::scope(|threads| {
            let writer = threads.spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                while waiting().1 == 0 {
                    assert!(
                        Instant::now() < deadline,
                        "the split Enrollment waiter never registered"
                    );
                    std::thread::yield_now();
                }
                Fixture::revoke();
                drop(held);
            });
            let error = refusal(run_real(&mut request, target, &authorization));
            writer.join().unwrap();
            error
        });
        drop(request);
        assert!(!error.contains(CLOSED), "{target:?}: {error}");
        assert_eq!(
            fixture.recorder.calls(),
            vec![
                Call::Lease {
                    endpoints: vec![RGB.into(), IR.into()],
                    kind: CameraOperationKind::Diagnostics,
                },
                lease_call(),
            ],
            "{target:?}: the waited lease confers no configuration authority, and the \
             revalidation under it refuses before any open"
        );
        assert_eq!(counts(), (0, 0), "{target:?}");
        assert_eq!(fixture.primary_bytes(), Some(before), "{target:?}");
        assert!(no_secondary_publication(), "{target:?}");
    }
}

#[test]
fn split_enrollment_refuses_without_ir_before_any_lease() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let _admitted = fixture
        .recorder
        .admit_split_trust(&[CameraOperationKind::Enrollment]);
    fixture.write_primary(&primary_with(Some(standing_binding()), true));
    let (_, authorization) = split_authorization();
    std::env::set_var("IRLUME_FORCE_NO_IR", "1");
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    assert!(!request.ir_available);
    let before = snapshot(&fixture.dir);
    for target in TARGETS {
        let error = refusal(run_real(&mut request, target, &authorization));
        assert!(error.contains(IR_OFF), "{target:?}: {error}");
        let captured = Cell::new(0);
        let error = refusal(run_injected(
            &mut request,
            target,
            1,
            &authorization,
            |_, count, _, _| {
                captured.set(captured.get() + 1);
                scans(count)
            },
        ));
        assert!(error.contains(IR_OFF), "{target:?}: {error}");
        assert_eq!(captured.get(), 0, "{target:?}");
    }
    drop(request);
    assert!(
        fixture.recorder.calls().is_empty(),
        "no RGB-only or convenience split enrollment: {:?}",
        fixture.recorder.calls()
    );
    assert_eq!(snapshot(&fixture.dir), before);
}

#[test]
fn split_enrollment_never_opens_a_held_pair_under_a_concurrent_override() {
    let _env = env_guard();
    let mut shared = shared();
    for value in ["0", "1"] {
        for target in TARGETS {
            let fixture = Fixture::new(true);
            let (guard, publication) = fixture.choice();
            let _admitted = fixture
                .recorder
                .admit_split_trust(&[CameraOperationKind::Enrollment]);
            fixture.write_primary(&target_primary(target));
            let (_, authorization) = split_authorization();
            // "0" is the operator's explicit concurrent schedule.
            std::env::set_var("IRLUME_SEQUENTIAL_CAPTURE", value);
            {
                let mut request = shared
                    .engine
                    .prepare_split_enrollment_camera(&guard, &publication)
                    .unwrap();
                let error = refusal(run_real(&mut request, target, &authorization));
                assert!(!error.contains(CLOSED), "{value} {target:?}: {error}");
            }
            let calls = fixture.recorder.calls();
            assert_eq!(
                calls,
                vec![lease_call(), Call::OpenRgb(RGB.into())],
                "IRLUME_SEQUENTIAL_CAPTURE={value} {target:?}: no dual or held open"
            );
            assert!(!calls.contains(&Call::OpenIr(IR.into())));
            assert!(!fixture.qualifications().exists(), "{value} {target:?}");
        }
    }
}

#[test]
fn split_entries_leave_the_declared_entry_on_every_exit() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let counts = fixture.recorder.lease_counts_observer();
    let _admitted = fixture
        .recorder
        .admit_split_trust(&[CameraOperationKind::Enrollment]);
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    // An error exit, twice on one scope: each call declares its entry anew.
    for _ in 0..2 {
        let error = refusal(request.enroll_split_prepared(USER, None, 1, false, &()));
        assert!(!error.contains(CLOSED), "{error}");
        assert!(refusal(request.validate_camera_request()).contains(CLOSED));
    }
    // An unwind with the split lease held.
    let unwound = std::panic::catch_unwind(AssertUnwindSafe(|| {
        request.enroll_split_prepared_with_capture(USER, None, 1, false, &(), |_, _, _, _| {
            panic!("synthetic unwind inside split enrollment capture")
        })
    }));
    assert!(unwound.is_err());
    assert_eq!(counts(), (0, 0));
    assert!(refusal(request.validate_camera_request()).contains(CLOSED));
    // A published exit.
    request
        .enroll_split_prepared_with_capture(USER, None, 1, false, &(), |_, count, _, _| {
            scans(count)
        })
        .expect("a complete injected split capture publishes");
    assert!(refusal(request.validate_camera_request()).contains(CLOSED));
    // The public ordinary entries stay closed on the same scope afterwards.
    let preflight = Cell::new(0);
    let error = refusal(
        request.enroll_profile_with_ir_preflight(USER, None, 1, |_| {
            preflight.set(preflight.get() + 1);
            true
        }),
    );
    assert!(error.contains(CLOSED), "{error}");
    assert_eq!(preflight.get(), 0);
    drop(request);
    assert_eq!(
        fixture.recorder.calls(),
        vec![
            lease_call(),
            Call::OpenRgb(RGB.into()),
            lease_call(),
            Call::OpenRgb(RGB.into()),
            lease_call(),
            lease_call(),
        ]
    );
    assert_eq!(fixture.stored().camera_binding, Some(split_binding()));
    assert!(shared.engine.camera_selection.is_none());
}

// Negative controls: GREEN from the stubs on.

#[test]
fn split_entries_stay_closed_without_enrollment_admission() {
    let _env = env_guard();
    let mut shared = shared();
    let admissions: [&[CameraOperationKind]; 2] = [&[], &[CameraOperationKind::Authentication]];
    for admitted in admissions {
        let fixture = Fixture::new(true);
        let (guard, publication) = fixture.choice();
        let _token = fixture.recorder.admit_split_trust(admitted);
        fixture.write_primary(&primary_with(Some(split_binding()), true));
        let (_, authorization) = split_authorization();
        let mut request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        let before = snapshot(&fixture.dir);
        let captured = Cell::new(0);
        for target in TARGETS {
            assert!(
                refusal(run_real(&mut request, target, &authorization)).contains(CLOSED),
                "{admitted:?} {target:?}"
            );
            let error = refusal(run_injected(
                &mut request,
                target,
                1,
                &authorization,
                |_, count, _, _| {
                    captured.set(captured.get() + 1);
                    scans(count)
                },
            ));
            assert!(error.contains(CLOSED), "{admitted:?} {target:?}: {error}");
        }
        drop(request);
        assert_eq!(captured.get(), 0);
        assert!(fixture.recorder.calls().is_empty(), "{admitted:?}");
        assert_eq!(snapshot(&fixture.dir), before, "{admitted:?}");
    }
}

#[test]
fn split_entries_refuse_closed_on_an_ordinary_or_absent_scope() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let _admitted = fixture
        .recorder
        .admit_split_trust(&[CameraOperationKind::Enrollment]);
    fixture.write_primary(&primary_with(Some(split_binding()), true));
    let (_, authorization) = split_authorization();
    let standing = Devices::new(&mut shared.engine);
    drop(standing.engine.prepare_camera_request().unwrap());
    let before = snapshot(&fixture.dir);
    let captured = Cell::new(0);
    for target in TARGETS {
        assert!(standing.engine.camera_selection.is_none());
        assert!(refusal(run_real(standing.engine, target, &authorization)).contains(CLOSED));
        {
            let mut request = standing.engine.prepare_camera_request().unwrap();
            assert!(request.camera_selection.is_some());
            assert!(refusal(run_real(&mut request, target, &authorization)).contains(CLOSED));
            let error = refusal(run_injected(
                &mut request,
                target,
                1,
                &authorization,
                |_, count, _, _| {
                    captured.set(captured.get() + 1);
                    scans(count)
                },
            ));
            assert!(error.contains(CLOSED), "{target:?}: {error}");
        }
    }
    drop(standing);
    assert_eq!(captured.get(), 0);
    assert!(fixture.recorder.calls().is_empty());
    assert_eq!(snapshot(&fixture.dir), before);
}

#[test]
fn split_runtime_keeps_the_split_route_off_every_ordinary_lowering() {
    let runtime = include_str!("../split_runtime.rs");
    let production = runtime
        .split("\n#[cfg(test)]\n")
        .next()
        .expect("split runtime source");
    assert!(
        production.contains("pub fn enroll_split_prepared(")
            && production.contains("pub fn add_split_camera_group_prepared("),
        "the scan must read the production entries"
    );
    for required in [
        "enter_split_trust(SplitTrustEntry::Enrollment)",
        "leave_split_trust()",
        "self.capture_scan_loop(",
        "use_ir: true,",
        "CameraOperationKind::Enrollment",
    ] {
        assert!(
            production.contains(required),
            "the split route lost `{required}`"
        );
    }
    for forbidden in [
        "dark_ir_rgb_only_enrollment_refusal",
        "capture_qualification_for_request",
        "capture_mode_selection_with_diagnostics",
        "capture_mode_selection_for_request",
        "maybe_switch_capture_mode_from_enrolment",
        "solo_rgb_starvation_probe",
        "capture_scans_observed",
        "assess_with_fresh_pair",
        ".open_rgb(",
        ".open_ir(",
        "dispatch_after_authorization",
        "EnrollmentRoute::Ordinary",
        "split_pair:",
        "rgb_primary_grant_admissible",
        "CameraOperationKind::Diagnostics",
    ] {
        assert!(
            !production.contains(forbidden),
            "the split route must not reach `{forbidden}`"
        );
    }
    let lib = include_str!("../lib.rs");
    let registrations = lib
        .split_once("mod engine_tests {")
        .and_then(|(_, rest)| rest.split_once("\n    use "))
        .map(|(registrations, _)| registrations)
        .expect("engine test registrations precede the first use");
    for line in [
        "    mod split_enrollment_tests;",
        "    mod split_routing_tests;",
    ] {
        assert_eq!(
            registrations.lines().filter(|text| *text == line).count(),
            1,
            "{line} must stay registered"
        );
    }
}
