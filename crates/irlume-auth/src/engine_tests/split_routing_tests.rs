// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The split trust entry, the AUTH activation gate and the split acquisition
//! arm of a retained split scope (ADR-0032 acceptance cases 12, 13 and 15).
//!
//! The camera fixture refuses every open. Its thread-local admission is the
//! only way a split trust kind opens in a test build; production keeps the
//! predicate closed, which the frozen closed-default tests cover.

mod split_account_routing_tests;
mod split_trust_entry_tests;
use super::*;
use crate::request_preparation::SplitTrustEntry;
use irlume_camera::lease::{CameraLeaseError, CameraOperationKind, CameraOperationSession};
use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
use irlume_common::split_schema::{AuthorizationRecord, SideFields};
use std::{cell::Cell, ffi::OsString, path::PathBuf, time::Duration};

use irlume_camera::lease::CameraOperationKind::{
    Authentication, Capture, Diagnostics, Enrollment, Preview, Setup,
};

const CLOSED: &str = "split enrollment and authentication are not enabled";
/// The production refusal text, referenced rather than copied so a wording
/// change cannot leave these expectations stale.
pub(super) const ORDINARY: &str = crate::request_preparation::ORDINARY_PATH_SPLIT_REFUSAL;
const RGB: &str = "/dev/irlume-split-routing-rgb";
const IR: &str = "/dev/irlume-split-routing-ir";
const SPLIT_KEY: &str = "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5";
const WAIT: Duration = Duration::from_secs(2);

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
    /// A sandboxed state/config directory and a non-granting inventory: two
    /// fixed single-endpoint USB devices (split) or one fixed RGB+IR unit.
    fn new(split: bool) -> Self {
        let no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let dir = std::env::temp_dir().join(format!(
            "irlume-split-routing-{}-{:?}",
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
            "IRLUME_GRACE_MS",
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
                unit("/devices/split-routing/rgb", "1234:0001:rgb", 8, vec![rgb]),
                unit("/devices/split-routing/ir", "1234:0002:ir", 5, vec![ir]),
            ]
        } else {
            vec![unit(
                "/devices/split-routing/ordinary",
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
    /// displayed guard and publication a daemon would hand to AUTH.
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
        let key = irlume_common::split_key::SplitPairKey::parse_canonical(SPLIT_KEY).unwrap();
        irlume_common::split_publish::publish_split(&[record], Some(&key)).unwrap();
        let snapshot = irlume_common::split_publish::read_camera_selection();
        let records = match snapshot.split() {
            irlume_common::split_publish::SplitReadState::Valid { records, .. } => records,
            state => panic!("fixture publication refused: {state:?}"),
        };
        let pair = irlume_camera::connected_pairs_with_split(records)
            .split_pairs
            .remove(0);
        let lease = pair.lease_request();
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

    fn qualification_dir(&self) -> PathBuf {
        self.dir.join("capture-qualifications")
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
        let previous = (
            engine.rgb_dev.clone(),
            engine.ir_dev.clone(),
            engine.ir_available,
        );
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

fn lease_call(kind: CameraOperationKind) -> Call {
    Call::Lease {
        endpoints: vec![RGB.into(), IR.into()],
        kind,
    }
}

fn acquire(
    engine: &Engine,
    endpoints: &[&str],
    kind: CameraOperationKind,
) -> Result<CameraOperationSession, CameraLeaseError> {
    engine.acquire_account_camera(endpoints, kind, WAIT)
}

fn closed(result: irlume_common::Result<()>) -> bool {
    result.is_err_and(|error| error.to_string().contains(CLOSED))
}

fn refusal<T>(result: irlume_common::Result<T>) -> String {
    match result {
        Ok(_) => panic!("a split scope admitted an entry it must refuse"),
        Err(error) => error.to_string(),
    }
}

// RED: these need the declared split trust entry and the split acquisition arm.

#[test]
fn admitted_split_enrollment_scope_acquires_one_split_lease_over_both_sides() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let counts = fixture.recorder.lease_counts_observer();
    let _admitted = fixture.recorder.admit_split_trust(&[Enrollment]);
    {
        let mut request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        // Admission alone opens no trust use: the running entry must be declared.
        assert!(closed(request.validate_camera_request()));
        request
            .enter_split_trust(SplitTrustEntry::Enrollment)
            .expect("the admitted Enrollment entry is declared on its own split");
        request
            .validate_camera_request()
            .expect("a declared admitted entry validates its retained split");
        let operation = acquire(&request, &[RGB, IR], Enrollment)
            .expect("one split Enrollment lease over both original sides");
        assert!(operation.lease().is_split_pair());
        assert_eq!(operation.lease().operation(), Enrollment);
        assert_eq!(counts(), (2, 0), "one permit reserves both incarnations");
        irlume_camera::test_support::capture_uniform_split_pair(&operation, RGB, IR)
            .expect("the AUTH lease covers both original sides, RGB then IR");
        drop(operation);
        assert_eq!(counts(), (0, 0));
        assert_eq!(
            fixture.recorder.calls(),
            vec![lease_call(Enrollment)],
            "exactly one split lease and no ordinary or single-side lease"
        );
        // Leaving the entry closes every split use again, in AUTH, before the
        // camera boundary records a lease attempt.
        request.leave_split_trust();
        assert!(closed(request.validate_camera_request()));
        assert_eq!(
            acquire(&request, &[RGB, IR], Enrollment).err(),
            Some(CameraLeaseError::SplitActivationDisabled)
        );
        assert_eq!(fixture.recorder.calls(), vec![lease_call(Enrollment)]);
        request
            .enter_split_trust(SplitTrustEntry::Enrollment)
            .expect("the same scope may declare its entry again");
    }
    // Scope drop clears the declared entry with the whole retained selection.
    assert!(shared.engine.camera_selection.is_none());
    let request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    assert!(closed(request.validate_camera_request()));
    assert_eq!(
        acquire(&request, &[RGB, IR], Enrollment).err(),
        Some(CameraLeaseError::SplitActivationDisabled)
    );
    drop(request);
    assert_eq!(fixture.recorder.calls(), vec![lease_call(Enrollment)]);
    assert_eq!(counts(), (0, 0));
}

#[test]
fn split_scope_refuses_single_side_and_diagnostics_acquisition() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let counts = fixture.recorder.lease_counts_observer();
    let _admitted = fixture
        .recorder
        .admit_split_trust(&[Enrollment, Authentication]);
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    for declared in [false, true] {
        if declared {
            request
                .enter_split_trust(SplitTrustEntry::Enrollment)
                .expect("the admitted Enrollment entry is declared");
        }
        // Single sides, swapped or repeated sides, the starvation probe and
        // capture-mode shapes, and every kind but the declared entry's own.
        let attempts: [(&[&str], CameraOperationKind); 13] = [
            (&[RGB], Enrollment),
            (&[IR], Enrollment),
            (&[IR, RGB], Enrollment),
            (&[RGB, IR, RGB], Enrollment),
            (&[], Enrollment),
            (&[RGB], Diagnostics),
            (&[RGB, IR], Diagnostics),
            (&[RGB, IR], Authentication),
            (&[RGB, IR], Capture),
            (&[RGB, IR], Preview),
            (&[RGB, IR], Setup),
            (&[RGB], Authentication),
            (&[IR], Diagnostics),
        ];
        for (endpoints, kind) in attempts {
            let refused = acquire(&request, endpoints, kind).err();
            let expected_kind = !declared || kind != Enrollment;
            match refused {
                Some(CameraLeaseError::SplitActivationDisabled) if expected_kind => {}
                Some(CameraLeaseError::InvalidEndpoint(_)) if !expected_kind => {}
                other => panic!(
                    "declared={declared} {endpoints:?} {kind:?} reached {other:?}; a split \
                     selection must never get a single-side, legacy or other-kind lease"
                ),
            }
            assert_eq!(
                counts(),
                (0, 0),
                "declared={declared} {endpoints:?} {kind:?}"
            );
        }
    }
    drop(request);
    assert!(
        fixture.recorder.calls().is_empty(),
        "every refusal precedes the camera boundary: {:?}",
        fixture.recorder.calls()
    );
}

#[test]
fn admitted_split_enrollment_activation_follows_the_prepared_entry() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let admissions: [&[CameraOperationKind]; 4] = [
        &[],
        &[Authentication],
        &[Enrollment],
        &[Enrollment, Authentication],
    ];
    for admitted in admissions {
        let _token = fixture.recorder.admit_split_trust(admitted);
        let request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        let activation = request.validate_enrollment_camera_activation();
        if admitted.contains(&Enrollment) {
            assert!(
                activation.is_ok(),
                "{admitted:?}: an admitted Enrollment split activates: {activation:?}"
            );
        } else {
            assert!(closed(activation), "{admitted:?}");
        }
        // Activation is not a trust use: nothing runs without the declared entry.
        assert!(closed(request.validate_camera_request()), "{admitted:?}");
    }
    assert!(fixture.recorder.calls().is_empty());
    assert!(shared.engine.camera_selection.is_none());
}

#[test]
fn declared_split_entry_admits_nested_preparation_only_while_declared() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let _admitted = fixture.recorder.admit_split_trust(&[Enrollment]);
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    assert!(refusal(request.prepare_camera_request()).contains(CLOSED));
    request
        .enter_split_trust(SplitTrustEntry::Enrollment)
        .expect("the admitted Enrollment entry is declared");
    {
        let nested = request
            .prepare_camera_request()
            .expect("the declared entry admits nested preparation");
        nested
            .validate_camera_request()
            .expect("nested preparation keeps the declared entry");
    }
    // A nested scope restores nothing and keeps the outer retained selection.
    assert!(request.camera_selection.is_some());
    request
        .validate_camera_request()
        .expect("the outer scope keeps its declared entry");
    request.leave_split_trust();
    assert!(refusal(request.prepare_camera_request()).contains(CLOSED));
    drop(request);
    assert!(fixture.recorder.calls().is_empty());
}

#[test]
fn revoked_admission_closes_a_declared_entry_before_the_camera_boundary() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let admitted = fixture.recorder.admit_split_trust(&[Enrollment]);
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    request
        .enter_split_trust(SplitTrustEntry::Enrollment)
        .expect("the admitted Enrollment entry is declared");
    request
        .validate_camera_request()
        .expect("a declared admitted entry validates");
    drop(admitted);
    assert!(closed(request.validate_camera_request()));
    assert!(closed(request.validate_enrollment_camera_activation()));
    assert_eq!(
        acquire(&request, &[RGB, IR], Enrollment).err(),
        Some(CameraLeaseError::SplitActivationDisabled)
    );
    assert!(refusal(request.prepare_camera_request()).contains(CLOSED));
    drop(request);
    assert!(
        fixture.recorder.calls().is_empty(),
        "a revoked predicate refuses in AUTH, before any lease attempt: {:?}",
        fixture.recorder.calls()
    );
}

// Negative controls: GREEN from the stub on; they guard against over-opening.

#[test]
fn admitted_split_scope_without_the_declared_entry_keeps_every_public_entry_closed() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let (mut enrollment, _) = pad_matching_fixture(0.2, false);
    enrollment.user = "split-routing".into();
    let before = serde_json::to_vec(&enrollment).unwrap();
    let path = fixture.dir.join("split-routing.json");
    std::fs::write(&path, &before).unwrap();
    let key = irlume_common::split_key::SplitPairKey::parse_canonical(SPLIT_KEY).unwrap();
    let authorization = irlume_core::multi_camera::authz::EnrollmentAuthorization::mint(
        enrollment.user.clone(),
        irlume_core::multi_camera::authz::EnrollmentOperation::add_group(
            "split-routing".into(),
            &irlume_core::multi_camera::GroupPair::Split(key),
        ),
        1_000_000,
        900,
        "split-routing".into(),
        irlume_core::multi_camera::authz::AuthorizationVia::ElevatedPeer { uid: 0 },
    )
    .unwrap();
    // Both trust kinds are admitted; no Engine split entry is declared.
    let _admitted = fixture
        .recorder
        .admit_split_trust(&[Enrollment, Authentication]);
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    let preflight = Cell::new(0);
    let mut refusals = vec![
        refusal(
            request.enroll_profile_with_ir_preflight("split-routing", None, 1, |_| {
                preflight.set(preflight.get() + 1);
                true
            }),
        ),
        refusal(
            request.replace_enrollment_with_ir_preflight_and_diagnostics(
                "split-routing",
                None,
                1,
                |_| {
                    preflight.set(preflight.get() + 1);
                    true
                },
                &(),
            ),
        ),
        refusal(request.add_camera_group_observed(
            "split-routing",
            None,
            1,
            &authorization,
            |_| {
                preflight.set(preflight.get() + 1);
                true
            },
            &(),
            &(),
        )),
        refusal(request.add_scan_observed(
            "split-routing",
            "fixture",
            1,
            |_| {
                preflight.set(preflight.get() + 1);
                true
            },
            &(),
        )),
        refusal(request.prepare_camera_request()),
        refusal(request.validate_camera_request()),
    ];
    for policy in [
        irlume_common::config::FaceSensorPolicy::Dual,
        irlume_common::config::FaceSensorPolicy::IrOnlyExperimental,
    ] {
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::CredentialRelease,
        ] {
            refusals.push(refusal(request.authenticate_for_in_window_with_policy(
                "split-routing",
                None,
                purpose,
                AuthenticationWindow::new(1000),
                policy,
                &(),
            )));
        }
    }
    refusals.push(refusal(request.identify_with_diagnostics(&())));
    refusals.push(refusal(
        request.identify_within_with_diagnostics("split-routing", &()),
    ));
    refusals.push(refusal(request.position_sample(None)));
    assert_eq!(refusals.len(), 13);
    for refusal in refusals {
        assert!(refusal.contains(CLOSED), "{refusal}");
    }
    assert!(request.capture_qualification_for_request().is_err());
    assert_eq!(preflight.get(), 0);
    assert!(
        fixture.recorder.calls().is_empty(),
        "{:?}",
        fixture.recorder.calls()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let secondary = irlume_core::multi_camera::secondary_store_path("split-routing");
    assert!(!secondary.exists());
    assert!(!irlume_core::multi_camera::commit::intent_path_for(&secondary).exists());
    assert!(!fixture.qualification_dir().exists());
    assert!(!request.request_key().holds_key());
    assert!(request.primary_attempt.is_none() && request.secondary_attempt.is_none());
}

#[test]
fn split_capture_qualification_refuses_before_any_lookup_or_lease() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    let _admitted = fixture.recorder.admit_split_trust(&[Enrollment]);
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    assert!(request.capture_qualification_for_request().is_err());
    // The declared entry (asserted by the RED tests) changes nothing here: a
    // split pair has no stored qualification and never gets a Diagnostics
    // half, so the legacy single-camera lookup must not run.
    let entered = request
        .enter_split_trust(SplitTrustEntry::Enrollment)
        .is_ok();
    let refused = refusal(request.capture_qualification_for_request());
    if entered {
        // Past the gate, the split refusal itself answers, not the gate.
        assert!(
            refused.contains("no stored capture qualification"),
            "{refused}"
        );
    }
    request.leave_split_trust();
    assert!(request.capture_qualification_for_request().is_err());
    drop(request);
    assert!(
        !fixture.qualification_dir().exists(),
        "a split qualification lookup touched the store"
    );
    assert!(
        fixture.recorder.calls().is_empty(),
        "{:?}",
        fixture.recorder.calls()
    );
}

#[test]
fn split_trust_entry_refuses_a_missing_mismatched_or_closed_scope() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    // No retained selection at all.
    {
        let _admitted = fixture
            .recorder
            .admit_split_trust(&[Enrollment, Authentication]);
        assert!(shared.engine.camera_selection.is_none());
        for entry in [SplitTrustEntry::Enrollment, SplitTrustEntry::Authentication] {
            assert!(closed(shared.engine.enter_split_trust(entry)), "{entry:?}");
        }
        assert!(shared.engine.camera_selection.is_none());
    }
    let admissions: [&[CameraOperationKind]; 4] = [
        &[],
        &[Authentication],
        &[Enrollment],
        &[Enrollment, Authentication],
    ];
    for admitted in admissions {
        let _token = fixture.recorder.admit_split_trust(admitted);
        let mut request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        // An Enrollment split never runs as an Authentication entry.
        assert!(
            closed(request.enter_split_trust(SplitTrustEntry::Authentication)),
            "{admitted:?}"
        );
        assert!(closed(request.validate_camera_request()), "{admitted:?}");
        if !admitted.contains(&Enrollment) {
            assert!(
                closed(request.enter_split_trust(SplitTrustEntry::Enrollment)),
                "{admitted:?}"
            );
            assert!(closed(request.validate_camera_request()), "{admitted:?}");
        }
    }
    assert!(fixture.recorder.calls().is_empty());
    assert!(shared.engine.camera_selection.is_none());
}

#[test]
fn split_enrollment_entry_refuses_when_ir_is_forced_off() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(true);
    let (guard, publication) = fixture.choice();
    std::env::set_var("IRLUME_FORCE_NO_IR", "1");
    let _admitted = fixture.recorder.admit_split_trust(&[Enrollment]);
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    assert!(!request.ir_available);
    // No RGB-only or convenience split enrollment: the entry itself refuses.
    assert!(request
        .enter_split_trust(SplitTrustEntry::Enrollment)
        .is_err());
    assert!(closed(request.validate_camera_request()));
    drop(request);
    assert!(fixture.recorder.calls().is_empty());
}

// Positive control: an ordinary selection keeps its exact selected lease.

#[test]
fn ordinary_scope_keeps_its_selected_lease_with_split_trust_admitted() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new(false);
    let _admitted = fixture
        .recorder
        .admit_split_trust(&[Enrollment, Authentication]);
    let devices = Devices::new(&mut shared.engine);
    let mut request = devices.engine.prepare_camera_request().unwrap();
    assert!(request.prepared_camera_lease().is_some());
    for entry in [SplitTrustEntry::Enrollment, SplitTrustEntry::Authentication] {
        assert!(closed(request.enter_split_trust(entry)), "{entry:?}");
    }
    request
        .validate_camera_request()
        .expect("an ordinary selection is unaffected by split admission");
    let operation = acquire(&request, &[RGB, IR], Enrollment)
        .expect("the selected ordinary pair still leases as one unit");
    assert!(!operation.lease().is_split_pair());
    assert_eq!(operation.lease().operation(), Enrollment);
    drop(operation);
    drop(request);
    assert_eq!(fixture.recorder.calls(), vec![lease_call(Enrollment)]);
}
