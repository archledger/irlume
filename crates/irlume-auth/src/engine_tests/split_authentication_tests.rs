// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Dual split authentication (ADR-0032 Step 5; acceptance cases 8, 10, 12,
//! 13 and 15; plan W2a-2, C5, C6, D8 and D10): the authentication call
//! routes an account onto its split pair through classified account
//! routing, leases both original sides as one split Authentication
//! operation, never opens a held pair, and decides the grant only under the
//! split's late machine authority, both original sides, its account scope,
//! its own complete binding and evidence from its split capture.
//!
//! The camera fixture refuses every open, so a real attempt ends at the RGB
//! side. Grant rows inject assessments into the real decision with the
//! split installed exactly as account routing installs it. No frame,
//! template or key here is biometric.

mod split_pinned_config_tests;
mod split_routed_grant_tests;
use super::*;
use crate::account_selection::{select_account_classified, ClassifiedChoice};
use crate::ir_assessment::IrOnlyScope;
use irlume_camera::lease::CameraOperationKind::{self, Authentication};
use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
use irlume_common::split_key::{SplitDomain, SplitPairKey, SplitUnitKey};
use irlume_common::split_schema::{AuthorizationRecord, SideFields};
use irlume_core::multi_camera::{
    save_secondary, secondary_store_path, CameraGroupId, GroupPair, SecondaryGroup,
    SecondaryProfileScans, SecondaryStore, SECONDARY_STORE_VERSION,
};
use irlume_core::storage::PrimarySnapshot;
use irlume_core::template_key::RequestTemplateKey;
use std::ffi::OsString;
use std::path::PathBuf;

const CLOSED: &str = "split enrollment and authentication are not enabled";
const LATE_REFUSAL: &str = "split camera authorization changed during the request";
const NOT_CONNECTED: &str = "no eligible enrolled camera is connected";
const IR_FORCED_OFF: &str = "needs both sides and IR is forced off";
const SIDES: &str = "split camera authentication needs both original sides with IR";
const SCOPE: &str = "split camera authentication has no account scope";
const BINDING: &str = "not bound to the routed split camera pair";
const EVIDENCE: &str = "split camera authentication needs evidence from its split capture";
const USER: &str = "split-authentication";
const S_RGB: &str = "/dev/irlume-split-authentication-rgb";
const S_IR: &str = "/dev/irlume-split-authentication-ir";
const O_RGB: &str = "/dev/irlume-split-authentication-ordinary-rgb";
const O_IR: &str = "/dev/irlume-split-authentication-ordinary-ir";
const MOVED: &str = "/dev/irlume-split-authentication-moved";
const STANDING_RGB: &str = "/dev/irlume-split-authentication-standing-rgb";
const STANDING_IR: &str = "/dev/irlume-split-authentication-standing-ir";
const RGB_UNIT: &str = "4321:0001:argb";
const IR_UNIT: &str = "4321:0002:air";
const ORDINARY_UNIT: &str = "4321:0003:aord";
const ABSENT_UNIT: &str = "4321:00ff:aabsent";
const CONTROLLER: &str = "0000:00:14.0";

/// A sandboxed state and config directory and a non-granting inventory: one
/// split pair on two fixed single-endpoint USB units, optionally beside one
/// fixed ordinary RGB+IR unit. Paths and identities are this suite's own.
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
    fn new(ordinary: bool) -> Self {
        let no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let dir = std::env::temp_dir().join(format!(
            "irlume-split-authentication-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let keys = [
            "IRLUME_CONFIG_DIR",
            "IRLUME_STATE_DIR",
            "IRLUME_METHOD_CONF",
            "IRLUME_TEMPLATE_KEY_DIR",
            "IRLUME_TCTI",
            "IRLUME_RGB_DEVICE",
            "IRLUME_IR_DEVICE",
            "IRLUME_FORCE_NO_IR",
            "IRLUME_CAMERA_REQUIRE_FIXED",
            "IRLUME_FORBID_EXTERNAL_CAMERAS",
            "IRLUME_GRACE_MS",
            "IRLUME_SEQUENTIAL_CAPTURE",
        ];
        let saved = keys
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_METHOD_CONF", dir.join("no-method-conf"));
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", dir.join("private-template-keys"));
        // No key resolution is expected; an explicit failed transport still
        // keeps any accidental one off the host TPM.
        std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-test-tpm");
        for key in &keys[5..] {
            std::env::remove_var(key);
        }
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
        let mut cameras = vec![
            unit(
                "/devices/split-authentication/rgb",
                RGB_UNIT,
                8,
                vec![endpoint(S_RGB, *b"YUYV")],
            ),
            unit(
                "/devices/split-authentication/ir",
                IR_UNIT,
                5,
                vec![endpoint(S_IR, *b"GREY")],
            ),
        ];
        if ordinary {
            cameras.push(unit(
                "/devices/split-authentication/ordinary",
                ORDINARY_UNIT,
                3,
                vec![endpoint(O_RGB, *b"YUYV"), endpoint(O_IR, *b"GREY")],
            ));
        }
        let recorder = Guard::install(&cameras).unwrap();
        Self {
            dir,
            saved,
            recorder,
            _no_tpm: no_tpm,
        }
    }

    /// Publish the one administrator-authorized split pair, selected
    /// (pinned) or not, then remove the writer's lock file, so a later one
    /// proves a later lock.
    fn authorize(&self, pinned: bool) {
        let key = key();
        irlume_common::split_publish::publish_split(&[record()], pinned.then_some(&key)).unwrap();
        let _ = std::fs::remove_file(self.lock());
    }

    /// Withdraw every split authorization, as an administrator would.
    fn revoke(&self) {
        irlume_common::split_publish::publish_split(&[], None).unwrap();
        let _ = std::fs::remove_file(self.lock());
    }

    fn lock(&self) -> PathBuf {
        self.dir.join("cameras.conf.lock")
    }

    fn primary_path(&self) -> PathBuf {
        self.dir.join(format!("{USER}.json"))
    }

    /// Plant a plaintext primary with IR templates the engine can compare,
    /// under `binding`, and return its snapshot.
    fn primary(&self, engine: &Engine, binding: Option<CameraBinding>) -> PrimarySnapshot {
        let enrollment = compatible_enrollment(engine, binding);
        let bytes = serde_json::to_vec(&enrollment).unwrap();
        std::fs::write(self.primary_path(), &bytes).unwrap();
        PrimarySnapshot {
            enrollment,
            key: None,
            bytes,
        }
    }

    /// Plant an active secondary store whose one group is the split pair.
    fn secondary(&self, primary: &PrimarySnapshot) {
        let store = SecondaryStore {
            format_version: SECONDARY_STORE_VERSION,
            owner: USER.into(),
            generation: 1,
            primary_snapshot_sha256: irlume_common::sha256_hex(&primary.bytes),
            groups: vec![SecondaryGroup {
                id: CameraGroupId::new("split-desk".into()).unwrap(),
                pair: GroupPair::Split(key()),
                profiles: vec![SecondaryProfileScans {
                    ir_calibs: Default::default(),
                    profile: "fixture".into(),
                    scans: primary.enrollment.profiles[0].scans.clone(),
                }],
            }],
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
        rgb: unit_key(RGB_UNIT, 8),
        ir: unit_key(IR_UNIT, 5),
    }
}

/// The same two units with the IR side on another port: a different
/// complete key that no connected pair carries.
fn other_key() -> SplitPairKey {
    SplitPairKey {
        rgb: unit_key(RGB_UNIT, 8),
        ir: unit_key(IR_UNIT, 6),
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
        rgb: side(RGB_UNIT, S_RGB, 8),
        ir: side(IR_UNIT, S_IR, 5),
    }
}

fn split_binding() -> CameraBinding {
    CameraBinding::Split(key())
}

fn absent_binding() -> CameraBinding {
    CameraBinding::Ordinary {
        rgb: Some(ABSENT_UNIT.into()),
        ir: Some(ABSENT_UNIT.into()),
    }
}

fn ordinary_binding() -> CameraBinding {
    CameraBinding::Ordinary {
        rgb: Some(ORDINARY_UNIT.into()),
        ir: Some(ORDINARY_UNIT.into()),
    }
}

/// The one split Authentication lease over both original sides, RGB first.
fn split_lease() -> Call {
    Call::Lease {
        endpoints: vec![S_RGB.into(), S_IR.into()],
        kind: Authentication,
    }
}

fn probe(cosine: f32) -> [f32; EMBED_DIM] {
    let mut embedding = [0.0; EMBED_DIM];
    embedding[0] = cosine;
    embedding[1] = (1.0 - cosine * cosine).sqrt();
    embedding
}

/// One profile whose RGB and IR templates the engine compares in its own
/// recognizer and IR spaces.
fn compatible_enrollment(engine: &Engine, binding: Option<CameraBinding>) -> Enrollment {
    let (mut enrollment, _) = pad_matching_fixture(0.1, false);
    enrollment.user = USER.into();
    let scan = &mut enrollment.profiles[0].scans[0];
    scan.ir = Some(scan.rgb.clone());
    scan.ir_space = Some(engine.ir_space().into());
    scan.embed_space = Some(engine.embed_space().into());
    enrollment.camera_binding = binding;
    enrollment
}

/// A live, PAD-clean assessment at zero skew. `split` is the capture's
/// split provenance: only a test can set it by hand.
fn assessment(rgb_cosine: f32, ir_cosine: f32, split: bool) -> Assessment {
    let (_, mut assessment) = pad_matching_fixture(0.1, false);
    assessment.embedding = Some(probe(rgb_cosine));
    assessment.ir_embedding = Some(probe(ir_cosine).to_vec());
    assessment.signals.rgb_face = Some(irlume_liveness::FaceBox {
        cx: 0.5,
        cy: 0.5,
        score: 0.9,
    });
    assessment.signals.ir_face = assessment.signals.rgb_face;
    assessment.signals.rgb_face_brightness = 130.0;
    assessment.ir_brightness = 35.0;
    assessment.ir_pad = PadEvidence::Score(0.1);
    assessment.sequential_pair = false;
    assessment.split_pair = split;
    assessment
}

/// Evidence the IR-fallback arm grants: a qualifying IR identity.
fn granting() -> Assessment {
    assessment(0.5, 0.8, true)
}

/// Route the account through the request's retained selection.
fn route(engine: &Engine, primary: PrimarySnapshot) -> Result<ClassifiedChoice, Outcome> {
    let mut keys = RequestTemplateKey::with_unsealer(|_: &str| Ok(None));
    let selection = engine
        .camera_selection
        .as_ref()
        .expect("a prepared request");
    select_account_classified(
        USER,
        primary,
        selection,
        |enrollment| {
            enrollment
                .profiles
                .iter()
                .any(|profile| !profile.scans.is_empty())
        },
        &mut keys,
        false,
    )
}

/// Prepare the authentication call, route the account's split primary and
/// install it exactly as the authentication call does: the choice, its
/// Authentication entry and the account scope of the attempt.
fn install<'a>(engine: &'a mut Engine, rig: &Rig) -> (CameraRequestScope<'a>, Enrollment) {
    let mut call = engine.prepare_authentication_camera_request().unwrap();
    let primary = rig.primary(&call, Some(split_binding()));
    let (enrollment, split, scope) = match route(&call, primary) {
        Ok(ClassifiedChoice::Split {
            enrollment,
            split,
            scope,
        }) => (enrollment, split, scope),
        Ok(_) => panic!("expected the split choice, got another class"),
        Err(outcome) => panic!("expected the split choice, got {}", outcome.reason),
    };
    call.select_account_split_camera(*split).unwrap();
    match scope {
        IrOnlyScope::Primary { .. } => call.primary_attempt = Some(scope),
        IrOnlyScope::Secondary(context) => call.secondary_attempt = Some(*context),
    }
    (call, enrollment)
}

fn decide_for(
    engine: &mut Engine,
    enrollment: &Enrollment,
    purpose: AuthenticationPurpose,
    assessment: Assessment,
) -> Outcome {
    engine
        .authenticate_qualified_assessment(enrollment, purpose, Some("login"), assessment, &())
        .unwrap()
}

fn decide(engine: &mut Engine, enrollment: &Enrollment, assessment: Assessment) -> Outcome {
    decide_for(
        engine,
        enrollment,
        AuthenticationPurpose::Verify,
        assessment,
    )
}

/// A final refusal before any grant arm: not live, never retried.
fn assert_refused(outcome: &Outcome, reason: &str, cause: OutcomeCause, case: &str) {
    assert!(
        !outcome.granted && !outcome.live,
        "{case}: expected a refusal, got {outcome:?}"
    );
    assert!(
        outcome.reason.contains(reason),
        "{case}: expected `{reason}`, got {outcome:?}"
    );
    assert_eq!(outcome.kind, OutcomeKind::OtherDeny, "{case}");
    assert_eq!(outcome.cause, Some(cause), "{case}");
    assert!(!presence_retryable(outcome), "{case}");
}

fn reply(result: &irlume_common::Result<Outcome>) -> String {
    match result {
        Ok(outcome) => format!(
            "{} ({:?}): {}",
            if outcome.granted { "granted" } else { "denied" },
            outcome.kind,
            outcome.reason
        ),
        Err(error) => format!("error: {error}"),
    }
}

fn granted(result: &irlume_common::Result<Outcome>) -> bool {
    result.as_ref().is_ok_and(|outcome| outcome.granted)
}

// RED: these need the classified authentication routing and the dual split
// arm (plan W2a-2, C5, D8).

#[test]
fn admitted_split_authentication_leases_both_sides_and_never_opens_a_held_pair() {
    let _env = env_guard();
    let mut shared = shared();
    // The operator's capture-schedule override never reaches a split pair.
    // A saved ordinary pair line beside a pinned split reads as a configured
    // selection, not automatic: only classified routing sees the pin, beside
    // a connected ordinary unit it never yields to.
    let shapes = [
        (false, false, None, false),
        (true, false, Some("0"), false),
        (false, true, Some("1"), false),
        (true, true, None, false),
        (true, false, None, true),
    ];
    for (pinned, secondary, schedule, ordinary_lines) in shapes {
        for purpose in [
            AuthenticationPurpose::Verify,
            AuthenticationPurpose::CredentialRelease,
        ] {
            let case = format!(
                "pinned={pinned} secondary={secondary} {schedule:?} lines={ordinary_lines} \
                 {purpose:?}"
            );
            let rig = Rig::new(ordinary_lines);
            if ordinary_lines {
                std::fs::write(
                    rig.dir.join("cameras.conf"),
                    format!("rgb={O_RGB}\nir={O_IR}\n"),
                )
                .unwrap();
            }
            rig.authorize(pinned);
            if let Some(schedule) = schedule {
                std::env::set_var("IRLUME_SEQUENTIAL_CAPTURE", schedule);
            }
            let counts = rig.recorder.lease_counts_observer();
            let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
            let standing = Standing::new(&mut shared.engine);
            let primary = if secondary {
                let primary = rig.primary(standing.engine, Some(absent_binding()));
                rig.secondary(&primary);
                primary
            } else {
                rig.primary(standing.engine, Some(split_binding()))
            };
            let result = standing
                .engine
                .authenticate_for(USER, Some("login"), purpose);
            assert_eq!(
                rig.recorder.calls(),
                vec![split_lease(), Call::OpenRgb(S_RGB.into())],
                "{case}: one split Authentication lease over both original sides, then the \
                 sequential RGB attempt only: no ordinary, single-side or Diagnostics lease, \
                 no held pair, no IR open after the refused RGB side ({})",
                reply(&result)
            );
            assert!(!granted(&result), "{case}: {}", reply(&result));
            assert!(
                !reply(&result).contains(CLOSED),
                "{case}: the admitted call must reach the camera: {}",
                reply(&result)
            );
            assert_eq!(counts(), (0, 0), "{case}: both reservations released");
            assert!(standing.engine.camera_selection.is_none(), "{case}");
            assert_eq!(
                standing.devices(),
                (STANDING_RGB, STANDING_IR, false),
                "{case}: no standing split choice outlives the call"
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
            assert!(
                !irlume_core::multi_camera::commit::intent_path_for(&secondary_store_path(USER))
                    .exists(),
                "{case}"
            );
        }
    }
}

#[test]
fn an_installed_split_grants_only_through_the_ir_identity_arms() {
    let _env = env_guard();
    let mut shared = shared();
    for pinned in [false, true] {
        let rig = Rig::new(false);
        rig.authorize(pinned);
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        let standing = Standing::new(&mut shared.engine);
        {
            let (mut call, enrollment) = install(standing.engine, &rig);
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
                    // Evidence without split provenance never reaches an arm.
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
        // Positive control: without an installed split the same unmarked
        // evidence grants through the ordinary RGB-primary and fusion arms.
        standing.engine.ir_available = true;
        let enrollment = compatible_enrollment(standing.engine, Some(split_binding()));
        for (rgb, arm) in [(0.9, "(rgb)"), (0.5, "rgb+ir fusion")] {
            let out = decide(standing.engine, &enrollment, assessment(rgb, 0.4, false));
            assert!(out.granted, "pinned={pinned} rgb={rgb}: {out:?}");
            assert!(out.reason.contains(arm), "{}", out.reason);
        }
        assert!(rig.recorder.calls().is_empty(), "pinned={pinned}");
        assert!(!rig.lock().exists(), "pinned={pinned}");
    }
}

#[test]
fn revocation_or_an_ended_entry_refuses_at_the_split_grant_boundary() {
    let _env = env_guard();
    let mut shared = shared();
    for pinned in [false, true] {
        for change in ["revoked", "reselected", "entry left", "admission ended"] {
            let case = format!("pinned={pinned} {change}");
            let rig = Rig::new(false);
            rig.authorize(pinned);
            let mut admitted = Some(rig.recorder.admit_split_trust(&[Authentication]));
            let standing = Standing::new(&mut shared.engine);
            {
                let (mut call, enrollment) = install(standing.engine, &rig);
                let out = decide(&mut call, &enrollment, granting());
                assert!(out.granted, "{case}: control before the change: {out:?}");
                match change {
                    "revoked" => rig.revoke(),
                    "reselected" => rig.authorize(!pinned),
                    "entry left" => call.leave_split_trust(),
                    _ => drop(admitted.take()),
                }
                let out = decide(&mut call, &enrollment, granting());
                assert_refused(&out, LATE_REFUSAL, OutcomeCause::SetupUnavailable, &case);
                assert!(
                    !rig.lock().exists(),
                    "{case}: the grant boundary takes no configuration lock"
                );
            }
            assert!(rig.recorder.calls().is_empty(), "{case}");
            assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
        }
    }
}

#[test]
fn split_authentication_refuses_without_both_sides_and_ir() {
    let _env = env_guard();
    let mut shared = shared();
    // The authentication call: IR forced off refuses the split install
    // before any lease, with no RGB-only or convenience split route.
    for pinned in [false, true] {
        let rig = Rig::new(false);
        rig.authorize(pinned);
        let counts = rig.recorder.lease_counts_observer();
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        let standing = Standing::new(&mut shared.engine);
        let primary = rig.primary(standing.engine, Some(split_binding()));
        std::env::set_var("IRLUME_FORCE_NO_IR", "1");
        let result =
            standing
                .engine
                .authenticate_for(USER, Some("login"), AuthenticationPurpose::Verify);
        std::env::remove_var("IRLUME_FORCE_NO_IR");
        assert!(
            !granted(&result) && reply(&result).contains(IR_FORCED_OFF),
            "pinned={pinned}: {}",
            reply(&result)
        );
        assert!(rig.recorder.calls().is_empty(), "pinned={pinned}");
        assert_eq!(counts(), (0, 0));
        assert_eq!(std::fs::read(rig.primary_path()).unwrap(), primary.bytes);
        assert!(standing.engine.camera_selection.is_none());
        assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
    }
    // The grant boundary: an installed split that lost IR or either
    // original side never grants.
    for pinned in [false, true] {
        for change in ["ir unavailable", "ir forced off", "rgb moved", "ir moved"] {
            let case = format!("pinned={pinned} {change}");
            let rig = Rig::new(false);
            rig.authorize(pinned);
            let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
            let standing = Standing::new(&mut shared.engine);
            {
                let (mut call, enrollment) = install(standing.engine, &rig);
                let out = decide(&mut call, &enrollment, granting());
                assert!(out.granted, "{case}: control before the change: {out:?}");
                match change {
                    "ir unavailable" => call.ir_available = false,
                    "ir forced off" => std::env::set_var("IRLUME_FORCE_NO_IR", "1"),
                    "rgb moved" => call.rgb_dev = MOVED.into(),
                    _ => call.ir_dev = MOVED.into(),
                }
                let out = decide(&mut call, &enrollment, granting());
                std::env::remove_var("IRLUME_FORCE_NO_IR");
                assert_refused(&out, SIDES, OutcomeCause::CameraUnavailable, &case);
            }
            assert!(rig.recorder.calls().is_empty(), "{case}");
            assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
        }
    }
}

#[test]
fn a_mismatched_complete_binding_refuses_before_any_split_grant() {
    let _env = env_guard();
    let mut shared = shared();
    // After activation, an account bound to another complete key never
    // routes onto the connected split pair: the call denies before any
    // lease (ADR-0032 case 15). A pinned split ranks only its own key, so a
    // connected ordinary binding refuses too (case 10). The automatic
    // unconnected ordinary binding is the unchanged control.
    let rows = [
        (false, false, CameraBinding::Split(other_key())),
        (true, false, CameraBinding::Split(other_key())),
        (false, false, absent_binding()),
        (true, false, absent_binding()),
        (true, true, ordinary_binding()),
    ];
    for (pinned, ordinary, binding) in rows {
        let case = format!("pinned={pinned} ordinary={ordinary} {binding:?}");
        let rig = Rig::new(ordinary);
        rig.authorize(pinned);
        let counts = rig.recorder.lease_counts_observer();
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        let standing = Standing::new(&mut shared.engine);
        let primary = rig.primary(standing.engine, Some(binding));
        let result =
            standing
                .engine
                .authenticate_for(USER, Some("login"), AuthenticationPurpose::Verify);
        assert!(
            result
                .as_ref()
                .is_ok_and(|out| !out.granted && out.reason.contains(NOT_CONNECTED)),
            "{case}: {}",
            reply(&result)
        );
        assert!(rig.recorder.calls().is_empty(), "{case}");
        assert_eq!(counts(), (0, 0), "{case}");
        assert_eq!(std::fs::read(rig.primary_path()).unwrap(), primary.bytes);
        assert!(standing.engine.camera_selection.is_none(), "{case}");
        assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
    }
    // The grant boundary: with the split installed, a decision against any
    // other binding, or without the account scope, refuses before any arm.
    for pinned in [false, true] {
        let rig = Rig::new(false);
        rig.authorize(pinned);
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        let standing = Standing::new(&mut shared.engine);
        {
            let (mut call, enrollment) = install(standing.engine, &rig);
            let out = decide(&mut call, &enrollment, granting());
            assert!(out.granted, "pinned={pinned}: control: {out:?}");
            for binding in [
                Some(CameraBinding::Split(other_key())),
                Some(ordinary_binding()),
                Some(CameraBinding::Ordinary {
                    rgb: Some(RGB_UNIT.into()),
                    ir: Some(IR_UNIT.into()),
                }),
                None,
            ] {
                let case = format!("pinned={pinned} {binding:?}");
                let mut other = enrollment.clone();
                other.camera_binding = binding;
                let out = decide(&mut call, &other, granting());
                assert_refused(&out, BINDING, OutcomeCause::NotEnrolledOnThisCamera, &case);
            }
            let scope = call.primary_attempt.take();
            assert!(scope.is_some(), "pinned={pinned}: the routed primary scope");
            let out = decide(&mut call, &enrollment, granting());
            assert_refused(
                &out,
                SCOPE,
                OutcomeCause::SetupUnavailable,
                &format!("pinned={pinned} no scope"),
            );
            call.primary_attempt = scope;
            let out = decide(&mut call, &enrollment, granting());
            assert!(out.granted, "pinned={pinned}: control after: {out:?}");
        }
        assert!(rig.recorder.calls().is_empty(), "pinned={pinned}");
    }
}

// Negative controls: GREEN before and after. They pin that the split arm is
// keyed on an installed split, never on admission or authorization alone,
// and that the closed default keeps its text before any camera boundary.

#[test]
fn admitted_split_trust_keeps_ordinary_authentication_on_its_held_pair() {
    let _env = env_guard();
    let mut shared = shared();
    for purpose in [
        AuthenticationPurpose::Verify,
        AuthenticationPurpose::CredentialRelease,
    ] {
        // The split pair is authorized and admitted beside the ordinary
        // unit; automatic ranking still chooses the account's ordinary pair.
        let rig = Rig::new(true);
        rig.authorize(false);
        let _admitted = rig.recorder.admit_split_trust(&[Authentication]);
        let standing = Standing::new(&mut shared.engine);
        let primary = rig.primary(standing.engine, Some(ordinary_binding()));
        let result = standing
            .engine
            .authenticate_for(USER, Some("login"), purpose);
        let calls = rig.recorder.calls();
        assert_eq!(
            calls.first(),
            Some(&Call::Lease {
                endpoints: vec![O_RGB.into(), O_IR.into()],
                kind: Authentication,
            }),
            "{purpose:?}: {calls:?} ({})",
            reply(&result)
        );
        assert!(
            calls.contains(&Call::OpenRgb(O_RGB.into()))
                && calls.contains(&Call::OpenIr(O_IR.into())),
            "{purpose:?}: the ordinary route keeps its held pair: {calls:?}"
        );
        let split_side = |path: &String| path == S_RGB || path == S_IR;
        assert!(
            !calls.iter().any(|call| {
                matches!(call, Call::Lease { endpoints, .. } if endpoints.iter().any(split_side))
                    || matches!(call, Call::OpenRgb(path) | Call::OpenIr(path) if split_side(path))
            }),
            "{purpose:?}: no split side reached: {calls:?}"
        );
        assert!(!granted(&result), "{purpose:?}: {}", reply(&result));
        assert!(!reply(&result).contains(CLOSED), "{purpose:?}");
        assert_eq!(std::fs::read(rig.primary_path()).unwrap(), primary.bytes);
        assert!(standing.engine.camera_selection.is_none());
    }
}

#[test]
fn split_authentication_stays_closed_without_authentication_admission() {
    let _env = env_guard();
    let mut shared = shared();
    let kinds: [&[CameraOperationKind]; 2] = [&[], &[CameraOperationKind::Enrollment]];
    for pinned in [false, true] {
        for admitted in kinds {
            let case = format!("pinned={pinned} admitted={admitted:?}");
            let rig = Rig::new(false);
            rig.authorize(pinned);
            let counts = rig.recorder.lease_counts_observer();
            let _admitted =
                (!admitted.is_empty()).then(|| rig.recorder.admit_split_trust(admitted));
            let standing = Standing::new(&mut shared.engine);
            let primary = rig.primary(standing.engine, Some(split_binding()));
            let result = standing.engine.authenticate_for(
                USER,
                Some("login"),
                AuthenticationPurpose::Verify,
            );
            // Automatic and pinned authentication can route after admission,
            // so their refusal must name the activation predicate.
            assert!(
                !granted(&result) && reply(&result).contains(CLOSED),
                "{case}: {}",
                reply(&result)
            );
            assert!(rig.recorder.calls().is_empty(), "{case}");
            assert_eq!(counts(), (0, 0), "{case}");
            assert_eq!(std::fs::read(rig.primary_path()).unwrap(), primary.bytes);
            assert!(!rig.lock().exists(), "{case}");
            assert!(standing.engine.camera_selection.is_none(), "{case}");
            assert_eq!(standing.devices(), (STANDING_RGB, STANDING_IR, false));
        }
    }
}
